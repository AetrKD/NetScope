"""
sniffer.py
──────────
안정적인 백그라운드 스레드 기반 패킷 캡처 엔진 (재작성)
"""

import threading
import ctypes
import json
import time
from pathlib import Path
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, wrpcap, conf
import socket as sock

from database import save_packet_async, main_db

def save_pcap(packet_data_list, filename):
    pkts = []
    for d in packet_data_list:
        raw_hex = d.get('raw')
        if raw_hex:
            try:
                pkts.append(Ether(bytes.fromhex(raw_hex)))
            except Exception:
                pass
    if pkts:
        wrpcap(filename, pkts)
        return True
    return False

def get_local_ips():
    ips = {'127.0.0.1'}
    try:
        hostname = sock.gethostname()
        for info in sock.getaddrinfo(hostname, None):
            ips.add(info[4][0])
    except Exception:
        pass
    return ips

LOCAL_IPS = get_local_ips()

def check_filter_match(f_dict: dict, src: str, dst: str, sport, dport, proto_name: str, direction: str, pkt_len: int, default_match: bool = False) -> bool:
    if not f_dict:
        return default_match

    f_ip    = (f_dict.get('ip')       or '').strip()
    f_port  = (f_dict.get('port')     or '').strip()
    f_proto = (f_dict.get('proto')    or '').strip()
    f_dir   = (f_dict.get('dir')      or '').strip()
    f_min   = (f_dict.get('min_size') or '').strip()
    f_max   = (f_dict.get('max_size') or '').strip()

    if not any([f_ip, f_port, f_proto, f_dir, f_min, f_max]):
        return default_match

    if f_ip and (f_ip != src and f_ip != dst): return False

    if f_port:
        try:
            fp = int(f_port)
            if fp not in (sport, dport): return False
        except ValueError:
            pass

    if f_proto and f_proto != proto_name: return False
    if f_dir and f_dir != direction: return False
    if f_min and pkt_len < int(f_min): return False
    if f_max and pkt_len > int(f_max): return False

    return True

class PacketSniffer:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(PacketSniffer, cls).__new__(cls)
            cls._instance._init()
        return cls._instance
        
    def _init(self):
        self.packet_count = 0
        self.is_paused = False
        self.alias_policies = {}
        self.current_filter = {}
        self.packet_rules = []
        self.emit_callback = None
        self._running = False
        self.capture_thread = None
        
    def set_emit_callback(self, cb): self.emit_callback = cb
    def set_pause(self, paused: bool): self.is_paused = paused
    def set_aliases_policy(self, policies: dict): self.alias_policies = policies
    def set_filter(self, f_dict: dict): self.current_filter = f_dict
    def set_packet_rules(self, rules: list): self.packet_rules = rules

    def _packet_handler(self, packet):
        if self.is_paused:
            return

        if not packet.haslayer(IP):
            return
            
        ip_layer = packet[IP]
        src, dst = ip_layer.src, ip_layer.dst
        proto_name = "OTHER"
        sport, dport = None, None

        if packet.haslayer(TCP):
            proto_name = "TCP"
            sport, dport = packet[TCP].sport, packet[TCP].dport
        elif packet.haslayer(UDP):
            proto_name = "UDP"
            sport, dport = packet[UDP].sport, packet[UDP].dport
        elif packet.haslayer(ICMP):
            proto_name = "ICMP"

        if dst in LOCAL_IPS: direction = "INBOUND"
        elif src in LOCAL_IPS: direction = "OUTBOUND"
        else: direction = "OTHER"

        pkt_len = len(packet)

        if not check_filter_match(self.current_filter, src, dst, sport, dport, proto_name, direction, pkt_len, True):
            return

        is_highlight = False
        if self.packet_rules:
            for rule in self.packet_rules:
                if check_filter_match(rule, src, dst, sport, dport, proto_name, direction, pkt_len, False):
                    action = rule.get('action', 'HIGHLIGHT')
                    if action == 'IGNORE':
                        return
                    elif action == 'HIGHLIGHT':
                        is_highlight = True
                        break

        self.packet_count += 1
        time_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        packet_data = {
            "no": self.packet_count,
            "time": time_str,
            "src": src,
            "dst": dst,
            "proto": proto_name,
            "len": pkt_len,
            "summary": packet.summary(),
            "direction": direction,
            "raw": bytes(packet).hex(),
            "highlight": is_highlight
        }

        is_saved = False
        src_policy = self.alias_policies.get(src, {}).get('policy')
        dst_policy = self.alias_policies.get(dst, {}).get('policy')
        
        if src_policy == 'SAVE_ALL' or dst_policy == 'SAVE_ALL':
            is_saved = True

        # Heuristic Analysis for Suspicious Traffic
        is_suspicious = False
        suspicion_reason = ""
        
        if proto_name == "ICMP" and pkt_len > 1000:
            is_suspicious = True
            suspicion_reason = "대용량 ICMP 패킷 (Ping of Death 의심)"
        elif direction == "INBOUND" and dport in {22, 23, 445, 1433, 3306, 3389}:
            is_suspicious = True
            suspicion_reason = f"외부망에서 주요 포트({dport}) 접근"
        elif packet.haslayer(TCP):
            flags = packet[TCP].flags
            if flags == 0:
                is_suspicious = True
                suspicion_reason = "TCP Null Scan 의심"
            elif flags == 0x29: # FIN, PSH, URG
                is_suspicious = True
                suspicion_reason = "TCP XMAS Scan 의심"

        packet_data["suspicious"] = is_suspicious
        packet_data["suspicion_reason"] = suspicion_reason

        if is_suspicious and src not in self.alias_policies:
            try:
                main_db.set_alias(src, "", "SAVE_ALL", "")
                self.alias_policies[src] = {'name': '', 'policy': 'SAVE_ALL'}
                is_saved = True
            except Exception as e:
                print(f"[ERROR] 의심 IP 자동 등록 실패: {e}")

        if is_saved or is_highlight or is_suspicious:
            save_packet_async(
                packet_data, 
                time_str, 
                is_saved=is_saved, 
                is_highlighted=is_highlight, 
                is_suspicious=is_suspicious, 
                suspicion_reason=suspicion_reason
            )

        if self.emit_callback:
            try:
                self.emit_callback('new_packet', packet_data)
            except Exception:
                pass

    def _sniff_loop(self, target_iface):
        try:
            if not target_iface:
                try:
                    # Windows에서 conf.iface가 엉뚱한 가상 어댑터를 잡는 것을 방지하기 위해 라우팅 테이블 조회
                    target_iface = conf.route.route('8.8.8.8')[0]
                    print(f"[INFO] 활성 네트워크 어댑터 자동 감지: {target_iface}")
                except Exception:
                    pass

            if target_iface:
                print(f"[INFO] 캡처 시작 (어댑터: {target_iface})...")
                while self._running:
                    sniff(iface=target_iface, prn=self._packet_handler, store=False, timeout=1.0)
            else:
                print("[INFO] 캡처 시작 (전체/기본 어댑터)...")
                while self._running:
                    sniff(prn=self._packet_handler, store=False, timeout=1.0)
        except Exception as e:
            print("=" * 60)
            print(f"[ERROR] 패킷 캡처 루프 오류: {e}")
            print("=" * 60)
            self._running = False

    def start(self):
        if self._running:
            return
            
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            is_admin = 0

        if is_admin == 0:
            print("[WARNING] 관리자 권한이 없어 일부 어댑터에서 캡처가 불가능할 수 있습니다.")
            
        config_path = Path(__file__).parent / "config.json"
        target_iface = None
        try:
            if config_path.exists():
                with open(config_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                    target_iface = cfg.get("server", {}).get("iface")
                    if target_iface == "all" or str(target_iface).strip() == "":
                        target_iface = None
        except Exception:
            pass

        self._running = True
        self.capture_thread = threading.Thread(target=self._sniff_loop, args=(target_iface,), daemon=True)
        self.capture_thread.start()
        
    def stop(self):
        self._running = False
        print("[INFO] 캡처 엔진 중지 요청 완료 (스레드 대기 중...).")

_instance = PacketSniffer()

def set_emit_callback(cb): _instance.set_emit_callback(cb)
def set_pause(paused): _instance.set_pause(paused)
def set_aliases_policy(policies): _instance.set_aliases_policy(policies)
def set_filter(f_dict): _instance.set_filter(f_dict)
def set_packet_rules(rules): _instance.set_packet_rules(rules)
def start_sniffing(): _instance.start()
def stop_sniffing(): _instance.stop()
