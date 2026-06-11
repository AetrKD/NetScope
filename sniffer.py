"""
sniffer.py
──────────
안정적인 백그라운드 스레드 기반 패킷 캡처 엔진 (재작성)
"""

import threading
import ctypes
import json
import time
import collections
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
        self.emit_callback = None
        self._running = False
        self.capture_thread = None
        self.recent_packets = collections.deque(maxlen=2000)
        self.active_incidents = {}
        self.incident_callback = None
        self.incident_start_callback = None
        
    def set_incident_start_callback(self, cb): self.incident_start_callback = cb
    def set_incident_callback(self, cb): self.incident_callback = cb
    def set_emit_callback(self, cb): self.emit_callback = cb
    def set_pause(self, paused: bool): self.is_paused = paused
    def set_aliases_policy(self, policies: dict): self.alias_policies = policies
    def set_filter(self, f_dict: dict): self.current_filter = f_dict

    def _packet_handler(self, packet):
        if self.is_paused:
            return

        if not packet.haslayer(IP):
            return
            
        ip_layer = packet[IP]
        src, dst = ip_layer.src, ip_layer.dst
        proto_name = "OTHER"
        sport, dport = None, None

        if packet.haslayer(TCP) or (packet.haslayer(IP) and packet[IP].proto == 6):
            proto_name = "TCP"
            if packet.haslayer(TCP):
                sport, dport = packet[TCP].sport, packet[TCP].dport
        elif packet.haslayer(UDP) or (packet.haslayer(IP) and packet[IP].proto == 17):
            proto_name = "UDP"
            if packet.haslayer(UDP):
                sport, dport = packet[UDP].sport, packet[UDP].dport
        elif packet.haslayer(ICMP) or (packet.haslayer(IP) and packet[IP].proto == 1):
            proto_name = "ICMP"

        if dst in LOCAL_IPS: direction = "INBOUND"
        elif src in LOCAL_IPS: direction = "OUTBOUND"
        else: direction = "OTHER"

        pkt_len = len(packet)

        if not check_filter_match(self.current_filter, src, dst, sport, dport, proto_name, direction, pkt_len, True):
            return

        self.packet_count += 1
        time_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

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

        # 패킷 헥스 데이터는 DB에 저장해야 하거나, 브로드캐스트할 때만 필요.
        # 하지만 브로드캐스트 성능을 위해 무조건 생성하지 않고 저장/의심 패킷인 경우에만 생성
        raw_hex = bytes(packet).hex() if (is_saved or is_suspicious) else ""

        packet_data = {
            "no": self.packet_count,
            "time": time_str,
            "src": src,
            "dst": dst,
            "sport": sport,
            "dport": dport,
            "proto": proto_name,
            "len": pkt_len,
            "summary": packet.summary(),
            "direction": direction,
            "raw": raw_hex,
            "suspicious": is_suspicious,
            "suspicion_reason": suspicion_reason
        }

        if is_suspicious and src not in self.alias_policies:
            try:
                main_db.set_alias(src, "", "AUTO", "의심 트래픽 자동 감지")
                self.alias_policies[src] = {'name': '', 'policy': 'AUTO'}
                src_policy = "AUTO"
            except Exception as e:
                print(f"[ERROR] 의심 IP 자동 등록 실패: {e}")

        if is_saved or is_suspicious:
            save_packet_async(
                packet_data, 
                time_str, 
                is_saved=is_saved, 
                is_suspicious=is_suspicious, 
                suspicion_reason=suspicion_reason
            )

        now = time.time()
        self.recent_packets.append((now, packet_data))

        # Check AUTO policy for incident reporting
        if is_suspicious and (src_policy == 'AUTO' or dst_policy == 'AUTO'):
            trigger_ip = src if src_policy == 'AUTO' else dst
            if trigger_ip not in self.active_incidents:
                # Start new incident
                
                # 즉시 UI 알림 전송
                if self.incident_start_callback:
                    self.incident_start_callback(trigger_ip, suspicion_reason)
                
                # snapshot last 5 seconds from ring buffer
                past_pkts = [p[1] for p in self.recent_packets if now - p[0] <= 5.0]
                self.active_incidents[trigger_ip] = {
                    "trigger_ip": trigger_ip,
                    "trigger_reason": suspicion_reason,
                    "start_time": now,
                    "end_time": now + 5.0,
                    "packets": past_pkts
                }

        # Append to active incidents and check completion
        completed_incidents = []
        for inc_ip, inc in list(self.active_incidents.items()):
            if now <= inc["end_time"]:
                # Only add if it wasn't already in past_pkts (handled by time check, but since we snapshot it, 
                # we just append new packets that arrive AFTER start_time)
                # Actually, all packets arriving here are current, so we just append
                if packet_data not in inc["packets"]:
                    inc["packets"].append(packet_data)
            else:
                completed_incidents.append(inc)
                del self.active_incidents[inc_ip]
                
        for inc in completed_incidents:
            if self.incident_callback:
                try:
                    self.incident_callback(inc)
                except Exception as e:
                    print(f"[ERROR] Incident Callback Error: {e}")

        if self.emit_callback:
            try:
                self.emit_callback('new_packet', packet_data)
            except Exception:
                pass

    def _sniff_loop(self, target_iface):
        if not target_iface:
            try:
                # Windows에서 conf.iface가 엉뚱한 가상 어댑터를 잡는 것을 방지하기 위해 라우팅 테이블 조회
                target_iface = conf.route.route('8.8.8.8')[0]
                print(f"[INFO] 활성 네트워크 어댑터 자동 감지: {target_iface}")
            except Exception:
                pass

        if target_iface:
            print(f"[INFO] 캡처 시작 (어댑터: {target_iface})...")
        else:
            print("[INFO] 캡처 시작 (전체/기본 어댑터)...")
            
        while self._running:
            try:
                if target_iface:
                    sniff(iface=target_iface, prn=self._packet_handler, store=False, timeout=1.0)
                else:
                    sniff(prn=self._packet_handler, store=False, timeout=1.0)
            except Exception as e:
                print(f"[WARNING] 패킷 캡처 중 오류 발생 (무시하고 계속 진행): {e}")
                time.sleep(0.5) # 오류가 반복될 경우 CPU 과부하 방지

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
def set_incident_start_callback(cb):
    PacketSniffer().set_incident_start_callback(cb)

def set_incident_callback(cb): _instance.set_incident_callback(cb)
def set_pause(paused): _instance.set_pause(paused)
def set_aliases_policy(policies): _instance.set_aliases_policy(policies)
def set_filter(f_dict): _instance.set_filter(f_dict)
def start_sniffing(): _instance.start()
def stop_sniffing(): _instance.stop()
