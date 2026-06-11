"""
database.py
───────────
SQLite 기반 패킷/규칙/별명 데이터 관리 모듈.
백그라운드 스레드에서 배치 단위로 DB에 기록하여 성능을 확보합니다.
"""

import sqlite3
import threading
import queue
import time
from pathlib import Path

DB_FILE = Path(__file__).parent / "packets.db"


class DBManager:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.packet_queue = queue.Queue(maxsize=10000)
        self.db_thread = None
        self.running = False
        self._local = threading.local()

    def get_conn(self):
        """현재 스레드에 특화된 DB 커넥션을 반환합니다 (커넥션 재사용)"""
        if not hasattr(self._local, 'conn'):
            conn = sqlite3.connect(self.db_path, timeout=15.0)
            conn.row_factory = sqlite3.Row
            # WAL 모드는 파일 레벨에서 유지되나 pragma 캐시 등은 커넥션별 최적화가 가능합니다.
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA cache_size=-128000")
            conn.execute("PRAGMA temp_store=MEMORY")
            self._local.conn = conn
        return self._local.conn

    # ─── 초기화 ──────────────────────────────────────────────
    def init_db(self):
        """데이터베이스 파일 및 테이블 생성"""
        conn = self.get_conn()
        conn.execute("PRAGMA journal_mode=WAL")
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                src TEXT,
                dst TEXT,
                proto TEXT,
                size INTEGER,
                direction TEXT,
                summary TEXT,
                raw_hex TEXT,
                is_saved INTEGER DEFAULT 0,
                is_highlighted INTEGER DEFAULT 0,
                is_suspicious INTEGER DEFAULT 0,
                suspicion_reason TEXT DEFAULT ''
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incident_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                trigger_ip TEXT NOT NULL,
                trigger_reason TEXT,
                report_text TEXT NOT NULL,
                raw_packets TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_aliases (
                ip TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                policy TEXT DEFAULT 'SAVE_ALL',
                description TEXT DEFAULT ''
            )
        """)
        # 성능 향상을 위한 인덱스 생성
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_saved ON packets(is_saved)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(src)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_dst ON packets(dst)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_proto ON packets(proto)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_src_dst ON packets(src, dst)")

        try:
            cursor.execute("ALTER TABLE ip_aliases ADD COLUMN policy TEXT DEFAULT 'SAVE_ALL'")
        except sqlite3.OperationalError:
            pass
            
        try:
            cursor.execute("ALTER TABLE ip_aliases ADD COLUMN description TEXT DEFAULT ''")
        except sqlite3.OperationalError:
            pass

        try:
            cursor.execute("ALTER TABLE packets ADD COLUMN is_suspicious INTEGER DEFAULT 0")
            cursor.execute("ALTER TABLE packets ADD COLUMN suspicion_reason TEXT DEFAULT ''")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_suspicious ON packets(is_suspicious)")
        except sqlite3.OperationalError:
            pass

        try:
            cursor.execute("ALTER TABLE packets ADD COLUMN sport INTEGER")
            cursor.execute("ALTER TABLE packets ADD COLUMN dport INTEGER")
        except sqlite3.OperationalError:
            pass

        try:
            cursor.execute("ALTER TABLE packets ADD COLUMN is_suspicious INTEGER DEFAULT 0")
            cursor.execute("ALTER TABLE packets ADD COLUMN suspicion_reason TEXT DEFAULT ''")
        except sqlite3.OperationalError:
            pass

        try:
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_sport ON packets(sport)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_dport ON packets(dport)")
        except sqlite3.OperationalError:
            pass

        conn.commit()

    # ─── 백그라운드 DB Writer ──────────────────────────────────
    def _db_worker(self):
        """백그라운드에서 큐의 데이터를 꺼내어 DB에 저장하는 스레드"""
        conn = self.get_conn()
        cursor = conn.cursor()
        batch_size = 50

        while self.running or not self.packet_queue.empty():
            items = []
            try:
                # 불필요한 대기 방지: 먼저 하나를 대기 없이 또는 짧은 대기로 가져옴
                items.append(self.packet_queue.get(timeout=0.1))
                # 큐에 남은 것들을 한 번에 배치 사이즈만큼 싹 쓸어옴
                while len(items) < batch_size and not self.packet_queue.empty():
                    try:
                        items.append(self.packet_queue.get_nowait())
                    except queue.Empty:
                        break
            except queue.Empty:
                continue

            if items:
                try:
                    with conn:
                        cursor.executemany("""
                            INSERT INTO packets (timestamp, src, dst, sport, dport, proto, size, direction, summary, raw_hex, is_saved, is_suspicious, suspicion_reason)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, items)
                except Exception as e:
                    import traceback
                    print(f"[DB ERROR] _db_worker insert failed: {e}")
                    traceback.print_exc()

                for _ in items:
                    self.packet_queue.task_done()

    def start_writer(self):
        """비동기 DB 저장 스레드 시작"""
        if self.running:
            return

        self.init_db()
        self.running = True
        self.db_thread = threading.Thread(target=self._db_worker, daemon=True)
        self.db_thread.start()

    def save_packet_async(self, packet_data: dict, time_str: str, is_saved: bool, is_suspicious: bool = False, suspicion_reason: str = ""):
        """패킷을 큐에 적재합니다."""
        if not self.running:
            return

        row = (
            time_str,
            packet_data.get("src"),
            packet_data.get("dst"),
            packet_data.get("sport"),
            packet_data.get("dport"),
            packet_data.get("proto"),
            packet_data.get("len", 0),
            packet_data.get("direction"),
            packet_data.get("summary"),
            packet_data.get("raw"),
            int(is_saved),
            int(is_suspicious),
            suspicion_reason
        )
        self.packet_queue.put(row)

    # ─── 조회 ──────────────────────────────────────────────────
    def query_history(self, filters: dict, db_type: str = 'ARCHIVE'):
        """저장된 패킷 이력과 총 개수를 조회합니다."""
        conn = self.get_conn()
        try:
            cursor = conn.cursor()
            where_clause = " FROM packets WHERE 1=1"

            if db_type == 'ARCHIVE':
                where_clause += " AND is_saved = 1"
            elif db_type == 'SUSPICIOUS':
                where_clause += " AND is_suspicious = 1"
            # If 'ALL', do not filter by is_highlighted, is_saved, or is_suspicious

            params = []

            f_ip = filters.get("ip", "").strip()
            if f_ip:
                where_clause += " AND (src LIKE ? OR dst LIKE ?)"
                params.extend([f"{f_ip}%", f"{f_ip}%"])

            f_port = filters.get("port", "").strip()
            if f_port:
                try:
                    port_val = int(f_port)
                    where_clause += " AND (sport = ? OR dport = ?)"
                    params.extend([port_val, port_val])
                except ValueError:
                    pass

            f_proto = filters.get("proto", "").strip()
            if f_proto:
                where_clause += " AND proto = ?"
                params.append(f_proto.upper())

            f_dir = filters.get("dir", "").strip()
            if f_dir:
                where_clause += " AND direction = ?"
                params.append(f_dir.upper())

            f_min = filters.get("min_size", "").strip()
            if f_min.isdigit():
                where_clause += " AND size >= ?"
                params.append(int(f_min))

            f_max = filters.get("max_size", "").strip()
            if f_max.isdigit():
                where_clause += " AND size <= ?"
                params.append(int(f_max))

            f_start = filters.get("start_time", "").strip()
            if f_start:
                where_clause += " AND timestamp >= ?"
                params.append(f_start)

            f_end = filters.get("end_time", "").strip()
            if f_end:
                where_clause += " AND timestamp <= ?"
                params.append(f_end)

            # Total Count
            count_query = "SELECT COUNT(*)" + where_clause
            cursor.execute(count_query, params)
            total_count = cursor.fetchone()[0]

            # 페이징
            limit = int(filters.get("limit", 1000))
            page = int(filters.get("page", 1))
            offset = (page - 1) * limit

            data_query = "SELECT *" + where_clause + " ORDER BY id DESC LIMIT ? OFFSET ?"
            data_params = params + [limit, offset]

            cursor.execute(data_query, data_params)
            rows = cursor.fetchall()

            results = []
            for row in rows:
                results.append({
                    "no": row["id"],
                    "time": row["timestamp"],
                    "src": row["src"],
                    "dst": row["dst"],
                    "sport": row["sport"] if "sport" in row.keys() else None,
                    "dport": row["dport"] if "dport" in row.keys() else None,
                    "proto": row["proto"],
                    "len": row["size"],
                    "direction": row["direction"],
                    "summary": row["summary"],
                    "raw": row["raw_hex"],
                    "reason": row["suspicion_reason"] if "suspicion_reason" in row.keys() else ""
                })

            return {"data": results, "total": total_count}
        except Exception as e:
            print("[DB Error]", e)
            return {"data": [], "total": 0}

    def query_suspicious_ips(self) -> list:
        """의심 트래픽이 있는 IP 목록과 통계를 반환합니다."""
        conn = self.get_conn()
        try:
            cursor = conn.cursor()
            # 출발지 기준 의심 트래픽 집계
            cursor.execute("""
                SELECT src as ip, MAX(timestamp) as last_seen, COUNT(*) as count 
                FROM packets 
                WHERE is_suspicious = 1 
                GROUP BY src
                ORDER BY last_seen DESC
            """)
            rows = cursor.fetchall()
            return [{"ip": row["ip"], "last_seen": row["last_seen"], "count": row["count"]} for row in rows]
        except Exception as e:
            print("[DB Error query_suspicious_ips]", e)
            return []

    # ─── 사고 리포트 (Incident Reports) ──────────────────────────────
    def save_incident_report(self, ip: str, reason: str, report_text: str, packets_json: str):
        conn = self.get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO incident_reports (timestamp, trigger_ip, trigger_reason, report_text, raw_packets)
                VALUES (datetime('now', 'localtime'), ?, ?, ?, ?)
            """, (ip, reason, report_text, packets_json))
            conn.commit()
        except Exception as e:
            print("[DB Error save_incident_report]", e)

    def query_incident_reports(self) -> list:
        conn = self.get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT id, timestamp, trigger_ip, trigger_reason, report_text FROM incident_reports ORDER BY id DESC LIMIT 50")
            return [dict(row) for row in cursor.fetchall()]
        except Exception:
            return []

    def delete_incident_report(self, report_id: int):
        conn = self.get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM incident_reports WHERE id = ?", (report_id,))
            conn.commit()
        except Exception as e:
            print("[DB Error delete_incident_report]", e)

    # ─── 삭제 ──────────────────────────────────────────────────
    def delete_packets(self, ids: list[int], db_type: str = 'ARCHIVE') -> int:
        """지정된 id 목록에 해당하는 패킷들을 논리 삭제합니다."""
        if not ids:
            return 0
        conn = self.get_conn()
        try:
            cursor = conn.cursor()
            placeholders = ','.join(['?'] * len(ids))

            if db_type == 'ARCHIVE':
                cursor.execute(f"UPDATE packets SET is_saved = 0 WHERE id IN ({placeholders})", ids)
            elif db_type == 'SUSPICIOUS':
                cursor.execute(f"UPDATE packets SET is_suspicious = 0 WHERE id IN ({placeholders})", ids)
            else:
                cursor.execute(f"UPDATE packets SET is_saved = 0, is_suspicious = 0 WHERE id IN ({placeholders})", ids)

            # 모두 0이 되면 완전 삭제 (지정된 ID 범위 내에서만 처리하여 전체 스캔 방지)
            cursor.execute(f"DELETE FROM packets WHERE id IN ({placeholders}) AND is_saved = 0 AND is_suspicious = 0", ids)

            conn.commit()
            return len(ids)
        except Exception as e:
            print("[DB Error delete_packets]", e)
            return 0

    def delete_device_all_packets(self, ip: str) -> int:
        """특정 IP 장비와 관련된 모든 패킷을 영구적으로 삭제합니다."""
        conn = self.get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM packets WHERE src = ? OR dst = ?", (ip, ip))
            deleted_count = cursor.rowcount
            conn.commit()
            return deleted_count
        except Exception as e:
            print("[DB Error delete_device_all_packets]", e)
            return 0

    # ─── IP 별명 ───────────────────────────────────────────────
    def get_aliases(self) -> dict:
        conn = self.get_conn()
        try:
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT ip, name, policy, description FROM ip_aliases")
                rows = cursor.fetchall()
            except sqlite3.OperationalError:
                rows = []
            return {row["ip"]: {"name": row["name"], "policy": row["policy"] or 'SAVE_ALL', "description": row["description"] or ''} for row in rows}
        except Exception:
            return {}

    def set_alias(self, ip: str, name: str, policy: str = 'SAVE_ALL', description: str = ''):
        conn = self.get_conn()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("INSERT OR REPLACE INTO ip_aliases (ip, name, policy, description) VALUES (?, ?, ?, ?)", (ip, name, policy, description))
        except Exception as e:
            print("[DB Error set_alias]", e)

    def delete_alias(self, ip: str):
        conn = self.get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM ip_aliases WHERE ip = ?", (ip,))
            conn.commit()
        except Exception as e:
            print("[DB Error delete_alias]", e)


# ─── 전역 싱글턴 인스턴스 ─────────────────────────────────────
main_db = DBManager(DB_FILE)


def init_db():
    main_db.init_db()

def start_db_writer():
    main_db.start_writer()

def save_packet_async(packet_data: dict, time_str: str, is_saved: bool, is_suspicious: bool = False, suspicion_reason: str = ""):
    main_db.save_packet_async(packet_data, time_str, is_saved, is_suspicious, suspicion_reason)

def query_history(filters: dict):
    return main_db.query_history(filters, db_type='ARCHIVE')

def query_device_history(filters: dict):
    return main_db.query_history(filters, db_type='ALL')

def query_suspicious_packets(filters: dict):
    return main_db.query_history(filters, db_type='SUSPICIOUS')

def query_suspicious_ips():
    return main_db.query_suspicious_ips()

def delete_history_packets(ids: list[int]):
    return main_db.delete_packets(ids, db_type='ARCHIVE')

def delete_device_packets(ids: list[int]):
    return main_db.delete_packets(ids, db_type='ALL')

def delete_device_all_packets(ip: str) -> int:
    return main_db.delete_device_all_packets(ip)

def delete_suspicious_packets(ids: list[int]):
    return main_db.delete_packets(ids, db_type='SUSPICIOUS')

def get_aliases():
    return main_db.get_aliases()

def set_alias(ip: str, name: str, policy: str = 'SAVE_ALL', description: str = ''):
    main_db.set_alias(ip, name, policy, description)

def delete_alias(ip: str):
    main_db.delete_alias(ip)

def save_incident_report(ip: str, reason: str, report_text: str, packets_json: str):
    main_db.save_incident_report(ip, reason, report_text, packets_json)

def query_incident_reports():
    return main_db.query_incident_reports()

def delete_incident_report(report_id: int):
    main_db.delete_incident_report(report_id)
