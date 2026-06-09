"""
app.py
──────
FastAPI 기반 실시간 패킷 모니터링 서버.
WebSocket으로 패킷 스트리밍, REST API로 분석/필터/설정 관리.
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import asyncio
import threading
import time
import logging
import concurrent.futures
import json
from pathlib import Path
from contextlib import asynccontextmanager

from database import start_db_writer, query_history, query_highlight_history, query_device_history, query_suspicious_packets, query_suspicious_ips, delete_history_packets, delete_highlight_packets, delete_device_packets, delete_device_all_packets, delete_suspicious_packets, get_aliases, set_alias, delete_alias, get_rules, save_rules
from sniffer import start_sniffing, set_pause, set_filter, set_emit_callback, set_packet_rules, set_aliases_policy, save_pcap
from ai import analyze_packet_data, assess_ip_risk

# ─── 전역 상태 변수 ───────────────────────────────────────────
_main_loop: asyncio.AbstractEventLoop | None = None
_ws_clients: set[WebSocket] = set()
_ws_lock = asyncio.Lock()
_packet_queue = asyncio.Queue(maxsize=20000)

# ─── Lifespan ─────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """서버 시작/종료 시 자원 관리"""
    global _main_loop
    _main_loop = asyncio.get_running_loop()

    # DB 초기화 및 백그라운드 워커 시작
    start_db_writer()

    # DB에서 저장된 패킷 규칙 복원
    try:
        saved_rules = get_rules()
        if saved_rules:
            set_packet_rules(saved_rules)
            print(f"[INFO] DB에서 패킷 규칙 {len(saved_rules)}개 복원 완료")
    except Exception as e:
        print(f"[WARNING] 패킷 규칙 복원 실패: {e}")

    try:
        aliases = get_aliases()
        set_aliases_policy(aliases)
    except Exception as e:
        print(f"[WARNING] 별명 정책 복원 실패: {e}")

    # sniffer 콜백 등록
    set_emit_callback(sync_broadcast)

    # 패킷 캡쳐 시작 (새로 구현된 AsyncSniffer가 스레드 풀을 내부적으로 관리함)
    start_sniffing()

    # 패킷 배치 전송 워커
    asyncio.create_task(packet_batch_worker())

    yield

    # 종료 시 스니퍼 정지
    from sniffer import stop_sniffing
    stop_sniffing()


app = FastAPI(lifespan=lifespan)

# 정적 파일 및 템플릿 설정
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


# ─── WebSocket 브로드캐스트 ───────────────────────────────────
async def broadcast(event: str, data: dict):
    """연결된 모든 WebSocket 클라이언트에 메시지를 브로드캐스트합니다."""
    message = json.dumps({"event": event, "data": data}, ensure_ascii=False)
    async with _ws_lock:
        dead = set()
        for ws in _ws_clients:
            try:
                await ws.send_text(message)
            except Exception:
                dead.add(ws)
        _ws_clients.difference_update(dead)


async def packet_batch_worker():
    """큐에 쌓인 패킷을 일정 시간마다 모아서 클라이언트에 전송합니다."""
    loop = asyncio.get_running_loop()
    while True:
        try:
            packets = []
            # 첫 번째 패킷 대기 (이벤트 발생 시까지 휴면)
            first_pkt = await _packet_queue.get()
            packets.append(first_pkt)

            start_time = loop.time()
            while len(packets) < 100:
                elapsed = loop.time() - start_time
                if elapsed >= 0.1:
                    break
                try:
                    pkt = await asyncio.wait_for(_packet_queue.get(), timeout=0.1 - elapsed)
                    packets.append(pkt)
                except asyncio.TimeoutError:
                    break

            if packets:
                await broadcast('new_packets', packets)

        except Exception as e:
            print(f"[DEBUG] Batch worker error: {e}")
            await asyncio.sleep(0.1)


def sync_broadcast(event: str, data: dict):
    """동기 코드(sniffer 콜백 등)에서 패킷을 큐에 넣거나 즉시 브로드캐스트합니다."""
    if not _main_loop or not _main_loop.is_running():
        return

    if event == 'new_packet':
        try:
            # 큐가 가득 차면 put_nowait은 QueueFull을 던집니다.
            _main_loop.call_soon_threadsafe(_packet_queue.put_nowait, data)
        except Exception:
            # 큐가 가득 찬 경우 등 예외 발생 시 패킷을 무시하여 시스템을 보호합니다.
            pass
    else:
        try:
            asyncio.run_coroutine_threadsafe(broadcast(event, data), _main_loop)
        except Exception as e:
            print(f"[DEBUG] Broadcast error: {e}")


# sniffer.py 콜백 등록
set_emit_callback(sync_broadcast)


# ─── 라우트: 페이지 ──────────────────────────────────────────
@app.get('/', response_class=HTMLResponse)
async def index(request: Request):
    start_db_writer()
    response = templates.TemplateResponse(request, "index.html")
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


# ─── 라우트: WebSocket ───────────────────────────────────────
@app.websocket('/ws')
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    client_host = ws.client.host if ws.client else "unknown"
    print(f"[INFO] WebSocket 연결됨: {client_host}")
    async with _ws_lock:
        _ws_clients.add(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        print(f"[INFO] WebSocket 연결 끊김: {client_host}")
    finally:
        async with _ws_lock:
            _ws_clients.discard(ws)


# ─── 라우트: 패킷 제어 ──────────────────────────────────────
@app.post('/api/toggle-pause')
async def api_toggle_pause(request: Request):
    try:
        data = await request.json()
        is_paused = data.get('paused', False)
        set_pause(is_paused)
        return JSONResponse({"success": True, "paused": is_paused})
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@app.post('/api/set-filter')
async def api_set_filter(request: Request):
    try:
        data = await request.json()
        new_filter = {
            'ip': data.get('ip', '').strip(),
            'port': data.get('port', '').strip(),
            'proto': data.get('proto', '').strip(),
            'dir': data.get('dir', '').strip(),
            'min_size': data.get('min_size', '').strip(),
            'max_size': data.get('max_size', '').strip(),
        }
        set_filter(new_filter)
        return JSONResponse({"success": True, "filter": new_filter})
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


# ─── 라우트: DB 조회/삭제 ────────────────────────────────────
@app.post('/api/history')
async def api_history(request: Request):
    try:
        data = await request.json()
        ret = await asyncio.to_thread(query_history, data)
        return JSONResponse({"success": True, "data": ret["data"], "total": ret["total"]})
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)

@app.post('/api/device-history')
async def api_device_history(request: Request):
    try:
        data = await request.json()
        ret = await asyncio.to_thread(query_device_history, data)
        return JSONResponse({"success": True, "data": ret["data"], "total": ret["total"]})
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@app.post('/api/highlight-history')
async def api_highlight_history(request: Request):
    try:
        data = await request.json()
        ret = await asyncio.to_thread(query_highlight_history, data)
        return JSONResponse({"success": True, "data": ret["data"], "total": ret["total"]})
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@app.post('/api/suspicious-history')
async def api_suspicious_history(request: Request):
    try:
        data = await request.json()
        ret = await asyncio.to_thread(query_suspicious_packets, data)
        return JSONResponse({"success": True, "data": ret["data"], "total": ret["total"]})
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)

@app.get('/api/suspicious-ips')
async def api_suspicious_ips():
    try:
        data = await asyncio.to_thread(query_suspicious_ips)
        return JSONResponse({"success": True, "data": data})
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@app.post('/api/delete-packets')
async def api_delete_packets(request: Request):
    try:
        data = await request.json()
        db_type = data.get('db_type', 'ARCHIVE')
        ids = data.get('ids', [])
        if db_type == 'HIGHLIGHT':
            deleted_count = await asyncio.to_thread(delete_highlight_packets, ids)
        elif db_type == 'DEVICE_DETAIL':
            deleted_count = await asyncio.to_thread(delete_device_packets, ids)
        elif db_type == 'SUSPICIOUS':
            deleted_count = await asyncio.to_thread(delete_suspicious_packets, ids)
        else:
            deleted_count = await asyncio.to_thread(delete_history_packets, ids)
        return JSONResponse({"success": True, "deleted": deleted_count})
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


# ─── 라우트: AI 분석 ──────────────────────────────────────────
@app.post('/api/ai-analyze')
async def api_ai_analyze(request: Request):
    try:
        data = await request.json()
        packets = data.get('packets', [])
        if not packets:
            return JSONResponse({"success": False, "error": "패킷 데이터가 없습니다."})
        result = await asyncio.to_thread(analyze_packet_data, packets)
        return JSONResponse({"success": True, "result": result})
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)

@app.post('/api/ai-risk-assess')
async def api_ai_risk_assess(request: Request):
    try:
        data = await request.json()
        ip = data.get('ip', '')
        if not ip:
            return JSONResponse({"success": False, "error": "IP 주소가 없습니다."})
        
        # IP에 관련된 최근 패킷 100개를 가져옵니다.
        # 기존 쿼리 함수 사용 (ip가 src이거나 dst인 경우 모두)
        query_data = {'ip': ip, 'page': 1, 'limit': 100}
        history = await asyncio.to_thread(query_device_history, query_data)
        packets = history.get("data", [])
        
        result = await asyncio.to_thread(assess_ip_risk, ip, packets)
        return JSONResponse({"success": True, "result": result})
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


# ─── 라우트: 패킷 규칙 ──────────────────────────────────────
@app.post('/api/set-rules')
async def api_set_rules(request: Request):
    try:
        data = await request.json()
        rules = data.get('rules', [])
        cleaned_rules = []
        for r in rules:
            action = r.get('action', 'HIGHLIGHT').strip().upper()
            if action not in ['HIGHLIGHT', 'IGNORE']:
                action = 'HIGHLIGHT'
            ip = r.get('ip', '').strip()
            port = r.get('port', '').strip()
            proto = r.get('proto', '').strip()
            direction = r.get('dir', '').strip()
            min_size = str(r.get('min_size', '')).strip()
            max_size = str(r.get('max_size', '')).strip()
            description = r.get('description', '').strip()

            if not any([ip, port, proto, direction, min_size, max_size]):
                continue

            cleaned_rules.append({
                'action': action, 'ip': ip, 'port': port, 'proto': proto,
                'dir': direction, 'min_size': min_size, 'max_size': max_size,
                'description': description,
            })
        set_packet_rules(cleaned_rules)
        save_rules(cleaned_rules)
        return JSONResponse({"success": True, "rules": cleaned_rules})
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@app.get('/api/rules')
async def api_get_rules():
    try:
        rules = get_rules()
        return JSONResponse({"success": True, "rules": rules})
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


# ─── 라우트: IP 별명 ─────────────────────────────────────────
@app.get('/api/aliases')
async def api_aliases_get():
    try:
        return JSONResponse({"success": True, "data": get_aliases()})
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@app.post('/api/aliases')
async def api_aliases_post(request: Request):
    try:
        data = await request.json()
        ip = data.get('ip', '').strip()
        name = data.get('name', '').strip()
        policy = data.get('policy', 'SAVE_ALL').strip()
        description = data.get('desc', '').strip()
        if not ip or not name:
            return JSONResponse({"success": False, "error": "IP와 이름이 모두 필요합니다."}, status_code=400)
        
        set_alias(ip, name, policy, description)
        set_aliases_policy(get_aliases())
        return JSONResponse({"success": True, "ip": ip, "name": name, "policy": policy})
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@app.delete('/api/aliases')
async def api_aliases_delete(request: Request):
    try:
        data = await request.json()
        ip = data.get('ip', '').strip()
        if not ip:
            return JSONResponse({"success": False, "error": "IP가 필요합니다."}, status_code=400)
        delete_alias(ip)
        delete_device_all_packets(ip)
        set_aliases_policy(get_aliases())
        return JSONResponse({"success": True, "ip": ip})
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@app.post('/api/export-pcap')
async def api_export_pcap(request: Request, background_tasks: BackgroundTasks):
    try:
        data = await request.json()
        packets = data.get('packets', [])
        if not packets:
            return JSONResponse({"success": False, "error": "내보낼 패킷이 없습니다."}, status_code=400)
        
        tmp_dir = Path(__file__).parent / "temp"
        tmp_dir.mkdir(exist_ok=True)
        filename = f"netscope_export_{int(time.time())}.pcap"
        file_path = tmp_dir / filename
        
        success = save_pcap(packets, str(file_path))
        if success:
            # 파일 전송 후 삭제 예약
            background_tasks.add_task(lambda p: p.unlink() if p.exists() else None, file_path)
            return FileResponse(path=str(file_path), filename=filename, media_type='application/octet-stream')
        else:
            return JSONResponse({"success": False, "error": "PCAP 생성 실패"}, status_code=500)
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


# ─── 라우트: 설정 ────────────────────────────────────────────
@app.get('/api/config')
async def api_config_get():
    config_path = Path(__file__).parent / "config.json"
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return JSONResponse({"success": True, "data": json.load(f)})
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@app.post('/api/config')
async def api_config_post(request: Request):
    config_path = Path(__file__).parent / "config.json"
    try:
        new_config = await request.json()
        if not new_config:
            return JSONResponse({"success": False, "error": "데이터가 없습니다."}, status_code=400)
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(new_config, f, indent=4, ensure_ascii=False)
        return JSONResponse({"success": True, "message": "설정이 저장 및 적용되었습니다."})
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@app.get('/api/interfaces')
async def api_interfaces():
    try:
        from scapy.arch.windows import get_windows_if_list
        if_list = get_windows_if_list()
        result = []
        for iface in if_list:
            if iface.get('description'):
                result.append({"name": iface.get('name'), "desc": iface.get('description')})
        return JSONResponse({"success": True, "data": result})
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e), "data": []}, status_code=500)


# ─── 엔트리포인트 ─────────────────────────────────────────────
if __name__ == '__main__':
    import uvicorn

    config_path = Path(__file__).parent / "config.json"
    _cfg = {}
    try:
        if config_path.exists():
            with open(config_path, "r", encoding="utf-8") as f:
                _cfg = json.load(f).get("server", {})
    except Exception:
        pass

    _host = _cfg.get("host", "0.0.0.0")
    _port = int(_cfg.get("port", 25565))

    print(f"서버 시작: http://{_host}:{_port}")
    uvicorn.run(app, host=_host, port=_port)

