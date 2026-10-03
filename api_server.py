"""在原有 api_server 之上包一层:
   1. 加 /ping 心跳(给 cron-job.org 打,防止 Render 免费实例睡眠)
   2. 解卡改成后台任务 + task_id 轮询(避免 Render 网关 100s 超时)

用法:把原来的 api_server.py 改名成 core_server.py,本文件放在同目录。
"""

import os
import sys
import time
import uuid
import asyncio
import hashlib
import threading
from collections import deque, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from fastapi import FastAPI, HTTPException, Header, Request, BackgroundTasks
from fastapi.responses import JSONResponse
import uvicorn

try:
    import core_server as CORE
except Exception as e:
    raise SystemExit("找不到 core_server.py,先把原 api_server.py 改名成 core_server.py") from e

from core_server import solve_chain
from auth_client import extract_ticket, MIN_TICKET_LEN, get_session_status
import auth_client as AUTH

API_TOKEN = os.environ.get("DELTA_API_TOKEN", "")
MAX_URL_LENGTH = 4096
RATE_WINDOW = 60.0
RATE_LIMIT = 20
TASK_TTL = 600.0
CACHE_TTL = 300.0

app = FastAPI(title="Delta Cardkey (Render)", default_response_class=JSONResponse)

_lock = threading.Lock()
_tasks = {}
_cache = {}
_client_hits = defaultdict(deque)
_started_at = time.time()
_last_ping = time.time()


def _authorized(v):
    return bool(API_TOKEN) and v == f"Bearer {API_TOKEN}"


def _allow(client_id):
    now = time.monotonic()
    with _lock:
        hits = _client_hits[client_id]
        while hits and now - hits[0] >= RATE_WINDOW:
            hits.popleft()
        if len(hits) >= RATE_LIMIT:
            return False
        hits.append(now)
        return True


def _gc():
    now = time.time()
    with _lock:
        for k in [k for k, v in _tasks.items() if now - v["created"] > TASK_TTL]:
            _tasks.pop(k, None)
        for k in [k for k, v in _cache.items() if now - v["ts"] > CACHE_TTL]:
            _cache.pop(k, None)


def _cache_get(ticket):
    d = hashlib.sha256(ticket.encode()).hexdigest()
    with _lock:
        r = _cache.get(d)
        if r and time.time() - r["ts"] < CACHE_TTL:
            return r["key"]
    return None


def _cache_put(ticket, key):
    if not key:
        return
    d = hashlib.sha256(ticket.encode()).hexdigest()
    with _lock:
        _cache[d] = {"key": key, "ts": time.time()}


def _confirmed(ticket):
    try:
        r = get_session_status(ticket)
        data = r.get("data", r) if isinstance(r, dict) else {}
        k = data.get("key")
        if r.get("success") is True and k and k != "KEY_NOT_FOUND":
            return k
    except Exception:
        pass
    return None


def _work(task_id, ticket):
    started = time.time()
    try:
        existing = _confirmed(ticket)
        if existing:
            with _lock:
                _tasks[task_id].update(state="done", key=existing, error=None,
                                       times=time.time() - started)
            return

        key, timer = solve_chain(ticket, verbose=False, max_rounds=3)
        result_ticket = getattr(timer, "result_ticket", None) or ticket
        confirmed = _confirmed(result_ticket)

        if confirmed:
            _cache_put(ticket, confirmed)
            with _lock:
                _tasks[task_id].update(state="done", key=confirmed, error=None,
                                       times=time.time() - started)
        elif getattr(timer, "oauth_locked", False):
            with _lock:
                _tasks[task_id].update(state="done", key=None,
                                       error="该链接需要先完成验证解锁", times=time.time() - started)
        else:
            with _lock:
                _tasks[task_id].update(state="done", key=None,
                                       error="未获得有效 key", times=time.time() - started)
    except Exception as exc:
        with _lock:
            _tasks[task_id].update(state="done", key=None,
                                   error=f"异常 {type(exc).__name__}", times=time.time() - started)
    finally:
        _gc()


@app.get("/ping")
async def ping():
    global _last_ping
    _last_ping = time.time()
    return {
        "ok": True,
        "t": round(time.time(), 3),
        "up": round(time.time() - _started_at, 1),
        "tasks": len(_tasks),
    }


@app.get("/health")
async def health():
    return {"ok": True, "uptime": round(time.time() - _started_at, 1)}


@app.post("/solve")
async def solve_async(request: Request, url: str,
                      authorization: str | None = Header(default=None)):
    if not _authorized(authorization):
        raise HTTPException(401, "unauthorized")
    if len(url) > MAX_URL_LENGTH:
        raise HTTPException(413, "url too long")
    cid = request.client.host if request.client else "unknown"
    if not _allow(cid):
        raise HTTPException(429, "rate limit exceeded")

    try:
        ticket = extract_ticket(url)
    except Exception:
        ticket = ""
    if len(ticket) < MIN_TICKET_LEN:
        return {"task_id": None, "error": "invalid url (no ticket)"}

    cached = _cache_get(ticket)
    if cached:
        return {"task_id": None, "key": cached, "cached": True, "error": None}

    task_id = uuid.uuid4().hex
    with _lock:
        _tasks[task_id] = {"state": "running", "key": None, "error": None,
                           "created": time.time(), "times": None}
    threading.Thread(target=_work, args=(task_id, ticket), daemon=True).start()
    return {"task_id": task_id, "state": "running", "cached": False}


@app.get("/result")
async def result(task_id: str):
    with _lock:
        t = _tasks.get(task_id)
        if not t:
            raise HTTPException(404, "task not found or expired")
        snap = dict(t)
    return {
        "task_id": task_id,
        "state": snap["state"],
        "key": snap["key"],
        "error": snap["error"],
        "times": f"{round(snap['times'], 3)}s" if snap["times"] else None,
    }


@app.get("/delta")
async def delta_sync(request: Request, url: str,
                     authorization: str | None = Header(default=None)):
    """兼容旧接口:同步等待。注意 Render 网关约 100s 上限,长任务请用 /solve + /result。"""
    if not _authorized(authorization):
        raise HTTPException(401, "unauthorized")
    if len(url) > MAX_URL_LENGTH:
        raise HTTPException(413, "url too long")
    cid = request.client.host if request.client else "unknown"
    if not _allow(cid):
        raise HTTPException(429, "rate limit exceeded")

    try:
        ticket = extract_ticket(url)
    except Exception:
        ticket = ""
    if len(ticket) < MIN_TICKET_LEN:
        return {"key": None, "error": "invalid url (no ticket)"}

    cached = _cache_get(ticket)
    if cached:
        return {"key": cached, "cached": True, "error": None}

    started = time.time()
    loop = asyncio.get_running_loop()
    try:
        key, timer = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: solve_chain(ticket, verbose=False, max_rounds=3)),
            timeout=90)
    except asyncio.TimeoutError:
        return {"key": None, "cached": False, "error": "解卡超时(90s)", "times": "90s"}

    result_ticket = getattr(timer, "result_ticket", None) or ticket
    confirmed = await loop.run_in_executor(None, _confirmed, result_ticket)
    if confirmed:
        _cache_put(ticket, confirmed)
        return {"key": confirmed, "cached": False, "error": None,
                "times": f"{round(time.time() - started, 3)}s"}
    if getattr(timer, "oauth_locked", False):
        return {"key": None, "cached": False, "error": "该链接需要先完成验证解锁",
                "times": f"{round(time.time() - started, 3)}s"}
    return {"key": None, "cached": False, "error": "未获得有效 key",
            "times": f"{round(time.time() - started, 3)}s"}


@app.on_event("startup")
async def _startup():
    if not API_TOKEN:
        raise SystemExit("DELTA_API_TOKEN 环境变量必须设置")
    try:
        AUTH.start_version_watcher()
    except Exception:
        pass
    print(f"[boot] port={os.environ.get('PORT')} token_len={len(API_TOKEN)}")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
