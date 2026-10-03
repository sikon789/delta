import sys
import os
import time
import asyncio
import argparse
import hashlib
import threading
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from fastapi import FastAPI, HTTPException, Header, Request
import uvicorn
try:
    from fastapi.responses import ORJSONResponse as JSONResponse
except Exception:
    from fastapi.responses import JSONResponse

from main import solve_chain
from auth_client import extract_ticket, MIN_TICKET_LEN, get_session_status
import auth_client as AUTH

OAUTH_ERROR = "该链接需要先完成 Google/Discord 验证解锁后才能解卡（打开链接完成验证后重发即可）"
MAX_URL_LENGTH = 4096
MAX_INFLIGHT = 20
RATE_WINDOW = 60.0
RATE_LIMIT = 20
CACHE_TTL = 300.0
API_TOKEN = os.environ.get("DELTA_API_TOKEN", "")

app = FastAPI(title="Delta Cardkey", default_response_class=JSONResponse)
executor = ThreadPoolExecutor(max_workers=10, thread_name_prefix="solve")
state_lock = threading.Lock()
inflight = {}
cache = {}
client_hits = defaultdict(deque)
active_solves = 0


def fmt_t(secs):
    return f"{round(float(secs or 0.0), 12)}s"


def authorized(value):
    return bool(API_TOKEN) and value == f"Bearer {API_TOKEN}"


def allow_request(client_id):
    now = time.monotonic()
    with state_lock:
        hits = client_hits[client_id]
        while hits and now - hits[0] >= RATE_WINDOW:
            hits.popleft()
        if len(hits) >= RATE_LIMIT:
            return False
        hits.append(now)
        return True


def cache_get(ticket):
    digest = hashlib.sha256(ticket.encode()).hexdigest()
    with state_lock:
        record = cache.get(digest)
        if record and time.monotonic() - record["ts"] < CACHE_TTL:
            return record["key"], record["solve_time"]
        cache.pop(digest, None)
    return None, 0.0


def cache_put(ticket, key, solve_time):
    if not key:
        return
    digest = hashlib.sha256(ticket.encode()).hexdigest()
    with state_lock:
        cache[digest] = {"key": key, "ts": time.monotonic(), "solve_time": solve_time}


def confirmed_key(ticket):
    try:
        result = get_session_status(ticket)
        data = result.get("data", result) if isinstance(result, dict) else {}
        key = data.get("key")
        if result.get("success") is True and key and key != "KEY_NOT_FOUND":
            return key
    except Exception:
        pass
    return None


def solve_once(ticket):
    global active_solves
    with state_lock:
        if active_solves >= MAX_INFLIGHT:
            return None, "服务器当前任务过多，请稍后重试", 0.0
        active_solves += 1
    started = time.time()
    try:
        existing = confirmed_key(ticket)
        if existing:
            return existing, None, time.time() - started
        key, timer = solve_chain(ticket, verbose=False, max_rounds=3)
        result_ticket = getattr(timer, "result_ticket", None) or ticket
        confirmed = confirmed_key(result_ticket)
        if confirmed:
            return confirmed, None, time.time() - started
        if getattr(timer, "oauth_locked", False):
            return None, OAUTH_ERROR, time.time() - started
        return None, "未获得远端确认的有效 key", time.time() - started
    except Exception as exc:
        return None, f"solve exception: {type(exc).__name__}", time.time() - started
    finally:
        with state_lock:
            active_solves -= 1


@app.get("/delta")
async def delta(request: Request, url: str, authorization: str | None = Header(default=None)):
    started = time.time()
    if not authorized(authorization):
        raise HTTPException(status_code=401, detail="unauthorized")
    if len(url) > MAX_URL_LENGTH:
        raise HTTPException(status_code=413, detail="url too long")
    client_id = request.client.host if request.client else "unknown"
    if not allow_request(client_id):
        raise HTTPException(status_code=429, detail="rate limit exceeded")
    try:
        ticket = extract_ticket(url)
    except Exception:
        ticket = ""
    if len(ticket) < MIN_TICKET_LEN:
        return {"key": None, "error": "invalid url (no ticket)", "cached": False, "times": fmt_t(time.time() - started)}

    cached_key, cached_time = cache_get(ticket)
    if cached_key:
        confirmed = await asyncio.get_running_loop().run_in_executor(None, confirmed_key, ticket)
        if confirmed == cached_key:
            return {"key": confirmed, "cached": True, "error": None, "times": fmt_t(cached_time)}
        with state_lock:
            cache.pop(hashlib.sha256(ticket.encode()).hexdigest(), None)

    digest = hashlib.sha256(ticket.encode()).hexdigest()
    loop = asyncio.get_running_loop()
    with state_lock:
        future = inflight.get(digest)
        if future is None:
            future = loop.create_future()
            inflight[digest] = future
            owner = True
        else:
            owner = False
    if owner:
        loop.create_task(drive(digest, future, ticket))
    try:
        key, error, solve_time = await asyncio.shield(future)
    except Exception as exc:
        key, error, solve_time = None, f"internal: {type(exc).__name__}", time.time() - started
    return {"key": key, "cached": False, "error": error, "times": fmt_t(solve_time)}


async def drive(digest, future, ticket):
    try:
        key, error, solve_time = await asyncio.get_running_loop().run_in_executor(executor, solve_once, ticket)
        if key:
            cache_put(ticket, key, solve_time)
    except Exception as exc:
        key, error, solve_time = None, f"solve exception: {type(exc).__name__}", 0.0
    finally:
        with state_lock:
            inflight.pop(digest, None)
        if not future.done():
            future.set_result((key, error, solve_time))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", "-p", type=int, default=2233)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--workers", "-w", type=int, default=10)
    args = parser.parse_args()
    if not API_TOKEN:
        raise SystemExit("DELTA_API_TOKEN is required")
    AUTH.start_version_watcher()
    kwargs = {}
    try:
        import uvloop
        kwargs["loop"] = "uvloop"
    except Exception:
        pass
    try:
        import httptools
        kwargs["http"] = "httptools"
    except Exception:
        pass
    executor = ThreadPoolExecutor(max_workers=max(1, min(args.workers, MAX_INFLIGHT)), thread_name_prefix="solve")
    uvicorn.run(app, host=args.host, port=args.port, backlog=128, access_log=False, **kwargs)
