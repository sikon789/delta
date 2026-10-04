"""Delta 解卡服务(带 QQ 白名单 + 代理接口)

用法:
    原 api_server.py 改名 core_server.py,本文件放同目录。

接口:
    GET  /ping                      心跳(给 cron-job 保活)
    GET  /proxy?q=<QQ>&l=<链接>      解卡(客户端调这个,无需 token)
    GET  /proxy?q=<QQ>&a=t          拉配置(文案/地址)
    GET  /admin?key=<管理密钥>       白名单管理页
"""

import os
import sys
import time
import json
import uuid
import asyncio
import hashlib
import threading
from collections import deque, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import JSONResponse, HTMLResponse

try:
    import core_server as CORE
except Exception as e:
    raise SystemExit("找不到 core_server.py") from e

from core_server import solve_chain
from auth_client import extract_ticket, MIN_TICKET_LEN, get_session_status
import auth_client as AUTH

# ============ 配置 ============
API_TOKEN = os.environ.get("DELTA_API_TOKEN", "")
ADMIN_KEY = os.environ.get("DELTA_ADMIN_KEY", "")
DATA_DIR = os.environ.get("DELTA_DATA_DIR", "/tmp/delta")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
LOG_FILE = os.path.join(DATA_DIR, "access.log")

MAX_URL_LENGTH = 4096
TASK_TTL = 600.0
CACHE_TTL = 300.0

# 文案(藏服务端)
MSG_START = (
    "检测到忍者执行器链接，正在尝试绕过\n"
    "1过期链接🔗发了没木\n"
    "2.同一链接重发没亩\n"
    "3.若无响应请直接艾特，艾特后无结果请自行解密\n"
    "4.若输出卡密不可用请30s后获取新链接发送"
)
MSG_FOOTER = "by司空"
MSG_OK = "卡密 [卡密]"
MSG_FAIL = "解密失败"
MSG_TIME = "获取卡密耗时 {t} 秒"     # {t} 会被替换成实际秒数

# 链接校验:域名后缀
ALLOW_SUFFIX = "platorelay.com"


def is_card_link(url):
    """域名必须是 platorelay.com 或 xxx.platorelay.com"""
    if not url or len(url) > MAX_URL_LENGTH:
        return False
    low = url.lower()
    if not low.startswith("https://"):
        return False
    after = low.index("://") + 3
    slash = low.find("/", after)
    host = low[after:] if slash < 0 else low[after:slash]
    if ":" in host:
        host = host.split(":")[0]
    return host == ALLOW_SUFFIX or host.endswith("." + ALLOW_SUFFIX)

app = FastAPI(title="Delta Cardkey", default_response_class=JSONResponse)

_lock = threading.Lock()
_tasks = {}
_cache = {}
_started_at = time.time()


# ============ 数据文件 ============
def _ensure_dir():
    if not os.path.isdir(DATA_DIR):
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
        except Exception:
            pass


def load_users():
    _ensure_dir()
    if not os.path.isfile(USERS_FILE):
        return {}
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def save_users(u):
    _ensure_dir()
    try:
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(u, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def log_access(qq, action, extra=""):
    _ensure_dir()
    try:
        line = "%s | qq=%s | %s | %s\n" % (
            time.strftime("%Y-%m-%d %H:%M:%S"), qq, action, extra)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass


def check_qq(qq):
    qq = (qq or "").strip()
    if not qq.isdigit() or not (4 <= len(qq) <= 12):
        return False, "QQ 号格式不对"
    users = load_users()
    if qq not in users:
        return False, "你没有使用权限"
    u = users[qq]
    exp = int(u.get("exp", 0) or 0)
    if exp > 0 and time.time() > exp:
        return False, "你的授权已过期"
    return True, ""


# ============ 任务管理 ============
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
                                       error="该链接需要先完成验证解锁",
                                       times=time.time() - started)
        else:
            with _lock:
                _tasks[task_id].update(state="done", key=None,
                                       error="未获得有效 key",
                                       times=time.time() - started)
    except Exception as exc:
        with _lock:
            _tasks[task_id].update(state="done", key=None,
                                   error="异常 %s" % type(exc).__name__,
                                   times=time.time() - started)
    finally:
        _gc()


# ============ 心跳 ============
@app.get("/ping")
async def ping():
    return {"ok": True, "t": round(time.time(), 3),
            "up": round(time.time() - _started_at, 1), "tasks": len(_tasks)}


@app.get("/health")
async def health():
    return {"ok": True, "uptime": round(time.time() - _started_at, 1)}


# ============ 代理接口(客户端调这个) ============
@app.get("/proxy")
async def proxy(request: Request, q: str = "", l: str = "", a: str = ""):
    # 拉配置
    if a == "t":
        ok, why = check_qq(q)
        if not ok:
            log_access(q, "deny", why)
            return JSONResponse({"ok": False, "e": why}, status_code=403)
        return {
            "ok": True,
            "u": "",                 # 客户端不需要换地址
            "a": MSG_START,
            "b": MSG_FOOTER,
            "c": MSG_OK,
            "d": MSG_FAIL,
            "e": "0",
            "f": MSG_TIME,           # 耗时模板,{t} 替换成秒数
        }

    # 解卡
    ok, why = check_qq(q)
    if not ok:
        log_access(q, "deny", why)
        return JSONResponse({"ok": False, "e": why}, status_code=403)

    if not l:
        return JSONResponse({"ok": False, "e": "缺少链接"}, status_code=400)
    if len(l) > MAX_URL_LENGTH:
        return JSONResponse({"ok": False, "e": "链接过长"}, status_code=413)
    if not is_card_link(l):
        log_access(q, "badlink", l[:60])
        return {"ok": False, "e": "不是有效的卡密链接"}

    started = time.time()
    try:
        ticket = extract_ticket(l)
    except Exception:
        ticket = ""
    if len(ticket) < MIN_TICKET_LEN:
        log_access(q, "badurl", "")
        return {"ok": False, "e": "无效链接"}

    cached = _cache_get(ticket)
    if cached:
        log_access(q, "cached", "")
        return {"ok": True, "k": cached, "t": "0.00"}

    task_id = uuid.uuid4().hex
    with _lock:
        _tasks[task_id] = {"state": "running", "key": None, "error": None,
                           "created": time.time(), "times": None}

    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _work, task_id, ticket)

    with _lock:
        t = dict(_tasks.get(task_id, {}))

    elapsed = time.time() - started
    if t.get("key"):
        log_access(q, "solve", "ok cost=%.2fs" % elapsed)
        return {"ok": True, "k": t["key"], "t": "%.2f" % elapsed}

    err = t.get("error") or MSG_FAIL
    log_access(q, "solve", "fail %s cost=%.2fs" % (err, elapsed))
    return {"ok": False, "e": err, "t": "%.2f" % elapsed}


# ============ 原始接口(带 token,给你自己用) ============
def _authorized(v):
    return bool(API_TOKEN) and v == "Bearer " + API_TOKEN


@app.post("/solve")
async def solve_async(request: Request, url: str,
                      authorization: str = Header(default=None)):
    if not _authorized(authorization):
        raise HTTPException(401, "unauthorized")
    if len(url) > MAX_URL_LENGTH:
        raise HTTPException(413, "url too long")

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
    return {"task_id": task_id, "state": snap["state"], "key": snap["key"],
            "error": snap["error"],
            "times": ("%.3fs" % snap["times"]) if snap["times"] else None}


@app.get("/delta")
async def delta_sync(request: Request, url: str,
                     authorization: str = Header(default=None)):
    if not _authorized(authorization):
        raise HTTPException(401, "unauthorized")
    if len(url) > MAX_URL_LENGTH:
        raise HTTPException(413, "url too long")

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
        return {"key": None, "error": "解卡超时(90s)"}

    result_ticket = getattr(timer, "result_ticket", None) or ticket
    confirmed = await loop.run_in_executor(None, _confirmed, result_ticket)
    if confirmed:
        _cache_put(ticket, confirmed)
        return {"key": confirmed, "cached": False, "error": None,
                "times": "%.3fs" % (time.time() - started)}
    if getattr(timer, "oauth_locked", False):
        return {"key": None, "error": "该链接需要先完成验证解锁"}
    return {"key": None, "error": "未获得有效 key"}


# ============ 管理后台 ============
@app.get("/admin", response_class=HTMLResponse)
async def admin(key: str = "", action: str = "", qq: str = "", days: str = "0",
                note: str = ""):
    if not ADMIN_KEY or key != ADMIN_KEY:
        return HTMLResponse("<h2>404</h2>", status_code=404)

    users = load_users()

    if action == "add" and qq:
        qq = qq.strip()
        if qq.isdigit():
            try:
                d = int(days or 0)
            except Exception:
                d = 0
            if d == 0:
                exp = 0                     # 0 = 永久
            else:
                exp = int(time.time()) + d * 86400   # 负数 = 已过期
            users[qq] = {"exp": exp, "note": note}
            save_users(users)
    elif action == "del" and qq:
        users.pop(qq.strip(), None)
        save_users(users)
    elif action == "renew" and qq:
        qq = qq.strip()
        if qq in users:
            base = max(int(time.time()), int(users[qq].get("exp", 0) or 0))
            users[qq]["exp"] = base + 30 * 86400
            save_users(users)

    rows = []
    for k, v in sorted(users.items()):
        exp = int(v.get("exp", 0) or 0)
        if exp <= 0:
            st = '<span style="color:#8e8e93">永久</span>'
        elif time.time() > exp:
            st = '<span style="color:#ff453a">已过期</span>'
        else:
            st = '<span style="color:#30d158">%s</span>' % time.strftime("%Y-%m-%d", time.localtime(exp))
        rows.append(
            '<tr><td style="font-family:monospace">%s</td><td>%s</td><td>%s</td>'
            '<td><a href="?key=%s&action=del&qq=%s">删</a> '
            '<a href="?key=%s&action=renew&qq=%s">+30天</a></td></tr>'
            % (k, st, v.get("note", ""), key, k, key, k))

    html = """<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>白名单</title>
<style>
body{font-family:-apple-system,"PingFang SC",sans-serif;background:#000;color:#fff;padding:20px;margin:0}
h1{font-size:20px}
table{width:100%%;border-collapse:collapse;margin:16px 0;font-size:14px}
td,th{padding:10px;border-bottom:1px solid #2c2c2e;text-align:left}
th{color:#8e8e93;font-size:12px}
input,button{padding:10px;border-radius:10px;border:1px solid #3a3a3c;background:#1c1c1e;color:#fff;font-size:15px;font-family:inherit}
button{background:#0a84ff;border:none;font-weight:600}
a{color:#0a84ff;text-decoration:none;margin-right:8px}
form{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
</style></head><body>
<h1>Delta 白名单</h1>
<form method="get">
<input type="hidden" name="key" value="%s">
<input type="hidden" name="action" value="add">
<input name="qq" placeholder="QQ 号" required style="width:130px">
<input name="days" value="0" style="width:60px">
<input name="note" placeholder="备注" style="width:100px">
<button type="submit">添加</button>
</form>
<table><tr><th>QQ</th><th>状态</th><th>备注</th><th>操作</th></tr>
%s
</table>
<p style="color:#636366;font-size:12px">天数填 0 = 永久</p>
</body></html>""" % (key, "".join(rows))

    return HTMLResponse(html)


@app.on_event("startup")
async def _startup():
    if not API_TOKEN:
        raise SystemExit("DELTA_API_TOKEN 环境变量必须设置")
    _ensure_dir()
    try:
        AUTH.start_version_watcher()
    except Exception:
        pass
    print("[boot] token_len=%d admin=%s data=%s" % (len(API_TOKEN), bool(ADMIN_KEY), DATA_DIR))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
