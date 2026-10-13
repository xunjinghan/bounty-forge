"""t4 漏洞挖掘公共库：原始请求/响应取证封装（仅 127.0.0.1）。

纪律：
- 每条证据含 ISO8601 时间戳(+08:00)、原始请求行/头/体、原始响应状态行/头/体。
- 禁访问 /__reset（除显式 reset 动作外）。
"""
import http.client
import json
import time
from datetime import datetime, timezone, timedelta

TZ = timezone(timedelta(hours=8))
HOST = "127.0.0.1"
PORT = 8095
BODY_LIMIT = 4000


def now():
    return datetime.now(TZ).isoformat(timespec="seconds")


def raw_req(method, path, headers, body):
    lines = [f"{method} {path} HTTP/1.1"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    if body:
        lines.append("")
        lines.append(body if isinstance(body, str) else body.decode("utf-8", "replace"))
    return "\r\n".join(lines)


def raw_resp(status, reason, headers, body):
    lines = [f"HTTP/1.1 {status} {reason}"]
    for k, v in headers:
        lines.append(f"{k}: {v}")
    lines.append("")
    text = body if isinstance(body, str) else body.decode("utf-8", "replace")
    return "\r\n".join(lines)


def send(method, path, headers=None, body=None, port=PORT, host=HOST,
         record=None, note="", transport_timeout=20):
    """发一条 HTTP 请求并返回结构化记录（原始包在 req_raw/resp_raw）。"""
    hdrs = {"Host": f"{host}:{port}", "Connection": "close",
            "User-Agent": "dsh-hunter/1.0 (lab-only)"}
    if headers:
        hdrs.update(headers)
    if isinstance(body, str):
        body = body.encode("utf-8")
    if body is not None:
        hdrs.setdefault("Content-Length", str(len(body)))
    entry = {
        "ts": now(),
        "note": note,
        "target": f"http://{host}:{port}{path}",
        "request_line": f"{method} {path} HTTP/1.1",
        "request_headers": hdrs,
        "request_body": (body.decode("utf-8", "replace") if body else ""),
        "req_raw": raw_req(method, path, hdrs, body),
    }
    t0 = time.time()
    try:
        conn = http.client.HTTPConnection(host, port, timeout=transport_timeout)
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        resp_hdrs = resp.getheaders()
        entry.update({
            "status": resp.status,
            "reason": resp.reason,
            "response_headers": resp_hdrs,
            "response_body": data.decode("utf-8", "replace"),
            "body_len": len(data),
            "elapsed_ms": round((time.time() - t0) * 1000),
            "resp_raw": raw_resp(resp.status, resp.reason, resp_hdrs, data),
            "error": None,
        })
        conn.close()
    except Exception as exc:  # noqa: BLE001
        entry.update({"status": None, "reason": None, "response_headers": [],
                      "response_body": "", "body_len": 0,
                      "elapsed_ms": round((time.time() - t0) * 1000),
                      "resp_raw": f"<transport error: {type(exc).__name__}: {exc}>",
                      "error": f"{type(exc).__name__}: {exc}"})
    if record is not None:
        record.append(entry)
    return entry


def login(username, password, record=None, port=PORT, host=HOST, cookie_name="token",
          accept_status=(303, 302)):
    """两段式登录：先 GET /login 取匿名会话与 csrf_token，再 POST。

    8091 强制 CSRF（403 无 token），8095 带多余 csrf_token 无副作用。
    """
    import re as _re
    g = send("GET", "/login", record=record, port=port, host=host,
             note=f"login-step1 GET /login ({username})")
    cookie = None
    for k, v in g["response_headers"]:
        if k.lower() == "set-cookie" and v.startswith(cookie_name + "="):
            cookie = v.split(";")[0]
    tok = ""
    m = _re.search(r'name="csrf_token"[^>]*value="([^"]*)"', g["response_body"])
    if m:
        tok = m.group(1)
    hdrs = {"Content-Type": "application/x-www-form-urlencoded"}
    if cookie:
        hdrs["Cookie"] = cookie
    body = f"username={username}&password={password}"
    if tok:
        body += f"&csrf_token={tok}"
    r = send("POST", "/login", headers=hdrs, body=body, record=record,
             port=port, host=host, note=f"login {username}")
    newcookie = None
    for k, v in r["response_headers"]:
        if k.lower() == "set-cookie" and v.startswith(cookie_name + "=") and \
                not v.startswith(cookie_name + "=;"):
            val = v.split(";")[0]
            if val != cookie:
                newcookie = val
    if newcookie is None and r["status"] in (302, 303) and cookie:
        newcookie = cookie
    loc = ""
    for k, v in r["response_headers"]:
        if k.lower() == "location":
            loc = v
    r["cookie"] = newcookie
    r["location"] = loc
    return r, newcookie


def get_cookie(username, password, record=None, port=PORT, host=HOST,
               cookie_name="token"):
    r, c = login(username, password, record=record, port=port, host=host,
                 cookie_name=cookie_name)
    if not c:
        raise SystemExit(f"登录失败：{username} (port={port}, status={r['status']}, "
                         f"location={r.get('location')})")
    return c


def get_status(e):
    return e["status"] if e["status"] is not None else -1


def sent(record, *args, **kwargs):
    """send() 并返回该条证据在 record 中的下标（稳妥版）。"""
    idx = len(record)
    send(*args, record=record, **kwargs)
    return idx


def head_text(e, n=300):
    return e["response_body"][:n].replace("\n", " ")


def dump(record, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"generated": now(), "targets": [f"http://{HOST}:{PORT}"],
                   "entries": record}, fh, ensure_ascii=False, indent=1)
    return path


def show(e, body_chars=200):
    return (f"[{e['ts']}] {e['request_line']} -> {get_status(e)} "
            f"(len={e['body_len']}, {e['elapsed_ms']}ms) :: "
            f"{e['response_body'][:body_chars].replace(chr(10), ' ')}")
