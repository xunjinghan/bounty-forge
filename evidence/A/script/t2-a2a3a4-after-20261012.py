#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Loop2 A2/A3/A4 加固后对照取证（8095）。

A2：四个写端点 GET/无 token/错 token → 405/403；正确 token POST → 200
A3：页面 token != HMAC(SECRET_KEY, session)；跨会话 token → 403
A4：GET /logout 后 sessions 行被删、旧 Cookie 重放 /home → 302
"""
import json
import re
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:8095"
DB = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace\target-site-lab\lab.db"
SECRET = "lab-secret-key-PLEASE-CHANGE-001"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def call(method, path, token=None, data=None, extra_headers=None):
    url = BASE + path
    body = urllib.parse.urlencode(data).encode() if data else None
    headers = {}
    if token:
        headers["Cookie"] = f"token={token}"
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        r = OPENER.open(req)
        return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def login(user, pw):
    req = urllib.request.Request(
        BASE + "/login",
        data=urllib.parse.urlencode({"username": user, "password": pw}).encode(),
        method="POST")
    try:
        r = OPENER.open(req)
    except urllib.error.HTTPError as e:
        r = e
    return re.search(r"token=([^;]+)", r.headers.get("Set-Cookie", "")).group(1)


def csrf_of(token):
    _, body = call("GET", "/home", token)
    return re.search(r'name="csrf_token" value="([^"]+)"', body).group(1)


def h1(body):
    return [m.group(1) for m in re.finditer(r"<h1>([^<]{0,80})</h1>", body)]


def sessions_rows():
    c = sqlite3.connect(DB)
    rows = c.execute("SELECT token, username, csrf_token FROM sessions").fetchall()
    c.close()
    return rows


def balance(username):
    c = sqlite3.connect(DB)
    v = c.execute("SELECT balance_cents FROM users WHERE username=?",
                  (username,)).fetchone()[0]
    c.close()
    return v


out = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "target": BASE, "cases": {}}

tok = login("alice", "alice123")
csrf = csrf_of(tok)
out["session_token"] = tok
out["page_csrf_token"] = csrf

# ---- A2 矩阵 ----
eps = [("wallet/withdraw", {"amount": "700"}),
       ("order/create", {"product_id": "1", "qty": "1"}),
       ("order/status", {"order_id": "2", "state": "paid"}),
       ("coupon/claim", {"code": "WELCOME10"})]
a2 = []
for path, data in eps:
    entry = {"endpoint": "/" + path, "before_balance": balance("alice")}
    q = urllib.parse.urlencode(data)
    entry["GET_no_token"] = call("GET", f"/{path}?{q}", tok)[0]
    entry["POST_no_token"] = call("POST", f"/{path}", tok, data)[0]
    d2 = dict(data)
    d2["csrf_token"] = "deadbeef"
    entry["POST_wrong_token"] = call("POST", f"/{path}", tok, d2)[0]
    d3 = dict(data)
    d3["csrf_token"] = csrf
    st, body = call("POST", f"/{path}", tok, d3)
    entry["POST_correct_token"] = st
    entry["POST_correct_token_h1"] = h1(body)
    entry["after_balance"] = balance("alice")
    a2.append(entry)
out["cases"]["A2_four_write_endpoints"] = a2

# ---- A3 不可离线推导 + 跨会话 ----
import hmac as _hmac
import hashlib as _hashlib
hmac_derived = _hmac.new(SECRET.encode(), tok.encode(), _hashlib.sha256).hexdigest()
out["cases"]["A3"] = {
    "hmac_derived_token": hmac_derived,
    "page_token": csrf,
    "page_token_equals_hmac": csrf == hmac_derived,
    "page_token_len": len(csrf),
    "hmac_len": len(hmac_derived),
    "db_stored_matches_page": any(r[0] == tok and r[2] == csrf
                                  for r in sessions_rows()),
}
tok2 = login("bob", "bob123")
csrf2 = csrf_of(tok2)
st, body = call("POST", "/wallet/withdraw", tok,
                {"amount": "700", "csrf_token": csrf2})
out["cases"]["A3"]["cross_session_token_http"] = st
out["cases"]["A3"]["cross_session_h1"] = h1(body)
out["cases"]["A3"]["bob_token"] = tok2

# ---- A4 会话销毁 ----
out["cases"]["A4"] = {"before_logout_rows": sessions_rows()}
out["cases"]["A4"]["logout_http"] = call("GET", "/logout", tok)[0]
out["cases"]["A4"]["after_logout_rows"] = sessions_rows()
st, body = call("GET", "/home", tok)
out["cases"]["A4"]["old_cookie_replay_home"] = st
out["cases"]["A4"]["old_cookie_replay_h1"] = h1(body)
st, body = call("POST", "/wallet/withdraw", tok, {"amount": "700"})
out["cases"]["A4"]["old_cookie_replay_write"] = st

# ---- 改前/改后首页表单方法 ----
_, home_body = call("GET", "/home", tok2)
out["cases"]["home_forms"] = re.findall(r'<form method="(\w+)" action="([^"]+)"',
                                        home_body)

print(json.dumps(out, ensure_ascii=False, indent=2))
path = (r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace"
        r"\security\learning\_evidence\t2-a2a3a4-after-20261012.json")
with open(path, "w", encoding="utf-8") as fh:
    json.dump(out, fh, ensure_ascii=False, indent=2)
print("[written]", path)
