#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Loop2 t2 边界用例：老会话兜底 + 其它 CSRF 入口不回归。"""
import json
import re
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:8095"
DB = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace\target-site-lab\lab.db"
OUT = (r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace"
       r"\security\learning\_evidence\t2-edgecases-20261012.json")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def call(method, path, token=None, data=None):
    headers = {"Cookie": f"token={token}"} if token else {}
    body = urllib.parse.urlencode(data).encode() if data else None
    req = urllib.request.Request(BASE + path, data=body, headers=headers,
                                 method=method)
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


def h1(b):
    return re.findall(r"<h1>([^<]{0,80})</h1>", b)


res = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "cases": {}}

# ---- 边界1：老会话行 csrf_token=NULL → 兜底生成并回写 ----
LEGACY = "LEGACYTOKEN-T2-TEST"
c = sqlite3.connect(DB)
c.execute("INSERT OR REPLACE INTO sessions"
          "(token,user_id,username,created_at,csrf_token) VALUES(?,?,?,?,NULL)",
          (LEGACY, 2, "demo", int(time.time())))
c.commit()
c.close()
st, body = call("GET", "/home", LEGACY)
tok_shown = re.search(r'name="csrf_token" value="([^"]+)"', body)
tok_shown = tok_shown.group(1) if tok_shown else None
c = sqlite3.connect(DB)
stored = c.execute("SELECT csrf_token FROM sessions WHERE token=?",
                   (LEGACY,)).fetchone()[0]
c.close()
st2, b2 = call("POST", "/wallet/withdraw", LEGACY,
               {"amount": "100", "csrf_token": tok_shown or ""})
res["cases"]["legacy_session_null_csrf"] = {
    "home_http": st, "generated_token": tok_shown, "db_written_back": stored,
    "write_back_matches": tok_shown == stored,
    "write_http": st2, "write_h1": h1(b2)}

# ---- 边界2：其它 CSRF 入口不回归 ----
jar = login("alice", "alice123")
_, hb = call("GET", "/home", jar)
csrf = re.search(r'name="csrf_token" value="([^"]+)"', hb).group(1)
checks = {}
checks["transfer_correct"] = call("POST", "/wallet/transfer", jar,
                                  {"to": "bob", "amount": "100",
                                   "csrf_token": csrf})[0]
checks["transfer_none"] = call("POST", "/wallet/transfer", jar,
                               {"to": "bob", "amount": "100"})[0]
checks["change_pw_form_get"] = call("GET", "/change-password", jar)[0]
st, b = call("POST", "/change-password", jar,
             {"new_password": "alice123", "csrf_token": csrf})
checks["change_pw_correct"] = st
checks["change_pw_h1"] = h1(b)
res["cases"]["other_csrf_endpoints"] = checks

# ---- 边界3：GET 顶级导航带 cross-site 头仍被 405 ----
st, b = call("GET", "/wallet/withdraw?amount=100", jar)
res["cases"]["top_level_get_write"] = {"http": st, "h1": h1(b)}
req = urllib.request.Request(
    BASE + "/wallet/withdraw?amount=100",
    headers={"Cookie": f"token={jar}", "Sec-Fetch-Site": "cross-site",
             "Sec-Fetch-Mode": "navigate",
             "Referer": "http://evil.example/csrf.html"})
try:
    r = OPENER.open(req)
    st3, b3 = r.status, r.read().decode("utf-8", "replace")
except urllib.error.HTTPError as e:
    st3, b3 = e.code, e.read().decode("utf-8", "replace")
res["cases"]["cross_site_navigation"] = {"http": st3, "h1": h1(b3)}

print(json.dumps(res, ensure_ascii=False, indent=2))
with open(OUT, "w", encoding="utf-8") as fh:
    json.dump(res, fh, ensure_ascii=False, indent=2)
print("[written]", OUT)
