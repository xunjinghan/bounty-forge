# -*- coding: utf-8 -*-
"""阶段2 侦察：登录时序单步追踪（8095 与 8091），只读。"""
import json
import re
import time
import urllib.parse
import urllib.request
import http.cookiejar

UA = "recon-lab/1.0 (authorized-local-only)"
TS = time.strftime("%Y%m%d-%H%M%S")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def opener():
    cj = http.cookiejar.CookieJar()
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj), NoRedirect), cj


def go(op, url, method="GET", data=None):
    h = {"User-Agent": UA}
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode()
        h["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        r = op.open(req, timeout=10)
        raw, code, hdrs = r.read(), r.status, dict(r.headers)
    except urllib.error.HTTPError as e:
        raw, code, hdrs = e.read(), e.code, dict(e.headers)
    return {"code": code, "set_cookie": hdrs.get("Set-Cookie"),
            "location": hdrs.get("Location"), "len": len(raw),
            "head": raw.decode("utf-8", "replace")[:200]}


log = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}

# ---- 8095 lab: token cookie 名 = token ----
op, cj = opener()
lab = {}
lab["GET /"] = go(op, "http://127.0.0.1:8095/")
lab["GET /login"] = go(op, "http://127.0.0.1:8095/login")
lab["POST /login"] = go(op, "http://127.0.0.1:8095/login", "POST",
                        {"username": "demo", "password": "demo123"})
lab["cookies"] = {c.name: c.value for c in cj}
lab["GET /home"] = go(op, "http://127.0.0.1:8095/home")
lab["GET /"] = go(op, "http://127.0.0.1:8095/")
lab["GET /board"] = go(op, "http://127.0.0.1:8095/board")
lab["GET /debug"] = go(op, "http://127.0.0.1:8095/debug")
lab["GET /admin/users"] = go(op, "http://127.0.0.1:8095/admin/users")
lab["GET /api/profile?id=1"] = go(op, "http://127.0.0.1:8095/api/profile?id=1")
lab["GET /order/create"] = go(op, "http://127.0.0.1:8095/order/create")
log["8095_lab"] = lab

# ---- 8091 site ----
op2, cj2 = opener()
site = {}
site["GET /"] = go(op2, "http://127.0.0.1:8091/")
r = go(op2, "http://127.0.0.1:8091/login")
site["GET /login"] = r
m = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', r["head"] + "")
# head 只有 200 字符，重新完整取一次
req = urllib.request.Request("http://127.0.0.1:8091/login",
                             headers={"User-Agent": UA})
full = op2.open(req, timeout=10).read().decode("utf-8", "replace")
mm = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', full)
csrf = mm.group(1) if mm else None
site["csrf_present"] = bool(csrf)
site["POST /login"] = go(op2, "http://127.0.0.1:8091/login", "POST",
                         {"username": "demo", "password": "demo1234",
                          "csrf_token": csrf or ""})
site["cookies"] = {c.name: c.value for c in cj2}
site["GET /profile"] = go(op2, "http://127.0.0.1:8091/profile")
site["GET /"] = go(op2, "http://127.0.0.1:8091/")
site["GET /api/profile"] = go(op2, "http://127.0.0.1:8091/api/profile")
site["GET /api/orders"] = go(op2, "http://127.0.0.1:8091/api/orders")
log["8091_site"] = site

path = rf"C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\recon-11-login-trace-{TS}.json"
with open(path, "w", encoding="utf-8") as fh:
    json.dump(log, fh, ensure_ascii=False, indent=2)
print(json.dumps(log, ensure_ascii=False, indent=2))
print("WROTE", path)
