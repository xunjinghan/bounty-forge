# -*- coding: utf-8 -*-
"""阶段2 侦察：只读攻击面采集（8091 target-site / 8095 target-site-lab）。
硬约束：仅 127.0.0.1；GET 探测为主；不改数据；不触发 /__reset；不爆破口令。
"""
import json
import re
import time
import urllib.parse
import urllib.request
import http.cookiejar

TS = time.strftime("%Y%m%d-%H%M%S")
OUT_JSON = rf"C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\recon-10-surface-{TS}.json"

UA = "recon-lab/1.0 (authorized-local-only)"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def make_opener():
    cj = http.cookiejar.CookieJar()
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj), NoRedirect), cj


def fetch(opener, url, method="GET", data=None, headers=None, timeout=10):
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode()
        h["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    t0 = time.time()
    try:
        r = opener.open(req, timeout=timeout)
        raw = r.read()
        return {"status": r.status, "headers": dict(r.headers), "body": raw,
                "err": None, "ms": int((time.time() - t0) * 1000)}
    except urllib.error.HTTPError as e:
        raw = e.read()
        return {"status": e.code, "headers": dict(e.headers), "body": raw,
                "err": None, "ms": int((time.time() - t0) * 1000)}
    except Exception as e:  # noqa
        return {"status": None, "headers": {}, "body": b"",
                "err": f"{type(e).__name__}: {e}", "ms": int((time.time() - t0) * 1000)}


def text(b):
    return b.decode("utf-8", "replace")


def summarize(r):
    t = text(r["body"])
    title = re.search(r"<title>(.*?)</title>", t, re.S)
    return {
        "status": r["status"],
        "len": len(r["body"]),
        "ct": r["headers"].get("Content-Type", r["headers"].get("content-type", "")),
        "title": title.group(1).strip() if title else None,
        "location": r["headers"].get("Location", r["headers"].get("location")),
        "ms": r["ms"],
        "err": r["err"],
        "sha1_hint": __import__("hashlib").sha1(r["body"]).hexdigest()[:12],
    }


def extract_links(html, base):
    urls = set()
    for m in re.finditer(r'(?:href|action|src)\s*=\s*"([^"]+)"', html):
        urls.add(urllib.parse.urljoin(base, m.group(1)))
    return sorted(urls)


def extract_params(html):
    names = set()
    for m in re.finditer(r'<input[^>]*name="([^"]+)"', html):
        names.add(m.group(1))
    for m in re.finditer(r'<textarea[^>]*name="([^"]+)"', html):
        names.add(m.group(1))
    for m in re.finditer(r'<select[^>]*name="([^"]+)"', html):
        names.add(m.group(1))
    return sorted(names)


RESULT = {
    "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    "scope": ["http://127.0.0.1:8091", "http://127.0.0.1:8095"],
    "method": "read-only GET probes + one login session (demo) for auth-state diff",
    "assets": {},
}

# ---------------- 8095 target-site-lab ----------------
LAB = "http://127.0.0.1:8095"
lab_paths = [
    "/", "/login", "/logout", "/home", "/search?q=test", "/api/search?q=test",
    "/api/order?id=1", "/api/profile?id=1", "/greet?name=world", "/download?file=readme.txt",
    "/board", "/forgot?username=demo", "/upload", "/order/create", "/order/status?order_id=1",
    "/coupon/claim", "/wallet/withdraw", "/wallet/transfer", "/change-password",
    "/admin/users", "/admin/orders", "/debug", "/uploads/", "/favicon.ico",
]
op, cj = make_opener()
lab = {"unauth": {}, "auth_demo": {}, "auth_admin": {}, "flows": {}}

for p in lab_paths:
    r = fetch(op, LAB + p)
    lab["unauth"][p] = summarize(r)
    if p in ("/", "/search?q=test", "/board", "/upload"):
        lab["unauth"][p]["links"] = extract_links(text(r["body"]), LAB)
        lab["unauth"][p]["form_fields"] = extract_params(text(r["body"]))

# 登录 demo（只读流程验证，不修改数据）
r = fetch(op, LAB + "/login")
csrf = None
m = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', text(r["body"]))
if m:
    csrf = m.group(1)
lab["flows"]["login_demo"] = {"csrf_present": bool(csrf),
                              "get_status": r["status"]}
form = {"username": "demo", "password": "demo123"}
if csrf:
    form["csrf_token"] = csrf
r = fetch(op, LAB + "/login", method="POST", data=form)
lab["flows"]["login_demo"]["post"] = summarize(r)
lab["flows"]["login_demo"]["cookies_after"] = [c.name for c in cj]

for p in lab_paths:
    r = fetch(op, LAB + p)
    lab["auth_demo"][p] = summarize(r)
    if p in ("/home", "/board", "/upload", "/admin/users", "/debug"):
        lab["auth_demo"][p]["links"] = extract_links(text(r["body"]), LAB)
        lab["auth_demo"][p]["form_fields"] = extract_params(text(r["body"]))

# 越权只读探测：demo 会话访问 admin 端点
admin_probe = {}
for p in ["/admin/users", "/admin/orders", "/debug", "/api/profile?id=1", "/api/order?id=1"]:
    r = fetch(op, LAB + p)
    body = text(r["body"])
    admin_probe[p] = summarize(r)
    admin_probe[p]["body_head"] = body[:400]
lab["flows"]["demo_cookie_hits_admin"] = admin_probe

RESULT["assets"]["127.0.0.1:8095"] = lab

# ---------------- 8091 target-site ----------------
SITE = "http://127.0.0.1:8091"
site_paths = [
    "/", "/login", "/register", "/profile", "/api/profile", "/api/orders",
    "/logout", "/change-password", "/favicon.ico", "/debug", "/forgot",
]
op2, cj2 = make_opener()
site = {"unauth": {}, "auth_demo": {}, "flows": {}}
for p in site_paths:
    r = fetch(op2, SITE + p)
    site["unauth"][p] = summarize(r)
    if p in ("/", "/login", "/register"):
        site["unauth"][p]["links"] = extract_links(text(r["body"]), SITE)
        site["unauth"][p]["form_fields"] = extract_params(text(r["body"]))

r = fetch(op2, SITE + "/login")
csrf = None
m = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', text(r["body"]))
if m:
    csrf = m.group(1)
site["flows"]["login_demo"] = {"csrf_present": bool(csrf), "get_status": r["status"]}
form = {"username": "demo", "password": "demo1234"}
if csrf:
    form["csrf_token"] = csrf
r = fetch(op2, SITE + "/login", method="POST", data=form)
site["flows"]["login_demo"]["post"] = summarize(r)
site["flows"]["login_demo"]["cookies_after"] = [c.name for c in cj2]

for p in site_paths:
    r = fetch(op2, SITE + p)
    site["auth_demo"][p] = summarize(r)
    body = text(r["body"])
    if p in ("/", "/profile"):
        site["auth_demo"][p]["links"] = extract_links(body, SITE)
        site["auth_demo"][p]["form_fields"] = extract_params(body)
    site["auth_demo"][p]["body_head"] = body[:300]

RESULT["assets"]["127.0.0.1:8091"] = site

with open(OUT_JSON, "w", encoding="utf-8") as fh:
    json.dump(RESULT, fh, ensure_ascii=False, indent=2)

print(json.dumps({
    "out": OUT_JSON,
    "8095_unauth_non200": {k: v["status"] for k, v in lab["unauth"].items() if v["status"] != 200},
    "8095_auth_non200": {k: v["status"] for k, v in lab["auth_demo"].items() if v["status"] != 200},
    "8095_login_post": lab["flows"]["login_demo"]["post"],
    "8095_admin_as_demo": {k: v["status"] for k, v in admin_probe.items()},
    "8091_unauth_non200": {k: v["status"] for k, v in site["unauth"].items() if v["status"] != 200},
    "8091_auth_non200": {k: v["status"] for k, v in site["auth_demo"].items() if v["status"] != 200},
    "8091_login_post": site["flows"]["login_demo"]["post"],
}, ensure_ascii=False, indent=2))
