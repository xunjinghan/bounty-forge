#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""recon-07: 方法矩阵 + 参数名验证（GET/POST/HEAD/OPTIONS/PUT）。"""
import sys, re, json, urllib.request, urllib.error, urllib.parse

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
A = "http://127.0.0.1:8095"
EV = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence"
NR = urllib.request.build_opener(type("NR", (urllib.request.HTTPRedirectHandler,), {
    "redirect_request": lambda *a, **k: None}))


def call(method, path, form=None, cookie=None, origin=None):
    r = urllib.request.Request(A + path, method=method)
    if cookie:
        r.add_header("Cookie", cookie)
    if origin:
        r.add_header("Origin", origin)
    d = None
    if form is not None:
        d = urllib.parse.urlencode(form).encode()
        r.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with NR.open(r, data=d, timeout=12) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except Exception as e:
        return -1, {}, str(e).encode()


def login(u, p):
    st, h, _ = call("POST", "/login", {"username": u, "password": p})
    return h.get("Set-Cookie", "").split(";")[0]


demo = login("demo", "demo123")
admin = login("admin", "admin123")
print("demo cookie:", demo)
print("admin cookie:", admin)

PATHS = ["/", "/login", "/logout", "/home", "/search", "/api/search", "/api/order",
         "/api/profile", "/greet", "/ping", "/download", "/board", "/forgot",
         "/fetch", "/upload", "/uploads/", "/order/create", "/order/status",
         "/coupon/claim", "/wallet/withdraw", "/wallet/transfer",
         "/change-password", "/admin/users", "/admin/orders", "/debug"]

print()
print("=" * 108)
print("方法矩阵（无 Cookie；HEAD 看 Server/长度，OPTIONS 看 204）")
print(f"{'path':20} {'GET':>12} {'POST':>12} {'HEAD':>12} {'OPTIONS':>12} {'PUT':>12}")
matrix = {}
for p in PATHS:
    row = {}
    for m in ("GET", "POST", "HEAD", "OPTIONS", "PUT"):
        st, h, raw = call(m, p)
        row[m] = {"status": st, "len": len(raw), "allow": h.get("Allow", "")}
        if m in ("GET", "POST") and p == "/" and False:
            pass
    matrix[p] = row
    f = lambda m: f"{row[m]['status']}/{row[m]['len']}"
    print(f"{p:20} {f('GET'):>12} {f('POST'):>12} {f('HEAD'):>12} "
          f"{f('OPTIONS'):>12} {f('PUT'):>12}")

print()
print("=" * 108)
print("参数名验证：POST 到 GET-only 路由 vs GET 到 POST-only 路由")
CASES = [
    ("POST", "/search", {"q": "k"}), ("POST", "/api/search", {"q": "k"}),
    ("POST", "/greet", {"name": "x"}), ("POST", "/ping", {"host": "127.0.0.1"}),
    ("POST", "/download", {"file": "readme.txt"}),
    ("POST", "/admin/users", None), ("POST", "/debug", None),
    ("POST", "/home", None), ("POST", "/fetch", {"url": "http://127.0.0.1:8095/"}),
    ("GET", "/upload", None), ("POST", "/uploads/x.txt", None),
    ("GET", "/login", None),
]
for m, p, f_ in CASES:
    st, h, raw = call(m, p, f_)
    loc = h.get("Location", "")
    m2 = re.search(rb"<title>(.*?)</title>", raw, re.S)
    title = m2.group(1).decode("utf-8", "replace") if m2 else ""
    print(f"  {m:4} {p:16} params={str(list(f_.keys()) if f_ else []):22} -> {st:4} "
          f"len={len(raw):6} loc={loc[:16]:16} title={title}")

print()
print("=" * 108)
print("CSRF 行为（加固版应 403；旧版会 200/302）")
for path, form, tag in [
    ("/wallet/transfer", {"to": "bob", "amount": "1"}, "无 csrf_token"),
    ("/wallet/transfer", {"to": "bob", "amount": "1", "csrf_token": "bogus"}, "错 csrf_token"),
    ("/change-password", {"new_password": "zzz"}, "无 csrf_token"),
]:
    st, h, raw = call("POST", path, form, cookie=demo)
    m2 = re.search(rb"<title>(.*?)</title>", raw, re.S)
    title = m2.group(1).decode("utf-8", "replace") if m2 else ""
    print(f"  POST {path:18} {tag:16} -> {st} loc={h.get('Location','')[:14]} title={title}")

print()
print("=" * 108)
print("GET 触发写操作？(旧洞：GET /wallet/transfer?to=&amount= 与 /change-password?new_password=)")
st, h, raw = call("GET", "/wallet/transfer?to=bob&amount=1", cookie=demo)
m2 = re.search(rb"<title>(.*?)</title>", raw, re.S)
print(f"  GET /wallet/transfer?to=bob&amount=1 -> {st} title="
      f"{m2.group(1).decode('utf-8','replace') if m2 else ''} loc={h.get('Location','')[:16]}")
st, h, raw = call("GET", "/change-password?new_password=zzz", cookie=demo)
m2 = re.search(rb"<title>(.*?)</title>", raw, re.S)
print(f"  GET /change-password?new_password=zzz -> {st} title="
      f"{m2.group(1).decode('utf-8','replace') if m2 else ''}")

print()
print("=" * 108)
print("CORS（同源 vs 异源 Origin）")
for o in ["http://127.0.0.1:8095", "http://evil.example"]:
    st, h, _ = call("GET", "/", origin=o)
    print(f"  Origin={o:28} -> ACAO={h.get('Access-Control-Allow-Origin')} "
          f"ACAC={h.get('Access-Control-Allow-Credentials')}")

print()
print("=" * 108)
print("Host 头注入（/forgot）")
for hh in [{"X-Forwarded-Host": "evil.com"}, {"Host": "evil.com"}]:
    r = urllib.request.Request(A + "/forgot?username=admin")
    for k, v in hh.items():
        r.add_header(k, v)
    try:
        with NR.open(r, timeout=10) as resp:
            txt = resp.read().decode("utf-8", "replace")
    except Exception as e:
        txt = str(e)
    mm = re.search(r"http://[^<\s]+", txt)
    print(f"  {list(hh.keys())[0]:20} -> {mm.group(0) if mm else '未找到'}")

with open(EV + r"\recon-07-methods.json", "w", encoding="utf-8") as fh:
    json.dump(matrix, fh, ensure_ascii=False, indent=2)
print("\n[saved]", EV + r"\recon-07-methods.json")
