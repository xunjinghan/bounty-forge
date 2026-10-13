#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""recon-05: 完整登录态侦察（禁用自动重定向）。
输出：每条路由 anon / demo(user) / admin 的 状态码+长度+Location，
并判定 auth 实际要求与越权证据。只读，不做破坏性调用。"""
import sys, json, re, urllib.request, urllib.error, urllib.parse

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
A = "http://127.0.0.1:8095"
B = "http://127.0.0.1:8091"
EV = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence"

NO_REDIRECT = urllib.request.build_opener(type("NR", (urllib.request.HTTPRedirectHandler,), {
    "redirect_request": lambda *a, **k: None}))


def req(url, method="GET", form=None, cookie=None, headers=None, raw_body=None,
        ctype="application/x-www-form-urlencoded"):
    r = urllib.request.Request(url, method=method)
    for k, v in (headers or {}).items():
        r.add_header(k, v)
    if cookie:
        r.add_header("Cookie", cookie)
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        r.add_header("Content-Type", ctype)
    elif raw_body is not None:
        data = raw_body.encode()
        r.add_header("Content-Type", ctype)
    try:
        with NO_REDIRECT.open(r, data=data, timeout=15) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except Exception as e:
        return -1, {}, str(e).encode()


def login(base, u, p):
    st, hdr, raw = req(base + "/login", "POST", form={"username": u, "password": p})
    sc = hdr.get("Set-Cookie", "")
    tok = sc.split(";")[0] if sc else ""
    return st, hdr.get("Location", ""), tok


# --- 建立三个身份 ---
print("=" * 112)
print("登录：anon / demo / admin")
st_d, loc_d, demo_cookie = login(A, "demo", "demo123")
print(f"  demo   -> {st_d} {loc_d}  cookie={demo_cookie}")
st_a, loc_a, admin_cookie = login(A, "admin", "admin123")
print(f"  admin  -> {st_a} {loc_a}  cookie={admin_cookie}")
st_al, loc_al, alice_cookie = login(A, "alice", "alice123")
print(f"  alice  -> {st_al} {loc_al}  cookie={alice_cookie}")

ROUTES = [
    ("/", "GET", None), ("/login", "GET", None),
    ("/login", "POST", {"username": "nosuchuser__x", "password": "x"}),
    ("/logout", "GET", None), ("/home", "GET", None),
    ("/search", "GET", {"q": "k"}), ("/api/search", "GET", {"q": "k"}),
    ("/api/order", "GET", {"id": "1"}), ("/api/order", "GET", {"id": "2"}),
    ("/api/profile", "GET", {"id": "1"}), ("/api/profile", "GET", {"id": "3"}),
    ("/greet", "GET", {"name": "world"}), ("/ping", "GET", {"host": "127.0.0.1"}),
    ("/download", "GET", {"file": "readme.txt"}),
    ("/download", "GET", {"file": "app.py"}),
    ("/download", "GET", {"file": "config.bak"}),
    ("/download", "GET", {"file": "../private/config.bak"}),
    ("/board", "GET", None), ("/forgot", "GET", {"username": "admin"}),
    ("/fetch", "GET", {"url": "http://127.0.0.1:8095/"}),
    ("/upload", "GET", None), ("/uploads/", "GET", None),
    ("/order/create", "GET", None), ("/order/status", "GET", {"order_id": "2", "state": "paid"}),
    ("/coupon/claim", "GET", {"code": "WELCOME10"}),
    ("/wallet/withdraw", "GET", None), ("/wallet/transfer", "GET", None),
    ("/change-password", "GET", None),
    ("/admin/users", "GET", None), ("/admin/orders", "GET", None),
    ("/debug", "GET", None),
]

results = {"anon": [], "demo": [], "admin": []}


def run(tag, cookie):
    print()
    print("=" * 112)
    print(f"身份 [{tag}] cookie={cookie or '(无)'}")
    for path, method, params in ROUTES:
        url = A + path
        form = None
        if params and method == "GET":
            url += "?" + urllib.parse.urlencode(params)
        elif params and method == "POST":
            form = params
        st, hdr, raw = req(url, method, form=form, cookie=cookie)
        loc = hdr.get("Location", "")
        txt = raw.decode("utf-8", "replace")
        title = ""
        m = re.search(r"<title>(.*?)</title>", txt, re.S)
        if m:
            title = m.group(1).strip()
        pm = ",".join(params.keys()) if params else ""
        rec = {"path": path, "method": method, "params": list(params.keys()) if params else [],
               "status": st, "len": len(raw), "location": loc, "title": title}
        results[tag].append(rec)
        print(f"  {method:4} {path:16} {pm:22} -> {st:4} len={len(raw):6} "
              f"loc={loc[:18]:18} title={title[:24]}")
        if path in ("/api/order", "/api/profile") and st == 200:
            print(f"        BODY: {txt[:150]}")
        if path == "/debug" and st == 200 and "SECRET_KEY" in txt:
            mm = re.search(r'"SECRET_KEY":\s*"([^"]*)"', txt)
            print(f"        *** /debug 泄露 SECRET_KEY={mm.group(1) if mm else '?'}")
        if path == "/download" and st == 200:
            print(f"        *** 下载成功 {len(raw)} bytes: {raw[:120]!r}")
        if path == "/admin/users" and st == 200 and len(raw) > 1500:
            print(f"        *** 后台页面可达 title={title}")


run("anon", None)
run("demo", demo_cookie)
run("admin", admin_cookie)

print()
print("=" * 112)
print("差异矩阵（anon vs demo vs admin）")
print(f"{'route':28} {'anon':>16} {'demo':>16} {'admin':>16}")
for i, (path, method, params) in enumerate(ROUTES):
    a_, d_, m_ = results["anon"][i], results["demo"][i], results["admin"][i]
    f = lambda r: f"{r['status']}/{r['len']}"
    flag = ""
    if a_["status"] != d_["status"] or a_["len"] != d_["len"]:
        flag += " <A≠D"
    if d_["status"] != m_["status"] or d_["len"] != m_["len"]:
        flag += " <D≠M"
    print(f"{method+' '+path:28} {f(a_):>16} {f(d_):>16} {f(m_):>16}{flag}")

with open(EV + r"\recon-05-authz.json", "w", encoding="utf-8") as fh:
    json.dump({"cookies": {"demo": demo_cookie, "admin": admin_cookie, "alice": alice_cookie},
               "results": results}, fh, ensure_ascii=False, indent=2)
print("\n[saved]", EV + r"\recon-05-authz.json")
