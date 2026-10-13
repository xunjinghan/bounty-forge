#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""recon-01: 逐路由实测（未登录 vs 登录后），只读侦察，不做破坏性操作。"""
import sys, json, urllib.request, urllib.error, urllib.parse, http.client, time

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

A = "http://127.0.0.1:8095"
EV = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence"

ROUTES = [
    ("/", "GET", None, "none"),
    ("/login", "GET", None, "none"),
    ("/login", "POST", "username=__probe_no_such_user__&password=x", "none"),
    ("/logout", "GET", None, "none"),
    ("/home", "GET", None, "user"),
    ("/search", "GET", "q=k", "none"),
    ("/api/search", "GET", "q=k", "none"),
    ("/api/order", "GET", "id=1", "user"),
    ("/api/profile", "GET", "id=1", "user"),
    ("/greet", "GET", "name=world", "none"),
    ("/ping", "GET", "host=127.0.0.1", "none"),
    ("/download", "GET", "file=readme.txt", "none"),
    ("/board", "GET", None, "none"),
    ("/forgot", "GET", "username=admin", "none"),
    ("/fetch", "GET", "url=http://127.0.0.1:8095/", "none"),
    ("/upload", "GET", None, "none"),
    ("/uploads/", "GET", None, "none"),
    ("/order/create", "GET", None, "user"),
    ("/order/status", "GET", "order_id=2&state=paid", "user"),
    ("/coupon/claim", "GET", "code=WELCOME10", "user"),
    ("/wallet/withdraw", "GET", None, "user"),
    ("/wallet/transfer", "GET", None, "user"),
    ("/change-password", "GET", None, "user"),
    ("/admin/users", "GET", None, "admin"),
    ("/admin/orders", "GET", None, "admin"),
    ("/debug", "GET", None, "admin"),
    ("/backup/config.bak", "GET", None, "none"),
    ("/private/config.bak", "GET", None, "none"),
    ("/config.bak", "GET", None, "none"),
    ("/lab.db", "GET", None, "none"),
    ("/lab_errors.log", "GET", None, "none"),
    ("/downloads/readme.txt", "GET", None, "none"),
    ("/nonexistent-xyz", "GET", None, "none"),
]


def req(url, method="GET", body=None, cookie=None, extra=None, timeout=12,
        form=False):
    r = urllib.request.Request(url, method=method)
    if cookie:
        r.add_header("Cookie", cookie)
    for k, v in (extra or {}).items():
        r.add_header(k, v)
    data = None
    if body is not None:
        data = body.encode()
        r.add_header("Content-Type", "application/x-www-form-urlencoded")
        r.add_header("Content-Length", str(len(data)))
    if form:
        data = urllib.parse.urlencode(form).encode()
        r.add_header("Content-Type", "application/x-www-form-urlencoded")
        r.add_header("Content-Length", str(len(data)))
    try:
        with urllib.request.urlopen(r, data=data, timeout=timeout) as resp:
            raw = resp.read()
            return resp.status, len(raw), dict(resp.headers), raw
    except urllib.error.HTTPError as e:
        raw = e.read()
        return e.code, len(raw), dict(e.headers), raw
    except Exception as e:
        return -1, 0, {}, str(e).encode()


def probe(cookie=None, tag="anon", limit_show=0):
    out = []
    for path, method, qs, auth in ROUTES:
        url = A + path + (("?" + qs) if qs and method == "GET" else "")
        body = qs if (qs and method == "POST") else None
        st, ln, hdr, raw = req(url, method, body, cookie=cookie)
        loc = hdr.get("Location", "")
        snippet = ""
        if st == 200 and raw:
            try:
                snippet = raw.decode("utf-8", "replace")
            except Exception:
                snippet = ""
        out.append({
            "path": path, "method": method, "qs": qs, "declared_auth": auth,
            "status": st, "len": ln, "location": loc,
            "ctype": hdr.get("Content-Type", ""),
            "server": hdr.get("Server", ""),
            "snippet": snippet,
        })
        print(f"[{tag}] {method:4} {path:22} qs={str(qs)[:34]:36} -> {st:4} len={ln:6} loc={loc}")
    return out


print("=" * 100)
print("A) 未登录探测")
anon = probe(None, "anon")

print()
print("=" * 100)
print("B) 登录流（POST /login，带正确 Content-Type）")


def do_login(u, p):
    st, ln, hdr, raw = req(A + "/login", "POST",
                           f"username={urllib.parse.quote(u)}&password={urllib.parse.quote(p)}")
    setc = hdr.get("Set-Cookie", "")
    txt = raw.decode("utf-8", "replace")
    mark = "登录失败" if "登录失败" in txt else ("账号锁定" if "次数过多" in txt else "OK?")
    print(f"  {u}/{p[:26]:26} -> {st:4} len={ln:6} Loc={hdr.get('Location','')[:14]:14} "
          f"SetCookie={setc[:34]:34} body={mark}")
    return (setc.split(";")[0] if setc else None), st, ln


admin_cookie = None
demo_cookie = None
# 先用任务书给的 admin123 + 源码里的加固口令各试一次
for u, p in [("admin", "admin123"),
             ("admin", "Lab@Admin2024!Secure#9"),
             ("demo", "demo123"),
             ("alice", "alice123"),
             ("bob", "bob123")]:
    ck, st, ln = do_login(u, p)
    if ck and u == "admin" and admin_cookie is None:
        admin_cookie = ck
    if ck and u == "demo":
        demo_cookie = ck
print("  admin_cookie:", admin_cookie)
print("  demo_cookie :", demo_cookie)

print()
print("=" * 100)
print("C) 带 admin Cookie 复探")
adm = probe(admin_cookie, "admin") if admin_cookie else []
print()
print("=" * 100)
print("D) 带 demo Cookie 复探")
dm = probe(demo_cookie, "demo") if demo_cookie else []

print()
print("=" * 100)
print("E) 登录前 vs 登录后 差异（admin）")
if adm:
    for a_, b_ in zip(anon, adm):
        if a_["status"] != b_["status"] or a_["len"] != b_["len"] or a_["location"] != b_["location"]:
            print(f"  {a_['method']:4} {a_['path']:22} anon={a_['status']}/{a_['len']}/{a_['location'][:20]}"
                  f"  ->  admin={b_['status']}/{b_['len']}/{b_['location'][:20]}")

print()
print("=" * 100)
print("F) demo(普通用户) vs admin 差异（垂直越权检查）")
if dm and adm:
    for d_, a_ in zip(dm, adm):
        if d_["status"] != a_["status"] or d_["len"] != a_["len"]:
            print(f"  {d_['method']:4} {d_['path']:22} demo={d_['status']}/{d_['len']}  admin={a_['status']}/{a_['len']}")

payload = {"anon": [{k: v for k, v in r.items() if k != "snippet"} for r in anon],
           "admin": [{k: v for k, v in r.items() if k != "snippet"} for r in adm],
           "demo": [{k: v for k, v in r.items() if k != "snippet"} for r in dm],
           "admin_cookie": admin_cookie, "demo_cookie": demo_cookie}
with open(EV + r"\recon-01-probe.json", "w", encoding="utf-8") as fh:
    json.dump(payload, fh, ensure_ascii=False, indent=2)
print("\n[saved]", EV + r"\recon-01-probe.json")
