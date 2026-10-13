#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""recon-04: 版本指纹判定——用只有"旧版(vulnerable)"或"磁盘加固版"才有的行为区分。
只读探测；特别避开会改数据的端点（不调 /__reset、不 upload、不 transfer）。"""
import sys, re, json, urllib.request, urllib.error, urllib.parse

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
A = "http://127.0.0.1:8095"
EV = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence"

# 旧版特征串 / 加固版特征串
OLD_MARKS = ["{{7*7}} 不会被执行", "模板引擎", "LabHTTP", "找回密码", "已为用户"]
NEW_MARKS = ["最小业务站点", "TargetSite", "请回到登录页重新提交", "CSRF"]


def get(path, cookie=None, headers=None, method="GET", body=None):
    r = urllib.request.Request(A + path, method=method)
    for k, v in (headers or {}).items():
        r.add_header(k, v)
    if cookie:
        r.add_header("Cookie", cookie)
    d = None
    if body is not None:
        d = body.encode()
        r.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(r, data=d, timeout=12) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def brief(txt, n=320):
    t = re.sub(r"<(style|script).*?</\1>", " ", txt, flags=re.S)
    t = re.sub(r"\s+", " ", t)
    return t[:n]


TESTS = [
    ("GET", "/", "首页：旧版列测试账号含 admin/admin123？加固版写 Lab@Admin2024"),
    ("GET", "/greet?name=%7B%7B7*7%7D%7D", "/greet {{7*7}}：旧版提到 eval 禁用；加固版无此路由"),
    ("GET", "/api/search?q=k", "/api/search：旧版回 {'sql':...}；加固版 404"),
    ("GET", "/api/order?id=2", "/api/order：旧版存在；加固版 404"),
    ("GET", "/forgot?username=admin", "/forgot：旧版存在；加固版 404"),
    ("GET", "/download?file=readme.txt", "/download：旧版白名单；加固版 404"),
    ("GET", "/coupon/claim?code=WELCOME10", "/coupon/claim：旧版存在；加固版 404"),
    ("GET", "/admin/users", "/admin/users：旧版存在；加固版 404"),
    ("GET", "/debug", "/debug：旧版 admin-only；加固版 404"),
    ("GET", "/register", "/register：加固版有；旧版 404"),
    ("GET", "/profile", "/profile：加固版有；旧版 404"),
    ("GET", "/api/orders?id=1", "/api/orders：加固版有；旧版 404"),
    ("GET", "/backup/config.bak", "备份文件直连（两个版本都该 404，因移出 web root）"),
    ("GET", "/private/config.bak", "private/ 备份直连"),
    ("GET", "/lab_errors.log", "错误日志直连"),
    ("GET", "/lab.db", "数据库直连"),
]

print("=" * 110)
for method, path, why in TESTS:
    st, hdr, raw = get(path)
    txt = raw.decode("utf-8", "replace")
    marks = []
    if "{{7*7}}" in txt or "模板引擎" in txt:
        marks.append("OLD:greet")
    if '"sql"' in txt:
        marks.append("OLD:api-search-sql-echo")
    if "找回密码" in txt:
        marks.append("OLD:forgot")
    if "最小业务站点" in txt:
        marks.append("NEW:home")
    if "未能提供" in txt:
        marks.append("?")
    print(f"{method} {path:34} -> {st:4} len={len(raw):6} "
          f"ctype={hdr.get('Content-Type','')[:30]:30} {','.join(marks)}")
    print(f"    理由: {why}")
    print(f"    body: {brief(txt)}")
    print()

print("=" * 110)
print("GET /login（看是否含 CSRF hidden 字段 = 加固版特征）")
st, hdr, raw = get("/login")
txt = raw.decode("utf-8", "replace")
print(f"  status={st} len={len(raw)} 含csrf_token字段={'csrf_token' in txt} "
      f"SetCookie={hdr.get('Set-Cookie','')[:60]}")
print("  body:", brief(txt, 500))

print()
print("=" * 110)
print("POST /login 不带 CSRF（加固版应 403 CSRF 校验失败；旧版应尝试认证）")
st, hdr, raw = get("/login", method="POST", body="username=demo&password=demo123")
txt = raw.decode("utf-8", "replace")
print(f"  status={st} len={len(raw)} Loc={hdr.get('Location','')} "
      f"SetCookie={hdr.get('Set-Cookie','')[:60]}")
print("  body:", brief(txt, 400))

with open(EV + r"\recon-04-fingerprint.txt", "w", encoding="utf-8") as fh:
    fh.write("version fingerprint probe @ 8095\n")
print("\n[done]")
