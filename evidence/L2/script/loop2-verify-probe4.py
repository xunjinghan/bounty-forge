#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
t3 补测探针 v4 —— 坐实残余绕过路径（自写）

修正 v3b 缺陷：
  * C4 的 Content-Length 写成 14，实际 body "confirm=RESET" 是 13 字节 -> 服务端等剩余字节，
    客户端超时 -> status=-1。本轮用 len(body) 动态计算。

本轮目标（三态结论所需的正/负证据）：
  D1 跨站复位：模拟受害浏览器（同机 127.0.0.1 源 IP）被诱导 POST /__reset?confirm=RESET
  D2 方法覆盖头（X-HTTP-Method-Override / _method）能否骗过 check_write
  D3 伪造来源头（X-Forwarded-For / X-Real-IP）能否骗过回环校验
  D4 multipart / 非 urlencoded 承载 confirm 是否被接受
  D5 A2 已覆盖四入口的 multipart 变形（技能 §7）
用法: python loop2-verify-probe4.py
"""
import hashlib
import http.client as httpc
import json
import os
import socket
import sqlite3
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SB = os.path.join(HERE, "loop2-verify-sandbox")
ORIG_DB = os.path.join(SB, "orig", "lab.db")
HARD_DB = os.path.join(SB, "hard", "lab.db")
TS = time.strftime("%Y%m%d-%H%M%S")


def raw_http(port, raw_bytes, timeout=12):
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        s.sendall(raw_bytes)
        data = b""
        while True:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if len(data) > 300000:
                break
        return data
    finally:
        s.close()


def status_of(data):
    if not data:
        return -1, "(no response)"
    line = data.split(b"\r\n", 1)[0].decode("utf-8", "replace")
    parts = line.split()
    return (int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else -1), line


def title_of(data):
    t = data.decode("utf-8", "replace")
    return t.split("<title>", 1)[1].split("</title>", 1)[0] if "<title>" in t else ""


def canary(dbfile):
    c = sqlite3.connect(dbfile)
    try:
        c.execute("INSERT INTO messages(author,content) VALUES('CANARY','t3')")
        c.commit()
    finally:
        c.close()


def n_messages(dbfile):
    c = sqlite3.connect("file:%s?mode=ro" % dbfile.replace("\\", "/"), uri=True)
    try:
        return c.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
    finally:
        c.close()


def audit_lines():
    p = os.path.join(SB, "hard", "reset-audit.log")
    return sum(1 for _ in open(p, encoding="utf-8", errors="replace")) if os.path.exists(p) else 0


def build(method, path, body=b"", ctype=None, extra=None, host="h"):
    lines = ["%s %s HTTP/1.1" % (method, path), "Host: %s" % host]
    if body:
        if ctype:
            lines.append("Content-Type: %s" % ctype)
        lines.append("Content-Length: %d" % len(body))
    for k, v in (extra or {}).items():
        lines.append("%s: %s" % (k, v))
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def run_reset_case(label, port, dbfile, rawreq):
    canary(dbfile)
    before = n_messages(dbfile)
    a0 = audit_lines()
    raw = raw_http(port, rawreq)
    st, line = status_of(raw)
    time.sleep(0.4)
    after = n_messages(dbfile)
    a1 = audit_lines()
    return {"case": label, "status": st, "status_line": line, "title": title_of(raw),
            "canary_before": before, "canary_after": after,
            "reset_triggered": after < before, "audit_delta": a1 - a0}


def http_req(port, method, path, body=None, cookie=None, headers=None):
    h = {"User-Agent": "lv-probe4/1.0"}
    if headers:
        h.update(headers)
    if cookie:
        h["Cookie"] = "token=%s" % cookie
    if body is not None and "Content-Type" not in h:
        h["Content-Type"] = "application/x-www-form-urlencoded"
    c = httpc.HTTPConnection("127.0.0.1", port, timeout=15)
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    raw = r.read()
    st = r.status
    sc = r.getheader("Set-Cookie") or ""
    c.close()
    tok = ""
    for part in sc.split(";"):
        if part.strip().startswith("token="):
            tok = part.strip()[6:]
    return st, raw.decode("utf-8", "replace"), tok


def hard_state():
    c = sqlite3.connect("file:%s?mode=ro" % HARD_DB.replace("\\", "/"), uri=True)
    try:
        return {"users": {r[0]: r[1] for r in
                          c.execute("SELECT username,balance_cents FROM users")},
                "orders": c.execute("SELECT COUNT(*) FROM orders").fetchone()[0]}
    finally:
        c.close()


def csrf_hard(tok):
    c = sqlite3.connect("file:%s?mode=ro" % HARD_DB.replace("\\", "/"), uri=True)
    try:
        r = c.execute("SELECT csrf_token FROM sessions WHERE token=?", (tok,)).fetchone()
        return r[0] if r else None
    finally:
        c.close()


def main():
    out = {"meta": {"timestamp": TS, "probe": os.path.basename(__file__),
                    "note": "Content-Length 动态计算；坐实残余绕过路径"}, "checks": {}}
    B = b"confirm=RESET"   # 13 字节

    # ---- D1 跨站复位（模拟同机受害浏览器）----
    print("[*] D1 cross-site reset with correct Content-Length", flush=True)
    d1 = []
    d1.append(run_reset_case(
        "cross_site_form_body(Origin/Referer/Sec-Fetch-Site=cross-site)",
        18096, HARD_DB,
        build("POST", "/__reset", B, "application/x-www-form-urlencoded",
              {"Origin": "http://evil.example", "Referer": "http://evil.example/poc.html",
               "Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate",
               "Sec-Fetch-Dest": "document"})))
    d1.append(run_reset_case(
        "cross_site_query_only(no body, confirm in query)",
        18096, HARD_DB,
        build("POST", "/__reset?confirm=RESET", b"", None,
              {"Origin": "http://evil.example", "Sec-Fetch-Site": "cross-site"})))
    d1.append(run_reset_case(
        "same_site_form_body(Origin=127.0.0.1:18096)",
        18096, HARD_DB,
        build("POST", "/__reset", B, "application/x-www-form-urlencoded",
              {"Origin": "http://127.0.0.1:18096"})))
    d1.append(run_reset_case(
        "no_origin_at_all(curl-like)",
        18096, HARD_DB,
        build("POST", "/__reset", B, "application/x-www-form-urlencoded")))
    out["checks"]["D1_cross_site_reset"] = d1

    # ---- D2 方法覆盖头 ----
    print("[*] D2 method override headers", flush=True)
    d2 = []
    for label, method, path, body, extra in (
            ("GET+X-HTTP-Method-Override:POST", "GET", "/__reset", b"", {"X-HTTP-Method-Override": "POST"}),
            ("GET+X-Method-Override", "GET", "/__reset", b"", {"X-Method-Override": "POST"}),
            ("GET+_method=POST(query)", "GET", "/__reset?confirm=RESET&_method=POST", b"", None),
            ("GET+confirm_in_query", "GET", "/__reset?confirm=RESET", b"", None),
    ):
        d2.append(run_reset_case(label, 18096, HARD_DB,
                                 build(method, path, body, None, extra)))
    out["checks"]["D2_method_override"] = d2

    # ---- D3 伪造来源头 ----
    print("[*] D3 spoofed origin headers", flush=True)
    d3 = []
    for label, extra in (
            ("X-Forwarded-For: 8.8.8.8", {"X-Forwarded-For": "8.8.8.8"}),
            ("X-Real-IP: 8.8.8.8", {"X-Real-IP": "8.8.8.8"}),
            ("X-Forwarded-For + X-Real-IP", {"X-Forwarded-For": "8.8.8.8", "X-Real-IP": "8.8.8.8"}),
            ("Forwarded: for=8.8.8.8", {"Forwarded": "for=8.8.8.8"}),
    ):
        d3.append(run_reset_case(label, 18096, HARD_DB,
                                 build("POST", "/__reset", B,
                                       "application/x-www-form-urlencoded", extra)))
    out["checks"]["D3_spoofed_origin_headers"] = d3

    # ---- D4 非 urlencoded 承载 confirm ----
    print("[*] D4 alternate content types", flush=True)
    d4 = []
    d4.append(run_reset_case("multipart/form-data with confirm",
                             18096, HARD_DB,
                             build("POST", "/__reset",
                                   b"--B\r\nContent-Disposition: form-data; name=\"confirm\"\r\n\r\nRESET\r\n--B--\r\n",
                                   "multipart/form-data; boundary=B")))
    d4.append(run_reset_case("text/plain body confirm=RESET", 18096, HARD_DB,
                             build("POST", "/__reset", B, "text/plain")))
    d4.append(run_reset_case("application/json body", 18096, HARD_DB,
                             build("POST", "/__reset", b'{"confirm":"RESET"}', "application/json")))
    d4.append(run_reset_case("no content-type but body present", 18096, HARD_DB,
                             build("POST", "/__reset", B, None)))
    out["checks"]["D4_alternate_content_types"] = d4

    # ---- D5 A2 四入口 multipart 变形 ----
    print("[*] D5 multipart on gated entries", flush=True)
    http_req(18096, "POST", "/__reset", "confirm=RESET")
    st, _, tok = http_req(18096, "POST", "/login", "username=alice&password=alice123")
    csrf = csrf_hard(tok)
    d5 = []
    for name, path, fields in (
            ("wallet_withdraw", "/wallet/withdraw", [("amount", "1")]),
            ("order_create", "/order/create", [("product_id", "1"), ("qty", "1")]),
    ):
        bnd = "BOUND"
        parts = []
        for k, v in fields:
            parts.append("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n" % (bnd, k, v))
        parts.append("--%s--\r\n" % bnd)
        body = "".join(parts).encode()
        s0 = hard_state()
        st1, t1, _ = http_req(18096, "POST", path, body,
                              cookie=tok, headers={"Content-Type": "multipart/form-data; boundary=" + bnd})
        s1 = hard_state()
        # 带 csrf 的 multipart
        parts2 = ["--%s\r\nContent-Disposition: form-data; name=\"csrf_token\"\r\n\r\n%s\r\n" % (bnd, csrf)]
        for k, v in fields:
            parts2.append("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n" % (bnd, k, v))
        parts2.append("--%s--\r\n" % bnd)
        body2 = "".join(parts2).encode()
        st2, t2, _ = http_req(18096, "POST", path, body2, cookie=tok,
                              headers={"Content-Type": "multipart/form-data; boundary=" + bnd})
        s2 = hard_state()
        d5.append({"entry": name, "multipart_no_csrf_status": st1,
                   "multipart_no_csrf_changed": s0 != s1,
                   "multipart_with_csrf_status": st2,
                   "multipart_with_csrf_changed": s1 != s2,
                   "state_before": s0, "state_after_csrf": s2})
    out["checks"]["D5_multipart_gated_entries"] = d5
    http_req(18096, "POST", "/__reset", "confirm=RESET")

    p = os.path.join(HERE, "loop2-verify-supplement4-%s.json" % TS)
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=2)
    print("[+] wrote %s" % p)
    print("sha256 =", hashlib.sha256(open(p, "rb").read()).hexdigest())


if __name__ == "__main__":
    main()
