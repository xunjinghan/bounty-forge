#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
t3 补测探针 v3 —— 修正 v1/v2 的判定方法缺陷（自写）

修正点：
  A. 复位判定：v1/v2 用 lab.db sha256 前后比对 -> 复位后回到种子态，哈希复原 = 假阴性。
     改用「canary 行」判定：先直接往沙箱库插一行 messages(author='CANARY')，
     任何真实复位都会重建库 -> canary 消失。这是不可伪装的复位证据。
  B. //__reset 路径归属：v2 用 http.client（可能改写路径），改用裸 socket 逐字节发送，
     排除客户端归一化因素。
  C. 跨站复位：用 canary + reset-audit.log 行数增量双重确认（v2 只靠 sha256，不可信）。

用法: python loop2-verify-probe3.py
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


def raw_http(port, raw_bytes, timeout=10):
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
            if len(data) > 200000:
                break
        return data
    finally:
        s.close()


def status_of(data):
    line = data.split(b"\r\n", 1)[0].decode("utf-8", "replace")
    parts = line.split()
    return (int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else -1), line


def title_of(data):
    t = data.decode("utf-8", "replace")
    if "<title>" in t:
        return t.split("<title>", 1)[1].split("</title>", 1)[0]
    return ""


def canary(dbfile, action="insert"):
    """往沙箱库插/查 canary 行（直接库操作，不经 HTTP）。"""
    c = sqlite3.connect(dbfile)
    try:
        if action == "insert":
            c.execute("INSERT INTO messages(author,content) VALUES('CANARY','t3-marker')")
            c.commit()
            return True
        return c.execute("SELECT COUNT(*) FROM messages WHERE author='CANARY'").fetchone()[0]
    finally:
        c.close()


def audit_lines():
    p = os.path.join(SB, "hard", "reset-audit.log")
    if not os.path.exists(p):
        return 0
    return sum(1 for _ in open(p, encoding="utf-8", errors="replace"))


def sess_state(dbfile):
    c = sqlite3.connect("file:%s?mode=ro" % dbfile.replace("\\", "/"), uri=True)
    try:
        return {"sessions": c.execute("SELECT COUNT(*) FROM sessions").fetchone()[0],
                "messages": c.execute("SELECT COUNT(*) FROM messages").fetchone()[0],
                "users": {r[0]: r[1] for r in
                          c.execute("SELECT username,balance_cents FROM users")},
                "orders": c.execute("SELECT COUNT(*) FROM orders").fetchone()[0]}
    finally:
        c.close()


def http_req(port, method, path, body=None, cookie=None):
    h = {"User-Agent": "lv-probe3/1.0"}
    if cookie:
        h["Cookie"] = "token=%s" % cookie
    if body is not None:
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


def csrf_hard(tok):
    c = sqlite3.connect("file:%s?mode=ro" % HARD_DB.replace("\\", "/"), uri=True)
    try:
        r = c.execute("SELECT csrf_token FROM sessions WHERE token=?", (tok,)).fetchone()
        return r[0] if r else None
    finally:
        c.close()


def main():
    out = {"meta": {"timestamp": TS, "probe": os.path.basename(__file__),
                    "method_fix": "复位判定改用 canary 行 + 裸 socket 排除客户端归一化"},
           "checks": {}}

    # ---------- C1 原件：HEAD 是否真删库（canary 判定） ----------
    print("[*] C1 orig HEAD canary test", flush=True)
    canary(ORIG_DB, "insert")
    before = sess_state(ORIG_DB)
    raw = raw_http(18095, b"HEAD /__reset HTTP/1.1\r\nHost: 127.0.0.1:18095\r\n"
                          b"Connection: close\r\n\r\n")
    st, line = status_of(raw)
    time.sleep(0.4)
    after = sess_state(ORIG_DB)
    wiped = after["messages"] < before["messages"]
    out["checks"]["C1_orig_HEAD"] = {
        "status": st, "status_line": line, "title": title_of(raw),
        "canary_before": before["messages"], "canary_after": after["messages"],
        "canary_wiped": wiped,
        "verdict": "原件 HEAD /__reset 触发重建" if wiped else "未触发",
    }

    # ---------- C2 加固件：HEAD / GET / 爬虫式访问 ----------
    print("[*] C2 hard HEAD/GET/crawler canary test", flush=True)
    c2 = []
    cases = [
        ("HEAD", b"HEAD /__reset HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n"),
        ("GET", b"GET /__reset HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n"),
        ("GET-crawler-ua",
         b"GET /__reset HTTP/1.1\r\nHost: h\r\nUser-Agent: Mozilla/5.0 (compatible;"
         b" Googlebot/2.1; +http://www.google.com/bot.html)\r\nConnection: close\r\n\r\n"),
        ("GET-img-tag",
         b"GET /__reset HTTP/1.1\r\nHost: h\r\nAccept: image/avif,image/webp,*/*\r\n"
         b"Sec-Fetch-Dest: image\r\nSec-Fetch-Mode: no-cors\r\n"
         b"Sec-Fetch-Site: cross-site\r\nConnection: close\r\n\r\n"),
        ("GET-range-probe",
         b"GET /__reset HTTP/1.1\r\nHost: h\r\nRange: bytes=0-1024\r\n"
         b"Connection: close\r\n\r\n"),
    ]
    for label, rawreq in cases:
        canary(HARD_DB, "insert")
        a0 = audit_lines()
        s0 = sess_state(HARD_DB)
        raw = raw_http(18096, rawreq)
        st, line = status_of(raw)
        time.sleep(0.4)
        s1 = sess_state(HARD_DB)
        a1 = audit_lines()
        c2.append({"case": label, "status": st, "status_line": line,
                   "title": title_of(raw),
                   "canary_before": s0["messages"], "canary_after": s1["messages"],
                   "reset_triggered": s1["messages"] < s0["messages"],
                   "audit_lines_delta": a1 - a0})
    out["checks"]["C2_hard_head_get_crawler"] = c2

    # ---------- C3 //__reset 裸 socket 路径归属 ----------
    print("[*] C3 raw-socket path attribution", flush=True)
    c3 = []
    for target, port, dbf in (("orig", 18095, ORIG_DB), ("hard", 18096, HARD_DB)):
        for p in ("//__reset", "/__reset", "/./__reset", "/__reset/", "/__reset;"):
            canary(dbf, "insert")
            s0 = sess_state(dbf)
            raw = raw_http(port, ("GET %s HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n"
                                  % p).encode())
            st, line = status_of(raw)
            time.sleep(0.35)
            s1 = sess_state(dbf)
            c3.append({"target": target, "path": p, "status": st, "status_line": line,
                       "title": title_of(raw), "reset_triggered": s1["messages"] < s0["messages"]})
    out["checks"]["C3_raw_path_attribution"] = c3

    # ---------- C4 跨站 POST 复位（canary + audit 双证） ----------
    print("[*] C4 cross-site reset via raw socket", flush=True)
    c4 = []
    variants = [
        ("cross_site_form_body",
         b"POST /__reset HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\n"
         b"Origin: http://evil.example\r\nReferer: http://evil.example/poc.html\r\n"
         b"Sec-Fetch-Site: cross-site\r\nSec-Fetch-Mode: navigate\r\n"
         b"Sec-Fetch-Dest: document\r\nContent-Length: 14\r\nConnection: close\r\n\r\nconfirm=RESET"),
        ("cross_site_query_only",
         b"POST /__reset?confirm=RESET HTTP/1.1\r\nHost: h\r\n"
         b"Origin: http://evil.example\r\nSec-Fetch-Site: cross-site\r\n"
         b"Content-Length: 0\r\nConnection: close\r\n\r\n"),
        ("same_site_body",
         b"POST /__reset HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\n"
         b"Origin: http://127.0.0.1:18096\r\nContent-Length: 14\r\nConnection: close\r\n\r\nconfirm=RESET"),
    ]
    for label, rawreq in variants:
        canary(HARD_DB, "insert")
        s0 = sess_state(HARD_DB)
        a0 = audit_lines()
        raw = raw_http(18096, rawreq)
        st, line = status_of(raw)
        time.sleep(0.4)
        s1 = sess_state(HARD_DB)
        a1 = audit_lines()
        c4.append({"case": label, "status": st, "status_line": line,
                   "canary_before": s0["messages"], "canary_after": s1["messages"],
                   "reset_triggered": s1["messages"] < s0["messages"],
                   "audit_lines_delta": a1 - a0,
                   "title": title_of(raw)})
    out["checks"]["C4_cross_site_reset"] = c4

    # ---------- C5 原件对照：跨站 POST（无 confirm 要求） ----------
    print("[*] C5 orig cross-site reset baseline", flush=True)
    canary(ORIG_DB, "insert")
    s0 = sess_state(ORIG_DB)
    raw = raw_http(18095, b"POST /__reset HTTP/1.1\r\nHost: h\r\nOrigin: http://evil.example\r\n"
                          b"Content-Length: 0\r\nConnection: close\r\n\r\n")
    st, line = status_of(raw)
    time.sleep(0.4)
    s1 = sess_state(ORIG_DB)
    out["checks"]["C5_orig_cross_site_baseline"] = {
        "status": st, "canary_before": s0["messages"], "canary_after": s1["messages"],
        "reset_triggered": s1["messages"] < s0["messages"], "status_line": line}

    # ---------- C6 A2 未覆盖入口：GET 写 ----------
    print("[*] C6 uncovered write entries", flush=True)
    http_req(18096, "POST", "/__reset", "confirm=RESET")
    st, _, tok = http_req(18096, "POST", "/login", "username=alice&password=alice123")
    csrf = csrf_hard(tok)
    c6 = []
    for name, path, body in (("wallet_transfer", "/wallet/transfer", "to=bob&amount=7"),
                             ("change_password", "/change-password", "new_password=zzz999")):
        s0 = sess_state(HARD_DB)
        st, txt, _ = http_req(18096, "GET", path + "?" + body + "&csrf_token=" + csrf,
                              cookie=tok)
        s1 = sess_state(HARD_DB)
        c6.append({"entry": name, "method": "GET", "status": st,
                   "balances_before": s0["users"], "balances_after": s1["users"],
                   "state_changed": s0 != s1,
                   "verdict": "GET 仍可改状态" if s0 != s1 else "未变更"})
    out["checks"]["C6_uncovered_write_entries"] = c6
    http_req(18096, "POST", "/__reset", "confirm=RESET")

    # ---------- 证据文件哈希 ----------
    p = os.path.join(HERE, "loop2-verify-supplement3-%s.json" % TS)
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=2)
    print("[+] wrote %s" % p)
    print("sha256 =", hashlib.sha256(open(p, "rb").read()).hexdigest())


if __name__ == "__main__":
    main()
