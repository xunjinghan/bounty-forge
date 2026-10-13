#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
t3 补测探针 v5 —— A1/A3/A4 的绕过矩阵（自写）

覆盖验收要求的「每条至少 3 类绕过」：
  E1 A1 绕过：qty 边界/负数/超大、product_id 伪造、大额单、跨端点竞态、多会话并发
  E2 A3 绕过：旧 HMAC 派生值是否仍被接受（向后兼容）、跨用户 token、空 token、
              token 复用（同一 token 打多个端点）、大小写/空白变形
  E3 A4 绕过：登出后 Cookie 变体重放、并发登出、登出后 CSRF token 复用、
              重新登录是否换新 token（会话固定）
用法: python loop2-verify-probe5.py
"""
import hashlib
import hmac
import http.client as httpc
import json
import os
import sqlite3
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SB = os.path.join(HERE, "loop2-verify-sandbox")
ORIG_DB = os.path.join(SB, "orig", "lab.db")
HARD_DB = os.path.join(SB, "hard", "lab.db")
SECRET_KEY = "lab-secret-key-PLEASE-CHANGE-001"
TS = time.strftime("%Y%m%d-%H%M%S")


def http_req(port, method, path, body=None, cookie=None, headers=None, record=None):
    h = {"User-Agent": "lv-probe5/1.0"}
    if headers:
        h.update(headers)
    if cookie:
        h["Cookie"] = "token=%s" % cookie
    if body is not None and "Content-Type" not in h:
        h["Content-Type"] = "application/x-www-form-urlencoded"
    try:
        c = httpc.HTTPConnection("127.0.0.1", port, timeout=15)
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        raw = r.read()
        st = r.status
        sc = r.getheader("Set-Cookie") or ""
        c.close()
    except Exception as exc:
        st, raw, sc = -1, ("EXC %r" % (exc,)).encode(), ""
    if record is not None:
        record.append({"method": method, "path": path, "body": body,
                       "cookie": (cookie or "")[:16], "status": st,
                       "snippet": raw.decode("utf-8", "replace")[:200].replace("\n", " ")})
    tok = ""
    for part in sc.split(";"):
        if part.strip().startswith("token="):
            tok = part.strip()[6:]
    return st, raw.decode("utf-8", "replace"), tok


def login(port, u, p):
    st, _, tok = http_req(port, "POST", "/login", "username=%s&password=%s" % (u, p))
    return st, tok


def q(dbfile, sql, params=(), ro=True):
    if ro:
        c = sqlite3.connect("file:%s?mode=ro" % dbfile.replace("\\", "/"), uri=True)
    else:
        c = sqlite3.connect(dbfile)
    try:
        rows = [tuple(r) for r in c.execute(sql, params)]
        if not ro:
            c.commit()
        return rows
    finally:
        c.close()


def users(dbfile):
    return {r[0]: r[1] for r in q(dbfile, "SELECT username,balance_cents FROM users")}


def n_orders(dbfile):
    return q(dbfile, "SELECT COUNT(*) FROM orders")[0][0]


def csrf_of(dbfile, tok):
    r = q(dbfile, "SELECT csrf_token FROM sessions WHERE token=?", (tok,))
    return r[0][0] if r else None


def main():
    out = {"meta": {"timestamp": TS, "probe": os.path.basename(__file__)}, "checks": {}}
    P, DB = 18096, HARD_DB

    # ================= E1: A1 绕过矩阵 =================
    print("[*] E1 A1 bypass matrix", flush=True)
    http_req(P, "POST", "/__reset", "confirm=RESET")
    _, tok = login(P, "demo", "demo123")
    csrf = csrf_of(DB, tok)
    e1 = []

    def a1_case(label, body, expect_note):
        b0u, b0o = users(DB), n_orders(DB)
        st, txt, _ = http_req(P, "POST", "/order/create",
                              "csrf_token=%s&%s" % (csrf, body), cookie=tok)
        b1u, b1o = users(DB), n_orders(DB)
        neg = any(v < 0 for v in b1u.values())
        e1.append({"case": label, "payload": body, "status": st, "note": expect_note,
                   "balance_before": b0u["demo"], "balance_after": b1u["demo"],
                   "orders_before": b0o, "orders_after": b1o,
                   "balance_negative": neg,
                   "snippet": txt[:120].replace("\n", " ")})
        return neg

    a1_case("qty=0", "product_id=1&qty=0", "数量校验应 400")
    a1_case("qty=-1", "product_id=1&qty=-1", "负数数量应 400")
    a1_case("qty=2147483648", "product_id=1&qty=2147483648", "32 位溢出尝试")
    a1_case("qty=100(大额)", "product_id=1&qty=100", "29900*100=2990000 > 50000 -> 400")
    a1_case("qty=1e3", "product_id=1&qty=1e3", "非整数")
    a1_case("product_id=999", "product_id=999&qty=1", "商品不存在")
    a1_case("product_id=1' OR 1=1--", "product_id=1' OR 1=1--&qty=1", "注入尝试")
    a1_case("缺 product_id", "qty=1", "缺参")
    a1_case("qty 重复参数", "product_id=1&qty=1&qty=100", "参数污染")
    # 跨端点竞态：提现 + 下单 同波
    http_req(P, "POST", "/__reset", "confirm=RESET")
    _, tokd = login(P, "demo", "demo123")
    csrfd = csrf_of(DB, tokd)
    b = threading.Barrier(20)
    res = []
    lk = threading.Lock()

    def w(i):
        try:
            b.wait(timeout=15)
        except Exception:
            pass
        if i % 2:
            st, _, _ = http_req(P, "POST", "/order/create",
                                "csrf_token=%s&product_id=1&qty=1" % csrfd, cookie=tokd)
        else:
            st, _, _ = http_req(P, "POST", "/wallet/withdraw",
                                "csrf_token=%s&amount=29900" % csrfd, cookie=tokd)
        with lk:
            res.append((i, st))

    ths = [threading.Thread(target=w, args=(i,)) for i in range(20)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    e1.append({"case": "跨端点竞态(下单/提现同波20并发)", "payload": "mixed",
               "status_counts": {s: sum(1 for _, x in res if x == s) for _, s in res},
               "balance_after": users(DB)["demo"], "orders_after": n_orders(DB),
               "balance_negative": any(v < 0 for v in users(DB).values()),
               "snippet": "20 并发混合端点"})
    # 多会话并发（同用户 3 会话）
    http_req(P, "POST", "/__reset", "confirm=RESET")
    toks = []
    for _ in range(3):
        _, t_ = login(P, "demo", "demo123")
        toks.append(t_)
    cs = [csrf_of(DB, t_) for t_ in toks]
    b2 = threading.Barrier(30)
    res2 = []
    lk2 = threading.Lock()

    def w2(i):
        try:
            b2.wait(timeout=15)
        except Exception:
            pass
        k = i % 3
        st, _, _ = http_req(P, "POST", "/order/create",
                            "csrf_token=%s&product_id=1&qty=1" % cs[k], cookie=toks[k])
        with lk2:
            res2.append((i, k, st))

    ths2 = [threading.Thread(target=w2, args=(i,)) for i in range(30)]
    for t in ths2:
        t.start()
    for t in ths2:
        t.join()
    e1.append({"case": "多会话并发(同用户3会话, 30并发)", "payload": "3 sessions x 10",
               "status_counts": {s: sum(1 for _, _, x in res2 if x == s) for _, _, s in res2},
               "balance_after": users(DB)["demo"], "orders_after": n_orders(DB),
               "balance_negative": any(v < 0 for v in users(DB).values()),
               "snippet": "同用户多会话抢同一余额行"})
    out["checks"]["E1_A1_bypass"] = e1
    out["checks"]["E1_A1_summary"] = {
        "any_negative": any(c.get("balance_negative") for c in e1),
        "cases": len(e1)}

    # ================= E2: A3 绕过矩阵 =================
    print("[*] E2 A3 bypass matrix", flush=True)
    http_req(P, "POST", "/__reset", "confirm=RESET")
    _, tok_a = login(P, "alice", "alice123")
    _, tok_b = login(P, "bob", "bob123")
    page_tok = csrf_of(DB, tok_a)
    hmac_old = hmac.new(SECRET_KEY.encode(), tok_a.encode(), hashlib.sha256).hexdigest()
    e2 = []

    def a3_case(label, token_value, use_tok, note, path="/wallet/withdraw", extra=""):
        b0 = users(DB)
        st, txt, _ = http_req(P, "POST", path,
                              "csrf_token=%s&amount=1%s" % (token_value, extra),
                              cookie=use_tok)
        b1 = users(DB)
        e2.append({"case": label, "token_used": (token_value or "")[:48], "note": note,
                   "status": st, "state_changed": b0 != b1,
                   "snippet": txt[:110].replace("\n", " ")})

    a3_case("HMAC 旧派生值(向后兼容探测)", hmac_old, tok_a,
            "若接受 = 加固可被 SECRET_KEY 泄露绕过")
    a3_case("跨会话(用 bob 的 token 打 alice 会话)", csrf_of(DB, tok_b), tok_a, "应 403")
    a3_case("空 token", "", tok_a, "应 403")
    a3_case("token 大小写翻转", page_tok.upper(), tok_a, "应 403")
    a3_case("token 去尾字符", page_tok[:-1], tok_a, "应 403")
    a3_case("token 加空白", page_tok + " ", tok_a, "应 403")
    a3_case("token 复用打不同端点", page_tok, tok_a, "同 token 打 order/status",
            path="/order/status", extra="&order_id=2&state=paid")
    # 多会话下同一 token 复用（3 次）
    reuse = []
    for i in range(3):
        b0 = users(DB)
        st, _, _ = http_req(P, "POST", "/wallet/withdraw",
                            "csrf_token=%s&amount=1" % page_tok, cookie=tok_a)
        reuse.append(st)
    e2.append({"case": "同 token 连续复用 3 次", "token_used": page_tok[:48],
               "note": "token 无一次性限制（设计如此，非缺陷）", "statuses": reuse,
               "state_changed": True})
    out["checks"]["E2_A3_bypass"] = e2
    out["checks"]["E2_A3_hmac_check"] = {
        "page_token": page_tok, "page_len": len(page_tok or ""),
        "hmac_derived": hmac_old, "hmac_len": len(hmac_old),
        "page_equals_hmac": page_tok == hmac_old,
        "hmac_value_accepted": e2[0]["status"] == 200 and e2[0]["state_changed"],
    }

    # ================= E3: A4 绕过矩阵 =================
    print("[*] E3 A4 bypass matrix", flush=True)
    http_req(P, "POST", "/__reset", "confirm=RESET")
    _, tok_v = login(P, "alice", "alice123")
    csrf_v = csrf_of(DB, tok_v)
    sess_before = q(DB, "SELECT COUNT(*) FROM sessions")[0][0]
    st_logout, _, _ = http_req(P, "GET", "/logout", cookie=tok_v)
    sess_after = q(DB, "SELECT COUNT(*) FROM sessions")[0][0]
    e3 = []
    variants = [("原 token", tok_v), ("大写", tok_v.upper()), ("带引号", '"%s"' % tok_v),
                ("加空格", tok_v + " "), ("截断", tok_v[:-1]), ("空", "")]
    for label, val in variants:
        st, txt, _ = http_req(P, "GET", "/home", cookie=val)
        st2, _, _ = http_req(P, "POST", "/wallet/withdraw",
                             "csrf_token=%s&amount=1" % csrf_v, cookie=val)
        e3.append({"variant": label, "home_status": st, "write_status": st2,
                   "home_is_wallet_page": "我的钱包" in txt})
    # 并发登出
    http_req(P, "POST", "/__reset", "confirm=RESET")
    _, tok_c = login(P, "alice", "alice123")
    outs = []
    lk3 = threading.Lock()
    bb = threading.Barrier(10)

    def lo(i):
        try:
            bb.wait(timeout=10)
        except Exception:
            pass
        st, _, _ = http_req(P, "GET", "/logout", cookie=tok_c)
        with lk3:
            outs.append(st)

    ths3 = [threading.Thread(target=lo, args=(i,)) for i in range(10)]
    for t in ths3:
        t.start()
    for t in ths3:
        t.join()
    sess_after_concurrent = q(DB, "SELECT COUNT(*) FROM sessions")[0][0]
    st_after = http_req(P, "GET", "/home", cookie=tok_c)[0]
    # 会话固定：重新登录是否换 token
    http_req(P, "POST", "/__reset", "confirm=RESET")
    _, t1 = login(P, "alice", "alice123")
    _, t2 = login(P, "alice", "alice123")
    out["checks"]["E3_A4_bypass"] = {
        "sessions_before_logout": sess_before, "sessions_after_logout": sess_after,
        "logout_status": st_logout, "replay_variants": e3,
        "concurrent_logout_statuses": outs, "sessions_after_concurrent_logout": sess_after_concurrent,
        "home_after_concurrent_logout": st_after,
        "token_rotated_on_relogin": t1 != t2,
        "t1": t1[:20], "t2": t2[:20],
    }

    p = os.path.join(HERE, "loop2-verify-supplement5-%s.json" % TS)
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=2)
    print("[+] wrote %s" % p)
    print("sha256 =", hashlib.sha256(open(p, "rb").read()).hexdigest())


if __name__ == "__main__":
    main()
