#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
t3 补测探针 v6 —— 真实 8095 上的 A1 并发验证（自写）

安全设计（硬纪律：写端点先判定、账号状态变更先报队长）：
  * 只打 127.0.0.1:8095，绝不打 /__reset（配额已用尽，队长明令）。
  * 载荷选「必然失败」型：bob 余额 100 分，商品单价 1900/29900 分 -> 无论并发与否都应 400。
    因此本测试的期望是「零状态变更」；若真出现扣款/负余额，那就是 A1 未修复的阳性证据。
  * 每轮前后直查 lab.db 取余额与订单数（不采信响应自报值）。

用法: python loop2-verify-probe6.py
"""
import hashlib
import http.client as httpc
import json
import os
import sqlite3
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
WS = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
REAL_DB = os.path.join(WS, "target-site-lab", "lab.db")
TS = time.strftime("%Y%m%d-%H%M%S")
PORT = 8095


def http_req(method, path, body=None, cookie=None):
    h = {"User-Agent": "lv-probe6/1.0"}
    if cookie:
        h["Cookie"] = "token=%s" % cookie
    if body is not None:
        h["Content-Type"] = "application/x-www-form-urlencoded"
    try:
        c = httpc.HTTPConnection("127.0.0.1", PORT, timeout=15)
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        raw = r.read()
        st = r.status
        sc = r.getheader("Set-Cookie") or ""
        c.close()
    except Exception as exc:
        st, raw, sc = -1, ("EXC %r" % (exc,)).encode(), ""
    tok = ""
    for part in sc.split(";"):
        if part.strip().startswith("token="):
            tok = part.strip()[6:]
    return st, raw.decode("utf-8", "replace"), tok


def ro(sql, params=()):
    c = sqlite3.connect("file:%s?mode=ro" % REAL_DB.replace("\\", "/"), uri=True)
    try:
        return [tuple(r) for r in c.execute(sql, params)]
    finally:
        c.close()


def snap():
    return {"balances": {r[0]: r[1] for r in ro("SELECT username,balance_cents FROM users")},
            "orders": ro("SELECT COUNT(*) FROM orders")[0][0],
            "sessions": ro("SELECT COUNT(*) FROM sessions")[0][0],
            "db_sha256": hashlib.sha256(open(REAL_DB, "rb").read()).hexdigest()}


def csrf_of(tok):
    r = ro("SELECT csrf_token FROM sessions WHERE token=?", (tok,))
    return r[0][0] if r else None


def main():
    out = {"meta": {"timestamp": TS, "probe": os.path.basename(__file__),
                    "target": "127.0.0.1:8095", "note": "零状态变更载荷；未打 /__reset"},
           "rounds": []}
    st, _, tok = http_req("POST", "/login", "username=bob&password=bob123")
    out["meta"]["login_status"] = st
    csrf = csrf_of(tok)
    out["meta"]["csrf_token_len"] = len(csrf or "")
    for rnd in range(1, 4):
        for pid, price in ((1, 29900), (3, 1900)):
            before = snap()
            barrier = threading.Barrier(30)
            res = []
            lk = threading.Lock()

            def w(i):
                try:
                    barrier.wait(timeout=20)
                except Exception:
                    pass
                st_, _, _ = http_req("POST", "/order/create",
                                     "csrf_token=%s&product_id=%d&qty=1" % (csrf, pid),
                                     cookie=tok)
                with lk:
                    res.append((i, st_))

            ths = [threading.Thread(target=w, args=(i,)) for i in range(30)]
            for t in ths:
                t.start()
            for t in ths:
                t.join()
            after = snap()
            codes = {}
            for _, s in res:
                codes[s] = codes.get(s, 0) + 1
            out["rounds"].append({
                "round": rnd, "product_id": pid, "unit_price": price, "concurrency": 30,
                "status_counts": codes,
                "bob_balance_before": before["balances"]["bob"],
                "bob_balance_after": after["balances"]["bob"],
                "orders_before": before["orders"], "orders_after": after["orders"],
                "balance_negative": after["balances"]["bob"] < 0,
                "state_changed": (before["balances"] != after["balances"]
                                  or before["orders"] != after["orders"]),
                "db_sha_before": before["db_sha256"][:16],
                "db_sha_after": after["db_sha256"][:16],
            })
    out["summary"] = {
        "any_negative": any(r["balance_negative"] for r in out["rounds"]),
        "any_state_change": any(r["state_changed"] for r in out["rounds"]),
        "rounds": len(out["rounds"]),
        "total_requests": len(out["rounds"]) * 30,
        "all_400": all(set(r["status_counts"]) == {400} for r in out["rounds"]),
    }
    out["final_snapshot"] = snap()
    p = os.path.join(HERE, "loop2-verify-real8095-a1-%s.json" % TS)
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=2)
    print("[+] wrote %s" % p)
    print(json.dumps(out["summary"], ensure_ascii=False))
    print("sha256 =", hashlib.sha256(open(p, "rb").read()).hexdigest())


if __name__ == "__main__":
    main()
