#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Loop2 A1 复测：/order/create 条件更新后的并发原子性验证（8095 加固版）。

判定标准（next-round-plan.md §2 A1）：30 并发 x 3 轮，库内余额从不为负，
且订单数 <= balance // price。

用法: python t2-a1-concurrency-20261012.py
"""
import json
import re
import sqlite3
import threading
import time
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:8095"
DB = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace\target-site-lab\lab.db"
N = 30
ROUNDS = 3


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """登录是 302，必须拿原始响应头里的 Set-Cookie。"""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def login(user, pw):
    req = urllib.request.Request(
        BASE + "/login",
        data=urllib.parse.urlencode({"username": user, "password": pw}).encode(),
        method="POST")
    try:
        r = OPENER.open(req)
    except urllib.error.HTTPError as e:
        r = e
    cookie = r.headers.get("Set-Cookie", "")
    token = re.search(r"token=([^;]+)", cookie).group(1)
    return token


def csrf_of(token):
    req = urllib.request.Request(BASE + "/home",
                                 headers={"Cookie": f"token={token}"})
    try:
        r = OPENER.open(req)
    except urllib.error.HTTPError as e:
        r = e
    body = r.read().decode("utf-8", "replace")
    return re.search(r'name="csrf_token" value="([^"]+)"', body).group(1)


def db_state(username):
    c = sqlite3.connect(DB)
    bal = c.execute("SELECT balance_cents FROM users WHERE username=?",
                    (username,)).fetchone()[0]
    uid = c.execute("SELECT id FROM users WHERE username=?",
                    (username,)).fetchone()[0]
    orders = c.execute("SELECT COUNT(*) FROM orders WHERE user_id=?",
                       (uid,)).fetchone()[0]
    c.close()
    return bal, orders


def one_order(token, csrf, pid):
    """返回 (http_code, 是否命中余额不足)。"""
    req = urllib.request.Request(
        BASE + "/order/create",
        data=urllib.parse.urlencode(
            {"product_id": pid, "qty": "1", "csrf_token": csrf}).encode(),
        headers={"Cookie": f"token={token}"}, method="POST")
    try:
        with OPENER.open(req) as r:
            code, body = r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        code, body = e.code, e.read().decode("utf-8", "replace")
    return code, ("余额不足" in body)


def hammer(user, pw, pid, price, rounds=ROUNDS, n=N):
    tok = login(user, pw)
    csrf = csrf_of(tok)
    result = {"user": user, "product_id": pid, "price_cents": price,
              "concurrency": n, "rounds": rounds, "rounds_detail": []}
    for rd in range(1, rounds + 1):
        bal0, ord0 = db_state(user)
        codes = []
        neg = []
        lock = threading.Lock()

        def worker():
            c, is_neg = one_order(tok, csrf, pid)
            with lock:
                codes.append(c)
                neg.append(is_neg)

        ts = [threading.Thread(target=worker) for _ in range(n)]
        t0 = time.time()
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        dt = time.time() - t0
        bal1, ord1 = db_state(user)
        result["rounds_detail"].append({
            "round": rd,
            "balance_before": bal0, "balance_after": bal1,
            "orders_before": ord0, "orders_after": ord1,
            "new_orders": ord1 - ord0,
            "http_200": codes.count(200),
            "http_400_insufficient": sum(1 for x in neg if x),
            "codes": sorted(set(codes)),
            "balance_negative": bal1 < 0,
            "affordable_max": bal0 // price,
            "orders_within_limit": (ord1 - ord0) <= (bal0 // price),
            "seconds": round(dt, 3),
        })
    result["all_balances_non_negative"] = all(
        not d["balance_negative"] for d in result["rounds_detail"])
    result["all_orders_within_limit"] = all(
        d["orders_within_limit"] for d in result["rounds_detail"])
    return result


if __name__ == "__main__":
    out = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
           "target": BASE + "/order/create",
           "note": "加固后：条件更新 UPDATE ... AND balance_cents >= ?",
           "cases": []}
    # bob: 100 分，产品 3（1900 分）→ 可支付 0 单，期望全失败且余额不变
    out["cases"].append(hammer("bob", "bob123", 3, 1900))
    # demo: 50000 分，产品 1（29900 分）→ 可支付 1 单，期望恰好 1 单成功
    out["cases"].append(hammer("demo", "demo123", 1, 29900))
    print(json.dumps(out, ensure_ascii=False, indent=2))
    path = (r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace"
            r"\security\learning\_evidence\t2-a1-concurrency-20261012.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=2)
    print("[written]", path)
