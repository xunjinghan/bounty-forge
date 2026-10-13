"""t4-A3b：决定性竞态测试——order_create 先读余额后原子扣款，无余额条件（8095）。

设计：
  1. 记录并发前 demo 余额 B、qty=1 单价 1900 分。
  2. N 路并发 GET /order/create?product_id=3&qty=1（每个线程独立连接）。
  3. 记录并发后余额 B'、orders 新增条数、200/400 分布、负余额出现。
判定：
  - 若 B' < 0 → 确认「下单并发扣款可把余额扣成负数」（校验与扣款非同一原子操作）。
  - 若 B' >= 0 且成功数 = floor(B/1900) → 阴性。
"""
import json
import os
import sys
import threading
import time
import sqlite3
import importlib.util as ilu

HERE = os.path.dirname(os.path.abspath(__file__))
spec = ilu.spec_from_file_location("hunt_lib", os.path.join(HERE, "hunt-lib.py"))
lib = ilu.module_from_spec(spec)
spec.loader.exec_module(lib)

BASE = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace"
DB = os.path.join(BASE, "target-site-lab", "lab.db")
OUT = os.path.join(HERE, "hunt-a3b-race-order-20261012-1835.json")
rec = []
N = 30
PRICE = 1900


def bal(user):
    conn = sqlite3.connect(DB)
    v = conn.execute("SELECT balance_cents FROM users WHERE username=?", (user,)).fetchone()[0]
    n = conn.execute("SELECT count(*) FROM orders").fetchone()[0]
    ords = [tuple(r) for r in conn.execute(
        "SELECT id,user_id,qty,amount_cents,state FROM orders ORDER BY id")]
    conn.close()
    return v, n, ords


cookie = lib.get_cookie("demo", "demo123", record=rec)
B, N0, _ = bal("demo")
print("并发前 demo 余额 =", B, "orders =", N0)

results = []
lock = threading.Lock()


def worker(i):
    try:
        e = lib.send("GET", "/order/create?product_id=3&qty=1",
                     headers={"Cookie": cookie}, note=f"A3b race #{i}")
        out = {"i": i, "status": e["status"], "len": e["body_len"],
               "title": e["response_body"].split("<title>")[1].split("</title>")[0]
               if "<title>" in e["response_body"] else "",
               "error": e["error"]}
        with lock:
            rec.append(e)
    except Exception as exc:  # noqa: BLE001
        out = {"i": i, "status": None, "error": str(exc)}
    with lock:
        results.append(out)


ths = [threading.Thread(target=worker, args=(i,)) for i in range(N)]
t0 = time.time()
for t in ths:
    t.start()
for t in ths:
    t.join()
elapsed = round((time.time() - t0) * 1000)
B2, N1, ords = bal("demo")
ok = [r for r in results if r["status"] == 200]
insufficient = [r for r in ok if r.get("title") == "余额不足"]
created = [r for r in ok if r.get("title") == "下单结果"]
summary = {
    "generated": lib.now(), "N": N, "price_per_unit": PRICE,
    "balance_before": B, "balance_after": B2,
    "orders_before": N0, "orders_after": N1, "orders_delta": N1 - N0,
    "http": {"200": len(ok), "400": len(results) - len(ok)},
    "titles": {t: sum(1 for r in ok if r.get("title") == t) for t in
               {r.get("title") for r in ok}},
    "insufficient_responses": len(insufficient),
    "order_created_responses": len(created),
    "elapsed_ms": elapsed,
    "negative_balance": B2 < 0,
    "verdict": ("确认：并发下单把余额扣成负数（先校验后扣款，扣款语句无余额条件）"
                if B2 < 0 else "阴性：余额未变负"),
    "orders_after_list": ords,
}
print(json.dumps({k: v for k, v in summary.items() if k != "orders_after_list"},
                 ensure_ascii=False, indent=1))
print("orders:", ords)

# ---------------- A4b：并发领券幂等（bob，10 并发，券值 1000 分） ----------------
bob_cookie = lib.get_cookie("bob", "bob123", record=rec)


def bal_of(user):
    conn = sqlite3.connect(DB)
    v = conn.execute("SELECT balance_cents FROM users WHERE username=?", (user,)).fetchone()[0]
    c = conn.execute("SELECT count(*) FROM coupon_claims").fetchone()[0]
    conn.close()
    return v, c


b_before, claims_before = bal_of("bob")
coupon_results = []


def claim_worker(i):
    try:
        e = lib.send("GET", "/coupon/claim?code=WELCOME10", headers={"Cookie": bob_cookie},
                     note=f"A4b coupon race #{i}")
        out = {"i": i, "status": e["status"],
               "title": e["response_body"].split("<title>")[1].split("</title>")[0]
               if "<title>" in e["response_body"] else "",
               "error": e["error"]}
        with lock:
            rec.append(e)
    except Exception as exc:  # noqa: BLE001
        out = {"i": i, "status": None, "error": str(exc)}
    with lock:
        coupon_results.append(out)


ths = [threading.Thread(target=claim_worker, args=(i,)) for i in range(10)]
for t in ths:
    t.start()
for t in ths:
    t.join()
b_after, claims_after = bal_of("bob")
coupon_summary = {
    "generated": lib.now(),
    "balance_before": b_before, "balance_after": b_after,
    "delta": b_after - b_before,
    "claims_before": claims_before, "claims_after": claims_after,
    "http": {"200": sum(1 for r in coupon_results if r["status"] == 200),
             "other": sum(1 for r in coupon_results if r["status"] != 200)},
    "titles": {t: sum(1 for r in coupon_results if r.get("title") == t)
               for t in {r.get("title") for r in coupon_results}},
    "verdict": ("阴性：仅入账一次（唯一约束 + INSERT 先行生效）" if b_after - b_before == 1000
                else f"需复核：入账 {b_after - b_before} 分（预期 1000）"),
}
print(json.dumps(coupon_summary, ensure_ascii=False, indent=1))
summary["coupon_race"] = coupon_summary
with open(OUT, "w", encoding="utf-8") as fh:
    json.dump({"summary": summary, "raw_entries": rec}, fh, ensure_ascii=False, indent=1)
print("WROTE", OUT)
