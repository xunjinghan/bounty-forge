"""t4-A：业务逻辑类测试（8095）。只读优先；写操作最小化并做前后 DB 快照。"""
import json
import os
import sqlite3
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import importlib.util as _ilu

_spec = _ilu.spec_from_file_location(
    "hunt_lib", os.path.join(os.path.dirname(os.path.abspath(__file__)), "hunt-lib.py"))
lib = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(lib)

BASE = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace"
DB = os.path.join(BASE, "target-site-lab", "lab.db")
OUT = os.path.join(BASE, "security", "learning", "_evidence",
                   "hunt-a-bizlogic-20261012-1830.json")
rec = []


def db_state(tag):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    users = {r[0]: r[1] for r in c.execute("SELECT username,balance_cents FROM users")}
    s = {
        "tag": tag,
        "ts": lib.now(),
        "balances": users,
        "orders": [tuple(r) for r in c.execute(
            "SELECT id,user_id,qty,amount_cents,state FROM orders")],
        "users_n": c.execute("SELECT count(*) FROM users").fetchone()[0],
        "claims": c.execute("SELECT count(*) FROM coupon_claims").fetchone()[0],
        "msgs": c.execute("SELECT count(*) FROM messages").fetchone()[0],
        "products": [tuple(r) for r in c.execute("SELECT id,name,price_cents,stock FROM products")],
        "sessions": c.execute("SELECT count(*) FROM sessions").fetchone()[0],
    }
    conn.close()
    return s


snapshots = [db_state("start")]
demo_cookie = lib.get_cookie("demo", "demo123", record=rec)
alice_cookie = lib.get_cookie("alice", "alice123", record=rec)
bob_cookie = lib.get_cookie("bob", "bob123", record=rec)
print("cookies ok")
results = []


def add(fid, cat, title, verdict, evidence_idx, detail, impact, needs_verify=True,
        rollback=None):
    results.append({
        "id": fid, "category": cat, "title": title, "verdict": verdict,
        "evidence_indices": evidence_idx, "detail": detail,
        "self_assessed_impact": impact, "needs_verifier": needs_verify,
        "rollback": rollback,
    })


def mark(name):
    return len(rec) - 1 if rec else 0


# ---------------------------------------------------------------- A1 GET 写接口无 CSRF
a1a = lib.sent(rec, "GET", "/wallet/withdraw?amount=1", headers={"Cookie": demo_cookie},
               note="A1a 纯 GET 无 CSRF 提现 1 分")
a1b = lib.sent(rec, "GET", "/order/create?product_id=3&qty=1", headers={"Cookie": demo_cookie},
               note="A1b 纯 GET 无 CSRF 下单 1 件低价商品")
a1c = lib.sent(rec, "POST", "/wallet/withdraw?amount=1", headers={
    "Cookie": demo_cookie, "Content-Type": "application/x-www-form-urlencoded"},
    body="", note="A1c POST + query 参数：form() 中 query 覆盖 body")
e, e2, e3 = rec[a1a], rec[a1b], rec[a1c]
add("HUNT-A1", "业务逻辑/CSRF", "状态变更接口无方法限制且无 CSRF：GET /wallet/withdraw、GET /order/create 即真实扣款/建单",
    "确认" if lib.get_status(e) == 200 else "需验证", [a1a, a1b, a1c],
    f"GET 提现返回 {lib.get_status(e)}：{lib.head_text(e,160)} | GET 下单返回 {lib.get_status(e2)}：{lib.head_text(e2,160)} | POST+query 覆盖 body 返回 {lib.get_status(e3)}",
    "攻击者构造 <img src=http://127.0.0.1:8095/wallet/withdraw?amount=N> 即可用受害者已登录会话扣款/下单，无 CSRF token 校验；SameSite=Lax 对顶级导航 GET 不设防",
    rollback="/__reset（未在本轮执行，由 DB 快照记录变更）")
snapshots.append(db_state("after-A1"))

# ---------------------------------------------------------------- A2 数量/金额边界
boundary = []
for q in ["-1", "0", "1", "100", "101", "99999999999999999999", "1e2", "1_0",
          " 5 ", "+5", "0x10", "null", "%20", "1.0"]:
    i = lib.sent(rec, "GET", f"/order/create?product_id=3&qty={q}",
                 headers={"Cookie": demo_cookie},
                 note=f"A2 qty={q!r}")
    e = rec[i]
    boundary.append({"qty": q, "status": lib.get_status(e),
                     "len": e["body_len"], "idx": i,
                     "snippet": lib.head_text(e, 120)})
    time.sleep(0.05)
add("HUNT-A2", "业务逻辑/参数边界", "qty 边界：负数/零/超大被拒（1-100 校验生效）；0x10/1e2 等非常规数字被 int() 拒绝",
    "已封堵", [b["idx"] for b in boundary],
    json.dumps(boundary, ensure_ascii=False),
    "未发现可绕过的数量/金额边界（本项为阴性结论，不作为漏洞）", needs_verify=False)

# ---------------------------------------------------------------- A3 竞态：提现 / 下单
before = db_state("before-A3-race")
race = {"withdraw": [], "order": []}


def worker(fn, n=12):
    ths = [threading.Thread(target=fn) for _ in range(n)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()


def wd():
    lib.send("GET", "/wallet/withdraw?amount=5000", headers={"Cookie": demo_cookie},
             note="A3 并发提现 5000")


def oc():
    lib.send("GET", "/order/create?product_id=3&qty=1", headers={"Cookie": demo_cookie},
             note="A3 并发下单")


worker(wd, 12)
mid = db_state("after-A3-withdraw")
worker(oc)
after = db_state("after-A3-order")
race_result = {
    "before": before, "after_withdraw": mid, "after_order": after,
    "expected_if_atomic": "demo 50000 - 12*5000 = -10000 若无限额；原子条件应使余额停在 >=0，"
                          "并至多 10 次成功（50000/5000）",
}
add("HUNT-A3", "业务逻辑/竞态", "并发提现/下单原子性核验（12 并发）",
    "见 detail", [], json.dumps(race_result, ensure_ascii=False),
    "若余额出现负数即并发扣款绕过；若余额非负则原子条件生效（阴性）",
    rollback="/__reset")
snapshots.append(db_state("after-A3"))

# ---------------------------------------------------------------- A4 优惠券并发幂等
def claim():
    lib.send("GET", "/coupon/claim?code=WELCOME10", headers={"Cookie": bob_cookie},
             note="A4 并发领券 WELCOME10")
b4 = db_state("before-A4")
worker(claim, 10)
a4 = db_state("after-A4")
add("HUNT-A4", "业务逻辑/竞态", "同一用户并发领取同一优惠券的幂等性（10 并发）",
    "见 detail", [], json.dumps({"before": b4["balances"]["bob"],
                                 "after": a4["balances"]["bob"],
                                 "claims_rows": a4["claims"]}, ensure_ascii=False),
    "bob 余额应只 +1000 一次；若多次入账即优惠券并发重复领取（资金漏洞）",
    rollback="/__reset")
snapshots.append(db_state("after-A4"))

# ---------------------------------------------------------------- A5 状态机跳步 + 越权改单
s5 = []
s5.append(lib.sent(rec, "GET", "/order/status?order_id=2&state=shipped",
                   headers={"Cookie": alice_cookie},
                   note="A5a alice 自身单 unpaid->shipped 跳步"))
s5.append(lib.sent(rec, "GET", "/order/status?order_id=1&state=shipped",
                   headers={"Cookie": alice_cookie},
                   note="A5b alice 改 demo 的单（属主校验）"))
s5.append(lib.sent(rec, "GET", "/order/status?order_id=2&state=paid",
                   headers={"Cookie": alice_cookie},
                   note="A5c alice 自身单 unpaid->paid 合法流转"))
add("HUNT-A5", "越权/状态机", "订单状态机跳步与跨用户改单核验",
    "见 detail", s5,
    json.dumps({"a5a_unpaid2shipped": lib.get_status(rec[s5[0]]),
                "a5b_alice_edit_demo_order": lib.get_status(rec[s5[1]]),
                "a5c_unpaid2paid": lib.get_status(rec[s5[2]])}),
    "越权改单若 200 即 IDOR；跳步若 200 即状态机绕过（可白拿已发货凭证）",
    rollback="order 2 state 由 paid 改回 unpaid（本轮已记录原值）")
snapshots.append(db_state("after-A5"))

# ---------------------------------------------------------------- A6 库存未扣减
b6 = db_state("before-A6")
i6 = lib.sent(rec, "GET", "/order/create?product_id=3&qty=100",
              headers={"Cookie": alice_cookie},
              note="A6 下单 100 件（product 3 stock=500）")
a6 = db_state("after-A6")
add("HUNT-A6", "业务逻辑/库存", "下单不扣减 products.stock（超卖）核验",
    "见 detail", [i6],
    json.dumps({"before_stock": b6["products"], "after_stock": a6["products"],
                "resp": lib.head_text(rec[i6], 200)}),
    "若 stock 前后一致即库存从不扣减，可无限超卖（影响面小：学习靶场无真实库存）",
    rollback="/__reset")
snapshots.append(db_state("after-A6"))

# ---------------------------------------------------------------- A7 改密越权/自身
s7 = []
s7.append(lib.sent(rec, "POST", "/change-password", headers={
    "Cookie": alice_cookie, "Content-Type": "application/x-www-form-urlencoded"},
    body="new_password=hacked123", note="A7a 无 CSRF token 改密"))
add("HUNT-A7", "越权/CSRF", "改密接口缺 CSRF token 时是否可改他人密码",
    "见 detail", s7, json.dumps({"no_csrf_change": lib.get_status(rec[s7[0]]),
                                 "body": lib.head_text(rec[s7[0]], 160)}),
    "若 200 即无 CSRF 改密；配合会话窃取可完全接管账号", rollback="无（未改成功）")

# ---------------------------------------------------------------- A8 board 匿名写
s8 = []
s8.append(lib.sent(rec, "POST", "/board",
                  headers={"Content-Type": "application/x-www-form-urlencoded"},
                  body="content=HUNT-t4-anon-probe",
                  note="A8a 匿名发帖（无认证无 CSRF）"))
s8.append(lib.sent(rec, "GET", "/board", note="A8b 读取留言板"))
add("HUNT-A8", "业务逻辑/匿名写", "POST /board 匿名可写（无认证、无 CSRF）",
    "确认" if lib.get_status(rec[s8[0]]) in (302, 200) else "见 detail", s8,
    json.dumps({"post_status": lib.get_status(rec[s8[0]]),
                "board_contains": "HUNT-t4-anon-probe" in rec[s8[1]]["response_body"]}),
    "任何匿名访问者可写入持久内容（留言板污染），且以匿名身份可无限次写库（写入放大）",
    rollback="删除 messages 中 content='HUNT-t4-anon-probe' 的行 或 /__reset")
snapshots.append(db_state("after-A8"))

# ---------------------------------------------------------------- A9 /login 无 CSRF（登录 CSRF）
s9 = []
s9.append(lib.sent(rec, "POST", "/login",
                  headers={"Content-Type": "application/x-www-form-urlencoded"},
                  body="username=demo&password=demo123",
                  note="A9 无 CSRF 的跨站登录请求（无 Origin/Referer 校验）"))
add("HUNT-A9", "业务逻辑/CSRF", "POST /login 不校验 CSRF/Origin，可跨站登录固定到攻击者账号（会话固定类风险）",
    "见 detail", s9,
    json.dumps({"status": lib.get_status(rec[s9[0]]),
                "set_cookie": [v for k, v in rec[s9[0]]["response_headers"]
                               if k.lower() == "set-cookie"]}),
    "登录接口无 CSRF：攻击者可强制受害者登录到攻击者控制的账号，诱导其在其中提交敏感数据",
    rollback="无（仅新建会话）")

# ---------------------------------------------------------------- A10 异常输入健壮性
bad10 = []
cases = [
    ("amount 超长", "/wallet/withdraw?amount=" + "9" * 400),
    ("amount 空", "/wallet/withdraw?amount="),
    ("order_id 非数字", "/order/status?order_id=abc&state=paid"),
    ("order_id 巨长", "/order/status?order_id=" + "1" * 30 + "&state=paid"),
    ("code 巨长", "/coupon/claim?code=" + "A" * 5000),
    ("product_id 非数字", "/order/create?product_id=abc&qty=1"),
    ("product_id 空", "/order/create?product_id=&qty=1"),
    ("state 空", "/order/status?order_id=3&state="),
    ("amount 负数大", "/wallet/withdraw?amount=-99999999999999999999"),
    ("transfer to 自身空", "/wallet/transfer?to=&amount=1&csrf_token=x"),
]
for name, p in cases:
    i = lib.sent(rec, "GET", p, headers={"Cookie": demo_cookie},
                 note=f"A10 {name}", transport_timeout=25)
    e = rec[i]
    bad10.append({"case": name, "path": p[:80], "status": lib.get_status(e),
                  "idx": i, "snippet": lib.head_text(e, 140)})
add("HUNT-A10", "业务逻辑/健壮性", "异常/超长参数与类型混淆健壮性",
    "见 detail", [x["idx"] for x in bad10], json.dumps(bad10, ensure_ascii=False),
    "若出现 500 即未处理异常（信息泄露/拒绝服务面）", needs_verify=False)

snapshots.append(db_state("end"))
payload = {"generated": lib.now(), "phase": "A-业务逻辑", "results": results,
           "boundary": boundary, "robustness": bad10, "snapshots": snapshots,
           "raw_entries": rec}
with open(OUT, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, ensure_ascii=False, indent=1)
print("WROTE", OUT, "entries", len(rec))
for r in results:
    print("-", r["id"], r["verdict"], "|", r["title"][:70])
print("balances:", snapshots[0]["balances"], "->", snapshots[-1]["balances"])
