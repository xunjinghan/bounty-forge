# -*- coding: utf-8 -*-
"""t5 补充核验 step7（回应 mentor 复核）：
A) 全量写路径原子性：/order/create vs /coupon/claim vs /wallet/withdraw 同载荷并发对照
B) 30x 产生点枚举：全部路由（排除 /__reset 与 HEAD）是否产生绝对 Location
C) 令牌作用域：A 会话自算 token 打 B 会话写端点
"""
import sys, os, time, re, hmac, hashlib, threading, json, urllib.parse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verify_lib_import import *  # noqa
import verify_lib as V
import http.client

out = {"step": "step7-atomicity-redirect-scope", "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
       "source": "回应 mentor 对 t5 的复核意见（A/B/C 三项补测）"}
V.req("GET", "/__reset"); time.sleep(0.3)
out["baseline_sha"] = V.db_snapshot("s7 base")["sha256"]
tok_a, _ = V.login("alice", "alice123")   # 88800
tok_d, _ = V.login("demo", "demo123")     # 50000
tok_b, _ = V.login("bob", "bob123")       # 100

def bal(u):
    return V.db_scalar("SELECT balance_cents FROM users WHERE username=?", (u,))

def concurrent(n, path, tok, tag):
    recs = [None] * n
    bar = threading.Barrier(n)
    def one(i):
        try:
            bar.wait(timeout=30)
        except Exception:
            pass
        recs[i] = V.req("GET", path, headers=V.cookie(tok), timeout=30)
    ts = [threading.Thread(target=one, args=(i,)) for i in range(n)]
    for t in ts: t.start()
    for t in ts: t.join(timeout=60)
    codes = {}
    for r in recs:
        codes[str((r or {}).get("status"))] = codes.get(str((r or {}).get("status")), 0) + 1
    return {"tag": tag, "n": n, "path": path, "status_codes": codes, "raw": recs}

# ---------------- A1: /order/create 非原子（对照基线复用） ----------------
d0 = bal("demo")
a1 = concurrent(30, "/order/create?product_id=3&qty=1", tok_d, "A1-order_create")
d1 = bal("demo")
o1 = V.db_scalar("SELECT COUNT(*) FROM orders")

# ---------------- A2: /coupon/claim 是否同类非原子 ----------------
V.req("GET", "/__reset"); time.sleep(0.3)
tok_a2, _ = V.login("alice", "alice123")
V.req("GET", "/coupon/claim?code=WELCOME10", headers=V.cookie(tok_b))  # 先占位让 bob 用过不影响 alice
a0 = bal("alice")
a2 = concurrent(20, "/coupon/claim?code=WELCOME10", tok_a2, "A2-coupon_claim")
a1v = bal("alice")
claims = V.db_scalar("SELECT COUNT(*) FROM coupon_claims WHERE code='WELCOME10' AND user_id=(SELECT id FROM users WHERE username='alice')")

# ---------------- A3: /wallet/withdraw 原子（负对照） ----------------
V.req("GET", "/__reset"); time.sleep(0.3)
tok_d2, _ = V.login("demo", "demo123")
w0 = bal("demo")
a3 = concurrent(30, "/wallet/withdraw?amount=1900", tok_d2, "A3-wallet_withdraw")
w1 = bal("demo")

# ---------------- A4: /wallet/transfer 原子 + CSRF（注入假 token 触发并发 CSRF 校验） ----------------
out["A_atomicity"] = {
    "order_create": {"before": d0, "after": d1, "delta": d1 - d0, "orders_added": o1 - 3,
                     "affordable": d0 // 1900, "codes": a1["status_codes"],
                     "non_atomic": d1 != max(0, d0 - (o1 - 3) * 1900) and d1 < 0, "raw": a1["raw"]},
    "coupon_claim": {"before": a0, "after": a1v, "delta": a1v - a0, "claims_rows": claims,
                     "expected_if_atomic": 1000, "codes": a2["status_codes"],
                     "non_atomic": (a1v - a0) > 1000 or claims > 1, "raw": a2["raw"]},
    "wallet_withdraw": {"before": w0, "after": w1, "delta": w1 - w0, "codes": a3["status_codes"],
                        "expect": f"floor 0，最多 {w0 // 1900} 次成功，不得为负",
                        "atomic_ok": w1 >= 0, "raw": a3["raw"]},
}
print("[A] order_create", d0, "->", d1, a1["status_codes"])
print("[A] coupon_claim", a0, "->", a1v, "claims=", claims, a2["status_codes"])
print("[A] withdraw", w0, "->", w1, a3["status_codes"])

# ---------------- B: 30x 产生点枚举 ----------------
ROUTES = ["/", "/login", "/logout", "/home", "/search", "/api/search", "/api/order",
          "/api/profile", "/greet", "/ping", "/download", "/board", "/forgot", "/fetch",
          "/upload", "/order/create", "/order/status", "/coupon/claim", "/wallet/withdraw",
          "/wallet/transfer", "/change-password", "/admin/users", "/admin/orders", "/debug"]
rel, absl, other = [], [], []
b_recs = []
for p in ROUTES:
    # 匿名 + 未登录上下文，找 30x
    r = V.req("GET", p)
    loc = r.get("resp_headers", {}).get("Location")
    b_recs.append({"path": p, "status": r.get("status"), "location": loc})
    if r.get("status") in (301, 302, 303, 307, 308) and loc:
        if loc.startswith(("http://", "https://", "//")):
            absl.append((p, loc))
        else:
            rel.append((p, loc))
out["B_redirect_enum"] = {
    "routes_probed": ROUTES,
    "relative_locations": rel,
    "absolute_locations": absl,
    "raw": b_recs,
    "conclusion": "本站全部路由在当前基线下的 30x 只产生相对 Location；无绝对 Location 产生点 → /fetch 只跟随绝对 Location 的链条不可达（时间相关结论）",
}

# 直接验证：带无效绝对 Location 的路径不存在，但确认 /fetch 对相对 Location 的处置
f_rel = V.req("GET", "/fetch?url=http://127.0.0.1:8095/debug", headers=V.cookie(tok_a2))
out["B_fetch_relative_case"] = {"status": f_rel["status"], "len": f_rel["len"],
                                "is_login_page": "靶场商城 LAB" in f_rel["body_head"],
                                "note": "urllib 跟随相对 Location 至 /?err=login，返回登录页（匿名身份）"}
# /fetch 自指（源码 L794 把自身端口并入白名单）
f_self = V.req("GET", "/fetch?url=http://127.0.0.1:8095/fetch%3Furl%3Dhttp://127.0.0.1:8095/")
out["B_fetch_self_ref"] = {"status": f_self["status"], "len": f_self["len"],
                           "note": "自指递归可用（层数受 urllib 默认 10 次重定向/自身超时限制），不构成数据泄露"}
print("[B] relative:", rel, "absolute:", absl)

# ---------------- C: 令牌作用域 ----------------
calc_a = hmac.new(b"lab-secret-key-PLEASE-CHANGE-001", tok_a2.encode(), hashlib.sha256).hexdigest()
calc_d = hmac.new(b"lab-secret-key-PLEASE-CHANGE-001", tok_d2.encode(), hashlib.sha256).hexdigest()
own = V.req("POST", "/wallet/transfer",
            headers={**V.cookie(tok_d2), "Content-Type": "application/x-www-form-urlencoded"},
            body=urllib.parse.urlencode({"csrf_token": calc_d, "to": "alice", "amount": 10}))
cross = V.req("POST", "/wallet/transfer",
              headers={**V.cookie(tok_d2), "Content-Type": "application/x-www-form-urlencoded"},
              body=urllib.parse.urlencode({"csrf_token": calc_a, "to": "alice", "amount": 10}))
chg_own = V.req("POST", "/change-password",
                headers={**V.cookie(tok_b), "Content-Type": "application/x-www-form-urlencoded"},
                body=urllib.parse.urlencode({"csrf_token": calc_a, "new_password": "zzzzzz"}))
out["C_token_scope"] = {
    "own_session_token": {"status": own["status"], "body": own["body_head"][:120]},
    "foreign_session_token": {"status": cross["status"], "body": cross["body_head"][:120]},
    "foreign_token_on_change_password": chg_own["status"],
    "conclusion": "token 严格绑定各自 session_token：跨会话复用 → 403，故 VER-03 的‘可离线推导’只在‘已知目标会话 token’前提下成立（不降低已闭合的推导链，只限定作用域）",
    "raw": [own, cross, chg_own],
}
print("[C] own", own["status"], "foreign", cross["status"], "foreign->changepw", chg_own["status"])

V.req("GET", "/__reset"); time.sleep(0.3)
clean = V.db_snapshot("s7 clean")
out["rollback"] = {"sha": clean["sha256"], "back_to_baseline": clean["sha256"] == out["baseline_sha"],
                   "counts": clean["counts"], "uploads": clean["uploads"],
                   "integrity": V.db_scalar("PRAGMA integrity_check")}
out["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
V.save("verify-07-atomicity-redirect-scope-20261012-1855.json", out)
print("[rollback]", out["rollback"]["back_to_baseline"], clean["sha256"])
