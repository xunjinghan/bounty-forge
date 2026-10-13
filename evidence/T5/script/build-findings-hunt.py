"""t4 汇总：把 A-F 各阶段结果合并为最终疑似漏洞清单。

输出：security/learning/_evidence/findings-hunt-<ts>.json
每条含：编号 / 类别 / 位置 / 参数 / payload / 请求响应证据（指向原始包文件与下标）/
自评危害 / 是否需要验证员复核 / 复现命令 / 回滚方式。
"""
import json
import os
import glob
import importlib.util as ilu
from datetime import datetime, timezone, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
TZ = timezone(timedelta(hours=8))
TS = datetime.now(TZ).strftime("%Y%m%d-%H%M%S")
OUT = os.path.join(HERE, f"findings-hunt-{TS}.json")
INDEX = os.path.join(HERE, f"findings-hunt-{TS}-index.md")

SRC = {
    "A": "hunt-a-bizlogic-20261012-1830.json",
    "A3b": "hunt-a3b-race-order-20261012-1835.json",
    "B": "hunt-b-idor-20261012-1840.json",
    "C": "hunt-c-upload-xss-rce-20261012-1845.json",
    "D": "hunt-d-ssrf-8091-20261012-1850.json",
    "E": "hunt-e-wrapup-20261012-1855.json",
    "F": "hunt-f-extra-20261012-1900.json",
    "F7": "hunt-f7-logout-20261012-1905.json",
}

findings = []


def F(fid, cat, port, sev, title, location, params, payload, evidence, impact,
      needs_verify=True, repro="", rollback="", verdict="确认", status="确认"):
    findings.append({
        "id": fid, "category": cat, "port": port, "severity_self": sev,
        "title": title, "location": location, "params": params, "payload": payload,
        "evidence": evidence, "self_assessed_impact": impact,
        "needs_verifier": needs_verify, "repro": repro, "rollback": rollback,
        "verdict": verdict, "status": status,
        "verified_by_hunter": status == "确认",
    })


# ---------------- 高危 ----------------
F("HUNT-01", "业务逻辑/竞态", 8095, "high",
  "并发下单可把余额扣成负数（先读余额校验、后无条件扣款，非同一原子操作）",
  "GET /order/create（任何方法）", "product_id, qty",
  "30 并发 GET /order/create?product_id=3&qty=1，单价 1900 分，余额 50000 分",
  {"file": "hunt-a3b-race-order-20261012-1835.json",
   "detail": "balance_before=50000, balance_after=-3200, orders 3→31/33, 200×30，"
             "30 次下单全部成功（应收敛为 ≤26 次）",
   "raw_entry": "A3b race #0（含原始请求/响应包）"},
  "以 1900 分/件的成本把 50000 分余额打到 -3200 分：绕过余额校验完成超额下单，"
  "订单随之进入 unpaid/paid 流程；资金逻辑可被并发放大（真实电商等价于超卖+透支）",
  repro="1) curl http://127.0.0.1:8095/__reset 复原；2) 登录取 demo Cookie；"
        "3) 30 路并发 curl 'http://127.0.0.1:8095/order/create?product_id=3&qty=1' "
        "-H 'Cookie: token=<demo>'；4) 查询 lab.db users.balance_cents = -3200",
  rollback="/__reset（本轮已执行，DB 已回种子态，sha256=49b2…6cc7af）")

F("HUNT-02", "业务逻辑/CSRF", 8095, "high",
  "状态变更接口无 HTTP 方法限制且无 CSRF token：GET 即真实扣款/建单/改单/领券",
  "GET /wallet/withdraw?amount=N、GET /order/create、GET /order/status、GET /coupon/claim",
  "amount / product_id+qty / order_id+state / code",
  "GET /wallet/withdraw?amount=1（仅带 Cookie，无任何 CSRF token）→ 200 提现成功",
  {"file": "hunt-a-bizlogic-20261012-1830.json",
   "index": ["A1a（GET 提现 200）", "A1b（GET 下单 200）", "A1c（POST+query 覆盖 200）"]},
  "攻击者页面 <img src='http://127.0.0.1:8095/wallet/withdraw?amount=5000'> 即可用受害者"
  "已登录会话扣款/下单/改单；SameSite=Lax 不拦截顶级 GET 导航，CSRF 完全成立",
  repro="curl -H 'Cookie: token=<demo>' 'http://127.0.0.1:8095/wallet/withdraw?amount=1' → 200 提现成功",
  rollback="/__reset")

F("HUNT-03", "敏感信息泄露/密钥推导", 8095, "high",
  "/debug 泄露 SECRET_KEY，导致 CSRF token 可离线伪造并完成转账（实测链条成立）",
  "GET /debug（admin 会话）→ HMAC-SHA256(SECRET_KEY, session_token) → GET /wallet/transfer",
  "SECRET_KEY / csrf_token", "SECRET_KEY=lab-secret-key-PLEASE-CHANGE-001",
  {"file": "hunt-e-wrapup-20261012-1855.json",
   "detail": "页面 csrf_token=a537…ef41 与自算 HMAC(SECRET_KEY, cookie token)=a537…ef41 "
             "逐字符一致；用该自算 token GET /wallet/transfer?to=alice&amount=1 → 200 转账成功",
   "index": ["E2 /debug 200 含 SECRET_KEY/DB_PATH/cwd", "E5 match=true + 两次转账 200"]},
  "拿到 SECRET_KEY（或读到 /debug）即可为任意已知会话 token 离线生成有效 CSRF token，"
  "把唯一强制 CSRF 的转账/改密入口变成可跨站构造的请求；配合会话泄露=资金转移",
  repro="1) admin 登录；2) curl -b cookie http://127.0.0.1:8095/debug 取 SECRET_KEY；"
        "3) python -c \"import hmac,hashlib;print(hmac.new(b'lab-secret-key-PLEASE-CHANGE-001',"
        "b'<session_token>',hashlib.sha256).hexdigest())\"；4) 用该值打 /wallet/transfer → 200",
  rollback="/__reset")

F("HUNT-04", "认证/会话管理", 8095, "high",
  "GET /logout 不销毁服务端会话：旧 Cookie 在登出后仍可完整访问账户",
  "GET /logout", "Cookie token", "登出后原样重放旧 Cookie",
  {"file": "hunt-f7-logout-20261012-1905.json",
   "detail": "登出前 sessions=1 且 token 命中；GET /logout → 302 仅 Set-Cookie token=; Max-Age=0；"
             "登出后 sessions 仍=1、token 仍在库；带旧 Cookie GET /home → 200『钱包』页",
   "raw_entry": "F7 raw_entries"},
  "『登出』只是让浏览器丢弃 Cookie，服务端会话仍有效：共享设备/被窃 Cookie 在用户登出后"
  "依然可用，会话失效语义失效（真实场景等同无法登出）",
  repro="curl -c j -d 'username=demo&password=demo123' http://127.0.0.1:8095/login；"
        "curl -b j http://127.0.0.1:8095/logout；curl -b j http://127.0.0.1:8095/home → 200",
  rollback="无副作用（仅新增/保留会话）")

# ---------------- 中危 ----------------
F("HUNT-05", "Host 头注入/弱 token", 8095, "medium",
  "/forgot 回显 Host / X-Forwarded-Host，且 token=md5(username) 可预测（含不存在用户）",
  "GET /forgot?username=*", "username, X-Forwarded-Host, Host",
  "X-Forwarded-Host: evil.example → http://evil.example/reset?user=demo&token=fe01ce2a7fbac8fafaed7c982a04e229",
  {"file": "hunt-d-ssrf-8091-20261012-1850.json", "index": ["D3 全部 13 组"]},
  "重置链接指向攻击者域名（钓鱼/邮箱链接劫持）；token 无需数据库即可预测（md5(用户名)），"
  "若存在 /reset 消费端即为任意用户改密链；当前 /reset 实测 404，链条未闭合",
  needs_verify=True,
  repro="curl -H 'X-Forwarded-Host: evil.example' 'http://127.0.0.1:8095/forgot?username=demo'",
  rollback="无（只读）", verdict="确认（Host 注入与 token 可预测）；改密链未闭合（/reset 404）",
  status="确认/待验证")

F("HUNT-06", "危险功能/认证缺失", 8095, "medium",
  "GET /__reset 无认证无 CSRF：任意可达进程/页面可一键删库重建",
  "GET /__reset", "-", "GET /__reset",
  {"file": "hunt-e-wrapup-20261012-1855.json", "index": ["E6 status=200 已重置"]},
  "仅校验 TCP 对端为回环；任何能访问 127.0.0.1:8095 的页面（CSRF 场景）或本地进程均可在"
  "无凭证下清空数据库与 uploads/（数据完整性完全丧失）",
  repro="curl http://127.0.0.1:8095/__reset → 200『已重置』",
  rollback="不可回滚（数据即被删除）——本轮 18:25/18:26/18:55 共触发 3 次用于复原脏数据，DB 已回种子态",
  verdict="确认", status="确认")

F("HUNT-07", "业务逻辑/匿名写", 8095, "medium",
  "POST /board 匿名可写（无认证、无 CSRF、无长度限制、无频控）",
  "POST /board", "content", "content=HUNT-t4-anon-probe",
  {"file": "hunt-a-bizlogic-20261012-1830.json", "index": ["A8a 匿名发帖 302", "A8b 板面含该条"]},
  "任何匿名访问者可持久污染留言板并无限写入（存储放大/内容注入），"
  "输出侧已 html.escape，未构成存储型 XSS（C5 实测 escaped=true）",
  repro="curl -d 'content=x' http://127.0.0.1:8095/board → 302；GET /board 可见",
  rollback="/__reset 或 SELECT 删除该行")

F("HUNT-08", "文件上传/异常处理", 8095, "medium",
  "匿名上传：非法文件名（超长/NUL/Windows 非法字符）触发未处理异常 500，无长度下限/字符集校验",
  "POST /upload", "filename, file",
  "filename='a'×296+'.txt' / 'shell.jsp\\x00.png' / '<img src=x onerror=alert(1)>.txt'",
  {"file": "hunt-c-upload-xss-rce-20261012-1845.json", "index": ["C1 三例 500", "lab_errors.log 三条堆栈"]},
  "匿名者可稳定触发 OSError(Errno 22)/ValueError(embedded null character) → 500 错误页"
  "（可用性/异常面、日志膨胀）；文件名未白名单化，属上传校验缺口",
  repro="curl -F 'file=@ok.txt;filename=aaaa…（296 个 a）.txt' http://127.0.0.1:8095/upload → 500；"
        "C:\\…\\target-site-lab\\lab_errors.log 出现 open(dest) OSError",
  rollback="无文件落盘（open 失败），无副作用")

F("HUNT-09", "业务逻辑/参数污染", 8095, "low",
  "表单解析：query 参数覆盖 POST body（form() 中 data.update(q)），方法语义与参数来源不严格",
  "所有 /order/*、/wallet/*、/coupon/* 入口", "amount / qty / state / code",
  "POST /wallet/withdraw?amount=1 with body amount=999999 → 实际按 1 分执行",
  {"file": "hunt-f-extra-20261012-1900.json", "index": ["F2 两例", "F4 方法矩阵"]},
  "GET 与 POST 同权、query 优先于 body：易被 WAF/自研校验只盯 body 的实现漏判，"
  "并为 GET 型 CSRF 提供通道（与 HUNT-02 叠加）",
  repro="curl -b cookie -d 'amount=999999' 'http://127.0.0.1:8095/wallet/withdraw?amount=1' → 按 1 分扣款",
  rollback="/__reset")

F("HUNT-10", "功能缺陷/异常", 8095, "low",
  "登录态访问 GET / 稳定 500（app.py:512 sqlite3.Row.get），未登录同请求 200",
  "GET /", "Cookie token", "-",
  {"file": "hunt-e-wrapup-20261012-1855.json",
   "index": ["E1：登录态 4/4 = 500", "未登录 3/3 = 200"]},
  "登录后首页 100% 崩溃（可用性缺陷 + 已认证用户可见错误页）；同时暴露未处理异常路径",
  repro="curl -b cookie http://127.0.0.1:8095/ → 500；curl http://127.0.0.1:8095/ → 200",
  rollback="无")

F("HUNT-11", "业务逻辑/整数边界", 8095, "low",
  "提现金额无上限：int 超 2^63-1 触发 SQLite 绑定 OverflowError → 500",
  "GET /wallet/withdraw", "amount", "amount=9223372036854775808",
  {"file": "hunt-f-extra-20261012-1900.json", "index": ["F3：2^63、1e23 → 500；2^63-1 → 提现失败 200"]},
  "金额缺乏最大值校验，超大整数进入未处理异常分支（500）——异常面/健壮性缺陷，"
  "不产生资金影响（SQLite 条件扣款阻止负余额）",
  repro="curl -b cookie 'http://127.0.0.1:8095/wallet/withdraw?amount=9223372036854775808' → 500",
  rollback="无")

F("HUNT-12", "信息泄露", 8095, "low",
  "/api/search 响应体回显 SQL 模板字符串（实现细节泄露），LIKE 通配符未转义",
  "GET /api/search?q=", "q", "q=% → 全量商品；q='" ,
  {"file": "hunt-f-extra-20261012-1900.json", "index": ["F5：% 与 _ 返回 167 字节全量结果"]},
  "泄露内部 SQL 语句与表结构线索；通配符可枚举全表（商品表仅 3 行，影响有限）。"
  "注入本身已被参数化封堵（sqlmap 阴性）",
  repro="curl 'http://127.0.0.1:8095/api/search?q=%25'",
  rollback="无")

F("HUNT-13", "CSRF/会话可用性", 8095, "low",
  "GET /logout 无 CSRF：任意页面可强制受害者登出（会话拒绝服务）",
  "GET /logout", "-", "<img src=/logout>",
  {"file": "hunt-f-extra-20261012-1900.json", "index": ["F1：302 → /"]},
  "骚扰型 CSRF，危害低；与 HUNT-04（会话不销毁）叠加后意义进一步降低",
  repro="curl -b cookie http://127.0.0.1:8095/logout → 302",
  rollback="无")

F("HUNT-14", "越权/参数校验", 8095, "info",
  "/api/order?id= 未做类型规范化：'+1'/'01'/'1e0'/'1.0' 均被判为 1",
  "GET /api/order, GET /api/profile", "id", "id=+1",
  {"file": "hunt-b-idor-20261012-1840.json", "index": ["B3（+1/01/1e0/1.0 → 200 命中 id=1）"]},
  "SQLite 隐式类型转换使多种写法的 id 等价；因属主校验仍在，未产生越权（阴性信息项）",
  needs_verify=False, verdict="确认（行为）；无越权影响", status="确认（无越权）")

F("HUNT-15", "垂直越权面", 8095, "info",
  "/debug 对已登录非 admin 返回 403 而非 404：存在性与权限边界被区分",
  "GET /debug", "-", "-",
  {"file": "hunt-b-idor-20261012-1840.json", "index": ["B5：demo/alice/bob → 403；/admin/* → 404"]},
  "普通用户可探测 /debug 存在（信息面）；本身需 admin 才能读 SECRET_KEY",
  needs_verify=False, verdict="确认（信息项）", status="确认")

# ---------------- 阴性/已封堵（供验证员核对，不计入漏洞） ----------------
negatives = [
    {"id": "N-01", "area": "SQL 注入", "target": "8095/8091",
     "evidence": "sqlmap -u …/search?q=k -p q；/api/search?q；/login(username)；/board(content)；"
                 "8091 /register(username)、/login(password) 均 level=2 risk=1 全阴性；"
                 "日志 security/learning/_evidence/sqlmap-run-8095-8091.log",
     "detail": "所有参数走 sqlite3 占位符参数化；8095 /api/search 直接回显 SQL 模板但无拼接"},
    {"id": "N-02", "area": "IDOR/越权", "target": "8095/8091",
     "evidence": "hunt-b-idor-20261012-1840.json（103 条原始包）",
     "detail": "8095 /api/order、/api/profile 跨用户统一 404；/order/status 跨用户 404；"
               "/admin/* 普通用户 404；8091 /api/profile、/api/orders 越权 404、未登录 401"},
    {"id": "N-03", "area": "命令注入", "target": "8095 /ping",
     "evidence": "hunt-c-upload-xss-rce-20261012-1845.json C6（13 组）",
     "detail": "正则 ^[a-zA-Z0-9.\\-]{1,253}$ + subprocess 参数数组 + shell=False；"
               "分隔符/换行/NUL/超长全部 400；仅 -n 被当作主机名传给 ping 工具（无命令执行）"},
    {"id": "N-04", "area": "SSTI", "target": "8095 /greet、/search、/api/search",
     "evidence": "C4 中 9 组模板探针",
     "detail": "{{7*7}}/${7*7}/#{7*7} 均原样回显，无 49；eval 已移除"},
    {"id": "N-05", "area": "XSS", "target": "8095/8091",
     "evidence": "C4（27 组）、C5（存储型）、D4（8091 12 组）",
     "detail": "输出侧 html.escape（8095）与 esc()（8091）生效：无原始 <script> 反射；"
               "留言板与上传结果页均转义"},
    {"id": "N-06", "area": "路径穿越/任意文件读", "target": "8095 /download",
     "evidence": "F6（10 组编码变体）",
     "detail": "../、..%2f、%2e%2e、....//、绝对路径、%00 截断全部 403/404；realpath 前缀校验生效"},
    {"id": "N-07", "area": "文件上传绕过后利用", "target": "8095 /upload",
     "evidence": "C1（21 组）+ C2 落地审计 + C3 响应头",
     "detail": "白名单外后缀（.php/.svg/.jpeg/.htaccess/无后缀）全部 400 拒绝；"
               "落盘文件仅 .jpg/.png/.txt；/uploads/* 以 octet-stream + attachment + nosniff 返回，"
               "浏览器不执行；未发现目录外落地（../、绝对路径均被 basename 规整）"},
    {"id": "N-08", "area": "SSRF 越界", "target": "8095 /fetch",
     "evidence": "D1（33 组）",
     "detail": "localhost/0.0.0.0/2130706433/0x7f000001/017700000001/127.1/[::1]/userinfo@ "
               "全部 403；非白名单端口 22/6379/3306/9999 403；file/gopher/dict 403；"
               "https 亦 403。仅 127.0.0.1 字面 + 白名单端口可达（含 8091，属设计内）"},
    {"id": "N-09", "area": "用户名枚举", "target": "8091 /login",
     "evidence": "D5",
     "detail": "存在用户与不存在用户失败响应一致（303 /login?m=bad）；dummy_verify 抹平计时"},
    {"id": "N-10", "area": "注册/改密 CSRF", "target": "8091",
     "evidence": "D7 + hunt-b-idor F 系列",
     "detail": "8091 /change-password 伪造/缺失 CSRF → 403；注册与登录同样强制 CSRF 与 Origin 校验"},
    {"id": "N-11", "area": "弱口令/口令存储", "target": "8095/8091",
     "evidence": "hunt-e-wrapup E2/E3 + 基线",
     "detail": "8095 admin 为 22 位强口令、明文入库（源码注明为教学面）；8091 PBKDF2-HMAC-SHA256"
               "(200000)+独立盐；/admin/users 不显示口令字段"},
    {"id": "N-12", "area": "模板级扫描", "target": "8095/8091",
     "evidence": "recon-nuclei-20261012-181707.jsonl、hunt-nuclei-20261012-1858.jsonl",
     "detail": "nuclei v3.11.1 以 medium,high,critical 跑 32130 模板/32044 请求，"
               "matched=0（errors 8895 为对 404/501 的模板噪声）"},
]

payload = {
    "generated": datetime.now(TZ).isoformat(timespec="seconds"),
    "task": "t4-hunt",
    "phase": "阶段3 漏洞挖掘",
    "scope": ["http://127.0.0.1:8095", "http://127.0.0.1:8091"],
    "method": "自研 Python 取证脚本（保留原始请求/响应包）+ sqlmap + nuclei + 源码审计",
    "priority_order_executed": ["业务逻辑", "SQL注入", "越权(IDOR)", "文件上传",
                                "XSS", "命令执行", "SSRF", "SSTI"],
    "finding_count": len(findings),
    "confirmed_count": sum(1 for f in findings if f["verified_by_hunter"]),
    "needs_verifier_count": sum(1 for f in findings if f["needs_verifier"]),
    "category_distribution": {},
    "severity_distribution": {},
    "findings": findings,
    "negatives": negatives,
    "evidence_files": [
        {"file": k, "path": os.path.join("security/learning/_evidence", v)}
        for k, v in SRC.items()
    ],
    "tool_logs": ["sqlmap-run-8095-8091.log", "hunt-nuclei-20261012-1858.jsonl",
                  "recon-nuclei-20261012-181707.jsonl"],
    "lab_side_effects": [
        "18:25:38 /__reset：复原 A 阶段写操作（demo 余额被扣至 -6802）",
        "18:25:52 /__reset：复原 A3b 竞态测试前状态",
        "18:25:53 后 A3b 竞态造成 lab.db demo 余额 -3200、orders 33 行",
        "18:55 E6 触发 /__reset 后 DB 回种子态",
        "19:07:23 收尾 /__reset：lab.db 恢复为 t1 基线完全一致状态——"
        "sha256=49b2032c29f8057530704203fd361bb162461eaeeeeb874c7ac1b8e8956cc7af、49152 字节、"
        "integrity_check=ok；users(admin100000/demo50000/alice88800/bob100)、orders 3、"
        "messages 1、sessions 0、coupon_claims 0、uploads/ 0 文件",
        "8091 无复位接口：sessions 由 42 增至约 50、login_attempts 新增探测/失败键"
        "（locked_until 均 0，无锁定态），属非破坏性累积",
    ],
    "residual_risks": [
        "HUNT-05 的 /reset 消费端缺失，改密链未闭合 → 需验证员确认是否存在隐藏消费路由",
        "HUNT-03 的会话 token 不可预测性（secrets.token_urlsafe(32)）未做熵评估",
        "HUNT-01 竞态在 Windows + SQLite 下重现；不同并发度/时序的稳定边界未穷举",
    ],
}

cat = {}
sev = {}
for f in findings:
    cat[f["category"]] = cat.get(f["category"], 0) + 1
    sev[f["severity_self"]] = sev.get(f["severity_self"], 0) + 1
payload["category_distribution"] = cat
payload["severity_distribution"] = sev

with open(OUT, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, ensure_ascii=False, indent=1)

# 索引 md
lines = [f"# 阶段3 漏洞挖掘清单（{payload['generated']}）", "",
         f"- 疑似/确认条目：**{len(findings)}**（确认 {payload['confirmed_count']}，"
         f"需验证 {payload['needs_verifier_count']}）",
         f"- 类别分布：{json.dumps(cat, ensure_ascii=False)}",
         f"- 严重度（自评）：{json.dumps(sev, ensure_ascii=False)}",
         f"- 阴性/已封堵核验项：{len(negatives)}",
         "- 范围：仅 127.0.0.1:8091 / 127.0.0.1:8095", "",
         "| 编号 | 类别 | 端口 | 自评 | 是否需要验证 | 标题 |", "|---|---|---|---|---|---|"]
for f in findings:
    lines.append(f"| {f['id']} | {f['category']} | {f['port']} | {f['severity_self']} | "
                 f"{'是' if f['needs_verifier'] else '否'} | {f['title']} |")
lines += ["", "## 原始证据文件", ""]
for k, v in SRC.items():
    lines.append(f"- `{k}` → `security/learning/_evidence/{v}`")
lines += ["", "## 阴性核验", ""]
for n in negatives:
    lines.append(f"- **{n['id']} {n['area']}**（{n['target']}）：{n['detail']}")
with open(INDEX, "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines))

print("WROTE", OUT)
print("WROTE", INDEX)
print(json.dumps({"findings": len(findings), "cat": cat, "sev": sev,
                  "negatives": len(negatives)}, ensure_ascii=False, indent=1))
