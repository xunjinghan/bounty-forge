# -*- coding: utf-8 -*-
"""生成阶段2 攻击面地图（JSON + MD）。数据源=本轮实测（recon-10/11/12 探针）+ 只读源码核对。"""
import hashlib
import json
import os
import time

TS = "20261012-182250"
EVID = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence"
OUT_JSON = os.path.join(EVID, f"attack-surface-{TS}.json")
OUT_MD = os.path.join(EVID, f"attack-surface-{TS}.md")

mapdata = {
    "meta": {
        "phase": "阶段2 侦察（攻击面地图）",
        "task_id": "t3",
        "attempt_id": "f60bb3ce-2202-4d9d-8530-8c52a819273f",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "scope": ["http://127.0.0.1:8091", "http://127.0.0.1:8095"],
        "hard_constraint": "仅 127.0.0.1 本地授权靶场；本阶段未发起任何写操作（除登录/无副作用校验分支）",
        "baseline_ref": "security/learning/_evidence/baseline-20261012-181212.json",
        "tools": {
            "nmap": "dsh-tools/tools/nmap/nmap-7.92/nmap.exe (-sT -sV --version-light)",
            "httpx": "dsh-tools/tools/httpx/httpx.exe",
            "katana": "dsh-tools/tools/katana/katana.exe (-d 3 -jc)",
            "ffuf": "dsh-tools/tools/ffuf/ffuf.exe (-t 8 -rate 40)",
            "nuclei": "dsh-tools/tools/nuclei/nuclei.exe (v3.11.1, -tags tech,exposure,misconfig,headers -s info,low)",
            "python": r"C:\Users\Administrator\AppData\Local\Programs\Python\Python312\python.exe"
        },
        "limits": [
            "本阶段为只读侦察：未执行上传/发帖/转账/提现/改单/改密等写操作，相关结论标注『代码级证据，未实测』",
            "nuclei 原计划 -rl 25 限速，实测 4339 次请求 / 3 分钟（模板内部并发），偏离限速预期，后续不建议对本靶场跑全模板",
            "katana 无 cookie 爬取，登录态页面靠手工时序探针补齐",
            "ffuf 字典为上一轮 wordlist.txt（约 200 条），未做深度扩展"
        ]
    },
    "assets": [
        {
            "asset": "127.0.0.1:8091",
            "name": "target-site（最小业务站点·安全加固版 v2）",
            "http_status": 200,
            "http_len": 3234,
            "server_header": "TargetSite/1.0",
            "title": "首页",
            "tech": ["Python3 stdlib ThreadingHTTPServer", "PBKDF2-HMAC-SHA256(200000) 口令存储",
                     "Cookie session + 每会话 CSRF token"],
            "security_headers_present": ["CSP(default-src 'none')", "X-Frame-Options",
                                         "X-Content-Type-Options", "Referrer-Policy",
                                         "Permissions-Policy", "Cache-Control: no-store"],
            "security_headers_missing": ["HSTS", "COEP", "COOP", "CORP",
                                          "X-Permitted-Cross-Domain-Policies"],
            "nmap": "8091/tcp open；banner Server: TargetSite/1.0（nmap 未识别为已知服务）",
            "accounts_public": {"demo": "demo1234", "alice": "alice1234"},
            "process": "pid 11776（t1 基线，18:11 重启）"
        },
        {
            "asset": "127.0.0.1:8095",
            "name": "target-site-lab（靶场商城 LAB · 第八轮加固版）",
            "http_status": 200,
            "http_len": 2120,
            "server_header": "LabHTTP/0.2 Python/3.12.10",
            "title": "靶场",
            "tech": ["Python3 stdlib ThreadingHTTPServer", "SQLite 明文口令（admin 强口令）",
                     "Cookie token 会话 + HMAC 派生 CSRF"],
            "security_headers_present": ["CSP(default-src 'self')", "X-Frame-Options",
                                         "X-Content-Type-Options", "Referrer-Policy",
                                         "Permissions-Policy", "HSTS"],
            "security_headers_missing": ["COEP", "COOP", "CORP",
                                          "X-Permitted-Cross-Domain-Policies"],
            "nmap": "8095/tcp open；banner Server: LabHTTP/0.2 Python/3.12.10（nmap 未识别）",
            "accounts_public": {"admin": "Lab@Admin2024!Secure#9（首页明文公开）",
                                "demo": "demo123", "alice": "alice123", "bob": "bob123"},
            "process": "pid 7908（t1 基线，18:11 重启）"
        }
    ],
    "routes": [],
    "params": [
        {"asset": "8095", "loc": "所有路由", "name": "q / form 键",
         "source": "query string 与 x-www-form-urlencoded 合并进同一 dict（parsed()/form()）",
         "note": "同名参数：query 覆盖 body（data.update(q)）"},
        {"asset": "8095", "loc": "POST /login", "name": "username,password", "type": "form", "auth": "none"},
        {"asset": "8095", "loc": "POST /board", "name": "content", "type": "form", "auth": "none（匿名可发帖）"},
        {"asset": "8095", "loc": "POST /upload", "name": "file", "type": "multipart", "auth": "none"},
        {"asset": "8095", "loc": "GET /search | /api/search", "name": "q", "type": "query", "auth": "none"},
        {"asset": "8095", "loc": "GET /api/order", "name": "id", "type": "query", "auth": "user（属主）"},
        {"asset": "8095", "loc": "GET /api/profile", "name": "id", "type": "query", "auth": "user（属主）"},
        {"asset": "8095", "loc": "GET /greet", "name": "name", "type": "query", "auth": "none"},
        {"asset": "8095", "loc": "GET /ping", "name": "host", "type": "query", "auth": "none",
         "validation": "^[a-zA-Z0-9.\\-]{1,253}$"},
        {"asset": "8095", "loc": "GET /download", "name": "file", "type": "query", "auth": "none",
         "validation": "realpath 白名单 downloads/"},
        {"asset": "8095", "loc": "GET /forgot", "name": "username", "type": "query", "auth": "none"},
        {"asset": "8095", "loc": "GET /fetch", "name": "url", "type": "query", "auth": "none",
         "validation": "scheme=http 且 hostname=127.0.0.1 且 port ∈ 白名单"},
        {"asset": "8095", "loc": "GET/POST /order/create", "name": "product_id,qty", "auth": "user"},
        {"asset": "8095", "loc": "GET/POST /order/status", "name": "order_id,state", "auth": "user（属主/admin）"},
        {"asset": "8095", "loc": "GET/POST /coupon/claim", "name": "code", "auth": "user"},
        {"asset": "8095", "loc": "GET/POST /wallet/withdraw", "name": "amount", "auth": "user"},
        {"asset": "8095", "loc": "GET/POST /wallet/transfer", "name": "to,amount,csrf_token", "auth": "user + CSRF"},
        {"asset": "8095", "loc": "GET/POST /change-password", "name": "new_password,csrf_token", "auth": "user + CSRF"},
        {"asset": "8091", "loc": "POST /login", "name": "username,password,csrf_token", "auth": "none"},
        {"asset": "8091", "loc": "POST /register", "name": "username,password,password2,csrf_token", "auth": "none"},
        {"asset": "8091", "loc": "POST /change-password", "name": "old_password,new_password,csrf_token", "auth": "user"},
        {"asset": "8091", "loc": "GET /api/profile", "name": "id", "type": "query", "auth": "user（仅本人）"},
        {"asset": "8091", "loc": "GET /api/orders", "name": "id", "type": "query", "auth": "user（仅本人）"},
        {"asset": "8091", "loc": "GET /", "name": "m", "type": "query", "auth": "none", "note": "flash 消息参数"}
    ],
    "business_flow": {},
    "attack_surface_stats": {},
    "priority_hints": [],
    "disabled_or_negative": [],
    "evidence_files": [],
}

# ---------------- 8095 routes ----------------
routes_8095 = [
    ("/", "GET", [], "none", 200, 200, "标题/入口页；实测未登录 200",
     "已登录会话访问会 500：index() 对 sqlite3.Row 调用 .get('username')（app.py:513 AttributeError）"),
    ("/login", "GET", [], "none", 302, 302, "GET 一律 302 → /", "仅 POST 处理"),
    ("/login", "POST", ["username", "password"], "none", None, None,
     "成功 302 /home + Set-Cookie token=...；失败 200『登录失败』；连续 5 次失败锁 15 分钟（429）", "无 CSRF token"),
    ("/logout", "GET", [], "none", 302, 302, "GET 即登出，无 CSRF", "登出型 CSRF（低危）"),
    ("/home", "GET", [], "user", 302, 200, "未登录 302 /?err=login；demo 登录后 200（钱包页）",
     "页面含 csrf_token 隐藏字段（HMAC(SECRET_KEY, token)）"),
    ("/search", "GET", ["q"], "none", 200, 200, "参数化 LIKE，输出 html.escape", "反射点已转义"),
    ("/api/search", "GET", ["q"], "none", 200, 200, "JSON 搜索；响应回显 SQL 模板字符串（参数化，无拼接）",
     "q=% 可列出全部 3 条商品"),
    ("/api/order", "GET", ["id"], "user", 302, 200, "demo 查本人单 200；查他人单 404（属主校验）", "垂直到 admin 亦 404"),
    ("/api/profile", "GET", ["id"], "user", 302, 200, "demo 查本人 200；查他人 404", "无枚举差异"),
    ("/greet", "GET", ["name"], "none", 200, 200, "SSTI 已禁用（{{7*7}} 原样回显）", "输出 html.escape"),
    ("/ping", "GET", ["host"], "none", 200, 200, "host 白名单正则；`127.0.0.1;id` → 400 无效主机", "shell 参数数组"),
    ("/download", "GET", ["file"], "none", 200, 200, "白名单 downloads/；readme.txt 200；../app.py 与 %2e%2e 编码均 403",
     "编码绕过已被 unquote+realpath 拦截"),
    ("/board", "GET", [], "none", 200, 200, "留言列表，输出 html.escape", ""),
    ("/board", "POST", ["content"], "none", None, None, "匿名可发帖（author=anonymous）", "写操作，本阶段未执行"),
    ("/forgot", "GET", ["username"], "none", 200, 200,
     "回显重置链接；X-Forwarded-Host 被拼进链接（实测 http://evil.example/reset?...）",
     "Host 头注入 + token=md5(username) 可预测；/reset 路由本身不存在"),
    ("/fetch", "GET", ["url"], "none", 200, 200,
     "仅 http://127.0.0.1 且端口白名单；实测 /fetch?url=http://127.0.0.1:8095/ → 200", "内网回环探测面"),
    ("/upload", "GET", [], "none", 200, 200, "上传表单页（jpg/png/txt + 魔数双校验，≤5MB）", ""),
    ("/upload", "POST", ["file"], "none", None, None, "写操作，本阶段未执行", "后缀+魔数白名单"),
    ("/uploads/<name>", "GET", [], "none", 404, 404, "目录列举 404；上传目录初始为空", ""),
    ("/order/create", "GET", ["product_id", "qty"], "user", 302, 400, "demo 带 qty=0 → 400 数量无效",
     "处理函数不校验 HTTP 方法：GET 携带参数即可进入下单分支（代码级证据，未实测写操作）"),
    ("/order/status", "GET", ["order_id", "state"], "user", 302, 400,
     "demo 带 state=bogus → 400 非法状态流转", "同样不校验 HTTP 方法"),
    ("/coupon/claim", "GET", ["code"], "user", 302, 404, "demo 带 code=NOPE → 404 券不存在",
     "没有 code 无沙箱；写操作未执行"),
    ("/wallet/withdraw", "GET", ["amount"], "user", 302, 400, "demo amount=0/abc → 400 金额无效",
     "GET 可进入扣款分支（无 CSRF）；正数金额将直接扣款——未实测"),
    ("/wallet/transfer", "GET", ["to", "amount", "csrf_token"], "user", 302, 403,
     "demo 缺 csrf_token → 403 CSRF 校验失败", "CSRF 校验有效"),
    ("/change-password", "GET", ["new_password", "csrf_token"], "user", 302, 200,
     "GET 返回改密表单（含 csrf_token）", "带 new_password 参数时 GET 也走改密分支（未实测）"),
    ("/admin/users", "GET", [], "admin", 302, 404, "demo → 404（垂直越权封堵）", ""),
    ("/admin/orders", "GET", [], "admin", 302, 404, "demo → 404", ""),
    ("/debug", "GET", [], "admin", 302, 403, "未登录 302；demo 已登录 403（存在性泄露）；admin 200 泄露 SECRET_KEY/DB_PATH/cwd",
     "高价值：SECRET_KEY=lab-secret-key-PLEASE-CHANGE-001（源码常量），可推导 CSRF token"),
    ("/__reset", "GET", [], "none", 200, 200,
     "⚠ 破坏性：删库重建 + 清空 uploads/。本轮 katana 爬取（18:15:19）无意触发过一次，已复核 DB 恢复种子态",
     "侦察阶段禁止再次访问"),
]
for p, m, params, auth, pre, post, note, extra in routes_8095:
    mapdata["routes"].append({
        "asset": "127.0.0.1:8095", "path": p, "method": m, "params": params,
        "auth": auth, "status_unauthed": pre, "status_authed_demo": post,
        "note": note, "extra": extra,
        "evidence": "recon-10-surface / recon-11-login-trace / recon-12-methods（_evidence 目录）"
    })

# ---------------- 8091 routes ----------------
routes_8091 = [
    ("/", "GET", ["m"], "none", 200, 200, "首页，公开 demo/alice 测试口令", ""),
    ("/login", "GET", [], "none", 200, 200, "登录表单，含 csrf_token 隐藏字段", ""),
    ("/login", "POST", ["username", "password", "csrf_token"], "none", None, None,
     "demo/demo1234 → 303 /profile + Set-Cookie session=...", "登录成功清空失败记录"),
    ("/register", "GET", [], "none", 200, 200, "注册表单（csrf_token）", ""),
    ("/register", "POST", ["username", "password", "password2", "csrf_token"], "none", None, None,
     "弱口令→303 ?m=invalid；两次口令不一致→303 ?m=invalid；重名 demo→303 ?m=exists；缺 csrf→403",
     "本阶段未创建任何账号（DB users 仍为 2 行）"),
    ("/logout", "POST", [], "user", 404, 404, "未登录 GET/POST 均 404（route_post 之外）", "登出在个人中心表单内"),
    ("/profile", "GET", [], "user", 303, 200, "未登录 303 /login?m=needlogin；demo 200（个人中心）", ""),
    ("/api/profile", "GET", ["id"], "user", 400, 400, "缺 id→400；未登录→401；他人 id→404（响应体与不存在一致）",
     "demo 查 id=3(alice) 404"),
    ("/api/orders", "GET", ["id"], "user", 400, 400, "缺 id→400；未登录→401；他人订单→404 且写审计 api_forbidden",
     "demo 查 id=3 → 404 并落审计"),
    ("/change-password", "POST", ["old_password", "new_password", "csrf_token"], "user", 404, 404,
     "GET 404，仅 POST；写操作未执行", "成功后踢掉全部会话"),
    ("/debug", "GET", [], "-", 404, 404, "不存在（8091 无 /debug）", "旧任务书提及的 BUG-01/VULN-02 需在挖掘阶段复测"),
    ("/forgot", "GET", [], "-", 404, 404, "不存在（Host 注入面仅在 8095 /forgot）", ""),
    ("/favicon.ico", "GET", [], "none", 204, 204, "204 空响应", ""),
]
for p, m, params, auth, pre, post, note, extra in routes_8091:
    mapdata["routes"].append({
        "asset": "127.0.0.1:8091", "path": p, "method": m, "params": params,
        "auth": auth, "status_unauthed": pre, "status_authed_demo": post,
        "note": note, "extra": extra,
        "evidence": "recon-10-surface / recon-11-login-trace / recon-12-methods"
    })

# ---------------- business flow ----------------
mapdata["business_flow"] = {
    "127.0.0.1:8095": [
        {"step": 1, "action": "GET /", "auth": "none", "result": "200 入口页，页面明文列出 4 个账号口令 + /__reset 链接",
         "sharable": "明文口令公开"},
        {"step": 2, "action": "POST /login {username,password}", "auth": "none",
         "result": "302 /home + Set-Cookie token=...（无 CSRF 校验）", "sharable": "登录 CSRF + 明文口令比对"},
        {"step": 3, "action": "GET /home", "auth": "user", "result": "200 钱包页：余额 + 订单表 + 转账/提现/改密表单（含 csrf_token）",
         "sharable": "csrf_token = HMAC(SECRET_KEY, session token)"},
        {"step": 4, "action": "GET /order/create?product_id&qty", "auth": "user", "result": "400（qty=0）",
         "sharable": "GET 可进入下单分支；无 CSRF"},
        {"step": 5, "action": "GET /order/status?order_id&state", "auth": "user", "result": "400（state=bogus）；合法流转 unpaid→paid→shipped",
         "sharable": "GET 可改单状态；无 CSRF；admin 可改任意单"},
        {"step": 6, "action": "GET /coupon/claim?code", "auth": "user", "result": "404（code=NOPE）；成功则加余额（幂等 PRIMARY KEY 去重）",
         "sharable": "GET 领取优惠券；无 CSRF"},
        {"step": 7, "action": "GET /wallet/withdraw?amount", "auth": "user", "result": "400（无效金额）；成功走原子 UPDATE 扣款",
         "sharable": "GET 提现；无 CSRF"},
        {"step": 8, "action": "GET /wallet/transfer?to&amount&csrf_token", "auth": "user+CSRF", "result": "403 缺 token",
         "sharable": "唯一强制 CSRF 的写入口"},
        {"step": 9, "action": "GET/POST /change-password", "auth": "user+CSRF", "result": "GET 200 表单；提交需 csrf_token",
         "sharable": "改密需 CSRF"},
        {"step": 10, "action": "GET /upload + POST /upload", "auth": "none", "result": "200 表单（未提交）",
         "sharable": "匿名上传面：jpg/png/txt + 魔数校验"},
        {"step": 11, "action": "GET /download?file", "auth": "none", "result": "readme.txt 200；越权路径 403",
         "sharable": "白名单下载"},
        {"step": 12, "action": "GET /forgot?username", "auth": "none", "result": "200 明文回显重置链接",
         "sharable": "X-Forwarded-Host 注入 + md5(user) token"},
        {"step": 13, "action": "GET /admin/users | /admin/orders | /debug", "auth": "admin", "result": "demo 404；/debug 对已登录非 admin 返回 403",
         "sharable": "/debug 泄露 SECRET_KEY、DB_PATH、cwd"},
        {"step": 14, "action": "GET /__reset", "auth": "none", "result": "200 将删库重建",
         "sharable": "⚠ 破坏性，漏洞挖掘阶段务必禁用"}
    ],
    "127.0.0.1:8091": [
        {"step": 1, "action": "GET /", "auth": "none", "result": "200 首页，公开 demo/demo1234、alice/alice1234", "sharable": "明文口令公开"},
        {"step": 2, "action": "GET /login → POST /login {+csrf_token}", "auth": "none",
         "result": "303 /profile + Set-Cookie session=...", "sharable": "强制 CSRF"},
        {"step": 3, "action": "GET /profile", "auth": "user", "result": "200 个人中心 + 订单 + 改密表单（POST /change-password）",
         "sharable": "改密成功后踢全部会话"},
        {"step": 4, "action": "GET /api/profile?id / /api/orders?id", "auth": "user",
         "result": "本人 200；他人/不存在统一 404；未登录统一 401", "sharable": "已封水平越权与枚举差异"},
        {"step": 5, "action": "POST /register", "auth": "none",
         "result": "弱口令/不一致 → ?m=invalid；重名 → ?m=exists；无 CSRF → 403", "sharable": "注册需 CSRF + 复杂度校验"}
    ]
}

# ---------------- stats ----------------
n_routes = len(mapdata["routes"])
param_names = set()
for p in mapdata["params"]:
    if not p.get("name"):
        continue
    for piece in str(p["name"]).replace(" ", "").split(","):
        if piece and "/" not in piece:
            param_names.add(piece)
n_endpoints = len({(r["asset"], r["path"], r["method"]) for r in mapdata["routes"]})
n_paths = len({(r["asset"], r["path"]) for r in mapdata["routes"]})
mapdata["attack_surface_stats"] = {
    "route_entries": n_routes,
    "unique_path_method": n_endpoints,
    "unique_paths": n_paths,
    "unique_params": len(param_names),
    "param_names": sorted(param_names),
    "entries_8091": len([r for r in mapdata["routes"] if r["asset"].endswith("8091")]),
    "entries_8095": len([r for r in mapdata["routes"] if r["asset"].endswith("8095")]),
    "unauthenticated_route_entries": len({(r["asset"], r["path"], r["method"]) for r in mapdata["routes"]
                                          if r["auth"] in ("none", "-")})
}

# ---------------- priority hints ----------------
mapdata["priority_hints"] = [
    {"rank": 1, "asset": "127.0.0.1:8095", "entry": "/forgot?username=<x>",
     "class": "Host 头注入 / 弱口令重置 token",
     "evidence": "实测 X-Forwarded-Host: evil.example → <pre>http://evil.example/reset?user=demo&token=fe01ce2a7fbac8fafaed7c982a04e229</pre>",
     "why_high": "token=md5(username) 完全可预测；若存在 /reset 消费端即可任意用户改密（当前该路由不存在，需确认消费面）",
     "status": "已实测（回显层面）"},
    {"rank": 2, "asset": "127.0.0.1:8095", "entry": "/debug",
     "class": "敏感信息泄露（SECRET_KEY）",
     "evidence": "debug_page() 输出 DEBUG/SECRET_KEY/DB_PATH/BASE_DIR/UPLOAD_DIR/cwd；KEY 常量 lab-secret-key-PLEASE-CHANGE-001（app.py:42）",
     "why_high": "拿到 SECRET_KEY = 可离线伪造任意会话的 CSRF token（HMAC(SECRET_KEY, token)），配合 GET 写入口放大",
     "status": "代码级证据 + 未登录 302/非 admin 403 实测；admin 成功响应未复现（阶段2不登录 admin）"},
    {"rank": 3, "asset": "127.0.0.1:8095", "entry": "GET /wallet/withdraw?amount=N（及 /order/create、/order/status、/coupon/claim）",
     "class": "无方法限制的状态变更 + 无 CSRF（GET 即可触发）",
     "evidence": "route() 后各 handler 只判断 self.command=='POST' 决定分支；withdraw 无 CSRF 校验；实测 GET 进入 400 校验分支",
     "why_high": "诱使已登录用户访问一个 GET 链接即可扣余额/领券/改单状态（CSRF），且 money 类接口",
     "status": "代码级证据已确认；扣款成功路径未实测（只读约束）"},
    {"rank": 4, "asset": "127.0.0.1:8095", "entry": "POST /board（匿名）+ GET /board 输出",
     "class": "匿名内容写入 / 存储型注入候选",
     "evidence": "board() POST 无需登录，author=anonymous；输出 html.escape（当前无 XSS）",
     "why_high": "任何匿名者都能污染留言板；后续若与 admin 浏览面联动即是存储型 XSS 入口",
     "status": "代码级证据；未写帖"},
    {"rank": 5, "asset": "127.0.0.1:8095", "entry": "GET /fetch?url=",
     "class": "内网回环探测（受限 SSRF）",
     "evidence": "实测 /fetch?url=http://127.0.0.1:8095/ → 200 原样回显；非 127.0.0.1 → 403；端口白名单 {80,443,8080,8081,8082,8090,8091,8092,...}",
     "why_high": "可探测本机白名单端口存活/内容（8091 已在白名单内），是横向侦察跳板",
     "status": "已实测"},
    {"rank": 6, "asset": "127.0.0.1:8095", "entry": "GET /（已登录会话）",
     "class": "功能性缺陷（认证态首页 500）",
     "evidence": "lab_errors.log 多次记录 app.py:513 AttributeError: 'sqlite3.Row' object has no attribute 'get'；实测带 token cookie 的 GET / → 500",
     "why_high": "登录后首页必崩，影响可用性；同时暴露未处理异常路径",
     "status": "已实测（复现条件：带有效会话 cookie）"},
    {"rank": 7, "asset": "127.0.0.1:8091", "entry": "/api/profile?id=、/api/orders?id=",
     "class": "越权/枚举面（当前已封堵）",
     "evidence": "demo 会话查 id=3 → 404 且审计 api_forbidden；未登录 → 401",
     "why_high": "历史漏洞面，需挖掘阶段用新会话/边界值复测（例如 id=0、超大 id、数组参数）",
     "status": "已实测为封堵"},
    {"rank": 8, "asset": "127.0.0.1:8091", "entry": "/register",
     "class": "用户枚举（差异化 msg）",
     "evidence": "重名 → ?m=exists；其他非法 → ?m=invalid（303 Location 差异）",
     "why_high": "可枚举已存在用户名（demo/alice 已知，价值有限）",
     "status": "已实测"}
]

mapdata["disabled_or_negative"] = [
    "katana / 全站爬虫：禁止再对 8095 无过滤爬取 —— 18:15:19 曾自动访问 /__reset 触发删库重建",
    "/__reset：漏洞挖掘阶段任何工具与人工请求都不得访问",
    "HTTP PUT/DELETE/PATCH/TRACE：8095 统一 501（BaseHTTPRequestHandler 未实现）；8091 统一 405",
    "OPTIONS：8095 204（do_OPTIONS 固定应答）；8091 405",
    "/download 路径穿越：../、%2f、%2e%2e 全部 403",
    "/ping 命令注入：; 号被正则拒绝（400 无效主机）",
    "/greet SSTI：{{7*7}} 原样回显",
    "/api/search SQLi：参数化 LIKE ?，UNION payload 无效（响应回显 SQL 模板）",
    "登录爆破：8095 连续 5 次失败锁 15 分钟（429）；8091 三重锁定（账号/IP/全局）"
]

mapdata["evidence_files"] = [
    "security/learning/_evidence/recon-httpx-20261012-181433.txt（httpx 指纹）",
    "security/learning/_evidence/recon-katana-8091-20261012-181504.jsonl（katana 8091，4 条）",
    "security/learning/_evidence/recon-katana-8095-20261012-181504.jsonl（katana 8095，15 条）",
    "security/learning/_evidence/recon-ffuf-8091-20261012-181448.json（ffuf 8091）",
    "security/learning/_evidence/recon-ffuf-8095-20261012-181448.json（ffuf 8095）",
    "security/learning/_evidence/recon-nuclei-20261012-181707.jsonl（nuclei 11 条 info 级）",
    "security/learning/_evidence/recon-10-surface-20261012-181548.json（未认证/认证面探针）",
    "security/learning/_evidence/recon-11-login-trace-20261012-181614.json（登录时序追踪）",
    "security/learning/_evidence/recon-12-methods-20261012-182046.json（方法矩阵 + 业务流程无副作用探针）",
    "security/learning/_evidence/recon-13-verify-state.py 输出（DB 未改动核验）",
    "target-site-lab/lab_errors.log（500 堆栈）",
    "target-site/audit.log（审计事件）"
]

with open(OUT_JSON, "w", encoding="utf-8") as fh:
    json.dump(mapdata, fh, ensure_ascii=False, indent=2)

# ---------------- markdown ----------------
md = []
md.append(f"# 攻击面地图 · 阶段2 侦察（{TS}）\n")
md.append(f"- 任务：t3 / attempt {mapdata['meta']['attempt_id']}")
md.append(f"- 生成时间：{mapdata['meta']['generated_at']}")
md.append("- 范围：仅 127.0.0.1:8091 / 127.0.0.1:8095（本地授权靶场）")
md.append("- 本阶段只读：未执行任何写操作（仅登录 demo 与无效参数校验分支）\n")

md.append("## 1. 结论\n")
md.append(f"- 攻击面规模：**路由条目（路径×方法）{mapdata['attack_surface_stats']['unique_path_method']} 条 / "
          f"唯一路径 {mapdata['attack_surface_stats']['unique_paths']} 个**"
          f"（8095 {mapdata['attack_surface_stats']['entries_8095']} 条记录 / 8091 "
          f"{mapdata['attack_surface_stats']['entries_8091']} 条记录），"
          f"**唯一参数名 {mapdata['attack_surface_stats']['unique_params']} 个**。")
md.append("- 高危入口集中在 8095：`/forgot`（Host 头注入 + md5 弱 token）、`/debug`（SECRET_KEY 泄露）、"
          "`/wallet/withdraw` 等 GET 可写的状态变更接口、匿名 `/board`、受限 SSRF `/fetch`。")
md.append("- 8091 当前加固到位：CSRF 强制、属主校验、注册复杂度校验均可复现为『已封堵』；其历史漏洞结论需在挖掘阶段用新会话复测。")
md.append("- 两站均只监听回环，未发现公网暴露面。\n")

md.append("## 2. 资源与指纹\n")
md.append("| 目标 | Server | 标题 | 长度 | 关键指纹 |")
md.append("|---|---|---|---|---|")
for a in mapdata["assets"]:
    md.append(f"| {a['asset']} | {a['server_header']} | {a['title']} | {a['http_len']} | "
              f"{', '.join(a['tech'][:2])} |")
md.append("")
md.append("nmap -sT -sV -p 8091,8095 127.0.0.1：两个端口 open，banner 分别为 `TargetSite/1.0`、`LabHTTP/0.2 Python/3.12.10`（nmap 均未识别为已知服务）。\n")

md.append("## 3. 路由与参数（节选，完整见同名 JSON）\n")
md.append("### 8095 target-site-lab\n")
md.append("| 路径 | 方法 | 参数 | 权限 | 未登录 | 已登录(demo) | 备注 |")
md.append("|---|---|---|---|---|---|---|")
for r in mapdata["routes"]:
    if not r["asset"].endswith("8095"):
        continue
    md.append(f"| `{r['path']}` | {r['method']} | {', '.join(r['params']) or '-'} | {r['auth']} | "
              f"{r['status_unauthed']} | {r['status_authed_demo']} | {r['note'][:70]} |")
md.append("\n### 8091 target-site\n")
md.append("| 路径 | 方法 | 参数 | 权限 | 未登录 | 已登录(demo) | 备注 |")
md.append("|---|---|---|---|---|---|---|")
for r in mapdata["routes"]:
    if not r["asset"].endswith("8091"):
        continue
    md.append(f"| `{r['path']}` | {r['method']} | {', '.join(r['params']) or '-'} | {r['auth']} | "
              f"{r['status_unauthed']} | {r['status_authed_demo']} | {r['note'][:70]} |")

md.append("\n## 4. 业务流程与可篡改点\n")
for asset, steps in mapdata["business_flow"].items():
    md.append(f"### {asset}\n")
    md.append("| # | 动作 | 权限 | 实测结果 | 可篡改/风险点 |")
    md.append("|---|---|---|---|---|")
    for s in steps:
        md.append(f"| {s['step']} | `{s['action']}` | {s['auth']} | {s['result'][:90]} | {s['sharable']} |")
    md.append("")

md.append("## 5. 高价值入口 Top\n")
for h in mapdata["priority_hints"]:
    md.append(f"### {h['rank']}. `{h['entry']}`（{h['asset']}）\n")
    md.append(f"- 类型：{h['class']}")
    md.append(f"- 证据：{h['evidence']}")
    md.append(f"- 价值：{h['why_high']}")
    md.append(f"- 状态：{h['status']}\n")

md.append("## 6. 无效面/禁止动作\n")
for d in mapdata["disabled_or_negative"]:
    md.append(f"- {d}")

md.append("\n## 7. 方法与证据文件\n")
for e in mapdata["evidence_files"]:
    md.append(f"- {e}")

md.append("\n## 8. 未决问题（移交挖掘阶段）\n")
md.append("1. `/forgot` 生成的 `/reset?token=` 是否存在消费端（当前 404）——若有即任意用户改密链，需确认。")
md.append("2. `GET /wallet/withdraw?amount=N` 等 GET 写入口在**真实扣款**路径未实测（只读约束），需在可控重置窗口内验证并立即 `/__reset` 复原。")
md.append("3. `/debug` 的 admin 响应体（SECRET_KEY 实值是否与源码常量一致）未复现，阶段3 可用 admin 账号验证。")
md.append("4. 8095 未登录访问 `/` 曾出现 500（lab_errors.log 18:15:15/18:15:49），随后同条件多次复现均为 200，**条件不明**，需补充复现实验。")
md.append("5. katana 本次误触 `/__reset`，DB 已确认回到种子态（users 4 行、orders 3 行、messages 1 条）；后续爬取必须 `-fs`/`-filter` 排除 `/__reset`。")
md.append("6. 8091 无 `/__reset`，其 sessions(41 行)、login_attempts(4 键 SQLi 探测残留) 会持续累积，需 captain 决定是否补复位流程。")

with open(OUT_MD, "w", encoding="utf-8") as fh:
    fh.write("\n".join(md) + "\n")

def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

print(json.dumps({
    "json": OUT_JSON, "json_size": os.path.getsize(OUT_JSON), "json_sha256": sha(OUT_JSON),
    "md": OUT_MD, "md_size": os.path.getsize(OUT_MD), "md_sha256": sha(OUT_MD),
    "stats": mapdata["attack_surface_stats"],
    "routes_total": len(mapdata["routes"]),
    "unique_params": sorted({p["name"] for p in mapdata["params"] if p.get("name")})
}, ensure_ascii=False, indent=2))
