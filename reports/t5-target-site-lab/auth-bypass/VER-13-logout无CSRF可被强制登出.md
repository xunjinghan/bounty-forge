# 漏洞笔记：GET /logout 无 CSRF 保护（可被任意页面强制登出）

- **编号**：VER-13（来源 HUNT-13，t5 判定 confirmed）
- **靶场**：target-site-lab `http://127.0.0.1:8095`（本机授权练习环境）
- **危害等级**：低危（Low），但与 VER-04 叠加后构成"假登出"
- **CWE/OWASP**：CWE-352（Cross-Site Request Forgery）；OWASP Top 10 2021 **A01:2021 Broken Access Control**
- **CVSS-like**：4.3（AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L）
- **复现率**：2/2（step2 / step3 各一次，均 302 且清 Cookie）
- **代码位置**：`target-site-lab/app.py:567-568`（`logout`）

---

## 1. 漏洞概述

`GET /logout` 不校验任何令牌、不限制方法，任意页面只要让受害者打开一个 URL（`<img src="http://127.0.0.1:8095/logout">`、`window.open`、`location.href` 均可）就能**强制其登出**。

单看是"登出拒绝服务"（低危），但与本靶场 VER-04 叠加后危害升级性质：**服务端会话并没有真的失效**。用户以为已退出、重新登录，而攻击者手上的旧 Cookie 依然可用——"登出"反而成了一种掩盖痕迹的动作。这条组合利用需在报告中成对描述，不能只报其中一条。

---

## 2. 原理（代码层根因）

```python
# target-site-lab/app.py:567-568
def logout(self):
    self.redirect("/", clear_cookie=True)
```

根因与 VER-02 同族：**状态变更端点缺少 CSRF 校验与方法限制**。`logout()` 既不判断 `self.command`（GET/POST 一律执行），也不调用 `verify_csrf`（对照 `wallet_transfer` 在 `app.py:1104` 有校验）。

叠加因素（VER-04）：`_send(clear_cookie=True)`（`app.py:308-309`）只下发 `Set-Cookie: token=; Path=/; Max-Age=0`，服务端 `sessions` 行原封不动，所以"被登出"的用户重新登录后旧 token 仍是有效凭证。

---

## 3. 可复现 payload

前置条件：靶场 8095 在跑；`demo/demo123` 可用。

```bash
# ① 登录 demo
curl.exe -s -c C:\temp\t5jar8 -d "username=demo&password=demo123" \
  http://127.0.0.1:8095/login

# ② 一句 GET 触发登出（无需任何令牌）
curl.exe -s -i -b C:\temp\t5jar8 http://127.0.0.1:8095/logout
#    → 302，Set-Cookie: token=; Path=/; Max-Age=0
```

浏览器侧等价载荷（攻击者页面上的一行 HTML）：

```html
<img src="http://127.0.0.1:8095/logout" alt="" width="1" height="1">
```

组合验证（呼应 VER-04，证明"假登出"）：

```bash
# ③ 用旧 Cookie 值重放，仍然 200（服务端会话未失效）
curl.exe -s -o NUL -w "%{http_code}\n" \
  -H "Cookie: token=<步骤①的 token 值>" http://127.0.0.1:8095/home
```

---

## 4. 复现步骤与证据

| 观测项 | 实测 |
|---|---|
| `GET /logout` 带有效 Cookie | **302** + `Set-Cookie: token=; Path=/; Max-Age=0` |
| 是否需要令牌 | 不需要（无 `csrf_token` 亦成功） |
| 服务端 `sessions` 行 | **仍存在**（见 VER-04） |
| 旧 Cookie 重放 `/home` | 200（"我的钱包"） |

原始证据文件：

- `security/learning/_evidence/verify-02-logic-session-20261012-1855.json`（sha256 `1b7b154509e9a95157fbd67b78a22289798a0d0383af802c48f8007a5a74cd5c`）——logout 响应与登出后会话状态
- `security/learning/_evidence/verified-20261012-184800.json`（sha256 `218dc13d10cb4063e2eb9b85d0b220fa04d33af20499f24025a103dcbf83c020`，VER-13 条目）
- `security/learning/_evidence/hunt-f7-logout-20261012-1905.json`——挖掘阶段登出行为原始包
- 源码比对：`target-site-lab/app.py:567-568` 与 `:305-309`

回滚：本项无数据变更（仅影响 Cookie），无需回滚；收尾统一 `GET /__reset` 清会话。

---

## 5. 修复方案

### 代码级（P1，落到 `app.py:567-568`）

登出改为 POST + CSRF 校验，并同步吊销服务端会话（两处修复合并写，避免只改一半）：

```python
def logout(self):
    if self.command != "POST":                       # 禁止 GET 触发
        self.html(405, page("405", "<h1>方法不允许</h1>"))
        return
    conn = get_db()
    try:
        user = self.require_user(conn)
        if not user:
            return
        if not self.verify_csrf(self.form()[1].get("csrf_token", "")):
            self.html(403, page("CSRF 校验失败", "<h1>请求被拒绝</h1>"))
            return
        conn.execute("DELETE FROM sessions WHERE token=?", (self._session_token(),))
        conn.commit()
    finally:
        conn.close()
    self.redirect("/", clear_cookie=True)
```

同时把导航栏里的登出链接改成表单：

```html
<form method="post" action="/logout" style="display:inline">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <button>退出登录</button>
</form>
```

### 纵深防御

- **敏感操作一律非 GET**：把"读用 GET、写用 POST"作为全站硬约定，并加自动化检查（路由表 × 方法白名单）。
- **SameSite**：会话 Cookie 用 `SameSite=Lax`（现状）或 `Strict`；但要清楚它**挡不住**顶级 GET 导航，不能作为唯一防线。
- **会话吊销联动**：登出、改密、管理员强制下线都应删除服务端会话行（与 VER-04 修复同一处代码）。
- **可观测性**：对 `/logout` 的高频调用做审计，异常登出模式（例如每秒多次）可能是"假登出"掩盖行为的信号。

---

## 6. 参考链接

- CWE-352: Cross-Site Request Forgery (CSRF)：https://cwe.mitre.org/data/definitions/352.html
- OWASP CSRF Prevention Cheat Sheet（"用 POST 处理状态变更"原则）：https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- CWE-613: Insufficient Session Expiration（与 VER-04 关联）：https://cwe.mitre.org/data/definitions/613.html

---

## 7. 学习要点

- **考什么思路**：CSRF 清点要覆盖**所有**会改状态的端点，包括看起来"无害"的登出。攻击者关注的是"能改状态"这一属性，而不是业务语义的轻重。
- **为什么这条不能单独报**：单独看只是"被别人强制登出"（缓解影响有限）；只有与"登出不销毁服务端会话"（VER-04）合并，才构成"用户以为安全、实际会话仍可用"的完整故事。**报告里要写清依赖关系**。
- **同类变体**：
  - 强制登出配合钓鱼（受害者重新登录时落入钓鱼页）。
  - GET 型"切换语言/主题"接口被用作 CSRF 探测点（判断是否有 token 机制）。
  - 无 CSRF 的"绑定邮箱/手机号"接口（这类危害远高于登出，属高危 CSRF）。
  - `?logout=1` 参数式登出（参数即动作，天然可被跨站触发）。
