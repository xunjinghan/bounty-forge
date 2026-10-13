# 漏洞笔记：/logout 只清浏览器 Cookie，不销毁服务端会话（假登出）

- **编号**：VER-04（来源 HUNT-04，t5 判定 confirmed）
- **靶场**：target-site-lab `http://127.0.0.1:8095`（本机授权练习环境）
- **危害等级**：中危（Medium）
- **CWE/OWASP**：CWE-613（Insufficient Session Expiration）；OWASP Top 10 2021 **A07:2021 Identification and Authentication Failures**
- **CVSS-like**：5.4（AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N）
- **复现率**：2/2（同一流程独立跑两轮，均复现）
- **代码位置**：`target-site-lab/app.py:567-568`（`logout`）、`:305-309`（`_send` 的 `clear_cookie` 分支）、`:220-228`（`create_session`）

---

## 1. 漏洞概述

`GET /logout` 只回一个 `Set-Cookie: token=; Path=/; Max-Age=0` 清理浏览器侧 Cookie，**不删除 `sessions` 表里对应的行**。任何还留着旧 Cookie 值的一方（浏览器历史/代理日志/被窃 Cookie/共享设备上的另一浏览器配置），在"登出"之后依然能以完整登录态访问 `/home`。用户以为已退出，服务端认为会话仍有效。

危害上限取决于"谁能拿到旧 Cookie 值"——需要先持有 Cookie 才能利用，所以定中危而非高危；但在共享设备与 Cookie 泄露场景下，这是**会话永不失效**的直接后果。

---

## 2. 原理（代码层根因）

```python
# target-site-lab/app.py:567-568
def logout(self):
    self.redirect("/", clear_cookie=True)
```

```python
# target-site-lab/app.py:305-309（_send）
if set_cookie:
    self.send_header("Set-Cookie",
                     f"token={set_cookie}; Path=/; HttpOnly; SameSite=Lax")
if clear_cookie:
    self.send_header("Set-Cookie", "token=; Path=/; Max-Age=0")   # 只清客户端
```

会话状态完全存在服务端：`current_user()`（`app.py:370-377`）用 Cookie 里的 token 去 `SELECT ... FROM sessions s JOIN users u ...`，会话行的存在即等于登录态。而 `logout` 里**没有任何 `DELETE FROM sessions`**，所以服务端会话在登出后依然可命中。

Cookie 属性对照（`app.py:306-309`）：登录下发 `token=<值>; Path=/; HttpOnly; SameSite=Lax`；登出下发 `token=; Path=/; Max-Age=0`。两者都只作用于**客户端存储**——`Max-Age=0` 只是让浏览器丢弃 Cookie，服务端数据一行没动。

对照可见项目内已有正确写法——`create_session()`（`app.py:220-228`）在登录时会 `DELETE FROM sessions WHERE user_id=?`（L221）主动清理旧会话；`logout` 这套"只清 Cookie"的处理显然漏了同一动作。

---

## 3. 可复现 payload

前置条件：靶场 8095 在跑；`demo/demo123` 可用。

```bash
# ① 登录 demo，Cookie 存到 jar
curl.exe -s -c C:\temp\t5jar4 -d "username=demo&password=demo123" \
  http://127.0.0.1:8095/login

# ② 登出
curl.exe -s -i -b C:\temp\t5jar4 http://127.0.0.1:8095/logout
#    期望（安全）：服务端会话被删，旧 token 立即失效
#    实测：302 + Set-Cookie: token=; Path=/; Max-Age=0

# ③ 拿旧 Cookie 值直接重放（不用浏览器，绕过 Cookie 清理）
curl.exe -s -o NUL -w "%{http_code}\n" \
  -H "Cookie: token=<步骤①抓到的 token 值>" http://127.0.0.1:8095/home
#    实测：200，正文含「我的钱包」

# ④ 直查服务端会话表（可选）
python -c "import sqlite3;print(sqlite3.connect(r'C:\Users\Administrator\Documents\deepseek-harness\default-workspace\target-site-lab\lab.db').execute(\"select count(*) from sessions where username='demo'\").fetchone())"
```

原始请求：

```http
GET /logout HTTP/1.1
Host: 127.0.0.1:8095
Cookie: token=<demo 会话>

→ 302, Set-Cookie: token=; Path=/; Max-Age=0
```

---

## 4. 复现步骤与证据

| 观测项 | 期望（安全实现） | 实测 |
|---|---|---|
| `/logout` 响应 | 302 + 清 Cookie | 302 + `Set-Cookie: token=; Path=/; Max-Age=0` |
| `sessions` 表是否仍含 demo 会话行 | 不存在 | **仍存在** |
| 旧 token 重放 `GET /home` | 302 跳登录 | **200，正文含「我的钱包」** |

原始证据文件：

- `security/learning/_evidence/verify-02-logic-session-20261012-1855.json`（sha256 `1b7b154509e9a95157fbd67b78a22289798a0d0383af802c48f8007a5a74cd5c`）——登出前后会话状态与 `/home` 响应
- `security/learning/_evidence/verify-03-injection-ssrf-upload-20261012-1855.json`（sha256 `d168699eede0933b74257f3080e4677db22e511859d25c0fa376b3de7a086fd2`）——第二轮独立复现（step3）
- `security/learning/_evidence/hunt-f7-logout-20261012-1905.json`——挖掘阶段登出行为原始包
- `security/learning/_evidence/verified-20261012-184800.json`（VER-04 条目）
- 源码比对：`target-site-lab/app.py:220-228 / 305-309 / 367-368`

回滚：本项不写数据、仅新增会话，收尾用 `GET /__reset` 统一清理；复核时点（2026-10-12T18:48+08:00）`sessions` 表 0 行。

---

## 5. 修复方案

### 代码级（P0，落到 `app.py:567-568`）

登出时同步删除服务端会话行，再清 Cookie：

```python
def logout(self):
    conn = get_db()
    try:
        tok = self._session_token()
        if tok:
            conn.execute("DELETE FROM sessions WHERE token=?", (tok,))
            conn.commit()
    finally:
        conn.close()
    self.redirect("/", clear_cookie=True)
```

顺带把方法收紧（与 VER-13 联动）：

```python
def logout(self):
    if self.command != "POST":                  # 避免被任意页面强制登出
        self.html(405, page("405", "<h1>方法不允许</h1>"))
        return
    ...
```

### 纵深防御

- **会话生命周期**：`sessions` 加 `expires_at`，`current_user()` 查询时过滤过期行，并起一个定期清理线程/启动时清理。
- **会话固定防护**：登录成功后轮换 token（本项目 `create_session` 已做旧会话清理，方向正确，可再确认"登录前 token 不可复用"）。
- **一键登出全部设备**：提供"下线所有会话"入口，删除该用户全部 `sessions` 行。
- **Cookie 属性**：保持 `HttpOnly`（现有）；HTTPS 环境加 `Secure`。
- **回归用例**：自动化里断言"`/logout` 后旧 Cookie 打 `/home` 必须 302"。

---

## 6. 参考链接

- CWE-613: Insufficient Session Expiration：https://cwe.mitre.org/data/definitions/613.html
- OWASP Session Management Cheat Sheet：https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- OWASP Top 10 2021 A07:2021 Identification and Authentication Failures：https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- MDN：HTTP Cookie 的 `Max-Age` 只作用于客户端存储：https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie

---

## 7. 学习要点

- **考什么思路**：区分**客户端清理**与**服务端失效**。`Set-Cookie: ...Max-Age=0` 只是让浏览器把值扔掉，服务端数据库里的会话行一条没少——凡是"会话状态存在服务端"的应用，登出必须做删除。
- **怎么验证**：不要用浏览器点登出后就"看起来退出登录"下结论。正确做法是**手工保存 token 值**，登出后用 `-H "Cookie: token=..."` 重放，或直查 `sessions` 表。
- **同类变体**：
  - 改密码后旧会话不失效（改密应吊销该用户全部会话）。
  - 管理员禁用账号后会话仍可用（`current_user()` 只看 sessions 表，不看用户状态）。
  - JWT 无黑名单/无短过期，"登出"只是前端删 token。
  - 会话无绝对过期时间，`created_at` 存了却从不校验（本项目 `sessions.created_at` 即如此）。
- **写报告要点**：会话类漏洞的证据链要包含"服务端状态"（`sessions` 表行数/内容），仅凭 HTTP 200 会被质疑是浏览器缓存。
