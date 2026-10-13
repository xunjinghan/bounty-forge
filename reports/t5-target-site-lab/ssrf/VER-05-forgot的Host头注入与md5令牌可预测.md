# 漏洞笔记：/forgot 回显攻击者可控 Host/X-Forwarded-Host + 重置 token=md5(username) 可离线预测

- **编号**：VER-05（来源 HUNT-05，t5 判定 confirmed；**利用链未闭合**）
- **靶场**：target-site-lab `http://127.0.0.1:8095`（本机授权练习环境）
- **危害等级**：中危（Medium）——**仅按 Host 注入与弱令牌计危害，不按"任意用户改密"计**（该链条证据不足）
- **CWE/OWASP**：CWE-644（Improper Neutralization of HTTP Headers for Scripting Syntax / 信任 Host 类头）＋ CWE-330（Use of Insufficiently Random Values）；OWASP Top 10 2021 **A04:2021 Insecure Design / A07:2021 Identification and Authentication Failures**
- **CVSS-like**：5.3（AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N）
- **复现率**：Host 注入 3/3（`X-Forwarded-Host`、`Host` 两种头均回显）；token 可预测 2/2；**`/reset` 消费端 GET/POST 均 404（2/2，链条未闭合）**
- **代码位置**：`target-site-lab/app.py:771-778`（`forgot`）

---

## 1. 漏洞概述

`GET /forgot?username=demo` 生成的"密码重置链接"有两个问题：

1. **主机名取自客户端可控头**：优先读 `X-Forwarded-Host`，其次 `Host`，原样拼进链接。攻击者可指定任意域名（本例回显 `http://evil.example/reset?...`），用于**钓鱼与链接劫持**（受害者收到的重置链接指向攻击者域）。
2. **令牌可离线预测**：`token = md5(username)`——不依赖任何服务端密钥、随机数或时间。任何人无需访问页面即可算出任意用户名的"重置令牌"。

**必须写清的边界（t5 与补充件一致）**：源码中**不存在 `/reset` 路由**（只有 `/__reset`），实测 `GET` 与 `POST /reset?user=…&token=…` 均 **404**，因此"任意用户改密"这条链**没有闭合**。本项危害只按上述两条计：

- 钓鱼/链接劫持：**成立**；
- 令牌可预测：**成立，但当前无消费端，无法据此改密**（属"待闭合的潜在链"）。

---

## 2. 原理（代码层根因）

```python
# target-site-lab/app.py:771-778
def forgot(self, username):
    host = (self.headers.get("X-Forwarded-Host")
            or self.headers.get("Host") or "127.0.0.1")     # L772-773 信任客户端头
    token = hashlib.md5(username.encode()).hexdigest()      # L774 无随机、无密钥、无过期
    link = f"http://{host}/reset?user={urllib.parse.quote(username)}&token={token}"   # L775
    body = (f"<h1>找回密码</h1><p>已为用户 <b>{html.escape(username)}</b> 生成重置链接：</p>"
            f"<pre>{html.escape(link)}</pre>")              # L776-777（此处有 html.escape，无 XSS）
    self.html(200, page("forgot", body))
```

根因：

- **L772-773 的"头优先"取值**：`X-Forwarded-Host` 本是给反向代理使用的头，直接信任等于把"链接主机名"的控制权交给请求方。同类问题还有 `X-Forwarded-For` 被当作可信来源 IP。
- **L774 的令牌派生**：`md5(username)` 空间是"用户名集合"，且不带时效与一次性语义——设计上就没把令牌当秘密（对比同类隐患：本靶场 VER-03 的 CSRF token 也用了可推导的 HMAC 派生，两处是同一类设计错误）。
- 输出已 `html.escape`（L776-777），所以**不构成 XSS**；这是要明确写清的阴性边界。

---

## 3. 可复现 payload

前置条件：靶场 8095 在跑；无需登录态。

```bash
# ① Host 注入：用 X-Forwarded-Host 指定攻击者域名
curl.exe -s -H "X-Forwarded-Host: evil.example" "http://127.0.0.1:8095/forgot?username=demo"
#    正文出现：http://evil.example/reset?user=demo&token=fe01ce2a7fbac8fafaed7c982a04e229

# ② 换用 Host 头同样生效
curl.exe -s -H "Host: attacker.tld" "http://127.0.0.1:8095/forgot?username=demo"

# ③ 离线复算令牌，验证无随机性
python -c "import hashlib;print(hashlib.md5(b'demo').hexdigest())"
#    → fe01ce2a7fbac8fafaed7c982a04e229（与页面回显逐字符一致）

# ④ 链条验证：消费端不存在
curl.exe -s -o NUL -w "%{http_code}\n" "http://127.0.0.1:8095/reset?user=demo&token=fe01ce2a7fbac8fafaed7c982a04e229"   # 404
curl.exe -s -o NUL -w "%{http_code}\n" -d "token=fe01ce2a7fbac8fafaed7c982a04e229&new_password=x" "http://127.0.0.1:8095/reset"  # 404
```

原始请求：

```http
GET /forgot?username=demo HTTP/1.1
Host: 127.0.0.1:8095
X-Forwarded-Host: evil.example
```

---

## 4. 复现步骤与证据

| 观测项 | 期望（安全实现） | 实测 |
|---|---|---|
| 链接主机名 | 固定为服务端配置的域名 | **攻击者可控**（`evil.example` / `attacker.tld` 均回显） |
| 令牌 | 随机、一次性、有时效 | **`md5(username)`**，可离线复算（与页面逐字符一致） |
| 消费端 `/reset` | 校验令牌并改密 | **404（GET/POST 均 404，链未闭合）** |
| XSS | — | 不成立（`html.escape`，见 `app.py:776-777`） |

原始证据文件：

- `security/learning/_evidence/verify-03-injection-ssrf-upload-20261012-1855.json`（sha256 `d168699eede0933b74257f3080e4677db22e511859d25c0fa376b3de7a086fd2`）——两种头的回显、token 复算、`/reset` 404
- `security/learning/_evidence/verified-20261012-184800.json`（sha256 `218dc13d10cb4063e2eb9b85d0b220fa04d33af20499f24025a103dcbf83c020`，VER-05 条目：`限定` 字段明确"按钓鱼/Host 劫持计，不按任意用户改密计"）
- `security/learning/_evidence/verified-20261012-184800-SUPPLEMENT-01.md`（sha256 `4f9d8344e257734afd981f0896b6d068e838121660123ce5992d995e1c84f24f`）——补充件的 24 条路由枚举同样未发现 `/reset`
- `security/learning/_evidence/attack-surface-20261012-182250.json`（sha256 `154b62ac6544fd7bb80b1d39264c02413a52d7b89705f7d911c9297457d8b91f`）——侦察阶段将该端点列为高价值入口（Host 注入 + 弱 token）
- 源码比对：`target-site-lab/app.py:771-778`（全文件无 `/reset` 路由）

回滚：本项只读，无数据变更。

---

## 5. 修复方案

### 代码级（P0/P1，落到 `app.py:771-778`）

```python
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "http://127.0.0.1:8095")   # 服务端配置，不接受客户端头

def forgot(self, username):
    # ① 主机名只来自服务端配置
    base = PUBLIC_BASE_URL.rstrip("/")
    # ② 令牌：随机 + 时效 + 一次性（存库校验）
    raw = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    conn = get_db()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO password_resets(token_hash,user_id,expires_at,used)"
            " VALUES (?,?,?,0)",
            (token_hash, user_id, int(time.time()) + 900))          # 15 分钟有效
        conn.commit()
    finally:
        conn.close()
    link = f"{base}/reset?user={urllib.parse.quote(username)}&token={raw}"   # 只下发原始随机串
    ...
```

配套的 `/reset` 消费端（当前缺失，需一并实现，否则本条永远停在"未闭合"）：

```python
def reset(self):
    path, form = self.form()
    if self.command != "POST":
        self.html(405, page("405", "<h1>方法不允许</h1>")); return
    raw = form.get("token", "")
    th = hashlib.sha256(raw.encode()).hexdigest()
    row = conn.execute(
        "SELECT * FROM password_resets WHERE token_hash=? AND used=0 AND expires_at>?",
        (th, int(time.time()))).fetchone()
    if row is None:
        self.html(400, page("重置失败", "<h1>链接无效或已过期</h1>")); return
    conn.execute("UPDATE users SET password=? WHERE id=?", (new_pw, row["user_id"]))
    conn.execute("UPDATE password_resets SET used=1 WHERE token_hash=?", (th,))
    conn.execute("DELETE FROM sessions WHERE user_id=?", (row["user_id"],))   # 重置后吊销全部会话
    conn.commit()
```

安全注意：无论用户是否存在，响应文案应一致（避免用户名枚举），且令牌只以哈希形式入库。

### 纵深防御

- **不接受客户端决定的"外部可见地址"**：`Host`、`X-Forwarded-Host`、`X-Forwarded-Proto` 一律不用于拼接对外链接；需要多域名时用白名单映射。
- **反向代理层清洗**：在入口处丢弃/覆盖不可信的 `X-Forwarded-*`，并把可信值显式传给应用。
- **口令哈希存储**：本项目 `users.password` 为明文入库（源码标注的教学面），应在修复时改为 `PBKDF2/bcrypt/argon2`；改密接口同时要校验旧口令强度与新口令策略。
- **邮件/短信外发限速**：`/forgot` 加频控与验证码，防止被作为"发信轰炸"通道。
- **回归用例**：伪造 `X-Forwarded-Host: evil.example` 后响应中不得出现该域名；`/reset` 用过期/已用/错误令牌必须失败。

---

## 6. 参考链接

- CWE-644: Improper Neutralization of HTTP Headers for Scripting Syntax：https://cwe.mitre.org/data/definitions/644.html
- CWE-330: Use of Insufficiently Random Values：https://cwe.mitre.org/data/definitions/330.html
- OWASP Forgot Password Cheat Sheet（找回口令流程设计要点）：https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
- Python `secrets` 模块（生成密码学安全随机串）：https://docs.python.org/3/library/secrets.html
- RFC 7230 §5.4 `Host` 头语义：https://www.rfc-editor.org/rfc/rfc7230#section-5.4

---

## 7. 学习要点

- **考什么思路**：找回口令是"身份核验 + 外发链接 + 时效令牌"的三段式。三段里任一环依赖客户端输入（Host 头）或可推导值（`md5(username)`），整条链就不可信。评测时要**分段判定**，别把"链没闭合"整体打成误报，也别把"Host 注入"夸成"任意改密"。
- **Host 头为什么不能信**：反代场景下 `Host` 由客户端提供，`X-Forwarded-Host` 更是明文可伪造；缓存投毒、密码重置链接劫持、虚拟主机路由错配都由它衍生。
- **同类变体**：
  - 用 `Host` 拼 `redirect_uri` / 回调地址 / 邮件里的绝对 URL。
  - 用 `X-Forwarded-For` 当来源 IP 做"内网信任"（本靶场 VER-06 的 IP 判定属同族）。
  - 令牌 = `md5(email)`、`md5(id+日期)`、自增 ID（可枚举/可预测）。
  - 令牌无过期、无一次性、重置后不吊销会话。
  - 找回口令响应泄露"用户是否存在"（用户名枚举）。
- **写报告要点**：链未闭合时**一定要写清"到哪一步为止"**并给出消费端 404 的原始证据，同时把"若消费端存在则危害升级"作为条件性结论单列，不要含糊成"可改任意用户密码"。
