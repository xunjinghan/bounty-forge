# 漏洞笔记：form() 中 query 覆盖 body——GET/POST 同权、参数来源不受方法限制

- **编号**：VER-09（来源 HUNT-09，t5 判定 confirmed）
- **靶场**：target-site-lab `http://127.0.0.1:8095`（本机授权练习环境）
- **危害等级**：低危（Low）——本身危害有限，但它是 VER-02（CSRF 全链路）的成因之一
- **CWE/OWASP**：CWE-235（Improper Handling of Extra Parameters）＋ CWE-436（Interpretation Conflict）；OWASP Top 10 2021 **A03:2021 Injection（参数解析层）/ A01:2021 Broken Access Control（方法限制缺失）**
- **CVSS-like**：3.1（AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N）
- **复现率**：1/1 本轮，与挖掘阶段 F2 独立结论一致
- **代码位置**：`target-site-lab/app.py:336-347`（`form()`，关键行 341-346）

---

## 1. 漏洞概述

`form()` 先读 body 的 urlencoded 参数，再执行 `data.update(q)` 用 query 覆盖之。于是 `POST /wallet/withdraw?amount=1` + body `amount=999999` 的实际执行金额是 **1**，不是 999999。两点后果：

1. **参数来源不再受 HTTP 方法约束**——只要把参数塞进 query，GET 和 POST 完全同权（这是 VER-02 里"纯 GET 就能改状态"的底层原因）。
2. **任何只校验 body 的安全控制都会被绕过**——例如"正则检查 body 里的 `amount` 是否在合法区间"或"body 里必须带 csrf_token"这类实现，攻击者把恶意值放 query、把干扰值放 body 即可。

---

## 2. 原理（代码层根因）

```python
# target-site-lab/app.py:336-347
def form(self):
    path, q = self.parsed()                       # L337 query 参数
    data = {}
    length = int(self.headers.get("Content-Length") or 0)
    ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip()
    if length and ctype == "application/x-www-form-urlencoded":
        raw = self.rfile.read(length).decode("utf-8", "replace")
        data.update({k: v[0] for k, v in
                     urllib.parse.parse_qs(raw, keep_blank_values=True).items()})  # L343-345 body
    data.update(q)                                # L346 ← query 后写，覆盖同名 body 参数
    return path, data
```

根因：**合并顺序 + 无来源标记**。`data.update(q)` 让 query 拥有更高优先级，同时把两个来源的键值压成同一个 dict，调用方（各 handler）根本无法区分某个值是"来自 body"还是"来自 query"。

叠加因素：所有写操作 handler 都用 `form()` 取参（`order_create:922`、`order_status:975`、`coupon_claim:1016`、`wallet_withdraw:1058`、`wallet_transfer:1098`），且没有任何一处拒绝 GET——所以"GET 也能改状态"是设计上的默认行为，而不是偶发。

---

## 3. 可复现 payload

前置条件：靶场 8095 在跑；`demo/demo123` 可用。

```bash
# ① 登录 demo
curl.exe -s -c C:\temp\t5jar5 -d "username=demo&password=demo123" \
  http://127.0.0.1:8095/login

# ② query 与 body 同时给 amount，观察谁生效
curl.exe -s -i -b C:\temp\t5jar5 \
  -d "amount=999999" "http://127.0.0.1:8095/wallet/withdraw?amount=1"
#    实测：按 1 分扣款（body 的 999999 被忽略）
```

原始请求：

```http
POST /wallet/withdraw?amount=1 HTTP/1.1
Host: 127.0.0.1:8095
Cookie: token=<demo>
Content-Type: application/x-www-form-urlencoded

amount=999999
```

同族验证（GET 完全等价，无需 body）：

```bash
curl.exe -s -o NUL -w "%{http_code}\n" -b C:\temp\t5jar5 \
  "http://127.0.0.1:8095/wallet/withdraw?amount=1"       # 200，与 POST 同效
```

---

## 4. 复现步骤与证据

| 观测项 | 改前 | 改后（实测） |
|---|---|---|
| `demo.balance_cents` | 50500 | **50499**（按 1 分扣，而非 999999） |
| 生效参数来源 | — | **query 优先**（body 的 999999 被覆盖） |

原始证据文件：

- `security/learning/_evidence/verify-02-logic-session-20261012-1855.json`（sha256 `1b7b154509e9a95157fbd67b78a22289798a0d0383af802c48f8007a5a74cd5c`）——同一请求的 body/query 双参数实测
- `security/learning/_evidence/verified-20261012-184800.json`（sha256 `218dc13d10cb4063e2eb9b85d0b220fa04d33af20499f24025a103dcbf83c020`，VER-09 条目：source_logic / harm_proof）
- `security/learning/_evidence/findings-hunt-20261012-184144.json`——挖掘阶段 F2 的独立结论（与本项一致）
- 源码比对：`target-site-lab/app.py:336-347`

回滚：`GET /__reset`；收集时点（2026-10-12T18:48+08:00）`demo` 余额回到 50000 分（种子态）。

---

## 5. 修复方案

### 代码级（P0，落到 `app.py:336-347`）

原则：**不合并两个来源，或合并时保留来源与优先级并显式判断**。

```python
# 改法一（推荐）：拒绝歧义——同名参数出现在两个来源时直接报错
def form(self):
    path, q = self.parsed()
    data = {}
    ...
    if length and ctype == "application/x-www-form-urlencoded":
        raw = self.rfile.read(length).decode("utf-8", "replace")
        body = {k: v[0] for k, v in
                urllib.parse.parse_qs(raw, keep_blank_values=True).items()}
    else:
        body = {}
    dup = set(q) & set(body)
    if dup:                                   # query 与 body 同名 → 400，不猜
        raise ValueError(f"参数来源冲突: {sorted(dup)}")
    data.update(body)
    data.update(q)
    return path, data
```

```python
# 改法二：写操作强制只认 body，query 一律忽略
def form(self, prefer_body=False):
    ...
    data.update(q)
    if prefer_body:
        data.update(body)        # 让 body 覆盖 query
```

### 纵深防御

- **方法限制**：写操作端点全部 `if self.command != "POST": 405`（与 VER-02 修复联动），从入口消除"GET 也能改状态"。
- **参数白名单**：每个 handler 只取自己声明的参数名，其余忽略并记录；不把整个 dict 透传给业务逻辑。
- **CSRF token 校验基于 body/头**：`verify_csrf` 的 token 必须来自固定来源（如 `X-CSRF-Token` 头），避免"token 放 query 就能过"的歧义。
- **回归用例**：对每个写端点跑"query/body 同名不同值"的用例，断言服务端拒绝或行为可预期。

---

## 6. 参考链接

- CWE-235: Improper Handling of Extra Parameters：https://cwe.mitre.org/data/definitions/235.html
- CWE-436: Interpretation Conflict：https://cwe.mitre.org/data/definitions/436.html
- OWASP Web Security Testing Guide — Testing for HTTP Parameter Pollution：https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution
- Python 标准库 `urllib.parse.parse_qs`：https://docs.python.org/3/library/urllib.parse.html#urllib.parse.parse_qs

---

## 7. 学习要点

- **考什么思路**：参数**来源**本身是攻击面。看到应用同时接受 query 与 body，就要做"同名参数不同值"的对照实验（HTTP Parameter Pollution 的静态变体）。
- **典型后果**：绕过只检查 body 的 WAF/正则；改变业务分支取到与审计日志不一致的值（日志记 body `999999`、实际执行 `1`）；与 CSRF 联动变成"GET 即改状态"。
- **同类变体**：
  - 同名参数多值（`?id=1&id=2`）时不同后端取第一个/最后一个（ASP.NET 拼接、PHP 取最后一个）。
  - `Content-Type` 与 body 编码不一致导致的解析差异（JSON body 配 urlencoded 头）。
  - 框架层 `request.args` / `request.form` / `request.values` 优先级差异（Flask 的 `values` 也是 query 优先）。
  - 头与参数同名时的优先级混淆（`X-Forwarded-*` 与 query 同名，见 VER-05）。
- **写报告要点**：单看"扣了 1 分"是低危，但必须写清它的**放大器作用**——它是 CSRF 与参数校验绕过的共同底座，这类"低级底座缺陷"往往比单点高危更有价值。
