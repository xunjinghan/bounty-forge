# 漏洞笔记：/api/order?id= 类型宽松（'+1' / '01' / '1e0' / '1.0' 均等价 id=1）

- **编号**：VER-14（来源 HUNT-14，t5 判定 **confirmed-no-impact**，标签为"行为确认但无实际影响"）
- **靶场**：target-site-lab `http://127.0.0.1:8095`（本机授权练习环境）
- **危害等级**：信息项（Info，CVSS-like 0.0）
- **CWE/OWASP**：CWE-704（Incorrect Type Conversion or Cast）＋ CWE-1287（Improper Validation of Specified Type of Input）的同类问题；OWASP Top 10 2021 **A03:2021 Injection（类型处理层）**
- **复现率**：1/1 本轮，与挖掘阶段 B3 独立结论一致
- **代码位置**：`target-site-lab/app.py:650-663`（`api_order`，关键行 656-660）

---

## 1. 漏洞概述

`GET /api/order?id=` 把用户提供的字符串直接交给 SQLite 比较（`WHERE id=?`），SQLite 的类型亲和性会把 `'+1'`、`'01'`、`'1e0'`、`'1.0'` 都折算成数值 `1`，于是这些写法都能命中 `id=1` 的订单。

**为什么算"无实际影响"**：该查询结果仍受属主校验约束（`row["user_id"] != user["id"]` → 统一 404），无论用哪种等价写法，**只能读到属于自己的订单**，没有产生越权或信息泄露。它是一条"行为确认但无可利用后果"的记录，价值在于：

1. 说明 ID 校验是"宽松类型"而非"严格正整数"，若将来 ACL 判定改用字符串比较（如把 `id` 与某处字符串拼接后比对），同类宽松处理可能升级为绕过；
2. 属于典型的"注入点被 ACL 兜住"案例，适合作为**判定边界的教材**：光看"参数能变形通过查询"不能直接写漏洞，必须验证 ACL 是否兜住。

按任务纪律，本项**不写误报**，但作为 confirmed-no-impact 记录归档，并明确标注"无可利用后果"。

---

## 2. 原理（代码层根因）

```python
# target-site-lab/app.py:650-663
def api_order(self, oid):
    conn = get_db()
    try:
        user = self.require_user(conn)
        if not user:
            return
        row = conn.execute(
            "SELECT * FROM orders WHERE id=?", (oid,)).fetchone()   # L656-657 字符串直传
        if row is None or row["user_id"] != user["id"]:             # L658 属主校验兜底
            self.json(404, {"error": "not found"})                  # L659
            return
        self.json(200, dict(row))
    finally:
        conn.close()
```

根因：

- **L656-657 未做 int 归一**：`oid` 是原样字符串，交由 SQLite 的类型亲和性（INTEGER 列的亲和转换）处理。`'+1'`/`'01'`/`'1e0'`/`'1.0'` 均转换为 `1`。
- **没有显式越权风险**：L658 的属主比较用的是数据库返回的 `row["user_id"]` 与会话用户的数值 `id`，类型一致，因此宽松转换无法"顺带"变成越权。
- 与 `/api/profile?id=`（`app.py:665-679`）同构，同一族问题。

---

## 3. 可复现 payload

前置条件：靶场 8095 在跑；登录 alice（订单 2 属主为 alice）。

```bash
# ① 登录 alice
curl.exe -s -c C:\temp\t5jar9 -d "username=alice&password=alice123" \
  http://127.0.0.1:8095/login

# ② 正常请求（命中 id=2，属主是 alice）
curl.exe -s -b C:\temp\t5jar9 "http://127.0.0.1:8095/api/order?id=2"

# ③ 类型变形：以下四种写法都等价 id=1
curl.exe -s -b C:\temp\t5jar9 "http://127.0.0.1:8095/api/order?id=+1"
curl.exe -s -b C:\temp\t5jar9 "http://127.0.0.1:8095/api/order?id=01"
curl.exe -s -b C:\temp\t5jar9 "http://127.0.0.1:8095/api/order?id=1e0"
curl.exe -s -b C:\temp\t5jar9 "http://127.0.0.1:8095/api/order?id=1.0"

# ④ 越权对照：alice 读 demo 的订单 → 404（证明 ACL 有效）
curl.exe -s -o NUL -w "%{http_code}\n" -b C:\temp\t5jar9 \
  "http://127.0.0.1:8095/api/order?id=3"
```

原始请求：

```http
GET /api/order?id=+1 HTTP/1.1
Host: 127.0.0.1:8095
Cookie: token=<alice 会话>
```

---

## 4. 复现步骤与证据

| 观测项 | 实测 |
|---|---|
| `id=+1` / `id=01` / `id=1e0` / `id=1.0` | 均命中 `id=1`（类型宽松确认） |
| 命中对象是否本人订单 | 属主不符时统一 **404**，未产生越权 |
| 与 `/api/profile` 行为 | 同构（同族问题） |

原始证据文件：

- `security/learning/_evidence/verify-02-logic-session-20261012-1855.json`（sha256 `1b7b154509e9a95157fbd67b78a22289798a0d0383af802c48f8007a5a74cd5c`）——四组等价写法的原始响应
- `security/learning/_evidence/verified-20261012-184800.json`（sha256 `218dc13d10cb4063e2eb9b85d0b220fa04d33af20499f24025a103dcbf83c020`，VER-14 条目：verdict=`confirmed-no-impact`、severity=`info`）
- `security/learning/_evidence/hunt-b-idor-20261012-1840.json`——挖掘阶段越权类原始包（含越权 404 对照）
- 源码比对：`target-site-lab/app.py:650-663`

回滚：本项只读，无需回滚。

---

## 5. 修复方案

### 代码级（P1，落到 `app.py:650-663`）

显式归一类型并校验，避免把类型解释权交给数据库：

```python
def api_order(self, oid):
    try:
        oid_i = int(str(oid).strip())          # 显式转换
        if oid_i <= 0:
            raise ValueError
    except (TypeError, ValueError):
        self.json(400, {"error": "invalid id"})
        return
    ...
    row = conn.execute("SELECT * FROM orders WHERE id=?", (oid_i,)).fetchone()
```

（注意：Python 的 `int()` 仍会接受 `'+1'`、`'01'`。若要严格，用 `str.isdigit()` 且拒绝前导 `0` 与符号位：`if not oid.isdigit() or oid != str(int(oid)): 400`。）

### 纵深防御

- **统一入口校验**：在路由层对 `id` 类参数做 `^\d{1,10}$` 正则约束，避免每个 handler 各写一套。
- **参数 schema 化**：给每个端点声明参数类型（int/str/enum）与范围，由框架统一校验。
- **ACL 独立且优先**：权限判定不要依赖"查询成功与否"，而是先取对象再显式比对属主（本项目已是正确做法，保持即可）。
- **回归用例**：`id=+1`、`id=1.0`、`id=%201` 等变形必须返回 400/404，且**不改变 ACL 结果**。

---

## 6. 参考链接

- CWE-704: Incorrect Type Conversion or Cast：https://cwe.mitre.org/data/definitions/704.html
- CWE-1287: Improper Validation of Specified Type of Input：https://cwe.mitre.org/data/definitions/1287.html
- SQLite 数据类型与亲和性（官方文档）：https://www.sqlite.org/datatype3.html
- Python `int()` 对 `'+1'` / `'01'` 的处理（数字字面量与转换规则）：https://docs.python.org/3/library/functions.html#int
- OWASP WSTG — Testing for IDOR：https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References

---

## 7. 学习要点

- **考什么思路**：**"参数能变形通过"≠"漏洞成立"**。判定 IDOR/越权必须做两件事：①确认 ID 能被宽松解释；②确认 ACL 是否被绕过。只做①就下结论，产出的是噪音。
- **本项的正确归档姿势**：标 `confirmed-no-impact`＋`info`，写清"行为确认、无可利用后果"，并给出它未来可能升级的前提条件（ACL 改为字符串比较、ID 与用户名拼接、下游系统二次解析）。
- **同类变体**：
  - `id[]=1`（数组型参数）触发类型混淆。
  - `id=1%00` 截断（旧版 PHP/Java 字符串处理）。
  - `id=1 OR 1=1` 若某处漏了参数化就升级为注入（本项目参数化到位）。
  - NoSQL 的 `id[$ne]=1` 类型混淆直接绕过查询条件（那类就越权成立）。
- **纪律提醒**：任务要求"误报不写"，但 confirmed-no-impact 不等于误报——它经过实测确认了行为，只是没有危害。笔记里必须把两者的差别写清楚，避免下游把 info 项当漏洞汇总。
