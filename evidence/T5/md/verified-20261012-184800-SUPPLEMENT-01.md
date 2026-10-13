# t5 补充核验补充件 SUPPLEMENT-01（回应 mentor 复核 A/B/C）

生成：2026-10-12T19:00+08:00　作者：verifier　归属任务：t5（attempt 450d203c-0db1-4e81-a1fd-bcd94117576a，已 completed）
原始证据：`security/learning/_evidence/verify-07-atomicity-redirect-scope-20261012-1855.json`（197395B，sha256 见文末）
性质：**追加证据，不改已提交产物 verified-20261012-184800.json 的任何 verdict 与判定。**

## 0. 先说一条自我更正（重要）

我向 captain 汇报 VER-01 时写过一句「对照组 /wallet/withdraw 并发 20 次无负数 → 证明**同应用内原子实现可行、唯独 /order/create 缺失**」。按 mentor 复核意见 A 重新做全量写路径对照后，**后半句我撤回**：

- 能站住的：`/order/create` 在**该端点本身**缺少条件更新（源码 + 并发实测双重支撑）；
- 站不住的：「唯独」是**全称断言**，单点对照组推不出来。要支撑全称命题必须扫描全部写路径 —— 本补充件第 1 节做的就是这件事。

同时补一条**对 VER-01 自身成立条件的限定**：并发不是每次都能撞上窗口。本轮 step7 以 30 并发重跑 `/order/create` 时，**26/30 成功、4 条 400 余额不足、余额 50000→600（精确等于 26 单应扣额），未出现负数** —— 即该次请求被服务端串行化了，原子性"看起来是对的"。这与 step1 的 30/30、28/30 出负数并不矛盾，而是同一缺陷在两种调度下的两种表现。**结论：TOCTOU 窗口真实存在但依赖调度，复现率应写「≥95%（30 并发 3/3 轮出现负余额 + 1 轮未触发）」而非"必现"。** 此限定与 captain 裁决 2 一致。

## 1. 全量写路径原子性表（回应意见 A）

扫描对象：`target-site-lab/app.py` 全部会改「资金/归属」表的语句，逐点判定是否原子条件更新。

| 写点（源码行） | 语句语义 | 是否原子条件更新 | 并发实测 |
|---|---|---|---|
| `app.py:955` `/order/create` 扣款 | `UPDATE users SET balance_cents=balance_cents-? WHERE id=?`（**无** `balance_cents>=?`） | **否**（先读 `user["balance_cents"]` 校验，后无条件扣） | 30 并发：历史出现 30/30、28/30 成功并打到负数；本轮 step7 26/30（未触发负） |
| `app.py:957` `/order/create` 建单 | `INSERT INTO orders(...)` | 不适用（无金额前置条件） | 随扣款同事务提交 |
| `app.py:1040` `/coupon/claim` 加余额 | `UPDATE users SET balance_cents=balance_cents+? WHERE id=?` | **是**（纯增量，无读-改-写） | 20 并发：余额 +1000（只一次），未放大 |
| `app.py:1031` `/coupon/claim` 领券记录 | `INSERT INTO coupon_claims(...)` 依赖 `(user_id,code)` 主键冲突 | **是**（数据库唯一约束兜底，捕获 IntegrityError） | 20 并发：`claims_rows=1`，未重复领取 |
| `app.py:1075` `/wallet/withdraw` 扣款 | `UPDATE ... WHERE id=? AND balance_cents>=?` | **是** | 30 并发 ×1900：30 条 200，但余额精确停在 600（= 50000-26×1900），**未透支** |
| `app.py:1129` `/wallet/transfer` 扣款 | `UPDATE ... WHERE id=? AND balance_cents>=?` + `cur.rowcount==0 → rollback` | **是** | 本轮未做并发，源码条件与 withdraw 同构 |
| `app.py:1138` `/wallet/transfer` 加余额 | `UPDATE users SET balance_cents=balance_cents+? WHERE id=?` | **是**（纯增量） | 同上 |
| `app.py:1177` `/change-password` | `UPDATE users SET password=? WHERE id=?` | 不涉及资金 | — |

**修正后的表述**：五处"扣款/加款"写点中，**四处为原子实现（withdraw / transfer×2 / coupon 加款）**，**唯一非原子的是 `/order/create`（app.py:955）**；`coupon_claims` 虽为非原子"先插后改"，但被主键唯一约束兜住。因此「唯独 /order/create 缺条件更新」在**本文件这五处写点范围内**成立（这是枚举结论，不是举例结论）。

## 2. 30x 产生点枚举（回应意见 B）

方法：对源码 `route()` 中**全部 24 条路由**逐一发匿名 GET（**排除 `/__reset`、不使用 HEAD**，遵守团队纪律），记录状态码与 `Location`。

结果：
- 相对 Location 产生点 **14 个**：`/login→/`、`/logout→/`、`/home|/api/order|/api/profile|/order/create|/order/status|/coupon/claim|/wallet/withdraw|/wallet/transfer|/change-password|/admin/users|/admin/orders|/debug → /?err=login`
- **绝对 Location 产生点：0 个**
- `/fetch` 对相对 Location 的处置：`GET /fetch?url=http://127.0.0.1:8095/debug` → 200 / 2156B，返回的是**登录页**（urllib 跟随相对跳转后拿到 `/?err=login`，全程匿名身份）
- `/fetch` 自指：`GET /fetch?url=http://127.0.0.1:8095/fetch%3Furl%3D...` → 200，可递归（受 urllib 重定向上限/超时约束），不产生数据泄露

**修正后的表述（采纳 mentor 意见）**：
> 出站请求**不转发 Cookie** 是硬结论（urllib 不代理 Cookie，`/debug` 匿名必 302 → 该链条当前不可达）；
> 「站点无绝对 Location 产生点」是**枚举结论、时间相关**：已覆盖当前全部 24 条路由，但**若站点未来新增任何产生绝对 Location 的 30x（含相对 Location 被改写为绝对的场景），该防护即失效**。源码 `app.py:783-800` 确实是「先用原始 URL 校验 scheme/hostname/port，再直接 `urlopen(url)`」，**对 30x 最终落点无二次校验** —— 这个残余面如实记录。

## 3. 令牌作用域（回应练习建议 1，mentor 意见 C 关联）

| 用例 | 结果 |
|---|---|
| demo 会话 + 该会话自算 token → `/wallet/transfer` | **200 转账成功** |
| demo 会话 + alice 会话自算 token → `/wallet/transfer` | **403 CSRF 校验失败** |
| bob 会话 + alice 会话自算 token → `/change-password` | **302**（未改密，重定向） |

**结论**：CSRF token 严格绑定各自 `session_token`，**跨会话不可复用**。因此 VER-03 的准确表述是「**已知目标会话 token 时**，CSRF token 可离线推导」，而非"任意用户可用"。该结果**不降低**已闭合的推导链（`/debug` 泄露 SECRET_KEY + 页面 token 与自算 HMAC 逐字符相等两条实测仍在），只限定作用域；因此 **VER-03 维持 high 不改判**（前置=admin 会话或被窃 token，已在原报告标注）。

## 4. 结论变更一览（相对 t5 原始产物）

| 项 | 原始产物 | 本补充件 |
|---|---|---|
| VER-01 对照组表述 | 「唯独 /order/create 缺失」（举例支撑） | 升级为**五处资金写点枚举**支撑；并新增「并发未必现」限定（≥95%） |
| VER-01 复现率 | 3/3（30 并发） | 3/3 出负 + 1 轮未触发 → **≥95%，非必现** |
| /fetch 误报排除依据 | 「站点无绝对 Location 产生点」 | 保留结论，**补枚举范围 + 时间相关性 + 源码无二次校验的残余面** |
| FP-01 机制描述 | 1e23 → ValueError（正确）/ 2^63 → OverflowError（正确） | 保持；两处机制已分开写，勿混（mentor 意见 C） |
| VER-03 作用域 | 未显式声明 | 补「严格绑定会话 token，跨会话 403」实测 |
| VER-14/15 标签 | 「行为确认但无实际影响」 | 保持；该标签**仅**指 VER-14、VER-15，与 VER-02（有实际影响）不冲突（mentor 意见 D） |

## 5. 回滚与环境

- 补测前后均执行 `/__reset`；终态 `lab.db` sha256 = `49b2032c29f8057530704203fd361bb162461eaeeeeb874c7ac1b8e8956cc7af`（= t1 基线），`integrity_check=ok`，users4 / orders3 / messages1 / sessions0 / claims0，`uploads/` 空。
- 补测仅打 127.0.0.1:8095，未触碰 8091 与其他成员在测资产。
- 本补充件对应原始包：`verify-07-atomicity-redirect-scope-20261012-1855.json`。
- 过程瑕疵如实记录：step7 首次运行时线程未传参（`Thread(target=one)` 缺 `args=(i,)`），三组并发全部空跑（状态码 None、余额未动、DB 未被污染）；已修正后重跑，上表数据均取自修正后的运行。
