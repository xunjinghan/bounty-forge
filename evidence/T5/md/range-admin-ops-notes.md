# range-admin 操作笔记 — 8095 靶场运维口径

> 维护者：range-admin（靶场与容器管理员）。**只打 127.0.0.1 本地靶场与本机容器。**
> 追加格式：`- [YYYY-MM-DD HH:mm] 内容 —— 证据（命令/文件/原始输出）`。
> 引用一律用完整文件名。

---

## 1. ★ 8095 复位口径（Loop2 A6 加固后变更，2026-10-12 19:53 起生效）

**旧口径（已作废，别再发）**：`curl http://127.0.0.1:8095/__reset`（GET，无需参数）
→ **现在返回 405，不执行复位。**

**新口径（唯一正确写法）**：

```
curl.exe -s -X POST "http://127.0.0.1:8095/__reset?confirm=RESET"
```

也可以把 `confirm=RESET` 放请求体（`-d "confirm=RESET"`），源码走的是 `self.form()`（query 与 body 都解析）。

### 实现级判据（源码 `target-site-lab/app.py` 第 1356-1387 行 `reset_endpoint()`）

| 序 | 条件 | 不满足时 | 代码行 |
|---|---|---|---|
| ① | `self.client_address[0]` ∈ {`127.0.0.1`, `::1`} | 403「仅允许本机回环访问。」 | 1360-1363 |
| ② | `self.command == "POST"` | **405**「复位接口仅接受 POST 请求，且需携带 confirm=RESET。」 | 1364-1369 |
| ③ | `form.get("confirm") == "RESET"` | 400「缺少二次确认」 | 1370-1375 |
| ④ | 写 `target-site-lab/reset-audit.log`（peer + UA），失败静默 | 不阻断 | 1376-1383 |
| ⑤ | 通过后执行 `reset_database()` | 200「已重置」 | 1384-1387 |

→ **`GET` 与 `HEAD` 都在第 ② 步被拦成 405，不会触发删库重建。** 历史上「HEAD 触发过删库」的隐患已被这一步修掉；
但**仍按纪律不发 HEAD**（任务书硬约束：8095 扫描排除 `/__reset` 与 HEAD）。

### 审计留痕（不可逆操作必须可追溯）

`target-site-lab/reset-audit.log`（2026-10-12 19:57:43 读取，406 字节）实测 7 条，全部 `peer=127.0.0.1 ua=curl/8.7.1`：

```
[2026-10-12 19:54:09] RESET peer=127.0.0.1 ua=curl/8.7.1
[2026-10-12 19:54:42] RESET peer=127.0.0.1 ua=curl/8.7.1
[2026-10-12 19:54:58] RESET peer=127.0.0.1 ua=curl/8.7.1
[2026-10-12 19:55:17] RESET peer=127.0.0.1 ua=curl/8.7.1
[2026-10-12 19:55:35] RESET peer=127.0.0.1 ua=curl/8.7.1
[2026-10-12 19:56:22] RESET peer=127.0.0.1 ua=curl/8.7.1
[2026-10-12 19:57:43] RESET peer=127.0.0.1 ua=curl/8.7.1
```

（这 7 次是 **t2 加固自测**产生的，不是本笔记作者所为。）

### ⚠️ 待修：文档与代码不同步

- `target-site-lab/README.md` 第 21 行仍写着 `curl http://127.0.0.1:8095/__reset`（GET 老写法）→ **照着敲会拿到 405**。
- `target-site-lab/LAB-MANIFEST.md` 第 19 行 `/__reset` 描述也是旧的 GET 口径。
- 归属：属靶场文档同步，**本笔记只记录，未擅自改靶场文件**；已报队长决定由谁改。

---

## 2. 8095 基线（Loop2 A 档加固后）

> 复核人：range-admin。**上一份快照 `security/learning/_evidence/baseline-20261012-194602.json` 已因 t2 的 schema 变更作废**，
> 其 `lab.db sha256 = 49b2032c…cc7af` 不再成立。
> ⚠️ **lab.db 的 sha256 只在"复位后、无会话写入"的瞬间稳定。** 任何登录都会写 `sessions` 行 → 哈希立刻变。
> 所以下面区分**稳定量**（进程/结构/种子态）与**易漂量**（lab.db sha256 / sessions 行数）。

### 2.1 稳定量（2026-10-12T20:00:06+08:00 实测，判据不随会话漂移）

| 项目 | 实测值 | 证据 |
|---|---|---|
| 进程 | PID **18824**，父 **20420**，CreationDate 2026-10-12T19:59:42 | `Get-CimInstance Win32_Process` |
| 命令 | `"<Python312>\python.exe" app.py 8095` | 同上 |
| 监听 | `TCP 127.0.0.1:8095 LISTENING 18824` | `netstat -ano` |
| HTTP | **200**，2165 字节，body sha256 `ae845cebefc5a68dc14ebfdfb8ab80955f5e272318f5dd631c071f55de74b248` | `curl.exe -s -o … -w "%{http_code}\|%{size_download}"` |
| 日志 | `target-site-lab\server-20261012-195942-err.log` / `server-20261012-195942-out.log`（0 字节） | `Get-ChildItem target-site-lab\server-*` |
| lab.db 结构 | 表 8 张：users/products/orders/messages/coupons/sessions/coupon_claims/sqlite_sequence；`integrity_check=ok` | sqlite 直查 |
| sessions 结构 | `token, user_id, username, created_at, **csrf_token**`（A3 新增列，**5 列**） | `PRAGMA table_info("sessions")` |
| 余额 balance_cents | admin 100000 / demo 50000 / alice 88800 / bob 100（**t2 复位态与 20:01 实测两次一致**） | sqlite 直查 |
| 口令 | admin `Lab@Admin2024!Secure#9`、demo `demo123`、alice `alice123`、bob `bob123` | `target-site-lab/app.py` 第 151-161 行种子常量 |
| 8091 | HTTP 200，PID 7700（未变动），body sha256 `a51e3ed1981bd7303e457f6421dfef3c38f5013178011024a7e536e5ae730b4d` | curl + netstat |
| app.py | sha256 **`870F28B3E1486A5FCD7FE5FCFC188B2D0BC2FF1A38FCC8DD70163D3A68310BA0`**，59159 字节，mtime 2026-10-12T19:53:34 | `Get-FileHash` |
| 原件备份 | `target-site-lab\app.py.loop1-original`，sha256 `D2992CD0F4832B9E67BACCB04163700D567F57B4ADA437E661017D015721B484`，54362 字节 | `Get-FileHash`（**完好，可回退**） |

### 2.2 lab.db 哈希轨迹（**每次变更都有归因，均非脏数据**）

| 时点 | sha256 | mtime | sessions 行数 | 归因 |
|---|---|---|---|---|
| 19:46:02（t1 复位后） | `49b2032c…cc7af` | 19:46:02 | 0 | A 档前置基线（4 列 sessions） |
| 19:57:43（t2 收尾复位） | `ffbb0f47…005e3` | 19:57:43 | 0 | **A3 加 `csrf_token` 列** → schema 变更 |
| 20:00:26（t3 验证登录） | `ceb139b2…93bd` | 20:00:26 | **1** | **t3 verifier 用 demo 登录**，写入 1 行 session |

→ 20:00:26 那行 session 实测为 `{token: riiFp7Zl…jRk, user_id: 2, username: demo, csrf_token: hK9ZwK5r…4Oac}`。
**这是正常的验证活动，不是污染**；余额四项与种子态一致，`coupon_claims` 仍为 0。

> 判据（schema 变更那条）：`PRAGMA table_info("sessions")` 返回 5 列（含 `csrf_token`）；19:46 快照时期为 4 列。
> ⚠️ **结论**：以后拿 lab.db sha256 当基线，必须先声明"复位后、未登录"这个前提；否则它一定会漂。

### 未验证项（诚实标注）

- **本笔记作者未发送任何 `/__reset` 请求**（GET/HEAD/POST 全未发）。上面 405 结论来自**源码阅读 + reset-audit.log + 他人 access log**，属**源码级/旁证级**结论，非本人实测。
- 新实例 err log 中 20:00:13 有 `HEAD /__reset → 405`、`GET /__reset → 405`、`POST /__reset → 400` 三条，
  **不是本笔记作者的命令**（作者 20:00:06-20:00:07 只发了 `GET /`），形态上属 **t3 verifier 的 A 档复打**。
  该组记录恰好旁证了 ①②③ 三道判据的拦截行为：
  - `HEAD /__reset → 405` ⇒ 判据 ② 生效（HEAD 不触发删库）→ **"HEAD 触发删库"的旧隐患已修**
  - `GET /__reset → 405` ⇒ 判据 ② 生效（GET 老写法失效）
  - `POST /__reset`（**不带 `confirm=RESET`**）→ **400** ⇒ 判据 ③ 生效（缺二次确认被拒）
  → 三条合起来正好是完整的行为矩阵，且**全程没有产生新的 RESET 审计行**（`reset-audit.log` 仍停在 19:57:43），
  即**三次尝试都没能删库** —— 这就是加固有效的硬证据。

---

## 3. 操作纪律（每次动手前过一遍）

1. **只打 127.0.0.1**；自动化扫描对 8095 一律**排除 `/__reset` 与 `HEAD`**（任务书硬约束）。
2. 打任何端点前**先判是否写端点**（POST/上传/下单/提现/复位/改密都算写操作）。
3. **账号状态变更（改口令/锁定/解锁）先报队长**。
4. 报数必须**改动后重读**；引用**用完整文件名**。
5. `/__reset` 是**不可逆**操作（删库重建 + 清空 `uploads/`），**每次执行前确认必要性，执行后立刻重录基线**。
6. 需要长期存活的服务**绝不放在 DSH 后台作业里**（应用重启会回收作业）→ 一律 `Start-Process` **独立进程**。
