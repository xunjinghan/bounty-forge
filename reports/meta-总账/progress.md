# 漏洞挖掘学习进度报告（security/learning/progress.md）

> 维护者：scribe（笔记生成员，负责 §1–§10；§11 循环记录由 mentor 追加）｜本段最后更新：**2026-10-12 19:05（Asia/Shanghai）**
> 章节级归属约定（captain 2026-10-12 终验时定，立即生效）：**§1–§10 归 scribe**（自主落笔）、**§11 归 mentor**（需其授权才能改）；**文件级由 scribe 单一落笔**以避免并发写冲突。任何人改非自己所属章节，须先取得该章节所有者授权，并在改动说明里注明"经 X 授权"（本次 §11 写法规范化即注明"受 mentor 授权"）。
> 纪律：只记录**已验证**漏洞；每条结论必须指向 `_evidence/` 下的原始证据；误报与"行为确认但无影响"单列，不计入漏洞数。
> 引用口径（scribe 自定，2026-10-12）：① §3/§7 中的证据引用一律使用**完整文件名**，禁止省略号或通配符写法；② 非 `_evidence/` 目录的文件（如靶场内置的 `target-site-lab/downloads/readme.txt`）必须标注所属目录，避免被当成缺失证据；③ 报数时同时给出「引用出现次数」与「唯一文件数」两个口径。

---

## 1. 本轮范围与靶场实况（2026-10-12 窗口）

| 靶场 | 地址 | 监听 | 本轮定位 |
|---|---|---|---|
| target-site-lab | http://127.0.0.1:8095 | 仅 127.0.0.1（pid 7908 起于 18:11） | 主目标（第八轮加固版，带 `/__reset`） |
| target-site | http://127.0.0.1:8091 | 仅 127.0.0.1（pid 11776 起于 18:11） | 仅做只读连通核对 |

启动/复现命令：

```powershell
$py = "C:\Users\Administrator\AppData\Local\Programs\Python\Python312\python.exe"
Start-Process $py -ArgumentList "app.py","8091" -WorkingDirectory "...\default-workspace\target-site"
Start-Process $py -ArgumentList "app.py","8095" -WorkingDirectory "...\default-workspace\target-site-lab"
# 复位（会删库重建，仅授权靶场可用；爬虫/扫描器必须排除）：
curl.exe -s http://127.0.0.1:8095/__reset
```

**基线（scribe 于 2026-10-12T18:48 收尾复核）**：

| 项目 | 实测值 |
|---|---|
| 8095 / 8091 | 均 HTTP 200（2120 / 3234 字节） |
| `lab.db`（`target-site-lab/lab.db`） sha256 | `49b2032c29f8057530704203fd361bb162461eaeeeeb874c7ac1b8e8956cc7af`（49152 字节） |
| `PRAGMA integrity_check` | ok |
| 表行数 | users 4 / orders 3 / messages 1 / sessions 0 / coupon_claims 0；`uploads/` 0 文件 |
| 余额（分） | admin 100000 / demo 50000 / alice 88800 / bob 100 |
| 种子口令 | `admin/Lab@Admin2024!Secure#9`、`demo/demo123`、`alice/alice123`、`bob/bob123`（**明文入库**，属源码标注的教学面） |
| 服务端源码 | `target-site-lab/app.py`（1319 行，sha256 `d2992cd0f4832b9e67baccb04163700d567f57b4ada437e661017d015721b484`） |

---

## 2. ★★ 核心结论：`LAB-MANIFEST.md`（`target-site-lab/LAB-MANIFEST.md`）的"全部已封"与实测不符（本轮再次证伪）

本轮 t4/t5 实测证明：**清单声称已封的类别里，CSRF 一类存在 4 个漏接入口**，且新增 9 条此前未列入清单的缺陷。

| 清单/旧进度声称 | **本轮实测判定** |
|---|---|
| A2/A3「改密/转账无 CSRF → 已封」 | ⚠️ **仅部分成立**：`/wallet/transfer`（`app.py:1104`）与 `/change-password` 有校验；**`/wallet/withdraw`、`/order/create`、`/order/status`、`/coupon/claim` 四个入口完全无校验且不限方法**（VER-02） |
| G4「提现并发竞态 → 已封」 | ✅ 成立（`/wallet/withdraw` 为条件更新，30 并发余额精确停在 600 分不导通） |
| 「业务逻辑类 5 项全封」 | ❌ **不成立**：本轮 business-logic 类命中 9 条（含 1 条 high 的 TOCTOU） |
| H2「`/debug` 配置泄露」 | ✅ 成立且升级为**完整攻击链**（VER-03，`/debug`→SECRET_KEY→CSRF 伪造成立） |
| 「21 条旧洞全封」 | ❌ 与实测不符（本轮 14 条 confirmed、5 条误报） |
| `admin/admin123` 弱口令（10-11 旧结论） | ❌ **已失效**：18:11 `/__reset` 后 admin 为 22 位强口令（源码种子值） |
| SQLi / XSS / IDOR / 命令注入 / SSTI / 路径穿越 / 上传后缀绕过 | ✅ 本轮独立复核**全部阴性**（见 §6） |

---

## 3. 本轮已验证漏洞对照表（16 条判定）

> 判定来自 t5：`_evidence/verified-20261012-184800.json`（sha256 `218dc13d10cb4063e2eb9b85d0b220fa04d33af20499f24025a103dcbf83c020`）＋ 补充件 `_evidence/verified-20261012-184800-SUPPLEMENT-01.md`（sha256 `4f9d8344e257734afd981f0896b6d068e838121660123ce5992d995e1c84f24f`）。
> 笔记路径相对 `security/learning/`。

| 编号 | 判定 | 严重度 | 标题 | 笔记归档路径 | 核心证据文件 |
|---|---|---|---|---|---|
| VER-01 | confirmed | **high** | 并发下单 TOCTOU 把余额扣成负数（≥95%） | `business-logic/VER-01-并发下单TOCTOU把余额扣成负数.md` | `verify-01-race-20261012-1855.json`、`verify-07-atomicity-redirect-scope-20261012-1855.json` |
| VER-02 | confirmed | medium | 业务接口漏接 CSRF 且不限方法（顶级 GET 即改状态） | `business-logic/VER-02-业务接口漏接CSRF校验且不限方法.md` | `verify-02-logic-session-20261012-1855.json` |
| VER-03 | confirmed | **high** | `/debug` 泄露 SECRET_KEY → CSRF 令牌可离线伪造 | `auth-bypass/VER-03-debug泄露SECRET_KEY导致CSRF令牌可伪造.md` | `verify-06-csrf-hmac-proof-20261012-1855.json` |
| VER-04 | confirmed | medium | `/logout` 不销毁服务端会话（假登出） | `auth-bypass/VER-04-登出不销毁服务端会话.md` | `verify-02-logic-session-20261012-1855.json` |
| VER-05 | confirmed | medium | `/forgot` Host 头注入 + `md5(username)` 弱令牌（链未闭合） | `ssrf/VER-05-forgot的Host头注入与md5令牌可预测.md` | `verify-03-injection-ssrf-upload-20261012-1855.json` |
| VER-06 | confirmed | medium | `GET /__reset` 无认证一键删库重建 | `business-logic/VER-06-__reset无认证一键删库重建.md` | `verify-00-baseline-20261012-1855.json` |
| VER-07 | confirmed | medium | `/board` 匿名可写、无频控、无长度上限 | `business-logic/VER-07-board匿名可写且无频控无长度限制.md` | `verify-03-injection-ssrf-upload-20261012-1855.json`、`sqlmap-t5-verify-board.log`、`sqlmap-t5-verify-board2.log` |
| VER-08 | confirmed | low | 上传文件名非法字符/超长/NUL → 500（无落盘） | `file-upload/VER-08-上传文件名非法字符触发500.md` | `verify-03-injection-ssrf-upload-20261012-1855.json`、`verify-04-ssrf-redirect-upload-20261012-1855.json` |
| VER-09 | confirmed | low | `form()` 中 query 覆盖 body（GET/POST 同权） | `business-logic/VER-09-query覆盖body参数来源不受方法限制.md` | `verify-02-logic-session-20261012-1855.json` |
| VER-10 | confirmed | low | 登录态访问 `GET /` 稳定 500（`sqlite3.Row` 无 `.get()`） | `auth-bypass/VER-10-登录态访问首页稳定500.md` | `verify-03-injection-ssrf-upload-20261012-1855.json` |
| VER-11 | confirmed | low | 提现金额超 int64 触发 `OverflowError` → 500 | `business-logic/VER-11-提现金额超int64触发500.md` | `verify-02-logic-session-20261012-1855.json` |
| VER-12 | confirmed | low | `/api/search` 回显 SQL 模板 + LIKE 通配符未转义 | `business-logic/VER-12-api-search回显SQL模板与LIKE通配符未转义.md` | `verify-02-logic-session-20261012-1855.json`、`sqlmap-t5-verify.log` |
| VER-13 | confirmed | low | `GET /logout` 无 CSRF（可强制登出） | `auth-bypass/VER-13-logout无CSRF可被强制登出.md` | `verify-02-logic-session-20261012-1855.json` |
| VER-14 | confirmed-no-impact | info | `/api/order?id=` 类型宽松（`+1/01/1e0/1.0` 等价） | `business-logic/VER-14-api-order类型宽松无越权影响.md` | `verify-02-logic-session-20261012-1855.json` |
| VER-15 | confirmed-no-impact | info | `/debug` 对非 admin 返回 403（端点存在性可探测） | `business-logic/VER-15-debug对非admin返回403暴露端点存在性.md` | `verify-02-logic-session-20261012-1855.json`、`attack-surface-20261012-182250.json` |
| VER-16 | confirmed | low | `POST /upload` 匿名可用（可无限写入 `uploads/`） | `file-upload/VER-08-上传文件名非法字符触发500.md` 文末独立小节「附：VER-16 匿名上传」 | `verify-04-ssrf-redirect-upload-20261012-1855.json` |

**归档说明（重要）**：

- **VER-16 未单独立篇**：任务给定的子目录只有 `file-upload`，而 VER-16（匿名上传）与 VER-08（文件名异常）是**同一入口 `/upload` 的两条缺陷线**，合并写入 `VER-08` 笔记可避免同一端点被拆成两份互相矛盾的描述；VER-16 在 `VER-08` 笔记中**独立成节**（小节标题「附：VER-16 匿名上传」，可按标题检索），并在 `VER-07`（`/board` 匿名无限写入）的纵深防御段作为同族问题交叉引用。**captain 于 2026-10-12 验收时批准维持合并、不拆分**（理由：同一入口同一代码路径、归档理由已在本节写明、VER-16 属 t5 新增而非 hunter 原始 15 条之一）。
- 其余 **13 条 confirmed**（VER-01..VER-13，含 2 条 info 单列）全部一对一归档。

---

## 4. 本轮统计口径与进度

### 4.1 输入→输出账目（与 t5 对齐）

| 口径 | 数量 | 说明 |
|---|---|---|
| t4 输入疑似 | 15 | `findings-hunt-20261012-184144.json` |
| t5 新增发现 | 1 | VER-16（匿名上传） |
| **confirmed（计入漏洞）** | **14** | 含 1 条本轮新增；不含 2 条 no-impact |
| confirmed-no-impact（**不计入漏洞**） | 2 | VER-14、VER-15（标签仅指这两条，与 VER-02 无关） |
| 误报/依据不足 | 5 | FP-01..FP-05，**本文件与笔记均不收录为漏洞** |
| 严重度分布（confirmed 14） | high 2 / medium 5 / low 7 | 另 info 2 属 no-impact |

### 4.2 本轮新增笔记

| 项目 | 值 |
|---|---|
| 新增结构化笔记 | **14 篇**（覆盖 16 条判定中的 15 条；VER-16 并入 VER-08 笔记） |
| 落盘目录分布 | `business-logic/` 9 篇（VER-01/02/06/07/09/11/12/14/15）、`auth-bypass/` 4 篇（VER-03/04/10/13）、`file-upload/` 1 篇（VER-08，含 VER-16）、`ssrf/` 1 篇（VER-05） |
| 模板 | 与 `VULN-03-SECRET_KEY泄露导致CSRF令牌可伪造.md` 对齐，七节结构（概述等级/原理/可复现 payload/复现步骤与证据/修复方案/参考链接/学习要点） |
| 写作口径 | 只写已验证结论；每篇均引用 `_evidence/` 下原始证据文件（含 sha256）；误报（FP-01..05）**零收录** |

### 4.3 旧 25 项判定对照表（10-11 历史基线，**结论已部分失效，保留存档**）

> 保留原表结构以便对照；「本轮复测」列是本轮实测后的修正。

| 漏洞类型 | 目标数 | 已实测判定 | 真漏洞（10-11） | 掌握度 | 本轮复测 |
|---|---|---|---|---|---|
| SQL 注入 | 2 | 2 | 0 | 认出参数化防线 ✅ | ✅ 仍阴性（sqlmap 独立复打三入口） |
| XSS（反射/存储） | 2 | 2 | 0 | 认出 `html.escape` ✅ | ✅ 仍阴性 |
| 越权 IDOR/垂直 | 3 | 3 | 0 | 认出属主校验 ✅ | ✅ 仍阴性（跨用户统一 404/302） |
| 文件上传 | 1 | 1 | 0 | 认出后缀+MIME 双校验 ✅ | ⚠️ 后缀/MIME 确实到位，但**新增文件名维度缺陷**（VER-08/16） |
| SSTI | 1 | 1 | 0 | 认出 eval 移除 ✅ | ✅ 仍阴性 |
| 命令注入 | 1 | 1 | 0 | 认出 `shell=False` ✅ | ✅ 仍阴性 |
| SSRF | 1 | 1 | 0 | 认出协议/主机/端口三重校验 ✅ | ✅ 仍阴性（33 组绕过全 403） |
| 路径穿越 | 1 | 1 | 0 | 认出 realpath 白名单 ✅ | ✅ 仍阴性 |
| 业务逻辑 | 5 | 5 | 0 | 认出幂等/边界/状态机 ✅ | ❌ **大幅修正**：本轮 9 条缺陷，含 1 条 high（VER-01） |
| 认证与会话 | 2 | 2 | 1（弱口令） | ✅ | ❌ 弱口令已随 `/__reset` 失效；新增会话类 3 条（VER-04/10/13） |
| 信息泄露 | 3 | 3 | 1（`/debug`） | ✅ | ✅ 升级为攻击链（VER-03）＋新增 2 条（VER-12/15） |
| CSRF / 密钥推导 | 2 | 2 | 1（攻击链） | ★ 本轮最大收获 | ⚠️ **修正**：CSRF 防线有 4 个漏接入口（VER-02）；攻击链作用域限定为"已知会话 token" |
| Host 头注入 | 1 | 1 | 1 | ✅ | ✅ 成立，危害限定为钓鱼/劫持（链未闭合，VER-05） |

**旧表合计**：25 项判定 → 真漏洞 4 条＋1 条完整攻击链＋1 条可用性 BUG。
**本轮合计**：15 项输入 → **confirmed 14 条（high 2 / medium 5 / low 7）＋ no-impact 2 条＋ 误报 5 条**；其中 9 条为 10-11 清单未收录的新缺陷。

### 4.4 方法论口径修正（本轮强制）

| 项 | 旧口径 | 本轮修正口径 |
|---|---|---|
| VER-01 复现率 | "3/3 必现" | **≥95%（30 并发 3/3 轮出负余额 + 1 轮 26/30 未触发）**，禁止写 100% |
| VER-01 对照组 | "唯独下单缺失"（单点举例） | **五处资金写点枚举**：四处原子（withdraw / transfer×2 / coupon 加款），唯一非原子为 `/order/create`（`app.py:955`） |
| VER-01 危害口径 | 57000 分/A -3200~-7000 混用 | 统一为 **57000 分 = 透支额 7000 ＋ 超额售出订单额 50000**（本文件与笔记统一取此口径） |
| VER-03 作用域 | 未声明 | **需已知目标会话 token**；跨会话复用实测 403（token 严格绑定会话） |
| VER-11 机制 | "`1e23` → 500" | **`1e23` → 400**（`ValueError` → `amount=0`）；`2^63` → 500（`OverflowError`），两类分开写 |
| VER-02 CSRF | "SameSite=Lax 不拦 CSRF" | 限定为**顶级 GET 导航**成立；跨站 POST 不带 Cookie |
| VER-05 危害 | 隐含"任意改密" | 只按 **Host 注入 + 弱 token** 计；`/reset` 消费端 404，链未闭合 |
| VER-14/15 标签 | "行为确认但无实际影响" | 该标签**仅指这两条**，与 VER-02（有实际影响）不冲突 |

---

## 5. 阴性复核（本轮独立重打，结论：封堵有效）

| 编号 | 领域 | 方式 | 结论 |
|---|---|---|---|
| N-01 | SQL 注入 | sqlmap（level2/risk1，BEUSTQ）打 8095 `/api/search?q`、`/login(username)`、`/board(content)` | 三处全阴性（`does not seem to be injectable`） |
| N-02 | IDOR/越权 | alice 读 bob 的 `/api/profile`、demo 的 `/api/order`；跨用户 `/order/status`；非 admin 访问 `/admin/*` | 全部 404/302，属主校验有效 |
| N-03 | XSS | `/forgot`、`/board` 输入 `<script>`、`<img onerror>` | 输出以 `&lt;` 转义，无原始标签反射 |
| N-04 | 路径穿越 | `/download?file=..%2fapp.py`、`../private/config.bak`、空值 | 403/404；`downloads/readme.txt`（靶场内置文件，位于 `target-site-lab/downloads/readme.txt`，**非** `_evidence/` 产物）正常 200 |
| N-05 | 上传后缀/MIME | `fake.jpg`（非 JPEG 魔数） | 400「文件内容与扩展名不匹配」 |
| N-06 | SSRF 越界 | integer/hex IP、`localhost`、`[::1]`、`userinfo@`、非白名单端口、`file://`、`gopher://`、33 组绕过 | 全部 403；仅白名单端口（本机 8091/8095）可达，属设计内 |
| N-07 | 令牌可预测性 | 5 个会话 token 样本 | `secrets.token_urlsafe(32)`，43 字符，无规律可推 |
| N-08 | 未授权状态变更 | 匿名 `GET /order/create`、`/wallet/withdraw` | 302 → `/?err=login`，无数据变更 |

> 阴性项的原始证据集中在 `verify-03-injection-ssrf-upload-20261012-1855.json` 与 `sqlmap-t5-verify*.log`；`/fetch` 33 组绕过与令牌熵的原始包在 `findings-hunt-20261012-184144.json` 与 `verify-07-atomicity-redirect-scope-20261012-1855.json`。

## 6. 误报与不成立（**不收录为漏洞**）

| 编号 | 内容 | 判为误报的依据 |
|---|---|---|
| FP-01 | "`amount=1e23` → 500" | 实测 400（`int('1e23')` 抛 `ValueError` → `amount=0` → 金额无效分支），非异常面 |
| FP-02 | "`/redirect` 开放重定向" | 该路径不存在，`GET /redirect` 与 `/redirect?to=` 均 404，源码无对应路由 |
| FP-03 | "`/fetch` 跟随重定向可读 admin `/debug`" | 出站请求不转发 Cookie（匿名身份必 302）；`/fetch` 只跟随绝对 Location，枚举全部 24 条路由后**绝对 Location 产生点为 0**（属枚举结论、时间相关；源码 `app.py:783-800` 对 30x 最终落点无二次校验，残余面如实记录） |
| FP-04 | "admin 弱口令 + 8095 明文口令" | 18:11 `/__reset` 后 admin 为 22 位强口令；明文入库属源码标注的教学面，非本期可报告漏洞 |
| FP-05 | "`/uploads/<name>` 结果页反射 XSS" | 文件名经 `urllib.parse.quote` 后插入 href、显示文本 `html.escape`；含 `<>`/引号的文件名被 400 拒绝或触发 500，未见原始标签反射 |

---

## 7. 证据索引（`security/learning/_evidence/`，本轮相关）

| 文件 | 内容 | sha256 |
|---|---|---|
| `baseline-20261012-181212.json` | 阶段1 基线快照 | `3d87f170acf57b9eb7374935463afb9b8c66dc23e5ec8092550032f6397d12bb` |
| `attack-surface-20261012-182250.json` / `.md` | 阶段2 攻击面地图（42 条路由） | `154b62ac…d8b91f` / `2f8cefd6…7f366d` |
| `findings-hunt-20261012-184144.json` | 阶段3 疑似清单（15 条） | — （见 `-index.md`） |
| `verified-20261012-184800.json` | 阶段4 验证报告（16 条判定） | `218dc13d10cb4063e2eb9b85d0b220fa04d33af20499f24025a103dcbf83c020` |
| `verified-20261012-184800.md` | 同上（可读版） | `b94cbc96f8637ac4af758c8b669f35de26395812131e910e3b588cca1f9d713d` |
| `verified-20261012-184800-SUPPLEMENT-01.md` | 补充核验（复现率/作用域/写点枚举修正） | `4f9d8344e257734afd981f0896b6d068e838121660123ce5992d995e1c84f24f` |
| `verify-00-baseline-20261012-1855.json` | 基线 | `c9aa99a4ea131a9840b9349c832357929466ffeeb23a40047fac94a6542ec818` |
| `verify-01-race-20261012-1855.json` | 并发下单 TOCTOU | `6169f0fe2a960c2bbe1dc3080948837805fcfe36b7f5b7042dbc1bcebd382793` |
| `verify-02-logic-session-20261012-1855.json` | 业务逻辑与会话 | `1b7b154509e9a95157fbd67b78a22289798a0d0383af802c48f8007a5a74cd5c` |
| `verify-03-injection-ssrf-upload-20261012-1855.json` | 注入/SSRF/上传复核 | `d168699eede0933b74257f3080e4677db22e511859d25c0fa376b3de7a086fd2` |
| `verify-04-ssrf-redirect-upload-20261012-1855.json` | SSRF 重定向与上传面 | `2efd7e6d8c30479da62d39f4354040d4b510e0a345be207c1c50156b3af6f5d2` |
| `verify-05-ssrf-chain-20261012-1855.json` | SSRF 链验证 | `d3ea2949199e7a5701fc54e167e4ee9172eeb2daaf525b85144486c258f54121` |
| `verify-06-csrf-hmac-proof-20261012-1855.json` | CSRF HMAC 伪造证明 | `11b0aabd9629d21c2d0e6fefbf9fbfd27ae35d5cd6bc975764df9d27cb8fd962` |
| `verify-07-atomicity-redirect-scope-20261012-1855.json` | 写点枚举与令牌作用域 | `58cd70138de1cc2662d9dcd878be3079ddf7b41d61b51bb3ff0de2a479a7ee84` |
| `sqlmap-t5-verify.log` | 注入阴性（三入口） | `6610e12565cdad10f94dff92a577d8c1a74ff8d9642a48e5d76f137d9a7ff24f` |
| `sqlmap-t5-verify-board.log` / `-board2.log` | `/board` 写入放大实测 | `7c5fb44c…180b7f` / `431bee02…e9f73` |

**可复跑脚本**：`verify_lib.py`（verifier 自写取证库）与 `verify-step0-baseline.py` … `verify-step7-atomicity.py`（逐阶段可独立执行）。

---

## 8. 纪律与教训（本窗口）

1. **写端点先判副作用**：用 sqlmap 打 `POST /board` 时，布尔盲注测试约 2 秒写入 555 行、累计 1454 行匿名 payload —— 工具本身在污染数据。**打类前先判断参数是否作用于写端点**，本次已 `job_kill` 并 `/__reset` 清除。
2. **爬虫必须排除 `/__reset`**：katana 自动访问 `/__reset`（18:15:19）触发一次删库重建；该端点无认证、无确认，任何爬虫/扫描器都会撞上。
3. **响应自报值不可信**：TOCTOU 轮次里响应体自报余额（17700/19600/25300）与库内真实余额（-7000/-3200/-7000）不一致，**必须直查数据库**。
4. **异常机制不能混写**：`int()` 解析失败（400）与 DB 绑定溢出（500）是两条路径，混写会产生错误结论（FP-01 即由此产生）。
5. **"行为确认"≠"误报"**：VER-14/15 经实测确认了行为，只是无可利用后果；笔记中必须与误报区分，避免下游把 info 项当漏洞汇总。
6. **证据链要含服务端状态**：会话类（VER-04/13）必须给 `sessions` 表状态；资金类（VER-01）必须给库内前后值与可支付上限对照（26 单 vs 30 单）。

---

## 9. 下一步学习推荐

1. **补闭链条**：VER-05 的 `/reset` 消费端缺失——补实现后重测"Host 注入 + 弱令牌 → 任意改密"是否闭合（当前只能按钓鱼计）。
2. **令牌改造后复测**：VER-03 的修复方案（随机令牌存服务端）落地后，应能观察到"页面 token 无法由 `HMAC(SECRET_KEY, session_token)` 复现"，作为修复验证用例。
3. **并发区间穷举**：VER-01 只测了 30 并发。建议补 10/50/100 并发 × 3 轮，给出成功率区间与置信表述（保持"≥95%"而非 100%）。
4. **`/fetch` 残余面**：补充件指出 `/fetch` 对 30x 最终落点无二次校验。可在靶场新增一个产生绝对 Location 的端点后重测，验证该残余面是否可升级为 SSRF 绕过。
5. **8091（target-site v2）横向复测**：本轮 8091 仅做只读连通核对。建议把 VER-01/02/03/04 四条在本机复测，练"同一缺陷在不同防护强度下的存活判定"。
6. **迁移新品类**：DVWA / bWAPP（Kali `dc1` 内）已就绪，可补文件包含、CSRF 实战、弱会话等品类，并沿用本轮的"判定对照表 + 证据文件 + 笔记三件套"流程。

---

## 10. 未决问题

1. **VER-16 归档粒度**：本文件按"同一入口合并写"处理（并入 VER-08/VER-07），若 captain 要求一对一，需拆分归档。
2. **VER-05 改密链**：`/reset` 消费端是否存在于隐藏路由仍未查明（24 条路由枚举 + 源码全文均无）。
3. **VER-01 复现率**：仅覆盖 Windows + SQLite 默认配置；换 Linux/WAL 模式后的表现未测。
4. **`/fetch` 枚举结论的时间相关性**：新增绝对 Location 产生点即失效，需在靶场演进后重测。
5. **8091 基线清理**：8091 无一键复位接口，`sessions`/`login_attempts` 会持续累积（非破坏性），是否需要补 `/__reset` 待 captain 决定。

---

## 11. 循环记录（Loop 1 · 2026-10-12 18:11–19:01）

> 维护：mentor（阶段6 归档，t8）。统计口径**沿用 §4.1/§4.2 既有表结构**（输入→输出账目、严重度分布、笔记落盘分布），未另起口径。
> 追加修订：scribe 于 **2026-10-12 19:07** 受 mentor 授权，仅做**引用写法规范化**（不改数字与结论）——§11.2 时序表 4 处省略号缩写展开为全名、§11.3 与 §11.4 的裸靶场文件引用补标为 `target-site-lab/downloads/readme.txt`、§11.4 补记复跑复核结果（`missing 0`）；§11 其余内容未动。
> 全部数字来自文件证据：`_evidence/t8-stats-20261012.py`（本段生成脚本）+ `_evidence/verified-20261012-184800.json` + 各阶段产物 mtime。**未从任务汇报文字里取数**。

### 11.1 本轮账目（与 §4.1 对齐，不含旧 25 项历史基线）

| 口径 | 数量 | 来源 |
|---|---|---|
| t4 输入疑似 | 15 | `findings-hunt-20261012-184144.json` |
| t5 新增发现 | 1 | `verified-…json` → `summary.new_findings` |
| **confirmed（计入漏洞）** | **14** | 同文件 `confirmed_findings` 中 `verdict=confirmed` 计数 |
| confirmed-no-impact（不计入） | 2 | `verdict=confirmed-no-impact`（VER-14/15） |
| 误报/依据不足 | 5 | `false_positives` 数组（FP-01..FP-05） |
| 阴性独立复核 | 8 | `negatives_verified` 数组长度 |
| 严重度分布（confirmed 14） | high 2 / medium 5 / low 7 | 逐条 `severity` 计数；另 info 2 属 no-impact |
| 新增结构化笔记 | **14 篇**（覆盖 15/16 条判定） | 目录扫描：`business-logic/` 9、`auth-bypass/` 4、`file-upload/` 1、`ssrf/` 1 |
| 覆盖漏洞类型数（本轮实测触达） | **11 类** | §3 表：业务逻辑/CSRF/会话/信息泄露/上传/SSRF-Host/Host 头/弱令牌/并发原子性/DoS-可用性/端点存在性 |
| 证据文件 | `_evidence/` 下本轮新增 96 个（含脚本与原始包） | `t8-stats-20261012.json` |

**confirmed/误报比**：14 / 5 = **2.8 : 1**（若把 2 条 no-impact 计入分母侧"不成立"则为 14 : 7 = 2 : 1）。旧 25 项历史基线的真漏洞率为 4/25 = 16%；本轮 14/20（输入 15 + 新增 1）= **70%**。

### 11.2 阶段耗时分布（各阶段起止，取各阶段产物文件 mtime）

| 阶段 | 起 | 止 | 时长 | 产物数 |
|---|---|---|---|---|
| 阶段1 靶场管理 | 18:11:18（首条 `/__reset` 生效） | 18:14:35（`recon-httpx-20261012-181433.txt`） | ≈3.3 min | 基线快照 + 日志 3 件 |
| 阶段2 侦察 | 18:14:29（`recon-httpx-20261012-181429.txt`） | 18:26:16（`attack-surface-20261012-182250-SUPPLEMENT-01-head-reset.md`） | ≈11.8 min | 14 件 |
| 阶段3 挖掘 | 18:25:08（`hunt-a-bizlogic.py`） | 18:41:24（`findings-hunt-…184124.json`） | ≈16.3 min | 18 件 |
| 阶段4 验证 | 18:42:45（`verify-lib.py`） | 18:49:45（`verified-20261012-184800-SUPPLEMENT-01.md`） | ≈7 min | 24 件 |
| 阶段5 笔记 | 18:50:05（`VER-06-__reset无认证一键删库重建.md`） | 18:53:33（`VER-04-登出不销毁服务端会话.md`） | ≈3.5 min | 15 篇 |
| 阶段6 归档 | 19:01 起 | 本段落盘 | 本轮归档 | 本段 + `next-round-plan.md` |

> 注：阶段2 与阶段3 有 ≈1.2 min 重叠（挖掘脚本在侦察补充件落盘前已启动），属并行产线，不是时序错误。

### 11.3 工具命中率（哪个工具真出活）

| 工具 | 投入 | 产出 | 命中率 | 结论 |
|---|---|---|---|---|
| **自写 Python 取证脚本**（`recon-10..13`、`hunt-a..f`、`verify-step0..7` + `verify_lib.py`） | 约 30 个脚本 | **全部 14 条 confirmed** | **100%（唯一出活路径）** | 本轮的"主武器"；带会话、带库直查、可复跑 |
| 源码审读（`app.py` 行号定位：949/955/1076/1130） | 人工 | VER-01 根因、VER-02 四入口、VER-03 HMAC | 高 | 竞态与 CSRF 类缺陷**只能**靠源码定位，扫描器无法给出 |
| sqlmap | 6 端点（level2/risk1，BEUSTQ） | 全阴性；**副作用：往 `/board` 写入 1454 行** | **0%** | 阴性结论有价值（SQLi 确已封堵）；但也证明"真出活不靠它" |
| nuclei v3.11.1（medium,high,critical） | 32,044 请求 | **0 命中** | **0%** | 对单文件自研靶场模板不匹配；`recon` 已建议不再跑全模板 |
| ffuf | 两站各约 200 条字典 | 仅已知文件（`target-site-lab/downloads/readme.txt` 等，靶场内置、非 `_evidence/` 产物） | ≈0% | 字典尺寸不足 + 404 页仅 1095 字节，需换判据而非换工具 |
| katana（爬虫） | `-d 3` | **触发一次 `/__reset` 删库重建** | 负命中 | 必须配路径排除 + 禁 HEAD，见 §8.2 |
| httpx | 两站 | 指纹（`LabHTTP/0.2`、`TargetSite/1.0`） | 低（有信息量） | 仅用于基线核对 |

**结论**：本轮 0 条漏洞由现成扫描器产出，**14/14 来自"手写脚本 + 源码审读"**。工具在本轮的正确用途是**阴性复核与基线核对**，不是发现路径。

### 11.4 归档完整性核查（阶段6 归档项）

| 检查项 | 结果 |
|---|---|
| 笔记就位 | 15 篇（14 新增 + 旧 VULN-03）：`business-logic/` 9、`auth-bypass/` 4、`file-upload/` 1、`ssrf/` 1 |
| 命名规范一致 | 全部 `<VER-id>-<中文标题>.md`；旧篇为 `VULN-03-…`，两套前缀并存（见 11.5 待办 1） |
| 空目录 | `xss/`、`sql-injection/`、`idor/`、`path-traversal/`、`ssti/`、`command-injection/` 六类**仍为空**——本轮这些类别独立复核全部阴性（SQLi/XSS/IDOR/穿越/SSTI/命令注入），空目录是"阴性"的正确表达，但**需要在 §5 之外显式说明**，避免下轮误读为"漏归档" |
| 证据引用可解析 | 由 t6 报告：60 条引用全部解析到实际文件（0 缺失）。**归档复跑核查**（`security/learning/_evidence/t8-archive-check-20261012.py` → `t8-archive-check-20261012.json`，改写前基线 `total 36 / missing 4`）：4 条未解析引用**已全部处置** —— 3 条是 §3 表的省略号写法（`verify-02-...json`→`verify-02-logic-session-20261012-1855.json`、`verify-03-...json`→`verify-03-injection-ssrf-upload-20261012-1855.json`、`verify-04-...json`→`verify-04-ssrf-redirect-upload-20261012-1855.json`），**已由 scribe 于 2026-10-12 19:06 改写为全名**；1 条是 `target-site-lab/downloads/readme.txt`（靶场内置文件，**非** `_evidence/` 产物，随 `/__reset` 重建），**已由 scribe 补标所在目录**。**复跑复核**（`security/learning/_evidence/t8-archive-recheck-1930.py` → `t8-archive-recheck-1930.json`，跑于 19:07:01，被扫版本 `progress.md` sha256 `963baba6e04c874b`）：**total 34 / missing 0 / missing_list 为空**。注意：本表与 §3 说明中的 `旧写法→新写法` 属**映射登记文本**，本身含省略号，朴素正则扫描会误报，勿据此判缺失。 |
| 基线收尾 | `lab.db` sha256 = `49b2032c…6cc7af`（= t1 基线）、`integrity_check=ok`、`uploads/` 空；8091/8095 均 HTTP 200（t5/t6 双次确认） |

### 11.5 本轮方法论教训（哪些打法无效 / 哪些有效）

**有效（下轮保留）**
1. **源码先行**：竞态（`app.py:949-955` 读校验+无条件扣款）、CSRF 漏接四入口、HMAC 派生令牌，全部靠**读源码定位行号 → 再设计验证**。扫描器对这三类**结构性缺陷**天然无感。
2. **库内前后值差分**：VER-01 的决定性证据不是 HTTP 200，而是「开账 50000 → 库内 -7000」＋「响应自报余额 25300/19600/17700 互不一致」。**响应自报值不可信，必须直查数据库**（§8.3）。
3. **全量枚举替代单点举例**：verifier 自我更正后把"唯独 `/order/create` 缺失"从**举例**升级为**五处写点枚举**（4 处条件更新 + 1 处非原子），结论强度显著提升。
4. **判定纪律的三层分离**：confirmed / confirmed-no-impact / false-positive 三分，且 no-impact 不计入漏洞数——本轮 5 条误报**零收录**，避免了污染统计。
5. **阴性也要留证**：8 项独立阴性复核（sqlmap + 33 组 SSRF 绕过 + 39 组 XSS）让「已封堵」从声称变成证据，这是下轮"复打测绕过"的对照基线。

**无效（下轮避免）**
1. **全模板扫描**：nuclei 32,044 请求 0 命中、ffuf 200 字典 0 新增——**在自研小靶场上，扫描器投入产出比为 0**；时间应转投源码审读与手写探针。
2. **对写端点打指纹类工具**：sqlmap 布尔盲注在 `/board` 2 秒写入 1454 行；katana 自动访问 `/__reset` 直接删库。**"只读工具"不存在——先判副作用再落工具**（已成为硬纪律）。
3. **文档驱动测试**：`LAB-MANIFEST.md` 的"21 条旧洞全封"与本轮实测（9 条未收录缺陷 + CSRF 4 入口漏接）偏差巨大；**清单只能当线索，运行时实测才是事实源**。
4. **状态码当结论**：`/coupon/claim` 由 500 恢复 200 曾差点被当成"竞态已修复"；状态码恢复只能推可用性。
5. **单轮/单并发度定复现率**：VER-01 一轮 30 并发出现 26/30 未触发 → 复现率必须写成「≥95%」并附失败轮次，**禁止 100%**。

### 11.6 循环记录·循环决策

下一轮方案（三选一，附练习题与预期收获）与推荐排序见独立产物 **`security/learning/next-round-plan.md`**（阶段6 产物）。

| 排序 | 方案 | 主要练习 | 预期收获 |
|---|---|---|---|
| **1（推荐）** | 加固后复打 8095 · 测绕过 | 按本轮 14 条 confirmed 逐条加固（源码级）→ 复测；重点测 CSRF 四入口、TOCTOU 条件更新、令牌随机化 | 练「修复验证 + 绕过对抗」，产出修复验证用例；把"识别防线"升级为"对抗防线" |
| 2 | 换靶场：Kali VM 的 DVWA / bWAPP（零下载） | 文件包含、XXE、弱会话、真实 CSRF token 约束 | 补齐本轮全阴性的 6 个空目录类别；接触带真实约束的应用 |
| 3 | 换靶场：Vulhub 首批 2 环境（shiro + tomcat） | 反序列化、PUT 上传 RCE、已知 CVE 复现 | 唯一能产出"可提交 CVE 报告"的路径；成本最高（拉取 ≈12–25 min） |

**依赖与前置**（t2-vulhub 结论对齐）：Docker 可用、mirror 链路已实测、`vulhub/shiro:1.2.4` 镜像已就位；**Docker 数据盘迁移待 captain 亲自执行**；RCE 类验证已获分层授权（只绑 127.0.0.1 / 不挂宿主目录 / 测完 `docker rm -f`）；Docker Desktop「用完即关」的触发条件为本轮 A/B/C 三档跑完。方案 3 的可执行性**取决于 captain 完成数据盘迁移**，故排第 3。

### 11.7 循环记录·待办（进 §10 未决问题）

1. 两套笔记前缀（`VER-*` 与 `VULN-*`）并存，是否统一编号体系待 captain 决定（本轮不改写已锁定产物）。
2. 六个空目录（xss/sql-injection/idor/path-traversal/ssti/command-injection）需在 §5 显式标注"本轮阴性"；本轮归档只做说明，不改 §5 表。
3. `progress.md` 由 scribe 与 mentor 双写（本轮新增 §11），后续并行修改前需先报 captain 协调。
4. **Loop 3 B 档（DVWA/bWAPP）账目见本文件 §12**（由 hunter-web 于 2026-10-12 22:25 追加，承接任务书写明的"回写 §11"要求；§11 为 Loop 1 记录，未改写其任何数字与结论）。
5. **Loop 3 C 档（Vulhub）账目见本文件 §13**（由 hunter-web 于 2026-10-12 23:45 追加）。**Loop 3 三档汇总见本文件 §11.8**（mentor-final 于 2026-10-13 00:12 追加）。

### 11.8 循环记录（Loop 3 · 2026-10-12 19:57 → 2026-10-13 00:10 · t9 / mentor-final 汇总）

> 维护：mentor-final（t9，attempt `21343f7c-c0ef-4549-ab16-8dd471a5bfa5`）。
> **取数铁律**：全部数字取自产物文件（笔记 / 报告 / 证据 JSON / 目录扫描 / cost-meter 落盘文件），
> **未从任务汇报文字取数**。取数脚本 `security/learning/_evidence/loop3-t9-summary.py`
> → 输出 `security/learning/_evidence/loop3-t9-summary-20261012.json`。
> **横向对比表全文**：`security/learning/loop3-trilateral-comparison-20261012.md`（第 2 版，含第 1 版勘误段）。
> **章节归属**：本节由 mentor 维护；§1–§10 归 scribe（本次**一字未动**）、§12/§13 为 hunter-web 所写（**未删改**）。

#### 11.8.1 三档时间线（取产物文件 mtime，非人工估）

| 档位 | 起 | 止 | 产物落盘跨度 | 纯作业窗口 | 产物数 |
|---|---|---|---|---|---|
| **A** 加固复核 | 19:57:51 | 21:29:09 | ≈91 min | 21:08 → 21:29（≈21 min） | 5 件（报告 + 2 笔记 + 1 证据 JSON + 1 实施报告） |
| **B** DVWA/bWAPP | 21:21:22 | 23:47:47 | ≈146 min（含 VM 前置 + 覆盖声明） | 21:51 → 22:13（≈22 min） | 12 件 |
| **C** Vulhub CVE | 23:01:49 | 23:49:46 | ≈48 min | 23:01 → 23:45（≈44 min） | 11 件 |

> 注：落盘跨度**不等于纯工时**——B 档跨 146 分钟是因为夹了 t5 归档与覆盖声明补写。括号内纯作业窗口才是干活时间。

#### 11.8.2 三档账目（confirmed / 残余 / 阴性 / 误报）

| 口径 | **A 档** | **B 档** | **C 档** |
|---|---|---|---|
| confirmed（结论成立） | **12**（P1–P12）¹ | **5**（B1–B5） | **2**（C1、C2） |
| 其中**新挖出的漏洞面** | **0**（产出的是加固有效性判定 + 残余面） | **5** | **2**，但**均为已公开 CVE 复现，非发现型** |
| 残余 / 需处理 | **6 条残余面**：成功 5（D1 / B1·C6 两个入口 / B2 / B3 / C3）+ C3 仅 orig 成立；**需处理 3**（D1、B1/C6、B3）+ 可接受 1（B2）+ 无需处理 1（C3） | 0 | 0 |
| 误报（零收录） | **0** | **0** | **0** |
| 阴性留证 | **14**（N1–N14） | **6**（N-B01…N-B06） | **6**（N-C01…N-C06） |
| 被推翻的错误判据 | 0 | 0 | **2**（`deleteMe` 无区分度、`sleep` 计时无区分度），原始证据**保留未删改** |
| 严重度分布 | 残余面**中危** | **High 3**（B1/B4/B5）／**Medium 2**（B2 未升级、B3） | **Critical 2**（均未认证 RCE）² |
| 本轮新增笔记 | **2 篇**（`hardening/` HARD-01、HARD-02） | **8 篇**（5 主 + 2 N-* + 1 覆盖声明）³ | **3 篇**（`cve/` C1、C2、N-C01） |
| 复现率（区间，禁 100%） | A1 负余额 **≥95%（6/6 轮，失败 0）** | 各项 **≥95%（3/3 或 5/5）**；B3 浏览器形态 **≥66%（2/3）** | CC6 **≥95%（5/5）**；四链横向 **≥66%（3/4）**；C2 **≥95%（3/3）** |

¹ A 档 P1–P12 **不等于 12 个漏洞**：P1/P4/P5/P6/P7/P12 描述**原版可被攻破**，P2/P3/P11 描述**加固版挡住**，P8/P9/P10 描述**加固后仍成立的残余绕过**。**不得按漏洞数入账。**（源：`security/learning/hardening/A-档验证报告-20261012.md` §5.1）
² Critical 只对"未认证即 RCE"这个事实成立，**不代表可提交赏金**——C 档两条 CVE 均已公开、已分配编号、已有修复。
³ 含 1 篇覆盖声明（`security/learning/N-LOOP3-B-COVERAGE-B档分类覆盖声明.md`），不是漏洞笔记、无危害等级，**计入篇数不计入漏洞数**。

#### 11.8.3 成本双口径（两个口径都要给，各自含义必须写明）

**口径 A —— 余额差值（严重低估，不可单独作结论）**
取数时刻 2026-10-13 00:10，来源 `~/.dsh/storages/cost-meter/ledger.json`
（该文件 sha256 `ADED1FCC23DBABCBBEAADB213D480D26811FD1E7BA89F7FB817A2B4D56FC9268`）：
`balanceRef.total = 3.80638416 CNY`，`balanceRef.ledgerCost = 0`，`balanceRef.date = 2026-10-13`，
`balanceRef.at = 2026-10-12 21:34:03`（epoch 1791820984398）。

**局限（必须一起读）**：① 本轮成员全跑在**免费车道**（`buddy` / `our-free-model/space-bunny-free` / `workbuddy`），**不扣余额** → 严重低估；② `balanceRef.at` 是 **21:34:03 快照**，**早于本轮 B 档（21:51 起）与 C 档（23:01–23:45）全部作业**；③ `date` 已翻到 2026-10-13 且 `granted=0`，说明**期间无新充值**，跨天余额**不可直接相减**。
→ **口径 A 当前的实际意义只剩：队长自身协调消耗的粗略下界。**

**口径 B —— 调用量（团队总消耗以此为准）**
来源同上文件的 `days['2026-10-12']`（取数时刻 2026-10-13 00:10）：

| provider:model | calls | input | output | cacheRead | 名义 cost (CNY) | 是否扣余额 |
|---|---|---|---|---|---|---|
| `workbuddy:deepseek-v4.1-flash` | 753 | 2,506,997 | 884,072 | 197,428,992 | 1.4988 | ❌ 免费，不扣 |
| `deepseek-account:deepseek-flash` | 749 | 937,440 | 647,908 | 134,081,792 | 1.0940 | ✅ 真付费，但全在 18:10–18:48 **旧会话** |
| `buddy:deepseek-v4.1-flash` | 665 | 2,097,421 | 762,239 | 198,006,912 | 1.4441 | ❌ 免费，不扣 |
| `our-free-model:space-bunny-free` | 475 | 2,291,387 | 291,111 | 49,473,803 | 0.0000 | ❌ 免费，账本记 0 |
| `deepseek-official:deepseek-v4-flash` | 9 | 73,279 | 7,638 | 3,840 | 0.0237 | 小额 |
| **合计** | **2651** | **7,906,524** | **2,592,968** | **579,395,547** | **4.0605** | — |

> **数字随时点漂移，引用必须带取数时刻**：队长 23:47 快照 2555 / 3.9052 → t9 第 1 版 23:52 为 2645 / 4.0396 → 本版 00:10 为 **2651 / 4.0605**。
> 三个免费车道名义合计 **2.9429 CNY 实际未从余额扣除**；真正扣余额的只有 `deepseek-account` 1.0940（**属旧会话**）+ `deepseek-official` 0.0237。

**⚠️ 按档归属只是近似，不得当精确消耗读**
按**会话起始时间**切窗得：A 档 515 calls / 名义 0.1302 CNY，B 档 398 calls / 0.7128 CNY，C 档 27 calls / 0.0591 CNY。
**但 ledger 的 `sessions` 没有"成员↔会话"映射** —— 例如 hunter-web 的 C 档主会话起始于 21:51，会被**整条**算进 B 窗口。**团队总消耗以本节全天 provider 拆分为准。**

**免费车道可靠性（供 loop4 路由决策）**：`space-bunny-free` 490 calls / 5 failed（≈1.0%，✅ 稳定）；
`mimo-v2.6-flash-free` 3/2（样本极小）；`deepseek-ai/deepseek-v4.1-flash`（EAC）4/4 = **100% 失败，已放弃**。
`workbuddy` 今日 761 请求被打爆、**限流至 2026-10-13 18:01:36**（`~/.dsh/channel-pack/state.json`）→ **loop4 严禁再把主力 hunter 放回 workbuddy**；
开工前必读 `~/.dsh/our-free-model/availability.json`，**严禁落到 `deepseek-account`**（真付费，已出白名单）。

#### 11.8.4 方法论教训（引用并展开：**三条判据类教训必须写进 Loop 3 记录**）

**★★★ 三条判据类教训（并列成条 · 原文完整在 `memory/context.md` §11 顶部 `[2026-10-12 23:52]` 条目，此处引用并展开，不重复全文。三条地位并列，无主次。）**

##### 判据类教训 ① —— Shiro 假 oracle：`rememberMe=deleteMe` 不能判反序列化成败

实测矩阵：不带 cookie → 无 Set-Cookie；`rememberMe=`（空值）→ false；4 字符垃圾 → **true**；4000 字符垃圾 → **true**；
   默认密钥加密的合法序列化流 → **true**；错误密钥同一流 → **true**；`/login`（anon 路径）→ **true**。
   → **只要 cookie 非空，无论内容与路径一律回 `deleteMe`，零区分度。**
   后果：`t7-c1-bruteforce-out.txt` 中"25 个候选密钥全部 deleteMe=true → 全部解密失败"的结论**判定依据无效、结论作废**（原文件保留不改，标注为"oracle 失效导致的无效结论"）。**C1 本身不作废**（靠 OOB + `/proc` 独立实证成功）。
   *本档展开*：这直接导致 C 档多烧一轮 —— 若不做 `security/learning/_evidence/loop3-t7-c1-matrix-20261012.json` 这个区分度矩阵，"deleteMe 恒真"这件事根本不会被发现。

##### 判据类教训 ② —— `Runtime.exec()` 异步：`sleep N` 计时不能判 RCE

   JVM 不等子进程就返回 → 用响应耗时差判 RCE 必得假阴性。铁证 `security/learning/_evidence/loop3-t7-c1-timing-20261012.json`：
   三条**都 RCE 成功**的链被文件自判 `executed:false` —— CB1 delta **−0.002s** / CC5 **+0.008s** / CC6 **−0.003s**。
   **成功链被自己的文件判成"未执行"**，hunter-web 据此一度误判 C1 失败，后靠 OOB + `/proc` 推翻。
   *本档展开*：与教训 ① 互为镜像 —— 一个是"单边信号恒真"，一个是"单边信号恒假"，**都是拿不能区分正负的量去判成败**。

##### 判据类教训 ③ —— 任何人的技术方案（包括队长的）都必须先做受控对照

   本轮队长错了三次，**全部由成员发现，没有一次是队长自查出来的**：
   Ⓐ 断言"t4 报告有笔记 hash 表、5 个 sha256 全失效" → **错**（t4 报告根本没有笔记 hash 表；§1 的「笔记」列只有路径无 sha256）。
   Ⓑ 提议"用 `BadPaddingException` 当新 oracle 判解密失败" → **错**。受控三组对照证伪：错误密钥 → **有**该异常；正确密钥+合法序列化 String → **无**；正确密钥+CC6 gadget → **无**。
     它是**单边判据：只在失败时出现，不出现 ≠ 成功**（也可能根本没走到解密）。队长原话："我拿'有 deleteMe'当失败，你拿'没 BadPaddingException'当成功——都是拿缺失的信号推断正面事实。"
   Ⓒ 核验 hunter-web 四份证据时，**批量核验脚本大小写归一化有误**，把唯一正确的那份（`security/learning/_evidence/loop3-t7-c1-logoracle-20261012.json`）判成 MISMATCH 并要求对方改文件 → **错**。逐字符复比确认完全一致，队长已道歉并撤回指令。
   **纪律**：不是"队长会错"这种泛泛免责，而是 —— **「任何人的技术方案，包括队长的，都必须先做受控对照才能采用；没有对照就没有发言权」**，对成员、对队长、对任何人同样成立。

**正确的 Shiro 成功锚点（收紧表述，别踩第三次同构错误）**：`AbstractRememberMeManager` 日志 **`:429`** = 解密阶段抛异常（BadPaddingException）→ 必然失败；
**`:431`** = 解密成功、进入反序列化阶段 —— 该阶段**可能成功产出对象**（→ `ClassCastException: java.util.HashSet cannot be cast`）、
**也可能反序列化失败**（→ `SerializationException`），故 `:431` 本身**不是**成功判据；
**真正的成功锚点 = `:431` + `ClassCastException: ... cannot be cast to ...PrincipalCollection`**。
队长独立复算计数：`BadPaddingException` 5 / `:429` 5 / `:431` **3** / `HashSet cannot be cast` **1**。
证据：`security/learning/loop3-c-c1-oracle-verdict-20261012.md` §3。

**其余本轮方法论教训（10 条）**（完整 13 条表见 `security/learning/loop3-trilateral-comparison-20261012.md` §5 与 `memory/context.md` §12 条目 14–27）：

4. `docker logs` **行数增量不能锚定事件**（日志轮转 → 假的 `new_log_lines:0`），必须带时间戳或按内容匹配。
5. `dsh-tools/kali-run.py` 在 **stdout 末尾追加 JSON**，下游"取第一行"会把 JSON 拼进数据 → **按 base64 字符集正则取最长串**，白烧约 15 min。
6. **"勘误比修改贵，但勘误才是对的"** —— 不改他人已锁定产物，只**追加勘误段**（本节 §11.8 与横向对比表第 2 版均按此执行）。
7. **"目录存在 ≠ 数据在此"** —— 判断存储位置必须**读配置 + 对候选位置分别测实际占用体积**。
8. **改已归档文件必须同步重报新 sha256** —— **规矩立完当天被立规矩者自己触发**（scribe 抄了旧 hash，自检抓出）。
9. **"凭印象写文件名 = 造引用"** —— 引用必须逐条存在性自检，**missing 必须为 0**。
10. **首次证据不干净要如实写** —— C2 首次 PUT 实测 204 不是 201、上传前 GET 200 不是 404，以第二轮为准并**如实标注**。
11. **回环校验 ≠ 来源校验**（A 档 D1）→ 待办 A7。
12. **逐个入口手工接检查，迟早会漏**（A 档 B1/C6）→ 校验上提到路由层/装饰器。
13. **跨文档汇总时，每个数字都要指回源文件**（t9 自身教训，见 §11.8.5）。

#### 11.8.5 ★ 本节的取数纪律（t9 自身教训，必须写死）

**第 1 版横向对比表把 A 档写成"残余 4 条 / 阴性 6 条"，源文件实为"残余 6 条 / 阴性 14 条"**
（源：`security/learning/hardening/HARD-02-A档残余绕过与阴性留证.md` §1 三态表 = 6 条残余；
`security/learning/hardening/A-档验证报告-20261012.md` §5.2 = N1–N14 共 **14 条**阴性）。
第 2 版已按源文件纠正并在文件顶部加**勘误块**，**第 1 版原文不删**。

**纪律**：汇总表每个数字旁**标源文件名 + 章节/行号**；汇总者**必须回源核对**，
**不得照抄下游结论、不得凭印象填、不得从任务汇报文字取数**。

**★ 同源第二条（mentor-final 本人踩，队长 00:12 指出）**：本节写完上述纪律后，我在同一次汇总里**自己违反了它**——
RISK_001（tomcat compose 端口缺 hostIP）是**直接继承 t7 汇报文本**的，没实读源文件。实读结果该文件 **82 B /
sha256 `7e29e11e5482fe086a23bd6497807dd10ec5d3ed4384c3cbec2b5f92dcf5bbb8` / mtime 2026-10-12 23:02:10 /
已含 `127.0.0.1:18082:8080`** → **风险不成立**。**四层转录、真读 0 次**：t7 汇报 → §13 → `memory/context.md` §11 → 我的汇总表。
→ **自己写的纪律不豁免**：教训清单里有的条款，恰恰最容易在赶工时被自己跳过。
逐条事实（端口/路径/行号/hash）汇总时**必须标记「实读」还是「转录」**，转录一律降级待核。
已在 §13 原行下方追加勘误（不删原行），并在 `security/learning/loop3-trilateral-comparison-20261012.md` §6.2 撤销该待办。

#### 11.8.6 下一步 / 待办（**A7 必须单列，归属 loop4**）

**★ A7 · `/__reset` 跨站来源校验修复（loop4 范围）**

- **归属**：**loop4**，不在 loop3 收尾内执行。
- **背景（t1 实测）**：A6 的 `/__reset` 加固**只校验回环来源**（peer 非 `127.0.0.1`/`::1` → 403），
  **未校验跨站上下文** → 带 `Origin` / `Referer` / `Sec-Fetch-Site: cross-site` 的表单**仍能触发复位**。
  证据：`security/learning/_evidence/loop2-verify-supplement4-20261012-201557.json`
  （sha256 `B105B1DA8B82F802C137217F8112CF3DA8DE099E717F8761F3ABE6C1B8695D9F`）的 `D1_cross_site_reset`：
  `reset_triggered=true`、`audit_delta=1`、`canary_before=2 → canary_after=1`。
- **① 修复目标**：**校验 `Origin` / `Referer` 来源**（要求精确等于 `http://127.0.0.1:<port>`，
  **缺失 `Origin` 也拒绝**，不得"没带就放过"）；**或**改用 **`SameSite=Strict` + 一次性 nonce**；
  更彻底可**摘掉 HTTP 路由、只留 `python app.py --reset` 启动参数**。
- **② 验证方式**：复用 supplement4 的**四个用例**，修复后要求**全部 `reset_triggered=false` 且 `audit_delta=0`**：

  | 用例 | 说明 | 期望 |
  |---|---|---|
  | `cross_site_form_body` | 跨站 Origin + urlencoded body 带 `confirm=RESET` | `reset_triggered=false` / `audit_delta=0` |
  | `cross_site_query_only` | 跨站 Origin + `confirm` 只放 query（无 body） | `reset_triggered=false` / `audit_delta=0` |
  | `same_site_form_body` | 同源 Origin + body | 按设计**允许**（用于证明不是"一刀切全拒"），报告中须注明这是设计意图 |
  | `no_origin_at_all` | 完全不带 Origin（curl 风格） | `reset_triggered=false` / `audit_delta=0`（缺失即拒） |

- **③ 归属标注**：**loop4**；同步写入 `memory/context.md` §11 与 `security/learning/loop3-trilateral-comparison-20261012.md` §6.1。

**其余 loop4 待办**

| # | 待办 | 验收标准 | 失败长什么样 |
|---|---|---|---|
| 2 | **B1/C6 顶级 GET 写入口修复**（A 档残余）：给 `wallet_transfer`（`app.py:1185-1196`）与 `change_password`（`app.py:1246-1254`）补 `check_write`，或把方法+CSRF 校验上提到路由层 | 两入口 `GET` → **405**、状态不变 | 仍 200 且余额/密码变了 |
| 3 | **B3 改密后销毁会话**：`change_password` 成功后 `DELETE FROM sessions WHERE user_id=?`（对齐 A4） | 改密后旧 Cookie `GET /home` → **302** | 旧 Cookie 仍 200、sessions 行未减 |
| 4 | **Cookie 属性取证**（A 档 §4.1 未验证项）：抓 `Set-Cookie` 确认 `HttpOnly`/`SameSite`/`Secure` | 把 D1/B1C6 严重性评级**钉死** | 属性缺失 → 严重性需**上调** |
| 5 | **首批自研 nuclei 规则**（把"自写脚本 3 级"往 4 级抬） | 对本地靶场复现命中、对他环境不误报 | 0 命中或大面积误报 |
| 6 | **B 档四类空白补齐**：`idor` / `command-injection` 优先（只读命令 `id`/`whoami`、越权最多 2–3 个他人账号） | 四目录**至少两类**有实证 | 把"未测"当"阴性"写进笔记 |
| 7 | **A1 窗口测量**：降并发 5/10/20 跑 ≥6 轮，给出成功率曲线 | 能写出"复现条件" | 只有单点 30 并发数据 |
| 8 | **Docker Desktop 关闭**：**须先报 captain 许可，不得自行关闭**（会中断既有 pentagi 4 容器；shiro Up、tomcat Exited(143) 保留现场） | captain 决策后执行 | 擅自关闭 → 现场丢失 |

**B 档遗留的未测边界（**不得**被误读为阴性或漏归档）**：`idor` / `sql-injection` / `ssti` / `command-injection`
四目录 md=0 = **本轮未测试**，逐条理由与下轮 P0/P1/P2 建议见 `security/learning/N-LOOP3-B-COVERAGE-B档分类覆盖声明.md`。

---

## 12. Loop 3 · B 档（DVWA / bWAPP）挖掘账目（2026-10-12 21:51–22:25，t4 / hunter-web）

> 本节由 **hunter-web** 于 2026-10-12 22:25 追加，全部数字取自
> `security/learning/_evidence/loop3-t4-probe13.json`（sha256 `74aeab1389021ff6dc41ebc33b3456469ce49c0a07b03abf31dc2054be3a4d37`）
> 与各阶段产物文件，**未从任务汇报文字取数**。主报告：`security/learning/loop3-b-dvwa-bwapp-report-t4-20261012.md`。

### 12.1 账目

| 口径 | 数量 | 来源 |
|---|---|---|
| 练习题（B1–B5） | 5 | 任务书 |
| 三态：成功 | **4**（B1/B3/B4/B5） | 各笔记 + probe13 |
| 三态：部分成功（结论含关键否定） | **1**（B2：内部实体可用、外部实体被运行时阻断） | probe2/probe9/probe11 |
| 三态：失败 | 0 | — |
| 新增漏洞笔记 | **5 篇** | 目录扫描 |
| 新增品类目录 | **2**（`xxe/`、`csrf/`） | 目录扫描 |
| 已补空目录 | **3**（`path-traversal/`、`xss/`、`auth-bypass/` 补实证） | 目录扫描 |
| **本轮未测品类** | **4**（`idor/`、`sql-injection/`、`ssti/`、`command-injection/`） | 任务书 + 本报告 §3 |
| 阴性项（附方法+原始请求） | **6**（N-B01..N-B06） | 本报告 §2 |
| 失败轮次/偏差（逐条） | **6**（F-01..F-06） | 本报告 §5 |
| 证据文件（原始取证：`loop3-t4-*.json` / `*.jsonl` / `b5-xss.png`） | **21** 个 | 目录扫描（`Get-ChildItem loop3-t4-*.json,*.jsonl,loop3-t4-b5-xss.png`） |
| 探针脚本与运行输出（`loop3-t4-probe*.py` / `loop3-t4-*.sh` / `loop3-b0-recon*.sh` / `*-out.txt`） | **45** 个 | 目录扫描 |
| 自建教学靶点 | 1（`/var/www/html/lo3-teach/`，**已删除**，不计入任何应用漏洞数） | probe11 |

### 12.2 复现率（尝试/成功）

| 项 | 尝试 | 成功 | 区间 |
|---|---|---|---|
| B1 路径穿越读 `/etc/passwd` | 5 | 5 | ≥95% |
| B1 `php://filter` base64 | 5 | 5 | ≥95% |
| B1 RFI（阴性） | 3 | 0 | — |
| B2 内部实体展开（原生关卡） | 5 | 5 | ≥95% |
| B2 外部实体（阴性） | 6 | 0 | — |
| B3 有 token 应拦 | 3 | 3（拦） | ≥95% |
| B3 无 token 写入 + 复原 | 3 | 3 + 3 | ≥95% |
| B4 会话固定 | 3 | 3 | ≥95% |
| B5 存储型 XSS → Cookie 外带 | 3 | 3 | ≥95% |
| B3 浏览器跨站形态（form/img/nav） | 3 | 2 | ≥66%（样本小） |

### 12.3 工具命中率（本轮）

| 工具 | 用途 | 是否出活 |
|---|---|---|
| 手写 Python 探针（requests） | 全部 LFI/XXE/CSRF/session 判定 | ✅ **主要出活手段** |
| Selenium 4.31.1 + Chromium 148 + ChromeDriver 148 | B5 真实执行 + B3 浏览器跨站 + SameSite 对照 | ✅ **决定性**（B5 的 Cookie 外带、B3 的 img/nav 差异只能靠它） |
| MariaDB 直查 | 库值四段链、行数复原核验 | ✅ 决定性 |
| PHP CLI 解析器矩阵 | B2 根因（`LIBXML_NOENT` 开/关） | ✅ 决定性 |
| paramiko（`kali-run.py`/`kali-put.py`/`kali-fetch-many-t4.py`） | VM 执行与取证 | ✅ 必备 |
| sqlmap / nmap / nuclei / ffuf / katana | — | ⬜ **本轮未使用** |

### 12.4 方法论教训（Loop 3 B 档新增，供 loop4 使用）

**有效**
1. **"关卡存在 ≠ 可利用"**：B2 是最典型的反例。bWAPP 自带 xxe 关卡、注释里还把实体禁用那行注释掉了，但 **PHP 8.4 + libxml 2.15 的默认行为直接堵死 SYSTEM 实体**。必须实测解析器行为，**不能凭关卡存在或注释推断可利用性**。
2. **"档位不同结论相反"**：B4 在 DVWA **默认 `impossible` 级是阴性**（ID 被轮换），切到 **low 才成立**。任何一条结论都必须绑定测试时的安全档位。
3. **内部实体能展开 ≠ 外部实体能展开**：B2 里这两条是**独立事实**，必须分开取证、分开表述。混写就是污染结论。
4. **真实浏览器不可替代**：B5 的"Cookie 被外带"和 B3 的"`<img>` 失败、`<form>`/顶级导航成功"，服务端探针**都看不出来**——前者要看 JS 真的有没有跑，后者要看浏览器带不带 Cookie。
5. **对照请求决定结论强度**：B3 若只测"low 无 token 能改"，会被质疑"是不是 token 校验根本没实现"；补上"medium 无 token → `Invalid token!`、带 token → 生效"后，结论才闭环。

**无效 / 踩坑**
1. **写端点"零写入"假设必须验证服务端取值来源**：bWAPP `xxe-2.php` 的 **medium/high 分支忽略 XML 里的 `<login>`、改用 `$_SESSION["login"]`**，导致我"用不存在的 login 就零写入"的判断在中/高档失效，**两次把 `bee.secret` 写成 `x`**（已复原并直查确认）。教训：**打写端点前先把服务端"参数从哪来"读清楚**。
2. **别用 `%` 格式化拼 XML/DTD 载荷**：`%xxe;` 会被格式化吃掉（`TypeError: not enough arguments`），改用字符串拼接。
3. **selenium 需显式驱动路径**：本机 `chromedriver` 在 PATH 里但 selenium 找不到 → `NoSuchDriverException`，用 `ChromeService(executable_path="/usr/bin/chromedriver")`。
4. **同名 `Set-Cookie` 合并显示会骗人**：`requests` 对同名 `Set-Cookie` 会合并，看 `r.headers["Set-Cookie"]` 可能只看到一个；判会话轮换/属性要用多值接口逐条取。

### 12.5 收尾状态（2026-10-12 22:17–22:20 复核）

| 项 | 状态 |
|---|---|
| `/var/www/html/` | 仅 `bWAPP`、`dvwa`、`index.html`、`index.nginx-debian.html` → 教学靶点已删 |
| `GET /lo3-teach/noent.php` | **404** |
| `127.0.0.1:8099` | **已关闭**，无残留探针进程 |
| `/var/lib/php/sessions/` | 无任何 loop3 测试会话 |
| `bWAPP.users` | `bee.secret = Any bugs?`（出厂值），密码哈希未变 |
| `dvwa.users` | 5 行，密码哈希与初始一致 |
| `dvwa.guestbook` | **3 行**（与注入前一致；`comment_id=2,3` 的 `XSS_S_MARK_66` 为上一轮遗留，未删） |
| `bWAPP.blog` | **0 行** |
| `apache2` / `mariadb` | active（未改动） |
| 公网请求 | **0**（全程仅 127.0.0.1 / 192.168.56.101 host-only / VM 内回环） |
| VM 配置 | **未改动**（仅读状态） |

---

## 13. Loop 3 · C 档（Vulhub Shiro + Tomcat）复现账目（2026-10-12 23:01–23:45，t7 / hunter-web）

> 本节由 **hunter-web** 于 2026-10-12 23:45 追加。全部数字取自
> `security/learning/_evidence/loop3-t7-c1-rate-and-baseline-20261012.json`
> （sha256 `68579107f657a551ca7032b456ecfec55863cdbf2e90d59cba65dd28d79d4a7e`）与各阶段产物，
> **未从任务汇报文字取数**。主报告：`security/learning/loop3-c-vulhub-report-t7-20261012.md`
> （sha256 `e784c5de71040424d57762a84030ec140ea6b0001731963de707855db3883ee8`）。

### 13.1 账目

| 口径 | 数值 | 来源 |
|---|---|---|
| 练习题（C1/C2/C3） | 3 | 任务书 |
| 三态：成功 | **2**（C1 Shiro、C2 Tomcat） | 本报告 §1/§2 |
| 三态：失败 | 0 | — |
| 基线记录（C3） | 1 份（含在 rate-and-baseline JSON 的 `baseline` 段） | 同文件 |
| CVE 复现 | **2**（CVE-2016-4437、CVE-2017-12615），均达 RCE | OOB + /proc + HTTP 回显 |
| gadget 链命中 | **3/4**（CommonsBeanutils1 / CommonsCollections5 / CommonsCollections6） | `loop3-t7-c1-shiro-20261012.json` |
| 阴性项（附方法与原始证据） | **6**（N-C01..N-C06） | 本报告 §3 |
| 被推翻的错误 oracle | **2**（deleteMe 标志、sleep 计时） | 报告 §1.4 / §3 |
| 工具缺陷导致的失败轮次 | **1**（cookie 被 JSON 尾部污染，白烧约 15 分钟） | 报告 §9.3 + shiro 容器日志 |
| 证据文件（`_evidence/` 下文件名含 `t7` 的全部文件） | **71 个** | 目录扫描（`Get-ChildItem -File | Where-Object { $_.Name -match 't7' }`） |
| 公网请求 | **0** | 全程仅 127.0.0.1 + host.docker.internal |
| 容器清理 | 容器按队长指令**保留**；容器内 `/tmp` 残留清零；OOB 端口关闭 | 报告 §6 |

### 13.2 复现率（尝试/成功，区间表述）

| 项 | 尝试 | 成功 | 区间 |
|---|---|---|---|
| C1 CC6 链 OOB 外带 | 5 | 5 | **≥95%** |
| C1 四链横向（CB1/CC5/CC6/CC2） | 4 | 3 | **≥66%**（单轮样本小） |
| C2 `PUT` 写 JSP | 3 | 3（201） | **≥95%** |
| C2 `GET` 执行并回显 | 3 | 3（200 + `uid=0(root)`） | **≥95%** |

### 13.3 工具命中率（本轮）

| 工具 | 用途 | 是否出活 |
|---|---|---|
| Ruby 自实现 ysoserial 模板 + AES-128-CBC | C1 payload 生成 | ✅ **核心**（离线，零下载） |
| Kali Metasploit 数据文件 `ysoserial_payloads.json` | gadget 模板源 | ✅ 决定性命中率 |
| 宿主 OOB 接收端（`127.0.0.1:8099`）+ 容器 `host.docker.internal` 回连 | C1 命令执行外带 | ✅ **决定性判据 J1** |
| `docker exec` + `/proc` 进程快照 | C1 命令执行第二判据 | ✅ **决定性判据 J2** |
| `curl` PUT/GET | C2 上传与执行 | ✅ 决定性 |
| MariaDB/Python/paramiko | 取证与脚本搬运 | ✅ 必备 |
| `deleteMe` 标志 / `sleep` 计时 | 曾用作 C1 oracle | ❌ **两者均被证伪**（报告 §3） |
| sqlmap / nmap / nuclei | — | ⬜ 本轮未使用 |

### 13.4 方法论教训（C 档新增，供 loop4 使用）

**有效**
1. **OOB + `/proc` 双硬判据**：C1 的真证据只有两条——接收端收到含命令输出的 URL、容器 `/proc` 里出现 gadget 拉起的 `sleep` 进程。**HTTP 状态码、响应时间、cookie 回写标志全都不靠谱。**
2. **先读 classpath 再选 gadget 链**：`unzip -l | grep` 一眼看出只有 `commons-collections-3.2.1`（Collections3），直接排除需要 collections4 的 CC2，省掉无效尝试。
3. **密钥来源要给出代码级证据**：反编译 `ShiroConfig.class` 证 `new CookieRememberMeManager()` 未设 key ⇒ 硬编码默认密钥，**不写"爆破成功"**。
4. **复核容器消失的正确姿势**：`docker inspect` 看 `ExitCode`（143=SIGTERM 优雅关闭）→ `docker logs` 看是否走完 stop 流程 → **再问，不擅自 start/rm**。本轮据此正确判断出"是队长按用户指令停的"。
5. **报告写完必跑自检**：`security/learning/_evidence/t7-report-selfcheck.py`（sha256 逐条核对 / 禁 100% / 禁证据名省略号），本轮它逮出 2 处镜像 digest 被写成省略号并已补全 → 终判 **ALL PASS**（sha256 核对 24 条全通过）。

**无效 / 踩坑**
1. **`rememberMe=deleteMe` 不是反序列化 oracle**——合法序列化 String 和错误密钥**都**返回 true，毫无区分度。**别用它下 C1 结论。**
2. **`sleep N` 计时不是 RCE oracle**——`Runtime.exec()` 异步，JVM 不等子进程，delta 仅 0.01s。我用它把**已经成功的 C1 误判为失败**，后靠 /proc 推翻。
3. **取 payload 别用"读第一行"**：`kali-run.py` 会在 stdout 追加 `{"rc":...}`，cookie 文件又没换行 → 拼成脏 cookie。**改用 base64 字符集正则取最长串**。这个 bug 让 C1 多绕了约 15 分钟。
4. **能 PUT 不等于能 DELETE**：`.jsp` 归 JspServlet（`doDelete` 未实现 → **405**），`readonly=false` 只管 DefaultServlet。**收尾路径必须单独实测**，不能想当然。
5. **msf 的 Ruby API 不能在裸 `ruby -e` 里用**：`Msf::Util::JavaDeserialization` 需要 `Msf::Config`，必须 `cd /usr/share/metasploit-framework && bundle exec`；否则报 `uninitialized constant Msf::Config`。绕行方案是**自实现模板拼装**（更可控）。
6. **JSP 首次编译有延迟**：宿主侧 PUT 后立刻 GET 可能 404，容器内同刻已 200。**别把编译延迟当成写入失败**——原始 404 记录我保留在证据里并给了根因。

### 13.5 收尾状态（2026-10-12 23:40–23:45 复核）

| 项 | 状态 |
|---|---|
| `vulhub-shiro-18081`（`3d7917aecbac`） | **Up**，`127.0.0.1:18081->8080/tcp`（按队长指令保留现场） |
| `vulhub-tomcat-18082`（`bb18b6fe2e26`） | **Exited (143)**（队长按用户指令 stop，保留现场） |
| 容器内 `/tmp` 残留（shiro） | **已清零**（`/tmp/jarx` `/tmp/lib` `/tmp/probe` `/tmp/t7*` 等全删） |
| 容器内已上传 JSP（tomcat） | **3 个全部删除，GET 均 404**，RCE 路径闭合 |
| OOB 接收端 `127.0.0.1:8099` | **已关闭**（`8099 not listening`） |
| 宿主临时脚本 | 无残留（全部落在 `_evidence/`） |
| 公网请求 | **0** |
| 容器挂载/隔离 | `Binds=null`、`MountCount=0`、`no-new-privileges`、`Restart=no`（基线核验） |
| 遗留风险（未改） | `D:\dsh-vulhub\tomcat-CVE-2017-12615\docker-compose.yml` 端口 `8080:8080` 缺 hostIP，下次 `compose up` 会绑 `0.0.0.0`；建议改 `127.0.0.1:18082:8080` |

> **勘误（2026-10-13 00:26，mentor-final）**：上行为 t7 汇报时的**过期信息**，该风险**不成立**。mentor-final 于 00:25 实读该文件确认：
> `D:\dsh-vulhub\tomcat-CVE-2017-12615\docker-compose.yml` = **82 B**，
> sha256 `7e29e11e5482fe086a23bd6497807dd10ec5d3ed4384c3cbec2b5f92dcf5bbb8`，mtime **2026-10-12 23:02:10**，
> 内容已含 `- "127.0.0.1:18082:8080"`（**已绑回环**）。该文件由 range-admin 在 t6 期间修复，**本轮不存在 LAN 暴露风险，无需再修**。
> 独立佐证：`security/learning/cve/C2-TOMCAT-2017-12615-PUT上传配置缺陷.md` §4.7 亦已实测闭环（物理网卡 curl exit 7）。
> ⚠️ **本条过期信息的成因**：t7 汇报文本先于文件修复而生成，下游（hunter-web 写 §13 → 队长转录进 `memory/context.md`）**照抄汇报文本未实读源文件**，导致同一过期结论被复制了两份。

### 13.6 C1 判定 oracle 的最终定论（2026-10-12 23:56 追加）

> 队长 23:45 通报「`deleteMe` 是无差别回包」，并提出以 `BadPaddingException` 作为新 oracle。我按此执行验证，
> 结论：**队长的前半段判断正确，后半段的提案不足以定性** —— 真正的硬锚点在**日志行号**。
> 补充报告：`security/learning/loop3-c-c1-oracle-verdict-20261012.md`（sha256 `6810aa90f84e634aa0b4e2444b91408138d210fdbe57640c822cb143595cf9d7`）。
>
> **🔺 勘误（2026-10-13 00:35，captain）——上行 sha256 为重写前的旧值，已失效。**
> 该报告经 `:431` 锚点精确化重写后，真实值为：
> ```
> 文件   : security/learning/loop3-c-c1-oracle-verdict-20261012.md
> size   : 17132 B
> sha256 : 17AC0E21C2ACE1A6954619B1109D7D1C4566AA1AD6FAD0AEF7678E2739BFCC6A
> ```
> 重写方：hunter-web（2026-10-13 00:0x，attempt `0d061d06-…`）；重写原因是把「`:431` = 成功锚点」
> 收紧为「`:431` 仅证明进入反序列化阶段；**真成功锚点 = `:431` + `ClassCastException: HashSet cannot be cast`」**。
> 实测分类（captain 独立复算）：`BadPaddingException`(:429) **5** / `SerializationException`(:431) **2** /
> `ClassCastException`(:431 真成功) **1**。台账：`_evidence/loop3-t7-c1-log-inventory-20261012.json`。

**四个候选 oracle 的实测对照**

| # | 候选 | 错误密钥 | 正确密钥+合法流 | 正确密钥+gadget | 判定 |
|---|---|---|---|---|---|
| 1 | HTTP `Set-Cookie: rememberMe=deleteMe` | true | true | true | ❌ 无区分度 |
| 2 | HTTP 响应时间（`sleep N` 计时） | ~0.01s | ~0.01s | ~0.01s | ❌ 无区分度（`Runtime.exec` 异步） |
| 3 | 日志 `BadPaddingException`（队长提案） | ✅ 有 | ❌ 无 | ❌ 无 | ⚠️ **单边**：只能判"解密失败"，不能判"成功" |
| 4 | **日志 `convertBytesToPrincipals` 行号** | `:429` | **`:431`** | **`:431`** | ✅ **可双向区分** |

**#4 是硬锚点（表述已按队长复核意见精确化，2026-10-13 00:05）**：Shiro 1.2.4 `AbstractRememberMeManager.convertBytesToPrincipals()` 的行号必须**三段式**读，不能简写：

| 行号 | 含义 | 断言强度 |
|---|---|---|
| `:429` | **解密阶段**抛异常（`CryptoException` ← `BadPaddingException`） | 必然失败 |
| `:431` | **解密成功、已进入反序列化阶段** | ⚠️ **只证明解密成功，不证明反序列化成功** |
| `:431` + `ClassCastException: HashSet cannot be cast` | 反序列化**真的产出了对象**，仅类型不符 | ✅ **真成功锚点** |
| `:431` + `SerializationException: Unable to deserialze argument byte array.` | 解密成功但**反序列化失败** | ❌ 失败 |

**完整台账**（逐块切分，非抽样；`loop3-t7-c1-log-inventory-20261012.json` sha256 `d9999386486cd56f2ffbe6c1ec2170fd96ce1777760290fd093b388ccc578074`）：

| 类别 | 计数 | 时间戳（UTC） |
|---|---|---|
| A `:429` 解密失败 | **5** | 15:09:33.057 / 15:18:39.291 / 15:19:00.964 / 15:33:54.922 / 15:33:56.591 |
| B `:431` 反序列化失败（`SerializationException`） | **2** | 15:18:40.540 / 15:19:02.185 |
| C **`:431` 反序列化成功（`ClassCastException: HashSet`）** | **1** | **15:38:29.985**（= 本地 23:38:29） |

行级原始计数（461 行日志）：`BadPaddingException` 5 / `:429` 5 / `:431` **3** / `ClassCastException` 1 / `SerializationException` 2 / `ClassResolvingObjectInputStream` 2 / `EOFException` 2 —— **与队长独立复算一致**。

**⚠️ 为什么必须收紧**：若写成"看到 `:431` 就是成功"，会被 B 类（2 次反序列化失败）误导 —— 那将是**本轮第三次同构错误**（拿"进入阶段"当"成功产出"）。**可用成功锚点必须同时满足 `:431` 与 `ClassCastException`。**

日志实测原始行（带时间戳，UTC `15:38:29.985` = 本地 **23:38:29**，落在本轮取证窗口内）：

```
2026-10-12 15:38:29.985  WARN 1 --- [nio-8080-exec-4] o.a.shiro.mgt.DefaultSecurityManager :
  Delegate RememberMeManager instance of type [org.apache.shiro.web.mgt.CookieRememberMeManager]
  threw an exception during getRememberedPrincipals().
java.lang.ClassCastException: java.util.HashSet cannot be cast to org.apache.shiro.subject.PrincipalCollection
	at AbstractRememberMeManager.deserialize(AbstractRememberMeManager.java:514)
	at AbstractRememberMeManager.convertBytesToPrincipals(AbstractRememberMeManager.java:431)
```

`java.util.HashSet` 正是 ysoserial `CommonsCollections6` 链的顶层反序列化对象 —— 与我的 payload 结构对应。

**C1 的四个独立判据交叉印证**：J1 OOB 外带（含 `id/whoami` 输出）→ 应用层命令执行；J2 容器 `/proc` 的 `sleep 10` 子进程 → OS 层真的起了进程；J3 日志 `:431` **且** `ClassCastException` 锚点 → 框架层解密+反序列化真的产出了对象；J4 本地默认密钥解密得 `aced0005` → 密码学层。**四条指向同一结论，不依赖任何单边 oracle。**

**新增的方法论教训**：`docker logs` 的**行数增量不能用来锚定事件**——本轮日志发生轮转（461 行快照 vs 后续 443 行），行号增量给出假的 `new_log_lines: 0`。**锚定日志事件必须带时间戳或按内容匹配。**

**被推翻证据的处置**：`t7-c1-bruteforce-out.txt`（25 密钥 × 计时法，`EXECUTED_KEYS=[]`）**未删改**，sha256 仍为 `e27d26961b48611be36987a57fd749e64aa058dc2dbfaace9e15051be9e596d9`（2169 字节），已在报告 N-C02 与本节标注为「**oracle 失效导致的无效结论**」，并同时说明**无需爆破（默认密钥即正确）、不主张"爆破成功"**。

**是否补 URLDNS 预检**：**不需要**。URLDNS 的用途是"无回显时先证链路通"，而本轮**已直接拿到 HTTP 外带命令输出**，预检会被后验证据覆盖。若队长坚持要 DNS 层证据，可按需补做（接收端仍限本地）。

**收尾复核**：OOB 接收端 `127.0.0.1:8099` 已关闭；shiro 容器 `/tmp` 残留再次清零（仅剩 Tomcat 自身运行时目录 `hsperfdata_root` / `tomcat.*.8080`）；容器状态 shiro **Up**、tomcat **Exited(143)**，均按队长指令保留。
