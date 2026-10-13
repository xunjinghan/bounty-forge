# 阶段2 侦察 · 补充纠正（SUPPLEMENT-01）

> 性质：对已交付产物的**追加说明**，不修改已锁定的 `attack-surface-20261012-182250.json` / `.md`
> （二者 sha256 保持 `154b62ac6544fd7bb80b1d39264c02413a52d7b89705f7d911c9297457d8b91f` /
> `2f8cefd67d25e33856b7511b223654d0ea35931bc73926bb95427014277f366d` 不变，避免哈希失效）。
> 本文件为唯一权威的纪律补丁，引用优先级高于原 MD 第 6/8 节。

- 任务：t3（attempt `f60bb3ce-2202-4d9d-8530-8c52a819273f`）
- 提出人：captain（2026-10-12 18:24 裁决）
- 复核人：recon
- 复核完成时间：2026-10-12T18:24:50+08:00（受控探针）

## 1. 结论（对原报告的修正）

| 原报告表述 | 修正后表述 |
|---|---|
| 「katana 于 18:15:19 误触 `/__reset` 触发一次删库重建」 | **不完整**。`/__reset` 的触发面不止 GET：`do_HEAD()` 同样调用 `route()`，而 `route()` 只判路径不判方法 ⇒ **`HEAD /__reset` 也会重置数据库**。已知至少 3 次重置（18:11:18 GET/range-admin、18:15:19 GET/katana、18:20:55 **HEAD**/方法探测）。 |
| 「lab.db sha256 = 49b2032c…（t1 基线）」 | 该哈希在 18:20:56 被打破（当时为 `815489e1…`）；经本次受控 HEAD 探针复现重置后，lab.db 哈希**再次回到** `49b2032c…`（种子内容可复现，但文件身份不再可信）。**基线哈希不能作为可复现性凭据**。 |
| 未决问题「/reset 消费端缺失」 | **已关闭**（captain 与 mentor 双重复验确认 404）。 |
| 未决问题「无 cookie 访问 `/` 的 500 复现条件不明」 | **已关闭**：条件明确为「请求携带有效会话 token」（有 cookie → 500 / 无 cookie → 200，两方复现一致）。 |

## 2. 证据（本轮受控验证，命令与原始输出）

- 源码（只读）：`target-site-lab/app.py` L399–403 `do_HEAD()` → `self.route()`；L425 `route()`；L478 `if path == "/__reset": return self.reset_endpoint()` —— **路由层不含方法判定**。
- 受控探针：`HEAD /__reset`（单个请求，User-Agent `recon-verify/1.0`）
  - 响应：`HTTP/1.0 200`，`Content-Length: 1190`（与 GET 触发的复位响应体长度一致）
  - 探测前 lab.db：`815489e1dfced91005f33c876ba2112c3a11365ac63dd8160110b8edc25a549e`（49152B，mtime 18:20:56）
  - 探测后 lab.db：`49b2032c29f8057530704203fd361bb162461eaeeeeb874c7ac1b8e8956cc7af`（49152B，mtime 18:24:50）
  - 同批被重写：`target-site-lab/private/config.bak`（241B，mtime 18:24:50）
  - 复位后直查：users = admin/100000、demo/50000、alice/88800、bob/100；orders 3；messages 1；sessions 0；coupon_claims 0；`PRAGMA integrity_check=ok`
- 结论：**HEAD `/__reset` 确实执行了 `reset_database()`**（删库重建 + 清空 uploads/ + 重写 config.bak）。

## 3. 纪律升级（硬规则，替代原 MD 第6节措辞）

> **对 8095 的任何自动扫描，必须同时排除「路径 `/__reset`」与「方法 HEAD」。**
> 原因：`do_HEAD` → `route()` → `path == "/__reset"` 无条件命中，HEAD 与 GET 等价破坏。

落地做法：

| 工具 | 必须参数 |
|---|---|
| katana | 过滤 `/__reset`（`-fs`/过滤规则），并对 8095 禁用 HEAD 类探测 |
| ffuf | `-fr '/__reset'`（或字典中删除该词）+ 不使用 `-X HEAD` |
| nuclei | **不对 8095 跑全模板**（实测 4339 请求/3 分钟，模板内部并发无视 `-rl 25`）；只跑定向模板清单 |
| httpx/dirsearch/自研脚本 | 不启用 HEAD 探测；脚本内对 8095 加路径黑名单 |
| 人工 | 复位只允许显式 `GET /__reset`，且必须记录复位前后 lab.db 哈希 |

## 4. 基线判据修正（替代「比对 lab.db 哈希」）

哈希会因任何一次误触失效，故改用**状态直查**作为污染判据：

- 8095：`users 4（admin 100000 / demo 50000 / alice 88800 / bob 100）`、`orders 3（qty 全 1，state ∈ paid/unpaid/shipped）`、`messages 1`、`sessions 0`、`coupon_claims 0`、无负余额。
- 8091（无复位接口，captain 裁决暂不补）：测试前直查并记录 `sessions` 行数与 `login_attempts` 键数；截至 2026-10-12 18:24，`sessions=41` 行、`login_attempts=4` 键（形如 `user:alice' or '1'='1`）。

## 5. 与其他阶段的口径衔接

- hunter（t4）获批可实测 GET 写入口真实扣款：**测后必须用显式 `GET /__reset` 复位**（纪律要求 GET，避免与 HEAD 产生歧义），并记录复位**前后**的状态直查结果。
- admin `/debug` 响应体复现归 t4；`/reset` 消费端问题已关闭，不再追踪。

## 6. 独立第三方验证（captain，2026-10-12 18:24–18:30）

由 captain 设计并执行的决定性实验，结论与本文档一致，作为交叉证据附记：

1. 人为污染：`UPDATE users SET balance_cents=999 WHERE username='bob'`（另 demo 余额改为 -3200）
   → 快照 sha256 = `309b834110c41da9…`，users = admin/100000、demo/**-3200**、alice/88800、bob/**999**
2. 发送单个 `HEAD /__reset`（UA `captain-verify/1.0`）→ `HTTP 200`，`Content-Length: 1190`
3. 再快照 → sha256 = **`49b2032c29f80575…`**，users = admin/100000、demo/**50000**、alice/88800、bob/**100**

判定：
- 「HEAD 与 GET 等价破坏」成立 —— 人工污染被完全抹除；
- 「lab.db 是确定性种子重建」成立 —— 异态哈希 `309b8341…` 被精确还原为 `49b2032c…`；
- 推论确认：**lab.db sha256 不能作为「是否干净」的凭据**，只能反映「是否被触发过一次重置」；判据一律使用状态直查。

补充事实：本文件以 append-only 方式发布（未改动已交付的 attack-surface JSON/MD），captain 已复核本文件 4522 字节、sha256 `d7e49371270e948a44b6db9ce0e367e22a01afe10771d6ee5f65a0ceb5dc0cc0` 逐字节吻合，原产物哈希 `154b62ac…` / `2f8cefd6…` 未被破坏。本节为事后追加，追加后本文件字节数与 sha256 会变化，引用时以最新一次复算为准。
