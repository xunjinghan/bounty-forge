# 分类覆盖声明：Loop 3 B 档（DVWA / bWAPP）本轮测了什么、没测什么

- **笔记编号**：LOOP3-B-COVERAGE（覆盖声明，非漏洞笔记，t5）
- **性质**：**归档声明**。本篇不含任何漏洞结论，**只声明 B 档的测试覆盖边界**，防止下轮误读为空目录 = 漏归档
- **适用任务**：t3（B 档前置）+ t4（B 档挖掘）+ t5（本篇归档）
- **测试窗口**：2026-10-12 21:51 – 22:25（Asia/Shanghai）
- **靶场**：Kali VM `dc1` 内 DVWA 与 bWAPP（均为**原有安装**，本轮**零部署、零下载、零公网请求**）

> **本篇最重要的用途**：`idor/`、`sql-injection/`、`ssti/`、`command-injection/` 四个目录**当前为 0 文件**。这是**"本轮未测试"**，**不是**"测过了没发现"，更**不是**"漏归档"。下轮接手前请先读这一篇。

---

## 1. 概述等级

**本篇不是漏洞笔记，无危害等级。**

### 1.1 B 档已补上的类别（本轮**确实测了**）

| 类别目录 | 笔记数 | 代表笔记 | 结论 |
|---|---|---|---|
| `path-traversal/` | 1 | `B1-LFI-01-DVWA文件包含路径穿越与phpfilter源码读取.md` | LFI 阳性 5/5；RFI / `data://` 阴性 |
| `xxe/` | 2 | `B2-XXE-01-…md`、`N-B03-B04-B05-bWAPP-XXE外部实体未复现.md` | 内部实体阳性 5/5；外部实体阴性 |
| `csrf/` | 2 | `B3-CSRF-01-…md`、`N-B01-B02-B06-CSRFimg形态与RFI未复现.md` | 顶级导航/表单阳性 3/3；`<img>` 形态阴性 |
| `auth-bypass/` | 5 | `B4-SESSION-01-DVWA会话固定与弱会话ID.md` | 会话固定 3/3（High） |
| `xss/` | 1 | `B5-XSS-01-DVWA存储型XSS到会话劫持完整链.md` | 存储型 XSS 完整链 3/3（High） |

### 1.2 B 档**仍未覆盖**的类别（本轮**完全没测**）

| 类别目录 | 当前文件数 | 本轮状态 | 说明 |
|---|---|---|---|
| **`idor/`** | **0** | ⚠️ **未测试** | 本轮**未发起任何越权测试** |
| **`sql-injection/`** | **0** | ⚠️ **未测试** | 本轮**未发起任何 SQL 注入测试**（Loop 1 的 `VER-12` 在 8095 自研靶场，与本档无关） |
| **`ssti/`** | **0** | ⚠️ **未测试** | 本轮**未发起任何模板注入测试** |
| **`command-injection/`** | **0** | ⚠️ **未测试** | 本轮**未发起任何命令注入测试** |

**必须写清的一句话**：**这四个目录为空，是因为本轮没测，不是因为测了没发现。** 两者在归档语义上完全不同 —— 前者是"未覆盖"，后者是"阴性结论"（阴性必须有证据，本轮对这四类**一条证据都没有**）。

### 1.3 部分覆盖情况（测了但受限）

| 类别 | 状态 | 说明 |
|---|---|---|
| `ssrf/` | **目录非空，但该篇不是本档产物** | `ssrf/VER-05-forgot的Host头注入与md5令牌可预测.md` 是 **Loop 1 · 8095 自研靶场**笔记，**不属于 B 档**。本轮 B 档**未测 SSRF**。详见 §5.2 |

---

## 2. 原理：为什么这四类本轮没测

不是遗漏，是**有意识的取舍**。本轮 B 档的时间窗（21:51–22:25，约 34 分钟）与约束决定了优先级：

| 因素 | 说明 |
|---|---|
| **时间预算** | 34 分钟内要完成 VM 拉起、建基线、跑 5 类练习、写报告与 5 篇笔记 |
| **写端点风险** | `sql-injection` 的布尔盲注会**真实修改数据库**；在 bWAPP 这类带真实业务的靶场上打盲注，违反"非破坏性"约束 |
| **A 档的经验迁移** | Loop 1（8095 自研靶场）的 A 档已覆盖业务逻辑/并发/CSRF/会话；本轮优先补**框架级真实约束**（`SameSite`、`session_regenerate_id`、libxml 解析器默认行为），这些是自研靶场给不了的 |
| **纪律要求** | 硬约束④明确"打任何端点前先判是否写端点" —— SQLi 恰恰是最容易违反的一条 |

> ⚠️ **不得声称已补**。本轮对 `idor` / `sql-injection` / `ssti` / `command-injection` **四类的覆盖率是 0**。

---

## 3. 可复现 payload

**本篇无 payload**（声明类文档）。

若下轮要补这四类，**建议的起手式**（仅供参考，本轮**未执行**）：

| 类别 | DVWA 落点 | bWAPP 落点 | 首要注意 |
|---|---|---|---|
| `sql-injection` | `/vulnerabilities/sqli/`（low/medium/high/impossible 四档） | `/bWAPP/sqli_1.php` … `sqli_*.php` | **只打只读函数**（`version()` / `user()`）；禁止布尔盲注打写端点 |
| `idor` | `/vulnerabilities/idor/` | `/bWAPP/idor_1.php` 等 | **最多查 2–3 个他人账号**；先确认该档是否真的开了 IDOR |
| `ssti` | `/vulnerabilities/ssti/` | `/bWAPP/ssti_1.php` | Twig/Smarty 各自的探测语法不同，先确认引擎 |
| `command-injection` | `/vulnerabilities/exec/` | `/bWAPP/command_injection_1.php` | **只跑 `id` / `whoami`**；先确认参数是否被 `system()`/`exec()` 直传 |

---

## 4. 复现步骤与证据

**本篇的"证据"是目录状态快照**，取自本轮实测：

| 目录 | `Get-ChildItem` 实测 | 判定 |
|---|---|---|
| `security/learning/idor/` | **文件数 = 0，md 数 = 0** | 未覆盖 |
| `security/learning/sql-injection/` | **文件数 = 0，md 数 = 0** | 未覆盖 |
| `security/learning/ssti/` | **文件数 = 0，md 数 = 0** | 未覆盖 |
| `security/learning/command-injection/` | **文件数 = 0，md 数 = 0** | 未覆盖 |

```powershell
# 可复跑（上表即由此命令产出）
$root = 'C:\Users\Administrator\Documents\deepseek-harness\default-workspace'
foreach ($d in @('idor','sql-injection','ssti','command-injection')) {
    $all = @(Get-ChildItem -LiteralPath "$root\security\learning\$d" -Recurse -File -ErrorAction SilentlyContinue)
    "{0}: 文件数={1} md数={2}" -f $d, $all.Count, @($all | Where-Object { $_.Extension -eq '.md' }).Count
}
```

**本轮实测输出**：

```
idor: 文件数=0 md数=0
sql-injection: 文件数=0 md数=0
ssti: 文件数=0 md数=0
command-injection: 文件数=0 md数=0
```

### 4.1 支撑证据文件（完整文件名 + sha256，**本轮独立重算**）

| 证据文件 | 内容 | sha256 |
|---|---|---|
| `loop3-kali-baseline-20261012-212122.json` | t3 基线：VM/服务/登录可用性（本档的前置条件） | `1f4ed4b34b173b664faef4c735ad0d7080f8d747df4fe80d9cb47da2bf5025f0` |
| `loop3-t4-probe13.json` | 本档**已测类别**的复现率汇总（穿越 5/5、filter 5/5、内部实体 5/5、会话固定 3/3、XSS 3/3、RFI 阴性 3/3） | `74aeab1389021ff6dc41ebc33b3456469ce49c0a07b03abf31dc2054be3a4d37` |
| `loop3-t4-probe15.json` | 收尾状态核查（含 `final_dvwa_users` / `final_bwapp` / `guestbook_after`） | `5160ffd3b337d1de51b049ba18add0ead4186ed358d1658b0f33942b030de253` |
| `t5-note-selfcheck.py` | **B/C 档 11 篇笔记的全量自检脚本**（七节 / missing=0 / sha256 逐条重算 / 复现率禁用） | `ca321b59f6af0990d3b05cb2a86777c6977ccc78cb474031dfa879467f28339e` |

> 注：证据命名约定见 §5.1 —— 本档历史证据为 `loop3-t4-*`（t4 挖掘期），**下轮 P0 执行后新增的证据一律用 `verify-<编号>-<类型>-<时间戳>.json`**，便于按轮次筛。

### 4.2 ⚠️ 勘误：基线 JSON 中的 `mitm8080` 条目为**修复前状态**（已闭环）

> **本节是勘误，不是新漏洞记录。** 记录写下时的结论与后续事实不一致，以本节为准。

**勘误事实**：

| 项 | 基线 JSON 记载（**已过期**） | 实际（**已修复**） |
|---|---|---|
| 转发规则 | `mitm8080,tcp,,8080,,8080`（**hostIP 空 = 绑 `0.0.0.0`**） | `mitm18080,tcp,127.0.0.1,18080,,8080`（**已绑回环**） |
| 宿主监听 | `0.0.0.0:8080` LISTENING（VBoxHeadless PID 16764） | `0.0.0.0:8080` **已消失**；只剩 `127.0.0.1:8080`（**Steam 的 `steamwebhelper`，与本题无关**） |
| LAN 可达性 | 宿主以物理网卡 `192.168.31.194:8080` 探测 → `exit 56`（可建连） | `192.168.31.194:8080` 与 `:18080` → **均 exit 7（拒绝）** |
| 风险定级 | 「低，但日后起 8080 服务将暴露到物理局域网」 | **已消除** |

- **修复执行时间**：**2026-10-12 21:52**
- **执行人**：**队长亲自执行**（用户已批准）
- **改动**：`删除 mitm8080,tcp,,8080,,8080` → `新增 mitm18080,tcp,127.0.0.1,18080,,8080`
- **端口为何从 8080 改成 18080**：宿主 `127.0.0.1:8080` 已被 **Steam `steamwebhelper`** 占用，直接绑回环会撞车
- **配套同步**：`dsh-tools/vulnhunt/apkline.py` 中的 `proxy_port` 与转发规则字符串已同步改为 **18080**

**基线 JSON 中该条目所在位置**（**保持原样，不修改**）：

| 位置 | 内容 |
|---|---|
| 第 59 行 | `{"name": "mitm8080", "hostip": "", "hostport": 8080, ...}`（NAT 转发原始记录） |
| 第 160–165 行 | `title` / `config_evidence` / `current_actual_risk` / `recommended_fix`（隐患记录与建议修复） |
| 第 280–282 行 | `risk_items` 条目「VBox NAT 转发 mitm8080 绑 0.0.0.0:8080」 |

**为什么不直接改基线 JSON**：

1. 该文件是 **t3 / range-admin 的产物**，且有 **sha256 锁定**（`1f4ed4b34b173b664faef4c735ad0d7080f8d747df4fe80d9cb47da2bf5025f0`）—— 改了会**破坏证据链**，而基线的价值恰恰在于"它是当时的样子"
2. 基线记录的**本身没错**：`mitm8080` 当时**确实**没绑回环。错的是**后续拿它当现状引用**
3. 正确做法 = **保留原始记录 + 另加勘误**，而不是重写历史

> **教训**：**任何"待修复"条目在闭环后都要留下勘误指针**，否则下轮读到基线会以为隐患仍在，可能重复排查甚至重复修复。**勘误比修改贵，但勘误才是对的。**

**引用存在性自检**：上述 3 个文件全部存在，**missing = 0**（见 §8）。

---

## 5. 下轮建议（**本轮未执行**）

按"投入产出比"排序：

| 优先级 | 类别 | 理由 |
|---|---|---|
| **P0** | `sql-injection` | 赏金平台最常收的类目；DVWA 四档 + bWAPP 多关卡，档位分叉结论有教学价值（同 B4/B3 经验） |
| **P0** | `command-injection` | 同上；且可与 XXE 的 `file://`/`expect://` 形成关联面 |
| **P1** | `idor` | bWAPP 的 idor 关卡多，适合练"越权只查 2–3 个账号"的取证纪律 |
| **P1** | `ssti` | 依赖模板引擎识别，DVWA 用 Twig、bWAPP 可能不同，需先做引擎指纹 |
| **P2** | SSRF（DVWA/bWAPP 侧） | `ssrf/` 目录已有 Loop 1 的笔记，B 档侧仍空白 |

### 5.1 下轮 P0 执行约定（bWAPP 写端点专项）· **队长 2026-10-12 批准写死**

**前提事实**：bWAPP 的 `sqli_*` 系列与 `commandi*.php` 多数关卡把输入**直接写库或写后端状态**，属**"写端点"**。直接套用自动化工具（sqlmap 盲注 / 时间盲注）会产生不可控的库写入或载荷落盘。**Loop 1 已有实证教训：sqlmap 布尔盲注 2 秒写入 `/board` 1454 行。**

#### 1) SQL 注入

- ✅ **允许**：`version()` / `user()` / `database()` / `sqlite_version()` 等**只读函数**
- ✅ **允许**：UNION 回显验证（**只取上述只读函数结果**）
- ⛔ **禁止**：任何形式的**盲注**（布尔 / 时间 / 报错堆叠）
- ⛔ **禁止**：`--os-shell`、`--file-write`、`--file-read`、`--sql-query` 中的**写操作**
- ⛔ **禁止**：`DROP` / `DELETE` / `UPDATE` / `INSERT` / `TRUNCATE` **任何形式**
- **工具纪律**：见 **§5.1.3**（命令行模板写死，**禁止临场拼参数**）
- **入库前先判**：该参数是否作用于写端点？**是 → 第 2 步整个取消**（**硬纪律**）

#### 2) 命令注入

- ✅ **允许**：`id` / `whoami` / `hostname` / `uname -a`（**只读**）
- ⛔ **禁止**：任何**写文件、下载、反弹 shell、持久化**
- **回显即止**：拿到只读命令输出后**立即停止**，不做第二次利用尝试

#### 3) 工具纪律（硬性，命令行模板写死，**禁止临场拼参数**）

- **第 1 步**：只用**只读 payload 手工验证**注入是否存在（curl / 自写脚本），**禁止在这一步就用 sqlmap**
- **第 2 步**：仅当手工确认存在后，才允许用 sqlmap 做复核，且**命令行模板固定为**：

  ```
  python sqlmap.py -u "<url>" --technique=EU --risk=1 --level=2 --batch \
    --threads=1 --delay=1 --time-sec=2
  ```

  - `--technique=EU` = 仅 **Union** 与 **Error-based**（**不含 B/T/S 盲注类**）
  - `--risk=1` = **不含任何写操作类测试**
  - `--threads=1 --delay=1` = **满足限速纪律**（并发 ≤5、间隔 ≥1s）

- **第 3 步**：⛔ **禁止**在该模板上追加 `--os-shell` / `--file-write` / `--file-read` / `--sql-query`（含写操作）/ `--dump-all` / `--sql-shell` / `--os-pwn`
- **第 4 步**：跑完**立即直查数据库**，比对测试前后状态，**证明无非预期变更**
- **若目标参数作用于写端点 → 整个第 2 步取消**，只保留手工只读验证，**不落自动化工具**
- **反面案例（必须保留在文档里）**：Loop 1 中 sqlmap 布尔盲注在 **2 秒内往 `/board` 写入 1454 行 payload**，就是因为**没有前置约定、也没有 technique 白名单**

> **为什么写成硬模板而不写成原则**：本约定的实际失效点就在**手工验证成功之后那一下顺手 `--batch`**。指望临场记住 `--technique` 白名单不现实 —— 参数必须**已经打在命令行里**，让手贱也得先改代码才能加上去。

#### 4) 通用

- 每次测试**前后直查数据库/文件系统状态**，证明未产生非预期变更
- 变更类操作**必须可回滚**，且**变更前后各查一次库**
- 复现率写**区间**，**禁止 100%**
- 证据落 `security/learning/_evidence/`，命名 **`verify-<编号>-<类型>-<时间戳>.json`**，每个算 **sha256**

#### 5) 其余类别沿用硬约束

- 越权（`idor`）**最多查 2–3 个他人账号**
- 写端点**打前先判副作用**，可回滚的必须留 **"前值 → 请求 → 后值 → 复原值"** 四段证据
- 接收端**只绑 `127.0.0.1`**

### 5.2 知识库：DVWA / bWAPP 档位 cookie 名（**谁踩谁死级**）

> **本节是 t11 修正 4 的固化产物。** verifier（t10）首轮复现 B4/B5 均因用错 cookie 名产生**假阴性** —— 报成"漏洞不存在"，比报错更糟。

**两个靶场，两个名字，绝不能混：**

| 靶场 | 档位 cookie 名 | 合法值 | 写错的后果 |
|---|---|---|---|
| **DVWA** | **`security`** | `low` / `medium` / `high` / `impossible` | **静默落到 `impossible`** → 全档位结论反转 → 假阴性 |
| **bWAPP** | **`security_level`** | `0`(low) / `1`(medium) / `2`(high) | 与 DVWA 混淆 → 同上 |

**DVWA 源码证据**（`/var/www/html/dvwa/dvwa/includes/dvwaPage.inc.php`，完整输出见 `loop3-b0-recon7-out.txt`）：

| 行号 | 源码 | 含义 |
|---|---|---|
| **L3** | `$security_levels = array('low', 'medium', 'high', 'impossible');` | 合法档位白名单 |
| **L4** | `if( !isset( $_COOKIE[ 'security' ] ) \|\| !in_array( $_COOKIE[ 'security' ], $security_levels ) ) {` | cookie 不存在或值非法 → 进入分支 |
| **L7** | `dvwaSecurityLevelSet( $_DVWA[ 'default_security_level' ] );` | 有配置默认值则用之 |
| **L9** | `dvwaSecurityLevelSet( 'impossible' );` | **否则一律落到 `impossible`** |
| **L204** | `if (isset($_COOKIE['security'])) { return $_COOKIE[ 'security' ]; }` | 读取键名 = **`security`** |
| **L226** | `setcookie( 'security', $pSecurityLevel, 0, "/", "", false, $httponly );` | 下发键名 = **`security`** |

**为什么这条是"谁踩谁死"级**：DVWA 在 cookie **缺失或非法时默认 `impossible`**。而 `impossible` 档恰好把所有漏洞都修了：

| 档位 | 会话固定 | 存储型 XSS | 弱会话 ID |
|---|---|---|---|
| `impossible`（**误落的档**） | ID 被 `session_regenerate_id()` 轮换 | `htmlspecialchars` 转义，脚本不执行 | 改用强随机，序列不可枚举 |
| `low`（**真正要测的档**） | ID 原样保留 | 未转义，脚本执行 | `1..7` 自增 |

**→ 在 `impossible` 档上得出的任何"阴性"结论，全部作废，必须回 `low` 重测。**

**探针代码模板（含防呆断言，后续所有人照抄）**：

```python
# ❌ 错误：DVWA 用 security_level → 服务端静默落到 impossible → 全面假阴性
cookies = {"PHPSESSID": sid, "security_level": "low"}

# ✅ 正确：DVWA 用 security
cookies = {"PHPSESSID": sid, "security": "low"}

# ✅ bWAPP 才用 security_level，值是 0/1/2
cookies_bwapp = {"PHPSESSID": sid, "security_level": "0"}

# 🛡 防呆断言：写探针时先断言，再发请求
def dvwa_cookies(sid, level="low"):
    assert level in ("low", "medium", "high", "impossible"), f"非法档位: {level}"
    c = {"security": level}
    if sid:
        c["PHPSESSID"] = sid
    assert "security_level" not in c, "DVWA 档位 cookie 名是 security，不是 security_level"
    return c
```

**已被这个坑坑过的实例（留证）**：

| 实例 | 踩法 | 观察到的假象 | 真相 |
|---|---|---|---|
| verifier t10 · B4 会话固定 | 设 `security_level=low` | 自选 SID 被 `session_regenerate_id()` 换掉 → 判"不成立" | 落在 `impossible`，**low 档实际成立** |
| verifier t10 · B5 存储型 XSS | 设 `security_level=low` | 浏览器落 `impossible`，`htmlspecialchars` 转义 → 脚本不执行、接收端 0 命中 | 同上，**low 档实际成立** |

> **教训**：**阴性结论必须先证明"我测的是我以为的那个档位"。** 否则你测的是 `impossible`，报的却是"low 档没有 XXE/XSS/会话固定" —— 这是**结论张冠李戴**，比没测更糟。

### 5.3 纪律：修改已归档文件必须同步重算并更新所有引用 hash

> **本节是 t11 修正 5 的固化产物。** 违反者会让整条证据链的引用失效。

**规矩**：

1. **任何成员修改已归档文件（`security/learning/**` 下的笔记 / 报告 / 证据）**，必须**同步**：
   - **重算并报出**该文件的**新 sha256 + 字节数**
   - **搜索并更新所有引用它的文档**里的旧 hash
2. **"改了但没报"等于没改**。引用方拿到旧 hash 会判定 DRIFT，整份报告的可信度归零。
3. **改一次报一次**：同一文件在本任务内被改多次，**每次改动后都要重算**，不能只在最后报一次 —— 因为中途的 hash 也会被外部引用。
4. **锁定产物例外**：带 sha256 锁定且属他人产物的文件（如 `loop3-kali-baseline-20261012-212122.json`），**只加勘误指针，不改数值**（见 §4.2）。
5. **本轮的真实教训（t11 修正 1）**：scribe 补七节模板时改了 B1–B5 五篇，**只报了新增的 3 篇**，漏报这 5 篇 → t4 主报告里 5 个旧 hash **全部失效**（队长实测 5/5 DRIFT）。**"顺手改一下"是引用失效的头号成因。**

**提交前自检清单**：

```powershell
# 改了哪些文件？一个不漏地列出来并重算
$changed = @('security/learning/xxe/B2-XXE-01-....md', 'security/learning/csrf/B3-....md')
foreach ($f in $changed) {
  $h = Get-FileHash -LiteralPath $f -Algorithm SHA256
  '{0}  {1}B  {2}' -f (Split-Path $f -Leaf), (Get-Item -LiteralPath $f).Length, $h.Hash
}

# 搜谁引用了它 —— 漏一个就是 DRIFT
Select-String -Path 'security/learning/**/*.md' -Pattern '<旧hash前8位>'
```

### 5.4 ⚠️ 目录归属防串味（队长要求固化）

**`security/learning/ssrf/` 目录里的笔记不属于 B 档。**

| 项 | 值 |
|---|---|
| 目录内笔记 | `security/learning/ssrf/VER-05-forgot的Host头注入与md5令牌可预测.md` |
| **实际归属** | **Loop 1 · 8095 自研靶场产物** |
| **是否 B 档（DVWA/bWAPP）** | ❌ **不是** |
| B 档 SSRF 状态 | **未测试**（DVWA / bWAPP 侧均未测） |

**为什么必须写死**：按目录名统计覆盖率会把 Loop 1 的结论**误记成 B 档成果**。跨档结论不可外推 —— 两边的框架默认行为、档位机制、数据库类型都不同。

**判定口径**：判断"本档测了什么"**必须看笔记正文里的靶场标注**，不能只看目录名。B 档笔记统一在头部写明 **靶场 = Kali VM `dc1` 内 DVWA / bWAPP**。

> 同理需注意：`business-logic/`(9)、`hardening/`(4)、`file-upload/`(1)、`ssrf/`(1) 均为 **A 档（8095 自研靶场）产物**，**不计入 B 档覆盖率**。B 档本轮实际产出仅 `path-traversal`/`xss`/`auth-bypass`/`csrf`/`xxe` 五个目录 + 本篇覆盖声明。

---

## 6. 参考链接

- **本档相关笔记**（完整路径）：
  - `security/learning/path-traversal/B1-LFI-01-DVWA文件包含路径穿越与phpfilter源码读取.md`
  - `security/learning/xxe/B2-XXE-01-bWAPP原生XXE关卡实体展开与外部实体阻断.md`
  - `security/learning/xxe/N-B03-B04-B05-bWAPP-XXE外部实体未复现.md`
  - `security/learning/csrf/B3-CSRF-01-bWAPP真实CSRF与token对照.md`
  - `security/learning/csrf/N-B01-B02-B06-CSRFimg形态与RFI未复现.md`
  - `security/learning/auth-bypass/B4-SESSION-01-DVWA会话固定与弱会话ID.md`
  - `security/learning/xss/B5-XSS-01-DVWA存储型XSS到会话劫持完整链.md`
- **本档主报告**：`security/learning/loop3-b-dvwa-bwapp-report-t4-20261012.md`
- **前置基线**：`security/learning/_evidence/loop3-kali-baseline-20261012-212122.json`
- OWASP WSTG 分类索引（四类待补的测试用例目录）：https://owasp.org/www-project-web-security-testing-guide/
- DVWA 官方仓库：https://github.com/digininja/DVWA
- bWAPP 官方站点：http://www.itsecgames.com/

---

## 7. 学习要点

1. **"空目录"必须带声明**。空目录有三种可能：**未测试**、**测了没发现**、**测了但归档失败**。**不写声明，下轮一定会误读。** 本篇就是为了消灭第三种歧义。

2. **未测试 ≠ 阴性结论**。阴性必须有证据（本档的阴性 N-B01…N-B06 都带原始请求/响应与 sha256）；**零证据的目录只能叫"未覆盖"**。

3. **测试取舍要写下来**。本轮不测 SQLi 是**有意识的选择**（写端点风险 + 时间预算），不是能力不足或遗漏。**写下取舍理由，下轮才知道这是待办而不是已办。**

4. **注意目录名会骗人**。`ssrf/` 里有文件，但那是 **Loop 1 自研靶场**的笔记，不是 B 档产物。**按目录统计覆盖率会跨轮串味** —— 判断"本档测了什么"要看笔记正文里的靶场标注。（已固化进 §5.2）

5. **跨轮统计要分档**。本档（DVWA/bWAPP，PHP+MySQL）与 A 档（8095 自研 Python 靶场）的结论**不可互相外推**：框架默认行为、档位机制、数据库类型都不同。

6. **执行约定要写进归档件，不能靠口头传**。下轮临场发挥必然走样 —— sqlmap 一上手就是盲注，盲注一跑就是不可控写入。**约束写死在文档里才有约束力**（§5.1，队长 2026-10-12 批准）。Loop 1 的 `sqlmap 布尔盲注 2 秒写入 /board 1454 行` 就是没有前置约定才出的事。

7. **"待修复"条目闭环后要留勘误指针，不要改原始记录**（§4.2）。基线 JSON 里的 `mitm8080` 未绑回环隐患**已于 2026-10-12 21:52 由队长修复为 `127.0.0.1:18080`** —— 该 JSON 内的条目是**修复前状态**，**不是现状**。**基线记录本身没错，错的是把它当现状引用。** 改了带 sha256 锁定的证据文件反而破坏证据链；正确做法是**留原始 + 加勘误**。

---

## 8. 引用存在性自检（可复跑）

```powershell
$root = 'C:\Users\Administrator\Documents\deepseek-harness\default-workspace'
$refs = @('loop3-kali-baseline-20261012-212122.json',
          'loop3-t4-probe13.json',
          'loop3-t4-probe15.json')
$missing = @($refs | Where-Object { -not (Test-Path -LiteralPath "$root\security\learning\_evidence\$_") })
"refs=$($refs.Count)  missing=$($missing.Count)"
$missing | ForEach-Object { "MISSING: $_" }

# 同时复核四个目录仍为空
foreach ($d in @('idor','sql-injection','ssti','command-injection')) {
    $n = @(Get-ChildItem -LiteralPath "$root\security\learning\$d" -File -ErrorAction SilentlyContinue).Count
    "$d = $n files"
}
```

**本轮实测输出**：

```
refs=3  missing=0
idor = 0 files
sql-injection = 0 files
ssti = 0 files
command-injection = 0 files
```
