# Loop 3 三档横向对比表与复盘（A 档收尾 / B 档 DVWA·bWAPP / C 档 Vulhub CVE）

- **任务**：t9「三档横向对比表与记忆回写」（loop3 收尾）
- **执行**：mentor-final；attempt_id `21343f7c-c0ef-4549-ab16-8dd471a5bfa5`
- **取数时刻**：2026-10-13 00:10（Asia/Shanghai）
- **取数铁律**：**只从产物文件取数**（笔记 / 报告 / 证据 JSON / 目录扫描 / cost-meter 落盘文件），
  **未从任何任务汇报文字取数**。
- **取数脚本**：`security/learning/_evidence/loop3-t9-summary.py`
  → 输出 `security/learning/_evidence/loop3-t9-summary-20261012.json`
- **性质声明**：本文是**复盘与方法论汇总**，不含新的漏洞结论。三档漏洞结论一律以各自笔记/报告为准。

> **⚠️ 本文件第 2 版勘误（2026-10-13 00:10，mentor-final）**
> 第 1 版（mentor-loop3，attempt `06f76e46-…`，23:52 落盘）因渠道限流中断，**记忆回写未落地**，
> 且主表有 **2 处数字与源文件不符**。本版已按源文件纠正，**不改写第 1 版的任何原始证据文件**：
> | 位置 | 第 1 版写的 | 源文件实测（本次 `Test-Path`+哈希复核） | 处置 |
> |---|---|---|---|
> | A 档「残余/需处理」 | 3 条需处理 + 1 可接受 = 4 | **6 条残余面**：成功 5（D1 / B1·C6 两个入口 / B2 / B3 / C3）+ C3 仅 orig 成立；其中**需处理 3**（D1、B1/C6、B3）+ 可接受 1（B2）+ 无需处理 1（C3） | 已纠正，源：`hardening/HARD-02-A档残余绕过与阴性留证.md` §1 三态表 + §4.1 + 附录三态汇总 |
> | A 档「误报/阴性」 | 「6 条阴性」 | **阴性 14 条**（N1–N14，全量留证） | 已纠正，源：`hardening/A-档验证报告-20261012.md` §5.2 |
>
> 教训见本文 §5 教训 13：**跨文档汇总时，每个数字都要指回它的源文件行号，不能凭印象填。**

---

## 0. 三档一句话结论

| 档位 | 一句话 |
|---|---|
| **A 档** | 六处加固**全部有 orig↔hard 双靶对照且有效**，但**不是零残留** —— 挖出 **6 条残余面**（其中 **3 条需处理**：D1 跨站复位、B1/C6 顶级 GET 写、B3 改密不轮换会话），另有 **14 条阴性**全量留证。**本轮最值钱的产出是残余面，不是"加固成功"。** |
| **B 档** | 5 条练习三态：成功 4 / 部分成功 1 / 失败 0，补上 4 个原本空白类别。**最大价值是两条认知修正**——「档位不同结论相反」（B4 在 `impossible` 级为阴性）与「关卡存在 ≠ 可利用」（B2 有 XXE 关卡但外部实体被运行时挡死）。 |
| **C 档** | Shiro CVE-2016-4437 与 Tomcat CVE-2017-12615 **双 RCE 实证**，C1 最终由**四条独立判据**交叉定性（OOB + `/proc` + 日志行号锚点 + 本地密钥解密），**不依赖任何单边 oracle**。代价是**两个假 oracle 各烧了一轮**（`deleteMe`、`sleep` 计时）。 |

---

## 1. 横向对比表（主表）

| 项 | **A 档**（加固复核与残余绕过） | **B 档**（DVWA / bWAPP 补类） | **C 档**（Vulhub CVE 复现） |
|---|---|---|---|
| **目标** | 复核 Loop 2 六处加固（A1/A2/A3/A4/A6）是否真落地；枚举残余绕过路径 | 补 `learning/` 空白类别：LFI/RFI、XXE、CSRF、会话固定、存储型 XSS 完整危害 | 复现 Shiro rememberMe 反序列化 + Tomcat PUT 上传，产出可提交级 CVE 报告的前置素材 |
| **靶场** | `target-site-lab` 8095（自建）＋沙箱副本 18095(orig)/18096(hard) | Kali VM `dc1`：DVWA + bWAPP（**原有安装**，零部署） | 本地 Docker：`vulhub-shiro-18081` / `vulhub-tomcat-18082`（仅绑 127.0.0.1） |
| **产物落盘跨度**¹ | 19:57:51 → 21:29:09（≈**91 min**）<br>纯验证窗口 21:08 → 21:29（≈**21 min**） | 21:21:22 → 23:47:47（≈**146 min**，含 VM 前置 + 覆盖声明）<br>纯挖掘窗口 21:51 → 22:13（≈**22 min**） | 23:01:49 → 23:49:46（≈**48 min**，含 t6 前置复核 + t8 归档）<br>纯复现窗口 23:01 → 23:45（≈**44 min**） |
| **confirmed（结论成立）** | **12 条**（P1–P12，见脚注 2） | **5 条**（B1–B5；B2 定性 Medium **未升级**） | **2 条**（C1 Shiro、C2 Tomcat，均达 RCE） |
| **其中新挖出的漏洞面** | **0 个新漏洞**；产出的是**加固有效性判定 + 3 条需处理残余** | **5 条**（LFI / XXE / CSRF / 会话固定 / 存储型 XSS） | **2 条**，但**均为已公开 CVE 复现，非发现型**（见脚注 3） |
| **残余 / 需处理** | **6 条残余面**：成功 5 + C3 仅 orig 成立；**需处理 3**（D1 跨站复位、B1/C6 顶级 GET 写、B3 改密不轮换会话）、可接受 1（B2 token 走 query）、无需处理 1（C3） | 0（B2 外部实体阴性归因于运行时，**不计为漏洞**） | 0 |
| **误报（零收录）** | **0** 新增 | **0** 新增 | **0** 新增 |
| **阴性留证** | **14 条**（N1–N14，§5.2 全量表） | **6 条**（N-B01…N-B06） | **6 条**（N-C01…N-C06，含 2 条被推翻的错误 oracle） |
| **被推翻的错误判据** | 0 | 0 | **2 条**（`deleteMe` 无区分度、`sleep` 计时无区分度）——**原始证据均保留未删改** |
| **严重度分布** | 残余面**中危**（HARD-02 §1 自述；主干已封） | **High 3**（B1/B4/B5）／**Medium 2**（B2 未升级、B3） | **Critical 2**（C1、C2 均未认证 RCE）⁴ |
| **笔记篇数（本轮新增）** | **2 篇**（`hardening/`：HARD-01、HARD-02） | **8 篇**（5 篇主 + 2 篇 N-* + 1 篇覆盖声明）⁵ | **3 篇**（`cve/`：C1、C2、N-C01） |
| **调用量（口径 B，近似归属）**⁶ | 窗口内新起会话 **515 calls**，账本名义 **0.1302 CNY** | 窗口内新起会话 **398 calls**，账本名义 **0.7128 CNY** | 窗口内新起会话 **27 calls**，账本名义 **0.0591 CNY** |
| **复现率（区间，禁 100%）** | A1 负余额 **≥95%（6/6 轮，失败 0）**；残余绕过单请求判定，**不写 100%** | 各项 **≥95%（3/3 或 5/5）**；B3 浏览器形态 **≥66%（2/3，样本小）** | C1 主链 CC6 **≥95%（5/5）**；四链横向 **≥66%（3/4）**；C2 **≥95%（3/3 / 3/3）** |
| **笔记路径（代表）** | `security/learning/hardening/A-档验证报告-20261012.md`、`security/learning/hardening/HARD-01-A档六处加固原理与落地diff.md`、`security/learning/hardening/HARD-02-A档残余绕过与阴性留证.md` | `security/learning/loop3-b-dvwa-bwapp-report-t4-20261012.md` + `path-traversal/`、`xxe/`、`csrf/`、`auth-bypass/`、`xss/` | `security/learning/loop3-c-vulhub-report-t7-20261012.md`、`security/learning/cve/C1-SHIRO-2016-4437-rememberMe反序列化默认密钥.md`、`security/learning/cve/C2-TOMCAT-2017-12615-PUT上传配置缺陷.md` |
| **方法论结论（一句话）** | **「回环校验 ≠ 来源校验」**；**「逐个入口手工接检查，迟早会漏」**（`check_write` 手接 4 处、漏 2 处，漏的正好是转账与改密） | **「档位不同结论相反」**；**「关卡存在 ≠ 可利用」**；**「内部实体能展开 ≠ 外部实体能展开」** | **「能判失败的单边信号，不能反推成功」**；RCE 真判据只有 **OOB 外带 + `/proc` 采样（+ 服务端日志锚点）** |

**脚注**

1. 「产物落盘跨度」口径 = 该档**首个与末个产物文件的 mtime 之差**（机器读取，非人工估）。它包含环境前置/归档等非挖掘时间，**不等于纯工时**；括号内另给纯作业窗口做对照。取数见 `_evidence/loop3-t9-summary-20261012.json`。
2. A 档 P1–P12 的"阳性"是**验证结论成立**，不是 12 个新漏洞：P1/P4/P5/P6/P7/P12 描述**原版可被攻破**，P2/P3/P11 描述**加固版挡住**，P8/P9/P10 描述**加固后仍成立的残余绕过**。**不得按漏洞数入账。**（源：`hardening/A-档验证报告-20261012.md` §5.1）
3. C 档两条是 **CVE 复现**（CVE-2016-4437 / CVE-2017-12615，均已公开、已分配编号、已有修复），**不是发现型漏洞**；三篇 `cve/` 笔记开头均有独立性质声明块写明"不得当作原创发现提交给任何赏金平台"。
4. Critical 只对**未认证即 RCE**这个事实成立；**不代表可提交赏金**——理由同脚注 3。
5. B 档"8 篇"含 1 篇**覆盖声明**（`security/learning/N-LOOP3-B-COVERAGE-B档分类覆盖声明.md`），它不是漏洞笔记、无危害等级，**计入篇数但不计入漏洞数**。
6. **口径 B 的"按档归属"是近似值，不得当精确消耗读**：ledger 的 `days[...].sessions` 只有会话 id 与起止时间，**没有"成员↔会话"映射**，无法把某个 call 精确归到某一档。切法按**会话起始时间**落窗，**跨窗口的长会话会被整条归到起始窗口**——例如 hunter-web 的 C 档主会话起始于 21:51，会被整条算进 B 窗口。**团队总消耗以 §3.2 的全天 provider 拆分为准。**

---

## 2. 三档的覆盖与未覆盖（明确边界，防下轮误读）

| 类别目录 | 轮前 | 轮后 | 本轮结论 |
|---|---|---|---|
| `path-traversal/` | 空 | **1** | LFI 阳性 5/5；RFI / `data://` 阴性（`allow_url_include=Off`） |
| `xxe/` | 空 | **2** | 内部实体阳性 5/5；**外部实体阴性**（PHP 8.4.24 + libxml 2.15.3 运行时默认行为） |
| `csrf/` | 空 | **2** | 顶级导航/表单阳性 3/3；`<img>` 形态阴性（子资源不带 Cookie） |
| `xss/` | 空 | **1** | 存储型 XSS → Cookie 外带 → 会话接管，完整链 3/3 |
| `auth-bypass/` | 4（Loop 1） | **5** | 新增 B4 会话固定实证（+1） |
| `cve/` | 空 | **3** | C1/C2 双 RCE；N-C01 阴性 |
| `idor/` | 空 | **仍空（0）** | ⚠️ **本轮未测**。不是"测了没发现"，更不是漏归档 |
| `sql-injection/` | 空 | **仍空（0）** | ⚠️ **本轮未测**（Loop 1 的 VER-12 在 8095 自研靶场，与本档无关） |
| `ssti/` | 空 | **仍空（0）** | ⚠️ **本轮未测** |
| `command-injection/` | 空 | **仍空（0）** | ⚠️ **本轮未测** |

**取数方式**：`Get-ChildItem` 目录扫描（见 `_evidence/loop3-t9-summary-20261012.json` 的 `note_dirs` 段），**非从汇报文字取数**。逐条边界声明见 `security/learning/N-LOOP3-B-COVERAGE-B档分类覆盖声明.md`。

---

## 3. 成本双口径（两个口径都要给，各自含义必须写明）

### 3.1 口径 A —— 余额差值（**严重低估，不可单独作结论**）

取数时刻 **2026-10-13 00:10**，来源 `~/.dsh/storages/cost-meter/ledger.json`
（该文件 sha256 `ADED1FCC23DBABCBBEAADB213D480D26811FD1E7BA89F7FB817A2B4D56FC9268`）。

| 项 | 值 |
|---|---|
| `balanceRef.total` | **3.80638416 CNY** |
| `balanceRef.currency` | CNY |
| `balanceRef.granted` / `topped` | 0 / 3.80638416 |
| `balanceRef.ledgerCost` | **0** |
| `balanceRef.date` | **2026-10-13** |
| `balanceRef.at`（快照时刻） | **2026-10-12 21:34:03**（epoch 1791820984398）—— ⚠️ **非实时，且早于本轮 B/C 档全部作业** |

**含义与局限（必须一起读）**：

1. **本轮成员全部跑在免费车道**（`buddy` / `our-free-model/space-bunny-free` / `workbuddy`），**免费车道不扣余额** → 口径 A **严重低估**团队本轮消耗，**不能单独作为团队花费结论**。
2. `balanceRef.at` 是 **21:34:03 快照**，而本轮 B 档挖掘（21:51 起）、C 档复现（23:01–23:45）**全在该快照之后** —— 该快照**根本不覆盖 B/C 档时段**。
3. 因此口径 A 当前的实际意义只剩：**队长（captain）自身协调消耗的粗略下界**（队长跑在真付费车道 `deepseek-account` / `deepseek-official`）。
4. **本轮起点余额**：`balanceRef.date` 已翻到 2026-10-13，`granted=0`、`topped=total`，说明**本轮期间没有新的充值**——所以余额差值近似反映"自上次充值以来的总扣费"，跨天不可直接相减。

> 上一轮的教训是"ledger 只统计部分 provider、低估 5 倍"；**本轮是反向**：免费车道让余额差值趋近于 0 增长。两种情形都指向同一条纪律——**单一口径不可独立成结论**。

### 3.2 口径 B —— 调用量（**团队总消耗以此为准**）

取数文件：`~/.dsh/storages/cost-meter/ledger.json` 的 `days['2026-10-12']`（取数时刻 2026-10-13 00:10）。

| provider:model | calls | input | output | cacheRead | 账本名义 cost (CNY) | 是否扣余额 |
|---|---|---|---|---|---|---|
| `workbuddy:deepseek-v4.1-flash` | 753 | 2,506,997 | 884,072 | 197,428,992 | 1.4988 | ❌ **免费渠道，不扣** |
| `deepseek-account:deepseek-flash` | 749 | 937,440 | 647,908 | 134,081,792 | 1.0940 | ✅ **真付费**，但全部发生在 18:10–18:48 **旧会话**，与本轮（21:08 后）无关 |
| `buddy:deepseek-v4.1-flash` | 665 | 2,097,421 | 762,239 | 198,006,912 | 1.4441 | ❌ 免费渠道，不扣 |
| `our-free-model:space-bunny-free` | 475 | 2,291,387 | 291,111 | 49,473,803 | 0.0000 | ❌ 免费，账本记 0 |
| `deepseek-official:deepseek-v4-flash` | 9 | 73,279 | 7,638 | 3,840 | 0.0237 | 小额 |
| **合计** | **2651** | **7,906,524** | **2,592,968** | **579,395,547** | **4.0605** | — |

> **数字随时点漂移，引用必须带取数时刻**：队长 23:47 快照为 calls 2555 / cost 3.9052；本文件第 1 版（23:52）为 2645 / 4.0396；本版（00:10）为 **2651 / 4.0605**。差异来自区间内仍在发生的调用（t8 归档收尾 + t9 自身）。

**口径 B 的含义**：这才是团队总消耗的度量 ——
三个免费车道（`workbuddy` + `buddy` + `space-bunny-free`）的**名义成本合计 2.9429 CNY 实际未从余额扣除**，
真正扣余额的只有 `deepseek-account` 的 1.0940 CNY（且属**旧会话**）与 `deepseek-official` 的 0.0237 CNY。

### 3.3 免费车道可靠性与路由事实（供 loop4 路由决策）

取数文件：`~/.dsh/our-free-model/stats.json`（取数时刻 2026-10-13 00:10，sha256 `CEE0330543154554F2E7D37B6C4F6EBC8123D1C76DF632F495B5A30619B7BE3B`）。

| 车道 | calls | failed | 失败率 | 判定 |
|---|---|---|---|---|
| `space-bunny-free` | **490** | 5 | ≈1.0% | ✅ **稳定，可继续作为主力免费车道** |
| `mimo-v2.6-flash-free` | 3 | 2 | ≈67% | ⚠️ 样本极小，暂不作为主力 |
| `deepseek-ai/deepseek-v4.1-flash`（EAC） | 4 | 4 | **100%** | ❌ **实测不可用，已放弃**（用户 21:46 下令） |
| 合计 | 497 | 11 | ≈2.2% | — |

**另两条关键路由事实**：
- **`workbuddy` 今日 761 请求被打爆，限流至 2026-10-13 18:01:36**
  （证据 `~/.dsh/channel-pack/state.json`，`modelRateLimits["deepseek-v4.1-flash"] = 1791885696000`）
  → **loop4 严禁再把主力 hunter 放回 workbuddy**。
- loop4 **开工前必读 `~/.dsh/our-free-model/availability.json`** 按当日 available 定路由；
  **严禁落到 `deepseek-account`**（真付费，已出白名单）。

---

## 4. 能力矩阵等级**建议值**（本轮只读不写，等级更新放 loop4）

> **队长指令（attempt 2 任务书）**：能力矩阵文件本轮**只读不写**，以下只是**建议值**，写在本报告里。

评级纪律：① 严格对照 `security/learning/能力矩阵-赏金能力记分板.md` 的 0–5 rubric；
② **「证明阴性 / 识别防护」最多记 1 级**；③ **未达 3 级不得标 3**；④ **每条等级必须指出对应产物文件**。

### 4.1 建议发生变动的能力项

| 能力项 | 建议 旧→新 | 依据产物（完整文件名） | 为什么是这个级（不更高） |
|---|---|---|---|
| **组件 CVE：Java 反序列化（Shiro rememberMe）** | **0 → 2** | `security/learning/cve/C1-SHIRO-2016-4437-rememberMe反序列化默认密钥.md`、`security/learning/loop3-c-vulhub-report-t7-20261012.md` | 达 2 级：硬编码默认密钥有**代码级证据**（反编译 `ShiroConfig.class`）、3/4 链 OOB 命中、复现率 ≥95%。**不到 3**：CVE 已公开、有现成 ysoserial 模板，且靶场是 vulhub 预置环境，**不是"没给漏洞位置的陌生靶场"** |
| **组件 CVE：Tomcat（PUT CVE-2017-12615）** | **0 → 2** | `security/learning/cve/C2-TOMCAT-2017-12615-PUT上传配置缺陷.md` | 达 2：PUT 尾部斜杠绕过 → 201 → GET 200 回显 `uid=0(root)`，配置层根因有表（`web.xml readonly=false`）。**不到 3**：同上，已知 CVE + 预置环境 |
| **组件指纹 → 版本 → CVE 匹配** | **1 → 2** | `security/learning/cve/C1-SHIRO-2016-4437-rememberMe反序列化默认密钥.md`、`security/learning/_evidence/loop3-t7-c1-rate-and-baseline-20261012.json` | 达 2：能从镜像 digest + classpath 清单（`commons-collections-3.2.1` 而非 4）定位版本并解释"为什么 CC2 链不命中"。**不到 3**：走的是**已知 CVE 清单**去匹配，不是对陌生目标独立指纹识别 |
| **通用 Web：任意文件读取 / LFI-RFI** | **1 → 2** | `security/learning/path-traversal/B1-LFI-01-DVWA文件包含路径穿越与phpfilter源码读取.md`、`security/learning/loop3-b-dvwa-bwapp-report-t4-20261012.md` | 达 2：DVWA low 读到 `/etc/passwd` 明文 5/5 + `php://filter` base64 读源码 5/5，RFI 阴性留证。**不到 3**：DVWA 是**已知漏洞位置的教学靶场** |
| **通用 Web：XSS（存储型）+ 危害证明** | **1 → 2** | `security/learning/xss/B5-XSS-01-DVWA存储型XSS到会话劫持完整链.md` | 达 2：真实 Chromium 执行 → Cookie 外带 → 会话接管 3/3（200 vs 负对照 302）。**不到 3**：同因，教学靶场 |
| **会话固定（Session Fixation）** | **1 → 2** | `security/learning/auth-bypass/B4-SESSION-01-DVWA会话固定与弱会话ID.md` | 达 2：low 档自选 PHPSESSID 登录后保留 3/3，且**识别出档位陷阱**（`impossible` 级阴性）。**不到 3**：同因 |
| **通用 Web：XXE** | **0 → 2** | `security/learning/xxe/B2-XXE-01-bWAPP原生XXE关卡实体展开与外部实体阻断.md`、`security/learning/xxe/N-B03-B04-B05-bWAPP-XXE外部实体未复现.md` | 达 2：内部实体展开 5/5，外部实体阴性给出**运行时根因**（PHP 8.4.24 + libxml 2.15.3 默认不展开 SYSTEM / 未传 `LIBXML_NOENT`）。**不到 3**：同因，且**外部实体未打通** |
| **红蓝对抗（加固 → 绕过迭代）** | **2 → 3** | `security/learning/hardening/A-档验证报告-20261012.md`（P8/P9/P10、§3.1/§3.5/§3.6）、`security/learning/hardening/HARD-02-A档残余绕过与阴性留证.md` | 达 3：**在加固之后的靶场上独立定位并稳定复现** 3 条需处理残余（跨站复位、顶级 GET 写、改密不轮换会话），每条有可复跑 payload + canary 判定。**不到 4**：4 级要求"写 nuclei 规则"——**本轮 0 条自研 nuclei 规则**；且靶场为自建白盒 |

### 4.2 建议**维持原级**的能力项（不升级，写明理由）

| 能力项 | 维持 | 为什么本轮不升级 |
|---|---|---|
| CSRF（通用 Web 侧） | **2** | 本轮 B3 补了"浏览器三形态"维度（form ✅ / nav ✅ / img ❌），但**仍是已知靶场的复现**，未突破 3 级门槛 |
| 误报识别与排除 | **2** | 本轮确有强化实证（主动推翻 2 条假 oracle、14+6+6 条阴性留证、被推翻证据**未删改**），但 rubric 3 级锚定"**陌生本地靶场**独立定位"，本轮未触及 → **保守维持 2**，不因"表现好"而抬级 |
| 自写 Python 取证/利用脚本 | **3** | 新增 `t7-c1-final.py`、`t7-report-selfcheck.py`、`security/learning/_evidence/t5-note-selfcheck.py`、`security/learning/_evidence/loop3-t9-summary.py` 等。**4 级要求写 nuclei 规则/通用 PoC —— 本轮 0 条**，故不升级 |
| 本地结构化学习笔记（七节归档） | **3** | 本轮新增 13 篇（A 2 + B 8 + C 3），七节模板 + 自检块齐备；但 3→4 差别在"能否迁移到赏金目标"，篇数增加不构成跃迁 |
| 证据规范（sha256 / 阴阳清单 / 完整文件名） | **3** | 继续严格执行，且**自主校验脚本抓出多处 hash 漂移与 1 处不存在文件名**（见 §5 教训 8、9）。仍 3 级（4 级锚定赏金目标迁移） |
| SQLi / IDOR / SSTI / 命令注入 | **不变** | **本轮未测**（四目录 md=0）。**不得因"目录空"而调级**，也不得记为阴性 |

---

## 5. 方法论教训（13 条 · 本轮实证，逐条给证据）

### 5.0 ★★★ 三条判据类教训（**并列成条，独立展开**）

> 原文完整版在 `memory/context.md` §11 顶部 `[2026-10-12 23:52] 三条"判据类"教训并列写死` 条目（队长写）。
> 本节只**引用并展开为并列小标题**，不重复原文。**三条地位并列，无主次。**

#### 判据类教训 ① —— Shiro 假 oracle：`rememberMe=deleteMe` 不能判反序列化成败

实测矩阵（`security/learning/_evidence/loop3-t7-c1-matrix-20261012.json`）：不带 cookie → 无 Set-Cookie；
`rememberMe=`（空值）→ false；4 字符垃圾 → **true**；4000 字符垃圾 → **true**；
默认密钥加密的合法序列化流 → **true**；错误密钥同一流 → **true**；`/login`（anon 路径，按 Shiro 逻辑不该解析 rememberMe）→ **true**。

→ **只要 cookie 非空，无论内容与路径一律回 `deleteMe`，零区分度。**

**后果**：`_evidence/t7-c1-bruteforce-out.txt` 中"25 个候选密钥全部 deleteMe=true → 全部解密失败"的结论
**判定依据无效、结论作废**（原文件保留不改，标注为"oracle 失效导致的无效结论"）。**C1 本身不作废**（靠 OOB + `/proc` 独立实证成功）。

#### 判据类教训 ② —— `Runtime.exec()` 异步：`sleep N` 计时不能判 RCE

JVM **不等子进程**就返回 → 用响应耗时差判 RCE 必得假阴性。

铁证 `security/learning/_evidence/loop3-t7-c1-timing-20261012.json`
（sha256 `02d547e655f7327db0bc6844ad02f9586aef9282be6173c6fdf65a96f8860051`）：
三条**都 RCE 成功**的链被文件自判 `executed:false` —— CB1 delta **−0.002s** / CC5 **+0.008s** / CC6 **−0.003s**，
而 `expected_delta_if_exec = 6`。**成功链被自己的文件判成"未执行"**，hunter-web 据此一度误判 C1 失败，后靠 OOB + `/proc` 推翻。

**与教训 ① 的对称关系**：① 是"单边信号恒真"，② 是"单边信号恒假" —— **都是拿不能区分正负的量去判成败**。

#### 判据类教训 ③ —— 任何人的技术方案（包括队长的）都必须先做受控对照

本轮**队长错了三次**，且**三次全部由成员发现，没有一次是队长自查出来的**：

- Ⓐ 断言"t4 报告有笔记 hash 表、5 个 sha256 全失效" → **错**（t4 报告根本没有笔记 hash 表；§1 的「笔记」列只有路径无 sha256）。scribe 顶回，队长认错。
- Ⓑ 提议"用 `BadPaddingException` 当新 oracle 判解密失败" → **错**。hunter-web 做**受控三组对照**证伪：
  错误密钥密文 → **有**该异常；正确密钥+合法序列化 String → **无**；正确密钥+CC6 gadget → **无**。
  **它是单边判据：只在失败时出现，不出现 ≠ 成功**（也可能根本没走到解密）。
  队长原话："我拿'有 deleteMe'当失败，你拿'没 BadPaddingException'当成功——都是拿缺失的信号推断正面事实。"
- Ⓒ 核验 hunter-web 四份证据时，**批量核验脚本大小写归一化有误**，把唯一正确的那份
  （`security/learning/_evidence/loop3-t7-c1-logoracle-20261012.json`）判成 MISMATCH 并要求对方改文件 → **错**。
  逐字符复比确认完全一致，队长已道歉并撤回指令。

**纪律**：不是"队长会错"这种泛泛的免责，而是 ——
**「任何人的技术方案，包括队长的，都必须先做受控对照才能采用。没有对照就没有发言权」**，
这条对成员、对队长、对任何人同样成立。（表述由 hunter-web 修订并被队长采纳，因为顶回靠的不是立场而是**做了三组对照**。）

**正确的 Shiro 成功锚点（收紧表述，别踩第三次同构错误）**：
`AbstractRememberMeManager` 日志 **`:429`** = 解密阶段抛异常（BadPaddingException）→ 必然失败；
**`:431`** = 解密成功、进入反序列化阶段 —— 该阶段**可能成功产出对象**（→ `ClassCastException: java.util.HashSet cannot be cast`）、
**也可能反序列化失败**（→ `SerializationException`），故 `:431` 本身**不是**成功判据；
**真正的成功锚点 = `:431` + `ClassCastException: ... cannot be cast to ...PrincipalCollection`**。
队长独立复算计数：`BadPaddingException` 5 / `:429` 5 / `:431` **3** / `HashSet cannot be cast` **1**。

### 5.1 其余教训表（13 条，含上述三条的表格式登记）

| # | 教训 | 本轮实证 | 落到哪条纪律 |
|---|---|---|---|
| 1 | **假 oracle 之 `rememberMe=deleteMe`**：合法序列化流 / 错误密钥 / 垃圾明文**全部** `deleteMe=true`，**零区分度** | `security/learning/_evidence/loop3-t7-c1-matrix-20261012.json`；被判无效的 `_evidence/t7-c1-bruteforce-out.txt`（**未删改**） | 结论边界：**"25 密钥全失败"作废（判据无效），C1 本身不作废** |
| 2 | **单边判据陷阱**：`BadPaddingException` **只在失败时出现** → "不出现"**不等于**"成功" | `security/learning/_evidence/loop3-t7-c1-badpadding-oracle-20261012.json` | 队长曾提议用它作新 oracle，被受控三组对照证伪。**正解是日志行号锚点**：失败分支 `AbstractRememberMeManager.java:429`、解密成功分支 **`:431`**；⚠️ **`:431` 本身也不是成功判据**，硬锚点必须是 **`:431` + `ClassCastException: java.util.HashSet cannot be cast to ...PrincipalCollection`** |
| 3 | **`Runtime.exec()` 异步 → 时序不能判 RCE**：成功链 delta 实测 −0.002 / +0.008 / −0.003 s，**被文件自己判成 `executed:false`** | `security/learning/_evidence/loop3-t7-c1-timing-20261012.json` | RCE 判据只有 **OOB 外带 + `/proc` 采样（+ 服务端日志锚点）** |
| 4 | **`docker logs` 行数增量不能锚定事件**：日志轮转（早先快照 461 行 vs 后续 443 行）给出假的 `new_log_lines:0` | `security/learning/loop3-c-c1-oracle-verdict-20261012.md` §3 | 锚定日志事件**必须带时间戳或按内容匹配** |
| 5 | **`kali-run.py` 在 stdout 末尾追加 JSON** → 下游"取第一行"会把 JSON 拼进数据 | C1 取证窗口内白烧约 **15 min**；铁证在 `security/learning/_evidence/t7-shiro-full-dockerlogs.txt`（`A cookie header was received [rc": 0, ...] that contained an invalid cookie`） | 修法：**按 base64 字符集正则取最长串** `[A-Za-z0-9+/]{40,}={0,2}`，不取"第一行" |
| 6 | **"勘误比修改贵，但勘误才是对的"** —— 不改他人已锁定产物，只**追加勘误段** | t11 处置：队长误判"t4 报告有 5 篇笔记 hash 表"，实为**汇报消息里的自报值**，责任错安在报告上；队长认错并批准"不伪造、只加勘误" | 已归档产物**只追加、不改写**；勘误段须注明原值与修订理由 |
| 7 | **"目录存在 ≠ 数据在此"**：不能凭路径名推断存储位置 | `security/learning/_evidence/loop3-vulhub-baseline-20261012-230400.json`（v2，含 RETRACTED 标注）；settings-store.json 的 `CustomWslDistroDir=D:\Docker\wsl\DockerDesktopWSL`；D:\Docker 树 9.52 GB vs C 盘 `%LOCALAPPDATA%\Docker` 仅 21.35 MB | 判断存储位置**必须读配置 + 对候选位置分别测实际占用体积** |
| 8 | **改已归档文件必须同步重报新 sha256**（规矩立完当天就被立规矩者自己触发） | scribe 把 `oob.jsonl` 的 hash 抄成旧值，**被自检脚本抓出**（`security/learning/_evidence/t5-note-selfcheck.py`） | 任何成员修改已归档文件 → **必须重算并同步重报 hash** |
| 9 | **"凭印象写文件名 = 造引用"** | scribe 写出不存在的 `t7-shiro-jar-ce.sh`，被自检抓出 | 引用必须**逐条存在性自检，missing 必须为 0** |
| 10 | **"不要因为队长说了就照做，事实优先"** | scribe 顶回队长"t4 报告有笔记 hash 表"的错误结论，队长认错 | 成员对上级结论**有核验义务**，不是执行义务 |
| 11 | **"队长提供的技术方案也可能错，成员必须验证后再执行"** | 本轮队长错了三次：① hash 表误判；② `BadPaddingException` 提议（被证伪）；③ 核验脚本大小写归一化有误致误判。**被顶回两次以上** | 方案类指令落地前**先做受控小实验**，用对照证真伪。**"没有对照就没有发言权"**，对成员、对队长、对任何人同样成立 |
| 12 | **首次证据不干净要如实写** | C2 首次 PUT 实测 **204 不是 201**、上传前 GET 是 **200 不是 404**（JSP 首编耗时）；scribe 以第二轮为准并**如实标注** | 不为"好看"修掉首轮原始记录；**保留原始 + 标注偏差原因** |
| 13 | **跨文档汇总时，每个数字都要指回源文件行号**（本文件第 1 版的教训） | mentor-loop3 第 1 版把 A 档写成"残余 4 条 / 阴性 6 条"，源文件实为"残余 6 条 / 阴性 14 条"；本次逐条 `Test-Path` + 哈希复核后纠正，**第 1 版原文不删** | 汇总表每个数字旁**标源文件名 + 章节/行号**；汇总者必须**回源核对**，不得照抄下游结论或凭印象填 |
| 14 | ★★★ **转录/继承来的具体事实必须实读源文件复核——包括自己刚写进教训清单的那条**（mentor-final 本人踩） | 本人写了教训 13「每个数字都要指回源文件」，**却在 RISK_001 上反向误报**：直接继承 t7 汇报文本里的"compose 写 8080:8080"，未实读 `D:\dsh-vulhub\tomcat-CVE-2017-12615\docker-compose.yml`（实为 82 B / sha256 `7e29e11e…5bbb8` / 已含 `127.0.0.1:18082:8080`）。经队长指出后实读才确认。**成因是四层转录、实读 0 次**：t7 汇报 → `progress.md` §13 → `memory/context.md` §11 → 我的汇总 | ① **写"某文件是 X"之前必须实读该文件**，不能凭上游任何人的任何文本；② **汇总时对每条具体事实（端口/路径/行号/hash）标记来源是「实读」还是「转录」**，转录的一律降级为待核；③ **自己写的纪律不豁免**——教训清单里有的条款，恰恰最容易在赶工时被自己跳过 |

---

## 6. loop4 待办（**A7 必须单列**）

### 6.1 ★ A7 · `/__reset` 跨站来源校验修复（**loop4 范围**）

- **归属**：**loop4**（不在 loop3 收尾内执行）。
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
  | `same_site_form_body` | 同源 Origin + body | 按设计**允许**（用于证明不是"一刀切全拒"），但需在报告里注明这是**设计意图**不是绕过成功 |
  | `no_origin_at_all` | 完全不带 Origin（curl 风格） | `reset_triggered=false` / `audit_delta=0`（缺失即拒） |

- **③ 归属标注**：**loop4** 范围，写入 `security/learning/progress.md` §11.8 待办 + `memory/context.md` §11。

### 6.2 其余 loop4 待办（每条带核对口径）

| # | 待办 | 目标 / 输入产物 / 验收标准 | 核对口径（怎么复现、怎么验证、失败长什么样） |
|---|---|---|---|
| 1 | **B1/C6 顶级 GET 写入口修复** | 给 `wallet_transfer`（`app.py:1185-1196`）与 `change_password`（`app.py:1246-1254`）补 `check_write`，或把方法+CSRF 校验**上提到路由层/装饰器**。输入：`security/learning/hardening/HARD-02-A档残余绕过与阴性留证.md` §2.2/§6（P0-1）。验收：两个入口 `GET` → 405、状态不变 | 复现：`curl -b <jar> "http://127.0.0.1:18096/wallet/transfer?to=bob&amount=7&csrf_token=<有效>"` → 修复前 200「转账成功」、修复后 405；改密同理查库 `users.password` 是否变化。**失败样子**：仍 200 且余额/密码变了 |
| 2 | **B3 改密后销毁会话** | `change_password` 成功后 `DELETE FROM sessions WHERE user_id=?`（对齐 A4）。输入：同上 §6（P1）。验收：改密后旧 Cookie 打 `/home` → 302 | 复现：改密 → 用旧 Cookie `GET /home`；再 `select count(*) from sessions`。**失败样子**：旧 Cookie 仍 200、sessions 行未减 |
| 3 | **Cookie 属性取证（A 档 §4.1 未验证项）** | 抓一次 `Set-Cookie`，确认 `HttpOnly` / `SameSite` / `Secure`。输入：`security/learning/hardening/A-档验证报告-20261012.md` §4.1。验收：把 §3.1/§3.5 的严重性评级**钉死** | 复现：登录后抓响应头 `Set-Cookie`，逐条读属性。**失败样子**：属性缺失 → 说明跨站表单可能带上会话 Cookie，D1/B1C6 严重性**上调** |
| 4 | **首批自研 nuclei 规则（把"自写脚本 3 级"往 4 级抬）** | 对已验证的 LFI / Shiro 指纹写模板。输入：`security/learning/path-traversal/B1-LFI-01-DVWA文件包含路径穿越与phpfilter源码读取.md`、`security/learning/cve/C1-SHIRO-2016-4437-rememberMe反序列化默认密钥.md`。验收：规则对本地靶场复现命中、对他环境不误报 | 复现：`nuclei -t <规则> -u 127.0.0.1:18081`。**失败样子**：0 命中或大面积误报 |
| 5 | **B 档四类空白补齐（P0）** | `idor` / `command-injection` 优先（只读命令 `id`/`whoami`、越权最多 2–3 个他人账号）。输入：`security/learning/N-LOOP3-B-COVERAGE-B档分类覆盖声明.md` §3 起手式。验收：四目录**至少两类**有实证 | 复现：按 §3 落点表逐档测。**失败样子**：把"未测"当"阴性"写进笔记 |
| 6 | **A1 窗口测量** | 降并发（5/10/20）跑一遍，给出成功率曲线，为报告写"复现条件"。输入：`security/learning/hardening/A-档验证报告-20261012.md` §6 建议 5 | 复现：按并发档各跑 ≥6 轮。**失败样子**：只有单点 30 并发的数据，写不出曲线 |
| 7 | **Docker Desktop 关闭决策** | **需先报队长许可**，不得自行关闭 | 现状：shiro 容器 Up、tomcat Exited(143) 保留现场；pentagi 4 容器 2026-10-12 20:49 已 stop 未删 |
| ~~8~~ | ~~**RISK_001：tomcat compose 端口缺 hostIP**~~ | ❌ **已撤销 —— 见下方说明，本条是反向误报** | — |

> **⚠️ RISK_001 已撤销（2026-10-13 00:26，mentor-final 实读复核）**
> 本文件第 1 版与我在 t9 汇报中均称「tomcat 的 `docker-compose.yml` 端口写 `8080:8080` 缺 hostIP，
> 今天谁执行 `docker compose up` 谁就会把 Tomcat 绑到 `0.0.0.0` 暴露到物理 LAN」。
> **该结论不成立。** mentor-final 于 00:25 **实读源文件**确认：
> `D:\dsh-vulhub\tomcat-CVE-2017-12615\docker-compose.yml` = **82 B**，
> sha256 `7e29e11e5482fe086a23bd6497807dd10ec5d3ed4384c3cbec2b5f92dcf5bbb8`，mtime **2026-10-12 23:02:10**，
> 内容已含 `- "127.0.0.1:18082:8080"` —— **已绑回环**。该文件由 range-admin 在 t6 期间修复。
> **本轮不存在 LAN 暴露风险，也不需要再修。** 独立佐证见
> `security/learning/cve/C2-TOMCAT-2017-12615-PUT上传配置缺陷.md` §4.7（物理网卡 curl exit 7 实测闭环）。
>
> **误报成因（三层转录，实读 0 次）**：t7 汇报文本生成于文件修复之前 → hunter-web **照抄汇报文本**写进 `progress.md` §13 →
> 队长**照抄汇报文本**转录进 `memory/context.md` §11 → mentor-final 汇总时又**继承**了一份。
> **四份材料里真读源文件的只有 0 份。** 这条正是本文件 §5 教训 14 的活教材：
> 我在教训清单里写了"每个数字都要指回源文件"，**唯独这条没指**。

---

## 7. 引用存在性自检（可复跑，missing 必须为 0）

**本轮实测（2026-10-13 00:10，逐条 `os.path.exists` + sha256 重算）**：
**A 档 5/5 + B 档 12/12 + C 档 11/11 + 补充 3/3 = 31/31 存在，missing = 0。**

```powershell
# 引用存在性 + hash 复核（只读，零靶场访问）
$py = 'C:\Users\Administrator\AppData\Local\Programs\Python\Python312\python.exe'
& $py 'C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\loop3-t9-summary.py'
```

期望输出含：`artifacts missing: 0`、`A 档 产物 5/5 存在`、`B 档 产物 12/12 存在`、`C 档 产物 11/11 存在`。

**关键产物 sha256（本轮实测，取数时刻 2026-10-13 00:10）**：

| 文件（完整名，相对 `security/learning/`） | 字节 | sha256 |
|---|---|---|
| `hardening/A-档验证报告-20261012.md` | 34852 | `F1F23606FEE8C8230EEB571478F88F60132EC8C8E326DA64202E44F60448B19F` |
| `hardening/A-档加固实施报告-t2-20261012.md` | 21493 | `FBAD08DA39EF709226D6F31C7B951CF75E1194D2BC3CA382480B7E06D14D481E` |
| `hardening/HARD-01-A档六处加固原理与落地diff.md` | 44409 | `ADD0CEA4CB3E0D4F0B3F4298BA0A6208720DA321C2C07E0D3FF7831712C99CE7` |
| `hardening/HARD-02-A档残余绕过与阴性留证.md` | 33171 | `5DCCB1794ADC4BA79E76F4093DE30AC4955C94FE10469E8653CCE216176923F3` |
| `_evidence/loop3-a-verify-20261012-212153.json` | 37941 | `614F20B2D7D4E74B7A94708D99DA4E6425FD0076F68705360A37E5B9835DFC3E` |
| `loop3-b-dvwa-bwapp-report-t4-20261012.md` | 26080 | `B6AC6E2AB3A8EBC5A49DD3A3F0E0950DB646BD2AAD5971B845336BCFF04EF0C3` |
| `path-traversal/B1-LFI-01-DVWA文件包含路径穿越与phpfilter源码读取.md` | 10261 | `AAF09D0444A21690FE39B281F0769E4F2FEF44E9567BE56169E7925253531859` |
| `xxe/B2-XXE-01-bWAPP原生XXE关卡实体展开与外部实体阻断.md` | 19183 | `A5CB26776F9EF679DB73FC73E693C3393B0A2A05C0E8AF33FD0E57A77D0FB0A9` |
| `csrf/B3-CSRF-01-bWAPP真实CSRF与token对照.md` | 18903 | `06992D3DF73B154AF31C22101E252D3F6B28B570F403F2AEADAD8FFADFCD864A` |
| `auth-bypass/B4-SESSION-01-DVWA会话固定与弱会话ID.md` | 17487 | `FBB98315B1D38A6144167C2548639786C3D931ECA537E28C5AA0D0324667062A` |
| `xss/B5-XSS-01-DVWA存储型XSS到会话劫持完整链.md` | 16556 | `DF1B6E3D71FAD2B4C830116F1EF7AD94591628041C88C6A91A284CD764B73137` |
| `xxe/N-B03-B04-B05-bWAPP-XXE外部实体未复现.md` | 13014 | `8200B42A0063932E67F637B65FC024D040CB1B863FFC7E4F7B4E2926E8F1DE3C` |
| `csrf/N-B01-B02-B06-CSRFimg形态与RFI未复现.md` | 13284 | `4A934DD3B17F9C800D9B3BDDA8B8314697C27337D18100F10B3733441D77B484` |
| `N-LOOP3-B-COVERAGE-B档分类覆盖声明.md` | 24219 | `EBE5A1BEDBAE1CB90F1DD200AD57CAA1CCE3B28847A788AE60315A28707C6BA0` |
| `_evidence/verified-loop3-b-20261012-2236.md` | 31185 | `3C6254D1A4061D5D4D2680803965EFD5602A130E19F930DC296637CE16160CD4` |
| `_evidence/verified-loop3-b-20261012-2236.json` | 19041 | `A9274A92E2C5E492109BA0B58811E81D3EEB8B83BC3410F11691792A73006804` |
| `_evidence/loop3-kali-baseline-20261012-212122.json` | 29241 | `1F4ED4B34B173B664FAEF4C735AD0D7080F8D747DF4FE80D9CB47DA2BF5025F0` |
| `loop3-c-vulhub-report-t7-20261012.md` | 24825 | `E784C5DE71040424D57762A84030EC140EA6B0001731963DE707855DB3883EE8` |
| `loop3-c-c1-oracle-verdict-20261012.md` | 17132 | `17AC0E21C2ACE1A6954619B1109D7D1C4566AA1AD6FAD0AEF7678E2739BFCC6A` |
| `cve/C1-SHIRO-2016-4437-rememberMe反序列化默认密钥.md` | 25216 | `625B312FC14C07E4551508B39A6250F3FA34BAF70FFA55523514A2172DF3D89B` |
| `cve/C2-TOMCAT-2017-12615-PUT上传配置缺陷.md` | 18729 | `79BB2717946A8D276F7C6E9B10EA3B31D52BA8BD7D7D5289CABEB37BBFE66D06` |
| `cve/N-C01-COMMONS-COLLECTIONS-2未复现.md` | 14881 | `1025F729E50B1DD8E7A3291330798ECCFAAF6DF1BD11855C6B22BB58A2A0FF066` |
| `_evidence/loop3-t7-c1-rate-and-baseline-20261012.json` | 4785 | `68579107F657A551CA7032B456ECFEC55863CDBF2E90D59CBA65DD28D79D4A7E` |
| `_evidence/t7-shiro-full-dockerlogs.txt` | 56159 | `6B37C61C4D4FCFED6036D7CE63F0323ADFC9BC0F7F9B8ACB6C66ABF2DB5D116B` |
| `_evidence/loop3-t7-c1-log-inventory-20261012.json` | 3500 | `D9999386486CD56F2FFBE6C1EC2170FD96CE1777760290FD093B388CCC578074` |
| `_evidence/loop3-vulhub-baseline-20261012-230400.json` | 25331 | `9405A117308A0235F55B1FDBD306CB63B26DB6848E9268CB36DBDD84BD87DF26` |
| `_evidence/loop3-t7-c1-matrix-20261012.json` | 1476 | （见 `_evidence/loop3-t7-c1-matrix-20261012.json` 本体） |
| `_evidence/loop3-t7-c1-timing-20261012.json` | 2868 | `02D547E655F7327DB0BC6844AD02F9586AEF9282BE6173C6FDF65A96F8860051` |
| `_evidence/loop2-verify-supplement4-20261012-201557.json` | 6288 | `B105B1DA8B82F802C137217F8112CF3DA8DE099E717F8761F3ABE6C1B8695D9F` |
| `_evidence/t5-note-selfcheck.py` | 5434 | `CA321B59F6AF0990D3B05CB2A86777C6977CCC78CB474031DFA879467F28339E` |

> **⚠️ 一处需要更正我自己的说法（2026-10-13 00:26，mentor-final）**：
> 本文件第 1 版写「`loop3-c-c1-oracle-verdict-20261012.md` 文件内自报其自身 sha256 为 `6810aa90…`，与实测不符」。
> mentor-final 于 00:25 **实读该文件复核**：`grep '6810aa90'` 在当前版本中 **命中 0 次**，
> 实测 sha256 = **`17AC0E21C2ACE1A6954619B1109D7D1C4566AA1AD6FAD0AEF7678E2739BFCC6A`**（17132 B）与队长独立复算一致。
> **该自引用漂移已在文件内被修复，不再存在。**（`6810aa90…` 是 hunter-web 23:46 落盘时点记录的旧值，
> 后续勘误重写已同步为 `17ac0e21…`。）
> **保留此条是因为它指向一个真实机制**：自我引用 hash 天然会因自身内容变化而失效——
> 这正是教训 8「改已归档文件必须同步重报新 sha256」要纪律化的原因。
> ⚠️ **归属**：该文件属 hunter-web（t8）责任范围，mentor-final **未修改**该文件，仅记录机制。

---

## 8. 交付物清单

| 文件（绝对路径） | 说明 |
|---|---|
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\loop3-trilateral-comparison-20261012.md` | **本文件**（三档横向对比表与复盘，第 2 版） |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\loop3-t9-summary.py` | 取数与自检脚本（零网络请求，可复跑） |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\loop3-t9-summary-20261012.json` | 机器可读取数结果（三档产物 hash / 目录扫描 / 成本双口径 / 免费车道可靠性） |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\progress.md` §11.8 | 循环记录 Loop 3（回写） |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\memory\context.md` §11 / §12 | 待办（含 A7）与教训（回写） |