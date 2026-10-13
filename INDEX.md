# bounty-forge 总索引 —— loop3 产物归档

## 0. 归档说明

- **归档时刻**：2026-10-13 00:33:10 (Asia/Shanghai, UTC+08:00)
- **源目录**：`C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning`
- **目标目录**：`D:\bounty-forge`
- **文件总数**：**369** 个（报告/笔记 39 + 原始证据 330）
- **校验方式**：`shutil.copy2` 只读复制（保留 mtime）→ 复制后对**目标文件**重新流式计算 sha256 与源文件逐一比对，同时比对 mtime（秒级）
- **校验结果**：**MISMATCH = 0**
- **源目录保护**：全程只读（`copy2` 读取 + 哈希读取），未对源目录执行任何写入/删除/改名；仅目标端同名旧副本会被覆盖以保证内容与源一致

### 0.1 三档划分依据（逐条实读，非转录）

权威依据是 `security/learning/progress.md` **§11.8.2「三档账目」表（第 349–363 行）**，已实读该段；各笔记自身的「编号 / 靶场」抬头字段亦逐篇实读（每篇首 14 行），两者一致才定档。

- **A 档 · 加固复核（Loop 3 · t1/t2）**
  - 依据：progress.md §11.8.2：A 档 confirmed 12 项（P1–P12）、新增笔记 2 篇（HARD-01/02）、产出为加固有效性判定与残余面，新挖漏洞面 0
- **B 档 · DVWA/bWAPP 原生漏洞复现（Loop 3 · t4/t5）**
  - 依据：progress.md §11.8.2：B 档 confirmed 5（B1–B5）、阴性留证 6（N-B01…N-B06）、严重度 High 3 / Medium 2、新挖漏洞面 5
- **C 档 · Vulhub CVE 复现（Loop 3 · t7/t8）**
  - 依据：progress.md §11.8.2：C 档 confirmed 2（C1 Shiro、C2 Tomcat）、阴性 6（N-C01…N-C06）、被推翻错误判据 2（deleteMe 无区分度、sleep 计时无区分度）、Critical 2 但均为已公开 CVE 复现、非发现型
- **t5 档 · target-site-lab:8095 自建靶场挖洞（VER-01…VER-15）**
  - 依据：各笔记抬头「编号：来源 HUNT-0x，t5 判定 confirmed」+「靶场：target-site-lab http://127.0.0.1:8095」（逐篇实读）。该批 15 篇不在 progress.md §11.8.2 三档表内，任务书亦未单列 → 本次新开 T5 档独立归档，不并入 B 档
- **总账与方法论（跨档，不计漏洞数）**
  - 依据：progress.md = 纵向流水与三档账目；learning-path.md = 学习路径；next-round-plan.md = 下一轮方案；能力矩阵 = 横向记分板。均非漏洞条目

### 0.2 必须一起读的三条口径修正（任务书 vs 实测）

1. **证据文件数 297 → 实测 330。** 297 是 `_evidence/` **根目录平铺**的文件数；另有 **33** 个位于 `loop2-verify-sandbox/` 与 `sqmap-809*` 等子目录中，合计 330。本次归档**全部 330 个**都收了，未做取舍。
2. **`auth-bypass/` 目录被整目录划给 B 档 —— 实读后拆开。** 该目录是混装：`B4-SESSION-01-DVWA会话固定与弱会话ID.md` 抬头为「编号：B4-SESSION-01（Loop 3 B 档，t4）」、靶场 Kali VM 内 DVWA → 属 **B 档**；而同目录 `VER-03 / VER-04 / VER-10 / VER-13` 抬头为「来源 HUNT-0x，t5 判定 confirmed」、靶场 `target-site-lab http://127.0.0.1:8095` → 属 **t5 档，不是 B 档**。按目录名一刀切会把 4 篇 t5 笔记错记进 B 档。
3. **t5 的 15 篇 target-site-lab 笔记任务书未单列 → 本次新开 T5 档独立归档。** 它们既不在 `progress.md` §11.8.2 三档表内，也不在任务书给定的 B 档清单内，强行并入 B 档会污染 B 档「confirmed 5」的账目。新增 T5 档是本次归档的**唯一结构调整**，所有文件一律不丢、不合并、不改名。

### 0.3 后续校验方式

- 证据一键校验：`cd /d D:\bounty-forge\evidence` 后对 `_sha256-manifest.txt` 逐行比对（sha256sum 格式，330 行）
- manifest 自身 sha256：见 §3
- 报告/笔记条目：§1 表内每行给出 sha256 与绝对路径，可逐条比对

---

## 1. 报告 / 笔记索引（按档位）

每条含：条目名 / 绝对路径 / 大小 / sha256 / 所属档位 / 漏洞ID / 一句话结论。
「漏洞ID」取自笔记抬头「编号」字段与正文 CVE 号（实读提取）；提取不到写 `-`，**不推测**。

### 1.1 A 档 · 加固复核（Loop 3 · t1/t2） —— 4 条

| # | 条目名 | 归档绝对路径 | 源相对路径 | 大小(B) | sha256 | 档位 | 漏洞ID | 一句话结论 |
|---|---|---|---|---|---|---|---|---|
| 1 | A-档加固实施报告-t2-20261012.md | `D:\bounty-forge\reports\a-档\hardening\A-档加固实施报告-t2-20261012.md` | `hardening/A-档加固实施报告-t2-20261012.md` | 21493 | `fbad08da39ef709226d6f31c7b951cf75e1194d2bc3ca382480b7e06d14d481e` | A | - | A 档加固实施报告：target-site-lab/app.py（Loop 2 · t2） |
| 2 | A-档验证报告-20261012.md | `D:\bounty-forge\reports\a-档\hardening\A-档验证报告-20261012.md` | `hardening/A-档验证报告-20261012.md` | 34852 | `f1f23606fee8c8230eeb571478f88f60132ec8c8e326da64202e44f60448b19f` | A | - | 只复核、零重跑。未发起任何 /__reset，未改动 app.py / lab.db，未访问任何非回环目标。 |
| 3 | HARD-01-A档六处加固原理与落地diff.md | `D:\bounty-forge\reports\a-档\hardening\HARD-01-A档六处加固原理与落地diff.md` | `hardening/HARD-01-A档六处加固原理与落地diff.md` | 44409 | `add0cea4cb3e0d4f0b3f4298ba0a6208720da321c2c07e0d3ff7831712c99ce7` | A | HARD-01 | 已在本机靶场端到端实证（非推测），加固实施（Loop 2 · t2）＋ 独立复核（Loop 3 · t1）双轮完成 |
| 4 | HARD-02-A档残余绕过与阴性留证.md | `D:\bounty-forge\reports\a-档\hardening\HARD-02-A档残余绕过与阴性留证.md` | `hardening/HARD-02-A档残余绕过与阴性留证.md` | 33171 | `5dccb1794adc4ba79e76f4093de30ac4955c94fe10469e8653cce216176923f3` | A | HARD-02 | 中危（Medium） —— 主干缺陷已封，残余面集中在"不可逆操作被跨站触发"与"两个写入口漏接门禁" |

### 1.2 B 档 · DVWA/bWAPP 原生漏洞复现（Loop 3 · t4/t5） —— 9 条

| # | 条目名 | 归档绝对路径 | 源相对路径 | 大小(B) | sha256 | 档位 | 漏洞ID | 一句话结论 |
|---|---|---|---|---|---|---|---|---|
| 1 | B1-LFI-01-DVWA文件包含路径穿越与phpfilter源码读取.md | `D:\bounty-forge\reports\b-档\path-traversal\B1-LFI-01-DVWA文件包含路径穿越与phpfilter源码读取.md` | `path-traversal/B1-LFI-01-DVWA文件包含路径穿越与phpfilter源码读取.md` | 10261 | `aaf09d0444a21690fe39b281f0769e4f2fef44e9567be56169e7925253531859` | B | B1-LFI-01（Loop 3 B 档，t4） | 高危（High）——本地文件读取；在真实应用中读取配置/密钥类文件时可直接升级为凭据泄露 |
| 2 | B2-XXE-01-bWAPP原生XXE关卡实体展开与外部实体阻断.md | `D:\bounty-forge\reports\b-档\xxe\B2-XXE-01-bWAPP原生XXE关卡实体展开与外部实体阻断.md` | `xxe/B2-XXE-01-bWAPP原生XXE关卡实体展开与外部实体阻断.md` | 19183 | `a5cb26776f9ef679db73fc73e693c3393b0a2a05c0e8af33fd0e57a77d0fb0a9` | B | B2-XXE-01（Loop 3 B 档，t4） | Low（低危） —— 2026-10-12 由 Medium 下调（verifier t10 独立复核、队长采纳）。可利用性实测为零，唯一实测影响是 low 档 display_errors 回显 PHP Warning… |
| 3 | N-B03-B04-B05-bWAPP-XXE外部实体未复现.md | `D:\bounty-forge\reports\b-档\xxe\N-B03-B04-B05-bWAPP-XXE外部实体未复现.md` | `xxe/N-B03-B04-B05-bWAPP-XXE外部实体未复现.md` | 13014 | `8200b42a0063932e67f637b65fc024d040cb1b863ffc7e4f7b4e2926e8f1de3c` | B | N-B03 / N-B04 / N-B05（Loop 3 B 档阴性归档，t5） | 未复现（阴性） —— 教科书 XXE 的三条主攻击链在本运行时全部未成立 |
| 4 | B3-CSRF-01-bWAPP真实CSRF与token对照.md | `D:\bounty-forge\reports\b-档\csrf\B3-CSRF-01-bWAPP真实CSRF与token对照.md` | `csrf/B3-CSRF-01-bWAPP真实CSRF与token对照.md` | 18903 | `06992d3df73b154af31c22101e252d3f6b28b570f403f2aeadad8ffadfcd864a` | B | B3-CSRF-01（Loop 3 B 档，t4） | bWAPP 原生漏洞复现（非自建靶点、非发现型） |
| 5 | N-B01-B02-B06-CSRFimg形态与RFI未复现.md | `D:\bounty-forge\reports\b-档\csrf\N-B01-B02-B06-CSRFimg形态与RFI未复现.md` | `csrf/N-B01-B02-B06-CSRFimg形态与RFI未复现.md` | 13284 | `4a934dd3b17f9c800d9b3bdda8b8314697c27337d18100f10b3733441d77b484` | B | N-B06（CSRF img 形态）、N-B01（DVWA RFI）、N-B02（`data://` 包装器）（Loop 3 B 档阴性归档，t5） | 未复现（阴性） —— 三条攻击形态在本环境均未成立 |
| 6 | B5-XSS-01-DVWA存储型XSS到会话劫持完整链.md | `D:\bounty-forge\reports\b-档\xss\B5-XSS-01-DVWA存储型XSS到会话劫持完整链.md` | `xss/B5-XSS-01-DVWA存储型XSS到会话劫持完整链.md` | 16556 | `df1b6e3d71fad2b4c830116f1ef7ad94591628041c88c6a91a284cd764b73137` | B | B5-XSS-01（Loop 3 B 档，t4） | DVWA 原生漏洞复现（DVWA 自带的故意漏洞关卡，非自建靶点） |
| 7 | loop3-b-dvwa-bwapp-report-t4-20261012.md | `D:\bounty-forge\reports\b-档\loop3-b-dvwa-bwapp-report-t4-20261012.md` | `loop3-b-dvwa-bwapp-report-t4-20261012.md` | 26080 | `b6ac6e2ab3a8ebc5a49dd3a3f0e0950db646bd2aad5971b845336bcff04ef0c3` | B | - | Loop 3 · B 档挖掘报告：DVWA / bWAPP 补空白类别（t4） |
| 8 | N-LOOP3-B-COVERAGE-B档分类覆盖声明.md | `D:\bounty-forge\reports\b-档\N-LOOP3-B-COVERAGE-B档分类覆盖声明.md` | `N-LOOP3-B-COVERAGE-B档分类覆盖声明.md` | 24219 | `ebe5a1bedbae1cb90f1dd200ad57caa1cce3b28847a788ae60315a28707c6ba0` | B | LOOP3-B-COVERAGE（覆盖声明，非漏洞笔记，t5） | 归档声明。本篇不含任何漏洞结论，只声明 B 档的测试覆盖边界，防止下轮误读为空目录 = 漏归档 |
| 9 | B4-SESSION-01-DVWA会话固定与弱会话ID.md | `D:\bounty-forge\reports\b-档\auth-bypass\B4-SESSION-01-DVWA会话固定与弱会话ID.md` | `auth-bypass/B4-SESSION-01-DVWA会话固定与弱会话ID.md` | 17487 | `fbb98315b1d38a6144167c2548639786c3d931eca537e28c5aa0d0324667062a` | B | B4-SESSION-01（Loop 3 B 档，t4） | DVWA 原生漏洞复现（DVWA 关卡作者在代码注释里明确写了"低级别下我们想允许会话固定攻击"） |

### 1.3 C 档 · Vulhub CVE 复现（Loop 3 · t7/t8） —— 6 条

| # | 条目名 | 归档绝对路径 | 源相对路径 | 大小(B) | sha256 | 档位 | 漏洞ID | 一句话结论 |
|---|---|---|---|---|---|---|---|---|
| 1 | C1-SHIRO-2016-4437-rememberMe反序列化默认密钥.md | `D:\bounty-forge\reports\c-档\cve\C1-SHIRO-2016-4437-rememberMe反序列化默认密钥.md` | `cve/C1-SHIRO-2016-4437-rememberMe反序列化默认密钥.md` | 25216 | `625b312fc14c07e4551508b39a6250f3fa34baf70ffa55523514a2172df3d89b` | C | C1-SHIRO-01（Loop 3 · C 档，t7 复现 / t8 归档） / CVE-2016-4437 | 严重（Critical） —— 未认证远程代码执行，容器内 root |
| 2 | C2-TOMCAT-2017-12615-PUT上传配置缺陷.md | `D:\bounty-forge\reports\c-档\cve\C2-TOMCAT-2017-12615-PUT上传配置缺陷.md` | `cve/C2-TOMCAT-2017-12615-PUT上传配置缺陷.md` | 18729 | `79bb2717946a8d276f7c6e9b10ea3b31d52ba8bd7d7d5289cabeb37bbfe66d06` | C | C2-TOMCAT-01（Loop 3 · C 档，t7 复现 / t8 归档） / CVE-2017-12615 | 严重（Critical） —— 未认证任意文件上传 → JSP 执行 → 容器内 root RCE |
| 3 | N-C01-COMMONS-COLLECTIONS-2未复现.md | `D:\bounty-forge\reports\c-档\cve\N-C01-COMMONS-COLLECTIONS-2未复现.md` | `cve/N-C01-COMMONS-COLLECTIONS-2未复现.md` | 14881 | `1025f729e50b1dd8e7a3291330798eccfaf6df1bd11855c6b22bb58a2a0ff066` | C | N-C01-SHIRO-02（Loop 3 · C 档，t7 复现 / t8 归档） / CVE-2016-4437 | 阴性结论 + 判据证伪记录，不是漏洞条目 |
| 4 | loop3-c-vulhub-report-t7-20261012.md | `D:\bounty-forge\reports\c-档\loop3-c-vulhub-report-t7-20261012.md` | `loop3-c-vulhub-report-t7-20261012.md` | 26573 | `911f25194392d086beea7f21b737fecd4e92111a460edb6f3a88753b378a4a66` | C | CVE-2016-4437;CVE-2017-12615 | Loop 3 · C 档复现报告：Vulhub Shiro rememberMe 反序列化 + Tomcat PUT 上传（t7） |
| 5 | loop3-c-c1-oracle-verdict-20261012.md | `D:\bounty-forge\reports\c-档\loop3-c-c1-oracle-verdict-20261012.md` | `loop3-c-c1-oracle-verdict-20261012.md` | 17132 | `17ac0e21c2ace1a6954619b1109d7d1c4566aa1ad6fad0aef7678e2739bfcc6a` | C | - | ⚠ 源文件编码异常（检出 Unicode 私用区字符 55 处 —— **源文件编码损坏**（UTF-8 字节被按 GBK 二次解码），非读取方式问题），结论未提取 |
| 6 | loop3-trilateral-comparison-20261012.md | `D:\bounty-forge\reports\c-档\loop3-trilateral-comparison-20261012.md` | `loop3-trilateral-comparison-20261012.md` | 43534 | `1b583e985305d4d2ced7214b7a93bdd818d0799fa20e56e7ae730ba30beaecaa` | C | CVE-2016-4437;CVE-2017-12615 | Loop 3 三档横向对比表与复盘（A 档收尾 / B 档 DVWA·bWAPP / C 档 Vulhub CVE） |

### 1.4 t5 档 · target-site-lab:8095 自建靶场挖洞（VER-01…VER-15） —— 16 条

| # | 条目名 | 归档绝对路径 | 源相对路径 | 大小(B) | sha256 | 档位 | 漏洞ID | 一句话结论 |
|---|---|---|---|---|---|---|---|---|
| 1 | VER-01-并发下单TOCTOU把余额扣成负数.md | `D:\bounty-forge\reports\t5-target-site-lab\business-logic\VER-01-并发下单TOCTOU把余额扣成负数.md` | `business-logic/VER-01-并发下单TOCTOU把余额扣成负数.md` | 12157 | `f34d92d18955663cb0532176d2919daa27f569915a769513478498a9b775f5f8` | T5 | VER-01（来源 HUNT-01，t5 判定 confirmed） | 高危（High） |
| 2 | VER-02-业务接口漏接CSRF校验且不限方法.md | `D:\bounty-forge\reports\t5-target-site-lab\business-logic\VER-02-业务接口漏接CSRF校验且不限方法.md` | `business-logic/VER-02-业务接口漏接CSRF校验且不限方法.md` | 9517 | `07f2714a99a6c4c4aaf0282918c334ef6696cbe9aa71c531d8a2c2788e9a5e95` | T5 | VER-02（来源 HUNT-02，t5 判定 confirmed） | 中危（Medium） |
| 3 | VER-06-__reset无认证一键删库重建.md | `D:\bounty-forge\reports\t5-target-site-lab\business-logic\VER-06-__reset无认证一键删库重建.md` | `business-logic/VER-06-__reset无认证一键删库重建.md` | 8762 | `59c312d34a92d3de7c8df56619685b233e0e26fde686f547937b7f3e122c6d7a` | T5 | VER-06（来源 HUNT-06，t5 判定 confirmed） | 中危（Medium）——若该端点出现在对外部署中，应直接升为高危 |
| 4 | VER-07-board匿名可写且无频控无长度限制.md | `D:\bounty-forge\reports\t5-target-site-lab\business-logic\VER-07-board匿名可写且无频控无长度限制.md` | `business-logic/VER-07-board匿名可写且无频控无长度限制.md` | 9414 | `a825f8bc3a9ddd7b0afb94a82b5198b61f8c8ae7131fed017f319f518d51e756` | T5 | VER-07（来源 HUNT-07，t5 判定 confirmed） | 中危（Medium，噪声型；若出现在公开站点则是典型的刷量/存储耗尽入口） |
| 5 | VER-09-query覆盖body参数来源不受方法限制.md | `D:\bounty-forge\reports\t5-target-site-lab\business-logic\VER-09-query覆盖body参数来源不受方法限制.md` | `business-logic/VER-09-query覆盖body参数来源不受方法限制.md` | 7868 | `a33d74ee99599beaf73ad16305065f72f5d708558fc0b1ad598d3f4eedc516ae` | T5 | VER-09（来源 HUNT-09，t5 判定 confirmed） | 低危（Low）——本身危害有限，但它是 VER-02（CSRF 全链路）的成因之一 |
| 6 | VER-11-提现金额超int64触发500.md | `D:\bounty-forge\reports\t5-target-site-lab\business-logic\VER-11-提现金额超int64触发500.md` | `business-logic/VER-11-提现金额超int64触发500.md` | 8737 | `0430d029bca68095971b3e882cfa9fca44d22f2feb4612359e3177e03237efb5` | T5 | VER-11（来源 HUNT-11，t5 判定 confirmed；含一处对挖掘阶段结论的修正） | 低危（Low） |
| 7 | VER-12-api-search回显SQL模板与LIKE通配符未转义.md | `D:\bounty-forge\reports\t5-target-site-lab\business-logic\VER-12-api-search回显SQL模板与LIKE通配符未转义.md` | `business-logic/VER-12-api-search回显SQL模板与LIKE通配符未转义.md` | 7548 | `26385ae93340e7562b2193ffaa97674ebdd4564c919f3f0fdff5834085b4dc42` | T5 | VER-12（来源 HUNT-12，t5 判定 confirmed） | 低危（Low） |
| 8 | VER-14-api-order类型宽松无越权影响.md | `D:\bounty-forge\reports\t5-target-site-lab\business-logic\VER-14-api-order类型宽松无越权影响.md` | `business-logic/VER-14-api-order类型宽松无越权影响.md` | 7768 | `ea50e4d2a1953465690b5b989c71d2c4f51eadad4c469836d2422307af3c2e53` | T5 | VER-14（来源 HUNT-14，t5 判定 **confirmed-no-impact**，标签为"行为确认但无实际影响"） | 信息项（Info，CVSS-like 0.0） |
| 9 | VER-15-debug对非admin返回403暴露端点存在性.md | `D:\bounty-forge\reports\t5-target-site-lab\business-logic\VER-15-debug对非admin返回403暴露端点存在性.md` | `business-logic/VER-15-debug对非admin返回403暴露端点存在性.md` | 6863 | `c100bcb641a71d9a3a1675032e10f572b4043a5572c99b8bc550a5a6684ea70e` | T5 | VER-15（来源 HUNT-15，t5 判定 **confirmed-no-impact**，标签为"行为确认但无实际影响"） | 信息项（Info，CVSS-like 0.0） |
| 10 | VER-05-forgot的Host头注入与md5令牌可预测.md | `D:\bounty-forge\reports\t5-target-site-lab\ssrf\VER-05-forgot的Host头注入与md5令牌可预测.md` | `ssrf/VER-05-forgot的Host头注入与md5令牌可预测.md` | 10537 | `a3becf5f12cbf3661ed37e94abece3488f6ad89805d3e57a214aa341b1fb8ef1` | T5 | VER-05（来源 HUNT-05，t5 判定 confirmed；**利用链未闭合**） | 中危（Medium）——仅按 Host 注入与弱令牌计危害，不按"任意用户改密"计（该链条证据不足） |
| 11 | VER-08-上传文件名非法字符触发500.md | `D:\bounty-forge\reports\t5-target-site-lab\file-upload\VER-08-上传文件名非法字符触发500.md` | `file-upload/VER-08-上传文件名非法字符触发500.md` | 16619 | `37ac5b3b84e85affea35b5bd33530fbb14c7fd3994e5bda66a9ba598f8e4597f` | T5 | VER-08（来源 HUNT-08，t5 判定 confirmed） | 低危（Low，可用性/异常面，无文件落地） |
| 12 | VER-03-debug泄露SECRET_KEY导致CSRF令牌可伪造.md | `D:\bounty-forge\reports\t5-target-site-lab\auth-bypass\VER-03-debug泄露SECRET_KEY导致CSRF令牌可伪造.md` | `auth-bypass/VER-03-debug泄露SECRET_KEY导致CSRF令牌可伪造.md` | 13927 | `129a3ddad44592ccfd010d171f9050f7b324649a59951abfa27255d26051a461` | T5 | VER-03（来源 HUNT-03，t5 判定 confirmed；本项与 `security/learning/VULN-03-SECRET_KEY泄露导致CSRF令牌可伪造.md` 是同一漏洞的两次独立验证记录，后者为 10-11 旧基线版本，以本笔记为准） | 高危（High） |
| 13 | VER-04-登出不销毁服务端会话.md | `D:\bounty-forge\reports\t5-target-site-lab\auth-bypass\VER-04-登出不销毁服务端会话.md` | `auth-bypass/VER-04-登出不销毁服务端会话.md` | 7757 | `d6c6fd75d8e9c169168291fcb64031d4d433f03c659596fa650b021f7370a2b7` | T5 | VER-04（来源 HUNT-04，t5 判定 confirmed） | 中危（Medium） |
| 14 | VER-10-登录态访问首页稳定500.md | `D:\bounty-forge\reports\t5-target-site-lab\auth-bypass\VER-10-登录态访问首页稳定500.md` | `auth-bypass/VER-10-登录态访问首页稳定500.md` | 7557 | `f3af8a76ba89071aae01e68fce9eed7421d1db854fd39a0e4abe0e6d6f696e99` | T5 | VER-10（来源 HUNT-10，t5 判定 confirmed；另对应旧编号 BUG-01） | 低危（Low，可用性缺陷；不泄露机密） |
| 15 | VER-13-logout无CSRF可被强制登出.md | `D:\bounty-forge\reports\t5-target-site-lab\auth-bypass\VER-13-logout无CSRF可被强制登出.md` | `auth-bypass/VER-13-logout无CSRF可被强制登出.md` | 6621 | `cbe453257f7b35540b8ed4c371887bb369e4ba95d7f3766094d1b6df52936f06` | T5 | VER-13（来源 HUNT-13，t5 判定 confirmed） | 低危（Low），但与 VER-04 叠加后构成"假登出" |
| 16 | VULN-03-SECRET_KEY泄露导致CSRF令牌可伪造.md | `D:\bounty-forge\reports\t5-target-site-lab\VULN-03-SECRET_KEY泄露导致CSRF令牌可伪造.md` | `VULN-03-SECRET_KEY泄露导致CSRF令牌可伪造.md` | 5710 | `c65ee8dbcc5c74c036b45a06d1f735d082bb6be272ad14bcfe96700cb7fcce12` | T5 | VULN-03 | 高危（High）—— 完整接管账号资金操作能力 |

### 1.5 总账与方法论（跨档，不计漏洞数） —— 4 条

| # | 条目名 | 归档绝对路径 | 源相对路径 | 大小(B) | sha256 | 档位 | 漏洞ID | 一句话结论 |
|---|---|---|---|---|---|---|---|---|
| 1 | progress.md | `D:\bounty-forge\reports\meta-总账\progress.md` | `progress.md` | 71321 | `d05102a5b2cf00be3ecf0330833cd76a5f5e5bc1b52d13d0baaed6a2702f64ae` | META | - | 漏洞挖掘学习进度报告（security/learning/progress.md） |
| 2 | learning-path.md | `D:\bounty-forge\reports\meta-总账\learning-path.md` | `learning-path.md` | 23898 | `dc6d7270635768b07cf1d948127876d968124c2330dcad928798efdcfb021ab4` | META | - | 漏洞挖掘学习路径（security/learning/learning-path.md） |
| 3 | next-round-plan.md | `D:\bounty-forge\reports\meta-总账\next-round-plan.md` | `next-round-plan.md` | 10271 | `285ac94509b6f9ab5288a7b66d258d36f6904b28d993eb3de6b9d3b41870e4df` | META | - | 方案待 captain 与用户确认后开单，本文件不自行启动任何下一轮任务 |
| 4 | 能力矩阵-赏金能力记分板.md | `D:\bounty-forge\reports\meta-总账\能力矩阵-赏金能力记分板.md` | `能力矩阵-赏金能力记分板.md` | 16941 | `6e5f2abde118f96ab4041f117f0707bfb266c0c0056807c6744d68db01e52226` | META | - | 赏金能力记分板（security/learning/能力矩阵-赏金能力记分板.md） |

> **「漏洞ID」列读法**：`笔记编号 / CVE 号`。前者取自笔记抬头「编号 / 笔记编号 / 报告编号」字段（如 `B1-LFI-01（Loop 3 B 档，t4）`、`C1-SHIRO-01`），后者取自**同一篇**抬头 60 行内出现的 `CVE-YYYY-NNNN`。**只扫抬头段**是有意为之：loop3 笔记之间互相引用对方的 CVE（C2 正文引了 C1 的 CVE-2016-4437），全文扫会把别人的 CVE 算成本篇的漏洞号。两个字段都取不到写 `-`，**不推测**。

> **为什么要「源相对路径」列**：不能靠 sha256 反查原件 —— 归档里有 0 字节空文件与重复内容（如 orig/hard 两份相同的 `readme.txt`），哈希相同但 mtime 不同，靠哈希反查会把文件认成别的原件（第一版 verify 脚本就因此误报 11 个「mtime 不一致」，实测证明 `copy2` 本身 diff=0，错的是校验逻辑）。本索引直接给出源路径映射，校验时按路径精确比对，不做身份推断。

### ⚠ 1.6 源文件编码异常（引用前必读）

下列文件**源文件本身编码已损坏**，不是本次归档造成的，也不是读取方式的问题 —— 以 UTF-8 / UTF-8-BOM / GBK 分别实读均解不出通顺中文。已按原样归档（字节级一致，sha256 与源相同），但**索引里的编号 / 结论 / 漏洞ID 均未提取**，标 `-` 是如实反映，不是漏提取。

| 条目名 | 归档绝对路径 | 大小(B) | sha256 | 诊断 |
|---|---|---|---|---|
| loop3-c-c1-oracle-verdict-20261012.md | `D:\bounty-forge\reports\c-档\loop3-c-c1-oracle-verdict-20261012.md` | 17132 | `17ac0e21c2ace1a6954619b1109d7d1c4566aa1ad6fad0aef7678e2739bfcc6a` | 检出 Unicode 私用区字符 55 处 —— **源文件编码损坏**（UTF-8 字节被按 GBK 二次解码），非读取方式问题 |

> 处置建议：该文件需重新用正确编码生成后再入索引；在此之前**不得据其内容做任何结论引用**。归档动作本身无误（字节一致可验）。

---

## 2. 原始证据索引（`_evidence/` 全量）

共 **330** 个文件，归档路径形如 `D:\bounty-forge\evidence\<档位>\<类别>\<源相对路径（`/` 替成 `__`）>`。

档位判定**三级优先、逐级降级**，每条都在「判定理由」列写明命中了第几级、命中哪条规则：

| 优先级 | 判定方式 | 命中条件 |
|---|---|---|
| ① | 文件名硬标记 | 含 `t7`→C；含 `t4`→B；含 `t5`→B；含 `t1`/`t2`/`t3`→A；含 `t8`→META；含 `loop2`→L2 |
| ① | **目录名硬标记** | 目录名含 `loop2-verify-sandbox`→L2；目录名含 `sqmap-8091`/`sqmap-8095`→T5 |
| ① | 文件名显式档位 | 形如 `loop3-a-` / `loop3-b-` / `loop3-c-` → 取字母对应档位 |
| ② | **内容实读嗅探**（前 8 KB） | 含 `shiro/rememberMe/18081/tomcat/18082/CVE 号`→C；含 `DVWA/bWAPP/192.168.56`→B；含 `target-site-lab/8095/8091`→T5 |
| ③ | 未判定 | 文件名、目录名与内容均无档位标识 → 归 `UNSORTED`，**不做推测性归类** |

> 为什么要 ② 级：loop3 早期 hunting 产物（`recon-*` / `hunt-*` / `attack-surface-*` / `baseline-*` 等 100 余个）文件名不带 `tN` 标记，只按名字分会有大部落进未判定桶。实读内容按靶场标识归位后，未判定量大幅下降（见下表实际分布）。

> 目录名规则也是踩坑后补的：`loop2-verify-sandbox/*`（14 个）与 `sqmap-809*/*`（13 个）的档位标记写在**目录名**里，只看文件名会全部漏判（第一版就掉进未判定桶）。

### 2.1 证据档位 **A** —— 10 个

| # | 文件名 | 归档绝对路径 | 源相对路径 | 大小(B) | sha256 | 档位 | 类别 | 判定理由 |
|---|---|---|---|---|---|---|---|---|
| 2 | `loop3-a-verify-20261012-212153.json` | `D:\bounty-forge\evidence\A\json\loop3-a-verify-20261012-212153.json` | `_evidence/loop3-a-verify-20261012-212153.json` | 37941 | `614f20b2d7d4e74b7a94708d99da4e6425fd0076f68705360a37e5b9835dfc3e` | A | json | ①文件名 loop3-a- 显式档位标记 |
| 3 | `loop3-a-verify-gen.py` | `D:\bounty-forge\evidence\A\script\loop3-a-verify-gen.py` | `_evidence/loop3-a-verify-gen.py` | 32566 | `28167728d279643447a1c3abb66acb5d3386cce509582a5eb21d039cebbced6a` | A | script | ①文件名 loop3-a- 显式档位标记 |
| 4 | `t2-a1-concurrency-20261012.json` | `D:\bounty-forge\evidence\A\json\t2-a1-concurrency-20261012.json` | `_evidence/t2-a1-concurrency-20261012.json` | 3469 | `0c79446a28ced3f6f96c0c574a66bd45cafe9bcb7f4bbc157386cfa8dd5e41d8` | A | json | ①文件名规则：文件名含 t1/t2/t3（加固与验证侧 A 档） |
| 5 | `t2-a1-concurrency-20261012.py` | `D:\bounty-forge\evidence\A\script\t2-a1-concurrency-20261012.py` | `_evidence/t2-a1-concurrency-20261012.py` | 5134 | `42082a1f5622eaf94b18bbc0d888ff692a34549706e26c6b763148edb4e8dcec` | A | script | ①文件名规则：文件名含 t1/t2/t3（加固与验证侧 A 档） |
| 6 | `t2-a2a3a4-after-20261012.json` | `D:\bounty-forge\evidence\A\json\t2-a2a3a4-after-20261012.json` | `_evidence/t2-a2a3a4-after-20261012.json` | 3235 | `80bdb8b6057beafa57c2ca43d7e2404dd5418f7f1287c3b1dc20a42dce0890a2` | A | json | ①文件名规则：文件名含 t1/t2/t3（加固与验证侧 A 档） |
| 7 | `t2-a2a3a4-after-20261012.py` | `D:\bounty-forge\evidence\A\script\t2-a2a3a4-after-20261012.py` | `_evidence/t2-a2a3a4-after-20261012.py` | 5295 | `ea2b8cc5112a82f6d86d7abd887cb357a89e41967f9ac38931919ae0e1e21630` | A | script | ①文件名规则：文件名含 t1/t2/t3（加固与验证侧 A 档） |
| 8 | `t2-apppy-diff-20261012.patch` | `D:\bounty-forge\evidence\A\patch\t2-apppy-diff-20261012.patch` | `_evidence/t2-apppy-diff-20261012.patch` | 15039 | `d97e1b574a750121fe196756e6755a6956e640304ce14b50af0ba935e9fe4423` | A | patch | ①文件名规则：文件名含 t1/t2/t3（加固与验证侧 A 档） |
| 9 | `t2-edgecases-20261012.json` | `D:\bounty-forge\evidence\A\json\t2-edgecases-20261012.json` | `_evidence/t2-edgecases-20261012.json` | 844 | `bb0648d05363b802febb8232870d331449b84898afb47af9871dc30aeee130aa` | A | json | ①文件名规则：文件名含 t1/t2/t3（加固与验证侧 A 档） |
| 10 | `t2-edgecases-20261012.py` | `D:\bounty-forge\evidence\A\script\t2-edgecases-20261012.py` | `_evidence/t2-edgecases-20261012.py` | 4327 | `6bed5411dcfeaafe93e077b99d0da0b08ea362f8a648e6b1f04e9d8494d2bb27` | A | script | ①文件名规则：文件名含 t1/t2/t3（加固与验证侧 A 档） |
| 11 | `t2-note-selfcheck.py` | `D:\bounty-forge\evidence\A\script\t2-note-selfcheck.py` | `_evidence/t2-note-selfcheck.py` | 4081 | `873cc567fe6e83119c52129564fb8d1ab69e477cb95bdf943ee783caa3de1fa9` | A | script | ①文件名规则：文件名含 t1/t2/t3（加固与验证侧 A 档） |

### 2.12 证据档位 **B** —— 87 个

| # | 文件名 | 归档绝对路径 | 源相对路径 | 大小(B) | sha256 | 档位 | 类别 | 判定理由 |
|---|---|---|---|---|---|---|---|---|
| 13 | `_t5_cookie.txt` | `D:\bounty-forge\evidence\B\txt\_t5_cookie.txt` | `_evidence/_t5_cookie.txt` | 43 | `c04593c5199c18043e719f79a8355ce05711ae061ddd0d77204510e89860c9d4` | B | txt | ①文件名规则：文件名含 t5（t5 亦参与 B 档阴性归档） |
| 14 | `build-verified-t5.py` | `D:\bounty-forge\evidence\B\script\build-verified-t5.py` | `_evidence/build-verified-t5.py` | 39505 | `922f5510e96532630045c9497c064f4cb85cb8a80660bb2a88c1798a396a9deb` | B | script | ①文件名规则：文件名含 t5（t5 亦参与 B 档阴性归档） |
| 15 | `loop3-b-probe1-out.txt` | `D:\bounty-forge\evidence\B\txt\loop3-b-probe1-out.txt` | `_evidence/loop3-b-probe1-out.txt` | 1863 | `bdae4fee3a7f9735f8f524af6b6becea254003454975099d7d85db9dab4dc193` | B | txt | ①文件名 loop3-b- 显式档位标记 |
| 16 | `loop3-b-probe1.sh` | `D:\bounty-forge\evidence\B\script\loop3-b-probe1.sh` | `_evidence/loop3-b-probe1.sh` | 772 | `3ccde87fd1dc2557bacab023166ba007b4b0b7e2933fc0b9d180bbb6c095f494` | B | script | ①文件名 loop3-b- 显式档位标记 |
| 17 | `loop3-b-probe2.sh` | `D:\bounty-forge\evidence\B\script\loop3-b-probe2.sh` | `_evidence/loop3-b-probe2.sh` | 683 | `9f5776e228d745a89a632d990db42174756efc55d84922dddda317f0a48fb831` | B | script | ①文件名 loop3-b- 显式档位标记 |
| 18 | `loop3-b0-recon.sh` | `D:\bounty-forge\evidence\B\script\loop3-b0-recon.sh` | `_evidence/loop3-b0-recon.sh` | 2027 | `c9ec9056d068e5b19b6ee4e2db0cd1f60c974cc7e14d43913bf522994aa708a6` | B | script | ②内容实读嗅探（前 8KB）：内容含 DVWA/bWAPP/192.168.56（Kali VM 靶场） |
| 19 | `loop3-b0-recon2.sh` | `D:\bounty-forge\evidence\B\script\loop3-b0-recon2.sh` | `_evidence/loop3-b0-recon2.sh` | 534 | `3f5c9282d29e5e0553be70d090f358440e58630e56a0c36ac36d7bc054dde18c` | B | script | ②内容实读嗅探（前 8KB）：内容含 DVWA/bWAPP/192.168.56（Kali VM 靶场） |
| 20 | `loop3-b0-recon3-out.txt` | `D:\bounty-forge\evidence\B\txt\loop3-b0-recon3-out.txt` | `_evidence/loop3-b0-recon3-out.txt` | 9769 | `b6617c10026ba2807d2af1ecd0071414bdccb898c7dfbe471e46bc0a3204aae6` | B | txt | ②内容实读嗅探（前 8KB）：内容含 DVWA/bWAPP/192.168.56（Kali VM 靶场） |
| 21 | `loop3-b0-recon3.sh` | `D:\bounty-forge\evidence\B\script\loop3-b0-recon3.sh` | `_evidence/loop3-b0-recon3.sh` | 927 | `f8fc93be63021d4fa20843b2d748d3b07a67bfe86df188a7fb0686185092e573` | B | script | ②内容实读嗅探（前 8KB）：内容含 DVWA/bWAPP/192.168.56（Kali VM 靶场） |
| 22 | `loop3-b0-recon4-out.txt` | `D:\bounty-forge\evidence\B\txt\loop3-b0-recon4-out.txt` | `_evidence/loop3-b0-recon4-out.txt` | 44893 | `fc55d98a9d638c822e5d144972ccad88b8de8d52e02fa4c6f05418a768a6dad6` | B | txt | ②内容实读嗅探（前 8KB）：内容含 DVWA/bWAPP/192.168.56（Kali VM 靶场） |
| 23 | `loop3-b0-recon4.sh` | `D:\bounty-forge\evidence\B\script\loop3-b0-recon4.sh` | `_evidence/loop3-b0-recon4.sh` | 721 | `58e5ebaba9f2e2ec27e3c667f97a22e6513655ccde1c8625a7181bc1f148da46` | B | script | ②内容实读嗅探（前 8KB）：内容含 DVWA/bWAPP/192.168.56（Kali VM 靶场） |
| 24 | `loop3-b0-recon5-out.txt` | `D:\bounty-forge\evidence\B\txt\loop3-b0-recon5-out.txt` | `_evidence/loop3-b0-recon5-out.txt` | 2616 | `55df9391d34c5f0893ccf1a8dff96e319891b674133b8928407d806da5377aab` | B | txt | ②内容实读嗅探（前 8KB）：内容含 DVWA/bWAPP/192.168.56（Kali VM 靶场） |
| 25 | `loop3-b0-recon5.sh` | `D:\bounty-forge\evidence\B\script\loop3-b0-recon5.sh` | `_evidence/loop3-b0-recon5.sh` | 671 | `9abaeb92015eadf80f96f444fe6555ff6fab15d4110a08c3f23c660fcab60d30` | B | script | ②内容实读嗅探（前 8KB）：内容含 DVWA/bWAPP/192.168.56（Kali VM 靶场） |
| 26 | `loop3-b0-recon6-out.txt` | `D:\bounty-forge\evidence\B\txt\loop3-b0-recon6-out.txt` | `_evidence/loop3-b0-recon6-out.txt` | 8072 | `af7aeabe5a74222faf11dab70292fd97ac012706b6ab05402b270555e5ce522b` | B | txt | ②内容实读嗅探（前 8KB）：内容含 DVWA/bWAPP/192.168.56（Kali VM 靶场） |
| 27 | `loop3-b0-recon6.sh` | `D:\bounty-forge\evidence\B\script\loop3-b0-recon6.sh` | `_evidence/loop3-b0-recon6.sh` | 1081 | `f0656f55b2f8db6e21e3089a4482d962e2c0cbac4063b8bd3387c93a4ff9c86f` | B | script | ②内容实读嗅探（前 8KB）：内容含 DVWA/bWAPP/192.168.56（Kali VM 靶场） |
| 28 | `loop3-b0-recon7-out.txt` | `D:\bounty-forge\evidence\B\txt\loop3-b0-recon7-out.txt` | `_evidence/loop3-b0-recon7-out.txt` | 10206 | `120d9bd50b7169dc18d2919e979721de6ecc912339674345b9932aa09c4a74f9` | B | txt | ②内容实读嗅探（前 8KB）：内容含 DVWA/bWAPP/192.168.56（Kali VM 靶场） |
| 29 | `loop3-b0-recon7.sh` | `D:\bounty-forge\evidence\B\script\loop3-b0-recon7.sh` | `_evidence/loop3-b0-recon7.sh` | 705 | `d3695677a51d3c7a5a3467376b93fc88912ee871d64a241b7031f7d33a336de6` | B | script | ②内容实读嗅探（前 8KB）：内容含 DVWA/bWAPP/192.168.56（Kali VM 靶场） |
| 30 | `loop3-kali-baseline-20261012-212122.json` | `D:\bounty-forge\evidence\B\json\loop3-kali-baseline-20261012-212122.json` | `_evidence/loop3-kali-baseline-20261012-212122.json` | 29241 | `1f4ed4b34b173b664faef4c735ad0d7080f8d747df4fe80d9cb47da2bf5025f0` | B | json | ②内容实读嗅探（前 8KB）：内容含 DVWA/bWAPP/192.168.56（Kali VM 靶场） |
| 31 | `loop3-t4-b5-sink.jsonl` | `D:\bounty-forge\evidence\B\jsonl\loop3-t4-b5-sink.jsonl` | `_evidence/loop3-t4-b5-sink.jsonl` | 1427 | `77f9c42b14294625764b83ff37aa65a7014a0b270494950a8f96cc8498838071` | B | jsonl | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 32 | `loop3-t4-b5-xss.png` | `D:\bounty-forge\evidence\B\other\loop3-t4-b5-xss.png` | `_evidence/loop3-t4-b5-xss.png` | 95256 | `ddfb4c791fca03362477e85da8fa966453e01d873b67d5978a91341bb280283c` | B | other | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 33 | `loop3-t4-cleanup-out.txt` | `D:\bounty-forge\evidence\B\txt\loop3-t4-cleanup-out.txt` | `_evidence/loop3-t4-cleanup-out.txt` | 3394 | `ff11ee9a1ed9d34f82b68ec8cbdcb00d100ae7f4bf1fe8865cacdbd50bf3c66d` | B | txt | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 34 | `loop3-t4-cleanup.sh` | `D:\bounty-forge\evidence\B\script\loop3-t4-cleanup.sh` | `_evidence/loop3-t4-cleanup.sh` | 1887 | `a85906310e6a0eb5ef4f7dd0052ca923b17cb3f6c36ac93c6dd7b7061a2b6693` | B | script | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 35 | `loop3-t4-probe1-out.txt` | `D:\bounty-forge\evidence\B\txt\loop3-t4-probe1-out.txt` | `_evidence/loop3-t4-probe1-out.txt` | 3211 | `f13f5e457fc897d6194576d61a73e123f9f81265054119b018a1aa67d9a0ba57` | B | txt | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 36 | `loop3-t4-probe1.json` | `D:\bounty-forge\evidence\B\json\loop3-t4-probe1.json` | `_evidence/loop3-t4-probe1.json` | 3689 | `10508d7fd0da7a9ec43ffe6cb5a70fdf4cbf2ebf3daf2cfbf8a26b84b03fdb5e` | B | json | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 37 | `loop3-t4-probe1.py` | `D:\bounty-forge\evidence\B\script\loop3-t4-probe1.py` | `_evidence/loop3-t4-probe1.py` | 6094 | `5a73570a34016101fbc744d44e48b5d838c90ec8bb13d4e87a63b0ba719924ed` | B | script | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 38 | `loop3-t4-probe10-out.txt` | `D:\bounty-forge\evidence\B\txt\loop3-t4-probe10-out.txt` | `_evidence/loop3-t4-probe10-out.txt` | 1573 | `4fe110c4153850f58e7ebcde4f823420925397cdcb83bb5d15eff99e46d92dae` | B | txt | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 39 | `loop3-t4-probe10.json` | `D:\bounty-forge\evidence\B\json\loop3-t4-probe10.json` | `_evidence/loop3-t4-probe10.json` | 1764 | `2d2a7cf8f6616702969843d376b7c9f8c3ce0f872a4b96b714ab3434e8b882a6` | B | json | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 40 | `loop3-t4-probe10.py` | `D:\bounty-forge\evidence\B\script\loop3-t4-probe10.py` | `_evidence/loop3-t4-probe10.py` | 2644 | `202a06d8d69e46b5fcb1a11b6944ad83483ef86662282807527bfb8dca41fd81` | B | script | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 41 | `loop3-t4-probe11-out.txt` | `D:\bounty-forge\evidence\B\txt\loop3-t4-probe11-out.txt` | `_evidence/loop3-t4-probe11-out.txt` | 4507 | `0bc4589cd4bf8f3e8163a99ccde8c81c846bcc9981725c4ebe124d6dbb7ae671` | B | txt | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 42 | `loop3-t4-probe11-sink.jsonl` | `D:\bounty-forge\evidence\B\jsonl\loop3-t4-probe11-sink.jsonl` | `_evidence/loop3-t4-probe11-sink.jsonl` | 158 | `12fdb00bf5f802cade9643f040a16d01b68665a753dfaf6230481b8d47e5b3ad` | B | jsonl | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 43 | `loop3-t4-probe11.json` | `D:\bounty-forge\evidence\B\json\loop3-t4-probe11.json` | `_evidence/loop3-t4-probe11.json` | 4727 | `108924d1bc00972b39b6a09ddb4b7e31ab16998231b1706fc2902998a107afe6` | B | json | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 44 | `loop3-t4-probe11.py` | `D:\bounty-forge\evidence\B\script\loop3-t4-probe11.py` | `_evidence/loop3-t4-probe11.py` | 8750 | `f3220efd1d57be2c5cd6e4b49237f904a4c1dc6a96c763d0402c4562dafb6f31` | B | script | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 45 | `loop3-t4-probe12-out.txt` | `D:\bounty-forge\evidence\B\txt\loop3-t4-probe12-out.txt` | `_evidence/loop3-t4-probe12-out.txt` | 2853 | `9a5959281f5dd940b777a523b63da3bfa1c41cf75279afdb61fd961ee2bda47b` | B | txt | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 46 | `loop3-t4-probe12.json` | `D:\bounty-forge\evidence\B\json\loop3-t4-probe12.json` | `_evidence/loop3-t4-probe12.json` | 3134 | `edd5d3f50418c39f53ac8acd3684138684d4107124395a19ac280762c5da6a77` | B | json | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 47 | `loop3-t4-probe12.py` | `D:\bounty-forge\evidence\B\script\loop3-t4-probe12.py` | `_evidence/loop3-t4-probe12.py` | 4527 | `24335ac0606afc48290a303479faef29ab3b0a325d7d9297af4e5e72e4f5015f` | B | script | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 48 | `loop3-t4-probe13-out.txt` | `D:\bounty-forge\evidence\B\txt\loop3-t4-probe13-out.txt` | `_evidence/loop3-t4-probe13-out.txt` | 2298 | `e27c2870bbc84c3c3766de9c1b1a8b2dfef2104ca79f1968848879729766873f` | B | txt | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 49 | `loop3-t4-probe13-sink.jsonl` | `D:\bounty-forge\evidence\B\jsonl\loop3-t4-probe13-sink.jsonl` | `_evidence/loop3-t4-probe13-sink.jsonl` | 7197 | `f7902c47d8d122fe305137b71db13f2a66e0f0a542b5e856cb1cc3db905b2c52` | B | jsonl | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 50 | `loop3-t4-probe13.json` | `D:\bounty-forge\evidence\B\json\loop3-t4-probe13.json` | `_evidence/loop3-t4-probe13.json` | 2876 | `74aeab1389021ff6dc41ebc33b3456469ce49c0a07b03abf31dc2054be3a4d37` | B | json | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 51 | `loop3-t4-probe13.py` | `D:\bounty-forge\evidence\B\script\loop3-t4-probe13.py` | `_evidence/loop3-t4-probe13.py` | 14056 | `127fb63b6ee5ed74adc7b826af294bf29cde87260c269cda544586bcc9dfe1ff` | B | script | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 52 | `loop3-t4-probe14-out.txt` | `D:\bounty-forge\evidence\B\txt\loop3-t4-probe14-out.txt` | `_evidence/loop3-t4-probe14-out.txt` | 1608 | `c13b9bd70e608793eb083b358be52f72c5f82dba7ba3655fa9a0646be7234657` | B | txt | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 53 | `loop3-t4-probe14.json` | `D:\bounty-forge\evidence\B\json\loop3-t4-probe14.json` | `_evidence/loop3-t4-probe14.json` | 1814 | `7bf0cdb02ac09d7815b6b1d81b430a56701aa37001638492dcd0c037427365bf` | B | json | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 54 | `loop3-t4-probe14.py` | `D:\bounty-forge\evidence\B\script\loop3-t4-probe14.py` | `_evidence/loop3-t4-probe14.py` | 5192 | `0cdfc68c632dc5dc92cbb393bed4e5ce08576b6b0ed6c949487249ddb06a7454` | B | script | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 55 | `loop3-t4-probe15-out.txt` | `D:\bounty-forge\evidence\B\txt\loop3-t4-probe15-out.txt` | `_evidence/loop3-t4-probe15-out.txt` | 5255 | `35c91c228dcf8fa46e0cdfddfb4e8eb9f7189e4d62439c34241d0c04d8018115` | B | txt | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 56 | `loop3-t4-probe15-sink.jsonl` | `D:\bounty-forge\evidence\B\jsonl\loop3-t4-probe15-sink.jsonl` | `_evidence/loop3-t4-probe15-sink.jsonl` | 2414 | `b8c956579fec1818dc1e81920d2cdc988cc914b78dee336babfec93be903f43d` | B | jsonl | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 57 | `loop3-t4-probe15.json` | `D:\bounty-forge\evidence\B\json\loop3-t4-probe15.json` | `_evidence/loop3-t4-probe15.json` | 4075 | `5160ffd3b337d1de51b049ba18add0ead4186ed358d1658b0f33942b030de253` | B | json | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 58 | `loop3-t4-probe15.py` | `D:\bounty-forge\evidence\B\script\loop3-t4-probe15.py` | `_evidence/loop3-t4-probe15.py` | 6931 | `8382acd328bb0a2590e108c1a7b18fdd87d97cc28d7f171e99c95ddaaa8a9f0a` | B | script | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 59 | `loop3-t4-probe2-out.txt` | `D:\bounty-forge\evidence\B\txt\loop3-t4-probe2-out.txt` | `_evidence/loop3-t4-probe2-out.txt` | 1894 | `4beccca4f49ab591178388112abb89c8fa665fda7b4bbed72f9f7d72aa694496` | B | txt | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 60 | `loop3-t4-probe2.json` | `D:\bounty-forge\evidence\B\json\loop3-t4-probe2.json` | `_evidence/loop3-t4-probe2.json` | 2136 | `ec21d03d66b844e4d8cee1032d56d5b3b240e1bf7206c7128095c7b85c738707` | B | json | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 61 | `loop3-t4-probe2.py` | `D:\bounty-forge\evidence\B\script\loop3-t4-probe2.py` | `_evidence/loop3-t4-probe2.py` | 4208 | `34f4f2305bf3bc4ed0b3a09c6509b64454c2c7ca316cb214e45784caf01ea034` | B | script | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 62 | `loop3-t4-probe3-out.txt` | `D:\bounty-forge\evidence\B\txt\loop3-t4-probe3-out.txt` | `_evidence/loop3-t4-probe3-out.txt` | 425 | `3b0777b65296042e3147ed63985ef15699578c0bb9531dd1485f5b5f1be699f2` | B | txt | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 63 | `loop3-t4-probe3.json` | `D:\bounty-forge\evidence\B\json\loop3-t4-probe3.json` | `_evidence/loop3-t4-probe3.json` | 494 | `3169954fd78e60c6468696f8bbcb4660b27a89d83b396c16d46c99b50ecd554d` | B | json | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 64 | `loop3-t4-probe3.py` | `D:\bounty-forge\evidence\B\script\loop3-t4-probe3.py` | `_evidence/loop3-t4-probe3.py` | 1566 | `1799a726eb5ee3c9209bf84b3126abfa4b846ca45baa3516fb0cbda1f18a878f` | B | script | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 65 | `loop3-t4-probe4-out.txt` | `D:\bounty-forge\evidence\B\txt\loop3-t4-probe4-out.txt` | `_evidence/loop3-t4-probe4-out.txt` | 2263 | `88684edb50d063c36839fc1c8e31dc3f9ce93490db904d1ad272946a6efc1852` | B | txt | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 66 | `loop3-t4-probe4.json` | `D:\bounty-forge\evidence\B\json\loop3-t4-probe4.json` | `_evidence/loop3-t4-probe4.json` | 2552 | `62dd2a4e63f24d6b2cc0606e451e77165a4cbe08b2a3093461ff0eba71cbdebe` | B | json | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 67 | `loop3-t4-probe4.py` | `D:\bounty-forge\evidence\B\script\loop3-t4-probe4.py` | `_evidence/loop3-t4-probe4.py` | 5369 | `2573430ded825ecfc919602ad877bcb21a40840bd1b3d20b4ad5b83fb779599a` | B | script | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 68 | `loop3-t4-probe5-out.txt` | `D:\bounty-forge\evidence\B\txt\loop3-t4-probe5-out.txt` | `_evidence/loop3-t4-probe5-out.txt` | 1607 | `3edaf82ea3c5f416ce87c80b49df06c63cfc83fb6dc75fc25b09e284d83bba56` | B | txt | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 69 | `loop3-t4-probe5.json` | `D:\bounty-forge\evidence\B\json\loop3-t4-probe5.json` | `_evidence/loop3-t4-probe5.json` | 1911 | `24eac0810fc4f9dd833f6e3779a069badb071377d6bc3e65fd213b6d9b3648cd` | B | json | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 70 | `loop3-t4-probe5.py` | `D:\bounty-forge\evidence\B\script\loop3-t4-probe5.py` | `_evidence/loop3-t4-probe5.py` | 4773 | `57c747da3884ff43889913664c901e4b7ad50f8d72978973a30560c4f481024d` | B | script | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 71 | `loop3-t4-probe6-out.txt` | `D:\bounty-forge\evidence\B\txt\loop3-t4-probe6-out.txt` | `_evidence/loop3-t4-probe6-out.txt` | 3212 | `e81ac2300c2dd86eb912a27b3e30f49d5635d9f24497f0ebd39da7bcbf562109` | B | txt | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 72 | `loop3-t4-probe6.json` | `D:\bounty-forge\evidence\B\json\loop3-t4-probe6.json` | `_evidence/loop3-t4-probe6.json` | 2677 | `99b532fa648baf2ec466d901d526c22f45401f5e7cdc85d4fe18fd9390ac83f9` | B | json | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 73 | `loop3-t4-probe6.py` | `D:\bounty-forge\evidence\B\script\loop3-t4-probe6.py` | `_evidence/loop3-t4-probe6.py` | 7242 | `43a08d5fe037241a8cde6d3a63f2d1ad79869839050d4f23d950e13f5de55d2c` | B | script | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 74 | `loop3-t4-probe7-out.txt` | `D:\bounty-forge\evidence\B\txt\loop3-t4-probe7-out.txt` | `_evidence/loop3-t4-probe7-out.txt` | 1242 | `80678861ec4dc6e0578c15a0c118c48cfaa1dc2586dee6dcfdd75618f0755665` | B | txt | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 75 | `loop3-t4-probe7.json` | `D:\bounty-forge\evidence\B\json\loop3-t4-probe7.json` | `_evidence/loop3-t4-probe7.json` | 1399 | `7a92dcc673326d16ac7d3a021cabc9e309af393d0e2d15a7522afae27b0d8c52` | B | json | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 76 | `loop3-t4-probe7.py` | `D:\bounty-forge\evidence\B\script\loop3-t4-probe7.py` | `_evidence/loop3-t4-probe7.py` | 3347 | `ea7a1bda6deae18b502734121b05456ba8de846990fefb0c10cc4947f61b4b44` | B | script | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 77 | `loop3-t4-probe8-out.txt` | `D:\bounty-forge\evidence\B\txt\loop3-t4-probe8-out.txt` | `_evidence/loop3-t4-probe8-out.txt` | 2837 | `c2feb03b1529f314d6f9f68e0b31d2d30ae1037eb2b5e9f18072957c37de50c0` | B | txt | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 78 | `loop3-t4-probe8.json` | `D:\bounty-forge\evidence\B\json\loop3-t4-probe8.json` | `_evidence/loop3-t4-probe8.json` | 5821 | `faeebbaad38701cd97c9c0f2867fff8279b791a186015e80b268da7cff387fbc` | B | json | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 79 | `loop3-t4-probe8.py` | `D:\bounty-forge\evidence\B\script\loop3-t4-probe8.py` | `_evidence/loop3-t4-probe8.py` | 7838 | `59190e472b418035890e3c4e6cfaf3dc56c540ce539b75b69ac08b37394f4b85` | B | script | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 80 | `loop3-t4-probe9-out.txt` | `D:\bounty-forge\evidence\B\txt\loop3-t4-probe9-out.txt` | `_evidence/loop3-t4-probe9-out.txt` | 4519 | `d094d863e0fbd280d747ab28696cdbda30cae5927e61b38c2dde57c03269f0ad` | B | txt | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 81 | `loop3-t4-probe9-sink.jsonl` | `D:\bounty-forge\evidence\B\jsonl\loop3-t4-probe9-sink.jsonl` | `_evidence/loop3-t4-probe9-sink.jsonl` | 2450 | `e79192488491278d08d06bb724a8631f3f0c164286eceba2c4edb3971548b18e` | B | jsonl | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 82 | `loop3-t4-probe9.json` | `D:\bounty-forge\evidence\B\json\loop3-t4-probe9.json` | `_evidence/loop3-t4-probe9.json` | 3718 | `9bc4e52fef99c42a3a3a4779d99cb7d1dae488b86db0c5d08f10131459758ac3` | B | json | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 83 | `loop3-t4-probe9.py` | `D:\bounty-forge\evidence\B\script\loop3-t4-probe9.py` | `_evidence/loop3-t4-probe9.py` | 8616 | `81e91dcd93fe12ab078e1d28d396b2adbbf33df68a5aa7aed3cc92a253330bd7` | B | script | ①文件名规则：文件名含 t4（t4 = DVWA/bWAPP B 档） |
| 84 | `sqlmap-t5-verify-board.log` | `D:\bounty-forge\evidence\B\log\sqlmap-t5-verify-board.log` | `_evidence/sqlmap-t5-verify-board.log` | 4306 | `7c5fb44c896f312c2cee8e6c79fac34ccbbf90dba6a030c974e43481ae180b7f` | B | log | ①文件名规则：文件名含 t5（t5 亦参与 B 档阴性归档） |
| 85 | `sqlmap-t5-verify-board2.log` | `D:\bounty-forge\evidence\B\log\sqlmap-t5-verify-board2.log` | `_evidence/sqlmap-t5-verify-board2.log` | 1734 | `431bee020a8216750d04227b618bd17b82ab94f32885ca0188548a95934e9f73` | B | log | ①文件名规则：文件名含 t5（t5 亦参与 B 档阴性归档） |
| 86 | `sqlmap-t5-verify.log` | `D:\bounty-forge\evidence\B\log\sqlmap-t5-verify.log` | `_evidence/sqlmap-t5-verify.log` | 5915 | `6610e12565cdad10f94dff92a577d8c1a74ff8d9642a48e5d76f137d9a7ff24f` | B | log | ①文件名规则：文件名含 t5（t5 亦参与 B 档阴性归档） |
| 87 | `t5-note-selfcheck.py` | `D:\bounty-forge\evidence\B\script\t5-note-selfcheck.py` | `_evidence/t5-note-selfcheck.py` | 5434 | `ca321b59f6af0990d3b05cb2a86777c6977ccc78cb474031dfa879467f28339e` | B | script | ①文件名规则：文件名含 t5（t5 亦参与 B 档阴性归档） |
| 88 | `verified-loop3-b-20261012-2236.json` | `D:\bounty-forge\evidence\B\json\verified-loop3-b-20261012-2236.json` | `_evidence/verified-loop3-b-20261012-2236.json` | 19041 | `a9274a92e2c5e492109ba0b58811e81d3eeb8b83bc3410f11691792a73006804` | B | json | ①文件名 loop3-b- 显式档位标记 |
| 89 | `verified-loop3-b-20261012-2236.md` | `D:\bounty-forge\evidence\B\md\verified-loop3-b-20261012-2236.md` | `_evidence/verified-loop3-b-20261012-2236.md` | 31185 | `3c6254d1a4061d5d4d2680803965efd5602a130e19f930dc296637ce16160cd4` | B | md | ①文件名 loop3-b- 显式档位标记 |
| 90 | `verified-loop3-b-b1-depth-20261012-2236.json` | `D:\bounty-forge\evidence\B\json\verified-loop3-b-b1-depth-20261012-2236.json` | `_evidence/verified-loop3-b-b1-depth-20261012-2236.json` | 9995 | `1640a87963f995b89f1cbef501d28e49734651975b1be9782335764eb76e8b79` | B | json | ①文件名 loop3-b- 显式档位标记 |
| 91 | `verified-loop3-b-b1b3-firstpass-20261012-2236.json` | `D:\bounty-forge\evidence\B\json\verified-loop3-b-b1b3-firstpass-20261012-2236.json` | `_evidence/verified-loop3-b-b1b3-firstpass-20261012-2236.json` | 4812 | `45e08136f18314cf9f2d637ec015b15560924d468362b385593193ca8263018d` | B | json | ①文件名 loop3-b- 显式档位标记 |
| 92 | `verified-loop3-b-b2-medctl-probe-20261012-2236.py` | `D:\bounty-forge\evidence\B\script\verified-loop3-b-b2-medctl-probe-20261012-2236.py` | `_evidence/verified-loop3-b-b2-medctl-probe-20261012-2236.py` | 3292 | `4504a43a684cb3f9940ed196fc7e5911f063bd49e724387374cca7d7087811a5` | B | script | ①文件名 loop3-b- 显式档位标记 |
| 93 | `verified-loop3-b-b2-rootcause-20261012-2236.json` | `D:\bounty-forge\evidence\B\json\verified-loop3-b-b2-rootcause-20261012-2236.json` | `_evidence/verified-loop3-b-b2-rootcause-20261012-2236.json` | 4752 | `df24291dff7aeaab6c0f815556d9d90f959ca837bfc2eb0710beac6ba422dac5` | B | json | ①文件名 loop3-b- 显式档位标记 |
| 94 | `verified-loop3-b-b2-xxe-raw-20261012-2236.json` | `D:\bounty-forge\evidence\B\json\verified-loop3-b-b2-xxe-raw-20261012-2236.json` | `_evidence/verified-loop3-b-b2-xxe-raw-20261012-2236.json` | 10800 | `b71444fec3d3bdba1fa1e2551f1631da4b76445817fc8303c89c66c41981e3b9` | B | json | ①文件名 loop3-b- 显式档位标记 |
| 95 | `verified-loop3-b-b3-browser-20261012-2236.json` | `D:\bounty-forge\evidence\B\json\verified-loop3-b-b3-browser-20261012-2236.json` | `_evidence/verified-loop3-b-b3-browser-20261012-2236.json` | 1373 | `08e825783dcbaa26e4d8ec140053da4efd9d3a9c06fc3c205f857bbae565ea90` | B | json | ①文件名 loop3-b- 显式档位标记 |
| 96 | `verified-loop3-b-b4-session-20261012-2236.json` | `D:\bounty-forge\evidence\B\json\verified-loop3-b-b4-session-20261012-2236.json` | `_evidence/verified-loop3-b-b4-session-20261012-2236.json` | 5301 | `8da7ea7a030d6780bb4d943d4e2722492d1591979fabe334f2d146c421df0cf7` | B | json | ①文件名 loop3-b- 显式档位标记 |
| 97 | `verified-loop3-b-b5-sink-20261012-2236.jsonl` | `D:\bounty-forge\evidence\B\jsonl\verified-loop3-b-b5-sink-20261012-2236.jsonl` | `_evidence/verified-loop3-b-b5-sink-20261012-2236.jsonl` | 1014 | `9c02018ae1b74037d61aceceed9bfd26680851f38f0d49d6dd9ae716f386214b` | B | jsonl | ①文件名 loop3-b- 显式档位标记 |
| 98 | `verified-loop3-b-b5-storedxss-20261012-2236.json` | `D:\bounty-forge\evidence\B\json\verified-loop3-b-b5-storedxss-20261012-2236.json` | `_evidence/verified-loop3-b-b5-storedxss-20261012-2236.json` | 4035 | `fed6f3bc6121f0430090f03312dce88edd9ba957175a8490fcce85135733f835` | B | json | ①文件名 loop3-b- 显式档位标记 |
| 99 | `verified-loop3-b-finalstate-20261012-2236.txt` | `D:\bounty-forge\evidence\B\txt\verified-loop3-b-finalstate-20261012-2236.txt` | `_evidence/verified-loop3-b-finalstate-20261012-2236.txt` | 2705 | `a28ac78c9688eb75ae717ff74ee91b6b93f11c8719288a52687aac71d26e74ce` | B | txt | ①文件名 loop3-b- 显式档位标记 |

### 2.100 证据档位 **C** —— 85 个

| # | 文件名 | 归档绝对路径 | 源相对路径 | 大小(B) | sha256 | 档位 | 类别 | 判定理由 |
|---|---|---|---|---|---|---|---|---|
| 101 | `T7LocalDeser.java` | `D:\bounty-forge\evidence\C\other\T7LocalDeser.java` | `_evidence/T7LocalDeser.java` | 1626 | `f6edd34945fd91635a646abd01bcf208812d1dc155b4449ca3a8cef6625fcbc1` | C | other | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 102 | `loop3-t7-c1-badpadding-oracle-20261012.json` | `D:\bounty-forge\evidence\C\json\loop3-t7-c1-badpadding-oracle-20261012.json` | `_evidence/loop3-t7-c1-badpadding-oracle-20261012.json` | 1745 | `af7b6fec1e3ecaa43a8c94e396b6a1b53b6ec08c7983cf3ccfd1ea1d9f4bd789` | C | json | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 103 | `loop3-t7-c1-discriminate-20261012.json` | `D:\bounty-forge\evidence\C\json\loop3-t7-c1-discriminate-20261012.json` | `_evidence/loop3-t7-c1-discriminate-20261012.json` | 903 | `07bcfa8bffa278c6609d4babf30837d13db9b6da741b04a2778f3b66506fe9a2` | C | json | ⚠️ **证据已证伪（采集器污染）**，见 §4 — 勿作结论引用 |
| 104 | `loop3-t7-c1-log-inventory-20261012.json` | `D:\bounty-forge\evidence\C\json\loop3-t7-c1-log-inventory-20261012.json` | `_evidence/loop3-t7-c1-log-inventory-20261012.json` | 3500 | `d9999386486cd56f2ffbe6c1ec2170fd96ce1777760290fd093b388ccc578074` | C | json | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 105 | `loop3-t7-c1-logoracle-20261012.json` | `D:\bounty-forge\evidence\C\json\loop3-t7-c1-logoracle-20261012.json` | `_evidence/loop3-t7-c1-logoracle-20261012.json` | 1708 | `2380fd6f63aa8d534db8001ddc0fbebc51af754667674583ed22b34f2814d783` | C | json | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 106 | `loop3-t7-c1-logtrace-20261012.json` | `D:\bounty-forge\evidence\C\json\loop3-t7-c1-logtrace-20261012.json` | `_evidence/loop3-t7-c1-logtrace-20261012.json` | 479 | `0fae78cfe7698e45b5c5ad13c74deddbf10ed2434a0551d24638f3d0841823a5` | C | json | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 107 | `loop3-t7-c1-matrix-20261012.json` | `D:\bounty-forge\evidence\C\json\loop3-t7-c1-matrix-20261012.json` | `_evidence/loop3-t7-c1-matrix-20261012.json` | 1476 | `99eba28d198218119330bb9852d75e7f7a518eef73d861d946a1e71bbb15e432` | C | json | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 108 | `loop3-t7-c1-oob.jsonl` | `D:\bounty-forge\evidence\C\jsonl\loop3-t7-c1-oob.jsonl` | `_evidence/loop3-t7-c1-oob.jsonl` | 3392 | `2a30520239c7f473ff5e9f2c4a239175e4b0805336e5f62ff81349912d721343` | C | jsonl | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 109 | `loop3-t7-c1-rate-and-baseline-20261012.json` | `D:\bounty-forge\evidence\C\json\loop3-t7-c1-rate-and-baseline-20261012.json` | `_evidence/loop3-t7-c1-rate-and-baseline-20261012.json` | 4785 | `68579107f657a551ca7032b456ecfec55863cdbf2e90d59cba65dd28d79d4a7e` | C | json | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 110 | `loop3-t7-c1-shiro-20261012.json` | `D:\bounty-forge\evidence\C\json\loop3-t7-c1-shiro-20261012.json` | `_evidence/loop3-t7-c1-shiro-20261012.json` | 3015 | `c08dc7eb74c3d000e9ec42dc728fab6edaf42d5a38dd406d05aee0b5188a49b7` | C | json | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 111 | `loop3-t7-c1-timing-20261012.json` | `D:\bounty-forge\evidence\C\json\loop3-t7-c1-timing-20261012.json` | `_evidence/loop3-t7-c1-timing-20261012.json` | 2868 | `02d547e655f7327db0bc6844ad02f9586aef9282be6173c6fdf65a96f8860051` | C | json | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 112 | `loop3-t7-c2-cleanup-raw.txt` | `D:\bounty-forge\evidence\C\txt\loop3-t7-c2-cleanup-raw.txt` | `_evidence/loop3-t7-c2-cleanup-raw.txt` | 4279 | `59dcb3a7e2b465456ac14fce59a90df169a2f6198890a0c1f4ab3c410d469ace` | C | txt | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 113 | `loop3-t7-c2-tomcat-put-raw.txt` | `D:\bounty-forge\evidence\C\txt\loop3-t7-c2-tomcat-put-raw.txt` | `_evidence/loop3-t7-c2-tomcat-put-raw.txt` | 794 | `80c1e9b297ce350717439b1afd68e6cf4f2318e7be2918e4ae327d036391a997` | C | txt | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 114 | `loop3-t7-recon1-out.txt` | `D:\bounty-forge\evidence\C\txt\loop3-t7-recon1-out.txt` | `_evidence/loop3-t7-recon1-out.txt` | 1078 | `9b50bc0bc63148a3e64470e99d7346a3faf0a816c7c0d0a6def61cbcd04945c2` | C | txt | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 115 | `loop3-t7-recon1.sh` | `D:\bounty-forge\evidence\C\script\loop3-t7-recon1.sh` | `_evidence/loop3-t7-recon1.sh` | 922 | `f7c256d06104998726befec1f6a5b7a99934db8e67ed9d7ea023f5c44030fcbb` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 116 | `loop3-t7-recon2-out.txt` | `D:\bounty-forge\evidence\C\txt\loop3-t7-recon2-out.txt` | `_evidence/loop3-t7-recon2-out.txt` | 1048 | `b79c32146a79eb9343278310998310d0957d46cc38dfbb367b6d6269d1fc4a14` | C | txt | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 117 | `loop3-t7-recon2.sh` | `D:\bounty-forge\evidence\C\script\loop3-t7-recon2.sh` | `_evidence/loop3-t7-recon2.sh` | 1803 | `506d802c202f4a94b6ca2d7fa7561991620e252616547db09ac0d0433c7c72c9` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 118 | `loop3-t7-shiro-jar-ce.sh` | `D:\bounty-forge\evidence\C\script\loop3-t7-shiro-jar-ce.sh` | `_evidence/loop3-t7-shiro-jar-ce.sh` | 782 | `f2d727119f1aaecaf419929b84c8ed42035ad86629a684e0cc316ac6970e56e9` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 119 | `loop3-t9-summary-20261012.json` | `D:\bounty-forge\evidence\C\json\loop3-t9-summary-20261012.json` | `_evidence/loop3-t9-summary-20261012.json` | 19208 | `2ed661810aa55a4bb3009cb4bbc8ec15fee1ff887208b352a5004538f5ef48d9` | C | json | ②内容实读嗅探（前 8KB）：内容含 shiro/rememberMe/18081/tomcat/18082/CVE 号 |
| 120 | `loop3-t9-summary.py` | `D:\bounty-forge\evidence\C\script\loop3-t9-summary.py` | `_evidence/loop3-t9-summary.py` | 11343 | `b8b908e5a600bce2fd5ac80b48fe2e7a729d8529dbbee9725376bda6f3ae40fe` | C | script | ②内容实读嗅探（前 8KB）：内容含 shiro/rememberMe/18081/tomcat/18082/CVE 号 |
| 121 | `loop3-vulhub-baseline-20261012-230400.json` | `D:\bounty-forge\evidence\C\json\loop3-vulhub-baseline-20261012-230400.json` | `_evidence/loop3-vulhub-baseline-20261012-230400.json` | 25331 | `9405a117308a0235f55b1fdbd306cb63b26db6848e9268cb36dbdd84bd87df26` | C | json | ②内容实读嗅探（前 8KB）：内容含 shiro/rememberMe/18081/tomcat/18082/CVE 号 |
| 122 | `loop3-vulhub-baseline-20261012-230400.sha256.txt` | `D:\bounty-forge\evidence\C\txt\loop3-vulhub-baseline-20261012-230400.sha256.txt` | `_evidence/loop3-vulhub-baseline-20261012-230400.sha256.txt` | 429 | `8a7fcde5ba00c9e8ee1ca60eedcc8ed6a9846c5f307261e6975c921fc2ba9d35` | C | txt | ②内容实读嗅探（前 8KB）：内容含 shiro/rememberMe/18081/tomcat/18082/CVE 号 |
| 123 | `next-lab-plan.md` | `D:\bounty-forge\evidence\C\md\next-lab-plan.md` | `_evidence/next-lab-plan.md` | 12597 | `09b6c9cdf18c673bd4a42782d35ed0a2aed5a83a53e69afa901ebcf46bc5a66d` | C | md | ②内容实读嗅探（前 8KB）：内容含 shiro/rememberMe/18081/tomcat/18082/CVE 号 |
| 124 | `t7-c1-badpadding-oracle.py` | `D:\bounty-forge\evidence\C\script\t7-c1-badpadding-oracle.py` | `_evidence/t7-c1-badpadding-oracle.py` | 5303 | `9554769d6a0e8abfa11b3690c3a2024fbff9d16c97818599a6a967fb2717c5d5` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 125 | `t7-c1-bruteforce-out.txt` | `D:\bounty-forge\evidence\C\txt\t7-c1-bruteforce-out.txt` | `_evidence/t7-c1-bruteforce-out.txt` | 2169 | `e27d26961b48611be36987a57fd749e64aa058dc2dbfaace9e15051be9e596d9` | C | txt | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 126 | `t7-c1-bruteforce.rb` | `D:\bounty-forge\evidence\C\other\t7-c1-bruteforce.rb` | `_evidence/t7-c1-bruteforce.rb` | 3061 | `dbb4196078b48d3685726ee284390aa05caf4baa36c1d1624da3e6e45b38fd95` | C | other | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 127 | `t7-c1-diag.rb` | `D:\bounty-forge\evidence\C\other\t7-c1-diag.rb` | `_evidence/t7-c1-diag.rb` | 1692 | `8776659bfc554ccc52c5693403bc2c100f7d68b902a00cdafbedcc4a26e47c5a` | C | other | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 128 | `t7-c1-discriminate.py` | `D:\bounty-forge\evidence\C\script\t7-c1-discriminate.py` | `_evidence/t7-c1-discriminate.py` | 2074 | `fcfc1506ef5bbb883825324ea153493fd29df150144172f59d38ce2a39de4063` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 129 | `t7-c1-discriminate.rb` | `D:\bounty-forge\evidence\C\other\t7-c1-discriminate.rb` | `_evidence/t7-c1-discriminate.rb` | 1586 | `a5eb4becce777cd01557bdd6cf974d3f371789fef9ebfd1cf5a650459a8a888c` | C | other | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 130 | `t7-c1-exploit2.py` | `D:\bounty-forge\evidence\C\script\t7-c1-exploit2.py` | `_evidence/t7-c1-exploit2.py` | 5032 | `d5bb2dad63baf2c4335797ebd8ff2f1a61bd864927f104a230454889c732ed7d` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 131 | `t7-c1-extractlib.sh` | `D:\bounty-forge\evidence\C\script\t7-c1-extractlib.sh` | `_evidence/t7-c1-extractlib.sh` | 694 | `fb7137aa355db06d9c3a40f6bbf7012c88db5222b7ae78ee5e689199642472b5` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 132 | `t7-c1-final.py` | `D:\bounty-forge\evidence\C\script\t7-c1-final.py` | `_evidence/t7-c1-final.py` | 5462 | `180ce35b96d06f140616ddbdc7759157c870e077a30289e27a6fb4121c936a9f` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 133 | `t7-c1-gen-cb1-out.txt` | `D:\bounty-forge\evidence\C\txt\t7-c1-gen-cb1-out.txt` | `_evidence/t7-c1-gen-cb1-out.txt` | 4040 | `77e2d4074e16ac50f73f875e6dbb29624f7c367adea5032b8d40d9e6147c7fbd` | C | txt | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 134 | `t7-c1-gen2.rb` | `D:\bounty-forge\evidence\C\other\t7-c1-gen2.rb` | `_evidence/t7-c1-gen2.rb` | 2647 | `a00bdfde394089f814a0b2358f9f7b0469bd6e1964684adc5fdc4c2948cb0bd9` | C | other | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 135 | `t7-c1-keycheck-out.txt` | `D:\bounty-forge\evidence\C\txt\t7-c1-keycheck-out.txt` | `_evidence/t7-c1-keycheck-out.txt` | 467 | `33a604f257bcde0a58cd1a37ab026cda1d88e6e062b96e8e4f4ac62c2af8e7be` | C | txt | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 136 | `t7-c1-keycheck.rb` | `D:\bounty-forge\evidence\C\other\t7-c1-keycheck.rb` | `_evidence/t7-c1-keycheck.rb` | 2150 | `fcf6f40afd7e4e8826b4a016a48ceb5919368f6a7aac2fc4c011ffe8f5f49e64` | C | other | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 137 | `t7-c1-log-inventory.py` | `D:\bounty-forge\evidence\C\script\t7-c1-log-inventory.py` | `_evidence/t7-c1-log-inventory.py` | 5194 | `59e5070eb5abacc74e1576c3edbd8987de3c7a85da5ca70e9f950b7e105eb6ab` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 138 | `t7-c1-log-oracle.sh` | `D:\bounty-forge\evidence\C\script\t7-c1-log-oracle.sh` | `_evidence/t7-c1-log-oracle.sh` | 1159 | `2a196e909a8762e74e96c82154db2e932934a8c95df10589da239d981f0e8a01` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 139 | `t7-c1-logoracle.py` | `D:\bounty-forge\evidence\C\script\t7-c1-logoracle.py` | `_evidence/t7-c1-logoracle.py` | 5906 | `cf2b1bd3d566f34f1f7a799816b280e3da73951a18f79bb2a8dd8c1c0aff5761` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 140 | `t7-c1-logstamp.sh` | `D:\bounty-forge\evidence\C\script\t7-c1-logstamp.sh` | `_evidence/t7-c1-logstamp.sh` | 1010 | `4575a13f0c00d37b6e426c946ad44dd84a81474930a0bb07e1b7b729c38bca6e` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 141 | `t7-c1-logtrace.py` | `D:\bounty-forge\evidence\C\script\t7-c1-logtrace.py` | `_evidence/t7-c1-logtrace.py` | 2682 | `16101f1eaa4b6eb2d83ecbad9faabeb9e013eb20ef5b436faac6f4785e78af81` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 142 | `t7-c1-matrix.py` | `D:\bounty-forge\evidence\C\script\t7-c1-matrix.py` | `_evidence/t7-c1-matrix.py` | 3074 | `35771951de99030843f0586ea3428a982e149bcac7cbf70e8646dd202ed58c36` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 143 | `t7-c1-matrix.rb` | `D:\bounty-forge\evidence\C\other\t7-c1-matrix.rb` | `_evidence/t7-c1-matrix.rb` | 1782 | `f883e7259757c9ff4f456106dd976a670f3f915b141c94a565096d24d9801e4c` | C | other | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 144 | `t7-c1-procwatch-inner-lf.sh` | `D:\bounty-forge\evidence\C\script\t7-c1-procwatch-inner-lf.sh` | `_evidence/t7-c1-procwatch-inner-lf.sh` | 723 | `06c7286c0f72474365e5413d66107131098cd55826c4092f4a3b057e80618cc7` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 145 | `t7-c1-procwatch-inner.sh` | `D:\bounty-forge\evidence\C\script\t7-c1-procwatch-inner.sh` | `_evidence/t7-c1-procwatch-inner.sh` | 747 | `60ebfc4ad6b65b1f9efe6b838224e53171a413f8ef9d915a55e39a6ceae4aa83` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 146 | `t7-c1-procwatch.sh` | `D:\bounty-forge\evidence\C\script\t7-c1-procwatch.sh` | `_evidence/t7-c1-procwatch.sh` | 1175 | `038b464c761ba007266227547091c8514c38c9e1fab3e138e30be3dff0c1934f` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 147 | `t7-c1-rate-baseline.py` | `D:\bounty-forge\evidence\C\script\t7-c1-rate-baseline.py` | `_evidence/t7-c1-rate-baseline.py` | 5536 | `6c5031e35d5617d93c24431200f0dc4071005c73b9bb3797e14c4f3388123560` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 148 | `t7-c1-rex-out.txt` | `D:\bounty-forge\evidence\C\txt\t7-c1-rex-out.txt` | `_evidence/t7-c1-rex-out.txt` | 1189 | `f4961af7909403921fbae2af5612994b8807ace645e648a3e122d312aa80c475` | C | txt | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 149 | `t7-c1-rex.sh` | `D:\bounty-forge\evidence\C\script\t7-c1-rex.sh` | `_evidence/t7-c1-rex.sh` | 899 | `4e0737d891fa3865cabe5a915da72be932931b0937550e90164283c077094092` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 150 | `t7-c1-send-self.sh` | `D:\bounty-forge\evidence\C\script\t7-c1-send-self.sh` | `_evidence/t7-c1-send-self.sh` | 537 | `e45372cad9816d89ad04962b2d03ef71683f9e1c21241430a5aaf073e2d58662` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 151 | `t7-c1-shiro-exploit.py` | `D:\bounty-forge\evidence\C\script\t7-c1-shiro-exploit.py` | `_evidence/t7-c1-shiro-exploit.py` | 4423 | `6c2faf497eb9ed536375ab27c92b638a0fb8c8f61973b7b22d5abf86516aa28a` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 152 | `t7-c1-shiro-gen.rb` | `D:\bounty-forge\evidence\C\other\t7-c1-shiro-gen.rb` | `_evidence/t7-c1-shiro-gen.rb` | 1692 | `9013779286eaa999776faa24713833b81e93d5c89721566ca93020c385cca59d` | C | other | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 153 | `t7-c1-timing.py` | `D:\bounty-forge\evidence\C\script\t7-c1-timing.py` | `_evidence/t7-c1-timing.py` | 3306 | `c380f85c0f179478145f85089fa821eb3804b6100721b80e30308488b466fe23` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 154 | `t7-c1-toolchain-out.txt` | `D:\bounty-forge\evidence\C\txt\t7-c1-toolchain-out.txt` | `_evidence/t7-c1-toolchain-out.txt` | 333 | `e5c00474c36ad013c62567f613ee85076056037f908ba51fdddaf1fc29cef013` | C | txt | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 155 | `t7-c1-toolchain.sh` | `D:\bounty-forge\evidence\C\script\t7-c1-toolchain.sh` | `_evidence/t7-c1-toolchain.sh` | 764 | `612ed9ea0eb2eedb8fcf20c1108b75371f708396b461fd757b49385a54405bb9` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 156 | `t7-c2-readonly.jsp` | `D:\bounty-forge\evidence\C\other\t7-c2-readonly.jsp` | `_evidence/t7-c2-readonly.jsp` | 703 | `75d4b2f2aa10a40d07ce3c7a3c98fbb6b7cdcc1fe9860f7bb64e86096eb0e8bf` | C | other | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 157 | `t7-localdeser-out.txt` | `D:\bounty-forge\evidence\C\txt\t7-localdeser-out.txt` | `_evidence/t7-localdeser-out.txt` | 2603 | `ea9eaaeee25c603dee544f63a05126a3cff3a6e77da3d24c2ec9a822174f54ff` | C | txt | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 158 | `t7-localdeser.sh` | `D:\bounty-forge\evidence\C\script\t7-localdeser.sh` | `_evidence/t7-localdeser.sh` | 1451 | `d345050a7fdf3818a7c68c54b4a42cd920d2792fe712e6c4c0c0d3de3ae7b4a1` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 159 | `t7-msf-check-out.txt` | `D:\bounty-forge\evidence\C\txt\t7-msf-check-out.txt` | `_evidence/t7-msf-check-out.txt` | 2762 | `f049579f318141ff5da0b2ea901de48a6be83bd36b91dfef0b4b3e46824fca10` | C | txt | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 160 | `t7-msf-check.sh` | `D:\bounty-forge\evidence\C\script\t7-msf-check.sh` | `_evidence/t7-msf-check.sh` | 665 | `f738001145e1ed718fab2ebad622578b57c4951392fc4b291af516e134ce5086` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 161 | `t7-msf-check2-out.txt` | `D:\bounty-forge\evidence\C\txt\t7-msf-check2-out.txt` | `_evidence/t7-msf-check2-out.txt` | 5926 | `ae50669a4d0e26bbb4fbffe714a6ee4e0fc3772e4c5a8227a5de7461014b9446` | C | txt | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 162 | `t7-msf-check2.sh` | `D:\bounty-forge\evidence\C\script\t7-msf-check2.sh` | `_evidence/t7-msf-check2.sh` | 600 | `d7c8eb935533cb40c20f126e861e8dc214009a9f22a1a3ccf53b55e191244d9b` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 163 | `t7-msf-crosscheck-out.txt` | `D:\bounty-forge\evidence\C\txt\t7-msf-crosscheck-out.txt` | `_evidence/t7-msf-crosscheck-out.txt` | 343 | `614d2b2e5ac471167b88aecb3506c6e473bb318a13f98cddeb36cd77462b3332` | C | txt | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 164 | `t7-msf-crosscheck.sh` | `D:\bounty-forge\evidence\C\script\t7-msf-crosscheck.sh` | `_evidence/t7-msf-crosscheck.sh` | 613 | `e1eba15a827b1a7c249a3aabbb575f77c316aeab67ebd16558e20f8f751540ff` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 165 | `t7-msf-java-out.txt` | `D:\bounty-forge\evidence\C\txt\t7-msf-java-out.txt` | `_evidence/t7-msf-java-out.txt` | 4400 | `b8c503892e054886700de82536c58402f0239a61e879f91edad0947ea789ed44` | C | txt | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 166 | `t7-msf-java.sh` | `D:\bounty-forge\evidence\C\script\t7-msf-java.sh` | `_evidence/t7-msf-java.sh` | 1371 | `c45ddc815d11797a23b46dad6667d468c375abaa17864e621f473301be0c20d2` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 167 | `t7-net-chain-check-out.txt` | `D:\bounty-forge\evidence\C\txt\t7-net-chain-check-out.txt` | `_evidence/t7-net-chain-check-out.txt` | 1880 | `6c840b7507e9dcbd740bba0e9ede9d2e8156506eb2a10b5a8be8dc9bcbe176bc` | C | txt | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 168 | `t7-net-chain-check.sh` | `D:\bounty-forge\evidence\C\script\t7-net-chain-check.sh` | `_evidence/t7-net-chain-check.sh` | 1209 | `c59328ae9a17ba1844e86ee31ff64c225cdefc0145840bb507677defed3d970a` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 169 | `t7-oob-listener.py` | `D:\bounty-forge\evidence\C\script\t7-oob-listener.py` | `_evidence/t7-oob-listener.py` | 1481 | `7b288e23be17b7bc0b90130ba73691d7ea3f1a06e974326070d04376647e0657` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 170 | `t7-prep-deser.sh` | `D:\bounty-forge\evidence\C\script\t7-prep-deser.sh` | `_evidence/t7-prep-deser.sh` | 716 | `90fef7cccdad1cdd0e5f87e7d41b45b421bb76e19c804e3e87c6683f80f11e48` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 171 | `t7-pw-cc6-clean.txt` | `D:\bounty-forge\evidence\C\txt\t7-pw-cc6-clean.txt` | `_evidence/t7-pw-cc6-clean.txt` | 1772 | `a2c4ae34bf2428c4f8c5193398d3cf411a50b8000a850ddf249aa0a67011da23` | C | txt | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 172 | `t7-pw-cc6.txt` | `D:\bounty-forge\evidence\C\txt\t7-pw-cc6.txt` | `_evidence/t7-pw-cc6.txt` | 1772 | `a2c4ae34bf2428c4f8c5193398d3cf411a50b8000a850ddf249aa0a67011da23` | C | txt | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 173 | `t7-pw-ck-clean.txt` | `D:\bounty-forge\evidence\C\txt\t7-pw-ck-clean.txt` | `_evidence/t7-pw-ck-clean.txt` | 1772 | `d5a97a9e5a6e5ecff12a2e2e89d9aafcff2a40e1036a2206680b662f4c2f0f5d` | C | txt | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 174 | `t7-report-selfcheck.py` | `D:\bounty-forge\evidence\C\script\t7-report-selfcheck.py` | `_evidence/t7-report-selfcheck.py` | 2707 | `e4042d7685c3e9b2d2977197c2935b2a41f0c57bf3314762d8fe23555e2e604a` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 175 | `t7-shiro-config.sh` | `D:\bounty-forge\evidence\C\script\t7-shiro-config.sh` | `_evidence/t7-shiro-config.sh` | 579 | `426080ece15659b6f20c69fa5bee4d415cec251cc985be7294eb65f498723b9a` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 176 | `t7-shiro-full-dockerlogs.txt` | `D:\bounty-forge\evidence\C\txt\t7-shiro-full-dockerlogs.txt` | `_evidence/t7-shiro-full-dockerlogs.txt` | 56159 | `6b37c61c4d4fcfed6036d7ce63f0323adfc9bc0f7f9b8acb6c66abf2db5d116b` | C | txt | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 177 | `t7-shiro-jar-inspect.sh` | `D:\bounty-forge\evidence\C\script\t7-shiro-jar-inspect.sh` | `_evidence/t7-shiro-jar-inspect.sh` | 560 | `634cf5a12b402e174caf629e3b986efb5b514eab5871cda99d60ff3bf26caa35` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 178 | `t7-shiro-javap.sh` | `D:\bounty-forge\evidence\C\script\t7-shiro-javap.sh` | `_evidence/t7-shiro-javap.sh` | 749 | `9e1cf59334b0327b6bed4db78f209825d4aeb450cdd1686217f8e5d5ad346b6a` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 179 | `t7-shiro-key.sh` | `D:\bounty-forge\evidence\C\script\t7-shiro-key.sh` | `_evidence/t7-shiro-key.sh` | 825 | `de474398897189f28eb31d3a718b16a95d2f360a724c6bec124e70cb65294cfc` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 180 | `t7-shiro-net.sh` | `D:\bounty-forge\evidence\C\script\t7-shiro-net.sh` | `_evidence/t7-shiro-net.sh` | 490 | `0e6a2fef9a0399fb5483b4685560a0fcd19a6d8306961787b8b8571b2a8d23bb` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 181 | `t7-tomcat-diag.sh` | `D:\bounty-forge\evidence\C\script\t7-tomcat-diag.sh` | `_evidence/t7-tomcat-diag.sh` | 728 | `143906b47dab12b7a2e53ee04807790e0be81d8742e7a8846c675dd82294ce75` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 182 | `t7-tomcat-inspect.sh` | `D:\bounty-forge\evidence\C\script\t7-tomcat-inspect.sh` | `_evidence/t7-tomcat-inspect.sh` | 514 | `139eee4b9386796bfb574915918dec232e4f5b2a876bb99689c26bbfd8ccdd4b` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 183 | `t7-tomcat-logs.sh` | `D:\bounty-forge\evidence\C\script\t7-tomcat-logs.sh` | `_evidence/t7-tomcat-logs.sh` | 431 | `37a9f1126b2c18e7b3b75f6dbfc87d462d97e41ee7c601599c65f1f20e365486` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 184 | `t7-tomcat-where.sh` | `D:\bounty-forge\evidence\C\script\t7-tomcat-where.sh` | `_evidence/t7-tomcat-where.sh` | 634 | `af3f0c9fcc85d9fe9969a6966dd333e80e72f0a609b09e388fb63dfd35e6028a` | C | script | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |
| 185 | `t7-ysoserial_payloads.json` | `D:\bounty-forge\evidence\C\json\t7-ysoserial_payloads.json` | `_evidence/t7-ysoserial_payloads.json` | 414380 | `4a93c6445e29d3d050ff910c8c91b2ce6b6d2a7d3066d67be1b5e2f13b9c1d57` | C | json | ①文件名规则：文件名含 t7（t7 = Vulhub C 档） |

### 2.186 证据档位 **T5** —— 90 个

| # | 文件名 | 归档绝对路径 | 源相对路径 | 大小(B) | sha256 | 档位 | 类别 | 判定理由 |
|---|---|---|---|---|---|---|---|---|
| 187 | `attack-surface-20261012-182250-SUPPLEMENT-01-head-reset.md` | `D:\bounty-forge\evidence\T5\md\attack-surface-20261012-182250-SUPPLEMENT-01-head-reset.md` | `_evidence/attack-surface-20261012-182250-SUPPLEMENT-01-head-reset.md` | 5985 | `ad9c3ada1919d7b192fdaa8c0c27c1c8f2ab6122acc7ec8754b5c6583e9c4598` | T5 | md | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 188 | `attack-surface-20261012-182250.json` | `D:\bounty-forge\evidence\T5\json\attack-surface-20261012-182250.json` | `_evidence/attack-surface-20261012-182250.json` | 37577 | `154b62ac6544fd7bb80b1d39264c02413a52d7b89705f7d911c9297457d8b91f` | T5 | json | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 189 | `attack-surface-20261012-182250.md` | `D:\bounty-forge\evidence\T5\md\attack-surface-20261012-182250.md` | `_evidence/attack-surface-20261012-182250.md` | 15138 | `2f8cefd67d25e33856b7511b223654d0ea35931bc73926bb95427014277f366d` | T5 | md | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 190 | `baseline-20261012-154202.json` | `D:\bounty-forge\evidence\T5\json\baseline-20261012-154202.json` | `_evidence/baseline-20261012-154202.json` | 1634 | `e82d757da4a86e87b78ce27af4b84a6b4741713d5bd01f0dfb2a256cb80beee7` | T5 | json | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 191 | `baseline-20261012-181212.json` | `D:\bounty-forge\evidence\T5\json\baseline-20261012-181212.json` | `_evidence/baseline-20261012-181212.json` | 11315 | `3d87f170acf57b9eb7374935463afb9b8c66dc23e5ec8092550032f6397d12bb` | T5 | json | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 192 | `baseline-20261012-194602.json` | `D:\bounty-forge\evidence\T5\json\baseline-20261012-194602.json` | `_evidence/baseline-20261012-194602.json` | 15473 | `4785110b6eb95db58cc5337095405ec0a8b175df336d221f2e9beeb8ba424103` | T5 | json | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 193 | `build-findings-hunt.py` | `D:\bounty-forge\evidence\T5\script\build-findings-hunt.py` | `_evidence/build-findings-hunt.py` | 20941 | `9fb81f480e7a93bfa78e0e69a341b93cb2bdea07ea1827e8b184051cda4d2d52` | T5 | script | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 194 | `findings-hunt-20261012-184124-index.md` | `D:\bounty-forge\evidence\T5\md\findings-hunt-20261012-184124-index.md` | `_evidence/findings-hunt-20261012-184124-index.md` | 6080 | `aeaee7fd23e8bf650f87ebc019a5182fd175cea2365ebc49be47ca5cc72df41a` | T5 | md | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 195 | `findings-hunt-20261012-184124.json` | `D:\bounty-forge\evidence\T5\json\findings-hunt-20261012-184124.json` | `_evidence/findings-hunt-20261012-184124.json` | 22465 | `44a39f9e92f8cf3ae562c5ea08deb41cf2f7eacb52e4d1972771bb2d5749ca29` | T5 | json | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 196 | `findings-hunt-20261012-184144-index.md` | `D:\bounty-forge\evidence\T5\md\findings-hunt-20261012-184144-index.md` | `_evidence/findings-hunt-20261012-184144-index.md` | 6080 | `1a2f28850cbdf851a2a9c97b9bd595eff3a65e338cb353c7740f6942935bc51e` | T5 | md | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 197 | `findings-hunt-20261012-184144.json` | `D:\bounty-forge\evidence\T5\json\findings-hunt-20261012-184144.json` | `_evidence/findings-hunt-20261012-184144.json` | 22620 | `82bd986a83f52f79045a0625f520d531c02b0e5e4295daa4d64bfcbe340340d6` | T5 | json | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 198 | `gen-attack-surface.py` | `D:\bounty-forge\evidence\T5\script\gen-attack-surface.py` | `_evidence/gen-attack-surface.py` | 30863 | `5d54ddc336bf250478e0d36fe60c8d52691e43007300fc0907037fbc1ed603b5` | T5 | script | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 199 | `hunt-a-bizlogic-20261012-1830.json` | `D:\bounty-forge\evidence\T5\json\hunt-a-bizlogic-20261012-1830.json` | `_evidence/hunt-a-bizlogic-20261012-1830.json` | 158748 | `74e927870ad07eb8935dedf8c5004c5653225a543f8ffd0e38b849ed8bdbcdb1` | T5 | json | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 200 | `hunt-a-bizlogic.py` | `D:\bounty-forge\evidence\T5\script\hunt-a-bizlogic.py` | `_evidence/hunt-a-bizlogic.py` | 13049 | `ad6a8be557a85d52ff367cec10529eae6deef542462cfd0b01e172fefad3089d` | T5 | script | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 201 | `hunt-a3b-race-order-20261012-1835.json` | `D:\bounty-forge\evidence\T5\json\hunt-a3b-race-order-20261012-1835.json` | `_evidence/hunt-a3b-race-order-20261012-1835.json` | 150960 | `f585a30f33984eb58c6bbf574f8dbe370df6509b092c4ab52430264dd41b9e85` | T5 | json | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 202 | `hunt-a3b-race-order.py` | `D:\bounty-forge\evidence\T5\script\hunt-a3b-race-order.py` | `_evidence/hunt-a3b-race-order.py` | 5687 | `79dcf050e07430301e725c4d443d3d220c6a01d0b1969f61db2dd42773372a8d` | T5 | script | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 203 | `hunt-b-idor.py` | `D:\bounty-forge\evidence\T5\script\hunt-b-idor.py` | `_evidence/hunt-b-idor.py` | 8471 | `6a2d1b4996c4b70c874b49c25f7c888b83fdd05f4424fb6f115d6a3b856b1d23` | T5 | script | ②内容实读嗅探（前 8KB）：内容为自建靶场通用探测工具链（recon/verify/sqlmap 等） |
| 204 | `hunt-c-upload-xss-rce.py` | `D:\bounty-forge\evidence\T5\script\hunt-c-upload-xss-rce.py` | `_evidence/hunt-c-upload-xss-rce.py` | 11027 | `e180d04cab501dad580754c4f9dc6817813faebef3c10f795ecd1643c52e67fc` | T5 | script | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 205 | `hunt-d-ssrf-8091-20261012-1850.json` | `D:\bounty-forge\evidence\T5\json\hunt-d-ssrf-8091-20261012-1850.json` | `_evidence/hunt-d-ssrf-8091-20261012-1850.json` | 651234 | `9b805df60b9c898364ffb32a6895e1d8a52926b9ec4d7b607ab0c3264cddae7d` | T5 | json | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 206 | `hunt-d-ssrf-8091.py` | `D:\bounty-forge\evidence\T5\script\hunt-d-ssrf-8091.py` | `_evidence/hunt-d-ssrf-8091.py` | 8953 | `64f2f40e95898e33e0dc92df84a737db436251944bc3d1f48401e2301c2e8c68` | T5 | script | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 207 | `hunt-e-wrapup.py` | `D:\bounty-forge\evidence\T5\script\hunt-e-wrapup.py` | `_evidence/hunt-e-wrapup.py` | 7586 | `9952e0186e185b411eef44c1e16b77f0035a44974456eaeb9809e6895af86ae8` | T5 | script | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 208 | `hunt-f-extra.py` | `D:\bounty-forge\evidence\T5\script\hunt-f-extra.py` | `_evidence/hunt-f-extra.py` | 7039 | `9b5c2da6460fa0b7e4902bdfab12a58cd031c838fcecbf6be74a6c026095b19c` | T5 | script | ②内容实读嗅探（前 8KB）：内容为自建靶场通用探测工具链（recon/verify/sqlmap 等） |
| 209 | `hunt-f7-logout-20261012-1905.json` | `D:\bounty-forge\evidence\T5\json\hunt-f7-logout-20261012-1905.json` | `_evidence/hunt-f7-logout-20261012-1905.json` | 12455 | `bf37dad242da54431174b44db341c942bba66280f4c05ebf370667d13dbd1a65` | T5 | json | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 210 | `mentor-recheck-20261012.json` | `D:\bounty-forge\evidence\T5\json\mentor-recheck-20261012.json` | `_evidence/mentor-recheck-20261012.json` | 1334 | `2278425a87d81ddfafa76eba8661bc36b5b7a949c06761a5efbfdf4b5bc1f1cc` | T5 | json | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 211 | `mentor-recheck-20261012.py` | `D:\bounty-forge\evidence\T5\script\mentor-recheck-20261012.py` | `_evidence/mentor-recheck-20261012.py` | 3193 | `504c53d2d889ebfd3d44956e649416e18ecd3fb348d56eb5c9d35a884776fe3f` | T5 | script | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 212 | `mentor-recheck2-20261012.py` | `D:\bounty-forge\evidence\T5\script\mentor-recheck2-20261012.py` | `_evidence/mentor-recheck2-20261012.py` | 1703 | `59d770596444b4bf96e0c8ef16bf118989a1e1581b72bd8826d4eedb6498920b` | T5 | script | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 213 | `range-admin-ops-notes.md` | `D:\bounty-forge\evidence\T5\md\range-admin-ops-notes.md` | `_evidence/range-admin-ops-notes.md` | 7928 | `1ad1b7a77e11f12b02e9fe91b74f4c658c62ec2692ef2a0e4915fc2b68ba8de7` | T5 | md | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 214 | `raw-probe.py` | `D:\bounty-forge\evidence\T5\script\raw-probe.py` | `_evidence/raw-probe.py` | 922 | `cc62681964a80528967bfce7141e5eb440c17f652fccb66c4006cdac7c1c0f64` | T5 | script | ②内容实读嗅探（前 8KB）：内容为自建靶场通用探测工具链（recon/verify/sqlmap 等） |
| 215 | `recon-01-probe.json` | `D:\bounty-forge\evidence\T5\json\recon-01-probe.json` | `_evidence/recon-01-probe.json` | 9313 | `d5497f08202c36f705256b2062d114d9f2dfa3a62107dd36e9e6843832be1216` | T5 | json | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 216 | `recon-01-probe.py` | `D:\bounty-forge\evidence\T5\script\recon-01-probe.py` | `_evidence/recon-01-probe.py` | 6651 | `cdd777603ad90aa65ea34d2d90702aba7657ac493d87c0523e1e7171dd0ce882` | T5 | script | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 217 | `recon-02-login-flow.py` | `D:\bounty-forge\evidence\T5\script\recon-02-login-flow.py` | `_evidence/recon-02-login-flow.py` | 2909 | `f67456c07caf8b4de082577553dfeaf5db29872c5e32eaa66d025fd0f05cca9a` | T5 | script | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 218 | `recon-03-proc-cwd.py` | `D:\bounty-forge\evidence\T5\script\recon-03-proc-cwd.py` | `_evidence/recon-03-proc-cwd.py` | 3678 | `d6c0f2a6eac6c54666d89c6ef2ac0a480057d294a0ce8d1e905ae5b7046f8841` | T5 | script | ②内容实读嗅探（前 8KB）：内容为自建靶场通用探测工具链（recon/verify/sqlmap 等） |
| 219 | `recon-04-fingerprint.py` | `D:\bounty-forge\evidence\T5\script\recon-04-fingerprint.py` | `_evidence/recon-04-fingerprint.py` | 4336 | `1b324a699bfdf3fc2fc99f35b8a1cb3baeac05f78267fe84acfc4375f73ede90` | T5 | script | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 220 | `recon-05-authz.py` | `D:\bounty-forge\evidence\T5\script\recon-05-authz.py` | `_evidence/recon-05-authz.py` | 6085 | `aa45b79c501d32e61a194b6a8e70576aa998dba66aeb593954c9fb400c129b74` | T5 | script | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 221 | `recon-07-methods.py` | `D:\bounty-forge\evidence\T5\script\recon-07-methods.py` | `_evidence/recon-07-methods.py` | 5740 | `c95eab75d2d787499d345f19d5b3796c9c5159542dd77be9fb1683f91fd832a3` | T5 | script | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 222 | `recon-08-targetb.py` | `D:\bounty-forge\evidence\T5\script\recon-08-targetb.py` | `_evidence/recon-08-targetb.py` | 4961 | `ecb45b871efc69a2a3b7a1bb40fe24b3d9dc9d9d9c27037758ef33ff0bbf968c` | T5 | script | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 223 | `recon-09-findings.json` | `D:\bounty-forge\evidence\T5\json\recon-09-findings.json` | `_evidence/recon-09-findings.json` | 6620 | `b0774a6227a40ff8b35f5becd7be2fe3d4123264cdb381f8855c4c984fb6781a` | T5 | json | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 224 | `recon-09-findings.py` | `D:\bounty-forge\evidence\T5\script\recon-09-findings.py` | `_evidence/recon-09-findings.py` | 13196 | `1b247ed0ee1a68b29f6f61ccd2210c134facf6b73d4313b0e8393a0fdc23b8ea` | T5 | script | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 225 | `recon-10-surface-20261012-181548.json` | `D:\bounty-forge\evidence\T5\json\recon-10-surface-20261012-181548.json` | `_evidence/recon-10-surface-20261012-181548.json` | 29254 | `bff6771f067154050308687a7afc5cfdbaeed8b797f2742ce9a9a7f2811ed987` | T5 | json | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 226 | `recon-10-surface.py` | `D:\bounty-forge\evidence\T5\script\recon-10-surface.py` | `_evidence/recon-10-surface.py` | 7690 | `d388d9c5e91a0ec5f97a53f75b884b87b424ae7db7632571d2d2a1e7a9f486ab` | T5 | script | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 227 | `recon-11-login-trace.py` | `D:\bounty-forge\evidence\T5\script\recon-11-login-trace.py` | `_evidence/recon-11-login-trace.py` | 3583 | `9ceccd42bb3b8975803f73bef93a17689adf063f0bb86c8b9197372f3455a413` | T5 | script | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 228 | `recon-12-methods-20261012-182046.json` | `D:\bounty-forge\evidence\T5\json\recon-12-methods-20261012-182046.json` | `_evidence/recon-12-methods-20261012-182046.json` | 44214 | `b2885beb9567dbec20645c331bfbe7b3bd6d039c65b6b4d7a65dcb8673dd9a02` | T5 | json | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 229 | `recon-12-methods.py` | `D:\bounty-forge\evidence\T5\script\recon-12-methods.py` | `_evidence/recon-12-methods.py` | 6382 | `de8647cd1bd542e0edcf511a6442519bef1db4af4ff9fa57a2323a01d88c988a` | T5 | script | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 230 | `recon-13-verify-state.py` | `D:\bounty-forge\evidence\T5\script\recon-13-verify-state.py` | `_evidence/recon-13-verify-state.py` | 1394 | `b6805fec140cf28b6dbc6111c044d83e1fb2f83f02dc79f102fee9b58ae663a6` | T5 | script | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 231 | `recon-attack-surface-map.json` | `D:\bounty-forge\evidence\T5\json\recon-attack-surface-map.json` | `_evidence/recon-attack-surface-map.json` | 14444 | `41be49e49707855bb39124a8a90258cb99b75b432fc9e0761298b3a7a4e7dcd4` | T5 | json | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 232 | `recon-ffuf-8091-20261012-181448.json` | `D:\bounty-forge\evidence\T5\json\recon-ffuf-8091-20261012-181448.json` | `_evidence/recon-ffuf-8091-20261012-181448.json` | 3391 | `8818d2256c296dc5714182b56d9bca953617a1a0e58ba2ffde07badb541ff3b4` | T5 | json | ②内容实读嗅探（前 8KB）：内容含 8091（target-site v2，同属自建靶场） |
| 233 | `recon-ffuf-8095-20261012-181448.json` | `D:\bounty-forge\evidence\T5\json\recon-ffuf-8095-20261012-181448.json` | `_evidence/recon-ffuf-8095-20261012-181448.json` | 5745 | `7980697e796cb83e4f4186807c93aeb9275666f4d84c84c1146444d8aae60526` | T5 | json | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 234 | `recon-httpx-20261012-181433.txt` | `D:\bounty-forge\evidence\T5\txt\recon-httpx-20261012-181433.txt` | `_evidence/recon-httpx-20261012-181433.txt` | 164 | `70e60440909c32016fdc511fd77f03dc25652d2344e4807006b755e6622acf34` | T5 | txt | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 235 | `recon-katana-8091-20261012-181504.jsonl` | `D:\bounty-forge\evidence\T5\jsonl\recon-katana-8091-20261012-181504.jsonl` | `_evidence/recon-katana-8091-20261012-181504.jsonl` | 26825 | `910558b23ff05998ff91a090e8133aa5545f2d0b884f4631c8305738ca2b1148` | T5 | jsonl | ②内容实读嗅探（前 8KB）：内容含 8091（target-site v2，同属自建靶场） |
| 236 | `recon-katana-8095-20261012-181504.jsonl` | `D:\bounty-forge\evidence\T5\jsonl\recon-katana-8095-20261012-181504.jsonl` | `_evidence/recon-katana-8095-20261012-181504.jsonl` | 55958 | `1937b0477798a7217a317eca368da3fa380ad736f016cbb2dfa7e88da3429c15` | T5 | jsonl | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 237 | `recon-nuclei-20261012-181707.jsonl` | `D:\bounty-forge\evidence\T5\jsonl\recon-nuclei-20261012-181707.jsonl` | `_evidence/recon-nuclei-20261012-181707.jsonl` | 64867 | `6133afc9485e5d7981a049779fd283ab4502d144c45667b20c86e081c1fd70d3` | T5 | jsonl | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 238 | `sqlmap-run-8095-8091.log` | `D:\bounty-forge\evidence\T5\log\sqlmap-run-8095-8091.log` | `_evidence/sqlmap-run-8095-8091.log` | 29314 | `b6678f290f96a640d49be420e51fd7a838aeb1001fe3323256cffa1c130a25df` | T5 | log | ②内容实读嗅探（前 8KB）：内容为自建靶场通用探测工具链（recon/verify/sqlmap 等） |
| 239 | `sqmap-8091-login__127.0.0.1__log` | `D:\bounty-forge\evidence\T5\other\sqmap-8091-login__127.0.0.1__log` | `_evidence/sqmap-8091-login/127.0.0.1/log` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | T5 | other | ①目录名规则：目录名 sqmap-8091/8095（自建靶场 sqlmap 会话） |
| 240 | `sqmap-8091-login__127.0.0.1__session.sqlite` | `D:\bounty-forge\evidence\T5\other\sqmap-8091-login__127.0.0.1__session.sqlite` | `_evidence/sqmap-8091-login/127.0.0.1/session.sqlite` | 8192 | `7f28040fbf4df5d2934de2bf33019a53173b9aa908be8f2f0ecf06b6557e1124` | T5 | other | ①目录名规则：目录名 sqmap-8091/8095（自建靶场 sqlmap 会话） |
| 241 | `sqmap-8091-login__127.0.0.1__target.txt` | `D:\bounty-forge\evidence\T5\txt\sqmap-8091-login__127.0.0.1__target.txt` | `_evidence/sqmap-8091-login/127.0.0.1/target.txt` | 340 | `07556b5993659fc3ffa96e42fc630a8f6bd3a6558ebdfd95e4cb4a80edb0fac2` | T5 | txt | ①目录名规则：目录名 sqmap-8091/8095（自建靶场 sqlmap 会话） |
| 242 | `sqmap-8091-loginpw__127.0.0.1__log` | `D:\bounty-forge\evidence\T5\other\sqmap-8091-loginpw__127.0.0.1__log` | `_evidence/sqmap-8091-loginpw/127.0.0.1/log` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | T5 | other | ①目录名规则：目录名 sqmap-8091/8095（自建靶场 sqlmap 会话） |
| 243 | `sqmap-8091-loginpw__127.0.0.1__target.txt` | `D:\bounty-forge\evidence\T5\txt\sqmap-8091-loginpw__127.0.0.1__target.txt` | `_evidence/sqmap-8091-loginpw/127.0.0.1/target.txt` | 318 | `36be3acdfa80f8fa659f19054f83015f732292de16a2824362b9961913fe70b3` | T5 | txt | ①目录名规则：目录名 sqmap-8091/8095（自建靶场 sqlmap 会话） |
| 244 | `sqmap-8091-register__127.0.0.1__log` | `D:\bounty-forge\evidence\T5\other\sqmap-8091-register__127.0.0.1__log` | `_evidence/sqmap-8091-register/127.0.0.1/log` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | T5 | other | ①目录名规则：目录名 sqmap-8091/8095（自建靶场 sqlmap 会话） |
| 245 | `sqmap-8091-register__127.0.0.1__session.sqlite` | `D:\bounty-forge\evidence\T5\other\sqmap-8091-register__127.0.0.1__session.sqlite` | `_evidence/sqmap-8091-register/127.0.0.1/session.sqlite` | 8192 | `6d4cd91d8bb53930ba9a09431ae7639d3ca251007b8d43f245b4c0b8b829055d` | T5 | other | ①目录名规则：目录名 sqmap-8091/8095（自建靶场 sqlmap 会话） |
| 246 | `sqmap-8091-register__127.0.0.1__target.txt` | `D:\bounty-forge\evidence\T5\txt\sqmap-8091-register__127.0.0.1__target.txt` | `_evidence/sqmap-8091-register/127.0.0.1/target.txt` | 381 | `ff8eba7ec0c134174019cef4c686375dad57744bc58176f96504b13ffb7a5050` | T5 | txt | ①目录名规则：目录名 sqmap-8091/8095（自建靶场 sqlmap 会话） |
| 247 | `sqmap-8095-apisearch__127.0.0.1__log` | `D:\bounty-forge\evidence\T5\other\sqmap-8095-apisearch__127.0.0.1__log` | `_evidence/sqmap-8095-apisearch/127.0.0.1/log` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | T5 | other | ①目录名规则：目录名 sqmap-8091/8095（自建靶场 sqlmap 会话） |
| 248 | `sqmap-8095-apisearch__127.0.0.1__session.sqlite` | `D:\bounty-forge\evidence\T5\other\sqmap-8095-apisearch__127.0.0.1__session.sqlite` | `_evidence/sqmap-8095-apisearch/127.0.0.1/session.sqlite` | 8192 | `27e61c98f4fc18d0400ae2ea63ba98d32413095924af95507e6e0ed97430f7c6` | T5 | other | ①目录名规则：目录名 sqmap-8091/8095（自建靶场 sqlmap 会话） |
| 249 | `sqmap-8095-apisearch__127.0.0.1__target.txt` | `D:\bounty-forge\evidence\T5\txt\sqmap-8095-apisearch__127.0.0.1__target.txt` | `_evidence/sqmap-8095-apisearch/127.0.0.1/target.txt` | 264 | `6c11c752086a6e08abff37e1693263c896dc1efa9cb7e96871b23e7dd5e7c582` | T5 | txt | ①目录名规则：目录名 sqmap-8091/8095（自建靶场 sqlmap 会话） |
| 250 | `sqmap-8095-board__127.0.0.1__log` | `D:\bounty-forge\evidence\T5\other\sqmap-8095-board__127.0.0.1__log` | `_evidence/sqmap-8095-board/127.0.0.1/log` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | T5 | other | ①目录名规则：目录名 sqmap-8091/8095（自建靶场 sqlmap 会话） |
| 251 | `sqmap-8095-board__127.0.0.1__target.txt` | `D:\bounty-forge\evidence\T5\txt\sqmap-8095-board__127.0.0.1__target.txt` | `_evidence/sqmap-8095-board/127.0.0.1/target.txt` | 265 | `132fa2d0f4356889d4a38533b6ed75088f51b0274ccf9973891838aecc86edec` | T5 | txt | ①目录名规则：目录名 sqmap-8091/8095（自建靶场 sqlmap 会话） |
| 252 | `sqmap-8095-login__127.0.0.1__log` | `D:\bounty-forge\evidence\T5\other\sqmap-8095-login__127.0.0.1__log` | `_evidence/sqmap-8095-login/127.0.0.1/log` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | T5 | other | ①目录名规则：目录名 sqmap-8091/8095（自建靶场 sqlmap 会话） |
| 253 | `sqmap-8095-login__127.0.0.1__session.sqlite` | `D:\bounty-forge\evidence\T5\other\sqmap-8095-login__127.0.0.1__session.sqlite` | `_evidence/sqmap-8095-login/127.0.0.1/session.sqlite` | 8192 | `7f28040fbf4df5d2934de2bf33019a53173b9aa908be8f2f0ecf06b6557e1124` | T5 | other | ①目录名规则：目录名 sqmap-8091/8095（自建靶场 sqlmap 会话） |
| 254 | `sqmap-8095-login__127.0.0.1__target.txt` | `D:\bounty-forge\evidence\T5\txt\sqmap-8095-login__127.0.0.1__target.txt` | `_evidence/sqmap-8095-login/127.0.0.1/target.txt` | 290 | `a569f2afdedcbc0ddb81e7d08b7d157f5ce0081ccc1a83b8f59382b24cf973b2` | T5 | txt | ①目录名规则：目录名 sqmap-8091/8095（自建靶场 sqlmap 会话） |
| 255 | `sqmap-8095-search__127.0.0.1__log` | `D:\bounty-forge\evidence\T5\other\sqmap-8095-search__127.0.0.1__log` | `_evidence/sqmap-8095-search/127.0.0.1/log` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | T5 | other | ①目录名规则：目录名 sqmap-8091/8095（自建靶场 sqlmap 会话） |
| 256 | `sqmap-8095-search__127.0.0.1__session.sqlite` | `D:\bounty-forge\evidence\T5\other\sqmap-8095-search__127.0.0.1__session.sqlite` | `_evidence/sqmap-8095-search/127.0.0.1/session.sqlite` | 8192 | `49d7afd03d930fe0658ebde0c54c21e6a611a58d42ddbd03c8685b43f06f1941` | T5 | other | ①目录名规则：目录名 sqmap-8091/8095（自建靶场 sqlmap 会话） |
| 257 | `sqmap-8095-search__127.0.0.1__target.txt` | `D:\bounty-forge\evidence\T5\txt\sqmap-8095-search__127.0.0.1__target.txt` | `_evidence/sqmap-8095-search/127.0.0.1/target.txt` | 268 | `2eca7447ff1405051d2f7a18ef030c4c9eff5cb462920094ba14397e38ab8262` | T5 | txt | ①目录名规则：目录名 sqmap-8091/8095（自建靶场 sqlmap 会话） |
| 258 | `verified-20261012-184800-SUPPLEMENT-01.md` | `D:\bounty-forge\evidence\T5\md\verified-20261012-184800-SUPPLEMENT-01.md` | `_evidence/verified-20261012-184800-SUPPLEMENT-01.md` | 7999 | `4f9d8344e257734afd981f0896b6d068e838121660123ce5992d995e1c84f24f` | T5 | md | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 259 | `verified-20261012-184800.json` | `D:\bounty-forge\evidence\T5\json\verified-20261012-184800.json` | `_evidence/verified-20261012-184800.json` | 38035 | `218dc13d10cb4063e2eb9b85d0b220fa04d33af20499f24025a103dcbf83c020` | T5 | json | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 260 | `verified-20261012-184800.md` | `D:\bounty-forge\evidence\T5\md\verified-20261012-184800.md` | `_evidence/verified-20261012-184800.md` | 8383 | `b94cbc96f8637ac4af758c8b669f35de26395812131e910e3b588cca1f9d713d` | T5 | md | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 261 | `verify-00-baseline-20261012-1855.json` | `D:\bounty-forge\evidence\T5\json\verify-00-baseline-20261012-1855.json` | `_evidence/verify-00-baseline-20261012-1855.json` | 10176 | `c9aa99a4ea131a9840b9349c832357929466ffeeb23a40047fac94a6542ec818` | T5 | json | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 262 | `verify-01-race-20261012-1855.json` | `D:\bounty-forge\evidence\T5\json\verify-01-race-20261012-1855.json` | `_evidence/verify-01-race-20261012-1855.json` | 215469 | `6169f0fe2a960c2bbe1dc3080948837805fcfe36b7f5b7042dbc1bcebd382793` | T5 | json | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 263 | `verify-02-logic-session-20261012-1855.json` | `D:\bounty-forge\evidence\T5\json\verify-02-logic-session-20261012-1855.json` | `_evidence/verify-02-logic-session-20261012-1855.json` | 71570 | `1b7b154509e9a95157fbd67b78a22289798a0d0383af802c48f8007a5a74cd5c` | T5 | json | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 264 | `verify-03-injection-ssrf-upload-20261012-1855.json` | `D:\bounty-forge\evidence\T5\json\verify-03-injection-ssrf-upload-20261012-1855.json` | `_evidence/verify-03-injection-ssrf-upload-20261012-1855.json` | 69509 | `d168699eede0933b74257f3080e4677db22e511859d25c0fa376b3de7a086fd2` | T5 | json | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 265 | `verify-04-ssrf-redirect-upload-20261012-1855.json` | `D:\bounty-forge\evidence\T5\json\verify-04-ssrf-redirect-upload-20261012-1855.json` | `_evidence/verify-04-ssrf-redirect-upload-20261012-1855.json` | 40297 | `2efd7e6d8c30479da62d39f4354040d4b510e0a345be207c1c50156b3af6f5d2` | T5 | json | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 266 | `verify-05-ssrf-chain-20261012-1855.json` | `D:\bounty-forge\evidence\T5\json\verify-05-ssrf-chain-20261012-1855.json` | `_evidence/verify-05-ssrf-chain-20261012-1855.json` | 2471 | `d3ea2949199e7a5701fc54e167e4ee9172eeb2daaf525b85144486c258f54121` | T5 | json | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 267 | `verify-06-csrf-hmac-proof-20261012-1855.json` | `D:\bounty-forge\evidence\T5\json\verify-06-csrf-hmac-proof-20261012-1855.json` | `_evidence/verify-06-csrf-hmac-proof-20261012-1855.json` | 8605 | `11b0aabd9629d21c2d0e6fefbf9fbfd27ae35d5cd6bc975764df9d27cb8fd962` | T5 | json | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 268 | `verify-07-atomicity-redirect-scope-20261012-1855.json` | `D:\bounty-forge\evidence\T5\json\verify-07-atomicity-redirect-scope-20261012-1855.json` | `_evidence/verify-07-atomicity-redirect-scope-20261012-1855.json` | 197395 | `58cd70138de1cc2662d9dcd878be3079ddf7b41d61b51bb3ff0de2a479a7ee84` | T5 | json | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 269 | `verify-lib.py` | `D:\bounty-forge\evidence\T5\script\verify-lib.py` | `_evidence/verify-lib.py` | 5108 | `01119ee376287c66c9656f63cddf8a6287fdfe88ac4852354c71ae55bf2b9576` | T5 | script | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 270 | `verify-step0-baseline.py` | `D:\bounty-forge\evidence\T5\script\verify-step0-baseline.py` | `_evidence/verify-step0-baseline.py` | 1328 | `209a997b8e53a47e3ba746696e27cc533a04801216d43d6e78cc52627d0a5ea5` | T5 | script | ②内容实读嗅探（前 8KB）：内容为自建靶场通用探测工具链（recon/verify/sqlmap 等） |
| 271 | `verify-step1-race.py` | `D:\bounty-forge\evidence\T5\script\verify-step1-race.py` | `_evidence/verify-step1-race.py` | 4216 | `1fd24283f43f9dc99d40a31a4cb7573d3188b39b3d36755cde5600f176b6cf9f` | T5 | script | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 272 | `verify-step3-step3.py` | `D:\bounty-forge\evidence\T5\script\verify-step3-step3.py` | `_evidence/verify-step3-step3.py` | 11438 | `7c874a9d676750214f8c9a3da0d593095c6ce64b9d6bc93380609e8e8520eba1` | T5 | script | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 273 | `verify-step4-ssrf.py` | `D:\bounty-forge\evidence\T5\script\verify-step4-ssrf.py` | `_evidence/verify-step4-ssrf.py` | 6987 | `fc4ead690d2be0a14252459ba4d6f358efa58bef2288a8b0e945d9cf3299611f` | T5 | script | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 274 | `verify-step5-ssrf-chain.py` | `D:\bounty-forge\evidence\T5\script\verify-step5-ssrf-chain.py` | `_evidence/verify-step5-ssrf-chain.py` | 2863 | `532496d9fe5663922b0c21bc2da622c4c82afa1f2303240457af3d7eefe5c973` | T5 | script | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 275 | `verify-step7-atomicity.py` | `D:\bounty-forge\evidence\T5\script\verify-step7-atomicity.py` | `_evidence/verify-step7-atomicity.py` | 8108 | `72af369ff2a8b5309bbad55302d5972f30b208b75853b6e1d6323f15771dfd16` | T5 | script | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |
| 276 | `verify_lib.py` | `D:\bounty-forge\evidence\T5\script\verify_lib.py` | `_evidence/verify_lib.py` | 5457 | `041ebd7ec9f59a874a74275f939ef16bedb6755dfacdd007f58fae91b4cd2151` | T5 | script | ②内容实读嗅探（前 8KB）：内容含 target-site-lab 或 8095（自建靶场） |

### 2.277 证据档位 **META** —— 8 个

| # | 文件名 | 归档绝对路径 | 源相对路径 | 大小(B) | sha256 | 档位 | 类别 | 判定理由 |
|---|---|---|---|---|---|---|---|---|
| 278 | `t8-archive-check-20261012.json` | `D:\bounty-forge\evidence\META\json\t8-archive-check-20261012.json` | `_evidence/t8-archive-check-20261012.json` | 11900 | `717c9afe88061b32eba1c8e7f55a0c272e846f0977bd65e66fde27094e64a518` | META | json | ①文件名规则：文件名含 t8（归档/统计类任务产物，非漏洞条目） |
| 279 | `t8-archive-check-20261012.pre-rewrite.json` | `D:\bounty-forge\evidence\META\json\t8-archive-check-20261012.pre-rewrite.json` | `_evidence/t8-archive-check-20261012.pre-rewrite.json` | 11711 | `f5afa7e06b9ac936e500ad7e3f659f045091d34d55d7ec6277c071fd7289bc74` | META | json | ①文件名规则：文件名含 t8（归档/统计类任务产物，非漏洞条目） |
| 280 | `t8-archive-check-20261012.py` | `D:\bounty-forge\evidence\META\script\t8-archive-check-20261012.py` | `_evidence/t8-archive-check-20261012.py` | 2255 | `2a69d0a959fb56221d9bb27938949b2a8a61166fe6c6a0583b31100f851014bd` | META | script | ①文件名规则：文件名含 t8（归档/统计类任务产物，非漏洞条目） |
| 281 | `t8-archive-recheck-1908.json` | `D:\bounty-forge\evidence\META\json\t8-archive-recheck-1908.json` | `_evidence/t8-archive-recheck-1908.json` | 11943 | `8cb684a0b4f6d8d9e167a97c27156c653b642b2688fc91637d7c35ef8d0fba74` | META | json | ①文件名规则：文件名含 t8（归档/统计类任务产物，非漏洞条目） |
| 282 | `t8-archive-recheck-1930.json` | `D:\bounty-forge\evidence\META\json\t8-archive-recheck-1930.json` | `_evidence/t8-archive-recheck-1930.json` | 11943 | `6dc3512b3289c13f8ab7416fb1dcac4749c2d49123941eaeefffa41af27d1eaa` | META | json | ①文件名规则：文件名含 t8（归档/统计类任务产物，非漏洞条目） |
| 283 | `t8-archive-recheck-1930.py` | `D:\bounty-forge\evidence\META\script\t8-archive-recheck-1930.py` | `_evidence/t8-archive-recheck-1930.py` | 3179 | `f8ce81f9cbd90a18eea9c305e69be5489e3c2fbec503320edae09edd41b1b15b` | META | script | ①文件名规则：文件名含 t8（归档/统计类任务产物，非漏洞条目） |
| 284 | `t8-stats-20261012.json` | `D:\bounty-forge\evidence\META\json\t8-stats-20261012.json` | `_evidence/t8-stats-20261012.json` | 1184 | `0032809e72995ec3e9080b441bca443d66dc841cb97eafda6a0cb36d162e65c7` | META | json | ①文件名规则：文件名含 t8（归档/统计类任务产物，非漏洞条目） |
| 285 | `t8-stats-20261012.py` | `D:\bounty-forge\evidence\META\script\t8-stats-20261012.py` | `_evidence/t8-stats-20261012.py` | 3571 | `6402adcdb4bb329f9adde7243263cab07048b78cd80d26555f7e56f0b1823600` | META | script | ①文件名规则：文件名含 t8（归档/统计类任务产物，非漏洞条目） |

### 2.286 证据档位 **L2** —— 28 个

| # | 文件名 | 归档绝对路径 | 源相对路径 | 大小(B) | sha256 | 档位 | 类别 | 判定理由 |
|---|---|---|---|---|---|---|---|---|
| 287 | `loop2-verify-20261012-200626.json` | `D:\bounty-forge\evidence\L2\json\loop2-verify-20261012-200626.json` | `_evidence/loop2-verify-20261012-200626.json` | 67682 | `fcf24fca95b31baf2e29fa09c32bc62332f4936f58875535853f64cf7bcf165e` | L2 | json | ①文件名含 loop2（loop2 基线证据） |
| 288 | `loop2-verify-20261012-200719.json` | `D:\bounty-forge\evidence\L2\json\loop2-verify-20261012-200719.json` | `_evidence/loop2-verify-20261012-200719.json` | 217228 | `2daa47cc5a1eb17f3f1c639334b43b013d048165fec68589f3a8542d45b8ddf8` | L2 | json | ①文件名含 loop2（loop2 基线证据） |
| 289 | `loop2-verify-pathprobe.py` | `D:\bounty-forge\evidence\L2\script\loop2-verify-pathprobe.py` | `_evidence/loop2-verify-pathprobe.py` | 1176 | `50e37a3edfc93b1a1aa4507145be50500a50c7df05627ad1012892696033e865` | L2 | script | ①文件名含 loop2（loop2 基线证据） |
| 290 | `loop2-verify-probe.py` | `D:\bounty-forge\evidence\L2\script\loop2-verify-probe.py` | `_evidence/loop2-verify-probe.py` | 33016 | `9d7fd9d111f4ca9bf23e1d7596b0d607b19c98b27f31f3622f147bfdc329473b` | L2 | script | ①文件名含 loop2（loop2 基线证据） |
| 291 | `loop2-verify-probe2.py` | `D:\bounty-forge\evidence\L2\script\loop2-verify-probe2.py` | `_evidence/loop2-verify-probe2.py` | 12540 | `d4c2a0b034e857d89fb9197513f31ad637d604a30640851d4acb93db30c54afb` | L2 | script | ①文件名含 loop2（loop2 基线证据） |
| 292 | `loop2-verify-probe3b.py` | `D:\bounty-forge\evidence\L2\script\loop2-verify-probe3b.py` | `_evidence/loop2-verify-probe3b.py` | 11225 | `fe247d4c8c2685c35a4a5438cfc85bd3b03f9c630e0a505edd1d1d9190c0b618` | L2 | script | ①文件名含 loop2（loop2 基线证据） |
| 293 | `loop2-verify-probe4.py` | `D:\bounty-forge\evidence\L2\script\loop2-verify-probe4.py` | `_evidence/loop2-verify-probe4.py` | 11057 | `154d1644c3b538b0efa3126736bf33d1e8d74e8e78b58a5e366a61b67449acb0` | L2 | script | ①文件名含 loop2（loop2 基线证据） |
| 294 | `loop2-verify-probe5.py` | `D:\bounty-forge\evidence\L2\script\loop2-verify-probe5.py` | `_evidence/loop2-verify-probe5.py` | 12291 | `8e1633f42db4754d603d327abab39dfba26185e4d44c59e21073f56922984039` | L2 | script | ①文件名含 loop2（loop2 基线证据） |
| 295 | `loop2-verify-probe6.py` | `D:\bounty-forge\evidence\L2\script\loop2-verify-probe6.py` | `_evidence/loop2-verify-probe6.py` | 5216 | `e9f62310ebb9937abb40eb5f62b8730fa1e6059529afdc6608fc4237309aff25` | L2 | script | ①文件名含 loop2（loop2 基线证据） |
| 296 | `loop2-verify-real8095-a1-20261012-201817.json` | `D:\bounty-forge\evidence\L2\json\loop2-verify-real8095-a1-20261012-201817.json` | `_evidence/loop2-verify-real8095-a1-20261012-201817.json` | 3300 | `8a350ede20a6afedf7abfcd685f937235f3b130ea42353011c40ba3acb0169a4` | L2 | json | ①文件名含 loop2（loop2 基线证据） |
| 297 | `loop2-verify-sandbox__hard.err.log` | `D:\bounty-forge\evidence\L2\log\loop2-verify-sandbox__hard.err.log` | `_evidence/loop2-verify-sandbox/hard.err.log` | 57757 | `c744debe59d48592cc5e54e8504684ba04893b0f5431c462e57ca34176c01daf` | L2 | log | ①目录名规则：目录名 loop2-verify-sandbox（loop2 加固验证沙箱） |
| 298 | `loop2-verify-sandbox__hard.out.log` | `D:\bounty-forge\evidence\L2\log\loop2-verify-sandbox__hard.out.log` | `_evidence/loop2-verify-sandbox/hard.out.log` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | L2 | log | ①目录名规则：目录名 loop2-verify-sandbox（loop2 加固验证沙箱） |
| 299 | `loop2-verify-sandbox__hard__app.py` | `D:\bounty-forge\evidence\L2\script\loop2-verify-sandbox__hard__app.py` | `_evidence/loop2-verify-sandbox/hard/app.py` | 59159 | `870f28b3e1486a5fcd7fe5fcfc188b2d0bc2ff1a38fcc8dd70163d3a68310ba0` | L2 | script | ①目录名规则：目录名 loop2-verify-sandbox（loop2 加固验证沙箱） |
| 300 | `loop2-verify-sandbox__hard__downloads__readme.txt` | `D:\bounty-forge\evidence\L2\txt\loop2-verify-sandbox__hard__downloads__readme.txt` | `_evidence/loop2-verify-sandbox/hard/downloads/readme.txt` | 120 | `aa03acae8a228539d048c7f48ef13164741c746c93c2fdb8ded6724bf5fd2226` | L2 | txt | ①目录名规则：目录名 loop2-verify-sandbox（loop2 加固验证沙箱） |
| 301 | `loop2-verify-sandbox__hard__lab.db` | `D:\bounty-forge\evidence\L2\db\loop2-verify-sandbox__hard__lab.db` | `_evidence/loop2-verify-sandbox/hard/lab.db` | 49152 | `8bfa6f9dea2decf805f36a143f28e9e8e5e48ef7af9fc63b6b3ceb69d9d44e6d` | L2 | db | ①目录名规则：目录名 loop2-verify-sandbox（loop2 加固验证沙箱） |
| 302 | `loop2-verify-sandbox__hard__lab_errors.log` | `D:\bounty-forge\evidence\L2\log\loop2-verify-sandbox__hard__lab_errors.log` | `_evidence/loop2-verify-sandbox/hard/lab_errors.log` | 8028 | `f8d6002ee2e2c76f9f636b92a3dd402c5499bef01cbcbc1151fde26962f43ecc` | L2 | log | ①目录名规则：目录名 loop2-verify-sandbox（loop2 加固验证沙箱） |
| 303 | `loop2-verify-sandbox__hard__private__config.bak` | `D:\bounty-forge\evidence\L2\other\loop2-verify-sandbox__hard__private__config.bak` | `_evidence/loop2-verify-sandbox/hard/private/config.bak` | 279 | `d5474e3022f7ee8597782c46eb3b4715a54844a87f577a67992257653048b543` | L2 | other | ①目录名规则：目录名 loop2-verify-sandbox（loop2 加固验证沙箱） |
| 304 | `loop2-verify-sandbox__hard__reset-audit.log` | `D:\bounty-forge\evidence\L2\log\loop2-verify-sandbox__hard__reset-audit.log` | `_evidence/loop2-verify-sandbox/hard/reset-audit.log` | 4501 | `22cef7525830803616aa1fd83956efde14efd8e3a7292ef34362093c480a9cd9` | L2 | log | ①目录名规则：目录名 loop2-verify-sandbox（loop2 加固验证沙箱） |
| 305 | `loop2-verify-sandbox__orig.err.log` | `D:\bounty-forge\evidence\L2\log\loop2-verify-sandbox__orig.err.log` | `_evidence/loop2-verify-sandbox/orig.err.log` | 36682 | `91e9c9b94b3d5daf09f74629e9b6a5a98632f10cd6bb27ceed3e85059387a957` | L2 | log | ①目录名规则：目录名 loop2-verify-sandbox（loop2 加固验证沙箱） |
| 306 | `loop2-verify-sandbox__orig.out.log` | `D:\bounty-forge\evidence\L2\log\loop2-verify-sandbox__orig.out.log` | `_evidence/loop2-verify-sandbox/orig.out.log` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | L2 | log | ①目录名规则：目录名 loop2-verify-sandbox（loop2 加固验证沙箱） |
| 307 | `loop2-verify-sandbox__orig__app.py` | `D:\bounty-forge\evidence\L2\script\loop2-verify-sandbox__orig__app.py` | `_evidence/loop2-verify-sandbox/orig/app.py` | 54362 | `d2992cd0f4832b9e67baccb04163700d567f57b4ada437e661017d015721b484` | L2 | script | ①目录名规则：目录名 loop2-verify-sandbox（loop2 加固验证沙箱） |
| 308 | `loop2-verify-sandbox__orig__downloads__readme.txt` | `D:\bounty-forge\evidence\L2\txt\loop2-verify-sandbox__orig__downloads__readme.txt` | `_evidence/loop2-verify-sandbox/orig/downloads/readme.txt` | 120 | `aa03acae8a228539d048c7f48ef13164741c746c93c2fdb8ded6724bf5fd2226` | L2 | txt | ①目录名规则：目录名 loop2-verify-sandbox（loop2 加固验证沙箱） |
| 309 | `loop2-verify-sandbox__orig__lab.db` | `D:\bounty-forge\evidence\L2\db\loop2-verify-sandbox__orig__lab.db` | `_evidence/loop2-verify-sandbox/orig/lab.db` | 49152 | `49b2032c29f8057530704203fd361bb162461eaeeeeb874c7ac1b8e8956cc7af` | L2 | db | ①目录名规则：目录名 loop2-verify-sandbox（loop2 加固验证沙箱） |
| 310 | `loop2-verify-sandbox__orig__private__config.bak` | `D:\bounty-forge\evidence\L2\other\loop2-verify-sandbox__orig__private__config.bak` | `_evidence/loop2-verify-sandbox/orig/private/config.bak` | 279 | `4496dbb3dfca48952ac1ed97c4d78b24d76d737cd400803bb32e1fc77fa07ab7` | L2 | other | ①目录名规则：目录名 loop2-verify-sandbox（loop2 加固验证沙箱） |
| 311 | `loop2-verify-supplement-20261012-200845.json` | `D:\bounty-forge\evidence\L2\json\loop2-verify-supplement-20261012-200845.json` | `_evidence/loop2-verify-supplement-20261012-200845.json` | 45379 | `f8b0248e6cc23bb2dc4bde84d69d211636cfe0620b6a93a65e41d20e53f507d7` | L2 | json | ①文件名含 loop2（loop2 基线证据） |
| 312 | `loop2-verify-supplement3-20261012-201334.json` | `D:\bounty-forge\evidence\L2\json\loop2-verify-supplement3-20261012-201334.json` | `_evidence/loop2-verify-supplement3-20261012-201334.json` | 6033 | `09d676c4f2a3c2b40ed032df3547a4bae3d58c015e79bdd49e89fade2914feac` | L2 | json | ①文件名含 loop2（loop2 基线证据） |
| 313 | `loop2-verify-supplement4-20261012-201557.json` | `D:\bounty-forge\evidence\L2\json\loop2-verify-supplement4-20261012-201557.json` | `_evidence/loop2-verify-supplement4-20261012-201557.json` | 6288 | `b105b1da8b82f802c137217f8112cf3da8de099e717f8761f3abe6c1b8695d9f` | L2 | json | ①文件名含 loop2（loop2 基线证据） |
| 314 | `loop2-verify-supplement5-20261012-201710.json` | `D:\bounty-forge\evidence\L2\json\loop2-verify-supplement5-20261012-201710.json` | `_evidence/loop2-verify-supplement5-20261012-201710.json` | 9991 | `c9d07ba1daf99ab2b1bfb292ee518057a0b75644962eba85c220fb1db2c92638` | L2 | json | ①文件名含 loop2（loop2 基线证据） |

### 2.315 证据档位 **UNSORTED** —— 22 个

| # | 文件名 | 归档绝对路径 | 源相对路径 | 大小(B) | sha256 | 档位 | 类别 | 判定理由 |
|---|---|---|---|---|---|---|---|---|
| 316 | `hunt-b-idor-20261012-1840.json` | `D:\bounty-forge\evidence\UNSORTED\json\hunt-b-idor-20261012-1840.json` | `_evidence/hunt-b-idor-20261012-1840.json` | 263281 | `1ba6e9ed0e21b47431c765df002ad533fef2229fc84111964fea4d98e2b4be50` | UNSORTED | json | ③文件名与内容均无档位标识，未判定（不做推测性归类） |
| 317 | `hunt-c-upload-xss-rce-20261012-1845.json` | `D:\bounty-forge\evidence\UNSORTED\json\hunt-c-upload-xss-rce-20261012-1845.json` | `_evidence/hunt-c-upload-xss-rce-20261012-1845.json` | 967313 | `aab93589d7e93236f8ba60ae90611a4ef297d575e0aedabcedcc87facd8ca484` | UNSORTED | json | ③文件名与内容均无档位标识，未判定（不做推测性归类） |
| 318 | `hunt-e-wrapup-20261012-1855.json` | `D:\bounty-forge\evidence\UNSORTED\json\hunt-e-wrapup-20261012-1855.json` | `_evidence/hunt-e-wrapup-20261012-1855.json` | 83503 | `c8b8b9304f255026a80d8919c0866f6d78eea7ec02e38bea200eaf707f2fc4f2` | UNSORTED | json | ③文件名与内容均无档位标识，未判定（不做推测性归类） |
| 319 | `hunt-f-extra-20261012-1900.json` | `D:\bounty-forge\evidence\UNSORTED\json\hunt-f-extra-20261012-1900.json` | `_evidence/hunt-f-extra-20261012-1900.json` | 109508 | `366c195a703d710b05f443807c86a6ea224d020993e7845e793bb789648b6647` | UNSORTED | json | ③文件名与内容均无档位标识，未判定（不做推测性归类） |
| 320 | `hunt-lib.py` | `D:\bounty-forge\evidence\UNSORTED\script\hunt-lib.py` | `_evidence/hunt-lib.py` | 6015 | `f9abd87a16a0a715f22523b63a217c8f583b07e7df1af5752a6508bc8d7fd7dd` | UNSORTED | script | ③文件名与内容均无档位标识，未判定（不做推测性归类） |
| 321 | `hunt-nuclei-20261012-1858.jsonl` | `D:\bounty-forge\evidence\UNSORTED\jsonl\hunt-nuclei-20261012-1858.jsonl` | `_evidence/hunt-nuclei-20261012-1858.jsonl` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | UNSORTED | jsonl | ③内容为空/不可读（空文件），未判定 |
| 322 | `labdb-before-reset-dirty.db` | `D:\bounty-forge\evidence\UNSORTED\db\labdb-before-reset-dirty.db` | `_evidence/labdb-before-reset-dirty.db` | 40960 | `75fbce2c8cfa1b0b822dff53a6f022baf8b6c62623643570ee5db244f00ae8cc` | UNSORTED | db | ③文件名与内容均无档位标识，未判定（不做推测性归类） |
| 323 | `loop3-b0-recon8.sh` | `D:\bounty-forge\evidence\UNSORTED\script\loop3-b0-recon8.sh` | `_evidence/loop3-b0-recon8.sh` | 387 | `16cd8a5093f6eea7a491b06bd57855a1ff631f25d4effb59db51e8c725677576` | UNSORTED | script | ③文件名与内容均无档位标识，未判定（不做推测性归类） |
| 324 | `loop3-kali-baseline-20261012-212122.sha256.txt` | `D:\bounty-forge\evidence\UNSORTED\txt\loop3-kali-baseline-20261012-212122.sha256.txt` | `_evidence/loop3-kali-baseline-20261012-212122.sha256.txt` | 183 | `219c0a73e3a4a0b879e66bac615a9e5b4227e04a3622958921f81e56795395ad` | UNSORTED | txt | ③文件名与内容均无档位标识，未判定（不做推测性归类） |
| 325 | `mentor-recheck2-20261012.json` | `D:\bounty-forge\evidence\UNSORTED\json\mentor-recheck2-20261012.json` | `_evidence/mentor-recheck2-20261012.json` | 1426 | `58d2bc46be47fad9de1675f60fa5f09b4869617d716753f0e0eaffaff7037d42` | UNSORTED | json | ③文件名与内容均无档位标识，未判定（不做推测性归类） |
| 326 | `recon-02-httpx.txt` | `D:\bounty-forge\evidence\UNSORTED\txt\recon-02-httpx.txt` | `_evidence/recon-02-httpx.txt` | 274 | `2f5ef80f8c00cb348bdf3047c7388845a31a244abda8436e553dc57b9a34164c` | UNSORTED | txt | ③文件名与内容均无档位标识，未判定（不做推测性归类） |
| 327 | `recon-04-fingerprint.txt` | `D:\bounty-forge\evidence\UNSORTED\txt\recon-04-fingerprint.txt` | `_evidence/recon-04-fingerprint.txt` | 34 | `f1da5ee427b076635a2a47b8dcccfc625168994d3eaa2932b4f0a649ea6a97f4` | UNSORTED | txt | ③文件名与内容均无档位标识，未判定（不做推测性归类） |
| 328 | `recon-05-authz.json` | `D:\bounty-forge\evidence\UNSORTED\json\recon-05-authz.json` | `_evidence/recon-05-authz.json` | 20025 | `8b7dc6f92784a422ee89320117c9a42e3a6722745702bd820e83fc822cd03a33` | UNSORTED | json | ③文件名与内容均无档位标识，未判定（不做推测性归类） |
| 329 | `recon-06-ffuf-8091.txt` | `D:\bounty-forge\evidence\UNSORTED\txt\recon-06-ffuf-8091.txt` | `_evidence/recon-06-ffuf-8091.txt` | 42 | `8e1eb9e912ab78fa3caca69cd1de52316ec9ea9bcd03359a6e5a8d57ac7d6083` | UNSORTED | txt | ③文件名与内容均无档位标识，未判定（不做推测性归类） |
| 330 | `recon-06-ffuf-8095.txt` | `D:\bounty-forge\evidence\UNSORTED\txt\recon-06-ffuf-8095.txt` | `_evidence/recon-06-ffuf-8095.txt` | 200 | `1a6d59065f672af8e165309cf4682088090a766e1f401b771ff499d5bdf8e13e` | UNSORTED | txt | ③文件名与内容均无档位标识，未判定（不做推测性归类） |
| 331 | `recon-07-methods.json` | `D:\bounty-forge\evidence\UNSORTED\json\recon-07-methods.json` | `_evidence/recon-07-methods.json` | 10849 | `42c7ea7220473b65fa526cf4721aae6d3158a06564b2b71f58f454815fe44f7e` | UNSORTED | json | ③文件名与内容均无档位标识，未判定（不做推测性归类） |
| 332 | `recon-11-login-trace-20261012-181614.json` | `D:\bounty-forge\evidence\UNSORTED\json\recon-11-login-trace-20261012-181614.json` | `_evidence/recon-11-login-trace-20261012-181614.json` | 4739 | `fa41ca494063f60e98cee0a855ba1d849661c3c14fee637b91234d4bc6d6ce77` | UNSORTED | json | ③文件名与内容均无档位标识，未判定（不做推测性归类） |
| 333 | `recon-httpx-20261012-181429.txt` | `D:\bounty-forge\evidence\UNSORTED\txt\recon-httpx-20261012-181429.txt` | `_evidence/recon-httpx-20261012-181429.txt` | 41 | `4e69346f6ae22bb6d4df2e1f0daf01c763b592e41c26d39fff508e4d85e2cbee` | UNSORTED | txt | ③文件名与内容均无档位标识，未判定（不做推测性归类） |
| 334 | `verify-step2-logic.py` | `D:\bounty-forge\evidence\UNSORTED\script\verify-step2-logic.py` | `_evidence/verify-step2-logic.py` | 15008 | `7057c1ce7bd0ced05dc362d46435e780657c7f3550edd62e8a095e11b5d54d87` | UNSORTED | script | ③文件名与内容均无档位标识，未判定（不做推测性归类） |
| 335 | `verify-step6-csrf-hmac.py` | `D:\bounty-forge\evidence\UNSORTED\script\verify-step6-csrf-hmac.py` | `_evidence/verify-step6-csrf-hmac.py` | 4422 | `551fba6863cc22558fa069e39e630002ed1794a9db64b7f17c8aca5610145ba1` | UNSORTED | script | ③文件名与内容均无档位标识，未判定（不做推测性归类） |
| 336 | `verify_lib_import.py` | `D:\bounty-forge\evidence\UNSORTED\script\verify_lib_import.py` | `_evidence/verify_lib_import.py` | 142 | `d8e52dce717475b86751e03657d3eac3410c6c8d941f2380fc10a54f6532fbfc` | UNSORTED | script | ③文件名与内容均无档位标识，未判定（不做推测性归类） |
| 337 | `wordlist.txt` | `D:\bounty-forge\evidence\UNSORTED\txt\wordlist.txt` | `_evidence/wordlist.txt` | 2002 | `2f33943fc90ed34a14d93224a2cd5cb66362c1397c3d1fe9d1cb3805038b89db` | UNSORTED | txt | ③文件名与内容均无档位标识，未判定（不做推测性归类） |

> **UNSORTED 说明**：以上文件已**完整归档、未丢任何字节**，只是文件自身不含任何档位标识（典型为空 log、sqlite 会话残留、`wordlist.txt` 等），无法据实归档。按纪律**不做推测性归类**，如实留在未判定档，后续拿到上下文再人工归位。

---

## 3. 校验产物

- `D:\bounty-forge\evidence\_sha256-manifest.txt` —— **330 行**，格式 `sha256␠␠相对路径`（sha256sum 兼容），自身 sha256 `137db6801fae091f966930b8cacd25f8664fcce0e25df7a52aa4c455604a1849`
- `D:\bounty-forge\_archive-report.json` —— 本次归档的机读汇总（复制数 / MISMATCH / 各档计数）
- INDEX.md 自身 sha256 见本次任务回报（自指，无法写进自身）

### 3.1 本目录内的非归档文件（明确划清责任边界）

`reports\archive\` 与 `reports\submit\` 下的文件**不属于本次归档范围**，是 loop4 并行任务（报告模板、提交清单等）同期产出。本索引不收录、不校验它们，以免与产出方的自校验口径打架。校验时请用 `reports\a-档|b-档|c-档|t5-target-site-lab|meta-总账\` 这五个目录，不要对 `reports\` 整目录做文件数断言。

---

## 4. 目录结构

```
D:\bounty-forge\
├─ INDEX.md                        ← 本文件
├─ _archive-report.json            ← 机读汇总
├─ reports\
│  ├─ a-档\                        ← 4 篇
│  ├─ b-档\                        ← 9 篇
│  ├─ c-档\                        ← 6 篇
│  ├─ t5-target-site-lab\                        ← 16 篇
│  ├─ meta-总账\                        ← 4 篇
│  ├─ archive\                     ← loop4 并行任务产出区（非本次归档范围）
│  └─ submit\                      ← loop4 并行任务产出区（非本次归档范围）
├─ evidence\
│  ├─ _sha256-manifest.txt         ← 330 行校验清单
│  ├─ A\<类别>\              ← 10 个
│  ├─ B\<类别>\              ← 87 个
│  ├─ C\<类别>\              ← 85 个
│  ├─ T5\<类别>\              ← 90 个
│  ├─ META\<类别>\              ← 8 个
│  ├─ L2\<类别>\              ← 28 个
│  ├─ UNSORTED\<类别>\              ← 22 个
│  └─ ...
├─ cve-lib\ fingerprints\ nuclei-rules\ poc\   ← loop4 其余任务填充，本任务未动
```

---

## 4. ⚠️ 证据状态声明 —— `deleteMe` 矛盾已定案（2026-10-13 08:5x，队长实读定案）

> 本节由**队长**在 forge-archivist 限流中断后补写（archivist 原计划做同一件事，未及落盘）。
> **文件本身零改动**，sha256 与归档时完全一致；本节只在**索引层标注证据状态**。

### 4.1 矛盾内容

loop3 C1 档对**同一组测试**留下两份结论**完全相反**的证据：

| 文件 | ts | deleteMe 取值 | 状态 |
|---|---|---|---|
| `evidence\C\json\loop3-t7-c1-discriminate-20261012.json` | 2026-10-12T23:21:39 | 合法流 / 垃圾 / 魔数截断 **全 `false`** | ⚠️ **已证伪** |
| `evidence\C\json\loop3-t7-c1-matrix-20261012.json` | 2026-10-12T23:31:33 | 五类 **全 `true`** | ✅ **有效** |

### 4.2 定案：`discriminate` 是**采集器污染导致的假阴性**，不是真实行为差异

三个**互相独立**的判据同时指向同一结论：

1. **长度不守恒** —— P1 合法序列化流 = IV(16B) + CBC 填充后密文(16B) = 32B → base64 **必须 = 44 chars**。
   `matrix` 记 `cookie_len=44` ✅ 吻合；`discriminate` 记 `88 / 153 / 88` = **44 + 44 字符 JSON 尾巴** → 污染。
2. **mod4 检验** —— 合法 base64 长度**必被 4 整除**。44 ✅、88 ✅，**但 `153 % 4 = 1` → 根本不是合法 base64**。
   （此判据不依赖任何外部假设，独立印证尾巴污染。）
3. **日志铁证** —— `evidence\C\txt\t7-shiro-full-dockerlogs.txt` 行 303：
   ```
   A cookie header was received [rc": 0, "stdout_len": 3884, "stderr_len": 0}] that contained an invalid cookie
   ```
   JSON 尾巴被拼进 Cookie 头 → **Tomcat 直接判整个 Cookie 非法** → Shiro 压根没进 RememberMeManager
   → 自然**没有** `deleteMe`。

### 4.3 根因：两脚本取 cookie 的方式不同

| 脚本 | 行号 | 取 cookie 的方式 | 结果 |
|---|---|---|---|
| `evidence\C\script\t7-c1-discriminate.py` | **L26** | `kali(...).splitlines()[0].strip()` → **取整行** | ❌ 带 JSON 尾巴 |
| `evidence\C\script\t7-c1-matrix.py` | **L57** | `clean_b64()` 正则 `[A-Za-z0-9+/]{40,}={0,2}` 取最长片段 | ✅ 纯 base64 |

两脚本的 `deleteMe` 取法**一字不差**（`"rememberMe=deleteMe" in r.headers.get("Set-Cookie","")`），
**唯一差别就是 cookie 怎么取**。→ 这是**教训 5**（`kali-run.py` JSON 尾巴污染）的**第二次发作**，
且**伪装成了「结论矛盾」而不是「工具报错」**，所以没被当场认出来。

### 4.4 结论

- **采信 `matrix`**：`deleteMe` 对合法流 / 垃圾 / 长垃圾 / 错误密钥**全 true** → **零区分度**。
- **loop3 报告 §3 N-C03 采信 matrix 是正确的**，「deleteMe 无区分度」结论**成立**。
- ⚠️ **引用 `discriminate` 那份的任何结论都是错的**，它只能作为「采集器污染」的案例被引用。

### 4.5 三层防线（为什么这个坑没酿成事故）

```
forge-archivist 归档时实读发现 → forge-detector 独立顶回矛盾 → 队长查源脚本 + 验算 + 翻日志定案
```

**任何一层单独都到不了终点。** 若不是 detector 顶回，这份坏证据会永远躺在本目录，
日后谁翻到「全 false」都会得出「`deleteMe` 其实有区分度」——**反过来推翻一个正确结论**。

### 4.6 派生的通用纪律

① **同一现象出现互相矛盾的证据时，先查「采集工具本身」有没有坏，再谈哪个结论对**——不要投票选一个。
② **`cookie_len` / `stdout_len` 这类长度字段是污染的免费探针** —— 非整数倍关系立刻露馅。
③ **采集器落盘前必须自检长度守恒**：`len(b64) == 4*ceil((len(plain)+pad)/3)` 且 `len(b64) % 4 == 0`，
   不满足直接 **abort，不要产出可疑数据**。
④ 展开记录见 `D:\bounty-forge\playbook\挖洞避坑手册.md` §13A 与 §14 第 13 项。

### 4.7 另一处证据状态：源文件编码损坏（未修复，按原样归档）

`reports\c-档\loop3-c-c1-oracle-verdict-20261012.md`
sha256 `17AC0E21C2ACE1A6954619B1109D7D1C4566AA1AD6FAD0AEF7678E2739BFCC6A` / 17132 B

- **问题**：UTF-8 BOM 头 + 内容被 GBK 二次编码，实测 **130 处 Unicode 私用区字符（U+E000–U+F8FF）**。
- **处置**：**按原样归档，字节一致，sha256 可验**（不修改证据本身）。
- ⚠️ **状态：编号与结论标「未提取」。在以正确编码重新生成之前，不得拿这份内容做结论引用。**
- 佐证：`loop3-t7-c1-log-inventory-20261012.json`（`d9999386…`）是**可用的替代证据源**，
  里面的 `:429`/`:431`/`ClassCastException` 三级锚点统计不依赖这份损坏文件。

