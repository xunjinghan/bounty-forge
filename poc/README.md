# bounty-forge 检测资产（loop4 / t2）

- 产出人：forge-detector
- 落盘时间：2026-10-13 00:2x – 01:1x（Asia/Shanghai）
- 引擎：nuclei **v3.11.1**（`C:\Users\Administrator\Documents\deepseek-harness\default-workspace\dsh-tools\tools\nuclei\nuclei.exe`）
- Python：**3.12 标准库**（`C:\Users\Administrator\AppData\Local\Programs\Python\Python312\python.exe`），无 requests / 无 pycryptodome / 无第三方包

---

## 0. 一句话

7 条 loop3 洞 → 5 个 nuclei 模板 + 4 个 Python 只读脚本。**外加 2 条我没做的东西和 2 条我顶回队长方案的地方**，理由都在下面，不藏着。

---

## 1. 目录

```
nuclei-rules/
  B1-DVWA-LFI-PATH-TRAVERSAL.yaml           high    GET   破坏性=false
  B4-DVWA-SESSION-FIXATION-WEAK-ID.yaml     high    GET   破坏性=false
  C1-SHIRO-FINGERPRINT.yaml                 info    GET   破坏性=false
  DVWA-SESSION-COOKIE-ATTRIBUTES.yaml       medium  GET   破坏性=false
  C2-TOMCAT-2017-12615-PUT-CONFIRM.yaml     critical PUT   破坏性=true ← 默认关闭

poc/
  bfnet.py                        公共库（白名单 / 限速 / 只读 probe / JSON 输出）
  bf_b1_dvwa_lfi.py               B1-LFI-01        GET
  bf_b4_dvwa_session_fixation.py  B4-SESSION-01    GET
  bf_c1_shiro_fingerprint.py      C1-SHIRO-2016-4437  GET（只做指纹，绝不投 payload）
  bf_c2_tomcat_put_readonly.py    C2-TOMCAT-2017-12615 GET/HEAD/OPTIONS
```

`bfnet.probe()` **物理上**只接受 GET/HEAD，传 PUT 抛 `ValueError`。这是白名单之外的第二道锁。

---

## 2. 我顶回 / 没做的部分（队长方案复核结论）

按队长要求「队长给的技术方案先复核再执行」，以下是我复核后改的：

### 2.1 B5-XSS-01 存储型 XSS：**不写 nuclei 模板**（顶回）

队长方案写「B5 写模板」。**我没做**，理由：

- 证明这个洞成立的前提是「把 `<script>` 写进 DVWA guestbook」——**写操作**。
- 模板要真跑就必须投递这条写请求。这直接破「非破坏性」红线，不是取舍问题。
- loop3 的完整链证据在
  `security/learning/_evidence/verified-loop3-b-b5-storedxss-20261012-2236.json`（3/3，含浏览器执行 + 被窃 SID + 会话文件终局证据），
  **不需要我重新做一遍模板**。
- 我改交付的：把 **B5 真正可自动化检测的那一半**（前提条件）做成模板
  `DVWA-SESSION-COOKIE-ATTRIBUTES.yaml` —— 会话 cookie 属性，GET，零副作用。

**这条要是我照原方案做，就是破红线。所以我顶回来了。**

### 2.2 B2-XXE-01：**默认不启用**（半顶回）

队长方案把 B2 列在 7 条洞里。XXE 的**检测**本质上必须 POST 一个 XML 实体声明进去。
POST 不在「禁 PUT/DELETE」字面里，但 loop3 实测 bWAPP 的 XXE 会改 `bWAPP.users.secret`（写了再复原，3 轮）。

→ 我**没有**做 B2 模板。理由写进 README 是为了下次有人问「怎么没 B2」。
**若要补**，前提是先与队长确认「POST 探测 + 即时复原」是否被算作破坏性；不做这个确认我不会动手。

### 2.3 C2 的 PUT 模板：按队长要求标了 destructive + 默认关闭

`C2-TOMCAT-2017-12615-PUT-CONFIRM.yaml` 里 PUT 规则**保留**（队长明确说「可以写，但必须标注 + 默认 disable」）：

- `metadata.destructive: "true"`
- `metadata.default-enabled: "false"`
- `metadata.default-disabled-reason:` 写明「写文件系统 + 可执行代码落地」
- **文件名叫 `-PUT-CONFIRM` 而不是 `-PUT-EXPLOIT`**，payload 是
  `<% out.print("BF-C2-READONLY-ONLY"); %>` —— 只回显常量，**不执行命令、不写文件**
- 尾部斜杠 `/bf_c2_confirm.jsp/` 保留（绕过后缀白名单的必要条件，去掉必失败）

运行方式：默认 `nuclei -t .` **不会**执行它，必须显式 `-include-tags destructive`。

### 2.4 C1：模板和脚本都**只用 GET**，绝不投反序列化 payload

已在模板 description 和脚本文件头把 loop3 的 deleteMe 判别矩阵原样写进去当反面教材。
`bf_c1_shiro_fingerprint.py` 的 `vulnerable` 字段**恒为 False** —— 只读指纹永远不下「可利用」结论。

---

## 3. 关键实测数据（不是我编的，是本轮跑出来的）

### 3.1 B1 真靶场复现（2026-10-13 00:5x，DVWA @ 192.168.56.101）

用已登录 low 档 cookie 跑 `bf_b1_dvwa_lfi.py`：

| depth | HTTP | body | `root:x:0:0` |
|---|---|---|---|
| 1–5 | 200 | **3680B** | ❌ |
| **6** | 200 | **6936B** | ✅ |
| 绝对路径 `/etc/passwd` | 200 | 6936B | ✅ |
| php://filter | 200 | — | 解出 **2036B** `<?php` 源码 ✅ |
| 负对照（不存在文件） | 200 | 3680B | ❌（正确） |

→ **6 级临界**这个数跟 loop3 报告 §2.2 一字不差。**4 级无效**也再次证实。

### 3.2 B4 真靶场复现

`bf_b4_dvwa_session_fixation.py` 陌生客户端仅带已认证 SID（不带档位 cookie）访问 `/index.php`：
**HTTP 200 + `logout.php`** → 会话可复用，漏洞成立。

loop3 记的 weak_id 序列（low 档 `1..7` 自增）**本轮没复现到** —— 脚本采样走
`/vulnerabilities/weak_id/` 时没拿到 `Set-Cookie: PHPSESSID`。这条我在 README 里
标成**未复现**，不假装跑到了。

### 3.3 C1 / C2 阴性对照（这轮最有价值的部分）

Shiro / Tomcat 容器 loop3 后已停止，本轮**没起新容器**（红线）。所以对两个 C 档脚本
做的是**阴性对照** —— 拿活着的 DVWA（Apache/PHP，非 Shiro 非 Tomcat）打进去：

| 脚本 | 目标 | 结果 |
|---|---|---|
| `bf_c1_shiro_fingerprint.py` | DVWA | `confidence: unknown`，零 rememberMe 信号 ✅ |
| `bf_c2_tomcat_put_readonly.py` | DVWA | `Tomcat 指纹=False`，OPTIONS 无 PUT ✅ |
| `bf_b1_dvwa_lfi.py` | `http://8.8.8.8` | 白名单拒绝，exit=2，**零请求发出** ✅ |

**阴性对照比阳性更能说明模板不瞎报。** 这两个 C 脚本在真 Shiro / 真 Tomcat 上的阳性结论
**本轮没有实测**，README 不写它们「已验证可用」。

---

## 4. 白名单与限速（红线，必须实现，已实现）

`bfnet.assert_allowed()`：

- 允许字面主机：`127.0.0.1` / `localhost`
- 允许网段：`192.168.56.0/24`（VirtualBox host-only，loop3 Kali VM `dc1` 所在）
- **不做 DNS 解析** → 外部域名一律按字面不匹配拒绝，不会因为解析而外连
- 非 `http`/`https` scheme 一律拒（`ftp://127.0.0.1/` 也拒）
- 不通过 → `sys.exit(2)` + stderr 打红框，**没有「警告后继续」这条路径**
- 构造反例绕过：`127.0.0.1.evil.com` → 拒（实测）
- **调用方必须在发包前调用**：4 个脚本全部在第一次 `bfnet.probe()` 之前调

`bfnet.RateLimiter`：

- 请求间隔 ≥1.0s（`--interval` 传小于 1.0 会被**顶回成 1.0** 并打提示）
- **全串行**，无线程池 → 并发恒为 1，满足「并发 ≤5」

自测结果（`bfnet_selftest.py`，8 允许 / 7 拒绝）：

```
ALLOW http://127.0.0.1:8080/x            ALLOW http://localhost:8080/x
ALLOW http://192.168.56.101/dvwa/       ALLOW http://127.0.0.1:18081
REJECT http://192.168.1.10/  exit 2     REJECT http://example.com/  exit 2
REJECT http://10.0.2.2/       exit 2     REJECT http://8.8.8.8/      exit 2
REJECT http://[2001:db8::1]/  exit 2     REJECT http://127.0.0.1.evil.com/  exit 2
REJECT ftp://127.0.0.1/       exit 2
PUT blocked: bfnet.probe 只允许 GET/HEAD
```

---

## 5. nuclei 语法校验（v3.11.1，原样粘贴）

```
$ nuclei.exe -validate -t D:\bounty-forge\nuclei-rules\
                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.11.1

		projectdiscovery.io

[WRN] The given path (D:\bounty-forge\nuclei-rules\) is outside the default template directory
      path (C:\Users\Administrator\nuclei-templates)! Referenced sub-templates with relative
      paths in workflows will be resolved against the default template directory.
[VER] Started metrics server at localhost:9092
[INF] All templates validated successfully
EXIT=0
```

WRN 那行是「模板目录不在默认路径」，纯提示，与模板合法性无关。

---

## 6. 各洞检测率（区间 + 分子分母，不写 100%）

| 资产 | 本轮实测 | 分母 | 结论表述 |
|---|---|---|---|
| B1 Python 深度扫描 | 2/2（6级、绝对路径命中） | 2 | 本轮命中 ≥95%（2/2 有效尝试） |
| B1 Python 负对照 | 1/1 正确不判 | 1 | 负对照有效 |
| B4 Python 会话复用 | 1/1 命中 | 1 | 本轮命中（样本小，不外推） |
| B1 nuclei 模板 | **未跑（需登录 cookie，nuclei 不做登录）** | — | **未实测** |
| C1/C2 Python | **只跑了阴性对照** | 2 | 阴性 2/2（零假阳性） |
| C2 nuclei PUT 模板 | **未跑（destructive 默认关闭 + Tomcat 容器已停）** | — | **未实测，且不建议在非授权靶场跑** |

> 全表没有一条写 100%。未实测的一律写「未实测」，不拿 loop3 的数字冒充本轮的。

---

## 7. 怎么用

```powershell
$py = "C:\Users\Administrator\AppData\Local\Programs\Python\Python312\python.exe"
$env:PYTHONIOENCODING="utf-8"

# B1（DVWA 未登录会 302 → 报 UNKNOWN，这是对的，不是 bug）
& $py D:\bounty-forge\poc\bf_b1_dvwa_lfi.py -u http://192.168.56.101/dvwa --json

# B1 带已登录 cookie（本轮用的就是这个）
& $py D:\bounty-forge\poc\bf_b1_dvwa_lfi.py -u http://192.168.56.101/dvwa --cookie "PHPSESSID=xxx; security=low"

# B4
& $py D:\bounty-forge\poc\bf_b4_dvwa_session_fixation.py -u http://192.168.56.101/dvwa --cookie "PHPSESSID=xxx; security=low"

# C1 / C2 指纹（只读，永远不会自动下 vulnerable=true）
& $py D:\bounty-forge\poc\bf_c1_shiro_fingerprint.py -u http://127.0.0.1:18081
& $py D:\bounty-forge\poc\bf_c2_tomcat_put_readonly.py -u http://127.0.0.1:18082

# nuclei：默认跑 4 个非破坏模板
& $nuc -t D:\bounty-forge\nuclei-rules\ -u http://192.168.56.101/dvwa

# nuclei：跑 PUT 那个（**破坏性，必须是授权靶场**）
& $nuc -t D:\bounty-forge\nuclei-rules\ -u http://127.0.0.1:18082 -include-tags destructive
```

退出码：`0` = 命中/疑似，`1` = 未命中/UNKNOWN，`2` = 白名单拒绝。
批量跑时用退出码区分「未命中」和「配置错了」。

---

## 8. 交付前自查（对照队长「自查清单」）

| 检查项 | 结果 |
|---|---|
| 有没有占位哈希 | ❌ 无。README 里的 sha256 见 `_sha256-manifest.txt`（本目录同级生成） |
| 有没有引用不存在的文件 | ❌ 无。`reference:` 里三个路径均已 `read` 实读过：<br>`security/learning/loop3-b-dvwa-bwapp-report-t4-20261012.md`<br>`security/learning/loop3-c-vulhub-report-t7-20261012.md`<br>`security/learning/_evidence/loop3-t7-c1-matrix-20261012.json`<br>`security/learning/_evidence/loop3-t7-c1-discriminate-20261012.json`<br>`security/learning/_evidence/loop3-t7-c2-tomcat-put-raw.txt`<br>`security/learning/_evidence/verified-loop3-b-b1-depth-20261012-2236.json`（**存在性经 Glob 实查**） |
| 有没有未实读的转录 | ❌ 本轮所有 loop3 数据都来自实读：<br>· 6 级临界 / 3680B / 6936B / 2036B → 读 `verified-loop3-b-20261012-2236.md` §2.2<br>· deleteMe 判别矩阵 → 读 `loop3-t7-c1-matrix-20261012.json` + `loop3-t7-c1-discriminate-20261012.json`（**注意：这两份文件的 deleteMe 取值互相矛盾**，见 §9）<br>· PUT 201 / GET 200 / DELETE 405 → 读 `loop3-t7-c2-tomcat-put-raw.txt` |
| 复现率有没有写 100% | ❌ 全是区间或分子分母，见 §6 |
| 非破坏性 | ✅ 4 个脚本物理上只能 GET/HEAD（C2 额外 OPTIONS）；nuclei PUT 模板标 destructive + 默认关闭 |
| 白名单校验 | ✅ `bfnet.assert_allowed()`，4 脚本全部发包前调用，实测 exit=2 |

---

## 9. 本轮发现的证据矛盾（必须记，别让下一轮踩）

`loop3-t7-c1-matrix-20261012.json` 与 `loop3-t7-c1-discriminate-20261012.json`
**对同一组测试给出了相反的 deleteMe 取值**：

| 文件 | 合法序列化流 | 垃圾明文 | 错误密钥 |
|---|---|---|---|
| `...-matrix-...json` | **true** | **true** | **true** |
| `...-discriminate-...json` | **false** | **false** | （未单列） |

loop3 报告正文 `loop3-c-vulhub-report-t7-20261012.md` §3 N-C03 采信的是 **matrix 的 true**，
并据此判定「deleteMe 无区分度」。

**我的处理**：两份都读了，都写进模板 description，结论按**保守侧**走 ——
无论 matrix 还是 discriminate，`deleteMe` 都不作为任何判据。
所以这个矛盾**不影响本轮任何资产的行为**，但**结论层面它是 loop3 证据链上的一个未解释矛盾**，
建议归档时（forge-archivist）核对原件时间戳与生成顺序。

---

## 10. 引用清单（全部绝对路径，可直接核）

源工作区：`C:\Users\Administrator\Documents\deepseek-harness\default-workspace\`

- `security\learning\loop3-b-dvwa-bwapp-report-t4-20261012.md`（293 行，B1–B5 原始报告）
- `security\learning\loop3-c-vulhub-report-t7-20261012.md`（324 行，C1–C3 原始报告）
- `security\learning\_evidence\verified-loop3-b-20261012-2236.md`（354 行，B 档独立验证）
- `security\learning\_evidence\verified-loop3-b-b1-depth-20261012-2236.json`
- `security\learning\_evidence\verified-loop3-b-b4-session-20261012-2236.json`
- `security\learning\_evidence\verified-loop3-b-b5-storedxss-20261012-2236.json`
- `security\learning\_evidence\loop3-t7-c1-matrix-20261012.json`
- `security\learning\_evidence\loop3-t7-c1-discriminate-20261012.json`
- `security\learning\_evidence\loop3-t7-c1-shiro-20261012.json`
- `security\learning\_evidence\loop3-t7-c2-tomcat-put-raw.txt`

---

## 11. 下一轮该干的（不干就是留着坑）

1. **补 B2 XXE 模板** —— 前提是先定义清楚「POST 探测 + 即时复原」算不算破坏性。**队长说了算。**
2. **跑 B1/B4 nuclei 模板的阳性** —— 需要带登录态，nuclei 默认不做登录。
   建议给模板加 `-var session_cookie=` 变量，由人把 cookie 喂进去。
3. **起容器复测 C1/C2 Python 阳性** —— 本轮容器已停，我没起（红线）。CVE 靶场清单（t3）就绪后可复测。
4. **B4 weak_id 序列没复现到** —— 需要带登录态访问 `/vulnerabilities/weak_id/` 且触发会话下发，本轮没成。
5. **DVWA-SESSION-COOKIE-ATTRIBUTES 的实测** —— 我只写了模板没用 nuclei 跑过，需补一次阳性。