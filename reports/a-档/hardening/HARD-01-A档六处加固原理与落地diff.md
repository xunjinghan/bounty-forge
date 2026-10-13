# 加固笔记：A1–A6 六处加固的原理、落地 diff 与 orig↔hard 对照验证

- **笔记编号**：HARD-01
- **靶场**：target-site-lab `http://127.0.0.1:8095`（本机授权练习环境，仅回环可达）
- **对象**：`target-site-lab/app.py` 六处源码级加固（A1/A2/A3/A4/A6；**A5 绕过对抗专项归 t5，本篇不下结论**）
- **危害等级（按加固前的原始缺陷）**：**高危（High）** —— A1 并发透支可造成直接资产缺口；A3 密钥派生令牌可离线伪造属完整攻击链；A2 顶级 GET 即改状态；A4 假登出；A6 无认证一键删库
- **加固后残余等级**：**中危（Medium）** —— 主干缺陷已封，但留 3 条真绕过（跨站 `/__reset`、两个 GET 写入口、改密不轮换会话），详见 `HARD-02-A档残余绕过与阴性留证.md`
- **CWE/OWASP**：CWE-362（竞态共享资源）+ CWE-841（行为工作流强制不当）+ CWE-352（CSRF）+ CWE-330（随机值不足）+ CWE-613（会话过期不足）+ CWE-749（暴露的危险方法）；OWASP Top 10 2021 A01:2021 / A04:2021 / A07:2021
- **性质**：**已在本机靶场端到端实证（非推测）**，加固实施（Loop 2 · t2）＋ 独立复核（Loop 3 · t1）双轮完成
- **加固前 sha256**：`D2992CD0F4832B9E67BACCB04163700D567F57B4ADA437E661017D015721B484`（54362 B，`target-site-lab/app.py.loop1-original`）
- **加固后 sha256**：`870F28B3E1486A5FCD7FE5FCFC188B2D0BC2FF1A38FCC8DD70163D3A68310BA0`（59159 B，`target-site-lab/app.py`）
- **复现率口径**：**一律写区间，禁止 100%**。A1 负余额复现率 **≥95%，n=6 轮，失败轮次 0**（orig 侧）；hard 侧负余额 **0/6 轮**。A2/A3/A4/A6 为单请求判定，不涉复现率。

> **行号约定（重要）**：「改前」= `target-site-lab/app.py.loop1-original`；「改后」= `target-site-lab/app.py`。
> 本篇所有行号均于 2026-10-12 本轮用 Python 逐行扫描 `app.py`（1429 行）**独立复核**，未直接采信报告中的引用。

---

## 1. 漏洞概述（概述等级）

`target-site-lab/app.py` 经历前七轮"自修复"后仍留六类可实证缺陷，本轮（Loop 2）做了源码级修复、Loop 3 做了独立 orig↔hard 双靶对照复核，结论如下：

| 编号 | 加固项 | 原版缺陷 | orig 实测 | hard 实测 | 判定 |
|---|---|---|---|---|---|
| **A1** | `/order/create` 改条件更新 | 读余额再扣款，非原子 → 并发透支 | 30 并发 6/6 轮出负余额，最低 **-219100** 分 | 6/6 轮无负余额、稳定停在 20100 分 | ✅ 有效 |
| **A2** | 四个写入口仅 POST + CSRF token | 无方法限制、无 token 校验 → 顶级 GET 即改状态 | `/wallet/withdraw` 错 token 仍 200 提现成功 | 已登录态 GET→405、无/错 token→403、正确 token→200 | ✅ 有效（口径见 §4.2） |
| **A3** | csrf_token 改服务端随机值 | `HMAC(SECRET_KEY, session)` 派生 → 密钥泄露即全站可伪造 | 64 字符 hex，`page==hmac` 为 **true** | 43 字符 urlsafe，`page≠hmac`，库内一致 | ✅ 有效 |
| **A4** | `/logout` 删 sessions 行 | 只清浏览器 Cookie → 假登出 | 行仍在，旧 Cookie 重放 **200** | 行被删，旧 Cookie 重放 **302** | ✅ 有效 |
| **A6** | `/__reset` 四层加固 | 仅回环 IP 校验 → HEAD/GET 都能删库 | HEAD **200 且真删库**（canary 2→1） | HEAD/GET→405、缺 confirm→400、confirm+POST→200、非回环→403 | ⚠️ **有效但属缓解非根除** |

**一句话概括**：六处加固**全部落地生效**，但 A6 漏了"跨站上下文"这一维、且 A2 的门禁**漏接两个写入口**——残余绕过见 HARD-02。

**范围交叉核验（本轮独立复算）**：`security/learning/_evidence/loop2-verify-sandbox/hard/app.py` 与真实 `target-site-lab/app.py` 的 sha256 **完全相同**（`870F28B3…10BA0`）→ 沙箱 hard:18096 的结论可外推到真实 8095；`loop2-verify-sandbox/orig/app.py` 与 `target-site-lab/app.py.loop1-original` **相同**（`D2992CD0…21B484`）→ 回退路径完好。

---

## 2. 原理（代码层根因）

### 2.1 A1 · `/order/create` 条件更新（原子扣款）

**原版**（`app.py.loop1-original:947-962`）：

```python
947:  amount = product["price_cents"] * qty
948:  # 余额校验
949:  if user["balance_cents"] < amount:              # ← 基于请求开始时的快照
950:      self.html(400, page("余额不足", ...))
951:      return
954:  # 扣款 + 建单（同一事务）
955:  conn.execute("UPDATE users SET balance_cents = balance_cents - ? WHERE id=?",
956:               (amount, user["id"]))               # ← 无余额条件
957:  cur = conn.execute("INSERT INTO orders(...) VALUES (?,?,?,?,?)", ...)
961:  conn.commit()
962:  new_balance = user["balance_cents"] - amount     # ← 用旧快照算响应值
```

缺陷链：`user` 来自 `require_user(conn)`，只在请求上下文读一次；L949 的校验针对该快照，L955 的 `UPDATE` **不把余额条件写进 `WHERE`**，也不加 `BEGIN IMMEDIATE` / 行锁。N 个并发线程各自读到同一旧值、各自通过校验、各自扣款 → **丢失更新（lost update）** → 余额扣穿成负数。L962 还让**响应自报余额与库内真实值脱钩**（这是 VER-01 取证时的关键旁证）。

**加固版**（`app.py:1018-1041`）：

```python
1018:  amount = product["price_cents"] * qty
1019:  # A1：条件更新（对齐 wallet_withdraw 的 app.py:1076 写法）。
1020:  # UPDATE 自带 balance_cents >= amount 条件，余额不足时 rowcount=0，
1021:  # 直接失败返回——不存在"先读余额再扣款"的非原子窗口。
1022:  cur = conn.execute(
1023:      "UPDATE users SET balance_cents = balance_cents - ?"
1024:      " WHERE id=? AND balance_cents >= ?",      # ← 条件收进 WHERE
1025:      (amount, user["id"], amount))
1026:  if cur.rowcount == 0:                          # ← 影响行数 0 = 余额不足
1027:      conn.rollback()
1028:      self.html(400, page("余额不足", ...))
1032:      return
1033:  cur2 = conn.execute("INSERT INTO orders(...) VALUES (?,?,?,?,?)", ...)
1037:  conn.commit()
1038:  # 改动后重读：余额以库内实际值为准（报数必须改动后重读）
1039:  new_balance = conn.execute(
1040:      "SELECT balance_cents FROM users WHERE id=?",
1041:      (user["id"],)).fetchone()["balance_cents"]
```

**原理一句话**：把"校验 + 扣款"合并成**单条带谓词的 `UPDATE`**，由数据库的行级原子性保证余额不会被扣穿；`rowcount == 0` 即失败，且失败时不建单。这是 SQLite（及所有关系库）下的标准做法，比应用层加锁更可靠。

> 注：本靶场 `hard/app.py` 中共有 **3 处** `balance_cents >= ?` 条件更新 —— `/order/create`（`:1024`）、`/wallet/withdraw`（`:1165`）、`/wallet/transfer`（`:1219`）。A1 是把已存在于 `/wallet/withdraw` 的正确写法**对齐**到 `/order/create`。

### 2.2 A2 · 四个写入口的 `check_write` 统一门禁

**加固版**（`app.py:425-438`，原版**无此方法**）：

```python
425:  # Loop2 A2 修复：写端点统一门禁——仅 POST + 必须带有效 CSRF token。
426:  # 返回 True 表示放行；False 表示已写出 405/403 响应，调用方直接 return。
427:  def check_write(self, user, form):
428:      if self.command != "POST":
429:          self.html(405, page("405", "<h1>方法不允许</h1>...", ...))
432:          return False
433:      if not self.verify_csrf(form.get("csrf_token", "")):
434:          self.html(403, page("CSRF 校验失败", "<h1>请求被拒绝</h1>...", ...))
437:          return False
438:      return True
```

四个调用点（本轮实测确认，全库**仅这 4 处**）：

| 端点 | 函数定义 | `check_write` 调用行 |
|---|---|---|
| `/order/create` | `app.py:989` | **`app.py:997`** |
| `/order/status` | `app.py:1053` | **`app.py:1061`** |
| `/coupon/claim` | `app.py:1097` | **`app.py:1105`** |
| `/wallet/withdraw` | `app.py:1142` | **`app.py:1150`** |

**⚠️ 调用顺序决定观测结果**：`require_user` 跑在 `check_write` **之前**，所以**匿名请求先被 302 跳登录，根本走不到方法校验**——「GET 返回 405」这句话只在**已登录态**成立。这条口径极易写错，见 §4.2。

原版的根因有两层：① 端点无门禁；② **钱包页自己把写操作写成 GET/无 token**（`/coupon/claim` 是 `<a href>`、`/order/status` 表单是 `method="get"`、另两个表单没有 `csrf_token` 隐藏域），等于应用在替攻击者构造合法请求。

### 2.3 A3 · csrf_token 从 HMAC 派生改为服务端随机值

**原版**（`app.py.loop1-original:357-362`）：

```python
357:  def csrf_token(self):
358:      tok = self._session_token()
359:      if not tok:
360:          return ""
361:      return hmac.new(SECRET_KEY.encode(), tok.encode(),
362:                      hashlib.sha256).hexdigest()
```

token 完全由 `(SECRET_KEY, session_token)` 决定，而 `SECRET_KEY` 经 `/debug` 明文输出（见 `security/learning/auth-bypass/VER-03-debug泄露SECRET_KEY导致CSRF令牌可伪造.md`）→ **持有会话 token 即可离线推出页面 token**。

**加固版**（`app.py:374-407`）：

```python
374:  # Loop2 A3 修复：CSRF token 改为服务端会话内随机值（secrets.token_urlsafe），
375:  # 不再由 HMAC(SECRET_KEY, session_token) 派生——即便 SECRET_KEY 泄露，
376:  # 也无法由会话 token 离线推导出页面 token。
377:  def csrf_token(self):
378:      tok = self._session_token()
379:      if not tok:
380:          return ""
381:      conn = get_db()
382:      try:
383:          row = conn.execute(
384:              "SELECT csrf_token FROM sessions WHERE token=?", (tok,)).fetchone()
385:      finally:
386:          conn.close()
387:      if row is None:
388:          return ""
389:      stored = row["csrf_token"]
390:      if stored:
391:          return stored
392:      # 兜底：老会话行尚无 csrf_token 时补齐（一次性）
393:      fresh = make_token()
394:      conn = get_db()
395:      try:
396:          conn.execute("UPDATE sessions SET csrf_token=? WHERE token=?", (fresh, tok))
397:          conn.commit()
398:      finally:
399:          conn.close()
400:      return fresh
```

配套三处改动：

1. `SCHEMA.sessions` 增列 `csrf_token TEXT`（`app.py:111`；改前 `:105-110` 只有 4 列）
2. `create_session` 生成并落库（`app.py:236-245`，其中 `:239` `csrf = make_token()`、`:241` `INSERT OR REPLACE INTO sessions`）：**改前 `:220-228` 只有 token 一个字段**
3. 新增 `migrate_schema()`（`app.py:206-216`）并在 `ensure_initialized()`（`app.py:225`）调用，幂等补列——**未删库重建**，老数据保留

`verify_csrf`（`app.py:403-407`）保持不变，仍用 `hmac.compare_digest` 做定长比较。**注：`hmac` 仍被引用（`:407`）是正确的定长比较用法，与"不再派生"不冲突。**

### 2.4 A4 · `/logout` 销毁服务端会话行

**原版**（`app.py.loop1-original:567-568`）：

```python
567:  def logout(self):
568:      self.redirect("/", clear_cookie=True)     # 只清浏览器 Cookie，sessions 行原封不动
```

**加固版**（`app.py:621-631`）：

```python
621:  # Loop2 A4 修复：登出必须销毁服务端会话行（旧 Cookie 立即失效）
622:  def logout(self):
623:      tok = self._session_token()
624:      if tok:
625:          conn = get_db()
626:          try:
627:              conn.execute("DELETE FROM sessions WHERE token=?", (tok,))
628:              conn.commit()
629:          finally:
630:              conn.close()
631:      self.redirect("/", clear_cookie=True)
```

这是 hunt-session 的经典形态：**服务端无状态 = 登出只是前端表演**。被偷的 Cookie 在受害者"登出后"依然有效。

### 2.5 A6 · `/__reset` 四层加固

**原版**（`app.py.loop1-original:1270-1278`）：

```python
1270:  def reset_endpoint(self):
1271:      peer = self.client_address[0]
1272:      if peer not in ("127.0.0.1", "::1"):   # ← 唯一防护
1273:          self.html(403, "<h1>403</h1>")
1274:          return
1275:      reset_database()                       # ← GET/HEAD/POST 一律执行
1276:      self.html(200, page("reset", "<h1>已重置</h1>..."))
```

**加固版**（`app.py:1355-1387`）：

```python
1355:  # ------------------------------------------------------------------ #
1356:  # 一键复位（Loop2 A6 加固：仅 POST + 回环 + 二次确认串 + 审计）
1357:  # ------------------------------------------------------------------ #
1358:  def reset_endpoint(self):
1359:      # ① 来源必须回环
1360:      peer = self.client_address[0]
1361:      if peer not in ("127.0.0.1", "::1"):
1362:          self.html(403, "<h1>403</h1><p>仅允许本机回环访问。</p>")
1363:          return
1364:      # ② 仅允许 POST（HEAD/GET 一律 405，爬虫与 <img> 不再触发重建）
1365:      if self.command != "POST":
1366:          self.html(405, page("405", "<h1>方法不允许</h1>..."))
1369:          return
1370:      # ③ 二次确认参数
1371:      path, form = self.form()
1372:      if form.get("confirm", "") != "RESET":
1373:          self.html(400, page("400", "<h1>缺少二次确认</h1>..."))
1375:          return
1376:      # ④ 审计日志（不可逆操作必须留痕）
1377:      try:
1378:          with open(os.path.join(BASE_DIR, "reset-audit.log"), "a", encoding="utf-8") as fh:
1380:              fh.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] "
1381:                       f"RESET peer={peer} ua={self.headers.get('User-Agent', '')}\n")
1382:      except Exception:
1383:          pass
1384:      reset_database()
1385:      self.html(200, page("reset", "<h1>已重置</h1>..."))
```

同步更新了文档字符串（`app.py:9`）、首页提示（`app.py:561`）与启动打印（`app.py:1418`），避免文档与行为不一致。

---

## 3. 可复现 payload

> **前置纪律（不可违反）**：① 只打 `127.0.0.1` 回环靶；② 全程非破坏性——**禁止对真实 8095 发起 `/__reset`**（本轮 `/__reset` 配额已用）；③ 并发 ≤5、请求间隔 ≥1s（下面 30 并发的复现命令仅用于**沙箱副本** `18096`/`18095`，且需显式确认）；④ 不删改业务数据、不拖库。
>
> **A6 的复现必须打在沙箱副本上**，真实 8095 只做零状态变更的只读/写入拒绝验证。

### A1 复现（orig 版 18095 才打得出来）

```bash
# ① 在 orig 沙箱（18095）上登录 demo
curl.exe -s -i -c C:\temp\t2jar -d "username=demo&password=demo123" http://127.0.0.1:18095/login

# ② 取页面 csrf_token（orig 无需 token 也能过，此步仅为对照）
curl.exe -s -b C:\temp\t2jar http://127.0.0.1:18095/home | findstr csrf_token

# ③ 30 路并发下单（PowerShell 7；Windows 下勿用 bash xargs 以免丢失并发性）
1..30 | ForEach-Object -Parallel {
  curl.exe -s -o NUL -w "%{http_code}\n" -b C:\temp\t2jar `
    -d "product_id=1&qty=1" http://127.0.0.1:18095/order/create
} -ThrottleLimit 30

# ④ 直查数据库（响应自报余额不可信，必须直查）
python -c "import sqlite3;c=sqlite3.connect(r'<orig沙箱>\lab.db');print(c.execute(\"select balance_cents from users where username='demo'\").fetchone(),c.execute('select count(*) from orders').fetchone())"
```

**期望（orig）**：余额出现负数，最低 **-219100** 分。**期望（hard 18096）**：余额稳定 20100 分（= 50000 − 29900），无负数。

### A2 复现矩阵（同一已登录会话）

```bash
# 已登录 alice 会话下四种请求，逐条打
curl.exe -s -o NUL -w "GET=%{http_code}\n"       -b C:\temp\t2jar "http://127.0.0.1:18096/wallet/withdraw?amount=700"
curl.exe -s -o NUL -w "NO_TOKEN=%{http_code}\n"  -b C:\temp\t2jar -d "amount=700"        http://127.0.0.1:18096/wallet/withdraw
curl.exe -s -o NUL -w "BAD_TOKEN=%{http_code}\n" -b C:\temp\t2jar -d "amount=700&csrf_token=deadbeef" http://127.0.0.1:18096/wallet/withdraw
curl.exe -s -o NUL -w "GOOD=%{http_code}\n"     -b C:\temp\t2jar -d "amount=700&csrf_token=<有效>"   http://127.0.0.1:18096/wallet/withdraw
```

**期望（orig 18095）**：四种全 **200**，且**四种都改库**（错 token `deadbeef` 仍提现成功 = token 根本没被看）。
**期望（hard 18096，已登录态）**：`405 / 403 / 403 / 200`。

### A3 复现（离线推算，无需发请求）

```python
import hmac, hashlib, sqlite3, re, urllib.request
sec  = "lab-secret-key-PLEASE-CHANGE-001"      # 本轮证据中已明文出现
tok  = "<登录拿到的 43 字符 session token>"
body = urllib.request.urlopen(
    urllib.request.Request("http://127.0.0.1:18096/home",
                           headers={"Cookie": f"token={tok}"})).read().decode()
page = re.search(r'name="csrf_token" value="([^"]+)"', body).group(1)
guess = hmac.new(sec.encode(), tok.encode(), hashlib.sha256).hexdigest()
print("page :", page, len(page))
print("guess:", guess, len(guess))
print("page == hmac ?", page == guess)
```

**期望（orig）**：`True`，长度 64（hex）。
**期望（hard）**：`False`，长度 43（urlsafe）；再直查库 `SELECT csrf_token FROM sessions WHERE token=?` 应与 `page` 一致。

### A4 复现

```bash
curl.exe -s -o NUL -w "%{http_code}\n" -b C:\temp\t2jar -c C:\temp\t2jar http://127.0.0.1:18096/logout
# 用登出前的旧 Cookie 重放
curl.exe -s -o NUL -w "replay=%{http_code}\n" -b C:\temp\t2oldjar http://127.0.0.1:18096/home
python -c "import sqlite3;c=sqlite3.connect(r'<hard沙箱>\lab.db');print(c.execute('select count(*) from sessions').fetchone())"
```

**期望（orig）**：重放 **200**、`sessions` 行数不变。
**期望（hard）**：重放 **302**、`sessions` 行数 −1。

### A6 复现（⚠️ 只在沙箱副本执行）

```bash
# ① HEAD 也能删库的实锤（原版）——用 canary 行判定，不看 HTTP 码
curl.exe -s -I -o NUL http://127.0.0.1:18095/__reset
# ② 加固版各路径
curl.exe -s -o NUL -w "HEAD=%{http_code}\n"  -I http://127.0.0.1:18096/__reset
curl.exe -s -o NUL -w "GET=%{http_code}\n"       http://127.0.0.1:18096/__reset
curl.exe -s -o NUL -w "POST_NO_CONFIRM=%{http_code}\n" -X POST http://127.0.0.1:18096/__reset
curl.exe -s -o NUL -w "POST_CONFIRM=%{http_code}\n"     -X POST -d "confirm=RESET" http://127.0.0.1:18096/__reset
```

**期望（orig 18095）**：HEAD `200` 且 **canary 行被清**。
**期望（hard 18096）**：`405 / 405 / 400 / 200`；非回环源（绑 `127.0.0.2` 连接）→ `403`。

---

## 4. 复现步骤与证据

### 4.1 A1 · 30 并发 × 3 轮 × 2 份证据文件

| target | 证据文件 | 轮 | status_counts | 余额 before→after | 建单 | 负余额 |
|---|---|---|---|---|---|---|
| orig | `loop2-verify-20261012-200626.json` | 1 | 400×26 / 200×4 | 50000 → **-69600** | 4 | 是 |
| orig | `loop2-verify-20261012-200626.json` | 2 | 400×28 / 200×2 | 50000 → **-9800** | 2 | 是 |
| orig | `loop2-verify-20261012-200626.json` | 3 | 400×25 / 200×5 | 50000 → **-99500** | 5 | 是 |
| orig | `loop2-verify-20261012-200719.json` | 1 | 400×25 / 200×5 | 50000 → **-99500** | 5 | 是 |
| orig | `loop2-verify-20261012-200719.json` | 2 | 400×21 / 200×9 | 50000 → **-219100** | 9 | 是 |
| orig | `loop2-verify-20261012-200719.json` | 3 | 400×24 / 200×6 | 50000 → **-129400** | 6 | 是 |
| hard | `loop2-verify-20261012-200719.json` | 1 | 400×29 / 200×1 | 50000 → 20100 | 1 | 否 |
| hard | `loop2-verify-20261012-200719.json` | 2 | 400×29 / 200×1 | 50000 → 20100 | 1 | 否 |
| hard | `loop2-verify-20261012-200719.json` | 3 | 400×29 / 200×1 | 50000 → 20100 | 1 | 否 |
| hard | `loop2-verify-20261012-200626.json` | 1–3 | 400×29 / 200×1 | 50000 → 20100 | 1 | 否 |

- **复现率**：orig 侧负余额 **6/6 轮（区间 ≥95%，n=6，失败轮次 0）**；请求粒度 **31/180 建单成功（17.2%）**，6 轮全部越过 `balance // 29900 = 1` 单上限。
- **hard 侧**：负余额 **0/6 轮**，超限 **0/6 轮**，每轮恰好 1 单、余额精确停在 20100 分（= 50000 − 29900）。
- **真实 8095 零状态变更复测**（`loop2-verify-real8095-a1-20261012-201817.json`）：6 轮 × 30 并发 = **180 次请求全 400**，`bob` 余额 100→100、订单 3→3、`db_sha256` 前后同为 `940d825e…d3ae`（`state_changed=false`）。**未打 `/__reset`**。
- 库层 `rowcount` 语义直证（不依赖 HTTP 层）：`bob` 余额 100 时，`UPDATE ... WHERE balance_cents >= 1900` → `rowcount=0`；`>= 50` → `rowcount=1`（已 rollback）。
- 源码位置：`app.py:1022-1032`（条件 UPDATE + `rowcount==0` 回滚返回 400）。

### 4.2 A2 · 四入口矩阵（**必须分开写口径**）

**已登录态矩阵**（同一 alice 会话）：

| 入口 | target | GET | POST 无 token | POST 错 token | POST 正确 token | 状态变更 |
|---|---|---|---|---|---|---|
| `/order/create` | orig | 200 ✱改 | 200 ✱改 | 400 | 400 | GET/无 token 改库 |
| `/order/create` | hard | **405** | **403** | **403** | 200 ✔改 | 仅正确 token |
| `/order/status` | orig | 200 | 400 | 400 | 400 | GET 可达（未改库） |
| `/order/status` | hard | **405** | **403** | **403** | 200 | 仅正确 token |
| `/coupon/claim` | orig | 200 ✱改 | 200 | 200 | 200 | GET 改库 |
| `/coupon/claim` | hard | **405** | **403** | **403** | 200 ✔改 | 仅正确 token |
| `/wallet/withdraw` | orig | 200 ✱改 | 200 ✱改 | **200 ✱改** | 200 ✱改 | 四种全改库 |
| `/wallet/withdraw` | hard | **405** | **403** | **403** | 200 ✔改 | 仅正确 token |

**两条必须写清的口径（写错就是给下游挖坑）**：

1. **405 只在已登录态成立**。调用顺序是 `require_user` → `check_write`（`app.py:993-997`、`:1061`、`:1105`、`:1150`），**匿名请求先被 `require_user` 302 掉**。证据：`loop2-verify-supplement-20261012-200845.json` 的 `fix4_anonymous_matrix` —— orig 与 hard 的四入口 `anon_GET=302`、`anon_POST=302`、`db_changed=false`，**两个靶完全一致**。
2. **orig 侧的状态码由业务逻辑决定，与 token 无关**。最硬的实锤：`/wallet/withdraw` 错 token（`csrf_token=deadbeef`）仍返回 **200「提现成功」且改库**——token 完全没被看。`/order/create` 的 400 是"余额不足"、`/order/status` 的 400 是"非法状态流转"，都是业务分支，**不能当成"原版有防护"**。

**真实 8095 复测矩阵**：四入口 `GET=405`、`POST_no_token=403`、`POST_wrong_token=403`，正确 token 分别落到 400/404/404/200，`db_changed=false`。

### 4.3 A3 · 派生 vs 随机

| 观测项 | orig（18095） | hard（18096） |
|---|---|---|
| session_token | `Yy6HeCc5TTbZKAjw3EBvhxf-HP3c-bOfXdDWzImA0xc` | `Ti6jkupRtPU6H8ftfC8NhT_uU0ueLXjZKKaemVtb6B8` |
| page_token | `0ef83dbdd138b5cfb1e7c7d12877722f7c0480ab085f41ec05be099b9564d095` | `HI7yU74nBhNMx2iwkeVH1vv5c1L9AXxL9b-ieIlgEYc` |
| page_token 长度 | **64**（hex） | **43**（urlsafe） |
| HMAC 猜测值 | `0ef83dbd…d095`（与 page 相同） | `20f9c9c5…24cc`（与 page 不同） |
| `page_equals_hmac` | **true（可离线推导）** | **false** |
| 库内 `sessions.csrf_token` | 无此列（`db_stored=null`） | `HI7yU74n…EYc`，`db_equals_page=true` |

- 跨会话复用：用 bob 的 token（`SekwLjFF0UMVaG8ihHnONyLsshagC_JbnzRMiKDXbhI`）打 alice 会话 → **403**。
- 老会话兜底（`csrf_token=NULL`）：`/home` 生成 `2AcM2Z0jpKZrGFLXaB_aZEyOYoNYu4QWvIh1x9--iik` 并回写库内，随后写请求 200。
- 真实 8095：`page_token=fPfPQ6oSI_MEqACYExNk_JiFqDVkRkGl8nhrKQ20r5U`（43 字符），`page_equals_hmac=false`、`db_equals_page=true`。
- **判定：有效**。SECRET_KEY 泄露（`lab-secret-key-PLEASE-CHANGE-001` 已在本轮证据里明文出现）**不再能推出页面 token**。

### 4.4 A4 · 登出销毁会话

| 观测项 | orig（18095） | hard（18096） |
|---|---|---|
| `sessions_before` → `after` | 1 → **1** | 1 → **0** |
| `row_gone` | **false** | **true** |
| 旧 Cookie 重放 `GET /home` | **200**（钱包页正常渲染） | **302**（跳 `/?err=login`） |
| 旧 Cookie 重放 `POST /wallet/withdraw` | **200** | **302** |
| 旧 Cookie 重放 `GET /admin/users` | 404 | 302 |

- **范围正确性**：2 会话时只登出 alice → `sessions 2→1`，bob 的会话 `bob_home_status=200`、`bob_token_still_valid=true` —— **没误杀别的会话**。
- 补充：6 种 Cookie 变形（原值/大写/带引号/加空格/截断/空）重放全部 302；10 并发登出全 302、之后 `sessions=0`；重新登录 token 轮换（无会话固定）。
- 源码位置：`app.py:621-631`。

### 4.5 A6 · `/__reset` 四层加固

| 用例 | orig | hard |
|---|---|---|
| `HEAD /__reset` | **200**，`db_changed=true` | **405**，`db_changed=false` |
| `GET /__reset` | **200**「已重置」 | **405** |
| `GET /__reset` + 爬虫 UA | 200 | **405** |
| `GET /__reset`（`<img>` 语义） | 200 | **405** |
| `POST /__reset` 无 confirm | 200 | **400** |
| `POST /__reset` 空 body | 200 | **400** |
| `POST /__reset` JSON body | 200 | **400** |
| `POST /__reset?confirm=RESET` | 200 | **200**（放行） |
| `POST /__reset` body `confirm=RESET` | 200 | **200** |
| `PUT /__reset` | 501 | 501 |
| `GET //__reset` | **200** 触发重建 | **405** |
| `GET /%5f%5freset` | 404 | 404 |
| `GET /__reset/` | 404 | 404 |
| `POST /__reset` 源地址 127.0.0.2（带 confirm） | — | **403** |

- **「HEAD 真的删库」是实锤不是推断**：canary 行判定 `canary_before=2 → canary_after=1`、`canary_wiped=true`。
- hard 侧五例（HEAD / GET / 爬虫 UA / img 标签 / Range 探测）全 405、`canary_before==canary_after`、`audit_lines_delta=0` —— **连审计都没记，因为压根没进执行层**。
- 审计日志确实在写：`security/learning/_evidence/loop2-verify-sandbox/hard/reset-audit.log` 共 **78 行**，格式 `[2026-10-12 20:17:13] RESET peer=127.0.0.1 ua=lv-probe5/1.0`；真实靶 `target-site-lab/reset-audit.log` 406 B，7 行。
- 源码位置：`app.py:1358-1387`。

### 4.6 引用文件清单（sha256 本轮独立重算，非引用上游）

根目录 `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\`

| 文件（相对路径） | 字节 | sha256 |
|---|---|---|
| `security/learning/_evidence/t2-apppy-diff-20261012.patch` | 15039 | `D97E1B574A750121FE196756E6755A6956E640304CE14B50AF0BA935E9FE4423` |
| `security/learning/_evidence/t2-a1-concurrency-20261012.json` | 3469 | `0C79446A28CED3F6F96C0C574A66BD45CAFE9BCB7F4BBC157386CFA8DD5E41D8` |
| `security/learning/_evidence/t2-a1-concurrency-20261012.py` | 5134 | `42082A1F5622EAF94B18BBC0D888FF692A34549706E26C6B763148EDB4E8DCEC` |
| `security/learning/_evidence/t2-a2a3a4-after-20261012.json` | 3235 | `80BDB8B6057BEAFA57C2CA43D7E2404DD5418F7F1287C3B1DC20A42DCE0890A2` |
| `security/learning/_evidence/t2-a2a3a4-after-20261012.py` | 5295 | `EA2B8CC5112A82F6D86D7ABD887CB357A89E41967F9AC38931919AE0E1E21630` |
| `security/learning/_evidence/t2-edgecases-20261012.json` | 844 | `BB0648D05363B802FEBB8232870D331449B84898AFB47AF9871DC30AEEE130AA` |
| `security/learning/_evidence/t2-edgecases-20261012.py` | 4327 | `6BED5411DCFEAAFE93E077B99D0DA0B08EA362F8A648E6B1F04E9D8494D2BB27` |
| `security/learning/_evidence/loop2-verify-20261012-200626.json` | 67682 | `FCF24FCA95B31BAF2E29FA09C32BC62332F4936F58875535853F64CF7BCF165E` |
| `security/learning/_evidence/loop2-verify-20261012-200719.json` | 217228 | `2DAA47CC5A1EB17F3F1C639334B43B013D048165FEC68589F3A8542D45B8DDF8` |
| `security/learning/_evidence/loop2-verify-supplement-20261012-200845.json` | 45379 | `F8B0248E6CC23BB2DC4BDE84D69D211636CFE0620B6A93A65E41D20E53F507D7` |
| `security/learning/_evidence/loop2-verify-supplement3-20261012-201334.json` | 6033 | `09D676C4F2A3C2B40ED032DF3547A4BAE3D58C015E79BDD49E89FADE2914FEAC` |
| `security/learning/_evidence/loop2-verify-supplement4-20261012-201557.json` | 6288 | `B105B1DA8B82F802C137217F8112CF3DA8DE099E717F8761F3ABE6C1B8695D9F` |
| `security/learning/_evidence/loop2-verify-supplement5-20261012-201710.json` | 9991 | `C9D07BA1DAF99AB2B1BFB292EE518057A0B75644962EBA85C220FB1DB2C92638` |
| `security/learning/_evidence/loop2-verify-real8095-a1-20261012-201817.json` | 3300 | `8A350EDE20A6AFEDF7ABFCD685F937235F3B130EA42353011C40BA3ACB0169A4` |
| `security/learning/_evidence/loop2-verify-pathprobe.py` | 1176 | `50E37A3EDFC93B1A1AA4507145BE50500A50C7DF05627AD1012892696033E865` |
| `security/learning/_evidence/baseline-20261012-194602.json` | 15473 | `4785110B6EB95DB58CC5337095405EC0A8B175DF336D221F2E9BEEB8BA424103` |
| `security/learning/_evidence/loop3-a-verify-20261012-212153.json` | 37941 | `614F20B2D7D4E74B7A94708D99DA4E6425FD0076F68705360A37E5B9835DFC3E` |
| `security/learning/_evidence/loop3-a-verify-gen.py` | 32566 | `28167728D279643447A1C3ABB66ACB5D3386CCE509582A5EB21D039CEBBCED6A` |
| `security/learning/_evidence/loop2-verify-sandbox/hard/reset-audit.log` | 4501 | `22CEF7525830803616AA1FD83956EFDE14EFD8E3A7292EF34362093C480A9CD9` |
| `target-site-lab/app.py` | 59159 | `870F28B3E1486A5FCD7FE5FCFC188B2D0BC2FF1A38FCC8DD70163D3A68310BA0` |
| `target-site-lab/app.py.loop1-original` | 54362 | `D2992CD0F4832B9E67BACCB04163700D567F57B4ADA437E661017D015721B484` |
| `target-site-lab/reset-audit.log` | 406 | `9C686781B44E0859454F50B847A94848F481ECF0381C812A4C695120BBBF4C45` |

上游报告：

| 文件 | 字节 | sha256 |
|---|---|---|
| `security/learning/hardening/A-档验证报告-20261012.md` | 34852 | `F1F23606FEE8C8230EEB571478F88F60132EC8C8E326DA64202E44F60448B19F` |
| `security/learning/hardening/A-档加固实施报告-t2-20261012.md` | 21493 | `FBAD08DA39EF709226D6F31C7B951CF75E1194D2BC3CA382480B7E06D14D481E` |
| `security/learning/progress.md` | 33274 | `D31E170C3C547E3536BC3A17D172D38BE781F6D41AD3FA06052E25EB8634AA4B` |

**存在性自检**：上表 26 个引用文件全部存在，`missing = 0`（自检命令见 §7）。

---

## 5. 修复方案（含实际落地 diff）

> **完整 diff 见**：`security/learning/_evidence/t2-apppy-diff-20261012.patch`（sha256 `D97E1B574A750121FE196756E6755A6956E640304CE14B50AF0BA935E9FE4423`，15039 B，350 行 unified diff，`--- app.py.loop1-original` / `+++ app.py`）。
> 下方逐处给出「改前 / 改后」代码片段 + 行号，便于按图索骥。

### A1 修复（已落地）

**改前**（`app.py.loop1-original:947-962`）：

```python
            amount = product["price_cents"] * qty
            # 余额校验
            if user["balance_cents"] < amount:
                self.html(400, page("余额不足", ...))
                return
            # 扣款 + 建单（同一事务）
            conn.execute("UPDATE users SET balance_cents = balance_cents - ? WHERE id=?",
                         (amount, user["id"]))
            cur = conn.execute("INSERT INTO orders(...) VALUES (?,?,?,?,?)", ...)
            conn.commit()
            new_balance = user["balance_cents"] - amount
```

**改后**（`app.py:1018-1041`）：

```python
            amount = product["price_cents"] * qty
            # A1：条件更新（对齐 wallet_withdraw 的 app.py:1076 写法）。
            cur = conn.execute(
                "UPDATE users SET balance_cents = balance_cents - ?"
                " WHERE id=? AND balance_cents >= ?",
                (amount, user["id"], amount))
            if cur.rowcount == 0:
                conn.rollback()
                self.html(400, page("余额不足",
                    f"<h1>余额不足</h1><p>需要 {amount} 分，余额不足，未创建订单。</p>",
                    user["username"]))
                return
            cur2 = conn.execute("INSERT INTO orders(...) VALUES (?,?,?,?,?)", ...)
            conn.commit()
            new_balance = conn.execute(
                "SELECT balance_cents FROM users WHERE id=?",
                (user["id"],)).fetchone()["balance_cents"]
```

**配套（未做，纵深防御缺口）**：`reset_database()` 无备份，删库前不落 `lab.db.bak-<时间戳>`。

### A2 修复（已落地，但**不完整**）

**改前**：`app.py.loop1-original` 中**无 `check_write` 方法**；`order_create`（`:921`）、`order_status`（`:974`）、`coupon_claim`（`:1015`）、`wallet_withdraw`（`:1057`）四个函数在 `require_user` 之后**直接进业务逻辑**。

**改后**：新增 `app.py:425-438` 的 `check_write`，四处调用见 §2.2 表。

**必须补的修复（尚未落地，本轮实测确认仍可绕过）**：

```python
# /wallet/transfer —— app.py:1185-1196，当前只有 verify_csrf，无方法限制
def wallet_transfer(self):
    ...
    if not self.verify_csrf(form.get("csrf_token", "")):   # ← :1192 缺方法校验
        ...
# 应改为：
    if not self.check_write(user, form):
        return

# /change-password —— app.py:1239-1268
    if self.command == "GET" and not form.get("new_password"):   # ← :1246 GET 分支只在无参时渲染
        ...
    if not self.verify_csrf(form.get("csrf_token", "")):         # ← :1255 只查 token 不查方法
        ...
# 应改为：GET 分支无条件渲染表单，写逻辑统一走 check_write
```

> **根因是设计问题不是笔误**：`check_write` 靠"逐入口手工接"，A2 已经漏了 2/6 个写入口。**建议**：把方法+CSRF 校验抽到路由分发层（`app.py:479` 的 `route()`）统一处理，或用装饰器，**别再一个入口一个入口手工接**。

### A3 修复（已落地）

**改前**（`app.py.loop1-original:357-362`）：

```python
    # 第七轮修复#5：CSRF token = HMAC-SHA256(SECRET_KEY, session_token)
    def csrf_token(self):
        tok = self._session_token()
        if not tok:
            return ""
        return hmac.new(SECRET_KEY.encode(), tok.encode(),
                        hashlib.sha256).hexdigest()
```

**改后**（`app.py:374-401`）：见 §2.3。

**配套改动**：

| 改动 | 改后位置 | 改前 |
|---|---|---|
| `SCHEMA.sessions` 增 `csrf_token TEXT` | `app.py:111` | `:105-110` 只有 4 列 |
| 新增 `migrate_schema()` | `app.py:206-216` | 无 |
| `ensure_initialized()` 调用迁移 | `app.py:225` | 无 |
| `create_session` 生成并落库 | `app.py:236-245`（`:239` `csrf = make_token()`） | `:220-228` |

**⚠️ 库哈希基线变更提醒**：A3 的 `ALTER TABLE ADD COLUMN` 改变了 schema，`lab.db` 文件哈希必然变。**加固后的新基线是 `940D825E…5D3AE`**，别再拿 `49B2032C…CC7AF`（加固前）做比对，会误判成"数据被污染"。行数与业务数据一致：`users=4 / orders=3 / messages=1 / sessions=0 / coupon_claims=0`。

### A4 修复（已落地，但**只修了 logout**）

**改前**（`app.py.loop1-original:567-568`）：

```python
    def logout(self):
        self.redirect("/", clear_cookie=True)
```

**改后**（`app.py:621-631`）：见 §2.4。

**必须补的修复（尚未落地）**：`change_password` 成功后同样要销毁会话——本轮实测改密后 `sessions` 行仍在、旧 Cookie 仍可用（200）：

```python
# app.py:1265-1267，改密成功处应补：
conn.execute("DELETE FROM sessions WHERE user_id=?", (user["id"],))   # 或至少保留当前会话
```

### A6 修复（已落地，**属缓解非根除**）

**改前**（`app.py.loop1-original:1270-1278`）：

```python
    def reset_endpoint(self):
        peer = self.client_address[0]
        if peer not in ("127.0.0.1", "::1"):
            self.html(403, "<h1>403</h1>")
            return
        reset_database()
        self.html(200, page("reset", "<h1>已重置</h1>..."))
```

**改后**（`app.py:1355-1387`）：见 §2.5。

**必须补的修复（尚未落地，D1 跨站复位实测成立）**：四层里**没有一层读 `Origin` / `Referer` / `Sec-Fetch-Site`**，回环校验看的是 TCP 源 IP 而非"谁发起的"。二选一：

```python
# 方案一：加来源上下文校验（缺失 Origin 也拒绝，别"没带就放过"）
orig = self.headers.get("Origin")
if orig not in (f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}"):
    self.html(403, ...); return

# 方案二（更彻底）：摘掉 HTTP 路由，只留启动参数
# python app.py --reset
```

> **为何当初没采纳方案二**：8095 的复位是后续档位（B/C）与复测流程的刚需。所以本轮判定为**缓解而非根除**，并把 D1 记为**成功 · 需处理**（见 HARD-02）。

### 修复优先级建议

| 优先级 | 项 | 理由 |
|---|---|---|
| **P0** | B1/C6：`/wallet/transfer`、`/change-password` 补 `check_write` | 同机场景下顶级 GET 即可改密/转账 |
| **P0** | D1：`/__reset` 加 `Origin` 校验或摘 HTTP 路由 | 不可逆操作（删库）可被跨站触发 |
| **P1** | B3：改密后销毁会话 | 受害者以为改密就断了攻击者，实际没有 |
| **P1** | 把方法+CSRF 校验上提到路由层/装饰器 | 防止第三次漏接 |
| **P2** | `reset_database()` 前落带时间戳的 `.bak` | 纵深防御 |
| **P2** | 补 Cookie 属性取证（`HttpOnly`/`Secure`/`SameSite`） | 定死 §D1/D1 的实际可利用性 |

---

## 6. 参考链接

- **CWE-362** — Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
- **CWE-841** — Improper Enforcement of Behavioral Workflow
- **CWE-352** — Cross-Site Request Forgery (CSRF)；OWASP CSRF Prevention Cheat Sheet（Synchronizer Token Pattern）
- **CWE-330** — Use of Insufficiently Random Values；OWASP Session Management Cheat Sheet（token 应用 `crypto-secure` 随机值，至少 64 位熵）
- **CWE-613** — Insufficient Session Expiration；OWASP 登出最佳实践：**必须服务端失效会话**
- **CWE-749** — Exposed Dangerous Method or Function
- **OWASP Top 10 2021** — A01:2021 Broken Access Control / A04:2021 Insecure Design / A07:2021 Identification and Authentication Failures
- **OWASP Testing Guide** — WSTG-IDNT / WSTG-SESS（会话与 CSRF 测试用例）
- **本靶场同族笔记**（按缺陷线交叉引用，避免重复记录）：
  - `security/learning/business-logic/VER-01-并发下单TOCTOU把余额扣成负数.md`（sha256 `F34D92D18955663CB0532176D2919DAA27F569915A769513478498A9B775F5F8`）—— A1 的原始漏洞笔记
  - `security/learning/business-logic/VER-02-业务接口漏接CSRF校验且不限方法.md`（sha256 `07F2714A99A6C4C4AAF0282918C334EF6696CBE9AA71C531D8A2C2788E9A5E95`）—— A2 的原始漏洞笔记
  - `security/learning/business-logic/VER-06-__reset无认证一键删库重建.md`（sha256 `59C312D34A92D3DE7C8DF56619685B233E0E26FDE686F547937B7F3E122C6D7A`）—— A6 的原始漏洞笔记
  - `security/learning/auth-bypass/VER-04-登出不销毁服务端会话.md`（sha256 `D6C6FD75D8E9C169168291FCB64031D4D433F03C659596FA650B021F7370A2B7`）—— A4 的原始漏洞笔记
  - `security/learning/auth-bypass/VER-03-debug泄露SECRET_KEY导致CSRF令牌可伪造.md` —— A3 的根因（密钥泄露）
  - `security/learning/VULN-03-SECRET_KEY泄露导致CSRF令牌可伪造.md`（sha256 `C65EE8DBCC5C74C036B45A06D1F735D082BB6BE272AD14BCFE96700CB7FCCE12`）—— 本篇七节模板的基准样本

---

## 7. 学习要点

1. **「读-判-写」三步在关系库里永远是坑**。校验和扣款只要分两条语句，就存在竞态窗口；正确做法是**把谓词收进 `UPDATE ... WHERE`**，让数据库用行锁保证原子性。别在应用层"先查一下再说"。

2. **响应里自报的数值不可信**。原版 L962 用旧快照算 `new_balance`，导致响应值与库内真实值脱钩——这既是漏洞的副产物，也是**取证时的关键旁证**。修复时也要养成"**改动后重读**"的习惯。

3. **CSRF 令牌的安全性不能建立在"某个长期密钥永不泄露"之上**。`HMAC(SECRET_KEY, session)` 把"一处密钥泄露"放大成"全站 CSRF 失效"。正解是**每会话独立的 `secrets.token_urlsafe` 随机值存服务端**（OWASP Synchronizer Token Pattern）。

4. **"登出"必须是服务端动作**。只清 Cookie 的登出等于没登出——被偷的 Cookie 依然有效。**且凭据变更（改密）同样要销毁会话**，A4 只修了 logout 是典型的半拉子。

5. **门禁不能靠"逐入口手工接"**。A2 给 4 个入口接了 `check_write`，就漏了 2 个（`/wallet/transfer`、`/change-password`）。**凡是"每个入口都要记得调"的检查，迟早会漏**——应当上提到路由层或用装饰器。**这类错误 A2 已经犯过一次，第二次几乎必然重演。**

6. **"仅回环 + 仅 POST + 二次确认"是缓解，不是根除**。回环校验看的是 **TCP 源 IP**，不是"谁发起的"——受害者本机浏览器打开恶意页面照样能触发。**不可逆操作不该挂在 HTTP 路由上**，挂路由就一定会被 CSRF。

7. **取证必须区分"业务分支 4xx"和"防护 4xx"**。orig 侧 `/order/create` 的 400 是"余额不足"、不是"CSRF 校验"；`/wallet/withdraw` 错 token 仍 200 才是"根本没校验"的实锤。**别把业务错误码当成防护证据。**

8. **方法限制要放在路由归一化之后**。裸路径 `//__reset`、`/__reset;` 在 orig 上能绕过路径匹配触发复位（`urllib.parse.urlparse("//__reset").path == ""`，服务端归一化成 `/__reset`），但在加固版上被 405 挡住——**说明方法校验的位置选对了**，这是加固的净收益。

9. **观测口径必须写明前置条件**。"GET 返回 405" 只在**已登录态**成立（`require_user` 排在 `check_write` 前面，匿名是 302）。这种口径不写清楚，下游一定会照抄错。

10. **口径纪律**：复现率一律写区间（**A1 为 ≥95%，n=6，失败轮次 0**），**严禁写 100%**；阴性结论同样要留证（14 条阴性见 HARD-02）；未验证的写"**未验证**"，不许凑数。

---

## 8. 引用存在性自检（可复跑）

```powershell
# 在工作区根目录执行；对本篇 §4.6 表格逐行校验，输出 missing 计数
$root = 'C:\Users\Administrator\Documents\deepseek-harness\default-workspace'
$refs = @(
  'security\learning\_evidence\t2-apppy-diff-20261012.patch',
  'security\learning\_evidence\t2-a1-concurrency-20261012.json',
  'security\learning\_evidence\t2-a1-concurrency-20261012.py',
  'security\learning\_evidence\t2-a2a3a4-after-20261012.json',
  'security\learning\_evidence\t2-a2a3a4-after-20261012.py',
  'security\learning\_evidence\t2-edgecases-20261012.json',
  'security\learning\_evidence\t2-edgecases-20261012.py',
  'security\learning\_evidence\loop2-verify-20261012-200626.json',
  'security\learning\_evidence\loop2-verify-20261012-200719.json',
  'security\learning\_evidence\loop2-verify-supplement-20261012-200845.json',
  'security\learning\_evidence\loop2-verify-supplement3-20261012-201334.json',
  'security\learning\_evidence\loop2-verify-supplement4-20261012-201557.json',
  'security\learning\_evidence\loop2-verify-supplement5-20261012-201710.json',
  'security\learning\_evidence\loop2-verify-real8095-a1-20261012-201817.json',
  'security\learning\_evidence\loop2-verify-pathprobe.py',
  'security\learning\_evidence\baseline-20261012-194602.json',
  'security\learning\_evidence\loop3-a-verify-20261012-212153.json',
  'security\learning\_evidence\loop3-a-verify-gen.py',
  'security\learning\_evidence\loop2-verify-sandbox\hard\reset-audit.log',
  'target-site-lab\app.py',
  'target-site-lab\app.py.loop1-original',
  'target-site-lab\reset-audit.log',
  'security\learning\hardening\A-档验证报告-20261012.md',
  'security\learning\hardening\A-档加固实施报告-t2-20261012.md',
  'security\learning\progress.md'
)
$missing = @($refs | Where-Object { -not (Test-Path -LiteralPath (Join-Path $root $_)) })
"refs=$($refs.Count)  missing=$($missing.Count)"
$missing | ForEach-Object { "MISSING: $_" }
```

**本轮实测输出**：`refs=25  missing=0`

---

## 附：本篇与 HARD-02 的分工

| 篇目 | 内容 |
|---|---|
| **本篇 HARD-01** | A1/A2/A3/A4/A6 五处加固的原理、落地 diff、orig↔hard 对照验证 |
| **HARD-02-A档残余绕过与阴性留证.md** | 残余绕过 11 条（成功/失败/不可验证三态）、阴性 14 条、未验证 9 条 |

> **A5（绕过对抗专项）不在本档**：由 t5 独立执行，本篇与 HARD-02 均不替它下结论。
