# 漏洞笔记：/board 匿名可写、无频控、内容长度无上限

- **编号**：VER-07（来源 HUNT-07，t5 判定 confirmed）
- **靶场**：target-site-lab `http://127.0.0.1:8095`（本机授权练习环境）
- **危害等级**：中危（Medium，噪声型；若出现在公开站点则是典型的刷量/存储耗尽入口）
- **CWE/OWASP**：CWE-862（Missing Authorization）＋ CWE-770（Allocation of Resources Without Limits or Throttling）；OWASP Top 10 2021 **A01:2021 Broken Access Control / A04:2021 Insecure Design**
- **CVSS-like**：5.3（AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L）
- **复现率**：稳定复现；副作用实测：sqlmap 布尔盲注测试 **2 秒写入 555 行**、累计 **1454 行**
- **代码位置**：`target-site-lab/app.py:736-766`（`board`，写入分支 740-752）

---

## 1. 漏洞概述

`POST /board` 的写入分支**不要求登录**：无 Cookie 的匿名请求直接落库，`author` 缺省为 `anonymous`。同一通道既无限速也无限长，实测 2 秒写 555 行、短时间累计 1454 行匿名留言。

注意边界：**输出侧转义到位**（`app.py:755-756` 对 `author`/`content` 调 `html.escape`），所以这是**写入滥用/存储耗尽**问题，不构成存储型 XSS。转义与限流是两件事，不要混为一谈。

---

## 2. 原理（代码层根因）

```python
# target-site-lab/app.py:736-752（节选）
def board(self):
    conn = get_db()
    try:
        user = self.current_user(conn)           # L739 取当前用户
        if self.command == "POST":
            ...
            content = form.get("content", "")
            author = user["username"] if user else "anonymous"   # L747 匿名也照写
            conn.execute("INSERT INTO messages(author,content) VALUES(?,?)",
                         (author, content))                        # L748 无任何校验
            conn.commit()
            self.redirect("/board")
            return
```

缺陷链条：

1. **认证缺失**：`board()` 调的是 `current_user()`（可为 `None`）而不是 `require_user()`，匿名被显式允许（`author=anonymous`）。
2. **无频控**：没有 IP/会话级限速、没有验证码、没有 pending 审核，写入速度等于网络速度。
3. **无长度上限**：`content` 没有长度校验。虽然入口处有 `Content-Length`（`app.py:741`）读取，但没有与上限比较（对比 `/upload` 在 `app.py:831-833` 就有 `MAX_UPLOAD_BYTES` 检查）。
4. **附带影响**：写入量直接膨胀 `lab.db` 体积与 `/board` 页面渲染成本，检索/备份都会被拖累；这反过来也是"注入测试工具误伤"的放大器（sqlmap 一次布尔盲注就写上千行）。

---

## 3. 可复现 payload

前置条件：靶场 8095 在跑；**无需登录态**。

```bash
# ① 匿名写入一条（无 Cookie）
curl.exe -s -i -d "content=T5-anon-verifier-probe" http://127.0.0.1:8095/board
#    → 302 → /board

# ② 确认已落库（匿名也能看到自己的留言）
curl.exe -s http://127.0.0.1:8095/board | Select-String "T5-anon-verifier-probe"

# ③ 写入量放大（仅演示无频控，1 万行级别；授权靶场外禁止执行）
1..500 | ForEach-Object -Parallel {
  curl.exe -s -o NUL -d "content=flood-$_" http://127.0.0.1:8095/board
} -ThrottleLimit 50

# ④ 直查行数
python -c "import sqlite3;print(sqlite3.connect(r'C:\Users\Administrator\Documents\deepseek-harness\default-workspace\target-site-lab\lab.db').execute('select count(*) from messages').fetchone())"
```

原始请求：

```http
POST /board HTTP/1.1
Host: 127.0.0.1:8095
Content-Type: application/x-www-form-urlencoded

content=T5-anon-verifier-probe
```

XSS 阴性对照（说明"能写"不等于"能弹窗"）：

```bash
curl.exe -s -d "content=<img src=x onerror=alert(1)>" http://127.0.0.1:8095/board
curl.exe -s http://127.0.0.1:8095/board | Select-String "&lt;img"
```

---

## 4. 复现步骤与证据

| 观测项 | 改前 | 改后（实测） |
|---|---|---|
| `messages` 行数 | 1 | **2**（新行 `author=anonymous, content=T5-anon-verifier-probe`） |
| 匿名批量写入速率 | — | sqlmap 布尔盲注 **约 2 秒 555 行** |
| 累计匿名写入 | — | **1454 行** |
| XSS 载荷落库后展示 | — | `&lt;img src=x onerror=alert(1)&gt;` 转义显示，**未构成 XSS** |

原始证据文件：

- `security/learning/_evidence/verify-03-injection-ssrf-upload-20261012-1855.json`（sha256 `d168699eede0933b74257f3080e4677db22e511859d25c0fa376b3de7a086fd2`）——匿名写入与转义复核
- `security/learning/_evidence/verify-02-logic-session-20261012-1855.json`（sha256 `1b7b154509e9a95157fbd67b78a22289798a0d0383af802c48f8007a5a74cd5c`）
- `security/learning/_evidence/sqlmap-t5-verify-board.log`（sha256 `7c5fb44c896f312c2cee8e6c79fac34ccbbf90dba6a030c974e43481ae180b7f`）与 `security/learning/_evidence/sqlmap-t5-verify-board2.log`（sha256 `431bee020a8216750d04227b618bd17b82ab94f32885ca0188548a95934e9f73`）——写入放大的实测来源
- `security/learning/_evidence/verified-20261012-184800.json`（VER-07 条目：harm_proof / source_logic）
- 源码比对：`target-site-lab/app.py:736-766`

回滚：`GET /__reset`；收集时点（2026-10-12T18:48+08:00）`messages` 回到 1 行。

---

## 5. 修复方案

### 代码级（P0，落到 `app.py:740-752`）

```python
def board(self):
    conn = get_db()
    try:
        user = self.current_user(conn)
        if self.command == "POST":
            if user is None:                                  # 新增：要求登录（或至少要求验证码）
                self.redirect("/?err=login")
                return
            length = int(self.headers.get("Content-Length") or 0)
            if length > 4096:                                 # 新增：请求体上限
                self.html(413, page("413", "<h1>内容过大</h1>"))
                return
            ...
            content = (form.get("content", "") or "").strip()[:2000]   # 截断 + 去空白
            if not content:                                   # 拒绝空内容
                self.html(400, page("400", "<h1>内容不能为空</h1>"))
                return
            if not rate_limit_ok(self.client_address[0]):     # 新增：频控（见下）
                self.html(429, page("429", "<h1>请求过于频繁</h1>"))
                return
            conn.execute("INSERT INTO messages(author,content) VALUES(?,?)",
                         (user["username"], content))
            conn.commit()
```

配套频控（模块级，用锁保护，参考项目已有 `LOGIN_FAILURES`/`LOGIN_LOCK` 写法）：

```python
BOARD_LAST = {}          # ip -> [时间戳,...]
BOARD_LOCK = threading.Lock()
BOARD_LIMIT = 5          # 每 60 秒最多 5 条

def rate_limit_ok(ip):
    now = time.time()
    with BOARD_LOCK:
        hist = [t for t in BOARD_LAST.get(ip, []) if now - t < 60]
        if len(hist) >= BOARD_LIMIT:
            BOARD_LAST[ip] = hist
            return False
        hist.append(now)
        BOARD_LAST[ip] = hist
        return True
```

### 纵深防御

- **内容治理**：留言入库前过敏感词/链接白名单，或先落"待审核"表由管理员放行（教育靶场可仅保留长度与频控）。
- **容量兜底**：`messages` 表设单用户/单 IP 行数上限，或按时间窗口滚动清理；DB 文件增长设磁盘配额告警。
- **匿名能力收窄**：若业务上确实需要匿名发帖，加轻量验证（一次性 token 或行为验证码），不要裸开放。
- **转义的既有防线要保住**：输出侧 `html.escape`（`app.py:755-756`）是正确的，改造时不要退化。

---

## 6. 参考链接

- CWE-862: Missing Authorization：https://cwe.mitre.org/data/definitions/862.html
- CWE-770: Allocation of Resources Without Limits or Throttling：https://cwe.mitre.org/data/definitions/770.html
- OWASP Input Validation Cheat Sheet：https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
- OWASP Automated Threats to Web Applications（OAT-011 Scraping / OAT-004 变体）：https://owasp.org/www-project-automated-threats-to-web-applications/

---

## 7. 学习要点

- **考什么思路**：把"**能写**"当成独立风险类别看待。很多测试者看到输出转义到位就写"无 XSS、无问题"，但匿名无限写入本身是资源与内容层面的缺陷，需要单独列项。
- **测试时的自伤提醒（本轮真实教训）**：用 sqlmap 打 `POST /board` 时，注入测试会**通过写端点落库**——2 秒写 555 行。任何注入/模糊测试**开始前必须先判断参数是否作用于写端点**，否则工具本身就在污染数据。本靶场已如实记录并回滚。
- **同类变体**：
  - 匿名评论/反馈接口被用于垃圾内容与 SEO 污染（邮件轰炸、外链注入）。
  - 上传接口无总量/频控导致磁盘写满（本靶场 VER-16 是同族问题，见 `file-upload/VER-08-上传文件名非法字符触发500.md` 文末「附：VER-16 匿名上传」独立小节）。
  - 日志记录接口 `POST /log` 无认证，用于日志投毒（伪造审计痕迹）。
  - 数据库/缓存膨胀型 DoS：单请求可控长度 × 无限次数。
- **写报告要点**：限流类漏洞要给**实测速率**（"2 秒 555 行"远大于"可以无限写"），并明确区分"能写"与"能执行脚本"。
