# 漏洞笔记：GET /__reset 无认证重置（一键删库重建）

- **编号**：VER-06（来源 HUNT-06，t5 判定 confirmed）
- **靶场**：target-site-lab `http://127.0.0.1:8095`（本机授权练习环境），限定"仅回环可达"
- **危害等级**：中危（Medium）——若该端点出现在对外部署中，应直接升为高危
- **CWE/OWASP**：CWE-306（Missing Authentication for Critical Function）＋ CWE-749（Exposed Dangerous Method or Function）；OWASP Top 10 2021 **A01:2021 Broken Access Control / A05:2021 Security Misconfiguration**
- **CVSS-like**：6.5（AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H）
- **复现率**：6/6（本轮每轮验证流程都用它复位，均 200 且库哈希回到基线）
- **代码位置**：`target-site-lab/app.py:1270-1278`（`reset_endpoint`）；调用入口 `app.py:1286-1302`（`--reset` 启动参数）

---

## 1. 漏洞概述

`GET /__reset` 不带任何 Cookie、令牌或二次确认，一个匿名 GET 就把 `lab.db` 整库删除重建、并把 `uploads/` 目录清空。它仅有的防护是"来源 IP 必须是回环"（`app.py:1271-1273`），而这个判断对**同机任何进程、任何浏览器页面**都不设防——包括被诱导访问 `http://127.0.0.1:8095/__reset` 的本地浏览器，以及扫描/爬虫工具。

实测中该端点确实造成过真实破坏：挖掘阶段 `katana` 爬虫自动访问过它（一次删库重建），验证阶段 `sqlmap` 对 `/board` 写入的 1454 行匿名留言也被它一次抹除。

---

## 2. 原理（代码层根因）

```python
# target-site-lab/app.py:1270-1278
def reset_endpoint(self):
    peer = self.client_address[0]
    if peer not in ("127.0.0.1", "::1"):     # 唯一防护：来源 IP 判断
        self.html(403, "<h1>403</h1>")
        return
    reset_database()                          # 删库 + 重建 + 清空 uploads/
    self.html(200, page("reset",
        "<h1>已重置</h1><p>数据库、上传目录已恢复初始状态。</p>" ...))
```

问题点：

1. **职责混淆**：把"开发/教学用的复位开关"做成了**业务 HTTP 路由**（走同一个 `do_GET` 路由表），与生产功能同面可达。
2. **认证缺失**：没有 admin 角色校验、没有 CSRF token、没有启动参数之外的开关。
3. **IP 白名单不是认证**：`client_address` 只能证明"请求来自本机"，无法证明"操作者有权复位"——浏览器里的任何页面都可以发起这个请求（`<img src="http://127.0.0.1:8095/__reset">` 即可，因为它是 GET）。
4. **不可逆**：`reset_database()` 直接删除数据文件重建，无备份、无确认、无审计日志。

---

## 3. 可复现 payload

前置条件：靶场 8095 在跑（仅回环监听）；不需要任何登录态。

```bash
# ① 先制造可观测的数据变更（匿名留言，见 VER-07）
curl.exe -s -i -d "content=T5-anon-verifier-probe" http://127.0.0.1:8095/board

# ② 匿名 GET 复位，无 Cookie、无 token
curl.exe -s -i http://127.0.0.1:8095/__reset
#    → 200，正文含「已重置」「数据库、上传目录已恢复初始状态」
```

```powershell
# ③ 直查数据库，确认数据被抹除
python -c "import sqlite3;c=sqlite3.connect(r'C:\Users\Administrator\Documents\deepseek-harness\default-workspace\target-site-lab\lab.db');print('messages=',c.execute('select count(*) from messages').fetchone(),'sessions=',c.execute('select count(*) from sessions').fetchone())"
```

浏览器侧等价载荷（证明"IP 白名单"挡不住本机浏览器）：

```html
<img src="http://127.0.0.1:8095/__reset" alt="">
```

---

## 4. 复现步骤与证据

| 观测项 | 复位前 | 复位后（实测） |
|---|---|---|
| `messages` 行数 | 1455（sqlmap 盲注测试积累） | **1** |
| `sessions` 行数 | 2 | **0** |
| `orders` 行数 | 3 | 3（种子态） |
| `lab.db` sha256 | 变动值 | **`49b2032c29f8057530704203fd361bb162461eaeeeeb874c7ac1b8e8956cc7af`** |
| `uploads/` | 有匿名上传文件 | 目录被重建清空 |

一次匿名 GET 抹掉全部业务数据与上传目录，全程 200。

原始证据文件：

- `security/learning/_evidence/verify-00-baseline-20261012-1855.json`（sha256 `c9aa99a4ea131a9840b9349c832357929466ffeeb23a40047fac94a6542ec818`）——复位前后基线与哈希
- `security/learning/_evidence/verify-03-injection-ssrf-upload-20261012-1855.json`（sha256 `d168699eede0933b74257f3080e4677db22e511859d25c0fa376b3de7a086fd2`）——sqlmap 写入 1454 行后被一次 `/__reset` 全部抹除的原始记录
- `security/learning/_evidence/verified-20261012-184800.json`（VER-06 条目：harm_proof / repro_cmd）
- `security/learning/_evidence/attack-surface-20261012-182250-SUPPLEMENT-01-head-reset.md`——侦察阶段的 `/__reset` 头探测补充记录
- 源码比对：`target-site-lab/app.py:1270-1278`

回滚：本项**不可回滚**（数据即被删除）——这本身就是危害的一部分。收集时点（2026-10-12T18:48+08:00）库已回到种子态，`PRAGMA integrity_check=ok`。

---

## 5. 修复方案

### 代码级（P0，落到 `app.py:1270-1278`）

教学环境的复位开关应满足三条中的任意两条组合：①只在启动参数下暴露 ②需要 admin 会话 + CSRF ③只在 DEBUG 开关为真时注册路由。

```python
# 改法一（推荐）：不做成 HTTP 路由，仅保留启动参数 python app.py --reset
#   删除 route() 中对 "/__reset" 的分发（app.py 路由表内对应条目）以及 reset_endpoint 方法

# 改法二：若必须保留 HTTP 形式，则叠加认证 + CSRF + 方法限制 + 显式开关
def reset_endpoint(self):
    if not DEBUG:                                       # DEBUG 由环境变量注入，生产默认 False
        self.html(404, page("404", "<h1>404</h1>"))
        return
    if self.command != "POST":                          # 禁止 GET 触发（避免 <img> 型 CSRF）
        self.html(405, page("405", "<h1>方法不允许</h1>"))
        return
    conn = get_db()
    try:
        user = self.require_user(conn)
        if not user:
            return
        if user["role"] != "admin":                      # 只允许管理员
            self.html(404, page("404", "<h1>404</h1>"))
            return
        if not self.verify_csrf(self.form()[1].get("csrf_token", "")):
            self.html(403, page("CSRF 校验失败", "<h1>请求被拒绝</h1>"))
            return
    finally:
        conn.close()
    reset_database()
```

### 纵深防御

- **审计与确认**：复位前写审计日志（时间、来源、会话），要求表单里输入 `RESET` 之类的二次确认串；复位前把 `lab.db` 复制为 `lab.db.bak-<时间戳>`。
- **路由分面**：把调试/运维端点放独立端口或独立一次性进程（只在需要时手动起），不与业务端口共用。
- **爬虫/扫描纪律**：自动化工具必须排除 `/__reset`（本靶场已发生两次误触发）；用 `robots.txt` 无济于事，更可靠的是"复位开关不做成 GET 路由"。
- **监控**：出现 `messages`/`orders` 行数骤降或数据文件 mtime 突变即告警。

---

## 6. 参考链接

- CWE-306: Missing Authentication for Critical Function：https://cwe.mitre.org/data/definitions/306.html
- CWE-749: Exposed Dangerous Method or Function：https://cwe.mitre.org/data/definitions/749.html
- OWASP Top 10 2021 A05:2021 Security Misconfiguration：https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
- OWASP WSTG — Testing for HTTP Methods and XST（GET 执行敏感动作）：https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods

---

## 7. 学习要点

- **考什么思路**：把"调试/运维面"当成攻击面的一部分来清点。越是"内部用的开关"，越容易缺认证，而且常常做成 GET 从而能被跨站触发。
- **为什么 `client_address` 不算认证**：它只是网络位置信息，任何能发请求到该端口的主体都满足；同机浏览器、代理、容器内的其他进程、被 SSRF 的内网跳板都能满足。
- **同类变体**：
  - `/debug`、`/admin/reindex`、`/actuator/*`（Spring Boot Actuator 未授权）。
  - 只校验 `X-Forwarded-For: 127.0.0.1` 就放行的"内网信任"实现（本靶场 VER-05 正是 Host/XFF 类头被信任的案例）。
  - 备份/导出接口（`/backup/download`）无认证导致整库泄露。
  - 运维端点用 GET 触发重启/清缓存，被页面 `<img>` 连带触发。
- **测试纪律**：这类端点一旦命中就是**破坏性操作**，自动化扫描器/爬虫必须提前排掉；本靶场两次误触发的教训已写入 `progress.md`。
