# 漏洞笔记：/debug 对已登录非 admin 返回 403 而非 404（端点存在性可探测）

- **编号**：VER-15（来源 HUNT-15，t5 判定 **confirmed-no-impact**，标签为"行为确认但无实际影响"）
- **靶场**：target-site-lab `http://127.0.0.1:8095`（本机授权练习环境）
- **危害等级**：信息项（Info，CVSS-like 0.0）
- **CWE/OWASP**：CWE-203（Observable Discrepancy，403 与 404 的语义差异可推断资源存在）；OWASP Top 10 2021 **A01:2021 Broken Access Control（信息暴露面）**
- **复现率**：1/1 本轮（demo/alice 均 403，`/admin/*` 均 404）
- **代码位置**：`target-site-lab/app.py:1240-1247`（`debug` 的角色校验）与 `:1264` 附近（`/admin/*` 的 404 隐藏写法，对照）

---

## 1. 漏洞概述

同一角色校验，两个端点给出两种语义的失败响应：

- `GET /debug`：已登录但非 admin → **403**（`app.py:1243-1247`）——明确告诉对方"这个资源存在，只是你没权限"。
- `GET /admin/users`、`GET /admin/orders`：非 admin → **404**——按"不存在"处理，不泄露端点是否存在。

这个 403/404 差异让攻击者可以**逐路径探测端点存在性**：收到 403 说明端点真实存在（只是权限不足），收到 404 则说明不存在或有意隐藏。它是纯粹的信息项，**不能读 SECRET_KEY**（读 `/debug` 仍需 admin 会话），所以按 info 归档、不按提权计。

---

## 2. 原理（代码层根因）

```python
# target-site-lab/app.py:1240-1247（debug）
user = self.require_user(conn)
if not user:
    return
if user["role"] != "admin":
    self.html(403, page("403",
        "<h1>403</h1><p>仅管理员可访问。</p>", user["username"]))   # L1243-1247
    return
```

对照（`/admin/*` 走 404 隐藏，与上者不一致）：

```python
# 同文件 admin_users / admin_orders 的非 admin 分支（语义为 404）
```

根因：**权限失败响应没有统一约定**。`/debug` 选择"告诉对方无权限（403）"，`/admin/*` 选择"假装不存在（404）"。二者都能算合理设计，但在同一个应用里混用，就把"端点存在性"变成了可观测的差异。此外 `debug` 的 403 响应还会回显当前用户名（`page(..., user["username"])`），进一步确认了会话身份。

---

## 3. 可复现 payload

前置条件：靶场 8095 在跑；demo/demo123（普通用户）可用。

```bash
# ① 登录普通用户
curl.exe -s -c C:\temp\t5jar10 -d "username=demo&password=demo123" \
  http://127.0.0.1:8095/login

# ② 探测 /debug：403 → 端点存在，权限不足
curl.exe -s -o NUL -w "%{http_code}\n" -b C:\temp\t5jar10 http://127.0.0.1:8095/debug

# ③ 对照 /admin/*：404 → 端点被隐藏
curl.exe -s -o NUL -w "%{http_code}\n" -b C:\temp\t5jar10 http://127.0.0.1:8095/admin/users

# ④ 匿名对照：/debug 未登录 → 302 跳登录
curl.exe -s -o NUL -w "%{http_code}\n" http://127.0.0.1:8095/debug
```

原始请求：

```http
GET /debug HTTP/1.1
Host: 127.0.0.1:8095
Cookie: token=<demo 会话>
```

---

## 4. 复现步骤与证据

| 请求者 | `/debug` | `/admin/users` | 语义 |
|---|---|---|---|
| 匿名 | 302 → `/?err=login` | 302 | 未认证 |
| demo（普通用户） | **403** | **404** | 403 暴露存在性；404 隐藏 |
| admin | 200（渲染配置页，含 SECRET_KEY——见 VER-03 笔记） | 200 | 越权成功面 |

原始证据文件：

- `security/learning/_evidence/verify-02-logic-session-20261012-1855.json`（sha256 `1b7b154509e9a95157fbd67b78a22289798a0d0383af802c48f8007a5a74cd5c`）——demo 访问 `/debug` 403 与 `/admin/*` 404 的原始响应
- `security/learning/_evidence/verified-20261012-184800.json`（sha256 `218dc13d10cb4063e2eb9b85d0b220fa04d33af20499f24025a103dcbf83c020`，VER-15 条目：verdict=`confirmed-no-impact`、severity=`info`）
- `security/learning/_evidence/attack-surface-20261012-182250.json`（sha256 `154b62ac6544fd7bb80b1d39264c02413a52d7b89705f7d911c9297457d8b91f`）——侦察阶段的鉴权矩阵（302/403/404 全量记录）
- 源码比对：`target-site-lab/app.py:1240-1247`

回滚：本项只读，无需回滚。

---

## 5. 修复方案

### 代码级（P2，落到 `app.py:1243-1247`）

统一"权限失败即 404"的约定（与 `/admin/*` 对齐），避免暴露端点存在性：

```python
user = self.require_user(conn)
if not user:
    return
if user["role"] != "admin":
    self.html(404, page("404", "<h1>404</h1>"))     # 改 403 → 404，且不回显用户名
    return
```

若业务上必须区分"未认证"与"无权限"，则统一：**未认证 → 302 跳登录；无权限 → 404**，全站一致，不允许个别端点用 403。

### 纵深防御

- **响应一致性约定**：把"权限失败响应"写进接口规范并加自动化用例，逐个端点断言状态码与响应体模板一致。
- **错误页裁剪**：404/403 页面不回显用户名/角色/路径等会话信息（`page(..., user["username"])` 这类写法在错误页要去掉）。
- **调试端点治理**：`/debug` 本身应彻底不在生产路由中（与 VER-03 修复的 P0 项同一动作）——端点不存在，也就没有存在性可探测。
- **枚举成本抬升**：对连续 4xx 探测做速率限制与告警。

---

## 6. 参考链接

- CWE-203: Observable Discrepancy：https://cwe.mitre.org/data/definitions/203.html
- OWASP WSTG — Enumerate Applications on Webserver：https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/04-Enumerate_Applications_on_Webserver
- OWASP Authorization Cheat Sheet（失败响应一致性）：https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html

---

## 7. 学习要点

- **考什么思路**：状态码也是信息通道。系统性地比较"存在但无权限"与"不存在"两类响应的差异，可以重建隐藏端点清单（403/401 vs 404、响应长度差异、响应时间差异都属同一族）。
- **本项的边际价值**：`/debug` 的存在性本身不值钱，值钱的是它背后的 403 → "端点存在" → 配合 VER-03（SECRET_KEY 泄露链）时，攻击者能在拿到 admin 会话前就锁定目标端点。信息项要按"在攻击链中的位置"评估价值，而不是只看单点危害。
- **同类变体**：
  - `/admin/*` 与 `/api/internal/*` 混用 403/404。
  - 响应体长度/时间差异暴露用户是否存在（登录用户名枚举，user enumeration）。
  - 目录列表被禁用但文件 403（存在）与 404（不存在）可区分。
  - GraphQL introspection 未关闭，直接给出完整 schema。
- **写报告要点**：info 项要**明说不可利用**（"无法读取 SECRET_KEY，需 admin"），否则 reviewer 会误判为夸大；同时给出"统一失败响应"的可落地修法。
