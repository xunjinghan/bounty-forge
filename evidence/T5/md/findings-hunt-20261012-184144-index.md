# 阶段3 漏洞挖掘清单（2026-10-12T18:41:44+08:00）

- 疑似/确认条目：**15**（确认 13，需验证 13）
- 类别分布：{"业务逻辑/竞态": 1, "业务逻辑/CSRF": 1, "敏感信息泄露/密钥推导": 1, "认证/会话管理": 1, "Host 头注入/弱 token": 1, "危险功能/认证缺失": 1, "业务逻辑/匿名写": 1, "文件上传/异常处理": 1, "业务逻辑/参数污染": 1, "功能缺陷/异常": 1, "业务逻辑/整数边界": 1, "信息泄露": 1, "CSRF/会话可用性": 1, "越权/参数校验": 1, "垂直越权面": 1}
- 严重度（自评）：{"high": 4, "medium": 4, "low": 5, "info": 2}
- 阴性/已封堵核验项：12
- 范围：仅 127.0.0.1:8091 / 127.0.0.1:8095

| 编号 | 类别 | 端口 | 自评 | 是否需要验证 | 标题 |
|---|---|---|---|---|---|
| HUNT-01 | 业务逻辑/竞态 | 8095 | high | 是 | 并发下单可把余额扣成负数（先读余额校验、后无条件扣款，非同一原子操作） |
| HUNT-02 | 业务逻辑/CSRF | 8095 | high | 是 | 状态变更接口无 HTTP 方法限制且无 CSRF token：GET 即真实扣款/建单/改单/领券 |
| HUNT-03 | 敏感信息泄露/密钥推导 | 8095 | high | 是 | /debug 泄露 SECRET_KEY，导致 CSRF token 可离线伪造并完成转账（实测链条成立） |
| HUNT-04 | 认证/会话管理 | 8095 | high | 是 | GET /logout 不销毁服务端会话：旧 Cookie 在登出后仍可完整访问账户 |
| HUNT-05 | Host 头注入/弱 token | 8095 | medium | 是 | /forgot 回显 Host / X-Forwarded-Host，且 token=md5(username) 可预测（含不存在用户） |
| HUNT-06 | 危险功能/认证缺失 | 8095 | medium | 是 | GET /__reset 无认证无 CSRF：任意可达进程/页面可一键删库重建 |
| HUNT-07 | 业务逻辑/匿名写 | 8095 | medium | 是 | POST /board 匿名可写（无认证、无 CSRF、无长度限制、无频控） |
| HUNT-08 | 文件上传/异常处理 | 8095 | medium | 是 | 匿名上传：非法文件名（超长/NUL/Windows 非法字符）触发未处理异常 500，无长度下限/字符集校验 |
| HUNT-09 | 业务逻辑/参数污染 | 8095 | low | 是 | 表单解析：query 参数覆盖 POST body（form() 中 data.update(q)），方法语义与参数来源不严格 |
| HUNT-10 | 功能缺陷/异常 | 8095 | low | 是 | 登录态访问 GET / 稳定 500（app.py:512 sqlite3.Row.get），未登录同请求 200 |
| HUNT-11 | 业务逻辑/整数边界 | 8095 | low | 是 | 提现金额无上限：int 超 2^63-1 触发 SQLite 绑定 OverflowError → 500 |
| HUNT-12 | 信息泄露 | 8095 | low | 是 | /api/search 响应体回显 SQL 模板字符串（实现细节泄露），LIKE 通配符未转义 |
| HUNT-13 | CSRF/会话可用性 | 8095 | low | 是 | GET /logout 无 CSRF：任意页面可强制受害者登出（会话拒绝服务） |
| HUNT-14 | 越权/参数校验 | 8095 | info | 否 | /api/order?id= 未做类型规范化：'+1'/'01'/'1e0'/'1.0' 均被判为 1 |
| HUNT-15 | 垂直越权面 | 8095 | info | 否 | /debug 对已登录非 admin 返回 403 而非 404：存在性与权限边界被区分 |

## 原始证据文件

- `A` → `security/learning/_evidence/hunt-a-bizlogic-20261012-1830.json`
- `A3b` → `security/learning/_evidence/hunt-a3b-race-order-20261012-1835.json`
- `B` → `security/learning/_evidence/hunt-b-idor-20261012-1840.json`
- `C` → `security/learning/_evidence/hunt-c-upload-xss-rce-20261012-1845.json`
- `D` → `security/learning/_evidence/hunt-d-ssrf-8091-20261012-1850.json`
- `E` → `security/learning/_evidence/hunt-e-wrapup-20261012-1855.json`
- `F` → `security/learning/_evidence/hunt-f-extra-20261012-1900.json`
- `F7` → `security/learning/_evidence/hunt-f7-logout-20261012-1905.json`

## 阴性核验

- **N-01 SQL 注入**（8095/8091）：所有参数走 sqlite3 占位符参数化；8095 /api/search 直接回显 SQL 模板但无拼接
- **N-02 IDOR/越权**（8095/8091）：8095 /api/order、/api/profile 跨用户统一 404；/order/status 跨用户 404；/admin/* 普通用户 404；8091 /api/profile、/api/orders 越权 404、未登录 401
- **N-03 命令注入**（8095 /ping）：正则 ^[a-zA-Z0-9.\-]{1,253}$ + subprocess 参数数组 + shell=False；分隔符/换行/NUL/超长全部 400；仅 -n 被当作主机名传给 ping 工具（无命令执行）
- **N-04 SSTI**（8095 /greet、/search、/api/search）：{{7*7}}/${7*7}/#{7*7} 均原样回显，无 49；eval 已移除
- **N-05 XSS**（8095/8091）：输出侧 html.escape（8095）与 esc()（8091）生效：无原始 <script> 反射；留言板与上传结果页均转义
- **N-06 路径穿越/任意文件读**（8095 /download）：../、..%2f、%2e%2e、....//、绝对路径、%00 截断全部 403/404；realpath 前缀校验生效
- **N-07 文件上传绕过后利用**（8095 /upload）：白名单外后缀（.php/.svg/.jpeg/.htaccess/无后缀）全部 400 拒绝；落盘文件仅 .jpg/.png/.txt；/uploads/* 以 octet-stream + attachment + nosniff 返回，浏览器不执行；未发现目录外落地（../、绝对路径均被 basename 规整）
- **N-08 SSRF 越界**（8095 /fetch）：localhost/0.0.0.0/2130706433/0x7f000001/017700000001/127.1/[::1]/userinfo@ 全部 403；非白名单端口 22/6379/3306/9999 403；file/gopher/dict 403；https 亦 403。仅 127.0.0.1 字面 + 白名单端口可达（含 8091，属设计内）
- **N-09 用户名枚举**（8091 /login）：存在用户与不存在用户失败响应一致（303 /login?m=bad）；dummy_verify 抹平计时
- **N-10 注册/改密 CSRF**（8091）：8091 /change-password 伪造/缺失 CSRF → 403；注册与登录同样强制 CSRF 与 Origin 校验
- **N-11 弱口令/口令存储**（8095/8091）：8095 admin 为 22 位强口令、明文入库（源码注明为教学面）；8091 PBKDF2-HMAC-SHA256(200000)+独立盐；/admin/users 不显示口令字段
- **N-12 模板级扫描**（8095/8091）：nuclei v3.11.1 以 medium,high,critical 跑 32130 模板/32044 请求，matched=0（errors 8895 为对 404/501 的模板噪声）