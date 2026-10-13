# 漏洞笔记：/api/search 回显 SQL 模板 + LIKE 通配符未转义

- **编号**：VER-12（来源 HUNT-12，t5 判定 confirmed）
- **靶场**：target-site-lab `http://127.0.0.1:8095`（本机授权练习环境）
- **危害等级**：低危（Low）
- **CWE/OWASP**：CWE-209（Generation of Error Message Containing Sensitive Information）＋ CWE-155（Improper Neutralization of Wildcards or Matching Symbols，LIKE 通配符未转义）；OWASP Top 10 2021 **A04:2021 Insecure Design / A01:2021 Broken Access Control（数据面过宽）**
- **CVSS-like**：3.7（AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N）
- **复现率**：3/3 稳定
- **代码位置**：`target-site-lab/app.py:619-627`（`api_search`，关键行 622 与 625）

---

## 1. 漏洞概述

两个问题叠加，都在同一个只读接口上：

1. **内部 SQL 模板回显**：响应 JSON 里带 `"sql": "SELECT id,name,price_cents FROM products WHERE name LIKE ?"`，直接泄露表名、列名与占位符风格（`?` 说明是 sqlite3/pyformat 风格），给攻击者做后续注入/拖库时省掉指纹阶段。
2. **LIKE 元字符未转义**：参数拼接为 `f"%{q}%"`，`%` 与 `_` 未做 `ESCAPE` 处理，`q=%` 或 `q=_` 直接返回全表——**单字符即可枚举整表数据**，绕过任何"按关键词过滤"的业务意图。

**明确边界**：SQL 注入本身**不成立**——语句是参数化的（`LIKE ?`），t5 用 sqlmap（level2/risk1，BEUSTQ）独立复打三处入口全部阴性（`does not seem to be injectable`）。本项只按"信息泄露 + 通配符枚举"计危害，不写成注入。

---

## 2. 原理（代码层根因）

```python
# target-site-lab/app.py:619-627
def api_search(self, q):
    conn = get_db()
    try:
        sql = "SELECT id,name,price_cents FROM products WHERE name LIKE ?"
        rows = [tuple(r) for r in
                conn.execute(sql, (f"%{q}%",)).fetchall()]      # L622-624 元字符未转义
        self.json(200, {"sql": sql, "results": rows})           # L625 SQL 模板回显
    finally:
        conn.close()
```

根因：

- **L625 把 `sql` 字符串当业务数据返回**，属于"调试残留进响应体"（与 VER-15 的 403/404 差异同族：都是信息暴露面）。列名与查询结构一旦公开，攻击面测绘成本大幅下降。
- **L622-624 的 `f"%{q}%"`** 让用户输入直接构成 LIKE 模式的一部分。LIKE 里 `%` 匹配任意串、`_` 匹配任意单字符；未转义等价于把"过滤条件"变成"过滤器开关"。正确写法是 `LIKE ? ESCAPE '\'` 并对输入中的 `%`、`_`、`\` 转义。

对照：同文件的 `/search`（HTML 版，`app.py:630-645`）用同样的 `f"%{q}%"`，只是输出经过 `html.escape`，所以通配符枚举在 HTML 版同样存在（XSS 则不成立）。

---

## 3. 可复现 payload

前置条件：靶场 8095 在跑；该接口无需登录态。

```bash
# ① 正常单字符查询（1 行）
curl.exe -s "http://127.0.0.1:8095/api/search?q=k"
#    响应含 "sql":"SELECT id,name,price_cents FROM products WHERE name LIKE ?"

# ② 通配符 % 枚举全表（3 行）
curl.exe -s "http://127.0.0.1:8095/api/search?q=%25"

# ③ 通配符 _ 同样全表（3 行）
curl.exe -s "http://127.0.0.1:8095/api/search?q=_"

# ④ HTML 版同样中招（仅信息面，不含 XSS）
curl.exe -s "http://127.0.0.1:8095/search?q=%25"
```

> 说明：URL 里 `%` 必须编码为 `%25`，否则被解析成转义序列起始符。

---

## 4. 复现步骤与证据

| 观测项 | 实测 |
|---|---|
| `q=k` | 1 行 / 84 字节 |
| `q=%` | **3 行 / 167 字节**（全表） |
| `q=_` | **3 行 / 167 字节**（全表） |
| 响应体字段 | 含 `sql` 字段，回显完整 SELECT 模板与表/列名 |

原始证据文件：

- `security/learning/_evidence/verify-02-logic-session-20261012-1855.json`（sha256 `1b7b154509e9a95157fbd67b78a22289798a0d0383af802c48f8007a5a74cd5c`）——`q=k` / `q=%` / `q=_` 三组响应原文与字节数
- `security/learning/_evidence/verified-20261012-184800.json`（sha256 `218dc13d10cb4063e2eb9b85d0b220fa04d33af20499f24025a103dcbf83c020`，VER-12 条目：raw_request / repro_cmd / harm_proof）
- `security/learning/_evidence/sqlmap-t5-verify.log`（sha256 `6610e12565cdad10f94dff92a577d8c1a74ff8d9642a48e5d76f137d9a7ff24f`）——参数化挡住注入的阴性证据（说明本项不是 SQLi）
- 源码比对：`target-site-lab/app.py:619-627`（HTML 版 `:630-645`）

回滚：本项只读，无需回滚；收集时点（2026-10-12T18:48+08:00）靶场库仍为种子态。

---

## 5. 修复方案

### 代码级（P0，落到 `app.py:619-627`）

```python
def api_search(self, q):
    conn = get_db()
    try:
        sql = "SELECT id,name,price_cents FROM products WHERE name LIKE ? ESCAPE '\\'"
        like = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        rows = [tuple(r) for r in
                conn.execute(sql, (f"%{like}%",)).fetchall()]
        self.json(200, {"results": rows})       # 删除 "sql" 字段，不在响应中回显语句
    finally:
        conn.close()
```

要点：① 转义 `\ % _` 三个元字符并显式声明 `ESCAPE '\'`；② 响应里**不返回任何 SQL 文本**，需要排障时写服务端日志而非响应体；③ 加结果条数上限（如 `LIMIT 200`）与最小关键词长度，避免"单字符拉全表"。

### 纵深防御

- **错误与调试信息出网策略**：统一约定"响应体不含 SQL/堆栈/路径"，用中间件过滤含 `SELECT`、`Traceback`、盘符路径的响应（本靶场 VER-15、VER-08 也属于信息外泄族）。
- **查询日志**：把真实 SQL 记到服务端审计日志，便于排障且不外泄。
- **数据面收敛**：`products` 这类表对外只暴露必要字段（本例 `price_cents` 是否对外可视按业务定）。
- **回归用例**：`q=%`、`q=_`、`q=\` 的响应行数必须等于精确匹配行数。

---

## 6. 参考链接

- CWE-209: Generation of Error Message Containing Sensitive Information：https://cwe.mitre.org/data/definitions/209.html
- OWASP WSTG — Testing for SQL Injection（LIKE 通配符与转义小节）：https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection
- SQLite `LIKE` 与 `ESCAPE` 语义（官方文档）：https://www.sqlite.org/lang_expr.html#like
- OWASP Top 10 2021 A04:2021 Insecure Design：https://owasp.org/Top10/A04_2021-Insecure_Design/

---

## 7. 学习要点

- **考什么思路**：把"信息泄露"和"注入"分开评估。参数化到位（挡住注入）不等于接口安全——**回显内部语句**和**元字符未转义**是两条独立的缺陷线，需要分开判定与分开取证。
- **LIKE 通配符注入**是一种容易被忽略的"非 SQLi 注入"：`%`/`_` 不需要任何引号破坏就能扩大查询结果，可用于**枚举与探测数据量**（本例 1 行 → 3 行全表）。
- **同类变体**：
  - 正则元字符未转义（服务端用用户输入拼 `re.compile`，`.*` 拉全量）。
  - 路径 glob 未转义（`*`、`?`、`[a-z]`）。
  - 前端过滤后端不过滤（只在 UI 判断关键词长度）。
  - GraphQL/Elasticsearch 查询 DSL 里 `wildcard` 查询未清洗导致全量拉取。
- **写报告要点**：这类"低危信息项"的正确写法是**明确边界**——写清楚"注入不成立（附 sqlmap 阴性证据）"，只按信息泄露计危害，否则报告可信度会被 reviewer 直接打掉。
