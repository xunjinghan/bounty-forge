# 导航 · NAVIGATION

`INDEX.md`（130KB+）是全量索引，整页加载对阅读和 diff 都不友好。
这份文件是**人手写的入口**：先看这里，再按需跳到 INDEX。

## 我想……

| 我想做的事 | 去哪 |
| --- | --- |
| 快速了解项目定位与方法论 | [`README.md`](../README.md) |
| 看"证据链 ↔ 方法论"对应关系 | [`EVIDENCE_METHODOLOGY_MAP.md`](../EVIDENCE_METHODOLOGY_MAP.md) |
| 按 CVE 打靶（执行顺序） | [`cve-lib/loop4-执行顺序.md`](../cve-lib/loop4-执行顺序.md) |
| 找 CVE 靶场清单 | [`cve-lib/CVE靶场清单.md`](../cve-lib/CVE靶场清单.md) |
| 学"怎么不踩坑" | [`playbook/挖洞避坑手册.md`](../playbook/挖洞避坑手册.md) |
| 抄报告格式 | [`reports/`](../reports/)（含 `submit/` 提交版与自查清单） |
| 用检测脚本 / nuclei 模板 | [`poc/`](../poc/)、[`nuclei-rules/`](../nuclei-rules/) |
| 看某次实战的原始证据 | [`evidence/`](../evidence/)（按批次分目录） |
| 全量索引（长文档） | [`INDEX.md`](../INDEX.md) |

## 建议的阅读顺序（新读者）

1. `README.md` —— 这是什么、覆盖了什么、红线在哪
2. `EVIDENCE_METHODOLOGY_MAP.md` —— 本项目的"魂"：证据链怎么和方法论挂钩
3. `playbook/挖洞避坑手册.md` —— 最实用的部分，能直接少走弯路
4. `reports/submit/` —— 报告怎么写才像能提交的
5. `cve-lib/loop4-执行顺序.md` + `poc/` —— 想动手时再进

## 给贡献者

新增内容请同步更新本文件（入口级内容）与 `INDEX.md`（全量索引）。
证据类产物请放在 `evidence/<批次>/<类型>/` 下，并在批次目录补一句"怎么复跑"。
