# t2 检测资产索引（nuclei + Python）

- 产出：forge-detector，loop4 任务 t2（profileSeed n2）
- 目录：`D:\vuln-xiuxian\nuclei-rules\`（5 个模板）+ `D:\vuln-xiuxian\poc\`（5 个 Python 文件）
- 哈希总表：`D:\vuln-xiuxian\_sha256-manifest-t2.txt`
- 说明文档：`D:\vuln-xiuxian\poc\README.md`（含实测数据、顶回理由、自查表）
- 引擎：nuclei **v3.11.1**；Python **3.12 标准库**（无 requests / pycryptodome / 任何第三方包）

---

## 1. 资产总表

| # | 资产 | 类型 | 洞 ID | 方法 | 破坏性 | 默认启用 |
|---|---|---|---|---|---|---|
| 1 | `B1-DVWA-LFI-PATH-TRAVERSAL.yaml` | nuclei | B1-LFI-01 | GET | 否 | 是 |
| 2 | `B4-DVWA-SESSION-FIXATION-WEAK-ID.yaml` | nuclei | B4-SESSION-01 | GET | 否 | 是 |
| 3 | `C1-SHIRO-FINGERPRINT.yaml` | nuclei | C1-SHIRO-2016-4437 | GET | 否 | 是 |
| 4 | `DVWA-SESSION-COOKIE-ATTRIBUTES.yaml` | nuclei | B5 前提条件 | GET | 否 | 是 |
| 5 | `C2-TOMCAT-2017-12615-PUT-CONFIRM.yaml` | nuclei | C2-TOMCAT-2017-12615 | **PUT** | **是** | **否（destructive tag）** |
| 6 | `poc/bfnet.py` | Python 公共库 | — | GET/HEAD | 否 | — |
| 7 | `poc/bf_b1_dvwa_lfi.py` | Python | B1-LFI-01 | GET | 否 | — |
| 8 | `poc/bf_b4_dvwa_session_fixation.py` | Python | B4-SESSION-01 | GET | 否 | — |
| 9 | `poc/bf_c1_shiro_fingerprint.py` | Python | C1-SHIRO-2016-4437 | GET | 否 | — |
| 10 | `poc/bf_c2_tomcat_put_readonly.py` | Python | C2-TOMCAT-2017-12615 | GET/HEAD/OPTIONS | 否 | — |

---

## 2. 引用文件的两套路径（工作区原件 ↔ vuln-xiuxian 归档版）

同一份文件有两处副本。**模板与脚本里写的是工作区原件路径**（archivist 按「只读复制」纪律
保证源目录未被改动），下表给出归档版对应位置，供按 `INDEX.md` 反查时使用。

| 文件（工作区原件） | 归档版（`D:\vuln-xiuxian\`） |
|---|---|
| `security\learning\loop3-b-dvwa-bwapp-report-t4-20261012.md` | `reports\b-档\loop3-b-dvwa-bwapp-report-t4-20261012.md` |
| `security\learning\loop3-c-vulhub-report-t7-20261012.md` | `reports\c-档\loop3-c-vulhub-report-t7-20261012.md` |
| `security\learning\_evidence\verified-loop3-b-20261012-2236.md` | `evidence\B\md\verified-loop3-b-20261012-2236.md` |
| `security\learning\_evidence\loop3-t7-c1-matrix-20261012.json` | `evidence\C\json\loop3-t7-c1-matrix-20261012.json` |
| `security\learning\_evidence\loop3-t7-c1-discriminate-20261012.json` | `evidence\C\json\loop3-t7-c1-discriminate-20261012.json` |
| `security\learning\_evidence\loop3-t7-c2-tomcat-put-raw.txt` | `evidence\C\txt\loop3-t7-c2-tomcat-put-raw.txt` |
| `security\learning\_loop3-c-c1-oracle-verdict-20261012.md` | 见 `INDEX.md` §1.6 —— **该文件编码损坏，禁止据其内容做结论引用** |

> ⚠️ 上述 6 个路径均已 `Glob` 实查存在（工作区原件）+ `Get-ChildItem` 实查存在（归档版）。

---

## 3. 未做的洞，以及为什么（顶回记录）

| 洞 | 状态 | 理由 |
|---|---|---|
| **B2-XXE-01** | **未做模板** | 探测必须 POST 实体声明，loop3 实测会改写 `bWAPP.users.secret`。是否算破坏性需队长裁定，未裁定前不动手 |
| **B3-CSRF-01** | **未做模板** | 同上，且 CSRF 的证明前提是「跨站发起真实状态变更」，必然写入。配置面（缺 Origin/Referer 校验）可只读检查，但单独立洞价值低 |
| **B5-XSS-01** | **未做漏洞模板，改为交付前提条件模板** | 漏洞成立前提是把 `<script>` 写进 guestbook = 写操作，破红线。改为交付 `DVWA-SESSION-COOKIE-ATTRIBUTES.yaml`（会话 cookie 属性，GET，零副作用） |

---

## 4. 一句话自检结论

**非破坏性自查通过**：5 个 nuclei 模板中 4 个纯 GET，1 个 PUT 模板已标 `destructive: "true"` +
`default-enabled: "false"` + 尾斜杠 + 只回显常量的无害 payload；
5 个 Python 文件中 `bfnet.probe()` **物理上**只接受 GET/HEAD（传 PUT 抛 `ValueError`），
C2 脚本额外走 OPTIONS（只读方法）。无任何脚本含 `deleteMe=deleteMe` 判据。

详见 `poc\README.md` §2（顶回三条）、§8（交付前自查表）、§9（loop3 证据矛盾）。