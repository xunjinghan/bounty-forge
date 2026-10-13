# 未复现笔记：CommonsCollections2 链失败 + `deleteMe` 判据被证伪（C1 配套阴性记录）

- **编号**：N-C01-SHIRO-02（Loop 3 · C 档，t7 复现 / t8 归档）
- **配套阳性笔记**：`security/learning/cve/C1-SHIRO-2016-4437-rememberMe反序列化默认密钥.md`（CVE-2016-4437，**Low 级配套阳性结论见该篇**）
- **靶场**：与 C1 同一环境，Vulhub `vulhub/shiro:1.2.4`，宿主 `http://127.0.0.1:18081/`
- **本文性质**：**阴性结论 + 判据证伪记录**，**不是漏洞条目**
- **测试时间**：2026-10-12 23:31–23:33（Asia/Shanghai）

> **本篇的价值**：阴性结论和阳性结论同等重要。
> **"CC1 主链打通了" ≠ "所有链都能打通"** —— 这条不写清楚，下游一定会照抄一条在别的环境里跑不通的链。

---

## 1. 结论概述

本轮 C1 复现中，**四条 gadget 链里有一条失败**，另有**一个原本打算用的判定方法被实测证伪**。两条都如实记录：

| 项 | 结论 |
|---|---|
| **CommonsCollections2** | ❌ **未复现** —— OOB **0 命中**。卡在 **classpath 缺 commons-collections 4** |
| **`deleteMe` 作为 RCE 判据** | ❌ **不可用** —— 实测矩阵证明成功链与失败链**返回完全相同**的 `deleteMe` |

---

## 2. 原理

### 2.1 CommonsCollections2 为何失败

**CC2 依赖 commons-collections 4.x 的特定 gadget**（`PriorityQueue` + `TransformingComparator` + `InvokerTransformer` 组合）。

**本环境实测 classpath 情况**：

| 依赖 | 版本 | 影响的链 |
|---|---|---|
| commons-collections | **3.2.1** | CC5 ✅ / CC6 ✅ / **CC2 ❌** |
| commons-beanutils | 1.9.2 | CB1 ✅ |

**卡在哪一步（明确）**：

1. **密钥解密环节：成功**（用默认密钥，cookie 已正常构造，序列化流 magic `aced0005` 正确）
2. **服务端反序列化：发生**（Shiro 走 `ObjectInputStream.readObject()`）
3. **❌ 卡在 gadget 触发**：**CC2 需要的 commons-collections 4 特有类在 classpath 里不存在** → gadget 链找不到入口 → **不会执行任何命令** → OOB 接收端 **0 命中**

**因此失败原因 = 依赖缺失，不是 payload 写错、不是密钥不对、不是环境不通。**

> **这一点必须写死**：`oob_hits: 0` **不等于**"打不通这个漏洞" —— 漏洞在 C1 里已经用 CC6 证明了成立。**CC2 失败只说明「这条链依赖的库不在」**，是**环境差异**，不是**漏洞否定**。

### 2.2 `deleteMe` 判据为何被证伪

**原本的假设**：`deleteMe=true` 表示解密/反序列化失败，`deleteMe=false` 表示成功 —— 若成立，就能用响应头直接判断成败，不用架 OOB。

**实测矩阵**（`loop3-t7-c1-matrix-20261012.json`，P1–P5 + 四条链）：

| 用例 | 输入 | HTTP | `deleteMe` |
|---|---|---|---|
| P1 | **合法 Java 序列化 String** | 302 | **`true`** |
| P2 | 乱码明文 | 302 | `true` |
| P3 | 截断 magic | 302 | `true` |
| P4 | 长乱码（2712 B） | 302 | `true` |
| P5 | **错误密钥** + 乱码 | 302 | `true` |
| CB1 | gadget（**RCE 成功**） | 302 | **`true`** |
| CC5 | gadget（**RCE 成功**） | 302 | **`true`** |
| CC6 | gadget（**RCE 成功**） | 302 | **`true`** |
| CC2 | gadget（**失败**） | 302 | **`true`** |

**结论**：`deleteMe=true` 只表示 `RememberMeManager` 没能取出合法 `PrincipalCollection`。**它对"解密成功/失败"和"RCE 成功/失败"全都没有区分能力** —— 连**错误密钥**（P5，理论上必失败）和**成功 RCE 的 CC6** 都返回 `true`。

**因此本轮改用 OOB 外带 + `/proc` 进程观测作为 RCE 判据**（两条独立证据互证，详见 C1 §4.2/§4.3）。

### 2.3 ⛔ 第二个被证伪的判据：响应时间

**原本的假设**：gadget 里放 `sleep 6`，看响应是否慢了 6 秒。

**为什么必然失败**：**`Runtime.exec()` / `ProcessBuilder.start()` 是异步的** —— JVM **不等子进程结束就返回**，所以响应耗时与子进程跑了多久**无关**。

**实测数据**（`loop3-t7-c1-timing-20261012.json`）—— 注意这三条链**在 OOB 与 `/proc` 上都证明 RCE 成功**：

| 链 | control | test(`sleep 6`) | **实测 delta** | 若同步执行应为 | 文件判定 |
|---|---|---|---|---|---|
| CommonsBeanutils1 | 0.008 s | 0.006 s | **−0.002 s** | +6 s | `executed: false` |
| CommonsCollections5 | 0.008 s | 0.016 s | **+0.008 s** | +6 s | `executed: false` |
| CommonsCollections6 | 0.008 s | 0.006 s | **−0.003 s** | +6 s | `executed: false` |

**成功链被判成"未执行"** —— 这就是假阴性。**hunter-web 一度据此误判 C1 漏洞不成立**，后靠 OOB + `/proc` 推翻。

### 2.4 正确的 oracle（本轮采用）

| 优先级 | 方法 | 判据 |
|---|---|---|
| **1（首选）** | **OOB 外带** | 回调**收到命中** = 解密 + 反序列化链路打通 |
| **2** | **容器进程表** | `/proc` 采样到 gadget 拉起的**子进程** |
| **3** | **容器日志** | **`BadPaddingException`** = 走到了解密步骤 |
| ⛔ | `deleteMe` 标志 | **恒为 `true`，零区分度**（§2.2） |
| ⛔ | `sleep` 计时 | **`Runtime.exec()` 异步，必假阴性**（§2.3） |

---

## 3. 可复现 payload（失败版）

CC2 链的 payload 生成**过程本身没有失败** —— 生成成功、cookie 长度正常：

| 项 | 实测值 |
|---|---|
| 序列化流长度 | 3274 B |
| cookie 长度 | 4396 |
| 明文 magic | `aced0005`（正常） |
| HTTP 响应 | `302` |
| **`deleteMe`** | `true` |
| **OOB 命中** | **`0`（0 条）** |

**对照**：同为 CC 系列、同样 magic 正常的 CC6（cookie 1880 B）**OOB 命中 1**。

> **关键对照关系**：**payload 生成正常 + cookie 可正常发出 + 服务端正常响应 = 只有 gadget 触发这一步没成。** 这把失败点精确定位到了"依赖缺失"，而不是前面任何环节。

---

## 4. 复现步骤与证据

### 4.1 失败步骤定位

| 步骤 | 期望 | 实测 | 判定 |
|---|---|---|---|
| 1 | 生成 CC2 gadget 序列化流 | 合法流 | ✅ 成功（3274 B，magic `aced0005`） |
| 2 | Base64 + AES 加密为 cookie | 合法 cookie | ✅ 成功（4396 B） |
| 3 | 携带 cookie 请求 | 302 | ✅ 服务端正常响应 |
| 4 | 服务端反序列化 | 走 `readObject()` | ✅ 发生（日志有 `ClassResolvingObjectInputStream`） |
| 5 | **gadget 触发 → 命令执行** | 命令执行 | ❌ **失败** |
| 6 | **OOB 外带确认** | 接收端收到 | ❌ **0 命中** |

**卡在第 5/6 步**，前四步全部正常。

### 4.2 依赖核对（失败根因）

| 链 | 需要的库 | 环境实测 | 结果 |
|---|---|---|---|
| CC2 | **commons-collections 4** | **只有 3.2.1** | ❌ **依赖缺失** |
| CC5 | commons-collections 3.x | 3.2.1 | ✅ |
| CC6 | commons-collections 3.x | 3.2.1 | ✅ |
| CB1 | commons-beanutils | 1.9.2 | ✅ |

**依赖核对的原始输出**：`t7-c1-toolchain-out.txt`。

### 4.3 原始证据文件（完整文件名 + sha256，t8 独立重算）

| 证据文件 | 内容 | sha256 |
|---|---|---|
| `loop3-t7-c1-matrix-20261012.json` | **`deleteMe` 判据证伪矩阵**（P1–P5 + 四链，全部 `true`） | `99eba28d198218119330bb9852d75e7f7a518eef73d861d946a1e71bbb15e432` |
| `loop3-t7-c1-timing-20261012.json` | **时序判据证伪**：三条成功链 delta 全为毫秒级/负数，文件自身判 `executed: false` | `02d547e655f7327db0bc6844ad02f9586aef9282be6173c6fdf65a96f8860051` |
| `t7-c1-bruteforce-out.txt` | ⚠️ **判定 oracle 失效导致的无效结论**（25 候选密钥全 `deleteMe=true` → 结论作废）。**文件保留不改** | `e27d26961b48611be36987a57fd749e64aa058dc2dbfaace9e15051be9e596d9` |
| `loop3-t7-c1-shiro-20261012.json` | 四条链结果（含 CC2 `oob_hits: 0` 与 cookie 元数据） | `c08dc7eb74c3d000e9ec42dc728fab6edaf42d5a38dd406d05aee0b5188a49b7` |
| `loop3-t7-c1-logtrace-20261012.json` | 容器日志：反序列化**确实发生**（`ClassResolvingObjectInputStream`） | `0fae78cfe7698e45b5c5ad13c74deddbf10ed2434a0551d24638f3d0841823a5` |
| `loop3-t7-c1-discriminate-20261012.json` | 成功/失败链的区分性实验 | `07bcfa8bffa278c6609d4babf30837d13db9b6da741b04a2778f3b66506fe9a2` |
| `t7-c1-toolchain-out.txt` | classpath 依赖核对原始输出 | `e5c00474c36ad013c62567f613ee85076056037f908ba51fdddaf1fc29cef013` |
| `loop3-t7-recon1-out.txt` | 前置侦察（java / ysoserial / python 库 / 网络） | `9b50bc0bc63148a3e64470e99d7346a3faf0a816c7c0d0a6def61cbcd04945c2` |

**可复跑脚本**（同目录，含 sha256）：
`t7-c1-matrix.py` `35771951de99030843f0586ea3428a982e149bcac7cbf70e8646dd202ed58c36`、
`t7-c1-matrix.rb` `f883e7259757c9ff4f456106dd976a670f3f915b141c94a565096d24d9801e4c`、
`t7-c1-discriminate.py` `fcfc1506ef5bbb883825324ea153493fd29df150144172f59d38ce2a39de4063`、
`t7-c1-discriminate.rb` `a5eb4becce777cd01557bdd6cf974d3f371789fef9ebfd1cf5a650459a8a888c`、
`t7-c1-shiro-gen.rb` `9013779286eaa999776faa24713833b81e93d5c89721566ca93020c385cca59d`、
`t7-c1-shiro-exploit.py` `6c2faf497eb9ed536375ab27c92b638a0fb8c8f61973b7b22d5abf86516aa28a`

### 4.4 与阳性笔记的对照（确保阴性不是漏洞否定）

| 对照项 | 阳性（C1 / CC6） | 阴性（本篇 / CC2） |
|---|---|---|
| 漏洞是否成立 | ✅ **成立（RCE）** | —— **同样成立**（C1 已证） |
| 默认密钥 | ✅ 正确 | ✅ **同样正确**（能解密，magic 正常） |
| 反序列化发生 | ✅ 是 | ✅ **同样是** |
| gadget 触发 | ✅ 是 | ❌ **否** |
| 依赖版本 | collections **3.x** | 需要 collections **4**，环境只有 3.2.1 |

**唯一差异 = classpath 依赖版本**。**漏洞成立与否与本条阴性无关。**

---

## 5. 修复方案：配置层根因 + 升级路径

> 本篇是阴性记录，**修复方案与 C1 一致**（同一个漏洞 CVE-2016-4437），此处只列**本篇阴性结论带来的额外启示**。

### 5.1 配置层根因（同 C1）

| # | 根因 | 修复 |
|---|---|---|
| R1 | `CookieRememberMeManager` **未设自定义密钥**，沿用源码公开默认 `kPH+bIxk5D2deZiIxcaaaA==` | **显式 `setCipherKey()` 配随机密钥**；密钥存密钥管理，不入代码库/镜像 |
| R2 | **反序列化无类型白名单** | **升级 Shiro** + JEP 290 白名单 |

### 5.2 升级路径（同 C1，此处只强调本篇相关的两点）

| 优先级 | 动作 | 本篇关联 |
|---|---|---|
| **P0** | 升级 Shiro 至已修复版本 | **⚠️ 未验证**具体哪个 patch 版本彻底消除默认密钥 —— 查官方 release note 逐版确认 |
| **P1** | **收敛 classpath 依赖** | **本篇的直接启示**：CC2 失败**正是受益于 classpath 里没有 collections 4**。**依赖越少，可打链越少** —— **减少依赖本身就是有效的纵深防御**，不是"顺带的好处" |

---

## 6. 参考链接

- C1 阳性笔记：`security/learning/cve/C1-SHIRO-2016-4437-rememberMe反序列化默认密钥.md`
- ysoserial（链与依赖对应关系）：https://github.com/frohoff/ysoserial
- Apache Shiro 官方仓库：https://github.com/apache/shiro
- JEP 290（反序列化过滤）：https://openjdk.org/jeps/290
- CWE-502：https://cwe.mitre.org/data/definitions/502.html

---

## 7. 学习要点

1. **阴性 ≠ 漏洞否定，必须分清"哪一步失败"。** CC2 失败但**漏洞在 C1 已证明成立**。写"未复现"时**必须写清卡在哪一步、为什么** —— 否则下游会误以为"这个 CVE 打不通"。

2. **打链前先清点 classpath。** CC2 要 collections 4、CC5/CC6 要 3.x —— **同名不同版本，结果天差地别**。先 `dependency:list` 或看容器里的 jar 再决定打哪条链，能省掉整轮试错。

3. **任何"单响应标志判成败"的思路都要先证伪。** `deleteMe` 看起来完美（成功该 false、失败该 true），实测**成功链和失败链全是 `true`**，连错误密钥也是 `true`。**如果当初不跑这个矩阵，就会拿 `deleteMe=true` 判定"打通了" —— 把失败的 CC2 也算成成功。**

4. **⛔ 响应时间同样不能判成败 —— `Runtime.exec()` 是异步的。** 本篇三条链**确实 RCE 成功**，但时序 delta 全是 **−0.002 / +0.008 / −0.003 秒**（详见 §2.3），文件自身都判 `executed: false`。**假 oracle 的真正代价不是"结论不准"，而是"把真漏洞当阴性丢掉"** —— hunter-web 一度据此误判 C1 不成立。

5. **作废结论要写清作废范围，别整篇连坐。** `t7-c1-bruteforce-out.txt` 里"25 个候选密钥全部 `deleteMe=true` → 全部解密失败"因判据无效而作废；**但 C1 漏洞本身不作废**（靠 OOB + `/proc` 独立实证成功）。**说清"哪部分作废、哪部分不受影响"，否则下一个人会连正确的结论一起丢掉。**

4. **依赖收敛是有实效的防御，不是理论最优解。** 本篇 CC2 失败**不是因为打了补丁，是因为那个库压根不在**。真实环境精简依赖能直接消灭整条攻击面。

5. **阴性笔记必须配"能成对照"。** 本篇把 CC6（成功）作为对照列出，**同一环境、同一密钥、同一路径，只有依赖不同** —— 这样才证明失败是**依赖导致**，而不是"我方法不对"。

6. **CVE 复现笔记 ≠ 原创漏洞报告。** 同 C1，本篇练的是**复现路径的边界认知**，不是拿去当赏金提交。

7. **⚠️ 工具缺陷会静默污染数据：`kali-run.py` 会在 stdout 末尾追加 `{"rc":...,"stdout_len":...}`。** 若下游脚本「取第一行」而目标输出**不带换行**，这段 JSON 会被拼进数据。**铁证**（混进了 shiro 容器日志）：

   ```
   A cookie header was received [rc": 0, "stdout_len": 3884, "stderr_len": 0}] that contained an invalid cookie
   ```

   **规避**：按目标格式（如 base64 字符集）正则取**最长串**，或用 `kali-fetch-bin.py` 取二进制。**本条卡了 hunter-web 约 15 分钟，且会把排查方向带偏。**

---

## 8. 引用存在性自检（可复跑）

本篇引用的全部证据文件均已核对存在性，**missing = 0**。

**自检命令**（在 `security/learning/_evidence` 目录下执行）：

```powershell
# 核对本篇引用的证据文件是否全部存在于 _evidence 目录
$files = @(
  'loop3-t7-c1-matrix-20261012.json','loop3-t7-c1-timing-20261012.json','t7-c1-bruteforce-out.txt',
  'loop3-t7-c1-shiro-20261012.json',
  'loop3-t7-c1-logtrace-20261012.json','loop3-t7-c1-discriminate-20261012.json',
  't7-c1-toolchain-out.txt','loop3-t7-recon1-out.txt',
  't7-c1-matrix.py','t7-c1-matrix.rb','t7-c1-discriminate.py','t7-c1-discriminate.rb',
  't7-c1-shiro-gen.rb','t7-c1-shiro-exploit.py'
)
$miss = @($files | Where-Object { -not (Test-Path -LiteralPath $_) })
"total={0}  missing={1}" -f $files.Count, $miss.Count
```

**期望输出**：`total=14  missing=0`