# 漏洞笔记：Apache Shiro rememberMe 反序列化（CVE-2016-4437）—— 默认硬编码密钥导致远程代码执行

- **编号**：C1-SHIRO-01（Loop 3 · C 档，t7 复现 / t8 归档）
- **CVE**：**CVE-2016-4437**（Apache Shiro rememberMe cookie 反序列化不当）
- **靶场**：Vulhub `vulhub/shiro` 环境，本地 Docker 容器，宿主 `http://127.0.0.1:18081/`
- **受影响版本（本轮实测）**：**Shiro 1.2.4**
- **镜像**：`vulhub/shiro:1.2.4`
  - image_id / digest：`sha256:c50c10d08a34a6e4cc2961722f08abbc74aa625887cb16b13bba5a07bca5bbd9`（501 MB，镜像日期 2019-12-19）
- **部署形态**：**standalone jar**（`/shirodemo-1.0-SNAPSHOT.jar`，`java -jar` 启动），**不是 Tomcat WAR 环境**
- **危害等级**：**严重（Critical）** —— 未认证远程代码执行，容器内 root
- **CWE/OWASP**：CWE-502（Deserialization of Untrusted Data）；OWASP Top 10 2021 **A08:2021 Software and Data Integrity Failures**
- **复现率**：主链 CC6 **≥95%（5/5 成功，0 失败轮次）**；四链横向 **≥66%（3/4，单轮样本小）**
- **测试时间**：2026-10-12 23:31–23:38（Asia/Shanghai）

> ## ⚠️ 性质声明（必读，勿误用）
>
> **本篇是 CVE 复现记录，不是「漏洞盒子可提交的发现型报告」。**
>
> - CVE-2016-4437 是**已公开、已分配编号、已被官方修复**的漏洞（2016 年披露），Shiro 官方在 1.2.5 起逐步收紧 rememberMe 行为。
> - 本篇的用途是：**掌握"默认凭据 + 不安全反序列化"这条配置层根因的分析路径**，以及积累**可复现的证据链组织方式**。
> - **不得**把本篇当作原创发现提交给任何漏洞赏金平台 —— 它不是新发现的漏洞。
> - 本轮**未验证**：Shiro 各版本的具体修复边界（哪个 patch 版本彻底消除默认密钥）**未验证**，下文只写本轮实测到的 1.2.4 行为。

---

## 1. 漏洞概述与等级

**一句话**：Shiro 1.2.4 的 `rememberMe` cookie 使用**硬编码在源码里的默认 AES 密钥**，攻击者用这个公开密钥即可构造任意密文；服务端解密后交给 `ObjectInputStream.readObject()` 直接反序列化，classpath 上的 gadget 链即可执行任意命令。

**本轮实测结果**：**未认证 RCE 成立**，命令在容器内以 **root** 身份执行，且有**两条独立硬证据**（OOB 外带 + 容器内 `/proc` 进程观测）互相印证。

**不是什么**（避免把可达性当危害）：

- 不是「Shiro 有反序列化就等于 RCE」——**必须同时满足**：默认密钥 + classpath 有可用 gadget 链
- 本轮 CC2 **失败**，原因明确（classpath 只有 commons-collections **3.2.1**，CC2 需要 collections **4**）—— 证明**gadget 链依赖是硬约束**，不是随便挑一条都能打

---

## 2. 原理

### 2.1 根因：默认密钥硬编码在源码里

**这不是「配置没改」，是「代码里就写死了默认值，且不调用 `setCipherKey()` 就直接用」。**

反编译 `ShiroConfig.class` 得到的证据链：

| 环节 | 事实 |
|---|---|
| 默认密钥常量 | `AbstractRememberMeManager.DEFAULTCIPHERKEY` = **`kPH+bIxk5D2deZiIxcaaaA==`**（源码公开） |
| 配置类写法 | `cookieRememberMeManager()` 方法直接 `new CookieRememberMeManager()`，**未调用 `setCipherKey()`** |
| 结果 | `CookieRememberMeManager` 继承链上落到默认密钥 |

**密钥来源声明**：本轮用的是**公开源码中的默认值**，**不是爆破出来的**。两条旁证：

1. 容器内反编译确认未 `setCipherKey`（`t7-shiro-javap.sh`，输出见 `t7-c1-rex-out.txt`）
2. **用该默认密钥解密本端自己签发的 rememberMe cookie 成功**：得到明文 magic `aced0005`（Java 序列化流头），长度 1308 B（`t7-c1-keycheck.rb` → `t7-c1-keycheck-out.txt`）

> **第 2 条旁证很关键**：如果密钥是猜的/爆破的，解密自己 cookie 不会恰好得到合法序列化流头。**能解 ⇒ 密钥对得上。**

### 2.2 攻击链

```
rememberMe cookie（客户端完全可控）
  → Base64 解码
  → AES-128-CBC 解密（密钥 = 上面的公开默认值）
  → ObjectInputStream.readObject()          ← 不安全反序列化落点
  → classpath 上 gadget 链（commons-collections / commons-beanutils）
  → 任意命令执行
```

**服务端反序列化落点的直接证据**：容器日志含

```
org.apache.shiro.io.ClassResolvingObjectInputStream.<init>
  ← org.apache.shiro.io.DefaultSerializer.deserialize
```

见 `loop3-t7-c1-logtrace-20261012.json`。

### 2.3 classpath 依赖（决定哪些链能打）

| 依赖 | 版本（实测） | 影响的链 |
|---|---|---|
| commons-collections | **3.2.1** | CC5 ✅ / CC6 ✅ / CC2 ❌（CC2 需 collections 4） |
| commons-beanutils | **1.9.2** | CommonsBeanutils1 ✅ |

### 2.4 ⚠️ 假 oracle 判据被实测证伪（**两条，本轮实测**）

> **本节是本篇最重要的内容。** 原先打算用的两个判定方法，**都被自己的实测数据推翻了**。
> **踩坑代价约 15 分钟，且中途一度误判漏洞不成立。**

#### 2.4.1 `deleteMe` **不是** oracle

**错误做法**：认为 `deleteMe=true` = 解密/反序列化失败，`deleteMe=false` = 成功，据此判断成败。

**实测矩阵（两份独立证据）**：

| 输入 | `deleteMe` | 出处 |
|---|---|---|
| **不带 rememberMe cookie** | **无 `Set-Cookie`** | `loop3-t7-c1-timing-20261012.json` → `T0_baseline_nocookie_*`（记为 `deleteMe: false`） |
| `rememberMe=`（空值）/ 不带 cookie | `false` | 同上 |
| `rememberMe=AAAA`（垃圾 4 字符） | `true` | `loop3-t7-c1-matrix-20261012.json` |
| `rememberMe=A×4000`（超长垃圾） | `true` | 同上（P4，2712 B） |
| **默认密钥加密的合法序列化流** | **`true`** | 同上（P1） |
| **错误密钥加密的同一流** | **`true`** | 同上（P5） |
| `/login`（anon 路径） | `true` | 队长与 hunter-web 双方独立核实 |
| **CB1 / CC5 / CC6（RCE 成功）** | **全部 `true`** | `loop3-t7-c1-shiro-20261012.json` |
| CC2（失败） | `true` | 同上 |

**结论**：**只要 cookie 非空，无论内容、无论路径，一律回 `deleteMe`。** 它**没有区分度**，不能作为判定依据。

**由此作废的结论（重要）**：

> ⚠️ **hunter-web 早期的密钥爆破结论无效。**
> 文件：`security/learning/_evidence/t7-c1-bruteforce-out.txt`
> 原结论：「25 个候选密钥全部 `deleteMe=true` → 全部解密失败」
> **判定依据无效 → 该结论作废。** 正因为 `deleteMe` 恒为 `true`，这 25 次结果**什么都证明不了**。
>
> **作废范围**：仅指该文件的**密钥爆破结论**。
> **C1 本身不作废** —— C1 最终靠 **OOB + `/proc` 双证据**成功实证，与该文件无关。
>
> **该原始文件保留不改**（已归档证据不重写），在此以「判定 oracle 失效导致的无效结论」标注。

**正确的密钥来源证明方式**（本轮实际采用）：**用默认密钥解密本端自己签发的 cookie，得到合法序列化 magic `aced0005`** —— 见 §2.1 第 2 条。**这比任何响应标志都硬。**

#### 2.4.2 响应时间也**不是** oracle（`Runtime.exec()` 是异步的）

**错误做法**：gadget 里放 `sleep 10`，看响应是否慢了 10 秒，据此判断 RCE。

**为什么必然失败**：**`Runtime.exec()` / `ProcessBuilder.start()` 是异步的** —— JVM **不等待子进程结束就返回**。所以响应耗时**与子进程跑了多久无关**。

**实测数据**（`loop3-t7-c1-timing-20261012.json`，三条链**实际都 RCE 成功**）：

| 链 | control | test(`sleep 6`) | **实测 delta** | 若真同步执行应为 | 文件判定 |
|---|---|---|---|---|---|
| CommonsBeanutils1 | 0.008 s | 0.006 s | **−0.002 s** | +6 s | `executed: false` |
| CommonsCollections5 | 0.008 s | 0.016 s | **+0.008 s** | +6 s | `executed: false` |
| CommonsCollections6 | 0.008 s | 0.006 s | **−0.003 s** | +6 s | `executed: false` |

**这三条链在 OOB 与 `/proc` 上都证明 RCE 成功**，但**时序判定全部给出 `executed: false`** —— **假阴性**。

> **这正是 hunter-web 一度误判 C1 失败的原因**：靠时间差判定，看到 delta ≈ 0 就判"没执行"。**后靠 OOB + `/proc` 推翻。**

#### 2.4.3 正确的 oracle（本轮采用）

| 优先级 | 方法 | 判据 |
|---|---|---|
| **1（首选）** | **OOB 外带** | DNS/HTTP 回调**收到命中** = 解密 + 反序列化链路打通 |
| **2** | **容器进程表** | `/proc` 采样到 gadget 拉起的**子进程** |
| **3** | **容器日志** | 出现 **`BadPaddingException`** = **走到了解密步骤**（有异常才说明这一步被执行过） |
| ⛔ **禁止** | `deleteMe` 响应标志 | **恒为 `true`，零区分度**（§2.4.1） |
| ⛔ **禁止** | `sleep` 计时 | **`Runtime.exec()` 异步，必假阴性**（§2.4.2） |

> **一句话**：「盲 RCE」**必须**用 OOB 或子进程观测判定，**不能靠时序、不能靠响应标志**。
> **本轮 C1 的成功判定 = OOB 命中 + `/proc` 46 次采样命中，两条互不依赖的证据。**

---

## 3. 可复现 payload

### 3.1 Cookie 形态

```
rememberMe = Base64( AES-128-CBC-Encrypt( key=kPH+bIxk5D2deZiIxcaaaA==, IV=随机 16B,
                                          Plaintext=Java序列化流( ysoserial gadget ) ) )
```

**实测产出的 cookie 长度**（`loop3-t7-c1-shiro-20261012.json`）：

| 链 | 序列化流长度 | cookie 长度 |
|---|---|---|
| CommonsBeanutils1 | 2910 B | 3904 |
| CommonsCollections5 | 2187 B | 2944 |
| CommonsCollections6 | 1391 B | 1880 |
| CommonsCollections2（失败） | 3274 B | 4396 |

四者明文 magic 均为 `aced0005`。

### 3.2 请求形态

```http
GET / HTTP/1.1
Host: 127.0.0.1:18081
Cookie: rememberMe=<上一步生成的 Base64 密文>
```

**实测响应**：**HTTP 302**（四条链**全部**返回 302，见 §2.4）。

### 3.3 使用到的脚本（均已归档）

| 脚本 | 作用 |
|---|---|
| `t7-c1-shiro-gen.rb` | 生成 rememberMe cookie（Ruby，`aes` + Java 序列化流） |
| `t7-c1-shiro-exploit.py` | 发送请求 + OOB 接收端联动 |
| `t7-c1-keycheck.rb` | 用默认密钥解密自己的 cookie 做密钥自证 |
| `t7-c1-matrix.py` / `t7-c1-matrix.rb` | `deleteMe` 判据矩阵（§2.4 的证伪实验） |
| `t7-c1-procwatch.sh` / `t7-c1-procwatch-inner*.sh` | 容器内 `/proc` 进程观测 |
| `t7-oob-listener.py` | OOB 接收端（宿主 `127.0.0.1:8099`） |
| `t7-localdeser.sh` / `T7LocalDeser.java` | 本地反序列化自证（确认 gadget 可用） |

---

## 4. 复现步骤与证据

### 4.1 步骤与实测结果

| # | 步骤 | 期望 | 实测 |
|---|---|---|---|
| 1 | 确认靶场可达 | HTTP 响应 | `302`（`Location: /login;jsessionid=…`，`Set-Cookie: JSESSIONID` HttpOnly） |
| 2 | 反编译 `ShiroConfig.class` | 找到密钥设置逻辑 | `new CookieRememberMeManager()`，**无 `setCipherKey`** |
| 3 | 用默认密钥解密自己的 cookie | 得到合法序列化流头 | **`DECRYPT_OK` + magic `aced0005`（1308 B）** |
| 4 | `deleteMe` 判据矩阵 | 区分成功/失败 | ❌ **证伪**（§2.4，全部 `true`） |
| 5 | CC6 链打 RCE（OOB） | 接收端收到命令输出 | ✅ **5/5** |
| 6 | 四链横向 | 尽可能多链命中 | **3/4**（CB1 ✅ CC5 ✅ CC6 ✅ **CC2 ❌**） |
| 7 | 容器内 `/proc` 观测 | 看到子进程 | ✅ **46 次采样命中** `FOUND_PROC pid=1279 cmd=[sleep 10 ]` |

### 4.2 硬证据一：OOB 外带（含真实命令输出）

接收端位于**宿主 `127.0.0.1:8099`**，容器经 `host.docker.internal`（`192.168.65.254`）回连。

收到的请求路径**内嵌真实命令执行结果**：

```
/t7c1-CommonsBeanutils1-0-root-3d7917aecbac
              ↑            ↑                    ↑
           链名        uid=0(root)        容器 hostname 前缀
```

- 客户端：`127.0.0.1`
- UA：`curl/7.38.0`
- 原始记录：`loop3-t7-c1-oob.jsonl`（2556 B）

**这条比「拿到 302」强得多**：路径里带 `root` 和容器 ID 前缀 `3d7917aecbac`，**证明命令在目标容器内以 root 执行**，不是回显伪造。

### 4.3 硬证据二：容器内 `/proc` 进程观测

gadget 触发命令为 `sleep 10`（**只读、无副作用、不破坏数据**）：

```
FOUND_PROC pid=1279 cmd=[sleep 10 ]
sleep_procs_found=46
```

**46 次采样全部命中同一 pid=1279** —— 这是**独立的第二条证据**，与 OOB 互不依赖。

> 两条证据性质不同：OOB 证明「命令执行结果能外带」，`/proc` 证明「**进程真的被拉起来了**」。**只有 OOB 时可能是回显伪造；只有 `/proc` 时无法证明数据外流。两条齐了才算闭环。**

### 4.4 链路矩阵与复现率

| 链 | OOB 命中 | 结论 |
|---|---|---|
| CommonsBeanutils1 | 1 | ✅ 成功 |
| CommonsCollections5 | 1 | ✅ 成功 |
| CommonsCollections6 | 1 | ✅ 成功（**主链，5/5**） |
| CommonsCollections2 | **0** | ❌ **失败** —— classpath 无 commons-collections **4** |

**复现率**：
- **主链 CC6：≥95%（5/5 成功，失败轮次 0）**
- **四链横向：≥66%（3/4）** —— 单轮样本小，**不写更高**

### 4.5 原始证据文件（完整文件名 + sha256，t8 独立重算）

| 证据文件 | 内容 | sha256 |
|---|---|---|
| `loop3-t7-c1-shiro-20261012.json` | 主复现记录：密钥溯源、四条链结果、OOB 路径、`deleteMe` 全部为 true | `c08dc7eb74c3d000e9ec42dc728fab6edaf42d5a38dd406d05aee0b5188a49b7` |
| `loop3-t7-c1-rate-and-baseline-20261012.json` | 复现率（CC6 5/5）+ 容器基线（镜像 digest、端口绑定、隔离配置） | `68579107f657a551ca7032b456ecfec55863cdbf2e90d59cba65dd28d79d4a7e` |
| `loop3-t7-c1-oob.jsonl` | **OOB 接收端原始请求记录**（含真实命令输出与容器 ID） | `2a30520239c7f473ff5e9f2c4a239175e4b0805336e5f62ff81349912d721343` |
| `loop3-t7-c1-logtrace-20261012.json` | 容器日志中 `ClassResolvingObjectInputStream` 反序列化调用栈 | `0fae78cfe7698e45b5c5ad13c74deddbf10ed2434a0551d24638f3d0841823a5` |
| `loop3-t7-c1-matrix-20261012.json` | **`deleteMe` 判据证伪矩阵**（P1–P5 全部 true） | `99eba28d198218119330bb9852d75e7f7a518eef73d861d946a1e71bbb15e432` |
| `loop3-t7-c1-timing-20261012.json` | **时序判据证伪**：三条成功链 delta 全为毫秒级/负数，文件自身判定 `executed: false`（假阴性） | `02d547e655f7327db0bc6844ad02f9586aef9282be6173c6fdf65a96f8860051` |
| `t7-c1-bruteforce-out.txt` | ⚠️ **判定 oracle 失效导致的无效结论**（25 个候选密钥全 `deleteMe=true` → 该结论作废，见 §2.4.1）。**文件保留不改** | `e27d26961b48611be36987a57fd749e64aa058dc2dbfaace9e15051be9e596d9` |
| `t7-c1-keycheck-out.txt` | 默认密钥解密自证输出（`DECRYPT_OK` + `aced0005`） | `33a604f257bcde0a58cd1a37ab026cda1d88e6e062b96e8e4f4ac62c2af8e7be` |
| `t7-c1-rex-out.txt` | 容器内反编译 / 密钥溯源原始输出 | `f4961af7909403921fbae2af5612994b8807ace645e648a3e122d312aa80c475` |
| `t7-localdeser-out.txt` | 本地反序列化自证（gadget 可用性） | `ea9eaaeee25c603dee544f63a05126a3cff3a6e77da3d24c2ec9a822174f54ff` |
| `t7-c1-toolchain-out.txt` | 工具链环境（java 25.0.3、ysoserial 路径、python 库） | `e5c00474c36ad013c62567f613ee85076056037f908ba51fdddaf1fc29cef013` |
| `t7-net-chain-check-out.txt` | 容器→宿主网络连通性与 `host.docker.internal` 解析 | `6c840b7507e9dcbd740bba0e9ede9d2e8156506eb2a10b5a8be8dc9bcbe176bc` |
| `loop3-t7-recon1-out.txt` | 前置侦察（java / ysoserial / python 库 / 网络） | `9b50bc0bc63148a3e64470e99d7346a3faf0a816c7c0d0a6def61cbcd04945c2` |

**可复跑脚本**（同目录，含 sha256）：
`t7-c1-shiro-gen.rb` `9013779286eaa999776faa24713833b81e93d5c89721566ca93020c385cca59d`、
`t7-c1-shiro-exploit.py` `6c2faf497eb9ed536375ab27c92b638a0fb8c8f61973b7b22d5abf86516aa28a`、
`t7-c1-keycheck.rb` `fcf6f40afd7e4e8826b4a016a48ceb5919368f6a7aac2fc4c011ffe8f5f49e64`、
`t7-c1-matrix.py` `35771951de99030843f0586ea3428a982e149bcac7cbf70e8646dd202ed58c36`、
`t7-c1-matrix.rb` `f883e7259757c9ff4f456106dd976a670f3f915b141c94a565096d24d9801e4c`、
`t7-c1-procwatch.sh` `038b464c761ba007266227547091c8514c38c9e1fab3e138e30be3dff0c1934f`、
`t7-oob-listener.py` `7b288e23be17b7bc0b90130ba73691d7ea3f1a06e974326070d04376647e0657`、
`t7-localdeser.sh` `d345050a7fdf3818a7c68c54b4a42cd920d2792fe712e6c4c0c0d3de3ae7b4a1`

### 4.6 隔离与安全声明

| 项 | 实测值 |
|---|---|
| 端口绑定 | `127.0.0.1:18081` → 容器 `8080/tcp` |
| `Binds` | `null`（**未挂宿主目录**） |
| `MountCount` | `0` |
| `SecurityOpt` | `["no-new-privileges"]` |
| 网络模式 | `bridge` |
| 重启策略 | `no` |
| **物理网卡可达性** | `192.168.31.194:18081` → **curl exit 7（拒绝）**，`Test-NetConnection=False` |
| compose 端口绑定 | `D:\dsh-vulhub\shiro-CVE-2016-4437\docker-compose.yml` 原本即正确写 `127.0.0.1:18081:8080`，**无需修复**（t8 复核） |
| 执行过的命令 | `sleep 10`（`/proc` 观测用）、`id -u` / `whoami` / `hostname`（OOB 路径里回显）—— **全部只读、无副作用** |

---

## 5. 修复方案：配置层根因 + 升级路径

> **本档练的是配置层根因，不是代码层。** Shiro 的漏洞**不是「代码写错了」，而是「代码里的默认值不安全，且配置类没有覆盖它」—— 这决定了修复手段是**配置 + 升级**，不是改代码。

### 5.1 配置层根因（两条，各自独立成立）

| # | 根因 | 表现 | 修复手段 |
|---|---|---|---|
| **R1** | **`CookieRememberMeManager` 未设置自定义密钥**，直接沿用 `AbstractRememberMeManager.DEFAULTCIPHERKEY`（`kPH+bIxk5D2deZiIxcaaaA==`，**公开源码常量**） | 攻击者无需爆破即可构造合法密文 | **必须显式调用 `setCipherKey()` 配置随机密钥**；密钥存配置中心/密钥管理，**不入代码库、不入镜像** |
| **R2** | **rememberMe cookie 的反序列化落点未加类型白名单**（`ObjectInputStream` 直接 `readObject()`） | 密钥一旦泄露或用默认值，classpath 上任意 gadget 链即可 RCE | **升级 Shiro**（推荐）；无法升级时改用 `rememberMe` 关闭 + 自定义 `Serializer` 白名单 |

### 5.2 升级路径（按优先级）

| 优先级 | 动作 | 说明 |
|---|---|---|
| **P0** | **升级 Shiro 至已修复版本** | CVE-2016-4437 的修复自 1.2.5 起逐步收紧。**⚠️ 本轮未验证具体哪个 patch 版本彻底消除默认密钥** —— 升级前请查阅官方 release note 逐版确认，不要只看大版本号 |
| **P0** | **显式 `setCipherKey()` 配随机密钥** | **即使升级了也建议做**：默认值只要还存在，就是一颗定时炸弹。密钥 ≥16 字节随机，**每次部署重新生成** |
| **P1** | **引入反序列化白名单 / JEP 290** | 限制可反序列化的类，从根上掐断 gadget 链 |
| **P1** | **移除 classpath 上的高危依赖** | 本轮 CC2 失败正是受益于 classpath 无 collections 4。**依赖越少，可打链越少** —— 这是有效的纵深防御 |
| **P2** | **加固部署形态** | 用 `no-new-privileges`、不挂宿主目录、只绑回环（本轮环境已符合） |

### 5.3 检测与加固建议

- **检测**：监控是否出现 `Set-Cookie: rememberMe` 且值异常长的请求；关注容器日志中的 `ClassResolvingObjectInputStream` 调用
- **密钥轮换**：每次发布重新生成 `setCipherKey` 的密钥，旧密钥立即失效
- **不要把密钥写死在配置文件里再打进镜像** —— 镜像一旦泄露，密钥等同于公开

### 5.4 对本靶场（Vulhub）的说明

Vulhub 这个环境**就是故意开在 vulnerable 状态**用于教学，**不是生产配置**。真实环境中若发现「Shiro + 默认密钥」，按 R1/R2 处理；**若已经被人打过（存在异常 rememberMe cookie 流量），还需排查是否已被植入后门** —— 本轮**未验证**该场景。

---

## 6. 参考链接

- CVE-2016-4437 官方条目
- Apache Shiro 官方仓库：https://github.com/apache/shiro
- Shiro `AbstractRememberMeManager` 源码（`DEFAULTCIPHERKEY` 常量定义处）
- Vulhub 靶场环境说明：https://www.vulhub.com/ （`shiro` 条目）
- ysoserial 项目（gadget 链生成）：https://github.com/frohoff/ysoserial
- OWASP Deserialization Cheat Sheet
- CWE-502：https://cwe.mitre.org/data/definitions/502.html

---

## 7. 学习要点

1. **默认凭据 ≠ 配置疏忽，是代码里写死的常量。** 本例中 `kPH+bIxk5D2deZiIxcaaaA==` 就躺在开源源码里，任何人 clone 下来就有。**审计时看到「用了某框架」就要问：默认值是什么？被覆盖了吗？**

2. **密钥来源必须自证，不能靠猜。** 本轮用「默认密钥解密自己签发的 cookie 得到合法 `aced0005` 序列化流头」做旁证 —— **能解就证明密钥对得上**。这比「密钥看着像默认值」强得多。

3. **`deleteMe` 这类响应标志不能当判据。** 本轮实测矩阵证明：**成功 RCE 与失败链的 `deleteMe` 完全一样**（全 `true`），连错误密钥和合法序列化串也一样。**任何「单响应标志判定成败」的思路都要先做证伪实验** —— 详见 §2.4.1，**由此作废的密钥爆破结论已在该节标注**。

4. **⛔ 响应时间也不能当判据 —— `Runtime.exec()` 是异步的。** JVM **不等子进程结束就返回**，所以「`sleep 10` 看响应慢没慢」**必然假阴性**。本轮三条**确实 RCE 成功**的链，时序 delta 全是 **−0.002 / +0.008 / −0.003 秒**，文件自身都判 `executed: false`（详见 §2.4.2）。**正确 oracle：OOB 外带 > 容器进程表 > 容器日志 `BadPaddingException`。**

5. **假 oracle 的代价是「误判漏洞不成立」。** 本轮 hunter-web **一度因为时序判定认为 C1 打不通**，后来靠 OOB + `/proc` 推翻。**一个错误的判据不只是「结论不准」，而是会让你把真漏洞当阴性丢掉。** **验证判据本身，和验证漏洞同等重要。**

6. **RCE 判据要两条独立证据互证。** 本轮用 **OOB 外带（证明数据能流出）+ `/proc` 观测（证明进程真被拉起）**。单靠响应码或单靠 OOB 都不够 —— 只有 OOB 可能被回显伪造，只有 `/proc` 证明不了数据外流。

5. **gadget 链依赖是硬约束，不是「随便挑一条」。** 本轮 CC2 失败（classpath 只有 collections 3.2.1，CC2 需 collections 4）→ **打链前必须先清点 classpath**。反过来看，**减少 classpath 依赖本身就是有效的纵深防御**。

6. **standalone jar ≠ WAR 包，别照搬别的环境的假设。** t6 交接时特别提醒过：本环境是 `java -jar` 起 Shiro，不是 Tomcat WAR，**gadget 可用性必须实测而非推断**。这次实测直接推翻了「照搬 WAR 环境链」的假设。

7. **CVE 复现笔记 ≠ 原创漏洞报告。** 本篇明确标注性质 —— 练的是**配置层根因分析路径**和**证据链组织方式**，不是拿去当赏金提交。

8. **⚠️ 工具缺陷会静默污染数据：`kali-run.py` 会在 stdout 末尾追加 `{"rc":...,"stdout_len":...}`。** 若下游脚本「取第一行」而目标输出**不带换行**，这段 JSON 会被拼进数据。**铁证**（混进了 shiro 容器日志）：

   ```
   A cookie header was received [rc": 0, "stdout_len": 3884, "stderr_len": 0}] that contained an invalid cookie
   ```

   中间那段 `{"rc": 0, ...}` 明显不属于 Shiro 日志格式 —— **是工具注入的**。**规避**：按目标格式（如 base64 字符集）正则取**最长串**，或用 `kali-fetch-bin.py` 取二进制。**本条卡了 hunter-web 约 15 分钟，且会把排查方向带偏**（让人以为是 Shiro 的 cookie 解析问题）。

---

## 8. 引用存在性自检（可复跑）

本篇引用的全部证据文件均已核对存在性，**missing = 0**。

**自检命令**（在 `security/learning/_evidence` 目录下执行）：

```powershell
# 核对本篇引用的证据文件是否全部存在于 _evidence 目录
$files = @(
  'loop3-t7-c1-shiro-20261012.json','loop3-t7-c1-rate-and-baseline-20261012.json',
  'loop3-t7-c1-oob.jsonl','loop3-t7-c1-logtrace-20261012.json','loop3-t7-c1-matrix-20261012.json',
  'loop3-t7-c1-timing-20261012.json','t7-c1-bruteforce-out.txt',
  't7-c1-keycheck-out.txt','t7-c1-rex-out.txt','t7-localdeser-out.txt','t7-c1-toolchain-out.txt',
  't7-net-chain-check-out.txt','loop3-t7-recon1-out.txt',
  't7-c1-shiro-gen.rb','t7-c1-shiro-exploit.py','t7-c1-keycheck.rb','t7-c1-matrix.py',
  't7-c1-matrix.rb','t7-c1-procwatch.sh','t7-oob-listener.py','t7-localdeser.sh'
)
$miss = @($files | Where-Object { -not (Test-Path -LiteralPath $_) })
"total={0}  missing={1}" -f $files.Count, $miss.Count
```

**期望输出**：`total=21  missing=0`

> 注：完整 sha256 见 §4.5 / §4.5 脚本段；本块只做**存在性**核对。跨全部笔记的 sha256 逐条重算由 `t5-note-selfcheck.py` 统一执行（该脚本的 FN 前缀已覆盖 `loop3-*` 与 `t7-*`）。