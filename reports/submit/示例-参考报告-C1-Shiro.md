# 示例 · 参考报告（C1 Shiro 改写成漏洞盒子提交版口径）

> ## ⚠️ 性质声明 —— 读之前先看这一段
>
> **本文件是「文风与证据组织方式」的示范样本，不是可投稿的报告。**
>
> - **不可直接投稿漏洞盒子、不可投任何赏金平台。**
> - 素材是 loop3 的 **CVE-2016-4437 复现记录**（Apache Shiro rememberMe 反序列化）。
>   该 CVE **2016 年已公开、已分配编号、已官方修复**，**不是原创发现**。
> - 本文件示范的东西只有两样：
>   ① **白帽文风**——根因怎么写、证据怎么组织、被推翻的结论怎么交代；
>   ② **证据组织方式**——密钥来源怎么自证、判据怎么交叉、阴性怎么留。
> - **它示范的不是漏洞本身**。真要投稿，参照模板 §0.3：还差「陌生目标独立定位」
>   「该目标自身业务根因」「核查非重复」三样。
>
> 配套：`漏洞盒子报告模板-提交版.md` v2 §1 / §1.1 / §7 / §8；`提交前自查清单.md`。
> 素材源：`security/learning/cve/C1-SHIRO-2016-4437-rememberMe反序列化默认密钥.md`
> sha256 `625b312fc14c07e4551508b39a6250f3fa34baf70ffa55523514a2172df3d89b`

---

## 一、示范报告正文（纯文本，可直接整段复制去对照改写）

> 下面这块**刻意不加 markdown 符号**，就是提交框里该有的样子。
> 【】已全部填成真实实测值；示范时**保留这些值**是为了让你看清"具体值填进去长什么样"。

```
Apache Shiro rememberMe cookie 反序列化导致未授权远程代码执行

漏洞类型：反序列化导致远程代码执行（CWE-502）
风险等级：不适用（本篇为 CVE 复现记录，非可提交报告，见文首性质声明）
影响资产：本地靶场 http://127.0.0.1:18081/ ，rememberMe cookie
测试环境：Shiro 1.2.4（vulhub/shiro:1.2.4 镜像，standalone jar 部署，非 Tomcat WAR），
          本机 Docker 容器 3d7917aecbac，JVM 1.8.0_102 / Debian 8，未登录状态

性质声明：
CVE-2016-4437 是 2016 年已公开、已分配编号、已官方修复的漏洞。本篇是复现记录，
不是漏洞盒子可提交的发现型报告，不得当作原创发现提交给任何赏金平台。
本轮未验证：Shiro 各版本的具体修复边界（哪个 patch 版本彻底消除默认密钥）未验证，
下文只写本轮实测到的 1.2.4 行为。

漏洞简述：
测 Shiro 的"记住我"功能时发现，rememberMe cookie 用的是硬编码在源码里的默认
AES 密钥，攻击者拿这个公开密钥就能构造任意密文。服务端把 cookie 解密后直接丢给
ObjectInputStream.readObject() 反序列化，classpath 上只要有可用的 gadget 链就是未授权
RCE。这不是"配置没改"，是"代码里就写死了默认值，且不调用 setCipherKey() 就直接用"。

不是什么（避免把可达性当危害）：
不是"Shiro 有反序列化就等于 RCE"。必须同时满足默认密钥 + classpath 有可用 gadget 链。
本轮 CC2 链失败，原因明确：classpath 只有 commons-collections 3.2.1，CC2 需要
collections 4。这条失败恰好证明 gadget 链依赖是硬约束，不是随便挑一条都能打。

密钥/凭据来源：
公开源码常量 AbstractRememberMeManager.DEFAULTCIPHERKEY = kPH+bIxk5D2deZiIxcaaaA==。
不是爆破出来的。反编译容器内 ShiroConfig.class，cookieRememberMeManager() 方法直接
new CookieRememberMeManager()，未调用 setCipherKey()，所以继承链上落到默认密钥。

来源自证：
用这个默认密钥解密本端自己签发的 rememberMe cookie，成功了，明文 magic 是
aced0005（Java 序列化流头），长度 1308 B。
第 2 条旁证很关键：如果密钥是猜的/爆破的，解密自己 cookie 不会恰好得到合法序列化流头。
能解 ⇒ 密钥对得上。

复现过程：
1. 确认靶场可达，GET / 返回 302，Location 是 /login;jsessionid=…，Set-Cookie 里 JSESSIONID
   带 HttpOnly。
2. 构造 rememberMe cookie：明文是 Java 序列化流（ysoserial gadget 模板 + 注入的命令），
   用上面那个默认密钥做 AES-128-CBC 加密，IV 随机 16 字节前置，再 Base64。
   本轮实测 cookie 长度：CB1 3904、CC5 2944、CC6 1880，四者明文 magic 都是 aced0005。
3. 投递。GET / HTTP/1.1，Host: 127.0.0.1:18081，Cookie: rememberMe=<上一步的 Base64 密文>。
   实测响应 HTTP 302。
4. 看接收端。OOB 接收端绑在宿主 127.0.0.1:8099，容器经 host.docker.internal 回连，
   收到的请求路径内嵌真实命令执行结果。
5. 换链路重复。CB1、CC5、CC6 三条链都命中，CC2 没命中。主链 CC6 做了 5 次，5 次全中。

请求包：
GET / HTTP/1.1
Host: 127.0.0.1:18081
Cookie: rememberMe=<base64(IV||AES-CBC(序列化 gadget 流))>
User-Agent: loop3-t7/1.0 (authorized local lab)

响应包（关键部分）：
响应行是 HTTP/1.1 302，跳 /login。这一条不算证据，见下面"判定依据"。
真正证明命令执行的是接收端的原始记录：
  PATH: /t7c1-CommonsBeanutils1-0-root-3d7917aecbac    CLIENT: 127.0.0.1
  PATH: /t7c1-CommonsCollections5-0-root-3d7917aecbac   CLIENT: 127.0.0.1
  PATH: /t7c1-CommonsCollections6-0-root-3d7917aecbac   CLIENT: 127.0.0.1
路径里的 0 是 id -u，root 是 whoami，3d7917aecbac 是容器 hostname 前缀。
这比"拿到 302"强得多：路径内容只能由容器内被执行的 shell 生成。

判定依据（成功与否）：
先说结论：本轮用的是 OOB 外带 + 主机进程表，两条互不依赖的证据。
OOB 外带命中 3/4 条链，路径里带 uid=0(root) 和容器 ID 前缀。
主机进程表采样到 gadget 拉起的子进程：FOUND_PROC pid=1279 cmd=[sleep 10 ]，
46 次采样全部命中同一个 pid=1279。
服务端日志这轮也留了一条，容器日志里出现
org.apache.shiro.io.ClassResolvingObjectInputStream.<init> ← DefaultSerializer.deserialize，
说明解密后的字节确实进了 readObject()。

不采用的判据（这两个都把我坑过，写出来免得下一个人再踩）：
一、deleteMe 响应标志。不能用。原先我是拿 deleteMe=true 当"解密/反序列化失败"的
oracle 的。实测打脸：5 类输入全部返回 true —— 垃圾 4 字符 rememberMe=AAAA、超长垃圾
rememberMe=A×4000、默认密钥加密的合法序列化流、错误密钥加密的同一流，甚至不带
cookie 的 /login 路径也回 deleteMe=1。只要 cookie 非空，无论内容、无论路径，一律回
deleteMe。它没有区分度。
因为这个原因，早期那份"25 个候选密钥全部解密失败"的爆破结论整条作废
（文件 t7-c1-bruteforce-out.txt 保留不改，在正文标注为判定 oracle 失效导致的无效结论）。
作废范围只限那个文件的爆破结论，C1 本身不作废 —— C1 最后是靠 OOB 和 /proc 实证的。

二、响应时间。也不能用。想法是 gadget 里放 sleep 10，看响应是不是慢了 10 秒。
必假阴性，因为 Runtime.exec() / ProcessBuilder.start() 是异步的，JVM 拉起子进程就返回，
不等它结束。实测数据：三条链在 OOB 和 /proc 上都证明 RCE 成功了，但计时对比是
CB1 delta -0.002 秒、CC5 +0.008 秒、CC6 -0.003 秒，证据文件自己都判 executed: false。
就是靠这个假 oracle，我一度认为 C1 打不通，后来靠 OOB 和 /proc 推翻了。
一个错误的判据不只是结论不准，是会让你把真漏洞当阴性丢掉。

独立证据交叉：
A（证明数据能流出）：OOB 收到含真实命令输出的请求原文。
B（证明动作真发生）：主机进程表采样到子进程 pid=1279。
只有 A 时可能是回显伪造；只有 B 时证明不了数据外流。两条齐了才算闭环。
密钥自证（aced0005）解决的是"密钥对不对得上"，反序列化日志解决的是"进没进 readObject"，
这两个和 A/B 又是不同维度。四条证据各证一段，没有一段是互相替代的。

复现率：
主链 CC6：≥95%（5 次尝试 5 次成功，失败轮次 0）。
四链横向：≥66%（3/4，CC2 未命中）。单轮样本小，不写更高。

隔离与非破坏：
端口绑 127.0.0.1:18081 映射容器 8080/tcp。物理网卡 192.168.31.194:18081 实测
curl exit 7（拒绝），Test-NetConnection=False。只绑回环不证明没外泄，所以真的从
物理网卡试了一次。
容器 Binds=null、MountCount=0（没挂宿主目录）、SecurityOpt 含 no-new-privileges、
网络模式 bridge、重启策略 no。
实际执行过的命令就这些：sleep 10（进程观测用）、id -u、whoami、hostname。全部只读，
无副作用。没反弹 shell，没写马，没拖库。

阴性清单（试了不通的）：
N-C01 CommonsCollections2 链，OOB 0 命中。原因：CC2 依赖 commons-collections4
（PriorityQueue + TransformingComparator），本容器 classpath 只有 commons-collections-3.2.1。
属 classpath 不匹配，不是打法错误 —— 其余 3 条链均命中恰好印证了这点。
N-C02 默认密钥爆破到其它 key，25 个常见候选全"未执行"。该结论无效，计时 oracle
本身已被证伪。但同时也证明不需要爆破：公开默认值就是正确的。明确不主张"爆破成功"。
N-C03 deleteMe 作 oracle，见上面判定依据，零区分度。
N-C04 HTTP DELETE 删已上传类文件，.jsp 归 JspServlet 管，返回 405。
N-C05 sleep 计时判 RCE，误判，见上面。
N-C06 顺带记一个工具坑：我用的执行脚本会在 stdout 末尾追加一段 {"rc":0,"stdout_len":…}
的 JSON，而取 cookie 的下游脚本取第一行。cookie 的 base64 输出恰好不带换行，那段 JSON
就被拼进了 cookie 值。容器日志里留下了铁证：A cookie header was received [rc": 0,
"stdout_len": 3884, "stderr_len": 0}] that contained an invalid cookie —— 中间那段明显
不属于 Shiro 的日志格式。最初我以为是 Shiro 的 cookie 解析有问题，查了约 15 分钟才发现
是工具注入。改用按 base64 字符集正则取最长串之后就好了。工具缺陷会静默污染数据，
报阴性之前先排一次工具。
留这些不是为了凑数：N-C01 说明"链没命中"可能是 classpath 问题不是打法问题，
N-C03/N-C05 是两个看着像 oracle 实则无效的判据，正是它们一度让我把成功的 C1 判成失败。

修复建议：
1. 根因 R1：CookieRememberMeManager 未设置自定义密钥，直接沿用公开常量
   kPH+bIxk5D2deZiIxcaaaA==。修法是显式调用 setCipherKey() 配随机密钥（≥16 字节），
   密钥存配置中心或 KMS，不入代码库、不入镜像，每次部署重新生成。
   即使升级了也建议做，默认值只要还存在就是定时炸弹。
2. 根因 R2：rememberMe 的反序列化落点没加类型白名单，ObjectInputStream 直接 readObject()。
   推荐升级 Shiro；无法升级时关闭 rememberMe（setRememberMeManager(null)）并自定义
   Serializer 白名单。本轮未验证哪个 patch 版本彻底消除默认密钥，升级前请查阅官方
   release note 逐版确认，不要只看大版本号。
3. 纵深防御：移除 classpath 上不必要的 gadget 依赖。本轮 CC2 失败正是受益于 classpath
   没有 collections 4。依赖越少，可打链越少，这本身就是有效的纵深防御。
4. 检测：监控 Set-Cookie: rememberMe 且值异常长的请求（实测本轮 cookie 1880–3904 字符）；
   关注容器日志里的 ClassResolvingObjectInputStream 调用。

本次测试仅做漏洞验证，没有修改、删除业务数据，未对站点业务造成影响，
测试行为符合平台众测协议。

证据文件（完整文件名 + sha256）：
loop3-t7-c1-shiro-20261012.json            c08dc7eb74c3d000e9ec42dc728fab6edaf42d5a38dd406d05aee0b5188a49b7
loop3-t7-c1-rate-and-baseline-20261012.json 68579107f657a551ca7032b456ecfec55863cdbf2e90d59cba65dd28d79d4a7e
loop3-t7-c1-oob.jsonl                      2a30520239c7f473ff5e9f2c4a239175e4b0805336e5f62ff81349912d721343
loop3-t7-c1-logtrace-20261012.json         0fae78cfe7698e45b5c5ad13c74deddbf10ed2434a0551d24638f3d0841823a5
loop3-t7-c1-matrix-20261012.json           99eba28d198218119330bb9852d75e7f7a518eef73d861d946a1e71bbb15e432
loop3-t7-c1-timing-20261012.json           02d547e655f7327db0bc6844ad02f9586aef9282be6173c6fdf65a96f8860051
t7-c1-keycheck-out.txt                     33a604f257bcde0a58cd1a37ab026cda1d88e6e062b96e8e4f4ac62c2af8e7be
t7-c1-rex-out.txt                          f4961af7909403921fbae2af5612994b8807ace645e648a3e122d312aa80c475
t7-c1-bruteforce-out.txt                   e27d26961b48611be36987a57fd749e64aa058dc2dbfaace9e15051be9e596d9
                                              （标注：判定 oracle 失效导致的无效结论，保留不改）
可复跑脚本：t7-c1-shiro-gen.rb / t7-c1-shiro-exploit.py / t7-c1-keycheck.rb /
t7-c1-matrix.py / t7-c1-matrix.rb / t7-c1-procwatch.sh / t7-oob-listener.py
```

---

## 二、这份样本在示范什么（拆解）

> 写报告最容易出的问题不是格式错，是**"通篇正确但没人味"**。
> 下面把这份样本里**故意的技术选择**拆开，每条对应模板的一节。

| # | 示范的技术 | 在样本哪里 | 对应模板 |
|---|---|---|---|
| 1 | **开头就分流**，不装作能投 | 「性质声明」段 + `风险等级：不适用` | §0 / §0.2 |
| 2 | **主动声明未验证项** | 「Shiro 各版本的具体修复边界……未验证」 | §7.3 判据 5 |
| 3 | **根因用否定句定界**，不是描述句 | 「这不是"配置没改"，是"代码里就写死了默认值」 | §7.1 正例 1 |
| 4 | **专写「不是什么」** | 「不是'Shiro 有反序列化就等于 RCE'」 | §6.1 纪律 1 |
| 5 | **密钥来源不靠猜，靠自证** | `aced0005` / 1308 B + 反证逻辑 | §8.1 |
| 6 | **被证伪的判据照样写出来** | 「不采用的判据」整段 | §7.1 正例 9 / §8.2 |
| 7 | **写明假阴性代价** | 「一度认为 C1 打不通」 | §7.1 正例 4 |
| 8 | **作废结论单列 + 划范围** | 「作废范围只限那个文件的爆破结论，C1 本身不作废」 | §5.1 |
| 9 | **四类证据各证一段，不互相替代** | 「四条证据各证一段，没有一段是互相替代的」 | §8.3 |
| 10 | **回显逐段解读** | `0`=id -u / `root`=whoami / `3d79…`=容器 hostname | §9.2 |
| 11 | **隔离写到物理网卡层** | `192.168.31.194:18081 curl exit 7` | §2.1 §11 |
| 12 | **执行过的命令逐条列** | `sleep 10` / `id -u` / `whoami` / `hostname` | §4 B04 |
| 13 | **阴性清单说清不通过的原因类型** | N-C01 classpath 不匹配 / N-C04 机制限制 | §3 C05 |
| 14 | **修复落到具体配置项**，不给"建议升级" | `setCipherKey()` / `setRememberMeManager(null)` | §7.2 反例 3 |
| 15 | **修复建议也带未验证声明** | 「本轮未验证哪个 patch 版本彻底消除默认密钥」 | §7.3 判据 5 |

### 2.1 三处最容易照错的地方

**① 别把 `302` 当证据。**
样本在「响应包」里明说「这一条不算证据」，然后把真正硬的证据（OOB 原始记录）单独摆出来。
多数人会把 `HTTP 302` 贴上去就收工 —— 审核一眼就知道那只能证明"请求被处理了"。

**② 别藏被打脸的记录。**
「不采用的判据」这一段是**整份样本最值钱的部分**。
它做了三件事：说清我原来怎么想的、说清实测数据是什么、说清因此作废了哪个结论。
没有这一段，读者会以为你第一次就做对了。

**③ 别把"可打链数量"当成危害。**
样本里 CC2 失败被写成了**正面证据**：它证明 gadget 依赖是硬约束，
反过来支撑「移除 classpath 依赖就是有效纵深防御」这条修复建议。

---

## 三、这份样本的量化自检（实测结果，不是估的）

按模板 §7.3 的判据，用脚本量了正文（不含本文件说明部分）。
**下表数字是 2026-10-13 实测输出，不是估的**，复跑命令见 §四。

| 判据 | 阈值 | **本样本实测** | 结论 |
|---|---|---|---|
| 句子长度标准差 σ | ≥ 8 字 | **26.65**（180 句，均长 35.7，最短 3 / 最长 108） | ✅ |
| 短句-长句交替 | ≥ 3 处 | 「它没有区分度。」「两条齐了才算闭环。」「不写更高。」等多处 | ✅ |
| 具体值密度 | 每 100 字 ≥ 1 个 | **1.98 个/百字**（6779 字中 134 个具体值：`aced0005` / `1308 B` / `pid=1279` / `-0.002` / `3904` 等） | ✅ |
| 段落长度离散度 | 最长段 ÷ 最短段 ≥ 3 | 「不采用的判据」两大段 vs「复现率」三行 | ✅ |
| **显式未验证声明** | ≥ 1 处 | **3 处**（性质声明、修复建议 2、修复建议 4 前置） | ✅ |
| **自我纠错记录** | ≥ 1 处 | **2 处**（「原先我是拿 deleteMe 当 oracle」「最初我以为是 Shiro 的 cookie 解析有问题」） | ✅ |
| 反向对照句 | ≥ 2 处 | **10 处**（「不是……是……」「不是 'Shiro 有反序列化就等于 RCE'」「只有 A 时……只有 B 时……」等） | ✅ |
| **AI 高频词命中** | = 0 | **0**（7 个高频词全未命中） | ✅ |
| 加粗密度（提交版） | ≤ 3 | 正文 0 处加粗 | ✅ |
| 证据引用完整度 | 100% | 9 个证据文件均带完整 sha256 | ✅ |

> 均长 35.7 但 σ 高达 26.65 —— **说明长短句混排是有效的**：
> 平均长度说明不了什么，离散度才说明这是人写的。

---

## 四、可复跑的自检命令

在 PowerShell 里，对本文件 `一、示范报告正文` 那个代码块的内容执行：

```powershell
# 量句长标准差 σ 与具体值密度
$text = <把正文粘到这里>
$sentences = [regex]::Split($text, '[。；\n]') | Where-Object { $_.Trim().Length -gt 0 }
$lengths = $sentences | ForEach-Object { $_.Trim().Length }
$avg  = ($lengths | Measure-Object -Average).Average
$std  = [math]::Sqrt( ( ($lengths | ForEach-Object { [math]::Pow($_ - $avg, 2) } | Measure-Object -Sum).Sum ) / $lengths.Count )
"句子数={0}  平均句长={1:N1}  标准差σ={2:N1}" -f $lengths.Count, $avg, $std
# 期望：σ >= 8

# 数 AI 高频词（期望 0）
$aiwords = @('综上所述','由此可见','该漏洞本质上','存在极大安全隐患','一旦被利用将','值得注意的是','全面系统')
$hits = $aiwords | Where-Object { $text -match $_ }
"AI高频词命中={0}" -f $hits.Count

# 数未验证声明与自我纠错（期望各 >= 1）
"未验证声明={0}" -f ([regex]::Matches($text,'未验证|未实测|不确定')).Count
"自我纠错={0}" -f ([regex]::Matches($text,'一开始|最初|原先|后来发现')).Count
```

---

## 五、别学这个的地方（反向示范）

这份样本有几处**刻意保留了复现笔记的口吻**，因为那是 C1 的原汁原味。
但**真要写成可投稿的报告，以下几点必须改**：

| 本样本这样写 | 可投稿报告必须改成 | 原因 |
|---|---|---|
| 风险等级写「不适用」 | 写高/中/低 | 可投稿报告必须有等级；本样本因是 CVE 复现才写不适用 |
| 影响资产写 `127.0.0.1:18081` | 写**真实目标**完整 URL + 参数 | 靶场地址不是可投稿的资产 |
| 通篇在讲 CVE 编号和修复版本 | 讲**该目标自身的**业务根因 | 组件 CVE 复现不是发现型漏洞 |
| 提到具体容器 ID、镜像 digest | 换成目标侧可见的信息 | 靶场细节对审核无用 |
| 写「本篇是复现记录」 | 删掉这句 | 投稿写这句等于自曝不是原创 |

> **判断一份报告能不能投，先看这五行。**
> 只要有任意一行是左边那栏，就还是 B 路，得继续练。

---

## 六、素材出处

| 项 | 值 |
|---|---|
| 本文件产出 | loop4 t5 / forge-template，2026-10-13 |
| 素材 | `security/learning/cve/C1-SHIRO-2016-4437-rememberMe反序列化默认密钥.md` sha256 `625b312fc14c07e4551508b39a6250f3fa34baf70ffa55523514a2172df3d89b` |
| 证据文件 sha256 | 转录自 C1 笔记 §4.5（该笔记由 t8 独立重算）；**投稿前须归档者再独立重算一遍** |
| 配套模板 | `漏洞盒子报告模板-提交版.md` v2 §1 / §1.1 / §7 / §8 |
| 配套自查 | `提交前自查清单.md` |
| 合规 | 全部实测仅在 127.0.0.1 本地容器靶场执行；验证性 payload，只读命令，无破坏 |
| 免责 | **本文件不可直接投稿**；示范文风与证据组织，不示范漏洞本身；不承诺任何审核结果 |