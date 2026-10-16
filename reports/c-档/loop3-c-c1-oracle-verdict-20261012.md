> ⚠️ **本文件说明（2026-10-16 编码修复）**
> 这份报告的原始文件曾因编码问题损坏（`D:\bounty-forge` 里的源文件同样损坏，部分字节已永久丢失）。
> 现在按可逆规则尽量还原成 UTF-8：残留的 `�` 表示**原始字节已丢失、无法恢复**，不是原文里的字。
> 正文文字没有做任何改写、补充或删减；涉及结论请配合 `evidence/C/` 下的原始脚本与日志一起核对。

# Loop 3 · C 档补充：C1 判定 oracle 的最终定论（日志级锚点）

- **任务**：t7 补遗（队长�报「deleteMe �回包」后追加
- **执�**：hunter-web；attempt_id `0d061d06-b986-48c7-ae2c-988180a5f29a`
- **时间**�026-10-12 23:48 �23:56（Asia/Shanghai
- **结�先�**：C1 **早已用�带（OOB）打通并定�*；队长的「`deleteMe` 无效」判�*我同�*，但队长随后提出�*�oracle（`BadPaddingException`）同样不足以定�*—�真正的�点在**日志里的 `convertBytesToPrincipals` 行号**�

---

## 1. 四个候�oracle 的实测�

| # | 候�oracle | 错�密钥密文 | 正确密钥 + 合法�| 正确密钥 + gadget | 判定 |
|---|---|---|---|---|---|
| 1 | HTTP `Set-Cookie: rememberMe=deleteMe` | `true` | `true` | `true` | �**无区分度** |
| 2 | HTTP 响应时间（`sleep N` 计时�| ~0.01s | ~0.01s | ~0.01s | �**无区分度**（`Runtime.exec` 异�|
| 3 | 日志 `BadPaddingException`（队长提案） | �有（5 次） | �**�* | �**�* | ⚠️ **�解密失败"，不能判"成功"** |
| 4 | **日志 `convertBytesToPrincipals` 行号** | `AbstractRememberMeManager.java:429` | **`:431`** | **`:431`** | �**�向区�* |

### 1.1 为什�#3（队长的提�）不�
`BadPaddingException` �*单边**判据：它�*解密失败**时出现，�*解密成功时不出现**—�不出�也可能意味着"请求根本没走到那�。所以：

- 用它�失败"�- 用它�成功"�**不成�*（无异常 �成功）�
**这恰好是我上�的同�的镜�*：我�`deleteMe`"当失败�队长把"�`BadPaddingException`"当成功�两者都�"缺失的信�去推�正面事实"�

### 1.2 #4 才是�点：行号不同，方向明�
Shiro 1.2.4 `AbstractRememberMeManager.convertBytesToPrincipals()` 的两条分�*行号不同**�
```
失败分支（解密抛异常�
  Caused by: javax.crypto.BadPaddingException: Given final block not properly padded
    at ...AbstractRememberMeManager.convertBytesToPrincipals(AbstractRememberMeManager.java:429)

成功分支（解�OK、反序列化产出�象�仅类型不�
  java.lang.ClassCastException: java.util.HashSet cannot be cast to org.apache.shiro.subject.PrincipalCollection
    at ...AbstractRememberMeManager.deserialize(AbstractRememberMeManager.java:514)
    at ...AbstractRememberMeManager.convertBytesToPrincipals(AbstractRememberMeManager.java:431)
```

### 1.2.1 ⚠️ 锚点表述精确化（2026-10-13 00:05 �，采纳队长�核意见）

**�前我写的�*：�`:431` 这一行只能�'解密成功 + `readObject()` 成功产出了�触达」�**这句话不准确** —�经队长指出后我�块复核日志�*�队长�*：`:431` �*两类**异常触达，必须收紧表述�
**�后的准确模型**（`AbstractRememberMeManager.convertBytesToPrincipals`）：

| 行号 | � | �强度 |
|---|---|---|
| `:429` | **解密阶�**抛异常（`CryptoException` �`BadPaddingException`�| 必然失败 |
| `:431` | **解密成功、已进入反序列化阶�**（`deserialize()` � | ⚠️ **�解密成功"，不证明"反序列化成功"** |
| `:431` + `ClassCastException: HashSet cannot be cast` | 反序列化**真的产出了�*，仅类型不� | �**真成功锚�* |
| `:431` + `SerializationException: Unable to deserialze argument byte array.` | 解密成功�*反序列化失败** | �失败 |

**完整台账（�块切分，非抽样；`loop3-t7-c1-log-inventory-20261012.json`�*�

| 类别 | 计数 | 时间戳（UTC�|
|---|---|---|
| A `:429` 解密失败（`CryptoException`/`BadPaddingException`�| **5** | 15:09:33.057 / 15:18:39.291 / 15:19:00.964 / 15:33:54.922 / 15:33:56.591 |
| B `:431` 反序列化失败（`SerializationException`�| **2** | 15:18:40.540 / 15:19:02.185 |
| C **`:431` 反序列化成功（`ClassCastException: HashSet`�* | **1** | **15:38:29.985**� � 23:38:29�|
| D 其它 | 0 | �|

**行级原�计数**（�整个 461 行日志）：`BadPaddingException` 5 / `:429` 5 / `:431` **3** / `ClassCastException` 1 / `HashSet cannot be cast` 1 / `SerializationException` 2 / `ClassResolvingObjectInputStream` 2 / `EOFException` 2 —�**与队长独立�算的计数完全�*�
**为什么必须收�*：若放任"看到 `:431` 就是成功"的写法，下一�有人�B 类（2 次反序列化失败）� —�那将�*�次同构错�*（拿"进入阶�"�成功产出"）�*真�的成功锚点必须同时满�`:431` �`ClassCastException`�*

日志�C 类（真成功锚点）的原始�录（带时间戳）：

```
2026-10-12 15:38:29.985  WARN 1 --- [nio-8080-exec-4] o.a.shiro.mgt.DefaultSecurityManager : Delegate RememberMeManager instance of type [org.apache.shiro.web.mgt.CookieRememberMeManager] threw an exception during getRememberedPrincipals().

java.lang.ClassCastException: java.util.HashSet cannot be cast to org.apache.shiro.subject.PrincipalCollection
	at org.apache.shiro.mgt.AbstractRememberMeManager.deserialize(AbstractRememberMeManager.java:514) ~[shiro-core-1.2.4.jar!/:1.2.4]
	at org.apache.shiro.mgt.AbstractRememberMeManager.convertBytesToPrincipals(AbstractRememberMeManager.java:431) ~[shiro-core-1.2.4.jar!/:1.2.4]
	at org.apache.shiro.mgt.AbstractRememberMeManager.getRememberedPrincipals(AbstractRememberMeManager.java:396) ~[shiro-core-1.2.4.jar!/:1.2.4]
	at org.apache.shiro.mgt.DefaultSecurityManager.getRememberedIdentity(DefaultSecurityManager.java:604) [shiro-core-1.2.4.jar!/:1.2.4]
```

> `15:38:29.985` UTC = **� 23:38:29**，落在我� C1 取证窗口内（23:30�3:40）�> `java.util.HashSet` 正是 ysoserial `CommonsCollections6` 链的**顶层反序列化对象**—�与我的 payload 结构完全对应�
**日志锚点计数**（`t7-shiro-full-dockerlogs.txt`�61 行；台账�`loop3-t7-c1-log-inventory-20261012.json`）：

| 锚点 | 行级计数 | 异常块�| 判定 |
|---|---|---|---|
| `:429` 解密失败（`BadPaddingException`/`CryptoException`�| 5 | **5** | 必然失败 |
| `:431` 进入反序列化阶� | 3 | 3 | ⚠️ 仅证明解密成�|
| �其中 `SerializationException`（反序列化失败） | 2 | **2** | �失败 |
| �其中 `ClassCastException: HashSet cannot be cast`�*真成�*�| 1 | **1** | �**成功锚点** |
| `ClassResolvingObjectInputStream`（Shiro 反序列化入口�| 2 | �| 证实 `readObject()` �|
| `EOFException`（空�| 2 | �| 无关�结� |

---

## 2. 四个�判据的交叉印证（C1 成功�
C1 的定�*不依赖任何单�oracle**，由四层�证据交叉得出�

| 判据 | 证据 | 层级 |
|---|---|---|
| **J1 OOB 外带** | 接收�`/t7badpad-cc6-0-root`、`/t7logoracle-cc6-0-root-3d7917aecbac`（含 `id -u`=0、`whoami`=root、�器主机名�| 应用�*命令执� + 回显** |
| **J2 容器 `/proc`** | `FOUND_PROC pid=1279 cmd=[sleep 10 ]`�6 次采样命� | OS �*子进程真的起�* |
| **J3 日志成功锚点** | `convertBytesToPrincipals(:431)` **�* `ClassCastException: java.util.HashSet`�5:38:29.985，唯� 1 次） | 框架�*解密+反序列化真的产出了�* |
| **J4 密钥�** | �用默认密钥解密自己的 cookie �`DECRYPT_OK` + magic `aced0005`�308B�| 密码学层 |

四条�判据指向同一结�*C1 定�为成功**�*不依赖任何单�oracle�*

---

## 3. 关于"新日志�= 0"的现象（如实说明�
我在�受控实验里用「`docker logs` 行数增量」判定锚点，得到 `new_log_lines: 0`。这不是"没发�，�是�
- 全量日志行数在两次采样间�**443 �443**，�早先抓取的完整�**461 �* �说明**日志�*，不能用行号增量做锚定；
- 正确做法�*按内�+ 时间�*定位（�.2 已给出带时间戳的原�行）�
**这个坑我留在报告�*：`docker logs` 行数增量在日志轮�不可靠，**锚定日志事件要带时间�*�

---

## 4. 队长指出的两点，我�条回应

### 4.1 「`deleteMe` �回包」�**同意**

我的�实测与队长一致：合法序列化流、错�钥�垃圾明�*全部** `deleteMe=true`；我另�还测了�不�cookie �`deleteMe=false`」与「`rememberMe=` 空�`false`」，�充队长的表�
**我上�纠错与队长结论相�*，且我把那份�翻的计时法证�`loop3-t7-c1-timing-20261012.json`）保留了，未删改�

### 4.2 「`t7-c1-bruteforce-out.txt` �25 密钥结�作废」�**接受，且我已主动这样标注**

该文�*�删改**，sha256 仍为 `e27d26961b48611be36987a57fd749e64aa058dc2dbfaace9e15051be9e596d9`�169 字节）�主报�§3 �**N-C02** 已写明：结�无效、`EXECUTED_KEYS=[]` 不可用�*同时证明无需爆破（默认密钥即正确�*�*不主�爆破成功"**。与队长的�致�

### 4.3 队长提供�`ensurePadding` 提示 —�**有用，但�发�*

我的 cookie 长度�772 / 1792 / 1308 密文）均�Base64 后自动为 4 的�数，`ensurePadding` �变字节�实测我�cookie 能� Shiro �`AesCipherService` 正确解密（队长在 Kali 侧独立验证：`SHIRO_DECRYPT_OK pt_len=82 head=aced000573720011`；我在本机验�`DECRYPT_OK len=1308 magic=aced0005`）�*两�验证�致�*

---

## 5. 还需要的动作（C1 �closure，�为�录）

| �| 状�|
|---|---|
| C1 定�| �**成功**（J1+J2+J3+J4 四判�叉） |
| �仍需 URLDNS 预� | �**不需�*。URLDNS 的价值是"在无回显时先证链�；本�*已直接拿�HTTP 外带命令输出**，�会�后验证据覆盖�*若队长坚持� DNS 层证�*，可按需补做（接收�仍限�|
| 待办 | 无（C1/C2/C3 均已交付；�器按队长指令保留�|

---

## 6. 证据文件（绝对路�+ sha256�

| 文件 | 内� | sha256 |
|---|---|---|
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\t7-shiro-full-dockerlogs.txt` | **shiro 容器全量日志�**（含 `:431` 成功锚点�`:429` 失败锚点，带时间戳） | `6b37c61c4d4fcfed6036d7ce63f0323adfc9bc0f7f9b8acb6c66abf2db5d116b` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\loop3-t7-c1-logoracle-20261012.json` | 受控日志 oracle 实验（三方�+ 判定�| `2380fd6f63aa8d534db8001ddc0fbebc51af754667674583ed22b34f2814d783` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\loop3-t7-c1-log-inventory-20261012.json` | **日志异常块完整台�*（�块切分，`:429`/`:431` 四类分类 + 时间戳，� §1.2.1 精确化） | `d9999386486cd56f2ffbe6c1ec2170fd96ce1777760290fd093b388ccc578074` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\t7-c1-log-inventory.py` | 台账生成脚本（可复跑�| `59e5070eb5abacc74e1576c3edbd8987de3c7a85da5ca70e9f950b7e105eb6ab` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\loop3-t7-c1-badpadding-oracle-20261012.json` | 队长 `BadPaddingException` 提�的验证�| `af7b6fec1e3ecaa43a8c94e396b6a1b53b6ec08c7983cf3ccfd1ea1d9f4bd789` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\t7-c1-logstamp.sh` | 日志锚点定位脚本 | `4575a13f0c00d37b6e426c946ad44dd84a81474930a0bb07e1b7b729c38bca6e` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\t7-c1-log-oracle.sh` | 日志锚点提取脚本 | `2a196e909a8762e74e96c82154db2e932934a8c95df10589da239d981f0e8a01` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\t7-c1-logoracle.py` | 受控日志 oracle 实验脚本（可复跑�| `cf2b1bd3d566f34f1f7a799816b280e3da73951a18f79bb2a8dd8c1c0aff5761` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\t7-c1-badpadding-oracle.py` | `BadPaddingException` 提�验证脚本（可复跑�| `9554769d6a0e8abfa11b3690c3a2024fbff9d16c97818599a6a967fb2717c5d5` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\t7-c1-bruteforce-out.txt` | **原�记录，未删改**（N-C02 标注为无效结论） | `e27d26961b48611be36987a57fd749e64aa058dc2dbfaace9e15051be9e596d9` |

### 上表 sha256 的核算方�
全部�`Get-FileHash -Algorithm SHA256` 逐文件实测（命令与输出�下方），**无占位�*�
```
6b37c61c4d4fcfed6036d7ce63f0323adfc9bc0f7f9b8acb6c66abf2db5d116b  56159  t7-shiro-full-dockerlogs.txt
d9999386486cd56f2ffbe6c1ec2170fd96ce1777760290fd093b388ccc578074   3500  loop3-t7-c1-log-inventory-20261012.json
59e5070eb5abacc74e1576c3edbd8987de3c7a85da5ca70e9f950b7e105eb6ab   5194  t7-c1-log-inventory.py
2380fd6f63aa8d534db8001ddc0fbebc51af754667674583ed22b34f2814d783   1708  loop3-t7-c1-logoracle-20261012.json
af7b6fec1e3ecaa43a8c94e396b6a1b53b6ec08c7983cf3ccfd1ea1d9f4bd789   1745  loop3-t7-c1-badpadding-oracle-20261012.json
4575a13f0c00d37b6e426c946ad44dd84a81474930a0bb07e1b7b729c38bca6e   1010  t7-c1-logstamp.sh
2a196e909a8762e74e96c82154db2e932934a8c95df10589da239d981f0e8a01   1159  t7-c1-log-oracle.sh
cf2b1bd3d566f34f1f7a799816b280e3da73951a18f79bb2a8dd8c1c0aff5761   5906  t7-c1-logoracle.py
9554769d6a0e8abfa11b3690c3a2024fbff9d16c97818599a6a967fb2717c5d5   5303  t7-c1-badpadding-oracle.py
e27d26961b48611be36987a57fd749e64aa058dc2dbfaace9e15051be9e596d9   2169  t7-c1-bruteforce-out.txt
```

---

## 7. 参�
- CVE-2016-4437 Apache Shiro rememberMe 反序列化
- Shiro 1.2.4 `AbstractRememberMeManager`（`convertBytesToPrincipals` 行号 429/431 分支�- 主报告：`security/learning/loop3-c-vulhub-report-t7-20261012.md`
- 进度账目：`security/learning/progress.md` §13

