# 工具清单与 OSINT 资源

> 来源：nahamsec Resources-for-Beginner-Bug-Bounty-Hunters tools.md，结合本项目实际工具链整理。
> 用途：赏金项目侦察、挖掘、验证阶段的工具参考，以及 OSINT 搜索引擎清单。

---

## 一、本项目已安装工具（18+）

### 侦察与枚举

| 工具 | 用途 | 状态 |
|---|---|---|
| nmap | 端口扫描、服务识别 | ✅ 已安装 |
| httpx | HTTP 存活探测、多探针 | ✅ 已安装 |
| subfinder | 子域名枚举（被动源） | ✅ 已安装 |
| dnsx | DNS 解析、爆破 | ✅ 已安装 |
| naabu | 快速端口扫描 | ✅ 已安装 |
| katana | 爬虫、URL 发现 | ✅ 已安装 |
| ffuf | 目录/参数模糊测试 | ✅ 已安装 |
| gobuster | 目录/DNS 爆破 | ✅ 已安装 |
| amass | 子域名枚举 + 网络地图（比 subfinder 更强） | ❌ 待安装 |
| waybackurls | 从 Wayback Machine 取历史 URL | ✅ 已安装 |
| gau | 获取所有 URL（Wayback + Common Crawl + URLScan） | ✅ 已安装 |

### 漏洞扫描与检测

| 工具 | 用途 | 状态 |
|---|---|---|
| nuclei | 基于模板的目标扫描 | ✅ 已安装 |
| dalfox | XSS 扫描器 | ✅ 已安装 |
| sqlmap | SQL 注入自动化 | ✅ 已安装 |
| tlsx | TLS/SSL 证书探测 | ✅ 已安装 |
| interactsh-client | OOB 回调服务器客户端 | ✅ 已安装 |
| zap | OWASP ZAP 代理扫描器 | ✅ 已安装 |
| dirsearch | Python 目录爆破（比 ffuf 易上手） | ❌ 待安装 |
| FeroxBuster | Rust 递归内容发现 | ❌ 待安装 |

### 密钥与秘密扫描

| 工具 | 用途 | 状态 |
|---|---|---|
| gitleaks | Git 历史密钥扫描 | ✅ 已安装 |
| trufflehog | 密钥扫描（支持更多源） | ✅ 已安装 |
| KeyHacks | 泄露 API Key 快速验证 | ❌ 待安装 |

### 其他

| 工具 | 用途 | 状态 |
|---|---|---|
| amass | 子域名枚举 + 网络地图 | ❌ 待安装 |
| Param Miner | Burp 插件，发现隐藏参数（缓存投毒必备） | ❌ 待安装 |
| AuthMatrix / Autorize | Burp 插件，自动化越权测试 | ❌ 待安装 |
| CyberChef | 编解码瑞士军刀（浏览器版免安装） | ❌ 待安装 |

---

## 二、代理与网络嗅探

| 工具 | 说明 | 语言 |
|---|---|---|
| Burp Suite | Web 流量拦截与修改（免费版 + 专业版） | Java |
| OWASP ZAP | 免费 Web 安全审计代理 | Java |
| Caido | 轻量级 Web 安全审计工具 | Web |
| Wireshark | 网络协议分析器 | C/C++ |

---

## 三、Burp 扩展推荐

| 扩展 | 用途 |
|---|---|
| Logger++ | 记录所有 Burp 工具的请求响应，可导出 CSV |
| AuthMatrix | 基于角色的授权测试矩阵 |
| Autorize | 自动检测授权漏洞 |
| Burp Bounty | 快速构建自定义扫描检查 |
| Param Miner | 发现隐藏、未链接的参数（缓存投毒必备） |

---

## 四、OSINT 搜索引擎（赏金侦察必备）

### 网络空间搜索引擎

| 搜索引擎 | 用途 | 网址 |
|---|---|---|
| Shodan | 搜索联网设备、服务、端口、漏洞 | shodan.io |
| Censys | 主机和网络搜索（证书、服务） | censys.io |
| ZoomEye | 网络空间搜索引擎（ Knownsec 出品） | zoomeye.org |
| FOFA | 网络空间资产检索（白帽汇出品） | fofa.info |
| Quake | 网络空间搜索引擎（360 出品） | quake.360.net |
| Hunter | 网络空间测绘（奇安信出品） | hunter.qianxin.com |
| Onyphe | 网络安全搜索引擎 | onyphe.io |
| BinaryEdge | 攻击面管理与威胁情报 | binaryedge.io |

### 域名与证书

| 工具 | 用途 | 网址 |
|---|---|---|
| crt.sh | SSL 证书透明度搜索 | crt.sh |
| VirusTotal | WHOIS、DNS、子域名侦察 | virustotal.com |
| SecurityTrails | DNS 历史、子域名、WHOIS | securitytrails.com |
| ViewDNS | DNS 历史、反向 IP、WHOIS | viewdns.info |
| DNSDumpster | 子域名枚举、DNS 记录 | dnsdumpster.com |

### 邮箱与人员

| 工具 | 用途 | 网址 |
|---|---|---|
| hunter.io | 企业邮箱枚举 | hunter.io |
| intelx.io | OSINT 瑞士军刀 | intelx.io |
| Snov.io | 邮箱查找与验证 | snov.io |
| Phonebook.cz | 邮箱枚举（捷克） | phonebook.cz |

### 代码搜索

| 工具 | 用途 | 网址 |
|---|---|---|
| GitHub Code Search | GitHub 代码搜索 | github.com/search?type=code |
| NerdyData | 源代码搜索引擎 | nerdydata.com |
| searchcode.com | 多语言代码搜索 | searchcode.com |
| Sourcegraph | 代码搜索与导航 | sourcegraph.com |
| PublicWWW | 网站源代码搜索（找用了某技术的网站） | publicwww.com |

### 历史与归档

| 工具 | 用途 | 网址 |
|---|---|---|
| Wayback Machine | 网页历史归档 | web.archive.org |
| Common Crawl | 网页爬取数据集 | commoncrawl.org |
| URLScan.io | URL 扫描与历史 | urlscan.io |
| Google Cache | Google 网页缓存 | webcache.googleusercontent.com |

### 威胁情报

| 工具 | 用途 | 网址 |
|---|---|---|
| AlienVault OTX | 开放威胁情报交换 | otx.alienvault.com |
| AbuseIPDB | IP 滥用报告 | abuseipdb.com |
| ThreatBook | 威胁情报（微步在线） | threatbook.cn |
| 0xinfection | 威胁情报 | 0xinfection.com |

---

## 五、侦察框架（一站式）

| 框架 | 说明 |
|---|---|
| reconftw | 自动化全流程侦察（子域名枚举 + 漏洞检查） |
| Sn1per | 发现隐藏资产和漏洞 |
| Spiderfoot | OSINT 自动化工具 |
| reNgine | Web 应用侦察套件 |
| AutoRecon | 多线程服务枚举（CTF/OSCP 用） |
| Osmedeus | 进攻性安全工作流引擎 |

---

## 六、模糊测试与目录爆破

| 工具 | 说明 | 语言 |
|---|---|---|
| FFuF | 快速模糊测试工具（目录/参数） | Go |
| dirsearch | 简单的目录/文件爆破工具 | Python |
| FeroxBuster | 简单快速的递归内容发现 | Rust |
| gobuster | 目录/DNS/虚拟主机爆破 | Go |
| wfuzz | Web 应用模糊测试 | Python |

---

## 七、内容发现

| 工具 | 说明 |
|---|---|
| meg | 批量获取 URL（对服务器友好） |
| httpx | 快速多用途 HTTP 工具包 |
| hakrawler | Go 写的 Web 爬虫 |
| nuclei | 基于模板的快速目标扫描 |
| waybackurls | 获取 Wayback Machine 知道的所有 URL |
| gau | 获取所有 URL（Wayback + Common Crawl + URLScan + OTX） |
| katana | 下一代爬虫 |
| gospider | Go 写的快速 Web 爬虫 |

---

## 八、利用工具

| 工具 | 说明 | 语言 |
|---|---|---|
| sqlmap | SQL 注入自动化检测与利用 | Python |
| commix | 命令注入检测与利用 | Python |
| XSStrike | XSS 检测与利用 | Python |
| SSRFmap | SSRF 检测与利用 | Python |
| ysoserial | Java 反序列化 payload 生成 | Java |
| ysoserial.net | .NET 反序列化 payload 生成 | C# |
| marshalsec | Java 反序列化利用辅助 | Java |

---

## 九、移动黑客

| 工具 | 说明 |
|---|---|
| Frida | 动态插桩工具 |
| jadx | Dex 到 Java 反编译器 |
| Ghidra | NSA 软件逆向工程套件 |
| dex2jar | dex 转 jar |
| MobSF | 移动应用安全测试框架 |
| objection | 运行时移动探索工具（基于 Frida） |
| RMS-Runtime-Mobile-Security | 运行时移动安全（Web 界面操作 Java 类） |

---

## 十、笔记与组织

| 工具 | 说明 |
|---|---|
| Reconness | 侦察管理平台 |
| Joplin | 开源笔记应用（Markdown） |
| Xmind | 思维导图 |
| Axiom | 动态基础设施管理（赏金用） |
| PenTest.ws | 渗透测试 Web 应用（组织主机/服务/漏洞/凭证） |
| Notion | 笔记与协作 |

---

## 十一、字典与 Payload

| 资源 | 说明 |
|---|---|
| SecLists | 超大安全测试字典集合 |
| AssetNote Wordlists | AssetNote 制作的字典 |
| PayloadsAllTheThings | Payload 集合（最经典） |
| FuzzDB | 模糊测试字典与 payload |
| defaultcreds-cheat-sheet | 默认凭证速查表 |
| rockyou.txt | 最经典的密码字典 |

---

## 十二、OOB 回调与测试辅助

| 工具 | 说明 |
|---|---|
| interactsh | ProjectDiscovery OOB 回调服务器 |
| webhook.site | 测试/检查/转发 HTTP 请求 |
| requestcatcher.com | 创建子域名测试应用 |
| canarytokens.org | 蜜罐令牌 |
| pingb.in | 临时 HTTP 回调 |
| dnslog.cn | DNS 日志（国内常用） |
| ceye.io | 带外注入检测平台（国内） |

---

## 十三、编解码与转换

| 工具 | 说明 |
|---|---|
| CyberChef | GCHQ 编解码瑞士军刀（浏览器版免安装） |
| Burp Decoder | Burp 内置编解码器 |
| Hackvertor | Burp 扩展，自定义编码/加密 |
| base64decode.org | 在线 Base64 编解码 |
| url-encode-decode.com | 在线 URL 编解码 |

---

## 十四、本项目工具链使用建议

### 侦察阶段标准流程

```bash
# 1. 子域名枚举
subfinder -d target.com -all -silent | dnsx -silent -a -resp

# 2. 存活探测
cat subs.txt | httpx -silent -title -status-code -tech-detect

# 3. URL 发现
cat alive.txt | katana -silent -d 5
cat alive.txt | waybackurls
cat alive.txt | gau

# 4. 目录爆破
ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301,302,403

# 5. 初始扫描
nuclei -l alive.txt -t cves/ -t vulnerabilities/ -severity high,critical
```

### 验证阶段标准流程

```bash
# 1. OOB 回调监听
interactsh-client

# 2. 手动验证（用 Burp/浏览器）
# 3. 证据留存（截图 + 响应体 + sha256）
```

---

## 十五、工具安装优先级

### 立即安装（高价值）

| 工具 | 理由 |
|---|---|
| amass | 子域名枚举比 subfinder 更全面，赏金侦察必备 |
| dirsearch | Python 写的，比 ffuf 易上手，适合快速目录爆破 |
| CyberChef | 浏览器版免安装，编解码日常必备 |

### 按需安装（中价值）

| 工具 | 理由 |
|---|---|
| Param Miner | 缓存投毒必备，但需要 Burp 专业版 |
| AuthMatrix / Autorize | 越权测试自动化，但需要 Burp |
| FeroxBuster | 递归内容发现，ffuf 已够用 |
| KeyHacks | 泄露密钥验证，gitleaks/trufflehog 已覆盖大部分 |
