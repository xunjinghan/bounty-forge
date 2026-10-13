# next-lab-plan.md — 靶场扩容评估（Vulhub / Docker / VM）

- 任务：t2 [t2-vulhub] 阶段1b 靶场扩容
- 执行人：range-admin（attempt 8eceea64-e265-49db-bc9f-1eb16c958f36）
- 实测时点窗口：2026-10-12T18:14:14+08:00 — 2026-10-12T18:32:00+08:00
- 约束：只操作本机 127.0.0.1 与本地文件；未访问任何未授权公网站点；未改系统/网络设置；未安装重型软件

---

## 结论（先给答案）

**能搭。推荐方案 A：Vulhub 精选子集 + Docker；以方案 C（Kali VM 内已装好的 DVWA/bWAPP）作为「零下载、立即可用」的过渡靶场。**

- Docker 守护进程可用，启动耗时约 14–24 秒（阈值 3 分钟，未触发阻塞分支）。
- Docker Hub 直连不可用（`registry-1.docker.io`/`hub.docker.com` 15s 超时、HTTP 000），**但本机已配置 4 个 mirror，镜像拉取实测成功**。
- Vulhub 仓库与镜像链路均已实测打通：仓库 zip 87.7 MiB（gh-proxy，实测 219 KB/s，约 7 分钟）；镜像 `vulhub/shiro:1.2.4` 实测拉取 **723.9 秒 / 137.4 MiB**，并已 `docker run` 冒烟验证（Tomcat 起在容器 8080，HTTP 302）。
- 最大约束不是能否搭，而是**慢 + C 盘余量很小**（18:31 实测 13.11 GB → 18:32 实测 12.86 GB，仍在缓慢下降；docker_data.vhdx 7.86 GB）。因此必须分批拉取，并建议（需 captain/用户批准）把 Docker 磁盘迁到 D 盘。

---

## 1. 现有靶场清单（实测）

| 名称 | 地址/位置 | 技术栈 | 实测状态（2026-10-12） |
|---|---|---|---|
| target-site | `http://127.0.0.1:8091` | Python 3.12 标准库 http.server 单文件 + SQLite(`target_site.db`) + PBKDF2-HMAC-SHA256(200000) | **运行中**，pid=11776，HTTP 200 / 3234 字节（基线见 `baseline-20261012-181212.json`） |
| target-site-lab | `http://127.0.0.1:8095` | Python 3.12 单文件 + SQLite(`lab.db`)，含 `GET /__reset` | **运行中**，pid=7908，HTTP 200 / 2120 字节，复位后 sha256 `49b2032c…6cc7af` |
| Kali VM | VirtualBox `kali-linux-2026.2-virtualbox-amd64`（VDI 16.2 GB，3 个快照） | Debian 64 / 4GB / 4CPU；SSH `127.0.0.1:2222`（kali/kali，免密 sudo） | **poweroff**。内含 DVWA（`/dvwa/`，admin/password）与 bWAPP（bee/bug），2026-10-11 已实测真登录；但 apache2/mysql 随 VM 关机停用 |
| Metasploitable2 VM | VirtualBox `metasploitable2`（`D:\dsh-vm\meta2\`，vmdk 1.92 GB） | Ubuntu 32bit 漏洞靶机 | **未运行**（有 saved 状态） |
| win10-av VM | VirtualBox `win10-av`（vdi 10.7 GB） | Windows 10 + 杀软 | **未运行** |
| win2022-dc VM | `D:\dsh-vm\win2022-dc\`（vdi 7.7 GB） | Windows Server 2022 域控 | **未运行** |
| Docker 现有工作负载 | Docker Desktop 29.8.2 | 4 个容器：pentagi(`127.0.0.1:8443`)、scraper(`127.0.0.1:9443`)、pgvector(`127.0.0.1:5432`)、pgexporter(`127.0.0.1:9187`) | 全部 Up（**非本次任务创建，未做任何改动**） |
| Vulhub | — | — | **本地不存在**：工作区、`dsh-tools\`、`D:\dsh-vm\` 全路径搜索无 `vulhub` 目录，也无任何 `docker-compose*.yml` 配方 |

---

## 2. Docker 可用性核实（本次实测）

| 项目 | 实测值 | 证据 |
|---|---|---|
| 安装路径 | `C:\Program Files\Docker\Docker\Docker Desktop.exe` 存在；CLI `…\resources\bin\docker.exe` | `Test-Path` → True |
| 服务基线 | `com.docker.service` = **Stopped**（手动启动类型） | `Get-Service` |
| 启动动作 | 2026-10-12T18:14:47 可见窗口方式 `Start-Process "Docker Desktop.exe"`（PID 8820） | 命令行原文见 §6 |
| 守护进程就绪 | `docker version --format {{.Server.Version}}` → `29.8.2`，**启动后约 14–24 秒**（首轮 10s 轮询即返回版本，脚本 READY 时点 18:15:25） | 未超过 3 分钟阈值，无需转阻塞分支 |
| 后端 | WSL2：`docker-desktop` 分发版 Stopped → **Running** | `wsl.exe -l -v` |
| 引擎信息 | `29.8.2 Docker Desktop (containerized) overlayfs containers=4 images=4` | `docker info` |
| Compose | `Docker Compose version v5.5.1` | `docker compose version` |
| Docker Hub 直连 | `registry-1.docker.io` / `hub.docker.com` → **HTTP 000，15s 超时** | `curl -I --max-time 15` |
| 已配置镜像站 | `docker.1panel.live`、`hub.rat.dev`、`docker.m.daocloud.io`、`dockerproxy.com` | `.docker\daemon.json` |
| 镜像站验证 | `docker.1panel.live` 对 `vulhub/{flask,struts2,shiro,tomcat}` `tags/list` → **200**（并成功取回真实 tag 列表：struts2 有 2.3.28/2.3.30/s2-053/s2-066/s2-067 等）；`hub.rat.dev` → 302；`docker.m.daocloud.io` → 401 | `curl -H "Accept: …" <mirror>/v2/<repo>/tags/list` |
| 镜像拉取实测 | `hello-world` **7.3s**；`alpine:3.19`（5.6 MB）**10.6s**；`vulhub/shiro:1.2.4`（137.4 MiB 压缩）**723.9s** | `docker pull` 计时 |
| 运行冒烟 | `docker run -d -p 127.0.0.1:18080:8080 vulhub/shiro:1.2.4` → 20s 后 `curl http://127.0.0.1:18080/` = **HTTP 302**；日志 `Tomcat started on port(s): 8080`、`Started ShirodemoApplication`。容器已删除，镜像保留 | `docker logs shiro-smoke` |

---

## 3. 拉取方式与体积评估（未做长下载，仅取样测速）

| 目标 | URL | 实测体积 | 实测耗时/速率 |
|---|---|---|---|
| Vulhub 仓库 zip | `https://gh-proxy.com/https://codeload.github.com/vulhub/vulhub/zip/refs/heads/master` | **91,978,397 B（87.7 MiB）**（HTTP 200 + Content-Length） | 分片实测 19,766,201 B / 90 s = **219,590 B/s**；按整包折算 **≈ 419 s ≈ 7 分钟** |
| 同上（备用线路） | `ghproxy.net/…github.com/vulhub/vulhub/archive/refs/heads/master.zip`、`codeload.github.com`（直连） | 均 HTTP 200（未测速） | 备用 |
| `raw.githubusercontent.com`（对照） | 直连 | — | **HTTP 000**（不通）；gh-proxy 302 链路正常 |
| `api.github.com/repos/vulhub/vulhub` | 直连 | — | HTTP 200，0.74s（可用，注意限流） |
| 镜像 `vulhub/shiro:1.2.4` | mirror | 137.4 MiB 压缩 / 501 MB 落盘 | **723.9 s ≈ 12.1 分钟**（≈199 KB/s），**已验证可运行** |
| 镜像 `vulhub/tomcat:8.5.19` | mirror | 120.8 MiB 压缩（manifest 实测，14 层） | 按 199 KB/s 估算 ≈ **10.4 分钟** |
| 镜像 `vulhub/struts2:2.3.28` | mirror | 244.3 MiB 压缩（manifest 实测，12 层） | 按 199 KB/s 估算 ≈ **21 分钟** |
| 镜像 `vulhub/flask:1.0.2` | mirror | **tag 不存在**（MANIFEST_UNKNOWN） | 选型时需以 `tags/list` 实测为准 |

**首批「可下载清单」（建议按此分批，每批 ≤ 2 个环境）**

| 序号 | 环境 | 镜像/体积 | 练习价值 |
|---|---|---|---|
| 1 | Shiro rememberMe 反序列化（CVE-2016-4483 系） | `vulhub/shiro:1.2.4` **已就位 501 MB** | Java 反序列化 + 密钥爆破，高 |
| 2 | Tomcat PUT 上传（CVE-2017-12615） | `vulhub/tomcat:8.5.19` ≈121 MiB | 文件上传/RCE，高 |
| 3 | Struts2 S2-045/046/057 | `vulhub/struts2:2.3.28` ≈244 MiB | OGNL 注入/RCE，高 |
| 4 | Apache httpd 路径穿越（CVE-2021-41773） | 官方 httpd 镜像 + 配置，体积小 | 路径穿越，中高 |
| 5 | Nginx 解析漏洞 / CRLF | 官方 nginx 镜像 + 配置，体积小 | 解析歧义，中 |
| 6 | ThinkPHP 5.x RCE | 体积小 | PHP 框架 RCE，中高 |
| 7 | fastjson 1.2.24/1.2.47 | 中等 | JNDI/反序列化，中高 |
| 8 | DVWA + bWAPP | **Kali VM 内已装，零下载** | Web 漏洞全谱，可作为即时补充 |

**时间与容量预估（以实测 199 KB/s 为基准）**：8 个环境压缩体积合计约 1.2–1.8 GiB → 纯拉取 **约 1.8–2.7 小时**；不含 `compose up` 启动与手工调试。
**磁盘**：C 盘剩余 **13.11 GB（18:31 实测）→ 12.86 GB（18:32 实测）**，D 盘 120.67 GB；Docker 数据盘 `C:\Users\Administrator\AppData\Local\Docker\wsl\disk\docker_data.vhdx` 已 **7.86 GB**（拉取 shiro 前 7.61 GB）。

---

## 4. 扩容方案对比表

| 方案 | 内容 | 获取难度 | 耗时 | 练习价值 | 结论 |
|---|---|---|---|---|---|
| **A. Vulhub 精选子集** | gh-proxy 拉仓库 zip（87.7 MiB）+ 分批拉 6–8 个镜像 | 低（链路已实测） | 仓库 ~7 分钟 + 镜像 1.8–2.7 小时（分批） | **高**：CVE 真实复现、可写正式报告、覆盖面广 | **推荐（首选）** |
| B. Vulhub 全量 | 整仓库数百环境 | 低 | 数十 GB / 10+ 小时 | 高但冗余 | 不推荐（C 盘容量与时间都不可行） |
| **C. Kali VM 复用 DVWA/bWAPP** | `VBoxManage startvm kali-linux-2026.2-virtualbox-amd64` → ssh `127.0.0.1:2222` → `systemctl start apache2 mysql` | 极低（已装好） | **约 2–5 分钟**（开机+起服务） | 中高：Web 漏洞全谱、有 CSRF token 等真实约束；比 8091/8095 更接近真实应用 | **推荐（过渡/并行）** |
| D. Metasploitable2 | 启动既有 VM（含 saved 状态） | 极低 | 约 2 分钟 | 中：老漏洞、偏网络服务与提权（受 host-only 网段限制） | 备选 |
| E. 自建最小 compose 靶场 | 用本机 8091/8095 的 Python 服务风格容器化 | 中（要自己写配方） | 1–2 小时 | 中：可控、可定制，但无「已知 CVE 复现」履历价值 | 备选 |

---

## 5. 推荐落地步骤（待 captain 批准后执行）

1. 建项目目录（建议 `D:\dsh-vulhub\`，避开 C 盘）：仅创建目录 + 从 gh-proxy 拉 `vulhub` 仓库 zip（87.7 MiB，约 7 分钟，后台作业）。
2. 首批只起 **2 个** 环境：`shiro`（镜像已就位）+ `tomcat`（约 10 分钟拉取）。
3. 端口规划：现有占用 8091/8095（靶场）、5432/8443/9187/9443（pentagi 栈）→ Vulhub 统一用 **18080–18099** 段，且只绑 `127.0.0.1`。
4. 每起一个环境，写一条基线记录（镜像 digest、端口、初始凭据、`/__reset` 或重建方式），沿用 t1 的 `baseline-*.json` 格式。
5. 并行启动 Kali VM 的 DVWA/bWAPP（方案 C），使团队在主链等待镜像时不空转。

**需要 captain 决策的三件事**
1. **C 盘容量**：是否允许把 Docker 数据盘迁到 D 盘（Docker Desktop 设置变更 = 系统设置类，我未擅自执行）？
2. **Vulhub 目标边界**：容器内允许执行到 RCE/反序列化验证吗？（只影响本机容器，但仍然要你点头）
3. **Docker Desktop 是否常驻**：本次启动后未关闭；常驻会与 4 个 pentagi 容器共同占用内存/磁盘，是否需要「用完即关」策略？

---

## 6. 证据命令与原始输出（摘录）

```
Start-Process -FilePath 'C:\Program Files\Docker\Docker\Docker Desktop.exe' -PassThru   # 18:14:47, pid=8820
docker version --format '{{.Server.Version}}'      # → 29.8.2（T+10s 轮询即成功；READY at 18:15:25）
docker info --format '{{.ServerVersion}} {{.OperatingSystem}} {{.Driver}} containers={{.Containers}} images={{.Images}}'
                                                   # → 29.8.2 Docker Desktop (containerized) overlayfs containers=4 images=4
docker pull hello-world                            # → 7.3s
docker pull alpine:3.19                            # → 10.6s
docker pull vulhub/shiro:1.2.4                     # → 723.9s，501MB 落盘
docker run -d --name shiro-smoke -p 127.0.0.1:18080:8080 vulhub/shiro:1.2.4
curl -s -o NUL -w "http=%{http_code}" http://127.0.0.1:18080/     # → http=302
docker logs shiro-smoke                            # → Tomcat started on port(s): 8080 / Started ShirodemoApplication
docker rm -f shiro-smoke                           # 冒烟容器已清理，镜像保留
curl -sIL --max-time 15 https://registry-1.docker.io/v2/          # → 000（15.0s 超时）
curl -sI  https://gh-proxy.com/https://codeload.github.com/vulhub/vulhub/zip/refs/heads/master  # → 200, Content-Length: 91978397
curl -s -o NUL -r 0-20971519 -w "%{size_download} %{time_total} %{speed_download}" --max-time 90 <同上>  # → 19766201 90.01 219590
Get-ChildItem C:\Users\Administrator,D:\ -Recurse -Depth 4 -Directory | ? Name -match 'vulhub'   # → 无结果
Get-ChildItem <工作区>,dsh-tools,D:\dsh-vm -Recurse -Depth 3 -Include docker-compose*.yml   # → 无结果
```

## 7. 未决问题与残余状态

- 本机**已新增**：`vulhub/shiro:1.2.4` 镜像（501 MB）、`hello-world`、`alpine:3.19`；冒烟容器 `shiro-smoke` 已删除。
- **Docker Desktop 当前仍在运行**（本次启动，未关闭）；4 个 pentagi 容器为既有负载，全程未触动。
- 未下载 Vulhub 仓库本体（按任务要求「先不要盲目长下载」）。
- Kali VM 的 DVWA/bWAPP 状态引用于 `memory/context.md`（2026-10-11 实测记录），**本次未启动 VM 复验**；若走方案 C 需在启动后重新实测并记录基线。
