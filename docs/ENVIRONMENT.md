# 运行环境与网络要求（Environment & Network）

> **一句话结论**：本仓库主体是 Markdown 知识库 + 几个**纯标准库** Python 脚本，**不装依赖也能读、能跑**。
> 真正需要环境的是靶场（Docker + Vulhub）和工具链（nuclei、nmap 等）。这份文档把**系统要求、官方安装链接、中国大陆网络实测**一次列全。

实测时间：2026-10-16 15:02–15:09（UTC+8），共三轮
测试机：Windows 11 x64 · Python 3.12 · Node 20 · Docker 27（Compose v2）
网络：上海 · 中国移动 AS9808 家庭宽带 · **未开任何代理**（开代理后复测 25/25 端点全通）

---

## 1. 最低环境

| 组件 | 最低要求 | 我实测过的版本 | 说明 |
| --- | --- | --- | --- |
| 操作系统 | Windows 10 1809+ / Ubuntu 20.04+ / Debian 11+ / macOS 12+ | Windows 11 x64 | 脚本本身跨平台 |
| Python | **3.10+** | 3.12.7 | `poc/` 的脚本用了联合类型标注（`str \| None` 这种），3.9 及以下会直接报错 |
| 第三方 Python 依赖 | **无** | — | 没有 `requirements.txt`，全靠标准库 |
| Docker | Engine 20.10+ / Desktop 4.x（Compose **v2**） | Docker 27 | Vulhub 靶场用，**只跑本地** |
| nuclei（可选） | 2.x / 3.x | — | 跑 `nuclei-rules/` 里的模板才需要 |
| 磁盘 | 20 GB+ 空闲 | — | Vulhub 镜像按需拉取，用多少占多少 |
| 内存 | 8 GB+ | 16 GB | 同时起多个容器靶场时更明显 |

**安全边界（写进代码里的）**：检测脚本只允许 `127.0.0.1` / `localhost` / `192.168.56.x`，传公网地址直接退出。

---

## 2. 官方安装链接（我逐个测了可达性）

| 工具 | 官方链接 | 国内直连（实测） |
| --- | --- | --- |
| Python 3.10+ | <https://www.python.org/downloads/> | ✅ 669 ms |
| Git | <https://git-scm.com/downloads> | 未实测（Windows 一般已自带 `git`） |
| Docker Desktop | <https://www.docker.com/products/docker-desktop/> | 未实测（安装包最终在 `objects.githubusercontent.com`，✅ 425 ms） |
| Docker Engine（Linux） | <https://docs.docker.com/engine/install/> | 未实测 |
| nuclei / httpx / katana | <https://github.com/projectdiscovery/nuclei/releases> | ✅ Release 附件走 `objects.githubusercontent.com`（425 ms） |
| Node.js（顺带） | <https://nodejs.org/> | ✅ 706 ms（国内镜像：<https://npmmirror.com/mirrors/node/>） |
| mpv（顺带） | <https://mpv.io/installation/> | ✅ 716 ms |

> 上面全是**官方源**。安全工具别从第三方"整合包 / 破解版"站点下——那种包里加了什么没人知道。

---

## 3. 中国大陆网络实测（**未开代理**）

| 域名 | 国内直连结果 | 延迟 | 谁需要它 |
| --- | --- | --- | --- |
| `pypi.org` / `files.pythonhosted.org` | ✅ 可用 | 345 / 628 ms | pip（本项目其实用不上） |
| `mirrors.aliyun.com` / `pypi.tuna.tsinghua.edu.cn` | ✅ 可用 | 476 / 670 ms | pip 国内镜像 |
| `registry-1.docker.io` / `auth.docker.io` / `hub.docker.com` | ❌ 连接超时 | — | **Docker Hub 官方**（Vulhub 拉镜像默认走这里） |
| `docker.m.daocloud.io` / `docker.1ms.run` / `docker.1panel.live` | ✅ 可用 | 217 / 248 / 1127 ms | Docker 镜像加速（替代上一行） |
| `github.com`（网页 / HTTPS 克隆） | ⚠️ TLS 握手超时 | — | `git clone` 本仓库 |
| `codeload.github.com`（Download ZIP） | ❌ 超时 | — | 「Download ZIP」按钮 |
| `raw.githubusercontent.com` | ❌ 连接被重置 | — | raw 直链 |
| `api.github.com` | ✅ 可用 | 331 ms | `gh` CLI / API |
| `objects.githubusercontent.com` | ✅ 可用 | 425 ms | Release 附件直链（下 nuclei 靠它） |
| `ghcr.io` | ✅ 可用 | 548 ms | GHCR 镜像 |
| `huggingface.co` | ❌ 超时 | — | 语音转写模型（本项目不用） |
| `hf-mirror.com` / `modelscope.cn` | ✅ 可用 | 439 / 368 ms | 上一行的国内替代 |

**结论**：跑本仓库的工具**不需要代理**；只有 `git clone`、`Download ZIP`、Docker Hub 这三件事在国内直连会卡。

---

## 4. 直连不通时：用**官方** WARP（附国内可达的下载路径）

> 先说清楚：这不是必需品，你可以只用镜像站绕开。但如果你要频繁取 GitHub 代码或拉 Docker 镜像，官方 WARP 是最省事的免费方案。
> **只走官方渠道**——第三方"加速器 / 纯净版 / 破解版"安装包风险自担。

| 官方入口 | 国内直连（实测） | 说明 |
| --- | --- | --- |
| `1.1.1.1`（WARP 官网） | ❌ **超时** | 官网本身在国内打不开，**打不开不是你的网络坏了** |
| `www.cloudflare.com` | ✅ 848 ms | Cloudflare 官网主页可开 |
| `developers.cloudflare.com` | ✅ 785 ms | 官方文档站，含 Windows / macOS / Linux 安装步骤 |
| `install.appcenter.ms` | ✅ 1583 ms | Cloudflare 官方安装包托管（Microsoft App Center） |
| `downloads.cloudflareclient.com` | ✅ TCP 可达（232 ms） | 安装包下载域名 |

### Windows：一条命令装（不需要翻墙）

```powershell
winget install --id Cloudflare.Warp -e
```

`winget` 源里这个包的版本（`26.8.2110.0`）与我本机在用的版本一致，属于官方发布渠道。

> ⚠️ 别敲 `scoop install warp`：scoop 里那个 `warp` 是**另一个不相干的工具**（0.3.0），不是 Cloudflare WARP。
> macOS / Linux 请按 `developers.cloudflare.com` 上的官方文档装（该站可直连）。

### 装好之后：确认真的生效

```powershell
# 1) 客户端状态（Windows 默认安装路径）
& "C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe" status
# 期望看到：Status update: Connected
```

2）浏览器打开 <https://www.cloudflare.com/cdn-cgi/trace>，看到 `warp=on` 就是真的生效了。

### 三个注意事项

1. **本地靶场不受影响**：WARP 默认排除内网段（`10/8`、`172.16/12`、`192.168/16` 等），`127.0.0.1` 的靶场照常能打，可以一边开 WARP 一边练。
2. **卡在 `Connecting` 怎么办**：国内部分网络对 WARP 的 MASQUE 端口不友好。我实测遇到过一次卡住，`warp-cli disconnect` 后再 `connect`，大约半分钟就上去了。
3. **免费档可能绕远**：我这边出口在洛杉矶（`colo=LAX`），拉大镜像反而可能更慢 —— 建议只在**下载卡住**的时候开，平时关掉。

---

## 5. 常见报错 → 处理

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| `git clone` 卡住 / `TLS handshake timeout` | `github.com` 握手被干扰 | 开官方 WARP（第 4 节）、改用 SSH、或从 Release 附件下载 |
| 「Download ZIP」失败 | `codeload.github.com` 不通 | 用 `git clone`（配代理），或下 Release 附件 |
| `docker pull` 卡住 / `dial tcp ... i/o timeout` | Docker Hub 直连不通 | 配镜像加速（可参考 [vuln-labs](https://github.com/xunwmw/vuln-labs) 的 `scripts/pull-with-mirror.*`，或 `daemon.json` 里的 `registry-mirrors`） |
| `python bf_*.py` 报下标/类型错误 | Python 低于 3.10 | 升到 3.10+ |
| 脚本提示「目标不在白名单」 | **护栏生效，预期行为** | 目标只能是 `127.0.0.1` / `localhost` / `192.168.56.x` |
| `1.1.1.1` 打不开 | 官网被墙 | 用 `winget` 或 `developers.cloudflare.com` |

---

## English summary

- Documentation + stdlib Python scripts only: **no `requirements.txt`, nothing to install** to read the playbooks or run the detection scripts.
- Python 3.10+ is required for `poc/` (union type annotations). Scripts hard-allow only `127.0.0.1` / `localhost` / `192.168.56.x`.
- Mainland-China direct connection (no proxy): PyPI, npm, Docker mirror endpoints, `api.github.com`, `ghcr.io` and GitHub Release attachments are reachable; **Docker Hub official endpoints, `codeload.github.com` (Download ZIP) and `raw.githubusercontent.com` are not**; `github.com` HTTPS clone can time out.
- `1.1.1.1` (the WARP homepage) **is unreachable from mainland China**, but `www.cloudflare.com`, `developers.cloudflare.com` and the official App Center installer host are reachable — so WARP can still be installed officially via `winget install --id Cloudflare.Warp -e`. Verify with `warp-cli status` (Connected) or `warp=on` in `cloudflare.com/cdn-cgi/trace`.
- Local labs are unaffected by WARP (loopback is not tunnelled). If WARP hangs on `Connecting`, disconnect and connect again; it usually comes up within 30–60 s.
