#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bfnet.py — vuln-xiuxian 检测脚本公共库（loop4 / n2）
=====================================================
职责：白名单校验、限速、只读 HTTP 探测（GET/HEAD）、sha256 取证、JSON 输出。

【非破坏性声明】
- 本模块只提供 GET / HEAD 两种只读方法。**没有** PUT / POST / DELETE / PATCH 的封装，
  也**没有**任何「上传」「执行命令」能力。调用方若需 POST 类探测，必须自行实现并
  在文件头显式标注破坏性 + 默认关闭。
- 本模块**不写文件**、**不执行系统命令**、**不拖库**。全部动作 = 发 HTTP 请求 + 在
  stdout 打印。

【白名单校验（团队红线，必须实现）】
允许的目标主机，**逐字面匹配**，不做 DNS 解析（避免解析外部域名产生外连）：
    127.0.0.1
    localhost
    192.168.56.x   （VirtualBox host-only 网段，loop3 Kali VM dc1 所在）
其余一律 `sys.exit(2)` 直接退出并报错，**不做「警告后继续」**。

【限速】
- 串行执行，请求间隔 ≥ `--interval`（默认 1.0 秒）。
- 本模块不提供并发；所有脚本调用序列为串行 ⇒ 并发数恒为 1，满足「并发 ≤5」。

【参考】
- loop3 B 档报告：security/learning/loop3-b-dvwa-bwapp-report-t4-20261012.md
- loop3 C 档报告：security/learning/loop3-c-vulhub-report-t7-20261012.md
- 本文件是 loop4 任务 t2（n2）的公共底座，不是漏洞实现。
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
import time
import urllib.error
import urllib.request

__all__ = [
    "ALLOW_HOSTNAMES",
    "WhitelistError",
    "assert_allowed",
    "describe_whitelist",
    "RateLimiter",
    "Response",
    "probe",
    "sha256_bytes",
    "emit",
    "add_common_args",
]

# --------------------------------------------------------------------------
# 1. 白名单
# --------------------------------------------------------------------------

#: 允许的字面主机名
ALLOW_HOSTNAMES = frozenset({"127.0.0.1", "localhost"})

#: 允许的 CIDR 网段（loop3 Kali VM dc1 用的 host-only 网段）
ALLOW_NETWORKS = (ipaddress.ip_network("192.168.56.0/24"),)


class WhitelistError(SystemExit):
    """白名单拒绝：直接以 exit code 2 终止整个进程。"""

    def __init__(self, host: str, url: str) -> None:
        self.host = host
        self.url = url
        msg = (
            "\n"
            "================================================================\n"
            " [红线拒绝] 目标不在团队白名单内，脚本已终止，未发出任何请求。\n"
            f"   target  : {url}\n"
            f"   host    : {host}\n"
            f"   允许范围: {describe_whitelist()}\n"
            "   纪律    : 只打 127.0.0.1 / localhost / 192.168.56.x；\n"
            "             不打公网、不打物理局域网、不打他人资产。\n"
            "   处置    : 若目标确属授权靶场，请确认它被映射到上述网段，\n"
            "             或改用 VM 内回环地址后重试。\n"
            "================================================================\n"
        )
        super().__init__(2)
        sys.stderr.write(msg)


def describe_whitelist() -> str:
    hosts = ", ".join(sorted(ALLOW_HOSTNAMES))
    nets = ", ".join(str(n) for n in ALLOW_NETWORKS)
    return f"host∈{{{hosts}}} 或 ip∈({nets})"


def assert_allowed(url: str) -> str:
    """校验 URL 主机属于白名单；不通过则抛 WhitelistError（进程 exit 2）。

    返回规范化后的 host 字符串。**不做 DNS 解析**：外部域名一律按「字面不匹配」
    拒绝，因此本函数永远不会因为解析域名而访问网络。
    """
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://([^/?#]+)", url)
    if not m:
        raise WhitelistError("<无法解析>", url)
    scheme = m.group(1).lower()
    if scheme not in ("http", "https"):
        raise WhitelistError(f"<scheme={scheme}>", url)
    authority = m.group(2)
    # 去掉 userinfo 与端口
    host = authority.rsplit("@", 1)[-1]
    if host.startswith("["):  # IPv6 字面量 [::1]
        host = host[1:host.index("]")] if "]" in host else host[1:]
    elif ":" in host:
        host = host.split(":", 1)[0]
    host = host.strip().lower()

    if host in ALLOW_HOSTNAMES:
        return host

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raise WhitelistError(host, url) from None

    for net in ALLOW_NETWORKS:
        if ip in net:
            return host
    raise WhitelistError(host, url)


# --------------------------------------------------------------------------
# 2. 限速
# --------------------------------------------------------------------------


class RateLimiter:
    """串行限速器：保证相邻两次请求的间隔 ≥ interval 秒。"""

    def __init__(self, interval: float = 1.0) -> None:
        if interval < 1.0:
            # 团队红线是「≥1s」。低于 1s 属于配置错误，直接顶回去而不是放行。
            sys.stderr.write(
                f"[红线拒绝] --interval={interval} 低于团队下限 1.0s，已按 1.0s 执行。\n"
            )
            interval = 1.0
        self.interval = float(interval)
        self._last: float | None = None
        self.sent = 0

    def wait(self) -> None:
        if self._last is not None:
            gap = time.monotonic() - self._last
            if gap < self.interval:
                time.sleep(self.interval - gap)
        self._last = time.monotonic()
        self.sent += 1


# --------------------------------------------------------------------------
# 3. 只读 HTTP 探测
# --------------------------------------------------------------------------


class Response:
    """一次只读请求的结果。body 保留原始 bytes，便于取 sha256。"""

    __slots__ = ("url", "method", "status", "headers", "body", "error", "elapsed")

    def __init__(self, url, method, status, headers, body, error, elapsed):
        self.url = url
        self.method = method
        self.status = status
        self.headers = headers  # list[tuple[str, str]]，保留重复头
        self.body = body or b""
        self.error = error
        self.elapsed = elapsed

    # -- 便捷访问 ---------------------------------------------------------
    def header_values(self, name: str) -> list[str]:
        low = name.lower()
        return [v for k, v in self.headers if k.lower() == low]

    def header(self, name: str) -> str | None:
        vals = self.header_values(name)
        return vals[0] if vals else None

    def has_header(self, name: str) -> bool:
        return bool(self.header_values(name))

    def header_map(self) -> dict[str, str]:
        """同名头合并成 `k: v1,v2`（Set-Cookie 尤其需要）。"""
        out: dict[str, str] = {}
        for k, v in self.headers:
            key = k.lower()
            out[key] = f"{out[key]},{v}" if key in out else v
        return out

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.body).hexdigest()

    @property
    def ok(self) -> bool:
        return self.error is None and self.status is not None

    def summary(self, limit: int = 220) -> str:
        if self.error:
            return f"{self.method} {self.url} -> ERROR {self.error}"
        snippet = " ".join(self.text.split())[:limit]
        return f"{self.method} {self.url} -> HTTP {self.status} body={len(self.body)}B sha256={self.sha256[:16]}… {snippet}"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """禁止自动跟随 3xx：302 本身就是要观察的证据。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)
_OPENER.addheaders = [("User-Agent", "bounty-forge-detector/1.0 (read-only, local lab)")]
_OPENER.addheaders.append(("Accept", "*/*"))
_OPENER.addheaders.append(("Connection", "close"))

_UA = "bounty-forge-detector/1.0 (read-only, local lab)"


def probe(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    limiter: RateLimiter | None = None,
    timeout: float = 10.0,
) -> Response:
    """发一次**只读**请求（GET / HEAD），返回 Response。

    - 不跟随重定向（302 是有效证据）
    - 超时 / 连接失败不抛异常，转成 Response.error
    - 调用方负责在发包前调用 assert_allowed()
    """
    method = method.upper()
    if method not in ("GET", "HEAD"):
        raise ValueError(
            f"bfnet.probe 只允许 GET/HEAD，收到 {method}。"
            "写操作请另写脚本并在文件头显式标注破坏性 + 默认关闭。"
        )
    if limiter:
        limiter.wait()

    hdrs = {"User-Agent": _UA}
    if headers:
        hdrs.update(headers)

    req = urllib.request.Request(url, method=method, headers=hdrs)
    t0 = time.monotonic()
    try:
        with _OPENER.open(req, timeout=timeout) as fp:
            body = fp.read() if method == "GET" else b""
            resp = Response(url, method, fp.status, list(fp.getheaders()), body, None, time.monotonic() - t0)
    except urllib.error.HTTPError as e:  # 3xx/4xx/5xx 都带完整响应体
        try:
            body = e.read()
        except Exception:  # noqa: BLE001
            body = b""
        resp = Response(url, method, e.code, list(e.headers.items()), body, None, time.monotonic() - t0)
    except Exception as e:  # noqa: BLE001 — 超时 / 连接拒绝 / DNS
        resp = Response(url, method, None, [], b"", f"{type(e).__name__}: {e}", time.monotonic() - t0)
    return resp


def sha256_bytes(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# 4. 输出
# --------------------------------------------------------------------------


def emit(result: dict, as_json: bool, stream=None) -> None:
    """输出结果。`--json` 时打印单个 JSON 对象；否则打印人类可读文本。"""
    stream = stream or sys.stdout
    if as_json:
        stream.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
        return

    stream.write("=" * 72 + "\n")
    stream.write(f"目标      : {result.get('target')}\n")
    stream.write(f"漏洞      : {result.get('vuln_id', '-')} / {result.get('name', '-')}\n")
    stream.write(f"结论      : {'VULNERABLE(需人工确认)' if result.get('vulnerable') else 'NOT-VULNERABLE/UNKNOWN'}\n")
    stream.write(f"把握度    : {result.get('confidence', '-')}\n")
    stream.write(f"响应 sha256: {result.get('sha256_of_response', '-')}\n")
    stream.write(f"请求次数  : {result.get('requests_sent', '-')}（限速 ≥{result.get('interval_s', '-')}s，并发 1）\n")
    ev = result.get("evidence") or []
    if isinstance(ev, str):
        ev = [ev]
    stream.write("证据      :\n")
    for i, e in enumerate(ev, 1):
        stream.write(f"  [{i}] {e}\n")
    notes = result.get("notes") or []
    if notes:
        stream.write("备注      :\n")
        for n in notes:
            stream.write(f"  - {n}\n")
    stream.write("=" * 72 + "\n")


def add_common_args(ap: argparse.ArgumentParser, default_baseurl: str | None = None,
                    skip_baseurl: bool = False) -> argparse.ArgumentParser:
    """挂载公共参数。

    注意：`-u/--baseurl` 与公共参数冲突时，调用方应传 ``skip_baseurl=True``
    自己声明（各漏洞脚本的 baseurl 语义不同：有的是站点根，有的是站点根带子路径）。
    """
    if not skip_baseurl:
        ap.add_argument("-u", "--baseurl", default=default_baseurl or "http://127.0.0.1",
                        help=f"目标基址（默认 {default_baseurl or 'http://127.0.0.1'}）；必须在白名单内，否则直接退出")
    ap.add_argument("--json", action="store_true", help="输出 JSON（target/vulnerable/evidence/sha256_of_response）")
    ap.add_argument("--interval", type=float, default=1.0, help="请求间隔秒数，团队红线 ≥1.0（默认 1.0）")
    ap.add_argument("--timeout", type=float, default=10.0, help="单请求超时秒数（默认 10）")
    return ap


def join(base: str, path: str) -> str:
    """拼接基址与路径，避免 // 与丢 path 前缀。"""
    return base.rstrip("/") + "/" + path.lstrip("/")