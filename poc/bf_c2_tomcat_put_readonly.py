#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bf_c2_tomcat_put_readonly.py — C2-TOMCAT-2017-12615 只读检测：Tomcat DefaultServlet 可写性
=============================================================================================
漏洞类型：Apache Tomcat DefaultServlet readonly=false 导致任意文件上传 / JSP 执行（CVE-2017-12615）
靶场标识：Vulhub `vulhub/tomcat-cve-2017-12615` / `vulhub/tomcat:8.5.19`（loop3 用 127.0.0.1:18082）
参考笔记：security/learning/loop3-c-vulhub-report-t7-20261012.md §2
          security/learning/_evidence/loop3-t7-c2-tomcat-put-raw.txt
原理    ：Tomcat 的 DefaultServlet 有 readonly 初始化参数（默认 true = 拒 PUT/DELETE）。
          CVE-2017-12615 靶场把 `conf/web.xml` 里 DefaultServlet 的 readonly 显式改为 false，
          任意 PUT 都会写进 webapps。真正的利用点：Servlet 映射只让 `.jsp` 走 JspServlet（禁 PUT），
          **在文件名后加尾部斜杠 `PUT /x.jsp/`** 才能命中 DefaultServlet 的写路径，
          落盘时去掉末尾斜杠得到 `x.jsp` —— 一个可执行 JSP。**尾部斜杠是绕过后缀白名单的必要条件。**

★★★ 本脚本为什么不做 PUT（团队红线 + loop3 教训）★★★
1. 队长纪律：**不做 PUT 验证**（写操作），nuclei 模板里的 PUT 规则必须标「破坏性」+ 默认 disable。
2. loop3 N-C04 实测：**HTTP DELETE 返回 405**（.jsp 归 JspServlet 管，其 HttpJspBase 无 doDelete；
   readonly=false 只影响 DefaultServlet）。→ 「能 PUT」不等于「能 DELETE」，
   收尾路径不能靠 HTTP。**这也反证了 HTTP 写方法路径本身是有副作用的**，
   不该被只读脚本触碰。
3. 本脚本只做**只读探测**：
   - `OPTIONS /<probe>.jsp/` → 看 DefaultServlet 是否宣告 PUT（`Allow: PUT, …` 或 `Public` 头）。
   - `OPTIONS /<probe>.txt/`  → 对照（普通静态路径）。
   - `HEAD /` 与 `/` 响应头 → 取 `Server`（Tomcat 指纹）。
   - `GET`/`HEAD` 一个 Tomcat 默认特征路径（如 `/manager/html`、`/host-manager/html`）确认容器。
   全部为 GET/HEAD/OPTIONS，只读，不写目标文件系统。

评级纪律  ：只输出「疑似 DefaultServlet 可写 / 未见证据」+ 证据，
          **绝不自动下『CVE-2017-12615 成立』**（确认需真实 PUT，属破坏性）。
          检测率写区间 + 分子分母，不写 100%。

用法
    python bf_c2_tomcat_put_readonly.py -u http://127.0.0.1:18082
    python bf_c2_tomcat_put_readonly.py -u http://127.0.0.1:18082 --json
"""

from __future__ import annotations

import argparse
import re
import sys

sys.path.insert(0, r"D:\bounty-forge\poc")
import bfnet  # noqa: E402

VULN_ID = "C2-TOMCAT-2017-12615"
NAME = "Tomcat DefaultServlet 可写（readonly=false）只读指纹"
CWE = ["CWE-434", "CWE-732"]  # 危险类型上传 / 错误权限配置

TOMCAT_SERVER_RE = re.compile(r"Apache-Coyote|Apache Tomcat|Tomcat/\d", re.I)


def options_probe(base: str, path: str, limiter, timeout) -> bfnet.Response:
    """OPTIONS 探测（只读方法）。bfnet.probe 只放行 GET/HEAD，这里直接用 urllib 发 OPTIONS。"""
    import time
    import urllib.error
    import urllib.request

    from bfnet import _OPENER  # 复用同一 opener（禁重定向、同一 UA）
    limiter.wait()
    req = urllib.request.Request(base.rstrip("/") + path, method="OPTIONS",
                                 headers={"User-Agent": "bounty-forge-detector/1.0 (read-only, local lab)"})
    t0 = time.monotonic()
    try:
        with _OPENER.open(req, timeout=timeout) as fp:
            body = fp.read()
            return bfnet.Response(req.full_url, "OPTIONS", fp.status, list(fp.getheaders()), body,
                                  None, time.monotonic() - t0)
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:  # noqa: BLE001
            body = b""
        return bfnet.Response(req.full_url, "OPTIONS", e.code, list(e.headers.items()), body,
                              None, time.monotonic() - t0)
    except Exception as e:  # noqa: BLE001
        return bfnet.Response(req.full_url, "OPTIONS", None, [], b"",
                              f"{type(e).__name__}: {e}", time.monotonic() - t0)


def run(args) -> dict:
    evidence: list[str] = []
    notes: list[str] = []
    limiter = bfnet.RateLimiter(args.interval)
    base = args.baseurl.rstrip("/")
    bfnet.assert_allowed(base)

    # ---- 1. 根路径：确认 Tomcat 指纹 ----
    r_root = bfnet.probe(base + "/", "GET", limiter=limiter, timeout=args.timeout)
    if not r_root.ok:
        return finish(args, base, evidence + [f"根路径探测失败：{r_root.error}"], None,
                      limiter, notes + ["目标不可达"], "UNKNOWN：目标不可达")
    server = r_root.header("Server") or ""
    is_tomcat = bool(TOMCAT_SERVER_RE.search(server)) or bool(
        TOMCAT_SERVER_RE.search(r_root.text[:2000]))
    evidence.append(
        f"GET / -> HTTP {r_root.status}，Server={server or '(无)'}，"
        f"Tomcat 指纹={is_tomcat}，body={len(r_root.body)}B，sha256={r_root.sha256[:16]}…"
    )

    # ---- 2. OPTIONS 带尾斜杠的 .jsp/ 路径（DefaultServlet 可写信号） ----
    probe_jsp = args.probe_name.rstrip("/") + "/"
    r_opt_jsp = options_probe(base, "/" + probe_jsp, limiter, args.timeout)
    allow_jsp = " ".join(r_opt_jsp.header_values("Allow")) + " " + (r_opt_jsp.header("Public") or "")
    jsp_put_advertised = bool(re.search(r"\bPUT\b", allow_jsp, re.I))
    evidence.append(
        f"OPTIONS /{probe_jsp}（**带尾斜杠**，DefaultServlet 写路径特征）-> HTTP {r_opt_jsp.status}，"
        f"Allow/Public={allow_jsp.strip() or '(无)'}，宣告 PUT={jsp_put_advertised}"
    )

    # ---- 3. OPTIONS 普通静态路径（对照） ----
    probe_txt = args.probe_name.rstrip("/") + ".txt/"
    r_opt_txt = options_probe(base, "/" + probe_txt, limiter, args.timeout)
    allow_txt = " ".join(r_opt_txt.header_values("Allow")) + " " + (r_opt_txt.header("Public") or "")
    txt_put_advertised = bool(re.search(r"\bPUT\b", allow_txt, re.I))
    evidence.append(
        f"OPTIONS /{probe_txt}（对照，普通静态路径）-> HTTP {r_opt_txt.status}，"
        f"Allow/Public={allow_txt.strip() or '(无)'}，宣告 PUT={txt_put_advertised}"
    )

    # ---- 4. Tomcat 管理端特征路径（确认是标准 Tomcat 布局） ----
    mgr_hits = []
    for p in ("/manager/html", "/host-manager/html"):
        r = bfnet.probe(base + p, "HEAD", limiter=limiter, timeout=args.timeout)
        if r.ok and r.status in (200, 401, 403):
            mgr_hits.append(f"{p}->{r.status}")
    if mgr_hits:
        evidence.append(f"Tomcat 管理端特征路径响应：{', '.join(mgr_hits)}（标准 Tomcat 布局）")

    # ---- 定性 ----
    if is_tomcat and (jsp_put_advertised or txt_put_advertised):
        confidence = "needs_manual_confirmation"
        verdict = ("疑似 Tomcat 且 DefaultServlet 宣告接受 PUT —— 可能存在 readonly=false。"
                   "**注意：OPTIONS 宣告 PUT 只是弱信号**，"
                   "Tomcat 可能在 OPTIONS 里统一宣告方法而实际 PUT 仍被拒。"
                   "确认 CVE-2017-12615 成立必须真实发 PUT（写操作，破坏性，"
                   "**本脚本与团队红线均不做**）。"
                   f"若在授权靶场人工验证：PUT /{probe_jsp} 应回 201，"
                   f"随后 GET /{probe_jsp.rstrip('/')} 应 200 并执行 JSP。")
    elif is_tomcat:
        confidence = "weak_signal"
        verdict = ("是 Tomcat，但 OPTIONS 未宣告 PUT —— readonly 可能为默认 true（漏洞不成立），"
                   "或 OPTIONS 不宣告方法（弱信号）。不下『无漏洞』定论。")
    else:
        confidence = "unknown"
        verdict = "未见 Tomcat 指纹。目标可能不是 Tomcat，或指纹未命中；不下『无漏洞』定论。"

    notes.append(
        "【红线声明】本脚本**从不发 PUT/POST/DELETE**，只发 GET/HEAD/OPTIONS。"
        "nuclei 模板 `C2-TOMCAT-2017-12615-PUT-确认.yaml` 中确有 PUT 规则，"
        "但已标 `destructive` tag 且**默认不启用**，仅供授权靶场手动确认。"
    )
    notes.append(
        "【loop3 教训】利用 `PUT /x.jsp/` 必须带**尾部斜杠**——这是绕过后缀白名单"
        "（.jsp 归 JspServlet，禁 PUT）的**必要条件**，去掉斜杠 100% 失败。"
        "loop3 首次实测 PUT 返回 204（非 201）也成功，以第二轮到 201 为准。"
    )
    notes.append(
        "【loop3 N-C04】HTTP DELETE 对已上传 JSP 返回 **405**（.jsp 归 JspServlet，其 "
        "HttpJspBase 无 doDelete）。→ 「能 PUT」≠「能 DELETE」；若日后人工验证，"
        "清理必须走容器内 rm，不能指望 HTTP DELETE。"
    )
    return finish(args, base, evidence, r_root.sha256, limiter, notes, verdict, confidence=confidence)


def finish(args, target, evidence, sha, limiter, notes, verdict, confidence="unknown") -> dict:
    return {
        "tool": "bf_c2_tomcat_put_readonly",
        "vuln_id": VULN_ID,
        "name": NAME,
        "cwe": CWE,
        "severity_hint": "Critical（若 readonly=false 且 PUT 可用）",
        "target": target,
        "vulnerable": False,  # 只读探测不下 vulnerable=true，确认需真实 PUT（破坏性）
        "confidence": confidence,
        "verdict": verdict,
        "evidence": evidence,
        "notes": notes,
        "sha256_of_response": sha,
        "requests_sent": limiter.sent,
        "interval_s": limiter.interval,
        "destructive": False,
        "methods_used": ["GET", "HEAD", "OPTIONS"],
        "loop3_reference": [
            "security/learning/loop3-c-vulhub-report-t7-20261012.md",
            "security/learning/_evidence/loop3-t7-c2-tomcat-put-raw.txt",
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="C2 Tomcat DefaultServlet 可写性只读指纹（不发 PUT/POST/DELETE）")
    ap.add_argument("-u", "--baseurl", default="http://127.0.0.1:18082",
                    help="Tomcat 靶场基址（loop3 用 127.0.0.1:18082）")
    ap.add_argument("--probe-name", default="bfc2probe.jsp",
                    help="探测用文件名（仅出现在 OPTIONS 请求里，不写入任何文件）")
    bfnet.add_common_args(ap, skip_baseurl=True)
    args = ap.parse_args()

    result = run(args)
    bfnet.emit(result, args.json)
    return 0 if result["confidence"] in ("needs_manual_confirmation", "weak_signal") else 1


if __name__ == "__main__":
    sys.exit(main())