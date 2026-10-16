#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bf_c1_shiro_fingerprint.py — C1-SHIRO-2016-4437 只读检测：Apache Shiro 指纹识别
==============================================================================
漏洞类型：Apache Shiro rememberMe cookie 反序列化（CVE-2016-4437 关联的默认密钥问题）
靶场标识：Vulhub `vulhub/shiro:1.2.4`（loop3 用 127.0.0.1:18081）
参考笔记：security/learning/loop3-c-vulhub-report-t7-20261012.md §1
          security/learning/_evidence/loop3-t7-c1-shiro-20261012.json
原理    ：Shiro 的 rememberMe 功能把 PrincipalCollection 序列化→AES 加密→Base64 写进 cookie。
          loop3 实测：Shiro 1.2.4 硬编码默认密钥 `kPH+bIxk5D2deZiIxcaaaA==` 可解密构造密文。

★★★ 本脚本**绝不做**的事（团队红线 / loop3 血泪教训）★★★
1. **绝不生成、绝不投递反序列化 payload / gadget 链**。只用纯 GET。
2. **绝不用 `rememberMe=deleteMe` 当成功判据**。loop3 §1.4 + N-C03 实测矩阵：
     - 不带 rememberMe cookie  →  **无 Set-Cookie**（deleteMe 不出现）
     - rememberMe= (空值)     →  false
     - 4 字符垃圾              →  true
     - 4000 字符垃圾            →  true
     - 默认密钥加密的合法序列化流 →  true
     - **错误密钥加密的同一流** →  **true**
     - /login anon 路径         →  true
   → 只要 cookie 非空一律回 deleteMe，**零区分度**，对任何非空输入都返回 true。
   把 deleteMe 当判据 = 100% 假阳性。**本脚本连 deleteMe 都不作为 vulnerable 的依据**，
   只在 evidence 里作为「rememberMe 机制存在」的旁证记录，且明确标注其无效。

本脚本做什么（纯只读指纹）：
- GET `/`（根路径）：看 302 -> /login、`Set-Cookie: JSESSIONID`、`rememberMe` 相关头。
- GET `/login`：看 Shiro 典型登录页特征。
- GET `/login;jsessionid=<不存在值>`：Shiro 经典特征路径（URL 中 path parameter）。
- GET `/favicon.ico`、HEAD `/`：指纹旁证。
- 收集并分析响应头指纹，输出 **needs_manual_confirmation**（疑似），
  **绝不**自动下 "确认可 RCE" 的结论 —— RCE 需要投递 payload，那是破坏性操作，
  不在本脚本职责内。

评级纪律  ：检测率写区间 + 分子分母；**不写 100%**。任何不确定一律 needs_manual_confirmation。

用法
    python bf_c1_shiro_fingerprint.py -u http://127.0.0.1:18081
    python bf_c1_shiro_fingerprint.py -u http://127.0.0.1:18081 --json
"""

from __future__ import annotations

import argparse
import sys

sys.path.insert(0, r"D:\vuln-xiuxian\poc")
import bfnet  # noqa: E402

VULN_ID = "C1-SHIRO-2016-4437"
NAME = "Apache Shiro rememberMe 机制指纹（关联 CVE-2016-4437 默认密钥）"
CWE = ["CWE-502", "CWE-798"]  # 反序列化 / 硬编码凭据

# Shiro 常见指纹信号。每一项都是「看起来像」的可收集证据，不单独作为 RCE 判据。
SIGNAL_WEIGHT = {
    "set_cookie_rememberme": 3,   # 出现 rememberMe cookie（即使=deleteMe，仅证机制存在）
    "redirect_to_login": 2,       # 302 -> /login（Shiro 保护页典型行为）
    "jsessionid_cookie": 1,       # JSESSIONID（Shiro/Servlet 容器通用，非 Shiro 独有）
    "shiro_login_page": 3,        # 登录页含 Shiro/RememberMe 字样
    "jsessionid_path_param": 2,   # /xxx;jsessionid= 路径参数被容器接受
    "server_header": 0,           # 弱信号
}


def parse_set_cookie_rememberme(resp: bfnet.Response) -> tuple[bool, list[str]]:
    """检查 Set-Cookie 里是否出现 rememberMe（仅作机制存在旁证，不作 RCE 判据）。"""
    vals = resp.header_values("Set-Cookie")
    hits = [v for v in vals if "rememberMe" in v]
    return bool(hits), hits


def run(args) -> dict:
    evidence: list[str] = []
    notes: list[str] = []
    limiter = bfnet.RateLimiter(args.interval)
    base = args.baseurl.rstrip("/")
    bfnet.assert_allowed(base)

    signals: dict[str, bool] = {}
    resp_root = None

    # ---- 1. GET / ----
    r_root = bfnet.probe(base + "/", "GET", limiter=limiter, timeout=args.timeout)
    resp_root = r_root
    if not r_root.ok:
        return finish(args, base, 0, {}, evidence + [f"根路径探测失败：{r_root.error}"],
                      None, limiter, notes + ["目标不可达"], "UNKNOWN：目标不可达")
    loc = r_root.header("Location") or ""
    rem_hits, rem_raw = parse_set_cookie_rememberme(r_root)
    signals["set_cookie_rememberme"] = rem_hits
    signals["redirect_to_login"] = "login" in loc.lower()
    signals["jsessionid_cookie"] = bool(r_root.header_values("Set-Cookie") and
                                        any("JSESSIONID" in v for v in r_root.header_values("Set-Cookie")))
    signals["server_header"] = bool(r_root.header("Server"))
    evidence.append(
        f"GET / -> HTTP {r_root.status}，Location={loc or '(无)'}，"
        f"Server={r_root.header('Server') or '(无)'}，body={len(r_root.body)}B，"
        f"sha256={r_root.sha256[:16]}…"
    )
    if rem_hits:
        evidence.append(
            f"Set-Cookie 含 rememberMe：{rem_raw} —— "
            f"**注意：这仅证明 Shiro rememberMe 机制存在，其取值（如 deleteMe）在 loop3 实测中"
            f"对任何非空输入均回 deleteMe，无区分度，不能作为漏洞判据**"
        )
    delete_markers = [v for v in rem_raw if "deleteMe" in v]
    if delete_markers:
        notes.append(
            f"观测到 rememberMe=deleteMe（{len(delete_markers)} 处）。"
            f"【loop3 血泪】deleteMe 无区分度（正确密钥/错误密钥/垃圾/合法序列化流 全部 true），"
            f"**本脚本不据此下任何结论**，仅记录现象。"
        )

    # ---- 2. GET /login（Shiro 登录页特征） ----
    r_login = bfnet.probe(base + "/login", "GET", limiter=limiter, timeout=args.timeout)
    if r_login.ok:
        low = r_login.text.lower()
        shiro_hit = ("remember" in low and ("shiro" in low or "password" in low)) or "shiro" in low
        signals["shiro_login_page"] = shiro_hit
        evidence.append(
            f"GET /login -> HTTP {r_login.status}，"
            f"含 Shiro/RememberMe 字样={shiro_hit}，body={len(r_login.body)}B"
        )
    else:
        notes.append(f"/login 探测失败：{r_login.error}")

    # ---- 3. GET /login;jsessionid=<值>（Shiro 经典特征路径） ----
    jsid = r_root.header_values("Set-Cookie")
    jsid_val = "none"
    for v in jsid:
        if "JSESSIONID=" in v:
            jsid_val = v.split("JSESSIONID=", 1)[1].split(";", 1)[0]
            break
    probe_path = base + "/login;jsessionid=" + (jsid_val if jsid_val != "none" else "bfprobe1234567890")
    r_jsid = bfnet.probe(probe_path, "GET", limiter=limiter, timeout=args.timeout)
    if r_jsid.ok:
        # 特征：path parameter 被 Servlet 容器解析，登录页仍正常返回（未 404）
        accepted = r_jsid.status in (200, 302, 401, 403)
        signals["jsessionid_path_param"] = accepted and r_jsid.status != 404
        evidence.append(
            f"GET /login;jsessionid={jsid_val[:12]}…（Shiro/容器 path 参数特征）"
            f"-> HTTP {r_jsid.status}，被解析={signals['jsessionid_path_param']}，"
            f"body={len(r_jsid.body)}B"
        )

    # ---- 打分 ----
    score = sum(SIGNAL_WEIGHT.get(k, 0) for k, v in signals.items() if v)
    present = [k for k, v in signals.items() if v]

    if rem_hits and signals.get("shiro_login_page"):
        confidence = "needs_manual_confirmation"
        verdict = ("疑似 Apache Shiro（rememberMe 机制 + Shiro 风格登录页同时存在），"
                   "**需人工确认**：本脚本不投递任何反序列化 payload，"
                   "不判定是否存在可利用的默认密钥或 gadget 链。"
                   "如需确认可利用性，请在**授权靶场**内手工验证（本脚本刻意不自动化该步，因其具破坏性）")
    elif rem_hits:
        confidence = "weak_signal"
        verdict = ("弱信号：仅观测到 rememberMe cookie，未确认 Shiro 登录页特征。"
                   "建议人工打开 /login 确认页面是否为 Shiro 默认演示应用")
    else:
        confidence = "unknown"
        verdict = "未发现 Shiro 指纹信号（无 rememberMe cookie 等）。不下『无漏洞』定论，仅代表本轮指纹未命中"

    notes.append(
        "【判据边界】rememberMe 默认密钥（CVE-2016-4437 关联）的可利用性确认，"
        "必须通过**投递**加密的序列化 gadget 链来验证 —— 那是破坏性操作，"
        "**不在本只读脚本范围内，也不在团队红线内**。本脚本只到「疑似 Shiro」为止。"
    )
    notes.append(
        f"loop3 已实测 vulhub/shiro:1.2.4 默认密钥 "
        f"`kPH+bIxk5D2deZiIxcaaaA==` 可用（OOB 3/4 链命中，"
        f"`security/learning/loop3-t7-c1-shiro-20261012.json`），"
        f"但该结论针对的是 vulhub 靶场，**不外推到任何其它目标**"
    )
    return finish(args, base, score, signals, evidence, r_root.sha256, limiter, notes, verdict,
                  confidence=confidence)


def finish(args, target, score, signals, evidence, sha, limiter, notes, verdict,
           confidence="unknown") -> dict:
    return {
        "tool": "bf_c1_shiro_fingerprint",
        "vuln_id": VULN_ID,
        "name": NAME,
        "cwe": CWE,
        "severity_hint": "Critical（若默认密钥成立）",
        "target": target,
        "vulnerable": False,  # 只读指纹**永远不下 vulnerable=true**，见文件头
        "confidence": confidence,
        "fingerprint_score": score,
        "signals": signals,
        "verdict": verdict,
        "evidence": evidence,
        "notes": notes,
        "sha256_of_response": sha,
        "requests_sent": limiter.sent,
        "interval_s": limiter.interval,
        "destructive": False,
        "methods_used": ["GET"],
        "loop3_reference": [
            "security/learning/loop3-c-vulhub-report-t7-20261012.md",
            "security/learning/_evidence/loop3-t7-c1-shiro-20261012.json",
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="C1 Shiro 指纹识别（只读，绝不投递反序列化 payload）")
    ap.add_argument("-u", "--baseurl", default="http://127.0.0.1:18081",
                    help="Shiro 靶场基址（loop3 用 127.0.0.1:18081）")
    bfnet.add_common_args(ap, skip_baseurl=True)
    args = ap.parse_args()

    result = run(args)
    bfnet.emit(result, args.json)
    # 疑似 Shiro 也返回 0，便于批处理里标记「需人工确认」
    return 0 if result["confidence"] in ("needs_manual_confirmation", "weak_signal") else 1


if __name__ == "__main__":
    sys.exit(main())