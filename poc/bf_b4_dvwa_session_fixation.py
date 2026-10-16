#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bf_b4_dvwa_session_fixation.py — B4-SESSION-01 只读检测：DVWA 会话固定 + 弱会话 ID
==============================================================================
漏洞类型：会话固定（Session Fixation），CWE-384；可预测会话 ID，CWE-330
靶场标识：DVWA `dvwa_start_session()` + `/vulnerabilities/weak_id/`
参考笔记：security/learning/loop3-b-dvwa-bwapp-report-t4-20261012.md §1（B4-SESSION-01）
          security/learning/_evidence/verified-loop3-b-b4-session-20261012-2236.json
原理    ：DVWA 的 low/medium/high 档在 `dvwa_start_session()` 里走
          `if (isset($_COOKIE[session_name()])) session_id($_COOKIE[session_name()]);`
          —— 源码注释直言 "we want to allow session fixation attacks"。
          只有 `impossible` 档才 `session_regenerate_id()`。
非破坏性：本脚本**只发 GET**。核心检测手段是「投一个自造、绝不可能被服务端预先创建过的
          PHPSESSID 出去，看服务端认不认」——**不需要登录、不改密码、不写库**。
          自造 ID 形如 `bffix<32 hex>`，与真实会话命名空间不冲突。
          本脚本**不会**尝试接管他人会话、不爆破别人的 cookie。
关键实测数据（loop3 §6.1，务必照抄不要自己拍）：
  - **DVWA 的档位 cookie 叫 `security`，不叫 `security_level`**（那是 bWAPP 的命名）。
    用 `security_level=low` 会被判成 impossible → 触发 session_regenerate_id →
    现象是「会话被再生成」，而不是「会话固定」，**必假阴性**。这是 loop3 两轮假阴性的同一个根因。
  - weak_id 档位序列：low = 1,2,3,4,5,6,7（完美自增，可预测）；
    medium = unix 时间戳（步长不稳，未证实可预测）；
    high = md5(1..7)（可离线穷举）；impossible = bin2hex(random_bytes(20))。
评级纪律  ：**不可测 ≠ 不可用**。未提供 cookie 时只能给出 needs_manual_confirmation，
          绝不据此下「无漏洞」结论。
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys

sys.path.insert(0, r"D:\vuln-xiuxian\poc")
import bfnet  # noqa: E402

VULN_ID = "B4-SESSION-01"
NAME = "DVWA 会话固定 + 弱会话 ID"
CWE = ["CWE-384", "CWE-330"]

# DVWA 真实档位 cookie 名。**不是 security_level**（loop3 踩过，见文件头）。
SECURITY_COOKIE = "security"
# 正常登录会话里会出现、匿名态不会出现的标记
LOGGED_IN_MARKERS = ("logout.php", "Security: Impossible", "Logout")


def make_fake_sid(tag: str = "bffix") -> str:
    """造一个自造的会话 ID：前缀 + 32 位 hex（loop3 用的也是 vrf<32hex> 形式）。

    前缀 bffix 保证「服务端不可能已创建过这个会话」，于是
    「服务端认了它」= 「它可以当任意攻击者自选会话使用」= 会话固定的直接证据。
    """
    digest = hashlib.sha256(f"{tag}:{sys.argv}".encode()).hexdigest()[:32]
    return f"{tag}{digest}"


def md5(n: int) -> str:
    return hashlib.md5(str(n).encode()).hexdigest()


def parse_cookie_header(raw: str) -> dict:
    out = {}
    for part in raw.split(";"):
        part = part.strip()
        if part and "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def detect_weak_id(responses: list, evidence: list) -> dict | None:
    """从一组已登录 weak_id 页面的响应里提取 PHPSESSID 序列，判断是否可预测。"""
    seq = []
    for r in responses:
        vals = r.header_values("Set-Cookie")
        for v in vals:
            m = re.search(r"PHPSESSID=([0-9a-fA-F]+)", v)
            if m:
                seq.append(m.group(1))
    if len(seq) < 2:
        return None
    nums = []
    for s in seq:
        try:
            nums.append(int(s))
        except ValueError:
            nums = []
            break
    info = {"sequence": seq}
    if len(nums) == len(seq) and len(nums) >= 2:
        diffs = [nums[i + 1] - nums[i] for i in range(len(nums) - 1)]
        info["all_numeric"] = True
        info["diffs"] = diffs
        info["is_sequential"] = all(d == 1 for d in diffs)
    return info


def run(args) -> dict:
    evidence: list[str] = []
    notes: list[str] = []
    limiter = bfnet.RateLimiter(args.interval)
    bfnet.assert_allowed(args.baseurl)

    cookies = parse_cookie_header(args.cookie) if args.cookie else {}
    notes.append(f"档位 cookie 名提醒：DVWA 用 `{SECURITY_COOKIE}=low`，"
                 f"`security_level=low` 会被当成 impossible 触发会话再生成（假阴性根因，loop3 踩过两次）")

    # ---- 1. 自造会话 ID 探针 ----
    # loop3 §6.1 的真实顺序（这里踩过一次坑）：
    #   匿名投自造 SID → DVWA 未认证 → 直接 302 login.php → preserved=False
    #   这是**假阴性**，不是「无漏洞」。会话固定要成立，必须让这个自造 SID
    #   **先被一次成功的登录创建过**，再由陌生客户端复用。
    # 所以本脚本的核心判据是「陌生客户端带同一个 SID 能否进已认证页」，
    # 而调用方必须提供一个**已知可复现的、已被 DVWA 认证过的会话**（--cookie）。
    # 没有 --cookie 时，脚本只输出探测事实，不下结论。
    fake_sid = make_fake_sid()
    forged_headers = {"Cookie": f"PHPSESSID={fake_sid}"}
    if cookies:
        forged_headers["Cookie"] += f"; " + "; ".join(f"{k}={v}" for k, v in cookies.items() if k != "PHPSESSID")

    r_forged = bfnet.probe(args.baseurl.rstrip("/") + "/index.php", "GET",
                           headers=forged_headers, limiter=limiter, timeout=args.timeout)
    if not r_forged.ok:
        return finish(args, False, evidence + [f"探测请求失败：{r_forged.error}"], None, limiter,
                      notes + ["端点不可达"], "UNKNOWN：目标不可达")

    issued = []
    for v in r_forged.header_values("Set-Cookie"):
        m = re.search(r"PHPSESSID=([0-9a-fA-F]+)", v)
        if m:
            issued.append(m.group(1))
    preserved = fake_sid in issued
    evidence.append(
        f"投自造 PHPSESSID={fake_sid}（服务端不可能预先创建过此会话）-> HTTP {r_forged.status}，"
        f"服务端回发 Set-Cookie 的 PHPSESSID={issued or '(无)'}，"
        f"preserved={preserved}"
    )
    if preserved:
        evidence.append(
            f"★ 会话固定证据：服务端接受并回发了攻击者自选的会话 ID {fake_sid}，"
            f"未做 session_regenerate_id() 替换"
        )
    else:
        notes.append(
            "preserved=False：服务端回发了自己生成的会话 ID（session_regenerate_id 生效）。"
            "这通常意味着当前处于 impossible 档，或未带正确档位 cookie。"
            "→ 按「不可测 ≠ 不可用」处理，见下方人工确认步骤。"
        )

    # ---- 2. 会话复用探测（核心判据）----
    # 逻辑：拿 --cookie 里那个**已经认证过的** PHPSESSID，用一个「全新、不带其它 cookie、
    # 不带会话」的干净请求去复用它。
    #   - 能进已认证页 → 会话固定链成立（loop3 §6.1：陌生客户端仅带该 ID 即 200 + logout.php）
    #   - 进不去       → 会话已被服务端绑定到具体客户端（IP/UA）或被重新生成
    # 注意：这是**只读复用已有会话**，脚本不新建会话、不登录、不改任何账号状态。
    reuse_verdict = None
    if cookies.get("PHPSESSID"):
        reuse_sid = cookies["PHPSESSID"]
        # 干净请求：只带这一个 cookie，不带档位 cookie —— 排除「档位 cookie 影响」的混淆
        r_reuse = bfnet.probe(args.baseurl.rstrip("/") + "/index.php", "GET",
                              headers={"Cookie": f"PHPSESSID={reuse_sid}"},
                              limiter=limiter, timeout=args.timeout)
        if r_reuse.ok:
            logged_in = any(m in r_reuse.text for m in LOGGED_IN_MARKERS)
            has_logout = "logout.php" in r_reuse.text
            evidence.append(
                f"陌生客户端仅带已认证 SID={reuse_sid[:12]}…（不带档位 cookie）"
                f"访问 /index.php -> HTTP {r_reuse.status}，"
                f"已登录标记={logged_in}，含 logout.php={has_logout}"
            )
            if logged_in or has_logout:
                reuse_verdict = True
                evidence.append(
                    "★ 会话可被陌生客户端复用：仅凭会话 ID 即进入已认证页面 —— "
                    "会话固定链完整（固定 → 受害者在该会话下登录 → 攻击者凭同一 ID 复用）"
                )
            else:
                reuse_verdict = False
                notes.append(
                    "已认证 SID 在干净请求下未能进入已认证页（HTTP "
                    f"{r_reuse.status}）→ 会话或被服务端绑定到客户端、或已被重新生成。"
                    "**不下『无漏洞』结论**：需按下方人工步骤在登录瞬间测试"
                )
        else:
            reuse_verdict = None
            notes.append(f"会话复用探测失败：{r_reuse.error}")
    else:
        notes.append(
            "未提供 PHPSESSID，跳过会话复用检测（核心判据）。"
            "会话固定必须有一个「已被认证的会话」才能测；本脚本不执行登录。"
        )

    # ---- 3. weak_id 可预测性（仅在已登录、且已明确 low/high 档时有意义） ----
    weak = None
    if cookies.get(SECURITY_COOKIE) in ("low", "high"):
        weak_responses = []
        for _ in range(min(args.weak_samples, 7)):
            r = bfnet.probe(args.baseurl.rstrip("/") + "/vulnerabilities/weak_id/", "GET",
                            headers=forged_headers, limiter=limiter, timeout=args.timeout)
            if r.ok:
                weak_responses.append(r)
        weak = detect_weak_id(weak_responses, evidence)
        if weak:
            if weak.get("is_sequential"):
                evidence.append(
                    f"★ weak_id 可预测：取到 PHPSESSID 序列 {weak['sequence']}，"
                    f"相邻差值全为 1（完美自增，可离线预测下一条会话 ID）"
                )
            elif len(weak.get("sequence", [])) == len([s for s in weak["sequence"] if len(s) == 32]) \
                    and all(len(s) == 32 and re.fullmatch(r"[0-9a-f]{32}", s) for s in weak["sequence"]):
                evidence.append(
                    f"weak_id 序列 {weak['sequence']}，全部为 32 位 hex（疑似 md5 或 random_bytes），"
                    f"需人工判断是否可离线穷举（loop3：high 档 = md5(1..n)，可穷举；"
                    f"impossible 档 = random_bytes，真随机）"
                )
    else:
        notes.append(
            f"未提供 {SECURITY_COOKIE}=low/high 档 cookie，跳过 weak_id 序列采样"
            f"（当前 security 档位 = {cookies.get(SECURITY_COOKIE, '(未提供)')}）"
        )

    # ---- 定性 ----
    # 三条判据取并集：自造 SID 被保留 / 已认证 SID 可被陌生客户端复用 / weak_id 可预测。
    # 任何一条成立即标 vulnerable（会话固定 + 弱会话 ID 是两个相关但独立的问题）。
    strong = []
    if preserved:
        strong.append("服务端接受并回发攻击者自选会话 ID（preserved=True，未做 session_regenerate_id）")
    if reuse_verdict is True:
        strong.append("已认证会话 ID 可被陌生客户端单独复用进入已认证页面")
    if weak and weak.get("is_sequential"):
        strong.append(f"weak_id 序列 {[int(s) for s in weak['sequence']]} 完美自增，可离线预测")

    vuln = bool(strong)
    if vuln:
        verdict = "VULNERABLE：" + "；".join(strong)
    else:
        verdict = ("UNKNOWN（不下『无漏洞』定论）：本轮三条判据均未成立。"
                   "可能原因：① 未提供已认证会话（--cookie），核心判据无法执行；"
                   "② 档位 cookie 缺失或档位为 impossible（防线生效，loop3 实测 impossible 档 preserved=False）；"
                   "③ 会话被服务端绑定到客户端。"
                   "loop3 实测 low 档该漏洞成立（3/3），人工确认步骤见 notes")
    if weak and not weak.get("is_sequential") and weak.get("all_numeric"):
        notes.append(
            f"weak_id 采样：序列 {weak['sequence']} 为纯数字，"
            f"相邻差值 {weak.get('diffs')} —— 步长不稳，**不主张可预测**"
            "（loop3 VN-07 同结论：medium 档未证实可预测）"
        )
    return finish(args, vuln, evidence, r_forged.sha256, limiter, notes, verdict)


def finish(args, vulnerable, evidence, sha, limiter, notes, verdict) -> dict:
    return {
        "tool": "bf_b4_dvwa_session_fixation",
        "vuln_id": VULN_ID,
        "name": NAME,
        "cwe": CWE,
        "severity_hint": "High",
        "target": args.baseurl,
        "vulnerable": vulnerable,
        "confidence": "confirmed_by_response" if vulnerable else "unknown",
        "verdict": verdict,
        "evidence": evidence,
        "notes": notes,
        "sha256_of_response": sha,
        "requests_sent": limiter.sent,
        "interval_s": limiter.interval,
        "destructive": False,
        "methods_used": ["GET"],
        "loop3_reference": [
            "security/learning/loop3-b-dvwa-bwapp-report-t4-20261012.md",
            "security/learning/_evidence/verified-loop3-b-b4-session-20261012-2236.json",
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="B4-SESSION-01 只读检测（DVWA 会话固定 + 弱会话 ID）")
    ap.add_argument("-u", "--baseurl", default="http://127.0.0.1",
                    help="DVWA 站点基址（必须是已登录会话的站点）")
    ap.add_argument("--cookie", default="",
                    help="可选：使用者自己已登录的 cookie（PHPSESSID=xxx; security=low）。"
                         "档位 cookie 名是 security，不是 security_level")
    ap.add_argument("--try-anon", action="store_true",
                    help="（已并入核心流程，保留此参数仅为向后兼容，不再产生额外请求）")
    ap.add_argument("--weak-samples", type=int, default=5,
                    help="weak_id 序列采样次数（默认 5，上限 7）")
    bfnet.add_common_args(ap, skip_baseurl=True)
    args = ap.parse_args()

    result = run(args)
    bfnet.emit(result, args.json)
    return 0 if result["vulnerable"] else 1


if __name__ == "__main__":
    sys.exit(main())