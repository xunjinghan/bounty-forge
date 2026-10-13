#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
loop3-t9-summary.py —— Loop 3 三档横向对比 · 取数与自检脚本（mentor-loop3 / t9）

铁律（对齐 t9 任务书）：
  1) 只从**产物文件**取数（笔记 / 报告 / 证据 JSON / 目录扫描），**禁止从任务汇报文字取数**。
  2) 成本双口径：口径 A（余额差值）+ 口径 B（调用量，按 provider 拆分），两者含义必须写明。
  3) 引用存续性自检：所有引用的产物文件必须存在，missing 必须为 0。
  4) 复现率禁止 100%；证据引用禁止省略号。

本脚本零网络请求、零靶场访问，只读本地文件 + 算 sha256。
输出：security/learning/_evidence/loop3-t9-summary-<日期>.json
"""
import os, sys, json, hashlib, datetime, glob

WS = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace"
LEARN = os.path.join(WS, "security", "learning")
EV = os.path.join(LEARN, "_evidence")
LEDGER = os.path.join(os.path.expanduser("~"), ".dsh", "storages", "cost-meter", "ledger.json")
STATS = os.path.join(os.path.expanduser("~"), ".dsh", "our-free-model", "stats.json")
DAY = "2026-10-12"


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest().upper()


def meta(rel):
    p = os.path.join(WS, rel.replace("/", os.sep))
    if not os.path.exists(p):
        return {"path": rel, "exists": False}
    st = os.stat(p)
    return {
        "path": rel,
        "exists": True,
        "bytes": st.st_size,
        "mtime": datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        "sha256": sha256(p) if st.st_size < 8 << 20 else "SKIPPED_TOO_LARGE",
    }


def dirmd(rel):
    """统计某目录下 .md 篇数（只读目录扫描）"""
    p = os.path.join(LEARN, rel)
    if not os.path.isdir(p):
        return {"dir": rel, "exists": False, "md": 0, "files": []}
    fs = sorted(f for f in os.listdir(p) if f.endswith(".md"))
    return {"dir": rel, "exists": True, "md": len(fs), "files": fs}


def evcount(pattern):
    return sorted(f for f in os.listdir(EV) if pattern in f and os.path.isfile(os.path.join(EV, f)))


# ---------- 1. 三档产物清单 ----------
ARTIFACTS = {
    "A": [
        "security/learning/hardening/A-档验证报告-20261012.md",
        "security/learning/hardening/A-档加固实施报告-t2-20261012.md",
        "security/learning/hardening/HARD-01-A档六处加固原理与落地diff.md",
        "security/learning/hardening/HARD-02-A档残余绕过与阴性留证.md",
        "security/learning/_evidence/loop3-a-verify-20261012-212153.json",
    ],
    "B": [
        "security/learning/loop3-b-dvwa-bwapp-report-t4-20261012.md",
        "security/learning/path-traversal/B1-LFI-01-DVWA文件包含路径穿越与phpfilter源码读取.md",
        "security/learning/xxe/B2-XXE-01-bWAPP原生XXE关卡实体展开与外部实体阻断.md",
        "security/learning/csrf/B3-CSRF-01-bWAPP真实CSRF与token对照.md",
        "security/learning/auth-bypass/B4-SESSION-01-DVWA会话固定与弱会话ID.md",
        "security/learning/xss/B5-XSS-01-DVWA存储型XSS到会话劫持完整链.md",
        "security/learning/xxe/N-B03-B04-B05-bWAPP-XXE外部实体未复现.md",
        "security/learning/csrf/N-B01-B02-B06-CSRFimg形态与RFI未复现.md",
        "security/learning/N-LOOP3-B-COVERAGE-B档分类覆盖声明.md",
        "security/learning/_evidence/verified-loop3-b-20261012-2236.md",
        "security/learning/_evidence/verified-loop3-b-20261012-2236.json",
        "security/learning/_evidence/loop3-t4-probe13.json",
    ],
    "C": [
        "security/learning/loop3-c-vulhub-report-t7-20261012.md",
        "security/learning/loop3-c-c1-oracle-verdict-20261012.md",
        "security/learning/cve/C1-SHIRO-2016-4437-rememberMe反序列化默认密钥.md",
        "security/learning/cve/C2-TOMCAT-2017-12615-PUT上传配置缺陷.md",
        "security/learning/cve/N-C01-COMMONS-COLLECTIONS-2未复现.md",
        "security/learning/_evidence/loop3-t7-c1-rate-and-baseline-20261012.json",
        "security/learning/_evidence/t7-shiro-full-dockerlogs.txt",
        "security/learning/_evidence/loop3-t7-c1-shiro-20261012.json",
        "security/learning/_evidence/loop3-t7-c1-oob.jsonl",
        "security/learning/_evidence/loop3-t7-c2-tomcat-put-raw.txt",
        "security/learning/_evidence/loop3-t7-c2-cleanup-raw.txt",
    ],
}

artifacts = {k: [meta(r) for r in v] for k, v in ARTIFACTS.items()}
missing = [m["path"] for k in artifacts for m in artifacts[k] if not m["exists"]]

# ---------- 2. 笔记目录现状（目录扫描，非汇报取数） ----------
note_dirs = ["path-traversal", "xxe", "csrf", "auth-bypass", "xss", "cve", "hardening",
             "business-logic", "file-upload", "ssrf", "idor", "sql-injection", "ssti",
             "command-injection"]
dir_stats = [dirmd(d) for d in note_dirs]

# ---------- 3. 成本双口径 ----------
led = json.load(open(LEDGER, encoding="utf-8"))
day = led["days"][DAY]
br = led["balanceRef"]

prov = {}
for s in day["sessions"]:
    for k, v in s.get("byProviderModel", {}).items():
        a = prov.setdefault(k, {"calls": 0, "input": 0, "output": 0, "cacheRead": 0,
                                "reasoning": 0, "cost_nominal": 0.0})
        for f in ("calls", "input", "output", "cacheRead", "reasoning"):
            a[f] += v.get(f, 0) or 0
        a["cost_nominal"] += v.get("cost", 0.0) or 0.0

# 按档位窗口归属（按**会话起始时间**切；方法与其局限见交付物）
def ms(h, m, s=0):
    return int(datetime.datetime(2026, 10, 12, h, m, s).timestamp() * 1000)


WINDOWS = {
    "A 档（21:08:47–21:30:00）": (ms(21, 8, 47), ms(21, 30, 0)),
    "B 档（21:30:00–22:57:00）": (ms(21, 30, 0), ms(22, 57, 0)),
    "C 档（22:57:00–t9 取数时）": (ms(22, 57, 0), 1 << 62),
}
win = {}
for label, (lo, hi) in WINDOWS.items():
    acc = {"calls": 0, "input": 0, "output": 0, "cacheRead": 0, "cost_nominal": 0.0,
           "sessions": [], "by_provider": {}}
    for s in day["sessions"]:
        at = s.get("at")
        if at is None or not (lo <= at < hi):
            continue
        acc["sessions"].append({"id": s["id"], "at": datetime.datetime.fromtimestamp(at / 1000).strftime("%H:%M:%S"),
                                "calls": s.get("calls", 0), "cost_nominal": s.get("cost", 0.0),
                                "providers": sorted(s.get("byProviderModel", {}).keys())})
        for f in ("calls", "input", "output", "cacheRead"):
            acc[f] += s.get(f, 0) or 0
        acc["cost_nominal"] += s.get("cost", 0.0) or 0.0
        for k, v in s.get("byProviderModel", {}).items():
            p = acc["by_provider"].setdefault(k, {"calls": 0, "cost_nominal": 0.0})
            p["calls"] += v.get("calls", 0) or 0
            p["cost_nominal"] += v.get("cost", 0.0) or 0.0
    win[label] = acc

# 免费车道可靠性
st = json.load(open(STATS, encoding="utf-8"))
free = {"requests": st.get("requests"), "failedRequests": st.get("failedRequests"),
        "models": {k: {"calls": v.get("calls"), "failed": v.get("failed")}
                   for k, v in st.get("models", {}).items()}}

out = {
    "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "generated_by": "mentor-loop3 / t9",
    "task": "t9 三档横向对比表与记忆回写",
    "method_note": "全部数字取自产物文件与 cost-meter/or our-free-model 落盘文件；未从任何任务汇报文字取数。",
    "source_files": {
        "ledger.json": {"path": LEDGER, "sha256": sha256(LEDGER), "bytes": os.path.getsize(LEDGER)},
        "our-free-model/stats.json": {"path": STATS, "sha256": sha256(STATS), "bytes": os.path.getsize(STATS)},
    },
    "artifacts": artifacts,
    "artifacts_missing": missing,
    "note_dirs": dir_stats,
    "evidence_counts": {
        "loop3-* 全部": len(evcount("loop3")),
        "loop3-t4-*（B 档）": len(evcount("loop3-t4")),
        "loop3-t7-*（C 档）": len(evcount("loop3-t7")),
        "t7-*（C 档）": len(evcount("t7")),
        "loop3-a-*（A 档）": len(evcount("loop3-a")),
    },
    "cost": {
        "口径A_余额": {
            "source": LEDGER,
            "balanceRef.total_CNY": br["total"],
            "balanceRef.topped_CNY": br.get("topped"),
            "balanceRef.ledgerCost_CNY": br.get("ledgerCost"),
            "balanceRef.at_local": datetime.datetime.fromtimestamp(br["at"] / 1000).strftime("%Y-%m-%d %H:%M:%S"),
            "balanceRef.at_ms": br["at"],
            "is_realtime": False,
            "limitation": "本轮成员全部跑在免费车道（buddy / our-free-model / workbuddy），免费车道不扣余额；"
                          "且 balanceRef.at 为 21:34:03 快照、非 t9 取数时刻 → 口径 A **严重低估**团队本轮消耗，"
                          "不可单独作为团队花费结论。",
        },
        "口径B_调用量": {
            "source": LEDGER,
            "day": DAY,
            "day_cost_nominal_CNY": day["cost"],
            "day_calls": day["calls"],
            "day_input": day["input"],
            "day_output": day["output"],
            "day_cacheRead": day["cacheRead"],
            "day_reasoning": day.get("reasoning"),
            "by_provider": prov,
            "note": "workbuddy / buddy 的 cost 为账本**名义价**，实走免费渠道不扣余额；"
                    "deepseek-account:deepseek-flash 的 749 calls 为真付费，但全部发生在 18:10–18:48 旧会话，"
                    "与本轮（21:08 之后 loop3）无关。",
            "by_tier_window": win,
            "attribution_method": "按**会话起始时间**（session.at）落窗口：A 档 21:08:47–21:30:00、"
                                  "B 档 21:30:00–22:57:00、C 档 22:57:00 至取数时刻。局限：会话可跨窗口，"
                                  "窗口边界附近的会话会被整条归到起始窗口，故本口径是**近似归属**，不做精确推断。",
        },
    },
    "free_lane_reliability": free,
}

dest = os.path.join(EV, "loop3-t9-summary-20261012.json")
with open(dest, "w", encoding="utf-8") as f:
    json.dump(out, f, ensure_ascii=False, indent=2)

print("=== loop3-t9-summary ===")
print("out:", dest, os.path.getsize(dest), "bytes")
print("artifacts missing:", len(missing), missing)
for k in artifacts:
    ok = sum(1 for m in artifacts[k] if m["exists"])
    print(f"  {k} 档 产物 {ok}/{len(artifacts[k])} 存在")
print("evidence counts:", out["evidence_counts"])
print("口径A balanceRef.total =", br["total"], "at", out["cost"]["口径A_余额"]["balanceRef.at_local"])
print("口径B day.cost =", day["cost"], "day.calls =", day["calls"])
for k in sorted(prov):
    p = prov[k]
    print(f"   {k:38} calls={p['calls']:>5} in={p['input']:>9} out={p['output']:>8} cacheRead={p['cacheRead']:>10} nominal={p['cost_nominal']:.4f}")
for label, a in win.items():
    print(f"  [窗口] {label}  calls={a['calls']} nominal={a['cost_nominal']:.4f}")
print("free lane:", free)
print("ledger sha256:", out["source_files"]["ledger.json"]["sha256"])
print("stats  sha256:", out["source_files"]["our-free-model/stats.json"]["sha256"])
