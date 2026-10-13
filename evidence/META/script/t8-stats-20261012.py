# -*- coding: utf-8 -*-
"""t8 归档统计：只用文件证据生成统计表，口径与 progress.md 既有表结构对齐。
不写任何目标状态；只读文件系统与 _evidence/ 下 JSON。"""
import os, re, json, datetime

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # security/learning
EV = os.path.join(BASE, "_evidence")

PHASES = [
    ("阶段1 靶场管理", r"^(baseline-2026|recon-httpx)"),
    ("阶段2 侦察", r"^recon-"),
    ("阶段3 挖掘", r"^(hunt-|findings-hunt-20261012-184124)"),
    ("阶段4 验证", r"^(verify-|verified-20261012-184800\.(json|md)$|sqlmap-t5-verify)"),
    ("阶段5 笔记", r"^$"),  # 由笔记目录 mtime 计算
    ("阶段6 归档", r"^$"),
]

def ts(p):
    return datetime.datetime.fromtimestamp(os.path.getmtime(p)).strftime("%H:%M:%S")

rows = []
files = [os.path.join(EV, f) for f in os.listdir(EV)]
files = [f for f in files if os.path.isfile(f)]

def match_any(name, prefix_list):
    return any(name.startswith(p) for p in prefix_list)

prefix = {
    "阶段1 靶场管理": ["baseline-20261012-181212", "recon-httpx-20261012-1814", "recon-ffuf-20261012-1814"],
    "阶段2 侦察": ["recon-10-surface", "recon-11-login", "recon-12-methods", "recon-13-verify",
                "recon-katana", "recon-nuclei", "attack-surface-20261012-182250", "gen-attack-surface"],
    "阶段3 挖掘": ["hunt-a", "hunt-b", "hunt-c", "hunt-d", "hunt-e", "hunt-f", "hunt-lib",
                "findings-hunt-20261012-184124"],
    "阶段4 验证": ["verify-", "verified-20261012-184800", "sqlmap-t5-verify", "build-verified-t5"],
}

for name in prefix:
    sel = [f for f in files if match_any(os.path.basename(f), prefix[name])]
    sel.sort(key=os.path.getmtime)
    if not sel:
        continue
    rows.append({
        "phase": name,
        "files": len(sel),
        "first": ts(sel[0]) + "  " + os.path.basename(sel[0]),
        "last": ts(sel[-1]) + "  " + os.path.basename(sel[-1]),
    })

# 阶段5 笔记：用 15 篇笔记 mtime
note_dirs = ["business-logic", "auth-bypass", "file-upload", "ssrf"]
notes = []
for d in note_dirs:
    p = os.path.join(BASE, d)
    if os.path.isdir(p):
        for f in os.listdir(p):
            if f.endswith(".md"):
                notes.append(os.path.join(p, f))
notes.sort(key=os.path.getmtime)
rows.append({
    "phase": "阶段5 笔记",
    "files": len(notes),
    "first": ts(notes[0]) + "  " + os.path.basename(notes[0]),
    "last": ts(notes[-1]) + "  " + os.path.basename(notes[-1]),
})

# 产物哈希与时间
def sha(p):
    import hashlib
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(65536), b""):
            h.update(c)
    return h.hexdigest()

out = {"generated": datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S%z"),
       "phase_timeline": rows, "evidence_file_count": len(files), "note_count": len(notes)}

# 环节计数（从 t5 报告里抽）
v = json.load(open(os.path.join(EV, "verified-20261012-184800.json"), encoding="utf-8"))
items = v.get("items") or v.get("verdicts") or v.get("findings") or []
counts = {}
for it in items:
    k = str(it.get("verdict"))
    counts[k] = counts.get(k, 0) + 1
out["t5_verdict_counts"] = counts

# 挖掘阶段工具痕迹
tools = {}
for f in files:
    n = os.path.basename(f)
    for t in ("sqlmap", "nuclei", "ffuf", "katana", "httpx"):
        if n.startswith(t):
            tools.setdefault(t, []).append(n)
out["tool_artifacts"] = {k: len(v) for k, v in tools.items()}

print(json.dumps(out, ensure_ascii=False, indent=2))
