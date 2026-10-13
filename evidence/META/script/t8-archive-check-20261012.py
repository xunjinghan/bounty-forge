# -*- coding: utf-8 -*-
"""t8 归档核查：验证 progress.md §11 与 next-round-plan.md 引用的文件真实存在。
只读；输出 JSON 供 update_task 的 commandsRun 引用。"""
import os, re, json

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # security/learning
WS = os.path.dirname(os.path.dirname(BASE))                          # workspace root
EV = os.path.join(BASE, "_evidence")

RE = re.compile(r"`([^`\n]+\.(?:json|jsonl|log|md|py|txt|db))`")

def resolve(name):
    cands = [os.path.join(EV, name), os.path.join(BASE, name),
             os.path.join(BASE, "business-logic", name), os.path.join(BASE, "auth-bypass", name),
             os.path.join(BASE, "file-upload", name), os.path.join(BASE, "ssrf", name),
             os.path.join(WS, name), os.path.join(WS, "target-site-lab", name),
             os.path.join(WS, "target-site", name)]
    return [c for c in cands if os.path.exists(c)]

report = {"checked": [], "missing": [], "cache_evidence": [], "ignored_patterns": []}
IGNORE = ("*", "…", "<", "/", "-board2.log", "-index.md")
for src in ("progress.md", "next-round-plan.md"):
    p = os.path.join(BASE, src)
    txt = open(p, encoding="utf-8").read()
    for name in sorted(set(RE.findall(txt))):
        if any(t in name for t in IGNORE):
            report["ignored_patterns"].append({"source": src, "pattern": name})
            continue
        found = resolve(name)
        entry = {"source": src, "ref": name, "resolved": bool(found),
                 "path": os.path.relpath(found[0], WS) if found else None}
        report["checked"].append(entry)
        if not found:
            report["missing"].append(entry)

# 缓存中间产物核查：标注后从正式引用中移除
ev = set(os.listdir(EV))
report["cache_evidence"] = sorted(n for n in ev if "SUPPLEMENT-01.md" == n or n.startswith("verify-07"))

out = os.path.join(EV, "t8-archive-check-20261012.json")
json.dump(report, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
print(json.dumps({"total": len(report["checked"]), "missing": len(report["missing"]),
                  "missing_list": [m["ref"] for m in report["missing"]],
                  "out": os.path.basename(out)}, ensure_ascii=False, indent=2))
