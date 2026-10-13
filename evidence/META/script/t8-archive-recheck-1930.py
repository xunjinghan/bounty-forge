# -*- coding: utf-8 -*-
"""t8 归档核查（复跑版）：验证 progress.md 与 next-round-plan.md 中的文件引用可解析。
只读；输出写到本文件同目录、但显式指出写入目标，避免「输出文件把自身记成缺失引用」。
用法：python t8-archive-recheck-1930.py [输出文件名]"""
import os, re, json, sys, hashlib

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # security/learning
WS = os.path.dirname(os.path.dirname(BASE))                          # workspace root
EV = os.path.join(BASE, "_evidence")

RE = re.compile(r"`([^`\n]+\.(?:json|jsonl|log|md|py|txt|db))`")


def resolve(name):
    cands = [os.path.join(EV, name), os.path.join(BASE, name),
             os.path.join(BASE, "business-logic", name), os.path.join(BASE, "auth-bypass", name),
             os.path.join(BASE, "file-upload", name), os.path.join(BASE, "ssrf", name),
             os.path.join(WS, name), os.path.join(WS, "target-site-lab", name),
             os.path.join(WS, "target-site-lab", "downloads", name),
             os.path.join(WS, "target-site", name)]
    return [c for c in cands if os.path.exists(c)]


report = {"checked": [], "missing": [], "ignored_patterns": [], "scanned": {}}
IGNORE = ("*", "…", "<", "/", "-board2.log", "-index.md")
# 先摘掉「`A`→`B`」形式的映射登记文本，避免把旧写法误判为现存引用
MAP_NOTE = re.compile(r"`[^`\n]+`\s*(?:→|->)\s*`[^`\n]+`")
for src in ("progress.md", "next-round-plan.md"):
    p = os.path.join(BASE, src)
    raw = open(p, "rb").read()
    txt = raw.decode("utf-8")
    report["scanned"][src] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    body = MAP_NOTE.sub(" ", txt)
    for name in sorted(set(RE.findall(body))):
        if any(t in name for t in IGNORE) or "→" in name or "->" in name:
            report["ignored_patterns"].append({"source": src, "pattern": name})
            continue
        found = resolve(name)
        entry = {"source": src, "ref": name, "resolved": bool(found),
                 "path": os.path.relpath(found[0], WS) if found else None}
        report["checked"].append(entry)
        if not found:
            report["missing"].append(entry)

ev = set(os.listdir(EV))
report["cache_evidence"] = sorted(n for n in ev if n == "verified-20261012-184800-SUPPLEMENT-01.md"
                                  or n.startswith("verify-07"))

outname = sys.argv[1] if len(sys.argv) > 1 else "t8-archive-recheck-1930.json"
out = os.path.join(EV, outname)
report["checked"].append({"source": "self", "ref": outname,
                          "resolved": True, "path": os.path.relpath(out, WS),
                          "why": "本次核查的输出文件（自引用，非文档引用）"})
json.dump(report, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
print(json.dumps({"total": len(report["checked"]), "missing": len(report["missing"]),
                  "missing_list": [m["ref"] for m in report["missing"]],
                  "scanned": {k: v["sha256"][:16] for k, v in report["scanned"].items()},
                  "out": os.path.basename(out)}, ensure_ascii=False, indent=2))
