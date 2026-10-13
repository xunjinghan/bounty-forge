#!/usr/bin/env python3
"""loop3 t7 报告自检：核验报告引用的每个证据文件名 + sha256 与磁盘一致。

检查项：
  1) 报告中出现的每个 `<路径>.json/.jsonl/.txt/.rb/.py/.sh/.jsp/.java` 文件存在
  2) 与紧邻的 64 位 sha256 匹配
  3) 报告中不出现 100% 复现率
  4) 不出现省略号缩写的证据文件名（…）
"""
import hashlib, os, re, sys

ROOT = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace"
EV = os.path.join(ROOT, r"security\learning\_evidence")
REPORT = os.path.join(ROOT, r"security\learning\loop3-c-vulhub-report-t7-20261012.md")

text = open(REPORT, encoding="utf-8").read()
lines = text.splitlines()

results = {"sha_ok": 0, "sha_mismatch": [], "file_missing": [], "no_100pct": True, "no_ellipsis": []}

# ---- 1/2) 表格行：... `path` | `sha256` ----
for row in lines:
    mh = re.search(r"([0-9a-f]{64})", row)
    if not mh:
        continue
    mp = re.search(r"`([^`]+\.(?:json|jsonl|txt|rb|py|sh|jsp|java))`", row)
    if not mp:
        continue
    path = mp.group(1)
    bn = os.path.basename(path.replace("\\", "/"))
    f = os.path.join(EV, bn)
    if not os.path.exists(f):
        cand = [x for x in os.listdir(EV) if x == bn]
        if cand:
            f = os.path.join(EV, cand[0])
        else:
            results["file_missing"].append(bn)
            continue
    h = hashlib.sha256(open(f, "rb").read()).hexdigest()
    if h == mh.group(1):
        results["sha_ok"] += 1
    else:
        results["sha_mismatch"].append({"file": bn, "report": mh.group(1), "disk": h})

# ---- 3) 禁止 100% ----
if re.search(r"100\s*%", text):
    # 允许出现"禁止写 100%"这类说明性文字，但不应出现在复现率语境
    for ln in lines:
        if re.search(r"100\s*%", ln) and not re.search(r"禁|不写|不得|禁止", ln):
            results["no_100pct"] = False
            results["pct100_line"] = ln.strip()[:140]

# ---- 4) 证据名省略号 ----
for ln in lines:
    for m in re.finditer(r"`([^`]*…[^`]*)`", ln):
        results["no_ellipsis"].append(m.group(1))

print("=" * 70)
print(f"报告: {REPORT}")
print(f"sha256 核对通过: {results['sha_ok']}")
print(f"sha256 不匹配 : {len(results['sha_mismatch'])} {results['sha_mismatch']}")
print(f"文件缺失      : {len(results['file_missing'])} {results['file_missing']}")
print(f"无 100% 复现率: {results['no_100pct']}")
print(f"证据名省略号  : {len(results['no_ellipsis'])} {results['no_ellipsis'][:5]}")
ok = (not results["sha_mismatch"]) and (not results["file_missing"]) and results["no_100pct"] and (not results["no_ellipsis"])
print("VERDICT:", "ALL PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
