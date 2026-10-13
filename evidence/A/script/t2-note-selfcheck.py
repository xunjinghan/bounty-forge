"""t2 自检：引用存在性 missing=0 / 禁 100% / 七节结构 / sha256 核对。"""
import io, os, re, sys, hashlib
sys.stdout.reconfigure(encoding="utf-8")
ROOT = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace"
NOTES = [
    "security/learning/hardening/HARD-01-A档六处加固原理与落地diff.md",
    "security/learning/hardening/HARD-02-A档残余绕过与阴性留证.md",
]
fails = []

for rel in NOTES:
    p = os.path.join(ROOT, rel)
    txt = io.open(p, encoding="utf-8").read()
    name = os.path.basename(rel)
    print(f"===== {name}  ({len(txt.encode('utf-8'))} B, {len(txt.splitlines())} 行) =====")

    # ① 七节模板
    need = ["概述等级", "原理", "可复现 payload", "复现步骤与证据", "修复方案", "参考链接", "学习要点"]
    miss = [s for s in need if s not in txt]
    print(f"  [1] 七节模板: {'OK' if not miss else 'MISSING ' + str(miss)}")
    if miss: fails.append((name, "七节缺 " + ",".join(miss)))

    # ② sha256 引用（64 hex，大小写皆可）
    shas = re.findall(r"\b([0-9a-fA-F]{64})\b", txt)
    uniq = sorted(set(s for s in shas if set(s) != {"0"}))
    print(f"  [2] sha256 引用: {len(shas)} 处 / 去重 {len(uniq)} 个")

    # ③ 路径引用存在性
    paths = set()
    for m in re.finditer(r"`((?:security|target-site-lab)[A-Za-z0-9_./\\\\\-一-鿿]+\.(?:md|json|py|patch|log|db))`", txt):
        s = m.group(1).replace("/", os.sep).replace("\\\\", os.sep)
        paths.add(s)
    missing = sorted(x for x in paths if not os.path.exists(os.path.join(ROOT, x)))
    print(f"  [3] 路径引用: {len(paths)} 个 / missing={len(missing)}")
    for x in missing:
        print(f"        MISSING: {x}")
        fails.append((name, "missing " + x))

    # ④ 禁 100%
    bad = []
    for i, line in enumerate(txt.splitlines(), 1):
        if re.search(r"100\s*%|百分之百|必现率\s*100", line):
            # 口径声明句（"不写 100%"/"严禁写 100%"/"任何地方都不写 100%"）不算违规
            if re.search(r"(不写|严禁|禁止|不得|非必现)[^。\n]{0,20}100\s*%", line):
                continue
            bad.append((i, line.strip()[:110]))
    print(f"  [4] 禁 100%: {'OK' if not bad else 'VIOLATION'}")
    for i, l in bad:
        print(f"        L{i}: {l}")
        fails.append((name, f"L{i} 出现 100%"))

    # ⑤ 复现率区间
    rng = re.findall(r"≥\s*9\d\s*%|n\s*=\s*\d+|0/30|0/6", txt)
    print(f"  [5] 复现率区间标记: {len(rng)} 处 -> {sorted(set(rng))[:8]}")

    # ⑥ 复现率自检脚本块
    print(f"  [6] 自检脚本块: {'OK' if '$missing = @(' in txt else 'MISSING'}")

    # ⑦ A1-A6 覆盖
    for tag in ["A1", "A2", "A3", "A4", "A6"]:
        print(f"  [7] {tag} 出现 {txt.count(tag)} 次")

print()
print("===== sha256 值与盘上实际核对 =====")
# 抽取 md 表格里的 `路径 | 字节 | sha256` 逐条核对
for rel in NOTES:
    txt = io.open(os.path.join(ROOT, rel), encoding="utf-8").read()
    name = os.path.basename(rel)
    ok = bad = 0
    for m in re.finditer(r"^\|\s*`([^`]+\.(?:md|json|py|patch|log))`\s*\|\s*(\d+)\s*\|\s*`([0-9a-fA-F]{64})`\s*\|", txt, re.M):
        f, size, sha = m.group(1), int(m.group(2)), m.group(3)
        fp = os.path.join(ROOT, f.replace("/", os.sep))
        if not os.path.exists(fp):
            print(f"  {name}: MISSING {f}"); bad += 1; fails.append((name, "table missing " + f)); continue
        real = hashlib.sha256(io.open(fp, "rb").read()).hexdigest()
        rsize = os.path.getsize(fp)
        if real.lower() == sha.lower() and rsize == size:
            ok += 1
        else:
            print(f"  {name}: MISMATCH {f}\n     表内 {size}B/{sha[:16]}\n     实际 {rsize}B/{real[:16]}")
            bad += 1; fails.append((name, "sha mismatch " + f))
    print(f"  {name}: 表格核对 ok={ok} bad={bad}")

print()
print("===== 结论 =====")
if fails:
    print(f"FAIL ({len(fails)} 项)")
    for f in fails[:40]: print("  -", f)
else:
    print("ALL PASS  missing=0  无 100%  全部 sha256 与盘上一致")
