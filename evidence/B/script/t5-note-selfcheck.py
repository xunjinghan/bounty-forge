"""t5 全量自检：B 档 8 篇笔记 七节模板 / 证据 sha256 逐条核对 / missing=0 / 禁 100% / 省略号。"""
import io, os, re, sys, hashlib
sys.stdout.reconfigure(encoding="utf-8")
ROOT = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace"
L = os.path.join(ROOT, "security/learning")
NOTES = [
    "path-traversal/B1-LFI-01-DVWA文件包含路径穿越与phpfilter源码读取.md",
    "xxe/B2-XXE-01-bWAPP原生XXE关卡实体展开与外部实体阻断.md",
    "csrf/B3-CSRF-01-bWAPP真实CSRF与token对照.md",
    "auth-bypass/B4-SESSION-01-DVWA会话固定与弱会话ID.md",
    "xss/B5-XSS-01-DVWA存储型XSS到会话劫持完整链.md",
    "xxe/N-B03-B04-B05-bWAPP-XXE外部实体未复现.md",
    "csrf/N-B01-B02-B06-CSRFimg形态与RFI未复现.md",
    "N-LOOP3-B-COVERAGE-B档分类覆盖声明.md",
    # C 档（t8 归档）：2 篇阳性 + 1 篇阴性
    "cve/C1-SHIRO-2016-4437-rememberMe反序列化默认密钥.md",
    "cve/C2-TOMCAT-2017-12615-PUT上传配置缺陷.md",
    "cve/N-C01-COMMONS-COLLECTIONS-2未复现.md",
]
SEVEN = ["概述", "原理", "可复现 payload", "复现步骤与证据", "修复方案", "参考链接", "学习要点"]
SHA = re.compile(r"\b([0-9a-fA-F]{64})\b")
# 证据文件必须落在已知前缀上（排除 note.md / ID.md / shell.txt 这类误报）
# 前缀：loop3-*（t4/t3/t7 挖掘证据）、t5-*（scribe 自检）、t7-*（C 档脚本与输出）、verified-*（verifier t10 独立复核）
FN = re.compile(r"((?:loop3|t5|t7|verified)[A-Za-z0-9._\-]*\.(?:jsonl|json|py|sh|txt|png|rb|java|jsp))")
# 攻击时落到容器 webapps/ 里的文件名（如 t7rce230826.jsp）不是 _evidence 证据文件，排除
FN_EXCLUDE = ("t7rce", "t7rep", "t7poc")
fails, t_ok, t_bad, t_miss = [], 0, 0, 0

for rel in NOTES:
    p = os.path.join(L, rel)
    txt = io.open(p, encoding="utf-8").read()
    name = rel.split("/")[-1]
    print(f"===== {name} ({len(txt.encode('utf-8'))}B, {len(txt.splitlines())} 行) =====")

    # 覆盖声明篇允许缺"修复方案"（非漏洞笔记）→ 用"修复方案/下轮建议"覆盖
    body = txt.replace("## 5. 下轮建议", "## 5. 修复方案").replace("## 5. 防护机制说明", "## 5. 修复方案")
    miss = [s for s in SEVEN if s not in body]
    print(f"  [1] 七节: {'OK' if not miss else '缺 ' + str(miss)}")
    if miss: fails.append((name, "七节缺 " + ",".join(miss)))

    shas = {x.lower() for x in SHA.findall(txt) if set(x) != {"0"}}
    print(f"  [2] sha256(去重): {len(shas)}")

    ev = set(x for x in FN.findall(txt) if not x.startswith(FN_EXCLUDE))
    miss_ev = sorted(x for x in ev if not os.path.exists(os.path.join(L, "_evidence", x)))
    print(f"  [3] 证据文件名: {len(ev)} / 缺失 {len(miss_ev)} {miss_ev}")
    if miss_ev: fails.append((name, f"missing {miss_ev}"))

    # 证据名省略号：排除自选会话 ID（loop3fixlow...）这类测试字符串
    ell = [x for x in re.findall(r"loop3[A-Za-z0-9._\-]*\.\.\.[A-Za-z0-9._\-]*", txt)
           if "fixlow" not in x]
    print(f"  [4] 证据名省略号: {len(ell)}")
    if ell: fails.append((name, f"证据名省略号 {ell[:3]}"))

    bad = []
    for i, line in enumerate(txt.splitlines(), 1):
        if re.search(r"100\s*%|百分之百|必现率?100", line):
            if re.search(r"(不写|严禁|禁止|不得|非必现|不要写)[^。\n]{0,20}100\s*%", line):
                continue
            bad.append((i, line.strip()[:90]))
    print(f"  [5] 禁100%(复现率): {'OK' if not bad else bad}")
    if bad: fails.append((name, f"100% @ {bad[0][0]}"))

    # sha256 逐条核对
    ok = mism = 0
    for line in txt.splitlines():
        if not SHA.search(line): continue
        fns, shas_l = FN.findall(line), SHA.findall(line)
        for i, f in enumerate(fns):
            fp = os.path.join(L, "_evidence", f)
            if not os.path.exists(fp): continue
            real = hashlib.sha256(io.open(fp, "rb").read()).hexdigest()
            s = shas_l[i] if len(shas_l) == len(fns) else (shas_l[-1] if len(shas_l) == 1 else None)
            if s is None: continue
            if real.lower() == s.lower(): ok += 1
            else:
                mism += 1
                print(f"        SHA MISMATCH {f}\n          表 {s}\n          实 {real}")
                fails.append((name, f"sha mismatch {f}"))
    t_ok += ok; t_bad += mism
    print(f"  [6] sha256 逐条核对: ok={ok} mismatch={mism}")
    t_miss += len(miss_ev)

    print(f"  [7] 自检块: {'OK' if '$missing = @(' in txt else '无（覆盖声明篇允许）'}")

print(f"\n===== 汇总 =====\nsha256 ok={t_ok} mismatch={t_bad} / 证据文件缺失={t_miss}")
print("\n===== 空目录复核 =====")
for d in ["idor", "sql-injection", "ssti", "command-injection"]:
    n = len([f for f in os.listdir(os.path.join(L, d)) if f.endswith(".md")]) if os.path.isdir(os.path.join(L, d)) else -1
    print(f"  {d:20s} md={n}  {'<< 仍为空（已在覆盖声明篇写明）' if n == 0 else ''}")
print("\n===== B 档目录分布 =====")
for d in sorted(os.listdir(L)):
    p = os.path.join(L, d)
    if os.path.isdir(p) and d != "_evidence":
        n = len([f for f in os.listdir(p) if f.endswith(".md")])
        print(f"  {d:20s} {n}")

print()
print("===== 结论 =====")
print("ALL PASS  missing=0  无 100%  全部 sha256 与盘上一致" if not fails
      else f"FAIL ({len(fails)} 项): {fails[:10]}")
