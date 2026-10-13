#!/usr/bin/env python3
# loop3 t7 C1 补充：日志异常块完整台账（不做抽样，逐块列全）
# 目的：把 AbstractRememberMeManager.convertBytesToPrincipals 的 :429 / :431 两个锚点
#       按【异常类型】精确区分为四类，给出各自计数与时间戳。
import json, os, re, datetime

EV = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence"
LOG = os.path.join(EV, "t7-shiro-full-dockerlogs.txt")
OUT = os.path.join(EV, "loop3-t7-c1-log-inventory-20261012.json")

lines = open(LOG, encoding="utf-8", errors="replace").read().splitlines()
TS = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+(\w+)\s+\d+ --- \[([^\]]+)\]\s+(\S+)\s*:\s*(.*)$")
EXC = re.compile(r"^(?:Caused by:\s+)?((?:java\.lang\.|org\.apache\.shiro\.|javax\.crypto\.)?[\w.$]*(?:Exception|Error))(?::\s*(.*))?$")

# 1) 异常块切分：以「WARN/ERROR + Delegate RememberMeManager」或异常头行为界
blocks = []
cur = None
last_ts = None
for i, ln in enumerate(lines, 1):
    m = TS.match(ln)
    if m:
        last_ts = {"ts": m.group(1), "level": m.group(2), "thread": m.group(3), "logger": m.group(4), "msg": m.group(5)}
        if "Delegate RememberMeManager" in m.group(5):
            cur = {"header_line": i, "ts": last_ts["ts"], "level": last_ts["level"], "thread": last_ts["thread"], "lines": [], "throwable": None, "frames": [], "caused_by": []}
            blocks.append(cur)
        continue
    if cur is not None:
        cur["lines"].append(ln)
        me = EXC.match(ln.strip())
        if me and cur["throwable"] is None:
            cur["throwable"] = {"type": me.group(1), "msg": (me.group(2) or "")[:160]}
        fc = re.match(r"^\s+at\s+([\w.$]+)\(([^)]*)\)", ln)
        if fc:
            cur["frames"].append({"cls": fc.group(1), "where": fc.group(2)})
        if ln.strip().startswith("Caused by:"):
            cur["caused_by"].append(ln.strip()[:160])

# 2) 按锚点分类
def anchor(b):
    frames = [f["where"] for f in b["frames"]]
    bp = any("BadPadding" in (c or "") for c in b["caused_by"]) or (b["throwable"] or {}).get("type") == "javax.crypto.BadPaddingException"
    a429 = any("AbstractRememberMeManager.java:429" in w for w in frames)
    a431 = any("AbstractRememberMeManager.java:431" in w for w in frames)
    return bp, a429, a431

classes = {"A_decrypt_failed_429": [], "B_deser_stage_431_SerializationException": [],
           "C_deser_success_431_ClassCastException": [], "D_other": []}
for b in blocks:
    bp, a429, a431 = anchor(b)
    t = (b["throwable"] or {}).get("type", "?")
    rec = {"ts": b["ts"], "throwable": t, "msg": (b["throwable"] or {}).get("msg", "")[:120],
           "badpadding": bp, "at_429": a429, "at_431": a431, "header_line": b["header_line"]}
    if a429 and bp:
        classes["A_decrypt_failed_429"].append(rec)
    elif a431 and t == "java.lang.ClassCastException":
        classes["C_deser_success_431_ClassCastException"].append(rec)
    elif a431 and t == "org.apache.shiro.io.SerializationException":
        classes["B_deser_stage_431_SerializationException"].append(rec)
    else:
        classes["D_other"].append(rec)

summary = {k: {"count": len(v), "items": v} for k, v in classes.items()}
raw_counts = {
    "BadPaddingException": sum(1 for l in lines if "BadPaddingException" in l),
    "convertBytesToPrincipals:429": sum(1 for l in lines if "AbstractRememberMeManager.java:429" in l),
    "convertBytesToPrincipals:431": sum(1 for l in lines if "AbstractRememberMeManager.java:431" in l),
    "ClassCastException": sum(1 for l in lines if "ClassCastException" in l),
    "HashSet cannot be cast": sum(1 for l in lines if "HashSet cannot be cast" in l),
    "SerializationException": sum(1 for l in lines if "SerializationException" in l),
    "ClassResolvingObjectInputStream": sum(1 for l in lines if "ClassResolvingObjectInputStream" in l),
    "EOFException": sum(1 for l in lines if "EOFException" in l),
    "total_lines": len(lines),
}

out = {"ts": datetime.datetime.now().isoformat(), "log_file": LOG,
       "note": "AbstractRememberMeManager.convertBytesToPrincipals 锚点台账：:429=解密阶段抛异常(必失败)；"
               ":431=解密成功、进入反序列化阶段；其中仅 ClassCastException 分支证明 readObject() 真的产出了对象。",
       "raw_line_counts": raw_counts, "throwable_blocks_total": len(blocks), "classification": summary}

with open(OUT, "w", encoding="utf-8") as f:
    json.dump(out, f, ensure_ascii=False, indent=1)

print("=" * 74)
print("raw line counts:")
for k, v in raw_counts.items():
    print(f"  {k:<34} {v}")
print(f"\nRememberMeManager throwable blocks: {len(blocks)}")
for k, v in summary.items():
    print(f"  {k:<52} count={v['count']}")
    for it in v["items"]:
        print(f"      {it['ts']}  {it['throwable']}  {it['msg'][:70]}")
print("\nverdict: :431 共 %d 次，其中 ClassCastException(真成功) %d 次，SerializationException(反序列化失败) %d 次" % (
    raw_counts["convertBytesToPrincipals:431"],
    summary["C_deser_success_431_ClassCastException"]["count"],
    summary["B_deser_stage_431_SerializationException"]["count"]))
