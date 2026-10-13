#!/usr/bin/env python3
# loop3 t7 C1 判别实验：三类自造密文 -> 看 Shiro 是否真的解密+反序列化
import json, os, subprocess, sys, time, datetime
import requests

CWD = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace"
SHIRO = "http://127.0.0.1:18081/"
UA = "loop3-t7/1.0 (authorized local lab)"
OUT_PATH = os.path.join(CWD, r"security\learning\_evidence\loop3-t7-c1-discriminate-20261012.json")
OUT = {"ts": datetime.datetime.now().isoformat(), "steps": []}


def rec(n, **kw):
    OUT["steps"].append({"step": n, **kw})
    print(f"--- {n}: " + json.dumps(kw, ensure_ascii=False)[:500], flush=True)
    return kw


def kali(cmd):
    r = subprocess.run([sys.executable, r"dsh-tools\kali-run.py", cmd],
                       capture_output=True, text=True, cwd=CWD)
    return (r.stdout + r.stderr).strip()


def get_cookie(name):
    return kali(f"cat /tmp/t7-c1-disc/{name}.txt").splitlines()[0].strip()


def probe(label, ck):
    time.sleep(1.2)
    r = requests.get(SHIRO, headers={"User-Agent": UA, "Cookie": "rememberMe=" + ck},
                     timeout=25, allow_redirects=False)
    sc = r.headers.get("Set-Cookie", "")
    return rec(label, status=r.status_code, deleteMe=("rememberMe=deleteMe" in sc),
               set_cookie=sc[:200], cookie_len=len(ck))


kali("ruby /tmp/t7-c1-discriminate.rb")
time.sleep(1)
for name, desc in (("A_valid_string", "AES ok + 合法 Java 序列化(String OK) -> 期望无 deleteMe"),
                   ("B_plain_garbage", "AES ok + 明文非 Java 序列化 -> 期望 deleteMe"),
                   ("C_magic_truncated", "AES ok + aced0005 魔数但截断 -> 期望 deleteMe")):
    ck = get_cookie(name)
    probe(f"DISCRIMINATE_{name}__{desc.split('->')[0].strip()}", ck)

# 对照：错误密钥加密的同一合法对象 -> 期望 deleteMe
rec("note_wrong_key_control", note="错误密钥在 oracle 校准时已证 deleteMe=true（B1/B2）")

with open(OUT_PATH, "w", encoding="utf-8") as f:
    json.dump(OUT, f, ensure_ascii=False, indent=1)
print(json.dumps({"rc": "ok"}))
