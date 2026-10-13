#!/usr/bin/env python3
# loop3 t4 probe3: 复原 bee.secret -> 出厂值 'Any bugs?'（经应用自身 xxe-2.php 路径），并直查数据库确认
import json, time, datetime, subprocess
import requests

BASE = "http://127.0.0.1"
OUT = {"ts": datetime.datetime.now().isoformat(), "steps": []}


def db_secret():
    r = subprocess.run(["sudo", "-n", "mariadb", "-N", "-e",
                        "SELECT login,secret FROM bWAPP.users;"], capture_output=True, text=True)
    return r.stdout.strip()


def rec(name, **kw):
    OUT["steps"].append({"step": name, **kw})
    print(f"--- {name}: " + json.dumps(kw, ensure_ascii=False)[:600], flush=True)


rec("db_before_restore", rows=db_secret())

B = requests.Session()
B.headers["User-Agent"] = "loop3-t4/1.0 (authorized local lab)"
r = B.post(BASE + "/bWAPP/login.php",
           data={"login": "bee", "password": "bug", "security_level": "0", "form": "submit"},
           allow_redirects=False, timeout=20)
rec("login", status=r.status_code, loc=r.headers.get("Location"), phpsessid=B.cookies.get("PHPSESSID"))
time.sleep(1.2)

body = '<?xml version="1.0"?><reset><login>bee</login><secret>Any bugs?</secret></reset>'
r = B.post(BASE + "/bWAPP/xxe-2.php", data=body.encode(),
           headers={"Content-Type": "text/xml; charset=UTF-8"}, timeout=25)
rec("restore_request", status=r.status_code, resp=r.text[:120])
time.sleep(1.2)
rec("db_after_restore", rows=db_secret())

with open("/tmp/loop3-t4-probe3.json", "w") as f:
    json.dump(OUT, f, ensure_ascii=False, indent=1)
print(json.dumps({"rc": "ok"}))
