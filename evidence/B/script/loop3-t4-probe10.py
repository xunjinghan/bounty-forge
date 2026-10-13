#!/usr/bin/env python3
# 复原 bee.secret 并核查；同时收集 bWAPP XXE 相关解析配置证据
import json, subprocess, time, datetime, re
import requests

BASE = "http://127.0.0.1"
OUT = {"ts": datetime.datetime.now().isoformat(), "steps": []}


def rec(n, **kw):
    OUT["steps"].append({"step": n, **kw})
    print(f"--- {n}: " + json.dumps(kw, ensure_ascii=False)[:800], flush=True)


def sh(c):
    r = subprocess.run(c, shell=True, capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()


def db(q):
    return sh(f'sudo -n mariadb -N -e "{q}"')


rec("secret_current", v=db("SELECT secret FROM bWAPP.users WHERE login='bee';"))

B = requests.Session()
B.headers["User-Agent"] = "loop3-t4/1.0 (authorized local lab)"
r = B.post(BASE + "/bWAPP/login.php",
           data={"login": "bee", "password": "bug", "security_level": "0", "form": "submit"},
           allow_redirects=False, timeout=20)
rec("login", status=r.status_code, phpsessid=B.cookies.get("PHPSESSID"), seclev=B.cookies.get("security_level"))
time.sleep(1.2)
r = B.post(BASE + "/bWAPP/xxe-2.php",
           data=b'<?xml version="1.0"?><reset><login>bee</login><secret>Any bugs?</secret></reset>',
           headers={"Content-Type": "text/xml; charset=UTF-8"}, timeout=20)
rec("restore", resp=r.text[:100])
time.sleep(1.2)
rec("secret_after_restore", v=db("SELECT secret FROM bWAPP.users WHERE login='bee';"))
rec("all_rows", v=db("SELECT id,login,secret,admin FROM bWAPP.users;"))

# bWAPP 中是否存在启用外部实体的解析标志
rec("grep_LIBXML_NOENT", v=sh("sudo -n grep -rn 'LIBXML_NOENT\\|libxml_disable_entity_loader\\|LIBXML_DTDLOAD\\|LIBXML_DTDVALID' /var/www/html/bWAPP/ 2>/dev/null | head -20"))
rec("grep_xml_parsers", v=sh("sudo -n grep -rln 'simplexml_load\\|DOMDocument\\|xml_parse' /var/www/html/bWAPP/*.php /var/www/html/bWAPP/soap/*.php 2>/dev/null"))
rec("php_default_entity_check", v=sh("php -r '$x=simplexml_load_string(\"<?xml version=\\\"1.0\\\"?><!DOCTYPE r [<!ENTITY e SYSTEM \\\"file:///etc/passwd\\\">]><r><a>&e;</a></r>\"); echo \"a=[\".$x->a.\"]\";' 2>&1 | head -5"))
rec("php_noent_entity_check", v=sh("php -r '$x=simplexml_load_string(\"<?xml version=\\\"1.0\\\"?><!DOCTYPE r [<!ENTITY e SYSTEM \\\"file:///etc/passwd\\\">]><r><a>&e;</a></r>\", LIBXML_NOENT); echo \"a=[\".substr($x->a,0,19).\"]\";' 2>&1 | head -5"))
rec("dvwa_guestbook_schema", v=db("SHOW COLUMNS FROM dvwa.guestbook;"))
rec("dvwa_guestbook_rows", v=db("SELECT comment_id,name FROM dvwa.guestbook;"))

with open("/tmp/loop3-t4-probe10.json", "w") as f:
    json.dump(OUT, f, ensure_ascii=False, indent=1)
print(json.dumps({"rc": "ok"}))
