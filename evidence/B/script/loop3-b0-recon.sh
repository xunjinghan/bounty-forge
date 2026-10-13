#!/bin/bash
# loop3 B 档 t4 侦察（只读）：服务/文件/安全级别/php 模块/浏览器可用性
echo "=== DATE ==="
date -Is
echo "=== HOSTNAME ==="
hostname; uname -r
echo "=== SERVICES ==="
systemctl is-active apache2 mariadb 2>&1
echo "=== LISTEN 80/3306 ==="
sudo -n ss -tlnp 2>/dev/null | grep -E ':80 |:3306 ' 
echo "=== DOCROOT ==="
ls -la /var/www/html/ | head -20
echo "=== DVWA VULN DIRS ==="
ls -1 /var/www/html/dvwa/vulnerabilities/ 2>&1
echo "=== BWAPP XXE FILES ==="
ls -la /var/www/html/bWAPP/ 2>/dev/null | grep -iE 'xxe|xml' 
echo "--- find xxe ---"
sudo -n find /var/www/html/bWAPP -maxdepth 2 -iname '*xxe*' 2>/dev/null
echo "=== BWAPP csrf/ssrf/xss files ==="
ls -1 /var/www/html/bWAPP/*.php 2>/dev/null | head -80
echo "=== PHP VERSION / MODULES ==="
php -v 2>&1 | head -2
php -m 2>/dev/null | grep -iE '^(dom|libxml|simplexml|xml|xmlreader|xmlwriter|curl|expect|iconv)$'
echo "=== php.ini key settings ==="
php -i 2>/dev/null | grep -E '^(allow_url_include|allow_url_fopen|session.cookie_httponly|session.use_strict_mode|session.use_only_cookies|session.cookie_samesite|session.save_path|libxml_disable_entity_loader)' 
echo "=== PHP-FPM/APACHE MODULE ==="
sudo -n apache2ctl -M 2>/dev/null | grep -iE 'php|mime'
echo "=== BROWSERS ==="
for b in chromium chromium-browser firefox firefox-esr google-chrome; do command -v $b && $b --version 2>&1 | head -1; done
echo "=== python libs ==="
python3 -c "import requests,sys;print('requests',requests.__version__)" 2>&1
python3 -c "import websocket" 2>&1 | head -1
python3 -c "import selenium;print('selenium ok')" 2>&1 | head -1
echo "=== curl version ==="
curl --version | head -1
echo "=== DVWA security setting ==="
grep -n "" /var/www/html/dvwa/config/config.inc.php 2>/dev/null | sed -n '1,40p'
echo "=== bWAPP security level file ==="
sudo -n grep -rn "security_level" /var/www/html/bWAPP/settings.php 2>/dev/null | head -5
ls -la /tmp/bwapp_security_level.txt 2>/dev/null; sudo -n ls -la /var/www/bWAPP/*.txt 2>/dev/null
echo "=== DONE ==="
