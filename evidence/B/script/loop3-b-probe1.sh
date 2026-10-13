#!/bin/bash
echo "=== systemctl ==="; systemctl is-active apache2; systemctl is-active mariadb
echo "=== bWAPP xxe/xml candidates (ls) ==="
ls -la /var/www/html/bWAPP/ | grep -iE 'xxe|xml|soap|ssrf|phpinfo'
echo "--- grep -ril xxe in bWAPP ---"
grep -ril 'xxe' /var/www/html/bWAPP/ --include='*.php' | head -20
echo "--- all php filenames mentioning xxe/xml/soap ---"
ls /var/www/html/bWAPP/*.php | grep -iE 'xxe|xml|soap'
echo "--- bwapp function list from functions.php ---"
grep -oE "xxe[a-zA-Z0-9_]*\.php|xml[a-zA-Z0-9_]*\.php|soap[a-zA-Z0-9_]*\.php" /var/www/html/bWAPP/*.php 2>/dev/null | sort -u | head -40
echo "=== DVWA modules dirs ==="
ls /var/www/html/dvwa/ | head -40
echo "=== DVWA vulnerabilities dir ==="
ls /var/www/html/dvwa/vulnerabilities/ 2>/dev/null
