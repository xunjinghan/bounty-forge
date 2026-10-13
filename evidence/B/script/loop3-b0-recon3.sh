#!/bin/bash
# loop3 B 档 t4 侦察3（只读）：全量关卡清单 + 关键源码
echo "=== BWAPP ALL PHP (one per line) ==="
ls -1 /var/www/html/bWAPP/*.php | xargs -n1 basename
echo "=== BWAPP subdirs ==="
ls -1d /var/www/html/bWAPP/*/ 2>/dev/null
echo "=== DVWA fi SOURCE (low) ==="
sudo -n cat -n /var/www/html/dvwa/vulnerabilities/fi/source/low.php
echo "=== DVWA fi index (form) ==="
sudo -n sed -n '1,60p' /var/www/html/dvwa/vulnerabilities/fi/index.php
echo "=== DVWA csrf SOURCE (low) ==="
sudo -n cat -n /var/www/html/dvwa/vulnerabilities/csrf/source/low.php
echo "=== DVWA weak_id SOURCE (low) ==="
sudo -n cat -n /var/www/html/dvwa/vulnerabilities/weak_id/source/low.php
echo "=== DVWA xss_s SOURCE (low) ==="
sudo -n cat -n /var/www/html/dvwa/vulnerabilities/xss_s/source/low.php
echo "=== DVWA xss_s index head ==="
sudo -n sed -n '1,40p' /var/www/html/dvwa/vulnerabilities/xss_s/index.php
echo "=== DONE ==="
