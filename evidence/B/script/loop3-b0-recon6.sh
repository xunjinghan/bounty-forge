#!/bin/bash
# 只读侦察6：DVWA session 处理代码 + weak_id 源码 + bWAPP xss_stored_1.php
echo "=== dvwaPage.inc.php session 相关 ==="
sudo -n grep -n "session" /var/www/html/dvwa/dvwa/includes/dvwaPage.inc.php | head -40
echo "=== dvwaPageStartup 函数体 ==="
sudo -n sed -n '/function dvwaPageStartup/,/^}/p' /var/www/html/dvwa/dvwa/includes/dvwaPage.inc.php
echo "=== weak_id/index.php ==="
sudo -n cat -n /var/www/html/dvwa/vulnerabilities/weak_id/index.php | sed -n '1,80p'
echo "=== weak_id helpers/other sources ==="
sudo -n ls -la /var/www/html/dvwa/vulnerabilities/weak_id/ /var/www/html/dvwa/vulnerabilities/weak_id/source/ 2>&1
echo "=== XSS stored index session 相关 ==="
sudo -n sed -n '508,560p' /var/www/html/dvwa/vulnerabilities/xss_s/index.php
echo "=== xss_stored_1.php (bWAPP) ==="
sudo -n sed -n '18,60p' /var/www/html/bWAPP/xss_stored_1.php
sudo -n grep -n "guestbook\|INSERT\|SELECT\|SELECT" /var/www/html/bWAPP/xss_stored_1.php | head -20
echo "=== sessions dir listing ==="
sudo -n ls -la /var/lib/php/sessions/ | tail -20
echo "=== DONE ==="
