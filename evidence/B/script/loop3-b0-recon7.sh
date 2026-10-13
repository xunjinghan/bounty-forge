#!/bin/bash
# 只读侦察7：DVWA session 初始化完整逻辑 + login.php + weak_id low/medium/high
echo "=== dvwaPage.inc.php lines 20-120 ==="
sudo -n sed -n '20,120p' /var/www/html/dvwa/dvwa/includes/dvwaPage.inc.php
echo "=== DVWA login.php (session 段) ==="
sudo -n sed -n '1,80p' /var/www/html/dvwa/login.php
echo "=== weak_id source low/medium/high/impossible ==="
for f in low medium high impossible; do echo "--- $f.php ---"; sudo -n cat /var/www/html/dvwa/vulnerabilities/weak_id/source/$f.php; done
echo "=== security level get/set ==="
sudo -n grep -n "dvwaSecurityLevelGet\|dvwaSecurityLevelSet" -A12 /var/www/html/dvwa/dvwa/includes/dvwaPage.inc.php | sed -n '1,60p'
echo "=== DONE ==="
