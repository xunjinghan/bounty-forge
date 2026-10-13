#!/bin/bash
# loop3 B 档 t4 侦察4（只读）：bWAPP 关键关卡源码
for f in xxe-1.php xxe-2.php csrf_1.php csrf_2.php csrf_3.php cs_validation.php rlfi.php; do
  echo "===== bWAPP/$f ====="
  sudo -n cat -n /var/www/html/bWAPP/$f 2>&1 | grep -vE '^\s*[0-9]+\s*$' | sed -n '1,120p'
done
echo "===== bWAPP xss_stored_1.php ====="
sudo -n sed -n '1,140p' /var/www/html/bWAPP/xss_stored_1.php
echo "===== bWAPP security_level_get / settings ====="
sudo -n grep -rn "security_level" /var/www/html/bWAPP/functions_external.php 2>/dev/null | head -10
sudo -n cat /var/www/html/bWAPP/security_level_check.php
echo "===== session files dir ====="
sudo -n ls -la /var/lib/php/sessions/ 2>&1 | head -10
echo "=== DONE ==="
