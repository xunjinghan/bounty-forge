#!/bin/bash
# 只读：查 bWAPP users 表当前 secret 值 + 出厂 seed 值来源
echo "=== users rows (login, secret) ==="
sudo -n mariadb -N -e "SELECT login, secret FROM bWAPP.users;" 2>&1
echo "=== users columns ==="
sudo -n mariadb -N -e "SHOW COLUMNS FROM bWAPP.users;" 2>&1
echo "=== seed in install sql ==="
sudo -n grep -rn "secret" /var/www/html/bWAPP/db/*.sql 2>/dev/null | head -20
echo "=== install.php secret refs ==="
sudo -n grep -n "secret" /var/www/html/bWAPP/install.php 2>/dev/null | head -20
echo "=== admin/ secrets ==="
sudo -n grep -rn "Any bugs" /var/www/html/bWAPP/*.php /var/www/html/bWAPP/db/*.sql 2>/dev/null | head -20
echo "=== DONE ==="
