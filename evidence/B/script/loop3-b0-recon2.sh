#!/bin/bash
# loop3 B 档 t4 侦察2（只读）：关卡源码 + 文件清单
echo "=== BWAPP ALL PHP (full list) ==="
ls -1 /var/www/html/bWAPP/*.php | xargs -n1 basename | tr '\n' ' '
echo; echo "=== LFI / XSS / SSRF / CSRF candidates ==="
ls -1 /var/www/html/bWAPP/ | grep -iE 'lfi|rfi|xxe|xss|csrf|ssrf|session|stored|htmli|phpi|file' | tr '\n' ' '
echo; echo "=== xxe-1.php SOURCE ==="
sudo -n cat -n /var/www/html/bWAPP/xxe-1.php
echo "=== xxe-2.php SOURCE ==="
sudo -n cat -n /var/www/html/bWAPP/xxe-2.php
echo "=== DONE ==="
