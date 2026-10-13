#!/bin/bash
echo "=== bWAPP all top-level php ==="
ls /var/www/html/bWAPP/*.php | xargs -n1 basename | sort | tr '\n' ' '
echo
echo "=== grep for XML parsing in bWAPP ==="
grep -rln 'DOMDocument\|simplexml\|loadXML\|LIBXML' /var/www/html/bWAPP/ --include='*.php' | head -20
echo "=== grep xxe keyword case-insensitive whole tree ==="
grep -ril 'xxe' /var/www/html/bWAPP/ 2>/dev/null | head -20
echo "=== bWAPP version/readme ==="
head -5 /var/www/html/bWAPP/README.md 2>/dev/null
grep -o 'bWAPP v[0-9.]*' /var/www/html/bWAPP/login.php 2>/dev/null | head -3
echo "=== DVWA modules present ==="
for d in /var/www/html/dvwa/vulnerabilities/*/; do basename "$d"; done | tr '\n' ' '
echo
