#!/bin/bash
# 只读：浏览器驱动版本探测
echo "=== chromedriver ==="
chromedriver --version 2>&1 | head -2
echo "=== chromium ==="
chromium --version 2>&1
echo "=== geckodriver ==="
geckodriver --version 2>&1 | head -2
echo "=== firefox ==="
firefox --version 2>&1
echo "=== 8099 free? ==="
sudo -n ss -tlnp | grep -E ':8099|:8081' || echo "8099/8081 free"
echo "=== DONE ==="
