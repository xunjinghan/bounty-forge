#!/bin/sh
# 只读：用 javap 反编译 ShiroConfig 提取硬编码 AES 密钥
cd /tmp/jarx 2>/dev/null || { mkdir -p /tmp/jarx && cd /tmp/jarx && unzip -o -q /shirodemo-1.0-SNAPSHOT.jar 'BOOT-INF/classes/org/vulhub/shirodemo/*'; }
echo "=== javap location ==="
command -v javap
javap -version 2>&1
echo "=== javap -c -p ShiroConfig ==="
javap -c -p -cp BOOT-INF/classes org.vulhub.shirodemo.ShiroConfig 2>&1 | head -120
echo "=== constant pool strings via od (AES key hunt) ==="
od -c BOOT-INF/classes/org/vulhub/shirodemo/ShiroConfig.class 2>/dev/null | grep -E 'k P H|k P H \+|b I x k' | head
echo "=== raw grep for base64-looking key ==="
od -c BOOT-INF/classes/org/vulhub/shirodemo/ShiroConfig.class | tr -s ' ' | head -60
echo "=== DONE ==="
