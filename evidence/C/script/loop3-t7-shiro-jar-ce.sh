#!/bin/sh
# 只读：检查 shirodemo jar 内是否含 gadget 依赖库
echo "=== jar entries: gadget libs ==="
unzip -l /shirodemo-1.0-SNAPSHOT.jar 2>/dev/null | grep -iE 'commons-collections|commons-beanutils|commons-logging|groovy|spring|c3p0|javassist|shiro-core' | head -30
echo "=== BOOT-INF/lib listing ==="
unzip -l /shirodemo-1.0-SNAPSHOT.jar 2>/dev/null | grep -iE 'BOOT-INF/lib/.*\.jar' | awk '{print $4}' | head -60
echo "=== shiro version ==="
unzip -l /shirodemo-1.0-SNAPSHOT.jar 2>/dev/null | grep -iE 'shiro-' | head -10
echo "=== commands available ==="
for t in curl wget bash sh python python3 nc perl; do p=$(command -v $t 2>/dev/null); echo "$t=${p:-MISSING}"; done
echo "=== unzip available ==="
command -v unzip jar || echo "no unzip/jar"
echo "=== DONE ==="
