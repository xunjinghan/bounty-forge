#!/bin/sh
echo "=== gadget libs in jar ==="
unzip -l /shirodemo-1.0-SNAPSHOT.jar 2>/dev/null | grep -iE 'commons-collections|beanutils|commons-logging|groovy|spring|c3p0|javassist|shiro-core|shiro-web' | head -40
echo "=== BOOT-INF/lib jars ==="
unzip -l /shirodemo-1.0-SNAPSHOT.jar 2>/dev/null | grep -E 'BOOT-INF/lib/' | awk '{print $4}' | head -80
echo "=== commands ==="
for t in curl wget bash sh python perl nc; do p=$(command -v $t 2>/dev/null); echo "$t=${p:-MISSING}"; done
echo "=== unzip/jar ==="
command -v unzip
command -v jar
echo "=== DONE ==="
