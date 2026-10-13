#!/bin/bash
# 决定性验证：把容器内的 gadget jar 抽到 Kali，用真实 Java 反序列化我的 payload
# 只读：不动靶场数据；仅在本机 /tmp 内操作
set -x
WORK=/tmp/t7-deser
rm -rf $WORK && mkdir -p $WORK/jars
# 从 shiro 容器导出依赖 jar（gadget 链需要的 commons-collections / commons-beanutils）
for j in commons-collections-3.2.1.jar commons-beanutils-1.9.2.jar shiro-core-1.2.4.jar commons-logging-1.1.1.jar; do
  cp /tmp/lib/$j $WORK/jars/ 2>/dev/null || echo "miss $j"
done
ls -la $WORK/jars/
echo "=== javac? ==="
command -v javac || echo "NO javac on kali"
echo "=== java only (25) - can we compile a single-file? ==="
java --version 2>&1 | head -2
echo "=== DONE ==="
