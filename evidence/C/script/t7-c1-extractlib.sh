#!/bin/sh
# 只读（仅写容器内 /tmp）：用 Shiro 自身的类做 encrypt/decrypt 往返对照
set -e
mkdir -p /tmp/lib /tmp/probe
cd /tmp/probe
# 从 fat jar 里解出所有依赖 jar
unzip -o -q /shirodemo-1.0-SNAPSHOT.jar 'BOOT-INF/lib/*' -d /tmp/probe >/dev/null 2>&1
cp /tmp/probe/BOOT-INF/lib/*.jar /tmp/lib/ 2>/dev/null || true
ls /tmp/lib | grep -iE 'shiro-core|commons-codec|commons-collections|commons-beanutils|slf4j' 
CP=$(ls /tmp/lib/*.jar | tr '\n' ':')
echo "CP entries: $(ls /tmp/lib/*.jar | wc -l)"
echo "=== jrunscript available? ==="
command -v jrunscript || echo "NO jrunscript"
echo "=== javac available? ==="
command -v javac || echo "NO javac"
echo "=== DONE ==="
