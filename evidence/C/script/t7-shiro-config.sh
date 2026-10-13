#!/bin/sh
# 只读：shiro 应用配置（密钥来源）+ jar 内 shiro 配置
echo "=== jar 内 application*.yml/properties ==="
unzip -p /shirodemo-1.0-SNAPSHOT.jar BOOT-INF/classes/application.yml 2>/dev/null | head -40
unzip -p /shirodemo-1.0-SNAPSHOT.jar BOOT-INF/classes/application.properties 2>/dev/null | head -40
echo "=== jar 内 shiro 配置类 ==="
unzip -l /shirodemo-1.0-SNAPSHOT.jar 2>/dev/null | grep -iE 'BOOT-INF/classes/.*(Shiro|Config|Realm)' | head -20
echo "=== 启动命令行 ==="
cat /proc/1/cmdline 2>/dev/null | tr '\0' ' '; echo
echo "=== DONE ==="
