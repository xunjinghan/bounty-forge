#!/bin/bash
# 定位日志锚点的【时间戳】，并诊断"新请求不产生新日志"现象
echo "=== 全量日志行数 ==="
docker logs vulhub-shiro-18081 2>&1 | wc -l
sleep 1
echo "=== 再取一次（有无变化）==="
docker logs vulhub-shiro-18081 2>&1 | wc -l
echo
echo "=== 锚点上下文（带时间戳，前后各3行）==="
docker logs vulhub-shiro-18081 2>&1 | grep -n -B3 -A1 'HashSet cannot be cast' | head -20
echo
echo "=== BadPadding 的时间戳锚定（往前找最近的带时间戳行）==="
docker logs vulhub-shiro-18081 2>&1 | awk '/^[0-9]{4}-[0-9]{2}-[0-9]{2}/{ts=$0} /BadPadding/{print NR": [ts] "ts; print "     >>> "$0}' | head -10
echo
echo "=== HashSet cast 的时间戳锚定 ==="
docker logs vulhub-shiro-18081 2>&1 | awk '/^[0-9]{4}-[0-9]{2}-[0-9]{2}/{ts=$0} /HashSet cannot be cast/{print NR": [ts] "ts; print "     >>> "$0}' | head -5
echo
echo "=== 最后 15 行（看日志尾部当前状态）==="
docker logs vulhub-shiro-18081 2>&1 | tail -15
echo "=== DONE ==="
