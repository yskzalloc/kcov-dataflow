#!/usr/bin/env bash
# Small 1-grain, 2-engine ENGINE DIAGNOSTIC — isolates the i2s/trace_cmp counter
# (CMP_I2S_HITS + the DF_CMP_RECS record-census) on ONE grain in ~5 min instead of a
# 60-min campaign, so the trace_cmp→dataflow path can be debugged in a tight loop.
#
# Uses the ALREADY-BUILT kernel (linux/arch/x86/boot/bzImage) — this is a userspace
# (.so) debug loop, so it never rebuilds the kernel. Only the lib is recompiled.
#
#   bash engine_1grain_test.sh [GRAIN] [SECS_PER_GRAIN]
#   GRAIN default query_dir (productive lib grain); SECS default 8.
set -u
GRAIN="${1:-query_dir}"
GMAX="${2:-8}"
ENGINES=(dataflow pc-i2s)
export PATH="/home/debian-sid/venv-virtme/bin:$PATH"
TS=$(date +%Y-%m-%d_%H-%M-%S)
LOGDIR="$HOME/ksmbdzzer-logs/1grain_${TS}"
mkdir -p "$LOGDIR"

echo "===== build lib (pfz_ API + trace_cmp i2s + DF_*_RECS census) $(date +%T) ====="
( cd ~/kcov-dataflow/ksmbd && \
  cc -shared -fPIC -O2 -I/usr/include/samba-4.0 -I. libksmbdzzer.c -o libksmbdzzer.so \
     -lsmbclient -lpthread -lrdmacm -libverbs -lcrypto ) \
  || { echo "!!! LIB FAIL"; exit 12; }

cd ~/kcov-dataflow/linux || { echo "!!! no linux dir"; exit 1; }
for eng in "${ENGINES[@]}"; do
  LOG="$LOGDIR/1grain-${GRAIN}-${eng}.log"
  echo "===== ENGINE=${eng} grain=${GRAIN} (${GMAX}s) $(date +%T) ====="
  timeout -s SIGKILL 15m vng --user root --memory 8G --rw --cpus 4 \
    --append "nokaslr" \
    --exec "sysctl -w kernel.kptr_restrict=0 2>/dev/null; rm -rf /tmp/ksmbdzzer_corpus_persistent /tmp/ksmbdzzer_stability.json; export KSMBDZZER_ENGINE=${eng}; export KSMBDZZER_P3_MAX_COMBOS=0; python3 ../ksmbd/ksmbdzzer.py init && python3 ../ksmbd/ksmbdzzer.py fuzz -r 1 --grain-max ${GMAX} -t ${GRAIN}; sync; poweroff -f 2>/dev/null" \
    < /dev/null > "$LOG" 2>&1
  echo "--- ${eng} metric lines ---"
  grep -aoE '(KERNEL_PCS|RET_TOKEN_HITS|CMP_I2S_HITS|DF_CMP_RECS|DF_ENT_RECS|DF_RET_RECS)=[0-9]+' "$LOG" | tail -14
done

echo
echo "===================== 1-GRAIN ENGINE DIAGNOSTIC ($(date +%T)) ====================="
printf "%-10s | %10s | %11s | %11s | %11s | %12s\n" ENGINE KERNEL_PCS DF_CMP_RECS DF_ENT_RECS DF_RET_RECS CMP_I2S_HITS
printf -- "-----------+------------+-------------+-------------+-------------+-------------\n"
_mx(){ grep -aoE "$1=[0-9]+" "$2" 2>/dev/null | grep -oE '[0-9]+' | sort -n | tail -1; }
for eng in "${ENGINES[@]}"; do
  LOG="$LOGDIR/1grain-${GRAIN}-${eng}.log"
  kp=$(_mx KERNEL_PCS "$LOG"); cr=$(_mx DF_CMP_RECS "$LOG"); en=$(_mx DF_ENT_RECS "$LOG")
  rr=$(_mx DF_RET_RECS "$LOG"); ch=$(_mx CMP_I2S_HITS "$LOG")
  printf "%-10s | %10s | %11s | %11s | %11s | %12s\n" "$eng" \
    "${kp:-0}" "${cr:--}" "${en:--}" "${rr:--}" "${ch:-0}"
done
echo "read: DF_CMP_RECS=0  => kernel is NOT delivering 0xC comparison records (trace_cmp→dataflow"
echo "                        path dead: static key / remote-context / instrumentation)."
echo "      DF_CMP_RECS>0 & CMP_I2S_HITS=0 => records arrive but the userspace RedQueen never"
echo "                        spliced (operand-in-input match too strict) — a lib engine fix."
echo "logs: $LOGDIR/"
