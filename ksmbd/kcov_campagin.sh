#!/bin/bash
# ksmbd MAINLINE-KCOV campaign runner (fork-free baseline).
#
# Runs `ksmbdzzer.py fuzz --kcov`: the fuzzer steers on plain /sys/kernel/debug/kcov
# trace-pc coverage instead of kcov-dataflow. This is the FIRST step of the
# KCOV-vs-KCOV-DATAFLOW comparison — it establishes what a stock, fork-free KCOV
# kernel achieves, before layering the value-sensitive kcov-dataflow engine.
#
# Deliberately SIMPLER than engine_compare_campagin.sh:
#   * NO kcov-dataflow config  (CONFIG_KCOV_DATAFLOW_* off) — no custom-clang dependency
#     for the coverage feature itself; a stock CONFIG_KCOV=y kernel is enough.
#   * NO engine arms / KSMBDZZER_ENGINE ablation — one coverage source (mainline kcov).
#   * NO P3 all-pairs combination sweep, NO INSTRUMENT_ALL dataflow toggle.
# It keeps the parts that matter for an unattended run: crash-resilient resume from the
# host-durable .fuzzdb, an in-guest lockup panic + host progress watchdog, and a clean
# Ctrl+C teardown of the VM tree.
#
# Usage:  kcov_campagin.sh [ROUNDS] [GRAIN_MAX] [TIMEOUT_MIN] [TRIALS]
#   ROUNDS       fuzz generations (default 5)
#   GRAIN_MAX    per-grain time cap, seconds (default 25)
#   TIMEOUT_MIN  hard-cap minutes per (trial) run (default: auto from fleet size)
#   TRIALS       independent cold repeats (default 1)
# Env overrides:  REDO (resume retries, default 2) · STALL_SECS (watchdog, default 420)
#                 PROCS (parallel grains, default 2) · GFUZZ_ARGS (extra fuzz args, e.g.
#                 --everytime-auth or --grain-sat R) · FLEET_EST (grain count, default 211)
#                 P3_MAX_COMBOS (all-pairs sweep budget, default 0=skip) · KSMBDZZER_ALIGNED=1
#                 (scope to grain/ALIGNED_SUBSET.txt).
# NOTE: no engine arms here — kcov is the single coverage source, so ARMS_OVERRIDE /
#       KSMBDZZER_ENGINE do NOT apply. Every other engine_compare knob carries over.
set -o pipefail

usage() { sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }
case "${1:-}" in -h|--help|help) usage;; esac

REDO="${REDO:-2}"
case "$REDO" in ''|*[!0-9]*) echo "!!! REDO must be a non-negative integer"; exit 2;; esac
ROUNDS="${1:-5}"
GRAIN_MAX="${2:-25}"
TRIALS="${4:-1}"
case "$ROUNDS" in ''|*[!0-9]*) echo "!!! ROUNDS must be a positive integer"; exit 2;; esac
case "$TRIALS" in ''|*[!0-9]*) echo "!!! TRIALS must be a positive integer"; exit 2;; esac
# P3 all-pairs combination sweep budget (same knob as engine_compare). 0 = skip P3.
P3_MAX_COMBOS="${P3_MAX_COMBOS:-0}"
case "$P3_MAX_COMBOS" in ''|*[!0-9]*) echo "!!! P3_MAX_COMBOS must be a non-negative integer"; exit 2;; esac

# Auto per-run cap from fleet size (same model as engine_compare, incl. the P3 tail).
_g="$GRAIN_MAX"; (( _g < 1 )) && _g=1
FLEET_EST="${FLEET_EST:-211}"
_procs="${PROCS:-2}"; (( _procs < 1 )) && _procs=1
_waves=$(( (FLEET_EST + _procs - 1) / _procs ))
_wave_sec=$(( 30 + _g ))
# --everytime-auth makes every grain redo a fresh NTLMv2 handshake (~2.5x per-wave).
case " ${GFUZZ_ARGS:-} " in *" --everytime-auth "*) _wave_sec=$(( _wave_sec * 25 / 10 ));; esac
DEF_P2_ROUND=$(( (_waves * _wave_sec * 15 / 10 + 59) / 60 )); (( DEF_P2_ROUND < 8 )) && DEF_P2_ROUND=8
# P3 tail: final-round all-pairs sweep, weighted by combos actually run (0 when skipped).
if [ "$P3_MAX_COMBOS" -eq 0 ]; then
  DEF_P3_TAIL=0
else
  _p3_pairs=$(( FLEET_EST * (FLEET_EST + 1) / 2 ))
  _p3_combos=$_p3_pairs; (( P3_MAX_COMBOS < _p3_combos )) && _p3_combos=$P3_MAX_COMBOS
  _p3_waves=$(( (_p3_combos + _procs - 1) / _procs ))
  DEF_P3_TAIL=$(( 5 + _p3_combos / 300 + (_p3_waves * _wave_sec * 15 / 10 + 59) / 60 ))
fi
DEF_TO=$(( 22 + ROUNDS * DEF_P2_ROUND + DEF_P3_TAIL + 20 )); (( DEF_TO < 90 )) && DEF_TO=90
TIMEOUT_MIN="${3:-$DEF_TO}"
STALL_SECS="${STALL_SECS:-420}"

# KSMBDZZER_ALIGNED=1: restrict the fleet to grains that reliably reach the kernel
# (grain/ALIGNED_SUBSET.txt), appended as a `-t` list to GFUZZ_ARGS. Same knob as
# engine_compare. Resolve the path now, before the cd into linux/ below.
if [ "${KSMBDZZER_ALIGNED:-0}" = 1 ]; then
  _subset_file="$(cd "$(dirname "$0")" && pwd)/grain/ALIGNED_SUBSET.txt"
  _subset=$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$_subset_file" 2>/dev/null | tr '\n' ' ')
  if [ -n "$_subset" ]; then
    GFUZZ_ARGS="${GFUZZ_ARGS:-} -t $_subset"
    echo "===== KSMBDZZER_ALIGNED=1: fleet scoped to $(echo "$_subset" | wc -w) curated aligned grains ====="
  else
    echo "!!! KSMBDZZER_ALIGNED=1 but $_subset_file is empty/missing — running the FULL fleet."
  fi
fi

CAMPAIGN_TS="$(date +%Y-%m-%d_%H-%M-%S)"
LOGDIR="$HOME/ksmbdzzer-logs/kcov-$CAMPAIGN_TS"
mkdir -p "$LOGDIR" || { echo "!!! cannot create log directory $LOGDIR"; exit 2; }
FUZZDB="$HOME/kcov-dataflow/ksmbd/.fuzzdb/corpus.json"

source ~/venv-virtme/bin/activate
cd ~/kcov-dataflow/linux || exit 2
export PATH="$HOME/kcov-dataflow/llvm-project/build/bin:$PATH"
export RUSTC="$HOME/kcov-dataflow/rust/build/x86_64-unknown-linux-gnu/stage1/bin/rustc"
export RUST_LIB_SRC="$HOME/kcov-dataflow/rust/library"

# ─── Ctrl+C / kill teardown + progress watchdog (as in engine_compare) ───────────
CUR_PID=""; WATCH_PID=""
_kill_tree() { local p=$1 sig=$2 c; for c in $(pgrep -P "$p" 2>/dev/null); do _kill_tree "$c" "$sig"; done; kill -"$sig" "$p" 2>/dev/null; }
cleanup() {
  trap - INT TERM
  echo >&2; echo "!!! interrupted ($(date +%T)) — tearing down the VM child tree" >&2
  [ -n "$WATCH_PID" ] && kill "$WATCH_PID" 2>/dev/null
  [ -n "$CUR_PID" ] && { _kill_tree "$CUR_PID" TERM; sleep 1; _kill_tree "$CUR_PID" KILL; }
  pkill -KILL -f 'qemu-system-x86_64 -name virtme-ng' 2>/dev/null
  exit 130
}
trap cleanup INT TERM

echo "===== MAINLINE-KCOV campaign: ${ROUNDS} rounds, grain-max ${GRAIN_MAX}, cap ${TIMEOUT_MIN}m/run, ${TRIALS} trial(s) $(date +%T) ====="
echo "===== logs -> ${LOGDIR}/ ====="

echo "===== build kernel via vng --build (mainline KCOV only; no kcov-dataflow) $(date +%T) ====="
# SIMPLE config: mainline KCOV (+ comparisons for a future --kcov i2s), the ksmbd/RDMA
# surface, and the memory-safety / lockup detectors. NO CONFIG_KCOV_DATAFLOW_* and NO
# dataflow INSTRUMENT_ALL — the whole point of --kcov is that a stock KCOV kernel suffices.
KCONFIG=(
  CONFIG_KCOV=y CONFIG_KCOV_INSTRUMENT_ALL=y CONFIG_KCOV_ENABLE_COMPARISONS=y
  CONFIG_NETWORK_FILESYSTEMS=y CONFIG_SMB_SERVER=y CONFIG_SMB_SERVER_SMBDIRECT=y CONFIG_UNICODE=y
  CONFIG_SMBDIRECT=y CONFIG_SMB_SERVER_KERBEROS5=y
  CONFIG_INFINIBAND=y CONFIG_INFINIBAND_USER_ACCESS=y CONFIG_RDMA_RXE=y CONFIG_RDMA_SIW=y CONFIG_DUMMY=y
  CONFIG_KASAN=y CONFIG_KASAN_GENERIC=y CONFIG_KASAN_INLINE=y
  CONFIG_SLUB_DEBUG=y CONFIG_SLUB_DEBUG_ON=y CONFIG_FORTIFY_SOURCE=y CONFIG_HARDENED_USERCOPY=y
  CONFIG_UBSAN=y CONFIG_UBSAN_BOUNDS=y CONFIG_UBSAN_ARRAY_BOUNDS=y
  CONFIG_LOCKDEP=y CONFIG_PROVE_LOCKING=y CONFIG_PROVE_RCU=y CONFIG_DEBUG_ATOMIC_SLEEP=y CONFIG_DEBUG_LIST=y
  CONFIG_DETECT_HUNG_TASK=y CONFIG_BOOTPARAM_HUNG_TASK_PANIC=y
  CONFIG_SOFTLOCKUP_DETECTOR=y CONFIG_BOOTPARAM_SOFTLOCKUP_PANIC=y
  CONFIG_FAULT_INJECTION=y CONFIG_FAILSLAB=y CONFIG_FAULT_INJECTION_DEBUG_FS=y
  CONFIG_DEBUG_INFO=y CONFIG_DEBUG_INFO_DWARF5=y CONFIG_DYNAMIC_DEBUG=y CONFIG_DEBUG_FS=y
)
CFG_ARGS=(); for c in "${KCONFIG[@]}"; do CFG_ARGS+=(--configitem "$c"); done
vng --build "${CFG_ARGS[@]}" LLVM=1 CC=clang RUSTC="$RUSTC" RUST_LIB_SRC="$RUST_LIB_SRC" \
  || { echo "!!! KBUILD FAIL"; exit 11; }

# vng --configitem silently drops the lockup detectors + dynamic-debug — force them and,
# if needed, do a cheap incremental rebuild so a wedge self-panics and the resume loop fires.
if ! grep -q '^CONFIG_DETECT_HUNG_TASK=y' .config || ! grep -q '^CONFIG_SOFTLOCKUP_DETECTOR=y' .config \
   || ! grep -q '^CONFIG_DYNAMIC_DEBUG=y' .config; then
  echo "===== config fixup: +lockup detectors, +dynamic-debug $(date +%T) ====="
  ./scripts/config --enable DEBUG_KERNEL \
                   --enable DETECT_HUNG_TASK --enable BOOTPARAM_HUNG_TASK_PANIC \
                   --enable SOFTLOCKUP_DETECTOR --enable BOOTPARAM_SOFTLOCKUP_PANIC \
                   --enable DEBUG_FS --enable DYNAMIC_DEBUG
  make LLVM=1 CC=clang RUSTC="$RUSTC" RUST_LIB_SRC="$RUST_LIB_SRC" olddefconfig >/dev/null \
    || { echo "!!! olddefconfig FAIL"; exit 11; }
  make LLVM=1 CC=clang RUSTC="$RUSTC" RUST_LIB_SRC="$RUST_LIB_SRC" -j"$(nproc)" bzImage \
    || { echo "!!! lockup-detector rebuild FAIL"; exit 11; }
fi

# sanity — KCOV + ksmbd must be present; kcov-dataflow must be ABSENT (this is the point).
for need in CONFIG_KCOV CONFIG_SMB_SERVER CONFIG_KASAN CONFIG_PROVE_LOCKING CONFIG_RDMA_RXE; do
  grep -q "^${need}=y" .config || { echo "!!! ${need}=y missing after vng --build (check deps)"; exit 13; }
done
if grep -q '^CONFIG_KCOV_DATAFLOW_ARGS=y' .config; then
  echo "!!! NOTE: CONFIG_KCOV_DATAFLOW_ARGS is still ON — this campaign intends a mainline-KCOV-ONLY"
  echo "!!!   kernel. It will still run (--kcov reads /sys/kernel/debug/kcov regardless), but the"
  echo "!!!   build is not the minimal fork-free baseline. Disable it for a clean comparison."
fi

echo "===== build lib (pfz_ API; mainline-kcov path compiled in) $(date +%T) ====="
( cd ~/kcov-dataflow/ksmbd && \
  cc -shared -fPIC -O2 -I/usr/include/samba-4.0 -I. libksmbdzzer.c -o libksmbdzzer.so \
     -lsmbclient -lpthread -lrdmacm -libverbs -lcrypto ) \
  || { echo "!!! LIB FAIL"; exit 12; }

echo "===== host-prebuild grain fleet (static-embed; in-guest P1 → cache hit) $(date +%T) ====="
( cd ~/kcov-dataflow/ksmbd && PATH="/usr/bin:$PATH" python3 ksmbdzzer.py build-grains ) \
  || echo "!!! build-grains prebuild failed (non-fatal — in-guest P1 will compile the fleet)"

MAX_ATTEMPTS=$(( REDO + 1 ))
echo "===== ${TRIALS} trial(s) x ${ROUNDS} rounds (<=${MAX_ATTEMPTS} attempts/run, resume-on-wedge) ====="
for trial in $(seq 1 "$TRIALS"); do
  LOG="$LOGDIR/kcov-t${trial}.log"
  echo "===== TRIAL ${trial}/${TRIALS} -> ${LOG} $(date +%T) ====="
  : > "$LOG"
  rm -f "$FUZZDB"                     # COLD start — only on the first attempt
  attempt=1
  while :; do
    echo "----- attempt ${attempt}/${MAX_ATTEMPTS} $(date +%T) -----" | tee -a "$LOG"
    _t0=$SECONDS
    timeout -s SIGKILL "${TIMEOUT_MIN}m" vng --verbose --user root --memory 16G --rw --cpus 8 \
      --append "nokaslr hung_task_panic=1 hung_task_timeout_secs=60 softlockup_panic=1" \
      --exec "mount -t debugfs none /sys/kernel/debug 2>/dev/null; sysctl -w kernel.kptr_restrict=0; rm -rf /tmp/ksmbdzzer_corpus_persistent /tmp/ksmbdzzer_stability.json; export KSMBDZZER_KCOV=1; export KSMBDZZER_SEED=${trial}; export KSMBDZZER_AUTH_DEBUG=1; export KSMBDZZER_P3_MAX_COMBOS=${P3_MAX_COMBOS}; python3 ../ksmbd/ksmbdzzer.py init && python3 ../ksmbd/ksmbdzzer.py fuzz --kcov -r ${ROUNDS} --grain-max ${GRAIN_MAX} -procs ${PROCS:-2} ${GFUZZ_ARGS:-}; timeout 12 sync 2>/dev/null; poweroff -f 2>/dev/null" \
      < /dev/null > >(tee -a "$LOG") 2>&1 &
    CUR_PID=$!
    ( _last=-1; _stuck=0
      while kill -0 "$CUR_PID" 2>/dev/null; do
        sleep 30
        _cur=$(wc -c < "$LOG" 2>/dev/null || echo 0)
        if [ "$_cur" = "$_last" ]; then
          _stuck=$(( _stuck + 30 ))
          if [ "$_stuck" -ge "$STALL_SECS" ]; then
            echo "===== WATCHDOG: no log progress for ${STALL_SECS}s — guest wedged; tree-killing to resume from .fuzzdb $(date +%T) =====" | tee -a "$LOG"
            _kill_tree "$CUR_PID" TERM; sleep 1; _kill_tree "$CUR_PID" KILL
            pkill -KILL -f 'qemu-system-x86_64 -name virtme-ng' 2>/dev/null
            break
          fi
        else
          _last=$_cur; _stuck=0
        fi
      done ) &
    WATCH_PID=$!
    wait "$CUR_PID"; rc=$?
    CUR_PID=""
    kill "$WATCH_PID" 2>/dev/null; wait "$WATCH_PID" 2>/dev/null; WATCH_PID=""
    sleep 0.5
    _dur=$(( SECONDS - _t0 ))
    echo "----- attempt ${attempt} exited rc=${rc} in ${_dur}s $(date +%T) -----" | tee -a "$LOG"
    if grep -qa '4-phase grain campaign done' "$LOG"; then
      echo "===== TRIAL ${trial}: completed on attempt ${attempt} $(date +%T) =====" | tee -a "$LOG"
      break
    fi
    _cap_secs=$(( TIMEOUT_MIN * 60 ))
    if grep -qa 'WATCHDOG: no log progress' "$LOG"; then
      _why="STALL (progress watchdog tree-killed a wedged guest)"; _hardcap=0
    elif grep -qaE 'KASAN|BUG:|blocked for more than|soft lockup|general protection|Oops|Kernel panic' "$LOG"; then
      _why="KERNEL PANIC/BUG (oops in the log)"; _hardcap=0
    elif [ "$rc" -eq 137 ] && [ "$_dur" -ge $(( _cap_secs - 30 )) ]; then
      _why="HARD CAP (${TIMEOUT_MIN}m) — progressing, not wedged; raise TIMEOUT_MIN"; _hardcap=1
    else
      _why="unexpected exit (rc=${rc})"; _hardcap=0
    fi
    if [ "$attempt" -ge "$MAX_ATTEMPTS" ]; then
      echo "===== TRIAL ${trial}: GAVE UP after ${MAX_ATTEMPTS} attempt(s) — ${_why}; .fuzzdb preserved $(date +%T) =====" | tee -a "$LOG"
      break
    fi
    if [ "$_hardcap" -eq 1 ]; then
      echo "===== TRIAL ${trial}: ${_why}; NOT re-doing — re-launch with a larger TIMEOUT_MIN. $(date +%T) =====" | tee -a "$LOG"
      break
    fi
    echo "===== TRIAL ${trial}: ${_why} on attempt ${attempt} — RE-DOING, resuming from .fuzzdb $(date +%T) =====" | tee -a "$LOG"
    attempt=$(( attempt + 1 ))
  done
done

echo
{
echo "===================== MAINLINE-KCOV CAMPAIGN ($(date +%T)) ====================="
echo "coverage source = mainline /sys/kernel/debug/kcov (trace-pc), --kcov"
_maxnum(){ grep -aoE "$1=[0-9]+" "$2" 2>/dev/null | grep -oE '[0-9]+' | sort -n | tail -1; }
printf "%-8s | %-20s | %8s | %6s\n" TRIAL "kern_pcs∪" corpus bugs
printf -- "---------+----------------------+----------+------\n"
for trial in $(seq 1 "$TRIALS"); do
  LOG="$LOGDIR/kcov-t${trial}.log"
  [ -f "$LOG" ] || { printf "%-8s | (no log)\n" "$trial"; continue; }
  kpu=$(_maxnum KERNEL_PCS_UNION "$LOG"); kps=$(_maxnum KERNEL_PCS "$LOG")
  kp="${kpu:-0}"; [ "${kp:-0}" -eq 0 ] && kp="${kps:-0}"
  cp=$(grep -aoE '\[corpus\] [0-9]+' "$LOG" | tail -1 | grep -oE '[0-9]+')
  bugs=$(grep -aE 'KASAN|BUG:|general protection|Oops|WARNING:|recursive locking|list_.*corrupt|UBSAN|blocked for more than|soft lockup' "$LOG" \
         | sed -E 's/0x[0-9a-fA-F]+/0xADDR/g; s/[0-9]+/N/g' | sort -u | wc -l)
  printf "%-8s | %-20s | %8s | %6s\n" "$trial" "${kp:-0}" "${cp:-0}" "$bugs"
done
printf -- "---------+----------------------+----------+------\n"
echo "kern_pcs = distinct kernel PCs reached (fork-free KCOV baseline). Compare this"
echo "against the kcov-dataflow 'dataflow' arm from engine_compare_campagin.sh: the"
echo "delta is the value-sensitivity payoff of kcov-dataflow over stock edge coverage."
echo "!!! PREREQUISITE: --kcov only collects once ksmbd routes mainline kcov-remote to the"
echo "!!!   per-connection handle (conn->kcov_handle == KSMBD_KCOV_IP_HANDLE). If kern_pcs"
echo "!!!   is 0 for every trial, that routing is not yet wired — see the kcov_remote notes."
echo "===== DONE $(date +%T) ====="
echo "===== logs: ${LOGDIR}/ ====="
} | tee "$LOGDIR/summary.txt"
