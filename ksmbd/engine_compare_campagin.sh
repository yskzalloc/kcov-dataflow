#!/bin/bash
# ksmbd gfuzz ENGINE COMPARISON runner.
#
# Runs the SAME grains, on the SAME kernel, under three fuzzing engines and diffs
# them head-to-head (a controlled ablation via KSMBDZZER_ENGINE — identical
# instrumentation, so the only variables are the coverage signal and the mutator):
#
#   1st engine  dataflow : value-sensitive (pc,val) kcov-dataflow coverage + i2s
#   2nd engine  pc-i2s   : pc-only coverage                              + i2s
#   2nd engine  pc-havoc : pc-only coverage                              + havoc
#
# So: dataflow-vs-pc-only isolates what the trace-args/ret VALUES add; pc-i2s-vs-
# pc-havoc isolates what trace_cmp i2s adds over blind havoc.
#
# Usage:  engine_compare_campagin.sh [ROUNDS] [GRAIN_MAX] [TIMEOUT_MIN_PER_ARM] [TRIALS]
#   ROUNDS   gfuzz rounds PER ARM PER TRIAL (default 5)
#   GRAIN_MAX  per-grain cap (default 25)
#   TIMEOUT_MIN_PER_ARM  safety cap per (arm,trial) (default ROUNDS*30, min 90)
#   TRIALS   independent cold repeats per arm (default 3) — fuzzing is stochastic, so
#            a single run ranks noise; each trial gets a distinct-but-reproducible
#            libFuzzer seed (KSMBDZZER_SEED) and its own cold corpus. The table
#            aggregates ACROSS trials (median kern_pcs + range, deduped bugs).
#
# Each (arm,trial) starts COLD (guest /tmp + host .fuzzdb corpus reset) so nothing
# inherits another run's corpus. All logs for one invocation land in a per-campaign,
# file-safe timestamped directory: ~/ksmbdzzer-logs/<YYYY-MM-DD_HH-MM-SS>/ (colons are
# replaced by hyphens so the path is a valid filename), holding
# engine-<arm>-t<trial>.log per run plus summary.txt (the final table).
#
# RESUME-ON-WEDGE: gfuzz saves the corpus to the host-durable mirror (.fuzzdb, 9p
# repo mount — NOT guest /tmp) after EVERY round, atomically. So if a run hangs
# (→ hung_task_panic) or panics the kernel, its accumulated generations survive.
# Each (arm,trial) is retried up to REDO+1 attempts; the COLD wipe happens ONLY on
# the first attempt — a re-do KEEPS .fuzzdb, so ksmbdzzer.py resumes the SAME trial's
# corpus (still isolated to this arm/trial, so the comparison stays valid). REDO=0
# disables re-doing.  Override: REDO=3 bash engine_compare_campagin.sh ...
set -o pipefail

usage() {
  cat <<'EOF'
engine_compare_campagin.sh — ksmbd gfuzz ENGINE COMPARISON runner

Builds ONE kernel + lib, then fuzzes the SAME grains under three engines (a
controlled ablation via KSMBDZZER_ENGINE) and prints a head-to-head table.
  dataflow  value-sensitive (pc,val) kcov-dataflow coverage + i2s   [1st engine]
  pc-i2s    pc-only coverage                              + i2s      [2nd engine]
  pc-havoc  pc-only coverage                              + havoc    [2nd engine]
dataflow-vs-pc-i2s isolates the VALUE payoff; pc-i2s-vs-pc-havoc isolates the i2s payoff.

USAGE
  engine_compare_campagin.sh [ROUNDS] [GRAIN_MAX] [TIMEOUT_MIN_PER_ARM] [TRIALS]
  engine_compare_campagin.sh -h | --help

POSITIONAL ARGUMENTS  (all optional; shown with their defaults)
  ROUNDS               5   gfuzz generations per (arm,trial). More = deeper feed-forward
                           corpus but longer runtime.
  GRAIN_MAX          25  per-grain time cap (seconds), passed to gfuzz --grain-max.
                           Higher = each grain fuzzes deeper before moving on (needed for
                           i2s to actually fire; too low and pc-i2s≈pc-havoc means nothing).
  TIMEOUT_MIN_PER_ARM  ROUNDS*30 (min 90)  SIGKILL safety cap PER RUN. Only trips on a
                           wedge — gfuzz exits on its own after ROUNDS.
  TRIALS               3   independent COLD repeats per arm. Fuzzing is stochastic, so a
                           single run ranks noise; each trial gets a distinct reproducible
                           libFuzzer seed and the table aggregates across trials
                           (median kern_pcs + [min-max] range, deduped bugs).

  Total VM runs = TRIALS x 3 arms, each up to REDO+1 attempts on a wedge.

ENVIRONMENT OVERRIDES
  REDO   2   resume-on-wedge retries per run (REDO=0 disables). A re-do KEEPS the durable
             .fuzzdb corpus, so the trial resumes where it wedged (still isolated to that
             arm/trial, so the comparison stays valid).
  ARMS_OVERRIDE   (unset)   space-separated subset of {dataflow pc-i2s pc-havoc}. Use for a
             LIGHT bug-fix RE-CHECK — one arm = one VM instead of TRIALS×3. The RDMA/
             smbdirect grain runs in every arm, so a single arm still exercises it.
  STALL_SECS   420   host watchdog: kill+resume if the live log makes no progress this long.

LIGHT RE-CHECK (verify a kernel deadlock/hang fix reproduces no more — fast, one VM)
  REDO=0 ARMS_OVERRIDE=dataflow bash engine_compare_campagin.sh 1 15 20 1
    → 1 round, elt-max 15s, 20-min cap, 1 trial, dataflow arm only, no re-do.
      FIX HELD  ⇒ log ends with '4-phase grain campaign done' (no hung_task panic).
      STILL BROKEN ⇒ hung_task panic (~2 min after a stuck release) → GAVE UP; the
      blocked-task stack is in the log. Bump ROUNDS 1→3 for more churn once it passes.

EXAMPLES
  engine_compare_campagin.sh                # defaults: 5 rounds, elt-max 25, 3 trials
  engine_compare_campagin.sh 5 25 150 3     # explicit defaults + a 150-min cap per run
  engine_compare_campagin.sh 3 20           # quick: 3 rounds, elt-max 20, 3 trials
  engine_compare_campagin.sh 10 40 300 5    # deep: 10 rounds, elt-max 40, 300-min cap, 5 trials
  engine_compare_campagin.sh 5 25 150 1     # fast: single trial (no cross-trial median)
  REDO=3 engine_compare_campagin.sh 5 25    # up to 4 attempts/run on a wedge
  REDO=0 engine_compare_campagin.sh 3 20    # no resume — bail a run on first wedge

OUTPUT
  Log dir:      ~/ksmbdzzer-logs/<YYYY-MM-DD_HH-MM-SS>/   (file-safe, per campaign)
  Per-run log:  <log-dir>/engine-<arm>-t<trial>.log
  Final table:  <log-dir>/summary.txt AND stdout — kern_pcs (PRIMARY, median[min-max]) |
                ret_hits | cmp_hits | corpus | max_ft | bugs.
                Ctrl+C once tears down the VM tree cleanly.

NOTES
  Rebuilds the kernel (vng --build, custom clang) + libksmbdzzer.so on every invocation.
  Needs ~/venv-virtme and the custom clang/rustc under ~/kcov-dataflow. Run from anywhere.
EOF
}
case "${1:-}" in -h|--help|help) usage; exit 0;; esac

REDO="${REDO:-2}"
case "$REDO" in ''|*[!0-9]*) echo "!!! REDO must be a non-negative integer"; exit 2;; esac

ROUNDS="${1:-5}"
GRAIN_MAX="${2:-25}"
DEF_TO=$(( ROUNDS * 30 )); (( DEF_TO < 90 )) && DEF_TO=90
TIMEOUT_MIN="${3:-$DEF_TO}"
TRIALS="${4:-3}"
case "$ROUNDS" in ''|*[!0-9]*) echo "!!! ROUNDS must be a positive integer"; exit 2;; esac
case "$TRIALS" in ''|*[!0-9]*) echo "!!! TRIALS must be a positive integer"; exit 2;; esac

# ARMS defaults to the full 3-arm ablation. For a LIGHT bug-fix RE-CHECK, override it
# with a single arm so one VM boots instead of TRIALS×3 — e.g. re-verify a kernel
# deadlock fix reproduces no more:
#   REDO=0 ARMS_OVERRIDE=dataflow bash engine_compare_campagin.sh 1 15 20 1
# (dataflow is the harshest arm — heaviest kcov-dataflow load — so it's the best
# single-arm smoke test; the RDMA/smbdirect grain runs in every arm regardless.)
if [ -n "${ARMS_OVERRIDE:-}" ]; then
  IFS=' ' read -r -a ARMS <<< "$ARMS_OVERRIDE"
else
  ARMS=(dataflow pc-i2s pc-havoc)
fi
FUZZDB="$HOME/kcov-dataflow/ksmbd/.fuzzdb/corpus.json"

# Per-campaign, FILE-SAFE log directory. `date` normally prints HH:MM:SS with colons,
# which are legal on Linux but break portability (and are illegal on other FSes), so we
# format with hyphens: 2026-07-07_21-09-33. All logs for THIS invocation live under it.
CAMPAIGN_TS="$(date +%Y-%m-%d_%H-%M-%S)"
LOGDIR="$HOME/ksmbdzzer-logs/$CAMPAIGN_TS"
mkdir -p "$LOGDIR" || { echo "!!! cannot create log directory $LOGDIR"; exit 2; }

source ~/venv-virtme/bin/activate
cd ~/kcov-dataflow/linux || exit 2
export PATH="$HOME/kcov-dataflow/llvm-project/build/bin:$PATH"
export RUSTC="$HOME/kcov-dataflow/rust/build/x86_64-unknown-linux-gnu/stage1/bin/rustc"
export RUST_LIB_SRC="$HOME/kcov-dataflow/rust/library"

# ─── Ctrl+C / kill teardown ────────────────────────────────────────────────────
# vng launches qemu through vng → virtme-run → sh → qemu, and qemu often reparents
# away (to init), so a plain SIGINT to this script leaves the VM orphaned (had to
# `kill <qemu-pid>` by hand). Track the current attempt's `timeout` PID and, on
# INT/TERM, recursively kill its whole descendant tree PLUS any straggler virtme
# qemu by name — so one Ctrl+C reliably stops everything.
CUR_PID=""
WATCH_PID=""
# Progress-watchdog stall threshold: if the LIVE log makes no progress for this
# long, the guest is wedged (kernel livelock / exit-storm the in-guest lockup
# detectors can't catch — e.g. a printk-to-serial livelock or a spin with IRQs
# off) and NOTHING inside the VM can rescue it. The host kills the tree so the
# re-do loop resumes from durable .fuzzdb instead of burning the whole
# ${TIMEOUT_MIN}m wall. MUST exceed the longest legitimately-quiet stretch (a P2
# saturation wave + its retry wave ≈ 2*max_time); default 420s is comfortably
# above that yet far below the multi-minute/hour cap. Tunable via env.
STALL_SECS="${STALL_SECS:-420}"
_kill_tree() {                    # _kill_tree PID SIGNAL — kill children depth-first, then PID
  local p=$1 sig=$2 c
  for c in $(pgrep -P "$p" 2>/dev/null); do _kill_tree "$c" "$sig"; done
  kill -"$sig" "$p" 2>/dev/null
}
cleanup() {
  trap - INT TERM
  echo >&2; echo "!!! interrupted ($(date +%T)) — tearing down the VM child tree" >&2
  [ -n "$WATCH_PID" ] && kill "$WATCH_PID" 2>/dev/null   # stop the progress watchdog first
  if [ -n "$CUR_PID" ]; then
    _kill_tree "$CUR_PID" TERM; sleep 1; _kill_tree "$CUR_PID" KILL
  fi
  pkill -KILL -f 'qemu-system-x86_64 -name virtme-ng' 2>/dev/null   # reparented straggler VM
  exit 130
}
trap cleanup INT TERM

echo "===== engine comparison: ${#ARMS[@]} arms x ${ROUNDS} rounds, grain-max ${GRAIN_MAX}, cap ${TIMEOUT_MIN}m/arm $(date +%T) ====="
echo "===== logs -> ${LOGDIR}/ ====="

echo "===== build kernel via vng --build (custom clang; portable configitems) $(date +%T) ====="
# PORTABLE config (no machine-specific .config snapshot): vng --build starts from
# virtme's base (make defconfig + VM essentials: 9p/virtio/overlay + crypto/keys/net)
# and we assert the ksmbdzzer "maximal detection" set (ksmbd/README.md) + the kcov
# trace_cmp stack via --configitem. CONFIG_SMB_SERVER=y auto-selects ksmbd's crypto
# deps, so we only list the feature/detector symbols. Kept in sync with README.md.
KCONFIG=(
  # kcov-dataflow steering + trace_cmp (the whole point of this comparison)
  CONFIG_KCOV=y CONFIG_KCOV_INSTRUMENT_ALL=y CONFIG_KCOV_ENABLE_COMPARISONS=y
  CONFIG_KCOV_DATAFLOW_ARGS=y CONFIG_KCOV_DATAFLOW_RET=y CONFIG_KCOV_DATAFLOW_INSTRUMENT_ALL=y
  # ksmbd + RDMA transport
  CONFIG_NETWORK_FILESYSTEMS=y CONFIG_SMB_SERVER=y CONFIG_SMB_SERVER_SMBDIRECT=y
  CONFIG_SMBDIRECT=y CONFIG_SMB_SERVER_KERBEROS5=y
  CONFIG_INFINIBAND=y CONFIG_INFINIBAND_USER_ACCESS=y CONFIG_RDMA_RXE=y CONFIG_RDMA_SIW=y CONFIG_DUMMY=y
  # memory safety / UB / locking / lists
  CONFIG_KASAN=y CONFIG_KASAN_GENERIC=y CONFIG_KASAN_INLINE=y
  CONFIG_SLUB_DEBUG=y CONFIG_SLUB_DEBUG_ON=y CONFIG_FORTIFY_SOURCE=y CONFIG_HARDENED_USERCOPY=y
  CONFIG_UBSAN=y CONFIG_UBSAN_BOUNDS=y CONFIG_UBSAN_ARRAY_BOUNDS=y
  CONFIG_LOCKDEP=y CONFIG_PROVE_LOCKING=y CONFIG_PROVE_RCU=y CONFIG_DEBUG_ATOMIC_SLEEP=y CONFIG_DEBUG_LIST=y
  # wedge self-termination — WITHOUT these the boot 'hung_task_panic=1'/'softlockup_panic=1'
  # silently no-op ("parameter not found") and the resume-on-wedge loop has no trigger:
  # a hang/livelock just spins until the outer SIGKILL. Build them so a wedge panics and
  # the (arm,trial) auto-re-does from the durable corpus.
  CONFIG_DETECT_HUNG_TASK=y CONFIG_BOOTPARAM_HUNG_TASK_PANIC=y
  CONFIG_SOFTLOCKUP_DETECTOR=y CONFIG_BOOTPARAM_SOFTLOCKUP_PANIC=y
  # fault injection (error-path testing)
  CONFIG_FAULT_INJECTION=y CONFIG_FAILSLAB=y CONFIG_FAULT_INJECTION_DEBUG_FS=y
  # symbolization (with nokaslr)
  CONFIG_DEBUG_INFO=y CONFIG_DEBUG_INFO_DWARF5=y
)
CFG_ARGS=(); for c in "${KCONFIG[@]}"; do CFG_ARGS+=(--configitem "$c"); done
vng --build "${CFG_ARGS[@]}" \
  LLVM=1 CC=clang RUSTC="$RUSTC" RUST_LIB_SRC="$RUST_LIB_SRC" \
  || { echo "!!! KBUILD FAIL"; exit 11; }

# vng --build's --configitem SILENTLY DROPS the lockup detectors (verified: scripts/config
# + olddefconfig KEEPS DETECT_HUNG_TASK/SOFTLOCKUP_DETECTOR — no missing dep, DEBUG_KERNEL=y
# — but virtme's configitem pass discards them). Force them in and do a small INCREMENTAL
# rebuild so a wedge self-panics (hung_task/softlockup) and the resume loop fires in ~60s
# instead of waiting out the ${TIMEOUT_MIN}m SIGKILL. Cheap: hung_task.o+watchdog.o + relink.
if ! grep -q '^CONFIG_DETECT_HUNG_TASK=y' .config || ! grep -q '^CONFIG_SOFTLOCKUP_DETECTOR=y' .config; then
  echo "===== force-enabling lockup detectors dropped by --configitem $(date +%T) ====="
  ./scripts/config --enable DEBUG_KERNEL \
                   --enable DETECT_HUNG_TASK --enable BOOTPARAM_HUNG_TASK_PANIC \
                   --enable SOFTLOCKUP_DETECTOR --enable BOOTPARAM_SOFTLOCKUP_PANIC
  make LLVM=1 CC=clang RUSTC="$RUSTC" RUST_LIB_SRC="$RUST_LIB_SRC" olddefconfig >/dev/null \
    || { echo "!!! olddefconfig FAIL"; exit 11; }
  make LLVM=1 CC=clang RUSTC="$RUSTC" RUST_LIB_SRC="$RUST_LIB_SRC" -j"$(nproc)" bzImage \
    || { echo "!!! lockup-detector rebuild FAIL"; exit 11; }
fi

# sanity — LOAD-BEARING symbols are FATAL (a dropped one silently breaks the experiment):
for need in CONFIG_KCOV_ENABLE_COMPARISONS CONFIG_KCOV_DATAFLOW_ARGS CONFIG_SMB_SERVER \
            CONFIG_KASAN CONFIG_PROVE_LOCKING CONFIG_RDMA_RXE; do
  grep -q "^${need}=y" .config || { echo "!!! ${need}=y missing after vng --build (check deps)"; exit 13; }
done
# lockup detectors are ADVISORY — without them a wedge falls back to the ${TIMEOUT_MIN}m
# SIGKILL backstop (slower, but the resume loop still recovers). WARN, never abort.
for need in CONFIG_DETECT_HUNG_TASK CONFIG_SOFTLOCKUP_DETECTOR; do
  grep -q "^${need}=y" .config || echo "!!! WARNING: ${need}=y still missing — wedge self-panic disabled; relying on the ${TIMEOUT_MIN}m SIGKILL backstop"
done

echo "===== build lib (pfz_ API + trace_cmp i2s) $(date +%T) ====="
( cd ~/kcov-dataflow/ksmbd && \
  cc -shared -fPIC -O2 -I/usr/include/samba-4.0 -I. libksmbdzzer.c -o libksmbdzzer.so \
     -lsmbclient -lpthread -lrdmacm -libverbs -lcrypto ) \
  || { echo "!!! LIB FAIL"; exit 12; }

MAX_ATTEMPTS=$(( REDO + 1 ))
echo "===== ${TRIALS} trial(s) x ${#ARMS[@]} arms x ${ROUNDS} rounds (<=${MAX_ATTEMPTS} attempts/run, resume-on-wedge) ====="
for trial in $(seq 1 "$TRIALS"); do
  for arm in "${ARMS[@]}"; do
    LOG="$LOGDIR/engine-${arm}-t${trial}.log"
    echo "===== TRIAL ${trial}/${TRIALS}  ARM '${arm}' -> ${LOG} $(date +%T) ====="
    : > "$LOG"                         # fresh log for this (arm,trial)
    rm -f "$FUZZDB"                    # COLD start — ONLY on the first attempt below
    attempt=1
    while :; do
      echo "----- attempt ${attempt}/${MAX_ATTEMPTS} $(date +%T) -----" | tee -a "$LOG"
      _t0=$SECONDS
      # Background + wait (not a foreground pipeline) so a Ctrl+C trap fires promptly
      # even when vng is blocked on a wedged qemu; CUR_PID = the `timeout` to tree-kill.
      timeout -s SIGKILL "${TIMEOUT_MIN}m" vng --verbose --user root --memory 16G --rw --cpus 8 \
        --append "nokaslr hung_task_panic=1 hung_task_timeout_secs=60 softlockup_panic=1" \
        --exec "mount -t debugfs none /sys/kernel/debug 2>/dev/null; sysctl -w kernel.kptr_restrict=0; rm -rf /tmp/ksmbdzzer_corpus_persistent /tmp/ksmbdzzer_stability.json; export KSMBDZZER_ENGINE=${arm}; export KSMBDZZER_SEED=${trial}; export KSMBDZZER_AUTH_DEBUG=1; python3 ../ksmbd/ksmbdzzer.py init && python3 ../ksmbd/ksmbdzzer.py gfuzz -r ${ROUNDS} --grain-max ${GRAIN_MAX}" \
        < /dev/null > >(tee -a "$LOG") 2>&1 &
      CUR_PID=$!
      # PROGRESS WATCHDOG: a wedged guest (kernel livelock / exit-storm) leaves the
      # vng `timeout` alive but the LOG frozen — so `wait` below would block the
      # whole ${TIMEOUT_MIN}m for nothing. This backgrounds a monitor on the log's
      # byte count; if it stops growing for STALL_SECS, it tree-kills CUR_PID so the
      # `wait` returns and the re-do loop resumes from durable .fuzzdb. This is the
      # ONLY layer that can rescue a frozen guest (in-guest logic isn't running).
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
      wait "$CUR_PID"; rc=$?          # 137 = SIGKILL wall; on Ctrl+C the trap runs here
      CUR_PID=""
      kill "$WATCH_PID" 2>/dev/null; wait "$WATCH_PID" 2>/dev/null; WATCH_PID=""
      sleep 0.5                       # let the tee process-sub flush the tail before we grep
      echo "----- attempt ${attempt} exited rc=${rc} in $((SECONDS-_t0))s $(date +%T) -----" | tee -a "$LOG"
      if grep -qa '4-phase grain campaign done' "$LOG"; then
        echo "===== TRIAL ${trial} ARM ${arm}: completed on attempt ${attempt} $(date +%T) =====" | tee -a "$LOG"
        break
      fi
      if [ "$attempt" -ge "$MAX_ATTEMPTS" ]; then
        echo "===== TRIAL ${trial} ARM ${arm}: GAVE UP after ${MAX_ATTEMPTS} attempt(s) (rc=${rc}) — durable corpus (.fuzzdb) preserved for a manual resume $(date +%T) =====" | tee -a "$LOG"
        break
      fi
      echo "===== TRIAL ${trial} ARM ${arm}: WEDGE/PANIC (rc=${rc}) on attempt ${attempt} — RE-DOING, resuming from durable corpus (.fuzzdb KEPT, NOT wiped) $(date +%T) =====" | tee -a "$LOG"
      attempt=$(( attempt + 1 ))
      # Deliberately DO NOT rm "$FUZZDB": ksmbdzzer.py corpus_load() falls back to the
      # host-durable mirror, so the re-do continues THIS trial's accumulated corpus.
    done
  done
done

echo
# Emit the whole summary to stdout AND persist it in the campaign log dir. The group
# is piped to tee so summary.txt captures the table verbatim (it only READS shell vars,
# so running the group in the pipe's subshell is fine).
{
echo "===================== ENGINE COMPARISON ($(date +%T)) ====================="
# Aggregated ACROSS ${TRIALS} independent trials per arm. PRIMARY metric = kern_pcs
# (distinct kernel PCs reached — the trustworthy cross-arm number; libFuzzer ft/corpus
# conflate harness edges with value buckets and are ENGINE-BIASED → secondary). We
# report the MEDIAN kern_pcs with the [min–max] trial range so a single lucky/unlucky
# run can't set the verdict. ret_hits/cmp_hits (i2s proof) are the MAX across trials
# (fired at least once ⇒ i2s active). bugs = DISTINCT crash signatures (addresses/line
# numbers normalized) deduped across all trials, not a raw log-hit count.
# Per-log max of "$1=N"; _median reads numbers on stdin.
_maxnum(){ grep -aoE "$1=[0-9]+" "$2" 2>/dev/null | grep -oE '[0-9]+' | sort -n | tail -1; }
_median(){ sort -n | awk '{a[NR]=$0} END{ if(NR==0){print 0}
  else if(NR%2){print a[(NR+1)/2]} else {print int((a[NR/2]+a[NR/2+1])/2)} }'; }
printf "%-10s | %-18s | %8s | %8s | %8s | %8s | %6s\n" \
  ENGINE "kern_pcs(med[rng])" ret_hits cmp_hits corpus max_ft bugs
printf -- "-----------+--------------------+----------+----------+----------+----------+-------\n"
for arm in "${ARMS[@]}"; do
  LOGS=( "$LOGDIR"/engine-"${arm}"-t*.log )
  [ -e "${LOGS[0]}" ] || { printf "%-10s | (no logs)\n" "$arm"; continue; }
  kp_list=(); cp_list=(); ft_list=(); rmax=0; cmax=0
  for LOG in "${LOGS[@]}"; do
    [ -f "$LOG" ] || continue
    kp=$(_maxnum KERNEL_PCS "$LOG");                  kp_list+=("${kp:-0}")
    cp=$(grep -aoE '\[corpus\] [0-9]+' "$LOG" | tail -1 | grep -oE '[0-9]+'); cp_list+=("${cp:-0}")
    ft=$(grep -aoE 'ft0=[0-9]+→[0-9]+' "$LOG" | grep -oE '→[0-9]+' | tr -d '→' | sort -n | tail -1); ft_list+=("${ft:-0}")
    r=$(_maxnum RET_TOKEN_HITS "$LOG"); (( ${r:-0} > rmax )) && rmax=${r:-0}
    c=$(_maxnum CMP_I2S_HITS  "$LOG"); (( ${c:-0} > cmax )) && cmax=${c:-0}
  done
  kp_med=$(printf '%s\n' "${kp_list[@]}" | _median)
  kp_min=$(printf '%s\n' "${kp_list[@]}" | sort -n | head -1)
  kp_max=$(printf '%s\n' "${kp_list[@]}" | sort -n | tail -1)
  cp_med=$(printf '%s\n' "${cp_list[@]}" | _median)
  ft_med=$(printf '%s\n' "${ft_list[@]}" | _median)
  # Distinct crash signatures across ALL trials of this arm (normalize hex + numbers).
  bugs=$(cat "${LOGS[@]}" 2>/dev/null \
         | grep -aE 'KASAN|BUG:|general protection|Oops|WARNING:|recursive locking|list_.*corrupt|UBSAN' \
         | sed -E 's/0x[0-9a-fA-F]+/0xADDR/g; s/[0-9]+/N/g' | sort -u | wc -l)
  kp_cell="${kp_med} [${kp_min}-${kp_max}]"
  printf "%-10s | %-18s | %8s | %8s | %8s | %8s | %6s\n" \
    "$arm" "$kp_cell" "$rmax" "$cmax" "$cp_med" "$ft_med" "$bugs"
done
printf -- "-----------+--------------------+----------+----------+----------+----------+-------\n"
echo "TWO engines, three arms, aggregated over ${TRIALS} trial(s):"
echo "  1st engine  = dataflow            (kcov-dataflow value coverage + i2s)"
echo "  2nd engine  = pc-i2s + pc-havoc   (pc-only coverage; i2s vs havoc mutation)"
echo "PRIMARY: kern_pcs = distinct kernel PCs reached, FLEET-WIDE. Both the lib grains"
echo "  (libksmbdzzer.c pfz_get_features) and the raw common.h grains now (a) honor"
echo "  KSMBDZZER_ENGINE so the pc-only arms REALLY drop the dataflow value, and"
echo "  (b) run pfz_mutate_i2s so i2s + its proof counters are fleet-wide — not just"
echo "  the 2 raw grains. dataflow-vs-pc-i2s therefore isolates the value payoff."
echo "PROOF: ret_hits = RedQueen return→token splices; cmp_hits = trace_cmp operand"
echo "  splices (now whole fleet). ret_hits>0 is the precondition for reading pc-i2s"
echo "  vs pc-havoc as an i2s result (else i2s was inert and they SHOULD tie)."
echo "SECONDARY (engine-biased, do NOT headline): corpus (median) = inputs kept — value"
echo "  coverage keeps more by construction; max_ft (median) = deepest single-grain ft."
echo "read: dataflow vs pc-i2s = value-coverage payoff ; pc-i2s vs pc-havoc = i2s payoff"
echo "===== DONE $(date +%T) ====="
echo "===== logs: ${LOGDIR}/ ====="
} | tee "$LOGDIR/summary.txt"
