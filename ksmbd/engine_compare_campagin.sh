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
#   TIMEOUT_MIN_PER_ARM  hard-cap MINUTES per (arm,trial). Default derived from the MEASURED
#            workload (cold P1 ~15m + ROUNDS x ~18m P2 + final-round P3 all-pairs tail),
#            GRAIN_MAX-scaled — NOT the legacy flat ROUNDS*30. It is a generous BUDGET, not
#            the wedge detector: STALL_SECS + hung_task/softlockup panics catch a wedge fast.
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
  TIMEOUT_MIN_PER_ARM  hard-cap MINUTES per run. DEFAULT is derived from the measured
                           present workload, not a flat ROUNDS*30 (which predates the
                           24->~100 grain fleet and the all-pairs P3 tail):
                             cold P1 build ~15m  +  ROUNDS x ~18m P2  +  final-round P3
                             all-pairs tail,  all scaled by GRAIN_MAX.
                           The cap is a generous BUDGET, NOT the wedge detector: STALL_SECS
                           (progress watchdog) + the in-guest hung_task/softlockup panics
                           catch a genuine wedge in ~7 min. A run that still reaches this cap
                           is reported as HARD CAP (progressing — raise it) instead of being
                           re-done as a false wedge.
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
  INSTRUMENT_ALL  1   1=whole-kernel dataflow (trace-args/ret folded past ksmbd into the VFS/mm
             it calls; needs the clang-23 fork fixes to build) · 0=scope to ksmbd TUs (faster,
             no clang-fork dep, avoids flooding/truncating the 64MB df_buf with off-path 0xE
             records). Flips ONLY the dataflow scope; mainline pc/cmp instrument-all stays on,
             so `INSTRUMENT_ALL=1 vs 0` is a clean A/B of "what whole-kernel VALUE folding adds":
               INSTRUMENT_ALL=1 REDO=0 ARMS_OVERRIDE=dataflow-vec bash engine_compare_campagin.sh 1 20 "" 1
               INSTRUMENT_ALL=0 REDO=0 ARMS_OVERRIDE=dataflow-vec bash engine_compare_campagin.sh 1 20 "" 1
  GFUZZ_ARGS   (unset)   extra args appended VERBATIM to the guest `ksmbdzzer.py gfuzz` command
             (after `-r ROUNDS --grain-max GRAIN_MAX`). Use it to scope the fleet with the
             gfuzz `-t/--target` list — e.g. run ONLY the suspect SET_INFO/delete grains to
             repro a wedge and capture its hung-task stack, or run a hang-free safe subset to
             validate metrics without fighting a kernel deadlock:
               GFUZZ_ARGS='-t set_disposition del_reparse set_eof offload_write offload_read' \
                 REDO=0 ARMS_OVERRIDE=dataflow bash engine_compare_campagin.sh 1 20 60 1
               GFUZZ_ARGS='-t write create_ctx query_dir oplock_ack' ...   # safe metric check

LIGHT RE-CHECK (verify a kernel deadlock/hang fix reproduces no more — fast, one VM)
  REDO=0 ARMS_OVERRIDE=dataflow bash engine_compare_campagin.sh 1 20 60 1
    → 1 round, grain-max 20s, 60-min cap, 1 trial, dataflow arm only, no re-do.
      FIX HELD  ⇒ log ends with '4-phase grain campaign done' (no hung_task panic).
      STILL BROKEN ⇒ hung_task/softlockup panic or STALL → GAVE UP; the blocked-task stack
      is in the log. Add GFUZZ_ARGS='-t <grain>...' to narrow to the culprit grain.

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
# Per-run hard-cap MINUTES, derived from the MEASURED present workload — not the legacy
# flat ROUNDS*30, which predates the 24->~100 grain fleet and the all-pairs P3 and so
# under-budgets (a still-progressing run then trips the cap). Measured 2026-07-08
# (GRAIN_MAX=25, ~112 harnesses, 8-way): cold P1 build ~15 min (887s; ~44s warm),
# P2 saturation ~18 min/round (~1000s). P3 (final round only) is thousands of all-pairs
# combo runs — the dominant tail; it never completed under the old caps, so it is an
# ESTIMATE. All three scale with GRAIN_MAX (per-grain seconds). This cap is a generous
# BUDGET, not the wedge detector: STALL_SECS (progress watchdog) + hung_task/softlockup
# panics catch a real wedge in ~7 min, and a run that still hits the cap is reported as
# HARD CAP (progressing) instead of re-done as a false wedge.
# P3 (final-round all-pairs C(n+1,2) combination sweep) budget. P3 is a crash-yield
# REFINEMENT and contributes NOTHING to the coverage comparison (kern_pcs/corpus/max_ft
# are all set in P2), yet it dominates wall-clock: PREP alone compiles one harness per
# pair (~4851 @ g=25 → ~20 min) and the sweep needs HOURS. A time-boxed comparison run
# then never reaches poweroff and gets SIGKILLed mid-sweep (rc=137), yielding a degenerate
# one-arm table. So DEFAULT to skipping P3 here (=0). Override P3_MAX_COMBOS=N to sample N
# pairs, or =full-ish for a bug-hunt (but then budget hours per arm).
P3_MAX_COMBOS="${P3_MAX_COMBOS:-0}"
case "$P3_MAX_COMBOS" in ''|*[!0-9]*) echo "!!! P3_MAX_COMBOS must be a non-negative integer"; exit 2;; esac

# INSTRUMENT_ALL (1=default, 0=off) toggles CONFIG_KCOV_DATAFLOW_INSTRUMENT_ALL — whole-kernel
# trace-args/ret (dataflow values folded past ksmbd into the VFS/mm it calls) vs ksmbd-TU-scoped.
# ONLY the dataflow scope flips; mainline CONFIG_KCOV_INSTRUMENT_ALL (pc/cmp) stays on, so the
# A/B isolates "what does WHOLE-KERNEL VALUE folding add" (reach into VFS OOB gates) against its
# cost (per-op overhead → fewer execs; whole-kernel 0xE volume can overflow the 64MB df_buf and
# TRUNCATE the ksmbd/VFS records). Off also drops the clang-fork build dependency.
INSTRUMENT_ALL="${INSTRUMENT_ALL:-1}"
case "$INSTRUMENT_ALL" in 0|1) ;; *) echo "!!! INSTRUMENT_ALL must be 0 or 1"; exit 2;; esac
_IA_YN=$( [ "$INSTRUMENT_ALL" = 1 ] && echo y || echo n )

_g="$GRAIN_MAX"; (( _g < 1 )) && _g=1
# The P2 wall is FLEET-driven: gfuzz runs one wave per grain, ceil(FLEET/procs) waves per
# round — it is NOT scaled by --grain-max (which only caps per-grain execs). The old model
# scaled P2 by grain-max and badly underestimated once the fleet grew 25→112 grains: a g=20
# run auto-derived 94m but needed ~100m and died at wave 108/112. Model per fleet size.
FLEET_EST="${FLEET_EST:-211}"           # ≈ lib.pfz_grain_count() (N_GRAINS, batches 10-15 landed 2026-07-22); bump from a log's "N grains" line as the fleet grows
_procs="${PROCS:-2}"; (( _procs < 1 )) && _procs=1
_waves=$(( (FLEET_EST + _procs - 1) / _procs ))
DEF_COLD_P1=22                          # boot + cold full-fleet grain compile (offloaded when build-grains ran) + boot variance
# per-wave seconds: ~45s measured at grain-max 20 / INSTRUMENT_ALL=1 / lazy auth; grows with
# the per-grain exec ceiling (more mutations per wave → longer wave).
_wave_sec=$(( 30 + _g ))
# --everytime-auth makes EVERY grain redo a fresh NTLMv2 pool handshake and provokes a
# mountd-storm at -procs>1. Cost is TWO-fold: (1) per-wave ~1.7x slower (measured ~77s vs
# ~45s), AND (2) the storm 0-execs more grains, each re-run up to 4x by the retry loop —
# retry amplification not captured by fleet×wave_sec. Fold both into ~2.5x. The cap is only
# a ceiling (poweroff -f ends a clean run early), so over-budgeting this heavy/high-variance
# mode is free — it just prevents a premature SIGKILL when the storm is bad.
_ETA_AUTH=0
case " ${GFUZZ_ARGS:-} " in *" --everytime-auth "*) _ETA_AUTH=1 ;; esac
(( _ETA_AUTH )) && _wave_sec=$(( _wave_sec * 25 / 10 ))
# RETRY/DEATH AMPLIFICATION (×1.5): the base fleet×wave model ignores that ~40% of
# grains 0-exec at init and are re-run in-place (gen.py retry wave), plus starvation
# re-waves — measured to add roughly half a fleet-pass of wall-clock per round. Fold
# it in so the auto-cap doesn't SIGKILL a still-progressing run mid-round (the exact
# trap the 2026-07-17 smoke hit: an explicit 90m vs a real ~2h+ need). Over-budgeting
# is free — a clean run reaches `poweroff -f` and ends early; the cap only bounds a wedge.
DEF_P2_ROUND=$(( (_waves * _wave_sec * 15 / 10 + 59) / 60 ))   # minutes for one full fleet pass (×1.5 retry/death)
(( DEF_P2_ROUND < 8 )) && DEF_P2_ROUND=8
# P3 tail term: 0 when P3 is skipped (the default). Otherwise WEIGHT it by the number
# of combos that actually run. P3 is combinations_with_replacement over the whole fleet
# — C(FLEET+1,2) = FLEET*(FLEET+1)/2 pairs (FLEET=112 → 6328; 95 → 4560) — capped to
# P3_MAX_COMBOS, scheduled ceil(combos/procs) waves through the -procs pool, each combo a
# saturation run at the SAME per-wave cost as P2 (grain-max seconds + overhead, auth-amp
# folded into _wave_sec). The OLD fixed 150*_g/25 ignored combo count, so a large/uncapped
# P3_MAX_COMBOS was badly under-budgeted and the fleet tripped the hard cap mid-sweep. Note
# a FULL sweep is genuinely many hours-to-days (6328 combos / 2 procs × ~70s ≈ days) — this
# estimate now reflects that, so cap P3_MAX_COMBOS for any time-boxed run.
if [ "$P3_MAX_COMBOS" -eq 0 ]; then
  DEF_P3_TAIL=0
else
  _p3_pairs=$(( FLEET_EST * (FLEET_EST + 1) / 2 ))   # C(FLEET+1,2), r=2 with replacement
  _p3_combos=$_p3_pairs
  (( P3_MAX_COMBOS < _p3_combos )) && _p3_combos=$P3_MAX_COMBOS
  _p3_waves=$(( (_p3_combos + _procs - 1) / _procs ))
  # PREP: 1 compile + a symlink/dict per pair (minor next to the run term).
  _p3_prep=$(( 5 + _p3_combos / 300 ))
  # Run: same per-wave secs as P2 (incl. auth amp), ×1.5 retry/death, rounded up to minutes.
  DEF_P3_TAIL=$(( _p3_prep + (_p3_waves * _wave_sec * 15 / 10 + 59) / 60 ))
fi
DEF_TO=$(( DEF_COLD_P1 + ROUNDS * DEF_P2_ROUND + DEF_P3_TAIL + 20 ))  # +20m mount/oracle/teardown + variance slack
(( DEF_TO < 90 )) && DEF_TO=90
TIMEOUT_MIN="${3:-$DEF_TO}"
# Warn (don't override) when an EXPLICIT arg-3 is below the auto-estimate — the exact trap
# that capped the --everytime-auth run: 60m set by hand vs a fleet needing ~90m+.
if [ -n "${3:-}" ] && (( TIMEOUT_MIN < DEF_TO )); then
  echo "!!! NOTE: TIMEOUT_MIN=${TIMEOUT_MIN}m is BELOW the auto-estimate ${DEF_TO}m$( (( _ETA_AUTH )) && echo ' (--everytime-auth ≈1.8x heavier)' ) — the fleet will likely hit the HARD CAP mid-run. Omit arg 3 to use the estimate, or raise it."
fi
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
# LOUD cap disclosure (#4): the derived per-run cap is otherwise buried, and a wedge-prone
# arm can silently burn the WHOLE cap (the dataflow arm hung ~8h under an 8.6h auto-cap
# before its own hung_task backstop fired). Surface the cap + worst-case wall-clock up
# front, and warn when the cap is large so the operator cuts ROUNDS/P3 or passes a tight
# explicit arg-3 BEFORE discovering a multi-day runtime after the fact.
if (( TIMEOUT_MIN > ${KSMBDZZER_CAP_WARN_MIN:-180} )); then
  echo "!!! CAP NOTE: per-run cap = ${TIMEOUT_MIN}m (auto-estimate ${DEF_TO}m). This is LARGE:"
  echo "!!!   a wedge-prone arm can burn the whole cap. For a coverage A/B set ROUNDS=1 +"
  echo "!!!   P3_MAX_COMBOS=0 and pass an explicit tight arg-3 (e.g. 75). Worst-case now:"
  echo "!!!   ${TIMEOUT_MIN}m x ${#ARMS[@]} arms x ${TRIALS} trials ≈ $(( TIMEOUT_MIN * ${#ARMS[@]} * TRIALS / 60 ))h."
fi
# CURATED subset (#7): KSMBDZZER_ALIGNED=1 restricts the fleet to the grains that RELIABLY
# reach the kernel (grain/ALIGNED_SUBSET.txt — aligned in >=6/9 of the 2026-07-19 campaign),
# dropping the ~50 consistently-shallow/free-running grains so budget goes to grains that
# actually penetrate ksmbd. Appends `-t <names>` to GFUZZ_ARGS. The auto-cap (FLEET_EST=112)
# is then conservative for the smaller fleet — safe (a clean run powers off early).
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

echo "===== engine comparison: ${#ARMS[@]} arms x ${ROUNDS} rounds, grain-max ${GRAIN_MAX}, cap ${TIMEOUT_MIN}m/arm, P3=$( [ "$P3_MAX_COMBOS" -eq 0 ] && echo 'skipped (coverage-only)' || echo "${_p3_combos}/${_p3_pairs} combos, ${_procs}-way ~${DEF_P3_TAIL}m" ), dataflow-instrument-all=$( [ "$INSTRUMENT_ALL" = 1 ] && echo 'whole-kernel' || echo 'ksmbd-scoped' ) $(date +%T) ====="
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
  # Whole-kernel dataflow instrumentation (args/ret past ksmbd into the VFS/mm it calls). The
  # two clang-23 fork bugs that broke this on core files are FIXED in SanitizerCoverage.cpp:
  # i915 SSA-dominance in the Pass-2 #dbg_value scan (e89ec35 regression), and topology_ext
  # base/frame-pointer interference from the trace-ret spill under KASAN (c60c03), guarded by
  # functionInlineAsmUsesBasePointerX86(). REBUILD clang (ninja -C llvm-project/build bin/clang-23)
  # after pulling those fixes, or the whole-kernel build breaks on i915/topology_ext.
  CONFIG_KCOV_DATAFLOW_ARGS=y CONFIG_KCOV_DATAFLOW_RET=y "CONFIG_KCOV_DATAFLOW_INSTRUMENT_ALL=${_IA_YN}"
  # ksmbd + RDMA transport. CONFIG_UNICODE = utf8_casefold path (case-insensitive share/file
  # names in ksmbd_casefold_sharename); without it that path falls back to ASCII and the
  # casefold_share_name grain's deep surface is unreachable.
  CONFIG_NETWORK_FILESYSTEMS=y CONFIG_SMB_SERVER=y CONFIG_SMB_SERVER_SMBDIRECT=y CONFIG_UNICODE=y
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
  # dynamic debug — lets `init` flip ksmbd's ksmbd_debug()/pr_debug on at runtime via
  # /sys/kernel/debug/dynamic_debug/control (needs DEBUG_FS) so a session-setup rejection
  # prints its EXACT reason ("Unexpected OID", "Not support authentication", …) to dmesg.
  CONFIG_DYNAMIC_DEBUG=y CONFIG_DEBUG_FS=y
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
# Config fixups (vng --configitem drops symbols unpredictably): force the lockup detectors,
# dynamic-debug, AND the INSTRUMENT_ALL toggle to its DESIRED scope (=${_IA_YN}) back in.
# Whole-kernel dataflow (INSTRUMENT_ALL=y) widens trace-args/ret past ksmbd into the VFS/mm it
# calls; it needs the clang-23 fork fixes (i915 SSA-dominance, topology_ext base/frame-pointer
# under KASAN) — now FIXED in SanitizerCoverage.cpp — to build. =n scopes it to ksmbd TUs.
if [ "$_IA_YN" = y ]; then
  grep -q '^CONFIG_KCOV_DATAFLOW_INSTRUMENT_ALL=y' .config && _ia_match=1 || _ia_match=0
  _ia_flag=--enable
else
  grep -q '^CONFIG_KCOV_DATAFLOW_INSTRUMENT_ALL=y' .config && _ia_match=0 || _ia_match=1
  _ia_flag=--disable
fi
if ! grep -q '^CONFIG_DETECT_HUNG_TASK=y' .config || ! grep -q '^CONFIG_SOFTLOCKUP_DETECTOR=y' .config \
   || [ "$_ia_match" = 0 ] \
   || ! grep -q '^CONFIG_DYNAMIC_DEBUG=y' .config; then
  echo "===== config fixup: +lockup detectors, INSTRUMENT_ALL=${_IA_YN}, +dynamic-debug $(date +%T) ====="
  ./scripts/config ${_ia_flag} KCOV_DATAFLOW_INSTRUMENT_ALL \
                   --enable DEBUG_KERNEL \
                   --enable DETECT_HUNG_TASK --enable BOOTPARAM_HUNG_TASK_PANIC \
                   --enable SOFTLOCKUP_DETECTOR --enable BOOTPARAM_SOFTLOCKUP_PANIC \
                   --enable DEBUG_FS --enable DYNAMIC_DEBUG
  make LLVM=1 CC=clang RUSTC="$RUSTC" RUST_LIB_SRC="$RUST_LIB_SRC" olddefconfig >/dev/null \
    || { echo "!!! olddefconfig FAIL"; exit 11; }
  make LLVM=1 CC=clang RUSTC="$RUSTC" RUST_LIB_SRC="$RUST_LIB_SRC" -j"$(nproc)" bzImage \
    || { echo "!!! lockup-detector rebuild FAIL"; exit 11; }
fi

# sanity — LOAD-BEARING symbols are FATAL (a dropped one silently breaks the experiment).
# CONFIG_KCOV_DATAFLOW_RET is the RETURN-value instrumentation the i2s ret-token path needs;
# without it df_buf carries no rt==0xF records (ret_hits stuck at 0). ADDED after a run where
# it was fine but INSTRUMENT_ALL had silently dropped — the old check only verified _ARGS.
for need in CONFIG_KCOV_ENABLE_COMPARISONS CONFIG_KCOV_DATAFLOW_ARGS CONFIG_KCOV_DATAFLOW_RET \
            CONFIG_SMB_SERVER CONFIG_KASAN CONFIG_PROVE_LOCKING CONFIG_RDMA_RXE; do
  grep -q "^${need}=y" .config || { echo "!!! ${need}=y missing after vng --build (check deps)"; exit 13; }
done
# INSTRUMENT_ALL scope should match the toggle (=${_IA_YN}). ADVISORY — a mismatch still builds/runs
# but the dataflow reach is not what you asked for, so make it visible.
if [ "$_IA_YN" = y ]; then
  grep -q '^CONFIG_KCOV_DATAFLOW_INSTRUMENT_ALL=y' .config \
    && echo "===== INSTRUMENT_ALL=1: whole-kernel dataflow (trace-args/ret past ksmbd into VFS/mm) =====" \
    || echo "!!! WARNING: INSTRUMENT_ALL=1 requested but CONFIG_KCOV_DATAFLOW_INSTRUMENT_ALL is OFF — dataflow limited to ksmbd TUs; did you rebuild clang with the SanitizerCoverage fixes?"
else
  grep -q '^CONFIG_KCOV_DATAFLOW_INSTRUMENT_ALL=y' .config \
    && echo "!!! WARNING: INSTRUMENT_ALL=0 requested but CONFIG_KCOV_DATAFLOW_INSTRUMENT_ALL is still ON (configitem/fixup didn't take)" \
    || echo "===== INSTRUMENT_ALL=0: dataflow scoped to ksmbd TUs (faster, no clang-fork dep, no whole-kernel df_buf flood) ====="
fi
# DYNAMIC_DEBUG is ADVISORY (diagnostic only): without it the init's write to
# /sys/kernel/debug/dynamic_debug/control no-ops and a mount rejection shows just the
# status code, not the ksmbd_debug() reason. WARN, never abort.
grep -q '^CONFIG_DYNAMIC_DEBUG=y' .config \
  || echo "!!! WARNING: CONFIG_DYNAMIC_DEBUG not set — ksmbd runtime debug unavailable (mount failures won't print their reason to dmesg)."
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

# HOST-PREBUILD the grain fleet now that libksmbdzzer.{c,so} are current. The in-guest P1
# keys its compile cache on grain-source identity + the .so/.c mtime, so building the whole
# fleet here on the native FS turns each arm's in-guest P1 from a ~10-15m 9p recompile into
# a cache hit (~seconds). Static-embed (default) → grains carry libksmbdzzer.c and need no
# libksmbdzzer.so at runtime (robust over 9p). Use SYSTEM clang, not the kernel-fork clang-23
# now first on PATH — grains are plain x86_64 libFuzzer harnesses matching the guest toolchain.
# Non-fatal: if this fails, the in-guest P1 still compiles the fleet the old way.
echo "===== host-prebuild grain fleet (static-embed; in-guest P1 → cache hit) $(date +%T) ====="
( cd ~/kcov-dataflow/ksmbd && PATH="/usr/bin:$PATH" python3 ksmbdzzer.py build-grains ) \
  || echo "!!! build-grains prebuild failed (non-fatal — in-guest P1 will compile the fleet)"

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
        --exec "mount -t debugfs none /sys/kernel/debug 2>/dev/null; sysctl -w kernel.kptr_restrict=0; rm -rf /tmp/ksmbdzzer_corpus_persistent /tmp/ksmbdzzer_stability.json; export KSMBDZZER_ENGINE=${arm}; export KSMBDZZER_SEED=${trial}; export KSMBDZZER_AUTH_DEBUG=1; export KSMBDZZER_P3_MAX_COMBOS=${P3_MAX_COMBOS}; python3 ../ksmbd/ksmbdzzer.py init && python3 ../ksmbd/ksmbdzzer.py gfuzz -r ${ROUNDS} --grain-max ${GRAIN_MAX} -procs ${PROCS:-2} ${GFUZZ_ARGS:-}; timeout 12 sync 2>/dev/null; poweroff -f 2>/dev/null" \
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
      _dur=$(( SECONDS - _t0 ))
      echo "----- attempt ${attempt} exited rc=${rc} in ${_dur}s $(date +%T) -----" | tee -a "$LOG"
      if grep -qa '4-phase grain campaign done' "$LOG"; then
        echo "===== TRIAL ${trial} ARM ${arm}: completed on attempt ${attempt} $(date +%T) =====" | tee -a "$LOG"
        break
      fi
      # CLASSIFY the stop reason — rc=137 is ambiguous (it is emitted by the outer hard-cap
      # `timeout`, by the progress-watchdog tree-kill, AND by a panic-driven SIGKILL). Do NOT
      # blanket-label everything "WEDGE/PANIC": a run that used ~the whole ${TIMEOUT_MIN}m and
      # left no stall/oops signature simply ran out of wall-clock while PROGRESSING.
      _cap_secs=$(( TIMEOUT_MIN * 60 ))
      if grep -qa 'WATCHDOG: no log progress' "$LOG"; then
        _why="STALL (progress watchdog tree-killed a wedged guest)"; _hardcap=0
      elif grep -qaE 'KASAN|BUG:|blocked for more than|soft lockup|general protection|Oops|Kernel panic' "$LOG"; then
        _why="KERNEL PANIC/BUG (oops in the log)"; _hardcap=0
      elif [ "$rc" -eq 137 ] && [ "$_dur" -ge $(( _cap_secs - 30 )) ]; then
        _why="HARD CAP (${TIMEOUT_MIN}m) — the run was PROGRESSING, not wedged; raise TIMEOUT_MIN (arg 3) or lower ROUNDS/GRAIN_MAX"; _hardcap=1
      else
        _why="unexpected exit (rc=${rc})"; _hardcap=0
      fi
      if [ "$attempt" -ge "$MAX_ATTEMPTS" ]; then
        echo "===== TRIAL ${trial} ARM ${arm}: GAVE UP after ${MAX_ATTEMPTS} attempt(s) — ${_why}; durable corpus (.fuzzdb) preserved for a manual resume $(date +%T) =====" | tee -a "$LOG"
        break
      fi
      # A HARD-CAP timeout means the workload does not fit ${TIMEOUT_MIN}m; re-running the SAME
      # budget just re-hits the same wall (and burns another full budget). Stop and tell the
      # user to raise it. STALL/PANIC are genuine wedges → resume-from-.fuzzdb is the designed
      # recovery, so those still re-do.
      if [ "$_hardcap" -eq 1 ]; then
        echo "===== TRIAL ${trial} ARM ${arm}: ${_why}; NOT re-doing (a re-run would hit the same wall). .fuzzdb preserved — re-launch with a larger TIMEOUT_MIN to continue. $(date +%T) =====" | tee -a "$LOG"
        break
      fi
      echo "===== TRIAL ${trial} ARM ${arm}: ${_why} on attempt ${attempt} — RE-DOING, resuming from durable corpus (.fuzzdb KEPT, NOT wiped) $(date +%T) =====" | tee -a "$LOG"
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
# Aggregated ACROSS ${TRIALS} independent trials per arm. PRIMARY metric = kern_pcs∪
# (DEDUPLICATED fleet-wide union of distinct kernel PCs — the throughput-FAIR cross-arm
# number. NOT the old per-grain-popcount SUM, which double-counts shared PCs and let the
# cheapest-per-exec engine win by cycling more grains. libFuzzer ft/corpus conflate
# harness edges with value buckets and are ENGINE-BIASED → secondary). We
# report the MEDIAN kern_pcs with the [min–max] trial range so a single lucky/unlucky
# run can't set the verdict. ret_hits/cmp_hits (i2s proof) are the MAX across trials
# (fired at least once ⇒ i2s active). bugs = DISTINCT crash signatures (addresses/line
# numbers normalized) deduped across all trials, not a raw log-hit count.
# Per-log max of "$1=N"; _median reads numbers on stdin.
_maxnum(){ grep -aoE "$1=[0-9]+" "$2" 2>/dev/null | grep -oE '[0-9]+' | sort -n | tail -1; }
_median(){ sort -n | awk '{a[NR]=$0} END{ if(NR==0){print 0}
  else if(NR%2){print a[(NR+1)/2]} else {print int((a[NR/2]+a[NR/2+1])/2)} }'; }
printf "%-10s | %-18s | %8s | %8s | %8s | %8s | %6s\n" \
  ENGINE "kern_pcs∪(med[rng])" ret_hits cmp_hits corpus max_ft bugs
printf -- "-----------+--------------------+----------+----------+----------+----------+-------\n"
_any_kp=0; _any_i2s=0     # all-zeros guard: did the PRIMARY (kern_pcs) / i2s-proof metrics emit at all?
for arm in "${ARMS[@]}"; do
  LOGS=( "$LOGDIR"/engine-"${arm}"-t*.log )
  [ -e "${LOGS[0]}" ] || { printf "%-10s | (no logs)\n" "$arm"; continue; }
  kp_list=(); cp_list=(); ft_list=(); rmax=0; cmax=0
  for LOG in "${LOGS[@]}"; do
    [ -f "$LOG" ] || continue
    # PRIMARY = deduplicated fleet UNION of kernel PCs (throughput-FAIR). The old
    # KERNEL_PCS was a per-grain-popcount SUM that double-counts shared PCs and rewards
    # the cheapest-per-exec engine (havoc scored 20x the SUM by cycling more grains, not
    # by reaching more code). Prefer KERNEL_PCS_UNION; fall back to the SUM for old logs.
    kpu=$(_maxnum KERNEL_PCS_UNION "$LOG"); kps=$(_maxnum KERNEL_PCS "$LOG")
    kp="${kpu:-0}"; [ "${kp:-0}" -eq 0 ] && kp="${kps:-0}"
    kp_list+=("${kp:-0}")
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
         | grep -aE 'KASAN|BUG:|general protection|Oops|WARNING:|recursive locking|list_.*corrupt|UBSAN|blocked for more than|soft lockup' \
         | sed -E 's/0x[0-9a-fA-F]+/0xADDR/g; s/[0-9]+/N/g' | sort -u | wc -l)
  kp_cell="${kp_med} [${kp_min}-${kp_max}]"
  (( kp_max > 0 )) && _any_kp=1
  # i2s-active gate = cmp_hits (trace_cmp operand splices), NOT ret_hits. In ksmbd the
  # return-token path is structurally ~0 (functions return status codes/pointers, filtered;
  # the magic values flow through output buffers -> args records, not C returns), so ret_hits
  # is a false negative. cmp_hits is the reliable "i2s fired" signal.
  (( cmax > 0 )) && _any_i2s=1
  printf "%-10s | %-18s | %8s | %8s | %8s | %8s | %6s\n" \
    "$arm" "$kp_cell" "$rmax" "$cmax" "$cp_med" "$ft_med" "$bugs"
done
printf -- "-----------+--------------------+----------+----------+----------+----------+-------\n"
# ALL-ZEROS GUARD: kern_pcs is the ONLY unbiased cross-arm metric, and ret/cmp_hits are the
# i2s proof. If they are zero for EVERY arm the metrics were not emitted (e.g. every grain
# SIGKILLed before its dump) — the table is a measurement artifact, NOT a real tie. Say so
# loudly instead of letting all-zero columns read like data.
if [ "$_any_kp" -eq 0 ]; then
  echo "!!! INVALID: kern_pcs = 0 for EVERY arm — the PRIMARY metric was NOT emitted (grains"
  echo "!!!   killed before their KERNEL_PCS dump, or no grain reached kernel PCs). The table"
  echo "!!!   above is a measurement artifact, not a comparison. Do NOT read a verdict from it."
  echo "!!!   Expect non-zero after the periodic-emission fix (fb()/pfz_get_features)."
elif [ "$_any_i2s" -eq 0 ]; then
  echo "!!! CAUTION: cmp_hits = 0 for every arm — the i2s mutator never spliced a trace_cmp"
  echo "!!!   operand (i2s inert or GRAIN_MAX too low). pc-i2s vs pc-havoc is UNREADABLE as an"
  echo "!!!   i2s result (they SHOULD tie); only dataflow-vs-pc-i2s (value payoff) is valid."
  echo "!!!   (ret_hits is IGNORED as a gate: ~0 by design in ksmbd — see PROOF note below.)"
fi
echo "TWO engines, three arms, aggregated over ${TRIALS} trial(s):"
echo "  1st engine  = dataflow            (kcov-dataflow value coverage + i2s)"
echo "  2nd engine  = pc-i2s + pc-havoc   (pc-only coverage; i2s vs havoc mutation)"
echo "PRIMARY: kern_pcs = distinct kernel PCs reached, FLEET-WIDE. Both the lib grains"
echo "  (libksmbdzzer.c pfz_get_features) and the raw common.h grains now (a) honor"
echo "  KSMBDZZER_ENGINE so the pc-only arms REALLY drop the dataflow value, and"
echo "  (b) run pfz_mutate_i2s so i2s + its proof counters are fleet-wide — not just"
echo "  the 2 raw grains. dataflow-vs-pc-i2s therefore isolates the value payoff."
echo "PROOF (i2s active): cmp_hits = trace_cmp operand splices — the RELIABLE signal, whole"
echo "  fleet. cmp_hits>0 is the precondition for reading pc-i2s vs pc-havoc as an i2s result"
echo "  (else i2s was inert and they SHOULD tie). ret_hits (return-token splices) is"
echo "  structurally ~0 in ksmbd and NOT a gate: C functions return status codes/pointers"
echo "  (filtered), while fids/resume-keys flow through OUTPUT BUFFERS → args records, not"
echo "  returns — so the return-value RedQueen has almost nothing to splice here."
echo "SECONDARY (engine-biased, do NOT headline): corpus (median) = inputs kept — value"
echo "  coverage keeps more by construction; max_ft (median) = deepest single-grain ft."
echo "read: dataflow vs pc-i2s = value-coverage payoff ; pc-i2s vs pc-havoc = i2s payoff"
echo "===== DONE $(date +%T) ====="
echo "===== logs: ${LOGDIR}/ ====="
} | tee "$LOGDIR/summary.txt"
