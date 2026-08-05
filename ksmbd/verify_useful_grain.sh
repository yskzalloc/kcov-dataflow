#!/bin/bash
# ksmbd grain-VALIDITY verifier — the "a grain must work" principle, made runnable.
#
# Boots ONE guest and runs `ksmbdzzer.py selftest`: each grain is executed a few times
# straight through the pfz_ ctypes API (no LibFuzzer / no P2) and classified by whether it
# actually reaches ksmbd KERNEL code (produces kcov-dataflow coverage):
#
#   WORKS = reached >= MIN_PCS kernel PCs      → a real, meaningful grain (pcs = its depth)
#   DEAD  = ran (ret>=0) but 0 kernel PCs       → its PDU never reached a handler (cut/fix)
#   BAIL  = returned <0 every run               → bailed at a prereq (pool/fid/auth/config)
#
# It writes the meaningful set to ksmbd/grain/WORKING_SUBSET.txt (coverage-desc, usable as a
# fuzz `-t` list) and the full run to a timestamped log. This is a seconds-scale filter over
# the WHOLE fleet — the cheap answer to "which of our grains are meaningful", run BEFORE any
# fuzzing campaign spends budget on dead weight.
#
# NOTE: this is NOT the engine comparison — for the dataflow-vs-pc coverage ablation use
# engine_compare_campagin.sh. This script only verifies grain validity.
#
# Usage:  verify_useful_grain.sh [REPEATS] [MIN_PCS]
#   REPEATS  runs per grain, MAX kernel-PC count taken (default 3)
#   MIN_PCS  min kernel PCs to count a grain as WORKS (default 1 = reached ksmbd at all)
# Env overrides:
#   REBUILD_KERNEL=1   force a full kernel rebuild (kcov-dataflow + ksmbd remote hooks).
#                      Default: reuse the current bzImage (the .so is ALWAYS rebuilt, since
#                      grain changes live there). Rebuild the kernel only after changing
#                      kernel/kcov code or the ksmbd remote hooks.
#   GRAIN_SUBSET       space-separated grain names to check (default: the whole fleet).
set -o pipefail

usage() { sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }
case "${1:-}" in -h|--help|help) usage;; esac

REPEATS="${1:-3}"
MIN_PCS="${2:-1}"
case "$REPEATS" in ''|*[!0-9]*) echo "!!! REPEATS must be a positive integer"; exit 2;; esac
case "$MIN_PCS" in ''|*[!0-9]*) echo "!!! MIN_PCS must be a positive integer"; exit 2;; esac

LOGDIR="$HOME/ksmbdzzer-logs/selftest-$(date +%Y-%m-%d_%H-%M-%S)"
mkdir -p "$LOGDIR" || { echo "!!! cannot create log dir $LOGDIR"; exit 2; }
LOG="$LOGDIR/selftest.log"

source ~/venv-virtme/bin/activate
cd ~/kcov-dataflow/linux || exit 2
export PATH="$HOME/kcov-dataflow/llvm-project/build/bin:$PATH"
export RUSTC="$HOME/kcov-dataflow/rust/build/x86_64-unknown-linux-gnu/stage1/bin/rustc"
export RUST_LIB_SRC="$HOME/kcov-dataflow/rust/library"

# ─── Ctrl+C / kill teardown (one VM; kill its whole tree + any straggler qemu) ───
CUR_PID=""
_kill_tree() { local p=$1 sig=$2 c; for c in $(pgrep -P "$p" 2>/dev/null); do _kill_tree "$c" "$sig"; done; kill -"$sig" "$p" 2>/dev/null; }
cleanup() {
  trap - INT TERM
  echo >&2; echo "!!! interrupted ($(date +%T)) — tearing down the VM tree" >&2
  [ -n "$CUR_PID" ] && { _kill_tree "$CUR_PID" TERM; sleep 1; _kill_tree "$CUR_PID" KILL; }
  pkill -KILL -f 'qemu-system-x86_64 -name virtme-ng' 2>/dev/null
  exit 130
}
trap cleanup INT TERM

# ─── Kernel build (only when forced) — the coverage bridge MUST be present ────────
# The selftest measures kcov-dataflow coverage, so the kernel needs CONFIG_KCOV_DATAFLOW_*
# AND the ksmbd remote hooks (kcov_df_remote_start in __handle_ksmbd_work). Those are the
# whole point; if the kernel is blind (hooks missing) EVERY grain reads 0 PCs and the
# selftest says so. Default is to reuse the current bzImage (grain changes are in the .so,
# rebuilt below); pass REBUILD_KERNEL=1 after touching kernel/kcov or the ksmbd hooks.
if [ "${REBUILD_KERNEL:-0}" = 1 ]; then
  echo "===== build kernel (kcov-dataflow + ksmbd; custom clang/rustc) $(date +%T) ====="
  # FULL SMB feature surface — MUST match engine_compare_campagin.sh, or grains that need a
  # feature (RDMA/SMBDirect transport, Kerberos) silently dead-end and skew the validity
  # result. The ksmbd userspace features (smb3 encryption / signing / durable) live in
  # ksmbd-sandbox.config, not here — this is the KERNEL surface only.
  KCONFIG=(
    CONFIG_KCOV=y CONFIG_KCOV_INSTRUMENT_ALL=y CONFIG_KCOV_ENABLE_COMPARISONS=y
    CONFIG_KCOV_DATAFLOW_ARGS=y CONFIG_KCOV_DATAFLOW_RET=y CONFIG_KCOV_DATAFLOW_INSTRUMENT_ALL=y
    # ksmbd + RDMA/SMBDirect transport + Kerberos (the whole client-reachable surface)
    CONFIG_NETWORK_FILESYSTEMS=y CONFIG_SMB_SERVER=y CONFIG_SMB_SERVER_SMBDIRECT=y CONFIG_SMBDIRECT=y CONFIG_UNICODE=y
    CONFIG_SMB_SERVER_KERBEROS5=y
    CONFIG_INFINIBAND=y CONFIG_INFINIBAND_USER_ACCESS=y CONFIG_RDMA_RXE=y CONFIG_RDMA_SIW=y CONFIG_DUMMY=y
    # memory-safety / lock detectors so a grain that trips a real ksmbd bug is caught here too
    CONFIG_KASAN=y CONFIG_KASAN_GENERIC=y CONFIG_KASAN_INLINE=y CONFIG_SLUB_DEBUG=y CONFIG_SLUB_DEBUG_ON=y
    CONFIG_LOCKDEP=y CONFIG_PROVE_LOCKING=y CONFIG_DEBUG_LIST=y
    CONFIG_DETECT_HUNG_TASK=y CONFIG_BOOTPARAM_HUNG_TASK_PANIC=y
    CONFIG_DEBUG_FS=y CONFIG_DEBUG_INFO=y CONFIG_DEBUG_INFO_DWARF5=y
  )
  CFG_ARGS=(); for c in "${KCONFIG[@]}"; do CFG_ARGS+=(--configitem "$c"); done
  vng --build "${CFG_ARGS[@]}" LLVM=1 CC=clang RUSTC="$RUSTC" RUST_LIB_SRC="$RUST_LIB_SRC" \
    || { echo "!!! KBUILD FAIL"; exit 11; }
  # vng --configitem can silently drop the INSTRUMENT_ALL toggle AND the RDMA transport; force
  # the ones that matter back in + rebuild if any dropped.
  _need_fixup=0
  grep -q '^CONFIG_KCOV_DATAFLOW_INSTRUMENT_ALL=y' .config || _need_fixup=1
  grep -q '^CONFIG_RDMA_RXE=y' .config || _need_fixup=1
  if [ "$_need_fixup" = 1 ]; then
    ./scripts/config --enable KCOV_DATAFLOW_INSTRUMENT_ALL \
                     --enable INFINIBAND --enable INFINIBAND_USER_ACCESS \
                     --enable RDMA_RXE --enable RDMA_SIW --enable DUMMY \
                     --enable SMB_SERVER_KERBEROS5
    make LLVM=1 CC=clang RUSTC="$RUSTC" RUST_LIB_SRC="$RUST_LIB_SRC" olddefconfig >/dev/null || exit 11
    make LLVM=1 CC=clang RUSTC="$RUSTC" RUST_LIB_SRC="$RUST_LIB_SRC" -j"$(nproc)" bzImage || exit 11
  fi
  # sanity: the load-bearing SMB + coverage symbols (a dropped one silently skews validity)
  for need in CONFIG_KCOV CONFIG_KCOV_DATAFLOW_ARGS CONFIG_KCOV_DATAFLOW_RET \
              CONFIG_SMB_SERVER CONFIG_SMB_SERVER_SMBDIRECT CONFIG_RDMA_RXE; do
    grep -q "^${need}=y" .config || { echo "!!! ${need}=y missing after build (check deps)"; exit 13; }
  done
else
  echo "===== reusing current kernel bzImage (REBUILD_KERNEL=1 to force) $(date +%T) ====="
fi

# ─── Library build (ALWAYS — grain changes live in libksmbdzzer.c) ───────────────
echo "===== build lib (pfz_ API + grain registry) $(date +%T) ====="
( cd ~/kcov-dataflow/ksmbd && \
  cc -shared -fPIC -O2 -I/usr/include/samba-4.0 -I. libksmbdzzer.c -o libksmbdzzer.so \
     -lsmbclient -lpthread -lrdmacm -libverbs -lcrypto ) \
  || { echo "!!! LIB FAIL"; exit 12; }

# ─── Boot ONE guest → init ksmbd → selftest the whole fleet ──────────────────────
_sub=""; [ -n "${GRAIN_SUBSET:-}" ] && _sub="-t ${GRAIN_SUBSET}"
echo "===== boot guest + selftest (REPEATS=${REPEATS}, MIN_PCS=${MIN_PCS}) $(date +%T) ====="
echo "===== log -> ${LOG} ====="
timeout 900 vng --user root --memory 8G --rw --cpus 4 --append "nokaslr hung_task_panic=1 hung_task_timeout_secs=60" \
  --exec "mount -t debugfs none /sys/kernel/debug 2>/dev/null; sysctl -w kernel.kptr_restrict=0; python3 ../ksmbd/ksmbdzzer.py init && python3 ../ksmbd/ksmbdzzer.py selftest --repeats ${REPEATS} --min-pcs ${MIN_PCS} ${_sub}; timeout 5 sync 2>/dev/null; poweroff -f 2>/dev/null" \
  < /dev/null > >(tee -a "$LOG") 2>&1 &
CUR_PID=$!
wait "$CUR_PID"; rc=$?
CUR_PID=""
sleep 0.5   # let the tee process-sub flush the tail

# ─── Result ──────────────────────────────────────────────────────────────────────
echo
echo "===================== GRAIN VALIDITY ($(date +%T)) ====================="
grep -aE '\[selftest\] (DONE|authed pool)|BAIL \(|DEAD \(|wrote .* working' "$LOG" | sed -E 's/\x1b\[[0-9;]*m//g'
# Coverage-bridge guard: 0 WORKS ⇒ the kernel is coverage-blind (ksmbd kcov remote hooks
# missing / config dropped), NOT a fleet of dead grains — the exact failure mode this
# tooling exists to catch.
if grep -qaE '\[selftest\] DONE .* 0 WORKS' "$LOG"; then
  echo "!!! 0 WORKS — the kernel is COVERAGE-BLIND (ksmbd kcov remote hooks missing or"
  echo "!!!   CONFIG_KCOV_DATAFLOW dropped), not a fleet of dead grains. Rebuild the kernel"
  echo "!!!   (REBUILD_KERNEL=1) and confirm fs/smb/server/server.c has kcov_df_remote_start."
fi
echo "===== full log:      ${LOG} ====="
echo "===== working subset: ~/kcov-dataflow/ksmbd/grain/WORKING_SUBSET.txt ====="
echo "===== DONE $(date +%T) ====="
