#!/bin/bash
# kcov-dataflow PoC Evaluation Script
#
# Usage (two steps):
#
# Step 1: Build kernel and modules (run from linux/ directory)
#   source /home/debian-sid/venv-virtme/bin/activate
#   export PATH="/home/debian-sid/kcov-dataflow/llvm-project/build/bin:$PATH"
#   export RUSTC=/home/debian-sid/kcov-dataflow/rust/build/x86_64-unknown-linux-gnu/stage1/bin/rustc
#   export RUST_LIB_SRC=/home/debian-sid/kcov-dataflow/rust/library
#
#   vng --build \
#     --configitem CONFIG_KCOV=y \
#     --configitem CONFIG_KCOV_DATAFLOW_ARGS=y \
#     --configitem CONFIG_KCOV_DATAFLOW_RET=y \
#     --configitem CONFIG_KCOV_DATAFLOW_INSTRUMENT_ALL=n \
#     --configitem CONFIG_KCOV_INSTRUMENT_ALL=y \
#     --configitem CONFIG_FRAME_WARN=4096 \
#     --configitem CONFIG_MODULES=y \
#     --configitem CONFIG_MODULE_UNLOAD=y \
#     --configitem CONFIG_PROC_FS=y \
#     --configitem CONFIG_DEBUG_FS=y \
#     --configitem CONFIG_RUST=y \
#     --configitem CONFIG_ANDROID_BINDER_IPC=y \
#     --configitem CONFIG_ANDROID_BINDERFS=y \
#     --configitem CONFIG_SAMPLES_RUST=y \
#     --configitem CONFIG_SAMPLE_RUST_MISC_DEVICE=y \
#     -- CC=clang LLVM=1 RUSTC=$RUSTC RUST_LIB_SRC=$RUST_LIB_SRC
#
#   # Build all PoC modules:
#   for dir in $(find /home/debian-sid/kcov-dataflow/findings -name Makefile -printf '%h\n'); do
#     make -j$(nproc) LLVM=1 CC=clang RUSTC=$RUSTC RUST_LIB_SRC=$RUST_LIB_SRC M=$dir modules
#   done
#
# Step 2: Run tests in VM
#   vng --user root --exec "bash /home/debian-sid/kcov-dataflow/findings/poc.sh"
#
set +e

FINDINGS=/home/debian-sid/kcov-dataflow/findings
PASS=0; FAIL=0

run_test() {
    local name="$1"; local desc="$2"
    echo ""
    echo "━━━ $name: $desc ━━━"
}

check() {
    if [ $? -eq 0 ]; then PASS=$((PASS+1)); echo "  ✓ $1"
    else FAIL=$((FAIL+1)); echo "  ✗ $1"; fi
}

dmesg -C

# ──────────────────────────────────────────────────────────────────────
# 1. FFI Contract Violation (High)
#    C function returns success (0) but leaves buffer=NULL.
#    kcov-dataflow detects: ENTRY/RET diff shows return=0 ∧ buffer=NULL.
# ──────────────────────────────────────────────────────────────────────
run_test "poc1_ffi" "Rust-to-C FFI contract violation (return=0 but buffer=NULL)"
insmod $FINDINGS/poc1_ffi/poc1_ffi_helper.ko 2>/dev/null
insmod $FINDINGS/poc1_ffi/poc1_ffi_rust.ko 2>/dev/null
echo 1 > /sys/kernel/debug/poc1_ffi 2>/dev/null
dmesg | grep -q "CONTRACT VIOLATION"; check "Contract violation detected"
dmesg -c > /dev/null

# ──────────────────────────────────────────────────────────────────────
# 2. Silent In-Bounds Corruption (High)
#    Writes REQ_F_RSRC_NODE to req->flags instead of req->rsrc_flags.
#    kcov-dataflow detects: ENTRY/RET struct snapshot shows wrong field mutated.
# ──────────────────────────────────────────────────────────────────────
run_test "poc2_iouring" "Silent in-bounds corruption (wrong struct field written)"
insmod $FINDINGS/poc2_iouring/poc2_iouring.ko 2>/dev/null
[ -e /proc/poc2_iouring ] && echo 1 > /proc/poc2_iouring 2>/dev/null
sleep 0.1
dmesg | grep -q "flags=0x240"; check "Flag corruption: flags=0x240 (expected 0x40)"
dmesg -c > /dev/null

# ──────────────────────────────────────────────────────────────────────
# 3. 10-Deep Taint Propagation (High)
#    Guest CR3 0xdeadb000 → >>12 → gfn=0xdeadb → OOB array index.
#    kcov-dataflow detects: cross-function value tracking shows full derivation.
# ──────────────────────────────────────────────────────────────────────
run_test "poc3_kvm" "10-deep taint propagation from user CR3 to OOB write"
insmod $FINDINGS/poc3_kvm/poc3_kvm.ko 2>/dev/null
[ -e /proc/poc3_kvm ] && echo 1 > /proc/poc3_kvm 2>/dev/null
sleep 0.1
dmesg | grep -q "OOB=YES"; check "OOB write from tainted gfn"
dmesg -c > /dev/null

# ──────────────────────────────────────────────────────────────────────
# 4. Binder SET_MAX_THREADS Unbounded (High)
#    Accepts any u32 without upper-bound validation.
#    kcov-dataflow detects: ENTRY arg=0xdeadbeef, RET=success (no rejection).
# ──────────────────────────────────────────────────────────────────────
run_test "poc_binder" "Binder SET_MAX_THREADS accepts 0xdeadbeef without validation"
mkdir -p /dev/binderfs && mount -t binder binder /dev/binderfs 2>/dev/null
insmod $FINDINGS/poc_binder/binder_audit.ko 2>/dev/null
echo 1 > /proc/binder_audit 2>/dev/null
dmesg | grep -q "set_max_threads(0xdeadbeef) done"; check "Unbounded max_threads accepted"
dmesg | grep -q "enter_looper(dup) done"; check "Duplicate BC_ENTER_LOOPER accepted"
dmesg -c > /dev/null

# ──────────────────────────────────────────────────────────────────────
# 5. Rust Binder IPC Audit (Medium)
#    Tests SET_MAX_THREADS, BC_ENTER_LOOPER, BC_FREE_BUFFER edge cases.
#    kcov-dataflow detects: argument values at Rust FFI boundary.
# ──────────────────────────────────────────────────────────────────────
run_test "poc_rust_binder" "Rust binder ioctl edge cases"
insmod $FINDINGS/poc_rust_binder/binder_ioctl_trigger.ko 2>/dev/null
if [ -e /proc/binder_ioctl ]; then
    echo 1 > /proc/binder_ioctl 2>/dev/null  # SET_MAX_THREADS(0xffffffff)
    echo 2 > /proc/binder_ioctl 2>/dev/null  # BC_ENTER_LOOPER
fi
dmesg | grep -q "binder_ioctl_trigger: ready"; check "Rust binder trigger loaded"
dmesg -c > /dev/null

# ──────────────────────────────────────────────────────────────────────
# 6. Error::from_errno(-4096) (Medium)
#    Out-of-range errno silently returns EINVAL instead of propagating.
#    kcov-dataflow detects: ENTRY arg=-4096, RET=EINVAL (semantic mismatch).
# ──────────────────────────────────────────────────────────────────────
run_test "poc_rust_core" "Rust core API: errno masking, KVec, KBox, Page"
insmod $FINDINGS/poc_rust_core/poc_rust_core.ko 2>/dev/null
echo 1 > /sys/kernel/debug/poc_rust_core 2>/dev/null
dmesg | grep -q "out of range.*errno.*-4096"; check "errno -4096 out-of-range warning"
dmesg | grep -q "test_error_codes(-4096): name=Some"; check "Silently returns EINVAL"
dmesg | grep -q "test_kvec_alloc(2147483647): FAILED"; check "KVec huge alloc rejected"
dmesg | grep -q "test_kbox_alloc.*OK"; check "KBox alloc works"
dmesg -c > /dev/null

# ──────────────────────────────────────────────────────────────────────
# 7. KVec Boundary Tests (Medium)
#    reserve(usize::MAX), push_within_capacity, remove OOB.
#    kcov-dataflow detects: exact boundary values accepted/rejected.
# ──────────────────────────────────────────────────────────────────────
run_test "poc_rust_vec" "KVec overflow and boundary conditions"
insmod $FINDINGS/poc_rust_vec/poc_rust_vec.ko 2>/dev/null
echo 1 > /sys/kernel/debug/poc_rust_vec 2>/dev/null
dmesg | grep -q "reserve(MAX): Err(AllocError)"; check "reserve(MAX) correctly rejected"
dmesg | grep -q "rejected val=0xcccc"; check "push_within_capacity rejects on full"
dmesg | grep -q "remove(0) empty: true"; check "remove(0) on empty returns Err"
dmesg | grep -q "remove(MAX) with len=1: true"; check "remove(MAX) OOB returns Err"
dmesg -c > /dev/null

# ──────────────────────────────────────────────────────────────────────
# 8. RBTree + Data Structures (Medium)
#    Duplicate key silently replaces (no error returned).
#    kcov-dataflow detects: two inserts with same key both succeed.
# ──────────────────────────────────────────────────────────────────────
run_test "poc_rust_ds" "RBTree duplicate key, CString, kstrtobool"
insmod $FINDINGS/poc_rust_ds/poc_rust_ds.ko 2>/dev/null
echo 1 > /sys/kernel/debug/poc_rust_ds 2>/dev/null
dmesg | grep -q "test_rbtree_dup.*val=200"; check "Duplicate key silently replaced (val=200)"
dmesg | grep -q "kstrtobool.*empty=Err"; check "kstrtobool('') returns Err"
dmesg | grep -q "test_rbtree_empty.*empty=true"; check "Empty tree operations safe"
dmesg -c > /dev/null

# ──────────────────────────────────────────────────────────────────────
# 9. Arc/Refcount Safety (Low)
#    into_unique_or_drop with multiple refs must drop, not return.
#    kcov-dataflow detects: refcount field value captured at -O2.
# ──────────────────────────────────────────────────────────────────────
run_test "poc_rust_sync" "Arc refcount, into_unique_or_drop, KBox raw"
insmod $FINDINGS/poc_rust_sync/poc_rust_sync.ko 2>/dev/null
echo 1 > /sys/kernel/debug/poc_rust_sync 2>/dev/null
dmesg | grep -q "test_arc_unique: converted to UniqueArc OK"; check "Single ref → UniqueArc"
dmesg | grep -q "test_arc_unique_multi: correctly dropped"; check "Multi ref → dropped (no UAF)"
dmesg | grep -q "test_arc_zero.*ptr!=NULL: true"; check "Arc(0) is not NULL pointer"
dmesg -c > /dev/null

# ──────────────────────────────────────────────────────────────────────
# 10. Memory/Uaccess Boundaries (Medium)
#     Cross-page read rejected, zero-length succeeds without validation.
#     kcov-dataflow detects: offset+len values vs return status.
# ──────────────────────────────────────────────────────────────────────
run_test "poc_rust_mm" "Page boundary, UserSlice NULL/zero-length, fget"
insmod $FINDINGS/poc_rust_mm/poc_rust_mm.ko 2>/dev/null
echo 1 > /sys/kernel/debug/poc_rust_mm 2>/dev/null
dmesg | grep -q "test_page_read_offset(4090, 8): ERR"; check "Cross-page (4090+8>4096) rejected"
dmesg | grep -q "test_userslice_zero.*Ok"; check "Zero-length read succeeds (no ptr validation!)"
dmesg | grep -q "test_userslice_invalid(0x0, 8): Err"; check "NULL ptr with len>0 rejected"
dmesg | grep -q "test_fget(4294967295): BadFd"; check "fget(0xFFFFFFFF) rejected"
dmesg -c > /dev/null

# ──────────────────────────────────────────────────────────────────────
# 11. Credential/Task Boundaries (Medium)
#     fget wrapping values, signal_pending race, secid access.
#     kcov-dataflow detects: u32 boundary values at Rust/C interface.
# ──────────────────────────────────────────────────────────────────────
run_test "poc_rust_cred" "fget wrapping, signal race, credential access"
insmod $FINDINGS/poc_rust_cred/poc_rust_cred.ko 2>/dev/null
echo 1 > /sys/kernel/debug/poc_rust_cred 2>/dev/null
dmesg | grep -q "test_fget_wrap.*0xFFFFFFFF=false"; check "fget(0xFFFFFFFF) correctly rejected"
dmesg | grep -q "test_fget_refcount.*successful fgets"; check "Multiple fget refcounting works"
dmesg | grep -q "test_task_consistency.*same=true"; check "Task pid consistent across calls"
dmesg -c > /dev/null

# ──────────────────────────────────────────────────────────────────────
# 12. Rust Struct Field Capture at -O2 (Novel)
#     First-ever runtime capture of Rust kernel struct fields under optimization.
#     kcov-dataflow detects: individual fields via DICompositeType metadata.
# ──────────────────────────────────────────────────────────────────────
run_test "rust_module" "Rust struct field capture at -O2 (novel observability)"
insmod $FINDINGS/rust_module/rust_verify_mod.ko 2>/dev/null
echo 1 > /sys/kernel/debug/rust_trigger 2>/dev/null
dmesg | grep -q "rust_process_data.*id=0x260fa.*value=0xefbed00023456789"; check "Struct fields captured at -O2"
dmesg -c > /dev/null

# ──────────────────────────────────────────────────────────────────────
# 13. Rust Misc Device (Low)
#     Integer boundary values via ioctl, invalid ioctl error path.
#     kcov-dataflow detects: ioctl argument values and return codes.
# ──────────────────────────────────────────────────────────────────────
run_test "poc_rust_misc" "Rust misc device: INT_MAX/MIN boundaries, invalid ioctl"
if [ -e /dev/rust-misc-device ]; then
    $FINDINGS/poc_rust_misc/poc_rust_misc 2>&1 | grep -q "value=0x80000000"; check "INT32_MIN stored correctly"
    $FINDINGS/poc_rust_misc/poc_rust_misc 2>&1 | grep -q "errno=25"; check "Invalid ioctl returns ENOTTY"
else
    echo "  ⊘ /dev/rust-misc-device not found (CONFIG_SAMPLE_RUST_MISC_DEVICE=m?)"
fi

# ──────────────────────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Results: $PASS passed, $FAIL failed"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
[ $FAIL -eq 0 ] && echo "  ALL TESTS PASSED" || echo "  SOME TESTS FAILED"
