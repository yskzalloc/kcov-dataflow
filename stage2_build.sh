#!/bin/bash
set -e

CLANG=/home/debian-sid/llvm-project/build/bin/clang
KERNEL_DIR=/home/debian-sid/next
MODULE_DIR=/home/debian-sid/kcov-dataflow-test/module
TRIGGER_SRC=/home/debian-sid/kcov-dataflow-test/trigger.c
TRIGGER_BIN=/home/debian-sid/kcov-dataflow-test/trigger

echo "=== Stage 2: Kernel & Module Build ==="

# Step 1: Build kernel with vng
echo "[1/3] Building kernel with virtme-ng..."
cd "$KERNEL_DIR"

# Use vng to build with required configs
vng --build \
    --configitem CONFIG_KCOV=y \
    --configitem CONFIG_KASAN=y \
    --configitem CONFIG_KASAN_GENERIC=y \
    --configitem CONFIG_DEBUG_INFO=y \
    --configitem CONFIG_DEBUG_INFO_DWARF5=y \
    --configitem CONFIG_KCOV_TRACE_ARGS=y \
    --configitem CONFIG_KCOV_TRACE_RET=y \
    --configitem CONFIG_KCOV_INSTRUMENT_ALL=n \
    --configitem CONFIG_MODULES=y \
    --configitem CONFIG_MODULE_UNLOAD=y \
    --configitem CONFIG_PROC_FS=y \
    -- CC="$CLANG"

echo "[1/3] Kernel build complete."

# Step 2: Build the kernel module
echo "[2/3] Building kernel module..."
make -C "$KERNEL_DIR" M="$MODULE_DIR" CC="$CLANG" modules
echo "[2/3] Module build complete: $(ls $MODULE_DIR/*.ko)"

# Step 3: Compile the trigger binary (static for portability in guest)
echo "[3/3] Compiling trigger binary..."
gcc -static -o "$TRIGGER_BIN" "$TRIGGER_SRC"
echo "[3/3] Trigger binary: $TRIGGER_BIN"

echo ""
echo "=== Stage 2 PASSED ==="
echo "Kernel: $KERNEL_DIR/.vng/bzImage (or arch/x86/boot/bzImage)"
echo "Module: $MODULE_DIR/simple_vuln_mod.ko"
echo "Trigger: $TRIGGER_BIN"
