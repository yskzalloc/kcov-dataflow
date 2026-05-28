#!/bin/bash
set -e

CLANG=/home/debian-sid/llvm-project/build/bin/clang
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

echo "=== Stage 1: LLVM Instrumentation Verification ==="

# Step 1: Generate IR with trace-args and trace-ret
echo "[1/4] Generating IR..."
$CLANG -S -emit-llvm -g -O0 -fno-inline \
  -fsanitize-coverage=dataflow-args,dataflow-ret \
  test_target.c -o test_target.ll

# Step 2: Verify callbacks are present in IR
echo "[2/4] Checking IR for callbacks..."
ARGS_COUNT=$(grep -c "__sanitizer_cov_trace_args" test_target.ll || true)
RET_COUNT=$(grep -c "__sanitizer_cov_trace_ret" test_target.ll || true)

echo "  Found $ARGS_COUNT trace_args calls"
echo "  Found $RET_COUNT trace_ret calls"

if [ "$ARGS_COUNT" -eq 0 ]; then
    echo "FAIL: No __sanitizer_cov_trace_args calls found in IR!"
    cat test_target.ll
    exit 1
fi

if [ "$RET_COUNT" -eq 0 ]; then
    echo "FAIL: No __sanitizer_cov_trace_ret calls found in IR!"
    cat test_target.ll
    exit 1
fi

# Step 3: Compile and link with mock
echo "[3/4] Compiling mock binary..."
$CLANG -g -O0 -fno-inline \
  -fsanitize-coverage=dataflow-args,dataflow-ret \
  test_target.c mock_kcov.c -o test_mock_binary

# Step 4: Run and verify output
echo "[4/4] Running mock binary..."
OUTPUT=$(./test_mock_binary || true)
echo "$OUTPUT"

# Verify we see TRACE_ARGS and TRACE_RET
if echo "$OUTPUT" | grep -q "\[TRACE_ARGS\]"; then
    echo "PASS: TRACE_ARGS callback fired"
else
    echo "FAIL: TRACE_ARGS callback not fired"
    exit 1
fi

if echo "$OUTPUT" | grep -q "\[TRACE_RET\]"; then
    echo "PASS: TRACE_RET callback fired"
else
    echo "FAIL: TRACE_RET callback not fired"
    exit 1
fi

# Check that struct fields are dumped (num_fields > 0 for pointer-to-struct args)
if echo "$OUTPUT" | grep -q "field\["; then
    echo "PASS: Struct field data captured"
else
    echo "WARN: No struct field data captured (may be expected if no pointer-to-struct args)"
fi

echo ""
echo "=== Stage 1 PASSED ==="
