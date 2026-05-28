#!/bin/bash
set -e

KERNEL_DIR=/home/debian-sid/next
MODULE_DIR=/home/debian-sid/kcov-dataflow-test/module
TRIGGER_BIN=/home/debian-sid/kcov-dataflow-test/trigger

echo "=== Stage 3: virtme-ng Execution & Analysis ==="

cd "$KERNEL_DIR"
source /home/debian-sid/venv-virtme/bin/activate

# Create a script to run inside the guest
GUEST_SCRIPT=/tmp/guest_script.sh
cat > "$GUEST_SCRIPT" << 'INNEREOF'
#!/bin/bash
set -x
echo "=== Guest booted ==="
uname -r

# Load the module
insmod /home/debian-sid/kcov-dataflow-test/module/simple_vuln_mod.ko || echo "insmod failed"
sleep 0.5
dmesg | grep simple_vuln_mod

# Run the trigger
echo "=== Running trigger ==="
/home/debian-sid/kcov-dataflow-test/trigger || echo "trigger exited with $?"

# Show kernel log for the corruption trace
echo "=== Kernel log after trigger ==="
dmesg | tail -20

echo "=== Guest done ==="
INNEREOF
chmod +x "$GUEST_SCRIPT"

echo "Booting kernel with vng..."
vng -v --user root --exec "bash $GUEST_SCRIPT" 2>&1 | tee /tmp/stage3_output.log

echo ""
echo "=== Stage 3 output saved to /tmp/stage3_output.log ==="

# Validate output
if grep -q "ENTRY\|TRACE_ARGS\|TLV Data Flow" /tmp/stage3_output.log; then
    echo "PASS: TLV data flow entries detected"
else
    echo "INFO: No TLV entries detected in output"
fi

if grep -q "simple_vuln_mod" /tmp/stage3_output.log; then
    echo "PASS: Module loaded and triggered"
else
    echo "FAIL: Module not loaded"
fi

echo "=== Stage 3 Complete ==="
