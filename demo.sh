#!/bin/bash
set -e
source /home/debian-sid/venv-virtme/bin/activate
cd /home/debian-sid/next

GUEST_SCRIPT=/tmp/demo_guest.sh
cat > "$GUEST_SCRIPT" << 'EOF'
#!/bin/bash
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  KCOV Data Flow Tracker: Many Arguments Demo (x86_64)      ║"
echo "║  x86_64 ABI: rdi, rsi, rdx, rcx, r8, r9 + stack           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  many_args(struct simple_data *sd,  ← rdi (ptr to struct)"
echo "            int a,                   ← rsi = 0x11"
echo "            long b,                  ← rdx = 0x2222"
echo "            unsigned int c,          ← rcx = 0x33"
echo "            char d,                  ← r8  = 'X' (0x58)"
echo "            long e,                  ← r9  = 0x5555"
echo "            int stack1,              ← [rsp+0] = 0x66"
echo "            long stack2)             ← [rsp+8] = 0x77"
echo ""

insmod /home/debian-sid/kcov-dataflow-test/module/simple_vuln_mod.ko
sleep 0.3

echo x > /proc/many_trigger 2>/dev/null
sleep 0.3

echo "┌─ many_args() ENTRY: all 8 arguments traced ────────────────┐"
dmesg | grep -A20 "KCOV_ENTRY.*many_args" | grep -E "ENTRY|field"
echo "└────────────────────────────────────────────────────────────┘"
echo ""
echo "┌─ many_args() RETURN value ─────────────────────────────────┐"
dmesg | grep -A5 "KCOV_RET.*many_args" | grep -E "RET|field"
echo "└────────────────────────────────────────────────────────────┘"
echo ""
echo "┌─ Interpretation ───────────────────────────────────────────┐"
echo "│ arg[0] sd   → ptr to struct (3 fields: id, buf, size)     │"
echo "│ arg[1] a    = 0x11          (int, via rsi)                 │"
echo "│ arg[2] b    = 0x2222        (long, via rdx)                │"
echo "│ arg[3] c    = 0x33          (uint, via rcx)                │"
echo "│ arg[4] d    = 0x58 ('X')    (char, via r8)                 │"
echo "│ arg[5] e    = 0x5555        (long, via r9)                 │"
echo "│ arg[6] stack1 = 0x66        (int, on stack)                │"
echo "│ arg[7] stack2 = 0x77        (long, on stack)               │"
echo "│                                                            │"
echo "│ Return: sd->id + sd->size (computed from all args)         │"
echo "└────────────────────────────────────────────────────────────┘"
echo ""
EOF
chmod +x "$GUEST_SCRIPT"

echo "Booting kernel with virtme-ng..."
echo ""
vng --user root --exec "bash $GUEST_SCRIPT" 2>&1 | sed 's/^\[.*\] //' | grep -v "^mount:\|^touch:" | grep -v "virtme-init"
