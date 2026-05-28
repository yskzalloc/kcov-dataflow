#!/usr/bin/env python3
"""
deep-trace-viz.py - Visualizes 10-deep call chain from kcov_dataflow.
Shows how attacker-controlled value propagates to the vulnerable function.

Usage: python3 deep-trace-viz.py (inside vng guest after triggering)
"""
import os, fcntl, ctypes, subprocess

BUF_SIZE = 65536
KCOV_DF_INIT = 0x80086401
KCOV_DF_ENABLE = 0x6464
KCOV_DF_DISABLE = 0x6465

def get_symbols():
    """Read module symbols from /proc/kallsyms"""
    syms = {}
    r = subprocess.run(["grep", "deep_chain_mod", "/proc/kallsyms"],
                       capture_output=True, text=True)
    for line in r.stdout.strip().split("\n"):
        parts = line.split()
        if len(parts) >= 3 and parts[1] == 't' and not parts[2].startswith('.') and not parts[2].startswith('__'):
            addr = int(parts[0], 16)
            name = parts[2]
            syms[addr] = name
    return syms

def symbolize(pc, syms):
    best = ("???", 0)
    for addr, name in syms.items():
        if addr <= pc and addr > best[1]:
            best = (name, addr)
    return best[0]

def main():
    os.system("insmod /home/debian-sid/kcov-dataflow-test/deep_module/deep_chain_mod.ko 2>/dev/null")
    syms = get_symbols()

    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.mmap.restype = ctypes.c_void_p
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                          ctypes.c_int, ctypes.c_int, ctypes.c_long]

    fd = os.open("/sys/kernel/debug/kcov_dataflow", os.O_RDWR)
    fcntl.ioctl(fd, KCOV_DF_INIT, BUF_SIZE)
    ptr = libc.mmap(None, BUF_SIZE * 8, 3, 1, fd, 0)
    arr = (ctypes.c_uint64 * BUF_SIZE).from_address(ptr)
    fcntl.ioctl(fd, KCOV_DF_ENABLE, 0)
    arr[0] = 0

    # Trigger
    tfd = os.open("/proc/deep_trigger", os.O_WRONLY)
    os.write(tfd, b"x")
    os.close(tfd)

    n = int(arr[0])
    fcntl.ioctl(fd, KCOV_DF_DISABLE, 0)

    # Parse records
    events = []
    i = 1
    while i <= n and i < BUF_SIZE:
        hdr = int(arr[i])
        typ = hdr & 0xF0000000
        if typ not in (0xE0000000, 0xF0000000):
            i += 1
            continue
        pc = int(arr[i+1])
        meta = int(arr[i+2])
        i += 3
        fields = []
        while i <= n and i < BUF_SIZE:
            v = int(arr[i])
            if (v & 0xF0000000) in (0xE0000000, 0xF0000000):
                break
            fields.append(v)
            i += 1
        name = symbolize(pc, syms)
        if name == "???":
            continue
        arg_idx = (meta >> 56) & 0xFF
        arg_sz = (meta >> 48) & 0xFF
        events.append({
            "type": "ENTRY" if typ == 0xE0000000 else "RET",
            "name": name, "pc": pc, "arg_idx": arg_idx,
            "arg_sz": arg_sz, "fields": fields
        })

    os.close(fd)

    # Visualize
    print()
    print("╔═══════════════════════════════════════════════════════════════════╗")
    print("║  Deep Call Chain Dataflow: Taint Propagation Visualization       ║")
    print("║  10 nested calls: attacker offset → OOB write                   ║")
    print("╚═══════════════════════════════════════════════════════════════════╝")
    print()
    print("  Attacker input: payload_offset=16, transform_key=3, filter_mask=0xFFFFFFFF")
    print("  Expected: 16*3=48 → (48&mask)>>1=24 → (48+24)&0xF=8 → slots[8] OOB!")
    print()
    print("  ┌─ Call Chain with Argument Values ─────────────────────────────────┐")

    depth = 0
    call_stack = []
    for ev in events:
        if ev["type"] == "ENTRY":
            indent = "  │" + "  " * depth
            if ev["fields"]:
                if len(ev["fields"]) > 3:
                    vals = ", ".join(f"0x{f:x}" for f in ev["fields"][:4]) + "..."
                else:
                    vals = ", ".join(f"0x{f:x}" for f in ev["fields"])
                print(f"{indent}→ {ev['name']}(arg[{ev['arg_idx']}] = struct{{{vals}}})")
            else:
                val = ev["fields"][0] if ev["fields"] else 0
                print(f"{indent}→ {ev['name']}(arg[{ev['arg_idx']}]({ev['arg_sz']}B) = 0x{val:x})")
            if ev["arg_idx"] == 0:
                call_stack.append(ev["name"])
                depth = min(depth + 1, 12)
        elif ev["type"] == "RET":
            depth = max(depth - 1, 0)
            indent = "  │" + "  " * depth
            if ev["fields"]:
                val = ev["fields"][0]
                print(f"{indent}← {ev['name']} returned 0x{val:x}")
            if ev["name"] in call_stack:
                call_stack.remove(ev["name"])

    print("  └──────────────────────────────────────────────────────────────────┘")
    print()
    print("  ┌─ Taint Flow Summary ─────────────────────────────────────────────┐")
    print("  │ deep_trigger_write: payload_offset = 16 (attacker-controlled)    │")
    print("  │   → entry_handler: passes offset to parse_request                │")
    print("  │     → parse_request: extracts payload at offset 16               │")
    print("  │       → validate_header: PASSES (no offset bounds check!)        │")
    print("  │       → extract_payload: returns ptr at buf+16                   │")
    print("  │     → transform_data(pl, offset=16): returns 16*3 = 48           │")
    print("  │     → apply_filter(pl, 48): returns (48 & 0xFFFF) >> 1 = 24     │")
    print("  │     → compute_index(48, 24): returns (48+24) & 0xF = 8          │")
    print("  │     → lookup_slot(table, 8): final_idx = 8 % 16 = 8             │")
    print("  │       → write_slot(table, idx=8, ...): passes to commit_write    │")
    print("  │         → commit_write(table, index=8, ...): table->slots[8] !!  │")
    print("  │           ╔══════════════════════════════════════════════╗        │")
    print("  │           ║ BUG: OOB WRITE at slots[8] (only 0-7 valid) ║        │")
    print("  │           ╚══════════════════════════════════════════════╝        │")
    print("  │                                                                  │")
    print("  │ ROOT CAUSE: validate_header() doesn't check payload_offset       │")
    print("  │ FIX: Add bounds check in validate_header or lookup_slot (% 8)    │")
    print("  └──────────────────────────────────────────────────────────────────┘")
    print()

if __name__ == "__main__":
    main()
