#!/usr/bin/env python3
"""
kcov-view.py - Merged KCOV + KCOV_DATAFLOW viewer

Reads both /sys/kernel/debug/kcov (PC trace) and /sys/kernel/debug/kcov_dataflow
(args/ret), correlates by PC, and produces a human-readable call trace with
argument values and struct field expansion.

Usage (inside guest or with appropriate permissions):
    python3 kcov-view.py <trigger_command>

Example:
    python3 kcov-view.py "echo x > /proc/uaf_trigger"

Output:
    func+0x0 [module]
      → a(arg[0]=0x1, arg[1]=0x2, arg[2]=0x3, arg[3]=struct{.f[0]=1, .f[1]=2, .f[2]=3})
        ← ret = struct{.f[0]=1, .f[1]=2, .f[2]=3}
      → a(arg[0]=0x0, arg[1]=0x0, arg[2]=0x1, arg[3]=NULL)
        ← ret = 0x0
"""
import os, sys, struct, mmap, fcntl, subprocess, re, ctypes
from collections import defaultdict

# Ioctl definitions (x86_64)
KCOV_INIT_TRACE = 0x80086301   # _IOR('c', 1, unsigned long)
KCOV_ENABLE = 0x6364           # _IO('c', 100)
KCOV_DISABLE = 0x6365          # _IO('c', 101)
KCOV_TRACE_PC = 0

KCOV_DF_INIT_TRACE = 0x80086401  # _IOR('d', 1, unsigned long)
KCOV_DF_ENABLE = 0x6464          # _IO('d', 100)
KCOV_DF_DISABLE = 0x6465         # _IO('d', 101)

BUF_SIZE = 65536  # 65536 * 8 = 512KB = 128 pages (page-aligned)

# Load kallsyms for symbolization
def load_kallsyms():
    syms = {}
    try:
        with open("/proc/kallsyms") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    addr = int(parts[0], 16)
                    name = parts[2]
                    mod = parts[3].strip("[]") if len(parts) > 3 else ""
                    syms[addr] = (name, mod)
    except:
        pass
    return syms

def symbolize(pc, syms):
    """Find nearest symbol <= pc"""
    best_addr = 0
    best_name = f"0x{pc:x}"
    best_mod = ""
    for addr, (name, mod) in syms.items():
        if addr <= pc and addr > best_addr:
            best_addr = addr
            best_name = name
            best_mod = mod
    offset = pc - best_addr
    if best_mod:
        return f"{best_name}+0x{offset:x} [{best_mod}]"
    return f"{best_name}+0x{offset:x}"

def parse_dataflow(buf, n):
    """Parse TLV records from kcov_dataflow buffer into a list of events."""
    events = []
    i = 1
    while i <= n and i < BUF_SIZE:
        hdr = buf[i]
        typ = hdr & 0xF0000000
        seq = hdr & 0x00FFFFFF

        if typ not in (0xE0000000, 0xF0000000):
            i += 1
            continue

        pc = buf[i + 1]
        meta = buf[i + 2]
        i += 3

        # Collect field values
        fields = []
        while i <= n and i < BUF_SIZE:
            v = buf[i]
            vtype = v & 0xF0000000
            if vtype == 0xE0000000 or vtype == 0xF0000000:
                break
            fields.append(v)
            i += 1

        if typ == 0xE0000000:
            arg_idx = (meta >> 56) & 0xFF
            arg_sz = (meta >> 48) & 0xFF
            ptr = meta & 0xFFFFFFFFFFFF
            events.append({
                "type": "entry", "seq": seq, "pc": pc,
                "arg_idx": arg_idx, "arg_size": arg_sz,
                "ptr": ptr, "fields": fields
            })
        else:
            ret_sz = (meta >> 48) & 0xFF
            ptr = meta & 0xFFFFFFFFFFFF
            events.append({
                "type": "ret", "seq": seq, "pc": pc,
                "ret_size": ret_sz, "ptr": ptr, "fields": fields
            })
    return events

def format_value(val):
    if val == 0xBADADD85:
        return "FAULT"
    if val == 0:
        return "0"
    return f"0x{val:x}"

def format_entry(ev):
    """Format an entry event as a function argument."""
    if len(ev["fields"]) > 1:
        # Struct: multiple fields
        flds = ", ".join(f".f[{i}]={format_value(v)}" for i, v in enumerate(ev["fields"]))
        return f"struct{{{flds}}}"
    elif len(ev["fields"]) == 1:
        v = ev["fields"][0]
        if v == 0 and ev["ptr"] == 0:
            return "NULL"
        return format_value(v)
    return format_value(ev["ptr"])

def merge_and_display(pc_trace, df_events, syms):
    """Display dataflow events with symbolization."""
    print("\n╔═══════════════════════════════════════════════════════════╗")
    print("║  Merged KCOV Coverage + Dataflow View                    ║")
    print("╚═══════════════════════════════════════════════════════════╝\n")

    if not df_events:
        print("  (no dataflow events captured)")
        return

    # Group events into calls: consecutive entries for same PC followed by a ret
    calls = []
    current_args = []
    current_pc = None

    for ev in df_events:
        if ev["type"] == "entry":
            if current_pc is not None and ev["pc"] != current_pc:
                calls.append({"pc": current_pc, "args": current_args, "ret": None})
                current_args = []
            current_pc = ev["pc"]
            current_args.append(ev)
        elif ev["type"] == "ret":
            if current_pc == ev["pc"]:
                calls.append({"pc": current_pc, "args": current_args, "ret": ev})
                current_args = []
                current_pc = None
            else:
                if current_args:
                    calls.append({"pc": current_pc, "args": current_args, "ret": None})
                    current_args = []
                calls.append({"pc": ev["pc"], "args": [], "ret": ev})
                current_pc = None

    if current_args:
        calls.append({"pc": current_pc, "args": current_args, "ret": None})

    for call in calls:
        sym = symbolize(call["pc"], syms)
        args_parts = []
        for a in call["args"]:
            idx = a["arg_idx"]
            if len(a["fields"]) > 1:
                flds = ", ".join(f".f[{i}]={format_value(v)}" for i, v in enumerate(a["fields"]))
                args_parts.append(f"arg[{idx}]=struct{{{flds}}}")
            elif len(a["fields"]) == 1:
                args_parts.append(f"arg[{idx}]={format_value(a['fields'][0])}")
            else:
                args_parts.append(f"arg[{idx}]=?")

        print(f"  → {sym}({', '.join(args_parts)})")

        if call["ret"]:
            r = call["ret"]
            if len(r["fields"]) > 1:
                flds = ", ".join(f".f[{i}]={format_value(v)}" for i, v in enumerate(r["fields"]))
                print(f"    ← ret = struct{{{flds}}}")
            elif len(r["fields"]) == 1:
                print(f"    ← ret = {format_value(r['fields'][0])}")
        print()

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <trigger_command>")
        print(f"Example: {sys.argv[0]} 'echo x > /proc/uaf_trigger'")
        sys.exit(1)

    trigger_cmd = sys.argv[1]
    syms = load_kallsyms()

    # Setup ctypes mmap
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.mmap.restype = ctypes.c_void_p
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                          ctypes.c_int, ctypes.c_int, ctypes.c_long]
    PROT_RW = 0x3  # PROT_READ | PROT_WRITE
    MAP_SHARED = 0x01

    # Open both devices
    kcov_fd = -1
    df_fd = -1
    kcov_arr = None
    df_arr = None

    # Legacy kcov (PC trace) - skip for now, use kallsyms for symbolization
    kcov_arr = None

    # Dataflow device - required
    df_fd = os.open("/sys/kernel/debug/kcov_dataflow", os.O_RDWR)
    fcntl.ioctl(df_fd, KCOV_DF_INIT_TRACE, BUF_SIZE)
    df_ptr = libc.mmap(None, BUF_SIZE * 8, PROT_RW, MAP_SHARED, df_fd, 0)
    if df_ptr == ctypes.c_void_p(-1).value:
        print("Error: kcov_dataflow mmap failed")
        sys.exit(1)
    df_arr = (ctypes.c_uint64 * BUF_SIZE).from_address(df_ptr)

    # Enable both
    if kcov_arr:
        fcntl.ioctl(kcov_fd, KCOV_ENABLE, KCOV_TRACE_PC)
        kcov_arr[0] = 0

    fcntl.ioctl(df_fd, KCOV_DF_ENABLE, 0)
    df_arr[0] = 0

    # Trigger - must happen in THIS process (kcov_dataflow is per-task)
    if ">" in trigger_cmd:
        target = trigger_cmd.split(">")[-1].strip()
    else:
        target = trigger_cmd
    try:
        fd_t = os.open(target, os.O_WRONLY)
        os.write(fd_t, b"x")
        os.close(fd_t)
    except Exception as e:
        print(f"Trigger failed: {e}")

    # Read results
    pc_trace = []
    if kcov_arr:
        n_pcs = kcov_arr[0]
        for i in range(1, min(int(n_pcs) + 1, BUF_SIZE)):
            pc_trace.append(kcov_arr[i])
        fcntl.ioctl(kcov_fd, KCOV_DISABLE, 0)

    n_df = int(df_arr[0])
    df_raw = [int(df_arr[i]) for i in range(min(n_df + 10, BUF_SIZE))]
    fcntl.ioctl(df_fd, KCOV_DF_DISABLE, 0)

    # Parse and display
    df_events = parse_dataflow(df_raw, int(n_df))
    merge_and_display(pc_trace, df_events, syms)

    # Cleanup
    if kcov_arr:
        os.close(kcov_fd)
    os.close(df_fd)

if __name__ == "__main__":
    main()
