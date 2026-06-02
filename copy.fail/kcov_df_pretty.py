#!/usr/bin/env python3
"""
kcov_df_pretty.py — Pretty-print kcov-dataflow trace as function calls.

Usage:
    ./kcov_df_pretty.py <trace.txt> <kallsyms.txt> [--filter KEYWORD]

Output:
    → crypto_aead_setkey(arg[0]=0x20, arg[1]=0x1000000008, arg[2]=0x48)
    ← crypto_aead_setkey() = 0xffffffea
"""
import sys
from bisect import bisect_right
from collections import defaultdict

def load_kallsyms(path):
    syms = []
    with open(path) as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 3 and parts[1] in 'tTwW':
                syms.append((int(parts[0], 16), parts[2]))
    syms.sort()
    return syms, [s[0] for s in syms]

def lookup(pc, syms, addrs):
    if pc < 0xffffffff80000000:
        return None
    idx = bisect_right(addrs, pc) - 1
    if idx >= 0 and pc - syms[idx][0] < 0x2000:
        return syms[idx][1]
    return None

def fmt_val(val, sz):
    if sz == 0:
        return f"0x{val:x}"
    if val == 0:
        return "0"
    return f"0x{val:x}"

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <trace.txt> <kallsyms.txt> [--filter KEYWORD]")
        sys.exit(1)

    trace_path = sys.argv[1]
    ksyms_path = sys.argv[2]
    filt = sys.argv[4] if len(sys.argv) > 4 and sys.argv[3] == '--filter' else None

    syms, addrs = load_kallsyms(ksyms_path)

    # Group consecutive ENTRY records by (seq-range, pc) into calls
    pending = {}  # pc -> list of (arg_idx, val)

    with open(trace_path) as f:
        for line in f:
            if 'pc=0x' not in line:
                continue
            parts = line.split()
            is_entry = '[ENTRY]' in line
            is_ret = '[RET  ]' in line
            if not is_entry and not is_ret:
                continue

            pc = int(line.split('pc=')[1].split(' ')[0], 16)
            sym = lookup(pc, syms, addrs)
            if not sym:
                continue
            if filt and filt.lower() not in sym.lower():
                # Flush pending if switching away
                if pc in pending:
                    args = pending.pop(pc)
                    arg_str = ', '.join(f"0x{v:x}" for _, v in sorted(args))
                    print(f"  → {sym}({arg_str})")
                continue

            # Extract arg_idx and val
            arg_idx = None
            val = 0
            for p in parts:
                if p.startswith('arg['):
                    arg_idx = int(p.split('[')[1].split(']')[0])
                if p.startswith('val='):
                    val = int(p[4:], 16)

            if is_entry:
                if pc not in pending:
                    pending[pc] = []
                if arg_idx is not None and arg_idx < 20:
                    pending[pc].append((arg_idx, val))
            elif is_ret:
                # Flush any pending ENTRY for this pc first
                if pc in pending:
                    args = pending.pop(pc)
                    arg_str = ', '.join(f"0x{v:x}" for _, v in sorted(args))
                    print(f"  → {sym}({arg_str})")
                print(f"  ← {sym}() = 0x{val:x}")

    # Flush remaining
    for pc, args in pending.items():
        sym = lookup(pc, syms, addrs)
        if sym:
            arg_str = ', '.join(f"0x{v:x}" for _, v in sorted(args))
            print(f"  → {sym}({arg_str})")

if __name__ == '__main__':
    main()
