#!/usr/bin/env python3
"""
kcov_df_symbolize.py — Symbolize kcov-dataflow trace using kallsyms.

Usage:
    ./kcov_df_symbolize.py <trace.txt> <kallsyms.txt> [--filter KEYWORD]

Output: symbolized ENTRY/RET records with function names and argument values.
"""
import sys
from bisect import bisect_right

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
        off = pc - syms[idx][0]
        return f"{syms[idx][1]}+0x{off:x}" if off else syms[idx][1]
    return None

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <trace.txt> <kallsyms.txt> [--filter KEYWORD]")
        sys.exit(1)

    trace_path = sys.argv[1]
    ksyms_path = sys.argv[2]
    filt = sys.argv[4] if len(sys.argv) > 4 and sys.argv[3] == '--filter' else None

    syms, addrs = load_kallsyms(ksyms_path)

    with open(trace_path) as f:
        for line in f:
            if 'pc=0x' not in line:
                continue
            pc_str = line.split('pc=')[1].split(' ')[0]
            pc = int(pc_str, 16)
            sym = lookup(pc, syms, addrs)
            if not sym:
                continue
            if filt and filt.lower() not in sym.lower():
                continue
            # Format: symbol + original line
            print(f"  {sym:45s} {line.rstrip()}")

if __name__ == '__main__':
    main()
