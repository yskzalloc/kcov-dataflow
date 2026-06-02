#!/usr/bin/env python3
"""
kcov_df_convert.py — Convert kcov-dataflow trace to readable function calls.

Usage:
    ./kcov_df_convert.py <trace.txt> <kallsyms.txt> > output.txt

Output format:
    ret = function(arg0, arg1, arg2, ...)
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
        return syms[idx][1]
    return None

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <trace.txt> <kallsyms.txt>", file=sys.stderr)
        sys.exit(1)

    syms, addrs = load_kallsyms(sys.argv[2])

    # Collect args per function call, emit on RET
    calls = {}  # pc -> {arg_idx: val}
    depth = 0

    with open(sys.argv[1]) as f:
        for line in f:
            if 'pc=0x' not in line:
                continue

            is_entry = '[ENTRY]' in line
            is_ret = '[RET  ]' in line
            if not is_entry and not is_ret:
                continue

            pc = int(line.split('pc=')[1].split(' ')[0], 16)
            sym = lookup(pc, syms, addrs)
            if not sym:
                continue

            # Parse arg_idx and val
            arg_idx = None
            val = 0
            for tok in line.split():
                if tok.startswith('arg['):
                    try:
                        arg_idx = int(tok.split('[')[1].split(']')[0])
                    except:
                        pass
                if tok.startswith('val='):
                    try:
                        val = int(tok[4:], 16)
                    except:
                        pass

            if is_entry:
                if pc not in calls:
                    calls[pc] = {}
                    depth += 1
                if arg_idx is not None and arg_idx < 32:
                    calls[pc][arg_idx] = val

            elif is_ret:
                args = calls.pop(pc, {})
                # Parse size to detect void return (sz=0, val=0)
                sz = 0
                for tok in line.split():
                    if tok.startswith('sz='):
                        try:
                            sz = int(tok[3:])
                        except:
                            pass

                indent = "  " * max(0, depth)
                if args:
                    arg_list = ', '.join(
                        f"0x{args[i]:x}" for i in sorted(args.keys())
                    )
                    if val == 0 and sz == 0:
                        print(f"{indent}{sym}({arg_list})")
                    else:
                        print(f"{indent}0x{val:x} = {sym}({arg_list})")
                else:
                    if val == 0 and sz == 0:
                        print(f"{indent}{sym}()")
                    else:
                        print(f"{indent}0x{val:x} = {sym}()")
                depth = max(0, depth - 1)

if __name__ == '__main__':
    main()
