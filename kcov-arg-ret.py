#!/usr/bin/env python3
"""
kcov-arg-ret.py - KCOV Data Flow Tracker Demo Script
Demonstrates trace-args/trace-ret for 3 memory corruption cases:
  1. Out-of-Bounds Write
  2. Use-After-Free Write
  3. Double-Free + Write

Usage:
  # Inside virtme-ng guest (after insmod simple_vuln_mod.ko):
  python3 kcov-arg-ret.py [oob|uaf|df|all]

  # Full automated run from host:
  source ~/venv-virtme/bin/activate && cd ~/next
  vng --user root --exec "insmod ~/kcov-dataflow-test/module/simple_vuln_mod.ko; \
    python3 ~/next/kcov-arg-ret.py all"
"""
import subprocess, sys, re, os

TRIGGERS = {
    "oob": ("/proc/vuln_trigger", "Out-of-Bounds Write",
            "memset(data->buf, 'A', 32) overflows 16-byte buffer"),
    "uaf": ("/proc/uaf_trigger", "Use-After-Free Write",
            "kfree(sd); uaf_write(sd, 0x41414141) writes to freed slab"),
    "df":  ("/proc/df_trigger", "Double-Free + Write",
            "kfree(sd); kfree(sd); df_write(sd, 0xDF00DF00) corrupts slab"),
}

BLUE = "\033[94m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"

def banner():
    print(f"""
{BOLD}╔═══════════════════════════════════════════════════════════════════╗
║  KCOV State-aware Data Flow Tracker                               ║
║  Traces function arguments (ENTRY) and return values (EXIT)       ║
║  with struct field expansion via DebugInfo                        ║
╚═══════════════════════════════════════════════════════════════════╝{RESET}
""")

def trigger(case):
    path, title, desc = TRIGGERS[case]
    print(f"{BOLD}{BLUE}━━━ Case: {title} ━━━{RESET}")
    print(f"  {desc}")
    print()

    # Clear dmesg ring buffer for clean output
    subprocess.run(["dmesg", "--clear"], capture_output=True)

    # Trigger the bug
    try:
        with open(path, "w") as f:
            f.write("x")
    except Exception:
        pass

    import time; time.sleep(0.3)

    # Read dmesg
    result = subprocess.run(["dmesg"], capture_output=True, text=True)
    lines = result.stdout.strip().split("\n")

    # Parse and display
    entry_lines = []
    ret_lines = []
    kasan_line = ""
    func_name = {"oob": "vuln_process", "uaf": "uaf_write", "df": "df_write"}[case]

    in_entry = False
    in_ret = False
    for line in lines:
        # Strip timestamp
        m = re.match(r'^\[\s*[\d.]+\]\s*(.*)', line)
        text = m.group(1) if m else line

        if f"KCOV_ENTRY" in text and func_name in text:
            in_entry = True; in_ret = False
            entry_lines.append(text)
        elif f"KCOV_RET" in text and func_name in text:
            in_ret = True; in_entry = False
            ret_lines.append(text)
        elif ".field[" in text:
            if in_entry:
                entry_lines.append(text)
            elif in_ret:
                ret_lines.append(text)
        else:
            in_entry = False; in_ret = False

        if "BUG: KASAN" in text:
            kasan_line = text

    # Display ENTRY
    print(f"  {GREEN}┌─ {func_name}() ENTRY (struct fields on function entry) ─┐{RESET}")
    for l in entry_lines:
        l = l.replace("kcov: ", "")
        print(f"  {GREEN}│{RESET} {l}")
    print(f"  {GREEN}└──────────────────────────────────────────────────────────┘{RESET}")
    print()

    # Display RETURN
    print(f"  {YELLOW}┌─ {func_name}() RETURN (struct fields after mutation) ────┐{RESET}")
    for l in ret_lines:
        l = l.replace("kcov: ", "")
        print(f"  {YELLOW}│{RESET} {l}")
    print(f"  {YELLOW}└──────────────────────────────────────────────────────────┘{RESET}")
    print()

    # Display KASAN
    if kasan_line:
        print(f"  {RED}✗ KASAN: {kasan_line.replace('kcov: ', '')}{RESET}")
    print()

def main():
    cases = sys.argv[1:] if len(sys.argv) > 1 else ["all"]
    if "all" in cases:
        cases = ["oob", "uaf", "df"]

    banner()
    for case in cases:
        if case in TRIGGERS:
            trigger(case)
        else:
            print(f"Unknown case: {case}. Use: oob, uaf, df, all")

if __name__ == "__main__":
    main()
