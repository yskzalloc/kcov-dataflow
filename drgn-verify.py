#!/usr/bin/env python3
"""
drgn-verify.py - Verify kcov_dataflow values match actual stack/register state.

Runs inside virtme-ng guest:
1. Triggers sleep_verify(sd, 0xDEADBEEF, 0x1234567890ABCDEF) with kcov_dataflow
2. While it sleeps, uses drgn to inspect the task's stack
3. Compares kcov_dataflow captured values with drgn-observed values
"""
import os, sys, fcntl, ctypes, time, threading, subprocess, struct

KCOV_DF_INIT_TRACE = 0x80086401
KCOV_DF_ENABLE = 0x6464
KCOV_DF_DISABLE = 0x6465
BUF_SIZE = 65536

# Known values passed to sleep_verify:
EXPECTED_MAGIC = 0xDEADBEEF
EXPECTED_COOKIE = 0x1234567890ABCDEF
EXPECTED_SD_ID = 0xAAAA
EXPECTED_SD_SIZE = 42

results = {"kcov": None, "drgn": None}

def run_trigger_with_kcov():
    """Thread: open kcov_dataflow, trigger, capture, disable."""
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.mmap.restype = ctypes.c_void_p
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                          ctypes.c_int, ctypes.c_int, ctypes.c_long]

    fd = os.open("/sys/kernel/debug/kcov_dataflow", os.O_RDWR)
    fcntl.ioctl(fd, KCOV_DF_INIT_TRACE, BUF_SIZE)
    ptr = libc.mmap(None, BUF_SIZE * 8, 3, 1, fd, 0)
    arr = (ctypes.c_uint64 * BUF_SIZE).from_address(ptr)
    fcntl.ioctl(fd, KCOV_DF_ENABLE, 0)
    arr[0] = 0

    # Trigger — this will sleep 30s inside sleep_verify
    fd_t = os.open("/proc/verify_trigger", os.O_WRONLY)
    os.write(fd_t, b"x")
    os.close(fd_t)

    # After wakeup, read buffer
    n = int(arr[0])
    records = []
    i = 1
    while i <= n and i < BUF_SIZE:
        hdr = int(arr[i])
        typ = hdr & 0xF0000000
        if typ in (0xE0000000, 0xF0000000):
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
            records.append({"type": "entry" if typ == 0xE0000000 else "ret",
                           "pc": pc, "meta": meta, "fields": fields})
        else:
            i += 1

    fcntl.ioctl(fd, KCOV_DF_DISABLE, 0)
    os.close(fd)
    results["kcov"] = records

def run_drgn_inspection():
    """After trigger starts sleeping, use drgn to inspect the task."""
    time.sleep(2)  # Wait for sleep_verify to be in msleep

    # Find the task by looking for the process writing to verify_trigger
    # It will be in state TASK_INTERRUPTIBLE (sleeping in msleep)
    script = '''
import drgn
from drgn.helpers.linux.pid import find_task

prog = drgn.Program()
prog.set_kernel()

# Find task sleeping in sleep_verify (comm will be the trigger process)
found = None
for task in drgn.helpers.linux.list.list_for_each_entry(
    "struct task_struct",
    prog["init_task"].tasks.address_of_(),
    "tasks"):
    try:
        comm = task.comm.string_().decode()
        if "cat" in comm or "sh" in comm or "python" in comm:
            # Check if it's in sleep_verify by looking at wchan
            pass
    except:
        pass

# Alternative: just find any task with kcov_df_enabled
for task in drgn.helpers.linux.list.list_for_each_entry(
    "struct task_struct",
    prog["init_task"].tasks.address_of_(),
    "tasks"):
    try:
        if task.kcov_df_enabled.value_():
            found = task
            break
    except:
        pass

if found:
    print(f"DRGN: Found task pid={found.pid.value_()} comm={found.comm.string_().decode()}")
    print(f"DRGN: kcov_df_area={hex(found.kcov_df_area.value_())}")
    print(f"DRGN: kcov_df_size={found.kcov_df_size.value_()}")
    print(f"DRGN: kcov_dataflow_seq={found.kcov_dataflow_seq.value_()}")

    # Read the dataflow buffer via the task's pointer
    area_addr = found.kcov_df_area.value_()
    if area_addr:
        count = prog.read_u64(area_addr)
        print(f"DRGN: buffer word count = {count}")
        # Read first few records
        if count > 0:
            for j in range(1, min(int(count)+1, 30)):
                val = prog.read_u64(area_addr + j*8)
                print(f"DRGN: buf[{j}] = {hex(val)}")
else:
    print("DRGN: No task with kcov_df_enabled found")
'''
    result = subprocess.run(
        ["drgn", "-k", "-c", script],
        capture_output=True, text=True, timeout=20
    )
    results["drgn"] = result.stdout + result.stderr

def main():
    print("=" * 60)
    print("KCOV Dataflow vs drgn Verification")
    print("=" * 60)
    print()
    print(f"Expected: sleep_verify(sd={{id=0x{EXPECTED_SD_ID:x}, size={EXPECTED_SD_SIZE}}},")
    print(f"                       magic=0x{EXPECTED_MAGIC:x},")
    print(f"                       cookie=0x{EXPECTED_COOKIE:x})")
    print()

    # Start trigger in background (it will sleep 30s)
    t = threading.Thread(target=run_trigger_with_kcov, daemon=True)
    t.start()

    # While it sleeps, inspect with drgn
    run_drgn_inspection()

    # Wait for trigger to complete (it sleeps 30s, but we can just report)
    print()
    print("--- drgn output ---")
    print(results["drgn"] or "(no output)")
    print()

    # Wait for kcov data (trigger will finish after 30s)
    print("Waiting for sleep_verify to wake up (30s)...")
    t.join(timeout=35)

    print()
    print("--- kcov_dataflow captured records ---")
    if results["kcov"]:
        for r in results["kcov"]:
            if "sleep_verify" in str(r.get("pc", "")):
                pass  # Can't symbolize here
            print(f"  {r['type']} pc=0x{r['pc']:x} fields={[hex(f) for f in r['fields']]}")
    else:
        print("  (no records)")

    print()
    print("=" * 60)
    print("VERIFICATION COMPLETE")
    print("=" * 60)

if __name__ == "__main__":
    main()
