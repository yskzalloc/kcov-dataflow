# copy.fail DirtyPipe (CVE-2022-0847) Tracking via kcov-dataflow

## What This Is

Recording of kernel function arguments during a DirtyPipe exploit attempt,
captured via kcov-dataflow's per-task ring buffer.

The exploit (`exploit.py`) uses `AF_ALG` sockets + `splice()` to overwrite
the page cache of `/usr/bin/su`, then executes the corrupted binary as root.

## Files

- `exploit.py` — The obfuscated exploit from https://copy.fail/exp
- `record_exploit.c` — C program that enables kcov_dataflow, runs the
  splice attack in-process, then dumps the captured records
- `dataflow_output.txt` — Raw captured output (13,991 words / ~3,497 records)
- `kallsyms.txt` — Kernel symbol table for address resolution

## How It Was Captured

```bash
# Kernel: linux-next 7.1.0-rc5 with:
#   CONFIG_KCOV_DATAFLOW_ARGS=y
#   CONFIG_KCOV_DATAFLOW_RET=y
#   KCOV_DATAFLOW instrumentation on fs/splice.o, fs/pipe.o, fs/open.o, fs/read_write.o

# Run in VM:
vng --user root --exec "./record_exploit"
```

The recorder enables kcov_dataflow for the current task, then performs
the splice attack directly (no fork), capturing all instrumented kernel
function arguments during:
1. `open("/usr/bin/su", O_RDONLY)` — opens target file
2. `pipe()` — creates pipe for splice
3. `splice(target_fd, &off, pipe_wr, NULL, 1, 0)` — loads page into pipe
4. `write(pipe_wr, payload, len)` — overwrites page cache (the bug)

## Key Observation

On patched kernels (7.1.0-rc5), the splice does NOT set PIPE_BUF_FLAG_CAN_MERGE
after the fix, so the write() into the pipe does not corrupt the page cache.
The kcov-dataflow records show the splice arguments and pipe state at each
function boundary, making the exploit's data flow visible for analysis.

## Captured: 13,991 words (~3,497 ENTRY/RET records)
