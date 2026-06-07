# kcov-dataflow

**Beyond Edge Coverage: Per-Task Data-Flow Extraction at Kernel Function Boundaries via LLVM**

A compiler-kernel co-designed system that captures function arguments and return values — including automatic struct field expansion — at every instrumented function boundary in the Linux kernel.

## What It Does

At compile time, an LLVM SanitizerCoverage pass emits callbacks at function entry/exit. At runtime, the kernel backend records argument values into a per-task lock-free ring buffer accessible via `mmap()`. Composite types (structs) are automatically decomposed using DWARF `DICompositeType` metadata — zero source annotation required.

```
Compile Time:  LLVM pass inserts __sanitizer_cov_trace_args/ret callbacks
Kernel:        Per-task ring buffer via /sys/kernel/debug/kcov_dataflow
User Space:    mmap() consumer reads structured (PC, args, ret) records
```

## Key Properties

- **Per-task isolation** — only the enabled task generates records; others pay a single boolean check
- **Lock-free** — atomic slot reservation, no spinlocks in the data path
- **Crash-safe** — all pointer reads via `copy_from_kernel_nofault()`
- **Rust support** — post-compilation pipeline (`rustc→opt→llc`) for Rust kernel modules at -O2
- **Independent** — completely separate from legacy `/sys/kernel/debug/kcov`

## Repository Structure

```
linux/                          Kernel tree (submodule)
  kernel/kcov.c                 Kernel backend (kcov_dataflow device)
  scripts/Makefile.kcov         Build system integration
  tools/kcov-dataflow/          Test modules (eight_args_c, deep_module, eight_args_rust)

findings/                       PoC evaluation
  poc.sh                        Automated test script (30/30 pass)
  findings.html                 Detailed findings report with dmesg output
  poc1_ffi/                     Rust-to-C FFI contract violation (High)
  poc2_iouring/                 Silent in-bounds struct corruption (High)
  poc3_kvm/                     10-deep taint propagation to OOB (High)
  poc_binder/                   Binder SET_MAX_THREADS / BC_ENTER_LOOPER (High/Medium)
  poc_rust_core/                Error::from_errno(-4096) masking (Medium)
  poc_rust_vec/                 KVec boundary conditions (Medium)
  poc_rust_ds/                  RBTree duplicate key semantics (Medium)
  poc_rust_sync/                Arc refcount safety at -O2 (Low)
  poc_rust_mm/                  Page boundary + UserSlice zero-length (Medium)
  poc_rust_cred/                fget wrapping u32 values (Medium)
  poc_rust_binder/              Rust binder ioctl edge cases (Medium)
  rust_module/                  Struct field capture verification (Novel)

paper/                          LaTeX paper (arxiv + NDSS formats)
  arxiv/main.tex
  shared/macros.tex

cover-letter.txt                RFC patch series cover letter
mail-search.sh                  Public-inbox search helper
```

## Quick Start

```bash
# Prerequisites
source /home/debian-sid/venv-virtme/bin/activate
export PATH="/home/debian-sid/kcov-dataflow/llvm-project/build/bin:$PATH"
export RUSTC=/home/debian-sid/kcov-dataflow/rust/build/x86_64-unknown-linux-gnu/stage1/bin/rustc
export RUST_LIB_SRC=/home/debian-sid/kcov-dataflow/rust/library

# Build kernel
cd linux
make LLVM=1 CC=clang RUSTC=$RUSTC RUST_LIB_SRC=$RUST_LIB_SRC olddefconfig
make -j$(nproc) LLVM=1 CC=clang RUSTC=$RUSTC RUST_LIB_SRC=$RUST_LIB_SRC

# Build a test module
make LLVM=1 CC=clang RUSTC=$RUSTC RUST_LIB_SRC=$RUST_LIB_SRC \
  M=tools/kcov-dataflow/eight_args_c modules

# Run tests
vng --user root --exec "bash findings/poc.sh"
```

## Enabling for a Module

```makefile
obj-m := my_module.o
KCOV_DATAFLOW_my_module.o := y
```

The build system auto-injects `-fsanitize-coverage=trace-args,trace-ret -g`.

## Kernel Config

```
CONFIG_KCOV=y
CONFIG_KCOV_DATAFLOW_ARGS=y
CONFIG_KCOV_DATAFLOW_RET=y
# Optional:
CONFIG_KCOV_DATAFLOW_INSTRUMENT_ALL=y  # instrument entire kernel
CONFIG_FRAME_WARN=4096                 # needed with clang + INSTRUMENT_ALL
```

## Ring Buffer Format

```
buf[0] = total u64 words written (atomic counter)

Each record (3 + N words):
  [pos+0] type_and_seq   — 0xE=entry/0xF=return (bits[31:28]) | seq (bits[23:0])
  [pos+1] PC             — instrumented function address
  [pos+2] meta           — arg_idx[63:56] | size[55:48] | pointer[47:0]
  [pos+3..N] field values — struct fields or single scalar
```

## Findings Summary (60 test cases)

| Category | Count | Description |
|----------|-------|-------------|
| High | 4 | Exploitable: OOB, NULL deref, DoS, silent corruption |
| Medium | 8 | Missing validation, semantic issues |
| Low | 4 | Minor correctness concerns |
| Info | 37 | Correct behavior confirmed (not bugs) |
| Novel | 7 | First-ever Rust observability at -O2 |

Only 16 are actual bugs. The remaining 44 confirm correct behavior.

## Upstream Hardening Patches

Based on findings, 4 patches submitted:

1. `rust/kernel/error.rs` — `pr_warn!` → `pr_warn_once!` for out-of-range errno
2. `rust/kernel/uaccess.rs` — explicit zero-length early return in `read_raw()`
3. `drivers/android/binder.c` — reject `SET_MAX_THREADS > 256`
4. `drivers/android/binder.c` — reject duplicate `BC_ENTER_LOOPER`

## Toolchain

| Component | Location |
|-----------|----------|
| Custom LLVM/Clang 23 | `/home/debian-sid/kcov-dataflow/llvm-project/build/bin/clang` |
| Custom rustc 1.98-nightly | `/home/debian-sid/kcov-dataflow/rust/build/x86_64-unknown-linux-gnu/stage1/bin/rustc` |
| Kernel | `/home/debian-sid/kcov-dataflow/linux` (linux-next 7.1.0-rc4) |

## Paper

```bash
cd paper && make arxiv
```

Title: *Beyond Edge Coverage: Per-Task Data-Flow Extraction at Kernel Function Boundaries via LLVM*

## License

Kernel patches: GPL-2.0. LLVM patches: Apache-2.0 with LLVM Exception.
