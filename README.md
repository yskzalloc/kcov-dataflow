# kcov-dataflow

**Beyond Edge Coverage: Per-Task Data-Flow Extraction at Kernel Function Boundaries via LLVM**

A compiler-kernel co-designed system that captures function arguments and return values, including automatic struct field expansion, at every instrumented function boundary in the Linux kernel.

## What It Does

At compile time, an LLVM SanitizerCoverage pass emits callbacks at function entry/exit. At runtime, the kernel backend records argument values into a per-task lock-free ring buffer accessible via `mmap()`. Composite types (structs) are automatically decomposed using DWARF `DICompositeType` metadata: zero source annotation required.

```
Compile Time:  LLVM pass inserts __sanitizer_cov_trace_args/ret callbacks
Kernel:        Per-task ring buffer via /sys/kernel/debug/kcov_dataflow
User Space:    mmap() consumer reads structured (PC, args, ret) records
```

## Key Properties

- **Per-task isolation**: only the enabled task generates records; others pay a single boolean check
- **Lock-free**: READ_ONCE/WRITE_ONCE pattern (portable to ARM64)
- **Crash-safe**: all pointer reads via `copy_from_kernel_nofault()`
- **Rust support**: post-compilation pipeline (`rustc -> opt -> llc`) for Rust kernel modules at -O2
- **Independent**: completely separate from legacy `/sys/kernel/debug/kcov`

## Repository Structure

```
linux/                                          Kernel tree (submodule)
  kernel/kcov_dataflow.c                        Kernel backend
  scripts/Makefile.kcov                         Build system flags
  scripts/Makefile.lib                          Per-module opt-in logic
  tools/testing/selftests/kcov_dataflow/        Selftests
    kcov-dataflow-trigger-and-view.py           Visualization tool
    user_ioctl/user_ioctl.c                     Automated ioctl test (TAP)
    eight_args_c/                               C 1-8 arg stress test
    eight_args_rust/                            Rust equivalent
    rust_ffi_contract/                          FFI contract violation demo

llvm-project/                                   Custom LLVM (submodule)
rust/                                           Custom rustc (submodule)

findings/                                       PoC evaluation modules
paper/                                          LaTeX paper (arxiv + overleaf)
```

## Quick Start

```bash
# Build custom LLVM
cd llvm-project
cmake -S llvm -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_ENABLE_PROJECTS="clang;lld" \
  -DLLVM_TARGETS_TO_BUILD="X86"
ninja -C build
cd ..

# Set up toolchain
export PATH="$PWD/llvm-project/build/bin:$PATH"
export RUSTC="$PWD/rust/build/x86_64-unknown-linux-gnu/stage1/bin/rustc"
export RUST_LIB_SRC="$PWD/rust/library"  # must be at rustc build commit

# Build and boot kernel
cd linux
vng --build \
  --configitem CONFIG_KCOV=y \
  --configitem CONFIG_KCOV_DATAFLOW_ARGS=y \
  --configitem CONFIG_KCOV_DATAFLOW_RET=y \
  LLVM=1 CC=clang

# Run selftests
make -C tools/testing/selftests/kcov_dataflow
vng --user root --exec tools/testing/selftests/kcov_dataflow/user_ioctl/user_ioctl
```

## Selftests

```bash
# Automated ioctl test (9 TAP cases)
make -C tools/testing/selftests/kcov_dataflow
./user_ioctl/user_ioctl

# Module capture with visualization
make LLVM=1 CC=clang M=tools/testing/selftests/kcov_dataflow/eight_args_c modules
python3 kcov-dataflow-trigger-and-view.py eight_args_c

# All via kselftest
make kselftest TARGETS=kcov_dataflow
```

## Enabling for a Module

```makefile
obj-m := my_module.o
KCOV_DATAFLOW_my_module.o := y
```

The build system auto-injects `-fsanitize-coverage=trace-args,trace-ret`.

## Kernel Config

```
CONFIG_KCOV=y
CONFIG_KCOV_DATAFLOW_ARGS=y
CONFIG_KCOV_DATAFLOW_RET=y
CONFIG_DEBUG_INFO=y

# Optional:
CONFIG_KCOV_DATAFLOW_INSTRUMENT_ALL=y   # instrument entire kernel
CONFIG_KCOV_DATAFLOW_NO_INLINE=y        # disable inlining for full visibility
CONFIG_RUST=y                           # for Rust module support
```

## Ring Buffer Format

```
buf[0] = total u64 words written (atomic counter)

Each record (3 + N words):
  [pos+0] type_and_seq : 0xE=entry/0xF=return (bits[31:28]) | seq (bits[23:0])
  [pos+1] PC           : instrumented function address
  [pos+2] meta         : arg_idx[63:56] | size[55:48] | pointer[47:0]
  [pos+3..N] field values: struct fields or single scalar
```

## Toolchain

| Component | Location |
|-----------|----------|
| Custom LLVM/Clang 23 | https://github.com/yskzalloc/llvm-project |
| Custom rustc 1.98-nightly | https://github.com/yskzalloc/rust |
| Kernel | https://github.com/yskzalloc/linux |

## Paper

```bash
cd paper && ./tex.sh
```

Title: *Beyond Edge Coverage: Per-Task Data-Flow Extraction at Kernel Function Boundaries via LLVM*

## License

Kernel patches: GPL-2.0. LLVM patches: Apache-2.0 with LLVM Exception.
