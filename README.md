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
- **Rust support**: native via custom rustc built against custom LLVM
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

## Testing Guide

### Prerequisites

- Linux host (x86_64 or arm64)
- cmake, ninja-build
- Host clang (for bootstrapping LLVM build)
- QEMU (for virtme-ng boot testing)
- Python 3 + virtme-ng (`pip install virtme-ng`)

### Step 1: Build Custom LLVM

```bash
cd llvm-project
cmake -S llvm -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DLLVM_ENABLE_LLD=ON \
  -DLLVM_ENABLE_PROJECTS="clang;lld" \
  -DLLVM_TARGETS_TO_BUILD="X86;AArch64;ARM"
ninja -C build
cd ..
```

For native arm64 builds, replace targets with `"AArch64;ARM"` (ARM needed
for vdso32 Thumb compilation).

Verify the custom passes are available:
```bash
llvm-project/build/bin/opt --help-hidden | grep trace-args
# Expected: --sanitizer-coverage-trace-args
```

### Step 2: Set Up Toolchain

```bash
export PATH="$PWD/llvm-project/build/bin:$PATH"
```

### Step 3: Build and Boot Kernel

```bash
cd linux
vng --build \
  --configitem CONFIG_KCOV=y \
  --configitem CONFIG_KCOV_DATAFLOW_ARGS=y \
  --configitem CONFIG_KCOV_DATAFLOW_RET=y \
  --configitem CONFIG_KCOV_DATAFLOW_INSTRUMENT_ALL=y \
  --configitem CONFIG_DEBUG_INFO=y \
  --configitem CONFIG_DEBUG_INFO_DWARF5=y \
  LLVM=1 CC=clang
```

For arm64 cross-compilation from x86_64 host:
```bash
vng --build --arch arm64 \
  --configitem CONFIG_KCOV=y \
  --configitem CONFIG_KCOV_DATAFLOW_ARGS=y \
  --configitem CONFIG_KCOV_DATAFLOW_RET=y \
  --configitem CONFIG_COMPAT_VDSO=n \
  LLVM=1 CC=clang CROSS_COMPILE_COMPAT=arm-linux-gnueabi-
```

### Step 4: Run Selftests

#### user_ioctl (TAP test, 9 cases)
```bash
make -C tools/testing/selftests/kcov_dataflow
vng --user root --exec tools/testing/selftests/kcov_dataflow/user_ioctl/user_ioctl
```

Expected output:
```
TAP version 13
1..9
ok 1 kcov_dataflow.init_track
...
ok 9 kcov_dataflow.records_captured
# PASSED: 9 / 9 tests passed.
```

#### eight_args_c (module capture)
```bash
make LLVM=1 CC=clang M=tools/testing/selftests/kcov_dataflow/eight_args_c modules
vng --user root --exec \
  "python3 tools/testing/selftests/kcov_dataflow/kcov-dataflow-trigger-and-view.py \
    eight_args_c --ko tools/testing/selftests/kcov_dataflow/eight_args_c/eight_args_mod.ko"
```

Expected: `# Captured N words` with N > 0.

### Step 5 (Optional): Rust Module Support

Requires building rustc against the custom LLVM:

```bash
cd rust
cat > config.toml << EOF
[llvm]
download-ci-llvm = false
[build]
target = ["x86_64-unknown-linux-gnu"]
docs = false
extended = false
[target.x86_64-unknown-linux-gnu]
llvm-config = "$PWD/../llvm-project/build/bin/llvm-config"
cc = "$PWD/../llvm-project/build/bin/clang"
cxx = "$PWD/../llvm-project/build/bin/clang++"
[rust]
codegen-backends = ["llvm"]
debug-assertions = false
channel = "nightly"
EOF
python3 x.py build --stage 1 library
cd ..

export RUSTC="$PWD/rust/build/x86_64-unknown-linux-gnu/stage1/bin/rustc"
export RUST_LIB_SRC="$PWD/rust/library"
```

Then rebuild the kernel with `CONFIG_RUST=y` and build Rust selftests:
```bash
cd linux
make LLVM=1 CC=clang RUSTC=$RUSTC RUST_LIB_SRC=$RUST_LIB_SRC \
  M=tools/testing/selftests/kcov_dataflow/eight_args_rust modules
```

## CI Pipeline

The GitHub Actions workflow (`.github/workflows/ci.yml`) runs a 3-stage pipeline:

1. **build-llvm**: Builds custom LLVM/Clang with X86+AArch64+ARM targets
2. **build-rust**: Builds rustc stage1 against custom LLVM
3. **test** (4x matrix): Builds kernel and runs selftests
   - x86_64 (KVM)
   - x86_64-rt (KVM, PREEMPT_RT)
   - arm64 (TCG, docker rootfs)
   - arm64-rt (TCG, docker rootfs, PREEMPT_RT)

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

## Links

| Resource | URL |
|----------|-----|
| LLVM PR | https://github.com/llvm/llvm-project/pull/201410 |
| LLVM RFC | https://discourse.llvm.org/t/rfc-sanitizercoverage-add-fsanitize-coverage-trace-args-trace-ret/91026 |
| Kernel v2 | https://lore.kernel.org/all/20260603-kcov-dataflow-next-20260603-v2-0-fee0939de2c4@est.tech/ |
| Custom LLVM | https://github.com/yskzalloc/llvm-project |
| Custom rustc | https://github.com/yskzalloc/rust |
| Kernel | https://github.com/yskzalloc/linux |

## Paper

```bash
cd paper && ./tex.sh
```

Title: *Beyond Edge Coverage: Per-Task Data-Flow Extraction at Kernel Function Boundaries via LLVM*

## License

Kernel patches: GPL-2.0. LLVM patches: Apache-2.0 with LLVM Exception.
