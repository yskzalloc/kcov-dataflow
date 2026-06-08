# RFC: [SanCov] Add `-fsanitize-coverage=trace-args,trace-ret`

## Summary

I propose two new SanitizerCoverage instrumentation modes:

```
-fsanitize-coverage=trace-args    # capture function arguments at entry
-fsanitize-coverage=trace-ret     # capture return values at exit
```

These emit callbacks that provide the runtime with function argument
values, return values, and automatic struct field expansion via
compile-time `DICompositeType` metadata.

PR: https://github.com/llvm/llvm-project/pull/201410

## The Problem: The Semantic Observability Gap in SanitizerCoverage

SanitizerCoverage currently provides control-flow observability:

| Mode | What it captures |
|------|-----------------|
| `trace-pc` | Which edges executed |
| `trace-cmp` | Comparison operands |
| `trace-pc-guard` | Edge with guard variable |
| `trace-pc-entry-exit` | Function enter/exit events |

None expose **values flowing through function boundaries**. Two calls
traversing identical edges with different argument values are
indistinguishable:

```c
process_request(buf, 16);    // safe
process_request(buf, 4096);  // triggers overflow
```

Coverage-guided fuzzers (LibFuzzer, syzkaller) plateau on stateful
programs where security-relevant behavior depends on argument values,
not control-flow topology. A composite feedback signal
`(PC, arg_hash)` provides finer-grained mutation guidance.

## Why Existing LLVM/Clang Flags Cannot Solve This

### Category A: SanitizerCoverage (trace-pc, trace-cmp)

Semantically blind to composite values. `trace-cmp` captures individual
comparison operands but not the full function parameter state.
`trace-pc-entry-exit` reports which functions executed but not with what
values.

### Category B: XRay (`-fxray-instrument`)

Designed for **latency profiling**. Inserts NOP sleds at function
boundaries to record timestamps. The XRay runtime and compiler frontend
are not designed to parse `DICompositeType` metadata or spill struct
fields into callback buffers. Repurposing XRay for data extraction
would corrupt its ultra-low-latency design goal.

### Category C: `-finstrument-functions`

Emits `__cyg_profile_func_enter(this_fn, call_site)` with **no argument
values**. Only provides the function address and caller address.

### Category D: DataFlowSanitizer (`-fsanitize=dataflow`)

Byte-level taint tracking on every load/store/ALU operation. 10-100x
overhead. Unsuitable for continuous fuzzing or production use. We only
need boundary snapshots, not full dataflow tracking.

### Category E: `-fpatchable-function-entry`

Provides NOPs for runtime patching (ftrace, kprobes, eBPF). These
runtime tools depend on DWARF to parse arguments. Under aggressive
optimization (`-O2`), DWARF variable locations are elided, so runtime
tools cannot extract values. Our pass operates at the **LLVM IR level**
where arguments are explicit SSA values with type metadata intact.

### The Gap

| | trace-pc | XRay | -finstrument-functions | DFSan | **trace-args/ret** |
|---|---|---|---|---|---|
| Argument values | No | No | No | Taint only | **Yes** |
| Struct field expansion | No | No | No | No | **Automatic** |
| Works under -O2 | N/A | N/A | N/A | Yes | **Yes** |
| Overhead | <5% | <1% idle | ~5% | 10-100x | **<10%** |
| Language-agnostic (Rust/C) | Yes | No (needs mfentry) | Partial | No | **Yes** |

## Proposed Design

### Callbacks

**`trace-args`** (one call per parameter at function entry):

```c
void __sanitizer_cov_trace_args(
    u64 pc,           // function address
    u32 arg_idx,      // parameter index
    u32 arg_size,     // sizeof(arg) in bytes
    void *arg_ptr,    // pointer to argument value
    u64 *offsets,     // compile-time struct field layout (NULL for scalars)
    u32 num_fields    // number of struct fields (0 for scalars)
);
```

**`trace-ret`** (before each `ReturnInst`):

```c
void __sanitizer_cov_trace_ret(
    u64 pc,
    u32 ret_size,
    void *ret_ptr,
    u64 *offsets,
    u32 num_fields
);
```

Both compose with existing modes (e.g., `trace-pc,trace-args`).

### Struct field expansion

When a parameter resolves (via `stripDITypedefs()`) to `DICompositeType`:

1. Walk member list: extract `(byte_offset, byte_size)` pairs
2. Compute FNV-1a hash of type name (stored at `offsets[0]`)
3. Emit module-level `ConstantArray`: `[hash, off_0, sz_0, ..., off_n, sz_n]`
4. Pass `&offsets[1]` and `num_fields` to callback

For scalars: `offsets = NULL`, `num_fields = 0`.

### Debug info and codegen semantics

This pass strictly obeys LLVM's rule that `-g` must not alter code
generation semantics. If `DISubprogram` is absent, the function is
skipped. Debug info controls *what metadata is available* to the
runtime, not *whether* instrumentation occurs.

**Key architectural property:** The inserted callbacks are explicit IR
`CallInst` instructions with side effects. They survive all optimization
passes without requiring metadata propagation through SelectionDAG,
FastISel, or GlobalISel. Unlike `!pcsections` metadata (which requires
`ReplaceAllUsesWith` handlers and `DAGUpdateListener` propagation), our
approach needs no backend changes.

### Edge cases

- No `DISubprogram`: function skipped
- Variadic: skipped
- `naked`: skipped
- `void` return: no `trace_ret`
- Multiple returns: `EscapeEnumerator` finds all exit points

## Implementation

~270 LOC in `SanitizerCoverage.cpp`, ~170 LOC tests/docs.

| File | Change |
|------|--------|
| `SanitizerCoverage.cpp` | `InjectTraceForArgs()`, `InjectTraceForRet()` |
| `CodeGenOptions.def` | Two `CODEGENOPT` flags |
| `SanitizerArgs.cpp` | Parse `"trace-args"` / `"trace-ret"` (enum `1<<20`, `1<<21`) |
| `BackendUtil.cpp` | Wire to `SanitizerCoverageOptions` |
| `Instrumentation.h` | `TraceArgs` / `TraceRet` booleans |

Tests:
- `llvm/test/Instrumentation/SanitizerCoverage/trace-args.ll`
- `llvm/test/Instrumentation/SanitizerCoverage/trace-ret.ll`
- `clang/test/CodeGen/sanitizer-coverage-trace-args-ret.c`
- `clang/test/Driver/fsanitize-coverage.c`

## Impact on LLVM

- Extends `SanitizerCoverage.cpp` only (~270 LOC)
- No changes to: optimizer, codegen, linker, other sanitizers
- No new metadata kinds or propagation requirements
- Fully backward compatible: existing `trace-pc`/`trace-cmp` unchanged
- Works with any LLVM-based frontend (clang, rustc via IR pipeline)

## Performance

Per-callback: ~27 ns (dominated by memory spill + indirect call).
With whole-program instrumentation: +133% (comparable to KASAN +100-200%).
Per-module opt-in: +8.3% on instrumented paths; zero on uninstrumented.

## Current status

- 4 commits: core pass, clang tests, LLVM IR tests, documentation
- Deployed with a Linux kernel runtime consumer (KCOV backend)
- Tested with both C and Rust-generated LLVM IR
- Kernel patch series under review (demonstrates real-world viability)

## Open questions

1. **Scalar optimization**: Should primitive types use size-specific
   overloads (like `__sanitizer_cov_trace_cmp{1,2,4,8}`) instead of
   alloca spill to `void *`?
2. **Offsets array format**: Implementation detail between compiler and
   runtime, or stable ABI?
3. **Field count limit**: Cap to bound per-call cost for large aggregates?
4. **LTO**: Cross-module inlining and offset global visibility?

Feedback welcome.
