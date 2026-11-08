# trace-args / trace-ret: Rust user space demo

This is the Rust twin of `../c`. The same `-O` program is shown two ways:
through gdb, and through the values trace-args/trace-ret record at function
boundaries. rustc uses the same LLVM pass as clang, so there is nothing
Rust-specific in the instrumentation. What differs is what the Rust ABI
tells the IR.

| Function | What it shows | gdb, plain `-O -g` | trace-args |
|---|---|---|---|
| `process(mode: i32, len: i32)` | `mode` is dead after line 13 | `mode=<optimized out>` | `arg[0] val=0x8201` |
| `many(a1 … a10: i64)` | `a7..a10` are on the stack on x86-64 | `a7=7 … a10=10`, from DWARF | `arg[6..9] = 0x7 … 0xa`, `RET 0x37` |
| `submit(r: Req)` | by value: the Rust ABI passes a `dereferenceable(24)` pointer | `Req {op: 2, len: 4096, flags: 65}` | `size=24 @addr {0x2, 0x1000, 0x41}` |
| `inspect(r: &Req)` | a shared reference is `dereferenceable(24)` | `Req {…}` via `p *r` | `size=24 @addr {0x2, 0x1000, 0x41}` |
| `checksum(buf: &[u8])` | one source parameter, two IR arguments | `break checksum` stops in an inlined `NonNull::eq`; `buf` not visible | `arg[0]` pointer, `arg[1] val=0x7` (length), `RET 0x29c` |

`inspect` is the case that differs from C. A C `const struct req *` has no
`dereferenceable` attribute, so trace-args reports only the pointer value. A
Rust `&Req` has one, so the 24 bytes behind it are snapshotted at entry.
That's a read the IR says is allowed at the call.

## Files

- `demo.rs`: the program under test, built with the instrumentation. The
  functions are `#[no_mangle]`, so they keep their arguments (no
  interprocedural constant propagation) and their plain symbol names. They're
  `#[inline(never)]`, so each one keeps its own boundary. The line numbers are
  quoted below, so don't move lines.
- `cb.rs`: the callbacks, as a separate crate built **without** the
  instrumentation. `demo.rs` links it with `extern crate cb;`.

## Requirements

- A rustc linked against an LLVM 24 that has the PR's TLV callbacks
  (`sancov-trace-args-docs`, PR #201410):

  ```c
  void __sanitizer_cov_trace_args(uint64_t tag, uint64_t val, const uint64_t *offsets);
  void __sanitizer_cov_trace_ret (uint64_t size, uint64_t val, const uint64_t *offsets);
  // tag = (arg_idx << 32) | size
  // offsets == NULL: val is the value; otherwise offsets[0] = N {offset, size} pairs
  ```

  This tree's stage 1 rustc is one (`rustc 1.101.0-nightly`, `LLVM version: 24.0.0`):

  ```sh
  R=../../../rust/build/host/stage1/bin/rustc
  ```

  Check which ABI it emits before relying on it:

  ```sh
  $R --edition 2021 -O $SANCOV -L . --emit=llvm-ir demo.rs -o - | grep 'declare.*trace_args'
  # declare void @__sanitizer_cov_trace_args(i64, i64, ptr)    <- TLV, matches cb.rs
  ```

  `SANCOV` is defined in the next section. Build `libcb.rlib` first, because
  `demo.rs` needs it. A 5-operand declaration
  `(i32, i32, i64, ptr, i32)` means a Phase 1/2 LLVM, and `cb.rs` won't match it.
- A stock rustc does **not** work, even through `--emit=llvm-ir` and the
  tree's `opt`. Its LLVM 23 IR is rejected by LLVM 24
  (`second domain operand must be an i1 constant`).
- x86-64 Linux. `cb.rs` reads the return address through `rbp`, so it's
  built with `-Cforce-frame-pointers=yes`. You also need `llvm-symbolizer`,
  and optionally `gdb` and `llvm-dwarfdump`.

## Build and run

```sh
R=../../../rust/build/host/stage1/bin/rustc
SANCOV="-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=1 \
        -Cllvm-args=-sanitizer-coverage-trace-args -Cllvm-args=-sanitizer-coverage-trace-ret"

$R --edition 2021 -O -g -Cforce-frame-pointers=yes --crate-type=rlib cb.rs -o libcb.rlib
$R --edition 2021 -O -g -Crelocation-model=static $SANCOV -L . demo.rs -o demo
./demo 2> trace.txt
```

- **No `-Zsanitizer` flag:** rustc has no option of its own for
  SanitizerCoverage. The kernel uses the same `-Cpasses=sancov-module` and
  `-Cllvm-args=` form.
- **Why `-sanitizer-coverage-level=1`:** in the PR, trace-args and trace-ret
  need a coverage level, as the other modes do. They count as the
  instrumentation type, so the level adds no `trace_pc_guard` callbacks here.
  (Level 1 *on its own* would select `trace-pc-guard`.)
- **Why `-Crelocation-model=static`:** a non-PIE binary records link
  addresses, so symbolizing needs no load bias.
- **Effect of `-g`:** it's only for symbolizing and gdb. The instrumentation
  is the same without it.

## Symbolize the records offline

```sh
while read -r line; do
	pc=${line#*pc=}; pc=${pc%% *}
	printf '%-62s <- %s\n' "$line" \
		"$(llvm-symbolizer --obj=demo --no-inlines --basenames \
			$(printf '%#x' $((pc - 1))) | paste -sd' ')"
done < trace.txt
```

Expected output, demo functions only (addresses vary). The full trace also
has `sink()`, `main` and `std::rt::lang_start` records, since those
generic instances are compiled into this crate:

```
ENTRY pc=0x407ac8 arg[0] size=4 val=0x8201                     <- process demo.rs:12:0
ENTRY pc=0x407adf arg[1] size=4 val=0x10                       <- process demo.rs:12:0
RET   pc=0x407b05 size=4 val=0x10                              <- process demo.rs:16:2
ENTRY pc=0x4079ab arg[0] size=8 val=0x1                        <- many demo.rs:21:0
...
ENTRY pc=0x407a25 arg[6] size=8 val=0x7                        <- many demo.rs:21:0
ENTRY pc=0x407a39 arg[7] size=8 val=0x8                        <- many demo.rs:21:0
ENTRY pc=0x407a4f arg[8] size=8 val=0x9                        <- many demo.rs:21:0
ENTRY pc=0x407a68 arg[9] size=8 val=0xa                        <- many demo.rs:21:0
RET   pc=0x407a9a size=8 val=0x37                              <- many demo.rs:24:2
ENTRY pc=0x407956 arg[0] size=24 @0x7ffd39cc07e8 {0x2, 0x1000, 0x41} <- inspect demo.rs:35:0
RET   pc=0x407969 size=8 val=0x41                              <- inspect demo.rs:35:43
ENTRY pc=0x407b29 arg[0] size=24 @0x7ffd39cc07e8 {0x2, 0x1000, 0x41} <- submit demo.rs:29:0
RET   pc=0x407b43 size=8 val=0x1043                            <- submit demo.rs:29:56
ENTRY pc=0x40786d arg[0] size=8 val=0x43e030                   <- checksum demo.rs:40:0
ENTRY pc=0x407881 arg[1] size=8 val=0x7                        <- checksum demo.rs:40:0
RET   pc=0x40792d size=4 val=0x29c                             <- checksum demo.rs:40:75
```

- **`process`:** `arg[0]` is `0x8201`, the value gdb reports as optimized out.
- **`many`:** the four stack arguments are recorded like the six register ones.
- **`inspect` and `submit`:** both reach the callback as an address plus the
  same 3-field table (`offsets[0] = 3`, `{0,8} {8,8} {16,8}`). The table comes
  from the IR, which says the pointer is `dereferenceable(24)`. DWARF isn't
  used. Both show the same address, because `r` was moved into `submit` without
  a copy.
- **`checksum`:** `&[u8]` is two IR arguments, so `arg_idx` is the IR
  position. `arg[0]` is the data pointer, reported as a value: a slice has no
  fixed `dereferenceable` size. `arg[1]` is the length, 7. The return value
  `0x29c` is 668, the byte sum of `"df-demo"`.

## Compare with gdb on the plain build

```sh
$R --edition 2021 -O -g -Crelocation-model=static -L . demo.rs -o plain
gdb -batch -ex 'break demo.rs:14' -ex 'break many' -ex 'break inspect' \
	-ex 'break submit' -ex 'break checksum' -ex run -ex 'p mode' -ex continue \
	-ex finish -ex continue -ex 'p *r' -ex continue -ex 'p r' -ex continue -ex 'p buf' ./plain
```

Output with gdb 18.1, trimmed:

```
Breakpoint 1, demo::process (mode=<optimized out>, len=16) at demo.rs:14
$1 = <optimized out>
Breakpoint 2, demo::many (a1=1, a2=2, a3=3, a4=4, a5=5, a6=6, a7=7, a8=8, a9=9, a10=10) at demo.rs:23
Value returned is $2 = 55
Breakpoint 3, demo::inspect (r=0x7fffffffd648) at demo.rs:35
$3 = demo::Req {op: 2, len: 4096, flags: 65}
Breakpoint 4, demo::submit (r=...) at demo.rs:29
$4 = demo::Req {op: 2, len: 4096, flags: 65}
Breakpoint 5, core::ptr::non_null::{impl#15}::eq<u8> (self=<optimized out>, other=<optimized out>) at .../core/src/ptr/non_null.rs:1664
No symbol 'buf' in current context
```

- **`mode`:** its location list ends at its last use. After that, only an
  entry value remains, which gdb can't evaluate here. Check with
  `llvm-dwarfdump --name=mode plain`:
  ```
  [0x407700, 0x407709): DW_OP_reg5 RDI
  [0x407709, 0x40771d): DW_OP_GNU_entry_value(DW_OP_reg5 RDI), DW_OP_stack_value
  ```
- **`checksum`:** the optimizer inlined the slice iterator into it, and gdb
  places `break checksum` inside the inlined `NonNull::eq`. There, `buf` isn't
  in scope, and `self`/`other` are optimized out. trace-args recorded both
  halves of `buf` at entry anyway.
- **gdb and Rust types:** gdb decodes Rust types fine in user space (`&Req`,
  `Req`, `&[u8]` once it is in scope). The kernel-side gap on the slides is
  about ftrace/BTF decoding, not about gdb.

**Observer effect:** on the instrumented `./demo`, the same commands show
`mode=33281`, and `break checksum` stops in `demo::checksum` with
`buf = &[u8] [100, 102, 45, 100, 101, 109, 111]`. Instrumentation changed
code generation: the trace calls kept the values alive and gave `checksum` an
entry boundary of its own. The records don't depend on that.

## Look at the emitted IR

```sh
$R --edition 2021 -O $SANCOV -L . --emit=llvm-ir demo.rs -o - |
	grep -E '^@__sancov_offsets_|^define .*@(inspect|submit|checksum)\(|trace_args\(i64 (24|4294967304),'
```

Output, trimmed to the three functions. The grep also matches `arg[1]` of other functions:

```llvm
@__sancov_offsets_.19 = private unnamed_addr constant [7 x i64] [i64 3, i64 0, i64 8, i64 8, i64 8, i64 16, i64 8]
define dso_local noundef i32 @checksum(ptr noalias ... nonnull readonly %buf.0, i64 noundef ... %buf.1) ...
  notail call void @__sanitizer_cov_trace_args(i64 4294967304, i64 %buf.1, ptr null)        ; (1 << 32) | 8: buf.len
define dso_local noundef i64 @inspect(ptr noalias ... readonly align 8 ... dereferenceable(24) %r) ...
  notail call void @__sanitizer_cov_trace_args(i64 24, i64 %0, ptr @__sancov_offsets_.19)   ; &Req snapshot
define dso_local noundef i64 @submit(ptr noalias ... readonly align 8 ... dereferenceable(24) %r) ...
  notail call void @__sanitizer_cov_trace_args(i64 24, i64 %0, ptr @__sancov_offsets_.19)   ; Req by value
```

The table name suffix (`.19`) may vary. The pass adds no `alloca`: the
module has 6 with or without instrumentation, all from rustc itself.

## Check the instrumentation in the disassembly

The checks are the same as in `../c/README.md`, which explains each one in
more detail. Addresses are from one build and will vary.

### 1. Count the callbacks per function

```sh
objdump -d --no-show-raw-insn -C demo | awk '
	/^[0-9a-f]+ <.*>:$/                  { fn = substr($0, index($0, "<")); seen[fn] }
	/call.*<__sanitizer_cov_trace_args>/ { a[fn]++ }
	/call.*<__sanitizer_cov_trace_ret>/  { r[fn]++ }
	END { for (f in seen) if (a[f] || r[f]) printf "%3d args %2d ret  %s\n", a[f], r[f], f }' | sort -k5
```
```
  2 args  1 ret  <checksum>:                  <- &[u8]: pointer + length
  0 args  1 ret  <demo::main>:                <- fn main(): no arguments
  1 args  1 ret  <demo::sink>:
  1 args  1 ret  <inspect>:
  2 args  1 ret  <main>:                      <- the C-ABI main rustc generates
 10 args  1 ret  <many>:
  2 args  1 ret  <process>:
  1 args  1 ret  <submit>:
  ...                                          <- std::rt::lang_start instances
```

- **`-C`:** demangles the generic `std` instances compiled into this crate.
- **Only this crate is instrumented.** The precompiled `std` and `libcb.rlib`
  contain no trace calls.

### 2. Read the operands: `rdi` = tag, `rsi` = value, `rdx` = offsets

```sh
objdump -d --no-show-raw-insn --disassemble=many demo       # same frame as in C: 0x48 bytes
```
```
  407a0f:  movabs $0x600000008,%rdi      ; tag: arg 6, 8 bytes
  407a19:  mov    0x50(%rsp),%rsi        ; val: a7, from the stack
  407a1e:  xor    %edx,%edx              ; offsets = NULL
  407a20:  call   4085d0 <__sanitizer_cov_trace_args>
```
```sh
objdump -d --no-show-raw-insn --disassemble=checksum demo
```
```
  40785e:  mov    $0x8,%edi              ; arg 0: buf.ptr
  407863:  mov    %r14,%rsi
  407866:  xor    %edx,%edx
  407868:  call   4085d0 <__sanitizer_cov_trace_args>
  40786d:  movabs $0x100000008,%rdi      ; arg 1: buf.len
  407877:  mov    %rbx,%rsi
```

### 3. Check the `&Req` snapshot table

```sh
objdump -d --no-show-raw-insn --disassemble=inspect demo
```
```
  407941:  mov    %rdi,%rbx              ; r: the reference itself
  407944:  mov    $0x18,%edi             ; tag: arg 0, 24 bytes (dereferenceable(24))
  407949:  mov    $0x43e060,%edx         ; offsets: the table
  40794e:  mov    %rbx,%rsi              ; val: the address to snapshot
  407951:  call   4085d0 <__sanitizer_cov_trace_args>
```
```sh
objdump -s --start-address=0x43e060 --stop-address=0x43e098 demo
```
```
 43e060 03000000 00000000 00000000 00000000   N = 3, {0, 8} {8, 8} {16, 8}
 43e070 08000000 00000000 08000000 00000000
 43e080 08000000 00000000 10000000 00000000
 43e090 08000000 00000000
```

`submit` passes the same table, because it's keyed on the same 24-byte layout.

### 4. Things that must not be there

```sh
objdump -d --no-show-raw-insn demo | grep -cE 'jmp.*<__sanitizer_cov_trace_(args|ret)>'      # 0: notail
objdump -d --no-show-raw-insn demo | grep -cE 'call.*<__sanitizer_cov_trace_pc'               # 0: level=1 adds no guards here
objdump -d --no-show-raw-insn demo |
	sed -n '/^[0-9a-f]* <__sanitizer_cov_trace_\(args\|ret\)>:/,/^$/p' | grep -c 'call.*<__sanitizer_cov'   # 0
```

### 5. In the object file

```sh
$R --edition 2021 -O -g -Crelocation-model=static $SANCOV -L . --emit=obj demo.rs -o demo.o
objdump -dr --no-show-raw-insn --disassemble=inspect demo.o
```
```
   9:  mov    $0x0,%edx
                a: R_X86_64_32      .rodata..L__sancov_offsets_.19
  11:  call   16 <inspect+0x16>
                12: R_X86_64_PLT32  __sanitizer_cov_trace_args-0x4
```

rustc puts each table in a section of its own, so the relocation names it
(`.L__sancov_offsets_.19`). The same check works on a Rust kernel module's `.o`.

## Clean up

```sh
rm -f demo plain demo.o libcb.rlib trace.txt
```
