# trace-args / trace-ret: user space demo

This is the demo from Part 3 of `../../slide.md`. It shows the same `-O2` program
two ways: through gdb, and through the values `-fsanitize-coverage=trace-args,trace-ret`
records at function boundaries.

| Function | What it shows | gdb, plain `-O2 -g` | trace-args |
|---|---|---|---|
| `process(int mode, int len)` | `mode` is dead after line 8 | `mode=<optimized out>` | `arg[0] val=0x8201` |
| `many(a1 … a10)` | `a7..a10` are on the stack on x86-64 | `a7=7 … a10=10`, from DWARF | `arg[6..9] = 0x7 … 0xa`, `RET 0x37` |
| `submit(struct req r)` | 24-byte struct passed by value (`byval`) | `{op = 2, len = 4096, flags = 65}` | `size=24 @addr {0x2, 0x1000, 0x41}` |
| `main(argc, argv)` | caller | `argc=<optimized out>` | `arg[0] val=0x1` |

gdb reads stack arguments in user space correctly, because DWARF describes
them. The stack-argument problem on the slides is about register-based probes
(ftrace, kprobes), not about debuggers.

## Files

- `demo.c`: the program under test. It is built with the instrumentation. The
  line numbers are the ones quoted on the slides, so don't move lines.
- `cb.c`: the callbacks. Build it **without** `-fsanitize-coverage`, so they
  don't instrument themselves. Without a strong definition, compiler-rt's weak
  empty ones would be used.

## Requirements

- clang built from the PR branch `sancov-trace-args-docs` (PR #201410). It
  provides the 3-operand TLV callbacks:

  ```c
  void __sanitizer_cov_trace_args(uint64_t tag, uint64_t val, const uint64_t *offsets);
  void __sanitizer_cov_trace_ret (uint64_t size, uint64_t val, const uint64_t *offsets);
  // tag = (arg_idx << 32) | size
  // offsets == NULL: val is the value; otherwise offsets[0] = N {offset, size} pairs
  ```

  The Phase 1 and Phase 2 branches still use the older 5-operand form, so
  `cb.c` does not match them.
- x86-64 Linux, `lld`, and `llvm-symbolizer`. Optionally `gdb` and `llvm-dwarfdump`.

The commands below assume `B=../../build/bin`, the in-tree build of that branch.

## Build and run

```sh
B=../../build/bin
$B/clang -O2 -g -fno-pie -fsanitize-coverage=trace-args,trace-ret -c demo.c -o demo.o
$B/clang -O2 -c cb.c -o cb.o
$B/clang -fuse-ld=lld -no-pie demo.o cb.o -o demo
./demo 2> trace.txt
```

`-fno-pie -no-pie` keeps the recorded PCs equal to link addresses, so
symbolizing needs no load bias. `-g` is only there for symbolizing and gdb:
the instrumentation is the same without it.

## Symbolize the records offline

Each record's PC is the callback's return address. Subtract 1 so it points
into the call:

```sh
while read -r line; do
	pc=${line#*pc=}; pc=${pc%% *}
	printf '%-60s <- %s\n' "$line" \
		"$(llvm-symbolizer --obj=demo --no-inlines --basenames \
			$(printf '%#x' $((pc - 1))) | paste -sd' ')"
done < trace.txt
```

Expected output (addresses vary). Shown here are the lines for the slides; the
full trace also has the `sink()` and `main()` records:

```
ENTRY pc=0x201908 arg[0] size=4 val=0x8201                   <- process demo.c:7:0
ENTRY pc=0x20191f arg[1] size=4 val=0x10                     <- process demo.c:7:0
RET   pc=0x201945 size=4 val=0x10                            <- process demo.c:10:2
ENTRY pc=0x20198b arg[0] size=8 val=0x1                      <- many demo.c:16:0
...
ENTRY pc=0x201a05 arg[6] size=8 val=0x7                      <- many demo.c:16:0
ENTRY pc=0x201a19 arg[7] size=8 val=0x8                      <- many demo.c:16:0
ENTRY pc=0x201a2f arg[8] size=8 val=0x9                      <- many demo.c:16:0
ENTRY pc=0x201a48 arg[9] size=8 val=0xa                      <- many demo.c:16:0
RET   pc=0x201a7a size=8 val=0x37                            <- many demo.c:17:2
ENTRY pc=0x201aa5 arg[0] size=24 @0x7ffcd335ff10 {0x2, 0x1000, 0x41} <- submit demo.c:21:0
RET   pc=0x201ac3 size=8 val=0x1043                          <- submit demo.c:21:55
```

- `process` `arg[0]` is `0x8201`: the value gdb reports as optimized out.
- The four stack arguments of `many` are recorded like the six register ones.
- `submit`'s struct is reported by address with the compiler's field table.
  That table comes from the IR type, not from DWARF.
- `sink`'s `RET size=0` is its `void` return: nothing to report.

## Compare with gdb on the plain build

```sh
$B/clang -O2 -g -fno-pie -c demo.c -o plain.o
$B/clang -fuse-ld=lld -no-pie plain.o -o plain
gdb -batch -ex 'break demo.c:9' -ex 'break many' -ex 'break submit' \
	-ex run -ex 'p mode' -ex continue -ex finish -ex continue -ex 'p r' ./plain
```

Output with gdb 18.1:

```
Breakpoint 1, process (mode=<optimized out>, len=len@entry=16) at demo.c:9
$1 = <optimized out>
Breakpoint 2, many (a1=a1@entry=1, ..., a6=a6@entry=6, a7=7, a8=8, a9=9, a10=10) at demo.c:17
main (argc=<optimized out>, argv=<optimized out>) at demo.c:26
Value returned is $2 = 55
Breakpoint 3, submit (r=...) at demo.c:21
$3 = {op = 2, len = 4096, flags = 65}
```

Why `mode` is gone: its location list ends at its last use. After that, only
an entry value remains, which gdb can't evaluate here:

```sh
llvm-dwarfdump --name=mode plain
```
```
[0x201690, 0x201699): DW_OP_reg5 RDI
[0x201699, 0x2016ad): DW_OP_entry_value(DW_OP_reg5 RDI), DW_OP_stack_value
```

**Observer effect:** run the same gdb commands on `./demo`, and gdb prints
`mode = 33281`. To pass `mode` to the callback, the backend kept it alive in a
callee-saved register, and gdb then happened to find it. The record doesn't
depend on that. It is correct whatever the debugger can see.

## Look at the emitted IR

```sh
$B/clang -O2 -fsanitize-coverage=trace-args,trace-ret -S -emit-llvm demo.c -o - |
	grep -E '__sancov_offsets_|define .*@(many|submit)|trace_args\(i64 (25769803784|38654705672|24),'
```
```llvm
@__sancov_offsets_ = private unnamed_addr constant [7 x i64] [i64 3, i64 0, i64 8, i64 8, i64 8, i64 16, i64 8]
define dso_local i64 @many(i64 noundef %0, ..., i64 noundef %9) ...
  notail call void @__sanitizer_cov_trace_args(i64 25769803784, i64 %6, ptr null)       ; (6 << 32) | 8: a7
  notail call void @__sanitizer_cov_trace_args(i64 38654705672, i64 %9, ptr null)       ; (9 << 32) | 8: a10
define dso_local i64 @submit(ptr ... byval(%struct.req) align 8 ... %0) ...
  notail call void @__sanitizer_cov_trace_args(i64 24, i64 %2, ptr @__sancov_offsets_)  ; byval req
```

There's no `alloca` and no spill. Each value is passed in a register, and the
tag is a constant.

## Check the instrumentation in the disassembly

The IR shows what the pass inserted. The disassembly shows what survived code
generation. GNU `objdump` (binutils 2.32 or later, for `--disassemble=SYMBOL`)
and `llvm-objdump` (`--disassemble-symbols=SYMBOL`) both work. Addresses below
are from one build and will vary.

### 1. Count the callbacks per function

Each function should have one `trace_args` call per IR argument and one
`trace_ret` call per return:

```sh
objdump -d --no-show-raw-insn demo | awk '
	/^[0-9a-f]+ <.*>:$/                  { fn = substr($0, index($0, "<")); seen[fn] }
	/call.*<__sanitizer_cov_trace_args>/ { a[fn]++ }
	/call.*<__sanitizer_cov_trace_ret>/  { r[fn]++ }
	END { for (f in seen) if (a[f] || r[f]) printf "%3d args %2d ret  %s\n", a[f], r[f], f }' | sort -k5
```
```
  2 args  1 ret  <main>:
 10 args  1 ret  <many>:
  2 args  1 ret  <process>:
  1 args  1 ret  <sink>:
  1 args  1 ret  <submit>:
```

`sink` returns `void`, and its `trace_ret` call carries `size = 0`.

### 2. Read the operands of each call

The callbacks use the normal C calling convention, so on x86-64 the three
operands are in `rdi`, `rsi` and `rdx`:

| Register | Operand | What to look for |
|---|---|---|
| `rdi` | `tag = (arg_idx << 32) \| size` | a constant: `mov $0x8,%edi` for arg 0, `movabs $0x600000008,%rdi` for arg 6 |
| `rsi` | `val` | the argument's register or stack slot |
| `rdx` | `offsets` | `xor %edx,%edx` (NULL) for a value, or the address of the field table |

```sh
objdump -d --no-show-raw-insn --disassemble=many demo
```
```
  201950:  push   %rbp                   ; 6 pushes + sub $0x18 = 0x48 bytes,
  ...                                    ; so the first stack argument is at 0x50(%rsp)
  20195a:  sub    $0x18,%rsp
  20197a:  mov    0x58(%rsp),%rbx         ; a8, loaded early
  20197f:  mov    $0x8,%edi               ; tag: arg 0, 8 bytes
  201984:  xor    %edx,%edx               ; offsets = NULL
  201986:  call   201bb0 <__sanitizer_cov_trace_args>
  ...
  2019ef:  movabs $0x600000008,%rdi       ; tag: arg 6, 8 bytes
  2019f9:  mov    0x50(%rsp),%rsi         ; val: a7, read from the caller's stack area
  2019fe:  xor    %edx,%edx
  201a00:  call   201bb0 <__sanitizer_cov_trace_args>
  ...
  201a2f:  movabs $0x900000008,%rdi       ; tag: arg 9
  201a39:  mov    0x68(%rsp),%r13         ; val: a10
  201a3e:  mov    %r13,%rsi
  201a43:  call   201bb0 <__sanitizer_cov_trace_args>
```

The stack arguments `a7`–`a10` are read from `0x50`–`0x68(%rsp)` and passed
in `rsi`, like the register arguments. The instrumented function's calling
convention doesn't matter to the callback.

### 3. Check a field table

For a value reported by address, `rsi` is the address and `rdx` points at the
table. With `-no-pie`, the table address is an immediate:

```sh
objdump -d --no-show-raw-insn --disassemble=submit demo
```
```
  201a91:  lea    0x10(%rsp),%rsi         ; val: address of the byval struct
  201a96:  mov    $0x18,%edi              ; tag: arg 0, 24 bytes
  201a9b:  mov    $0x200520,%edx          ; offsets: the field table
  201aa0:  call   201bb0 <__sanitizer_cov_trace_args>
```
```sh
objdump -s --start-address=0x200520 --stop-address=0x200558 demo
```
```
 200520 03000000 00000000 00000000 00000000   N = 3      {0,
 200530 08000000 00000000 08000000 00000000        8}   {8,
 200540 08000000 00000000 10000000 00000000        8}   {16,
 200550 08000000 00000000                              8}
```

That's `offsets[0] = 3` followed by `{0,8} {8,8} {16,8}`: the three `long`
fields of `struct req`.

### 4. Things that must not be there

```sh
# notail: the return address identifies the observation, so no tail jumps
objdump -d --no-show-raw-insn demo | grep -cE 'jmp.*<__sanitizer_cov_trace_(args|ret)>'      # 0
# trace-args/ret alone add no edge coverage
objdump -d --no-show-raw-insn demo | grep -cE 'call.*<__sanitizer_cov_trace_pc'               # 0
# the callbacks themselves are not instrumented (cb.c built without the flag)
objdump -d --no-show-raw-insn demo |
	sed -n '/^[0-9a-f]* <__sanitizer_cov_trace_\(args\|ret\)>:/,/^$/p' | grep -c 'call.*<__sanitizer_cov'   # 0
```

### 5. In the object file, before linking

`-r` shows the relocations. Each trace call is a `PLT32` relocation against
the callback, and each table is an `R_X86_64_32` relocation into `.rodata`:

```sh
objdump -dr --no-show-raw-insn --disassemble=submit demo.o
```
```
 1cb:  mov    $0x0,%edx
                1cc: R_X86_64_32      .rodata
 1d0:  call   1d5 <submit+0x15>
                1d1: R_X86_64_PLT32   __sanitizer_cov_trace_args-0x4
```

This is also the quickest check on a kernel object (`.o` or `.ko`): every
`__sanitizer_cov_trace_args` relocation is one observation.

## Clean up

```sh
rm -f demo plain *.o trace.txt
```
