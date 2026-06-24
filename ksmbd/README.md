# ksmbdzzer — a scalable SMB-procedure fuzzer for KSMBD

A **high-level, SMB-procedure-level** coverage-guided fuzzer for the Linux in-kernel
SMB server (ksmbd), built to find **write-side privilege-escalation and non-crashing
logic bugs**. It steers with **kcov-dataflow** (kernel function argument/return
**values** + **comparison operand pairs** from `trace_cmp`, not just edges), runs
authenticated SMB2/3 sessions via **libsmbclient**, and exercises the SMBDirect/RDMA
transport via **librdmacm/libibverbs**. Today the grain fleet covers the **whole
SMB1/2/3 procedure surface (95 grains)**, and an **engine-comparison harness**
measures the dataflow steering against a pc-only + i2s/havoc baseline.

> **Not a syzkaller.** syzkaller fuzzes at the *syscall* level with edge coverage and
> finds *crashes*. ksmbdzzer fuzzes one layer up — at the *SMB procedure* level — with
> **dataflow argument/return values**, **procedure combination**, and a **contract
> oracle** for non-crashing access-control/logic bugs. They look at different things;
> do not benchmark one against the other.

---

## Design principles

These are the founding principles of the architecture. Everything below is an
implementation of them.

1. **SMB-procedure level, not syscall level.** The atom of work is an SMB procedure
   (CREATE, WRITE, SET_INFO, IOCTL, …), not a syscall. High-level by design.

2. **trace-args/ret is the primary signal.** kcov-dataflow reports the *values* a
   kernel function saw as arguments and returned. That is the differentiator over
   edge-coverage fuzzers, and the thesis of the project: turn those values into a
   real proving case (e.g. a check that returned "deny" now returns "allow"). With
   `CONFIG_KCOV_ENABLE_COMPARISONS`, the same dataflow buffer *also* carries
   `trace_cmp` **comparison operand pairs** — the correct substrate for RedQueen
   input-to-state (both sides of a `cmp` are known), fed into the mutator.

3. **KCOV path coverage for the bulk; trace-args/ret only when stuck.** kcov-dataflow
   also exposes plain KCOV path coverage. Drive the *bulk* of mutation with cheap
   path coverage; only when an element **saturates** (stops finding new paths) do we
   capture the stuck point via trace-args/ret and use it to break through. Saving a
   dataflow record on every input is wasteful — the highest-saturated coverage is
   what makes the eventual dataflow reading worth extracting.

4. **Grain = a working scenario.** A *grain* is a normal, valid scenario — the fixed
   negotiation + authentication + CREATE prefix — that fuzzes **only the last target
   PDU**. Because the prefix is valid, the grain is **deep by construction**: mutation
   starts *past* the SMB2 parser wall that kills from-scratch fuzzing.

5. **Capture normal behavior first.** Seed the corpus from the coverage that
   *legitimate* operations produce. Coverage *beyond* that normal baseline is
   anomalous by construction → rank it up.

6. **Four-phase round loop.** `P1 enumerate grains → P2 saturate each → P3 combine →
   P4 save/feed-forward`. Each round carries the strong grains and their corpus into
   the next generation, which therefore starts deeper.

7. **All performance-critical fuzzing lives in the C harness; Python only manages.**
   The mutation loop, execution, and coverage feedback run inside the LibFuzzer C
   program. Python enumerates grains, launches elements, aggregates results — it does
   no per-input work.

8. **LibFuzzer must see kernel coverage.** Each harness copies the kernel's KCOV path
   coverage into LibFuzzer's `__libfuzzer_extra_counters` after every input, so
   LibFuzzer's own mutation engine is steered by *kernel* coverage, not userspace.

9. **Alignment is the most important step.** An auto-generated element is only as good
   as its prefix: the prefix must reproduce the normal scenario's deep coverage, or
   the element just fuzzes shallow code. Enforce with a coverage gate — keep
   **ALIGNED** elements (`ft ≥ 100`), drop the misaligned. Deep-by-construction grains
   satisfy this by design.

10. **Anti-monkey selection.** A mutation is only interesting if its coverage **beats
    the working grain's own baseline** (`ft0`). Keep/rank/combine only **PRODUCTIVE**
    elements (`Δ = ft − ft0` over a threshold); a mutation that adds nothing over the
    bare scenario is a monkey at a keyboard and is dropped.

11. **Oracles are checks, not phases.** Three oracles run alongside fuzzing:
    - **crash** — KASAN/UBSAN/lockdep/BUG on the serial console.
    - **stability** — re-run the bare grain each round; if a scenario that reached
      deep before now collapses, the prior round's fuzzing **destabilized ksmbd** — a
      real *non-crashing* state-corruption bug.
    - **contract (dataflow)** — the write-side LPE oracle: ksmbd honoring
      write/delete/lock on a handle that lacks the right. This is the class syzkaller
      is blind to.

12. **Scale via parallel map-reduce.** Default `-procs` = all CPUs. Every element runs
    on its **own loopback IP**, so ksmbd routes each element's kernel coverage to its
    own buffer (no handle collision). When there are fewer grains than cores, fill the
    idle cores with **mutation replicas of the same grain** that share one corpus.

13. **Feed-forward across generations.** Each grain has a **persistent corpus**;
    round N replays round N−1's corpus, so its first coverage (`ft0`) starts high.
    The value pool is carried forward too. Deeper every generation.

14. **Escape the legacy low-level fuzz smell.** The old 12/8-phase random-tactic worker
    is consolidated into the clean deep-by-construction grain loop. No random havoc
    from scratch; directed mutation from valid deep state.

15. **Lightweight data-flow-guided input-to-state steering.** RedQueen input-to-state
    is now driven by real `trace_cmp` **operand pairs**: for each `cmp` record, if the
    input holds one operand, overwrite it with the other so the branch flips — clearing
    a magic-value gate in one step (`mutate_i2s` pass 0). The older arg/ret single-value
    substitution (drive an observed value to a type boundary) and Eclipser/GREYONE-style
    boundary steering remain as fallbacks. No SMT, no symbolic execution, no byte-level
    taint engine — all infeasible in-kernel. (cmp *operands* feed the mutator only; they
    are excluded from the coverage map — they are input-derived and would explode it.)

16. **Comparable, not just assertible.** A second, pc-only engine (edge coverage +
    i2s-or-havoc mutation) runs the same grains so the dataflow steering can be *measured*
    head-to-head, not merely claimed. `dataflow` vs `pc-i2s` = the value-coverage payoff;
    `pc-i2s` vs `pc-havoc` = the i2s payoff. Same instrumentation, controlled ablation.

---

## Architecture

```
ksmbdzzer.py  — orchestrator ONLY (enumerate, launch, aggregate; no per-input work)
    │
    │  gfuzz: the 4-phase GRAIN loop (the current architecture)
    │    P1 enumerate grains   — lib grains + raw-PDU grains + v2 hybrid grains
    │    P2 saturate each       — one LibFuzzer element per grain, map-reduce parallel
    │    P3 combine             — ALL-PAIRS combination of grains on a shared object
    │    P4 save                — persistent per-grain corpus + value pool → next round
    │
    ├── element/gen.py  — LibFuzzer C harness template engine  (was sniper/)
    │     • generate_grain_elements()  one harness per lib grain
    │     • generate_grain_combo_pool() ONE compiled combo harness + per-pair symlinks
    │     • run_elements()  per-element loopback IP, map-reduce replicas, compile cache
    │
    ├── element/common.h  — raw-grain harness: KCOV path coverage + mutate_i2s
    │     (RedQueen from trace_cmp pairs) + KSMBDZZER_ENGINE comparison switch
    │
    └── ctypes ─→ libksmbdzzer.so  — C library
                    ├── libsmbclient (NTLMv2 auth, signing) — valid deep prefixes
                    ├── kcov-dataflow mmap — arg/ret VALUES + trace_cmp pairs + KCOV path
                    ├── GRAINS[] registry — 95 normal scenarios, deep-by-construction
                    │     (whole SMB1/2/3 surface; canonical map: GRAIN.md)
                    ├── raw authed PDU injection — fuzz only the last target PDU
                    ├── pfz_grain_combo2() — run grains A+B on a SHARED fid/handle
                    └── librdmacm + libibverbs — SMBDirect/RDMA transport
```

### The grain (deep-by-construction)

Each grain establishes the prerequisite kernel state (negotiate → authenticate →
tree-connect → CREATE) as a **fixed valid prefix**, then hands LibFuzzer the **raw
target PDU** to mutate. The prefix is never fuzzed, so every input reaches deep ksmbd
code on the first try. **95 grains today** cover the whole upstream SMB procedure
surface: all 19 SMB2 commands, every FSCTL and SET_INFO/QUERY_INFO class, all CREATE
contexts, the SMB3 features (encryption/compression/multichannel/lease-v2/durable-v2/
RDMA-SMBDirect), the SMB1 legacy opcodes (deliberate version-conflict surface), and
the ksmbd blind spots (IPC netlink, signing crypto, deep DACL, RPC opnums). The
canonical grain↔handler map is **`GRAIN.md`**.

**Grain combination (P3).** All grains are combined pairwise on a **shared object**:
`pfz_grain_combo2(a,b)` runs grain A then B (or interleaved, or forked-concurrent) on
the *same* handle/path, so interaction bugs — B abusing a lock/lease/handle A left —
can arise. The all-pairs sweep is one compiled harness + per-pair symlinks, scheduled
through the `-procs` pool.

### The hybrid mutator (principle 3, in the C harness)

```
LLVMFuzzerTestOneInput(data):
    run the target PDU                       # deep by construction
    fold kernel coverage → ctr[]             # KCOV path + arg/ret VALUES; cmp = PC-only
    if new path:  g_stuck = 0
    else:         g_stuck++

LLVMFuzzerCustomMutator(data):
    # pass 0 (RedQueen / trace_cmp): for each cmp operand pair (a1,a2) in df_buf,
    #   if the input holds a1 → overwrite with a2 (and vice-versa) → flip the branch
    # then: cheap KCOV-bulk havoc, and at SATURATION drive an observed arg value to a
    #   type boundary via trace-args/ret.
```

`KSMBDZZER_ENGINE` selects the coverage+mutator so the same harness runs as distinct
engines for the comparison: `dataflow` (value coverage + i2s), `pc-i2s` (pc-only + i2s),
`pc-havoc` (pc-only + pure havoc).

---

## Quick start

The fuzzer is **100% guest-internal loopback** — each worker dials `127.0.0.<octet>`
and ksmbd binds loopback, so **no `--network` flag is needed** (the `lo` interface is
always up).

```bash
# The 4-phase grain fuzzer. -r = generations, -procs defaults to all CPUs. Each round
# carries the strong grains + corpus forward (feed-forward).
vng --user root --memory 16G --rw --cpus 8 \
  --append "nokaslr hung_task_panic=1 hung_task_timeout_secs=60" \
  --exec 'mount -t debugfs none /sys/kernel/debug; sysctl -w kernel.kptr_restrict=0;
          python3 ../ksmbd/ksmbdzzer.py init &&
          python3 ../ksmbd/ksmbdzzer.py gfuzz -r 30 --element-max 32'
```

Two ready-made runners (build kernel+lib, then run in `vng`):
- **`~/run_campaign.sh [ROUNDS] [ELEMENT_MAX] [TIMEOUT_MIN]`** — a full N-generation
  hunting campaign.
- **`~/engine_compare_campagin.sh [ROUNDS] [ELEMENT_MAX]`** — the 2-engine / 3-arm
  comparison (below).

`gfuzz` options:

| Option | Meaning |
|---|---|
| `-r N` | generations (each carries strong grains + corpus forward) |
| `-procs N` | parallel workers (default: **all CPUs**) |
| `--element-max S` | hard ceiling (s) per grain element if it never saturates |
| `--element-sat R` | LibFuzzer saturation ratio per element (default 0.02) |

> The old `ksmbdzzer.py fuzz` (8-phase, random-tactic worker + differential failslab)
> is **legacy** — retained for the failslab error-path campaign, superseded by `gfuzz`
> for the procedure-fuzzing architecture above.

## Build

**Library** (the `pfz_` C API):

```bash
cc -shared -fPIC -O2 -I/usr/include/samba-4.0 -I. \
   libksmbdzzer.c -o libksmbdzzer.so \
   -lsmbclient -lpthread -lrdmacm -libverbs -lcrypto
```

**Kernel** — portable (no machine-specific `.config`): start from virtme's base and
assert the detection + kcov stack via `--configitem` (see *Bug detection* for the full
list). Requires the custom clang on `PATH`:

```bash
export PATH="$PWD/../llvm-project/build/bin:$PATH"      # kcov-dataflow clang
vng --build --configitem CONFIG_KCOV=y \
            --configitem CONFIG_KCOV_ENABLE_COMPARISONS=y \
            --configitem CONFIG_KCOV_DATAFLOW_ARGS=y \
            --configitem CONFIG_KCOV_DATAFLOW_RET=y \
            --configitem CONFIG_SMB_SERVER=y \
            ... (rest of the detection set below) ... \
            LLVM=1 CC=clang
```

> **Footgun:** `make olddefconfig`/`vng --build` silently drops
> `CONFIG_KCOV_DATAFLOW_*` (and `_ENABLE_COMPARISONS`) unless the **custom clang 23**
> that emits `trace-args`/`trace-ret`/`trace-cmp` is on `PATH`.

Harnesses are compiled on demand by `element/gen.py`. A **compile cache** (source
content-hash + dependency mtime) skips `clang` when a harness is unchanged — so only
the first round of a multi-round run compiles; later rounds go straight to fuzzing.
The value pool is fed to LibFuzzer via the `.dict`, not baked into the C source, so
value feed-forward does not force a recompile.

---

## Scalability engineering notes

- **Per-element loopback IP** (`127.0.0.<slot>`): ksmbd derives the per-connection
  kcov handle from the destination IP, so a globally-unique IP per element guarantees
  no coverage-buffer collision — the basis for parallel map-reduce (principle 12).
- **Map-reduce replicas**: when grains < cores, idle cores run extra mutation
  instances of the same grain, all sharing that grain's persistent corpus dir.
- **Compile cache**: unchanged harness ⇒ no `clang`; multi-round runs compile once.
- **Lightened restart**: ksmbd is reset only before the first wave or after a wave
  that showed session-setup death (a 0-exec element) — not unconditionally per wave.
  This removes most restart latency and stops needlessly re-triggering the SMBDirect
  listener-cleanup path each wave.

---

## Bug detection

### Recommended kernel config (maximal detection)

These are asserted via `vng --build --configitem` (portable — no `.config` snapshot).
`CONFIG_SMB_SERVER=y` auto-`select`s ksmbd's crypto deps, and virtme's defconfig base
supplies keys/net/9p/overlay, so only the feature/detector symbols are listed:

```kconfig
# kcov-dataflow steering + trace_cmp (the primary signal)
CONFIG_KCOV=y   CONFIG_KCOV_INSTRUMENT_ALL=y
CONFIG_KCOV_ENABLE_COMPARISONS=y            # trace_cmp operand pairs -> RedQueen i2s
CONFIG_KCOV_DATAFLOW_ARGS=y
CONFIG_KCOV_DATAFLOW_RET=y
CONFIG_KCOV_DATAFLOW_INSTRUMENT_ALL=y

# ksmbd + RDMA transport
CONFIG_SMB_SERVER=y
CONFIG_SMB_SERVER_SMBDIRECT=y   CONFIG_SMBDIRECT=y
CONFIG_SMB_SERVER_KERBEROS5=y
CONFIG_RDMA_SIW=y   CONFIG_RDMA_RXE=y   CONFIG_INFINIBAND=y
CONFIG_INFINIBAND_USER_ACCESS=y   CONFIG_DUMMY=y

# Memory safety / UB / locking / lists
CONFIG_KASAN=y CONFIG_KASAN_GENERIC=y CONFIG_KASAN_INLINE=y
CONFIG_SLUB_DEBUG=y CONFIG_SLUB_DEBUG_ON=y
CONFIG_FORTIFY_SOURCE=y CONFIG_HARDENED_USERCOPY=y
CONFIG_UBSAN=y CONFIG_UBSAN_BOUNDS=y CONFIG_UBSAN_ARRAY_BOUNDS=y
CONFIG_LOCKDEP=y CONFIG_PROVE_LOCKING=y CONFIG_PROVE_RCU=y
CONFIG_DEBUG_ATOMIC_SLEEP=y CONFIG_DEBUG_LIST=y

# Fault injection (error-path testing, legacy failslab campaign)
CONFIG_FAULT_INJECTION=y CONFIG_FAILSLAB=y CONFIG_FAULT_INJECTION_DEBUG_FS=y

# Symbolization (with nokaslr)
CONFIG_DEBUG_INFO=y
```

### Catching bugs from outside the guest

```bash
# Serial capture + panic-on-oops so the VM exits on any bug:
vng --append "console=ttyS0 nokaslr panic=1 oops=panic" --exec '...'
# panic_on_warn=1 also turns a WARN() into a VM-exiting panic (aggressive).
grep -E "BUG:|KASAN:|UBSAN:|WARNING:|recursive locking|Oops" <kernel log>
```

| Detector | Class | Oracle it serves |
|---|---|---|
| KASAN | UAF / OOB / double-free | crash |
| LOCKDEP | deadlock / recursive-lock / ABBA | crash |
| UBSAN | integer overflow / array OOB | crash |
| DEBUG_LIST | list corruption | crash |
| *(grain re-run)* | scenario stopped working | **stability** (non-crashing) |
| *(dataflow contract)* | check-deny → allow | **contract** (write-side LPE) |

---

## Engine comparison

`~/engine_compare_campagin.sh [ROUNDS] [ELEMENT_MAX]` runs the **same grains, same
kernel** under two engines / three arms and prints a diff table
(`corpus | max_ft | productive | findings | bugs`), selected per-arm by
`KSMBDZZER_ENGINE` (a controlled ablation — identical instrumentation):

| Arm | Engine | Coverage | Mutator |
|---|---|---|---|
| `dataflow` | 1st | value-sensitive (pc,val) + cmp | i2s (RedQueen) |
| `pc-i2s` | 2nd | pc-only | i2s (RedQueen) |
| `pc-havoc` | 2nd | pc-only | pure havoc |

`dataflow` vs `pc-i2s` isolates the **value-coverage** payoff; `pc-i2s` vs `pc-havoc`
isolates the **i2s** payoff. Each arm starts cold (corpus reset) so none inherits
another's inputs.

---

## Findings

Kernel defects surfaced by the campaign (write-side / RDMA teardown):

1. **ksmbd oplock lev-II break deadlock** — `__smb_break_all_levII_oplock` sent the
   break under `m_lock`, inverting `srv_mutex→session_lock→m_lock→srv_mutex`.
   **Fixed** (collect brk_ops under lock, break after unlock) — `oplock.c`.
2. **SMBDirect `smbdirect_socket_destroy_sync` recursive `handler_mutex`** — the
   listener held its cm_id handler lock while releasing child sockets, which recurse
   into the child's handler lock (same class → lockdep deadlock; the 3h round-6 hang).
   **Fixed** (defer child release past the handler unlock) —
   `findings/smbdirect_socket_destroy_sync_deadlock.md`.
3. **SMBDirect recv_io / mem-pool teardown null-deref (BUG 1)** — **Fixed**
   (`accept.c`, drain qp before destroying pools).
4. **SMBDirect recursive `&sc->listen.lock`** on listener teardown — **Fixed**
   (splice-then-unlock) — `findings/smbdirect_recursive_listen_lock.md`.
5. **SMBDirect cm_id UAF in `_cma_cancel_listens` (BUG 2)** — **OPEN**, rare
   (needs a restart during active RDMA); hard RDMA-CM ref-lifetime fix.

Dataflow contract-oracle candidates (MS-SMB2 access-control class): the write-side
"granted-access-absent + op succeeded" checks (lock-without-WRITE, DELETE_ON_CLOSE-
without-DELETE, OVERWRITE_IF-without-WRITE) are **real missing SMB-layer checks** but
are **Unix-gated** — ksmbd authorizes at the VFS/POSIX layer, so an owner-on-own-file
never violates authorization. The oracle now uses a **cross-user** (root-owned) victim
so it can only flag a *genuine* integrity/LPE denial. See
`findings/TRIAGE-contract-oracle.md`.

---

## Files

```
ksmbdzzer.py                    orchestrator — gfuzz (4-phase grain loop) + legacy fuzz
libksmbdzzer.c / .h / .so       C library — 95-grain GRAINS[] registry, kcov-dataflow
                                (arg/ret + trace_cmp), combo2 shared-object, RDMA
element/gen.py                  LibFuzzer C harness engine — grain + combo-pool + v2
element/common.h, ntlmv2.h      raw-grain harness (mutate_i2s, KSMBDZZER_ENGINE) + auth
GRAIN.md                        canonical grain ↔ ksmbd-handler coverage map (95 grains)
ksmbd-sandbox.config            ksmbd server configuration
findings/                       confirmed-finding write-ups (oplock + smbdirect fixes)
~/run_campaign.sh               N-generation hunting campaign runner
~/engine_compare_campagin.sh    2-engine / 3-arm comparison runner
ksmbdzzer.html                  visual architecture overview (this design, rendered)
```
