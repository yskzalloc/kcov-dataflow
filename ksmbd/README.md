# ksmbdzzer — KSMBD Write-Side LPE Fuzzer

Dataflow-guided fuzzer for Linux KSMBD using **trace-args/ret** (kcov_dataflow) + **libFuzzer** to find write-side privilege escalation bugs.

## How It Works

```
┌─────────────────────────────────────────────────────────┐
│ Per Round:                                               │
│                                                          │
│ Phase 1-5: Python orchestrator                           │
│   → 11 VFS ops via CIFS mount                           │
│   → kcov_df_remote captures trace-args/ret              │
│   → ret=0 ranking: "which values bypass validation?"    │
│   → builds value_pool + corpus                          │
│                                                          │
│ Phase 6: Auto-generated libFuzzer snipers (C)           │
│   → 15 targeted harnesses (raw TCP, no CIFS client)     │
│   → __libfuzzer_extra_counters from kcov_dataflow       │
│   → ret=0 → 3× weight (deeper = more exploration)      │
│   → persistent corpus across rounds                     │
│   → live dictionary from Phase 1-5 discoveries          │
│                                                          │
│ Phase 7: Sharp analysis                                  │
│   → binary search validation boundaries                 │
│   → anomaly detection (ret=0 for unexpected values)     │
│   → trust boundary checking                             │
└─────────────────────────────────────────────────────────┘
```

## Key Design: trace-args/ret + libFuzzer

The snipers are libFuzzer binaries that read `kcov_dataflow` via `__libfuzzer_extra_counters`:
- **Entry records** (trace-args): which argument values reach each function
- **Return records** (trace-ret): which functions return 0 (success = bypassed validation)
- **Feedback**: `ret=0 → ctr += 3` (libFuzzer explores more inputs that succeed)

This means: libFuzzer automatically mutates toward values that **pass** ksmbd's checks — exactly the boundary where bugs live.

## Usage

```bash
cd linux && source ../venv-virtme/bin/activate
export PATH="$PWD/../llvm-project/build/bin:$PATH"

vng --user root --memory 8G --rw --cpus 4 --exec '
  python3 ../ksmbd/ksmbdzzer.py init
  python3 ../ksmbd/ksmbdzzer.py fuzz -t 5h -procs 2 -target write -sniper-time 60
'
```

### Options

| Flag | Description |
|------|-------------|
| `-t 30m\|1h\|5h` | Timeout — graceful save + exit. **Use this instead of external `timeout`** |
| `-procs 2` | Worker count (2 recommended — more overwhelms ksmbd) |
| `-target write\|race\|dacl\|boundary\|all` | Focus area |
| `-sniper-time 60` | Seconds per sniper per round. **Higher = deeper corpus**. 30-120s recommended for production |

### `-sniper-time` Explained

Each round runs 5 snipers sequentially. `-sniper-time 60` = 5 × 60s = 5 minutes of libFuzzer per round. Longer gives libFuzzer more iterations to explore its persistent corpus. **Increase as much as your time budget allows** — the `-t` flag handles safe shutdown.

Rule of thumb: `-sniper-time` = `total_time / (rounds_desired × 5)`

### Commands

```
init [--install-deps]     Setup KSMBD + shares + KDC
fuzz [options]            Write-side fuzzing campaign
validate -time N          Quick check (all snipers × N seconds)
campaign -hours N         Multi-phase campaign
```

## Files

```
ksmbd/
├── ksmbdzzer.py              — Orchestrator (Config, KsmbdService, FuzzWorker, FuzzCampaign)
├── sniper/
│   ├── gen.py                — Generates 15 C snipers from templates
│   ├── common.h              — Shared C: raw TCP auth + kcov_df + reconnect
│   ├── ntlmv2.h             — NTLMv2 (with -lcrypto)
│   └── harness.c/.so        — C extension (fast VFS syscalls)
├── bug_repro.py              — Standalone CVE reproducers
├── test_lock_bypass.py       — Finding 1 reproducer
├── test_delete_bypass.py     — Finding 2 reproducer
├── find.md                   — Confirmed findings
├── ksmbd-sandbox.config      — Server config (3 shares)
└── README.md                 — This file
```

## Snipers (15 total)

| Sniper | Target | How trace-args/ret helps |
|--------|--------|--------------------------|
| `raw_write` | TCP→smb2_write (streams + negative offsets) | ret=0 = write SUCCEEDED, learned offset feeds back |
| `read_after_write` | WRITE+READ (UAF/leak detection) | ret=0 on read = data returned |
| `dacl_setinfo` | SET_INFO(Security) | ret=0 = SD accepted (bypass?) |
| `compound` | WRITE+AllocationSize+CLOSE race | ret=0 = overflow accepted |
| `mt_race` | Multi-threaded WRITE+CLOSE (shared fid) | ret=0 during race = potential UAF |
| `write_lock_race` | LOCK(blocking)+CANCEL race | ret=0 = cleanup triggered |
| `priv_bypass` | READ-only → WRITE/LOCK/DELETE_ON_CLOSE | **ret=0 = PRIVILEGE BYPASS!** |
| `dh_trust` | DH2C reconnect with forged ID | ret=0 = trust boundary bypass |
| + 7 more | stream_oob, ea, lock, create_ctx, ndr, vfs_write, spnego | |

## Findings

See `find.md` for confirmed bugs:
1. **Exclusive lock without WRITE** (MS-SMB2 3.3.5.14 violation) — DoS
2. **DELETE_ON_CLOSE without DELETE** (MS-SMB2 3.3.5.9 violation) — unauthorized file deletion

## Shares

| Share | Purpose | Config |
|-------|---------|--------|
| `[share]` | VFS + raw TCP testing | `force user=root`, `guest ok=yes` |
| `[aclshare]` | ACL testing | `acl_xattr`, `force user=fuzz` |
| `[privtest]` | **Privilege bypass testing** | No force user, respects DesiredAccess |
