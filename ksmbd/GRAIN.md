# ksmbdzzer Grain Coverage Map

Goal: a grain for **every SMB2/SMB3 procedure** (and sub-operation), whether or not
ksmbd currently supports it, so the fuzzer exercises the whole protocol surface.

Sources cross-referenced:
- **SMB2/SMB3 command set**: `linux/fs/smb/common/smb2pdu.h` (19 commands, `SMB2_*_HE`).
- **KSMBD impl**: `linux/fs/smb/server/smb2ops.c` dispatch table + `smb2pdu.c` handlers.
- **Samba client verbs**: `samba/source3/libsmb/cli_smb2_fnum.c` (`cli_smb2_*`) and
  `libsmbclient.h` (`smbc_*`) — the reference for what a client can drive.
- **Our grains**: `ksmbd/libksmbdzzer.c` GRAINS[] registry (**211 active**, `N_GRAINS`;
  `secdesc` suppressed).

Legend: ✅ grain exists · ⚠️ partial / only-as-preamble · ❌ no grain (TODO) ·
KSMBD col: ✅ implemented · ➖ not implemented (grain still worth it for robustness).

**How `grain/gen.py` runs these.** `generate_grains()` emits one LibFuzzer harness per
GRAINS[] entry; `run_grains()` fuzzes each on its own loopback IP, applies the **ALIGNED
gate** (`ALIGN_MIN_FT = 100` — a grain whose input never penetrates past the SMB parser
is flagged misaligned) and the **anti-monkey** `Δ = ft − ft0` PRODUCTIVE gate, fast-bails
grains that free-run without a session, and reports the deduplicated **fleet-union**
kernel-PC metric. `KSMBDZZER_ALIGNED=1` scopes a campaign to `grain/ALIGNED_SUBSET.txt`
(the grains here that reliably reach the kernel).

---

## 0. Verifying a grain works — `ksmbdzzer.py selftest` (via kcov-dataflow)

The whole map above is only worth its coverage if each grain **actually reaches ksmbd
kernel code**. A grain is a hand-built SMB PDU with a working auth→tree→open preamble; a
subtle field-offset slip, a wrong StructureSize, an early-reject dialect, or a torn-down
pool makes ksmbd drop the PDU *before* any handler runs — and it fuzzes nothing while
still burning campaign budget. `selftest` is the **"a grain must work"** gate that proves
each grain reaches the kernel, and it proves it by **measuring kcov-dataflow coverage**,
not by trusting the SMB reply.

### Why kcov-dataflow is what makes "does it reach ksmbd" measurable

An SMB response only tells you ksmbd *answered* — not how deep the PDU went (an error
reply is produced both by a rejected-at-dispatch PDU and by one that ran the full handler
and failed a check). kcov-dataflow closes that gap: it instruments ksmbd's kernel code, so
the count of coverage records a grain produces **is** the depth it reached. Zero records =
the PDU never entered a handler.

The bridge, per connection (see `[[ksmbd-remote-hooks-rebase-drop]]`):

1. On init each grain opens `/sys/kernel/debug/kcov_dataflow`, mmaps a per-worker buffer
   `g_df_buf`, and arms a **remote handle** `KSMBD_KCOV_DF_IP_HANDLE(octet)` keyed to its
   own loopback octet (`127.0.0.<octet>`).
2. ksmbd's `__handle_ksmbd_work()` wraps every request in
   `kcov_df_remote_start(conn->kcov_handle)` … `kcov_df_remote_stop()`
   (`fs/smb/server/server.c`), and `conn->kcov_handle` is set from the connection's dest
   IP octet in `transport_tcp.c`. So all kernel PCs (and, with `CONFIG_KCOV_DATAFLOW_ARGS/
   RET`, the folded trace-args/ret **values**) executed while servicing *that grain's*
   connection are routed into *that grain's* `g_df_buf`.
3. `pfz_grain_run(i, data, len)` resets coverage, self-bootstraps the pool, and runs
   `GRAINS[i].fn(data, len)` — which drives the SMB PDU to ksmbd over loopback.
4. `pfz_get_features(FEAT, N)` returns the number of distinct kernel-PC records now in the
   buffer. **`pcs > 0` ⇒ the PDU reached a ksmbd handler under `__handle_ksmbd_work`**;
   `pcs == 0` ⇒ it did not. The count doubles as the grain's **depth** (a ranking), which
   is why `WORKING_SUBSET.txt` is written coverage-descending.

### The four verdicts

Each grain is run `--repeats` times (default **4**) with a deterministic-but-varied 64-byte
seed per (grain, try); the MAX kernel-PC count over the tries is taken:

| Verdict | Condition | Meaning |
|---------|-----------|---------|
| **WORKS** | best pcs ≥ `--min-pcs` (default 1) | reached ksmbd kernel code — a real grain; `pcs` = its depth |
| **DEAD**  | ran (ret ≥ 0) but 0 kernel PCs | its PDU never reached a handler — cut or fix the grain |
| **BAIL**  | ret < 0 on every try | bailed at a prerequisite (no authed pool/fid, connect/auth/config failed) — it never executed |
| **EXCL**  | name ∈ `{ipc, rdma}` | *architectural* — cannot produce per-SMB-connection coverage here, but stays in the fleet for real gfuzz (see below) |

### Three subtleties that make the count ACCURATE (not the grains' fault)

`selftest` runs the whole fleet in ONE process (seconds-scale, no VM reboot, no LibFuzzer),
which is *not* how gfuzz runs them (a fresh process per grain). Three shared-process
artifacts once made honest grains look broken; all three are handled so the verdict
reflects the grain, not the harness:

1. **Async coverage-merge race → false DEAD.** ksmbd's `kcov_df_remote_stop()` merges into
   `g_df_buf` *after* the SMB response is sent, so a **single-op** grain (one CREATE/IOCTL/
   QUERY) can read the buffer *before* the merge lands and see 0. Fixed by `_cov()` in
   `cmd_selftest`, which polls `pfz_get_features` up to 6× at 3 ms (the read is idempotent /
   non-resetting) until non-zero. This is what made `create_ctx_dup`, `create_path_traversal`,
   `offload_read`, `query_network_openinfo`, `filename_null_embed`, `lease_parent_key` flap
   DEAD at low repeats — all reach ksmbd with pcs 2 000–8 000 once the merge is awaited.
2. **Conn-disrupting grains close the shared pool → false BAIL.** Grains that tear a
   connection down (`encrypt`, `session_setup`, `smb1_*`, `sign`, `logoff*`, `tdis*`) close
   the raw pool socket but leave `g_pool[].has_fid=1`, so `pool_ensure_fid` reuses the dead
   socket and every pool grain after them fails to write (-1). Per-grain re-auth is WRONG
   (210 back-to-back handshakes = a mountd auth **storm** that itself drops WORKS to 78).
   Fixed by an **on-bail heal**: only when a grain bails every repeat, `cmd_selftest` runs
   ONE `pfz_pool_init(2)` (fresh raw socket+fid) **and** `pfz_reopen_smb_fd()` (reopens just
   the libsmbclient scratch fd `g_smb_fd` that `rmxattr`/`setxattr`-family lib grains use —
   without a full `pfz_reconnect`, which would drop the kcov handle), then retries. This
   heals the pool for the FOLLOWING grains too, so re-auths ≈ #disruptors, not #grains.
3. **`ipc` / `rdma` are unmeasurable HERE, not broken → EXCL.** `ipc` drives SMBD_GENL
   *netlink* (`transport_ipc.c`), not an SMB connection, so the IP-handle remote hook never
   fires; `rdma` needs the RXE/SMBDirect **data-plane** the loopback selftest can't drive.
   Both still exercise ksmbd via those paths in a real gfuzz run, so they are reported EXCL,
   left OUT of the WORKS/DEAD verdict, and **kept in the `GRAINS[]` registry** (removing them
   would lose real coverage). This is deactivation from the *accounting*, not the map.

### Result (2026-07-22, kernel #119, full 210-grain fleet)

**208 WORKS / 0 DEAD / 0 BAIL / 2 EXCL** — 100 % of the measurable fleet reaches ksmbd.
Zero grains were removed or commented out; every prior "failure" was one of the three
artifacts above, proven by re-running the suspects at `--repeats 6/10` (all flipped to
WORKS). See `[[grain-selftest-and-kconfig]]`.

### Running it

- **Wrapper (recommended):** `verify_useful_grain.sh [REPEATS] [MIN_PCS]` — builds the
  `.so` (always; grain code lives there), boots ONE guest, runs `init` + `selftest`, and
  prints the WORKS/DEAD/BAIL/EXCL summary. It reuses the current bzImage by default;
  `REBUILD_KERNEL=1` forces a kernel rebuild (needed only after touching kernel/kcov code
  or the ksmbd remote hooks). `GRAIN_SUBSET="a b c"` scopes to specific grains.
  - Its KCONFIG **must match** `engine_compare_campagin.sh` (full SMB surface + RDMA/
    SMBDirect + Kerberos + **`CONFIG_UNICODE=y`** for the `utf8_casefold` path), or a
    feature-gated grain silently dead-ends and skews the verdict.
- **In-guest, directly:** `ksmbdzzer.py init && ksmbdzzer.py selftest [--repeats N]
  [--min-pcs P] [-t grain …]`.
- **Coverage-bridge guard:** if EVERY grain reads 0 (`DONE … 0 WORKS`), the *kernel* is
  coverage-blind — the ksmbd kcov remote hooks are missing (a rebase can leave them in an
  unpopped stash) or `CONFIG_KCOV_DATAFLOW` was dropped — **not** a fleet of dead grains.
  Both the script and `[[ksmbd-remote-hooks-rebase-drop]]` call this out; rebuild with the
  hooks present and confirm `fs/smb/server/server.c` has `kcov_df_remote_start`.

### Where selftest sits vs gen.py's ALIGNED gate vs engine_compare

- **`selftest`** — a *validity* filter: "does this grain reach the kernel *at all*?"
  Cheap (seconds), whole-fleet, run BEFORE a campaign. Writes `grain/WORKING_SUBSET.txt`.
- **gen.py ALIGNED gate** (`ALIGN_MIN_FT=100`) — a *depth/alignment* filter applied DURING
  a LibFuzzer campaign: fast-bails a grain whose input never penetrates past the SMB parser
  so it doesn't free-run and pollute the fleet-union metric.
- **`engine_compare_campagin.sh`** — the *coverage ablation* (dataflow-vec vs pc-i2s vs
  pc-havoc). `KSMBDZZER_ALIGNED=1` scopes it to `grain/ALIGNED_SUBSET.txt`, the curated
  subset that reaches the kernel *consistently across arms* so no grain biases one engine.
  `selftest` answers "is it a real grain"; the comparison answers "which coverage signal
  finds more with it".

---

## 1. Top-level SMB2/SMB3 commands (19)

| Op | Command | KSMBD handler | Samba client verb | Grain | Status |
|----|---------|---------------|-------------------|-------|--------|
| 0x00 | NEGOTIATE | ✅ smb2_negotiate_request | (protocol) | `negotiate` | ✅ |
| 0x01 | SESSION_SETUP | ✅ smb2_sess_setup | (protocol) | `session_setup` `session_bind` | ✅ (auth-blob + multichannel bind) |
| 0x02 | LOGOFF | ✅ smb2_session_logoff | — | `logoff` | ✅ (session teardown + fuzzed SessionId → re-auth cycle) |
| 0x03 | TREE_CONNECT | ✅ smb2_tree_connect | (tcon) | `tcon` (+ preamble) | ✅ (fuzzed UNC/share path) |
| 0x04 | TREE_DISCONNECT | ✅ smb2_tree_disconnect | — | `tdis` | ✅ (fuzzed TreeId) |
| 0x05 | CREATE | ✅ smb2_open | cli_smb2_create_fnum | `lease` `durable` `unicode` `mkrmdir` + preamble | ✅ (contexts partial, §4) |
| 0x06 | CLOSE | ✅ smb2_close | cli_smb2_close_fnum | `close` | ✅ (Flags/Reserved + post-close double-close UAF probe) |
| 0x07 | FLUSH | ✅ smb2_flush | — | `flush` | ✅ |
| 0x08 | READ | ✅ smb2_read | cli_smb2_read | `read` | ✅ (offset/len/channel fuzzed) |
| 0x09 | WRITE | ✅ smb2_write | cli_smb2_write / writeall | `write` `write_ext` | ✅ |
| 0x0A | LOCK | ✅ smb2_lock | — | `lock` (+ `race`) | ✅ (byte-range grain) |
| 0x0B | IOCTL (FSCTL) | ✅ smb2_ioctl | cli_smb2_fsctl | `copychunk` `compress` `reparse` `pipe` `ndr` `fsctl_zero` `fsctl_dupext` | ✅ (more FSCTLs in §2) |
| 0x0C | CANCEL | ✅ smb2_cancel | — | `cancel` | ✅ (fuzzed MID) |
| 0x0D | ECHO | ✅ smb2_echo | — | `echo` | ✅ |
| 0x0E | QUERY_DIRECTORY | ✅ smb2_query_dir | cli_smb2_list | `query_dir` | ✅ |
| 0x0F | CHANGE_NOTIFY | ✅ smb2_notify | cli_smb2_notify | `notify` | ✅ (fuzzed filter) |
| 0x10 | QUERY_INFO | ✅ smb2_query_info | cli_smb2_qpathinfo / query_info_fnum / query_mxac | `query_info` | ✅ (InfoType/class fuzzed) |
| 0x11 | SET_INFO | ✅ smb2_set_info | cli_smb2_set_info_fnum | `truncate` `setattr` `dosattr` `rename` `unlink` `setxattr` `rmxattr` | ✅ (classes partial, §3) |
| 0x12 | OPLOCK_BREAK | ✅ smb2_oplock_break | (server-initiated) | `oplock_ack` (deadlock found via oracle) | ✅ (client break-ack) |

**KSMBD implements all 19 SMB2 commands.** Grain coverage:
**19 of 19 commands have a DEDICATED grain** ✅ — CLOSE (`close`) and LOGOFF (`logoff`)
got their own grains 2026-07-07 (batch 9), so no command is preamble/oracle-only anymore.
**211 grains total** spanning all 19 commands, all 16 FSCTLs, 11 CREATE contexts, SMB3
encryption/multichannel/durable-v2/lease-v2, SMB1 legacy (generic + 5 per-opcode), and
(batches 10-15) 112 parser-depth/interaction/backlog grains that walk chain/array parsers the single-element
grains left at iteration count 1 — see §7.

---

## 2. IOCTL / FSCTL codes (KSMBD `smb2_ioctl`)

| FSCTL | KSMBD | Grain | Notes |
|-------|-------|-------|-------|
| FSCTL_SRV_COPYCHUNK / _WRITE | ✅ | `copychunk` | server-side copy (write-side) |
| FSCTL_SET_COMPRESSION / GET | ✅ | `compress` | compression transform |
| FSCTL_SET_REPARSE_POINT / GET | ✅ | `reparse` | reparse/symlink (write-side) |
| FSCTL_PIPE_TRANSCEIVE | ✅ | `pipe` `ndr` | named-pipe RPC |
| FSCTL_SET_SPARSE | ✅ | ✅ `fsctl_sparse` | sparse flag (write-side) |
| FSCTL_SET_ZERO_DATA | ✅ | ✅ `fsctl_zero` | hole-punch — hit vfs_fallocate |
| FSCTL_DUPLICATE_EXTENTS_TO_FILE | ✅ | ✅ `fsctl_dupext` | block clone (write-side) |
| FSCTL_SET_COMPRESSION | ✅ | ✅ `fsctl_setcomp` | compression state |
| FSCTL_QUERY_ALLOCATED_RANGES | ✅ | ✅ `fsctl_qar` | allocated-ranges query |
| FSCTL_VALIDATE_NEGOTIATE_INFO | ✅ | ✅ `fsctl_valneg` | downgrade attack (session-level) |
| FSCTL_SRV_COPYCHUNK | ✅ | ✅ `copychunk` | server-side copy |
| FSCTL_SRV_COPYCHUNK_WRITE | ✅ | ✅ `copychunk_write` | **write variant (audit gap)** |
| FSCTL_SRV_REQUEST_RESUME_KEY | ✅ | ✅ `resume_key` | resume key (audit gap) |
| FSCTL_DFS_GET_REFERRALS | ✅ | ✅ `fsctl_dfs` | DFS path parsing |
| FSCTL_DFS_GET_REFERRALS_EX | ✅ | ✅ `fsctl_dfs_ex` | DFS EX (audit gap) |
| FSCTL_GET_REPARSE_POINT | ✅ | ✅ `get_reparse` | read reparse (audit gap) |
| FSCTL_GET_COMPRESSION | ✅ | ✅ `get_compression` | (audit gap) |
| FSCTL_QUERY_NETWORK_INTERFACE_INFO | ✅ | ✅ `fsctl_netif` | multichannel discovery |
| FSCTL_CREATE_OR_GET_OBJECT_ID | ✅ | ✅ `fsctl_objid` | object id |
| FSCTL_OFFLOAD_WRITE / READ | ➖ (default-reject) | ✅ `offload_write`/`offload_read` | not in ksmbd switch → reject path |
| FSCTL_DELETE_REPARSE_POINT | ➖ (default-reject) | ✅ `del_reparse` | not in ksmbd switch → reject path |
| (any / unimplemented FSCTL) | ➖ default | ✅ `fsctl_sweep` | fuzz full ctl-code range → reject robustness |

---

## 3. SET_INFO file-info classes (KSMBD `smb2_set_info`)

| Class | KSMBD | Grain | Notes |
|-------|-------|-------|-------|
| FILE_END_OF_FILE_INFORMATION | ✅ | `truncate` | set EOF (write-side) |
| FILE_BASIC_INFORMATION | ✅ | `setattr` `dosattr` | times + DOS attrs |
| FILE_RENAME_INFORMATION | ✅ | `rename` | rename/traversal (write-side) |
| FILE_DISPOSITION_INFORMATION | ✅ | `unlink` `mkrmdir` | delete-on-close (write-side) |
| FILE_FULL_EA_INFORMATION | ✅ | `setxattr` `rmxattr` | EA add/remove |
| FILE_ALLOCATION_INFORMATION | ✅ | ✅ `set_alloc` | set alloc size (write-side) |
| FILE_LINK_INFORMATION | ✅ | ✅ `hardlink` | hardlink (write-side, traversal) |
| FILE_END_OF_FILE_INFORMATION (20) | ✅ | ✅ `set_eof` (+`truncate`) | raw set-EOF boundary |
| FILE_VALID_DATA_LENGTH_INFORMATION (39) | ✅ | ✅ `set_valid_data` | **SetValidData — uninitialized-disk-data disclosure** |
| FILE_POSITION_INFORMATION (14) | ✅ | ✅ `set_position` | file position |
| FILE_MODE_INFORMATION (16) | ✅ | ✅ `set_mode` | mode flags |
| FILE_DISPOSITION_INFORMATION (13) | ✅ | ✅ `set_disposition` (+`unlink`) | raw delete-pending |
| FILE_FULL_EA_INFORMATION (15) | ✅ | ✅ `set_full_ea` (+`setxattr`) | raw EA-list parser |
| SET_INFO InfoType=SECURITY (0x03) | ✅ smb2_set_info_sec | ✅ `set_secinfo` (+`create_sd`) | **ACL write via SET_INFO — audit gap, the write-side ACL path** |
| (any / unimplemented FILE info class) | ➖ default | ✅ `setinfo_sweep` | fuzz full class range → reject robustness |

---

## 4. CREATE contexts (KSMBD `smb2_open`)

| Context | KSMBD | Grain | Notes |
|---------|-------|-------|-------|
| RqLs (lease) | ✅ | `lease` | lease request/state |
| DHnQ / DH2Q (durable) | ✅ | `durable` | durable/persistent handle |
| SMB2_CREATE_EA_BUFFER (ExtA) | ✅ | ✅ `create_ea` | EA-on-create |
| SMB2_CREATE_SD_BUFFER (SecD) | ✅ | ✅ `create_sd` | **reaches parse_sec_desc (ACL NDR) — the write-side ACL surface** |
| SMB2_CREATE_QUERY_MAXIMAL_ACCESS (MxAc) | ✅ | ✅ `create_mxac` | maximal-access query |
| SMB2_CREATE_ALLOCATION_SIZE (AlSi) | ✅ | ✅ `create_alsi` | allocation-size on create |
| SMB2_CREATE_QUERY_ON_DISK_ID (QFid) | ✅ | ✅ `create_qfid` | on-disk id |
| SMB2_CREATE_TAG_POSIX | ✅ | ✅ `create_posix` | POSIX extensions (16-byte GUID tag) |
| SMB2_CREATE_APP_INSTANCE_ID | ✅ | ❌ | TODO — failover |
| SMB2_CREATE_AAPL | ✅ | ❌ | TODO — Apple ext |
| (unicode path) | — | `unicode` | path-name fuzzing |

---

## 5. SMB3 features / transport

| Feature | KSMBD | Grain | Notes |
|---------|-------|-------|-------|
| SMBDirect (RDMA) | ✅ | `rdma` | fixed 2026-07-05 (port 445/5445 auto) |
| Compound requests | ✅ | `compound` `sequence` | chained ops in one PDU |
| Compression transform (0xFC'SMB') | ✅ | `compress_transform` | MS-SMB2 3.1.5.3 chained decompress (bomb/overflow) |
| Shadow copy / VSS | ➖ | `shadow_copy` | FSCTL_SRV_ENUMERATE_SNAPSHOTS (Samba cli verb) |
| Resilient handles | ➖ | `resiliency` | FSCTL_LMR_REQUEST_RESILIENCY |
| Quota (set) | ➖ | `set_quota` | SET_INFO InfoType=QUOTA (Samba set_user_quota) |
| Quota (query) | ➖ | ✅ `get_quota` | QUERY_INFO InfoType=QUOTA + real SMB2_QUERY_QUOTA_INFO input (Samba get_user_quota) |
| Integrity (ReFS) | ➖ | `set_integrity` | FSCTL_SET_INTEGRITY_INFORMATION |
| Named-pipe wait | ✅ | `pipe_wait` | FSCTL_PIPE_WAIT |
| Multichannel (session bind) | ✅ | ✅ `session_bind` | 2nd-channel SESSION_SETUP bind |
| SMB3 encryption (transform) | ✅ (cfg now `enabled`) | ✅ `encrypt` | fuzzed transform hdr → decrypt path |
| Leases v2 / directory leases | ✅ | `lease` (v1) `lease_v2` | v2 epoch/ParentLeaseKey |
| Persistent handles (CA) | ✅ | `durable` `create_dh2` `dh2c` | v2 request + reconnect |
| Witness (RPC) | ➖ | `ndr` `pipe` (generic) | TODO — witness ops |
| Auth surface | ✅ | `session_setup` | fuzz SPNEGO/NTLMSSP blob |
| Oplock break ack | ✅ | `oplock_ack` | client break-ack |
| Concurrency / races | — | `race` | parallel write/lock |

---

## 6. SMB1 (downgrade / compat)

`fs/smb/common/smb1pdu.h` exists — ksmbd handles **SMB1 NEGOTIATE** only, to downgrade
a legacy client to SMB2. Grain `smb1` (✅ added 2026-07-05) sends an SMB1 PDU (`\xffSMB`
+ fuzzed command byte: SMBopen/SMBwrite/SMBtrans/SMBtconX/…) over an authed SMB2 socket
to hit ksmbd's legacy/version-conflict handling — the "old protocol meets new server"
attack surface. TODO: split into per-opcode variants (see §8).

---

## 7. Current grains (211 in source + 1 suppressed; selftest: 208 WORKS / 2 EXCL, see §0)

Batch 15 (2026-07-22, the THIRD 32-grain backlog, groups M-R; N_GRAINS 179→211, source-only
UNBUILT, `gcc -fsyntax-only` clean). M crypto/signing (5): encrypt_then_compound,
sign_compound_mixed, encrypt_wrong_session, gss_mechlist_mic, negotiate_signing_ctx. N durable/
lease/oplock (6): lease_upgrade_downgrade, durable_v1_v2_mix, oplock_level2_break,
lease_parent_key, durable_timeout_zero, persistent_handle_ca. O vfs/path/xattr (6):
xattr_name_max, filename_null_embed, filename_max_path, stream_delete, hardlink_cross_share,
casefold_share_name. P data-path (5): copychunk_self, write_sparse_hole, read_compound_close,
set_eof_shrink_race, append_past_max. Q info edges (5): query_full_ea_size, set_rename_stream,
query_dir_short_buf, set_disposition_dir, query_attr_tag_reparse. R conn lifecycle (5):
tcon_max_trees, session_max_opens, conn_negotiate_twice, session_setup_no_negotiate,
interim_response_flood. FLEET_EST bumped 112→211 in engine_compare_campagin.sh.

Batch 14 (2026-07-22, the SECOND 32-grain backlog; N_GRAINS 147→179, source-only UNBUILT,
`gcc -fsyntax-only` clean). F create/ctx (6): create_ctx_dup, create_ctx_giant_data,
create_twrp, create_alloc_vs_eof, create_disposition_matrix, create_impersonation. G rd/wr
edge (5): write_compound_flush, read_padding_edge, write_zero_length, write_rdma_channel,
read_beyond_eof. H lock (3): lock_unlock_mismatch, lock_shared_excl_conflict, lock_reflexive.
I session/auth (4): session_reauth_switch, guest_anon_auth, logoff_reuse_sid, tcon_ipc_vs_disk.
J info-class (5): query_all_info, set_basic_time_edge, query_stream_info, set_pipe_info,
query_network_openinfo. K transport (4): pipelined_requests, oversize_pdu, partial_pdu_dribble,
compound_padding. L more FSCTLs (5): fsctl_set_object_id, fsctl_lmr_set_link,
fsctl_query_file_regions, fsctl_duplicate_extents_v2, fsctl_offload_read_token.

Batch 13 (2026-07-22, the 32-grain backlog; N_GRAINS 115→147, source-only UNBUILT, all
`gcc -fsyntax-only` clean). A chain/array (7): create_dh2q_internals, notify_output_walk,
query_dir_resume, set_ea_private, ioctl_inout_overlap, sd_owner_group, sd_sacl. B state/
concurrency (9, SINGLE-THREADED directed sequences — reach teardown/lifetime paths, don't
truly interleave; socket-raw grains restore via pool_reconnect): durable_reconnect_race,
lease_break_ack_mismatch, oplock_break_race, logoff_inflight, tdis_open_fid,
close_durable_scavenger, cancel_async_target, credit_exhaust, compound_unrelated_session.
C crypto (5): transform_nested, compress_bomb, sign_downgrade, preauth_hash_mismatch,
multichannel_bind_replay. D path/name (4): create_path_traversal, stream_name_edge,
unicode_surrogate, rename_target_edge. E fsctl/info (7): pipe_transceive_bind,
set_integrity_deep, query_fs_info, smb1_dialects, fsctl_reparse_get_chain,
query_info_ea_list, set_link_root.

Batch 12 (2026-07-22, interaction + protocol-parse depth; N_GRAINS 110→115, source-only
UNBUILT): `compound_related_fid` (RELATED compound CREATE→WRITE→CLOSE on the inherited fid —
cross-op state resolution, deeper than compound_chain's ECHOs), `reparse_symlink`
(FSCTL_SET_REPARSE_POINT symlink buffer SubstituteName/PrintName off+len), `dfs_referral_ex`
(FSCTL_DFS_GET_REFERRALS_EX structured request), `negotiate_dialects` (DialectCount 2-31 fuzzed
dialect array — negotiate_ctx_multi pins DialectCount=1), `spnego_asn1` (SESSION_SETUP
SPNEGO/DER blob with fuzzed TLV lengths → ASN.1/GSS-API parse). All `gcc -fsyntax-only` clean.

Batch 11 (2026-07-22, parser-DEPTH cont. — five more chain/array-walk grains; N_GRAINS
105→110, source-only UNBUILT):
- `lock_array` — SMB2 LOCK with LockCount 2-8 + independently-fuzzed element array →
  `smb2_lock()` `for (i<lock_count)` walk (smb2pdu.c:8249; find.md #1 surface). grain_lock=1.
- `create_ctx_chain` — CREATE with 2-4 Next-linked create contexts (fuzzed Next) →
  `smb2_open` context array walk (smb2_find_context_vals). pool_create_with_ctx sends Next=0.
- `copychunk_multi` — FSCTL_SRV_COPYCHUNK (0x1440F2, correct code) with ChunkCount 2-8 +
  independently-fuzzed per-chunk Source/TargetOffset/Length → fsctl_copychunk chunk-array
  walk. pfz_copychunk used linear chunks + a WRONG ctl code (0x1480044).
- `quota_chain` — QUERY_INFO QUOTA with a chained FILE_GET_QUOTA_INFORMATION SID list
  (NextEntryOffset) → the multi-entry SID-list walk get_quota's flat blob misses.
- `rdma_channel_desc` — SMB2 READ with Channel=RDMA_V1 + fuzzed buffer_descriptor_v1 array →
  channel-info parse/validation. NOTE over loopback TCP ksmbd rejects RDMA channels before
  deep descriptor consume (full path needs the RDMA transport / `rdma` grain).

Batch 10 (2026-07-22, parser-DEPTH — six grains that exercise chain/array parser LOOPS the
existing single-element grains left at iteration count 1; each verified against both the
KSMBD parser and the grain that was supposed to hit it). Source-only until next `.so` build.
Registry = 105.
- `set_ea_chain` — multi-entry FILE_FULL_EA list with fuzzed `NextEntryOffset` → the
  `smb2_set_ea()` do/while chain-walk (set_full_ea/create_ea hardcode NextEntryOffset=0).
- `negotiate_ctx_multi` — NEGOTIATE with `NegotiateContextCount` 2-6 + N fuzzed contexts →
  `deassemble_neg_contexts()` array walk + the 2nd..Nth sub-decoders (preauth SaltLength/
  HashAlgorithmCount, compress/encrypt counts); throwaway conn (pfz_negotiate_contexts pinned count=1).
- `compound_chain` — structured 2-4 command compound linked by fuzzed `NextCommand` +
  mid-chain SessionId/TreeId (RELATED_OPERATIONS) → `__handle_ksmbd_work()` is_chained loop +
  credit/tcon accounting (pfz_compound only sprayed raw bytes).
- `ndr_xattr` — SET fuzzed SD then QUERY it back → `ndr_decode_v4_ntacl()` on the stored
  security.NTACL blob (indirect control, but the decode size-math executes).
- `dir_pattern` — QUERY_DIRECTORY on a directory handle with a wildcard-dense search pattern →
  misc.c `match_pattern()` backtracker (pfz_query_dir lists a subpath, never sends a pattern).
- `transport_frame` — fuzz the RFC1001/NetBIOS 4-byte length prefix (type byte + length that
  mismatches the payload) → connection read-assembly / length validation; throwaway conn.

Batch 9 (2026-07-07, LAST-command completion — the 2 SMB2 commands that had only a
preamble/oracle grain now have DEDICATED grains): `close` (SMB2 CLOSE 0x06 — Flags/
Reserved fuzz + a data-gated post-close DOUBLE-CLOSE on the stale FileId = use-after-
close probe) and `logoff` (SMB2 LOGOFF 0x02 — session teardown, optionally against a
fuzzed SessionId, then forces pool re-auth = session-object lifetime surface). Now
19/19 commands are dedicated grains, not preamble-only. Plus `get_quota` (QUERY_INFO
InfoType=QUOTA, Samba cli_smb2_get_user_quota) — builds a real fuzzed SMB2_QUERY_QUOTA_INFO
input so ksmbd's quota-query path is actually walked (the generic `query_info` grain sends
no input buffer, so its InfoType=QUOTA is rejected before the parser). Registry = 99.
Source-only until next `.so` build. Verified vs Samba cli_smb2_* + kernel neg-context
defines: SMB3.1.1 NEGOTIATE contexts (preauth/encryption/compression/signing/RDMA-transform
caps, dialect 0x0311) are ALREADY covered by grain_negotiate → pfz_negotiate_contexts.

Batch 8 (2026-07-05, BLIND-SPOT grains — reach ksmbd subsystems no SMB grain touched;
see findings/COVERAGE-blindspots.md): `ipc` (SMBD_GENL netlink → transport_ipc.c,
non-SMB), `dacl_deep` (multi-ACE SD → smbacl.c parse_dacl), `sign` (signed msg →
crypto_ctx signing; needs `server signing = auto`), `rpc_opnum` (DCE/RPC fuzzed opnum →
ndr.c). Source-only until next build (running campaign predates them).


Batch 7 (2026-07-05, SMB3-standard procedures missing vs Samba — even ones ksmbd may
reject; source-only, running campaign has 68): `compress_transform` (0xFC'SMB' chained
decompress), `shadow_copy` (VSS), `set_integrity` (ReFS), `pipe_wait`, `resiliency`
(resilient handle), `set_quota` (InfoType=QUOTA). Cross-checked vs Samba cli_smb2_* and
fs/smb SMB3 transform defines.


Batch 6 (2026-07-05, OMISSION AUDIT — diffed ksmbd's handler switches vs grains;
source-only, running campaign has 68): `set_secinfo` (**SET_INFO SECURITY = write-side
ACL, the big miss**), `copychunk_write` (SRV_COPYCHUNK_WRITE), `resume_key`,
`fsctl_dfs_ex`, `get_reparse`, `get_compression`, and full-range sweeps `fsctl_sweep`
(any FSCTL) + `setinfo_sweep` (any info class) for the unimplemented-op reject paths.
Audit result: every FSCTL case + SET_INFO InfoType in ksmbd is now grained.


Batch 5 (2026-07-05, write-side depth — storage-server threat model, source-only until
next build; the running 30-round campaign has 68): `set_valid_data` (SetValidData —
uninitialized-data disclosure), `set_eof`, `set_position`, `set_mode`,
`set_disposition`, `set_full_ea`, `offload_write`, `offload_read`, `del_reparse`.


Batch 3 (2026-07-05): `tcon` (TREE_CONNECT path-fuzz), `create_aapl`, `create_appinst`,
`create_dh2` (durable-v2), and **write-side focus** `stream_write` (alternate data
streams → streams_xattr), `write_flags` (WRITETHROUGH/UNBUFFERED), `append` (EOF-grow).

Batch 4 (2026-07-05, §8 remainder — required cfg change `smb3 encryption = enabled`):
`encrypt` (transform/decrypt), `session_bind` (multichannel), `lease_v2`, `dh2c`
(durable reconnect), `oplock_ack`, `session_setup` (auth-fuzz), and per-opcode legacy
`smb1_tconx` `smb1_ntcreate` `smb1_trans` `smb1_open` `smb1_write`. NOTE: encrypt /
session_setup / smb1_* can tear down the shared pool connection (they send session/
protocol-level messages), so they reach ksmbd but may leave the conn for re-auth.


Original 24: `write, write_ext, truncate, setxattr, rmxattr, setattr, dosattr, rename,
unlink, mkrmdir, copychunk, compress, reparse, query_dir, ndr, pipe, negotiate, lease,
durable, race, sequence, compound, unicode, rdma`.

**Added 2026-07-05 (GRAIN.md gap grains, all verified reaching ksmbd):**
- Commands: `read`, `lock`, `flush`, `echo`, `cancel`, `query_info`, `notify`, `tdis`.
- Write-side sub-ops: `fsctl_zero` (SET_ZERO_DATA→vfs_fallocate), `fsctl_dupext`
  (DUPLICATE_EXTENTS), `set_alloc` (ALLOCATION_INFO), `hardlink` (LINK_INFO).
- CREATE contexts: `create_ea` `create_sd` (**→parse_sec_desc, ACL NDR**) `create_mxac`
  `create_alsi` `create_qfid` `create_posix`.
- FSCTLs: `fsctl_sparse` `fsctl_qar` `fsctl_setcomp` `fsctl_objid` `fsctl_valneg`
  (downgrade) `fsctl_dfs` (DFS path) `fsctl_netif`.
- Legacy: `smb1` (SMB1 command over SMB2 session = version-conflict).
Built on pool_ensure_fid()/pool_ioctl()/pool_create_with_ctx() working-preambles;
pool-fid gap #40 fixed (pool_create_file now checks NTSTATUS).

Suppressed: `secdesc` (needs aclshare, #42). Known dead/underperforming:
`compress`, `copychunk`, `reparse` (early-reject #41 / were pool-fid-blocked, now #40 fixed).

---

## 8. Gaps — implemented vs remaining (the "whole procedure" goal)

**DONE 2026-07-05 (13 grains, verified reaching ksmbd):**
- ✅ `fsctl_zero` — FSCTL_SET_ZERO_DATA (hit vfs_fallocate)
- ✅ `fsctl_dupext` — FSCTL_DUPLICATE_EXTENTS_TO_FILE
- ✅ `set_alloc` — SET_INFO FILE_ALLOCATION_INFORMATION
- ✅ `hardlink` — SET_INFO FILE_LINK_INFORMATION
- ✅ `read` (0x08), `lock` (0x0A), `flush` (0x07), `echo` (0x0D), `cancel` (0x0C)
- ✅ `query_info` (0x10), `notify` / CHANGE_NOTIFY (0x0F), `tdis` / TREE_DISCONNECT (0x04)
- ✅ `smb1` — legacy SMB1 command over an SMB2 session (version-conflict surface)

**DONE 2026-07-05 (batch 2, 13 grains, verified):** `create_ea` `create_sd`
(→parse_sec_desc, ACL) `create_mxac` `create_alsi` `create_qfid` `create_posix` +
`fsctl_sparse` `fsctl_qar` `fsctl_setcomp` `fsctl_objid` `fsctl_valneg` `fsctl_dfs`
`fsctl_netif`. NOTE: `create_sd` reaches the ACL NDR parser on [share], so it covers
the ACL write-side surface that `secdesc`/#42 (aclshare) could not.

**DONE 2026-07-05 (batch 3):** `tcon` (TREE_CONNECT path-fuzz), `create_aapl`,
`create_appinst`, `create_dh2` (durable-v2), + write-side `stream_write` (ADS),
`write_flags`, `append`.

**DONE 2026-07-05 (batch 4, §8 remainder — cfg: `smb3 encryption = enabled`):**
`encrypt` (transform→"Transform message too small"), `session_bind` (multichannel),
`lease_v2`, `dh2c` (durable reconnect), `oplock_ack`, `session_setup` (auth-fuzz→
"Unknown NTLMSSP message type"), `smb1_tconx/ntcreate/trans/open/write` (per-opcode legacy).

**REMAINING (small / genuinely lower-value):**
- `dir_lease` (directory-lease epoch — subset of lease_v2)
- Witness protocol RPC ops (covered generically by `ndr`/`pipe`)
- FSCTL_GET_* read-side (get_compression/get_reparse/get_object_id) — low priority
- Robustness: give conn-disrupting grains (encrypt/session_setup/smb1_*) their own
  throwaway connection so they don't leave the shared pool for re-auth.

**More write-side depth (storage-server focus) — candidates:**
- interleaved write+set-EOF+set-alloc chains (via `compound`); stream rename/delete;
  large chunked-upload via `copychunk`+`append`; `write_flags` × sparse combos.

### First 32-candidate backlog — IMPLEMENTED as batch 13 (2026-07-22)

The 32 candidates below (groups A-E) were all implemented in batch 13. Kept for reference.

*Chain/array/nested parse (7):* `create_dh2q_internals` (DH2Q durable-v2 ctx +DH2C match),
`notify_output_walk` (FILE_NOTIFY_INFORMATION out-walk + filter/OutputBufferLength),
`query_dir_resume` (INDEX_SPECIFIED+FileIndex+resume name), `set_ea_private`
(smb2_is_private_ea names: security.*/DOSATTRIB/streams), `ioctl_inout_overlap`
(Input/Output offset overlap → buffer_check_err), `sd_owner_group` (parse_sec_desc
Owner/Group SID), `sd_sacl` (SACL_SECURITY_INFORMATION audit ACL).

*State/lifetime/concurrency (9):* `durable_reconnect_race` (DH2C reclaim/scavenger),
`lease_break_ack_mismatch` (mismatched LeaseKey/state), `oplock_break_race` (directed
oplock-deadlock repro), `logoff_inflight` (LOGOFF vs inflight LOCK/notify),
`tdis_open_fid` (TREE_DISCONNECT w/ live fids), `close_durable_scavenger`,
`cancel_async_target` (CANCEL inflight async by MID), `credit_exhaust` (CreditRequest=0/
large CreditCharge), `compound_unrelated_session` (per-cmd SessionId/TreeId).

*Crypto/transform/signing (5):* `transform_nested` (OriginalMessageSize mismatch +
double-wrap decrypt), `compress_bomb` (chained-decompress loop), `sign_downgrade`
(signing-algo/context mismatch → check_sign_req), `preauth_hash_mismatch` (SMB3.1.1
preauth integrity), `multichannel_bind_replay` (channel-bind replayed session key).

*Path/name/unicode (4):* `create_path_traversal` (`..\`/`\\`/`:`/long UTF-16 →
validate_filename), `stream_name_edge` (parse_stream_name `::$DATA`/multi-colon),
`unicode_surrogate` (utf8_casefold non-BMP/invalid surrogate), `rename_target_edge`
(RootDirectory fid + traversal + ReplaceIfExists).

*FSCTL/info-class/legacy breadth (7):* `pipe_transceive_bind` (DCE/RPC bind ctx-list +
opnum), `set_integrity_deep` (FSCTL_SET_INTEGRITY ChecksumAlgorithm/Flags),
`query_fs_info` (FILESYSTEM class sweep), `smb1_dialects` (SMB1 NEGOTIATE DialectsArray),
`fsctl_reparse_get_chain` (GET_REPARSE_POINT output bounds), `query_info_ea_list`
(chained FILE_GET_EA_INFORMATION query walk), `set_link_root` (FILE_LINK/RENAME w/
RootDirectory fid relative-path resolution).

### Second 32-candidate backlog — IMPLEMENTED as batch 14 (2026-07-22)

The 32 candidates below (groups F-L) were all implemented in batch 14. Kept for reference.

*F. CREATE / context combinations (6):* `create_ctx_dup` (duplicate same-type contexts →
dedup/last-wins), `create_ctx_giant_data` (context DataLength ≫ buffer), `create_twrp`
(TWrp @GMT timewarp token parse), `create_alloc_vs_eof` (AllocationSize ctx + immediate
set-EOF conflict), `create_disposition_matrix` (all Disposition × Options combos),
`create_impersonation` (SecurityFlags/ImpersonationLevel + oplock-level matrix).

*G. Read/Write edge & channel (5):* `write_compound_flush` (WRITE→FLUSH→WRITE ordering),
`read_padding_edge` (Padding/MinimumCount vs Length), `write_zero_length` (Length=0 +
non-zero DataOffset), `write_rdma_channel` (WRITE Channel=RDMA_V1 WriteChannelInfo — write
side of rdma_channel_desc), `read_beyond_eof` (Offset+Length past EOF / overflow).

*H. Lock semantics (3):* `lock_unlock_mismatch` (UNLOCK never-locked range /
LockSequenceNumber mismatch), `lock_shared_excl_conflict` (overlapping SHARED then EXCL
across 2 conns), `lock_reflexive` (re-LOCK identical range).

*I. Session/auth state (4):* `session_reauth_switch` (re-auth existing session as different
user), `guest_anon_auth` (empty NTLMSSP guest/anon path), `logoff_reuse_sid` (reuse stale
SessionId post-LOGOFF), `tcon_ipc_vs_disk` (disk op on an IPC$ tid — tree-type confusion).

*J. Info-class depth (5):* `query_all_info` (FILE_ALL_INFORMATION aggregate → many
sub-encoders), `set_basic_time_edge` (extreme/negative NT times → ksmbd_NTtimeToUnix
overflow), `query_stream_info` (FILE_STREAM_INFORMATION enumeration walk), `set_pipe_info`
(SET_INFO on an IPC pipe fid), `query_network_openinfo` (FILE_NETWORK_OPEN/INTERNAL edge).

*K. Transport/framing/compound edge (4):* `pipelined_requests` (many requests, no reads →
queue depth), `oversize_pdu` (PDU near/over max_read/write/trans), `partial_pdu_dribble`
(one byte at a time → read-loop assembly), `compound_padding` (NextCommand > sub-cmd length).

*L. FSCTL breadth not yet grained (5):* `fsctl_set_object_id` (SET_OBJECT_ID),
`fsctl_lmr_set_link` (LMR_SET_LINK_TRACKING_INFORMATION), `fsctl_query_file_regions`
(QUERY_FILE_REGIONS), `fsctl_duplicate_extents_v2` (DUPLICATE_EXTENTS_TO_FILE_EX v2),
`fsctl_offload_read_token` (OFFLOAD_READ → token → OFFLOAD_WRITE token round-trip).

### Third 32-candidate backlog — IMPLEMENTED as batch 15 (2026-07-22, groups M-R)

Identified after batch 14 (179 grains). Deeper sequences / ksmbd-subsystem edges. Not yet
implemented. Diminishing returns beyond here — prioritize N (durable/lease/oplock state) and
R (lifecycle exhaustion), historically the bug-rich areas.

*M. Encryption/signing deep (5):* `encrypt_then_compound` (decrypt→compound parse),
`sign_compound_mixed` (per-cmd signed/unsigned in one chain), `encrypt_wrong_session`
(transform SessionId ≠ key), `gss_mechlist_mic` (SPNEGO mechListMIC), `negotiate_signing_ctx`
(SIGNING_CAPABILITIES SigningAlgorithmCount array).

*N. Durable/lease/oplock state machine (6):* `lease_upgrade_downgrade` (RWH→R transition),
`durable_v1_v2_mix` (DHnQ create + DH2C reconnect), `oplock_level2_break` (lev-II break
sequence — the deadlock class path), `lease_parent_key` (lease-v2 ParentLeaseKey to
nonexistent parent), `durable_timeout_zero` (Timeout=0 default path + reconnect),
`persistent_handle_ca` (PERSISTENT flag on a non-CA share → reject).

*O. VFS/path/xattr edges (6):* `xattr_name_max` (EA name at XATTR_NAME_MAX boundary),
`filename_null_embed` (embedded UTF-16 NUL), `filename_max_path` (PATH_MAX/component-max),
`stream_delete` (open stream → delete-on-close streams_xattr), `hardlink_cross_share`
(FILE_LINK target escaping the share), `casefold_share_name` (ksmbd_casefold_sharename edges).

*P. Read/write/copy data-path (5):* `copychunk_self` (src==tgt overlapping ranges),
`write_sparse_hole` (write across sparse holes), `read_compound_close` (READ→CLOSE chain on
one fid), `set_eof_shrink_race` (truncate vs pending read), `append_past_max` (append past
smb2_max_write).

*Q. Info-class/query edges (5):* `query_full_ea_size` (tiny OutputBufferLength EA truncation),
`set_rename_stream` (FILE_RENAME on a stream), `query_dir_short_buf` (OutputBufferLength < one
entry), `set_disposition_dir` (delete-on-close on non-empty dir), `query_attr_tag_reparse`
(FILE_ATTRIBUTE_TAG on a reparse point).

*R. Session/tree/conn lifecycle (5):* `tcon_max_trees` (tree-table exhaustion),
`session_max_opens` (open-file-table exhaustion), `conn_negotiate_twice` (re-NEGOTIATE state),
`session_setup_no_negotiate` (out-of-order state), `interim_response_flood` (async
interim-response allocation churn).

Grain-authoring principle (memory `ksmbdzzer-architecture-principles`): each grain =
a **working** preamble (auth → tree → open → real fid) with only the **last** endpoint
fuzzed; duplicated preambles across grains are expected and fine.
