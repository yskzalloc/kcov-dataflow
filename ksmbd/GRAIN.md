# ksmbdzzer Grain Coverage Map

Goal: a grain for **every SMB2/SMB3 procedure** (and sub-operation), whether or not
ksmbd currently supports it, so the fuzzer exercises the whole protocol surface.

Sources cross-referenced:
- **SMB2/SMB3 command set**: `linux/fs/smb/common/smb2pdu.h` (19 commands, `SMB2_*_HE`).
- **KSMBD impl**: `linux/fs/smb/server/smb2ops.c` dispatch table + `smb2pdu.c` handlers.
- **Samba client verbs**: `samba/source3/libsmb/cli_smb2_fnum.c` (`cli_smb2_*`) and
  `libsmbclient.h` (`smbc_*`) — the reference for what a client can drive.
- **Our grains**: `ksmbd/libksmbdzzer.c` GRAINS[] registry (24 active + 1 suppressed).

Legend: ✅ grain exists · ⚠️ partial / only-as-preamble · ❌ no grain (TODO) ·
KSMBD col: ✅ implemented · ➖ not implemented (grain still worth it for robustness).

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
98 grains total spanning all 19 commands, all 16 FSCTLs, 11 CREATE contexts, SMB3
encryption/multichannel/durable-v2/lease-v2, and SMB1 legacy (generic + 5 per-opcode).

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

## 7. Current grains (95 in source + 1 suppressed)

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

Grain-authoring principle (memory `ksmbdzzer-architecture-principles`): each grain =
a **working** preamble (auth → tree → open → real fid) with only the **last** endpoint
fuzzed; duplicated preambles across grains are expected and fine.
