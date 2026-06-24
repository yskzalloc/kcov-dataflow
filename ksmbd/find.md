# ksmbdzzer Findings

## Finding 1: Exclusive Lock Without Write Access (MS-SMB2 Spec Violation)

**Status:** Confirmed on mainline 7.1-rc7 (unfixed)  
**Severity:** Medium (DoS via lock poisoning)  
**Spec Reference:** MS-SMB2 3.3.5.14

### Description

`smb2_lock()` in `fs/smb/server/smb2pdu.c` grants exclusive byte-range locks without verifying the file handle has `FILE_WRITE_DATA` access. Per MS-SMB2 section 3.3.5.14, the server SHOULD verify the handle's granted access before allowing exclusive locks.

### Impact

An authenticated user with only READ access to a file can take an exclusive lock on any byte range, preventing all other sessions from writing to that range. This enables:
- **DoS**: Lock any readable file → block all writers
- **Lock poisoning**: Prevent legitimate operations on shared files

### Reproduction

```python
# Connect to [privtest] share (respects DesiredAccess, no force user)
t = TreeConnect(s, r"\\127.0.0.1\privtest")

# Open file with READ-ONLY (no FILE_WRITE_DATA)
o.create(0, FILE_READ_DATA | FILE_READ_ATTRIBUTES, ...)

# Take exclusive lock — SUCCEEDS (should fail per spec)
lock = SMB2LockElement(offset=0, length=4096, flags=EXCLUSIVE|FAIL_IMMEDIATELY)
o.lock([lock])  # Returns STATUS_SUCCESS!

# Meanwhile: WRITE correctly denied (ACCESS_DENIED) — so daccess IS enforced for writes
# And: SHARED lock correctly allowed — so lock infrastructure works
# Only EXCLUSIVE lock is missing the check
```

**Confirmed on [privtest] share** (no force user, proper `fuzz:fuzz` auth, DesiredAccess respected).

### Suggested Fix

```c
// In smb2_lock(), before processing lock elements:
if (lock_flags & SMB2_LOCKFLAG_EXCLUSIVE_LOCK) {
    if (!(fp->daccess & (FILE_WRITE_DATA_LE | FILE_APPEND_DATA_LE))) {
        pr_err("Exclusive lock requires write access\n");
        return -EACCES;
    }
}
```

### How Found

1. Code audit: identified `smb2_lock()` has zero `fp->daccess` checks
2. `sniper_priv_bypass` (case 6): opens READ-ONLY, sends EXCLUSIVE LOCK
3. Manual confirmation via smbprotocol with proper authentication

---

## Finding 2: FILE_DELETE_ON_CLOSE Without DELETE Access (MS-SMB2 Spec Violation)

**Status:** Confirmed on mainline 7.1-rc7 (unfixed)  
**Severity:** High (unauthorized file deletion)  
**Spec Reference:** MS-SMB2 3.3.5.9

### Description

ksmbd allows `CreateOptions = FILE_DELETE_ON_CLOSE` to succeed even when `DesiredAccess` does not include `FILE_DELETE`. Per MS-SMB2 section 3.3.5.9, the server MUST verify that the granted access includes DELETE before allowing DELETE_ON_CLOSE.

### Impact

An authenticated user with only READ access can delete any file they can open by specifying `FILE_DELETE_ON_CLOSE` in CreateOptions. When the handle is closed, the file is permanently deleted.

- **Data destruction**: Any readable file can be deleted without DELETE permission
- **Privilege escalation path**: Delete critical files (configs, locks) to disrupt services

### Reproduction

```python
# Connect to [privtest] share (respects DesiredAccess)
t = TreeConnect(s, r"\\127.0.0.1\privtest")

# Open with READ-ONLY + DELETE_ON_CLOSE (no FILE_DELETE in DesiredAccess)
o.create(0, FILE_READ_DATA | FILE_READ_ATTRIBUTES,  # NO DELETE!
         FILE_ATTRIBUTE_NORMAL, SHARE_ALL, FILE_OPEN,
         FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE)
# SUCCEEDS! Should return STATUS_ACCESS_DENIED per spec.

o.close()  # File is now DELETED without ever having DELETE permission!
```

**Confirmed on [privtest] share** (no force user, proper `fuzz:fuzz` auth).

### Suggested Fix

```c
// In smb2_create(), after computing daccess:
if (req->CreateOptions & FILE_DELETE_ON_CLOSE_LE) {
    if (!(daccess & FILE_DELETE_LE)) {
        rc = -EACCES;
        rsp->hdr.Status = STATUS_ACCESS_DENIED;
        goto err_out;
    }
}
```

### How Found

1. Code audit: MS-SMB2 3.3.5.9 says DELETE required for DELETE_ON_CLOSE
2. Manual test via smbprotocol on `[privtest]` share
3. `sniper_priv_bypass` pattern: restricted access + dangerous option

---

## Finding 3: Directory DELETE_ON_CLOSE Without DELETE Access

**Status:** Confirmed on mainline 7.1-rc7 (unfixed)  
**Severity:** High (unauthorized directory deletion)  
**Spec Reference:** MS-SMB2 3.3.5.9

### Description

Same as Finding 2 but for directories. An authenticated user with only READ access can delete entire directory trees by opening them with `FILE_DELETE_ON_CLOSE`.

### Reproduction

```python
od.create(0, FILE_READ_DATA | FILE_READ_ATTRIBUTES,  # NO DELETE!
          FILE_ATTRIBUTE_NORMAL, SHARE_ALL, FILE_OPEN,
          FILE_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE)  # SUCCEEDS!
od.close()  # Directory DELETED!
```

**Confirmed: directory actually deleted after close.**

---

## Finding 4: FILE_OVERWRITE_IF Without WRITE Access (Data Destruction)

**Status:** Confirmed on mainline 7.1-rc7 (unfixed)  
**Severity:** High (unauthorized data destruction)  
**Spec Reference:** MS-SMB2 3.3.5.9

### Description

ksmbd allows `CreateDisposition = FILE_OVERWRITE_IF` to succeed even when `DesiredAccess` does not include `FILE_WRITE_DATA`. Per MS-SMB2 section 3.3.5.9, the server MUST verify that the granted access includes WRITE_DATA before allowing OVERWRITE/OVERWRITE_IF.

### Impact

An authenticated user with only READ access can truncate/wipe any file's contents by opening it with `FILE_OVERWRITE_IF`. The file data is destroyed on open.

### Reproduction

```python
# File has "PRECIOUS DATA"
o.create(0, FILE_READ_DATA | FILE_READ_ATTRIBUTES,  # NO WRITE!
         FILE_ATTRIBUTE_NORMAL, SHARE_ALL, FILE_OVERWRITE_IF,  # OVERWRITES!
         FILE_NON_DIRECTORY_FILE)
# File data is now WIPED (0 bytes) — read returns END_OF_FILE
```

**Confirmed on [privtest] share** — file contents destroyed without write permission.

### Suggested Fix

```c
// In smb2_create(), check CreateDisposition:
if (req->CreateDisposition == FILE_OVERWRITE_LE ||
    req->CreateDisposition == FILE_OVERWRITE_IF_LE) {
    if (!(daccess & FILE_WRITE_DATA_LE)) {
        rc = -EACCES;
        rsp->hdr.Status = STATUS_ACCESS_DENIED;
        goto err_out;
    }
}
```

---

## Finding 5: (Investigating) FSCTL_QUERY_ALLOCATED_RANGES Without Read Check

**Status:** Under investigation  
**Severity:** Low (info leak)  
**Spec Reference:** MS-FSCC 2.3.53

### Description

`fsctl_query_allocated_ranges()` in `fs/smb/server/smb2pdu.c` does not verify `fp->daccess & FILE_READ_DATA_LE` before returning file allocation information. This may leak file layout metadata to users without read permission.

### Status

Unable to confirm via smbprotocol (signing/encryption interferes with raw IOCTL injection). Requires dedicated raw TCP sniper on `[privtest]` share with proper NTLMv2 auth.

### Next Steps

- Implement NTLMv2 auth in sniper to connect to `[privtest]` 
- Or test via kernel module that calls `fsctl_query_allocated_ranges` directly

---
