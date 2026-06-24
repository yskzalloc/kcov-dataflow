from smbprotocol.connection import Connection, Dialects
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import Open, CreateDisposition, ShareAccess, CreateOptions, FilePipePrinterAccessMask, SMB2LockElement, LockFlags
import uuid

c = Connection(uuid.uuid4(), "127.0.0.1", 445)
c.connect(Dialects.SMB_3_0_0)
s = Session(c, "fuzz", "fuzz")
s.connect()
t = TreeConnect(s, r"\\127.0.0.1\share")
t.connect()

# Open with READ-ONLY
o = Open(t, "lock_bypass_test")
o.create(0, FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES,
         0x80, ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE | ShareAccess.FILE_SHARE_DELETE,
         CreateDisposition.FILE_OPEN_IF, CreateOptions.FILE_NON_DIRECTORY_FILE)
print("Opened with READ-ONLY (no FILE_WRITE_DATA)")

# Exclusive lock
lock = SMB2LockElement()
lock['offset'] = 0
lock['length'] = 4096
lock['flags'] = LockFlags.SMB2_LOCKFLAG_EXCLUSIVE_LOCK | LockFlags.SMB2_LOCKFLAG_FAIL_IMMEDIATELY
try:
    o.lock([lock])
    print("[BUG] EXCLUSIVE LOCK SUCCEEDED with READ-ONLY daccess!")
    print("      MS-SMB2 3.3.5.14: server SHOULD verify handle has access")
    print("      ksmbd does NOT check → spec violation / hardening bug")
except Exception as e:
    err_str = str(e)
    if "ACCESS_DENIED" in err_str:
        print(f"[OK] Lock denied with ACCESS_DENIED")
    else:
        print(f"Lock result: {err_str[:100]}")

o.close(); t.disconnect(); s.disconnect(); c.disconnect()
