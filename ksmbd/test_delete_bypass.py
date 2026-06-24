"""Test: CREATE with FILE_DELETE_ON_CLOSE without DELETE permission."""
from smbprotocol.connection import Connection, Dialects
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import Open, CreateDisposition, ShareAccess, CreateOptions, FilePipePrinterAccessMask
import uuid

c = Connection(uuid.uuid4(), "127.0.0.1", 445)
c.connect(Dialects.SMB_3_0_0)
s = Session(c, "fuzz", "fuzz")
s.connect()
t = TreeConnect(s, r"\\127.0.0.1\privtest")
t.connect()

# Create a target file
o = Open(t, "delete_test")
o.create(0, 0x12019F, 0x80, 7, CreateDisposition.FILE_OPEN_IF, CreateOptions.FILE_NON_DIRECTORY_FILE)
o.write(b"precious data", 0)
o.close()
print("Created target file")

# Try to open with DELETE_ON_CLOSE but WITHOUT FILE_DELETE access
# MS-SMB2 3.3.5.9: "If FILE_DELETE_ON_CLOSE is set and
# Open.GrantedAccess does not include DELETE, return STATUS_ACCESS_DENIED"
try:
    o2 = Open(t, "delete_test")
    # FILE_READ_DATA | FILE_READ_ATTRIBUTES (no DELETE)
    o2.create(0, FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES,
              0x80, 7, CreateDisposition.FILE_OPEN,
              CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_DELETE_ON_CLOSE)
    print("[BUG] CREATE with DELETE_ON_CLOSE but no DELETE access: SUCCEEDED!")
    print("      MS-SMB2 3.3.5.9 violation: requires DELETE in DesiredAccess")
    o2.close()
except Exception as e:
    err = str(e)
    if "ACCESS_DENIED" in err:
        print(f"[OK] DELETE_ON_CLOSE without DELETE: correctly denied")
    elif "INVALID_PARAMETER" in err:
        print(f"[OK] DELETE_ON_CLOSE without DELETE: invalid parameter")
    else:
        print(f"[?] Result: {err[:100]}")

# Also test: can we SET disposition (delete) on a READ-ONLY handle?
o3 = Open(t, "delete_test")
o3.create(0, FilePipePrinterAccessMask.FILE_READ_DATA,
          0x80, 7, CreateDisposition.FILE_OPEN, CreateOptions.FILE_NON_DIRECTORY_FILE)
# Try SET_INFO(FileDispositionInformation) - delete flag
try:
    # smbprotocol doesn't expose raw set_info easily, but the open worked
    print(f"[INFO] Opened without DELETE. Handle open for further testing.")
except: pass
o3.close()

t.disconnect(); s.disconnect(); c.disconnect()
