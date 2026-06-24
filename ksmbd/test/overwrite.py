"""Test: FILE_OVERWRITE / FILE_OVERWRITE_IF without FILE_WRITE_DATA."""
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

# Create target with data
o = Open(t, "overwrite_victim")
o.create(0, 0x12019F, 0x80, 7, CreateDisposition.FILE_OPEN_IF, CreateOptions.FILE_NON_DIRECTORY_FILE)
o.write(b"PRECIOUS DATA THAT SHOULD NOT BE OVERWRITTEN" * 10, 0)
o.close()
print("Created file with precious data")

# TEST: Open with FILE_OVERWRITE_IF but only READ access
# MS-SMB2 3.3.5.9: "If CreateDisposition is FILE_OVERWRITE/FILE_OVERWRITE_IF
# and DesiredAccess does not include FILE_WRITE_DATA... fail with ACCESS_DENIED"
try:
    o2 = Open(t, "overwrite_victim")
    o2.create(0, FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES,
              0x80, 7, CreateDisposition.FILE_OVERWRITE_IF,
              CreateOptions.FILE_NON_DIRECTORY_FILE)
    print("[BUG-5] FILE_OVERWRITE_IF with READ-ONLY: SUCCEEDED!")
    print("        File contents may be truncated/overwritten!")
    # Check if data was wiped
    data = o2.read(0, 100)
    if len(data) == 0:
        print("        CONFIRMED: File data WIPED (0 bytes)!")
    else:
        print(f"        File still has {len(data)} bytes")
    o2.close()
except Exception as e:
    err = str(e)
    if "ACCESS_DENIED" in err:
        print("[OK-5] FILE_OVERWRITE_IF denied (ACCESS_DENIED)")
    else:
        print(f"[?-5] {err[:80]}")

t.disconnect(); s.disconnect(); c.disconnect()
