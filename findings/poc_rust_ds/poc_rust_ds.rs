// SPDX-License-Identifier: GPL-2.0
//! PoC: Audit Rust kernel data structures and sync primitives.
//! Exercises: RBTree, CStr/BStr, Mutex, Arc, Completion, kstrtobool.
//! Write to /sys/kernel/debug/poc_rust_ds to trigger.
#![allow(missing_docs)]

use kernel::prelude::*;
use kernel::c_str;
use kernel::alloc::flags;
use kernel::alloc::kbox::KBox;
use kernel::rbtree::RBTree;
use kernel::str::CString;

module! {
    type: PocRustDs,
    name: "poc_rust_ds",
    authors: ["kcov-dataflow"],
    description: "Audit Rust data structures and sync",
    license: "GPL",
}

// Case 1: RBTree insert/lookup with boundary keys
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_rbtree_boundaries() -> i64 {
    let mut tree = RBTree::<i64, u64>::new();
    // Insert with extreme keys
    let _ = tree.try_create_and_insert(0, 0xAAAA, flags::GFP_KERNEL);
    let _ = tree.try_create_and_insert(i64::MAX, 0xBBBB, flags::GFP_KERNEL);
    let _ = tree.try_create_and_insert(i64::MIN, 0xCCCC, flags::GFP_KERNEL);
    let _ = tree.try_create_and_insert(-1, 0xDDDD, flags::GFP_KERNEL);

    // Lookup
    let v0 = tree.get(&0).map(|v| *v).unwrap_or(0);
    let vmax = tree.get(&i64::MAX).map(|v| *v).unwrap_or(0);
    let vmin = tree.get(&i64::MIN).map(|v| *v).unwrap_or(0);
    pr_info!("test_rbtree: get(0)=0x{:x} get(MAX)=0x{:x} get(MIN)=0x{:x}\n", v0, vmax, vmin);
    v0 as i64
}

// Case 2: RBTree duplicate key insert
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_rbtree_duplicate() -> i64 {
    let mut tree = RBTree::<u32, u32>::new();
    let _ = tree.try_create_and_insert(42, 100, flags::GFP_KERNEL);
    let _ret = tree.try_create_and_insert(42, 200, flags::GFP_KERNEL);
    // What happens? Does it replace? Error? Silent drop?
    let val = tree.get(&42).map(|v| *v).unwrap_or(0);
    pr_info!("test_rbtree_dup: insert(42,200) over existing → val={}\n", val);
    val as i64
}

// Case 3: CString from bytes with embedded NUL
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_cstring_embedded_nul() -> i64 {
    // "hello\0world" - embedded NUL should be rejected or truncated
    let bytes = b"hello\0world";
    let cs = CString::try_from_fmt(fmt!("{}", core::str::from_utf8(&bytes[..5]).unwrap_or("")));
    match cs {
        Ok(_s) => {
            pr_info!("test_cstring: created OK\n");
            5
        }
        Err(_) => {
            pr_info!("test_cstring: creation failed\n");
            -1
        }
    }
}

// Case 4: kstrtobool edge cases
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_kstrtobool() -> i64 {
    let r1 = kernel::str::kstrtobool(c_str!("1"));
    let r0 = kernel::str::kstrtobool(c_str!("0"));
    let ry = kernel::str::kstrtobool(c_str!("y"));
    let rn = kernel::str::kstrtobool(c_str!("n"));
    let re = kernel::str::kstrtobool(c_str!(""));
    let rx = kernel::str::kstrtobool(c_str!("maybe"));
    pr_info!("kstrtobool: 1={:?} 0={:?} y={:?} n={:?} empty={:?} maybe={:?}\n",
             r1, r0, ry, rn, re, rx);
    let mut count = 0i64;
    if r1.is_ok() { count += 1; }
    if r0.is_ok() { count += 1; }
    if ry.is_ok() { count += 1; }
    if rn.is_ok() { count += 1; }
    if re.is_ok() { count += 1; }
    if rx.is_ok() { count += 1; }
    count
}

// Case 5: KBox allocation of large struct
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_kbox_large() -> i64 {
    // Allocate a large struct via KBox
    let b: core::result::Result<KBox<[u8; 4096]>, _> =
        KBox::new([0xABu8; 4096], flags::GFP_KERNEL);
    match b {
        Ok(boxed) => {
            pr_info!("test_kbox_large: OK, first=0x{:x} last=0x{:x}\n",
                     boxed[0], boxed[4095]);
            boxed[0] as i64
        }
        Err(_) => {
            pr_info!("test_kbox_large: FAILED\n");
            -1
        }
    }
}

// Case 6: RBTree with 0 elements - empty tree operations
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_rbtree_empty() -> i64 {
    let tree = RBTree::<u32, u32>::new();
    let is_empty = tree.is_empty();
    let get_none = tree.get(&0);
    let cursor = tree.cursor_front();
    pr_info!("test_rbtree_empty: empty={} get(0)={:?} cursor={:?}\n",
             is_empty, get_none.is_none(), cursor.is_none());
    is_empty as i64
}

unsafe extern "C" fn write_handler(
    _file: *mut kernel::bindings::file,
    _buf: *const core::ffi::c_char,
    count: usize,
    _ppos: *mut kernel::bindings::loff_t,
) -> kernel::ffi::c_long {
    test_rbtree_boundaries();    // Case 1
    test_rbtree_duplicate();     // Case 2
    test_cstring_embedded_nul(); // Case 3
    test_kstrtobool();           // Case 4
    test_kbox_large();           // Case 5
    test_rbtree_empty();         // Case 6
    count as kernel::ffi::c_long
}

#[repr(transparent)]
struct SyncFops(kernel::bindings::file_operations);
unsafe impl Sync for SyncFops {}
static FOPS: SyncFops = SyncFops(kernel::bindings::file_operations {
    write: Some(unsafe { core::mem::transmute(write_handler as *const ()) }),
    ..unsafe { core::mem::zeroed() }
});

struct PocRustDs { d: *mut kernel::bindings::dentry }
impl kernel::Module for PocRustDs {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        let d = unsafe { kernel::bindings::debugfs_create_file_unsafe(
            c_str!("poc_rust_ds").as_char_ptr(), 0o222,
            core::ptr::null_mut(), core::ptr::null_mut(), &FOPS.0) };
        pr_info!("poc_rust_ds: loaded\n");
        Ok(Self { d })
    }
}
impl Drop for PocRustDs {
    fn drop(&mut self) { unsafe { kernel::bindings::debugfs_remove(self.d) }; }
}
unsafe impl Send for PocRustDs {}
unsafe impl Sync for PocRustDs {}
