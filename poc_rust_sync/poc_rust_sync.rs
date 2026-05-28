// SPDX-License-Identifier: GPL-2.0
//! PoC: Audit Rust kernel sync/refcount/Arc/workqueue subsystem.
//! Write to /sys/kernel/debug/poc_rust_sync to trigger.
#![allow(missing_docs)]

use kernel::prelude::*;
use kernel::c_str;
use kernel::alloc::flags;
use kernel::alloc::kbox::KBox;
use kernel::sync::Arc;

module! {
    type: PocRustSync,
    name: "poc_rust_sync",
    authors: ["kcov-dataflow"],
    description: "Audit Rust sync/Arc/refcount",
    license: "GPL",
}

// Case 1: Arc creation and clone (refcount increment)
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_arc_refcount() -> i64 {
    let arc1 = match Arc::new(0xDEADu64, flags::GFP_KERNEL) {
        Ok(a) => a,
        Err(_) => return -1,
    };
    let arc2 = arc1.clone();
    let arc3 = arc2.clone();
    let val = *arc3;
    pr_info!("test_arc_refcount: val=0x{:x} (3 refs)\n", val);
    // Drop arc3, arc2 - refcount goes 3→2→1
    drop(arc3);
    drop(arc2);
    // arc1 is last ref
    *arc1 as i64
}

// Case 2: Arc::into_raw / from_raw cycle (unsafe boundary)
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_arc_raw_roundtrip() -> i64 {
    let arc = match Arc::new(0xCAFEBABEu64, flags::GFP_KERNEL) {
        Ok(a) => a,
        Err(_) => return -1,
    };
    let raw_ptr = Arc::into_raw(arc);
    pr_info!("test_arc_raw: ptr={:?}\n", raw_ptr);
    // Reconstruct - this is the unsafe boundary
    let arc2 = unsafe { Arc::from_raw(raw_ptr) };
    let val = *arc2;
    pr_info!("test_arc_raw: reconstructed val=0x{:x}\n", val);
    val as i64
}

// Case 3: Arc with zero value (potential confusion with NULL)
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_arc_zero() -> i64 {
    let arc = match Arc::new(0u64, flags::GFP_KERNEL) {
        Ok(a) => a,
        Err(_) => return -1,
    };
    let val = *arc;
    let ptr = Arc::as_ptr(&arc);
    pr_info!("test_arc_zero: val={} ptr={:?} (ptr!=NULL: {})\n",
             val, ptr, !ptr.is_null());
    val as i64
}

// Case 4: KBox into_raw / from_raw (ownership transfer)
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_kbox_raw() -> i64 {
    let b = match KBox::new(0x1234_5678_9ABC_DEF0u64, flags::GFP_KERNEL) {
        Ok(b) => b,
        Err(_) => return -1,
    };
    let raw = KBox::into_raw(b);
    pr_info!("test_kbox_raw: raw_ptr={:?}\n", raw);
    // Reconstruct
    let b2 = unsafe { KBox::from_raw(raw) };
    let val = *b2;
    pr_info!("test_kbox_raw: val=0x{:x}\n", val);
    val as i64
}

// Case 5: Multiple KBox allocations (heap layout)
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_heap_layout() -> i64 {
    let b1 = KBox::new(1u64, flags::GFP_KERNEL).ok();
    let b2 = KBox::new(2u64, flags::GFP_KERNEL).ok();
    let b3 = KBox::new(3u64, flags::GFP_KERNEL).ok();
    if let (Some(ref a), Some(ref b), Some(ref c)) = (&b1, &b2, &b3) {
        let p1 = &**a as *const u64 as usize;
        let p2 = &**b as *const u64 as usize;
        let p3 = &**c as *const u64 as usize;
        let d12 = if p2 > p1 { p2 - p1 } else { p1 - p2 };
        let d23 = if p3 > p2 { p3 - p2 } else { p2 - p3 };
        pr_info!("test_heap_layout: p1=0x{:x} p2=0x{:x} p3=0x{:x} d12={} d23={}\n",
                 p1, p2, p3, d12, d23);
        d12 as i64
    } else { -1 }
}

// Case 6: Arc::into_unique_or_drop with single ref (should succeed)
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_arc_unique() -> i64 {
    let arc = match Arc::new(42u64, flags::GFP_KERNEL) {
        Ok(a) => a,
        Err(_) => return -1,
    };
    // Only one reference - should convert to UniqueArc
    match Arc::into_unique_or_drop(arc) {
        Some(_unique) => {
            pr_info!("test_arc_unique: converted to UniqueArc OK\n");
            1
        }
        None => {
            pr_info!("test_arc_unique: dropped (unexpected!)\n");
            0
        }
    }
}

// Case 7: Arc::into_unique_or_drop with multiple refs (should drop)
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_arc_unique_multi() -> i64 {
    let arc1 = match Arc::new(99u64, flags::GFP_KERNEL) {
        Ok(a) => a,
        Err(_) => return -1,
    };
    let _arc2 = arc1.clone(); // 2 refs
    // Should NOT convert - has multiple refs
    match Arc::into_unique_or_drop(arc1) {
        Some(_) => {
            pr_info!("test_arc_unique_multi: converted (BUG!)\n");
            -99 // This would be a bug
        }
        None => {
            pr_info!("test_arc_unique_multi: correctly dropped\n");
            0
        }
    }
}

unsafe extern "C" fn write_handler(
    _file: *mut kernel::bindings::file,
    _buf: *const core::ffi::c_char,
    count: usize,
    _ppos: *mut kernel::bindings::loff_t,
) -> kernel::ffi::c_long {
    test_arc_refcount();       // Case 1
    test_arc_raw_roundtrip();  // Case 2
    test_arc_zero();           // Case 3
    test_kbox_raw();           // Case 4
    test_heap_layout();        // Case 5
    test_arc_unique();         // Case 6
    test_arc_unique_multi();   // Case 7
    count as kernel::ffi::c_long
}

#[repr(transparent)]
struct SyncFops(kernel::bindings::file_operations);
unsafe impl Sync for SyncFops {}
static FOPS: SyncFops = SyncFops(kernel::bindings::file_operations {
    write: Some(unsafe { core::mem::transmute(write_handler as *const ()) }),
    ..unsafe { core::mem::zeroed() }
});

struct PocRustSync { d: *mut kernel::bindings::dentry }
impl kernel::Module for PocRustSync {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        let d = unsafe { kernel::bindings::debugfs_create_file_unsafe(
            c_str!("poc_rust_sync").as_char_ptr(), 0o222,
            core::ptr::null_mut(), core::ptr::null_mut(), &FOPS.0) };
        Ok(Self { d })
    }
}
impl Drop for PocRustSync {
    fn drop(&mut self) { unsafe { kernel::bindings::debugfs_remove(self.d) }; }
}
unsafe impl Send for PocRustSync {}
unsafe impl Sync for PocRustSync {}
