// SPDX-License-Identifier: GPL-2.0
//! PoC: Audit Rust KVec (kernel Vec) memory management edge cases.
//! Write to /sys/kernel/debug/poc_rust_vec to trigger.
#![allow(missing_docs)]

use kernel::prelude::*;
use kernel::c_str;
use kernel::alloc::flags;
use kernel::alloc::kvec::KVec;

module! {
    type: PocRustVec,
    name: "poc_rust_vec",
    authors: ["kcov-dataflow"],
    description: "Audit Rust KVec memory edge cases",
    license: "GPL",
}

// Case 1: reserve(0) on empty vec
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_vec_reserve_zero() -> i64 {
    let mut v: KVec<u8> = KVec::new();
    let ret = v.reserve(0, flags::GFP_KERNEL);
    pr_info!("reserve(0): {:?} cap={}\n", ret, v.capacity());
    v.capacity() as i64
}

// Case 2: reserve(usize::MAX) - overflow check
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_vec_reserve_max() -> i64 {
    let mut v: KVec<u8> = KVec::new();
    let ret = v.reserve(usize::MAX, flags::GFP_KERNEL);
    pr_info!("reserve(MAX): {:?}\n", ret);
    match ret { Ok(()) => 0, Err(_) => -1 }
}

// Case 3: reserve(usize::MAX - 1) with existing capacity
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_vec_reserve_overflow() -> i64 {
    let mut v: KVec<u64> = KVec::with_capacity(10, flags::GFP_KERNEL).unwrap_or_else(|_| KVec::new());
    // len=0, cap=10. reserve(usize::MAX) should check len+additional overflow
    let ret = v.reserve(usize::MAX, flags::GFP_KERNEL);
    pr_info!("reserve(MAX) with cap=10: {:?}\n", ret);
    match ret { Ok(()) => 0, Err(_) => -1 }
}

// Case 4: push_within_capacity on full vec
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_vec_push_full() -> i64 {
    let mut v: KVec<u32> = KVec::with_capacity(2, flags::GFP_KERNEL).unwrap_or_else(|_| KVec::new());
    let _ = v.push_within_capacity(0xAAAA);
    let _ = v.push_within_capacity(0xBBBB);
    // Vec is now full (len=2, cap=2). Next push should fail.
    let ret = v.push_within_capacity(0xCCCC);
    pr_info!("push_within_capacity(full): {:?} len={} cap={}\n",
             ret.is_err(), v.len(), v.capacity());
    match ret { Ok(()) => 0, Err(e) => { pr_info!("  rejected val=0x{:x}\n", e.0); -1 } }
}

// Case 5: remove(0) from empty vec
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_vec_remove_empty() -> i64 {
    let mut v: KVec<u64> = KVec::new();
    let ret = v.remove(0);
    pr_info!("remove(0) empty: {:?}\n", ret.is_err());
    match ret { Ok(val) => val as i64, Err(_) => -1 }
}

// Case 6: remove(usize::MAX) - out of bounds
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_vec_remove_oob() -> i64 {
    let mut v: KVec<u64> = KVec::new();
    let _ = v.push(42, flags::GFP_KERNEL);
    let ret = v.remove(usize::MAX);
    pr_info!("remove(MAX) with len=1: {:?}\n", ret.is_err());
    match ret { Ok(val) => val as i64, Err(_) => -1 }
}

// Case 7: truncate to larger than len (should be no-op)
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_vec_truncate_larger() -> i64 {
    let mut v: KVec<u32> = KVec::new();
    let _ = v.push(1, flags::GFP_KERNEL);
    let _ = v.push(2, flags::GFP_KERNEL);
    v.truncate(100); // len=2, truncate to 100 → should be no-op
    pr_info!("truncate(100) with len=2: len={}\n", v.len());
    v.len() as i64
}

// Case 8: extend_from_slice with empty slice
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_vec_extend_empty() -> i64 {
    let mut v: KVec<u8> = KVec::new();
    let empty: &[u8] = &[];
    let ret = v.extend_from_slice(empty, flags::GFP_KERNEL);
    pr_info!("extend_from_slice(empty): {:?} len={}\n", ret, v.len());
    v.len() as i64
}

// Case 9: from_elem with size 0
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_vec_from_elem_zero() -> i64 {
    let v: Result<KVec<u8>, _> = KVec::from_elem(0xAB, 0, flags::GFP_KERNEL);
    match v {
        Ok(vec) => {
            pr_info!("from_elem(0xAB, 0): len={} cap={}\n", vec.len(), vec.capacity());
            vec.len() as i64
        }
        Err(_) => -1,
    }
}

// Case 10: into_raw_parts and reconstruct (unsafe boundary)
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_vec_raw_parts() -> i64 {
    let mut v: KVec<u64> = KVec::with_capacity(4, flags::GFP_KERNEL).unwrap_or_else(|_| KVec::new());
    let _ = v.push(0x1111, flags::GFP_KERNEL);
    let _ = v.push(0x2222, flags::GFP_KERNEL);
    let (ptr, len, cap) = v.into_raw_parts();
    pr_info!("into_raw_parts: ptr={:?} len={} cap={}\n", ptr, len, cap);
    // Reconstruct - unsafe boundary
    let v2 = unsafe { KVec::from_raw_parts(ptr, len, cap) };
    let val = v2.as_slice().get(0).copied().unwrap_or(0);
    pr_info!("  reconstructed: val[0]=0x{:x}\n", val);
    val as i64
}

unsafe extern "C" fn write_handler(
    _file: *mut kernel::bindings::file,
    _buf: *const core::ffi::c_char,
    count: usize,
    _ppos: *mut kernel::bindings::loff_t,
) -> kernel::ffi::c_long {
    test_vec_reserve_zero();      // 1
    test_vec_reserve_max();       // 2
    test_vec_reserve_overflow();  // 3
    test_vec_push_full();         // 4
    test_vec_remove_empty();      // 5
    test_vec_remove_oob();        // 6
    test_vec_truncate_larger();   // 7
    test_vec_extend_empty();      // 8
    test_vec_from_elem_zero();    // 9
    test_vec_raw_parts();         // 10
    count as kernel::ffi::c_long
}

#[repr(transparent)]
struct SyncFops(kernel::bindings::file_operations);
unsafe impl Sync for SyncFops {}
static FOPS: SyncFops = SyncFops(kernel::bindings::file_operations {
    write: Some(unsafe { core::mem::transmute(write_handler as *const ()) }),
    ..unsafe { core::mem::zeroed() }
});

struct PocRustVec { d: *mut kernel::bindings::dentry }
impl kernel::Module for PocRustVec {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        let d = unsafe { kernel::bindings::debugfs_create_file_unsafe(
            c_str!("poc_rust_vec").as_char_ptr(), 0o222,
            core::ptr::null_mut(), core::ptr::null_mut(), &FOPS.0) };
        Ok(Self { d })
    }
}
impl Drop for PocRustVec {
    fn drop(&mut self) { unsafe { kernel::bindings::debugfs_remove(self.d) }; }
}
unsafe impl Send for PocRustVec {}
unsafe impl Sync for PocRustVec {}
