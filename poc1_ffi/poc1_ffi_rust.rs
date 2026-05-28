// SPDX-License-Identifier: GPL-2.0
//! PoC 1: Rust-to-C FFI contract violation detection.
//! Write to /sys/kernel/debug/poc1_ffi to trigger.
#![allow(missing_docs)]

use kernel::prelude::*;
use kernel::c_str;

module! {
    type: Poc1Module,
    name: "poc1_ffi_rust",
    authors: ["kcov-dataflow"],
    description: "FFI contract violation PoC",
    license: "GPL",
}

#[repr(C)]
pub struct FfiAlloc {
    pub buffer: *mut u8,
    pub data_size: u64,
    pub free_async: u32,
    pub flags: u32,
}

extern "C" {
    fn ffi_alloc_buf(alloc: *mut FfiAlloc, data_size: u64,
                     offsets_size: u64, is_async: core::ffi::c_int) -> core::ffi::c_int;
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn rust_ffi_caller(alloc: *mut FfiAlloc, is_async: i32) -> i64 {
    let ret = unsafe { ffi_alloc_buf(alloc, 256, 16, is_async) };
    if ret == 0 {
        // Contract says buffer is valid on success
        let buf = unsafe { (*alloc).buffer };
        if buf.is_null() {
            pr_err!("CONTRACT VIOLATION: ffi_alloc_buf returned 0 but buffer is NULL!\n");
            return -1;
        }
        pr_info!("rust_ffi_caller: success, buffer={:p}\n", buf);
        unsafe { kernel::bindings::kfree(buf as *const _) };
        return 0;
    }
    pr_info!("rust_ffi_caller: alloc failed with {}\n", ret);
    ret as i64
}

unsafe extern "C" fn write_handler(
    _file: *mut kernel::bindings::file, _buf: *const core::ffi::c_char,
    count: usize, _ppos: *mut kernel::bindings::loff_t,
) -> kernel::ffi::c_long {
    let mut alloc = FfiAlloc { buffer: core::ptr::null_mut(), data_size: 0, free_async: 0, flags: 0 };
    // Trigger the bug: is_async=1, free_async=0 (pool exhausted)
    rust_ffi_caller(&mut alloc as *mut FfiAlloc, 1);
    count as kernel::ffi::c_long
}

#[repr(transparent)]
struct SyncFops(kernel::bindings::file_operations);
unsafe impl Sync for SyncFops {}
static FOPS: SyncFops = SyncFops(kernel::bindings::file_operations {
    write: Some(unsafe { core::mem::transmute(write_handler as *const ()) }),
    ..unsafe { core::mem::zeroed() }
});

struct Poc1Module { d: *mut kernel::bindings::dentry }
impl kernel::Module for Poc1Module {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        let d = unsafe { kernel::bindings::debugfs_create_file_unsafe(
            c_str!("poc1_ffi").as_char_ptr(), 0o222,
            core::ptr::null_mut(), core::ptr::null_mut(), &FOPS.0) };
        pr_info!("poc1_ffi_rust: loaded\n");
        Ok(Self { d })
    }
}
impl Drop for Poc1Module { fn drop(&mut self) { unsafe { kernel::bindings::debugfs_remove(self.d) }; } }
unsafe impl Send for Poc1Module {}
unsafe impl Sync for Poc1Module {}
