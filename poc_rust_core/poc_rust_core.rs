// SPDX-License-Identifier: GPL-2.0
//! PoC: Audit Rust kernel core APIs via kcov_dataflow.
//! Exercises: KVec, KBox, UserSlice, Task, Page, error paths.
//! Write to /sys/kernel/debug/poc_rust_core to trigger.
#![allow(missing_docs)]

use kernel::prelude::*;
use kernel::c_str;
use kernel::alloc::kvec::KVec;
use kernel::alloc::kbox::KBox;
use kernel::alloc::flags;
use kernel::page::Page;
use kernel::task::Task;

module! {
    type: PocRustCore,
    name: "poc_rust_core",
    authors: ["kcov-dataflow"],
    description: "Audit Rust core kernel APIs",
    license: "GPL",
}

// Case 1: KVec allocation with extreme sizes
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_kvec_alloc(size: usize) -> i64 {
    let v: core::result::Result<KVec<u8>, _> = KVec::with_capacity(size, flags::GFP_KERNEL);
    match v {
        Ok(vec) => {
            pr_info!("test_kvec_alloc({}): OK, cap={}\n", size, vec.capacity());
            vec.capacity() as i64
        }
        Err(_) => {
            pr_info!("test_kvec_alloc({}): FAILED\n", size);
            -1
        }
    }
}

// Case 2: KBox allocation
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_kbox_alloc(value: u64) -> i64 {
    let b: core::result::Result<KBox<u64>, _> = KBox::new(value, flags::GFP_KERNEL);
    match b {
        Ok(boxed) => {
            pr_info!("test_kbox_alloc(0x{:x}): OK, val=0x{:x}\n", value, *boxed);
            *boxed as i64
        }
        Err(_) => {
            pr_info!("test_kbox_alloc(0x{:x}): FAILED\n", value);
            -1
        }
    }
}

// Case 3: Page allocation
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_page_alloc(gfp: u32) -> i64 {
    let page = Page::alloc_page(flags::GFP_KERNEL);
    match page {
        Ok(p) => {
            let nid = p.nid();
            pr_info!("test_page_alloc(0x{:x}): OK, nid={}\n", gfp, nid);
            nid as i64
        }
        Err(_) => {
            pr_info!("test_page_alloc(0x{:x}): FAILED\n", gfp);
            -1
        }
    }
}

// Case 4: Current task info
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_task_info() -> i64 {
    let task = unsafe { Task::current() };
    let pid = task.pid();
    let signal = task.signal_pending();
    pr_info!("test_task_info: pid={} signal={}\n", pid, signal);
    pid as i64
}

// Case 5: KVec push beyond capacity (reallocation path)
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_kvec_push(count: u32) -> i64 {
    let mut v: KVec<u32> = KVec::new();
    for i in 0..count {
        if v.push(i, flags::GFP_KERNEL).is_err() {
            pr_info!("test_kvec_push({}): OOM at i={}\n", count, i);
            return -(i as i64);
        }
    }
    pr_info!("test_kvec_push({}): OK, len={} cap={}\n", count, v.len(), v.capacity());
    v.len() as i64
}

// Case 6: Error code conversion (Rust errno handling)
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_error_codes(code: i32) -> i64 {
    let err = kernel::error::Error::from_errno(code);
    let name = err.name();
    pr_info!("test_error_codes({}): name={:?}\n", code, name);
    code as i64
}

unsafe extern "C" fn write_handler(
    _file: *mut kernel::bindings::file,
    _buf: *const core::ffi::c_char,
    count: usize,
    _ppos: *mut kernel::bindings::loff_t,
) -> kernel::ffi::c_long {
    // Exercise all test cases
    test_kvec_alloc(0);           // Case 1a: zero-size alloc
    test_kvec_alloc(16);          // Case 1b: normal alloc
    test_kvec_alloc(0x7fffffff);  // Case 1c: huge alloc (should fail)
    test_kbox_alloc(0xdeadbeefcafebabe);  // Case 2: known value
    test_page_alloc(0xcc0);       // Case 3: GFP_KERNEL
    test_task_info();             // Case 4: current task
    test_kvec_push(1000);         // Case 5: many pushes (realloc path)
    test_error_codes(-1);         // Case 6a: EPERM
    test_error_codes(-22);        // Case 6b: EINVAL
    test_error_codes(-4096);      // Case 6c: invalid (out of range)
    count as kernel::ffi::c_long
}

#[repr(transparent)]
struct SyncFops(kernel::bindings::file_operations);
unsafe impl Sync for SyncFops {}
static FOPS: SyncFops = SyncFops(kernel::bindings::file_operations {
    write: Some(unsafe { core::mem::transmute(write_handler as *const ()) }),
    ..unsafe { core::mem::zeroed() }
});

struct PocRustCore { d: *mut kernel::bindings::dentry }
impl kernel::Module for PocRustCore {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        let d = unsafe { kernel::bindings::debugfs_create_file_unsafe(
            c_str!("poc_rust_core").as_char_ptr(), 0o222,
            core::ptr::null_mut(), core::ptr::null_mut(), &FOPS.0) };
        pr_info!("poc_rust_core: loaded\n");
        Ok(Self { d })
    }
}
impl Drop for PocRustCore {
    fn drop(&mut self) { unsafe { kernel::bindings::debugfs_remove(self.d) }; }
}
unsafe impl Send for PocRustCore {}
unsafe impl Sync for PocRustCore {}
