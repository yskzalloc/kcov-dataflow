// SPDX-License-Identifier: GPL-2.0
//! PoC: Audit Rust kernel memory/fs subsystem via kcov_dataflow.
//! Exercises: Page alloc/map/read, UserSlice copy, File operations, mm virt.
//! Write to /sys/kernel/debug/poc_rust_mm to trigger.
#![allow(missing_docs)]

use kernel::prelude::*;
use kernel::c_str;
use kernel::alloc::flags;
use kernel::page::Page;
use kernel::uaccess::{UserPtr, UserSlice};
use kernel::fs::file::LocalFile;

module! {
    type: PocRustMm,
    name: "poc_rust_mm",
    authors: ["kcov-dataflow"],
    description: "Audit Rust mm/fs/uaccess core",
    license: "GPL",
}

// Case 1: Page alloc + write + read
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_page_map_read() -> i64 {
    let page = match Page::alloc_page(flags::GFP_KERNEL) {
        Ok(p) => p,
        Err(_) => return -1,
    };
    // Write a pattern
    let pattern: [u8; 8] = [0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44];
    let _ = unsafe { page.write_raw(pattern.as_ptr(), 0, 8) };
    // Read back
    let mut buf = [0u8; 8];
    let ret = unsafe { page.read_raw(buf.as_mut_ptr(), 0, 8) };
    pr_info!("test_page_map_read: buf[0]=0x{:x} buf[1]=0x{:x} ret={:?}\n",
             buf[0], buf[1], ret);
    buf[0] as i64
}

// Case 2: Page read at offset (boundary check)
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_page_read_offset(offset: usize, len: usize) -> i64 {
    let page = match Page::alloc_page(flags::GFP_KERNEL) {
        Ok(p) => p,
        Err(_) => return -1,
    };
    let mut buf = [0u8; 16];
    let actual_len = core::cmp::min(len, 16);
    let ret = unsafe { page.read_raw(buf.as_mut_ptr(), offset, actual_len) };
    match ret {
        Ok(()) => {
            pr_info!("test_page_read_offset({}, {}): OK\n", offset, len);
            0
        }
        Err(e) => {
            pr_info!("test_page_read_offset({}, {}): ERR {:?}\n", offset, len, e);
            -1
        }
    }
}

// Case 3: UserSlice with zero length
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_userslice_zero() -> i64 {
    let ptr = UserPtr::from_addr(0x1000);  // arbitrary user addr
    let slice = UserSlice::new(ptr, 0);    // zero length
    let mut reader = slice.reader();
    let mut buf = [0u8; 1];
    // Reading 0 bytes should succeed, reading 1 byte should fail
    let ret = reader.read_slice(&mut buf[..0]);
    pr_info!("test_userslice_zero: read(0)={:?}\n", ret);
    match ret {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

// Case 4: UserSlice with invalid address
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_userslice_invalid(addr: u64, len: usize) -> i64 {
    let ptr = UserPtr::from_addr(addr as usize);
    let slice = UserSlice::new(ptr, len);
    let mut reader = slice.reader();
    let mut buf = [0u8; 8];
    let actual = core::cmp::min(len, 8);
    let ret = reader.read_slice(&mut buf[..actual]);
    pr_info!("test_userslice_invalid(0x{:x}, {}): {:?}\n", addr, len, ret);
    match ret {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

// Case 5: File descriptor lookup (fget)
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_fget(fd: u32) -> i64 {
    let result = LocalFile::fget(fd);
    match result {
        Ok(file) => {
            let flags = file.flags();
            pr_info!("test_fget({}): OK flags=0x{:x}\n", fd, flags);
            flags as i64
        }
        Err(_) => {
            pr_info!("test_fget({}): BadFd\n", fd);
            -1
        }
    }
}

// Case 6: Page nid (NUMA node) - information leak potential
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_page_nid() -> i64 {
    let page = match Page::alloc_page(flags::GFP_KERNEL) {
        Ok(p) => p,
        Err(_) => return -1,
    };
    let nid = page.nid();
    pr_info!("test_page_nid: nid={}\n", nid);
    nid as i64
}

unsafe extern "C" fn write_handler(
    _file: *mut kernel::bindings::file,
    _buf: *const core::ffi::c_char,
    count: usize,
    _ppos: *mut kernel::bindings::loff_t,
) -> kernel::ffi::c_long {
    // Exercise all cases
    test_page_map_read();                    // Case 1: page alloc+map+read
    test_page_read_offset(0, 8);             // Case 2a: normal read
    test_page_read_offset(4090, 8);          // Case 2b: cross-page boundary
    test_page_read_offset(4096, 1);          // Case 2c: exactly at page end
    test_page_read_offset(4097, 1);          // Case 2d: past page end
    test_userslice_zero();                   // Case 3: zero-length UserSlice
    test_userslice_invalid(0, 8);            // Case 4a: NULL user pointer
    test_userslice_invalid(0xffffffff0000, 8); // Case 4b: kernel-range addr
    test_userslice_invalid(0x7fffffffe000, 4096); // Case 4c: near stack top
    test_fget(0);                            // Case 5a: stdin
    test_fget(999);                          // Case 5b: invalid fd
    test_fget(0xffffffff);                   // Case 5c: u32::MAX fd
    test_page_nid();                         // Case 6: NUMA node info
    count as kernel::ffi::c_long
}

#[repr(transparent)]
struct SyncFops(kernel::bindings::file_operations);
unsafe impl Sync for SyncFops {}
static FOPS: SyncFops = SyncFops(kernel::bindings::file_operations {
    write: Some(unsafe { core::mem::transmute(write_handler as *const ()) }),
    ..unsafe { core::mem::zeroed() }
});

struct PocRustMm { d: *mut kernel::bindings::dentry }
impl kernel::Module for PocRustMm {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        let d = unsafe { kernel::bindings::debugfs_create_file_unsafe(
            c_str!("poc_rust_mm").as_char_ptr(), 0o222,
            core::ptr::null_mut(), core::ptr::null_mut(), &FOPS.0) };
        pr_info!("poc_rust_mm: loaded\n");
        Ok(Self { d })
    }
}
impl Drop for PocRustMm {
    fn drop(&mut self) { unsafe { kernel::bindings::debugfs_remove(self.d) }; }
}
unsafe impl Send for PocRustMm {}
unsafe impl Sync for PocRustMm {}
