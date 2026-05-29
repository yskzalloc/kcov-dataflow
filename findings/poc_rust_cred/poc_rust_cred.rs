// SPDX-License-Identifier: GPL-2.0
//! PoC: Audit Rust kernel credential/task/mm subsystem.
//! Write to /sys/kernel/debug/poc_rust_cred to trigger.
#![allow(missing_docs)]

use kernel::prelude::*;
use kernel::c_str;
use kernel::alloc::flags;
use kernel::alloc::kvec::KVec;
use kernel::task::Task;
use kernel::fs::file::LocalFile;

module! {
    type: PocRustCred,
    name: "poc_rust_cred",
    authors: ["kcov-dataflow"],
    description: "Audit Rust cred/task/mm",
    license: "GPL",
}

// Case 1: Get current task credentials
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_current_cred() -> i64 {
    let task = unsafe { Task::current() };
    let pid = task.pid();
    let signal = task.signal_pending();
    pr_info!("test_cred: pid={} signal={}\n", pid, signal);
    pid as i64
}

// Case 2: File credential access
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_file_cred(fd: u32) -> i64 {
    match LocalFile::fget(fd) {
        Ok(file) => {
            let cred = file.cred();
            let secid = cred.get_secid();
            pr_info!("test_file_cred({}): secid={}\n", fd, secid);
            secid as i64
        }
        Err(_) => {
            pr_info!("test_file_cred({}): BadFd\n", fd);
            -1
        }
    }
}

// Case 3: Task mm access
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_task_mm() -> i64 {
    let task = unsafe { Task::current() };
    match task.mm() {
        Some(mm) => {
            let raw = mm.as_raw();
            pr_info!("test_task_mm: mm={:?}\n", raw);
            raw as i64
        }
        None => {
            pr_info!("test_task_mm: no mm (kernel thread?)\n");
            0
        }
    }
}

// Case 4: PID namespace
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_pid_ns() -> i64 {
    let task = unsafe { Task::current() };
    match task.get_pid_ns() {
        Some(ns) => {
            let ptr = ns.as_ptr();
            pr_info!("test_pid_ns: ns={:?}\n", ptr);
            ptr as i64
        }
        None => {
            pr_info!("test_pid_ns: no pidns\n");
            0
        }
    }
}

// Case 5: Multiple fget on same fd (refcount)
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_fget_refcount() -> i64 {
    let f1 = LocalFile::fget(0);
    let f2 = LocalFile::fget(0);
    let f3 = LocalFile::fget(0);
    let count = f1.is_ok() as i64 + f2.is_ok() as i64 + f3.is_ok() as i64;
    pr_info!("test_fget_refcount: {} successful fgets on fd 0\n", count);
    // All three hold a reference - when dropped, refcount decrements
    count
}

// Case 6: fget on negative-equivalent fd (u32 wrapping)
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_fget_wrap() -> i64 {
    // fd is u32, so -1 as u32 = 0xFFFFFFFF
    let ret1 = LocalFile::fget(0xFFFFFFFE);
    let ret2 = LocalFile::fget(0xFFFFFFFF);
    let ret3 = LocalFile::fget(0x80000000); // INT_MAX+1 as u32
    pr_info!("test_fget_wrap: 0xFFFFFFFE={} 0xFFFFFFFF={} 0x80000000={}\n",
             ret1.is_ok(), ret2.is_ok(), ret3.is_ok());
    (ret1.is_ok() as i64) + (ret2.is_ok() as i64) + (ret3.is_ok() as i64)
}

// Case 7: Vec of file references
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_vec_of_files() -> i64 {
    let mut files: KVec<u32> = KVec::new();
    // Collect valid fds
    for fd in 0u32..10 {
        if LocalFile::fget(fd).is_ok() {
            let _ = files.push(fd, flags::GFP_KERNEL);
        }
    }
    pr_info!("test_vec_of_files: {} valid fds in [0..10)\n", files.len());
    files.len() as i64
}

// Case 8: Task signal_pending in loop (race window)
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_signal_race() -> i64 {
    let task = unsafe { Task::current() };
    let mut count = 0i64;
    for _ in 0..100 {
        if task.signal_pending() {
            count += 1;
        }
    }
    pr_info!("test_signal_race: signal_pending true {} times in 100 checks\n", count);
    count
}

// Case 9: Credential secid (SELinux context)
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_secid_values() -> i64 {
    // Get secid from multiple file descriptors
    let mut secids: KVec<u32> = KVec::new();
    for fd in 0u32..5 {
        if let Ok(file) = LocalFile::fget(fd) {
            let secid = file.cred().get_secid();
            let _ = secids.push(secid, flags::GFP_KERNEL);
        }
    }
    let all_same = secids.as_slice().windows(2).all(|w| w[0] == w[1]);
    pr_info!("test_secid: {} fds, all_same_secid={}\n", secids.len(), all_same);
    secids.as_slice().first().copied().unwrap_or(0) as i64
}

// Case 10: Multiple task info calls (consistency check)
#[no_mangle]
#[inline(never)]
pub extern "C" fn test_task_consistency() -> i64 {
    let t1 = unsafe { Task::current() };
    let pid1 = t1.pid();
    let t2 = unsafe { Task::current() };
    let pid2 = t2.pid();
    // PIDs should be identical (same task)
    let consistent = pid1 == pid2;
    pr_info!("test_task_consistency: pid1={} pid2={} same={}\n", pid1, pid2, consistent);
    consistent as i64
}

unsafe extern "C" fn write_handler(
    _file: *mut kernel::bindings::file,
    _buf: *const core::ffi::c_char,
    count: usize,
    _ppos: *mut kernel::bindings::loff_t,
) -> kernel::ffi::c_long {
    test_current_cred();    // 1
    test_file_cred(0);      // 2a: stdin
    test_file_cred(999);    // 2b: invalid
    test_task_mm();         // 3
    test_pid_ns();          // 4
    test_fget_refcount();   // 5
    test_fget_wrap();       // 6
    test_vec_of_files();    // 7
    test_signal_race();     // 8
    test_secid_values();    // 9
    test_task_consistency();  // 10
    count as kernel::ffi::c_long
}

#[repr(transparent)]
struct SyncFops(kernel::bindings::file_operations);
unsafe impl Sync for SyncFops {}
static FOPS: SyncFops = SyncFops(kernel::bindings::file_operations {
    write: Some(unsafe { core::mem::transmute(write_handler as *const ()) }),
    ..unsafe { core::mem::zeroed() }
});

struct PocRustCred { d: *mut kernel::bindings::dentry }
impl kernel::Module for PocRustCred {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        let d = unsafe { kernel::bindings::debugfs_create_file_unsafe(
            c_str!("poc_rust_cred").as_char_ptr(), 0o222,
            core::ptr::null_mut(), core::ptr::null_mut(), &FOPS.0) };
        Ok(Self { d })
    }
}
impl Drop for PocRustCred {
    fn drop(&mut self) { unsafe { kernel::bindings::debugfs_remove(self.d) }; }
}
unsafe impl Send for PocRustCred {}
unsafe impl Sync for PocRustCred {}
