// SPDX-License-Identifier: GPL-2.0
//! Verify kcov_dataflow captures 1-arg through 8-arg functions.
//! Write to /sys/kernel/debug/test_args_rust to trigger all 8.
#![allow(missing_docs)]

use kernel::prelude::*;
use kernel::c_str;

module! {
    type: ArgsModule,
    name: "eight_args_rust",
    authors: ["kcov-dataflow"],
    description: "1-8 arg verification",
    license: "GPL",
}

#[no_mangle] #[inline(never)] pub extern "C" fn rfunc1(a1: u64) -> u64 { a1 }
#[no_mangle] #[inline(never)] pub extern "C" fn rfunc2(a1: u64, a2: u64) -> u64 { a1+a2 }
#[no_mangle] #[inline(never)] pub extern "C" fn rfunc3(a1: u64, a2: u64, a3: u64) -> u64 { a1+a2+a3 }
#[no_mangle] #[inline(never)] pub extern "C" fn rfunc4(a1: u64, a2: u64, a3: u64, a4: u64) -> u64 { a1+a2+a3+a4 }
#[no_mangle] #[inline(never)] pub extern "C" fn rfunc5(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 { a1+a2+a3+a4+a5 }
#[no_mangle] #[inline(never)] pub extern "C" fn rfunc6(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 { a1+a2+a3+a4+a5+a6 }
#[no_mangle] #[inline(never)] pub extern "C" fn rfunc7(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64, a7: u64) -> u64 { a1+a2+a3+a4+a5+a6+a7 }
#[no_mangle] #[inline(never)] pub extern "C" fn rfunc8(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64, a7: u64, a8: u64) -> u64 { a1+a2+a3+a4+a5+a6+a7+a8 }

unsafe extern "C" fn write_handler(
    _file: *mut kernel::bindings::file,
    _buf: *const core::ffi::c_char,
    count: usize,
    _ppos: *mut kernel::bindings::loff_t,
) -> kernel::ffi::c_long {
    let r1 = rfunc1(0x11);
    pr_info!("rfunc1: ret=0x{:x}\n", r1);
    let r2 = rfunc2(0x11, 0x22);
    pr_info!("rfunc2: ret=0x{:x}\n", r2);
    let r3 = rfunc3(0x11, 0x22, 0x33);
    pr_info!("rfunc3: ret=0x{:x}\n", r3);
    let r4 = rfunc4(0x11, 0x22, 0x33, 0x44);
    pr_info!("rfunc4: ret=0x{:x}\n", r4);
    let r5 = rfunc5(0x11, 0x22, 0x33, 0x44, 0x55);
    pr_info!("rfunc5: ret=0x{:x}\n", r5);
    let r6 = rfunc6(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
    pr_info!("rfunc6: ret=0x{:x}\n", r6);
    let r7 = rfunc7(0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77);
    pr_info!("rfunc7: ret=0x{:x}\n", r7);
    let r8 = rfunc8(0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88);
    pr_info!("rfunc8: ret=0x{:x}\n", r8);
    count as kernel::ffi::c_long
}

#[repr(transparent)]
struct SyncFops(kernel::bindings::file_operations);
unsafe impl Sync for SyncFops {}

static FOPS: SyncFops = SyncFops(kernel::bindings::file_operations {
    write: Some(unsafe { core::mem::transmute(write_handler as *const ()) }),
    ..unsafe { core::mem::zeroed() }
});

struct ArgsModule { d: *mut kernel::bindings::dentry }

impl kernel::Module for ArgsModule {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        let d = unsafe {
            kernel::bindings::debugfs_create_file_unsafe(
                c_str!("test_args_rust").as_char_ptr(),
                0o222, core::ptr::null_mut(), core::ptr::null_mut(), &FOPS.0,
            )
        };
        Ok(Self { d })
    }
}
impl Drop for ArgsModule {
    fn drop(&mut self) { unsafe { kernel::bindings::debugfs_remove(self.d) }; }
}
unsafe impl Send for ArgsModule {}
unsafe impl Sync for ArgsModule {}
