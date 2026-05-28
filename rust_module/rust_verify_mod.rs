// SPDX-License-Identifier: GPL-2.0

//! KCOV dataflow verification Rust kernel module.
//! Write to /sys/kernel/debug/rust_trigger to invoke rust_process_data.

use kernel::prelude::*;
use kernel::c_str;

module! {
    type: RustVerifyModule,
    name: "rust_verify_mod",
    authors: ["kcov-dataflow"],
    description: "Rust module for kcov_dataflow verification",
    license: "GPL",
}

/// Struct whose fields are traced by kcov_dataflow.
#[repr(C)]
#[allow(missing_docs)]
pub struct RustData {
    pub id: u32,
    pub value: u64,
    pub flags: u32,
}

/// Function with known arguments — traced by kcov_dataflow.
#[no_mangle]
#[inline(never)]
pub extern "C" fn rust_process_data(data: *mut RustData, multiplier: u32, cookie: u64) -> u64 {
    let d = unsafe { &mut *data };
    d.id = d.id.wrapping_mul(multiplier);
    d.value = d.value.wrapping_add(cookie);
    d.flags |= 0xF0;

    pr_info!(
        "rust_process_data: id=0x{:x} value=0x{:x} flags=0x{:x} mult={} cookie=0x{:x}\n",
        d.id, d.value, d.flags, multiplier, cookie
    );

    d.value
}

/// Write handler for debugfs file
unsafe extern "C" fn rust_write(
    _file: *mut kernel::bindings::file,
    _buf: *const core::ffi::c_char,
    count: usize,
    _ppos: *mut kernel::bindings::loff_t,
) -> kernel::ffi::c_long {
    let mut data = RustData {
        id: 0xCAFE,
        value: 0xDEAD_BEEF_1234_5678,
        flags: 0x0A,
    };

    rust_process_data(&mut data as *mut RustData, 3, 0x1111_1111_1111_1111);
    count as kernel::ffi::c_long
}

// Wrapper to make file_operations Sync
#[repr(transparent)]
struct SyncFops(kernel::bindings::file_operations);
unsafe impl Sync for SyncFops {}

static RUST_FOPS: SyncFops = SyncFops(kernel::bindings::file_operations {
    write: Some(unsafe { core::mem::transmute(rust_write as *const ()) }),
    ..unsafe { core::mem::zeroed() }
});

struct RustVerifyModule {
    _debugfs: *mut kernel::bindings::dentry,
}

impl kernel::Module for RustVerifyModule {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        let dentry = unsafe {
            kernel::bindings::debugfs_create_file_unsafe(
                c_str!("rust_trigger").as_char_ptr(),
                0o222,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &RUST_FOPS.0,
            )
        };
        pr_info!("rust_verify_mod: loaded. echo x > /sys/kernel/debug/rust_trigger\n");
        Ok(RustVerifyModule { _debugfs: dentry })
    }
}

impl Drop for RustVerifyModule {
    fn drop(&mut self) {
        unsafe { kernel::bindings::debugfs_remove(self._debugfs) };
        pr_info!("rust_verify_mod: unloaded\n");
    }
}

// SAFETY: The debugfs dentry pointer is only used for cleanup.
unsafe impl Send for RustVerifyModule {}
unsafe impl Sync for RustVerifyModule {}
