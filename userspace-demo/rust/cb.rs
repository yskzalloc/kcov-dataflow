//! trace-args/trace-ret callbacks for demo.rs. Build this crate WITHOUT
//! -Cpasses=sancov-module, so the callbacks do not instrument themselves.
//!
//! TLV contract:
//!   tag = (arg_idx << 32) | size
//!   offsets == NULL: val is the value itself, zero-extended to 64 bits
//!   offsets != NULL: val is an address; offsets[0] = N, followed by N
//!                    {byte offset, byte size} pairs
//! The call site, the return address minus 1, identifies the observation.

use std::io::Write;

#[inline(always)]
fn return_address() -> usize {
    // The callbacks are leaf-like Rust functions compiled with frame
    // pointers, so the caller's return address is at [rbp + 8].
    let ra: usize;
    unsafe { std::arch::asm!("mov {}, [rbp + 8]", out(reg) ra, options(nostack, readonly)) };
    ra
}

fn dump(kind: &str, tag: u64, val: u64, off: *const u64, pc: usize) {
    let mut s = format!("{kind:<5} pc={pc:#x}");
    if kind == "ENTRY" {
        s += &format!(" arg[{}]", tag >> 32);
    }
    s += &format!(" size={}", tag as u32);
    if off.is_null() {
        s += &format!(" val={val:#x}");
    } else {
        // The compiler only passes a table for memory the IR says is
        // readable: a byval/sret object or a dereferenceable(N) pointee.
        let n = unsafe { *off } as usize;
        let fields: Vec<String> = (0..n)
            .map(|i| unsafe {
                let (o, sz) = (*off.add(1 + 2 * i), *off.add(2 + 2 * i));
                let p = (val + o) as *const u8;
                let mut w = [0u8; 8];
                std::ptr::copy_nonoverlapping(p, w.as_mut_ptr(), sz.min(8) as usize);
                format!("{:#x}", u64::from_le_bytes(w))
            })
            .collect();
        s += &format!(" @{val:#x} {{{}}}", fields.join(", "));
    }
    let _ = writeln!(std::io::stderr(), "{s}");
}

#[no_mangle]
pub extern "C" fn __sanitizer_cov_trace_args(tag: u64, val: u64, off: *const u64) {
    dump("ENTRY", tag, val, off, return_address());
}

#[no_mangle]
pub extern "C" fn __sanitizer_cov_trace_ret(size: u64, val: u64, off: *const u64) {
    dump("RET", size, val, off, return_address());
}
