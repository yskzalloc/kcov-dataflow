use std::hint::black_box;

#[repr(C)]
pub struct Req { op: i64, len: i64, flags: i64 } // 24 bytes, same as demo/c

#[inline(never)]
fn sink(v: i64) { black_box(v); }

// 1. last use of `mode` is the first line: later it is <optimized out>
#[no_mangle]
#[inline(never)]
pub fn process(mode: i32, len: i32) -> i32 {
    sink(mode.wrapping_mul(3) as i64);
    sink(len as i64); // gdb breakpoint here
    len
}

// 2. ten arguments: a7..a10 are on the stack on x86-64
#[no_mangle]
#[inline(never)]
pub fn many(a1: i64, a2: i64, a3: i64, a4: i64, a5: i64,
            a6: i64, a7: i64, a8: i64, a9: i64, a10: i64) -> i64 {
    a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8 + a9 + a10
}

// 3. struct by value: the Rust ABI passes it as a dereferenceable(24) pointer
#[no_mangle]
#[inline(never)]
pub fn submit(r: Req) -> i64 { r.op + r.len + r.flags }

// 4. shared reference: dereferenceable(24), so the pointee is snapshotted
//    (a C `const struct req *` gets only the pointer value)
#[no_mangle]
#[inline(never)]
pub fn inspect(r: &Req) -> i64 { r.flags }

// 5. slice: one source parameter, two IR arguments (pointer, length)
#[no_mangle]
#[inline(never)]
pub fn checksum(buf: &[u8]) -> u32 { buf.iter().map(|&b| b as u32).sum() }

extern crate cb; // links the uninstrumented callbacks

fn main() {
    let argc = std::env::args().len() as i32;
    sink(process(argc.wrapping_mul(0x8201), 16) as i64);
    sink(many(argc as i64, 2, 3, 4, 5, 6, 7, 8, 9, 10));
    let r = Req { op: argc as i64 + 1, len: 4096, flags: 0x41 };
    sink(inspect(&r));
    sink(submit(r));
    sink(checksum(black_box(b"df-demo")) as i64);
}
