#![no_std]
#![allow(
    dead_code,
    reason = "SDK runtime/params include! lands at crate root; each shim drives a subset"
)]
// Runtime e2e probe: PUT → GET → verify against the body plane.
// Step 1 sends the PUT; later steps read the answer, send the GET,
// and verify the returned bytes byte-for-byte. Requests and answers
// are body frames, and each answer must carry its request's cid.

use core::ffi::c_void;

#[allow(
    dead_code,
    unused_imports,
    reason = "shared fluxor SDK include; each module uses a subset"
)]
#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");

#[path = "../../common/mechanics/loam_body_wire.rs"]
mod body_wire;

#[path = "../../common/mechanics/body_frame.rs"]
mod body_frame;

const BODY: &[u8] = b"loam disk-backed body e2e";
const PUT_CID: u32 = 1;
const GET_CID: u32 = 2;

#[repr(C)]
pub struct ModuleState {
    syscalls: *const SyscallTable,
    resp_in: i32,
    req_out: i32,
    phase: u8, // 0 = send PUT, 1 = await digest, 2 = await body, 3 = done
    digest: [u8; body_wire::DIGEST_LEN],
    tx: body_frame::Sender,
    tx_buf: [u8; 128],
    rx: body_frame::Inbox<256>,
}

unsafe fn fail(sys: &SyscallTable, s: &mut ModuleState, why: &[u8]) {
    dev_log(sys, 3, why.as_ptr(), why.len());
    s.phase = 3;
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<ModuleState>() as u32
}

#[no_mangle]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// The module ABI's constructor: `state_ptr` points to `state_size`
/// zeroed bytes this module owns, `params` to `params_len` bytes, and
/// `syscalls` to the runtime's table, all valid for the call.
#[no_mangle]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<ModuleState>() {
            return -2;
        }
        core::ptr::write_bytes(state, 0u8, state_size);
        let s = &mut *(state as *mut ModuleState);
        s.syscalls = syscalls as *const SyscallTable;
        s.resp_in = in_chan;
        s.req_out = out_chan;
        s.phase = 0;
        0
    }
}

/// # Safety
/// The module ABI's step: the state pointer is the state `module_new`
/// initialised, and the runtime steps it from one caller at a time.
#[no_mangle]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;
        if !s.tx.flush(sys, s.req_out, &s.tx_buf) {
            return 0;
        }
        match s.phase {
            0 => {
                let Ok(n) = body_wire::encode_put_req(&mut s.tx_buf, BODY) else {
                    fail(sys, s, b"[body_e2e] FAIL encode");
                    return 0;
                };
                s.tx.stage(PUT_CID, n);
                s.tx.flush(sys, s.req_out, &s.tx_buf);
                s.phase = 1;
            }
            1 | 2 => {
                if s.rx.pull(sys, s.resp_in) != body_frame::Pull::Record {
                    return 0;
                }
                let want = if s.phase == 1 { PUT_CID } else { GET_CID };
                if s.rx.cid() != want {
                    fail(sys, s, b"[body_e2e] FAIL cid");
                    return 0;
                }
                if s.phase == 1 {
                    match body_wire::decode_put_resp(s.rx.record()) {
                        Ok(d) => s.digest.copy_from_slice(d),
                        Err(_) => {
                            fail(sys, s, b"[body_e2e] FAIL put-resp");
                            return 0;
                        }
                    }
                    s.rx.take();
                    let Ok(m) = body_wire::encode_get_req(&mut s.tx_buf, &s.digest) else {
                        fail(sys, s, b"[body_e2e] FAIL get-enc");
                        return 0;
                    };
                    s.tx.stage(GET_CID, m);
                    s.tx.flush(sys, s.req_out, &s.tx_buf);
                    s.phase = 2;
                } else {
                    match body_wire::decode_get_resp(s.rx.record()) {
                        Ok(body) if body == BODY => {
                            dev_log(sys, 3, b"[body_e2e] PASS".as_ptr(), 15);
                        }
                        _ => {
                            dev_log(sys, 3, b"[body_e2e] FAIL body".as_ptr(), 20);
                        }
                    }
                    s.rx.take();
                    s.phase = 3;
                }
            }
            _ => {}
        }
        0
    }
}
