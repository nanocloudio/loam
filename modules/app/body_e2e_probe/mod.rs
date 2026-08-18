#![no_std]
// Runtime e2e probe: PUT → GET → verify against the body_store PIC.
// Step 1 sends the PUT; subsequent steps read the response channel,
// then send the GET, then verify the returned bytes byte-for-byte.

use core::ffi::c_void;

#[allow(dead_code, unused_imports, reason = "shared fluxor SDK include; each module uses a subset")]
#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/mechanics/loam_body_wire.rs"]
mod wire;

const BODY: &[u8] = b"loam disk-backed body e2e";

#[repr(C)]
pub struct ModuleState {
    syscalls: *const SyscallTable,
    resp_in: i32,
    req_out: i32,
    phase: u8, // 0 = send PUT, 1 = await digest, 2 = await body, 3 = done
    digest: [u8; wire::DIGEST_LEN],
    buf: [u8; 4096],
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<ModuleState>() as u32
}

#[no_mangle]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
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
        let s = &mut *(state as *mut ModuleState);
        s.syscalls = syscalls as *const SyscallTable;
        s.resp_in = in_chan;
        s.req_out = out_chan;
        s.phase = 0;
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;
        match s.phase {
            0 => {
                let n = match wire::encode_put_req(&mut s.buf, BODY) {
                    Ok(n) => n,
                    Err(_) => {
                        dev_log(sys, 3, b"[body_e2e] FAIL encode".as_ptr(), 22);
                        s.phase = 3;
                        return 0;
                    }
                };
                (sys.channel_write)(s.req_out, s.buf.as_ptr(), n);
                s.phase = 1;
            }
            1 => {
                let n = (sys.channel_read)(s.resp_in, s.buf.as_mut_ptr(), s.buf.len());
                if n <= 0 {
                    return 0;
                }
                match wire::decode_put_resp(&s.buf[..n as usize]) {
                    Ok(d) => {
                        s.digest.copy_from_slice(d);
                        let m = match wire::encode_get_req(&mut s.buf, &s.digest) {
                            Ok(m) => m,
                            Err(_) => {
                                dev_log(sys, 3, b"[body_e2e] FAIL get-enc".as_ptr(), 23);
                                s.phase = 3;
                                return 0;
                            }
                        };
                        (sys.channel_write)(s.req_out, s.buf.as_ptr(), m);
                        s.phase = 2;
                    }
                    Err(_) => {
                        dev_log(sys, 3, b"[body_e2e] FAIL put-resp".as_ptr(), 24);
                        s.phase = 3;
                    }
                }
            }
            2 => {
                let n = (sys.channel_read)(s.resp_in, s.buf.as_mut_ptr(), s.buf.len());
                if n <= 0 {
                    return 0;
                }
                match wire::decode_get_resp(&s.buf[..n as usize]) {
                    Ok(body) if body == BODY => {
                        dev_log(sys, 3, b"[body_e2e] PASS".as_ptr(), 15);
                    }
                    _ => {
                        dev_log(sys, 3, b"[body_e2e] FAIL body".as_ptr(), 20);
                    }
                }
                s.phase = 3;
            }
            _ => {}
        }
        0
    }
}
