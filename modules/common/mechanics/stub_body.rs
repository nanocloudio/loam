// Shared step body for Loam's public-surface PIC modules.
//
// Implements a small request/response protocol over the Fluxor
// channel ABI:
//
//   opcode 0x01 (OP_PING)   — in: [opcode]
//                              out: [opcode, 0x01]  (pong tag)
//   opcode 0x02 (OP_NOOP)   — in: [opcode]
//                              out: [opcode]
//   opcode 0x03 (OP_TICKS)  — in: [opcode]
//                              out: [opcode, t[0..4]]  (LE u32 tick count)
//
// Anything else is dropped after a single-byte read (the module never
// blocks on garbage). Step contract: bounded work per step (at most
// `MAX_OPS_PER_STEP` opcodes), no blocking, no hidden threads, no
// allocation beyond the fixed-size `ModuleState`.
//
// This is the integration shape every Loam public-surface module
// uses. A full host-side `LoamInstance` bridge is layered on top via
// a separate request schema (serialized through `OctetStream`); that
// schema lives in a follow-on round.

const OP_PING: u8 = 0x01;
const OP_NOOP: u8 = 0x02;
const OP_TICKS: u8 = 0x03;

const MAX_OPS_PER_STEP: u32 = 4;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    ticks: u32,
    ops_handled: u32,
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<ModuleState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
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
        if state.is_null() || syscalls.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<ModuleState>() {
            return -2;
        }
        let s = &mut *(state as *mut ModuleState);
        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.out_chan = out_chan;
        s.ticks = 0;
        s.ops_handled = 0;
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut ModuleState);
        s.ticks = s.ticks.wrapping_add(1);

        let syscalls = match s.syscalls.as_ref() {
            Some(t) => t,
            None => return -1,
        };

        // Bounded work: handle at most MAX_OPS_PER_STEP opcodes per
        // step. Stop early on an empty inbound channel or any error.
        let mut handled: u32 = 0;
        while handled < MAX_OPS_PER_STEP {
            let mut op_buf: [u8; 1] = [0];
            let n = (syscalls.channel_read)(s.in_chan, op_buf.as_mut_ptr(), 1);
            if n <= 0 {
                // 0 = empty; <0 = error. Either way, yield to the
                // scheduler this step.
                break;
            }

            let mut resp: [u8; 8] = [0; 8];
            let resp_len: usize = match op_buf[0] {
                OP_PING => {
                    resp[0] = OP_PING;
                    resp[1] = 0x01;
                    2
                }
                OP_NOOP => {
                    resp[0] = OP_NOOP;
                    1
                }
                OP_TICKS => {
                    resp[0] = OP_TICKS;
                    let t = s.ticks.to_le_bytes();
                    resp[1] = t[0];
                    resp[2] = t[1];
                    resp[3] = t[2];
                    resp[4] = t[3];
                    5
                }
                _ => {
                    // Unknown opcode: drop it; do NOT advance handled
                    // toward the cap so a flood of garbage still
                    // honors bounded-work via the outer loop.
                    handled = handled.wrapping_add(1);
                    continue;
                }
            };

            let wrote = (syscalls.channel_write)(s.out_chan, resp.as_ptr(), resp_len);
            if wrote < 0 {
                // Backpressure or error on the outbound channel.
                // Stop this step; producer side will retry next tick.
                break;
            }
            handled = handled.wrapping_add(1);
            s.ops_handled = s.ops_handled.wrapping_add(1);
        }
        0
    }
}

// ABI-surface attestation: `fluxor pack` refuses ELFs without this
// symbol (compile-provenance pinning). Modules that include the full
// SDK runtime.rs get it there; stub-bodied modules embed it here.
#[used]
pub static FLUXOR_ABI_SURFACE: [u8; 32] = crate::abi::abi_surface::ABI_SURFACE_DIGEST;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
