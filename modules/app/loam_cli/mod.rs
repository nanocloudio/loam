#![no_std]
#![allow(
    dead_code,
    reason = "SDK runtime/params include! lands at crate root; each shim drives a subset"
)]

// Loam's operator applet: `fluxor exec loam -- <command> …`. Step body in
// `modules/common/mechanics/loam_cli_body.rs`; ports in `manifest.toml`;
// the graph it runs in, `packaging/cli/linux.yaml`.

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

// SHA-256: content digests of what is put, read and exported.
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha256.rs");

#[path = "../../common/mechanics/loam_limits.rs"]
mod limits;

#[path = "../../common/mechanics/loam_body_wire.rs"]
mod body_wire;

#[path = "../../common/mechanics/loam_admin_wire.rs"]
mod admin;

#[path = "../../common/mechanics/loam_volume_map_wire.rs"]
mod map_wire;

#[path = "../../common/mechanics/loam_manifest_wire.rs"]
mod manifest;

#[path = "../../common/mechanics/admin_client.rs"]
mod admin_client;

#[path = "../../common/mechanics/loam_cli_body.rs"]
mod body;

/// `net_in` after `args`; `exit` and `net_out` after `stdout`.
const NET_IN: u8 = 1;
const EXIT_OUT: u8 = 1;
const NET_OUT: u8 = 2;

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<body::ModuleState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
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
    state_ptr: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        let sys = &*(syscalls as *const SyscallTable);
        let net_in = dev_channel_port(sys, 0, NET_IN);
        let exit = dev_channel_port(sys, 1, EXIT_OUT);
        let net_out = dev_channel_port(sys, 1, NET_OUT);
        body::module_new_impl(
            in_chan,
            out_chan,
            exit,
            body::Transport::Net { net_in, net_out },
            state_ptr,
            state_size,
            syscalls as *const SyscallTable,
        )
    }
}

/// # Safety
/// The module ABI's step: the state pointer is the state `module_new`
/// initialised, and the runtime steps it from one caller at a time.
#[no_mangle]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state_ptr: *mut u8) -> i32 {
    unsafe { body::module_step_impl(state_ptr) }
}

// Panic handler comes from `runtime.rs` via the include! above.
