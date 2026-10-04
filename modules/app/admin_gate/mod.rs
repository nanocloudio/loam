#![no_std]
#![allow(
    dead_code,
    reason = "SDK runtime/params include! lands at crate root; each shim drives a subset"
)]

// Loam's admin_gate PIC module: terminates every admin session, admits
// each request under the capabilities its session presented, and
// multiplexes the admitted ones onto admin_router. Step body in
// `modules/common/mechanics/admin_gate_body.rs`; ports and parameters in
// `manifest.toml`.

use core::ffi::c_void;

#[allow(
    dead_code,
    unused_imports,
    reason = "shared fluxor SDK include; each module uses a subset"
)]
#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::contracts::mesh::capability as cap;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/params.rs");

// SHA-256 for scopes and holders, SHA-512 and the field arithmetic
// Ed25519 needs, and Ed25519 for capability chains: all SDK-owned.
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha256.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha384.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/hmac.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/p256.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/ed25519.rs");

#[path = "../../common/mechanics/loam_limits.rs"]
mod limits;

#[path = "../../common/mechanics/loam_body_wire.rs"]
mod body_wire;

#[path = "../../common/mechanics/loam_admin_wire.rs"]
mod admin;

#[path = "../../common/mechanics/admin_gate_body.rs"]
mod body;

/// The capability verifier's crypto.
struct Crypto;

impl cap::CapCrypto for Crypto {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        sha256(data)
    }
    fn ed25519_verify(&self, key: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
        ed25519_verify(key, msg, sig)
    }
}

/// Input indices after `net_in`.
const ID_IN: u8 = 1;
const ROUTER_IN: u8 = 2;
const LINK_IN_BASE: u8 = 3;
/// Output indices after `net_out`.
const ROUTER_OUT: u8 = 1;
const LINK_OUT_BASE: u8 = 2;

mod params_def {
    use super::{cap, p_u16, SCHEMA_MAX};

    pub struct Config {
        pub port: u16,
        pub roots: [[u8; cap::KEY_LEN]; cap::MAX_ROOTS],
        pub roots_len: usize,
        pub roots_bad: bool,
    }

    fn hexval(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }

    pub unsafe fn parse_roots(c: &mut Config, d: *const u8, len: usize) {
        c.roots_len = 0;
        c.roots_bad = false;
        let v = core::slice::from_raw_parts(d, len);
        for item in v.split(|&b| b == b',') {
            if item.len() != 64 || c.roots_len == cap::MAX_ROOTS {
                c.roots_bad = true;
                return;
            }
            let mut k = [0u8; 32];
            for i in 0..32 {
                match (hexval(item[2 * i]), hexval(item[2 * i + 1])) {
                    (Some(h), Some(l)) => k[i] = (h << 4) | l,
                    _ => {
                        c.roots_bad = true;
                        return;
                    }
                }
            }
            c.roots[c.roots_len] = k;
            c.roots_len += 1;
        }
    }

    define_params! {
        Config;
        1, port, u16, 0
            => |s, d, len| { s.port = p_u16(d, len, 0, 0); };
        2, mesh_roots, str, 0
            => |s, d, len| { parse_roots(s, d, len); };
    }
}

unsafe fn refuse(sys: &SyscallTable, why: &[u8]) -> i32 {
    dev_log(sys, 1, why.as_ptr(), why.len());
    -22
}

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
    params: *const u8,
    params_len: usize,
    state_ptr: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        let sys = &*(syscalls as *const SyscallTable);
        let mut cfg = params_def::Config {
            port: 0,
            roots: [[0; cap::KEY_LEN]; cap::MAX_ROOTS],
            roots_len: 0,
            roots_bad: false,
        };
        if !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01 {
            params_def::parse_tlv(&mut cfg, params, params_len);
        }
        if cfg.roots_bad || cfg.roots_len == 0 {
            return refuse(
                sys,
                b"[admin_gate] mesh_roots is required: one or two 64-hex Ed25519 keys",
            );
        }
        let id_in = dev_channel_port(sys, 0, ID_IN);
        let router_in = dev_channel_port(sys, 0, ROUTER_IN);
        let router_out = dev_channel_port(sys, 1, ROUTER_OUT);
        if router_in < 0 || router_out < 0 {
            return refuse(
                sys,
                b"[admin_gate] admin_req and admin_resp must be wired to admin_router",
            );
        }
        if (in_chan < 0) != (out_chan < 0) {
            return refuse(
                sys,
                b"[admin_gate] net_in and net_out are wired together or not at all",
            );
        }
        if in_chan >= 0 && (id_in < 0 || cfg.port == 0) {
            return refuse(
                sys,
                b"[admin_gate] a network listener needs peer_identity and a port",
            );
        }
        let mut links_in = [-1i32; body::LINKS];
        let mut links_out = [-1i32; body::LINKS];
        for i in 0..body::LINKS {
            links_in[i] = dev_channel_port(sys, 0, LINK_IN_BASE + i as u8);
            links_out[i] = dev_channel_port(sys, 1, LINK_OUT_BASE + i as u8);
            if (links_in[i] < 0) != (links_out[i] < 0) {
                return refuse(sys, b"[admin_gate] a link is wired in one direction only");
            }
        }
        let port = if in_chan >= 0 { cfg.port } else { 0 };
        body::module_new_impl(
            state_ptr,
            state_size,
            syscalls as *const SyscallTable,
            (in_chan, out_chan, id_in),
            (router_out, router_in),
            &links_in,
            &links_out,
            port,
            &cfg.roots[..cfg.roots_len],
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
