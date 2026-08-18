#![no_std]

// Loam's namespace_router PIC module. The step-body logic lives in
// `modules/common/mechanics/namespace_pic_body.rs`, path-included below; this
// file is the thin `#[no_mangle] extern "C"` glue plus the
// `define_params!` schema that lets the fluxor build tool pack a
// YAML `params: { wal_path: "..." }` field into the TLV blob the
// kernel hands to `module_new`.

#![allow(dead_code, reason = "SDK runtime/params include! lands at crate root; each shim drives a subset")]
use core::ffi::c_void;

#[allow(dead_code, unused_imports, reason = "shared fluxor SDK include; each module uses a subset")]
#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

// Pulls in memset / memcpy / panic helpers the embedded linker
// needs when the module body initializes fixed-size arrays or uses
// non-trivial slice indexing. See `fluxor/modules/sdk/runtime.rs`.
include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");

// `define_params!` macro + TLV/schema constants. Exports `SCHEMA_MAX`
// referenced by the macro-generated `PARAM_SCHEMA` table.
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/params.rs");

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/mechanics/loam_wire.rs"]
mod wire;

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/mechanics/namespace_pic_state.rs"]
mod state;

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/mechanics/wal_io.rs"]
mod wal;

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/mechanics/loam_snapshot.rs"]
mod snapshot;

#[allow(dead_code, reason = "shared PIC body; each module shim drives a subset")]
#[path = "../../common/mechanics/namespace_pic_body.rs"]
mod body;

/// TLV parameter schema. `tag = 1` carries `wal_path` as a UTF-8
/// byte string; the handler copies bytes into the inline buffer on
/// `ModuleState` and records the length. The PIC mod.rs then drives
/// `body::open_wal_from_state` to actually open the file.
///
/// Tag 0 is reserved; `0xFF` is the TLV end marker.
mod params_def {
    use super::body::{ModuleState, WAL_PATH_BUF};
    use super::SCHEMA_MAX;

    define_params! {
        ModuleState;
        1, wal_path, str, 0
            => |s, d, len| {
                if len == 0 || len > WAL_PATH_BUF { return; }
                let mut i = 0usize;
                while i < len {
                    s.wal_path[i] = *d.add(i);
                    i += 1;
                }
                s.wal_path_len = len as u16;
            };
    }
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<body::ModuleState>() as u32
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
    params: *const u8,
    params_len: usize,
    state_ptr: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        let sys = syscalls as *const SyscallTable;
        // Init the channel/arena state. `wal_fd = -1` and
        // `wal_path_len = 0` until/unless the TLV handler runs.
        let rc = body::module_new_impl(in_chan, out_chan, state_ptr, state_size, sys);
        if rc != 0 {
            return rc;
        }

        body::decode_wal_path_params(state_ptr, params, params_len);

        // Replication channels (manifest: metadata_ops = out[1],
        // committed = in[1]). Unwired ports resolve to -1 and the
        // body stays in direct-apply mode.
        let metadata_ops = dev_channel_port(&*sys, 1, 1);
        let committed = dev_channel_port(&*sys, 0, 1);
        body::set_replication_channels(state_ptr, metadata_ops, committed);

        // If a wal path was set, open + replay. Returns 0 when no
        // path is configured, so a channel-only graph profile is fine.
        body::open_wal_from_state(state_ptr)
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state_ptr: *mut u8) -> i32 {
    unsafe { body::module_step_impl(state_ptr) }
}

// ── storage.namespace provider exports ─────────────────────────────
//
// The loader registers a contract provider by resolving these two
// symbols. Without them a manifest's `provides = ["storage.namespace"]`
// advertises a surface nothing can reach — which is what it did before
// these landed (RFC 0005 P2.8).

#[no_mangle]
#[link_section = ".text.module_provides_contract"]
pub extern "C" fn module_provides_contract() -> u32 {
    body::CONTRACT_STORAGE_NAMESPACE
}

/// # Safety
/// The loader passes this module's own state pointer and a caller
/// buffer valid for `arg_len` bytes.
#[export_name = "module_provider_dispatch"]
#[link_section = ".text.module_provider_dispatch"]
pub unsafe extern "C" fn namespace_provider_dispatch(
    state_ptr: *mut u8,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    body::provider_dispatch_impl(state_ptr, handle, opcode, arg, arg_len)
}

// Panic handler comes from `runtime.rs` via the include! above.
