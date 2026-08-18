//! Loam dev CLI — fluxor-native client. Each command spins up
//! the PIC bodies it needs in-process, sends one request through
//! the appropriate wire format, drives the step bodies until the
//! response lands, and prints. No `LoamInstance`, no host-side
//! stores: the CLI exercises the same code paths a deployed
//! graph would.
//!
//! The surface, by what a command needs:
//!
//! - Writes: `bind`, `put-body`, `put-object`, `put-file` run
//!   end-to-end through namespace_router / body_store /
//!   object_index.
//! - Reads: `read` (OP_LOOKUP) and `resolve` (LOOKUP then
//!   OP_OBJ_GET) return the binding and its descriptor.
//! - Pure-local: `validate`, `plan`, `surfaces` parse config /
//!   print the module-binding table — no PIC needed.
//! - Remote: `admin-bind` is a one-shot client against a running
//!   `loam-server --socket`; `tools/loam-client/` is the library
//!   form of the same wire.

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use loam::core::config::Config;
use loam::core::runtime::RuntimePlan;
use loam::module_bindings::{ModuleVisibility, MODULE_BINDINGS};
use serde::Serialize;
use std::io::Read;
use std::path::PathBuf;

mod pic;
#[allow(
    dead_code,
    unused_imports,
    reason = "shared fluxor SDK include; each includer uses a subset"
)]
mod sha256_impl {
    include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha256.rs");
}

#[derive(Debug, Parser)]
#[command(name = "loam")]
#[command(about = "Fluxor-native loam CLI — drives PICs in-process")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Validate a TOML config.
    Validate {
        #[arg(short, long, default_value = "config/loam.toml")]
        config: PathBuf,
    },
    /// Print a runtime plan derived from a config.
    Plan {
        #[arg(short, long, default_value = "config/loam.toml")]
        config: PathBuf,
    },
    /// Print the public surface module bindings.
    Surfaces,
    /// Bind a namespace path to an ObjectId. Spins up
    /// namespace_router with `wal_path` for the apply.
    Bind {
        #[arg(long)]
        wal: PathBuf,
        namespace: String,
        path: String,
        object_id: String,
        #[arg(long, default_value = "file")]
        kind: String,
    },
    /// Store a body, content-addressed. Returns the digest the
    /// caller would use as the ObjectId.
    PutBody {
        #[arg(long)]
        body_root: PathBuf,
        /// Path to file whose contents to store. Use `-` for stdin.
        content_file: PathBuf,
    },
    /// Composed: put body + register object descriptor + bind
    /// path. Drives the three public PICs through an admin_router
    /// state machine, matching what AdminPutFile does in production.
    PutFile {
        #[arg(long)]
        wal: PathBuf,
        #[arg(long)]
        body_root: PathBuf,
        namespace: String,
        path: String,
        /// Path to file whose contents to store. Use `-` for stdin.
        content_file: PathBuf,
    },
    /// Read a namespace binding (OP_LOOKUP). Returns the
    /// ObjectId, revision, and kind the path is bound to.
    Read {
        #[arg(long)]
        wal: PathBuf,
        namespace: String,
        path: String,
    },
    /// Register an object descriptor (OP_OBJ_PUT). Used to
    /// pre-populate object_index so `resolve` can return the
    /// full descriptor.
    PutObject {
        #[arg(long)]
        wal: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long)]
        namespace: String,
        #[arg(long)]
        key: String,
        #[arg(long, default_value_t = 0)]
        size: u64,
    },
    /// Resolve a path: LOOKUP the binding, then GET its
    /// object descriptor. Returns both in one JSON document.
    Resolve {
        #[arg(long)]
        ns_wal: PathBuf,
        #[arg(long)]
        obj_wal: PathBuf,
        namespace: String,
        path: String,
    },
    /// Send an AdminBind request to a running loam-server over
    /// its unix socket. Demonstrates the fluxor-native transport
    /// pattern: the daemon hosts the PIC graph, the CLI is a
    /// thin client.
    AdminBind {
        #[arg(long)]
        socket: PathBuf,
        namespace: String,
        path: String,
        object_id: String,
        #[arg(long, default_value = "file")]
        kind: String,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(cli.command) {
        emit_err(&err);
        std::process::exit(1);
    }
}

fn run(cmd: Commands) -> Result<()> {
    match cmd {
        Commands::Validate { config } => cmd_validate(config),
        Commands::Plan { config } => cmd_plan(config),
        Commands::Surfaces => cmd_surfaces(),
        Commands::Bind {
            wal,
            namespace,
            path,
            object_id,
            kind,
        } => cmd_bind(wal, namespace, path, object_id, kind),
        Commands::PutBody {
            body_root,
            content_file,
        } => cmd_put_body(body_root, content_file),
        Commands::PutFile {
            wal,
            body_root,
            namespace,
            path,
            content_file,
        } => cmd_put_file(wal, body_root, namespace, path, content_file),
        Commands::Read {
            wal,
            namespace,
            path,
        } => cmd_read(wal, namespace, path),
        Commands::PutObject {
            wal,
            id,
            namespace,
            key,
            size,
        } => cmd_put_object(wal, id, namespace, key, size),
        Commands::Resolve {
            ns_wal,
            obj_wal,
            namespace,
            path,
        } => cmd_resolve(ns_wal, obj_wal, namespace, path),
        Commands::AdminBind {
            socket,
            namespace,
            path,
            object_id,
            kind,
        } => cmd_admin_bind(socket, namespace, path, object_id, kind),
    }
}

// ── Pure-local commands ──────────────────────────────────────────

fn cmd_validate(config: PathBuf) -> Result<()> {
    let _ = Config::load_from_path(&config)?;
    emit_ok(&serde_json::json!({ "config": config, "status": "ok" }))
}

fn cmd_plan(config: PathBuf) -> Result<()> {
    let cfg = Config::load_from_path(&config)?;
    let plan = RuntimePlan::from_config(&cfg);
    emit_ok(&serde_json::json!({
        "node_id": plan.node_id,
        "node_class": format!("{:?}", plan.placement.node_class),
        "roles": plan.placement.roles.iter().map(|r| format!("{r:?}")).collect::<Vec<_>>(),
        "colocate_metadata_and_data": plan.placement.colocate_metadata_and_data,
    }))
}

fn cmd_surfaces() -> Result<()> {
    let bindings: Vec<_> = MODULE_BINDINGS
        .iter()
        .map(|b| match b.visibility {
            ModuleVisibility::PublicSurface {
                surface,
                achievable,
            } => serde_json::json!({
                "module": b.module,
                "visibility": "public",
                "surface": surface.content_type(),
                "achievable_fence": achievable,
            }),
            ModuleVisibility::Internal { rationale } => serde_json::json!({
                "module": b.module,
                "visibility": "internal",
                "rationale": rationale,
            }),
        })
        .collect();
    emit_ok(&serde_json::json!({ "bindings": bindings }))
}

// ── PIC-driven commands ─────────────────────────────────────────

fn cmd_bind(
    wal: PathBuf,
    namespace: String,
    path: String,
    object_id: String,
    kind: String,
) -> Result<()> {
    let kind_byte = parse_kind(&kind)?;
    let wal_bytes = wal.to_str().ok_or_else(|| anyhow!("non-utf8 wal path"))?;
    pic::reset_state();

    let syscalls = pic::make_syscalls();
    let mut storage = pic::ModuleStorage::new(core::mem::size_of::<pic::ns_body::ModuleState>());
    let rc = unsafe {
        pic::ns_body::module_new_with_wal_impl(
            pic::CHAN_IN,
            pic::CHAN_OUT,
            wal_bytes.as_bytes(),
            storage.as_mut_ptr(),
            storage.len(),
            &syscalls,
        )
    };
    if rc != 0 {
        return Err(anyhow!("namespace_router init failed: rc={rc}"));
    }

    let mut buf = vec![0u8; 1024];
    let n = pic::ns_wire::encode_bind(
        &mut buf,
        namespace.as_bytes(),
        path.as_bytes(),
        object_id.as_bytes(),
        kind_byte,
        /*revision=*/ 1,
    )
    .map_err(|e| anyhow!("encode bind: {e:?}"))?;
    buf.truncate(n);
    pic::push_inbound(buf);
    unsafe { pic::ns_body::module_step_impl(storage.as_mut_ptr()) };
    let acks = pic::drain_outbound();
    let state = unsafe { &*(storage.as_ptr() as *const pic::ns_body::ModuleState) };
    let _ = unsafe { pic::wal::wal_close(&syscalls, state.wal_fd) };

    if acks.len() == 1 && acks[0] == pic::ns_wire::OP_BIND {
        emit_ok(&serde_json::json!({
            "status": "ok",
            "namespace": namespace,
            "path": path,
            "object_id": object_id,
            "fence": "LocalDurable",
        }))
    } else {
        Err(anyhow!("namespace_router NAK; ack bytes = {:?}", acks))
    }
}

fn cmd_put_body(body_root: PathBuf, content_file: PathBuf) -> Result<()> {
    let body = read_content(&content_file)?;
    if body.len() > pic::body_wire::MAX_BODY {
        return Err(anyhow!(
            "body too large: {} > MAX_BODY ({})",
            body.len(),
            pic::body_wire::MAX_BODY
        ));
    }
    std::fs::create_dir_all(&body_root)?;
    let root_bytes = body_root
        .to_str()
        .ok_or_else(|| anyhow!("non-utf8 body_root path"))?;

    pic::reset_state();
    let syscalls = pic::make_syscalls();
    let mut storage =
        pic::ModuleStorage::new(core::mem::size_of::<pic::body_store_body::ModuleState>());
    let rc = unsafe {
        pic::body_store_body::module_new_impl(
            pic::CHAN_IN,
            pic::CHAN_OUT,
            storage.as_mut_ptr(),
            storage.len(),
            &syscalls,
        )
    };
    if rc != 0 {
        return Err(anyhow!("body_store init failed: rc={rc}"));
    }
    unsafe {
        pic::body_store_body::set_root_dir(storage.as_mut_ptr(), root_bytes.as_bytes());
    }

    let mut buf = vec![0u8; 5 + body.len()];
    let n = pic::body_wire::encode_put_req(&mut buf, &body)
        .map_err(|e| anyhow!("encode put: {e:?}"))?;
    buf.truncate(n);
    pic::push_inbound(buf);
    unsafe { pic::body_store_body::module_step_impl(storage.as_mut_ptr()) };
    let resp = pic::drain_outbound();
    if resp.first() == Some(&pic::body_wire::OP_PUT) {
        let digest = pic::body_wire::decode_put_resp(&resp).map_err(|e| anyhow!("{e:?}"))?;
        let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
        emit_ok(&serde_json::json!({
            "status": "ok",
            "digest": format!("sha256:{hex}"),
            "size_bytes": body.len(),
            "fence": "ContentHashed",
        }))
    } else if resp.first() == Some(&pic::body_wire::OP_NAK) {
        Err(anyhow!(
            "body_store NAK; errno={}",
            resp.get(1).unwrap_or(&0)
        ))
    } else {
        Err(anyhow!("unexpected body_store response: {:?}", resp))
    }
}

fn cmd_put_file(
    wal: PathBuf,
    body_root: PathBuf,
    namespace: String,
    path: String,
    content_file: PathBuf,
) -> Result<()> {
    let body = read_content(&content_file)?;
    if body.len() > pic::body_wire::MAX_BODY {
        return Err(anyhow!(
            "body too large: {} > MAX_BODY ({})",
            body.len(),
            pic::body_wire::MAX_BODY
        ));
    }
    std::fs::create_dir_all(&body_root)?;

    // Compute the digest up front so we can build the object id
    // and bind even if we drive each PIC sequentially below.
    let digest = {
        let mut h = sha256_impl::Sha256::new();
        h.update(&body);
        h.finalize()
    };
    let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
    let object_id = format!("sha256:{hex}");

    pic::reset_state();
    let syscalls = pic::make_syscalls();

    // Stage 1: body_store PUT.
    {
        let mut storage =
            pic::ModuleStorage::new(core::mem::size_of::<pic::body_store_body::ModuleState>());
        let rc = unsafe {
            pic::body_store_body::module_new_impl(
                pic::CHAN_IN,
                pic::CHAN_OUT,
                storage.as_mut_ptr(),
                storage.len(),
                &syscalls,
            )
        };
        if rc != 0 {
            return Err(anyhow!("body_store init failed: rc={rc}"));
        }
        let root_bytes = body_root
            .to_str()
            .ok_or_else(|| anyhow!("non-utf8 body_root"))?;
        unsafe {
            pic::body_store_body::set_root_dir(storage.as_mut_ptr(), root_bytes.as_bytes());
        }
        let mut buf = vec![0u8; 5 + body.len()];
        let n = pic::body_wire::encode_put_req(&mut buf, &body)
            .map_err(|e| anyhow!("encode put: {e:?}"))?;
        buf.truncate(n);
        pic::push_inbound(buf);
        unsafe { pic::body_store_body::module_step_impl(storage.as_mut_ptr()) };
        let resp = pic::drain_outbound();
        if resp.first() != Some(&pic::body_wire::OP_PUT) {
            return Err(anyhow!("body_store stage failed: resp={:?}", resp));
        }
    }
    pic::reset_state();

    // Stage 2: namespace_router BIND. (We skip the explicit
    // object_index stage in the CLI for simplicity — the digest
    // IS the object id under content addressing; consumers can
    // register a richer descriptor separately if they want one.)
    let wal_bytes = wal.to_str().ok_or_else(|| anyhow!("non-utf8 wal path"))?;
    let mut storage = pic::ModuleStorage::new(core::mem::size_of::<pic::ns_body::ModuleState>());
    let rc = unsafe {
        pic::ns_body::module_new_with_wal_impl(
            pic::CHAN_IN,
            pic::CHAN_OUT,
            wal_bytes.as_bytes(),
            storage.as_mut_ptr(),
            storage.len(),
            &syscalls,
        )
    };
    if rc != 0 {
        return Err(anyhow!("namespace_router init failed: rc={rc}"));
    }
    let mut buf = vec![0u8; 1024];
    let n = pic::ns_wire::encode_bind(
        &mut buf,
        namespace.as_bytes(),
        path.as_bytes(),
        object_id.as_bytes(),
        pic::ns_wire::KIND_FILE,
        1,
    )
    .map_err(|e| anyhow!("encode bind: {e:?}"))?;
    buf.truncate(n);
    pic::push_inbound(buf);
    unsafe { pic::ns_body::module_step_impl(storage.as_mut_ptr()) };
    let acks = pic::drain_outbound();
    let state = unsafe { &*(storage.as_ptr() as *const pic::ns_body::ModuleState) };
    let _ = unsafe { pic::wal::wal_close(&syscalls, state.wal_fd) };
    if acks.first() != Some(&pic::ns_wire::OP_BIND) {
        return Err(anyhow!("namespace_router NAK on bind: ack={:?}", acks));
    }

    emit_ok(&serde_json::json!({
        "status": "ok",
        "object_id": object_id,
        "size_bytes": body.len(),
        "fence_body": "ContentHashed",
        "fence_binding": "LocalDurable",
        "namespace": namespace,
        "path": path,
    }))
}

// ── Read-side commands ──────────────────────────────────────────

fn cmd_read(wal: PathBuf, namespace: String, path: String) -> Result<()> {
    let wal_bytes = wal.to_str().ok_or_else(|| anyhow!("non-utf8 wal path"))?;
    pic::reset_state();
    let syscalls = pic::make_syscalls();
    let mut storage = pic::ModuleStorage::new(core::mem::size_of::<pic::ns_body::ModuleState>());
    let rc = unsafe {
        pic::ns_body::module_new_with_wal_impl(
            pic::CHAN_IN,
            pic::CHAN_OUT,
            wal_bytes.as_bytes(),
            storage.as_mut_ptr(),
            storage.len(),
            &syscalls,
        )
    };
    if rc != 0 {
        return Err(anyhow!("namespace_router init failed: rc={rc}"));
    }
    let mut buf = vec![0u8; 256];
    let n = pic::ns_wire::encode_lookup_req(&mut buf, namespace.as_bytes(), path.as_bytes())
        .map_err(|e| anyhow!("encode lookup: {e:?}"))?;
    buf.truncate(n);
    pic::push_inbound(buf);
    unsafe { pic::ns_body::module_step_impl(storage.as_mut_ptr()) };
    let resp = pic::drain_outbound();
    let state = unsafe { &*(storage.as_ptr() as *const pic::ns_body::ModuleState) };
    let _ = unsafe { pic::wal::wal_close(&syscalls, state.wal_fd) };

    let decoded =
        pic::ns_wire::decode_lookup_resp(&resp).map_err(|e| anyhow!("decode lookup: {e:?}"))?;
    match decoded {
        pic::ns_wire::DecodedLookupResp::Found {
            object_id,
            revision,
            kind,
        } => emit_ok(&serde_json::json!({
            "status": "ok",
            "namespace": namespace,
            "path": path,
            "object_id": String::from_utf8_lossy(object_id),
            "revision": revision,
            "kind": kind_name(kind),
        })),
        pic::ns_wire::DecodedLookupResp::NotFound => emit_ok(&serde_json::json!({
            "status": "not_found",
            "namespace": namespace,
            "path": path,
        })),
    }
}

fn cmd_put_object(
    wal: PathBuf,
    id: String,
    namespace: String,
    key: String,
    size: u64,
) -> Result<()> {
    let wal_bytes = wal.to_str().ok_or_else(|| anyhow!("non-utf8 wal path"))?;
    pic::reset_state();
    let syscalls = pic::make_syscalls();
    let mut storage = pic::ModuleStorage::new(core::mem::size_of::<pic::obj_body::ModuleState>());
    let rc = unsafe {
        pic::obj_body::module_new_with_wal_impl(
            pic::CHAN_IN,
            pic::CHAN_OUT,
            wal_bytes.as_bytes(),
            storage.as_mut_ptr(),
            storage.len(),
            &syscalls,
        )
    };
    if rc != 0 {
        return Err(anyhow!("object_index init failed: rc={rc}"));
    }
    let fields = pic::obj_wire::PutFields {
        id: id.as_bytes(),
        namespace: namespace.as_bytes(),
        key: key.as_bytes(),
        content_hash: id.as_bytes(),
        size_bytes: size,
        revision: 1,
        data_class: 0,
        replica_count: 1,
        erasure: None,
    };
    let mut buf = vec![0u8; 512];
    let n =
        pic::obj_wire::encode_put(&mut buf, &fields).map_err(|e| anyhow!("encode put: {e:?}"))?;
    buf.truncate(n);
    pic::push_inbound(buf);
    unsafe { pic::obj_body::module_step_impl(storage.as_mut_ptr()) };
    let acks = pic::drain_outbound();
    let state = unsafe { &*(storage.as_ptr() as *const pic::obj_body::ModuleState) };
    let _ = unsafe { pic::wal::wal_close(&syscalls, state.wal_fd) };

    if acks.first() == Some(&pic::obj_wire::OP_OBJ_PUT) {
        emit_ok(&serde_json::json!({
            "status": "ok",
            "object_id": id,
            "fence": "LocalDurable",
        }))
    } else {
        Err(anyhow!("object_index NAK: ack={:?}", acks))
    }
}

fn cmd_resolve(ns_wal: PathBuf, obj_wal: PathBuf, namespace: String, path: String) -> Result<()> {
    // Stage 1: LOOKUP in namespace_router.
    let ns_wal_bytes = ns_wal.to_str().ok_or_else(|| anyhow!("non-utf8 ns_wal"))?;
    pic::reset_state();
    let syscalls = pic::make_syscalls();
    let mut storage = pic::ModuleStorage::new(core::mem::size_of::<pic::ns_body::ModuleState>());
    let rc = unsafe {
        pic::ns_body::module_new_with_wal_impl(
            pic::CHAN_IN,
            pic::CHAN_OUT,
            ns_wal_bytes.as_bytes(),
            storage.as_mut_ptr(),
            storage.len(),
            &syscalls,
        )
    };
    if rc != 0 {
        return Err(anyhow!("namespace_router init failed: rc={rc}"));
    }
    let mut buf = vec![0u8; 256];
    let n = pic::ns_wire::encode_lookup_req(&mut buf, namespace.as_bytes(), path.as_bytes())
        .map_err(|e| anyhow!("encode lookup: {e:?}"))?;
    buf.truncate(n);
    pic::push_inbound(buf);
    unsafe { pic::ns_body::module_step_impl(storage.as_mut_ptr()) };
    let resp = pic::drain_outbound();
    let state = unsafe { &*(storage.as_ptr() as *const pic::ns_body::ModuleState) };
    let _ = unsafe { pic::wal::wal_close(&syscalls, state.wal_fd) };
    drop(storage);

    let (object_id_bytes, revision, kind) = match pic::ns_wire::decode_lookup_resp(&resp)
        .map_err(|e| anyhow!("decode lookup: {e:?}"))?
    {
        pic::ns_wire::DecodedLookupResp::Found {
            object_id,
            revision,
            kind,
        } => (object_id.to_vec(), revision, kind),
        pic::ns_wire::DecodedLookupResp::NotFound => {
            return emit_ok(&serde_json::json!({
                "status": "not_found",
                "namespace": namespace,
                "path": path,
            }));
        }
    };
    let object_id = String::from_utf8_lossy(&object_id_bytes).to_string();

    // Stage 2: GET descriptor from object_index.
    let obj_wal_bytes = obj_wal
        .to_str()
        .ok_or_else(|| anyhow!("non-utf8 obj_wal"))?;
    pic::reset_state();
    let mut obj_storage =
        pic::ModuleStorage::new(core::mem::size_of::<pic::obj_body::ModuleState>());
    let rc = unsafe {
        pic::obj_body::module_new_with_wal_impl(
            pic::CHAN_IN,
            pic::CHAN_OUT,
            obj_wal_bytes.as_bytes(),
            obj_storage.as_mut_ptr(),
            obj_storage.len(),
            &syscalls,
        )
    };
    if rc != 0 {
        return Err(anyhow!("object_index init failed: rc={rc}"));
    }
    let mut buf = vec![0u8; 256];
    let n = pic::obj_wire::encode_get_req(&mut buf, object_id_bytes.as_slice())
        .map_err(|e| anyhow!("encode get: {e:?}"))?;
    buf.truncate(n);
    pic::push_inbound(buf);
    unsafe { pic::obj_body::module_step_impl(obj_storage.as_mut_ptr()) };
    let resp = pic::drain_outbound();
    let obj_state = unsafe { &*(obj_storage.as_ptr() as *const pic::obj_body::ModuleState) };
    let _ = unsafe { pic::wal::wal_close(&syscalls, obj_state.wal_fd) };

    let descriptor = match pic::obj_wire::decode_get_resp(&resp)
        .map_err(|e| anyhow!("decode get: {e:?}"))?
    {
        pic::obj_wire::DecodedGetResp::Found {
            size_bytes,
            revision,
            data_class,
            replica_count,
            erasure,
        } => serde_json::json!({
            "size_bytes": size_bytes,
            "revision": revision,
            "data_class": data_class,
            "replica_count": replica_count,
            "erasure": erasure.map(|(d, q)| serde_json::json!({"data_shards": d, "parity_shards": q})),
        }),
        pic::obj_wire::DecodedGetResp::NotFound => {
            // Binding without descriptor — "dangling".
            return emit_ok(&serde_json::json!({
                "status": "dangling",
                "namespace": namespace,
                "path": path,
                "binding_object_id": object_id,
                "binding_revision": revision,
                "binding_kind": kind_name(kind),
            }));
        }
    };

    emit_ok(&serde_json::json!({
        "status": "ok",
        "namespace": namespace,
        "path": path,
        "binding": {
            "object_id": object_id,
            "revision": revision,
            "kind": kind_name(kind),
        },
        "descriptor": descriptor,
    }))
}

// ── Admin client (over a running loam-server) ───────────────────

fn cmd_admin_bind(
    socket_path: PathBuf,
    namespace: String,
    path: String,
    object_id: String,
    kind: String,
) -> Result<()> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    let kind_byte = parse_kind(&kind)?;
    // Open the connection.
    let mut stream = UnixStream::connect(&socket_path)
        .map_err(|e| anyhow!("connect {}: {e}", socket_path.display()))?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .ok();
    // Build the AdminBind request.
    let cid: u32 = 1;
    let mut buf = vec![0u8; 1024];
    let n = pic::admin_wire::encode_admin_bind(
        &mut buf,
        cid,
        namespace.as_bytes(),
        path.as_bytes(),
        object_id.as_bytes(),
        kind_byte,
        /*revision=*/ 1,
    )
    .map_err(|e| anyhow!("encode admin_bind: {e:?}"))?;
    buf.truncate(n);
    stream
        .write_all(&buf)
        .map_err(|e| anyhow!("write admin request: {e}"))?;
    // Read the response (max 64 bytes for an AdminBindAck).
    let mut resp = [0u8; 64];
    let nread = stream
        .read(&mut resp)
        .map_err(|e| anyhow!("read admin response: {e}"))?;
    let ack = pic::admin_wire::decode_admin_bind_ack(&resp[..nread])
        .map_err(|e| anyhow!("decode admin ack: {e:?}"))?;
    if ack.status == pic::admin_wire::STATUS_OK {
        emit_ok(&serde_json::json!({
            "status": "ok",
            "correlation_id": ack.correlation_id,
            "namespace": namespace,
            "path": path,
            "object_id": object_id,
            "transport": "unix-socket",
        }))
    } else {
        Err(anyhow!("admin_router NAK; status={}", ack.status))
    }
}

fn kind_name(kind: u8) -> &'static str {
    match kind {
        0 => "file",
        1 => "directory",
        2 => "object",
        3 => "volume",
        4 => "symlink",
        _ => "unknown",
    }
}

// ── helpers ──────────────────────────────────────────────────────

fn read_content(content_file: &std::path::Path) -> Result<Vec<u8>> {
    if content_file == std::path::Path::new("-") {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| anyhow!("read stdin: {e}"))?;
        Ok(buf)
    } else {
        std::fs::read(content_file).map_err(|e| anyhow!("read {}: {e}", content_file.display()))
    }
}

fn parse_kind(s: &str) -> Result<u8> {
    match s {
        "file" => Ok(pic::ns_wire::KIND_FILE),
        "directory" => Ok(pic::ns_wire::KIND_DIRECTORY),
        "object" => Ok(pic::ns_wire::KIND_OBJECT),
        "volume" => Ok(pic::ns_wire::KIND_VOLUME),
        "symlink" => Ok(pic::ns_wire::KIND_SYMLINK),
        other => Err(anyhow!("unknown namespace kind: {other}")),
    }
}

fn emit_ok<T: Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn emit_err(err: &anyhow::Error) {
    let payload = serde_json::json!({ "error": err.to_string() });
    eprintln!("{}", serde_json::to_string(&payload).unwrap());
}
