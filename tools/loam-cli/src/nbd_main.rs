//! `loam-nbd` — export a loam block volume as an NBD device.
//!
//! A kernel (via `nbd-client`) or a hypervisor (via qemu's `nbd:`
//! driver) mounts a loam volume. The server takes the volume's writer
//! lease at start and holds it until it exits, so a second server on
//! the same volume is refused rather than allowed to race the first.
//!
//!   loam-nbd --socket /run/loam.sock --volume vol:/disks/data \
//!            --listen 127.0.0.1:10809
//!
//! Remote, with the volume backend on a different host to the
//! storage node, over mutually authenticated TLS:
//!
//!   loam-nbd --admin storage-node:7788 --tls-server-name storage-node \
//!            --tls-ca /etc/loam/ca.pem --tls-cert /etc/loam/nbd.pem \
//!            --tls-key /etc/loam/nbd.key \
//!            --volume vol:/disks/data --listen 127.0.0.1:10809

use anyhow::{anyhow, Result};
use clap::Parser;
use loam_client::{admin_wire, random_holder, ClientError, LoamClient, VolumeWriter};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[path = "nbd.rs"]
mod nbd;

#[derive(Parser, Debug)]
#[command(about = "Export a loam block volume as an NBD device")]
struct Args {
    /// Unix admin socket of the loam-server holding the volume.
    #[arg(long, conflicts_with = "admin")]
    socket: Option<PathBuf>,
    /// Remote admin surface, `host:port`, over TLS 1.3. Requires
    /// --tls-ca, --tls-cert and --tls-key.
    #[arg(long)]
    admin: Option<String>,
    /// Name the server's certificate must carry. Defaults to the host
    /// part of --admin.
    #[arg(long)]
    tls_server_name: Option<String>,
    /// PEM CA certificate(s) the server is verified against.
    #[arg(long)]
    tls_ca: Option<PathBuf>,
    /// PEM certificate chain this client presents: its name is the
    /// identity the server's grants are checked for.
    #[arg(long)]
    tls_cert: Option<PathBuf>,
    /// PEM private key for --tls-cert.
    #[arg(long)]
    tls_key: Option<PathBuf>,
    /// File holding the admin token, for a --socket server started
    /// with --admin-token.
    #[arg(long, conflicts_with = "admin")]
    token_file: Option<PathBuf>,
    /// The volume, as `namespace_root:path`.
    #[arg(long)]
    volume: String,
    /// Address to serve NBD on.
    #[arg(long, default_value = "127.0.0.1:10809")]
    listen: String,
    /// Writer lease TTL in milliseconds. The server renews it every
    /// third of this; it bounds how long a crashed server keeps the
    /// volume from its successor.
    #[arg(long, default_value_t = 30_000)]
    lease_ttl_ms: u32,
}

/// Set by SIGINT or SIGTERM: stop serving, commit what is staged, and
/// give the lease back so the next server need not wait out its TTL.
static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_stop_signal(_signum: i32) {
    STOP.store(true, Ordering::SeqCst);
}

extern "C" {
    fn signal(signum: i32, handler: extern "C" fn(i32)) -> usize;
}

const SIGINT: i32 = 2;
const SIGTERM: i32 = 15;

fn main() -> Result<()> {
    let args = Args::parse();

    let (root, path) = args
        .volume
        .split_once(':')
        .ok_or_else(|| anyhow!("--volume must be `namespace_root:path`"))?;

    let read = |p: &PathBuf| std::fs::read(p).map_err(|e| anyhow!("reading {}: {e}", p.display()));
    let mut client = match (&args.socket, &args.admin) {
        (Some(p), None) => {
            let mut c = LoamClient::connect(p)?;
            if let Some(tf) = &args.token_file {
                let token = std::fs::read_to_string(tf)
                    .map_err(|e| anyhow!("reading {}: {e}", tf.display()))?;
                c.authenticate(token.trim().as_bytes())?;
            }
            c
        }
        (None, Some(addr)) => {
            // Refused here rather than attempted-and-failed: there is no
            // remote admin surface without TLS, so a client missing its
            // credentials is misconfigured, not unlucky.
            let (Some(ca), Some(cert), Some(key)) = (&args.tls_ca, &args.tls_cert, &args.tls_key)
            else {
                return Err(anyhow!(
                    "--admin requires --tls-ca, --tls-cert and --tls-key: \
                     the remote admin surface is TLS only"
                ));
            };
            let server_name = match &args.tls_server_name {
                Some(n) => n.clone(),
                None => host_of(addr).to_string(),
            };
            LoamClient::connect_tls(
                addr.as_str(),
                &server_name,
                &read(ca)?,
                &read(cert)?,
                &read(key)?,
            )?
        }
        _ => return Err(anyhow!("pass exactly one of --socket or --admin")),
    };

    let volume = client
        .open_volume(root.as_bytes(), path.as_bytes())?
        .ok_or_else(|| anyhow!("no volume at {}:{}", root, path))?;

    let writer = match VolumeWriter::open(&mut client, volume, random_holder(), args.lease_ttl_ms) {
        Ok(w) => w,
        Err(ClientError::Nak(s)) if s == admin_wire::STATUS_LEASE_HELD => {
            return Err(anyhow!(
                "{root}:{path} is held by another writer (lease held); \
                 refusing to serve it twice"
            ))
        }
        Err(e) => return Err(e.into()),
    };

    // SAFETY: the handler only stores to an atomic, which is
    // async-signal-safe.
    unsafe {
        signal(SIGINT, on_stop_signal);
        signal(SIGTERM, on_stop_signal);
    }

    let dev: nbd::Shared = Arc::new(Mutex::new(nbd::Device { client, writer }));
    nbd::spawn_renewer(dev.clone(), args.lease_ttl_ms, &STOP);
    let served = nbd::serve(&dev, &args.listen, &STOP);

    nbd::flush_quietly(&dev, "at shutdown");
    STOP.store(true, Ordering::SeqCst);
    let mut d = dev.lock().unwrap_or_else(|p| p.into_inner());
    let nbd::Device { client, writer } = &mut *d;
    let root_b = writer.volume().namespace_root.clone();
    let path_b = writer.volume().path.clone();
    if let Err(e) = client.release_lease(&root_b, &path_b, &writer.holder()) {
        eprintln!("[loam-nbd] releasing the lease: {e}");
    }
    served
}

/// The host part of `host:port`, `[v6]:port` or a bare host.
fn host_of(addr: &str) -> &str {
    if let Some(rest) = addr.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match addr.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && port.parse::<u16>().is_ok() => host,
        _ => addr,
    }
}
