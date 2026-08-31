//! `loam-nbd` — export a loam block volume as an NBD device.
//!
//! A kernel (via `nbd-client`) or a hypervisor (via qemu's `nbd:`
//! driver) mounts what loam's extent plane already stores and
//! replicates.
//!
//!   loam-nbd --socket /run/loam.sock --volume vol:/disks/data \
//!            --listen 127.0.0.1:10809
//!
//! Remote, with the volume backend on a different host to the
//! storage node:
//!
//!   loam-nbd --admin tcp://storage-node:7788 --token-file /etc/loam.token \
//!            --volume vol:/disks/data --listen 127.0.0.1:10809

use anyhow::{anyhow, Result};
use clap::Parser;
use loam_client::LoamClient;
use std::path::PathBuf;

#[path = "nbd.rs"]
mod nbd;

#[derive(Parser, Debug)]
#[command(about = "Export a loam block volume as an NBD device")]
struct Args {
    /// Unix admin socket of the loam-server holding the volume.
    #[arg(long, conflicts_with = "admin")]
    socket: Option<PathBuf>,
    /// Remote admin surface, `tcp://host:port`. Requires --token-file.
    #[arg(long)]
    admin: Option<String>,
    /// File holding the admin token. Required with --admin.
    #[arg(long)]
    token_file: Option<PathBuf>,
    /// The volume, as `namespace_root:path`.
    #[arg(long)]
    volume: String,
    /// Address to serve NBD on.
    #[arg(long, default_value = "127.0.0.1:10809")]
    listen: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let (root, path) = args
        .volume
        .split_once(':')
        .ok_or_else(|| anyhow!("--volume must be `namespace_root:path`"))?;

    let mut client = match (&args.socket, &args.admin) {
        (Some(p), None) => LoamClient::connect(p)?,
        (None, Some(addr)) => {
            let addr = addr.strip_prefix("tcp://").unwrap_or(addr);
            let mut c = LoamClient::connect_tcp(addr)?;
            // Refused here rather than attempted-and-failed: a remote
            // admin surface without a token should not exist, so a
            // client that was not given one is misconfigured, not
            // unlucky.
            let tf = args.token_file.as_ref().ok_or_else(|| {
                anyhow!(
                    "--admin requires --token-file: the admin surface is not anonymous over TCP"
                )
            })?;
            let token = std::fs::read_to_string(tf)
                .map_err(|e| anyhow!("reading {}: {e}", tf.display()))?;
            c.authenticate(token.trim().as_bytes())?;
            c
        }
        _ => return Err(anyhow!("pass exactly one of --socket or --admin")),
    };

    let volume = client
        .open_volume(root.as_bytes(), path.as_bytes())?
        .ok_or_else(|| anyhow!("no volume at {}:{}", root, path))?;

    nbd::serve(client, volume, &args.listen)
}
