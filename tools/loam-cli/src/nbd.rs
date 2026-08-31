//! NBD server over a loam block volume — the device protocol that
//! makes the block plane mountable.
//!
//! The extent plane already has volume descriptors, derived-key
//! mutable extents, read-modify-write and replication. What NBD adds
//! is a peer a kernel can talk to, and it is the shortest honest
//! path to that: a small, stable, well-specified protocol
//! whose read / write / flush / trim map almost one-to-one onto the
//! extent API, with `nbd-client` and qemu as ready-made peers. ublk
//! is the higher-performance follow-up and needs none of this
//! rewritten — it replaces the transport, not the mapping.
//!
//! What this is NOT: a multi-writer device. Loam's extents follow a
//! one-publisher discipline, so a volume served here is
//! single-writer, and that is a property of the storage rather than
//! of this server. Two NBD clients on one volume will corrupt it,
//! which is why `--allow-multi` does not exist.
//!
//! Protocol: fixed-newstyle handshake. `NBD_OPT_EXPORT_NAME` is the
//! only option honoured; anything else is answered `ERR_UNSUP` and
//! haggling continues, which is what the spec asks for and what lets
//! a client that probes first still connect. That is deliberately
//! the smallest surface real clients use — every extra option is
//! another thing to get subtly wrong, and none of them change what
//! the device does.

use anyhow::{anyhow, Result};
use loam_client::{LoamClient, Volume};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

// ── Handshake constants (nbd protocol "fixed newstyle") ───────────

const NBD_MAGIC: u64 = 0x4e42444d41474943; // "NBDMAGIC"
const IHAVEOPT: u64 = 0x49484156454F5054; // "IHAVEOPT"
const NBD_FLAG_FIXED_NEWSTYLE: u16 = 1 << 0;
const NBD_FLAG_NO_ZEROES: u16 = 1 << 1;
const NBD_OPT_EXPORT_NAME: u32 = 1;
const NBD_OPT_ABORT: u32 = 2;
/// Option-reply framing (fixed newstyle).
const NBD_REP_MAGIC: u64 = 0x3e889045565a9;
const NBD_REP_ERR_UNSUP: u32 = 0x8000_0001;

/// Transmission flags advertised for the export.
///
/// `SEND_FLUSH` is advertised even though a loam write is durable by
/// the time it is acked: a client that believes flush is unsupported
/// may refuse to mount, and answering a flush with "done" is
/// truthful here rather than a stub. `SEND_TRIM` is NOT advertised —
/// an extent has no sparse representation to punch, and claiming
/// trim we cannot honour would be a lie a filesystem acts on.
const NBD_FLAG_HAS_FLAGS: u16 = 1 << 0;
const NBD_FLAG_SEND_FLUSH: u16 = 1 << 2;

// ── Transmission constants ────────────────────────────────────────

const NBD_REQUEST_MAGIC: u32 = 0x25609513;
const NBD_REPLY_MAGIC: u32 = 0x67446698;
const NBD_CMD_READ: u16 = 0;
const NBD_CMD_WRITE: u16 = 1;
const NBD_CMD_DISC: u16 = 2;
const NBD_CMD_FLUSH: u16 = 3;

const NBD_OK: u32 = 0;
const NBD_EIO: u32 = 5;
const NBD_EINVAL: u32 = 22;
const NBD_ENOSPC: u32 = 28;

/// Largest single read or write this server will service.
///
/// A client chooses the request size and a hostile or buggy one can
/// ask for anything a u32 holds; without a ceiling that is a 4 GiB
/// allocation on our side per request. 32 MiB is far above what any
/// real client asks (typically 128 KiB–1 MiB) and far below anything
/// that hurts.
const MAX_IO: usize = 32 * 1024 * 1024;

fn read_exact(s: &mut TcpStream, buf: &mut [u8]) -> Result<()> {
    s.read_exact(buf).map_err(|e| anyhow!("nbd read: {e}"))
}

/// Serve `volume` over NBD on `listen`, one client at a time.
///
/// Serial by construction, and that is the correct shape: the volume
/// is single-writer, so a second concurrent client is a corruption
/// waiting to happen rather than a throughput opportunity.
pub fn serve(mut client: LoamClient, volume: Volume, listen: &str) -> Result<()> {
    let listener = TcpListener::bind(listen)?;
    eprintln!(
        "[loam-nbd] serving {} bytes on {} (single-writer)",
        volume.desc.size_bytes,
        listener.local_addr()?
    );
    for conn in listener.incoming() {
        let mut s = match conn {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[loam-nbd] accept: {e}");
                continue;
            }
        };
        s.set_nodelay(true).ok();
        if let Err(e) = session(&mut client, &volume, &mut s) {
            eprintln!("[loam-nbd] session ended: {e}");
        }
    }
    Ok(())
}

/// One client: handshake, then transmission until it disconnects.
fn session(client: &mut LoamClient, vol: &Volume, s: &mut TcpStream) -> Result<()> {
    handshake(vol, s)?;
    transmission(client, vol, s)
}

fn handshake(vol: &Volume, s: &mut TcpStream) -> Result<()> {
    // Server greeting.
    s.write_all(&NBD_MAGIC.to_be_bytes())?;
    s.write_all(&IHAVEOPT.to_be_bytes())?;
    s.write_all(&(NBD_FLAG_FIXED_NEWSTYLE | NBD_FLAG_NO_ZEROES).to_be_bytes())?;
    s.flush()?;

    // Client flags.
    let mut cf = [0u8; 4];
    read_exact(s, &mut cf)?;

    // Option haggling. Only EXPORT_NAME is honoured; an ABORT ends
    // the session, and anything else is refused with ERR_UNSUP so
    // the client can try something we do support.
    loop {
        let mut hdr = [0u8; 8 + 4 + 4];
        read_exact(s, &mut hdr)?;
        if u64::from_be_bytes(hdr[0..8].try_into().unwrap()) != IHAVEOPT {
            return Err(anyhow!("client sent a malformed option header"));
        }
        let opt = u32::from_be_bytes(hdr[8..12].try_into().unwrap());
        let len = u32::from_be_bytes(hdr[12..16].try_into().unwrap()) as usize;
        if len > 4096 {
            return Err(anyhow!("option payload of {len} bytes is not credible"));
        }
        let mut payload = vec![0u8; len];
        if len > 0 {
            read_exact(s, &mut payload)?;
        }
        match opt {
            NBD_OPT_EXPORT_NAME => {
                // The export name is ignored: this server was
                // started against ONE volume, so answering any name
                // with a different device would be a surprise. The
                // volume is chosen by the operator, not the client.
                s.write_all(&vol.desc.size_bytes.to_be_bytes())?;
                s.write_all(&(NBD_FLAG_HAS_FLAGS | NBD_FLAG_SEND_FLUSH).to_be_bytes())?;
                // NO_ZEROES was advertised and the client acknowledged
                // the handshake, so the 124-byte pad is omitted.
                s.flush()?;
                return Ok(());
            }
            NBD_OPT_ABORT => return Err(anyhow!("client aborted the handshake")),
            other => {
                // Fixed newstyle says: answer an option you do not
                // implement with ERR_UNSUP and keep haggling. Ending
                // the session instead would break clients that probe
                // with an informational option first — several do —
                // and the probe is precisely how they discover what
                // this server supports.
                s.write_all(&NBD_REP_MAGIC.to_be_bytes())?;
                s.write_all(&other.to_be_bytes())?;
                s.write_all(&NBD_REP_ERR_UNSUP.to_be_bytes())?;
                s.write_all(&0u32.to_be_bytes())?;
                s.flush()?;
            }
        }
    }
}

fn reply(s: &mut TcpStream, error: u32, handle: u64) -> Result<()> {
    s.write_all(&NBD_REPLY_MAGIC.to_be_bytes())?;
    s.write_all(&error.to_be_bytes())?;
    s.write_all(&handle.to_be_bytes())?;
    Ok(())
}

fn transmission(client: &mut LoamClient, vol: &Volume, s: &mut TcpStream) -> Result<()> {
    let size = vol.desc.size_bytes;
    loop {
        let mut hdr = [0u8; 4 + 2 + 2 + 8 + 8 + 4];
        match s.read_exact(&mut hdr) {
            Ok(()) => {}
            // A client that closes without DISC is ordinary, not an
            // error worth logging as one.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(anyhow!("nbd read: {e}")),
        }
        if u32::from_be_bytes(hdr[0..4].try_into().unwrap()) != NBD_REQUEST_MAGIC {
            return Err(anyhow!("bad request magic — stream is desynchronised"));
        }
        let cmd = u16::from_be_bytes(hdr[6..8].try_into().unwrap());
        let handle = u64::from_be_bytes(hdr[8..16].try_into().unwrap());
        let offset = u64::from_be_bytes(hdr[16..24].try_into().unwrap());
        let length = u32::from_be_bytes(hdr[24..28].try_into().unwrap()) as usize;

        // Range and size checks BEFORE any allocation: `length` is
        // attacker-chosen and this is the only thing between it and
        // a multi-gigabyte Vec.
        let oversize = length > MAX_IO;
        let out_of_range = offset.saturating_add(length as u64) > size;

        match cmd {
            NBD_CMD_DISC => return Ok(()),

            NBD_CMD_FLUSH => {
                // A loam write is durable by the time it is acked, so
                // there is nothing outstanding to force. Answering OK
                // is the truth, not a stub.
                reply(s, NBD_OK, handle)?;
                s.flush()?;
            }

            NBD_CMD_READ => {
                if oversize || out_of_range {
                    reply(s, if oversize { NBD_EINVAL } else { NBD_ENOSPC }, handle)?;
                    s.flush()?;
                    continue;
                }
                let mut buf = vec![0u8; length];
                match client.volume_read(vol, offset, &mut buf) {
                    Ok(()) => {
                        reply(s, NBD_OK, handle)?;
                        s.write_all(&buf)?;
                    }
                    Err(e) => {
                        eprintln!("[loam-nbd] read {offset}+{length}: {e}");
                        reply(s, NBD_EIO, handle)?;
                    }
                }
                s.flush()?;
            }

            NBD_CMD_WRITE => {
                // The payload must be consumed even when refusing it,
                // or the next request header reads the middle of it
                // and the stream is lost. An oversize length is the
                // one case we cannot drain safely, so it ends the
                // session instead.
                if oversize {
                    return Err(anyhow!(
                        "write of {length} bytes exceeds the {MAX_IO}-byte ceiling"
                    ));
                }
                let mut data = vec![0u8; length];
                read_exact(s, &mut data)?;
                if out_of_range {
                    reply(s, NBD_ENOSPC, handle)?;
                    s.flush()?;
                    continue;
                }
                match client.volume_write(vol, offset, &data) {
                    Ok(()) => reply(s, NBD_OK, handle)?,
                    Err(e) => {
                        eprintln!("[loam-nbd] write {offset}+{length}: {e}");
                        reply(s, NBD_EIO, handle)?;
                    }
                }
                s.flush()?;
            }

            other => {
                // Unknown commands carry no payload we know how to
                // drain, so refusing and continuing would desync the
                // stream. End the session with a reason instead.
                reply(s, NBD_EINVAL, handle)?;
                s.flush()?;
                return Err(anyhow!("unsupported nbd command {other}"));
            }
        }
    }
}
