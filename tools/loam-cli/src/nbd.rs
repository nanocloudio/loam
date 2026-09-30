//! NBD server over a loam block volume — the device protocol that
//! makes the block plane mountable.
//!
//! A loam volume is a copy-on-write map of content-addressed extents,
//! committed by a fenced, revisioned bind (`loam-client`'s
//! `VolumeWriter`). What NBD adds is a peer a kernel can talk to, and
//! it maps almost one-to-one: READ reads through the writer, WRITE
//! stages, FLUSH commits. A write is durable, and visible to any other
//! reader, once a FLUSH (or a FUA write) has been answered — the
//! answer is sent only after the commit — and until then a crash
//! loses it without tearing anything already committed. The mapping
//! is independent of the transport: a faster kernel interface such as
//! ublk would replace the socket and keep all of this.
//!
//! What this is NOT: a multi-writer device. The server holds the
//! volume's writer lease for as long as it runs, renewing it in the
//! background, so a second server on the same volume is refused the
//! lease at start, and a server whose lease has passed on is refused
//! at its next commit. That is why `--allow-multi` does not exist.
//!
//! Protocol: fixed-newstyle handshake. `NBD_OPT_EXPORT_NAME` is the
//! only option honoured; anything else is answered `ERR_UNSUP` and
//! haggling continues, which is what the spec asks for and what lets
//! a client that probes first still connect. That is deliberately
//! the smallest surface real clients use — every extra option is
//! another thing to get subtly wrong, and none of them change what
//! the device does.

use anyhow::{anyhow, Result};
use loam_client::{LoamClient, VolumeWriter};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
/// `SEND_FLUSH` and `SEND_FUA`: a write is staged until a flush
/// commits it, so a client must be told it has to ask. `SEND_TRIM` is
/// NOT advertised — a trim would be a write of zeros to every extent
/// it covers, not a hole, and claiming a trim we would honour that way
/// is a performance promise a filesystem acts on.
const NBD_FLAG_HAS_FLAGS: u16 = 1 << 0;
const NBD_FLAG_SEND_FLUSH: u16 = 1 << 2;
const NBD_FLAG_SEND_FUA: u16 = 1 << 3;

/// Command flag: this write must be durable before it is answered.
const NBD_CMD_FLAG_FUA: u16 = 1 << 0;

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

/// How often an idle session looks up from its socket to see whether
/// the server is shutting down.
const IDLE_POLL: Duration = Duration::from_millis(200);

fn read_exact(s: &mut TcpStream, buf: &mut [u8]) -> Result<()> {
    s.read_exact(buf).map_err(|e| anyhow!("nbd read: {e}"))
}

/// The admin connection and the volume's one writer. Shared between the
/// session and the lease renewer; each takes it for one request.
pub struct Device {
    pub client: LoamClient,
    pub writer: VolumeWriter,
}

pub type Shared = Arc<Mutex<Device>>;

fn lock(dev: &Shared) -> std::sync::MutexGuard<'_, Device> {
    // A panic while holding it leaves nothing half-applied that a
    // later request could observe: staged writes are all or nothing
    // until a commit, so the poison is not worth a second failure.
    dev.lock().unwrap_or_else(|p| p.into_inner())
}

/// Renew the lease every third of its TTL until `stop`. A renewal the
/// server refuses ends the writer, so every later request fails rather
/// than being accepted and then refused at its commit.
pub fn spawn_renewer(dev: Shared, ttl_ms: u32, stop: &'static AtomicBool) {
    let every = Duration::from_millis((ttl_ms / 3).max(1) as u64);
    std::thread::spawn(move || {
        let mut slept = Duration::ZERO;
        while !stop.load(Ordering::SeqCst) {
            std::thread::sleep(IDLE_POLL.min(every));
            slept += IDLE_POLL.min(every);
            if slept < every {
                continue;
            }
            slept = Duration::ZERO;
            let mut d = lock(&dev);
            let Device { client, writer } = &mut *d;
            if let Err(e) = writer.renew(client) {
                eprintln!("[loam-nbd] lease renewal failed: {e}");
            }
        }
    });
}

/// Serve the device over NBD on `listen`, one client at a time, until
/// `stop` is set.
///
/// Serial by construction, and that is the correct shape: the volume
/// is single-writer, so a second concurrent client is a corruption
/// waiting to happen rather than a throughput opportunity.
pub fn serve(dev: &Shared, listen: &str, stop: &'static AtomicBool) -> Result<()> {
    let listener = TcpListener::bind(listen)?;
    listener.set_nonblocking(true)?;
    let size = lock(dev).writer.volume().size_bytes;
    eprintln!(
        "[loam-nbd] serving {} bytes on {} (single-writer, lease held)",
        size,
        listener.local_addr()?
    );
    while !stop.load(Ordering::SeqCst) {
        let mut s = match listener.accept() {
            Ok((s, _)) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            Err(e) => {
                eprintln!("[loam-nbd] accept: {e}");
                continue;
            }
        };
        s.set_nonblocking(false).ok();
        s.set_nodelay(true).ok();
        if let Err(e) = session(dev, &mut s, stop) {
            eprintln!("[loam-nbd] session ended: {e}");
        }
        // A client that went away without flushing has lost nothing it
        // was promised; committing here anyway means a disconnect never
        // throws away what an orderly shutdown would have kept.
        flush_quietly(dev, "after the session");
    }
    Ok(())
}

/// Commit whatever is staged, logging rather than failing.
pub fn flush_quietly(dev: &Shared, when: &str) {
    let mut d = lock(dev);
    let Device { client, writer } = &mut *d;
    if writer.staged_extents() == 0 {
        return;
    }
    if let Err(e) = writer.flush(client) {
        eprintln!("[loam-nbd] flush {when}: {e}");
    }
}

/// One client: handshake, then transmission until it disconnects.
fn session(dev: &Shared, s: &mut TcpStream, stop: &AtomicBool) -> Result<()> {
    let size = lock(dev).writer.volume().size_bytes;
    handshake(size, s)?;
    transmission(dev, size, s, stop)
}

fn handshake(size: u64, s: &mut TcpStream) -> Result<()> {
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
                s.write_all(&size.to_be_bytes())?;
                s.write_all(
                    &(NBD_FLAG_HAS_FLAGS | NBD_FLAG_SEND_FLUSH | NBD_FLAG_SEND_FUA).to_be_bytes(),
                )?;
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

/// Wait for the next request to start arriving, looking up every
/// `IDLE_POLL` to see whether the server is stopping. False when it is,
/// or when the client has gone.
fn await_request(s: &mut TcpStream, stop: &AtomicBool) -> Result<bool> {
    s.set_read_timeout(Some(IDLE_POLL))?;
    let mut probe = [0u8; 1];
    let ready = loop {
        if stop.load(Ordering::SeqCst) {
            break false;
        }
        match s.peek(&mut probe) {
            Ok(0) => break false,
            Ok(_) => break true,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(anyhow!("nbd read: {e}")),
        }
    };
    // A request is read whole once it starts: a timeout part-way through
    // one would lose the bytes already taken off the socket.
    s.set_read_timeout(None)?;
    Ok(ready)
}

/// Commit the staged writes and answer the result as an NBD error.
fn commit(dev: &Shared, what: &str) -> u32 {
    let mut d = lock(dev);
    let Device { client, writer } = &mut *d;
    match writer.flush(client) {
        Ok(_) => NBD_OK,
        Err(e) => {
            eprintln!("[loam-nbd] {what}: {e}");
            NBD_EIO
        }
    }
}

fn transmission(dev: &Shared, size: u64, s: &mut TcpStream, stop: &AtomicBool) -> Result<()> {
    loop {
        if !await_request(s, stop)? {
            return Ok(());
        }
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
        let flags = u16::from_be_bytes(hdr[4..6].try_into().unwrap());
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
                // Answered only once the commit has landed: OK means
                // every write before it is durable and visible.
                let err = commit(dev, "flush");
                reply(s, err, handle)?;
                s.flush()?;
            }

            NBD_CMD_READ => {
                if oversize || out_of_range {
                    reply(s, if oversize { NBD_EINVAL } else { NBD_ENOSPC }, handle)?;
                    s.flush()?;
                    continue;
                }
                let mut buf = vec![0u8; length];
                let read = {
                    let mut d = lock(dev);
                    let Device { client, writer } = &mut *d;
                    writer.read(client, offset, &mut buf)
                };
                match read {
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
                let staged = {
                    let mut d = lock(dev);
                    let Device { client, writer } = &mut *d;
                    writer.write(client, offset, &data)
                };
                let err = match staged {
                    Ok(()) if flags & NBD_CMD_FLAG_FUA != 0 => commit(dev, "fua write"),
                    Ok(()) => NBD_OK,
                    Err(e) => {
                        eprintln!("[loam-nbd] write {offset}+{length}: {e}");
                        NBD_EIO
                    }
                };
                reply(s, err, handle)?;
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
