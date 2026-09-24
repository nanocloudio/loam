//! `loam-nbd` against a real loam-server: the NBD handshake and
//! transmission phase, driven by a hand-written client so the bytes
//! on the wire are checked rather than assumed.
//!
//! A real `nbd-client` would need root and a kernel module, so the
//! peer here is the protocol itself. That is the right level: what
//! matters is that a kernel WOULD be satisfied, and the way to know
//! is to send exactly what one sends.

mod support;

use loam_client::LoamClient;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use support::{announced_addr, spawn_ready, Proc};

const NBD_MAGIC: u64 = 0x4e42444d41474943;
const IHAVEOPT: u64 = 0x49484156454F5054;
const NBD_OPT_EXPORT_NAME: u32 = 1;
const NBD_REQUEST_MAGIC: u32 = 0x25609513;
const NBD_REPLY_MAGIC: u32 = 0x67446698;
const NBD_CMD_READ: u16 = 0;
const NBD_CMD_WRITE: u16 = 1;
const NBD_CMD_DISC: u16 = 2;
const NBD_CMD_FLUSH: u16 = 3;

/// Handshake as a client does, returning the export size.
fn handshake(s: &mut TcpStream) -> u64 {
    let mut magic = [0u8; 8];
    s.read_exact(&mut magic).unwrap();
    assert_eq!(u64::from_be_bytes(magic), NBD_MAGIC, "NBDMAGIC greeting");
    let mut opt = [0u8; 8];
    s.read_exact(&mut opt).unwrap();
    assert_eq!(u64::from_be_bytes(opt), IHAVEOPT);
    let mut flags = [0u8; 2];
    s.read_exact(&mut flags).unwrap();
    assert_ne!(
        u16::from_be_bytes(flags) & 1,
        0,
        "fixed newstyle advertised"
    );

    s.write_all(&0u32.to_be_bytes()).unwrap(); // client flags
    s.write_all(&IHAVEOPT.to_be_bytes()).unwrap();
    s.write_all(&NBD_OPT_EXPORT_NAME.to_be_bytes()).unwrap();
    s.write_all(&0u32.to_be_bytes()).unwrap(); // empty name
    s.flush().unwrap();

    let mut size = [0u8; 8];
    s.read_exact(&mut size).unwrap();
    let mut tflags = [0u8; 2];
    s.read_exact(&mut tflags).unwrap();
    assert_ne!(u16::from_be_bytes(tflags) & 1, 0, "HAS_FLAGS set");
    u64::from_be_bytes(size)
}

fn request(s: &mut TcpStream, cmd: u16, handle: u64, offset: u64, len: u32) {
    s.write_all(&NBD_REQUEST_MAGIC.to_be_bytes()).unwrap();
    s.write_all(&0u16.to_be_bytes()).unwrap(); // command flags
    s.write_all(&cmd.to_be_bytes()).unwrap();
    s.write_all(&handle.to_be_bytes()).unwrap();
    s.write_all(&offset.to_be_bytes()).unwrap();
    s.write_all(&len.to_be_bytes()).unwrap();
}

/// Read a reply header; returns (error, handle).
fn reply(s: &mut TcpStream) -> (u32, u64) {
    let mut hdr = [0u8; 16];
    s.read_exact(&mut hdr).unwrap();
    assert_eq!(
        u32::from_be_bytes(hdr[0..4].try_into().unwrap()),
        NBD_REPLY_MAGIC
    );
    (
        u32::from_be_bytes(hdr[4..8].try_into().unwrap()),
        u64::from_be_bytes(hdr[8..16].try_into().unwrap()),
    )
}

fn setup() -> (tempfile::TempDir, Proc, Proc, String) {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("admin.sock");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_loam-server"));
    cmd.args([
        "--socket",
        sock.to_str().unwrap(),
        "--ns-wal",
        dir.path().join("ns.wal").to_str().unwrap(),
        "--obj-wal",
        dir.path().join("obj.wal").to_str().unwrap(),
        "--fleet",
        &format!("dir:{}", dir.path().join("bodies").display()),
        "--tick-us",
        "1000",
    ]);
    let (server, _) = spawn_ready(cmd, "admin socket on");

    // Create the volume the device will front.
    let mut c = LoamClient::connect(&sock).unwrap();
    c.create_volume(b"vol", b"/disk", 64 * 1024, 4096).unwrap();
    drop(c);

    let mut ncmd = Command::new(env!("CARGO_BIN_EXE_loam-nbd"));
    ncmd.args([
        "--socket",
        sock.to_str().unwrap(),
        "--volume",
        "vol:/disk",
        "--listen",
        "127.0.0.1:0",
    ]);
    let (nbd, line) = spawn_ready(ncmd, "[loam-nbd] serving");
    (dir, server, nbd, announced_addr(&line).to_string())
}

#[test]
fn the_handshake_reports_the_volume_size() {
    let (_d, _s, _n, addr) = setup();
    let mut c = TcpStream::connect(&addr).unwrap();
    assert_eq!(
        handshake(&mut c),
        64 * 1024,
        "the export size is the volume's, so a kernel sizes the device right"
    );
    request(&mut c, NBD_CMD_DISC, 1, 0, 0);
    c.flush().unwrap();
}

#[test]
fn a_write_then_read_round_trips_through_the_extent_plane() {
    let (_d, _s, _n, addr) = setup();
    let mut c = TcpStream::connect(&addr).unwrap();
    assert_eq!(handshake(&mut c), 64 * 1024);

    // Write across an extent boundary (extent_size is 4096), which is
    // the case the read-modify-write path exists for.
    let payload: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
    request(&mut c, NBD_CMD_WRITE, 42, 4000, payload.len() as u32);
    c.write_all(&payload).unwrap();
    c.flush().unwrap();
    let (err, handle) = reply(&mut c);
    assert_eq!(err, 0, "write succeeded");
    assert_eq!(handle, 42, "the handle is echoed, so replies are matchable");

    request(&mut c, NBD_CMD_READ, 43, 4000, payload.len() as u32);
    c.flush().unwrap();
    let (err, handle) = reply(&mut c);
    assert_eq!(err, 0);
    assert_eq!(handle, 43);
    let mut got = vec![0u8; payload.len()];
    c.read_exact(&mut got).unwrap();
    assert_eq!(got, payload, "what was written is what comes back");

    // And the bytes either side are untouched — a spanning write must
    // not clobber the rest of the extents it partially covered.
    request(&mut c, NBD_CMD_READ, 44, 0, 4000);
    c.flush().unwrap();
    assert_eq!(reply(&mut c).0, 0);
    let mut head = vec![0u8; 4000];
    c.read_exact(&mut head).unwrap();
    assert!(head.iter().all(|&b| b == 0), "untouched region stays zero");

    request(&mut c, NBD_CMD_DISC, 45, 0, 0);
    c.flush().unwrap();
}

#[test]
fn flush_is_answered_because_a_loam_write_is_already_durable() {
    let (_d, _s, _n, addr) = setup();
    let mut c = TcpStream::connect(&addr).unwrap();
    handshake(&mut c);
    request(&mut c, NBD_CMD_FLUSH, 7, 0, 0);
    c.flush().unwrap();
    let (err, handle) = reply(&mut c);
    assert_eq!(err, 0, "flush is answered OK, not refused");
    assert_eq!(handle, 7);
}

#[test]
fn a_read_past_the_end_is_refused_rather_than_served() {
    let (_d, _s, _n, addr) = setup();
    let mut c = TcpStream::connect(&addr).unwrap();
    let size = handshake(&mut c);
    request(&mut c, NBD_CMD_READ, 9, size - 10, 4096);
    c.flush().unwrap();
    let (err, handle) = reply(&mut c);
    assert_ne!(err, 0, "a read past the device end must be an error");
    assert_eq!(handle, 9, "and still matchable to its request");
}

#[test]
fn a_write_past_the_end_is_refused_without_desynchronising_the_stream() {
    // The payload must be drained even when the write is refused, or
    // the next request header would be read out of the middle of it.
    // This test would hang or mis-parse if that were wrong.
    let (_d, _s, _n, addr) = setup();
    let mut c = TcpStream::connect(&addr).unwrap();
    let size = handshake(&mut c);

    let data = vec![0xAAu8; 4096];
    request(&mut c, NBD_CMD_WRITE, 11, size - 10, data.len() as u32);
    c.write_all(&data).unwrap();
    c.flush().unwrap();
    let (err, handle) = reply(&mut c);
    assert_ne!(err, 0, "refused");
    assert_eq!(handle, 11);

    // The stream is still usable: a following request is understood.
    request(&mut c, NBD_CMD_FLUSH, 12, 0, 0);
    c.flush().unwrap();
    let (err, handle) = reply(&mut c);
    assert_eq!(err, 0);
    assert_eq!(handle, 12, "the session survived the refusal");
}
