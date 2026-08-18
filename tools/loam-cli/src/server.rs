//! `loam-server` — long-running fluxor-native loam daemon.
//!
//! Hosts a PIC graph and exposes it through up to three surfaces:
//!
//!   --socket PATH       admin channel over a unix socket (raw
//!                       loam_admin_wire frames, one per read)
//!   --s3-listen ADDR    minimal S3-compatible HTTP gateway:
//!                       PUT/GET/HEAD/DELETE /bucket/key mapped to
//!                       AdminPutFile/GetFile/DeleteFile; buckets
//!                       are namespace roots
//!   --serve-body ADDR   body node: hosts ONLY body_store and
//!                       serves its channels to a remote admin
//!                       node over the loam_net_wire TCP bridge
//!   --remote-body ADDR  admin node whose body plane lives on a
//!                       --serve-body node: the local
//!                       body_req/body_resp channels are bridged
//!                       over TCP instead of a local body_store
//!
//! The network contract (modules/common/mechanics/loam_net_wire.rs) is
//! message-per-frame channel bridging: a bridged channel pair is
//! indistinguishable from a local one to the PICs on either end.

mod runtime;

#[path = "../../../modules/common/mechanics/loam_net_wire.rs"]
mod net_wire;

// SigV4 verification; the file expects `super::sha256::Sha256`.
mod sigv4_scope {
    pub mod sha256 {
        pub use crate::runtime::sha256::Sha256;
    }
    #[path = "../sigv4.rs"]
    pub mod sigv4;
}
use sigv4_scope::sigv4;

use anyhow::{anyhow, Result};
use clap::Parser;
use runtime::admin_wire;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(name = "loam-server")]
#[command(about = "Fluxor-native loam daemon (unix-socket / S3 / net-bridge surfaces)")]
struct Args {
    /// Unix socket path for the admin surface. Removed + recreated
    /// on start.
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Namespace WAL path (created if missing).
    #[arg(long)]
    ns_wal: Option<PathBuf>,
    /// Object index WAL path (created if missing).
    #[arg(long)]
    obj_wal: Option<PathBuf>,
    /// Body root directory (created if missing).
    #[arg(long)]
    body_root: Option<PathBuf>,
    /// S3 gateway listen address (e.g. 127.0.0.1:9000).
    #[arg(long)]
    s3_listen: Option<String>,
    /// Body node: serve the local body_store's channels to a
    /// remote admin node on this address.
    #[arg(long)]
    serve_body: Option<String>,
    /// Admin node: the body fleet, comma-separated member specs —
    /// `dir:PATH` for an in-process body_store on a local root,
    /// `tcp:ADDR` for a --serve-body node bridged over
    /// loam_net_wire. Member order defines rendezvous identity.
    #[arg(long)]
    fleet: Option<String>,
    /// Replicas per body (all-must-succeed PUT). 0 = min(3, fleet).
    #[arg(long, default_value_t = 0)]
    replica_count: u8,
    /// Fanout-router scrub interval in ticks (0 = off): finds and
    /// heals under-replicated bodies across the fleet.
    #[arg(long, default_value_t = 0)]
    scrub_interval: u32,
    /// Loop tick delay in microseconds (default: 200).
    #[arg(long, default_value_t = 200)]
    tick_us: u64,
    /// Orphan-body GC interval in ticks (0 = off). Collects body
    /// blobs no namespace binding references.
    #[arg(long, default_value_t = 0)]
    gc_interval: u32,
    /// S3 credentials file: one `access_key secret bucket_scope`
    /// per line (# comments allowed). bucket_scope is `*`, an
    /// exact bucket name, or a prefix ending in `*`. When set,
    /// every S3 request MUST carry a valid SigV4 signature scoped
    /// to an allowed bucket; without it the gateway is anonymous.
    #[arg(long)]
    s3_credentials: Option<PathBuf>,
}

// ── S3 auth ────────────────────────────────────────────────────────

struct Credential {
    secret: String,
    bucket_scope: String,
}

/// None = anonymous gateway (no credentials configured).
type AuthConfig = Option<std::collections::HashMap<String, Credential>>;

fn load_credentials(
    path: &std::path::Path,
) -> Result<std::collections::HashMap<String, Credential>> {
    let text = std::fs::read_to_string(path)?;
    let mut map = std::collections::HashMap::new();
    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.split_whitespace();
        let (key, secret, scope) = (it.next(), it.next(), it.next());
        match (key, secret, scope) {
            (Some(k), Some(s), Some(sc)) => {
                map.insert(
                    k.to_string(),
                    Credential {
                        secret: s.to_string(),
                        bucket_scope: sc.to_string(),
                    },
                );
            }
            _ => {
                return Err(anyhow!(
                    "{}:{}: expected `access_key secret bucket_scope`",
                    path.display(),
                    lineno + 1
                ))
            }
        }
    }
    if map.is_empty() {
        return Err(anyhow!("{}: no credentials", path.display()));
    }
    Ok(map)
}

fn bucket_allowed(scope: &str, bucket: &str) -> bool {
    if scope == "*" {
        return true;
    }
    match scope.strip_suffix('*') {
        Some(prefix) => bucket.starts_with(prefix),
        None => bucket == scope,
    }
}

// ── Framed-stream plumbing ─────────────────────────────────────────

/// Accumulates stream bytes and yields complete frames.
struct FrameReader {
    buf: Vec<u8>,
}

impl FrameReader {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }
    fn feed(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }
    fn next(&mut self) -> Option<(u16, Vec<u8>)> {
        let (tag, len) = net_wire::decode_frame_header(&self.buf).ok()?;
        if self.buf.len() < net_wire::FRAME_HDR + len {
            return None;
        }
        let payload = self.buf[net_wire::FRAME_HDR..net_wire::FRAME_HDR + len].to_vec();
        self.buf.drain(..net_wire::FRAME_HDR + len);
        Some((tag, payload))
    }
}

fn write_frame(stream: &mut TcpStream, tag: u16, payload: &[u8]) -> std::io::Result<()> {
    let mut hdr = [0u8; net_wire::FRAME_HDR];
    net_wire::encode_frame_header(&mut hdr, tag, payload.len())
        .map_err(|_| std::io::Error::other("frame too large"))?;
    stream.set_nonblocking(false)?;
    stream.write_all(&hdr)?;
    stream.write_all(payload)?;
    stream.set_nonblocking(true)?;
    Ok(())
}

fn exchange_hello(stream: &mut TcpStream, my_role: u8) -> Result<u8> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut hello = [0u8; net_wire::HELLO_LEN];
    net_wire::encode_hello(&mut hello, my_role).map_err(|e| anyhow!("{e:?}"))?;
    stream.write_all(&hello)?;
    let mut peer = [0u8; net_wire::HELLO_LEN];
    stream.read_exact(&mut peer)?;
    let role = net_wire::decode_hello(&peer).map_err(|e| anyhow!("bad hello: {e:?}"))?;
    stream.set_read_timeout(None)?;
    stream.set_nonblocking(true)?;
    Ok(role)
}

/// Pump one bridged channel pair. `pop_out`/`out_tag` is the
/// locally-produced side; incoming frames tagged `in_tag` land via
/// `push_in`. Returns false when the connection died.
fn pump_bridge(
    stream: &mut TcpStream,
    reader: &mut FrameReader,
    out_tag: u16,
    pop_out: fn() -> Option<Vec<u8>>,
    in_tag: u16,
    push_in: fn(Vec<u8>),
) -> bool {
    while let Some(msg) = pop_out() {
        if write_frame(stream, out_tag, &msg).is_err() {
            return false;
        }
    }
    let mut chunk = [0u8; 16384];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => return false,
            Ok(n) => reader.feed(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => return false,
        }
    }
    while let Some((tag, payload)) = reader.next() {
        if tag == in_tag {
            push_in(payload);
        }
    }
    true
}

// ── Fleet member bridges (admin node ⇄ --serve-body nodes) ────────

/// One remote fleet member: its address, its live connection (None
/// while down), and a reconnect pacing counter.
struct MemberBridge {
    member: usize,
    addr: String,
    conn: Option<(TcpStream, FrameReader)>,
    retry_in: u32,
}

impl MemberBridge {
    fn connect(&mut self) {
        match TcpStream::connect(&self.addr) {
            Ok(mut stream) => match exchange_hello(&mut stream, net_wire::ROLE_BODY_CLIENT) {
                Ok(role) if role == net_wire::ROLE_BODY_SERVER => {
                    eprintln!(
                        "[loam-server] fleet member {} connected: {}",
                        self.member, self.addr
                    );
                    self.conn = Some((stream, FrameReader::new()));
                }
                _ => self.conn = None,
            },
            Err(_) => self.conn = None,
        }
    }

    /// One pump pass. A DOWN member answers every queued request
    /// with a NAK so the fanout router's fallback machinery treats
    /// it exactly like a NAK-ing store instead of hanging joins.
    fn pump(&mut self) {
        if let Some((ref mut stream, ref mut reader)) = self.conn {
            let mut alive = true;
            while let Some(msg) = runtime::pop_fleet_req(self.member) {
                if write_frame(stream, net_wire::TAG_BODY_REQ, &msg).is_err() {
                    alive = false;
                    // The request we just popped will never be
                    // answered by the peer — NAK it now.
                    let mut nak = [0u8; 2];
                    if runtime::body_wire::encode_nak(&mut nak, runtime::body_wire::ERR_IO).is_ok()
                    {
                        runtime::push_fleet_resp(self.member, nak.to_vec());
                    }
                    break;
                }
            }
            if alive {
                let mut chunk = [0u8; 16384];
                loop {
                    match stream.read(&mut chunk) {
                        Ok(0) => {
                            alive = false;
                            break;
                        }
                        Ok(n) => reader.feed(&chunk[..n]),
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(_) => {
                            alive = false;
                            break;
                        }
                    }
                }
                while let Some((tag, payload)) = reader.next() {
                    if tag == net_wire::TAG_BODY_RESP {
                        runtime::push_fleet_resp(self.member, payload);
                    }
                }
            }
            if !alive {
                eprintln!(
                    "[loam-server] fleet member {} lost ({}) — NAKing until reconnect",
                    self.member, self.addr
                );
                self.conn = None;
                self.retry_in = 2000;
            }
            return;
        }
        // Down: synthesize NAKs so joins resolve and reads fall
        // back to surviving replicas; retry the dial periodically.
        while let Some(_req) = runtime::pop_fleet_req(self.member) {
            let mut nak = [0u8; 2];
            if runtime::body_wire::encode_nak(&mut nak, runtime::body_wire::ERR_IO).is_ok() {
                runtime::push_fleet_resp(self.member, nak.to_vec());
            }
        }
        if self.retry_in == 0 {
            self.connect();
            self.retry_in = 2000;
        } else {
            self.retry_in -= 1;
        }
    }
}

// ── S3 gateway ─────────────────────────────────────────────────────

/// Bodies up to this stay in memory; larger ones spool to disk so
/// a multi-hundred-MB PUT doesn't balloon the gateway.
const SPOOL_MEM_MAX: usize = 1 << 20;
/// Chunk size for streamed admin writes and ranged reads — under
/// the body-wire single-op cap with framing headroom.
const IO_CHUNK: usize = 48 * 1024;

enum HttpBody {
    Mem(Vec<u8>),
    Spooled(tempfile::NamedTempFile, u64),
}

impl HttpBody {
    fn len(&self) -> u64 {
        match self {
            HttpBody::Mem(v) => v.len() as u64,
            HttpBody::Spooled(_, n) => *n,
        }
    }
    /// Visit the body in IO_CHUNK pieces.
    fn for_each_chunk(&mut self, mut f: impl FnMut(&[u8]) -> Result<()>) -> Result<()> {
        match self {
            HttpBody::Mem(v) => {
                for c in v.chunks(IO_CHUNK) {
                    f(c)?;
                }
                Ok(())
            }
            HttpBody::Spooled(file, len) => {
                use std::io::Seek;
                let f_ref = file.as_file_mut();
                f_ref.seek(std::io::SeekFrom::Start(0))?;
                let mut remaining = *len;
                let mut buf = vec![0u8; IO_CHUNK];
                while remaining > 0 {
                    let want = (remaining as usize).min(IO_CHUNK);
                    f_ref.read_exact(&mut buf[..want])?;
                    f(&buf[..want])?;
                    remaining -= want as u64;
                }
                Ok(())
            }
        }
    }
    fn sha256(&mut self) -> Result<[u8; 32]> {
        let mut h = runtime::sha256::Sha256::new();
        self.for_each_chunk(|c| {
            h.update(c);
            Ok(())
        })?;
        Ok(h.finalize())
    }
}

struct HttpRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: HttpBody,
}

fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 64 * 1024 {
            return Err(anyhow!("headers too large"));
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(anyhow!("connection closed mid-request"));
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_uppercase();
    let path = parts.next().unwrap_or("").to_string();
    let mut content_length = 0u64;
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().unwrap_or(0);
            }
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    let preread = &buf[header_end..];
    let body = if content_length as usize <= SPOOL_MEM_MAX {
        let mut body = preread.to_vec();
        while (body.len() as u64) < content_length {
            let n = stream.read(&mut chunk)?;
            if n == 0 {
                return Err(anyhow!("connection closed mid-body"));
            }
            body.extend_from_slice(&chunk[..n]);
        }
        body.truncate(content_length as usize);
        HttpBody::Mem(body)
    } else {
        let mut spool = tempfile::NamedTempFile::new()?;
        let mut written: u64 = 0;
        let take = (preread.len() as u64).min(content_length) as usize;
        spool.write_all(&preread[..take])?;
        written += take as u64;
        while written < content_length {
            let n = stream.read(&mut chunk)?;
            if n == 0 {
                return Err(anyhow!("connection closed mid-body"));
            }
            let take = ((content_length - written) as usize).min(n);
            spool.write_all(&chunk[..take])?;
            written += take as u64;
        }
        HttpBody::Spooled(spool, content_length)
    };
    Ok(HttpRequest {
        method,
        path,
        headers,
        body,
    })
}

fn http_respond(stream: &mut TcpStream, status: &str, headers: &[(&str, String)], body: &[u8]) {
    let mut resp = format!("HTTP/1.1 {status}\r\n");
    for (k, v) in headers {
        resp.push_str(&format!("{k}: {v}\r\n"));
    }
    resp.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

/// `/bucket/key...` → (bucket, "/key..."). Keys keep their leading
/// slash — they ARE loam namespace paths.
fn parse_object_path(path: &str) -> Option<(String, String)> {
    let trimmed = path.strip_prefix('/')?;
    let (bucket, key) = trimmed.split_once('/')?;
    if bucket.is_empty() || key.is_empty() {
        return None;
    }
    Some((bucket.to_string(), format!("/{key}")))
}

/// `/bucket` or `/bucket/` (with optional query string) → bucket.
fn parse_bucket_path(path: &str) -> Option<String> {
    let no_query = path.split('?').next().unwrap_or(path);
    let trimmed = no_query.strip_prefix('/')?.trim_end_matches('/');
    if trimmed.is_empty() || trimmed.contains('/') {
        return None;
    }
    Some(trimmed.to_string())
}

/// Minimal percent-decoding for query values (%2F and friends).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = |c: u8| -> Option<u8> {
                match c {
                    b'0'..=b'9' => Some(c - b'0'),
                    b'a'..=b'f' => Some(c - b'a' + 10),
                    b'A'..=b'F' => Some(c - b'A' + 10),
                    _ => None,
                }
            };
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// Pull `prefix` / `delimiter` out of a request path's query.
fn parse_list_query(path: &str) -> (String, Option<String>) {
    let mut prefix = String::new();
    let mut delimiter = None;
    if let Some((_, query)) = path.split_once('?') {
        for pair in query.split('&') {
            let (k, v) = match pair.split_once('=') {
                Some(kv) => kv,
                None => continue,
            };
            match k {
                "prefix" => prefix = percent_decode(v),
                "delimiter" => delimiter = Some(percent_decode(v)),
                _ => {}
            }
        }
    }
    (prefix, delimiter)
}

/// Bucket listing: page through AdminListFiles and answer with a
/// minimal S3 ListBucketResult document. Keys are the namespace
/// paths minus their leading slash; `prefix` filters, `delimiter`
/// rolls matching keys up into CommonPrefixes (the "directory"
/// view real S3 clients use).
fn handle_s3_list(port: &AdminPort, stream: &mut TcpStream, bucket: &str, raw_path: &str) {
    let (prefix, delimiter) = parse_list_query(raw_path);
    let mut keys: Vec<String> = Vec::new();
    let mut cursor = 0u32;
    loop {
        let reply = port.round_trip(|cid| {
            let mut buf = vec![0u8; bucket.len() + 64];
            let n =
                admin_wire::encode_admin_list_files(&mut buf, cid, bucket.as_bytes(), cursor, 16)
                    .ok()?;
            buf.truncate(n);
            Some(buf)
        });
        let reply = match reply {
            Some(r) => r,
            None => {
                http_respond(stream, "500 Internal Server Error", &[], b"timeout");
                return;
            }
        };
        let parsed = admin_wire::decode_admin_list_files_ack(&reply, |path| {
            let key = String::from_utf8_lossy(path)
                .trim_start_matches('/')
                .to_string();
            keys.push(key);
        });
        match parsed {
            Ok((_, status, next, _)) if status == admin_wire::STATUS_OK => {
                if next == 0 {
                    break;
                }
                cursor = next;
            }
            _ => {
                http_respond(stream, "500 Internal Server Error", &[], b"");
                return;
            }
        }
    }

    // Prefix filter, then delimiter roll-up.
    keys.retain(|k| k.starts_with(&prefix));
    keys.sort();
    let mut contents: Vec<String> = Vec::new();
    let mut common: Vec<String> = Vec::new();
    match &delimiter {
        Some(d) if !d.is_empty() => {
            for key in &keys {
                let rest = &key[prefix.len()..];
                match rest.find(d.as_str()) {
                    Some(pos) => {
                        let cp = format!("{}{}{}", prefix, &rest[..pos], d);
                        if common.last() != Some(&cp) {
                            common.push(cp);
                        }
                    }
                    None => contents.push(key.clone()),
                }
            }
        }
        _ => contents = keys,
    }

    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
    );
    xml.push_str(&format!(
        "<Name>{bucket}</Name><Prefix>{prefix}</Prefix><KeyCount>{}</KeyCount><IsTruncated>false</IsTruncated>",
        contents.len() + common.len()
    ));
    if let Some(d) = &delimiter {
        xml.push_str(&format!("<Delimiter>{d}</Delimiter>"));
    }
    for key in &contents {
        xml.push_str(&format!("<Contents><Key>{key}</Key></Contents>"));
    }
    for cp in &common {
        xml.push_str(&format!(
            "<CommonPrefixes><Prefix>{cp}</Prefix></CommonPrefixes>"
        ));
    }
    xml.push_str("</ListBucketResult>");
    let headers = [("Content-Type", "application/xml".to_string())];
    http_respond(stream, "200 OK", &headers, xml.as_bytes());
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn hex_of(digest: &[u8]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// One admin request from an S3 worker thread to the graph loop.
/// The reply comes back correlation-routed.
struct AdminJob {
    cid: u32,
    frame: Vec<u8>,
    reply: std::sync::mpsc::Sender<Vec<u8>>,
}

/// S3 workers' handle onto the single-threaded PIC graph: frames
/// go through an mpsc into the main loop, replies are routed back
/// by correlation id. S3 cids live in the high half of the id
/// space so they can never collide with unix-socket clients'.
#[derive(Clone)]
struct AdminPort {
    tx: std::sync::mpsc::Sender<AdminJob>,
    cid_counter: std::sync::Arc<std::sync::atomic::AtomicU32>,
}

const S3_CID_BASE: u32 = 0x8000_0000;

// ── Multipart uploads ──────────────────────────────────────────────
//
// Parts spool on the gateway host (tempfiles); Complete streams the
// ordered concatenation through the digest-first PutFile path, so
// the storage plane only ever sees one whole object. The ETag is
// loam's content digest (sha256), same as every other write path.

struct MultipartPart {
    file: tempfile::NamedTempFile,
    len: u64,
}

struct MultipartUpload {
    bucket: String,
    key: String,
    parts: std::collections::BTreeMap<u32, MultipartPart>,
}

type MultipartTable =
    std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, MultipartUpload>>>;

/// First query parameter named `name`; `Some("")` for a bare flag
/// (`?uploads`).
fn query_param(raw_path: &str, name: &str) -> Option<String> {
    let query = raw_path.split_once('?').map(|(_, q)| q)?;
    query.split('&').find_map(|p| {
        if p == name {
            Some(String::new())
        } else {
            p.strip_prefix(name)
                .and_then(|r| r.strip_prefix('='))
                .map(str::to_string)
        }
    })
}

impl AdminPort {
    /// Build a frame with a fresh cid, submit it, await the reply.
    fn round_trip(&self, build: impl FnOnce(u32) -> Option<Vec<u8>>) -> Option<Vec<u8>> {
        let cid = S3_CID_BASE
            | (self
                .cid_counter
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                & !S3_CID_BASE);
        let frame = build(cid)?;
        let (rtx, rrx) = std::sync::mpsc::channel();
        self.tx
            .send(AdminJob {
                cid,
                frame,
                reply: rtx,
            })
            .ok()?;
        rrx.recv_timeout(Duration::from_secs(30)).ok()
    }
}

fn handle_s3_request(
    port: &AdminPort,
    auth: &std::sync::Arc<AuthConfig>,
    multiparts: &MultipartTable,
    stream: &mut TcpStream,
) {
    let mut req = match read_http_request(stream) {
        Ok(r) => r,
        Err(_) => {
            http_respond(stream, "400 Bad Request", &[], b"");
            return;
        }
    };
    let path_only = req.path.split('?').next().unwrap_or(&req.path).to_string();

    // ── SigV4 gate. The whole surface is authenticated when
    // credentials are configured; per-key bucket scopes are the
    // tenancy boundary. ──────────────────────────────────────────
    if let Some(creds) = auth.as_ref() {
        let bucket_for_auth = parse_object_path(&path_only)
            .map(|(b, _)| b)
            .or_else(|| parse_bucket_path(&req.path));
        let body_hash = match req.body.sha256() {
            Ok(d) => hex_of(&d),
            Err(_) => {
                http_respond(stream, "500 Internal Server Error", &[], b"spool");
                return;
            }
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let verdict = sigv4::verify(
            &req.method,
            &req.path,
            &req.headers,
            &body_hash,
            now,
            |key_id| creds.get(key_id).map(|c| c.secret.clone()),
        );
        let key_id = match verdict {
            Ok(k) => k,
            Err(e) => {
                http_respond(
                    stream,
                    "403 Forbidden",
                    &[],
                    format!("signature rejected: {e:?}").as_bytes(),
                );
                return;
            }
        };
        if let Some(bucket) = &bucket_for_auth {
            let scope = &creds[&key_id].bucket_scope;
            if !bucket_allowed(scope, bucket) {
                http_respond(stream, "403 Forbidden", &[], b"bucket not in key scope");
                return;
            }
        }
    }
    let (bucket, key) = match parse_object_path(&path_only) {
        Some(v) => v,
        None => {
            // `GET /bucket` (no key) is a bucket listing.
            if let Some(bucket) = parse_bucket_path(&req.path) {
                if req.method == "GET" {
                    handle_s3_list(port, stream, &bucket, &req.path);
                    return;
                }
            }
            http_respond(stream, "400 Bad Request", &[], b"invalid object path");
            return;
        }
    };

    // ── Multipart routing (uploadId / uploads query params). The
    // SigV4 gate above already covered these (the signature signs
    // the query string) and bucket scope applied. ──
    if req.method == "POST" && query_param(&req.path, "uploads").is_some() {
        s3_multipart_create(multiparts, stream, &bucket, &key);
        return;
    }
    if let Some(upload_id) = query_param(&req.path, "uploadId") {
        match req.method.as_str() {
            "PUT" => {
                let part_number =
                    query_param(&req.path, "partNumber").and_then(|n| n.parse::<u32>().ok());
                match part_number {
                    Some(n) if (1..=10_000).contains(&n) => {
                        s3_multipart_upload_part(
                            multiparts,
                            stream,
                            &bucket,
                            &key,
                            &upload_id,
                            n,
                            &mut req.body,
                        );
                    }
                    _ => http_respond(stream, "400 Bad Request", &[], b"bad partNumber"),
                }
            }
            "POST" => s3_multipart_complete(
                port,
                multiparts,
                stream,
                &bucket,
                &key,
                &upload_id,
                &mut req.body,
            ),
            "DELETE" => s3_multipart_abort(multiparts, stream, &bucket, &key, &upload_id),
            _ => http_respond(stream, "405 Method Not Allowed", &[], b""),
        }
        return;
    }

    match req.method.as_str() {
        "PUT" => {
            let total = req.body.len();
            if total as usize <= IO_CHUNK {
                // Small object: one composed PutFile frame.
                let mut small = Vec::new();
                let _ = req.body.for_each_chunk(|c| {
                    small.extend_from_slice(c);
                    Ok(())
                });
                let reply = port.round_trip(|cid| {
                    let mut buf = vec![0u8; small.len() + bucket.len() + key.len() + 64];
                    let n = admin_wire::encode_admin_put_file(
                        &mut buf,
                        cid,
                        bucket.as_bytes(),
                        key.as_bytes(),
                        0,
                        now_millis(),
                        &small,
                    )
                    .ok()?;
                    buf.truncate(n);
                    Some(buf)
                });
                match reply {
                    Some(reply) => match admin_wire::decode_admin_put_file_ack(&reply) {
                        Ok((_, status, Some(digest))) if status == admin_wire::STATUS_OK => {
                            let etag = format!("\"{}\"", hex_of(digest));
                            http_respond(stream, "200 OK", &[("ETag", etag)], b"");
                        }
                        _ => http_respond(stream, "500 Internal Server Error", &[], b""),
                    },
                    None => http_respond(stream, "500 Internal Server Error", &[], b"timeout"),
                }
                return;
            }
            // Large object: digest-first streamed put.
            let digest = match req.body.sha256() {
                Ok(d) => d,
                Err(_) => {
                    http_respond(stream, "500 Internal Server Error", &[], b"spool");
                    return;
                }
            };
            let open = port.round_trip(|cid| {
                let mut buf = vec![0u8; bucket.len() + key.len() + 128];
                let n = admin_wire::encode_put_file_open(
                    &mut buf,
                    cid,
                    bucket.as_bytes(),
                    key.as_bytes(),
                    0,
                    now_millis(),
                    &digest,
                    total,
                )
                .ok()?;
                buf.truncate(n);
                Some(buf)
            });
            let pfid = match open.and_then(|r| admin_wire::decode_put_file_open_ack(&r).ok()) {
                Some((_, status, pfid)) if status == admin_wire::STATUS_OK => pfid,
                _ => {
                    http_respond(stream, "500 Internal Server Error", &[], b"open");
                    return;
                }
            };
            let mut chunks_ok = true;
            let stream_res = req.body.for_each_chunk(|chunk| {
                let reply = port.round_trip(|cid| {
                    let mut buf = vec![0u8; chunk.len() + 32];
                    let n = admin_wire::encode_put_file_chunk(&mut buf, cid, pfid, chunk).ok()?;
                    buf.truncate(n);
                    Some(buf)
                });
                match reply.and_then(|r| admin_wire::decode_put_file_chunk_ack(&r).ok()) {
                    Some((_, status)) if status == admin_wire::STATUS_OK => Ok(()),
                    _ => {
                        chunks_ok = false;
                        Err(anyhow!("chunk refused"))
                    }
                }
            });
            if stream_res.is_err() || !chunks_ok {
                http_respond(stream, "500 Internal Server Error", &[], b"chunk");
                return;
            }
            let commit = port.round_trip(|cid| {
                let mut buf = vec![0u8; 16];
                let n = admin_wire::encode_put_file_commit(&mut buf, cid, pfid).ok()?;
                buf.truncate(n);
                Some(buf)
            });
            match commit.as_deref().map(admin_wire::decode_admin_put_file_ack) {
                Some(Ok((_, status, Some(d)))) if status == admin_wire::STATUS_OK => {
                    let etag = format!("\"{}\"", hex_of(d));
                    http_respond(stream, "200 OK", &[("ETag", etag)], b"");
                }
                _ => http_respond(stream, "500 Internal Server Error", &[], b"commit"),
            }
        }
        "GET" | "HEAD" => {
            // Size first (STAT = ns lookup + body HEAD), then pick
            // whole-object or ranged streaming.
            let stat = port.round_trip(|cid| {
                let mut buf = vec![0u8; bucket.len() + key.len() + 64];
                let n =
                    admin_wire::encode_stat_file(&mut buf, cid, bucket.as_bytes(), key.as_bytes())
                        .ok()?;
                buf.truncate(n);
                Some(buf)
            });
            let size = match stat.and_then(|r| admin_wire::decode_stat_file_ack(&r).ok()) {
                Some((_, status, size)) if status == admin_wire::STATUS_OK => size,
                Some((_, status, _)) if status == admin_wire::STATUS_NOT_FOUND => {
                    http_respond(stream, "404 Not Found", &[], b"");
                    return;
                }
                _ => {
                    http_respond(stream, "500 Internal Server Error", &[], b"stat");
                    return;
                }
            };
            if req.method == "HEAD" {
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {size}\r\nConnection: close\r\n\r\n"
                );
                let _ = stream.write_all(resp.as_bytes());
                return;
            }
            if size as usize <= IO_CHUNK {
                let reply = port.round_trip(|cid| {
                    let mut buf = vec![0u8; bucket.len() + key.len() + 64];
                    let n = admin_wire::encode_admin_get_file(
                        &mut buf,
                        cid,
                        bucket.as_bytes(),
                        key.as_bytes(),
                    )
                    .ok()?;
                    buf.truncate(n);
                    Some(buf)
                });
                match reply {
                    Some(reply) => match admin_wire::decode_admin_get_file_ack(&reply) {
                        Ok((_, status, Some(body))) if status == admin_wire::STATUS_OK => {
                            let headers =
                                [("Content-Type", "application/octet-stream".to_string())];
                            http_respond(stream, "200 OK", &headers, body);
                        }
                        Ok((_, status, _)) if status == admin_wire::STATUS_NOT_FOUND => {
                            http_respond(stream, "404 Not Found", &[], b"");
                        }
                        _ => http_respond(stream, "500 Internal Server Error", &[], b""),
                    },
                    None => http_respond(stream, "500 Internal Server Error", &[], b"timeout"),
                }
                return;
            }
            // Large object: write headers, then stream ranges
            // straight onto the socket.
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {size}\r\nConnection: close\r\n\r\n"
            );
            if stream.write_all(head.as_bytes()).is_err() {
                return;
            }
            let mut off: u64 = 0;
            while off < size {
                let want = ((size - off) as usize).min(IO_CHUNK) as u32;
                let reply = port.round_trip(|cid| {
                    let mut buf = vec![0u8; bucket.len() + key.len() + 64];
                    let n = admin_wire::encode_read_file_range(
                        &mut buf,
                        cid,
                        off,
                        want,
                        bucket.as_bytes(),
                        key.as_bytes(),
                    )
                    .ok()?;
                    buf.truncate(n);
                    Some(buf)
                });
                let done = match reply {
                    Some(reply) => match admin_wire::decode_read_file_range_ack(&reply) {
                        Ok((_, status, Some(bytes)))
                            if status == admin_wire::STATUS_OK && !bytes.is_empty() =>
                        {
                            if stream.write_all(bytes).is_err() {
                                true
                            } else {
                                off += bytes.len() as u64;
                                false
                            }
                        }
                        _ => true, // error or EOF mid-stream: connection just closes short
                    },
                    None => true,
                };
                if done {
                    break;
                }
            }
            let _ = stream.flush();
        }
        "DELETE" => {
            let reply = port.round_trip(|cid| {
                let mut buf = vec![0u8; bucket.len() + key.len() + 64];
                let n = admin_wire::encode_admin_delete_file(
                    &mut buf,
                    cid,
                    bucket.as_bytes(),
                    key.as_bytes(),
                )
                .ok()?;
                buf.truncate(n);
                Some(buf)
            });
            match reply {
                // S3 semantics: DELETE of a missing key is still 204.
                Some(reply) if admin_wire::decode_admin_delete_file_ack(&reply).is_ok() => {
                    http_respond(stream, "204 No Content", &[], b"");
                }
                _ => http_respond(stream, "500 Internal Server Error", &[], b""),
            }
        }
        _ => http_respond(stream, "405 Method Not Allowed", &[], b""),
    }
}

// ── Multipart handlers ─────────────────────────────────────────────

fn s3_multipart_create(
    multiparts: &MultipartTable,
    stream: &mut TcpStream,
    bucket: &str,
    key: &str,
) {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seed = format!(
        "{bucket}/{key}/{}/{}",
        now_millis(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let mut h = runtime::sha256::Sha256::new();
    h.update(seed.as_bytes());
    let upload_id = hex_of(&h.finalize());
    multiparts.lock().unwrap().insert(
        upload_id.clone(),
        MultipartUpload {
            bucket: bucket.to_string(),
            key: key.to_string(),
            parts: Default::default(),
        },
    );
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <InitiateMultipartUploadResult>\
         <Bucket>{bucket}</Bucket><Key>{key}</Key>\
         <UploadId>{upload_id}</UploadId>\
         </InitiateMultipartUploadResult>"
    );
    http_respond(
        stream,
        "200 OK",
        &[("Content-Type", "application/xml".to_string())],
        xml.as_bytes(),
    );
}

/// Look up an upload and check it belongs to (bucket, key); a valid
/// uploadId presented against a different object is a client error,
/// not a way to write across objects.
fn multipart_matches(u: &MultipartUpload, bucket: &str, key: &str) -> bool {
    u.bucket == bucket && u.key == key
}

fn s3_multipart_upload_part(
    multiparts: &MultipartTable,
    stream: &mut TcpStream,
    bucket: &str,
    key: &str,
    upload_id: &str,
    part_number: u32,
    body: &mut HttpBody,
) {
    {
        let table = multiparts.lock().unwrap();
        match table.get(upload_id) {
            Some(u) if multipart_matches(u, bucket, key) => {}
            _ => {
                http_respond(stream, "404 Not Found", &[], b"no such upload");
                return;
            }
        }
    }
    // Spool the part OUTSIDE the table lock — parts are big and
    // uploads are concurrent.
    let mut file = match tempfile::NamedTempFile::new() {
        Ok(f) => f,
        Err(_) => {
            http_respond(stream, "500 Internal Server Error", &[], b"spool");
            return;
        }
    };
    let mut h = runtime::sha256::Sha256::new();
    let mut len = 0u64;
    let spooled = body.for_each_chunk(|c| {
        use std::io::Write as _;
        h.update(c);
        len += c.len() as u64;
        file.as_file_mut().write_all(c)?;
        Ok(())
    });
    if spooled.is_err() {
        http_respond(stream, "500 Internal Server Error", &[], b"spool");
        return;
    }
    let etag = format!("\"{}\"", hex_of(&h.finalize()));
    let mut table = multiparts.lock().unwrap();
    match table.get_mut(upload_id) {
        Some(u) if multipart_matches(u, bucket, key) => {
            // Same part re-uploaded replaces the old spool (S3
            // last-write-wins per part).
            u.parts.insert(part_number, MultipartPart { file, len });
            http_respond(stream, "200 OK", &[("ETag", etag)], b"");
        }
        _ => http_respond(stream, "404 Not Found", &[], b"upload vanished"),
    }
}

fn s3_multipart_complete(
    port: &AdminPort,
    multiparts: &MultipartTable,
    stream: &mut TcpStream,
    bucket: &str,
    key: &str,
    upload_id: &str,
    body: &mut HttpBody,
) {
    // Unknown upload first: 404 is the truthful answer no matter
    // what the request body says.
    {
        let table = multiparts.lock().unwrap();
        match table.get(upload_id) {
            Some(u) if multipart_matches(u, bucket, key) => {}
            _ => {
                http_respond(stream, "404 Not Found", &[], b"no such upload");
                return;
            }
        }
    }
    // The CompleteMultipartUpload XML names the parts (and their
    // order is required ascending). Minimal parse: the PartNumber
    // values, in document order.
    let mut xml = Vec::new();
    if body
        .for_each_chunk(|c| {
            xml.extend_from_slice(c);
            Ok(())
        })
        .is_err()
    {
        http_respond(stream, "400 Bad Request", &[], b"body");
        return;
    }
    let xml = String::from_utf8_lossy(&xml);
    let mut listed: Vec<u32> = Vec::new();
    let mut rest = xml.as_ref();
    while let Some(pos) = rest.find("<PartNumber>") {
        rest = &rest[pos + "<PartNumber>".len()..];
        let end = match rest.find('<') {
            Some(e) => e,
            None => break,
        };
        match rest[..end].trim().parse::<u32>() {
            Ok(n) => listed.push(n),
            Err(_) => {
                http_respond(stream, "400 Bad Request", &[], b"bad PartNumber");
                return;
            }
        }
    }
    if listed.is_empty() || listed.windows(2).any(|w| w[0] >= w[1]) {
        http_respond(
            stream,
            "400 Bad Request",
            &[],
            b"parts must be listed ascending",
        );
        return;
    }
    // Take the upload out of the table (holding the lock only for
    // the removal); a failed commit below drops the spools — the
    // client retries the whole upload, matching the all-or-nothing
    // storage-plane commit.
    let upload = {
        let mut table = multiparts.lock().unwrap();
        match table.get(upload_id) {
            Some(u) if multipart_matches(u, bucket, key) => table.remove(upload_id).unwrap(),
            _ => {
                http_respond(stream, "404 Not Found", &[], b"no such upload");
                return;
            }
        }
    };
    if listed.iter().any(|n| !upload.parts.contains_key(n)) {
        http_respond(stream, "400 Bad Request", &[], b"unknown part listed");
        return;
    }
    // Whole-object size + digest over the listed parts in order —
    // digest-first is what the streamed storage path requires, so
    // Complete reads every spool twice (hash, then send).
    let total: u64 = listed.iter().map(|n| upload.parts[n].len).sum();
    let mut h = runtime::sha256::Sha256::new();
    let read_part = |p: &MultipartPart, f: &mut dyn FnMut(&[u8]) -> bool| -> bool {
        use std::io::{Read as _, Seek as _};
        let file = match p.file.reopen() {
            Ok(f) => f,
            Err(_) => return false,
        };
        let mut file = file;
        if file.seek(std::io::SeekFrom::Start(0)).is_err() {
            return false;
        }
        let mut remaining = p.len;
        let mut buf = vec![0u8; IO_CHUNK];
        while remaining > 0 {
            let want = (remaining as usize).min(IO_CHUNK);
            if file.read_exact(&mut buf[..want]).is_err() {
                return false;
            }
            if !f(&buf[..want]) {
                return false;
            }
            remaining -= want as u64;
        }
        true
    };
    for n in &listed {
        if !read_part(&upload.parts[n], &mut |c| {
            h.update(c);
            true
        }) {
            http_respond(stream, "500 Internal Server Error", &[], b"spool read");
            return;
        }
    }
    let digest = h.finalize();

    // Stream into the storage plane: open(digest, total) → chunks
    // in listed-part order → commit.
    let open = port.round_trip(|cid| {
        let mut buf = vec![0u8; bucket.len() + key.len() + 128];
        let n = admin_wire::encode_put_file_open(
            &mut buf,
            cid,
            bucket.as_bytes(),
            key.as_bytes(),
            0,
            now_millis(),
            &digest,
            total,
        )
        .ok()?;
        buf.truncate(n);
        Some(buf)
    });
    let pfid = match open.and_then(|r| admin_wire::decode_put_file_open_ack(&r).ok()) {
        Some((_, status, pfid)) if status == admin_wire::STATUS_OK => pfid,
        _ => {
            http_respond(stream, "500 Internal Server Error", &[], b"open");
            return;
        }
    };
    let mut ok = true;
    'outer: for n in &listed {
        if !read_part(&upload.parts[n], &mut |chunk| {
            let reply = port.round_trip(|cid| {
                let mut buf = vec![0u8; chunk.len() + 32];
                let n = admin_wire::encode_put_file_chunk(&mut buf, cid, pfid, chunk).ok()?;
                buf.truncate(n);
                Some(buf)
            });
            matches!(
                reply.and_then(|r| admin_wire::decode_put_file_chunk_ack(&r).ok()),
                Some((_, status)) if status == admin_wire::STATUS_OK
            )
        }) {
            ok = false;
            break 'outer;
        }
    }
    if !ok {
        http_respond(stream, "500 Internal Server Error", &[], b"chunk");
        return;
    }
    let commit = port.round_trip(|cid| {
        let mut buf = vec![0u8; 16];
        let n = admin_wire::encode_put_file_commit(&mut buf, cid, pfid).ok()?;
        buf.truncate(n);
        Some(buf)
    });
    match commit.as_deref().map(admin_wire::decode_admin_put_file_ack) {
        Some(Ok((_, status, Some(d)))) if status == admin_wire::STATUS_OK => {
            let etag = hex_of(d);
            let xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                 <CompleteMultipartUploadResult>\
                 <Bucket>{bucket}</Bucket><Key>{key}</Key>\
                 <ETag>\"{etag}\"</ETag>\
                 </CompleteMultipartUploadResult>"
            );
            http_respond(
                stream,
                "200 OK",
                &[("Content-Type", "application/xml".to_string())],
                xml.as_bytes(),
            );
        }
        _ => http_respond(stream, "500 Internal Server Error", &[], b"commit"),
    }
}

fn s3_multipart_abort(
    multiparts: &MultipartTable,
    stream: &mut TcpStream,
    bucket: &str,
    key: &str,
    upload_id: &str,
) {
    let mut table = multiparts.lock().unwrap();
    match table.get(upload_id) {
        Some(u) if multipart_matches(u, bucket, key) => {
            table.remove(upload_id);
            http_respond(stream, "204 No Content", &[], b"");
        }
        _ => http_respond(stream, "404 Not Found", &[], b"no such upload"),
    }
}

// ── Main ───────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let args = Args::parse();

    let body_node = args.serve_body.is_some();
    if body_node && (args.socket.is_some() || args.s3_listen.is_some() || args.fleet.is_some()) {
        return Err(anyhow!("--serve-body is exclusive with admin surfaces"));
    }
    if !body_node && args.fleet.is_none() {
        return Err(anyhow!(
            "admin node needs --fleet (e.g. --fleet dir:/var/lib/loam/bodies or --fleet tcp:nodeB:7100,tcp:nodeC:7100)"
        ));
    }

    let mut server = runtime::Server::new()?;

    // ── Body node: body_store + net bridge, nothing else. ───────
    if let Some(addr) = &args.serve_body {
        let body_root = args
            .body_root
            .as_ref()
            .ok_or_else(|| anyhow!("--serve-body needs --body-root"))?;
        std::fs::create_dir_all(body_root)?;
        server.spin_up_body_only(body_root.to_str().ok_or_else(|| anyhow!("non-utf8"))?)?;
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        eprintln!(
            "[loam-server] body-serve listening on {}",
            listener.local_addr()?
        );
        let tick = Duration::from_micros(args.tick_us);
        let mut conn: Option<(TcpStream, FrameReader)> = None;
        loop {
            if conn.is_none() {
                match listener.accept() {
                    Ok((mut stream, peer)) => {
                        match exchange_hello(&mut stream, net_wire::ROLE_BODY_SERVER) {
                            Ok(role) if role == net_wire::ROLE_BODY_CLIENT => {
                                eprintln!("[loam-server] body client connected: {peer}");
                                conn = Some((stream, FrameReader::new()));
                            }
                            _ => eprintln!("[loam-server] rejected peer {peer}"),
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => {}
                }
            }
            if let Some((ref mut stream, ref mut reader)) = conn {
                let alive = pump_bridge(
                    stream,
                    reader,
                    net_wire::TAG_BODY_RESP,
                    runtime::pop_body_resp,
                    net_wire::TAG_BODY_REQ,
                    runtime::push_body_req,
                );
                if !alive {
                    eprintln!("[loam-server] body client disconnected");
                    conn = None;
                }
            }
            server.tick_once();
            std::thread::sleep(tick);
        }
    }

    // ── Admin node. ─────────────────────────────────────────────
    let ns_wal = args.ns_wal.ok_or_else(|| anyhow!("need --ns-wal"))?;
    let obj_wal = args.obj_wal.ok_or_else(|| anyhow!("need --obj-wal"))?;
    if let Some(parent) = ns_wal.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    if let Some(parent) = obj_wal.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let ns_wal_str = ns_wal.to_str().ok_or_else(|| anyhow!("non-utf8 ns_wal"))?;
    let obj_wal_str = obj_wal
        .to_str()
        .ok_or_else(|| anyhow!("non-utf8 obj_wal"))?;

    // ── Fleet: parse specs, spin up locals, bridge remotes. ─────
    let specs: Vec<String> = args
        .fleet
        .as_ref()
        .unwrap()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if specs.is_empty() || specs.len() > runtime::MAX_SERVER_FLEET {
        return Err(anyhow!(
            "fleet size {} out of range 1..={}",
            specs.len(),
            runtime::MAX_SERVER_FLEET
        ));
    }
    let mut local_members: Vec<(usize, String)> = Vec::new();
    let mut member_bridges: Vec<MemberBridge> = Vec::new();
    for (i, spec) in specs.iter().enumerate() {
        if let Some(path) = spec.strip_prefix("dir:") {
            std::fs::create_dir_all(path)?;
            local_members.push((i, path.to_string()));
        } else if let Some(addr) = spec.strip_prefix("tcp:") {
            member_bridges.push(MemberBridge {
                member: i,
                addr: addr.to_string(),
                conn: None,
                retry_in: 0,
            });
        } else {
            return Err(anyhow!(
                "fleet spec '{spec}': expected dir:PATH or tcp:ADDR"
            ));
        }
    }
    let replica_count = if args.replica_count == 0 {
        (specs.len() as u8).min(3)
    } else {
        args.replica_count.min(specs.len() as u8)
    };
    server.spin_up_pics_fleet(
        ns_wal_str,
        obj_wal_str,
        &local_members,
        specs.len(),
        replica_count,
        args.scrub_interval,
    )?;
    eprintln!(
        "[loam-server] fleet: {} member(s) ({} local, {} remote), replica_count {}",
        specs.len(),
        local_members.len(),
        member_bridges.len(),
        replica_count
    );
    for b in &mut member_bridges {
        b.connect();
    }
    server.set_gc_interval(args.gc_interval);
    if args.gc_interval != 0 {
        eprintln!("[loam-server] orphan GC every {} ticks", args.gc_interval);
    }
    eprintln!("[loam-server] PICs spun up");

    let unix_listener = match &args.socket {
        Some(path) => {
            if path.exists() {
                std::fs::remove_file(path).ok();
            }
            let l = std::os::unix::net::UnixListener::bind(path)
                .map_err(|e| anyhow!("bind {}: {e}", path.display()))?;
            l.set_nonblocking(true)?;
            eprintln!("[loam-server] admin socket on {}", path.display());
            Some(l)
        }
        None => None,
    };
    let s3_listener = match &args.s3_listen {
        Some(addr) => {
            let l = TcpListener::bind(addr)?;
            l.set_nonblocking(true)?;
            eprintln!("[loam-server] s3 gateway on {}", l.local_addr()?);
            Some(l)
        }
        None => None,
    };
    if unix_listener.is_none() && s3_listener.is_none() {
        return Err(anyhow!("no surface: pass --socket and/or --s3-listen"));
    }

    // ── Concurrency shape: the PIC graph stays single-threaded in
    // THIS loop; each S3 connection gets its own worker thread
    // whose admin round-trips funnel through the job channel and
    // come back correlation-routed. A slow client blocks only its
    // own worker. Unix-socket admin frames are read here and their
    // replies are whatever ADMIN_OUT frames carry a cid no S3
    // worker owns.
    let (job_tx, job_rx) = std::sync::mpsc::channel::<AdminJob>();
    let port = AdminPort {
        tx: job_tx,
        cid_counter: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(1)),
    };
    let auth_config: std::sync::Arc<AuthConfig> = std::sync::Arc::new(match &args.s3_credentials {
        Some(path) => {
            let creds = load_credentials(path)?;
            eprintln!(
                "[loam-server] s3 auth REQUIRED ({} access key(s))",
                creds.len()
            );
            Some(creds)
        }
        None => None,
    });
    if let Some(l) = s3_listener {
        l.set_nonblocking(false)?;
        let acceptor_port = port.clone();
        let acceptor_auth = auth_config.clone();
        let multiparts: MultipartTable = Default::default();
        std::thread::spawn(move || {
            for conn in l.incoming() {
                if let Ok(mut stream) = conn {
                    let port = acceptor_port.clone();
                    let auth = acceptor_auth.clone();
                    let mp = multiparts.clone();
                    std::thread::spawn(move || handle_s3_request(&port, &auth, &mp, &mut stream));
                }
            }
        });
    }
    drop(port);

    let tick = Duration::from_micros(args.tick_us);
    let mut unix_conn: Option<std::os::unix::net::UnixStream> = None;
    let mut pending: std::collections::HashMap<u32, std::sync::mpsc::Sender<Vec<u8>>> =
        std::collections::HashMap::new();
    let mut read_buf = vec![0u8; 128 * 1024];
    loop {
        if let Some(ref l) = unix_listener {
            if unix_conn.is_none() {
                match l.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(true).ok();
                        unix_conn = Some(stream);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => {}
                }
            }
        }
        let mut drop_unix = false;
        if let Some(ref mut c) = unix_conn {
            match c.read(&mut read_buf) {
                Ok(0) => drop_unix = true,
                Ok(n) => server.push_admin_request(read_buf[..n].to_vec()),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => drop_unix = true,
            }
        }
        if drop_unix {
            unix_conn = None;
        }
        while let Ok(job) = job_rx.try_recv() {
            pending.insert(job.cid, job.reply);
            server.push_admin_request(job.frame);
        }
        for b in &mut member_bridges {
            b.pump();
        }
        server.tick_once();
        let mut drop_unix = false;
        while let Some(frame) = runtime::pop_admin_out() {
            let cid = if frame.len() >= 5 {
                u32::from_le_bytes(frame[1..5].try_into().unwrap())
            } else {
                0
            };
            if let Some(tx) = pending.remove(&cid) {
                let _ = tx.send(frame);
            } else if let Some(ref mut c) = unix_conn {
                if c.write_all(&frame).is_err() {
                    drop_unix = true;
                }
            }
        }
        if drop_unix {
            unix_conn = None;
        }
        std::thread::sleep(tick);
    }
}
