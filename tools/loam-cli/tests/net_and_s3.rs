//! Integration tests for the network contract and the S3 gateway.
//! Each test spawns real `loam-server` processes and talks to them
//! over their public surfaces — TCP body bridge, unix admin
//! socket, HTTP.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

fn server_bin() -> &'static str {
    env!("CARGO_BIN_EXE_loam-server")
}

struct ServerProc {
    child: Child,
}

impl Drop for ServerProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn loam-server with `args`, wait for a stderr line containing
/// `ready_marker`, and return (process, that line).
fn spawn_server(args: &[&str], ready_marker: &str) -> (ServerProc, String) {
    let mut child = Command::new(server_bin())
        .args(args)
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn loam-server");
    let stderr = child.stderr.take().unwrap();
    let mut reader = BufReader::new(stderr);
    let mut line = String::new();
    let marker = loop {
        line.clear();
        let n = reader.read_line(&mut line).expect("read server stderr");
        assert!(n > 0, "server exited before becoming ready");
        if line.contains(ready_marker) {
            break line.trim().to_string();
        }
    };
    // Keep draining stderr in the background so the server can't
    // block on a full pipe.
    std::thread::spawn(move || {
        let mut sink = String::new();
        while reader.read_line(&mut sink).map(|n| n > 0).unwrap_or(false) {
            sink.clear();
        }
    });
    (ServerProc { child }, marker)
}

fn addr_from_marker(marker: &str) -> String {
    marker
        .rsplit(' ')
        .next()
        .expect("addr at end of marker line")
        .to_string()
}

/// Send one admin frame over the unix socket and read one reply.
fn admin_request(socket: &str, frame: &[u8]) -> Vec<u8> {
    // The server may not have bound the listener the instant the
    // ready line prints; retry briefly.
    let mut conn = None;
    for _ in 0..50 {
        match std::os::unix::net::UnixStream::connect(socket) {
            Ok(c) => {
                conn = Some(c);
                break;
            }
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    let mut conn = conn.expect("connect admin socket");
    conn.set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    conn.write_all(frame).unwrap();
    let mut buf = vec![0u8; 128 * 1024];
    let n = conn.read(&mut buf).expect("read admin reply");
    assert!(n > 0, "empty admin reply");
    buf.truncate(n);
    buf
}

// Admin wire encoding, duplicated minimally so the test speaks the
// wire like any external client would.
mod wire {
    pub fn put_file(cid: u32, ns: &[u8], path: &[u8], revision: u64, body: &[u8]) -> Vec<u8> {
        let mut f = vec![0x43u8];
        f.extend_from_slice(&cid.to_le_bytes());
        f.extend_from_slice(&(ns.len() as u16).to_le_bytes());
        f.extend_from_slice(&(path.len() as u16).to_le_bytes());
        f.push(0); // kind
        f.extend_from_slice(&revision.to_le_bytes());
        f.extend_from_slice(&(body.len() as u32).to_le_bytes());
        f.extend_from_slice(ns);
        f.extend_from_slice(path);
        f.extend_from_slice(body);
        f
    }
    pub fn get_file(cid: u32, ns: &[u8], path: &[u8]) -> Vec<u8> {
        let mut f = vec![0x44u8];
        f.extend_from_slice(&cid.to_le_bytes());
        f.extend_from_slice(&(ns.len() as u16).to_le_bytes());
        f.extend_from_slice(&(path.len() as u16).to_le_bytes());
        f.extend_from_slice(ns);
        f.extend_from_slice(path);
        f
    }
    /// (status, body) from a GetFile ack.
    pub fn parse_get_file_ack(resp: &[u8]) -> (u8, Option<Vec<u8>>) {
        assert_eq!(resp[0], 0x44);
        let status = resp[5];
        if status != 0x01 {
            return (status, None);
        }
        let len = u32::from_le_bytes(resp[6..10].try_into().unwrap()) as usize;
        (status, Some(resp[10..10 + len].to_vec()))
    }
}

#[test]
fn body_plane_spans_two_nodes_over_tcp() {
    let tmp = tempfile::tempdir().unwrap();
    let body_root = tmp.path().join("node-b-bodies");
    let socket = tmp.path().join("node-a.sock");

    // Node B: body storage only, serving its channels over TCP.
    let (_node_b, marker) = spawn_server(
        &[
            "--serve-body",
            "127.0.0.1:0",
            "--body-root",
            body_root.to_str().unwrap(),
        ],
        "body-serve listening on",
    );
    let b_addr = addr_from_marker(&marker);

    // Node A: metadata plane + admin surface; body plane bridged
    // to node B.
    let (_node_a, _) = spawn_server(
        &[
            "--socket",
            socket.to_str().unwrap(),
            "--ns-wal",
            tmp.path().join("a-ns.wal").to_str().unwrap(),
            "--obj-wal",
            tmp.path().join("a-obj.wal").to_str().unwrap(),
            "--fleet",
            &format!("tcp:{b_addr}"),
        ],
        "admin socket on",
    );

    // PUT a file through node A. The body bytes must cross the
    // wire and land on node B's disk.
    let body = b"cross-node body bytes travel over loam_net_wire";
    let reply = admin_request(
        socket.to_str().unwrap(),
        &wire::put_file(1, b"tenant", b"/hello.txt", 1, body),
    );
    assert_eq!(reply[0], 0x43, "PutFileAck");
    assert_eq!(reply[5], 0x01, "status OK");
    let digest_hex: String = reply[6..38].iter().map(|b| format!("{b:02x}")).collect();
    let on_disk = body_root.join(&digest_hex);
    assert!(
        on_disk.exists(),
        "body file landed on NODE B: {}",
        on_disk.display()
    );
    assert_eq!(std::fs::read(&on_disk).unwrap(), body);

    // GET it back through node A — served from node B's disk.
    let reply = admin_request(
        socket.to_str().unwrap(),
        &wire::get_file(2, b"tenant", b"/hello.txt"),
    );
    let (status, got) = wire::parse_get_file_ack(&reply);
    assert_eq!(status, 0x01);
    assert_eq!(got.unwrap(), body);
}

// ── S3 gateway ────────────────────────────────────────────────────

fn http(addr: &str, request: &str, body: &[u8]) -> (String, Vec<u8>) {
    let mut conn = None;
    for _ in 0..50 {
        match TcpStream::connect(addr) {
            Ok(c) => {
                conn = Some(c);
                break;
            }
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    let mut conn = conn.expect("connect s3 gateway");
    conn.set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    conn.write_all(request.as_bytes()).unwrap();
    conn.write_all(body).unwrap();
    let mut raw = Vec::new();
    conn.read_to_end(&mut raw).expect("read http response");
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("header terminator")
        + 4;
    let head = String::from_utf8_lossy(&raw[..header_end]).to_string();
    (head, raw[header_end..].to_vec())
}

#[test]
fn s3_gateway_object_lifecycle() {
    let tmp = tempfile::tempdir().unwrap();
    let (_server, marker) = spawn_server(
        &[
            "--s3-listen",
            "127.0.0.1:0",
            "--ns-wal",
            tmp.path().join("ns.wal").to_str().unwrap(),
            "--obj-wal",
            tmp.path().join("obj.wal").to_str().unwrap(),
            "--fleet",
            &format!("dir:{}", tmp.path().join("bodies").display()),
        ],
        "s3 gateway on",
    );
    let addr = addr_from_marker(&marker);

    // PUT an object.
    let content = b"hello from the loam s3 gateway";
    let (head, _) = http(
        &addr,
        &format!(
            "PUT /demo/greeting.txt HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            content.len()
        ),
        content,
    );
    assert!(head.starts_with("HTTP/1.1 200"), "PUT: {head}");
    assert!(
        head.contains("ETag: \""),
        "PUT carries content ETag: {head}"
    );

    // GET it back.
    let (head, body) = http(
        &addr,
        "GET /demo/greeting.txt HTTP/1.1\r\nHost: x\r\n\r\n",
        b"",
    );
    assert!(head.starts_with("HTTP/1.1 200"), "GET: {head}");
    assert_eq!(body, content);

    // HEAD reports the size without a body.
    let (head, body) = http(
        &addr,
        "HEAD /demo/greeting.txt HTTP/1.1\r\nHost: x\r\n\r\n",
        b"",
    );
    assert!(head.starts_with("HTTP/1.1 200"), "HEAD: {head}");
    assert!(
        head.contains(&format!("Content-Length: {}", content.len())),
        "{head}"
    );
    assert!(body.is_empty());

    // Overwrite (S3 PUT semantics — later write wins).
    let content2 = b"a newer greeting, longer than before";
    let (head, _) = http(
        &addr,
        &format!(
            "PUT /demo/greeting.txt HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            content2.len()
        ),
        content2,
    );
    assert!(head.starts_with("HTTP/1.1 200"), "overwrite PUT: {head}");
    let (_, body) = http(
        &addr,
        "GET /demo/greeting.txt HTTP/1.1\r\nHost: x\r\n\r\n",
        b"",
    );
    assert_eq!(body, content2, "GET serves the overwritten content");

    // A second object, then a bucket listing shows both keys.
    let (head, _) = http(
        &addr,
        "PUT /demo/nested/deep.txt HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\n",
        b"deep",
    );
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let (head, body) = http(&addr, "GET /demo HTTP/1.1\r\nHost: x\r\n\r\n", b"");
    assert!(head.starts_with("HTTP/1.1 200"), "LIST: {head}");
    assert!(head.contains("application/xml"), "{head}");
    let xml = String::from_utf8_lossy(&body).to_string();
    assert!(xml.contains("<Key>greeting.txt</Key>"), "{xml}");
    assert!(xml.contains("<Key>nested/deep.txt</Key>"), "{xml}");
    assert!(xml.contains("<KeyCount>2</KeyCount>"), "{xml}");
    // Delimiter view: nested keys roll up into CommonPrefixes.
    let (_, body) = http(
        &addr,
        "GET /demo?delimiter=/ HTTP/1.1\r\nHost: x\r\n\r\n",
        b"",
    );
    let xml = String::from_utf8_lossy(&body).to_string();
    assert!(
        xml.contains("<Contents><Key>greeting.txt</Key></Contents>"),
        "{xml}"
    );
    assert!(
        xml.contains("<CommonPrefixes><Prefix>nested/</Prefix></CommonPrefixes>"),
        "{xml}"
    );
    assert!(
        !xml.contains("<Key>nested/deep.txt</Key>"),
        "rolled up: {xml}"
    );
    // Prefix filter narrows to the subtree.
    let (_, body) = http(
        &addr,
        "GET /demo?prefix=nested/ HTTP/1.1\r\nHost: x\r\n\r\n",
        b"",
    );
    let xml = String::from_utf8_lossy(&body).to_string();
    assert!(xml.contains("<Key>nested/deep.txt</Key>"), "{xml}");
    assert!(!xml.contains("<Key>greeting.txt</Key>"), "{xml}");
    assert!(xml.contains("<Prefix>nested/</Prefix>"), "{xml}");
    // Another bucket's listing is empty.
    let (_, body) = http(&addr, "GET /empty-bucket HTTP/1.1\r\nHost: x\r\n\r\n", b"");
    let xml = String::from_utf8_lossy(&body).to_string();
    assert!(xml.contains("<KeyCount>0</KeyCount>"), "{xml}");

    // DELETE, then GET → 404. DELETE of a missing key stays 204.
    let (head, _) = http(
        &addr,
        "DELETE /demo/greeting.txt HTTP/1.1\r\nHost: x\r\n\r\n",
        b"",
    );
    assert!(head.starts_with("HTTP/1.1 204"), "DELETE: {head}");
    let (head, _) = http(
        &addr,
        "GET /demo/greeting.txt HTTP/1.1\r\nHost: x\r\n\r\n",
        b"",
    );
    assert!(head.starts_with("HTTP/1.1 404"), "GET after delete: {head}");
    let (head, _) = http(
        &addr,
        "DELETE /demo/greeting.txt HTTP/1.1\r\nHost: x\r\n\r\n",
        b"",
    );
    assert!(
        head.starts_with("HTTP/1.1 204"),
        "idempotent DELETE: {head}"
    );

    // Objects in different buckets don't collide.
    let (head, _) = http(
        &addr,
        "PUT /other/greeting.txt HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\n",
        b"abc",
    );
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let (head, _) = http(
        &addr,
        "GET /demo/greeting.txt HTTP/1.1\r\nHost: x\r\n\r\n",
        b"",
    );
    assert!(head.starts_with("HTTP/1.1 404"), "bucket isolation: {head}");

    // A bare bucket path is a (possibly empty) listing, not an
    // error; the root path IS malformed.
    let (head, _) = http(&addr, "GET /justabucket HTTP/1.1\r\nHost: x\r\n\r\n", b"");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let (head, _) = http(&addr, "GET / HTTP/1.1\r\nHost: x\r\n\r\n", b"");
    assert!(head.starts_with("HTTP/1.1 400"), "{head}");
    // PUT to a bare bucket is not an object write.
    let (head, _) = http(
        &addr,
        "PUT /justabucket HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\n",
        b"x",
    );
    assert!(head.starts_with("HTTP/1.1 400"), "{head}");
}

#[test]
fn s3_gateway_fronts_a_remote_body_node() {
    let tmp = tempfile::tempdir().unwrap();
    let body_root = tmp.path().join("remote-bodies");

    let (_node_b, marker) = spawn_server(
        &[
            "--serve-body",
            "127.0.0.1:0",
            "--body-root",
            body_root.to_str().unwrap(),
        ],
        "body-serve listening on",
    );
    let b_addr = addr_from_marker(&marker);

    let (_node_a, marker) = spawn_server(
        &[
            "--s3-listen",
            "127.0.0.1:0",
            "--ns-wal",
            tmp.path().join("ns.wal").to_str().unwrap(),
            "--obj-wal",
            tmp.path().join("obj.wal").to_str().unwrap(),
            "--fleet",
            &format!("tcp:{b_addr}"),
        ],
        "s3 gateway on",
    );
    let addr = addr_from_marker(&marker);

    // The full stack: HTTP → admin_router → namespace/object PICs
    // locally, body bytes over the TCP bridge to the other node.
    let content = b"stored on another machine, served over s3";
    let (head, _) = http(
        &addr,
        &format!(
            "PUT /edge/blob.bin HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            content.len()
        ),
        content,
    );
    assert!(head.starts_with("HTTP/1.1 200"), "PUT via bridge: {head}");
    let (head, body) = http(&addr, "GET /edge/blob.bin HTTP/1.1\r\nHost: x\r\n\r\n", b"");
    assert!(head.starts_with("HTTP/1.1 200"), "GET via bridge: {head}");
    assert_eq!(body, content);

    // And the bytes really live on node B.
    let stored: Vec<_> = std::fs::read_dir(&body_root).unwrap().collect();
    assert_eq!(stored.len(), 1, "exactly one body on the remote node");
}

#[test]
fn s3_gateway_serves_concurrent_clients() {
    let tmp = tempfile::tempdir().unwrap();
    let (_server, marker) = spawn_server(
        &[
            "--s3-listen",
            "127.0.0.1:0",
            "--ns-wal",
            tmp.path().join("ns.wal").to_str().unwrap(),
            "--obj-wal",
            tmp.path().join("obj.wal").to_str().unwrap(),
            "--fleet",
            &format!("dir:{}", tmp.path().join("bodies").display()),
        ],
        "s3 gateway on",
    );
    let addr = addr_from_marker(&marker);

    // A slow client connects and sends NOTHING — its worker thread
    // sits in the request read. Other clients must not be blocked
    // behind it (pre-concurrency, the accept loop stalled on the
    // slow connection's 5s read timeout).
    let _slow = TcpStream::connect(&addr).expect("slow client connects");
    std::thread::sleep(Duration::from_millis(200));

    let started = std::time::Instant::now();
    let content = b"served while a slow client stalls";
    let (head, _) = http(
        &addr,
        &format!(
            "PUT /fast/obj HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            content.len()
        ),
        content,
    );
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let (head, body) = http(&addr, "GET /fast/obj HTTP/1.1\r\nHost: x\r\n\r\n", b"");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body, content);
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "fast client not serialized behind the slow one ({:?})",
        started.elapsed()
    );

    // Ten parallel PUTs then GETs — all must land intact.
    let mut handles = Vec::new();
    for i in 0..10 {
        let addr = addr.clone();
        handles.push(std::thread::spawn(move || {
            let content = format!("parallel-object-{i}");
            let (head, _) = http(
                &addr,
                &format!(
                    "PUT /par/obj{i} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
                    content.len()
                ),
                content.as_bytes(),
            );
            assert!(head.starts_with("HTTP/1.1 200"), "PUT {i}: {head}");
            let (head, body) = http(
                &addr,
                &format!("GET /par/obj{i} HTTP/1.1\r\nHost: x\r\n\r\n"),
                b"",
            );
            assert!(head.starts_with("HTTP/1.1 200"), "GET {i}: {head}");
            assert_eq!(body, content.as_bytes());
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn replicated_fleet_survives_a_body_node_death() {
    let tmp = tempfile::tempdir().unwrap();
    let root_a = tmp.path().join("bodies-a");
    let root_b = tmp.path().join("bodies-b");

    let (node_a, marker) = spawn_server(
        &[
            "--serve-body",
            "127.0.0.1:0",
            "--body-root",
            root_a.to_str().unwrap(),
        ],
        "body-serve listening on",
    );
    let a_addr = addr_from_marker(&marker);
    let (_node_b, marker) = spawn_server(
        &[
            "--serve-body",
            "127.0.0.1:0",
            "--body-root",
            root_b.to_str().unwrap(),
        ],
        "body-serve listening on",
    );
    let b_addr = addr_from_marker(&marker);

    let (_admin, marker) = spawn_server(
        &[
            "--s3-listen",
            "127.0.0.1:0",
            "--ns-wal",
            tmp.path().join("ns.wal").to_str().unwrap(),
            "--obj-wal",
            tmp.path().join("obj.wal").to_str().unwrap(),
            "--fleet",
            &format!("tcp:{a_addr},tcp:{b_addr}"),
        ],
        "s3 gateway on",
    );
    let addr = addr_from_marker(&marker);

    // PUT with replica_count 2 (auto: min(3, fleet=2)) — the blob
    // must land on BOTH body nodes' disks.
    let content = b"replicated across two real processes";
    let (head, _) = http(
        &addr,
        &format!(
            "PUT /ha/blob HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            content.len()
        ),
        content,
    );
    assert!(head.starts_with("HTTP/1.1 200"), "PUT: {head}");
    let count = |root: &std::path::Path| std::fs::read_dir(root).map(|d| d.count()).unwrap_or(0);
    assert_eq!(count(&root_a), 1, "replica on node A");
    assert_eq!(count(&root_b), 1, "replica on node B");

    let (head, body) = http(&addr, "GET /ha/blob HTTP/1.1\r\nHost: x\r\n\r\n", b"");
    assert!(head.starts_with("HTTP/1.1 200"), "GET both up: {head}");
    assert_eq!(body, content);

    // Kill node A. Reads must survive via fallback to node B —
    // whichever of the two is the rendezvous primary.
    drop(node_a);
    std::thread::sleep(Duration::from_millis(500));
    let (head, body) = http(&addr, "GET /ha/blob HTTP/1.1\r\nHost: x\r\n\r\n", b"");
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "GET after node death: {head}"
    );
    assert_eq!(body, content, "served from the surviving replica");

    // Writes are all-must-succeed at replica_count 2 with one
    // member down: an honest 500, not a silent under-replication.
    let (head, _) = http(
        &addr,
        "PUT /ha/second HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\n",
        b"nope!",
    );
    assert!(
        head.starts_with("HTTP/1.1 500"),
        "degraded PUT refused: {head}"
    );
}

#[test]
fn s3_gateway_streams_large_objects() {
    let tmp = tempfile::tempdir().unwrap();
    let (_server, marker) = spawn_server(
        &[
            "--s3-listen",
            "127.0.0.1:0",
            "--ns-wal",
            tmp.path().join("ns.wal").to_str().unwrap(),
            "--obj-wal",
            tmp.path().join("obj.wal").to_str().unwrap(),
            "--fleet",
            &format!("dir:{}", tmp.path().join("bodies").display()),
        ],
        "s3 gateway on",
    );
    let addr = addr_from_marker(&marker);

    // 2 MiB: past the gateway's memory-spool threshold AND ~44
    // chunked admin round-trips each way.
    let total = 2 * 1024 * 1024;
    let content: Vec<u8> = (0..total).map(|i| (i * 7 % 250) as u8).collect();

    let started = std::time::Instant::now();
    let (head, _) = http(
        &addr,
        &format!(
            "PUT /big/blob.bin HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            content.len()
        ),
        &content,
    );
    assert!(head.starts_with("HTTP/1.1 200"), "large PUT: {head}");
    assert!(
        head.contains("ETag: \""),
        "PUT returns the content ETag: {head}"
    );

    // HEAD reports the true size without transferring the body.
    let (head, body) = http(&addr, "HEAD /big/blob.bin HTTP/1.1\r\nHost: x\r\n\r\n", b"");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(head.contains(&format!("Content-Length: {total}")), "{head}");
    assert!(body.is_empty());

    // GET streams the whole object back intact.
    let (head, body) = http(&addr, "GET /big/blob.bin HTTP/1.1\r\nHost: x\r\n\r\n", b"");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body.len(), content.len(), "full length streamed");
    assert_eq!(body, content, "bytes intact end to end");
    eprintln!("[test] 2 MiB round trip in {:?}", started.elapsed());

    // Overwrite with different large content; last write wins.
    let content2: Vec<u8> = (0..total).map(|i| (i * 11 % 249) as u8).collect();
    let (head, _) = http(
        &addr,
        &format!(
            "PUT /big/blob.bin HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            content2.len()
        ),
        &content2,
    );
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let (_, body) = http(&addr, "GET /big/blob.bin HTTP/1.1\r\nHost: x\r\n\r\n", b"");
    assert_eq!(body, content2, "overwritten large object served");
}

// ── SigV4 auth ────────────────────────────────────────────────────

#[allow(
    dead_code,
    unused_imports,
    reason = "shared include; each includer uses a subset"
)]
#[path = "../../../target/fluxor/fluxor-abi/sdk/crypto/sha256.rs"]
mod sha256_impl;

mod net_sigv4_scope {
    pub mod sha256 {
        pub use super::super::sha256_impl::Sha256;
    }
    #[allow(
        dead_code,
        unused_imports,
        reason = "shared include; each includer uses a subset"
    )]
    #[path = "../../src/sigv4.rs"]
    pub mod sigv4;
}
use net_sigv4_scope::sigv4;

/// Epoch → `yyyymmddThhmmssZ` (inverse of sigv4::parse_amz_date;
/// Hinnant civil-from-days).
fn amz_date(epoch: i64) -> String {
    let days = epoch.div_euclid(86400);
    let secs = epoch.rem_euclid(86400);
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        y,
        mo,
        d,
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

/// Send a SigV4-signed request; `date_epoch` lets tests forge
/// stale timestamps.
fn http_signed(
    addr: &str,
    method: &str,
    path: &str,
    body: &[u8],
    key_id: &str,
    secret: &str,
    date_epoch: i64,
) -> (String, Vec<u8>) {
    let payload_hash = sigv4::sha256_hex(body);
    let date_full = amz_date(date_epoch);
    let date_short = &date_full[..8];
    let headers = vec![
        ("host".to_string(), addr.to_string()),
        ("x-amz-content-sha256".to_string(), payload_hash.clone()),
        ("x-amz-date".to_string(), date_full.clone()),
    ];
    let auth = sigv4::AuthHeader {
        access_key: key_id.to_string(),
        date: date_short.to_string(),
        region: "us-east-1".to_string(),
        service: "s3".to_string(),
        signed_headers: vec![
            "host".to_string(),
            "x-amz-content-sha256".to_string(),
            "x-amz-date".to_string(),
        ],
        signature: String::new(),
    };
    let signature = sigv4::compute_signature(
        secret,
        &auth,
        method,
        path,
        &headers,
        &date_full,
        &payload_hash,
    );
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={key_id}/{date_short}/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={signature}"
    );
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nx-amz-date: {date_full}\r\nx-amz-content-sha256: {payload_hash}\r\nAuthorization: {authorization}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    http(addr, &request, body)
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[test]
fn s3_gateway_enforces_sigv4_and_bucket_scopes() {
    let tmp = tempfile::tempdir().unwrap();
    let creds_path = tmp.path().join("credentials");
    std::fs::write(
        &creds_path,
        "# loam s3 credentials\n\
         AKIAFULL secret-full-access *\n\
         AKIATEAM team-secret team-*\n",
    )
    .unwrap();
    let (_server, marker) = spawn_server(
        &[
            "--s3-listen",
            "127.0.0.1:0",
            "--ns-wal",
            tmp.path().join("ns.wal").to_str().unwrap(),
            "--obj-wal",
            tmp.path().join("obj.wal").to_str().unwrap(),
            "--fleet",
            &format!("dir:{}", tmp.path().join("bodies").display()),
            "--s3-credentials",
            creds_path.to_str().unwrap(),
        ],
        "s3 gateway on",
    );
    let addr = addr_from_marker(&marker);

    // Unsigned requests are refused outright.
    let (head, _) = http(
        &addr,
        "PUT /team-a/doc HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\n",
        b"nope",
    );
    assert!(head.starts_with("HTTP/1.1 403"), "unsigned: {head}");
    let (head, _) = http(&addr, "GET /team-a/doc HTTP/1.1\r\nHost: x\r\n\r\n", b"");
    assert!(head.starts_with("HTTP/1.1 403"), "unsigned GET: {head}");

    // A correctly signed PUT + GET round-trips.
    let content = b"authenticated content";
    let (head, _) = http_signed(
        &addr,
        "PUT",
        "/team-a/doc",
        content,
        "AKIATEAM",
        "team-secret",
        now_epoch(),
    );
    assert!(head.starts_with("HTTP/1.1 200"), "signed PUT: {head}");
    let (head, body) = http_signed(
        &addr,
        "GET",
        "/team-a/doc",
        b"",
        "AKIATEAM",
        "team-secret",
        now_epoch(),
    );
    assert!(head.starts_with("HTTP/1.1 200"), "signed GET: {head}");
    assert_eq!(body, content);

    // Wrong secret → 403.
    let (head, _) = http_signed(
        &addr,
        "GET",
        "/team-a/doc",
        b"",
        "AKIATEAM",
        "WRONG",
        now_epoch(),
    );
    assert!(head.starts_with("HTTP/1.1 403"), "wrong secret: {head}");

    // Unknown key id → 403.
    let (head, _) = http_signed(
        &addr,
        "GET",
        "/team-a/doc",
        b"",
        "AKIANOBODY",
        "team-secret",
        now_epoch(),
    );
    assert!(head.starts_with("HTTP/1.1 403"), "unknown key: {head}");

    // Stale timestamp (an hour old) → 403.
    let (head, _) = http_signed(
        &addr,
        "GET",
        "/team-a/doc",
        b"",
        "AKIATEAM",
        "team-secret",
        now_epoch() - 3600,
    );
    assert!(head.starts_with("HTTP/1.1 403"), "stale date: {head}");

    // Tenancy: the team-scoped key cannot touch another bucket…
    let (head, _) = http_signed(
        &addr,
        "PUT",
        "/other/doc",
        b"x",
        "AKIATEAM",
        "team-secret",
        now_epoch(),
    );
    assert!(
        head.starts_with("HTTP/1.1 403"),
        "out-of-scope bucket: {head}"
    );
    let (head, _) = http_signed(
        &addr,
        "GET",
        "/other",
        b"",
        "AKIATEAM",
        "team-secret",
        now_epoch(),
    );
    assert!(
        head.starts_with("HTTP/1.1 403"),
        "out-of-scope listing: {head}"
    );

    // …while the wildcard key can, and can list team buckets too.
    let (head, _) = http_signed(
        &addr,
        "PUT",
        "/other/doc",
        b"admin!",
        "AKIAFULL",
        "secret-full-access",
        now_epoch(),
    );
    assert!(head.starts_with("HTTP/1.1 200"), "wildcard PUT: {head}");
    let (head, body) = http_signed(
        &addr,
        "GET",
        "/team-a",
        b"",
        "AKIAFULL",
        "secret-full-access",
        now_epoch(),
    );
    assert!(head.starts_with("HTTP/1.1 200"), "wildcard listing: {head}");
    let xml = String::from_utf8_lossy(&body).to_string();
    assert!(xml.contains("<Key>doc</Key>"), "{xml}");

    // Payload-hash tampering: sign one body, send another.
    let payload_hash = sigv4::sha256_hex(b"signed body");
    let date_full = amz_date(now_epoch());
    let date_short = &date_full[..8];
    let headers = vec![
        ("host".to_string(), addr.to_string()),
        ("x-amz-content-sha256".to_string(), payload_hash.clone()),
        ("x-amz-date".to_string(), date_full.clone()),
    ];
    let auth = sigv4::AuthHeader {
        access_key: "AKIATEAM".to_string(),
        date: date_short.to_string(),
        region: "us-east-1".to_string(),
        service: "s3".to_string(),
        signed_headers: vec![
            "host".to_string(),
            "x-amz-content-sha256".to_string(),
            "x-amz-date".to_string(),
        ],
        signature: String::new(),
    };
    let signature = sigv4::compute_signature(
        "team-secret",
        &auth,
        "PUT",
        "/team-a/tampered",
        &headers,
        &date_full,
        &payload_hash,
    );
    let request = format!(
        "PUT /team-a/tampered HTTP/1.1\r\nHost: {addr}\r\nx-amz-date: {date_full}\r\nx-amz-content-sha256: {payload_hash}\r\nAuthorization: AWS4-HMAC-SHA256 Credential=AKIATEAM/{date_short}/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={signature}\r\nContent-Length: 14\r\n\r\n"
    );
    let (head, _) = http(&addr, &request, b"TAMPERED BODY!");
    assert!(head.starts_with("HTTP/1.1 403"), "tampered payload: {head}");

    // ── Presigned URLs: query auth, no Authorization header. ──
    let presign = |method: &str,
                   object: &str,
                   key_id: &str,
                   secret: &str,
                   signed_epoch: i64,
                   expires: i64|
     -> String {
        let date_full = amz_date(signed_epoch);
        let date_short = date_full[..8].to_string();
        let base = format!(
            "{object}?X-Amz-Algorithm=AWS4-HMAC-SHA256\
             &X-Amz-Credential={key_id}%2F{date_short}%2Fus-east-1%2Fs3%2Faws4_request\
             &X-Amz-Date={date_full}&X-Amz-Expires={expires}&X-Amz-SignedHeaders=host"
        )
        .replace(' ', "");
        let auth = sigv4::AuthHeader {
            access_key: key_id.to_string(),
            date: date_short,
            region: "us-east-1".to_string(),
            service: "s3".to_string(),
            signed_headers: vec!["host".to_string()],
            signature: String::new(),
        };
        let headers = vec![("host".to_string(), addr.to_string())];
        let signature = sigv4::compute_signature(
            secret,
            &auth,
            method,
            &base,
            &headers,
            &date_full,
            sigv4::UNSIGNED_PAYLOAD,
        );
        format!("{base}&X-Amz-Signature={signature}")
    };

    // A valid presigned GET serves the object with no headers signed
    // but Host.
    let url = presign(
        "GET",
        "/team-a/doc",
        "AKIATEAM",
        "team-secret",
        now_epoch(),
        300,
    );
    let (head, body) = http(
        &addr,
        &format!("GET {url} HTTP/1.1\r\nHost: {addr}\r\n\r\n"),
        b"",
    );
    assert!(head.starts_with("HTTP/1.1 200"), "presigned GET: {head}");
    assert_eq!(body, content);

    // Expired link → 403.
    let url = presign(
        "GET",
        "/team-a/doc",
        "AKIATEAM",
        "team-secret",
        now_epoch() - 600,
        300,
    );
    let (head, _) = http(
        &addr,
        &format!("GET {url} HTTP/1.1\r\nHost: {addr}\r\n\r\n"),
        b"",
    );
    assert!(
        head.starts_with("HTTP/1.1 403"),
        "expired presigned: {head}"
    );

    // Tampered object path → 403 (signature covers the URI).
    let url = presign(
        "GET",
        "/team-a/doc",
        "AKIATEAM",
        "team-secret",
        now_epoch(),
        300,
    )
    .replace("/team-a/doc", "/team-a/other");
    let (head, _) = http(
        &addr,
        &format!("GET {url} HTTP/1.1\r\nHost: {addr}\r\n\r\n"),
        b"",
    );
    assert!(
        head.starts_with("HTTP/1.1 403"),
        "tampered presigned: {head}"
    );

    // Bucket scope still applies to presigned access.
    let url = presign(
        "GET",
        "/other/doc",
        "AKIATEAM",
        "team-secret",
        now_epoch(),
        300,
    );
    let (head, _) = http(
        &addr,
        &format!("GET {url} HTTP/1.1\r\nHost: {addr}\r\n\r\n"),
        b"",
    );
    assert!(
        head.starts_with("HTTP/1.1 403"),
        "presigned out-of-scope: {head}"
    );
}

#[test]
fn s3_gateway_multipart_upload() {
    let tmp = tempfile::tempdir().unwrap();
    let (_server, marker) = spawn_server(
        &[
            "--s3-listen",
            "127.0.0.1:0",
            "--ns-wal",
            tmp.path().join("ns.wal").to_str().unwrap(),
            "--obj-wal",
            tmp.path().join("obj.wal").to_str().unwrap(),
            "--fleet",
            &format!("dir:{}", tmp.path().join("bodies").display()),
        ],
        "s3 gateway on",
    );
    let addr = addr_from_marker(&marker);

    // Initiate.
    let (head, body) = http(
        &addr,
        "POST /mp/asm.bin?uploads HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n",
        b"",
    );
    assert!(head.starts_with("HTTP/1.1 200"), "initiate: {head}");
    let xml = String::from_utf8_lossy(&body).to_string();
    let upload_id = xml
        .split("<UploadId>")
        .nth(1)
        .and_then(|r| r.split("</UploadId>").next())
        .expect("uploadId in initiate XML")
        .to_string();

    // Three parts, deliberately uploaded out of order, sizes chosen
    // so the assembled object exceeds the single-shot path.
    let part = |n: usize| -> Vec<u8> {
        (0..600 * 1024 + n * 1000)
            .map(|i| ((i * 11 + n * 3) % 251) as u8)
            .collect()
    };
    for n in [2usize, 1, 3] {
        let bytes = part(n);
        let (head, _) = http(
            &addr,
            &format!(
                "PUT /mp/asm.bin?partNumber={n}&uploadId={upload_id} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
                bytes.len()
            ),
            &bytes,
        );
        assert!(head.starts_with("HTTP/1.1 200"), "part {n}: {head}");
        assert!(head.contains("ETag: \""), "part {n} etag: {head}");
    }

    // A part against an unknown upload id is refused.
    let (head, _) = http(
        &addr,
        "PUT /mp/asm.bin?partNumber=1&uploadId=deadbeef HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\n",
        b"z",
    );
    assert!(head.starts_with("HTTP/1.1 404"), "bogus upload id: {head}");

    // Complete (parts listed ascending, as S3 requires).
    let complete_xml = "<CompleteMultipartUpload>\
        <Part><PartNumber>1</PartNumber></Part>\
        <Part><PartNumber>2</PartNumber></Part>\
        <Part><PartNumber>3</PartNumber></Part>\
        </CompleteMultipartUpload>";
    let (head, body) = http(
        &addr,
        &format!(
            "POST /mp/asm.bin?uploadId={upload_id} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            complete_xml.len()
        ),
        complete_xml.as_bytes(),
    );
    assert!(head.starts_with("HTTP/1.1 200"), "complete: {head}");
    assert!(
        String::from_utf8_lossy(&body).contains("<CompleteMultipartUploadResult>"),
        "complete XML"
    );

    // The upload id is consumed.
    let (head, _) = http(
        &addr,
        &format!(
            "POST /mp/asm.bin?uploadId={upload_id} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            complete_xml.len()
        ),
        complete_xml.as_bytes(),
    );
    assert!(head.starts_with("HTTP/1.1 404"), "consumed id: {head}");

    // The assembled object reads back byte-identical to the
    // ordered concatenation.
    let mut expect = Vec::new();
    for n in 1..=3 {
        expect.extend_from_slice(&part(n));
    }
    let (head, got) = http(&addr, "GET /mp/asm.bin HTTP/1.1\r\nHost: x\r\n\r\n", b"");
    assert!(head.starts_with("HTTP/1.1 200"), "GET: {head}");
    assert_eq!(got.len(), expect.len(), "assembled size");
    assert!(got == expect, "assembled bytes");

    // Abort path: initiate, add a part, abort, complete → 404.
    let (_, body) = http(
        &addr,
        "POST /mp/gone.bin?uploads HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n",
        b"",
    );
    let xml = String::from_utf8_lossy(&body).to_string();
    let dead_id = xml
        .split("<UploadId>")
        .nth(1)
        .and_then(|r| r.split("</UploadId>").next())
        .unwrap()
        .to_string();
    let (head, _) = http(
        &addr,
        &format!("PUT /mp/gone.bin?partNumber=1&uploadId={dead_id} HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\n"),
        b"abc",
    );
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let (head, _) = http(
        &addr,
        &format!("DELETE /mp/gone.bin?uploadId={dead_id} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"),
        b"",
    );
    assert!(head.starts_with("HTTP/1.1 204"), "abort: {head}");
    let (head, _) = http(
        &addr,
        &format!(
            "POST /mp/gone.bin?uploadId={dead_id} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"
        ),
        b"",
    );
    assert!(head.starts_with("HTTP/1.1 404"), "aborted id: {head}");
    // The aborted upload never became an object.
    let (head, _) = http(&addr, "GET /mp/gone.bin HTTP/1.1\r\nHost: x\r\n\r\n", b"");
    assert!(
        head.starts_with("HTTP/1.1 404"),
        "aborted object absent: {head}"
    );
}
