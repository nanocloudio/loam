//! A Fluxor node publishing a Loam volume as an encrypted block device,
//! run live: `crypt_block` over `loam_volume`, reaching the server through
//! Fluxor's own `tls` module under the node's certificate.
//!
//! The node is a real `fluxor run` graph:
//!
//! ```text
//! NBD client (this test) → nbd_serve → crypt_block → loam_volume
//!                                                      ⇅ admin wire, as bytes
//!                                                   stream_bridge (connect)
//!                                                      ⇅ clear stream
//!                                                   tls (client, node certificate)
//!                                                      ⇅ ciphertext
//!                                                   linux_net → loam-server --admin-listen
//! ```
//!
//! What these pin:
//! - the node authenticates with its own certificate, is authorised by its
//!   grant, takes the writer lease under that identity, and commits what an
//!   NBD client wrote and flushed, which `loam-client` then opens;
//! - with `crypt_block` in the stack the committed volume holds none of the
//!   plaintext; without it (the control) the plaintext is there to find,
//!   so its absence is evidence;
//! - an identity with no grant on the volume's root never gets a volume.
//!
//! The suite runtime-skips when the Fluxor Linux runtime, the `fluxor` tool
//! or the modules are absent; `LOAM_REQUIRE_E2E=1` makes a skip a failure.

#[path = "support/pki.rs"]
mod pki;
mod support;

use pki::{spawn_tls_server, Name, TlsServer};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const GRANTS: &str = r#"{
  "grants": [
    { "identity": "node-a", "roots": ["tenant"], "ops": ["read", "write", "lease"] },
    { "identity": "node-b", "roots": ["other"], "ops": ["read", "write", "lease"] }
  ]
}"#;

const SEAL_KEY: &str = "5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed";
const VOLUME_BYTES: u64 = 16 * 1024 * 1024;
const EXTENT: u32 = 4096;
/// Where the client writes, clear of the container's own metadata at the
/// front of the device.
const AT: u64 = 1024 * 1024;
const NEEDLE: &[u8] = b"LOAM-NODE-PLAINTEXT-NEEDLE";

fn server_bin() -> &'static str {
    env!("CARGO_BIN_EXE_loam-server")
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fluxor_tool() -> PathBuf {
    std::env::var_os("FLUXOR_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("fluxor"))
}

fn on_path(tool: &Path) -> bool {
    if tool.components().count() > 1 {
        return tool.exists();
    }
    std::env::var_os("PATH")
        .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(tool).is_file()))
}

fn missing_prereq() -> Option<String> {
    let root = workspace_root();
    let linux = root.join("target/aarch64-unknown-linux-gnu/release/fluxor-linux");
    if !linux.exists() {
        return Some(format!("fluxor-linux not at {}", linux.display()));
    }
    if !on_path(&fluxor_tool()) {
        return Some("fluxor build tool not on PATH (or $FLUXOR_BIN)".into());
    }
    let modules = root.join("target/fluxor/bcm2712/modules");
    for m in [
        "tls",
        "stream_bridge",
        "loam_volume",
        "crypt_block",
        "nbd_serve",
    ] {
        let fmod = modules.join(format!("{m}.fmod"));
        if !fmod.exists() {
            return Some(format!("{} missing", fmod.display()));
        }
    }
    None
}

fn prereqs_or_skip() -> bool {
    match missing_prereq() {
        None => true,
        Some(missing) => {
            if std::env::var("LOAM_REQUIRE_E2E").as_deref() == Ok("1") {
                panic!("LOAM_REQUIRE_E2E=1 but a node-graph prerequisite is missing: {missing}");
            }
            eprintln!("[node_volume_tls] skipping: {missing}");
            false
        }
    }
}

/// A TCP port nothing is listening on, for the node's NBD export.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The node's graph, with or without `crypt_block` between the export and
/// the volume.
fn graph(dir: &Path, srv: &TlsServer, root: &str, encrypted: bool, nbd_port: u16) -> String {
    let file = |name: &str, bytes: &[u8]| -> String {
        let p = dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        p.to_str().unwrap().to_string()
    };
    let identity = srv.ca.client(Name::Cn("node-a"));
    let ca = file("ca.der", &srv.ca.der());
    let cert = file("node.der", &identity.cert_der);
    let key = file("node.key.der", &identity.key_der);
    let (crypt, export) = if encrypted {
        (
            r#"
  - name: crypt_block
    params:
      key: loam-vol0
      format: 1
      block_size: 512
      unit_size: 4096
      journal_units: 64
"#,
            "  - from: loam_volume.blocks\n    to: crypt_block.lower\n  - from: crypt_block.blocks\n    to: nbd_serve.blocks\n",
        )
    } else {
        (
            "",
            "  - from: loam_volume.blocks\n    to: nbd_serve.blocks\n",
        )
    };
    format!(
        r#"target: linux
tick_us: 1000
module_search_paths:
  - {modules}

platform:
  net: {{}}

modules:
  - name: tls
    mode: 0
    peer_auth: ca_dns
    verify_hostname: localhost
    trust: "${{file:{ca}}}"
    cert_file: {cert}
    key_file: {key}
    clock_policy: unchecked
  - name: stream_bridge
    params:
      mode: 1
      authority: "{addr}"
  - name: loam_volume
    params:
      root: {root}
      path: /vols/v0
      block_size: 512
{crypt}
  - name: nbd_serve
    params:
      port: {nbd_port}

wiring:
  - from: linux_net.net_out
    to: tls.cipher_in
  - from: tls.cipher_out
    to: linux_net.net_in
  - from: linux_net.net_out
    to: nbd_serve.net_in
  - from: nbd_serve.net_out
    to: linux_net.net_in
  - from: tls.clear_out
    to: stream_bridge.net_in
  - from: stream_bridge.net_out
    to: tls.clear_in
  - from: loam_volume.admin_req
    to: stream_bridge.bytes_in
  - from: stream_bridge.bytes_out
    to: loam_volume.admin_resp
{export}"#,
        modules = workspace_root().join("modules/app").display(),
        addr = srv.addr,
    )
}

/// A running `fluxor run` node, killed with its process group on drop.
struct Node {
    child: Option<Child>,
    dir: PathBuf,
}

impl Node {
    fn run(dir: &Path, yaml: &str) -> Node {
        let path = dir.join("node.yaml");
        std::fs::write(&path, yaml).unwrap();
        let log = |name: &str| std::fs::File::create(dir.join(name)).unwrap();
        let child = Command::new(fluxor_tool())
            .arg("run")
            .arg(&path)
            .current_dir(dir)
            .env("FLUXOR_PROJECT_ROOT", workspace_root())
            .env("FLUXOR_SEAL_KEY", SEAL_KEY)
            .env("FLUXOR_VAULT_DIR", dir.join("vault"))
            .stdin(Stdio::null())
            .stdout(log("node.stdout"))
            .stderr(log("node.stderr"))
            .process_group(0)
            .spawn()
            .expect("spawn fluxor run");
        Node {
            child: Some(child),
            dir: dir.to_path_buf(),
        }
    }

    fn log(&self) -> String {
        let read = |n: &str| std::fs::read_to_string(self.dir.join(n)).unwrap_or_default();
        read("node.stdout") + &read("node.stderr")
    }

    /// Wait until the log shows every one of `ready` (Ok) or `fail` (Err),
    /// or the node exits, or `within` runs out.
    fn wait(&mut self, ready: &[&str], fail: &str, within: Duration) -> Result<(), String> {
        let t0 = Instant::now();
        while t0.elapsed() < within {
            let exited = self
                .child
                .as_mut()
                .is_some_and(|c| c.try_wait().ok().flatten().is_some());
            let log = self.log();
            if ready.iter().all(|r| log.contains(r)) {
                return Ok(());
            }
            if log.contains(fail) {
                return Err(tail(&log));
            }
            if exited {
                return Err(format!("the node exited\n{}", tail(&log)));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        Err(format!("timed out after {within:?}\n{}", tail(&self.log())))
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = Command::new("kill")
                .args(["-KILL", &format!("-{}", child.id())])
                .status();
            let _ = child.wait();
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The log's last module lines, without the scheduler's timing noise.
fn tail(log: &str) -> String {
    let lines: Vec<&str> = log
        .lines()
        .filter(|l| !l.contains("MON_") && !l.contains("] hb ") && !l.contains("] tlm "))
        .collect();
    lines[lines.len().saturating_sub(60)..].join("\n")
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// A fixed-newstyle NBD client on one export.
struct Nbd {
    s: TcpStream,
    size: u64,
}

impl Nbd {
    fn attach(port: u16) -> Nbd {
        let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect to the export");
        s.set_read_timeout(Some(Duration::from_secs(120))).unwrap();
        let mut greeting = [0u8; 18];
        s.read_exact(&mut greeting).unwrap();
        assert_eq!(&greeting[..8], b"NBDMAGIC");
        // Client flags: fixed newstyle, no zero padding.
        s.write_all(&3u32.to_be_bytes()).unwrap();
        s.write_all(&0x49484156454F5054u64.to_be_bytes()).unwrap();
        s.write_all(&1u32.to_be_bytes()).unwrap(); // NBD_OPT_EXPORT_NAME
        s.write_all(&0u32.to_be_bytes()).unwrap(); // any export
        let mut export = [0u8; 10];
        s.read_exact(&mut export).unwrap();
        let size = u64::from_be_bytes(export[..8].try_into().unwrap());
        Nbd { s, size }
    }

    fn request(&mut self, cmd: u16, handle: u64, off: u64, len: u32) {
        let mut h = Vec::with_capacity(28);
        h.extend_from_slice(&0x25609513u32.to_be_bytes());
        h.extend_from_slice(&0u16.to_be_bytes());
        h.extend_from_slice(&cmd.to_be_bytes());
        h.extend_from_slice(&handle.to_be_bytes());
        h.extend_from_slice(&off.to_be_bytes());
        h.extend_from_slice(&len.to_be_bytes());
        self.s.write_all(&h).unwrap();
    }

    fn reply(&mut self, handle: u64) -> u32 {
        let mut hdr = [0u8; 16];
        self.s.read_exact(&mut hdr).unwrap();
        assert_eq!(u32::from_be_bytes(hdr[..4].try_into().unwrap()), 0x67446698);
        assert_eq!(u64::from_be_bytes(hdr[8..].try_into().unwrap()), handle);
        u32::from_be_bytes(hdr[4..8].try_into().unwrap())
    }

    fn write(&mut self, off: u64, data: &[u8]) {
        self.request(1, 1, off, data.len() as u32);
        self.s.write_all(data).unwrap();
        assert_eq!(self.reply(1), 0, "write");
    }

    fn flush(&mut self) {
        self.request(3, 2, 0, 0);
        assert_eq!(self.reply(2), 0, "flush");
    }

    fn read(&mut self, off: u64, len: usize) -> Vec<u8> {
        self.request(0, 3, off, len as u32);
        assert_eq!(self.reply(3), 0, "read");
        let mut out = vec![0u8; len];
        self.s.read_exact(&mut out).unwrap();
        out
    }

    fn disconnect(mut self) {
        self.request(2, 4, 0, 0);
    }
}

/// What the client writes: the needle, repeated through a position-dependent
/// pattern, so a read-back that returns the right number of wrong bytes
/// fails.
fn payload() -> Vec<u8> {
    let mut p: Vec<u8> = (0..64 * 1024).map(|i| (i * 31 % 251) as u8).collect();
    for at in (0..p.len() - NEEDLE.len()).step_by(4096) {
        p[at..at + NEEDLE.len()].copy_from_slice(NEEDLE);
    }
    p
}

/// Write and flush through the node's export on a fresh volume; return the
/// committed volume's bytes as `loam-client` reads them.
fn write_through_the_node(encrypted: bool) -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn_tls_server(server_bin(), dir.path(), GRANTS);
    srv.connect(Name::Cn("node-a"))
        .create_volume(b"tenant", b"/vols/v0", VOLUME_BYTES, EXTENT)
        .unwrap();

    let port = free_port();
    let mut node = Node::run(
        dir.path(),
        &graph(dir.path(), &srv, "tenant", encrypted, port),
    );
    let mut ready = vec!["[loam_volume] ready", "[nbd] listening"];
    if encrypted {
        ready.push("[crypt_block] ready");
    }
    if let Err(why) = node.wait(&ready, "ERROR", Duration::from_secs(120)) {
        panic!("the node did not come up:\n{why}");
    }

    let data = payload();
    let mut nbd = Nbd::attach(port);
    assert!(
        nbd.size >= AT + data.len() as u64,
        "export of {} bytes",
        nbd.size
    );
    nbd.write(AT, &data);
    nbd.flush();
    assert!(
        nbd.read(AT, data.len()) == data,
        "the export reads back what was written"
    );
    nbd.disconnect();
    // The admin surface serves one connection at a time: the node's must
    // end before the read-back's is served.
    node.stop();

    let mut c = srv.connect(Name::Cn("node-a"));
    let mut vol = c
        .open_volume(b"tenant", b"/vols/v0")
        .unwrap()
        .expect("the node committed the volume");
    let mut bytes = vec![0u8; vol.size_bytes as usize];
    c.volume_read(&mut vol, 0, &mut bytes).unwrap();
    bytes
}

#[test]
fn a_node_publishes_an_encrypted_loam_volume_over_mutual_tls() {
    if !prereqs_or_skip() {
        return;
    }
    let bytes = write_through_the_node(true);
    assert!(
        bytes.iter().any(|&b| b != 0),
        "the node committed nothing to the volume"
    );
    assert!(
        !contains(&bytes, NEEDLE),
        "the committed volume holds the client's plaintext"
    );
}

#[test]
fn control_without_crypt_block_the_volume_holds_the_plaintext() {
    if !prereqs_or_skip() {
        return;
    }
    let bytes = write_through_the_node(false);
    assert!(
        bytes[AT as usize..].starts_with(NEEDLE),
        "the control volume lacks what the client wrote: the needle would prove nothing"
    );
}

#[test]
fn a_node_without_a_grant_on_the_root_gets_no_volume() {
    if !prereqs_or_skip() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn_tls_server(server_bin(), dir.path(), GRANTS);
    srv.connect(Name::Cn("node-b"))
        .create_volume(b"other", b"/vols/v0", VOLUME_BYTES, EXTENT)
        .unwrap();
    // node-a's certificate, naming a root only node-b is granted.
    let mut node = Node::run(
        dir.path(),
        &graph(dir.path(), &srv, "other", false, free_port()),
    );
    let outcome = node.wait(&["[loam_volume] ready"], "ERROR", Duration::from_secs(60));
    let log = node.log();
    assert!(outcome.is_err(), "an ungranted node got its volume");
    assert!(
        log.lines()
            .any(|l| l.contains("ERROR") && l.contains("[loam_volume] ")),
        "the refusal should surface at the volume:\n{}",
        tail(&log)
    );
}
