//! End-to-end tests for the fluxor-native loam CLI. Each test
//! invokes the binary as a subprocess (via `CARGO_BIN_EXE_loam`)
//! and asserts on stdout JSON. The CLI drives real PIC bodies
//! in-process; these tests therefore exercise the same code
//! paths a deployed fluxor graph would.
//!
//! Read-side commands (`read`, `list`, etc.) are not yet wired
//! into the public PICs, so the CLI doesn't ship them. Tests
//! cover the surface that does exist.
//!
//! Tests serialize via `TEST_LOCK` since they all share the
//! `/tmp` filesystem and the CLI's in-process channels are
//! reset per-invocation already.

use serde_json::Value;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use tempfile::tempdir;

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_loam")
}

fn run(args: &[&str]) -> (Value, Vec<u8>, std::process::ExitStatus) {
    run_with_stdin(args, &[])
}

fn run_with_stdin(args: &[&str], stdin: &[u8]) -> (Value, Vec<u8>, std::process::ExitStatus) {
    let mut cmd = Command::new(bin());
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn loam binary");
    if !stdin.is_empty() {
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(stdin)
            .expect("write stdin");
    }
    let output = child.wait_with_output().expect("wait on loam");
    let stdout = output.stdout.clone();
    let json = if stdout.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&stdout).unwrap_or_else(|e| {
            panic!(
                "expected JSON stdout; got:\n{}\nerr: {e}",
                String::from_utf8_lossy(&stdout)
            )
        })
    };
    (json, output.stderr, output.status)
}

#[test]
fn cli_validate_accepts_default_config() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let (json, _, status) = run(&["validate", "--config", "../../config/loam.toml"]);
    assert!(status.success());
    assert_eq!(json["status"], "ok");
}

#[test]
fn cli_plan_reports_node_class() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let (json, _, status) = run(&["plan", "--config", "../../config/loam.toml"]);
    assert!(status.success());
    assert!(
        json.get("node_class").is_some(),
        "plan output missing node_class: {json}"
    );
}

#[test]
fn cli_surfaces_lists_public_and_internal_modules() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let (json, _, status) = run(&["surfaces"]);
    assert!(status.success());
    let bindings = json["bindings"].as_array().expect("bindings array");
    let public: Vec<_> = bindings
        .iter()
        .filter(|b| b["visibility"] == "public")
        .collect();
    let internal: Vec<_> = bindings
        .iter()
        .filter(|b| b["visibility"] == "internal")
        .collect();
    assert_eq!(public.len(), 3, "three public surfaces expected");
    assert!(!internal.is_empty(), "internal modules present");
}

#[test]
fn cli_bind_persists_to_wal() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempdir().unwrap();
    let wal = dir.path().join("ns.wal");
    let (json, _, status) = run(&[
        "bind",
        "--wal",
        wal.to_str().unwrap(),
        "acme",
        "/users/alice",
        "sha256:cafebabe",
    ]);
    assert!(status.success(), "bind failed: {json}");
    assert_eq!(json["status"], "ok");
    assert_eq!(json["namespace"], "acme");
    assert_eq!(json["object_id"], "sha256:cafebabe");
    assert!(wal.exists());
    let wal_bytes = std::fs::read(&wal).unwrap();
    assert!(!wal_bytes.is_empty(), "WAL has at least one record");
}

#[test]
fn cli_put_body_stores_content_addressed_file() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempdir().unwrap();
    let body_root = dir.path().join("bodies");
    let payload = b"hello loam";
    let (json, _, status) = run_with_stdin(
        &["put-body", "--body-root", body_root.to_str().unwrap(), "-"],
        payload,
    );
    assert!(status.success(), "put-body failed: {json}");
    assert_eq!(json["fence"], "ContentHashed");
    let digest = json["digest"].as_str().expect("digest string");
    let hex = digest.strip_prefix("sha256:").expect("sha256: prefix");
    let on_disk = body_root.join(hex);
    assert!(
        on_disk.exists(),
        "body file landed at {}",
        on_disk.display()
    );
    let stored = std::fs::read(&on_disk).unwrap();
    assert_eq!(stored, payload);
}

#[test]
fn cli_put_file_composes_body_put_and_bind() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempdir().unwrap();
    let wal = dir.path().join("ns.wal");
    let body_root = dir.path().join("bodies");
    let payload = b"composed-put-file";
    let (json, _, status) = run_with_stdin(
        &[
            "put-file",
            "--wal",
            wal.to_str().unwrap(),
            "--body-root",
            body_root.to_str().unwrap(),
            "acme",
            "/composed.txt",
            "-",
        ],
        payload,
    );
    assert!(status.success(), "put-file failed: {json}");
    assert_eq!(json["status"], "ok");
    assert_eq!(json["fence_body"], "ContentHashed");
    assert_eq!(json["fence_binding"], "LocalDurable");
    assert!(json["object_id"].as_str().unwrap().starts_with("sha256:"));
    let oid = json["object_id"].as_str().unwrap();
    let hex = oid.strip_prefix("sha256:").unwrap();
    assert!(body_root.join(hex).exists(), "body landed");
    assert!(wal.exists(), "WAL has bind record");
}

#[test]
fn cli_read_returns_bound_object_id_after_bind() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempdir().unwrap();
    let wal = dir.path().join("ns.wal");

    let (bind_json, _, status) = run(&[
        "bind",
        "--wal",
        wal.to_str().unwrap(),
        "acme",
        "/r/read.txt",
        "sha256:feedface",
    ]);
    assert!(status.success(), "bind: {bind_json}");

    let (read_json, _, status) = run(&[
        "read",
        "--wal",
        wal.to_str().unwrap(),
        "acme",
        "/r/read.txt",
    ]);
    assert!(status.success(), "read: {read_json}");
    assert_eq!(read_json["status"], "ok");
    assert_eq!(read_json["object_id"], "sha256:feedface");
    assert_eq!(read_json["kind"], "file");
}

#[test]
fn cli_read_reports_not_found_for_unbound_path() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempdir().unwrap();
    let wal = dir.path().join("ns.wal");
    // Bind something else so the WAL has at least one record.
    let _ = run(&[
        "bind",
        "--wal",
        wal.to_str().unwrap(),
        "acme",
        "/exists",
        "sha256:1",
    ]);
    let (json, _, status) = run(&["read", "--wal", wal.to_str().unwrap(), "acme", "/nope"]);
    assert!(
        status.success(),
        "read should succeed even when not found: {json}"
    );
    assert_eq!(json["status"], "not_found");
}

#[test]
fn cli_resolve_returns_binding_and_descriptor() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempdir().unwrap();
    let ns_wal = dir.path().join("ns.wal");
    let obj_wal = dir.path().join("obj.wal");
    let oid = "sha256:resolveme";

    run(&[
        "bind",
        "--wal",
        ns_wal.to_str().unwrap(),
        "acme",
        "/resolve.txt",
        oid,
    ]);
    run(&[
        "put-object",
        "--wal",
        obj_wal.to_str().unwrap(),
        "--id",
        oid,
        "--namespace",
        "acme",
        "--key",
        "/resolve.txt",
        "--size",
        "42",
    ]);

    let (json, _, status) = run(&[
        "resolve",
        "--ns-wal",
        ns_wal.to_str().unwrap(),
        "--obj-wal",
        obj_wal.to_str().unwrap(),
        "acme",
        "/resolve.txt",
    ]);
    assert!(status.success(), "resolve: {json}");
    assert_eq!(json["status"], "ok");
    assert_eq!(json["binding"]["object_id"], oid);
    assert_eq!(json["descriptor"]["size_bytes"], 42);
}

#[test]
fn cli_resolve_reports_dangling_when_descriptor_missing() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempdir().unwrap();
    let ns_wal = dir.path().join("ns.wal");
    let obj_wal = dir.path().join("obj.wal");
    let oid = "sha256:bindonly";

    // Bind path; never put the corresponding descriptor.
    run(&[
        "bind",
        "--wal",
        ns_wal.to_str().unwrap(),
        "acme",
        "/dangle.txt",
        oid,
    ]);
    // Need at least an empty obj_wal for the resolve to succeed.
    // First put-object with a different id seeds the WAL.
    run(&[
        "put-object",
        "--wal",
        obj_wal.to_str().unwrap(),
        "--id",
        "sha256:other",
        "--namespace",
        "acme",
        "--key",
        "/other",
        "--size",
        "1",
    ]);

    let (json, _, status) = run(&[
        "resolve",
        "--ns-wal",
        ns_wal.to_str().unwrap(),
        "--obj-wal",
        obj_wal.to_str().unwrap(),
        "acme",
        "/dangle.txt",
    ]);
    assert!(status.success(), "resolve: {json}");
    assert_eq!(json["status"], "dangling");
    assert_eq!(json["binding_object_id"], oid);
}

#[test]
fn cli_validate_missing_config_errors_out() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let nope = Path::new("/nonexistent/loam-cli/does-not-exist.toml");
    let (_, _, status) = run(&["validate", "--config", nope.to_str().unwrap()]);
    assert!(!status.success(), "missing config should fail");
}
