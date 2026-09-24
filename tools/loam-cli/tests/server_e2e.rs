//! End-to-end test for the loam-server + admin-bind pipe.
//! Spawns the server as a subprocess, waits for it to announce its
//! admin socket, fires an `admin-bind` from the CLI, and verifies the
//! round-trip.

mod support;

use serde_json::Value;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use support::{spawn_ready, Proc};
use tempfile::tempdir;

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn cli_bin() -> &'static str {
    env!("CARGO_BIN_EXE_loam")
}

fn server_bin() -> &'static str {
    env!("CARGO_BIN_EXE_loam-server")
}

fn spawn_server(socket: &std::path::Path, dir: &std::path::Path) -> Proc {
    let mut cmd = Command::new(server_bin());
    cmd.args([
        "--socket",
        socket.to_str().unwrap(),
        "--ns-wal",
        dir.join("ns.wal").to_str().unwrap(),
        "--obj-wal",
        dir.join("obj.wal").to_str().unwrap(),
        "--fleet",
        &format!("dir:{}", dir.join("bodies").display()),
        "--tick-us",
        "1000",
    ]);
    spawn_ready(cmd, "admin socket on").0
}

fn run_cli(args: &[&str]) -> (Value, std::process::ExitStatus) {
    let mut cmd = Command::new(cli_bin());
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    let output = cmd.output().expect("run cli");
    let json = if output.stdout.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
            panic!(
                "expected JSON; got:\n{}\nerr: {e}",
                String::from_utf8_lossy(&output.stdout)
            )
        })
    };
    (json, output.status)
}

#[test]
fn admin_bind_round_trips_through_loam_server() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempdir().unwrap();
    let socket = dir.path().join("loam.sock");
    let _server = spawn_server(&socket, dir.path());

    let (json, status) = run_cli(&[
        "admin-bind",
        "--socket",
        socket.to_str().unwrap(),
        "acme",
        "/server/round-trip.txt",
        "sha256:abc",
    ]);
    assert!(status.success(), "admin-bind: {json}");
    assert_eq!(json["status"], "ok");
    assert_eq!(json["transport"], "unix-socket");
    assert_eq!(json["object_id"], "sha256:abc");
}

#[test]
fn admin_bind_nak_returns_error_for_duplicate_path() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempdir().unwrap();
    let socket = dir.path().join("loam.sock");
    let _server = spawn_server(&socket, dir.path());

    // First bind succeeds.
    let (_, status) = run_cli(&[
        "admin-bind",
        "--socket",
        socket.to_str().unwrap(),
        "acme",
        "/dup",
        "sha256:1",
    ]);
    assert!(status.success(), "first bind should succeed");
    // Second bind to the same path NAKs.
    let (_json, status) = run_cli(&[
        "admin-bind",
        "--socket",
        socket.to_str().unwrap(),
        "acme",
        "/dup",
        "sha256:2",
    ]);
    assert!(!status.success(), "duplicate bind should fail at CLI exit");
}
