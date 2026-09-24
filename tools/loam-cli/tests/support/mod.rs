//! Starting the binaries under test, and knowing when they are ready.
//!
//! Readiness is the process's OWN announcement, read from its stderr,
//! never a probe of the address it was asked to use. A connect that
//! succeeds proves only that something listens there: when two suites
//! run at once and a port is already held, the new process fails to
//! bind and exits, the probe connects to the other suite's server,
//! and the test goes on talking to a stranger. Every listener here
//! therefore binds port 0 and is found through the address it
//! reports, so no two processes can be handed the same one.

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// How long a process has to announce itself before the test fails.
const READY_WITHIN: Duration = Duration::from_secs(10);

/// A spawned process, killed and reaped when dropped so a failing
/// test cannot leave a server holding its socket.
pub struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Spawn `cmd` and wait for the first stderr line containing
/// `ready`. Returns the process and that line.
///
/// Fails the test if the process exits, or stays silent past
/// `READY_WITHIN`, before announcing — both surface the process's
/// own output rather than a later, misleading protocol error.
pub fn spawn_ready(mut cmd: Command, ready: &str) -> (Proc, String) {
    cmd.stdout(Stdio::null()).stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn process under test");
    let stderr = child.stderr.take().expect("piped stderr");
    let proc = Proc(child);

    // Stderr is drained for the life of the process, not just until
    // ready: a server whose pipe fills blocks on its next log line.
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let _ = tx.send(line.trim_end().to_string());
                }
            }
        }
    });

    let mut seen = Vec::new();
    loop {
        match rx.recv_timeout(READY_WITHIN) {
            Ok(line) if line.contains(ready) => return (proc, line),
            Ok(line) => seen.push(line),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!(
                    "exited before announcing {ready:?}; stderr:\n{}",
                    seen.join("\n")
                )
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!(
                    "no {ready:?} within {READY_WITHIN:?}; stderr:\n{}",
                    seen.join("\n")
                )
            }
        }
    }
}

/// The socket address an announcement names — the first token that
/// parses as one, so it holds wherever the address sits in the line.
#[allow(
    dead_code,
    reason = "mounted into every suite; the unix-socket-only suites never read an address"
)]
pub fn announced_addr(line: &str) -> SocketAddr {
    line.split_whitespace()
        .find_map(|tok| tok.parse().ok())
        .unwrap_or_else(|| panic!("no socket address in {line:?}"))
}
