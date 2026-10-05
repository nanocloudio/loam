// The client side of loam's admin plane, shared by every module that
// speaks to `admin_gate`: a volume, the operator applet.
//
// A client reaches the gate one of two ways:
//
// - an in-graph link (`link{i}_in` / `link{i}_out` on the gate): records
//   `[session:u32][frame]`, one per buffer, both ways;
// - the network: net_proto to the clear side of a client-mode `tls`
//   (`net_out` to `tls.clear_in`, `tls.clear_out` to `net_in`), dialing
//   the gate's authority. Mutual TLS authenticates the client; its
//   certificate is the `tls` module's.
//
// Before anything else the client presents every capability chain it was
// given (`MSG_CAP_PRESENT`) and waits for each answer; a chain refused is
// the end of the client, reported with its reason, never retried. Then it
// is ready: `send` takes one admin request at a time, whole, and `recv`
// yields answers, whole, in the order the gate sends them. Capability
// answers never reach the caller.
//
// Over the network the gate's answers are a byte stream, delimited by
// `loam_admin_wire::response_len`; the client reads it only while it has
// room for what may arrive, so a slow consumer slows the stream instead
// of losing it.
//
// The includer's scope provides `SyscallTable`, `abi` and `admin`
// (loam_admin_wire).

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

use super::abi::contracts::mesh::capability as cap;
use super::abi::contracts::net::net_proto;
use super::admin as aw;

/// Chains one client presents: a key scope and the body plane, with room
/// for a client that holds several scopes. Bounded by what one session
/// may hold.
pub const MAX_CHAINS: usize = cap::MAX_SESSION_GRANTS;
/// A capability file: one `fxcap1.` chain per line.
pub const CAP_FILE_MAX: usize = MAX_CHAINS * (cap::MAX_TEXT_LEN + 1);
/// Longest `host[:port]` a client dials.
pub const AUTHORITY_MAX: usize = 128;
/// How long a connection or a presentation may take before the client
/// gives up.
pub const SETUP_TIMEOUT_MS: u64 = 10_000;
/// The wait before dialing again when the transport refused a dial for
/// now. A dial is refused only while another is in flight, which is one
/// TCP handshake; retries stay inside `SETUP_TIMEOUT_MS`.
const DIAL_RETRY_MS: u64 = 20;
/// `EAGAIN`, as a transport's `MSG_ERROR` carries it.
const EAGAIN: i32 = -11;

pub const NET_FRAME_MAX: usize =
    net_proto::FRAME_HDR + net_proto::CONN_ID_LEN + net_proto::MAX_DATA_FRAGMENT;
/// Bytes of the gate's answers held: one whole answer, and behind it the
/// network fragment, or the link record, that may follow it.
const RX_MAX: usize = 4 + aw::RESPONSE_MAX + net_proto::MAX_DATA_FRAGMENT;
const CAP_ANSWER_FRAME_MAX: usize = cap::FRAME_HDR + cap::ANSWER_GRANTED;

pub const T_LINK: u8 = 1;
pub const T_NET: u8 = 2;

pub const ST_CONNECTING: u8 = 0;
pub const ST_PRESENTING: u8 = 1;
pub const ST_READY: u8 = 2;
pub const ST_FAILED: u8 = 3;

/// Why a client failed.
pub const WHY_NONE: u8 = 0;
/// The connection could not be made, or closed.
pub const WHY_TRANSPORT: u8 = 1;
/// A chain was refused; `refusal` says why.
pub const WHY_REFUSED: u8 = 2;
/// The gate saw no authenticated peer on the session.
pub const WHY_UNAUTHENTICATED: u8 = 3;
/// The session already holds as many grants as it may.
pub const WHY_GRANTS_FULL: u8 = 4;
/// The stream carried something no answer can be.
pub const WHY_PROTOCOL: u8 = 5;
/// Setup did not finish in time.
pub const WHY_TIMEOUT: u8 = 6;

#[repr(C)]
pub struct Client {
    pub transport: u8,
    pub status: u8,
    pub why: u8,
    /// The `cap::Refusal` byte of a refused chain.
    pub refusal: u8,
    // ── Link ──
    pub link_in: i32,
    pub link_out: i32,
    pub session: u32,
    // ── Network ──
    pub net_in: i32,
    pub net_out: i32,
    pub tag: u8,
    /// Another owner reads the transport and feeds this client
    /// (`feed`): clients dialing over one `tls` share its clear side.
    pub shared: u8,
    pub conn: u16,
    pub connected: u8,
    pub dialed: u8,
    /// The transport refused the dial for now (`EAGAIN`: `tls` makes one
    /// outbound connection at a time): 1 until the next poll schedules
    /// the redial, 2 until `redial_at_ms`.
    pub redial: u8,
    pub redial_at_ms: u64,
    pub authority: [u8; AUTHORITY_MAX],
    pub authority_len: u8,
    pub since_ms: u64,
    // ── Chains ──
    pub chains: [[u8; cap::MAX_CHAIN_BYTES]; MAX_CHAINS],
    pub chain_len: [u16; MAX_CHAINS],
    pub chain_count: u8,
    /// The next chain to present, and whether its answer is awaited.
    pub presenting: u8,
    pub awaiting: u8,
    // ── Outgoing: one frame at a time ──
    pub tx_len: u32,
    pub tx_sent: u32,
    pub tx: [u8; 4 + aw::REQUEST_MAX],
    // ── Incoming ──
    pub nf_len: u32,
    pub nf: [u8; NET_FRAME_MAX],
    pub rx_len: u32,
    pub rx: [u8; RX_MAX],
    /// Length of the whole answer at the front of `rx` the caller holds,
    /// 0 when it holds none.
    pub held: u32,
}

/// Copy `src` to the front of `dst` by index: a slice copy of a runtime
/// length pulls panic paths the PIC link does not carry.
#[allow(
    clippy::manual_memcpy,
    reason = "a slice copy of a runtime length pulls panic paths the PIC link does not carry"
)]
fn put(dst: &mut [u8], src: &[u8]) {
    for i in 0..src.len() {
        dst[i] = src[i];
    }
}

/// Parse a capability file: one `fxcap1.` chain per line; blank lines
/// and lines starting `#` are skipped. False when a line does not decode
/// or there are more than `MAX_CHAINS`.
pub fn load_chains(c: &mut Client, text: &[u8]) -> bool {
    c.chain_count = 0;
    let mut start = 0;
    while start <= text.len() {
        let mut end = start;
        while end < text.len() && text[end] != b'\n' {
            end += 1;
        }
        let mut line = &text[start..end];
        while let [rest @ .., b'\r' | b' ' | b'\t'] = line {
            line = rest;
        }
        while let [b' ' | b'\t', rest @ ..] = line {
            line = rest;
        }
        if !line.is_empty() && line[0] != b'#' {
            let i = c.chain_count as usize;
            if i == MAX_CHAINS {
                return false;
            }
            match cap::decode_text(line, &mut c.chains[i]) {
                Some(n) => {
                    c.chain_len[i] = n as u16;
                    c.chain_count += 1;
                }
                None => return false,
            }
        }
        start = end + 1;
    }
    true
}

/// `fs` opcodes for reading a capability file.
const FS_OPEN: u32 = 0x0900;
const FS_READ: u32 = 0x0901;
const FS_CLOSE: u32 = 0x0903;

/// Read a capability file through `fs` and load its chains. `Err` names
/// the cause: the file is missing or unreadable, larger than any file of
/// `MAX_CHAINS` chains, holds a line that is not a chain, or holds none.
pub unsafe fn load_chain_file(
    c: &mut Client,
    sys: &super::SyscallTable,
    path: &[u8],
    scratch: &mut [u8; CAP_FILE_MAX],
) -> Result<(), &'static [u8]> {
    let fd = (sys.provider_call)(-1, FS_OPEN, path.as_ptr() as *mut u8, path.len());
    if fd < 0 {
        return Err(b"the capability file cannot be opened");
    }
    let mut filled = 0usize;
    let mut over = false;
    loop {
        if filled == scratch.len() {
            // Probe for one byte past the ceiling: a file that has one is
            // refused, not cut short.
            let mut probe = [0u8; 1];
            over = (sys.provider_call)(fd, FS_READ, probe.as_mut_ptr(), 1) > 0;
            break;
        }
        let n = (sys.provider_call)(
            fd,
            FS_READ,
            scratch.as_mut_ptr().add(filled),
            scratch.len() - filled,
        );
        if n <= 0 {
            break;
        }
        filled += n as usize;
    }
    (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
    if over {
        return Err(b"the capability file is larger than MAX_CHAINS chains");
    }
    if !load_chains(c, &scratch[..filled]) {
        return Err(b"the capability file holds a line that is not a chain, or too many");
    }
    if c.chain_count == 0 {
        return Err(b"the capability file holds no chain");
    }
    Ok(())
}

/// A client over an in-graph link.
pub fn init_link(c: &mut Client, link_in: i32, link_out: i32, session: u32, now_ms: u64) {
    c.transport = T_LINK;
    c.link_in = link_in;
    c.link_out = link_out;
    c.session = session;
    c.status = ST_PRESENTING;
    c.since_ms = now_ms;
}

/// A client over the network, dialing `authority` (`host[:port]`).
/// False when the authority is too long to hold.
pub fn init_net(
    c: &mut Client,
    net_in: i32,
    net_out: i32,
    tag: u8,
    authority: &[u8],
    now_ms: u64,
) -> bool {
    if authority.is_empty() || authority.len() > AUTHORITY_MAX {
        return false;
    }
    c.transport = T_NET;
    c.net_in = net_in;
    c.net_out = net_out;
    c.tag = tag;
    put(&mut c.authority, authority);
    c.authority_len = authority.len() as u8;
    c.status = ST_CONNECTING;
    c.since_ms = now_ms;
    true
}

pub fn is_ready(c: &Client) -> bool {
    c.status == ST_READY
}

pub fn has_failed(c: &Client) -> bool {
    c.status == ST_FAILED
}

/// A request can be handed over now.
pub fn can_send(c: &Client) -> bool {
    c.status == ST_READY && c.tx_len == 0
}

fn fail(c: &mut Client, why: u8) {
    c.status = ST_FAILED;
    c.why = why;
}

/// Hand over one whole admin request. False, with nothing taken, unless
/// `can_send`.
pub unsafe fn send(c: &mut Client, sys: &super::SyscallTable, frame: &[u8]) -> bool {
    if !can_send(c) || frame.len() > aw::REQUEST_MAX {
        return false;
    }
    stage(c, frame);
    flush(c, sys);
    true
}

/// Stage a frame, enveloped for a link.
fn stage(c: &mut Client, frame: &[u8]) {
    let at = if c.transport == T_LINK {
        put(&mut c.tx[..4], &c.session.to_le_bytes());
        4
    } else {
        0
    };
    put(&mut c.tx[at..at + frame.len()], frame);
    c.tx_len = (at + frame.len()) as u32;
    c.tx_sent = 0;
}

/// Drive the client: dial, present, send what is owed, read what came.
pub unsafe fn poll(c: &mut Client, sys: &super::SyscallTable, now_ms: u64) {
    if c.status == ST_FAILED {
        return;
    }
    if c.status != ST_READY && now_ms.saturating_sub(c.since_ms) > SETUP_TIMEOUT_MS {
        fail(c, WHY_TIMEOUT);
        return;
    }
    if c.redial == 1 {
        c.redial = 2;
        c.redial_at_ms = now_ms + DIAL_RETRY_MS;
    } else if c.redial == 2 && now_ms >= c.redial_at_ms {
        c.redial = 0;
    }
    match c.transport {
        T_NET => net_poll(c, sys),
        T_LINK => link_poll(c, sys),
        _ => {}
    }
    if c.status == ST_PRESENTING && c.awaiting == 0 && c.tx_len == 0 {
        if c.presenting >= c.chain_count {
            c.status = ST_READY;
        } else {
            let i = c.presenting as usize;
            let n = c.chain_len[i] as usize;
            let mut f = [0u8; cap::FRAME_HDR + 4 + cap::MAX_CHAIN_BYTES];
            f[0] = cap::MSG_CAP_PRESENT;
            put(&mut f[1..3], &((4 + n) as u16).to_le_bytes());
            put(&mut f[3..7], &(i as u32 + 1).to_le_bytes());
            let chain: &[u8] = &*(&c.chains[i][..n] as *const [u8]);
            put(&mut f[7..7 + n], chain);
            stage(c, &f[..7 + n]);
            c.awaiting = 1;
        }
    }
    flush(c, sys);
}

/// Offer the staged frame.
unsafe fn flush(c: &mut Client, sys: &super::SyscallTable) {
    if c.tx_len == 0 {
        return;
    }
    match c.transport {
        T_LINK => {
            let n = c.tx_len as usize;
            if (sys.channel_write)(c.link_out, c.tx.as_ptr(), n) == n as i32 {
                c.tx_len = 0;
            }
        }
        _ => {
            if c.connected == 0 {
                return;
            }
            while c.tx_sent < c.tx_len {
                let at = c.tx_sent as usize;
                let take = (c.tx_len as usize - at).min(net_proto::MAX_CMD_DATA);
                let mut f =
                    [0u8; net_proto::FRAME_HDR + net_proto::CONN_ID_LEN + net_proto::MAX_CMD_DATA];
                let plen = net_proto::CONN_ID_LEN + take;
                f[0] = net_proto::CMD_SEND;
                put(&mut f[1..3], &(plen as u16).to_le_bytes());
                put(&mut f[3..5], &c.conn.to_le_bytes());
                let src: &[u8] = &*(&c.tx[at..at + take] as *const [u8]);
                put(&mut f[5..5 + take], src);
                let n = net_proto::FRAME_HDR + plen;
                if (sys.channel_write)(c.net_out, f.as_ptr(), n) != n as i32 {
                    return;
                }
                c.tx_sent += take as u32;
            }
            c.tx_len = 0;
            c.tx_sent = 0;
        }
    }
}

// ── Answers ───────────────────────────────────────────────────────────────

/// The next whole admin answer, held until `take`.
pub fn recv(c: &mut Client) -> Option<&[u8]> {
    if c.held != 0 {
        return Some(&c.rx[..c.held as usize]);
    }
    loop {
        let have = c.rx_len as usize;
        if have == 0 {
            return None;
        }
        if c.rx[0] == cap::MSG_CAP_ANSWER {
            if have < cap::FRAME_HDR {
                return None;
            }
            let n = cap::FRAME_HDR + u16::from_le_bytes([c.rx[1], c.rx[2]]) as usize;
            if n > CAP_ANSWER_FRAME_MAX {
                fail(c, WHY_PROTOCOL);
                return None;
            }
            if have < n {
                return None;
            }
            let payload: &[u8] = unsafe { &*(&c.rx[cap::FRAME_HDR..n] as *const [u8]) };
            on_cap_answer(c, payload);
            consume(c, n);
            if c.status == ST_FAILED {
                return None;
            }
            continue;
        }
        return match aw::response_len(&c.rx[..have]) {
            Ok(n) if n > aw::RESPONSE_MAX => {
                fail(c, WHY_PROTOCOL);
                None
            }
            Ok(n) if n <= have => {
                c.held = n as u32;
                Some(&c.rx[..n])
            }
            Ok(_) | Err(aw::WireError::Truncated) => None,
            Err(_) => {
                fail(c, WHY_PROTOCOL);
                None
            }
        };
    }
}

/// Release the answer `recv` returned.
pub fn take(c: &mut Client) {
    let n = c.held as usize;
    c.held = 0;
    consume(c, n);
}

fn consume(c: &mut Client, n: usize) {
    let have = c.rx_len as usize;
    for k in n..have {
        c.rx[k - n] = c.rx[k];
    }
    c.rx_len = (have - n) as u32;
}

fn on_cap_answer(c: &mut Client, p: &[u8]) {
    if c.awaiting == 0 || p.len() < cap::ANSWER_FIXED {
        fail(c, WHY_PROTOCOL);
        return;
    }
    c.awaiting = 0;
    match p[4] {
        cap::status::GRANTED => c.presenting += 1,
        cap::status::UNAUTHENTICATED => fail(c, WHY_UNAUTHENTICATED),
        cap::status::GRANTS_FULL => fail(c, WHY_GRANTS_FULL),
        _ => {
            c.refusal = p[5];
            fail(c, WHY_REFUSED);
        }
    }
}

/// Append answer bytes from the transport.
fn absorb(c: &mut Client, data: &[u8]) -> bool {
    let at = c.rx_len as usize;
    if at + data.len() > RX_MAX {
        return false;
    }
    put(&mut c.rx[at..at + data.len()], data);
    c.rx_len += data.len() as u32;
    true
}

// ── Transports ─────────────────────────────────────────────────────────────

unsafe fn link_poll(c: &mut Client, sys: &super::SyscallTable) {
    loop {
        // A record is read straight into place, so only with room for
        // the largest.
        let at = c.rx_len as usize;
        if at + 4 + aw::RESPONSE_MAX > RX_MAX {
            return;
        }
        let n = (sys.channel_read)(c.link_in, c.rx.as_mut_ptr().add(at), 4 + aw::RESPONSE_MAX);
        if n <= 0 {
            return;
        }
        let n = n as usize;
        if n < 4 {
            fail(c, WHY_PROTOCOL);
            return;
        }
        let session = u32::from_le_bytes([c.rx[at], c.rx[at + 1], c.rx[at + 2], c.rx[at + 3]]);
        // Lift the frame over its envelope.
        for k in 0..n - 4 {
            c.rx[at + k] = c.rx[at + 4 + k];
        }
        if session != c.session {
            // Another session's answer on a shared link.
            continue;
        }
        c.rx_len += (n - 4) as u32;
        if c.status == ST_PRESENTING {
            // Presentation answers come before any admin answer.
            let _ = recv(c);
        }
    }
}

unsafe fn net_poll(c: &mut Client, sys: &super::SyscallTable) {
    net_dial(c, sys);
    if c.shared != 0 || c.status == ST_FAILED {
        return;
    }
    net_read(c, sys);
}

unsafe fn net_dial(c: &mut Client, sys: &super::SyscallTable) {
    if c.connected == 0 && c.dialed == 0 && c.redial == 0 {
        let authority: &[u8] = &*(&c.authority[..c.authority_len as usize] as *const [u8]);
        let Some((target, port)) = net_proto::Target::parse(authority) else {
            fail(c, WHY_TRANSPORT);
            return;
        };
        let mut p = [0u8; net_proto::CONNECT_TO_MAX];
        let n = net_proto::write_connect_to(
            &mut p,
            net_proto::SOCK_TYPE_STREAM,
            port.unwrap_or(7443),
            &target,
            Some(c.tag),
        );
        if n == 0 {
            fail(c, WHY_TRANSPORT);
            return;
        }
        if net_cmd(c, sys, net_proto::CMD_CONNECT_TO, &p[..n]) {
            c.dialed = 1;
        }
    }
}

unsafe fn net_read(c: &mut Client, sys: &super::SyscallTable) {
    for _ in 0..16 {
        // Read only with room for the fragment a frame may carry.
        if c.rx_len as usize + net_proto::MAX_DATA_FRAGMENT > RX_MAX {
            break;
        }
        let have = c.nf_len as usize;
        let want = if have < net_proto::FRAME_HDR {
            net_proto::FRAME_HDR - have
        } else {
            let len = u16::from_le_bytes([c.nf[1], c.nf[2]]) as usize;
            if net_proto::FRAME_HDR + len > NET_FRAME_MAX {
                fail(c, WHY_PROTOCOL);
                return;
            }
            net_proto::FRAME_HDR + len - have
        };
        if want > 0 {
            let n = (sys.channel_read)(c.net_in, c.nf.as_mut_ptr().add(have), want);
            if n <= 0 {
                return;
            }
            c.nf_len += n as u32;
            if (n as usize) < want {
                continue;
            }
            if have < net_proto::FRAME_HDR {
                let len = u16::from_le_bytes([c.nf[1], c.nf[2]]) as usize;
                if len != 0 {
                    continue;
                }
            }
        }
        let len = c.nf_len as usize;
        c.nf_len = 0;
        let ty = c.nf[0];
        let p: &[u8] = &*(&c.nf[net_proto::FRAME_HDR..len] as *const [u8]);
        net_event(c, sys, ty, p);
        if c.status == ST_FAILED {
            return;
        }
    }
}

unsafe fn net_event(c: &mut Client, sys: &super::SyscallTable, ty: u8, p: &[u8]) {
    match ty {
        net_proto::MSG_CONNECTED if p.len() >= net_proto::CONNECTED_FIXED => {
            let (conn, tag) = net_proto::connected_parts(p);
            if tag != c.tag {
                return;
            }
            if c.connected != 0 {
                net_cmd(c, sys, net_proto::CMD_CLOSE, &conn.to_le_bytes());
                return;
            }
            c.conn = conn;
            c.connected = 1;
            c.status = ST_PRESENTING;
        }
        net_proto::MSG_DATA if p.len() > net_proto::CONN_ID_LEN => {
            if c.connected == 0 || net_proto::conn_id(p) != c.conn {
                return;
            }
            if !absorb(c, &p[net_proto::CONN_ID_LEN..]) {
                fail(c, WHY_PROTOCOL);
                return;
            }
            if c.status == ST_PRESENTING {
                let _ = recv(c);
            }
        }
        net_proto::MSG_CLOSED if p.len() >= net_proto::CONN_ID_LEN => {
            if c.connected != 0 && net_proto::conn_id(p) == c.conn {
                net_cmd(c, sys, net_proto::CMD_CLOSE, &c.conn.to_le_bytes());
                fail(c, WHY_TRANSPORT);
            } else if c.connected == 0 && c.dialed != 0 && c.shared == 0 {
                // A session `tls` ended before its handshake completed —
                // the node refused this client's certificate — is
                // reported by its connection id alone, which the client
                // has not been told. Alone on its transport, the close
                // can only be its own dial's.
                fail(c, WHY_TRANSPORT);
            }
        }
        net_proto::MSG_ERROR if p.len() > net_proto::CONN_ID_LEN => {
            let (conn, errno, tag) = net_proto::error_parts(p);
            if c.connected == 0 && tag == c.tag && errno as i32 == EAGAIN {
                // Another dial over the same transport is in flight: dial
                // again once it has had time to finish.
                c.dialed = 0;
                c.redial = 1;
                return;
            }
            if (c.connected == 0 && tag == c.tag) || (c.connected != 0 && conn == c.conn) {
                fail(c, WHY_TRANSPORT);
            }
        }
        _ => {}
    }
}

// ── A transport shared by several clients ─────────────────────────────────
//
// Clients that dial over one `tls` see one clear side: its events name
// the connection (or, before it exists, the dial's tag) they belong to.
// The owner reads each frame once with a `NetReader` and feeds it to
// every client; each takes what names it and ignores the rest.

/// Mark `c` as fed by its owner rather than reading the transport.
pub fn share_transport(c: &mut Client) {
    c.shared = 1;
}

/// `c` can take the largest fragment a frame may carry.
pub fn has_room(c: &Client) -> bool {
    c.rx_len as usize + net_proto::MAX_DATA_FRAGMENT <= RX_MAX
}

/// Hand `c` one transport event.
pub unsafe fn feed(c: &mut Client, sys: &super::SyscallTable, ty: u8, payload: &[u8]) {
    if c.status != ST_FAILED {
        net_event(c, sys, ty, payload);
    }
}

/// Hand one transport event to every client sharing the transport.
///
/// A session `tls` ended before its handshake completed is reported by
/// its connection id alone, which its client has not yet been told.
/// `tls` makes one outbound connection at a time, so a close naming no
/// client's connection belongs to the one client whose dial is still
/// out, and that client fails as a refused connection.
pub unsafe fn feed_all(clients: &mut [Client], sys: &super::SyscallTable, ty: u8, payload: &[u8]) {
    let mut k = 0;
    while k < clients.len() {
        feed(&mut clients[k], sys, ty, payload);
        k += 1;
    }
    if ty != net_proto::MSG_CLOSED || payload.len() < net_proto::CONN_ID_LEN {
        return;
    }
    let conn = net_proto::conn_id(payload);
    let mut dialing = usize::MAX;
    let mut k = 0;
    while k < clients.len() {
        let c = &clients[k];
        if c.status != ST_FAILED && c.connected != 0 && c.conn == conn {
            return;
        }
        if c.status != ST_FAILED && c.connected == 0 && c.dialed != 0 {
            dialing = k;
        }
        k += 1;
    }
    if dialing != usize::MAX {
        fail(&mut clients[dialing], WHY_TRANSPORT);
    }
}

/// Reassembles the transport's frames for a shared reader.
pub struct NetReader {
    pub len: u32,
    pub buf: [u8; NET_FRAME_MAX],
}

pub enum Frame<'a> {
    /// A whole frame: its type and payload.
    Whole(u8, &'a [u8]),
    /// Nothing whole yet.
    None,
    /// A frame longer than any the transport sends.
    Broken,
}

/// Read toward the next whole frame on `net_in`.
pub unsafe fn read_frame<'a>(
    r: &'a mut NetReader,
    sys: &super::SyscallTable,
    net_in: i32,
) -> Frame<'a> {
    loop {
        let have = r.len as usize;
        let want = if have < net_proto::FRAME_HDR {
            net_proto::FRAME_HDR - have
        } else {
            let len = u16::from_le_bytes([r.buf[1], r.buf[2]]) as usize;
            if net_proto::FRAME_HDR + len > NET_FRAME_MAX {
                r.len = 0;
                return Frame::Broken;
            }
            net_proto::FRAME_HDR + len - have
        };
        if want == 0 {
            r.len = 0;
            let p: &[u8] = &*(&r.buf[net_proto::FRAME_HDR..have] as *const [u8]);
            return Frame::Whole(r.buf[0], p);
        }
        let n = (sys.channel_read)(net_in, r.buf.as_mut_ptr().add(have), want);
        if n <= 0 {
            return Frame::None;
        }
        r.len += n as u32;
    }
}

unsafe fn net_cmd(c: &Client, sys: &super::SyscallTable, ty: u8, payload: &[u8]) -> bool {
    let mut f = [0u8; net_proto::FRAME_HDR + net_proto::CONNECT_TO_MAX];
    let n = net_proto::FRAME_HDR + payload.len();
    if n > f.len() {
        return false;
    }
    f[0] = ty;
    put(&mut f[1..3], &(payload.len() as u16).to_le_bytes());
    put(&mut f[3..n], payload);
    (sys.channel_write)(c.net_out, f.as_ptr(), n) == n as i32
}

/// End the client's session: a link record with an empty frame, or a
/// network close. The gate forgets the session's grants either way.
pub unsafe fn close(c: &mut Client, sys: &super::SyscallTable) {
    match c.transport {
        T_LINK => {
            let rec = c.session.to_le_bytes();
            (sys.channel_write)(c.link_out, rec.as_ptr(), 4);
        }
        _ => {
            if c.connected != 0 {
                net_cmd(c, sys, net_proto::CMD_CLOSE, &c.conn.to_le_bytes());
                c.connected = 0;
            }
        }
    }
    fail(c, WHY_TRANSPORT);
}
