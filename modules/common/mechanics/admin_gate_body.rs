// Step body for the `admin_gate` PIC: the admin plane's front door.
//
// `admin_router` composes the admin wire's operations for one client.
// This module is that client for everybody: it terminates every admin
// session, decides what each one may do, and multiplexes what they may
// do onto the router.
//
// Sessions come two ways:
//
// - Over the network: the clear side of a server-mode `tls` (net_proto
//   on `net_in` / `net_out`), one session per connection. Mutual TLS
//   authenticates the channel: `tls` reports each session's peer on
//   `peer_identity`, named by connection id and generation, and a
//   session whose peer did not bind an identity can present nothing.
// - Over an in-graph link (`link{i}_in` / `link{i}_out`): a module in
//   the same graph — a storage provider, a volume — sends records
//   `[session:u32][frame]`, one per buffer, and gets answers the same
//   way. The wiring is the authentication: a link is a channel inside
//   this graph, so it must never be carried across a network, where the
//   gate could not see who is on the far end. A record with an empty
//   frame ends its session.
//
// On a session the client speaks frames:
//
//   [0xD0 MSG_CAP_PRESENT][len:2][presentation:4][chain]
//   [0xD2 MSG_CAP_WITHDRAW][len:2][presentation:4]
//   an admin request (`loam_admin_wire`, delimited by `request_len`)
//
// and hears `[0xD1 MSG_CAP_ANSWER][len:2][…]` and admin answers. A
// presented chain is verified against the configured mesh roots and the
// trusted clock and recorded against the session (at most
// `MAX_SESSION_GRANTS`); it dies with the session.
//
// Authority (`mesh/capability.rs`): every request names what it touches
// (`loam_admin_wire::request_scope`). A key under a namespace root is
// admitted by a grant whose object is `grant::scope_object` of a
// `/`-terminated prefix of `root/path` — the storage contract's scope
// rule, so a grant minted with `--scope photos/` reaches the same keys
// here as through `storage.object`. The content-addressed body plane is
// granted on `BODY_PLANE_OBJECT`. Reads need `ReadState`, writes and
// leases `SendCommand`, the raw keyed body plane `Admin`; a stream's
// chunks and commit belong to the session that opened it. A lease may
// not reach past the grant that admitted it. Nothing else is admitted:
// a refusal is answered `STATUS_FORBIDDEN` in the op's own ack shape,
// and a byte that names no request closes the session.
//
// A lease or volume request's holder is replaced with one bound to the
// session's identity (`bound_holder`), so no session can name another
// identity's writer.
//
// Requests reach the router under a correlation id the gate assigns;
// the answer is routed back to the session that asked under the id it
// chose, and dropped if that session has gone.
//
// The includer's scope provides `SyscallTable`, `abi`, `admin`
// (loam_admin_wire), `limits`, `Crypto` (the capability verifier's
// SHA-256 and Ed25519) and `sha256` (`sha256(data) -> [u8; 32]`).

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

use super::abi::contracts::mesh::capability as cap;
use super::abi::contracts::net::{net_proto, peer_identity};
use super::abi::contracts::storage::object::grant;
use super::admin as aw;

/// In-graph link port pairs the manifest declares.
pub const LINKS: usize = 4;
pub const NET_SESSIONS: usize = super::limits::ADMIN_SESSIONS;
pub const LINK_SESSIONS: usize = super::limits::ADMIN_LINK_SESSIONS;
/// Requests forwarded and not yet answered: the router's own pending
/// table, so the gate never holds more than the router can.
pub const PENDING: usize = super::limits::ADMIN_PENDING;

/// One request or answer, with the four-byte envelope a link adds.
pub const RECORD_MAX: usize = 4 + aw::REQUEST_MAX;
/// One answer and its envelope.
pub const ANSWER_MAX: usize = 4 + aw::RESPONSE_MAX;
/// The longest capability frame a client may send.
const CAP_FRAME_MAX: usize = cap::FRAME_HDR + cap::PRESENT_MAX;
/// A session's reassembly: a whole request, and the one transport
/// fragment that may arrive behind a partial one. Network bytes are read
/// only while nothing is owed (`read_net`), so a session never holds more.
const RX_MAX: usize = aw::REQUEST_MAX + net_proto::MAX_DATA_FRAGMENT;
/// One net_proto frame from the transport.
const NET_FRAME_MAX: usize =
    net_proto::FRAME_HDR + net_proto::CONN_ID_LEN + net_proto::MAX_DATA_FRAGMENT;
/// Identity bytes kept per session: a key fingerprint, or a link's tag.
const ID_MAX: usize = peer_identity::MAX_FINGERPRINT;
/// Steps between `CMD_BIND` attempts until the transport answers.
const BIND_RETRY_STEPS: u16 = 256;

const KIND_NET: u8 = 1;
const KIND_LINK: u8 = 2;

/// Where a session lives: the network table, or the link table.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Who {
    Net(u16),
    Link(u16),
}

/// What one session may do.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Auth {
    pub grants: cap::SessionGrants,
    /// Streamed writes (`pfid`s) this session opened.
    pub streams: [u64; 4],
    /// The identity lease holders are bound to.
    pub id: [u8; ID_MAX],
    pub id_len: u8,
    /// The channel authenticated a peer, so presentations are verified.
    pub bound: u8,
}

impl Auth {
    const fn new() -> Self {
        Self {
            grants: cap::SessionGrants::new(),
            streams: [0; 4],
            id: [0; ID_MAX],
            id_len: 0,
            bound: 0,
        }
    }

    fn owns(&self, pfid: u8) -> bool {
        self.streams[(pfid / 64) as usize] & (1u64 << (pfid % 64)) != 0
    }

    fn set_stream(&mut self, pfid: u8, owned: bool) {
        let bit = 1u64 << (pfid % 64);
        let word = &mut self.streams[(pfid / 64) as usize];
        if owned {
            *word |= bit;
        } else {
            *word &= !bit;
        }
    }
}

#[repr(C)]
pub struct NetSession {
    pub in_use: u8,
    /// `MSG_ACCEPTED` has arrived; until then the slot only holds an
    /// identity that arrived first.
    pub accepted: u8,
    /// The session must close once its owed answer is out.
    pub closing: u8,
    pub conn: u16,
    pub gen: u16,
    /// Bumped each time the slot is reused, so an answer for a closed
    /// session is never delivered to the next one.
    pub incarnation: u32,
    pub auth: Auth,
    pub rx_len: u32,
    pub rx: [u8; RX_MAX],
}

#[repr(C)]
pub struct LinkSession {
    pub in_use: u8,
    pub link: u8,
    pub session: u32,
    pub incarnation: u32,
    pub auth: Auth,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Pending {
    pub in_use: u8,
    pub kind: u8,
    pub index: u16,
    pub incarnation: u32,
    pub gate_cid: u32,
    pub client_cid: u32,
    pub op: u8,
}

/// The answer owed: where it goes and its bytes.
#[repr(C)]
pub struct Outbox {
    pub kind: u8,
    pub conn: u16,
    pub link: u8,
    pub len: u32,
    pub sent: u32,
    pub buf: [u8; ANSWER_MAX],
}

#[repr(C)]
pub struct ModuleState {
    pub syscalls: *const super::SyscallTable,
    pub net_in: i32,
    pub net_out: i32,
    pub id_in: i32,
    pub router_in: i32,
    pub router_out: i32,
    pub link_in: [i32; LINKS],
    pub link_out: [i32; LINKS],
    pub port: u16,
    pub bound: u8,
    pub bind_wait: u16,
    pub roots: [[u8; cap::KEY_LEN]; cap::MAX_ROOTS],
    pub roots_len: u8,
    /// The body plane's capability object (`BODY_PLANE_DOMAIN`).
    pub body_object: cap::ObjectId,
    pub net: [NetSession; NET_SESSIONS],
    pub links: [LinkSession; LINK_SESSIONS],
    pub pending: [Pending; PENDING],
    pub next_cid: u32,
    pub next_incarnation: u32,
    /// The request owed to the router: one at a time, whole.
    pub req_len: u32,
    pub req: [u8; aw::REQUEST_MAX],
    pub out: Outbox,
    /// One net_proto frame being assembled from `net_in`.
    pub nf_len: u32,
    pub nf: [u8; NET_FRAME_MAX],
    /// One link record being read.
    pub rec: [u8; RECORD_MAX],
    pub ticks: u32,
    pub forwarded: u32,
    pub answered: u32,
    pub refused: u32,
    pub presented: u32,
    pub presentations_refused: u32,
    pub sessions_refused: u32,
    pub dropped_answers: u32,
    pub protocol_errors: u32,
}

/// Construct the gate. Channels it is not wired with are -1: without
/// `net_in`/`net_out` it serves links only, and `port` 0 binds nothing.
#[allow(
    clippy::too_many_arguments,
    reason = "bounded no_std step functions pass explicit scalar params"
)]
pub unsafe fn module_new_impl(
    state_ptr: *mut u8,
    state_size: usize,
    syscalls: *const super::SyscallTable,
    net: (i32, i32, i32),
    router: (i32, i32),
    links_in: &[i32; LINKS],
    links_out: &[i32; LINKS],
    port: u16,
    roots: &[[u8; cap::KEY_LEN]],
) -> i32 {
    if state_ptr.is_null() || syscalls.is_null() {
        return -1;
    }
    if state_size < core::mem::size_of::<ModuleState>() {
        return -2;
    }
    if roots.is_empty() || roots.len() > cap::MAX_ROOTS {
        return -22;
    }
    core::ptr::write_bytes(state_ptr, 0u8, state_size);
    let s = &mut *(state_ptr as *mut ModuleState);
    s.syscalls = syscalls;
    (s.net_in, s.net_out, s.id_in) = net;
    (s.router_out, s.router_in) = router;
    s.link_in = *links_in;
    s.link_out = *links_out;
    s.port = port;
    s.bound = u8::from(port == 0);
    for (i, r) in roots.iter().enumerate() {
        s.roots[i] = *r;
    }
    s.roots_len = roots.len() as u8;
    let h = super::sha256(aw::BODY_PLANE_DOMAIN);
    put(&mut s.body_object, &h[..16]);
    0
}

/// Copy `src` to the front of `dst` by index. Slice copies of a runtime
/// length pull panic paths the PIC link does not carry.
#[allow(
    clippy::manual_memcpy,
    reason = "a slice copy of a runtime length pulls panic paths the PIC link does not carry"
)]
fn put(dst: &mut [u8], src: &[u8]) {
    for i in 0..src.len() {
        dst[i] = src[i];
    }
}

fn sys(s: &ModuleState) -> &super::SyscallTable {
    unsafe { &*s.syscalls }
}

/// The trusted wall clock, or `None` when the platform does not vouch
/// for one.
unsafe fn clock(s: &ModuleState) -> Option<cap::Clock> {
    let mut rec = [0u8; super::abi::kernel_abi::trusted_time::LEN];
    let rc = (sys(s).provider_call)(
        -1,
        super::abi::kernel_abi::timer::TRUSTED_UNIX,
        rec.as_mut_ptr(),
        rec.len(),
    );
    if rc < 0 {
        return None;
    }
    cap::Clock::from_trusted(&rec)
}

pub unsafe fn module_step_impl(state_ptr: *mut u8) -> i32 {
    if state_ptr.is_null() {
        return -1;
    }
    let s = &mut *(state_ptr as *mut ModuleState);
    s.ticks = s.ticks.wrapping_add(1);

    bind_listener(s);
    flush_request(s);
    flush_answer(s);
    read_identities(s);
    read_router(s);
    serve_all(s);
    read_net(s);
    for l in 0..LINKS {
        read_link(s, l);
    }
    flush_request(s);
    flush_answer(s);
    0
}

/// Serve every network session with whole frames waiting, while the
/// router can take a request and nothing is owed to a client.
unsafe fn serve_all(s: &mut ModuleState) {
    for i in 0..NET_SESSIONS {
        if s.req_len != 0 || s.out.len != 0 {
            return;
        }
        if s.net[i].in_use != 0 && s.net[i].accepted != 0 && s.net[i].rx_len != 0 {
            serve_net(s, i);
        }
    }
}

// ── The listener ───────────────────────────────────────────────────────────

unsafe fn net_cmd(s: &ModuleState, ty: u8, payload: &[u8]) -> bool {
    if s.net_out < 0 {
        return false;
    }
    let mut f = [0u8; net_proto::FRAME_HDR + net_proto::CONN_ID_LEN + net_proto::MAX_CMD_DATA];
    let n = net_proto::FRAME_HDR + payload.len();
    if n > f.len() {
        return false;
    }
    f[0] = ty;
    put(&mut f[1..3], &(payload.len() as u16).to_le_bytes());
    put(&mut f[3..n], payload);
    (sys(s).channel_write)(s.net_out, f.as_ptr(), n) == n as i32
}

unsafe fn bind_listener(s: &mut ModuleState) {
    if s.bound != 0 || s.net_out < 0 {
        return;
    }
    if s.bind_wait > 0 {
        s.bind_wait -= 1;
        return;
    }
    if net_cmd(s, net_proto::CMD_BIND, &s.port.to_le_bytes()) {
        s.bind_wait = BIND_RETRY_STEPS;
    }
}

// ── Peer identities ────────────────────────────────────────────────────────

unsafe fn read_identities(s: &mut ModuleState) {
    if s.id_in < 0 {
        return;
    }
    let mut rec = [0u8; peer_identity::MAX_TOTAL];
    for _ in 0..super::limits::OPS_PER_STEP {
        let n = (sys(s).channel_read)(s.id_in, rec.as_mut_ptr(), rec.len());
        if n <= 0 {
            return;
        }
        let Some((t, p)) = peer_identity::frame_parts(&rec[..n as usize]) else {
            s.protocol_errors = s.protocol_errors.wrapping_add(1);
            continue;
        };
        if t != peer_identity::MSG_PEER_IDENTITY || p.len() < peer_identity::PAYLOAD_FIXED {
            continue;
        }
        let conn = peer_identity::conn_id(p);
        let gen = peer_identity::generation(p);
        let i = match net_find(s, conn, gen) {
            Some(i) => i,
            None => match net_alloc(s, conn, gen) {
                Some(i) => i,
                None => continue,
            },
        };
        let a = &mut s.net[i].auth;
        match peer_identity::fingerprint(p) {
            Some(fp) => {
                let k = fp.len().min(ID_MAX);
                put(&mut a.id[..k], &fp[..k]);
                a.id_len = k as u8;
                a.bound = 1;
            }
            None => a.bound = 0,
        }
    }
}

fn net_find(s: &ModuleState, conn: u16, gen: u16) -> Option<usize> {
    (0..NET_SESSIONS)
        .find(|&i| s.net[i].in_use != 0 && s.net[i].conn == conn && s.net[i].gen == gen)
}

fn net_by_conn(s: &ModuleState, conn: u16) -> Option<usize> {
    (0..NET_SESSIONS)
        .find(|&i| s.net[i].in_use != 0 && s.net[i].accepted != 0 && s.net[i].conn == conn)
}

fn net_alloc(s: &mut ModuleState, conn: u16, gen: u16) -> Option<usize> {
    // A slot for an earlier session on this connection id is stale: the
    // transport has moved on to a new generation.
    for i in 0..NET_SESSIONS {
        if s.net[i].in_use != 0 && s.net[i].conn == conn && s.net[i].gen != gen {
            s.net[i].in_use = 0;
            s.net[i].auth = Auth::new();
            s.net[i].rx_len = 0;
        }
    }
    let i = (0..NET_SESSIONS).find(|&i| s.net[i].in_use == 0)?;
    s.next_incarnation = s.next_incarnation.wrapping_add(1);
    let n = &mut s.net[i];
    n.in_use = 1;
    n.accepted = 0;
    n.closing = 0;
    n.conn = conn;
    n.gen = gen;
    n.incarnation = s.next_incarnation;
    n.auth = Auth::new();
    n.rx_len = 0;
    Some(i)
}

// ── The network side ───────────────────────────────────────────────────────

/// Read net_proto frames from the transport, one whole frame at a time.
unsafe fn read_net(s: &mut ModuleState) {
    if s.net_in < 0 {
        return;
    }
    for _ in 0..super::limits::OPS_PER_STEP * 4 {
        // While a request waits on the router or an answer on its
        // client, a session's bytes cannot be served, and reading more
        // would pile them up behind it. The transport holds them.
        if s.req_len != 0 || s.out.len != 0 {
            return;
        }
        let have = s.nf_len as usize;
        let want = if have < net_proto::FRAME_HDR {
            net_proto::FRAME_HDR - have
        } else {
            let len = u16::from_le_bytes([s.nf[1], s.nf[2]]) as usize;
            if net_proto::FRAME_HDR + len > NET_FRAME_MAX {
                // Not a frame any transport sends: the stream is lost.
                s.protocol_errors = s.protocol_errors.wrapping_add(1);
                s.net_in = -1;
                return;
            }
            net_proto::FRAME_HDR + len - have
        };
        if want > 0 {
            let n = (sys(s).channel_read)(s.net_in, s.nf.as_mut_ptr().add(have), want);
            if n <= 0 {
                return;
            }
            s.nf_len += n as u32;
            if (n as usize) < want {
                continue;
            }
            if have < net_proto::FRAME_HDR && s.nf_len as usize == net_proto::FRAME_HDR {
                // The header is in; read the payload next pass.
                let len = u16::from_le_bytes([s.nf[1], s.nf[2]]) as usize;
                if len != 0 {
                    continue;
                }
            }
        }
        let len = s.nf_len as usize;
        s.nf_len = 0;
        let ty = s.nf[0];
        let payload: &[u8] = &*(&s.nf[net_proto::FRAME_HDR..len] as *const [u8]);
        net_event(s, ty, payload);
    }
}

unsafe fn net_event(s: &mut ModuleState, ty: u8, p: &[u8]) {
    match ty {
        net_proto::MSG_BOUND => s.bound = 1,
        net_proto::MSG_ACCEPTED => {
            if p.len() < net_proto::ACCEPTED_FIXED {
                return;
            }
            let (conn, local_port) = net_proto::accepted_parts(p);
            if local_port != s.port {
                return;
            }
            let gen = net_proto::session_generation(p, net_proto::ACCEPTED_FIXED);
            let i = match net_find(s, conn, gen) {
                Some(i) => Some(i),
                None => net_alloc(s, conn, gen),
            };
            match i {
                Some(i) => s.net[i].accepted = 1,
                None => {
                    s.sessions_refused = s.sessions_refused.wrapping_add(1);
                    net_cmd(s, net_proto::CMD_CLOSE, &conn.to_le_bytes());
                }
            }
        }
        net_proto::MSG_DATA => {
            if p.len() < net_proto::CONN_ID_LEN {
                return;
            }
            let conn = net_proto::conn_id(p);
            let Some(i) = net_by_conn(s, conn) else {
                return;
            };
            let data = &p[net_proto::CONN_ID_LEN..];
            let n = &mut s.net[i];
            let at = n.rx_len as usize;
            if n.closing != 0 {
                return;
            }
            if at + data.len() > RX_MAX {
                // More than one whole request has arrived unframed:
                // nothing after it can be trusted to line up.
                close_net(s, i);
                return;
            }
            put(&mut n.rx[at..at + data.len()], data);
            n.rx_len += data.len() as u32;
            serve_net(s, i);
        }
        net_proto::MSG_CLOSED => {
            if p.len() < net_proto::CONN_ID_LEN {
                return;
            }
            let conn = net_proto::conn_id(p);
            if let Some(i) = net_by_conn(s, conn) {
                end_net(s, i);
            }
            net_cmd(s, net_proto::CMD_CLOSE, &conn.to_le_bytes());
        }
        _ => {}
    }
}

/// Forget a network session: its grants die and late answers drop.
unsafe fn end_net(s: &mut ModuleState, i: usize) {
    s.net[i].in_use = 0;
    s.net[i].auth = Auth::new();
    s.net[i].rx_len = 0;
}

unsafe fn close_net(s: &mut ModuleState, i: usize) {
    let conn = s.net[i].conn;
    end_net(s, i);
    net_cmd(s, net_proto::CMD_CLOSE, &conn.to_le_bytes());
}

/// Serve the whole frames at the front of a network session's bytes.
unsafe fn serve_net(s: &mut ModuleState, i: usize) {
    loop {
        if s.net[i].in_use == 0 || s.req_len != 0 || s.out.len != 0 {
            return;
        }
        let have = s.net[i].rx_len as usize;
        if have == 0 {
            return;
        }
        let head = s.net[i].rx[0];
        let len = if is_cap_frame(head) {
            if have < cap::FRAME_HDR {
                return;
            }
            let l = cap::FRAME_HDR + u16::from_le_bytes([s.net[i].rx[1], s.net[i].rx[2]]) as usize;
            if l > CAP_FRAME_MAX {
                close_net(s, i);
                return;
            }
            l
        } else {
            match aw::request_len(&s.net[i].rx[..have]) {
                Ok(l) if l > RX_MAX => {
                    close_net(s, i);
                    return;
                }
                Ok(l) => l,
                Err(aw::WireError::Truncated) => return,
                Err(_) => {
                    // A byte that names no request: nothing after it
                    // can be framed.
                    close_net(s, i);
                    return;
                }
            }
        };
        if have < len {
            return;
        }
        let frame: &mut [u8] = &mut *(&mut s.net[i].rx[..len] as *mut [u8]);
        let keep = handle_frame(s, Who::Net(i as u16), frame);
        if s.net[i].in_use == 0 {
            return;
        }
        let n = &mut s.net[i];
        for k in len..have {
            n.rx[k - len] = n.rx[k];
        }
        n.rx_len = (have - len) as u32;
        if !keep {
            close_net(s, i);
            return;
        }
    }
}

fn is_cap_frame(b: u8) -> bool {
    b == cap::MSG_CAP_PRESENT || b == cap::MSG_CAP_WITHDRAW
}

// ── The links ──────────────────────────────────────────────────────────────

unsafe fn read_link(s: &mut ModuleState, l: usize) {
    let chan = s.link_in[l];
    if chan < 0 {
        return;
    }
    for _ in 0..super::limits::OPS_PER_STEP {
        if s.req_len != 0 || s.out.len != 0 {
            return;
        }
        let n = (sys(s).channel_read)(chan, s.rec.as_mut_ptr(), RECORD_MAX);
        if n <= 0 {
            return;
        }
        let n = n as usize;
        if n < 4 {
            s.protocol_errors = s.protocol_errors.wrapping_add(1);
            continue;
        }
        let session = u32::from_le_bytes([s.rec[0], s.rec[1], s.rec[2], s.rec[3]]);
        let found = (0..LINK_SESSIONS).find(|&j| {
            s.links[j].in_use != 0 && s.links[j].link == l as u8 && s.links[j].session == session
        });
        if n == 4 {
            // An empty frame ends the session.
            if let Some(j) = found {
                s.links[j].in_use = 0;
                s.links[j].auth = Auth::new();
            }
            continue;
        }
        let j = match found {
            Some(j) => j,
            None => match link_alloc(s, l, session) {
                Some(j) => j,
                None => {
                    s.sessions_refused = s.sessions_refused.wrapping_add(1);
                    let frame: &mut [u8] = &mut *(&mut s.rec[4..n] as *mut [u8]);
                    refuse_unsessioned(s, l, session, frame);
                    continue;
                }
            },
        };
        let frame: &mut [u8] = &mut *(&mut s.rec[4..n] as *mut [u8]);
        let whole = if is_cap_frame(frame[0]) {
            frame.len() >= cap::FRAME_HDR
                && cap::FRAME_HDR + u16::from_le_bytes([frame[1], frame[2]]) as usize == frame.len()
        } else {
            aw::request_len(frame) == Ok(frame.len())
        };
        if !whole || !handle_frame(s, Who::Link(j as u16), frame) {
            // A record that is not exactly one frame: the session is
            // over, as a network one would be closed.
            s.protocol_errors = s.protocol_errors.wrapping_add(1);
            s.links[j].in_use = 0;
            s.links[j].auth = Auth::new();
        }
    }
}

fn link_alloc(s: &mut ModuleState, l: usize, session: u32) -> Option<usize> {
    let j = (0..LINK_SESSIONS).find(|&j| s.links[j].in_use == 0)?;
    s.next_incarnation = s.next_incarnation.wrapping_add(1);
    let e = &mut s.links[j];
    e.in_use = 1;
    e.link = l as u8;
    e.session = session;
    e.incarnation = s.next_incarnation;
    e.auth = Auth::new();
    // The wiring authenticated it; its identity is the link it is on.
    e.auth.bound = 1;
    put(&mut e.auth.id[..4], b"link");
    e.auth.id[4] = l as u8;
    e.auth.id_len = 5;
    Some(j)
}

/// A link session the table cannot hold: answer its request refused
/// busy so the client backs off, or its presentation full.
unsafe fn refuse_unsessioned(s: &mut ModuleState, l: usize, session: u32, frame: &mut [u8]) {
    s.out.kind = KIND_LINK;
    s.out.link = l as u8;
    put(&mut s.out.buf[..4], &session.to_le_bytes());
    let n = if frame.first() == Some(&cap::MSG_CAP_PRESENT) && frame.len() >= cap::FRAME_HDR + 4 {
        let p = u32::from_le_bytes([frame[3], frame[4], frame[5], frame[6]]);
        cap_answer(
            &mut s.out.buf[4..],
            &cap::encode_answer_refused(p, cap::status::GRANTS_FULL, 0),
        )
    } else if frame.first() == Some(&cap::MSG_CAP_WITHDRAW) {
        return;
    } else {
        aw::refusal(frame, aw::STATUS_BUSY, &mut s.out.buf[4..])
    };
    if n == 0 {
        return;
    }
    s.out.len = (4 + n) as u32;
    s.out.sent = 0;
}

// ── Frames ────────────────────────────────────────────────────────────────

fn auth_of(s: &mut ModuleState, who: Who) -> &mut Auth {
    match who {
        Who::Net(i) => &mut s.net[i as usize].auth,
        Who::Link(j) => &mut s.links[j as usize].auth,
    }
}

/// Handle one whole frame. False when the session must end.
unsafe fn handle_frame(s: &mut ModuleState, who: Who, frame: &mut [u8]) -> bool {
    match frame[0] {
        cap::MSG_CAP_PRESENT => present(s, who, &frame[cap::FRAME_HDR..]),
        cap::MSG_CAP_WITHDRAW => {
            let p = &frame[cap::FRAME_HDR..];
            if p.len() != 4 {
                return false;
            }
            auth_of(s, who)
                .grants
                .withdraw(u32::from_le_bytes([p[0], p[1], p[2], p[3]]));
            true
        }
        _ => request(s, who, frame),
    }
}

/// `MSG_CAP_PRESENT`: verify the chain and record the grant.
unsafe fn present(s: &mut ModuleState, who: Who, p: &[u8]) -> bool {
    if p.len() < 4 {
        return false;
    }
    let presentation = u32::from_le_bytes([p[0], p[1], p[2], p[3]]);
    let chain = &p[4..];
    let answer: ([u8; cap::ANSWER_GRANTED], usize) = if auth_of(s, who).bound == 0 {
        refused(presentation, cap::status::UNAUTHENTICATED, 0)
    } else {
        let roots = &s.roots[..s.roots_len as usize];
        match cap::verify(&super::Crypto, chain, roots, clock(s), None) {
            Ok(g) => {
                if auth_of(s, who).grants.insert(presentation, g) {
                    s.presented = s.presented.wrapping_add(1);
                    (
                        cap::encode_answer_granted(presentation, &g),
                        cap::ANSWER_GRANTED,
                    )
                } else {
                    refused(presentation, cap::status::GRANTS_FULL, 0)
                }
            }
            Err(r) => {
                s.presentations_refused = s.presentations_refused.wrapping_add(1);
                refused(presentation, cap::status::REFUSED, r as u8)
            }
        }
    };
    stage_answer_frame(s, who, &answer.0[..answer.1]);
    true
}

fn refused(presentation: u32, status: u8, refusal: u8) -> ([u8; cap::ANSWER_GRANTED], usize) {
    let mut b = [0u8; cap::ANSWER_GRANTED];
    put(
        &mut b[..cap::ANSWER_FIXED],
        &cap::encode_answer_refused(presentation, status, refusal),
    );
    (b, cap::ANSWER_FIXED)
}

/// Frame a `MSG_CAP_ANSWER` payload into `out`; its length.
fn cap_answer(out: &mut [u8], payload: &[u8]) -> usize {
    let n = cap::FRAME_HDR + payload.len();
    if out.len() < n {
        return 0;
    }
    out[0] = cap::MSG_CAP_ANSWER;
    put(&mut out[1..3], &(payload.len() as u16).to_le_bytes());
    put(&mut out[3..n], payload);
    n
}

/// Stage a capability answer for `who`.
unsafe fn stage_answer_frame(s: &mut ModuleState, who: Who, payload: &[u8]) {
    let at = stage_dest(s, who);
    let n = cap_answer(&mut s.out.buf[at..], payload);
    s.out.len = (at + n) as u32;
    s.out.sent = 0;
}

/// Point the outbox at `who`; the offset its frame starts at.
fn stage_dest(s: &mut ModuleState, who: Who) -> usize {
    match who {
        Who::Net(i) => {
            s.out.kind = KIND_NET;
            s.out.conn = s.net[i as usize].conn;
            0
        }
        Who::Link(j) => {
            let e = &s.links[j as usize];
            s.out.kind = KIND_LINK;
            s.out.link = e.link;
            let session = e.session;
            put(&mut s.out.buf[..4], &session.to_le_bytes());
            4
        }
    }
}

/// Answer request `frame` refused with `status`, to `who`.
unsafe fn refuse(s: &mut ModuleState, who: Who, frame: &[u8], status: u8) {
    s.refused = s.refused.wrapping_add(1);
    let at = stage_dest(s, who);
    let n = aw::refusal(frame, status, &mut s.out.buf[at..]);
    s.out.len = (at + n) as u32;
    s.out.sent = 0;
}

/// An admin request: authorise it, bind its holder, forward it.
unsafe fn request(s: &mut ModuleState, who: Who, frame: &mut [u8]) -> bool {
    let Some((scope, need)) = aw::request_scope(frame) else {
        // Not a well-formed request: nothing after it can be trusted.
        return false;
    };
    let admitted = match scope {
        aw::Scope::Stream(pfid) => auth_of(s, who).owns(pfid).then_some(None),
        aw::Scope::Bodies => {
            let object = s.body_object;
            authorise_object(s, who, object, need).map(Some)
        }
        aw::Scope::Key { root, path } => authorise_key(s, who, root, path, need).map(Some),
    };
    let Some(grant) = admitted else {
        refuse(s, who, frame, aw::STATUS_FORBIDDEN);
        return true;
    };
    if frame[0] == aw::OP_LEASE {
        // A lease may not outlive the authority it was taken under.
        let Ok(l) = aw::decode_admin_lease(frame) else {
            return false;
        };
        let Some(g) = grant else {
            return false;
        };
        let Some(c) = clock(s) else {
            refuse(s, who, frame, aw::STATUS_FORBIDDEN);
            return true;
        };
        let ends = c.now + c.uncertainty + (l.ttl_ms as u64).div_ceil(1000);
        if ends > g.not_after as u64 {
            refuse(s, who, frame, aw::STATUS_FORBIDDEN);
            return true;
        }
    }
    if let aw::Scope::Stream(pfid) = scope {
        if frame[0] == aw::OP_PUT_FILE_COMMIT {
            auth_of(s, who).set_stream(pfid, false);
        }
    }
    let (id, id_len) = {
        let a = auth_of(s, who);
        (a.id, a.id_len as usize)
    };
    if let Some(holder) = aw::request_holder_mut(frame) {
        *holder = bound_holder(&id[..id_len], holder);
    }
    forward(s, who, frame);
    true
}

/// The permission bits an operation's class needs.
fn permission(need: aw::Need) -> u16 {
    match need {
        aw::Need::Read => cap::perm::READ_STATE,
        aw::Need::Write => cap::perm::SEND_COMMAND,
        aw::Need::Admin => cap::perm::ADMIN,
    }
}

unsafe fn authorise_object(
    s: &mut ModuleState,
    who: Who,
    object: cap::ObjectId,
    need: aw::Need,
) -> Option<cap::Grant> {
    let c = clock(s);
    auth_of(s, who)
        .grants
        .authorise(
            cap::Demand {
                object_id: object,
                permissions: permission(need),
            },
            c,
        )
        .ok()
}

/// Admit a key by any `/`-terminated prefix of `root/path` a held grant
/// names, shallowest first, up to `ADMIN_SCOPE_DEPTH` separators.
unsafe fn authorise_key(
    s: &mut ModuleState,
    who: Who,
    root: &[u8],
    path: &[u8],
    need: aw::Need,
) -> Option<cap::Grant> {
    let mut key = [0u8; grant::SCOPE_MAX + 1];
    let total = root.len() + 1 + path.len();
    // A key's scope is bounded as a storage key is; a longer key's
    // prefixes past the bound are not scopes any grant can name.
    let len = total.min(key.len());
    let rl = root.len().min(len);
    put(&mut key[..rl], &root[..rl]);
    if rl < len {
        key[rl] = b'/';
        let pl = len - rl - 1;
        put(&mut key[rl + 1..len], &path[..pl]);
    }
    let mut slash = false;
    for &b in root {
        slash |= b == b'/';
    }
    if root.is_empty() || slash {
        // A root holding a separator would make two keys one scope.
        return None;
    }
    let c = clock(s);
    let mut depth = 0usize;
    for end in 0..len {
        if key[end] != b'/' {
            continue;
        }
        depth += 1;
        if depth > super::limits::ADMIN_SCOPE_DEPTH {
            break;
        }
        let Some(object) = grant::scope_object(&super::Crypto, &key[..end + 1]) else {
            continue;
        };
        let d = cap::Demand {
            object_id: object,
            permissions: permission(need),
        };
        if let Ok(g) = auth_of(s, who).grants.authorise(d, c) {
            return Some(g);
        }
    }
    None
}

/// The holder the store records for `id` writing as `chosen`: keyed by
/// the session's identity, so none can produce another's, and by the
/// caller's choice, so one identity can run writers that exclude each
/// other. A client never needs the result; it names its writer with
/// `chosen` on every request and gets the same holder each time.
pub fn bound_holder(id: &[u8], chosen: &[u8; aw::LEASE_HOLDER_LEN]) -> [u8; aw::LEASE_HOLDER_LEN] {
    const DOMAIN: &[u8] = b"loam-lease-holder\0";
    let mut buf = [0u8; DOMAIN.len() + 2 + ID_MAX + aw::LEASE_HOLDER_LEN];
    let mut at = 0;
    put(&mut buf[..DOMAIN.len()], DOMAIN);
    at += DOMAIN.len();
    put(&mut buf[at..at + 2], &(id.len() as u16).to_le_bytes());
    at += 2;
    put(&mut buf[at..at + id.len()], id);
    at += id.len();
    put(&mut buf[at..at + aw::LEASE_HOLDER_LEN], chosen);
    at += aw::LEASE_HOLDER_LEN;
    let d = super::sha256(&buf[..at]);
    let mut out = [0u8; aw::LEASE_HOLDER_LEN];
    put(&mut out, &d[..aw::LEASE_HOLDER_LEN]);
    out
}

// ── To and from the router ─────────────────────────────────────────────────

/// Forward an admitted request under a gate correlation id.
unsafe fn forward(s: &mut ModuleState, who: Who, frame: &mut [u8]) {
    let Some(k) = (0..PENDING).find(|&k| s.pending[k].in_use == 0) else {
        refuse(s, who, frame, aw::STATUS_BUSY);
        return;
    };
    let mut cid = s.next_cid.wrapping_add(1);
    loop {
        let mut taken = cid == 0;
        for k in 0..PENDING {
            taken |= s.pending[k].in_use != 0 && s.pending[k].gate_cid == cid;
        }
        if !taken {
            break;
        }
        cid = cid.wrapping_add(1);
    }
    s.next_cid = cid;
    let client_cid = u32::from_le_bytes([frame[1], frame[2], frame[3], frame[4]]);
    let (kind, index, incarnation) = match who {
        Who::Net(i) => (KIND_NET, i, s.net[i as usize].incarnation),
        Who::Link(j) => (KIND_LINK, j, s.links[j as usize].incarnation),
    };
    s.pending[k] = Pending {
        in_use: 1,
        kind,
        index,
        incarnation,
        gate_cid: cid,
        client_cid,
        op: frame[0],
    };
    put(&mut frame[1..5], &cid.to_le_bytes());
    put(&mut s.req[..frame.len()], frame);
    s.req_len = frame.len() as u32;
    s.forwarded = s.forwarded.wrapping_add(1);
    flush_request(s);
}

/// Offer the request owed to the router. True once nothing is owed.
unsafe fn flush_request(s: &mut ModuleState) -> bool {
    if s.req_len == 0 {
        return true;
    }
    let n = s.req_len as usize;
    let rc = (sys(s).channel_write)(s.router_out, s.req.as_ptr(), n);
    if rc == n as i32 {
        s.req_len = 0;
        return true;
    }
    false
}

/// Take router answers while nothing is owed to a client.
unsafe fn read_router(s: &mut ModuleState) {
    if s.router_in < 0 {
        return;
    }
    for _ in 0..super::limits::OPS_PER_STEP {
        if s.out.len != 0 {
            return;
        }
        let n = (sys(s).channel_read)(s.router_in, s.out.buf.as_mut_ptr().add(4), aw::RESPONSE_MAX);
        if n <= 0 {
            return;
        }
        let n = n as usize;
        if n < 5 {
            s.protocol_errors = s.protocol_errors.wrapping_add(1);
            continue;
        }
        let gate_cid = u32::from_le_bytes([s.out.buf[5], s.out.buf[6], s.out.buf[7], s.out.buf[8]]);
        let Some(k) =
            (0..PENDING).find(|&k| s.pending[k].in_use != 0 && s.pending[k].gate_cid == gate_cid)
        else {
            s.dropped_answers = s.dropped_answers.wrapping_add(1);
            continue;
        };
        let p = s.pending[k];
        s.pending[k].in_use = 0;
        put(&mut s.out.buf[5..9], &p.client_cid.to_le_bytes());
        let ans = &s.out.buf[4..4 + n];
        if p.op == aw::OP_PUT_FILE_OPEN {
            if let Ok((_, aw::STATUS_OK, pfid)) = aw::decode_put_file_open_ack(ans) {
                if let Some(a) = live_auth(s, &p) {
                    a.set_stream(pfid, true);
                }
            }
        }
        match p.kind {
            KIND_NET if net_live(s, &p) => {
                let i = p.index as usize;
                s.out.kind = KIND_NET;
                s.out.conn = s.net[i].conn;
                for k in 0..n {
                    s.out.buf[k] = s.out.buf[4 + k];
                }
                s.out.len = n as u32;
            }
            KIND_LINK if link_live(s, &p) => {
                let e = &s.links[p.index as usize];
                s.out.kind = KIND_LINK;
                s.out.link = e.link;
                let session = e.session;
                put(&mut s.out.buf[..4], &session.to_le_bytes());
                s.out.len = (4 + n) as u32;
            }
            _ => {
                // The session that asked has gone: the answer has
                // nobody to go to.
                s.dropped_answers = s.dropped_answers.wrapping_add(1);
                continue;
            }
        }
        s.out.sent = 0;
        s.answered = s.answered.wrapping_add(1);
        flush_answer(s);
    }
}

fn net_live(s: &ModuleState, p: &Pending) -> bool {
    let n = &s.net[p.index as usize];
    n.in_use != 0 && n.incarnation == p.incarnation
}

fn link_live(s: &ModuleState, p: &Pending) -> bool {
    let e = &s.links[p.index as usize];
    e.in_use != 0 && e.incarnation == p.incarnation
}

fn live_auth<'a>(s: &'a mut ModuleState, p: &Pending) -> Option<&'a mut Auth> {
    match p.kind {
        KIND_NET if net_live(s, p) => Some(&mut s.net[p.index as usize].auth),
        KIND_LINK if link_live(s, p) => Some(&mut s.links[p.index as usize].auth),
        _ => None,
    }
}

/// Offer the owed answer. True once nothing is owed.
unsafe fn flush_answer(s: &mut ModuleState) -> bool {
    if s.out.len == 0 {
        return true;
    }
    match s.out.kind {
        KIND_NET => {
            while s.out.sent < s.out.len {
                let at = s.out.sent as usize;
                let take = (s.out.len as usize - at).min(net_proto::MAX_CMD_DATA);
                let mut f =
                    [0u8; net_proto::FRAME_HDR + net_proto::CONN_ID_LEN + net_proto::MAX_CMD_DATA];
                let plen = net_proto::CONN_ID_LEN + take;
                f[0] = net_proto::CMD_SEND;
                put(&mut f[1..3], &(plen as u16).to_le_bytes());
                put(&mut f[3..5], &s.out.conn.to_le_bytes());
                put(&mut f[5..5 + take], &s.out.buf[at..at + take]);
                let n = net_proto::FRAME_HDR + plen;
                if (sys(s).channel_write)(s.net_out, f.as_ptr(), n) != n as i32 {
                    return false;
                }
                s.out.sent += take as u32;
            }
        }
        _ => {
            let chan = s.link_out[s.out.link as usize];
            let n = s.out.len as usize;
            if chan >= 0 && (sys(s).channel_write)(chan, s.out.buf.as_ptr(), n) != n as i32 {
                return false;
            }
        }
    }
    s.out.len = 0;
    s.out.sent = 0;
    true
}
