// Step body for the `loam_cli` applet: the operator's command surface,
// `fluxor exec loam -- <command> …`.
//
// The applet is a client of a node's admin plane like any other: it
// dials the node's `admin_gate` through a client-mode `tls` (mutual TLS
// authenticates it), presents the capability chains in the file it is
// given, and works under the grants they earn. `export` holds a second
// session, to a second node, over the same `tls`.
//
// Every command runs the admin wire the node's own modules run
// (`loam_admin_wire`, `loam_volume_map_wire`, `loam_manifest_wire`), one
// request at a time: a command is a resumable sequence of requests, each
// sent when the last is answered. Files are read and written through the
// `fs` contract, a block at a time, so a command's memory does not grow
// with the data it moves.
//
//   lookup  <root> <path>                       the binding at a path
//   ls      <root> [prefix]                     the bindings under a prefix
//   put     <root> <path> <file> [--if-absent | --if <object-id>] [--type <t>]
//   get     <root> <path> <file>                bytes, verified against their digest
//   rm      <root> <path> [--if <object-id>]
//   volume create <root> <path> <size> <extent-size>
//   volume delete <root> <path>
//   volume read   <root> <path> <offset> <length> <file>
//   snapshot create  <src-root> <snap-root> <manifest-file>
//   snapshot restore <manifest-file> <dst-root>
//   snapshot delete  <snap-root>
//   export <manifest-file> <dst-root> --to <host:port> --to-capability <file>
//
// Options before the command: `--admin <host:port>` (default
// `localhost:7443`) and `--capability <file>` (required).
//
// A snapshot binds every content-addressed entry of a root under another,
// at revision 1, as what it was — a volume through a fenced commit of the
// root it had — so it shares their bodies and pins them against the
// orphan sweep by the ordinary means. Its manifest describes it for
// restore and export. An export moves every body the destination lacks —
// a volume's pages and extents included — before it binds anything, so an
// interrupted export leaves unreferenced bodies, never dangling names.
//
// The includer's scope provides `SyscallTable`, `abi`, `admin`
// (loam_admin_wire), `admin_client`, `body_wire`, `limits`, `map_wire`,
// `manifest`, `Sha256` and `sha256`.

#![allow(
    dead_code,
    reason = "shared #[path]-included body; each includer drives a subset"
)]

use super::admin as aw;
use super::admin_client as ac;
use super::manifest as mw;
use super::map_wire as mp;

const MAX_BODY: usize = super::body_wire::MAX_BODY;
pub const ARGV_MAX: usize = 8192;
const MAX_ARGS: usize = 24;
/// Steps to wait for the argv record before answering with help.
const ARGV_WAIT: u32 = 2000;
/// stdout held before it is written. A command's output past
/// `OUT_FLUSH` goes out in whole lines before the command produces more,
/// and nothing a command adds at once — a listing page at most — is
/// larger than the difference, so nothing is ever clipped.
pub const OUT_MAX: usize = 65536;
const OUT_FLUSH: usize = 32768;
const _: () = assert!(OUT_MAX - OUT_FLUSH > aw::RESPONSE_MAX / 2);
const PATH_MAX: usize = 1024;
const KIND_VOLUME: u8 = 3;
const LEASE_TTL_MS: u32 = 30_000;
/// How long a volume commit waits out a flush the orphan sweep holds open.
const BEGIN_PATIENCE_MS: u64 = 10_000;
const BEGIN_RETRY_MS: u64 = 200;
const DEFAULT_ADMIN: &[u8] = b"localhost:7443";
/// The tags this applet's two dials carry on the shared `tls`.
const TAG_A: u8 = 1;
const TAG_B: u8 = 2;

pub const STEP_DONE: i32 = 1;

// fs
const FS_OPEN: u32 = 0x0900;
const FS_READ: u32 = 0x0901;
const FS_SEEK: u32 = 0x0902;
const FS_CLOSE: u32 = 0x0903;
const FS_FSYNC: u32 = 0x0905;
const FS_WRITE: u32 = 0x0906;
const FS_OPEN_CREATE: u32 = 0x0909;
const FS_UNLINK: u32 = 0x090A;
const TIMER_MILLIS: u32 = 0x0602;
const RANDOM: u32 = 0x0C3C;

/// How the applet reaches the admin plane.
#[derive(Clone, Copy)]
pub enum Transport {
    /// net_proto to a client-mode `tls` clear side.
    Net { net_in: i32, net_out: i32 },
    /// In-graph links to `admin_gate`s: one `(in, out)` pair per session,
    /// the destination's second.
    Link { links: [(i32, i32); 2] },
}

const C_NONE: u8 = 0;
const C_HELP: u8 = 1;
const C_LOOKUP: u8 = 2;
const C_LS: u8 = 3;
const C_PUT: u8 = 4;
const C_GET: u8 = 5;
const C_RM: u8 = 6;
const C_VCREATE: u8 = 7;
const C_VDELETE: u8 = 8;
const C_VREAD: u8 = 9;
const C_SCREATE: u8 = 10;
const C_SRESTORE: u8 = 11;
const C_SDELETE: u8 = 12;
const C_EXPORT: u8 = 13;

/// The volume-bind sub-flow's stages: lease, begin, (store the root),
/// commit, release.
const VB_IDLE: u8 = 0;
const VB_LEASE: u8 = 1;
const VB_BEGIN: u8 = 2;
const VB_PUT: u8 = 3;
const VB_COMMIT: u8 = 4;
const VB_RELEASE: u8 = 5;
const VB_DELETE: u8 = 6;

#[repr(C)]
pub struct ModuleState {
    pub syscalls: *const super::SyscallTable,
    pub args_chan: i32,
    pub out_chan: i32,
    pub exit_chan: i32,
    pub transport: Transport,
    pub waited: u32,
    pub started: u8,
    pub done: u8,
    pub exit_code: i32,
    pub exit_sent: u8,
    pub now_ms: u64,
    // argv
    pub argv: [u8; ARGV_MAX],
    pub argv_len: u32,
    pub args: [(u16, u16); MAX_ARGS],
    pub argc: u8,
    /// The command's own arguments start here, after the options.
    pub cmd_at: u8,
    pub admin_at: i8,
    pub cap_at: i8,
    pub to_at: i8,
    pub to_cap_at: i8,
    pub if_at: i8,
    pub type_at: i8,
    pub if_absent: u8,
    // sessions
    pub clients: [ac::Client; 2],
    pub nclients: u8,
    pub reader: ac::NetReader,
    pub cap_scratch: [u8; ac::CAP_FILE_MAX],
    // the command
    pub cmd: u8,
    pub st: u8,
    /// The session an answer is awaited on, +1; 0 when none is.
    pub waiting: u8,
    pub resume_at: u64,
    pub cid: u32,
    pub req: [u8; aw::REQUEST_MAX],
    pub ans: [u8; aw::RESPONSE_MAX],
    pub ans_len: u32,
    pub out: [u8; OUT_MAX],
    pub out_len: u32,
    /// Output that did not fit: the run fails rather than print less.
    pub out_over: u8,
    pub pfid: u8,
    // files
    pub fd: i32,
    pub fd2: i32,
    pub size: u64,
    pub off: u64,
    pub hash: super::Sha256,
    pub digest: [u8; 32],
    pub buf: [u8; MAX_BODY],
    // a listing page held while its entries are worked through
    pub list: [u8; aw::RESPONSE_MAX],
    pub list_len: u32,
    pub list_at: u32,
    pub list_more: u8,
    pub after: [u8; PATH_MAX],
    pub after_len: u16,
    // the entry in hand
    pub key: [u8; PATH_MAX],
    pub key_len: u16,
    pub kind: u8,
    pub revision: u64,
    pub entry_digest: [u8; 32],
    /// What the entry's binding records besides its target.
    pub entry_size: u64,
    pub ctype: [u8; 128],
    pub ctype_len: u8,
    // the volume-bind sub-flow
    pub vb: u8,
    pub vb_client: u8,
    pub vb_root: [u8; 64],
    pub vb_root_len: u8,
    pub vb_put_page: u8,
    pub vb_delete: u8,
    pub vb_expected: u64,
    pub vb_status: u8,
    pub vb_revision: u64,
    pub holder: [u8; aw::LEASE_HOLDER_LEN],
    pub fence: u64,
    pub begin_since: u64,
    // map pages
    pub page: [u8; mp::MAX_PAGE_LEN],
    pub page_len: u32,
    pub leaf: [u8; mp::MAX_PAGE_LEN],
    pub leaf_len: u32,
    pub leaf_child: u64,
    pub child_i: u32,
    pub leaf_i: u32,
    // a manifest read a record at a time
    pub mf: [u8; mw::HEADER_MAX + mw::RECORD_MAX],
    pub mf_len: u32,
    pub mf_eof: u8,
    pub mf_count: u32,
    pub mf_seen: u32,
    pub mf_pass: u8,
    pub count: u64,
    pub sent: u64,
    // a body moved during export
    pub mv: u8,
    pub mv_digest: [u8; 32],
    /// The body is a file entry larger than one answer: it moves as a
    /// streamed file, read by range and written by chunks.
    pub mv_large: u8,
    /// The root the manifest's entries are bound under at the source.
    pub mf_root: [u8; super::limits::MAX_ROOT],
    pub mf_root_len: u8,
}

unsafe fn sys(s: &ModuleState) -> &super::SyscallTable {
    &*s.syscalls
}

fn put(dst: &mut [u8], src: &[u8]) {
    let mut i = 0;
    while i < src.len() && i < dst.len() {
        dst[i] = src[i];
        i += 1;
    }
}

fn eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && {
        let mut i = 0;
        while i < a.len() && a[i] == b[i] {
            i += 1;
        }
        i == a.len()
    }
}

// ── Construction ───────────────────────────────────────────────────────────

/// # Safety
/// `state_ptr` is this module's state of `state_size` bytes; `syscalls`
/// outlives the module.
pub unsafe fn module_new_impl(
    args_chan: i32,
    out_chan: i32,
    exit_chan: i32,
    transport: Transport,
    state_ptr: *mut u8,
    state_size: usize,
    syscalls: *const super::SyscallTable,
) -> i32 {
    if state_ptr.is_null() || syscalls.is_null() {
        return -1;
    }
    if state_size < core::mem::size_of::<ModuleState>() {
        return -2;
    }
    core::ptr::write_bytes(state_ptr, 0, state_size);
    let s = &mut *(state_ptr as *mut ModuleState);
    s.syscalls = syscalls;
    s.args_chan = args_chan;
    s.out_chan = out_chan;
    s.exit_chan = exit_chan;
    s.transport = transport;
    s.fd = -1;
    s.fd2 = -1;
    0
}

// ── Output ─────────────────────────────────────────────────────────────────

fn say(s: &mut ModuleState, b: &[u8]) {
    let at = s.out_len as usize;
    if b.len() > OUT_MAX - at {
        s.out_over = 1;
        return;
    }
    put(&mut s.out[at..], b);
    s.out_len += b.len() as u32;
}

fn say_u64(s: &mut ModuleState, mut v: u64) {
    let mut d = [0u8; 20];
    let mut n = 0;
    loop {
        d[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
        if v == 0 {
            break;
        }
    }
    while n > 0 {
        n -= 1;
        let c = [d[n]];
        say(s, &c);
    }
}

fn say_hex(s: &mut ModuleState, b: &[u8]) {
    const H: &[u8; 16] = b"0123456789abcdef";
    for &x in b {
        let c = [H[(x >> 4) as usize], H[(x & 15) as usize]];
        say(s, &c);
    }
}

fn say_oid(s: &mut ModuleState, d: &[u8; 32]) {
    say(s, b"sha256:");
    say_hex(s, d);
}

/// Output so far, written now as whole lines. False while the channel has
/// not taken it.
unsafe fn flush_out(s: &mut ModuleState) -> bool {
    if s.out_len == 0 {
        return true;
    }
    if s.out_chan < 0 {
        s.out_len = 0;
        return true;
    }
    let n = s.out_len as usize;
    if (sys(s).channel_write)(s.out_chan, s.out.as_ptr(), n) == n as i32 {
        s.out_len = 0;
        return true;
    }
    false
}

/// End the command with `code`, its message already said.
fn finish(s: &mut ModuleState, code: i32) {
    s.exit_code = code;
    s.done = 1;
}

fn fail(s: &mut ModuleState, why: &[u8]) {
    say(s, b"error: ");
    say(s, why);
    say(s, b"\n");
    finish(s, 1);
}

fn fail_status(s: &mut ModuleState, what: &[u8], status: u8) {
    say(s, b"error: ");
    say(s, what);
    say(s, b": ");
    say_status(s, status);
    say(s, b"\n");
    finish(s, if status == aw::STATUS_BUSY { 75 } else { 1 });
}

/// Say what an admin status means. Each branch says its own words: a
/// `match` that returned them would be a table of pointers, which a
/// module loaded where it was not linked cannot read.
fn say_status(s: &mut ModuleState, st: u8) {
    if st == aw::STATUS_OK {
        say(s, b"ok")
    } else if st == aw::STATUS_NOT_FOUND {
        say(s, b"not found")
    } else if st == aw::STATUS_BUSY {
        say(s, b"busy, try again")
    } else if st == aw::STATUS_QUOTA {
        say(s, b"quota exceeded")
    } else if st == aw::STATUS_CONFLICT {
        say(s, b"conflict: the key moved, or is not bound as asked")
    } else if st == aw::STATUS_LEASE_HELD {
        say(s, b"another writer holds the lease")
    } else if st == aw::STATUS_LEASE_LOST {
        say(s, b"the lease was lost")
    } else if st == aw::STATUS_FORBIDDEN {
        say(s, b"forbidden: no capability presented covers it")
    } else if st == aw::STATUS_EXISTS {
        say(s, b"exists")
    } else {
        say(s, b"refused")
    }
}

// ── argv ───────────────────────────────────────────────────────────────────

fn arg(s: &ModuleState, i: usize) -> &[u8] {
    let (a, b) = s.args[i];
    &s.argv[a as usize..b as usize]
}

/// The command's `i`th argument.
fn carg(s: &ModuleState, i: usize) -> Option<&[u8]> {
    let at = s.cmd_at as usize + i;
    if at < s.argc as usize {
        Some(arg(s, at))
    } else {
        None
    }
}

fn opt(s: &ModuleState, at: i8) -> Option<&[u8]> {
    if at < 0 {
        None
    } else {
        Some(arg(s, at as usize))
    }
}

/// Split the argv record and take the options, wherever they stand.
/// False with the reason said when the record is not a command line.
fn parse(s: &mut ModuleState) -> bool {
    let n = s.argv_len as usize;
    let mut argc = 0usize;
    let mut start = 0usize;
    let mut i = 0;
    while i <= n {
        if i == n || s.argv[i] == 0 {
            if i > start || i < n {
                if argc == MAX_ARGS {
                    fail(s, b"too many arguments");
                    return false;
                }
                s.args[argc] = (start as u16, i as u16);
                argc += 1;
            }
            start = i + 1;
        }
        i += 1;
    }
    s.argc = argc as u8;
    s.admin_at = -1;
    s.cap_at = -1;
    s.to_at = -1;
    s.to_cap_at = -1;
    s.if_at = -1;
    s.type_at = -1;
    // Options are taken out; what is left, in order, is the command.
    let mut kept = [(0u16, 0u16); MAX_ARGS];
    let mut nk = 0;
    let mut k = 0;
    while k < argc {
        let a = s.args[k];
        let word = &s.argv[a.0 as usize..a.1 as usize];
        let slot: Option<*mut i8> = if eq(word, b"--admin") {
            Some(&mut s.admin_at)
        } else if eq(word, b"--capability") {
            Some(&mut s.cap_at)
        } else if eq(word, b"--to") {
            Some(&mut s.to_at)
        } else if eq(word, b"--to-capability") {
            Some(&mut s.to_cap_at)
        } else if eq(word, b"--if") {
            Some(&mut s.if_at)
        } else if eq(word, b"--type") {
            Some(&mut s.type_at)
        } else {
            None
        };
        if eq(word, b"--if-absent") {
            s.if_absent = 1;
            k += 1;
            continue;
        }
        match slot {
            Some(p) => {
                if k + 1 >= argc {
                    fail(s, b"an option is missing its value");
                    return false;
                }
                // The value's index in the final table is assigned below.
                unsafe { *p = -2 - (k + 1) as i8 };
                k += 2;
            }
            None => {
                kept[nk] = a;
                nk += 1;
                k += 1;
            }
        }
    }
    // Options' values go after the command's arguments in the table.
    let mut table = [(0u16, 0u16); MAX_ARGS];
    put_args(&mut table, &kept[..nk]);
    let mut at = nk;
    for p in [
        &mut s.admin_at,
        &mut s.cap_at,
        &mut s.to_at,
        &mut s.to_cap_at,
        &mut s.if_at,
        &mut s.type_at,
    ] {
        if *p <= -2 {
            let src = (-2 - *p) as usize;
            table[at] = s.args[src];
            *p = at as i8;
            at += 1;
        }
    }
    s.args = table;
    s.argc = nk as u8;
    s.cmd_at = 0;
    true
}

fn put_args(dst: &mut [(u16, u16)], src: &[(u16, u16)]) {
    let mut i = 0;
    while i < src.len() {
        dst[i] = src[i];
        i += 1;
    }
}

/// `(a / b, a % b)` for `b` > 0, by shift and subtract: a division by a
/// value known only at run time links a panic path a module cannot carry.
fn divmod(a: u64, b: u64) -> (u64, u64) {
    if b == 0 {
        return (0, a);
    }
    let mut q = 0u64;
    let mut r = 0u64;
    let mut i = 64;
    while i > 0 {
        i -= 1;
        r = (r << 1) | ((a >> i) & 1);
        if r >= b {
            r -= b;
            q |= 1 << i;
        }
    }
    (q, r)
}

fn parse_u64(b: &[u8]) -> Option<u64> {
    if b.is_empty() || b.len() > 19 {
        return None;
    }
    let mut v: u64 = 0;
    for &c in b {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (c - b'0') as u64;
    }
    Some(v)
}

fn help(s: &mut ModuleState) {
    say(
        s,
        b"loam - the operator's admin applet\n\
          usage: loam [--admin <host:port>] --capability <file> <command> ...\n\
          \x20 lookup  <root> <path>\n\
          \x20 ls      <root> [prefix]\n\
          \x20 put     <root> <path> <file> [--if-absent | --if <object-id>] [--type <content-type>]\n\
          \x20 get     <root> <path> <file>\n\
          \x20 rm      <root> <path> [--if <object-id>]\n\
          \x20 volume create <root> <path> <size> <extent-size>\n\
          \x20 volume delete <root> <path>\n\
          \x20 volume read   <root> <path> <offset> <length> <file>\n\
          \x20 snapshot create  <src-root> <snap-root> <manifest-file>\n\
          \x20 snapshot restore <manifest-file> <dst-root>\n\
          \x20 snapshot delete  <snap-root>\n\
          \x20 export <manifest-file> <dst-root> --to <host:port> --to-capability <file>\n\
          The capability file holds one fxcap1. chain per line, presented\n\
          to the node before anything else.\n",
    );
}

// ── Files ──────────────────────────────────────────────────────────────────

unsafe fn fs_open(s: &ModuleState, path: &[u8]) -> i32 {
    let mut p = [0u8; PATH_MAX];
    if path.len() > PATH_MAX {
        return -22;
    }
    put(&mut p, path);
    (sys(s).provider_call)(-1, FS_OPEN, p.as_mut_ptr(), path.len())
}

/// A new, empty file at `path`.
unsafe fn fs_create(s: &ModuleState, path: &[u8]) -> i32 {
    let mut p = [0u8; PATH_MAX];
    if path.len() > PATH_MAX {
        return -22;
    }
    put(&mut p, path);
    let _ = (sys(s).provider_call)(-1, FS_UNLINK, p.as_mut_ptr(), path.len());
    (sys(s).provider_call)(-1, FS_OPEN_CREATE, p.as_mut_ptr(), path.len())
}

unsafe fn fs_unlink(s: &ModuleState, path: &[u8]) {
    let mut p = [0u8; PATH_MAX];
    if path.len() <= PATH_MAX {
        put(&mut p, path);
        let _ = (sys(s).provider_call)(-1, FS_UNLINK, p.as_mut_ptr(), path.len());
    }
}

unsafe fn fs_close(s: &mut ModuleState) {
    if s.fd >= 0 {
        let fd = s.fd;
        let _ = (sys(s).provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.fd = -1;
    }
}

/// Fill `buf[..n]` from `fd`; the count read, short only at the end.
unsafe fn fs_read_full(s: &mut ModuleState, n: usize) -> Option<usize> {
    let fd = s.fd;
    let mut got = 0;
    while got < n {
        let rc = (sys(s).provider_call)(fd, FS_READ, s.buf.as_mut_ptr().add(got), n - got);
        if rc < 0 {
            return None;
        }
        if rc == 0 {
            break;
        }
        got += rc as usize;
    }
    Some(got)
}

unsafe fn fs_write_all(s: &ModuleState, fd: i32, b: &[u8]) -> bool {
    if b.is_empty() {
        return true;
    }
    let rc = (sys(s).provider_call)(fd, FS_WRITE, b.as_ptr() as *mut u8, b.len());
    rc >= 0 && rc as usize == b.len()
}

// ── Sessions and requests ──────────────────────────────────────────────────

/// Open session `k` to `authority` with the chains in `cap_file`.
unsafe fn open_session(
    s: &mut ModuleState,
    k: usize,
    authority: &[u8],
    cap_file: &[u8],
    tag: u8,
) -> bool {
    let now = s.now_ms;
    let sysp: &super::SyscallTable = &*s.syscalls;
    let mut path = [0u8; PATH_MAX];
    if cap_file.len() > PATH_MAX {
        fail(s, b"the capability file's path is too long");
        return false;
    }
    put(&mut path, cap_file);
    let scratch: &mut [u8; ac::CAP_FILE_MAX] = &mut *(&mut s.cap_scratch as *mut _);
    if let Err(why) = ac::load_chain_file(&mut s.clients[k], sysp, &path[..cap_file.len()], scratch)
    {
        fail(s, why);
        return false;
    }
    match s.transport {
        Transport::Net { net_in, net_out } => {
            if !ac::init_net(&mut s.clients[k], net_in, net_out, tag, authority, now) {
                fail(s, b"the authority is too long");
                return false;
            }
            ac::share_transport(&mut s.clients[k]);
        }
        Transport::Link { links } => {
            let (link_in, link_out) = links[k];
            ac::init_link(&mut s.clients[k], link_in, link_out, tag as u32, now);
        }
    }
    true
}

/// Send the `n`-byte request in `req` on session `k` and await its answer.
unsafe fn ask(s: &mut ModuleState, k: usize, n: usize) {
    let sysp: &super::SyscallTable = &*s.syscalls;
    let req: &[u8] = &*(&s.req[..n] as *const [u8]);
    if !ac::send(&mut s.clients[k], sysp, req) {
        fail(s, b"the session could not take a request");
        return;
    }
    s.waiting = k as u8 + 1;
}

fn next_cid(s: &mut ModuleState) -> u32 {
    s.cid = s.cid.wrapping_add(1);
    s.cid
}

/// The answer in hand.
fn answer(s: &ModuleState) -> &'static [u8] {
    unsafe { &*(&s.ans[..s.ans_len as usize] as *const [u8]) }
}

/// Fresh random bytes; false when the platform has none. A holder and a
/// volume id must be distinct from every other, so there is no stand-in.
unsafe fn random(s: &ModuleState, out: &mut [u8]) -> bool {
    (sys(s).provider_call)(-1, RANDOM, out.as_mut_ptr(), out.len()) >= 0
}

fn digest_of(oid: &[u8]) -> Option<[u8; 32]> {
    if oid.len() != 71 || !eq(&oid[..7], b"sha256:") {
        return None;
    }
    let mut d = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        let h = nib(oid[7 + 2 * i])?;
        let l = nib(oid[8 + 2 * i])?;
        d[i] = (h << 4) | l;
        i += 1;
    }
    Some(d)
}

fn nib(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

fn oid_of(d: &[u8; 32]) -> [u8; 71] {
    let mut o = [0u8; 71];
    put(&mut o[..7], b"sha256:");
    super::body_wire::hex_lower_into(d, &mut o[7..]);
    o
}

// ── The step ───────────────────────────────────────────────────────────────

/// # Safety
/// `state_ptr` is this module's state, built by `module_new_impl`.
pub unsafe fn module_step_impl(state_ptr: *mut u8) -> i32 {
    if state_ptr.is_null() {
        return STEP_DONE;
    }
    let s = &mut *(state_ptr as *mut ModuleState);
    if s.syscalls.is_null() {
        return STEP_DONE;
    }
    let mut b = [0u8; 8];
    (sys(s).provider_call)(-1, TIMER_MILLIS, b.as_mut_ptr(), 8);
    s.now_ms = u64::from_le_bytes(b);

    if s.done != 0 {
        if !flush_out(s) {
            return 0;
        }
        if s.exit_sent == 0 {
            close_all(s);
            if s.out_over != 0 && s.exit_code == 0 {
                s.exit_code = 1;
            }
            if s.exit_chan >= 0 {
                let code = s.exit_code.to_le_bytes();
                if (sys(s).channel_write)(s.exit_chan, code.as_ptr(), 4) != 4 {
                    return 0;
                }
            }
            s.exit_sent = 1;
        }
        return STEP_DONE;
    }
    if s.started == 0 {
        if !start(s) {
            return 0;
        }
        s.started = 1;
        if s.done != 0 {
            return 0;
        }
    }
    drive(s);
    if s.out_len as usize > OUT_FLUSH {
        let _ = flush_out(s);
    }
    0
}

unsafe fn close_all(s: &mut ModuleState) {
    fs_close(s);
    if s.fd2 >= 0 {
        let fd = s.fd2;
        let _ = (sys(s).provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.fd2 = -1;
    }
    let sysp: &super::SyscallTable = &*s.syscalls;
    let mut k = 0;
    while k < s.nclients as usize {
        if ac::is_ready(&s.clients[k]) {
            ac::close(&mut s.clients[k], sysp);
        }
        k += 1;
    }
}

/// Take the argv record, choose the command, open its sessions. False
/// while the record has not arrived.
unsafe fn start(s: &mut ModuleState) -> bool {
    let n = if s.args_chan >= 0 {
        (sys(s).channel_read)(s.args_chan, s.argv.as_mut_ptr(), ARGV_MAX)
    } else {
        0
    };
    if n <= 0 {
        s.waited += 1;
        if s.waited < ARGV_WAIT {
            return false;
        }
        help(s);
        finish(s, 2);
        return true;
    }
    s.argv_len = n as u32;
    if !parse(s) {
        return true;
    }
    let Some(c0) = carg(s, 0) else {
        help(s);
        finish(s, 2);
        return true;
    };
    let c1 = carg(s, 1).unwrap_or(&[]);
    let (cmd, skip) = if eq(c0, b"help") {
        (C_HELP, 1)
    } else if eq(c0, b"lookup") {
        (C_LOOKUP, 1)
    } else if eq(c0, b"ls") {
        (C_LS, 1)
    } else if eq(c0, b"put") {
        (C_PUT, 1)
    } else if eq(c0, b"get") {
        (C_GET, 1)
    } else if eq(c0, b"rm") {
        (C_RM, 1)
    } else if eq(c0, b"volume") && eq(c1, b"create") {
        (C_VCREATE, 2)
    } else if eq(c0, b"volume") && eq(c1, b"delete") {
        (C_VDELETE, 2)
    } else if eq(c0, b"volume") && eq(c1, b"read") {
        (C_VREAD, 2)
    } else if eq(c0, b"snapshot") && eq(c1, b"create") {
        (C_SCREATE, 2)
    } else if eq(c0, b"snapshot") && eq(c1, b"restore") {
        (C_SRESTORE, 2)
    } else if eq(c0, b"snapshot") && eq(c1, b"delete") {
        (C_SDELETE, 2)
    } else if eq(c0, b"export") {
        (C_EXPORT, 1)
    } else {
        say(s, b"error: unknown command\n");
        help(s);
        finish(s, 2);
        return true;
    };
    s.cmd = cmd;
    s.cmd_at += skip;
    if cmd == C_HELP {
        help(s);
        finish(s, 0);
        return true;
    }
    let need = match cmd {
        C_LOOKUP | C_RM | C_VDELETE | C_SRESTORE => 2,
        C_LS | C_SDELETE => 1,
        C_PUT | C_GET | C_SCREATE => 3,
        C_VCREATE => 4,
        C_VREAD => 5,
        C_EXPORT => 2,
        _ => 0,
    };
    let have = s.argc as usize - s.cmd_at as usize;
    if have < need {
        fail(s, b"missing arguments (see `loam help`)");
        return true;
    }
    let Some(cap) = opt(s, s.cap_at) else {
        fail(s, b"--capability <file> is required");
        return true;
    };
    let mut capb = [0u8; PATH_MAX];
    let cl = cap.len().min(PATH_MAX);
    put(&mut capb, cap);
    let admin = opt(s, s.admin_at).unwrap_or(DEFAULT_ADMIN);
    let mut adminb = [0u8; ac::AUTHORITY_MAX];
    let al = admin.len().min(ac::AUTHORITY_MAX);
    put(&mut adminb, admin);
    if !open_session(s, 0, &adminb[..al], &capb[..cl], TAG_A) {
        return true;
    }
    s.nclients = 1;
    if cmd == C_EXPORT {
        let (Some(to), Some(tocap)) = (opt(s, s.to_at), opt(s, s.to_cap_at)) else {
            fail(
                s,
                b"export needs --to <host:port> and --to-capability <file>",
            );
            return true;
        };
        let mut tob = [0u8; ac::AUTHORITY_MAX];
        let tl = to.len().min(ac::AUTHORITY_MAX);
        put(&mut tob, to);
        let mut tcb = [0u8; PATH_MAX];
        let tcl = tocap.len().min(PATH_MAX);
        put(&mut tcb, tocap);
        if !open_session(s, 1, &tob[..tl], &tcb[..tcl], TAG_B) {
            return true;
        }
        s.nclients = 2;
    }
    true
}

/// Move the sessions, deliver an answer, or advance the command.
unsafe fn drive(s: &mut ModuleState) {
    let sysp: &super::SyscallTable = &*s.syscalls;
    // The shared transport, read once and handed to every session.
    if let Transport::Net { net_in, .. } = s.transport {
        for _ in 0..16 {
            let mut room = true;
            let mut k = 0;
            while k < s.nclients as usize {
                room &= ac::has_room(&s.clients[k]);
                k += 1;
            }
            if !room {
                break;
            }
            let reader: &mut ac::NetReader = &mut *(&mut s.reader as *mut _);
            match ac::read_frame(reader, sysp, net_in) {
                ac::Frame::Whole(ty, p) => {
                    let n = s.nclients as usize;
                    ac::feed_all(&mut s.clients[..n], sysp, ty, p);
                }
                ac::Frame::None => break,
                ac::Frame::Broken => {
                    fail(s, b"the transport sent a frame no session can be");
                    return;
                }
            }
        }
    }
    let mut k = 0;
    while k < s.nclients as usize {
        ac::poll(&mut s.clients[k], sysp, s.now_ms);
        if ac::has_failed(&s.clients[k]) {
            session_failed(s, k);
            return;
        }
        k += 1;
    }
    let mut k = 0;
    while k < s.nclients as usize {
        if !ac::is_ready(&s.clients[k]) {
            return;
        }
        k += 1;
    }
    if s.waiting != 0 {
        let k = s.waiting as usize - 1;
        let Some(a) = ac::recv(&mut s.clients[k]) else {
            return;
        };
        let n = a.len();
        if n > aw::RESPONSE_MAX {
            fail(s, b"an answer larger than any the wire carries");
            return;
        }
        let src: &[u8] = &*(a as *const [u8]);
        put(&mut s.ans, src);
        s.ans_len = n as u32;
        ac::take(&mut s.clients[k]);
        s.waiting = 0;
        advance(s, true);
        return;
    }
    if s.resume_at != 0 && s.now_ms < s.resume_at {
        return;
    }
    s.resume_at = 0;
    if s.out_len as usize > OUT_FLUSH && !flush_out(s) {
        return;
    }
    advance(s, false);
}

fn session_failed(s: &mut ModuleState, k: usize) {
    let c = &s.clients[k];
    let (why, refusal) = (c.why, c.refusal);
    say(s, b"error: ");
    if k == 1 {
        say(s, b"the destination: ");
    }
    if why == ac::WHY_TRANSPORT {
        say(s, b"the connection could not be made, or closed");
    } else if why == ac::WHY_REFUSED {
        say(s, b"a capability was refused (reason ");
    } else if why == ac::WHY_UNAUTHENTICATED {
        say(s, b"the node saw no client certificate");
    } else if why == ac::WHY_GRANTS_FULL {
        say(s, b"the session holds as many capabilities as it may");
    } else if why == ac::WHY_TIMEOUT {
        say(s, b"the connection or the presentation timed out");
    } else {
        say(s, b"the node sent something no answer can be");
    }
    if why == ac::WHY_REFUSED {
        say_u64(s, refusal as u64);
        say(s, b")");
    }
    say(s, b"\n");
    finish(s, 1);
}

/// Advance the command: `answered` when an answer to its last request is
/// in `ans`.
unsafe fn advance(s: &mut ModuleState, answered: bool) {
    if s.vb != VB_IDLE {
        vb_step(s, answered);
        if s.vb != VB_IDLE || s.done != 0 {
            return;
        }
        // The sub-flow ended: its caller resumes, with no answer of its own.
        return command(s, false);
    }
    if s.mv != 0 {
        mv_step(s, answered);
        if s.mv != 0 || s.done != 0 {
            return;
        }
        return command(s, false);
    }
    command(s, answered)
}

unsafe fn command(s: &mut ModuleState, answered: bool) {
    match s.cmd {
        C_LOOKUP => cmd_lookup(s, answered),
        C_LS => cmd_ls(s, answered),
        C_PUT => cmd_put(s, answered),
        C_GET => cmd_get(s, answered),
        C_RM => cmd_rm(s, answered),
        C_VCREATE => cmd_vcreate(s, answered),
        C_VDELETE => cmd_vdelete(s, answered),
        C_VREAD => cmd_vread(s, answered),
        C_SCREATE => cmd_screate(s, answered),
        C_SRESTORE => cmd_srestore(s, answered),
        C_SDELETE => cmd_sdelete(s, answered),
        C_EXPORT => cmd_export(s, answered),
        _ => finish(s, 2),
    }
}

/// The root and path the command names first.
fn key_args(s: &ModuleState) -> (&'static [u8], &'static [u8]) {
    let r = carg(s, 0).unwrap_or(&[]);
    let p = carg(s, 1).unwrap_or(&[]);
    unsafe { (&*(r as *const [u8]), &*(p as *const [u8])) }
}

unsafe fn send_lookup(s: &mut ModuleState, k: usize, root: &[u8], path: &[u8]) {
    let cid = next_cid(s);
    match aw::encode_admin_lookup(&mut s.req, cid, root, path) {
        Ok(n) => ask(s, k, n),
        Err(_) => fail(s, b"the key is not one the wire carries"),
    }
}

unsafe fn send_get_body(s: &mut ModuleState, k: usize, d: &[u8; 32]) {
    let cid = next_cid(s);
    match aw::encode_admin_get_body(&mut s.req, cid, d) {
        Ok(n) => ask(s, k, n),
        Err(_) => fail(s, b"a body request could not be encoded"),
    }
}

/// A binding a lookup found: revision, kind, object id and its length,
/// size.
type Found = (u64, u8, [u8; 96], usize, u64);

/// The binding a lookup answered, or `None` with the command ended
/// unless the key was simply unbound (`Some(None)`).
fn lookup_answer(s: &mut ModuleState) -> Option<Option<Found>> {
    match aw::decode_admin_lookup_ack(answer(s)) {
        Ok((_, aw::STATUS_OK, Some(b))) => {
            let mut oid = [0u8; 96];
            put(&mut oid, b.object_id);
            Some(Some((b.revision, b.kind, oid, b.object_id.len(), b.size)))
        }
        Ok((_, aw::STATUS_NOT_FOUND, _)) => Some(None),
        Ok((_, st, _)) => {
            fail_status(s, b"lookup", st);
            None
        }
        Err(_) => {
            fail(s, b"the node's answer does not decode");
            None
        }
    }
}

// ── lookup, ls, rm ─────────────────────────────────────────────────────────

unsafe fn cmd_lookup(s: &mut ModuleState, answered: bool) {
    let (root, path) = key_args(s);
    if !answered {
        return send_lookup(s, 0, root, path);
    }
    match aw::decode_admin_lookup_ack(answer(s)) {
        Ok((_, aw::STATUS_OK, Some(b))) => {
            say(s, b"revision ");
            say_u64(s, b.revision);
            say(s, b"\nkind ");
            say_u64(s, b.kind as u64);
            say(s, b"\nobject ");
            say(s, b.object_id);
            say(s, b"\nsize ");
            say_u64(s, b.size);
            say(s, b"\ntype ");
            say(s, b.content_type);
            say(s, b"\nstamp_ms ");
            say_u64(s, b.stamp_ms);
            say(s, b"\n");
            finish(s, 0);
        }
        Ok((_, st, _)) => fail_status(s, b"lookup", st),
        Err(_) => fail(s, b"the node's answer does not decode"),
    }
}

/// Ask for the next listing page of `root` under `prefix`.
unsafe fn send_list(s: &mut ModuleState, k: usize, root: &[u8], prefix: &[u8]) {
    let cid = next_cid(s);
    let after: &[u8] = &*(&s.after[..s.after_len as usize] as *const [u8]);
    match aw::encode_admin_list_files(
        &mut s.req,
        cid,
        root,
        prefix,
        after,
        aw::LIST_PAGE_MAX as u8,
    ) {
        Ok(n) => ask(s, k, n),
        Err(_) => fail(s, b"the prefix is not one the wire carries"),
    }
}

/// Hold a listing answer and start on its entries. False with the
/// command ended when it is a refusal.
fn hold_list(s: &mut ModuleState) -> bool {
    let a = answer(s);
    match aw::decode_admin_list_files_ack(a, |_, _| {}) {
        Ok((_, aw::STATUS_OK, more)) => {
            put(&mut s.list, a);
            s.list_len = a.len() as u32;
            s.list_at = 0;
            s.list_more = more as u8;
            true
        }
        Ok((_, st, _)) => {
            fail_status(s, b"list", st);
            false
        }
        Err(_) => {
            fail(s, b"the node's answer does not decode");
            false
        }
    }
}

/// The held page's next entry into `key`, `kind`, `revision`,
/// `entry_digest` (zero when the binding names no content). False when
/// the page is spent; the cursor moves past every entry taken.
fn next_entry(s: &mut ModuleState) -> bool {
    let page: &[u8] = unsafe { &*(&s.list[..s.list_len as usize] as *const [u8]) };
    let want = s.list_at;
    let mut i = 0u32;
    let mut found = false;
    let mut key = [0u8; PATH_MAX];
    let mut key_len = 0usize;
    let (mut kind, mut rev, mut digest, mut size) = (0u8, 0u64, [0u8; 32], 0u64);
    let mut ctype = [0u8; 128];
    let mut ctype_len = 0usize;
    let _ = aw::decode_admin_list_files_ack(page, |path, b| {
        if i == want && path.len() <= PATH_MAX && b.content_type.len() <= 128 {
            put(&mut key, path);
            key_len = path.len();
            kind = b.kind;
            rev = b.revision;
            digest = digest_of(b.object_id).unwrap_or([0u8; 32]);
            size = b.size;
            put(&mut ctype, b.content_type);
            ctype_len = b.content_type.len();
            found = true;
        }
        i += 1;
    });
    if !found {
        return false;
    }
    s.list_at += 1;
    put(&mut s.key, &key[..key_len]);
    s.key_len = key_len as u16;
    s.kind = kind;
    s.revision = rev;
    s.entry_digest = digest;
    s.entry_size = size;
    s.ctype = ctype;
    s.ctype_len = ctype_len as u8;
    put(&mut s.after, &key[..key_len]);
    s.after_len = key_len as u16;
    true
}

unsafe fn cmd_ls(s: &mut ModuleState, answered: bool) {
    let root = carg(s, 0).unwrap_or(&[]);
    let root: &[u8] = &*(root as *const [u8]);
    let prefix: &[u8] = &*(carg(s, 1).unwrap_or(&[]) as *const [u8]);
    if !answered {
        return send_list(s, 0, root, prefix);
    }
    let a = answer(s);
    let decoded = aw::decode_admin_list_files_ack(a, |path, b| {
        let sp: &mut ModuleState = &mut *(s as *mut ModuleState);
        say(sp, path);
        say(sp, b"\t");
        say_u64(sp, b.size);
        say(sp, b"\t");
        say(sp, b.object_id);
        say(sp, b"\n");
        put(&mut sp.after, path);
        sp.after_len = path.len() as u16;
    });
    match decoded {
        Ok((_, aw::STATUS_OK, true)) => send_list(s, 0, root, prefix),
        Ok((_, aw::STATUS_OK, false)) => finish(s, 0),
        Ok((_, st, _)) => fail_status(s, b"list", st),
        Err(_) => fail(s, b"the node's answer does not decode"),
    }
}

unsafe fn cmd_rm(s: &mut ModuleState, answered: bool) {
    let (root, path) = key_args(s);
    if !answered {
        let expect: &[u8] = &*(opt(s, s.if_at).unwrap_or(&[]) as *const [u8]);
        let cond = aw::WriteCond {
            mode: if expect.is_empty() {
                aw::WRITE_ANY
            } else {
                aw::WRITE_IF
            },
            expect,
        };
        let cid = next_cid(s);
        return match aw::encode_admin_delete_file(&mut s.req, cid, root, path, &cond) {
            Ok(n) => ask(s, 0, n),
            Err(_) => fail(s, b"the key or condition is not one the wire carries"),
        };
    }
    match aw::decode_admin_delete_file_ack(answer(s)) {
        Ok((_, aw::STATUS_OK, _)) => {
            say(s, b"deleted\n");
            finish(s, 0);
        }
        Ok((_, st, _)) => fail_status(s, b"delete", st),
        Err(_) => fail(s, b"the node's answer does not decode"),
    }
}

// ── put ────────────────────────────────────────────────────────────────────

const PUT_HASH: u8 = 0;
const PUT_OPENED: u8 = 1;
const PUT_CHUNKED: u8 = 2;
const PUT_DONE: u8 = 3;

unsafe fn cmd_put(s: &mut ModuleState, _answered: bool) {
    let (root, path) = key_args(s);
    let file: &[u8] = &*(carg(s, 2).unwrap_or(&[]) as *const [u8]);
    let expect: &[u8] = &*(opt(s, s.if_at).unwrap_or(&[]) as *const [u8]);
    let ctype: &[u8] = &*(opt(s, s.type_at).unwrap_or(&[]) as *const [u8]);
    let cond = aw::WriteCond {
        mode: if s.if_absent != 0 {
            aw::WRITE_ABSENT
        } else if !expect.is_empty() {
            aw::WRITE_IF
        } else {
            aw::WRITE_ANY
        },
        expect,
    };
    match s.st {
        PUT_HASH => {
            // Pass one: the digest and the size, a block at a time.
            s.fd = fs_open(s, file);
            if s.fd < 0 {
                return fail(s, b"the file cannot be opened");
            }
            s.hash = super::Sha256::new();
            s.size = 0;
            loop {
                let Some(n) = fs_read_full(s, MAX_BODY) else {
                    return fail(s, b"the file cannot be read");
                };
                let b: &[u8] = &*(&s.buf[..n] as *const [u8]);
                s.hash.update(b);
                s.size += n as u64;
                if s.size > super::body_wire::MAX_STREAM_TOTAL {
                    return fail(s, b"the file is larger than the largest object (1 GiB)");
                }
                if n < MAX_BODY {
                    break;
                }
            }
            s.digest = core::mem::take(&mut s.hash).finalize();
            fs_close(s);
            s.fd = fs_open(s, file);
            if s.fd < 0 {
                return fail(s, b"the file cannot be opened");
            }
            s.off = 0;
            let cid = next_cid(s);
            if s.size as usize <= MAX_BODY {
                // One request carries it whole.
                let Some(n) = fs_read_full(s, s.size as usize) else {
                    return fail(s, b"the file cannot be read");
                };
                if n as u64 != s.size {
                    return fail(s, b"the file changed while it was being sent");
                }
                let body: &[u8] = &*(&s.buf[..n] as *const [u8]);
                s.st = PUT_DONE;
                return match aw::encode_admin_put_file(
                    &mut s.req, cid, root, path, 0, &cond, ctype, body,
                ) {
                    Ok(m) => ask(s, 0, m),
                    Err(_) => fail(s, b"the key, condition or type is not one the wire carries"),
                };
            }
            s.st = PUT_OPENED;
            let d = s.digest;
            match aw::encode_put_file_open(&mut s.req, cid, root, path, 0, &cond, ctype, &d, s.size)
            {
                Ok(m) => ask(s, 0, m),
                Err(_) => fail(s, b"the key, condition or type is not one the wire carries"),
            }
        }
        PUT_OPENED | PUT_CHUNKED => {
            if s.st == PUT_OPENED {
                match aw::decode_put_file_open_ack(answer(s)) {
                    Ok((_, aw::STATUS_OK, pfid)) => s.pfid = pfid,
                    Ok((_, st, _)) => return fail_status(s, b"put", st),
                    Err(_) => return fail(s, b"the node's answer does not decode"),
                }
            } else {
                match aw::decode_put_file_chunk_ack(answer(s)) {
                    Ok((_, aw::STATUS_OK)) => {}
                    Ok((_, st)) => return fail_status(s, b"put", st),
                    Err(_) => return fail(s, b"the node's answer does not decode"),
                }
            }
            let cid = next_cid(s);
            let pfid = s.pfid;
            if s.off >= s.size {
                s.st = PUT_DONE;
                return match aw::encode_put_file_commit(&mut s.req, cid, pfid) {
                    Ok(m) => ask(s, 0, m),
                    Err(_) => fail(s, b"a commit could not be encoded"),
                };
            }
            let left = s.size - s.off;
            let want = if left < MAX_BODY as u64 {
                left as usize
            } else {
                MAX_BODY
            };
            let Some(n) = fs_read_full(s, want) else {
                return fail(s, b"the file cannot be read");
            };
            if n != want {
                return fail(s, b"the file changed while it was being sent");
            }
            s.off += n as u64;
            s.st = PUT_CHUNKED;
            let chunk: &[u8] = &*(&s.buf[..n] as *const [u8]);
            match aw::encode_put_file_chunk(&mut s.req, cid, pfid, chunk) {
                Ok(m) => ask(s, 0, m),
                Err(_) => fail(s, b"a chunk could not be encoded"),
            }
        }
        _ => match aw::decode_admin_put_file_ack(answer(s)) {
            Ok((_, aw::STATUS_OK, Some(d), _)) if eq(d, &s.digest) => {
                let dg = s.digest;
                say(s, b"object ");
                say_oid(s, &dg);
                say(s, b"\nsize ");
                say_u64(s, s.size);
                say(s, b"\n");
                finish(s, 0);
            }
            Ok((_, aw::STATUS_OK, _, _)) => {
                fail(s, b"the node stored the bytes under another digest")
            }
            Ok((_, st, _, _)) => fail_status(s, b"put", st),
            Err(_) => fail(s, b"the node's answer does not decode"),
        },
    }
}

// ── get ────────────────────────────────────────────────────────────────────

unsafe fn cmd_get(s: &mut ModuleState, answered: bool) {
    let (root, path) = key_args(s);
    let file: &[u8] = &*(carg(s, 2).unwrap_or(&[]) as *const [u8]);
    if !answered {
        s.st = 0;
        return send_lookup(s, 0, root, path);
    }
    if s.st == 0 {
        let Some(found) = lookup_answer(s) else {
            return;
        };
        let Some((_, _, oid, olen, size)) = found else {
            return fail(s, b"not found");
        };
        let Some(d) = digest_of(&oid[..olen]) else {
            return fail(s, b"the path is bound to something that is not content");
        };
        s.digest = d;
        s.size = size;
        s.off = 0;
        s.hash = super::Sha256::new();
        s.fd = fs_create(s, file);
        if s.fd < 0 {
            return fail(s, b"the file cannot be created");
        }
        s.st = 1;
    } else {
        match aw::decode_read_file_range_ack(answer(s)) {
            Ok((_, aw::STATUS_OK, Some(bytes))) if !bytes.is_empty() => {
                let fd = s.fd;
                if !fs_write_all(s, fd, bytes) {
                    return fail(s, b"the file cannot be written");
                }
                s.hash.update(bytes);
                s.off += bytes.len() as u64;
            }
            Ok((_, aw::STATUS_OK, _)) => return fail(s, b"the object ended before its size"),
            Ok((_, st, _)) => return fail_status(s, b"read", st),
            Err(_) => return fail(s, b"the node's answer does not decode"),
        }
    }
    if s.off >= s.size {
        let got = core::mem::take(&mut s.hash).finalize();
        fs_close(s);
        if got != s.digest {
            fs_unlink(s, file);
            return fail(s, b"the bytes read do not hash to the object's digest");
        }
        say(s, b"wrote ");
        say_u64(s, s.size);
        say(s, b" bytes\n");
        return finish(s, 0);
    }
    let left = s.size - s.off;
    let n = if left < MAX_BODY as u64 {
        left as u32
    } else {
        MAX_BODY as u32
    };
    let oid = oid_of(&s.digest);
    let cid = next_cid(s);
    match aw::encode_read_file_range(&mut s.req, cid, s.off, n, root, path, &oid) {
        Ok(m) => ask(s, 0, m),
        Err(_) => fail(s, b"a read could not be encoded"),
    }
}

// ── The volume-bind sub-flow ───────────────────────────────────────────────
//
// A volume binding exists only through a fenced commit: take the lease,
// open a flush (so the orphan sweep keeps what is about to be named),
// store the root page if it is new, commit it at revision 1 from 0, and
// release. The lease is released however the commit went. The same flow
// deletes a volume: lease, delete at its revision, release.

/// Start binding `entry_digest` (or the page in `page`, stored first) as
/// a volume at `vb_root`/`key` on session `k`.
unsafe fn vb_start(s: &mut ModuleState, k: usize, root: &[u8], store_page: bool, delete: bool) {
    s.vb_client = k as u8;
    put(&mut s.vb_root, root);
    s.vb_root_len = root.len() as u8;
    s.vb_put_page = store_page as u8;
    s.vb_delete = delete as u8;
    s.vb_status = aw::STATUS_OK;
    let mut h = [0u8; aw::LEASE_HOLDER_LEN];
    if !random(s, &mut h) {
        return fail(s, b"the platform offers no randomness for a lease holder");
    }
    s.holder = h;
    s.vb = VB_LEASE;
    let cid = next_cid(s);
    let (r, p) = vb_key(s);
    match aw::encode_admin_lease(&mut s.req, cid, aw::LEASE_ACQUIRE, r, p, &h, LEASE_TTL_MS) {
        Ok(n) => ask(s, k, n),
        Err(_) => {
            s.vb = VB_IDLE;
            fail(s, b"the key is not one the wire carries");
        }
    }
}

fn vb_key(s: &ModuleState) -> (&'static [u8], &'static [u8]) {
    unsafe {
        (
            &*(&s.vb_root[..s.vb_root_len as usize] as *const [u8]),
            &*(&s.key[..s.key_len as usize] as *const [u8]),
        )
    }
}

unsafe fn vb_volume(s: &mut ModuleState, mode: u8, oid: &[u8], expected: u64) {
    let cid = next_cid(s);
    let (r, p) = vb_key(s);
    let req = aw::DecodedAdminVolume {
        correlation_id: cid,
        mode,
        namespace_root: r,
        path: p,
        object_id: oid,
        holder: s.holder,
        fence: s.fence,
        expected,
    };
    let k = s.vb_client as usize;
    match aw::encode_admin_volume(&mut s.req, &req) {
        Ok(n) => ask(s, k, n),
        Err(_) => {
            s.vb = VB_IDLE;
            fail(s, b"a volume request could not be encoded");
        }
    }
}

unsafe fn vb_release(s: &mut ModuleState) {
    s.vb = VB_RELEASE;
    let cid = next_cid(s);
    let (r, p) = vb_key(s);
    let h = s.holder;
    let k = s.vb_client as usize;
    match aw::encode_admin_lease(&mut s.req, cid, aw::LEASE_RELEASE, r, p, &h, LEASE_TTL_MS) {
        Ok(n) => ask(s, k, n),
        Err(_) => s.vb = VB_IDLE,
    }
}

unsafe fn vb_step(s: &mut ModuleState, answered: bool) {
    match s.vb {
        VB_LEASE => match aw::decode_admin_lease_ack(answer(s)) {
            Ok((_, aw::STATUS_OK, fence, _)) => {
                s.fence = fence;
                if s.vb_delete != 0 {
                    s.vb = VB_DELETE;
                    let e = s.vb_expected;
                    return vb_volume(s, aw::VOLUME_DELETE, &[], e);
                }
                s.vb = VB_BEGIN;
                s.begin_since = s.now_ms;
                vb_volume(s, aw::VOLUME_BEGIN, &[], 0)
            }
            Ok((_, st, _, _)) => {
                s.vb = VB_IDLE;
                s.vb_status = st;
            }
            Err(_) => {
                s.vb = VB_IDLE;
                fail(s, b"the node's answer does not decode");
            }
        },
        VB_BEGIN => {
            if !answered {
                return vb_volume(s, aw::VOLUME_BEGIN, &[], 0);
            }
            match aw::decode_admin_volume_ack(answer(s)) {
                Ok((_, aw::STATUS_OK, _)) => {
                    if s.vb_put_page != 0 {
                        s.vb = VB_PUT;
                        let cid = next_cid(s);
                        let page: &[u8] = &*(&s.page[..s.page_len as usize] as *const [u8]);
                        let k = s.vb_client as usize;
                        return match aw::encode_admin_put_body(&mut s.req, cid, page) {
                            Ok(n) => ask(s, k, n),
                            Err(_) => fail(s, b"the root page could not be encoded"),
                        };
                    }
                    s.vb = VB_COMMIT;
                    let oid = oid_of(&s.entry_digest);
                    vb_volume(s, aw::VOLUME_COMMIT, &oid, 0)
                }
                // The orphan sweep holds a reservation that ends shortly.
                Ok((_, aw::STATUS_BUSY, _)) if s.now_ms - s.begin_since < BEGIN_PATIENCE_MS => {
                    s.resume_at = s.now_ms + BEGIN_RETRY_MS;
                }
                Ok((_, st, _)) => {
                    s.vb_status = st;
                    vb_release(s)
                }
                Err(_) => {
                    s.vb_status = 0xFF;
                    vb_release(s)
                }
            }
        }
        VB_PUT => match aw::decode_admin_put_body_ack(answer(s)) {
            Ok(a) if a.status == aw::STATUS_OK => {
                let want = super::sha256(&s.page[..s.page_len as usize]);
                match a.digest {
                    Some(d) if eq(d, &want) => {
                        s.entry_digest = want;
                        s.vb = VB_COMMIT;
                        let oid = oid_of(&want);
                        vb_volume(s, aw::VOLUME_COMMIT, &oid, 0)
                    }
                    _ => {
                        s.vb_status = 0xFF;
                        vb_release(s)
                    }
                }
            }
            Ok(a) => {
                s.vb_status = a.status;
                vb_release(s)
            }
            Err(_) => {
                s.vb_status = 0xFF;
                vb_release(s)
            }
        },
        VB_COMMIT | VB_DELETE => {
            match aw::decode_admin_volume_ack(answer(s)) {
                Ok((_, st, rev)) => {
                    s.vb_status = st;
                    s.vb_revision = rev;
                }
                Err(_) => s.vb_status = 0xFF,
            }
            vb_release(s)
        }
        _ => {
            // The release's answer: whatever it was, the flow is over.
            s.vb = VB_IDLE;
        }
    }
}

// ── volume create / delete / read ──────────────────────────────────────────

unsafe fn cmd_vcreate(s: &mut ModuleState, _answered: bool) {
    let (root, path) = key_args(s);
    if s.st == 0 {
        let (Some(size), Some(extent)) = (
            carg(s, 2).and_then(parse_u64),
            carg(s, 3).and_then(parse_u64),
        ) else {
            return fail(s, b"size and extent size are decimal byte counts");
        };
        if extent > u32::MAX as u64 {
            return fail(s, b"no map describes that geometry");
        }
        let Ok(depth) = mp::select_depth(size, extent as u32) else {
            return fail(s, b"no map describes that geometry: an extent of 1..=61440 bytes, at most 1048576 extents");
        };
        let span = if depth == 1 {
            extent
        } else {
            extent * mp::PAGE_ENTRIES as u64
        };
        let (q, r) = divmod(size, span);
        let children = (q + (r != 0) as u64) as usize;
        if children > mp::PAGE_ENTRIES || path.len() > PATH_MAX {
            return fail(s, b"no map describes that geometry");
        }
        let mut vid = [0u8; mp::VOLUME_ID_LEN];
        if !random(s, &mut vid) {
            return fail(s, b"the platform offers no randomness for a volume id");
        }
        // The root page's children: all unwritten. Laid out in the leaf
        // buffer, zeroed, rather than on the stack.
        let mut i = 0;
        while i < children * mp::DIGEST_LEN {
            s.leaf[i] = 0;
            i += 1;
        }
        let zeros: &[[u8; mp::DIGEST_LEN]] =
            core::slice::from_raw_parts(s.leaf.as_ptr() as *const [u8; mp::DIGEST_LEN], children);
        let page: &mut [u8] = &mut *(&mut s.page[..] as *mut [u8]);
        match mp::encode_root(page, &vid, size, extent as u32, zeros) {
            Ok(n) => s.page_len = n as u32,
            Err(_) => return fail(s, b"the root page could not be built"),
        }
        put(&mut s.key, path);
        s.key_len = path.len() as u16;
        s.st = 1;
        return vb_start(s, 0, root, true, false);
    }
    if s.vb_status != aw::STATUS_OK {
        return fail_status(s, b"volume create", s.vb_status);
    }
    let d = s.entry_digest;
    say(s, b"revision ");
    say_u64(s, s.vb_revision);
    say(s, b"\nroot ");
    say_oid(s, &d);
    say(s, b"\n");
    finish(s, 0);
}

unsafe fn cmd_vdelete(s: &mut ModuleState, answered: bool) {
    let (root, path) = key_args(s);
    match s.st {
        0 => {
            s.st = 1;
            send_lookup(s, 0, root, path)
        }
        1 if answered => {
            let Some(found) = lookup_answer(s) else {
                return;
            };
            let Some((rev, kind, _, _, _)) = found else {
                return fail(s, b"no volume is bound there");
            };
            if kind != KIND_VOLUME {
                return fail(s, b"the path is bound, but not to a volume");
            }
            put(&mut s.key, path);
            s.key_len = path.len() as u16;
            s.vb_expected = rev;
            s.st = 2;
            vb_start(s, 0, root, false, true)
        }
        _ => {
            if s.vb_status != aw::STATUS_OK {
                return fail_status(s, b"volume delete", s.vb_status);
            }
            say(s, b"deleted\n");
            finish(s, 0);
        }
    }
}

/// `volume read`: the committed revision's bytes in a window, through the
/// map — root, leaf, extent — with unwritten extents reading as zeros.
unsafe fn cmd_vread(s: &mut ModuleState, answered: bool) {
    let (root, path) = key_args(s);
    let file: &[u8] = &*(carg(s, 4).unwrap_or(&[]) as *const [u8]);
    match s.st {
        0 => {
            let (Some(off), Some(len)) = (
                carg(s, 2).and_then(parse_u64),
                carg(s, 3).and_then(parse_u64),
            ) else {
                return fail(s, b"offset and length are decimal byte counts");
            };
            s.off = off;
            s.size = off.saturating_add(len);
            s.st = 1;
            send_lookup(s, 0, root, path)
        }
        1 => {
            let Some(found) = lookup_answer(s) else {
                return;
            };
            let Some((_, kind, oid, olen, _)) = found else {
                return fail(s, b"no volume is bound there");
            };
            let Some(d) = (if kind == KIND_VOLUME {
                digest_of(&oid[..olen])
            } else {
                None
            }) else {
                return fail(s, b"the path is bound, but not to a volume");
            };
            s.fd = fs_create(s, file);
            if s.fd < 0 {
                return fail(s, b"the file cannot be created");
            }
            s.st = 2;
            send_get_body(s, 0, &d)
        }
        2 => {
            let Some(page) = body_answer(s, b"map root") else {
                return;
            };
            put(&mut s.page, page);
            s.page_len = page.len() as u32;
            match mp::decode_root(&s.page[..s.page_len as usize]) {
                Ok(r) if s.size <= r.size_bytes => {}
                Ok(_) => return fail(s, b"the window runs past the end of the volume"),
                Err(_) => return fail(s, b"the map root does not decode"),
            }
            s.leaf_len = 0;
            s.st = 3;
            vread_next(s, false)
        }
        _ => vread_next(s, answered),
    }
}

/// A body answer's bytes, or `None` with the command ended.
fn body_answer(s: &mut ModuleState, what: &[u8]) -> Option<&'static [u8]> {
    match aw::decode_admin_get_body_ack(answer(s)) {
        Ok((_, aw::STATUS_OK, Some(b))) => Some(unsafe { &*(b as *const [u8]) }),
        Ok((_, st, _)) => {
            say(s, b"error: ");
            say(s, what);
            say(s, b": ");
            say_status(s, st);
            say(s, b"\n");
            finish(s, 1);
            None
        }
        Err(_) => {
            fail(s, b"the node's answer does not decode");
            None
        }
    }
}

/// Step 3 of `volume read`: the extent under `off`, or the leaf page that
/// names it; then its bytes into the file.
unsafe fn vread_next(s: &mut ModuleState, answered: bool) {
    let Ok(root) = mp::decode_root(&*(&s.page[..s.page_len as usize] as *const [u8])) else {
        return fail(s, b"the map root does not decode");
    };
    let es = root.extent_size as u64;
    if answered {
        let Some(b) = body_answer(s, b"map page or extent") else {
            return;
        };
        if s.st == 4 {
            // A leaf page arrived.
            put(&mut s.leaf, b);
            s.leaf_len = b.len() as u32;
            s.st = 3;
        } else {
            // An extent arrived: its part of the window into the file.
            let index = divmod(s.off, es).0;
            let start = (s.off - index * es) as usize;
            let end = ((s.size - index * es).min(es)) as usize;
            if b.len() < end {
                return fail(s, b"an extent is shorter than the volume's geometry");
            }
            let fd = s.fd;
            if !fs_write_all(s, fd, &b[start..end]) {
                return fail(s, b"the file cannot be written");
            }
            s.off = index * es + end as u64;
        }
    }
    while s.off < s.size {
        let index = divmod(s.off, es).0;
        let (child, slot) = mp::locate(root.depth, index);
        let Some(cd) = root.child(child as usize) else {
            return fail(s, b"the map root names fewer children than its geometry");
        };
        let extent = if root.depth == 1 {
            cd
        } else if cd == mp::ZERO_DIGEST {
            mp::ZERO_DIGEST
        } else {
            if s.leaf_len == 0 || s.leaf_child != child {
                s.leaf_child = child;
                s.leaf_len = 0;
                s.st = 4;
                return send_get_body(s, 0, &cd);
            }
            match mp::decode_leaf(&s.leaf[..s.leaf_len as usize]) {
                Ok(l) => l.digest(slot).unwrap_or(mp::ZERO_DIGEST),
                Err(_) => return fail(s, b"a leaf page does not decode"),
            }
        };
        if extent == mp::ZERO_DIGEST {
            let start = s.off - index * es;
            let end = (s.size - index * es).min(es);
            let zero = [0u8; 4096];
            let mut left = end - start;
            let fd = s.fd;
            while left > 0 {
                let n = if left < 4096 { left as usize } else { 4096 };
                if !fs_write_all(s, fd, &zero[..n]) {
                    return fail(s, b"the file cannot be written");
                }
                left -= n as u64;
            }
            s.off = index * es + end;
            continue;
        }
        s.st = 5;
        return send_get_body(s, 0, &extent);
    }
    fs_close(s);
    say(s, b"read ");
    say_u64(s, s.size - carg(s, 2).and_then(parse_u64).unwrap_or(0));
    say(s, b" bytes\n");
    finish(s, 0);
}

// ── Manifests, a record at a time ──────────────────────────────────────────

/// Fill the manifest buffer from `fd2`.
unsafe fn mf_fill(s: &mut ModuleState) -> bool {
    if s.mf_eof != 0 {
        return true;
    }
    let at = s.mf_len as usize;
    let room = s.mf.len() - at;
    if room == 0 {
        return true;
    }
    let fd = s.fd2;
    let rc = (sys(s).provider_call)(fd, FS_READ, s.mf.as_mut_ptr().add(at), room);
    if rc < 0 {
        return false;
    }
    if rc == 0 {
        s.mf_eof = 1;
    }
    s.mf_len += rc as u32;
    true
}

fn mf_consume(s: &mut ModuleState, n: usize) {
    let have = s.mf_len as usize;
    let mut i = n;
    while i < have {
        s.mf[i - n] = s.mf[i];
        i += 1;
    }
    s.mf_len = (have - n) as u32;
}

/// Open a manifest and take its header. False with the command ended.
unsafe fn mf_open(s: &mut ModuleState, file: &[u8]) -> bool {
    let mut p = [0u8; PATH_MAX];
    put(&mut p, file);
    s.fd2 = fs_open(s, &p[..file.len().min(PATH_MAX)]);
    if s.fd2 < 0 {
        fail(s, b"the manifest cannot be opened");
        return false;
    }
    s.mf_len = 0;
    s.mf_eof = 0;
    s.mf_seen = 0;
    loop {
        if !mf_fill(s) {
            fail(s, b"the manifest cannot be read");
            return false;
        }
        match mw::read_header(&s.mf[..s.mf_len as usize]) {
            Ok(Some((root, count, n))) => {
                s.mf_count = count;
                put(&mut s.mf_root, root);
                s.mf_root_len = root.len() as u8;
                mf_consume(s, n);
                return true;
            }
            Ok(None) if s.mf_eof == 0 => continue,
            _ => {
                fail(s, b"the file is not a manifest");
                return false;
            }
        }
    }
}

/// The manifest's next record into `key`, `entry_digest`, `kind`. False
/// at the end; the command is ended if the manifest is short or corrupt.
unsafe fn mf_next(s: &mut ModuleState) -> bool {
    if s.mf_seen == s.mf_count {
        return false;
    }
    loop {
        if !mf_fill(s) {
            fail(s, b"the manifest cannot be read");
            return false;
        }
        let have: &[u8] = &*(&s.mf[..s.mf_len as usize] as *const [u8]);
        match mw::read_record(have) {
            Ok(Some((e, n))) => {
                put(&mut s.key, e.key);
                s.key_len = e.key.len() as u16;
                s.entry_digest = e.digest;
                s.kind = e.kind;
                s.entry_size = e.size;
                put(&mut s.ctype, e.content_type);
                s.ctype_len = e.content_type.len() as u8;
                mf_consume(s, n);
                s.mf_seen += 1;
                return true;
            }
            Ok(None) if s.mf_eof == 0 => continue,
            _ => {
                fail(
                    s,
                    b"the manifest ends before its declared count, or is corrupt",
                );
                return false;
            }
        }
    }
}

/// Bind the entry in hand under `root` on session `k`: a volume through
/// the volume-bind flow, anything else at revision 1.
unsafe fn bind_entry(s: &mut ModuleState, k: usize, root: &[u8]) {
    if s.kind == KIND_VOLUME {
        return vb_start(s, k, root, false, false);
    }
    let oid = oid_of(&s.entry_digest);
    let cid = next_cid(s);
    let key: &[u8] = &*(&s.key[..s.key_len as usize] as *const [u8]);
    let ctype: &[u8] = &*(&s.ctype[..s.ctype_len as usize] as *const [u8]);
    match aw::encode_admin_bind(
        &mut s.req,
        cid,
        root,
        key,
        &oid,
        s.kind,
        1,
        s.entry_size,
        ctype,
    ) {
        Ok(n) => ask(s, k, n),
        Err(_) => fail(s, b"an entry is not one the wire carries"),
    }
}

/// The status binding the last entry answered.
fn bind_status(s: &ModuleState, plain: bool) -> u8 {
    if !plain {
        return s.vb_status;
    }
    match aw::decode_admin_bind_ack(answer(s)) {
        Ok(a) => a.status,
        Err(_) => 0xFF,
    }
}

// ── snapshot create / restore / delete ─────────────────────────────────────

unsafe fn cmd_screate(s: &mut ModuleState, answered: bool) {
    let src: &[u8] = &*(carg(s, 0).unwrap_or(&[]) as *const [u8]);
    let snap: &[u8] = &*(carg(s, 1).unwrap_or(&[]) as *const [u8]);
    let file: &[u8] = &*(carg(s, 2).unwrap_or(&[]) as *const [u8]);
    match s.st {
        0 => {
            s.fd2 = fs_create(s, file);
            if s.fd2 < 0 {
                return fail(s, b"the manifest file cannot be created");
            }
            let mut h = [0u8; mw::HEADER_MAX];
            let Ok(n) = mw::encode_header(&mut h, src, 0) else {
                return fail(s, b"the root is longer than a root may be");
            };
            if !fs_write_all(s, s.fd2, &h[..n]) {
                return fail(s, b"the manifest file cannot be written");
            }
            s.count = 0;
            s.after_len = 0;
            s.st = 1;
            send_list(s, 0, src, &[])
        }
        1 => {
            if !hold_list(s) {
                return;
            }
            s.st = 2;
            screate_next(s, src, snap)
        }
        2 => {
            // The last entry's binding answered.
            let plain = s.kind != KIND_VOLUME;
            if answered || !plain {
                let st = bind_status(s, plain);
                if st != aw::STATUS_OK {
                    return fail_status(s, b"snapshot bind", st);
                }
                let mut r = [0u8; mw::RECORD_MAX];
                let e = mw::Entry {
                    key: &*(&s.key[..s.key_len as usize] as *const [u8]),
                    digest: s.entry_digest,
                    kind: s.kind,
                    size: s.entry_size,
                    content_type: &*(&s.ctype[..s.ctype_len as usize] as *const [u8]),
                };
                let Ok(n) = mw::encode_record(&mut r, &e) else {
                    return fail(s, b"an entry is not one a manifest carries");
                };
                if !fs_write_all(s, s.fd2, &r[..n]) {
                    return fail(s, b"the manifest file cannot be written");
                }
                s.count += 1;
            }
            screate_next(s, src, snap)
        }
        _ => {}
    }
}

/// The next content-addressed entry of the held page bound under the
/// snapshot root; the next page, or the end.
unsafe fn screate_next(s: &mut ModuleState, src: &[u8], snap: &[u8]) {
    while next_entry(s) {
        if s.entry_digest == [0u8; 32] {
            // Names no content: nothing a manifest could carry.
            continue;
        }
        return bind_entry(s, 0, snap);
    }
    if s.list_more != 0 {
        s.st = 1;
        return send_list(s, 0, src, &[]);
    }
    // Every entry is in: the header again, with the count.
    let mut h = [0u8; mw::HEADER_MAX];
    let n = mw::encode_header(&mut h, src, s.count as u32).unwrap_or(0);
    let fd = s.fd2;
    let zero = [0u8; 4];
    let ok = (sys(s).provider_call)(fd, FS_SEEK, zero.as_ptr() as *mut u8, 4) >= 0
        && fs_write_all(s, fd, &h[..n])
        && (sys(s).provider_call)(fd, FS_FSYNC, core::ptr::null_mut(), 0) >= 0;
    if !ok {
        return fail(s, b"the manifest file cannot be finished");
    }
    say(s, b"entries ");
    say_u64(s, s.count);
    say(s, b"\n");
    finish(s, 0);
}

unsafe fn cmd_srestore(s: &mut ModuleState, answered: bool) {
    let file: &[u8] = &*(carg(s, 0).unwrap_or(&[]) as *const [u8]);
    let dst: &[u8] = &*(carg(s, 1).unwrap_or(&[]) as *const [u8]);
    if s.st == 0 {
        if !mf_open(s, file) {
            return;
        }
        s.count = 0;
        s.st = 1;
    } else {
        let plain = s.kind != KIND_VOLUME;
        if answered || !plain {
            let st = bind_status(s, plain);
            if st != aw::STATUS_OK {
                return fail_status(s, b"restore bind", st);
            }
            s.count += 1;
        }
    }
    if mf_next(s) {
        return bind_entry(s, 0, dst);
    }
    if s.done != 0 {
        return;
    }
    say(s, b"bound ");
    say_u64(s, s.count);
    say(s, b"\n");
    finish(s, 0);
}

unsafe fn cmd_sdelete(s: &mut ModuleState, answered: bool) {
    let snap: &[u8] = &*(carg(s, 0).unwrap_or(&[]) as *const [u8]);
    match s.st {
        0 => {
            s.count = 0;
            s.after_len = 0;
            s.st = 1;
            send_list(s, 0, snap, &[])
        }
        1 => {
            if !hold_list(s) {
                return;
            }
            s.st = 2;
            sdelete_next(s, snap)
        }
        _ => {
            let plain = s.kind != KIND_VOLUME;
            if answered || !plain {
                let st = if plain {
                    match aw::decode_admin_delete_file_ack(answer(s)) {
                        Ok((_, st, _)) => st,
                        Err(_) => 0xFF,
                    }
                } else {
                    s.vb_status
                };
                if st != aw::STATUS_OK && st != aw::STATUS_NOT_FOUND {
                    return fail_status(s, b"snapshot delete", st);
                }
                if st == aw::STATUS_OK {
                    s.count += 1;
                }
            }
            sdelete_next(s, snap)
        }
    }
}

unsafe fn sdelete_next(s: &mut ModuleState, snap: &[u8]) {
    if next_entry(s) {
        if s.kind == KIND_VOLUME {
            s.vb_expected = s.revision;
            return vb_start(s, 0, snap, false, true);
        }
        let cid = next_cid(s);
        let key: &[u8] = &*(&s.key[..s.key_len as usize] as *const [u8]);
        return match aw::encode_admin_delete_file(&mut s.req, cid, snap, key, &aw::WriteCond::ANY) {
            Ok(n) => ask(s, 0, n),
            Err(_) => fail(s, b"an entry is not one the wire carries"),
        };
    }
    if s.list_more != 0 {
        s.st = 1;
        return send_list(s, 0, snap, &[]);
    }
    say(s, b"deleted ");
    say_u64(s, s.count);
    say(s, b"\n");
    finish(s, 0);
}

// ── export ─────────────────────────────────────────────────────────────────
//
// Pass one moves bodies: for each entry its body and, for a volume, every
// page and extent its root reaches — each sent only if the destination
// lacks it. A body that fits one answer moves whole; a file larger than
// that moves as a streamed file, which binds its key as it lands. Pass
// two binds. Nothing is bound before every body it needs has landed.

/// The body-move sub-flow: does the destination hold `mv_digest`? If
/// not, fetch it from the source, check it, and store it there.
const MV_ASK_DST: u8 = 1;
const MV_FETCH: u8 = 2;
const MV_STORE: u8 = 3;
// A file entry larger than one answer moves as a streamed file: opened at
// the destination under its key, read from the source by range (pinned to
// its object), written by chunks, committed. The commit binds the key at
// revision 1 with the same object the bind pass names, so that bind is the
// same write again and is answered done.
const MV_OPEN: u8 = 4;
const MV_READ: u8 = 5;
const MV_CHUNK: u8 = 6;
const MV_COMMIT: u8 = 7;

unsafe fn mv_start(s: &mut ModuleState, d: &[u8; 32]) {
    s.mv_digest = *d;
    s.mv = MV_ASK_DST;
    s.mv_large = 0;
    send_get_body(s, 1, d)
}

/// Move the body of the entry in hand.
unsafe fn mv_start_entry(s: &mut ModuleState) {
    let d = s.entry_digest;
    mv_start(s, &d);
    s.mv_large = u8::from(s.kind != KIND_VOLUME && s.entry_size > MAX_BODY as u64);
}

/// Open the destination's streamed write for the entry in hand.
unsafe fn mv_open(s: &mut ModuleState) {
    let d = s.mv_digest;
    let dst: &[u8] = &*(carg(s, 1).unwrap_or(&[]) as *const [u8]);
    let key: &[u8] = &*(&s.key[..s.key_len as usize] as *const [u8]);
    let ctype: &[u8] = &*(&s.ctype[..s.ctype_len as usize] as *const [u8]);
    let cond = aw::WriteCond {
        mode: aw::WRITE_ABSENT,
        expect: &[],
    };
    let cid = next_cid(s);
    s.off = 0;
    s.mv = MV_OPEN;
    match aw::encode_put_file_open(
        &mut s.req,
        cid,
        dst,
        key,
        s.kind,
        &cond,
        ctype,
        &d,
        s.entry_size,
    ) {
        Ok(m) => ask(s, 1, m),
        Err(_) => {
            s.mv = 0;
            fail(s, b"an entry is not one the wire carries")
        }
    }
}

/// Read the source's next range of the entry in hand.
unsafe fn mv_read(s: &mut ModuleState) {
    let left = s.entry_size - s.off;
    let n = if left < MAX_BODY as u64 {
        left as u32
    } else {
        MAX_BODY as u32
    };
    let oid = oid_of(&s.mv_digest);
    let root: &[u8] = &*(&s.mf_root[..s.mf_root_len as usize] as *const [u8]);
    let key: &[u8] = &*(&s.key[..s.key_len as usize] as *const [u8]);
    let cid = next_cid(s);
    s.mv = MV_READ;
    match aw::encode_read_file_range(&mut s.req, cid, s.off, n, root, key, &oid) {
        Ok(m) => ask(s, 0, m),
        Err(_) => {
            s.mv = 0;
            fail(s, b"a read could not be encoded")
        }
    }
}

unsafe fn mv_step(s: &mut ModuleState, _answered: bool) {
    let d = s.mv_digest;
    match s.mv {
        MV_ASK_DST => match aw::decode_admin_get_body_ack(answer(s)) {
            // Held — whole, or larger than one answer.
            Ok((_, aw::STATUS_OK | aw::STATUS_EXISTS, _)) => s.mv = 0,
            Ok((_, aw::STATUS_NOT_FOUND, _)) if s.mv_large != 0 => mv_open(s),
            Ok((_, aw::STATUS_NOT_FOUND, _)) => {
                s.mv = MV_FETCH;
                send_get_body(s, 0, &d)
            }
            Ok((_, st, _)) => {
                s.mv = 0;
                fail_status(s, b"the destination", st)
            }
            Err(_) => {
                s.mv = 0;
                fail(s, b"the destination's answer does not decode")
            }
        },
        MV_FETCH => match aw::decode_admin_get_body_ack(answer(s)) {
            Ok((_, aw::STATUS_OK, Some(b))) => {
                if super::sha256(b) != d {
                    s.mv = 0;
                    return fail(s, b"the source holds a body that does not hash to its name");
                }
                // A map page of a volume is read again from here below.
                let b: &[u8] = &*(b as *const [u8]);
                put(&mut s.buf, b);
                let n = b.len();
                s.mv = MV_STORE;
                let cid = next_cid(s);
                let body: &[u8] = &*(&s.buf[..n] as *const [u8]);
                match aw::encode_admin_put_body(&mut s.req, cid, body) {
                    Ok(m) => ask(s, 1, m),
                    Err(_) => {
                        s.mv = 0;
                        fail(s, b"a body could not be encoded")
                    }
                }
            }
            Ok((_, aw::STATUS_NOT_FOUND, _)) => {
                s.mv = 0;
                say(s, b"error: the source does not hold ");
                say_oid(s, &d);
                say(s, b", so this manifest cannot be exported whole\n");
                finish(s, 1)
            }
            Ok((_, st, _)) => {
                s.mv = 0;
                fail_status(s, b"the source", st)
            }
            Err(_) => {
                s.mv = 0;
                fail(s, b"the source's answer does not decode")
            }
        },
        MV_OPEN => match aw::decode_put_file_open_ack(answer(s)) {
            Ok((_, aw::STATUS_OK, pfid)) => {
                s.pfid = pfid;
                mv_read(s)
            }
            Ok((_, st, _)) => {
                s.mv = 0;
                fail_status(s, b"the destination", st)
            }
            Err(_) => {
                s.mv = 0;
                fail(s, b"the destination's answer does not decode")
            }
        },
        MV_READ => match aw::decode_read_file_range_ack(answer(s)) {
            Ok((_, aw::STATUS_OK, Some(bytes))) if !bytes.is_empty() => {
                let bytes: &[u8] = &*(bytes as *const [u8]);
                s.off += bytes.len() as u64;
                let cid = next_cid(s);
                let pfid = s.pfid;
                s.mv = MV_CHUNK;
                match aw::encode_put_file_chunk(&mut s.req, cid, pfid, bytes) {
                    Ok(m) => ask(s, 1, m),
                    Err(_) => {
                        s.mv = 0;
                        fail(s, b"a chunk could not be encoded")
                    }
                }
            }
            Ok((_, aw::STATUS_OK, _)) => {
                s.mv = 0;
                fail(s, b"the source's object ended before its size")
            }
            Ok((_, aw::STATUS_NOT_FOUND, _)) => {
                s.mv = 0;
                say(s, b"error: the source does not hold ");
                say_oid(s, &d);
                say(s, b", so this manifest cannot be exported whole\n");
                finish(s, 1)
            }
            Ok((_, st, _)) => {
                s.mv = 0;
                fail_status(s, b"the source", st)
            }
            Err(_) => {
                s.mv = 0;
                fail(s, b"the source's answer does not decode")
            }
        },
        MV_CHUNK => match aw::decode_put_file_chunk_ack(answer(s)) {
            Ok((_, aw::STATUS_OK)) if s.off < s.entry_size => mv_read(s),
            Ok((_, aw::STATUS_OK)) => {
                let cid = next_cid(s);
                let pfid = s.pfid;
                s.mv = MV_COMMIT;
                match aw::encode_put_file_commit(&mut s.req, cid, pfid) {
                    Ok(m) => ask(s, 1, m),
                    Err(_) => {
                        s.mv = 0;
                        fail(s, b"a commit could not be encoded")
                    }
                }
            }
            Ok((_, st)) => {
                s.mv = 0;
                fail_status(s, b"the destination", st)
            }
            Err(_) => {
                s.mv = 0;
                fail(s, b"the destination's answer does not decode")
            }
        },
        MV_COMMIT => match aw::decode_admin_put_file_ack(answer(s)) {
            Ok((_, aw::STATUS_OK, Some(g), _)) if eq(g, &d) => {
                s.sent += 1;
                s.mv = 0;
            }
            Ok((_, aw::STATUS_OK, _, _)) => {
                s.mv = 0;
                fail(
                    s,
                    b"the destination named a body differently than its content",
                )
            }
            Ok((_, st, _, _)) => {
                s.mv = 0;
                fail_status(s, b"the destination", st)
            }
            Err(_) => {
                s.mv = 0;
                fail(s, b"the destination's answer does not decode")
            }
        },
        _ => match aw::decode_admin_put_body_ack(answer(s)) {
            Ok(a) if a.status == aw::STATUS_OK && a.digest.is_some_and(|g| eq(g, &d)) => {
                s.sent += 1;
                s.mv = 0;
            }
            Ok(a) if a.status == aw::STATUS_OK => {
                s.mv = 0;
                fail(
                    s,
                    b"the destination named a body differently than its content",
                )
            }
            Ok(a) => {
                s.mv = 0;
                fail_status(s, b"the destination", a.status)
            }
            Err(_) => {
                s.mv = 0;
                fail(s, b"the destination's answer does not decode")
            }
        },
    }
}

/// Export stages.
const EX_OPEN: u8 = 0;
/// Moving an entry's own body.
const EX_ENTRY: u8 = 1;
/// Reading a volume entry's root page from the source.
const EX_ROOT: u8 = 2;
/// Walking a root's children (`child_i`).
const EX_CHILD: u8 = 3;
/// Reading a leaf page from the source.
const EX_LEAF: u8 = 4;
/// Walking a leaf's extents (`leaf_i`).
const EX_EXTENT: u8 = 5;
/// Binding at the destination.
const EX_BIND: u8 = 6;

unsafe fn cmd_export(s: &mut ModuleState, answered: bool) {
    let file: &[u8] = &*(carg(s, 0).unwrap_or(&[]) as *const [u8]);
    let dst: &[u8] = &*(carg(s, 1).unwrap_or(&[]) as *const [u8]);
    loop {
        if s.done != 0 {
            return;
        }
        match s.st {
            EX_OPEN => {
                if !mf_open(s, file) {
                    return;
                }
                s.sent = 0;
                s.count = 0;
                s.mf_pass = 1;
                if !mf_next(s) {
                    if s.done != 0 {
                        return;
                    }
                    s.st = EX_BIND;
                    continue;
                }
                s.st = EX_ENTRY;
                return mv_start_entry(s);
            }
            EX_ENTRY => {
                // The entry's body is at the destination.
                if s.kind == KIND_VOLUME {
                    s.st = EX_ROOT;
                    let d = s.entry_digest;
                    return send_get_body(s, 0, &d);
                }
                if !mf_next(s) {
                    if s.done != 0 {
                        return;
                    }
                    s.st = EX_BIND;
                    continue;
                }
                return mv_start_entry(s);
            }
            EX_ROOT => {
                if !answered {
                    return;
                }
                let Some(page) = body_answer(s, b"a volume's map root at the source") else {
                    return;
                };
                put(&mut s.page, page);
                s.page_len = page.len() as u32;
                if mp::decode_root(&s.page[..s.page_len as usize]).is_err() {
                    return fail(s, b"a volume's map root does not decode");
                }
                s.child_i = 0;
                s.leaf_len = 0;
                s.st = EX_CHILD;
                return export_child(s);
            }
            EX_CHILD => return export_child(s),
            EX_LEAF => {
                if !answered {
                    return;
                }
                let Some(page) = body_answer(s, b"a leaf page at the source") else {
                    return;
                };
                put(&mut s.leaf, page);
                s.leaf_len = page.len() as u32;
                if mp::decode_leaf(&s.leaf[..s.leaf_len as usize]).is_err() {
                    return fail(s, b"a leaf page does not decode");
                }
                s.leaf_i = 0;
                s.st = EX_EXTENT;
                return export_extent(s);
            }
            EX_EXTENT => return export_extent(s),
            _ => {
                // Pass two: bind.
                if s.mf_pass == 1 {
                    s.mf_pass = 2;
                    if s.fd2 >= 0 {
                        let fd = s.fd2;
                        let _ = (sys(s).provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
                        s.fd2 = -1;
                    }
                    if !mf_open(s, file) {
                        return;
                    }
                } else {
                    let plain = s.kind != KIND_VOLUME;
                    if answered || !plain {
                        let st = bind_status(s, plain);
                        if st != aw::STATUS_OK {
                            return fail_status(s, b"export bind", st);
                        }
                        s.count += 1;
                    }
                }
                if mf_next(s) {
                    return bind_entry(s, 1, dst);
                }
                if s.done != 0 {
                    return;
                }
                say(s, b"sent ");
                say_u64(s, s.sent);
                say(s, b"\nbound ");
                say_u64(s, s.count);
                say(s, b"\n");
                return finish(s, 0);
            }
        }
    }
}

/// The root's next child: moved, and for a depth-2 root, walked.
unsafe fn export_child(s: &mut ModuleState) {
    let Ok(root) = mp::decode_root(&*(&s.page[..s.page_len as usize] as *const [u8])) else {
        return fail(s, b"a volume's map root does not decode");
    };
    while (s.child_i as usize) < root.count() {
        let i = s.child_i as usize;
        let c = root.child(i).unwrap_or(mp::ZERO_DIGEST);
        if c == mp::ZERO_DIGEST {
            s.child_i += 1;
            continue;
        }
        if root.depth == 2 && s.st == EX_CHILD && s.leaf_len == 0 {
            // Move the leaf first, then read it here to walk its extents.
            s.leaf_len = 1;
            return mv_start(s, &c);
        }
        if root.depth == 2 {
            s.leaf_len = 0;
            s.st = EX_LEAF;
            s.child_i += 1;
            return send_get_body(s, 0, &c);
        }
        s.child_i += 1;
        return mv_start(s, &c);
    }
    // Every child is across: the next entry.
    s.leaf_len = 0;
    if !mf_next(s) {
        if s.done != 0 {
            return;
        }
        s.st = EX_BIND;
        return cmd_export(s, false);
    }
    s.st = EX_ENTRY;
    let d = s.entry_digest;
    mv_start(s, &d)
}

/// The leaf's next extent moved; then back to the root's children.
unsafe fn export_extent(s: &mut ModuleState) {
    let Ok(leaf) = mp::decode_leaf(&*(&s.leaf[..s.leaf_len as usize] as *const [u8])) else {
        return fail(s, b"a leaf page does not decode");
    };
    while (s.leaf_i as usize) < leaf.count() {
        let d = leaf.digest(s.leaf_i as usize).unwrap_or(mp::ZERO_DIGEST);
        s.leaf_i += 1;
        if d != mp::ZERO_DIGEST {
            return mv_start(s, &d);
        }
    }
    s.leaf_len = 0;
    s.st = EX_CHILD;
    export_child(s)
}
