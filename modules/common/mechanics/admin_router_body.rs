// Step body for the `admin_router` PIC. Translates admin
// requests (loam_admin_wire) into the downstream PICs' native
// channel formats, then routes the responses back to the admin
// reply channel with the original correlation_id attached.
//
// Op routing:
//   AdminBind     → namespace_router (1-byte ack/nak)
//   AdminPutBody  → body_store        (PutResp / NAK)
//   AdminGetBody  → body_store        (GetResp / NAK)
//   AdminPutFile  → 3-stage composed (body PUT → object PUT → ns BIND)
//
// Each downstream channel has its own pending FIFO. The
// downstream PIC writes responses in the order it consumes
// requests, so head-of-FIFO is the next expected response.
//
// PutFile state machine: each in-flight composed op holds a
// `PendingPutFile` entry that records which stage is active. The
// downstream response handler advances the state and emits the
// next downstream request (or the final ack).

// Module builds compile edition-2015 (direct rustc); TryInto is
// not in that prelude.
use core::convert::TryInto;

// Buffers derive from the body wire cap so a max-size body can't
// truncate on the way through the admin surface.
const READ_BUF: usize = super::body_wire::MAX_BODY + 128;
const SCRATCH: usize = super::body_wire::MAX_BODY + 128;
/// Reassembly capacity for `ns_responses`. Sized to hold a full step's
/// budget of the largest response plus one more read, so refilling
/// never starves the step.
const NS_ASM: usize = 4096 * (super::limits::OPS_PER_STEP as usize + 1);
/// Inline key buffers for the composed PUT_FILE state machine.
/// Derived from the key ceilings, NOT chosen independently: a
/// second, smaller ceiling here would refuse (or worse, truncate) a
/// key the namespace surface accepted, which is the same
/// accepted-but-unusable failure the ceilings exist to prevent.
const NS_PATH_BUF: usize = super::limits::MAX_PATH;
const NS_ROOT_BUF: usize = super::limits::MAX_ROOT;

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct PendingDownstream {
    pub in_use: u8,
    pub correlation_id: u32,
    /// Original admin opcode (OP_BIND / OP_PUT_BODY / OP_GET_BODY /
    /// OP_PUT_FILE).
    pub admin_op: u8,
    /// PutFile entry index when admin_op == OP_PUT_FILE; ignored
    /// otherwise. Lets the downstream response handler resume the
    /// composed state machine without scanning the PutFile table.
    pub putfile_idx: u16,
    /// READ_FILE_RANGE: the requested (off, len), carried from the
    /// lookup stage to the body range dispatch.
    pub aux_off: u64,
    pub aux_len: u32,
}

/// A streamed put-file between OPEN and COMMIT.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct StreamedPutFile {
    pub in_use: u8,
    /// Downstream body-plane stream id (valid once wid_valid = 1).
    pub wid: u8,
    pub wid_valid: u8,
    pub kind: u8,
    pub revision: u64,
    pub total_len: u64,
    pub digest: [u8; 32],
    pub ns_root: [u8; NS_ROOT_BUF],
    pub ns_root_len: u8,
    pub path: [u8; NS_PATH_BUF],
    pub path_len: u8,
}

pub const PUTFILE_STAGE_BODY: u8 = 0;
pub const PUTFILE_STAGE_OBJECT: u8 = 1;
pub const PUTFILE_STAGE_BIND: u8 = 2;
pub const PUTFILE_STAGE_DONE: u8 = 3;

/// Per-in-flight PutFile state. The body stage runs first; on its
/// PutResp the digest is stashed here and the object stage emits.
/// On the object ack the bind stage emits. On the bind ack the
/// final AdminPutFileAck goes to the client.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct PendingPutFile {
    pub in_use: u8,
    pub stage: u8,
    pub correlation_id: u32,
    pub kind: u8,
    pub digest: [u8; 32],
    pub body_len: u32,
    pub revision: u64,
    pub ns_root: [u8; NS_ROOT_BUF],
    pub ns_root_len: u8,
    pub path: [u8; NS_PATH_BUF],
    pub path_len: u8,
}

#[repr(C)]
pub struct ModuleState {
    pub syscalls: *const super::SyscallTable,
    /// admin_in (incoming AdminBind/etc. requests from client).
    pub admin_in_chan: i32,
    /// admin_out (outgoing AdminBindAck/etc. responses to client).
    pub admin_out_chan: i32,
    /// ns_req (forwarded namespace events to namespace_router).
    pub ns_req_chan: i32,
    /// ns_resp (1-byte acks from namespace_router).
    pub ns_resp_chan: i32,
    /// body_req (forwarded body ops to body_store; -1 if unwired).
    pub body_req_chan: i32,
    /// body_resp (responses from body_store; -1 if unwired).
    pub body_resp_chan: i32,
    /// obj_req (forwarded object descriptor puts to object_index; -1 if unwired).
    pub obj_req_chan: i32,
    /// obj_resp (1-byte acks from object_index; -1 if unwired).
    pub obj_resp_chan: i32,
    pub scratch: [u8; SCRATCH],
    /// The admin response owed on `admin_out`, held in `scratch`.
    /// `resp_len` is its length and `resp_sent` how much the channel
    /// has taken; both zero means nothing is owed.
    ///
    /// Every response is staged here rather than in a second buffer:
    /// an admin response carries body bytes and runs to `SCRATCH`, so
    /// a copy would double the largest allocation in the router. The
    /// discipline matches the arena PICs — an answer the channel
    /// refuses is retained, and no new request or downstream response
    /// is taken while one is owed, because both would overwrite it.
    pub resp_len: u32,
    pub resp_sent: u32,
    /// Reassembly for the `ns_responses` byte stream. A downstream PIC
    /// that answers several records before this router drains has its
    /// answers coalesce into one read, and a read can end mid-record;
    /// both are the stream behaving normally.
    pub ns_asm: [u8; NS_ASM],
    pub ns_asm_len: usize,
    // Per-downstream pending FIFOs (head, tail, ring storage).
    pub ns_head: u32,
    pub ns_tail: u32,
    pub ns_pending: [PendingDownstream; super::limits::ADMIN_PENDING],
    pub body_head: u32,
    pub body_tail: u32,
    pub body_pending: [PendingDownstream; super::limits::ADMIN_PENDING],
    pub obj_head: u32,
    pub obj_tail: u32,
    pub obj_pending: [PendingDownstream; super::limits::ADMIN_PENDING],
    pub putfiles: [PendingPutFile; super::limits::ADMIN_PUTFILE],
    /// In-flight STREAMED put-files (large bodies): open → chunks →
    /// commit, then the commit chains into the standard object +
    /// bind stages via a PendingPutFile slot.
    pub spf: [StreamedPutFile; super::limits::ADMIN_STREAMED_PUTFILE],
    /// Lifecycle GC (active when `gc_interval` != 0). Alternating
    /// sweeps over the two things a composed PUT_FILE leaves behind:
    /// body blobs and object descriptors. Each interval takes one
    /// bounded inventory page — body_store's digests, or
    /// object_index's content-derived descriptor ids — and for each
    /// entry reserves the id at the namespace, asks whether it is
    /// bound anywhere (OP_REFERENCED), and deletes what backs it only
    /// while the reservation still stands. Never runs while a PutFile
    /// is in flight: the window between a body landing and its bind
    /// committing must not be collectable. Raw PutBody users must bind
    /// before the next GC pass or their blob is fair game.
    pub gc_interval: u32,
    pub gc_cursor: u32,
    /// Which inventory the current pass is walking: `GC_PHASE_BODY` or
    /// `GC_PHASE_OBJECT`.
    pub gc_phase: u8,
    /// Descriptor-inventory paging cursor, separate from the body one.
    pub gc_obj_cursor: u32,
    /// The current entry holds a namespace deletion reservation.
    pub gc_reserved: u8,
    /// The current page wrapped its inventory, so the phase alternates
    /// once the page's entries are done. Flipping at scan time instead
    /// would change what the page's own entries are allowed to delete.
    pub gc_wrapped: u8,
    /// Descriptors deleted by the sweep.
    pub gc_obj_deleted: u32,
    pub gc_inflight: u8,
    pub gc_digests: [[u8; 32]; super::body_wire::MAX_SCAN_DIGESTS],
    pub gc_q_len: u8,
    pub gc_q_pos: u8,
    /// Snapshot-scan continuation cursor for the current digest's
    /// REFERENCED check.
    pub gc_check_cursor: u32,
    pub gc_scans: u32,
    pub gc_checked: u32,
    pub gc_deleted: u32,
    pub gc_kept: u32,
    /// The volume-map walk for the current entry. A body no binding
    /// names may still be an extent or a map page of a bound volume
    /// root, so before deleting it the sweep walks every volume root
    /// the namespace reports — root page, then each leaf — looking for
    /// the digest. One downstream read at a time, so per-step work is
    /// one page. `gc_walk_view` is the namespace snapshot generation
    /// the first roots page reported; a later page reporting another
    /// crossed a compaction and the entry is kept.
    pub gc_walk_view: u64,
    pub gc_walk_view_set: u8,
    /// Cursor of the next roots page, 0 once the current page is the
    /// last.
    pub gc_walk_next: u32,
    pub gc_roots: [[u8; 32]; super::ns_wire::MAX_VOLUME_ROOTS],
    pub gc_roots_len: u8,
    pub gc_roots_pos: u8,
    /// The current depth-2 root's leaf digests.
    pub gc_leaves: [[u8; 32]; super::map_wire::PAGE_ENTRIES],
    pub gc_leaves_len: u16,
    pub gc_leaves_pos: u16,
    /// Map pages the walk has read.
    pub gc_map_reads: u32,
    pub ticks: u32,
    pub forwarded: u32,
    /// Answers the channel has ACCEPTED, counted where they land
    /// rather than where they are built. A response staged and then
    /// refused is not an answer the requester received, and counting
    /// it as one is what would make the conservation claim — every
    /// request answered exactly once — true by arithmetic instead of
    /// by behaviour.
    pub replied: u32,
    pub apply_errors: u32,
    /// The `now` stamped on the last lease request. Stamps are strictly
    /// increasing: the namespace treats a lease record stamped no later
    /// than the one before it as a redelivered duplicate, so two
    /// requests inside one clock tick, or across a clock stepped back,
    /// must still read as later.
    pub lease_stamp: u64,
}

/// Internal pending-op markers for the GC's downstream requests —
/// outside the admin opcode space so drains can demux them.
const GC_OP_SCAN: u8 = 0xF0;
const GC_OP_CHECK: u8 = 0xF1;
const GC_OP_DELETE: u8 = 0xF2;
const GC_OP_OBJ_SCAN: u8 = 0xF3;
const GC_OP_RESERVE: u8 = 0xF4;
const GC_OP_OBJ_REMOVE: u8 = 0xF5;
const GC_OP_RELEASE: u8 = 0xF6;
const GC_OP_ROOTS: u8 = 0xF7;
const GC_OP_MAP_ROOT: u8 = 0xF8;
const GC_OP_MAP_LEAF: u8 = 0xF9;

/// Which inventory a GC pass is walking.
pub const GC_PHASE_BODY: u8 = 0;
pub const GC_PHASE_OBJECT: u8 = 1;

/// Host/test helper + server config: enable the orphan GC.
pub unsafe fn set_gc_interval(state_ptr: *mut u8, interval: u32) {
    let s = &mut *(state_ptr as *mut ModuleState);
    s.gc_interval = interval;
}

/// Namespace-only constructor: wires the admin pair and the
/// namespace pair, leaving the body and object pairs unbound. Enough
/// for `AdminBind`; any op that needs bytes NAKs without a body
/// channel.
pub unsafe fn module_new_impl(
    admin_in_chan: i32,
    admin_out_chan: i32,
    ns_req_chan: i32,
    ns_resp_chan: i32,
    state_ptr: *mut u8,
    state_size: usize,
    syscalls: *const super::SyscallTable,
) -> i32 {
    init_state(
        admin_in_chan,
        admin_out_chan,
        ns_req_chan,
        ns_resp_chan,
        -1,
        -1,
        -1,
        -1,
        state_ptr,
        state_size,
        syscalls,
    )
}

/// Namespace + body constructor: wires everything except the object
/// pair. Enough for `AdminBind` and the direct body ops; the
/// composed `AdminPutFile` needs the object channels too.
pub unsafe fn module_new_full_impl(
    admin_in_chan: i32,
    admin_out_chan: i32,
    ns_req_chan: i32,
    ns_resp_chan: i32,
    body_req_chan: i32,
    body_resp_chan: i32,
    state_ptr: *mut u8,
    state_size: usize,
    syscalls: *const super::SyscallTable,
) -> i32 {
    init_state(
        admin_in_chan,
        admin_out_chan,
        ns_req_chan,
        ns_resp_chan,
        body_req_chan,
        body_resp_chan,
        -1,
        -1,
        state_ptr,
        state_size,
        syscalls,
    )
}

/// Full constructor: all three downstream PIC channel pairs wired
/// (namespace, body_store, object_index). Required for the composed
/// `AdminPutFile` op, which touches all three in sequence.
pub unsafe fn module_new_with_objects_impl(
    admin_in_chan: i32,
    admin_out_chan: i32,
    ns_req_chan: i32,
    ns_resp_chan: i32,
    body_req_chan: i32,
    body_resp_chan: i32,
    obj_req_chan: i32,
    obj_resp_chan: i32,
    state_ptr: *mut u8,
    state_size: usize,
    syscalls: *const super::SyscallTable,
) -> i32 {
    init_state(
        admin_in_chan,
        admin_out_chan,
        ns_req_chan,
        ns_resp_chan,
        body_req_chan,
        body_resp_chan,
        obj_req_chan,
        obj_resp_chan,
        state_ptr,
        state_size,
        syscalls,
    )
}

unsafe fn init_state(
    admin_in_chan: i32,
    admin_out_chan: i32,
    ns_req_chan: i32,
    ns_resp_chan: i32,
    body_req_chan: i32,
    body_resp_chan: i32,
    obj_req_chan: i32,
    obj_resp_chan: i32,
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
    core::ptr::write_bytes(state_ptr, 0u8, state_size);
    let s = &mut *(state_ptr as *mut ModuleState);
    s.syscalls = syscalls;
    s.admin_in_chan = admin_in_chan;
    s.admin_out_chan = admin_out_chan;
    s.ns_req_chan = ns_req_chan;
    s.ns_resp_chan = ns_resp_chan;
    s.body_req_chan = body_req_chan;
    s.body_resp_chan = body_resp_chan;
    s.obj_req_chan = obj_req_chan;
    s.obj_resp_chan = obj_resp_chan;
    0
}

#[derive(Clone, Copy)]
enum Stream {
    Namespace,
    Body,
    Object,
}

unsafe fn enqueue_pending(
    s: &mut ModuleState,
    stream: Stream,
    correlation_id: u32,
    admin_op: u8,
    putfile_idx: u16,
) -> bool {
    let (head, tail, ring) = match stream {
        Stream::Namespace => (&mut s.ns_head, &mut s.ns_tail, &mut s.ns_pending),
        Stream::Body => (&mut s.body_head, &mut s.body_tail, &mut s.body_pending),
        Stream::Object => (&mut s.obj_head, &mut s.obj_tail, &mut s.obj_pending),
    };
    let next = (tail.wrapping_add(1)) % super::limits::ADMIN_PENDING as u32;
    if next == *head {
        return false;
    }
    ring[*tail as usize] = PendingDownstream {
        in_use: 1,
        correlation_id,
        admin_op,
        putfile_idx,
        aux_off: 0,
        aux_len: 0,
    };
    *tail = next;
    true
}

unsafe fn dequeue_pending(s: &mut ModuleState, stream: Stream) -> Option<PendingDownstream> {
    let (head, tail, ring) = match stream {
        Stream::Namespace => (&mut s.ns_head, &mut s.ns_tail, &mut s.ns_pending),
        Stream::Body => (&mut s.body_head, &mut s.body_tail, &mut s.body_pending),
        Stream::Object => (&mut s.obj_head, &mut s.obj_tail, &mut s.obj_pending),
    };
    if *head == *tail {
        return None;
    }
    let entry = ring[*head as usize];
    ring[*head as usize].in_use = 0;
    *head = (head.wrapping_add(1)) % super::limits::ADMIN_PENDING as u32;
    Some(entry)
}

unsafe fn allocate_putfile_slot(s: &mut ModuleState) -> Option<u16> {
    for (i, slot) in s.putfiles.iter_mut().enumerate() {
        if slot.in_use == 0 {
            slot.in_use = 1;
            return Some(i as u16);
        }
    }
    None
}

unsafe fn free_putfile_slot(s: &mut ModuleState, idx: u16) {
    let i = idx as usize;
    if i < s.putfiles.len() {
        s.putfiles[i].in_use = 0;
        s.putfiles[i].stage = PUTFILE_STAGE_DONE;
    }
}

/// Take ownership of the response now in `scratch` and offer it.
unsafe fn reply_staged(s: &mut ModuleState, syscalls: &super::SyscallTable, n: usize) {
    if n == 0 || n > s.scratch.len() {
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    s.resp_len = n as u32;
    s.resp_sent = 0;
    let _ = flush_reply(s, syscalls);
}

/// Stage a response built outside `scratch`, then offer it.
unsafe fn reply_bytes(s: &mut ModuleState, syscalls: &super::SyscallTable, bytes: &[u8]) {
    if bytes.is_empty() || bytes.len() > s.scratch.len() {
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    s.scratch[..bytes.len()].copy_from_slice(bytes);
    reply_staged(s, syscalls, bytes.len());
}

/// Offer the owed response. True once every byte has been accepted,
/// and when nothing is owed, so a caller can gate on it directly.
unsafe fn flush_reply(s: &mut ModuleState, syscalls: &super::SyscallTable) -> bool {
    if s.resp_len == 0 {
        return true;
    }
    if s.admin_out_chan < 0 {
        return false;
    }
    let at = s.resp_sent as usize;
    let rc = (syscalls.channel_write)(
        s.admin_out_chan,
        s.scratch.as_ptr().add(at),
        s.resp_len as usize - at,
    );
    if rc <= 0 {
        return false;
    }
    s.resp_sent = (s.resp_sent + rc as u32).min(s.resp_len);
    if s.resp_sent < s.resp_len {
        return false;
    }
    s.resp_len = 0;
    s.resp_sent = 0;
    s.replied = s.replied.wrapping_add(1);
    true
}

pub unsafe fn module_step_impl(state_ptr: *mut u8) -> i32 {
    if state_ptr.is_null() {
        return -1;
    }
    let s = &mut *(state_ptr as *mut ModuleState);
    s.ticks = s.ticks.wrapping_add(1);

    let syscalls = match s.syscalls.as_ref() {
        Some(t) => t,
        None => return -1,
    };

    // An owed answer owns the step until the channel takes it. It
    // lives in `scratch`, which the next request or downstream
    // response would overwrite.
    if !flush_reply(s, syscalls) {
        return 0;
    }

    // ── 0. Orphan GC: kick one inventory SCAN when due, idle,
    //      and no composed write is mid-flight. ──
    if s.gc_interval != 0
        && s.body_req_chan >= 0
        && s.gc_inflight == 0
        && s.gc_q_len == 0
        && s.ticks % s.gc_interval == 0
        && s.putfiles.iter().all(|p| p.in_use == 0)
    {
        gc_kick(s, syscalls);
    }

    // ── 1. Drain inbound admin requests, forward downstream. ──
    let mut handled: u32 = 0;
    while handled < super::limits::OPS_PER_STEP {
        // An answer still owed means `admin_out` is not draining, and
        // `scratch` holds it — the next request would overwrite it.
        if s.resp_len != 0 {
            break;
        }
        let mut buf = [0u8; READ_BUF];
        let n = (syscalls.channel_read)(s.admin_in_chan, buf.as_mut_ptr(), READ_BUF);
        if n <= 0 {
            break;
        }
        let bytes = &buf[..n as usize];
        let op = match super::admin::peek_opcode(bytes) {
            Some(op) => op,
            None => {
                s.apply_errors = s.apply_errors.wrapping_add(1);
                handled = handled.wrapping_add(1);
                continue;
            }
        };
        match op {
            super::admin::OP_BIND => handle_admin_bind(s, syscalls, bytes),
            super::admin::OP_PUT_BODY => handle_admin_put_body(s, syscalls, bytes),
            super::admin::OP_GET_BODY => handle_admin_get_body(s, syscalls, bytes),
            super::admin::OP_PUT_BODY_KEYED => handle_admin_put_body_keyed(s, syscalls, bytes),
            super::admin::OP_DELETE_BODY => handle_admin_delete_body(s, syscalls, bytes),
            super::admin::OP_PUT_FILE => handle_admin_put_file(s, syscalls, bytes),
            super::admin::OP_GET_FILE => handle_admin_get_file(s, syscalls, bytes),
            super::admin::OP_DELETE_FILE => handle_admin_delete_file(s, syscalls, bytes),
            super::admin::OP_LIST_FILES => handle_admin_list_files(s, syscalls, bytes),
            super::admin::OP_PUT_FILE_OPEN => handle_put_file_open(s, syscalls, bytes),
            super::admin::OP_PUT_FILE_CHUNK => handle_put_file_chunk(s, syscalls, bytes),
            super::admin::OP_PUT_FILE_COMMIT => handle_put_file_commit(s, syscalls, bytes),
            super::admin::OP_READ_FILE_RANGE => handle_read_file_range(s, syscalls, bytes),
            super::admin::OP_STAT_FILE => handle_stat_file(s, syscalls, bytes),
            super::admin::OP_LEASE => handle_admin_lease(s, syscalls, bytes),
            super::admin::OP_VOLUME => handle_admin_volume(s, syscalls, bytes),
            super::admin::OP_LOOKUP => handle_admin_lookup(s, syscalls, bytes),
            _ => {
                s.apply_errors = s.apply_errors.wrapping_add(1);
            }
        }
        handled = handled.wrapping_add(1);
    }

    // ── 2. Drain downstream namespace_router responses. What a
    //      response IS depends on the pending admin op: BIND and
    //      PutFile's bind stage get 1-byte acks, GetFile's lookup
    //      stage gets a multi-byte LookupResp, DeleteFile's unbind
    //      gets a 1-byte ack. Head-of-FIFO tells us which.
    if s.ns_resp_chan >= 0 {
        // Refill first, then take whole records off the front. One read
        // is not one response.
        loop {
            let space = NS_ASM.saturating_sub(s.ns_asm_len);
            if space < 4096 {
                break;
            }
            let n = (syscalls.channel_read)(
                s.ns_resp_chan,
                s.ns_asm.as_mut_ptr().add(s.ns_asm_len),
                4096,
            );
            if n <= 0 {
                break;
            }
            s.ns_asm_len = (s.ns_asm_len + (n as usize).min(space)).min(NS_ASM);
        }
        let mut drained: u32 = 0;
        let mut ns_off: usize = 0;
        while drained < super::limits::OPS_PER_STEP {
            // Same buffer, same rule: a downstream response would
            // overwrite the answer still owed upstream.
            if s.resp_len != 0 {
                break;
            }
            let rec_len = match super::ns_wire::response_record_len(&s.ns_asm[ns_off..s.ns_asm_len])
            {
                Ok(Some(len)) => len,
                // Nothing, or an incomplete tail: keep it and wait.
                Ok(_) => break,
                Err(_) => {
                    // An undecodable response byte desyncs the stream;
                    // there is no framing to resynchronise against, so
                    // drop what is buffered rather than mis-attribute
                    // every answer after it.
                    s.apply_errors = s.apply_errors.wrapping_add(1);
                    s.ns_asm_len = 0;
                    ns_off = 0;
                    break;
                }
            };
            let ns_resp = &*(&s.ns_asm[ns_off..ns_off + rec_len] as *const [u8]);
            ns_off += rec_len;
            let entry = match dequeue_pending(s, Stream::Namespace) {
                Some(e) => e,
                None => {
                    s.apply_errors = s.apply_errors.wrapping_add(1);
                    drained = drained.wrapping_add(1);
                    continue;
                }
            };
            match entry.admin_op {
                super::admin::OP_GET_FILE => {
                    handle_getfile_lookup_response(s, syscalls, entry, ns_resp);
                }
                super::admin::OP_LIST_FILES => {
                    handle_listfiles_response(s, syscalls, entry, ns_resp);
                }
                super::admin::OP_STAT_FILE | super::admin::OP_READ_FILE_RANGE => {
                    handle_pathread_lookup_response(s, syscalls, entry, ns_resp);
                }
                GC_OP_CHECK => {
                    gc_apply_check(s, syscalls, ns_resp);
                }
                GC_OP_RESERVE => {
                    gc_apply_reserve(s, syscalls, ns_resp);
                }
                GC_OP_RELEASE => {
                    gc_next(s, syscalls);
                }
                super::admin::OP_LEASE => {
                    handle_lease_response(s, syscalls, entry, ns_resp);
                }
                super::admin::OP_VOLUME => {
                    handle_volume_response(s, syscalls, entry, ns_resp);
                }
                super::admin::OP_LOOKUP => {
                    handle_lookup_response(s, syscalls, entry, ns_resp);
                }
                GC_OP_ROOTS => {
                    gc_apply_roots(s, syscalls, ns_resp);
                }
                super::admin::OP_DELETE_FILE => {
                    let status = if ns_resp[0] == super::ns_wire::OP_UNBIND {
                        super::admin::STATUS_OK
                    } else if ns_resp[0] == super::ns_wire::NAK_FENCED {
                        // A volume: bound, and not this op's to remove.
                        super::admin::STATUS_NAK
                    } else {
                        super::admin::STATUS_NOT_FOUND
                    };
                    if let Ok(resp_n) = super::admin::encode_admin_delete_file_ack(
                        &mut s.scratch,
                        entry.correlation_id,
                        status,
                    ) {
                        reply_staged(s, syscalls, resp_n);
                    }
                }
                super::admin::OP_PUT_FILE => {
                    let status = if ns_resp[0] == super::ns_wire::OP_BIND {
                        super::admin::STATUS_OK
                    } else {
                        super::admin::STATUS_NAK
                    };
                    // PutFile's BIND stage just completed. Emit the
                    // composed AdminPutFileAck (status + digest).
                    handle_putfile_bind_response(s, syscalls, entry, status);
                }
                _ => {
                    let status = if ns_resp[0] == super::ns_wire::OP_BIND {
                        super::admin::STATUS_OK
                    } else {
                        super::admin::STATUS_NAK
                    };
                    let resp_n = match super::admin::encode_admin_bind_ack(
                        &mut s.scratch,
                        entry.correlation_id,
                        status,
                    ) {
                        Ok(n) => n,
                        Err(_) => {
                            s.apply_errors = s.apply_errors.wrapping_add(1);
                            drained = drained.wrapping_add(1);
                            continue;
                        }
                    };
                    reply_staged(s, syscalls, resp_n);
                }
            }
            drained = drained.wrapping_add(1);
        }
        // Keep whatever the step budget did not reach. Records left
        // here are pending work, not discarded work.
        if ns_off > 0 {
            let remaining = s.ns_asm_len - ns_off;
            let mut i = 0usize;
            while i < remaining {
                s.ns_asm[i] = s.ns_asm[ns_off + i];
                i += 1;
            }
            s.ns_asm_len = remaining;
        }
    }

    // ── 3. Drain downstream body_store responses, emit replies. ──
    if s.body_resp_chan >= 0 {
        let mut drained: u32 = 0;
        while drained < super::limits::OPS_PER_STEP {
            // Same buffer, same rule: a downstream response would
            // overwrite the answer still owed upstream.
            if s.resp_len != 0 {
                break;
            }
            let mut resp_buf = [0u8; READ_BUF];
            let n =
                (syscalls.channel_read)(s.body_resp_chan, resp_buf.as_mut_ptr(), resp_buf.len());
            if n <= 0 {
                break;
            }
            let body_resp = &resp_buf[..n as usize];
            let entry = match dequeue_pending(s, Stream::Body) {
                Some(e) => e,
                None => {
                    s.apply_errors = s.apply_errors.wrapping_add(1);
                    drained = drained.wrapping_add(1);
                    continue;
                }
            };
            match entry.admin_op {
                super::admin::OP_PUT_FILE => {
                    handle_putfile_body_response(s, syscalls, entry, body_resp);
                }
                super::admin::OP_PUT_FILE_OPEN => {
                    handle_spf_open_response(s, syscalls, entry, body_resp);
                }
                super::admin::OP_PUT_FILE_CHUNK => {
                    let status = if body_resp.first() == Some(&super::body_wire::OP_WAPPEND) {
                        super::admin::STATUS_OK
                    } else {
                        super::admin::STATUS_NAK
                    };
                    if let Ok(n) = super::admin::encode_put_file_chunk_ack(
                        &mut s.scratch,
                        entry.correlation_id,
                        status,
                    ) {
                        reply_staged(s, syscalls, n);
                    }
                    if status != super::admin::STATUS_OK {
                        free_spf(s, entry.putfile_idx);
                    }
                }
                super::admin::OP_PUT_FILE_COMMIT => {
                    handle_spf_commit_response(s, syscalls, entry, body_resp);
                }
                super::admin::OP_STAT_FILE => {
                    let (status, size) = if body_resp.first() == Some(&super::body_wire::OP_HEAD) {
                        match super::body_wire::decode_head_resp(body_resp) {
                            Ok(sz) => (super::admin::STATUS_OK, sz),
                            Err(_) => (super::admin::STATUS_NAK, 0),
                        }
                    } else if body_resp.len() >= 2
                        && body_resp[0] == super::body_wire::OP_NAK
                        && body_resp[1] == super::body_wire::ERR_NOT_FOUND
                    {
                        (super::admin::STATUS_NOT_FOUND, 0)
                    } else {
                        (super::admin::STATUS_NAK, 0)
                    };
                    if let Ok(n) = super::admin::encode_stat_file_ack(
                        &mut s.scratch,
                        entry.correlation_id,
                        status,
                        size,
                    ) {
                        reply_staged(s, syscalls, n);
                    }
                }
                super::admin::OP_READ_FILE_RANGE => {
                    handle_range_body_response(s, syscalls, entry, body_resp);
                }
                GC_OP_SCAN => gc_apply_scan(s, syscalls, body_resp),
                GC_OP_DELETE => gc_apply_delete(s, syscalls, body_resp),
                GC_OP_MAP_ROOT => gc_apply_map_root(s, syscalls, body_resp),
                GC_OP_MAP_LEAF => gc_apply_map_leaf(s, syscalls, body_resp),
                _ => emit_body_admin_response(s, syscalls, entry, body_resp),
            }
            drained = drained.wrapping_add(1);
        }
    }

    // ── 4. Drain downstream object_index acks, advance PutFile state. ──
    if s.obj_resp_chan >= 0 {
        let mut drained: u32 = 0;
        while drained < super::limits::OPS_PER_STEP {
            // Same buffer, same rule: a downstream response would
            // overwrite the answer still owed upstream.
            if s.resp_len != 0 {
                break;
            }
            // Sized for a descriptor inventory page, not just the
            // 1-byte apply ack.
            let mut ack_buf = [0u8; 8 + super::obj_wire::MAX_OBJ_SCAN * 32];
            let n = (syscalls.channel_read)(s.obj_resp_chan, ack_buf.as_mut_ptr(), ack_buf.len());
            if n <= 0 {
                break;
            }
            let obj_resp = &ack_buf[..n as usize];
            let ack_byte = ack_buf[0];
            let entry = match dequeue_pending(s, Stream::Object) {
                Some(e) => e,
                None => {
                    s.apply_errors = s.apply_errors.wrapping_add(1);
                    drained = drained.wrapping_add(1);
                    continue;
                }
            };
            match entry.admin_op {
                GC_OP_OBJ_SCAN => gc_apply_obj_scan(s, syscalls, obj_resp),
                GC_OP_OBJ_REMOVE => gc_apply_obj_remove(s, syscalls, ack_byte),
                _ => handle_putfile_object_response(s, syscalls, entry, ack_byte),
            }
            drained = drained.wrapping_add(1);
        }
    }

    // ── 5. Drain NS acks that belong to a PutFile (final BIND stage).
    //      The Phase-4a drain at step 2 already handled OP_BIND
    //      entries; PutFile entries on the NS channel are also
    //      OP_BIND but with admin_op=OP_PUT_FILE. They were
    //      dispatched in step 2 already; this block exists for
    //      readability — no extra work here.

    0
}

unsafe fn handle_admin_bind(s: &mut ModuleState, syscalls: &super::SyscallTable, bytes: &[u8]) {
    let req = match super::admin::decode_admin_bind(bytes) {
        Ok(r) => r,
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return;
        }
    };
    let n = match super::ns_wire::encode_bind(
        &mut s.scratch,
        req.namespace_root,
        req.path,
        req.object_id,
        req.kind,
        req.revision,
    ) {
        Ok(n) => n,
        Err(_) => {
            emit_bind_nak(s, syscalls, req.correlation_id);
            return;
        }
    };
    if !enqueue_pending(
        s,
        Stream::Namespace,
        req.correlation_id,
        super::admin::OP_BIND,
        u16::MAX,
    ) {
        emit_bind_nak(s, syscalls, req.correlation_id);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    let wrote = (syscalls.channel_write)(s.ns_req_chan, s.scratch.as_ptr(), n);
    if wrote < 0 || (wrote as usize) != n {
        let _ = dequeue_pending(s, Stream::Namespace);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    s.forwarded = s.forwarded.wrapping_add(1);
}

/// `TIMER::UNIX_MILLIS`: wall-clock milliseconds, 0 when the platform
/// has none.
const TIMER_UNIX_MILLIS: u32 = 0x0608;

/// This server's wall clock as a record stamp, strictly later than the
/// last one issued; 0 when there is no wall clock.
unsafe fn stamp_now(s: &mut ModuleState, syscalls: &super::SyscallTable) -> u64 {
    let mut clock = [0u8; 8];
    let rc = (syscalls.provider_call)(-1, TIMER_UNIX_MILLIS, clock.as_mut_ptr(), clock.len());
    let wall = if rc < 0 { 0 } else { u64::from_le_bytes(clock) };
    if wall == 0 {
        return 0;
    }
    let now = wall.max(s.lease_stamp.saturating_add(1));
    s.lease_stamp = now;
    now
}

/// Forward a lease request to the namespace, stamped with this
/// server's wall clock.
///
/// The stamp is taken here and nowhere else. The namespace judges
/// expiry against the `now` in the record so that every replica and
/// every replay agrees; that makes the stamp authoritative, so it
/// cannot come from the client.
unsafe fn handle_admin_lease(s: &mut ModuleState, syscalls: &super::SyscallTable, bytes: &[u8]) {
    let req = match super::admin::decode_admin_lease(bytes) {
        Ok(r) => r,
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return;
        }
    };
    let now = stamp_now(s, syscalls);
    if now == 0 {
        // No wall clock: a lease granted now could never be judged
        // expired, so none is granted.
        emit_lease_status(s, syscalls, req.correlation_id, super::admin::STATUS_NAK);
        return;
    }
    let n = match super::ns_wire::encode_lease_req(
        &mut s.scratch,
        req.mode,
        req.namespace_root,
        req.path,
        &req.holder,
        now,
        req.ttl_ms,
    ) {
        Ok(n) => n,
        Err(_) => {
            emit_lease_status(s, syscalls, req.correlation_id, super::admin::STATUS_NAK);
            return;
        }
    };
    if !enqueue_pending(
        s,
        Stream::Namespace,
        req.correlation_id,
        super::admin::OP_LEASE,
        u16::MAX,
    ) {
        emit_lease_status(s, syscalls, req.correlation_id, super::admin::STATUS_BUSY);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    let wrote = (syscalls.channel_write)(s.ns_req_chan, s.scratch.as_ptr(), n);
    if wrote < 0 || (wrote as usize) != n {
        let _ = dequeue_pending(s, Stream::Namespace);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    s.forwarded = s.forwarded.wrapping_add(1);
}

/// Translate the namespace's lease verdict into the admin ack. A
/// one-byte nak in place of a verdict is a record the namespace could
/// not apply at all.
unsafe fn handle_lease_response(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    entry: PendingDownstream,
    ns_resp: &[u8],
) {
    let (status, fence, expires) = match super::ns_wire::decode_lease_resp(ns_resp) {
        Ok((verdict, fence, expires)) => {
            let status = match verdict {
                super::ns_wire::LEASE_GRANTED => super::admin::STATUS_OK,
                super::ns_wire::LEASE_HELD => super::admin::STATUS_LEASE_HELD,
                super::ns_wire::LEASE_LOST => super::admin::STATUS_LEASE_LOST,
                // Both resolve by asking again: a table with room, or
                // a request carrying a later stamp.
                super::ns_wire::LEASE_BUSY | super::ns_wire::LEASE_STALE => {
                    super::admin::STATUS_BUSY
                }
                _ => super::admin::STATUS_NAK,
            };
            (status, fence, expires)
        }
        Err(_) => (super::admin::STATUS_NAK, 0, 0),
    };
    if let Ok(n) = super::admin::encode_admin_lease_ack(
        &mut s.scratch,
        entry.correlation_id,
        status,
        fence,
        expires,
    ) {
        reply_staged(s, syscalls, n);
    }
}

/// Forward a volume flush record to the namespace, stamped like a lease
/// request: the namespace judges the writer's lease against it.
unsafe fn handle_admin_volume(s: &mut ModuleState, syscalls: &super::SyscallTable, bytes: &[u8]) {
    let req = match super::admin::decode_admin_volume(bytes) {
        Ok(r) => r,
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return;
        }
    };
    let now = stamp_now(s, syscalls);
    if now == 0 {
        emit_volume_status(s, syscalls, req.correlation_id, super::admin::STATUS_NAK, 0);
        return;
    }
    let rec = super::ns_wire::DecodedVolumeReq {
        mode: req.mode,
        namespace_root: req.namespace_root,
        path: req.path,
        object_id: req.object_id,
        holder: req.holder,
        fence: req.fence,
        expected: req.expected,
        now_ms: now,
    };
    let n = match super::ns_wire::encode_volume_req(&mut s.scratch, &rec) {
        Ok(n) => n,
        Err(_) => {
            emit_volume_status(s, syscalls, req.correlation_id, super::admin::STATUS_NAK, 0);
            return;
        }
    };
    if !enqueue_pending(
        s,
        Stream::Namespace,
        req.correlation_id,
        super::admin::OP_VOLUME,
        u16::MAX,
    ) {
        emit_volume_status(
            s,
            syscalls,
            req.correlation_id,
            super::admin::STATUS_BUSY,
            0,
        );
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    let wrote = (syscalls.channel_write)(s.ns_req_chan, s.scratch.as_ptr(), n);
    if wrote < 0 || (wrote as usize) != n {
        let _ = dequeue_pending(s, Stream::Namespace);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    s.forwarded = s.forwarded.wrapping_add(1);
}

/// Translate the namespace's verdict on a volume record.
unsafe fn handle_volume_response(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    entry: PendingDownstream,
    ns_resp: &[u8],
) {
    let (status, revision) = match super::ns_wire::decode_volume_resp(ns_resp) {
        Ok((verdict, revision)) => {
            let status = match verdict {
                super::ns_wire::VOLUME_OK => super::admin::STATUS_OK,
                super::ns_wire::VOLUME_CONFLICT => super::admin::STATUS_CONFLICT,
                super::ns_wire::VOLUME_LEASE_LOST => super::admin::STATUS_LEASE_LOST,
                super::ns_wire::VOLUME_RESERVED => super::admin::STATUS_BUSY,
                _ => super::admin::STATUS_NAK,
            };
            (status, revision)
        }
        Err(_) => (super::admin::STATUS_NAK, 0),
    };
    emit_volume_status(s, syscalls, entry.correlation_id, status, revision);
}

unsafe fn emit_volume_status(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    correlation_id: u32,
    status: u8,
    revision: u64,
) {
    if let Ok(n) =
        super::admin::encode_admin_volume_ack(&mut s.scratch, correlation_id, status, revision)
    {
        reply_staged(s, syscalls, n);
    }
}

/// Resolve a path to its binding: a namespace LOOKUP, answered without
/// touching the body plane.
unsafe fn handle_admin_lookup(s: &mut ModuleState, syscalls: &super::SyscallTable, bytes: &[u8]) {
    let req = match super::admin::decode_admin_lookup(bytes) {
        Ok(r) => r,
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return;
        }
    };
    let n = match super::ns_wire::encode_lookup_req(&mut s.scratch, req.namespace_root, req.path) {
        Ok(n) => n,
        Err(_) => {
            emit_lookup_status(s, syscalls, req.correlation_id, super::admin::STATUS_NAK);
            return;
        }
    };
    if !enqueue_pending(
        s,
        Stream::Namespace,
        req.correlation_id,
        super::admin::OP_LOOKUP,
        u16::MAX,
    ) {
        emit_lookup_status(s, syscalls, req.correlation_id, super::admin::STATUS_BUSY);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    let wrote = (syscalls.channel_write)(s.ns_req_chan, s.scratch.as_ptr(), n);
    if wrote < 0 || (wrote as usize) != n {
        let _ = dequeue_pending(s, Stream::Namespace);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    s.forwarded = s.forwarded.wrapping_add(1);
}

unsafe fn handle_lookup_response(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    entry: PendingDownstream,
    ns_resp: &[u8],
) {
    match super::ns_wire::decode_lookup_resp(ns_resp) {
        Ok(super::ns_wire::DecodedLookupResp::Found {
            object_id,
            revision,
            kind,
        }) => {
            // Copied out: the response lives in the reassembly buffer,
            // and the ack is encoded into `scratch`.
            let mut oid = [0u8; super::limits::MAX_OBJECT_ID];
            let len = object_id.len().min(oid.len());
            oid[..len].copy_from_slice(&object_id[..len]);
            let binding = super::admin::AdminBinding {
                revision,
                kind,
                object_id: &oid[..len],
            };
            match super::admin::encode_admin_lookup_ack(
                &mut s.scratch,
                entry.correlation_id,
                super::admin::STATUS_OK,
                Some(&binding),
            ) {
                Ok(n) => reply_staged(s, syscalls, n),
                Err(_) => {
                    emit_lookup_status(s, syscalls, entry.correlation_id, super::admin::STATUS_NAK)
                }
            }
        }
        Ok(super::ns_wire::DecodedLookupResp::NotFound) => emit_lookup_status(
            s,
            syscalls,
            entry.correlation_id,
            super::admin::STATUS_NOT_FOUND,
        ),
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            emit_lookup_status(s, syscalls, entry.correlation_id, super::admin::STATUS_NAK);
        }
    }
}

unsafe fn emit_lookup_status(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    correlation_id: u32,
    status: u8,
) {
    if let Ok(n) =
        super::admin::encode_admin_lookup_ack(&mut s.scratch, correlation_id, status, None)
    {
        reply_staged(s, syscalls, n);
    }
}

unsafe fn emit_lease_status(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    correlation_id: u32,
    status: u8,
) {
    if let Ok(n) =
        super::admin::encode_admin_lease_ack(&mut s.scratch, correlation_id, status, 0, 0)
    {
        reply_staged(s, syscalls, n);
    }
}

unsafe fn handle_admin_put_body(s: &mut ModuleState, syscalls: &super::SyscallTable, bytes: &[u8]) {
    let (cid, body) = match super::admin::decode_admin_put_body(bytes) {
        Ok(p) => p,
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return;
        }
    };
    if s.body_req_chan < 0 {
        emit_put_body_nak(s, syscalls, cid);
        return;
    }
    let n = match super::body_wire::encode_put_req(&mut s.scratch, body) {
        Ok(n) => n,
        Err(_) => {
            emit_put_body_nak(s, syscalls, cid);
            return;
        }
    };
    if !enqueue_pending(s, Stream::Body, cid, super::admin::OP_PUT_BODY, u16::MAX) {
        emit_put_body_nak(s, syscalls, cid);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    let wrote = (syscalls.channel_write)(s.body_req_chan, s.scratch.as_ptr(), n);
    if wrote < 0 || (wrote as usize) != n {
        let _ = dequeue_pending(s, Stream::Body);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    s.forwarded = s.forwarded.wrapping_add(1);
}

/// Raw keyed body write. Body-plane forward of
/// OP_PUT_KEYED; ack is status-only (the key is the caller's).
unsafe fn handle_admin_put_body_keyed(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    bytes: &[u8],
) {
    let (cid, key, body) = match super::admin::decode_admin_put_body_keyed(bytes) {
        Ok(p) => p,
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return;
        }
    };
    if s.body_req_chan < 0 {
        emit_admin_status_nak(s, syscalls, super::admin::OP_PUT_BODY_KEYED, cid);
        return;
    }
    let mut key_arr = [0u8; super::admin::DIGEST_LEN];
    key_arr.copy_from_slice(key);
    let n = match super::body_wire::encode_put_keyed_req(&mut s.scratch, &key_arr, body) {
        Ok(n) => n,
        Err(_) => {
            emit_admin_status_nak(s, syscalls, super::admin::OP_PUT_BODY_KEYED, cid);
            return;
        }
    };
    if !enqueue_pending(
        s,
        Stream::Body,
        cid,
        super::admin::OP_PUT_BODY_KEYED,
        u16::MAX,
    ) {
        emit_admin_status_nak(s, syscalls, super::admin::OP_PUT_BODY_KEYED, cid);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    let wrote = (syscalls.channel_write)(s.body_req_chan, s.scratch.as_ptr(), n);
    if wrote < 0 || (wrote as usize) != n {
        let _ = dequeue_pending(s, Stream::Body);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    s.forwarded = s.forwarded.wrapping_add(1);
}

/// Raw body delete by key/digest. Fans out downstream via the router.
unsafe fn handle_admin_delete_body(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    bytes: &[u8],
) {
    let (cid, key) = match super::admin::decode_admin_delete_body(bytes) {
        Ok(p) => p,
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return;
        }
    };
    if s.body_req_chan < 0 {
        emit_admin_status_nak(s, syscalls, super::admin::OP_DELETE_BODY, cid);
        return;
    }
    let mut key_arr = [0u8; super::admin::DIGEST_LEN];
    key_arr.copy_from_slice(key);
    let n = match super::body_wire::encode_delete_req(&mut s.scratch, &key_arr) {
        Ok(n) => n,
        Err(_) => {
            emit_admin_status_nak(s, syscalls, super::admin::OP_DELETE_BODY, cid);
            return;
        }
    };
    if !enqueue_pending(s, Stream::Body, cid, super::admin::OP_DELETE_BODY, u16::MAX) {
        emit_admin_status_nak(s, syscalls, super::admin::OP_DELETE_BODY, cid);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    let wrote = (syscalls.channel_write)(s.body_req_chan, s.scratch.as_ptr(), n);
    if wrote < 0 || (wrote as usize) != n {
        let _ = dequeue_pending(s, Stream::Body);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    s.forwarded = s.forwarded.wrapping_add(1);
}

/// Status-only NAK for the keyed-body ops.
unsafe fn emit_admin_status_nak(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    op: u8,
    cid: u32,
) {
    let n = if op == super::admin::OP_DELETE_BODY {
        super::admin::encode_admin_delete_body_ack(
            &mut s.scratch,
            cid,
            super::admin::STATUS_NAK,
            false,
        )
    } else {
        super::admin::encode_admin_put_body_keyed_ack(&mut s.scratch, cid, super::admin::STATUS_NAK)
    };
    if let Ok(n) = n {
        reply_staged(s, syscalls, n);
    }
}

unsafe fn handle_admin_get_body(s: &mut ModuleState, syscalls: &super::SyscallTable, bytes: &[u8]) {
    let (cid, digest) = match super::admin::decode_admin_get_body(bytes) {
        Ok(p) => p,
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return;
        }
    };
    if s.body_req_chan < 0 {
        emit_get_body_nak(s, syscalls, cid);
        return;
    }
    let mut digest_arr = [0u8; super::admin::DIGEST_LEN];
    digest_arr.copy_from_slice(digest);
    let n = match super::body_wire::encode_get_req(&mut s.scratch, &digest_arr) {
        Ok(n) => n,
        Err(_) => {
            emit_get_body_nak(s, syscalls, cid);
            return;
        }
    };
    if !enqueue_pending(s, Stream::Body, cid, super::admin::OP_GET_BODY, u16::MAX) {
        emit_get_body_nak(s, syscalls, cid);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    let wrote = (syscalls.channel_write)(s.body_req_chan, s.scratch.as_ptr(), n);
    if wrote < 0 || (wrote as usize) != n {
        let _ = dequeue_pending(s, Stream::Body);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    s.forwarded = s.forwarded.wrapping_add(1);
}

unsafe fn emit_body_admin_response(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    entry: PendingDownstream,
    body_resp: &[u8],
) {
    let op = super::body_wire::peek_opcode(body_resp).unwrap_or(0xFF);
    match entry.admin_op {
        super::admin::OP_PUT_BODY => {
            let resp_n = if op == super::body_wire::OP_PUT {
                let digest = match super::body_wire::decode_put_resp(body_resp) {
                    Ok(d) => d,
                    Err(_) => {
                        emit_put_body_nak(s, syscalls, entry.correlation_id);
                        return;
                    }
                };
                let mut digest_arr = [0u8; super::admin::DIGEST_LEN];
                digest_arr.copy_from_slice(digest);
                match super::admin::encode_admin_put_body_ack(
                    &mut s.scratch,
                    entry.correlation_id,
                    super::admin::STATUS_OK,
                    Some(&digest_arr),
                ) {
                    Ok(n) => n,
                    Err(_) => {
                        s.apply_errors = s.apply_errors.wrapping_add(1);
                        return;
                    }
                }
            } else {
                // NAK from downstream.
                match super::admin::encode_admin_put_body_ack(
                    &mut s.scratch,
                    entry.correlation_id,
                    super::admin::STATUS_NAK,
                    None,
                ) {
                    Ok(n) => n,
                    Err(_) => {
                        s.apply_errors = s.apply_errors.wrapping_add(1);
                        return;
                    }
                }
            };
            reply_staged(s, syscalls, resp_n);
        }
        super::admin::OP_PUT_BODY_KEYED => {
            let status = if op == super::body_wire::OP_PUT_KEYED {
                super::admin::STATUS_OK
            } else {
                super::admin::STATUS_NAK
            };
            let resp_n = match super::admin::encode_admin_put_body_keyed_ack(
                &mut s.scratch,
                entry.correlation_id,
                status,
            ) {
                Ok(n) => n,
                Err(_) => {
                    s.apply_errors = s.apply_errors.wrapping_add(1);
                    return;
                }
            };
            reply_staged(s, syscalls, resp_n);
        }
        super::admin::OP_DELETE_BODY => {
            let (status, existed) = if op == super::body_wire::OP_DELETE {
                match super::body_wire::decode_delete_resp(body_resp) {
                    Ok(e) => (super::admin::STATUS_OK, e),
                    Err(_) => (super::admin::STATUS_NAK, false),
                }
            } else {
                (super::admin::STATUS_NAK, false)
            };
            let resp_n = match super::admin::encode_admin_delete_body_ack(
                &mut s.scratch,
                entry.correlation_id,
                status,
                existed,
            ) {
                Ok(n) => n,
                Err(_) => {
                    s.apply_errors = s.apply_errors.wrapping_add(1);
                    return;
                }
            };
            reply_staged(s, syscalls, resp_n);
        }
        super::admin::OP_GET_BODY => {
            let resp_n = if op == super::body_wire::OP_GET {
                let body = match super::body_wire::decode_get_resp(body_resp) {
                    Ok(b) => b,
                    Err(_) => {
                        emit_get_body_nak(s, syscalls, entry.correlation_id);
                        return;
                    }
                };
                // Encode into scratch — body is borrowed FROM
                // scratch indirectly via the channel read, but we
                // re-encode into the same buffer here. Use a
                // temporary copy to avoid alias.
                let body_owned: heapless_copy::Vec<u8, { super::body_wire::MAX_BODY }> =
                    heapless_copy::Vec::from_slice(body);
                match super::admin::encode_admin_get_body_ack(
                    &mut s.scratch,
                    entry.correlation_id,
                    super::admin::STATUS_OK,
                    Some(body_owned.as_slice()),
                ) {
                    Ok(n) => n,
                    Err(_) => {
                        emit_get_body_nak(s, syscalls, entry.correlation_id);
                        return;
                    }
                }
            } else {
                // body_store NAK — likely ERR_NOT_FOUND.
                let status = if body_resp.len() >= 2
                    && body_resp[0] == super::body_wire::OP_NAK
                    && body_resp[1] == super::body_wire::ERR_NOT_FOUND
                {
                    super::admin::STATUS_NOT_FOUND
                } else {
                    super::admin::STATUS_NAK
                };
                match super::admin::encode_admin_get_body_ack(
                    &mut s.scratch,
                    entry.correlation_id,
                    status,
                    None,
                ) {
                    Ok(n) => n,
                    Err(_) => {
                        s.apply_errors = s.apply_errors.wrapping_add(1);
                        return;
                    }
                }
            };
            reply_staged(s, syscalls, resp_n);
        }
        super::admin::OP_GET_FILE => {
            // GetFile's body stage: the resolved digest's bytes.
            let resp_n = if op == super::body_wire::OP_GET {
                let body = match super::body_wire::decode_get_resp(body_resp) {
                    Ok(b) => b,
                    Err(_) => {
                        emit_get_file_status(
                            s,
                            syscalls,
                            entry.correlation_id,
                            super::admin::STATUS_NAK,
                        );
                        return;
                    }
                };
                let body_owned: heapless_copy::Vec<u8, { super::body_wire::MAX_BODY }> =
                    heapless_copy::Vec::from_slice(body);
                match super::admin::encode_admin_get_file_ack(
                    &mut s.scratch,
                    entry.correlation_id,
                    super::admin::STATUS_OK,
                    Some(body_owned.as_slice()),
                ) {
                    Ok(n) => n,
                    Err(_) => {
                        emit_get_file_status(
                            s,
                            syscalls,
                            entry.correlation_id,
                            super::admin::STATUS_NAK,
                        );
                        return;
                    }
                }
            } else {
                let status = if body_resp.len() >= 2
                    && body_resp[0] == super::body_wire::OP_NAK
                    && body_resp[1] == super::body_wire::ERR_NOT_FOUND
                {
                    super::admin::STATUS_NOT_FOUND
                } else {
                    super::admin::STATUS_NAK
                };
                match super::admin::encode_admin_get_file_ack(
                    &mut s.scratch,
                    entry.correlation_id,
                    status,
                    None,
                ) {
                    Ok(n) => n,
                    Err(_) => {
                        s.apply_errors = s.apply_errors.wrapping_add(1);
                        return;
                    }
                }
            };
            reply_staged(s, syscalls, resp_n);
        }
        _ => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
        }
    }
}

// ── AdminGetFile / AdminDeleteFile ────────────────────────────────

unsafe fn emit_get_file_status(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    correlation_id: u32,
    status: u8,
) {
    if let Ok(n) =
        super::admin::encode_admin_get_file_ack(&mut s.scratch, correlation_id, status, None)
    {
        reply_staged(s, syscalls, n);
    }
}

/// GetFile stage 1: forward a namespace LOOKUP for the path.
unsafe fn handle_admin_get_file(s: &mut ModuleState, syscalls: &super::SyscallTable, bytes: &[u8]) {
    let req = match super::admin::decode_admin_get_file(bytes) {
        Ok(r) => r,
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return;
        }
    };
    if s.body_req_chan < 0 {
        emit_get_file_status(s, syscalls, req.correlation_id, super::admin::STATUS_NAK);
        return;
    }
    let n = match super::ns_wire::encode_lookup_req(&mut s.scratch, req.namespace_root, req.path) {
        Ok(n) => n,
        Err(_) => {
            emit_get_file_status(s, syscalls, req.correlation_id, super::admin::STATUS_NAK);
            return;
        }
    };
    if !enqueue_pending(
        s,
        Stream::Namespace,
        req.correlation_id,
        super::admin::OP_GET_FILE,
        0,
    ) {
        emit_get_file_status(s, syscalls, req.correlation_id, super::admin::STATUS_NAK);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    let wrote = (syscalls.channel_write)(s.ns_req_chan, s.scratch.as_ptr(), n);
    if wrote < 0 || (wrote as usize) != n {
        let _ = dequeue_pending(s, Stream::Namespace);
        emit_get_file_status(s, syscalls, req.correlation_id, super::admin::STATUS_NAK);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    s.forwarded = s.forwarded.wrapping_add(1);
}

/// Parse a bound object id of the form `sha256:<64 lowercase hex>`
/// back into the 32-byte content digest.
fn digest_from_object_id(object_id: &[u8]) -> Option<[u8; 32]> {
    if object_id.len() != 7 + 64 || &object_id[..7] != b"sha256:" {
        return None;
    }
    let mut digest = [0u8; 32];
    for (i, out) in digest.iter_mut().enumerate() {
        let hi = hex_nibble(object_id[7 + 2 * i])?;
        let lo = hex_nibble(object_id[7 + 2 * i + 1])?;
        *out = (hi << 4) | lo;
    }
    Some(digest)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// GetFile stage 2 trigger: the namespace answered the LOOKUP.
unsafe fn handle_getfile_lookup_response(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    entry: PendingDownstream,
    ns_resp: &[u8],
) {
    let digest = match super::ns_wire::decode_lookup_resp(ns_resp) {
        Ok(super::ns_wire::DecodedLookupResp::Found { object_id, .. }) => {
            match digest_from_object_id(object_id) {
                Some(d) => d,
                None => {
                    // Bound to something that isn't a content
                    // digest — not servable through GetFile.
                    emit_get_file_status(
                        s,
                        syscalls,
                        entry.correlation_id,
                        super::admin::STATUS_NAK,
                    );
                    return;
                }
            }
        }
        Ok(super::ns_wire::DecodedLookupResp::NotFound) => {
            emit_get_file_status(
                s,
                syscalls,
                entry.correlation_id,
                super::admin::STATUS_NOT_FOUND,
            );
            return;
        }
        Err(_) => {
            emit_get_file_status(s, syscalls, entry.correlation_id, super::admin::STATUS_NAK);
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return;
        }
    };
    let n = match super::body_wire::encode_get_req(&mut s.scratch, &digest) {
        Ok(n) => n,
        Err(_) => {
            emit_get_file_status(s, syscalls, entry.correlation_id, super::admin::STATUS_NAK);
            return;
        }
    };
    if !enqueue_pending(
        s,
        Stream::Body,
        entry.correlation_id,
        super::admin::OP_GET_FILE,
        0,
    ) {
        emit_get_file_status(s, syscalls, entry.correlation_id, super::admin::STATUS_NAK);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    let wrote = (syscalls.channel_write)(s.body_req_chan, s.scratch.as_ptr(), n);
    if wrote < 0 || (wrote as usize) != n {
        let _ = dequeue_pending(s, Stream::Body);
        emit_get_file_status(s, syscalls, entry.correlation_id, super::admin::STATUS_NAK);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    s.forwarded = s.forwarded.wrapping_add(1);
}

/// DeleteFile: forward a namespace UNBIND. The body blob stays —
/// content-addressed and possibly shared by other paths.
unsafe fn handle_admin_delete_file(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    bytes: &[u8],
) {
    let req = match super::admin::decode_admin_delete_file(bytes) {
        Ok(r) => r,
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return;
        }
    };
    let n = match super::ns_wire::encode_unbind(&mut s.scratch, req.namespace_root, req.path) {
        Ok(n) => n,
        Err(_) => {
            if let Ok(rn) = super::admin::encode_admin_delete_file_ack(
                &mut s.scratch,
                req.correlation_id,
                super::admin::STATUS_NAK,
            ) {
                reply_staged(s, syscalls, rn);
            }
            return;
        }
    };
    if !enqueue_pending(
        s,
        Stream::Namespace,
        req.correlation_id,
        super::admin::OP_DELETE_FILE,
        0,
    ) {
        if let Ok(rn) = super::admin::encode_admin_delete_file_ack(
            &mut s.scratch,
            req.correlation_id,
            super::admin::STATUS_NAK,
        ) {
            reply_staged(s, syscalls, rn);
        }
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    let wrote = (syscalls.channel_write)(s.ns_req_chan, s.scratch.as_ptr(), n);
    if wrote < 0 || (wrote as usize) != n {
        let _ = dequeue_pending(s, Stream::Namespace);
        if let Ok(rn) = super::admin::encode_admin_delete_file_ack(
            &mut s.scratch,
            req.correlation_id,
            super::admin::STATUS_NAK,
        ) {
            reply_staged(s, syscalls, rn);
        }
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    s.forwarded = s.forwarded.wrapping_add(1);
}

/// ListFiles: forward a namespace LIST page request.
unsafe fn handle_admin_list_files(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    bytes: &[u8],
) {
    let req = match super::admin::decode_admin_list_files(bytes) {
        Ok(r) => r,
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return;
        }
    };
    let n = match super::ns_wire::encode_list_req(
        &mut s.scratch,
        req.namespace_root,
        req.cursor,
        req.max,
    ) {
        Ok(n) => n,
        Err(_) => {
            emit_list_files_nak(s, syscalls, req.correlation_id);
            return;
        }
    };
    if !enqueue_pending(
        s,
        Stream::Namespace,
        req.correlation_id,
        super::admin::OP_LIST_FILES,
        0,
    ) {
        emit_list_files_nak(s, syscalls, req.correlation_id);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    let wrote = (syscalls.channel_write)(s.ns_req_chan, s.scratch.as_ptr(), n);
    if wrote < 0 || (wrote as usize) != n {
        let _ = dequeue_pending(s, Stream::Namespace);
        emit_list_files_nak(s, syscalls, req.correlation_id);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    s.forwarded = s.forwarded.wrapping_add(1);
}

unsafe fn emit_list_files_nak(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    correlation_id: u32,
) {
    if let Ok(n) = super::admin::encode_admin_list_files_ack(
        &mut s.scratch,
        correlation_id,
        super::admin::STATUS_NAK,
        0,
        0,
        &[],
    ) {
        reply_staged(s, syscalls, n);
    }
}

/// The namespace answered a LIST — re-frame it as the admin ack.
/// The entry section (`[(path_len,path)*]`) is carried verbatim.
unsafe fn handle_listfiles_response(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    entry: PendingDownstream,
    ns_resp: &[u8],
) {
    let ok = ns_resp.len() >= 6 && ns_resp[0] == super::ns_wire::OP_LIST;
    let resp_n = if ok {
        let next_cursor = u32::from_le_bytes(ns_resp[1..5].try_into().unwrap());
        let count = ns_resp[5];
        // Stage the entry bytes so encoding into scratch can't
        // alias a borrow of ns_resp (it's a caller stack buffer,
        // but keep the copy local and bounded anyway).
        match super::admin::encode_admin_list_files_ack(
            &mut s.scratch,
            entry.correlation_id,
            super::admin::STATUS_OK,
            next_cursor,
            count,
            &ns_resp[6..],
        ) {
            Ok(n) => n,
            Err(_) => {
                s.apply_errors = s.apply_errors.wrapping_add(1);
                return;
            }
        }
    } else {
        match super::admin::encode_admin_list_files_ack(
            &mut s.scratch,
            entry.correlation_id,
            super::admin::STATUS_NAK,
            0,
            0,
            &[],
        ) {
            Ok(n) => n,
            Err(_) => {
                s.apply_errors = s.apply_errors.wrapping_add(1);
                return;
            }
        }
    };
    reply_staged(s, syscalls, resp_n);
}

// ── Orphan-body GC ────────────────────────────────────────────────

/// Forward a request to a downstream stream with a GC pending
/// marker. Returns false (with the pending unwound) on failure.
unsafe fn gc_forward(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    stream: Stream,
    chan: i32,
    gc_op: u8,
    req_n: usize,
) -> bool {
    if !enqueue_pending(s, stream, 0, gc_op, 0) {
        return false;
    }
    let wrote = (syscalls.channel_write)(chan, s.scratch.as_ptr(), req_n);
    if wrote < 0 || (wrote as usize) != req_n {
        // No response will ever come — unwind the just-pushed TAIL
        // entry (popping the head would desync the FIFO).
        gc_unenqueue_tail(s, stream);
        return false;
    }
    s.forwarded = s.forwarded.wrapping_add(1);
    true
}

unsafe fn gc_unenqueue_tail(s: &mut ModuleState, stream: Stream) {
    let (head, tail, ring) = match stream {
        Stream::Namespace => (&mut s.ns_head, &mut s.ns_tail, &mut s.ns_pending),
        Stream::Body => (&mut s.body_head, &mut s.body_tail, &mut s.body_pending),
        Stream::Object => (&mut s.obj_head, &mut s.obj_tail, &mut s.obj_pending),
    };
    if *head == *tail {
        return;
    }
    let prev = (tail.wrapping_add(super::limits::ADMIN_PENDING as u32 - 1))
        % super::limits::ADMIN_PENDING as u32;
    ring[prev as usize].in_use = 0;
    *tail = prev;
}

/// Ask the current phase's inventory for one page.
unsafe fn gc_kick(s: &mut ModuleState, syscalls: &super::SyscallTable) {
    if s.gc_phase == GC_PHASE_OBJECT {
        let req_n = match super::obj_wire::encode_scan_req(
            &mut s.scratch,
            s.gc_obj_cursor,
            super::obj_wire::MAX_OBJ_SCAN as u8,
        ) {
            Ok(n) => n,
            Err(_) => return,
        };
        if gc_forward(
            s,
            syscalls,
            Stream::Object,
            s.obj_req_chan,
            GC_OP_OBJ_SCAN,
            req_n,
        ) {
            s.gc_inflight = 1;
            s.gc_scans = s.gc_scans.wrapping_add(1);
        }
        return;
    }
    let req_n = match super::body_wire::encode_scan_req(
        &mut s.scratch,
        s.gc_cursor,
        super::body_wire::MAX_SCAN_DIGESTS as u8,
    ) {
        Ok(n) => n,
        Err(_) => return,
    };
    if gc_forward(
        s,
        syscalls,
        Stream::Body,
        s.body_req_chan,
        GC_OP_SCAN,
        req_n,
    ) {
        s.gc_inflight = 1;
        s.gc_scans = s.gc_scans.wrapping_add(1);
    }
}

/// Alternate to the other inventory once this one has wrapped, so
/// neither sweep can starve the other. The descriptor sweep needs an
/// object_index to ask.
unsafe fn gc_advance_phase(s: &mut ModuleState) {
    s.gc_phase = if s.gc_phase == GC_PHASE_BODY && s.obj_req_chan >= 0 {
        GC_PHASE_OBJECT
    } else {
        GC_PHASE_BODY
    };
}

/// Build the content-derived object id `sha256:<hex>` for a digest.
fn gc_object_id(digest: &[u8; 32]) -> [u8; 7 + 64] {
    let mut oid = [0u8; 7 + 64];
    oid[..7].copy_from_slice(b"sha256:");
    super::body_wire::hex_lower_into(digest, &mut oid[7..]);
    oid
}

/// One page of descriptor ids came back. Same queue as the body
/// sweep: the per-entry pipeline below does not care which inventory
/// produced the digest, only which phase decides what gets deleted.
unsafe fn gc_apply_obj_scan(s: &mut ModuleState, syscalls: &super::SyscallTable, resp: &[u8]) {
    s.gc_inflight = 0;
    let mut digests = [[0u8; super::obj_wire::DIGEST_LEN]; super::obj_wire::MAX_OBJ_SCAN];
    match super::obj_wire::decode_scan_resp(resp, &mut digests) {
        Ok((next, count)) => {
            s.gc_obj_cursor = next;
            s.gc_wrapped = u8::from(next == 0);
            if count > 0 {
                for (i, d) in digests.iter().take(count).enumerate() {
                    s.gc_digests[i] = *d;
                }
                s.gc_q_len = count as u8;
                s.gc_q_pos = 0;
                gc_begin_current(s, syscalls);
            } else if core::mem::replace(&mut s.gc_wrapped, 0) != 0 {
                gc_advance_phase(s);
            }
        }
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            s.gc_obj_cursor = 0;
            gc_advance_phase(s);
        }
    }
}

/// Take the namespace deletion reservation for the current entry. The
/// reservation is taken BEFORE the absence proof so the whole
/// cursor-paged proof runs inside the fence: no BIND naming this id
/// can be admitted between the proof and the deletions it licenses.
unsafe fn gc_begin_current(s: &mut ModuleState, syscalls: &super::SyscallTable) {
    // A composed write in flight owns the window between its body
    // landing and its bind committing. Its bind would be refused by
    // our own reservation, so do not take one.
    if s.putfiles.iter().any(|p| p.in_use != 0) {
        s.gc_kept = s.gc_kept.wrapping_add(1);
        gc_skip_current(s, syscalls);
        return;
    }
    let oid = gc_object_id(&s.gc_digests[s.gc_q_pos as usize]);
    // Stamped so the namespace can end flushes whose writers' leases
    // have expired by now; with no clock it ends none.
    let now = stamp_now(s, syscalls);
    let req_n = match super::ns_wire::encode_gc_reserve_req(&mut s.scratch, &oid, now) {
        Ok(n) => n,
        Err(_) => {
            gc_skip_current(s, syscalls);
            return;
        }
    };
    if !gc_forward(
        s,
        syscalls,
        Stream::Namespace,
        s.ns_req_chan,
        GC_OP_RESERVE,
        req_n,
    ) {
        gc_skip_current(s, syscalls);
    }
}

unsafe fn gc_apply_reserve(s: &mut ModuleState, syscalls: &super::SyscallTable, ns_resp: &[u8]) {
    // A refused reservation means the fence is unavailable, so nothing
    // may be deleted this pass.
    match super::ns_wire::decode_gc_reserve_resp(ns_resp) {
        Ok(true) => {
            s.gc_reserved = 1;
            s.gc_check_cursor = 0;
            gc_check_current(s, syscalls);
        }
        _ => {
            s.gc_kept = s.gc_kept.wrapping_add(1);
            gc_skip_current(s, syscalls);
        }
    }
}

/// Release the reservation, then move on. Every path that leaves an
/// entry goes through here so a reservation cannot outlive its sweep.
unsafe fn gc_release_current(s: &mut ModuleState, syscalls: &super::SyscallTable) {
    if s.gc_reserved == 0 {
        gc_next(s, syscalls);
        return;
    }
    s.gc_reserved = 0;
    let oid = gc_object_id(&s.gc_digests[s.gc_q_pos as usize]);
    let req_n = match super::ns_wire::encode_gc_release_req(&mut s.scratch, &oid) {
        Ok(n) => n,
        Err(_) => {
            gc_next(s, syscalls);
            return;
        }
    };
    if !gc_forward(
        s,
        syscalls,
        Stream::Namespace,
        s.ns_req_chan,
        GC_OP_RELEASE,
        req_n,
    ) {
        gc_next(s, syscalls);
    }
}

/// Leave the current entry alone without having reserved it.
unsafe fn gc_skip_current(s: &mut ModuleState, syscalls: &super::SyscallTable) {
    s.gc_reserved = 0;
    gc_next(s, syscalls);
}

/// Delete the object descriptor for the current entry. Runs under the
/// reservation in both phases: the descriptor is the reachable half of
/// the pair, so it goes first and a crash between the two deletions
/// leaves only an orphan body for a later body pass.
unsafe fn gc_delete_descriptor(s: &mut ModuleState, syscalls: &super::SyscallTable) {
    if s.obj_req_chan < 0 {
        gc_delete_body(s, syscalls);
        return;
    }
    let oid = gc_object_id(&s.gc_digests[s.gc_q_pos as usize]);
    let req_n = match super::obj_wire::encode_remove(&mut s.scratch, &oid) {
        Ok(n) => n,
        Err(_) => {
            gc_release_current(s, syscalls);
            return;
        }
    };
    if !gc_forward(
        s,
        syscalls,
        Stream::Object,
        s.obj_req_chan,
        GC_OP_OBJ_REMOVE,
        req_n,
    ) {
        gc_release_current(s, syscalls);
    }
}

unsafe fn gc_delete_body(s: &mut ModuleState, syscalls: &super::SyscallTable) {
    // The descriptor sweep enumerates descriptors, not bodies: a body
    // for the same digest is the body sweep's to collect.
    if s.gc_phase == GC_PHASE_OBJECT {
        gc_release_current(s, syscalls);
        return;
    }
    let digest = s.gc_digests[s.gc_q_pos as usize];
    let req_n = match super::body_wire::encode_delete_req(&mut s.scratch, &digest) {
        Ok(n) => n,
        Err(_) => {
            gc_release_current(s, syscalls);
            return;
        }
    };
    if !gc_forward(
        s,
        syscalls,
        Stream::Body,
        s.body_req_chan,
        GC_OP_DELETE,
        req_n,
    ) {
        gc_release_current(s, syscalls);
    }
}

unsafe fn gc_apply_scan(s: &mut ModuleState, syscalls: &super::SyscallTable, resp: &[u8]) {
    s.gc_inflight = 0;
    if resp.first() != Some(&super::body_wire::OP_SCAN) {
        s.apply_errors = s.apply_errors.wrapping_add(1);
        s.gc_cursor = 0;
        return;
    }
    let mut digests = [[0u8; 32]; super::body_wire::MAX_SCAN_DIGESTS];
    let mut keyed = [0u8; super::body_wire::MAX_SCAN_DIGESTS];
    match super::body_wire::decode_scan_resp(resp, &mut digests, &mut keyed) {
        Ok((next, count)) => {
            s.gc_cursor = next;
            // Keyed blobs (EC shards) are NOT orphan-GC's to
            // collect: their keys are never bound in the namespace by
            // design, and their lifecycle belongs to the EC router,
            // whose scrub deletes a shard copy found off its ranked
            // home.
            let mut kept = 0usize;
            for i in 0..count {
                if keyed[i] == 0 {
                    s.gc_digests[kept] = digests[i];
                    kept += 1;
                }
            }
            s.gc_wrapped = u8::from(next == 0);
            if kept > 0 {
                s.gc_q_len = kept as u8;
                s.gc_q_pos = 0;
                gc_begin_current(s, syscalls);
            } else if core::mem::replace(&mut s.gc_wrapped, 0) != 0 {
                // An empty final page still ends the pass, so the
                // other inventory gets its turn.
                gc_advance_phase(s);
            }
        }
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            s.gc_cursor = 0;
            gc_advance_phase(s);
        }
    }
}

/// Ask the namespace whether the current digest's object id
/// (`sha256:<hex>`) is bound anywhere.
unsafe fn gc_check_current(s: &mut ModuleState, syscalls: &super::SyscallTable) {
    let digest = s.gc_digests[s.gc_q_pos as usize];
    let mut oid = [0u8; 7 + 64];
    oid[..7].copy_from_slice(b"sha256:");
    super::body_wire::hex_lower_into(&digest, &mut oid[7..]);
    let req_n = match super::ns_wire::encode_referenced_req(&mut s.scratch, s.gc_check_cursor, &oid)
    {
        Ok(n) => n,
        Err(_) => {
            gc_release_current(s, syscalls);
            return;
        }
    };
    if !gc_forward(
        s,
        syscalls,
        Stream::Namespace,
        s.ns_req_chan,
        GC_OP_CHECK,
        req_n,
    ) {
        gc_release_current(s, syscalls);
    }
}

unsafe fn gc_apply_check(s: &mut ModuleState, syscalls: &super::SyscallTable, ns_resp: &[u8]) {
    s.gc_checked = s.gc_checked.wrapping_add(1);
    // On a malformed reply, treat as referenced — never delete on
    // doubt.
    let (referenced, next_cursor) =
        super::ns_wire::decode_referenced_resp(ns_resp).unwrap_or((true, 0));
    if !referenced && next_cursor != 0 {
        // Undecided: continue the namespace's snapshot scan.
        s.gc_check_cursor = next_cursor;
        gc_check_current(s, syscalls);
        return;
    }
    s.gc_check_cursor = 0;
    // The PutFile guard re-checks HERE, not just at kick time: a
    // composed write may have started since the scan.
    if referenced || s.putfiles.iter().any(|p| p.in_use != 0) {
        s.gc_kept = s.gc_kept.wrapping_add(1);
        gc_release_current(s, syscalls);
        return;
    }
    // No binding names it. In the body sweep it may still be a page or
    // an extent of a bound volume root, which only the maps can say.
    if s.gc_phase == GC_PHASE_BODY {
        gc_walk_begin(s, syscalls);
        return;
    }
    // Absence is proven and the reservation still stands, so it stays
    // proven through both deletions.
    gc_delete_descriptor(s, syscalls);
}

/// Keep the current entry: something may reach it, or the walk could
/// not tell.
unsafe fn gc_keep_current(s: &mut ModuleState, syscalls: &super::SyscallTable) {
    s.gc_kept = s.gc_kept.wrapping_add(1);
    gc_release_current(s, syscalls);
}

/// Start the volume-map walk for the current entry. It runs inside the
/// reservation, and while a reservation stands the namespace refuses to
/// open a volume flush — so no commit can bind a new root during the
/// walk, and the roots it sees are every root that can reach the body.
unsafe fn gc_walk_begin(s: &mut ModuleState, syscalls: &super::SyscallTable) {
    s.gc_walk_view_set = 0;
    s.gc_walk_next = 0;
    s.gc_roots_len = 0;
    s.gc_roots_pos = 0;
    s.gc_leaves_len = 0;
    s.gc_leaves_pos = 0;
    gc_walk_roots_page(s, syscalls, 0);
}

unsafe fn gc_walk_roots_page(s: &mut ModuleState, syscalls: &super::SyscallTable, cursor: u32) {
    let req_n = match super::ns_wire::encode_volume_roots_req(&mut s.scratch, cursor) {
        Ok(n) => n,
        Err(_) => {
            gc_keep_current(s, syscalls);
            return;
        }
    };
    if !gc_forward(
        s,
        syscalls,
        Stream::Namespace,
        s.ns_req_chan,
        GC_OP_ROOTS,
        req_n,
    ) {
        gc_keep_current(s, syscalls);
    }
}

unsafe fn gc_apply_roots(s: &mut ModuleState, syscalls: &super::SyscallTable, ns_resp: &[u8]) {
    let (next, view, digests) = match super::ns_wire::decode_volume_roots_resp(ns_resp) {
        Ok(v) => v,
        Err(_) => {
            gc_keep_current(s, syscalls);
            return;
        }
    };
    if s.gc_walk_view_set != 0 && s.gc_walk_view != view {
        gc_keep_current(s, syscalls);
        return;
    }
    s.gc_walk_view = view;
    s.gc_walk_view_set = 1;
    let mut n = 0usize;
    while n < super::ns_wire::MAX_VOLUME_ROOTS {
        let at = n * 32;
        match digests.get(at..at + 32) {
            Some(d) => s.gc_roots[n].copy_from_slice(d),
            None => break,
        }
        n += 1;
    }
    s.gc_roots_len = n as u8;
    s.gc_roots_pos = 0;
    s.gc_walk_next = next;
    gc_walk_next_root(s, syscalls);
}

/// Read the next root of the current page, or the next page, or — with
/// every root walked — delete.
unsafe fn gc_walk_next_root(s: &mut ModuleState, syscalls: &super::SyscallTable) {
    if s.gc_roots_pos < s.gc_roots_len {
        let digest = s.gc_roots[s.gc_roots_pos as usize];
        gc_walk_read(s, syscalls, &digest, GC_OP_MAP_ROOT);
        return;
    }
    if s.gc_walk_next != 0 {
        let next = s.gc_walk_next;
        gc_walk_roots_page(s, syscalls, next);
        return;
    }
    // Walked every root. The PutFile guard is re-checked here for the
    // reason it is re-checked after the reachability answer.
    if s.putfiles.iter().any(|p| p.in_use != 0) {
        gc_keep_current(s, syscalls);
        return;
    }
    gc_delete_descriptor(s, syscalls);
}

unsafe fn gc_walk_read(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    digest: &[u8; 32],
    gc_op: u8,
) {
    let req_n = match super::body_wire::encode_get_req(&mut s.scratch, digest) {
        Ok(n) => n,
        Err(_) => {
            gc_keep_current(s, syscalls);
            return;
        }
    };
    if !gc_forward(s, syscalls, Stream::Body, s.body_req_chan, gc_op, req_n) {
        gc_keep_current(s, syscalls);
    }
}

/// The bytes of a map page read by the walk, or `None` for anything
/// else — a refusal, a missing body — which keeps the entry: a map the
/// walk cannot read is a map it cannot prove the body absent from.
fn gc_page_bytes(resp: &[u8]) -> Option<&[u8]> {
    if resp.first() != Some(&super::body_wire::OP_GET) {
        return None;
    }
    super::body_wire::decode_get_resp(resp).ok()
}

unsafe fn gc_apply_map_root(s: &mut ModuleState, syscalls: &super::SyscallTable, resp: &[u8]) {
    s.gc_map_reads = s.gc_map_reads.wrapping_add(1);
    let candidate = s.gc_digests[s.gc_q_pos as usize];
    let root = match gc_page_bytes(resp).and_then(|b| super::map_wire::decode_root(b).ok()) {
        Some(r) => r,
        None => {
            gc_keep_current(s, syscalls);
            return;
        }
    };
    if super::map_wire::names_digest(root.children, &candidate) {
        gc_keep_current(s, syscalls);
        return;
    }
    if root.depth == 1 {
        s.gc_roots_pos = s.gc_roots_pos.wrapping_add(1);
        gc_walk_next_root(s, syscalls);
        return;
    }
    let mut n = 0usize;
    while n < super::map_wire::PAGE_ENTRIES {
        match root.child(n) {
            Some(d) => s.gc_leaves[n] = d,
            None => break,
        }
        n += 1;
    }
    s.gc_leaves_len = n as u16;
    s.gc_leaves_pos = 0;
    gc_walk_next_leaf(s, syscalls);
}

/// Read the next written leaf of the current root, or move to the next
/// root. Never-written leaves are skipped without a read.
unsafe fn gc_walk_next_leaf(s: &mut ModuleState, syscalls: &super::SyscallTable) {
    while s.gc_leaves_pos < s.gc_leaves_len
        && s.gc_leaves[s.gc_leaves_pos as usize] == super::map_wire::ZERO_DIGEST
    {
        s.gc_leaves_pos += 1;
    }
    if s.gc_leaves_pos < s.gc_leaves_len {
        let digest = s.gc_leaves[s.gc_leaves_pos as usize];
        gc_walk_read(s, syscalls, &digest, GC_OP_MAP_LEAF);
        return;
    }
    s.gc_leaves_len = 0;
    s.gc_leaves_pos = 0;
    s.gc_roots_pos = s.gc_roots_pos.wrapping_add(1);
    gc_walk_next_root(s, syscalls);
}

unsafe fn gc_apply_map_leaf(s: &mut ModuleState, syscalls: &super::SyscallTable, resp: &[u8]) {
    s.gc_map_reads = s.gc_map_reads.wrapping_add(1);
    let candidate = s.gc_digests[s.gc_q_pos as usize];
    let leaf = match gc_page_bytes(resp).and_then(|b| super::map_wire::decode_leaf(b).ok()) {
        Some(l) => l,
        None => {
            gc_keep_current(s, syscalls);
            return;
        }
    };
    if super::map_wire::names_digest(leaf.digests, &candidate) {
        gc_keep_current(s, syscalls);
        return;
    }
    s.gc_leaves_pos += 1;
    gc_walk_next_leaf(s, syscalls);
}

unsafe fn gc_apply_obj_remove(s: &mut ModuleState, syscalls: &super::SyscallTable, ack: u8) {
    // The body is deleted only on a DEFINITE answer about the
    // descriptor: removed, or absent. A generic failure means the
    // index could not say — a WAL or I/O error is indistinguishable
    // from absence at that point — and deleting the body under it
    // would strand a descriptor pointing at bytes that are gone.
    // Retain both and let a later pass re-prove it.
    match ack {
        super::obj_wire::OP_OBJ_REMOVE => {
            s.gc_obj_deleted = s.gc_obj_deleted.wrapping_add(1);
            gc_delete_body(s, syscalls);
        }
        // Absent is the normal case for a body whose composed write
        // never reached its object stage.
        super::obj_wire::ACK_ABSENT => gc_delete_body(s, syscalls),
        _ => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            s.gc_kept = s.gc_kept.wrapping_add(1);
            gc_release_current(s, syscalls);
        }
    }
}

unsafe fn gc_apply_delete(s: &mut ModuleState, syscalls: &super::SyscallTable, resp: &[u8]) {
    if resp.first() == Some(&super::body_wire::OP_DELETE) {
        s.gc_deleted = s.gc_deleted.wrapping_add(1);
    } else {
        s.apply_errors = s.apply_errors.wrapping_add(1);
    }
    gc_release_current(s, syscalls);
}

unsafe fn gc_next(s: &mut ModuleState, syscalls: &super::SyscallTable) {
    s.gc_check_cursor = 0;
    s.gc_q_pos = s.gc_q_pos.wrapping_add(1);
    if s.gc_q_pos < s.gc_q_len {
        gc_begin_current(s, syscalls);
    } else {
        s.gc_q_len = 0;
        s.gc_q_pos = 0;
        if core::mem::replace(&mut s.gc_wrapped, 0) != 0 {
            gc_advance_phase(s);
        }
    }
}

// ── Streamed AdminPutFile + path reads ────────────────────────────

unsafe fn free_spf(s: &mut ModuleState, idx: u16) {
    if (idx as usize) < super::limits::ADMIN_STREAMED_PUTFILE {
        s.spf[idx as usize].in_use = 0;
    }
}

/// OPEN: stash the metadata, open a body-plane stream for the
/// declared digest.
unsafe fn handle_put_file_open(s: &mut ModuleState, syscalls: &super::SyscallTable, bytes: &[u8]) {
    let req = match super::admin::decode_put_file_open(bytes) {
        Ok(r) => r,
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return;
        }
    };
    let refuse = |s: &mut ModuleState, syscalls: &super::SyscallTable, cid: u32, status: u8| unsafe {
        if let Ok(n) = super::admin::encode_put_file_open_ack(&mut s.scratch, cid, status, 0) {
            reply_staged(s, syscalls, n);
        }
    };
    let nak = |s: &mut ModuleState, syscalls: &super::SyscallTable, cid: u32| {
        refuse(s, syscalls, cid, super::admin::STATUS_NAK)
    };
    if s.body_req_chan < 0
        || req.namespace_root.len() > NS_ROOT_BUF
        || req.path.len() > NS_PATH_BUF
        || req.digest.len() != 32
    {
        nak(s, syscalls, req.correlation_id);
        return;
    }
    let idx = match (0..super::limits::ADMIN_STREAMED_PUTFILE).find(|&i| s.spf[i].in_use == 0) {
        Some(i) => i,
        None => {
            // Every streaming slot is taken. Well-formed, just not
            // now — the caller should back off, not give up.
            refuse(s, syscalls, req.correlation_id, super::admin::STATUS_BUSY);
            return;
        }
    };
    {
        let e = &mut s.spf[idx];
        e.in_use = 1;
        e.wid = 0;
        e.wid_valid = 0;
        e.kind = req.kind;
        e.revision = req.revision;
        e.total_len = req.total_len;
        e.digest.copy_from_slice(req.digest);
        e.ns_root_len = req.namespace_root.len() as u8;
        e.ns_root[..req.namespace_root.len()].copy_from_slice(req.namespace_root);
        e.path_len = req.path.len() as u8;
        e.path[..req.path.len()].copy_from_slice(req.path);
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(req.digest);
    let n = match super::body_wire::encode_wopen_req(&mut s.scratch, &digest, req.total_len) {
        Ok(n) => n,
        Err(_) => {
            free_spf(s, idx as u16);
            nak(s, syscalls, req.correlation_id);
            return;
        }
    };
    if !enqueue_pending(
        s,
        Stream::Body,
        req.correlation_id,
        super::admin::OP_PUT_FILE_OPEN,
        idx as u16,
    ) {
        free_spf(s, idx as u16);
        nak(s, syscalls, req.correlation_id);
        return;
    }
    let wrote = (syscalls.channel_write)(s.body_req_chan, s.scratch.as_ptr(), n);
    if wrote < 0 || (wrote as usize) != n {
        let _ = dequeue_pending(s, Stream::Body);
        free_spf(s, idx as u16);
        nak(s, syscalls, req.correlation_id);
        return;
    }
    s.forwarded = s.forwarded.wrapping_add(1);
}

unsafe fn handle_spf_open_response(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    entry: PendingDownstream,
    body_resp: &[u8],
) {
    let idx = entry.putfile_idx;
    let wid = match super::body_wire::decode_wopen_resp(body_resp) {
        Ok(w) => w,
        Err(_) => {
            free_spf(s, idx);
            if let Ok(n) = super::admin::encode_put_file_open_ack(
                &mut s.scratch,
                entry.correlation_id,
                super::admin::STATUS_NAK,
                0,
            ) {
                reply_staged(s, syscalls, n);
            }
            return;
        }
    };
    if (idx as usize) < super::limits::ADMIN_STREAMED_PUTFILE {
        s.spf[idx as usize].wid = wid;
        s.spf[idx as usize].wid_valid = 1;
    }
    if let Ok(n) = super::admin::encode_put_file_open_ack(
        &mut s.scratch,
        entry.correlation_id,
        super::admin::STATUS_OK,
        idx as u8,
    ) {
        reply_staged(s, syscalls, n);
    }
}

unsafe fn handle_put_file_chunk(s: &mut ModuleState, syscalls: &super::SyscallTable, bytes: &[u8]) {
    let (cid, pfid, chunk) = match super::admin::decode_put_file_chunk(bytes) {
        Ok(v) => v,
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return;
        }
    };
    let idx = pfid as usize;
    let nak = |s: &mut ModuleState, syscalls: &super::SyscallTable| unsafe {
        if let Ok(n) =
            super::admin::encode_put_file_chunk_ack(&mut s.scratch, cid, super::admin::STATUS_NAK)
        {
            reply_staged(s, syscalls, n);
        }
    };
    if idx >= super::limits::ADMIN_STREAMED_PUTFILE
        || s.spf[idx].in_use == 0
        || s.spf[idx].wid_valid == 0
    {
        nak(s, syscalls);
        return;
    }
    let wid = s.spf[idx].wid;
    let n = match super::body_wire::encode_wappend_req(&mut s.scratch, wid, chunk) {
        Ok(n) => n,
        Err(_) => {
            nak(s, syscalls);
            return;
        }
    };
    if !enqueue_pending(
        s,
        Stream::Body,
        cid,
        super::admin::OP_PUT_FILE_CHUNK,
        pfid as u16,
    ) {
        nak(s, syscalls);
        return;
    }
    let wrote = (syscalls.channel_write)(s.body_req_chan, s.scratch.as_ptr(), n);
    if wrote < 0 || (wrote as usize) != n {
        let _ = dequeue_pending(s, Stream::Body);
        nak(s, syscalls);
        return;
    }
    s.forwarded = s.forwarded.wrapping_add(1);
}

unsafe fn handle_put_file_commit(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    bytes: &[u8],
) {
    let (cid, pfid) = match super::admin::decode_put_file_commit(bytes) {
        Ok(v) => v,
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return;
        }
    };
    let idx = pfid as usize;
    if idx >= super::limits::ADMIN_STREAMED_PUTFILE
        || s.spf[idx].in_use == 0
        || s.spf[idx].wid_valid == 0
    {
        emit_putfile_nak(s, syscalls, cid);
        return;
    }
    let wid = s.spf[idx].wid;
    let n = match super::body_wire::encode_wcommit_req(&mut s.scratch, wid) {
        Ok(n) => n,
        Err(_) => {
            free_spf(s, pfid as u16);
            emit_putfile_nak(s, syscalls, cid);
            return;
        }
    };
    if !enqueue_pending(
        s,
        Stream::Body,
        cid,
        super::admin::OP_PUT_FILE_COMMIT,
        pfid as u16,
    ) {
        free_spf(s, pfid as u16);
        emit_putfile_nak(s, syscalls, cid);
        return;
    }
    let wrote = (syscalls.channel_write)(s.body_req_chan, s.scratch.as_ptr(), n);
    if wrote < 0 || (wrote as usize) != n {
        let _ = dequeue_pending(s, Stream::Body);
        free_spf(s, pfid as u16);
        emit_putfile_nak(s, syscalls, cid);
        return;
    }
    s.forwarded = s.forwarded.wrapping_add(1);
}

/// The body plane committed the stream — verify the digest it
/// returns matches the declaration, then chain into the object +
/// bind stages exactly like a single-frame PutFile.
unsafe fn handle_spf_commit_response(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    entry: PendingDownstream,
    body_resp: &[u8],
) {
    let idx = entry.putfile_idx;
    let spf = if (idx as usize) < super::limits::ADMIN_STREAMED_PUTFILE {
        s.spf[idx as usize]
    } else {
        emit_putfile_nak(s, syscalls, entry.correlation_id);
        return;
    };
    free_spf(s, idx);
    let ok = matches!(
        super::body_wire::decode_wcommit_resp(body_resp),
        Ok(d) if d == spf.digest
    );
    if !ok {
        emit_putfile_nak(s, syscalls, entry.correlation_id);
        return;
    }
    let slot_idx = match allocate_putfile_slot(s) {
        Some(i) => i,
        None => {
            // Full, not wrong — see `emit_putfile_busy`.
            emit_putfile_busy(s, syscalls, entry.correlation_id);
            return;
        }
    };
    {
        let slot = &mut s.putfiles[slot_idx as usize];
        slot.correlation_id = entry.correlation_id;
        slot.kind = spf.kind;
        slot.digest = spf.digest;
        slot.body_len = spf.total_len.min(u32::MAX as u64) as u32;
        slot.revision = spf.revision;
        slot.ns_root_len = spf.ns_root_len;
        slot.ns_root = spf.ns_root;
        slot.path_len = spf.path_len;
        slot.path = spf.path;
    }
    emit_putfile_object_stage(s, syscalls, slot_idx, entry.correlation_id);
}

/// STAT_FILE / READ_FILE_RANGE: forward the namespace lookup with
/// the aux (off, len) riding the pending entry.
unsafe fn handle_stat_file(s: &mut ModuleState, syscalls: &super::SyscallTable, bytes: &[u8]) {
    let req = match super::admin::decode_stat_file(bytes) {
        Ok(r) => r,
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return;
        }
    };
    dispatch_pathread_lookup(
        s,
        syscalls,
        super::admin::OP_STAT_FILE,
        req.correlation_id,
        req.namespace_root,
        req.path,
        0,
        0,
    );
}

unsafe fn handle_read_file_range(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    bytes: &[u8],
) {
    let req = match super::admin::decode_read_file_range(bytes) {
        Ok(r) => r,
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return;
        }
    };
    dispatch_pathread_lookup(
        s,
        syscalls,
        super::admin::OP_READ_FILE_RANGE,
        req.correlation_id,
        req.namespace_root,
        req.path,
        req.off,
        req.len,
    );
}

unsafe fn emit_pathread_nak(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    admin_op: u8,
    cid: u32,
    status: u8,
) {
    let n = if admin_op == super::admin::OP_STAT_FILE {
        super::admin::encode_stat_file_ack(&mut s.scratch, cid, status, 0)
    } else {
        super::admin::encode_read_file_range_ack(&mut s.scratch, cid, status, None)
    };
    if let Ok(n) = n {
        reply_staged(s, syscalls, n);
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "bounded no_std step functions pass explicit scalar params"
)]
unsafe fn dispatch_pathread_lookup(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    admin_op: u8,
    cid: u32,
    root: &[u8],
    path: &[u8],
    off: u64,
    len: u32,
) {
    if s.body_req_chan < 0 {
        emit_pathread_nak(s, syscalls, admin_op, cid, super::admin::STATUS_NAK);
        return;
    }
    let n = match super::ns_wire::encode_lookup_req(&mut s.scratch, root, path) {
        Ok(n) => n,
        Err(_) => {
            emit_pathread_nak(s, syscalls, admin_op, cid, super::admin::STATUS_NAK);
            return;
        }
    };
    if !enqueue_pending(s, Stream::Namespace, cid, admin_op, 0) {
        emit_pathread_nak(s, syscalls, admin_op, cid, super::admin::STATUS_NAK);
        return;
    }
    set_ns_tail_aux(s, off, len);
    let wrote = (syscalls.channel_write)(s.ns_req_chan, s.scratch.as_ptr(), n);
    if wrote < 0 || (wrote as usize) != n {
        let _ = dequeue_pending(s, Stream::Namespace);
        emit_pathread_nak(s, syscalls, admin_op, cid, super::admin::STATUS_NAK);
        return;
    }
    s.forwarded = s.forwarded.wrapping_add(1);
}

/// Stamp aux (off, len) onto the just-enqueued namespace pending.
unsafe fn set_ns_tail_aux(s: &mut ModuleState, off: u64, len: u32) {
    let prev = (s
        .ns_tail
        .wrapping_add(super::limits::ADMIN_PENDING as u32 - 1))
        % super::limits::ADMIN_PENDING as u32;
    s.ns_pending[prev as usize].aux_off = off;
    s.ns_pending[prev as usize].aux_len = len;
}

/// The namespace answered a STAT/RANGE lookup: resolve the digest
/// and forward the body op (HEAD for stat, RANGE for range).
unsafe fn handle_pathread_lookup_response(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    entry: PendingDownstream,
    ns_resp: &[u8],
) {
    let digest = match super::ns_wire::decode_lookup_resp(ns_resp) {
        Ok(super::ns_wire::DecodedLookupResp::Found { object_id, .. }) => {
            match digest_from_object_id(object_id) {
                Some(d) => d,
                None => {
                    emit_pathread_nak(
                        s,
                        syscalls,
                        entry.admin_op,
                        entry.correlation_id,
                        super::admin::STATUS_NAK,
                    );
                    return;
                }
            }
        }
        Ok(super::ns_wire::DecodedLookupResp::NotFound) => {
            emit_pathread_nak(
                s,
                syscalls,
                entry.admin_op,
                entry.correlation_id,
                super::admin::STATUS_NOT_FOUND,
            );
            return;
        }
        Err(_) => {
            emit_pathread_nak(
                s,
                syscalls,
                entry.admin_op,
                entry.correlation_id,
                super::admin::STATUS_NAK,
            );
            return;
        }
    };
    let n = if entry.admin_op == super::admin::OP_STAT_FILE {
        super::body_wire::encode_head_req(&mut s.scratch, &digest)
    } else {
        super::body_wire::encode_range_req(&mut s.scratch, &digest, entry.aux_off, entry.aux_len)
    };
    let n = match n {
        Ok(n) => n,
        Err(_) => {
            emit_pathread_nak(
                s,
                syscalls,
                entry.admin_op,
                entry.correlation_id,
                super::admin::STATUS_NAK,
            );
            return;
        }
    };
    if !enqueue_pending(s, Stream::Body, entry.correlation_id, entry.admin_op, 0) {
        emit_pathread_nak(
            s,
            syscalls,
            entry.admin_op,
            entry.correlation_id,
            super::admin::STATUS_NAK,
        );
        return;
    }
    let wrote = (syscalls.channel_write)(s.body_req_chan, s.scratch.as_ptr(), n);
    if wrote < 0 || (wrote as usize) != n {
        let _ = dequeue_pending(s, Stream::Body);
        emit_pathread_nak(
            s,
            syscalls,
            entry.admin_op,
            entry.correlation_id,
            super::admin::STATUS_NAK,
        );
        return;
    }
    s.forwarded = s.forwarded.wrapping_add(1);
}

/// The body plane answered a RANGE — re-frame as the admin ack.
unsafe fn handle_range_body_response(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    entry: PendingDownstream,
    body_resp: &[u8],
) {
    let resp_n = if body_resp.first() == Some(&super::body_wire::OP_RANGE) {
        let bytes = match super::body_wire::decode_range_resp(body_resp) {
            Ok(b) => b,
            Err(_) => {
                emit_pathread_nak(
                    s,
                    syscalls,
                    entry.admin_op,
                    entry.correlation_id,
                    super::admin::STATUS_NAK,
                );
                return;
            }
        };
        let owned: heapless_copy::Vec<u8, { super::body_wire::MAX_BODY }> =
            heapless_copy::Vec::from_slice(bytes);
        match super::admin::encode_read_file_range_ack(
            &mut s.scratch,
            entry.correlation_id,
            super::admin::STATUS_OK,
            Some(owned.as_slice()),
        ) {
            Ok(n) => n,
            Err(_) => {
                emit_pathread_nak(
                    s,
                    syscalls,
                    entry.admin_op,
                    entry.correlation_id,
                    super::admin::STATUS_NAK,
                );
                return;
            }
        }
    } else {
        let status = if body_resp.len() >= 2
            && body_resp[0] == super::body_wire::OP_NAK
            && body_resp[1] == super::body_wire::ERR_NOT_FOUND
        {
            super::admin::STATUS_NOT_FOUND
        } else {
            super::admin::STATUS_NAK
        };
        emit_pathread_nak(s, syscalls, entry.admin_op, entry.correlation_id, status);
        return;
    };
    reply_staged(s, syscalls, resp_n);
}

// ── AdminPutFile state machine ────────────────────────────────────

unsafe fn handle_admin_put_file(s: &mut ModuleState, syscalls: &super::SyscallTable, bytes: &[u8]) {
    let req = match super::admin::decode_admin_put_file(bytes) {
        Ok(r) => r,
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return;
        }
    };
    // All three downstream channels must be wired for PutFile.
    if s.body_req_chan < 0 || s.obj_req_chan < 0 {
        emit_putfile_nak(s, syscalls, req.correlation_id);
        return;
    }
    if req.namespace_root.len() > NS_ROOT_BUF || req.path.len() > NS_PATH_BUF {
        emit_putfile_nak(s, syscalls, req.correlation_id);
        return;
    }

    let slot_idx = match allocate_putfile_slot(s) {
        Some(i) => i,
        None => {
            emit_putfile_busy(s, syscalls, req.correlation_id);
            s.apply_errors = s.apply_errors.wrapping_add(1);
            return;
        }
    };
    {
        let slot = &mut s.putfiles[slot_idx as usize];
        slot.stage = PUTFILE_STAGE_BODY;
        slot.correlation_id = req.correlation_id;
        slot.kind = req.kind;
        slot.digest = [0u8; 32];
        slot.body_len = req.body.len() as u32;
        slot.revision = req.revision;
        slot.ns_root_len = req.namespace_root.len() as u8;
        slot.ns_root[..req.namespace_root.len()].copy_from_slice(req.namespace_root);
        slot.path_len = req.path.len() as u8;
        slot.path[..req.path.len()].copy_from_slice(req.path);
    }

    // Stage 1: forward the body bytes to body_store.
    let n = match super::body_wire::encode_put_req(&mut s.scratch, req.body) {
        Ok(n) => n,
        Err(_) => {
            free_putfile_slot(s, slot_idx);
            emit_putfile_nak(s, syscalls, req.correlation_id);
            return;
        }
    };
    if !enqueue_pending(
        s,
        Stream::Body,
        req.correlation_id,
        super::admin::OP_PUT_FILE,
        slot_idx,
    ) {
        free_putfile_slot(s, slot_idx);
        emit_putfile_nak(s, syscalls, req.correlation_id);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    let wrote = (syscalls.channel_write)(s.body_req_chan, s.scratch.as_ptr(), n);
    if wrote < 0 || (wrote as usize) != n {
        let _ = dequeue_pending(s, Stream::Body);
        free_putfile_slot(s, slot_idx);
        emit_putfile_nak(s, syscalls, req.correlation_id);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    s.forwarded = s.forwarded.wrapping_add(1);
}

unsafe fn handle_putfile_body_response(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    entry: PendingDownstream,
    body_resp: &[u8],
) {
    let slot_idx = entry.putfile_idx;
    let op = super::body_wire::peek_opcode(body_resp).unwrap_or(0xFF);
    if op != super::body_wire::OP_PUT {
        // body_store NAKed.
        free_putfile_slot(s, slot_idx);
        emit_putfile_nak(s, syscalls, entry.correlation_id);
        return;
    }
    let digest = match super::body_wire::decode_put_resp(body_resp) {
        Ok(d) => d,
        Err(_) => {
            free_putfile_slot(s, slot_idx);
            emit_putfile_nak(s, syscalls, entry.correlation_id);
            return;
        }
    };
    {
        let slot = &mut s.putfiles[slot_idx as usize];
        slot.digest.copy_from_slice(digest);
    }
    emit_putfile_object_stage(s, syscalls, slot_idx, entry.correlation_id);
}

/// Stage 2 of the composed put: write the object descriptor.
/// Entered from the single-frame path (body PutResp) AND the
/// streamed path (WCommitResp) — the slot's digest must be set.
unsafe fn emit_putfile_object_stage(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    slot_idx: u16,
    correlation_id: u32,
) {
    {
        let slot = &mut s.putfiles[slot_idx as usize];
        slot.stage = PUTFILE_STAGE_OBJECT;
    }

    // Stage 2: write the object descriptor. The object's id is
    // the digest hex; the namespace + key fields come from the
    // putfile slot. content_hash = "sha256:<hex>".
    let (object_id_str, body_len, ns_len, ns_root, path_len, path, kind, revision) = {
        let slot = &s.putfiles[slot_idx as usize];
        let mut id = [0u8; 7 + 64]; // "sha256:" + hex
        id[..7].copy_from_slice(b"sha256:");
        super::body_wire::hex_lower_into(&slot.digest, &mut id[7..7 + 64]);
        (
            id,
            slot.body_len,
            slot.ns_root_len as usize,
            slot.ns_root,
            slot.path_len as usize,
            slot.path,
            slot.kind,
            slot.revision,
        )
    };
    let object_id_slice = &object_id_str[..7 + 64];
    // The object wire `decode_put` returns a `PutFields` carrying
    // (id, namespace, key, content_hash, size, revision, data_class,
    // replica_count, erasure). For PutFile we set
    //   id = "sha256:<hex>"
    //   namespace = ns_root
    //   key = path
    //   content_hash = same as id
    //   size = body_len
    //   data_class = 0 (Local), replica_count = 1, erasure = None.
    let fields = super::obj_wire::PutFields {
        id: object_id_slice,
        namespace: &ns_root[..ns_len],
        key: &path[..path_len],
        content_hash: object_id_slice,
        size_bytes: body_len as u64,
        revision,
        data_class: 0,
        replica_count: 1,
        erasure: None,
    };
    let _ = kind; // used in BIND stage, not object stage
    let n = match super::obj_wire::encode_put(&mut s.scratch, &fields) {
        Ok(n) => n,
        Err(_) => {
            free_putfile_slot(s, slot_idx);
            emit_putfile_nak(s, syscalls, correlation_id);
            return;
        }
    };
    if !enqueue_pending(
        s,
        Stream::Object,
        correlation_id,
        super::admin::OP_PUT_FILE,
        slot_idx,
    ) {
        free_putfile_slot(s, slot_idx);
        emit_putfile_nak(s, syscalls, correlation_id);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    let wrote = (syscalls.channel_write)(s.obj_req_chan, s.scratch.as_ptr(), n);
    if wrote < 0 || (wrote as usize) != n {
        let _ = dequeue_pending(s, Stream::Object);
        free_putfile_slot(s, slot_idx);
        emit_putfile_nak(s, syscalls, correlation_id);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    s.forwarded = s.forwarded.wrapping_add(1);
}

unsafe fn handle_putfile_object_response(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    entry: PendingDownstream,
    ack_byte: u8,
) {
    let slot_idx = entry.putfile_idx;
    if ack_byte != super::obj_wire::OP_OBJ_PUT {
        free_putfile_slot(s, slot_idx);
        // A quota refusal keeps its identity all the way out. The
        // body is already stored and will be reclaimed by the orphan
        // sweep like any unbound blob; what the client needs is to
        // know that waiting will not help.
        if ack_byte == super::obj_wire::ACK_QUOTA {
            emit_putfile_quota(s, syscalls, entry.correlation_id);
        } else {
            emit_putfile_nak(s, syscalls, entry.correlation_id);
        }
        return;
    }
    {
        let slot = &mut s.putfiles[slot_idx as usize];
        slot.stage = PUTFILE_STAGE_BIND;
    }

    // Stage 3: bind the path to the new object id.
    let (object_id_str, ns_len, ns_root, path_len, path, kind, revision) = {
        let slot = &s.putfiles[slot_idx as usize];
        let mut id = [0u8; 7 + 64];
        id[..7].copy_from_slice(b"sha256:");
        super::body_wire::hex_lower_into(&slot.digest, &mut id[7..7 + 64]);
        (
            id,
            slot.ns_root_len as usize,
            slot.ns_root,
            slot.path_len as usize,
            slot.path,
            slot.kind,
            slot.revision,
        )
    };
    let object_id_slice = &object_id_str[..7 + 64];
    let n = match super::ns_wire::encode_bind(
        &mut s.scratch,
        &ns_root[..ns_len],
        &path[..path_len],
        object_id_slice,
        kind,
        revision,
    ) {
        Ok(n) => n,
        Err(_) => {
            free_putfile_slot(s, slot_idx);
            emit_putfile_nak(s, syscalls, entry.correlation_id);
            return;
        }
    };
    if !enqueue_pending(
        s,
        Stream::Namespace,
        entry.correlation_id,
        super::admin::OP_PUT_FILE,
        slot_idx,
    ) {
        free_putfile_slot(s, slot_idx);
        emit_putfile_nak(s, syscalls, entry.correlation_id);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    let wrote = (syscalls.channel_write)(s.ns_req_chan, s.scratch.as_ptr(), n);
    if wrote < 0 || (wrote as usize) != n {
        let _ = dequeue_pending(s, Stream::Namespace);
        free_putfile_slot(s, slot_idx);
        emit_putfile_nak(s, syscalls, entry.correlation_id);
        s.apply_errors = s.apply_errors.wrapping_add(1);
        return;
    }
    s.forwarded = s.forwarded.wrapping_add(1);
}

unsafe fn handle_putfile_bind_response(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    entry: PendingDownstream,
    status: u8,
) {
    let slot_idx = entry.putfile_idx;
    let digest = {
        let slot = &s.putfiles[slot_idx as usize];
        slot.digest
    };
    let resp_n = if status == super::admin::STATUS_OK {
        match super::admin::encode_admin_put_file_ack(
            &mut s.scratch,
            entry.correlation_id,
            super::admin::STATUS_OK,
            Some(&digest),
        ) {
            Ok(n) => n,
            Err(_) => {
                free_putfile_slot(s, slot_idx);
                s.apply_errors = s.apply_errors.wrapping_add(1);
                return;
            }
        }
    } else {
        match super::admin::encode_admin_put_file_ack(
            &mut s.scratch,
            entry.correlation_id,
            super::admin::STATUS_NAK,
            None,
        ) {
            Ok(n) => n,
            Err(_) => {
                free_putfile_slot(s, slot_idx);
                s.apply_errors = s.apply_errors.wrapping_add(1);
                return;
            }
        }
    };
    reply_staged(s, syscalls, resp_n);
    free_putfile_slot(s, slot_idx);
}

/// Refuse a composed write because the table is FULL, not because
/// anything was wrong with it.
///
/// The distinction reaches the client: the gateway turns this into a
/// 503 with a Retry-After, where a generic NAK becomes a 500. An S3
/// client backs off on the first and gives up on the second, so
/// collapsing them costs real availability under exactly the load
/// that produces them.
unsafe fn emit_putfile_busy(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    correlation_id: u32,
) {
    emit_putfile_status(s, syscalls, correlation_id, super::admin::STATUS_BUSY)
}

/// Refuse a composed write because the tenant's quota would be
/// crossed. Unlike BUSY, waiting will not help — the remedy is the
/// tenant's or the operator's, and the status has to say so or a
/// client retries forever against a ceiling.
unsafe fn emit_putfile_quota(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    correlation_id: u32,
) {
    emit_putfile_status(s, syscalls, correlation_id, super::admin::STATUS_QUOTA)
}

unsafe fn emit_putfile_status(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    correlation_id: u32,
    status: u8,
) {
    let mut buf = [0u8; 6];
    if super::admin::encode_admin_put_file_ack(&mut buf, correlation_id, status, None).is_ok() {
        let _ = (syscalls.channel_write)(s.admin_out_chan, buf.as_ptr(), buf.len());
    }
}

unsafe fn emit_putfile_nak(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    correlation_id: u32,
) {
    let mut buf = [0u8; 6];
    if super::admin::encode_admin_put_file_ack(
        &mut buf,
        correlation_id,
        super::admin::STATUS_NAK,
        None,
    )
    .is_ok()
    {
        reply_bytes(s, syscalls, &buf);
    }
}

unsafe fn emit_bind_nak(s: &mut ModuleState, syscalls: &super::SyscallTable, correlation_id: u32) {
    let mut buf = [0u8; 6];
    if super::admin::encode_admin_bind_ack(&mut buf, correlation_id, super::admin::STATUS_NAK)
        .is_ok()
    {
        reply_bytes(s, syscalls, &buf);
    }
}

unsafe fn emit_put_body_nak(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    correlation_id: u32,
) {
    let mut buf = [0u8; 6];
    if super::admin::encode_admin_put_body_ack(
        &mut buf,
        correlation_id,
        super::admin::STATUS_NAK,
        None,
    )
    .is_ok()
    {
        reply_bytes(s, syscalls, &buf);
    }
}

unsafe fn emit_get_body_nak(
    s: &mut ModuleState,
    syscalls: &super::SyscallTable,
    correlation_id: u32,
) {
    let mut buf = [0u8; 6];
    if super::admin::encode_admin_get_body_ack(
        &mut buf,
        correlation_id,
        super::admin::STATUS_NAK,
        None,
    )
    .is_ok()
    {
        reply_bytes(s, syscalls, &buf);
    }
}

// Tiny inline-vector helper to copy a slice off the scratch
// buffer before re-encoding into it. no_std-safe (just a stack
// array + a length).
mod heapless_copy {
    pub struct Vec<T, const N: usize> {
        data: [T; N],
        len: usize,
    }
    impl<const N: usize> Vec<u8, N> {
        pub fn from_slice(src: &[u8]) -> Self {
            let mut data = [0u8; N];
            let n = src.len().min(N);
            data[..n].copy_from_slice(&src[..n]);
            Self { data, len: n }
        }
        pub fn as_slice(&self) -> &[u8] {
            &self.data[..self.len]
        }
    }
}
