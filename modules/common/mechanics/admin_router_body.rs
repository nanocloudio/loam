// Step body for the `admin_router` PIC. Translates admin
// requests (loam_admin_wire) into the downstream PICs' native
// channel formats, then routes the responses back to the admin
// reply channel with the original correlation_id attached.
//
// Phase 4a + 4b + 4b.2 scope:
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

const MAX_OPS_PER_STEP: u32 = 4;
// Buffers derive from the body wire cap so a max-size body can't
// truncate on the way through the admin surface.
const READ_BUF: usize = super::body_wire::MAX_BODY + 128;
const PENDING_CAP: usize = 64;
const PUTFILE_CAP: usize = 16;
const SCRATCH: usize = super::body_wire::MAX_BODY + 128;
const NS_PATH_BUF: usize = 256;
const NS_ROOT_BUF: usize = 128;

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

pub const SPF_CAP: usize = 4;

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
    // Per-downstream pending FIFOs (head, tail, ring storage).
    pub ns_head: u32,
    pub ns_tail: u32,
    pub ns_pending: [PendingDownstream; PENDING_CAP],
    pub body_head: u32,
    pub body_tail: u32,
    pub body_pending: [PendingDownstream; PENDING_CAP],
    pub obj_head: u32,
    pub obj_tail: u32,
    pub obj_pending: [PendingDownstream; PENDING_CAP],
    pub putfiles: [PendingPutFile; PUTFILE_CAP],
    /// In-flight STREAMED put-files (large bodies): open → chunks →
    /// commit, then the commit chains into the standard object +
    /// bind stages via a PendingPutFile slot.
    pub spf: [StreamedPutFile; SPF_CAP],
    /// Orphan-body GC (active when `gc_interval` != 0): each
    /// interval, SCAN one page of body_store's digest inventory;
    /// for each digest ask the namespace whether `sha256:<hex>` is
    /// bound anywhere (OP_REFERENCED); unreferenced blobs are
    /// DELETEd. Never runs while a PutFile is in flight — the
    /// window between a body landing and its bind committing must
    /// not be collectable. Raw PutBody users must bind before the
    /// next GC pass or their blob is fair game.
    pub gc_interval: u32,
    pub gc_cursor: u32,
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
    pub ticks: u32,
    pub forwarded: u32,
    pub replied: u32,
    pub apply_errors: u32,
}

/// Internal pending-op markers for the GC's downstream requests —
/// outside the admin opcode space so drains can demux them.
const GC_OP_SCAN: u8 = 0xF0;
const GC_OP_CHECK: u8 = 0xF1;
const GC_OP_DELETE: u8 = 0xF2;

/// Host/test helper + server config: enable the orphan GC.
pub unsafe fn set_gc_interval(state_ptr: *mut u8, interval: u32) {
    let s = &mut *(state_ptr as *mut ModuleState);
    s.gc_interval = interval;
}

/// Phase 4a entry point (namespace-only). Kept so the existing
/// 3-test bind harness keeps working.
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

/// Phase 4b entry point: namespace + body_store wired.
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

/// Phase 4b.2 entry point: all four downstream PIC channel pairs
/// wired (namespace, body_store, object_index). Required for the
/// composed AdminPutFile op; AdminBind / AdminPutBody /
/// AdminGetBody still work with the previous entry points.
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
    let next = (tail.wrapping_add(1)) % PENDING_CAP as u32;
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
    *head = (head.wrapping_add(1)) % PENDING_CAP as u32;
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
    while handled < MAX_OPS_PER_STEP {
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
        let mut drained: u32 = 0;
        while drained < MAX_OPS_PER_STEP {
            let mut ack_buf = [0u8; 4096];
            let n = (syscalls.channel_read)(s.ns_resp_chan, ack_buf.as_mut_ptr(), ack_buf.len());
            if n <= 0 {
                break;
            }
            let ns_resp = &ack_buf[..n as usize];
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
                super::admin::OP_DELETE_FILE => {
                    let status = if ns_resp[0] == super::ns_wire::OP_UNBIND {
                        super::admin::STATUS_OK
                    } else {
                        super::admin::STATUS_NOT_FOUND
                    };
                    if let Ok(resp_n) = super::admin::encode_admin_delete_file_ack(
                        &mut s.scratch,
                        entry.correlation_id,
                        status,
                    ) {
                        let _ =
                            (syscalls.channel_write)(s.admin_out_chan, s.scratch.as_ptr(), resp_n);
                        s.replied = s.replied.wrapping_add(1);
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
                    let _ = (syscalls.channel_write)(s.admin_out_chan, s.scratch.as_ptr(), resp_n);
                    s.replied = s.replied.wrapping_add(1);
                }
            }
            drained = drained.wrapping_add(1);
        }
    }

    // ── 3. Drain downstream body_store responses, emit replies. ──
    if s.body_resp_chan >= 0 {
        let mut drained: u32 = 0;
        while drained < MAX_OPS_PER_STEP {
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
                        let _ = (syscalls.channel_write)(s.admin_out_chan, s.scratch.as_ptr(), n);
                        s.replied = s.replied.wrapping_add(1);
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
                        let _ = (syscalls.channel_write)(s.admin_out_chan, s.scratch.as_ptr(), n);
                        s.replied = s.replied.wrapping_add(1);
                    }
                }
                super::admin::OP_READ_FILE_RANGE => {
                    handle_range_body_response(s, syscalls, entry, body_resp);
                }
                GC_OP_SCAN => gc_apply_scan(s, syscalls, body_resp),
                GC_OP_DELETE => gc_apply_delete(s, syscalls, body_resp),
                _ => emit_body_admin_response(s, syscalls, entry, body_resp),
            }
            drained = drained.wrapping_add(1);
        }
    }

    // ── 4. Drain downstream object_index acks, advance PutFile state. ──
    if s.obj_resp_chan >= 0 {
        let mut drained: u32 = 0;
        while drained < MAX_OPS_PER_STEP {
            let mut ack_buf = [0u8; 8];
            let n = (syscalls.channel_read)(s.obj_resp_chan, ack_buf.as_mut_ptr(), ack_buf.len());
            if n <= 0 {
                break;
            }
            let ack_byte = ack_buf[0];
            let entry = match dequeue_pending(s, Stream::Object) {
                Some(e) => e,
                None => {
                    s.apply_errors = s.apply_errors.wrapping_add(1);
                    drained = drained.wrapping_add(1);
                    continue;
                }
            };
            handle_putfile_object_response(s, syscalls, entry, ack_byte);
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

/// Raw keyed body write (volume extents). Body-plane forward of
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

/// Raw body delete by key/digest (the volume-delete path's
/// per-extent cleanup). Fans out downstream via the router.
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
        let _ = (syscalls.channel_write)(s.admin_out_chan, s.scratch.as_ptr(), n);
        s.replied = s.replied.wrapping_add(1);
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
            let _ = (syscalls.channel_write)(s.admin_out_chan, s.scratch.as_ptr(), resp_n);
            s.replied = s.replied.wrapping_add(1);
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
            let _ = (syscalls.channel_write)(s.admin_out_chan, s.scratch.as_ptr(), resp_n);
            s.replied = s.replied.wrapping_add(1);
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
            let _ = (syscalls.channel_write)(s.admin_out_chan, s.scratch.as_ptr(), resp_n);
            s.replied = s.replied.wrapping_add(1);
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
            let _ = (syscalls.channel_write)(s.admin_out_chan, s.scratch.as_ptr(), resp_n);
            s.replied = s.replied.wrapping_add(1);
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
            let _ = (syscalls.channel_write)(s.admin_out_chan, s.scratch.as_ptr(), resp_n);
            s.replied = s.replied.wrapping_add(1);
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
        let _ = (syscalls.channel_write)(s.admin_out_chan, s.scratch.as_ptr(), n);
        s.replied = s.replied.wrapping_add(1);
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
                let _ = (syscalls.channel_write)(s.admin_out_chan, s.scratch.as_ptr(), rn);
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
            let _ = (syscalls.channel_write)(s.admin_out_chan, s.scratch.as_ptr(), rn);
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
            let _ = (syscalls.channel_write)(s.admin_out_chan, s.scratch.as_ptr(), rn);
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
        let _ = (syscalls.channel_write)(s.admin_out_chan, s.scratch.as_ptr(), n);
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
    let _ = (syscalls.channel_write)(s.admin_out_chan, s.scratch.as_ptr(), resp_n);
    s.replied = s.replied.wrapping_add(1);
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
    let prev = (tail.wrapping_add(PENDING_CAP as u32 - 1)) % PENDING_CAP as u32;
    ring[prev as usize].in_use = 0;
    *tail = prev;
}

/// Ask body_store for one inventory page.
unsafe fn gc_kick(s: &mut ModuleState, syscalls: &super::SyscallTable) {
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
            // Keyed blobs (volume extents, EC shards) are NOT
            // orphan-GC's to collect: their keys are never bound in
            // the namespace by design — lifecycle belongs to their
            // writers (volume delete / EC scrub stray-delete).
            let mut kept = 0usize;
            for i in 0..count {
                if keyed[i] == 0 {
                    s.gc_digests[kept] = digests[i];
                    kept += 1;
                }
            }
            if kept > 0 {
                s.gc_q_len = kept as u8;
                s.gc_q_pos = 0;
                gc_check_current(s, syscalls);
            }
        }
        Err(_) => {
            s.apply_errors = s.apply_errors.wrapping_add(1);
            s.gc_cursor = 0;
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
            gc_next(s, syscalls);
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
        gc_next(s, syscalls);
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
        gc_next(s, syscalls);
        return;
    }
    let digest = s.gc_digests[s.gc_q_pos as usize];
    let req_n = match super::body_wire::encode_delete_req(&mut s.scratch, &digest) {
        Ok(n) => n,
        Err(_) => {
            gc_next(s, syscalls);
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
        gc_next(s, syscalls);
    }
}

unsafe fn gc_apply_delete(s: &mut ModuleState, syscalls: &super::SyscallTable, resp: &[u8]) {
    if resp.first() == Some(&super::body_wire::OP_DELETE) {
        s.gc_deleted = s.gc_deleted.wrapping_add(1);
    } else {
        s.apply_errors = s.apply_errors.wrapping_add(1);
    }
    gc_next(s, syscalls);
}

unsafe fn gc_next(s: &mut ModuleState, syscalls: &super::SyscallTable) {
    s.gc_check_cursor = 0;
    s.gc_q_pos = s.gc_q_pos.wrapping_add(1);
    if s.gc_q_pos < s.gc_q_len {
        gc_check_current(s, syscalls);
    } else {
        s.gc_q_len = 0;
        s.gc_q_pos = 0;
    }
}

// ── Streamed AdminPutFile + path reads ────────────────────────────

unsafe fn free_spf(s: &mut ModuleState, idx: u16) {
    if (idx as usize) < SPF_CAP {
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
    let nak = |s: &mut ModuleState, syscalls: &super::SyscallTable, cid: u32| unsafe {
        if let Ok(n) =
            super::admin::encode_put_file_open_ack(&mut s.scratch, cid, super::admin::STATUS_NAK, 0)
        {
            let _ = (syscalls.channel_write)(s.admin_out_chan, s.scratch.as_ptr(), n);
        }
    };
    if s.body_req_chan < 0
        || req.namespace_root.len() > NS_ROOT_BUF
        || req.path.len() > NS_PATH_BUF
        || req.digest.len() != 32
    {
        nak(s, syscalls, req.correlation_id);
        return;
    }
    let idx = match (0..SPF_CAP).find(|&i| s.spf[i].in_use == 0) {
        Some(i) => i,
        None => {
            nak(s, syscalls, req.correlation_id);
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
                let _ = (syscalls.channel_write)(s.admin_out_chan, s.scratch.as_ptr(), n);
            }
            return;
        }
    };
    if (idx as usize) < SPF_CAP {
        s.spf[idx as usize].wid = wid;
        s.spf[idx as usize].wid_valid = 1;
    }
    if let Ok(n) = super::admin::encode_put_file_open_ack(
        &mut s.scratch,
        entry.correlation_id,
        super::admin::STATUS_OK,
        idx as u8,
    ) {
        let _ = (syscalls.channel_write)(s.admin_out_chan, s.scratch.as_ptr(), n);
        s.replied = s.replied.wrapping_add(1);
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
            let _ = (syscalls.channel_write)(s.admin_out_chan, s.scratch.as_ptr(), n);
        }
    };
    if idx >= SPF_CAP || s.spf[idx].in_use == 0 || s.spf[idx].wid_valid == 0 {
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
    if idx >= SPF_CAP || s.spf[idx].in_use == 0 || s.spf[idx].wid_valid == 0 {
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
    let spf = if (idx as usize) < SPF_CAP {
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
            emit_putfile_nak(s, syscalls, entry.correlation_id);
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
        let _ = (syscalls.channel_write)(s.admin_out_chan, s.scratch.as_ptr(), n);
        s.replied = s.replied.wrapping_add(1);
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
    let prev = (s.ns_tail.wrapping_add(PENDING_CAP as u32 - 1)) % PENDING_CAP as u32;
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
    let _ = (syscalls.channel_write)(s.admin_out_chan, s.scratch.as_ptr(), resp_n);
    s.replied = s.replied.wrapping_add(1);
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
            emit_putfile_nak(s, syscalls, req.correlation_id);
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
        emit_putfile_nak(s, syscalls, entry.correlation_id);
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
    let _ = (syscalls.channel_write)(s.admin_out_chan, s.scratch.as_ptr(), resp_n);
    s.replied = s.replied.wrapping_add(1);
    free_putfile_slot(s, slot_idx);
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
        let _ = (syscalls.channel_write)(s.admin_out_chan, buf.as_ptr(), 6);
        s.replied = s.replied.wrapping_add(1);
    }
}

unsafe fn emit_bind_nak(s: &mut ModuleState, syscalls: &super::SyscallTable, correlation_id: u32) {
    let mut buf = [0u8; 6];
    if super::admin::encode_admin_bind_ack(&mut buf, correlation_id, super::admin::STATUS_NAK)
        .is_ok()
    {
        let _ = (syscalls.channel_write)(s.admin_out_chan, buf.as_ptr(), 6);
        s.replied = s.replied.wrapping_add(1);
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
        let _ = (syscalls.channel_write)(s.admin_out_chan, buf.as_ptr(), 6);
        s.replied = s.replied.wrapping_add(1);
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
        let _ = (syscalls.channel_write)(s.admin_out_chan, buf.as_ptr(), 6);
        s.replied = s.replied.wrapping_add(1);
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
