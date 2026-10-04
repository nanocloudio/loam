// The member side of a body router, shared by `body_fanout_router` and
// `ec_body_router`.
//
// Both routers fan one upstream request to several body_store members
// and rejoin the answers. Their join payloads and repair actions differ;
// how they talk to members does not, and this file owns that:
//
// - `Inflight` — every answer a router awaits, keyed by the correlation
//   id its request frame carried (`body_frame.rs`) and stamped with when
//   it was asked. An answer is matched by its member and cid, never by
//   arrival order: a member reached over `remote_channel` can lose the
//   requests in flight when its session ends, and later answers would
//   otherwise be attributed to the wrong request. An expectation past
//   `MEMBER_DEADLINE_MS` is handed back as that member's failure, and an
//   answer arriving after it finds nothing to match and is dropped.
//
// - `Members` — each member's request channel, the frame owed on it, and
//   the one inbox the members' answers are assembled in. A frame a
//   member's channel has taken in part is finished before anything else
//   is sent to that member; one it has not taken by the deadline marks
//   the member stalled, and sends to it are refused at once until it
//   drains, so a dead member costs each request one refusal rather than
//   a wait. Answers are assembled one frame at a time, finishing a
//   member's frame before moving to the next member's.
//
// - A member across a network can take a request and never answer it:
//   its session is down, and the channel holds the request for the next
//   one. Such a member is `quiet` from the deadline it missed until it
//   answers again, and a router asks it last wherever another member
//   can answer instead — so a read is not made to wait out a deadline
//   per request while one replica is down. A quiet member is still sent
//   what only it can answer, which is how it is seen to come back.
//
// The includer's scope provides `SyscallTable`, `body_frame` and
// `limits`.

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

use super::body_frame::{Inbox, Pull, Sender, RECORD_MAX};

/// `TIMER::MILLIS`: monotonic milliseconds.
const TIMER_MILLIS: u32 = 0x0602;

/// The monotonic clock, in milliseconds.
pub unsafe fn now_ms(sys: &super::SyscallTable) -> u64 {
    let mut buf = [0u8; 8];
    (sys.provider_call)(-1, TIMER_MILLIS, buf.as_mut_ptr(), buf.len());
    u64::from_le_bytes(buf)
}

/// One awaited answer.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Expect {
    pub in_use: u8,
    pub target: u8,
    pub join_idx: u16,
    /// The join slot's incarnation when the request was sent: an answer
    /// for a freed-and-reused slot is dropped, not misattributed.
    pub join_gen: u16,
    pub cid: u32,
    pub at_ms: u64,
}

impl Expect {
    const EMPTY: Expect = Expect {
        in_use: 0,
        target: 0,
        join_idx: 0,
        join_gen: 0,
        cid: 0,
        at_ms: 0,
    };
}

/// Every answer a router awaits from its members.
#[repr(C)]
pub struct Inflight<const CAP: usize> {
    slots: [Expect; CAP],
    next_cid: u32,
}

impl<const CAP: usize> Inflight<CAP> {
    pub const fn new() -> Self {
        Self {
            slots: [Expect::EMPTY; CAP],
            next_cid: 0,
        }
    }

    fn cid_in_use(&self, cid: u32) -> bool {
        for i in 0..CAP {
            if self.slots[i].in_use != 0 && self.slots[i].cid == cid {
                return true;
            }
        }
        false
    }

    /// Await an answer from `target` for a join. Returns the cid its
    /// request frame must carry, or `None` when the table is full — a
    /// refusal the caller surfaces, never swallows.
    pub fn issue(&mut self, target: u8, join_idx: u16, join_gen: u16, now_ms: u64) -> Option<u32> {
        let mut free = None;
        for i in 0..CAP {
            if self.slots[i].in_use == 0 {
                free = Some(i);
                break;
            }
        }
        let i = free?;
        // Never zero, never one still awaited: an id wraps only after
        // four billion requests, and the table is small enough to check.
        let mut cid = self.next_cid.wrapping_add(1);
        while cid == 0 || self.cid_in_use(cid) {
            cid = cid.wrapping_add(1);
        }
        self.next_cid = cid;
        self.slots[i] = Expect {
            in_use: 1,
            target,
            join_idx,
            join_gen,
            cid,
            at_ms: now_ms,
        };
        Some(cid)
    }

    /// Forget an expectation whose request was never sent.
    pub fn unissue(&mut self, cid: u32) {
        for i in 0..CAP {
            if self.slots[i].in_use != 0 && self.slots[i].cid == cid {
                self.slots[i].in_use = 0;
                return;
            }
        }
    }

    /// Match an answer `target` sent under `cid`. `None` for an answer
    /// nothing awaits: one past its deadline, or one no request asked for.
    pub fn resolve(&mut self, target: u8, cid: u32) -> Option<Expect> {
        for i in 0..CAP {
            let e = self.slots[i];
            if e.in_use != 0 && e.target == target && e.cid == cid {
                self.slots[i].in_use = 0;
                return Some(e);
            }
        }
        None
    }

    /// Take one expectation older than `deadline_ms`, if any.
    pub fn take_expired(&mut self, now_ms: u64, deadline_ms: u64) -> Option<Expect> {
        for i in 0..CAP {
            let e = self.slots[i];
            if e.in_use != 0 && now_ms.saturating_sub(e.at_ms) >= deadline_ms {
                self.slots[i].in_use = 0;
                return Some(e);
            }
        }
        None
    }

    /// Answers awaited from `target`.
    pub fn depth(&self, target: u8) -> usize {
        let mut n = 0;
        for i in 0..CAP {
            if self.slots[i].in_use != 0 && self.slots[i].target == target {
                n += 1;
            }
        }
        n
    }

    /// Answers awaited from every member.
    pub fn len(&self) -> usize {
        let mut n = 0;
        for i in 0..CAP {
            if self.slots[i].in_use != 0 {
                n += 1;
            }
        }
        n
    }
}

/// What `Members::pull` found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MemberPull {
    /// Member `0` answered under cid `1`: read `record()`, then `take()`.
    Record(u8, u32),
    /// Member `0` answered under cid `1` with a record too large for any
    /// answer this plane defines; it is discarded. Treat it as a failure.
    Oversize(u8, u32),
    /// Nothing whole has arrived.
    Empty,
}

/// The members a router fronts: their channels and their owed frames.
#[repr(C)]
pub struct Members<const M: usize> {
    pub req: [i32; M],
    pub resp: [i32; M],
    pub count: u8,
    tx: [Sender; M],
    /// When each member's owed frame was staged.
    tx_since: [u64; M],
    /// 1: a frame has been owed past the deadline; sends are refused.
    stalled: [u8; M],
    /// 1: the member's answer channel carried a header no frame can
    /// have; nothing more can be read from it.
    broken: [u8; M],
    /// 1: the member missed a deadline and has not answered since.
    quiet: [u8; M],
    tx_buf: [[u8; RECORD_MAX]; M],
    rx: Inbox<RECORD_MAX>,
    /// The member whose frame `rx` is assembling.
    rx_member: u8,
    /// Where the next search for an answer starts.
    rx_next: u8,
}

impl<const M: usize> Members<M> {
    /// Wire the members. False when the lists differ in length or exceed
    /// the router's member ceiling.
    pub fn wire(&mut self, req: &[i32], resp: &[i32]) -> bool {
        if req.len() != resp.len() || req.len() > M {
            return false;
        }
        for i in 0..M {
            self.req[i] = if i < req.len() { req[i] } else { -1 };
            self.resp[i] = if i < resp.len() { resp[i] } else { -1 };
            self.tx[i] = Sender::new();
            self.tx_since[i] = 0;
            self.stalled[i] = 0;
            self.broken[i] = 0;
            self.quiet[i] = 0;
        }
        self.count = req.len() as u8;
        self.rx.reset();
        self.rx_member = 0;
        self.rx_next = 0;
        true
    }

    /// Member `t` has a request channel.
    pub fn wired(&self, t: u8) -> bool {
        (t as usize) < self.count as usize && self.req[t as usize] >= 0
    }

    pub fn is_stalled(&self, t: u8) -> bool {
        (t as usize) < M && self.stalled[t as usize] != 0
    }

    /// Member `t` missed an answer's deadline.
    pub fn mark_quiet(&mut self, t: u8) {
        if (t as usize) < M {
            self.quiet[t as usize] = 1;
        }
    }

    /// Member `t` missed a deadline and has not answered since.
    pub fn is_quiet(&self, t: u8) -> bool {
        (t as usize) < M && self.quiet[t as usize] != 0
    }

    /// Reorder `targets` so members that are quiet come after those that
    /// are not, keeping each group's order.
    pub fn quiet_last(&self, targets: &mut [u8]) {
        let mut order = [0u8; M];
        let mut n = 0;
        for pass in 0..2u8 {
            for &t in targets.iter() {
                if (self.is_quiet(t) as u8) == pass && n < M {
                    order[n] = t;
                    n += 1;
                }
            }
        }
        if n == targets.len() {
            targets.copy_from_slice(&order[..n]);
        }
    }

    /// A frame can be sent to member `t` now.
    pub fn can_send(&self, t: u8) -> bool {
        self.wired(t)
            && self.tx[t as usize].is_idle()
            && self.stalled[t as usize] == 0
            && self.broken[t as usize] == 0
    }

    /// No member is part-way through taking a frame it may yet take:
    /// every wired member is idle, stalled or broken. A router admits
    /// new work only then, so a send it makes is never refused merely
    /// because a healthy member's channel was briefly full.
    pub fn settled(&self) -> bool {
        for t in 0..self.count as usize {
            if self.req[t] >= 0
                && !self.tx[t].is_idle()
                && self.stalled[t] == 0
                && self.broken[t] == 0
            {
                return false;
            }
        }
        true
    }

    /// Send one framed record to member `t`. False, with nothing sent,
    /// when `can_send(t)` is false or the record is too large.
    pub unsafe fn send(
        &mut self,
        sys: &super::SyscallTable,
        t: u8,
        cid: u32,
        record: &[u8],
        now_ms: u64,
    ) -> bool {
        if !self.can_send(t) || record.len() > RECORD_MAX {
            return false;
        }
        let i = t as usize;
        self.tx_buf[i][..record.len()].copy_from_slice(record);
        self.tx[i].stage(cid, record.len());
        self.tx_since[i] = now_ms;
        let chan = self.req[i];
        self.tx[i].flush(sys, chan, &self.tx_buf[i]);
        true
    }

    /// Offer every owed frame. A member whose frame has been owed past
    /// `deadline_ms` is marked stalled; one that drains is not.
    pub unsafe fn flush(&mut self, sys: &super::SyscallTable, now_ms: u64, deadline_ms: u64) {
        for i in 0..self.count as usize {
            if self.req[i] < 0 {
                continue;
            }
            let chan = self.req[i];
            if self.tx[i].flush(sys, chan, &self.tx_buf[i]) {
                self.stalled[i] = 0;
            } else if now_ms.saturating_sub(self.tx_since[i]) >= deadline_ms {
                self.stalled[i] = 1;
            }
        }
    }

    /// Assemble the next answer. Finishes the frame in hand before
    /// looking at another member, then searches from where it left off
    /// so no member is starved.
    pub unsafe fn pull(&mut self, sys: &super::SyscallTable) -> MemberPull {
        let n = self.count as usize;
        if n == 0 {
            return MemberPull::Empty;
        }
        if self.rx.busy() {
            return self.pull_from(sys, self.rx_member);
        }
        // Round robin from `rx_next`. No runtime division on a PIC
        // target, so the cursor wraps by comparison.
        let mut cursor = self.rx_next as usize;
        for _ in 0..n {
            if cursor >= n {
                cursor = 0;
            }
            let t = cursor as u8;
            cursor += 1;
            if self.resp[t as usize] < 0 || self.broken[t as usize] != 0 {
                continue;
            }
            match self.pull_from(sys, t) {
                MemberPull::Empty => {
                    if self.rx.busy() {
                        // Part of a frame arrived: finish it next time.
                        return MemberPull::Empty;
                    }
                }
                found => {
                    self.rx_next = if cursor >= n { 0 } else { cursor as u8 };
                    return found;
                }
            }
        }
        MemberPull::Empty
    }

    unsafe fn pull_from(&mut self, sys: &super::SyscallTable, t: u8) -> MemberPull {
        self.rx_member = t;
        match self.rx.pull(sys, self.resp[t as usize]) {
            Pull::Record => {
                self.quiet[t as usize] = 0;
                MemberPull::Record(t, self.rx.cid())
            }
            Pull::Oversize(cid) => {
                self.quiet[t as usize] = 0;
                MemberPull::Oversize(t, cid)
            }
            Pull::Empty => MemberPull::Empty,
            Pull::Malformed => {
                self.broken[t as usize] = 1;
                self.rx.reset();
                MemberPull::Empty
            }
        }
    }

    /// The answer `pull` reported.
    pub fn record(&self) -> &[u8] {
        self.rx.record()
    }

    /// Release the answer `pull` reported.
    pub fn take(&mut self) {
        self.rx.take();
    }
}
