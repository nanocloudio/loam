// The per-target dispatch queue shared by every fan-out router.
//
// Both `body_fanout_router` and `ec_body_router` fan one upstream
// request to several body_store members and rejoin the answers. The
// SHAPE of that is identical in both — a bounded FIFO per target
// holding "which join is this member's next answer for?" — while the
// join payload and the repair action are not. So this file owns the
// queue and nothing else — the seam where the two routers genuinely
// agree, rather than one where they only look similar.
//
// Why a queue per target at all: a member answers in the order it was
// asked, but different members interleave freely. Keeping one FIFO
// per member is what lets an arriving response be attributed to the
// right join without the response carrying a correlation id — the
// body wire has no room for one, and adding it would cost a field on
// every frame to solve a problem the ordering already solves.
//
// The queue is intentionally not generic over the payload. A
// `PendingTarget` is (join index, join generation) in both routers,
// and the generation is what makes a late answer for a freed-and-
// reused slot droppable instead of misattributed — the property most
// worth keeping in one audited place.

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

/// One queued expectation: the join slot a target's next response
/// belongs to, plus the generation that slot held when it was queued.
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct PendingTarget {
    pub in_use: u8,
    pub join_idx: u16,
    pub join_gen: u16,
}

/// A bounded FIFO per fleet member.
///
/// `TARGETS` is the fleet ceiling (`MAX_FLEET`) and `CAP` the
/// in-flight ceiling per member (`PENDING_CAP`). One slot is
/// sacrificed to the classic ring discipline — head == tail means
/// empty, so a full ring holds `CAP - 1`.
#[repr(C)]
pub struct TargetQueues<const TARGETS: usize, const CAP: usize> {
    pub pending: [[PendingTarget; CAP]; TARGETS],
    pub head: [u32; TARGETS],
    pub tail: [u32; TARGETS],
}

impl<const TARGETS: usize, const CAP: usize> TargetQueues<TARGETS, CAP> {
    pub const fn new() -> Self {
        Self {
            pending: [[PendingTarget {
                in_use: 0,
                join_idx: 0,
                join_gen: 0,
            }; CAP]; TARGETS],
            head: [0; TARGETS],
            tail: [0; TARGETS],
        }
    }

    /// Queue an expectation for `target`. Returns false when the ring
    /// is full or the target is out of range — a refusal the caller
    /// must surface upstream, never swallow: a dispatch whose
    /// expectation was dropped would leave a response with no join to
    /// land on.
    pub fn enqueue(&mut self, target: u8, join_idx: u16, join_gen: u16) -> bool {
        let t = target as usize;
        if t >= TARGETS {
            return false;
        }
        let next = (self.tail[t].wrapping_add(1)) % CAP as u32;
        if next == self.head[t] {
            return false;
        }
        self.pending[t][self.tail[t] as usize] = PendingTarget {
            in_use: 1,
            join_idx,
            join_gen,
        };
        self.tail[t] = next;
        true
    }

    /// Take the oldest expectation for `target`, if any.
    pub fn dequeue(&mut self, target: u8) -> Option<PendingTarget> {
        let t = target as usize;
        if t >= TARGETS || self.head[t] == self.tail[t] {
            return None;
        }
        let entry = self.pending[t][self.head[t] as usize];
        self.pending[t][self.head[t] as usize].in_use = 0;
        self.head[t] = (self.head[t].wrapping_add(1)) % CAP as u32;
        Some(entry)
    }

    /// Undo the most recent `enqueue` for `target`.
    ///
    /// This exists for exactly one situation and it is worth naming:
    /// the caller queues the expectation BEFORE writing the request,
    /// because a response can in principle be observed before the
    /// write call returns. If the write then fails, the expectation
    /// must come back off or that member's FIFO is permanently
    /// skewed by one — every later response attributed to the join
    /// before it.
    pub fn unenqueue_tail(&mut self, target: u8) {
        let t = target as usize;
        if t >= TARGETS || self.head[t] == self.tail[t] {
            return;
        }
        let prev = (self.tail[t].wrapping_add(CAP as u32 - 1)) % CAP as u32;
        self.pending[t][prev as usize].in_use = 0;
        self.tail[t] = prev;
    }

    /// Expectations outstanding for `target`.
    pub fn depth(&self, target: u8) -> usize {
        let t = target as usize;
        if t >= TARGETS {
            return 0;
        }
        (self.tail[t].wrapping_add(CAP as u32) - self.head[t]) as usize % CAP
    }

    /// Drop every expectation for `target` — used when a member
    /// leaves the fleet, so its queued joins fail fast rather than
    /// waiting for answers that can no longer come.
    pub fn clear(&mut self, target: u8) {
        let t = target as usize;
        if t >= TARGETS {
            return;
        }
        for e in self.pending[t].iter_mut() {
            e.in_use = 0;
        }
        self.head[t] = 0;
        self.tail[t] = 0;
    }
}

impl<const TARGETS: usize, const CAP: usize> Default for TargetQueues<TARGETS, CAP> {
    fn default() -> Self {
        Self::new()
    }
}
