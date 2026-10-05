// The body plane's channel framing.
//
// Every record on a body channel, request or response, travels as
//
//   [len:u32 LE][cid:u32 LE][record: len - 4 bytes]
//
// `len` counts what follows it — the correlation id and the record —
// which is fluxor's `len32` framing, so a body channel crosses nodes on
// `remote_channel` (`OctetStream:len32:FRAME_MAX`) without the module on
// either end knowing whether its peer is local or remote. The record is
// a `loam_body_wire` request or response, unchanged.
//
// `cid` is the requester's correlation id; a responder echoes the cid of
// the request it answers. A channel delimits records but does not keep
// them: a member across a network can lose the requests in flight when
// its session ends and never answer them. The cid is what lets a
// requester put a deadline on an answer and drop one that arrives after
// it, instead of attributing every later answer to the wrong request.
//
// Reading: an `Inbox` reads exactly one frame — its header, then its
// record — and never past it, so nothing is ever shifted or carried over,
// and a frame that arrives over several steps is assembled in place. A
// frame announcing a record larger than the inbox is skipped whole and
// reported once, with its cid, so the requester still gets one answer.
//
// Writing: a channel write is all-or-nothing, and a channel's ring may be
// smaller than a frame, so a frame goes out in pieces (`offer`): what the
// channel refuses whole is offered again in smaller pieces, down to the
// smallest ring a channel has. `Sender` offers the header and then the
// record from wherever the caller staged it, picking up where the channel
// stopped; `Ring` queues whole frames for a channel that several answers
// can be owed on at once. Neither ever drops a byte: a frame is fully
// written or still owed.
//
// The includer's scope provides `SyscallTable` and `body_wire`.

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

/// `[len:u32]`.
pub const LEN_HDR: usize = 4;
/// `[cid:u32]`.
pub const CID_LEN: usize = 4;
/// The whole header: length, then correlation id.
pub const HDR: usize = LEN_HDR + CID_LEN;
/// The largest body-wire record.
pub const RECORD_MAX: usize = super::body_wire::RECORD_MAX;
/// The largest frame: what a body channel's `remote_channel` entry names
/// as its `max_record`, and what each end's buffers are sized to.
pub const FRAME_MAX: usize = HDR + RECORD_MAX;

/// Write a frame header for a record of `record_len` bytes.
pub fn header(cid: u32, record_len: usize) -> [u8; HDR] {
    let mut h = [0u8; HDR];
    h[..LEN_HDR].copy_from_slice(&((CID_LEN + record_len) as u32).to_le_bytes());
    h[LEN_HDR..].copy_from_slice(&cid.to_le_bytes());
    h
}

/// The smallest ring a channel is granted: a piece this size goes
/// whenever the channel has any room a piece could use.
pub const PIECE_MIN: usize = 64;

/// Offer `len` bytes at `src` to `chan`. A write the channel cannot take
/// whole is offered again a quarter the size, down to `PIECE_MIN`.
/// Returns the bytes taken; 0 when the channel took none.
pub unsafe fn offer(sys: &super::SyscallTable, chan: i32, src: *const u8, len: usize) -> usize {
    let mut n = len;
    loop {
        let rc = (sys.channel_write)(chan, src, n);
        if rc > 0 {
            return rc as usize;
        }
        if n <= PIECE_MIN {
            return 0;
        }
        n = (n >> 2).max(PIECE_MIN);
    }
}

/// Encode a whole frame into `out`. Returns its length, or `None` when
/// `out` cannot hold it.
pub fn encode(out: &mut [u8], cid: u32, record: &[u8]) -> Option<usize> {
    let n = HDR + record.len();
    if out.len() < n {
        return None;
    }
    out[..HDR].copy_from_slice(&header(cid, record.len()));
    out[HDR..n].copy_from_slice(record);
    Some(n)
}

/// Split one whole frame at the front of `bytes` into `(cid, record,
/// frame length)`. `None` when `bytes` does not start with a whole frame.
pub fn decode(bytes: &[u8]) -> Option<(u32, &[u8], usize)> {
    if bytes.len() < HDR {
        return None;
    }
    let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if len < CID_LEN {
        return None;
    }
    let total = LEN_HDR.checked_add(len)?;
    if bytes.len() < total {
        return None;
    }
    let cid = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    Some((cid, &bytes[HDR..total], total))
}

/// What one `Inbox::pull` found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pull {
    /// A whole record is in the inbox: `record()`, `cid()`, then `take()`.
    Record,
    /// Nothing more has arrived.
    Empty,
    /// A frame announced a record larger than the inbox can hold. Its
    /// bytes are being discarded; this is reported once, with its cid.
    Oversize(u32),
    /// A frame announced a length below the correlation id it must carry.
    /// Nothing after it can be delimited; the channel is unusable.
    Malformed,
}

/// Assembles one frame at a time from a channel, in place.
#[repr(C)]
pub struct Inbox<const N: usize> {
    hdr: [u8; HDR],
    hdr_have: u8,
    /// A whole record is held and has not been taken.
    ready: u8,
    /// The channel delivered a header no frame can have.
    broken: u8,
    need: u32,
    have: u32,
    /// Bytes of an oversize record still to discard.
    skip: u32,
    cid: u32,
    pub buf: [u8; N],
}

impl<const N: usize> Inbox<N> {
    pub const fn new() -> Self {
        Self {
            hdr: [0; HDR],
            hdr_have: 0,
            ready: 0,
            broken: 0,
            need: 0,
            have: 0,
            skip: 0,
            cid: 0,
            buf: [0; N],
        }
    }

    /// Read toward the next whole record. Reads only what the current
    /// frame still owes, so the channel keeps every byte after it.
    pub unsafe fn pull(&mut self, sys: &super::SyscallTable, chan: i32) -> Pull {
        if self.broken != 0 {
            return Pull::Malformed;
        }
        if self.ready != 0 {
            return Pull::Record;
        }
        if chan < 0 {
            return Pull::Empty;
        }
        // An oversize record already reported: discard the rest of it.
        while self.skip != 0 {
            let mut sink = [0u8; 256];
            let want = (self.skip as usize).min(sink.len());
            let n = (sys.channel_read)(chan, sink.as_mut_ptr(), want);
            if n <= 0 {
                return Pull::Empty;
            }
            self.skip -= n as u32;
        }
        while (self.hdr_have as usize) < HDR {
            let at = self.hdr_have as usize;
            let n = (sys.channel_read)(chan, self.hdr.as_mut_ptr().add(at), HDR - at);
            if n <= 0 {
                return Pull::Empty;
            }
            self.hdr_have += n as u8;
        }
        if self.need == 0 && self.have == 0 {
            let len = u32::from_le_bytes([self.hdr[0], self.hdr[1], self.hdr[2], self.hdr[3]]);
            if (len as usize) < CID_LEN {
                self.broken = 1;
                return Pull::Malformed;
            }
            self.cid = u32::from_le_bytes([self.hdr[4], self.hdr[5], self.hdr[6], self.hdr[7]]);
            let record = len - CID_LEN as u32;
            if record as usize > N {
                self.skip = record;
                self.hdr_have = 0;
                return Pull::Oversize(self.cid);
            }
            if record == 0 {
                self.ready = 1;
                return Pull::Record;
            }
            self.need = record;
        }
        while self.have < self.need {
            let at = self.have as usize;
            let want = (self.need - self.have) as usize;
            let n = (sys.channel_read)(chan, self.buf.as_mut_ptr().add(at), want);
            if n <= 0 {
                return Pull::Empty;
            }
            self.have += n as u32;
        }
        self.ready = 1;
        Pull::Record
    }

    /// The held record. Valid between `Pull::Record` and `take`.
    pub fn record(&self) -> &[u8] {
        &self.buf[..self.have as usize]
    }

    /// The held record's correlation id.
    pub fn cid(&self) -> u32 {
        self.cid
    }

    /// A partly arrived frame is in hand.
    pub fn busy(&self) -> bool {
        self.ready != 0 || self.hdr_have != 0 || self.skip != 0
    }

    /// Release the held record; the next `pull` starts the next frame.
    pub fn take(&mut self) {
        self.ready = 0;
        self.hdr_have = 0;
        self.need = 0;
        self.have = 0;
    }

    /// Forget everything, including a broken channel: used when the
    /// channel itself is replaced.
    pub fn reset(&mut self) {
        self.take();
        self.skip = 0;
        self.broken = 0;
    }
}

/// One frame owed on a channel: its header here, its record wherever the
/// caller staged it.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Sender {
    hdr: [u8; HDR],
    /// Record bytes, 0 when nothing is owed and nothing was staged.
    len: u32,
    /// Bytes of header and record the channel has taken.
    sent: u32,
    /// A frame is owed (a zero-length record is still a frame).
    owed: u8,
}

impl Sender {
    pub const fn new() -> Self {
        Self {
            hdr: [0; HDR],
            len: 0,
            sent: 0,
            owed: 0,
        }
    }

    /// Nothing is owed.
    pub fn is_idle(&self) -> bool {
        self.owed == 0
    }

    /// Owe a frame for the `record_len` bytes the caller has staged.
    pub fn stage(&mut self, cid: u32, record_len: usize) {
        self.hdr = header(cid, record_len);
        self.len = record_len as u32;
        self.sent = 0;
        self.owed = 1;
    }

    /// Offer what is owed. `record` is the staged record (at least
    /// `record_len` bytes). True once the whole frame has been taken, and
    /// when nothing is owed.
    pub unsafe fn flush(&mut self, sys: &super::SyscallTable, chan: i32, record: &[u8]) -> bool {
        if self.owed == 0 {
            return true;
        }
        if chan < 0 {
            return false;
        }
        let total = HDR as u32 + self.len;
        while self.sent < total {
            let at = self.sent as usize;
            let took = if at < HDR {
                offer(sys, chan, self.hdr.as_ptr().add(at), HDR - at)
            } else {
                let r = at - HDR;
                offer(sys, chan, record.as_ptr().add(r), self.len as usize - r)
            };
            if took == 0 {
                return false;
            }
            self.sent += took as u32;
        }
        self.owed = 0;
        self.len = 0;
        self.sent = 0;
        true
    }
}

/// A queue of whole frames owed on one channel.
#[repr(C)]
pub struct Ring<const N: usize> {
    head: u32,
    len: u32,
    pub buf: [u8; N],
}

impl<const N: usize> Ring<N> {
    pub const fn new() -> Self {
        Self {
            head: 0,
            len: 0,
            buf: [0; N],
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Bytes the ring can still take.
    pub fn free(&self) -> usize {
        N - self.len as usize
    }

    /// Room for one more frame of any size the plane allows.
    pub fn has_room_for_frame(&self) -> bool {
        self.free() >= FRAME_MAX
    }

    fn put(&mut self, bytes: &[u8]) {
        let mut tail = (self.head as usize + self.len as usize) % N;
        for &b in bytes {
            self.buf[tail] = b;
            tail += 1;
            if tail == N {
                tail = 0;
            }
        }
        self.len += bytes.len() as u32;
    }

    /// Queue `bytes` as they are, for a channel whose records delimit
    /// themselves. False, with nothing queued, when they do not fit.
    pub fn push_bytes(&mut self, bytes: &[u8]) -> bool {
        if bytes.len() > self.free() {
            return false;
        }
        self.put(bytes);
        true
    }

    /// Queue one frame. False, with nothing queued, when it does not fit.
    pub fn push(&mut self, cid: u32, record: &[u8]) -> bool {
        if HDR + record.len() > self.free() {
            return false;
        }
        self.put(&header(cid, record.len()));
        self.put(record);
        true
    }

    /// Offer the queued bytes. True once the ring is empty.
    pub unsafe fn flush(&mut self, sys: &super::SyscallTable, chan: i32) -> bool {
        if chan < 0 {
            return self.len == 0;
        }
        while self.len != 0 {
            let head = self.head as usize;
            let run = (self.len as usize).min(N - head);
            let rc = offer(sys, chan, self.buf.as_ptr().add(head), run);
            if rc == 0 {
                return false;
            }
            self.head = ((head + rc) % N) as u32;
            self.len -= rc as u32;
        }
        self.head = 0;
        true
    }
}
