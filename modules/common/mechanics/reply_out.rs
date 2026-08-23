// Retained outbound records for PIC step bodies. no_std.
//
// A channel is not obliged to accept a write. When it refuses, the
// bytes stay with the caller — so a module that mutates state and then
// writes its answer once, discarding the result, has changed the world
// and told nobody. The requester sees neither a result nor a refusal
// and waits out its own timeout, which is indistinguishable from the
// module having lost the record entirely.
//
// The record owed is therefore held, not dropped: `stage` takes it,
// `flush` offers it, and the module consumes no new work while one is
// owed. The same applies to a record being FORWARDED rather than
// answered: abandoning a partial write and re-encoding the whole
// record later leaves a truncated prefix on the channel, and the
// reader's frame splitter then parses across the seam and corrupts
// the record that follows. That is the same discipline `wal_io::WalAppender` applies to an
// append that has left its stream and not yet resolved, for the same
// reason — a step must be able to make no progress without anything
// being lost.
//
// A short write is progress, not failure: the accepted prefix is gone
// from the channel's point of view and must not be re-sent, so `sent`
// tracks how much of the answer has landed.

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

/// The kernel's channel-write entry point, taken by pointer so this
/// file names no type from its includer's module tree.
pub type ChannelWrite = unsafe extern "C" fn(i32, *const u8, usize) -> i32;

/// One outstanding outbound record, at most `N` bytes.
#[repr(C)]
pub struct ReplyOut<const N: usize> {
    len: u16,
    sent: u16,
    buf: [u8; N],
}

impl<const N: usize> ReplyOut<N> {
    pub const fn new() -> Self {
        Self {
            len: 0,
            sent: 0,
            buf: [0u8; N],
        }
    }

    /// True while a record is owed. The caller must not take new work
    /// off its input stream, and must not stage another answer, while
    /// this holds.
    pub fn owed(&self) -> bool {
        self.sent < self.len
    }

    /// Drop any owed record. For re-init only — a record discarded
    /// here is one the peer never receives.
    pub fn reset(&mut self) {
        self.len = 0;
        self.sent = 0;
    }

    /// Take ownership of one record. Returns false when a record is
    /// already owed or `bytes` does not fit, both of which mean the
    /// caller's own bookkeeping is wrong: it processed new work while
    /// indebted, or sized this buffer below its largest response.
    pub fn stage(&mut self, bytes: &[u8]) -> bool {
        if self.owed() || bytes.is_empty() || bytes.len() > N {
            return false;
        }
        self.buf[..bytes.len()].copy_from_slice(bytes);
        self.len = bytes.len() as u16;
        self.sent = 0;
        true
    }

    /// Offer the owed record to `chan`. Returns true once every byte
    /// has been accepted — and when nothing was owed, so a caller can
    /// gate on it unconditionally.
    ///
    /// # Safety
    /// `write` must be the live channel-write entry and `chan` a
    /// writable channel index.
    pub unsafe fn flush(&mut self, write: ChannelWrite, chan: i32) -> bool {
        if !self.owed() {
            return true;
        }
        if chan < 0 {
            return false;
        }
        let at = self.sent as usize;
        let rc = write(chan, self.buf.as_ptr().add(at), self.len as usize - at);
        if rc <= 0 {
            return false;
        }
        self.sent = self.sent.saturating_add(rc as u16).min(self.len);
        if self.owed() {
            return false;
        }
        self.len = 0;
        self.sent = 0;
        true
    }

    /// Stage and immediately offer, for the common case where the
    /// channel accepts and no later step is needed.
    ///
    /// # Safety
    /// Same constraints as `flush`.
    pub unsafe fn send(&mut self, write: ChannelWrite, chan: i32, bytes: &[u8]) -> bool {
        if !self.stage(bytes) {
            return false;
        }
        self.flush(write, chan)
    }
}

impl<const N: usize> Default for ReplyOut<N> {
    fn default() -> Self {
        Self::new()
    }
}
