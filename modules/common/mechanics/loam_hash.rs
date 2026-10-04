// The small pure functions shared by the three state machines and
// the body store.
//
// `fnv1a64` is the one that matters. It narrows every identity scan
// in the namespace, object and block surfaces — three files, three
// byte-identical copies, and a hash function that defines which key
// a lookup lands on. Two of those copies drifting by one constant
// would not fail to compile, would not fail a unit test in either
// file, and would silently split one keyspace into two. It belongs
// in one place for that reason alone, before any line count.
//
// Note what fnv1a64 is NOT: it is not the identity. Every slot type
// compares full key bytes after the hash matches, because FNV-1a is
// trivially collidable by construction, and a tenant who names
// their own keys can collide it deliberately. The hash is a scan
// filter and nothing more.

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;

/// FNV-1a, 64-bit. Non-cryptographic: a scan filter, never an
/// identity. See the module header.
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h = FNV_OFFSET;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// One lowercase-hex digit to its value, or `None`. Used wherever a
/// content-derived id (`sha256:<64 hex>`) is decoded back to bytes.
pub fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Order two keys: the root's bytes, then the path's. Bytewise by
/// index, so the comparison links into a module with no `memcmp`.
pub fn key_cmp(ra: &[u8], pa: &[u8], rb: &[u8], pb: &[u8]) -> core::cmp::Ordering {
    match bytes_cmp(ra, rb) {
        core::cmp::Ordering::Equal => bytes_cmp(pa, pb),
        o => o,
    }
}

/// Bytewise order of two slices; a prefix sorts first.
pub fn bytes_cmp(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    let n = if a.len() < b.len() { a.len() } else { b.len() };
    let mut i = 0;
    while i < n {
        if a[i] != b[i] {
            return if a[i] < b[i] {
                core::cmp::Ordering::Less
            } else {
                core::cmp::Ordering::Greater
            };
        }
        i += 1;
    }
    a.len().cmp(&b.len())
}

/// Whether `b` is well-formed UTF-8: shortest-form sequences, no
/// surrogates, nothing past U+10FFFF. Written out because a PIC cannot
/// link `core::str::from_utf8`.
pub fn utf8_valid(b: &[u8]) -> bool {
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        // The sequence length, and the range its second byte must fall
        // in to be shortest-form, not a surrogate, and in range.
        let (n, lo, hi) = match c {
            0x00..=0x7F => {
                i += 1;
                continue;
            }
            0xC2..=0xDF => (2, 0x80, 0xBF),
            0xE0 => (3, 0xA0, 0xBF),
            0xE1..=0xEC | 0xEE..=0xEF => (3, 0x80, 0xBF),
            0xED => (3, 0x80, 0x9F),
            0xF0 => (4, 0x90, 0xBF),
            0xF1..=0xF3 => (4, 0x80, 0xBF),
            0xF4 => (4, 0x80, 0x8F),
            _ => return false,
        };
        if b.len() - i < n {
            return false;
        }
        if b[i + 1] < lo || b[i + 1] > hi {
            return false;
        }
        let mut k = 2;
        while k < n {
            if b[i + k] & 0xC0 != 0x80 {
                return false;
            }
            k += 1;
        }
        i += n;
    }
    true
}
