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
