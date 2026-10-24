// What remains of `namespace.change` once subscriptions stopped pushing.
//
// A `namespace::SUBSCRIBE` (0x1305) is a doorbell: the provider rings the
// subscriber's own kernel event and writes nothing to any channel, and
// the subscriber reads what changed with `namespace::CHANGES` (0x1307).
// The page, its records and its tokens are fluxor's, encoded and decoded
// through the contract's own codecs
// (`contracts::storage::namespace::{subscribe, take, changes}`), so no
// layout is restated here. What loam keeps is the one rule both the ring
// and the page apply: which keys a prefix covers.
//
// Same include discipline as the other mechanics sources.

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

/// Does `key` fall under `prefix`? An empty prefix matches everything,
/// which is how a subscriber asks for the whole namespace.
pub fn under_prefix(key: &[u8], prefix: &[u8]) -> bool {
    prefix.is_empty() || (key.len() >= prefix.len() && &key[..prefix.len()] == prefix)
}
