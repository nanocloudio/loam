// How a commit's proof is derived from what a replica group actually
// committed.
//
// The two functions here are what turn a Clustor committed entry into
// the terms of `Fence::dominates`. They live in one file, apart from
// the bridge that calls them, because the fork guarantee is a
// PROPERTY worth testing directly: given two divergent logs, the
// witnesses must differ, and that is a statement about these
// functions rather than about any graph they run in.
//
// The includer's scope must provide `super::sha256::Sha256` — the
// same discipline `loam_extent_wire.rs` uses, so a consumer that
// needs no witness pays for no hash.

/// Domain separator, so a commit witness can never collide with a
/// digest this store computed for some other purpose over the same
/// bytes. Versioned by its trailing byte: a change to what the
/// witness covers is a different commitment and must not be
/// mistakable for the old one.
pub const WITNESS_DOMAIN: &[u8] = b"loam-commit-witness\x01";

/// The 16-byte identity of the replicated log an entry committed in.
///
/// `Fence::dominates` compares `commit_index` only once `source` and
/// `epoch` match, so two logs sharing a source would have their
/// unrelated indices ordered against each other. One Clustor engine
/// hosts K groups whose indices each start at 1, so `partition_id`
/// separates them and is folded in unconditionally.
///
/// `group_id` separates DEPLOYMENTS. Left zero it contributes
/// nothing, which is correct for the only place these fences meet
/// today — one engine, whose partitions are already distinct. An
/// operator whose fences travel between clusters sets it, and two
/// clusters then cannot order each other's commits.
pub fn commit_source(group_id: &[u8; 16], partition_id: u16) -> [u8; 16] {
    let mut out = *group_id;
    let p = partition_id.to_le_bytes();
    out[14] ^= p[0];
    out[15] ^= p[1];
    out
}

/// Commitment to one committed entry.
///
/// This is the fork check. Two replicas of the same log at the same
/// `(term, index)` commit identical command bytes and so compute an
/// identical witness; two logs that diverged at that position commit
/// different bytes and do not. `dominates` consults it exactly when
/// the indices are equal — the case where a counter alone cannot tell
/// agreement from divergence.
///
/// Computed here rather than taken from Clustor because the
/// committed-entry envelope carries no commitment of its own. It is a
/// function of what the group actually committed, which is the
/// property the fence needs; a counter would order forks as though
/// they agreed.
pub fn commit_witness(source: &[u8; 16], term: u64, index: u64, command: &[u8]) -> [u8; 32] {
    let mut h = super::sha256::Sha256::new();
    h.update(WITNESS_DOMAIN);
    h.update(source);
    h.update(&term.to_le_bytes());
    h.update(&index.to_le_bytes());
    h.update(command);
    h.finalize()
}
