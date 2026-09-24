// Small helpers shared by the two load-plane modules,
// `loam_load_gen` and `loam_throughput_counter`.
//
// They live in the REPLICATED tier because that is where their
// consumers live: both speak `loam_decision_wire`, so they sit with
// the tier whose vocabulary they carry — the same reasoning
// `tier_guard.sh`'s roster already applies to the modules
// themselves.
//
// Deliberately tiny. These are here because two modules had
// byte-identical copies, not because a "utils" module is a good
// idea: a third consumer would be a reason to look again at what
// they have in common, not a reason to add more here.

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Write `value` as 8 lowercase hex digits. Returns bytes written,
/// or 0 if `dst` cannot hold them — a short buffer writes NOTHING
/// rather than a truncated number, because half a correlation id
/// reads as a different correlation id.
pub fn write_hex_u32(dst: &mut [u8], value: u32) -> usize {
    if dst.len() < 8 {
        return 0;
    }
    let mut n = value;
    let mut i = 8usize;
    while i > 0 {
        i -= 1;
        dst[i] = HEX[(n & 0xF) as usize];
        n >>= 4;
    }
    8
}

/// Copy `tag` into `dst`, clamped to whichever is shorter. Returns
/// bytes copied.
pub fn copy_tag(dst: &mut [u8], tag: &[u8]) -> usize {
    let mut i = 0usize;
    while i < tag.len() && i < dst.len() {
        dst[i] = tag[i];
        i += 1;
    }
    i
}
