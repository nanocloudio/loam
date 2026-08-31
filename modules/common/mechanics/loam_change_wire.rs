// `namespace.change` — the event vocabulary behind `namespace::SUBSCRIBE`
// (0x1305) and `namespace::CHANGES` (0x1307).
//
// This is NOT loam's format. It is fluxor's, restated here in the shape
// a no_std PIC can emit: the encoder below produces bytes that fluxor's
// own `modules/sdk/cores/table_consumer.rs::parse_change_record` decodes,
// and that nanocloud's `modules/app/_shared/store.rs` already drains.
// Forty nanocloud modules consume this stream — every reconciler plus
// kubelet, scheduler, rbac_gate and core_api — so the layout is a
// commitment to an existing fleet, not a new interface.
//
// Two framings of the same record:
//
//   SUBSCRIBE (push)  [32-byte mesh Event header][change record]
//   CHANGES  (pull)   [status u8][count u32][change record × count]
//
//   change record     [rev u64][kind u8][key_len u16][val_len u32]
//                     [key][val]
//
// The mesh Event header, all little-endian:
//
//   [source 16][sequence u32][timestamp u64][content_type u8]
//   [flags u8][payload_len u16]                          = 32 bytes
//
// Same include discipline as the other mechanics sources.

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

/// Mesh Event header length, prefixing every pushed subscription event.
pub const EVENT_HEADER_SIZE: usize = 32;
/// Offset of the little-endian payload length within the header.
pub const EVENT_LEN_OFFSET: usize = 30;
/// Offset of the content-type byte within the header.
pub const EVENT_CT_OFFSET: usize = 28;

/// Content type of a `namespace.change` payload, from fluxor's
/// content-type table. An append-only position: never renumber.
pub const CT_NAMESPACE_CHANGE: u8 = 15;

/// Event `source` — 16 bytes identifying the producer. Zero-padded.
pub const SOURCE: [u8; 16] = *b"loam-namespace\0\0";

/// Change kinds.
pub const KIND_ADDED: u8 = 0;
pub const KIND_MODIFIED: u8 = 1;
pub const KIND_DELETED: u8 = 2;

/// `CHANGES` response status byte.
pub const STATUS_EVENTS: u8 = 0;
/// The requested window preceded what we can still vouch for; the
/// client must relist. Also ridden on the SUBSCRIBE stream as a
/// `kind=Deleted` record with an EMPTY key — the distinguished
/// sentinel fluxor's `is_lost_sentinel` recognises.
pub const STATUS_LOST: u8 = 1;

/// Fixed part of a change record, before key and value bytes.
pub const REC_HEADER: usize = 8 + 1 + 2 + 4;

/// `CHANGES` response header: status byte plus a u32 count.
pub const CHANGES_HEADER: usize = 1 + 4;

/// Largest record this surface can produce: the fixed header plus the
/// key and value ceilings from the limit register. Derived, so it
/// tracks the register rather than restating a number.
pub const REC_MAX: usize = REC_HEADER + super::limits::MAX_PATH + super::limits::MAX_OBJECT_ID;

/// Largest pushed event: the mesh header plus the largest record.
pub const EVENT_MAX: usize = EVENT_HEADER_SIZE + REC_MAX;

/// Encode one change record (no event header) into `out`.
/// Returns the byte count, or `None` if `out` is too small.
pub fn encode_record(
    out: &mut [u8],
    revision: u64,
    kind: u8,
    key: &[u8],
    value: &[u8],
) -> Option<usize> {
    let n = REC_HEADER + key.len() + value.len();
    if out.len() < n || key.len() > u16::MAX as usize {
        return None;
    }
    out[0..8].copy_from_slice(&revision.to_le_bytes());
    out[8] = kind;
    out[9..11].copy_from_slice(&(key.len() as u16).to_le_bytes());
    out[11..15].copy_from_slice(&(value.len() as u32).to_le_bytes());
    out[15..15 + key.len()].copy_from_slice(key);
    out[15 + key.len()..n].copy_from_slice(value);
    Some(n)
}

/// Encode one pushed event: mesh header followed by the change record.
pub fn encode_event(
    out: &mut [u8],
    sequence: u32,
    revision: u64,
    kind: u8,
    key: &[u8],
    value: &[u8],
) -> Option<usize> {
    let payload = REC_HEADER + key.len() + value.len();
    if out.len() < EVENT_HEADER_SIZE + payload || payload > u16::MAX as usize {
        return None;
    }
    for b in out[..EVENT_HEADER_SIZE].iter_mut() {
        *b = 0;
    }
    out[0..16].copy_from_slice(&SOURCE);
    out[16..20].copy_from_slice(&sequence.to_le_bytes());
    // timestamp (bytes 20..28) stays zero — advisory, and a PIC step
    // has no clock it should be asserting into a durability record.
    out[EVENT_CT_OFFSET] = CT_NAMESPACE_CHANGE;
    out[29] = 0; // flags
    out[EVENT_LEN_OFFSET..EVENT_HEADER_SIZE].copy_from_slice(&(payload as u16).to_le_bytes());
    encode_record(&mut out[EVENT_HEADER_SIZE..], revision, kind, key, value)?;
    Some(EVENT_HEADER_SIZE + payload)
}

/// The LOST sentinel as a pushed event: `kind=Deleted`, empty key.
pub fn encode_lost_event(out: &mut [u8], sequence: u32, revision: u64) -> Option<usize> {
    encode_event(out, sequence, revision, KIND_DELETED, &[], &[])
}

/// One decoded change record, borrowed from a wire buffer.
pub struct ChangeRecord<'a> {
    pub revision: u64,
    pub kind: u8,
    pub key: &'a [u8],
    /// Empty for `Deleted`.
    pub value: &'a [u8],
}

/// Decode one record; returns it and the bytes consumed. Mirrors
/// fluxor's `parse_change_record` so the two stay checkable against
/// each other by test rather than by inspection.
pub fn decode_record(rec: &[u8]) -> Option<(ChangeRecord<'_>, usize)> {
    if rec.len() < REC_HEADER {
        return None;
    }
    let mut r8 = [0u8; 8];
    r8.copy_from_slice(&rec[0..8]);
    let revision = u64::from_le_bytes(r8);
    let kind = rec[8];
    let key_len = u16::from_le_bytes([rec[9], rec[10]]) as usize;
    let val_len = u32::from_le_bytes([rec[11], rec[12], rec[13], rec[14]]) as usize;
    let key_start = REC_HEADER;
    let val_start = key_start.checked_add(key_len)?;
    let end = val_start.checked_add(val_len)?;
    if end > rec.len() {
        return None;
    }
    Some((
        ChangeRecord {
            revision,
            kind,
            key: &rec[key_start..val_start],
            value: &rec[val_start..end],
        },
        end,
    ))
}

/// True when `r` is the LOST relist sentinel.
pub fn is_lost_sentinel(r: &ChangeRecord<'_>) -> bool {
    r.kind == KIND_DELETED && r.key.is_empty()
}

/// Payload length declared by a pushed event's header.
pub fn event_payload_len(hdr: &[u8]) -> Option<usize> {
    if hdr.len() < EVENT_HEADER_SIZE {
        return None;
    }
    Some(u16::from_le_bytes([hdr[EVENT_LEN_OFFSET], hdr[EVENT_LEN_OFFSET + 1]]) as usize)
}

/// Does `key` fall under `prefix`? An empty prefix matches everything,
/// which is how a subscriber asks for the whole namespace.
pub fn under_prefix(key: &[u8], prefix: &[u8]) -> bool {
    prefix.is_empty() || (key.len() >= prefix.len() && &key[..prefix.len()] == prefix)
}
