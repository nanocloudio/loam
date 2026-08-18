// Pure erasure-coding compute. Consumed by the EC body router —
// the sibling of `body_fanout_router` that stores k data + m
// parity shards instead of full replicas. Same discipline as
// `loam_placement.rs`: no_std, no syscalls, no allocation; every
// buffer is caller-owned and every loop bound is a constant.
//
// Scheme: systematic Cauchy Reed-Solomon over GF(256) (the
// Jerasure construction). The generator is [I; C] where C is the
// m×k Cauchy matrix C[j][i] = 1/(x_j ^ y_i), x_j = k+j, y_i = i.
// x and y ranges are disjoint so x_j ^ y_i is never zero, and
// every square submatrix of a Cauchy matrix is invertible — any k
// of the k+m shards reconstruct the body. Data shards are the
// body split into k runs (zero-padded), so the common no-loss
// read path is a straight concatenation with no field math.
//
// Bounds: k ≥ 1 data shards, m ≥ 0 parity shards,
// k + m ≤ MAX_SHARDS. Shards live in ONE contiguous caller
// buffer of (k+m)·shard_len bytes — shard s occupies
// [s·shard_len, (s+1)·shard_len). Reconstruction cost is one k×k
// Gauss-Jordan inversion (≤ 16³ byte-ops) plus a table-lookup
// multiply per recovered byte.

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

pub const MAX_SHARDS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcError {
    /// k = 0, k + m > MAX_SHARDS, or shard_len = 0.
    BadParams,
    /// Shards buffer smaller than (k+m)·shard_len.
    BufferTooSmall { needed: usize, actual: usize },
    /// Fewer than k shards present in the mask.
    NotEnoughShards { present: u8, need: u8 },
    /// Body longer than k·shard_len.
    BodyTooLarge { len: usize, max: usize },
}

// ── GF(256) arithmetic, poly 0x11D ─────────────────────────────────

const fn build_tables() -> ([u8; 512], [u8; 256]) {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    let mut i = 0;
    while i < 255 {
        exp[i] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= 0x11D;
        }
        i += 1;
    }
    // Mirror the cycle so mul can index log[a]+log[b] directly.
    let mut j = 255;
    while j < 512 {
        exp[j] = exp[j - 255];
        j += 1;
    }
    (exp, log)
}

const TABLES: ([u8; 512], [u8; 256]) = build_tables();
const EXP: [u8; 512] = TABLES.0;
const LOG: [u8; 256] = TABLES.1;

#[inline]
fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        EXP[LOG[a as usize] as usize + LOG[b as usize] as usize]
    }
}

#[inline]
fn gf_inv(a: u8) -> u8 {
    // a must be nonzero; callers only invert Cauchy elements and
    // pivots, both nonzero by construction.
    EXP[255 - LOG[a as usize] as usize]
}

/// Cauchy coefficient for parity row j over data column i.
#[inline]
fn cauchy(k: u8, j: u8, i: u8) -> u8 {
    gf_inv((k + j) ^ i)
}

// ── Parameter / buffer checks ──────────────────────────────────────

fn check_params(k: u8, m: u8, shard_len: usize, shards: &[u8]) -> Result<(), EcError> {
    if k == 0 || (k as usize + m as usize) > MAX_SHARDS || shard_len == 0 {
        return Err(EcError::BadParams);
    }
    let needed = (k as usize + m as usize) * shard_len;
    if shards.len() < needed {
        return Err(EcError::BufferTooSmall {
            needed,
            actual: shards.len(),
        });
    }
    Ok(())
}

/// Shard length for a body of `body_len` bytes split k ways.
pub fn shard_len_for(body_len: usize, k: u8) -> usize {
    if k == 0 {
        return 0;
    }
    body_len.div_ceil(k as usize).max(1)
}

// ── Encode ─────────────────────────────────────────────────────────

/// Split `body` into k data shards (zero-padded) and compute m
/// parity shards, all written into the contiguous `shards` buffer.
/// Returns the shard length used.
pub fn encode(body: &[u8], k: u8, m: u8, shards: &mut [u8]) -> Result<usize, EcError> {
    let shard_len = shard_len_for(body.len(), k);
    check_params(k, m, shard_len, shards)?;
    if body.len() > k as usize * shard_len {
        return Err(EcError::BodyTooLarge {
            len: body.len(),
            max: k as usize * shard_len,
        });
    }
    // Data shards: body runs, zero-padded through shard k-1.
    let data_area = k as usize * shard_len;
    shards[..data_area].fill(0);
    shards[..body.len()].copy_from_slice(body);
    // Parity shards.
    for j in 0..m {
        let base = (k as usize + j as usize) * shard_len;
        shards[base..base + shard_len].fill(0);
        for i in 0..k {
            let c = cauchy(k, j, i);
            let src = i as usize * shard_len;
            for p in 0..shard_len {
                shards[base + p] ^= gf_mul(c, shards[src + p]);
            }
        }
    }
    Ok(shard_len)
}

/// Copy the body back out of the data shards (the no-loss read
/// path — call `reconstruct` first if any data shard is missing).
pub fn body_from_shards(
    shards: &[u8],
    shard_len: usize,
    k: u8,
    body_len: usize,
    out: &mut [u8],
) -> Result<(), EcError> {
    if k == 0 || shard_len == 0 || body_len > k as usize * shard_len {
        return Err(EcError::BadParams);
    }
    if shards.len() < k as usize * shard_len || out.len() < body_len {
        return Err(EcError::BufferTooSmall {
            needed: body_len,
            actual: out.len().min(shards.len()),
        });
    }
    out[..body_len].copy_from_slice(&shards[..body_len]);
    Ok(())
}

// ── Reconstruct ────────────────────────────────────────────────────

/// Rebuild every missing shard in place. `present_mask` bit s set
/// means shard s's bytes in the buffer are valid; at least k bits
/// must be set. On success the whole buffer (all k+m shards) is
/// valid — the mask's complement has been recomputed.
pub fn reconstruct(
    shards: &mut [u8],
    shard_len: usize,
    k: u8,
    m: u8,
    present_mask: u32,
) -> Result<(), EcError> {
    check_params(k, m, shard_len, shards)?;
    let total = k as usize + m as usize;
    let present = (present_mask & ((1u32 << total) - 1)).count_ones() as u8;
    if present < k {
        return Err(EcError::NotEnoughShards { present, need: k });
    }
    let all_data_present = {
        let data_mask = (1u32 << k) - 1;
        present_mask & data_mask == data_mask
    };

    if !all_data_present {
        // Choose the first k present shards as the solve basis.
        let mut chosen = [0u8; MAX_SHARDS];
        let mut cnt = 0usize;
        for s in 0..total {
            if present_mask & (1u32 << s) != 0 && cnt < k as usize {
                chosen[cnt] = s as u8;
                cnt += 1;
            }
        }
        // M row r = generator row of chosen shard r over the k data
        // shards: identity for data shards, Cauchy for parity.
        let mut mat = [[0u8; MAX_SHARDS]; MAX_SHARDS];
        for (r, &s) in chosen[..k as usize].iter().enumerate() {
            if s < k {
                mat[r][s as usize] = 1;
            } else {
                for i in 0..k {
                    mat[r][i as usize] = cauchy(k, s - k, i);
                }
            }
        }
        let inv = invert(&mut mat, k as usize)?;
        // data[i] = Σ_r inv[i][r] · shard[chosen[r]] — only for
        // missing data shards; the reads (chosen, present) and the
        // write (missing) never alias.
        for i in 0..k {
            if present_mask & (1u32 << i) != 0 {
                continue;
            }
            let dst = i as usize * shard_len;
            for p in 0..shard_len {
                let mut acc = 0u8;
                for r in 0..k as usize {
                    let src = chosen[r] as usize * shard_len;
                    acc ^= gf_mul(inv[i as usize][r], shards[src + p]);
                }
                shards[dst + p] = acc;
            }
        }
    }

    // All data shards valid now — recompute any missing parity.
    for j in 0..m {
        let s = k + j;
        if present_mask & (1u32 << s) != 0 {
            continue;
        }
        let base = s as usize * shard_len;
        shards[base..base + shard_len].fill(0);
        for i in 0..k {
            let c = cauchy(k, j, i);
            let src = i as usize * shard_len;
            for p in 0..shard_len {
                shards[base + p] ^= gf_mul(c, shards[src + p]);
            }
        }
    }
    Ok(())
}

/// Gauss-Jordan inversion of the leading n×n block of `mat`.
/// Cauchy-mix matrices are always invertible, so a zero pivot
/// column means caller error (duplicate chosen shard) — surfaced
/// as BadParams rather than a panic.
fn invert(
    mat: &mut [[u8; MAX_SHARDS]; MAX_SHARDS],
    n: usize,
) -> Result<[[u8; MAX_SHARDS]; MAX_SHARDS], EcError> {
    let mut inv = [[0u8; MAX_SHARDS]; MAX_SHARDS];
    for (i, row) in inv.iter_mut().enumerate().take(n) {
        row[i] = 1;
    }
    for col in 0..n {
        // Partial pivot: find a row at/below `col` with a nonzero
        // entry in this column.
        let mut pivot = None;
        for r in col..n {
            if mat[r][col] != 0 {
                pivot = Some(r);
                break;
            }
        }
        let pivot = match pivot {
            Some(p) => p,
            None => return Err(EcError::BadParams),
        };
        if pivot != col {
            mat.swap(pivot, col);
            inv.swap(pivot, col);
        }
        // Normalize the pivot row.
        let pinv = gf_inv(mat[col][col]);
        for c in 0..n {
            mat[col][c] = gf_mul(mat[col][c], pinv);
            inv[col][c] = gf_mul(inv[col][c], pinv);
        }
        // Eliminate the column from every other row.
        for r in 0..n {
            if r == col || mat[r][col] == 0 {
                continue;
            }
            let f = mat[r][col];
            for c in 0..n {
                mat[r][c] ^= gf_mul(f, mat[col][c]);
                inv[r][c] ^= gf_mul(f, inv[col][c]);
            }
        }
    }
    Ok(inv)
}
