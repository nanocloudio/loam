//! AWS Signature Version 4 verification for the S3 gateway.
//!
//! Scope: header-based auth (`Authorization: AWS4-HMAC-SHA256 …`)
//! and presigned-URL (query) auth for the S3 service.
//! Canonicalization matches what loam's gateway
//! actually serves: the canonical URI is the path as sent (the
//! gateway never percent-decodes object keys), and the canonical
//! query string is the sorted raw `k=v` pairs.
//!
//! Requires `super::sha256::Sha256` (the fluxor SDK hasher) from
//! the including module — same include discipline as the wire
//! files, which is what lets the integration tests `#[path]` this
//! file and sign requests with an independent client-side signer.

use super::sha256::Sha256;

#[allow(
    dead_code,
    reason = "part of the SigV4 public vocabulary; some include scopes sign only non-empty payloads"
)]
pub const EMPTY_PAYLOAD_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// ±15 minutes, AWS's documented tolerance.
pub const MAX_CLOCK_SKEW_SECS: i64 = 15 * 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    MissingAuthorization,
    MalformedAuthorization,
    UnknownAccessKey,
    SignatureMismatch,
    PayloadHashMismatch,
    ClockSkew,
    Expired,
    MissingHeader(&'static str),
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex(&h.finalize())
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// HMAC-SHA256 (block size 64).
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        let mut h = Sha256::new();
        h.update(key);
        key_block[..32].copy_from_slice(&h.finalize());
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(msg);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_digest);
    outer.finalize()
}

/// SigV4 signing key: HMAC chain over date/region/service.
pub fn derive_signing_key(secret: &str, date: &str, region: &str, service: &str) -> [u8; 32] {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

/// Parsed pieces of an `AWS4-HMAC-SHA256` Authorization header.
#[derive(Debug, Clone)]
pub struct AuthHeader {
    pub access_key: String,
    pub date: String, // yyyymmdd from the credential scope
    pub region: String,
    pub service: String,
    pub signed_headers: Vec<String>,
    pub signature: String,
}

pub fn parse_authorization(value: &str) -> Result<AuthHeader, AuthError> {
    let rest = value
        .strip_prefix("AWS4-HMAC-SHA256")
        .ok_or(AuthError::MalformedAuthorization)?
        .trim();
    let mut access_key = None;
    let mut date = None;
    let mut region = None;
    let mut service = None;
    let mut signed_headers = None;
    let mut signature = None;
    for part in rest.split(',') {
        let part = part.trim();
        if let Some(cred) = part.strip_prefix("Credential=") {
            let mut it = cred.split('/');
            access_key = it.next().map(str::to_string);
            date = it.next().map(str::to_string);
            region = it.next().map(str::to_string);
            service = it.next().map(str::to_string);
            if it.next() != Some("aws4_request") {
                return Err(AuthError::MalformedAuthorization);
            }
        } else if let Some(sh) = part.strip_prefix("SignedHeaders=") {
            signed_headers = Some(sh.split(';').map(str::to_string).collect::<Vec<_>>());
        } else if let Some(sig) = part.strip_prefix("Signature=") {
            signature = Some(sig.to_string());
        }
    }
    Ok(AuthHeader {
        access_key: access_key.ok_or(AuthError::MalformedAuthorization)?,
        date: date.ok_or(AuthError::MalformedAuthorization)?,
        region: region.ok_or(AuthError::MalformedAuthorization)?,
        service: service.ok_or(AuthError::MalformedAuthorization)?,
        signed_headers: signed_headers.ok_or(AuthError::MalformedAuthorization)?,
        signature: signature.ok_or(AuthError::MalformedAuthorization)?,
    })
}

/// Build the canonical request + string-to-sign and return the
/// expected signature for `secret`.
pub fn compute_signature(
    secret: &str,
    auth: &AuthHeader,
    method: &str,
    raw_path: &str,
    headers: &[(String, String)],
    amz_date: &str,
    payload_hash: &str,
) -> String {
    let (uri, query) = match raw_path.split_once('?') {
        Some((u, q)) => (u, q),
        None => (raw_path, ""),
    };
    let canonical_query = {
        // X-Amz-Signature is never part of what it signs — this is
        // the presigned rule, and header-auth requests don't carry
        // the parameter.
        let mut pairs: Vec<&str> = query
            .split('&')
            .filter(|p| !p.is_empty() && !p.starts_with("X-Amz-Signature="))
            .collect();
        pairs.sort_unstable();
        pairs.join("&")
    };
    let mut canonical_headers = String::new();
    for name in &auth.signed_headers {
        let value = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim())
            .unwrap_or("");
        canonical_headers.push_str(&format!("{name}:{value}\n"));
    }
    let canonical_request = format!(
        "{method}\n{uri}\n{canonical_query}\n{canonical_headers}\n{}\n{payload_hash}",
        auth.signed_headers.join(";")
    );
    let scope = format!(
        "{}/{}/{}/aws4_request",
        auth.date, auth.region, auth.service
    );
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let key = derive_signing_key(secret, &auth.date, &auth.region, &auth.service);
    hex(&hmac_sha256(&key, string_to_sign.as_bytes()))
}

/// Parse `yyyymmddThhmmssZ` to unix seconds. Returns None on any
/// malformation.
pub fn parse_amz_date(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return None;
    }
    let num = |r: core::ops::Range<usize>| -> Option<i64> { s.get(r)?.parse().ok() };
    let (y, mo, d) = (num(0..4)?, num(4..6)?, num(6..8)?);
    let (h, mi, sec) = (num(9..11)?, num(11..13)?, num(13..15)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    // Howard Hinnant's days-from-civil.
    let y_adj = if mo <= 2 { y - 1 } else { y };
    let era = y_adj.div_euclid(400);
    let yoe = y_adj - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + h * 3600 + mi * 60 + sec)
}

/// Full verification: signature, payload hash, clock skew.
/// `lookup` maps an access key id to its secret. Returns the
/// verified access key id.
#[allow(
    clippy::too_many_arguments,
    reason = "bounded no_std step functions pass explicit scalar params"
)]
pub fn verify(
    method: &str,
    raw_path: &str,
    headers: &[(String, String)],
    body_sha256_hex: &str,
    now_epoch: i64,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<String, AuthError> {
    let header = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim().to_string())
    };
    let auth_value = match header("authorization") {
        Some(v) => v,
        None => {
            return verify_presigned(method, raw_path, headers, now_epoch, lookup);
        }
    };
    let auth = parse_authorization(&auth_value)?;
    let amz_date = header("x-amz-date").ok_or(AuthError::MissingHeader("x-amz-date"))?;
    let ts = parse_amz_date(&amz_date).ok_or(AuthError::MalformedAuthorization)?;
    if (now_epoch - ts).abs() > MAX_CLOCK_SKEW_SECS {
        return Err(AuthError::ClockSkew);
    }
    let declared_payload =
        header("x-amz-content-sha256").ok_or(AuthError::MissingHeader("x-amz-content-sha256"))?;
    if declared_payload != UNSIGNED_PAYLOAD && declared_payload != body_sha256_hex {
        return Err(AuthError::PayloadHashMismatch);
    }
    let secret = lookup(&auth.access_key).ok_or(AuthError::UnknownAccessKey)?;
    let expected = compute_signature(
        &secret,
        &auth,
        method,
        raw_path,
        headers,
        &amz_date,
        &declared_payload,
    );
    // Constant-time-ish comparison (length + fold).
    if expected.len() != auth.signature.len()
        || expected
            .bytes()
            .zip(auth.signature.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            != 0
    {
        return Err(AuthError::SignatureMismatch);
    }
    Ok(auth.access_key)
}

/// Minimal percent-decoding for the presigned auth parameters
/// (Credential's `%2F`, SignedHeaders' `%3B`). Object-key paths are
/// never decoded — the canonical URI is the path as sent.
fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hx = |c: u8| -> Option<u8> {
                match c {
                    b'0'..=b'9' => Some(c - b'0'),
                    b'a'..=b'f' => Some(c - b'a' + 10),
                    b'A'..=b'F' => Some(c - b'A' + 10),
                    _ => None,
                }
            };
            if let (Some(h), Some(l)) = (hx(b[i + 1]), hx(b[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Presigned max validity: 7 days (AWS's cap).
pub const MAX_PRESIGN_EXPIRES_SECS: i64 = 7 * 24 * 3600;

/// Presigned-URL (query) verification: the `X-Amz-*` parameters
/// carry what the Authorization header would; the payload is
/// UNSIGNED-PAYLOAD by definition; validity is
/// `[X-Amz-Date - skew, X-Amz-Date + X-Amz-Expires]`.
pub fn verify_presigned(
    method: &str,
    raw_path: &str,
    headers: &[(String, String)],
    now_epoch: i64,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<String, AuthError> {
    let query = raw_path.split_once('?').map(|(_, q)| q).unwrap_or("");
    let param = |name: &str| {
        query
            .split('&')
            .find_map(|p| p.strip_prefix(name).and_then(|r| r.strip_prefix('=')))
            .map(pct_decode)
    };
    match param("X-Amz-Algorithm") {
        Some(a) if a == "AWS4-HMAC-SHA256" => {}
        Some(_) => return Err(AuthError::MalformedAuthorization),
        None => return Err(AuthError::MissingAuthorization),
    }
    let credential = param("X-Amz-Credential").ok_or(AuthError::MalformedAuthorization)?;
    let mut it = credential.split('/');
    let access_key = it.next().unwrap_or("").to_string();
    let date = it.next().unwrap_or("").to_string();
    let region = it.next().unwrap_or("").to_string();
    let service = it.next().unwrap_or("").to_string();
    if access_key.is_empty() || it.next() != Some("aws4_request") {
        return Err(AuthError::MalformedAuthorization);
    }
    let signed_headers: Vec<String> = param("X-Amz-SignedHeaders")
        .ok_or(AuthError::MalformedAuthorization)?
        .split(';')
        .map(str::to_string)
        .collect();
    let signature = param("X-Amz-Signature").ok_or(AuthError::MalformedAuthorization)?;
    let amz_date = param("X-Amz-Date").ok_or(AuthError::MalformedAuthorization)?;
    let ts = parse_amz_date(&amz_date).ok_or(AuthError::MalformedAuthorization)?;
    let expires: i64 = param("X-Amz-Expires")
        .and_then(|e| e.parse().ok())
        .ok_or(AuthError::MalformedAuthorization)?;
    if !(1..=MAX_PRESIGN_EXPIRES_SECS).contains(&expires) {
        return Err(AuthError::MalformedAuthorization);
    }
    if now_epoch < ts - MAX_CLOCK_SKEW_SECS {
        return Err(AuthError::ClockSkew);
    }
    if now_epoch > ts + expires {
        return Err(AuthError::Expired);
    }
    let auth = AuthHeader {
        access_key,
        date,
        region,
        service,
        signed_headers,
        signature,
    };
    let secret = lookup(&auth.access_key).ok_or(AuthError::UnknownAccessKey)?;
    let expected = compute_signature(
        &secret,
        &auth,
        method,
        raw_path,
        headers,
        &amz_date,
        UNSIGNED_PAYLOAD,
    );
    if expected.len() != auth.signature.len()
        || expected
            .bytes()
            .zip(auth.signature.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            != 0
    {
        return Err(AuthError::SignatureMismatch);
    }
    Ok(auth.access_key)
}
