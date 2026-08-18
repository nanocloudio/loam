//! Pin the SigV4 primitives against published vectors: RFC 4231
//! (HMAC-SHA256) and AWS's documented signing-key derivation
//! example. If these hold, the composed verification differs from
//! AWS only in canonicalization scope (documented in sigv4.rs).

#[allow(
    dead_code,
    unused_imports,
    reason = "shared include; each includer uses a subset"
)]
#[path = "../../../target/fluxor/fluxor-abi/sdk/crypto/sha256.rs"]
mod sha256_impl;

mod sigv4_scope {
    pub mod sha256 {
        pub use super::super::sha256_impl::Sha256;
    }
    #[allow(
        dead_code,
        unused_imports,
        reason = "shared include; each includer uses a subset"
    )]
    #[path = "../../src/sigv4.rs"]
    pub mod sigv4;
}
use sigv4_scope::sigv4;

#[test]
fn hmac_sha256_rfc4231_case_1() {
    let key = [0x0bu8; 20];
    let mac = sigv4::hmac_sha256(&key, b"Hi There");
    assert_eq!(
        sigv4::hex(&mac),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
}

#[test]
fn hmac_sha256_rfc4231_case_2() {
    // Key "Jefe", data "what do ya want for nothing?"
    let mac = sigv4::hmac_sha256(b"Jefe", b"what do ya want for nothing?");
    assert_eq!(
        sigv4::hex(&mac),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}

#[test]
fn aws_documented_signing_key_derivation() {
    // From "Deriving the signing key" in the AWS SigV4 docs.
    let key = sigv4::derive_signing_key(
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "20150830",
        "us-east-1",
        "iam",
    );
    assert_eq!(
        sigv4::hex(&key),
        "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
    );
}

#[test]
fn amz_date_parses_to_epoch() {
    // 2015-08-30T12:36:00Z = 1440938160.
    assert_eq!(sigv4::parse_amz_date("20150830T123600Z"), Some(1440938160));
    // Epoch itself.
    assert_eq!(sigv4::parse_amz_date("19700101T000000Z"), Some(0));
    assert_eq!(sigv4::parse_amz_date("garbage"), None);
    assert_eq!(sigv4::parse_amz_date("20150830T123600X"), None);
}

#[test]
fn empty_payload_constant_is_sha256_of_nothing() {
    assert_eq!(sigv4::sha256_hex(b""), sigv4::EMPTY_PAYLOAD_SHA256);
}

// ── Presigned (query) auth ─────────────────────────────────────────

/// The AWS SigV4 docs' presigned example request: GET
/// examplebucket.s3.amazonaws.com/test.txt, 86400s validity,
/// signed 20130524T000000Z with the documented example keypair.
/// Signature cross-checked against an independent Python
/// (hmac/hashlib) implementation of AWS's documented steps; the
/// primitives themselves are pinned by the RFC 4231 and
/// signing-key vectors above.
fn aws_presigned_example_path() -> String {
    "/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256\
     &X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request\
     &X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host\
     &X-Amz-Signature=3ed0be64024db54d5574a27da223529635c383f911f80e636f0ccc13890053d2"
        .replace(' ', "")
}

fn aws_presigned_headers() -> Vec<(String, String)> {
    vec![("host".into(), "examplebucket.s3.amazonaws.com".into())]
}

fn example_lookup(key: &str) -> Option<String> {
    (key == "AKIAIOSFODNN7EXAMPLE").then(|| "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string())
}

#[test]
fn aws_documented_presigned_url_verifies() {
    // now = signing time + 1h, well inside the 24h window.
    let now = sigv4::parse_amz_date("20130524T000000Z").unwrap() + 3600;
    let got = sigv4::verify(
        "GET",
        &aws_presigned_example_path(),
        &aws_presigned_headers(),
        sigv4::UNSIGNED_PAYLOAD,
        now,
        example_lookup,
    );
    assert_eq!(got, Ok("AKIAIOSFODNN7EXAMPLE".to_string()));
}

#[test]
fn presigned_url_expires() {
    let now = sigv4::parse_amz_date("20130524T000000Z").unwrap() + 86400 + 1;
    let got = sigv4::verify(
        "GET",
        &aws_presigned_example_path(),
        &aws_presigned_headers(),
        sigv4::UNSIGNED_PAYLOAD,
        now,
        example_lookup,
    );
    assert_eq!(got, Err(sigv4::AuthError::Expired));
}

#[test]
fn presigned_url_tamper_rejected() {
    let now = sigv4::parse_amz_date("20130524T000000Z").unwrap() + 3600;
    // Different object than what was signed.
    let path = aws_presigned_example_path().replace("/test.txt", "/other.txt");
    let got = sigv4::verify(
        "GET",
        &path,
        &aws_presigned_headers(),
        sigv4::UNSIGNED_PAYLOAD,
        now,
        example_lookup,
    );
    assert_eq!(got, Err(sigv4::AuthError::SignatureMismatch));
    // Or presented too early (beyond skew).
    let got = sigv4::verify(
        "GET",
        &aws_presigned_example_path(),
        &aws_presigned_headers(),
        sigv4::UNSIGNED_PAYLOAD,
        sigv4::parse_amz_date("20130524T000000Z").unwrap() - 3600,
        example_lookup,
    );
    assert_eq!(got, Err(sigv4::AuthError::ClockSkew));
}
