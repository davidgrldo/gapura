//! Sessions are a signed cookie and nothing else: this stage stores no state.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// The identity provider's subject claim.
    pub subject: String,
    pub groups: Vec<String>,
    /// Unix seconds after which this is no longer valid.
    pub expires_at: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Invalid {
    Malformed,
    BadSignature,
    Expired,
}

impl std::fmt::Display for Invalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The words a reader meets in a log or an error, phrased as what the cookie is
        // rather than what the code did, so `?` and tracing carry something usable.
        let what = match self {
            Invalid::Malformed => "the session cookie is not one of ours",
            Invalid::BadSignature => "the session cookie failed signature verification",
            Invalid::Expired => "the session has expired",
        };
        f.write_str(what)
    }
}

impl std::error::Error for Invalid {}

fn sign(payload: &[u8], key: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(payload);
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

pub fn encode(session: &Session, key: &[u8]) -> String {
    let json = serde_json::to_vec(session).expect("a Session always serialises");
    let payload = URL_SAFE_NO_PAD.encode(&json);
    let signature = sign(payload.as_bytes(), key);
    format!("{payload}.{signature}")
}

pub fn decode(cookie: &str, key: &[u8], now: u64) -> Result<Session, Invalid> {
    let (payload, signature) = cookie.split_once('.').ok_or(Invalid::Malformed)?;
    // Verify before decoding: nothing from an unverified payload should reach a parser,
    // and `Mac::verify_slice` is the constant-time comparison we want here.
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(payload.as_bytes());
    // A signature field that is not even valid base64 is a structurally broken cookie, not a
    // cryptographic mismatch, so it is Malformed rather than BadSignature; only a well-formed
    // signature that fails the constant-time comparison below counts as a bad signature.
    let provided = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| Invalid::Malformed)?;
    mac.verify_slice(&provided)
        .map_err(|_| Invalid::BadSignature)?;

    let json = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| Invalid::Malformed)?;
    let session: Session = serde_json::from_slice(&json).map_err(|_| Invalid::Malformed)?;
    if now >= session.expires_at {
        return Err(Invalid::Expired);
    }
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"a key of no particular significance";

    fn session(expires_at: u64) -> Session {
        Session {
            subject: "alice@example.test".into(),
            groups: vec!["team-a".into()],
            expires_at,
        }
    }

    #[test]
    fn a_session_survives_a_round_trip() {
        let original = session(2000);
        let got = decode(&encode(&original, KEY), KEY, 1000).unwrap();
        assert_eq!(got, original);
    }

    #[test]
    fn a_session_signed_with_another_key_is_refused() {
        let cookie = encode(&session(2000), b"a different key");
        assert_eq!(decode(&cookie, KEY, 1000), Err(Invalid::BadSignature));
    }

    #[test]
    fn altering_the_payload_invalidates_the_signature() {
        let cookie = encode(&session(2000), KEY);
        let (payload, signature) = cookie.split_once('.').unwrap();
        let mut bytes = payload.as_bytes().to_vec();
        bytes[0] = if bytes[0] == b'A' { b'B' } else { b'A' };
        let tampered = format!("{}.{signature}", String::from_utf8(bytes).unwrap());
        assert_eq!(decode(&tampered, KEY, 1000), Err(Invalid::BadSignature));
    }

    #[test]
    fn a_session_past_its_expiry_is_refused() {
        let cookie = encode(&session(2000), KEY);
        assert_eq!(decode(&cookie, KEY, 2001), Err(Invalid::Expired));
    }

    #[test]
    fn expiry_is_checked_after_the_signature_not_before() {
        // An expired cookie with a broken signature must report the signature, so that a
        // forged cookie can never be told apart from an honestly stale one.
        let cookie = encode(&session(2000), b"a different key");
        assert_eq!(decode(&cookie, KEY, 2001), Err(Invalid::BadSignature));
    }

    #[test]
    fn nonsense_is_refused_without_panicking() {
        assert_eq!(decode("", KEY, 1000), Err(Invalid::Malformed));
        assert_eq!(decode("no-dot-here", KEY, 1000), Err(Invalid::Malformed));
        assert_eq!(decode("!!!.!!!", KEY, 1000), Err(Invalid::Malformed));
    }
}

/// The env var holding the session-signing key, so restarts (and a fleet of replicas)
/// verify each other's cookies instead of only their own process's.
pub const SESSION_KEY_VAR: &str = "GAPURA_SESSION_KEY";

/// Below this length a key is not a secret. `Hmac::new_from_slice` accepts a key of any
/// length, including none, so an empty or unresolved Secret would otherwise sign sessions
/// that anyone can forge — and a forged session naming a group with a `*` grant reads every
/// namespace, defeating the scoping without going anywhere near the scoping code.
pub const MIN_SESSION_KEY_BYTES: usize = 32;

/// The key a configured `GAPURA_SESSION_KEY` yields, or why it is not usable as one.
///
/// The value may arrive as base64 — the shape secret managers hand out — and is decoded
/// when that reading yields a real key, which also stops the key being treated as UTF-8:
/// it is bytes. A value that is already 32 or more raw bytes is taken as it stands, so
/// existing deployments keep working; when both readings are possible the decoded one
/// wins, because a 43-character secret that decodes to 32 bytes was base64 all along.
pub fn checked_session_key(configured: &str) -> anyhow::Result<Vec<u8>> {
    if let Some(decoded) = URL_SAFE_NO_PAD
        .decode(configured)
        .ok()
        .filter(|k| k.len() >= MIN_SESSION_KEY_BYTES)
    {
        return Ok(decoded);
    }
    let key = configured.as_bytes();
    anyhow::ensure!(
        key.len() >= MIN_SESSION_KEY_BYTES,
        "{} is {} bytes long; it must be at least {MIN_SESSION_KEY_BYTES}",
        SESSION_KEY_VAR,
        key.len()
    );
    Ok(key.to_vec())
}

/// A key for this process only: every session is invalidated on restart.
pub fn random_session_key() -> Vec<u8> {
    use rand::RngCore;
    let mut key = vec![0u8; MIN_SESSION_KEY_BYTES];
    rand::rng().fill_bytes(&mut key);
    key
}

/// The configured key, or a random one when nothing is configured.
pub fn session_key() -> anyhow::Result<Vec<u8>> {
    // An absent variable is a development convenience rather than a weak secret, so it
    // still falls back to a random key; a variable that is set but too short is a
    // misconfiguration that must stop the process instead of running unprotected.
    let Ok(configured) = std::env::var(SESSION_KEY_VAR) else {
        tracing::warn!(
            "{SESSION_KEY_VAR} is not set; generating a random session key for this process              only, so every session will be invalidated the next time it restarts"
        );
        return Ok(random_session_key());
    };
    checked_session_key(&configured)
}

#[cfg(test)]
mod session_key_tests {
    use super::*;

    #[test]
    fn an_empty_key_is_refused() {
        // What an unresolved Secret looks like: the variable is set, to nothing.
        assert!(checked_session_key("").is_err());
    }

    #[test]
    fn a_key_shorter_than_the_minimum_is_refused() {
        let error = checked_session_key(&"k".repeat(MIN_SESSION_KEY_BYTES - 1))
            .expect_err("one byte short is still short");
        let error = error.to_string();
        assert!(
            error.contains(SESSION_KEY_VAR) && error.contains(&MIN_SESSION_KEY_BYTES.to_string()),
            "the error must name the variable and the minimum, got {error}"
        );
    }

    #[test]
    fn a_key_of_adequate_length_is_taken_as_it_stands() {
        let configured = "k".repeat(MIN_SESSION_KEY_BYTES);
        assert_eq!(
            checked_session_key(&configured).unwrap(),
            configured.as_bytes()
        );
    }

    #[test]
    fn a_base64_key_is_decoded_rather_than_taken_as_utf8() {
        // 32 zero bytes as base64: raw it is 43 bytes and would pass as-is; decoded it is
        // exactly the key the operator pasted.
        let b64 = URL_SAFE_NO_PAD.encode([0u8; MIN_SESSION_KEY_BYTES]);
        assert_eq!(
            checked_session_key(&b64).unwrap(),
            vec![0u8; MIN_SESSION_KEY_BYTES]
        );
    }

    #[test]
    fn the_generated_fallback_key_passes_the_same_check() {
        // The fallback is a convenience, not an exemption: it must clear the bar it sets.
        assert!(random_session_key().len() >= MIN_SESSION_KEY_BYTES);
    }
}
