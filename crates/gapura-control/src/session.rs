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
    if now > session.expires_at {
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
