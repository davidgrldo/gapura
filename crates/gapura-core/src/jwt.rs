//! Reading a JWKS document and verifying a JWT against a policy's keys.
//!
//! Shared by the data plane, which reads each document once per configuration generation and
//! verifies every request against the result, and by the control plane, which reads a document
//! before storing it so that one the data plane would find no usable key in is refused when it is
//! written rather than discovered when every request is. Both read it here, so the two cannot
//! disagree about which keys a document holds.
//!
//! The one exception in this crate to "no clock": [`verify`] reads the system clock, through
//! `jsonwebtoken`, to check a token's `exp` and `nbf`.

use std::collections::HashMap;

use crate::config::JwtPolicy;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};

/// The largest JWKS document a policy uses: room for dozens of keys, and a bound on what every
/// configuration served to every data plane repeats. The control plane refuses a longer paste and
/// the data plane stops reading a longer fetch.
pub const MAX_JWKS_BYTES: usize = 64 * 1024;

/// Whether a JWKS document holds key material that must never verify anything: an HMAC secret
/// (`kty: "oct"`), which anyone who can read the document -- a workspace viewer, or the whole
/// internet for a published `jwks_uri` -- could sign with; or a private key (`d`, `p`, `q`, `dp`,
/// `dq` or `qi`, RFC 7517 section 4), which can *sign* tokens for every audience this gateway
/// verifies. Verification needs public keys only. An unreadable document holds nothing.
pub fn holds_a_secret(jwks: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(jwks).is_ok_and(|document| {
        document["keys"].as_array().is_some_and(|keys| {
            keys.iter().any(|key| {
                key["kty"] == "oct"
                    || ["d", "p", "q", "dp", "dq", "qi"]
                        .iter()
                        .any(|field| key.get(*field).is_some_and(|v| !v.is_null()))
            })
        })
    })
}

/// Decoding keys by `kid`, plus the keys a JWKS offered without one.
#[derive(Default)]
pub struct Keys {
    by_kid: HashMap<String, (DecodingKey, Algorithm)>,
    /// A JWKS is allowed to omit `kid`, and a token is allowed to omit the header. These are
    /// tried for a token without a `kid`, and for one whose `kid` names no key in `by_kid`: an
    /// IdP that stamps `kid` on its tokens but publishes a key without one still verifies.
    anonymous: Vec<(DecodingKey, Algorithm)>,
    /// Keys the document offered that could not be used.
    skipped: usize,
}

impl Keys {
    /// How many keys a token can be verified with. Two keys with one `kid` count once: the
    /// later replaces the earlier, as a lookup by that `kid` finds only one.
    pub fn usable(&self) -> usize {
        self.by_kid.len() + self.anonymous.len()
    }

    /// How many keys the document offered that cannot verify anything: a key type this verifier
    /// does not read, key material that does not parse, no `alg` it knows, or an `alg` the key's
    /// type or curve contradicts.
    pub fn skipped(&self) -> usize {
        self.skipped
    }
}

/// Why a JWKS document yields no keys at all.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JwksError {
    /// Not a JSON object with a `keys` array of JWKs.
    #[error("not a JWKS document")]
    Unreadable,
    /// A key set, but not one of its keys can verify anything.
    #[error("no usable key ({skipped} unusable)")]
    NoUsableKey { skipped: usize },
}

/// The keys `jwks` holds that a token can be verified with. A key is usable when `jsonwebtoken`
/// reads its material, it names an `alg` this verifier knows, and that `alg` fits the key: an
/// RSA key labelled ES256, or a P-384 key labelled ES256, would be refused by `jsonwebtoken` at
/// every verification, so it counts as skipped here rather than usable. The algorithm comes from
/// the key, never from a token. A document with at least one usable key is `Ok` and says how many
/// it skipped.
pub fn keys(jwks: &str) -> Result<Keys, JwksError> {
    let set = serde_json::from_str::<jsonwebtoken::jwk::JwkSet>(jwks)
        .map_err(|_| JwksError::Unreadable)?;
    let mut keys = Keys::default();
    for jwk in set.keys {
        let alg = jwk
            .common
            .key_algorithm
            .and_then(|a| a.to_string().parse::<Algorithm>().ok());
        match (DecodingKey::from_jwk(&jwk), alg) {
            (Ok(k), Some(alg)) if fits(&jwk, &k, alg) => match &jwk.common.key_id {
                Some(kid) => {
                    keys.by_kid.insert(kid.clone(), (k, alg));
                }
                None => keys.anonymous.push((k, alg)),
            },
            _ => keys.skipped += 1,
        }
    }
    if keys.usable() == 0 {
        return Err(JwksError::NoUsableKey {
            skipped: keys.skipped,
        });
    }
    Ok(keys)
}

/// Whether `alg` is one `key` can verify: the same family (HMAC, RSA, EC, EdDSA), and for a
/// curve-based key the curve that algorithm is defined over.
fn fits(jwk: &jsonwebtoken::jwk::Jwk, key: &DecodingKey, alg: Algorithm) -> bool {
    use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve};
    if key.family() != alg.family() {
        return false;
    }
    match (&jwk.algorithm, alg) {
        (AlgorithmParameters::EllipticCurve(p), Algorithm::ES256) => p.curve == EllipticCurve::P256,
        (AlgorithmParameters::EllipticCurve(p), Algorithm::ES384) => p.curve == EllipticCurve::P384,
        (AlgorithmParameters::OctetKeyPair(p), Algorithm::EdDSA) => {
            p.curve == EllipticCurve::Ed25519
        }
        _ => true,
    }
}

/// Why a request was refused. Each maps to 401, but they are separated because "no token" and
/// "a token signed by the wrong key" are different operator problems and the logs should say so.
#[derive(Debug, PartialEq)]
pub enum Refusal {
    Missing,
    Malformed,
    UnknownKey,
    BadSignature,
    Claims,
}

impl Refusal {
    pub fn as_str(&self) -> &'static str {
        match self {
            Refusal::Missing => "missing",
            Refusal::Malformed => "malformed",
            Refusal::UnknownKey => "unknown_key",
            Refusal::BadSignature => "bad_signature",
            Refusal::Claims => "claims",
        }
    }
}

/// Whether `token` is one `policy` accepts, verified with `keys`, the keys of its JWKS, and its
/// claims when it is.
pub fn verify(
    policy: &JwtPolicy,
    keys: &Keys,
    token: Option<&str>,
) -> Result<serde_json::Value, Refusal> {
    let Some(token) = token else {
        return Err(Refusal::Missing);
    };
    let header = jsonwebtoken::decode_header(token).map_err(|_| Refusal::Malformed)?;
    // A `kid` that names a key gets that key alone; one that names nothing falls back to the
    // keys published without a `kid`, as a token without a `kid` does.
    let candidates: Vec<&(DecodingKey, Algorithm)> =
        match header.kid.as_ref().and_then(|kid| keys.by_kid.get(kid)) {
            Some(key) => vec![key],
            None => keys.anonymous.iter().collect(),
        };
    if candidates.is_empty() {
        return Err(Refusal::UnknownKey);
    }

    let mut last = Refusal::BadSignature;
    for (key, alg) in candidates {
        let mut validation = Validation::new(*alg);
        match &policy.issuer {
            Some(iss) => validation.set_issuer(&[iss]),
            // Off explicitly. `jsonwebtoken` validates nothing it was not told to, and leaving
            // that implicit is how a policy ends up accepting any issuer without anyone deciding.
            None => validation.iss = None,
        }
        match &policy.audience {
            Some(aud) => validation.set_audience(&[aud]),
            None => validation.validate_aud = false,
        }
        // `set_issuer` and `set_audience` only say which values are acceptable when the claim
        // is there; `jsonwebtoken` skips the check for a token that leaves the claim out. A
        // policy that names an issuer or an audience means the claim is required, so say so.
        let mut required = vec!["exp"];
        if policy.issuer.is_some() {
            required.push("iss");
        }
        if policy.audience.is_some() {
            required.push("aud");
        }
        validation.set_required_spec_claims(&required);
        // Off by default in `jsonwebtoken`; a token that says it is not valid yet is not.
        validation.validate_nbf = true;
        match jsonwebtoken::decode::<serde_json::Value>(token, key, &validation) {
            Ok(data) => return Ok(data.claims),
            Err(e) => {
                last = match e.kind() {
                    jsonwebtoken::errors::ErrorKind::InvalidSignature => Refusal::BadSignature,
                    _ => Refusal::Claims,
                }
            }
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;

    const SECRET: &[u8] = b"a-secret-long-enough-for-hs256-to-be-happy";

    fn oct(kid: Option<&str>) -> serde_json::Value {
        let k = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(SECRET);
        let mut key = json!({"kty": "oct", "alg": "HS256", "k": k});
        if let Some(kid) = kid {
            key["kid"] = json!(kid);
        }
        key
    }

    /// An `oct` JWKS, which is what an HMAC secret looks like published as a key set.
    fn jwks(kid: Option<&str>) -> String {
        json!({"keys": [oct(kid)]}).to_string()
    }

    fn token(kid: Option<&str>, claims: serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = kid.map(str::to_string);
        encode(&header, &claims, &EncodingKey::from_secret(SECRET)).unwrap()
    }

    fn policy(jwks: String) -> JwtPolicy {
        JwtPolicy {
            issuer: Some("https://id.example".into()),
            audience: Some("orders".into()),
            jwks,
            ..JwtPolicy::default()
        }
    }

    fn good_claims() -> serde_json::Value {
        json!({
            "iss": "https://id.example",
            "aud": "orders",
            "exp": 4102444800u64, // 2100
        })
    }

    fn keys_for(p: &JwtPolicy) -> Keys {
        let keys = keys(&p.jwks).expect("the fixture's own JWKS has to parse");
        assert_eq!(keys.skipped(), 0, "and every key in it");
        keys
    }

    #[test]
    fn a_document_is_counted_by_the_keys_it_can_use() {
        let unusable = json!({"kty": "oct", "k": "AAAA"}); // no alg
        let document = json!({"keys": [oct(Some("k1")), oct(None), unusable]}).to_string();
        let read = keys(&document).unwrap();
        assert_eq!((read.usable(), read.skipped()), (2, 1));
        // One kid twice is one key a token can name.
        let twice = json!({"keys": [oct(Some("k1")), oct(Some("k1"))]}).to_string();
        assert_eq!(keys(&twice).unwrap().usable(), 1);
    }

    #[test]
    fn a_document_without_a_usable_key_is_an_error() {
        for (document, error) in [
            ("not a key set at all", JwksError::Unreadable),
            (r#"{"no":"keys"}"#, JwksError::Unreadable),
            (r#"{"keys":[]}"#, JwksError::NoUsableKey { skipped: 0 }),
            (
                r#"{"keys":[{"kty":"oct","k":"AAAA"}]}"#,
                JwksError::NoUsableKey { skipped: 1 },
            ),
        ] {
            assert_eq!(keys(document).err(), Some(error), "{document}");
        }
    }

    #[test]
    fn a_token_this_policy_accepts_is_accepted() {
        let p = policy(jwks(Some("k1")));
        let t = token(Some("k1"), good_claims());
        assert_eq!(verify(&p, &keys_for(&p), Some(&t)).map(|_| ()), Ok(()));
    }

    #[test]
    fn a_verified_token_hands_back_its_claims() {
        let p = policy(jwks(Some("k1")));
        let t = token(
            Some("k1"),
            json!({"iss": "https://id.example", "aud": "orders", "exp": 4102444800u64, "sub": "mobile"}),
        );
        assert_eq!(
            verify(&p, &keys_for(&p), Some(&t)).unwrap()["sub"],
            "mobile"
        );
    }

    #[test]
    fn no_token_at_all_is_a_different_answer_from_a_bad_one() {
        let p = policy(jwks(Some("k1")));
        assert_eq!(verify(&p, &keys_for(&p), None), Err(Refusal::Missing));
        assert_eq!(
            verify(&p, &keys_for(&p), Some("not-a-jwt")),
            Err(Refusal::Malformed)
        );
    }

    #[test]
    fn a_signature_from_another_key_is_refused() {
        let p = policy(jwks(Some("k1")));
        let forged = encode(
            &{
                let mut h = Header::new(Algorithm::HS256);
                h.kid = Some("k1".into());
                h
            },
            &good_claims(),
            &EncodingKey::from_secret(b"a-different-secret-entirely-not-ours"),
        )
        .unwrap();
        assert_eq!(
            verify(&p, &keys_for(&p), Some(&forged)),
            Err(Refusal::BadSignature)
        );
    }

    #[test]
    fn a_kid_the_policy_never_published_is_refused() {
        let p = policy(jwks(Some("k1")));
        let t = token(Some("k2"), good_claims());
        assert_eq!(
            verify(&p, &keys_for(&p), Some(&t)),
            Err(Refusal::UnknownKey)
        );
    }

    /// A correctly signed token from the wrong issuer is the case that matters most: the
    /// signature proves who minted it, and without this check any issuer whose key is listed
    /// could mint tokens for this route.
    #[test]
    fn a_valid_signature_from_the_wrong_issuer_is_still_refused() {
        let p = policy(jwks(Some("k1")));
        let mut claims = good_claims();
        claims["iss"] = json!("https://someone-else.example");
        assert_eq!(
            verify(&p, &keys_for(&p), Some(&token(Some("k1"), claims))),
            Err(Refusal::Claims)
        );
    }

    #[test]
    fn a_valid_signature_for_the_wrong_audience_is_still_refused() {
        let p = policy(jwks(Some("k1")));
        let mut claims = good_claims();
        claims["aud"] = json!("billing");
        assert_eq!(
            verify(&p, &keys_for(&p), Some(&token(Some("k1"), claims))),
            Err(Refusal::Claims)
        );
    }

    #[test]
    fn an_expired_token_is_refused() {
        let p = policy(jwks(Some("k1")));
        let mut claims = good_claims();
        claims["exp"] = json!(1000);
        assert_eq!(
            verify(&p, &keys_for(&p), Some(&token(Some("k1"), claims))),
            Err(Refusal::Claims)
        );
    }

    /// A JWKS may omit `kid` and so may a token header. One key is unambiguous.
    #[test]
    fn a_key_set_without_key_ids_still_works() {
        let p = policy(jwks(None));
        assert_eq!(
            verify(&p, &keys_for(&p), Some(&token(None, good_claims()))).map(|_| ()),
            Ok(())
        );
    }

    /// The `Keys` doc promises it: an IdP that stamps `kid` on its tokens but publishes its one
    /// key without one is not refused as `unknown_key`.
    #[test]
    fn a_kid_no_key_carries_falls_back_to_the_keys_without_one() {
        let p = policy(jwks(None));
        let t = token(Some("abc"), good_claims());
        assert_eq!(verify(&p, &keys_for(&p), Some(&t)).map(|_| ()), Ok(()));
    }

    /// The fallback is for a `kid` nothing answers to. A `kid` that names a key gets that key
    /// alone, and a bad signature against it is not retried against the anonymous ones.
    #[test]
    fn a_kid_that_names_a_key_does_not_fall_back() {
        let other = json!({
            "kty": "oct",
            "alg": "HS256",
            "kid": "k1",
            "k": base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(b"a-different-secret-entirely-not-ours"),
        });
        let p = policy(json!({"keys": [other, oct(None)]}).to_string());
        let t = token(Some("k1"), good_claims());
        assert_eq!(
            verify(&p, &keys_for(&p), Some(&t)),
            Err(Refusal::BadSignature)
        );
    }

    // Public key material from RFC 7517, appendix A.1. `keys` only has to read it, not verify
    // with it, so the curve it is really on does not matter to the tests that relabel it.
    const EC_X: &str = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";
    const EC_Y: &str = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";

    fn ec(crv: &str, alg: &str) -> serde_json::Value {
        json!({"kty": "EC", "crv": crv, "alg": alg, "x": EC_X, "y": EC_Y, "kid": "e"})
    }

    fn rsa(alg: &str) -> serde_json::Value {
        json!({"kty": "RSA", "alg": alg, "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw", "e": "AQAB", "kid": "r"})
    }

    #[test]
    fn a_key_whose_alg_fits_its_type_and_curve_is_usable() {
        for key in [
            ec("P-256", "ES256"),
            ec("P-384", "ES384"),
            rsa("RS256"),
            rsa("PS256"),
        ] {
            let document = json!({"keys": [key]}).to_string();
            let read = keys(&document).unwrap_or_else(|e| panic!("{document}: {e}"));
            assert_eq!((read.usable(), read.skipped()), (1, 0), "{document}");
        }
    }

    /// `jsonwebtoken` refuses such a pair at every verification, so a document holding only
    /// these must be refused when it is written, not discovered when every request is a 401.
    #[test]
    fn a_key_whose_alg_contradicts_its_type_or_curve_is_skipped() {
        for key in [
            rsa("ES256"),
            rsa("HS256"),
            ec("P-256", "RS256"),
            ec("P-384", "ES256"),
            ec("P-256", "ES384"),
            ec("P-256", "EdDSA"),
            json!({"kty": "oct", "alg": "RS256", "k": "AAAA"}),
        ] {
            let document = json!({"keys": [key]}).to_string();
            assert_eq!(
                keys(&document).err(),
                Some(JwksError::NoUsableKey { skipped: 1 }),
                "{document}"
            );
        }
        // Beside a key that fits, it is counted as skipped rather than refusing the document.
        let document = json!({"keys": [ec("P-384", "ES256"), rsa("RS256")]}).to_string();
        let read = keys(&document).unwrap();
        assert_eq!((read.usable(), read.skipped()), (1, 1));
    }

    /// The direction a configuration mistake must fail in. A policy whose keys did not load has
    /// no way to verify anything, and letting traffic past unverified would turn a typo into an
    /// open route.
    #[test]
    fn no_keys_refuse_everything() {
        let p = policy("not a key set at all".into());
        assert_eq!(
            verify(
                &p,
                &Keys::default(),
                Some(&token(Some("k1"), good_claims()))
            ),
            Err(Refusal::UnknownKey)
        );
    }

    #[test]
    fn a_policy_that_names_an_audience_refuses_a_token_without_one() {
        let p = policy(jwks(Some("k1")));
        let mut claims = good_claims();
        claims.as_object_mut().unwrap().remove("aud");
        let t = token(Some("k1"), claims);
        assert_eq!(verify(&p, &keys_for(&p), Some(&t)), Err(Refusal::Claims));
    }

    #[test]
    fn a_policy_that_names_an_issuer_refuses_a_token_without_one() {
        let p = policy(jwks(Some("k1")));
        let mut claims = good_claims();
        claims.as_object_mut().unwrap().remove("iss");
        let t = token(Some("k1"), claims);
        assert_eq!(verify(&p, &keys_for(&p), Some(&t)), Err(Refusal::Claims));
    }

    #[test]
    fn a_policy_that_names_neither_does_not_require_them() {
        let mut p = policy(jwks(Some("k1")));
        p.issuer = None;
        p.audience = None;
        let t = token(Some("k1"), json!({"exp": 4102444800u64}));
        assert_eq!(verify(&p, &keys_for(&p), Some(&t)).map(|_| ()), Ok(()));
    }

    #[test]
    fn a_token_that_is_not_valid_yet_is_refused() {
        let p = policy(jwks(Some("k1")));
        let mut claims = good_claims();
        claims["nbf"] = json!(4102444000u64); // still in the future in 2100's terms
        let t = token(Some("k1"), claims);
        assert_eq!(verify(&p, &keys_for(&p), Some(&t)), Err(Refusal::Claims));
    }

    #[test]
    fn the_algorithm_comes_from_the_key_not_the_token() {
        // A token claiming HS384 against an HS256 key is refused rather than verified with the
        // key read as something it is not.
        let p = policy(jwks(Some("k1")));
        let mut header = Header::new(Algorithm::HS384);
        header.kid = Some("k1".into());
        let t = encode(&header, &good_claims(), &EncodingKey::from_secret(SECRET)).unwrap();
        assert!(verify(&p, &keys_for(&p), Some(&t)).is_err());
    }

    #[test]
    fn a_jwks_uri_policy_reads_and_writes_beside_an_empty_document() {
        let policy: JwtPolicy =
            serde_json::from_value(json!({"issuer": "i", "jwks_uri": "https://idp.example/jwks"}))
                .unwrap();
        assert_eq!(
            policy.jwks, "",
            "no document until the data plane fetches one"
        );
        assert_eq!(policy.jwks_uri.as_deref(), Some("https://idp.example/jwks"));
        let written = serde_json::to_value(&policy).unwrap();
        assert_eq!(
            written["jwks"], "",
            "always written, so a data plane older than jwks_uri still parses the configuration"
        );
        assert!(written.get("jwks_ca_pem").is_none());
        let verbatim = serde_json::to_value(JwtPolicy {
            jwks: "{}".into(),
            ..JwtPolicy::default()
        })
        .unwrap();
        assert!(
            verbatim.get("jwks_uri").is_none(),
            "a verbatim policy is written as before"
        );
    }

    #[test]
    fn a_secret_is_found_beside_public_keys() {
        let public = json!({"kty": "EC", "crv": "P-256", "alg": "ES256", "x": "x", "y": "y"});
        let doc = |keys: Vec<serde_json::Value>| json!({ "keys": keys }).to_string();
        assert!(!holds_a_secret(&doc(vec![public.clone()])));
        assert!(holds_a_secret(&doc(vec![public.clone(), oct(Some("k"))])));
        let mut private = public;
        private["d"] = json!("d");
        assert!(holds_a_secret(&doc(vec![private])));
        assert!(
            !holds_a_secret("not json"),
            "unreadable is a different refusal"
        );
    }
}
