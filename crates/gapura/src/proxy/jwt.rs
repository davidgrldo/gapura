//! Verifying a JWT against a rule's policy.
//!
//! Keys are parsed once per configuration generation, not per request -- the same treatment
//! `compile_regexes` gives path patterns and `ParsedCert` gives certificates. A JWKS document is
//! a few hundred bytes of JSON and parsing one per request would put that on the hot path for no
//! benefit, since it cannot change between swaps.

use std::collections::HashMap;

use gapura_core::config::{Config, JwtPolicy, Plugin};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};

/// Decoding keys by `kid`, plus the keys a JWKS offered without one.
#[derive(Default)]
pub struct JwtKeys {
    by_kid: HashMap<String, (DecodingKey, Algorithm)>,
    /// A JWKS is allowed to omit `kid`, and a token is allowed to omit the header. With one key
    /// there is no ambiguity to resolve, so these are tried when a lookup by `kid` finds nothing.
    anonymous: Vec<(DecodingKey, Algorithm)>,
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

/// Parse every JWKS the configuration mentions. Returns the number of keys a document offered
/// that could not be parsed, so a swap can say so once rather than a request saying it forever.
pub fn compile(config: &Config) -> (HashMap<String, JwtKeys>, usize) {
    let mut out: HashMap<String, JwtKeys> = HashMap::new();
    let mut skipped = 0;
    for listener in &config.listeners {
        for rule in &listener.rules {
            for plugin in &rule.plugins {
                let Plugin::Jwt(policy) = plugin else {
                    continue;
                };
                if out.contains_key(&policy.jwks) {
                    continue;
                }
                let (keys, bad) = parse_jwks(&policy.jwks);
                skipped += bad;
                out.insert(policy.jwks.clone(), keys);
            }
        }
    }
    (out, skipped)
}

fn parse_jwks(document: &str) -> (JwtKeys, usize) {
    let mut keys = JwtKeys::default();
    let Ok(set) = serde_json::from_str::<jsonwebtoken::jwk::JwkSet>(document) else {
        // One unparseable document, not one per key. A policy whose keys did not load refuses
        // every request, which is the safe direction: the alternative is letting traffic
        // through unverified because a configuration error made verification impossible.
        return (keys, 1);
    };
    let mut skipped = 0;
    for jwk in set.keys {
        let alg = jwk
            .common
            .key_algorithm
            .and_then(|a| a.to_string().parse::<Algorithm>().ok());
        match (DecodingKey::from_jwk(&jwk), alg) {
            (Ok(k), Some(alg)) => match &jwk.common.key_id {
                Some(kid) => {
                    keys.by_kid.insert(kid.clone(), (k, alg));
                }
                None => keys.anonymous.push((k, alg)),
            },
            _ => skipped += 1,
        }
    }
    (keys, skipped)
}

/// `Bearer <token>` from the Authorization header, case-insensitively on the scheme.
pub fn bearer(header: Option<&str>) -> Option<&str> {
    let value = header?;
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
}

pub fn verify(policy: &JwtPolicy, keys: &JwtKeys, token: Option<&str>) -> Result<(), Refusal> {
    let Some(token) = token else {
        return Err(Refusal::Missing);
    };
    let header = jsonwebtoken::decode_header(token).map_err(|_| Refusal::Malformed)?;
    let candidates: Vec<&(DecodingKey, Algorithm)> = match &header.kid {
        Some(kid) => keys.by_kid.get(kid).into_iter().collect(),
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
        match jsonwebtoken::decode::<serde_json::Value>(token, key, &validation) {
            Ok(_) => return Ok(()),
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

    /// An `oct` JWKS, which is what an HMAC secret looks like published as a key set.
    fn jwks(kid: Option<&str>) -> String {
        let k = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(SECRET);
        let mut key = json!({"kty": "oct", "alg": "HS256", "k": k});
        if let Some(kid) = kid {
            key["kid"] = json!(kid);
        }
        json!({"keys": [key]}).to_string()
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
        }
    }

    fn good_claims() -> serde_json::Value {
        json!({
            "iss": "https://id.example",
            "aud": "orders",
            "exp": 4102444800u64, // 2100
        })
    }

    fn keys_for(p: &JwtPolicy) -> JwtKeys {
        let (keys, bad) = parse_jwks(&p.jwks);
        assert_eq!(bad, 0, "the fixture's own JWKS has to parse");
        keys
    }

    #[test]
    fn a_token_this_policy_accepts_is_accepted() {
        let p = policy(jwks(Some("k1")));
        let t = token(Some("k1"), good_claims());
        assert_eq!(verify(&p, &keys_for(&p), Some(&t)), Ok(()));
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
            verify(&p, &keys_for(&p), Some(&token(None, good_claims()))),
            Ok(())
        );
    }

    /// The direction a configuration mistake must fail in. A policy whose keys did not load has
    /// no way to verify anything, and letting traffic past unverified would turn a typo into an
    /// open route.
    #[test]
    fn a_policy_whose_keys_did_not_load_refuses_everything() {
        let p = policy("not a key set at all".into());
        let (keys, bad) = parse_jwks(&p.jwks);
        assert_eq!(bad, 1, "and the swap gets told");
        assert_eq!(
            verify(&p, &keys, Some(&token(Some("k1"), good_claims()))),
            Err(Refusal::UnknownKey)
        );
    }

    #[test]
    fn the_scheme_is_read_case_insensitively_and_nothing_else_is_accepted() {
        assert_eq!(bearer(Some("Bearer abc")), Some("abc"));
        assert_eq!(bearer(Some("bearer abc")), Some("abc"));
        assert_eq!(bearer(Some("BEARER abc")), Some("abc"));
        assert_eq!(bearer(Some("Basic abc")), None);
        assert_eq!(bearer(Some("abc")), None);
        assert_eq!(bearer(None), None);
    }
}
