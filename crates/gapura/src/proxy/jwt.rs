//! Verifying a JWT against a rule's policy.
//!
//! Keys are parsed once per configuration generation, not per request -- the same treatment
//! `compile_regexes` gives path patterns and `ParsedCert` gives certificates. A JWKS document is
//! a few hundred bytes of JSON and parsing one per request would put that on the hot path for no
//! benefit, since it cannot change between swaps. Reading a document and verifying a token are
//! `gapura_core::jwt`'s, which the control plane reads a document with before it stores one.

use std::collections::HashMap;

use gapura_core::config::{Config, Plugin};
use gapura_core::jwt::JwksError;
pub use gapura_core::jwt::{verify, Keys};

/// Parse every JWKS the configuration mentions. Returns the number of keys a document offered
/// that could not be parsed, so a swap can say so once rather than a request saying it forever.
pub fn compile(config: &Config) -> (HashMap<String, Keys>, usize) {
    let mut out: HashMap<String, Keys> = HashMap::new();
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

fn parse_jwks(document: &str) -> (Keys, usize) {
    match gapura_core::jwt::keys(document) {
        Ok(keys) => {
            let skipped = keys.skipped();
            (keys, skipped)
        }
        // One unparseable document, not one per key. A policy whose keys did not load refuses
        // every request, which is the safe direction: the alternative is letting traffic
        // through unverified because a configuration error made verification impossible.
        Err(JwksError::Unreadable) => (Keys::default(), 1),
        Err(JwksError::NoUsableKey { skipped }) => (Keys::default(), skipped),
    }
}

/// `Bearer <token>` from the Authorization header, case-insensitively on the scheme.
pub fn bearer(header: Option<&str>) -> Option<&str> {
    let value = header?;
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gapura_core::config::JwtPolicy;
    use gapura_core::jwt::Refusal;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde_json::json;

    /// The direction a configuration mistake must fail in. A policy whose keys did not load has
    /// no way to verify anything, and letting traffic past unverified would turn a typo into an
    /// open route.
    #[test]
    fn a_policy_whose_keys_did_not_load_refuses_everything() {
        let p = JwtPolicy {
            issuer: Some("https://id.example".into()),
            audience: None,
            jwks: "not a key set at all".into(),
        };
        let (keys, bad) = parse_jwks(&p.jwks);
        assert_eq!(bad, 1, "and the swap gets told");
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("k1".into());
        let t = encode(
            &header,
            &json!({"iss": "https://id.example", "exp": 4102444800u64}),
            &EncodingKey::from_secret(b"a-secret-long-enough-for-hs256-to-be-happy"),
        )
        .unwrap();
        assert_eq!(verify(&p, &keys, Some(&t)), Err(Refusal::UnknownKey));
    }

    /// Every key a document offered that cannot be used is counted, whether or not another
    /// key in it can be, so a swap says so either way.
    #[test]
    fn unusable_keys_are_counted_with_or_without_a_usable_one() {
        let usable = json!({"kty": "oct", "alg": "HS256", "kid": "k1", "k": "c2VjcmV0"});
        let unusable = json!({"kty": "oct", "k": "c2VjcmV0"});
        let (keys, bad) = parse_jwks(&json!({"keys": [usable, unusable]}).to_string());
        assert_eq!((keys.usable(), bad), (1, 1));
        let (keys, bad) = parse_jwks(&json!({"keys": [unusable, unusable]}).to_string());
        assert_eq!((keys.usable(), bad), (0, 2));
        let (_, bad) = parse_jwks(r#"{"keys":[]}"#);
        assert_eq!(bad, 0);
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
