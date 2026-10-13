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
