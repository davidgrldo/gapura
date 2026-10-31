//! Request debug timing: a `Server-Timing` header on the answer to a request that carries the
//! data plane's debug token (`--debug-token-file`), with the time the route match, each Access
//! step, the UpstreamRequest and Response phases, the upstream connect and its first byte, and the
//! whole request took. Without the token nothing is measured: `RequestCtx::timing` stays `None`
//! and every timer below is a branch on it.

use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

/// The request header that carries the token. Removed from every request while a token is
/// configured, whatever it holds: the token is the gateway's to check, never an upstream's or a
/// mirror's to see.
pub const HEADER: &str = "x-gapura-debug-token";

/// Whether `presented` is the token whose SHA-256 is `want`. Compared as digests, so the time it
/// takes says nothing of the token's length, and a timing leak would reveal a digest, not a token;
/// written constant-time anyway.
pub fn token_matches(want: &[u8; 32], presented: &[u8]) -> bool {
    let got = Sha256::digest(presented);
    want.iter()
        .zip(got.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// One timed request's `Server-Timing` entries, in the order they were taken.
#[derive(Default)]
pub struct Timing {
    entries: Vec<String>,
    /// When the request was handed to the upstream, for its time to first byte.
    pub sent: Option<Instant>,
}

impl Timing {
    /// One entry, in milliseconds as `Server-Timing` counts them. `name` repeats on a retry,
    /// which the header allows.
    pub fn push(&mut self, name: &str, took: Duration) {
        let ms = took.as_secs_f64() * 1000.0;
        self.entries.push(format!("{name};dur={ms:.3}"));
    }

    pub fn header(&self) -> String {
        self.entries.join(", ")
    }
}

/// The time now, when the request is timed: what [`stop`] measures from.
pub fn start(timing: &Option<Box<Timing>>) -> Option<Instant> {
    timing.as_ref().map(|_| Instant::now())
}

/// Record that `name` took the time since `start`, when the request is timed.
pub fn stop(timing: &mut Option<Box<Timing>>, start: Option<Instant>, name: &str) {
    if let (Some(timing), Some(start)) = (timing, start) {
        timing.push(name, start.elapsed());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_token_itself_matches() {
        let want: [u8; 32] = Sha256::digest(b"s3cret-debug").into();
        assert!(token_matches(&want, b"s3cret-debug"));
        for wrong in [&b""[..], b"s3cret", b"s3cret-debug ", b"S3CRET-DEBUG"] {
            assert!(!token_matches(&want, wrong), "{wrong:?}");
        }
    }

    #[test]
    fn entries_are_milliseconds_in_the_order_taken() {
        let mut t = Timing::default();
        t.push("route", Duration::from_micros(12));
        t.push("access.jwt", Duration::from_micros(1500));
        assert_eq!(t.header(), "route;dur=0.012, access.jwt;dur=1.500");
        // Untimed, a stop records nothing and a start reads no clock.
        let mut off: Option<Box<Timing>> = None;
        assert!(start(&off).is_none());
        stop(&mut off, Some(Instant::now()), "route");
        assert!(off.is_none());
    }
}
