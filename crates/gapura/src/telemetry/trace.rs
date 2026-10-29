//! The gateway's span for one request, and its export as OTLP/HTTP JSON.

use rand::RngCore;

use super::{hex, is_valid_traceparent};

/// One request's trace context while span export is on: the trace it belongs to, the span the
/// gateway opens for it, and the caller's span that one is a child of.
pub struct SpanCtx {
    trace_id: String,
    span_id: String,
    /// The caller's span, from its `traceparent`; `None` for a trace that starts here.
    parent: Option<String>,
    /// The `traceparent` flags: the caller's, or `01`/`00` as this gateway sampled the trace.
    flags: u8,
}

impl SpanCtx {
    /// Continue the caller's trace when `incoming` is a valid `traceparent`, keeping its sampling
    /// decision; otherwise start one, sampled with probability `ratio`.
    pub fn start(incoming: Option<&str>, ratio: f64) -> SpanCtx {
        let span_id = random_id::<8>();
        match incoming.filter(|tp| is_valid_traceparent(tp)) {
            Some(tp) => {
                let parts: Vec<&str> = tp.split('-').collect();
                SpanCtx {
                    trace_id: parts[1].to_ascii_lowercase(),
                    span_id,
                    parent: Some(parts[2].to_ascii_lowercase()),
                    flags: u8::from_str_radix(parts[3], 16).unwrap_or(0),
                }
            }
            None => SpanCtx {
                trace_id: random_id::<16>(),
                span_id,
                parent: None,
                flags: u8::from(rand::random::<f64>() < ratio),
            },
        }
    }

    /// Whether this request's span is exported.
    pub fn sampled(&self) -> bool {
        self.flags & 1 == 1
    }

    /// The `traceparent` the upstream is sent: the gateway's span as the parent of whatever the
    /// upstream does next, with the sampling decision passed on.
    pub fn traceparent(&self) -> String {
        format!("00-{}-{}-{:02x}", self.trace_id, self.span_id, self.flags)
    }
}

/// `N` random bytes as hex, never all zero: W3C reads an all-zero id as no id at all.
fn random_id<const N: usize>() -> String {
    let mut bytes = [0u8; N];
    while bytes == [0u8; N] {
        rand::rng().fill_bytes(&mut bytes);
    }
    hex(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INCOMING: &str = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";

    #[test]
    fn a_valid_traceparent_is_continued_with_its_own_decision() {
        let span = SpanCtx::start(Some(INCOMING), 0.0);
        assert!(
            span.sampled(),
            "the caller's sampled flag wins over the ratio"
        );
        let tp = span.traceparent();
        let parts: Vec<&str> = tp.split('-').collect();
        assert_eq!(parts[1], "0af7651916cd43dd8448eb211c80319c");
        assert_ne!(
            parts[2], "b7ad6b7169203331",
            "the upstream's parent is the gateway's span"
        );
        assert_eq!(parts[3], "01");
        assert_eq!(span.parent.as_deref(), Some("b7ad6b7169203331"));
        assert!(is_valid_traceparent(&tp), "{tp}");

        let unsampled = SpanCtx::start(
            Some("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-00"),
            1.0,
        );
        assert!(
            !unsampled.sampled(),
            "an unsampled caller stays unsampled at ratio 1"
        );
        assert!(unsampled.traceparent().ends_with("-00"));
    }

    #[test]
    fn a_trace_starting_here_is_sampled_by_the_ratio() {
        for incoming in [
            None,
            Some("garbage"),
            Some("00-00000000000000000000000000000000-b7ad6b7169203331-01"),
        ] {
            let always = SpanCtx::start(incoming, 1.0);
            assert!(always.sampled() && always.parent.is_none());
            assert!(is_valid_traceparent(&always.traceparent()));
            assert!(always.traceparent().ends_with("-01"));
            let never = SpanCtx::start(incoming, 0.0);
            assert!(!never.sampled());
            assert!(never.traceparent().ends_with("-00"));
        }
    }
}
