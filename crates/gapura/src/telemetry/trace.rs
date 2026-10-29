//! The gateway's span for one request, and its export as OTLP/HTTP JSON.

use std::time::Duration;

use bytes::Bytes;
use rand::RngCore;
use serde_json::{json, Value};

use super::{hex, is_valid_traceparent, now_nanos, AccessLog};

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

    /// The span of the request `entry` records, ending now after `elapsed`. `service` is the
    /// cluster the request was proxied to, if it was.
    pub fn finish(&self, entry: &AccessLog<'_>, service: Option<&str>, elapsed: Duration) -> Span {
        let end_ns = now_nanos();
        let route = Some(entry.route).filter(|r| *r != "-");
        let text = |value: &str| json!({ "stringValue": value });
        let mut attributes = vec![
            ("http.request.method", text(entry.method)),
            ("url.path", text(entry.path)),
        ];
        if entry.status != 0 {
            attributes.push((
                "http.response.status_code",
                json!({ "intValue": entry.status.to_string() }),
            ));
        }
        for (key, value) in [
            ("server.address", Some(entry.host).filter(|h| !h.is_empty())),
            ("client.address", entry.client_ip),
            ("http.route", route),
            ("gapura.service", service),
            ("gapura.consumer", entry.consumer),
            ("gapura.error_key", entry.error_key),
            (
                "gapura.listener",
                Some(entry.listener).filter(|l| *l != "-"),
            ),
        ] {
            if let Some(value) = value {
                attributes.push((key, text(value)));
            }
        }
        Span {
            trace_id: self.trace_id.clone(),
            span_id: self.span_id.clone(),
            parent: self.parent.clone(),
            name: match route {
                Some(route) => format!("{} {route}", entry.method),
                None => entry.method.to_string(),
            },
            start_ns: end_ns.saturating_sub(u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)),
            end_ns,
            error: entry.status >= 500,
            attributes,
        }
    }
}

/// One finished span, as it waits in the export queue.
pub struct Span {
    trace_id: String,
    span_id: String,
    parent: Option<String>,
    name: String,
    start_ns: u64,
    end_ns: u64,
    /// A 5xx answer: OTel marks a server span an error for those, and only those.
    error: bool,
    /// Keys and their OTLP `AnyValue`s.
    attributes: Vec<(&'static str, Value)>,
}

impl Span {
    /// The OTLP JSON encoding: ids in hex, times in nanoseconds as strings, kind 2 (SERVER).
    fn to_otlp(&self) -> Value {
        let attributes: Vec<Value> = self
            .attributes
            .iter()
            .map(|(key, value)| json!({ "key": key, "value": value }))
            .collect();
        let mut span = json!({
            "traceId": self.trace_id,
            "spanId": self.span_id,
            "name": self.name,
            "kind": 2,
            "startTimeUnixNano": self.start_ns.to_string(),
            "endTimeUnixNano": self.end_ns.to_string(),
            "attributes": attributes,
        });
        if let Some(parent) = &self.parent {
            span["parentSpanId"] = json!(parent);
        }
        if self.error {
            span["status"] = json!({ "code": 2 });
        }
        span
    }
}

/// `spans` as one OTLP/HTTP JSON export request from the replica named `instance`.
pub fn encode(instance: &str, spans: &[Span]) -> Bytes {
    let text = |key: &str, value: &str| json!({ "key": key, "value": { "stringValue": value } });
    let spans: Vec<Value> = spans.iter().map(Span::to_otlp).collect();
    let request = json!({ "resourceSpans": [{
        "resource": {
            "attributes": [text("service.name", "gapura"), text("service.instance.id", instance)],
        },
        "scopeSpans": [{
            "scope": { "name": "gapura", "version": env!("CARGO_PKG_VERSION") },
            "spans": spans,
        }],
    }]});
    Bytes::from(serde_json::to_vec(&request).expect("a JSON value always serializes"))
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

    fn entry() -> AccessLog<'static> {
        AccessLog {
            ts_ms: 1,
            request_id: "r",
            trace_id: "t",
            method: "GET",
            host: "echo.test",
            path: "/api/x",
            query: None,
            status: 502,
            bytes: 0,
            duration_ms: 3,
            upstream_duration_ms: None,
            client_abort: false,
            mirrored: false,
            listener: "infra/main/http",
            route: "apps/echo",
            consumer: Some("shop/roomy"),
            upstream: None,
            client_ip: Some("10.0.0.9"),
            user_agent: None,
            error: None,
            error_key: Some("UPSTREAM_ERROR"),
        }
    }

    fn attr(span: &Value, key: &str) -> Option<Value> {
        span["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["key"] == key)
            .map(|a| a["value"].clone())
    }

    #[test]
    fn a_span_carries_the_request_and_encodes_as_otlp_json() {
        let ctx = SpanCtx::start(Some(INCOMING), 1.0);
        let span = ctx.finish(&entry(), Some("apps/echo:80"), Duration::from_millis(3));
        assert_eq!(span.end_ns - span.start_ns, 3_000_000);
        let body: Value = serde_json::from_slice(&encode("pod-a", &[span])).unwrap();
        let rs = &body["resourceSpans"][0];
        assert_eq!(
            rs["resource"]["attributes"][0],
            json!({"key": "service.name", "value": {"stringValue": "gapura"}})
        );
        assert_eq!(
            rs["resource"]["attributes"][1],
            json!({"key": "service.instance.id", "value": {"stringValue": "pod-a"}})
        );
        let s = &rs["scopeSpans"][0]["spans"][0];
        assert_eq!(s["traceId"], "0af7651916cd43dd8448eb211c80319c");
        assert_eq!(s["parentSpanId"], "b7ad6b7169203331");
        assert_eq!(s["spanId"], ctx.span_id.as_str());
        assert_eq!(s["name"], "GET apps/echo");
        assert_eq!(s["kind"], 2);
        assert_eq!(s["status"], json!({"code": 2}), "a 5xx is an error");
        assert!(s["startTimeUnixNano"].is_string() && s["endTimeUnixNano"].is_string());
        assert_eq!(
            attr(s, "http.request.method"),
            Some(json!({"stringValue": "GET"}))
        );
        assert_eq!(
            attr(s, "http.response.status_code"),
            Some(json!({"intValue": "502"}))
        );
        assert_eq!(attr(s, "url.path"), Some(json!({"stringValue": "/api/x"})));
        assert_eq!(
            attr(s, "server.address"),
            Some(json!({"stringValue": "echo.test"}))
        );
        assert_eq!(
            attr(s, "client.address"),
            Some(json!({"stringValue": "10.0.0.9"}))
        );
        assert_eq!(
            attr(s, "http.route"),
            Some(json!({"stringValue": "apps/echo"}))
        );
        assert_eq!(
            attr(s, "gapura.service"),
            Some(json!({"stringValue": "apps/echo:80"}))
        );
        assert_eq!(
            attr(s, "gapura.consumer"),
            Some(json!({"stringValue": "shop/roomy"}))
        );
        assert_eq!(
            attr(s, "gapura.error_key"),
            Some(json!({"stringValue": "UPSTREAM_ERROR"}))
        );
        assert_eq!(
            attr(s, "gapura.listener"),
            Some(json!({"stringValue": "infra/main/http"}))
        );
        assert_eq!(attr(s, "url.query"), None, "never the query");
    }

    #[test]
    fn a_span_leaves_out_what_the_request_does_not_have() {
        let e = AccessLog {
            status: 404,
            route: "-",
            listener: "-",
            consumer: None,
            client_ip: None,
            error_key: Some("NO_ROUTE"),
            ..entry()
        };
        let s = SpanCtx::start(None, 1.0)
            .finish(&e, None, Duration::ZERO)
            .to_otlp();
        assert_eq!(s["name"], "GET", "no route, so the method alone");
        assert!(s.get("parentSpanId").is_none(), "a trace that starts here");
        assert!(s.get("status").is_none(), "a 4xx is not a server error");
        let keys: Vec<&str> = s["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["key"].as_str().unwrap())
            .collect();
        for absent in [
            "http.route",
            "gapura.service",
            "gapura.consumer",
            "gapura.listener",
            "client.address",
        ] {
            assert!(!keys.contains(&absent), "{absent} in {keys:?}");
        }
    }
}
