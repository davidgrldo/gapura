//! The export sinks a replica is started with (`--http-log-url`, `--otlp-traces-url`), and the
//! background service that delivers what the request path queues for them.
//!
//! Per replica, set by flags, never by a store policy: a Kubernetes-mode or `--config-dir`
//! gateway exports exactly as a `--control-plane` one does, and a sink's token never travels in a
//! configuration or lands in a data plane's disk cache.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE};

use super::export::{self, Queue, CAPACITY, MAX_BYTES};
use super::trace::{self, Span};

/// The `sink` label of each sink's metric and log lines.
const HTTP_LOG: &str = "http_log";
const OTLP_TRACES: &str = "otlp_traces";

/// How long one POST may take before it counts as failed and is retried.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// The request path's side of the sinks: where `logging` puts a request's record. Empty unless a
/// sink was configured, which leaves the request path exactly as it was without one.
#[derive(Clone, Default)]
pub struct Sinks {
    /// Access-log lines, as written to stdout.
    pub http_log: Option<Arc<Queue<String>>>,
    pub traces: Option<Traces>,
}

#[derive(Clone)]
pub struct Traces {
    pub queue: Arc<Queue<Span>>,
    /// The share of traces starting at this gateway that are sampled.
    pub ratio: f64,
}

/// Where one sink POSTs, and the headers it sends with each POST.
struct Target {
    url: String,
    headers: HeaderMap,
}

impl Target {
    fn new(url: &str, headers_file: Option<&Path>) -> Result<Target, String> {
        let mut headers = match headers_file {
            None => HeaderMap::new(),
            Some(path) => {
                let text = std::fs::read_to_string(path)
                    .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
                parse_headers(&text).map_err(|e| format!("{}: {e}", path.display()))?
            }
        };
        // Every body is JSON: a Content-Type line in the file would otherwise go beside this one.
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        Ok(Target {
            url: url.to_string(),
            headers,
        })
    }

    /// One POST of `body`; any 2xx is delivered, anything else, a redirect included, is retried.
    /// A send error keeps its cause (refused, timed out, untrusted certificate) and drops its URL,
    /// which may carry `user:token@`.
    async fn post(&self, client: &reqwest::Client, body: Bytes) -> Result<(), String> {
        let response = client
            .post(&self.url)
            .headers(self.headers.clone())
            .body(body)
            .send()
            .await
            .map_err(|e| crate::source::jwks::chain(&e.without_url()))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("answered {}", response.status()))
        }
    }
}

/// `Name: value` lines; blank lines and `#` comments are skipped. An error names the line and
/// never its value: these files hold tokens.
fn parse_headers(text: &str) -> Result<HeaderMap, String> {
    let mut headers = HeaderMap::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let bad = |what: &str| format!("line {}: {what}", i + 1);
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| bad("expected `Name: value`"))?;
        let name =
            HeaderName::from_bytes(name.trim().as_bytes()).map_err(|_| bad("not a header name"))?;
        let mut value =
            HeaderValue::from_str(value.trim()).map_err(|_| bad("not a header value"))?;
        value.set_sensitive(true);
        headers.append(name, value);
    }
    Ok(headers)
}

/// Access-log lines as one JSON array, each line's bytes as they were written to stdout.
fn json_array(lines: &[String]) -> Bytes {
    let mut body = Vec::with_capacity(2 + lines.iter().map(|l| l.len() + 1).sum::<usize>());
    body.push(b'[');
    for (i, line) in lines.iter().enumerate() {
        if i > 0 {
            body.push(b',');
        }
        body.extend_from_slice(line.as_bytes());
    }
    body.push(b']');
    Bytes::from(body)
}

/// The background service that drains each configured sink's queue, one worker per sink.
pub struct Exporter {
    client: reqwest::Client,
    /// This replica's name, the OTLP resource's `service.instance.id`.
    instance: String,
    http_log: Option<(Arc<Queue<String>>, Target)>,
    traces: Option<(Arc<Queue<Span>>, Target)>,
}

/// The client every sink POSTs with: certificates verified against the public roots, and no
/// redirects. A redirect would turn a 301/302 POST into a bodiless GET whose 2xx counts as
/// delivered, and would carry the headers file's tokens wherever it points: it is a failure.
fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(SEND_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("cannot build the export client: {e}"))
}

/// The sinks `args` configures and the service that delivers to them, which is `None` when there
/// is no sink. An unreadable or malformed headers file is an error, to stop the start.
pub fn build(args: &crate::cli::Args) -> Result<(Sinks, Option<Exporter>), String> {
    let target = |url: &Option<String>, file: &Option<std::path::PathBuf>| {
        url.as_deref()
            .map(|url| Target::new(url, file.as_deref()))
            .transpose()
    };
    let http_log = target(&args.http_log_url, &args.http_log_headers_file)?;
    let traces = target(&args.otlp_traces_url, &args.otlp_headers_file)?;
    if http_log.is_none() && traces.is_none() {
        return Ok((Sinks::default(), None));
    }
    let client = client()?;
    let http_log = http_log.map(|t| (Arc::new(Queue::new(HTTP_LOG, CAPACITY, MAX_BYTES)), t));
    let traces = traces.map(|t| (Arc::new(Queue::new(OTLP_TRACES, CAPACITY, MAX_BYTES)), t));
    let sinks = Sinks {
        http_log: http_log.as_ref().map(|(queue, _)| Arc::clone(queue)),
        traces: traces.as_ref().map(|(queue, _)| Traces {
            queue: Arc::clone(queue),
            ratio: args.otlp_sample_ratio.unwrap_or(1.0),
        }),
    };
    let exporter = Exporter {
        client,
        instance: args.identity(),
        http_log,
        traces,
    };
    Ok((sinks, Some(exporter)))
}

#[async_trait]
impl BackgroundService for Exporter {
    async fn start(&self, shutdown: ShutdownWatch) {
        let client = &self.client;
        let http_log = async {
            if let Some((queue, target)) = &self.http_log {
                export::run(queue, shutdown.clone(), json_array, |body| {
                    target.post(client, body)
                })
                .await;
            }
        };
        let traces = async {
            if let Some((queue, target)) = &self.traces {
                let encode = |spans: &[Span]| trace::encode(&self.instance, spans);
                export::run(queue, shutdown.clone(), encode, |body| {
                    target.post(client, body)
                })
                .await;
            }
        };
        tokio::join!(http_log, traces);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn a_headers_file_is_name_value_lines_and_its_errors_never_show_a_value() {
        let h = parse_headers(
            "# for the collector\n\nAuthorization: Bearer s3cret\nX-Scope-OrgID:  tenant-a \n",
        )
        .unwrap();
        assert_eq!(h["authorization"], "Bearer s3cret");
        assert!(h["authorization"].is_sensitive());
        assert_eq!(h["x-scope-orgid"], "tenant-a");
        assert_eq!(
            parse_headers("Authorization Bearer s3cret").unwrap_err(),
            "line 1: expected `Name: value`"
        );
        assert_eq!(
            parse_headers("ok: 1\nbad name: s3cret\n").unwrap_err(),
            "line 2: not a header name"
        );
        assert_eq!(
            parse_headers("x: s3cret\u{7f}").unwrap_err(),
            "line 1: not a header value"
        );
    }

    #[test]
    fn a_batch_of_lines_is_one_json_array_of_them() {
        let lines = [r#"{"a":1}"#.to_string(), r#"{"b":2}"#.to_string()];
        assert_eq!(&json_array(&lines)[..], br#"[{"a":1},{"b":2}]"#);
        assert_eq!(&json_array(&[])[..], b"[]");
    }

    #[test]
    fn no_flag_means_no_sink_and_no_service() {
        let args = crate::cli::Args::parse_from(["gapura", "--config-dir", "/tmp/x"]);
        let (sinks, exporter) = build(&args).unwrap();
        assert!(sinks.http_log.is_none() && sinks.traces.is_none() && exporter.is_none());
    }

    #[test]
    fn a_sink_gets_its_queue_its_ratio_and_its_headers_file() {
        let dir = tempfile::tempdir().unwrap();
        let headers = dir.path().join("headers");
        std::fs::write(
            &headers,
            "Authorization: Bearer t\nContent-Type: text/plain\n",
        )
        .unwrap();
        let args = crate::cli::Args::parse_from([
            "gapura",
            "--config-dir",
            "/tmp/x",
            "--otlp-traces-url",
            "http://otel:4318/v1/traces",
            "--otlp-sample-ratio",
            "0.5",
            "--otlp-headers-file",
            headers.to_str().unwrap(),
        ]);
        let (sinks, exporter) = build(&args).unwrap();
        assert!(sinks.http_log.is_none());
        assert_eq!(sinks.traces.as_ref().map(|t| t.ratio), Some(0.5));
        let exporter = exporter.expect("a sink, so a service");
        let (_, target) = exporter.traces.as_ref().unwrap();
        assert_eq!(target.headers["authorization"], "Bearer t");
        assert_eq!(
            target
                .headers
                .get_all(CONTENT_TYPE)
                .iter()
                .map(|v| v.to_str().unwrap())
                .collect::<Vec<_>>(),
            ["application/json"]
        );

        let args = crate::cli::Args::parse_from([
            "gapura",
            "--config-dir",
            "/tmp/x",
            "--http-log-url",
            "http://logs/in",
            "--http-log-headers-file",
            "/nonexistent/headers",
        ]);
        let Err(err) = build(&args) else {
            panic!("an unreadable headers file must stop the start")
        };
        assert!(err.starts_with("cannot read /nonexistent/headers"), "{err}");
    }

    #[tokio::test]
    async fn a_redirect_is_a_failure_not_a_delivery() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await;
            let _ = sock
                .write_all(b"HTTP/1.1 307 Temporary Redirect\r\nlocation: http://127.0.0.1:9/elsewhere\r\ncontent-length: 0\r\n\r\n")
                .await;
        });
        let target = Target::new(&format!("http://{addr}/logs"), None).unwrap();
        let err = target
            .post(&client().unwrap(), Bytes::from_static(b"[]"))
            .await
            .unwrap_err();
        assert!(err.contains("307"), "{err}");
    }

    #[tokio::test]
    async fn a_send_error_says_why_and_not_where() {
        // Nothing listens on a port just released.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let target = Target::new(
            &format!("http://user:s3cret@127.0.0.1:{port}/logs?key=t0ken"),
            None,
        )
        .unwrap();
        let err = target
            .post(&client().unwrap(), Bytes::from_static(b"[]"))
            .await
            .unwrap_err();
        assert!(!err.contains("s3cret") && !err.contains("t0ken"), "{err}");
        assert!(err.contains(": "), "a cause after the message: {err}");
    }
}
