//! Pure decisions after a rule matched: which backend, which endpoint, redirect target, rewritten path.

use std::net::{IpAddr, SocketAddr};

use gapura_core::config::{Cluster, PathMatch, PathRewrite, Redirect, WeightedBackend};
use rand::Rng;

/// Answer locally instead of proxying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Local {
    /// Gateway API: invalid or missing backend -> 500.
    NoBackend,
    /// Cluster exists but has no ready endpoint -> 503.
    NoEndpoints,
}

impl Local {
    pub fn status(self) -> u16 {
        match self {
            Local::NoBackend => 500,
            Local::NoEndpoints => 503,
        }
    }
}

/// Weighted choice. `roll(total)` must return a number in `0..total`; injectable for tests.
pub fn pick_backend(
    backends: &[WeightedBackend],
    roll: impl FnOnce(u64) -> u64,
) -> Result<&str, Local> {
    let total: u64 = backends.iter().map(|b| u64::from(b.weight)).sum();
    if total == 0 {
        return Err(Local::NoBackend);
    }
    let mut r = roll(total).min(total - 1);
    for b in backends {
        let w = u64::from(b.weight);
        if r < w {
            return b.cluster.as_deref().ok_or(Local::NoBackend);
        }
        r -= w;
    }
    Err(Local::NoBackend)
}

pub fn random_roll(total: u64) -> u64 {
    rand::rng().random_range(0..total)
}

/// Endpoint at the round-robin cursor, skipping addresses already tried by this request.
pub fn pick_endpoint(
    cluster: &Cluster,
    cursor: usize,
    tried: &[SocketAddr],
) -> Result<SocketAddr, Local> {
    let n = cluster.endpoints.len();
    if n == 0 {
        return Err(Local::NoEndpoints);
    }
    for i in 0..n {
        let e = &cluster.endpoints[(cursor % n + i) % n];
        let Ok(ip) = e.address.parse::<IpAddr>() else {
            continue;
        };
        let addr = SocketAddr::new(ip, e.port);
        if !tried.contains(&addr) {
            return Ok(addr);
        }
    }
    Err(Local::NoEndpoints)
}

/// New path for a RequestRedirect or URLRewrite path modifier. `matched` is the PathMatch that
/// won; `ReplacePrefixMatch` keeps everything after the prefix (Gateway API examples table).
pub fn rewrite_path(modifier: &PathRewrite, path_in: &str, matched: &PathMatch) -> String {
    match modifier {
        PathRewrite::ReplaceFullPath(p) => p.clone(),
        PathRewrite::ReplacePrefixMatch(replacement) => {
            let rest = match matched {
                PathMatch::Prefix(prefix) if prefix != "/" => {
                    path_in.get(prefix.len()..).unwrap_or("")
                }
                PathMatch::Prefix(_) => path_in,
                PathMatch::Exact(_) => "",
            };
            if replacement == "/" {
                return if rest.is_empty() {
                    "/".to_string()
                } else {
                    rest.to_string()
                };
            }
            match format!("{}{}", replacement.trim_end_matches('/'), rest) {
                p if p.is_empty() => "/".to_string(),
                p => p,
            }
        }
    }
}

/// Location header value for a RequestRedirect filter.
/// Port rule (Gateway API): explicit port wins; else the scheme's well-known port when a scheme
/// is set; else the port the request came in on. Well-known ports are omitted.
pub fn redirect_location(
    r: &Redirect,
    scheme_in: &str,
    host_in: &str,
    port_in: u16,
    path_in: &str,
    query: Option<&str>,
    matched: &PathMatch,
) -> String {
    let scheme = r.scheme.as_deref().unwrap_or(scheme_in);
    let host = r.hostname.as_deref().unwrap_or(host_in);
    let port = match (r.port, r.scheme.is_some()) {
        (Some(p), _) => Some(p),
        (None, true) => None,
        (None, false) => Some(port_in),
    };
    let default_port = match scheme {
        "https" => 443,
        _ => 80,
    };
    let port_part = match port {
        Some(p) if p != default_port => format!(":{p}"),
        _ => String::new(),
    };
    let path = match &r.path {
        Some(m) => rewrite_path(m, path_in, matched),
        None => path_in.to_string(),
    };
    let query_part = query.map(|q| format!("?{q}")).unwrap_or_default();
    format!("{scheme}://{host}{port_part}{path}{query_part}")
}

#[cfg(test)]
mod tests {
    use gapura_core::config::Endpoint;

    use super::*;

    fn wb(cluster: Option<&str>, weight: u32) -> WeightedBackend {
        WeightedBackend {
            cluster: cluster.map(String::from),
            weight,
        }
    }

    #[test]
    fn pick_backend_by_weight_and_500_cases() {
        let b = [wb(Some("a"), 3), wb(Some("b"), 1), wb(None, 1)];
        assert_eq!(pick_backend(&b, |_| 0), Ok("a"));
        assert_eq!(pick_backend(&b, |_| 2), Ok("a"));
        assert_eq!(pick_backend(&b, |_| 3), Ok("b"));
        assert_eq!(
            pick_backend(&b, |_| 4),
            Err(Local::NoBackend),
            "invalid backendRef gets its weighted share of 500s"
        );
        assert_eq!(pick_backend(&[], |_| 0), Err(Local::NoBackend));
        assert_eq!(
            pick_backend(&[wb(Some("a"), 0)], |_| 0),
            Err(Local::NoBackend),
            "weight 0 is never selected"
        );
        let even = [wb(Some("a"), 1), wb(Some("b"), 1)];
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..200 {
            seen.insert(pick_backend(&even, random_roll).unwrap());
        }
        assert_eq!(seen.len(), 2);
    }

    #[test]
    fn pick_endpoint_rotates_and_skips_tried() {
        let c = Cluster {
            endpoints: vec![
                Endpoint {
                    address: "10.0.0.1".into(),
                    port: 8080,
                },
                Endpoint {
                    address: "fd00::2".into(),
                    port: 8080,
                },
            ],
        };
        let a: SocketAddr = "10.0.0.1:8080".parse().unwrap();
        let b: SocketAddr = "[fd00::2]:8080".parse().unwrap();
        assert_eq!(pick_endpoint(&c, 0, &[]), Ok(a));
        assert_eq!(pick_endpoint(&c, 1, &[]), Ok(b));
        assert_eq!(
            pick_endpoint(&c, usize::MAX, &[]),
            Ok(b),
            "cursor wrap must not overflow"
        );
        assert_eq!(pick_endpoint(&c, 0, &[a]), Ok(b));
        assert_eq!(pick_endpoint(&c, 0, &[a, b]), Err(Local::NoEndpoints));
        assert_eq!(
            pick_endpoint(&Cluster::default(), 0, &[]),
            Err(Local::NoEndpoints)
        );
    }

    #[test]
    fn rewrite_path_follows_gateway_api_table() {
        let prefix = PathMatch::Prefix("/foo".into());
        let rep = |r: &str| PathRewrite::ReplacePrefixMatch(r.into());
        assert_eq!(rewrite_path(&rep("/bar"), "/foo", &prefix), "/bar");
        assert_eq!(rewrite_path(&rep("/bar"), "/foo/", &prefix), "/bar/");
        assert_eq!(rewrite_path(&rep("/bar"), "/foo/bar", &prefix), "/bar/bar");
        assert_eq!(rewrite_path(&rep("/"), "/foo", &prefix), "/");
        assert_eq!(rewrite_path(&rep("/"), "/foo/", &prefix), "/");
        assert_eq!(rewrite_path(&rep("/"), "/foo/bar", &prefix), "/bar");
        assert_eq!(
            rewrite_path(&rep("/bar"), "/x/y", &PathMatch::Prefix("/".into())),
            "/bar/x/y"
        );
        assert_eq!(
            rewrite_path(
                &PathRewrite::ReplaceFullPath("/index.html".into()),
                "/foo/bar",
                &prefix
            ),
            "/index.html"
        );
        assert_eq!(
            rewrite_path(&rep("/new"), "/exact", &PathMatch::Exact("/exact".into())),
            "/new"
        );
        assert_eq!(
            rewrite_path(&rep("//"), "/foo", &prefix),
            "/",
            "all-slash replacement never yields an empty path"
        );
    }

    #[test]
    fn redirect_location_port_and_scheme_rules() {
        let m = PathMatch::Prefix("/".into());
        let r = |scheme: Option<&str>, port: Option<u16>| Redirect {
            scheme: scheme.map(String::from),
            hostname: None,
            port,
            status: 302,
            path: None,
        };
        assert_eq!(
            redirect_location(
                &r(Some("https"), None),
                "http",
                "a.com",
                80,
                "/p",
                Some("x=1"),
                &m
            ),
            "https://a.com/p?x=1"
        );
        assert_eq!(
            redirect_location(&r(None, None), "http", "a.com", 8080, "/p", None, &m),
            "http://a.com:8080/p"
        );
        assert_eq!(
            redirect_location(&r(None, Some(80)), "http", "a.com", 8080, "/p", None, &m),
            "http://a.com/p"
        );
        assert_eq!(
            redirect_location(
                &r(Some("https"), Some(8443)),
                "http",
                "a.com",
                80,
                "/p",
                None,
                &m
            ),
            "https://a.com:8443/p"
        );
        let with_host = Redirect {
            scheme: None,
            hostname: Some("b.com".into()),
            port: None,
            status: 301,
            path: Some(PathRewrite::ReplaceFullPath("/z".into())),
        };
        assert_eq!(
            redirect_location(&with_host, "https", "a.com", 443, "/p", None, &m),
            "https://b.com/z"
        );
    }
}
