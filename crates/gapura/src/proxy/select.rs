//! Pure decisions after a rule matched: which backend, which endpoint, redirect target, rewritten path.

use std::net::{IpAddr, SocketAddr};

use gapura_core::config::{Cluster, Endpoint, PathMatch, PathRewrite, Redirect, WeightedBackend};
use rand::Rng;

use crate::proxy::failure::ErrorKey;

/// Answer locally instead of proxying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Local {
    /// Gateway API: invalid or missing backend -> 500.
    NoBackend,
    /// Cluster exists but has no ready endpoint -> 503.
    NoEndpoints,
}

impl Local {
    pub fn key(self) -> ErrorKey {
        match self {
            Local::NoBackend => ErrorKey::NoBackend,
            Local::NoEndpoints => ErrorKey::NoEndpoints,
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

/// The address of a configured endpoint; `None` for one that does not parse.
pub fn endpoint_addr(e: &Endpoint) -> Option<SocketAddr> {
    let ip = e.address.parse::<IpAddr>().ok()?;
    Some(SocketAddr::new(ip, e.port))
}

/// Endpoint for this attempt, as `(index, address)`: the one at the round-robin cursor, unless
/// this request already tried it or outlier detection ejected it. Then one of those still
/// eligible, chosen by the same cursor, so the skipped endpoint's share spreads evenly instead of
/// landing on its neighbour. With more than `max_ejected_percent` of the cluster ejected,
/// ejection is ignored (healthy panic); and when only ejected endpoints are left untried, one of
/// them is used. An ejection makes an endpoint less likely; it never fails a request that would
/// otherwise have had somewhere to go.
pub fn pick_endpoint(
    cluster: &Cluster,
    cursor: usize,
    tried: &[SocketAddr],
    ejected: impl Fn(usize) -> bool,
    max_ejected_percent: u8,
) -> Result<(usize, SocketAddr), Local> {
    let n = cluster.endpoints.len();
    if n == 0 {
        return Err(Local::NoEndpoints);
    }
    let untried = |i: usize| endpoint_addr(&cluster.endpoints[i]).filter(|a| !tried.contains(a));
    let start = cursor % n;
    if let Some(addr) = untried(start).filter(|_| !ejected(start)) {
        return Ok((start, addr));
    }
    let panic = (0..n).filter(|&i| ejected(i)).count() * 100 > n * usize::from(max_ejected_percent);
    let left: Vec<(usize, SocketAddr)> =
        (0..n).filter_map(|i| untried(i).map(|a| (i, a))).collect();
    let healthy: Vec<(usize, SocketAddr)> = left
        .iter()
        .copied()
        .filter(|&(i, _)| panic || !ejected(i))
        .collect();
    let pool = if healthy.is_empty() { &left } else { &healthy };
    if pool.is_empty() {
        return Err(Local::NoEndpoints);
    }
    Ok(pool[cursor % pool.len()])
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
                // Translation rejects ReplacePrefixMatch combined with a regex path match, so a
                // regex winner has no prefix to strip: there is nothing sensible to compute here.
                PathMatch::Regex(_) => unreachable!(
                    "ReplacePrefixMatch with a RegularExpression path match is rejected at translate time"
                ),
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
            tls: None,
            resolve: None,
            outlier: None,
        };
        let a: SocketAddr = "10.0.0.1:8080".parse().unwrap();
        let b: SocketAddr = "[fd00::2]:8080".parse().unwrap();
        let none = |_: usize| false;
        assert_eq!(pick_endpoint(&c, 0, &[], none, 50), Ok((0, a)));
        assert_eq!(pick_endpoint(&c, 1, &[], none, 50), Ok((1, b)));
        assert_eq!(
            pick_endpoint(&c, usize::MAX, &[], none, 50),
            Ok((1, b)),
            "cursor wrap must not overflow"
        );
        assert_eq!(pick_endpoint(&c, 0, &[a], none, 50), Ok((1, b)));
        assert_eq!(
            pick_endpoint(&c, 0, &[a, b], none, 50),
            Err(Local::NoEndpoints)
        );
        assert_eq!(
            pick_endpoint(&Cluster::default(), 0, &[], none, 50),
            Err(Local::NoEndpoints)
        );
    }

    fn cluster(n: usize) -> Cluster {
        Cluster {
            endpoints: (0..n)
                .map(|i| Endpoint {
                    address: format!("10.0.0.{}", i + 1),
                    port: 80,
                })
                .collect(),
            ..Cluster::default()
        }
    }

    fn addr(i: usize) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, i as u8 + 1], 80))
    }

    #[test]
    fn an_ejected_endpoints_share_spreads_evenly_over_the_rest() {
        let c = cluster(4);
        let mut hits = [0; 4];
        for cursor in 0..400 {
            hits[pick_endpoint(&c, cursor, &[], |i| i == 0, 50).unwrap().0] += 1;
        }
        assert_eq!(hits[0], 0);
        let (lo, hi) = (
            hits[1..].iter().min().unwrap(),
            hits[1..].iter().max().unwrap(),
        );
        assert!(hi - lo <= 1, "{hits:?}");
    }

    #[test]
    fn half_ejected_is_honoured_and_more_than_half_panics() {
        let two = cluster(2);
        for cursor in 0..10 {
            assert_eq!(
                pick_endpoint(&two, cursor, &[], |i| i == 0, 50),
                Ok((1, addr(1)))
            );
        }
        let three = cluster(3);
        let picked: std::collections::BTreeSet<usize> = (0..30)
            .map(|cursor| pick_endpoint(&three, cursor, &[], |i| i < 2, 50).unwrap().0)
            .collect();
        assert_eq!(
            picked,
            [0, 1, 2].into(),
            "with 2 of 3 out, ejection is ignored"
        );
    }

    #[test]
    fn ejection_never_leaves_a_request_with_nowhere_to_go() {
        let one = cluster(1);
        assert_eq!(pick_endpoint(&one, 7, &[], |_| true, 50), Ok((0, addr(0))));
        let two = cluster(2);
        assert_eq!(
            pick_endpoint(&two, 0, &[addr(1)], |i| i == 0, 50),
            Ok((0, addr(0))),
            "the retry goes to the ejected endpoint rather than nowhere"
        );
        assert_eq!(
            pick_endpoint(&two, 0, &[addr(0), addr(1)], |_| true, 50),
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

    /// A store route with `strip_path`, as the control plane compiles it and the proxy applies
    /// it: the rule's rewrite taken with the path of the entry that won.
    #[test]
    fn a_store_route_that_strips_its_path_sends_the_upstream_the_rest() {
        use gapura_core::matcher::RegexMap;
        use gapura_core::store::{StoreRoute, StoreService, StoreSettings};
        use gapura_core::{compile, RequestAttrs, StoreSnapshot};

        let snap = StoreSnapshot {
            services: vec![StoreService {
                workspace: String::new(),
                name: "gin-ping-api".into(),
                protocol: gapura_core::config::Protocol::Http,
                host: "gin.internal".into(),
                port: 8080,
                connect_timeout_ms: None,
                read_timeout_ms: None,
                tls_verify: true,
                tls_ca_pem: None,
                tls_sni: None,
            }],
            routes: vec![StoreRoute {
                workspace: String::new(),
                name: "test".into(),
                service: "gin-ping-api".into(),
                hosts: Vec::new(),
                paths: vec![
                    PathMatch::Prefix("/test".into()),
                    PathMatch::Exact("/health".into()),
                ],
                methods: Vec::new(),
                headers: Vec::new(),
                strip_path: true,
                priority: 0,
            }],
            ..Default::default()
        };
        let cfg = compile(&snap, &StoreSettings::default());
        let upstream_path = |path: &str| {
            let hit = cfg
                .match_port_with(
                    80,
                    &RequestAttrs {
                        host: "api.example.com",
                        path,
                        method: "GET",
                        headers: &[],
                        query: &[],
                    },
                    &RegexMap::default(),
                )
                .unwrap_or_else(|| panic!("{path} matches no route"));
            let rewrite = hit.rule.filters.rewrite.as_ref().unwrap();
            rewrite_path(
                rewrite.path.as_ref().expect("a path rewrite"),
                path,
                &hit.entry.matcher.path,
            )
        };
        assert_eq!(upstream_path("/test/ping"), "/ping");
        assert_eq!(upstream_path("/test/a/b"), "/a/b");
        assert_eq!(upstream_path("/test"), "/");
        assert_eq!(upstream_path("/test/"), "/");
        assert_eq!(upstream_path("/health"), "/");
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
