//! The store compiler's whole output for a snapshot with consumers' own request limits, pinned
//! with insta, and its key facts asserted explicitly beside it, as `golden.rs` does for the
//! Gateway API path, so a wrong snapshot cannot be accepted by accident.

use gapura_core::config::{LimitBy, PathMatch, Protocol, RateLimit};
use gapura_core::store::{
    compile, StoreRateLimit, StoreRoute, StoreService, StoreSettings, StoreSnapshot,
};

fn service(name: &str) -> StoreService {
    StoreService {
        workspace: "shop".into(),
        name: name.into(),
        protocol: Protocol::Http,
        host: format!("{name}.internal"),
        port: 8080,
        connect_timeout_ms: None,
        read_timeout_ms: None,
        tls_verify: true,
        tls_ca_pem: None,
        tls_sni: None,
    }
}

fn route(name: &str, service: &str) -> StoreRoute {
    StoreRoute {
        workspace: "shop".into(),
        name: name.into(),
        service: service.into(),
        hosts: vec![format!("{name}.example")],
        paths: vec![PathMatch::Prefix("/".into())],
        methods: vec![],
        headers: vec![],
        strip_path: false,
        priority: 0,
    }
}

fn limit(
    route: Option<&str>,
    service: Option<&str>,
    consumer: Option<&str>,
    per_minute: u32,
    by: LimitBy,
) -> StoreRateLimit {
    StoreRateLimit {
        workspace: "shop".into(),
        route: route.map(str::to_string),
        service: service.map(str::to_string),
        consumer: consumer.map(str::to_string),
        limit: RateLimit {
            limit: per_minute,
            window_ms: 60_000,
            by,
        },
    }
}

#[test]
fn store_consumer_rate_limits() {
    let snap = StoreSnapshot {
        services: vec![service("orders"), service("billing")],
        routes: vec![
            route("api", "orders"),
            route("web", "orders"),
            route("pay", "billing"),
        ],
        rate_limits: vec![
            limit(None, None, None, 100, LimitBy::Ip),
            limit(
                Some("api"),
                None,
                None,
                20,
                LimitBy::Header("x-tenant".into()),
            ),
            limit(Some("api"), None, Some("mobile"), 9, LimitBy::Consumer),
            limit(None, Some("orders"), Some("mobile"), 8, LimitBy::Consumer),
            limit(None, None, Some("mobile"), 7, LimitBy::Ip),
            limit(
                None,
                Some("billing"),
                Some("partner"),
                500,
                LimitBy::Consumer,
            ),
        ],
        ..Default::default()
    };
    let cfg = compile(&snap, &StoreSettings::default());

    let mobile = &cfg.consumer_rate_limits["shop/mobile"];
    assert_eq!(mobile.routes["shop/api"].limit, 9, "route+consumer");
    assert_eq!(mobile.routes["shop/web"].limit, 8, "service+consumer");
    assert!(
        !mobile.routes.contains_key("shop/pay"),
        "billing is not orders"
    );
    assert_eq!(mobile.any.as_ref().map(|l| l.limit), Some(7), "consumer");
    let partner = &cfg.consumer_rate_limits["shop/partner"];
    assert_eq!(partner.routes.keys().collect::<Vec<_>>(), ["shop/pay"]);
    assert_eq!(partner.any, None);
    let rule = |id: &str| {
        cfg.listeners[0]
            .rules
            .iter()
            .find(|r| r.route == id)
            .unwrap_or_else(|| panic!("{id}"))
    };
    let api = rule("shop/api").rate_limit.clone().expect("route limit");
    assert_eq!(
        (api.limit, api.by),
        (20, LimitBy::Header("x-tenant".into()))
    );
    assert_eq!(
        rule("shop/pay").rate_limit.as_ref().map(|l| l.limit),
        Some(100)
    );

    insta::assert_yaml_snapshot!("store-consumer-rate-limits", cfg);
}
