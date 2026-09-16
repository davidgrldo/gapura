//! The HTTP surface. Handlers stay thin: they resolve scope, call a reader, and serialise.

use axum::{routing::get, Router};

pub fn router() -> Router {
    Router::new().route("/healthz", get(|| async { "ok\n" }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn healthz_answers_ok() {
        let response = router()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}

use crate::rows::Row;
use std::collections::BTreeSet;

/// Drop every row outside the caller's namespaces. `None` means every namespace.
///
/// Not yet reachable outside tests: `api` is a private module and no handler calls this
/// until the next commit wires it into `/api/routes`. `allow` rather than `expect`
/// because the test build already calls it from `scope_tests`, which would make an
/// `expect` inconsistent between the plain and test compilations; remove this once
/// `routes()` calls it too.
#[allow(dead_code)]
pub fn only_visible(rows: Vec<Row>, visible: Option<&BTreeSet<String>>) -> Vec<Row> {
    match visible {
        None => rows,
        Some(allowed) => rows
            .into_iter()
            .filter(|r| allowed.contains(&r.namespace))
            .collect(),
    }
}

#[cfg(test)]
mod scope_tests {
    use super::*;
    use crate::rows::State;

    fn row(id: &str) -> Row {
        Row {
            id: id.to_string(),
            namespace: id.split('/').next().unwrap().to_string(),
            state: State::Served,
            reason: None,
            message: None,
        }
    }

    #[test]
    fn a_namespace_outside_the_grant_is_not_returned_at_all() {
        let rows = vec![row("apps/checkout"), row("shop/catalog")];
        let visible = BTreeSet::from(["apps".to_string()]);
        let got = only_visible(rows, Some(&visible));
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "apps/checkout");
    }

    #[test]
    fn granting_nothing_returns_nothing() {
        let rows = vec![row("apps/checkout")];
        assert!(only_visible(rows, Some(&BTreeSet::new())).is_empty());
    }

    #[test]
    fn a_grant_over_every_namespace_returns_every_row() {
        let rows = vec![row("apps/checkout"), row("shop/catalog")];
        assert_eq!(only_visible(rows, None).len(), 2);
    }
}
