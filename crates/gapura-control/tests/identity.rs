//! The console's accounts and access in the store, and the API over them, against a real
//! Postgres.
//!
//! Skipped unless `GAPURA_TEST_DATABASE_URL` is set, like `config_endpoint.rs` and for the same
//! reason: the alternative mocks the database and proves the mock. CI sets it. Run it with:
//!
//! ```text
//! docker run -d --rm --name gapura-pg -e POSTGRES_PASSWORD=x -p 5433:5432 postgres:17-alpine
//! GAPURA_TEST_DATABASE_URL=postgres://postgres:x@localhost:5433/postgres cargo test -p gapura-control --test identity
//! ```

use std::sync::Arc;

use gapura_control::store::Store;

/// One database, so the tests take turns: each starts by dropping the schema, and two doing
/// that at once would delete each other's tables mid-run.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn fresh_store() -> Option<(Arc<Store>, tokio::sync::MutexGuard<'static, ()>)> {
    let url = match std::env::var("GAPURA_TEST_DATABASE_URL") {
        Ok(url) => url,
        // Optional locally, mandatory in CI, so a typo in the workflow cannot turn these into a
        // green build that exercised nothing.
        Err(_) => {
            assert!(
                std::env::var_os("CI").is_none(),
                "GAPURA_TEST_DATABASE_URL must be set in CI"
            );
            eprintln!("skipped: set GAPURA_TEST_DATABASE_URL to run this");
            return None;
        }
    };
    let guard = ONE_AT_A_TIME.lock().await;
    let store = Arc::new(Store::connect(&url).await.expect("connecting"));
    store
        .client()
        .await
        .expect("client")
        .batch_execute(
            "drop schema public cascade; create schema public;
             grant all on schema public to public;",
        )
        .await
        .expect("resetting the schema");
    store.migrate().await.expect("migrating");
    Some((store, guard))
}

#[tokio::test]
async fn an_account_is_either_local_or_oidc_and_never_both_or_neither() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let db = store.client().await.unwrap();
    for (what, sql) in [
        ("a local row without a password hash", "insert into users (username) values ('maya')"),
        (
            "an OIDC row without a subject",
            "insert into users (oidc_issuer) values ('https://id.example')",
        ),
        (
            "a row claiming both shapes",
            "insert into users (username, password_hash, oidc_issuer, oidc_subject)
             values ('maya', 'x', 'https://id.example', 's1')",
        ),
        ("a row with neither", "insert into users (superuser) values (true)"),
    ] {
        assert!(db.execute(sql, &[]).await.is_err(), "{what} was accepted");
    }
    db.execute(
        "insert into users (username, password_hash) values ('maya', 'x')",
        &[],
    )
    .await
    .expect("a local row");
    db.execute(
        "insert into users (oidc_issuer, oidc_subject) values ('https://id.example', 's1')",
        &[],
    )
    .await
    .expect("an OIDC row");
}

#[tokio::test]
async fn usernames_are_unique_ignoring_case_and_subjects_per_issuer() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let db = store.client().await.unwrap();
    db.execute(
        "insert into users (username, password_hash) values ('maya', 'x')",
        &[],
    )
    .await
    .unwrap();
    assert!(
        db.execute(
            "insert into users (username, password_hash) values ('MAYA', 'y')",
            &[]
        )
        .await
        .is_err(),
        "maya and MAYA would be two accounts that sign in as each other"
    );
    db.execute(
        "insert into users (oidc_issuer, oidc_subject) values ('https://id.example', 's1')",
        &[],
    )
    .await
    .unwrap();
    assert!(db
        .execute(
            "insert into users (oidc_issuer, oidc_subject) values ('https://id.example', 's1')",
            &[]
        )
        .await
        .is_err());
    db.execute(
        "insert into users (oidc_issuer, oidc_subject) values ('https://other.example', 's1')",
        &[],
    )
    .await
    .expect("the same subject from another issuer is another person");
}
