//! Granting and removing roles and group mappings, the audit entries they leave, and the
//! cross-site rules in front of every write.
//!
//! The tests that need a store skip unless `GAPURA_TEST_DATABASE_URL` is set, like
//! `identity.rs`, and for the same reason: the alternative mocks the database and proves the
//! mock. CI sets it. The cross-site tests need no store and always run. Run them with:
//!
//! ```text
//! docker run -d --rm --name gapura-pg -e POSTGRES_PASSWORD=x -p 5433:5432 postgres:17-alpine
//! GAPURA_TEST_DATABASE_URL=postgres://postgres:x@localhost:5433/postgres cargo test -p gapura-control --test grants
//! ```
//!
//! The helpers are copies of `identity.rs`'s rather than a shared `tests/common` module, so that
//! each file reads on its own; the accounts each file seeds are its own.

use std::sync::Arc;

use gapura_control::store::Store;

/// One database, so the tests take turns: each starts by dropping the schema, and two doing
/// that at once would delete each other's tables mid-run. The guard is held for the whole test
/// rather than just the reset, because the race is between one test's reset and another's
/// queries. Cargo runs test binaries one after another, so the other test files that reset
/// this schema never use the database at the same time as this one. Two cargo runs against one
/// database still collide, and so does a runner that gives each test a process of its own.
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

/// The constraint a failed statement broke, by name, so a test can tell the rule it meant to
/// exercise from any other way the insert might have failed.
fn violated(error: tokio_postgres::Error) -> Option<String> {
    error
        .as_db_error()
        .and_then(|d| d.constraint())
        .map(str::to_string)
}

#[tokio::test]
async fn an_audit_entry_records_how_its_actor_signed_in_or_nothing() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let db = store.client().await.unwrap();
    let insert = "insert into audit_log (actor_name, actor_method, action, object_kind)
                  values ('pat', $1, 'update', 'user')";
    // Local, single sign-on, and an entry no person made.
    for method in [Some("local"), Some("oidc"), None] {
        db.execute(insert, &[&method])
            .await
            .unwrap_or_else(|e| panic!("{method:?} was refused: {e}"));
    }
    let refused = db
        .execute(insert, &[&Some("saml")])
        .await
        .expect_err("a third way in is not one this console has");
    assert_eq!(
        violated(refused),
        Some("audit_log_actor_method".to_string())
    );
}
