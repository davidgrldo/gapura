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
/// that at once would delete each other's tables mid-run. The guard is held for the whole test
/// rather than just the reset, because the race is between one test's reset and another's
/// queries.
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
async fn an_account_is_exactly_local_or_exactly_oidc() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let db = store.client().await.unwrap();
    // Every combination of the four identity columns, set or not. Each value is unique to its
    // combination, so no uniqueness rule can be what refuses one; exactly two shapes are accounts.
    let mut accepted = Vec::new();
    for mask in 0u8..16 {
        let [username, hash, issuer, subject] = [0, 1, 2, 3].map(|bit| mask & (1 << bit) != 0);
        let value = |set: bool| set.then(|| format!("v{mask}"));
        let result = db
            .execute(
                "insert into users (username, password_hash, oidc_issuer, oidc_subject)
                 values ($1, $2, $3, $4)",
                &[
                    &value(username),
                    &value(hash),
                    &value(issuer),
                    &value(subject),
                ],
            )
            .await;
        match result {
            Ok(_) => accepted.push((username, hash, issuer, subject)),
            Err(error) => assert_eq!(
                violated(error),
                Some("users_local_or_oidc".to_string()),
                "shape {mask:04b} was refused by something other than the shape rule"
            ),
        }
    }
    assert_eq!(
        accepted,
        [(true, true, false, false), (false, false, true, true)],
        "only (username, password) and (issuer, subject) are accounts"
    );
}

#[tokio::test]
async fn usernames_are_unique_ignoring_case_and_subjects_per_issuer() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let db = store.client().await.unwrap();
    let local = "insert into users (username, password_hash) values ($1, 'x')";
    let oidc = "insert into users (oidc_issuer, oidc_subject) values ($1, $2)";
    db.execute(local, &[&"maya"]).await.unwrap();
    let same_name = db
        .execute(local, &[&"MAYA"])
        .await
        .expect_err("maya and MAYA would be two accounts that sign in as each other");
    assert_eq!(
        violated(same_name),
        Some("users_username_lower".to_string())
    );

    db.execute(oidc, &[&"https://id.example", &"s1"])
        .await
        .unwrap();
    let same_subject = db
        .execute(oidc, &[&"https://id.example", &"s1"])
        .await
        .expect_err("one subject from one issuer is one person");
    assert_eq!(
        violated(same_subject),
        Some("users_oidc_identity".to_string())
    );
    db.execute(oidc, &[&"https://other.example", &"s1"])
        .await
        .expect("the same subject from another issuer is another person");
}
