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

use gapura_control::access::{Grant, Method, Role, Source};

#[tokio::test]
async fn access_rows_reads_accounts_grants_and_mappings_in_one_go() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let db = store.client().await.unwrap();
    let payments: uuid::Uuid = db
        .query_one(
            "insert into workspaces (name) values ('payments') returning id",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(store.bootstrap_superuser("root", "x").await.unwrap());
    let oli = store
        .upsert_oidc_user(
            "https://id.example",
            "s-oli",
            "oli",
            &["payments-dev".to_string()],
        )
        .await
        .unwrap();
    db.execute(
        "insert into group_bindings (group_name, workspace_id, role) values ('payments-dev', $1, 'editor')",
        &[&payments],
    )
    .await
    .unwrap();
    let root_id: uuid::Uuid = db
        .query_one("select id from users where username = 'root'", &[])
        .await
        .unwrap()
        .get(0);
    db.execute(
        "insert into role_bindings (user_id, workspace_id, role) values ($1, $2, 'viewer')",
        &[&root_id, &payments],
    )
    .await
    .unwrap();

    let rows = store.access_rows().await.unwrap();
    assert_eq!(
        rows.grants,
        [Grant {
            user: root_id,
            workspace: payments,
            role: Role::Viewer,
        }],
        "a direct grant reads back with its user and workspace the right way round"
    );
    assert_eq!(rows.workspaces.len(), 2, "default and payments");
    let oli_row = rows.users.iter().find(|u| u.id == oli.id).unwrap();
    assert_eq!(oli_row.method, Method::Oidc);
    assert_eq!(oli_row.name, "oli");
    assert_eq!(
        rows.effective(oli_row, payments)
            .map(|a| (a.role, a.sources)),
        Some((Role::Editor, vec![Source::Group("payments-dev".into())]))
    );
    let root = rows.users.iter().find(|u| u.name == "root").unwrap();
    assert!(root.superuser && root.method == Method::Local);
}

#[tokio::test]
async fn an_oidc_account_is_one_row_per_subject_and_follows_its_latest_sign_in() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let first = store
        .upsert_oidc_user("https://id.example", "s1", "rini", &["a".to_string()])
        .await
        .unwrap();
    // Cleared, so the next sign-in has to stamp it rather than leave the first one standing.
    store
        .client()
        .await
        .unwrap()
        .execute(
            "update users set last_sign_in_at = null where id = $1",
            &[&first.id],
        )
        .await
        .unwrap();
    let again = store
        .upsert_oidc_user(
            "https://id.example",
            "s1",
            "rini.wulandari",
            &["b".to_string()],
        )
        .await
        .unwrap();
    assert_eq!(first.id, again.id);
    let rows = store.access_rows().await.unwrap();
    assert_eq!(rows.users.len(), 1);
    assert_eq!(rows.users[0].name, "rini.wulandari");
    assert_eq!(rows.users[0].groups, ["b"]);
    assert!(rows.users[0].last_sign_in.is_some());
}

#[tokio::test]
async fn a_disabled_oidc_account_stays_disabled_and_its_refused_sign_in_is_not_recorded() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let account = store
        .upsert_oidc_user("https://id.example", "s1", "rini", &[])
        .await
        .unwrap();
    store
        .client()
        .await
        .unwrap()
        .execute(
            "update users set disabled_at = now(), last_sign_in_at = null where id = $1",
            &[&account.id],
        )
        .await
        .unwrap();
    let refused = store
        .upsert_oidc_user("https://id.example", "s1", "rini", &[])
        .await
        .unwrap();
    assert!(refused.disabled);
    let rows = store.access_rows().await.unwrap();
    assert_eq!(rows.users[0].last_sign_in, None);
}

#[tokio::test]
async fn an_oidc_account_with_no_name_is_shown_by_its_subject() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    store
        .upsert_oidc_user("https://id.example", "s-quiet", "", &[])
        .await
        .unwrap();
    let rows = store.access_rows().await.unwrap();
    assert_eq!(rows.users[0].name, "s-quiet");
}

#[tokio::test]
async fn bootstrap_creates_one_superuser_and_only_into_an_empty_table() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    // Both bootstraps are made to queue behind a lock this test holds, and released together,
    // so they really do overlap instead of depending on how fast a connection opens.
    let mut holder = store.client().await.unwrap();
    let hold = holder.transaction().await.unwrap();
    hold.batch_execute("lock table users in access exclusive mode")
        .await
        .unwrap();
    let a = tokio::spawn({
        let store = store.clone();
        async move { store.bootstrap_superuser("root", "x").await }
    });
    let b = tokio::spawn({
        let store = store.clone();
        async move { store.bootstrap_superuser("admin", "y").await }
    });
    let probe = store.client().await.unwrap();
    loop {
        let queued: i64 = probe
            .query_one(
                "select count(*) from pg_locks where relation = 'users'::regclass and not granted",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        if queued == 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    hold.rollback().await.unwrap();
    let created = [a.await.unwrap().unwrap(), b.await.unwrap().unwrap()]
        .iter()
        .filter(|created| **created)
        .count();
    assert_eq!(
        created, 1,
        "two replicas starting at once create one superuser"
    );
    assert_eq!(store.user_count().await.unwrap(), 1);
    assert!(!store.bootstrap_superuser("third", "z").await.unwrap());
}

#[tokio::test]
async fn a_local_account_is_found_ignoring_case_and_its_sign_in_is_recorded() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    store.bootstrap_superuser("Root", "the-hash").await.unwrap();
    let found = store
        .local_user("rOOt")
        .await
        .unwrap()
        .expect("found ignoring case");
    assert_eq!(found.password_hash, "the-hash");
    assert!(!found.disabled);
    assert!(store.local_user("nobody").await.unwrap().is_none());
    store.record_sign_in(found.id).await.unwrap();
    let rows = store.access_rows().await.unwrap();
    assert!(rows.users[0].last_sign_in.is_some());
}

#[tokio::test]
async fn bootstrap_stores_a_hash_and_never_replaces_the_first_superuser() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let pair = |password: &str| (Some("root".to_string()), Some(password.to_string()));
    let (u, p) = pair("correct horse battery");
    gapura_control::bootstrap::apply(&store, u, p)
        .await
        .unwrap();
    let first = store.local_user("root").await.unwrap().expect("created");
    assert_ne!(first.password_hash, "correct horse battery");
    assert!(gapura_control::password::verify(
        "correct horse battery",
        &first.password_hash
    ));
    let (u, p) = pair("another long password");
    gapura_control::bootstrap::apply(&store, u, p)
        .await
        .unwrap();
    let still = store.local_user("root").await.unwrap().expect("kept");
    assert!(
        gapura_control::password::verify("correct horse battery", &still.password_hash),
        "a second start with another password changed nothing"
    );
}

#[tokio::test]
async fn once_accounts_exist_an_invalid_or_half_pair_is_ignored_rather_than_fatal() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    store.bootstrap_superuser("root", "x").await.unwrap();
    for (username, password) in [
        (Some("root"), Some("short")),
        (Some("root"), None),
        (None, Some("correct horse battery")),
    ] {
        gapura_control::bootstrap::apply(
            &store,
            username.map(String::from),
            password.map(String::from),
        )
        .await
        .expect("ignored once an account exists");
    }
}

#[tokio::test]
async fn into_an_empty_table_an_invalid_pair_stops_the_start() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let refused = gapura_control::bootstrap::apply(
        &store,
        Some("root".to_string()),
        Some("correct horse battery\n".to_string()),
    )
    .await;
    assert!(refused.is_err(), "a password the sign-in form cannot send");
    assert_eq!(store.user_count().await.unwrap(), 0);
}
