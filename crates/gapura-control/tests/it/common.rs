//! What every module's database tests share: the one store they all reset, and the one lock that
//! makes them take turns at it. The rest of each module's helpers are its own.

use std::sync::Arc;

use gapura_control::store::Store;

/// One database, so the tests take turns: each starts by dropping the schema, and two doing
/// that at once would delete each other's tables mid-run. The guard is held for the whole test
/// rather than just the reset, because the race is between one test's reset and another's
/// queries.
///
/// One lock for the whole binary, not one per module: the harness runs every module's tests on
/// parallel threads, so a module with a lock of its own would reset the schema under another
/// module's test. The crate's unit tests reset it too, from a binary of their own, which cargo
/// runs before or after this one and never beside it. Two cargo runs against one database still
/// collide, and so does a runner that gives each test a process of its own.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A migrated store with nothing else in it, and the guard that keeps it so until the test ends;
/// `None`, after saying so, when no database is set.
pub async fn fresh_store() -> Option<(Arc<Store>, tokio::sync::MutexGuard<'static, ()>)> {
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
