//! What every module's database tests share: a migrated template, and a database of its own for
//! each test, cloned from it, so the tests run side by side instead of taking turns at one. The
//! rest of each module's helpers are its own.
//!
//! The template is migrated once per set of migrations and kept between runs, under a name that
//! hashes them (`gapura_it_tpl_<hash>`), so a run whose migrations have not changed migrates
//! nothing at all; a run that changes them builds a new one and drops the old. Each test's
//! database (`gapura_it_<pid>_<n>`) is dropped when the test ends, whether it passed or not.
//!
//! What a database cannot keep apart is shared by every test, and none of the store's state is
//! of that kind: its advisory locks and its `LISTEN` channel are both per database in Postgres.

use std::cell::RefCell;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use gapura_control::store::Store;
use sha2::{Digest, Sha256};

/// At most this many tests hold a database at once. Each store pools up to four connections per
/// core and the listener holds one more, and Postgres allows 100 by default: unbounded, a run on
/// a machine with many cores would exhaust it and fail tests that did nothing wrong.
static SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(8);

/// The template every test's database is cloned from, made by the first test to need it.
static TEMPLATE: OnceLock<String> = OnceLock::new();

/// Numbers this process's databases apart.
static NEXT: AtomicU32 = AtomicU32::new(0);

thread_local! {
    /// The URL of the database the test running on this thread was given: a test's body runs on
    /// its own thread, under either runtime flavour.
    static URL: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// A test's own database, dropped when this is. Hold it for as long as the store is used.
pub struct Fresh {
    name: String,
    admin: String,
    _slot: tokio::sync::SemaphorePermit<'static>,
}

impl Drop for Fresh {
    /// On a thread and a runtime of its own, because a drop cannot wait on the test's runtime.
    /// `with (force)` ends whatever connection the test's store still holds.
    fn drop(&mut self) {
        let (name, admin) = (self.name.clone(), self.admin.clone());
        let dropped = std::thread::spawn(move || {
            runtime().block_on(async {
                execute(
                    &admin,
                    &format!("drop database if exists \"{name}\" with (force)"),
                )
                .await
            })
        })
        .join();
        if !matches!(dropped, Ok(Ok(()))) {
            eprintln!("could not drop the test database {}", self.name);
        }
    }
}

/// A migrated store with nothing else in it, on a database of the test's own, and the guard that
/// drops that database when the test ends; `None`, after saying so, when no database is set.
pub async fn fresh_store() -> Option<(Arc<Store>, Fresh)> {
    let admin = match std::env::var("GAPURA_TEST_DATABASE_URL") {
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
    let slot = SLOTS
        .acquire()
        .await
        .expect("the semaphore is never closed");
    let template = TEMPLATE.get_or_init(|| {
        let admin = admin.clone();
        std::thread::spawn(move || runtime().block_on(build_template(&admin)))
            .join()
            .expect("building the template database")
    });
    let name = format!(
        "gapura_it_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    execute(
        &admin,
        &format!("create database \"{name}\" template \"{template}\""),
    )
    .await
    .expect("creating the test database");
    let url = with_database(&admin, &name);
    URL.with(|u| *u.borrow_mut() = Some(url.clone()));
    let store = Arc::new(Store::connect(&url).await.expect("connecting"));
    Some((
        store,
        Fresh {
            name,
            admin,
            _slot: slot,
        },
    ))
}

/// The URL of the database `fresh_store` gave the test running on this thread, for a test that
/// connects to it some other way than through the store.
pub fn url() -> String {
    URL.with(|u| u.borrow().clone())
        .expect("fresh_store gives this test its database first")
}

/// Makes the template, unless a run before this one already made it for these migrations, and
/// drops templates made for others. Under a lock, so two runs at once make it once.
async fn build_template(admin: &str) -> String {
    let mut digest = Sha256::new();
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/migrations");
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .expect("reading the migrations")
        .map(|e| e.expect("a migration").path())
        .collect();
    files.sort();
    for file in &files {
        digest.update(file.file_name().unwrap().as_encoded_bytes());
        // Line endings aside, so a checkout with CRLF names the template a LF one does.
        let text = std::fs::read_to_string(file).expect("reading a migration");
        digest.update(text.replace("\r\n", "\n").as_bytes());
    }
    let hash: String = digest.finalize()[..6]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let name = format!("gapura_it_tpl_{hash}");

    let (client, connection) = tokio_postgres::connect(admin, tokio_postgres::NoTls)
        .await
        .expect("connecting to the test database server");
    tokio::spawn(connection);
    client
        .execute(
            "select pg_advisory_lock(hashtext('gapura it template'))",
            &[],
        )
        .await
        .expect("taking the template lock");
    let exists = client
        .query_opt("select 1 from pg_database where datname = $1", &[&name])
        .await
        .expect("looking for the template")
        .is_some();
    if !exists {
        // Built under another name and renamed once migrated, so a run that dies half way leaves
        // nothing a later run would mistake for a template.
        let building = format!("{name}_building");
        for sql in [
            format!("drop database if exists \"{building}\" with (force)"),
            format!("create database \"{building}\""),
        ] {
            client
                .batch_execute(&sql)
                .await
                .expect("making the template");
        }
        {
            let store = Store::connect(&with_database(admin, &building))
                .await
                .expect("connecting to the template");
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
            store.migrate().await.expect("migrating the template");
        }
        // The store's connections close as their tasks see it dropped; a rename waits for none,
        // so it is tried until they have.
        let rename = format!("alter database \"{building}\" rename to \"{name}\"");
        let mut tries = 0;
        while let Err(e) = client.batch_execute(&rename).await {
            tries += 1;
            assert!(tries < 50, "renaming the template: {e}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let stale = client
            .query(
                "select datname from pg_database
                  where datname like 'gapura\\_it\\_tpl\\_%' and datname <> $1",
                &[&name],
            )
            .await
            .expect("listing old templates");
        for row in stale {
            let old: String = row.get(0);
            let _ = client
                .batch_execute(&format!("drop database if exists \"{old}\""))
                .await;
        }
    }
    client
        .execute(
            "select pg_advisory_unlock(hashtext('gapura it template'))",
            &[],
        )
        .await
        .expect("releasing the template lock");
    name
}

/// Runs `sql` on the server's own database, over a connection of its own.
async fn execute(admin: &str, sql: &str) -> Result<(), tokio_postgres::Error> {
    let (client, connection) = tokio_postgres::connect(admin, tokio_postgres::NoTls).await?;
    tokio::spawn(connection);
    client.batch_execute(sql).await
}

/// `url` naming the database `name` instead of its own: the path of a `postgres://` URL, kept
/// apart from whatever query follows it.
fn with_database(url: &str, name: &str) -> String {
    let authority = url.find("://").map_or(0, |i| i + 3);
    let (base, query) = match url[authority..].find('?') {
        Some(q) => url.split_at(authority + q),
        None => (url, ""),
    };
    let base = match base[authority..].find('/') {
        Some(slash) => &base[..authority + slash],
        None => base,
    };
    format!("{base}/{name}{query}")
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime")
}

#[test]
fn a_url_names_another_database_and_keeps_its_query() {
    assert_eq!(
        with_database("postgres://u:p@h:5433/postgres", "t"),
        "postgres://u:p@h:5433/t"
    );
    assert_eq!(
        with_database("postgres://u:p@h:5433/postgres?sslmode=require", "t"),
        "postgres://u:p@h:5433/t?sslmode=require"
    );
    assert_eq!(with_database("postgres://h", "t"), "postgres://h/t");
    assert_eq!(
        with_database("postgres://h?sslmode=disable", "t"),
        "postgres://h/t?sslmode=disable"
    );
}
