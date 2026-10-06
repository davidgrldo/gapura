//! The store's TLS against a real Postgres that has it on.
//!
//! Skipped unless `GAPURA_TEST_TLS_DATABASE_URL` (a `localhost` URL with no `sslmode`) and
//! `GAPURA_TEST_DATABASE_CA` (the CA that signed the server's certificate, which must name
//! `localhost` and nothing else) are set. A server for it:
//!
//! ```text
//! openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=test-ca -keyout ca.key -out ca.crt
//! openssl req -newkey rsa:2048 -nodes -subj /CN=localhost -keyout server.key -out server.csr
//! printf 'subjectAltName=DNS:localhost\n' > ext
//! openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -extfile ext -out server.crt
//! docker run -d --rm --name pgtls -e POSTGRES_PASSWORD=x -p 5434:5432 \
//!   -v $PWD/server.crt:/tls/server.crt:ro -v $PWD/server.key:/tls/server.key.src:ro \
//!   postgres:17-alpine sh -c 'cp /tls/server.key.src /tmp/k && chown postgres /tmp/k && chmod 600 /tmp/k \
//!   && exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tls/server.crt -c ssl_key_file=/tmp/k'
//! GAPURA_TEST_TLS_DATABASE_URL=postgres://postgres:x@localhost:5434/postgres \
//!   GAPURA_TEST_DATABASE_CA=$PWD/ca.crt cargo test -p gapura-control --test store_tls
//! ```

use gapura_control::store::Store;

fn server() -> Option<(String, Vec<u8>)> {
    let url = std::env::var("GAPURA_TEST_TLS_DATABASE_URL").ok()?;
    let ca = std::fs::read(std::env::var("GAPURA_TEST_DATABASE_CA").ok()?).expect("the CA file");
    Some((url, ca))
}

#[tokio::test]
async fn a_ca_file_without_sslmode_require_is_refused_before_connecting() {
    // No server needed: the refusal comes before any connection is attempted.
    let ca = rcgen::generate_simple_self_signed(vec!["db.internal".into()])
        .unwrap()
        .cert
        .pem();
    let err = Store::connect_with("postgres://u:p@127.0.0.1:1/db", Some(ca.as_bytes()))
        .await
        .err()
        .expect("refused");
    assert!(err.to_string().contains("sslmode=require"), "{err:#}");
}

#[tokio::test]
async fn sslmode_require_connects_encrypted_with_the_right_ca() {
    let Some((url, ca)) = server() else {
        eprintln!("skipped: set GAPURA_TEST_TLS_DATABASE_URL and GAPURA_TEST_DATABASE_CA");
        return;
    };
    let store = Store::connect_with(&format!("{url}?sslmode=require"), Some(&ca))
        .await
        .expect("a verified connection");
    let encrypted: bool = store
        .client()
        .await
        .unwrap()
        .query_one(
            "select ssl from pg_stat_ssl where pid = pg_backend_pid()",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(encrypted);
}

#[tokio::test]
async fn sslmode_require_refuses_a_server_it_cannot_verify() {
    let Some((url, ca)) = server() else {
        return;
    };
    // Only the public roots: the test CA is not among them.
    assert!(Store::connect_with(&format!("{url}?sslmode=require"), None)
        .await
        .is_err());
    // The right CA, the wrong name: the certificate names localhost, not 127.0.0.1.
    let by_address = url.replace("localhost", "127.0.0.1");
    assert!(
        Store::connect_with(&format!("{by_address}?sslmode=require"), Some(&ca))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn without_sslmode_require_the_connection_is_plain_text_as_before() {
    let Some((url, _)) = server() else {
        return;
    };
    let store = Store::connect(&url).await.expect("a plain-text connection");
    let encrypted: bool = store
        .client()
        .await
        .unwrap()
        .query_one(
            "select ssl from pg_stat_ssl where pid = pg_backend_pid()",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!encrypted, "prefer must not quietly become TLS");
}
