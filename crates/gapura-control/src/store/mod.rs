//! Postgres, which ADR 2 made the owner of the configuration.
//!
//! Nothing in the request path of a *data plane* opens a connection here. This is the control
//! plane's own store, read on behalf of data planes that ask for their configuration over the
//! endpoint in [`config_api`](super::config_api).

use std::time::Duration;

use anyhow::{Context, Result};
use deadpool_postgres::{Config as PoolConfig, Pool, Runtime};
use gapura_core::config::{JwtPolicy, KeyAuthPolicy, PathMatch, Plugin, Protocol};
use gapura_core::store::{StoreCredential, StorePlugin, StoreRoute, StoreService, StoreSnapshot};
use sha2::{Digest, Sha256};
use tokio_postgres::NoTls;

/// Applied in order, recorded in `_migrations`. ADR 2 called schema migration permanent work;
/// embedding them in the binary is what keeps the schema and the code that queries it shipped
/// as one thing rather than matched by release notes.
const MIGRATIONS: &[(&str, &str)] = &[(
    "0001_initial",
    include_str!("../../migrations/0001_initial.sql"),
)];

pub struct Store {
    pool: Pool,
}

impl Store {
    /// `url` is a libpq connection string. TLS is deliberately not configured here yet: the
    /// store is reached over a network the operator controls, and adding it half-way -- accepted
    /// but unverified -- would be worse than the absence, which is at least visible.
    pub async fn connect(url: &str) -> Result<Self> {
        let mut cfg = PoolConfig::new();
        cfg.url = Some(url.to_string());
        let pool = cfg
            .create_pool(Some(Runtime::Tokio1), NoTls)
            .context("building the Postgres pool")?;
        // Fail at startup rather than on the first data plane's call.
        let _probe = pool.get().await.context("connecting to Postgres")?;
        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .batch_execute(
                "create table if not exists _migrations (
                     name text primary key,
                     applied_at timestamptz not null default now()
                 )",
            )
            .await?;
        for (name, sql) in MIGRATIONS {
            let already: i64 = client
                .query_one("select count(*) from _migrations where name = $1", &[name])
                .await?
                .get(0);
            if already > 0 {
                continue;
            }
            // One transaction per migration: a migration that fails half way leaves nothing
            // behind, so the next start retries it rather than finding a shape nobody designed.
            let mut c = self.pool.get().await?;
            let tx = c.transaction().await?;
            tx.batch_execute(sql)
                .await
                .with_context(|| format!("applying migration {name}"))?;
            tx.execute("insert into _migrations (name) values ($1)", &[name])
                .await?;
            tx.commit().await?;
        }
        Ok(())
    }

    /// The version and the rows, read in one transaction.
    ///
    /// One transaction is the whole point: read them separately and a write landing in between
    /// yields rows from after the change stamped with the version from before it. Every data
    /// plane would then hold that version, believe itself current, and never fetch the change.
    pub async fn snapshot(&self) -> Result<(i64, StoreSnapshot)> {
        let mut client = self.pool.get().await?;
        let tx = client
            .build_transaction()
            .read_only(true)
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .start()
            .await?;

        let version: i64 = tx
            .query_one("select version from config_state", &[])
            .await?
            .get(0);

        let services = tx
            .query(
                "select name, protocol, host, port from services order by name",
                &[],
            )
            .await?
            .into_iter()
            .map(|r| {
                let protocol: String = r.get("protocol");
                StoreService {
                    name: r.get("name"),
                    protocol: if protocol == "https" {
                        Protocol::Https
                    } else {
                        Protocol::Http
                    },
                    host: r.get("host"),
                    port: r.get::<_, i32>("port") as u16,
                }
            })
            .collect();

        let routes = tx
            .query(
                "select r.name, s.name as service, r.hosts, r.methods, r.paths, r.priority
                   from routes r join services s on s.id = r.service_id
                  order by r.name",
                &[],
            )
            .await?
            .into_iter()
            .map(|r| {
                let paths: serde_json::Value = r.get("paths");
                StoreRoute {
                    name: r.get("name"),
                    service: r.get("service"),
                    hosts: r.get("hosts"),
                    methods: r.get("methods"),
                    paths: parse_paths(&paths),
                    priority: r.get("priority"),
                }
            })
            .collect();

        // Only the ones attached to a route or a service, or to neither. A policy scoped to a
        // consumer needs consumers, which this phase does not have yet, and a row that cannot be
        // honoured is better left out than half applied.
        let plugins = tx
            .query(
                "select p.name, p.config, r.name as route, s.name as service
                   from plugins p
                   left join routes r   on r.id = p.route_id
                   left join services s on s.id = p.service_id
                  where p.enabled and p.consumer_id is null
                  order by p.name",
                &[],
            )
            .await?
            .into_iter()
            .filter_map(|r| {
                let name: String = r.get("name");
                let config: serde_json::Value = r.get("config");
                Some(StorePlugin {
                    route: r.get("route"),
                    service: r.get("service"),
                    plugin: parse_plugin(&name, config)?,
                })
            })
            .collect();

        // Expired keys are left out here rather than checked at request time: the data plane
        // holds a map, not a clock over rows, so a key that has expired is one the next
        // configuration no longer contains. The bound on that is the polling interval, which is
        // the bound revocation already has.
        let credentials = tx
            .query(
                "select k.key_hash, c.username
                   from consumer_keys k
                   join consumers c on c.id = k.consumer_id
                  where k.expires_at is null or k.expires_at > now()
                  order by k.key_hash",
                &[],
            )
            .await?
            .into_iter()
            .map(|r| StoreCredential {
                key_hash: r.get("key_hash"),
                consumer: r.get("username"),
            })
            .collect();

        tx.commit().await?;
        Ok((
            version,
            StoreSnapshot {
                services,
                routes,
                plugins,
                credentials,
            },
        ))
    }

    /// Returns the data plane's id when the token is one it holds.
    ///
    /// Looked up by prefix because the stored value is a hash and a hash cannot be indexed. The
    /// hash is plain SHA-256 rather than a password KDF on purpose: a KDF exists to make
    /// guessing a low-entropy secret expensive, and these tokens are 256 bits of randomness the
    /// control plane issued. Nothing is guessing them, and the endpoint is called by every data
    /// plane every few seconds, which is the wrong place to spend a deliberately slow function.
    pub async fn authenticate(&self, token: &str) -> Result<Option<uuid::Uuid>> {
        let Some(prefix) = token.get(..PREFIX_LEN) else {
            return Ok(None);
        };
        let client = self.pool.get().await?;
        let rows = client
            .query(
                "select data_plane_id, token_hash from data_plane_tokens
                  where token_prefix = $1 and (expires_at is null or expires_at > now())",
                &[&prefix],
            )
            .await?;
        let presented = hash(token);
        for row in rows {
            let stored: String = row.get("token_hash");
            if constant_time_eq(stored.as_bytes(), presented.as_bytes()) {
                return Ok(Some(row.get("data_plane_id")));
            }
        }
        Ok(None)
    }

    /// ADR 3: liveness is the configuration call, not a second mechanism reporting the same fact.
    pub async fn record_call(&self, id: uuid::Uuid, version: i64) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "update data_planes set last_seen_at = now(), last_seen_version = $2 where id = $1",
                &[&id, &version],
            )
            .await?;
        Ok(())
    }

    /// Registers a data plane and returns its token, which is shown once and never stored.
    pub async fn issue_token(&self, name: &str) -> Result<String> {
        let raw: [u8; 32] = rand::random();
        let token = format!("gpdp_{}", hex(&raw));
        let prefix = &token[..PREFIX_LEN];

        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let id: uuid::Uuid = tx
            .query_one(
                "insert into data_planes (name) values ($1)
                 on conflict (name) do update set name = excluded.name
                 returning id",
                &[&name],
            )
            .await?
            .get(0);
        tx.execute(
            "insert into data_plane_tokens (data_plane_id, token_prefix, token_hash)
             values ($1, $2, $3)",
            &[&id, &prefix, &hash(&token)],
        )
        .await?;
        tx.commit().await?;
        Ok(token)
    }

    /// A pooled connection, for seeding and for the console's own writes later.
    pub async fn client(&self) -> Result<deadpool_postgres::Object> {
        Ok(self.pool.get().await?)
    }

    /// Issues an API key for a consumer and returns it. Shown once; only the hash is kept.
    ///
    /// Plain SHA-256, for the reason ADR 4 gives for data plane tokens and one more: the data
    /// plane has to compute this over a presented key and look it up directly, which a salted
    /// hash cannot be.
    pub async fn issue_key(&self, consumer: &str) -> Result<String> {
        let raw: [u8; 32] = rand::random();
        let key = format!("gpak_{}", hex(&raw));
        let client = self.pool.get().await?;
        let n = client
            .execute(
                "insert into consumer_keys (consumer_id, key_prefix, key_hash)
                 select id, $2, $3 from consumers where username = $1",
                &[&consumer, &&key[..PREFIX_LEN], &hash(&key)],
            )
            .await?;
        anyhow::ensure!(n == 1, "no consumer named {consumer}");
        Ok(key)
    }

    pub fn timeout() -> Duration {
        Duration::from_secs(5)
    }
}

/// Long enough that a prefix collision is a curiosity rather than a lookup that scans, short
/// enough to be safe to log and to print in the console next to a data plane's name.
const PREFIX_LEN: usize = 13;

fn hash(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Comparing two hashes rather than two secrets, so a timing leak reveals a digest and not a
/// token. Written constant-time anyway: it is four lines, and the alternative is an argument
/// about whether this particular comparison is the one that does not matter.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A policy row into the typed thing the data plane runs.
///
/// A name this binary does not know, or a configuration that does not fit the shape it names, is
/// dropped rather than guessed at. The console should refuse the write and the enum should make
/// the set of names visible; this is the backstop for both being wrong, and dropping is the safe
/// direction -- a policy that half-applies is worse than one that visibly did not.
fn parse_plugin(name: &str, config: serde_json::Value) -> Option<Plugin> {
    match name {
        "jwt" => serde_json::from_value::<JwtPolicy>(config)
            .inspect_err(
                |e| tracing::warn!(error = %e, "a jwt policy row does not fit JwtPolicy and is ignored"),
            )
            .ok()
            .map(Plugin::Jwt),
        "key_auth" => serde_json::from_value::<KeyAuthPolicy>(config)
            .inspect_err(
                |e| tracing::warn!(error = %e, "a key_auth policy row does not fit KeyAuthPolicy and is ignored"),
            )
            .ok()
            .map(Plugin::KeyAuth),
        other => {
            tracing::warn!(plugin = %other, "unknown policy name, ignored");
            None
        }
    }
}

/// `[{"type":"prefix","value":"/v1"}]`. An entry that is not one of the three known shapes is
/// dropped rather than guessed at: a route that matches nothing is visible in the console, and a
/// route that matches the wrong thing is not.
fn parse_paths(v: &serde_json::Value) -> Vec<PathMatch> {
    v.as_array()
        .map(|entries| {
            entries
                .iter()
                .filter_map(|e| {
                    let value = e.get("value")?.as_str()?.to_string();
                    match e.get("type")?.as_str()? {
                        "exact" => Some(PathMatch::Exact(value)),
                        "prefix" => Some(PathMatch::Prefix(value)),
                        "regex" => Some(PathMatch::Regex(value)),
                        _ => None,
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}
