//! Postgres, the owner of the configuration.
//!
//! Nothing in the request path of a *data plane* opens a connection here. This is the control
//! plane's own store, read on behalf of data planes that ask for their configuration over the
//! endpoint in [`config_api`](super::config_api).

use std::time::Duration;

use anyhow::{Context, Result};
use deadpool_postgres::{Manager, ManagerConfig, Pool};
use gapura_core::config::{JwtPolicy, KeyAuthPolicy, PathMatch, Plugin, Protocol};
use gapura_core::store::{StoreCredential, StorePlugin, StoreRoute, StoreService, StoreSnapshot};
use sha2::{Digest, Sha256};
use tokio_postgres::config::SslMode;

mod grants;
mod identity;
mod tls;
pub(crate) use grants::sqlstate;
pub use grants::WriteError;
pub use identity::{LocalAccount, OidcAccount};

/// Applied in order, recorded in `_migrations`. Schema migration is permanent work;
/// embedding them in the binary is what keeps the schema and the code that queries it shipped
/// as one thing rather than matched by release notes.
const MIGRATIONS: &[(&str, &str)] = &[
    (
        "0001_initial",
        include_str!("../../migrations/0001_initial.sql"),
    ),
    (
        "0002_identity",
        include_str!("../../migrations/0002_identity.sql"),
    ),
    (
        "0003_audit_method",
        include_str!("../../migrations/0003_audit_method.sql"),
    ),
];

/// The advisory lock key `migrate` holds: "gapura" in ASCII, then 1. Any constant works as long as
/// nothing else sharing the database takes the same one.
const MIGRATION_LOCK: i64 = 0x6761_7075_7261_0001;

pub struct Store {
    pool: Pool,
}

impl Store {
    /// `url` is a libpq connection string, in plain text unless it says `sslmode=require`.
    pub async fn connect(url: &str) -> Result<Self> {
        Self::connect_with(url, None).await
    }

    /// `sslmode=require` in `url` turns TLS on, and verified: the certificate has to chain to
    /// Mozilla's roots or to `extra_ca`, and name the host. That is stricter than libpq's
    /// `require`, which checks neither and so stops only a passive observer, and the store holds
    /// every credential hash and every private key the gateway serves. Anything else, including
    /// libpq's default `prefer`, connects in plain text as before: a TLS attempt that falls back
    /// to plain text when the handshake fails protects nothing an attacker on the path cannot
    /// strip.
    pub async fn connect_with(url: &str, extra_ca: Option<&[u8]>) -> Result<Self> {
        let mut pg: tokio_postgres::Config = url.parse().context("parsing DATABASE_URL")?;
        if pg.get_ssl_mode() == SslMode::Require {
            tracing::info!("the store connection uses TLS, verified");
        } else {
            anyhow::ensure!(
                extra_ca.is_none(),
                "a database CA file is set, but DATABASE_URL has no sslmode=require, so it \
                 would never be used"
            );
            pg.ssl_mode(SslMode::Disable);
            tracing::warn!(
                "the store connection is not encrypted (fine for a Unix socket or a local \
                 proxy); add sslmode=require to DATABASE_URL to encrypt and verify it"
            );
        }
        let manager = Manager::from_config(
            pg,
            tls::MakeRustls::new(extra_ca)?,
            ManagerConfig::default(),
        );
        let pool = Pool::builder(manager)
            .build()
            .context("building the Postgres pool")?;
        // Fail at startup rather than on the first data plane's call.
        let _probe = pool.get().await.context("connecting to Postgres")?;
        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> Result<()> {
        let mut client = self.pool.get().await?;
        // Two replicas starting together would both find a migration unapplied and both apply
        // it; the loser fails its start on a duplicate. A session lock serialises them: the
        // second waits, then finds everything recorded. It is released below, or by Postgres
        // when the connection drops if this process dies half way.
        client
            .execute("select pg_advisory_lock($1)", &[&MIGRATION_LOCK])
            .await
            .context("taking the migration lock")?;
        let result = self.apply_migrations(&mut client).await;
        if let Err(e) = client
            .execute("select pg_advisory_unlock($1)", &[&MIGRATION_LOCK])
            .await
        {
            tracing::warn!(error = %e, "releasing the migration lock");
        }
        result
    }

    async fn apply_migrations(&self, client: &mut deadpool_postgres::Object) -> Result<()> {
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
            // On the lock's own connection, so nothing here runs outside it.
            let tx = client.transaction().await?;
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
                "select w.name as workspace, s.name, s.protocol, s.host, s.port,
                        s.connect_timeout_ms, s.read_timeout_ms
                   from services s join workspaces w on w.id = s.workspace_id
                  order by w.name, s.name",
                &[],
            )
            .await?
            .into_iter()
            .map(|r| {
                let protocol: String = r.get("protocol");
                StoreService {
                    workspace: r.get("workspace"),
                    name: r.get("name"),
                    protocol: if protocol == "https" {
                        Protocol::Https
                    } else {
                        Protocol::Http
                    },
                    host: r.get("host"),
                    port: r.get::<_, i32>("port") as u16,
                    connect_timeout_ms: r
                        .get::<_, Option<i32>>("connect_timeout_ms")
                        .map(|ms| ms as u32),
                    read_timeout_ms: r
                        .get::<_, Option<i32>>("read_timeout_ms")
                        .map(|ms| ms as u32),
                }
            })
            .collect();

        let routes = tx
            .query(
                "select w.name as workspace, r.name, s.name as service, r.hosts, r.methods,
                        r.paths, r.priority
                   from routes r
                   join services s   on s.id = r.service_id
                   join workspaces w on w.id = r.workspace_id
                  order by w.name, r.name",
                &[],
            )
            .await?
            .into_iter()
            .map(|r| {
                let name: String = r.get("name");
                let paths: serde_json::Value = r.get("paths");
                let paths = parse_paths(&paths)
                    .with_context(|| format!("route {name:?} has paths this binary cannot read"))?;
                Ok(StoreRoute {
                    workspace: r.get("workspace"),
                    name,
                    service: r.get("service"),
                    hosts: r.get("hosts"),
                    methods: r.get("methods"),
                    paths,
                    priority: r.get("priority"),
                })
            })
            .collect::<Result<Vec<_>>>()?;

        // Only the ones attached to a route or a service, or to neither. A policy scoped to a
        // consumer needs consumers, which this phase does not have yet. A row that is selected and
        // cannot be read fails the whole snapshot: see `parse_plugin` for why that, and not
        // leaving the row out, is the safe direction.
        let plugins = tx
            .query(
                "select w.name as workspace, p.name, p.config, r.name as route, s.name as service,
                        coalesce(r.workspace_id <> p.workspace_id, false)
                          or coalesce(s.workspace_id <> p.workspace_id, false) as foreign_target
                   from plugins p
                   join workspaces w    on w.id = p.workspace_id
                   left join routes r   on r.id = p.route_id
                   left join services s on s.id = p.service_id
                  where p.enabled and p.consumer_id is null
                  order by w.name, p.name, p.id",
                &[],
            )
            .await?
            .into_iter()
            .map(|r| {
                let name: String = r.get("name");
                let config: serde_json::Value = r.get("config");
                let workspace: String = r.get("workspace");
                let route: Option<String> = r.get("route");
                let service: Option<String> = r.get("service");
                // The foreign keys allow a policy to name another workspace's route or service.
                // Compiled, it would attach to a same-named route in its own workspace instead --
                // the wrong target, silently -- so it fails the snapshot like any unreadable row.
                if r.get::<_, bool>("foreign_target") {
                    anyhow::bail!(
                        "policy {name:?} in workspace {workspace:?} names a route or service of \
                         another workspace"
                    );
                }
                let plugin = parse_plugin(&name, config).with_context(|| {
                    format!("policy {name:?} on route {route:?} service {service:?} cannot be read")
                })?;
                Ok(StorePlugin {
                    workspace,
                    route,
                    service,
                    plugin,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        // Expired keys are left out here rather than checked at request time: the data plane
        // holds a map, not a clock over rows, so a key that has expired is one the next
        // configuration no longer contains. The bound on that is the polling interval, which is
        // the bound revocation already has.
        let credentials = tx
            .query(
                "select k.key_hash, c.username, w.name as workspace
                   from consumer_keys k
                   join consumers c on c.id = k.consumer_id
                   join workspaces w on w.id = c.workspace_id
                  where k.expires_at is null or k.expires_at > now()
                  order by k.key_hash",
                &[],
            )
            .await?
            .into_iter()
            .map(|r| StoreCredential {
                key_hash: r.get("key_hash"),
                consumer: r.get("username"),
                workspace: r.get("workspace"),
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

    /// Liveness is the configuration call, not a second mechanism reporting the same fact.
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
    /// Plain SHA-256, for the reason data plane tokens use it and one more: the data
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
/// an error, never a row left out. Leaving out a policy is not the cautious choice it looks like:
/// the route it guarded is still compiled, so a JWT or key-auth row that fails to parse becomes a
/// route that admits everyone. An error fails the snapshot instead, `/v1/config` answers 503, and
/// every data plane keeps serving the last configuration it verified -- a bad row costs new
/// configuration, never protection. The same holds for a newer console writing a shape an older
/// replica does not know during a rolling upgrade.
fn parse_plugin(name: &str, config: serde_json::Value) -> Result<Plugin> {
    match name {
        "jwt" => serde_json::from_value::<JwtPolicy>(config)
            .map(Plugin::Jwt)
            .context("the configuration does not fit a jwt policy"),
        "key_auth" => serde_json::from_value::<KeyAuthPolicy>(config)
            .map(Plugin::KeyAuth)
            .context("the configuration does not fit a key_auth policy"),
        other => anyhow::bail!("unknown policy name {other:?}"),
    }
}

/// `[{"type":"prefix","value":"/v1"}]`. An empty list is valid and means every path.
///
/// An entry that is not one of the three known shapes is an error, never an entry left out.
/// Leaving one out is not harmless: drop every entry of a route and the empty list that remains
/// means every path, so `[{"type":"PathPrefix","value":"/admin"}]` -- the Gateway API spelling,
/// and the obvious mistake to make -- would turn a route for `/admin` into a catch-all.
fn parse_paths(v: &serde_json::Value) -> Result<Vec<PathMatch>> {
    let entries = v
        .as_array()
        .with_context(|| format!("paths is not a list: {v}"))?;
    entries
        .iter()
        .map(|e| {
            let value = e
                .get("value")
                .and_then(|v| v.as_str())
                .with_context(|| format!("path entry has no string value: {e}"))?
                .to_string();
            if !value.starts_with('/') && e.get("type").and_then(|t| t.as_str()) != Some("regex") {
                anyhow::bail!("path {value:?} does not start with /");
            }
            match e.get("type").and_then(|t| t.as_str()) {
                Some("exact") => Ok(PathMatch::Exact(value)),
                Some("prefix") => Ok(PathMatch::Prefix(value)),
                Some("regex") => {
                    // Refused here rather than skipped by the data plane, where a pattern that
                    // does not compile would leave its route matching nothing.
                    gapura_core::matcher::compile_path_regex(&value)
                        .with_context(|| format!("path regex {value:?} does not compile"))?;
                    Ok(PathMatch::Regex(value))
                }
                other => {
                    anyhow::bail!("path type {other:?} is not one of exact, prefix, regex: {e}")
                }
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn known_path_shapes_are_read() {
        let paths = parse_paths(&json!([
            {"type": "exact", "value": "/a"},
            {"type": "prefix", "value": "/b"},
            {"type": "regex", "value": "^/c$"},
        ]))
        .unwrap();
        assert_eq!(
            paths,
            vec![
                PathMatch::Exact("/a".into()),
                PathMatch::Prefix("/b".into()),
                PathMatch::Regex("^/c$".into()),
            ]
        );
    }

    #[test]
    fn an_empty_path_list_is_valid_and_means_every_path() {
        assert!(parse_paths(&json!([])).unwrap().is_empty());
    }

    #[test]
    fn an_unreadable_path_entry_is_an_error_not_a_catch_all() {
        // Dropping these used to leave an empty list, which compiles to `PathPrefix /`.
        for bad in [
            json!([{"type": "PathPrefix", "value": "/admin"}]),
            json!([{"type": "prefix"}]),
            json!([{"value": "/admin"}]),
            json!([{"type": "prefix", "value": 5}]),
            json!([{"type": "prefix", "value": "admin"}]),
            json!({"type": "prefix", "value": "/admin"}),
            json!(null),
        ] {
            assert!(parse_paths(&bad).is_err(), "accepted {bad}");
        }
        // One bad entry among good ones still fails: a route that matches part of what was
        // written is as wrong as one that matches all of it.
        assert!(parse_paths(&json!([
            {"type": "prefix", "value": "/ok"},
            {"type": "glob", "value": "/admin/*"},
        ]))
        .is_err());
    }

    #[test]
    fn an_unreadable_policy_is_an_error_not_an_open_route() {
        assert!(parse_plugin("jwt", json!({"jwks": 5})).is_err());
        assert!(
            parse_plugin("jwt", json!({"issuer": "x"})).is_err(),
            "no jwks"
        );
        assert!(parse_plugin("key_auth", json!({"header": 7})).is_err());
        assert!(parse_plugin("oauth2", json!({})).is_err(), "unknown name");
    }

    #[test]
    fn readable_policies_are_read() {
        assert!(matches!(
            parse_plugin("jwt", json!({"jwks": "{\"keys\":[]}"})),
            Ok(Plugin::Jwt(_))
        ));
        assert!(matches!(
            parse_plugin("key_auth", json!({"header": "x-api-key"})),
            Ok(Plugin::KeyAuth(_))
        ));
    }
}
