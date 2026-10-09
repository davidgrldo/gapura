//! Services and routes as the console reads and writes them.
//!
//! Each write is one transaction, in the grants slice's order: re-read the caller's rights
//! locked and decide with `configuration::allowed`; read the row it changes `FOR UPDATE`; write;
//! leave one `audit_log` row. A refusal writes nothing, and neither does a replace that changes
//! nothing. The data planes see a write through the trigger that bumps `config_state.version`.
//!
//! A route write also takes one advisory lock before it reads other workspaces' hosts, so two
//! workspaces claiming one host at the same moment are ordered. Every write takes its locks in
//! one order: the caller's grant rows `FOR SHARE`; on a replace, the route `FOR UPDATE`, so a
//! missing or stale one answers before anything else is weighed; the hosts advisory lock; the
//! route's service `FOR SHARE`; the row written; `config_state`, through the trigger. A writer
//! that holds the advisory lock waits only on locks later in that order, so the lock cannot close
//! a cycle, and a deadlock between two writes elsewhere is settled by `retrying`.

use super::grants::{audit, retrying, rights, Entry};
use super::{Store, WriteError};
use crate::access::User;
use crate::configuration::{
    self, Action, HeaderMatch, HeadersOnReplace, JwtRequirementView, KeyAuthView, PathMatch,
    Protocol, Route, RouteView, Service, ServiceView, Tls, TlsOnReplace,
};
use crate::grants::Refusal;
use anyhow::Result;
use std::collections::{BTreeSet, HashMap};
use tokio_postgres::Transaction;
use uuid::Uuid;

/// `column`, a `timestamptz`, as the API shows it and compares it: UTC, to the microsecond, as
/// text. Postgres keeps microseconds, so a value read back and sent again compares equal, which
/// is what lets a stale save be told from a fresh one.
pub(super) fn updated_at(column: &str) -> String {
    format!(r#"to_char({column} at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')"#)
}

const STALE: &str =
    "Someone changed this since you opened it, so your change was not saved. Reload to see theirs.";

/// The advisory lock every route write takes before it reads other workspaces' hosts, so two
/// workspaces claiming the same host at the same moment are ordered and the second sees the
/// first's.
const ROUTE_HOSTS_LOCK: &str = "select pg_advisory_xact_lock(hashtext('gapura route hosts'))";

/// The schema's check allows only these two, so anything else cannot be read back.
fn protocol(name: &str) -> Protocol {
    if name == "https" {
        Protocol::Https
    } else {
        Protocol::Http
    }
}

fn service_from(row: &tokio_postgres::Row) -> Service {
    Service {
        name: row.get("name"),
        protocol: protocol(row.get("protocol")),
        host: row.get("host"),
        port: row.get("port"),
        connect_timeout_ms: row.get("connect_timeout_ms"),
        read_timeout_ms: row.get("read_timeout_ms"),
        tls: Tls {
            verify: row.get("tls_verify"),
            ca_pem: row.get("tls_ca_pem"),
            sni: row.get("tls_sni"),
        },
    }
}

/// The columns `service_from` reads, besides `name`.
const SERVICE_COLUMNS: &str = "protocol, host, port, connect_timeout_ms, read_timeout_ms, \
                               tls_verify, tls_ca_pem, tls_sni";

/// A route row as the API shows it. A `paths` or `headers` value this binary cannot read is an
/// error, not an empty list, which would read as "every path" or "any headers".
fn route_from(row: &tokio_postgres::Row) -> Result<Route> {
    let paths: serde_json::Value = row.get("paths");
    let paths: Vec<PathMatch> = serde_json::from_value(paths)
        .map_err(|e| anyhow::anyhow!("a route's paths do not read: {e}"))?;
    let headers: serde_json::Value = row.get("headers");
    let headers: Vec<HeaderMatch> = serde_json::from_value(headers)
        .map_err(|e| anyhow::anyhow!("a route's headers do not read: {e}"))?;
    Ok(Route {
        name: row.get("name"),
        service: row.get("service"),
        hosts: row.get("hosts"),
        paths,
        methods: row.get("methods"),
        headers,
        priority: row.get("priority"),
    })
}

/// Step 1 of every write: may `caller` do `action` in `workspace`, decided over rows locked here.
/// `allowed` also refuses a disabled caller, which `rights` leaves to it.
pub(super) async fn decide(
    tx: &Transaction<'_>,
    caller: Uuid,
    workspace: Uuid,
    action: Action,
) -> Result<User, WriteError> {
    let (actor, rows) = rights(tx, caller, &BTreeSet::from([workspace])).await?;
    // Deleted since the handler found it, by a delete this read waited for: answered as the
    // handler answers a workspace that does not exist, where a superuser, who holds a role in
    // every workspace, would otherwise go on to a write the foreign key refuses.
    if !rows.workspaces.iter().any(|w| w.id == workspace) {
        return Err(configuration::no_role().into());
    }
    configuration::allowed(&rows, &actor, workspace, action)?;
    Ok(actor)
}

/// May `actor` route `hosts` from `workspace`: a route for any host only as a superuser, a
/// wildcard over a single label only as a superuser, and never a host another workspace already
/// routes. Hosts belong to one workspace, so one workspace's editor cannot take another's
/// traffic. Only other workspaces are read, so a route never conflicts with itself or with its
/// own workspace's routes, whose order the priority settles.
///
/// A route with no hosts neither claims a host nor is blocked by one: it takes whatever no named
/// host matches, so a superuser's catch-all is exempt from the overlap rule, and a workspace that
/// names a host the catch-all would also serve is not refused for it.
async fn may_route(
    tx: &Transaction<'_>,
    actor: &User,
    workspace: Uuid,
    hosts: &[String],
) -> Result<(), WriteError> {
    if hosts.is_empty() {
        configuration::may_route_any_host(actor)?;
    }
    for host in hosts {
        configuration::may_claim_wildcard(actor, host)?;
    }
    tx.execute(ROUTE_HOSTS_LOCK, &[]).await?;
    let taken: Vec<String> = tx
        .query(
            "select h from routes, unnest(hosts) as h where workspace_id <> $1",
            &[&workspace],
        )
        .await?
        .iter()
        .map(|row| row.get(0))
        .collect();
    // The other workspace is not named: a caller may hold no role there, and the answer would
    // tell them it exists.
    if let Some(host) = hosts
        .iter()
        .find(|host| taken.iter().any(|t| configuration::hosts_overlap(host, t)))
    {
        return Err(
            Refusal::Conflict(format!("{host} is already routed by another workspace.")).into(),
        );
    }
    Ok(())
}

pub(super) fn json<T: serde::Serialize>(value: &T) -> serde_json::Value {
    serde_json::to_value(value).expect("a validated row always serialises")
}

/// Refuses a delete while policies hang off the row. They go with it by `on delete cascade`, and
/// that would drop a route's key-auth or JWT policy unseen: delete and create again, and the route
/// answers without asking for credentials, with no audit entry saying the policy went. `column`
/// is `route_id` or `service_id`, `kind` the word for the row.
async fn no_policies(
    tx: &Transaction<'_>,
    column: &str,
    id: Uuid,
    kind: &str,
) -> Result<(), WriteError> {
    let attached: i64 = tx
        .query_one(
            &format!("select count(*) from plugins where {column} = $1"),
            &[&id],
        )
        .await?
        .get(0);
    match attached {
        0 => Ok(()),
        1 => Err(Refusal::Conflict(format!(
            "1 policy is attached to this {kind}. Remove it first."
        ))
        .into()),
        n => Err(Refusal::Conflict(format!(
            "{n} policies are attached to this {kind}. Remove them first."
        ))
        .into()),
    }
}

/// A workspace's policies of one name, by what they are attached to: the policies the compiler
/// reads, enabled rows with no consumer, each as the value a list shows of it.
struct Attached<T> {
    workspace: Option<T>,
    services: HashMap<Uuid, T>,
    routes: HashMap<Uuid, T>,
}

impl<T: Clone> Attached<T> {
    async fn read(
        client: &tokio_postgres::Client,
        workspace: Uuid,
        name: &str,
        value: impl Fn(serde_json::Value) -> Result<T>,
    ) -> Result<Attached<T>> {
        let rows = client
            .query(
                "select route_id, service_id, config from plugins
                  where workspace_id = $1 and name = $2 and consumer_id is null
                    and enabled",
                &[&workspace, &name],
            )
            .await?;
        let mut found = Attached {
            workspace: None,
            services: HashMap::new(),
            routes: HashMap::new(),
        };
        for row in rows {
            let v = value(row.get("config"))?;
            let route: Option<Uuid> = row.get("route_id");
            let service: Option<Uuid> = row.get("service_id");
            match (route, service) {
                (Some(route), _) => found.routes.insert(route, v),
                (None, Some(service)) => found.services.insert(service, v),
                (None, None) => found.workspace.replace(v),
            };
        }
        Ok(found)
    }

    /// A service's own policy, else the workspace's, and which it is.
    fn service(&self, service: Uuid) -> Option<(T, &'static str)> {
        let own = self.services.get(&service).map(|v| (v.clone(), "service"));
        own.or_else(|| self.workspace.clone().map(|v| (v, "workspace")))
    }

    /// A route's own policy, else its service's, else the workspace's, and which it is.
    fn route(&self, route: Uuid, service: Uuid) -> Option<(T, &'static str)> {
        let own = self.routes.get(&route).map(|v| (v.clone(), "route"));
        own.or_else(|| self.service(service))
    }
}

/// The key and JWT requirements of a workspace, as its service and route lists show them.
struct Requirements {
    key_auth: Attached<String>,
    jwt: Attached<Option<String>>,
}

impl Requirements {
    async fn read(client: &tokio_postgres::Client, workspace: Uuid) -> Result<Requirements> {
        let key_auth = Attached::read(client, workspace, "key_auth", |config| {
            // The compiler refuses such a row too, so it is an error here, not a requirement
            // listed with no header.
            config
                .get("header")
                .and_then(|h| h.as_str())
                .map(str::to_string)
                .ok_or_else(|| anyhow::anyhow!("a key_auth policy has no header"))
        })
        .await?;
        let jwt = Attached::read(client, workspace, "jwt", |config| {
            // Likewise a configuration that does not fit a jwt policy.
            serde_json::from_value::<gapura_core::config::JwtPolicy>(config)
                .map(|p| p.issuer)
                .map_err(|_| anyhow::anyhow!("a jwt policy does not fit its shape"))
        })
        .await?;
        Ok(Requirements { key_auth, jwt })
    }

    fn key_auth((header, from): (String, &'static str)) -> KeyAuthView {
        KeyAuthView { header, from }
    }

    fn jwt((issuer, from): (Option<String>, &'static str)) -> JwtRequirementView {
        JwtRequirementView { issuer, from }
    }
}

impl Store {
    /// A workspace's services, by name, each with how many routes use it and the key and JWT
    /// requirements it carries.
    pub async fn services(&self, workspace: Uuid) -> Result<Vec<ServiceView>> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                &format!(
                    "select s.id, s.name, s.protocol, s.host, s.port, s.connect_timeout_ms,
                            s.read_timeout_ms, s.tls_verify, s.tls_ca_pem, s.tls_sni,
                            {} as updated_at,
                            (select count(*) from routes r where r.service_id = s.id) as routes
                       from services s where s.workspace_id = $1 order by s.name",
                    updated_at("s.updated_at")
                ),
                &[&workspace],
            )
            .await?;
        let found = Requirements::read(&client, workspace).await?;
        Ok(rows
            .iter()
            .map(|r| ServiceView {
                service: service_from(r),
                routes: r.get("routes"),
                updated_at: r.get("updated_at"),
                key_auth: found
                    .key_auth
                    .service(r.get("id"))
                    .map(Requirements::key_auth),
                jwt: found.jwt.service(r.get("id")).map(Requirements::jwt),
            })
            .collect())
    }

    /// A workspace's routes, in the order the data plane matches them: priority, then name, each
    /// with the key and JWT requirements that apply to it. A
    /// route with no service, which only SQL written by hand can make, is not listed, just as
    /// the compiler does not serve it.
    pub async fn routes(&self, workspace: Uuid) -> Result<Vec<RouteView>> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                &format!(
                    "select r.id, r.service_id, r.name, s.name as service, r.hosts, r.methods,
                            r.paths, r.headers, r.priority, {} as updated_at,
                            {} as service_updated_at
                       from routes r join services s on s.id = r.service_id
                      where r.workspace_id = $1 order by r.priority desc, r.name",
                    updated_at("r.updated_at"),
                    updated_at("s.updated_at")
                ),
                &[&workspace],
            )
            .await?;
        let found = Requirements::read(&client, workspace).await?;
        rows.iter()
            .map(|r| {
                let (id, service) = (r.get("id"), r.get("service_id"));
                Ok(RouteView {
                    route: route_from(r)?,
                    updated_at: r.get("updated_at"),
                    service_updated_at: r.get("service_updated_at"),
                    key_auth: found
                        .key_auth
                        .route(id, service)
                        .map(Requirements::key_auth),
                    jwt: found.jwt.route(id, service).map(Requirements::jwt),
                })
            })
            .collect()
    }

    /// Creates `s` in `workspace` as `caller`, who needs the editor role there.
    pub async fn create_service(
        &self,
        caller: Uuid,
        workspace: Uuid,
        s: &Service,
    ) -> Result<(), WriteError> {
        retrying(move || self.try_create_service(caller, workspace, s)).await
    }

    async fn try_create_service(
        &self,
        caller: Uuid,
        workspace: Uuid,
        s: &Service,
    ) -> Result<(), WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let actor = decide(&tx, caller, workspace, Action::Write).await?;
        let Some(row) = tx
            .query_opt(
                "insert into services (workspace_id, name, protocol, host, port,
                                       connect_timeout_ms, read_timeout_ms, tls_verify,
                                       tls_ca_pem, tls_sni)
                 values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                 on conflict (workspace_id, name) do nothing returning id",
                &[
                    &workspace,
                    &s.name,
                    &s.protocol.as_str(),
                    &s.host,
                    &s.port,
                    &s.connect_timeout_ms,
                    &s.read_timeout_ms,
                    &s.tls.verify,
                    &s.tls.ca_pem,
                    &s.tls.sni,
                ],
            )
            .await?
        else {
            return Err(Refusal::Conflict(format!(
                "A service named {} already exists in this workspace.",
                s.name
            ))
            .into());
        };
        audit(
            &tx,
            &actor,
            Entry {
                action: "create",
                object_kind: "service",
                object_id: Some(row.get("id")),
                workspace: Some(workspace),
                before: None,
                after: Some(json(s)),
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Replaces the service called `current`, which may rename it, when `seen` is its
    /// `updated_at` as last read. Its routes follow it, since they hold its id, not its name.
    /// `tls` says whether `s.tls` is written or the stored settings are kept.
    pub async fn replace_service(
        &self,
        caller: Uuid,
        workspace: Uuid,
        current: &str,
        s: &Service,
        seen: &str,
        tls: TlsOnReplace,
    ) -> Result<(), WriteError> {
        retrying(move || self.try_replace_service(caller, workspace, current, s, seen, tls)).await
    }

    async fn try_replace_service(
        &self,
        caller: Uuid,
        workspace: Uuid,
        current: &str,
        s: &Service,
        seen: &str,
        tls: TlsOnReplace,
    ) -> Result<(), WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let actor = decide(&tx, caller, workspace, Action::Write).await?;
        let Some(row) = tx
            .query_opt(
                &format!(
                    "select id, name, {SERVICE_COLUMNS}, {} as updated_at
                       from services where workspace_id = $1 and name = $2 for update",
                    updated_at("updated_at")
                ),
                &[&workspace, &current],
            )
            .await?
        else {
            return Err(Refusal::NotFound(format!(
                "There is no service named {current} in this workspace."
            ))
            .into());
        };
        if row.get::<_, &str>("updated_at") != seen {
            return Err(Refusal::Conflict(STALE.into()).into());
        }
        let id: Uuid = row.get("id");
        if s.name != current
            && tx
                .query_opt(
                    "select 1 from services where workspace_id = $1 and name = $2",
                    &[&workspace, &s.name],
                )
                .await?
                .is_some()
        {
            return Err(Refusal::Conflict(format!(
                "A service named {} already exists in this workspace.",
                s.name
            ))
            .into());
        }
        let before = service_from(&row);
        // Read under the `for update` above, so what is kept is what is there when this writes.
        // An `http` service keeps nothing: it may only have the defaults, which `s` carries.
        let mut s = s.clone();
        if tls == TlsOnReplace::Kept && s.protocol == Protocol::Https {
            s.tls = before.tls.clone();
        }
        // Nothing to write, so nothing to audit and nothing for the data planes to reload.
        if before == s {
            return Ok(());
        }
        tx.execute(
            "update services set name = $2, protocol = $3, host = $4, port = $5,
                    connect_timeout_ms = $6, read_timeout_ms = $7, tls_verify = $8,
                    tls_ca_pem = $9, tls_sni = $10, updated_at = now()
              where id = $1",
            &[
                &id,
                &s.name,
                &s.protocol.as_str(),
                &s.host,
                &s.port,
                &s.connect_timeout_ms,
                &s.read_timeout_ms,
                &s.tls.verify,
                &s.tls.ca_pem,
                &s.tls.sni,
            ],
        )
        .await?;
        audit(
            &tx,
            &actor,
            Entry {
                action: "update",
                object_kind: "service",
                object_id: Some(id),
                workspace: Some(workspace),
                before: Some(json(&before)),
                after: Some(json(&s)),
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Deletes the service called `name`, which needs the admin role, and only while no route
    /// uses it, since they would point nowhere, and no policy is attached to it.
    pub async fn delete_service(
        &self,
        caller: Uuid,
        workspace: Uuid,
        name: &str,
    ) -> Result<(), WriteError> {
        retrying(move || self.try_delete_service(caller, workspace, name)).await
    }

    async fn try_delete_service(
        &self,
        caller: Uuid,
        workspace: Uuid,
        name: &str,
    ) -> Result<(), WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let actor = decide(&tx, caller, workspace, Action::Delete).await?;
        let Some(row) = tx
            .query_opt(
                &format!(
                    "select id, name, {SERVICE_COLUMNS}
                       from services where workspace_id = $1 and name = $2 for update"
                ),
                &[&workspace, &name],
            )
            .await?
        else {
            return Err(Refusal::NotFound(format!(
                "There is no service named {name} in this workspace."
            ))
            .into());
        };
        let id: Uuid = row.get("id");
        // Route writes hold the service `for share`, so none can start using it between this
        // count and the delete: the `for update` above waits for them, and they for it.
        let used: i64 = tx
            .query_one("select count(*) from routes where service_id = $1", &[&id])
            .await?
            .get(0);
        if used > 0 {
            let routes = if used == 1 {
                "1 route uses".to_string()
            } else {
                format!("{used} routes use")
            };
            return Err(Refusal::Conflict(format!(
                "{routes} this service. Point them at another service or delete them first."
            ))
            .into());
        }
        no_policies(&tx, "service_id", id, "service").await?;
        tx.execute("delete from services where id = $1", &[&id])
            .await?;
        audit(
            &tx,
            &actor,
            Entry {
                action: "delete",
                object_kind: "service",
                object_id: Some(id),
                workspace: Some(workspace),
                before: Some(json(&service_from(&row))),
                after: None,
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    // Routes follow the same three shapes. The differences: the service is looked up by name in
    // the same workspace (`for share`, so it cannot be deleted under the write), a missing one
    // is a 400 naming it, and the hosts are checked against every other workspace's.

    /// Creates `r` in `workspace` as `caller`, who needs the editor role there.
    pub async fn create_route(
        &self,
        caller: Uuid,
        workspace: Uuid,
        r: &Route,
    ) -> Result<(), WriteError> {
        retrying(move || self.try_write_route(caller, workspace, None, r)).await
    }

    /// Replaces the route called `current`, which may rename it, when `seen` is its
    /// `updated_at` as last read and `service_seen`, when sent, is the `updated_at` of the
    /// service the route pointed at then. `headers` says whether `r.headers` is written or the
    /// stored ones are kept.
    #[allow(clippy::too_many_arguments)]
    pub async fn replace_route(
        &self,
        caller: Uuid,
        workspace: Uuid,
        current: &str,
        r: &Route,
        seen: &str,
        service_seen: Option<&str>,
        headers: HeadersOnReplace,
    ) -> Result<(), WriteError> {
        retrying(move || {
            self.try_write_route(
                caller,
                workspace,
                Some((current, seen, service_seen, headers)),
                r,
            )
        })
        .await
    }

    /// Creates `r` when `replacing` is `None`, and otherwise replaces the route it names when
    /// the `updated_at` beside the name is the route's own, and the service's -- when sent --
    /// is the one its row had as last read.
    async fn try_write_route(
        &self,
        caller: Uuid,
        workspace: Uuid,
        replacing: Option<(&str, &str, Option<&str>, HeadersOnReplace)>,
        r: &Route,
    ) -> Result<(), WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let actor = decide(&tx, caller, workspace, Action::Write).await?;
        // The route being replaced is read first, so a save to one that is gone or was changed
        // meanwhile answers that, not some other refusal its new contents would earn.
        let existing = match replacing {
            None => None,
            Some((current, seen, service_seen, headers)) => {
                let Some(row) = tx
                    .query_opt(
                        &format!(
                            "select r.id, r.name, s.name as service, r.hosts, r.methods, r.paths,
                                    r.headers, r.priority, {} as updated_at,
                                    {} as service_updated_at
                               from routes r join services s on s.id = r.service_id
                              where r.workspace_id = $1 and r.name = $2 for update of r",
                            updated_at("r.updated_at"),
                            updated_at("s.updated_at")
                        ),
                        &[&workspace, &current],
                    )
                    .await?
                else {
                    return Err(Refusal::NotFound(format!(
                        "There is no route named {current} in this workspace."
                    ))
                    .into());
                };
                if row.get::<_, &str>("updated_at") != seen {
                    return Err(Refusal::Conflict(STALE.into()).into());
                }
                // The service is part of what the reader saw, and a rename or a re-creation
                // moves the service's row without moving the route's, so the route's stamp
                // alone calls that read fresh. When the client sent the service's stamp and it
                // no longer matches, the save is stale whatever the name it carries now
                // resolves to: to nothing, which used to be a 400, or to a new row of the old
                // name, which silently moved the route onto it.
                if let Some(seen_service) = service_seen {
                    if row.get::<_, &str>("service_updated_at") != seen_service {
                        return Err(Refusal::Conflict(STALE.into()).into());
                    }
                }
                let before = route_from(&row).map_err(WriteError::Store)?;
                Some((row.get::<_, Uuid>("id"), before, headers))
            }
        };
        // Read under the `for update` above, so what is kept is what is there when this writes.
        let r = &match &existing {
            Some((_, before, HeadersOnReplace::Kept)) => Route {
                headers: before.headers.clone(),
                ..r.clone()
            },
            _ => r.clone(),
        };
        // On a replace as well as a create, so a save that keeps `hosts: []` is checked too.
        may_route(&tx, &actor, workspace, &r.hosts).await?;
        let Some(service) = tx
            .query_opt(
                "select id from services where workspace_id = $1 and name = $2 for share",
                &[&workspace, &r.service],
            )
            .await?
        else {
            return Err(Refusal::Invalid(format!(
                "There is no service named {} in this workspace.",
                r.service
            ))
            .into());
        };
        let service_id: Uuid = service.get("id");
        let paths = json(&r.paths);
        let headers = json(&r.headers);
        match existing {
            None => {
                let Some(row) = tx
                    .query_opt(
                        "insert into routes (workspace_id, service_id, name, hosts, methods,
                                             paths, headers, priority)
                         values ($1, $2, $3, $4, $5, $6, $7, $8)
                         on conflict (workspace_id, name) do nothing returning id",
                        &[
                            &workspace,
                            &service_id,
                            &r.name,
                            &r.hosts,
                            &r.methods,
                            &paths,
                            &headers,
                            &r.priority,
                        ],
                    )
                    .await?
                else {
                    return Err(Refusal::Conflict(format!(
                        "A route named {} already exists in this workspace.",
                        r.name
                    ))
                    .into());
                };
                audit(
                    &tx,
                    &actor,
                    Entry {
                        action: "create",
                        object_kind: "route",
                        object_id: Some(row.get("id")),
                        workspace: Some(workspace),
                        before: None,
                        after: Some(json(r)),
                    },
                )
                .await?;
            }
            Some((id, before, _)) => {
                if r.name != before.name
                    && tx
                        .query_opt(
                            "select 1 from routes where workspace_id = $1 and name = $2",
                            &[&workspace, &r.name],
                        )
                        .await?
                        .is_some()
                {
                    return Err(Refusal::Conflict(format!(
                        "A route named {} already exists in this workspace.",
                        r.name
                    ))
                    .into());
                }
                // Checked like any other save, then nothing to write, so nothing to audit and
                // nothing for the data planes to reload.
                if before == *r {
                    return Ok(());
                }
                tx.execute(
                    "update routes set service_id = $2, name = $3, hosts = $4, methods = $5,
                            paths = $6, headers = $7, priority = $8, updated_at = now()
                      where id = $1",
                    &[
                        &id,
                        &service_id,
                        &r.name,
                        &r.hosts,
                        &r.methods,
                        &paths,
                        &headers,
                        &r.priority,
                    ],
                )
                .await?;
                audit(
                    &tx,
                    &actor,
                    Entry {
                        action: "update",
                        object_kind: "route",
                        object_id: Some(id),
                        workspace: Some(workspace),
                        before: Some(json(&before)),
                        after: Some(json(r)),
                    },
                )
                .await?;
            }
        }
        tx.commit().await?;
        Ok(())
    }

    /// Deletes the route called `name`, which needs the admin role, and only while no policy is
    /// attached to it.
    pub async fn delete_route(
        &self,
        caller: Uuid,
        workspace: Uuid,
        name: &str,
    ) -> Result<(), WriteError> {
        retrying(move || self.try_delete_route(caller, workspace, name)).await
    }

    async fn try_delete_route(
        &self,
        caller: Uuid,
        workspace: Uuid,
        name: &str,
    ) -> Result<(), WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let actor = decide(&tx, caller, workspace, Action::Delete).await?;
        let Some(row) = tx
            .query_opt(
                "select r.id, r.name, s.name as service, r.hosts, r.methods, r.paths, r.headers,
                        r.priority
                   from routes r join services s on s.id = r.service_id
                  where r.workspace_id = $1 and r.name = $2 for update of r",
                &[&workspace, &name],
            )
            .await?
        else {
            return Err(Refusal::NotFound(format!(
                "There is no route named {name} in this workspace."
            ))
            .into());
        };
        let id: Uuid = row.get("id");
        no_policies(&tx, "route_id", id, "route").await?;
        let before = route_from(&row).map_err(WriteError::Store)?;
        tx.execute("delete from routes where id = $1", &[&id])
            .await?;
        audit(
            &tx,
            &actor,
            Entry {
                action: "delete",
                object_kind: "route",
                object_id: Some(id),
                workspace: Some(workspace),
                before: Some(json(&before)),
                after: None,
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
}
