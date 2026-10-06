# Changelog

Notable changes, newest first. v0.1.0 is the first release: nothing was tagged before it, so
everyone running Gapura until now has been running a checkout of this repository, and "upgrading"
to v0.1.0 means `helm upgrade` from that checkout to the published chart. From v0.1.0 onward it
means what it usually does, moving from one version below to a later one. Release procedure:
[docs/RELEASING.md](docs/RELEASING.md).

## Unreleased

- The console now refuses a workspace admin's change that would leave the workspace with no
  admin, with 409 and a sentence saying to make someone else an admin first. The console warned
  before such a save, but only in the browser and from what the page read when it loaded, so a
  stale tab or a request made with curl could leave a workspace that only a superuser could
  repair. The rule covers direct grants and group mappings, counts admins through groups, and
  orders two admins stepping down at the same moment so that one of them is refused. A
  superuser's changes are exempt.
- Every console response now carries a Content Security Policy that allows only the console's
  own origin (`frame-ancestors 'none'` included), `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`. Before, the console set
  none, so another site could frame it and a response could be sniffed as a type it is not.
- A store row the control plane cannot read now fails the configuration instead of being left
  out. Before, a `jwt` or `key_auth` policy whose configuration did not parse was dropped with a
  warning while the route it guarded was still compiled, so that route admitted everyone; and a
  path entry with an unknown `type` (Gateway API's `PathPrefix` spelling is the easy mistake) was
  dropped, and a route left with no paths matches every path. Now either one makes `/v1/config`
  answer 503 naming the row, and every data plane keeps serving the last configuration it
  verified: a bad row costs new configuration, never protection. A path that does not start with
  `/` is refused the same way. An empty path list is still valid and still means every path.
- `/debug/config` no longer serves key material besides TLS private keys. It already redacted
  `tls.key_pem`, but every JWT policy's JWKS went out verbatim, and an `oct` key in a JWKS is the
  HMAC signing secret: anyone who could reach the admin port could mint tokens that every JWT
  route accepted. The JWKS is now `<redacted>`, as is the credential map (the SHA-256 of every
  issued API key, which `/debug/config` printed in full) -- it now says only how many keys there
  are. A test builds a config with one of each secret and fails if any value reaches the dump.
- The chart can close the admin port with a NetworkPolicy (`networkPolicy.enabled`). The admin
  port has no authentication, so any pod in the cluster can read the full routing map, and a
  tenant who can create a Service with a hand-written EndpointSlice can route an internet hostname
  to it. The policy admits anyone on the traffic ports (including `extraListenHttp/Https`) and only
  the release namespace and `networkPolicy.adminFromNamespaces` on the admin port. Off by default
  because turning it on stops a Prometheus in another namespace from scraping until that namespace
  is listed; turning it on is recommended.
- In `--control-plane` mode, a resolver error no longer empties a backend. The control plane sends
  resolve-backed clusters with no addresses, and the data plane fills them; on a lookup error it
  meant to keep the previous addresses but kept the control plane's empty list, so a CoreDNS
  restart was a 503 for every such backend. It now keeps the addresses it is already serving for
  that cluster, as long as the cluster still names the same host.
- A `--control-plane` gateway that starts from its cache and is then told "nothing has changed"
  now keeps re-resolving its backends. Before, a 304 left it with no configuration to resolve
  from, so a pod that booted before DNS answered stayed Ready serving 503 until the control plane's
  version changed; and `gapura_config_from_cache` stayed 1 although the control plane had just
  confirmed the version. A 304 now clears it.
- `--control-plane` refuses an `http://` URL. Every configuration carries the private key of each
  certificate the gateway serves, and ADR 4 requires TLS, but the gateway accepted plain http and
  could not trust a private CA. `--control-plane-ca` adds CA certificates to trust;
  `--control-plane-insecure-http` allows http for a control plane on loopback or behind a TLS
  sidecar. `gapura-control` does not yet terminate TLS on `/v1/config` itself.
- Routes are matched on a normalised path, and that path is what reaches the backend. The raw
  request target used to be matched and forwarded unchanged, so the two could disagree with the
  backend's own normalisation: `/public/../admin` matched an unguarded `/public` rule and was
  served as `/admin`, and `/%61dmin`, `//admin` and an absolute-form `GET http://x/admin` all
  missed a `/admin` rule carrying a JWT or key policy and fell through to a catch-all. Now
  percent-encoded unreserved characters are decoded, repeated slashes merged, and a target that is
  not an absolute path, or holds a `.` or `..` segment (encoded or not), is answered `400`. An
  encoded slash (`%2F`) is left as it is, as Envoy does by default. `OPTIONS *` is now `400`.
- A JWT policy that names an issuer or an audience requires the claim. `jsonwebtoken` only checks
  `iss` and `aud` when the token carries them, so a correctly signed token that simply left `aud`
  out was accepted by a policy with `audience: orders`. `nbf` is now honoured too.
- A request is replayed after a failure on a reused upstream connection only if its method is
  idempotent, and only once. Pingora's default, which this did not override, retried any method up
  to sixteen times, replaying the body: a `POST` the backend had processed before its keep-alive
  connection died could be sent again.
- A `RequestMirror` asking for a share of the traffic is refused instead of mirroring all of it.
  `percent` and `fraction` were not read, and unknown fields are ignored, so `percent: 1` -- or
  `percent: 0`, the usual way to pause a mirror -- mirrored every request while the route reported
  `Accepted=True`. A partial mirror now gets `Accepted=False` with reason `UnsupportedValue` until
  the data plane can sample; `percent: 100` or a whole fraction is accepted, being what happens.
- Rollouts and node drains no longer refuse connections. On SIGTERM Pingora closes its listeners at
  once, while the pod leaves the Service endpoints asynchronously and a cloud load balancer keeps
  sending to the node until its health checks fail, so every `helm upgrade` refused new
  connections for that window. The chart now holds SIGTERM back for `preStopDelaySeconds` (15)
  with a `sleep` pre-stop action, applied on Kubernetes 1.30+ since the image has no shell, and
  sets `minReadySeconds` (10) so an old pod is not terminated the moment its replacement is Ready.
  `terminationGracePeriodSeconds` goes from 75 to 90 to fit both. A values file that still says
  75 keeps rendering, with the delay shortened to what fits; below 61 the chart refuses to render.
- `helm upgrade --reuse-values` from 0.1.0 renders again. `accessLog` did not exist in 0.1.0, and
  the template read `.Values.accessLog.query` bare, which is a nil-pointer error when the section
  is missing. `hack/chart-render.sh` now fails on any two-level `.Values` access without a nil
  guard, so the next section added cannot reintroduce it.
- A dispatched release may only publish a prerelease (`v0.2.0-rc.9`); a release is published by
  pushing its tag. Dispatch builds whatever the dispatched branch holds, so dispatching `v0.2.0` by
  mistake published the GA image and chart from `main`, and the later tag push silently overwrote
  both. The dispatch input now reaches shell through the environment rather than template
  interpolation. The quickstart workflow that runs after a release now installs the version that
  release published -- read from the run's name, `release <version>` -- instead of the newest
  tag, which after every RC re-tested the previous release; it also orders prereleases correctly,
  so `0.1.0` sorts after `0.1.0-rc.3`.
- The console runs at most two password checks at once. The limit was the core count, which in
  a pod with a memory limit and no CPU limit -- the chart's default -- is the node's: each argon2id
  check holds 19 MiB, so on a node with seven or more cores seven anonymous sign-ins at once
  exceeded the 128Mi limit and the pod was OOM-killed, repeatedly. A compile-time check now keeps
  the cap within half the chart's limit.

- A gateway that loses its listen port to another process between its startup bind check and
  Pingora's own bind now exits once Pingora gives up on the port, 30 s later, instead of running
  on without that listener while its probes stay green (#104). Only a process in the same network
  namespace can take the port in that window, which lasts milliseconds.
- Superusers and workspace admins grant, change and remove direct roles and group mappings from
  the console: Edit access on an opened Users row, and Map a group, Edit and Remove on Roles,
  whose mappings now say how many accounts were in each group at their last sign-in. An admin does
  so in the workspaces they administer, up to and including admin and their own grant, and the
  console asks first when a change would leave them no longer admin there, through a group
  mapping as well as a direct grant. The check is made again inside the transaction that writes,
  so a demotion that races the write is ordered, never interleaved. `/api/me` gains the account's
  `id`, names the workspaces in `grantable`, and lists in each of its `roles` the `sources` that
  give it, as `/api/users` does; every source in `/api/users` names the role it gives. Workspaces
  are listed by name in byte order, the same on every deployment, so `Zeta` comes before `alpha`.
- Every such change is an `audit_log` entry naming who made it and how they signed in, in the
  nullable `actor_method` column (`local` or `oidc`) that migration `0003` adds.
- A request other than `GET` or `HEAD` from another site is refused, sign-in and sign-out
  included: `Sec-Fetch-Site` has to say `same-origin`, or, from a browser that does not send it,
  `Origin` has to name the host the request was sent to, as `Host` or a proxy's
  `X-Forwarded-Host` gives it, with `:443` and `:80` taken as default ports. That fallback is for
  Safari before 16.4.
  Writes to the API take JSON only, so a script that writes through it has to send `Content-Type:
  application/json`, on a `DELETE` with no body too, and must not send another site's `Origin`.
- The console's OIDC callback only finishes a sign-in in the browser that began it. Before, the
  `state` it checked was held by the server alone, so someone could begin a sign-in, sign in at
  the identity provider as themselves, and send another person's browser to the callback with
  their code, signing that browser in to the console as them. `GET /auth/login` now also sets a
  `gapura_login_state` cookie (HttpOnly, Secure, SameSite=Lax, path `/auth/callback`, ten
  minutes) holding the state, and the callback refuses a state that does not match it, with the
  "This sign-in is no longer valid" page that an unknown or expired state now gets too, where
  before it was a bare 401. Of two sign-ins begun at once in one browser, only the later one
  completes.
- An EndpointSlice whose `endpoints` is null, or holds null entries, loads as a slice with no
  endpoints instead of being dropped (#98). The API server sends `endpoints: null` for the slice of any
  Service with nothing behind it -- the read-replica Service CloudNativePG creates beside a
  one-instance cluster, a Deployment scaled to zero -- and the strict sequence type rejected it
  with a WARN (`invalid type: null, expected a sequence`) and a tick of
  `gapura_objects_rejected_total{kind="EndpointSlice"}` for an ordinary object. Routing does not
  change: a dropped slice and an empty one both leave a backend with no ready endpoints, answered
  with 503 `no ready endpoints`. The same rule `ports` got in #19.
- The chart can run the console in store mode (#97): `console.store.existingSecret` names a Secret
  holding `DATABASE_URL` (key `console.store.urlKey`, default `database-url`), and
  `console.store.bootstrap.existingSecret` one holding the first superuser's `username` and
  `password`. The URL is never a plain value, since it carries the database password. With a
  store the chart renders no users Secret, mounts no users file and passes no `--grant`, and it
  fails at render time when `console.grants` or `console.auth.local` is still set -- the same
  combinations gapura-control refuses at start, caught before a pod crash-loops on them. Moving
  an existing local-mode release over means emptying those values; its users are not imported,
  so the bootstrap superuser is the first account. Nothing changes for a release that does not
  set `console.store`.
- The console keeps its accounts in Postgres when it has one. With `DATABASE_URL` set, a local
  account is a row that signs in with an argon2id password, an OIDC account becomes a row at its
  first sign-in, and roles come from the role and group bindings there; new Users and Roles pages
  show them to superusers and to each workspace's admins, who see roles only in the workspaces
  they administer. `GAPURA_BOOTSTRAP_USERNAME` and `GAPURA_BOOTSTRAP_PASSWORD` create the first
  superuser in an empty store and are ignored once any account exists, an SSO one included, so set
  them before anyone signs in. `--local-users-file` and `--grant` are refused alongside
  `DATABASE_URL` rather than ignored. A deployment that already sets `DATABASE_URL` for the
  configuration endpoint moves its console into this mode on upgrade: sessions signed in before it
  end, and it will not start while it still passes `--local-users-file`, whose users are not
  imported. The chart sets it through `console.store` (below). In this mode Overview and Routes
  are for superusers until they learn about workspaces. `POST /auth/logout` signs out, in either
  mode.
- The chart installs the console's local users Secret again: `console.yaml` had no `---` between
  that Secret and the console's ServiceAccount, so the two parsed as one object, the
  ServiceAccount's keys won, and the Secret was never created -- helm and the API server only
  warned (`unknown field "stringData"`, `unknown field "type"`). A local-mode install without
  `console.auth.local.existingSecret` therefore had no users file, and changes to
  `console.auth.local.users` reached nothing. `hack/chart-render.sh` now fails on any rendered
  document that holds two objects. Upgrading over a cluster where that Secret was created by
  hand fails on Helm's ownership check: either point `console.auth.local.existingSecret` at it,
  or delete it and let the chart create it from the values.
- The console is drawn from shadcn-svelte components on Tailwind, and bundles its font (#90): the
  two screens and the shell say and do what they did, but from one set of components and tokens
  instead of CSS written per component, with one accent, a terracotta, spent on identity and
  selection. 0.2.0 ruled a web font out as hundreds of kilobytes inside a binary; Geist bundled is
  about 76 KB of woff2 across five subsets, of which a browser fetches only those it needs, and
  the console's assets inside `gapura-control` come to about 410 KB. What 0.2.0 was protecting
  still holds, and is now checked: the build fails if the page, its CSS or its JavaScript asks a
  third party for anything, and CI runs that check. The console now sets a `sidebar_state` cookie
  (path `/`, seven days) remembering whether the sidebar is collapsed, and Ctrl/Cmd+B toggles the
  sidebar in place of the browser's own shortcut; nothing on the server reads the cookie.
- The sign-in pages look like the console they lead to (#93): the local sign-in form, "Not signed in"
  and "Signed in — session not stored" now use shadcn's centred-card login layout with the
  console's mark, tokens and dark mode. They are still server-rendered with their CSS inline, so
  they keep working when `web/dist` is empty; nothing about the sign-in flow itself changed.

## 0.2.0 — unreleased (prepared 2026-09-24)

- A key a caller presents identifies it as a consumer (#87): the console issues an API key, the
  store keeps only its SHA-256, and the configuration carries that hash — never the key. A
  configuration is written to the data plane's disk cache and read by whoever can read that file,
  so a stolen cache must not yield a working credential; the hash is deterministic, so a presented
  key hashes to exactly the map key and no prefix index is needed. Keys ride the configuration
  rather than a lookup per request, which keeps the control plane off the data path — a round trip
  there would put it in front of every request and take every gateway down with it — at the cost
  that revocation waits for the next poll, the bound routes already accept. The consumer header is
  stripped from the inbound request unconditionally and only then set, so a route with no policy
  cannot forward whatever a caller claimed.
- Policies come from the store, starting with JWT (#86): a rule carries the policy the control
  plane serves with it, and the data plane refuses a request whose token does not verify.
  `gapura_policy_refused_total` carries a `policy` label — two policies refusing on one route were
  otherwise indistinguishable.
- A gateway can take its configuration from the control plane, and survive losing it (#84): a
  third source beside `--config-dir` and `--kubernetes` and exclusive with both, with the disk
  cache that makes a control plane outage cost new configuration instead of traffic. The cache is
  loaded before the first successful call, because a control plane that is down at startup would
  otherwise mean `/readyz` never passes, the pod never joins its Service, and a gateway holding a
  perfectly good configuration refuses to serve with it — readiness here means "I can route", not
  "I have spoken to the control plane". It is written after a swap and never before, atomically at
  0600 (it holds a private key for every certificate the gateway serves), and a damaged cache is
  logged and ignored rather than taking the gateway down harder than never having had one. Loading
  it does not touch `config_last_reload_timestamp_seconds`, which would turn every "has not
  reloaded recently" alert green on a gateway serving a week-old cache; `gapura_config_from_cache`
  says so instead. The endpoint's tests now run against a real Postgres in CI, and stop skipping
  when `CI` is set, so a typo in the variable name cannot report a green build that exercised
  nothing.
  The chart does not expose this mode yet: `--control-plane` and its token file are flags on the
  binary with no values entry behind them, so a Helm install still takes its configuration from
  the cluster exactly as it did in 0.1.0. Wiring the chart is the next release's work — this one
  ships the mechanism and the proof it works, not the way to turn it on from a chart.
- A configuration written by an older binary still loads (#83): `Config` had no `serde(default)`,
  so a cache missing any field failed the whole load — a path nothing exercises until an operator
  upgrades in production and the gateway comes back empty instead of serving what it had. The
  default is at the top level and deliberately nowhere below it: a missing field there sensibly
  means "none of those", while an `Endpoint` whose address defaults to the empty string is a
  silent hole where failing loudly is correct.
- One token layer in the console, and a dark mode that follows the system (#82): colour, radius
  and surface were hardcoded across six components, so there was no way to have a dark mode and no
  way to change a grey once. The chrome is deliberately almost colourless — on the Routes screen
  the badge tones *are* the data, so anything else putting colour on the page competes with the
  only colour that carries meaning, and the accent is spent on links and the active tab and
  nowhere else. No web font: a CDN font is a third-party request from a page showing cluster
  state, and a bundled one is hundreds of kilobytes inside a binary that ships to a cluster.
- The console's local mode actually starts (#80, #81): clap-required OIDC flags made the IdP-less
  mode impossible to express, and the chart's local Deployment passes none of them, so the binary
  exited on a usage error — CrashLoopBackOff on a fresh install. The flags are `Option` now and
  main validates the four of them only under `--auth-mode oidc`. Making them optional then exposed
  `Oidc::new` refusing the empty strings local mode passed it; local mode carries `Oidc::unused()`
  instead, whose issuer points at a reserved domain that answers nothing, so losing the guard that
  keeps it unreachable would be loud rather than silent. Both were found deploying to the live
  cluster.
- The console is IdP-less by default (#78): `--auth-mode local` (the chart's default) signs
  users in from a mounted users file -- `users: [{email, bcrypt, groups}]`, rendered by the
  chart into a Secret -- through a server-rendered form at /auth/login. No identity provider
  anywhere until `console.auth.mode: oidc` is set, exactly the ArgoCD shape; a local mode with
  zero users refuses to start. The form's CSRF is the OIDC flow's own single-use pending
  state; `return_to` rides the same validated path; wrong password and unknown email answer
  identically and cost the same bcrypt second, so the form cannot enumerate users; sessions,
  grants and the whole API surface are untouched.
- The quickstart workflow verifies the console image too (#74): the same anonymous manifest
  fetch RELEASING 5.3 documents, against the sha tag of the tag-push release under test. All
  three published packages now have the same standing tripwire; versions before the console
  image existed (0.1.0-rc.3) are skipped with a line, not failed.
- The console's scopes and its groups claim are now connected where an operator reads (#73):
  the chart's scopes comment names the scope each provider needs for the claim (dex: `email`
  under the email scope), and NOTES warns at install time when the console is enabled with no
  scopes -- the combination whose first sign-in sees an empty console with no error anywhere.
- A dispatch release publishes the version it was asked for (#72): the image tags gained a raw
  entry carrying the dispatched version, so `0.1.0-rc.N` exists on both images and the chart's
  appVersion default is a tag that can actually be pulled -- two installs in a row had met
  `ImagePullBackOff` otherwise. On a tag push the raw tag duplicates the semver one, which the
  manifest join applies idempotently.
- The console refuses to issue a session it knows the browser will drop (#60): a sign-in that
  completes over plain HTTP on a non-loopback origin now answers with a page saying the sign-in
  worked and the session could not be stored -- HTTPS or `localhost` -- instead of a redirect
  that loses the session one request later. Loopback origins keep working (browsers trust them
  with `Secure` cookies), and a proxy's `X-Forwarded-Proto`/`X-Forwarded-Host` are honoured.
- The console follows list pagination to the end (#48): a cluster with more HTTPRoutes than
  one API-server page used to render a silently short list — routes that exist and are served
  simply off the screen. `continue` tokens are followed (bounded, so a server that never stops
  paginating is an error, not a loop).
- Signing back in returns the reader to where they were (#61): the screen a 401 interrupted
  travels through the OIDC round trip in the login state and becomes the redirect target. The
  path is validated as strictly local when accepted and again when used — `//evil.example`,
  absolute schemes, and control characters fall back to the overview rather than redirecting.
- A state badge's explanation is in the document, not in a `title` (#62): announced to screen
  readers as part of the badge (visually hidden text, not an attribute), and shown visibly in
  the expanded attachment row — so a phone with no hover and a keyboard-only reader both get
  the sentence that explains the colour grouping. `check.mjs` fails if the detail ever moves
  back into an attribute.
- gapura-control housekeeping (#49): the served-rules lookup is an index instead of a scan of
  every rule per route; session expiry means `>=`; `session::Invalid` implements `Display`/`Error`
  so it propagates; the session key may be base64 (the shape secret managers hand out) and the
  key logic lives beside the sessions it signs; `AppState.session_key` is `Arc<[u8]>`;
  `--log-level` sets the tracing filter instead of compile time; `hmac`/`sha2`/`tower` come from
  the workspace; the crate is a library with a thin binary, so `pub` means something and
  integration tests can reach the modules. Left as-is deliberately: `ServedRule.cluster`, whose
  surfacing is a product decision about the API shape, not hygiene.
- The console can run on a cluster (#63): releases build and publish a second image,
  `ghcr.io/davidgrldo/gapura-control`, with the same per-arch push-by-digest join, provenance
  and SBOM as the data plane; the chart grows a `console` section -- its own Deployment,
  Service, ServiceAccount and read-only ClusterRole over HTTPRoutes -- off by default, because
  it needs an identity provider before it does anything. Two images stays the answer: the data
  plane faces the internet and does not carry browser assets. RELEASING 5.3 now counts three
  packages to make public.
- `helm upgrade --reuse-values` across chart versions no longer crashes on values sections the
  installed release never had (#24). Reuse-values replaces the new chart's defaults wholesale,
  so a section introduced after the installed version (like `tests` or `metrics`) arrives as an
  explicit null, and the templates' bare `.Values.section.field` access died on a nil pointer.
  Every multi-level access now uses the chart's parenthesized nil-safe form, reading a null
  section as off: the gated resource renders absent instead of materializing silently, which is
  the safe direction for an upgrade. Pinned by the `reuse-null` render case, which nulls both
  crashers and must equal the default render minus the smoke test.
- Schema-rejected objects are counted, not only logged: `gapura_objects_rejected_total{kind}`
  rises beside the existing WARN (#29). The failure class an operator could previously catch only
  by reading logs — a backend Service whose objects are dropped keeps resolving while the proxy
  has no upstream — is now coverable by one alert rule: the gateway is dropping objects it
  watches. The counter counts rejection events, so an object that stays invalid across updates
  keeps it rising.
- An EndpointSlice whose `ports` is null, or holds null entries, loads instead of being dropped.
  Both shapes are written by kube-proxy/kubelet in the ordinary course of events (#19), and the
  strict sequence type rejected the whole object — a Service whose only slice had that shape
  silently lost its endpoints from the routing table, with just a WARN to say why. Null now reads
  as no ports and null entries are skipped (they carry nothing to match on); the endpoints
  themselves were never the problem. A backend whose cluster ends up with no endpoints either
  way was, and is, answered with 503 `no ready endpoints` — a named case in the access log.
- An address per Gateway: `--gateway-address namespace/name=ip-or-host` (repeatable) publishes
  per-Gateway status addresses instead of one shared list, and the translator remaps the listener of a Gateway that carries such an override —
  the declaration that it is individually addressable — onto the next free bound port of its
  protocol whenever it would tie with another Gateway — the proxy
  only ever binds the `--listen-http`/`--listen-https` sockets, so a deployment that wants
  addressable Gateways binds a second port (chart value `extraListenHttp`) and points a Service
  at it. The allocation is deterministic, so the Service mapping is stable. Listeners whose
  requests precedence can already tell apart — disjoint or strictly-more-specific hostnames, or
  one route attached to both — keep sharing the port, and with a single bound port nothing
  changes at all. This is what the `HTTPRouteMultipleGateways` conformance test needed: the
  GATEWAY-HTTP profile now passes 37 of 37 core plus 1 of 1 extended, the chart's `gatewayAddresses`
  value carries the per-Gateway addresses, and `hack/conformance.sh` runs with an empty
  `EXPECTED_FAILURES` — any failure fails the run.
- `RequestRedirect` accepts the full statusCode enum the CRD defines: 301, 302 (the default),
  303, 307 and 308. The response was already status-plus-Location with nothing rewritten —
  method and body preservation on 307/308 is the client's obligation, and the server's duty is
  not to touch them, which this path never did — so widening the accepted set is the whole
  change. Codes outside the enum (306 and friends) still reject the route as `Unsupported`.
  Three extended features claimed (`HTTPRoute303/307/308RedirectStatusCode`): the extended
  section is now 4 of 4, core still 36 of 37.

- The release workflow can no longer publish a release whose notes say nothing. The check meant
  to catch that ran over the finished file, which by then already carried the `## Packages` list
  the same step writes, so both of its conditions were satisfied by its own output and it passed
  for every version -- including ones with no section in this file at all. It now reads the
  section before anything else is added and stops there when it is empty. A dispatch of the
  workflow also stops trying to create a release: it builds a branch and makes no tag, so there
  is nothing to hang one on, and the image and chart it publishes are the point of that path.
- `RequestMirror` fires a bounded, fire-and-forget copy of the request. Headers-only: the mirror
  never promises a body it does not send (content-length and transfer-encoding are stripped), and
  body tee-ing is a follow-up. The mirror also dials plaintext HTTP regardless of the cluster's
  TLS policy: a TLS-only shadow backend shows up as counted `error`s, a dual listener receives
  the copy unencrypted, and honoring `BackendTLSPolicy` for mirrors is the same follow-up. A global 1024 in-flight bound drops mirrors past it, counted as
  `overflow` on `gapura_mirror_requests_total{route, result}` (`sent|error|timeout|overflow`); each
  mirror is one 3s attempt with no retries, and the primary's access-log line gains a `mirrored`
  field. The mirror's backendRef resolves like any other — ReferenceGrant included — and a mirror
  that cannot resolve sets `ResolvedRefs=False` while the route keeps serving unmirrored. Claiming
  the extended `HTTPRouteRequestMirror` adds the one extended test that gates on it: the report now
  carries an extended section, 1 of 1 passing, core still 36 of 37.
- The access log can name the client again. `client_ip` was read straight off the connection, so
  anywhere an ingress, a mesh or a CDN sits in front, every line recorded that proxy and the
  visitor appeared nowhere -- and anything later keyed on the client address would have read the
  proxy too. `--trusted-proxy` takes a CIDR or a bare address and is repeatable (`trustedProxies`
  in the chart); with at least one set, a connection arriving from one of those networks has its
  `X-Forwarded-For` read from the right until an address no listed network vouches for, and that
  is the client. Anything a caller wrote into the header itself sits further left and is never
  reached, and a connection from outside those networks is taken at face value however it filled
  the header in. Nothing is listed by default, which is the old behaviour: the header ignored,
  the peer logged. What gapura sends upstream does not change.
- `path.type: RegularExpression` is matched, not rejected. Patterns compile once per config
  generation into a side map next to the round-robin cursors, match the raw request path, and
  rank below `Exact` and `PathPrefix` in the precedence chain, the pattern length breaking ties
  inside the type. A pattern that does not compile, or a `ReplacePrefixMatch` rewrite on a regex
  match, still rejects the route as `Unsupported`. `PathMatchRegularExpression` is now claimed in
  `GatewayClass.status.supportedFeatures` and passed to the suite; v1.6.2's standard channel has
  no core regex cases, so the conformance counts stand at 36 of 37.
- `helm test` on a release now proves it routes: the chart ships a throwaway Gateway, HTTPRoute
  and echo backend as `helm.sh/hook: test` resources, plus a curl pod that drives one request
  through the data plane and checks the answer. Nothing exists at install time; `helm test`
  creates it, waits, and cleans up after itself (gated by `tests.smoke.enabled`, on by default).
- New `quickstart` workflow: the README quickstart, verbatim, on a fresh kind cluster, with no
  ghcr credentials anywhere. Automates the anonymous check of RELEASING 5.3 and all of 5.5 —
  red while a package is private, the tripwire for every release after that.
- The release workflow now publishes a GitHub Release from the tag: the CHANGELOG section for
  the version as notes, the conformance report attached as an asset.
- The chart's NOTES now cover NodePort installs: they print the exact `curl`, NodePort included,
  because a Gateway's published address never carries a port and that is the trap every NodePort
  install hits.
- The controller now diagnoses absent or stale Gateway API CRDs out loud. A missing optional
  kind logs what stops working (a `loses` field: absent `BackendTLSPolicy` means TLS to
  backends is off), the aggregate warning names the expected channel (`v1.6.2`) and says the
  fix needs no restart, a missing required kind says the same at startup, and one info line
  summarizes every watched kind with its apiVersion. Verified live: CRD deleted at startup,
  pod warned and degraded; CRD reinstalled, the 60s recheck picked it up and rebuilt the watch
  list, traffic uninterrupted. Chart NOTES say which channel the build is made for.
- k3s gets a first-class seat: a `k3s` workflow runs `hack/k3s-deploy.sh` — build, import into a
  k3d cluster with traefik deliberately left on, NodePort install, one request through the
  gateway — on every PR and push to main. The README quickstart documents the stock-k3s case
  (traefik holds 80/443 through ServiceLB, so the default LoadBalancer Service hangs rather than
  fails) with the NodePort install for it.
- The chart can pin the image by digest (`image.digest`, taking precedence over the tag), for
  operators who want the release to run byte-for-byte what CI pushed; `externalTrafficPolicy`'s
  Local default now says what it costs on a multi-node cluster.
- Release images now carry `provenance: mode=max` and an SBOM per platform, and the digest-join
  is asserted to keep them: `hack/release-dry-run.sh` fails if the manifest list arrives without
  its attestations. A project with no edition to buy should not need one to verify what it runs.
- RELEASING gains section 8, the post-public listings (Gateway API implementations page,
  upstream report submission once the profile allows it, Artifact Hub, README badge), and 5.3
  now points at the quickstart workflow as the standing private-package detector.
- Named single-IP client headers (`--trusted-client-header`, chart value `trustedClientHeaders`),
  e.g. `CF-Connecting-IP` or `X-Real-IP`: believed only when the peer is a `--trusted-proxy`
  network and the request carries no `X-Forwarded-For` chain — the shape of a CDN tunnel that
  names the client nowhere else. A chain that names a client keeps its precedence.
- The access log can carry the query string. Off by default (`--access-log-query`, chart value
  `accessLog.query`): query strings carry tokens and secrets and an access log is written to be
  read. With it on, the line gains a `query` field naming the exact request — the `path` field
  never carries it — so a parameterized endpoint's log line is finally correlatable to the
  request that produced it.

## 0.1.0 — 2026-09-11

The first release, and the first time any of this installs without a checkout. What ships: the
Gateway API core objects — `Gateway`, `HTTPRoute` and `ReferenceGrant` — served by one binary that
watches the API server and translates them into a routing table, at 36 of 37 GATEWAY-HTTP core
conformance tests. TLS terminates from a `Secret` on the listener, and is re-established to
backends through `BackendTLSPolicy`. Observability is open formats only: Prometheus metrics on the
admin port next to `/healthz` and `/readyz`, one JSON access log line per request on stdout, and
W3C `traceparent` plus `X-Request-Id` propagated upstream, created when the client sent neither.
It is delivered as a `linux/amd64` and `linux/arm64` image and the Helm chart in
[charts/gapura](charts/gapura).

### Read this before upgrading

**1. HTTPRoutes that were shadowed before now serve traffic.**

Gapura used to pick a single winning listener per port and hostname, and every other Gateway's
routes on that port were unreachable. It now builds one match table per port, over every listener
on it, so all of those routes match. A Gateway and HTTPRoute that have been sitting dead in your
cluster will start answering requests the moment you upgrade.

Audit what is attached to your shared ports before upgrading:

```bash
kubectl get httproute -A -o custom-columns=\
NS:.metadata.namespace,NAME:.metadata.name,PARENTS:.spec.parentRefs[*].name,HOSTS:.spec.hostnames
```

**2. A data-plane port that cannot be bound is now fatal.**

Before, Pingora's bind failure was swallowed by the panic hook: the pod stayed Ready and served
nothing. Gapura now tries every `--listen-http`, `--listen-https` and `--admin` address before
starting, logs `cannot bind a listen address`, and exits 1. The pod goes into CrashLoopBackOff
instead of lying about its health. If a gateway that used to come up now crash-loops, read the
first log line: something else on the node already holds the port.

**3. The liveness probe moved to the data-plane port.**

It was an HTTP GET on `/healthz` on the admin port; it is now a TCP probe on the http port, so a
dead data-plane listener is visible from outside. The trade-off is that a hung admin thread is no
longer caught by liveness. Set `livenessPort: admin` to restore the old behaviour.

### Also in this release

- Gapura refuses to start when one address is repeated across `--listen-http`, `--listen-https`
  and `--admin`. Both services used to bind it (Pingora sets `SO_REUSEPORT`) and the kernel split
  connections between them, silently. The chart rejects a values file whose `ports.http`,
  `ports.https` and `ports.admin` are not all distinct.
- Gateway API GATEWAY-HTTP conformance is at 36 of 37 core tests; the report and the reason for the
  remaining failure are in [conformance/](conformance/).
- Access log gained two fields: `client_abort` (the downstream client went away mid-request, not an
  error on our side) and `upstream_duration_ms` (null when no peer was ever picked).
- New metric `gapura_discovery_missing{kind}`, 1 while an optional kind is not served by the API
  server.
- An optional CRD (BackendTLSPolicy) that is absent at startup is rechecked every 60 seconds, and
  the source rebuilds itself once the CRD appears and can be listed. Installing it no longer needs
  a pod restart.
- Example Prometheus alerts ship as a PrometheusRule with `metrics.prometheusRule.enabled=true`
  (needs the Prometheus Operator CRDs).
- Status writes go out concurrently, in batches, and a demoted leader stops patching immediately
  instead of finishing its batch.
