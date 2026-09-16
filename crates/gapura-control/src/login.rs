//! Signing in, which is the whole reason this component exists.
//!
//! The console's users have no identity the cluster would recognise — no kubeconfig, no
//! ServiceAccount, nothing Kubernetes RBAC could authorise — so the organisation's identity
//! provider is the only thing that can say who they are. This module runs the authorization
//! code flow with PKCE and turns its answer into the signed cookie `session` defines.
//!
//! Nothing here is persisted. A login in flight lives in memory for a few minutes and a
//! session lives only in the browser's cookie jar, so a control-plane restart mid-login
//! means signing in again. That is deliberate rather than forgotten: this stage stores
//! nothing, and a login is cheap to repeat where a database to lose is not.

use crate::session::{self, Session};
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreAuthenticationFlow, CoreErrorResponseType,
    CoreGenderClaim, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
    CoreProviderMetadata, CoreRevocableToken, CoreRevocationErrorResponse,
    CoreTokenIntrospectionResponse, CoreTokenType,
};
use openidconnect::{
    AdditionalClaims, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, IdTokenFields, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, StandardErrorResponse,
    StandardTokenResponse, TokenResponse,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The cookie a session travels in. `api` reads it back out under the same name.
pub const COOKIE_NAME: &str = "gapura_session";

/// Where a browser lands once it is signed in. The console is one page; there is nothing
/// finer to return to yet.
const AFTER_LOGIN: &str = "/";

/// How long a browser has to come back from the identity provider: long enough for a
/// password and a second factor, short enough that abandoned logins do not pile up.
const PENDING_LIFETIME: Duration = Duration::from_secs(10 * 60);

/// A ceiling on logins in flight. `/auth/login` is unauthenticated of necessity — it is how
/// you stop being anonymous — so anyone at all can ask us to remember another entry, and
/// expiry on its own bounds that only at whatever rate a flood can sustain for ten minutes.
/// Past the ceiling the oldest entry goes, which spends abandoned logins before memory.
const MAX_PENDING: usize = 1024;

/// The identity provider is a separate system and may be slow, unreachable, or accepting
/// connections while answering nothing. Sign-in must fail rather than hold a task open.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// The ID token claims this crate does not know the names of.
///
/// Which claim carries a person's groups is configuration — Keycloak and Okta say `groups`,
/// Entra ID says `roles` — so it cannot be a field on a struct. Keeping the rest of the
/// token as it arrived is what lets `groups_from` be told at runtime where to look.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ExtraClaims {
    #[serde(flatten)]
    other: serde_json::Map<String, serde_json::Value>,
}

impl AdditionalClaims for ExtraClaims {}

type ExtraIdTokenFields = IdTokenFields<
    ExtraClaims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

type ExtraTokenResponse = StandardTokenResponse<ExtraIdTokenFields, CoreTokenType>;

/// `CoreClient` with `ExtraClaims` in place of `EmptyAdditionalClaims`, and the endpoint
/// states `from_provider_metadata` hands back.
type Client = openidconnect::Client<
    ExtraClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    ExtraTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

/// What this console was registered as with the identity provider, and what it asks for.
pub struct Oidc {
    issuer: IssuerUrl,
    client_id: ClientId,
    client_secret: ClientSecret,
    redirect: RedirectUrl,
    /// The ID token claim listing a person's groups, by name.
    pub groups_claim: String,
    scopes: Vec<Scope>,
    http: reqwest::Client,
}

impl Oidc {
    /// Parses the configuration, so a URL that was never going to work stops the process at
    /// startup rather than turning every sign-in into a five-hundred nobody can read.
    pub fn new(
        issuer: &str,
        client_id: &str,
        client_secret: &str,
        redirect_url: &str,
        groups_claim: &str,
        scopes: &[String],
    ) -> anyhow::Result<Self> {
        Ok(Self {
            issuer: IssuerUrl::new(issuer.to_string())?,
            client_id: ClientId::new(client_id.to_string()),
            client_secret: ClientSecret::new(client_secret.to_string()),
            redirect: RedirectUrl::new(redirect_url.to_string())?,
            groups_claim: groups_claim.to_string(),
            scopes: scopes.iter().map(|s| Scope::new(s.clone())).collect(),
            http: reqwest::Client::builder()
                // Following a redirect out of the discovery or token endpoint would let the
                // provider's answer point this client at anything it liked.
                .redirect(reqwest::redirect::Policy::none())
                .timeout(REQUEST_TIMEOUT)
                .connect_timeout(CONNECT_TIMEOUT)
                .build()?,
        })
    }

    /// A client built from the provider's discovery document.
    ///
    /// Discovery runs per sign-in rather than once at startup. It costs two requests on a
    /// path a person only takes when their session has run out, and in exchange a provider
    /// that rotates its signing keys is followed without a restart, rather than through a
    /// cache whose staleness nobody would notice until every login began failing. It also
    /// keeps an identity-provider outage from being something that stops this process from
    /// starting, which would take the console's already signed-in readers down with it.
    async fn client(&self) -> anyhow::Result<Client> {
        let metadata = CoreProviderMetadata::discover_async(self.issuer.clone(), &self.http)
            .await
            .map_err(|e| anyhow::anyhow!("reading the provider's discovery document: {e}"))?;
        Ok(Client::from_provider_metadata(
            metadata,
            self.client_id.clone(),
            Some(self.client_secret.clone()),
        )
        .set_redirect_uri(self.redirect.clone()))
    }
}

/// One login in flight: what must be remembered between sending a browser to the provider
/// and it coming back.
pub struct Pending {
    state: String,
    verifier: String,
    nonce: String,
    /// When this was minted, so a browser that never came back can be thrown away.
    started: Instant,
}

/// A callback presented a state this process never issued, or issued too long ago.
#[derive(Debug, PartialEq, Eq)]
pub struct UnknownState;

impl Pending {
    pub fn new(state: &str, verifier: &str, nonce: &str) -> Self {
        Self {
            state: state.to_string(),
            verifier: verifier.to_string(),
            nonce: nonce.to_string(),
            started: Instant::now(),
        }
    }

    /// Whether `presented` is the state this login was issued with.
    ///
    /// The comparison runs over every byte it has rather than stopping at the first
    /// difference. This is not the timing-critical check a signature is — the state is a
    /// single-use value, not a key — but a wrong value of the right length and a wrong
    /// value of the wrong length should fail identically, with no branch between them.
    pub fn check_state(&self, presented: &str) -> Result<(), UnknownState> {
        let expected = self.state.as_bytes();
        let presented = presented.as_bytes();
        let mut difference = u8::from(expected.len() != presented.len());
        for (a, b) in expected.iter().zip(presented) {
            difference |= a ^ b;
        }
        if difference == 0 {
            Ok(())
        } else {
            Err(UnknownState)
        }
    }

    fn is_expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.started) > PENDING_LIFETIME
    }
}

/// The logins this process has sent to the provider and not yet heard back about.
#[derive(Clone, Default)]
pub struct PendingLogins {
    // A blocking mutex rather than tokio's: nothing is awaited while it is held, and the
    // critical section is a hash lookup.
    by_state: Arc<Mutex<HashMap<String, Pending>>>,
}

impl PendingLogins {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Pending>> {
        // A panic with the lock held would leave the map poisoned; the logins in it are
        // worth nothing individually, so carrying on beats refusing every sign-in after.
        self.by_state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn remember(&self, pending: Pending) {
        let mut logins = self.lock();
        forget_expired_in(&mut logins, Instant::now());
        while logins.len() >= MAX_PENDING {
            let Some(oldest) = logins
                .iter()
                .min_by_key(|(_, p)| p.started)
                .map(|(state, _)| state.clone())
            else {
                break;
            };
            logins.remove(&oldest);
        }
        logins.insert(pending.state.clone(), pending);
    }

    /// The login this state belongs to, removed as it is handed over: the authorization
    /// code a callback carries may only be redeemed once, so a replay must find nothing.
    ///
    /// The map lookup narrows; `check_state` is what accepts. Keeping the decision in one
    /// tested place means rekeying this map could not quietly remove the check.
    pub fn take(&self, state: &str) -> Result<Pending, UnknownState> {
        let mut logins = self.lock();
        forget_expired_in(&mut logins, Instant::now());
        let pending = logins.remove(state).ok_or(UnknownState)?;
        pending.check_state(state)?;
        Ok(pending)
    }

    #[cfg(test)]
    fn forget_expired(&self, now: Instant) {
        forget_expired_in(&mut self.lock(), now);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.lock().len()
    }
}

fn forget_expired_in(logins: &mut HashMap<String, Pending>, now: Instant) {
    logins.retain(|_, pending| !pending.is_expired(now));
}

/// The groups an identity provider put in `claim`, or none at all.
///
/// Anything that is not a list yields nothing rather than an error. Someone who signed in
/// correctly and was granted nothing gets an empty console, which is a different thing from
/// a failed login and reads very differently when you are the one debugging it. Entries
/// that are not strings are skipped rather than failing the whole list, because dropping
/// one can only ever grant less.
pub fn groups_from(claims: &serde_json::Value, claim: &str) -> Vec<String> {
    claims
        .get(claim)
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// The `Set-Cookie` value carrying a freshly minted session.
///
/// `HttpOnly` puts it out of reach of any script on the page, `Secure` keeps it off
/// plaintext connections, and `SameSite=Lax` is what stops another origin's page from
/// making the browser call this cookie-authenticated JSON API on its behalf. All three are
/// a hard requirement, recorded in #49, and the tests assert them rather than trusting a
/// reading of this line.
pub fn set_cookie(value: &str, lifetime: Duration) -> String {
    format!(
        "{COOKIE_NAME}={value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={}",
        lifetime.as_secs()
    )
}

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// `GET /auth/login`: send the browser to the identity provider.
pub async fn begin(State(state): State<AppState>) -> Result<Response, StatusCode> {
    let client = state.oidc.client().await.map_err(|error| {
        tracing::warn!(%error, "cannot reach the identity provider to begin a sign-in");
        StatusCode::BAD_GATEWAY
    })?;
    // PKCE: the verifier never leaves this process, so an authorization code intercepted on
    // its way back through the browser cannot be redeemed by whoever intercepted it.
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let (url, csrf, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scopes(state.oidc.scopes.iter().cloned())
        .set_pkce_challenge(challenge)
        .url();
    state.pending.remember(Pending::new(
        csrf.secret(),
        verifier.secret(),
        nonce.secret(),
    ));
    Ok(Redirect::to(url.as_str()).into_response())
}

/// What the identity provider puts in the query string when it sends the browser back.
#[derive(Deserialize)]
pub struct Callback {
    code: Option<String>,
    state: Option<String>,
    /// Present instead of a code when the provider refused: `access_denied` and friends.
    error: Option<String>,
}

/// `GET /auth/callback`: turn the provider's answer into a session cookie.
pub async fn callback(
    State(state): State<AppState>,
    Query(query): Query<Callback>,
) -> Result<Response, StatusCode> {
    // Only the provider's error code is logged, never its description: the description is
    // free text from another system and the query string it arrived in also holds a code.
    if let Some(error) = &query.error {
        tracing::info!(provider_error = %error, "the identity provider refused a sign-in");
        return Err(StatusCode::UNAUTHORIZED);
    }
    let (Some(code), Some(returned_state)) = (query.code, query.state) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let pending = state.pending.take(&returned_state).map_err(|_| {
        tracing::warn!("a callback arrived with a state this process never issued");
        StatusCode::UNAUTHORIZED
    })?;

    let client = state.oidc.client().await.map_err(|error| {
        tracing::warn!(%error, "cannot reach the identity provider to finish a sign-in");
        StatusCode::BAD_GATEWAY
    })?;
    let tokens = client
        .exchange_code(AuthorizationCode::new(code))
        .map_err(|error| {
            tracing::error!(%error, "the provider's metadata has no token endpoint");
            StatusCode::BAD_GATEWAY
        })?
        .set_pkce_verifier(PkceCodeVerifier::new(pending.verifier))
        .request_async(&state.oidc.http)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "exchanging an authorization code failed");
            StatusCode::UNAUTHORIZED
        })?;

    // Verifying the ID token is what makes any of this worth anything: signature, issuer,
    // audience, and the nonce that ties this token to the redirect we sent this browser on.
    let id_token = tokens.id_token().ok_or_else(|| {
        tracing::warn!("the provider returned no ID token");
        StatusCode::UNAUTHORIZED
    })?;
    let claims = id_token
        .claims(&client.id_token_verifier(), &Nonce::new(pending.nonce))
        .map_err(|error| {
            tracing::warn!(%error, "an ID token did not verify");
            StatusCode::UNAUTHORIZED
        })?;

    let subject = claims.subject().to_string();
    let as_json = serde_json::to_value(claims).map_err(|error| {
        tracing::error!(%error, "verified claims would not serialise");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let groups = groups_from(&as_json, &state.oidc.groups_claim);
    // The subject and how many groups it came with: enough to answer "did they get in, and
    // did the console look empty because of the grants or because of the claim?" without
    // the code, the tokens, or the cookie ever reaching a log.
    tracing::info!(
        subject = %subject,
        groups = groups.len(),
        "signed in"
    );

    let cookie = set_cookie(
        &session::encode(
            &Session {
                subject,
                groups,
                expires_at: now_seconds() + state.session_lifetime.as_secs(),
            },
            &state.session_key,
        ),
        state.session_lifetime,
    );
    let mut response = Redirect::to(AFTER_LOGIN).into_response();
    let value = header::HeaderValue::from_str(&cookie).map_err(|_| {
        tracing::error!("a session cookie would not fit in a header");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    response.headers_mut().insert(header::SET_COOKIE, value);
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_callback_without_the_state_we_issued_is_refused() {
        // Cross-site request forgery on the callback: an attacker sends the victim to our
        // callback with the attacker's code. Only a state we minted and stored is acceptable.
        let pending = Pending::new("the-state", "the-verifier", "the-nonce");
        assert!(pending.check_state("a-different-state").is_err());
    }

    #[test]
    fn a_callback_with_the_state_we_issued_is_accepted() {
        let pending = Pending::new("the-state", "the-verifier", "the-nonce");
        assert!(pending.check_state("the-state").is_ok());
    }

    #[test]
    fn state_comparison_does_not_short_circuit_on_length() {
        // Not timing-critical the way a signature is, but a same-length wrong value and a
        // different-length wrong value must both simply fail.
        let pending = Pending::new("abcdef", "v", "n");
        assert!(pending.check_state("abcdeX").is_err());
        assert!(pending.check_state("abc").is_err());
        assert!(pending.check_state("").is_err());
    }

    #[test]
    fn groups_come_out_of_the_claim_we_were_told_to_read() {
        let claims = serde_json::json!({ "sub": "alice", "groups": ["team-a", "team-b"] });
        let got = groups_from(&claims, "groups");
        assert_eq!(got, vec!["team-a".to_string(), "team-b".to_string()]);
    }

    #[test]
    fn an_identity_with_no_groups_claim_gets_no_groups_rather_than_an_error() {
        // Someone signed in correctly and was granted nothing. That is an empty console,
        // not a failed login, and the difference matters when you are the one debugging it.
        let claims = serde_json::json!({ "sub": "alice" });
        assert!(groups_from(&claims, "groups").is_empty());
    }

    #[test]
    fn a_groups_claim_that_is_not_a_list_of_strings_yields_nothing() {
        let claims = serde_json::json!({ "sub": "alice", "groups": "team-a" });
        assert!(groups_from(&claims, "groups").is_empty());
    }

    #[test]
    fn the_session_cookie_carries_the_attributes_that_make_it_safe() {
        // #49. HttpOnly keeps it away from any script on the page, Secure keeps it off
        // plaintext, and without SameSite another origin's page can make the browser call
        // this JSON API with the cookie attached. Asserted rather than left to inspection.
        let cookie = set_cookie("a.b", Duration::from_secs(3600));
        assert!(cookie.contains("HttpOnly"), "got {cookie}");
        assert!(cookie.contains("Secure"), "got {cookie}");
        assert!(cookie.contains("SameSite=Lax"), "got {cookie}");
        assert!(cookie.starts_with("gapura_session=a.b;"), "got {cookie}");
        assert!(cookie.contains("Max-Age=3600"), "got {cookie}");
        assert!(cookie.contains("Path=/"), "got {cookie}");
    }

    #[test]
    fn a_login_nobody_ever_came_back_from_is_forgotten() {
        let logins = PendingLogins::default();
        logins.remember(Pending::new("the-state", "v", "n"));
        logins.forget_expired(Instant::now() + PENDING_LIFETIME + Duration::from_secs(1));
        assert!(logins.take("the-state").is_err());
    }

    #[test]
    fn a_state_is_accepted_once_and_not_a_second_time() {
        // The authorization code it carries may only be redeemed once, so a replay of the
        // same callback must find nothing rather than start another exchange.
        let logins = PendingLogins::default();
        logins.remember(Pending::new("the-state", "v", "n"));
        assert!(logins.take("the-state").is_ok());
        assert!(logins.take("the-state").is_err());
    }

    #[test]
    fn logins_in_flight_do_not_grow_without_bound() {
        // `/auth/login` is unauthenticated by necessity, so anyone can ask us to remember
        // another entry. Expiry alone bounds that only at whatever rate a flood sustains.
        let logins = PendingLogins::default();
        for i in 0..MAX_PENDING + 100 {
            logins.remember(Pending::new(&format!("state-{i}"), "v", "n"));
        }
        assert!(logins.len() <= MAX_PENDING, "got {}", logins.len());
    }
}

/// The one thing in this module that a unit test cannot reach on its own: the exchange with
/// a real identity provider. These drive the two handlers against a stand-in provider that
/// serves a discovery document and mints an ID token, so the parts that only show up when
/// the crate is in the loop — PKCE, the nonce, the verification, the cookie that comes out
/// the far end — are exercised rather than reasoned about.
#[cfg(test)]
mod against_a_stub_provider {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use chrono::Utc;
    use openidconnect::core::CoreHmacKey;
    use openidconnect::{Audience, IdToken, IdTokenClaims, StandardClaims, SubjectIdentifier};
    use tower::ServiceExt;

    const CLIENT_ID: &str = "console";
    // OpenID Connect lets a confidential client's ID token be signed with HMAC over the
    // client secret, which is what spares this test having to carry an RSA key around.
    const CLIENT_SECRET: &str = "the client secret, which is not in any log";
    const SESSION_KEY: &[u8] = b"a session key of at least thirty-two bytes";

    /// What the stub was asked and what it should answer.
    #[derive(Default)]
    struct Provider {
        /// The nonce the authorization request carried, which the ID token must echo.
        nonce: Mutex<Option<String>>,
        /// Whether the token request carried a PKCE verifier.
        saw_verifier: Mutex<bool>,
        groups: Mutex<serde_json::Value>,
    }

    fn id_token(issuer: &str, provider: &Provider) -> String {
        let nonce = provider.nonce.lock().unwrap().clone().unwrap_or_default();
        let mut other = serde_json::Map::new();
        other.insert(
            "groups".to_string(),
            provider.groups.lock().unwrap().clone(),
        );
        let claims = IdTokenClaims::<ExtraClaims, CoreGenderClaim>::new(
            IssuerUrl::new(issuer.to_string()).unwrap(),
            vec![Audience::new(CLIENT_ID.to_string())],
            Utc::now() + chrono::Duration::minutes(5),
            Utc::now(),
            StandardClaims::new(SubjectIdentifier::new("alice".to_string())),
            ExtraClaims { other },
        )
        .set_nonce(Some(Nonce::new(nonce)));
        IdToken::<
            ExtraClaims,
            CoreGenderClaim,
            CoreJweContentEncryptionAlgorithm,
            CoreJwsSigningAlgorithm,
        >::new(
            claims,
            &CoreHmacKey::new(CLIENT_SECRET.as_bytes().to_vec()),
            CoreJwsSigningAlgorithm::HmacSha256,
            None,
            None,
        )
        .unwrap()
        .to_string()
    }

    /// An identity provider with just enough of one to be discovered and believed.
    async fn stub(provider: Arc<Provider>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let document = serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/jwks"),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["HS256"],
        });
        let token_issuer = issuer.clone();
        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || {
                    let document = document.clone();
                    async move { Json(document) }
                }),
            )
            .route(
                "/jwks",
                get(|| async { Json(serde_json::json!({"keys": []})) }),
            )
            .route(
                "/token",
                post(move |body: String| {
                    let provider = provider.clone();
                    let issuer = token_issuer.clone();
                    async move {
                        *provider.saw_verifier.lock().unwrap() = body.contains("code_verifier=");
                        Json(serde_json::json!({
                            "access_token": "an access token",
                            "token_type": "Bearer",
                            "id_token": id_token(&issuer, &provider),
                        }))
                    }
                }),
            );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        issuer
    }

    fn state(issuer: &str) -> AppState {
        AppState {
            mapping: Arc::new([("team-a".to_string(), vec!["apps".to_string()])].into()),
            session_key: Arc::new(SESSION_KEY.to_vec()),
            // Signing in reads neither source, so both readers point at nothing: these
            // tests are about the way in, and one that needed a cluster to run would be
            // testing something else.
            source: Arc::new(crate::kube_source::Source::new(
                "http://127.0.0.1:1".to_string(),
            )),
            admin: Arc::new(crate::served::Admin::new("http://127.0.0.1:1")),
            controller_name: Arc::new("gapura.dev/controller".to_string()),
            oidc: Arc::new(
                Oidc::new(
                    issuer,
                    CLIENT_ID,
                    CLIENT_SECRET,
                    "http://console.example.test/auth/callback",
                    "groups",
                    &[],
                )
                .unwrap(),
            ),
            pending: PendingLogins::default(),
            session_lifetime: Duration::from_secs(3600),
        }
    }

    async fn get_from(state: &AppState, uri: &str) -> axum::response::Response {
        crate::api::router_with(state.clone())
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    fn location(response: &axum::response::Response) -> String {
        response.headers()["location"].to_str().unwrap().to_string()
    }

    /// Sends a browser to `/auth/login` and reads back the state and nonce the provider
    /// would have been handed, which is how the stub learns which nonce to echo.
    async fn begin_a_login(state: &AppState) -> (String, String) {
        let response = get_from(state, "/auth/login").await;
        assert_eq!(
            response.status(),
            StatusCode::SEE_OTHER,
            "expected a redirect"
        );
        let url = openidconnect::url::Url::parse(&location(&response)).unwrap();
        let query: HashMap<_, _> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(
            query.get("code_challenge_method").map(String::as_str),
            Some("S256"),
            "the authorization request must carry a PKCE challenge"
        );
        (query["state"].clone(), query["nonce"].clone())
    }

    #[tokio::test]
    async fn a_person_who_signs_in_comes_back_with_a_session_naming_their_groups() {
        let provider = Arc::new(Provider::default());
        *provider.groups.lock().unwrap() = serde_json::json!(["team-a", "team-b"]);
        let state = state(&stub(provider.clone()).await);

        let (csrf, nonce) = begin_a_login(&state).await;
        *provider.nonce.lock().unwrap() = Some(nonce);
        let response = get_from(&state, &format!("/auth/callback?code=a-code&state={csrf}")).await;

        assert_eq!(
            response.status(),
            StatusCode::SEE_OTHER,
            "expected a redirect"
        );
        assert_eq!(location(&response), AFTER_LOGIN);
        assert!(
            *provider.saw_verifier.lock().unwrap(),
            "the code exchange must prove PKCE by sending the verifier"
        );

        let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
        // #49, asserted on the header this handler actually emits rather than only on the
        // function that formats it.
        assert!(cookie.contains("HttpOnly"), "got {cookie}");
        assert!(cookie.contains("Secure"), "got {cookie}");
        assert!(cookie.contains("SameSite=Lax"), "got {cookie}");

        let value = cookie
            .strip_prefix("gapura_session=")
            .and_then(|rest| rest.split(';').next())
            .expect("a gapura_session cookie");
        let session = session::decode(value, SESSION_KEY, now_seconds()).expect("a valid session");
        assert_eq!(session.subject, "alice");
        assert_eq!(session.groups, ["team-a", "team-b"]);
        assert!(
            session.expires_at > now_seconds(),
            "a session that is already over"
        );
    }

    #[tokio::test]
    async fn a_callback_carrying_a_state_we_never_issued_never_reaches_the_provider() {
        // The forgery this whole dance exists to refuse: an attacker's code, delivered by
        // the victim's browser. It must be turned away before a token is ever exchanged.
        let provider = Arc::new(Provider::default());
        let state = state(&stub(provider.clone()).await);
        begin_a_login(&state).await;

        let response = get_from(&state, "/auth/callback?code=a-code&state=not-one-of-ours").await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(
            !*provider.saw_verifier.lock().unwrap(),
            "an unknown state must not reach the token endpoint at all"
        );
        assert!(response.headers().get(header::SET_COOKIE).is_none());
    }

    #[tokio::test]
    async fn an_id_token_whose_nonce_is_not_the_one_we_sent_is_refused() {
        // A token replayed from some other login verifies perfectly and is still not an
        // answer to the question this browser asked.
        let provider = Arc::new(Provider::default());
        *provider.groups.lock().unwrap() = serde_json::json!(["team-a"]);
        let state = state(&stub(provider.clone()).await);

        let (csrf, _) = begin_a_login(&state).await;
        *provider.nonce.lock().unwrap() = Some("a nonce from somewhere else".to_string());
        let response = get_from(&state, &format!("/auth/callback?code=a-code&state={csrf}")).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
    }

    #[tokio::test]
    async fn an_identity_the_provider_granted_no_groups_still_signs_in() {
        let provider = Arc::new(Provider::default());
        *provider.groups.lock().unwrap() = serde_json::json!([]);
        let state = state(&stub(provider.clone()).await);

        let (csrf, nonce) = begin_a_login(&state).await;
        *provider.nonce.lock().unwrap() = Some(nonce);
        let response = get_from(&state, &format!("/auth/callback?code=a-code&state={csrf}")).await;

        assert_eq!(
            response.status(),
            StatusCode::SEE_OTHER,
            "no groups is an empty console, not a failed login"
        );
    }

    #[tokio::test]
    async fn an_identity_provider_that_is_not_answering_is_a_bad_gateway_not_a_panic() {
        let state = state("http://127.0.0.1:1");
        assert_eq!(
            get_from(&state, "/auth/login").await.status(),
            StatusCode::BAD_GATEWAY
        );
    }

    #[tokio::test]
    async fn a_provider_that_refused_is_reported_without_a_session() {
        let state = state(&stub(Arc::new(Provider::default())).await);
        let response = get_from(&state, "/auth/callback?error=access_denied").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
    }

    #[tokio::test]
    async fn the_cookie_the_callback_sets_is_the_one_the_api_reads_back() {
        // The two halves are written in different modules and only agree by name; if they
        // ever stopped agreeing, every sign-in would appear to work and nothing would.
        let provider = Arc::new(Provider::default());
        *provider.groups.lock().unwrap() = serde_json::json!(["team-a"]);
        // The API answers OK only when it can also read the cluster, so this one needs an
        // API server to read. What is asserted is still about the cookie: a caller whose
        // cookie was not accepted is turned away before either reader is consulted.
        let mut state = state(&stub(provider.clone()).await);
        state.source = Arc::new(crate::kube_source::Source::new(
            crate::kube_source::tests::stub_api(include_str!("../tests/fixtures/httproutes.json"))
                .await,
        ));

        let (csrf, nonce) = begin_a_login(&state).await;
        *provider.nonce.lock().unwrap() = Some(nonce);
        let signed_in = get_from(&state, &format!("/auth/callback?code=a-code&state={csrf}")).await;
        let cookie = signed_in.headers()[header::SET_COOKIE].to_str().unwrap();

        let response = crate::api::router_with(state.clone())
            .oneshot(
                Request::builder()
                    .uri("/api/routes")
                    .header("cookie", cookie.split(';').next().unwrap())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "the API did not accept its own cookie"
        );
    }
}
