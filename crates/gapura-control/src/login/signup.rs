//! Signing up: a local account made by whoever reaches the console, while a superuser has opened
//! sign-up. It holds no role, so it reaches nothing until someone grants it one, and the console
//! shows it the Waiting page meanwhile.
//!
//! Served the way the sign-in form is: server-rendered, carrying the same signed, expiring form
//! state, and posted under `/auth/`, where `same_origin` refuses a post another site's page sent.
//! The page and the post read whether sign-up is open, and the store decides it again in the
//! transaction that creates the account, so an account is never made after closing has been
//! answered.
//!
//! Every post that reaches the form's checks counts against its address (`throttle::SignUps`),
//! whatever it ends in: five in ten minutes and twenty in a day. "That username is taken." tells
//! anyone which names exist; that limit is what bounds it.

use super::{auth_page, client_addr, issued_at_or_after, notice_page, session_response, Pending};
use super::{AuthMode, MAX_LOGIN_FORM};
use crate::grants::Refusal;
use crate::password::{Busy, MAX_USERNAME_CHARS, MIN_PASSWORD_CHARS};
use crate::state::AppState;
use crate::store::{Store, WriteError};
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use serde::Deserialize;

/// The most a note may hold, in characters.
pub const MAX_NOTE_CHARS: usize = 500;

// The form's largest honest post fits under the cap its route shares with the sign-in form: two
// passwords of `MAX_PASSWORD_BYTES` percent-encoded, a note of 4-byte characters percent-encoded,
// a name, and a state with no return path in it, well under 1 KiB.
const _: () = assert!(
    2 * 3 * crate::password::MAX_PASSWORD_BYTES + 12 * MAX_NOTE_CHARS + 2 * 1024 <= MAX_LOGIN_FORM
);

/// Whether sign-up is open, for the sign-in page's link: never in Kubernetes mode. A store that
/// cannot be read leaves the link out; a sign-in fails meanwhile too, and says why.
pub(super) async fn is_open(state: &AppState) -> bool {
    let Some(store) = &state.store else {
        return false;
    };
    match store.sign_up_open().await {
        Ok(open) => open,
        Err(error) => {
            tracing::warn!(
                error = format!("{error:#}"),
                "reading whether sign-up is open failed"
            );
            false
        }
    }
}

/// What the form posts. Every field defaults to empty, so a post missing one is refused in words
/// by the checks below rather than by the extractor.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct SignUp {
    state: String,
    username: String,
    password: String,
    password_again: String,
    note: String,
}

/// `GET /auth/signup`: the form while sign-up is open; otherwise what to do instead.
pub async fn page(State(state): State<AppState>) -> Response {
    let Some(store) = state.store.as_deref() else {
        return no_sign_up();
    };
    match store.sign_up_open().await {
        Ok(true) => form(&state, StatusCode::OK, None, "", ""),
        Ok(false) => closed(&state, StatusCode::OK),
        Err(error) => {
            tracing::warn!(
                error = format!("{error:#}"),
                "reading whether sign-up is open failed"
            );
            unavailable()
        }
    }
}

/// `POST /auth/signup`: create the account and sign it in, or say why not with the form again,
/// filled in with what was typed but the passwords.
pub async fn submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<axum::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    axum::Form(input): axum::Form<SignUp>,
) -> Response {
    let Some(store) = state.store.clone() else {
        return no_sign_up();
    };
    // Read here so that a closed console never shows the form, whatever was posted; the store
    // reads it again where it counts.
    match store.sign_up_open().await {
        Ok(true) => {}
        Ok(false) => return closed(&state, StatusCode::FORBIDDEN),
        Err(error) => {
            tracing::warn!(
                error = format!("{error:#}"),
                "reading whether sign-up is open failed"
            );
            return unavailable();
        }
    }
    // A form this console never issued, or issued too long ago, costs nothing and counts for
    // nothing: it is shown again, with a fresh state, to be checked and sent again.
    if Pending::resume(&state.session_key, &input.state).is_err() {
        return form(
            &state,
            StatusCode::BAD_REQUEST,
            Some("This sign-up form is no longer valid. Check it and send it again."),
            &input.username,
            &input.note,
        );
    }
    let addr = client_addr(&state, &headers, peer);
    let attempt = match state.sign_up.begin(addr) {
        Ok(attempt) => attempt,
        Err(wait) => {
            let mut response = form(
                &state,
                StatusCode::TOO_MANY_REQUESTS,
                Some(&crate::throttle::wait_message(wait)),
                &input.username,
                &input.note,
            );
            if let Ok(value) = HeaderValue::from_str(&wait.as_secs().max(1).to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            return response;
        }
    };
    let (response, counted) = create(&state, &store, &input).await;
    // Counted whatever the answer, but for one that said nothing about the form, such as the
    // store being down: dropping the attempt gives it back.
    if counted {
        attempt.failed();
    } else {
        drop(attempt);
    }
    response
}

/// The checks, the hash and the insert. The answer, and whether it counts against the address.
async fn create(state: &AppState, store: &Store, input: &SignUp) -> (Response, bool) {
    let refused = |status: StatusCode, message: &str| {
        (
            form(state, status, Some(message), &input.username, &input.note),
            true,
        )
    };
    if let Err(fragment) = crate::password::check_username(&input.username) {
        return refused(
            StatusCode::BAD_REQUEST,
            &crate::accounts::sentence(fragment),
        );
    }
    if input.password != input.password_again {
        return refused(StatusCode::BAD_REQUEST, "The two passwords do not match.");
    }
    if let Err(fragment) = crate::password::check_password(&input.username, &input.password) {
        return refused(
            StatusCode::BAD_REQUEST,
            &crate::accounts::sentence(fragment),
        );
    }
    let note = match note(&input.note) {
        Ok(note) => note,
        Err(message) => return refused(StatusCode::BAD_REQUEST, message),
    };
    let hash = match crate::password::hash_or_busy(input.password.clone()).await {
        Ok(Ok(hash)) => hash,
        Ok(Err(error)) => {
            tracing::error!(
                error = format!("{error:#}"),
                "hashing a password for a sign-up failed"
            );
            return (unavailable(), false);
        }
        Err(Busy) => return (busy(), false),
    };
    match store.sign_up(&input.username, &hash, note).await {
        Ok(signed_up) => {
            tracing::info!(user = %signed_up.id, "signed up");
            let response = session_response(
                state,
                signed_up.id.to_string(),
                Vec::new(),
                None,
                issued_at_or_after(signed_up.signed_in_at),
            );
            (response, true)
        }
        Err(WriteError::Refused(Refusal::Conflict(_))) => {
            refused(StatusCode::CONFLICT, "That username is taken.")
        }
        // Closed after the read above, before the insert.
        Err(WriteError::Refused(Refusal::Forbidden(_))) => {
            (closed(state, StatusCode::FORBIDDEN), true)
        }
        Err(WriteError::Refused(other)) => refused(other.status(), other.sentence()),
        Err(WriteError::Field(error)) => refused(StatusCode::BAD_REQUEST, &error.sentence),
        Err(WriteError::Store(error)) => {
            tracing::warn!(
                error = format!("{error:#}"),
                sqlstate = crate::store::sqlstate(&error).map(|c| c.code()),
                "creating a signed-up account failed"
            );
            (unavailable(), false)
        }
    }
}

/// The note as it is kept: trimmed, and none when nothing is left. Plain text: line breaks and
/// tabs, which a text box holds, but no other control character.
fn note(raw: &str) -> Result<Option<&str>, &'static str> {
    let note = raw.trim();
    if note.chars().count() > MAX_NOTE_CHARS {
        return Err("A note has at most 500 characters.");
    }
    if note
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err("A note can hold only plain text.");
    }
    Ok((!note.is_empty()).then_some(note))
}

/// `text` made safe inside an element and inside a quoted attribute.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// A page in the sign-in pages' style, never cached.
fn html(status: StatusCode, title: &str, content: &str) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(axum::body::Body::from(auth_page(title, content)))
        .expect("a page")
}

/// The form, with a fresh state, `message` above it when the last post was refused, and the
/// username and note that post carried. Every value from the post is escaped, the message too:
/// a refusal of a username quotes the character it refused.
fn form(
    state: &AppState,
    status: StatusCode,
    message: Option<&str>,
    username: &str,
    note: &str,
) -> Response {
    let alert = message
        .map(|m| format!(r#"<p class="alert" role="alert">{}</p>"#, escape(m)))
        .unwrap_or_default();
    let form_state = Pending::begin(&state.session_key, None).state;
    let (username, note) = (escape(username), escape(note));
    html(
        status,
        "Create an account",
        &format!(
            r#"<div class="card"><div class="card-header">
<h1 class="card-title">Create an account</h1>
<p class="card-description">It reaches nothing until someone grants it a role.</p>
</div><div class="card-content">
<form class="form" method="post" action="/auth/signup">{alert}
<input type="hidden" name="state" value="{form_state}">
<div class="field"><label for="username">Username</label>
<input id="username" type="text" name="username" value="{username}" autocomplete="username" maxlength="{MAX_USERNAME_CHARS}" required autofocus>
<p class="hint">Letters, digits and . _ ~ -, starting with a letter or a digit.</p></div>
<div class="field"><label for="password">Password</label>
<input id="password" type="password" name="password" autocomplete="new-password" minlength="{MIN_PASSWORD_CHARS}" required>
<p class="hint">At least {MIN_PASSWORD_CHARS} characters.</p></div>
<div class="field"><label for="password_again">Password again</label>
<input id="password_again" type="password" name="password_again" autocomplete="new-password" minlength="{MIN_PASSWORD_CHARS}" required></div>
<div class="field"><label for="note">Note (optional)</label>
<textarea id="note" name="note" rows="3" maxlength="{MAX_NOTE_CHARS}">{note}</textarea>
<p class="hint">Who you are and what you need. Only the people who grant access see it.</p></div>
<button class="button" type="submit">Create account</button>
</form>
<p class="footer">Already have an account? <a class="link" href="/auth/login">Sign in</a></p>
</div></div>"#
        ),
    )
}

/// What sign-up says while it is closed, the page and a post alike: the ways in that remain.
fn closed(state: &AppState, status: StatusCode) -> Response {
    let sso = if state.auth_mode == AuthMode::Oidc {
        r#"<p>Or sign in through your organisation's identity provider: an account is made for
you the first time you do.</p>"#
    } else {
        ""
    };
    let sso_button = if state.auth_mode == AuthMode::Oidc {
        r#"<a class="button" href="/auth/login?sso=1">Sign in with SSO</a>"#
    } else {
        ""
    };
    html(
        status,
        "Sign-up closed",
        &format!(
            r#"<div class="card"><div class="card-header">
<h1 class="card-title">Sign-up is closed</h1>
<p class="card-description">This console is not taking new accounts.</p>
</div><div class="card-content form"><div class="prose">
<p>Ask a superuser of this console to create an account for you.</p>{sso}
</div>{sso_button}
<a class="button" href="/auth/login">Back to sign-in</a>
</div></div>"#
        ),
    )
}

/// Kubernetes mode: no store, so no accounts to sign up for.
fn no_sign_up() -> Response {
    notice_page(
        StatusCode::NOT_FOUND,
        "No sign-up",
        "There is no sign-up here",
        "This console runs without a database, so it keeps no accounts to sign up for. Ask \
         whoever runs it for access.",
    )
}

/// The store could not be read or written: not the form's fault, and not counted.
fn unavailable() -> Response {
    notice_page(
        StatusCode::SERVICE_UNAVAILABLE,
        "Sign-up unavailable",
        "Sign-up is unavailable right now",
        "The console cannot reach its database. Try again in a moment.",
    )
}

/// Too many passwords are already waiting to be checked or hashed: see `login::busy_page`.
fn busy() -> Response {
    let mut response = notice_page(
        StatusCode::SERVICE_UNAVAILABLE,
        "Sign-up busy",
        "Sign-up is busy right now",
        "Too many passwords are being checked at once. Try again in a moment.",
    );
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_note_is_trimmed_bounded_and_plain() {
        assert_eq!(note("  \n "), Ok(None));
        assert_eq!(
            note(" platform team,\nneed payments "),
            Ok(Some("platform team,\nneed payments"))
        );
        assert_eq!(
            note(&"é".repeat(MAX_NOTE_CHARS)).map(|n| n.is_some()),
            Ok(true)
        );
        assert!(note(&"a".repeat(MAX_NOTE_CHARS + 1)).is_err());
        assert!(note("a\u{0}b").is_err());
        assert!(note("a\u{1b}[31mb").is_err());
    }

    #[test]
    fn what_is_echoed_cannot_end_its_element_or_attribute() {
        assert_eq!(
            escape(r#"</textarea><script>"x"&'y'"#),
            "&lt;/textarea&gt;&lt;script&gt;&quot;x&quot;&amp;&#39;y&#39;"
        );
    }
}
