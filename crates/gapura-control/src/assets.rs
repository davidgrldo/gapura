//! Serves the built console (`web/dist`, baked into the binary by `rust-embed`) as the axum
//! fallback, and says so in words when nothing has been built yet.
//!
//! `resolve` is a pure function over a path string: it decides what a request *should* get
//! before anything here touches the embed or axum. That split is what keeps the tests below
//! honest — they assert on the decision directly, with no request or router involved.

use axum::body::Body;
use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

/// The console's built assets. On a fresh clone, and in every `cargo build` that never ran
/// `npm run build`, this folder holds only `web/dist/.gitkeep` — `rust-embed` still compiles
/// against it, and an embed with no `index.html` is a normal, expected state here rather
/// than a build failure. The Dockerfile's Node stage is what actually populates it.
#[derive(RustEmbed)]
#[folder = "../../web/dist/"]
struct Assets;

/// What a request path should be answered with, decided before anything is read off disk.
#[derive(Debug, PartialEq)]
pub enum Resolved {
    /// Serve the document — either `/` itself, or a client-side route the single-page app
    /// owns, which must still return `index.html` so a reload does not 404.
    Index,
    /// Serve this exact embedded path: a hashed bundle, a stylesheet, a font, an image.
    File(String),
    /// A path this server already answers for elsewhere (or claims to), which the fallback
    /// must refuse rather than paper over with the document.
    NotFound,
}

/// Whether `path` falls under a prefix the API or the auth flow owns. Checked here, not just
/// left to routing order, because the danger this guards against is specifically a path
/// *neither* of them has a route for — `/api/typo` — which is exactly the case that reaches
/// this fallback in the first place.
fn is_reserved(path: &str) -> bool {
    path == "api" || path == "auth" || path.starts_with("api/") || path.starts_with("auth/")
}

/// Decide what `path` (with or without a leading slash) resolves to. Total and pure: every
/// input lands in exactly one of the three cases, and none of them consult the filesystem —
/// that happens only once the caller already has this answer.
pub fn resolve(path: &str) -> Resolved {
    let path = path.trim_start_matches('/');
    if is_reserved(path) {
        return Resolved::NotFound;
    }
    // A dot in the final path segment marks a request for a specific built file — a hashed
    // JS/CSS bundle, a font, a favicon. Anything else names a client-side route the
    // single-page app owns, which must resolve to the document rather than a 404.
    let names_a_file = path
        .rsplit('/')
        .next()
        .is_some_and(|last| last.contains('.'));
    if names_a_file {
        Resolved::File(path.to_string())
    } else {
        Resolved::Index
    }
}

/// What `/` shows when `web/dist` has nothing but `.gitkeep` in it. Most people working in
/// this repository never open `web/`, and `cargo build` must never start needing Node — so
/// an unbuilt console says so in words on the page itself, rather than failing the Rust
/// build or serving a blank document nobody watching a browser could diagnose.
pub fn fallback_page() -> String {
    "<!doctype html>\n\
     <html lang=\"en\">\n\
     <head><meta charset=\"utf-8\"><title>gapura console</title></head>\n\
     <body style=\"font-family: system-ui, sans-serif; max-width: 40rem; margin: 4rem auto; \
     line-height: 1.5;\">\n\
     <h1>The console has not been built</h1>\n\
     <p>This binary has no <code>web/dist</code> to serve. Build it with:</p>\n\
     <pre>cd web &amp;&amp; npm install &amp;&amp; npm run build</pre>\n\
     <p>The gateway itself is unaffected: <code>/api</code> and <code>/auth</code> work \
     whether or not the console has been built.</p>\n\
     </body>\n\
     </html>\n"
        .to_string()
}

/// A response carrying `body` as `text/html; charset=utf-8` — the one content type this
/// module ever sets by hand, since both the fallback page and `index.html` are HTML and
/// every other served path gets its type from `mime_guess` instead.
fn html(body: impl Into<Body>) -> Response {
    Response::builder()
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(body.into())
        .expect("a static header name and a body are always a valid response")
}

fn serve_index() -> Response {
    match Assets::get("index.html") {
        Some(asset) => html(asset.data.into_owned()),
        None => html(fallback_page()),
    }
}

fn serve_file(path: &str) -> Response {
    match Assets::get(path) {
        Some(asset) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            Response::builder()
                .header(header::CONTENT_TYPE, mime.as_ref())
                .body(Body::from(asset.data.into_owned()))
                .expect("a static header name and a body are always a valid response")
        }
        // `resolve` decided this path names a file without ever checking the embed, so a
        // stale index.html referencing a bundle from a previous build, or any other path
        // merely shaped like a file, lands here. Only a real 404 says the file is missing —
        // falling back to the document would hand a browser HTML where it asked for
        // JavaScript, and the failure would show up as a script error instead of a clear one.
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// The axum fallback: whatever no explicit route matched. Mounted after `/api` and `/auth`,
/// which always win a match first, so this only ever runs for a path neither of them has a
/// route for — and `resolve` still refuses to answer for it if it starts with either prefix,
/// so a typo'd API path 404s instead of quietly getting a page of HTML back.
pub async fn fallback(uri: Uri) -> Response {
    match resolve(uri.path()) {
        Resolved::NotFound => StatusCode::NOT_FOUND.into_response(),
        Resolved::Index => serve_index(),
        Resolved::File(path) => serve_file(&path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_build_is_reported_rather_than_served_as_a_blank_page() {
        // Most people working in this repository never touch web/, and `cargo build` must not
        // start needing Node. An unbuilt console says so in words instead of failing the build
        // or serving an empty document nobody can diagnose.
        let page = fallback_page();
        assert!(
            page.contains("npm run build"),
            "it must say how to fix it: {page}"
        );
    }

    #[test]
    fn an_unknown_path_falls_back_to_the_document_so_client_routing_works() {
        // A single-page app owns its own routes. A reload on /routes must return index.html,
        // not a 404, or every deep link breaks.
        assert_eq!(resolve("routes"), Resolved::Index);
        assert_eq!(
            resolve("assets/app-abc123.js"),
            Resolved::File("assets/app-abc123.js".into())
        );
    }

    #[test]
    fn the_api_and_auth_prefixes_are_never_swallowed_by_the_fallback() {
        // Whatever the fallback does, it must not answer for routes the server owns, or a
        // mistyped API path returns a cheerful HTML page and the bug hides for a day.
        assert_eq!(resolve("api/routes"), Resolved::NotFound);
        assert_eq!(resolve("auth/login"), Resolved::NotFound);
    }
}
