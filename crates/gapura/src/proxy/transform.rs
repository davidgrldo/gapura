//! What a request_transformer and a response_transformer do: edit a head's headers
//! ([`edit_headers`]) and a request's query string ([`edit_query`]), in Kong's order -- remove,
//! then rename, then replace, then add, then append. The steps that call these, and where they
//! run, are `plugin`'s.

use std::borrow::Cow;

use gapura_core::config::HeaderEdits;

use super::HeaderTarget;

/// Apply `edits` to `target`'s headers, a name matched without regard to case as the header
/// map matches it. A rename moves every value as it is, bytes a `&str` cannot hold included, and
/// the new name keeps none it had before: Kong's rename sets the new name, so an operator moving
/// a header onto one the client also sent gets the moved value and not both.
///
/// No write here can fail, and none is reported: `Chain::compile` refuses a rule whose edits
/// fail [`writable`], so every name and value left is one the header map takes. An error carried
/// out of here instead would be one every caller had to answer for a write that cannot happen.
pub(super) fn edit_headers(target: &mut impl HeaderTarget, edits: &HeaderEdits) {
    for name in &edits.remove {
        target.del(name);
    }
    for (from, to) in &edits.rename {
        let values = target.get_all(from);
        if values.is_empty() {
            continue;
        }
        // Both go before the values are written back, so a rename onto the same name, in another
        // case, keeps its values rather than removing them after writing them.
        target.del(from);
        target.del(to);
        for value in values {
            let _ = target.append(to, value);
        }
    }
    for (name, value) in &edits.replace {
        if !target.get_all(name).is_empty() {
            let _ = target.set(name, value);
        }
    }
    for (name, value) in &edits.add {
        if target.get_all(name).is_empty() {
            let _ = target.set(name, value);
        }
    }
    for (name, value) in &edits.append {
        let _ = target.add(name, value);
    }
}

/// Whether every name `edits` touches is a header name and every value it writes a header
/// value, as the header map reads them: what lets [`edit_headers`] make every write without an
/// error to answer. The control plane refuses anything else before it is stored; this is the
/// data plane's own check, for a configuration it did not validate.
pub(super) fn writable(edits: &HeaderEdits) -> bool {
    let name = |n: &String| http::HeaderName::from_bytes(n.as_bytes()).is_ok();
    let value = |v: &String| http::HeaderValue::from_str(v).is_ok();
    edits.remove.iter().all(name)
        && edits.rename.iter().all(|(from, to)| name(from) && name(to))
        && [&edits.replace, &edits.add, &edits.append]
            .into_iter()
            .flatten()
            .all(|(n, v)| name(n) && value(v))
}

/// Apply `edits` to `uri`'s query string, and the URI to send instead, with the same path;
/// `None` when nothing changed, so a request the edits do not touch goes upstream as it came.
///
/// A parameter's name is matched exactly once it is decoded: `a%62=1` is named `ab`, and `A` is
/// not `a`. An escape that is not one is left as it is, so `%zz` is named `%zz`. What an edit
/// writes is percent-encoded as a form encodes it, except that a space is `%20` and not `+`
/// (`a b&c` is `a%20b%26c`), as Kong writes it: only a form decoder reads `+` as a space, and an
/// upstream that does not read its query as a form would take it for a plus sign. A renamed
/// parameter keeps its value as it was written, and every parameter already under the new name
/// goes, as Kong's rename sets the new name rather than adding to it. Every parameter no edit
/// touches keeps the bytes the client sent, and its place. Decoding the whole query and encoding
/// it again would rewrite parameters the policy never named -- `%20` would become `+`, and a
/// value that is not UTF-8 would be lost to U+FFFD. A bare `?` is a query with no parameters, so
/// an add to `/p?` gives `/p?v=2`, not `/p?&v=2`.
///
/// An edit that changes the query sends the path as the URI holds it. A client's path whose
/// bytes are not UTF-8 is kept beside the URI as it came, and sent so while nothing replaces the
/// URI; once a query edit does, the path goes as the URI parsed it, each such byte replaced by
/// U+FFFD. Normalisation and a rewrite replace the URI, and lose those bytes, alike.
pub(super) fn edit_query(uri: &http::Uri, edits: &HeaderEdits) -> Option<http::Uri> {
    if edits.is_empty() {
        return None;
    }
    let query = uri.query().unwrap_or_default();
    // Every piece, empty ones too, so that joining them again gives back the query unedited; but
    // none for a bare `?`, whose one empty piece would put an `&` before the first one added.
    let mut params: Vec<Param> = match uri.query() {
        None | Some("") => Vec::new(),
        Some(q) => q.split('&').map(Param::read).collect(),
    };
    params.retain(|p| !edits.remove.iter().any(|name| p.name == name.as_str()));
    for (from, to) in &edits.rename {
        if !params.iter().any(|p| p.name == from.as_str()) {
            continue;
        }
        // The old name's pieces are taken out first, so a rename onto the same decoded name
        // moves them rather than dropping them with what the new name already had.
        let (moved, mut kept): (Vec<Param>, Vec<Param>) =
            params.into_iter().partition(|p| p.name == from.as_str());
        kept.retain(|p| p.name != to.as_str());
        params = kept;
        params.extend(moved.into_iter().map(|p| p.renamed(to)));
    }
    for (name, value) in &edits.replace {
        // Where the first value was: none of those removed comes before it.
        if let Some(at) = params.iter().position(|p| p.name == name.as_str()) {
            params.retain(|p| p.name != name.as_str());
            params.insert(at, Param::new(name, value));
        }
    }
    for (name, value) in &edits.add {
        if !params.iter().any(|p| p.name == name.as_str()) {
            params.push(Param::new(name, value));
        }
    }
    for (name, value) in &edits.append {
        params.push(Param::new(name, value));
    }

    let edited = params
        .iter()
        .map(|p| p.raw.as_ref())
        .collect::<Vec<&str>>()
        .join("&");
    if edited == query {
        return None;
    }
    let target = match edited.as_str() {
        "" => uri.path().to_string(),
        q => format!("{}?{q}", uri.path()),
    };
    let rebuilt = target
        .parse::<http::uri::PathAndQuery>()
        .map_err(http::Error::from)
        .and_then(|path_and_query| {
            let mut parts = uri.clone().into_parts();
            parts.path_and_query = Some(path_and_query);
            Ok(http::Uri::from_parts(parts)?)
        });
    match rebuilt {
        Ok(uri) => Some(uri),
        // Cannot happen with today's inputs: the path is the URI's own, and every piece of the
        // query is one the URI already held or one encoded here, which writes nothing a query
        // cannot hold. Said aloud all the same, since the request then goes upstream without
        // every edit the policy asked for -- a parameter it meant to remove among them.
        Err(e) => {
            tracing::warn!(target, error = %e, "the edited query is not a valid URI, sending the request without the query edits");
            None
        }
    }
}

/// One `name=value` piece of a query string: its name decoded, which is what an edit matches,
/// and the piece as it goes upstream.
struct Param<'a> {
    name: Cow<'a, str>,
    raw: Cow<'a, str>,
}

impl<'a> Param<'a> {
    /// A piece as the client wrote it, kept so.
    fn read(raw: &'a str) -> Self {
        let name = raw.split_once('=').map_or(raw, |(name, _)| name);
        // `parse` decodes `+` and `%XX`; it yields nothing for an empty name.
        let name = form_urlencoded::parse(name.as_bytes())
            .next()
            .map_or(Cow::Borrowed(""), |(name, _)| name);
        Param {
            name,
            raw: Cow::Borrowed(raw),
        }
    }

    /// A piece an edit writes, encoded as a form encodes it but for a space, which is `%20`.
    /// Every `+` the serializer writes is a space: a `+` in the text is written `%2B`.
    fn new(name: &'a str, value: &str) -> Self {
        let raw = form_urlencoded::Serializer::new(String::new())
            .append_pair(name, value)
            .finish()
            .replace('+', "%20");
        Param {
            name: Cow::Borrowed(name),
            raw: Cow::Owned(raw),
        }
    }

    /// This piece under the name `to`, encoded as [`Param::new`] encodes it, its value as it was
    /// written.
    fn renamed(self, to: &'a str) -> Self {
        let name = form_urlencoded::byte_serialize(to.as_bytes())
            .collect::<String>()
            .replace('+', "%20");
        let raw = match self.raw.split_once('=') {
            Some((_, value)) => format!("{name}={value}"),
            None => name,
        };
        Param {
            name: Cow::Borrowed(to),
            raw: Cow::Owned(raw),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingora::http::RequestHeader;

    fn pair(name: &str, value: &str) -> (String, String) {
        (name.to_string(), value.to_string())
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn values(req: &RequestHeader, name: &str) -> Vec<String> {
        req.headers
            .get_all(name)
            .iter()
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
            .collect()
    }

    fn with(headers: &[(&str, &str)]) -> RequestHeader {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        for (name, value) in headers {
            req.append_header(name.to_string(), *value).unwrap();
        }
        req
    }

    /// Kong's order over one header named in all five lists: the remove takes it, so the rename
    /// and the replace find nothing, the add sets it afresh and the append adds beside that.
    /// The order the lists are written in plays no part.
    #[test]
    fn edits_run_remove_rename_replace_add_append() {
        let mut req = with(&[("x-h", "1")]);
        let edits = HeaderEdits {
            append: vec![pair("x-h", "b")],
            add: vec![pair("x-h", "a")],
            replace: vec![pair("x-h", "r")],
            rename: vec![pair("x-h", "x-r")],
            remove: names(&["x-h"]),
        };
        edit_headers(&mut req, &edits);
        assert_eq!(values(&req, "x-h"), ["a", "b"]);
        assert!(values(&req, "x-r").is_empty());

        // Without the remove the rename moves it, the replace rewrites it under its new name and
        // the add finds it there already.
        let mut req = with(&[("x-h", "1")]);
        let edits = HeaderEdits {
            rename: vec![pair("x-h", "x-r")],
            replace: vec![pair("x-r", "2")],
            add: vec![pair("x-r", "3")],
            ..HeaderEdits::default()
        };
        edit_headers(&mut req, &edits);
        assert!(values(&req, "x-h").is_empty());
        assert_eq!(values(&req, "x-r"), ["2"]);
    }

    /// Every value moves, in order, and bytes that are not UTF-8 move as they are. Nothing happens
    /// for a name that is not there.
    #[test]
    fn a_rename_moves_every_value() {
        let mut req = with(&[("x-old", "a"), ("x-old", "b")]);
        req.append_header("x-old", http::HeaderValue::from_bytes(b"caf\xe9").unwrap())
            .unwrap();
        let edits = HeaderEdits {
            rename: vec![pair("X-Old", "x-new"), pair("x-absent", "x-other")],
            ..HeaderEdits::default()
        };
        edit_headers(&mut req, &edits);
        assert!(req.headers.get("x-old").is_none());
        let moved: Vec<&[u8]> = req
            .headers
            .get_all("x-new")
            .iter()
            .map(|v| v.as_bytes())
            .collect();
        assert_eq!(moved, [&b"a"[..], b"b", b"caf\xe9"]);
        assert!(req.headers.get("x-other").is_none());
    }

    /// A rename onto a name the head already has replaces what it had, as Kong's sets the new
    /// name: the client's own `x-new` does not reach the upstream beside the moved one. A name the
    /// old one is not there for keeps its values; a rename onto the same name in another case
    /// keeps its values too.
    #[test]
    fn a_renamed_header_replaces_what_the_new_name_had() {
        let mut req = with(&[
            ("x-new", "client"),
            ("x-old", "a"),
            ("x-new", "client-2"),
            ("x-old", "b"),
            ("x-kept", "k"),
            ("x-same", "s"),
        ]);
        let edits = HeaderEdits {
            rename: vec![
                pair("x-old", "x-new"),
                pair("x-absent", "x-kept"),
                pair("x-same", "X-Same"),
            ],
            ..HeaderEdits::default()
        };
        edit_headers(&mut req, &edits);
        assert!(values(&req, "x-old").is_empty());
        assert_eq!(values(&req, "x-new"), ["a", "b"]);
        assert_eq!(values(&req, "x-kept"), ["k"]);
        assert_eq!(values(&req, "x-same"), ["s"]);
    }

    /// A replace only rewrites a header that is there, an add only sets one that is not, and an
    /// append keeps whatever was there.
    #[test]
    fn replace_needs_the_header_add_needs_it_absent_and_append_keeps_it() {
        let mut req = with(&[("x-present", "1"), ("x-present", "2"), ("x-tag", "client")]);
        let edits = HeaderEdits {
            replace: vec![pair("x-present", "r"), pair("x-absent", "r")],
            add: vec![pair("x-present", "a"), pair("x-new", "a")],
            append: vec![pair("x-tag", "gw")],
            ..HeaderEdits::default()
        };
        edit_headers(&mut req, &edits);
        assert_eq!(values(&req, "x-present"), ["r"]);
        assert!(values(&req, "x-absent").is_empty());
        assert_eq!(values(&req, "x-new"), ["a"]);
        assert_eq!(values(&req, "x-tag"), ["client", "gw"]);
    }

    #[test]
    fn only_header_names_and_values_are_writable() {
        let ok = HeaderEdits {
            remove: names(&["x-a"]),
            add: vec![pair("x-b", "visible ascii\tand tab")],
            ..HeaderEdits::default()
        };
        assert!(writable(&ok));
        for bad in [
            HeaderEdits {
                remove: names(&["x a"]),
                ..HeaderEdits::default()
            },
            HeaderEdits {
                rename: vec![pair("x-a", "x:b")],
                ..HeaderEdits::default()
            },
            HeaderEdits {
                append: vec![pair("x-a", "one\r\nx-injected: 1")],
                ..HeaderEdits::default()
            },
        ] {
            assert!(!writable(&bad), "{bad:?}");
        }
    }

    fn query(uri: &str, edits: &HeaderEdits) -> Option<String> {
        edit_query(&uri.parse().unwrap(), edits).map(|u| u.to_string())
    }

    /// What an edit writes is encoded as a form encodes it, but with a space as `%20`, and a `+`
    /// it writes stays a plus sign; the query appears when there was none and goes when nothing
    /// is left of it.
    #[test]
    fn a_written_parameter_is_percent_encoded() {
        let add = HeaderEdits {
            add: vec![pair("q", "a b&c"), pair("my key", "1+1")],
            ..HeaderEdits::default()
        };
        assert_eq!(
            query("/p?keep=1", &add).as_deref(),
            Some("/p?keep=1&q=a%20b%26c&my%20key=1%2B1")
        );
        assert_eq!(
            query("/p", &add).as_deref(),
            Some("/p?q=a%20b%26c&my%20key=1%2B1")
        );
        let remove = HeaderEdits {
            remove: names(&["secret"]),
            ..HeaderEdits::default()
        };
        assert_eq!(query("/p?secret=s", &remove).as_deref(), Some("/p"));
    }

    /// A bare `?` has no parameters, so the first one added is the first in the query, with no
    /// `&` before it; edits that match nothing there leave it as it came.
    #[test]
    fn a_bare_question_mark_is_no_parameters() {
        let add = HeaderEdits {
            add: vec![pair("v", "2")],
            ..HeaderEdits::default()
        };
        assert_eq!(query("/p?", &add).as_deref(), Some("/p?v=2"));
        let append = HeaderEdits {
            append: vec![pair("v", "2"), pair("v", "3")],
            ..HeaderEdits::default()
        };
        assert_eq!(query("/p?", &append).as_deref(), Some("/p?v=2&v=3"));
        let remove = HeaderEdits {
            remove: names(&["v"]),
            ..HeaderEdits::default()
        };
        assert_eq!(query("/p?", &remove), None);
    }

    /// A name is matched exactly once decoded: names that differ only in case are two names, and
    /// one whose escape is not one, `%zz`, is left as it was written and matched so -- the same
    /// name as `%25zz`, which decodes to it.
    #[test]
    fn names_are_matched_exactly_once_decoded() {
        let edits = HeaderEdits {
            remove: names(&["a"]),
            ..HeaderEdits::default()
        };
        assert_eq!(query("/p?A=1&a=2&a=3", &edits).as_deref(), Some("/p?A=1"));

        let edits = HeaderEdits {
            remove: names(&["%zz"]),
            ..HeaderEdits::default()
        };
        assert_eq!(
            query("/p?%zz=1&zz=2&%25zz=3&k=4", &edits).as_deref(),
            Some("/p?zz=2&k=4")
        );
        let edits = HeaderEdits {
            rename: vec![pair("%zz", "b")],
            ..HeaderEdits::default()
        };
        assert_eq!(query("/p?%zz=1&k=2", &edits).as_deref(), Some("/p?k=2&b=1"));
    }

    /// Removing a parameter leaves the others in order and as they were written, and a name is
    /// matched once decoded.
    #[test]
    fn a_removed_parameter_leaves_the_rest_as_sent() {
        let edits = HeaderEdits {
            remove: names(&["secret", "ab"]),
            add: vec![pair("v", "2")],
            ..HeaderEdits::default()
        };
        assert_eq!(
            query("/p?secret=s&keep=1", &edits).as_deref(),
            Some("/p?keep=1&v=2")
        );
        assert_eq!(
            query("/p?x=%20%7e&secret=s&a%62=1&q=caf%E9&secret=t&&b+c", &edits).as_deref(),
            Some("/p?x=%20%7e&q=caf%E9&&b+c&v=2")
        );
    }

    /// A rename moves every value to the end under the new name, each as it was written; a
    /// replace takes the place of the first value and drops the others.
    #[test]
    fn rename_and_replace_keep_what_they_do_not_write() {
        let edits = HeaderEdits {
            rename: vec![pair("old", "new name")],
            replace: vec![pair("v", "9")],
            ..HeaderEdits::default()
        };
        assert_eq!(
            query("/p?v=1&old=a%20b&k=2&old&v=3", &edits).as_deref(),
            Some("/p?v=9&k=2&new%20name=a%20b&new%20name")
        );
    }

    /// A rename onto a name the query already has replaces every parameter under it, matched
    /// once decoded, as Kong's sets the new name; one whose old name is absent leaves the new
    /// name's parameters alone, and one onto its own name keeps its values.
    #[test]
    fn a_renamed_parameter_replaces_what_the_new_name_had() {
        let edits = HeaderEdits {
            rename: vec![pair("old", "new"), pair("absent", "k"), pair("s", "s")],
            ..HeaderEdits::default()
        };
        assert_eq!(
            query("/p?new=x&old=a&k=1&n%65w=y&old=b&s=1", &edits).as_deref(),
            Some("/p?k=1&new=a&new=b&s=1")
        );
    }

    /// Edits that match nothing change nothing, and the URI is not rebuilt.
    #[test]
    fn nothing_matched_is_no_change() {
        let edits = HeaderEdits {
            remove: names(&["x"]),
            rename: vec![pair("y", "z")],
            replace: vec![pair("w", "1")],
            ..HeaderEdits::default()
        };
        assert_eq!(query("/p?a=1&b=%20", &edits), None);
        assert_eq!(query("/p", &edits), None);
        assert_eq!(query("/p?", &edits), None);
        assert_eq!(query("/p?a=1", &HeaderEdits::default()), None);
    }
}
