//! What a request_transformer and a response_transformer do: edit a head's headers
//! ([`edit_headers`]) and a request's query string ([`edit_query`]), in Kong's order -- remove,
//! then rename, then replace, then add, then append. The steps that call these, and where they
//! run, are `plugin`'s.

use std::borrow::Cow;

use gapura_core::config::HeaderEdits;

use super::HeaderTarget;

/// Apply `edits` to `target`'s headers, a name matched without regard to case as the header
/// map matches it. A rename moves every value as it is, bytes a `&str` cannot hold included.
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
        target.del(from);
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
/// A parameter's name is matched exactly once it is decoded: `a%62=1` is named `ab`. What an
/// edit writes is encoded as a form encodes it (`a b&c` is `a+b%26c`), and a renamed parameter
/// keeps its value as it was written; every parameter no edit touches keeps the bytes the
/// client sent. Decoding the whole query and encoding it again would rewrite parameters the
/// policy never named -- `%20` would become `+`, which an upstream that does not read its query
/// as a form takes for a plus sign, and a value that is not UTF-8 would be lost to U+FFFD.
pub(super) fn edit_query(uri: &http::Uri, edits: &HeaderEdits) -> Option<http::Uri> {
    if edits.is_empty() {
        return None;
    }
    let query = uri.query().unwrap_or_default();
    // Every piece, empty ones too, so that joining them again gives back the query unedited.
    let mut params: Vec<Param> = match uri.query() {
        None => Vec::new(),
        Some(q) => q.split('&').map(Param::read).collect(),
    };
    params.retain(|p| !edits.remove.iter().any(|name| p.name == name.as_str()));
    for (from, to) in &edits.rename {
        if !params.iter().any(|p| p.name == from.as_str()) {
            continue;
        }
        let (moved, kept): (Vec<Param>, Vec<Param>) =
            params.into_iter().partition(|p| p.name == from.as_str());
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
    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(target.parse().ok()?);
    http::Uri::from_parts(parts).ok()
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

    /// A piece an edit writes, encoded as a form encodes it.
    fn new(name: &'a str, value: &str) -> Self {
        let raw = form_urlencoded::Serializer::new(String::new())
            .append_pair(name, value)
            .finish();
        Param {
            name: Cow::Borrowed(name),
            raw: Cow::Owned(raw),
        }
    }

    /// This piece under the name `to`, its value as it was written.
    fn renamed(self, to: &'a str) -> Self {
        let name: String = form_urlencoded::byte_serialize(to.as_bytes()).collect();
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

    /// Every value moves, in order, beside any the new name already had, and bytes that are not
    /// UTF-8 move as they are. Nothing happens for a name that is not there.
    #[test]
    fn a_rename_moves_every_value() {
        let mut req = with(&[("x-old", "a"), ("x-old", "b"), ("x-new", "c")]);
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
        assert_eq!(moved, [&b"c"[..], b"a", b"b", b"caf\xe9"]);
        assert!(req.headers.get("x-other").is_none());
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

    /// What an edit writes is encoded as a form encodes it, and the query appears when there was
    /// none and goes when nothing is left of it.
    #[test]
    fn a_written_parameter_is_form_encoded() {
        let add = HeaderEdits {
            add: vec![pair("q", "a b&c")],
            ..HeaderEdits::default()
        };
        assert_eq!(
            query("/p?keep=1", &add).as_deref(),
            Some("/p?keep=1&q=a+b%26c")
        );
        assert_eq!(query("/p", &add).as_deref(), Some("/p?q=a+b%26c"));
        let remove = HeaderEdits {
            remove: names(&["secret"]),
            ..HeaderEdits::default()
        };
        assert_eq!(query("/p?secret=s", &remove).as_deref(), Some("/p"));
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
            Some("/p?v=9&k=2&new+name=a%20b&new+name")
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
