//! What a signed-in identity is allowed to see.

use std::collections::{BTreeMap, BTreeSet};

/// Group name to the namespaces it grants. `*` as a namespace grants every one.
pub type Mapping = BTreeMap<String, Vec<String>>;

/// The namespaces an identity may read.
///
/// This is an enum rather than an `Option<BTreeSet<String>>` because with an `Option` the
/// absent value — the one a `?`, an `unwrap_or_default` or an `.ok()` produces when
/// something goes wrong — was the value that granted every namespace. Here nothing a
/// mistake can reach means more than the empty set: the wildcard has to be named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// Every namespace. Only reachable by a group granted `*`.
    AllNamespaces,
    Only(BTreeSet<String>),
}

// Written out rather than derived because `#[derive(Default)]` can only pick a unit
// variant, and the default has to be the empty grant rather than the wildcard.
impl Default for Scope {
    fn default() -> Self {
        Scope::Only(BTreeSet::new())
    }
}

/// The namespaces these groups may read.
pub fn visible(groups: &[String], mapping: &Mapping) -> Scope {
    let mut namespaces = BTreeSet::new();
    for group in groups {
        for granted in mapping.get(group).into_iter().flatten() {
            if granted == "*" {
                return Scope::AllNamespaces;
            }
            namespaces.insert(granted.clone());
        }
    }
    Scope::Only(namespaces)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapping(pairs: &[(&str, &[&str])]) -> Mapping {
        pairs
            .iter()
            .map(|(g, ns)| (g.to_string(), ns.iter().map(|s| s.to_string()).collect()))
            .collect()
    }
    fn groups(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_group_grants_the_namespaces_it_names() {
        let m = mapping(&[("team-a", &["apps"])]);
        let got = visible(&groups(&["team-a"]), &m);
        assert_eq!(got, Scope::Only(BTreeSet::from(["apps".to_string()])));
    }

    #[test]
    fn several_groups_add_up() {
        let m = mapping(&[("team-a", &["apps"]), ("team-b", &["shop", "apps"])]);
        let got = visible(&groups(&["team-a", "team-b"]), &m);
        assert_eq!(
            got,
            Scope::Only(BTreeSet::from(["apps".to_string(), "shop".to_string()]))
        );
    }

    #[test]
    fn a_group_nobody_mapped_grants_nothing() {
        let m = mapping(&[("team-a", &["apps"])]);
        assert_eq!(
            visible(&groups(&["strangers"]), &m),
            Scope::Only(BTreeSet::new()),
            "an unmapped group must not grant a namespace"
        );
    }

    #[test]
    fn no_groups_at_all_grants_nothing() {
        let m = mapping(&[("team-a", &["apps"])]);
        assert_eq!(visible(&[], &m), Scope::Only(BTreeSet::new()));
    }

    #[test]
    fn a_star_grants_every_namespace() {
        let m = mapping(&[("platform", &["*"])]);
        assert_eq!(visible(&groups(&["platform"]), &m), Scope::AllNamespaces);
    }

    #[test]
    fn a_star_wins_over_a_narrower_grant_held_at_the_same_time() {
        let m = mapping(&[("platform", &["*"]), ("team-a", &["apps"])]);
        assert_eq!(
            visible(&groups(&["team-a", "platform"]), &m),
            Scope::AllNamespaces
        );
    }

    #[test]
    fn the_default_scope_grants_nothing() {
        // The point of the type: what you get from Default, or from an empty set, is the
        // least privilege rather than the most. Under the old Option this test could not be
        // written, because the empty value WAS the wildcard.
        assert_eq!(Scope::default(), Scope::Only(BTreeSet::new()));
    }
}
