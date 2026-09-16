//! What a signed-in identity is allowed to see.

use std::collections::{BTreeMap, BTreeSet};

/// Group name to the namespaces it grants. `*` as a namespace grants every one.
pub type Mapping = BTreeMap<String, Vec<String>>;

/// Namespaces these groups may read. `None` means every namespace.
pub fn visible(groups: &[String], mapping: &Mapping) -> Option<BTreeSet<String>> {
    let mut namespaces = BTreeSet::new();
    for group in groups {
        for granted in mapping.get(group).into_iter().flatten() {
            if granted == "*" {
                return None;
            }
            namespaces.insert(granted.clone());
        }
    }
    Some(namespaces)
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
        let got = visible(&groups(&["team-a"]), &m).unwrap();
        assert_eq!(got, BTreeSet::from(["apps".to_string()]));
    }

    #[test]
    fn several_groups_add_up() {
        let m = mapping(&[("team-a", &["apps"]), ("team-b", &["shop", "apps"])]);
        let got = visible(&groups(&["team-a", "team-b"]), &m).unwrap();
        assert_eq!(
            got,
            BTreeSet::from(["apps".to_string(), "shop".to_string()])
        );
    }

    #[test]
    fn a_group_nobody_mapped_grants_nothing() {
        let m = mapping(&[("team-a", &["apps"])]);
        let got = visible(&groups(&["strangers"]), &m).unwrap();
        assert!(
            got.is_empty(),
            "an unmapped group must not grant a namespace"
        );
    }

    #[test]
    fn no_groups_at_all_grants_nothing() {
        let m = mapping(&[("team-a", &["apps"])]);
        assert!(visible(&[], &m).unwrap().is_empty());
    }

    #[test]
    fn a_star_grants_every_namespace() {
        let m = mapping(&[("platform", &["*"])]);
        assert_eq!(visible(&groups(&["platform"]), &m), None);
    }

    #[test]
    fn a_star_wins_over_a_narrower_grant_held_at_the_same_time() {
        let m = mapping(&[("platform", &["*"]), ("team-a", &["apps"])]);
        assert_eq!(visible(&groups(&["team-a", "platform"]), &m), None);
    }
}
