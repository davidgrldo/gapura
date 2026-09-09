//! Dev and test config source: a directory of Gateway API YAML documents, loaded once at startup.

use std::path::Path;

use anyhow::{bail, Context};
use gapura_core::{translate, Settings, Snapshot};

use crate::store::Store;
use crate::telemetry::METRICS;

/// What a load produced, for the startup log line.
#[derive(Debug, PartialEq, Eq)]
pub struct Summary {
    pub listeners: usize,
    pub rules: usize,
    pub clusters: usize,
    pub status_patches: usize,
}

/// Read every `*.yaml`/`*.yml` in `dir` (sorted) into one Snapshot.
pub fn load_snapshot(dir: &Path) -> anyhow::Result<Snapshot> {
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("reading config dir {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "yaml" || x == "yml"))
        .collect();
    files.sort();
    if files.is_empty() {
        bail!("no *.yaml files in {}", dir.display());
    }
    let mut yaml = String::new();
    for f in &files {
        yaml.push_str(
            &std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?,
        );
        yaml.push_str("\n---\n");
    }
    Snapshot::from_yaml_docs(&yaml).with_context(|| format!("parsing YAML in {}", dir.display()))
}

/// Load, translate, and install into the store. Status patches are only logged here;
/// applying them to the API server is Plan 3.
pub fn apply(dir: &Path, settings: &Settings, store: &Store) -> anyhow::Result<Summary> {
    let result = load_snapshot(dir).map(|snap| translate(&snap, settings));
    let translation = match result {
        Ok(t) => t,
        Err(e) => {
            METRICS
                .config_reloads_total
                .with_label_values(&["failure"])
                .inc();
            return Err(e);
        }
    };
    for patch in &translation.status {
        tracing::debug!(?patch, "status computed (file mode: not applied)");
    }
    let summary = Summary {
        listeners: translation.config.listeners.len(),
        rules: translation
            .config
            .listeners
            .iter()
            .map(|l| l.rules.len())
            .sum(),
        clusters: translation.config.clusters.len(),
        status_patches: translation.status.len(),
    };
    store.swap(translation.config);
    METRICS
        .config_reloads_total
        .with_label_values(&["success"])
        .inc();
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn fixture(case: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../gapura-core/tests/fixtures")
            .join(case)
            .join("input")
    }

    #[test]
    fn applies_basic_http_fixture() {
        let store = Store::empty();
        let settings = Settings::default(); // ports 80/443, controller gapura.dev/controller
        let summary = apply(&fixture("basic-http"), &settings, &store).unwrap();
        assert_eq!(
            summary,
            Summary {
                listeners: 1,
                rules: 1,
                clusters: 1,
                status_patches: 3
            }
        );
        assert!(store.is_ready());
        assert_eq!(store.load().config.listeners[0].id, "infra/main/http");
        assert_eq!(store.load().next_index("apps/echo:80"), Some(0));
    }

    #[test]
    fn missing_dir_and_empty_dir_are_errors() {
        let store = Store::empty();
        assert!(apply(
            Path::new("/definitely/not/here"),
            &Settings::default(),
            &store
        )
        .is_err());
        let empty = tempfile::tempdir().unwrap();
        let err = apply(empty.path(), &Settings::default(), &store).unwrap_err();
        assert!(err.to_string().contains("no *.yaml files"), "{err}");
        assert!(!store.is_ready());
    }
}
