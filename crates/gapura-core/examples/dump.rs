//! Translate a fixture directory and print the Translation as YAML.
//! Usage: cargo run -p gapura-core --example dump -- crates/gapura-core/tests/fixtures/basic-http/input

use std::error::Error;

use gapura_core::{translate, Settings, Snapshot};

fn main() -> Result<(), Box<dyn Error>> {
    let dir = std::env::args()
        .nth(1)
        .ok_or("usage: dump <directory with *.yaml>")?;
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .map_err(|e| format!("{dir}: {e}"))?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<_, _>>()?;
    files.sort();
    let yaml_files: Vec<_> = files
        .iter()
        .filter(|f| f.extension().is_some_and(|x| x == "yaml" || x == "yml"))
        .collect();
    if yaml_files.is_empty() {
        eprintln!("warning: no *.yaml files in {dir}");
    }
    let mut yaml = String::new();
    for f in yaml_files {
        yaml.push_str(&std::fs::read_to_string(f).map_err(|e| format!("{}: {e}", f.display()))?);
        yaml.push_str("\n---\n");
    }
    let translation = translate(&Snapshot::from_yaml_docs(&yaml)?, &Settings::default());
    println!("{}", serde_yaml_ng::to_string(&translation)?);
    Ok(())
}
