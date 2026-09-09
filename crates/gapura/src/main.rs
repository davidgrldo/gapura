//! Gapura data plane binary.

mod cli;
#[allow(dead_code)] // used from Task 10
mod proxy;
#[allow(dead_code)] // used from Task 10
mod source;
mod store;
mod telemetry;

use clap::Parser;

fn main() {
    let args = cli::Args::parse();
    println!(
        "gapura: config_dir={} ports={:?}",
        args.config_dir.display(),
        args.supported_ports()
    );
}
