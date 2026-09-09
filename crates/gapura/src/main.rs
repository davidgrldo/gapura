//! Gapura data plane binary.

mod cli;

use clap::Parser;

fn main() {
    let args = cli::Args::parse();
    println!(
        "gapura: config_dir={} ports={:?}",
        args.config_dir.display(),
        args.supported_ports()
    );
}
