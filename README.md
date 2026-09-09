# Gapura

The Rust API gateway. Kubernetes Gateway API-native, one binary, no database, no enterprise edition. Built on [Pingora](https://github.com/cloudflare/pingora).

Status: Plan 1 done (the pure translation library gapura-core, with unit, golden, and property tests) and the Plan 2 data plane binary now runs against file-based config; the Kubernetes controller and the Helm chart are not built yet.

- Design spec (Indonesian): [docs/superpowers/specs/2026-09-09-gapura-sp1-design.md](docs/superpowers/specs/2026-09-09-gapura-sp1-design.md)
- Diagrams: [docs/diagrams/](docs/diagrams/) (open the HTML files in a browser)
- Market research and gap analysis: [docs/superpowers/specs/research/](docs/superpowers/specs/research/)

## Development

```bash
cargo test -p gapura-core                 # unit + golden tests (< 60 s)
cargo install cargo-insta                 # once; needed for the review command below
cargo insta review                        # review changed golden snapshots
cargo run -p gapura-core --example dump -- crates/gapura-core/tests/fixtures/basic-http/input
```

### Running the data plane locally

`cargo build -p gapura` compiles a vendored OpenSSL the first time (a few minutes). Then follow
[crates/gapura/examples/dev/README.md](crates/gapura/examples/dev/README.md) to run Gapura against a
local backend with the file-based config source. End-to-end tests (`cargo test -p gapura`) start the
real binary against generated configs and a mock upstream.

`gapura-core` is the pure translation library (Gateway API resources in, routing Config and status out). The Kubernetes controller and the Helm chart follow in later plans.

License: Apache-2.0.
