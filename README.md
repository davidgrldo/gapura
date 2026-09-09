# Gapura

The Rust API gateway. Kubernetes Gateway API-native, one binary, no database, no enterprise edition. Built on [Pingora](https://github.com/cloudflare/pingora).

Status: design phase. Nothing to run yet.

- Design spec (Indonesian): [docs/superpowers/specs/2026-09-09-gapura-sp1-design.md](docs/superpowers/specs/2026-09-09-gapura-sp1-design.md)
- Diagrams: [docs/diagrams/](docs/diagrams/) (open the HTML files in a browser)
- Market research and gap analysis: [docs/superpowers/specs/research/](docs/superpowers/specs/research/)

## Development

```bash
cargo test -p gapura-core                 # unit + golden tests (< 60 s)
cargo insta review                        # review changed golden snapshots
cargo run -p gapura-core --example dump -- crates/gapura-core/tests/fixtures/basic-http/input
```

`gapura-core` is the pure translation library (Gateway API resources in, routing Config and status out). The proxy, the Kubernetes controller, and the Helm chart follow in later plans.

License: Apache-2.0.
