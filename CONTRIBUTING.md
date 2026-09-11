# Contributing to Gapura

Thanks for looking. Gapura is a Kubernetes Gateway API gateway built on Pingora, maintained by one
person in their spare time. That shapes what this document asks of you: the checks below are the
ones CI runs, and a patch that arrives with them already green is a patch I can read instead of
debug.

Before starting anything large, open an issue and describe the problem you want solved. It is
cheaper for both of us to disagree about an approach in a paragraph than in a thousand-line diff.

By contributing you agree that your work is licensed under [Apache-2.0](LICENSE), the same as the
rest of the repository. There is no CLA and no sign-off requirement.

## Prerequisites

**Rust.** `rust-toolchain.toml` pins the `stable` channel with `rustfmt` and `clippy`, so `rustup`
installs the right toolchain the first time you run `cargo` in this checkout — you do not need to
pick a version yourself.

The minimum supported Rust version is **1.89**, declared as `rust-version` in the workspace
[`Cargo.toml`](Cargo.toml). The `msrv` job in CI enforces it, so a patch that uses a feature newer
than 1.89 fails CI even though it built fine on your stable toolchain. To check before pushing:

```bash
rustup toolchain install 1.89                                       # once
RUSTUP_TOOLCHAIN=1.89 cargo check --workspace --all-targets --locked
```

The `RUSTUP_TOOLCHAIN` variable is not optional: `rust-toolchain.toml` pins `stable`, which would
otherwise silently win over the 1.89 you asked for and check nothing.

**Other tools**, in rough order of how likely you are to need them:

| Tool | Version | Needed for |
| --- | --- | --- |
| `cargo-deny` | 0.20 or newer | `cargo deny check all` (licenses and advisories) |
| `helm` | **4.1.4** | `./hack/chart-render.sh` |
| `cargo-insta` | 0.20 or newer | reviewing golden snapshots (optional, see below) |
| `docker`, `kind`, `kubectl` | 0.20 or newer | `./hack/kind-deploy.sh`, `./hack/kind-e2e.sh` |
| `go` | **1.26 or newer** | `./hack/conformance.sh` only |

Install the cargo tools with `cargo install cargo-deny cargo-insta`.

The helm version is pinned rather than "recent" on purpose. The golden chart renders under
`charts/gapura/tests/golden/` were produced by helm 4.1.4, and a helm release that changes rendering
makes `./hack/chart-render.sh` fail for reasons that have nothing to do with your change. CI pins
the same version via `azure/setup-helm`. If your renders differ and you did not touch the chart,
check your helm version first.

Go is needed *only* to run the upstream Gateway API conformance suite. Nothing else in the
repository is Go, and you can contribute to the data plane, the controller, and the chart without
installing it at all.

## Before you send a patch

Every one of these must be green. They are the checks CI runs:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
./hack/check-identity.sh
./hack/chart-render.sh
cargo deny check all
```

Two of those are easy to overlook:

- **`cargo doc`** is a CI gate with `-D warnings`, so a broken intra-doc link fails the build like a
  compile error does.
- **`./hack/check-identity.sh`** fails if the pre-publication placeholder owner name appears
  anywhere that ships. If it fires on your patch, you copied a URL from an old file; the real
  repository is `github.com/davidgrldo/gapura`.

`./hack/chart-render.sh` also refuses to pass if the Grafana dashboard or the Prometheus rules have
drifted between `deploy/` and their copies under `charts/gapura/`. It tells you the `cp` to run.

The kind-based scripts (`./hack/kind-deploy.sh`, `./hack/kind-e2e.sh`) and the conformance suite are
*not* run by the pre-patch checklist above, because they need a cluster and take a long time —
conformance alone is 10 to 40 minutes. Run them when your change touches the controller, the chart,
or routing behaviour. `cargo test --workspace` skips the kind end-to-end test unless it is asked for
explicitly, which is why it passes on a machine with no cluster.

## Golden snapshots

`gapura-core` is a pure function: Gateway API resources in, a routing `Config` and a set of status
patches out. Almost all of its coverage is golden tests, and they are the fastest way to say what
your change does.

The layout:

- `crates/gapura-core/tests/fixtures/<case>/input/*.yaml` — the input resources for one scenario.
  Every `*.yaml` in the directory is read in filename order and concatenated, which is why they are
  named `00-class.yaml`, `10-gateway.yaml`, `20-route.yaml` and so on.
- `crates/gapura-core/tests/snapshots/golden__<case>.snap` — the committed output.
- `crates/gapura-core/tests/golden.rs` — the test for each case.

To see what a fixture translates to without running the suite:

```bash
cargo run -p gapura-core --example dump -- crates/gapura-core/tests/fixtures/basic-http/input
```

### Reviewing a changed snapshot

When your change alters the output, the snapshot test fails and shows a diff. Review it — do not
regenerate it reflexively. The snapshot is the specification of the behaviour; if you accept a
wrong one, the test now enforces the bug.

With `cargo-insta` installed, which is the better experience:

```bash
cargo install cargo-insta   # once
cargo insta review          # step through each change, accept or reject
```

Without it, have the test runner write the new snapshots and read the result as a diff:

```bash
INSTA_UPDATE=always cargo test -p gapura-core
git diff crates/gapura-core/tests/snapshots
```

Either way, the question to answer for each hunk is "is this new output correct?", and the answer
belongs in the commit message.

### Changes to the translator need a new fixture

**A pull request that changes translation behaviour must add a golden fixture that fails before the
change and passes after it.** Updating an existing snapshot is not enough: it shows that the output
moved, not that the new behaviour is the one you intended.

Add a directory under `tests/fixtures/`, write the test in `golden.rs`, and follow the convention
already there — each test snapshots the whole `Translation` *and* asserts the specific facts it
cares about (this condition is `True` with this reason, this route resolves to this backend). The
explicit assertions are what stop a wrong snapshot from being accepted by accident, so a test that
only snapshots is not finished.

For a bug fix, the fixture is the reproduction: write it first, watch it fail, then fix it.

## Chart changes

The chart is covered by rendered golden output for every values file in `charts/gapura/tests/`.
After an intentional chart change:

```bash
./hack/chart-render.sh --update
git diff charts/gapura/tests/golden
```

Read that diff as carefully as a code diff — it is the Kubernetes the chart will apply to somebody's
cluster. Changing a default, a security context, or anything in the RBAC deserves a sentence in the
commit message explaining why.

If you add a values file, `hack/chart-render.sh` picks it up automatically and creates its golden on
the next `--update`.

## Conformance reports

`conformance/reports/` holds reports generated by `./hack/conformance.sh`. **Never hand-edit one.**
The identity fields inside a report are derived from the `ORG` the script ran under, and an edited
or mismatched report is worth nothing to the upstream project — correcting one costs a full rerun.
If a report needs to change, rerun the suite.

## Commits and pull requests

Commit subjects follow Conventional Commits with a scope where one helps, and the subject says what
changed *and why it matters*, not just which file moved:

```
fix(gapura): rediscovery reports its own failures once, and never announces a restart while stopping
test(gapura): kind-e2e stands the chart's gateway down for the run
feat(chart): example PrometheusRule, and the measured numbers for the definition of done
```

Keep the subject lowercase, in the imperative or the present tense, and with no trailing period. Put
the reasoning in the body: what was broken, what you observed, why this fix and not another one.

For the pull request itself, say what a reviewer should look at hardest, and note anything you could
not test. If your change affects operators — a changed default, a behaviour that starts or stops on
upgrade — add an entry to [CHANGELOG.md](CHANGELOG.md) under `Unreleased`, in the style of the
entries already there, which tell the reader what to check in their cluster before upgrading.

Small, self-contained pull requests get reviewed sooner, because they can be reviewed in one sitting.

## Reporting bugs and vulnerabilities

For an ordinary bug, open an issue with the version or commit, the Gateway API resources involved,
what you expected, and what happened. A failing fixture is the best possible bug report.

**For a security issue, do not open a public issue.** Use GitHub's private vulnerability reporting,
as described in [SECURITY.md](SECURITY.md).

## Code of conduct

Participation in this project is governed by the [Contributor Covenant](CODE_OF_CONDUCT.md).
