# syntax=docker/dockerfile:1
# Two stages. The builder compiles OpenSSL 3.6.3 and zlib-ng from source (pingora pins
# openssl/vendored and flate2/zlib-ng), so it needs cmake and perl on top of a C toolchain.
# The runtime is distroless cc: the binary is *-linux-gnu and needs libc plus libgcc_s,
# which `static` and `base` do not carry. `nonroot` runs as uid 65532 and ships CA
# certificates, which BackendTLSPolicy `System` mode and the kube client both read.
FROM rust:1-bookworm AS builder
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake perl pkg-config \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# The dependencies first, OpenSSL among them, as a layer of their own: built from the manifests
# and the lockfile with every crate of the workspace stubbed out, so the layer changes only when
# they do, and a change to the code reuses it. A layer rather than a cache mount: CI keeps layers
# between runs (`cache-to: type=gha`) and drops cache mounts, so with a mount every pull request
# rebuilt every dependency.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/gapura-core/Cargo.toml crates/gapura-core/
COPY crates/gapura/Cargo.toml crates/gapura/
COPY crates/gapura-control/Cargo.toml crates/gapura-control/
RUN for c in gapura-core gapura gapura-control; do mkdir -p "crates/$c/src"; done \
 && touch crates/gapura-core/src/lib.rs crates/gapura-control/src/lib.rs \
 && for c in gapura gapura-control; do \
      echo 'fn main() { panic!("a dependency stub, not the real binary") }' > "crates/$c/src/main.rs"; \
    done \
 && cargo build --release --locked -p gapura
COPY crates ./crates
# The tag this image is published under, which the data plane reports to the control plane as
# its version: every prerelease of one version shares the crate's. Empty outside a release, and
# the crate's version is used.
ARG GAPURA_VERSION
# The sources are touched because COPY keeps their times, which can predate the stubs above, and
# cargo would then take the stubs for an up-to-date build of them. A stub panics, so an image
# that shipped one anyway fails `--version` here.
RUN find crates -name '*.rs' -exec touch {} + \
 && cargo build --release --locked -p gapura \
 && cp /src/target/release/gapura /usr/local/bin/gapura \
 && /usr/local/bin/gapura --version

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /usr/local/bin/gapura /usr/local/bin/gapura
USER 65532:65532
EXPOSE 80 443 9090
ENTRYPOINT ["/usr/local/bin/gapura"]
