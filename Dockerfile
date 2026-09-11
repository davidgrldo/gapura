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
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
# Cache mounts keep the OpenSSL build across image rebuilds; the binary is copied out of
# the cache because a cache mount is not part of the layer.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p gapura \
 && cp /src/target/release/gapura /usr/local/bin/gapura \
 && /usr/local/bin/gapura --version

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /usr/local/bin/gapura /usr/local/bin/gapura
USER 65532:65532
EXPOSE 80 443 9090
ENTRYPOINT ["/usr/local/bin/gapura"]
