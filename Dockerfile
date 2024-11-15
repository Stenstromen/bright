FROM rust:bullseye AS builder
WORKDIR /usr/src/bright

RUN apt-get update && apt-get install -y \
    musl-tools \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-unknown-linux-musl

COPY . .

RUN PKG_CONFIG_ALLOW_CROSS=1 \
    RUSTFLAGS='-C target-feature=+crt-static' \
    cargo build --target x86_64-unknown-linux-musl --release

RUN ldd target/x86_64-unknown-linux-musl/release/bright || true

FROM scratch
COPY --from=builder /usr/src/bright/target/x86_64-unknown-linux-musl/release/bright /bright
EXPOSE 8000
USER 65534:65534
CMD ["/bright"]