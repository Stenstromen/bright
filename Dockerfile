FROM rust:latest AS builder
WORKDIR /usr/src/bright
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        musl-tools \
        musl-dev \
        pkg-config \
        libssl-dev \
        openssl && \
    rustup target add x86_64-unknown-linux-musl
COPY . .
RUN CC=musl-gcc \
    OPENSSL_DIR=/usr \
    OPENSSL_STATIC=yes \
    cargo build --target x86_64-unknown-linux-musl --release

FROM scratch
COPY --from=builder /usr/src/bright/target/x86_64-unknown-linux-musl/release/bright /bright
EXPOSE 8000
USER 65534:65534
CMD ["/bright"]