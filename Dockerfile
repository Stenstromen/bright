FROM rust:latest AS builder
WORKDIR /usr/src/bright
RUN apt-get update && \
    apt-get install -y --no-install-recommends musl-tools musl-dev pkg-config libssl-dev && \
    rustup target add x86_64-unknown-linux-musl
COPY . .
RUN OPENSSL_DIR=/usr/include/openssl \
    OPENSSL_LIB_DIR=/usr/lib/x86_64-linux-gnu \
    OPENSSL_INCLUDE_DIR=/usr/include \
    cargo build --target x86_64-unknown-linux-musl --release

FROM scratch
COPY --from=builder /usr/src/bright/target/x86_64-unknown-linux-musl/release/bright /bright
EXPOSE 8000
USER 65534:65534
CMD ["/bright"]