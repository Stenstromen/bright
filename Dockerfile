FROM rust:latest AS builder
WORKDIR /usr/src/bright

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        musl-tools \
        musl-dev \
        pkg-config \
        wget \
        make && \
    wget https://www.openssl.org/source/openssl-3.0.12.tar.gz && \
    tar xvf openssl-3.0.12.tar.gz && \
    cd openssl-3.0.12 && \
    CC=musl-gcc ./Configure no-shared no-async --prefix=/usr/local/musl --openssldir=/usr/local/musl/ssl linux-x86_64 && \
    make -j$(nproc) && \
    make install && \
    cd .. && \
    rm -rf openssl-3.0.12* && \
    rustup target add x86_64-unknown-linux-musl

COPY . .
RUN CC=musl-gcc \
    OPENSSL_DIR=/usr/local/musl \
    OPENSSL_STATIC=yes \
    OPENSSL_INCLUDE_DIR=/usr/local/musl/include \
    cargo build --target x86_64-unknown-linux-musl --release

FROM scratch
COPY --from=builder /usr/src/bright/target/x86_64-unknown-linux-musl/release/bright /bright
EXPOSE 8000
USER 65534:65534
CMD ["/bright"]