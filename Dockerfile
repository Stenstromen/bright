FROM alpine:latest AS builder
WORKDIR /usr/src/bright

# Install build dependencies
RUN apk add --no-cache \
    rust \
    cargo \
    musl-dev \
    gcc \
    openssl-dev \
    openssl-libs-static \
    pkgconfig

COPY . .
RUN OPENSSL_STATIC=1 \
    OPENSSL_DIR=/usr \
    cargo build --release

FROM scratch
COPY --from=builder /usr/src/bright/target/release/bright /bright
EXPOSE 8000
USER 65534:65534
CMD ["/bright"]