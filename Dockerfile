FROM rust:alpine AS builder
WORKDIR /app
COPY . .
RUN apk add --no-cache musl-dev gcc && \
    rustup target add x86_64-unknown-linux-musl && \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=gcc cargo build --target x86_64-unknown-linux-musl --release

FROM scratch
COPY --from=builder /usr/src/bright/target/x86_64-unknown-linux-musl/release/bright /bright
EXPOSE 8000
USER 65534:65534
CMD ["/bright"]