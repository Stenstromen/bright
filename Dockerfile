FROM rust:latest as builder
WORKDIR /usr/src/bright
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends libssl3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/bright/target/release/bright /usr/local/bin/bright
CMD ["bright"]