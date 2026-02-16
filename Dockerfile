FROM rust:1.85-slim AS builder

WORKDIR /build
COPY . .

RUN cargo build --release && \
    strip target/release/ak

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/ak /usr/local/bin/ak

ENTRYPOINT ["ak"]
