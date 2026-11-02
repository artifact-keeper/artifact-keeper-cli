# The builder and runtime must share a Debian release: the binary links against
# the builder's glibc, so a builder newer than the runtime stage produces an
# image that fails at startup with "GLIBC_x.y not found". The CI Docker job
# runs the built image to catch this.
FROM rust:1.99-slim-bookworm AS builder

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
