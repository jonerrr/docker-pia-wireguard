FROM rust:alpine as builder
WORKDIR /app

COPY . .

RUN apk add --no-cache openssl-dev alpine-sdk

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    RUSTFLAGS=-Ctarget-feature=-crt-static cargo build --release; mv ./target/release/pia-wireguard ./pia-wireguard


FROM alpine
WORKDIR /app

RUN apk add --no-cache openssl libgcc ipcalc iptables iproute2 openresolv wireguard-tools

COPY --from=builder /app/pia-wireguard .

ENTRYPOINT ["/app/pia-wireguard"]