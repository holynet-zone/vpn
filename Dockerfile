FROM rust:1.95-alpine3.23 AS chef
RUN apk add --no-cache musl-dev gcc
RUN cargo install cargo-chef --locked
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder

RUN apk add --no-cache ca-certificates

COPY --from=planner /app/recipe.json recipe.json

RUN mkdir -p .cargo && cat > .cargo/config.toml << 'EOF'
[target.x86_64-unknown-linux-musl]
rustflags = ["-C", "target-feature=+crt-static"]
EOF

RUN cargo chef cook --release \
    --target x86_64-unknown-linux-musl \
    --recipe-path recipe.json

COPY . .
RUN cargo build --release \
    --target x86_64-unknown-linux-musl \
    --package holynet

FROM scratch AS runtime

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/holynet /holynet

WORKDIR /conf

ENTRYPOINT ["/holynet"]
