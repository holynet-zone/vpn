FROM ubuntu:22.04


RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    gcc \
    g++ \
    libc6-dev \
    pkg-config \
    clang \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /app
ENV CARGO_TARGET_DIR="/app/target"

COPY crates/ ./crates/
COPY Cargo.toml ./Cargo.toml
COPY Cargo.lock ./Cargo.lock

RUN cargo build --release --features udp
