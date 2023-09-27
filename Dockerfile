FROM rust:latest AS build
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN apt-get update && apt-get install -y musl-tools
RUN rustup target add x86_64-unknown-linux-musl

COPY src /src
COPY Cargo.toml /Cargo.toml
COPY rustfmt.toml /rustfmt.toml

ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse
RUN cargo build --release --target x86_64-unknown-linux-musl

# Finish by copying over the compiled binary:
FROM scratch AS bin
COPY --from=build /target/x86_64-unknown-linux-musl/release/xtender /xtender
