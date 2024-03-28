FROM blackdex/rust-musl:x86_64-musl-stable-1.77.0 AS build
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

COPY src /src
COPY Cargo.toml /Cargo.toml
COPY rustfmt.toml /rustfmt.toml

ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse
RUN cargo build --release --target x86_64-unknown-linux-musl

# Finish by copying over the compiled binary:
FROM scratch AS bin
COPY --from=build /target/x86_64-unknown-linux-musl/release/xtender /xtender
