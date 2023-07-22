FROM rust:bookworm 
WORKDIR /netdebug
# tip from https://docs.docker.com/build/cache/
RUN \
    --mount=type=cache,target=/var/cache/apt \
    apt-get update && apt-get install -y libpcap-dev 
RUN --mount=type=cache,target=/root/.cargo cargo install wasm-pack && \
    cargo install bindgen-cli && \
    rustup target add wasm32-unknown-unknown
COPY . .
RUN cargo build --release
RUN wasm-pack build --target=web webserver/web-client


# start from a recent stable debian for a small container

CMD ["/netdebug/target/release/webserver" , "--production"]