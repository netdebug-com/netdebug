FROM rust:bookworm 
WORKDIR /netdebug
COPY . .
RUN apt-get update 
RUN apt-get install -y \
    libpcap-dev 
RUN cargo build --release
RUN wasm-pack build webserver/web-client

COPY target/release/webserver webserver/html ./
COPY webserver/web-client/pkg wasm
RUN mkdir logs

# start from a recent stable debian for a small container

CMD ["/netdebug/webserver" , "--production", "--html-dir=./html", "--wasm-dir=./wasm", "--log-dir=./logs"]