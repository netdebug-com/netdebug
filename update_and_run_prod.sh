#!/bin/bash

set -x

git pull && \
	cargo b --release && \
	wasm-pack build --target=web webserver/web-client/ && \
	sudo ./target/release/webserver --production --listen-port 443 \
	|& tee out.$$.log
