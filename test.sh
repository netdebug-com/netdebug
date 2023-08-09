#!/bin/sh
set -x

cargo t $@
# WASM integration tests are not run through cargo - sigh
wasm-pack test --chrome --headless $@ webserver/web-client
wasm-pack test --chrome --headless $@ desktop/web-gui
