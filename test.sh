#!/bin/bash
set -x
set -e

cargo t $@
# WASM integration tests are not run through cargo - sigh
wasm-pack test --chrome --headless $@ webserver/web-client
