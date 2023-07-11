#!/bin/sh

set -x

cargo clean
# all of the wasm-pack output goes here and no clean command
rm -rf webserver/web-client/pkg
