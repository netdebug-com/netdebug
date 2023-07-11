#!/bin/sh

set -x

./build.sh && sudo ./target/debug/webserver
