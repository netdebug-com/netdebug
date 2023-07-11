#!/bin/sh

set -x

cargo b && sudo ./target/debug/webserver
