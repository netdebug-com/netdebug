#!/bin/bash

set -x

BUILD_VERSION=0.1

docker build . -t netdebug:$BUILD_VERSION
# map the host's external port 3030 to the container's port 3030
docker run -p 3030:3030 netdebug:$BUILD_VERSION
