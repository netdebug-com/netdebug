#!/bin/bash

## TODO
# Think about logrotation, connection db management, etc.

exec sudo ./target/release/webserver --production --listen-port 443 |& tee webserver.logs