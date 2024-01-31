#!/usr/bin/env python

# NOTE: does not currently work with self-signed certs - electron won't accept them
# Find a machine (e.g., topology.netdebug.com) with real certs and link them here, e.g.,
# root@c3-small-x86-01:~/upgrade_testing# ls -l
# total 8
# lrwxrwxrwx 1 root root   52 Jan 30 22:56 cert.pem -> /etc/letsencrypt/live/topology.netdebug.com/cert.pem
# lrwxrwxrwx 1 root root   55 Jan 30 22:56 key.pem -> /etc/letsencrypt/live/topology.netdebug.com/privkey.pem
# -rwxr-xr-x 1 root root 1173 Jan 30 23:00 test_update_server.py
#
# NOTE: electronjs needs encryption (https, not http) or it will assert() and fail
#
# NOTE: When running in developer mode (e.g., 'npm start'), updates are DISABLED
# "update-electron-app config looks good; aborting updates since app is in development mode"
#
# NOTE: You cannot even run the binary from 'npm run package', as you will get
# "Error: Can not find Squirrel" --> Squirrel is only available from an
# *installed* binary, ala 'npm run make'
#

from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl


httpd = HTTPServer(('127.0.0.1', 8000), SimpleHTTPRequestHandler)

httpd.socket = ssl.wrap_socket(httpd.socket,
                               keyfile="./key.pem",
                               certfile='./cert.pem', server_side=True)

httpd.serve_forever()
