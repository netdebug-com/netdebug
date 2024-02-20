#!/bin/bash
#
#Grr! would love for build.rs to make this work... but it doesn't...

set -x
set -e 

if [ $# == 0 ] ; then
   build_opt=--dev
   outpath=target/debug
else 
   build_opt=--release
   outpath=target/release
fi

cargo build $@
wasm-pack build --target=web webserver/web-client ${build_opt}
# add cargo tauri build here?  or cargo tauri dev?

#
# Electron hackery
#
# ... unlink the file first, otherwise cp just truncates the file and I 
#     think this does weird things to currently running processes using 
#     that binary. This way, the new binary will get a new inode and the existing
#     processe won't see their binary modified underneath them. At least on MacOS
rm -f electron/extra-resources/netdebug-desktop
cp $outpath/netdebug-desktop electron/extra-resources
