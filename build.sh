#!/bin/sh
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
wasm-pack build --target=web desktop/web-gui ${build_opt}
# add cargo tauri build here?  or cargo tauri dev?

# Electron hackery
cp $outpath/desktop electron/extra-resources
cp -r desktop/web-gui/pkg electron/src/
