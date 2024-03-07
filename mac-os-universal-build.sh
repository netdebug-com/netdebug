#!/usr/bin/env bash 
#

# Build the desktop binary and electron app as universal MacOS binary 
# (i.e., for x86 and aarch64)

set -x 
set -e

# Hacky way to make sure we are called from project
# root dir :-)
test -d frontend/electron

UNIVERSAL_DESKTOP_OUTDIR=target/release/mac-os-universal

mkdir -p $UNIVERSAL_DESKTOP_OUTDIR

#
# if one of these fail, make sure you have the target installed: 
#    rustup target add x86_64-apple-darwin
#    rustup target add aarch64-apple-darwin
cargo build --release --bin netdebug-desktop --target=x86_64-apple-darwin
cargo build --release --bin netdebug-desktop --target=aarch64-apple-darwin

# This is a MacOSX utility that creates the universal binary from 
# target specific ones. 
# TODO: apparently xcframeworks is the preferred new way to do this on 
# Mac but I didn't find easy instructions. So lets use lipo since it works. 
lipo -create \
    target/aarch64-apple-darwin/release/netdebug-desktop \
    target/x86_64-apple-darwin/release/netdebug-desktop \
    -output $UNIVERSAL_DESKTOP_OUTDIR/netdebug-desktop

# delete the old name if it's there
rm -f frontend/electron/extra-resources/desktop
# Now copy the universal binary into frontend/electron
cp $UNIVERSAL_DESKTOP_OUTDIR/netdebug-desktop frontend/electron/extra-resources/

# build shared js code
(cd frontend/common && npm build)

# Finally use electron-forge to build the universal .app bundle of the GUI
cd frontend/electron 
npm run make -- --arch=universal

