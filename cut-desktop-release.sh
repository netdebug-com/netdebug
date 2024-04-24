#!/usr/bin/env bash 
#

# Build the desktop binary and electron app as universal MacOS binary 
# (i.e., for x86 and aarch64)

set -x 
set -e

# Hacky way to make sure we are called from project
# root dir :-)
test -d frontend/electron

cut_windows_desktop_release() {
    echo "Building desktop release for windows"
    cargo build --release --bin netdebug-desktop
    cp target/release/netdebug-desktop.exe frontend/electron/extra-resources/
    cd frontend/electron && npm install && npm run make
    # TODO: windows code signing...
    echo "Output is in frontend/electron/out/make/win32/..."
}

cut_mac_os_desktop_release() {
    echo "Building desktop release for MacOS"
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
    # delete old DMGs and ZIPs
    rm -f frontend/electron/out
    # Now copy the universal binary into frontend/electron
    cp $UNIVERSAL_DESKTOP_OUTDIR/netdebug-desktop frontend/electron/extra-resources/

    # Finally use electron-forge to build the universal .app bundle of the GUI
    cd frontend/electron 
    npm run make -- --arch=universal
}

case `uname` in
    # on windows, `uname` outputs MINGW64_NT-10.0-22631 so do our best for now
    MINGW64_NT-10.0-22631) cut_windows_desktop_release
    ;;
    Darwin) cut_mac_os_desktop_release 
    ;;
    *) echo "Unknown OS Type `uname`; exiting... " >&2
    exit 1
    ;;
esac
