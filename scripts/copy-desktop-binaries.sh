#!/usr/bin/env bash 

set -e
set -x 

test -d frontend/electron/out/make/zip

destinations="dal1"
os=$(uname)


echo $os
if test "$os" == "Darwin"; then
    for dest in $destinations; do
        scp frontend/electron/out/make/zip/darwin/universal/*.zip root@${dest}.topology.netdebug.com:updates_dir/darwin/universal/
        scp frontend/electron/out/make/zip/darwin/universal/RELEASES.json root@${dest}.topology.netdebug.com:updates_dir/darwin/universal/
        scp frontend/electron/out/make/*.dmg root@${dest}.topology.netdebug.com:updates_dir/darwin/universal/
    done
fi

