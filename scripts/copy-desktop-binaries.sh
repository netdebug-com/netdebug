#!/usr/bin/env bash 

set -e
set -x 


destinations="sea1"
os=$(uname)


echo $os
if test "$os" == "Darwin"; then
    test -d frontend/electron/out/make/zip
    dmg=`cd frontend/electron/out/make/zip/ && ls *.dmg`
    for dest in $destinations; do
        scp frontend/electron/out/make/zip/darwin/universal/*.zip root@${dest}.topology.netdebug.com:updates_dir/darwin/universal/
        scp frontend/electron/out/make/zip/darwin/universal/RELEASES.json root@${dest}.topology.netdebug.com:updates_dir/darwin/universal/
        scp frontend/electron/out/make/*.dmg root@${dest}.topology.netdebug.com:updates_dir/darwin/universal/
	# create latest symlink
	ssh root@${dest}.topology.netdebug.com "cd updates_dir/darwin/universal/ && ln -sf ${dmg} desktop-latest.zip" 
    done
elif test "$os" == MINGW64_NT-10.0-22631 ; then 
    win_out=frontend/electron/out/make/squirrel.windows/x64
    test -d $win_out
    exe=`cd $win_out && ls *.exe`
    for dest in $destinations ; do
	# NOTE: the .exe is for the initial install and the .nupkg is for upgrading existing clients
	scp $win_out/*.nupkg $win_out/*.exe root@${dest}.topology.netdebug.com:updates_dir/win32/x64/
	scp $win_out/RELEASES root@${dest}.topology.netdebug.com:updates_dir/win32/x64/
	# create latest symlink
	ssh root@${dest}.topology.netdebug.com "cd updates_dir/win32/x64/ && ln -sf \"${exe}\" desktop-latest.exe" 
    done
fi

