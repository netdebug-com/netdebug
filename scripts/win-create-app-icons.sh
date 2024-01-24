#!/usr/bin/env bash 
#
#
# usage: win-create-app-icons.sh input-file.png output-file-basename

base=$1
out=$2
set -e 

if [ -z "$base" ]; then
    echo "ERROR: no input file"
    exit 1
fi

if [ ! -r "$base" ]; then
    echo "ERROR: can't read input $1"
    exit 1
fi

if [ -z "$out" ]; then
    echo "ERROR: no output name given"
    exit 1
fi

unsharp="-unsharp 1x4"

convert "$base" -resize "256x256!" $unsharp ${out}.ico
