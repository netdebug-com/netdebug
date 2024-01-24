#!/usr/bin/env bash 
#
# usage: macos-create-app-icons.sh input-file.png output_basename 
#
# See https://developer.apple.com/library/archive/documentation/Xcode/Reference/xcode_ref-Asset_Catalog_Format/IconSetType.html
#

base=$1
output_name=$2
set -e 

if [ -z "$base" ]; then
    echo "ERROR: no input file"
    exit 1
fi

if [ ! -r "$base" ]; then
    echo "ERROR: can't read input $1"
    exit 1
fi

if [ -z "$output_name" ]; then
    echo "ERROR: no output name given"
    exit 1
fi

out=${output_name}.iconset
if [ -e "$out" ]; then
    echo "ERROR: ${out} already exists"
    exit 1
fi

mkdir -p $out

unsharp="-unsharp 1x4"

convert "$base" -resize "16x16!" $unsharp ${out}/"icon_16x16.png"
convert "$base" -resize "32x32!" $unsharp ${out}/"icon_16x16@2x.png"
convert "$base" -resize "32x32!" $unsharp ${out}/"icon_32x32.png"
convert "$base" -resize "64x64!" $unsharp ${out}/"icon_32x32@2x.png"

convert "$base" -resize "128x128!" $unsharp ${out}/"icon_128x128.png"
convert "$base" -resize "256x256!" $unsharp ${out}/"icon_128x128@2x.png"

convert "$base" -resize "256x256!" $unsharp ${out}/"icon_256x256.png"
convert "$base" -resize "512x512!" $unsharp ${out}/"icon_256x256@2x.png"

convert "$base" -resize "512x512!" $unsharp ${out}/"icon_512x512.png"
convert "$base" -resize "1024x1024!" $unsharp ${out}/"icon_512x512@2x.png"

# this is a MacOS only utility
iconutil -c icns ${out}
