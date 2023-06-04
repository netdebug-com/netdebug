#!/bin/sh
set -x   # for verbosity and to ease minds

die() {
    >&2 echo $1  
    exit 1
}

test -d .git || die "Run from root directory"

cp hooks/pre-commit .git/hooks
chmod 755 hooks/pre-commit .git/hooks/pre-commit
