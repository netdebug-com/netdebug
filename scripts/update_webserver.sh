#!/bin/bash
# Needs to be bash and not just 'sh' for $(...) subshell

set -x

die () {
  echo $@ >2 
  exit 1
}

# Needs 'gh' installed from https://github.com/cli/cli/blob/trunk/docs/install_linux.md
which gh || die "gh not found"
which curl || die "curl not found"

# List of ways to grab artifacts from repo
# https://gist.github.com/umohi/bfc7ad9a845fc10289c03d532e3d2c2f

ACCESS_FILE=$HOME/.github_access_token

if [ ! -f $ACCESS_FILE ]; then
  die "Can't find $ACCESS_FILE"
fi

ACCESS_TOKEN=`cat $ACCESS_FILE`
if [ -z $ACCESS_TOKEN ] ; then
  die "Empty access token!?"
fi
repo=netdebug
org=netdebug-com

gh auth login --with-token <<< $ACCESS_TOKEN
asset=$(gh api repos/${org}/${repo}/releases --jq '.[0].assets.[0].url')
curl -L -o pre-prod-release.tgz "$asset" \
   -H "Accept: application/octet-stream" \
   -H "Authorization: Bearer $ACCESS_TOKEN"
