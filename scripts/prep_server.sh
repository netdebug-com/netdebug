#!/bin/bash

# Use this script to install anything we need on a server; 
# TODO: proper chef/puppet automation
set -x

# this is intended for Ubuntu LTS 22.04 - "jammy"

if [ `lsb_release -c -s` != "jammy" ] ; then
    lsb_release -a
    echo "Are you sure this is Ubuntu Jammy?" >&2
    exit 1
else
    echo "Correctly running Ubuntu 22.04 Jammy"
fi

sudo apt update

## install any deps here; for jammy, libpcap is v0.8 in the package
sudo apt install libpcap0.8 certbot

## install the 'gh' command
type -p curl >/dev/null || (sudo apt update && sudo apt install curl -y)
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
&& sudo chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
&& echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
&& sudo apt update \
&& sudo apt install gh -y

# create signed ssl cert with certbot!
echo "Enter 'webmaster@netdebug.com' for email and the full server name"
echo " (e.g., "bay1.topology.netdebug.com") for the domain name"
echo " Make sure you've allocated the DNS name *before* this as it's used for auth"
sudo certbot certonly --standalone
# setup compat symlink so that every machine finds the ssl in the same place
# (without messing with where certbot expects them to be)
# NOTE: certbot will also create a cronjob to auto-renew certs - magic!
ln -s /etc/letsencrypt/live/*topology.netdebug.com /etc/letsencrypt/live/topology.netdebug.com

## install a user 'deploy' for us to install into
echo "Hit <enter> to enter blanks for real name, office, etc..."
sudo adduser deploy --disabled-password
sudo addgroup deploy sudo

if [ -f update_webserver.sh ]; then
    mv update_webserver.sh ~deploy
    chown deploy:deploy ~deploy/update_webserver.sh
else
    echo "No update-webserver.sh found!? " >&2
    exit 1

fi

SYSTEMD=netdebug-webserver.service
if [ -f $SYSTEMD ] ; then
    cp $SYSTEMD /etc/systemd/system
    systemctl start netdebug-webserver
    systemctl enable netdebug-webserver
else 
    echo "No $SYSTEMD found!? " >&2
    exit 1
fi

# TODO: make sure the root user is sane - currently on Equinix metal you can log in as root by default
echo "Now manually copy .github_access_token into ~deploy"
echo "Now manually set group 'sudo' with NOPASSWD: "