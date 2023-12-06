#!/bin/bash

# Use this script to install anything we need on a server; 
# TODO: proper chef/puppet automation
set -x

sudo apt update

## install any deps here
sudo apt install libpcap

## install the 'gh' command
type -p curl >/dev/null || (sudo apt update && sudo apt install curl -y)
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
&& sudo chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
&& echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
&& sudo apt update \
&& sudo apt install gh -y

## install a user 'deploy' for us to install into
sudo adduser deploy
sudo addgroup deploy sudo

# TODO: make sure the root user is sane - currently on Equinix metal you can log in as root by default