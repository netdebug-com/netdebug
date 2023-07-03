# Dev Setup Instructions
1. Create a _dedicated_ github account for netdebug using your netdebug.com email
2. Enable 2FA for that account with both XXX (looking at yubikey) and SMS as a backup
3. Run the git hooks setup script in ./hooks/setup.sh to setup all of your hooks
4. VS code is strongly recommended with a bunch of project defaults built into the repo
    1. Recommended that you install the vscode rpm repo so you get auto 6.1updates!
    2. Recommended packages include : 
5. Setup a new ssh-key only for the new github account (github requires this)
6. On ubuntu server instances:
```
# install rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# update system to current
sudo apt-get update
sudo apt-get upgrade
# install build deps - TODO - just publish a built image
sudo apt-get install -y build-essential libpcap-dev cmake libfontconfig-dev tmux
# Install required rust tools
cargo install wasm-pack
```
7. You can manage multiple ssh-keys into github ala a special ssh config
    and then add the actual repo as:

```
# create an ssh config override that maps the key to a special hostname
$ cat .ssh/config 
# Netdebug GitHub account
Host github.com-netdebug
         HostName github.com
         User git
         AddKeysToAgent yes
         IdentityFile /home/robs/.ssh/id_rsa_netdebug
# Personal GitHub account
Host github.com-capveg
         HostName github.com
         User git
         AddKeysToAgent yes
         IdentityFile /home/robs/.ssh/id_rsa


# now add the remote with the 'github.com-netdebug' hostname
$ git remote add origin git@github.com-netdebug:netdebug-com/netdebug.git
```
8. DON'T DO THIS ANYMORE - GRR - We need the 'per-project-target' feature which only exists in cargo nightly, so run:
```
rustup override set nightly
```

# NOTES:

In VSCode, CTR+SHIFT+V will generate a preview of markdown
9. If this a new cloud instance, make sure to allow ICMP and ICMP6 in both directions in your security group or 
nothing will work properly!