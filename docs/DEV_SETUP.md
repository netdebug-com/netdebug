# Dev Setup Instructions
1. Create a _dedicated_ github account for netdebug using your netdebug.com email
2. Enable 2FA for that account with both XXX (looking at yubikey) and SMS as a backup
3. Run the git hooks setup script in ./hooks/setup.sh to setup all of your hooks
4. VS code is strongly recommended with a bunch of project defaults built into the repo
    1. Recommended that you install the vscode rpm repo so you get auto 6.1updates!
    2. Recommended packages include : 
5. Setup a new ssh-key only for the new github account (github requires this)
6. On RPM instances, install min packages:
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
sudo dnf install git gcc tmux libpcap fontconfig-devel
```
7. Install required rust tools
```
for p in wasm-pack fmt clippy; do
    cargo install $p
done
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
