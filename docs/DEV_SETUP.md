# Dev setup instructions 

1. Create a _dedicated_ github account for netdebug using your netdebug.com email
1. Enable 2FA for that account with both XXX (looking at yubikey) and SMS as a backup
1. Run the git setup script in `./setup-git-clone.sh` to setup git hooks and a commit template
1. Install rust: https://rustup.sh
1. See `electron/README.MD` for instructions to setup `node` and `npm` for UI development
1. VSCode is strongly recommended: https://code.visualstudio.com/download. The repo has VScode config files that recommend good/useful extensions. 
1. Install additional rust tools / utilities: 
   ```
   cargo install wasm-pack   # for wasm development
   cargo install flamegraph  # for flamegraph profiler
   cargo install udeps       # for finding unused dependencies
   rustup component add llvm-tools-preview # llvm tools used for code coverage
   cargo install cargo-llvm-cov # for code coverage (nice utilities that hide low-level commands)
   ```
1. Install Graphite for code review (git/gh frontend)  https://graphite.dev 
   TODO: more details
1. Install graphviz 

## Git setup tips:

* Set up name and email
  ```
  $ git config --global user.name "John Doe"
  $ git config --global user.email john.doe@netdebug.com
  ```
  **NOTE** if you have multiple git hub users on your machine, you can also set
  name and email per clone. Simply use `--local` instead of `--global`. You need
  to repeat this every time you re-clone.

* Set up hooks and commit template: it's already mentioned above but simply run `./setup-git-clone.sh`

* **Merge conflict markers** We recommend, you use `diff3` style merge conflict markers. In addition to the two revisions a normal conflict marker shows, this one will also show the
base revision, which is incredibly helpful in properly resolving the conflict:
  ```
  git config --global merge.conflictstyle diff3
  ```


## Setting up windows & Bash:
1. You must install npcap by hand (for now): https://npcap.com/#download.

**NOTE** : when installing, you MUST check the box "Install Npcap in WinPcap API Compatibility mode" or the
  binaries will not find wpcap.dll at runtime.  You can check this by running ```ldd target/debug/desktop.exe```
  and making sure that wpcap.dll is resolved.  Note that if you reinstall some other tool on the system that
  uses Npcap, e.g., wireshark, you need to make sure this box is re-checked or everything will break.

2. Optional but recommended is to run through git-bash " https://gitforwindows.org/
3. When running ```ssh-add``` to cache your password, you must use ```cmd``` not ```bash``` else it will talk to the wrong ssh-agent instance and will not work as expected.

# Older Dev Setup Instructions -- should revamp
1. Create a _dedicated_ github account for netdebug using your netdebug.com email
2. Enable 2FA for that account with both XXX (looking at yubikey) and SMS as a backup
3. Run the git setup script in `./setup-git-clone.sh` to setup git hooks and a commit template
4. VS code is strongly recommended with a bunch of project defaults built into the repo
    1. Recommended that you install the vscode rpm repo so you get auto 6.1updates!
    2. Recommended packages include : 
5. Setup a new ssh-key only for the new github account (github requires this)
6. On ubuntu server instances:
```
# install rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# get cargo into the path
. ~/.bashrc
# update system to current
sudo apt-get update
sudo apt-get upgrade -y
# install build deps - TODO - just publish a built image
sudo apt-get install -y build-essential libpcap-dev cmake libfontconfig-dev tmux
# Install required rust tools
cargo install wasm-pack
git clone git@github.com:netdebug-com/netdebug
cd netdebug
./build.sh
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