#!/usr/bin/env python3

from typing import List
import urllib.request
import json
import subprocess
import sys

RunAsUser = "deploy"

# get list of servers
# req = urllib.request.Request(url="https://topology.netdebug.com/static/vantages.json",
# headers={'User-Agent': 'Mozilla/5.0'})
# servers = json.load(urllib.request.urlopen(req))
servers = [
    "nyc1.topology.netdebug.com",
    "dal1.topology.netdebug.com",
    "bay1.topology.netdebug.com",
]


def ssh_cmd(server: str, cmd: List[str]):
    new_cmd = ["ssh", f"root@{server}"]
    new_cmd.extend(cmd)
    print(f"Running {new_cmd} on {server}")
    subprocess.run(new_cmd, check=False)


# The directory that contains the script as
# absolute path with symlinks resovled
script_dir = sys.path[0]

for server in servers:
    # Assumes that a server has already been manually prep'd via
    # ./current/scripts/prep_server.sh and has already successfully unpacked
    # a deployment tarball (e.g., with ./$VERSION/targets/release/webserver) in
    # ~deploy
    #
    # Assumes that the person running this has credentials to ssh in as
    # root (fixme??)
    print(f"Updating server {server}")
    # running as root, needs root to kill

    # TODO: need to consider a drain/undrain here so that user traffic to the console
    # isn't effected
    subprocess.run(
        [
            "scp",
            f"{script_dir}/update_webserver.sh",
            f"root@{server}:/home/deploy/",
        ],
        check=True,
    )
    ssh_cmd(server, ["systemctl", "stop", "netdebug-webserver"])

    ssh_cmd(
        server,
        ["su", "-", RunAsUser, "-c", "~deploy/update_webserver.sh"],
    )
    # add the sleep to avoid a race
    # tried 'systemctl is-failed $foo' but it didn't seem to exit with the right
    # error code to trigger the check=False part of subprocess.run()
    # TODO: cross fingers to hope this is robust...
    ssh_cmd(
        server,
        [
            "systemctl",
            "restart",
            "netdebug-webserver",
            "&&",
            "sleep",
            "1",
            "&&",
            "systemctl",
            "status",
            "netdebug-webserver",
        ],
    )

    print(f"Done updating server {server}")
    print("##########################################################")

print(f"##################### Done {len(servers)} servers ###########################")
