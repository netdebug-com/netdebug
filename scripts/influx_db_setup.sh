#!/bin/bash


## DONT INSTALL THE LOCAL INFLUXDB SERVER - JUST USE THE CLOUD
# get + install package + systemd service
# curl -O https://dl.influxdata.com/influxdb/releases/influxdb2_2.7.4-1_amd64.deb
#sudo dpkg -i influxdb2_2.7.4-1_amd64.deb
#sudo service influxdb start

### DO install the CLI
# get, unpack, and install the cli (yes, it's just a 'cp' !?)
wget https://dl.influxdata.com/influxdb/releases/influxdb2-client-2.3.0-linux-amd64.tar.gz
tar xzvf influxdb2-client-2.3.0-linux-amd64.tar.gz
cp influxdb2-client-2.3.0-linux-amd64/influx /usr/local/bin




