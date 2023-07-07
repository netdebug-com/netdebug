# Linux network debugging

## Wifi
iwconfig
lspci -vv -s 0c:00.0  # replace with busid of wifi
watch -n 1 cat /proc/net/wireless
sudo lshw -C network

## Network Manager commands
nmcli device wifi list
nmcli connection show $ESSID


# Windows
netsh wlan show drivers
netsh wlan show interface


# Reminder

CTR+SHIFT+V to preview markdown in VSCode