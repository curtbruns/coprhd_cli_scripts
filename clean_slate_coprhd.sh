#!/bin/bash
source ~/coprhd_cli_scripts/coprhd_settings
# Stop Services
echo ${ROOT_PASSWORD} | su -c "/etc/storageos/storageos stop"
# Delete Database and all Data
sleep 2
echo ${ROOT_PASSWORD} | su -c "rm -vrf /data/db/*"
echo ${ROOT_PASSWORD} | su -c "rm -vrf /data/zk/*"
echo ${ROOT_PASSWORD} | su -c "rm -vrf /data/geodb/*"
sleep 2
echo "Not restarting the services...do what you need to do..."
#echo "Restarting Services after cleaning"
#echo
#echo ${ROOT_PASSWORD} | su -c "/etc/storageos/storageos start"
