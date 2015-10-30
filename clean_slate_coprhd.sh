#!/bin/bash
source coprhd_settings
# Stop Services
sudo /etc/storageos/storageos stop
# Delete Database and all Data
sleep 2
echo ${ROOT_PASSWORD} | su -c "rm -vrf /data/db/*"
echo ${ROOT_PASSWORD} | su -c "rm -vrf /data/zk/*"
echo ${ROOT_PASSWORD} | su -c "rm -vrf /data/geodb/*"
sleep 2
#echo "Not restarting the services...do what you need to do..."
echo "Restarting Services after cleaning"
echo
sudo /etc/storageos/storageos start
