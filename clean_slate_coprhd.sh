#!/bin/bash
sudo /etc/storageos/storageos stop
sleep 2
echo vagrant | su -c "rm -vrf /data/db/*"
echo vagrant | su -c "rm -vrf /data/zk/*"
echo vagrant | su -c "rm -vrf /data/geodb/*"
sleep 2
echo "Not restarting the services...do what you need to do..."
#echo "Restarting Services after cleaning"
#echo
#sudo /etc/storageos/storageos start
