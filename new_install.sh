#! /bin/bash
echo "Removing CoprHD Controller"
sudo rpm -e storageos

echo "RPMs available:"
ls -al "/home/vagrant/source/coprhd_from_mac/coprhd-controller/build/RPMS/x86_64/"

echo "Now - you need sudo rpm -Uvh one of those files above"
echo "Dir is: /home/vagrant/source/coprhd_from_mac/coprhd-controller/build/RPMS/x86_64/"
echo "IF you want to wipe, use the clean_slate script in Home Dir"
