#!/bin/bash

####################################################################
# Assumes simulators have already been downloaded and setup
# as documented in the CoprHD Wiki
####################################################################
coprhd_ip="192.168.100.11"

# Run as Root!
if [[ $UID -ne 0 ]]; then
   echo "Must run as root"
   exit
fi

# Start the SMIs Simulator
cd /opt/storageos/ecom/bin
chmod +x  ECOM
chmod +x  system/ECOM
./ECOM &

INTERVAL=3
COUNT=0
echo "Checking for ECOM Service Starting...."
while [ $COUNT -lt 4 ];
do
   COUNT="$(netstat -anp  | grep -c ECOM)"
   printf "."
   sleep $INTERVAL
done

# Start LDAP Simulator Service
cd /simulator/ldapsvc-1.0.0/bin/
echo "Starting LDAP Simulator Service"
./ldapsvc &
sleep 5
curl -X POST -H "Content-Type: application/json" -d "{\"listener_name\": \"COPRHDLDAPSanity\"}" http://${coprhd_ip}:8082/ldap-service/start


# Start Windows Host Simulator
echo "Starting Windows Simulator"
cd /simulator/win-sim
# Update Provider IP for SMIS Simulator address (running on CoprHD in this setup)
sed -i "s/<provider ip=\"10.247.66.220\" username=\"admin\" password=\"#1Password\" port=\"5989\" type=\"VMAX\"><\/provider>/<provider ip=\"${coprhd_ip}\" username=\"admin\" password=\"#1Password\" port=\"5989\" type=\"VMAX\"><\/provider>/" /simulator/win-sim/config/simulator.xml

./runWS.sh &
sleep 5

# Start VPlex Simulator
echo "Starting VPlex Simulato"
cd /simulator/vplex-simulators-1.0.0.0.41/
./run.sh &
# Need to wait for service to be running
sleep 2
PID=`ps -ef | grep [v]plex_config | awk '{print $2}'`
if [[ -z ${PID} ]]; then
   echo "Vplex_Config Simulator Not running - Fail"
   exit 1
fi
TIMER=1
INTERVAL=3
echo "Waiting for VPlex Simulator to Start..."
while [[ "`netstat -anp | grep 4430 | grep -c ${PID}`" == 0 ]];
do
   if [ $TIMER -gt 10 ]; then
      echo ""
      echo "VPlex Sim did not start!" >&2
      exit 1
    fi
   printf "."
   sleep $INTERVAL
   let TIMER=TIMER+$INTERVAL
done
echo "VPlex Simulator Started!"
