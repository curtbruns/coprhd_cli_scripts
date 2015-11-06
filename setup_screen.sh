#! /bin/bash
# Setup screen process to capture the logging of the CoprHD
# modules so we can scan through them 
NL=`echo -ne '\015'`
SCREEN_NAME=${SCREEN_NAME:-coprhd}

echo "Starting Screen"
# Screen 0
screen -h 5000 -d -m -S $SCREEN_NAME -t shell -s /bin/bash

# Screens 1..x
count=1
for service in apisvc authsvc dbsvc controllersvc syssvc portalsvc
do
  screen -h 5000 -S $SCREEN_NAME -X screen -t $service
  echo "Starting ${service}"
  screen -S $SCREEN_NAME -p ${count} -h 5000 -X stuff "tail -f /opt/storageos/logs/${service}.log"$NL
  count=$((count+1))
done


