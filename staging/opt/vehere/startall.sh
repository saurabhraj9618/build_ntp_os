#!/bin/bash

##starting balancer
PID1=`ps -eaf | grep vnfs_probe | grep -v grep | awk '{print $2}'`
if [[ "" !=  "$PID1" ]]; then
  echo "probe is already running..."
else
  echo "starting probe.."
  /usr/local/bin/pf_ringctl start
  sleep 10
fi






