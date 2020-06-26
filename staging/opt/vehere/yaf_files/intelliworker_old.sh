#!/bin/bash

while true;
do
PID1=`ps -eaf | grep vnfs_balance | grep -v grep | awk '{print $2}'`
PID2=`ps -eaf | grep bin/suricata | grep -v grep | awk '{print $2}'`
PID3=`ps -eaf | grep spread | grep -v grep | awk '{print $2}'`
PID4=`ps -eaf | grep bin/yaf | grep -v grep | awk '{print $2}'`

if [[ "" == "$PID1" || "" == "$PID2" || "" == "$PID3" || "" == "$PID4" ]]; then
	echo "restart all process"
  	/usr/local/bin/stopall.sh
  	/usr/local/bin/startall.sh
fi
sleep 60
done

