#!/bin/bash

##Stopping suricata
PID1=`ps -eaf | grep bin/suricata | grep -v grep | awk '{print $2}'`
if [[ "" !=  "$PID1" ]]; then
  echo "stopping suricata ..."
  /bin/systemctl stop suricata
  rm -f /var/run/suricata.pid
else
  echo "suricata is not running .."
fi


##stopping yaf, spread
PID2=`ps -eaf | grep bin/yaf | grep -v grep | awk '{print $2}'`
if [[ "" !=  "$PID2" ]]; then
  echo "stopping yaf ..."
  kill -TERM $PID2
  sleep 5
  kill -9 $PID2
else
  echo "yaf is not running .."
fi

sleep 2
PID3=`ps -eaf | grep spread | grep -v grep | awk '{print $2}'`
if [[ "" !=  "$PID3" ]]; then
  echo "stopping spread ..."
  kill -9 $PID3
else
  echo "spread is not running .."
fi


##stopping pf_ringctl
while true;
do
    PID4=`ps -eaf | grep vnfs_balance | grep -v grep | awk '{print $2}'`
    if [[ "" !=  "$PID4" ]]; then
        echo "stopping balancer ..."
	/usr/local/bin/pf_ringctl stop
    else
        echo "zc-balancer is not running .."
	break
    fi
done
