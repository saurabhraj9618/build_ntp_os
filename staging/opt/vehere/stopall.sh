#!/bin/bash
##stopping probe

PID2=`ps -eaf | grep bin/vnfs_probe | grep -v grep | awk '{print $2}'`
if [[ "" !=  "$PID2" ]]; then
  echo "stopping probe ..."
  kill -TERM $PID2
  sleep 5
  kill -9 $PID2
else
  echo "probe is not running .."
fi


##stopping pf_ringctl
while true;
do
    PID4=`ps -eaf | grep vnfs_balance | grep -v grep | awk '{print $2}'`
    if [[ "" !=  "$PID4" ]]; then
        echo "stopping balancer ..."
	/usr/local/bin/pf_ringctl stop
    else
        echo "balancer is not running .."
	break
    fi
done
