#!/bin/bash

##starting balancer
PID1=`ps -eaf | grep vnfs_balance | grep -v grep | awk '{print $2}'`
if [[ "" !=  "$PID1" ]]; then
  echo "zc-balancer is already running..."
else
  echo "starting zc-balancer.."
  /usr/local/bin/pf_ringctl start
  sleep 10
fi
#sleep 10
##starting suricata
PID2=`ps -eaf | grep bin/suricata | grep -v grep | awk '{print $2}'`
if [[ "" !=  "$PID2" ]]; then
  echo "suricata is already running..."
else
  echo "starting suricata ..."
  /bin/systemctl stop suricata
  rm -f /var/run/suricata.pid
  sleep 2
  /bin/systemctl start suricata
fi

##starting spread
PID3=`ps -eaf | grep spread | grep -v grep | awk '{print $2}'`
if [[ "" !=  "$PID3" ]]; then
  echo "spread is already running..."
else
  echo "starting spraed ..."
  mkdir /var/run/spread
  chown logstash:logstash /var/run/spread
  /usr/local/sbin/spread -c /usr/local/etc/spread.conf &
fi
sleep 1
##starting yaf
PID4=`ps -eaf | grep bin/yaf | grep -v grep | awk '{print $2}'`
if [[ "" !=  "$PID4" ]]; then
  echo "yaf is already running..."
else
  echo "starting yaf ..."
  /usr/local/bin/yaf --ndpi --ndpi-protocol-file /usr/local/etc/protos.txt --entropy --become-user logstash --become-group logstash --config /usr/local/etc/yaf.init --daemonize
fi







