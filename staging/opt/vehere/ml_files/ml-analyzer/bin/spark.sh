#!/bin/bash
echo "RUNNING JOB"
export SPARK_HOME=/home/dipawali/spark-2.0.2-bin-hadoop2.7
#export SPARK_CLASSPATH=$SPARK_CLASSPATH:/home/dipawali/spark-2.0.2-bin-hadoop2.7/conf/*

$SPARK_HOME/bin/spark-submit --class "org.apache.spot.SuspiciousConnects" --master local target/scala-2.10/spotmldns.jar --analysis "dns"  --input "/home/dipawali/spark-2.0.2-bin-hadoop2.7/bin/DNS_DATA/Dnsdata26.json"   --dupfactor 1000   --feedback "/home/dipawali/spark-2.0.2-bin-hadoop2.7/bin/feedback.csv"   --ldatopiccount 20 --scored /home/dipawali/spark-2.0.2-bin-hadoop2.7/bin/scores   --threshold 1 --maxresults -1 --esnode "192.168.2.244" --esport "9200"
echo "finished JOB"
