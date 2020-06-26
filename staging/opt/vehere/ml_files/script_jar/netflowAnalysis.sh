#!/bin/bash

path=/var/log/vehere/ml-dnsalert/merge/four
filterpath=/var/log/vehere/ml-alert/filter

#. /usr/local/etc/vnfs.cfg

enable=$(cat /usr/local/etc/vnfs.json| jq  -r .ml.var_vnfs_ml_netflow_service_enable)
if [[ "$enable" == 0 ]]
then
	echo "ML Netflow service is disabled"
	sleep 1
	exit
fi

th=$(cat /usr/local/etc/vnfs.json|jq -r .ml.var_vnfs_ml_netflow_threshold)
dns_path=$(cat /usr/local/etc/vnfs.json|jq -r .ml.var_vnfs_ml_netflow_out_path)
netflow_alert_limit=$(cat /usr/local/etc/vnfs.json|jq -r .ml.var_vnfs_ml_netflow_alert_notification_limit)
st=$(cat /usr/local/etc/vnfs.json|jq .alerts.var_vnfs_alert_suppression_time)


#th=$var_vnfs_ml_netflow_threshold
#netflow_alert_limit=$var_vnfs_ml_netflow_alert_notification_limit
#st=$var_vnfs_alert_suppression_time
suppression_time=${st:1: -2}

th_int=`echo $th |bc`


spath="/usr/local/bin/ml-analyzer"
csvpath="/usr/local/bin/ml-analyzer/DNS_DATA"
cd /usr/local/bin/ml-analyzer
if [[ -s /var/log/vehere/ml-alert/merge/mergeData-1h.json ]]
then
	echo "Please wait.. summary data is being prepared."
	./summaryDataScript.sh &>/dev/null
	echo "Summary data is ready for netflow analysis"

    	cd /usr/local/bin/ml-analyzer/bin
	rm -f ./mlnetflow_metastore/metastore_db/*.lck
	rm -f ./mlnetflow_metastore/*.log
     	./spark-shell --conf "spark.driver.extraJavaOptions=-Dderby.system.home=./mlnetflow_metastore/" --master local[2] -i mlnetflowfilter_probe.scala
    	cat /var/log/vehere/ml-alert/filter/*.json > /usr/local/bin/ml-analyzer/DNS_DATA/mlfilter.json

    	cat /usr/local/bin/ml-analyzer/DNS_DATA/mlfilter.json |jq '{"match_body":.match_body,"ndpiType":.ndpiType, "srcAsn":.srcAsn, "summaryData1h":.summaryData1h, "summaryData8h":.summaryData8h, "summaryData1d":.summaryData1d, "summaryData1w":.summaryData1w, "dpiProtoValue":.ndpiValue, "sessionGap":.sessionGap, "Durationseconds":.Durationseconds, "queryCount":.queryCount, "dstAsn":.dstAsno, "flowEndMilliseconds":.flowEndMilliseconds, "nonEmptyPacketCount":.nonEmptyPacketCount, "reverseNonEmptyPacketCount":.reverseNonEmptyPacketCount, "numAppLabel":.numAppLabel, "flowStartMilliseconds":.flowStartMilliseconds, "protocolIdentifier":.protocolIdentifier, "sourceTransportPort":.sourceTransportPort, "flowDurationMilliseconds":.flowDurationMilliseconds, "destinationTransportPort":.destinationTransportPort, "sourceIPv4Address":.sourceIPv4Address, "destinationIPv4Address":.destinationIPv4Address, "reverseDataByteCount":.reverseDataByteCount, "dataByteCount":.dataByteCount, "reversePacketTotalCount":.reversePacketTotalCount, "packetTotalCount":.packetTotalCount, "flowKeyHash":.flowKeyHash,"flowEndReason":.flowEndReason, "dpiL7Value":.nDPIL7Protocol, "dpiL7SubValue":.nDPIL7SubProtocol}'|jq -c . > "/usr/local/bin/ml-analyzer/DNS_DATA/netflow.json"
else
 echo "Merge Data not generated.."

fi

p=$(cat /usr/local/bin/ml-analyzer/DNS_DATA/netflow.json | jq '{"match_body":.match_body,"flowKeyHash":.flowKeyHash}' | jq -s . )

cd /usr/local/bin/ml-analyzer/bin
if [[ -s /usr/local/bin/ml-analyzer/DNS_DATA/netflow.json ]]
then
	currentDateTime="$(date +'%Y%m%d%H%M%S')"
	touch /var/log/vehere/tmpnetflow-suppressionlist/tmpsuppressionlist.json
	touch /var/log/vehere/ml-pauselist/netflow/tmppauselist.json

	/usr/local/bin/ml-analyzer/bin/spark-submit --class "org.apache.spot.SuspiciousConnects" --master local[6] --driver-memory=10g  target/scala-2.10/mlnetflowanalysis.jar --analysis "flow"  --input "/usr/local/bin/ml-analyzer/DNS_DATA/netflow.json"   --summarydatapath "/var/log/vehere/ml-alert/merge/summaryData.json" --dupfactor 1000   --ldatopiccount 20 --scored /var/log/vehere/tmpml --no_score /var/log/vehere/tmpmlnoalert --pauselist /usr/local/etc/mlconfig/mlnetflow-pauselist --plist /var/log/vehere/ml-pauselist/netflow --threshold $th --maxresults $netflow_alert_limit --esnode "localhost" --esport "9200" --pauseinterval 48 --supression_list /usr/local/etc/mlconfig/mlnetflow-suppressionlist --tmpsupression_list /var/log/vehere/tmpnetflow-suppressionlist --suppressioninterval $suppression_time
        q=$(cat /var/log/vehere/tmpml/*.json | jq -s . ) 
        (echo $p $q | jq -s '[ .[0] + .[1] | group_by(.flowKeyHash)[] | select(length > 1) | add ]' | jq .[] | jq 'del(.flowKeyHash)') | jq -c '{"match_body":.match_body,"boosted_score":.boostedScore,"durationseconds":.durationseconds,"flowkeyhash":.flowKeyHash,"src_word".srcWord,"dst_word":.dstWord,"flow_score":.flowScore,"src_asn":.srcAsn,"dst_asn":.dstAsn,"ndpi_type":.ndpiType,"dpi_protovalue":.dpiProtoValue,"query_count":.queryCount,"session_gap":.sessionGap}'> "/var/log/vehere/ml-alert/netflow-$currentDateTime.json" 
        r=$(cat /var/log/vehere/tmpmlnoalert/*.json | jq -s . ) 
        (echo $p $r | jq -s '[ .[0] + .[1] | group_by(.flowKeyHash)[] | select(length > 1) | add ]' | jq .[] | jq 'del(.flowKeyHash)') | jq -c '{"match_body":.match_body,"boosted_score":.boostedScore,"durationseconds":.durationseconds,"flowkeyhash":.flowKeyHash,"src_word".srcWord,"dst_word":.dstWord,"flow_score":.flowScore,"src_asn":.srcAsn,"dst_asn":.dstAsn,"ndpi_type":.ndpiType,"dpi_protovalue":.dpiProtoValue,"query_count":.queryCount,"session_gap":.sessionGap}'> "/var/log/vehere/ml-noalert/netflow-$currentDateTime.json"
   	rm -rf /var/log/vehere/tmpml/*

   	rm -rf /var/log/vehere/tmpmlnoalert/*

   	rm -rf /var/log/vehere/ml-pauselist/netflow/*
   	cat /usr/local/etc/mlconfig/mlnetflow-pauselist/*.json > /var/log/vehere/ml-pauselist/netflow/pauseList.json

   	rm -rf /var/log/vehere/tmpnetflow-suppressionlist/*
	cat /usr/local/etc/mlconfig/mlnetflow-suppressionlist/*.json > /var/log/vehere/tmpnetflow-suppressionlist/mlsuppressionList.json

else
	echo "Filter data not generated.."
fi
