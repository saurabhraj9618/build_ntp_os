#!/bin/bash

echo $1
echo $2
rm -f /var/log/vehere/ml-alert/merge/summaryData.json
rm -f /tmp/summaryDataTemp.json
inputfile=/var/log/vehere/ml-alert/merge/mergeData-1h.json

cat $inputfile |jq -R 'fromjson?' |jq .flows |jq -c . > /var/log/vehere/ml-alert/merge/mergeData.json

#inputfile=/var/log/vehere/ml-dnsalert/merge/four/mergeData-1h.json

cat /var/log/vehere/ml-alert/merge/mergeData.json |jq -R 'fromjson?' |jq -s . | jq 'unique_by(.sourceIPv4Address,.nDPIL7Protocol,.nDPIL7SubProtocol,.numAppLabel)' |jq .[] > DNS_DATA/uniqueDataList.json

cat DNS_DATA/uniqueDataList.json |jq -c . | while read row; do

#echo $row

#row1=$(echo $(_jq))
#row1=$( echo $row | base64 --decode |jq -r $1)

flowkeyhash=$(echo $row |jq -r '.flowKeyHash')

dpiproto=""
filterList=$(curl -XGET "localhost:9200/logvehere-flows-*/_search?size=1" -d'
{
        "query": {
                "bool": {
			"must": [
                         {"term": { "flows.flowKeyHash": "'"$flowkeyhash"'"}},
                         {"range": { "@timestamp": {"gte": "now-1h/d", "lte": "now"}}}
                     ]
                 }
        }

}' | jq '.hits.hits'| jq .[]._source.flows | jq -c '{
	"dpiProto":.dpiProto,
	"dstAsn":.dstGeoIP.asn,
	"srcAsn":.srcGeoIP.asn
}')

dpiproto=$(echo $filterList |jq -r '.dpiProto')
srcAsn=$(echo $filterList |jq -r '.srcAsn')
dstAsn=$(echo $filterList |jq -r '.dstAsn')


sourceip=$(echo $row |jq -r '.sourceIPv4Address')
#dpiproto=$(echo $row |jq -r '.dpiProto')


#echo $sourceip $dpiproto
#echo "...................."
#echo $flowkeyhash
#echo $dpiproto
#echo $srcAsn
#echo $dstAsn
#echo "..................."


if [[ "$dpiproto" != "" ]]; then

echo $dpiproto

result=$(curl -XGET "localhost:9200/logvehere-flows-*/_search?" -d'
{
	"query": {
		 "bool": {
	 	     "filter": {
	     		"term": { "flows.sourceIPv4Address": "'"$sourceip"'"}
	     	     },
		     "must": [
			 {"term": { "flows.dpiProto": "'"$dpiproto"'"}},
			 {"range": { "@timestamp": {"gte": "now-2h/d", "lte": "now-1h/d"}}}
		     ]
	 	 }
       },
       "aggs" : {
         "stats_packetTotalCount" : { "extended_stats" : { "field" : "flows.packetTotalCount" } },
         "stats_dataByteCount" : { "extended_stats" : { "field" : "flows.dataByteCount" } },
         "stats_reversePacketTotalCount" : { "extended_stats" : { "field" : "flows.reversePacketTotalCount" } },
         "stats_reverseDataByteCount" : { "extended_stats" : { "field" : "flows.reverseDataByteCount" } }
      }
}' | jq '.aggregations' | jq -c .)

result1=$(curl -XGET "localhost:9200/logvehere-flows-*/_search?" -d'
{
        "query": {
                 "bool": {
                     "filter": {
                        "term": { "flows.sourceIPv4Address": "'"$sourceip"'"}
                     },
                     "must": [
                         {"term": { "flows.dpiProto": "'"$dpiproto"'"}},
                         {"range": { "@timestamp": {"gte": "now-9h/d", "lte": "now-1h/d"}}}
                     ]
                 }
       },
       "aggs" : {
         "stats_packetTotalCount" : { "extended_stats" : { "field" : "flows.packetTotalCount" } },
         "stats_dataByteCount" : { "extended_stats" : { "field" : "flows.dataByteCount" } },
         "stats_reversePacketTotalCount" : { "extended_stats" : { "field" : "flows.reversePacketTotalCount" } },
         "stats_reverseDataByteCount" : { "extended_stats" : { "field" : "flows.reverseDataByteCount" } }
      }
}' | jq '.aggregations' | jq -c .)

result2=$(curl -XGET "localhost:9200/logvehere-flows-*/_search?" -d'
{
        "query": {
                 "bool": {
                     "filter": {
                        "term": { "flows.sourceIPv4Address": "'"$sourceip"'"}
                     },
                     "must": [
                         {"term": { "flows.dpiProto": "'"$dpiproto"'"}},
                         {"range": { "@timestamp": {"gte": "now-1d/d", "lte": "now-1h/d"}}}
                     ]
                 }
       },
       "aggs" : {
         "stats_packetTotalCount" : { "extended_stats" : { "field" : "flows.packetTotalCount" } },
         "stats_dataByteCount" : { "extended_stats" : { "field" : "flows.dataByteCount" } },
         "stats_reversePacketTotalCount" : { "extended_stats" : { "field" : "flows.reversePacketTotalCount" } },
         "stats_reverseDataByteCount" : { "extended_stats" : { "field" : "flows.reverseDataByteCount" } }
      }
}' | jq '.aggregations' | jq -c .)

result3=$(curl -XGET "localhost:9200/logvehere-flows-*/_search?" -d'
{
        "query": {
                 "bool": {
                     "filter": {
                        "term": { "flows.sourceIPv4Address": "'"$sourceip"'"}
                     },
                     "must": [
                         {"term": { "flows.dpiProto": "'"$dpiproto"'"}},
                         {"range": { "@timestamp": {"gte": "now-7d/d", "lte": "now-1h/d"}}}
                     ]
                 }
       },
       "aggs" : {
         "stats_packetTotalCount" : { "extended_stats" : { "field" : "flows.packetTotalCount" } },
         "stats_dataByteCount" : { "extended_stats" : { "field" : "flows.dataByteCount" } },
         "stats_reversePacketTotalCount" : { "extended_stats" : { "field" : "flows.reversePacketTotalCount" } },
         "stats_reverseDataByteCount" : { "extended_stats" : { "field" : "flows.reverseDataByteCount" } }
      }
}' | jq '.aggregations' | jq -c .)


echo $row |jq --arg str1 $srcAsn '. + {srcAsn: $str1}' |jq --arg str2 $dstAsn '. + {dstAsn: $str2}' |jq --argjson obj $result '. + {summaryData1h: [$obj]}' | jq --argjson obj1 $result1 '. + {summaryData8h: [$obj1]}' | jq --argjson obj2 $result2 '. + {summaryData1d: [$obj2]}' | jq --argjson obj3 $result3 '. + {summaryData1w: [$obj3]}' | jq -c . >> /tmp/summaryDataTemp.json
fi

done
mv /tmp/summaryDataTemp.json /var/log/vehere/ml-alert/merge/summaryData.json
#rm -f /tmp/summaryDataTemp.json
#echo $result


