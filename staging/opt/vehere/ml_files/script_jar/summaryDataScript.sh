#!/bin/bash

echo $1
echo $2
rm -f /var/log/vehere/ml-alert/merge/summaryData.json
rm -f /tmp/summaryDataTemp.json
inputfile=/var/log/vehere/ml-alert/merge/mergeData-1h.json

cat $inputfile |jq -R 'fromjson?' |jq '{"match_body":.}' |jq '{"match_body":.match_body,"id":.match_body.session.id,"src_ip":.match_body.network.src_ip,"dpi_protocol":.match_body.session.dpi_protocol,"dpi_num_master_protocol":.match_body.session.dpi_num_master_protocol,"dpi_num_app_protocol":.match_body.session.dpi_num_app_protocol,"num_app_protocol":.match_body.session.num_app_protocol}'|jq -c . > /var/log/vehere/ml-alert/merge/mergeData.json

#inputfile=/var/log/vehere/ml-dnsalert/merge/four/mergeData-1h.json

cat /var/log/vehere/ml-alert/merge/mergeData.json |jq -R 'fromjson?' |jq -s . | jq 'unique_by(.src_ip,.dpi_num_master_protocol,.dpi_num_app_protocol,.num_app_protocol)' |jq .[] > DNS_DATA/uniqueDataList.json

cat DNS_DATA/uniqueDataList.json |jq -c . | while read row; do

echo $row

#row1=$(echo $(_jq))
#row1=$( echo $row | base64 --decode |jq -r $1)

id=$(echo $row |jq -r '.id')

dpiproto=""
filterList=$(curl -XGET "localhost:9200/logvehere-probe-*/_search?size=1" -d'
{
        "query": {
                "bool": {
			"must": [
                         {"term": { "session.id": "'"$id"'"}},
                         {"range": { "@timestamp": {"gte": "now-1h/d", "lte": "now"}}}
                     ]
                 }
        }

}' | jq '.hits.hits'| jq .[]._source.network | jq -c '{
	"dstAsn":.dst_geo_ip.asn,
	"srcAsn":.src_geo_ip.asn
}')

srcAsn=$(echo $filterList |jq -r '.srcAsn')
dstAsn=$(echo $filterList |jq -r '.dstAsn')


sourceip=$(echo $row |jq -r '.src_ip')
dpiproto=$(echo $row |jq -r '.dpi_protocol')


#echo $sourceip $dpi_protocol
echo "...................."
echo $id
echo $dpiproto
echo $srcAsn
echo $dstAsn
echo "..................."


if [[ "$dpiproto" != "" ]]; then

#echo $dpi_protocol

result=$(curl -XGET "localhost:9200/logvehere-probe-*/_search?" -d'
{
	"query": {
		 "bool": {
	 	     "filter": {
	     		"term": { "network.src_ip": "'"$sourceip"'"}
	     	     },
		     "must": [
			 {"term": { "session.dpi_protocol": "'"$dpiproto"'"}},
			 {"range": { "@timestamp": {"gte": "now-2h/d", "lte": "now-1h/d"}}}
		     ]
	 	 }
       },
       "aggs" : {
         "stats_transmitted_packets" : { "extended_stats" : { "field" : "session.transmitted_packets" } },
         "stats_transmitted_bytes" : { "extended_stats" : { "field" : "session.transmitted_bytes" } },
         "stats_received_packets" : { "extended_stats" : { "field" : "session.received_packets" } },
         "stats_received_bytes" : { "extended_stats" : { "field" : "session.received_bytes" } }
      }
}' | jq '.aggregations' | jq -c .)

result1=$(curl -XGET "localhost:9200/logvehere-probe-*/_search?" -d'
{
        "query": {
                 "bool": {
                     "filter": {
                        "term": { "network.src_ip": "'"$sourceip"'"}
                     },
                     "must": [
                         {"term": { "session.dpi_protocol": "'"$dpiproto"'"}},
                         {"range": { "@timestamp": {"gte": "now-9h/d", "lte": "now-1h/d"}}}
                     ]
                 }
       },
       "aggs" : {
         "stats_transmitted_packets" : { "extended_stats" : { "field" : "session.transmitted_packets" } },
         "stats_transmitted_bytes" : { "extended_stats" : { "field" : "session.transmitted_bytes" } },
         "stats_received_packets" : { "extended_stats" : { "field" : "session.received_packets" } },
         "stats_received_bytes" : { "extended_stats" : { "field" : "session.received_bytes" } }
      }
}' | jq '.aggregations' | jq -c .)

result2=$(curl -XGET "localhost:9200/logvehere-probe-*/_search?" -d'
{
        "query": {
                 "bool": {
                     "filter": {
                        "term": { "network.src_ip": "'"$sourceip"'"}
                     },
                     "must": [
                         {"term": { "session.dpi_protocol": "'"$dpiproto"'"}},
                         {"range": { "@timestamp": {"gte": "now-1d/d", "lte": "now-1h/d"}}}
                     ]
                 }
       },
       "aggs" : {
         "stats_transmitted_packets" : { "extended_stats" : { "field" : "session.transmitted_packets" } },
         "stats_transmitted_bytes" : { "extended_stats" : { "field" : "session.transmitted_bytes" } },
         "stats_received_packets" : { "extended_stats" : { "field" : "session.received_packets" } },
         "stats_received_bytes" : { "extended_stats" : { "field" : "session.received_bytes" } }
      }
}' | jq '.aggregations' | jq -c .)

result3=$(curl -XGET "localhost:9200/logvehere-probe-*/_search?" -d'
{
        "query": {
                 "bool": {
                     "filter": {
                        "term": { "network.src_ip": "'"$sourceip"'"}
                     },
                     "must": [
                         {"term": { " session.dpi_protocol": "'"$dpiproto"'"}},
                         {"range": { "@timestamp": {"gte": "now-7d/d", "lte": "now-1h/d"}}}
                     ]
                 }
       },
       "aggs" : {
         "stats_transmitted_packets" : { "extended_stats" : { "field" : "session.transmitted_packets" } },
         "stats_transmitted_bytes" : { "extended_stats" : { "field" : "session.transmitted_bytes" } },
         "stats_received_packets" : { "extended_stats" : { "field" : "session.received_packets" } },
         "stats_received_bytes" : { "extended_stats" : { "field" : "session.received_bytes" } }
      }
}' | jq '.aggregations' | jq -c .)


echo $row |jq --arg str1 $srcAsn '. + {srcAsn: $str1}' |jq --arg str2 $dstAsn '. + {dstAsn: $str2}' |jq --argjson obj $result '. + {summaryData1h: [$obj]}' | jq --argjson obj1 $result1 '. + {summaryData8h: [$obj1]}' | jq --argjson obj2 $result2 '. + {summaryData1d: [$obj2]}' | jq --argjson obj3 $result3 '. + {summaryData1w: [$obj3]}' | jq -c . >> /tmp/summaryDataTemp.json
fi

done
mv /tmp/summaryDataTemp.json /var/log/vehere/ml-alert/merge/summaryData.json
#rm -f /tmp/summaryDataTemp.json
#echo $result


