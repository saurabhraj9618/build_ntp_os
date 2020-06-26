now="$(date +'%d-%m-%Y')"
echo capture-$now
lesstime="$(date +'%d-%m-%Y %H:%M:%S')"
echo $lesstime
newtime="$(date +%s%3N)"
echo $newtime
ptime= date --date '-30 min' 
echo $ptime
p1time="$(date --date '-30 min' +%s%3N)"
echo $p1time
sec=$(date +'%S')


curl -XGET "192.168.2.244:9200/ vnfsdb-12012018/l7/_search?size=10000" -H 'Content-Type: application/json' -d '{"_source": ["_id","_index", "dns.qry_name", "dns.resp_type", "dns.qry_class", "dns.qry_name_len", "dns.qry_type", "dns.a","dns.flags_rcode" ,”dns.count_queries”, “dns.count_answers”], "query": {"constant_score": {"filter": {"bool":{"must":[{"range" :{"timestamp" : {"gt":'$p1time', "lte": '$newtime', "format": "epoch_millis"}}},{"exists":{"field":"dns.qry_name"}}]}}}}}' | jq -cM '.hits.hits[] | ._source.dns  + {"id": ._id} + {"index": ._index}' | jq --arg frame_time $now '. + {frame_time: $frame_time}'| jq --arg frame_len $sec '. + {frame_len: $frame_len}'| jq -cM 'to_entries |  
	map(if .key == "id" 
	then . + {"key":"id"}
	else .
	end
	) |
	map(if .key == "qry_name" 
	then . + {"key":"dns_qry_name"}
	else .
	end
	) |
	map(if .key == "resp_type" 
	then . + {"key":"dns_resp_type"}
	else .
	end 
	) | 
	map(if .key == " qry_class" 
	then . + {"key":"dns_qry_class"}
	else .
	end 
	) |
	map(if .key == " qry_name_len" 
	then . + {"key":"dns_qry_name_len"} 
	else .
	end 
	) |
        map(if .key == " qry_type" 
	then . + {"key":"dns_qry_type"} 
	else .
	end 
	) |
        map(if .key == "a" 
	then . + {"key":"dns_a"} 
	else .
	end 
	) |
        map(if .key == " frame_time" 
	then . + {"key":"frame_time"} 
	else .
	end 
	) |
        map(if .key == " frame_len" 
	then . + {"key":"frame_len"} 
	else .
	end 
	) |
        map(if .key == " count_queries " 
	then . + {"key":"ip_src"} 
	else .
	end 
	) |
        map(if .key == " count_answers " 
	then . + {"key":"ip_dst"} 
	else .
	end 
	) |
        map(if .key == "frame_frame_time_epoch" 
	then . + {"key":"unix_tstamp"} 
	else .
	end 
	) |
       map(if .key == " flags_rcode" 
	then . + {"key":"dns_qry_rcode"} 
	else .
	end 
	) |
from_entries '  | jq -c . > "/home/dipawali/spark-2.0.2-bin-hadoop2.7/bin/DNS_DATA/dns-es1.json"

# /home/dipawali/spark-2.0.2-bin-hadoop2.7/bin/spark-submit --class "org.apache.spot.SuspiciousConnects" --master local /home/dipawali/spark-2.0.2-bin-hadoop2.7/bin/target/scala-2.10/spotmldns.jar --analysis "dns"  --input "/home/dipawali/spark-2.0.2-bin-hadoop2.7/bin/DNS_DATA/Dnsdata27.json"   --dupfactor 1000   --feedback "/home/dipawali/spark-2.0.2-bin-hadoop2.7/bin/feedback.csv"   --ldatopiccount 20 --scored /home/dipawali/spark-2.0.2-bin-hadoop2.7/bin/scores   --threshold 1 --maxresults -1 --esnode "192.168.2.244" --esport "9200"





















