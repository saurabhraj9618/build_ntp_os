#!/bin/bash 

#. /usr/local/etc/vnfs.cfg

enable=$(cat /usr/local/etc/vnfs.json| jq  -r .ml.var_vnfs_ml_dns_service_enable)
if [[ "$enable" == 0 ]]
then
        echo "ML-DNS service is disabled"
        sleep 1
        exit
fi

th=$(cat /usr/local/etc/vnfs.json|jq -r .ml.var_vnfs_ml_dns_threshold)
dns_path=$(cat /usr/local/etc/vnfs.json|jq -r .ml.var_vnfs_ml_dns_out_path)
dns_alert_limit=$(cat /usr/local/etc/vnfs.json|jq -r .ml.var_vnfs_ml_dns_alert_notification_limit)
st=$(cat /usr/local/etc/vnfs.json|jq .alerts.var_vnfs_alert_suppression_time)

#th=$var_vnfs_ml_dns_threshold
#dns_path=$var_vnfs_ml_dns_out_path
#dns_alert_limit=$var_vnfs_ml_dns_alert_notification_limit
#st=$var_vnfs_alert_suppression_time
suppression_time=${st:1: -2}

initialize=$(cat /usr/local/etc/mlconfig/mldns-configuration.json|jq .initialize)

dns_out_path=${dns_path//\"/}

mpath=/var/log/vehere/ml-dnsalert/merge/four
spath="/usr/local/bin/ml-analyzer"
csvpath="/usr/local/bin/ml-analyzer/DNS_DATA"

th_int=`echo $th |bc`

cat $mpath/mergeData-15m.json |jq -c '{"match_body":.}' > $mpath/mergeData-15min.json

if [[ -s $mpath/mergeData-15min.json ]]
then
	cd /usr/local/bin/ml-analyzer/bin
	rm -f ./mldns_metastore/metastore_db/*.lck
	rm -f ./mldns_metastore/*.log
	./spark-shell --conf "spark.driver.extraJavaOptions=-Dderby.system.home=./mldns_metastore/" --master local[2] -i /usr/local/bin/ml-analyzer/bin/mldnsfilter_probe.scala
	cat /var/log/vehere/ml-dnsalert/filter/data/*.json > $spath/DNS_DATA/new.json
 
cat /usr/local/bin/ml-analyzer/DNS_DATA/new.json|jq -c '{
        "match_body":.match_body,
        "queryScore":.queryScore,
        "query":.query,
        "suffix":.suffix,
        "prefix":.prefix,
        "prefixSuffixRatio":.prefixSuffixRatio,
        "fullQueryIPCount":.fullQueryIPCount,
        "suffixQueryIPCount":.suffixQueryIPCount,
	"reverseNonEmptyPacketCount":.reverseNonEmptyPacketCount,
	"flowEndMilliseconds":.flowEndMilliseconds,
	"destinationTransportPort":.destinationTransportPort,
	"sourceIPv4Address":.sourceIPv4Address,
	"nonEmptyPacketCount":.nonEmptyPacketCount,
	"sourceTransportPort":.sourceTransportPort,
	"flowKeyHash":.flowKeyHash,
	"destinationIPv4Address":.destinationIPv4Address,
	"dnsNXDomain":.dnsNXDomain,
	"dnsQRType": .dnsQRType,"dnsRRSection": .dnsRRSection,"dnsQName": .dnsQName,"dnsQName2": .dnsQName2,"dnsQName3": .dnsQName3,"dnsQName4": .dnsQName4,"dnsQName5": .dnsQName5,"dnsQName6": .dnsQName6,"dnsQName7": .dnsQName7,"dnsQName8": .dnsQName8,"dnsQName9": .dnsQName9,"dnsQName10": .dnsQName10,"dnsQName11": .dnsQName11,"dnsQName12": .dnsQName12,"dnsQName13": .dnsQName13,"dnsQName14": .dnsQName14,"dnsQName15": .dnsQName15,"dnsQName16": .dnsQName16,"dnsQName17": .dnsQName17,"dnsQName18": .dnsQName18,"dnsQName19": .dnsQName19,"dnsQName20": .dnsQName20}'> "$spath/DNS_DATA/dns.json"
else

 echo "Merged data does not exist..... "

fi
rm -f /usr/local/bin/ml-analyzer/DNS_DATA/new.json 


rm -f $csvpath/*.csv

#source /usr/local/etc/vnfs.cfg
#private_ip=" $var_vnfs_private_ip_address"

echo "Starting ML-DNS Analysis."
iteration=$(cat /usr/local/etc/mlconfig/mldns-configuration.json|jq .iteration)
iterationTemp=0
cd $spath
if [[ -s $spath/DNS_DATA/dns.json ]]
then
	echo "inside if condition."
	cd /usr/local/bin/ml-analyzer/bin
        tmpmldnspath=/var/log/vehere/tmpmldns
        tmpmldnsnoalertpath=/var/log/vehere/tmpmldnsnoalert
	mldnspath=/var/log/vehere/ml-dnsalert
        mldnsnoalertpath=/var/log/vehere/ml-dns-no-alert
        if [[ ("$initialize" == 1) && ("$iteration" -lt 8) ]]
	then
	    echo "Starting 1st Iteration..."
            echo "Current Iteration value $iteration"
	    iterationTemp=$((iteration+1))
#	    if [[ "$iterationTemp" == 8 ]]
#	    then
#		sed -i -e "s|\"iteration\"\:$iteration|\"iteration\"\:0|" /usr/local/etc/mlconfig/mldns-configuration.json
#            else
#     		sed -i -e "s|\"iteration\"\:$iteration|\"iteration\"\:$iterationTemp|" /usr/local/etc/mlconfig/mldns-configuration.json
#	    fi
            sleep 10
            if [[ "$iterationTemp" == 1 ]]
            then
	    	./spark-submit --class "org.apache.spot.SuspiciousConnects" --master local[8] target/scala-2.10/mldnsanalysis.jar --condition 1 --pauseinterval 48 --boostvar 100 --analysis "dns"  --input "$spath/DNS_DATA/dns.json"  --dupfactor 100   --feedback "/var/log/vehere/feedback" --toplist "/usr/local/bin/ml-analyzer/top-1m.csv" --tld "/usr/local/bin/ml-analyzer/top-1m-TLD.csv" --ldatopiccount 20 --ldaalpha 3.5 --ldabeta 1.01 --ldamaxiterations 20 --ldaoptimizer "em" --scored $tmpmldnspath --no_score $tmpmldnsnoalertpath --threshold $th_int --maxresults $dns_alert_limit

	    	currentDateTime="$(date +'%Y%m%d%H%M%S')"
	    	fileCount="$(ls $tmpmldnspath | wc -l)"
            	fileCount2="$(ls $tmpmldnsnoalertpath |wc -l)"
                if [[ "$fileCount2" != "0" ]]; then
                        cat $tmpmldnsnoalertpath/*.json > "/var/log/vehere/ml-dns-no-alert/file-$currentDateTime.json"
                        rm -f $tmpmldnsnoalertpath/*
                fi

		if [[ "$fileCount" != "0" ]] 
		then
                        sed -i -e "s|\"iteration\"\:$iteration|\"iteration\"\:$iterationTemp|" /usr/local/etc/mlconfig/mldns-configuration.json
			sleep 10
			cat $tmpmldnspath/*.json > "/var/log/vehere/ml-dns-no-alert/iterationData/file-$iterationTemp.json"

			find /var/log/vehere/ml-dns-no-alert/iterationData/ -cmin -1440 |xargs cat  > /var/log/vehere/ml-dns-no-alert/merge8/mergeData-8i.json
                	rm -f $tmpmldnspath/*
            	else
                	echo "$tmpmldnspath is empty."
                fi
	    else
		    touch /var/log/vehere/tmpdns-suppressionlist/mlsuppression.json
		    touch /var/log/vehere/ml-pauselist/dns/mlpauselist.json
             	./spark-submit --class "org.apache.spot.SuspiciousConnects" --master local[8] target/scala-2.10/mldnsanalysis.jar --condition 2 --pauseinterval 48 --boostvar 100 --analysis "dns"  --input "$spath/DNS_DATA/dns.json"  --whitelist "/usr/local/etc/mldns-whitelist.txt" --dupfactor 100   --feedback "/var/log/vehere/feedback" --toplist "/usr/local/bin/ml-analyzer/top-1m.csv" --tld "/usr/local/bin/ml-analyzer/top-1m-TLD.csv" --ldatopiccount 20 --ldaalpha 3.5 --ldabeta 1.01 --ldamaxiterations 20 --ldaoptimizer "em" --scored $tmpmldnspath --no_score $tmpmldnsnoalertpath --mergeitem8 "/var/log/vehere/ml-dns-no-alert/merge8/mergeData-8i.json" --pauselist /usr/local/etc/mlconfig/mldns-pauselist --plist /var/log/vehere/ml-pauselist/dns --threshold $th_int --maxresults $dns_alert_limit --supression_list /usr/local/etc/mlconfig/mldns-suppressionlist --tmpsupression_list /var/log/vehere/tmpdns-suppressionlist --suppressioninterval $suppression_time
 		rm -rf /var/log/vehere/ml-pauselist/dns/*
		cat /usr/local/etc/mlconfig/mldns-pauselist/*.json > /var/log/vehere/ml-pauselist/dns/pauseList.json
                rm -rf /var/log/vehere/tmpdns-suppressionlist/*
                cat /usr/local/etc/mlconfig/mldns-suppressionlist/*.json > /var/log/vehere/tmpdns-suppressionlist/mlsuppressionList.json
                currentDateTime="$(date +'%Y%m%d%H%M%S')"
            	fileCount="$(ls $tmpmldnspath | wc -l)"
		fileCount2="$(ls $tmpmldnsnoalertpath |wc -l)"
            	if [[ "$fileCount2" != "0" ]]; then
                        cat $tmpmldnsnoalertpath/*.json > "/var/log/vehere/ml-dns-no-alert/file-$currentDateTime.json"
                        rm -f $tmpmldnsnoalertpath/*
            	fi

            	if [[ "$fileCount" != "0" ]]; then
                	 if [[ "$iterationTemp" -le 8 ]]
			 then
				 sed -i -e "s|\"iteration\"\:$iteration|\"iteration\"\:$iterationTemp|" /usr/local/etc/mlconfig/mldns-configuration.json
			  fi
			  sleep 10

			cat $tmpmldnspath/*.json > "/var/log/vehere/ml-dns-no-alert/iterationData/file-$iterationTemp.json"

                	find /var/log/vehere/ml-dns-no-alert/iterationData/ -cmin -1440 |xargs cat  > /var/log/vehere/ml-dns-no-alert/merge8/mergeData-8i.json
                	rm -f $tmpmldnspath/*
            	else
                	echo "$tmpmldnspath is empty."
                fi

	  fi

	elif [[ "$initialize" == 0 ]]; then
	    echo "Starting alert genetaion process."
	    touch /var/log/vehere/ml-pauselist/dns/mlpauselist.json
	    touch /var/log/vehere/tmpdns-suppressionlist/mlsuppression.json
	    fileCount1="$(find $mldnspath -type f | wc -l)"
	    if [[ "$fileCount1" -ge 8 ]]; then
	       cat `ls -lrt /var/log/vehere/ml-dnsalert/file-*.json | awk '{if ($5 != 0) print $9}' |tail -8` > /var/log/vehere/ml-dns-no-alert/merge8/mergeData-8i.json
#               find /var/log/vehere/ml-dnsalert/ -name "file-*.json" -cmin -1440 |xargs cat  > /var/log/vehere/ml-dns-no-alert/merge8/mergeData-8i.json
            else
		cat `ls -lrt /var/log/vehere/ml-dns-no-alert/file-*.json | awk '{if ($5 != 0) print $9}' |tail -8` > /var/log/vehere/ml-dns-no-alert/merge8/mergeData-8i.json
#            	find /var/log/vehere/ml-dns-no-alert/ -name "file-*.json" -cmin -120 |xargs cat  > /var/log/vehere/ml-dns-no-alert/merge8/mergeData-8i.json
            fi

	    ./spark-submit --class "org.apache.spot.SuspiciousConnects" --master local[8] target/scala-2.10/mldnsanalysis.jar --condition 2 --pauseinterval 48 --boostvar 100 --analysis "dns"  --input "$spath/DNS_DATA/dns.json"  --whitelist "/usr/local/etc/mldns-whitelist.txt" --dupfactor 100   --feedback "/var/log/vehere/feedback" --toplist "/usr/local/bin/ml-analyzer/top-1m.csv" --tld "/usr/local/bin/ml-analyzer/top-1m-TLD.csv" --ldatopiccount 20 --ldaalpha 3.5 --ldabeta 1.01 --ldamaxiterations 20 --ldaoptimizer "em" --scored $tmpmldnspath --no_score $tmpmldnsnoalertpath --mergeitem8 "/var/log/vehere/ml-dns-no-alert/merge8/mergeData-8i.json" --pauselist /usr/local/etc/mlconfig/mldns-pauselist --plist /var/log/vehere/ml-pauselist/dns --threshold $th_int --maxresults $dns_alert_limit --supression_list /usr/local/etc/mlconfig/mldns-suppressionlist --tmpsupression_list /var/log/vehere/tmpdns-suppressionlist --suppressioninterval $suppression_time
	    rm -rf /var/log/vehere/ml-pauselist/dns/*
	    cat /usr/local/etc/mlconfig/mldns-pauselist/*.json > /var/log/vehere/ml-pauselist/dns/pauseList.json
            rm -rf /var/log/vehere/tmpdns-suppressionlist/*
            cat /usr/local/etc/mlconfig/mldns-suppressionlist/*.json > /var/log/vehere/tmpdns-suppressionlist/mlsuppressionList.json
            currentDateTime="$(date +'%Y%m%d%H%M%S')"
	    fileCount="$(ls $tmpmldnspath | wc -l)"
            fileCount2="$(ls $tmpmldnsnoalertpath |wc -l)"
	    if [[ "$fileCount2" != "0" ]]; then
                        cat $tmpmldnsnoalertpath/*.json | jq -c '{"match_body":.match_body,"prefixsuffix_ratio":.prefixSuffixRatio,"suffixquery_ipcount":.suffixQueryIPCount,"fullquery_ipcount":.fullQueryIPCount,"prefix":.prefix,"suffix":.suffix,"word":.word,"dns_score":.dnsScore,"boosted_value":.boostedValue,"priority":.priority,"boosted_score":.boostedScore,"query_score":.queryScore,"dns_nxdomain":.dnsNXDomain,"dns_qname":.dnsQName,"fullquery_entropy":.fullQueryEntropy}'> "/var/log/vehere/ml-dns-no-alert/file-$currentDateTime.json"
                        rm -f $tmpmldnsnoalertpath/*
            fi

	    if [[ "$fileCount" != "0" ]]; then
    		cat $tmpmldnspath/*.json | jq -c '{"match_body":.match_body,"prefixsuffix_ratio":.prefixSuffixRatio,"suffixquery_ipcount":.suffixQueryIPCount,"fullquery_ipcount":.fullQueryIPCount,"prefix":.prefix,"suffix":.suffix,"word":.word,"dns_score":.dnsScore,"boosted_value":.boostedValue,"priority":.priority,"boosted_score":.boostedScore,"query_score":.queryScore,"dns_nxdomain":.dnsNXDomain,"dns_qname":.dnsQName,"fullquery_entropy":.fullQueryEntropy}'> "/var/log/vehere/ml-dnsalert/file-$currentDateTime.json"
		rm -f $tmpmldnspath/*
	    else
    		echo "$tmpmldnspath is empty."
	    fi
       fi
else

  echo "ML-DNS Process is not completed as filter data does not exist."

fi
rm -rf $csvpath/*.csv

