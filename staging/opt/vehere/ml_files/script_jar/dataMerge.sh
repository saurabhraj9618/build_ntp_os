#!/bin/bash

initialize=$(cat /usr/local/etc/mlconfig/mldns-configuration.json|jq .initialize)
firstBaseliningInterval=$(cat /usr/local/etc/mlconfig/mldns-configuration.json|jq .firstBaseliningInterval)
fullBaseliningInterval=$(cat /usr/local/etc/mlconfig/mldns-configuration.json|jq .fullBaseliningInterval)
steppingIntervals=$(cat /usr/local/etc/mlconfig/mldns-configuration.json|jq .steppingIntervals)
no_of_steppingIntervals=$(cat /usr/local/etc/mlconfig/mldns-configuration.json|jq .no_of_steppingIntervals)

x=60*$steppingIntervals
var2=`echo $x |bc`
currentDateTime="$(date +'%Y%m%d%H%M%S')"

path=$(cat /usr/local/etc/vnfs.json|jq -r .probe.var_vnfs_meta_storage_path)
nodepath=/var/cache/logstash/sincedbs
mergeflow=$(cat /usr/local/etc/vnfs.json|jq -r .ml.var_vnfs_ml_netflow_out_path)/merge
mergedns6=$(cat /usr/local/etc/vnfs.json|jq -r .ml.var_vnfs_ml_dns_out_path)/merge/six
mergedns4=$(cat /usr/local/etc/vnfs.json|jq -r .ml.var_vnfs_ml_dns_out_path)/merge/four

dbfile="$nodepath/mlDataMerge.db"
if [ ! -f "$dbfile" ]
then
    touch $dbfile
fi
#cd $path

intervalTime=$var2/60
count=0
iteration=$(cat /usr/local/etc/mlconfig/mldns-configuration.json|jq .iteration)

i=0
echo "Starting while loop."
echo "....................................."
while [[ i -lt "$fullBaseliningInterval" ]]
do
	echo "Inside while loop .. Interval value is $i"
	
	rm -f $mergedns6/mergeData-15m.json
	touch $mergedns6/mergeData-15m.json
	
	find $path/ -name "*.json" -cmin -$steppingIntervals -print0 | while read -d $'\0' file1
        do
	     echo "$file1"
	     inode1=$(stat -c%i $file1)
	     sp="$(grep $inode1 $nodepath/mlDataMerge.db)"
	     echo $sp
	     if [ -z "$sp" ]
	     then
		     echo "node value is $inode1"
	          echo $inode1 >> $nodepath/mlDataMerge.db
	          cat $file1 >> $mergedns6/mergeData-15m.json
	     fi

	done
	
	if [[ "$initialize" == 1 ]]
	then
		find $path/ -cmin -60 |xargs cat > $mergeflow/mergeData-1h.json
                find $path/ -name "*.json" -cmin -60 > $mergedns6/list1.txt
		find $path/ -name "*.json" -cmin -15 > $mergedns6/list2.txt
                grep -vxFf $mergedns6/list2.txt $mergedns6/list1.txt |xargs cat > $mergedns4/mergeData-45m.json
		cp $mergedns6/mergeData-15m.json $mergedns4/
		echo "Enter into the if condition when intialize value is $initialize"
		#iteration=$((iteration+1))
		iteration=$(cat /usr/local/etc/mlconfig/mldns-configuration.json|jq .iteration)
		sleep $var2
		if [[ "$iteration" -ge 8 ]]
		then
			sed -i -e "s|\"iteration\"\:$iteration|\"iteration\"\:0|" /usr/local/etc/mlconfig/mldns-configuration.json
			initialize=$((initialize-1))
			sed -i -e 's|\"initialize\"\:1|\"initialize\"\:0|' /usr/local/etc/mlconfig/mldns-configuration.json
			iteration=0
		fi
	fi

	if [[ "$initialize" == 0 && ("$iteration" -lt 8) ]]
	then
		if [[ "$firstBaseliningInterval" -lt "$fullBaseliningInterval" ]]
		then
			find $path/ -cmin -60 |xargs cat > $mergeflow/mergeData-1h.json
                        find $path/ -name "*.json" -cmin -60 > $mergedns6/list1.txt
                	find $path/ -name "*.json" -cmin -15 > $mergedns6/list2.txt
                	grep -vxFf $mergedns6/list2.txt $mergedns6/list1.txt |xargs cat > $mergedns4/mergeData-45m.json
			cp $mergedns6/mergeData-15m.json $mergedns4/
		#	find . -cmin -$steppingIntervals |xargs cat  > $mergedns4/mergeData-15m.json
			echo  "Stepping interval is $var2 sec."
			sleep $var2
			firstBaseliningInterval=$((firstBaseliningInterval + $intervalTime))
			echo "Baseline Interval is $firstBaseliningInterval sec."
		fi
		if [[ "$firstBaseliningInterval" -ge "$fullBaseliningInterval" ]]
		then
			firstBaseliningInterval=0
			rm -f $dbfile
			touch $dbfile
		fi
	fi
        i=$(($i + $intervalTime))
done

