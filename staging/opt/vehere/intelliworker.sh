#!/bin/bash

c_zero=0
c_one=1
c_two=2
balance_id=0
probe_id=0
e1000e_driver="e1000e"

ip_addr=$(hostname -i)
jq --arg ip "$ip_addr" '.probe.var_vnfs_probe_ip = $ip' /usr/local/etc/vnfs.json |sponge /usr/local/etc/vnfs.json
chown kibana:kibana /usr/local/etc/vnfs.json
for i in $( ls /sys/class/net ); do echo -n $i , ; cat /sys/class/net/$i/carrier; done | grep -v lo | grep -v Invalid > connected_iface.lst

########## Filtering Monitoring Interface and Assigning it to the Network interface list ##########
ip addr show | awk '/inet.*brd/{print $NF}' > m_iface_temp
sort m_iface_temp > m_iface
rm -f m_iface_temp

ifconfig -a | sed 's/[ \t].*//;/^\(lo\|\)$/d' |awk -F: '{print $1;}'|grep -v lo > all_iface_temp
sort all_iface_temp > all_iface
rm -f all_iface_temp

iw dev | awk '$1=="Interface"{print $2}' > wifi_iface_temp
sort wifi_iface_temp > wifi_iface
rm -f wifi_iface_temp

diff m_iface all_iface |grep ">" | cut -c 3- > diff_iface_temp
diff wifi_iface diff_iface_temp |grep ">" | cut -c 3- > diff_iface
while IFS="" read -r p || [ -n "$p" ]
do
          printf '%s\n' "$p"
          if grep -Fxq "$p ,1" connected_iface.lst
          then
                ifconfig $p promisc
                if grep -Fxq "auto $p" /etc/network/interfaces
                then
                        echo "interface name already exist in interfaces file"
                else
                        echo "auto $p" >> /etc/network/interfaces
                        echo "iface $p inet dhcp" >> /etc/network/interfaces
                        echo  >> /etc/network/interfaces
                fi
         fi

done < diff_iface

############# End Filtering #############

interface_all=$(ifconfig -a | sed 's/[ \t].*//;/^\(lo\|\)$/d' |awk -F: '{print $1;}'|grep -v lo)
interface_d=$(diff m_iface all_iface | grep ">" | cut -c 3-)

for i in $( ls /sys/class/net ); do echo -n $i, ; cat /sys/class/net/$i/carrier; done > connected_iface.lst

#echo "management interface = $interface_m"
driver=$(ethtool -i $interface_d | grep "driver" | cut -c 8-)
echo "interface driver = $driver"
echo "e1000e_driver = $e1000e_driver"

########## Performance Tuning #########
echo 60 > /proc/sys/kernel/watchdog_thresh

PID_L=`ps -eaf | grep /etc/logstash | grep -v grep | awk '{print $2}'`
echo "logstash_prcess_id = $PID_L"

#if [ ! -z "$PID_L" ] ; then
#        renice -n 0 -p $PID_L
#fi
total_memory=$(awk '/^(MemTotal)/{print $2}' /proc/meminfo)
echo "Total Memory = $total_memory"

x=0.03*$total_memory
unoccupied_memory=`echo $x |bc`
echo $unoccupied_memory | xargs printf "%.*f\n" 0 > /proc/sys/vm/min_free_kbytes
echo 0 > /proc/sys/vm/swappiness

####### End Performance Tuning #########

###### Starting While Loop ############
while true;
do
PID1=`ps -eaf | grep vnfs_balance | grep -v grep | awk '{print $2}'`
PID3=`ps -eaf | grep vnfs_probe | grep -v grep | awk '{print $2}'`


echo "balance_process_id = $PID1"
echo "probe_process_id = $PID3"
echo "balance_id = $balance_id"
echo "probe_id = $probe_id"
if [ "$driver"  =  "e1000e" ] ; then
    echo "Driver found match"
fi
if [ -z "$PID3" ] ; then
#        probe_id=`ps -eaf | grep crypto | grep -v grep | awk '{print $2}'`
        if [ $probe_id -ne $c_zero  ] ; then 
            echo "********************** debug 4 ********************"
	     for i in $( ls /sys/class/net ); do echo -n $i , ; cat /sys/class/net/$i/carrier; done | grep -v lo | grep -v Invalid > connected_iface.lst
		diff m_iface all_iface |grep ">" | cut -c 3- > diff_iface_temp
		diff wifi_iface diff_iface_temp |grep ">" | cut -c 3- > diff_iface
		awk '{print $0, ",1"}' m_iface > management.lst
		awk '{print $0, ",0"}' diff_iface > monitoring.lst
		diff management.lst connected_iface.lst |grep ">" | cut -c 3- > connected_iface_temp.lst
		diff monitoring.lst connected_iface_temp.lst |grep ">" | cut -c 3- |grep -v docker> monitoring_temp.lst
		cat monitoring_temp.lst | tr -d " " > /usr/local/etc/iface.monitoring.lst
		capture_iface=$(head -n 1 /usr/local/etc/iface.monitoring.lst | cut -d',' -f1)
		jq --arg iface "pc:$capture_iface" '.probe.probes[0].var_vnfs_capture_interfaces[0] = $iface' /usr/local/etc/vnfs.json |sponge /usr/local/etc/vnfs.json
		jq '.probe.var_vnfs_import_pcap_probe_id = 0' /usr/local/etc/vnfs.json |sponge /usr/local/etc/vnfs.json
		chown kibana:kibana /usr/local/etc/vnfs.json
		rm -f monitoring.lst management.lst connected_iface_temp.lst connected_iface.lst monitoring_temp.lst diff_iface_temp	
            	if [ $driver  =  'e1000e' ] ; then
         	    echo "******************** debug 5 *****************"
                    rmmod e1000e_zc
                    rmmod -f pf_ring
                    modprobe e1000e	
            	fi
            /usr/local/bin/probe/vnfs_probe -i 0 &
            probe_id=0
	    break
        else
	    echo "restart all process"
  	    /usr/local/bin/stopall.sh
  	    /usr/local/bin/startall.sh
	    if [ $balance_id -eq $c_zero ]; then
                sleep 5
		PID2=`ps -eaf | grep vnfs_balance | grep -v grep | awk '{print $2}'`	
                echo "balance_id = $balance_id"
		echo "balance_process_id = $PID2"
                if [ ! -z  "$PID2" ]; then
		    balance_id=$PID2
		    jq '.probe.var_vnfs_import_pcap_probe_id = 4' /usr/local/etc/vnfs.json |sponge /usr/local/etc/vnfs.json
		    chown kibana:kibana /usr/local/etc/vnfs.json
		    break
                else
                    balance_id=$((balance_id+1))
                fi
            elif [ $balance_id -eq $c_one ]; then
                PID2=`ps -eaf | grep vnfs_balance | grep -v grep | awk '{print $2}'`	
                echo "balance_id = $balance_id"
		echo "balance_process_id = $PID2"
                if [ ! -z  "$PID2" ]; then
		    balance_id=$PID2
		    jq '.probe.var_vnfs_import_pcap_probe_id = 4' /usr/local/etc/vnfs.json |sponge /usr/local/etc/vnfs.json
		    chown kibana:kibana /usr/local/etc/vnfs.json
		    break
                else
                    balance_id=$((balance_id+1))
                fi
	    fi
#           PID1=`ps -eaf | grep crypto | grep -v grep | awk '{print $2}'`
	    echo "balance_id = $balance_id"
            echo "balance_process_id = $PID1"
	    if [ ! -z "$PID1" ] ; then
                echo "********************* debug 1 ******************"
	        if [ "$PID1" -ne "$balance_id" ]; then
                        echo "debug 2"	        
 			for i in $( ls /sys/class/net ); do echo -n $i , ; cat /sys/class/net/$i/carrier; done | grep -v lo | grep -v Invalid > connected_iface.lst
                	diff m_iface all_iface |grep ">" | cut -c 3- > diff_iface_temp
                	diff wifi_iface diff_iface_temp |grep ">" | cut -c 3- > diff_iface
               		 awk '{print $0, ",1"}' m_iface > management.lst
                	awk '{print $0, ",0"}' diff_iface > monitoring.lst
                	diff management.lst connected_iface.lst |grep ">" | cut -c 3- > connected_iface_temp.lst
                	diff monitoring.lst connected_iface_temp.lst |grep ">" | cut -c 3- |grep -v docker> monitoring_temp.lst
                	cat monitoring_temp.lst | tr -d " " > /usr/local/etc/iface.monitoring.lst
                	capture_iface=$(head -n 1 /usr/local/etc/iface.monitoring.lst | cut -d',' -f1)
			jq --arg iface "pc:$capture_iface" '.probe.probes[0].var_vnfs_capture_interfaces[0] = $iface' /usr/local/etc/vnfs.json |sponge /usr/local/etc/vnfs.json
			jq '.probe.var_vnfs_import_pcap_probe_id = 0' /usr/local/etc/vnfs.json |sponge /usr/local/etc/vnfs.json
			chown kibana:kibana /usr/local/etc/vnfs.json
			
                	rm -f monitoring.lst management.lst connected_iface_temp.lst connected_iface.lst monitoring_temp.lst diff_iface_temp
			if [ $driver  =  'e1000e' ] ; then
	                    echo "***************** debug 2 ***************"
                            rmmod e1000e_zc
                            rmmod -f pf_ring
                            modprobe e1000e	
                        fi
		        /usr/local/bin/probe/vnfs_probe -i 0 &
			break
                fi
            elif [ $balance_id -eq $c_two ]; then
			for i in $( ls /sys/class/net ); do echo -n $i , ; cat /sys/class/net/$i/carrier; done | grep -v lo | grep -v Invalid > connected_iface.lst
                	diff m_iface all_iface |grep ">" | cut -c 3- > diff_iface_temp
                	diff wifi_iface diff_iface_temp |grep ">" | cut -c 3- > diff_iface
                	awk '{print $0, ",1"}' m_iface > management.lst
                	awk '{print $0, ",0"}' diff_iface > monitoring.lst
                	diff management.lst connected_iface.lst |grep ">" | cut -c 3- > connected_iface_temp.lst
                	diff monitoring.lst connected_iface_temp.lst |grep ">" | cut -c 3- |grep -v docker> monitoring_temp.lst
                	cat monitoring_temp.lst | tr -d " " > /usr/local/etc/iface.monitoring.lst
                	capture_iface=$(head -n 1 /usr/local/etc/iface.monitoring.lst | cut -d',' -f1)
			jq --arg iface "pc:$capture_iface" '.probe.probes[0].var_vnfs_capture_interfaces[0] = $iface' /usr/local/etc/vnfs.json |sponge /usr/local/etc/vnfs.json
                        jq '.probe.var_vnfs_import_pcap_probe_id = 0' /usr/local/etc/vnfs.json |sponge /usr/local/etc/vnfs.json
                        chown kibana:kibana /usr/local/etc/vnfs.json			
                	rm -f monitoring.lst management.lst connected_iface_temp.lst connected_iface.lst monitoring_temp.lst diff_iface_temp
		if [ $driver  =  'e1000e' ] ; then
                    echo "****************** debug 3 **************"
                    rmmod e1000e_zc
                    rmmod -f pf_ring
                    modprobe e1000e	
                fi
		/usr/local/bin/probe/vnfs_probe -i 0 &
		break 
	    fi
        fi
else
        if [ $probe_id -ne $c_zero  ] ; then
            if [ "$PID3" -ne "$probe_id" ]; then	
                echo "debug 6"
                for i in $( ls /sys/class/net ); do echo -n $i , ; cat /sys/class/net/$i/carrier; done | grep -v lo | grep -v Invalid > connected_iface.lst
                diff m_iface all_iface |grep ">" | cut -c 3- > diff_iface_temp
                diff wifi_iface diff_iface_temp |grep ">" | cut -c 3- > diff_iface
                awk '{print $0, ",1"}' m_iface > management.lst
                awk '{print $0, ",0"}' diff_iface > monitoring.lst
                diff management.lst connected_iface.lst |grep ">" | cut -c 3- > connected_iface_temp.lst
                diff monitoring.lst connected_iface_temp.lst |grep ">" | cut -c 3- |grep -v docker> monitoring_temp.lst
                cat monitoring_temp.lst | tr -d " " > /usr/local/etc/iface.monitoring.lst
                capture_iface=$(head -n 1 /usr/local/etc/iface.monitoring.lst | cut -d',' -f1)
		jq --arg iface "pc:$capture_iface" '.probe.probes[0].var_vnfs_capture_interfaces[0] = $iface' /usr/local/etc/vnfs.json |sponge /usr/local/etc/vnfs.json
                jq '.probe.var_vnfs_import_pcap_probe_id = 0' /usr/local/etc/vnfs.json |sponge /usr/local/etc/vnfs.json
                chown kibana:kibana /usr/local/etc/vnfs.json
                rm -f monitoring.lst management.lst connected_iface_temp.lst connected_iface.lst monitoring_temp.lst diff_iface_temp
		if [ $driver  =  'e1000e' ] ; then
	            echo "********************** debug 7 ************"
                    rmmod e1000e_zc
                    rmmod -f pf_ring
                    modprobe e1000e
                fi
                /usr/local/bin/probe/vnfs_probe -i 0 &
            fi
        fi
        probe_id=$PID3
	break
fi
echo "going to sleep for 15s"
sleep 15
done

######### End While Loop ##############
