#!/bin/bash

##install metricbeat 5.5.2
#wget https://artifacts.elastic.co/downloads/beats/metricbeat/metricbeat-5.5.2-amd64.deb
dpkg -i metricbeat-5.5.2-amd64.deb
sudo /bin/systemctl enable metricbeat && \
sudo /bin/systemctl daemon-reload
##update metricbeat config and restart metricbeat

rm -f /etc/metricbeat/metricbeat.yml
cp metricbeat.yml /etc/metricbeat/
chmod 644 /etc/metricbeat/metricbeat.yml

#rm -f /lib/systemd/system/metricbeat.service
cp metricbeat /etc/default/
chmod 646 /etc/default/metricbeat

#cp metricbeat.service /lib/systemd/system/metricbeat.service
chmod 664 /lib/systemd/system/metricbeat.service

sudo /bin/systemctl daemon-reload

##import metricbeat dashboards (for local elasticsearch)
##/usr/share/metricbeat/scripts/import_dashboards -dir /path_to_metricbeat_custom_dashboards

##import metricbeat dashboards (for remote elasticsearch, additional -es parameter specifying remote elasticsearch url)
##/usr/share/metricbeat/scripts/import_dashboards -dir /path_to_metricbeat_custom_dashboards -es http://xx.xx.xx.xx:9200



##---------------------------------------------------------------
## metricbeat index format : logvehere-bt${USER}-%{+yyyy.MM.dd}
## metricbeat type : doc
## processes details can be found in file : metricbeat_processes_custom


