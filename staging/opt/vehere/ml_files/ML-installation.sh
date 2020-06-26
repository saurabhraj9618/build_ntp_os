#!/bin/bash

###installation of Scala

wget http://downloads.typesafe.com/scala/2.11.7/scala-2.11.7.tgz
tar xaf scala-2.11.7.tgz
sudo mv scala-2.11.7 /usr/lib
sudo ln -s /usr/lib/scala-2.11.7 /usr/lib/scala
sudo export PATH=$PATH:/usr/lib/scala/bin

rm -f scala-2.11.7.tgz
###install sbt #######
#echo "deb https://dl.bintray.com/sbt/debian /" | sudo tee -a /etc/apt/sources.list.d/sbt.list
#sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 2EE0EA64E40A89B84B2DF73499E82A75642AC823
#sudo apt-get update
#sudo apt-get -y --allow-unauthenticated install sbt

sudo dpkg -i sbt-1.0.3.deb

sudo apt-get install -y mmdb-bin
sudo apt-get install -y bc

#wget https://github.com/stedolan/jq/releases/download/jq-1.5/jq-1.5.tar.gz
tar xzf jq-1.5.tar.gz
cd jq-1.5/
./configure && make && sudo make install
###installation of ml-analyzer
cd ..

#tar xaf ml-analyzer.tar.gz

cp script_jar/*.sh ml-analyzer/
chmod +x ml-analyzer/*.sh

#cp script_jar/*.scala ml-analyzer/bin/
#chmod +x ml-analyzer/bin/*.scala

mkdir ml-analyzer/bin/mldns_metastore
mkdir ml-analyzer/bin/mlnetflow_metastore

cp -r script_jar/metastore_db ml-analyzer/bin/mldns_metastore/
cp -r script_jar/metastore_db ml-analyzer/bin/mlnetflow_metastore/

cd ml-analyzer/bin/
sbt package
cd ../../

mkdir -p ml-analyzer/bin/target/scala-2.10/

cp script_jar/*.jar ml-analyzer/bin/target/scala-2.10/
chmod +x ml-analyzer/bin/target/scala-2.10/*.jar

cp script_jar/spark-defaults.conf ml-analyzer/conf/
chmod 644 ml-analyzer/conf/spark-defaults.conf

cp script_jar/*.scala ml-analyzer/bin/
chmod +x ml-analyzer/bin/*.scala

mkdir /usr/local/etc/mlconfig
mkdir /usr/local/etc/mlconfig/mlnetflow-suppressionlist
mkdir /usr/local/etc/mlconfig/mldns-suppressionlist
mkdir /usr/local/etc/mlconfig/mlnetflow-pauselist
mkdir /usr/local/etc/mlconfig/mldns-pauselist

mkdir /var/log/sparkLog
chown -R logstash:logstash /var/log/sparkLog

mkdir /var/log/vehere/ml-dnsalert
mkdir /var/log/vehere/ml-alert
mkdir /var/log/vehere/ml-noalert
mkdir /var/log/vehere/ml-dns-no-alert
mkdir /var/log/vehere/ml-dns-no-alert/merge8
mkdir /var/log/vehere/ml-pauselist
mkdir /var/log/vehere/ml-pauselist/dns
mkdir /var/log/vehere/ml-pauselist/netflow
mkdir /var/log/vehere/ml-dns-no-alert/iterationData
mkdir /var/log/vehere/ml-alert/merge
mkdir /var/log/vehere/ml-alert/filter
mkdir /var/log/vehere/ml-dnsalert/filter
mkdir /var/log/vehere/ml-dnsalert/filter/data
mkdir /var/log/vehere/ml-dnsalert/merge
mkdir /var/log/vehere/ml-dnsalert/merge/four
mkdir /var/log/vehere/ml-dnsalert/merge/six
mkdir /var/log/vehere/tmpmldns
mkdir /var/log/vehere/tmpml
mkdir /var/log/vehere/tmpmldnsnoalert
mkdir /var/log/vehere/tmpmlnoalert
mkdir /var/log/vehere/tmpdns-suppressionlist
mkdir /var/log/vehere/tmpnetflow-suppressionlist

cp script_jar/ml*.json /usr/local/etc/mlconfig/
chown -R logstash:logstash /usr/local/etc/mlconfig

cp script_jar/mldns-whitelist.txt /usr/local/etc/
chown logstash:logstash /usr/local/etc/mldns-whitelist.txt 

cp script_jar/netflowpl.csv /var/log/vehere/ml-pauselist/netflow/
cp script_jar/dnspl.csv /var/log/vehere/ml-pauselist/dns/
cp script_jar/dnssl.csv /var/log/vehere/tmpdns-suppressionlist/
cp script_jar/netflowsl.csv /var/log/vehere/tmpnetflow-suppressionlist/

cd ml-analyzer/bin/
chmod a+rwx . --recursive
cd ../../

cp script_jar/top*.csv ml-analyzer/
cp script_jar/netflow-20190801190653.json /var/log/vehere/ml-noalert/
chown logstash:logstash /var/log/vehere/ml-noalert/netflow-20190801190653.json


cp -r ml-analyzer /usr/local/bin/

chown logstash:logstash /usr/local/bin/ml-analyzer/bin/DNS_DATA
chown logstash:logstash /usr/local/bin/ml-analyzer/DNS_DATA
chmod 744 /usr/local/bin/ml-analyzer/DNS_DATA

chown -R logstash:logstash /usr/local/bin/ml-analyzer/bin/mldns_metastore
chown -R logstash:logstash /usr/local/bin/ml-analyzer/bin/mlnetflow_metastore
chown -R logstash:logstash /var/log/vehere/


cat >> //usr/local/bin/ml-analyzer/bin/load-spark-env.sh <<EOF
export SPARK_LOCAL_IP='127.0.0.1'
EOF

mkdir -p /usr/local/bin/ml-analyzer/assembly/target/scala-2.10
ln -s /usr/local/bin/ml-analyzer/jars /usr/local/bin/ml-analyzer/assembly/target/scala-2.10/jars

cp script_jar/mldns.service /etc/systemd/system/
cp script_jar/mlnetflow.service /etc/systemd/system/
cp script_jar/mldatamerge.service /etc/systemd/system/

sudo /bin/systemctl disable mldns.service && \
sudo /bin/systemctl enable mldns.service && \
sudo /bin/systemctl disable mlnetflow.service && \
sudo /bin/systemctl enable mlnetflow.service && \
sudo /bin/systemctl disable mldatamerge.service && \
sudo /bin/systemctl enable mldatamerge.service && \
sudo /bin/systemctl daemon-reload
