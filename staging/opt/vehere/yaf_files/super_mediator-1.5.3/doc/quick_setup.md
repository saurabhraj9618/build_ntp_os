Quick Setup Guide for super_mediator    {#quick_setup}
=====================================

This tutorial is a step-by-step guide of setting up [yaf](../yaf/index.html)
and **super_mediator**.
For a detailed tutorial on **super_mediator** and the different configuration
options, see [this tutorial](sm_guide.html). This particular tutorial takes the DPI data
produced by **yaf** and imports the data into a MySQL database. 
This also enables DNS deduplication in **super_mediator**
This tutorial does not give an example of
how to setup SiLK.  See [this page](../yaf/libyaf/yaf_sm_silk.html) for a tutorial
that includes [SiLK](../silk/index.html).

* [Install Procedure](#install)
  * [Install Tools](#tools)
  * [Setup mysqld](#mysql)
* [Create MySQL Tables](#tables)
* [Configure super_mediator](#sm)
* [Start Tools](#start)

Install Procedure {#install}
===================

Install prerequisites {#tools}
--------------------

    yum groupinstall "Development Tools"
    yum install libpcap-devel pcre-devel mysql-server* mysql-devel*

    *RHEL7 mariadb-server mariadb-devel

Build libfixbuf:
    
    tar -xvzf libfixbuf-1.7.0.tar.gz
    cd libfixbuf-1.7.0
    ./configure
    make
    make install
    
Build **yaf**:
    
    tar -xvzf yaf-2.7.0.tar.gz
    cd yaf-2.7.0
    ./configure --enable-applabel --enable-plugins
    make
    make install
    
Build **super_mediator**:
    
    tar -xvzf super_mediator-1.2.0.tar.gz
    cd super_mediator-1.2.0
    ./configure --with-mysql
    make
    make install
    
Setup mysqld {#mysql}
-------------

    service [mysqld|mariadb] start

Setup a password for the root user:

    /usr/bin/mysqladmin -u root password '<SuperSecretPassword>'

Login to the database (It will prompt you for the password you created in the
last step):

    mysql -u root -p

Create the database you intend to use for **super_mediator**:

    mysql> create database smediator;

Create a user for **super_mediator** to access the database:

    mysql> CREATE USER 'mediator'@'localhost' IDENTIFIED BY '<SuperSecretPassword>';

Giver permissions to user to access only the smediator database:

    mysql> GRANT ALL ON smediator.* TO mediator@'localhost';

Create MySQL Tables {#tables}
--------------------

Use super_table_creator to create all the tables in your database:
    
    /usr/local/bin/super_table_creator --name mediator --pass=<SuperSecretPassword>\
     --database=smediator
    /usr/local/bin/super_table_creator --name mediator --pass=<SuperSecretPassword> \
    --database=smediator --dns-dedup

    
Configure **super_mediator** {#sm}
--------------------------

Create output directories:

    mkdir -p /data/smediator/dpi
    mkdir -p /data/smediator/dns


Create your super_mediator.conf file.  One is installed by default into /usr/local/etc.  The following one will get you started (you should add your <SuperSecretPassword>):
    
    COLLECTOR TCP
       PORT 18000
    COLLECTOR END
    
    #dedup process
    EXPORTER TEXT
       PATH "/data/smediator/dns/yaf2dns"
       DELIMITER "|"
       ROTATE 1200
       DNS_DEDUP_ONLY
       LOCK
       MYSQL_USER "mediator"
       MYSQL_PASSWORD "<SuperSecretPassword>"
       MYSQL_TABLE "dns-dedup"
       MYSQL_DATABASE "smediator"
    EXPORTER END
    
    #dpi 2 database
    EXPORTER TEXT
       PATH "/data/smediator/dpi"
       ROTATE 1200
       MULTI_FILES
       DPI_ONLY
       LOCK
       MYSQL_USER "mediator"
       MYSQL_PASSWORD "<SuperSecretPassword>"
       MYSQL_DATABASE "smediator"
    EXPORTER END
    
    DNS_DEDUP
       MAX_HIT_COUNT 5000
    DNS_DEDUP END
    
    LOGLEVEL DEBUG
    
    LOG "/var/log/super_mediator.log"
    
    PIDFILE "/data/super_mediator.pid"
    
Start tools {#start}
----------------------

Start **super_mediator**

    super_mediator -c /usr/local/etc/super_mediator.conf --daemonize

Confirm **super_mediator** is running:

    ps -ef | grep super

If **super_mediator** is not running, check for any errors:

    cat /var/log/super_mediator.log

Start **YAF**:

    mkdir /var/log/yaf

    export LTDL_LIBRARY_PATH=/usr/local/lib/yaf

Run **YAF** over PCAP file:
    
    /usr/local/bin/yaf
    --in <PCAP FILE> \
    --ipfix tcp \
    --out localhost \
    --log /var/log/yaf/yaf.log \
    --verbose \
    --silk \
    --verbose \
    --ipfix-port=18000 \
    --applabel --max-payload 2048 \
    --plugin-name=/usr/local/lib/yaf/dpacketplugin.so 
    
*OR* Run **YAF** on interface eth0:
    
    /usr/local/bin/yaf
    --in eth0 --live pcap \
    --ipfix tcp \
    --out localhost \
    --log /var/log/yaf/yaf.log \
    --verbose \
    --silk \
    --verbose \
    --ipfix-port=18000 \
    --applabel --max-payload 2048 \
    --plugin-name=/usr/local/lib/yaf/dpacketplugin.so
    
</body>