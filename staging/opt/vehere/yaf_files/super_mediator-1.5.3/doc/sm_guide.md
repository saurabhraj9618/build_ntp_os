super_mediator Tutorial  {#sm}
=========================

* [Overview](#overview)
* [Dependencies](#deps)
* [Install](#install)
* [Getting Started](#start)
    * [Common Warnings and Errors](#common)
    * [Interpreting YAF output](#interpret)
    * [Using **yafscii**](#yafscii)
* [**super_mediator** Command Line](#commandline)
* [Configuration File](#configfile)
* [IPFIX File Example](#ipfixfile)
    * [Exporter 1 - SiLK Exporter](#exp1)
    * [Exporter 2 - DNS Deduplication](#exp2)
    * [Exporter 3 - MULTIFILES](#exp3)
        * [Manual Import to Database](#manualimport)
        * [Auto Import Configuration](#autoimport)
        * [Enable De-duplication per flow](#dedupperflow)
    * [Exporter 4 - Custom](#exp4)
* [MySQL Bonus - Correlating Exporters](#correlate)

Overview {#overview}
==========

What is super_mediator?
------------------------

**super_mediator** is an IPFIX mediator that ingests IPFIX data from YAF 
(via TCP, UDP, file(s), Spread, etc.) and exports to one or more collectors 
such as SiLK, CSV files, JSON files, or a MySQL database.  Like a traditional IPFIX 
mediator, **super_mediator** can filter, modify, and aggregate the data
as it passes through.

Why do you need a mediator?
-----------------------------

You don't, if you just want to traditional flow data and don't need to 
modify, filter, or aggregate it any way.  The standard tool
chain works just fine.  You will typically run YAF exporting IPFIX over TCP
to rwflowpack which either writes flow data locally to your repository or
sends it back to your data repository hosted on a separate server.
[See the SiLK Install Guide](../silk/install-handbook.html)

**super_mediator** is used to collect the Deep Packet Inspection (DPI) data
elements that YAF exports and write them in a format that can be used for
bulk loading into a database or rotating CSV files.

**super_mediator** can be used to export to Orcus, a passive DNS analysis system.
You don't NEED **super_mediator** to use Orcus.  YAF can export directly
to Orcus if your flow sensor is dedicated to monitoring DNS traffic.  However,
if you have single sensor that you hope to collect traditional flow data
AND create a passive DNS repository, **super_mediator** can be used to forward
the flow data to SiLK and the DNS-enriched flow data to Orcus.
Alternatively, if you're concerned with PII or have limited bandwidth,
super_mediator can perform de-duplication of DNS resource records.  The
deduplication removes attribution of DNS queries but can reduce the data
signficantly.

Goal for this tutorial
--------------------

This tutorial will provide examples of different exporters.  It will
show multiple configurations and the data that each one produces.  The 
[super_mediator.conf](super_mediator.conf.html) man page provides additional
examples and more detailed documentation.  This tutorial shows
multiple methods of structuring your MySQL database and a few
methods of import.  The example only uses an IPFIX file as input.
**super_mediator** has multiple methods of ingest.  It can listen on
a TCP or UDP port for connections from **yaf** (the preferred method)
or poll a file directory for IPFIX files.  Spread is also supported.
See the [super_mediator.conf](super_mediator.conf.html) man page
for examples of different COLLECTOR configurations.

Dependencies {#deps}
===============

Core dependencies for **yaf** and **super_mediator**:
-------------------

* glib-2.0 
* pcre (for **yaf**)
* libpcap (for **yaf**)
* [libfixbuf](http://tools.netsa.cert.org/fixbuf/index.html)

Tools:
-------

* [YAF](http://tools.netsa.cert.org/yaf/index.html)
* [super_mediator](http://tools.netsa.cert.org/super_mediator/index.html)

Optional:

* MySQL (will be used for this tutorial)

MySQL is needed if you want to store your data in a MySQL database.  We will
show a few examples of how to setup your MySQL database if you choose to store
the DPI data in MySQL.

* [SiLK IPset Library](http://tools.netsa.cert.org/silk-ipset/index.html)

SiLK IPset is only used if you want to filter on IP addresses.  This may be due to
privacy concerns or policy or you simply just want to limit the amount of data to
keep around.

* [SiLK](http://tools.netsa.cert.org/silk/index.html) (will be used for this tutorial)

SiLK is the ideal tool for flow analysis.  A MySQL database is not the appropriate
tool for analyzing a lot of flow data. One of the examples will show how 
to export flow data from super_mediator to SiLK.

* [Orcus](http://tools.netsa.cert.org/orcus/index.html) 

If you want some cool tools for analyzing DNS that work on top of an Oracle or
PostgreSQL database, download and install Orcus.  

How to install {#install}
================

The following tools can be downloaded from [https://tools.netsa.cert.org].

    tar -xvzf libfixbuf-1.7.0.tar.gz
    cd libfixbuf-1.7.0
    ./configure
    make
    make install
    
    tar -xvzf yaf-2.7.0.tar.gz
    cd yaf-2.7.0
    ./configure --enable-applabel --enable-plugins
    make
    make install
    
    tar -xvzf super_mediator-1.1.0.tar.gz
    cd super_mediator-1.1.0
    ./configure
    make
    make install
    
    tar -xvzf silk-3.10.0.tar.gz
    cd silk-3.10.0
    ./configure --with-libfixbuf=/usr/local/lib/pkgconfig --enable-ipv6
    make
    make install
    
Getting Started {#start}
======================

We need data to get started.  You can sniff your network and get the data that way,
or if you already have a large pcap or a bunch of small pcaps, we can run **yaf** 
with Deep Packet Inspection (DPI) enabled on the PCAP file and 
and use **super_mediator** to analyze the flow and DPI data.  
Let's start with a PCAP example just to
experiment.  It is a good idea to start with a small amount of data in 
order to determine the best configuration for your analysis needs.

Starting yaf:
    
    $ yaf --in some_big_pcap.pcap \
        --out ipfix_file.yaf \
        --applabel \
        --max-payload=2048 \
        --plugin-name=/usr/local/lib/dpacketplugin.la \
        --verbose

In the unlikely event you run into an error message running **yaf**, here 
are a few common warning and error messages, and solutions on how to
silence them.
    
###Common warning and error messages: {#common}

**Problem:**

    yaf: error while loading libraries: libairframe-2.7.0.so.4:
    cannot open share object file: No such file or directory
    
**Solution:**  Most likely YAF libraries were installed in a nonstandard location.
Try running `ldconfig` or setting LD_LIBRARY_PATH to the location of
libairframe.

**Problem:**

    Couldn't open library "dnsplugin": file not found
    
**Solution:** Most likely YAF application labeling libraries were installed in
a nonstandard location.  Set LTDL_LIBRARY_PATH to the location of those
libraries.

Interpreting **yaf** output {#interpret}
----------------------------

If you don't run into any of the above issues, you should see something
like this after running **yaf** with the above options:
    
    [2014-01-16 14:05:04] yaf starting
    [2014-01-16 14:05:04] Initializing Rules From File: /usr/local/etc/yafApplabelRules.conf
    [2014-01-16 14:05:04] Application Labeler accepted 36 rules.
    [2014-01-16 14:05:04] Application Labeler accepted 0 signatures.
    [2014-01-16 14:05:04] DPI Running for ALL Protocols
    [2014-01-16 14:05:04] Reading packets from some_big_pcap.pcap
    [2014-01-16 14:05:04] Initializing Rules from DPI File /usr/local/etc/yafDPIRules.conf
    [2014-01-16 14:05:04] DPI rule scanner accepted 63 rules from the DPI Rule File
    [2014-01-16 14:05:07] Processed 5921725 packets into 42096 flows:
    [2014-01-16 14:05:07]   Mean flow rate 15599.44/s.
    [2014-01-16 14:05:07]   Mean packet rate 2194402.64/s.
    [2014-01-16 14:05:07]   Virtual bandwidth 7851.6178 Mbps.
    [2014-01-16 14:05:07]   Maximum flow table size 10742.
    [2014-01-16 14:05:07]   181 flush events.
    [2014-01-16 14:05:07]   19580 asymmetric/unidirectional flows detected (46.51%)
    [2014-01-16 14:05:07] Assembled 33328 fragments into 15414 packets:
    [2014-01-16 14:05:07]   Expired 552 incomplete fragmented packets. (0.01%)
    [2014-01-16 14:05:07]   Maximum fragment table size 41.
    [2014-01-16 14:05:07] Rejected 201232 packets during decode: (3.29%)
    [2014-01-16 14:05:07]   201232 due to unsupported/rejected packet type: (3.29%)
    [2014-01-16 14:05:07]     201232 unsupported/rejected Layer 3 headers. (3.29%)
    [2014-01-16 14:05:07]     196465 ARP packets. (3.21%)
    [2014-01-16 14:05:07] yaf Exported 1 stats records.
    [2014-01-16 14:05:07] yaf terminating
    

**yaf** tells you which application labeling rules file it used to grab its rules
and signatures.  36 rules were loaded into YAF at startup time, 0 signatures.
What's the difference between rules and signatures?  Rules are first executed
against flows that have a src/dst port matching the rule ID first.  If there
are no matches, **yaf** starts with the first rule listed in the file and
continues down the list until it finds a match.  A signature, on the other
hand, is performed on every flow irregardless of the ports.
**yaf** does not load any signatures by default.  Signatures may be useful if
you're looking for command and control strings in an HTTP request/response
so that **yaf** looks for the string of interest instead of jumping to the HTTP
regular expression and labeling it as 80.

You should also see the following line which indicates successful loading of the DPI plugin:

    [2014-01-16 14:05:04] DPI Running for ALL Protocols

If that line is absent, or **yaf** couldn't find one of the application labeling plugins you will see an error such as:

**Problem:**

    couldn't load requested plugin: missing function "ypGetMetaData" in \
    /usr/local/lib/yaf/dpacketplugin.la plugin

**Solution:**  You probably didn't run configure with ``--enable-applabel``.  Scroll
to the top of this page, reread the directions for installing **yaf** and try
again.

**Problem:**

    couldn't load requested plugin: missing function "ypGetMetaData" in aolplugin plugin.

**Solution:**  You didn't give the correct argument to ``--plugin-name``.  The only
acceptable plugins to this command line option are ``dpacketplugin.la`` and
``dhcp_fp_plugin.la``, unless you have written your own.  Please scroll up,
reread the directions for running **yaf** and try again.

Next, you'll see the PCAP file that you specified on the command line, the
location of the ``yafDPIRules.conf`` that **yaf** is reading from, and how many
accepted DPI rules **yaf** collected from it.

The remaining 16 lines provide statistics about what **yaf** found in the PCAP
file and what it exported.  This information was also exported in an IPFIX
Options Record in the output file you provided when you ran **yaf**.  You'll see
that **yaf** ignored 201,232 packets.  A majority of these packets were
ARP (196,465) packets.

Using yafscii {#yafscii}
------------------------

A quick way to view the data is to use [yafscii](../yaf/yafscii.html).  **yafscii**
takes IPFIX flow data files and prints them in an ASCII format that looks
similar to tcpdump, with one flow per line.  It can also write it in
pipe-delimited format.  **yafscii** ONLY PRINTS FLOW RECORDS.  It will not
print the DPI data that **yaf** exported.  This is how the data should look:
    
    $ yafscii --in ipfix_file.ipfix --out - | less
    2011-01-28 22:00:22.230 - 22:00:25.763 (3.533 sec) tcp 74.125.113.109:993 => 10.
    10.0.183:63216 89bcf80b AP/AP vlan 384 (10/850 ->) eof
    2011-01-28 22:00:25.635 - 22:00:25.776 (0.141 sec) tcp 10.10.1.16:49356 => 64.23
    3.169.193:443 5b17dc2d:097ab094 S/APS:AS/APS vlan 384:384 (14/1418 <-> 8/3876) r
    tt 6 ms eof applabel: 443
    2011-01-28 22:00:25.779 tcp 10.10.0.41:44520 => 184.168.85.77:443 9f849956 S/S v
    lan 384 (2/120 ->) eof
    2011-01-28 21:52:05.070 - 22:00:25.779 (500.709 sec) udp 172.16.0.1:1867 => 172.
    16.0.160:9996 vlan 1f4 (1898/2772880 ->) eof
    2011-01-28 21:45:25.899 - 22:00:25.779 (899.880 sec) udp 172.16.6.1:62499 => 172
    .16.6.10:12000 vlan 1fa (3943/5764000 ->) eof
    
If you are not familiar with **yafscii**, check out the 
[yafscii man page](../yaf/yafscii.html).

Super_mediator Command Line {#commandline}
==============================

Now let's see what kind of information **super_mediator** will produce.  You can run
**super_mediator** from the command line with a limited set of features or use
the *super_mediator.conf* file and get the full set of capabilities. By default,
**super_mediator** run from the command line will read and write an IPFIX file.  In
text mode (``-m TEXT``) it will decode the IPFIX and write to a text file in
pipe-delimited format.
    
    $ super_mediator -i ipfix_file.ipfix -o - -m TEXT
    
    2011-01-28 21:45:28.636|2011-01-28 21:45:29.131|   0.495|   0.080|  6|
                      172.16.0.163|58367|      14|    3502|00|00:00:00:00:00:00|
                         128.121.146.100|   80|      13|    6916|00|00:00:00:00:00:0
    0|       S|    APSF|      AS|    APSF|65d93ec9|508634fa|1f4|   80|000|000|
    http|111|Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.2.13) \	
    	     Gecko/20101203 Firefox/3.6.13
    http|112|GET /account/available_features
    http|115|http://twitter.com/
    http|117|twitter.com
    http|118|2094
    http|123|203 Firefox
    http|123|200 OK
    http|123|200 OK
    http|121|en-us,en;q=0.5
    http|120|application/json, text
    http|122|text/javascript
    http|114|HTTP/1.1
    
Above is one particular HTTP flow.  The first line is the flow information,
similar to what `yafscii` outputs in ``--tabular`` mode.  The following lines are 
the DPI data fields
that **yaf** collected and exported. The first column identifies the protocol, the
second column identifies the information element ID, and the third column
displays the data that was stored in the information element.  You could easily
grep for all http flows in the file or user-agent strings (information element
111).  A list of information element IDs can be found [here](super_mediator.conf.html)
along with a description of what each information element should contain.

Perhaps, we only want to see the IP addresses, ports, application label,
and DPI data.  From the command line:
    
    $ super_mediator -i ipfix_file.ipfix -o - -m TEXT -f 0,1,4,5,7,73
    
    172.16.0.163|128.121.146.100|58367|80|80|111|Mozilla/5.0 (Macintosh; U; \		
    Intel Mac OS X 10.6; en-US; rv:1.9.2.13) Gecko/20101203 Firefox/3.6.13
    172.16.0.163|128.121.146.100|58367|80|80|112|GET /account/available_features
    172.16.0.163|128.121.146.100|58367|80|80|115|http://twitter.com/
    172.16.0.163|128.121.146.100|58367|80|80|117|twitter.com
    172.16.0.163|128.121.146.100|58367|80|80|118|2094
    172.16.0.163|128.121.146.100|58367|80|80|123|203 Firefox
    172.16.0.163|128.121.146.100|58367|80|80|123|200 OK
    172.16.0.163|128.121.146.100|58367|80|80|123|200 OK
    172.16.0.163|128.121.146.100|58367|80|80|121|en-us,en;q=0.5
    172.16.0.163|128.121.146.100|58367|80|80|120|application/json, text
    172.16.0.163|128.121.146.100|58367|80|80|122|text/javascript
    172.16.0.163|128.121.146.100|58367|80|80|114|HTTP/1.1
    
As you can see it exports one line for each DPI data element **yaf** exported.

There are a few other basic command line options available, mainly for
input/output, daemonizing, and logging.  The [super_mediator man page](super_mediator.html)
will give you all of the options available.

Configuration File {#configfile}
=========================

The vast majority of configuration options are only available through 
the the configuration file.  The *super_mediator.conf*
allows you to do all the basic configuration the command line options provide
and more.  You can configure automatic uploads into a MySQL database,
filtering, multiple collectors and exporters, de-duplication, and more.

By default the *super_mediator.conf* is installed in ``/usr/local/etc``.  Let's walk
through the default file:

The first block is the COLLECTOR block.  This block configures how **super_mediator**
should be listening for connections from **yaf**.  You can configure multiple
COLLECTOR blocks. As you can see this is listening for TCP connections on
port 18000.  This must match the **yaf** command line arguments ``--ipfix`` and
``--ipfix-port``.
    
    COLLECTOR TCP
       PORT 18000
    COLLECTOR END
    
The second block is the first of 4 EXPORTER blocks.  This particular EXPORTER
uses the keyword FLOW_ONLY so that only flow is sent to the collecting process.
This particular EXPORTER is meant for an [rwflowpack](../silk/rwflowpack.html)
process running on localhost listening for TCP connections on port 18001. This
EXPORTER is given the name "silk" which will help identify log messages pertaining
to this exporter in the log file.  The name is optional. 
This should match the SiLK [sensor.conf](../silk/sensor.conf.html) 
``probe protocol`` and ``listen-on-port`` values. [Exporter 1 Output](#exp1)
    
    # rwflowpack - exporter 1
    EXPORTER TCP "silk"
       PORT 18001
       HOST localhost
       FLOW_ONLY
    EXPORTER END
    
The third block configures **super_mediator** to perform de-duplication of DNS
resource records.  It's writing the records to pipe-delimited text files
to ``/data/dns`` and each file
will have the prefix "yaf2dns" and the timestamp that the file was 
opened.  The files will rotate every 1200 seconds (20 minutes).  The files
will be "locked" until **super_mediator** has finished writing to them.  This
means that the file will be prepended with a "." until the time limit expires.
See [below](#exp2) for more detail on how to further configure DNS deduplication.  
[Exporter 2 Output](#exp2)
    
    #dedup process - exporter 2
    EXPORTER TEXT "dns-dedup"
       PATH "/data/dns/yaf2dns"
       DELIMITER "|"
       ROTATE 1200
       DNS_DEDUP_ONLY
       LOCK
    EXPORTER END
    
The third exporter block configures **super_mediator** to write only DPI data to 
protocol-specific, pipe-delimited files.  The files will rotate every
20 minutes and they will be locked until **super_mediator** has finished
writing to them.  The files will be written to the /data/dpi directory.
When using the MULTI_FILES keyword, PATH expects a file directory.
The filenames will the protocol names, dns.txt0, http.txt1, smtp.txt2, etc.
This EXPORTER could be used for external script or daemon that 
is loading the files into a database or simply for quick searching
per protocol.  Note that if the keyword TIMESTAMP_FILES is not
present, the files will rollover approximately every 3.5 days.  
[Exporter 3 Output](#exp3)

    #dpi 2 database - exporter 3
    EXPORTER TEXT "dpi"
       PATH "/data/dpi"
       ROTATE 1200
       MULTI_FILES
       DPI_ONLY
       LOCK
    EXPORTER END
    
The fourth exporter is meant for a custom collector.  Perhaps, you have
your own database schema and you didn't use the one that **super_table_creator**
creates for you.  You can specify the matching fields using the FIELDS
keyword.  This exporter writes to one particular file.  It does not
rollover.  [Exporter 4 Output](#exp4)
    
    #custom field lists - exporter 4
    EXPORTER TEXT "custom"
       PATH "/data/flow/custom.txt"
       FIELDS stime,etime,sip,dip,sport,dport,protocol,vlanint,iflags,\
       	      uflags,riflags,ruflags,application,DPI
    EXPORTER END
    
The following block is commented out by default, but if uncommented it would
effect the second EXPORTER block.  An EXPORTER that uses the keyword
MULTI_FILES, can further specify a DPI_CONFIG block to configure 
the filenames and which elements to write to that file.  By default, 
**super_mediator** will write all the HTTP elements to the http file, all
of the DNS resource records to the dns file, and so on.  If you use the
following DPI_CONFIG block, **super_mediator** will only write user-agent
strings (111) and HTTP Get strings (112) to a file prefixed with "http."
For DNS, **super_mediator** will only write A, NS, SOA, MX, and AAAA records
to a file prefixed with "dns."
    
    #DPI_CONFIG
    #  TABLE http [111, 112]
    #  TABLE dns [1, 2, 6, 12, 28]
    #DPI_CONFIG END
    
The following block further configures the DNS de-duplication
capability in **super_mediator**.  By default, **super_mediator** will
write a DNS record the first time it is seen and keep the 
record in memory for five minutes or until it has been seen 500 
times.  At that time, the record will be flushed from memory
and the next time that record is seen it will be exported. You
can change the default behavior using the DNS_DEDUP block. The
below block would change the hit count from 500 to 10000.  You could
also use the FLUSH_TIME keyword to change the flush time from 5
minutes to something longer (or shorter).  Additionally, there is a keyword,
LAST_SEEN, which will change the format of the data and how the
records are exported [see below].
    
    DNS_DEDUP
       MAX_HIT_COUNT 10000
    DNS_DEDUP END
    
This statement changes the default logging behavior to DEBUG.

    LOGLEVEL DEBUG

This statement defines the location of the log file.

    LOG "/var/log/super_mediator.log"

To configure **super_mediator** to rollover the log file
each day, and to compress old log files, add the following
statement to the configuration file (it must be a valid
file directory):

    LOGDIR "/var/log/super_mediator"

IPFIX File Example {#ipfixfile}
====================

To demonstrate the exporters defined in the configuration file, 
we will run an IPFIX file created by **yaf**.
In order to use the IPFIX file created by **yaf** from the above
example, we will need to change the COLLECTOR block to:

    COLLECTOR FILEHANDLER
       PATH "ipfixfile.ipfix"
    COLLECTOR END
    
Since we're just running **super_mediator** over a file, we may
want to just log to the terminal, so comment out the following
line:

    #LOG "/var/log/super_mediator.log"

Create the file directories:

    mkdir /data/flow
    mkdir /data/dns
    mkdir /data/dpi

We also need to start [rwflowpack](../silk/rwflowpack.html) if we want to
use this configuration file. This example will use the same 
[sensor.conf](../silk/sensor.conf.html) created in 
[this example](../yaf/libyaf/yaf_sm_silk.html).  **rwflowpack** must
be started prior to starting **super_mediator**:

    /usr/local/sbin/rwflowpack --sensor-conf=/data/sensor.conf \
    			       --root-dir=/data \
    			       --log-destination-/var/log/rwflowpack.log \
    			       --site-config=/data/silk.conf


If **rwflowpack** is not running properly, an error message such as
the one below will be written in the log file:

    [2014-01-18 19:07:43] Fatal: couldn't create connected TCP socket to localhost:18001 \
    Connection refused

Otherwise, you'll see that **super_mediator** successfully read the given
file.  **super_mediator** will display log messages of every file it opens
and closes, the YAF statistics records, and statistics about it's own
process such as how many flows it read and wrote, filtered, and 
de-duplicated.

Running **super_mediator** with a configuration file: {#run}
-------------------------------------

    $ /usr/local/bin/super_mediator -c /usr/local/etc/super_mediator.conf
    [2015-06-29 14:48:16] super_mediator starting
    [2015-06-29 14:48:16] custom: Opening Text File: /data/flow/custom.txt
    [2015-06-29 14:48:16] custom: Exporter Active.
    [2015-06-29 14:48:16] dpi: Exporter Active.
    [2015-06-29 14:48:16] dns-dedup: Exporter Active.
    [2015-06-29 14:48:16] silk: Exporter Active.
    [2014-02-11 15:18:33] Initialization Successful, starting...
    [2015-06-29 14:48:16] C1: Opening file: ipfixfile.ipfix
    [2015-06-29 14:48:16] dpi: Opening Text File: /data/dpi/.http.txt0
    [2015-06-29 14:48:16] dpi: Opening Text File: /data/dpi/.flow.txt0
    [2015-06-29 14:48:16] dpi: Opening Text File: /data/dpi/.tls.txt0
    [2015-06-29 14:48:16] dpi: Opening Text File: /data/dpi/.ftp.txt0
    [2015-06-29 14:48:16] dpi: Opening Text File: /data/dpi/.ssh.txt0
    [2015-06-29 14:48:16] dpi: Opening Text File: /data/dpi/.dns.txt0
    [2015-06-29 14:48:16] dns-dedup: Opening Text File: /data/dns/.yaf2dns.20110128215027.txt
    [2015-06-29 14:48:16] dpi: Opening Text File: /data/dpi/.rtp.txt0
    [2015-06-29 14:48:17] dpi: Opening Text File: /data/dpi/.imap.txt0
    [2015-06-29 14:48:17] dpi: Opening Text File: /data/dpi/.smtp.txt0
    [2015-06-29 14:48:17] dpi: Opening Text File: /data/dpi/.pop3.txt0
    [2015-06-29 14:48:17] dpi: Opening Text File: /data/dpi/.irc.txt0
    [2015-06-29 14:48:17] dpi: Opening Text File: /data/dpi/.tftp.txt0
    [2015-06-29 14:48:17] C1: YAF ID: 0 IP: 192.168.1.5 Uptime: 0d:0h:22m:29s
    [2015-06-29 14:48:17] C1: YAF Flows: 42096 Packets: 5921725 Dropped: 0 Ignored: 201232 Out of Sequence: 0 Expired Frags: 552 Assembled Frags: 15414
    [2015-06-29 14:48:17] C1: Closing Connection: End of file
    [2015-06-29 14:48:17] INACTIVE Collector C1: 42096 flows, 0 other flows, 1 stats, 0 filtered, 0 files
    [2015-06-29 14:48:17] Exporter custom: 42096 records, 0 stats, 117.7622 Mbps, 349.68 bytes per record
    [2015-06-29 14:48:17] Exporter dpi: 42096 records, 0 stats, 65.3756 Mbps, 194.13 bytes per record
    [2015-06-29 14:48:17] Exporter dns-dedup: 5899 records, 0 stats, 3.0931 Mbps, 65.54 bytes per record
    [2015-06-29 14:48:17] Exporter silk: 42096 records, 0 stats, 67.3536 Mbps, 200.00 bytes per record
    [2015-06-29 14:48:17] custom: Closing File /data/flow/custom.txt
    [2015-06-29 14:48:17] Unlocking File /data/dpi/ftp.txt0
    [2015-06-29 14:48:17] Unlocking File /data/dpi/ssh.txt0
    [2015-06-29 14:48:17] Unlocking File /data/dpi/smtp.txt0
    [2015-06-29 14:48:17] Unlocking File /data/dpi/dns.txt0
    [2015-06-29 14:48:17] Unlocking File /data/dpi/tftp.txt0
    [2015-06-29 14:48:17] Unlocking File /data/dpi/http.txt0
    [2015-06-29 14:48:17] Unlocking File /data/dpi/imap.txt0
    [2015-06-29 14:48:17] Unlocking File /data/dpi/irc.txt0
    [2015-06-29 14:48:17] Unlocking File /data/dpi/pop3.txt0
    [2015-06-29 14:48:17] Unlocking File /data/dpi/tls.txt0
    [2015-06-29 14:48:17] Unlocking File /data/dpi/flow.txt0
    [2015-06-29 14:48:17] Unlocking File /data/dpi/rtp.txt0
    [2015-06-29 14:48:17] Exporter dns-dedup: 22285 DNS records, 3459 filtered, 5899 flushed (73.53% compression)
    [2015-06-29 14:48:17] dns-dedup: Closing File /data/dns/yaf2dns.20110128215027.txt
    [2015-06-29 14:48:17] Unlocking File /data/dns/yaf2dns.20110128215027.txt
    [2015-06-29 14:48:17] SM: Uptime: 0d:0h:0m:0s, Total Flows: 42096, Filtered: 0, Stats: 1, DNS: 14345
    [2015-06-29 14:48:17] super_mediator Terminating


As you can see, **super_mediator** provides a lot of log information
in DEBUG mode.  It logs every file open, close, lock, and unlock 
procedure.  It provides statistics about how many flows it exported
to each exporter. In addition, it writes the **yaf** statistics
record to the log file. (To disable this, use the *NO_STATS* keyword
in the *super_mediator.conf* file).
Finally, it writes overall statistics about the flows, DNS flows,
and the DNS records it has received, as well as how
many DNS resource records that have been aggregated.

Exporter 1 Explained - SiLK {#exp1}
------------------------

The first exporter sent flow data to SiLK.  We can do some simple 
queries to determine how many flows it received. The following 
query uses [rwfilter](../silk/rwfilter.html) to query all the 
flows (the PCAP is from 2011).  [rwstats](../silk/rwstats.html)
is used to calculate the protocols from most to least active:

    $ export SILK_DATA_ROOTDIR=/data

    $ rwfilter --start-date=2010/01/01 --end-date=2014/01/01 \
      	       --proto=0- --type=all --pass=stdout \
	       | rwstats --fields=protocol --bottom --count=10
    INPUT: 64501 Records for 5 Bins and 64501 Total Records
    OUTPUT: Top 10 Bins by Records
    pro|   Records|  %Records|   cumul_%|
      6|     32005| 49.619386| 49.619386|
     17|     31697| 49.141874| 98.761260|
      2|       399|  0.618595| 99.379855|
      1|       368|  0.570534| 99.950388|
     47|        32|  0.049612|100.000000|

Exporter 2 Explained - DNS Deduplication {#exp2}
----------------------------------------

The second exporter was the DNS de-duplication exporter.  
    
    $ head -n 6 /data/dns/yaf2dns.20110128215025.txt
    2011-01-28 21:50:25.880|1|spreadsheets.l.google.com.|72.14.204.102
    2011-01-28 21:50:25.880|1|spreadsheets.l.google.com.|72.14.204.100
    2011-01-28 21:50:25.880|1|spreadsheets.l.google.com.|72.14.204.113
    2011-01-28 21:50:25.880|1|spreadsheets.l.google.com.|72.14.204.101
    2011-01-28 21:50:25.880|6|l.google.com.|ns2.google.com.
    2011-01-28 21:50:36.205|6|l.google.com.|ns4.google.com.
    
The above lines are in the format:

*first seen time | resource record type | rrname | rrval*

As you can see the first 4 rows are A records, while the last 2 rows are SOA records.

What if we would like to see how many times a particular resource record appeared in the given
time period?  You would need to modify the *super_mediator.conf* DNS_DEDUP block.  Add the 
LAST_SEEN keyword:
    
    DNS_DEDUP
       MAX_HIT_COUNT 5000
       LAST_SEEN
       FLUSH_TIME 900
    DNS_DEDUP END
    
The LAST_SEEN keyword instructs **super_mediator** to write records when they are flushed,
rather than when they are first seen.  When this option is used, the output format
will also include the time the record was last seen and a count of the number of times
it was seen.  This particular PCAP is data collected over a 15 minute time period, 
so adjusting the timeout to 900 seconds will give us the hit count for the whole PCAP
(unless of course there are more than 5000 records).

Rerunning **super_mediator** with the new configuration file yields the following
results:
    
    $ head -n 6 /data/dns/yaf2dns.20110128215106.txt 
    2011-01-28 21:50:25.880|2011-01-28 21:50:25.880|1|spreadsheets.l.google.com.|1|72.14.204.102
    2011-01-28 21:50:25.880|2011-01-28 21:50:25.880|1|spreadsheets.l.google.com.|1|72.14.204.100
    2011-01-28 21:50:25.880|2011-01-28 21:50:25.880|1|spreadsheets.l.google.com.|1|72.14.204.113
    2011-01-28 21:50:25.880|2011-01-28 21:50:25.880|1|spreadsheets.l.google.com.|1|72.14.204.101
    2011-01-28 21:50:25.880|2011-01-28 21:50:25.880|6|l.google.com.|1|ns2.google.com.
    2011-01-28 21:50:36.205|2011-01-28 21:50:36.205|6|l.google.com.|1|ns4.google.com.
    
The format of the above lines is:

**first seen time | last seen time | rrtype | rrname | hitcount | rrval**

For the above records, each record was only seen once in the 15 minute time period.

When performing DNS analysis with **yaf** and **super_mediator**, it is a good idea
to add the following option to the **yaf** command line:

``--udp-uniflow=53``

The ``--udp-uniflow`` option instructs **yaf** to create one flow for each DNS packet.
By default **yaf** only captures the payload from the first packet (in each 
direction) for a UDP flow.  If you use the ``--udp-uniflow`` option, it ensures
that you get every DNS request/response **yaf** processes.

See [below](#manualimport) for instructions on how to manually load this 
data into the MySQL database or [here](#autoimport) for 
instructions on how to setup automatic upload.

Exporter 3 Explained - MULTIFILES {#exp3}
---------------------------------

The third exporter wrote a file for each protocol **yaf** captured information for.  The
MULTI_FILES option is ideal for database import.  **super_mediator** writes the flow
information to the ``flow.txt`` file and creates one file for each protocol.  The flow
information and the DPI information can be correlated using the flow key hash, 
the start time, and the observation ID,  which together
make up a primary key for the flow.  The flow key hash is a hash of the 
5-tuple and vlan.  The 5-tuple is the source IP address, destination IP address,
protocol, source transport port, and destination transport port.

For the most part, the protocol files have the same format:

**flow key hash | start time | obID | Info Element ID | data**

Field | Description
--- | ---
flow key hash | The hash of the 5-tuple and vlan
start time | The start time (in milliseconds since EPOCH) of the flow
obID | The observation ID of the exporting process (by default YAF uses 0)
Info Element ID | The ID of the IPFIX Information Element that contained the data.
data | The data that YAF collected.

The flow file will have the format:

**flow key hash | start time | src IP | dst IP | protocol | src port | dst port | VLAN | obID**

Field |	 Description
--- | ---
flow key hash | The hash of the 5-tuple and vlan
start time | The start time (in	milliseconds since EPOCH) of the flow
src IP | source IP Address
dst IP | destination IP Address
protocol | transport protocol of the flow
src port | source transport port
dst port | destination transport port
vlan | The VLAN tag for the flow
obID | The observation ID of the exporting process (by default **yaf** uses 0)

DNS and TLS/SSL are the exceptions to the above format. DNS output has
the format:

**flow key hash | start time | obid | QR | dnsID | section | nx | authoritative | rrtype | ttl | rrname | rrval**

Field |	 Description
--- | ---
flow key hash |	The hash of the	5-tuple and vlan
start time | The start time (in milliseconds since EPOCH) of the flow
obID | The observation ID of the exporting process (by default YAF uses 0)
QR | Q for Query, R for Response
dnsID | The DNS transaction ID used to match Queries and Responses
section | The section of the DNS record that this resource record was taken from.  \
	  0 for Question, 1 for Answer, 2 for Name Server, 3 for Additonal section.
nx | The DNS NXDomain or Response Code.  This corresponds with \
     the DNS RCODE header field.  The field will be set to 3 \
     for a Name Error, 2 for a Server Failure, 1 for a Format Error,\
      and 0 for No Error.
authoritative | The Authoritative Header field, this bit is only \
	      valid in responses and specifies that the name server is \
	      an authority for the domain name in the question section.
rrtype | The Type of Resource Record.  See a list in *super_mediator.conf* man page.
ttl | The DNS Time to Live.
rrname | The QNAME from the DNS Question Section or NAME in the DNS Resource Record Section
rrval | This depends on the type of the DNS Resource Record Type.

TLS/SSL files have the format:

**flow key hash | start time | obID | Info Element ID | SI | cert number | data**

Field | Description
--- | ---
flow key hash | The hash of the 5-tuple and vlan
start time | The start time (in milliseconds since EPOCH) of the flow
obID | The observation ID of the exporting process (by default **yaf** uses 0)
Info Element ID | The object identifier from the X.509 RelativeDistinguishedName Sequence
SI | S if the field was taken from the Subject Section of the Certificate, \
     I for the Issuer Section
cert number | There may be multiple certificates in the certificate chain, \
     	    this lists the order in the sequence
data | The X.509 object identifier value.

Here are some examples:
    
    $ ls /data/dpi
    dns.txt0   ftp.txt0    imap.txt0	pop3.txt0	ssh.txt0
    flow.txt0  http.txt0   irc.txt0		smtp.txt0	tls.txt0

    $ head -n5 /data/dpi/dns.txt0
    1361713272|1296251349702|0|R|51786|1|0|0|5|69883|spreadsheets.google.com.|spreadsheets.l.google.com.
    1361713272|1296251349702|0|R|51786|1|0|0|1|77|spreadsheets.l.google.com.|72.14.204.102
    1361713272|1296251349702|0|R|51786|1|0|0|1|77|spreadsheets.l.google.com.|72.14.204.100
    1361713272|1296251349702|0|R|51786|1|0|0|1|77|spreadsheets.l.google.com.|72.14.204.113
    1361713272|1296251349702|0|R|51786|1|0|0|1|77|spreadsheets.l.google.com.|72.14.204.101
    
To find the corresponding DNS flow:
    
    $ cat /data/dpi/flow.txt0 | grep 1361713272
    1361713272|1296251349702|172.16.0.5|8.8.8.8|17|60019|53|500|0
        
    $ cat /data/dpi/tls.txt0
    2993670442|1296252025635|0|6|I|0|ZA
    2993670442|1296252025635|0|10|I|0|Thawte Consulting (Pty) Ltd.
    2993670442|1296252025635|0|3|I|0|Thawte SGC CA
    2993670442|1296252025635|0|6|S|0|US
    2993670442|1296252025635|0|8|S|0|California
    2993670442|1296252025635|0|7|S|0|Mountain View
    2993670442|1296252025635|0|10|S|0|Google Inc
    2993670442|1296252025635|0|3|S|0|m.google.com
    2993670442|1296252025635|0|189|I|0|2
    2993670442|1296252025635|0|244|I|0|1a f7 d3 de 2a 67 9c 85 77 2c 93 f8 5d de 8b b4
    2993670442|1296252025635|0|247|I|0|091218000000Z
    2993670442|1296252025635|0|248|I|0|111218235959Z
    2993670442|1296252025635|0|250|I|0|141
    2993670442|1296252025635|0|187|I|0|0x0005
    2993670442|1296252025635|0|186|I|0|3
    2993670442|1296252025635|0|288|I|0|0x0301
    
To find the corresponding TLS flow:
    
    $ cat /data/dpi/flow.txt0 | grep 2993670442
    2993670442|1296252025635|10.10.1.16|64.233.169.193|6|49356|443|900|0
    
    $ cat /data/dpi/http.txt0
    3069422788|1296252022064|0|111|Apple iPhone v8A306 Maps v4.0.1
    3069422788|1296252022064|0|111|Apple iPhone v8A306 Maps v4.0.1
    3069422788|1296252022064|0|111|Apple iPhone v8A306 Maps v4.0.1
    3069422788|1296252022064|0|112|POST /glm/mmap
    3069422788|1296252022064|0|117|www.google.com
    3069422788|1296252022064|0|117|www.google.com
    3069422788|1296252022064|0|117|www.google.com
    3069422788|1296252022064|0|118|88
    3069422788|1296252022064|0|118|145
    3069422788|1296252022064|0|118|221
    3069422788|1296252022064|0|118|8
    3069422788|1296252022064|0|118|25611
    3069422788|1296252022064|0|123|306 Maps v
    3069422788|1296252022064|0|123|306 Maps v
    3069422788|1296252022064|0|123|306 Maps v
    3069422788|1296252022064|0|123|200 OK
    3069422788|1296252022064|0|123|200 OK
    3069422788|1296252022064|0|121|en-us
    3069422788|1296252022064|0|121|en-us
    3069422788|1296252022064|0|121|en-us
    3069422788|1296252022064|0|120|*/*
    3069422788|1296252022064|0|120|*/*
    3069422788|1296252022064|0|120|*/*
    3069422788|1296252022064|0|122|application/x-www-form-urlencoded
    3069422788|1296252022064|0|122|application/x-www-form-urlencoded
    3069422788|1296252022064|0|122|application/x-www-form-urlencoded
    3069422788|1296252022064|0|122|application/binary
    3069422788|1296252022064|0|122|application/binary
    3069422788|1296252022064|0|114|HTTP/1.1
    3069422788|1296252022064|0|114|HTTP/1.1
    3069422788|1296252022064|0|114|HTTP/1.1
    3069422788|1296252022064|0|114|HTTP/1.1
    3069422788|1296252022064|0|114|HTTP/1.1
    
To find the corresponding http flow:
    
    $ cat /data/dpi/flow.txt | grep 3069422788
    3069422788|1296252022064|10.10.0.188|72.14.204.104|6|52407|80|900|0
    
### Manual Import into MySQL Database {#manualimport}

Now let's upload this data to a MySQL database:

First we need to build the database and tables.  **super_mediator** provides
a program, **super_table_creator**, that will do this for you.  If **super_table_creator**
was not installed with **super_mediator**, it was probably because the MySQL client
library is not installed, or that it couldn't find it.  You may need
to recompile **super_mediator** using:
    
    $ ./configure --with-mysql=[path to mysql_config utility]
    $ make
    $ make install
    
To use **super_table_creator** to create the appropriate, **super_table_creator**
needs the credentials to access the MySQL database:
    
    $ super_table_creator --name root --password password --database super_flows
    Flow Index Table Created Successfully
    DNS Table Created Successfully
    HTTP Table Created Successfully
    TLS Table Created Successfully
    SLP Table Created Successfully
    IMAP Table Created Successfully
    SMTP Table Created Successfully
    POP3 Table Created Successfully
    IRC Table Created Successfully
    FTP Table Created Successfully
    TFTP Table Created Successfully
    SIP Table Created Successfully
    RTSP Table Created Successfully
    MYSQL Table Created Successfully
    P0F Table Created Successfully
    DHCP Table Created Successfully
    SSH Table Created Successfully
    NNTP Table Created Successfully
    
If you check your database, you should see all the above tables were created in
the "super_flows" database.  Check out the [super_table_creator](super_table_creator.html)
man page for a description of the schemas it creates for each table.

To manually load each file into the database individually:
    
    $ mysqlimport -u root -p --fields-terminated-by="|" super_flows /data/dpi/http.txt0
    super_flows.http: Records: 38731  Deleted: 0  Skipped: 0  Warnings: 567
    
This shows that all the lines in the file were uploaded into the database.
Unfortunately, **mysqlimport** will not show the warnings.  If you're interested in seeing the 
warnings, you can use the ``mysql -e`` command:

    $ mysql -u root -p -e "LOAD DATA INFILE '/data/dpi/http.txt0' \
    into table http FIELDS TERMINATED by '|'; SHOW WARNINGS;" super_flows

You could also write a script that uploads all the files to the database:

    $ for file in /data/dpi/*; \
    do mysqlimport -u root --password=password \
    --fields-terminated-by="|" super_flows ${file}; done

We could also load the dns dedup records from Exporter 2 to the database:

    $ super_table_creator --name root --password password --database super_flows --dns-dedup
    Successfully created DNS dedup table.

If you used the LAST_SEEN keyword in the DNS_DEDUP configuration block:
    
    $ super_table_creator --name root --password password --database super_flows --dns-dedup
    Successfully created DNS dedup last seen table.
    
To load the data in the database:
    
    $ for file in /data/dns/*; \
    do mysql -u root --password=password -e \
    "load data infile '${file}' into table dns_dedup \
    FIELDS TERMINATED BY '|'" super_flows; done
    
### Automating MySQL Import {#autoimport}

How to setup **super_mediator** with MySQL:

It is possible to have **super_mediator** automatically import the files into the database.
For each exporter, **super_mediator** needs the MySQL credentials and database/table name.
To do this using the above configuration file:
    
    EXPORTER TEXT
       PATH "/data/dpi"
       ROTATE 1200
       MULTI_FILES
       DPI_ONLY
       LOCK
       MYSQL_USER "root"
       MYSQL_PASSWORD "secretPassword"
       MYSQL_DATABASE "super_flows"
       REMOVE_UPLOADED
    EXPORTER END
    
Since we're using the MULTI_FILES keyword, we don't have to specify a table
using the MYSQL_TABLE keyword.  The filename is used to determine which
table the file should be loaded to.  Note that if you're using the DPI_CONFIG
block and renaming the files to different names, the filename prefix should
match the MySQL table you intend to upload the file to.
The REMOVE_UPLOADED file will remove the file onces it's been successfully
uploaded.  If there is an error, the file will remain in the file PATH.

Similarly, we can have it upload our deduplicated DNS records:
    
    EXPORTER TEXT
       PATH "/data/dns/yaf2dns"
       DELIMITER "|"
       ROTATE 1200
       DNS_DEDUP_ONLY
       LOCK
       MYSQL_USER "root"
       MYSQL_PASSWORD "secretPassword"
       MYSQL_DATABASE "super_flows"
       MYSQL_TABLE "dns_dedup"
       REMOVE_UPLOADED
    EXPORTER END
    
**super_mediator** will display messages in the log file such as:

    [2014-01-22 14:40:23] Successfully imported file /data/dpi/ftp.txt0 to table 'ftp'
    [2014-01-22 14:40:23] Removed Imported File '/data/dpi/ftp.txt0'
    
With the above setup, you would have to join the flow table and the dns, http, etc. when
you want to find the flow information for a particular DPI string.  For example, you 
may want to find out who queried for "news.google.com":

    mysql> select f.sip from flow f, dns d where d.qr='Q' and \
    d.name='news.google.com.' and f.flow_key = d.flow_key and f.stime = d.stime;

Depending on the amount of data, this query may take a while.  By adding the NO_INDEX
keyword to the second EXPORTER block, **super_mediator** will not create the
flow index file/table and instead write the 5-tuple with the DPI data.
    
    EXPORTER TEXT
       PATH "/data/dpi"
       ROTATE 1200
       MULTI_FILES
       DPI_ONLY
       LOCK
       NO_INDEX
    EXPORTER END

    $ cat /data/dpi/http.txt0
    2011-01-28 22:00:22.064|10.10.0.188|72.14.204.104|6|52407|80|900|0|111|Apple iPhone \
    v8A306 Maps v4.0.1
    2011-01-28 22:00:22.064|10.10.0.188|72.14.204.104|6|52407|80|900|0|112|POST /glm/mmap
    2011-01-28 22:00:22.064|10.10.0.188|72.14.204.104|6|52407|80|900|0|117|www.google.com
    2011-01-28 22:00:22.064|10.10.0.188|72.14.204.104|6|52407|80|900|0|118|88
    2011-01-28 22:00:22.064|10.10.0.188|72.14.204.104|6|52407|80|900|0|118|145
    2011-01-28 22:00:22.064|10.10.0.188|72.14.204.104|6|52407|80|900|0|118|221
    2011-01-28 22:00:22.064|10.10.0.188|72.14.204.104|6|52407|80|900|0|123|306 Maps v
    2011-01-28 22:00:22.064|10.10.0.188|72.14.204.104|6|52407|80|900|0|123|200 OK
    2011-01-28 22:00:22.064|10.10.0.188|72.14.204.104|6|52407|80|900|0|121|en-us
    2011-01-28 22:00:22.064|10.10.0.188|72.14.204.104|6|52407|80|900|0|122|application/\
    x-www-form-urlencoded
    2011-01-28 22:00:22.064|10.10.0.188|72.14.204.104|6|52407|80|900|0|122|application/binary
    2011-01-28 22:00:22.064|10.10.0.188|72.14.204.104|6|52407|80|900|0|114|HTTP/1.1

    $ cat /data/dpi/dns.txt0
    2011-01-28 21:49:09.702|172.16.0.5|8.8.8.8|17|60019|53|500|0|Q|51786|0|0|0|1|0|\
    spreadsheets.google.com.|
    2011-01-28 21:49:09.702|172.16.0.5|8.8.8.8|17|60019|53|500|0|R|51786|1|0|0|5|69883|\
    spreadsheets.google.com.|spreadsheets.l.google.com.
    2011-01-28 21:49:09.702|172.16.0.5|8.8.8.8|17|60019|53|500|0|R|51786|1|0|0|1|77|\
    spreadsheets.l.google.com.|72.14.204.102
    2011-01-28 21:49:09.702|172.16.0.5|8.8.8.8|17|60019|53|500|0|R|51786|1|0|0|1|77|\
    spreadsheets.l.google.com.|72.14.204.100
    2011-01-28 21:49:09.702|172.16.0.5|8.8.8.8|17|60019|53|500|0|R|51786|1|0|0|1|77|\
    spreadsheets.l.google.com.|72.14.204.113
    2011-01-28 21:49:09.702|172.16.0.5|8.8.8.8|17|60019|53|500|0|R|51786|1|0|0|1|77|\
    spreadsheets.l.google.com.|72.14.204.101
    
    $ cat /data/dpi/tls.txt0
    2011-01-28 22:00:25.635|10.10.1.16|64.233.169.193|6|49356|443|900|0|6|I|0|ZA
    2011-01-28 22:00:25.635|10.10.1.16|64.233.169.193|6|49356|443|900|0|10|I|0|Thawte \
    Consulting (Pty) Ltd.
    2011-01-28 22:00:25.635|10.10.1.16|64.233.169.193|6|49356|443|900|0|3|I|0|Thawte SGC CA
    2011-01-28 22:00:25.635|10.10.1.16|64.233.169.193|6|49356|443|900|0|6|S|0|US
    2011-01-28 22:00:25.635|10.10.1.16|64.233.169.193|6|49356|443|900|0|8|S|0|California
    2011-01-28 22:00:25.635|10.10.1.16|64.233.169.193|6|49356|443|900|0|7|S|0|Mountain View
    2011-01-28 22:00:25.635|10.10.1.16|64.233.169.193|6|49356|443|900|0|10|S|0|Google Inc
    2011-01-28 22:00:25.635|10.10.1.16|64.233.169.193|6|49356|443|900|0|3|S|0|m.google.com
    2011-01-28 22:00:25.635|10.10.1.16|64.233.169.193|6|49356|443|900|0|289|I|0|2
    2011-01-28 22:00:25.635|10.10.1.16|64.233.169.193|6|49356|443|900|0|244|I|0|\
    1af7d3de2a679c85772c93f85dde8bb4
    2011-01-28 22:00:25.635|10.10.1.16|64.233.169.193|6|49356|443|900|0|247|I|0|091218000000Z
    2011-01-28 22:00:25.635|10.10.1.16|64.233.169.193|6|49356|443|900|0|248|I|0|111218235959Z
    2011-01-28 22:00:25.635|10.10.1.16|64.233.169.193|6|49356|443|900|0|250|I|0|141
    2011-01-28 22:00:25.635|10.10.1.16|64.233.169.193|6|49356|443|900|0|6|I|1|US
    2011-01-28 22:00:25.635|10.10.1.16|64.233.169.193|6|49356|443|900|0|10|I|1|VeriSign, Inc.
    2011-01-28 22:00:25.635|10.10.1.16|64.233.169.193|6|49356|443|900|0|11|I|1|Class 3 \
    Public Primary Certification Authority
    2011-01-28 22:00:25.635|10.10.1.16|64.233.169.193|6|49356|443|900|0|6|S|1|ZA
    2011-01-28 22:00:25.635|10.10.1.16|64.233.169.193|6|49356|443|900|0|10|S|1|Thawte \
    Consulting (Pty) Ltd.
    2011-01-28 22:00:25.635|10.10.1.16|64.233.169.193|6|49356|443|900|0|3|S|1|Thawte SGC CA
    2011-01-28 22:00:25.635|10.10.1.16|64.233.169.193|6|49356|443|900|0|289|I|1|2
    2011-01-28 22:00:25.635|10.10.1.16|64.233.169.193|6|49356|443|900|0|244|I|1|30000002
    2011-01-28 22:00:25.635|10.10.1.16|64.233.169.193|6|49356|443|900|0|247|I|1|040513000000Z
    2011-01-28 22:00:25.635|10.10.1.16|64.233.169.193|6|49356|443|900|0|248|I|1|140512235959Z
    2011-01-28 22:00:25.635|10.10.1.16|64.233.169.193|6|49356|443|900|0|250|I|1|141

The NO_INDEX keyword adds the following 8 fields to every row in the file:

**start time | src IP | dst IP | protocol | src port | dst port | vlan | obid**

To create MySQL tables with the above NO_INDEX schema:

    $ super_table_creator --name root --password password --database super_flows --no-index

### De-duplication per flow {#dedupperflow}

As you may have noticed in the HTTP data above, most of the fields appear
with repeated data.  As of **super_mediator** version 1.1.0, you can add the
DEDUP_PER_FLOW keyword within the EXPORTER block to consolidate repeated field values
into one row.  If I modify the third exporter block to the following and re-run
**super_mediator**:

    EXPORTER TEXT "dpi"
       PATH "/data/dpi"
       ROTATE 1200
       MULTI_FILES
       DPI_ONLY
       DEDUP_PER_FLOW
       LOCK
    EXPORTER END

    $ cat /data/dpi/http.txt0
    3069422788|1296252022064|0|111|3|Apple iPhone v8A306 Maps v4.0.1
    3069422788|1296252022064|0|112|1|POST /glm/mmap
    3069422788|1296252022064|0|117|3|www.google.com
    3069422788|1296252022064|0|118|1|88
    3069422788|1296252022064|0|118|1|145
    3069422788|1296252022064|0|118|1|221
    3069422788|1296252022064|0|118|1|8
    3069422788|1296252022064|0|118|1|25611
    3069422788|1296252022064|0|123|3|306 Maps v
    3069422788|1296252022064|0|123|2|200 OK
    3069422788|1296252022064|0|121|3|en-us
    3069422788|1296252022064|0|120|3|*/*
    3069422788|1296252022064|0|122|3|application/x-www-form-urlencoded
    3069422788|1296252022064|0|122|2|application/binary
    3069422788|1296252022064|0|114|5|HTTP/1.1

You can see that it changes the format of the CSV file slightly by 
adding an additional column, count.  Using the DEDUP_PER_FLOW
option with TEXT exporters, **super_mediator ** will de-duplicate 
repeated data values and add the count column between the Information
Element ID and the data field. The DEDUP_PER_FLOW option only affects
certain protocols (HTTP, RTSP, SMTP, POP3, IRC, SSH, IMAP, SIP, SLP, 
FTP, POP3, RTSP, MODBUS, ENIP).  **super_table_creator** will create
the count column for the tables if ran with the --dedupflow
option.

Exporter 4 Explained - Custom Exporters {#exp4}
----------------------------------------

The fourth exporter was our "custom list" exporter.  It defined which
fields we wanted to export for each flow.

    $ head -4 /data/dpi/custom.txt
    2011-01-28 21:45:28.636|2011-01-28 21:45:29.131|172.16.0.163|128.121.146.100|\
    58367|80|6|500|S|APSF|AS|APSF|80|111|Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6;\
     en-US; rv:1.9.2.13) Gecko/20101203 Firefox/3.6.13
    2011-01-28 21:45:28.636|2011-01-28 21:45:29.131|172.16.0.163|128.121.146.100|\
    58367|80|6|500|S|APSF|AS|APSF|80|112|GET /account/available_features
    2011-01-28 21:45:28.636|2011-01-28 21:45:29.131|172.16.0.163|128.121.146.100|\
    58367|80|6|500|S|APSF|AS|APSF|80|115|http://twitter.com/
    2011-01-28 21:45:28.636|2011-01-28 21:45:29.131|172.16.0.163|128.121.146.100|\
    58367|80|6|500|S|APSF|AS|APSF|80|117|twitter.com


MySQL Bonus - Correlating Exporters. {#correlate}
=============================

The following configuration will allow you to correlate the DPI data with all of the
flow information in order to view packet/byte count, TCP flags, etc.

You should create two exporters, one MULTI_FILES exporter and one custom exporter:
    
    EXPORTER TEXT
      PATH "/data/mediator/dpi"
      ROTATE 600
      MULTI_FILES
      LOCK
      DPI_ONLY
      TIMESTAMP_FILES
      REMOVE_UPLOADED
      MYSQL_USER "mediator"
      MYSQL_PASSWORD "AnExtremelySecretPassword"
      MYSQL_DATABASE "super_flows"
    EXPORTER END
    
    
    EXPORTER TEXT
      PATH "/data/mediator/dpi/fflow"
      FIELDS hash,stimems,etimems,sipint,dipint,sport,dport,protocol,application,vlanint,\
      OBDOMAIN,pkts,rpkts,bytes,rbytes,iflags,riflags,uflags,ruflags
      ROTATE 600
      REMOVE_UPLOADED
      TIMESTAMP_FILES
      MYSQL_USER "mediator"
      MYSQL_PASSWORD "AnExtremelySecretPassword"
      MYSQL_DATABASE "super_flows"
      MYSQL_TABLE "custom_flow"
    EXPORTER END
    

For the second exporter, you will need to create a new table in the database
that matches the fields you defined.  As a bonus, I have included the 
MySQL create table command to create the corresponding table for
the above exporter:
    
    CREATE TABLE `custom_flow` (
     `flow_key` int unsigned NOT NULL,
     `stime` bingint unsigned DEFAULT NULL,
     `etime` bigint unsigned DEFAULT NULL,
     `sip` int unsigned DEFAULT NULL,
     `dip` int unsigned DEFAULT NULL,
     `sport` mediumint unsigned DEFAULT NULL,
     `dport` mediumint unsigned DEFAULT NULL,
     `protocol` tinyint unsigned DEFAULT NULL,
     `application` mediumint unsigned DEFAULT NULL,
     `vlan` int unsigned DEFAULT NULL,
     `obid` int unsigned  DEFAULT NULL,
     `pkts` bigint unsigned  DEFAULT NULL,
     `rpkts` bigint unsigned DEFAULT NULL,
     `bytes` bigint  unsigned DEFAULT NULL,
     `rbytes` bigint unsigned DEFAULT NULL,
     `iflags` VARCHAR(10) DEFAULT NULL,
     `riflags` VARCHAR(10) DEFAULT NULL,
     `uflags` VARCHAR(10) DEFAULT NULL,
     `ruflags` VARCHAR(10) DEFAULT NULL
    );
    
So if something interesting is identified in the DPI data, it can easily
be joined with the custom_flow table to determine packet and byte counts.








