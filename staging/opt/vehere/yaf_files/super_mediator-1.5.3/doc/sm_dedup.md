super_mediator De-duplication Tutorial {#smdedup}
==========================================

* [Overview](#overview)
* [Configuration File](#config)
* [Examples](#examples)
    * [TEXT Exporter](#text)
    * [JSON Exporter](#json)
    * [IPFIX File Exporter](#ipfix)
    * [TCP Exporter](#tcp)
* [MERGE_TRUNCATED](#merge)

Overview {#overview}
====================

**super_mediator** has always been capable of performing de-duplication
of DNS resource records. If enabled, **super_mediator** collects
all DNS resource records captured and exported by **yaf** and caches
unique name, value pairs for A, AAAA, NS, CNAME, PTR, SOA, MX, TXT, SRV,
NX, and particular DNSSEC records. The 1.1.0 release of **super_mediator**
extends this capability to other types of DPI data. For example, it 
may be of interest to determine what user agent string a particular IP
Address used at any point in time or to identify unique IP, service string
pairs on your network.  This type of information can assist in fingerprinting
hosts or identifying vulnerable systems on the network.

The de-duplication feature discussed in this article is different
from the DEDUP_PER_FLOW de-duplication that is performed within
each flow record and discussed [here](sm_guide.html).

**super_mediator** de-duplication configured within the DEDUP_CONFIG
block is done per IP address.  **super_mediator** caches all unique
IP, data pairs. This unique tuple is only flushed from memory when
either the MAX_HIT_COUNT value has been reached or the tuple has
not been seen within the FLUSH_TIMEOUT period.


Configuration File {#config}
============================

De-duplication of all data types other than DNS resource record
responses must be configured through the super_mediator.conf 
configuration file. The DEDUP_CONFIG block must be associated
with a single EXPORTER block. If the EXPORTER is a TEXT exporter 
the PATH defined in the EXPORTER block must be a
valid file directory.  For each PREFIX line present within
the DEDUP_CONFIG block, a separate file will be created with
the file name prefix defined on the PREFIX line. For IPFIX
FILE exporters, the PATH in the EXPORTER block will be
the file name used, or if ROTATE is also present, the PATH
will be the file prefix used and the date and serial number will
be appended to the file prefix in the form -YYYYMMDDHHMMSS-SSSSS.med.

Examples {#examples}
--------------------

Below are four configuration file and data examples of EXPORTERS 
that have a DEDUP_CONFIG block associated with it. 

### TEXT Exporter {#text}

The following is an example configuration for a TEXT exporter:

    EXPORTER TEXT "dedup"
        PATH "/data/dedup"
        ROTATE 300
        LOCK
    EXPORTER END
    
    DEDUP_CONFIG "dedup"
        PREFIX "useragent" [111]
        PREFIX "server" DIP [110, 171]
        PREFIX "host" [117]
        PREFIX "dns" [179]
    DEDUP_CONFIG END

By default, the Source IP Address is cached, along with the data
value identified by the information element ID(s) defined
within the square brackets on the PREFIX line. Some information
element IDs are associated with the server, and therefore,
using the destination IP address would make more sense.  The
example above configures **super_mediator** to de-duplicate
unique SIP, HTTP user agent pairs, unique DIP, HTTP server strings and 
SSH version pairs, unique SIP, HTTP Host strings, and DNS queries.  
**The only information element
ID valid for DNS is 179.** Using 179, will configure **super_mediator**
to de-duplicate unique Source IP Address and DNS query pairs. To
de-duplicate on DNS responses, refer to the [super_mediator.conf](super_mediator.conf.html) man
page, specifically the DNS_DEDUP block. **The only information element ID
valid for SSL is 244.** See the [SSL de-duplication article](sm_ssl_dedup.html) for more
information.

The CSV data format for de-duplicated data values configured
in the DEDUP_CONFIG block is:

    first_seen | last_seen | IP address | flowkeyhash | count | data

first_seen is the flowStartMilliseconds of the first flow
that contained this unique pair. first_seen is a timestamp in the form 
"2012-01-23 04:45:13.897."

last_seen is the flowStartMilliseconds of the last flow
before the record was flushed that contained this unique pair.  last_seen
is a timestamp in the form "2012-01-23 04:45:13.897."

IP address is, by default, the sourceIPv4Address or sourceIPv6Address
of the flow.  This behavior can be changed by adding "DIP" to the PREFIX
line in the DEDUP_CONFIG block.  

flowkeyhash is the 32-bit hash of the 5-tuple + vlan of the last flow
that contained this unique pair. This value can be used to pivot into 
a PCAP data repository, if available.  See [this YAF PCAP tutorial](../yaf/libyaf/yaf_pcap.html)
for more information.

count is the number of times this unique pair was seen within the
first_seen, last_seen time period.  

data is the value retrieved from
the incoming IPFIX stream identified by the information element ID 
defined in the square brackets on the PREFIX line within the DEDUP_CONFIG
block.

**SSL de-duplicated data has a slightly different format. See [this article](sm_ssl_dedup.html) 
for more information about SSL de-duplication.**

See the following example data (lines wrapped for readability):


    $ head -n 5 /data/dedup/host.20110128220025.txt 
    2011-01-28 21:45:34.904|2011-01-28 21:45:34.995|10.10.1.60|2640424260|4|www.google.com
    2011-01-28 21:45:37.636|2011-01-28 21:45:37.636|10.10.0.205|696160288|1|api.twitter.com
    2011-01-28 21:45:27.349|2011-01-28 21:45:43.933|10.10.0.196|2697798766|2|www.funtrivia.com
    2011-01-28 21:45:40.508|2011-01-28 21:45:40.508|10.11.0.139|3092428228|1|ajax.googleapis.com
    2011-01-28 21:46:51.836|2011-01-28 21:46:51.836|10.10.1.33|741168033|1|mirror.liberty.edu

    $ head -n 5 /data/dedup/useragent.20110128220025.txt
    2011-01-28 21:45:34.904|2011-01-28 21:45:34.995|10.10.1.60|2640424260|4|Mozilla/5.0 \
    (X11; U; Linux i686; en-US; rv:1.9.0.8) Gecko/2009033100 Ubuntu/9.04 (jaunty) Firefox/3.0.8
    2011-01-28 21:45:37.636|2011-01-28 21:45:37.636|10.10.0.205|696160288|1|TwitterAndroid/1.0.5 \
    (109) Nexus One/8 (HTC;passion)
    2011-01-28 21:46:23.366|2011-01-28 21:46:23.426|10.13.0.63|3301408776|2|urlgrabber/3.9.1 yum/3.2.28
    2011-01-28 21:46:06.001|2011-01-28 21:47:06.736|10.11.0.139|671893917|4|OpenTable/3.2 \
    CFNetwork/485.12.7 Darwin/10.4.0
    2011-01-28 21:47:06.458|2011-01-28 21:47:15.766|10.13.0.65|2005639129|6|ChessWithFriendsPaid/3.07 \
    CFNetwork/485.12.7 Darwin/10.4.

    $ head -n 5 /data/dedup/dns.20110128220025.txt 
    2011-01-28 21:50:31.285|2011-01-28 21:50:31.285|10.10.1.60|1463750989|1|suggestqueries.google.com.
    2011-01-28 21:50:31.285|2011-01-28 21:50:31.285|10.10.1.60|739184970|1|id.google.com.
    2011-01-28 21:50:36.205|2011-01-28 21:50:36.205|10.10.0.251|428413069|1|14-courier.push.apple.com.
    2011-01-28 21:50:36.205|2011-01-28 21:50:36.205|10.10.1.31|1604129129|1|reviews-cdn.northerntool.com.
    2011-01-28 21:50:36.205|2011-01-28 21:50:36.205|10.10.1.31|1247744361|1|answers.northerntool.com.

In the above examples, **yaf** generated an IPFIX file from a large PCAP file
captured at a conference in 2011.  **super_mediator** used the IPFIX 
file as input and de-duplicated unique IP, data pairs defined in
the DEDUP_CONFIG block. Perhaps you are curious about the particular
DNS query made by IP 10.10.1.60 to "id.google.com" and would like
to see the PCAP of this particular DNS transaction.  You can simply provide
the flow key hash to **yaf** to generate the PCAP file for this particular
flow:

    $ yaf --in big.pcap --no-output --pcap=mydns.pcap --max-payload=2000 \
    --hash=739184970 --verbose

    $ tcpdump -r mydns.pcap 
    reading from file mydns.pcap, link-type EN10MB (Ethernet)
    17:45:29.409353 IP 10.10.1.60.53168 > resolver1.level3.net.domain: 28965+ A? id.google.com. (31)
    17:45:29.412611 IP resolver1.level3.net.domain > 10.10.1.60.53168: 28965 5/0/0 \
    CNAME id.l.google.com., A 72.14.204.101, A 72.14.204.102, A 72.14.204.113, A 72.14.204.100 (114)

### JSON Exporter {#json}

The following is an example configuration for a JSON exporter:

    EXPORTER TEXT "dedup"
        PATH "/data/dedup"
        JSON
    EXPORTER END

    DEDUP_CONFIG "dedup"
        PREFIX "useragent" [111]
        PREFIX "server" DIP [110, 171]
        PREFIX "host" [117]
        PREFIX "dns" [179]
        MAX_HIT_COUNT 10000
        FLUSH_TIMEOUT 600
    DEDUP_CONFIG END

JSON exporters configured with a DEDUP_CONFIG block will have
the top-level command "dedup."  The same columns defined
above for CSV export will be present in the JSON record.
**super_mediator** will use the PREFIX name for the data
keyword.

    $ cat /data/dedup/host.txt
    {"dedup":{"firstSeen":"2011-01-28 21:46:13.580","lastSeen":"2011-01-28 21:47:45.852",\
    "sourceIPv4Address":"10.13.0.70","flowKeyHash":574225501,"observedDataTotalCount":8,\
    "host":"search.twitter.com"}}
    {"dedup":{"firstSeen":"2011-01-28 21:47:46.994","lastSeen":"2011-01-28 21:47:46.994",\
    "sourceIPv4Address":"10.10.1.59","flowKeyHash":3289550532,"observedDataTotalCount":1,\
    "host":"ocsp.godaddy.com"}}
    {"dedup":{"firstSeen":"2011-01-28 21:47:47.073","lastSeen":"2011-01-28 21:47:47.073",\
    "sourceIPv4Address":"10.10.1.59","flowKeyHash":2310975606,"observedDataTotalCount":1,\
    "host":"en-us.fxfeeds.mozilla.com"}}
    {"dedup":{"firstSeen":"2011-01-28 21:47:47.073","lastSeen":"2011-01-28 21:47:47.073",\
    "sourceIPv4Address":"10.10.1.59","flowKeyHash":2310910070,"observedDataTotalCount":1,\
    "host":"fxfeeds.mozilla.com"}}
    {"dedup":{"firstSeen":"2011-01-28 21:47:30.433","lastSeen":"2011-01-28 21:47:31.174",\
    "sourceIPv4Address":"10.10.1.4","flowKeyHash":1147488830,"observedDataTotalCount":2,\
    "host":"chibis.adotube.com"}}

### IPFIX File Exporter {#ipfix}

The following is an example configuration for a IPFIX file exporter:

    EXPORTER FILEHANDLER "dedup"
        PATH "/data/dedup"
        ROTATE 120
        LOCK
    EXPORTER END

    DEDUP_CONFIG "dedup"
        PREFIX "useragent" [111]
        PREFIX "server" DIP [110, 171]
        PREFIX "host" [117]
        PREFIX "dns" [179]
    DEDUP_CONFIG END

The IPFIX template will have the following elements (output produced by [ipfixDump](../yaf/ipfixDump.html)):

    --- template record ---
    header:
    	 tid: 55976 (0xdaa8)	field count:     7	scope:     0
    fields:
    	 ent:     0  id:   152  type: milsec	length:     8  flowStartMilliseconds
    	 ent:     0  id:   153  type: milsec	length:     8  flowEndMilliseconds
    	 ent:  6871  id:   929  type: octet	length:     8  observedDataTotalCount
    	 ent:     0  id:    27  type: ipv6	length:    16  sourceIPv6Address
    	 ent:     0  id:     8  type: ipv4	length:     4  sourceIPv4Address
    	 ent:  6871  id:   106  type: uint32	length:     4  flowKeyHash
    	 ent:  6871  id:   930  type: octet	length: 65535  observedData

**super_mediator** can read the IPFIX file it created:

    $ super_mediator -i /data/dedup-20150630135338-00000.med -o - -m TEXT | less
    
    2011-01-28 21:46:06.001|2011-01-28 21:47:06.736|10.11.0.139|671893917|4|OpenTable/3.2 \
    CFNetwork/485.12.7 Darwin/10.4.0
    2011-01-28 21:45:40.508|2011-01-28 21:47:04.890|10.11.0.139|3000427195|10|www.opentable.com
    2011-01-28 21:47:06.736|2011-01-28 21:47:06.736|10.11.0.139|671893917|1|data.flurry.com
    2011-01-28 21:47:08.890|2011-01-28 21:47:08.890|10.13.0.65|1959568909|1|ads.mobclix.com
    2011-01-28 21:47:06.977|2011-01-28 21:47:08.985|10.13.0.65|2005835719|3|newtoyinc.com
    2011-01-28 21:47:09.036|2011-01-28 21:47:09.036|10.13.0.65|379960495|1|s.mobclix.com


### TCP Exporter {#tcp}

The following is an example configuration for a TCP exporter:

    EXPORTER TCP "dedup"
       HOST "localhost"
       PORT 18000
    EXPORTER END

    DEDUP_CONFIG "dedup"
        PREFIX "useragent" [111]
        PREFIX "server" DIP [110, 171]
        PREFIX "host" [117]
        PREFIX "dns" [179]
    DEDUP_CONFIG END

    
To collect this information via TCP, another **super_mediator** can
be used to listen for TCP connections on port 18000:

    $ super_mediator -i localhost --ipfix-input=TCP -m TEXT --ipfix-port=18000
    2011-01-28 21:59:00.189|2011-01-28 21:59:00.189|10.10.0.188|970020836|1|securityd \
    (unknown version) CFNetwork/485.2 Darwin/10.3.1
    2011-01-28 21:59:06.491|2011-01-28 21:59:12.815|10.10.0.188|4017770420|19|Apple%20Store/1.2.1 \
    CFNetwork/485.2 Darwin/10.3.1
    2011-01-28 21:59:12.815|2011-01-28 22:00:06.234|10.10.0.188|4016590772|4|CMC
    2011-01-28 21:59:12.731|2011-01-28 22:00:25.761|10.10.0.188|3069422788|9|Apple iPhone v8A306 Maps v4.0.1
    2011-01-28 21:58:57.019|2011-01-28 21:58:57.019|10.13.0.72|4253820902|2|Microsoft-CryptoAPI/5.131.2600.5512

MERGE_TRUNCATED {#merge}
---------------------

If the MERGE_TRUNCATED keyword is present in the DEDUP_CONFIG block,
**super_mediator** will collapse truncated records into the longest
data value.  **yaf** captures and stores a limited amount of payload data 
for each flow in memory.  The amount of payload it captures is set by
the user on the command line with the --max-payload option. Often,
HTTP headers will get truncated at the max-payload limit.  Data can
also be truncated by the dpacketplugin in YAF when the max-export
limit is met (this value is set in the yafDPIRules.conf file). This will
result in duplicate header fields with one value truncated. 

For example, the following is the output for a TEXT EXPORTER that does
not have the MERGE_TRUNCATED keyword present:

    2011-01-28 21:46:40.534|2011-01-28 21:46:40.534|10.13.0.69|3132439844|1|Mozilla/5.0 (Macintosh; U; \
    Intel Mac OS X 10_6_6; en-us) AppleWebKit/533.19.4 (KHTML, like Gecko) Version/5.0.3 Safari/533.1
    2011-01-28 21:47:49.400|2011-01-28 21:47:49.400|10.13.0.69|3038288354|1|Mozilla/5.0 (Macintosh; U; \
    Intel Mac OS X 10_6_6; en-us) Apple
    2011-01-28 21:47:49.400|2011-01-28 21:47:49.400|10.13.0.69|3038484962|1|Mozilla/5.0 (Macintosh; U; \
    Intel Mac OS X 10_6_6; en-us) AppleWebKit/53
    2011-01-28 21:47:49.401|2011-01-28 21:47:49.401|10.13.0.69|3038419426|1|Mozilla/5.0 (Macintosh; U; \
    Intel Mac OS X 10_6_6; e
    2011-01-28 21:47:49.402|2011-01-28 21:47:49.402|10.13.0.69|3038747106|1|Mozilla/5.0 (Macintosh; U;
    2011-01-28 21:46:40.519|2011-01-28 21:47:49.402|10.13.0.69|3038616034|26|Mozilla/5.0 (Macintosh; U; \
    Intel Mac OS X 10_6_6; en-us) AppleWebKit/533.19.4 (KHTML, like Gecko) Version/5.0.3 Safari/533.19.4

Using the MERGE_TRUNCATED keyword will collapse all of the above records into:

    2011-01-28 21:46:40.519|2011-01-28 21:47:49.402|10.13.0.69|3038616034|31|Mozilla/5.0 (Macintosh; U; \
    Intel Mac OS X 10_6_6; en-us) AppleWebKit/533.19.4 (KHTML, like Gecko) Version/5.0.3 Safari/533.19.4


