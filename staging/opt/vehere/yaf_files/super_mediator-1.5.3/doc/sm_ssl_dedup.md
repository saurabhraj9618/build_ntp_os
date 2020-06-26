super_mediator SSL Certificate De-duplication Configuration Tutorial {#sm_ssl_dedup}
==================================================

* [Overview](#overview)
* [Configuration File](#config)
* [Example TEXT Exporter](#text)
* [De-duplicating IPs and Certificates](#ip)
* [Using MySQL](#mysql)

Overview {#overview}
====================

SSL/TLS are cryptographic protocols that add encryption and entity
authentication to Internet communications.  These protocols are commonly
used with HTTP, aka HTTPS, to secure web traffic.
Servers send certificates to clients to authenticate themselves for TLS
sessions.  Certificates are issued to administrators by Certificate
Authorities (CAs). The role of the CA is to verify that the certificate
holder is in control of the domain name in question and then mathematically
bind particular encryption parameters to that domain name.  

TLS connections start with an unencrypted handshake. The server presents
its authentication credentials in the form of a certificate.  The certificate
contains public information about the server, such as its advertised domain name,
public key, company, and information about the CA that issued the certificate.
The certificate also contains certain characteristics that should prove
the validity and authenticity of the certificate.

Computer Network Defense (CND) analysts often want to identify
certificates used by malware command and control servers, certificates
with weak cryptographic parameters to determine at-risk connections, and
forged certificates. Collecting certificate information traversing 
the network can assist
analysts in comparing collected certificate attributes to known forged
or compromised certificate attributes.

Collecting SSL/TLS certificates can be very cumbersome, as they are rather large
and you can end up with a lot of duplicate data, putting
a strain on storage resources. **super_mediator** can help with de-duplicating
SSL certificates by writing certificate data captured by **yaf** once and
caching the certificate's serial number and issuer name in memory until 
either the MAX_HIT_COUNT has been met or the unique pair has not been
seen in the FLUSH_TIMEOUT period.  This tutorial will provide examples
of **super_mediator** SSL de-duplication configurations. 

Configuration File {#config}
============================

The most important part of the configuration file for SSL de-duplication
is the SSL_CONFIG block.  An SSL_CONFIG block must be associated with
a single EXPORTER.  SSL de-duplication can be configured for any
type of EXPORTER (TEXT, JSON, IPFIX, TCP, etc.).  If SSL de-duplication
is enabled, **super_mediator** exports two unique types of records: "certificate" 
records, and "dedup" records.  "Certificate" records contain all of the
data that **yaf** captures for an X.509 Certificate.  The full list can be
found in the [yafdpi man page](../yaf/yafdpi.html).  The fields that
**super_mediator** exports in "Certificate" records is configurable in
the SSL_CONFIG block with the ISSUER, SUBJECT, OTHER, and EXTENSION keywords.
The argument provided with each one of these keywords is a bracketed-list
of object identifier values.  Some common object IDs for certificate ISSUER
and SUBJECT are listed in the following
table.  By default, **super_mediator** will export all issuer and subject fields.
 
id | description
--- | ---
3 | common name
6 | country name
7 | locality name
8 | state or province name
9 | street address
10 | organization
11 | organizational unit
12 | title
17 | postal code
41 | name

The OTHER list can contain any one of the following information element
IDs:

id | description
--- | ---
186 | ssl Client version
187 | ssl server cipher
188 | ssl compression method
189 | ssl cert version
244 | ssl cert serial number
247 | ssl cert validity not before
248 | ssl cert validity not after
250 | ssl public key length
288 | ssl record version
294 | ssl server name
298 | sha1 hash of X.509 certificate
299 | md5 hash of X.509 certificate


The EXTENSION list can contain any of the following object identfier
values.  By default, **super_mediator** will not write any EXTENSION
objects.  These must be explicitly identified in the SSL_CONFIG block.

id | description
--- | ---
14 | subject Key Identifier
15 | key Usage
16 | private Key Usage Period
17 | subject Alt Name (list)
18 | issuer Alt Name (list)
29 | certificate Issuer (list)
31 | CRL Distribution points (list)
32 | certificate policies

To force **super_mediator** to write all SSL certificate characteristics
captured by **yaf**, use the following configuration:

    SSL_CONFIG "exportername"
       ISSUER [*]
       SUBJECT [*]
       OTHER [*]
       EXTENSIONS [*]
    SSL_CONFIG END

The "certificate" record will have the following CSV format:

serial number | issuer name | first_seen | obj id | ISE | cert_no | data

field | description
--- | ---
serial number | the serial number of the X.509 Certificate (hexadecimal)
issuer name | the common name of the Issuer (Certificate Authority) in the X.509 certificate
first_seen | the first time this certificate was seen (start time of the flow that contained this certificate)
obj id | object/member ID for the X.509 RelativeDistinguishedName Sequence (see tables above)
ISE | ISE denotes if the data came from an Issuer Field (I), Subject Field (S), or Extension Field (E)
cert_no | cert_no signifies which certificate the data came from in the certificate chain. Usually, this field will contain a 0, 1, or 2.
data | data collected by YAF (typically a string, but may be hexadecimal)

There may be more than one of the same object IDs present for a ssl certificate 
if the object is a list (e.g. issuerAltName).

The IPFIX template for the "certificate" record is as follows:

    --- template record ---
    header:
    	tid: 51723 (0xca0b)	field count:    11	scope:     0
    fields:
    	 ent:     0  id:   292  type: stl	length: 65535  subTemplateList
    	 ent:     0  id:   292  type: stl	length: 65535  subTemplateList
    	 ent:     0  id:   292  type: stl	length: 65535  subTemplateList
    	 ent:  6871  id:   190  type: octet	length: 65535  sslCertSignature
    	 ent:  6871  id:   244  type: string	length: 65535  sslCertSerialNumber
    	 ent:  6871  id:   247  type: string	length: 65535  sslCertValidityNotBefore
    	 ent:  6871  id:   248  type: string	length: 65535  sslCertValidityNotAfter
    	 ent:  6871  id:   249  type: octet	length: 65535  sslPublicKeyAlgorithm
  	 ent:  6871  id:   250  type: uint16	length:     2  sslPublicKeyLength
    	 ent:  6871  id:   189  type: uint8	length:     1  sslCertVersion
  	 ent:     0  id:   210  type: octet	length:     5  paddingOctets


The other type of record **super_mediator** will export is a 
"dedup" record.  A "dedup" record is a short record that simply
provides the first and last time a certificate was seen, the 
unique identifier for a certificate (serial number, issuer name),
and the number of times it was seen within that time period. The
CSV format is as follows:

first_seen | last_seen | serial number | count | issuer name

field | description
--- | ---
first_seen | the first time this certificate was seen (start time of the flow that contained this certificate)
last_seen | the last time this certificate was seen before the record was flushed (start time of the flow that contained this certificate)
serial number | the serial number of the X.509 Certificate (hexadecimal)
count | the number of times the certificate was seen in the time period
issuer name | the common name of the Issuer (Certificate Authority) in the X.509 certificate

The "dedup" IPFIX template is as follows:

    --- template record ---
    header:
    	tid: 55983 (0xdaaf)	field count:     5	scope:     0
    fields:
    	 ent:     0  id:   152  type: milsec	length:     8  flowStartMilliseconds
    	 ent:     0  id:   153  type: milsec	length:     8  flowEndMilliseconds
    	 ent:  6871  id:   929  type: octet	length:     8  observedDataTotalCount
    	 ent:  6871  id:   244  type: string	length: 65535  sslCertSerialNumber
    	 ent:  6871  id:   196  type: octet	length: 65535  sslCertIssuerCommonName


To enable SSL Certificate de-duplication either the SSL_DEDUP_ONLY
keyword must be present in the EXPORTER block **OR** the SSL_DEDUP
keyword must be present in the SSL_CONFIG block:
	
    EXPORTER TEXT "name"
        PATH "/data/ssl/sslcerts.txt"
        SSL_DEDUP_ONLY
    EXPORTER END

**OR**

    SSL_CONFIG "exportername"
        SSL_DEDUP
    SSL_CONFIG END

By default, **super_mediator** will write both types of records
(certificate and dedup) to the filename given to "PATH" in the EXPORTER
block.  However, if the CERT_FILE keyword is present in the SSL_CONFIG
block, **super_mediator** will write "certificate" records to the filename
given to CERT_FILE. This file will rotate and/or lock using the same
configuration settings given in the EXPORTER block associated with
the SSL_CONFIG block.  The CERT_FILE keyword is ignored for all exporter
types other than TEXT. 

Example TEXT Exporter {#text}
==============================

The following is an example configuration file that enables
SSL Certificate de-duplication and exports all characteristics
of an SSL certificate to the rotating file prefix "/data/ssl/sslcerts".

    EXPORTER TEXT "e1"
      PATH "/data/ssl/certs_dedup"
      SSL_DEDUP_ONLY
      ROTATE 300
      LOCK
    EXPORTER END
    
    SSL_CONFIG "e1"
      ISSUER [*]
      SUBJECT [*]
      OTHER [*]
      EXTENSIONS [*]
      CERT_FILE "/data/ssl/certs"
      MAX_HIT_COUNT 25000
      FLUSH_TIME 3600
    SSL_CONFIG END

The following is an example of the data that the above configuration
produces:

    $ cat /data/ssl/certs_dedup.20150408192918.txt
    2015-04-08 19:14:29.556|2015-04-08 19:28:57.914|0x008620ad42a17aea20|4|Go Daddy Secure Certificate Authority - G2
    2015-04-08 19:29:14.389|2015-04-08 19:29:14.389|0x01fe4a238b2e7ce313c506df7fd7ca4e|4|DigiCert SHA2 Secure Server CA
    2015-04-08 19:16:20.469|2015-04-08 19:29:14.389|0x01fda3eb6eca75c888438b724bcfbc91|38|DigiCert Global Root CA
    2015-04-08 19:29:14.391|2015-04-08 19:29:14.391|0x040bd4f82588c5|4|Go Daddy Secure Certificate Authority - G2
    2015-04-08 19:17:14.651|2015-04-08 19:29:14.404|0x5cc17e9b9b4933fe|10|Google Internet Authority G2


    $ cat /data/ssl/certs.20150408191312.txt 
    
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|6|I|0|US
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|8|I|0|Arizona
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|7|I|0|Scottsdale
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|10|I|0|GoDaddy.com, Inc.
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|11|I|0|http://certs.godaddy.com/repository/
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|3|I|0|Go Daddy Secure Certificate Authority - G2
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|11|S|0|Domain Control Validated
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|3|S|0|load.exelator.com
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|15|E|0|03 02 05 a0
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|31|E|0|http://crl.godaddy.com/gdig2s1-87.crl
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|32|E|0|60 86 48 01 86 fd 6d 01 07 17 01
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|32|E|0|http://certificates.godaddy.com/repository/
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|17|E|0|load.exelator.com
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|17|E|0|www.load.exelator.com
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|17|E|0|meta.exelator.com
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|17|E|0|loadm.exelator.com
    
As you can see from the above example data the Go Daddy certificate 
with serial number 0x008620ad42a17aea20 was seen four times within
a 14 minute time period.  

De-duplicating IPs and Certificates {#ip}
=====================================

Now that the SSL certificates have been collected and de-duplicated, 
it might be necessary to determine which IP address on the network
received a particular certificate.  The SSL certificate de-duplication
feature can be combined with the DEDUP_CONFIG block to determine which 
IP used a particular certificate.

    EXPORTER TEXT "ssl_ip_dedup"
        PATH "/data/ssl/"
        ROTATE 300
        LOCK
    EXPORTER END

    DEDUP_CONFIG "ssl_ip_dedup"
        PREFIX ssl_ip_dedup [244]
    DEDUP_CONFIG END

Adding the above DEDUP_CONFIG block and EXPORTER block to
the above configuration will configure **super_mediator** to de-duplicate
unique IP address, certificate chain tuples.  **super_mediator** will
store in memory every unique serial number, issuer name tuple for 
a certificate. Furthermore, it will maintain information about the 
certificate chain an IP address receives in the TLS handshake.
**super_mediator** will export the IP and first two certificate tuples
when MAX_HIT_COUNT or FLUSH_TIMEOUT period has been met.  The CSV
format for these records is as follows:

first_seen | last_seen | IP | flowkeyhash | count | serial1 | issuer1 | serial2 | issuer2

field | description
--- | ---
first_seen | the first time the IP received this certificate chain
last_seen | the last time the IP received this certificate chain before it flushed the record
IP | the IP address, source IP address by default. Use DIP keyword on PREFIX line to use the destination IP address
flowkeyhash | the 32 bit hash of the last flow's 5-tuple + vlan with this unique tuple
count | the number of times this IP, certificate chain tuple was seen in the time period
serial1 | the serial number of the first certificate in the SSL certificate chain
issuer1 | the issuer's common name of the first certificate in the SSL certificate chain
serial2 | the serial number of the second certificate in the SSL certificate chain
issuer2 | the issuer's common name of the second certificate in the SSL certificate chain

Typically, the first certificate is an end-user certificate that 
cannot be trusted as it is not embedded in the web browser
or operating system.  The second certificate is the intermediate or 
root certificate that may be explicitly trusted if it is issued
by a CA that is embedded in the web browser or OS.

The serial number, issuer name pair will let the analyst pivot
between the "certificate records" and the "IP dedup" records
to determine when an IP saw a particular certificate and
the particular characteristics of that certificate.

The above additions to the configuration file will produce
the following data:

    $ cat /data/ssl/ssl_ip_dedup.20150408192918.txt
    2015-04-08 19:14:29.556|2015-04-08 19:14:29.680|10.27.33.66|2154341740|2|\
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|\
    0x07|Go Daddy Root Certificate Authority - G2
    2015-04-08 19:15:24.633|2015-04-08 19:17:14.722|10.27.33.66|3741584532|6|\
    0x0754|GeoTrust SSL CA - G4|0x023a79|GeoTrust Global CA
    2015-04-08 19:14:54.239|2015-04-08 19:17:14.724|10.27.33.66|3730640023|10|\
    0x0765|GeoTrust SSL CA - G4|0x023a79|GeoTrust Global CA
    2015-04-08 19:18:10.483|2015-04-08 19:19:04.602|10.27.33.66|395876596|6|\
    0x516f2670a7991b70|Google Internet Authority G2|0x023a76|GeoTrust Global CA

Using MySQL {#mysql}
=======================

The data produced by **super_mediator** can easily be imported into a MySQL
database.  **super_table_creator** will create the appropriate tables for the
data produced by the above configuration.

    $ super_table_creator -n root -p password -d ssl_database --ssl-certs
    certs table successfully created
    certs_dedup table successfully created

    $ super_table_creator -n root -p password -d ssl_database --ssl-dedup
    Ignoring Warning: Database ssl_database 1007: Can't create database 'ssl_database'; database exists
    ssl_ip_dedup table successfully created

The Warning produced by **super_table_creator** just means that the database
already exists.  **super_table_creator** tries to create the database
every time it is run.  If it already exists, this error is ignored.

Now the data can be easily imported using the mysqlimport tool:

    $ mysqlimport -u root -p --fields-terminated-by="|" ssl_database /data/ssl/certs_dedup.20150408192918.txt
    Enter password: 
    ssl_database.certs_dedup: Records: 440  Deleted: 0  Skipped: 0  Warnings: 0

    $ mysqlimport -u root -p --fields-terminated-by="|" ssl_database /data/ssl/ssl_ip_dedup.20150408192918.txt 
    Enter password: 
    ssl_database.ssl_ip_dedup: Records: 338  Deleted: 0  Skipped: 0  Warnings: 0

    $ mysqlimport -u root -p --fields-terminated-by="|" ssl_database /data/ssl/certs.20150408192355.txt 
    Enter password: 
    ssl_database.certs: Records: 1540  Deleted: 0  Skipped: 0  Warnings: 0

