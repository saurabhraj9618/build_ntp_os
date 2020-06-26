/**
 * @file templates.h
 *
 * contains all the templates the mediator needs to collect/export
 *
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2012-2017 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Emily Sarneso
 ** ------------------------------------------------------------------------ *
 * @OPENSOURCE_HEADER_START@
 * Use of this (and related) source code is subject to the terms
 * of the following licenses:
 *
 * GNU Public License (GPL) Rights pursuant to Version 2, June 1991
 * Government Purpose License Rights (GPLR) pursuant to DFARS 252.227.7013
 *
 *
 * This material is based upon work funded and supported by
 * the Department of Defense under Contract FA8721-05-C-0003 with
 * Carnegie Mellon University for the operation of the Software Engineering
 * Institue, a federally funded research and development center. Any opinions,
 * findings and conclusions or recommendations expressed in this
 * material are those of the author(s) and do not
 * necessarily reflect the views of the United States
 * Department of Defense.
 *
 * NO WARRANTY
 *
 * THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE
 * MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY
 * MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED
 * AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF
 * FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS
 * OBTAINED FROM THE USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY
 * DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM
 * PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
 *
 * This material has been approved for public release and unlimited
 * distribution.
 *
 * Carnegie Mellon®, CERT® and CERT Coordination Center® are
 * registered marks of Carnegie Mellon University.
 *
 * DM-0001877
 *
 * Carnegie Mellon University retains
 * copyrights in all material produced under this contract. The U.S.
 * Government retains a non-exclusive, royalty-free license to publish or
 * reproduce these documents, or allow others to do so, for U.S.
 * Government purposes only pursuant to the copyright license under the
 * contract clause at 252.227.7013.
 *
 * Licensee hereby agrees to defend, indemnify, and hold harmless Carnegie
 * Mellon University, its trustees, officers, employees, and agents from
 * all claims or demands made against them (and any related losses,
 * expenses, or attorney's fees) arising out of, or relating to Licensee's
 * and/or its sub licensees' negligent use or willful misuse of or
 * negligent conduct or willful misconduct regarding the Software,
 * facilities, or other rights or assistance granted by Carnegie Mellon
 * University under this License, including, but not limited to, any
 * claims of product liability, personal injury, death, damage to
 * property, or violation of any laws or regulations.
 *
 * @OPENSOURCE_HEADER_END@
 */

#ifndef MD_CONF
#define MD_CONF

#include "mediator_ctx.h"
#if HAVE_OPENSSL
#include <openssl/md5.h>
#include <openssl/sha.h>
#endif

/* Special dimensions */
#define YTF_TOTAL       0x0001
#define YTF_PAD         0x0002
#define YTF_REV         0x0010
#define YTF_TCP         0x0020
#define YTF_DAGIF       0x0040
#define YTF_DELTA       0x0080
#define YTF_LIST        0x0100
#define YTF_IP4         0x0200
#define YTF_IP6         0x0400
#define YTF_MPLS        0x0004

#define MD_LAST_SEEN    0x0002
#define MD_DNSRR_FULL   0x0002
#define MD_DNS_AREC     0x0004
#define MD_DNS_OREC     0x0008
#define MD_DEDUP_SSL    0x0002

/* YAF TID's */
#define YAF_SILK_FLOW_TID      0xB000
#define YAF_OPTIONS_FLOW_TID   0xD000
#define YAF_ENTROPY_FLOW_TID   0xC002
#define YAF_TCP_FLOW_TID       0xC003
#define YAF_MAC_FLOW_TID       0xC004
#define YAF_STATS_FLOW_TID     0xC005
#define YAF_P0F_FLOW_TID       0xC006
#define YAF_HTTP_FLOW_TID      0xC600
#define YAF_FPEXPORT_FLOW_TID  0xC007
#define YAF_PAYLOAD_FLOW_TID   0xC008
#define YAF_MPTCP_FLOW_TID     0xC009
#define YTF_BIF                0xFF0F
#define YAF_IRC_FLOW_TID       0xC200
#define YAF_POP3_FLOW_TID      0xC300
#define YAF_TFTP_FLOW_TID      0xC400
#define YAF_SLP_FLOW_TID       0xC500
#define YAF_FTP_FLOW_TID       0xC700
#define YAF_IMAP_FLOW_TID      0xC800
#define YAF_RTSP_FLOW_TID      0xC900
#define YAF_SIP_FLOW_TID       0xCA00
#define YAF_SMTP_FLOW_TID      0xCB00
#define YAF_SSH_FLOW_TID       0xCC00
#define YAF_NNTP_FLOW_TID      0xCD00
#define YAF_DNS_FLOW_TID       0xCE00
#define YAF_DNSQR_FLOW_TID     0xCF00
#define YAF_DNSA_FLOW_TID      0xCE01
#define YAF_DNSAAAA_FLOW_TID   0xCE02
#define YAF_DNSCN_FLOW_TID     0xCE03
#define YAF_DNSMX_FLOW_TID     0xCE04
#define YAF_DNSNS_FLOW_TID     0xCE05
#define YAF_DNSPTR_FLOW_TID    0xCE06
#define YAF_DNSTXT_FLOW_TID    0xCE07
#define YAF_DNSSRV_FLOW_TID    0xCE08
#define YAF_DNSSOA_FLOW_TID    0xCE09
#define YAF_SSL_FLOW_TID       0xCE0A
#define YAF_SSL_CERT_FLOW_TID  0xCE0B
#define YAF_NEW_SSL_FLOW_TID   0xCA0A
#define SM_INTSSL_FLOW_TID     0xDA0A
#define YAF_NEW_SSL_CERT_TID   0xCA0B
#define SM_INTCERT_FLOW_TID    0xDA0B
#define YAF_SSL_SUBCERT_TID    0xCE14
#define YAF_MYSQL_FLOW_TID     0xCE0C
#define YAF_MYSQLTXT_FLOW_TID  0xCE0D
#define YAF_DNSDS_FLOW_TID     0xCE0E
#define YAF_DNSRRSIG_FLOW_TID  0xCE0F
#define YAF_DNSNSEC_FLOW_TID   0xCE11
#define YAF_DNSKEY_FLOW_TID    0xCE12
#define YAF_DNSNSEC3_FLOW_TID  0xCE13
#define YAF_DHCP_FLOW_TID      0xC201
#define YAF_DNP3_FLOW_TID      0xC202
#define YAF_DNP3_REC_FLOW_TID  0xC203
#define YAF_MODBUS_FLOW_TID    0xC204
#define YAF_ENIP_FLOW_TID      0xC205
#define YAF_RTP_FLOW_TID       0xC206
#define YAF_FULL_CERT_TID      0xC207
#define YAF_DHCP_OP_TID        0xC208
#define MD_DNS_OUT             0xCEE0
#define MD_DNS_FULL            0xCEEF
#define MD_DNSRR               0xC0C1
#define UDP_FORCE              0x1F
#define MD_SSL_TID             0xDAAF
#define MD_DEDUP_TID           0xDAA8
#define MD_DEDUP_FULL          0xDAAA

#define MD_ERROR_DOMAIN     g_quark_from_string("MediatorError")
/* Template Issue - Not Critical*/
#define MD_ERROR_TMPL   1
/* IO Error - Critical */
#define MD_ERROR_IO     2
/* Setup Error */
#define MD_ERROR_SETUP  3
/* memory problem */
#define MD_ERROR_MEM    4
/* Error to ignore */
#define MD_ERROR_NODROP 5
/* silk record */

//MD specific names
#define MD_LAST_SEEN_NAME "last_seen"
#define MD_DNS_AREC_NAME "dns_arec"
#define MD_DNS_OREC_NAME "dns_orec"
#define MD_DNSRR_FULL_NAME "dnsrr_full"
#define MD_DEDUP_SSL_NAME "dedup_ssl"

//also defined in yafcore.c, should consider pulling from YAF
#define YTF_TOTAL_NAME "total"
#define YTF_REV_NAME         "rev"
#define YTF_DELTA_NAME       "delta"
#define YTF_IP6_NAME "ip6"
#define YTF_IP4_NAME "ip4"
#define YTF_DAGIF_NAME       "dagif"
#define YTF_MPLS_NAME        "mpls"

//not defined in YAF, should consider including in YAF
#define YTF_TCP_NAME "tcp"
#define YTF_PAD_NAME "pad"
#define YTF_LIST_NAME "list"

/* Full DNS flow record */
typedef struct md_dns_st {
    uint64_t      fseen;
    uint64_t      lseen;
    uint32_t      ip;
    uint32_t      ttl;
    uint16_t      rrtype;
    uint16_t      hitcount;
    uint8_t       padding[4];
    fbVarfield_t  rrname;
    fbVarfield_t  rrdata;
    fbVarfield_t  mapname;
} md_dns_t;


/*SSL Record */
typedef struct md_ssl_st {
    uint64_t      fseen;
    uint64_t      lseen;
    uint64_t      hitcount;
    fbVarfield_t  serial;
    fbVarfield_t  issuer;
    fbVarfield_t  mapname;
} md_ssl_t;


typedef struct mdRecord_st {
    uint64_t    flowStartMilliseconds;
    uint64_t    flowEndMilliseconds;
    uint64_t    octetTotalCount;
    uint64_t    reverseOctetTotalCount;
    uint64_t    octetDeltaCount;
    uint64_t    reverseOctetDeltaCount;
    uint64_t    packetTotalCount;
    uint64_t    reversePacketTotalCount;
    uint64_t    packetDeltaCount;
    uint64_t    reversePacketDeltaCount;

    uint8_t     sourceIPv6Address[16];
    uint8_t     destinationIPv6Address[16];

    uint32_t    sourceIPv4Address;
    uint32_t    destinationIPv4Address;

    uint16_t    sourceTransportPort;
    uint16_t    destinationTransportPort;
    uint16_t    flowAttributes;
    uint16_t    reverseFlowAttributes;

    uint8_t     protocolIdentifier;
    uint8_t     flowEndReason;
    uint16_t    numAppLabel;
    int32_t     reverseFlowDeltaMilliseconds;

    uint32_t    tcpSequenceNumber;
    uint32_t    reverseTcpSequenceNumber;

    uint8_t     initialTCPFlags;
    uint8_t     unionTCPFlags;
    uint8_t     reverseInitialTCPFlags;
    uint8_t     reverseUnionTCPFlags;
    uint16_t    vlanId;
    uint16_t    reverseVlanId;

    uint32_t    ingressInterface;
    uint32_t    egressInterface;

    uint8_t     ipClassOfService;
    uint8_t     reverseIpClassOfService;
    uint8_t     mpls_label1[3];
    uint8_t     mpls_label2[3];

    uint8_t     mpls_label3[3];
    uint8_t     paddingOctets;
    uint32_t    obsid;

    uint32_t    flowKeyHash;
    uint16_t    ndpi_master;
    uint16_t    ndpi_sub;

    fbSubTemplateMultiList_t stml;

} mdRecord_t;



typedef struct yfIpfixStats_st {
    uint64_t    sysInitTime;
    uint64_t    exportedFlowTotalCount;
    uint64_t    packetTotalCount;
    uint64_t    droppedPacketTotalCount;
    uint64_t    ignoredPacketTotalCount;
    uint64_t    rejectedPacketTotalCount;
    uint32_t    expiredFragmentCount;
    uint32_t    assembledFragmentCount;
    uint32_t    flowTableFlushEvents;
    uint32_t    flowTablePeakCount;
    uint32_t    exporterIPv4Address;
    uint32_t    exportingProcessId;
    uint32_t    meanFlowRate;
    uint32_t    meanPacketRate;
} yfIpfixStats_t;

typedef struct yfSSLFlow_st {
    fbBasicList_t sslCipherList;
    uint32_t      sslServerCipher;
    uint8_t       sslClientVersion;
    uint8_t       sslCompressionMethod;
} yfSSLFlow_t;

typedef struct yfNewSSLFlow_st {
    fbBasicList_t        sslCipherList;
    uint32_t             sslServerCipher;
    uint8_t              sslClientVersion;
    uint8_t              sslCompressionMethod;
    uint16_t             sslRecordVersion;
    fbSubTemplateList_t  sslCertList;
    fbVarfield_t         sslServerName;
} yfNewSSLFlow_t;

typedef struct yfNewSSLCertFlow_st {
    fbSubTemplateList_t     issuer;
    fbSubTemplateList_t     subject;
    fbSubTemplateList_t     extension;
    fbVarfield_t            sig;
    fbVarfield_t            serial;
    fbVarfield_t            not_before;
    fbVarfield_t            not_after;
    fbVarfield_t            pkalg;
    uint16_t                pklen;
    uint8_t                 version;
    uint8_t                 padding[5];
    fbVarfield_t            hash;
    fbVarfield_t            sha1;
    fbVarfield_t            md5;
} yfNewSSLCertFlow_t;

typedef struct yfSSLObjValue_st {
    fbVarfield_t            obj_value;
    uint8_t                 obj_id;
    uint8_t                 padding[7];
} yfSSLObjValue_t;


typedef struct yfSSLCertFlow_st {
    fbVarfield_t sslSignature;
    fbVarfield_t sslICountryName;
    fbVarfield_t sslIOrgName;
    fbVarfield_t sslIOrgUnitName;
    fbVarfield_t sslIZipCode;
    fbVarfield_t sslIState;
    fbVarfield_t sslICommonName;
    fbVarfield_t sslILocalityName;
    fbVarfield_t sslIStreetAddress;
    fbVarfield_t sslSCountryName;
    fbVarfield_t sslSOrgName;
    fbVarfield_t sslSOrgUnitName;
    fbVarfield_t sslSZipCode;
    fbVarfield_t sslSState;
    fbVarfield_t sslSCommonName;
    fbVarfield_t sslSLocalityName;
    fbVarfield_t sslSStreetAddress;
    uint8_t     sslVersion;
} yfSSLCertFlow_t;

typedef struct yfSSLFullCert_st {
    fbBasicList_t          cert;
} yfSSLFullCert_t;

typedef struct yfEntropyFlow_st {
    uint8_t     entropy;
    uint8_t     reverseEntropy;
} yfEntropyFlow_t;

typedef struct yfTcpFlow_st {
    uint32_t    tcpSequenceNumber;
    uint8_t     initialTCPFlags;
    uint8_t     unionTCPFlags;
    uint8_t     reverseInitialTCPFlags;
    uint8_t     reverseUnionTCPFlags;
    uint32_t    reverseTcpSequenceNumber;
} yfTcpFlow_t;

typedef struct yfMacFlow_st {
    uint8_t     sourceMacAddress[6];
    uint8_t     destinationMacAddress[6];
} yfMacFlow_t;

typedef struct yfP0fFlow_st {
    fbVarfield_t    osName;
    fbVarfield_t    osVersion;
    fbVarfield_t    osFingerPrint;
    fbVarfield_t    reverseOsName;
    fbVarfield_t    reverseOsVersion;
    fbVarfield_t    reverseOsFingerPrint;
} yfP0fFlow_t;

typedef struct yfFPExportFlow_st {
    fbVarfield_t    firstPacketBanner;
    fbVarfield_t    reverseFirstPacketBanner;
    fbVarfield_t    secondPacketBanner;
} yfFPExportFlow_t;

typedef struct yfPayloadFlow_st {
    fbVarfield_t payload;
    fbVarfield_t reversePayload;
} yfPayloadFlow_t;

typedef struct yfMPTCPFlow_st {
    /** initial data seq no. */
    uint64_t          idsn;
    /** receiver token */
    uint32_t          token;
    /** max segment size */
    uint16_t          mss;
    /* addr id */
    uint8_t           addrid;
    /* hash_flags */
    uint8_t           flags;
} yfMPTCPFlow_t;

typedef struct yfHTTPFlow_st {
    fbBasicList_t server;
    fbBasicList_t userAgent;
    fbBasicList_t get;
    fbBasicList_t connection;
    fbBasicList_t referer;
    fbBasicList_t location;
    fbBasicList_t host;
    fbBasicList_t contentLength;
    fbBasicList_t age;
    fbBasicList_t response;
    fbBasicList_t acceptLang;
    fbBasicList_t accept;
    fbBasicList_t contentType;
    fbBasicList_t version;
    fbBasicList_t cookie;
    fbBasicList_t setcookie;
    fbBasicList_t httpAuthorization;
    fbBasicList_t httpVia;
    fbBasicList_t xforward;
    fbBasicList_t httpRefresh;
    uint8_t       httpBasicListBuf[0];
} yfHTTPFlow_t;

typedef struct yfIRCFlow_st {
    fbBasicList_t ircMsg;
} yfIRCFlow_t;

typedef struct yfPOP3Flow_st {
    fbBasicList_t pop3msg;
} yfPOP3Flow_t;

typedef struct yfTFTPFlow_st {
    fbVarfield_t tftpFilename;
    fbVarfield_t tftpMode;
} yfTFTPFlow_t;

typedef struct yfSLPFlow_st {
    fbBasicList_t slpString;
    uint8_t     slpVersion;
    uint8_t     slpMessageType;
} yfSLPFlow_t;

typedef struct yfFTPFlow_st {
    fbBasicList_t ftpReturn;
    fbBasicList_t ftpUser;
    fbBasicList_t ftpPass;
    fbBasicList_t ftpType;
    fbBasicList_t ftpRespCode;
    uint8_t       ftpBasicListBuf[0];
} yfFTPFlow_t;

typedef struct yfIMAPFlow_st {
    fbBasicList_t imapCapability;
    fbBasicList_t imapLogin;
    fbBasicList_t imapStartTLS;
    fbBasicList_t imapAuthenticate;
    fbBasicList_t imapCommand;
    fbBasicList_t imapExists;
    fbBasicList_t imapRecent;
    uint8_t       imapBasicListBuf[0];
} yfIMAPFlow_t;

typedef struct yfRTSPFlow_st {
    fbBasicList_t rtspURL;
    fbBasicList_t rtspVersion;
    fbBasicList_t rtspReturnCode;
    fbBasicList_t rtspContentLength;
    fbBasicList_t rtspCommand;
    fbBasicList_t rtspContentType;
    fbBasicList_t rtspTransport;
    fbBasicList_t rtspCSeq;
    fbBasicList_t rtspLocation;
    fbBasicList_t rtspPacketsReceived;
    fbBasicList_t rtspUserAgent;
    fbBasicList_t rtspJitter;
    uint8_t       rtspBasicListBuf[0];
} yfRTSPFlow_t;

typedef struct yfSIPFlow_st {
    fbBasicList_t sipInvite;
    fbBasicList_t sipCommand;
    fbBasicList_t sipVia;
    fbBasicList_t sipMaxForwards;
    fbBasicList_t sipAddress;
    fbBasicList_t sipContentLength;
    fbBasicList_t sipUserAgent;
    uint8_t       sipBasicListBuf[0];
} yfSIPFlow_t;

typedef struct yfSMTPFlow_st {
    fbBasicList_t smtpHello;
    fbBasicList_t smtpFrom;
    fbBasicList_t smtpTo;
    fbBasicList_t smtpContentType;
    fbBasicList_t smtpSubject;
    fbBasicList_t smtpFilename;
    fbBasicList_t smtpContentDisposition;
    fbBasicList_t smtpResponse;
    fbBasicList_t smtpEnhanced;
    fbBasicList_t smtpSize;
    fbBasicList_t smtpDate;
    uint8_t       smtpBasicListBuf[0];
} yfSMTPFlow_t;

typedef struct yfSSHFlow_st {
    fbBasicList_t sshVersion;
    uint8_t       sshBasicListBuf[0];
} yfSSHFlow_t;

typedef struct yfNNTPFlow_st {
    fbBasicList_t nntpResponse;
    fbBasicList_t nntpCommand;
} yfNNTPFlow_t;


typedef struct yfDNSFlow_st {
    fbSubTemplateList_t   dnsQRList;
} yfDNSFlow_t;

typedef struct yfDNSQRFlow_st {
    fbSubTemplateList_t dnsRRList;
    fbVarfield_t dnsQName;
    uint32_t dnsTTL;
    uint16_t dnsQRType;
    uint8_t dnsQueryResponse;
    uint8_t dnsAuthoritative;
    uint8_t dnsNXDomain;
    uint8_t dnsRRSection;
    uint16_t dnsID;
    uint8_t padding[4];
} yfDNSQRFlow_t;

typedef struct yfDNSAFlow_st {
    uint32_t ip;
} yfDNSAFlow_t;

typedef struct yfDNSAAAAFlow_st {
    uint8_t  ip[16];
} yfDNSAAAAFlow_t;

typedef struct yfDNSCNameFlow_st {
    fbVarfield_t cname;
} yfDNSCNameFlow_t;

typedef struct yfDNSMXFlow_st {
    fbVarfield_t exchange;
    uint16_t     preference;
    uint8_t      padding[6];
} yfDNSMXFlow_t;

typedef struct yfDNSNSFlow_st {
    fbVarfield_t nsdname;
} yfDNSNSFlow_t;

typedef struct yfDNSPTRFlow_st {
    fbVarfield_t ptrdname;
} yfDNSPTRFlow_t;

typedef struct yfDNSTXTFlow_st {
    fbVarfield_t txt_data;
} yfDNSTXTFlow_t;

typedef struct yfDNSSOAFlow_st {
    fbVarfield_t mname;
    fbVarfield_t rname;
    uint32_t     serial;
    uint32_t     refresh;
    uint32_t     retry;
    uint32_t     expire;
    uint32_t     minimum;
    uint8_t      padding[4];
} yfDNSSOAFlow_t;

typedef struct yfDNSSRVFlow_st {
    fbVarfield_t dnsTarget;
    uint16_t     dnsPriority;
    uint16_t     dnsWeight;
    uint16_t     dnsPort;
    uint8_t      padding[2];
} yfDNSSRVFlow_t;

typedef struct yfDNSRRSigFlow_st {
    fbVarfield_t dnsSigner;
    fbVarfield_t dnsSignature;
    uint32_t     dnsSigInception;
    uint32_t     dnsSigExp;
    uint32_t     dnsTTL;
    uint16_t     dnsTypeCovered;
    uint16_t     dnsKeyTag;
    uint8_t      dnsAlgorithm;
    uint8_t      dnsLabels;
    uint8_t      padding[6];
} yfDNSRRSigFlow_t;

typedef struct yfDNSDSFlow_st {
    fbVarfield_t dnsDigest;
    uint16_t     dnsKeyTag;
    uint8_t      dnsAlgorithm;
    uint8_t      dnsDigestType;
    uint8_t      padding[4];
} yfDNSDSFlow_t;

typedef struct yfDNSKeyFlow_st {
    fbVarfield_t dnsPublicKey;
    uint16_t     dnsFlags;
    uint8_t      protocol;
    uint8_t      dnsAlgorithm;
    uint8_t      padding[4];
} yfDNSKeyFlow_t;

typedef struct yfDNSNSECFlow_st {
    fbVarfield_t dnsHashData;
} yfDNSNSECFlow_t;

typedef struct yfDNSNSEC3Flow_st {
    fbVarfield_t dnsSalt;
    fbVarfield_t dnsNextDomainName;
    uint16_t     iterations;
    uint8_t      dnsAlgorithm;
    uint8_t      padding[5];
} yfDNSNSEC3Flow_t;

typedef struct yfMySQLFlow_st {
    fbSubTemplateList_t mysqlList;
    fbVarfield_t        mysqlUsername;
} yfMySQLFlow_t;

typedef struct yfMySQLTxtFlow_st {
    fbVarfield_t  mysqlCommandText;
    uint8_t       mysqlCommandCode;
    uint8_t       padding[7];
} yfMySQLTxtFlow_t;

typedef struct yfDHCP_FP_Flow_st {
    fbVarfield_t dhcpFP;
    fbVarfield_t dhcpVC;
    fbVarfield_t reverseDhcpFP;
    fbVarfield_t reverseDhcpVC;
} yfDHCP_FP_Flow_t;

typedef struct yfDHCP_OP_Flow_st {
    fbBasicList_t options;
    fbVarfield_t dhcpVC;
    fbBasicList_t revOptions;
    fbVarfield_t reverseDhcpVC;
} yfDHCP_OP_Flow_t;

typedef struct yfRTPFlow_st {
    uint8_t rtpPayloadType;
    uint8_t reverseRtpPayloadType;
} yfRTPFlow_t;

typedef struct yfDNP3Flow_st {
    fbSubTemplateList_t dnp_list;
} yfDNP3Flow_t;

typedef struct yfDNP3Rec_st {
    uint16_t src_address;
    uint16_t dst_address;
    uint8_t  function;
    uint8_t  padding[3];
    fbVarfield_t object;
} yfDNP3Rec_t;

typedef struct yfModbusFlow_st {
    fbBasicList_t mbmsg;
} yfModbusFlow_t;

typedef struct yfEnIPFlow_st {
    fbBasicList_t enipmsg;
} yfEnIPFlow_t;

typedef struct yfFlowStatsRecord_st {
    uint64_t dataByteCount;
    uint64_t averageInterarrivalTime;
    uint64_t standardDeviationInterarrivalTime;
    uint32_t tcpUrgTotalCount;
    uint32_t smallPacketCount;
    uint32_t nonEmptyPacketCount;
    uint32_t largePacketCount;
    uint16_t firstNonEmptyPacketSize;
    uint16_t maxPacketSize;
    uint16_t standardDeviationPayloadLength;
    uint8_t  firstEightNonEmptyPacketDirections;
    uint8_t  padding[1];
    /* reverse Fields */
    uint64_t reverseDataByteCount;
    uint64_t reverseAverageInterarrivalTime;
    uint64_t reverseStandardDeviationInterarrivalTime;
    uint32_t reverseTcpUrgTotalCount;
    uint32_t reverseSmallPacketCount;
    uint32_t reverseNonEmptyPacketCount;
    uint32_t reverseLargePacketCount;
    uint16_t reverseFirstNonEmptyPacketSize;
    uint16_t reverseMaxPacketSize;
    uint16_t reverseStandardDeviationPayloadLength;
    uint8_t  padding2[2];
} yfFlowStatsRecord_t;


typedef struct mdDnsRR_st {
    uint64_t      start;
    uint8_t       sip6[16];
    uint8_t       dip6[16];
    uint32_t      sip;
    uint32_t      dip;
    uint32_t      ttl;
    uint32_t      obid;
    uint32_t      hash;
    uint16_t      type;
    uint16_t      sp;
    uint16_t      dp;
    uint16_t      vlan;
    uint16_t      id;
    uint8_t       proto;
    uint8_t       qr;
    uint8_t       auth;
    uint8_t       nx;
    uint8_t       rr;
    uint8_t       padding[5];
    fbVarfield_t  rrname;
    fbVarfield_t  rrdata;
} mdDnsRR_t;

typedef struct md_dedup_st {
    uint64_t      fseen;
    uint64_t      lseen;
    /* with hash this (stime) makes unique key */
    uint64_t      stime;
    uint64_t      count;
    uint8_t       sip6[16];
    uint32_t      sip;
    uint32_t      hash;
    fbVarfield_t  mapname;
    fbVarfield_t  data;
    /* ssl only fields */
    fbVarfield_t  serial1;
    fbVarfield_t  issuer1;
    fbVarfield_t  serial2;
    fbVarfield_t  issuer2;
} md_dedup_t;

typedef struct md_dedup_old_st {
    uint64_t      fseen;
    uint64_t      lseen;
    uint64_t      count;
    uint8_t       sip6[16];
    uint32_t      sip;
    uint32_t      hash;
    fbVarfield_t  data;
    /* ssl only fields */
    fbVarfield_t  serial1;
    fbVarfield_t  issuer1;
    fbVarfield_t  serial2;
    fbVarfield_t  issuer2;
} md_dedup_old_t;


typedef struct mdFullFlow_st {
    mdRecord_t          *rec;
    yfEntropyFlow_t     *entropy;
    yfMacFlow_t         *mac;
    yfPayloadFlow_t     *pay;
    yfP0fFlow_t         *p0f;
    yfFlowStatsRecord_t *stats;
    yfFPExportFlow_t    *fp;
    fbSubTemplateMultiListEntry_t *dhcpfp;
    //    yfDHCP_FP_Flow_t    *dhcpfp;
    yfMPTCPFlow_t       *mptcp;
    void                *app;
    fbSubTemplateMultiListEntry_t  *cert;
    yfSSLFullCert_t     *fullcert;
    yfNewSSLCertFlow_t  **sslcerts;
    char                *collector_name;
    uint16_t            app_tid;
    uint16_t            app_elements;
    uint16_t            tid;
    uint8_t             collector_id;
} mdFullFlow_t;

typedef gboolean (*mdPrint_fn)(mdFullFlow_t *, mdBuf_t *, size_t *, char *);

typedef struct mdFieldList_st mdFieldList_t;

struct mdFieldList_st {
    mdFieldList_t           *next;
    mdPrint_fn              print_fn;
    mdAcceptFilterField_t   field;
    GString                 *decorator;
};

#endif
