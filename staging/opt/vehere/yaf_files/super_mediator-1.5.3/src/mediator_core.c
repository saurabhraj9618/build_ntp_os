/**
 * @file mediator_core.c
 *
 * Yaf mediator for filtering, DNS deduplication, and other mediator-like
 * things
 *
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2012-2017 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 * Authors: Emily Sarneso, Matt Coates <netsa-help@cert.org>
 * ------------------------------------------------------------------------
 * @OPENSOURCE_HEADER_START@
 * Use of this (and related) source code is subject to the terms
 * of the following licenses:
 *
 * GNU Public License (GPL) Rights pursuant to Version 2, June 1991
 * Government Purpose License Rights (GPLR) pursuant to DFARS 252.227.7013
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
 * -----------------------------------------------------------
 */

#include <mediator/mediator_core.h>
#include <mediator/mediator_filter.h>
#include <mediator/mediator_CERT_IE.h>
#include <mediator/mediator_util.h>
#include "mediator_stat.h"
#include "mediator_dns.h"
#include "mediator_dedup.h"
#include "mediator_print.h"
#include "mediator_ssl.h"

static fbTemplate_t *sm_sub_ssl_tmpl = NULL;

static fbInfoElementSpec_t md_main_template[] = {
    { "flowStartMilliseconds",               0, 0 },
    { "flowEndMilliseconds",                 0, 0 },
    { "octetTotalCount",                     0, YTF_TOTAL },
    { "reverseOctetTotalCount",              0, YTF_TOTAL | YTF_REV },
    { "octetDeltaCount",                     0, YTF_DELTA },
    { "reverseOctetDeltaCount",              0, YTF_REV | YTF_DELTA },
    { "packetTotalCount",                    0, YTF_TOTAL },
    { "reversePacketTotalCount",             0, YTF_TOTAL | YTF_REV },
    { "packetDeltaCount",                    0, YTF_DELTA },
    { "reversePacketDeltaCount",             0, YTF_REV | YTF_DELTA },
    { "sourceIPv6Address",                   0, YTF_IP6 },
    { "destinationIPv6Address",              0, YTF_IP6 },
    { "sourceIPv4Address",                   0, YTF_IP4 },
    { "destinationIPv4Address",              0, YTF_IP4 },
    { "sourceTransportPort",                 0, 0 },
    { "destinationTransportPort",            0, 0 },
    { "flowAttributes",                      0, 0 },
    { "reverseFlowAttributes",               0, YTF_REV },
    { "protocolIdentifier",                  0, 0 },
    { "flowEndReason",                       0, 0 },
    { "numAppLabel",                        0, 0 },
    { "reverseFlowDeltaMilliseconds",        0, YTF_REV },
    { "tcpSequenceNumber",                   0, YTF_TCP },
    { "reverseTcpSequenceNumber",            0, YTF_TCP | YTF_REV },
    { "initialTCPFlags",                     0, YTF_TCP },
    { "unionTCPFlags",                       0, YTF_TCP },
    { "reverseInitialTCPFlags",              0, YTF_TCP | YTF_REV },
    { "reverseUnionTCPFlags",                0, YTF_TCP | YTF_REV },
    /* MAC-specific information */
    { "vlanId",                              0, 0 },
    { "reverseVlanId",                       0, YTF_REV },
    { "ingressInterface",                    0, YTF_DAGIF },
    { "egressInterface",                     0, YTF_DAGIF },
    { "ipClassOfService",                    0, 0 },
    { "reverseIpClassOfService",             0, YTF_REV },
    { "mplsTopLabelStackSection",            3, YTF_MPLS },
    { "mplsLabelStackSection2",              3, YTF_MPLS },
    { "mplsLabelStackSection3",              3, YTF_MPLS },
    /* add an obs id */
    { "paddingOctets",                       1, YTF_PAD },
    { "observationDomainId",                 0, 0 },
    { "flowKeyHash",                      0, 0 },
    { "nDPIL7Protocol",                      0, 0 },
    { "nDPIL7SubProtocol",                   0, 0 },
    { "subTemplateMultiList",                0, YTF_LIST },
    FB_IESPEC_NULL
};


static fbInfoElementSpec_t yaf_stats_option_spec[] = {
    { "systemInitTimeMilliseconds",         0, 0 },
    { "exportedFlowRecordTotalCount",       0, 0 },
    { "packetTotalCount",                   0, 0 },
    { "droppedPacketTotalCount",            0, 0 },
    { "ignoredPacketTotalCount",            0, 0 },
    { "notSentPacketTotalCount",            0, 0 },
    { "expiredFragmentCount",               0, 0 },
    { "assembledFragmentCount",             0, 0 },
    { "flowTableFlushEventCount",           0, 0 },
    { "flowTablePeakCount",                 0, 0 },
    { "exporterIPv4Address",                0, 0 },
    { "exportingProcessId",                 0, 0 },
    { "meanFlowRate",                       0, 0 },
    { "meanPacketRate",                     0, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_entropy_spec[] = {
    { "payloadEntropy",                     0, 0 },
    { "reversePayloadEntropy",              0, YTF_REV },
    FB_IESPEC_NULL
};


static fbInfoElementSpec_t yaf_tcp_spec[] = {
    /* TCP-specific information */
    { "tcpSequenceNumber",                  0, 0 },
    { "initialTCPFlags",                    0, 0 },
    { "unionTCPFlags",                      0, 0 },
    { "reverseInitialTCPFlags",             0, YTF_REV },
    { "reverseUnionTCPFlags",               0, YTF_REV },
    { "reverseTcpSequenceNumber",           0, YTF_REV },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_mptcp_spec[] = {
    { "mptcpInitialDataSequenceNumber",      0, 0 },
    { "mptcpReceiverToken",                 0, 0 },
    { "mptcpMaximumSegmentSize",            0, 0 },
    { "mptcpAddressID",                     0, 0 },
    { "mptcpFlags",                         0, 0 },
    FB_IESPEC_NULL
};

/* MAC-specific information */
static fbInfoElementSpec_t yaf_mac_spec[] = {
    { "sourceMacAddress",                   0, 0 },
    { "destinationMacAddress",              0, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_p0f_spec[] = {
    { "osName",                             0, 0 },
    { "osVersion",                          0, 0 },
    { "osFingerPrint",                      0, 0 },
    { "reverseOsName",                      0, YTF_REV },
    { "reverseOsVersion",                   0, YTF_REV },
    { "reverseOsFingerPrint",               0, YTF_REV },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_fpexport_spec[] = {
    { "firstPacketBanner",                  0, 0 },
    { "secondPacketBanner",                 0, 0 },
    { "reverseFirstPacketBanner",           0, YTF_REV },
    FB_IESPEC_NULL
};

/* Variable-length payload fields */
static fbInfoElementSpec_t yaf_payload_spec[] = {
    { "payload",                            0, 0 },
    { "reversePayload",                     0, YTF_REV },
    FB_IESPEC_NULL
};


static fbInfoElementSpec_t yaf_singleBL_spec[] = {
    {"basicList",       0, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_tftp_spec[] = {
    {"tftpFilename",          0, 0 },
    {"tftpMode",              0, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_flow_stats_spec[] = {
    { "dataByteCount",                      0, 0 },
    { "averageInterarrivalTime",            0, 0 },
    { "standardDeviationInterarrivalTime",  0, 0 },
    { "tcpUrgTotalCount",                   4, 0 },
    { "smallPacketCount",                   0, 0 },
    { "nonEmptyPacketCount",                0, 0 },
    { "largePacketCount",                   0, 0 },
    { "firstNonEmptyPacketSize",            0, 0 },
    { "maxPacketSize",                      0, 0 },
    { "standardDeviationPayloadLength",     0, 0 },
    { "firstEightNonEmptyPacketDirections", 0, 0 },
    { "paddingOctets",                      1, 1 },
    { "reverseDataByteCount",               0, YTF_REV },
    { "reverseAverageInterarrivalTime",     0, YTF_REV },
    { "reverseStandardDeviationInterarrivalTime", 0, YTF_REV },
    { "reverseTcpUrgTotalCount",            4, YTF_REV },
    { "reverseSmallPacketCount",            0, YTF_REV },
    { "reverseNonEmptyPacketCount",         0, YTF_REV },
    { "reverseLargePacketCount",            0, YTF_REV },
    { "reverseFirstNonEmptyPacketSize",     0, YTF_REV },
    { "reverseMaxPacketSize",               0, YTF_REV },
    { "reverseStandardDeviationPayloadLength", 0, YTF_REV },
    { "paddingOctets",                      2, 1 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_slp_spec[] = {
    {"basicList",             0, 0 },
    {"slpVersion",            0, 0 },
    {"slpMessageType",        0, 0 },
    {"paddingOctets",         6, 1 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_http_spec[] = {
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    FB_IESPEC_NULL
};
static fbInfoElementSpec_t yaf_ftp_spec[] = {
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_imap_spec[] = {
    {"basicList",        0, 0 },
    {"basicList",        0, 0 },
    {"basicList",        0, 0 },
    {"basicList",        0, 0 },
    {"basicList",        0, 0 },
    {"basicList",        0, 0 },
    {"basicList",        0, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_rtsp_spec[] = {
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    FB_IESPEC_NULL
};


static fbInfoElementSpec_t yaf_sip_spec[] = {
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_smtp_spec[] = {
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_nntp_spec[] = {
    {"basicList",       0, 0 },
    {"basicList",       0, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_dns_spec[] = {
    {"subTemplateList",    0, 0 },
    FB_IESPEC_NULL
};
static fbInfoElementSpec_t yaf_dnsQR_spec[] = {
    {"subTemplateList",     0, 0 }, /*based on type of RR */
    {"dnsQName",            0, 0 }, /*name - varfield*/
    {"dnsTTL",              0, 0 },
    {"dnsQRType",           0, 0 },  /*Type - uint8*/
    {"dnsQueryResponse",    0, 0 },  /*Q or R - uint8*/
    {"dnsAuthoritative",    0, 0 }, /* authoritative response (1)*/
    {"dnsNXDomain",         0, 0 }, /* nxdomain (1) */
    {"dnsRRSection",        0, 0 }, /*0, 1, 2 (ans, auth, add'l) */
    {"dnsID",               0, 0 },
    {"paddingOctets",       4, 1 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_dnsA_spec[] = {
    {"sourceIPv4Address",         0, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_dnsAAAA_spec[] = {
    {"sourceIPv6Address",         0, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_dnsCNAME_spec[] = {
    {"dnsCName",                  0, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_dnsMX_spec[] = {
    {"dnsMXExchange",             0, 0 },
    {"dnsMXPreference",           0, 0 },
    {"paddingOctets",             6, 1 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_dnsNS_spec[] = {
    {"dnsNSDName",                0, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_dnsPTR_spec[] = {
    {"dnsPTRDName",               0, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_dnsTXT_spec[] = {
    {"dnsTXTData",                0, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_dnsSOA_spec[] = {
    {"dnsSOAMName",               0, 0 },
    {"dnsSOARName",               0, 0 },
    {"dnsSOASerial",              0, 0 },
    {"dnsSOARefresh",             0, 0 },
    {"dnsSOARetry",               0, 0 },
    {"dnsSOAExpire",              0, 0 },
    {"dnsSOAMinimum",             0, 0 },
    {"paddingOctets",             4, 1 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_dnsSRV_spec[] = {
    {"dnsSRVTarget",              0, 0 },
    {"dnsSRVPriority",            0, 0 },
    {"dnsSRVWeight",              0, 0 },
    {"dnsSRVPort",                0, 0 },
    {"paddingOctets",             2, 1 },
    FB_IESPEC_NULL
};


static fbInfoElementSpec_t yaf_dnsDS_spec[] = {
    {"dnsDigest",                 0, 0 },
    {"dnsKeyTag",                 0, 0 },
    {"dnsAlgorithm",              0, 0 },
    {"dnsDigestType",             0, 0 },
    {"paddingOctets",             4, 1 },
    FB_IESPEC_NULL
};


static fbInfoElementSpec_t yaf_dnsSig_spec[] = {
    {"dnsSigner",                 0, 0 },
    {"dnsSignature",              0, 0 },
    {"dnsSignatureInception",     0, 0 },
    {"dnsSignatureExpiration",    0, 0 },
    {"dnsTTL",                    0, 0 },
    {"dnsKeyTag",                 0, 0 },
    {"dnsTypeCovered",            0, 0 },
    {"dnsAlgorithm",              0, 0 },
    {"dnsLabels",                 0, 0 },
    {"paddingOctets",             6, 1 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_dnsNSEC_spec[] = {
    {"dnsHashData",               0, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_dnsKey_spec[] = {
    {"dnsPublicKey",              0, 0 },
    {"dnsFlags",                  0, 0 },
    {"protocolIdentifier",        0, 0 },
    {"dnsAlgorithm",              0, 0 },
    {"paddingOctets",             4, 1 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_dnsNSEC3_spec[] = {
    {"dnsSalt",                   0, 0 },
    {"dnsHashData",               0, 0 },
    {"dnsIterations",             0, 0 },
    {"dnsAlgorithm",              0, 0 },
    {"paddingOctets",             5, 1 },
    FB_IESPEC_NULL
};


static fbInfoElementSpec_t yaf_ssl_spec[] = {
    {"basicList",                 0, 0 }, /*list of ciphers 32bit */
    {"sslServerCipher",           0, 0 }, /*cipher suite in server hello */
    {"sslClientVersion",          0, 0 },
    {"sslCompressionMethod",      0, 0 }, /*compression method in serv hello*/
    {"paddingOctets",             2, 1 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_newssl_spec[] = {
    {"basicList",                 0, 0 }, /*list of ciphers 32bit */
    {"sslServerCipher",           0, 0 }, /*cipher suite in server hello */
    {"sslClientVersion",          0, 0 },
    {"sslCompressionMethod",      0, 0 }, /*compression method in serv hello*/
    {"sslRecordVersion",          0, 0 },
    {"subTemplateList",           0, 0 }, /* list of certs */
    {"sslServerName",             0, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_new_cert_spec[] = {
    {"subTemplateList",             0, 0 },
    {"subTemplateList",             0, 0 },
    {"subTemplateList",             0, 0 },
    {"sslCertSignature",            0, 0 },
    {"sslCertSerialNumber",         0, 0 },
    {"sslCertValidityNotBefore",    0, 0 },
    {"sslCertValidityNotAfter",     0, 0 },
    {"sslPublicKeyAlgorithm",       0, 0 },
    {"sslPublicKeyLength",          0, 0 },
    {"sslCertVersion",              0, 0 },
    {"paddingOctets",               5, 1 },
    {"sslCertificateHash",          0, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_subssl_spec[] = {
    {"sslObjectValue",              0, 0 },
    {"sslObjectType",               0, 0 },
    {"paddingOctets",               7, 1 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_cert_spec[] = {
    {"sslCertSignature",            0, 0 },
    {"sslCertIssuerCountryName",    0, 0 },
    {"sslCertIssuerOrgName",        0, 0 },
    {"sslCertIssuerOrgUnitName",    0, 0 },
    {"sslCertIssuerZipCode",        0, 0 },
    {"sslCertIssuerState",          0, 0 },
    {"sslCertIssuerCommonName",     0, 0 },
    {"sslCertIssuerLocalityName",   0, 0 },
    {"sslCertIssuerStreetAddress",  0, 0 },
    {"sslCertSubCountryName",       0, 0 },
    {"sslCertSubOrgName",           0, 0 },
    {"sslCertSubOrgUnitName",       0, 0 },
    {"sslCertSubZipCode",           0, 0 },
    {"sslCertSubState",             0, 0 },
    {"sslCertSubCommonName",        0, 0 },
    {"sslCertSubLocalityName",      0, 0 },
    {"sslCertSubStreetAddress",     0, 0 },
    {"sslCertVersion",              0, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_mysql_spec[] = {
    {"subTemplateList",            0, 0 },
    {"mysqlUsername",              0, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_mysql_txt_spec[] = {
    {"mysqlCommandText",           0, 0 },
    {"mysqlCommandCode",           0, 0 },
    {"paddingOctets",              7, 1 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_dhcp_fp_spec[] = {
    {"dhcpFingerPrint",             0, 0 },
    {"dhcpVendorCode",              0, 0 },
    {"reverseDhcpFingerPrint",      0, YTF_REV },
    {"reverseDhcpVendorCode",       0, YTF_REV },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_dhcp_options_spec[] = {
    {"basicList",                   0, 0 },
    {"dhcpVendorCode",              0, 0 },
    {"basicList",                   0, YTF_REV},
    {"reverseDhcpVendorCode",       0, YTF_REV },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_rtp_spec[] = {
    {"rtpPayloadType",           0, 0 },
    {"reverseRtpPayloadType",    0, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_dnp_rec_spec[] = {
    {"dnp3SourceAddress",        0, 0 },
    {"dnp3DestinationAddress",   0, 0 },
    {"dnp3Function",             0, 0 },
    {"paddingOctets",            3, 1 },
    {"dnp3ObjectData",           0, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_dnp_spec[] = {
    {"subTemplateList",     0, 0 },
    FB_IESPEC_NULL
};


static fbInfoElementSpec_t md_dns_spec[] = {
    /* Millisecond first seen and last seen (epoch) (native time) */
    { "flowStartMilliseconds",              0, 0 },
    { "flowEndMilliseconds",                0, MD_LAST_SEEN },
    /* A-record IP */
    { "sourceIPv4Address",                  0, MD_DNS_AREC },
    /** Max TTL */
    { "dnsTTL",                             0, MD_LAST_SEEN },
    /* rrType */
    { "dnsQRType",                          0, 0 },
    /* how many times we saw it */
    { "dnsHitCount",                        0, MD_LAST_SEEN },
    { "paddingOctets",                      4, 1 },
    /* rrData */
    { "dnsQName",                           0, 0 },
    { "dnsRName",                           0, MD_DNS_OREC },
    { "observationDomainName",              0, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t md_dns_rr_spec[] = {
    { "flowStartMilliseconds",              0, 0 },
    { "sourceIPv6Address",                  0, YTF_IP6 | MD_DNSRR_FULL },
    { "destinationIPv6Address",             0, YTF_IP6 | MD_DNSRR_FULL },
    { "sourceIPv4Address",                  0, YTF_IP4 | MD_DNSRR_FULL },
    { "destinationIPv4Address",             0, YTF_IP4 | MD_DNSRR_FULL },
    { "dnsTTL",                             0, 0 },
    { "observationDomainId",                0, 0 },
    { "flowKeyHash",                     0, 0 },
    { "dnsQRType",                          0, 0 },
    { "sourceTransportPort",                0, MD_DNSRR_FULL },
    { "destinationTransportPort",           0, MD_DNSRR_FULL },
    { "vlanId",                             0, MD_DNSRR_FULL },
    { "dnsID",                              0, 0 },
    { "protocolIdentifier",                 0, MD_DNSRR_FULL },
    { "dnsQueryResponse",                   0, 0 },  /*Q or R - uint8*/
    { "dnsAuthoritative",                   0, 0 }, /* auth response (1)*/
    { "dnsNXDomain",                        0, 0 }, /* nxdomain (1) */
    { "dnsRRSection",                       0, 0 }, /*(qry,ans,auth,add'l) */
    { "paddingOctets",                      5, 1 },
    { "dnsQName",                           0, 0 },
    { "dnsRName",                           0, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t md_dedup_spec[] = {
    /* Millisecond first seen and last seen (epoch) (native time) */
    { "monitoringIntervalStartMilliSeconds", 0, 0 },
    { "monitoringIntervalEndMilliSeconds",   0, 0 },
    { "flowStartMilliseconds",              0, 0 },
    { "observedDataTotalCount",             0, 0 },
    { "sourceIPv6Address",                  0, 0 },
    { "sourceIPv4Address",                  0, 0 },
    { "flowKeyHash",                     0, 0 },
    { "observationDomainName",              0, 0 },
    { "observedData",                       0, 0 },
    { "sslCertSerialNumber",                0, MD_DEDUP_SSL },
    { "sslCertIssuerCommonName",            0, MD_DEDUP_SSL },
    { "sslCertSerialNumber",                0, MD_DEDUP_SSL },
    { "sslCertIssuerCommonName",            0, MD_DEDUP_SSL },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t md_ssl_spec[] = {
    { "flowStartMilliseconds",              0, 0 },
    { "flowEndMilliseconds",                0, 0 },
    { "observedDataTotalCount",             0, 0 },
    { "sslCertSerialNumber",                0, 0 },
    { "sslCertIssuerCommonName",            0, 0 },
    { "observationDomainName",              0, 0 },
    FB_IESPEC_NULL
};



/**
 * mdInfoModel
 *
 * create an appropriate info model  --- see mediator_CERT_IE.h
 * ================================
 * alloc the default (with IANA elements pre-populated) via fbInfoModelAlloc
 * add in the CERT/NetSA added elements using
 * fbInfoModelAddElement/fbInfoModelAddElementArray
 * need to add the FB_IE_INIT("numAppLabel", 6871, 33, 2, FB_IE_F_ENDIAN)
 * information element to the model that creates a complete info model
 * for use through the rest of the app
 * (fbInfoModel_t)
 *
 */

fbInfoModel_t *mdInfoModel()
{

    static fbInfoModel_t *md_info_model = NULL;

    if (!md_info_model) {

        md_info_model = fbInfoModelAlloc();

        fbInfoModelAddElementArray(md_info_model, yaf_info_elements);

        if (user_elements) {
            fbInfoModelAddElementArray(md_info_model, user_elements);
        }
    }

    return md_info_model;
}

static void templateFree(
    void *ctx)
{
    g_slice_free(mdTmplContext_t, ctx);
}


static void mdTemplateCallback(
    fbSession_t          *session,
    uint16_t             tid,
    fbTemplate_t         *tmpl,
    void                 **ctx,
    fbTemplateCtxFree_fn *fn)
{
    /*uint16_t ntid = tid & 0xFF0F;*/
    fbInfoModel_t *sm_model = mdInfoModel();
    fbInfoElement_t *ie = NULL;
    GError *err = NULL;
    uint16_t ntid = 0;
    mdTmplContext_t *myctx = NULL;

    /* We do this because the SSL Templates/Records have changed
       between YAF releases and we don't want any read errors due
       to typecasting the STMLs and STLs.  This is the proper way
       to decode the data in IPFIX. */
    if (tid == YAF_NEW_SSL_FLOW_TID) {
        fbSessionAddTemplatePair(session, tid, SM_INTSSL_FLOW_TID);
    } else if (tid == YAF_NEW_SSL_CERT_TID) {
        fbSessionAddTemplatePair(session, tid, SM_INTCERT_FLOW_TID);
    } else if (tid == MD_DEDUP_FULL) {
        /* standard ssl dedup rec */
        /* md_dedup_rec */
        fbSessionAddTemplatePair(session, tid, tid);
    } else if (tid == MD_SSL_TID) {
        /* standard cert dedup rec */
        /* md_ssl_spec */
        fbSessionAddTemplatePair(session, tid, tid);
    } else if (fbTemplateContainsElement(tmpl,
                                         fbInfoModelGetElementByName(sm_model,
                                         "observedDataTotalCount")))
    {
        /* this is a dedup record */
        ntid = fbSessionAddTemplate(session, TRUE, tid, tmpl, &err);
        if (ntid == 0) {
            g_warning("Unable to add incoming template %02x to session %s",
                      tid, err->message);
        }

        myctx = g_slice_new0(mdTmplContext_t);
        myctx->tid = ntid;
        myctx->num_elem = fbTemplateCountElements(tmpl);
        /* Get the last element in the template */
        ie = fbTemplateGetIndexedIE(tmpl, (myctx->num_elem)-1);
        /* get the id of the IE */
        myctx->ie = ie->num;
        *ctx = myctx;
        *fn = templateFree;
        /* need to set this so internal template matches up with struct */
    } else {
        fbSessionAddTemplatePair(session, tid, tid);
    }

    return;
}


#ifdef HAVE_SPREAD
static fbTemplate_t *mdAddSpreadTmpl(
    fbSession_t       *session,
    fbInfoElementSpec_t *spec,
    uint16_t           tid,
    gboolean           rev,
    GError            **err)
{

    fbInfoModel_t *model = mdInfoModel();
    fbTemplate_t  *tmpl = NULL;
    uint16_t      rtid = rev ? tid | YTF_REV : tid;

    tmpl = fbTemplateAlloc(model);

    if (!fbTemplateAppendSpecArray(tmpl, spec, 0xffffffff, err)) {
        return NULL;
    }

    if (!(fbSessionAddTemplate(session, TRUE, rtid, tmpl, err))) {
        return NULL;
    }

    if (!fbSessionAddTemplatesMulticast(session, md_config.out_spread.groups,
                                        FALSE, rtid, tmpl, err))
    {
        return NULL;
    }

    if (rev) {
        tmpl = fbTemplateAlloc(model);

        if (!fbTemplateAppendSpecArray(tmpl, spec, 0, err)) {
            return NULL;
        }

        if (!fbSessionAddTemplatesMulticast(session,
                                            md_config.out_spread.groups,
                                            FALSE, tid, tmpl, err))
        {
            return NULL;
        }
    }

    return tmpl;
}

/**
 * mdInitSpreadExporterSession
 *
 *
 *
 **/
fbSession_t *mdInitSpreadExporterSession(
    fbSession_t      *session,
    gboolean         dedup,
    GError           **err)
{
    fbTemplate_t *tmpl = NULL;

    if (!mdAddSpreadTmpl(session, md_main_template, YAF_SILK_FLOW_TID, FALSE,
                         err))
    {
        return NULL;
    }

    if (dedup) {
        if (!mdAddSpreadTmpl(session, md_dns_spec, MD_DNS_FULL, FALSE, err)) {
            return NULL;
        }
    }

    /* dns rr only template */
    if (!mdAddSpreadTmpl(session, md_dns_rr_spec, MD_DNSRR, FALSE, err)) {
        return NULL;
    }

    /* dedup template */
    if (!mdAddSpreadTmpl(session, md_dedup_spec, MD_DEDUP_FULL, FALSE, err)) {
        return NULL;
    }

    /* ssl dedup template */
    if (!mdAddSpreadTmpl(session, md_ssl_spec, MD_SSL_TID, FALSE, err)) {
        return NULL;
    }

    /* add export template */
    tmpl = fbTemplateAlloc(mdInfoModel());
    if (!fbTemplateAppendSpecArray(tmpl, md_dns_rr_spec, 0, err)) {
        return NULL;
    }
    if (!fbSessionAddTemplatesMulticast(session, md_config.out_spread.groups,
                                        FALSE, MD_DNSRR, tmpl, err))
    {
        return NULL;
    }

    /* Options Template */
    tmpl = mdAddSpreadTmpl(session, yaf_stats_option_spec,
                           YAF_OPTIONS_FLOW_TID, FALSE, err);
    if (!tmpl) {
        return NULL;
    }
    fbTemplateSetOptionsScope(tmpl, 2);

    /* flow stats template */
    if (!mdAddSpreadTmpl(session, yaf_flow_stats_spec, YAF_STATS_FLOW_TID,
                         TRUE, err))
    {
        return NULL;
    }

    /* Entropy Template */
    if (!mdAddSpreadTmpl(session, yaf_entropy_spec, YAF_ENTROPY_FLOW_TID,
                         TRUE, err))
    {
        return NULL;
    }

    /* TCP Template */
    if (!mdAddSpreadTmpl(session, yaf_tcp_spec, YAF_TCP_FLOW_TID, TRUE, err)) {
        return NULL;
    }

    /* MPTCP Template */
    if (!mdAddSpreadTmpl(session, yaf_mptcp_spec, YAF_MPTCP_FLOW_TID, FALSE, err)) {
        return NULL;
    }

    /* MAC Template */
    if (!mdAddSpreadTmpl(session, yaf_mac_spec, YAF_MAC_FLOW_TID, FALSE, err)){
        return NULL;
    }


    /* p0f Template */
    if (!mdAddSpreadTmpl(session, yaf_p0f_spec,YAF_P0F_FLOW_TID, TRUE, err)) {
        return NULL;
    }

    /* dhcp Template */
    if (!mdAddSpreadTmpl(session, yaf_dhcp_fp_spec, YAF_DHCP_FLOW_TID,
                         TRUE, err))
    {
        return NULL;
    }

    if (!mdAddSpreadTmpl(session, yaf_dhcp_options_spec, YAF_DHCP_OP_TID,
                         TRUE, err))
    {
        return NULL;
    }

    /* fpExport Template */
    if (!mdAddSpreadTmpl(session, yaf_fpexport_spec,YAF_FPEXPORT_FLOW_TID,
                         TRUE, err))
    {
        return NULL;
    }

    /* Payload Template */
    if (!mdAddSpreadTmpl(session, yaf_payload_spec,YAF_PAYLOAD_FLOW_TID, TRUE,
                         err))
    {
        return NULL;
    }

    /* DPI TEMPLATES - HTTP*/
    if (!mdAddSpreadTmpl(session, yaf_http_spec,YAF_HTTP_FLOW_TID,FALSE, err)){
        return NULL;
    }

    /* IRC Template */
    if (!mdAddSpreadTmpl(session, yaf_singleBL_spec, YAF_IRC_FLOW_TID, FALSE,
                         err))
    {
        return NULL;
    }

    /* SSH Template */
    if (!mdAddSpreadTmpl(session, yaf_singleBL_spec, YAF_SSH_FLOW_TID, FALSE,
                         err))
    {
        return NULL;
    }

    /* POP3 Template */
    if (!mdAddSpreadTmpl(session, yaf_singleBL_spec, YAF_POP3_FLOW_TID, FALSE,
                         err))
    {
        return NULL;
    }

    /* TFTP Template */
    if (!mdAddSpreadTmpl(session, yaf_tftp_spec, YAF_TFTP_FLOW_TID, FALSE,
                         err))
    {
        return NULL;
    }

    /* SLP Template */
    if (!mdAddSpreadTmpl(session, yaf_slp_spec, YAF_SLP_FLOW_TID, FALSE,
                         err))
    {
        return NULL;
    }

    /* FTP Template */
    if (!mdAddSpreadTmpl(session, yaf_ftp_spec, YAF_FTP_FLOW_TID, FALSE, err))
    {
        return NULL;
    }

    /* IMAP Template */
    if (!mdAddSpreadTmpl(session, yaf_imap_spec, YAF_IMAP_FLOW_TID, FALSE,err))
    {
        return NULL;
    }

    /* RTSP Template */
    if (!mdAddSpreadTmpl(session, yaf_rtsp_spec, YAF_RTSP_FLOW_TID, FALSE,
                         err))
    {
        return NULL;
    }

    /* SIP Template */
    if (!mdAddSpreadTmpl(session, yaf_sip_spec, YAF_SIP_FLOW_TID, FALSE, err))
    {
        return NULL;
    }

    /* NNTP Template */
    if (!mdAddSpreadTmpl(session, yaf_nntp_spec, YAF_NNTP_FLOW_TID, FALSE,
                         err))
    {
        return NULL;
    }

    /* SMTP Template */
    if (!mdAddSpreadTmpl(session, yaf_smtp_spec, YAF_SMTP_FLOW_TID, FALSE,
                         err))
    {
        return NULL;
    }

    /* DNS Template */
    if (!mdAddSpreadTmpl(session, yaf_dns_spec, YAF_DNS_FLOW_TID, FALSE,
                         err))
    {
        return NULL;
    }

    /* DNS QR Template */
    if (!mdAddSpreadTmpl(session, yaf_dnsQR_spec, YAF_DNSQR_FLOW_TID, FALSE,
                         err))
    {
        return NULL;
    }

    /* DNS A Template */
    if (!mdAddSpreadTmpl(session, yaf_dnsA_spec, YAF_DNSA_FLOW_TID, FALSE,
                         err))
    {
        return NULL;
    }

    /* DNS AAAA Template */
    if (!mdAddSpreadTmpl(session, yaf_dnsAAAA_spec, YAF_DNSAAAA_FLOW_TID,FALSE,
                         err))
    {
        return NULL;
    }

    /* DNS CNAME Template */
    if (!mdAddSpreadTmpl(session, yaf_dnsCNAME_spec, YAF_DNSCN_FLOW_TID,
                         FALSE, err))
    {
        return NULL;
    }

    /* DNS MX Template */
    if (!mdAddSpreadTmpl(session, yaf_dnsMX_spec, YAF_DNSMX_FLOW_TID, FALSE,
                         err))
    {
        return NULL;
    }

    /* DNS NS Template */
    if (!mdAddSpreadTmpl(session, yaf_dnsNS_spec, YAF_DNSNS_FLOW_TID, FALSE,
                         err))
    {
        return NULL;
    }

    /* DNS PTR Template */
    if (!mdAddSpreadTmpl(session, yaf_dnsPTR_spec, YAF_DNSPTR_FLOW_TID, FALSE,
                         err))
    {
        return NULL;
    }

    /* DNS TXT Template */
    if (!mdAddSpreadTmpl(session, yaf_dnsTXT_spec, YAF_DNSTXT_FLOW_TID, FALSE,
                         err))
    {
        return NULL;
    }

    /* DNS SOA Template */
    if (!mdAddSpreadTmpl(session, yaf_dnsSOA_spec, YAF_DNSSOA_FLOW_TID, FALSE,
                         err))
    {
        return NULL;
    }

    /* DNS SRV Template */
    if (!mdAddSpreadTmpl(session, yaf_dnsSRV_spec, YAF_DNSSRV_FLOW_TID, FALSE,
                         err))
    {
        return NULL;
    }

    /* DNS DS Template */
    if (!mdAddSpreadTmpl(session, yaf_dnsDS_spec, YAF_DNSDS_FLOW_TID, FALSE,
                         err))
    {
        return NULL;
    }

    /* DNS RRSig Template */
    if (!mdAddSpreadTmpl(session, yaf_dnsSig_spec, YAF_DNSRRSIG_FLOW_TID,FALSE,
                         err))
    {
        return NULL;
    }

    /* DNS NSEC Template */
    if (!mdAddSpreadTmpl(session, yaf_dnsNSEC_spec, YAF_DNSNSEC_FLOW_TID,FALSE,
                         err))
    {
        return NULL;
    }

    /* DNS Key Template */
    if (!mdAddSpreadTmpl(session, yaf_dnsKey_spec, YAF_DNSKEY_FLOW_TID, FALSE,
                         err))
    {
        return NULL;
    }

    /* DNS NSEC3 Template */
    if (!mdAddSpreadTmpl(session, yaf_dnsNSEC3_spec, YAF_DNSNSEC3_FLOW_TID,
                         FALSE, err))
    {
        return NULL;
    }

    /* SSL Template */
    if (!mdAddSpreadTmpl(session, yaf_ssl_spec, YAF_SSL_FLOW_TID, FALSE, err))
    {
        return NULL;
    }

    /* SSL Cert Template */
    if (!mdAddSpreadTmpl(session, yaf_cert_spec, YAF_SSL_CERT_FLOW_TID, FALSE,
                         err))
    {
        return NULL;
    }

    /* New SSL Template */
    if (!mdAddSpreadTmpl(session, yaf_newssl_spec, YAF_NEW_SSL_FLOW_TID, FALSE,
                         err))
    {
        return NULL;
    }

    /* New SSL CERT Template */
    /* SSL Cert Template */
    if (!mdAddSpreadTmpl(session, yaf_new_cert_spec, YAF_NEW_SSL_CERT_TID,
                         FALSE, err))
    {
        return NULL;
    }

    /* SSL Sub Template */
    if (!mdAddSpreadTmpl(session, yaf_subssl_spec,
                         YAF_SSL_SUBCERT_TID, FALSE, err))
    {
        return NULL;
    }

    /* Full Cert SSL Template */
    if (!mdAddSpreadTmpl(session, yaf_singleBL_spec, YAF_FULL_CERT_TID, FALSE,
                         err))
    {
        return NULL;
    }

    /* MySQL Template */
    if (!mdAddSpreadTmpl(session, yaf_mysql_spec, YAF_MYSQL_FLOW_TID, FALSE,
                         err))
    {
        return NULL;
    }

    /* MYSQL TXT Template */
    if (!mdAddSpreadTmpl(session, yaf_mysql_txt_spec, YAF_MYSQLTXT_FLOW_TID,
                         FALSE, err))
    {
        return NULL;
    }

    /* DNP 3.0 */
    if (!mdAddSpreadTmpl(session, yaf_dnp_spec, YAF_DNP3_FLOW_TID, FALSE, err))
    {
        return NULL;
    }

    if (!mdAddSpreadTmpl(session, yaf_dnp_rec_spec, YAF_DNP3_REC_FLOW_TID,
                         FALSE, err))
    {
        return NULL;
    }

    /* Modbus */
    if (!mdAddSpreadTmpl(session, yaf_singleBL_spec, YAF_MODBUS_FLOW_TID,FALSE,
                         err))
    {
        return NULL;
    }

    /* ENIP */
    if (!mdAddSpreadTmpl(session, yaf_singleBL_spec, YAF_ENIP_FLOW_TID, FALSE,
                         err))
    {
        return NULL;
    }

    /** RTP */
    if (!mdAddSpreadTmpl(session, yaf_rtp_spec, YAF_RTP_FLOW_TID, FALSE, err))
    {
        return NULL;
    }

    return session;

}
#endif

/**
 * mdAddTmpl
 *
 *
 */
static fbTemplate_t *mdAddTmpl(
    fbSession_t       *session,
    fbInfoElementSpec_t *spec,
    uint16_t           tid,
    gboolean           rev,
    const gchar *name,
    const gchar *description,
    GError            **err)
{

    fbInfoModel_t *model = mdInfoModel();
    fbTemplate_t  *tmpl = NULL;
    uint16_t      rtid = rev ? tid | YTF_REV : tid;

    tmpl = fbTemplateAlloc(model);

    if (!fbTemplateAppendSpecArray(tmpl, spec, 0xffffffff, err)) {
        return NULL;
    }

    if (!(fbSessionAddTemplate(session, TRUE, rtid, tmpl, err))) {
        return NULL;
    }

#if SM_ENABLE_METADATA_EXPORT
    if (!(fbSessionAddTemplateWithMetadata(session, FALSE, rtid, tmpl, name,description, err))) {
#else
    if (!(fbSessionAddTemplate(session, FALSE, rtid, tmpl, err))) {
#endif
        return NULL;
    }

    if (rev) {
        tmpl = fbTemplateAlloc(model);

        if (!fbTemplateAppendSpecArray(tmpl, spec, 0, err)) {
            return NULL;
        }

#if SM_ENABLE_METADATA_EXPORT
        if (!(fbSessionAddTemplateWithMetadata(session, FALSE, tid, tmpl, name, description, err))) {
#else
        if (!(fbSessionAddTemplate(session, FALSE, tid, tmpl, err))) {
#endif
            return NULL;
        }
    }

    return tmpl;
}


/**
 * mdInitExporterSessionDNSDedupOnly
 *
 *
 */
fbSession_t *mdInitExporterSessionDNSDedupOnly(
    fbSession_t     *session,
    GError          **err,
    uint8_t         stats,
    gboolean        metadata_export)
{
    fbInfoModel_t      *model = mdInfoModel();

    /*Allocate the session */
    if (!session) {
        session = fbSessionAlloc(model);
    }
#if SM_ENABLE_METADATA_EXPORT
    if (metadata_export) {
        if (!fbSessionEnableTypeMetadata(session, TRUE, err) ||
                !fbSessionEnableTemplateMetadata(session, TRUE, err)) {
            return NULL;
        }
    }
#endif
    if (!mdAddTmpl(session, md_dns_spec, MD_DNS_FULL, FALSE, "md_dns_dedup", NULL, err)) {
        return NULL;
    }

    if (stats != 1) {
        fbTemplate_t    *tmpl = NULL;
        /* Options Template */
        tmpl = mdAddTmpl(session, yaf_stats_option_spec,
                         YAF_OPTIONS_FLOW_TID, FALSE, "yaf_stats_options", NULL, err);
        if (!tmpl) {
            return NULL;
        }
        fbTemplateSetOptionsScope(tmpl, 2);
    }

    return session;
}

/**
 * mdInitExporterSessionDNSRROnly
 *
 *
 */
fbSession_t *mdInitExporterSessionDNSRROnly(
    fbSession_t      *session,
    GError           **err,
    uint8_t          stats,
    gboolean         metadata_export)
{
    fbInfoModel_t    *model = mdInfoModel();
    fbTemplate_t     *tmpl = NULL;

    if (!session) {
        session = fbSessionAlloc(model);
    }
#if SM_ENABLE_METADATA_EXPORT
    if (metadata_export) {
        if (!fbSessionEnableTypeMetadata(session, TRUE, err) ||
                !fbSessionEnableTemplateMetadata(session, TRUE, err)) {
            return NULL;
        }
    }
#endif
    tmpl = fbTemplateAlloc(model);

    if (!fbTemplateAppendSpecArray(tmpl, md_dns_rr_spec, 0xffffffff, err)) {
        return NULL;
    }

    if (!(fbSessionAddTemplate(session, TRUE, MD_DNSRR, tmpl, err))) {
        return NULL;
    }

    /* external template */
    tmpl = fbTemplateAlloc(model);

    if (!fbTemplateAppendSpecArray(tmpl, md_dns_rr_spec, 0, err)) {
        return NULL;
    }

#if SM_ENABLE_METADATA_EXPORT
    if (!(fbSessionAddTemplateWithMetadata(session, FALSE, MD_DNSRR, tmpl, "md_dns_rr_external", NULL, err))) {
#else
    if (!(fbSessionAddTemplate(session, FALSE, MD_DNSRR, tmpl, err))) {
#endif
        return NULL;
    }

    if (stats != 1) {
        /* Options Template */
        tmpl = mdAddTmpl(session, yaf_stats_option_spec,
                         YAF_OPTIONS_FLOW_TID, FALSE, "yaf_stats_options", NULL, err);
        if (!tmpl) {
            return NULL;
        }
        fbTemplateSetOptionsScope(tmpl, 2);
    }

    return session;
}


fbSession_t *mdInitExporterSessionFlowOnly(
    fbSession_t      *session,
    GError           **err,
    uint8_t          stats,
    gboolean         metadata_export)
{
    fbInfoModel_t   *model = mdInfoModel();

    if (!session) {
        session = fbSessionAlloc(model);
    }
#if SM_ENABLE_METADATA_EXPORT
    if (metadata_export) {
        if (!fbSessionEnableTypeMetadata(session, TRUE, err) ||
                !fbSessionEnableTemplateMetadata(session, TRUE, err)) {
            return NULL;
        }
    }
#endif
    /* SiLK Template 4 Export*/
    if (!mdAddTmpl(session, md_main_template, YAF_SILK_FLOW_TID, FALSE,
                   "md_main_silk", NULL, err))
    {
        return NULL;
    }

    if (stats != 1) {
        fbTemplate_t    *tmpl = NULL;
        /* Options Template */
        tmpl = mdAddTmpl(session, yaf_stats_option_spec,
                         YAF_OPTIONS_FLOW_TID, FALSE, "yaf_stats_options", NULL, err);
        if (!tmpl) {
            return NULL;
        }
        fbTemplateSetOptionsScope(tmpl, 2);
    }
    return session;
}


fbSession_t *mdInitExporterSessionDedupOnly(
    fbSession_t      *session,
    GError           **err,
    uint8_t         stats,
    gboolean        metadata_export)
{

    fbInfoModel_t   *model = mdInfoModel();

    if (!session) {
        session = fbSessionAlloc(model);
    }
#if SM_ENABLE_METADATA_EXPORT
    if (metadata_export) {
        if (!fbSessionEnableTypeMetadata(session, TRUE, err) ||
                !fbSessionEnableTemplateMetadata(session, TRUE, err)) {
            return NULL;
        }
    }
#endif
    if (!mdAddTmpl(session, md_dedup_spec, MD_DEDUP_FULL, FALSE,
                   "md_dedup_full", NULL, err))
    {
        return NULL;
    }

    if (stats != 1) {
        fbTemplate_t    *tmpl = NULL;
        /* Options Template */
        tmpl = mdAddTmpl(session, yaf_stats_option_spec,
                         YAF_OPTIONS_FLOW_TID, FALSE, "yaf_stats_options", NULL, err);
        if (!tmpl) {
            return NULL;
        }
        fbTemplateSetOptionsScope(tmpl, 2);
    }
    return session;
}

fbSession_t *mdInitExporterSessionSSLDedupOnly(
    fbSession_t      *session,
    GError           **err,
    uint8_t          stats,
    gboolean         metadata_export)
{

    fbInfoModel_t   *model = mdInfoModel();

    if (!session) {
        session = fbSessionAlloc(model);
    }
#if SM_ENABLE_METADATA_EXPORT
    if (metadata_export) {
        if (!fbSessionEnableTypeMetadata(session, TRUE, err) ||
                !fbSessionEnableTemplateMetadata(session, TRUE, err)) {
            return NULL;
        }
    }
#endif
    /* SSL dedup spec 4 Export*/
    if (!mdAddTmpl(session, md_ssl_spec, MD_SSL_TID, FALSE,
                   "md_ssl_dedup", NULL, err))
    {
        return NULL;
    }

    if (!mdAddTmpl(session, yaf_new_cert_spec, YAF_NEW_SSL_CERT_TID,
                   FALSE, "yaf_ssl_cert", NULL, err))
    {
        return NULL;
    }

    /* SSL Sub Template */
    if (!mdAddTmpl(session, yaf_subssl_spec,
                   YAF_SSL_SUBCERT_TID, FALSE, "yaf_ssl_subcert", NULL, err))
    {
        return NULL;
    }

    if (stats != 1) {
        fbTemplate_t    *tmpl = NULL;
        /* Options Template */
        tmpl = mdAddTmpl(session, yaf_stats_option_spec,
                         YAF_OPTIONS_FLOW_TID, FALSE, "yaf_stats_options", NULL, err);
        if (!tmpl) {
            return NULL;
        }
        fbTemplateSetOptionsScope(tmpl, 2);
    }
    return session;
}



/**
 * mdInitExporterSession
 *
 *
 *
 **/
fbSession_t *mdInitExporterSession(
    fbSession_t     *session,
    GError          **err,
    uint8_t         stats,
    gboolean        metadata_export)
{

    fbTemplate_t     *tmpl = NULL;
    fbInfoModel_t    *model = mdInfoModel();

    /*Allocate the session */
    if (!session) {
        session = fbSessionAlloc(model);
    }

#if SM_ENABLE_METADATA_EXPORT
    if (metadata_export) {
        if (!fbSessionEnableTypeMetadata(session, TRUE, err) ||
                !fbSessionEnableTemplateMetadata(session, TRUE, err)) {
            return NULL;
        }
    }
#endif
    /* SiLK Template 4 Export*/
    if (!mdAddTmpl(session, md_main_template, YAF_SILK_FLOW_TID, FALSE,
                         "md_main_silk", NULL, err))
    {
        return NULL;
    }

    /* dns dedup */
    if (!mdAddTmpl(session, md_dns_spec, MD_DNS_FULL, FALSE, "md_dns_full", NULL, err)) {
        return NULL;
    }

    /* dedup */
    if (!mdAddTmpl(session, md_dedup_spec, MD_DEDUP_FULL, FALSE, "md_dns_dedup_full", NULL, err)) {
        return NULL;
    }

    /* ssl dedup */
    if (!mdAddTmpl(session, md_ssl_spec, MD_SSL_TID, FALSE, "md_ssl_dedup", NULL, err)) {
        return NULL;
    }

    if (stats != 1) {
        /* Options Template */
        tmpl = mdAddTmpl(session, yaf_stats_option_spec,
                         YAF_OPTIONS_FLOW_TID, FALSE, "yaf_stats_options", NULL, err);
        if (!tmpl) {
            return NULL;
        }
        fbTemplateSetOptionsScope(tmpl, 2);
    }

    /* flow stats template */
    if (!mdAddTmpl(session, yaf_flow_stats_spec, YAF_STATS_FLOW_TID,
                         TRUE, "yaf_flow_stats", NULL, err))
    {
        return NULL;
    }

    /* Entropy Template */
    if (!mdAddTmpl(session, yaf_entropy_spec, YAF_ENTROPY_FLOW_TID,
                         TRUE, "yaf_entropy", NULL, err))
    {
        return NULL;
    }

    /* TCP Template */
    if (!mdAddTmpl(session, yaf_tcp_spec, YAF_TCP_FLOW_TID, TRUE, "yaf_tcp_flow", NULL, err)) {
        return NULL;
    }

    /* MPTCP Template */
    if (!mdAddTmpl(session, yaf_mptcp_spec, YAF_MPTCP_FLOW_TID, FALSE, "yaf_mptcp_flow", NULL, err)) {
        return NULL;
    }

    /* MAC Template */
    if (!mdAddTmpl(session, yaf_mac_spec, YAF_MAC_FLOW_TID, FALSE, "yaf_mac_flow", NULL, err)){
        return NULL;
    }


    /* p0f Template */
    if (!mdAddTmpl(session, yaf_p0f_spec,YAF_P0F_FLOW_TID, TRUE, "yaf_p0f_flow", NULL, err)) {
        return NULL;
    }

    /* dhcp Template */
    if (!mdAddTmpl(session, yaf_dhcp_fp_spec, YAF_DHCP_FLOW_TID,
                         TRUE, "yaf_dhcp_flow", NULL, err))
    {
        return NULL;
    }

    /*dhcp Options Template */
    if (!mdAddTmpl(session, yaf_dhcp_options_spec, YAF_DHCP_OP_TID,
                   TRUE, "yaf_dhcp_options", NULL, err))
    {
        return NULL;
    }

    /* fpExport Template */
    if (!mdAddTmpl(session, yaf_fpexport_spec,YAF_FPEXPORT_FLOW_TID,
                         TRUE, "yaf_fpexport_flow", NULL, err))
    {
        return NULL;
    }

    /* Payload Template */
    if (!mdAddTmpl(session, yaf_payload_spec,YAF_PAYLOAD_FLOW_TID, TRUE,
                         "yaf_payload_flow", NULL, err))
    {
        return NULL;
    }

    /* DPI TEMPLATES - HTTP*/
    if (!mdAddTmpl(session, yaf_http_spec,YAF_HTTP_FLOW_TID,FALSE, "yaf_http", NULL, err)){
        return NULL;
    }

    /* IRC Template */
    if (!mdAddTmpl(session, yaf_singleBL_spec, YAF_IRC_FLOW_TID, FALSE,
                         "yaf_irc", NULL, err))
    {
        return NULL;
    }

    /* SSH Template */
    if (!mdAddTmpl(session, yaf_singleBL_spec, YAF_SSH_FLOW_TID, FALSE,
                         "yaf_ssh", NULL, err))
    {
        return NULL;
    }

    /* POP3 Template */
    if (!mdAddTmpl(session, yaf_singleBL_spec, YAF_POP3_FLOW_TID, FALSE,
                         "yaf_pop3", NULL, err))
    {
        return NULL;
    }

    /* TFTP Template */
    if (!mdAddTmpl(session, yaf_tftp_spec, YAF_TFTP_FLOW_TID, FALSE,
                         "yaf_tftp", NULL, err))
    {
        return NULL;
    }

    /* SLP Template */
    if (!mdAddTmpl(session, yaf_slp_spec, YAF_SLP_FLOW_TID, FALSE,
                         "yaf_slp", NULL, err))
    {
        return NULL;
    }

    /* FTP Template */
    if (!mdAddTmpl(session, yaf_ftp_spec, YAF_FTP_FLOW_TID, FALSE, "yaf_ftp", NULL, err))
    {
        return NULL;
    }

    /* IMAP Template */
    if (!mdAddTmpl(session, yaf_imap_spec, YAF_IMAP_FLOW_TID, FALSE, "yaf_imap", NULL, err))
    {
        return NULL;
    }

    /* RTSP Template */
    if (!mdAddTmpl(session, yaf_rtsp_spec, YAF_RTSP_FLOW_TID, FALSE,
                         "yaf_rtsp", NULL, err))
    {
        return NULL;
    }

    /* SIP Template */
    if (!mdAddTmpl(session, yaf_sip_spec, YAF_SIP_FLOW_TID, FALSE, "yaf_sip", NULL, err))
    {
        return NULL;
    }

    /* NNTP Template */
    if (!mdAddTmpl(session, yaf_nntp_spec, YAF_NNTP_FLOW_TID, FALSE,
                         "yaf_nntp", NULL, err))
    {
        return NULL;
    }

    /* SMTP Template */
    if (!mdAddTmpl(session, yaf_smtp_spec, YAF_SMTP_FLOW_TID, FALSE,
                         "yaf_smtp", NULL, err))
    {
        return NULL;
    }

    /* DNS Template */
    if (!mdAddTmpl(session, yaf_dns_spec, YAF_DNS_FLOW_TID, FALSE,
                         "yaf_dns", NULL, err))
    {
        return NULL;
    }

    /* DNS QR Template */
    if (!mdAddTmpl(session, yaf_dnsQR_spec, YAF_DNSQR_FLOW_TID, FALSE,
                         "yaf_dns_qr", NULL, err))
    {
        return NULL;
    }

    /* DNS A Template */
    if (!mdAddTmpl(session, yaf_dnsA_spec, YAF_DNSA_FLOW_TID, FALSE,
                         "yaf_dns_a", NULL, err))
    {
        return NULL;
    }

    /* DNS AAAA Template */
    if (!mdAddTmpl(session, yaf_dnsAAAA_spec, YAF_DNSAAAA_FLOW_TID,FALSE,
                         "yaf_dns_aaaa", NULL, err))
    {
        return NULL;
    }

    /* DNS CNAME Template */
    if (!mdAddTmpl(session, yaf_dnsCNAME_spec, YAF_DNSCN_FLOW_TID,
                         FALSE, "yaf_dns_cname", NULL, err))
    {
        return NULL;
    }

    /* DNS MX Template */
    if (!mdAddTmpl(session, yaf_dnsMX_spec, YAF_DNSMX_FLOW_TID, FALSE,
                         "yaf_dns_mx", NULL, err))
    {
        return NULL;
    }

    /* DNS NS Template */
    if (!mdAddTmpl(session, yaf_dnsNS_spec, YAF_DNSNS_FLOW_TID, FALSE,
                         "yaf_dns_ns", NULL, err))
    {
        return NULL;
    }

    /* DNS PTR Template */
    if (!mdAddTmpl(session, yaf_dnsPTR_spec, YAF_DNSPTR_FLOW_TID, FALSE,
                         "yaf_dns_ptr", NULL, err))
    {
        return NULL;
    }

    /* DNS TXT Template */
    if (!mdAddTmpl(session, yaf_dnsTXT_spec, YAF_DNSTXT_FLOW_TID, FALSE,
                         "yaf_dns_txt", NULL, err))
    {
        return NULL;
    }

    /* DNS SOA Template */
    if (!mdAddTmpl(session, yaf_dnsSOA_spec, YAF_DNSSOA_FLOW_TID, FALSE,
                         "yaf_dns_soa", NULL, err))
    {
        return NULL;
    }

    /* DNS SRV Template */
    if (!mdAddTmpl(session, yaf_dnsSRV_spec, YAF_DNSSRV_FLOW_TID, FALSE,
                         "yaf_dns_srv", NULL, err))
    {
        return NULL;
    }

    /* DNS DS Template */
    if (!mdAddTmpl(session, yaf_dnsDS_spec, YAF_DNSDS_FLOW_TID, FALSE,
                         "yaf_dns_ds", NULL, err))
    {
        return NULL;
    }

    /* DNS RRSig Template */
    if (!mdAddTmpl(session, yaf_dnsSig_spec, YAF_DNSRRSIG_FLOW_TID,FALSE,
                         "yaf_dns_sig", NULL, err))
    {
        return NULL;
    }

    /* DNS NSEC Template */
    if (!mdAddTmpl(session, yaf_dnsNSEC_spec, YAF_DNSNSEC_FLOW_TID,FALSE,
                         "yaf_dns_nsec", NULL, err))
    {
        return NULL;
    }

    /* DNS Key Template */
    if (!mdAddTmpl(session, yaf_dnsKey_spec, YAF_DNSKEY_FLOW_TID, FALSE,
                         "yaf_dns_key", NULL, err))
    {
        return NULL;
    }

    /* DNS NSEC3 Template */
    if (!mdAddTmpl(session, yaf_dnsNSEC3_spec, YAF_DNSNSEC3_FLOW_TID,
                         FALSE, "yaf_dns_nsec3", NULL, err))
    {
        return NULL;
    }

    /* Full CERT SSL Template */
    if (!mdAddTmpl(session, yaf_singleBL_spec, YAF_FULL_CERT_TID, FALSE, "yaf_ssl_cert_full", NULL, err))
    {
        return NULL;
    }

    /* SSL Template */
    if (!mdAddTmpl(session, yaf_ssl_spec, YAF_SSL_FLOW_TID, FALSE, "yaf_ssl", NULL, err))
    {
        return NULL;
    }

    /* SSL Cert Template */
    if (!mdAddTmpl(session, yaf_cert_spec, YAF_SSL_CERT_FLOW_TID, FALSE,
                         "yaf_ssl_cert", NULL, err))
    {
        return NULL;
    }

    /* New SSL Template */
    if (!mdAddTmpl(session, yaf_newssl_spec, YAF_NEW_SSL_FLOW_TID, FALSE,
                   "yaf_new_ssl", NULL, err))
    {
        return NULL;
    }

    /* New SSL CERT Template */
    /* SSL Cert Template */
    if (!mdAddTmpl(session, yaf_new_cert_spec, YAF_NEW_SSL_CERT_TID,
                   FALSE, "yaf_new_ssl_cert", NULL, err))
    {
        return NULL;
    }

    /* SSL Sub Template */
    if (!mdAddTmpl(session, yaf_subssl_spec,
                   YAF_SSL_SUBCERT_TID, FALSE, "yaf_ssl_subcert", NULL, err)) 
    {
        return NULL;
    }

    /* MySQL Template */
    if (!mdAddTmpl(session, yaf_mysql_spec, YAF_MYSQL_FLOW_TID, FALSE,
                         "yaf_mysql", NULL, err))
    {
        return NULL;
    }

    /* MYSQL TXT Template */
    if (!mdAddTmpl(session, yaf_mysql_txt_spec, YAF_MYSQLTXT_FLOW_TID,
                         FALSE, "yaf_mysql_txt", NULL, err))
    {
        return NULL;
    }

    /* DNP 3.0 */
    if (!mdAddTmpl(session, yaf_dnp_spec, YAF_DNP3_FLOW_TID, FALSE, "yaf_dnp", NULL, err))
    {
        return NULL;
    }

    if (!mdAddTmpl(session, yaf_dnp_rec_spec, YAF_DNP3_REC_FLOW_TID,
                         FALSE, "yaf_dnp_rec", NULL, err))
    {
        return NULL;
    }

    /* Modbus */
    if (!mdAddTmpl(session, yaf_singleBL_spec, YAF_MODBUS_FLOW_TID,FALSE,
                         "yaf_modbus", NULL, err))
    {
        return NULL;
    }

    /* ENIP */
    if (!mdAddTmpl(session, yaf_singleBL_spec, YAF_ENIP_FLOW_TID, FALSE,
                         "yaf_enip", NULL, err))
    {
        return NULL;
    }

    /** RTP */
    if (!mdAddTmpl(session, yaf_rtp_spec, YAF_RTP_FLOW_TID, FALSE, "yaf_rtp", NULL, err))
    {
        return NULL;
    }

    return session;
}

/**
 * mdInitCollectorSession
 *
 *  =============================================
 * create a session (fbSession_t) and attach it to the info model via
 * fbSessionAlloc create a collector session and then pass that session
 * to the listener to finish building the collector
 *
 **/
fbSession_t *mdInitCollectorSession(
    GError         **err)
{
    fbInfoModel_t *model = mdInfoModel();
    fbTemplate_t *tmpl = NULL;
    fbTemplate_t *o_tmpl = NULL;
    fbSession_t  *session = NULL;


    /* Allocate the session */
    session = fbSessionAlloc(model);

    tmpl = fbTemplateAlloc(model);

    if (!fbTemplateAppendSpecArray(tmpl, md_main_template, 0xffffffff, err)) {
        return NULL;
    }
    if (!fbSessionAddTemplate(session, TRUE, YAF_SILK_FLOW_TID, tmpl, err)) {
        return NULL;
    }


    o_tmpl = fbTemplateAlloc(model);

    if (!fbTemplateAppendSpecArray(o_tmpl, yaf_stats_option_spec, 0xffffffff,
                                   err))
    {
        return NULL;
    }

    if (!fbSessionAddTemplate(session, TRUE, YAF_OPTIONS_FLOW_TID, o_tmpl,
                              err))
    {
        return NULL;
    }

    /* read dns rr only template */
    tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(tmpl, md_dns_rr_spec, 0xffffffff, err)) {
        return NULL;
    }
    if (!fbSessionAddTemplate(session, TRUE, MD_DNSRR, tmpl, err)) {
        return NULL;
    }

    /* dns dedup */
    tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(tmpl, md_dns_spec, 0xffffffff, err)) {
        return NULL;
    }

    if (!fbSessionAddTemplate(session, TRUE, MD_DNS_FULL, tmpl, err)) {
        return NULL;
    }


    /* dedup */
    tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(tmpl, md_dedup_spec, 0xffffffff, err)) {
        return NULL;
    }
    if (!fbSessionAddTemplate(session, TRUE, MD_DEDUP_FULL, tmpl, err)) {
        return NULL;
    }

    /* ssl dedup */
    tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(tmpl, md_ssl_spec, 0, err)) {
        return NULL;
    }

    if (!fbSessionAddTemplate(session, TRUE, MD_SSL_TID, tmpl, err)) {
        return NULL;
    }


    /* ssl cert */
    tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(tmpl, yaf_new_cert_spec, 0xffffffff, err)) {
        return NULL;
    }

    if (!fbSessionAddTemplate(session, TRUE, YAF_NEW_SSL_CERT_TID, tmpl, err)) {
        return NULL;
    }

    tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(tmpl, yaf_new_cert_spec, 0xffffffff, err)) {
        return NULL;
    }

    if (!(fbSessionAddTemplate(session, TRUE, SM_INTCERT_FLOW_TID, tmpl, err))) {
        return NULL;
    }

    tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(tmpl, yaf_newssl_spec, 0xffffffff, err)) {
        return NULL;
    }

    if (!(fbSessionAddTemplate(session, TRUE, SM_INTSSL_FLOW_TID, tmpl, err))) {
        return NULL;
    }

    /** we will want to add a template callback eventually */
    fbSessionAddTemplateCtxCallback(session, mdTemplateCallback);

    return session;
}





/**
 * mdSetExportTemplate
 *
 * set the export template on the fbuf
 */
gboolean mdSetExportTemplate(
    fBuf_t          *fbuf,
    uint16_t        tid,
    GError          **err)
{

    fbSession_t *session = NULL;
    fbTemplate_t *tmpl = NULL;
    GString             *template_name = g_string_new("");
    
    if (fBufSetExportTemplate(fbuf, tid, err)) {
        g_string_free(template_name, TRUE);
        return TRUE;
    }

    if (!g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_TMPL)) {
        g_string_free(template_name, TRUE);
        return FALSE;
    }

    g_clear_error(err);
    session = fBufGetSession(fbuf);
    tmpl = fbTemplateAlloc(mdInfoModel());

    if (tid == YAF_OPTIONS_FLOW_TID) {
        g_string_append_printf(template_name, "yaf_options_flow"); 
        if (!fbTemplateAppendSpecArray(tmpl, yaf_stats_option_spec,
                                       YAF_OPTIONS_FLOW_TID, err)) {
            g_string_free(template_name, TRUE);
            return FALSE;
        }
        fbTemplateSetOptionsScope(tmpl, 2);
    } else if ((tid & 0xFFF0) == MD_DNS_OUT) {
#if SM_ENABLE_METADATA_EXPORT
        g_string_append_printf(template_name, "md_dns"); 
        if (tid & MD_LAST_SEEN)
            g_string_append_printf(template_name, "_%s", MD_LAST_SEEN_NAME);
        if (tid & MD_DNS_AREC)
            g_string_append_printf(template_name, "_%s", MD_DNS_AREC_NAME);
        if (tid & MD_DNS_OREC)
            g_string_append_printf(template_name, "_%s", MD_DNS_OREC_NAME);
#endif
        if (!fbTemplateAppendSpecArray(tmpl, md_dns_spec,
                                       (tid & (~MD_DNS_OUT)), err))
        {
            g_string_free(template_name, TRUE);
            return FALSE;
        }
    } else if ((tid & 0xF0F1) == MD_DNSRR) {
#if SM_ENABLE_METADATA_EXPORT
        g_string_append_printf(template_name, "md_dnsrr"); 
        if (tid & YTF_IP6)
            g_string_append_printf(template_name, "_%s", YTF_IP6_NAME);
        if (tid & YTF_IP4)
            g_string_append_printf(template_name, "_%s", YTF_IP4_NAME);
        if (tid & MD_DNSRR_FULL)
            g_string_append_printf(template_name, "_%s", MD_DNSRR_FULL_NAME);
#endif
        if (!fbTemplateAppendSpecArray(tmpl, md_dns_rr_spec,
                                       (tid & (~MD_DNSRR)), err))
        {
            g_string_free(template_name, TRUE);
            return FALSE;
        }
    } else if ((tid & 0xFFF8) == MD_DEDUP_TID) {
#if SM_ENABLE_METADATA_EXPORT
        g_string_append_printf(template_name, "md_dedup"); 
        if (tid & MD_DEDUP_SSL)
            g_string_append_printf(template_name, "_%s", MD_DEDUP_SSL_NAME);
#endif
        if (!fbTemplateAppendSpecArray(tmpl, md_dedup_spec,
                                       (tid & (~MD_DEDUP_TID)), err))
        {
            g_string_free(template_name, TRUE);
            return FALSE;
        }
    } else if (tid == MD_SSL_TID) {
#if SM_ENABLE_METADATA_EXPORT
        g_string_append_printf(template_name, "md_ssl"); 
#endif
        if (!fbTemplateAppendSpecArray(tmpl, md_ssl_spec, tid, err)) {
            g_string_free(template_name, TRUE);
            return FALSE;
        }
    } else {
#if SM_ENABLE_METADATA_EXPORT
        g_string_append_printf(template_name, "md_main"); 
        if (tid & YTF_TOTAL)
            g_string_append_printf(template_name, "_%s", YTF_TOTAL_NAME);
        if (tid & YTF_REV)
            g_string_append_printf(template_name, "_%s", YTF_REV_NAME);
        if (tid & YTF_DELTA)
            g_string_append_printf(template_name, "_%s", YTF_DELTA_NAME);
        if (tid & YTF_IP6)
            g_string_append_printf(template_name, "_%s", YTF_IP6_NAME);
        if (tid & YTF_IP4)
            g_string_append_printf(template_name, "_%s", YTF_IP4_NAME);
        if (tid & YTF_TCP)
            g_string_append_printf(template_name, "_%s", YTF_TCP_NAME);
        if (tid & YTF_DAGIF)
            g_string_append_printf(template_name, "_%s", YTF_DAGIF_NAME);
        if (tid & YTF_MPLS)
            g_string_append_printf(template_name, "_%s", YTF_MPLS_NAME);
        if (tid & YTF_PAD)
            g_string_append_printf(template_name, "_%s", YTF_PAD_NAME);
        if (tid & YTF_LIST)
            g_string_append_printf(template_name, "_%s", YTF_LIST_NAME);
#endif
        if (!fbTemplateAppendSpecArray(tmpl, md_main_template,
                                       (tid & (~YAF_SILK_FLOW_TID)), err))
        {
            g_string_free(template_name, TRUE);
            return FALSE;
        }
    }
#if SM_ENABLE_METADATA_EXPORT
    if (!fbSessionAddTemplateWithMetadata(session, FALSE, tid, tmpl, template_name->str, NULL, err)) {
#else
    if (!fbSessionAddTemplate(session, FALSE, tid, tmpl, err)) {
#endif
        g_string_free(template_name, TRUE);
        return FALSE;
    }

    g_string_free(template_name, TRUE);
    return fBufSetExportTemplate(fbuf, tid, err);
}


#if HAVE_SPREAD
/**
 * mdSetSpreadExportTemplate
 *
 * set the template on the fbuf and groups
 *
 */
gboolean mdSetSpreadExportTemplate(
    fBuf_t           *fbuf,
    fbSpreadParams_t *sp,
    uint16_t         tid,
    char             **groups,
    int              num_groups,
    GError           **err)
{
    fbSession_t *session = NULL;
    fbTemplate_t *tmpl = NULL;

    if (fBufSetExportTemplate(fbuf, tid, err)) {
        return TRUE;
    }

    if (!g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_TMPL)) {
        return FALSE;
    }

    g_clear_error(err);

    session = fBufGetSession(fbuf);
    tmpl = fbTemplateAlloc(mdInfoModel());

    if (tid == YAF_OPTIONS_FLOW_TID) {

        if (!fbTemplateAppendSpecArray(tmpl, yaf_stats_option_spec,
                                       YAF_OPTIONS_FLOW_TID, err)) {
            return FALSE;
        }
        fbTemplateSetOptionsScope(tmpl, 2);
    } else if ((tid & 0xFFF0) == MD_DNS_OUT) {
        if (!fbTemplateAppendSpecArray(tmpl, md_dns_spec,
                                       (tid & (~MD_DNS_OUT)), err))
        {
            return FALSE;
        }
    } else if ((tid & 0xF0F1) == MD_DNSRR) {
        if (!fbTemplateAppendSpecArray(tmpl, md_dns_rr_spec,
                                       (tid & (~MD_DNSRR)), err))
        {
            return FALSE;
        }
    } else if ((tid & 0xFFF8) == MD_DEDUP_TID) {
        if (!fbTemplateAppendSpecArray(tmpl, md_dedup_spec,
                                       (tid & (~MD_DEDUP_TID)), err))
        {
            return FALSE;
        }
    } else if (tid == MD_SSL_TID) {
        if (!fbTemplateAppendSpecArray(tmpl, md_ssl_spec, tid, err)) {
            return FALSE;
        }
    } else {

        if (!fbTemplateAppendSpecArray(tmpl, md_main_template,
                                       (tid & (~YAF_SILK_FLOW_TID)), err))
        {
            return FALSE;
        }
    }


    if (!fbSessionAddTemplatesMulticast(session, sp->groups, FALSE, tid,
                                       tmpl, err))
    {
        return FALSE;
    }

    fBufSetSpreadExportGroup(fbuf, groups, num_groups, err);

    return fBufSetExportTemplate(fbuf, tid, err);

}

#endif





/**
 * mdOptionsCheck
 *
 * check to see if the next record on the fbuf is an options record
 *
 */
gboolean mdOptionsCheck(
    fBuf_t         **fbuf,
    uint16_t       *tid,
    fbTemplate_t   **tmpl,
    GError         **err)
{
    fbInfoElementSpec_t tname;

    tname.name = "templateName";

    *tmpl = fBufNextCollectionTemplate(*fbuf, tid, err);
    if (*tmpl) {
        if (fbTemplateGetOptionsScope(*tmpl)) {
            /* options message */
            if (fbTemplateContainsElementByName(*tmpl, &tname)) {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_TMPL,
                            "Got a template stats message - ignore");
                g_warning("got a template descritpion options record.");
                /* ignore template metadata records */
                *tid = 0;
            } else if (fbInfoModelTypeInfoRecord(*tmpl)) {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_TMPL,
                            "Got a info element type  message - ignore");
                /* ignore template metadata records */
                *tid = 0;
            }
            return TRUE;
        }
    } else {
        if ((g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_EOM)) ||
            (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD)) ||
            (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_IPFIX)))
        {
            *tid = 0;
            return TRUE;
        } else {
            fBufFree(*fbuf);
            *fbuf = NULL;
            return FALSE;
        }
    }

    return FALSE;
}


gboolean mdIgnoreRecord(
    mdContext_t    *ctx,
    fBuf_t         *fbuf,
    GError         **err)
{
    gboolean       rc;
    yfIpfixStats_t stats;
    size_t         stats_len = sizeof(stats);

    if (!fBufSetInternalTemplate(fbuf, YAF_OPTIONS_FLOW_TID, err)) {
        /* log an error */
        return FALSE;
    }

    rc = fBufNext(fbuf, (uint8_t *)&stats, &stats_len, err);

    if (FALSE == rc) {
        /* End of Set. */
        g_clear_error(err);
    }

    /* set internal template back to SiLK Flow */
    if (!fBufSetInternalTemplate(fbuf, YAF_SILK_FLOW_TID, err))
    {
        return FALSE;
    }

    return TRUE;
}

/**
 * mdForwardOptions
 *
 * forward the options record to the exporters that
 * are configured to receive YAF stats
 *
 */
gboolean mdForwardOptions(
    mdContext_t    *ctx,
    fBuf_t         *fbuf,
    char           *colname,
    GError         **err)
{

    gboolean       rc;
    yfIpfixStats_t stats;
    size_t         stats_len = sizeof(stats);
    md_export_node_t *cnode = NULL;

    if (!fBufSetInternalTemplate(fbuf, YAF_OPTIONS_FLOW_TID, err)) {
        /* log an error */
        return FALSE;
    }

    rc = fBufNext(fbuf, (uint8_t *)&stats, &stats_len, err);

    if (FALSE == rc) {
        /* End of Set. */
        g_clear_error(err);
        goto end;
    }

    if (ctx->cfg->no_stats) {
        goto end;
    }

    mdLogStats(&stats, colname);

    for (cnode = ctx->cfg->flowexit; cnode; cnode = cnode->next) {
        if (cnode->filter) {
            rc = mdFilter(cnode->filter, NULL, ctx->cfg->current_domain,
                          cnode->and_filter, ctx->cfg->collector_id);
            if (!rc) continue;
        }
        if (!mdExporterWriteOptions(ctx->cfg, cnode->exp, &stats, err)) {
            return FALSE;
        }
    }

  end:
    /* set internal template back to SiLK Flow */
    if (!fBufSetInternalTemplate(fbuf, YAF_SILK_FLOW_TID, err))
    {
        return FALSE;
    }

    return TRUE;
}

/**
 * mdForwardDNSDedup
 *
 */
gboolean mdForwardDNSDedup(
    mdContext_t *ctx,
    fBuf_t      *fbuf,
    GError      **err)
{

    gboolean       rc;
    md_dns_t       dns;
    size_t         dns_len = sizeof(dns);
    md_export_node_t *cnode = NULL;
    uint16_t       tid;

    if (!fBufSetInternalTemplate(fbuf, MD_DNS_FULL, err)) {
        return FALSE;
    }

    rc = fBufNext(fbuf, (uint8_t *)&dns, &dns_len, err);

    if (FALSE == rc) {
        /* End of Set. */
        g_clear_error(err);
        goto end;
    }


    if (fBufGetExportTime(fbuf) > (ctx->cfg->ctime/1000)) {
        ctx->cfg->ctime = (uint64_t)fBufGetExportTime(fbuf);
        ctx->cfg->ctime = ctx->cfg->ctime * 1000;
    }

    fBufGetCollectionTemplate(fbuf, &tid);

    for (cnode = ctx->cfg->flowexit; cnode; cnode = cnode->next) {
        if (cnode->filter) {
            rc = mdFilter(cnode->filter, NULL, ctx->cfg->current_domain,
                          cnode->and_filter, ctx->cfg->collector_id);
            if (!rc) continue;
        }
        if (!mdExporterWriteRecord(ctx->cfg, cnode->exp, tid,
                                   (uint8_t *)&dns, dns_len, err)) {
            return FALSE;
        }
    }

  end:
    /* set internal template back to SiLK Flow */
    if (!fBufSetInternalTemplate(fbuf, YAF_SILK_FLOW_TID, err))
    {
        return FALSE;
    }

    return TRUE;
}



/**
 * mdForwardDNSRR
 *
 * forward the dns rr-only record to the exporters
 * that are configured to receive them
 *
 */
gboolean mdForwardDNSRR(
    mdContext_t *ctx,
    fBuf_t      *fbuf,
    GError      **err)
{

    gboolean       rc;
    mdDnsRR_t      dnsrr;
    size_t         rr_len = sizeof(dnsrr);
    md_export_node_t *cnode = NULL;
    uint16_t       tid;

    if (!fBufSetInternalTemplate(fbuf, MD_DNSRR, err)) {
        return FALSE;
    }

    rc = fBufNext(fbuf, (uint8_t *)&dnsrr, &rr_len, err);

    if (FALSE == rc) {
        /* End of Set. */
        g_clear_error(err);
        goto end;
    }

    if (fBufGetExportTime(fbuf) > (ctx->cfg->ctime/1000)) {
        ctx->cfg->ctime = (uint64_t)fBufGetExportTime(fbuf);
        ctx->cfg->ctime = ctx->cfg->ctime * 1000;
    }

    fBufGetCollectionTemplate(fbuf, &tid);

    for (cnode = ctx->cfg->flowexit; cnode; cnode = cnode->next) {
        if (cnode->filter) {
            rc = mdFilter(cnode->filter, NULL, ctx->cfg->current_domain,
                          cnode->and_filter, ctx->cfg->collector_id);
            if (!rc) {
                continue;
            }
        }
        if (!mdExporterWriteDNSRRRecord(ctx->cfg, cnode->exp, tid,
                                        (uint8_t *)&dnsrr, rr_len, err))
        {
            return FALSE;
        }
    }

  end:

    /* set internal template back to SiLK Flow */
    if (!fBufSetInternalTemplate(fbuf, YAF_SILK_FLOW_TID, err))
    {
        return FALSE;
    }

    return TRUE;
}
/**
 * mdForwardDedupCustom
 *
 *
 */
gboolean mdForwardDedupCustom(
    mdContext_t      *ctx,
    mdTmplContext_t  *tctx,
    fBuf_t           *fbuf,
    GError           **err)
{

    gboolean       rc;
    md_dedup_t     dedup;
    md_dedup_old_t odedup;
    size_t         dedup_len = sizeof(dedup);
    size_t         odedup_len = sizeof(odedup);
    md_export_node_t *cnode = NULL;
    uint16_t       tid;


    if (!fBufSetInternalTemplate(fbuf, tctx->tid, err)) {
        return FALSE;
    }

    if (tctx->num_elem < 8) {
        rc = fBufNext(fbuf, (uint8_t *)&odedup, &odedup_len, err);
        if (FALSE == rc) {
            /* End of Set. */
            g_clear_error(err);
            goto end;
        }
        dedup.fseen = odedup.fseen;
        dedup.lseen = odedup.lseen;
        dedup.stime = 0;
        dedup.count = odedup.count;
        memcpy(dedup.sip6, odedup.sip6, 16);
        dedup.sip = odedup.sip;
        dedup.hash = odedup.hash;
        dedup.data.buf = odedup.data.buf;
        dedup.data.len = odedup.data.len;
        dedup.mapname.buf = NULL;
        dedup.mapname.len = 0;
    } else {
        rc = fBufNext(fbuf, (uint8_t *)&dedup, &dedup_len, err);

        if (FALSE == rc) {
            /* End of Set. */
            g_clear_error(err);
            goto end;
        }
    }

    if (fBufGetExportTime(fbuf) > (ctx->cfg->ctime/1000)) {
        ctx->cfg->ctime = (uint64_t)fBufGetExportTime(fbuf);
        ctx->cfg->ctime = ctx->cfg->ctime * 1000;
    }

    fBufGetCollectionTemplate(fbuf, &tid);

    for (cnode = ctx->cfg->flowexit; cnode; cnode = cnode->next) {
        if (cnode->filter) {
            rc = mdFilter(cnode->filter, NULL, ctx->cfg->current_domain,
                          cnode->and_filter, ctx->cfg->collector_id);
            if (!rc) {
                continue;
            }
        }
        if (cnode->dedup) {
            if (!md_dedup_write_dedup(ctx, cnode, &dedup, tctx->ie, err)) {
                return FALSE;
            }
        } else {
            if (!mdExporterWriteDedupRecord(ctx->cfg, cnode, NULL,
                                            &dedup, "dedup", 0, tid, err))
            {
                return FALSE;
            }
        }
    }

  end:
    /* set internal template back to SiLK Flow */
    if (!fBufSetInternalTemplate(fbuf, YAF_SILK_FLOW_TID, err))
    {
        return FALSE;
    }

    return TRUE;
}




/**
 * mdForwardDedup
 *
 */
gboolean mdForwardDedup(
    mdContext_t *ctx,
    fBuf_t      *fbuf,
    GError      **err)
{
    gboolean       rc;
    md_dedup_t     dedup;
    size_t         dedup_len = sizeof(dedup);
    md_export_node_t *cnode = NULL;
    uint16_t       tid;

    if (!fBufSetInternalTemplate(fbuf, MD_DEDUP_FULL, err)) {
        return FALSE;
    }

    rc = fBufNext(fbuf, (uint8_t *)&dedup, &dedup_len, err);

    if (FALSE == rc) {
        /* End of Set. */
        g_clear_error(err);
        goto end;
    }

    if (fBufGetExportTime(fbuf) > (ctx->cfg->ctime/1000)) {
        ctx->cfg->ctime = (uint64_t)fBufGetExportTime(fbuf);
        ctx->cfg->ctime = ctx->cfg->ctime * 1000;
    }

    fBufGetCollectionTemplate(fbuf, &tid);

    for (cnode = ctx->cfg->flowexit; cnode; cnode = cnode->next) {
        if (cnode->filter) {
            rc = mdFilter(cnode->filter, NULL, ctx->cfg->current_domain,
                          cnode->and_filter, ctx->cfg->collector_id);
            if (!rc) {
                continue;
            }
        }
        if (cnode->dedup) {
            /* ssl is the only way that should make it here */
            if (!md_dedup_write_dedup(ctx, cnode, &dedup, 244,
                                      err)) {
                return FALSE;
            }
        } else {
            if (!mdExporterWriteDedupRecord(ctx->cfg, cnode, NULL,
                                            &dedup, "dedup", 0, tid, err))
            {
                return FALSE;
            }
        }
    }

  end:
    /* set internal template back to SiLK Flow */
    if (!fBufSetInternalTemplate(fbuf, YAF_SILK_FLOW_TID, err))
    {
        return FALSE;
    }

    return TRUE;
}

/**
 * mdForwardSSLDedup
 *
 */
gboolean mdForwardSSLDedup(
    mdContext_t *ctx,
    fBuf_t      *fbuf,
    GError      **err)
{
    gboolean       rc;
    md_ssl_t       ssl;
    size_t         ssl_len = sizeof(ssl);
    md_export_node_t *cnode = NULL;

    if (!fBufSetInternalTemplate(fbuf, MD_SSL_TID, err)) {
        return FALSE;
    }

    rc = fBufNext(fbuf, (uint8_t *)&ssl, &ssl_len, err);

    if (FALSE == rc) {
        /* End of Set. */
        g_clear_error(err);
        goto end;
    }

    if (fBufGetExportTime(fbuf) > (ctx->cfg->ctime/1000)) {
        ctx->cfg->ctime = (uint64_t)fBufGetExportTime(fbuf);
        ctx->cfg->ctime = ctx->cfg->ctime * 1000;
    }

    for (cnode = ctx->cfg->flowexit; cnode; cnode = cnode->next) {
        if (cnode->filter) {
            rc = mdFilter(cnode->filter, NULL, ctx->cfg->current_domain,
                          cnode->and_filter, ctx->cfg->collector_id);
            if (!rc) {
                continue;
            }
        }
        if (!mdExporterWriteSSLDedupRecord(ctx->cfg, cnode->exp, MD_SSL_TID,
                                           (uint8_t *)&ssl, ssl_len, err))
        {
            return FALSE;
        }
    }

  end:

    /* set internal template back to SiLK Flow */
    if (!fBufSetInternalTemplate(fbuf, YAF_SILK_FLOW_TID, err))
    {
        return FALSE;
    }

    return TRUE;
}

/**
 * mdForwardSSLDedup
 *
 */
gboolean mdForwardSSLCert(
    mdContext_t *ctx,
    fBuf_t      *fbuf,
    GError      **err)
{
    gboolean       rc;
    yfNewSSLCertFlow_t cert;
    size_t         cert_len = sizeof(cert);
    md_export_node_t *cnode = NULL;

    if (!fBufSetInternalTemplate(fbuf, YAF_NEW_SSL_CERT_TID, err)) {
        return FALSE;
    }

    memset(&cert, 0, cert_len);

    rc = fBufNext(fbuf, (uint8_t *)&cert, &cert_len, err);

    if (FALSE == rc) {
        /* End of Set. */
        g_clear_error(err);
        goto end;
    }

    if (fBufGetExportTime(fbuf) > (ctx->cfg->ctime/1000)) {
        /* fbufgetexporttime returns time in seconds -  need ms */
        ctx->cfg->ctime = (uint64_t)fBufGetExportTime(fbuf);
        ctx->cfg->ctime = ctx->cfg->ctime * 1000;
    }

    for (cnode = ctx->cfg->flowexit; cnode; cnode = cnode->next) {
        if (cnode->filter) {
            rc = mdFilter(cnode->filter, NULL, ctx->cfg->current_domain,
                          cnode->and_filter, ctx->cfg->collector_id);
            if (!rc) {
                continue;
            }
        }

        md_ssl_export_ssl_cert(ctx, cnode, &cert, err);
    }

    mdCleanUpSSLCert(&cert);

  end:
    /* set internal template back to SiLK Flow */
    if (!fBufSetInternalTemplate(fbuf, YAF_SILK_FLOW_TID, err))
    {
        return FALSE;
    }

    return TRUE;
}



/**
 * mdConvertToSiLK
 *
 * convert a normal YAF record to SiLK record
 * put TCP info back in the normal IPFIX record
 *
 * @return the template id of the record
 */
uint16_t mdConvertToSiLK(
    mdRecord_t        *rec,
    uint16_t           tid)
{
    uint16_t     wtid = YAF_SILK_FLOW_TID;

    if (rec->reversePacketTotalCount || rec->reversePacketDeltaCount) {
        wtid |= YTF_REV;
    }
    if (rec->sourceIPv4Address == 0) {
        wtid |= YTF_IP6;
    } else {
        wtid |= YTF_IP4;
    }

    if (rec->protocolIdentifier == 6) {
        wtid |= YTF_TCP;
    }

    if (rec->ingressInterface || rec->egressInterface) {
        wtid |= YTF_DAGIF;
    }

    if (tid & YTF_MPLS) {
        wtid |= YTF_MPLS;
    }

    if (rec->packetDeltaCount) {
        wtid |= YTF_DELTA;
    } else {
        wtid |= YTF_TOTAL;
    }


    return wtid;
}


/**
 * mdDecodeAndClear
 *
 * Do the STML decode and clean up
 *
 */
void mdDecodeAndClear(
    mdContext_t    *ctx,
    mdRecord_t     *rec)
{

    mdFullFlow_t *md_flow;

    md_flow = g_slice_new0(mdFullFlow_t);

    md_flow->rec = rec;

    mdMainDecode(ctx, md_flow);

    mdCleanUP(md_flow);

    fbSubTemplateMultiListClear(&(rec->stml));

    g_slice_free(mdFullFlow_t, md_flow);

}

/**
 * mdForwardFlow
 *
 * Forward a normal flow record to the exporters
 * that are configured to receive it
 *
 */
gboolean mdForwardFlow(
    mdContext_t   *ctx,
    mdRecord_t    *rec,
    uint16_t       tid,
    GError         **err)
{
    gboolean         rc;
    int              wf = 0;
    mdFullFlow_t     *md_flow;
    md_export_node_t *cnode = NULL;

    md_flow = g_slice_new0(mdFullFlow_t);

    md_flow->rec = rec;

    md_flow->rec->flowKeyHash = md_util_flow_key_hash(rec);

    mdMainDecode(ctx, md_flow);

    md_flow->tid = tid;

    md_flow->rec->obsid = ctx->cfg->current_domain;

    /* copy collector name */
    md_flow->collector_name = ctx->cfg->collector_name;
    md_flow->collector_id = ctx->cfg->collector_id;
    for (cnode = ctx->cfg->flowexit; cnode; cnode = cnode->next) {

        rc = TRUE;
        if (cnode->filter) {
            rc = mdFilter(cnode->filter, rec,
                          ctx->cfg->current_domain, cnode->and_filter,
                          ctx->cfg->collector_id);
        }

        if (rc) {
            if (cnode->dns_dedup && (md_flow->app_tid == YAF_DNS_FLOW_TID)) {
                md_add_dns_node(ctx, cnode, md_flow);
            }
            if (cnode->ssl_dedup && ((md_flow->app_tid == SM_INTSSL_FLOW_TID)
                                     || md_flow->fullcert))
            {
                md_ssl_add_node(ctx, cnode, md_flow);
            }

            if (cnode->dedup) {
                if ((md_flow->app_tid == 0) && !md_flow->dhcpfp &&
                    !md_flow->p0f)
                {
                    //continue;
                } else {
                    md_dedup_lookup_node(ctx, cnode, md_flow, err);
                }
                //continue;
            }

            wf = mdExporterWriteFlow(ctx->cfg, cnode->exp, md_flow, err);
            if (wf < 0) {
                rc = FALSE;
                goto done;
            }
        }

        if (cnode->dns_dedup || cnode->dedup) {
            /* only flush queue every 50 flows */
            if ((ctx->stats->recvd_flows % 50) == 0) {
                if (cnode->dns_dedup) {
                    if (!md_dns_flush_queue(cnode, ctx->cfg, err)) {
                        rc = FALSE;
                        goto done;
                    }
                }
                if (cnode->dedup) {
                    if (!md_dedup_flush_queue(cnode, ctx->cfg, err)) {
                        rc = FALSE;
                        goto done;
                    }
                }
            }
        }
    }

    rc = TRUE;

  done:
    mdCleanUP(md_flow);

    fbSubTemplateMultiListClear(&(rec->stml));

    g_slice_free(mdFullFlow_t, md_flow);

    return rc;

}

/**
 * mdMainDecode
 *
 * loop through the STML and store the pointers
 * to specific records in the mdFullFlow for quick
 * retrieval later
 *
 */
void mdMainDecode(
    mdContext_t   *ctx,
    mdFullFlow_t  *md_flow)
{

    fbSubTemplateMultiListEntry_t *stml = NULL;

    if (md_flow->rec->packetTotalCount == 0) {
        md_flow->rec->packetTotalCount = md_flow->rec->packetDeltaCount;
        md_flow->rec->reversePacketTotalCount = md_flow->rec->reversePacketDeltaCount;
    }
    if (md_flow->rec->octetTotalCount == 0) {
        md_flow->rec->octetTotalCount = md_flow->rec->octetDeltaCount;
        md_flow->rec->reverseOctetTotalCount = md_flow->rec->reverseOctetDeltaCount;
    }

    while ((stml =
            fbSubTemplateMultiListGetNextEntry(&(md_flow->rec->stml), stml)))
    {
        switch ((stml->tmplID & YTF_BIF)) {
          case YAF_ENTROPY_FLOW_TID:
            md_flow->entropy =
                (yfEntropyFlow_t *)FBSTMLNEXT(stml, md_flow->entropy);
            break;
          case YAF_TCP_FLOW_TID:
            {
                yfTcpFlow_t *tcp = NULL;
                tcp = (yfTcpFlow_t *)FBSTMLNEXT(stml, tcp);
                md_flow->rec->tcpSequenceNumber = tcp->tcpSequenceNumber;
                md_flow->rec->initialTCPFlags = tcp->initialTCPFlags;
                md_flow->rec->unionTCPFlags = tcp->unionTCPFlags;
                if ((stml->tmplID & YTF_REV)) {
                    md_flow->rec->reverseTcpSequenceNumber = tcp->reverseTcpSequenceNumber;
                    md_flow->rec->reverseInitialTCPFlags = tcp->reverseInitialTCPFlags;
                    md_flow->rec->reverseUnionTCPFlags = tcp->reverseUnionTCPFlags;
                }
                break;
            }
          case YAF_MAC_FLOW_TID:
            md_flow->mac = (yfMacFlow_t *)FBSTMLNEXT(stml, md_flow->mac);
            break;
          case YAF_PAYLOAD_FLOW_TID:
            {
                md_flow->pay = (yfPayloadFlow_t *)FBSTMLNEXT(stml,
                                                             md_flow->pay);
            }
            break;
          case YAF_P0F_FLOW_TID:
            {
                md_flow->p0f = (yfP0fFlow_t *)FBSTMLNEXT(stml, md_flow->p0f);
            }
            break;
          case YAF_FPEXPORT_FLOW_TID:
            {
                md_flow->fp =(yfFPExportFlow_t *)FBSTMLNEXT(stml, md_flow->fp);
            }
            break;
          case YAF_MPTCP_FLOW_TID:
            {
                md_flow->mptcp = (yfMPTCPFlow_t *)FBSTMLNEXT(stml, md_flow->mptcp);
            }
            break;
          case YAF_HTTP_FLOW_TID:
          case YAF_FTP_FLOW_TID:
          case YAF_IMAP_FLOW_TID:
          case YAF_SIP_FLOW_TID:
          case YAF_SMTP_FLOW_TID:
          case YAF_SSH_FLOW_TID:
          case YAF_NNTP_FLOW_TID:
          case YAF_RTSP_FLOW_TID:
            md_flow->app = (void *)FBSTMLNEXT(stml, md_flow->app);
            md_flow->app_tid = stml->tmplID;
            md_flow->app_elements = fbTemplateCountElements(stml->tmpl);
            break;
          case YAF_POP3_FLOW_TID:
          case YAF_IRC_FLOW_TID:
          case YAF_TFTP_FLOW_TID:
          case YAF_SLP_FLOW_TID:
          case YAF_SSL_FLOW_TID:
          case YAF_NEW_SSL_FLOW_TID:
          case SM_INTSSL_FLOW_TID:
          case YAF_MYSQL_FLOW_TID:
          case YAF_DNP3_FLOW_TID:
          case YAF_MODBUS_FLOW_TID:
          case YAF_ENIP_FLOW_TID:
          case YAF_RTP_FLOW_TID:
            md_flow->app = (void *)FBSTMLNEXT(stml, md_flow->app);
            md_flow->app_tid = stml->tmplID;
            md_flow->cert = (fbSubTemplateMultiListEntry_t *)stml;
            break;
          case YAF_SSL_CERT_FLOW_TID:
            md_flow->cert = (fbSubTemplateMultiListEntry_t *)stml;
            break;
          case YAF_DNS_FLOW_TID:
            {
                yfDNSFlow_t *dnsflow = NULL;
                yfDNSQRFlow_t *dnsqrflow = NULL;
                md_flow->app = (void *)FBSTMLNEXT(stml, md_flow->app);
                md_flow->app_tid = stml->tmplID;
                dnsflow = (yfDNSFlow_t *)md_flow->app;
                dnsqrflow = FBSTLNEXT(&(dnsflow->dnsQRList), dnsqrflow);
                if (dnsqrflow) {
                    if (dnsqrflow->dnsQueryResponse || dnsqrflow->dnsNXDomain) {
                        /* if the first one is a response & it's UDP_FORCE,
                           reversify flow key hash */
                        if (md_flow->rec->flowEndReason == UDP_FORCE) {
                            md_flow->rec->flowKeyHash = md_util_rev_flow_key_hash(md_flow->rec);
                        }
                    }
                    ctx->stats->dns++;
                }
                if (md_flow->rec->flowEndReason == UDP_FORCE) {
                    ctx->stats->uniflows++;
                }
            }
            break;
          case YAF_DHCP_FLOW_TID:
          case YAF_DHCP_OP_TID:
            md_flow->dhcpfp = NULL;
            /*md_flow->dhcpfp = (yfDHCP_FP_Flow_t *)FBSTMLNEXT(stml, md_flow->dhcpfp);*/
            md_flow->dhcpfp = (fbSubTemplateMultiListEntry_t *)stml;
            md_flow->app_tid = stml->tmplID;
            break;
          case YAF_STATS_FLOW_TID:
            md_flow->stats = NULL;
            md_flow->stats = (yfFlowStatsRecord_t *)FBSTMLNEXT(stml,
                                                               md_flow->stats);
            break;
          case YAF_FULL_CERT_TID:
            {
                int i = 0;
                fbVarfield_t *ct = NULL;

                if (!sm_sub_ssl_tmpl) {
                    fbInfoModel_t *model = mdInfoModel();
                    sm_sub_ssl_tmpl = fbTemplateAlloc(model);
                    if (!fbTemplateAppendSpecArray(sm_sub_ssl_tmpl,
                                                   yaf_subssl_spec, 0xffffffff, &(ctx->err))) {
                        g_warning("error creating template for ssl cert decode %s", ctx->err->message);
                        break;
                    }
                }

                md_flow->fullcert = NULL;
                md_flow->fullcert = (yfSSLFullCert_t *)FBSTMLNEXT(stml, md_flow->fullcert);
                md_flow->sslcerts = g_new0(yfNewSSLCertFlow_t*,
                                           (md_flow->fullcert->cert.numElements+1));
                if (md_flow->app_tid == 0) {
                    md_flow->app_tid = stml->tmplID;
                }
                while ((ct = (fbVarfield_t *)fbBasicListGetNextPtr(&(md_flow->fullcert->cert), ct))) {
                    md_flow->sslcerts[i] = md_ssl_cert_decode(ct->buf, ct->len, sm_sub_ssl_tmpl);
                    i++;
                }
                break;
            }
          default:
            g_debug("Received Unknown Template ID %02x in STML", stml->tmplID);
            break;
        }
    }
}


/**
 * mdCleanUP
 *
 * clean up after the messy dynamic lists...
 *
 */
void mdCleanUP(
    mdFullFlow_t  *md_flow)
{
    fbBasicList_t *bl = NULL;
    int           loop;

    switch (md_flow->app_tid & YTF_BIF) {
      case YAF_HTTP_FLOW_TID:
      case YAF_IMAP_FLOW_TID:
      case YAF_SSH_FLOW_TID:
      case YAF_RTSP_FLOW_TID:
      case YAF_SMTP_FLOW_TID:
      case YAF_SIP_FLOW_TID:
      case YAF_FTP_FLOW_TID:
      case YAF_NNTP_FLOW_TID:
        bl = (fbBasicList_t *)md_flow->app;
        for (loop = 0; loop < md_flow->app_elements; loop++) {
            fbBasicListClear(bl);
            bl++;
        }
        break;
      case YAF_POP3_FLOW_TID:
        {
            yfPOP3Flow_t *rec = (yfPOP3Flow_t *)md_flow->app;
            fbBasicListClear(&(rec->pop3msg));
            break;
        }
      case YAF_MODBUS_FLOW_TID:
        {
            yfModbusFlow_t *rec = (yfModbusFlow_t *)md_flow->app;
            fbBasicListClear(&(rec->mbmsg));
            break;
        }
      case YAF_ENIP_FLOW_TID:
        {
            yfEnIPFlow_t *rec = (yfEnIPFlow_t *)md_flow->app;
            fbBasicListClear(&(rec->enipmsg));
            break;
        }
      case YAF_IRC_FLOW_TID:
        {
            yfIRCFlow_t *rec = (yfIRCFlow_t *)md_flow->app;
            fbBasicListClear(&(rec->ircMsg));
            break;
        }
      case YAF_SLP_FLOW_TID:
        {
            yfSLPFlow_t *rec = (yfSLPFlow_t *)md_flow->app;
            fbBasicListClear(&(rec->slpString));
            break;
        }
      case YAF_SSL_FLOW_TID:
        {
            yfSSLFlow_t *rec = (yfSSLFlow_t *)md_flow->app;
            fbBasicListClear(&(rec->sslCipherList));
            break;
        }
      case SM_INTSSL_FLOW_TID:
        {
            yfNewSSLFlow_t *rec = (yfNewSSLFlow_t *)md_flow->app;
            yfNewSSLCertFlow_t *cert = NULL;
            while ((cert = fbSubTemplateListGetNextPtr(&(rec->sslCertList),
                                                       cert)))
            {
                fbSubTemplateListClear(&(cert->issuer));
                fbSubTemplateListClear(&(cert->subject));
                fbSubTemplateListClear(&(cert->extension));
            }
            fbSubTemplateListClear(&(rec->sslCertList));
            fbBasicListClear(&(rec->sslCipherList));
        }
        break;
      case YAF_MYSQL_FLOW_TID:
        {
            yfMySQLFlow_t *rec = (yfMySQLFlow_t *)md_flow->app;
            fbSubTemplateListClear(&(rec->mysqlList));
            break;
        }
      case YAF_DNS_FLOW_TID:
        {
            yfDNSFlow_t *rec = (yfDNSFlow_t *)md_flow->app;
            yfDNSQRFlow_t *dns = NULL;
            while ((dns = fbSubTemplateListGetNextPtr(&(rec->dnsQRList), dns))) {
                fbSubTemplateListClear(&(dns->dnsRRList));
            }

            fbSubTemplateListClear(&(rec->dnsQRList));
            break;
        }
      case YAF_DHCP_OP_TID:
        {
            yfDHCP_OP_Flow_t *dhcp = NULL;
            dhcp = (yfDHCP_OP_Flow_t*)FBSTMLNEXT(md_flow->dhcpfp, dhcp);
            fbBasicListClear(&(dhcp->options));
            if (md_flow->app_tid & YTF_REV) {
                fbBasicListClear(&(dhcp->revOptions));
            }
            break;
        }
      default:
        break;
    }

    if (md_flow->fullcert) {
        yfNewSSLCertFlow_t *cert;
        int i = 0;
        while ((cert = md_flow->sslcerts[i])) {
            fbSubTemplateListClear(&(cert->issuer));
            fbSubTemplateListClear(&(cert->subject));
            fbSubTemplateListClear(&(cert->extension));
            g_slice_free(yfNewSSLCertFlow_t, cert);
            i++;
        }
        g_free(md_flow->sslcerts);
        fbBasicListClear(&(md_flow->fullcert->cert));
    }

}

void mdCleanUpSSLCert(
    yfNewSSLCertFlow_t *cert)
{
    fbSubTemplateListClear(&(cert->issuer));
    fbSubTemplateListClear(&(cert->subject));
    fbSubTemplateListClear(&(cert->extension));
}


/**
 * mdCreateFieldList
 *
 * add custom field to field list
 *
 */
mdFieldList_t *mdCreateFieldList(
    mdAcceptFilterField_t    field)
{
    mdFieldList_t *item = NULL;

    item = mdNewFieldList();

    item->field = field;

    switch (field) {
      case FLOWKEYHASH:
        item->print_fn = mdPrintFlowKeyHash;
        break;
      case SIP_ANY:
        item->print_fn = mdPrintSIP;
        break;
      case DIP_ANY:
        item->print_fn = mdPrintDIP;
        break;
      case SIP_INT:
        item->print_fn = mdPrintSIPINT;
        break;
      case DIP_INT:
        item->print_fn = mdPrintDIPINT;
        break;
      case STIMEMS:
        item->print_fn = mdPrintSTIMEMS;

        break;
      case ETIMEMS:
        item->print_fn = mdPrintETIMEMS;
        break;
      case SPORT:
        item->print_fn = mdPrintSPort;
        break;
      case DPORT:
        item->print_fn = mdPrintDPort;
        break;
      case PROTOCOL:
        item->print_fn = mdPrintProto;
        break;
      case APPLICATION:
        item->print_fn = mdPrintApp;
        break;
      case OBDOMAIN:
        item->print_fn = mdPrintOBDomain;
        break;
      case VLAN:
        item->print_fn = mdPrintVLAN;
        break;
      case VLANINT:
        item->print_fn = mdPrintVLANINT;
        break;
      case DURATION:
        item->print_fn = mdPrintDuration;
        break;
      case STIME:
        item->print_fn = mdPrintSTIME;
        break;
      case ENDTIME:
        item->print_fn = mdPrintETIME;
        break;
      case RTT:
        item->print_fn = mdPrintRTT;
        break;
      case PKTS:
        item->print_fn = mdPrintPackets;
        break;
      case RPKTS:
        item->print_fn = mdPrintRPackets;
        break;
      case BYTES:
        item->print_fn = mdPrintBytes;
        break;
      case RBYTES:
        item->print_fn = mdPrintRBytes;
        break;
      case IFLAGS:
        item->print_fn = mdPrintIFlags;
        break;
      case RIFLAGS:
        item->print_fn = mdPrintRIFlags;
        break;
      case UFLAGS:
        item->print_fn = mdPrintUFlags;
        break;
      case RUFLAGS:
        item->print_fn = mdPrintRUFlags;
        break;
      case ATTRIBUTES:
        item->print_fn = mdPrintAttributes;
        break;
      case RATTRIBUTES:
        item->print_fn = mdPrintRAttributes;
        break;
      case MAC:
        item->print_fn = mdPrintMAC;
        break;
      case DSTMAC:
        item->print_fn = mdPrintDSTMAC;
        break;
      case TCPSEQ:
        item->print_fn = mdPrintTCPSeq;
        break;
      case RTCPSEQ:
        item->print_fn = mdPrintRTCPSeq;
        break;
      case ENTROPY:
        item->print_fn = mdPrintEntropy;
        break;
      case RENTROPY:
        item->print_fn = mdPrintREntropy;
        break;
      case END:
        item->print_fn = mdPrintEnd;
        break;
      case DHCPFP:
        item->print_fn = mdPrintDHCPFP;
        break;
      case RDHCPFP:
        item->print_fn = mdPrintRDHCPFP;
        break;
      case DHCPVC:
        item->print_fn = mdPrintDHCPVC;
        break;
      case RDHCPVC:
        item->print_fn = mdPrintRDHCPVC;
        break;
      case OSNAME:
        item->print_fn = mdPrintOSNAME;
        break;
      case OSVERSION:
        item->print_fn = mdPrintOSVersion;
        break;
      case ROSNAME:
        item->print_fn = mdPrintROSNAME;
        break;
      case ROSVERSION:
        item->print_fn = mdPrintROSVersion;
        break;
      case FINGERPRINT:
        item->print_fn = mdPrintOSFingerprint;
        break;
      case RFINGERPRINT:
        item->print_fn = mdPrintROSFingerprint;
        break;
      case INGRESS:
        item->print_fn = mdPrintIngress;
        break;
      case EGRESS:
        item->print_fn = mdPrintEgress;
        break;
      case DATABYTES:
        item->print_fn = mdPrintDataBytes;
        break;
      case RDATABYTES:
        item->print_fn = mdPrintRDataBytes;
        break;
      case ITIME:
        item->print_fn = mdPrintITime;
        break;
      case RITIME:
        item->print_fn = mdPrintRITime;
        break;
      case STDITIME:
        item->print_fn = mdPrintSTDITime;
        break;
      case RSTDITIME:
        item->print_fn = mdPrintRSTDITime;
        break;
      case TCPURG:
        item->print_fn = mdPrintTCPURG;
        break;
      case RTCPURG:
        item->print_fn = mdPrintRTCPURG;
        break;
      case SMALLPKTS:
        item->print_fn = mdPrintSmallPkts;

        break;
      case RSMALLPKTS:
        item->print_fn = mdPrintRSmallPkts;
        break;
      case LARGEPKTS:
        item->print_fn = mdPrintLargePkts;
        break;
      case RLARGEPKTS:
        item->print_fn = mdPrintRLargePkts;
        break;
      case NONEMPTYPKTS:
        item->print_fn = mdPrintNonEmptyPkts;
        break;
      case RNONEMPTYPKTS:
        item->print_fn = mdPrintRNonEmptyPkts;
        break;
      case MAXSIZE:
        item->print_fn = mdPrintMaxPacketSize;
        break;
      case RMAXSIZE:
        item->print_fn = mdPrintRMaxPacketSize;
        break;
      case STDPAYLEN:
        item->print_fn = mdPrintSTDPayLen;
        break;
      case RSTDPAYLEN:
        item->print_fn = mdPrintRSTDPayLen;
        break;
      case FIRSTEIGHT:
        item->print_fn = mdPrintFirstEight;
        break;
      case TOS:
        item->print_fn = mdPrintTOS;
        break;
      case RTOS:
        item->print_fn = mdPrintRTOS;
        break;
      case MPLS1:
        item->print_fn = mdPrintMPLS1;
        break;
      case MPLS2:
        item->print_fn = mdPrintMPLS2;
        break;
      case MPLS3:
        item->print_fn = mdPrintMPLS3;
        break;
      case COLLECTOR:
        item->print_fn = mdPrintCollectorName;
        break;
      case FIRSTNONEMPTY:
        item->print_fn = mdPrintFirstNonEmpty;
        break;
      case RFIRSTNONEMPTY:
        item->print_fn = mdPrintRFirstNonEmpty;
        break;
      case MPTCPSEQ:
        item->print_fn = mdPrintMPTCPSeq;
        break;
      case MPTCPTOKEN:
        item->print_fn = mdPrintMPTCPToken;
        break;
      case MPTCPMSS:
        item->print_fn = mdPrintMPTCPMss;
        break;
      case MPTCPID:
        item->print_fn = mdPrintMPTCPId;
        break;
      case MPTCPFLAGS:
        item->print_fn = mdPrintMPTCPFlags;
        break;
      case NONE_FIELD:
        item->print_fn = mdPrintNone;
        break;
      case PAYLOAD:
        item->print_fn = mdPrintPayload;
        break;
      case RPAYLOAD:
        item->print_fn = mdPrintRPayload;
        break;
      case DHCPOPTIONS:
        item->print_fn = mdPrintDHCPOptions;
        break;
      case RDHCPOPTIONS:
        item->print_fn = mdPrintRevDHCPOptions;
        break;
      case NDPI_MASTER:
        item->print_fn = mdPrintNDPIMaster;
        break;
      case NDPI_SUB:
        item->print_fn = mdPrintNDPISub;
        break;
      default:
        return NULL;
    }

    return item;
}



/**
 * mdSetFieldListDecorator
 *
 * create custom printer for CSV
 *
 */
void mdSetFieldListDecoratorCustom(
    mdFieldList_t *list,
    char          delimiter)

{
    mdFieldList_t *item = NULL;

    for (item = list; item; item = item->next) {
        if (item->decorator) {
            /* decorator already set */
            return;
        }
        switch (item->field) {
          case FLOWKEYHASH:
            item->decorator = g_string_new("%u");
            break;
          case SIP_ANY:
            item->decorator = g_string_new("%s");
            break;
          case DIP_ANY:
            item->decorator = g_string_new("%s");
            break;
          case SIP_INT:
            item->decorator = g_string_new("%u");
            break;
          case DIP_INT:
            item->decorator = g_string_new("%u");
            break;
          case STIMEMS:
            item->decorator = g_string_new("%"PRIu64"");
            break;
          case ETIMEMS:
            item->decorator = g_string_new("%"PRIu64"");
            break;
          case SPORT:
            item->decorator = g_string_new("%d");
            break;
          case DPORT:
            item->decorator = g_string_new("%d");
            break;
          case PROTOCOL:
            item->decorator = g_string_new("%d");
            break;
          case NDPI_MASTER:
          case NDPI_SUB:
          case APPLICATION:
            item->decorator = g_string_new("%d");
            break;
          case OBDOMAIN:
            item->decorator = g_string_new("%u");
            break;
          case VLAN:
            item->decorator = g_string_new("%03x");
            break;
          case VLANINT:
            item->decorator = g_string_new("%u");
            break;
          case DURATION:
            item->decorator = g_string_new("%.3f");
            break;
          case STIME:
            item->decorator = g_string_new("%s");
            break;
          case ENDTIME:
            item->decorator = g_string_new("%s");
            break;
          case RTT:
            item->decorator =   g_string_new("%.3f");
            break;
          case PKTS:
            item->decorator = g_string_new("%"PRIu64"");
            break;
          case RPKTS:
            item->decorator =  g_string_new("%"PRIu64"");
            break;
          case BYTES:
            item->decorator = g_string_new("%"PRIu64"");
            break;
          case RBYTES:
            item->decorator =  g_string_new("%"PRIu64"");
            break;
          case IFLAGS:
            item->decorator = g_string_new("%s");
            break;
          case RIFLAGS:
            item->decorator = g_string_new("%s");
            break;
          case UFLAGS:
            item->decorator = g_string_new("%s");
            break;
          case RUFLAGS:
            item->decorator = g_string_new("%s");
            break;
          case ATTRIBUTES:
            item->decorator = g_string_new("%02x");
            break;
          case RATTRIBUTES:
            item->decorator =  g_string_new("%02x");
            break;
          case MAC:
            item->decorator =  g_string_new("%s");
            break;
          case DSTMAC:
            item->decorator =  g_string_new("%s");
            break;
          case TCPSEQ:
            item->decorator = g_string_new("%08x");
            break;
          case RTCPSEQ:
            item->decorator = g_string_new("%08x");
            break;
          case ENTROPY:
            item->decorator =  g_string_new("%u");
            break;
          case RENTROPY:
            item->decorator = g_string_new("%u");
            break;
          case END:
            item->decorator = g_string_new("%s");
            break;
          case DHCPFP:
            item->decorator = g_string_new("%s");
            break;
          case RDHCPFP:
            item->decorator = g_string_new("%s");
            break;
          case DHCPVC:
            item->decorator = g_string_new("%s");
            break;
          case RDHCPVC:
            item->decorator = g_string_new("%s");
            break;
          case DHCPOPTIONS:
            item->decorator = g_string_new("%s");
            break;
          case RDHCPOPTIONS:
            item->decorator = g_string_new("%s");
            break;
          case OSNAME:
            item->decorator = g_string_new("%s");
            break;
          case OSVERSION:
            item->decorator = g_string_new("%s");
            break;
          case ROSNAME:
            item->decorator = g_string_new("%s");
            break;
          case ROSVERSION:
            item->decorator = g_string_new("%s");
            break;
          case FINGERPRINT:
            item->decorator = g_string_new("%s");
            break;
          case RFINGERPRINT:
            item->decorator = g_string_new("%s");
            break;
          case INGRESS:
            item->decorator = g_string_new("%u");
            break;
          case EGRESS:
            item->decorator = g_string_new("%u");
            break;
          case DATABYTES:
            item->decorator = g_string_new("%"PRIu64"");
            break;
          case RDATABYTES:
            item->decorator = g_string_new("%"PRIu64"");
            break;
          case ITIME:
            item->decorator = g_string_new("%.3f");
            break;
          case RITIME:
            item->decorator = g_string_new("%.3f");
            break;
          case STDITIME:
            item->decorator = g_string_new("%.3f");
            break;
          case RSTDITIME:
            item->decorator = g_string_new("%.3f");
            break;
          case TCPURG:
            item->decorator = g_string_new("%u");
            break;
          case RTCPURG:
            item->decorator = g_string_new("%u");
            break;
          case SMALLPKTS:
            item->decorator = g_string_new("%u");
            break;
          case RSMALLPKTS:
            item->decorator = g_string_new("%u");
            break;
          case LARGEPKTS:
            item->decorator = g_string_new("%u");
            break;
          case RLARGEPKTS:
            item->decorator = g_string_new("%u");
            break;
          case NONEMPTYPKTS:
            item->decorator = g_string_new("%u");
            break;
          case RNONEMPTYPKTS:
            item->decorator = g_string_new("%u");
            break;
          case MAXSIZE:
            item->decorator = g_string_new("%d");
            break;
          case RMAXSIZE:
            item->decorator = g_string_new("%d");
            break;
          case STDPAYLEN:
            item->decorator = g_string_new("%d");
            break;
          case RSTDPAYLEN:
            item->decorator = g_string_new("%d");
            break;
          case FIRSTEIGHT:
            item->decorator = g_string_new("%02x");
            break;
          case TOS:
            item->decorator = g_string_new("%02x");
            break;
          case RTOS:
            item->decorator = g_string_new("%02x");
            break;
          case MPLS1:
            item->decorator = g_string_new("%d");
            break;
          case MPLS2:
            item->decorator = g_string_new("%d");
            break;
          case MPLS3:
            item->decorator = g_string_new("%d");
            break;
          case COLLECTOR:
            item->decorator = g_string_new("%s");
            break;
          case FIRSTNONEMPTY:
            item->decorator = g_string_new("%d");
            break;
          case RFIRSTNONEMPTY:
            item->decorator = g_string_new("%d");
            break;
          case MPTCPSEQ:
            item->decorator = g_string_new("%"PRIu64"");
            break;
          case MPTCPTOKEN:
            item->decorator = g_string_new("%u");
            break;
          case MPTCPMSS:
            item->decorator = g_string_new("%d");
            break;
          case MPTCPID:
            item->decorator = g_string_new("%d");
            break;
          case MPTCPFLAGS:
            item->decorator = g_string_new("%02x");
            break;
          case NONE_FIELD:
            item->decorator = g_string_new("");
            break;
          case PAYLOAD:
          case RPAYLOAD:
            item->decorator = g_string_new("");
            break;
          default:
            return;
        }

        g_string_append_c(item->decorator, delimiter);
    }

}

/**
 * mdSetFieldListDecoratorJSON
 *
 * create the custom printer for JSON
 *
 */
void mdSetFieldListDecoratorJSON(
    mdFieldList_t *list)

{
    mdFieldList_t *item = NULL;

    for (item = list; item; item = item->next) {
        if (item->decorator) {
            /* decorator already set */
            return;
        }
        switch (item->field) {
          case FLOWKEYHASH:
            item->decorator = g_string_new("\"flowKeyHash\":%u,");
            break;
          case SIP_ANY:
            item->decorator = g_string_new("\"sourceIPv4Address\":\"%s\",");
            break;
          case DIP_ANY:
            item->decorator = g_string_new("\"destinationIPv4Address\":\"%s\",");
            break;
          case SIP_INT:
            item->decorator = g_string_new("\"sourceIPv4Address\":%u,");
            break;
          case DIP_INT:
            item->decorator = g_string_new("\"destinationIPv4Address\":%u,");
            break;
          case STIMEMS:
            item->decorator = g_string_new("\"flowStartMilliseconds\":\"%"PRIu64"\",");
            break;
          case ETIMEMS:
            item->decorator = g_string_new("\"flowEndMilliseconds\":\"%"PRIu64"\",");
            break;
          case SPORT:
            item->decorator = g_string_new("\"sourceTransportPort\":%d,");
            break;
          case DPORT:
            item->decorator = g_string_new("\"destinationTransportPort\":%d,");
            break;
          case PROTOCOL:
            item->decorator = g_string_new("\"protocolIdentifier\":%d,");
            break;
          case APPLICATION:
            item->decorator = g_string_new("\"numAppLabel\":%d,");
            break;
          case OBDOMAIN:
            item->decorator = g_string_new("\"observationDomainId\":%u,");
            break;
          case VLAN:
            item->decorator = g_string_new("\"vlanId\":\"0x%03x\",");
            break;
          case VLANINT:
            item->decorator = g_string_new("\"vlanId\":%u,");
            break;
          case DURATION:
            item->decorator = g_string_new("\"flowDurationMilliseconds\":%.3f,");
            break;
          case STIME:
            item->decorator = g_string_new("\"flowStartMilliseconds\":\"%s\",");
            break;
          case ENDTIME:
            item->decorator = g_string_new("\"flowEndMilliseconds\":\"%s\",");
            break;
          case RTT:
            item->decorator =  g_string_new("\"reverseFlowDeltaMilliseconds\":%.3f,");
            break;
          case PKTS:
            item->decorator = g_string_new("\"packetTotalCount\":%"PRIu64",");
            break;
          case RPKTS:
            item->decorator =  g_string_new("\"reversePacketTotalCount\":%"PRIu64",");
            break;
          case BYTES:
            item->decorator = g_string_new("\"octetTotalCount\":%"PRIu64",");
            break;
          case RBYTES:
            item->decorator =  g_string_new("\"reverseOctetTotalCount\":%"PRIu64",");
            break;
          case IFLAGS:
            item->decorator = g_string_new("\"initialTCPFlags\":\"%s\",");
            break;
          case RIFLAGS:
            item->decorator = g_string_new("\"reverseInitialTCPFlags\":\"%s\",");
            break;
          case UFLAGS:
            item->decorator = g_string_new("\"unionTCPFlags\":\"%s\",");
            break;
          case RUFLAGS:
            item->decorator = g_string_new("\"reverseUnionTCPFlags\":\"%s\",");
            break;
          case ATTRIBUTES:
            item->decorator = g_string_new("\"flowAttributes\":\"%02x\",");
            break;
          case RATTRIBUTES:
            item->decorator =  g_string_new("\"reverseFlowAttributes\":\"%02x\",");
            break;
          case MAC:
            item->decorator =  g_string_new("\"sourceMacAddress\":\"%s\",");
            break;
          case DSTMAC:
            item->decorator =  g_string_new("\"destinationMacAddress\":\"%s\",");
            break;
          case TCPSEQ:
            item->decorator = g_string_new("\"tcpSequenceNumber\":\"0x%08x\",");
            break;
          case RTCPSEQ:
            item->decorator = g_string_new("\"reverseTcpSequenceNumber\":\"0x%08x\",");
            break;
          case ENTROPY:
            item->decorator =  g_string_new("\"payloadEntropy\":%u,");
            break;
          case RENTROPY:
            item->decorator = g_string_new("\"reversePayloadEntropy\":%u,");
            break;
          case END:
            item->decorator = g_string_new("\"flowEndReason\":\"%s\",");
            break;
          case DHCPFP:
            item->decorator = g_string_new("\"dhcpFingerPrint\":\"%s\",");
            break;
          case RDHCPFP:
            item->decorator = g_string_new("\"reverseDhcpFingerPrint\":\"%s\",");
            break;
          case DHCPVC:
            item->decorator = g_string_new("\"dhcpVendorCode\":\"%s\",");
            break;
          case RDHCPVC:
            item->decorator = g_string_new("\"reverseDhcpVendorCode\":\"%s\",");
            break;
          case DHCPOPTIONS:
            item->decorator = g_string_new("\"dhcpOptionsList\":[%s],");
            break;
          case RDHCPOPTIONS:
            item->decorator = g_string_new("\"reverseDhcpOptionsList\":[%s],");
            break;
          case OSNAME:
            item->decorator = g_string_new("\"osName\":\"%s\",");
            break;
          case OSVERSION:
            item->decorator = g_string_new("\"osVersion\":\"%s\",");
            break;
          case ROSNAME:
            item->decorator = g_string_new("\"reverseOsName\":\"%s\",");
            break;
          case ROSVERSION:
            item->decorator = g_string_new("\"reverseOsVersion\":\"%s\",");
            break;
          case FINGERPRINT:
            item->decorator = g_string_new("\"osFingerPrint\":\"%s\",");
            break;
          case RFINGERPRINT:
            item->decorator = g_string_new("\"reverseOsFingerPrint\":\"%s\",");
            break;
          case INGRESS:
            item->decorator = g_string_new("\"ingressInterface\":%u,");
            break;
          case EGRESS:
            item->decorator = g_string_new("\"egressInterface\":%u,");
            break;
          case DATABYTES:
            item->decorator = g_string_new("\"dataByteCount\":%"PRIu64",");
            break;
          case RDATABYTES:
            item->decorator = g_string_new("\"reverseDataByteCount\":%"PRIu64",");
            break;
          case ITIME:
            item->decorator = g_string_new("\"averageInterarrivalTime\":%.3f,");
            break;
          case RITIME:
            item->decorator = g_string_new("\"reverseAverageInterArrivalTime\":%.3f,");
            break;
          case STDITIME:
            item->decorator = g_string_new("\"standardDeviationInterarrivalTime\":%.3f,");
            break;
          case RSTDITIME:
            item->decorator = g_string_new("\"reverseStandardDeviationInterarrivalTime\":%.3f,");
            break;
          case TCPURG:
            item->decorator = g_string_new("\"tcpUrgentCount\":%u,");
            break;
          case RTCPURG:
            item->decorator = g_string_new("\"reverseTcpUrgentCount\":%u,");
            break;
          case SMALLPKTS:
            item->decorator = g_string_new("\"smallPacketCount\":%u,");
            break;
          case RSMALLPKTS:
            item->decorator = g_string_new("\"reverseSmallPacketCount\":%u,");
            break;
          case LARGEPKTS:
            item->decorator = g_string_new("\"largePacketCount\":%u,");
            break;
          case RLARGEPKTS:
            item->decorator = g_string_new("\"reverseLargePacketCount\":%u,");
            break;
          case NONEMPTYPKTS:
            item->decorator = g_string_new("\"nonEmptyPacketCount\":%u,");
            break;
          case RNONEMPTYPKTS:
            item->decorator = g_string_new("\"reverseNonEmptyPacketCount\":%u,");
            break;
          case MAXSIZE:
            item->decorator = g_string_new("\"maxPacketSize\":%d,");
            break;
          case RMAXSIZE:
            item->decorator = g_string_new("\"reverseMaxPacketSize\":%d,");
            break;
          case STDPAYLEN:
            item->decorator = g_string_new("\"standardDeviationPayloadLength\":%d,");
            break;
          case RSTDPAYLEN:
            item->decorator = g_string_new("\"reverseStandardDeviationPayloadLength\":%d,");
            break;
          case FIRSTEIGHT:
            item->decorator = g_string_new("\"firstEightNonEmptyPacketDirections\":\"%02x\",");
            break;
          case TOS:
            item->decorator = g_string_new("\"ipClassOfService\":\"0x%02x\",");
            break;
          case RTOS:
            item->decorator = g_string_new("\"reverseIpClassOfService\":\"0x%02x\",");
            break;
          case MPLS1:
            item->decorator = g_string_new("\"mplsTopLabelStackSection\":%d,");
            break;
          case MPLS2:
            item->decorator = g_string_new("\"mplsTopLabelStackSection2\":%d,");
            break;
          case MPLS3:
            item->decorator = g_string_new("\"mplsTopLabelStackSection3\":%d,");
            break;
          case COLLECTOR:
            item->decorator = g_string_new("\"collectorName\":\"%s\",");
            break;
          case FIRSTNONEMPTY:
            item->decorator = g_string_new("\"firstNonEmptyPacketSize\":%d,");
            break;
          case RFIRSTNONEMPTY:
            item->decorator = g_string_new("\"reverseFirstNonEmptyPacketSize\":%d,");
            break;
          case MPTCPSEQ:
            item->decorator = g_string_new("\"mptcpInitialDataSequenceNumber\":%"PRIu64",");
            break;
          case MPTCPTOKEN:
            item->decorator = g_string_new("\"mptcpReceiverToken\":%u,");
            break;
          case MPTCPMSS:
            item->decorator = g_string_new("\"mptcpMaximumSegmentSize\":%d,");
            break;
          case MPTCPID:
            item->decorator = g_string_new("\"mptcpAddressID\":%d,");
            break;
          case MPTCPFLAGS:
            item->decorator = g_string_new("\"mptcpFlags\":\"%02x\",");
            break;
          case PAYLOAD:
            item->print_fn = mdPrintPayloadJSON;
            item->decorator = g_string_new("\"payload\":\"%s\",");
            break;
          case RPAYLOAD:
            item->print_fn = mdPrintRPayloadJSON;
            item->decorator = g_string_new("\"reversePayload\":\"%s\",");
            break;
          case NDPI_MASTER:
            item->decorator = g_string_new("\"nDPIL7Protocol\":%d,");
            break;
          case NDPI_SUB:
            item->decorator = g_string_new("\"nDPIL7SubProtocol\":%d,");
            break;
          case NONE_FIELD:
            item->decorator = NULL;
            break;
          default:
            break;
        }
    }
}


/**
 * mdSetFieldListDecoratorBasic
 *
 * create basic printer for CSV
 *
 */
void mdSetFieldListDecoratorBasic(
    mdFieldList_t *list,
    char          delimiter)

{
    mdFieldList_t *item = NULL;


    for (item = list; item; item = item->next) {
        if (item->decorator) {
            /* decorator already set */
            return;
        }
        switch (item->field) {
          case SIP_ANY:
            item->decorator = g_string_new("%40s");
            break;
          case DIP_ANY:
            item->decorator = g_string_new("%40s");
            break;
          case SPORT:
            item->decorator = g_string_new("%5d");
            break;
          case DPORT:
            item->decorator = g_string_new("%5d");
            break;
          case PROTOCOL:
            item->decorator = g_string_new("%3d");
            break;
          case NDPI_MASTER:
          case NDPI_SUB:
          case APPLICATION:
            item->decorator = g_string_new("%5d");
            break;
          case VLAN:
            item->decorator = g_string_new("%03x");
            break;
          case DURATION:
            item->decorator = g_string_new("%8.3f");
            break;
          case STIME:
            item->decorator = g_string_new("%s");
            break;
          case ENDTIME:
            item->decorator = g_string_new("%s");
            break;
          case RTT:
            item->decorator =   g_string_new("%8.3f");
            break;
          case PKTS:
            item->decorator = g_string_new("%8"PRIu64"");
            break;
          case RPKTS:
            item->decorator =  g_string_new("%8"PRIu64"");
            break;
          case BYTES:
            item->decorator = g_string_new("%8"PRIu64"");
            break;
          case RBYTES:
            item->decorator =  g_string_new("%8"PRIu64"");
            break;
          case IFLAGS:
            item->decorator = g_string_new("%8s");
            break;
          case RIFLAGS:
            item->decorator = g_string_new("%8s");
            break;
          case UFLAGS:
            item->decorator = g_string_new("%8s");
            break;
          case RUFLAGS:
            item->decorator = g_string_new("%8s");
            break;
          case ATTRIBUTES:
            item->decorator = g_string_new("%02x");
            break;
          case RATTRIBUTES:
            item->decorator =  g_string_new("%02x");
            break;
          case MAC:
            item->decorator =  g_string_new("%s");
            break;
          case DSTMAC:
            item->decorator =  g_string_new("%s");
            break;
          case TCPSEQ:
            item->decorator = g_string_new("%08x");
            break;
          case RTCPSEQ:
            item->decorator = g_string_new("%08x");
            break;
          case ENTROPY:
            item->decorator =  g_string_new("%3u");
            break;
          case RENTROPY:
            item->decorator = g_string_new("%3u");
            break;
          case END:
            item->decorator = g_string_new("%6s");
            break;
          case INGRESS:
            item->decorator = g_string_new("%5u");
            break;
          case EGRESS:
            item->decorator = g_string_new("%5u");
            break;
          case TOS:
            item->decorator = g_string_new(" %02x");
            break;
          case RTOS:
            item->decorator = g_string_new("%02x");
            break;
          case COLLECTOR:
            /* collector is last field so no delimiter, add newline */
            item->decorator = g_string_new("%s\n");
            continue;
          case PAYLOAD:
          case RPAYLOAD:
            item->decorator = g_string_new("");
            continue;
          default:
            g_warning("Invalid field for Basic Flow Print.");
            break;
        }

        g_string_append_c(item->decorator, delimiter);
    }

}


mdFieldList_t *mdCreateBasicFlowList(
    gboolean payload)
{
    mdFieldList_t *start = NULL;
    mdFieldList_t *item = NULL;
    mdFieldList_t *cur = NULL;

    start = mdCreateFieldList(STIME);
    cur = start;
    item = mdCreateFieldList(ENDTIME);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(DURATION);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(RTT);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(PROTOCOL);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(SIP_ANY);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(SPORT);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(PKTS);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(BYTES);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(ATTRIBUTES);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(MAC);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(DIP_ANY);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(DPORT);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(RPKTS);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(RBYTES);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(RATTRIBUTES);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(DSTMAC);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(IFLAGS);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(UFLAGS);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(RIFLAGS);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(RUFLAGS);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(TCPSEQ);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(RTCPSEQ);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(INGRESS);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(EGRESS);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(VLAN);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(APPLICATION);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(TOS);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(END);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(COLLECTOR);
    cur->next = item;
    cur = item;
    if (payload) {
        item = mdCreateFieldList(PAYLOAD);
        cur->next = item;
        cur = item;
        item = mdCreateFieldList(RPAYLOAD);
        cur->next = item;
        cur = item;
    }

    return start;
}

mdFieldList_t *mdCreateIndexFlowList(
                                     )
{
    mdFieldList_t *start = NULL;
    mdFieldList_t *item = NULL;
    mdFieldList_t *cur = NULL;

    start = mdCreateFieldList(STIME);
    cur = start;
    item = mdCreateFieldList(PROTOCOL);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(SIP_ANY);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(SPORT);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(DIP_ANY);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(DPORT);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(VLAN);
    cur->next = item;
    cur = item;
    item = mdCreateFieldList(OBDOMAIN);
    cur->next = item;
    cur = item;

    return start;
}

/**
 *  Function: attachHeadToSLL
 *  Description: attach a new entry to the front of a singly linked list
 *  Params: **head - double pointer to the current head.  *head will point
 *                to that new element at the end of this function
 *          *newEntry - a pointer to the previously allocated entry to be added
 *  Return: NONE
 */
void attachHeadToSLL(
    mdSLL_t **head,
    mdSLL_t  *newEntry)
{
    assert(head);
    assert(newEntry);

    /*  works even if *head starts out null, being no elements attach
     *  the new entry to the head */
    newEntry->next = *head;
    /*  reassign the head pointer to the new entry */
    *head = newEntry;
}

/**
 *  Function: detachHeadOfSLL
 *  Description: remove the head entry from a singly linked list, set
 *      the head pointer to the next one in the list, and return the
 *      old head
 *  Params: **head - double pointer to the head node of the list.  After
 *                      this function, (*head) will point to the
 *                      new head (*(originalhead)->next)
 *          **toRemove - double pointer to use to return the old head
 *  Return: NONE
 */
void detachHeadOfSLL(
    mdSLL_t **head,
    mdSLL_t **toRemove)
{
    assert(toRemove);
    assert(head);
    assert(*head);

    /*  set the outgoing pointer to point to the head listing */
    *toRemove = *head;
    /*  move the head pointer down one */
    *head = (*head)->next;
}
