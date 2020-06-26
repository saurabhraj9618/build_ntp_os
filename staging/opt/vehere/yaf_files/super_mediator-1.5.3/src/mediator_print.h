/**
 * @file mediator_print.h
 *
 * header file for mediator_print.c
 *
 * -------------------------------------------------------------------------
 * Copyright (C) 2012-2017 Carnegie Mellon University. All Rights Reserved.
 * -------------------------------------------------------------------------
 * Authors: Emily Sarneso
 * -------------------------------------------------------------------------
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
 * University under this License, inluding, but not limited to, any
 * claims of product liability, personal injury, death, damage to
 * property, or violation of any laws or regulations.
 *
 * @OPENSOURCE_HEADER_END@
 * -----------------------------------------------------------
 */

#include <stdint.h>
#include <stdlib.h>
#include <glib.h>
#include <mediator/templates.h>

gboolean mdPrintDecimal(
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         delimiter,
    int          decimal);

gboolean mdPrintCollectorName(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator);

gboolean mdPrintSIP(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator);

gboolean mdPrintDIP(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator);

gboolean mdPrintTOS(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator);

gboolean mdPrintRTOS(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator);


gboolean mdPrintSTIME(
    mdFullFlow_t  *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char          *decorator);

gboolean mdPrintETIME(
    mdFullFlow_t  *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char          *decorator);

gboolean mdPrintDuration(
    mdFullFlow_t     *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char             *decorator);

gboolean mdPrintRTT(
    mdFullFlow_t     *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char             *decorator);

gboolean mdPrintProto(
    mdFullFlow_t     *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char             *decorator);
gboolean mdPrintSPort(
    mdFullFlow_t    *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char            *decorator);

gboolean mdPrintDPort(
    mdFullFlow_t    *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char            *decorator);

gboolean mdPrintPackets(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator);

gboolean mdPrintRPackets(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator);

gboolean mdPrintBytes(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator);

gboolean mdPrintRBytes(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator);

gboolean mdPrintIFlags(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator);

gboolean mdPrintUFlags(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator);

gboolean mdPrintRIFlags(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator);

gboolean mdPrintRUFlags(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator);

gboolean mdPrintAttributes(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator);

gboolean mdPrintRAttributes(
    mdFullFlow_t     *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char             *decorator);

gboolean mdPrintMAC(
    mdFullFlow_t    *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char            *decorator);

gboolean mdPrintDSTMAC(
    mdFullFlow_t    *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char            *decorator);

gboolean mdPrintTCPSeq(
    mdFullFlow_t    *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char            *decorator);

gboolean mdPrintRTCPSeq(
    mdFullFlow_t    *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char            *decorator);

gboolean mdPrintVLAN(
    mdFullFlow_t    *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char            *decorator);

gboolean mdPrintVLANINT(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator);

gboolean mdPrintApp(
    mdFullFlow_t    *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char            *decorator);

gboolean mdPrintEntropy(
    mdFullFlow_t    *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char            *decorator);

gboolean mdPrintREntropy(
    mdFullFlow_t    *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char            *decorator);

gboolean mdPrintEnd(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator);

gboolean mdPrintRDHCPVC(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator);

gboolean mdPrintDHCPVC(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator);

gboolean mdPrintRDHCPFP(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator);

gboolean mdPrintDHCPFP(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator);

gboolean mdPrintOSNAME(
    mdFullFlow_t    *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char            *decorator);

gboolean mdPrintROSNAME(
    mdFullFlow_t    *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char            *decorator);

gboolean mdPrintOSVersion(
    mdFullFlow_t    *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char            *decorator);

gboolean mdPrintROSVersion(
    mdFullFlow_t     *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char             *decorator);

gboolean mdPrintOSFingerprint(
    mdFullFlow_t     *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char             *decorator);

gboolean mdPrintROSFingerprint(
    mdFullFlow_t     *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char             *decorator);

gboolean mdPrintOBDomain(
    mdFullFlow_t    *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char            *decorator);

gboolean mdPrintIngress(
    mdFullFlow_t     *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char             *decorator);

gboolean mdPrintEgress(
    mdFullFlow_t     *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char             *decorator);

gboolean mdPrintDataBytes(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator);

gboolean mdPrintITime(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator);

gboolean mdPrintSTDITime(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator);

gboolean mdPrintTCPURG(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator);

gboolean mdPrintSmallPkts(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator);

gboolean mdPrintNonEmptyPkts(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator);

gboolean mdPrintLargePkts(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator);

gboolean mdPrintFirstNonEmpty(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator);

gboolean mdPrintMaxPacketSize(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator);

gboolean mdPrintSTDPayLen(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator);

gboolean mdPrintFirstEight(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator);

gboolean mdPrintRDataBytes(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator);

gboolean mdPrintRITime(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator);

gboolean mdPrintRSTDITime(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator);

gboolean mdPrintRTCPURG(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator);

gboolean mdPrintRSmallPkts(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator);

gboolean mdPrintRNonEmptyPkts(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator);

gboolean mdPrintRLargePkts(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator);

gboolean mdPrintRFirstNonEmpty(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator);

gboolean mdPrintRMaxPacketSize(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator);

gboolean mdPrintRSTDPayLen(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator);

gboolean mdPrintFlowKeyHash(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator);

gboolean mdPrintSIPINT(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator);

gboolean mdPrintDIPINT(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator);

gboolean mdPrintSTIMEMS(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator);

gboolean mdPrintETIMEMS(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator);

gboolean mdPrintISN(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator);

gboolean mdPrintRISN(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator);

gboolean mdPrintMPLS1(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator);

gboolean mdPrintMPLS2(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator);

gboolean mdPrintMPLS3(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator);

gboolean mdPrintNone(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator);

gboolean mdPrintMPTCPSeq(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator);


gboolean mdPrintMPTCPToken(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator);

gboolean mdPrintMPTCPMss(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator);

gboolean mdPrintMPTCPId(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator);

gboolean mdPrintMPTCPFlags(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator);

size_t mdPrintBasicFlow(
    mdFullFlow_t  *fflow,
    FILE          *fp,
    char          delimiter,
    GError        **err);

gboolean mdPrintPayload(
    mdFullFlow_t   *flow,
    mdBuf_t        *buf,
    size_t         *bufsize,
    char           *decorator);

gboolean mdPrintRPayload(
    mdFullFlow_t   *flow,
    mdBuf_t        *buf,
    size_t         *bufsize,
    char           *decorator);

gboolean mdPrintPayloadJSON(
    mdFullFlow_t   *flow,
    mdBuf_t        *buf,
    size_t         *bufsize,
    char           *decorator);

gboolean mdPrintRPayloadJSON(
    mdFullFlow_t   *flow,
    mdBuf_t        *buf,
    size_t         *bufsize,
    char           *decorator);

void mdPrintBasicHeader(
    GString *rstr,
    char delimiter);

/**
 * mdPrintStats
 *
 * print a YAF stats message to the given exporter
 *
 */
size_t mdPrintStats(
    yfIpfixStats_t     *stats,
    char               *name,
    FILE               *lfp,
    char               delim,
    gboolean           no_stats,
    GError             **err);

int mdPrintDNSRecord(
    FILE             *fp,
    mdBuf_t          *buf,
    char             delimiter,
    uint8_t          *record,
    gboolean         base64,
    gboolean         print_last,
    gboolean         escape_chars,
    GError           **err);

int mdPrintDNSRRRecord(
    mdBuf_t          *buf,
    FILE             *fp,
    char             delimiter,
    uint8_t          *rec,
    gboolean         base64,
    gboolean         escape_chars,
    GError           **err);

gboolean mdPrintEscapeChars(
    mdBuf_t          *mdbuf,
    size_t           *rem,
    uint8_t          *buf,
    size_t           buflen,
    char             delimiter);

gboolean mdPrintBasicList(
    mdBuf_t          *buf,
    GString          *index_str,
    fbBasicList_t    *bl,
    char             delimiter,
    gboolean         hex,
    gboolean         escape);

gboolean mdPrintVariableLength(
    mdBuf_t          *mdbuf,
    size_t           *brem,
    uint8_t          *buf,
    size_t           buflen,
    char             delimiter,
    gboolean         hex,
    gboolean         escape);

int mdPrintDedupRecord(
    FILE                *fp,
    mdBuf_t             *buf,
    md_dedup_t          *rec,
    char                delimiter,
    GError              **err);

int mdPrintSSLDedupRecord(
    FILE      *fp,
    mdBuf_t   *buf,
    uint8_t   *rec,
    char      delimiter,
    GError    **err);

void mdPrintEscapeStrChars(
    GString     *str,
    uint8_t     *buf,
    size_t      buflen,
    char        delimiter);

gboolean mdPrintDHCPOptions(
    mdFullFlow_t   *flow,
    mdBuf_t        *buf,
    size_t         *bufsize,
    char           *decorator);

gboolean mdPrintRevDHCPOptions(
    mdFullFlow_t   *flow,
    mdBuf_t        *buf,
    size_t         *bufsize,
    char           *decorator);

gboolean mdPrintNDPIMaster(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator);

gboolean mdPrintNDPISub(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator);
