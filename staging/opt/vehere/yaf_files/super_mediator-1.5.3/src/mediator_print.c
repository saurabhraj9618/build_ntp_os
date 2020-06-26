/**
 * @file mediator_print.c
 *
 * Contains all printing functions for custom field printers
 *
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2012-2017 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 * Authors: Emily Sarneso <netsa-help@cert.org>
 * ------------------------------------------------------------------------
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
 * -----------------------------------------------------------
 */

#include <mediator/mediator_ctx.h>
#include <mediator/mediator_util.h>
#include <mediator/mediator_inf.h>
#include "mediator_print.h"

#define MD_WR_BDC(_ret_, _size_)             \
    if (_ret_ < 0) return FALSE;             \
    if ((size_t)_ret_ >= _size_) return FALSE;  \
    _size_ -= _ret_;

#define MD_WR_BDC0(_ret_, _size_)        \
    if (_ret_ < 0) return 0;             \
    if ((size_t)_ret_ >= _size_) return 0;      \
    _size_ -= _ret_;

#define MD_APPEND_CHAR(_buf_, _ch_)           \
    *(_buf_->cp) = _ch_;                      \
    ++(_buf_->cp);

gboolean mdPrintFlowKeyHash(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator)
{
    uint32_t     hash = flow->rec->flowKeyHash;
    int          ret;

    if (hash == 0) {
        hash = md_util_flow_key_hash(flow->rec);
    }

    ret = snprintf(buf->cp, *bufsize, decorator, hash);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;

}

gboolean mdPrintDecimal(
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         delimiter,
    int          decimal)
{
    int ret;

    ret = snprintf(buf->cp, *bufsize, "%d%c", decimal, delimiter);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintNone(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator)
{
    return TRUE;
}


gboolean mdPrintSIPINT(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator)
{
    int ret;

    ret = snprintf(buf->cp, *bufsize, decorator, flow->rec->sourceIPv4Address);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintDIPINT(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator)
{
    int ret;

    ret = snprintf(buf->cp, *bufsize, decorator,
                   flow->rec->destinationIPv4Address);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintSTIMEMS(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator)
{
    int ret;

    ret = snprintf(buf->cp, *bufsize, decorator,
                   flow->rec->flowStartMilliseconds);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;

}

gboolean mdPrintETIMEMS(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator)
{
    int ret;

    ret = snprintf(buf->cp, *bufsize, decorator,
                   flow->rec->flowEndMilliseconds);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;

}

gboolean mdPrintSIP(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char        *decorator)
{
    char         sabuf[40];
    int          ret;

    if (flow->rec->sourceIPv4Address) {
        md_util_print_ip4_addr(sabuf, flow->rec->sourceIPv4Address);
    } else {
        md_util_print_ip6_addr(sabuf, (uint8_t *)&(flow->rec->sourceIPv6Address));
    }

    ret = snprintf(buf->cp, *bufsize, decorator, sabuf);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}


gboolean mdPrintDIP(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator)
{
    char         dabuf[40];
    int ret;

    if (flow->rec->destinationIPv4Address) {
        md_util_print_ip4_addr(dabuf, flow->rec->destinationIPv4Address);
    } else {
        md_util_print_ip6_addr(dabuf, (uint8_t *)&(flow->rec->destinationIPv6Address));
    }

    ret = snprintf(buf->cp, *bufsize, decorator, dabuf);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintSTIME(
    mdFullFlow_t  *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char          *decorator)
{
    uint64_t        start_secs = flow->rec->flowStartMilliseconds / 1000;
    uint32_t        start_rem = flow->rec->flowStartMilliseconds % 1000;
    int             ret;
    GString *tmp = g_string_new("");

    md_util_time_g_string_append(tmp, start_secs, PRINT_TIME_FMT);

    g_string_append_printf(tmp, ".%03u", start_rem);

    ret = snprintf(buf->cp, *bufsize, decorator, tmp->str);

    g_string_free(tmp, TRUE);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;

}

gboolean mdPrintETIME(
    mdFullFlow_t  *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char          *decorator)
{
    uint64_t        end_secs = flow->rec->flowEndMilliseconds / 1000;
    uint32_t        end_rem = flow->rec->flowEndMilliseconds % 1000;
    GString *tmp = g_string_new("");
    int             ret;

    md_util_time_g_string_append(tmp, end_secs, PRINT_TIME_FMT);
    g_string_append_printf(tmp, ".%03u", end_rem);

    ret = snprintf(buf->cp, *bufsize, decorator, tmp->str);

    g_string_free(tmp, TRUE);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;

}

gboolean mdPrintDuration(
    mdFullFlow_t     *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char             *decorator)
{
    int ret;

    ret = snprintf(buf->cp, *bufsize, decorator,
                   (flow->rec->flowEndMilliseconds -
                    flow->rec->flowStartMilliseconds) / 1000.0);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;

}

gboolean mdPrintRTT(
    mdFullFlow_t     *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char             *decorator)
{

    int ret;

    ret = snprintf(buf->cp, *bufsize, decorator,
                   flow->rec->reverseFlowDeltaMilliseconds/ 1000.0);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;

}

gboolean mdPrintProto(
    mdFullFlow_t     *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char             *decorator)
{
    int ret;

    ret = snprintf(buf->cp, *bufsize, decorator,flow->rec->protocolIdentifier);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintSPort(
    mdFullFlow_t    *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char             *decorator)
{
    int ret;
    uint16_t sp = flow->rec->sourceTransportPort;

    if (flow->rec->protocolIdentifier == 1) {
        sp = (flow->rec->destinationTransportPort >> 8);
    }

    ret = snprintf(buf->cp, *bufsize, decorator, sp);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintDPort(
    mdFullFlow_t    *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char            *decorator)
{
    int ret;
    uint16_t dp = flow->rec->destinationTransportPort;

    if (flow->rec->protocolIdentifier == 1) {
        dp = (flow->rec->destinationTransportPort & 0xFF);
    }

    ret = snprintf(buf->cp, *bufsize, decorator, dp);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintPackets(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{

    int ret;

    ret = snprintf(buf->cp, *bufsize, decorator,
                   flow->rec->packetTotalCount);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}


gboolean mdPrintRPackets(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;

    ret = snprintf(buf->cp, *bufsize, decorator,
                   flow->rec->reversePacketTotalCount);
    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;

}

gboolean mdPrintBytes(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;

    ret = snprintf(buf->cp, *bufsize, decorator,
                   flow->rec->octetTotalCount);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintRBytes(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;

    ret = snprintf(buf->cp, *bufsize, decorator,
                   flow->rec->reverseOctetTotalCount);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintTOS(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;

    ret = snprintf(buf->cp, *bufsize, decorator,
                   flow->rec->ipClassOfService);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintRTOS(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;

    ret = snprintf(buf->cp, *bufsize, decorator,
                   flow->rec->reverseIpClassOfService);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintMPLS1(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    uint32_t   label = 0;
    int ret;

    memcpy(&label, flow->rec->mpls_label1, 3);

    ret = snprintf(buf->cp, *bufsize, decorator, label);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;

}

gboolean mdPrintMPLS2(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    uint32_t   label = 0;
    int ret;

    memcpy(&label, flow->rec->mpls_label2, 3);

    ret = snprintf(buf->cp, *bufsize, decorator, label);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintMPLS3(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;
    uint32_t   label = 0;

    memcpy(&label, flow->rec->mpls_label3, 3);

    ret = snprintf(buf->cp, *bufsize, decorator, label);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintIFlags(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    uint8_t flags = flow->rec->initialTCPFlags;
    int     ret;
    char    tmp[10] = "\0";

    if (flags & 0x40) snprintf(tmp + strlen(tmp), 10, "E");
    if (flags & 0x80) snprintf(tmp+strlen(tmp), 10,"C");
    if (flags & 0x20) snprintf(tmp+strlen(tmp), 10,"U");
    if (flags & 0x10) snprintf(tmp+strlen(tmp), 10,"A");
    if (flags & 0x08) snprintf(tmp+strlen(tmp), 10,"P");
    if (flags & 0x04) snprintf(tmp+strlen(tmp), 10,"R");
    if (flags & 0x02) snprintf(tmp+strlen(tmp), 10,"S");
    if (flags & 0x01) snprintf(tmp+strlen(tmp), 10,"F");
    if (!flags) snprintf(tmp, 10, "0");

    ret = snprintf(buf->cp, *bufsize, decorator, tmp);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintUFlags(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    uint8_t flags = flow->rec->unionTCPFlags;
    int     ret;
    char    tmp[10] = "\0";

    if (flags & 0x40) snprintf(tmp + strlen(tmp), 10,"E");
    if (flags & 0x80) snprintf(tmp + strlen(tmp), 10,"C");
    if (flags & 0x20) snprintf(tmp + strlen(tmp), 10,"U");
    if (flags & 0x10) snprintf(tmp + strlen(tmp), 10,"A");
    if (flags & 0x08) snprintf(tmp + strlen(tmp), 10,"P");
    if (flags & 0x04) snprintf(tmp + strlen(tmp), 10,"R");
    if (flags & 0x02) snprintf(tmp + strlen(tmp), 10,"S");
    if (flags & 0x01) snprintf(tmp + strlen(tmp), 10,"F");
    if (!flags) snprintf(tmp, 10, "0");

    ret = snprintf(buf->cp, *bufsize, decorator, tmp);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintRIFlags(
    mdFullFlow_t    *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char            *decorator)
{
    uint8_t flags = flow->rec->reverseInitialTCPFlags;
    int     ret;
    char    tmp[10] = "\0";

    if (flags & 0x40) snprintf(tmp + strlen(tmp), 10,"E");
    if (flags & 0x80) snprintf(tmp + strlen(tmp), 10,"C");
    if (flags & 0x20) snprintf(tmp + strlen(tmp), 10,"U");
    if (flags & 0x10) snprintf(tmp + strlen(tmp), 10,"A");
    if (flags & 0x08) snprintf(tmp + strlen(tmp), 10,"P");
    if (flags & 0x04) snprintf(tmp + strlen(tmp), 10,"R");
    if (flags & 0x02) snprintf(tmp + strlen(tmp), 10,"S");
    if (flags & 0x01) snprintf(tmp + strlen(tmp), 10,"F");
    if (!flags) snprintf(tmp, 10, "0");

    ret = snprintf(buf->cp, *bufsize, decorator, tmp);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintRUFlags(
    mdFullFlow_t    *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char            *decorator)
{
    uint8_t flags = flow->rec->reverseUnionTCPFlags;
    int     ret;
    char    tmp[10] = "\0";

    if (flags & 0x40) snprintf(tmp + strlen(tmp), 10,"E");
    if (flags & 0x80) snprintf(tmp + strlen(tmp), 10,"C");
    if (flags & 0x20) snprintf(tmp + strlen(tmp), 10,"U");
    if (flags & 0x10) snprintf(tmp + strlen(tmp), 10,"A");
    if (flags & 0x08) snprintf(tmp + strlen(tmp), 10,"P");
    if (flags & 0x04) snprintf(tmp + strlen(tmp), 10,"R");
    if (flags & 0x02) snprintf(tmp + strlen(tmp), 10,"S");
    if (flags & 0x01) snprintf(tmp + strlen(tmp), 10,"F");
    if (!flags) snprintf(tmp, 10, "0");

    ret = snprintf(buf->cp, *bufsize, decorator, tmp);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintAttributes(
    mdFullFlow_t      *flow,
    mdBuf_t           *buf,
    size_t            *bufsize,
    char              *decorator)
{
    int ret;

    ret = snprintf(buf->cp, *bufsize, decorator, flow->rec->flowAttributes);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintRAttributes(
    mdFullFlow_t      *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char              *decorator)
{
    int ret;

    ret = snprintf(buf->cp, *bufsize, decorator,
                   flow->rec->reverseFlowAttributes);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintMAC(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator)
{
    int loop;
    char tmp[30] = "00:00:00:00:00:00";
    int total = 0;
    int ret;

    if (flow->mac) {
        for (loop = 0; loop < 5; loop++) {
            ret = snprintf(tmp + total, 30, "%02x:",
                           flow->mac->sourceMacAddress[loop]);
            total += ret;
        }
        ret = snprintf(tmp + total, 30, "%02x:",
                       flow->mac->sourceMacAddress[loop]);
        ret = snprintf(buf->cp, *bufsize, decorator, tmp);
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, tmp);
    }

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintDSTMAC(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int loop;
    char tmp[30] = "00:00:00:00:00:00";
    int total = 0;
    int ret;

    if (flow->mac) {
        for (loop = 0; loop < 5; loop++) {
            ret = snprintf(tmp + total, 30, "%02x:",
                           flow->mac->destinationMacAddress[loop]);
            total += ret;
        }
        ret = snprintf(tmp + total, 30, "%02x:",
                       flow->mac->destinationMacAddress[loop]);
        ret = snprintf(buf->cp, *bufsize, decorator, tmp);
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, tmp);
    }

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintTCPSeq(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;

    ret = snprintf(buf->cp, *bufsize, decorator,
                   flow->rec->tcpSequenceNumber);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintRTCPSeq(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;

    ret = snprintf(buf->cp, *bufsize, decorator,
                   flow->rec->reverseTcpSequenceNumber);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintVLAN(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator)
{
    int ret;

    ret = snprintf(buf->cp, *bufsize, decorator,flow->rec->vlanId);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;

}

gboolean mdPrintVLANINT(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator)
{
    int ret;

    ret = snprintf(buf->cp, *bufsize, decorator,flow->rec->vlanId);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;

}

gboolean mdPrintApp(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator)
{
    int ret;

    ret = snprintf(buf->cp, *bufsize, decorator,
                   flow->rec->numAppLabel);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintNDPIMaster(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator)
{
    int ret;

    ret = snprintf(buf->cp, *bufsize, decorator,
                   flow->rec->ndpi_master);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintNDPISub(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator)
{
    int ret;

    ret = snprintf(buf->cp, *bufsize, decorator,
                   flow->rec->ndpi_sub);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}


gboolean mdPrintOBDomain(
    mdFullFlow_t     *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char             *decorator)
{
    int ret;

    ret = snprintf(buf->cp, *bufsize, decorator,flow->rec->obsid);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintIngress(
    mdFullFlow_t     *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char             *decorator)
{
    int ret;

    ret = snprintf(buf->cp, *bufsize, decorator,
                   flow->rec->ingressInterface);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintEgress(
    mdFullFlow_t     *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char             *decorator)
{
    int ret;

    ret = snprintf(buf->cp, *bufsize, decorator,
                   flow->rec->egressInterface);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintEntropy(
    mdFullFlow_t    *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char            *decorator)
{

    int ret;

    if (flow->entropy) {
        ret = snprintf(buf->cp, *bufsize, decorator,
                       flow->entropy->entropy);
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, 0);
    }

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;

}


gboolean mdPrintREntropy(
    mdFullFlow_t    *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char            *decorator)
{
    int ret;

    if (flow->entropy) {
        if (flow->rec->reverseOctetTotalCount) {
            ret = snprintf(buf->cp, *bufsize, decorator,
                           flow->entropy->reverseEntropy);
        } else {
            ret = snprintf(buf->cp, *bufsize, decorator, 0);
        }
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, 0);
    }

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintEnd(
    mdFullFlow_t *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char         *decorator)
{
    int ret;
    char tmp[10] = "\0";

    if ((flow->rec->flowEndReason & 0x7f) == 1)
        snprintf(tmp, 10, "idle");
    if ((flow->rec->flowEndReason & 0x7f) == 2)
        snprintf(tmp, 10, "active");
    if ((flow->rec->flowEndReason & 0x7f) == 4)
        snprintf(tmp, 10, "eof");
    if ((flow->rec->flowEndReason & 0x7f) == 5)
        snprintf(tmp, 10, "rsrc");
    if ((flow->rec->flowEndReason & 0x7f) == 0x1f)
        snprintf(tmp, 10, "force");


    ret = snprintf(buf->cp, *bufsize, decorator,tmp);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintDHCPFP(
    mdFullFlow_t   *flow,
    mdBuf_t        *buf,
    size_t         *bufsize,
    char           *decorator)
{
    int ret;
    GString *tmp = g_string_new("");
    yfDHCP_FP_Flow_t *dhcp = NULL;

    if (flow->dhcpfp) {
        if (flow->dhcpfp->tmplID == YAF_DHCP_FLOW_TID) {
            dhcp = (yfDHCP_FP_Flow_t *)FBSTMLNEXT(flow->dhcpfp, dhcp);
            g_string_append_len(tmp, (char *)dhcp->dhcpFP.buf,
                                dhcp->dhcpFP.len);
        }
    }

    ret = snprintf(buf->cp, *bufsize, decorator, tmp->str);

    g_string_free(tmp, TRUE);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;

}

gboolean mdPrintRDHCPFP(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    GString *tmp = g_string_new("");
    int ret;
    yfDHCP_FP_Flow_t *dhcp = NULL;

    if (flow->dhcpfp) {
        if (flow->dhcpfp->tmplID == (YAF_DHCP_FLOW_TID | YTF_REV)) {
            dhcp = (yfDHCP_FP_Flow_t *)FBSTMLNEXT(flow->dhcpfp,dhcp);
            g_string_append_len(tmp, (char *)dhcp->reverseDhcpFP.buf,
                                dhcp->reverseDhcpFP.len);
        }
    }

    ret = snprintf(buf->cp, *bufsize, decorator, tmp->str);

    g_string_free(tmp, TRUE);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;


    return TRUE;
}


gboolean mdPrintDHCPVC(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    GString *tmp = g_string_new("");
    int ret;

    if (flow->dhcpfp) {
        if (flow->dhcpfp->tmplID == YAF_DHCP_FLOW_TID) {
            yfDHCP_FP_Flow_t *dhcp = NULL;
            dhcp = (yfDHCP_FP_Flow_t *)FBSTMLNEXT(flow->dhcpfp,dhcp);
            g_string_append_len(tmp, (char *)dhcp->dhcpVC.buf,
                                dhcp->dhcpVC.len);
        } else if (flow->dhcpfp->tmplID == YAF_DHCP_OP_TID) {
            yfDHCP_OP_Flow_t *dhcp = NULL;
            dhcp = (yfDHCP_OP_Flow_t *)FBSTMLNEXT(flow->dhcpfp, dhcp);
            g_string_append_len(tmp, (char *)dhcp->dhcpVC.buf,
                                dhcp->dhcpVC.len);
        }
    }

    ret = snprintf(buf->cp, *bufsize, decorator, tmp->str);

    g_string_free(tmp, TRUE);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintRDHCPVC(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    GString *tmp = g_string_new("");
    int ret;

    if (flow->dhcpfp) {
        if (flow->dhcpfp->tmplID == (YAF_DHCP_FLOW_TID | YTF_REV)) {
            yfDHCP_FP_Flow_t *dhcp = NULL;
            dhcp = (yfDHCP_FP_Flow_t *)FBSTMLNEXT(flow->dhcpfp, dhcp);
            g_string_append_len(tmp, (char *)dhcp->reverseDhcpVC.buf,
                                dhcp->reverseDhcpVC.len);
        } else if (flow->dhcpfp->tmplID == (YAF_DHCP_OP_TID | YTF_REV)) {
            yfDHCP_OP_Flow_t *dhcp = NULL;
            dhcp = (yfDHCP_OP_Flow_t *)FBSTMLNEXT(flow->dhcpfp, dhcp);
            g_string_append_len(tmp, (char *)dhcp->reverseDhcpVC.buf,
                                dhcp->reverseDhcpVC.len);
        }
    }

    ret = snprintf(buf->cp, *bufsize, decorator, tmp->str);

    g_string_free(tmp, TRUE);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintDHCPOptions(
    mdFullFlow_t   *flow,
    mdBuf_t        *buf,
    size_t         *bufsize,
    char           *decorator)
{
    int ret, w;
    GString *tmp = g_string_new("");
    yfDHCP_OP_Flow_t *dhcp = NULL;
    uint8_t *option;

    if (flow->dhcpfp) {
        if (flow->dhcpfp->tmplID == YAF_DHCP_OP_TID) {
            dhcp = (yfDHCP_OP_Flow_t *)FBSTMLNEXT(flow->dhcpfp, dhcp);
            for (w = 0; (option =
                         (uint8_t*)fbBasicListGetIndexedDataPtr(&(dhcp->options), w));
                 w++)
            {
                g_string_append_printf(tmp, "%d, ", *option);
            }
        }
    }

    if (tmp->len > 2) {
        g_string_truncate(tmp, tmp->len - 2);
    }

    ret = snprintf(buf->cp, *bufsize, decorator, tmp->str);

    g_string_free(tmp, TRUE);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;

}

gboolean mdPrintRevDHCPOptions(
    mdFullFlow_t   *flow,
    mdBuf_t        *buf,
    size_t         *bufsize,
    char           *decorator)
{
    int ret, w;
    GString *tmp = g_string_new("");
    yfDHCP_OP_Flow_t *dhcp = NULL;
    uint8_t *option;

    if (flow->dhcpfp) {
        if (flow->dhcpfp->tmplID == (YAF_DHCP_OP_TID | YTF_REV)) {
            dhcp = (yfDHCP_OP_Flow_t *)FBSTMLNEXT(flow->dhcpfp, dhcp);
            for(w = 0;(option =
                       (uint8_t*)fbBasicListGetIndexedDataPtr(&(dhcp->revOptions), w));
                w++)
            {
                g_string_append_printf(tmp, "%d, ", *option);
            }
        }
    }

    if (tmp->len > 2) {
        g_string_truncate(tmp, tmp->len - 2);
    }

    ret = snprintf(buf->cp, *bufsize, decorator, tmp->str);

    g_string_free(tmp, TRUE);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;

}

gboolean mdPrintOSNAME(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    GString *tmp = g_string_new("");
    int ret;
    if (flow->p0f) {
        g_string_append_len(tmp, (char *)flow->p0f->osName.buf,
                            flow->p0f->osName.len);
    }
    ret = snprintf(buf->cp, *bufsize, decorator, tmp->str);

    g_string_free(tmp, TRUE);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintROSNAME(
    mdFullFlow_t    *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char            *decorator)
{
    GString *tmp = g_string_new("");
    int ret;

    if (flow->p0f && flow->rec->reverseOctetTotalCount) {
        g_string_append_len(tmp, (char *)flow->p0f->reverseOsName.buf,
                            flow->p0f->reverseOsName.len);
    }
    ret = snprintf(buf->cp, *bufsize, decorator, tmp->str);

    g_string_free(tmp, TRUE);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}


gboolean mdPrintOSVersion(
    mdFullFlow_t     *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char             *decorator)
{
    GString *tmp = g_string_new("");
    int ret;
    if (flow->p0f) {
        g_string_append_len(tmp, (char *)flow->p0f->osVersion.buf,
                            flow->p0f->osVersion.len);
    }
    ret = snprintf(buf->cp, *bufsize, decorator, tmp->str);

    g_string_free(tmp, TRUE);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;

}

gboolean mdPrintROSVersion(
    mdFullFlow_t      *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char              *decorator)
{
    GString *tmp = g_string_new("");
    int ret;
    if (flow->p0f && flow->rec->reverseOctetTotalCount) {
        g_string_append_len(tmp, (char *)flow->p0f->reverseOsVersion.buf,
                            flow->p0f->reverseOsVersion.len);
    }
    ret = snprintf(buf->cp, *bufsize, decorator, tmp->str);

    g_string_free(tmp, TRUE);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintOSFingerprint(
    mdFullFlow_t      *flow,
    mdBuf_t           *buf,
    size_t            *bufsize,
    char              *decorator)
{
    GString *tmp = g_string_new("");
    int ret;
    if (flow->p0f) {
        g_string_append_len(tmp, (char *)flow->p0f->osFingerPrint.buf,
                            flow->p0f->osFingerPrint.len);
    }
    ret = snprintf(buf->cp, *bufsize, decorator, tmp->str);

    g_string_free(tmp, TRUE);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;

}

gboolean mdPrintROSFingerprint(
    mdFullFlow_t       *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char               *decorator)
{
    GString *tmp = g_string_new("");
    int ret;

    if (flow->p0f && flow->rec->reverseOctetTotalCount) {
        g_string_append_len(tmp, (char *)flow->p0f->reverseOsFingerPrint.buf,
                            flow->p0f->reverseOsFingerPrint.len);
    }
    ret = snprintf(buf->cp, *bufsize, decorator, tmp->str);

    g_string_free(tmp, TRUE);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;

}

gboolean mdPrintDataBytes(
    mdFullFlow_t     *flow,
    mdBuf_t          *buf,
    size_t           *bufsize,
    char             *decorator)
{
    int ret;
    int none = 0;

    if (flow->stats) {
        ret = snprintf(buf->cp, *bufsize, decorator,
                       flow->stats->dataByteCount);
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, none);
    }

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintITime(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;
    float none = 0;

    if (flow->stats) {
        ret = snprintf(buf->cp, *bufsize, decorator,
                       flow->stats->averageInterarrivalTime/1000.0);
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, none);
    }

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintSTDITime(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;
    float none = 0;

    if (flow->stats) {
        ret = snprintf(buf->cp, *bufsize, decorator,
                               flow->stats->standardDeviationInterarrivalTime);
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, none);
    }

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintTCPURG(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;
    int none = 0;

    if (flow->stats) {
        ret = snprintf(buf->cp, *bufsize, decorator,
                       flow->stats->tcpUrgTotalCount);
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, none);
    }

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintSmallPkts(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;
    int none = 0;

    if (flow->stats) {
        ret = snprintf(buf->cp, *bufsize, decorator,
                       flow->stats->smallPacketCount);
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, none);
    }

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintNonEmptyPkts(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;
    int none = 0;

    if (flow->stats) {
        ret = snprintf(buf->cp, *bufsize, decorator,
                       flow->stats->nonEmptyPacketCount);
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, none);
    }

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintLargePkts(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;
    int none = 0;

    if (flow->stats) {
        ret = snprintf(buf->cp, *bufsize, decorator,
                       flow->stats->largePacketCount);
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, none);
    }

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintFirstNonEmpty(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;
    int none = 0;

    if (flow->stats) {
        ret = snprintf(buf->cp, *bufsize, decorator,
                       flow->stats->firstNonEmptyPacketSize);
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, none);
    }

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintMaxPacketSize(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;
    int none = 0;

    if (flow->stats) {
        ret = snprintf(buf->cp, *bufsize, decorator,
                       flow->stats->maxPacketSize);
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, none);
    }

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintSTDPayLen(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;
    int none = 0;

    if (flow->stats) {
        ret = snprintf(buf->cp, *bufsize, decorator,
                       flow->stats->standardDeviationPayloadLength);
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, none);
    }

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintFirstEight(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;
    int none = 0;

    if (flow->stats) {
        ret = snprintf(buf->cp, *bufsize, decorator,
                       flow->stats->firstEightNonEmptyPacketDirections);
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, none);
    }

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintRDataBytes(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;
    int none = 0;

    if (flow->stats && flow->rec->reverseOctetTotalCount) {
        ret = snprintf(buf->cp, *bufsize, decorator,
                       flow->stats->reverseDataByteCount);
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, none);
    }

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintRITime(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;
    float none = 0;

    if (flow->stats && flow->rec->reverseOctetTotalCount) {
        ret = snprintf(buf->cp, *bufsize, decorator,
                       flow->stats->reverseAverageInterarrivalTime/1000.0);
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, none);
    }

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintRSTDITime(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;
    float none = 0;

    if (flow->stats && flow->rec->reverseOctetTotalCount) {
        ret = snprintf(buf->cp, *bufsize, decorator,
                       flow->stats->reverseStandardDeviationInterarrivalTime);
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, none);
    }

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}


gboolean mdPrintRTCPURG(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;
    int none = 0;

    if (flow->stats && flow->rec->reverseOctetTotalCount) {
        ret = snprintf(buf->cp, *bufsize, decorator,
                       flow->stats->reverseTcpUrgTotalCount);
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, none);
    }

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintRSmallPkts(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;
    int none = 0;

    if (flow->stats && flow->rec->reverseOctetTotalCount) {
        ret = snprintf(buf->cp, *bufsize, decorator,
                       flow->stats->reverseSmallPacketCount);
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, none);
    }

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintRNonEmptyPkts(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;
    int none = 0;

    if (flow->stats && flow->rec->reverseOctetTotalCount) {
        ret = snprintf(buf->cp, *bufsize, decorator,
                       flow->stats->reverseNonEmptyPacketCount);
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, none);
    }

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintRLargePkts(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;
    int none = 0;

    if (flow->stats && flow->rec->reverseOctetTotalCount) {
        ret = snprintf(buf->cp, *bufsize, decorator,
                       flow->stats->reverseLargePacketCount);
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, none);
    }

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}


gboolean mdPrintRFirstNonEmpty(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;
    int none = 0;

    if (flow->stats && flow->rec->reverseOctetTotalCount) {
        ret = snprintf(buf->cp, *bufsize, decorator,
                       flow->stats->reverseFirstNonEmptyPacketSize);
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, none);
    }

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintRMaxPacketSize(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;
    int none = 0;

    if (flow->stats && flow->rec->reverseOctetTotalCount) {
        ret = snprintf(buf->cp, *bufsize, decorator,
                       flow->stats->reverseMaxPacketSize);
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, none);
    }

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintCollectorName(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;

    ret = snprintf(buf->cp, *bufsize, decorator, flow->collector_name);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintRSTDPayLen(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;
    int none = 0;

    if (flow->stats && flow->rec->reverseOctetTotalCount) {
        ret = snprintf(buf->cp, *bufsize, decorator,
                       flow->stats->reverseStandardDeviationPayloadLength);
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, none);
    }

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintISN (
    mdFullFlow_t    *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char            *decorator)
{

    int ret;

    ret = snprintf(buf->cp, *bufsize, decorator, flow->rec->tcpSequenceNumber);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintRISN (
    mdFullFlow_t    *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char            *decorator)
{
    int ret;

    ret = snprintf(buf->cp, *bufsize, decorator,
                   flow->rec->reverseTcpSequenceNumber);

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;

}

gboolean mdPrintMPTCPSeq(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;
    int none = 0;

    if (flow->mptcp) {
        ret = snprintf(buf->cp, *bufsize, decorator, flow->mptcp->idsn);
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, none);
    }
    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintMPTCPToken(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;
        int none = 0;

    if (flow->mptcp) {
        ret = snprintf(buf->cp, *bufsize, decorator, flow->mptcp->token);
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, none);
    }
    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintMPTCPMss(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;
    int none = 0;

    if (flow->mptcp) {
        ret = snprintf(buf->cp, *bufsize, decorator, flow->mptcp->mss);
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, none);
    }
    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintMPTCPId(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;
    int none = 0;

    if (flow->mptcp) {
        ret = snprintf(buf->cp, *bufsize, decorator, flow->mptcp->addrid);
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, none);
    }
    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintMPTCPFlags(
    mdFullFlow_t   *flow,
    mdBuf_t      *buf,
    size_t       *bufsize,
    char           *decorator)
{
    int ret;
    int none = 0;

    if (flow->mptcp) {
        ret = snprintf(buf->cp, *bufsize, decorator, flow->mptcp->flags);
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, none);
    }

    MD_WR_BDC(ret, *bufsize);

    buf->cp += ret;

    return TRUE;
}

gboolean mdPrintPayload(
    mdFullFlow_t   *flow,
    mdBuf_t        *buf,
    size_t         *bufsize,
    char           *decorator)
{
    GString *str = NULL;
    int ret, none=0;

    if (flow->pay) {
        str = g_string_new("\n");
        md_util_hexdump_g_string_append(str, "  -> ", flow->pay->payload.buf,
                                        flow->pay->payload.len);
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, none);
        MD_WR_BDC(ret, *bufsize);
        buf->cp += ret;
    }

    if (str) {
        if (!md_util_append_gstr(buf, bufsize, str)) {
            g_string_free(str, TRUE);
            return FALSE;
        }
        g_string_free(str, TRUE);
    }
    return TRUE;
}

gboolean mdPrintPayloadJSON(
    mdFullFlow_t   *flow,
    mdBuf_t        *buf,
    size_t         *bufsize,
    char           *decorator)
{
    gchar *base1 = NULL;
    int ret, none=0;

    if (flow->pay) {
        base1 = g_base64_encode((const guchar *)flow->pay->payload.buf,
                                flow->pay->payload.len);
        ret = snprintf(buf->cp, *bufsize, decorator, base1);
        MD_WR_BDC0(ret, *bufsize);
        buf->cp += ret;
        g_free(base1);
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, none);
        MD_WR_BDC0(ret, *bufsize);
        buf->cp += ret;
    }

    return TRUE;
}


gboolean mdPrintRPayload(
    mdFullFlow_t   *flow,
    mdBuf_t        *buf,
    size_t         *bufsize,
    char           *decorator)
{
    GString *str = NULL;
    int ret, none=0;

    if (flow->pay) {
        if (flow->rec->reverseOctetTotalCount) {
            str = g_string_new("\n");
            md_util_hexdump_g_string_append(str, "  <- ", flow->pay->reversePayload.buf,
                                            flow->pay->reversePayload.len);
        }
    }

    if (str) {
        if (!md_util_append_gstr(buf, bufsize, str)) {
            g_string_free(str, TRUE);
            return FALSE;
        }
        g_string_free(str, TRUE);

    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, none);
        MD_WR_BDC(ret, *bufsize);
        buf->cp += ret;
    }

    return TRUE;
}

gboolean mdPrintRPayloadJSON(
    mdFullFlow_t   *flow,
    mdBuf_t        *buf,
    size_t         *bufsize,
    char           *decorator)
{
    gchar *base1 = NULL;
    int ret, none=0;

    if (flow->pay) {
        if (flow->rec->reverseOctetTotalCount) {
            base1 = g_base64_encode((const guchar *)flow->pay->reversePayload.buf,
                                    flow->pay->reversePayload.len);
            ret = snprintf(buf->cp, *bufsize, decorator, base1);
            MD_WR_BDC0(ret, *bufsize);
            buf->cp += ret;
            g_free(base1);
        }
    } else {
        ret = snprintf(buf->cp, *bufsize, decorator, none);
        MD_WR_BDC0(ret, *bufsize);
        buf->cp += ret;
    }

    return TRUE;
}



/**
 * mdPrintBasicFlow
 *
 * print the given flow to the given FILE.
 * this only prints basic flow information, as well
 * as p0f and payload if they are available.
 *
 */
size_t mdPrintBasicFlow(
    mdFullFlow_t  *fflow,
    FILE          *fp,
    char          delimiter,
    GError        **err)
{
    mdRecord_t      *flow = fflow->rec;
    GString         *str = NULL;
    GString         *tstr = NULL;
    char            sabuf[40];
    char            dabuf[40];
    size_t          rc = 0;
    int             loop;
    uint64_t        start_secs = flow->flowStartMilliseconds / 1000;
    uint32_t        start_rem = flow->flowStartMilliseconds % 1000;
    uint64_t        end_secs = flow->flowEndMilliseconds / 1000;
    uint32_t        end_rem = flow->flowEndMilliseconds % 1000;

    str = g_string_new("");

    md_util_time_g_string_append(str, start_secs, PRINT_TIME_FMT);

    g_string_append_printf(str, ".%03u", start_rem);
    g_string_append_printf(str, "%c", delimiter);
    md_util_time_g_string_append(str, end_secs, PRINT_TIME_FMT);

    g_string_append_printf(str, ".%03u", end_rem);

    g_string_append_printf(str, "%c%8.3f", delimiter,
                           (flow->flowEndMilliseconds -
                            flow->flowStartMilliseconds) / 1000.0);
    g_string_append_printf(str, "%c%8.3f", delimiter,
                           flow->reverseFlowDeltaMilliseconds/ 1000.0);
    if (flow->sourceIPv4Address) {
        md_util_print_ip4_addr(sabuf, flow->sourceIPv4Address);
        md_util_print_ip4_addr(dabuf, flow->destinationIPv4Address);
    } else {
        md_util_print_ip6_addr(sabuf, (uint8_t *)&(flow->sourceIPv6Address));
        md_util_print_ip6_addr(dabuf, (uint8_t *)&(flow->destinationIPv6Address));
    }
    g_string_append_printf(str, "%c%3d", delimiter, flow->protocolIdentifier);
    if (flow->protocolIdentifier == 1) {
        g_string_append_printf(str, "%c%40s%c%5u%c%8llu%c%8llu%c%02x",
                               delimiter, sabuf, delimiter,
                               flow->destinationTransportPort >> 8, delimiter,
                               (long long unsigned int)flow->packetTotalCount,
                               delimiter,
                               (long long unsigned int)flow->octetTotalCount,
                               delimiter, flow->flowAttributes);
        if (fflow->mac) {
            g_string_append_printf(str, "%c", delimiter);
            for (loop = 0; loop < 5; loop++) {
                g_string_append_printf(str, "%02x:",
                                       fflow->mac->sourceMacAddress[loop]);
            }
            g_string_append_printf(str, "%02x",
                                   fflow->mac->sourceMacAddress[loop]);
        } else {
            g_string_append_printf(str,"%c00:00:00:00:00:00", delimiter);
        }

        g_string_append_printf(str, "%c%40s%c%5u%c%8llu%c%8llu%c%02x",
                               delimiter, dabuf, delimiter,
                               flow->destinationTransportPort& 0xFF, delimiter,
                               (long long unsigned int)flow->reversePacketTotalCount,
                               delimiter,
                               (long long unsigned int)flow->reverseOctetTotalCount,
                               delimiter, flow->reverseFlowAttributes);
        if (fflow->mac) {
            g_string_append_printf(str, "%c", delimiter);
            for (loop = 0; loop < 5; loop ++) {
                g_string_append_printf(str, "%02x:",
                                       fflow->mac->destinationMacAddress[loop]);
            }
            g_string_append_printf(str, "%02x",
                                   fflow->mac->destinationMacAddress[loop]);
        } else {
            g_string_append_printf(str,"%c00:00:00:00:00:00", delimiter);
        }

    } else {
        g_string_append_printf(str, "%c%40s%c%5u%c%8llu%c%8llu%c%02x",
                               delimiter, sabuf, delimiter,
                               flow->sourceTransportPort, delimiter,
                               (long long unsigned int)flow->packetTotalCount,
                               delimiter,
                               (long long unsigned int)flow->octetTotalCount,
                               delimiter, flow->flowAttributes);
        if (fflow->mac) {
            g_string_append_printf(str, "%c", delimiter);
            for (loop = 0; loop < 5; loop++) {
                g_string_append_printf(str, "%02x:",
                                       fflow->mac->sourceMacAddress[loop]);
            }
            g_string_append_printf(str, "%02x",
                                   fflow->mac->sourceMacAddress[loop]);
        } else {
            g_string_append_printf(str, "%c00:00:00:00:00:00", delimiter);
        }

        g_string_append_printf(str, "%c%40s%c%5u%c%8llu%c%8llu%c%02x",
                               delimiter, dabuf, delimiter,
                               flow->destinationTransportPort, delimiter,
                               (long long unsigned int)flow->reversePacketTotalCount,
                               delimiter,
                               (long long unsigned int)flow->reverseOctetTotalCount,
                               delimiter, flow->reverseFlowAttributes);
        if (fflow->mac) {
            g_string_append_printf(str, "%c", delimiter);
            for (loop = 0; loop < 5; loop ++) {
                g_string_append_printf(str, "%02x:",
                                       fflow->mac->destinationMacAddress[loop]);
            }
            g_string_append_printf(str, "%02x",
                                   fflow->mac->destinationMacAddress[loop]);
        } else {
            g_string_append_printf(str,"%c00:00:00:00:00:00", delimiter);
        }
    }


    tstr = g_string_new("");
    md_util_print_tcp_flags(tstr, flow->initialTCPFlags);
    g_string_append_printf(str, "%c%8s", delimiter, tstr->str);
    g_string_truncate(tstr, 0);
    md_util_print_tcp_flags(tstr, flow->unionTCPFlags);
    g_string_append_printf(str,"%c%8s", delimiter, tstr->str);
    g_string_truncate(tstr, 0);
    md_util_print_tcp_flags(tstr, flow->reverseInitialTCPFlags);
    g_string_append_printf(str,"%c%8s", delimiter, tstr->str);
    g_string_truncate(tstr, 0);
    md_util_print_tcp_flags(tstr, flow->reverseUnionTCPFlags);
    g_string_append_printf(str,"%c%8s", delimiter, tstr->str);
    g_string_free(tstr, TRUE);

    g_string_append_printf(str, "%c%08x%c%08x", delimiter,
                           flow->tcpSequenceNumber,
                           delimiter,
                           flow->reverseTcpSequenceNumber);
    /*g_string_append_printf(str, "%c%04x", delimiter, flow->ingressInterface);
      g_string_append_printf(str, "%c%04x", delimiter, flow->egressInterface);*/
    g_string_append_printf(str, "%c%03x", delimiter, flow->vlanId);
    g_string_append_printf(str, "%c%5u", delimiter, flow->numAppLabel);
    if (fflow->entropy) {
        g_string_append_printf(str, "%c%3u", delimiter,
                               fflow->entropy->entropy);
        if (flow->reverseOctetTotalCount) {
            g_string_append_printf(str, "%c%3u", delimiter,
                                   fflow->entropy->reverseEntropy);
        } else {
            g_string_append_printf(str, "%c000", delimiter);
        }
    } else {
        g_string_append_printf(str, "%c000%c000",
                               delimiter, delimiter);
    }
    g_string_append_printf(str, "%c", delimiter);
    /* end reason flags */
    if ((flow->flowEndReason & 0x7f) == 1)
        g_string_append_printf(str, "idle  ");
    if ((flow->flowEndReason & 0x7f) == 2)
        g_string_append_printf(str, "active");
    if ((flow->flowEndReason & 0x7f) == 4)
        g_string_append_printf(str,"eof   ");
    if ((flow->flowEndReason & 0x7f) == 5)
        g_string_append_printf(str,"rsrc  ");
    if ((flow->flowEndReason & 0x7f) == 0x1f)
        g_string_append_printf(str, "force ");

    if (fflow->collector_name) {
        g_string_append_printf(str, "%c%s", delimiter, fflow->collector_name);
    } else {
        g_string_append_printf(str, "%c", delimiter);
    }

    g_string_append_printf(str, "\n");

    if (fflow->pay) {
        md_util_hexdump_g_string_append(str, "  -> ", fflow->pay->payload.buf,
                                        fflow->pay->payload.len);
        if (flow->reversePacketTotalCount) {
            md_util_hexdump_g_string_append(str, " <- ",
                                            fflow->pay->reversePayload.buf,
                                            fflow->pay->reversePayload.len);
        }
    }

    rc = fwrite(str->str, 1, str->len, fp);

    if (rc != str->len) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                    "Error printing flow: %s\n", strerror(errno));
        return 0;
    }

    g_string_free(str, TRUE);

    return rc;

}

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
    GError             **err)
{
    GString            *str = NULL;
    char               ipaddr[20];
    size_t             rc;

    md_util_print_ip4_addr(ipaddr, stats->exporterIPv4Address);
    str = g_string_new("");

    if (no_stats != 2) {
        g_string_append_printf(str, "stats%c%"PRIu64"%c%"PRIu64"%c%"PRIu64"%c%"PRIu64"%c",
                               delim, stats->exportedFlowTotalCount, delim,
                               stats->packetTotalCount, delim,
                               stats->droppedPacketTotalCount, delim,
                               stats->ignoredPacketTotalCount, delim);
    } else {
        /* stats only */
        g_string_append_printf(str, "\\N%c%"PRIu64"%c%"PRIu64"%c%"PRIu64"%c%"PRIu64"%c", delim,
                               stats->exportedFlowTotalCount, delim,
                               stats->packetTotalCount, delim,
                               stats->droppedPacketTotalCount, delim,
                               stats->ignoredPacketTotalCount, delim);
    }

    g_string_append_printf(str, "%u%c%u%c%u%c%u%c%s%c",
                           stats->expiredFragmentCount, delim,
                           stats->assembledFragmentCount, delim,
                           stats->flowTableFlushEvents, delim,
                           stats->flowTablePeakCount, delim,
                           ipaddr, delim);
    g_string_append_printf(str, "%d%c%u%c%u%c%s\n",
                           stats->exportingProcessId, delim,
                           stats->meanFlowRate, delim,
                           stats->meanPacketRate, delim,
                           name);

    rc = fwrite(str->str, 1, str->len, lfp);

    if (rc != str->len) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                    "Error writing %d bytes to file: %s\n",
                    (unsigned int)str->len, strerror(errno));
        return 0;
    }

    g_string_free(str, TRUE);

    return rc;
}


/**
 * mdPrintBasicHeader
 *
 * appends a format header to the given GString
 *
 */
void mdPrintBasicHeader(
    GString *rstr,
    char delimiter)
{

    g_string_append_printf(rstr, "start-time%14c", delimiter);
    g_string_append_printf(rstr, "end-time%16c", delimiter);
    g_string_append_printf(rstr, "dur%6c", delimiter);
    g_string_append_printf(rstr, "rtt%6c", delimiter);
    g_string_append_printf(rstr, "pro%c", delimiter);
    g_string_append_printf(rstr, "sip%38c", delimiter);
    g_string_append_printf(rstr, "sp%4c", delimiter);
    g_string_append_printf(rstr, "pkt%6c", delimiter);
    g_string_append_printf(rstr, "oct%6c", delimiter);
    g_string_append_printf(rstr, "at%c", delimiter);
    g_string_append_printf(rstr, "srcMacAddr%8c", delimiter);
    g_string_append_printf(rstr, "dip%38c", delimiter);
    g_string_append_printf(rstr, "dp%4c", delimiter);
    g_string_append_printf(rstr, "rpkt%5c", delimiter);
    g_string_append_printf(rstr, "roct%5c", delimiter);
    g_string_append_printf(rstr, "ra%c", delimiter);
    g_string_append_printf(rstr, "destMacAddr%7c", delimiter);
    g_string_append_printf(rstr, "iflags%3c", delimiter);
    g_string_append_printf(rstr, "uflags%3c", delimiter);
    g_string_append_printf(rstr, "riflags%2c", delimiter);
    g_string_append_printf(rstr, "ruflags%2c", delimiter);
    g_string_append_printf(rstr, "isn%6c", delimiter);
    g_string_append_printf(rstr, "risn%5c", delimiter);
    g_string_append_printf(rstr, "in%4c", delimiter);
    g_string_append_printf(rstr, "out%3c", delimiter);
    g_string_append_printf(rstr, "tag%c", delimiter);
    g_string_append_printf(rstr, "app%3c", delimiter);
    g_string_append_printf(rstr, "tos%c", delimiter);
    g_string_append_printf(rstr, "end%4c", delimiter);
    g_string_append_printf(rstr, "collector");
    g_string_append(rstr,"\n");

}

int mdPrintDNSRecord(
    FILE             *fp,
    mdBuf_t          *buf,
    char             delimiter,
    uint8_t          *rec,
    gboolean         base64,
    gboolean         print_last,
    gboolean         escape_chars,
    GError           **err)
{
    char            sabuf[40];
    md_dns_t        *record = (md_dns_t *)rec;
    uint64_t        start_secs = record->fseen / 1000;
    uint32_t        start_rem = record->fseen % 1000;
    uint64_t        end_secs = record->lseen / 1000;
    uint32_t        end_rem = record->lseen % 1000;
    int             ret;
    size_t          rc;
    size_t          brem = buf->buflen - (buf->cp - buf->buf);
    gchar           *base1 = NULL;
    gchar           *base2 = NULL;


    if (!md_util_time_buf_append(buf, &brem, start_secs, PRINT_TIME_FMT)) {
        return 0;
    }
    ret = snprintf(buf->cp, brem, ".%03u%c", start_rem, delimiter);
    MD_WR_BDC0(ret, brem);
    buf->cp += ret;

    if (print_last) {
        if (!md_util_time_buf_append(buf, &brem, end_secs, PRINT_TIME_FMT)) {
            return 0;
        }
        ret = snprintf(buf->cp, brem, ".%03u%c", end_rem, delimiter);
        MD_WR_BDC0(ret, brem);
        buf->cp += ret;
    }

    ret = snprintf(buf->cp, brem, "%d%c", record->rrtype, delimiter);
    MD_WR_BDC0(ret, brem);
    buf->cp += ret;

    if (record->rrname.len) {
        if (base64) {
            base1 = g_base64_encode((const guchar *)record->rrname.buf,
                                    record->rrname.len-1);
            ret = snprintf(buf->cp, brem, "%s%c", base1, delimiter);
            MD_WR_BDC0(ret, brem);
            buf->cp += ret;
        } else {
            /* this is a dns dedup record so we have to subtract one
               from the name since we added one for the hash table
               (string hash requires null char at end of string) */
            if (escape_chars) {
                if (!mdPrintEscapeChars(buf, &brem, record->rrname.buf,
                                        record->rrname.len-1, delimiter)) {
                    return 0;
                }
            } else {
                if (!md_util_append_buffer(buf, &brem, record->rrname.buf,
                                           record->rrname.len-1)) {
                    return 0;
                }
            }
            if (brem > 1) {
                MD_APPEND_CHAR(buf, delimiter);
                brem += 1;
            } else { return 0;}
        }
    }

    if (print_last) {
        ret = snprintf(buf->cp, brem, "%d%c", record->hitcount, delimiter);
        MD_WR_BDC0(ret, brem);
        buf->cp += ret;
    }

    if (record->ip) {
        md_util_print_ip4_addr(sabuf, record->ip);
        ret = snprintf(buf->cp, brem, "%s", sabuf);
        MD_WR_BDC0(ret, brem);
        buf->cp += ret;
    } else if (record->rrtype == 28) {
        md_util_print_ip6_addr(sabuf, record->rrdata.buf);
        ret = snprintf(buf->cp, brem, "%s", sabuf);
        MD_WR_BDC0(ret, brem);
        buf->cp += ret;
    } else if (record->rrdata.len) {
        if (base64) {
            base2 = g_base64_encode((const guchar *)record->rrdata.buf,
                                    record->rrdata.len);
            ret = snprintf(buf->cp, brem, "%s", base2);
            MD_WR_BDC0(ret, brem);
            buf->cp += ret;
        } else {
            if (escape_chars) {
                if (!mdPrintEscapeChars(buf, &brem, record->rrdata.buf,
                                        record->rrdata.len, delimiter)) {
                    return 0;
                }
            } else {
                if (!md_util_append_buffer(buf, &brem, record->rrdata.buf,
                                           record->rrdata.len)) {
                    return 0;
                }
            }
        }
    }
    if (record->mapname.len) {
        if (brem > 1) {
            MD_APPEND_CHAR(buf, delimiter);
            brem += 1;
        } else { return 0; }
        if (!md_util_append_buffer(buf, &brem, record->mapname.buf,
                                   record->mapname.len)) {
            return 0;
        }
    }

    if (brem > 1) {
        MD_APPEND_CHAR(buf, '\n');
    } else { return 0; }

    rc = md_util_write_buffer(fp, buf, "", err);

    if (base1) {
        g_free(base1);
    }
    if (base2) {
        g_free(base2);
    }

    if (!rc) {
        return -1;
    }

    return rc;
}

int mdPrintDNSRRRecord(
    mdBuf_t          *buf,
    FILE             *fp,
    char             delimiter,
    uint8_t          *rec,
    gboolean         base64,
    gboolean         escape_chars,
    GError           **err)
{
    char            sabuf[40];
    mdDnsRR_t       *record = (mdDnsRR_t *)rec;
    uint64_t        start_secs = record->start / 1000;
    uint32_t        start_rem = record->start % 1000;
    size_t          rc;
    size_t          brem = buf->buflen - (buf->cp - buf->buf);
    int             ret;
    gchar           *base1 = NULL;
    gchar           *base2 = NULL;

    if (!md_util_time_buf_append(buf, &brem, start_secs, PRINT_TIME_FMT)) {
        return 0;
    }

    ret = snprintf(buf->cp, brem,".%03u%c%u%c%u%c", start_rem, delimiter,
                   record->hash, delimiter, record->obid, delimiter);

    MD_WR_BDC0(ret, brem);
    buf->cp += ret;

    if (record->sip) {
        md_util_print_ip4_addr(sabuf, record->sip);
    } else {
        md_util_print_ip6_addr(sabuf, record->sip6);
    }

    ret = snprintf(buf->cp, brem, "%s%c", sabuf, delimiter);
    MD_WR_BDC0(ret, brem);
    buf->cp += ret;

    if (record->dip) {
        md_util_print_ip4_addr(sabuf, record->dip);
    } else {
        md_util_print_ip6_addr(sabuf, record->sip6);
    }
    ret = snprintf(buf->cp, brem, "%s", sabuf);
    MD_WR_BDC0(ret, brem);
    buf->cp += ret;

    ret = snprintf(buf->cp, brem, "%c%d%c%d%c%d%c%d",
                   delimiter, record->proto,
                   delimiter, record->sp, delimiter,
                   record->dp, delimiter, record->vlan);
    MD_WR_BDC0(ret, brem);
    buf->cp += ret;

    if (record->qr) {
        /* this is a response */
        ret = snprintf(buf->cp, brem, "%cR%c%d%c", delimiter, delimiter,
                       record->id, delimiter);
    } else {
        ret = snprintf(buf->cp, brem, "%cQ%c%d%c", delimiter, delimiter,
                       record->id, delimiter);
    }
    MD_WR_BDC0(ret, brem);
    buf->cp += ret;

    /* section, nxdomain, auth, type, ttl */

    ret = snprintf(buf->cp, brem, "%d%c%d%c%d%c%d%c%u%c", record->rr,
                   delimiter, record->nx, delimiter, record->auth,
                   delimiter, record->type, delimiter, record->ttl,
                   delimiter);
    MD_WR_BDC0(ret, brem);
    buf->cp += ret;

    if (record->rrname.len) {
        if (base64) {
            base1 = g_base64_encode((const guchar *)record->rrname.buf,
                                    record->rrname.len);
            ret = snprintf(buf->cp, brem, "%s%c", base1, delimiter);
            MD_WR_BDC0(ret, brem);
            buf->cp += ret;
        } else {
            if (escape_chars) {
                mdPrintEscapeChars(buf, &brem, record->rrname.buf,
                                   record->rrname.len, delimiter);
            } else {
                if (!md_util_append_buffer(buf, &brem, record->rrname.buf,
                                           record->rrname.len)) {
                    return FALSE;
                }
            }
            if (brem > 1) {
                MD_APPEND_CHAR(buf, delimiter);
                brem += 1;
            } else { return FALSE;}
        }
    }

    if (record->rrdata.len) {
        if (record->type == 1) {
            uint32_t sip;
            memcpy(&sip, record->rrdata.buf, sizeof(uint32_t));
            md_util_print_ip4_addr(sabuf, sip);
            ret = snprintf(buf->cp, brem, "%s", sabuf);
            MD_WR_BDC0(ret, brem);
            buf->cp += ret;
        } else if (record->type == 28) {
            uint8_t sip[16];
            memcpy(sip, record->rrdata.buf, sizeof(sip));
            md_util_print_ip6_addr(sabuf, sip);
            ret = snprintf(buf->cp, brem, "%s", sabuf);
            MD_WR_BDC0(ret, brem);
            buf->cp += ret;
        } else {
            if (base64) {
                base2 = g_base64_encode((const guchar *)record->rrdata.buf,
                                        record->rrdata.len);
                ret = snprintf(buf->cp, brem, "%s", base2);
                MD_WR_BDC0(ret, brem);
                buf->cp += ret;
            } else {
                if (escape_chars) {
                    if (!mdPrintEscapeChars(buf, &brem, record->rrdata.buf,
                                            record->rrdata.len, delimiter)) {
                        return 0;
                    }
                } else {
                    if (!md_util_append_buffer(buf, &brem, record->rrdata.buf,
                                               record->rrdata.len)) {
                        return 0;
                    }
                }
            }
        }
    }

    if (brem > 1) {
        MD_APPEND_CHAR(buf, '\n');
    } else { return 0; }

    rc = md_util_write_buffer(fp, buf, "", err);

    if (base1) {
        g_free(base1);
    }
    if (base2) {
        g_free(base2);
    }

    if (!rc) {
        return -1;
    }

    return rc;


}


gboolean mdPrintEscapeChars(
    mdBuf_t  *mdbuf,
    size_t   *rem,
    uint8_t  *buf,
    size_t   buflen,
    char     delimiter)
{
    int i, ret;
    uint8_t ch;

    for (i = 0; i < (int)buflen; i++) {
        ch = buf[i];
        if (ch == '\\') {
            ret = snprintf(mdbuf->cp, *rem, "\\\\");
        } else if (ch < 32 || ch >= 127) {
            ret = snprintf(mdbuf->cp, *rem, "\\%03o", ch);
        } else if (ch == delimiter) {
            ret = snprintf(mdbuf->cp, *rem, "\\%c", ch);
        } else {
            ret = snprintf(mdbuf->cp, *rem, "%c", ch);
        }
        MD_WR_BDC(ret, *rem);
        mdbuf->cp += ret;
    }

    return TRUE;

}
gboolean mdPrintBasicList(
    mdBuf_t          *buf,
    GString          *index_str,
    fbBasicList_t    *bl,
    char             delimiter,
    gboolean         hex,
    gboolean         escape)
{

    uint16_t                w = 0;
    fbVarfield_t            *var = NULL;
    char                    hexdump[65534];
    size_t                  hexlen = sizeof(hexdump);
    size_t                  buflen;
    int                     ret;
    size_t                  brem = (buf->buflen - (buf->cp - buf->buf));

    for (w = 0;
         (var = (fbVarfield_t *)fbBasicListGetIndexedDataPtr(bl, w));
         w++) {

        if (var->len == 0) {
            continue;
        }

        if (index_str) {
            if (!md_util_append_gstr(buf, &brem, index_str)) {
                return FALSE;
            }
        }

        if (hex) {
            buflen = var->len;
            if (buflen > hexlen) {
                buflen = hexlen;
            }
            ret = md_util_hexdump_append(hexdump, &hexlen, var->buf, buflen);
            if (!ret) {
                return FALSE;
            }
            if (!md_util_append_buffer(buf, &brem, (uint8_t*)hexdump, ret)) {
                return FALSE;
            }
        } else {
            if (escape) {
                if (!mdPrintEscapeChars(buf, &brem, var->buf, var->len, delimiter)) {
                    return FALSE;
                }
            } else {
                if (!md_util_append_buffer(buf, &brem, var->buf, var->len)) {
                    return FALSE;
                }
            }
        }

        MD_APPEND_CHAR(buf, '\n');
    }
    return TRUE;

}

gboolean mdPrintVariableLength(
    mdBuf_t          *mdbuf,
    size_t           *brem,
    uint8_t          *buf,
    size_t           buflen,
    char             delimiter,
    gboolean         hex,
    gboolean         escape)
{

    char             hexdump[65534];
    size_t           hexlen = sizeof(hexdump);
    int              ret;

    if (!buflen || !buf) {
        return TRUE;
    }

    if (hex) {
        ret = md_util_hexdump_append(hexdump, &hexlen, buf, buflen);
        if (!md_util_append_buffer(mdbuf, brem, (uint8_t*)hexdump, ret)) {
            return FALSE;
        }
    } else {
        if (escape) {
            return mdPrintEscapeChars(mdbuf, brem, buf, buflen, delimiter);
        } else {
            if (!md_util_append_buffer(mdbuf, brem, buf, buflen)) {
                return FALSE;
            }
        }
    }

    return TRUE;
}

int mdPrintDedupRecord(
    FILE                *fp,
    mdBuf_t             *buf,
    md_dedup_t          *rec,
    char                delimiter,
    GError              **err)
{

    char     sabuf[40];
    uint64_t start_secs = rec->fseen / 1000;
    uint32_t start_rem = rec->fseen % 1000;
    uint64_t end_secs = rec->lseen / 1000;
    uint32_t end_rem = rec->lseen % 1000;
    uint64_t stime_secs = rec->stime /1000;
    uint32_t stime_rem = rec->stime % 1000;
    size_t brem = buf->buflen - (buf->cp - buf->buf);
    size_t  rc;
    int ret;

    if (!md_util_time_buf_append(buf, &brem, start_secs, PRINT_TIME_FMT)) {
        return 0;
    }

    ret = snprintf(buf->cp, brem, ".%03u%c", start_rem, delimiter);
    MD_WR_BDC0(ret, brem);
    buf->cp += ret;

    if (!md_util_time_buf_append(buf, &brem, end_secs, PRINT_TIME_FMT)) {
        return 0;
    }

    ret = snprintf(buf->cp, brem, ".%03u%c", end_rem, delimiter);
    MD_WR_BDC0(ret, brem);
    buf->cp += ret;

    if (rec->sip != rec->hash) {
        if (rec->sip == 0) {
            md_util_print_ip6_addr(sabuf, rec->sip6);
        } else {
            md_util_print_ip4_addr(sabuf, rec->sip);
        }
        ret = snprintf(buf->cp, brem,"%s%c", sabuf, delimiter);
    } else {
        /* configured to dedup on hash (not IP) */
        ret = snprintf(buf->cp, brem, "%u%c", rec->sip, delimiter);
    }

    MD_WR_BDC0(ret, brem);
    buf->cp += ret;

    /*stime for flow - with hash makes unique key */
    if (!md_util_time_buf_append(buf, &brem, stime_secs, PRINT_TIME_FMT)) {
        return 0;
    }

    ret = snprintf(buf->cp, brem, ".%03u%c", stime_rem, delimiter);
    MD_WR_BDC0(ret, brem);
    buf->cp += ret;

    /* hash, count */
    ret = snprintf(buf->cp, brem, "%u%c%"PRIu64"%c",
                   rec->hash, delimiter, rec->count, delimiter);
    MD_WR_BDC0(ret, brem);
    buf->cp += ret;

    if (rec->data.len) {
        if (!md_util_append_varfield(buf, &brem, &(rec->data))) {
            return 0;
        }
    } else if (rec->serial1.len) {
        ret = md_util_hexdump_append_nospace(buf->cp, &brem, rec->serial1.buf,
                                             rec->serial1.len);
        if (!ret) {
            return 0;
        }
        buf->cp += ret;

        if (brem > 1) {
            MD_APPEND_CHAR(buf, delimiter);
            brem += 1;
        } else { return 0; }

        if (!md_util_append_varfield(buf, &brem, &(rec->issuer1))) {
            return 0;
        }

        if (brem > 1) {
            MD_APPEND_CHAR(buf, delimiter);
            brem+=1;
        } else { return 0; }

        if (rec->serial2.len) {
            ret = md_util_hexdump_append_nospace(buf->cp, &brem, rec->serial2.buf,
                                                 rec->serial2.len);
            if (!ret) {
                return 0;
            }
            buf->cp += ret;

            if (brem > 1) {
                MD_APPEND_CHAR(buf, delimiter);
                brem += 1;
            } else { return 0; }

            if (!md_util_append_varfield(buf, &brem, &(rec->issuer2))) {
                return 0;
            }
        } else {

            if (brem > 1) {
                MD_APPEND_CHAR(buf, delimiter);
                brem += 1;
            } else { return 0; }
        }
    }

    /* PRINT MAPNAME if available */
    if (rec->mapname.len) {
        if (brem > 1) {
            MD_APPEND_CHAR(buf, delimiter);
            brem += 1;
        } else { return 0; }
        if (!md_util_append_varfield(buf, &brem, &(rec->mapname))) {
            return 0;
        }
    }

    if (brem > 1) {
        MD_APPEND_CHAR(buf, '\n');
    } else { return 0; }

    rc = md_util_write_buffer(fp, buf, "", err);

    if (!rc) {
        return -1;
    }

    return rc;
}

int mdPrintSSLDedupRecord(
    FILE      *fp,
    mdBuf_t   *buf,
    uint8_t   *rec,
    char      delimiter,
    GError    **err)
{

    md_ssl_t *ssl = (md_ssl_t *)rec;
    uint64_t start_secs = ssl->fseen / 1000;
    uint32_t start_rem = ssl->fseen % 1000;
    uint64_t end_secs = ssl->lseen / 1000;
    uint32_t end_rem = ssl->lseen % 1000;
    size_t brem = buf->buflen - (buf->cp - buf->buf);
    size_t  rc;
    int ret;


    if (!md_util_time_buf_append(buf, &brem, start_secs, PRINT_TIME_FMT)) {
        return 0;
    }
    ret = snprintf(buf->cp, brem, ".%03u%c", start_rem, delimiter);
    MD_WR_BDC0(ret, brem);
    buf->cp += ret;

    if (!md_util_time_buf_append(buf, &brem, end_secs, PRINT_TIME_FMT)) {
        return 0;
    }
    ret = snprintf(buf->cp, brem, ".%03u%c", end_rem, delimiter);
    MD_WR_BDC0(ret, brem);
    buf->cp += ret;

    ret = md_util_hexdump_append_nospace(buf->cp, &brem,
                                         ssl->serial.buf, ssl->serial.len);
    if (!ret) {
        return 0;
    }
    buf->cp += ret;

    ret = snprintf(buf->cp, brem, "%c%"PRIu64"%c", delimiter, ssl->hitcount,
                   delimiter);
    MD_WR_BDC0(ret, brem);
    buf->cp += ret;

    if (!md_util_append_varfield(buf, &brem, &(ssl->issuer))) {
        return 0;
    }

    if (ssl->mapname.len) {
        if (brem > 1) {
            MD_APPEND_CHAR(buf, delimiter);
            brem += 1;
        }
        if (!md_util_append_varfield(buf, &brem, &(ssl->mapname))) {
            return 0;
        }
    }

    if (brem > 1) {
        MD_APPEND_CHAR(buf, '\n');
    } else {
        return 0;
    }

    rc = md_util_write_buffer(fp, buf, "", err);

    if (!rc) {
        return -1;
    }

    return rc;
}


void mdPrintEscapeStrChars(
    GString     *str,
    uint8_t     *buf,
    size_t      buflen,
    char        delimiter)
{
    int i;
    uint8_t ch;

    for (i = 0; i < (int)buflen; i++) {
        ch = buf[i];
        if (ch == '\\') {
            g_string_append(str, "\\\\");
        } else if (ch < 32 || ch >= 127) {
            g_string_append_printf(str, "\\%03o", ch);
        } else if (ch == delimiter) {
            g_string_append_printf(str, "\\%c", ch);
        } else {
            g_string_append_c(str, ch);
        }

    }
}
