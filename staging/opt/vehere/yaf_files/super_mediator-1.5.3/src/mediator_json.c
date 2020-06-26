/**
 * @file mediator_json.c
 *
 * Contains most of the JSON-y functions.
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
 * NO WARRANTY
 *
 * ANY INFORMATION, MATERIALS, SERVICES, INTELLECTUAL PROPERTY OR OTHER
 * PROPERTY OR RIGHTS GRANTED OR PROVIDED BY CARNEGIE MELLON UNIVERSITY
 * PURSUANT TO THIS LICENSE (HEREINAFTER THE "DELIVERABLES") ARE ON AN
 * "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY
 * KIND, EITHER EXPRESS OR IMPLIED AS TO ANY MATTER INCLUDING, BUT NOT
 * LIMITED TO, WARRANTY OF FITNESS FOR A PARTICULAR PURPOSE,
 * MERCHANTABILITY, INFORMATIONAL CONTENT, NONINFRINGEMENT, OR ERROR-FREE
 * OPERATION. CARNEGIE MELLON UNIVERSITY SHALL NOT BE LIABLE FOR INDIRECT,
 * SPECIAL OR CONSEQUENTIAL DAMAGES, SUCH AS LOSS OF PROFITS OR INABILITY
 * TO USE SAID INTELLECTUAL PROPERTY, UNDER THIS LICENSE, REGARDLESS OF
 * WHETHER SUCH PARTY WAS AWARE OF THE POSSIBILITY OF SUCH DAMAGES.
 * LICENSEE AGREES THAT IT WILL NOT MAKE ANY WARRANTY ON BEHALF OF
 * CARNEGIE MELLON UNIVERSITY, EXPRESS OR IMPLIED, TO ANY PERSON
 * CONCERNING THE APPLICATION OF OR THE RESULTS TO BE OBTAINED WITH THE
 * DELIVERABLES UNDER THIS LICENSE.
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
 * Carnegie Mellon University Software Engineering Institute authored
 * documents are sponsored by the U.S. Department of Defense under
 * Contract FA8721-05-C-0003. Carnegie Mellon University retains
 * copyrights in all material produced under this contract. The U.S.
 * Government retains a non-exclusive, royalty-free license to publish or
 * reproduce these documents, or allow othersto do so, for U.S.
 * Government purposes only pursuant to the copyright license under the
 * contract clause at 252.227.7013.
 *
 *
 * @OPENSOURCE_HEADER_END@
 * -----------------------------------------------------------
 */

#include <mediator/mediator_ctx.h>
#include <mediator/mediator_util.h>
#include <mediator/mediator_inf.h>
#include "mediator_print.h"
#include "mediator_json.h"

#define FBSTLNEXT(a, b) fbSubTemplateListGetNextPtr(a, b)
#define MD_REM_MSG(_buf_) (buf->buflen - (_buf_->cp - _buf_->buf))

#define MD_WR_BDC(_ret_, _size_)             \
    if (_ret_ < 0) return FALSE;             \
    if ((size_t)_ret_ >= _size_) return FALSE;  \
    _size_ -= _ret_;

#define MD_CHECK_RET(_buf_, _ret_, _size_)    \
    if (_ret_ < 0) return FALSE;              \
    if ((size_t)_ret_ >= _size_) return FALSE;  \
    _size_ -= _ret_;                          \
    _buf_->cp += _ret_;

#define MD_CHECK_RET0(_buf_, _ret_, _size_)    \
    if (_ret_ < 0) return 0;                  \
    if ((size_t)_ret_ >= _size_) return 0;    \
    _size_ -= _ret_;                          \
    _buf_->cp += _ret_;

#define MD_APPEND_CHAR(_buf_, _ch_)           \
    *(_buf_->cp) = _ch_;                      \
    ++(_buf_->cp);
#define MD_APPEND_CHAR_CHECK(_rem_, _buf_, _ch_)        \
    if (_rem_ > 1) {                           \
        MD_APPEND_CHAR(_buf_, _ch_);           \
        _rem_ -= 1;                            \
    } else {                                   \
        return FALSE;                          \
    }


/* RFC 4627 -
Any character may be escaped.  If the character is in the Basic
   Multilingual Plane (U+0000 through U+FFFF), then it may be
   represented as a six-character sequence: a reverse solidus, followed
   by the lowercase letter u, followed by four hexadecimal digits that
   encode the character's code point.  The hexadecimal letters A though
   F can be upper or lowercase.  So, for example, a string containing
   only a single reverse solidus character may be represented as
   "\u005C".
*/

gboolean mdJsonifyEscapeChars(
    mdBuf_t  *mdbuf,
    size_t   *rem,
    uint8_t  *buf,
    size_t   buflen)
{
    int i, ret;
    uint8_t ch;

    for (i = 0; i < (int)buflen; i++) {
        ch = buf[i];
        if (ch == '\\') {
            ret = snprintf(mdbuf->cp, *rem, "\\\\");
        } else if (ch < 32 || ch >= 127) {
            ret = snprintf(mdbuf->cp, *rem, "\\u%04x", ch);
        } else if (ch == '"') {
            ret = snprintf(mdbuf->cp, *rem, "\\%c", ch);
        } else {
            ret = snprintf(mdbuf->cp, *rem, "%c", ch);
        }
        MD_WR_BDC(ret, *rem);
        mdbuf->cp += ret;
    }

    return TRUE;

}

gboolean mdJsonifyDNSRRRecord(
    mdDnsRR_t          *rec,
    mdBuf_t            *buf)
{
    size_t brem = MD_REM_MSG(buf);
    size_t buftest;
    uint64_t start_secs = rec->start / 1000;
    uint32_t start_rem = rec->start % 1000;
    char     sabuf[40];
    char    testsip[16];
    int ret;

    ret = snprintf(buf->cp, brem, "{\"dns\":{\"flowStartMilliseconds\":\"");
    MD_CHECK_RET0(buf, ret, brem);

    memset(testsip, 0, sizeof(testsip));

    if (!md_util_time_buf_append(buf, &brem, start_secs, PRINT_TIME_FMT)) {
        return 0;
    }

    ret = snprintf(buf->cp, brem, ".%03u\",", start_rem);

    MD_CHECK_RET0(buf, ret, brem);

    if (rec->sip == 0) {
        if (memcmp(rec->sip6, testsip, sizeof(rec->sip6))) {
            md_util_print_ip6_addr(sabuf, rec->sip6);
            ret = snprintf(buf->cp, brem, "\"sourceIPv6Address\":\"%s\",", sabuf);
            MD_CHECK_RET0(buf, ret, brem);
            md_util_print_ip6_addr(sabuf, rec->dip6);
            ret = snprintf(buf->cp, brem, "\"destinationIPv6Address\":\"%s\",", sabuf);
            MD_CHECK_RET0(buf, ret, brem);
        }
    } else {
        md_util_print_ip4_addr(sabuf, rec->sip);
        ret = snprintf(buf->cp, brem, "\"sourceIPv4Address\":\"%s\",", sabuf);
        MD_CHECK_RET0(buf, ret, brem);
        md_util_print_ip4_addr(sabuf, rec->dip);
        ret = snprintf(buf->cp, brem, "\"destinationIPv4Address\":\"%s\",", sabuf);
        MD_CHECK_RET0(buf, ret, brem);

    }

    if (rec->proto) {
        ret = snprintf(buf->cp, brem, "\"protocolIdentifier\":%d,", rec->proto);
        MD_CHECK_RET0(buf, ret, brem);
    }

    if (rec->vlan) {
        ret = snprintf(buf->cp, brem, "\"vlanId\":\"%u,", rec->vlan);
        MD_CHECK_RET0(buf, ret, brem);
    }

    if (rec->sp) {
        ret = snprintf(buf->cp, brem, "\"sourceTransportPort\":%d,", rec->sp);
        MD_CHECK_RET0(buf, ret, brem);
    }

    if (rec->dp) {
        ret = snprintf(buf->cp,brem, "\"destinationTransportPort\":%d,", rec->dp);
        MD_CHECK_RET0(buf, ret,brem);
    }

    if (rec->hash) {
        ret = snprintf(buf->cp,brem, "\"flowKeyHash\":%u,", rec->hash);
        MD_CHECK_RET0(buf, ret,brem);
    }

    if (rec->obid) {
        ret = snprintf(buf->cp, brem, "\"observationDomainId\":%u,", rec->obid);
        MD_CHECK_RET0(buf, ret, brem);
    }

    ret = snprintf(buf->cp, brem, "\"dnsRRSection\":%d,\"dnsNXDomain\":%d,",
                   rec->rr, rec->nx);
    MD_CHECK_RET(buf, ret, brem);

    if (rec->auth) {
        ret = snprintf(buf->cp, brem, "\"dnsAuthoritative\":\"True\",");
    } else {
        ret = snprintf(buf->cp, brem, "\"dnsAuthoritative\":\"False\",");
    }
    MD_CHECK_RET(buf, ret, brem);

    ret = snprintf(buf->cp, brem, "\"dnsQRType\":%d, \"dnsTTL\":%u, "
                   "\"dnsID\":%d,",
                   rec->type, rec->ttl, rec->id);

    MD_CHECK_RET(buf, ret, brem);

    if (rec->rrname.buf) {
        ret = snprintf(buf->cp, brem, "\"dnsQName\":\"");
        MD_CHECK_RET(buf, ret, brem);
        mdJsonifyEscapeChars(buf, &brem, rec->rrname.buf, rec->rrname.len);
        ret = snprintf(buf->cp, brem, "\",");
        MD_CHECK_RET(buf, ret, brem);
    } /* else - query may be for the root server which is NULL*/

    buftest = MD_REM_MSG(buf);

    if (rec->qr == 0) {
        /* query */
        buf->cp -= 1;
        brem += 1;
        MD_APPEND_CHAR_CHECK(brem, buf, '}');
        MD_APPEND_CHAR_CHECK(brem, buf, '}');
        MD_APPEND_CHAR_CHECK(brem, buf, '\n');

        return TRUE;
    }

    if (rec->type == 1) {
        uint32_t sip;
        if (rec->rrdata.len) {
            memcpy(&sip, rec->rrdata.buf, sizeof(uint32_t));
            md_util_print_ip4_addr(sabuf, sip);
            ret = snprintf(buf->cp, brem, "\"A\":\"%s\"", sabuf);
            MD_CHECK_RET(buf, ret, brem);
        }
    } else if (rec->type == 2) {
        ret = snprintf(buf->cp, brem, "\"dnsNSDName\":\"");
        MD_CHECK_RET(buf, ret, brem);
        mdJsonifyEscapeChars(buf, &brem, rec->rrdata.buf,
                             rec->rrdata.len);
        MD_APPEND_CHAR_CHECK(brem, buf, '\"');

    } else if (rec->type == 5) {
        ret = snprintf(buf->cp, brem, "\"dnsCName\":\"");
        MD_CHECK_RET(buf, ret, brem);
        mdJsonifyEscapeChars(buf, &brem, rec->rrdata.buf,
                             rec->rrdata.len);
        MD_APPEND_CHAR_CHECK(brem, buf, '\"');
    } else if (rec->type == 12) {
        ret = snprintf(buf->cp, brem, "\"dnsPTRDName\":\"");
        MD_CHECK_RET(buf, ret, brem);
        mdJsonifyEscapeChars(buf, &brem, rec->rrdata.buf,
                             rec->rrdata.len);
        MD_APPEND_CHAR_CHECK(brem, buf, '\"');
    } else if (rec->type == 15) {
        ret = snprintf(buf->cp, brem, "\"dnsMXExchange\":\"");
        MD_CHECK_RET(buf, ret, brem);
        mdJsonifyEscapeChars(buf, &brem, rec->rrdata.buf,
                             rec->rrdata.len);
        MD_APPEND_CHAR_CHECK(brem, buf, '\"');
    } else if (rec->type == 28) {
        uint8_t sip[16];
        if (rec->rrdata.len) {
            memcpy(sip, rec->rrdata.buf, sizeof(sip));
            md_util_print_ip6_addr(sabuf, sip);
            ret = snprintf(buf->cp, brem, "\"AAAA\":\"%s\"", sabuf);
            MD_CHECK_RET(buf, ret, brem);
        }
    } else if (rec->type == 16) {
        ret = snprintf(buf->cp, brem, "\"dnsTXTData\":\"");
        MD_CHECK_RET(buf, ret, brem);
        mdJsonifyEscapeChars(buf, &brem, rec->rrdata.buf,
                             rec->rrdata.len);
        MD_APPEND_CHAR_CHECK(brem, buf, '\"');
    } else if (rec->type == 33) {
        ret = snprintf(buf->cp, brem, "\"dnsSRVTarget\":\"");
        MD_CHECK_RET(buf, ret, brem);
        mdJsonifyEscapeChars(buf, &brem, rec->rrdata.buf,
                             rec->rrdata.len);
        MD_APPEND_CHAR_CHECK(brem, buf, '\"');
    } else if (rec->type == 6) {
        ret = snprintf(buf->cp, brem, "\"dnsSOAMName\":\"");
        MD_CHECK_RET(buf, ret, brem);
        mdJsonifyEscapeChars(buf, &brem, rec->rrdata.buf,
                             rec->rrdata.len);
        MD_APPEND_CHAR_CHECK(brem, buf, '\"');
    } else if (rec->type == 46) {
        ret = snprintf(buf->cp, brem, "\"dnsSigner\":\"");
        MD_CHECK_RET(buf, ret, brem);
        mdJsonifyEscapeChars(buf, &brem, rec->rrdata.buf,
                             rec->rrdata.len);
        MD_APPEND_CHAR_CHECK(brem, buf, '\"');
    } else if (rec->type == 47) {
        ret = snprintf(buf->cp, brem, "\"dnsHashData\":\"");
        MD_CHECK_RET(buf, ret, brem);
        mdJsonifyEscapeChars(buf, &brem, rec->rrdata.buf,
                             rec->rrdata.len);
        MD_APPEND_CHAR_CHECK(brem, buf, '\"');
    }

    brem = MD_REM_MSG(buf);

    /* no rrname/rrdata */
    if (brem == buftest) {
        /* remove the comma at the end of dnsQName */
        buf->cp -= 1;
        brem += 1;
    }

    MD_APPEND_CHAR_CHECK(brem, buf, '}');
    MD_APPEND_CHAR_CHECK(brem, buf, '}');
    MD_APPEND_CHAR_CHECK(brem, buf, '\n');
    return TRUE;

}



gboolean mdJsonifyDNSRecord(
    yfDNSQRFlow_t     *dns,
    mdBuf_t           *buf)
{
    size_t brem = MD_REM_MSG(buf);
    size_t buftest;
    int ret;

    ret = snprintf(buf->cp, brem, "\"dnsRRSection\":%d,\"dnsNXDomain\":%d,",
                   dns->dnsRRSection, dns->dnsNXDomain);
    MD_CHECK_RET(buf, ret, brem);

    if (dns->dnsAuthoritative) {
        ret = snprintf(buf->cp, brem, "\"dnsAuthoritative\":\"True\",");
    } else {
        ret = snprintf(buf->cp, brem, "\"dnsAuthoritative\":\"False\",");
    }
    MD_CHECK_RET(buf, ret, brem);

    ret = snprintf(buf->cp, brem, "\"dnsQRType\":%d, \"dnsTTL\":%u, \"dnsID\":%d,",
                   dns->dnsQRType, dns->dnsTTL, dns->dnsID);

    MD_CHECK_RET(buf, ret, brem);

    if (dns->dnsQName.buf) {
        ret = snprintf(buf->cp, brem, "\"dnsQName\":\"");
        MD_CHECK_RET(buf, ret, brem);
        mdJsonifyEscapeChars(buf, &brem, dns->dnsQName.buf, dns->dnsQName.len);
        ret = snprintf(buf->cp, brem, "\",");
        MD_CHECK_RET(buf, ret, brem);
    } /* else - query may be for the root server which is NULL*/

    buftest = MD_REM_MSG(buf);

    if (dns->dnsQRType == 1) {
        yfDNSAFlow_t *aflow = NULL;
        char ipaddr[20];
        while ((aflow = (yfDNSAFlow_t *)FBSTLNEXT(&(dns->dnsRRList), aflow))) {
            if (aflow->ip) {
                md_util_print_ip4_addr(ipaddr, aflow->ip);
                ret = snprintf(buf->cp, brem, "\"A\":\"%s\"", ipaddr);
                MD_CHECK_RET(buf, ret, brem);
            }
        }
    } else if (dns->dnsQRType == 2) {
        yfDNSNSFlow_t *ns = NULL;
        while ((ns = (yfDNSNSFlow_t *)FBSTLNEXT(&(dns->dnsRRList), ns))){
            ret = snprintf(buf->cp, brem, "\"dnsNSDName\":\"");
            MD_CHECK_RET(buf, ret, brem);
            mdJsonifyEscapeChars(buf, &brem, ns->nsdname.buf,
                                      ns->nsdname.len);
            MD_APPEND_CHAR_CHECK(brem, buf, '\"');
        }

    } else if (dns->dnsQRType == 5) {
        yfDNSCNameFlow_t *c = NULL;
        while ((c = (yfDNSCNameFlow_t *)FBSTLNEXT(&(dns->dnsRRList), c)))
        {
            ret = snprintf(buf->cp, brem, "\"dnsCName\":\"");
            MD_CHECK_RET(buf, ret, brem);
            mdJsonifyEscapeChars(buf, &brem, c->cname.buf,
                                  c->cname.len);
            MD_APPEND_CHAR_CHECK(brem, buf, '\"');
        }
    } else if (dns->dnsQRType == 12) {
        yfDNSPTRFlow_t *ptr = NULL;
        while ((ptr = (yfDNSPTRFlow_t *)FBSTLNEXT(&(dns->dnsRRList), ptr)))
        {
            ret = snprintf(buf->cp, brem, "\"dnsPTRDName\":\"");
            MD_CHECK_RET(buf, ret, brem);
            mdJsonifyEscapeChars(buf, &brem, ptr->ptrdname.buf,
                                      ptr->ptrdname.len);
            MD_APPEND_CHAR_CHECK(brem, buf, '\"');
        }
    } else if (dns->dnsQRType == 15) {
        yfDNSMXFlow_t *mx = NULL;
        while (( mx = (yfDNSMXFlow_t *)FBSTLNEXT(&(dns->dnsRRList), mx)))
        {
            ret = snprintf(buf->cp, brem, "\"dnsMXExchange\":\"");
            MD_CHECK_RET(buf, ret, brem);
            mdJsonifyEscapeChars(buf, &brem, mx->exchange.buf,
                                  mx->exchange.len);
            MD_APPEND_CHAR_CHECK(brem, buf, '\"');
        }
    } else if (dns->dnsQRType == 28) {
        yfDNSAAAAFlow_t *aa = NULL;
        char ipaddr[40];
        while ((aa = (yfDNSAAAAFlow_t *)FBSTLNEXT(&(dns->dnsRRList), aa)))
        {
            md_util_print_ip6_addr(ipaddr,(uint8_t *)&(aa->ip));
            ret = snprintf(buf->cp, brem, "\"AAAA\":\"%s\"", ipaddr);
            MD_CHECK_RET(buf, ret, brem);
        }
    } else if (dns->dnsQRType == 16) {
        yfDNSTXTFlow_t *txt = NULL;
        while ((txt = (yfDNSTXTFlow_t *)FBSTLNEXT(&(dns->dnsRRList), txt)))
        {
            ret = snprintf(buf->cp, brem, "\"dnsTXTData\":\"");
            MD_CHECK_RET(buf, ret, brem);
            mdJsonifyEscapeChars(buf, &brem, txt->txt_data.buf,
                                  txt->txt_data.len);
            MD_APPEND_CHAR_CHECK(brem, buf, '\"');
        }
    } else if (dns->dnsQRType == 33) {
        yfDNSSRVFlow_t *srv = NULL;
        while ((srv = (yfDNSSRVFlow_t *)FBSTLNEXT(&(dns->dnsRRList), srv)))
        {
            ret = snprintf(buf->cp, brem, "\"dnsSRVTarget\":\"");
            MD_CHECK_RET(buf, ret, brem);
            mdJsonifyEscapeChars(buf, &brem,srv->dnsTarget.buf,
                                      srv->dnsTarget.len);
            MD_APPEND_CHAR_CHECK(brem, buf, '\"');
        }
    } else if (dns->dnsQRType == 6) {
        yfDNSSOAFlow_t *soa = NULL;
        while ((soa = (yfDNSSOAFlow_t *)FBSTLNEXT(&(dns->dnsRRList), soa))) {
            ret = snprintf(buf->cp, brem, "\"dnsSOAMName\":\"");
            MD_CHECK_RET(buf, ret, brem);
            mdJsonifyEscapeChars(buf, &brem,soa->mname.buf,
                                      soa->mname.len);
            MD_APPEND_CHAR_CHECK(brem, buf, '\"');
        }
    } else if (dns->dnsQRType == 46) {
        yfDNSRRSigFlow_t *rr = NULL;
        while ((rr = (yfDNSRRSigFlow_t *)FBSTLNEXT(&(dns->dnsRRList), rr))) {
            ret = snprintf(buf->cp, brem, "\"dnsSigner\":\"");
            MD_CHECK_RET(buf, ret, brem);
            mdJsonifyEscapeChars(buf, &brem, rr->dnsSigner.buf,
                                      rr->dnsSigner.len);
            MD_APPEND_CHAR_CHECK(brem, buf, '\"');
        }
    } else if (dns->dnsQRType == 47) {
        yfDNSNSECFlow_t *nsec = NULL;
        while ((nsec = (yfDNSNSECFlow_t *)FBSTLNEXT(&(dns->dnsRRList), nsec)))
        {
            ret = snprintf(buf->cp, brem, "\"dnsHashData\":\"");
            MD_CHECK_RET(buf, ret, brem);
            mdJsonifyEscapeChars(buf, &brem, nsec->dnsHashData.buf,
                                      nsec->dnsHashData.len);
            MD_APPEND_CHAR_CHECK(brem, buf, '\"');
        }
    }

    brem = MD_REM_MSG(buf);

    /* no rrname/rrdata */
    if (brem == buftest) {
        /* remove the comma at the end of dnsQName */
        buf->cp -= 1;
        brem += 1;
    }

    return TRUE;

}

size_t mdPrintJsonStats(
    yfIpfixStats_t  *stats,
    char            *name,
    FILE            *lfp,
    GError          **err)
{

    GString *str = NULL;
    char ipaddr[20];
    size_t rc;

    md_util_print_ip4_addr(ipaddr, stats->exporterIPv4Address);
    str = g_string_new("");

    g_string_append(str, "{\"stats\":{");

    g_string_append_printf(str, "\"exportedFlowTotalCount\":%"PRIu64",",
            stats->exportedFlowTotalCount);
    g_string_append_printf(str, "\"packetTotalCount\":%"PRIu64",",
            stats->packetTotalCount);
    g_string_append_printf(str, "\"droppedPacketTotalCount\":%"PRIu64",",
            stats->droppedPacketTotalCount);
    g_string_append_printf(str, "\"ignoredPacketTotalCount\":%"PRIu64",",
            stats->ignoredPacketTotalCount);
    g_string_append_printf(str, "\"expiredFragmentCount\":%u,",
            stats->expiredFragmentCount);
    g_string_append_printf(str, "\"assembledFragmentCount\":%u,",
            stats->assembledFragmentCount);
    g_string_append_printf(str, "\"flowTableFlushEvents\":%u,",
            stats->flowTableFlushEvents);
    g_string_append_printf(str, "\"flowTablePeakCount\":%u,",
            stats->flowTablePeakCount);
    g_string_append_printf(str, "\"exporterIPv4Address\":\"%s\",", ipaddr);
    g_string_append_printf(str, "\"exportingProcessId\":%d,",
            stats->exportingProcessId);
    g_string_append_printf(str, "\"meanFlowRate\":%u,",
            stats->meanFlowRate);
    g_string_append_printf(str, "\"meanPacketRate\":%u,",
            stats->meanPacketRate);
    g_string_append_printf(str, "\"exporterName\":\"%s\"", name);

    g_string_append(str, "}}\n");

    if (lfp != NULL){
    	rc = fwrite(str->str, 1, str->len, lfp);
    }

    if (rc != str->len) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                "Error writing %d b ytes to file: %s\n",
                (unsigned int)str->len, strerror(errno));
        return 0;
    }

    g_string_free(str, TRUE);

    return rc;
}

int mdJsonifyDNSDedupRecord(
    FILE        *fp,
    mdBuf_t     *buf,
    uint8_t     *rec,
    gboolean    print_last,
    gboolean    base64,
    GError      **err)
{
    size_t rc = 0;
    char sabuf[40];
    md_dns_t *record = (md_dns_t *)rec;
    uint64_t start_secs = record->fseen / 1000;
    uint32_t start_rem = record->fseen % 1000;
    uint64_t end_secs = record->lseen / 1000;
    uint32_t end_rem = record->lseen % 1000;
    gchar *base1 = NULL;
    size_t brem = MD_REM_MSG(buf);
    gboolean encode = FALSE;
    int ret;

    ret = snprintf(buf->cp, brem, "{\"dns\":{\"flowStartMilliseconds\":\"");
    MD_CHECK_RET0(buf, ret, brem);

    if (!md_util_time_buf_append(buf, &brem, start_secs, PRINT_TIME_FMT)) {
        return 0;
    }

    ret = snprintf(buf->cp, brem, ".%03u\",", start_rem);

    MD_CHECK_RET0(buf, ret, brem);

    if (print_last) {
        ret = snprintf(buf->cp, brem, "\"flowEndMilliseconds\":\"");
        MD_CHECK_RET0(buf, ret, brem);

        if (!md_util_time_buf_append(buf, &brem, end_secs, PRINT_TIME_FMT)) {
            return 0;
        }

        ret = snprintf(buf->cp, brem, ".%03u\",", end_rem);
        MD_CHECK_RET0(buf, ret, brem);
    }

    ret = snprintf(buf->cp, brem, "\"dnsQRType\":%d,", record->rrtype);
    MD_CHECK_RET0(buf, ret, brem);

    if (print_last) {
        ret = snprintf(buf->cp, brem, "\"dnsHitCount\":%d,\"dnsTTL\":%d,",
                       record->hitcount, record->ttl);
        MD_CHECK_RET0(buf, ret, brem);
    }

    if (record->rrname.len) {

        if (base64) {
            base1 = g_base64_encode((const guchar *)record->rrname.buf,
                    record->rrname.len-1);
            ret = snprintf(buf->cp, brem, "\"dnsQName\":\"%s\",", base1);
            MD_CHECK_RET0(buf, ret, brem);
            g_free(base1);
        } else {
            ret = snprintf(buf->cp, brem, "\"dnsQName\":\"");
            MD_CHECK_RET0(buf, ret, brem);
            if (!mdJsonifyEscapeChars(buf, &brem, (uint8_t *)record->rrname.buf,
                                    record->rrname.len-1)) {
                return 0;
            }
            if (brem > 2) {
                MD_APPEND_CHAR(buf, '\"');
                MD_APPEND_CHAR(buf, ',');
            }
        }
    }

    if (record->rrtype == 1) {
        if (record->ip) {
            md_util_print_ip4_addr(sabuf, record->ip);
            ret = snprintf(buf->cp, brem, "\"A\":\"%s\"", sabuf);
            MD_CHECK_RET0(buf, ret, brem);
        }
    } else if (record->rrtype == 2) {
        ret = snprintf(buf->cp, brem, "\"dnsNSDName\":\"");
        MD_CHECK_RET(buf, ret, brem);
        if (base64) {
            encode = TRUE;
        }  else {
            mdJsonifyEscapeChars(buf, &brem, record->rrdata.buf,
                                 record->rrdata.len);
            MD_APPEND_CHAR_CHECK(brem, buf, '\"');
        }

    } else if (record->rrtype == 5) {
        ret = snprintf(buf->cp, brem, "\"dnsCName\":\"");
        MD_CHECK_RET(buf, ret, brem);
        if (base64) {
            encode = TRUE;
        }  else {
            mdJsonifyEscapeChars(buf, &brem, record->rrdata.buf,
                                 record->rrdata.len);
            MD_APPEND_CHAR_CHECK(brem, buf, '\"');
        }
    } else if (record->rrtype == 12) {
        ret = snprintf(buf->cp, brem, "\"dnsPTRDName\":\"");
        MD_CHECK_RET(buf, ret, brem);
        if (base64) {
            encode = TRUE;
        }  else {
            mdJsonifyEscapeChars(buf, &brem, record->rrdata.buf,
                                 record->rrdata.len);
            MD_APPEND_CHAR_CHECK(brem, buf, '\"');
        }
    } else if (record->rrtype == 15) {
        ret = snprintf(buf->cp, brem, "\"dnsMXExchange\":\"");
        MD_CHECK_RET(buf, ret, brem);
        if (base64) {
            encode = TRUE;
        }  else {
            mdJsonifyEscapeChars(buf, &brem, record->rrdata.buf,
                                 record->rrdata.len);
            MD_APPEND_CHAR_CHECK(brem, buf, '\"');
        }
    } else if (record->rrtype == 28) {
        md_util_print_ip6_addr(sabuf, record->rrdata.buf);
        ret = snprintf(buf->cp, brem, "\"AAAA\":\"%s\"", sabuf);
        MD_CHECK_RET0(buf, ret, brem);
    } else if (record->rrtype == 16) {
        ret = snprintf(buf->cp, brem, "\"dnsTXTData\":\"");
        MD_CHECK_RET(buf, ret, brem);
        if (base64) {
            encode = TRUE;
        }  else {
            mdJsonifyEscapeChars(buf, &brem, record->rrdata.buf,
                                 record->rrdata.len);
            MD_APPEND_CHAR_CHECK(brem, buf, '\"');
        }
    } else if (record->rrtype == 33) {
        ret = snprintf(buf->cp, brem, "\"dnsSRVTarget\":\"");
        MD_CHECK_RET(buf, ret, brem);
        if (base64) {
            encode = TRUE;
        }  else {
            mdJsonifyEscapeChars(buf, &brem, record->rrdata.buf,
                                 record->rrdata.len);
            MD_APPEND_CHAR_CHECK(brem, buf, '\"');
        }
    } else if (record->rrtype == 6) {
        ret = snprintf(buf->cp, brem, "\"dnsSOAMName\":\"");
        MD_CHECK_RET(buf, ret, brem);
        if (base64) {
            encode = TRUE;
        }  else {
            mdJsonifyEscapeChars(buf, &brem, record->rrdata.buf,
                                 record->rrdata.len);
            MD_APPEND_CHAR_CHECK(brem, buf, '\"');
        }
    } else if (record->rrtype == 46) {
        ret = snprintf(buf->cp, brem, "\"dnsSigner\":\"");
        MD_CHECK_RET(buf, ret, brem);
        if (base64) {
            encode = TRUE;
        }  else {
            mdJsonifyEscapeChars(buf, &brem, record->rrdata.buf,
                                 record->rrdata.len);
            MD_APPEND_CHAR_CHECK(brem, buf, '\"');
        }
    } else if (record->rrtype == 47) {
        ret = snprintf(buf->cp, brem, "\"dnsHashData\":\"");
        MD_CHECK_RET(buf, ret, brem);
        mdJsonifyEscapeChars(buf, &brem, record->rrdata.buf,
                             record->rrdata.len);
        if (base64) {
            encode = TRUE;
        }  else {
            MD_APPEND_CHAR_CHECK(brem, buf, '\"');
        }
    } else {
        /* if we found no rrData then we need to snip the trailing comma from
         * the previous field.
         */
        buf->cp -= 1;
        brem += 1;
    }

    if (base64 && encode) {
        base1 = g_base64_encode((const guchar *)record->rrdata.buf,
                                record->rrdata.len-1);
        ret = snprintf(buf->cp, brem, "%s\"", base1);
        MD_CHECK_RET0(buf, ret, brem);
        g_free(base1);
    }

    if (record->mapname.len) {
        MD_APPEND_CHAR_CHECK(brem, buf, ',');
        ret = snprintf(buf->cp, brem, "\"observationDomainName\":\"");
        MD_CHECK_RET0(buf, ret, brem);
        if (!md_util_append_varfield(buf, &brem, &(record->mapname))) {
            return 0;
        }
        MD_APPEND_CHAR_CHECK(brem, buf, '\"');
    }

    if (brem > 3) {
        MD_APPEND_CHAR(buf, '}');
        MD_APPEND_CHAR(buf, '}');
        MD_APPEND_CHAR(buf, '\n');
    } else { return 0; }

    rc = md_util_write_buffer(fp, buf, "", err);

    if (!rc) {
        return -1;
    }

    return rc;
}

int mdJsonifySSLDedupRecord(
    FILE        *fp,
    mdBuf_t     *buf,
    uint8_t     *rec,
    GError      **err)
{

    size_t rc = 0;
    size_t brem = MD_REM_MSG(buf);
    int ret;
    md_ssl_t *ssl = (md_ssl_t *)rec;
    uint64_t start_secs = ssl->fseen / 1000;
    uint32_t start_rem = ssl->fseen % 1000;
    uint64_t end_secs = ssl->lseen / 1000;
    uint32_t end_rem = ssl->lseen % 1000;

    ret = snprintf(buf->cp, brem, "{\"ssl\":{\"firstSeen\":\"");
    MD_CHECK_RET0(buf, ret, brem);

    if (!md_util_time_buf_append(buf, &brem, start_secs, PRINT_TIME_FMT)) {
        return 0;
    }
    ret = snprintf(buf->cp, brem, ".%03u\",\"lastSeen\":\"", start_rem);
    MD_CHECK_RET0(buf, ret, brem);

    if (!md_util_time_buf_append(buf, &brem, end_secs, PRINT_TIME_FMT)) {
        return 0;
    }

    ret = snprintf(buf->cp, brem,  ".%03u\",\"sslCertSerialNumber\":\"",
                   end_rem);
    MD_CHECK_RET0(buf, ret, brem);

    ret = md_util_hexdump_append_nospace(buf->cp, &brem,
                                         ssl->serial.buf, ssl->serial.len);
    if (!ret) {
        return 0;
    }
    buf->cp += ret;

    if (ssl->mapname.len) {
        ret = snprintf(buf->cp, brem, "\",\"observationDomainName\":\"");
        MD_CHECK_RET0(buf, ret, brem);
        if (!md_util_append_varfield(buf, &brem, &(ssl->mapname))) {
            return 0;
        }
    }

    ret = snprintf(buf->cp, brem, "\",\"observedDataTotalCount\":%"PRIu64
                   ",\"sslCertIssuerCommonName\":\"", ssl->hitcount);
    MD_CHECK_RET0(buf, ret, brem);

    if (!md_util_append_varfield(buf, &brem, &(ssl->issuer))) {
        return 0;
    }

    ret = snprintf(buf->cp, brem, "\"}}\n");

    MD_CHECK_RET0(buf, ret, brem);

    rc = md_util_write_buffer(fp, buf, "", err);

    if (!rc) {
        return -1;
    }

    return rc;
}

int mdJsonifyDedupRecord(
    FILE                *fp,
    mdBuf_t             *buf,
    char                *prefix,
    md_dedup_t          *rec,
    GError              **err)
{

    size_t rc = 0;
    size_t brem = MD_REM_MSG(buf);
    uint64_t start_secs = rec->fseen / 1000;
    uint32_t start_rem = rec->fseen % 1000;
    uint64_t end_secs = rec->lseen / 1000;
    uint32_t end_rem = rec->lseen % 1000;
    uint64_t flow_secs = rec->stime / 1000;
    uint32_t flow_rem = rec->stime % 1000;
    char     sabuf[40];
    int      ret;



    ret = snprintf(buf->cp, brem, "{\"dedup\":{\"firstSeen\":\"");
    MD_CHECK_RET0(buf, ret, brem);

    if (!md_util_time_buf_append(buf, &brem, start_secs, PRINT_TIME_FMT)) {
        return 0;
    }
    ret = snprintf(buf->cp, brem, ".%03u\",\"lastSeen\":\"", start_rem);
    MD_CHECK_RET0(buf, ret, brem);

    if (!md_util_time_buf_append(buf, &brem, end_secs, PRINT_TIME_FMT)) {
        return 0;
    }

    if (rec->sip != rec->hash) {
        if (rec->sip == 0) {
            ret = snprintf(buf->cp, brem, ".%03u\",\"sourceIPv6Address\":\"",
                           end_rem);
            MD_CHECK_RET0(buf, ret, brem);
            md_util_print_ip6_addr(sabuf, rec->sip6);
        } else {
            ret = snprintf(buf->cp, brem, ".%03u\",\"sourceIPv4Address\":\"",
                           end_rem);
            MD_CHECK_RET0(buf, ret, brem);
            md_util_print_ip4_addr(sabuf, rec->sip);
        }
        ret = snprintf(buf->cp, brem, "%s\",\"flowKeyHash\":%u,"
                       "\"observedDataTotalCount\":%"PRIu64",",
                       sabuf, rec->hash, rec->count);
    } else {
        /* deduped on hash, not IP so don't print IP */
        ret = snprintf(buf->cp, brem, ".%03u\",\"flowKeyHash\":%u,"
                       "\"observedDataTotalCount\":%"PRIu64",",
                       end_rem, rec->hash, rec->count);
    }

    MD_CHECK_RET0(buf, ret, brem);

    /* flow's start time */
    ret = snprintf(buf->cp, brem, "\"flowStartMilliseconds\":\"");
    MD_CHECK_RET0(buf, ret, brem);

    if (!md_util_time_buf_append(buf, &brem, flow_secs, PRINT_TIME_FMT)) {
        return 0;
    }

    ret = snprintf(buf->cp, brem, ".%03u\",", flow_rem);
    MD_CHECK_RET0(buf, ret, brem);


    if (rec->mapname.len) {
        ret = snprintf(buf->cp, brem, "\"observationDomainName\":\"");
        MD_CHECK_RET0(buf, ret, brem);
        if (!md_util_append_varfield(buf, &brem, &(rec->mapname))) {
            return 0;
        }
        MD_APPEND_CHAR_CHECK(brem, buf, '\"');
        MD_APPEND_CHAR_CHECK(brem, buf, ',');
    }


    if (rec->data.len) {
        ret = snprintf(buf->cp, brem, "\"%s\":\"", prefix);
        MD_CHECK_RET0(buf, ret, brem);
        if (!md_util_append_varfield(buf, &brem, &(rec->data))) {
            return 0;
        }
        MD_APPEND_CHAR_CHECK(brem, buf, '\"');
    } else if (rec->serial1.len) {
        ret = snprintf(buf->cp, brem, "\"sslCertificateChain\":[{\""
                       "sslCertSerialNumber\":\"");
        MD_CHECK_RET0(buf, ret, brem);
        ret = md_util_hexdump_append_nospace(buf->cp, &brem, rec->serial1.buf,
                                             rec->serial1.len);
        if (!ret) {
            return 0;
        }
        buf->cp += ret;
        ret = snprintf(buf->cp, brem, "\", \"sslCertIssuerCommonName\":\"");
        MD_CHECK_RET0(buf, ret, brem);
        if (!md_util_append_varfield(buf, &brem, &(rec->issuer1))) {
            return 0;
        }
        MD_APPEND_CHAR_CHECK(brem, buf, '\"');
        MD_APPEND_CHAR_CHECK(brem, buf, '}');
        if (rec->serial2.len) {
            ret = snprintf(buf->cp, brem, ",{\"sslCertSerialNumber\":\"");
            MD_CHECK_RET0(buf, ret, brem);
            ret = md_util_hexdump_append_nospace(buf->cp, &brem,
                                                 rec->serial2.buf,
                                                 rec->serial2.len);
            if (!ret) {
                return 0;
            }
            buf->cp += ret;
            ret = snprintf(buf->cp, brem, "\", \"sslCertIssuerCommonName\":\"");
            MD_CHECK_RET0(buf, ret, brem);
            if (!md_util_append_varfield(buf, &brem, &(rec->issuer2))) {
                return 0;
            }
            ret = snprintf(buf->cp, brem, "\"}]");
            MD_CHECK_RET0(buf, ret, brem);
        } else {
            MD_APPEND_CHAR_CHECK(brem, buf, ']');
        }
    }

    ret = snprintf(buf->cp, brem, "}}\n");
    MD_CHECK_RET0(buf, ret, brem);

    rc = md_util_write_buffer(fp, buf, "", err);

    if (!rc) {
        return -1;
    }

    return rc;
}

gboolean mdJsonifySSLCertBase64(
    mdBuf_t             *buf,
    fbVarfield_t        *cert)
{
    size_t brem = MD_REM_MSG(buf);
    gchar *base1 = NULL;
    int ret;

    /* remove '},' */
    buf->cp -= 2;
    brem += 2;

    base1 = g_base64_encode((const guchar *)cert->buf,
                            cert->len);

    ret = snprintf(buf->cp, brem, ",\"sslCertificate\":\"%s\"},", base1);
    MD_CHECK_RET0(buf, ret, brem);

    if (base1) {
        g_free(base1);
    }

    return TRUE;
}
