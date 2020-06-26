/**
 * @file mediator_dedup.c
 *
 * deduplication code.
 *
 *
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2006-2017 Carnegie Mellon University. All Rights Reserved.
 * -----------------------------------------------------------
 * Authors: Emily Sarneso <netsa-help@cert.org>
 * -----------------------------------------------------------
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

#include "mediator_dedup.h"
#include <mediator/mediator_core.h>
#include <mediator/mediator_inf.h>
#include "mediator_print.h"

#define DEDUP_DEBUG 0
#define CERT_PEN 6871

#define FBSTLNEXT(a, b) fbSubTemplateListGetNextPtr(a, b)
#define FBBLNEXT(a, b) fbBasicListGetIndexedDataPtr(a, b)

#define SSL_SERIAL_IE 244
#define SSL_COMMON_NAME 3
#define SSL_ORG_UNIT 11

#define MD_APPEND_CHAR(_buf_, _ch_)           \
    *(_buf_->cp) = _ch_;                      \
    ++(_buf_->cp);


static fbInfoElementSpec_t md_dedup_spec_add[] = {
    /* Millisecond first seen and last seen (epoch) (native time) */
    { "monitoringIntervalStartMilliSeconds", 0, 0 },
    { "monitoringIntervalEndMilliSeconds",   0, 0 },
    { "flowStartMilliseconds",              0, 0 },
    { "observedDataTotalCount",             0, 0 },
    { "sourceIPv6Address",                  0, 0 },
    { "sourceIPv4Address",                  0, 0 },
    { "flowKeyHash",                     0, 0 },
    { "observationDomainName",              0, 0 },
    FB_IESPEC_NULL
};


gboolean md_dedup_basic_list(
    fbBasicList_t *bl,
    mdBuf_t       *buf,
    GString       *tstr,
    char          delim,
    gboolean      hex,
    gboolean      escape)
{

    uint16_t      k = 0;
    fbVarfield_t  *var = NULL;
    fbVarfield_t  *varlist[100];
    int           hits[100];
    int           varnum = 0;
    int           w = 0;
    gboolean      found;
    char          hexdump[65534];
    size_t        hexlen = sizeof(hexdump);
    int           ret;
    size_t        brem = (buf->buflen - (buf->cp - buf->buf));

    if (bl->numElements < 2) {
        /* not exciting - just add hit count and done */
        g_string_append_printf(tstr, "1%c", delim);
        mdPrintBasicList(buf, tstr, bl, delim, hex, escape);
        return TRUE;
    }

    for (k = 0; k < 100; k++) {
        hits[k] = 0;
    }

    varlist[varnum] = (fbVarfield_t *)FBBLNEXT(bl, 0);
    hits[varnum] = 1;
    varnum++;

    for (k = 1; (var = (fbVarfield_t *)FBBLNEXT(bl, k)); k++) {
        found = FALSE;

        if (var->len == 0) {
            continue;
        }

        for (w = 0; w < varnum; w++) {
            if (var->len != varlist[w]->len) {
                continue;
            } else {
                if (memcmp(var->buf, varlist[w]->buf, var->len) == 0) {
                    hits[w]++;
                    found = TRUE;
                    break;
                }
            }
        }
        if (!found) {
            varlist[varnum] = var;
            hits[varnum] = 1;
            varnum++;
        }
    }

    for (k = 0; k < varnum; k++) {
        md_util_append_gstr(buf, &brem, tstr);
        if (!mdPrintDecimal(buf, &brem, delim, hits[k])) {
            return FALSE;
        }
        if (hex) {
            ret = md_util_hexdump_append(hexdump, &hexlen, varlist[k]->buf,
                                         varlist[k]->len);
            if (!ret) return FALSE;
            if (!md_util_append_buffer(buf, &brem, (uint8_t*)hexdump, ret)) {
                return FALSE;
            }
        } else {
            if (escape) {
                if (!mdPrintEscapeChars(buf, &brem, varlist[k]->buf,
                                        varlist[k]->len, delim))
                {
                    return FALSE;
                }
            } else {
                if (!md_util_append_buffer(buf, &brem, varlist[k]->buf,
                                           varlist[k]->len))
                {
                    return FALSE;
                }
            }
            MD_APPEND_CHAR(buf, '\n');
        }
    }
    return TRUE;
}

GString *md_dedup_basic_list_no_count(
    fbBasicList_t *bl,
    char          delim,
    gboolean      quote,
    gboolean      hex,
    gboolean      escape)
{

    uint16_t      k = 1;
    fbVarfield_t  *var = NULL;
    fbVarfield_t  *varlist[100];
    int           varnum = 0;
    int           w = 0;
    gboolean      found;
    char          hexdump[65534];
    size_t        hexlen = sizeof(hexdump);
    GString      *str = NULL;

    var = (fbVarfield_t *)FBBLNEXT(bl, 0);
    if (var) {
        varlist[varnum] = var;
        varnum++;
    } else {
        return NULL;
    }

    var = NULL;
    str = g_string_new("");

    for (k = 1; (var = (fbVarfield_t *)FBBLNEXT(bl, k)); k++) {
        found = FALSE;

        if (var->len == 0) {
            continue;
        }

        for (w = 0; w < varnum; w++) {
            if (var->len != varlist[w]->len) {
                continue;
            } else {
                if (memcmp(var->buf, varlist[w]->buf, var->len) == 0) {
                    found = TRUE;
                    break;
                }
            }
        }
        if (!found) {
            varlist[varnum] = var;
            varnum++;
        }
    }

    for (k = 0; k < varnum; k++) {
        if (quote) {
            g_string_append_printf(str, "\"");
        }
        if (hex) {
            w = md_util_hexdump_append(hexdump, &hexlen, varlist[k]->buf,
                                       varlist[k]->len);
            if (!w) return FALSE;
            g_string_append_len(str, (gchar *)hexdump, w);
        } else {
            if (escape) {
                if (quote) {
                    mdPrintEscapeStrChars(str, varlist[k]->buf,
                                          varlist[k]->len, '"');
                } else {
                    mdPrintEscapeStrChars(str, varlist[k]->buf, varlist[k]->len,
                                          delim);
                }
            } else {
                g_string_append_len(str, (gchar *)varlist[k]->buf,
                                    varlist[k]->len);
            }
        }
        if (quote) {
            g_string_append_printf(str, "\"%c", delim);
        } else {
            g_string_append_printf(str, "%c", delim);
        }
    }
    if (str->len) {
        /* remove last delimiter */
        g_string_truncate(str, str->len-1);
    }

    return str;

}

void md_dedup_print_stats(
    md_dedup_state_t *state,
    char             *exp_name)
{
    if (state->stats.recvd == 0) {
        g_message("Exporter %s: %"PRIu64" Records, %"PRIu64" flushed",
                  exp_name, state->stats.recvd, state->stats.flushed);
        return;
    }

    g_message("Exporter %s: %"PRIu64" Records, %"PRIu64" flushed"
              "(%2.2f%% compression)", exp_name, state->stats.recvd,
              state->stats.flushed, (1-(((double)state->stats.flushed)/
                                        ((double)state->stats.recvd)))*100);
}

static void md_dedup_ssl_decrement_cert(
    md_dedup_state_t        *state,
    md_dedup_ssl_str_node_t *node)
{
    char                 temp[4092];
    smVarHashKey_t       lookup;

    --(node->cert1->count);

    if (node->cert1->count == 0) {
        if ((node->cert1->issuer_len + node->cert1->serial_len) < 4092) {
            memcpy(temp, node->cert1->serial, node->cert1->serial_len);
            memcpy(temp + node->cert1->serial_len, node->cert1->issuer,
                   node->cert1->issuer_len);
            lookup.val = (uint8_t*)temp;
            lookup.len = node->cert1->serial_len + node->cert1->issuer_len;
            g_hash_table_remove(state->cert_table, &lookup);
            g_slice_free1(node->cert1->issuer_len, node->cert1->issuer);
            g_slice_free1(node->cert1->serial_len, node->cert1->serial);
            g_slice_free(md_dedup_ssl_node_t, node->cert1);
        }
    }

    if (node->cert2) {
        --(node->cert2->count);
        if (node->cert2->count == 0) {
            if ((node->cert2->issuer_len + node->cert2->serial_len) < 4092) {
                memcpy(temp, node->cert2->serial, node->cert2->serial_len);
                memcpy(temp + node->cert2->serial_len, node->cert2->issuer,
                       node->cert2->issuer_len);
                lookup.val = (uint8_t *)temp;
                lookup.len = node->cert2->serial_len + node->cert2->issuer_len;
                g_hash_table_remove(state->cert_table, &lookup);
                g_slice_free1(node->cert2->issuer_len, node->cert2->issuer);
                g_slice_free1(node->cert2->serial_len, node->cert2->serial);
                g_slice_free(md_dedup_ssl_node_t, node->cert2);
            }
        }
    }


}



gboolean md_dedup_flush_queue(
    md_export_node_t         *exp,
    mdConfig_t               *cfg,
    GError                   **err)
{
    md_dedup_node_t          *node = NULL;
    md_dedup_state_t         *state = exp->dedup;
    md_dedup_cqueue_t        *cq = state->cq;

    if (cq == NULL) {
        return TRUE;
    }

    while ((node = detachFromEndOfDLL((mdDLL_t **)&(cq->head),
                                      (mdDLL_t **)&(cq->tail))))
    {
        if (!mdExporterDedupFileOpen(cfg, exp->exp, &(node->ietab->out_file),
                                     &(node->ietab->last_file),
                                     node->ietab->file_prefix,
                                     &(node->ietab->last_rotate_ms)))
        {
            return FALSE;
        }
#if DEDUP_DEBUG
        g_debug("flushing queue node: %p, node->ietab %p, node->strnode %p",
                node, node->ietab, node->strnode);
        g_debug("file->prefix %s, intid %02x, extid %02x", node->ietab->file_prefix,
                node->ietab->tmpl->intid, node->ietab->tmpl->extid);
#endif
        if (state->add_export) {
            if (node->exnode.mapname.len == 0) {
                node->exnode.mapname.buf = (uint8_t*)mdExporterGetName(exp->exp);
                node->exnode.mapname.len = strlen(mdExporterGetName(exp->exp));
            }
        }

        if (!mdExporterWriteDedupRecord(cfg, exp, node->ietab->out_file,
                                        &(node->exnode), node->ietab->file_prefix,
                                        node->ietab->tmpl->intid, node->ietab->tmpl->extid, err))
        {
            return FALSE;
        }

        if (!node->ietab->ssl) {
            g_slice_free1(node->strnode->caplen, node->strnode->data);
            g_slice_free(md_dedup_str_node_t, node->strnode);
        } else {
            md_dedup_ssl_decrement_cert(state, (md_dedup_ssl_str_node_t*)node->strnode);
            g_slice_free(md_dedup_ssl_str_node_t,
                         (md_dedup_ssl_str_node_t *)node->strnode);
            /* check count on certs... free certs if necessary */
        }
        g_slice_free(md_dedup_node_t, node);

        state->stats.flushed++;
    }

    return TRUE;
}



md_dedup_state_t *md_dedup_new_dedup_state(
                               )
{
    md_dedup_state_t *state = g_slice_new0(md_dedup_state_t);

    state->ie_table = g_hash_table_new((GHashFunc)g_direct_hash,
                                       (GEqualFunc)g_direct_equal);

    state->cq = g_slice_new0(md_dedup_cqueue_t);

    /* set defaults */
    state->max_hit_count = 5000;
    state->flush_timeout = 300 * 1000;

#if DEDUP_DEBUG
    fprintf(stderr, "created new dedup state %p\n", state->ie_table);
#endif

    return state;

}

gboolean md_dedup_add_templates(
    md_dedup_state_t *state,
    fBuf_t           *fbuf,
    GError           **err)
{
    md_dedup_tmpl_t *tnode  = NULL;
    fbSession_t *session = fBufGetSession(fbuf);
    md_dedup_ie_t       *tn = NULL, *cn = NULL;
    fbInfoModel_t *sm_model = mdInfoModel();
    const fbInfoElement_t *ie_to_add  = NULL;
    fbInfoElementSpec_t md_dedup_ie_spec;

    for (tn = state->head; tn; tn = cn) {
        cn = tn->next;
        tnode = tn->tmpl;

        /* really should have configureable PEN */
        ie_to_add = fbInfoModelGetElementByID(sm_model, tnode->ie, CERT_PEN);

        if (tn->ssl == FALSE) {
            tnode->tmpl = fbTemplateAlloc(sm_model);

            if (!fbTemplateAppendSpecArray(tnode->tmpl, md_dedup_spec_add,
                                           0xffffffff, err))
            {
                return FALSE;
            }

            md_dedup_ie_spec.name = (char *)ie_to_add->ref.name;
            md_dedup_ie_spec.len_override = 0;
            md_dedup_ie_spec.flags = 0;

            if (!fbTemplateAppendSpec(tnode->tmpl, &md_dedup_ie_spec, 0, err))
            {
                return FALSE;
            }

            tnode->intid = fbSessionAddTemplate(session, TRUE, tnode->intid,
                                                tnode->tmpl, err);
            if (tnode->intid == 0) {
                return FALSE;
            }

            tnode->extid = fbSessionAddTemplate(session, FALSE, tnode->extid,
                                                tnode->tmpl, err);
            if (tnode->extid == 0) {
                return FALSE;
            }
        } else {
            tnode->intid = MD_DEDUP_FULL;
            tnode->extid = MD_DEDUP_FULL;
        }
    }

    /*    if (!fbSessionExportTemplates(session, err)) {
        return FALSE;
        }*/

    return TRUE;
}

static void md_dedup_reset(
    md_export_node_t *exp,
    uint64_t           ctime)
{
    g_warning("Potentially out of memory for deduplication."
              " Resetting all tables.");
    md_dedup_flush_alltab(exp, ctime, TRUE);
}

void md_dedup_configure_state(
    md_dedup_state_t *state,
    int               max_hit_count,
    int               flush_timeout,
    gboolean          merge_truncated,
    gboolean          add_export)
{
    if (max_hit_count) {
        state->max_hit_count = max_hit_count;
    }

    if (flush_timeout) {
        state->flush_timeout = flush_timeout * 1000;
    }

    if (merge_truncated) {
        state->merge = merge_truncated;
    }

    if (add_export) {
        state->add_export = add_export;
    }
}

static md_dedup_str_node_t *md_dedup_new_str_node(
    uint8_t        *data,
    size_t         caplen,
    uint64_t       time,
    uint32_t       hash,
    uint64_t       stime)
{
    md_dedup_str_node_t *stn;

    stn = g_slice_new0(md_dedup_str_node_t);
    if (stn == NULL) {
        return NULL;
    }

    stn->ftime = time;
    stn->ltime = time;
    stn->hitcount = 1;
    stn->hash = hash;
    stn->stime = stime;

    stn->data = g_slice_alloc0(caplen);
    if (stn->data == NULL) {
        return NULL;
    }
    memcpy(stn->data, data, caplen);
    stn->caplen = caplen;

    return stn;
}

static md_dedup_ie_t *md_dedup_ie_lookup(
    md_dedup_state_t  *state,
    uint16_t          ie)
{

    md_dedup_ie_t *ret = NULL;

    ret = g_hash_table_lookup(state->ie_table, GUINT_TO_POINTER((unsigned int)ie));

    return ret;
}

void md_dedup_add_ie(
    md_dedup_state_t *state,
    md_dedup_ie_t    *ie_tab,
    uint16_t          ie)
{
#if DEDUP_DEBUG
    fprintf(stderr, "add ie %d to ietab %p\n", ie, ie_tab);
#endif
    g_hash_table_insert(state->ie_table, GUINT_TO_POINTER((unsigned int)ie), ie_tab);
}


md_dedup_ie_t *md_dedup_add_ie_table(
    md_dedup_state_t *state,
    char             *prefix,
    smFieldMap_t     *map,
    uint16_t         ie,
    int              sip)
{

    md_dedup_ie_t *ie_tab = NULL;
    md_dedup_tmpl_t *dedup_tmpl = NULL;

#if DEDUP_DEBUG
    fprintf(stderr, "state->ie_table is %p\n", state->ie_table);
#endif

    if ((ie_tab = g_hash_table_lookup(state->ie_table,
                                      GUINT_TO_POINTER((unsigned int)ie))))
    {
        /* already exists */
        return NULL;
    }

    ie_tab = g_slice_new0(md_dedup_ie_t);

    if (map) {
        ie_tab->ip_table = smCreateHashTable(sizeof(uint32_t) + sizeof(uint32_t), NULL, NULL);
        ie_tab->ip6_table = smCreateHashTable(sizeof(uint32_t) + sizeof(uint8_t[16]), NULL, NULL);
        /*        ie_tab->ip_table = g_hash_table_new((GHashFunc)g_direct_hash,
                                            (GEqualFunc)g_direct_equal);

        ie_tab->ip6_table = g_hash_table_new_full((GHashFunc)sm_octet_array_hash,
                                                  (GEqualFunc)sm_octet_array_equal,
                                                  sm_octet_array_key_destroy,
                                                  NULL);*/
    } else {
        ie_tab->ip_table = smCreateHashTable(sizeof(uint32_t), NULL, NULL);
        ie_tab->ip6_table = smCreateHashTable(sizeof(uint8_t[16]), NULL, NULL);
    }

    ie_tab->file_prefix = g_strdup(prefix);

    ie_tab->sip = sip;

    ie_tab->map = map;

    g_hash_table_insert(state->ie_table, GUINT_TO_POINTER((unsigned int)ie),
                        ie_tab);

    attachHeadToDLL((mdDLL_t **)&(state->head),
                    (mdDLL_t **)&(state->tail),
                    (mdDLL_t *)ie_tab);

    /* if ie == serial #, then set up SSL state */
    if (ie == SSL_SERIAL_IE) {
        state->cert_table = g_hash_table_new_full((GHashFunc)sm_octet_array_hash,
                                                  (GEqualFunc)sm_octet_array_equal,
                                                  sm_octet_array_key_destroy, NULL);
        ie_tab->ssl = TRUE;
    }

    dedup_tmpl = g_slice_new0(md_dedup_tmpl_t);

    dedup_tmpl->ie = ie;

    ie_tab->tmpl = dedup_tmpl;

    return ie_tab;
}

static void md_dedup_ip_node_close(
    md_dedup_ie_t         *ietab,
    md_dedup_ip_node_t    *ipnode)
{

    if (ipnode->sip6_key) {
        /*g_hash_table_remove(ietab->ip6_table, ipnode->sip6_key);*/
        smHashTableRemove(ietab->ip6_table, (uint8_t*)(ipnode->sip6_key));
        g_slice_free(mdMapKey6_t, ipnode->sip6_key);
    } else {
        smHashTableRemove(ietab->ip_table, (uint8_t*)(ipnode->sip_key));
        g_slice_free(mdMapKey4_t, ipnode->sip_key);
        /*g_hash_table_remove(ietab->ip_table, GUINT_TO_POINTER(ipnode->sip_key));*/
    }

    detachThisEntryOfDLL((mdDLL_t **)&(ietab->head),
                         (mdDLL_t **)&(ietab->tail),
                         (mdDLL_t *)ipnode);
#if DEDUP_DEBUG
    g_debug("REMOVE IPNODE %u", ipnode->sip_key);
#endif

    if (ietab->ssl) {
        g_slice_free(md_dedup_ssl_ip_node_t, (md_dedup_ssl_ip_node_t*)ipnode);
    }  else {
        g_slice_free(md_dedup_ip_node_t, ipnode);
    }
    --(ietab->count);
}

static void md_dedup_str_node_close(
    md_export_node_t      *exp,
    md_dedup_ie_t         *ietab,
    md_dedup_ip_node_t    *ipnode,
    md_dedup_str_node_t   *strnode)
{
    md_dedup_cqueue_t *cq = exp->dedup->cq;
    md_dedup_node_t *cn = g_slice_new0(md_dedup_node_t);

    if (cn == NULL) {
        g_warning("Error allocating md_dedup_node.");
        return;
    }
#if DEDUP_DEBUG
    fprintf(stderr, "CLOSING STRNODE %p\n", strnode);
#endif
    cn->strnode = strnode;
    cn->ietab = ietab;
    cn->exnode.fseen = strnode->ftime;
    cn->exnode.lseen = strnode->ltime;
    cn->exnode.count = strnode->hitcount;
    cn->exnode.hash = strnode->hash;
    cn->exnode.stime = strnode->stime;
    if (ipnode->sip_key) {
        cn->exnode.sip = ipnode->sip_key->ip;
    }
    if (ipnode->sip6_key) {
        //        memcpy(cn->exnode.sip6, ipnode->sip6_key->val, 16);
        memcpy(cn->exnode.sip6, ipnode->sip6_key, 16);
    }

    if (ietab->map) {
        int mapindex = 0;
        if (ipnode->sip_key) {
            mapindex = ipnode->sip_key->map;
        } else {
            /*mapindex = ((mdMapKey6_t*)(ipnode->sip6_key->val))->map;*/
            mapindex = ((mdMapKey6_t*)(ipnode->sip6_key))->map;
        }
#if DEDUP_DEBUG
        g_debug("maps on %s", ietab->map->labels[mapindex]);
#endif
        cn->exnode.mapname.buf = (uint8_t*)(ietab->map->labels[mapindex]);
        cn->exnode.mapname.len = strlen(ietab->map->labels[mapindex]);
    }

    if (!ietab->ssl) {
        cn->exnode.data.buf = strnode->data;
        cn->exnode.data.len = strnode->caplen;
    } else {
        md_dedup_ssl_str_node_t *ssl = (md_dedup_ssl_str_node_t *)strnode;
        cn->exnode.serial1.buf = ssl->cert1->serial;
        cn->exnode.serial1.len = ssl->cert1->serial_len;
        cn->exnode.issuer1.buf = ssl->cert1->issuer;
        cn->exnode.issuer1.len = ssl->cert1->issuer_len;
        if (ssl->cert2) {
            cn->exnode.serial2.buf = ssl->cert2->serial;
            cn->exnode.serial2.len= ssl->cert2->serial_len;
            cn->exnode.issuer2.buf= ssl->cert2->issuer;
            cn->exnode.issuer2.len= ssl->cert2->issuer_len;
        }
    }

    attachHeadToDLL((mdDLL_t **)&(cq->head),
                    (mdDLL_t **)&(cq->tail),
                    (mdDLL_t *)cn);

    detachThisEntryOfDLL((mdDLL_t**)&(ipnode->head),
                         (mdDLL_t**)&(ipnode->tail),
                         (mdDLL_t*)strnode);

    if (!ipnode->head) {
        md_dedup_ip_node_close(ietab, ipnode);
    }

}


static void md_dedup_str_node_tick(
    md_export_node_t      *exp,
    md_dedup_ie_t         *ietab,
    md_dedup_ip_node_t    *ipnode,
    md_dedup_str_node_t   *strnode)
{
    if (ipnode->head != strnode) {
        if (strnode->prev != NULL) {
            detachThisEntryOfDLL((mdDLL_t**)&(ipnode->head),
                                 (mdDLL_t**)&(ipnode->tail),
                                 (mdDLL_t*)strnode);
        }
        attachHeadToDLL((mdDLL_t **)&(ipnode->head),
                        (mdDLL_t **)&(ipnode->tail),
                        (mdDLL_t *)strnode);
    }

    while (ipnode->tail && ((strnode->ltime - ipnode->tail->ltime) > exp->dedup->flush_timeout)) {
        md_dedup_str_node_close(exp, ietab, ipnode, ipnode->tail);
    }
}

static void md_dedup_ip_node_tick(
    md_dedup_ie_t       *ietab,
    md_dedup_ip_node_t  *ipnode)
{
    if (ietab->head != ipnode) {
        if (ipnode->prev != NULL) {
            detachThisEntryOfDLL((mdDLL_t **)&(ietab->head),
                                 (mdDLL_t **)&(ietab->tail), (mdDLL_t *)ipnode);
        }

        attachHeadToDLL((mdDLL_t **)&(ietab->head),
                        (mdDLL_t **)&(ietab->tail),
                        (mdDLL_t *)ipnode);
    }
}

static void md_dedup_add_node(
    mdContext_t      *ctx,
    md_export_node_t *exp,
    md_dedup_ie_t    *ietab,
    uint8_t          *data,
    size_t           datalen,
    uint16_t         ie,
    mdFullFlow_t     *flow,
    gboolean         rev)
{

    md_dedup_state_t *state = exp->dedup;
    md_dedup_ip_node_t *ipnode = NULL;
    md_dedup_str_node_t *strnode = NULL,  *cn = NULL, *tn = NULL;
    size_t cmpsize = datalen;
    int rc;
    uint32_t sip = 0;
    uint32_t hash = md_util_flow_key_hash(flow->rec);
    mdMapKey4_t mapkey4;
    mdMapKey6_t mapkey6;
    gboolean v6 = FALSE;

    mapkey4.map = 0;
    mapkey6.map = 0;

    if (datalen == 0 || !data) {
        /* no data to add */
        return;
    }

    if (ietab->sip == 2) {
        mapkey4.ip = hash;
        sip = hash;
    } else {

        if (flow->rec->sourceIPv4Address || flow->rec->destinationIPv4Address) {
            if (rev || (!rev && !ietab->sip)) {
                mapkey4.ip = flow->rec->destinationIPv4Address;
                sip = flow->rec->destinationIPv4Address;
            } else {
                mapkey4.ip = flow->rec->sourceIPv4Address;
                sip = flow->rec->sourceIPv4Address;
            }
        } else {
            if (rev || (!rev && !ietab->sip)) {
                memcpy(mapkey6.ip, flow->rec->destinationIPv6Address, 16);
            } else {
                memcpy(mapkey6.ip, flow->rec->sourceIPv6Address, 16);

            }
            v6 = TRUE;
        }
    }

    if (ietab->map) {
        mapkey4.map = smFieldMapTranslate(ietab->map, flow);
        if (ietab->map->discard && (mapkey4.map == 0)) {
            return;
        }
        mapkey6.map = mapkey4.map;
    }

    if (v6) {
        ipnode = smHashLookup(ietab->ip6_table, (uint8_t*)&mapkey6);
    } else {
        ipnode = smHashLookup(ietab->ip_table, (uint8_t*)&mapkey4);
#if DEDUP_DEBUG
        g_debug("looking up sip %08x %p %04x - returned %p", mapkey4, ietab->ip_table, mapkey4.ip, ipnode);
#endif
    }


    if (ipnode) {
        for (tn = ipnode->head; tn; tn = cn) {
            cn = tn->next;
            if (ie != tn->ie) {
                continue;
            }
            if (!state->merge) {
                /* not merging truncated fields - so if lengths don't match,
                   continue */
                if (datalen != tn->caplen) {
                    continue;
                }
            } else {
                cmpsize = datalen < tn->caplen ? datalen : tn->caplen;
            }
            rc = memcmp(tn->data, data, cmpsize);
            if (!rc) {
                state->stats.recvd++;
                ++(tn->hitcount);
                tn->hash = hash;
                tn->stime = flow->rec->flowStartMilliseconds;
                tn->ltime = ctx->cfg->ctime;
                if (tn->hitcount == state->max_hit_count) {
                    md_dedup_str_node_close(exp, ietab, ipnode, tn);
                } else {
                    md_dedup_str_node_tick(exp, ietab, ipnode, tn);
                    md_dedup_ip_node_tick(ietab, ipnode);
                }
                return;
            }
        }
    } else {
        /* IP address not found for this IE */
        ipnode = g_slice_new0(md_dedup_ip_node_t);
        if (ipnode == NULL) {
            md_dedup_reset(exp, ctx->cfg->ctime);
            return;
        }
        if (v6) {
            ipnode->sip6_key = g_slice_new0(mdMapKey6_t);
            memcpy(ipnode->sip6_key, &mapkey6, sizeof(mdMapKey6_t));
            smHashTableInsert(ietab->ip6_table, (uint8_t*)ipnode->sip6_key,
                              (uint8_t*)ipnode);
        } else {
            ipnode->sip_key = g_slice_new0(mdMapKey4_t);
            ipnode->sip_key->ip = sip;
            ipnode->sip_key->map = mapkey4.map;
            smHashTableInsert(ietab->ip_table, (uint8_t*)ipnode->sip_key,
                              (uint8_t*)ipnode);
            /*g_hash_table_insert(ietab->ip_table,
              GUINT_TO_POINTER((unsigned int)sip), ipnode);*/
        }
        ++(ietab->count);
    }

    strnode = md_dedup_new_str_node(data, datalen, ctx->cfg->ctime, hash,
                                    flow->rec->flowStartMilliseconds);

    if (strnode == NULL) {
        md_dedup_reset(exp, ctx->cfg->ctime);
        return;
    }

    strnode->ie = ie;

    /* add to stats recvd count */
    state->stats.recvd++;

    md_dedup_str_node_tick(exp, ietab, ipnode, strnode);
    md_dedup_ip_node_tick(ietab, ipnode);
}

static void md_dedup_free_ietab(
    md_export_node_t *exp,
    md_dedup_ie_t    *ietab)
{
    /*g_hash_table_destroy(ietab->ip_table);
      g_hash_table_destroy(ietab->ip6_table);*/
    smHashTableFree(ietab->ip_table);
    smHashTableFree(ietab->ip6_table);

    if (ietab->out_file) {
        mdExporterDedupFileClose(exp->exp, ietab->out_file, ietab->last_file);
    }

    if (ietab->file_prefix) {
        g_free(ietab->file_prefix);
    }

    if (ietab->tmpl) {
        /* ietab->tmpl->tmpl should get freed when session is freed */
        g_slice_free(md_dedup_tmpl_t, ietab->tmpl);
    }

    g_slice_free(md_dedup_ie_t, ietab);
}

static void md_dedup_flush_ietab(
    md_export_node_t   *exp,
    md_dedup_ie_t      *ietab,
    uint64_t            ctime,
    gboolean            flush_all)
{
    if (ietab == NULL) {
        return;
    }

    ietab->last_flush = ctime;

    while (flush_all && ietab->tail) {
        md_dedup_str_node_close(exp, ietab, ietab->tail, ietab->tail->tail);
    }

    while (ietab->tail && (ietab->last_flush - ietab->tail->tail->ltime >
                           exp->dedup->flush_timeout))
    {
        md_dedup_str_node_close(exp, ietab, ietab->tail, ietab->tail->tail);
    }
}

void md_dedup_flush_alltab(
    md_export_node_t   *exp,
    uint64_t            ctime,
    gboolean            flush_all)
{
    md_dedup_state_t    *state = exp->dedup;
    md_dedup_ie_t       *tn = NULL, *cn = NULL;

    for (tn = state->head; tn; tn = cn) {
        cn = tn->next;
        md_dedup_flush_ietab(exp, tn, ctime, flush_all);
    }
}

gboolean md_dedup_free_state(
    mdConfig_t          *cfg,
    md_export_node_t    *exp,
    GError              **err)
{
    md_dedup_state_t *state = exp->dedup;
    md_dedup_ie_t     *tn = NULL, *cn = NULL;

    md_dedup_flush_alltab(exp, cfg->ctime, TRUE);

    if (!md_dedup_flush_queue(exp, cfg, err)) {
        return FALSE;
    }

    for (tn = state->head; tn; tn = cn) {
        cn = tn->next;
        md_dedup_free_ietab(exp, tn);
    }

    g_hash_table_destroy(state->ie_table);

    if (state->cert_table) {
        g_hash_table_destroy(state->cert_table);
    }

    g_slice_free1(sizeof(md_dedup_cqueue_t), state->cq);

    return TRUE;
}


static void md_dedup_add_bl(
    mdContext_t          *ctx,
    md_export_node_t     *exp,
    md_dedup_ie_t        *ietab,
    fbBasicList_t        *bl,
    mdFullFlow_t         *flow)
{
    uint16_t w = 0;
    fbVarfield_t            *var = NULL;

    for (w = 0;
         (var = (fbVarfield_t *)fbBasicListGetIndexedDataPtr(bl, w));
         w++) {

        if (var->len == 0) {
            continue;
        }

        md_dedup_add_node(ctx, exp, ietab, var->buf, var->len,
                          bl->infoElement->num, flow, FALSE);
    }
}

static md_dedup_ssl_node_t *md_dedup_new_ssl_node(
    uint8_t *serial,
    size_t  serial_len,
    uint8_t *issuer,
    size_t  issuer_len)
{

    md_dedup_ssl_node_t *node = g_slice_new0(md_dedup_ssl_node_t);

    node->serial = g_slice_alloc0(serial_len);
    memcpy(node->serial, serial, serial_len);
    node->serial_len = serial_len;

    node->issuer = g_slice_alloc0(issuer_len);
    memcpy(node->issuer, issuer, issuer_len);
    node->issuer_len = issuer_len;

    return node;
}



static void md_dedup_ssl_add_node(
    mdContext_t          *ctx,
    md_export_node_t     *exp,
    md_dedup_ie_t        *ietab,
    yfNewSSLFlow_t       *ssl,
    mdFullFlow_t         *flow)
{
    yfNewSSLCertFlow_t   *cert = NULL;
    yfSSLObjValue_t      *obj = NULL;
    yfSSLObjValue_t      *ou = NULL;
    md_dedup_state_t     *state = exp->dedup;
    md_dedup_ssl_node_t  *cert1 = NULL, *cert2 = NULL;
    md_dedup_ssl_str_node_t *cn = NULL, *tn = NULL;
    md_dedup_ssl_str_node_t *strnode = NULL;
    md_dedup_ssl_ip_node_t   *ipnode = NULL;
    smVarHashKey_t       lookup;
    smVarHashKey_t       *newkey;
    uint32_t             hash = md_util_flow_key_hash(flow->rec);
    uint32_t             sip;
    mdMapKey4_t          mapkey4;
    mdMapKey6_t          mapkey6;
    gboolean             found;
    gboolean             v6 = FALSE;
    uint8_t              temp[4092];
    int                  cert_no = 0;

    if (ietab->sip == 2) {
        mapkey4.ip = hash;
        sip = hash;
    } else {

        if (flow->rec->sourceIPv4Address || flow->rec->destinationIPv4Address) {
            if (ietab->sip == 0) {
                mapkey4.ip = flow->rec->destinationIPv4Address;
                sip = flow->rec->destinationIPv4Address;
            } else {
                mapkey4.ip = flow->rec->sourceIPv4Address;
                sip = flow->rec->sourceIPv4Address;
            }
        } else {
            if (ietab->sip == 0) {
                memcpy(mapkey6.ip, flow->rec->destinationIPv6Address, 16);
            } else {
                memcpy(mapkey6.ip, flow->rec->sourceIPv6Address, 16);
            }
            v6 = TRUE;
        }
    }

    if (ietab->map) {
        mapkey4.map = smFieldMapTranslate(ietab->map, flow);
        mapkey6.map = mapkey4.map;
    }

    while ((cert = (yfNewSSLCertFlow_t *)FBSTLNEXT(&(ssl->sslCertList), cert)))
    {

        obj = NULL;
        ou = NULL;
        if (cert->serial.len == 0) {
            /* no serial number */
            if (cert_no == 0) {
                return;
            } else {
                break;
            }
        }

        found = FALSE;
        while ((obj = (yfSSLObjValue_t *)FBSTLNEXT(&(cert->issuer), obj)))
        {

            if (obj->obj_id != SSL_COMMON_NAME) {
                if (obj->obj_id == SSL_ORG_UNIT) {
                    /* save just in case */
                    ou = obj;
                }
                continue;
            }

            if (obj->obj_value.len == 0) {
                continue;
            }

            found = TRUE;
            break;
        }

        if (!found) {
            if (ou) {
                obj = ou;
            } else return;
        }

        if (cert->serial.len + obj->obj_value.len < 4092) {
            memcpy(temp, cert->serial.buf, cert->serial.len);
            memcpy(temp + cert->serial.len, obj->obj_value.buf,
                   obj->obj_value.len);
        } else {
            /* cut this off somehow */
            g_debug("COMBO serial + issuer name over 4092");
            return;
        }

        lookup.val = temp;
        lookup.len = cert->serial.len + obj->obj_value.len;

        if (!cert1) {
            cert1 = g_hash_table_lookup(state->cert_table, &lookup);

            if (!cert1) {
                /* add this cert */
                cert1 = md_dedup_new_ssl_node(cert->serial.buf,
                                              cert->serial.len,
                                              obj->obj_value.buf,
                                              obj->obj_value.len);
                newkey = sm_new_hash_key(lookup.val, lookup.len);
                g_hash_table_insert(state->cert_table, newkey, cert1);

            }
        } else if (!cert2) {
            cert2 = g_hash_table_lookup(state->cert_table, &lookup);

            if (!cert2) {
                /* add this cert */
                cert2 = md_dedup_new_ssl_node(cert->serial.buf,
                                              cert->serial.len,
                                              obj->obj_value.buf,
                                              obj->obj_value.len);
                newkey = sm_new_hash_key(lookup.val, lookup.len);
                g_hash_table_insert(state->cert_table, newkey, cert2);
            }
        }

        if (cert1 && cert2) {
            break;
        }
    }

    if (!cert1) {
        /* must have 1 valid cert! */
        return;
    }

    if (v6) {
        ipnode = smHashLookup(ietab->ip6_table, (uint8_t*)&mapkey6);
        /*ipnode = g_hash_table_lookup(ietab->ip6_table, &iplookup);*/
    } else {
        ipnode = smHashLookup(ietab->ip_table, (uint8_t*)&mapkey4);
#if DEDUP_DEBUG
        g_debug("looking up sip %u - returned %p", sip, ipnode);
#endif
        /*ipnode = g_hash_table_lookup(ietab->ip_table,
          GUINT_TO_POINTER((unsigned int)sip));*/
    }

    if (ipnode) {
        for (tn = ipnode->head; tn; tn = cn) {
            cn = tn->next;

            if (cert1 != tn->cert1) {
                continue;
            }
            if (cert2 != tn->cert2) {
                continue;
            }
            /* found a match */
            state->stats.recvd++;
            ++(tn->hitcount);
            tn->ltime = ctx->cfg->ctime;
            tn->hash = hash;
            tn->stime = flow->rec->flowStartMilliseconds;
            if (tn->hitcount == state->max_hit_count) {
                md_dedup_str_node_close(exp, ietab, (md_dedup_ip_node_t*)ipnode,
                                        (md_dedup_str_node_t *)tn);
            } else {
                md_dedup_str_node_tick(exp, ietab, (md_dedup_ip_node_t*)ipnode,
                                       (md_dedup_str_node_t *)tn);
                md_dedup_ip_node_tick(ietab, (md_dedup_ip_node_t*)ipnode);
            }
            return;
        }
    } else {
        /* IP address not found in this table */
        ipnode = g_slice_new0(md_dedup_ssl_ip_node_t);
        if (ipnode == NULL) {
            md_dedup_reset(exp, ctx->cfg->ctime);
            return;
        }

        if (v6) {
            ipnode->sip6_key = g_slice_new0(mdMapKey6_t);
            memcpy(ipnode->sip6_key, &mapkey6, sizeof(mdMapKey6_t));
            /*ipnode->sip6_key = sm_new_hash_key(iplookup.val, iplookup.len);*/
            /*g_hash_table_insert(ietab->ip6_table, ipnode->sip6_key, ipnode);*/
            smHashTableInsert(ietab->ip6_table, (uint8_t*)ipnode->sip6_key,
                              (uint8_t*)ipnode);
        } else {
            ipnode->sip_key = g_slice_new0(mdMapKey4_t);
            ipnode->sip_key->ip = sip;
            ipnode->sip_key->map = mapkey4.map;
            smHashTableInsert(ietab->ip_table, (uint8_t*)ipnode->sip_key,
                              (uint8_t*)ipnode);
            /*g_hash_table_insert(ietab->ip_table,
              GUINT_TO_POINTER((unsigned int)sip), ipnode);*/
        }
        ++(ietab->count);
    }

    strnode = g_slice_new0(md_dedup_ssl_str_node_t);
    if (strnode == NULL) {
        md_dedup_reset(exp, ctx->cfg->ctime);
        return;
    }

    strnode->ftime = ctx->cfg->ctime;
    strnode->ltime = ctx->cfg->ctime;
    strnode->hitcount = 1;
    strnode->hash = hash;
    strnode->stime = flow->rec->flowStartMilliseconds;
    strnode->cert1 = cert1;
    strnode->cert2 = cert2;
    ++(cert1->count);
    if (cert2) {
        ++(cert2->count);
    }

    state->stats.recvd++;

    md_dedup_str_node_tick(exp, ietab, (md_dedup_ip_node_t*)ipnode,
                           (md_dedup_str_node_t*)strnode);
    md_dedup_ip_node_tick(ietab, (md_dedup_ip_node_t*)ipnode);
}

gboolean md_dedup_write_dedup(
    mdContext_t           *ctx,
    md_export_node_t      *exp,
    md_dedup_t            *dedup,
    uint16_t              ie,
    GError                **err)
{

    md_dedup_state_t *state = exp->dedup;
    md_dedup_ie_t *ietab = NULL;

    ietab = md_dedup_ie_lookup(state, ie);

    if (!ietab) {
        g_message("Ignoring incoming record: No IE dedup table for ie %d", ie);
        return TRUE;
    }

    if (!mdExporterDedupFileOpen(ctx->cfg, exp->exp, &(ietab->out_file),
                                 &(ietab->last_file),
                                 ietab->file_prefix,
                                 &(ietab->last_rotate_ms)))
    {
        return FALSE;
    }

    if (!mdExporterWriteDedupRecord(ctx->cfg, exp, ietab->out_file,
                                    dedup, ietab->file_prefix,
                                    ietab->tmpl->intid, ietab->tmpl->extid,
                                    err))
    {
        return FALSE;
    }

    state->stats.flushed++;

    return TRUE;

}


void md_dedup_lookup_node(
    mdContext_t           *ctx,
    md_export_node_t      *exp,
    mdFullFlow_t          *flow,
    GError                **err)
{
    md_dedup_state_t *state = exp->dedup;
    fbBasicList_t *bl = NULL;
    md_dedup_ie_t *ietab = NULL;
    gboolean rev = FALSE;
    int loop;

    if (flow->rec->reversePacketTotalCount) {
        rev = TRUE;
    }

    if (flow->p0f) {
        ietab = md_dedup_ie_lookup(state, 36);
        if (ietab) {
            md_dedup_add_node(ctx, exp, ietab, flow->p0f->osName.buf,
                              flow->p0f->osName.len, 36, flow, FALSE);
            if (rev) {
                md_dedup_add_node(ctx, exp,ietab, flow->p0f->reverseOsName.buf,
                                  flow->p0f->reverseOsName.len, 36, flow, TRUE);
            }
        }
        ietab = md_dedup_ie_lookup(state, 37);
        if (ietab) {
            md_dedup_add_node(ctx, exp,ietab, flow->p0f->osVersion.buf,
                              flow->p0f->osVersion.len, 37, flow, FALSE);
            if (rev) {
                md_dedup_add_node(ctx, exp,ietab, flow->p0f->reverseOsVersion.buf,
                                  flow->p0f->reverseOsVersion.len, 37, flow, TRUE);
            }
        }
        ietab = md_dedup_ie_lookup(state, 107);
        if (ietab) {
            md_dedup_add_node(ctx, exp,ietab, flow->p0f->osFingerPrint.buf,
                              flow->p0f->osFingerPrint.len, 107, flow, FALSE);
            if (rev) {
                md_dedup_add_node(ctx, exp,ietab,
                                  flow->p0f->reverseOsFingerPrint.buf,
                                  flow->p0f->reverseOsFingerPrint.len, 107,
                                  flow, TRUE);
            }
        }
    }

    if (flow->dhcpfp) {
        if ((flow->dhcpfp->tmplID & YTF_BIF) == YAF_DHCP_FLOW_TID) {
            yfDHCP_FP_Flow_t *dhcp = NULL;
            ietab = md_dedup_ie_lookup(state, 242);
            if (ietab) {
                dhcp = (yfDHCP_FP_Flow_t*)FBSTMLNEXT(flow->dhcpfp, dhcp);
                md_dedup_add_node(ctx, exp,ietab, dhcp->dhcpFP.buf,
                                  dhcp->dhcpFP.len, 242, flow, FALSE);
                if (flow->dhcpfp->tmplID & YTF_REV) {
                    md_dedup_add_node(ctx, exp,ietab, dhcp->reverseDhcpFP.buf,
                                      dhcp->reverseDhcpFP.len, 242,
                                      flow, TRUE);
                }
            }
            ietab = md_dedup_ie_lookup(state, 243);
            if (ietab) {
                md_dedup_add_node(ctx, exp,ietab, dhcp->dhcpVC.buf,
                                  dhcp->dhcpVC.len, 243, flow, FALSE);
                if (flow->dhcpfp->tmplID & YTF_REV) {
                    md_dedup_add_node(ctx, exp,ietab, dhcp->reverseDhcpVC.buf,
                                      dhcp->reverseDhcpVC.len, 243,
                                      flow, TRUE);
                }
            }
        } else if ((flow->dhcpfp->tmplID & YTF_BIF) == YAF_DHCP_OP_TID) {
            yfDHCP_OP_Flow_t *dhcp = NULL;
            ietab = md_dedup_ie_lookup(state, 243);
            if (ietab) {
                dhcp = (yfDHCP_OP_Flow_t*)FBSTMLNEXT(flow->dhcpfp, dhcp);
                md_dedup_add_node(ctx, exp,ietab, dhcp->dhcpVC.buf,
                                  dhcp->dhcpVC.len, 243, flow, FALSE);
                if (flow->dhcpfp->tmplID & YTF_REV) {
                    md_dedup_add_node(ctx, exp,ietab, dhcp->reverseDhcpVC.buf,
                                      dhcp->reverseDhcpVC.len, 243,
                                      flow, TRUE);
                }
            }
        }
    }


    switch(flow->app_tid & YTF_BIF) {
      case YAF_HTTP_FLOW_TID:
      case YAF_POP3_FLOW_TID:
      case YAF_IRC_FLOW_TID:
      case YAF_FTP_FLOW_TID:
      case YAF_IMAP_FLOW_TID:
      case YAF_SIP_FLOW_TID:
      case YAF_RTSP_FLOW_TID:
      case YAF_SSH_FLOW_TID:
      case YAF_SMTP_FLOW_TID:
      case YAF_NNTP_FLOW_TID:
      case YAF_MODBUS_FLOW_TID:
      case YAF_ENIP_FLOW_TID:
        bl = (fbBasicList_t *)flow->app;
        for (loop = 0; loop < flow->app_elements; loop++) {
            if (bl->infoElement) {
                ietab = md_dedup_ie_lookup(state, bl->infoElement->num);
                if (ietab) {
                    md_dedup_add_bl(ctx, exp, ietab, bl, flow);
                }
            }
            bl++;
        }
        break;
      case YAF_TFTP_FLOW_TID:
        {
            yfTFTPFlow_t *tftp = (yfTFTPFlow_t *)flow->app;
            ietab = md_dedup_ie_lookup(state, 127);
            if (ietab) {
                md_dedup_add_node(ctx, exp, ietab, tftp->tftpMode.buf,
                                  tftp->tftpMode.len, 127, flow, FALSE);
            }
            ietab = md_dedup_ie_lookup(state, 126);
            if (ietab) {
                md_dedup_add_node(ctx, exp, ietab, tftp->tftpFilename.buf,
                                  tftp->tftpFilename.len, 126, flow, FALSE);
            }
            break;
        }
      case YAF_SLP_FLOW_TID:
        {
            yfSLPFlow_t *slp = (yfSLPFlow_t *)flow->app;
            char slp_buffer[20];

            ietab = md_dedup_ie_lookup(state, 128);
            if (ietab) {
                snprintf(slp_buffer,sizeof(slp_buffer), "%d", slp->slpVersion);
                md_dedup_add_node(ctx, exp, ietab, (uint8_t*)slp_buffer,
                                  strlen(slp_buffer), 128, flow, FALSE);
            }
            ietab = md_dedup_ie_lookup(state, 129);
            if (ietab) {
                snprintf(slp_buffer, sizeof(slp_buffer), "%d",
                         slp->slpMessageType);
                md_dedup_add_node(ctx, exp, ietab, (uint8_t*)slp_buffer,
                                  strlen(slp_buffer), 129, flow, FALSE);
            }
            bl = (fbBasicList_t *)flow->app;
            if (bl->infoElement) {
                ietab = md_dedup_ie_lookup(state, bl->infoElement->num);
                if (ietab) {
                    md_dedup_add_bl(ctx, exp, ietab, bl, flow);
                }
            }
            break;
        }
      case YAF_NEW_SSL_FLOW_TID:
      case SM_INTSSL_FLOW_TID:
        {
            yfNewSSLFlow_t       *sslflow = (yfNewSSLFlow_t *)flow->app;

            ietab = md_dedup_ie_lookup(state, SSL_SERIAL_IE);
            if (!ietab) {
                break;
            }

            md_dedup_ssl_add_node(ctx, exp, ietab, sslflow, flow);

        }
        break;
      case YAF_MYSQL_FLOW_TID:
        {
            yfMySQLFlow_t *mflow = (yfMySQLFlow_t *)flow->app;
            yfMySQLTxtFlow_t *mtxt = NULL;
            ietab = md_dedup_ie_lookup(state, 223);
            if (ietab) {
                md_dedup_add_node(ctx, exp, ietab, mflow->mysqlUsername.buf,
                                  mflow->mysqlUsername.len, 223, flow, FALSE);
            }
            ietab = md_dedup_ie_lookup(state, 225);
            if (ietab) {
                while((mtxt =(yfMySQLTxtFlow_t *)FBSTLNEXT(&(mflow->mysqlList),
                                                             mtxt)))
                {
                    md_dedup_add_node(ctx, exp, ietab,
                                      mtxt->mysqlCommandText.buf,
                                      mtxt->mysqlCommandText.len, 225, flow,
                                      FALSE);
                }
            }
            break;
        }
      case YAF_DNS_FLOW_TID:
        {
            yfDNSFlow_t          *dnsflow = (yfDNSFlow_t *)flow->app;
            yfDNSQRFlow_t        *dnsqrflow = NULL;

            /* dns query name */
            ietab = md_dedup_ie_lookup(state, 179);
            if (ietab) {
                while (( dnsqrflow = (yfDNSQRFlow_t *)FBSTLNEXT(&(dnsflow->dnsQRList),
                                                                dnsqrflow)))
                {
                    /* just queries */
                    if (dnsqrflow->dnsQueryResponse == 0) {
                        md_dedup_add_node(ctx, exp, ietab,
                                          dnsqrflow->dnsQName.buf,
                                          dnsqrflow->dnsQName.len, 179, flow,
                                          FALSE);
                    }
                }
            }
        }
        break;
      case YAF_RTP_FLOW_TID:
        {
            yfRTPFlow_t *rtp = (yfRTPFlow_t *)flow->app;
            char  rtp_buffer[20];

            ietab = md_dedup_ie_lookup(state, 287);
            if (ietab && rtp) {
                snprintf(rtp_buffer, sizeof(rtp_buffer), "%d",
                         rtp->rtpPayloadType);
                md_dedup_add_node(ctx, exp, ietab, (uint8_t *)rtp_buffer,
                                  strlen(rtp_buffer), 287, flow, FALSE);
                snprintf(rtp_buffer, sizeof(rtp_buffer), "%d",
                         rtp->reverseRtpPayloadType);
                /* for reverse fields, swap sip & dip */
                md_dedup_add_node(ctx, exp, ietab, (uint8_t *)rtp_buffer,
                                  strlen(rtp_buffer), 287, flow, TRUE);
            }
        }
        break;
      case YAF_DNP3_FLOW_TID:
        {
            yfDNP3Flow_t *dnp = (yfDNP3Flow_t *)flow->app;
            yfDNP3Rec_t *rec = NULL;
            char dnp_buffer[65535];
            size_t bufsz = sizeof(dnp_buffer);
            size_t buflen;
            int i;

            ietab = md_dedup_ie_lookup(state, 284);
            if (ietab && dnp) {
                while ((rec = (yfDNP3Rec_t *)FBSTLNEXT(&(dnp->dnp_list), rec)))
                {
                    buflen = rec->object.len;
                    if (buflen > bufsz) {
                        buflen = bufsz;
                    }
                    i = md_util_hexdump_append(dnp_buffer, &bufsz,
                                               rec->object.buf, buflen);
                    md_dedup_add_node(ctx, exp, ietab, (uint8_t*)dnp_buffer,
                                      i, 284, flow, FALSE);
                }

            }
        }
        break;
      default:
        break;
    }

    /* attempt to flush all tables */
    md_dedup_flush_alltab(exp, ctx->cfg->ctime, FALSE);

}
