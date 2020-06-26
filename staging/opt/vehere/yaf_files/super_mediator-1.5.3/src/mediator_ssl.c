/**
 * @file mediator_ssl.c
 *
 *  SSL Cert Deduplication
 *
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2012-2017 Carnegie Mellon University. All Rights Reserved.
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

#include "mediator_ssl.h"
#include <mediator/mediator_inf.h>
#include <mediator/mediator_core.h>

#if HAVE_OPENSSL
#include <openssl/md5.h>
#include <openssl/sha.h>
#endif

#define DNS_DEBUG 0

#define FBSTLNEXT(a, b) fbSubTemplateListGetNextPtr(a, b)
#define SSL_COMMON_NAME 3
#define SSL_ORG_UNIT 11
/* ASN.1 Tag Numbers (for SSL) */
#define CERT_BOOL               0x01
#define CERT_INT                0x02
#define CERT_BITSTR             0x03
#define CERT_OCTSTR             0x04
#define CERT_NULL               0x05
/* Object Identifer */
#define CERT_OID                0x06
/* Start of Sequence */
#define CERT_SEQ                0x10
/* Start of Set */
#define CERT_SET                0x11
/* Printable String */
#define CERT_PRINT              0x13
/* UTC Time */
#define CERT_TIME               0x17
#define CERT_EXPLICIT           0xa0
/* ASN.1 P/C Bit (primitive, constucted) */
#define CERT_PRIM               0x00
#define CERT_CONST              0x01
/* ASN.1 Length 0x81 is length follows in 1 byte */
#define CERT_1BYTE              0x81
/* ASN.1 Length 0x82 is length follows in 2 bytes */
#define CERT_2BYTE              0x82
#define CERT_IDCE               0x551D
#define CERT_IDAT               0x5504
/* {iso(1) member-body (2) us(840) rsadsi(113459) pkcs(1) 9} */
#define CERT_PKCS               0x2A864886
/* 0.9.2342.19200300.100.1.25 */
#define CERT_DC                 0x09922689

/**
 * md_ssl_dedup_print_stats
 *
 * Prints stats to the log.
 *
 *
 */
void md_ssl_dedup_print_stats(
    md_ssl_dedup_state_t *state,
    char                 *exp_name)
{
    if (state->stats.ssl_recvd == 0) {
        return;
    }

    g_message("Exporter %s: %"PRIu64" SSL records, %"PRIu64" filtered"
              ", %"PRIu64" flushed (%2.2f%% compression)", exp_name,
              state->stats.ssl_recvd, state->stats.ssl_filtered,
              state->stats.ssl_flushed,(1 -(((double)state->stats.ssl_flushed)/
                               ((double)state->stats.ssl_recvd))) * 100);
}


/**
 * md_dns_reset_dedup
 *
 * Flushes all Hash Tables.
 *
 */

static void md_ssl_reset_dedup(
    md_ssl_dedup_state_t *state,
    uint64_t             cur_time)
{
    g_warning("Out of Memory Error.  Resetting all Hash Tables");
    md_ssl_flush_tab(state, cur_time, TRUE);
}


gboolean md_ssl_dedup_free_state(
    mdConfig_t           *cfg,
    md_export_node_t     *exp,
    GError               **err)

{
    md_ssl_dedup_state_t *state = exp->ssl_dedup;

    md_ssl_flush_tab(state, cfg->ctime, TRUE);
    if (!md_ssl_flush_queue(exp, cfg, err)) {
        return FALSE;
    }

    if (state->cert_table) {
        if (state->cert_table->table) {
            /*g_hash_table_destroy(state->cert_table->table);*/
            smHashTableFree(state->cert_table->table);
        }
    }

    if (state->cert_file) {
        mdExporterDedupFileClose(exp->exp, state->file, state->last_file);
        g_free(state->cert_file);
    }

    g_slice_free1(sizeof(md_ssl_hashtab_t), state->cert_table);

    g_slice_free1(sizeof(md_ssl_cqueue_t), state->cq);

    return TRUE;
}

/**
 * md_debug_table
 *
 *
 */
#if DNS_DEBUG == 1
static void md_debug_table(
    md_ssl_hashtab_t *nodeTab)
{

    md_ssl_issuer_node_t *cq;
    md_ssl_serial_node_t *hn;

    for (hn = nodeTab->head; hn; hn = hn->next) {
        for (cq = hn->head; cq; cq = cq->next) {
            //g_debug("%d %p rrname %s", cq->rrtype, cq,
            //       hn->rrname);
            g_debug("cq->next is %p", cq->next);
        }
    }
}
#endif

md_ssl_dedup_state_t *md_ssl_new_dedup_state(
    void)
{
    md_ssl_dedup_state_t *state = g_slice_new0(md_ssl_dedup_state_t);

    state->cq = g_slice_new0(md_ssl_cqueue_t);

    state->cert_table = g_slice_new0(md_ssl_hashtab_t);

    /*    state->cert_table->table = g_hash_table_new((GHashFunc)sm_octet_array_hash,
          (GEqualFunc)sm_octet_array_equal);*/
    state->cert_table->table = smCreateHashTable(0xFF,
                                                 sm_octet_array_key_destroy,
                                                 NULL);

    if (state->cert_table->table == NULL) {
        return NULL;
    }

    /* set defaults */
    state->max_hit_count = 5000;
    state->flush_timeout = 300 * 1000;

    return state;
}

void md_ssl_dedup_configure_state(
    md_ssl_dedup_state_t *state,
    int                   max_hit,
    int                   flush_timeout,
    char                  *filename,
    smFieldMap_t          *map,
    gboolean              export_name)
{
    if (!state) {
        return;
    }

    if (max_hit) {
        state->max_hit_count = max_hit;
    }

    if (flush_timeout) {
        state->flush_timeout = flush_timeout * 1000;
    }

    if (filename) {
        state->cert_file = g_strdup(filename);
    }

    if (map) {
        state->map = map;
    }

    if (export_name) {
        state->export_name = export_name;
    }

}

/**
 * md_ssl_flush_queue
 *
 * Flushes all records in the close queue.
 *
 */
gboolean md_ssl_flush_queue(
    md_export_node_t    *exp,
    mdConfig_t          *cfg,
    GError              **err)
{

    md_ssl_node_t         *node;
    md_ssl_dedup_state_t  *state = exp->ssl_dedup;
    md_ssl_cqueue_t       *cq = exp->ssl_dedup->cq;
    uint16_t              tid = MD_SSL_TID;

     if (cq == NULL) {
         return TRUE;
    }

    while ((node = detachFromEndOfDLL((mdDLL_t **)&(cq->head),
                                      (mdDLL_t **)&(cq->tail))))
    {
        if (state->export_name && (node->ssl_node.mapname.len == 0)) {
            node->ssl_node.mapname.buf = (uint8_t*)mdExporterGetName(exp->exp);
            node->ssl_node.mapname.len = strlen(mdExporterGetName(exp->exp));
        }

        if (!mdExporterWriteSSLDedupRecord(cfg, exp->exp, tid,
                                   (uint8_t *)&(node->ssl_node),
                                   sizeof(md_ssl_t), err))
        {
             return FALSE;
        }

        state->stats.ssl_flushed++;
        /* free the node we just sent out */
        g_slice_free1(node->ssl_node.serial.len, node->ssl_node.serial.buf);
        g_slice_free1(node->ssl_node.issuer.len, node->ssl_node.issuer.buf);
        g_slice_free(md_ssl_node_t, node);

    }

    return TRUE;
}



/**
 * nodeClose
 *
 * closes the HASHnode, this means that there is no more
 * cache nodes that belong to this "hash node."  Basically
 * this means that we flushed all information associated
 * with this query name.
 *
 * @param struct that contains node hash table
 * @param pointer to the node entry that we want to close
 *
 */
static void md_ssl_serial_node_close(
    md_ssl_hashtab_t     *nodeTab,
    md_ssl_serial_node_t *snode)
{
    /*Remove it from table*/

    /*g_hash_table_remove(nodeTab->table, &(snode->serial));*/
    smHashTableRemove(nodeTab->table, (uint8_t*)snode->serial);

    detachThisEntryOfDLL((mdDLL_t**)&(nodeTab->head),
                         (mdDLL_t**)&(nodeTab->tail), (mdDLL_t*)snode);

    /* free the serial */

    /*g_slice_free1(snode->serial.len, snode->serial.val);*/
    g_slice_free(md_ssl_serial_node_t, snode);

    --(nodeTab->count);
}

/**
 * hashTick
 *
 * advances a node to the head of the
 * queue - bottom of queue gets examined
 * for flush timeouts
 *
 * @param pointer to table
 * @param pointer to node
 *
 */
static void md_ssl_serial_node_tick (
    md_ssl_hashtab_t     *nodeTab,
    md_ssl_serial_node_t *entry)
{

    if (nodeTab->head != entry) {
        if (entry->prev != NULL) {
            detachThisEntryOfDLL((mdDLL_t**)&(nodeTab->head),
                                 (mdDLL_t**)&(nodeTab->tail), (mdDLL_t*)entry);
        }
        attachHeadToDLL((mdDLL_t**)&(nodeTab->head),
                        (mdDLL_t**)&(nodeTab->tail),
                        (mdDLL_t*)entry);
    }

    /*    md_debug_table(nodeTab);*/
}

/**
 * md_ssl_issuer_node_close
 *
 * creates a new md_dns_node_t for output,
 * attaches it to the close queue, and frees the
 * cache node associated with the domain name.
 *
 *
 * @param hashNode
 * @param CacheNode to close
 * @param filepointers
 */
static void md_ssl_issuer_node_close (
    md_ssl_dedup_state_t    *state,
    md_ssl_serial_node_t    *snode,
    md_ssl_issuer_node_t    *inode)
{

    md_ssl_cqueue_t         *cq = state->cq;
    md_ssl_node_t *node = g_slice_new0(md_ssl_node_t);

    node->ssl_node.fseen = inode->ftime;
    node->ssl_node.lseen = inode->ltime;
    node->ssl_node.hitcount = inode->hitcount;

    node->ssl_node.issuer.buf = g_slice_alloc0(inode->issuer_len);
    memcpy(node->ssl_node.issuer.buf, inode->issuer, inode->issuer_len);
    node->ssl_node.issuer.len = inode->issuer_len;

    if (snode->mapindex < 0) {
        node->ssl_node.serial.buf = g_slice_alloc0(snode->serial->len);
        memcpy(node->ssl_node.serial.buf, snode->serial->val, snode->serial->len);
        node->ssl_node.serial.len = snode->serial->len;
        node->ssl_node.mapname.len = 0;
    } else {
        node->ssl_node.serial.buf = g_slice_alloc0(snode->serial->len - sizeof(uint32_t));
        memcpy(node->ssl_node.serial.buf, snode->serial->val + sizeof(uint32_t),
               snode->serial->len - sizeof(uint32_t));
        node->ssl_node.serial.len = snode->serial->len - sizeof(uint32_t);
        node->ssl_node.mapname.buf = (uint8_t*)(state->map->labels[snode->mapindex]);
        node->ssl_node.mapname.len = strlen(state->map->labels[snode->mapindex]);
    }


    /*node->ssl_node.serial.buf = g_slice_alloc0(snode->serial.len);
    memcpy(node->ssl_node.serial.buf, snode->serial.val, snode->serial.len);
    node->ssl_node.serial.len = snode->serial.len;*/


    attachHeadToDLL((mdDLL_t **)&(cq->head),
                    (mdDLL_t **)&(cq->tail),
                    (mdDLL_t *)node);

    detachThisEntryOfDLL((mdDLL_t**)&(snode->head),
                         (mdDLL_t**)&(snode->tail),
                         (mdDLL_t*)inode);

    g_slice_free1(inode->issuer_len, inode->issuer);
    g_slice_free(md_ssl_issuer_node_t, inode);

    if (!snode->head) {
        /*last issuer associated with this serial # - remove from hashtable*/
        md_ssl_serial_node_close(state->cert_table, snode);
    }
}

/**
 * md_ssl_emit_record
 *
 * Adds the record to the close queue without removing
 * the node.
 *
 * @param cq - the close queue to add it to
 * @param cn - the node to add
 *
 */

#if 0

static void md_ssl_emit_record(
    md_ssl_cqueue_t         *cq,
    md_ssl_serial_node_t    *snode,
    md_ssl_issuer_node_t    *inode)
{

    md_ssl_node_t *node = g_slice_new0(md_ssl_node_t);

    if (node == NULL) {
        g_debug("Potentially out of memory.");
        return;
    }

    node->ssl_node.fseen = inode->ftime;
    node->ssl_node.lseen = inode->ltime;
    node->ssl_node.hitcount = inode->hitcount;
    node->ssl_node.issuer.buf = g_slice_alloc0(inode->issuer_len);
    memcpy(node->ssl_node.issuer.buf, inode->issuer, inode->issuer_len);
    node->ssl_node.issuer.len = inode->issuer_len;
    node->ssl_node.serial.buf = g_slice_alloc0(snode->serial->len);
    memcpy(node->ssl_node.serial.buf, snode->serial->val, snode->serial->len);
    node->ssl_node.serial.len = snode->serial->len;


    attachHeadToDLL((mdDLL_t **)&(cq->head),
                    (mdDLL_t **)&(cq->tail),
                    (mdDLL_t *)node);
}

#endif
/**
 * md_ssl_issuer_node_tick
 *
 * advances a node to the head of the cache queue
 * bottom gets examined for flush timeouts
 *
 * @param pointer to head of table
 * @param pointer to node
 *
 */
static void md_ssl_issuer_node_tick (
    md_export_node_t         *exp,
    md_ssl_serial_node_t     *snode,
    md_ssl_issuer_node_t     *inode)
{

    if (snode->head != inode) {
        if (inode->prev != NULL) {
            detachThisEntryOfDLL((mdDLL_t**)&(snode->head),
                                 (mdDLL_t**)&(snode->tail),
                                 (mdDLL_t*)inode);
        }
        attachHeadToDLL((mdDLL_t**)&(snode->head),
                        (mdDLL_t**)&(snode->tail),
                        (mdDLL_t*)inode);
    }

    while (snode->tail && ((inode->ltime - snode->tail->ltime) >
                           exp->ssl_dedup->flush_timeout))
    {
        md_ssl_issuer_node_close(exp->ssl_dedup, snode, snode->tail);
    }

}

/**
 * md_ssl_flush_tab
 *
 * Checks entries in the hash table to see if they are past the
 * flush limit.  If so, it outputs to the appropriate file and deallocates
 * the memory
 *
 * @param the struct that contains the hash table and linked list
 * @param cq - the close queue.
 * @param cur_time to keep track of how often we're flushing
 * @param flush_all (if TRUE -> close all)
 *
 */
void md_ssl_flush_tab (
    md_ssl_dedup_state_t *state,
    uint64_t             cur_time,
    gboolean             flush_all)
{

    md_ssl_hashtab_t *nodeTab = state->cert_table;

    if (nodeTab == NULL) {
        return;
    }

    nodeTab->last_flush = cur_time;

    while (flush_all && nodeTab->tail) {
        md_ssl_issuer_node_close(state, nodeTab->tail, nodeTab->tail->tail);
    }

    while (nodeTab->tail && (nodeTab->last_flush - nodeTab->tail->tail->ltime >
                             state->flush_timeout))
    {
        md_ssl_issuer_node_close(state, nodeTab->tail, nodeTab->tail->tail);
    }

}


/**
 * md_ssl_get_cert
 *
 *
 */
static yfNewSSLCertFlow_t *md_ssl_get_cert(
    mdFullFlow_t         *flow,
    yfNewSSLCertFlow_t   **cert)
{
    yfNewSSLFlow_t *sslflow = (yfNewSSLFlow_t *)flow->app;
    /*static yfSSLFullCert_t *fullcert;
      static fbVarfield_t *ct;*/
    static int i = 0;

    if (flow->sslcerts) {
        *cert = flow->sslcerts[i];
        i++;
        if (*cert == NULL) {
            i = 0;
        }
    } else if (sslflow) {
        *cert = (yfNewSSLCertFlow_t *)FBSTLNEXT(&(sslflow->sslCertList), *cert);
    }

    return *cert;

}

/**
 * md_ssl_export_ssl_cert
 *
 *
 *
 */
gboolean md_ssl_export_ssl_cert(
    mdContext_t *ctx,
    md_export_node_t *exp,
    yfNewSSLCertFlow_t *cert,
    GError **err)
{
    md_ssl_dedup_state_t *state = exp->ssl_dedup;
    yfSSLObjValue_t      *obj = NULL;
    yfSSLObjValue_t      *ou = NULL;
    gboolean             found = FALSE;
    FILE                 *fp = NULL;


    while ((obj = (yfSSLObjValue_t *)FBSTLNEXT(&(cert->issuer), obj))) {

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
            found = TRUE;
        }
    }

    if (state) {

        if (state->cert_file) {
            if (!mdExporterDedupFileOpen(ctx->cfg, exp->exp,
                                         &(state->file), &(state->last_file),
                                         state->cert_file,
                                         &(state->last_rotate)))
            {
                return FALSE;
            }
        }

        fp = state->file;
    }

    if ( found ) {
        if (!mdExporterSSLCertRecord(ctx->cfg, exp->exp, fp, cert,
                                     NULL, obj->obj_value.buf,
                                     obj->obj_value.len, 0, err))

        {
            return FALSE;
        }
    } else {
        /* this is where we write the full SSL record */
        if (!mdExporterSSLCertRecord(ctx->cfg, exp->exp, fp, cert,
                                     NULL, NULL, 0, 0, err))

        {
            return FALSE;
        }
    }

    return TRUE;

}


/**
 * md_ssl_add_node
 *
 * add the dns node to the appropriate hash table
 * this is the main part of deduplication.
 *
 * @param ctx
 * @param mdflow
 *
 */

gboolean md_ssl_add_node(
    mdContext_t *ctx,
    md_export_node_t *exp,
    mdFullFlow_t *flow)
{

    md_ssl_dedup_state_t *state = exp->ssl_dedup;
    yfNewSSLCertFlow_t   *cert = NULL;
    yfSSLObjValue_t      *obj = NULL;
    yfSSLObjValue_t      *ou = NULL;
    md_ssl_issuer_node_t *inode = NULL, *tinode = NULL;
    md_ssl_serial_node_t *snode = NULL;
    md_ssl_hashtab_t    *mdtab = state->cert_table;
    uint8_t              namebuf[1024];
    size_t               name_offset = 0;
    smVarHashKey_t       serial;
    gboolean             found = FALSE;
    uint8_t              cert_no = 0;
    uint32_t             mapkey = 0;

    while (md_ssl_get_cert(flow, &cert)) {
        obj = NULL;
        ou = NULL;

        if (cert->serial.len == 0) {
            /* no serial number */
            state->stats.ssl_filtered++;
            cert_no++;
            continue;
        }

        name_offset = 0;

        serial.len = cert->serial.len > 1020 ? 1020 : cert->serial.len;
        serial.val = cert->serial.buf;
        found = FALSE;
        while ((obj = (yfSSLObjValue_t *)FBSTLNEXT(&(cert->issuer), obj))) {

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

            /* update stats */
            state->stats.ssl_recvd++;

            break;
        }

        if (!found) {
            if (ou) {
                obj = ou;
            } else {
                state->stats.ssl_filtered++;
                continue;
            }
        }

        found = FALSE;
        if (state->map) {
            mapkey = smFieldMapTranslate(state->map, flow);
            if (state->map->discard && mapkey == 0) {
                return TRUE;
            }
            memcpy(namebuf, &mapkey, sizeof(uint32_t));
            name_offset += sizeof(uint32_t);
            memcpy(namebuf + name_offset, cert->serial.buf, serial.len);
            serial.len += sizeof(uint32_t);
            serial.val = namebuf;
        }


        /*if (( snode = g_hash_table_lookup(mdtab->table, &serial))) {*/
        if ((snode = smHashLookup(mdtab->table, (uint8_t*)&serial))) {
            for (tinode = snode->head; tinode; tinode = inode) {
                inode = tinode->next;
                if (obj->obj_value.len == tinode->issuer_len) {
                    if (memcmp(obj->obj_value.buf, tinode->issuer, tinode->issuer_len)
                        == 0)
                    {
                        /* match */
                        ++(tinode->hitcount);
                        tinode->ltime = ctx->cfg->ctime;
                        if (tinode->hitcount == state->max_hit_count) {
                            md_ssl_issuer_node_close(state, snode, tinode);
                        } else {
                            md_ssl_issuer_node_tick(exp, snode, tinode);
                            md_ssl_serial_node_tick(mdtab, snode);
                        }
                        found = TRUE;
                        break;
                    }
                }
            }
        } else {

            snode = g_slice_new0(md_ssl_serial_node_t);
            if (snode == NULL) {
                md_ssl_reset_dedup(state, ctx->cfg->ctime);
                snode = g_slice_new0(md_ssl_serial_node_t);
            }

            /* copy key over */
            snode->serial = sm_new_hash_key(serial.val, serial.len);
            /*snode->serial.val = g_slice_alloc0(serial.len);*/
            if (snode->serial == NULL) {
                md_ssl_reset_dedup(state, ctx->cfg->ctime);
                /*snode->serial.val = g_slice_alloc0(serial.len);*/
                snode->serial = sm_new_hash_key(serial.val, serial.len);
            }
            /*memcpy(snode->serial.val, serial.val, serial.len);
              snode->serial.len = serial.len;*/

            if (state->map) {
                snode->mapindex = mapkey;
            } else {
                snode->mapindex = -1;
            }

            /* Insert into hashtable */
            /*g_hash_table_insert(mdtab->table, &(snode->serial), snode);*/
            smHashTableInsert(mdtab->table, (uint8_t*)snode->serial,
                              (uint8_t*)snode);
            ++(mdtab->count);
        }

        if (!found) {
            inode = g_slice_new0(md_ssl_issuer_node_t);
            if (inode == NULL) {
                md_ssl_reset_dedup(state, ctx->cfg->ctime);
                inode = g_slice_new0(md_ssl_issuer_node_t);
            }
            inode->issuer = g_slice_alloc0(obj->obj_value.len);
            memcpy(inode->issuer, obj->obj_value.buf, obj->obj_value.len);
            inode->issuer_len = obj->obj_value.len;
            inode->ftime = ctx->cfg->ctime;
            inode->ltime = ctx->cfg->ctime;
            (inode->hitcount)++;

            if (state->cert_file) {
                if (!mdExporterDedupFileOpen(ctx->cfg, exp->exp,
                                            &(state->file), &(state->last_file),
                                            state->cert_file, &(state->last_rotate)))
                {
                    return FALSE;
                }
            }

            /* this is where we write the full SSL record */
            if (!mdExporterSSLCertRecord(ctx->cfg, exp->exp, state->file, cert,
                                         flow->fullcert,
                                         inode->issuer,
                                         inode->issuer_len, cert_no,
                                         &(ctx->err)))
            {
                return FALSE;
            }

            md_ssl_issuer_node_tick(exp, snode, inode);
            md_ssl_serial_node_tick(mdtab, snode);
        }

        cert_no++;

    }

    /* attempt a flush on all tables */
    md_ssl_flush_tab(state, ctx->cfg->ctime, FALSE);

    return TRUE;

}

static gboolean md_ssl_decode_oid(
    uint8_t         *buffer,
    uint16_t        *offset,
    uint8_t         obj_len)
{
    uint32_t tobjid;

    if (obj_len == 9) {
        /* pkcs-9 */
        tobjid = ntohl(*(uint32_t *)(buffer + *offset));
        if (tobjid != CERT_PKCS) {
            return FALSE;
        }
        *offset += 8;
    } else if (obj_len == 10) {
        /* LDAP Domain Component */
        tobjid = ntohl(*(uint32_t *)(buffer + *offset));
        if (tobjid != CERT_DC) {
            return FALSE;
        }
        *offset += 9;
    } else if (obj_len == 3) {
        *offset += 2;
    } else {
        /* this isn't the usual id-at, pkcs, or dc - so lets ignore it */
        return FALSE;
    }

    return TRUE;
}


static uint8_t md_ssl_get_extension_count(
    uint8_t                *buffer,
    uint16_t                ext_len)
{

    uint16_t               offsetptr = 0;
    md_asn_tlv_t           tlv;
    uint16_t               len = 2;
    uint16_t               obj_len = 0;
    uint16_t               id_ce;
    uint8_t                obj_type = 0;
    uint8_t                count = 0;

    obj_len = md_util_decode_tlv(&tlv, buffer, &offsetptr);
    while (tlv.tag == CERT_SEQ && len < ext_len) {
        len += obj_len + 2;
        if (*(buffer + offsetptr) == CERT_OID) {
            id_ce = ntohs(*(uint16_t *)(buffer + offsetptr + 2));
            if (id_ce == CERT_IDCE) {
                obj_type = *(buffer + offsetptr + 4);
                switch (obj_type) {
                  case 14:
                    /* subject key identifier */
                  case 15:
                    /* key usage */
                  case 16:
                    /* private key usage period */
                  case 17:
                    /* alternative name */
                  case 18:
                    /* alternative name */
                  case 29:
                    /* authority key identifier */
                  case 31:
                    /* CRL dist points */
                  case 32:
                    /* Cert Policy ID */
                  case 35:
                    /* Authority Key ID */
                  case 37:
                    count++;
                  default:
                    break;
                }
            }
        }
        offsetptr += obj_len;
        obj_len = md_util_decode_tlv(&tlv, buffer, &offsetptr);
    }

    return count;
}


yfNewSSLCertFlow_t *md_ssl_cert_decode(
    uint8_t      *cert,
    size_t        cert_len,
    fbTemplate_t  *tmpl)
{
    yfNewSSLCertFlow_t     *sslCert = NULL;
    uint16_t                offsetptr = 0;
    uint16_t                tot_ext_len = 0;
    uint16_t                ext_hold = 0;
    uint8_t                 seq_count;
    uint8_t                 obj_type = 0;
    md_asn_tlv_t            tlv;
    yfSSLObjValue_t         *sslObject = NULL;
    uint16_t                obj_len;
    uint16_t                set_len;
    uint16_t                off_hold;
    uint16_t                id_ce;

    if (ntohs(*(uint16_t *)(cert + offsetptr)) != 0x3082) {
        g_warning("Error decoding template. Invalid header.");
        return NULL;
    }

    sslCert = g_slice_new0(yfNewSSLCertFlow_t);

    /* 2 bytes for above, 2 for length of CERT */
    /* Next we have a signed CERT so 0x3082 + length */

    offsetptr += 8;

    /* A0 is for explicit tagging of Version Number */
    /* 03 is an Integer - 02 is length, 01 is for tagging */
    if (*(cert + offsetptr) == CERT_EXPLICIT) {
        offsetptr += 4;
        sslCert->version = *(cert + offsetptr);
        offsetptr++;
    } else {
        /* default version is version 1 [0] */
        sslCert->version = 0;
    }

    /* serial number */
    obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
    if (obj_len > cert_len) {
        g_debug("Error decoding certificate: Invalid serial number length");
        goto err;
    }
    if (tlv.tag == CERT_INT) {
        sslCert->serial.buf = cert + offsetptr;
        sslCert->serial.len = obj_len;
    }
    offsetptr += obj_len;

    /* signature */
    obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
    if (obj_len > cert_len) {
        g_debug("Error decoding certificate: Invalid signature length");
        goto err;
    }

    if (tlv.tag != CERT_SEQ) {
        offsetptr += obj_len;
    } else {
        obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
        if (tlv.tag == CERT_OID) {
            if (obj_len > cert_len) {
                g_debug("Error decoding certificate: Invalid object length");
                goto err;
            }
            sslCert->sig.buf = cert + offsetptr;
            sslCert->sig.len = obj_len;
        }
        offsetptr += obj_len;
    }

    /* issuer - sequence */
    obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
    if (obj_len > cert_len) {
        g_debug("Error decoding certificate: Invalid sequence length");
        goto err;
    }

    if (tlv.tag == CERT_SEQ) {
        seq_count = md_util_asn1_sequence_count((cert + offsetptr), obj_len);
    } else {
        g_debug("Error decoding certificate: Invalid issuer sequence");
        goto err;
    }

    sslObject = (yfSSLObjValue_t *)fbSubTemplateListInit(&(sslCert->issuer),
                                                         0,
                                                         YAF_SSL_SUBCERT_TID,
                                                         tmpl,
                                                         seq_count);
    while (seq_count && sslObject) {
        set_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
        if (set_len >= cert_len) {
            g_debug("Error decoding certificate: Invalid set length");
            goto err;
        }
        if (tlv.tag != CERT_SET) {
            break;
        }
        off_hold = offsetptr;
        obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
        if (obj_len >= cert_len) {
            g_debug("Error decoding certificate: Invalid object length");
            goto err;
        }
        if (tlv.tag != CERT_SEQ) {
            break;
        }
        obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
        if (obj_len >= cert_len) {
            g_debug("Error decoding certificate: Invalid object length");
            goto err;
        }

        if (tlv.tag != CERT_OID) {
            break;
        }

        if (!md_ssl_decode_oid(cert, &offsetptr, obj_len)) {
            sslObject++;
            seq_count--;
            offsetptr = off_hold + set_len;
            continue;
        }

        sslObject->obj_id = *(cert + offsetptr);
        offsetptr += 2;
        sslObject->obj_value.len = md_util_decode_length(cert, &offsetptr);
        if (sslObject->obj_value.len >= cert_len) {
            g_debug("Error decoding certificate: Invalid object length");
            goto err;
        }
        offsetptr++;
        /* OBJ VALUE */
        sslObject->obj_value.buf = cert + offsetptr;
        offsetptr += sslObject->obj_value.len;
        seq_count--;
        sslObject++;
    }

    /* VALIDITY is a sequence of times */
    obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
    if (obj_len >= cert_len) {
        g_debug("Error decoding certificate: Invalid object length");
        goto err;
    }

    if (tlv.tag != CERT_SEQ) {
        g_debug("Error decoding certificate: Invalid validity sequence");
        goto err;
    }

    /* notBefore time */
    obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
    if (obj_len >= cert_len) {
        g_debug("Error decoding certificate: Invalid object length notBeforeTime");
        goto err;
    }
    if (tlv.tag != CERT_TIME) {
        g_debug("Error decoding certificate: Invalid Time Tag");
        goto err;
    }
    sslCert->not_before.buf = cert + offsetptr;
    sslCert->not_before.len = obj_len;

    offsetptr += obj_len;

    /* not After time */
    obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
    if (obj_len >= cert_len) {
        g_debug("Error decoding certificate: Invalid object length notAfter Time");
        goto err;
    }
    if (tlv.tag != CERT_TIME) {
        g_debug("Error decoding certificate: Invalid Time Tag");
        goto err;
    }
    sslCert->not_after.buf = cert + offsetptr;
    sslCert->not_after.len = obj_len;

    offsetptr += obj_len;

    obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
    if (obj_len >= cert_len) {
        g_debug("Error decoding certificate: Invalid object length for subject seq");
        goto err;
    }

    /* subject - sequence */
    if (tlv.tag == CERT_SEQ) {
        seq_count = md_util_asn1_sequence_count((cert + offsetptr), obj_len);
    } else {
        g_debug("Error decoding certificate: Invalid subject sequence");
        goto err;
    }

    sslObject = (yfSSLObjValue_t *)fbSubTemplateListInit(&(sslCert->subject), 0,
                                                         YAF_SSL_SUBCERT_TID,
                                                         tmpl,
                                                         seq_count);

    while (seq_count && sslObject) {
        set_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
        if (set_len >= cert_len) {
            g_debug("Error decoding certificate: Invalid subject set length");
            goto err;
        }
        off_hold = offsetptr;
        if (tlv.tag != CERT_SET) {
            break;
        }
        obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
        if (obj_len >= cert_len) {
            g_debug("Error decoding certificate: Invalid object length");
            goto err;
        }

        if (tlv.tag != CERT_SEQ) {
            break;
        }
        obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
        if (obj_len >= cert_len) {
            g_debug("Error decoding certificate: Invalid object length");
            goto err;
        }
        if (tlv.tag != CERT_OID) {
            break;
        }

        if (!md_ssl_decode_oid(cert, &offsetptr, obj_len)) {
            sslObject++;
            seq_count--;
            offsetptr = off_hold + set_len;
            continue;
        }
        sslObject->obj_id = *(cert + offsetptr);
        offsetptr += 2;
        sslObject->obj_value.len = md_util_decode_length(cert, &offsetptr);
        if (sslObject->obj_value.len >= cert_len) {
            g_debug("Error decoding certificate: Invalid object length");
            goto err;
        }
        offsetptr++;
        /* OBJ VALUE */
        sslObject->obj_value.buf = cert + offsetptr;
        offsetptr += sslObject->obj_value.len;
        seq_count--;
        sslObject++;
    }

    /* subject public key info */
    /* this is a sequence of a sequence of algorithms and public key */
    obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
    if (obj_len >= cert_len) {
        g_debug("Error decoding certificate: Invalid object length for pk info");
        goto err;
    }
    /* this needs to be a sequence */
    if (tlv.tag != CERT_SEQ) {
        offsetptr += obj_len;
    } else {
        /* this is also a seq */
        obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
        if (obj_len >= cert_len) {
            g_debug("Error decoding certificate: Invalid sequence");
            goto err;
        }
        if (tlv.tag != CERT_SEQ) {
            offsetptr += obj_len;
        } else {
            obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
            if (obj_len >= cert_len) {
                g_debug("Error decoding certificate: Invalid object length");
                goto err;
            }
            /* this is the algorithm id */
            if (tlv.tag == CERT_OID) {
                sslCert->pkalg.buf = cert + offsetptr;
                sslCert->pkalg.len = obj_len;
            }
            offsetptr += obj_len;
            obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
            if (obj_len >= cert_len) {
                g_debug("Error decoding certificate: Invalid object length");
                goto err;
            }
            /* this is the actual public key */
            if (tlv.tag == CERT_BITSTR) {
                sslCert->pklen = obj_len;
            }
            offsetptr += obj_len;
        }
    }

    /* EXTENSIONS! - ONLY AVAILABLE FOR VERSION 3 */
    /* since it's optional - it has a tag if it's here */
    obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
    if (obj_len >= cert_len) {
        g_debug("Error decoding certificate: Invalid object length for Extensions");
        goto err;
    }

    if ((tlv.class != 2) || (sslCert->version != 2)) {
        /* no extensions */
        ext_hold = offsetptr;
        fbSubTemplateListInit(&(sslCert->extension), 0,
                              YAF_SSL_SUBCERT_TID,
                              tmpl, 0);
    } else {
        uint16_t ext_len;
        obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
        tot_ext_len = obj_len;
        if (obj_len >= cert_len) {
            g_debug("Error decoding certificate: Invalid ext object length");
            goto err;
        }

        ext_hold = offsetptr;

        if (tlv.tag == CERT_SEQ) {
            seq_count = md_ssl_get_extension_count((cert + offsetptr), obj_len);
        } else {
            g_debug("Error decoding certificate: Invalid extension sequence");
            goto err;
        }
        /* extensions */
        sslObject =
            (yfSSLObjValue_t *)fbSubTemplateListInit(&(sslCert->extension),
                                                     0,
                                                     YAF_SSL_SUBCERT_TID,
                                                     tmpl,
                                                     seq_count);
        /* exts is a sequence of a sequence of {id, critical flag, value} */
        while (seq_count && sslObject) {
            ext_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
            if (ext_len >= cert_len) {
                g_debug("Error decoding certificate: Invalid ext object length");
                goto err;
            }

            if (tlv.tag != CERT_SEQ) {
                g_debug("Error decoding certificate: Invalid ext sequence tag");
                goto err;
            }

            off_hold = offsetptr;
            obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
            if (obj_len >= ext_len) {
                g_debug("Error decoding certificate: Invalid ext object length");
                goto err;
            }

            if (tlv.tag != CERT_OID) {
                g_debug("Error decoding certificate: Invalid ext object tag");
                goto err;
            }
            id_ce = ntohs(*(uint16_t *)(cert + offsetptr));
            if (id_ce != CERT_IDCE) {
                /* jump past this */
                offsetptr = off_hold + ext_len;
                continue;
            }
            offsetptr += 2;
            obj_type = *(cert + offsetptr);
            offsetptr++;
            obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
            if (obj_len >= ext_len) {
                g_debug("Error decoding certificate: Invalid ext object length");
                goto err;
            }
            if (tlv.tag == CERT_BOOL) {
                /* this is optional CRITICAL flag */
                offsetptr += obj_len;
                obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
                if (obj_len >= ext_len) {
                    g_debug("Error decoding certificate: Invalid ext object length");
                    goto err;
                }
            }
            switch (obj_type) {
              case 14:
                /* subject key identifier */
              case 15:
                /* key usage */
              case 16:
                /* private key usage period */
              case 17:
                /* alternative name */
              case 18:
                /* alternative name */
              case 29:
                /* authority key identifier */
              case 31:
                /* CRL dist points */
              case 32:
                /* Cert Policy ID */
              case 35:
                /* Authority Key ID */
              case 37:
                /* ext. key usage */
                sslObject->obj_id = obj_type;
                sslObject->obj_value.len = obj_len;
                sslObject->obj_value.buf = cert + offsetptr;
                offsetptr += obj_len;
                seq_count--;
                sslObject++;
                break;
              default:
                offsetptr = off_hold + ext_len;
                continue;
            }

        }
    }

    /* signature again */
    offsetptr = ext_hold + tot_ext_len;
    if (offsetptr > cert_len) {
        goto err;
    }
    obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
    if (obj_len > cert_len) {
        goto err;
    }

    if (tlv.tag == CERT_SEQ) {
        obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
        if (tlv.tag != CERT_OID) {
            goto err;
        }

        offsetptr += obj_len;
        if (offsetptr > cert_len) {
            goto err;
        }
        obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
        /*get past padding */
        offsetptr++;
        if ((offsetptr + obj_len) > cert_len) {
            goto err;
        }
        if (tlv.tag != CERT_BITSTR) {
            goto err;
        }
        if ((obj_len-1) % 16) {
            goto err;
        }
        sslCert->hash.len = obj_len - 1;
        sslCert->hash.buf = cert + offsetptr;
    }

  err:

    return sslCert;

}

#if HAVE_OPENSSL
void md_ssl_md5_hash(
    unsigned char    *hash,
    uint8_t          *cert,
    size_t           cert_len)
{
    MD5(cert, cert_len, hash);
}

void md_ssl_sha1_hash(
    unsigned char    *hash,
    uint8_t          *cert,
    size_t           cert_len)
{
    SHA1(cert, cert_len, hash);
}




#endif
