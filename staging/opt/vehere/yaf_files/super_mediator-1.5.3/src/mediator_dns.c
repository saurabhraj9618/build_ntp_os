/**
 * @file mediator_dns.c
 *
 * Yaf mediator for filtering, DNS deduplication, and other mediator-like
 * things
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

#include "mediator_dns.h"
#include <mediator/mediator_inf.h>
#include <mediator/mediator_util.h>

#define DNS_DEBUG 0

#define FBSTLNEXT(a, b) fbSubTemplateListGetNextPtr(a, b)
#define A_REC_TID(_id_) (_id_ |= MD_DNS_AREC)
#define OTHER_REC_TID(_id_) (_id_ |= MD_DNS_OREC)

typedef struct md_dns_dedup_stats_st {
    uint64_t       dns_recvd;
    uint64_t       dns_filtered;
    uint64_t       dns_flushed;
} md_dns_dedup_stats_t;


struct md_dns_dedup_state_st {
    md_dns_dedup_stats_t  stats;
    md_type_hashtab_t *a_table;
    md_type_hashtab_t *ns_table;
    md_type_hashtab_t *cname_table;
    md_type_hashtab_t *soa_table;
    md_type_hashtab_t *ptr_table;
    md_type_hashtab_t *mx_table;
    md_type_hashtab_t *txt_table;
    md_type_hashtab_t *aaaa_table;
    md_type_hashtab_t *srv_table;
    md_type_hashtab_t *nx_table;
    md_dns_cqueue_t   *cq;
    smFieldMap_t      *map;
    int               *dedup_type_list;
    uint64_t dedup_flush_to;
    uint32_t dedup_max_hit_count;
    gboolean print_lastseen;
    gboolean export_name;
};

struct md_dns_node_st {
    struct md_dns_node_st *next;
    struct md_dns_node_st *prev;
    md_dns_t dns_node;
};


/**
 * allocTypeTab
 *
 *
 */
static md_type_hashtab_t *allocTypeTab (
    uint64_t            cur_time)
{

    md_type_hashtab_t *md_type_tab;

    md_type_tab = g_slice_new0(md_type_hashtab_t);
    /*md_type_tab->table = g_hash_table_new((GHashFunc)g_str_hash,
      (GEqualFunc)g_str_equal);*/
    md_type_tab->table = smCreateHashTable(0xFF,
                                           sm_octet_array_key_destroy, NULL);
    if (md_type_tab->table == NULL) {
        return NULL;
    }

    md_type_tab->last_flush = cur_time;

    return md_type_tab;

}

/**
 * md_dns_dedup_print_stats
 *
 * Prints stats to the log.
 *
 *
 */
void md_dns_dedup_print_stats(
    md_dns_dedup_state_t *state,
    char                 *exp_name)
{
    if (state->stats.dns_recvd == 0) {
        return;
    }

    g_message("Exporter %s: %"PRIu64" DNS records, %"PRIu64" filtered"
              ", %"PRIu64" flushed (%2.2f%% compression)", exp_name,
              state->stats.dns_recvd, state->stats.dns_filtered,
              state->stats.dns_flushed, (1 -(((double)state->stats.dns_flushed)/
                                             ((double)state->stats.dns_recvd))) *
              100);
}

/**
 * md_dns_reset_dedup
 *
 * Flushes all Hash Tables.
 *
 */

void md_dns_reset_dedup(
    md_dns_dedup_state_t *state,
    uint64_t             cur_time)
{
    g_warning("Out of Memory Error.  Resetting all Hash Tables");
    md_dns_flush_all_tab(state, cur_time, TRUE);
}

static void md_dns_attempt_flush_tab(
    md_type_hashtab_t    *md_type_tab,
    md_dns_dedup_state_t *state,
    uint64_t             ctime)
{

    if (md_type_tab && ((ctime - md_type_tab->last_flush) >
                        state->dedup_flush_to))
    {
        md_dns_flush_tab(md_type_tab, state, ctime, FALSE);
    }
}

static void md_dns_attempt_all_flush(
    md_dns_dedup_state_t *state,
    uint64_t             cur_time)
{
    md_dns_attempt_flush_tab(state->a_table, state, cur_time);
    md_dns_attempt_flush_tab(state->ns_table, state, cur_time);
    md_dns_attempt_flush_tab(state->cname_table, state, cur_time);
    md_dns_attempt_flush_tab(state->soa_table, state, cur_time);
    md_dns_attempt_flush_tab(state->ptr_table, state, cur_time);
    md_dns_attempt_flush_tab(state->mx_table, state, cur_time);
    md_dns_attempt_flush_tab(state->txt_table, state, cur_time);
    md_dns_attempt_flush_tab(state->aaaa_table, state, cur_time);
    md_dns_attempt_flush_tab(state->srv_table, state, cur_time);
    md_dns_attempt_flush_tab(state->nx_table, state, cur_time);
}




/**
 * md_dns_destroy_tab
 *
 * destroys all hash tables
 *
 */
void md_dns_destroy_tab(
    md_dns_dedup_state_t *state)
{

    if (state->a_table && state->a_table->table) {
        smHashTableFree(state->a_table->table);
    }
    if (state->ns_table && state->ns_table->table) {
        smHashTableFree(state->ns_table->table);
    }
    if (state->cname_table && state->cname_table->table) {
        smHashTableFree(state->cname_table->table);
    }
    if (state->soa_table && state->soa_table->table) {
        smHashTableFree(state->soa_table->table);
    }
    if (state->ptr_table && state->ptr_table->table) {
        smHashTableFree(state->ptr_table->table);
    }
    if (state->mx_table && state->mx_table->table) {
        smHashTableFree(state->mx_table->table);
    }
    if (state->txt_table && state->txt_table->table) {
        smHashTableFree(state->txt_table->table);
    }
    if (state->aaaa_table && state->aaaa_table->table) {
        smHashTableFree(state->aaaa_table->table);
    }
    if (state->nx_table && state->nx_table->table) {
        smHashTableFree(state->nx_table->table);
    }
    if (state->srv_table && state->srv_table->table) {
        smHashTableFree(state->srv_table->table);
    }
}

gboolean md_dns_dedup_free_state(
    mdConfig_t           *cfg,
    md_export_node_t     *exp,
    GError               **err)

{
    md_dns_dedup_state_t *state = exp->dns_dedup;

    md_dns_flush_all_tab(state, cfg->ctime, TRUE);

    if (!md_dns_flush_queue(exp, cfg, err)) {
        return FALSE;
    }

    md_dns_destroy_tab(state);
    if (state->dedup_type_list) {
        g_free(state->dedup_type_list);
    }

    g_slice_free1(sizeof(md_dns_cqueue_t), state->cq);
    return TRUE;
}

/**
 * md_debug_table
 *
 *
 */
#if DNS_DEBUG == 1
static void md_debug_table(
    md_type_hashtab_t *nodeTab)
{

    md_cache_node_t *cq;
    md_hashtab_node_t *hn;

    for (hn = nodeTab->head; hn; hn = hn->next) {
        for (cq = hn->head; cq; cq = cq->next) {
            g_debug("%d %p rrname %s", cq->rrtype, cq,
                    hn->rrname);
            g_debug("cq->next is %p", cq->next);
        }
    }
}
#endif
/**
 * md_new_dns_queue
 *
 * creates a new close queue for dns-dedup
 */
md_dns_cqueue_t *md_new_dns_queue(
    void)
{

    md_dns_cqueue_t *cq = g_slice_new0(md_dns_cqueue_t);

    cq->head = NULL;
    cq->tail = NULL;

    return cq;
}

md_dns_dedup_state_t *md_new_dns_dedup_state(
    void)
{
    md_dns_dedup_state_t *state = g_slice_new0(md_dns_dedup_state_t);

    state->cq = md_new_dns_queue();

    /* set defaults */
    state->dedup_max_hit_count = 5000;
    state->dedup_flush_to = 300 * 1000;
    state->print_lastseen = FALSE;

    return state;
}

void md_dns_dedup_configure_state(
    md_dns_dedup_state_t *state,
    int                  *dedup_list,
    int                   max_hit,
    int                   flush_timeout,
    gboolean              lastseen,
    smFieldMap_t          *map,
    gboolean              export_name)
{
    if (!state) {
        return;
    }

    state->dedup_type_list = dedup_list;
    state->print_lastseen = lastseen;
    state->export_name = export_name;
    if (max_hit) {
        state->dedup_max_hit_count = max_hit;
    }
    if (flush_timeout) {
        state->dedup_flush_to = flush_timeout * 1000;
    }
    if (map) {
        state->map = map;
    }
}

/**
 * md_dns_flush_queue
 *
 * Flushes all records in the close queue.
 *
 */
gboolean md_dns_flush_queue(
    md_export_node_t    *exp,
    mdConfig_t          *cfg,
    GError              **err)
{
    md_dns_node_t       *node;
    md_dns_dedup_state_t *state = exp->dns_dedup;
    md_dns_cqueue_t     *cq = exp->dns_dedup->cq;
    uint16_t            tid = MD_DNS_OUT;
    uint16_t            wtid;

    if (cq == NULL) {
        return TRUE;
    }

    if (state->print_lastseen) {
       tid |= MD_LAST_SEEN;
    }

    wtid = tid;

    while ((node = detachFromEndOfDLL((mdDLL_t **)&(cq->head),
                                      (mdDLL_t **)&(cq->tail))))
    {   wtid = tid;
        if (node->dns_node.rrtype == 1) {
            A_REC_TID(wtid);
        } else {
            OTHER_REC_TID(wtid);
        }

        if (state->export_name && (node->dns_node.mapname.len == 0)) {
            node->dns_node.mapname.buf = (uint8_t*)mdExporterGetName(exp->exp);
            node->dns_node.mapname.len = strlen(mdExporterGetName(exp->exp));
        }

        if (!mdExporterWriteRecord(cfg, exp->exp, wtid,
                                   (uint8_t *)&(node->dns_node),
                                   sizeof(md_dns_t), err))
        {
            return FALSE;
        }

        state->stats.dns_flushed++;
        g_slice_free1(node->dns_node.rrdata.len, node->dns_node.rrdata.buf);
        g_slice_free1(node->dns_node.rrname.len, node->dns_node.rrname.buf);
        g_slice_free(md_dns_node_t, node);

    }

    /* free the node we just sent out */

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
static void nodeClose (
    md_type_hashtab_t *nodeTab,
    md_hashtab_node_t *hnode)
{
    /*Remove it from list*/

    /*    g_hash_table_remove(nodeTab->table, hnode->rrname);*/
    smHashTableRemove(nodeTab->table, (uint8_t*)hnode->rkey);

    detachThisEntryOfDLL((mdDLL_t**)&(nodeTab->head),
                         (mdDLL_t**)&(nodeTab->tail), (mdDLL_t*)hnode);

    /* free the rrname */

    //    g_slice_free1(hnode->rrname_len, hnode->rrname);
    g_slice_free(md_hashtab_node_t, hnode);

    --(nodeTab->count);
}

/**
 * newCacheNode
 *
 * creates a new cache node which will go into
 * a linked list by hash node.  Basically this
 * has the same query name, but a different type
 * or rrdata
 */
static md_cache_node_t *newCacheNode (
    uint64_t            start_time,
    uint32_t            ip,
    uint16_t            rrtype,
    uint8_t             *capt,
    unsigned int        caplen)
{
    md_cache_node_t *cn;

    cn = g_slice_new0(md_cache_node_t);
    if (cn == NULL) {
        return NULL;
    }
    cn->hitcount = 1;
    cn->ftime = start_time;
    cn->ltime = start_time;
    cn->ip = ip;
    cn->rrtype = rrtype;

    if (caplen) {
        cn->rrdata = g_slice_alloc0(caplen);
        if (cn->rrdata == NULL) {
            return NULL;
        }
        memcpy(cn->rrdata, capt, caplen);
        cn->caplen = caplen;
    }

    return cn;
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
static void hashTick (
    md_type_hashtab_t *nodeTab,
    md_hashtab_node_t *entry)
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
 * cacheNodeClose
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
static void cacheNodeClose (
    md_type_hashtab_t       *nodeTab,
    md_hashtab_node_t       *hn,
    md_cache_node_t         *cn,
    md_dns_dedup_state_t    *state)
{

    md_dns_cqueue_t         *cq = state->cq;

    if (state->print_lastseen) {
        md_dns_node_t *node = g_slice_new0(md_dns_node_t);
        node->dns_node.fseen = cn->ftime;
        node->dns_node.lseen = cn->ltime;
        node->dns_node.ip = cn->ip;
        node->dns_node.rrtype = cn->rrtype;
        node->dns_node.hitcount = cn->hitcount;
        node->dns_node.ttl = cn->ttl;
        node->dns_node.rrdata.buf = g_slice_alloc0(cn->caplen);
        memcpy(node->dns_node.rrdata.buf, cn->rrdata, cn->caplen);
        node->dns_node.rrdata.len = cn->caplen;
        /*node->dns_node.rrname.buf = g_slice_alloc0(hn->rrname_len);*/
        /*memcpy(node->dns_node.rrname.buf, hn->rrname, hn->rrname_len);
          node->dns_node.rrname.len = hn->rrname_len;*/
        if (hn->mapindex < 0) {
            node->dns_node.rrname.buf = g_slice_alloc0(hn->rkey->len);
            memcpy(node->dns_node.rrname.buf, hn->rkey->val, hn->rkey->len);
            node->dns_node.rrname.len = hn->rkey->len;
            node->dns_node.mapname.len = 0;
        } else {
            node->dns_node.rrname.buf = g_slice_alloc0(hn->rkey->len - sizeof(uint32_t));
            memcpy(node->dns_node.rrname.buf, hn->rkey->val+sizeof(uint32_t), hn->rkey->len-sizeof(uint32_t));
            node->dns_node.rrname.len = hn->rkey->len - sizeof(uint32_t);
            node->dns_node.mapname.buf = (uint8_t*)(state->map->labels[hn->mapindex]);
            node->dns_node.mapname.len = strlen(state->map->labels[hn->mapindex]);
        }


        attachHeadToDLL((mdDLL_t **)&(cq->head),
                        (mdDLL_t **)&(cq->tail),
                        (mdDLL_t *)node);
    }
    detachThisEntryOfDLL((mdDLL_t**)&(hn->head),
                         (mdDLL_t**)&(hn->tail),
                         (mdDLL_t*)cn);

    g_slice_free1(cn->caplen, cn->rrdata);
    g_slice_free(md_cache_node_t, cn);

    if (!hn->head) {
        /*last cacheNode in hashTabNode - remove from hashtable*/
        nodeClose(nodeTab, hn);
    }
}

/**
 * md_dns_emit_record
 *
 * Adds the record to the close queue without removing
 * the node.
 *
 * @param cq - the close queue to add it to
 * @param cn - the node to add
 *
 */

static void md_dns_emit_record(
    md_dns_dedup_state_t *state,
    md_dns_cqueue_t      *cq,
    md_hashtab_node_t    *hn,
    md_cache_node_t      *cn)
{

    md_dns_node_t *node = g_slice_new0(md_dns_node_t);

    if (node == NULL) {
        g_debug("Potentially out of memory.");
        return;
    }

    node->dns_node.fseen = cn->ftime;
    node->dns_node.lseen = cn->ltime;
    node->dns_node.ip = cn->ip;
    node->dns_node.rrtype = cn->rrtype;
    node->dns_node.hitcount = cn->hitcount;
    node->dns_node.ttl = cn->ttl;
    if (hn->mapindex < 0) {
        node->dns_node.rrname.buf = g_slice_alloc0(hn->rkey->len);
        memcpy(node->dns_node.rrname.buf, hn->rkey->val, hn->rkey->len);
        node->dns_node.rrname.len = hn->rkey->len;
        node->dns_node.mapname.len = 0;
    } else {
        node->dns_node.rrname.buf = g_slice_alloc0(hn->rkey->len - sizeof(uint32_t));
        memcpy(node->dns_node.rrname.buf, hn->rkey->val+sizeof(uint32_t),
               hn->rkey->len-sizeof(uint32_t));
        node->dns_node.rrname.len = hn->rkey->len - sizeof(uint32_t);
        node->dns_node.mapname.buf = (uint8_t*)(state->map->labels[hn->mapindex]);
        node->dns_node.mapname.len = strlen(state->map->labels[hn->mapindex]);
    }

    node->dns_node.rrdata.buf = g_slice_alloc0(cn->caplen);
    memcpy(node->dns_node.rrdata.buf, cn->rrdata, cn->caplen);
    node->dns_node.rrdata.len = cn->caplen;

    /*node->dns_node.rrname.buf = g_slice_alloc0(hn->rrname_len);
    memcpy(node->dns_node.rrname.buf, hn->rrname, hn->rrname_len);
    node->dns_node.rrname.len = hn->rrname_len;*/

    attachHeadToDLL((mdDLL_t **)&(cq->head),
                    (mdDLL_t **)&(cq->tail),
                    (mdDLL_t *)node);
}


/**
 * hashCacheTick
 *
 * advances a node to the head of the cache queue
 * bottom gets examined for flush timeouts
 *
 * @param pointer to head of table
 * @param pointer to node
 *
 */
static void hashCacheTick (
    md_dns_dedup_state_t  *state,
    md_type_hashtab_t     *nodeTab,
    md_hashtab_node_t     *hn,
    md_cache_node_t       *cn)
{

    if (hn->head != cn) {
        if (cn->prev != NULL) {
            detachThisEntryOfDLL((mdDLL_t**)&(hn->head),
                                 (mdDLL_t**)&(hn->tail),
                                 (mdDLL_t*)cn);
        }
        attachHeadToDLL((mdDLL_t**)&(hn->head),
                        (mdDLL_t**)&(hn->tail),
                        (mdDLL_t*)cn);
    }

    while (hn->tail &&((cn->ltime - hn->tail->ltime) > state->dedup_flush_to))
    {
        cacheNodeClose(nodeTab, hn, hn->tail, state);
    }

}


/**
 * md_dns_flush_tab
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
void md_dns_flush_tab (
    md_type_hashtab_t *nodeTab,
    md_dns_dedup_state_t *state,
    uint64_t          cur_time,
    gboolean          flush_all)
{

    if (nodeTab == NULL) {
        return;
    }

    nodeTab->last_flush = cur_time;

    while (flush_all && nodeTab->tail) {
        cacheNodeClose(nodeTab, nodeTab->tail, nodeTab->tail->tail, state);
    }

    while (nodeTab->tail && (nodeTab->last_flush - nodeTab->tail->tail->ltime >
                             state->dedup_flush_to))
    {
        cacheNodeClose(nodeTab, nodeTab->tail, nodeTab->tail->tail, state);
    }

}


/**
 * md_dns_flush_all_tab
 *
 * Flushes all entries from all hash tables
 *
 * @param cq
 *
 */
void md_dns_flush_all_tab(
    md_dns_dedup_state_t *state,
    uint64_t         cur_time,
    gboolean         flush_all)
{
    md_dns_flush_tab(state->a_table, state, cur_time, flush_all);
    md_dns_flush_tab(state->ns_table, state, cur_time, flush_all);
    md_dns_flush_tab(state->cname_table, state, cur_time, flush_all);
    md_dns_flush_tab(state->soa_table, state, cur_time, flush_all);
    md_dns_flush_tab(state->ptr_table, state, cur_time, flush_all);
    md_dns_flush_tab(state->mx_table, state, cur_time, flush_all);
    md_dns_flush_tab(state->txt_table, state, cur_time, flush_all);
    md_dns_flush_tab(state->aaaa_table, state, cur_time, flush_all);
    md_dns_flush_tab(state->srv_table, state, cur_time, flush_all);
    md_dns_flush_tab(state->nx_table, state, cur_time, flush_all);


}

/**
 * md_add_dns_node
 *
 * add the dns node to the appropriate hash table
 * this is the main part of deduplication.
 *
 * @param ctx
 * @param mdflow
 *
 */

void md_add_dns_node(
    mdContext_t *ctx,
    md_export_node_t *exp,
    mdFullFlow_t *flow)
{

    md_dns_dedup_state_t *state = exp->dns_dedup;
    yfDNSFlow_t          *dnsflow = (yfDNSFlow_t *)flow->app;
    yfDNSQRFlow_t        *dnsqrflow = NULL;
    md_cache_node_t      *cn = NULL, *tn = NULL;
    int                  *type_list = state->dedup_type_list;
    md_cache_node_t      find;
    md_hashtab_node_t    *hn = NULL;
    md_type_hashtab_t    *md_type_tab = NULL;
    uint8_t              namebuf[1024];
    uint16_t             name_offset=0;
    size_t               namelen = 0;
    gboolean             found = FALSE;
    int                  nx = 0;
    smVarHashKey_t       key;
    uint32_t             mapkey = 0;

    while (( dnsqrflow = (yfDNSQRFlow_t *)FBSTLNEXT(&(dnsflow->dnsQRList),
                                                    dnsqrflow)))
    {
        find.ip = 0;
        find.caplen = 0;
        find.rrdata = NULL;
        namelen = 0;
        name_offset = 0;
        found = FALSE;
        nx = 0;
        find.rrtype = dnsqrflow->dnsQRType;
        find.ttl = dnsqrflow->dnsTTL;

        if (dnsqrflow->dnsNXDomain == 3 && dnsqrflow->dnsRRSection == 0) {
            find.rrtype = 0;
            nx = 1;
        }

        if (!nx && !dnsqrflow->dnsQueryResponse) {
            /* don't do queries */
            continue;
        }

        if (find.rrtype > 34) {
            /* not a valid DNS type for super_mediator dedup */
            state->stats.dns_filtered++;
            continue;
        }

        if (type_list) {
            if (type_list[find.rrtype] == 0) {
                /* filtered out*/
                state->stats.dns_filtered++;
                continue;
            }
        }

        if (nx == 1) {
            /* NXDomain */
            if (dnsqrflow->dnsQName.buf) {
                if (state->nx_table == NULL) {
                    state->nx_table = allocTypeTab(ctx->cfg->ctime);
                }
                md_type_tab = state->nx_table;
            } else {
                state->stats.dns_filtered++;
                continue;
            }
        } else if (dnsqrflow->dnsQueryResponse) {

            if (dnsqrflow->dnsQName.len == 0) {
                state->stats.dns_filtered++;
                continue;
            }

            if (dnsqrflow->dnsQRType == 1) {
                yfDNSAFlow_t *aflow = NULL;
                if (state->a_table == NULL) {
                    state->a_table = allocTypeTab(ctx->cfg->ctime);
                }
                while (( aflow = (yfDNSAFlow_t *)FBSTLNEXT(&(dnsqrflow->dnsRRList), aflow))) {

                    md_type_tab = state->a_table;
                    find.ip = aflow->ip;
                }
            } else if (dnsqrflow->dnsQRType == 2) {
                yfDNSNSFlow_t *nsflow  = NULL;
                if (state->ns_table == NULL) {
                    state->ns_table = allocTypeTab(ctx->cfg->ctime);
                }
                while ((nsflow = (yfDNSNSFlow_t *)FBSTLNEXT(&(dnsqrflow->dnsRRList), nsflow))) {
                    md_type_tab = state->ns_table;
                    find.caplen = nsflow->nsdname.len;
                    find.rrdata = nsflow->nsdname.buf;
                }

            } else if (dnsqrflow->dnsQRType == 5) {
                yfDNSCNameFlow_t *cflow = NULL;
                if (state->cname_table == NULL) {
                    state->cname_table = allocTypeTab(ctx->cfg->ctime);
                }
                while ((cflow = (yfDNSCNameFlow_t *)FBSTLNEXT(&(dnsqrflow->dnsRRList), cflow))) {
                    md_type_tab = state->cname_table;
                    find.caplen = cflow->cname.len;
                    find.rrdata = cflow->cname.buf;
                }
            } else if (dnsqrflow->dnsQRType == 12) {
                yfDNSPTRFlow_t *ptrflow = NULL;
                if (state->ptr_table == NULL) {
                    state->ptr_table = allocTypeTab(ctx->cfg->ctime);
                }
                while ((ptrflow = (yfDNSPTRFlow_t *)FBSTLNEXT(&(dnsqrflow->dnsRRList), ptrflow)))
                {
                    md_type_tab = state->ptr_table;
                    find.caplen = ptrflow->ptrdname.len;
                    find.rrdata = ptrflow->ptrdname.buf;
                }
            } else if (dnsqrflow->dnsQRType == 15) {
                yfDNSMXFlow_t *mx = NULL;
                if (state->mx_table == NULL) {
                    state->mx_table = allocTypeTab(ctx->cfg->ctime);
                }
                while (( mx = (yfDNSMXFlow_t *)FBSTLNEXT(&(dnsqrflow->dnsRRList), mx)))
                {
                    md_type_tab = state->mx_table;
                    find.caplen = mx->exchange.len;
                    find.rrdata = mx->exchange.buf;
                }
            } else if (dnsqrflow->dnsQRType == 28) {
                yfDNSAAAAFlow_t *aa = NULL;
                if (state->aaaa_table == NULL) {
                    state->aaaa_table = allocTypeTab(ctx->cfg->ctime);
                }
                while ((aa = (yfDNSAAAAFlow_t *)FBSTLNEXT(&(dnsqrflow->dnsRRList), aa)))
                {
                    md_type_tab = state->aaaa_table;
                    find.rrdata = (aa->ip);
                    find.caplen = 16;
                }
            } else if (dnsqrflow->dnsQRType == 16) {
                yfDNSTXTFlow_t *txt = NULL;
                if (state->txt_table == NULL) {
                    state->txt_table = allocTypeTab(ctx->cfg->ctime);
                }
                while ((txt = (yfDNSTXTFlow_t *)FBSTLNEXT(&(dnsqrflow->dnsRRList), txt)))
                {
                    md_type_tab = state->txt_table;
                    find.caplen = txt->txt_data.len;
                    find.rrdata = txt->txt_data.buf;
                }
            } else if (dnsqrflow->dnsQRType == 33) {
                yfDNSSRVFlow_t *srv = NULL;
                if (state->srv_table == NULL) {
                    state->srv_table = allocTypeTab(ctx->cfg->ctime);
                }
                while ((srv = (yfDNSSRVFlow_t *)FBSTLNEXT(&(dnsqrflow->dnsRRList), srv)))
                {
                    md_type_tab = state->srv_table;
                    find.rrdata = srv->dnsTarget.buf;
                    find.caplen = srv->dnsTarget.len;
                }
            } else if (dnsqrflow->dnsQRType == 6) {
                yfDNSSOAFlow_t *soa = NULL;
                if (state->soa_table == NULL) {
                    state->soa_table = allocTypeTab(ctx->cfg->ctime);
                }
                while ((soa = (yfDNSSOAFlow_t *)FBSTLNEXT(&(dnsqrflow->dnsRRList), soa))) {
                    md_type_tab = state->soa_table;
                    find.rrdata = soa->mname.buf;
                    find.caplen = soa->mname.len;
                }
            } else {
                /* we don't do this one */
                state->stats.dns_filtered++;
                continue;
            }
        }

        if (find.caplen == 0 && find.ip == 0) {
            if (nx == 0) {
                /* got nothing */
                state->stats.dns_filtered++;
                continue;
            }
        }

        /* update stats */
        state->stats.dns_recvd++;

        if (state->map) {
            mapkey = smFieldMapTranslate(state->map, flow);
            if (state->map->discard && mapkey == 0) {
                return;
            }
            memcpy(namebuf, &mapkey, sizeof(uint32_t));
            name_offset += sizeof(uint32_t);
            namelen += sizeof(uint32_t);
        }

        memcpy(namebuf + name_offset, dnsqrflow->dnsQName.buf,
               dnsqrflow->dnsQName.len);
        /* get rid of trailing "." */
        namelen += dnsqrflow->dnsQName.len;
        key.val = namebuf;
        key.len = namelen;
        //namebuf[dnsqrflow->dnsQName.len] = '\0';
        if (( hn = smHashLookup(md_type_tab->table, (uint8_t *)&key))) {
            /*if (( hn = g_hash_table_lookup(md_type_tab->table,
                                       namebuf)))
                                       {*/
            for (tn = hn->head; tn; tn = cn) {
                cn = tn->next;
                if (find.rrtype != tn->rrtype) {
                    continue;
                }
                if (find.ip && (dnsqrflow->dnsQRType == 1)) {
                    if (find.ip == tn->ip) {
                        ++(tn->hitcount);
                        tn->ltime = ctx->cfg->ctime;
                        if (find.ttl > tn->ttl) tn->ttl = find.ttl;
                        if (tn->hitcount == state->dedup_max_hit_count) {
                            cacheNodeClose(md_type_tab, hn, tn, state);
                        } else {
                            hashCacheTick(state, md_type_tab, hn, tn);
                            hashTick(state->a_table, hn);
                        }
                        found = TRUE;
                        break;
                    }
                } else if (find.caplen == tn->caplen) {
                    if (memcmp(find.rrdata, tn->rrdata, find.caplen) == 0) {
                        /* match */
                        ++(tn->hitcount);
                        tn->ltime = ctx->cfg->ctime;
                        if (find.ttl > tn->ttl) tn->ttl = find.ttl;
                        if (tn->hitcount == state->dedup_max_hit_count) {
                            cacheNodeClose(md_type_tab, hn, tn, state);
                        } else {
                            hashCacheTick(state, md_type_tab, hn, tn);
                            hashTick(md_type_tab, hn);
                        }
                        found = TRUE;
                        break;
                    }
                }
            }
        } else {
            hn = g_slice_new0(md_hashtab_node_t);
            if (hn == NULL) {
                md_dns_reset_dedup(state, ctx->cfg->ctime);
                hn = g_slice_new0(md_hashtab_node_t);
            }

            /* copy key over */
            /*hn->rrname = g_slice_alloc0(dnsqrflow->dnsQName.len + 1);*/
            hn->rkey = sm_new_hash_key(key.val, key.len);
            /*            if (hn->rrname == NULL) {*/
            if (hn->rkey == NULL) {
                md_dns_reset_dedup(state, ctx->cfg->ctime);
                /*hn->rrname = g_slice_alloc0(dnsqrflow->dnsQName.len + 1);*/
                hn->rkey = sm_new_hash_key(key.val, key.len);
            }

            if (state->map) {
                hn->mapindex = mapkey;
            } else {
                hn->mapindex = -1;
            }


            /*memcpy(hn->rrname, dnsqrflow->dnsQName.buf,
                   dnsqrflow->dnsQName.len);
            hn->rrname_len = dnsqrflow->dnsQName.len;
            *(hn->rrname + hn->rrname_len) = '\0';
            hn->rrname_len += 1;*/
            /* Insert into hash table */
            smHashTableInsert(md_type_tab->table, (uint8_t*)hn->rkey,
                              (uint8_t*)hn);
            /*g_hash_table_insert(md_type_tab->table, hn->rrname, hn);*/
            ++(md_type_tab->count);
        }

        if (!found) {
            cn = newCacheNode(ctx->cfg->ctime, find.ip, find.rrtype,
                              find.rrdata, find.caplen);
            if (cn == NULL) {
                md_dns_reset_dedup(state, ctx->cfg->ctime);
                cn = newCacheNode(ctx->cfg->ctime, find.ip, find.rrtype,
                                  find.rrdata, find.caplen);
            }
            cn->ttl = find.ttl;
            if (!state->print_lastseen) {
                md_dns_emit_record(state, state->cq, hn, cn);
            }
            hashCacheTick(state, md_type_tab, hn, cn);
            if (hn) hashTick(md_type_tab, hn);
        }
    }

    /* attempt a flush on all tables */
    md_dns_attempt_all_flush(state, ctx->cfg->ctime);
}
