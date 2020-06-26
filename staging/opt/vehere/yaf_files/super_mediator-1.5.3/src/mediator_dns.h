/**
 * @file mediator_dns.h
 *
 * header file for mediator_dns.c
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

#include <mediator/templates.h>
#include <mediator/mediator_util.h>

typedef struct md_cache_node_st md_cache_node_t;

typedef struct md_hashtab_node_st md_hashtab_node_t;

struct md_cache_node_st {
    md_cache_node_t *next;
    md_cache_node_t *prev;
    uint64_t      ftime;
    uint64_t      ltime;
    uint32_t      ip;
    uint32_t      ttl;
    uint16_t      rrtype;
    uint16_t      hitcount;
    size_t        caplen;
    uint8_t       *rrdata;
};

struct md_hashtab_node_st {
    md_hashtab_node_t *next;
    md_hashtab_node_t *prev;
    md_cache_node_t   *head;
    md_cache_node_t   *tail;
    smVarHashKey_t    *rkey;
    int               mapindex;
    size_t        rrname_len;
    uint8_t       *rrname;
};

typedef struct md_type_hashtab_st {
    smHashTable_t       *table;
    uint64_t            last_flush;
    uint32_t            count;
    md_hashtab_node_t   *head;
    md_hashtab_node_t   *tail;
} md_type_hashtab_t;

md_dns_cqueue_t *md_new_dns_queue(
    void);

md_dns_dedup_state_t *md_new_dns_dedup_state(
    void);

void md_dns_dedup_configure_state(
    md_dns_dedup_state_t *state,
    int                  *dedup_list,
    int                   max_hit,
    int                   flush_timeout,
    gboolean              lastseen,
    smFieldMap_t          *map,
    gboolean              export_name);

void md_dns_destroy_tab(
    md_dns_dedup_state_t *state);

void md_dns_reset_dedup(
    md_dns_dedup_state_t *state,
    uint64_t             ctime);

gboolean md_dns_flush_queue(
    md_export_node_t    *exp,
    mdConfig_t          *md_config,
    GError              **err);

gboolean md_dns_dedup_free_state(
    mdConfig_t           *cfg,
    md_export_node_t     *state,
    GError               **err);

void md_dns_dedup_print_stats(
    md_dns_dedup_state_t *state,
    char                 *exp_name);

void md_dns_flush_tab(
    md_type_hashtab_t    *nodeTab,
    md_dns_dedup_state_t *state,
    uint64_t             ctime,
    gboolean             flush_all);

void md_add_dns_node(
    mdContext_t *ctx,
    md_export_node_t *exp,
    mdFullFlow_t *flow);

void md_dns_flush_all_tab(
    md_dns_dedup_state_t *state,
    uint64_t           ctime,
    gboolean           flush_all);
