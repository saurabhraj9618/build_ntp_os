/**
 * @file mediator_dedup.h
 *
 * header file for mediator_dedup.c
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

typedef struct md_dedup_ip_node_st md_dedup_ip_node_t;
typedef struct md_dedup_ie_st md_dedup_ie_t;
typedef struct md_dedup_node_st md_dedup_node_t;
typedef struct md_dedup_ssl_ip_node_st md_dedup_ssl_ip_node_t;
typedef struct md_dedup_ssl_str_node_st md_dedup_ssl_str_node_t;

typedef struct md_dedup_stats_st {
    uint64_t      recvd;
    uint64_t      flushed;
} md_dedup_stats_t;

struct md_dedup_node_st {
    md_dedup_node_t     *next;
    md_dedup_node_t     *prev;
    md_dedup_str_node_t *strnode;
    md_dedup_ie_t       *ietab;
    md_dedup_t           exnode;
};

typedef struct md_dedup_cqueue_st {
    md_dedup_node_t     *head;
    md_dedup_node_t     *tail;
} md_dedup_cqueue_t;

typedef struct md_dedup_ssl_node_st {
    uint8_t             *serial;
    size_t              serial_len;
    uint8_t             *issuer;
    size_t              issuer_len;
    uint64_t            count;
} md_dedup_ssl_node_t;

typedef struct mdMapKey4_st {
    uint32_t        ip;
    uint32_t        map;
} mdMapKey4_t;

typedef struct mdMapKey6_st {
    uint8_t        ip[16];
    uint32_t       map;
} mdMapKey6_t;

typedef struct md_dedup_tmpl_st md_dedup_tmpl_t;

struct md_dedup_tmpl_st {
    fbTemplate_t       *tmpl;
    uint16_t           intid;
    uint16_t           extid;
    uint16_t           ie;
};

struct md_dedup_state_st {
    GHashTable         *ie_table;
    GHashTable         *cert_table;
    md_dedup_cqueue_t  *cq;
    md_dedup_ie_t      *head;
    md_dedup_ie_t      *tail;
    md_dedup_stats_t   stats;
    uint64_t           flush_timeout;
    uint64_t           max_hit_count;
    gboolean           merge;
    gboolean           add_export;
};

struct md_dedup_ip_node_st {
    md_dedup_ip_node_t  *next;
    md_dedup_ip_node_t  *prev;
    md_dedup_str_node_t *head;
    md_dedup_str_node_t *tail;
    smFieldMap_t        *map;
    /*smVarHashKey_t      *sip6_key;*/
    mdMapKey6_t         *sip6_key;
    mdMapKey4_t         *sip_key;
};

struct md_dedup_ssl_ip_node_st {
    md_dedup_ssl_ip_node_t *next;
    md_dedup_ssl_ip_node_t *prev;
    md_dedup_ssl_str_node_t *head;
    md_dedup_ssl_str_node_t *tail;
    smFieldMap_t            *map;
    /*    smVarHashKey_t         *sip6_key;*/
    mdMapKey6_t             *sip6_key;
    mdMapKey4_t             *sip_key;
};

struct md_dedup_ssl_str_node_st {
    md_dedup_ssl_str_node_t *next;
    md_dedup_ssl_str_node_t *prev;
    uint64_t                ftime;
    uint64_t                ltime;
    uint64_t                hitcount;
    uint64_t                stime;
    uint32_t                hash;
    md_dedup_ssl_node_t     *cert1;
    md_dedup_ssl_node_t     *cert2;
};

struct md_dedup_ie_st {
    md_dedup_ie_t      *next;
    md_dedup_ie_t      *prev;
    md_dedup_ip_node_t *head;
    md_dedup_ip_node_t *tail;
    smHashTable_t      *ip_table;
    smHashTable_t      *ip6_table;
    smFieldMap_t       *map;
    FILE               *out_file;
    char               *file_prefix;
    char               *last_file;
    md_dedup_tmpl_t    *tmpl;
    uint64_t           last_rotate_ms;
    uint64_t           count;
    uint64_t           last_flush;
    /* 1 for SIP, 0 for DIP */
    int                sip;
    /* TRUE if this is an ssl table */
    gboolean           ssl;
};

struct md_dedup_str_node_st {
    md_dedup_str_node_t *next;
    md_dedup_str_node_t *prev;
    uint64_t           ftime;
    uint64_t           ltime;
    uint64_t           hitcount;
    uint64_t           stime;
    uint32_t           hash;
    uint16_t           ie;
    size_t             caplen;
    uint8_t            *data;
};

void md_dedup_flush_alltab(
    md_export_node_t   *exp,
    uint64_t            ctime,
    gboolean            flush_all);


gboolean md_dedup_basic_list(
    fbBasicList_t *bl,
    mdBuf_t       *buf,
    GString       *tstr,
    char          delim,
    gboolean      hex,
    gboolean      escape);

GString *md_dedup_basic_list_no_count(
    fbBasicList_t *bl,
    char          delim,
    gboolean      quote,
    gboolean      hex,
    gboolean      escape);

gboolean md_dedup_flush_queue(
    md_export_node_t         *exp,
    mdConfig_t               *cfg,
    GError                   **err);

void md_dedup_configure_state(
    md_dedup_state_t *state,
    int            max_hit_count,
    int            flush_timeout,
    gboolean       merge_truncated,
    gboolean       add_export);

md_dedup_state_t *md_dedup_new_dedup_state(
    void);

md_dedup_ie_t *md_dedup_add_ie_table(
    md_dedup_state_t *state,
    char             *prefix,
    smFieldMap_t     *map,
    uint16_t         ie,
    int              sip);

void md_dedup_add_ie(
    md_dedup_state_t *state,
    md_dedup_ie_t    *ie_tab,
    uint16_t          ie);

void md_dedup_lookup_node(
    mdContext_t           *ctx,
    md_export_node_t      *exp,
    mdFullFlow_t          *flow,
    GError                **err);

gboolean md_dedup_free_state(
    mdConfig_t          *cfg,
    md_export_node_t    *exp,
    GError              **err);

void md_dedup_print_stats(
    md_dedup_state_t *state,
    char           *exp_name);

gboolean md_dedup_add_templates(
    md_dedup_state_t *state,
    fBuf_t           *fbuf,
    GError           **err);

gboolean md_dedup_write_dedup(
    mdContext_t           *ctx,
    md_export_node_t      *exp,
    md_dedup_t            *dedup,
    uint16_t              ie,
    GError                **err);
