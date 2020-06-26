/**
 * @file mediator_util.h
 *
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2012-2017 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Emily Sarneso
 ** ------------------------------------------------------------------------
 *
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

#ifndef MD_UTIL
#define MD_UTIL

#include <stdlib.h>
#include <stdint.h>
#include <glib.h>
#include <time.h>
#include "templates.h"

#define FBSTLNEXT(a, b) fbSubTemplateListGetNextPtr(a, b)
#define FBSTMLNEXT(a, b) fbSubTemplateMultiListEntryNextDataPtr(a, b)

typedef struct smVarHashKey_st {
    size_t  len;
    uint8_t *val;
} smVarHashKey_t;

typedef struct md_asn_tlv_st {
    uint8_t        class:2;
    uint8_t        p_c:1;
    uint8_t        tag:5;
} md_asn_tlv_t;

int md_util_hexdump_append(
    char            *dest,
    size_t          *drem,
    uint8_t         *src,
    size_t          len);

int md_util_hexdump_append_nospace(
    char            *dest,
    size_t          *drem,
    uint8_t         *src,
    size_t          len);

uint32_t md_util_hexdump_g_string_append_line(
    GString             *str,
    char                *lpfx,
    uint8_t             *cp,
    uint32_t            lineoff,
    uint32_t            buflen);

void md_util_hexdump_g_string_append(
    GString             *str,
    char                *lpfx,
    uint8_t             *buf,
    uint32_t            len);

void md_util_print_tcp_flags(
    GString             *str,
    uint8_t             flags);

void md_util_print_ip6_addr(
    char        *ipaddr_buf,
    uint8_t     *ipaddr);

void md_util_print_ip4_addr(
    char           *ipaddr_buf,
    uint32_t       ip);

uint32_t md_util_flow_key_hash(
    mdRecord_t         *rec);

uint32_t md_util_rev_flow_key_hash(
    mdRecord_t *rec);

void md_util_time_g_string_append(
    GString    *str,
    time_t     c_time,
    char       *format);

gboolean md_util_time_buf_append(
    mdBuf_t    *buf,
    size_t     *brem,
    time_t     c_time,
    char       *format);

uint16_t md_util_decode_asn1_length(
    uint8_t    **buffer,
    size_t     *len);

uint16_t md_util_decode_asn1_sequence(
    uint8_t     **buffer,
    size_t      *len);

void *detachFromEndOfDLL(
    mdDLL_t           **head,
    mdDLL_t           **tail);

void detachThisEntryOfDLL (
    mdDLL_t           **head,
    mdDLL_t           **tail,
    mdDLL_t           *entry);

void attachHeadToDLL(
    mdDLL_t           **head,
    mdDLL_t           **tail,
    mdDLL_t           *newEntry);

guint sm_octet_array_hash(
    gconstpointer v);

gboolean sm_octet_array_equal(
    gconstpointer v1,
    gconstpointer v2);

void sm_octet_array_key_destroy(
    gpointer data);

smVarHashKey_t *sm_new_hash_key(
    uint8_t        *val,
    size_t         len);

size_t md_util_write_buffer(
    FILE          *fp,
    mdBuf_t       *buf,
    char        *exp_name,
    GError        **err);

gboolean md_util_append_buffer(
    mdBuf_t         *buf,
    size_t          *brem,
    uint8_t         *var,
    size_t          len);

gboolean md_util_append_gstr(
    mdBuf_t       *buf,
    size_t        *brem,
    GString       *str);

gboolean md_util_append_varfield(
    mdBuf_t       *buf,
    size_t        *brem,
    fbVarfield_t  *var);


uint16_t md_util_decode_length(
    uint8_t           *buffer,
    uint16_t          *offset);

uint16_t md_util_decode_tlv(
    md_asn_tlv_t        *tlv,
    uint8_t             *buffer,
    uint16_t            *offset);

uint8_t md_util_asn1_sequence_count(
    uint8_t *buffer,
    uint16_t seq_len);

void md_util_compress_file(
    char          *file);

smHashTable_t *smCreateHashTable(
    size_t length,
    GDestroyNotify freeKeyfn,
    GDestroyNotify freeValfn);

gpointer smHashLookup(
    smHashTable_t *table,
    uint8_t       *key);

void smHashTableInsert(
    smHashTable_t *table,
    uint8_t       *key,
    uint8_t       *value);

void smHashTableFree(
    smHashTable_t *table);

void smHashTableRemove(
    smHashTable_t *table,
    uint8_t       *key);

uint32_t smFieldMapTranslate(
    smFieldMap_t  *map,
    mdFullFlow_t  *flow);

void md_free_hash_key(
    gpointer v1);

#endif
