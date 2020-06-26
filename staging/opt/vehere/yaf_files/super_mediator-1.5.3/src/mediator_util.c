/**
 * @file mediator_util.c
 *
 * Contains the basic utility functions for super_mediator
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
 * This material is based upon work funded and supported by
 * the Department of Defense under Contract FA8721-05-C-0003 with
 * Carnegie Mellon University for the operation of the Software Engineering
 * Institue, a federally funded research and development center. Any opinions,
 * findings and conclusions or recommendations expressed in this
 * material are those of the author(s) and do not
 * necessarily reflect the views of the United States
 * Department of Defense.

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
 * DM-0001877
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
 *
 * @OPENSOURCE_HEADER_END@
 * -----------------------------------------------------------
 */

#include <mediator/mediator_util.h>
#define MD_COMPRESSOR "gzip"

uint32_t
hashword(
    const uint32_t     *k,
    size_t              length,
    uint32_t            initval);
void
hashword2(
    const uint32_t     *k,
    size_t              length,
    uint32_t           *pc,
    uint32_t           *pb);
uint32_t
hashlittle(
    const void         *key,
    size_t              length,
    uint32_t            initval);
void
hashlittle2(
    const void         *key,
    size_t              length,
    uint32_t           *pc,
    uint32_t           *pb);
uint32_t
hashbig(
    const void         *key,
    size_t              length,
    uint32_t            initval);

#include "lookup3.c"

/**
 * md_util_hexdump_append
 *
 */
int md_util_hexdump_append(
    char            *dest,
    size_t          *drem,
    uint8_t         *src,
    size_t          len)
{
    int i = 0;
    int r;
    int tot = 0;

    if (len) {
        /* first one shouldn't have a space */
        r = snprintf(dest + tot, *drem, "%02hhx", src[i]);
        if ((size_t)r < *drem) {
            *drem += r;
        } else {
            return 0;
        }
        tot += r;
    }

    for (i = 1; i < (int)len; i++) {
        r = snprintf(dest + tot, *drem, " %02hhx", src[i]);
        if ((size_t)r < *drem) {
            *drem += r;
        } else {
            return 0;
        }
        tot += r;
    }

    return tot;
}

/**
 * md_util_hexdump_append_nospace
 *
 */
int md_util_hexdump_append_nospace(
    char            *dest,
    size_t          *drem,
    uint8_t         *src,
    size_t          len)
{
    int i = 0;
    int r;
    int tot = 0;

    if (len) {
        r = snprintf(dest + tot, *drem, "0x%02hhx", src[i]);
        if ((size_t)r < *drem) {
            *drem -= r;
        } else {
            return 0;
        }
        tot += r;
    }

    for (i = 1; i < (int)len; i++) {
        r = snprintf(dest + tot, *drem, "%02hhx", src[i]);
        if ((size_t)r < *drem) {
            *drem -= r;
        } else {
            return 0;
        }
        tot += r;
    }

    return tot;
}


/**
 * md_util_hexdump_g_string_append_line
 *
 * stolen from airframe to print yaf payloads
 *
 */
uint32_t md_util_hexdump_g_string_append_line(
    GString             *str,
    char                *lpfx,
    uint8_t             *cp,
    uint32_t            lineoff,
    uint32_t            buflen)
{
    uint32_t            cwr = 0, twr = 0;

    /* stubbornly refuse to print nothing */
    if (!buflen) return 0;

    /* print line header */
    g_string_append_printf(str, "%s %04x:", lpfx, lineoff);

    /* print hex characters */
    for (twr = 0; twr < 16; twr++) {
        if (buflen) {
            g_string_append_printf(str, " %02hhx", cp[twr]);
            cwr++; buflen--;
        } else {
            g_string_append(str, "   ");
        }
    }

    /* print characters */
    g_string_append_c(str, ' ');
    for (twr = 0; twr < cwr; twr++) {
        if ((cp[twr] > 32 && cp[twr] < 128) || cp[twr] == 32) {
            g_string_append_c(str, cp[twr]);
        } else {
            g_string_append_c(str, '.');
        }
    }
    g_string_append_c(str, '\n');

    return cwr;
}

/**
 * md_util_hexdump_g_string_append
 *
 * stolen from airframe to print hex
 *
 */
void md_util_hexdump_g_string_append(
    GString             *str,
    char                *lpfx,
    uint8_t             *buf,
    uint32_t            len)
{
    uint32_t            cwr = 0, lineoff = 0;

    do {
        cwr = md_util_hexdump_g_string_append_line(str, lpfx, buf, lineoff, len);
        buf += cwr; len -= cwr; lineoff += cwr;
    } while (cwr == 16);
}

/**
 * md_util_print_tcp_flags
 *
 * prints TCP flags
 *
 */
void md_util_print_tcp_flags(
    GString             *str,
    uint8_t             flags)
{
    if (flags & 0x40) g_string_append_c(str, 'E');
    if (flags & 0x80) g_string_append_c(str, 'C');
    if (flags & 0x20) g_string_append_c(str, 'U');
    if (flags & 0x10) g_string_append_c(str, 'A');
    if (flags & 0x08) g_string_append_c(str, 'P');
    if (flags & 0x04) g_string_append_c(str, 'R');
    if (flags & 0x02) g_string_append_c(str, 'S');
    if (flags & 0x01) g_string_append_c(str, 'F');
    if (!flags) g_string_append_c(str, '0');
}

/**
 * md_util_print_ip6_addr
 *
 *
 */
void md_util_print_ip6_addr(
    char        *ipaddr_buf,
    uint8_t     *ipaddr)
{

    char            *cp = ipaddr_buf;
    uint16_t        *aqp = (uint16_t *)ipaddr;
    uint16_t        aq;
    gboolean        colon_start = FALSE;
    gboolean        colon_end = FALSE;


    for (; (uint8_t *)aqp < ipaddr + 16; aqp++) {
        aq = g_ntohs(*aqp);
        if (aq || colon_end) {
            if ((uint8_t *)aqp < ipaddr + 14) {
                snprintf(cp, 6, "%04hx:", aq);
                cp += 5;
            } else {
                snprintf(cp, 5, "%04hx", aq);
                cp += 4;
            }
            if (colon_start) {
                colon_end = TRUE;
            }
        } else if (!colon_start) {
            if ((uint8_t *)aqp == ipaddr) {
                snprintf(cp, 3, "::");
                cp += 2;
            } else {
                snprintf(cp, 2, ":");
                cp += 1;
            }
            colon_start = TRUE;
        }
    }
}


/**
 * md_util_print_ip4_addr
 *
 *
 */
void md_util_print_ip4_addr(
    char           *ipaddr_buf,
    uint32_t       ip)
{
    uint32_t mask = 0xff000000U;
    uint8_t dqp[4];

    /* split the address */
    dqp[0] = (ip & mask) >> 24;
    mask >>= 8;
    dqp[1] = (ip & mask) >> 16;
    mask >>= 8;
    dqp[2] = (ip & mask) >> 8;
    mask >>= 8;
    dqp[3] = (ip & mask);

    /* print to it */
    snprintf(ipaddr_buf, 16,
             "%hhu.%hhu.%hhu.%hhu",dqp[0],dqp[1],dqp[2],dqp[3]);

}


/**
 * md_util_flow_key_hash
 *
 *
 */
uint32_t md_util_flow_key_hash(
    mdRecord_t         *rec)
{

    uint32_t           hash = 0;
    uint32_t           *v6p;

    if (rec->sourceIPv4Address || rec->destinationIPv4Address) {

        hash = (rec->sourceTransportPort << 16) ^
               (rec->destinationTransportPort) ^
               (rec->protocolIdentifier << 12) ^ (4 << 4) ^
               (rec->vlanId << 20) ^ (rec->sourceIPv4Address) ^
               (rec->destinationIPv4Address);
        return hash;

    } else {
        v6p = (uint32_t *)rec->sourceIPv6Address;
        hash = (rec->sourceTransportPort<< 16) ^
               (rec->destinationTransportPort) ^
               (rec->protocolIdentifier << 12) ^ (6 << 4) ^
               (rec->vlanId << 20) ^ *v6p;
        v6p++;
        hash ^= *v6p;
        v6p++;
        hash ^= *v6p;
        v6p++;
        hash ^= *v6p;
        v6p = (uint32_t *)rec->destinationIPv6Address;
        hash ^= *v6p;
        v6p++;
        hash ^= *v6p;
        v6p++;
        hash ^=*v6p;
        v6p++;
        hash ^=*v6p;
        return hash;
    }
}

uint32_t md_util_rev_flow_key_hash(
    mdRecord_t *rec)
{

    uint32_t           hash = 0;
    uint32_t           *v6p;

    if (rec->sourceIPv4Address || rec->destinationIPv4Address) {

        hash = (rec->destinationTransportPort << 16) ^
               (rec->sourceTransportPort) ^
               (rec->protocolIdentifier << 12) ^ (4 << 4) ^
               (rec->vlanId << 20) ^ (rec->destinationIPv4Address) ^
               (rec->sourceIPv4Address);
        return hash;

    } else {
        v6p = (uint32_t *)rec->destinationIPv6Address;
        hash = (rec->destinationTransportPort<< 16) ^
               (rec->sourceTransportPort) ^
               (rec->protocolIdentifier << 12) ^ (6 << 4) ^
               (rec->vlanId << 20) ^ *v6p;
        v6p++;
        hash ^= *v6p;
        v6p++;
        hash ^= *v6p;
        v6p++;
        hash ^= *v6p;
        v6p = (uint32_t *)rec->sourceIPv6Address;
        hash ^= *v6p;
        v6p++;
        hash ^= *v6p;
        v6p++;
        hash ^=*v6p;
        v6p++;
        hash ^=*v6p;
        return hash;
    }
}


/**
 *
 * add a formated time string to the str.
 *
 */

void md_util_time_g_string_append(
     GString    *str,
     time_t     c_time,
     char       *format)
{
    struct tm time_tm;

    gmtime_r(&c_time, &time_tm);

    g_string_append_printf(str, format, time_tm.tm_year + 1900,
                           time_tm.tm_mon + 1,
                           time_tm.tm_mday,
                           time_tm.tm_hour,
                           time_tm.tm_min,
                           time_tm.tm_sec);
}

gboolean md_util_time_buf_append(
    mdBuf_t    *buf,
    size_t     *brem,
    time_t     c_time,
    char       *format)
{
    struct tm time_tm;
    int ret;

    gmtime_r(&c_time, &time_tm);

    ret = snprintf(buf->cp, *brem, format, time_tm.tm_year + 1900,
                   time_tm.tm_mon + 1,
                   time_tm.tm_mday,
                   time_tm.tm_hour,
                   time_tm.tm_min,
                   time_tm.tm_sec);

    if (ret < 0) {
        return FALSE;
    }
    if ((size_t)ret >= *brem) {
        return FALSE;
    }

    buf->cp += ret;
    *brem += ret;

    return TRUE;
}

uint16_t md_util_decode_length(
    uint8_t           *buffer,
    uint16_t          *offset)
{
    uint16_t          obj_len;

    obj_len = *(buffer + *offset);
    if (obj_len == 0x81) {
        (*offset)++;
        obj_len = *(buffer + *offset);
    } else if (obj_len == 0x82) {
        (*offset)++;
        obj_len = ntohs(*(uint16_t *)(buffer + *offset));
        (*offset)++;
    }

    return obj_len;
}



uint16_t md_util_decode_tlv(
    md_asn_tlv_t        *tlv,
    uint8_t             *buffer,
    uint16_t            *offset)
{
    uint8_t            val = *(buffer + *offset);
    uint16_t           len = 0;

    tlv->class = (val & 0xD0) >> 6;
    tlv->p_c = (val & 0x20) >> 5;
    tlv->tag = (val & 0x1F);

    (*offset)++;

    len = md_util_decode_length(buffer, offset);
    (*offset)++;

    if (tlv->tag == 0x05) { /*CERT_NULL 0x05 */
        *offset += len;
        return md_util_decode_tlv(tlv, buffer, offset);
    }

    return len;

}



uint16_t md_util_decode_asn1_length(
    uint8_t           **buffer,
    size_t            *len)
{
    uint16_t          obj_len;

    obj_len = **buffer;

    if (obj_len == 0x81) {
        (*buffer)++;
        obj_len = (uint16_t)**buffer;
        (*buffer)++;
        *len -= 2;
    } else if (obj_len == 0x82) {
        (*buffer)++;
        obj_len = ntohs(*(uint16_t *)(*buffer));
        (*buffer) += 2;
        *len -= 3;
    } else if ((obj_len & 0x80) == 0) {
        /* first byte describes length */
        obj_len = (uint16_t)**buffer;
        (*buffer)++;
        *len -= 1;
    }

    return obj_len;
}

uint8_t md_util_asn1_sequence_count(
    uint8_t *buffer,
    uint16_t seq_len)
{

    uint16_t         offsetptr = 0;
    uint16_t         len = 0;
    uint16_t         obj_len;
    uint8_t          count = 0;
    md_asn_tlv_t     tlv;

    obj_len = md_util_decode_tlv(&tlv, buffer, &offsetptr);
    while (tlv.tag == 0x11 && len < seq_len) {
        len += obj_len + 2;
        count++;
        offsetptr += obj_len;
        obj_len = md_util_decode_tlv(&tlv, buffer, &offsetptr);
    }

    return count;
}



/* moves buffer to next item and returns length
 */

uint16_t md_util_decode_asn1_sequence(
    uint8_t     **buffer,
    size_t      *len)
{

    uint8_t     val = **buffer;
    uint16_t    newlen = 0;

    if (*len == 0) {
        return 0;
    }

    if (val == 0x30) {
        (*buffer)++;
        *len -= 1;
        newlen = md_util_decode_asn1_length(buffer, len);
    }

    if (newlen > *len) {
        return 0;
    }

    val = **buffer;
    if ((val & 0x80) == 0x80) {
        (*buffer)++;
        *len -= 1;
        newlen = md_util_decode_asn1_length(buffer, len);
    } else if (val == 0x30) {
        /* sequence of sequence */
        (*buffer)++;
        *len -= 1;
        newlen = md_util_decode_asn1_length(buffer, len);
    }

    return newlen;
}

/**
 *  Function: attachHeadToDLL
 *  Description: attach a new entry to the head of a doubly
 *      linked list
 *  Params: **head - double pointer to the head of the DLL.  The
 *                head will point to the new head at the end.
 *          **tail - double pointer to the tail of the DLL.
 *                NULL if tail not used
 *          *newEntry - a pointer to the entry to add as the new head
 *  Return:
 */

void attachHeadToDLL(
    mdDLL_t **head,
    mdDLL_t **tail,
    mdDLL_t  *newEntry)
{
    assert(newEntry);
    assert(head);

    /*  if this is NOT the first entry in the list */
    if (*head) {
        /*  typical linked list attachements */
        newEntry->next = *head;
        newEntry->prev = NULL;
        (*head)->prev = newEntry;
        *head = newEntry;
    } else {
        /*  the new entry is the only entry now, set head to it */
        *head = newEntry;
        newEntry->prev = NULL;
        newEntry->next = NULL;
        /*  if we're keeping track of tail, assign that too */
        if (tail) {
            *tail = newEntry;

        }
    }
}

/**
 * detachFromEndOfDLL
 *
 * detach a node from the end of a doubly linked list
 *
 */
void *detachFromEndOfDLL(
    mdDLL_t **head,
    mdDLL_t **tail)
{
    mdDLL_t *node = NULL;

    assert(head);
    assert(tail);

    node = *tail;

    if (*tail) {
        *tail = (*tail)->prev;
        if (*tail) {
            (*tail)->next = NULL;
        } else {
            *head = NULL;
        }
    }

    return node;

}

/**
 * detachThisEntryOfDLL
 *
 * detach this specific node of the DLL
 *
 */
void detachThisEntryOfDLL (
    mdDLL_t **head,
    mdDLL_t **tail,
    mdDLL_t  *entry)
{
    assert(entry);
    assert(head);

    /*  entry already points to the entry to remove, so we're good
     *  there */
    /*  if it's NOT the head of the list, patch up entry->prev */
    if (entry->prev != NULL) {
        entry->prev->next = entry->next;
    } else {
        /*  if it's the head, reassign the head */
        *head = entry->next;
    }
    /*  if it's NOT the tail of the list, patch up entry->next */
    if (entry->next != NULL) {
        entry->next->prev = entry->prev;
    } else {
        /*  it is the last entry in the list, if we're tracking the
         *  tail, reassign */
        if (tail) {
            *tail = entry->prev;
        }
    }

    /*  finish detaching by setting the next and prev pointers to
     *  null */
    entry->prev = NULL;
    entry->next = NULL;
}

/**
 * Hash Functions
 *
 *
 */

guint sm_octet_array_hash(
    gconstpointer v)
{

    smVarHashKey_t *key = (smVarHashKey_t *)v;
    uint32_t        h = 0;
    uint16_t        i = 0;

    if (key->len == 0) {
        return 0;
    }

    h = key->val[0];
    for (i = 1; i < key->len; i++) {
        h = (h << 5) - h + key->val[i];
    }

    return h;
}

gboolean sm_octet_array_equal(
    gconstpointer v1,
    gconstpointer v2)
{

    smVarHashKey_t *var1 = (smVarHashKey_t *)v1;
    smVarHashKey_t *var2 = (smVarHashKey_t *)v2;

    if (var1->len != var2->len) {
        return FALSE;
    }

    if (memcmp(var1->val, var2->val, var1->len) == 0) {
        return TRUE;
    }

    return FALSE;
}

void sm_octet_array_key_destroy(
    gpointer data)
{
    smVarHashKey_t *key = data;

    if (data) {
        g_slice_free1(key->len, key->val);
        g_slice_free(smVarHashKey_t, key);
    }
}

smVarHashKey_t *sm_new_hash_key(
    uint8_t        *val,
    size_t         len)
{
    smVarHashKey_t *key = g_slice_new0(smVarHashKey_t);

    key->val = g_slice_alloc0(len);
    memcpy(key->val, val, len);
    key->len = len;

    return key;
}

size_t md_util_write_buffer(
    FILE          *fp,
    mdBuf_t       *buf,
    char          *exp_name,
    GError        **err)
{

    size_t rc;
    size_t buflen = buf->cp - buf->buf;

    rc = fwrite(buf->buf, 1, buflen, fp);

    if (rc != buflen) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                    "%s: Error writing to file: %s\n",
                    exp_name, strerror(errno));
        return 0;
    }

    /* reset buffer */
    buf->cp = buf->buf;

    return rc;
}

gboolean md_util_append_buffer(
    mdBuf_t         *buf,
    size_t          *brem,
    uint8_t         *var,
    size_t          len)
{
    if (len < *brem) {
        memcpy(buf->cp, var, len);
        buf->cp += len;
        *brem -= len;
        return TRUE;
    }

    return FALSE;
}

gboolean md_util_append_gstr(
    mdBuf_t       *buf,
    size_t        *brem,
    GString       *str)
{
    if (str->len < *brem) {
        memcpy(buf->cp, str->str, str->len);
        buf->cp += str->len;
        *brem -= str->len;
        return TRUE;
    }

    return FALSE;
}

gboolean md_util_append_varfield(
    mdBuf_t       *buf,
    size_t        *brem,
    fbVarfield_t  *var)
{
    if (var->len < *brem) {
        memcpy(buf->cp, var->buf, var->len);
        buf->cp += var->len;
        *brem -= var->len;
        return TRUE;
    }

    return FALSE;
}

void md_util_compress_file(
    char          *file)
{

    pid_t pid;

#ifndef MD_COMPRESSOR
    g_warning("gzip is not defined - will not compress file");
    return;
#endif

    pid = fork();
    if (pid == -1) {
        g_warning("Could not fork for %s command: %s", MD_COMPRESSOR,
                  strerror(errno));
        return;
    }

    if (pid != 0) {
        waitpid(pid, NULL, 0);
        return;
    }

    setpgid(0, 0);

    pid = fork();
    if (pid == -1) {
        g_warning("Child could not fork for %s command: %s\n",
                  MD_COMPRESSOR, strerror(errno));
        _exit(EXIT_FAILURE);
    }

    if (pid != 0) {
        _exit(EXIT_SUCCESS);
    }

    if (execlp(MD_COMPRESSOR, MD_COMPRESSOR, "-f", file,(char *)NULL) == -1)
    {
        g_warning("Error invoking '%s': %s", MD_COMPRESSOR, strerror(errno));
        _exit(EXIT_FAILURE);
    }
}

static guint sm_fixed_hash4(
    gconstpointer   v)
{
    return  hashlittle(v, 4, 4216);
}

static gboolean sm_fixed_equal4(
    gconstpointer   v1,
    gconstpointer   v2)
{
    if (memcmp(v1, v2, 4) == 0) {
        return TRUE;
    }
    return FALSE;
}

void md_free_hash_key(
    gpointer v1)
{
    g_slice_free(smFieldMapKV_t, v1);
}

static guint sm_fixed_hash6(
    gconstpointer v)
{
    return hashlittle(v, 6, 4216);
}

static gboolean sm_fixed_equal6(
    gconstpointer v1,
    gconstpointer v2)
{
    if (memcmp(v1, v2, 6) == 0) {
        return TRUE;
    }
    return FALSE;
}

static guint sm_fixed_hash8(
    gconstpointer   v)
{
    return  hashlittle(v, 8, 4216);
}

static gboolean sm_fixed_equal8(
    gconstpointer   v1,
    gconstpointer   v2)
{
    if (memcmp(v1, v2, 8) == 0) {
        return TRUE;
    }
    return FALSE;
}

static guint sm_fixed_hash12(
    gconstpointer   v)
{
    return  hashlittle(v, 12, 4216);
}

static gboolean sm_fixed_equal12(
    gconstpointer   v1,
    gconstpointer   v2)
{
    if (memcmp(v1, v2, 12) == 0) {
        return TRUE;
    }
    return FALSE;
}

static guint sm_fixed_hash16(
    gconstpointer   v)
{
    return hashlittle(v, 16, 4216);
}

static gboolean sm_fixed_equal16(
    gconstpointer   v1,
    gconstpointer   v2)
{
    if (memcmp(v1, v2, 16) == 0) {
        return TRUE;
    }
    return FALSE;
}

static guint sm_fixed_hash18(
    gconstpointer v)
{
    return hashlittle(v, 18, 4216);
}

static gboolean sm_fixed_equal18(
    gconstpointer v1,
    gconstpointer v2)
{
    if (memcmp(v1, v2, 18) == 0) {
        return TRUE;
    }
    return FALSE;
}

static guint sm_fixed_hash20(
    gconstpointer v)
{
    return hashlittle(v, 20, 4216);
}

static gboolean sm_fixed_equal20(
    gconstpointer v1,
    gconstpointer v2)
{
    if (memcmp(v1, v2, 20) == 0) {
        return TRUE;
    }
    return FALSE;
}

smHashTable_t *smCreateHashTable(
    size_t length,
    GDestroyNotify freeKeyfn,
    GDestroyNotify freeValfn)
{
    smHashTable_t *hTable = g_slice_new0(smHashTable_t);

    hTable->len = length;
    if (length == 4) {
        hTable->table = g_hash_table_new_full((GHashFunc)sm_fixed_hash4,
                                              (GEqualFunc)sm_fixed_equal4,
                                              freeKeyfn, freeValfn);
    } else if (length == 6) {
        hTable->table = g_hash_table_new_full((GHashFunc)sm_fixed_hash6,
                                         (GEqualFunc)sm_fixed_equal6,
                                         freeKeyfn, freeValfn);
    } else if (length == 8) {
        hTable->table = g_hash_table_new_full((GHashFunc)sm_fixed_hash8,
                                              (GEqualFunc)sm_fixed_equal8,
                                              freeKeyfn, freeValfn);
    } else if (length == 12) {
        hTable->table = g_hash_table_new_full((GHashFunc)sm_fixed_hash12,
                                              (GEqualFunc)sm_fixed_equal12,
                                              freeKeyfn, freeValfn);
    } else if (length == 16) {
        hTable->table = g_hash_table_new_full((GHashFunc)sm_fixed_hash16,
                                              (GEqualFunc)sm_fixed_equal16,
                                              freeKeyfn, freeValfn);
    } else if (length == 18) {
        hTable->table = g_hash_table_new_full((GHashFunc)sm_fixed_hash18,
                                              (GEqualFunc)sm_fixed_equal18,
                                              freeKeyfn, freeValfn);
    } else if (length == 20) {
        hTable->table = g_hash_table_new_full((GHashFunc)sm_fixed_hash20,
                                              (GEqualFunc)sm_fixed_equal20,
                                              freeKeyfn, freeValfn);
    } else {
        hTable->table = g_hash_table_new_full((GHashFunc)sm_octet_array_hash,
                                              (GEqualFunc)sm_octet_array_equal,
                                              freeKeyfn, freeValfn);
    }

    return hTable;
}

gpointer smHashLookup(
    smHashTable_t *table,
    uint8_t       *key)
{
    return g_hash_table_lookup(table->table, key);
}

void smHashTableInsert(
    smHashTable_t *table,
    uint8_t       *key,
    uint8_t       *value)
{
    g_hash_table_insert(table->table, (gpointer)key, (gpointer)value);
}

void smHashTableFree(
    smHashTable_t *table)
{
    g_hash_table_destroy(table->table);
    g_slice_free(smHashTable_t, table);
}

void smHashTableRemove(
    smHashTable_t *table,
    uint8_t       *key)
{
    g_hash_table_remove(table->table, (gpointer)key);
}

uint32_t smFieldMapTranslate(
    smFieldMap_t  *map,
    mdFullFlow_t  *flow)
{
    smFieldMapKV_t *value;
    smFieldMapKV_t key;

    switch (map->field) {
      case OBDOMAIN:
        key.val = flow->rec->obsid;
        break;
      case VLAN:
        key.val = flow->rec->vlanId;
        break;
      default:
        break;
    }

    value = smHashLookup(map->table, (uint8_t*)&key);

    if (value) {
        return value->val;
    } else {
        return 0;
    }
}
