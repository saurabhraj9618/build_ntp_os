/**
 * @file mediator_export.c
 *
 * All exporting related functions, bulk of the code.
 *
 * ------------------------------------------------------------------------
 * Copyright (C) 2012-2017 Carnegie Mellon University. All Rights Reserved.
 * ------------------------------------------------------------------------
 * Authors: Emily Sarneso, Matt Coates
 * -----------------------------------------------------------------------
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

#include <mediator/mediator_inf.h>
#include <mediator/mediator_core.h>
#include <mediator/config.h>
#include <mediator/mediator_filter.h>
#include <mediator/mediator_util.h>
#include <mediator/mediator_CERT_IE.h>
#include "mediator_dns.h"
#include "mediator_dedup.h"
#include "mediator_ssl.h"
#include "mediator_stat.h"
#include "mediator_print.h"
#include "mediator_json.h"

#if HAVE_MYSQL
#include <mysql.h>
#endif

#define TIME_FMT  "%04u%02u%02u%02u%02u%02u"
#define PRINT_SHORT_TIME_FMT "%02u:%02u:%02u"

#define FBBLNP(a, b) fbBasicListGetNextPtr(a, b)

#define MD_REM_MSG(_buf_) (_buf_->buflen - (_buf_->cp - _buf_->buf))
#define MD_MSG_LEN(_buf_) (_buf_->cp - _buf_->buf)
#define MD_CHECK_RET(_buf_, _ret_, _size_)    \
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

#define MD_RET0(_rv_)                         \
    if (!_rv_) {                              \
        return 0;                             \
    }


/* a struct to keep track of table/file names for  DPI output */
typedef struct mdTableInfo_st {
    char     *table_name;
    FILE     *table_file;
    char     *file_name;
    uint64_t last_rotate_ms;
    uint8_t  serial;
} mdTableInfo_t;

mdTableInfo_t           **table_info = NULL;
static int               num_tables = 0;
static GHashTable        *table_hash = NULL;

static int               num_exporters = 0;

typedef struct mdMySQLInfo_st {
    char     *user;
    char     *password;
    char     *db_name;
    char     *db_host;
    char     *table;
#if HAVE_MYSQL
    MYSQL    *conn;
#endif
} mdMySQLInfo_t;

typedef struct mdSSLConfig_st {
    int      *issuer;
    int      *subject;
    int      *other;
    int      *extensions;
} mdSSLConfig_t;

typedef gboolean (*mdBLPrint_fn)(mdFlowExporter_t *, fbBasicList_t *,
                                 char *, size_t, char *, gboolean);
typedef gboolean (*mdVLPrint_fn)(mdFlowExporter_t *,uint8_t *, char *,
                                 char *, size_t, uint16_t, size_t, gboolean);

struct mdFlowExporter_st {
    fbExporter_t      *exporter;
    FILE              *lfp;
    char              *outspec;
    char              *current_fname;
    char              *mv_path;
    fBuf_t            *fbuf;
    mdMySQLInfo_t     *mysql;
    mdFieldList_t     *custom_list;
    mdSSLConfig_t     *ssl_config;
    GHashTable        *dpi_field_table;
    char              *name;
    mdBuf_t           *buf;
    mdBLPrint_fn      BLprint_fn;
    mdVLPrint_fn      VLprint_fn;
    md_sess_init_fn   sess_init;
    fbConnSpec_t      spec;
    uint64_t          rotate;
    uint64_t          last_rotate_ms;
    uint64_t          last_restart_ms;
    uint64_t          lastUdpTempTime;
    uint64_t          exp_flows;
    uint64_t          exp_stats;
    uint64_t          exp_bytes;
    uint64_t          time_started;
    mdTransportType_t type;
    char              delimiter;
    char              dpi_delimiter;
    gboolean          lock;
    uint8_t           no_stats;
    uint8_t           id;
    uint8_t           dns_rr_only;
    gboolean          gzip;
    gboolean          custom_list_dpi;
    gboolean          basic_list_dpi;
    gboolean          flowonly;
    gboolean          dpionly;
    gboolean          dnsdedup;
    gboolean          dnsdeduponly;
    gboolean          print_header;
    gboolean          remove_empty;
    gboolean          multi_files;
    gboolean          no_index;
    gboolean          timestamp_files;
    gboolean          no_flow_stats;
    gboolean          escape_chars;
    gboolean          remove_uploaded;
    gboolean          active;
    gboolean          json;
    gboolean          dns_resp_only;
    gboolean          dedup_per_flow;
    gboolean          dedupconfig;
    gboolean          deduponly;
    gboolean          ssldedup;
    gboolean          ssldeduponly;
    gboolean          md5_hash;
    gboolean          sha1_hash;
    gboolean          no_flow;
    gboolean          metadata_export;
};

static gboolean mdJsonifyNewSSLCertRecord(
    mdFlowExporter_t    *exporter,
    yfNewSSLCertFlow_t  *cert,
    uint8_t             cert_no);

static gboolean mdExporterTextNewSSLCertPrint(
    mdFlowExporter_t    *exporter,
    yfNewSSLCertFlow_t  *cert,
    char                *index_str,
    size_t              index_len,
    uint8_t             cert_no);

static gboolean mdExporterCheckSSLConfig(
    mdFlowExporter_t *exporter,
    int              obj_id,
    uint8_t          type);

static void mdCloseAndUnlock(
    mdFlowExporter_t  *exporter,
    FILE              *fp,
    char              *filename,
    char              *table);

/**
 * mdNewTable
 *
 *
 * create a new table to keep track of the table or file names
 * for DPI to CSV output
 *
 * @param table name of table
 */
void *mdNewTable(
    char *table)
{

    if (!table_info) {
        table_info =
           (mdTableInfo_t **)g_malloc(MAX_VALUE_LIST*sizeof(mdTableInfo_t *));
    }

    if (num_tables > 0 && (num_tables % MAX_VALUE_LIST)) {
        table_info =
            (mdTableInfo_t **)g_realloc(table_info,
                                        ((MAX_VALUE_LIST + num_tables) *sizeof(mdTableInfo_t *)));
    }

    table_info[num_tables] = g_slice_new0(mdTableInfo_t);
    table_info[num_tables]->table_name = g_strdup(table);
    table_info[num_tables]->serial = 0;
    num_tables++;

    return (void *)table_info[num_tables-1];
}


void *mdGetTable(
    int id)
{

    mdTableInfo_t *ret = NULL;

    /* associate app label with known info element */
    switch (id) {
      case 80:
        id = 110;
        break;
      case 21:
        id = 131;
        break;
      case 25:
        id = 162;
        break;
      case 53:
        id = 1;
        break;
      case 143:
        id = 136;
        break;
      case 554:
        id = 143;
        break;
      case 5060:
        id = 155;
        break;
      case 22:
        id = 171;
        break;
      default:
        return NULL;
    }

    ret = g_hash_table_lookup(table_hash, GUINT_TO_POINTER((unsigned int)id));

    return (void *)ret;

}

/**
 * mdInsertTableItem
 *
 *
 * Insert an Info Element ID/mdTableInfo struct into the hash table
 * for quick lookup.
 *
 */
gboolean mdInsertTableItem(
    void    *table_name,
    int     val)
{

    void      *key = NULL;
    gpointer  value = NULL;
    gboolean  rc;

    if (!table_hash) {
        table_hash = g_hash_table_new((GHashFunc)g_direct_hash,
                                      (GEqualFunc)g_direct_equal);
        if (table_hash == NULL) {
            return FALSE;
        }
    }

    rc = g_hash_table_lookup_extended(table_hash,
                                      GUINT_TO_POINTER((unsigned int)val),
                                      key, &value);
    if (rc) {
        return FALSE;
    }

    g_hash_table_insert(table_hash, GUINT_TO_POINTER(val), table_name);

    return TRUE;
}


/**
 * mdBuildDefaultTableHash
 *
 * if the user doesn't give us names for the files,
 * we need to create the hash table with all the default ones.
 *
 */
void mdBuildDefaultTableHash()
{
    mdTableInfo_t *tab = NULL;

    tab = mdNewTable(FLOW_STATS_DEFAULT);
    mdInsertTableItem(tab, 500);

    tab = mdNewTable(FTP_DEFAULT);
    mdInsertTableItem(tab, 131);
    mdInsertTableItem(tab, 132);
    mdInsertTableItem(tab, 133);
    mdInsertTableItem(tab, 134);
    mdInsertTableItem(tab, 135);

    tab = mdNewTable(SSH_DEFAULT);
    mdInsertTableItem(tab, 171);

    tab = mdNewTable(SMTP_DEFAULT);
    mdInsertTableItem(tab, 162);
    mdInsertTableItem(tab, 163);
    mdInsertTableItem(tab, 164);
    mdInsertTableItem(tab, 165);
    mdInsertTableItem(tab, 166);
    mdInsertTableItem(tab, 167);
    mdInsertTableItem(tab, 168);
    mdInsertTableItem(tab, 169);
    mdInsertTableItem(tab, 170);
    mdInsertTableItem(tab, 222);
    mdInsertTableItem(tab, 251);

    tab = mdNewTable(DNS_DEFAULT);
    mdInsertTableItem(tab, 1);
    mdInsertTableItem(tab, 2);
    mdInsertTableItem(tab, 5);
    mdInsertTableItem(tab, 6);
    mdInsertTableItem(tab, 12);
    mdInsertTableItem(tab, 15);
    mdInsertTableItem(tab, 16);
    mdInsertTableItem(tab, 28);
    mdInsertTableItem(tab, 33);
    mdInsertTableItem(tab, 43);
    mdInsertTableItem(tab, 47);
    mdInsertTableItem(tab, 48);
    mdInsertTableItem(tab, 50);
    mdInsertTableItem(tab, 51);
    mdInsertTableItem(tab, 53);


    tab = mdNewTable(TFTP_DEFAULT);
    mdInsertTableItem(tab, 126);
    mdInsertTableItem(tab, 127);

    tab = mdNewTable(HTTP_DEFAULT);
    mdInsertTableItem(tab, 110);
    mdInsertTableItem(tab, 111);
    mdInsertTableItem(tab, 112);
    mdInsertTableItem(tab, 113);
    mdInsertTableItem(tab, 114);
    mdInsertTableItem(tab, 115);
    mdInsertTableItem(tab, 116);
    mdInsertTableItem(tab, 117);
    mdInsertTableItem(tab, 118);
    mdInsertTableItem(tab, 119);
    mdInsertTableItem(tab, 120);
    mdInsertTableItem(tab, 121);
    mdInsertTableItem(tab, 122);
    mdInsertTableItem(tab, 123);
    mdInsertTableItem(tab, 220);
    mdInsertTableItem(tab, 221);
    mdInsertTableItem(tab, 252);
    mdInsertTableItem(tab, 253);
    mdInsertTableItem(tab, 254);
    mdInsertTableItem(tab, 255);
    mdInsertTableItem(tab, 256);
    mdInsertTableItem(tab, 257);
    mdInsertTableItem(tab, 258);
    mdInsertTableItem(tab, 259);
    mdInsertTableItem(tab, 260);
    mdInsertTableItem(tab, 261);
    mdInsertTableItem(tab, 262);
    mdInsertTableItem(tab, 263);
    mdInsertTableItem(tab, 264);
    mdInsertTableItem(tab, 265);
    mdInsertTableItem(tab, 266);
    mdInsertTableItem(tab, 267);
    mdInsertTableItem(tab, 268);
    mdInsertTableItem(tab, 269);
    mdInsertTableItem(tab, 270);
    mdInsertTableItem(tab, 271);
    mdInsertTableItem(tab, 272);
    mdInsertTableItem(tab, 273);
    mdInsertTableItem(tab, 274);
    mdInsertTableItem(tab, 275);
    mdInsertTableItem(tab, 276);
    mdInsertTableItem(tab, 277);
    mdInsertTableItem(tab, 278);
    mdInsertTableItem(tab, 279);
    mdInsertTableItem(tab, 280);


    tab = mdNewTable(IMAP_DEFAULT);
    mdInsertTableItem(tab, 136);
    mdInsertTableItem(tab, 137);
    mdInsertTableItem(tab, 138);
    mdInsertTableItem(tab, 139);
    mdInsertTableItem(tab, 140);
    mdInsertTableItem(tab, 141);
    mdInsertTableItem(tab, 142);

    tab = mdNewTable(IRC_DEFAULT);
    mdInsertTableItem(tab, 125);

    tab = mdNewTable(SIP_DEFAULT);
    mdInsertTableItem(tab, 155);
    mdInsertTableItem(tab, 156);
    mdInsertTableItem(tab, 157);
    mdInsertTableItem(tab, 158);
    mdInsertTableItem(tab, 159);
    mdInsertTableItem(tab, 160);
    mdInsertTableItem(tab, 161);

    tab = mdNewTable(MYSQL_DEFAULT);
    mdInsertTableItem(tab, 223);
    mdInsertTableItem(tab, 225);

    tab = mdNewTable(SLP_DEFAULT);
    mdInsertTableItem(tab, 128);
    mdInsertTableItem(tab, 129);
    mdInsertTableItem(tab, 130);

    tab = mdNewTable(POP3_DEFAULT);
    mdInsertTableItem(tab, 124);

    tab = mdNewTable(RTSP_DEFAULT);
    mdInsertTableItem(tab, 143);
    mdInsertTableItem(tab, 144);
    mdInsertTableItem(tab, 145);
    mdInsertTableItem(tab, 146);
    mdInsertTableItem(tab, 147);
    mdInsertTableItem(tab, 148);
    mdInsertTableItem(tab, 149);
    mdInsertTableItem(tab, 150);
    mdInsertTableItem(tab, 151);
    mdInsertTableItem(tab, 152);
    mdInsertTableItem(tab, 153);
    mdInsertTableItem(tab, 154);

    tab = mdNewTable(NNTP_DEFAULT);
    mdInsertTableItem(tab, 172);
    mdInsertTableItem(tab, 173);

    tab = mdNewTable(SSL_DEFAULT);
    mdInsertTableItem(tab, 186);
    mdInsertTableItem(tab, 187);
    mdInsertTableItem(tab, 188);
    mdInsertTableItem(tab, 189);
    mdInsertTableItem(tab, 190);
    mdInsertTableItem(tab, 191);
    mdInsertTableItem(tab, 192);
    mdInsertTableItem(tab, 193);
    mdInsertTableItem(tab, 194);
    mdInsertTableItem(tab, 195);
    mdInsertTableItem(tab, 196);
    mdInsertTableItem(tab, 197);
    mdInsertTableItem(tab, 198);
    mdInsertTableItem(tab, 199);
    mdInsertTableItem(tab, 200);
    mdInsertTableItem(tab, 201);
    mdInsertTableItem(tab, 202);
    mdInsertTableItem(tab, 203);
    mdInsertTableItem(tab, 204);
    mdInsertTableItem(tab, 205);
    mdInsertTableItem(tab, 206);
    mdInsertTableItem(tab, 207);
    mdInsertTableItem(tab, 244);
    mdInsertTableItem(tab, 245);
    mdInsertTableItem(tab, 246);
    mdInsertTableItem(tab, 247);
    mdInsertTableItem(tab, 248);
    mdInsertTableItem(tab, 249);
    mdInsertTableItem(tab, 250);
    mdInsertTableItem(tab, 288);
    mdInsertTableItem(tab, 443);
    mdInsertTableItem(tab, 294);
    mdInsertTableItem(tab, 295);
    mdInsertTableItem(tab, 296);
    mdInsertTableItem(tab, 299);
    mdInsertTableItem(tab, 298);

    tab = mdNewTable(INDEX_DEFAULT);
    mdInsertTableItem(tab, 0);

    tab = mdNewTable(DHCP_DEFAULT);
    mdInsertTableItem(tab, 242);
    mdInsertTableItem(tab, 243);
    mdInsertTableItem(tab, 297);

    tab = mdNewTable(P0F_DEFAULT);
    mdInsertTableItem(tab, 36);
    mdInsertTableItem(tab, 37);
    mdInsertTableItem(tab, 107);
    mdInsertTableItem(tab, 36|FB_IE_VENDOR_BIT_REVERSE);
    mdInsertTableItem(tab, 37|FB_IE_VENDOR_BIT_REVERSE);
    mdInsertTableItem(tab, 107|FB_IE_VENDOR_BIT_REVERSE);

    tab = mdNewTable(RTP_DEFAULT);
    mdInsertTableItem(tab, 287);

    tab = mdNewTable(DNP_DEFAULT);
    mdInsertTableItem(tab, 284);

    tab = mdNewTable(MODBUS_DEFAULT);
    mdInsertTableItem(tab, 285);

    tab = mdNewTable(ENIP_DEFAULT);
    mdInsertTableItem(tab, 286);

}

static gboolean mdExporterExpandBuf(
    mdFlowExporter_t *exporter)
{
    g_debug("Expanding output buffer for exporter %s", exporter->name);

    /* free the old buffer */
    g_slice_free1(exporter->buf->buflen, exporter->buf->buf);
    /* double the size */
    exporter->buf->buflen = (exporter->buf->buflen * 2);
    exporter->buf->buf = g_slice_alloc(exporter->buf->buflen);
    if (exporter->buf->buf == NULL) {
        return FALSE;
    }
    exporter->buf->cp = exporter->buf->buf;
    return TRUE;
}


/**
 * mdGetTableItem
 *
 * retrieve the name of the table or file associated with this info element
 * id as given by the user, or by default.
 *
 */
static char * mdGetTableItem(
    uint16_t  id)
{

    mdTableInfo_t *ret = NULL;

    ret = g_hash_table_lookup(table_hash, GUINT_TO_POINTER((unsigned int)id));
    if (ret) {
        return ret->table_name;
    }

    return NULL;
}

/**
 * mdNewFieldList
 *
 */
mdFieldList_t *mdNewFieldList(
                              )
{
    return g_slice_new0(mdFieldList_t);
}

/**
 * mdNewFlowExporter
 *
 *
 */
mdFlowExporter_t *mdNewFlowExporter(
    mdTransportType_t type)
{

    mdFlowExporter_t *exporter = g_slice_new0(mdFlowExporter_t);

    exporter->type = type;
    exporter->mysql = NULL;
    exporter->spec.host = NULL;
    exporter->spec.svc = NULL;
    exporter->spec.ssl_ca_file = NULL;
    exporter->spec.ssl_cert_file = NULL;
    exporter->spec.ssl_key_file = NULL;
    exporter->spec.ssl_key_pass = NULL;
    exporter->spec.vai = NULL;
    exporter->spec.vssl_ctx = NULL;
    exporter->delimiter = '|';
    exporter->dpi_delimiter = 0;
    exporter->dnsdedup = FALSE;
    exporter->dnsdeduponly = FALSE;
    exporter->no_flow_stats = FALSE;
    exporter->timestamp_files = FALSE;
    /* set default session initializer */
    exporter->sess_init = mdInitExporterSession;

    if (type == UDP) {
        exporter->spec.transport = FB_UDP;
    } else {
        exporter->spec.transport = FB_TCP;
    }

    if (type == TEXT) {
        exporter->buf = g_slice_new0(mdBuf_t);
        exporter->buf->buf = g_slice_alloc(MD_MSGLEN_STD + 1);
        exporter->buf->buflen = MD_MSGLEN_STD + 1;
        exporter->buf->cp = exporter->buf->buf;
    }

    exporter->dpi_field_table = NULL;

    exporter->metadata_export = FALSE;
    
    return exporter;
}

/**
 * mdInsertDPIFieldItem
 *
 *
 */
void mdInsertDPIFieldItem(
    mdFlowExporter_t      *exporter,
    int                   ie)
{

    int on = 1;

    if (exporter->dpi_field_table == NULL) {
        exporter->dpi_field_table = g_hash_table_new((GHashFunc)g_direct_hash,
                                                     (GEqualFunc)g_direct_equal);
        if (exporter->dpi_field_table == NULL) {
            g_warning("Can not create DPI Field List Hash Table.");
            return;
        }
    }

    g_hash_table_insert(exporter->dpi_field_table, GUINT_TO_POINTER(ie),
                        GUINT_TO_POINTER(on));
}


/**
 * mdGetDPIItem
 *
 *
 */
static gboolean mdGetDPIItem(
    GHashTable               *table,
    uint16_t                 id)
{
    gboolean       rc;
    void           *key = NULL;
    gpointer       value = NULL;

    rc = g_hash_table_lookup_extended(table,
                                      GUINT_TO_POINTER((unsigned int)id),
                                      key, &value);

    return rc;
}

/**
 * mdExporterSetName
 *
 *
 */
void mdExporterSetName(
    mdFlowExporter_t *exporter,
    char             *name)
{
    exporter->name = g_strdup(name);
}

/**
 * mdExporterSetPort
 *
 *
 */
void mdExporterSetPort(
    mdFlowExporter_t *exporter,
    char             *port)
{
    exporter->spec.svc = g_strdup(port);
}

/**
 * mdExporterSetHost
 *
 *
 */
void mdExporterSetHost(
    mdFlowExporter_t *exporter,
    char             *host)
{
    exporter->spec.host = g_strdup(host);
}

/**
 * mdExporterSetRotate
 *
 *
 */
void mdExporterSetRotate(
    mdFlowExporter_t *exporter,
    uint32_t         rotate)
{
    exporter->rotate = rotate * 1000;
}

/**
 * mdExporterSetFileSpec
 *
 *
 */
void mdExporterSetFileSpec(
    mdFlowExporter_t *exporter,
    char             *spec)
{
    exporter->outspec = g_strdup(spec);
}

/**
 * mdExporterSetDelim
 *
 */
void mdExporterSetDelim(
    mdFlowExporter_t *exporter,
    char             *delim)
{
    exporter->delimiter = *delim;
}

/**
 * mdExporterSetDPIDelim
 *
 */
void mdExporterSetDPIDelim(
    mdFlowExporter_t *exporter,
    char             *delim)
{
    exporter->dpi_delimiter = *delim;
}

/**
 * mdExporterSetMovePath
 *
 */
void mdExporterSetMovePath(
    mdFlowExporter_t *exporter,
    char             *path)
{
    exporter->mv_path = g_strdup(path);
}

/**
 * mdExporterSetNoFlow
 *
 *
 */
void mdExporterSetNoFlow(
    mdFlowExporter_t  *exporter)
{
    exporter->no_flow = TRUE;
}

/**
 * mdExporterSetFlowExportLock
 *
 *
 */
void mdExporterSetLock(
    mdFlowExporter_t *exporter)
{
    exporter->lock = TRUE;
}

/**
 * mdExporterGZIPFiles
 *
 */
void mdExporterGZIPFiles(
    mdFlowExporter_t *exporter)
{
    exporter->gzip = TRUE;
}

void  mdExporterDedupPerFlow(
    mdFlowExporter_t *exporter)
{
    exporter->dedup_per_flow = TRUE;
}

/**
 * mdExporterSetFlowOnly
 *
 *
 */
gboolean mdExporterSetFlowOnly(
    mdFlowExporter_t *exporter)
{
    if (exporter->flowonly || exporter->dnsdedup ||
        exporter->ssldedup || exporter->dns_rr_only ||
        exporter->dedupconfig)
    {
        return FALSE;
    }

    exporter->flowonly = TRUE;
    exporter->no_stats = 1;
    exporter->sess_init = mdInitExporterSessionFlowOnly;

    return TRUE;
}

/**
 * mdExporterSetDPIOnly
 *
 *
 */
gboolean mdExporterSetDPIOnly(
    mdFlowExporter_t *exporter)
{
    if (exporter->flowonly)
    {
        return FALSE;
    }

    exporter->dpionly = TRUE;
    exporter->no_stats = 1;
    return TRUE;
}

/**
 * mdExporterSetStats
 *
 *
 */
void mdExporterSetStats(
    mdFlowExporter_t *exporter,
    uint8_t          mode)
{
    if (exporter->flowonly || exporter->dpionly || exporter->dnsdeduponly ||
        exporter->dns_rr_only || exporter->ssldeduponly)
    {
        exporter->no_stats = 0;
    } else {
        /* no_stats = 2 means JUST STATS!!! */
        exporter->no_stats = mode;
    }
}

/**
 * mdExporterSetDeDup
 *
 *
 */
void mdExporterSetDNSDeDup(
    mdFlowExporter_t *exporter)
{
    exporter->dnsdedup = TRUE;
}

/**
 * mdExporterSetDeDupConfig
 *
 *
 */
void mdExporterSetDeDupConfig(
    mdFlowExporter_t *exporter)
{
    exporter->dedupconfig = TRUE;
    exporter->sess_init = mdInitExporterSessionDedupOnly;
}

/**
 * mdExporterSetSSLDeDupConfig
 *
 *
 */
void mdExporterSetSSLDeDupConfig(
    mdFlowExporter_t *exporter)
{
    exporter->ssldedup = TRUE;
    exporter->no_stats = 1;
}

/**
 * mdExporterSetSSLDedupOnly
 *
 *
 */
gboolean mdExporterSetSSLDeDupOnly(
    mdFlowExporter_t *exporter,
    gboolean          dedup_only)
{
    if (exporter->flowonly || exporter->dnsdeduponly ||
        exporter->dns_rr_only || exporter->deduponly)
    {
        return FALSE;
    }

    if (dedup_only) {
        if (exporter->dnsdedup || exporter->ssldedup)
        {
            return FALSE;
        }
        exporter->no_flow = TRUE;
    }

    exporter->ssldedup = TRUE;
    exporter->ssldeduponly = dedup_only;
    exporter->no_stats = 1;
    exporter->no_index = TRUE;
    exporter->sess_init = mdInitExporterSessionSSLDedupOnly;
    return TRUE;
}

/**
 * mdExporterDedupOnly
 *
 */
gboolean mdExporterDedupOnly(
    mdFlowExporter_t *exporter)
{

    if (exporter->flowonly || exporter->dnsdedup ||
        exporter->ssldedup || exporter->dns_rr_only )
    {
        return FALSE;
    }

    exporter->deduponly = TRUE;
    exporter->no_stats = 1;
    exporter->no_index = TRUE;
    exporter->no_flow = TRUE;
    exporter->sess_init = mdInitExporterSessionDedupOnly;
    return TRUE;
}


/**
 * mdExporterSetPrintHeader
 *
 *
 */
void mdExporterSetPrintHeader(
    mdFlowExporter_t *exporter)
{
    exporter->print_header = TRUE;
}

/**
 * mdExporterSetEscapeChars
 *
 *
 */
void mdExporterSetEscapeChars(
    mdFlowExporter_t *exporter)
{
    exporter->escape_chars = TRUE;
}

/**
 * mdExporterCompareNames
 *
 */
gboolean mdExporterCompareNames(
    mdFlowExporter_t *exporter,
    char             *name)
{

    if (!g_strcmp0(exporter->name, name)) {
        return TRUE;
    }

    return FALSE;
}

void mdExporterSetSSLConfig(
    mdFlowExporter_t  *exporter,
    int               *list,
    int                type)
{
    if (!exporter->ssl_config) {
        exporter->ssl_config = g_slice_new0(mdSSLConfig_t);
    }

    if (type == 1) {
        exporter->ssl_config->issuer = list;
    } else if (type == 2) {
        exporter->ssl_config->subject = list;
    } else if (type == 3) {
        exporter->ssl_config->other = list;
        /* if there's a DPI field list - add any of these items in
           the DPI field list as well */
        if (exporter->dpi_field_table) {
            int i;
            for (i = 0; i < 300; i++) {
                if (list[i] == 1) {
                    mdInsertDPIFieldItem(exporter, i);
                }
            }
        }
    } else if (type == 4) {
        exporter->ssl_config->extensions = list;
    }
}


/**
 * mdExporterSetDeDupOnly
 *
 *
 */
gboolean mdExporterSetDNSDeDupOnly(
    mdFlowExporter_t *exporter)
{
    if (exporter->flowonly || exporter->ssldedup || exporter->dedupconfig ||
        exporter->dns_rr_only)
    {
        return FALSE;
    }

    exporter->dnsdeduponly = TRUE;
    exporter->dnsdedup = TRUE;
    exporter->no_stats = 1;
    exporter->sess_init = mdInitExporterSessionDNSDedupOnly;
    exporter->no_flow = TRUE;
    return TRUE;
}

gboolean mdExporterGetDNSDedupStatus(
    mdFlowExporter_t *exporter)
{
    if (exporter->dnsdedup) {
        return TRUE;
    }

    return FALSE;
}

char *mdExporterGetName(
    mdFlowExporter_t *exporter)
{
    return exporter->name;
}

gboolean mdExporterGetJson(
    mdFlowExporter_t *exporter)
{
    return exporter->json;
}

void mdExporterSetRemoveEmpty(
    mdFlowExporter_t *exporter)
{
    exporter->remove_empty = TRUE;

}

void mdExporterSetNoIndex(
    mdFlowExporter_t *exporter,
    gboolean         val)
{
    exporter->no_index = val;
}

void mdExporterSetTimestampFiles(
    mdFlowExporter_t *exporter)
{
    exporter->timestamp_files = TRUE;
}

void mdExporterSetRemoveUploaded(
    mdFlowExporter_t *exporter)
{
    exporter->remove_uploaded = TRUE;
}

void mdExporterSetId(
    mdFlowExporter_t *exporter,
    uint8_t          id)
{
    exporter->id = id;
}

/**
 * mdExporterSetNoFlowStats
 *
 */
void mdExporterSetNoFlowStats(
    mdFlowExporter_t *exporter)
{
    exporter->no_flow_stats = TRUE;
}

/**
 * mdExporterSetJson
 *
 */
void mdExporterSetJson(
    mdFlowExporter_t *exporter)
{
    exporter->json = TRUE;
    exporter->escape_chars = TRUE;
}

/**
 * mdExportCustomList
 *
 *
 */
void mdExportCustomList(
    mdFlowExporter_t *exporter,
    mdFieldList_t    *list)
{
    exporter->custom_list = list;
    exporter->no_stats = 1;
}

void mdExporterCustomListDPI(
    mdFlowExporter_t  *exporter)
{
    exporter->custom_list_dpi = TRUE;
    exporter->no_index = TRUE;
}

int mdExporterGetType(
    mdFlowExporter_t *exporter)
{
    return exporter->type;
}

/**
 * mdExporterSetDNSRROnly
 *
 */
gboolean mdExporterSetDNSRROnly(
    mdFlowExporter_t *exporter,
    int               mode)
{
    if (mode == 1 || mode == 2) {
        if (exporter->flowonly || exporter->ssldedup ||
            exporter->dedupconfig || exporter->dnsdedup)
        {
            return FALSE;
        }
        exporter->no_flow = TRUE;
    }

    /* 1 is rr only */
    /* 2 is rr only full */
    /* 3 is rr */
    /* 4 is rr full */

    exporter->dns_rr_only = mode;
    exporter->sess_init = mdInitExporterSessionDNSRROnly;
    exporter->no_stats = 1;

    return TRUE;

}

gboolean mdExporterSetSSLMD5Hash(
    mdFlowExporter_t *exporter)
{
    if (exporter->flowonly || exporter->dns_rr_only ||
        exporter->dnsdeduponly || exporter->dns_resp_only ||
        (exporter->no_stats == 2))
    {
        return FALSE;
    }

    exporter->md5_hash = TRUE;

    return TRUE;
}


gboolean mdExporterSetSSLSHA1Hash(
    mdFlowExporter_t *exporter)
{
    if (exporter->flowonly || exporter->dns_rr_only ||
        exporter->dnsdeduponly || exporter->dns_resp_only ||
        (exporter->no_stats == 2))
    {
        return FALSE;
    }

    exporter->sha1_hash = TRUE;

    return TRUE;
}

/**
 * mdExporterSetDNSRespOnly
 *
 */
void mdExporterSetDNSRespOnly(
    mdFlowExporter_t *exporter)
{
    exporter->dns_resp_only = TRUE;
}

/**
 * mdExporterAddMySQLInfo
 *
 *
 */
gboolean mdExporterAddMySQLInfo(
    mdFlowExporter_t *exporter,
    char             *user,
    char             *password,
    char             *db_name,
    char             *db_host,
    char             *table)
{

    if (exporter->mysql == NULL) {
        exporter->mysql = g_slice_new0(mdMySQLInfo_t);
    }
    if (user) {
        exporter->mysql->user = g_strdup(user);
    }
    if (password) {
        exporter->mysql->password = g_strdup(password);
    }
    if (db_name) {
        exporter->mysql->db_name = g_strdup(db_name);
    }
    if (db_host) {
        exporter->mysql->db_host = g_strdup(db_host);
    }
    if (table) {
        exporter->mysql->table = g_strdup(table);
    }

#if HAVE_MYSQL
    if (exporter->mysql->user && exporter->mysql->password &&
        exporter->mysql->db_name)
    {
        exporter->mysql->conn = mysql_init(NULL);
        //#if MYSQL_VERSION_ID >= 50013
        my_bool reconnect = 1;
        mysql_options(exporter->mysql->conn, MYSQL_OPT_RECONNECT, &reconnect);
        //#endif
        if (exporter->mysql->conn == NULL) {
            g_warning("Error Initializing Connection %u: %s\n",
                      mysql_errno(exporter->mysql->conn),
                      mysql_error(exporter->mysql->conn));
            return FALSE;
        }
        if (mysql_real_connect(exporter->mysql->conn, exporter->mysql->db_host,
                               exporter->mysql->user,exporter->mysql->password,
                               exporter->mysql->db_name, 0, NULL, 0) == NULL)
        {
            g_warning("Error Connection %u: %s",
                      mysql_errno(exporter->mysql->conn),
                      mysql_error(exporter->mysql->conn));
            return FALSE;
        }
    }
#else
    g_warning("Invalid Keyword: super_mediator not configured for MySQL.");
#endif
    return TRUE;
}

/**
 * mdExporterSetMetadataExport
 *
 *
 */
void mdExporterSetMetadataExport(
    mdFlowExporter_t *exporter)
{
    exporter->metadata_export = TRUE;
}

/**
 * mdLockFile
 *
 * "Locks" a file.  Really just prepends "." to the filename
 *
 */
static void mdLockFile(
    GString            *path)
{
    char              *find = NULL;
    gssize            pos;


    find = g_strrstr(path->str, "/");
    if (find) {
        pos = find - path->str + 1;
        g_string_insert_c(path, pos, '.');
    } else {
        g_string_prepend_c(path, '.');
    }

}

/**
 * mdUnlockFile
 *
 * "Unlocks" a file.  Really just renames the file.
 *
 */
static void mdUnlockFile(
    char             *path)
{
    GString           *lock_name = NULL;
    char              *find = NULL;
    gssize            pos;


    lock_name = g_string_new("");
    g_string_assign(lock_name, path);
    find = g_strrstr(lock_name->str, "/");
    if (find) {
        pos = find - lock_name->str + 1;
        g_string_insert_c(lock_name, pos, '.');
    } else {
        g_string_prepend_c(lock_name, '.');
    }
    g_debug("Unlocking File %s", path);

    if (g_rename(lock_name->str, path) != 0) {
        g_warning("Error renaming file from %s to %s",
                  lock_name->str, path);
    }
    g_string_free(lock_name, TRUE);
}




/**
 * mdExportMultiFiles
 *
 *
 */
gboolean mdExportMultiFiles(
    mdFlowExporter_t  *exporter)
{
    static gboolean on = FALSE;
    int    offset;
    char   *hold_spec;

    if (!on) {
        exporter->multi_files = TRUE;
        on = TRUE;
        if (!g_file_test(exporter->outspec, G_FILE_TEST_IS_DIR)) {
            fprintf(stderr, "Error: MULTI_FILES requires PATH to be a File "
                    "Directory\n");
            return FALSE;
        }
        offset = strlen(exporter->outspec);
        if (exporter->outspec[offset-1] != '/') {
            hold_spec = g_strconcat(exporter->outspec, "/", NULL);
            g_free(exporter->outspec);
            exporter->outspec = hold_spec;
        }

        return TRUE;
    }

    fprintf(stderr, "MULTI_FILES feature only valid for 1 Exporter\n");
    /* only 1 exporter can turn this feature on */
    return FALSE;
}

/**
 * mdExporterFree
 *
 *
 */
void mdExporterFree(
    mdFlowExporter_t *exporter)
{
    g_slice_free(mdFlowExporter_t, exporter);
}

/**
 * mdLoadFile
 *
 * load a dpi file into the database.
 *
 */
static void mdLoadFile(
    mdFlowExporter_t *exporter,
    char             *table,
    char             *filename)
{
#if HAVE_MYSQL
    char          query[500];
    int           err;
    unsigned long bid = 0;
    unsigned long aid = 0;
    mdMySQLInfo_t *mysql = exporter->mysql;

    if (mysql->conn) {
        sprintf(query, "LOAD DATA LOCAL INFILE '%s' INTO TABLE %s.%s"
                " FIELDS TERMINATED BY '%c'", filename, mysql->db_name,
                table, exporter->delimiter);
        err = mysql_query(mysql->conn, query);

#if MYSQL_VERSION_ID >=50013
        bid = mysql_thread_id(mysql->conn);
        mysql_ping(mysql->conn);
        aid = mysql_thread_id(mysql->conn);
#endif
        /* try again for specific errors */
        if (err) {
            if ((mysql_errno(mysql->conn) == 0) ||
                (mysql_errno(mysql->conn) == 1143))
            {
                g_debug("%s: Error importing local file %u: %s. "
                        "Trying query again without LOCAL keyword.",
                        exporter->name, mysql_errno(mysql->conn),
                        mysql_error(mysql->conn));
                sprintf(query, "LOAD DATA INFILE '%s' INTO TABLE %s"
                        " FIELDS TERMINATED BY '%c'", filename,
                        table, exporter->delimiter);
                err = mysql_query(mysql->conn, query);
            } else if ( bid != aid ) {
                g_message("%s: Reconnected to MySQL Database.",exporter->name);
                sprintf(query, "LOAD DATA LOCAL INFILE '%s' INTO TABLE %s"
                        " FIELDS TERMINATED BY '%c'", filename,
                        table, exporter->delimiter);
                err = mysql_query(mysql->conn, query);

            }
        }

        if (err) {
            g_warning("%s: Error loading data %u:%s", exporter->name,
                      mysql_errno(mysql->conn), mysql_error(mysql->conn));
        } else {
            g_debug("%s: Successfully imported file %s to table '%s'",
                    exporter->name, filename, table);
            if (exporter->remove_uploaded) {
                if (!g_remove(filename)) {
                    g_debug("%s: Removed Imported File '%s'", exporter->name,
                            filename);
                } else {
                    g_warning("%s: Error removing file: %d", exporter->name,
                              g_file_error_from_errno(errno));
                }
            }
        }
    }
#endif

}



/**
 * mdGetTableFile
 *
 * returns the file pointer for this element id.
 */
static FILE * mdGetTableFile(
    mdFlowExporter_t *exporter,
    uint16_t         id)
{

    mdTableInfo_t  *ret = NULL;
    GString        *file_name;
    uint64_t       start_secs;

    if (!table_hash) {
        mdBuildDefaultTableHash();
    }
    ret = g_hash_table_lookup(table_hash, GUINT_TO_POINTER((unsigned int)id));
    if (ret) {
        if (!ret->table_file ||
            (ret->last_rotate_ms &&
             (exporter->last_rotate_ms != ret->last_rotate_ms)))
        {
            file_name = g_string_new("");
            g_string_assign(file_name, exporter->outspec);
            if (ret->table_file) {
                mdCloseAndUnlock(exporter, ret->table_file, ret->file_name,
                                 ret->table_name);
                /*if (exporter->lock) {
                    mdUnlockFile(ret->file_name);
                }
                fclose(ret->table_file);
                if (exporter->mysql) {
                    mdLoadFile(exporter, ret->table_name, ret->file_name);
                }
                g_free(ret->file_name);*/
            }
            start_secs = exporter->last_rotate_ms / 1000;
            g_string_append_printf(file_name, "%s.txt", ret->table_name);
            if (exporter->timestamp_files) {
                md_util_time_g_string_append(file_name, start_secs, TIME_FMT);
            } else {
                g_string_append_printf(file_name, "%d", ret->serial);
            }
            ret->serial++;
            ret->file_name = g_strdup(file_name->str);
            if (exporter->lock) {
                mdLockFile(file_name);
            }
            ret->table_file = fopen(file_name->str, "w");
            ret->last_rotate_ms = exporter->last_rotate_ms;
            if (ret->table_file == NULL) {
                g_warning("%s: Error Opening File %s", exporter->name,
                          file_name->str);
            }
            g_debug("%s: Opening Text File %s", exporter->name,
                    file_name->str);
            g_string_free(file_name, TRUE);
        }
        return ret->table_file;
    }

    return NULL;
}


/**
 * mdExporterVerifySetup
 *
 * verifies that the exporters are appropriately setup
 * and that all configuration parameters were used
 * correctly
 *
 * @param exp to be verified
 * @param err not really used
 * @return true if correct
 */
gboolean mdExporterVerifySetup(
    mdFlowExporter_t *exporter)
{
    switch (exporter->type) {
      case SPREAD:
#if HAVE_SPREAD
        if (md_out_groups == NULL) {
            fprintf(stderr, "Error EXPORTER %s: SPREAD Exporter "
                    "Requires AT LEAST ONE group.\n", exporter->name);
            return FALSE;
        } else if (exporter->outspec == NULL) {
            fprintf(stderr, "Error EXPORTER %s: SPREAD Exporter Requires DAEMON Name.\n",
                    exporter->name);
            return FALSE;
        }
        if (exporter->ssl_config) {
            fprintf(stderr, "Error EXPORTER %s: SSL_CONFIG does not apply to SPREAD"
                    " Exporters.\n", exporter->name);
            return FALSE;
        }
#else
        fprintf(stderr, "Error: SPREAD Not enabled.\n");
        return FALSE;
#endif
        break;
      case FILEHANDLER:
        if (exporter->outspec == NULL) {
            fprintf(stderr, "Error: FILE Exporter %s Requires a FILE\n", exporter->name);
            return FALSE;
        }
        if (exporter->lock && exporter->rotate == 0) {
            fprintf(stderr, "Error EXPORTER %s: LOCK Only valid with ROTATE\n",
                    exporter->name);
            return FALSE;
        }
        if (exporter->timestamp_files) {
            g_debug("Keyword TIMESTAMP_FILES is ignored for FILEHANDLER "
                    "Exporters %s\n", exporter->name);
            exporter->timestamp_files = FALSE;
        }
        exporter->remove_empty = TRUE;
      case TCP:
      case UDP:
        if (exporter->type != FILEHANDLER) {
            if (exporter->spec.host == NULL) {
                exporter->spec.host = g_strdup("localhost");
            }
            if (exporter->spec.svc == NULL) {
                fprintf(stderr, "Error: TCP/UDP Exporter %s Requires PORT\n", exporter->name);
                return FALSE;
            }
        }
        if (exporter->ssl_config) {
            fprintf(stderr, "Error: SSL_CONFIG does not apply to IPFIX"
                    " Exporters.\n Remove ISSUER, SUBJECT, EXTENSIONS, OTHER keywords\n");
            return FALSE;
        }
        if (exporter->no_flow == 0) {
            exporter->sess_init = mdInitExporterSession;
        }
        if (exporter->dnsdeduponly) {
            if (exporter->ssldedup || exporter->dedupconfig || exporter->flowonly
                || exporter->dns_rr_only)
            {
                fprintf(stderr, "Error exporter %s: DNS_DEDUP_ONLY not permitted with SSL_DEDUP,"
                        " DEDUP_CONFIG, FLOW_ONLY, or DNS_RR\n", exporter->name);
                return FALSE;
            }
        }
        if (exporter->ssldeduponly) {
            if (exporter->dnsdedup || exporter->dedupconfig || exporter->flowonly
                || exporter->dns_rr_only)
            {
                fprintf(stderr,"Error exporter %s: SSL_DEDUP_ONLY not permitted with DNS_DEDUP,"
                        " DEDUP_CONFIG, FLOW_ONLY, or DNS_RR\n", exporter->name);
                return FALSE;
            }
        }
        if (exporter->deduponly) {
            if (exporter->dnsdedup || exporter->ssldedup || exporter->flowonly
                || exporter->dns_rr_only)
            {
                fprintf(stderr,"Error exporter %s: DEDUP_ONLY not permitted with DNS_DEDUP,"
                        " DEDUP_CONFIG, FLOW_ONLY, or DNS_RR\n", exporter->name);
                return FALSE;
            }
        }
        if ((exporter->dns_rr_only == 1) || (exporter->dns_rr_only == 2)) {
            if (exporter->dnsdedup || exporter->ssldedup || exporter->flowonly
                || exporter->dedupconfig)
            {
                fprintf(stderr,"Error exporter %s: DNS_RR_ONLY not permitted with DNS_DEDUP,"
                        " DEDUP_CONFIG, FLOW_ONLY, or SSL_DEDUP\n", exporter->name);
                return FALSE;
            }
        }
        break;
      case TEXT:
        exporter->BLprint_fn = mdExportBL;
        exporter->VLprint_fn = mdAppendDPIStr;
        exporter->remove_empty = TRUE;
        if (exporter->custom_list && !exporter->json) {
            mdSetFieldListDecoratorCustom(exporter->custom_list,
                                          exporter->delimiter);
        }

        if (exporter->outspec == NULL) {
            fprintf(stderr, "Error: TEXT Exporter %s Requires "
                    "a FILE or DIRECTORY Path.\n", exporter->name);
            return FALSE;
        }
        if (exporter->lock && exporter->rotate ==0) {
            fprintf(stderr, "Error EXPORTER %s: LOCK Only valid with ROTATE\n",
                    exporter->name);
            return FALSE;
        }
        if (exporter->multi_files && !exporter->dpionly) {
            fprintf(stderr, "Error EXPORTER %s: MULTI_FILES Only Valid "
                    "with DPI_ONLY\n", exporter->name);
            return FALSE;
        }
        if (exporter->multi_files && exporter->dnsdedup) {
            fprintf(stderr, "Error EXPORTER %s: MULTI_FILES not valid with  DEDUP\n",
                    exporter->name);
            return FALSE;
        }
        if (exporter->timestamp_files && !exporter->rotate) {
            fprintf(stderr, "Error EXPORTER %s: TIMESTAMP_FILES only valid with ROTATE\n",
                    exporter->name);
            return FALSE;
        }

        if (exporter->multi_files && exporter->dpi_field_table) {
            fprintf(stderr, "Error EXPORTER %s: Invalid DPI_FIELD_LIST with MULTI_FILES. "
                    "Use DPI_CONFIG block to configure MULTI_FILES.\n",
                    exporter->name);
            return FALSE;
        }

        if (exporter->multi_files && table_hash &&
            (exporter->md5_hash || exporter->sha1_hash)) {
            fprintf(stderr, "Error EXPORTER %s: For MULTI_FILES USE 299 for MD5_HASH or "
                    " 298 for SHA1_HASH in the DPI_CONFIG block.\n",
                    exporter->name);
            return FALSE;
        }

        if (exporter->multi_files && table_hash) {
            if (mdGetTableItem(299)) {
                exporter->md5_hash = TRUE;
            }
            if (mdGetTableItem(298)) {
                exporter->sha1_hash = TRUE;
            }
        }

        if (exporter->custom_list_dpi) {
            exporter->BLprint_fn = mdExportBLCustomList;
        }

        if (!exporter->custom_list && exporter->custom_list_dpi) {
            mdFieldList_t *item = NULL;
            item = mdCreateFieldList(NONE_FIELD);
            mdExporterSetDPIOnly(exporter);
            mdExportCustomList(exporter, item);
        }
        if (exporter->dedupconfig && !exporter->json) {
            exporter->deduponly = TRUE;
            exporter->no_stats = 1;
        }

        /* create a basic flow printing custom list */
        if (!exporter->custom_list) {
            if (!exporter->multi_files && !exporter->dnsdeduponly
                && !exporter->dpionly && !exporter->ssldeduponly &&
                !exporter->deduponly && !exporter->dns_rr_only)
            {
                /* if JSON - don't print payload */
                gboolean payload_on = exporter->json ? FALSE : TRUE;
                exporter->custom_list = mdCreateBasicFlowList(payload_on);
                exporter->no_stats = 0;
                if (!exporter->json) {
                    mdSetFieldListDecoratorBasic(exporter->custom_list,
                                                 exporter->delimiter);
                }
                if (!exporter->flowonly) {
                    /* turn on DPI... */
                    exporter->basic_list_dpi = TRUE;
                }
            }
            if (exporter->json && exporter->dpionly) {
                exporter->custom_list = mdCreateIndexFlowList();
                exporter->custom_list_dpi = TRUE;
            }
        }

        if (exporter->dpionly && exporter->custom_list &&
            (!exporter->custom_list_dpi && !exporter->basic_list_dpi))
        {
            fprintf(stderr, "Error Exporter %s: Specified 'DPI_ONLY' "
                    "but DPI not listed in custom FIELD list.\n",
                    exporter->name);
            return FALSE;
        }
        if (exporter->dpi_delimiter == 0) {
            /* not set by user */
            exporter->dpi_delimiter = exporter->delimiter;
        }
        if (exporter->flowonly && exporter->custom_list &&
            exporter->custom_list_dpi)
        {
            g_warning("FLOW_ONLY keyword for EXPORTER %s "
                      "is ignored due to DPI in "
                      "custom FIELD list.", exporter->name);
        }
        if (exporter->flowonly && exporter->dpi_field_table) {
            g_warning("FLOW_ONLY keyword is present with DPI_FIELD_LIST. "
                      "Ignoring DPI_FIELD_LIST for EXPORTER %s",
                      exporter->name);
        }

        if (!exporter->multi_files && exporter->rotate) {
            exporter->timestamp_files = TRUE;
        }
        if (exporter->dnsdeduponly) {
            if (exporter->custom_list) {
                g_warning("Warning: FIELD list is ignored due to"
                          " presence of DNS_DEDUP_ONLY keyword in"
                          " EXPORTER %s.", exporter->name);
            }
        }

        if (exporter->ssldedup) {
            if (exporter->multi_files) {
                fprintf(stderr, "Error: MULTI_FILES not compatible"
                        " with SSL_DEDUP_ONLY or SSL_DEDUP for EXPORTER %s\n",
                        exporter->name);
                return FALSE;
            }
        }

        if (exporter->ssldeduponly) {
            if (exporter->custom_list) {
                g_warning("Warning: FIELD list is ignored due to"
                          " presence of SSL_DEDUP_ONLY keyword for "
                          "EXPORTER %s", exporter->name);
            }
        }

        if (exporter->mysql) {
            if (exporter->flowonly) {
                if (exporter->mysql->table == NULL) {
                    exporter->mysql->table = g_strdup(INDEX_DEFAULT);
                }
            }
            if (exporter->dnsdeduponly) {
                if (exporter->mysql->table == NULL) {
                    exporter->mysql->table = g_strdup(DNS_DEDUP_DEFAULT);
                }
            }
            if (exporter->no_stats == 2) {
                if (exporter->mysql->table == NULL) {
                    exporter->mysql->table = g_strdup(YAF_STATS_DEFAULT);
                }
            }
            if (exporter->custom_list) {
                if (exporter->mysql->table == NULL) {
                    fprintf(stderr, "Error: Custom FIELD List with MySQL import "
                            "requires MYSQL_TABLE name for EXPORTER %s.\n",
                            exporter->name);
                    return FALSE;
                }
            }
        }

        if (exporter->dedupconfig && !exporter->json) {
            int    offset;
            char   *hold_spec;

            if (!g_file_test(exporter->outspec, G_FILE_TEST_IS_DIR)) {
                fprintf(stderr, "Error EXPORTER %s: DEDUP_CONFIG requires "
                        "PATH to be a File Directory\n", exporter->name);
                return FALSE;
            }
            offset = strlen(exporter->outspec);
            if (exporter->outspec[offset-1] != '/') {
                hold_spec = g_strconcat(exporter->outspec, "/", NULL);
                g_free(exporter->outspec);
                exporter->outspec = hold_spec;
            }
        }

        if (exporter->json) {

            if (exporter->multi_files) {
                fprintf(stderr, "Error EXPORTER %s: MULTI_FILES not valid with JSON\n",
                        exporter->name);
                return FALSE;
            }

            if (exporter->print_header) {
                g_warning("PRINT_HEADER is ignored with JSON.");
                exporter->print_header = FALSE;
            }

            if (exporter->custom_list) {
                mdSetFieldListDecoratorJSON(exporter->custom_list);
            }
            exporter->escape_chars = TRUE;

        }

        if (exporter->multi_files) {
            exporter->BLprint_fn = mdExportBLMultiFiles;
            exporter->VLprint_fn = mdAppendDPIStrMultiFiles;
        }
        if (exporter->json) {
            exporter->BLprint_fn = mdJsonizeBLElement;
            exporter->VLprint_fn = mdJsonizeVLElement;
        }

        break;
      default:
        /* this really should never happen */
        fprintf(stderr, "Error: Invalid Transport for Exporter %s\n",
                exporter->name);
        return FALSE;

    }

    if (exporter->deduponly && !exporter->dedupconfig) {
        fprintf(stderr, "Error: DEDUP_ONLY was set for Exporter %s "
                "but no corresponding DEDUP_CONFIG block was found.\n", exporter->name);
        return FALSE;
    }

    num_exporters++;

    mdExporterSetId(exporter, num_exporters);

    if (!exporter->name) {
        exporter->name = g_strdup_printf("E%d", exporter->id);
    }

    return TRUE;
}

/**
 * mdExporterMoveFile
 *
 *
 */
static GString * mdExporterMoveFile(
    char       *file,
    char       *new_dir)
{

    GString *new_file = NULL;
    char *filename;

    filename = g_strrstr(file, "/");

    new_file = g_string_new("");

    g_string_append_printf(new_file, "%s", new_dir);
    g_string_append_printf(new_file, "%s", filename);

    if (g_rename(file, new_file->str) != 0) {
        g_string_free(new_file, TRUE);
        return  NULL;
    }

    return new_file;
}



/**
 * mdCloseAndUnlock
 *
 * close a file, unlock it, possibly remove it.
 *
 */
static void mdCloseAndUnlock(
    mdFlowExporter_t  *exporter,
    FILE              *fp,
    char              *filename,
    char              *table)
{
    gboolean          rm = FALSE;
    GString           *mv_name = NULL;
    char              *table_name = NULL;

    if (fp == NULL || filename == NULL) {
        return;
    }

    if (filename[0] != '-' && (strlen(filename) != 1)) {
        g_debug("%s: Closing File %s", exporter->name, filename);
    }

    if (exporter->remove_empty) {
        fseek(fp, 0L, SEEK_END);
        if (!ftell(fp)) {
            rm = TRUE;
        }
    }

    fclose(fp);

    if (exporter->lock) {
        mdUnlockFile(filename);
    }

    if (rm) {
        g_debug("%s: Removing Empty File %s", exporter->name, filename);
        g_remove(filename);
    }

    fp = NULL;

    if (exporter->mysql && !rm) {
        if (exporter->flowonly || exporter->dnsdeduponly ||
            exporter->multi_files || exporter->no_stats == 2 ||
            exporter->custom_list)
        {
            table_name = table ? table : exporter->mysql->table;
            mdLoadFile(exporter, table_name, filename);
            /* don't compress if already removed */
            if (exporter->remove_uploaded) {
                if (filename) {
                    g_free(filename);
                }
                return;
            }
        }
    }

    if (exporter->mv_path && !rm) {
        mv_name = mdExporterMoveFile(filename, exporter->mv_path);
        if (!mv_name) {
            g_warning("Unable to move file to %s", exporter->mv_path);
        }
    }

    if (exporter->gzip && !rm) {
        if (mv_name) {
            md_util_compress_file(mv_name->str);
        } else {
            md_util_compress_file(filename);
        }
    }

    if (mv_name) {
        g_string_free(mv_name, TRUE);
    }

    if (filename) {
        g_free(filename);
    }
}




/**
 * mdOpenFileExport
 *
 * open an IPFIX file, close the current IPFIX file
 *
 */
static fBuf_t *mdOpenFileExport(
    mdFlowExporter_t *exporter,
    const char       *path,
    GError           **err)
{

    fBuf_t            *fbuf = NULL;
    fbSession_t       *session;

    if (exporter == NULL) {
        exporter = g_new0(mdFlowExporter_t, 1);
    }


    if (strlen(path) == 1 && path[0] == '-') {
        g_debug("%s: Writing to stdout", exporter->name);
        exporter->lfp = stdout;
    } else {
        exporter->lfp = fopen(path, "w");

        g_debug("%s: Opening File %s", exporter->name, path);
    }

    if ( exporter->lfp == NULL ) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                    "%s: Can not open file %s for writing", exporter->name,
                    path);
        return NULL;
    }

    exporter->exporter = fbExporterAllocFP(exporter->lfp);

    if ( exporter->exporter == NULL ) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                    "%s: Error creating the exporter", exporter->name);
        return NULL;
    }

    if (!(session = exporter->sess_init(NULL, err, exporter->no_stats, exporter->metadata_export))) {
        return NULL;
    }

    fbuf = fBufAllocForExport(session, exporter->exporter);

    if (!fbSessionExportTemplates(session, err)) {
        if (fbuf) fBufFree(fbuf);
        return NULL;
    }

    return fbuf;

}

/**
 * mdOpenTextFileExport
 *
 * open a new text file, close the current one
 *
 *
 */
static gboolean mdOpenTextFileExport(
    mdFlowExporter_t    *exporter,
    const char          *path,
    GError              **err)
{
    GString *str;
    size_t rc;

    if (exporter == NULL) {
        exporter = g_new0(mdFlowExporter_t, 1);
    }

    if (strlen(path) == 1 && path[0] == '-') {
        g_debug("%s: Writing Text to stdout", exporter->name);
        exporter->lfp = stdout;
    } else {
        g_debug("%s: Opening Text File: %s", exporter->name, path);
        exporter->lfp = fopen(path, "w+");
    }
    if (exporter->lfp == NULL) {
        if (errno == 2) {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                        "%s: Error opening file %s: No such file or directory",
                        exporter->name, path);
        } else {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                        "%s: Can not open file %s for writing", exporter->name,
                        path);
        }
        return FALSE;
    }

    if (exporter->print_header) {
        str = g_string_new("");
        mdPrintBasicHeader(str, exporter->delimiter);
        rc = fwrite(str->str, 1, str->len, exporter->lfp);

        if (rc != str->len) {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                        "%s: Error writing to file: %s\n", exporter->name,
                        strerror(errno));
            return FALSE;
        }
        g_string_free(str, TRUE);
    }

    return TRUE;
}


/**
 * mdOutputClose
 *
 * emit the fbuf, and free it.
 *
 */
static gboolean mdOutputClose(
    fBuf_t      *fbuf,
    gboolean    flush,
    GError      **err)
{

    gboolean ok = TRUE;

    if (fbuf == NULL) {
        return ok;
    }

    if (flush) {
        ok = fBufEmit(fbuf, err);
    }

    fBufFree(fbuf);
    fbuf = NULL;

    return ok;

}

/**
 * mdFileOpenRotater
 *
 * get a new filename for file rotaters in the format of
 * outspec-TIME-serial_no
 *
 */
static GString *mdFileOpenRotater(
    mdFlowExporter_t *exporter)
{
    GString         *namebuf = NULL;
    static uint32_t serial = 0;
    time_t          cur_time= time(NULL);

    namebuf = g_string_new("");

    if (exporter->type == TEXT) {
        g_string_append_printf(namebuf, "%s.", exporter->outspec);
    } else {
        g_string_append_printf(namebuf, "%s-", exporter->outspec);
    }

    if (exporter->timestamp_files) {
        uint64_t flow_secs = exporter->last_rotate_ms /1000;
        md_util_time_g_string_append(namebuf, flow_secs, TIME_FMT);
    } else {
        md_util_time_g_string_append(namebuf, cur_time, TIME_FMT);
    }

    if (!exporter->timestamp_files) {
        g_string_append_printf(namebuf, "-%05u", serial++);
    }

    return namebuf;
}

/**
 * mdOpenTextOutput
 *
 * open a new text exporter
 *
 */
static gboolean mdOpenTextOutput(
    mdFlowExporter_t    *exporter,
    GError              **err)
{
    GString     *namebuf = NULL;
    gboolean    rc;

    if (exporter->multi_files || (exporter->dedupconfig && !exporter->json)) {
        return TRUE;
    }

    if (exporter->rotate) {
        namebuf = mdFileOpenRotater(exporter);
        if (exporter->json) {
            g_string_append_printf(namebuf, ".json");
        } else {
            g_string_append_printf(namebuf, ".txt");
        }
        exporter->current_fname = g_strdup(namebuf->str);
        if (exporter->lock) {
            mdLockFile(namebuf);
        }
        rc = mdOpenTextFileExport(exporter, namebuf->str, err);
        g_string_free(namebuf, TRUE);
        return rc;
    }

    return mdOpenTextFileExport(exporter, exporter->outspec, err);
}

/**
 * mdTextFileRotate
 *
 * close the current text file, and get a new filename
 * for the new one
 *
 */
static gboolean mdTextFileRotate(
    mdFlowExporter_t  *exporter,
    uint64_t          cur_time,
    GError            **err)
{
    GString          *namebuf;
    gboolean         rc = FALSE;

    if (exporter->multi_files) {
        exporter->last_rotate_ms = cur_time;
        return TRUE;
    }

    if (exporter->dedupconfig && !exporter->json) {
        return TRUE;
    }

    if (exporter->last_rotate_ms == 0) {
        exporter->last_rotate_ms = cur_time;
        return mdOpenTextOutput(exporter, err);
    }

    exporter->last_rotate_ms = cur_time;

    if (exporter->lfp) {
        mdCloseAndUnlock(exporter, exporter->lfp, exporter->current_fname,
                         NULL);
    }

    namebuf = mdFileOpenRotater(exporter);

    if (exporter->json) {
        g_string_append_printf(namebuf, ".json");
    } else {
        g_string_append_printf(namebuf, ".txt");
    }

    exporter->current_fname = g_strdup(namebuf->str);

    if (exporter->lock) {
        mdLockFile(namebuf);
    }

    rc = mdOpenTextFileExport(exporter, namebuf->str, err);

    g_string_free(namebuf, TRUE);

    return rc;
}

static gboolean mdVerifyRotatePath(
    mdFlowExporter_t      *exporter,
    GError                **err)
{
    FILE                  *tmp = NULL;
    GString               *tmpname = NULL;
    /* test that path exists and file can be created */

    tmpname = mdFileOpenRotater(exporter);

    tmp = fopen(tmpname->str, "w+");

    if (tmp == NULL) {
        if (errno == 2) {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                        "%s: Error opening file %s: No such file or directory",
                        exporter->name, exporter->outspec);
        } else {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                        "%s: Can not open file %s for writing",
                        exporter->name, exporter->outspec);
        }
        return FALSE;
    } else {
        /* close and remove empty temp file */
        fclose(tmp);
        g_remove(tmpname->str);
        g_string_free(tmpname, TRUE);
    }

    return TRUE;
}

/**
 * mdFileRotate
 *
 * rotate IPFIX files, will have ".med" suffix
 *
 */
static fBuf_t *mdFileRotate(
    mdFlowExporter_t  *exporter,
    uint64_t          cur_time,
    GError            **err)
{
    GString           *namebuf;
    fBuf_t            *buf = NULL;

    exporter->last_rotate_ms = cur_time;

    mdOutputClose(exporter->fbuf, TRUE, err);

    if (exporter->lfp) {
        mdCloseAndUnlock(exporter, exporter->lfp, exporter->current_fname,
                         NULL);
    }

    namebuf = mdFileOpenRotater(exporter);

    g_string_append_printf(namebuf, ".med");

    exporter->current_fname = g_strdup(namebuf->str);

    if (exporter->lock) {
        mdLockFile(namebuf);
    }

    buf = mdOpenFileExport(exporter, namebuf->str, err);

    g_string_free(namebuf, TRUE);

    return buf;

}

#if HAVE_SPREAD
/**
 * mdSpreadExport
 *
 * open a new Spread Exporter
 *
 */
static fBuf_t *mdSpreadExport(
    mdConfig_t        *cfg,
    mdFlowExporter_t  *exporter,
    GError            **err)
{

    fbSession_t *session;
    fBuf_t      *fbuf = NULL;

    session = fbSessionAlloc(mdInfoModel());
    cfg->out_spread.session = session;

    cfg->out_spread.daemon = exporter->outspec;

    exporter->exporter = fbExporterAllocSpread(&(cfg->out_spread));

    if (exporter->exporter == NULL) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                    "Unabled to create Spread Exporter\n");
        return NULL;
    }

    fbuf = fBufAllocForExport(session, exporter->exporter);

    if (!(session = mdInitSpreadExporterSession(session,
                                                exporter->dnsdedup, err)))
    {
        if (fbuf) fBufFree(fbuf);
        return NULL;
    }

    if (!fbSessionExportTemplates(session, err)) {
        if (fbuf) fBufFree(fbuf);
        return NULL;
    }

    /* set internal template ? */
    if (!fBufSetInternalTemplate(fbuf, YAF_SILK_FLOW_TID, err)){
        return NULL;
    }

    return fbuf;
}
#endif

/**
 * mdOpenIntExport
 *
 * open a TCP/UDP Exporter
 *
 */
static fBuf_t *mdOpenIntExport(
    mdFlowExporter_t    *exporter,
    GError              **err)
{

    fbSession_t       *session;
    fBuf_t            *fbuf = NULL;

    if (!(session = exporter->sess_init(NULL, err, exporter->no_stats, exporter->metadata_export))) {
        return NULL;
    }

    exporter->exporter = fbExporterAllocNet(&(exporter->spec));

    if (exporter->exporter == NULL) {
        return NULL;
    }

    fbuf = fBufAllocForExport(session, exporter->exporter);

    if (!fbSessionExportTemplates(session, err)) {
        if (fbuf) fBufFree(fbuf);
        return NULL;
    }

    /* set internal template ? */
    /*if (!fBufSetInternalTemplate(fbuf, YAF_SILK_FLOW_TID, err)){
        return NULL;
        }*/


    return fbuf;
}


/**
 * mdOutputOpen
 *
 * configure the new exporter
 *
 */
static fBuf_t *mdOutputOpen(
    mdConfig_t       *cfg,
    mdFlowExporter_t *exporter,
    GError           **err)
{

#if HAVE_SPREAD
    if (exporter->type == SPREAD) {
        return mdSpreadExport(cfg, exporter, err);
    }
#endif
    if (exporter->type == TCP || exporter->type == UDP) {
        return mdOpenIntExport(exporter, err);
    }

    if (exporter->rotate) {
        return mdFileRotate(exporter, cfg->ctime, err);
    }

    return mdOpenFileExport(exporter, exporter->outspec, err);

}

/**
 * mdExporterWriteOptions
 *
 * write an IPFIX Options Record
 *
 * @param cfg - mediator configuration options
 * @param exporter - the exporter to write to
 * @param stats - an ipfix stats record
 * @param err
 * @param TRUE, if everything's good.
 */
gboolean mdExporterWriteOptions(
    mdConfig_t         *cfg,
    mdFlowExporter_t   *exporter,
    yfIpfixStats_t     *stats,
    GError             **err)
{
    size_t bytes;

    if (exporter->no_stats == 1) {
        return TRUE;
    }

    if (!exporter->active) {
        if (cfg->ctime - exporter->last_restart_ms > MD_RESTART_MS) {
            if (!mdExporterRestart(cfg, exporter, err)) {
                g_message("Error restarting exporter %s: %s",
                          exporter->name, (*err)->message);
                g_clear_error(err);
                return TRUE;
            }
        } else {
            return TRUE;
        }
    }

    if (exporter->fbuf) {
        if (!fBufSetInternalTemplate(exporter->fbuf,YAF_OPTIONS_FLOW_TID, err))
        {
            return FALSE;
        }

        if (exporter->type == SPREAD) {
#if HAVE_SPREAD
            fBufSetSpreadExportGroup(exporter->fbuf, cfg->out_spread.groups,
                                     num_out_groups, err);
            if (!mdSetSpreadExportTemplate(exporter->fbuf, &(cfg->out_spread),
                                           YAF_OPTIONS_FLOW_TID,
                                           cfg->out_spread.groups,
                                           num_out_groups, err))
            {
                goto err;
            }
#endif
        } else {
            if (!mdSetExportTemplate(exporter->fbuf, YAF_OPTIONS_FLOW_TID,err))
            {
                goto err;
            }
        }

        if (!(fBufAppend(exporter->fbuf, (uint8_t *)stats,
                         sizeof(yfIpfixStats_t), err)))
        {
            fBufFree(exporter->fbuf);
            exporter->fbuf = NULL;
            goto err;
        }

    } else {

        if (exporter->rotate) {
            if ((cfg->ctime - exporter->last_rotate_ms) > exporter->rotate) {
                if (!mdTextFileRotate(exporter, cfg->ctime, err)) {
                    exporter->last_rotate_ms = 0;
                    goto err;
                }
            }
        }

        if (exporter->json) {
            bytes = mdPrintJsonStats(stats, cfg->collector_name,
                    exporter->lfp, err);
        } else {
            bytes = mdPrintStats(stats, cfg->collector_name, exporter->lfp,
                    exporter->delimiter, exporter->no_stats, err);
        }
        if (!bytes) {
            goto err;
        }

        exporter->exp_bytes += bytes;
    }

    /* update exporter stats */
    ++(exporter->exp_stats);
    exporter->exp_bytes += sizeof(yfIpfixStats_t);

    return TRUE;

  err:
    g_warning("Error writing option statistics: %s", (*err)->message);
    g_clear_error(err);
    g_warning("Deactivating Exporter %s.", exporter->name);
    exporter->active = FALSE;
    if (!mdExporterRestart(cfg, exporter, err)) {
        g_warning("Error restarting exporter %s: %s",
                  exporter->name, (*err)->message);
        g_clear_error(err);
    }
    return TRUE;
}


static gboolean mdExporterfBufSetup(
    mdConfig_t          *cfg,
    mdFlowExporter_t    *exporter,
    mdFullFlow_t        *flow,
    GError              **err,
    md_sess_init_fn     sess_init,
    uint16_t            int_tid,
    uint16_t            ext_tid)
{

#if HAVE_SPREAD
    char             *groups[10];
    int              num_groups;
#endif

    if (exporter->rotate) {
        if (exporter->last_rotate_ms &&
            (cfg->ctime - exporter->last_rotate_ms) > exporter->rotate)
        {
            exporter->fbuf = (fBuf_t *)mdFileRotate(exporter, cfg->ctime,
                                                    err);
        } else if (exporter->last_rotate_ms == 0) {
            exporter->last_rotate_ms = cfg->ctime;
        }
    }

    if (exporter->type == SPREAD) {
#if HAVE_SPREAD
        if (cfg->mdspread) {
            if ((num_groups = mdSpreadExporterFilter(cfg->mdspread,
                                                     flow, groups)))
            {
                fBufSetSpreadExportGroup(exporter->fbuf, groups, num_groups,
                                         err);
            } else {
                return FALSE;
            }
        }
#endif

    } else if (exporter->type == UDP) {

        if ((cfg->ctime - exporter->lastUdpTempTime) >
            ((cfg->udp_template_timeout)/3))
        {
            if (!fbSessionExportTemplates(fBufGetSession(exporter->fbuf),
                                          err))
            {
                g_warning("Failed to renew UDP Templates: %s",
                          (*err)->message);
                g_clear_error(err);
            }
            exporter->lastUdpTempTime = cfg->ctime;
        }
    }

    /* set internal template */
    if (!fBufSetInternalTemplate(exporter->fbuf, int_tid, err)) {

        /* if template doesn't exist, then use the sess_init function
           to create templates and add them to the session */
        if (!g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_TMPL)) {
            return FALSE;
        }

        g_clear_error(err);

        if (!sess_init(fBufGetSession(exporter->fbuf), err,exporter->no_stats, exporter->metadata_export))
        {
            return FALSE;
        }

        if (!fBufSetInternalTemplate(exporter->fbuf, int_tid, err)) {
            return FALSE;
        }
    }

    if (exporter->type == SPREAD) {
#if HAVE_SPREAD
        if (!mdSetSpreadExportTemplate(exporter->fbuf, &(cfg->out_spread),
                                       ext_tid, groups, num_groups, err))
        {
            return FALSE;
        }
#endif
    } else {
        if (!mdSetExportTemplate(exporter->fbuf, ext_tid, err)) {
            return FALSE;
        }
    }

    return TRUE;

}

/**
 * mdExporterWriteFlow
 *
 * write a mediator flow record
 *
 * @param cfg - mediator configuration options
 * @param exporter - exporter to write to
 * @param flow - a full mediator flow
 * @param err
 * @return TRUE if no errors were encountered
 */
int mdExporterWriteFlow(
    mdConfig_t          *cfg,
    mdFlowExporter_t    *exporter,
    mdFullFlow_t        *flow,
    GError              **err)
{

    gboolean         rc;
    uint16_t         tid;
    int              ret;
    char             *indexstr = NULL;
    size_t           indexlen = 0;

    if (exporter->fbuf && exporter->dns_rr_only) {
        /* dns rr only? */
        if ((flow->rec->numAppLabel == 53) && flow->app) {
            if (!mdExportDNSRR(cfg, exporter, flow, flow->tid, err)) {
                return -1;
            }
        }
    }

    if (exporter->dnsdeduponly || (exporter->no_stats == 2) ||
        exporter->ssldeduponly || exporter->deduponly || exporter->no_flow)
    {
        return 0;
    }

    tid = mdConvertToSiLK(flow->rec, flow->tid);

    if (!exporter->flowonly) {
        /* If FLOW_ONLY isn't present, include STML */
        tid |= YTF_LIST;
        /* check to see if TCP is in main record, if not-keep it in list */
        if ((flow->tid & 0x0020) == 0) {
            /* don't include tcp in reg template - use stml */
            tid &= 0xFFDF;
        }

        /* Since we use Template PAIRS for SSL - we need to change the template
           ID from our internal template ID back to the external template ID
           that is used to define SSL Entries */
        if (flow->app_tid == SM_INTSSL_FLOW_TID) {
            yfNewSSLFlow_t *sslflow = (yfNewSSLFlow_t *)flow->app;
            fbSubTemplateList_t *stl = &(sslflow->sslCertList);
            stl->tmplID = YAF_NEW_SSL_CERT_TID;
            flow->cert->tmplID = YAF_NEW_SSL_FLOW_TID;
        }

    } else {
        if (flow->rec->flowEndReason == UDP_FORCE) {
            /* ignore dns records */
            return 0;
        }
    }

    if (!exporter->active) {
        if (cfg->ctime - exporter->last_restart_ms > MD_RESTART_MS) {
            if (!mdExporterRestart(cfg, exporter, err)) {
                g_message("Error restarting exporter %s: %s",
                          exporter->name, (*err)->message);
                g_clear_error(err);
                return 0;
            }
        } else {
            return 0;
        }
    }

    if (exporter->fbuf) {

        if (exporter->dpionly) {
            if (flow->app_tid == 0) {
                return 0;
            }
        }

        if (!mdExporterfBufSetup(cfg, exporter, flow, err,
                               mdInitExporterSession, YAF_SILK_FLOW_TID, tid))
        {
            goto err;
        }

        if (cfg->usec_sleep) {
            usleep(cfg->usec_sleep);
        }

        exporter->exp_bytes += sizeof(mdRecord_t);

        rc = fBufAppend(exporter->fbuf, (uint8_t *)flow->rec,
                        sizeof(mdRecord_t), err);

        if (!rc) {
            fBufFree(exporter->fbuf);
            goto err;
        }

    } else if (exporter->type == TEXT) {

        if (exporter->rotate) {
            if ((cfg->ctime - exporter->last_rotate_ms) > exporter->rotate) {
                if (!mdTextFileRotate(exporter, cfg->ctime, err)) {
                    exporter->last_rotate_ms = 0;
                    goto err;
                }
            }
        }

        if (exporter->custom_list) {
            ret = mdCustomFlowPrint(exporter->custom_list, flow, exporter,
                                    err);
            if (ret == 1) {
                return 0;
            }
        } else {
            /* if it's not custom - it's multi-files OR DPI-only */
            if (mdExporterDPIGetIndexStr(exporter, flow)) {
                indexlen = MD_MSG_LEN(exporter->buf);
                indexstr = malloc(indexlen);
                memcpy(indexstr, exporter->buf->buf, indexlen);
                /* reset buffer */
                exporter->buf->cp = exporter->buf->buf;
                ret = mdExporterDPIFlowPrint(exporter, flow,
                                             indexstr, indexlen, err);
                if (ret > 0) free(indexstr);
                /* didn't actually add anything */
                if (ret == 1) return 0;
            } else {
                /* NO DPI DATA - continue */
                return 0;
            }
        }

        if (ret < 0) {
            goto err;
        } else if (ret == 0) {
            /* realloc bigger buffer and try again */
            if (!mdExporterExpandBuf(exporter)) {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_MEM,
                            "Error allocating memory for exporter %s",
                            exporter->name);
                return -1;
            }
            if (exporter->custom_list) {
                ret = mdCustomFlowPrint(exporter->custom_list, flow, exporter,
                                        err);
            } else if (indexstr) {
                ret = mdExporterDPIFlowPrint(exporter, flow,
                                             indexstr, indexlen, err);
                if (ret > 0) free(indexstr);
            }
            if (ret < 0) {
                goto err;
            } else if (ret == 0) {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                            "Error writing to buffer for exporter %s",
                            exporter->name);
                goto err;
            }
        }

    } /* TEXT type exporter */

    ++(exporter->exp_flows);

    return 1;

  err:
    g_warning("Error writing flow: %s", (*err)->message);
    g_clear_error(err);
    g_warning("Deactivating Exporter %s.", exporter->name);
    exporter->active = FALSE;
    if (!mdExporterRestart(cfg, exporter, err)) {
        g_warning("Error restarting exporter %s: %s",
                  exporter->name, (*err)->message);
        g_clear_error(err);
    }
    return 1;
}

/**
 * mdExporterWriteRecord
 *
 * write a DNS de-duplicated record to the given exporter
 *
 * @param cfg - mediator configuration options
 * @param exporter - exporter to write to
 * @param tid - template id
 * @param rec - the record to write
 * @param rec_length - length of record to write
 * @param err
 * @return TRUE if no errors
 */
gboolean mdExporterWriteRecord(
    mdConfig_t        *cfg,
    mdFlowExporter_t  *exporter,
    uint16_t          tid,
    uint8_t           *rec,
    size_t             rec_length,
    GError            **err)
{
    int              ret;
    gboolean         print_last_seen = FALSE;

    if (exporter == NULL) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                    "Exporter Node Exists, but No Type\n");
        return FALSE;
    }

    if (!exporter->dnsdedup) {
        return TRUE;
    }

    if (!exporter->active) {
        if (cfg->ctime - exporter->last_restart_ms > MD_RESTART_MS) {
            if (!mdExporterRestart(cfg, exporter, err)) {
                g_message("Error restarting exporter %s: %s",
                          exporter->name, (*err)->message);
                g_clear_error(err);
                return TRUE;
            }
        } else {
            return TRUE;
        }

    }

    if (exporter->fbuf) {
        /* remove null char at the end of dnsrrname? */

        if (!mdExporterfBufSetup(cfg, exporter, NULL, err,
                                 mdInitExporterSessionDNSDedupOnly,
                                 MD_DNS_FULL, tid))
        {
            return FALSE;
        }

        if (!fBufAppend(exporter->fbuf, (uint8_t *)rec, rec_length, err)) {
            fBufFree(exporter->fbuf);
            goto err;
        }
        /* update stats */
        exporter->exp_bytes += rec_length;

    }

    if (exporter->type == TEXT) {
        if (tid & MD_LAST_SEEN) {
            print_last_seen = TRUE;
        }

        if (exporter->rotate) {
            if ((cfg->ctime - exporter->last_rotate_ms) > exporter->rotate) {
                if (!mdTextFileRotate(exporter, cfg->ctime, err)) {
                    exporter->last_rotate_ms = 0;
                    goto err;
                }
            }
        }

        if (exporter->json) {
            ret = mdJsonifyDNSDedupRecord(exporter->lfp, exporter->buf, rec,
                                          print_last_seen,
                                          cfg->dns_base64_encode, err);
        } else {
            ret = mdPrintDNSRecord(exporter->lfp, exporter->buf,
                                   exporter->delimiter, rec,
                                   cfg->dns_base64_encode, print_last_seen,
                                   exporter->escape_chars, err);
        }

        if (ret < 0) {
            goto err;
        } else if (ret == 0) {
            /* realloc bigger buffer and try again */
            if (!mdExporterExpandBuf(exporter)) {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_MEM,
                            "Error allocating memory for exporter %s",
                            exporter->name);
                return FALSE;
            }
            if (exporter->json) {
                ret = mdJsonifyDNSDedupRecord(exporter->lfp, exporter->buf,
                                              rec, print_last_seen,
                                              cfg->dns_base64_encode, err);
            } else {
                ret = mdPrintDNSRecord(exporter->lfp, exporter->buf,
                                       exporter->delimiter, rec,
                                       cfg->dns_base64_encode, print_last_seen,
                                       exporter->escape_chars, err);
            }

            if (ret < 0) {
                goto err;
            } else if (ret == 0) {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                            "Error writing to buffer for exporter %s",
                            exporter->name);
                goto err;
            }
        }

        exporter->exp_bytes += ret;
    }

    ++(exporter->exp_flows);

    return TRUE;

  err:

    g_warning("Error writing DNS Record: %s", (*err)->message);
    g_clear_error(err);
    g_warning("Deactivating Exporter %s.", exporter->name);
    exporter->active = FALSE;
    if (!mdExporterRestart(cfg, exporter, err)) {
        g_warning("Error restarting exporter %s: %s",
                  exporter->name, (*err)->message);
        g_clear_error(err);
    }

    return TRUE;
}

/**
 * mdExportersInit
 *
 * cycle through exporters and open their output methods
 *
 */
gboolean mdExportersInit(
    mdConfig_t          *cfg,
    md_export_node_t    *node,
    GError              **err)
{
    md_export_node_t *cnode = NULL;
    fbSession_t *session = NULL;

    for (cnode = node; cnode; cnode = cnode->next) {

        if (cnode->exp == NULL) {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "Error: No Exporter Defined.\n");
            return FALSE;
        }

        if (cnode->exp->type == TEXT) {
            if (!cnode->exp->rotate) {
                if (!mdOpenTextOutput(cnode->exp, err)) {
                    return FALSE;
                }
            } else {
                if (!mdVerifyRotatePath(cnode->exp, err)) {
                    return FALSE;
                }
            }
        } else {
            cnode->exp->fbuf = mdOutputOpen(cfg, cnode->exp, err);
            if (cnode->exp->fbuf == NULL) {
                g_warning("Error connecting to exporter: %s", (*err)->message);
                g_clear_error(err);
                cnode->exp->active = FALSE;
                continue;
                /*return FALSE;*/
            }

            if (cnode->dedup) {
                if (!md_dedup_add_templates(cnode->dedup, cnode->exp->fbuf,
                                            err))
                {
                    g_warning("Error adding dedup templates: %s",
                              (*err)->message);
                    cnode->exp->active = FALSE;
                    continue;
                }
            }

            /* just try to emit, there will be an error if not connected */
            if (!fBufEmit(cnode->exp->fbuf, err)) {
                if (cnode->exp->fbuf) fBufFree(cnode->exp->fbuf);
                g_warning("Error connecting to exporter: %s", (*err)->message);
                g_clear_error(err);
                cnode->exp->active = FALSE;
                continue;
                /*return FALSE;*/
            }
        }
        
        g_message("%s: Exporter Active.", cnode->exp->name);
        cnode->exp->active = TRUE;
    }

    return TRUE;
}

gboolean mdExporterRestart(
    mdConfig_t          *cfg,
    mdFlowExporter_t    *exporter,
    GError              **err)
{
    exporter->last_restart_ms = cfg->ctime;

    if (exporter == NULL) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Error: No Exporter Defined.\n");
        return FALSE;
    }

    if (exporter->type == TEXT) {
        if (!exporter->rotate) {
            if (!mdOpenTextOutput(exporter, err)) {
                return FALSE;
            }
        } else {
            if ((cfg->ctime - exporter->last_rotate_ms) > exporter->rotate) {
                if (!mdTextFileRotate(exporter, cfg->ctime, err)) {
                    exporter->last_rotate_ms = 0;
                    return FALSE;
                }
            }
        }

    } else {
        exporter->fbuf = mdOutputOpen(cfg, exporter, err);
        if (exporter->fbuf == NULL) {
            return FALSE;
        }
        if (!fBufEmit(exporter->fbuf, err)) {
            if (exporter->fbuf) fBufFree(exporter->fbuf);
            return FALSE;
        }
    }

    g_debug("%s: Total Flows Exported Before Restart: %"PRIu64,
            exporter->name, exporter->exp_flows);
    /*if (exporter->exp_dns) {
        g_debug("%s: Total DNS Records Exported Before Restart: %llu",
                exporter->name, exporter->exp_dns);
                }*/
    g_message("%s: Exporter successfully restarted. Now active.",
              exporter->name);
    /* reset counters */
    exporter->exp_flows = 0;
    exporter->exp_stats = 0;
    exporter->exp_bytes = 0;
    exporter->active = TRUE;
    exporter->last_restart_ms = 0;
    /* note that exporter was restarted */
    exporter->time_started = g_timer_elapsed(mdStatGetTimer(), NULL);
    return TRUE;

}

void mdExporterUpdateStats(
    mdConfig_t       *cfg,
    gboolean         dedup)
{
    md_export_node_t *cnode = NULL;
    uint64_t         seconds = g_timer_elapsed(mdStatGetTimer(), NULL);

    if (!seconds) seconds = 1;

    for (cnode = cfg->flowexit; cnode; cnode = cnode->next) {

        if (cnode->dedup) {
            if (dedup) {
                md_dedup_print_stats(cnode->dedup, cnode->exp->name);
            }
            continue;
        }

        if (cnode->exp->exp_flows) {
            g_message("Exporter %s: %"PRIu64" records, %"PRIu64" stats, "
                      "%.4f Mbps, %.2f bytes per record",
                      cnode->exp->name, cnode->exp->exp_flows,
                      cnode->exp->exp_stats,
                      ((((double)cnode->exp->exp_bytes * 8.0) / 1000000) /
                       seconds),
                      ((double)cnode->exp->exp_bytes / cnode->exp->exp_flows));
        } else {
            g_message("Exporter %s: %"PRIu64" records, %"PRIu64" stats",
                      cnode->exp->name, cnode->exp->exp_flows,
                      cnode->exp->exp_stats);
        }

        if (cnode->dns_dedup && dedup) {
            md_dns_dedup_print_stats(cnode->dns_dedup, cnode->exp->name);
        }

    }
}

/**
 * mdExporterDestroy
 *
 * loop through exporter list and remove the exporters
 * flush the DNS close queue, and destroy tables
 *
 */
gboolean mdExporterDestroy(
    mdConfig_t        *cfg,
    GError            **err)
{
    md_export_node_t *cnode = NULL;
    int              loop;

    mdExporterUpdateStats(cfg, FALSE);

    for (cnode = cfg->flowexit; cnode; cnode = cnode->next) {
        detachHeadOfSLL((mdSLL_t **)&(cfg->flowexit), (mdSLL_t **)&cnode);

        if (cnode->dns_dedup) {
            md_dns_flush_all_tab(cnode->dns_dedup, cfg->ctime, TRUE);
            if (!md_dns_flush_queue(cnode, cfg, err)) {
                return FALSE;
            }
            /* print final stats */
            md_dns_dedup_print_stats(cnode->dns_dedup, cnode->exp->name);
            if (!md_dns_dedup_free_state(cfg, cnode, err)) {
                return FALSE;
            }
        }

        if (cnode->dedup) {
            md_dedup_flush_alltab(cnode, cfg->ctime, TRUE);
            if (!md_dedup_flush_queue(cnode, cfg, err)) {
                return FALSE;
            }
            md_dedup_print_stats(cnode->dedup, cnode->exp->name);
            if (!md_dedup_free_state(cfg, cnode, err)) {
                return FALSE;
            }
            if (cnode->exp->type == TEXT && !cnode->exp->json) {
                /* otherwise it will be freed below */
                g_free(cnode->exp->outspec);
            }
        }

        if (cnode->ssl_dedup) {
            md_ssl_flush_tab(cnode->ssl_dedup, cfg->ctime, TRUE);
            if (!md_ssl_flush_queue(cnode, cfg, err)) {
                return FALSE;
            }
            md_ssl_dedup_print_stats(cnode->ssl_dedup, cnode->exp->name);
            if (!md_ssl_dedup_free_state(cfg, cnode, err)) {
                return FALSE;
            }
        }

        if (cnode->exp->fbuf && cnode->exp->active) {
            if (!mdOutputClose(cnode->exp->fbuf, TRUE, err)) {
                return FALSE;
            }
        }

        if (cnode->exp->spec.host) {
            g_free(cnode->exp->spec.host);
        }

        if (cnode->exp->spec.svc) {
            g_free(cnode->exp->spec.svc);
        }

        if (cnode->exp->ssl_config) {
            if (cnode->exp->ssl_config->issuer) {
                g_free(cnode->exp->ssl_config->issuer);
            }
            if (cnode->exp->ssl_config->subject) {
                g_free(cnode->exp->ssl_config->subject);
            }
            if (cnode->exp->ssl_config->other) {
                g_free(cnode->exp->ssl_config->other);
            }
            if (cnode->exp->ssl_config->extensions) {
                g_free(cnode->exp->ssl_config->extensions);
            }
            g_slice_free1(sizeof(cnode->exp->ssl_config),
                          cnode->exp->ssl_config);
        }

        if (cnode->exp->multi_files) {
            for (loop = 0; loop < num_tables; loop++) {
                if (table_info[loop]->table_file) {
                    mdCloseAndUnlock(cnode->exp, table_info[loop]->table_file,
                                     table_info[loop]->file_name,
                                     table_info[loop]->table_name);
                    /*fclose(table_info[loop]->table_file);
                    if (cnode->exp->lock) {
                        mdUnlockFile(table_info[loop]->file_name);
                    }
                    if (cnode->exp->mysql) {
                        mdLoadFile(cnode->exp, table_info[loop]->table_name,
                                   table_info[loop]->file_name);
                    }
                    g_free(table_info[loop]->file_name);*/
                }
                g_free(table_info[loop]->table_name);
                g_slice_free(mdTableInfo_t, table_info[loop]);
            }

            if (table_info) {
                g_free(table_info);
                g_hash_table_destroy(table_hash);
                num_tables = 0;
            }

            g_free(cnode->exp->outspec);

        } else if (cnode->exp->lfp) {
            if (cnode->exp->current_fname) {
                mdCloseAndUnlock(cnode->exp, cnode->exp->lfp,
                                 cnode->exp->current_fname, NULL);
                if (cnode->exp->outspec) {
                    g_free(cnode->exp->outspec);
                }
            } else {
                mdCloseAndUnlock(cnode->exp, cnode->exp->lfp,
                                 cnode->exp->outspec, NULL);
            }
        }

        if (cnode->exp->custom_list) {
            mdFieldList_t *list = cnode->exp->custom_list;
            mdFieldList_t *list2 = NULL;
            while (list) {
                detachHeadOfSLL((mdSLL_t **)&(cnode->exp->custom_list),
                                (mdSLL_t **)&list);
                list2 = list->next;
                g_string_free(list->decorator, TRUE);
                g_slice_free(mdFieldList_t, list);
                list = list2;
            }
        }

        if (cnode->exp->mysql) {
            g_free(cnode->exp->mysql->user);
            g_free(cnode->exp->mysql->password);
            g_free(cnode->exp->mysql->db_name);
            g_free(cnode->exp->mysql->db_host);
            g_free(cnode->exp->mysql->table);
#if HAVE_MYSQL
            if (cnode->exp->mysql->conn) {
                mysql_close(cnode->exp->mysql->conn);
            }
#endif
            g_slice_free(mdMySQLInfo_t, cnode->exp->mysql);
        }

        /* free exporter name */
        g_free(cnode->exp->name);

        if (cnode->exp->type == TEXT) {
            g_slice_free1(cnode->exp->buf->buflen, cnode->exp->buf->buf);
            g_slice_free(mdBuf_t, cnode->exp->buf);
        }

        mdExporterFree(cnode->exp);

        if (cnode->filter) {
            md_filter_t *cfil = cnode->filter;
            md_filter_t *nfil = NULL;

            while (cfil) {
                detachHeadOfSLL((mdSLL_t **)&(cnode->filter),
                                (mdSLL_t **)&cfil);
                nfil = cfil->next;
#if ENABLE_SKIPSET
                if (cfil->ipset) {
                    skIPSetDestroy(&(cfil->ipset));
                }
#endif
                g_slice_free(md_filter_t, cfil);
                cfil = nfil;
            }
#if ENABLE_SKIPSET
            skAppUnregister();
#endif
        }
        /*g_slice_free(md_export_node_t, cnode);*/

    }

    return TRUE;
}


/**
 * mdExporterConnectionReset
 *
 * when a connection is reset via TCP, flush the DNS tables
 * and buffer so we don't hang on to records too long.
 * this also gets called every 5 minutes if we're not receiving
 * anything
 *
 */
gboolean mdExporterConnectionReset(
    mdConfig_t        *cfg,
    GError            **err)
{

    md_export_node_t *cnode = NULL;

    for (cnode = cfg->flowexit; cnode; cnode = cnode->next) {

        if (!cnode->exp->active) {
            continue;
        }

        if (cnode->dns_dedup) {
            md_dns_flush_all_tab(cnode->dns_dedup, cfg->ctime, FALSE);
            if (!md_dns_flush_queue(cnode, cfg, err)) {
                return FALSE;
            }
        }

        if (cnode->dedup) {
            md_dedup_flush_alltab(cnode, cfg->ctime, FALSE);
            if (!md_dedup_flush_queue(cnode, cfg, err)) {
                return FALSE;
            }
        }

        if (cnode->ssl_dedup) {
            md_ssl_flush_tab(cnode->ssl_dedup, cfg->ctime, FALSE);
            if (!md_ssl_flush_queue(cnode, cfg, err)) {
                return FALSE;
            }
        }

        if (cnode->exp->fbuf) {
            if (!fBufEmit(cnode->exp->fbuf, err)) {
                g_warning("Error emitting buffer: %s", (*err)->message);
                g_warning("Deactivating Exporter %s.", cnode->exp->name);
                cnode->exp->active = FALSE;
                g_clear_error(err);
            }

            if (cnode->exp->rotate) {
                if (cnode->exp->last_rotate_ms == 0) {
                    cnode->exp->last_rotate_ms = cfg->ctime;
                } else if ((cfg->ctime - cnode->exp->last_rotate_ms) >
                           cnode->exp->rotate)
                {
                    cnode->exp->fbuf = (fBuf_t *)mdFileRotate(cnode->exp,
                                                              cfg->ctime,
                                                              err);
                }
            }
        }

        if (cnode->exp->lfp) {
            fflush(cnode->exp->lfp);
        }

        if (cnode->exp->type == TEXT) {
            if (cnode->exp->rotate) {
                if ((cfg->ctime - cnode->exp->last_rotate_ms) >
                    cnode->exp->rotate)
                {
                    if (!mdTextFileRotate(cnode->exp, cfg->ctime, err)) {
                        cnode->exp->last_rotate_ms = 0;
                        g_warning("Error rotating file: %s",(*err)->message);
                        g_warning("Deactivating Exporter %s.",
                                  cnode->exp->name);
                        cnode->exp->active = FALSE;
                        g_clear_error(err);
                    }
                }
            }
        }
    }

    return TRUE;

}

/**
 * mdAppendDPIStrMultiFiles
 *
 */
gboolean mdAppendDPIStrMultiFiles(
    mdFlowExporter_t  *exporter,
    uint8_t           *buf,
    char              *label,
    char              *index_str,
    size_t            index_len,
    uint16_t          id,
    size_t            buflen,
    gboolean          hex)
{

    char              delim = exporter->dpi_delimiter;
    mdBuf_t           *mdbuf = exporter->buf;
    size_t            brem = MD_REM_MSG(mdbuf);
    int               ret;
    FILE              *fp;
    size_t            rc;
    GError            *err;

    if (buflen == 0) {
        return TRUE;
    }

    if (table_hash) {
        label = mdGetTableItem(id);
        if (label == NULL) {
            return TRUE;
        }
    }

    if (!md_util_append_buffer(mdbuf, &brem, (uint8_t*)index_str, index_len)) {
        return FALSE;
    }

    ret = snprintf(mdbuf->cp, brem, "%d%c", id, delim);
    MD_CHECK_RET(mdbuf, ret, brem);

    if (!mdPrintVariableLength(mdbuf, &brem, buf, buflen,
                               delim, hex, exporter->escape_chars)) {
        return FALSE;
    }


    MD_APPEND_CHAR_CHECK(brem, mdbuf, '\n');

    fp = mdGetTableFile(exporter, id);

    if (fp == NULL) {
        g_warning("Error: File does not exist for id %d", id);
        return FALSE;
    }

    rc = md_util_write_buffer(fp, mdbuf, exporter->name, &err);

    if (!rc) {
        g_warning("Error writing file for id %d: %s",
                  id, err->message);
        g_clear_error(&err);
        return FALSE;
    }

    exporter->exp_bytes += rc;

    return TRUE;
}


/**
 * mdAppendDPIStr
 *
 * append the given string and label to the given GString
 *
 */
gboolean mdAppendDPIStr(
    mdFlowExporter_t  *exporter,
    uint8_t           *buf,
    char              *label,
    char              *index_str,
    size_t            index_len,
    uint16_t          id,
    size_t            buflen,
    gboolean          hex)
{

    char              delim = exporter->dpi_delimiter;
    mdBuf_t           *mdbuf = exporter->buf;
    size_t            brem = MD_REM_MSG(mdbuf);
    int               ret;

    if (buflen == 0) {
        return TRUE;
    }

    if (exporter->dpi_field_table) {
        if (!mdGetDPIItem(exporter->dpi_field_table, id)) {
            return TRUE;
        }
    }

    if (!exporter->no_index) {
        ret = snprintf(mdbuf->cp, brem, "%s%c", label, delim);
        MD_CHECK_RET(mdbuf, ret, brem);
    }

    if (!md_util_append_buffer(mdbuf, &brem, (uint8_t*)index_str, index_len)) {
        return FALSE;
    }

    ret = snprintf(mdbuf->cp, brem, "%d%c", id, delim);
    MD_CHECK_RET(mdbuf, ret, brem);

    if (!mdPrintVariableLength(mdbuf, &brem, buf, buflen, delim, hex,
                               exporter->escape_chars)) {
        return FALSE;
    }

    MD_APPEND_CHAR_CHECK(brem, mdbuf, '\n');

    return TRUE;
}

/**
 * mdCustomFlowPrint
 *
 *
 */
int mdCustomFlowPrint(
    mdFieldList_t     *list,
    mdFullFlow_t      *fflow,
    mdFlowExporter_t  *exporter,
    GError            **err)
{
    mdFieldList_t   *cnode = NULL;
    mdBuf_t         *buf = exporter->buf;
    char            *bufstart = buf->cp;
    size_t          brem = MD_REM_MSG(buf);
    size_t          buflen;
    size_t          rc = 0;
    int             ret;


    if (exporter->dpionly && !(fflow->app_tid || fflow->dhcpfp)) {
        return 1;
    }

    if (exporter->json) {
        ret = snprintf(buf->cp, brem, "{\"flows\":{");
        MD_CHECK_RET(buf, ret, brem);
    }

    for (cnode = list; cnode; cnode = cnode->next) {
        if (!cnode->print_fn(fflow, buf, &brem, cnode->decorator->str)) {
            return 0;
        }
        rc++;
    }

    if (exporter->basic_list_dpi &&
        (fflow->app_tid || fflow->dhcpfp || fflow->stats))
    {
        ret = mdExporterDPIFlowPrint(exporter, fflow, NULL, 0, err);
    } else if (exporter->custom_list_dpi && fflow->app_tid) {
        /* reset buffer - since it will be copied for each DPI line */
        char *indexstr = NULL;
        buflen = MD_MSG_LEN(buf);
        indexstr = malloc(buflen);
        memcpy(indexstr, buf->buf, buflen);
        buf->cp = buf->buf;
        ret = mdExporterDPIFlowPrint(exporter, fflow, indexstr, buflen, err);
        free(indexstr);
    } else if (!exporter->dpionly) {
        /* remove last delimiter */
        buf->cp -= 1;
        brem += 1;
        if (exporter->json) {
            ret = snprintf(buf->cp, brem, "}}\n");
            MD_CHECK_RET(buf, ret, brem);
        } else {
            MD_APPEND_CHAR_CHECK(brem, buf, '\n');
        }
        rc = md_util_write_buffer(exporter->lfp, buf, exporter->name, err);

        if (!rc) {
            return -1;
        }

        exporter->exp_bytes += rc;

        ret = rc;
    } else {
        /* if DPI_ONLY - only print line if DPI is associated with it." */
        /* don't write anything - rewind buffer */
        buf->cp = bufstart;
        ret = 1;
    }

    return ret;
}


/**
 * mdDPIIndex
 *
 * print an index line in the output file.
 *
 */
static gboolean mdDPIIndex(
    mdFlowExporter_t *exporter,
    mdFullFlow_t     *flow,
    char             *label)
{
    mdBuf_t          *buf = exporter->buf;
    size_t            brem = MD_REM_MSG(buf);
    char              strdec[10];
    char              intdec[10];
    int               ret;

    if (exporter->json) {
        /* no for JSON */
        return TRUE;
    }

    snprintf(strdec, sizeof(strdec), "%%s%c", exporter->dpi_delimiter);
    snprintf(intdec, sizeof(intdec), "%%u%c", exporter->dpi_delimiter);

    if (table_hash) {
        label = mdGetTableItem(0);
        if (label == NULL) {
            return TRUE;
        }
    }

    if (!exporter->multi_files) {
        ret = snprintf(buf->cp, brem, "%s%c", label, exporter->dpi_delimiter);
        MD_CHECK_RET(buf, ret, brem);
    }

    if (!mdPrintFlowKeyHash(flow, buf, &brem, intdec)) return FALSE;
    if (!mdPrintSTIMEMS(flow, buf, &brem, "%llu")) return FALSE;
    MD_APPEND_CHAR_CHECK(brem, buf, exporter->dpi_delimiter);
    if (!mdPrintSIP(flow, buf, &brem, strdec)) return FALSE;
    if (!mdPrintDIP(flow, buf, &brem, strdec)) return FALSE;
    if (!mdPrintProto(flow, buf, &brem, intdec)) return FALSE;
    if (!mdPrintSPort(flow, buf, &brem, intdec)) return FALSE;
    if (!mdPrintDPort(flow, buf, &brem, intdec)) return FALSE;
    if (!mdPrintVLANINT(flow, buf, &brem, intdec)) return FALSE;
    if (!mdPrintOBDomain(flow, buf, &brem, "%u")) return FALSE;

    MD_APPEND_CHAR_CHECK(brem, buf, '\n');

    if (exporter->multi_files) {
        FILE  *fp = mdGetTableFile(exporter, 0);
        size_t rc;
        GError *err;
        if (fp == NULL) {
            g_warning("Error retrieving file for index records");
            return TRUE;
        }
        rc = md_util_write_buffer(fp, buf, exporter->name, &err);
        if (!rc) {
            g_warning("Error writing index records: %s",
                      err->message);
            g_clear_error(&err);
            return FALSE;

        }
        exporter->exp_bytes += rc;
    }

    return TRUE;

}

static gboolean mdDPIExtendedIndex(
    mdFlowExporter_t *exporter,
    mdFullFlow_t     *flow)
{
    mdBuf_t          *buf = exporter->buf;
    size_t            brem = MD_REM_MSG(buf);
    char              delim = exporter->dpi_delimiter;
    char              strdec[10];
    char              intdec[10];

    snprintf(strdec, sizeof(strdec), "%%s%c", delim);
    snprintf(intdec, sizeof(intdec), "%%d%c", delim);

    if (!mdPrintSTIME(flow, buf, &brem, strdec)) return FALSE;
    if (!mdPrintSIP(flow, buf, &brem, strdec)) return FALSE;
    if (!mdPrintDIP(flow, buf, &brem, strdec)) return FALSE;
    if (!mdPrintProto(flow, buf, &brem, intdec)) return FALSE;
    if (!mdPrintSPort(flow, buf, &brem, intdec)) return FALSE;
    if (!mdPrintDPort(flow, buf, &brem, intdec)) return FALSE;
    if (!mdPrintVLANINT(flow, buf, &brem, intdec)) return FALSE;
    if (!mdPrintOBDomain(flow, buf, &brem, intdec)) return FALSE;

    return TRUE;
}

/**
 * mdExportFlowStats
 *
 */
static gboolean mdExportFlowStats(
    mdFlowExporter_t     *exporter,
    yfFlowStatsRecord_t  *stats,
    char                 *index_str,
    size_t               index_len,
    char                 *label,
    uint8_t              rev)
{
    char delim = exporter->delimiter;
    mdBuf_t *buf = exporter->buf;
    size_t brem = MD_REM_MSG(buf);
    char *bufstart = buf->cp;
    int ret;
    GError *err;

    if (exporter->no_flow_stats) {
        return TRUE;
    }

    if (!exporter->no_index) {
        ret = snprintf(buf->cp, brem, "%s%c", label, delim);
        MD_CHECK_RET(buf, ret, brem);
    }

    if (!md_util_append_buffer(buf, &brem, (uint8_t*)index_str, index_len)) {
        return FALSE;
    }

    ret = snprintf(buf->cp, brem, "%u%c%u%c%u%c%"PRIu64,
                   stats->tcpUrgTotalCount, delim,
                   stats->smallPacketCount, delim,
                   stats->nonEmptyPacketCount, delim,
                   stats->dataByteCount);
    MD_CHECK_RET(buf, ret, brem);
    ret = snprintf(buf->cp, brem, "%c%"PRIu64"%c%d%c%d%c%d%c", delim,
                   stats->averageInterarrivalTime, delim,
                   stats->firstNonEmptyPacketSize, delim,
                   stats->largePacketCount, delim,
                   stats->maxPacketSize, delim);
    MD_CHECK_RET(buf, ret, brem);
    ret = snprintf(buf->cp, brem, "%02x%c%d%c%"PRIu64"%c",
                   stats->firstEightNonEmptyPacketDirections, delim,
                   stats->standardDeviationPayloadLength, delim,
                   stats->standardDeviationInterarrivalTime, delim);
    MD_CHECK_RET(buf, ret, brem);
    if (stats->nonEmptyPacketCount) {
        ret = snprintf(buf->cp, brem, "%"PRIu64"%c",
                       stats->dataByteCount/stats->nonEmptyPacketCount,
                       delim);
        MD_CHECK_RET(buf, ret, brem);
    } else {
        MD_APPEND_CHAR_CHECK(brem, buf, '0');
        MD_APPEND_CHAR_CHECK(brem, buf, delim);
    }

    if (rev) {
        ret = snprintf(buf->cp, brem, "%u%c%u%c%u%c%"PRIu64,
                       stats->reverseTcpUrgTotalCount, delim,
                       stats->reverseSmallPacketCount, delim,
                       stats->reverseNonEmptyPacketCount, delim,
                       stats->reverseDataByteCount);
        MD_CHECK_RET(buf, ret, brem);
        ret = snprintf(buf->cp, brem, "%c%"PRIu64"%c%d%c%d%c%d%c", delim,
                       stats->reverseAverageInterarrivalTime, delim,
                       stats->reverseFirstNonEmptyPacketSize, delim,
                       stats->reverseLargePacketCount, delim,
                       stats->reverseMaxPacketSize, delim);
        MD_CHECK_RET(buf, ret, brem);
        ret = snprintf(buf->cp, brem, "%d%c%"PRIu64"%c",
                       stats->reverseStandardDeviationPayloadLength,
                       delim,
                       stats->reverseStandardDeviationInterarrivalTime,
                       delim);
        MD_CHECK_RET(buf, ret, brem);
        if (stats->reverseNonEmptyPacketCount) {
            ret = snprintf(buf->cp, brem, "%"PRIu64,
                           stats->reverseDataByteCount / stats->reverseNonEmptyPacketCount);
        MD_CHECK_RET(buf, ret, brem);

        } else {
            MD_APPEND_CHAR_CHECK(brem, buf, '0');
        }
    } else {
        ret = snprintf(buf->cp, brem,"0%c0%c0%c0%c0%c0%c0%c0%c0%c0%c0%c0",
                       delim, delim, delim, delim, delim, delim, delim,
                       delim, delim, delim, delim);
        MD_CHECK_RET(buf, ret, brem);
    }

    MD_APPEND_CHAR_CHECK(brem, buf, '\n');


    if (exporter->multi_files) {
        FILE *fp = mdGetTableFile(exporter, 500);
        size_t rc;
        if (fp == NULL) {
            buf->cp = bufstart;
            return TRUE;
        }

        rc = md_util_write_buffer(fp, buf, exporter->name, &err);

        if (!rc) {
            g_warning("Error writing file for flowstats: %s",
                      err->message);
            g_clear_error(&err);
            return FALSE;
        }

        exporter->exp_bytes += rc;
    }

    return TRUE;
}

static gboolean mdJsonizeFlowStats(
    mdFlowExporter_t    *exporter,
    yfFlowStatsRecord_t *stats,
    char                *index_str,
    size_t               index_len,
    uint8_t              rev)
{
    mdBuf_t *buf = exporter->buf;
    size_t brem = MD_REM_MSG(buf);
    int ret;

    if (exporter->no_flow_stats) {
        return TRUE;
    }

    if (exporter->no_index) {
        if (!md_util_append_buffer(buf, &brem, (uint8_t*)index_str, index_len)) {
            return FALSE;
        }
    }

    ret = snprintf(buf->cp, brem, "\"tcpUrgTotalCount\":%u,",
                   stats->tcpUrgTotalCount);
    MD_CHECK_RET(buf, ret, brem);
    ret = snprintf(buf->cp, brem, "\"smallPacketCount\":%u,",
                   stats->smallPacketCount);
    MD_CHECK_RET(buf, ret, brem);
    ret = snprintf(buf->cp, brem, "\"nonEmptyPacketCount\":%u,",
                   stats->nonEmptyPacketCount);
    MD_CHECK_RET(buf, ret, brem);
    ret = snprintf(buf->cp, brem, "\"dataByteCount\":%"PRIu64",",
                   stats->dataByteCount);
    MD_CHECK_RET(buf, ret, brem);
    ret = snprintf(buf->cp, brem, "\"averageInterarrivalTime\":%"PRIu64",",
                   stats->averageInterarrivalTime);
    MD_CHECK_RET(buf, ret, brem);
    ret = snprintf(buf->cp, brem, "\"firstNonEmptyPacketSize\":%d,",
                   stats->firstNonEmptyPacketSize);
    MD_CHECK_RET(buf, ret, brem);
    ret = snprintf(buf->cp, brem, "\"largePacketCount\":%d,",
                   stats->largePacketCount);
    MD_CHECK_RET(buf, ret, brem);
    ret = snprintf(buf->cp, brem, "\"maxPacketSize\":%d,",
                   stats->maxPacketSize);
    MD_CHECK_RET(buf, ret, brem);
    ret = snprintf(buf->cp, brem, "\"firstEightNonEmptyPacketDirections\":\"%02x\",",
                   stats->firstEightNonEmptyPacketDirections);
    MD_CHECK_RET(buf, ret, brem);
    ret = snprintf(buf->cp, brem, "\"standardDeviationPayloadLength\":%u,",
                   stats->standardDeviationPayloadLength);
    MD_CHECK_RET(buf, ret, brem);
    ret = snprintf(buf->cp, brem, "\"standardDeviationInterarrivalTime\":%"PRIu64",",
                   stats->standardDeviationInterarrivalTime);
    MD_CHECK_RET(buf, ret, brem);

    if (stats->nonEmptyPacketCount) {
        ret = snprintf(buf->cp, brem, "\"bytesPerPacket\":%"PRIu64",",
                       stats->dataByteCount/stats->nonEmptyPacketCount);
        MD_CHECK_RET(buf, ret, brem);
    }

    if (rev) {
        ret = snprintf(buf->cp, brem, "\"reverseTcpUrgTotalCount\":%u,",
                       stats->reverseTcpUrgTotalCount);
        MD_CHECK_RET(buf, ret, brem);
        ret = snprintf(buf->cp, brem, "\"reverseSmallPacketCount\":%u,",
                       stats->reverseSmallPacketCount);
        MD_CHECK_RET(buf, ret, brem);
        ret = snprintf(buf->cp, brem, "\"reverseNonEmptyPacketCount\":%u,",
                       stats->reverseNonEmptyPacketCount);
        MD_CHECK_RET(buf, ret, brem);
        ret = snprintf(buf->cp, brem, "\"reverseDataByteCount\":%"PRIu64",",
                       stats->reverseDataByteCount);
        MD_CHECK_RET(buf, ret, brem);
        ret = snprintf(buf->cp, brem, "\"reverseAverageInterarrivalTime\":%"PRIu64",",
                       stats->reverseAverageInterarrivalTime);
        MD_CHECK_RET(buf, ret, brem);
        ret = snprintf(buf->cp, brem, "\"reverseFirstNonEmptyPacketSize\":%d,",
                       stats->reverseFirstNonEmptyPacketSize);
        MD_CHECK_RET(buf, ret, brem);
        ret = snprintf(buf->cp, brem, "\"reverseLargePacketCount\":%d,",
                       stats->reverseLargePacketCount);
        MD_CHECK_RET(buf, ret, brem);
        ret = snprintf(buf->cp, brem, "\"reverseMaxPacketSize\":%d,",
                       stats->reverseMaxPacketSize);
        MD_CHECK_RET(buf, ret, brem);
        ret = snprintf(buf->cp, brem, "\"reverseStandardDeviationPayloadLength\":%u,",
                       stats->reverseStandardDeviationPayloadLength);
        MD_CHECK_RET(buf, ret, brem);
        ret = snprintf(buf->cp, brem,
                "\"reverseStandardDeviationInterarrivalTime\":%"PRIu64",",
                stats->reverseStandardDeviationInterarrivalTime);
        MD_CHECK_RET(buf, ret, brem);

        if (stats->reverseNonEmptyPacketCount) {
            ret = snprintf(buf->cp, brem, "\"reverseBytesPerPacket\":%"PRIu64",",
                    stats->reverseDataByteCount/
                    stats->reverseNonEmptyPacketCount);
            MD_CHECK_RET(buf, ret, brem);
        }
    }
    return TRUE;
}

/**
 * mdExportBLMultiFiles
 *
 */

gboolean mdExportBLMultiFiles(
    mdFlowExporter_t *exporter,
    fbBasicList_t    *bl,
    char             *index_str,
    size_t           index_len,
    char             *label,
    gboolean         hex)
{
    uint16_t                elem_id;
    char                    delim = exporter->dpi_delimiter;
    GString                 *tstr = NULL;
    mdBuf_t                 *mdbuf = exporter->buf;
    GError                  *err;

    if (bl->infoElement == NULL) {
        /* this item must not be included in infoModel. */
        return TRUE;
    }

    elem_id = bl->infoElement->num;

    if (table_hash) {
        label = mdGetTableItem(elem_id);
        if (label == NULL) {
            return TRUE;
        }
    }

    tstr = g_string_new("");

    g_string_append_len(tstr, index_str, index_len);
    g_string_append_printf(tstr, "%d%c", elem_id, delim);

    if (exporter->dedup_per_flow) {
        if (!md_dedup_basic_list(bl, mdbuf, tstr, delim, hex, exporter->escape_chars)) {
            g_string_free(tstr, TRUE);
            return FALSE;
        }
    } else {
        if (!mdPrintBasicList(mdbuf, tstr, bl, delim, hex, exporter->escape_chars)) {
            g_string_free(tstr, TRUE);
            return FALSE;
        }
    }

    g_string_free(tstr, TRUE);

    if (MD_MSG_LEN(mdbuf)) {
        FILE *fp = mdGetTableFile(exporter, elem_id);
        size_t rc;
        if (fp == NULL) {
            g_debug("%s: Error retrieving file for id %d", exporter->name,
                    elem_id);
            return FALSE;
        }

        rc = md_util_write_buffer(fp, mdbuf, exporter->name, &err);

        if (!rc) {
            g_warning("Error writing file for id %d: %s",
                      elem_id, err->message);
            g_clear_error(&err);
            return FALSE;
        }

        exporter->exp_bytes += rc;
    }

    return TRUE;
}



/**
 * mdExportBLCustomList
 *
 *
 */
gboolean mdExportBLCustomList(
    mdFlowExporter_t *exporter,
    fbBasicList_t    *bl,
    char             *index_str,
    size_t           index_len,
    char             *label,
    gboolean         hex)
{
    uint16_t                elem_id;
    char                    delim = exporter->dpi_delimiter;
    GString                 *tstr = NULL;
    mdBuf_t                 *mdbuf = exporter->buf;

    if (bl->infoElement == NULL) {
        /* InfoElement must be in infoModel */
        return TRUE;
    }

    elem_id = bl->infoElement->num;

    if (exporter->dpi_field_table) {
        if (!mdGetDPIItem(exporter->dpi_field_table, elem_id)) {
            return TRUE;
        }
    }

    tstr = g_string_new("");

    g_string_append_len(tstr, index_str, index_len);

    g_string_append_printf(tstr, "%d%c", elem_id, delim);

    if (exporter->dedup_per_flow) {
        if (!md_dedup_basic_list(bl, mdbuf, tstr, delim, hex, exporter->escape_chars)) {
            g_string_free(tstr, TRUE);
            return FALSE;
        }
    } else {
        if (!mdPrintBasicList(mdbuf, tstr, bl, delim, hex, exporter->escape_chars)) {
            g_string_free(tstr, TRUE);
            return FALSE;
        }
    }

    g_string_free(tstr, TRUE);
    return TRUE;
}




/**
 * mdExportBL
 *
 *
 *
 */
gboolean mdExportBL(
    mdFlowExporter_t *exporter,
    fbBasicList_t    *bl,
    char            *index_str,
    size_t           index_len,
    char             *label,
    gboolean         hex)
{
    uint16_t                elem_id;
    char                    delim = exporter->dpi_delimiter;
    mdBuf_t                 *mdbuf = exporter->buf;
    GString                 *tstr = NULL;

    if (bl->infoElement == NULL) {
        /* InfoElement must be in infoModel */
        return TRUE;
    }

    elem_id = bl->infoElement->num;

    if (exporter->dpi_field_table) {
        if (!mdGetDPIItem(exporter->dpi_field_table, elem_id)) {
            return TRUE;
        }
    }

    tstr = g_string_new("");

    if (index_len) {
        if (!exporter->no_index) {
            /* print label */
            g_string_append_printf(tstr, "%s%c", label, delim);
        }
        g_string_append_len(tstr, index_str, index_len);
        g_string_append_printf(tstr, "%d%c", elem_id, delim);
    } else {
        g_string_append_printf(tstr, "%s%c%d%c", label, delim, elem_id, delim);
    }

    if (exporter->dedup_per_flow) {
        if (!md_dedup_basic_list(bl, mdbuf, tstr, delim, hex, exporter->escape_chars)) {
            g_string_free(tstr, TRUE);
            return FALSE;
        }
    } else {
        if (!mdPrintBasicList(mdbuf, tstr, bl, delim, hex, exporter->escape_chars)) {
            g_string_free(tstr, TRUE);
            return FALSE;
        }
    }

    g_string_free(tstr, TRUE);
    return TRUE;
}

/**
 * mdJsonizeBLElement
 *
 */
gboolean mdJsonizeBLElement(
    mdFlowExporter_t    *exporter,
    fbBasicList_t       *bl,
    char                *index_str,
    size_t              index_len,
    char                *label,
    gboolean            hex)
{

    uint16_t                elem_id;
    const fbInfoElement_t   *ie = NULL;
    uint16_t                w = 0;
    fbVarfield_t            *var = NULL;
    char                    hexdump[65534];
    size_t                  hexlen = sizeof(hexdump);
    size_t                  buflen;
    GString                 *tstr = NULL;
    mdBuf_t                 *mdbuf = exporter->buf;
    char                    *bufstart = mdbuf->cp;
    char                    *blstart;
    size_t                  brem = MD_REM_MSG(mdbuf);
    int                     ret;

    if (bl->infoElement == NULL) {
        return TRUE;
    }

    /* Get the IE name from fixbuf */

    elem_id = bl->infoElement->num;
    ie = fbInfoModelGetElementByID(mdInfoModel(), elem_id, CERT_PEN);

    if (exporter->dpi_field_table) {
        if (!mdGetDPIItem(exporter->dpi_field_table, elem_id)) {
            return TRUE;
        }
    }

    if (exporter->dedup_per_flow) {
        tstr = md_dedup_basic_list_no_count(bl, ',', TRUE, hex,
                                            exporter->escape_chars);
        if (tstr) {
            ret = snprintf(mdbuf->cp, brem, "\"%s\":[%s],", ie->ref.name,
                           tstr->str);
            if ((ret < 0) || ((size_t)ret >= brem)) {
                g_string_free(tstr, TRUE);
                return FALSE;
            }
            mdbuf->cp += ret;
            brem -= ret;
            g_string_free(tstr, TRUE);
        }
    } else {
        ret = snprintf(mdbuf->cp, brem, "\"%s\":[\"", ie->ref.name);
        MD_CHECK_RET(mdbuf, ret, brem);
        blstart = mdbuf->cp;
        for (w = 0;
             (var = (fbVarfield_t *)fbBasicListGetIndexedDataPtr(bl, w));
             w++) {

            if (hex) {
                buflen = var->len;
                if (buflen > sizeof(hexdump)) {
                    buflen = sizeof(hexdump);
                }
                ret = md_util_hexdump_append(hexdump, &hexlen,
                                             var->buf, buflen);
                if (!ret) return FALSE;
                if (!md_util_append_buffer(mdbuf, &brem, (uint8_t*)hexdump, ret)) {
                    return FALSE;
                }
            } else {
                if (!mdJsonifyEscapeChars(mdbuf, &brem, var->buf, var->len)) {
                    return FALSE;
                }
            }
            ret = snprintf(mdbuf->cp, brem, "\", \"");
            MD_CHECK_RET(mdbuf, ret, brem);
        }

        if (mdbuf->cp > blstart) {
            mdbuf->cp -= 3;
            brem += 3;
            if (brem > 2) {
                MD_APPEND_CHAR(mdbuf, ']');
                MD_APPEND_CHAR(mdbuf, ',');
            } else {
                return FALSE;
            }
        } else {
            mdbuf->cp = bufstart;
        }
    }

    return TRUE;
}

/**
 * mdJsonizeVLElement
 *
 */
gboolean mdJsonizeVLElement(
    mdFlowExporter_t    *exporter,
    uint8_t             *buf,
    char                *label,
    char                *index_str,
    size_t              index_len,
    uint16_t            id,
    size_t              buflen,
    gboolean            hex)
{

    const fbInfoElement_t *ie = NULL;
    mdBuf_t           *mdbuf = exporter->buf;
    size_t            brem = MD_REM_MSG(mdbuf);
    int               ret;
    char              hexdump[65534];
    size_t            hexlen = sizeof(hexdump);

    if (exporter->dpi_field_table) {
        if (!mdGetDPIItem(exporter->dpi_field_table, id)) {
            return TRUE;
        }
    }

    /* Get the IE name from fixbuf */

    ie = fbInfoModelGetElementByID(mdInfoModel(), id, CERT_PEN);

    if (ie->type != 0 && ie->type < 11) {
        /* use fixbuf 1.4 to get type information, and if integer,
         * don't quote the value: (0 is octet array, 1-10 are integers, floats) */
        ret = snprintf(mdbuf->cp, brem, "\"%s\":", ie->ref.name);
        MD_CHECK_RET(mdbuf, ret, brem);

        if (!mdPrintVariableLength(mdbuf, &brem, buf, buflen, '"', hex,
                                   exporter->escape_chars))
        {
            return FALSE;
        }


    } else {
        /* quote because it's an octet array, string, or other */

        ret = snprintf(mdbuf->cp, brem, "\"%s\":\"", ie->ref.name);
        MD_CHECK_RET(mdbuf, ret, brem);
        if (hex) {
            ret = md_util_hexdump_append(hexdump, &hexlen, buf, buflen);
            if (!md_util_append_buffer(mdbuf, &brem, (uint8_t*)hexdump, ret)) {
                return FALSE;
            }
        } else {
            mdJsonifyEscapeChars(mdbuf, &brem, buf, buflen);
        }
        MD_APPEND_CHAR_CHECK(brem, mdbuf, '\"');
    }

    MD_APPEND_CHAR_CHECK(brem, mdbuf, ',');

    return TRUE;
}

/**
 * mdExporterDPIGetIndexStr
 *
 *
 */
gboolean mdExporterDPIGetIndexStr(
    mdFlowExporter_t *exporter,
    mdFullFlow_t     *flow)
{
    char             delim = exporter->dpi_delimiter;
    int              ret;
    mdBuf_t          *buf = exporter->buf;
    size_t            brem = MD_REM_MSG(buf);

    if (flow->app_tid == 0 && !flow->p0f && !flow->dhcpfp && !flow->stats) {
        return FALSE;
    }

    /* this prints the index record for this flow */
    if (exporter->dpionly) {
        if (exporter->no_index) {
            /* if this fails - it will fail in the DPI Flow Print and realloc*/
            mdDPIExtendedIndex(exporter, flow);
        } else {
            ret = snprintf(buf->cp, brem, "%u%c%"PRIu64"%c%u%c",
                           md_util_flow_key_hash(flow->rec), delim,
                           flow->rec->flowStartMilliseconds, delim,
                           flow->rec->obsid, delim);
            MD_CHECK_RET(buf, ret, brem);
        }
    }

    return TRUE;
}



int mdExporterSSLCertHash(
    mdFlowExporter_t    *exporter,
    fbVarfield_t        *ct,
    char                *index_str,
    size_t              index_len,
    int                 cert_no)
{
#if HAVE_OPENSSL
    mdBuf_t *buf = exporter->buf;
    size_t brem = MD_REM_MSG(buf);
    char ssl_buffer[4096];
    char delim = exporter->dpi_delimiter;
    size_t bufsz = sizeof(ssl_buffer);
    int i, ret;
    unsigned char md5[MD5_DIGEST_LENGTH];
    unsigned char sha1[SHA_DIGEST_LENGTH];

    if (exporter->json) {
        /* remove '},' */
        buf->cp -= 2;
        brem += 2;
        if (exporter->md5_hash || mdExporterCheckSSLConfig(exporter, 299, 3)) {
            md_ssl_md5_hash(md5, ct->buf, ct->len);
            ret = snprintf(buf->cp, brem, ",\"sslCertificateMD5\":\"");
            MD_CHECK_RET(buf, ret, brem);
            ret = md_util_hexdump_append_nospace(buf->cp, &brem,
                                                 md5, MD5_DIGEST_LENGTH);
            if (!ret) {
                return 0;
            }
            buf->cp += ret;
            MD_APPEND_CHAR_CHECK(brem, buf, '"');
        }
        if (exporter->sha1_hash || mdExporterCheckSSLConfig(exporter, 298, 3)) {
            md_ssl_sha1_hash(sha1, ct->buf, ct->len);
            ret = snprintf(buf->cp, brem, ",\"sslCertificateSHA1\":\"");
            MD_CHECK_RET(buf, ret, brem);
            ret = md_util_hexdump_append_nospace(buf->cp, &brem,
                                                 sha1, SHA_DIGEST_LENGTH);
            if (!ret) {
                return 0;
            }
            buf->cp += ret;
            MD_APPEND_CHAR_CHECK(brem, buf, '"');
        }

        MD_APPEND_CHAR_CHECK(brem, buf, '}');
        MD_APPEND_CHAR_CHECK(brem, buf, ',');

    } else {
        if (exporter->md5_hash || mdExporterCheckSSLConfig(exporter, 299, 3)) {
            md_ssl_md5_hash(md5, ct->buf, ct->len);
            i = snprintf(ssl_buffer, bufsz, "I%c%d%c", delim, cert_no, delim);
            bufsz -= i;
            i += md_util_hexdump_append(ssl_buffer + i, &bufsz, md5,
                                        MD5_DIGEST_LENGTH);
            exporter->VLprint_fn(exporter, (uint8_t *)ssl_buffer,
                                 SSL_DEFAULT, index_str, index_len, 299,
                                 i, FALSE);
        }
        bufsz = sizeof(ssl_buffer);
        if (exporter->sha1_hash || mdExporterCheckSSLConfig(exporter, 298, 3)) {
            md_ssl_sha1_hash(sha1, ct->buf, ct->len);
            i = snprintf(ssl_buffer, bufsz, "I%c%d%c", delim, cert_no, delim);
            bufsz -= i;
            i += md_util_hexdump_append(ssl_buffer + i, &bufsz, sha1,
                                        SHA_DIGEST_LENGTH);
            exporter->VLprint_fn(exporter, (uint8_t *)ssl_buffer,
                                 SSL_DEFAULT, index_str, index_len, 298,
                                 i, FALSE);
        }
    }

#endif

    return 1;

}

/**
 * mdExporterSSLBase64Encode
 *
 */
gboolean mdExporterSSLBase64Encode(
    mdFlowExporter_t    *exporter,
    fbVarfield_t        *ct,
    char                *index_str,
    size_t              index_len,
    int                 cert_no)
{
    char delim = exporter->dpi_delimiter;
    char ssl_buffer[4096];
    int ret;
    gchar *base1 = NULL;
    size_t bufsz = sizeof(ssl_buffer);

    ret = snprintf(ssl_buffer, bufsz, "I%c%d%c", delim, cert_no, delim);
    bufsz -= ret;

    base1 = g_base64_encode((const guchar *)ct->buf, ct->len);

    if (strlen(base1) < bufsz) {
        memcpy(ssl_buffer + ret, base1, strlen(base1));
        bufsz = strlen(base1) + ret;
    } else {
        g_free(base1);
        return TRUE;
    }

    exporter->VLprint_fn(exporter, (uint8_t *)ssl_buffer,
                         SSL_DEFAULT, index_str, index_len, 296,
                         bufsz, FALSE);
    if (base1) {
        g_free(base1);
    }

    return TRUE;
}

/**
 * mdExporterDPIFlowPrint
 *
 * writes all the DPI data to the given FILE.
 *
 */
int mdExporterDPIFlowPrint(
    mdFlowExporter_t   *exporter,
    mdFullFlow_t       *flow,
    char               *index_str,
    size_t             index_len,
    GError             **err)
{

    mdBuf_t            *buf = exporter->buf;
    char               *bufstart = buf->cp;
    gboolean           rev = FALSE;
    int                loop;
    size_t             rc;
    char               delim = exporter->dpi_delimiter;
    fbBasicList_t      *bl = NULL;
    int                ret;
    size_t             brem = MD_REM_MSG(buf);
    gboolean           rv = TRUE;

    if (flow->rec->reversePacketTotalCount) {
        rev = TRUE;
    }

    if (exporter->json) {
        /* since index_str is technically already in the buffer, just move up
           buf->cp index_len */
        buf->cp += index_len;
        bufstart = buf->cp;
    }

    if (flow->p0f) {
        rv = exporter->VLprint_fn(exporter,  flow->p0f->osName.buf, P0F_DEFAULT,
                             index_str, index_len, 36, flow->p0f->osName.len,
                             FALSE);
        MD_RET0(rv);
        rv = exporter->VLprint_fn(exporter,  flow->p0f->osVersion.buf,
                             P0F_DEFAULT, index_str, index_len, 37,
                             flow->p0f->osVersion.len, FALSE);
        MD_RET0(rv);
        rv = exporter->VLprint_fn(exporter,  flow->p0f->osFingerPrint.buf,
                                  P0F_DEFAULT, index_str, index_len, 107,
                                  flow->p0f->osFingerPrint.len, FALSE);
        MD_RET0(rv);
        if (rev) {
            rv = exporter->VLprint_fn(exporter,  flow->p0f->reverseOsName.buf,
                                      P0F_DEFAULT, index_str, index_len,
                                      36|FB_IE_VENDOR_BIT_REVERSE,
                                      flow->p0f->reverseOsName.len, FALSE);
            MD_RET0(rv);
            rv = exporter->VLprint_fn(exporter, flow->p0f->reverseOsVersion.buf,
                                 P0F_DEFAULT, index_str, index_len,
                                 37|FB_IE_VENDOR_BIT_REVERSE,
                                 flow->p0f->reverseOsVersion.len, FALSE);
            MD_RET0(rv);
            rv = exporter->VLprint_fn(exporter,
                                 flow->p0f->reverseOsFingerPrint.buf,
                                 P0F_DEFAULT, index_str, index_len,
                                 107|FB_IE_VENDOR_BIT_REVERSE,
                                 flow->p0f->reverseOsFingerPrint.len, FALSE);
            MD_RET0(rv);
        }
    }

    switch (flow->app_tid & YTF_BIF) {
      case YAF_HTTP_FLOW_TID:
        bl = (fbBasicList_t *)flow->app;
        for (loop = 0; loop < flow->app_elements; loop++) {
            rv = exporter->BLprint_fn(exporter, bl, index_str, index_len,
                                      HTTP_DEFAULT, FALSE);
            MD_RET0(rv);
            bl++;
        }
        break;

      case YAF_POP3_FLOW_TID:
        rv = exporter->BLprint_fn(exporter, (fbBasicList_t *)flow->app,
                                  index_str, index_len, POP3_DEFAULT, FALSE);
        MD_RET0(rv);
        break;
      case YAF_IRC_FLOW_TID:
        rv = exporter->BLprint_fn(exporter, (fbBasicList_t *)flow->app,
                                  index_str, index_len, IRC_DEFAULT, FALSE);
        MD_RET0(rv);
        break;
      case YAF_TFTP_FLOW_TID:
        {
            yfTFTPFlow_t *tftp = (yfTFTPFlow_t *)flow->app;
            rv = exporter->VLprint_fn(exporter,  tftp->tftpMode.buf,
                                 TFTP_DEFAULT, index_str, index_len, 127,
                                 tftp->tftpMode.len, FALSE);
            MD_RET0(rv);
            rv = exporter->VLprint_fn(exporter,  tftp->tftpFilename.buf,
                                 TFTP_DEFAULT, index_str, index_len, 126,
                                 tftp->tftpFilename.len, FALSE);
            MD_RET0(rv);
            break;
        }
      case YAF_SLP_FLOW_TID:
        {
            yfSLPFlow_t *slp = (yfSLPFlow_t *)flow->app;
            char slp_buffer[20];

            snprintf(slp_buffer, sizeof(slp_buffer), "%d", slp->slpVersion);
            rv = exporter->VLprint_fn(exporter, (uint8_t *)slp_buffer,
                                      SLP_DEFAULT, index_str, index_len, 128,
                                      strlen(slp_buffer), FALSE);
            MD_RET0(rv);
            snprintf(slp_buffer, sizeof(slp_buffer), "%d", slp->slpMessageType);
            rv = exporter->VLprint_fn(exporter, (uint8_t *)slp_buffer,
                                      SLP_DEFAULT, index_str, index_len, 129,
                                      strlen(slp_buffer), FALSE);
            MD_RET0(rv);
            rv = exporter->BLprint_fn(exporter, (fbBasicList_t *)flow->app,
                                      index_str, index_len, SLP_DEFAULT, FALSE);
            MD_RET0(rv);
            break;
        }
      case YAF_FTP_FLOW_TID:
        bl = (fbBasicList_t *)flow->app;
        for (loop = 0; loop < flow->app_elements; loop++) {
            rv = exporter->BLprint_fn(exporter, bl, index_str, index_len,
                                      FTP_DEFAULT, 0);
            MD_RET0(rv);
            bl++;
        }
        break;
      case YAF_IMAP_FLOW_TID:
        bl = (fbBasicList_t *)flow->app;
        for (loop = 0; loop < flow->app_elements; loop++) {
            rv = exporter->BLprint_fn(exporter, bl, index_str,
                                      index_len, IMAP_DEFAULT,0);
            MD_RET0(rv);
            bl++;
        }
        break;
      case YAF_SIP_FLOW_TID:
        bl = (fbBasicList_t *)flow->app;
        for (loop = 0; loop < flow->app_elements; loop++) {
            rv = exporter->BLprint_fn(exporter, bl, index_str,
                                      index_len, SIP_DEFAULT, 0);
            MD_RET0(rv);
            bl++;
        }
        break;
      case YAF_SMTP_FLOW_TID:
        bl = (fbBasicList_t *)flow->app;
        for (loop = 0; loop < flow->app_elements; loop++) {
            rv = exporter->BLprint_fn(exporter, bl, index_str,
                                      index_len, SMTP_DEFAULT,0);
            MD_RET0(rv);
            bl++;
        }
        break;
      case YAF_SSH_FLOW_TID:
        bl = (fbBasicList_t *)flow->app;
        for (loop = 0; loop < flow->app_elements; loop++) {
            rv=exporter->BLprint_fn(exporter, bl, index_str, index_len, SSH_DEFAULT, 0);
            MD_RET0(rv);
            bl++;
        }
        break;
      case YAF_NNTP_FLOW_TID:
        bl = (fbBasicList_t *)flow->app;
        for (loop = 0; loop < flow->app_elements; loop++) {
            rv = exporter->BLprint_fn(exporter, bl, index_str,
                                      index_len, NNTP_DEFAULT,0);
            bl++;
        }
        break;
      case SM_INTSSL_FLOW_TID:
        {
            yfNewSSLFlow_t *sslflow = (yfNewSSLFlow_t *)flow->app;
            if (exporter->json) {
                if (!mdJsonifyNewSSLRecord(exporter, sslflow, FALSE,
                                           exporter->escape_chars)) {
                    return 0;
                }
            } else {
                if (!mdExporterTextNewSSLPrint(exporter, sslflow, index_str,
                                               index_len)) {
                    return 0;
                }
            }
            break;
        }
      case YAF_SSL_FLOW_TID:
        {
            yfSSLFlow_t *sslflow = (yfSSLFlow_t *)flow->app;
            yfSSLCertFlow_t *cert = NULL;

            char ssl_buffer[20];

            if (flow->cert == NULL) {
                break;
            }

            if (sslflow->sslServerCipher) {
                snprintf(ssl_buffer, sizeof(ssl_buffer), "%d", sslflow->sslServerCipher);
                rv = exporter->VLprint_fn(exporter,  (uint8_t *)ssl_buffer,
                               SSL_DEFAULT,index_str, index_len, 187, strlen(ssl_buffer),
                               FALSE);
                MD_RET0(rv);
            }

            if (sslflow->sslCompressionMethod) {
                snprintf(ssl_buffer, sizeof(ssl_buffer), "%d", sslflow->sslCompressionMethod);
                rv = exporter->VLprint_fn(exporter,  (uint8_t *)ssl_buffer,
                               SSL_DEFAULT,index_str, index_len, 188, strlen(ssl_buffer),
                               FALSE);
                MD_RET0(rv);
            }

            if (sslflow->sslClientVersion) {
                snprintf(ssl_buffer, sizeof(ssl_buffer), "%d", sslflow->sslClientVersion);
                rv = exporter->VLprint_fn(exporter,  (uint8_t *)ssl_buffer,
                               SSL_DEFAULT,index_str, index_len, 186, strlen(ssl_buffer),
                               FALSE);
                MD_RET0(rv);
            }

            while ((cert = fbSubTemplateMultiListEntryNextDataPtr(flow->cert,
                                                                  cert)))
            {

                /*                g_string_append_printf(str, "SSL Cert:");
                if (cert->sslSignature.len) {
                    g_string_append_printf(str, "0x");
                }
                for (w = 0; w < cert->sslSignature.len; w++) {
                    g_string_append_printf(str, "%02x",
                                           *(cert->sslSignature.buf + w));
                }
                g_string_append_printf(str, "%c", delim);*/
                rv = exporter->VLprint_fn(exporter,  cert->sslICountryName.buf,
                                     SSL_DEFAULT, index_str, index_len, 191,
                                     cert->sslICountryName.len, FALSE);
                MD_RET0(rv);
                rv = exporter->VLprint_fn(exporter,  cert->sslIOrgName.buf,
                                     SSL_DEFAULT, index_str, index_len, 192,
                                     cert->sslIOrgName.len, FALSE);
                MD_RET0(rv);
                rv = exporter->VLprint_fn(exporter,  cert->sslIOrgUnitName.buf,
                                     SSL_DEFAULT, index_str, index_len, 193,
                                     cert->sslIOrgUnitName.len, FALSE);
                MD_RET0(rv);
                rv = exporter->VLprint_fn(exporter,  cert->sslIZipCode.buf,
                                     SSL_DEFAULT, index_str, index_len, 194,
                                     cert->sslIZipCode.len, FALSE);
                MD_RET0(rv);
                rv = exporter->VLprint_fn(exporter,  cert->sslIState.buf,
                                     SSL_DEFAULT, index_str, index_len, 195,
                                     cert->sslIState.len, FALSE);
                MD_RET0(rv);
                rv = exporter->VLprint_fn(exporter,  cert->sslICommonName.buf,
                                     SSL_DEFAULT, index_str, index_len, 196,
                                     cert->sslICommonName.len, FALSE);
                MD_RET0(rv);
                rv = exporter->VLprint_fn(exporter,  cert->sslILocalityName.buf,
                                     SSL_DEFAULT, index_str, index_len, 197,
                                     cert->sslILocalityName.len, FALSE);
                MD_RET0(rv);
                rv = exporter->VLprint_fn(exporter, cert->sslIStreetAddress.buf,
                                     SSL_DEFAULT, index_str, index_len, 198,
                                     cert->sslIStreetAddress.len, FALSE);
                MD_RET0(rv);
                rv = exporter->VLprint_fn(exporter,  cert->sslSCountryName.buf,
                                     SSL_DEFAULT, index_str, index_len, 200,
                                     cert->sslSCountryName.len, FALSE);
                MD_RET0(rv);
                rv = exporter->VLprint_fn(exporter,  cert->sslSOrgName.buf,
                                     SSL_DEFAULT, index_str, index_len, 201,
                                     cert->sslSOrgName.len, FALSE);
                MD_RET0(rv);
                rv = exporter->VLprint_fn(exporter,  cert->sslSOrgUnitName.buf,
                                     SSL_DEFAULT, index_str, index_len, 202,
                                     cert->sslSOrgUnitName.len, FALSE);
                MD_RET0(rv);
                rv = exporter->VLprint_fn(exporter,  cert->sslSZipCode.buf,
                                     SSL_DEFAULT, index_str, index_len, 203,
                                     cert->sslSZipCode.len, FALSE);
                MD_RET0(rv);
                rv = exporter->VLprint_fn(exporter,  cert->sslSState.buf,
                                     SSL_DEFAULT, index_str, index_len, 204,
                                     cert->sslSState.len, FALSE);
                MD_RET0(rv);
                rv = exporter->VLprint_fn(exporter,  cert->sslSCommonName.buf,
                                     SSL_DEFAULT, index_str, index_len, 205,
                                     cert->sslSCommonName.len, FALSE);
                MD_RET0(rv);
                rv = exporter->VLprint_fn(exporter,  cert->sslSLocalityName.buf,
                                     SSL_DEFAULT, index_str, index_len, 206,
                                     cert->sslSLocalityName.len, FALSE);
                MD_RET0(rv);
                rv = exporter->VLprint_fn(exporter, cert->sslSStreetAddress.buf,
                                     SSL_DEFAULT, index_str, index_len, 207,
                                     cert->sslSStreetAddress.len, FALSE);
                MD_RET0(rv);
            }

            break;
        }
      case YAF_MYSQL_FLOW_TID:
        {
            yfMySQLFlow_t *mflow = (yfMySQLFlow_t *)flow->app;
            yfMySQLTxtFlow_t *mtxt = NULL;
            rv = exporter->VLprint_fn(exporter,  mflow->mysqlUsername.buf,
                                 MYSQL_DEFAULT, index_str, index_len, 223,
                                 mflow->mysqlUsername.len, FALSE);
            MD_RET0(rv);
            while ((mtxt = (yfMySQLTxtFlow_t *)FBSTLNEXT(&(mflow->mysqlList),
                                                         mtxt)))
            {
                rv = exporter->VLprint_fn(exporter,  mtxt->mysqlCommandText.buf,
                                     MYSQL_DEFAULT, index_str, index_len, 225,
                                     mtxt->mysqlCommandText.len, FALSE);
                MD_RET0(rv);
            }
            break;
        }
      case YAF_DNS_FLOW_TID:
        {
            yfDNSFlow_t *dnsflow = (yfDNSFlow_t *)flow->app;
            yfDNSQRFlow_t *dnsqrflow = NULL;
            char *label = DNS_DEFAULT;
            size_t buftest = 0;
            uint16_t uid;

            if (exporter->json) {
                ret = snprintf(buf->cp, brem, "\"dnsRecord\":[");
                MD_CHECK_RET(buf, ret, brem);
                buftest = MD_REM_MSG(buf);
            }

            while((dnsqrflow =(yfDNSQRFlow_t *)FBSTLNEXT(&(dnsflow->dnsQRList),
                                                         dnsqrflow)))
            {
                uid = dnsqrflow->dnsQRType > 51 ? 53 : dnsqrflow->dnsQRType;

                if (exporter->dns_resp_only) {
                    if (dnsqrflow->dnsQueryResponse == 0) continue;
                }

                if (exporter->dpi_field_table) {
                    if (!mdGetDPIItem(exporter->dpi_field_table,uid)) {
                        continue;
                    }
                }
                if (exporter->json) {

                    MD_APPEND_CHAR_CHECK(brem, buf, '{');
                    if (!mdJsonifyDNSRecord(dnsqrflow, buf)) {
                        return FALSE;
                    }
                    brem = MD_REM_MSG(buf);
                    MD_APPEND_CHAR_CHECK(brem, buf, '}');
                    MD_APPEND_CHAR_CHECK(brem, buf, ',');

                } else if (exporter->multi_files) {
                    FILE *fp = NULL;
                    if (table_hash) {
                        label = mdGetTableItem(uid);
                        if (label == NULL) {
                            continue;
                        }
                    }

                    if (!md_util_append_buffer(buf, &brem, (uint8_t*)index_str, index_len)) {
                        return 0;
                    }

                    if (!mdExporterTextDNSPrint(exporter, dnsqrflow)) {
                        return 0;
                    }

                    fp = mdGetTableFile(exporter, uid);
                    if (fp == NULL) {
                        g_warning("Error: File does not exist for DNS "
                                "Type: %d", dnsqrflow->dnsQRType);
                        continue;
                    }

                    rc = md_util_write_buffer(fp, buf, exporter->name, err);
                    if (!rc) {
                        return -1;
                    }
                    exporter->exp_bytes += rc;
                } else {
                    if (exporter->custom_list_dpi) {
                        if (!md_util_append_buffer(buf, &brem, (uint8_t*)index_str, index_len)) {
                            return 0;
                        }
                    } else {
                        if (!exporter->no_index) {
                            ret = snprintf(buf->cp, brem, "%s%c", label, delim);
                            MD_CHECK_RET(buf, ret, brem);
                        }
                        if (index_str) {
                            if (!md_util_append_buffer(buf, &brem, (uint8_t*)index_str, index_len)) {
                                return 0;
                            }
                        }
                    }
                    if (!mdExporterTextDNSPrint(exporter, dnsqrflow)) {
                        return 0;
                    }
                }
            } /* record loop */

            if (exporter->json) {
                brem = MD_REM_MSG(buf);
                if (buftest == brem) {
                    buf->cp -= 13;
                    brem += 13;
                } else {
                    buf->cp -= 1;
                    brem += 1;
                    MD_APPEND_CHAR_CHECK(brem, buf, ']');
                    MD_APPEND_CHAR_CHECK(brem, buf, ',');
                }
            }

        } /* dns */
        break;
      case YAF_RTSP_FLOW_TID:
        bl = (fbBasicList_t *)flow->app;
        for (loop = 0; loop < flow->app_elements; loop++) {
            rv = exporter->BLprint_fn(exporter, bl,  index_str, index_len, RTSP_DEFAULT,0);
            MD_RET0(rv);
            bl++;
        }
        break;
      case YAF_RTP_FLOW_TID:
        {
            yfRTPFlow_t *rtp = (yfRTPFlow_t *)flow->app;
            char  rtp_buffer[20];

            if (rtp) {
                snprintf(rtp_buffer, sizeof(rtp_buffer), "%d",
                         rtp->rtpPayloadType);
                rv = exporter->VLprint_fn(exporter,  (uint8_t *)rtp_buffer,
                                          RTP_DEFAULT, index_str, index_len, 287,
                                          strlen(rtp_buffer), FALSE);
                MD_RET0(rv);
                if (rtp->reverseRtpPayloadType) {
                    snprintf(rtp_buffer, sizeof(rtp_buffer), "%d",
                             rtp->reverseRtpPayloadType);
                    rv = exporter->VLprint_fn(exporter,  (uint8_t *)rtp_buffer,
                                              RTP_DEFAULT, index_str, index_len, 287,
                                              strlen(rtp_buffer), FALSE);
                    MD_RET0(rv);
                }
            }
        }
        break;
      case YAF_DNP3_FLOW_TID:
        {
            yfDNP3Flow_t *dnp = (yfDNP3Flow_t *)flow->app;
            yfDNP3Rec_t *rec = NULL;
            char dnp_buffer[65535];
            size_t buflen;
            size_t bufsz;
            int i;

            if (dnp) {
                while ((rec = (yfDNP3Rec_t *)FBSTLNEXT(&(dnp->dnp_list), rec)))
                {
                    i = 0;
                    bufsz = sizeof(dnp_buffer);
                    if (!exporter->json) {
                        i = snprintf(dnp_buffer, bufsz, "%d%c%d%c%d%c",
                                     rec->src_address,
                                     delim, rec->dst_address, delim, rec->function,
                                     delim);
                    }
                    buflen = rec->object.len;
                    bufsz -= i;
                    if (buflen > bufsz) {
                        buflen = bufsz;
                    }
                    i += md_util_hexdump_append(dnp_buffer + i,
                                                &bufsz, rec->object.buf, buflen);
                    rv = exporter->VLprint_fn(exporter,  (uint8_t *)dnp_buffer,
                                   DNP_DEFAULT, index_str, index_len, 284, i, FALSE);
                    MD_RET0(rv);
                }

            }
        }
        break;
      case YAF_MODBUS_FLOW_TID:
        rv = exporter->BLprint_fn(exporter, (fbBasicList_t *)flow->app,
                             index_str, index_len, MODBUS_DEFAULT, TRUE);
        MD_RET0(rv);
        break;
      case YAF_ENIP_FLOW_TID:
        rv = exporter->BLprint_fn(exporter, (fbBasicList_t *)flow->app,
                             index_str, index_len, ENIP_DEFAULT, TRUE);
        MD_RET0(rv);
        break;
      default:
        break;
    }

    if (flow->fullcert) {
        yfNewSSLCertFlow_t  *cert = NULL;
        size_t buftest;
        fbVarfield_t *ct = NULL;
        int i = 0;
        int cert_no = 0;

        brem = MD_REM_MSG(buf);

        if (exporter->json) {
            if (flow->sslcerts) {
                ret = snprintf(buf->cp, brem, "\"sslCertList\":[");
                MD_CHECK_RET(buf, ret, brem);
            }
            buftest = brem;

            while ((cert = flow->sslcerts[i])) {
                if (!mdJsonifyNewSSLCertRecord(exporter, cert, cert_no)) {
                    return 0;
                }
                ct = (fbVarfield_t *)FBBLNP(&(flow->fullcert->cert), ct);
                if (ct->len == 0) {
                    continue;
                }
                if (exporter->md5_hash || exporter->sha1_hash ||
                    mdExporterCheckSSLConfig(exporter, 299, 3) ||
                    mdExporterCheckSSLConfig(exporter, 298, 3))
                {
                    if (!mdExporterSSLCertHash(exporter, ct, NULL, 0, cert_no)) {
                        return 0;
                    }
                    brem = MD_REM_MSG(buf);
                }
                if (mdExporterCheckSSLConfig(exporter, 296, 3)) {
                    if (!mdJsonifySSLCertBase64(exporter->buf, ct)) {
                        return FALSE;
                    }
                }
                cert_no++;
                i++;
            } /* cert list loop */

            brem = MD_REM_MSG(buf);

            if (flow->sslcerts) {
                if (brem != buftest) {
                    /* remove comma if sslCertList array is not empty*/
                    buf->cp -= 1;
                    brem += 1;
                }
                MD_APPEND_CHAR_CHECK(brem, exporter->buf, ']');
                MD_APPEND_CHAR_CHECK(brem, exporter->buf, ',');
            }
        } else {
            while ((cert = flow->sslcerts[i]))
            {
                if (!mdExporterTextNewSSLCertPrint(exporter, cert, index_str,
                                                   index_len, cert_no)) {
                    return 0;
                }
                if (exporter->md5_hash || exporter->sha1_hash ||
                    mdExporterCheckSSLConfig(exporter, 299, 3) ||
                    mdExporterCheckSSLConfig(exporter, 298, 3) ||
                    mdExporterCheckSSLConfig(exporter, 296, 3))
                {
                    ct = (fbVarfield_t *)FBBLNP(&(flow->fullcert->cert), ct);
                    if (ct->len == 0) {
                        continue;
                    }
                    if (!mdExporterSSLCertHash(exporter, ct, index_str, index_len, cert_no)) {
                        return 0;
                    }
                    if (mdExporterCheckSSLConfig(exporter, 296, 3)) {
                        if (!mdExporterSSLBase64Encode(exporter, ct, index_str, index_len, cert_no)) {
                            return FALSE;
                        }
                    }

                }
                cert_no++;
                i++;
            }
        }
    }

    if (flow->stats && exporter->basic_list_dpi) {
        if (exporter->json) {
            rv = mdJsonizeFlowStats(exporter, flow->stats, index_str, index_len,
                                    rev);
            MD_RET0(rv);
        } else {
            rv = mdExportFlowStats(exporter, flow->stats, index_str, index_len,
                                   FLOW_STATS_DEFAULT, rev);
            MD_RET0(rv);
        }
    }


    if (flow->dhcpfp) {
        if ((flow->dhcpfp->tmplID & YTF_BIF) == YAF_DHCP_FLOW_TID) {
            yfDHCP_FP_Flow_t *dhcp = NULL;
            dhcp = (yfDHCP_FP_Flow_t *)fbSubTemplateMultiListEntryNextDataPtr(flow->dhcpfp, dhcp);
            rv = exporter->VLprint_fn(exporter,  dhcp->dhcpFP.buf,
                                      DHCP_DEFAULT, index_str, index_len, 242,
                                      dhcp->dhcpFP.len, FALSE);
            MD_RET0(rv);
            rv = exporter->VLprint_fn(exporter,  dhcp->dhcpVC.buf,
                                      DHCP_DEFAULT, index_str, index_len, 243,
                                      dhcp->dhcpVC.len, FALSE);
            MD_RET0(rv);
            if (flow->dhcpfp->tmplID & YTF_REV) {
                rv = exporter->VLprint_fn(exporter,
                                          dhcp->reverseDhcpFP.buf,
                                          DHCP_DEFAULT, index_str, index_len, 242,
                                          dhcp->reverseDhcpFP.len, FALSE);
                MD_RET0(rv);
                rv = exporter->VLprint_fn(exporter,
                                          dhcp->reverseDhcpVC.buf,
                                          DHCP_DEFAULT, index_str, index_len, 243,
                                          dhcp->reverseDhcpVC.len, FALSE);
                MD_RET0(rv);
            }
        } else if ((flow->dhcpfp->tmplID & YTF_BIF) == YAF_DHCP_OP_TID) {
            yfDHCP_OP_Flow_t *dhcp = NULL;
            uint8_t *option;
            char dhcp_buffer[4096];
            size_t dhcpbuflen = 0;
            dhcp = (yfDHCP_OP_Flow_t *)fbSubTemplateMultiListEntryNextDataPtr(flow->dhcpfp, dhcp);
            /* print options basiclist */
            for (loop = 0; (option =
              (uint8_t*)fbBasicListGetIndexedDataPtr(&(dhcp->options), loop));
                 loop++)
            {
                dhcpbuflen += snprintf(dhcp_buffer+dhcpbuflen,
                                       sizeof(dhcp_buffer) - dhcpbuflen, "%d, ", *option);
            }

            if (dhcpbuflen > 2) {
                if (exporter->json) {
                    if (exporter->dpi_field_table) {
                        if (!mdGetDPIItem(exporter->dpi_field_table, 297)) {
                            /* fix me */
                            return 0;
                        }
                    }
                    ret = snprintf(buf->cp, brem,
                                   "\"dhcpOptionsList\":[");
                    MD_CHECK_RET(buf, ret, brem);
                    if (!md_util_append_buffer(buf, &brem, (uint8_t*)dhcp_buffer,
                                               dhcpbuflen-2)) {
                        return 0;
                    }
                    MD_APPEND_CHAR(buf, ']');
                    MD_APPEND_CHAR(buf, ',');
                } else {
                    rv = exporter->VLprint_fn(exporter,  (uint8_t*)dhcp_buffer,
                                              DHCP_DEFAULT, index_str, index_len, 297,
                                              dhcpbuflen-2, FALSE);
                    MD_RET0(rv);
                }
            }
            rv = exporter->VLprint_fn(exporter,  dhcp->dhcpVC.buf,
                                      DHCP_DEFAULT, index_str, index_len, 243,
                                      dhcp->dhcpVC.len, FALSE);
            MD_RET0(rv);
            if (flow->dhcpfp->tmplID & YTF_REV) {
                /*print reverse options basiclist */
                dhcpbuflen = 0;
                /* print options basiclist */
                for (loop = 0; (option =
                                (uint8_t*)fbBasicListGetIndexedDataPtr(&(dhcp->revOptions), loop));
                     loop++)
                {
                    dhcpbuflen += snprintf(dhcp_buffer+dhcpbuflen,
                                           sizeof(dhcp_buffer) - dhcpbuflen, "%d, ", *option);
                }

                if (dhcpbuflen > 2) {
                    if (exporter->json) {
                        if (exporter->dpi_field_table) {
                            if (!mdGetDPIItem(exporter->dpi_field_table, 297)) {
                                /* fix me */
                                return 0;
                            }
                        }
                        ret = snprintf(buf->cp, brem,
                                       "\"reverseDhcpOptionsList\":[");
                        MD_CHECK_RET(buf, ret, brem);
                        if (!md_util_append_buffer(buf, &brem, (uint8_t*)dhcp_buffer,
                                                   dhcpbuflen-2)) {
                            return 0;
                        }
                        MD_APPEND_CHAR(buf, ']');
                        MD_APPEND_CHAR(buf, ',');
                    } else {
                        rv = exporter->VLprint_fn(exporter,  (uint8_t*)dhcp_buffer,
                                                  DHCP_DEFAULT, index_str, index_len, 297,
                                                  dhcpbuflen-2, FALSE);
                        MD_RET0(rv);
                    }
                }

                rv = exporter->VLprint_fn(exporter,
                                          dhcp->reverseDhcpVC.buf,
                                          DHCP_DEFAULT, index_str, index_len, 243,
                                          dhcp->reverseDhcpVC.len, FALSE);
                MD_RET0(rv);
            }
        }

    }

    brem = MD_REM_MSG(buf);

    if (exporter->json) {
        buf->cp -= 1;
        brem++;
        if (brem > 3) {
            MD_APPEND_CHAR(buf, '}');
            MD_APPEND_CHAR(buf, '}');
            MD_APPEND_CHAR(buf, '\n');
        }
    }

    /* this prints the index record for this flow */
    if (exporter->dpionly && !exporter->no_index) {
        if (!mdDPIIndex(exporter, flow, INDEX_DEFAULT)) {
            return 0;
        }
    }

    /* only write if we have something.
       The exception is if we have a custom list.
       We want to print the data even if we don't have relevant DPI data
       since we don't print to the file in mdCustomFlowPrint. */

    if (buf->cp > bufstart) {

        rc = md_util_write_buffer(exporter->lfp, buf, exporter->name, err);

        if (!rc) {
            return -1;
        }

        exporter->exp_bytes += rc;

    } else if (exporter->custom_list_dpi || exporter->basic_list_dpi) {

        if (exporter->dpionly && (buf->cp == bufstart)) {
            /* didn't add any DPI and we only want dpi...*/
            return 1;
        } else if (buf->cp == bufstart) {
            /* if custom_list_dpi - add the index_str back on the buffer */
            /* this can happen if DPI_FIELD_LIST or SSL_CONFIG is configured */
            buf->cp += index_len;
        }

        rc = md_util_write_buffer(exporter->lfp, buf, exporter->name, err);

        if (!rc) {
            return -1;
        }

        exporter->exp_bytes += rc;
    } else {
        rc = 1;
    }

    return rc;

}

/**
 * mdExporterTextDNSPrint
 *
 * Returns DNS elements from DPI suitable for text output
 *
 */
gboolean mdExporterTextDNSPrint(
    mdFlowExporter_t   *exporter,
    yfDNSQRFlow_t      *dns)
{
    char delim = exporter->dpi_delimiter;
    mdBuf_t *buf = exporter->buf;
    size_t brem = MD_REM_MSG(buf);
    int ret;

    if (dns->dnsQueryResponse) {
        /* this is a response */
        ret = snprintf(buf->cp, brem, "R%c%d%c", delim, dns->dnsID, delim);
    } else {
        ret = snprintf(buf->cp, brem, "Q%c%d%c", delim, dns->dnsID, delim);
    }

    MD_CHECK_RET(buf, ret, brem);


    ret = snprintf(buf->cp, brem, "%d%c%d%c", dns->dnsRRSection, delim,
                           dns->dnsNXDomain, delim);
    MD_CHECK_RET(buf, ret, brem);

    if (dns->dnsAuthoritative) {
        ret = snprintf(buf->cp, brem, "1%c", delim);
    } else {
        ret = snprintf(buf->cp, brem, "0%c", delim);
    }

    MD_CHECK_RET(buf, ret, brem);

    ret = snprintf(buf->cp, brem, "%d%c%u%c", dns->dnsQRType, delim,
                   dns->dnsTTL, delim);
    MD_CHECK_RET(buf, ret, brem);

    if (dns->dnsQName.buf) {
        if (!md_util_append_varfield(buf, &brem, &(dns->dnsQName))) {
            return FALSE;
        }
    } /* else - query may be for the root server which is NULL*/

    if (dns->dnsQueryResponse == 0) {
        ret = snprintf(buf->cp, brem, "%c\n", delim);
        MD_CHECK_RET(buf, ret, brem);
        return TRUE;
    }

    MD_APPEND_CHAR_CHECK(brem, buf, delim);

    switch (dns->dnsQRType) {
      case 1:
        {
            yfDNSAFlow_t *a = NULL;
            char ipaddr[20];
            while ((a = (yfDNSAFlow_t *)FBSTLNEXT(&(dns->dnsRRList), a))) {
                if (a->ip) {
                    md_util_print_ip4_addr(ipaddr, a->ip);
                    ret = snprintf(buf->cp, brem, "%s", ipaddr);
                    MD_CHECK_RET(buf, ret, brem);
                }
            }

            MD_APPEND_CHAR(buf, '\n');

            break;
        }
      case 2:
        {
            yfDNSNSFlow_t *ns = NULL;
            while ((ns = (yfDNSNSFlow_t *)FBSTLNEXT(&(dns->dnsRRList), ns))) {

                mdPrintVariableLength(buf, &brem, ns->nsdname.buf,
                                      ns->nsdname.len, delim, 0,
                                      exporter->escape_chars);
            }
            MD_APPEND_CHAR(buf, '\n');
            break;

        }
      case 5:
        {
            yfDNSCNameFlow_t *c = NULL;
            while ((c = (yfDNSCNameFlow_t *)FBSTLNEXT(&(dns->dnsRRList), c)))
            {
                mdPrintVariableLength(buf, &brem, c->cname.buf,
                                      c->cname.len, delim, 0,
                                      exporter->escape_chars);
            }
            MD_APPEND_CHAR(buf, '\n');
            break;
        }
      case 6:
        {
            yfDNSSOAFlow_t *soa = NULL;
            while ((soa=(yfDNSSOAFlow_t *)FBSTLNEXT(&(dns->dnsRRList), soa))) {
                mdPrintVariableLength(buf, &brem, soa->mname.buf,
                                      soa->mname.len, delim, 0,
                                      exporter->escape_chars);

                /*g_string_append_len(str, soa->rname.buf,
                  soa->rname.len);
                  g_string_append_printf(str,
                  "%u%c%u%c%u%c%u%c%u",
                  soa->serial, delim,
                  soa->refresh, delim,
                  soa->retry, delim,
                  soa->expire, delim,
                  soa->minimum);*/
            }
            MD_APPEND_CHAR(buf, '\n');
            break;
        }
      case 12:
        {
            yfDNSPTRFlow_t *ptr = NULL;
            while ((ptr = (yfDNSPTRFlow_t *)FBSTLNEXT(&(dns->dnsRRList), ptr)))
            {
                mdPrintVariableLength(buf, &brem, ptr->ptrdname.buf,
                                      ptr->ptrdname.len, delim, 0,
                                      exporter->escape_chars);
            }
            MD_APPEND_CHAR_CHECK(brem, buf, '\n');
            break;
        }
      case 15:
        {
            yfDNSMXFlow_t *mx = NULL;
            while (( mx = (yfDNSMXFlow_t *)FBSTLNEXT(&(dns->dnsRRList), mx)))
            {
                mdPrintVariableLength(buf, &brem, mx->exchange.buf,
                                      mx->exchange.len, delim, 0,
                                      exporter->escape_chars);
            }
            MD_APPEND_CHAR_CHECK(brem, buf, '\n');
            break;

        }
      case 16:
        {
            yfDNSTXTFlow_t *txt = NULL;
            while ((txt = (yfDNSTXTFlow_t *)FBSTLNEXT(&(dns->dnsRRList), txt)))
            {

                mdPrintVariableLength(buf, &brem, txt->txt_data.buf,
                                      txt->txt_data.len,delim, 0,
                                      exporter->escape_chars);
            }
            MD_APPEND_CHAR_CHECK(brem, buf, '\n');
            break;
        }
      case 28:
        {
            yfDNSAAAAFlow_t *aa = NULL;
            char ipaddr[40];
            while ((aa = (yfDNSAAAAFlow_t *)FBSTLNEXT(&(dns->dnsRRList), aa)))
            {
                md_util_print_ip6_addr(ipaddr,(uint8_t *)&(aa->ip));
                ret = snprintf(buf->cp, brem, "%s", ipaddr);
                MD_CHECK_RET(buf, ret, brem);
            }
            MD_APPEND_CHAR_CHECK(brem, buf, '\n');
            break;
        }
      case 33:
        {
            yfDNSSRVFlow_t *srv = NULL;
            while ((srv = (yfDNSSRVFlow_t *)FBSTLNEXT(&(dns->dnsRRList), srv)))
            {
                mdPrintVariableLength(buf, &brem, srv->dnsTarget.buf,
                                      srv->dnsTarget.len, delim, 0,
                                      exporter->escape_chars);

                /*g_string_append_printf(str, "%c%d%c%d%c%d",
                  delim, srv->dnsPriority,
                  delim, srv->dnsWeight,
                  delim, srv->dnsPort);*/
            }
            MD_APPEND_CHAR_CHECK(brem, buf, '\n');
            break;
        }
      case 46:
        {
            yfDNSRRSigFlow_t *rr = NULL;
            while ((rr =(yfDNSRRSigFlow_t *)FBSTLNEXT(&(dns->dnsRRList), rr))){
                mdPrintVariableLength(buf, &brem, rr->dnsSigner.buf,
                                      rr->dnsSigner.len, delim, 0,
                                      exporter->escape_chars);
            }
            MD_APPEND_CHAR_CHECK(brem, buf, '\n');
            break;
        }
      case 47:
        {
            yfDNSNSECFlow_t *nsec = NULL;
            while ((nsec = (yfDNSNSECFlow_t *)FBSTLNEXT(&(dns->dnsRRList), nsec))) {
                mdPrintVariableLength(buf, &brem, nsec->dnsHashData.buf,
                                      nsec->dnsHashData.len,delim, 0,
                                      exporter->escape_chars);
            }
            MD_APPEND_CHAR_CHECK(brem, buf, '\n');
            break;
        }
      default:
        MD_APPEND_CHAR_CHECK(brem, buf, '\n');
    }

    return TRUE;

}

static gboolean mdExporterCheckSSLConfig(
    mdFlowExporter_t *exporter,
    int              obj_id,
    uint8_t          type)
{

    if (exporter->ssl_config) {
        if (type == 1) {
            if (exporter->ssl_config->issuer) {
                if (exporter->ssl_config->issuer[obj_id] == 1) {
                    return TRUE;
                }
            }
        } else if (type == 2) {
            if (exporter->ssl_config->subject) {
                if (exporter->ssl_config->subject[obj_id] == 1) {
                    return TRUE;
                }
            }
        } else if (type == 3) {
            if (exporter->ssl_config->other) {
                if (exporter->ssl_config->other[obj_id] == 1) {
                    return TRUE;
                }
            }
        } else if (type == 4) {
            if (exporter->ssl_config->extensions) {
                if (exporter->ssl_config->extensions[obj_id] == 1) {
                    return TRUE;
                }
            }
        }

        return FALSE;
    }

    /* extensions & SHA1/MD5 have to be enabled manually! */
    if (type == 4 || ((obj_id == 298) || (obj_id == 299))) {
        return FALSE;
    }

    return TRUE;
}


static gboolean mdJsonifyNewSSLCertRecord(
    mdFlowExporter_t    *exporter,
    yfNewSSLCertFlow_t  *cert,
    uint8_t             cert_no)
{

    GString *ou_str = g_string_new("\"sslCertIssuerOrgUnitName\":[");
    mdBuf_t *buf = exporter->buf;
    size_t brem = MD_REM_MSG(buf);
    int ret;
    yfSSLObjValue_t *obj = NULL;
    char ssl_buffer[4096];
    size_t buflen;
    gboolean rv = TRUE;

    /* print issuer label and opening delimiter, only if issuer list
     * exists.
     */
    if (fbSubTemplateListGetIndexedDataPtr(&cert->issuer, 0)) {
        ret = snprintf(buf->cp, brem, "{\"sslCertIssuer\":{");
        MD_CHECK_RET(buf, ret, brem);
    }

    while ((obj = (yfSSLObjValue_t *)FBSTLNEXT(&(cert->issuer),
                                               obj)))
    {
        if (!mdExporterCheckSSLConfig(exporter, obj->obj_id, 1)) {
            continue;
        }

        if (obj->obj_value.len) {

            switch (obj->obj_id) {

              case 3: /* Common Name */

                ret = snprintf(buf->cp, brem,"\"sslCertIssuerCommonName\":\"");
                break;

              case 6: /* Country Name */

                ret = snprintf(buf->cp, brem,
                               "\"sslCertIssuerCountryName\":\"");
                break;

              case 7: /* Locality Name */

                ret = snprintf(buf->cp, brem,
                               "\"sslCertIssuerLocalityName\":\"");
                break;

              case 8: /* State Name */

                ret = snprintf(buf->cp, brem, "\"sslCertIssuerState\":\"");
                break;

              case 9: /* Street Address */

                ret = snprintf(buf->cp, brem,
                               "\"sslCertIssuerStreetAddress\":\"");
                break;

              case 10: /* Organization Name */

                ret = snprintf(buf->cp, brem,
                               "\"sslCertIssuerOrgName\":\"");
                break;

              case 11: /* Organization Unit Name -- note, multi! */
                g_string_append_c(ou_str, '\"');
                g_string_append_len(ou_str, (char *)obj->obj_value.buf,
                                    obj->obj_value.len);
                g_string_append_printf(ou_str, "\",");
                continue;
              case 17: /* Zip Code */
                ret = snprintf(buf->cp, brem, "\"sslCertIssuerZipCode\":\"");
                break;
              default: /* We don't know */
                ret = snprintf(buf->cp, brem, "\"sslObjectID%d\":\"",
                               obj->obj_id);
            } /* switch */

            MD_CHECK_RET(buf, ret, brem);

            if (!md_util_append_varfield(buf, &brem, &(obj->obj_value))) {
                return FALSE;
            }

            MD_APPEND_CHAR_CHECK(brem, buf, '\"');
            MD_APPEND_CHAR_CHECK(brem, buf, ',');
        } /* if obj valid */
    } /* issuer loop */

    /* print OU string if configured, and closing delimiters if issuer
     * exists.
     */
    if (fbSubTemplateListGetIndexedDataPtr(&cert->issuer, 0)) {

        if (mdExporterCheckSSLConfig(exporter, 11, 1)) {
            if (ou_str->str[ou_str->len-1] == ',') {
                g_string_truncate(ou_str, ou_str->len-1);
            }
            g_string_append(ou_str, "]");
            if (!md_util_append_gstr(buf, &brem, ou_str)) {
                return FALSE;
            }
        } else {
            /* we need to snip the trailing comma since we aren't appending
             * the ou string
             */
            if (buf->buf[MD_MSG_LEN(buf)-1] == ',') {
                buf->cp -= 1;
                brem += 1;
            }
        }
        MD_APPEND_CHAR_CHECK(brem, buf, '}');
        MD_APPEND_CHAR_CHECK(brem, buf, ',');
    }

    /* print subject key and opening delimiter, only if subject lists
     * exists.
     */
    if (fbSubTemplateListGetIndexedDataPtr(&cert->subject, 0)) {
        ret = snprintf(buf->cp, brem, "\"sslCertSubject\":{");
        MD_CHECK_RET(buf, ret, brem);
    }

    g_string_truncate(ou_str, 0);
    g_string_append(ou_str, "\"sslCertSubjectOrgUnitName\":[");
    obj = NULL;

    while ((obj = (yfSSLObjValue_t *)FBSTLNEXT(&(cert->subject),
                                               obj)))
    {
        if (!mdExporterCheckSSLConfig(exporter, obj->obj_id, 2)) {
            continue;
        }

        if (obj->obj_value.len) {
            switch (obj->obj_id) {

              case 3: /* Common Name */

                ret = snprintf(buf->cp, brem,
                               "\"sslCertSubCommonName\":\"");
                break;

              case 6: /* Country Name */

                ret = snprintf(buf->cp, brem,
                               "\"sslCertSubCountryName\":\"");
                break;

              case 7: /* Locality Name */

                ret = snprintf(buf->cp, brem,
                               "\"sslCertSubLocalityName\":\"");
                break;

              case 8: /* State Name */

                ret = snprintf(buf->cp, brem,
                               "\"sslCertSubState\":\"");
                break;

              case 9: /* Street Address */

                ret = snprintf(buf->cp, brem,
                               "\"sslCertSubStreetAddress\":\"");
                break;

              case 10: /* Organization Name */

                ret = snprintf(buf->cp, brem,
                               "\"sslCertSubOrgName\":\"");
                break;

              case 11: /* Organization Unit Name -- note, multi! */
                g_string_append_c(ou_str, '\"');
                g_string_append_len(ou_str, (char *)obj->obj_value.buf,
                                    obj->obj_value.len);
                g_string_append_printf(ou_str, "\",");
                continue;
              case 17: /* Zip Code */
                ret = snprintf(buf->cp, brem,
                               "\"sslCertSubZipCode\":\"");
                break;

              default: /* We don't know */
                ret = snprintf(buf->cp, brem, "\"sslObjectID%d\":\"",
                               obj->obj_id);
            } /* switch */

            MD_CHECK_RET(buf, ret, brem);

            if (!md_util_append_varfield(buf, &brem, &(obj->obj_value))) {
                return FALSE;
            }
            MD_APPEND_CHAR_CHECK(brem, buf, '\"');
            MD_APPEND_CHAR_CHECK(brem, buf, ',');
        } /* if obj valid */
    } /* cert subject loop */

    /* append OU string if configured, and closing delimiters if subject
     * exists
     */

    if (fbSubTemplateListGetIndexedDataPtr(&cert->subject, 0)) {

        if (mdExporterCheckSSLConfig(exporter, 11, 2)) {

            if (ou_str->str[ou_str->len-1] == ',') {
                g_string_truncate(ou_str, ou_str->len-1);
            }
            g_string_append(ou_str, "]");
            if (!md_util_append_gstr(buf, &brem, ou_str)) {
                return FALSE;
            }
        } else {
            /* we need to snip the trailing comma since we aren't appending
             * the ou string
             */
            if (buf->buf[MD_MSG_LEN(buf)-1] == ',') {
                buf->cp -= 1;
                brem += 1;
            }
        }

        MD_APPEND_CHAR_CHECK(brem, buf, '}');
        MD_APPEND_CHAR_CHECK(brem, buf, ',');
    }

    /* print cert version */

    if (mdExporterCheckSSLConfig(exporter, 189, 3)) {
        snprintf(ssl_buffer, sizeof(ssl_buffer), "%d", cert->version);
        rv = exporter->VLprint_fn(exporter, (uint8_t *)ssl_buffer,
                                  SSL_DEFAULT, NULL, 0, 189, strlen(ssl_buffer),
                                  FALSE);
        MD_RET0(rv);
    }

    if (cert->serial.len && (mdExporterCheckSSLConfig(exporter, 244, 3))) {
        size_t bufsz = sizeof(ssl_buffer);
        buflen = cert->serial.len > bufsz ? bufsz : cert->serial.len;
        ret = md_util_hexdump_append(ssl_buffer, &bufsz,
                                     cert->serial.buf, buflen);
        rv = exporter->VLprint_fn(exporter, (uint8_t *)ssl_buffer,
                             SSL_DEFAULT, NULL, 0, 244, ret, FALSE);
        MD_RET0(rv);
    }
    if (cert->not_before.len &&
        (mdExporterCheckSSLConfig(exporter, 247, 3)))
    {
        rv = exporter->VLprint_fn(exporter, cert->not_before.buf,
                             SSL_DEFAULT, NULL, 0, 247,
                             cert->not_before.len, FALSE);
        MD_RET0(rv);
    }
    if (cert->not_after.len && (mdExporterCheckSSLConfig(exporter, 248, 3)))
    {
        rv = exporter->VLprint_fn(exporter, cert->not_after.buf,
                                  SSL_DEFAULT, NULL, 0, 248,
                                  cert->not_after.len, FALSE);
        MD_RET0(rv);
    }

    if (cert->pklen && (mdExporterCheckSSLConfig(exporter, 250, 3))) {
        snprintf(ssl_buffer, sizeof(ssl_buffer), "%d", cert->pklen);
        rv = exporter->VLprint_fn(exporter, (uint8_t *)ssl_buffer,
                                  SSL_DEFAULT, NULL, 0, 250,
                                  strlen(ssl_buffer), FALSE);
        MD_RET0(rv);
    }

    /* this element was added in yaf 2.8 */
    if (cert->hash.len && (mdExporterCheckSSLConfig(exporter, 295, 3)))
    {
        size_t bufsz = sizeof(ssl_buffer);
        buflen = cert->hash.len > bufsz ? bufsz : cert->hash.len;
        ret = md_util_hexdump_append(ssl_buffer, &bufsz,
                                     cert->hash.buf, buflen);
        rv = exporter->VLprint_fn(exporter, (uint8_t *)ssl_buffer,
                                  SSL_DEFAULT, NULL, 0, 295,
                                  ret, FALSE);
        MD_RET0(rv);
    }

    brem = MD_REM_MSG(buf);

    /* print extension and opening delimiter, only if ext lists
     * exists.
     */
    if (fbSubTemplateListGetIndexedDataPtr(&cert->extension, 0)) {
        ret = snprintf(buf->cp, brem, "\"sslExtensions\":{");
        MD_CHECK_RET(buf, ret, brem);
    }
    obj = NULL;
    while ((obj = (yfSSLObjValue_t *)FBSTLNEXT(&(cert->extension),
                                               obj)))
    {
        if (!mdExporterCheckSSLConfig(exporter, obj->obj_id, 4)) {
            continue;
        }

        if (obj->obj_value.len) {
            switch (obj->obj_id) {
              case 14:
                {
                    ret = snprintf(buf->cp, brem,
                                   "\"sslSubjectKeyIdentifier\":\"");
                    MD_CHECK_RET(buf, ret, brem);
                    ret = md_util_hexdump_append(buf->cp, &brem, obj->obj_value.buf,
                                                 obj->obj_value.len);
                    if (!ret) return FALSE;
                    buf->cp += ret;
                    MD_APPEND_CHAR_CHECK(brem, buf, '\"');
                    MD_APPEND_CHAR_CHECK(brem, buf, ',');
                }
                break;
              case 15:
                {
                    ret = snprintf(buf->cp, brem, "\"sslKeyUsage\":\"");
                    MD_CHECK_RET(buf, ret, brem);
                    ret = md_util_hexdump_append(buf->cp, &brem, obj->obj_value.buf,
                                                 obj->obj_value.len);
                    if (!ret) return FALSE;
                    buf->cp += ret;
                    MD_APPEND_CHAR_CHECK(brem, buf, '\"');
                    MD_APPEND_CHAR_CHECK(brem, buf, ',');
                }
                break;
              case 16:
                {
                    ret = snprintf(buf->cp, brem,
                                   "\"sslPrivateKeyUsagePeriod\":\"");
                    MD_CHECK_RET(buf, ret, brem);
                    ret = md_util_hexdump_append(buf->cp, &brem, obj->obj_value.buf,
                                                 obj->obj_value.len);
                    if (!ret) return FALSE;
                    buf->cp += ret;
                    MD_APPEND_CHAR_CHECK(brem, buf, '\"');
                    MD_APPEND_CHAR_CHECK(brem, buf, ',');
                }
                break;
              case 17:
                /* subject/issuer alt name can be a list */
                {
                    uint8_t *buffer = obj->obj_value.buf;
                    size_t  len = obj->obj_value.len;
                    uint16_t newlen;
                    ret = snprintf(buf->cp, brem, "\"sslSubjectAltName\":[");
                    MD_CHECK_RET(buf, ret, brem);
                    while ((newlen = md_util_decode_asn1_sequence(&buffer,
                                                                  &len)))
                    {
                        if (*buffer == 0x30) {
                            /* this is a sequence - ignore */
                            break;
                        }
                        MD_APPEND_CHAR_CHECK(brem, buf, '\"');
                        if (!md_util_append_buffer(buf, &brem, buffer, newlen))
                        {
                            return FALSE;
                        }
                        buffer += newlen;
                        len -= newlen;

                        ret = snprintf(buf->cp, brem, "\",");
                        MD_CHECK_RET(buf, ret, brem);
                    }
                    if (buf->buf[MD_MSG_LEN(buf)-1] == ',') {
                        buf->cp -= 1;
                        brem += 1;
                    }
                    MD_APPEND_CHAR_CHECK(brem, buf, ']');
                    MD_APPEND_CHAR_CHECK(brem, buf, ',');
                }
                break;
              case 18:
                /* subject/issuer alt name can be a list */
                {
                    uint8_t *buffer = obj->obj_value.buf;
                    size_t  len = obj->obj_value.len;
                    uint16_t newlen;
                    ret = snprintf(buf->cp, brem, "\"sslIssuerAltName\":[");
                    MD_CHECK_RET(buf, ret, brem);
                    while ((newlen = md_util_decode_asn1_sequence(&buffer,
                                                                  &len)))
                    {
                        if (*buffer == 0x30) {
                            /* this is a sequence - ignore */
                            break;
                        }
                        MD_APPEND_CHAR_CHECK(brem, buf,'\"');
                        if (!md_util_append_buffer(buf,&brem, buffer, newlen))
                        {
                            return FALSE;
                        }
                        buffer += newlen;
                        len -= newlen;
                        MD_APPEND_CHAR_CHECK(brem, buf, '\"');
                        MD_APPEND_CHAR_CHECK(brem, buf, ',');
                    }
                    if (buf->buf[MD_MSG_LEN(buf)-1] == ',') {
                        buf->cp -= 1;
                        brem += 1;
                    }
                    MD_APPEND_CHAR_CHECK(brem, buf, ']');
                    MD_APPEND_CHAR_CHECK(brem, buf, ',');
                }
                break;
              case 29:
                /* subject/issuer alt name can be a list */
                {
                    uint8_t *buffer = obj->obj_value.buf;
                    size_t  len = obj->obj_value.len;
                    uint16_t newlen;
                    ret = snprintf(buf->cp, brem,"\"sslCertificateIssuer\":[");
                    MD_CHECK_RET(buf, ret, brem);
                    while ((newlen = md_util_decode_asn1_sequence(&buffer,
                                                                  &len)))
                    {
                        if (*buffer == 0x30) {
                            /* this is a sequence - ignore */
                            break;
                        }
                        MD_APPEND_CHAR_CHECK(brem, buf,'\"');
                        if (!md_util_append_buffer(buf,&brem, buffer, newlen))
                        {
                            return FALSE;
                        }
                        buffer += newlen;
                        len -= newlen;
                        MD_APPEND_CHAR_CHECK(brem, buf, '\"');
                        MD_APPEND_CHAR_CHECK(brem, buf, ',');
                    }
                    if (buf->buf[MD_MSG_LEN(buf)-1] == ',') {
                        buf->cp -= 1;
                        brem += 1;
                    }
                    MD_APPEND_CHAR_CHECK(brem, buf, ']');
                    MD_APPEND_CHAR_CHECK(brem, buf, ',');
                }
                break;
              case 31:
                {
                    uint8_t *buffer = obj->obj_value.buf;
                    size_t  len = obj->obj_value.len;
                    uint16_t newlen;
                    gboolean a;
                    ret = snprintf(buf->cp, brem,
                                   "\"sslCRLDistributionPoints\":[");
                    MD_CHECK_RET(buf, ret, brem);
                    while ((newlen = md_util_decode_asn1_sequence(&buffer, &len))) {
                        a = FALSE;
                        while (*buffer == 0xa0) {
                            buffer++;
                            len -= 1;
                            md_util_decode_asn1_length(&buffer, &len);
                            a = TRUE;
                        }
                        if (a) continue; /* start over */
                        MD_APPEND_CHAR_CHECK(brem, buf,'\"');
                        if (!md_util_append_buffer(buf,&brem, buffer, newlen))
                        {
                            return FALSE;
                        }
                        buffer += newlen;
                        len -= newlen;
                        MD_APPEND_CHAR_CHECK(brem, buf, '\"');
                        MD_APPEND_CHAR_CHECK(brem, buf, ',');
                    }
                    if (buf->buf[MD_MSG_LEN(buf)-1] == ',') {
                        buf->cp -= 1;
                        brem += 1;
                    }
                    MD_APPEND_CHAR_CHECK(brem, buf, ']');
                    MD_APPEND_CHAR_CHECK(brem, buf, ',');
                }
                break;
              case 32:
                {
                    uint8_t *buffer = obj->obj_value.buf;
                    size_t  len = obj->obj_value.len;
                    uint16_t newlen;
                    newlen = md_util_decode_asn1_sequence(&buffer, &len);
                    if (*buffer == 0x06) {
                        /* OID */
                        buffer++;
                        newlen = (uint16_t)*buffer;
                        buffer++;
                        ret = snprintf(buf->cp, brem,
                                       "\"sslCertificatePolicyID\":\"");
                        MD_CHECK_RET(buf, ret, brem);
                        /* subject key identifier - just an octet string*/
                        ret = md_util_hexdump_append(buf->cp, &brem, buffer,
                                                     newlen);
                        if (!ret) return FALSE;
                        buf->cp += ret;
                        buffer += newlen;
                        len -= newlen;
                        MD_APPEND_CHAR_CHECK(brem, buf, '\"');
                        MD_APPEND_CHAR_CHECK(brem, buf, ',');
                    }
                    /* now to a sequqnece {policyQualifierID, qualifier} */
                    if (*buffer == 0x30) {
                        /* string */
                        len = len - newlen - 2;
                        newlen = md_util_decode_asn1_sequence(&buffer, &len);
                        if (*buffer == 0x06) {
                            /* OID */
                            buffer++;
                            newlen = (uint16_t)*buffer;
                            buffer += newlen + 1;
                            if (*buffer == 0x16) {
                                buffer++;
                                newlen = (uint16_t)*buffer;
                                buffer++;

                                ret = snprintf(buf->cp, brem,
                                               "\"sslCertificatePolicy\":\"");
                                MD_CHECK_RET(buf, ret, brem);
                                if (!md_util_append_buffer(buf, &brem, buffer, newlen))
                                {
                                    return FALSE;
                                }
                                MD_APPEND_CHAR_CHECK(brem, buf, '\"');
                                MD_APPEND_CHAR_CHECK(brem, buf, ',');
                            }
                        }
                    }
                }
                break;
              default:
                break;
            }
        }
    }

    if (fbSubTemplateListGetIndexedDataPtr(&cert->extension, 0)) {
        if (buf->buf[MD_MSG_LEN(buf)-1] == ',') {
            buf->cp -= 1;
            brem += 1;
        }
        /* close extensions... */
        MD_APPEND_CHAR_CHECK(brem, buf, '}');
    }

    if (buf->buf[MD_MSG_LEN(buf)-1] == ',') {
        buf->cp -= 1;
        brem += 1;
    }

    /* close this certificate in the chain */
    MD_APPEND_CHAR_CHECK(brem, buf, '}');
    MD_APPEND_CHAR_CHECK(brem, buf, ',');

    g_string_free(ou_str, TRUE);
    return TRUE;
}



gboolean mdJsonifyNewSSLRecord(
    mdFlowExporter_t    *exporter,
    yfNewSSLFlow_t      *sslflow,
    gboolean            hex,
    gboolean            escape)
{

    yfNewSSLCertFlow_t *cert = NULL;
    fbSubTemplateList_t *stl = &(sslflow->sslCertList);
    char ssl_buffer[500];
    int cert_no = 0, ret;
    size_t brem = MD_REM_MSG(exporter->buf);

    if (!sslflow) {
        return TRUE;
    }

    if (fbSubTemplateListGetIndexedDataPtr(stl, 0)) {
        ret = snprintf(exporter->buf->cp, brem, "\"sslCertList\":[");
        MD_CHECK_RET(exporter->buf, ret, brem);
    }

    while ((cert = (yfNewSSLCertFlow_t *)FBSTLNEXT(stl, cert)))
    {
        if(!mdJsonifyNewSSLCertRecord(exporter, cert, cert_no)) {
            return FALSE;
        }
        cert_no++;
    } /* cert list loop */

    brem = MD_REM_MSG(exporter->buf);

    if (fbSubTemplateListGetIndexedDataPtr(stl, 0)) {
        exporter->buf->cp -= 1;
        brem += 1;
        MD_APPEND_CHAR_CHECK(brem, exporter->buf, ']');
        MD_APPEND_CHAR_CHECK(brem, exporter->buf, ',');
    }

    if (sslflow->sslServerCipher &&
        (mdExporterCheckSSLConfig(exporter, 187, 3)))
    {
        snprintf(ssl_buffer, sizeof(ssl_buffer), "%d",
                 sslflow->sslServerCipher);
        exporter->VLprint_fn(exporter, (uint8_t *)ssl_buffer,
                             SSL_DEFAULT, NULL, 0, 187,
                             strlen(ssl_buffer), FALSE);
    }

    if (sslflow->sslCompressionMethod &&
        (mdExporterCheckSSLConfig(exporter, 188, 3)))
    {
        snprintf(ssl_buffer, sizeof(ssl_buffer), "%d",
                 sslflow->sslCompressionMethod);
        exporter->VLprint_fn(exporter, (uint8_t *)ssl_buffer,
                             SSL_DEFAULT, NULL, 0, 188,
                             strlen(ssl_buffer), FALSE);
    }

    if (sslflow->sslClientVersion &&
        (mdExporterCheckSSLConfig(exporter, 186, 3)))
    {
        snprintf(ssl_buffer, sizeof(ssl_buffer), "%d",
                 sslflow->sslClientVersion);
        exporter->VLprint_fn(exporter, (uint8_t *)ssl_buffer,
                             SSL_DEFAULT, NULL, 0, 186,
                             strlen(ssl_buffer), FALSE);
    }

    if (sslflow->sslRecordVersion &&
        (mdExporterCheckSSLConfig(exporter, 288, 3)))
    {
        snprintf(ssl_buffer, sizeof(ssl_buffer), "%d",
                 sslflow->sslRecordVersion);
        exporter->VLprint_fn(exporter, (uint8_t *)ssl_buffer,
                             SSL_DEFAULT, NULL, 0, 288,
                             strlen(ssl_buffer), FALSE);
    }

    /* this element was added in yaf 2.8 */
    if (sslflow->sslServerName.buf &&
        (mdExporterCheckSSLConfig(exporter, 294, 3)))
    {
        exporter->VLprint_fn(exporter, sslflow->sslServerName.buf,
                             SSL_DEFAULT, NULL, 0, 294,
                             sslflow->sslServerName.len, FALSE);
    }

    return TRUE;
}


static gboolean mdExporterTextNewSSLCertObjectPrint(
    mdFlowExporter_t    *exporter,
    yfSSLObjValue_t     *obj,
    char                *index_str,
    size_t              index_len,
    uint8_t             section,
    uint8_t             cert_no,
    char                ise,
    char                delim)
{

    char *label = SSL_DEFAULT;
    mdBuf_t *buf = exporter->buf;
    size_t brem = MD_REM_MSG(buf);
    int ret;

    if (!mdExporterCheckSSLConfig(exporter, obj->obj_id, section)) {
        return FALSE;
    }

    if (obj->obj_value.len == 0) {
        return FALSE;
    }

    if (!exporter->no_index && !exporter->multi_files) {
        /* print label */
        ret = snprintf(buf->cp, brem, "%s%c", label, delim);
        MD_CHECK_RET(buf, ret, brem);
    }

    if (!md_util_append_buffer(buf, &brem, (uint8_t*)index_str, index_len)) {
        g_warning("Error %s: error appending index (%zu) to buffer (%zu)",
                  exporter->name, index_len, brem);
        return FALSE;
    }

    ret = snprintf(buf->cp, brem,  "%d%c%c%c%d%c", obj->obj_id, delim, ise,
                   delim, cert_no, delim);

    MD_CHECK_RET(buf, ret, brem);

    if (section == 4) {
        return TRUE;
    }

    if (exporter->escape_chars) {
        if (!mdPrintEscapeChars(buf, &brem, obj->obj_value.buf,
                                obj->obj_value.len, delim)) {
            g_warning("Error %s: error appending escape buf (%zu) to buffer "
                      "(%zu)", exporter->name, obj->obj_value.len, brem);
            return FALSE;
        }
    } else {
        if (!md_util_append_varfield(buf, &brem, &(obj->obj_value))) {
            g_warning("Error %s: error appending varfield (%zu) to buffer "
                      "(%zu)", exporter->name, obj->obj_value.len, brem);
            return FALSE;
        }
    }

    MD_APPEND_CHAR_CHECK(brem, buf, '\n');

    return TRUE;
}

static gboolean mdExporterTextNewSSLCertPrint(
    mdFlowExporter_t    *exporter,
    yfNewSSLCertFlow_t  *cert,
    char                *index_str,
    size_t              index_len,
    uint8_t             cert_no)
{

    yfSSLObjValue_t *obj = NULL;
    char delim = exporter->dpi_delimiter;
    char ssl_buffer[2500];
    char new_index[500];
    size_t buflen, afterlen, brem;
    char *bufstart = NULL;
    mdBuf_t *buf = exporter->buf;
    int ret;

    while ((obj = (yfSSLObjValue_t *)FBSTLNEXT(&(cert->issuer),
                                               obj)))
    {
        mdExporterTextNewSSLCertObjectPrint(exporter, obj, index_str,
                                            index_len, 1, cert_no, 'I',
                                            delim);
    }

    obj = NULL;
    while ((obj = (yfSSLObjValue_t *)FBSTLNEXT(&(cert->subject),
                                               obj)))
    {
        mdExporterTextNewSSLCertObjectPrint(exporter, obj, index_str,
                                            index_len, 2, cert_no, 'S',
                                            delim);
    }

    obj = NULL;

    /* Extensions have to be manually set in the SSL_CONFIG -
       they will not print in any default configuration */
    while ((obj = (yfSSLObjValue_t *)FBSTLNEXT(&(cert->extension), obj))) {

        bufstart = buf->cp;
        if (!mdExporterTextNewSSLCertObjectPrint(exporter, obj,
                                                 index_str, index_len, 4,
                                                 cert_no, 'E', delim))
        {
            continue;
        }
        afterlen = buf->cp - bufstart;
        if (afterlen < sizeof(new_index)) {
            memcpy(new_index, bufstart, afterlen);
        } else {
            memcpy(new_index, bufstart, sizeof(new_index));
        }
        buf->cp = bufstart;
        if (obj->obj_value.len) {
            switch (obj->obj_id) {
              case 14:
              case 15:
              case 16:
                /* push buffer up */
                buf->cp += afterlen;
                /* subject key identifier - just an octet string*/
                brem = MD_REM_MSG(buf);
                ret = md_util_hexdump_append(buf->cp, &brem,
                                             obj->obj_value.buf,
                                             obj->obj_value.len);
                if (!ret) return FALSE;
                buf->cp += ret;
                MD_APPEND_CHAR_CHECK(brem, buf, '\n');
                continue;
              case 17:
              case 18:
              case 29:
                /* subject/issuer alt name can be a list */
                {
                    uint8_t *buffer = obj->obj_value.buf;
                    size_t  len = obj->obj_value.len;
                    uint16_t newlen;

                    brem = MD_REM_MSG(buf);
                    while ((newlen = md_util_decode_asn1_sequence(&buffer, &len))) {
                        if (*buffer == 0x30) {
                            /* this is a sequence - ignore */
                            break;
                        }
                        if (!md_util_append_buffer(buf, &brem,
                                                   (uint8_t*)new_index,
                                                   afterlen))
                        {
                            g_warning("Error %s: error appending index (%zu) to"
                                      " buffer (%zu)", exporter->name, afterlen,
                                      brem);
                            return FALSE;
                        }
                        if (exporter->escape_chars) {
                            if (!mdPrintEscapeChars(buf, &brem, buffer,
                                                    newlen, delim)) {
                                g_warning("Error %s: error appending escape "
                                          "(%d) to buffer (%zu)",
                                          exporter->name, newlen, brem);
                                return FALSE;
                            }
                        } else {
                            if (!md_util_append_buffer(buf, &brem, buffer,
                                                       newlen)) {
                                g_warning("Error %s: error appending data "
                                          "(%d) to buffer (%zu)",
                                          exporter->name, newlen, brem);
                                return FALSE;
                            }
                        }
                        buffer += newlen;
                        len -= newlen;
                        MD_APPEND_CHAR_CHECK(brem, buf, '\n');
                    }
                }
                continue;
              case 31:
                {
                    uint8_t *buffer = obj->obj_value.buf;
                    size_t  len = obj->obj_value.len;
                    uint16_t newlen;
                    gboolean a;
                    brem = MD_REM_MSG(buf);
                    while ((newlen = md_util_decode_asn1_sequence(&buffer, &len))) {
                        a = FALSE;
                        while (*buffer == 0xa0) {
                            buffer++;
                            len -= 1;
                            md_util_decode_asn1_length(&buffer, &len);
                            a = TRUE;
                        }
                        if (a) continue; /* start over */
                        if (!md_util_append_buffer(buf, &brem,
                                                   (uint8_t*)new_index,
                                                   afterlen))
                        {
                            return FALSE;
                        }
                        if (exporter->escape_chars) {
                            if (!mdPrintEscapeChars(buf, &brem, buffer,
                                                    newlen, delim)) {
                                return FALSE;
                            }
                        } else {
                            if (!md_util_append_buffer(buf, &brem, buffer,
                                                       newlen)) {
                                return FALSE;
                            }
                        }
                        buffer += newlen;
                        len -= newlen;
                        MD_APPEND_CHAR_CHECK(brem, buf, '\n');
                    }
                }
                continue;
              case 32:
                {
                    uint8_t *buffer = obj->obj_value.buf;
                    size_t  len = obj->obj_value.len;
                    uint16_t newlen;

                    brem = MD_REM_MSG(buf);
                    newlen = md_util_decode_asn1_sequence(&buffer, &len);
                    if (*buffer == 0x06) {
                        /* OID */
                        buffer++;
                        newlen = (uint16_t)*buffer;
                        buffer++;
                        if (!md_util_append_buffer(buf, &brem,
                                                   (uint8_t*)new_index,
                                                   afterlen))
                        {
                            return FALSE;
                        }

                        /* subject key identifier - just an octet string*/
                        if (newlen > sizeof(ssl_buffer)) {
                            newlen = sizeof(ssl_buffer);
                        }
                        ret = md_util_hexdump_append(buf->cp, &brem, buffer,
                                                     newlen);
                        if (!ret) return FALSE;
                        buf->cp += ret;
                        MD_APPEND_CHAR_CHECK(brem, buf, '\n');
                        buffer += newlen;
                    }
                    /* now to a sequqnece {policyQualifierID, qualifier} */
                    if (*buffer == 0x30) {
                        /* string */
                        len = len - newlen - 2;
                        newlen = md_util_decode_asn1_sequence(&buffer, &len);
                        if (*buffer == 0x06) {
                            /* OID */
                            buffer++;
                            newlen = (uint16_t)*buffer;
                            buffer += newlen + 1;
                            if (*buffer == 0x16) {
                                buffer++;
                                newlen = (uint16_t)*buffer;
                                buffer++;
                                if (!md_util_append_buffer(buf, &brem,
                                                           (uint8_t*)new_index,
                                                           afterlen))
                                {
                                    return FALSE;
                                }
                                if (!md_util_append_buffer(buf, &brem, buffer,
                                                           newlen))
                                {
                                    return FALSE;
                                }
                                MD_APPEND_CHAR_CHECK(brem, buf, '\n');
                            }
                        }
                    }
                }
                continue;
              default:
                continue;
            }
        }
    }

    if (exporter->multi_files) {
        FILE *fp = mdGetTableFile(exporter, 443);
        GError *err;

        if (fp == NULL) {
            g_warning("Error: File does not exist for 443");
            return FALSE;
        }

        ret = md_util_write_buffer(fp, buf, exporter->name, &err);

        if (!ret) {
            g_warning("Error writing file for id 443: %s",
                      err->message);
            g_clear_error(&err);
        }

        exporter->exp_bytes += ret;
    }

    /* print cert version */
    if (mdExporterCheckSSLConfig(exporter, 189, 3)) {
        ret = snprintf(ssl_buffer, sizeof(ssl_buffer), "I%c%d%c%d", delim,
                       cert_no, delim, cert->version);
        exporter->VLprint_fn(exporter, (uint8_t *)ssl_buffer,
                             SSL_DEFAULT, index_str, index_len,
                             189, ret, FALSE);
    }
    if (cert->serial.len && (mdExporterCheckSSLConfig(exporter, 244, 3))) {
        int i;
        size_t bufsz = sizeof(ssl_buffer);
        i = snprintf(ssl_buffer, bufsz, "I%c%d%c", delim, cert_no, delim);
        bufsz -= i;
        if (cert->serial.len > bufsz) {
            buflen = bufsz;
        } else {
            buflen = cert->serial.len;
        }
        i += md_util_hexdump_append(ssl_buffer + i, &bufsz, cert->serial.buf,
                                    buflen);
        exporter->VLprint_fn(exporter, (uint8_t *)ssl_buffer,
                             SSL_DEFAULT, index_str, index_len, 244, i, FALSE);
    }
    if (cert->not_before.len && (mdExporterCheckSSLConfig(exporter, 247, 3)))
    {
        ret = snprintf(ssl_buffer, sizeof(ssl_buffer), "I%c%d%c", delim,
                 cert_no, delim);
        strncat(ssl_buffer,(char *)cert->not_before.buf,
                cert->not_before.len);
        ret += cert->not_before.len;
        exporter->VLprint_fn(exporter, (uint8_t *)ssl_buffer,
                             SSL_DEFAULT, index_str, index_len,  247,
                             ret, FALSE);
    }

    if (cert->not_after.len &&(mdExporterCheckSSLConfig(exporter, 248, 3)))
    {
        ret = snprintf(ssl_buffer, sizeof(ssl_buffer), "I%c%d%c", delim,
                 cert_no, delim);
        strncat(ssl_buffer, (char *)cert->not_after.buf,
                cert->not_after.len);
        ret += cert->not_after.len;
        exporter->VLprint_fn(exporter, (uint8_t *)ssl_buffer,
                             SSL_DEFAULT, index_str, index_len, 248,
                             ret, FALSE);
    }

    if (cert->pklen && (mdExporterCheckSSLConfig(exporter, 250, 3))) {
        ret = snprintf(ssl_buffer, sizeof(ssl_buffer), "I%c%d%c%d", delim,
                       cert_no, delim, cert->pklen);
        exporter->VLprint_fn(exporter, (uint8_t *)ssl_buffer,
                             SSL_DEFAULT, index_str, index_len, 250,
                             ret, FALSE);
    }

    if (cert->hash.len && (mdExporterCheckSSLConfig(exporter, 295, 3))) {
        int i;
        size_t bufsz = sizeof(ssl_buffer);
        i = snprintf(ssl_buffer, bufsz, "I%c%d%c", delim, cert_no, delim);
        bufsz -= i;
        i += md_util_hexdump_append(ssl_buffer + i, &bufsz, cert->hash.buf,
                                    cert->hash.len);
        exporter->VLprint_fn(exporter, (uint8_t *)ssl_buffer,
                             SSL_DEFAULT, index_str, index_len, 295,
                             i, FALSE);
    }

    if (cert->sig.len && (mdExporterCheckSSLConfig(exporter, 190, 3))) {
        int i;
        size_t bufsz = sizeof(ssl_buffer);
        i = snprintf(ssl_buffer, bufsz, "I%c%d%c", delim, cert_no, delim);
        bufsz -= i;
        i += md_util_hexdump_append(ssl_buffer + i, &bufsz, cert->sig.buf,
                                    cert->sig.len);
        exporter->VLprint_fn(exporter, (uint8_t *)ssl_buffer,
                             SSL_DEFAULT, index_str, index_len, 190,
                             i, FALSE);
    }

    return TRUE;

}


gboolean mdExporterTextNewSSLPrint(
    mdFlowExporter_t    *exporter,
    yfNewSSLFlow_t      *sslflow,
    char                *index_str,
    size_t               index_len)
{
    char delim = exporter->dpi_delimiter;
    yfNewSSLCertFlow_t *cert = NULL;
    fbSubTemplateList_t *stl = &(sslflow->sslCertList);
    int cert_no = 0;
    char ssl_buffer[500];
    size_t buflen;


    while ((cert = (yfNewSSLCertFlow_t *)FBSTLNEXT(stl, cert)))
    {
        if (!mdExporterTextNewSSLCertPrint(exporter, cert, index_str,
                                           index_len, cert_no)) {
            return FALSE;
        }
        cert_no++;
    }

    if (sslflow->sslServerCipher &&(mdExporterCheckSSLConfig(exporter, 187,3)))
    {
        snprintf(ssl_buffer, sizeof(ssl_buffer), "I%c%d%c0x%04x",
                 delim, 0, delim, sslflow->sslServerCipher);
        exporter->VLprint_fn(exporter, (uint8_t *)ssl_buffer,
                             SSL_DEFAULT, index_str, index_len, 187,
                             strlen(ssl_buffer), FALSE);
    }

    if (sslflow->sslCompressionMethod &&
        (mdExporterCheckSSLConfig(exporter, 188, 3)))
    {
        snprintf(ssl_buffer, sizeof(ssl_buffer), "I%c%d%c%d", delim, 0, delim,
                 sslflow->sslCompressionMethod);
        exporter->VLprint_fn(exporter, (uint8_t *)ssl_buffer,
                             SSL_DEFAULT, index_str, index_len, 188,
                             strlen(ssl_buffer), FALSE);
    }

    if (sslflow->sslClientVersion &&
        (mdExporterCheckSSLConfig(exporter, 186, 3))) {
        snprintf(ssl_buffer, sizeof(ssl_buffer), "I%c%d%c%d", delim, 0, delim,
                 sslflow->sslClientVersion);
        exporter->VLprint_fn(exporter, (uint8_t *)ssl_buffer,
                             SSL_DEFAULT, index_str, index_len, 186,
                             strlen(ssl_buffer), FALSE);
    }

    if (sslflow->sslRecordVersion &&
        (mdExporterCheckSSLConfig(exporter, 288, 3)))
    {
        snprintf(ssl_buffer, sizeof(ssl_buffer), "I%c%d%c0x%04x", delim,
                 0, delim, sslflow->sslRecordVersion);
        exporter->VLprint_fn(exporter, (uint8_t *)ssl_buffer,
                             SSL_DEFAULT, index_str, index_len, 288,
                             strlen(ssl_buffer), FALSE);
    }

    if (sslflow->sslServerName.buf &&
        (mdExporterCheckSSLConfig(exporter, 294, 3)))
    {
        snprintf(ssl_buffer, sizeof(ssl_buffer), "I%c%d%c", delim, 0,
                 delim);
        if ((sslflow->sslServerName.len + strlen(ssl_buffer)) < sizeof(ssl_buffer))
        {
            buflen = strlen(ssl_buffer);
            memcpy(ssl_buffer + buflen, sslflow->sslServerName.buf,
                   sslflow->sslServerName.len);
            buflen += sslflow->sslServerName.len;
            exporter->VLprint_fn(exporter, (uint8_t *)ssl_buffer,
                                 SSL_DEFAULT, index_str, index_len, 294,
                                 buflen, FALSE);
        }
    }

    return TRUE;
}

gboolean mdExporterWriteDNSRRRecord(
    mdConfig_t          *cfg,
    mdFlowExporter_t    *exporter,
    uint16_t            tid,
    uint8_t             *rec,
    size_t              rec_length,
    GError              **err)
{
    int              ret;
    size_t           bytes;
    gboolean         expand = FALSE;
    mdDnsRR_t        *dns = (mdDnsRR_t *)rec;

    if (exporter == NULL) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                    "Exporter Node Exists, but No Type\n");
        return FALSE;
    }

    if (exporter->multi_files || (exporter->no_stats == 2)) {
        /* don't export anything for these exporters */
        return TRUE;
    }

    if (!exporter->active) {
        if (cfg->ctime - exporter->last_restart_ms > MD_RESTART_MS) {
            if (!mdExporterRestart(cfg, exporter, err)) {
                g_message("Error restarting exporter %s: %s",
                          exporter->name, (*err)->message);
                g_clear_error(err);
                return TRUE;
            }
        } else {
            return TRUE;
        }

    }

    if (exporter->fbuf) {

        if (!mdExporterfBufSetup(cfg, exporter, NULL, err,
                                 mdInitExporterSessionDNSRROnly, MD_DNSRR, tid))
        {
            return FALSE;
        }

        if (!fBufAppend(exporter->fbuf, (uint8_t *)rec, rec_length, err)) {
            fBufFree(exporter->fbuf);
            goto err;
        }
        /* update stats */
        exporter->exp_bytes += rec_length;

    }

    if (exporter->type == TEXT) {
        if (exporter->rotate) {
            if ((cfg->ctime - exporter->last_rotate_ms) > exporter->rotate) {
                if (!mdTextFileRotate(exporter, cfg->ctime, err)) {
                    exporter->last_rotate_ms = 0;
                    goto err;
                }
            }
        }
        if (exporter->custom_list && !exporter->basic_list_dpi) {
            mdFullFlow_t fflow;
            mdRecord_t   mdrec;
            mdFieldList_t   *cnode = NULL;
            size_t       buflen = MD_REM_MSG(exporter->buf);

            memset(&fflow, 0, sizeof(mdFullFlow_t));
            memset(&mdrec, 0, sizeof(mdRecord_t));

            mdrec.flowStartMilliseconds = dns->start;
            mdrec.flowEndMilliseconds = dns->start;
            if (dns->sip || dns->dip) {
                mdrec.sourceIPv4Address = dns->sip;
                mdrec.destinationIPv4Address = dns->dip;
            } else {
                memcpy(&(mdrec.sourceIPv6Address), dns->sip6, 16);
                memcpy(&(mdrec.destinationIPv6Address), dns->dip6, 16);
            }
            mdrec.numAppLabel = 53;
            mdrec.obsid = dns->obid;
            mdrec.sourceTransportPort = dns->sp;
            mdrec.destinationTransportPort = dns->dp;
            mdrec.vlanId = dns->vlan;
            mdrec.protocolIdentifier = dns->proto;
            fflow.rec = &mdrec;

            for (cnode = exporter->custom_list; cnode; cnode = cnode->next) {
                if (!cnode->print_fn(&fflow, exporter->buf, &buflen,
                                     cnode->decorator->str))
                {
                    if (!expand) {
                        if (!mdExporterExpandBuf(exporter)) {
                            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_MEM,
                                    "Error allocating memory for exporter %s",
                                        exporter->name);
                            return FALSE;
                        }
                        expand = TRUE;
                        /* start over */
                        cnode = exporter->custom_list;
                    } else {
                        /* already tried this - ABORT! */
                        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                                    "Error writing to buffer for exporter %s",
                                    exporter->name);
                        goto err;
                    }
                }
            }
            exporter->buf->cp -= 1;
            buflen += 1;
            MD_APPEND_CHAR(exporter->buf, '\n');
            bytes = md_util_write_buffer(exporter->lfp, exporter->buf,
                                         exporter->name, err);
            if (!bytes) {
                goto err;
            }

        } else if (exporter->json) {
            /* here will call printDNS function already implemented in JSON code */
            if (!mdJsonifyDNSRRRecord((mdDnsRR_t *)rec, exporter->buf)) {
                goto err;
            }
            bytes = md_util_write_buffer(exporter->lfp, exporter->buf,
                                         exporter->name, err);
            if (!bytes) {
                goto err;
            }


        } else {

            ret = mdPrintDNSRRRecord(exporter->buf, exporter->lfp,
                                     exporter->delimiter, rec,
                                     cfg->dns_base64_encode,
                                     exporter->escape_chars, err);
            if (ret < 0) {
                goto err;
            } else if (ret == 0) {
                if (!mdExporterExpandBuf(exporter)) {
                    g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_MEM,
                                "Error allocating memory for exporter %s",
                                exporter->name);
                    return FALSE;
                }
                ret = mdPrintDNSRRRecord(exporter->buf, exporter->lfp,
                                         exporter->delimiter, rec,
                                         cfg->dns_base64_encode,
                                         exporter->escape_chars, err);
                if (ret < 0) {
                    goto err;
                } else if (ret == 0) {
                    g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                                "Error writing to buffer for exporter %s",
                                exporter->name);
                    goto err;
                }
            }
            bytes = ret;
        }

        exporter->exp_bytes += bytes;
    }

    ++(exporter->exp_flows);

    return TRUE;

  err:

    g_warning("Error writing DNS Record: %s", (*err)->message);
    g_clear_error(err);
    g_warning("Deactivating Exporter %s.", exporter->name);
    exporter->active = FALSE;
    if (!mdExporterRestart(cfg, exporter, err)) {
        g_warning("Error restarting exporter %s: %s",
                  exporter->name, (*err)->message);
        g_clear_error(err);
    }

    return TRUE;
}

gboolean mdExportDNSRR(
    mdConfig_t       *cfg,
    mdFlowExporter_t *exporter,
    mdFullFlow_t     *flow,
    uint16_t          tid,
    GError           **err)
{

    mdDnsRR_t    dns;
    yfDNSFlow_t *dnsflow = (yfDNSFlow_t *)flow->app;
    yfDNSQRFlow_t *dnsqr = NULL;

    if ((flow->rec->numAppLabel != 53) || (dnsflow == NULL)) {
        return TRUE;
    }

    if (exporter->deduponly || exporter->dnsdeduponly ||
        exporter->ssldeduponly || exporter->flowonly || exporter->multi_files)
    {
        return TRUE;
    }

    memset(&dns, 0, sizeof(dns));

    if (exporter->dns_rr_only == 2) {
        /* check if flow is v4 or v6 */
        if (tid & YTF_IP4) {
            dns.sip = flow->rec->sourceIPv4Address;
            dns.dip = flow->rec->destinationIPv4Address;
            tid = MD_DNSRR;
            tid |= MD_DNSRR_FULL;
            tid |= YTF_IP4;
        } else {
            memcpy(dns.sip6, flow->rec->sourceIPv6Address, 16);
            memcpy(dns.dip6, flow->rec->destinationIPv6Address, 16);
            tid = MD_DNSRR;
            tid |= MD_DNSRR_FULL;
            tid |= YTF_IP6;
        }
        dns.sp = flow->rec->sourceTransportPort;
        dns.dp = flow->rec->destinationTransportPort;
        dns.vlan = flow->rec->vlanId;
        dns.proto = flow->rec->protocolIdentifier;
    } else {
        tid = MD_DNSRR;
    }


    dns.hash = md_util_flow_key_hash(flow->rec);
    dns.start = flow->rec->flowStartMilliseconds;
    dns.obid = flow->rec->obsid;

    while ((dnsqr =(yfDNSQRFlow_t *)FBSTLNEXT(&(dnsflow->dnsQRList),
                                                  dnsqr)))
    {
        dns.ttl = dnsqr->dnsTTL;
        dns.type = dnsqr->dnsQRType;
        dns.id = dnsqr->dnsID;
        dns.qr = dnsqr->dnsQueryResponse;
        dns.auth = dnsqr->dnsAuthoritative;
        dns.nx = dnsqr->dnsNXDomain;
        dns.rrname.buf = dnsqr->dnsQName.buf;
        dns.rrname.len = dnsqr->dnsQName.len;

        if (exporter->dns_resp_only) {
            if (dns.qr == 0) continue;
        }

        if (flow->rec->flowEndReason == UDP_FORCE && dns.qr == 1) {
            dns.hash = md_util_rev_flow_key_hash(flow->rec);
        }

        dns.rrdata.buf = NULL;
        dns.rrdata.len = 0;

        if (dns.qr) {
            switch (dnsqr->dnsQRType) {
              case 1:
                {
                    yfDNSAFlow_t *a = NULL;
                    while ((a = (yfDNSAFlow_t *)FBSTLNEXT(&(dnsqr->dnsRRList), a))) {
                        dns.rrdata.buf = (uint8_t *)&(a->ip);
                        dns.rrdata.len = sizeof(flow->rec->sourceIPv4Address);
                    }
                    break;
                }
              case 2:
                {
                    yfDNSNSFlow_t *ns = NULL;
                    while ((ns = (yfDNSNSFlow_t *)FBSTLNEXT(&(dnsqr->dnsRRList), ns)))
                    {
                        dns.rrdata.buf = ns->nsdname.buf;
                        dns.rrdata.len = ns->nsdname.len;
                    }
                    break;

                }
              case 5:
                {
                    yfDNSCNameFlow_t *c = NULL;
                    while ((c = (yfDNSCNameFlow_t *)FBSTLNEXT(&(dnsqr->dnsRRList), c)))
                    {
                        dns.rrdata.buf = c->cname.buf;
                        dns.rrdata.len = c->cname.len;
                    }
                    break;
                }
              case 6:
                {
                    yfDNSSOAFlow_t *soa = NULL;
                    while ((soa=(yfDNSSOAFlow_t *)FBSTLNEXT(&(dnsqr->dnsRRList), soa))) {
                        dns.rrdata.buf = soa->mname.buf;
                        dns.rrdata.len = soa->mname.len;
                    }
                    break;
                }
              case 12:
                {
                    yfDNSPTRFlow_t *ptr = NULL;
                    while ((ptr = (yfDNSPTRFlow_t *)FBSTLNEXT(&(dnsqr->dnsRRList), ptr)))
                    {
                        dns.rrdata.buf = ptr->ptrdname.buf;
                        dns.rrdata.len = ptr->ptrdname.len;
                    }
                    break;
                }
              case 15:
                {
                    yfDNSMXFlow_t *mx = NULL;
                    while (( mx = (yfDNSMXFlow_t *)FBSTLNEXT(&(dnsqr->dnsRRList), mx)))
                    {
                        dns.rrdata.buf = mx->exchange.buf;
                        dns.rrdata.len = mx->exchange.len;
                    }
                    break;

                }
              case 16:
                {
                    yfDNSTXTFlow_t *txt = NULL;
                    while ((txt = (yfDNSTXTFlow_t *)FBSTLNEXT(&(dnsqr->dnsRRList), txt)))
                    {
                        dns.rrdata.buf = txt->txt_data.buf;
                        dns.rrdata.len = txt->txt_data.len;
                    }
                    break;
                }
              case 28:
                {
                    yfDNSAAAAFlow_t *aa = NULL;
                    while ((aa = (yfDNSAAAAFlow_t *)FBSTLNEXT(&(dnsqr->dnsRRList), aa)))
                    {
                        dns.rrdata.buf = (uint8_t *)&(aa->ip);
                        dns.rrdata.len = sizeof(flow->rec->sourceIPv6Address);
                    }
                    break;
                }
              case 33:
                {
                    yfDNSSRVFlow_t *srv = NULL;
                    while ((srv = (yfDNSSRVFlow_t *)FBSTLNEXT(&(dnsqr->dnsRRList), srv)))
                    {
                        dns.rrdata.buf = srv->dnsTarget.buf;
                        dns.rrdata.len = srv->dnsTarget.len;
                    }
                    break;
                }
              case 46:
                {
                    yfDNSRRSigFlow_t *rr = NULL;
                    while ((rr =(yfDNSRRSigFlow_t *)FBSTLNEXT(&(dnsqr->dnsRRList), rr))){
                        dns.rrdata.buf = rr->dnsSigner.buf;
                        dns.rrdata.len = rr->dnsSigner.len;
                    }
                    break;
                }
              case 47:
                {
                    yfDNSNSECFlow_t *nsec = NULL;
                    while ((nsec = (yfDNSNSECFlow_t *)FBSTLNEXT(&(dnsqr->dnsRRList), nsec))) {
                        dns.rrdata.buf = nsec->dnsHashData.buf;
                        dns.rrdata.len = nsec->dnsHashData.len;
                    }
                    break;
                }
              default:
                dns.rrdata.buf = NULL;
                dns.rrdata.len = 0;
            }
        }

        if (!mdExporterWriteDNSRRRecord(cfg, exporter, tid, (uint8_t *)&dns,
                                        sizeof(dns), err)) {
            return FALSE;
        }
    }

    return TRUE;
}

void mdExporterDedupFileClose(
    mdFlowExporter_t *exporter,
    FILE             *fp,
    char             *last_file)
{
    mdCloseAndUnlock(exporter, fp, last_file, NULL);
    /*if (fp) {
        fclose(fp);
        }

    if (last_file) {
        if (exporter->lock) {
            mdUnlockFile(last_file);
        }
        g_free(last_file);

    }*/
}

gboolean mdExporterDedupFileOpen(
    mdConfig_t          *cfg,
    mdFlowExporter_t    *exporter,
    FILE                **file,
    char                **last_file,
    char                *prefix,
    uint64_t            *rotate)
{

    GString *file_name;
    uint64_t start_secs;
    FILE     *fp = *file;

    if (exporter->type != TEXT) {
        return TRUE;
    }

    if (exporter->json) {
        fp = exporter->lfp;
    }

    if (fp && !exporter->rotate) {
        return TRUE;
    }

    if (fp && exporter->rotate) {
        if ((cfg->ctime - *rotate) < exporter->rotate) {
            return TRUE;
        } else {
            if (exporter->json) {
                mdExporterDedupFileClose(exporter, fp, exporter->current_fname);
            } else {
                mdExporterDedupFileClose(exporter, fp, *last_file);
            }
        }
    }

    file_name = g_string_new("");

    if (exporter->dedupconfig) {
        g_string_assign(file_name, exporter->outspec);
    }

    if (exporter->rotate) {
        start_secs = cfg->ctime / 1000;

        if (!exporter->json) {
            /* 1 FILE for JSON */
            g_string_append_printf(file_name, "%s.", prefix);
        }
        md_util_time_g_string_append(file_name, start_secs, TIME_FMT);

        if (exporter->json) {
            g_string_append_printf(file_name, ".json");
        } else {
            g_string_append_printf(file_name, ".txt");
        }
    } else if (!exporter->json) {
        if (!exporter->dedupconfig) {
            g_string_append_printf(file_name, "%s", prefix);
        } else {
            g_string_append_printf(file_name, "%s.txt", prefix);
        }
    }

    if (exporter->json) {
        exporter->current_fname = g_strdup(file_name->str);
    } else {
        *last_file = g_strdup(file_name->str);
    }
    if (exporter->lock) {
        mdLockFile(file_name);
    }

    fp = fopen(file_name->str, "w");
    if (fp == NULL) {
        g_warning("%s: Error Opening File (%d) %s", exporter->name, errno,
                  file_name->str);
        return FALSE;
    }
    g_debug("%s: Opening Text File: %s", exporter->name,
            file_name->str);
    g_string_free(file_name, TRUE);

    if (exporter->rotate) {
        *rotate = cfg->ctime;
    }
    if (exporter->json) {
        exporter->lfp = fp;
    } else {
        *file = fp;
    }

    return TRUE;
}

gboolean mdExporterWriteDedupRecord(
    mdConfig_t           *cfg,
    md_export_node_t     *enode,
    FILE                 *fp,
    md_dedup_t           *rec,
    char                 *prefix,
    uint16_t             int_tid,
    uint16_t             ext_tid,
    GError               **err)
{
    mdFlowExporter_t *exporter = enode->exp;
    size_t rec_length = sizeof(md_dedup_t);
    int    ret = 0;

    if (exporter == NULL) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                    "Exporter Node Exists, but No Type\n");
        return FALSE;
    }

    if (exporter->ssldeduponly || exporter->dnsdeduponly ||
        exporter->flowonly || exporter->multi_files)
    {
        return TRUE;
    }

    if (!exporter->active) {
        if (cfg->ctime - exporter->last_restart_ms > MD_RESTART_MS) {
            if (!mdExporterRestart(cfg, exporter, err)) {
                g_message("Error restarting exporter %s: %s",
                          exporter->name, (*err)->message);
                g_clear_error(err);
                return TRUE;
            }
        } else {
            return TRUE;
        }
    }

    if (exporter->fbuf) {
        if (int_tid == 0) {
            int_tid = MD_DEDUP_FULL;
        }

        if (!mdExporterfBufSetup(cfg, exporter, NULL, err,
                                 mdInitExporterSessionDedupOnly,
                                 int_tid, ext_tid))
        {
            /* if this fails, it's probably because the internal dedup
               templates have not been added to the session.  Add them
               and try again */

            if (!g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_TMPL)) {
                return FALSE;
            }

            g_clear_error(err);
            if (!md_dedup_add_templates(enode->dedup, exporter->fbuf, err)) {
                return FALSE;
            }
            if (!mdExporterfBufSetup(cfg, exporter, NULL, err,
                                     mdInitExporterSessionDedupOnly,
                                     int_tid, ext_tid))
            {
                return FALSE;
            }
        }
        if (!fBufAppend(exporter->fbuf, (uint8_t *)rec, rec_length, err)) {
            fBufFree(exporter->fbuf);
            goto err;
        }
        /* update stats */
        exporter->exp_bytes += rec_length;

    }

    if (exporter->type == TEXT) {

        if (!fp) {
            /* for collectors OR JSON exporters */
            fp = exporter->lfp;
        }

        if (exporter->json) {
            ret = mdJsonifyDedupRecord(fp, exporter->buf, prefix,
                                       rec, err);

        } else {
            ret = mdPrintDedupRecord(fp, exporter->buf, rec,
                                     exporter->delimiter, err);
        }

        if (ret < 0) {
            goto err;
        } else if (ret == 0) {
            if (!mdExporterExpandBuf(exporter)) {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_MEM,
                            "Error allocating memory for exporter %s",
                            exporter->name);
                return FALSE;
            }

            if (exporter->json) {
                ret = mdJsonifyDedupRecord(fp, exporter->buf, prefix,
                                           rec, err);
            } else {
                ret = mdPrintDedupRecord(fp, exporter->buf, rec,
                                         exporter->delimiter, err);
            }

            if (ret< 0) {
                goto err;
            } else if (ret == 0) {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                            "Error writing to buffer for exporter %s",
                            exporter->name);
                goto err;
            }
        }

        exporter->exp_bytes += ret;
    }

    ++(exporter->exp_flows);

    return TRUE;

  err:

    g_warning("Error writing Dedup Record: %s", (*err)->message);
    g_clear_error(err);
    g_warning("Deactivating Exporter %s.", exporter->name);
    exporter->active = FALSE;
    if (!mdExporterRestart(cfg, exporter, err)) {
        g_warning("Error restarting exporter %s: %s",
                  exporter->name, (*err)->message);
        g_clear_error(err);
    }

    return TRUE;
}

gboolean mdExporterSSLCertRecord(
    mdConfig_t           *cfg,
    mdFlowExporter_t     *exporter,
    FILE                 *cert_file,
    yfNewSSLCertFlow_t   *ssl,
    yfSSLFullCert_t      *fullcert,
    uint8_t              *issuer,
    size_t               issuer_len,
    uint8_t              cert_no,
    GError               **err)
{
    size_t rc;
    size_t brem;
    int ret;
    uint64_t start_secs = cfg->ctime/1000;
    uint32_t start_rem = cfg->ctime %1000;

    if (exporter->deduponly || exporter->dnsdeduponly ||
        exporter->dns_rr_only || exporter->flowonly || exporter->multi_files)
    {
        return TRUE;
    }

    if (!exporter->active) {
        if (cfg->ctime - exporter->last_restart_ms > MD_RESTART_MS) {
            if (!mdExporterRestart(cfg, exporter, err)) {
                g_message("Error restarting exporter %s: %s",
                          exporter->name, (*err)->message);
                g_clear_error(err);
                return TRUE;
            }
        } else {
            return TRUE;
        }

    }

    if (exporter->fbuf) {

        if (!mdExporterfBufSetup(cfg, exporter, NULL, err,
                                 mdInitExporterSessionSSLDedupOnly,
                                 YAF_NEW_SSL_CERT_TID, YAF_NEW_SSL_CERT_TID))
        {
            return FALSE;
        }

        if (!fBufAppend(exporter->fbuf, (uint8_t *)ssl,
                        sizeof(yfNewSSLCertFlow_t), err))
        {
            fBufFree(exporter->fbuf);
            goto err;
        }
        /* update stats */
        exporter->exp_bytes += sizeof(yfNewSSLCertFlow_t);

    }

    if (exporter->type == TEXT) {

        brem = MD_REM_MSG(exporter->buf);

        if (exporter->json) {

            ret = snprintf(exporter->buf->cp, brem, "{\"sslCert\":");
            MD_CHECK_RET(exporter->buf, ret, brem);
            if (!mdJsonifyNewSSLCertRecord(exporter, ssl, cert_no)) {
                /* expand buffer */
                if (!mdExporterExpandBuf(exporter)) {
                    g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_MEM,
                                "Error allocating memory for exporter %s",
                                exporter->name);
                    return -1;
                }
                brem = MD_REM_MSG(exporter->buf);
                /* try again with expanded buffer */
                ret = snprintf(exporter->buf->cp, brem,
                               "{\"sslCert\":");
                MD_CHECK_RET(exporter->buf, ret, brem);
                if (!mdJsonifyNewSSLCertRecord(exporter, ssl, cert_no)) {
                    return FALSE;
                }
            }
            if (fullcert && (exporter->md5_hash || exporter->sha1_hash ||
                             mdExporterCheckSSLConfig(exporter, 299, 3) ||
                             mdExporterCheckSSLConfig(exporter, 298, 3) ||
                             mdExporterCheckSSLConfig(exporter, 296, 3)))
            {
                fbVarfield_t *ct =
                    fbBasicListGetIndexedDataPtr(&(fullcert->cert), cert_no);

                if (ct->len) {
                    if (!mdExporterSSLCertHash(exporter, ct, NULL, 0, cert_no)) {
                        return FALSE;
                    }
                    if (!mdJsonifySSLCertBase64(exporter->buf, ct)) {
                        return FALSE;
                    }
                }
            }
            /* remove '},' */
            exporter->buf->cp -= 2;
            brem += 2;
            ret = snprintf(exporter->buf->cp, brem,
                           ",\"flowStartMilliseconds\":\"");
            MD_CHECK_RET(exporter->buf, ret, brem);
            md_util_time_buf_append(exporter->buf, &brem, start_secs,
                                    PRINT_TIME_FMT);

            ret = snprintf(exporter->buf->cp, brem, ".%03u\"}}\n", start_rem);
            MD_CHECK_RET(exporter->buf, ret, brem);
        } else {
            char *bufstart = exporter->buf->cp;
            size_t afterlen;
            gboolean index_config = exporter->no_index;

            /* set temporarily */
            exporter->no_index = TRUE;

            ret = md_util_hexdump_append_nospace(exporter->buf->cp, &brem,
                                             ssl->serial.buf, ssl->serial.len);
            if (!ret) {
                exporter->no_index = index_config;
                g_warning("Error %s: error appending serial (%zu) to buffer",
                          exporter->name, ssl->serial.len);
                return FALSE;
            }
            exporter->buf->cp += ret;
            MD_APPEND_CHAR_CHECK(brem, exporter->buf, exporter->delimiter);

            if (issuer) {
                if (!md_util_append_buffer(exporter->buf, &brem, issuer,
                                           issuer_len))
                {
                   g_warning("Error %s: error appending issuer (%zu) to buffer",
                             exporter->name, issuer_len);
                   exporter->no_index = index_config;
                    return FALSE;
                }
            }
            MD_APPEND_CHAR_CHECK(brem, exporter->buf, exporter->delimiter);

            if (start_secs) {
                if (!md_util_time_buf_append(exporter->buf, &brem, start_secs,
                                             PRINT_TIME_FMT))
                {
                    g_warning("Error %s: error appending time to buffer (%zu)",
                              exporter->name, brem);
                    exporter->no_index = index_config;
                    return FALSE;
                }

                ret = snprintf(exporter->buf->cp, brem, ".%03u%c",
                               start_rem, exporter->delimiter);
                MD_CHECK_RET(exporter->buf, ret, brem);
            } else {
                MD_APPEND_CHAR_CHECK(brem, exporter->buf, exporter->delimiter);
            }
            afterlen = exporter->buf->cp - bufstart;
            /* reset buffer */
            exporter->buf->cp = bufstart;
            bufstart = malloc(afterlen);
            memcpy(bufstart, exporter->buf->cp, afterlen);
            if (!mdExporterTextNewSSLCertPrint(exporter, ssl, bufstart,
                                               afterlen, cert_no)) {
                /* expand buffer */
                if (!mdExporterExpandBuf(exporter)) {
                    g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_MEM,
                                "Error allocating memory for exporter %s",
                                exporter->name);
                    exporter->no_index = index_config;
                    free(bufstart);
                    return FALSE;
                }
                /* try again with expanded buffer */
                brem = MD_REM_MSG(exporter->buf);
                if (!md_util_append_buffer(exporter->buf, &brem,
                                           (uint8_t*)bufstart, afterlen))
                {
                    exporter->no_index = index_config;
                    free(bufstart);
                    return FALSE;
                }
                if (!mdExporterTextNewSSLCertPrint(exporter, ssl, bufstart,
                                                   afterlen, cert_no)) {

                    exporter->no_index = index_config;
                    free(bufstart);
                    return FALSE;
                }
            }
            if (fullcert && (exporter->md5_hash || exporter->sha1_hash ||
                             mdExporterCheckSSLConfig(exporter, 299, 3) ||
                             mdExporterCheckSSLConfig(exporter, 298, 3) ||
                             mdExporterCheckSSLConfig(exporter, 296, 3)))
            {
                fbVarfield_t *ct = fbBasicListGetIndexedDataPtr(&(fullcert->cert), cert_no);
                if (ct->len) {
                    if (!mdExporterSSLCertHash(exporter, ct, bufstart, afterlen, cert_no)) {
                        return FALSE;
                    }
                    if (mdExporterCheckSSLConfig(exporter, 296, 3)) {
                        if (!mdExporterSSLBase64Encode(exporter, ct, bufstart, afterlen, cert_no)) {
                            return FALSE;
                        }
                    }
                }
            }

            exporter->no_index = index_config;
            free(bufstart);
        }

        /* write to file */
        if (!cert_file && exporter->rotate) {
            if ((cfg->ctime - exporter->last_rotate_ms) > exporter->rotate) {
                if (!mdTextFileRotate(exporter, cfg->ctime, err)) {
                    exporter->last_rotate_ms = 0;
                    return FALSE;
                }
            }
        }

        if (MD_MSG_LEN(exporter->buf) == 0) {
            /* Nothing to write */
            return TRUE;
        }

        if (cert_file) {
            rc = md_util_write_buffer(cert_file, exporter->buf,
                                      exporter->name, err);
        } else {
            rc = md_util_write_buffer(exporter->lfp, exporter->buf,
                                      exporter->name, err);
        }

        if (!rc) {
            goto err;
        }

        exporter->exp_bytes += rc;
    }

    return TRUE;

  err:

    g_warning("Error writing SSL CERT Record: %s", (*err)->message);
    g_clear_error(err);
    g_warning("Deactivating Exporter %s.", exporter->name);
    exporter->active = FALSE;
    if (!mdExporterRestart(cfg, exporter, err)) {
        g_warning("Error restarting exporter %s: %s",
                  exporter->name, (*err)->message);
        g_clear_error(err);
    }

    return TRUE;
}

/**
 * mdExporterWriteSSLDedupRecord
 *
 * write a SSL de-duplicated record to the given exporter
 *
 * @param cfg - mediator configuration options
 * @param exporter - exporter to write to
 * @param tid - template id
 * @param rec - the record to write
 * @param rec_length - length of record to write
 * @param err
 * @return TRUE if no errors
 */
gboolean mdExporterWriteSSLDedupRecord(
    mdConfig_t        *cfg,
    mdFlowExporter_t  *exporter,
    uint16_t          tid,
    uint8_t           *rec,
    size_t             rec_length,
    GError            **err)
{
    int              ret;

    if (exporter == NULL) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                    "Exporter Node Exists, but No Type\n");
        return FALSE;
    }

    if (exporter->deduponly || exporter->dnsdeduponly ||
        exporter->dns_rr_only || exporter->flowonly || exporter->multi_files)
    {
        return TRUE;
    }

    if (!exporter->active) {
        if (cfg->ctime - exporter->last_restart_ms > MD_RESTART_MS) {
            if (!mdExporterRestart(cfg, exporter, err)) {
                g_message("Error restarting exporter %s: %s",
                          exporter->name, (*err)->message);
                g_clear_error(err);
                return TRUE;
            }
        } else {
            return TRUE;
        }

    }

    if (exporter->fbuf) {

        if (!mdExporterfBufSetup(cfg, exporter, NULL, err,
                                 mdInitExporterSessionSSLDedupOnly, tid, tid))
        {
            return FALSE;
        }

        if (!fBufAppend(exporter->fbuf, (uint8_t *)rec, rec_length, err)) {
            fBufFree(exporter->fbuf);
            goto err;
        }
        /* update stats */
        exporter->exp_bytes += rec_length;

    }

    if (exporter->type == TEXT) {

        if (exporter->rotate) {
            if ((cfg->ctime - exporter->last_rotate_ms) > exporter->rotate) {
                if (!mdTextFileRotate(exporter, cfg->ctime, err)) {
                    exporter->last_rotate_ms = 0;
                    goto err;
                }
            }
        }

        if (exporter->json) {
            ret = mdJsonifySSLDedupRecord(exporter->lfp, exporter->buf, rec,
                                          err);
        } else {
            ret = mdPrintSSLDedupRecord(exporter->lfp, exporter->buf, rec,
                                        exporter->delimiter, err);
        }

        if (ret < 0) {
            goto err;
        } else if (ret == 0) {
            if (!mdExporterExpandBuf(exporter)) {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_MEM,
                            "Error allocating memory for exporter %s",
                            exporter->name);
                return FALSE;
            }
            /* try again with expanded buffer */
            if (exporter->json) {
                ret = mdJsonifySSLDedupRecord(exporter->lfp, exporter->buf,
                                              rec, err);
            } else {
                ret = mdPrintSSLDedupRecord(exporter->lfp, exporter->buf, rec,
                                            exporter->delimiter, err);
            }
            if (ret < 0) {
                goto err;
            } else if (ret == 0) {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                            "Error writing to buffer for exporter %s",
                            exporter->name);
                goto err;
            }
        }
        exporter->exp_bytes += ret;
    }

    ++(exporter->exp_flows);

    return TRUE;

  err:

    g_warning("Error writing SSL Dedup Record: %s", (*err)->message);
    g_clear_error(err);
    g_warning("Deactivating Exporter %s.", exporter->name);
    exporter->active = FALSE;
    if (!mdExporterRestart(cfg, exporter, err)) {
        g_warning("Error restarting exporter %s: %s",
                  exporter->name, (*err)->message);
        g_clear_error(err);
    }

    return TRUE;
}
