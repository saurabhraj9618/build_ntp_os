/**
 * @file mediator_inf.h
 *
 * Yaf mediator for filtering, DNS deduplication, and other mediator-like
 * things
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2012-2017 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 * Authors: Emily Sarneso
 * -------------------------------------------------------------------------
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


#include "templates.h"
#include "mediator_ctx.h"
#include <pthread.h>
#if ENABLE_SKIPSET
#include SKIPSET_HEADER_NAME
#ifdef HAVE_SILK_UTILS_H
#include <silk/utils.h>
#endif
#endif

#define FTP_DEFAULT   "ftp"
#define SSH_DEFAULT   "ssh"
#define SMTP_DEFAULT  "smtp"
#define DNS_DEFAULT   "dns"
#define TFTP_DEFAULT  "tftp"
#define HTTP_DEFAULT  "http"
#define IMAP_DEFAULT  "imap"
#define IRC_DEFAULT   "irc"
#define SIP_DEFAULT   "sip"
#define MYSQL_DEFAULT "mysql"
#define SLP_DEFAULT   "slp"
#define POP3_DEFAULT  "pop3"
#define RTSP_DEFAULT  "rtsp"
#define NNTP_DEFAULT  "nntp"
#define SSL_DEFAULT   "tls"
#define DHCP_DEFAULT  "dhcp"
#define P0F_DEFAULT   "p0f"
#define INDEX_DEFAULT "flow"
#define DNS_DEDUP_DEFAULT "dns"
#define FLOW_STATS_DEFAULT "flowstats"
#define YAF_STATS_DEFAULT "yaf_stats"
#define DNP_DEFAULT   "dnp"
#define RTP_DEFAULT   "rtp"
#define MODBUS_DEFAULT "modbus"
#define ENIP_DEFAULT   "enip"

mdFlowExporter_t *mdNewFlowExporter(
    mdTransportType_t type);

mdFlowCollector_t *mdNewFlowCollector(
    mdTransportType_t    mode,
    char                 *name);

gboolean mdCollectorsInit(
    mdConfig_t            *md,
    md_collect_node_t     *collector,
    GError                **err);

void mdInterruptListeners(
    mdConfig_t        *cfg);

void mdCollectorSetInSpec(
    mdFlowCollector_t      *collector,
    char                   *inspec);

void mdCollectorSetDeleteFiles(
    mdFlowCollector_t        *collector,
    gboolean                 delete);

void mdCollectorSetPollTime(
    mdFlowCollector_t      *collector,
    char                   *poll_time);

void mdCollectorSetDecompressDir(
    mdFlowCollector_t *collector,
    char            *path);

void mdCollectorSetMoveDir(
    mdFlowCollector_t      *collector,
    char                   *move_dir);

void mdCollectorSetLockMode(
    mdFlowCollector_t      *collector,
    gboolean               lockmode);

md_collect_node_t *mdCollectorFindListener(
    md_collect_node_t *collector,
    fbListener_t      *listener);

void mdCollectorSetPort(
    mdFlowCollector_t      *collector,
    char               *port);

void mdCollectorAddSpreadGroup(
    mdFlowCollector_t          *collector,
    char                     *group,
    int                      group_no);

char *mdCollectorGetName(
    md_collect_node_t *node);

uint8_t mdCollectorGetID(
    md_collect_node_t *node);

gboolean mdCollectorVerifySetup(
    mdFlowCollector_t       *collector,
    GError              **err);

void *mdNewTable(
    char    *table);

void *mdGetTable(
    int id);

void mdBuildDefaultTableHash(void);

gboolean mdInsertTableItem(
    void    *table_name,
    int     val);

void mdInsertDPIFieldItem(
    mdFlowExporter_t      *exporter,
    int                   ie);

mdFieldList_t *mdNewFieldList(void);

void mdExporterSetPort(
    mdFlowExporter_t *exporter,
    char             *port);

void mdExporterSetHost(
    mdFlowExporter_t *exporter,
    char             *host);

void mdExporterSetRotate(
    mdFlowExporter_t *exporter,
    uint32_t         rotate);

void mdExporterSetDelim(
    mdFlowExporter_t *exporter,
    char             *delim);

void mdExporterSetDPIDelim(
    mdFlowExporter_t *exporter,
    char             *delim);

void mdExporterSetFileSpec(
    mdFlowExporter_t *exporter,
    char             *spec);

void mdExporterFree(
    mdFlowExporter_t *exporter);

void mdExporterSetLock(
    mdFlowExporter_t *exporter);

void  mdExporterDedupPerFlow(
    mdFlowExporter_t *exporter);

void mdExporterSetRemoveEmpty(
    mdFlowExporter_t *exporter);

gboolean mdExporterVerifySetup(
    mdFlowExporter_t *exporter);

void mdExporterSetName(
    mdFlowExporter_t *exporter,
    char             *name);

void mdExporterGZIPFiles(
    mdFlowExporter_t *exporter);

gboolean mdExporterSetDPIOnly(
    mdFlowExporter_t *exporter);

gboolean mdExporterSetFlowOnly(
    mdFlowExporter_t *exporter);

void mdExporterSetDNSDeDup(
    mdFlowExporter_t *exporter);

void mdExporterSetDeDupConfig(
    mdFlowExporter_t *exporter);

void mdExporterSetSSLDeDupConfig(
    mdFlowExporter_t *exporter);

gboolean mdExporterSetSSLDeDupOnly(
    mdFlowExporter_t *exporter,
    gboolean          dedup_only);

gboolean mdExporterGetDNSDedupStatus(
    mdFlowExporter_t *exporter);

void mdExporterSetDNSRespOnly(
    mdFlowExporter_t *exporter);

gboolean mdExporterSetDNSDeDupOnly(
    mdFlowExporter_t *exporter);

void mdExporterSetStats(
    mdFlowExporter_t *exporter,
    uint8_t          mode);

void mdExporterSetNoFlowStats(
    mdFlowExporter_t *exporter);

void mdExporterSetJson(
    mdFlowExporter_t *exporter);

void mdExporterSetNoIndex(
    mdFlowExporter_t *exporter,
    gboolean         val);

void mdExporterSetPrintHeader(
    mdFlowExporter_t *exporter);

void mdExporterSetEscapeChars(
    mdFlowExporter_t *exporter);

gboolean mdExportMultiFiles(
    mdFlowExporter_t  *exporter);

int mdExporterGetType(
    mdFlowExporter_t *exporter);

void mdExporterSetTimestampFiles(
    mdFlowExporter_t *exporter);

void mdExporterSetRemoveUploaded(
    mdFlowExporter_t *exporter);

void mdExportCustomList(
    mdFlowExporter_t *exporter,
    mdFieldList_t    *list);

void mdExporterCustomListDPI(
    mdFlowExporter_t *exporter);

void mdExporterSetId(
    mdFlowExporter_t *exporter,
    uint8_t          id);

gboolean mdExporterCompareNames(
    mdFlowExporter_t *exporter,
    char             *name);

void mdExporterSetSSLConfig(
    mdFlowExporter_t  *exporter,
    int               *list,
    int                type);

gboolean mdExporterSetDNSRROnly(
    mdFlowExporter_t *exporter,
    int               mode);

gboolean mdExporterAddMySQLInfo(
    mdFlowExporter_t *exporter,
    char             *user,
    char             *password,
    char             *db_name,
    char             *db_host,
    char             *table);

void mdInterruptFlowSource(
    mdConfig_t *md);


int mdExporterWriteFlow(
    mdConfig_t          *cfg,
    mdFlowExporter_t    *exporter,
    mdFullFlow_t        *flow,
    GError              **err);

gboolean mdExporterWriteOptions(
    mdConfig_t         *cfg,
    mdFlowExporter_t   *exporter,
    yfIpfixStats_t     *stats,
    GError             **err);

gboolean mdExporterWriteRecord(
    mdConfig_t        *cfg,
    mdFlowExporter_t  *exporter,
    uint16_t          tid,
    uint8_t           *rec,
    size_t             rec_length,
    GError            **err);


gboolean mdExporterWriteDNSRRRecord(
    mdConfig_t          *cfg,
    mdFlowExporter_t    *exporter,
    uint16_t            tid,
    uint8_t             *rec,
    size_t              rec_length,
    GError              **err);

gboolean mdCollectorWait(
    mdContext_t *ctx,
    GError      **err);

gboolean mdCollectorRestartListener(
    mdConfig_t         *md,
    md_collect_node_t  *collector,
    GError             **err);

gboolean mdCollectorStartListeners(
    mdConfig_t         *md,
    md_collect_node_t  *collector,
    GError             **err);

gboolean mdExportersInit(
    mdConfig_t       *cfg,
    md_export_node_t *node,
    GError            **err);

gboolean mdExporterRestart(
    mdConfig_t          *cfg,
    mdFlowExporter_t    *exp,
    GError              **err);

void mdExporterUpdateStats(
    mdConfig_t       *cfg,
    gboolean         dedup);

gboolean mdExporterDestroy(
    mdConfig_t        *cfg,
    GError            **err);

void mdCollectorDestroy(
    mdConfig_t    *cfg,
    gboolean      active);


int mdExporterDPIFlowPrint(
    mdFlowExporter_t   *exporter,
    mdFullFlow_t       *flow,
    char               *index_str,
    size_t             index_len,
    GError             **err);

gboolean mdExporterTextDNSPrint(
    mdFlowExporter_t   *exporter,
    yfDNSQRFlow_t      *dns);

GString *mdExporterJsonDNSPrint(
    mdFlowExporter_t   *exporter,
    yfDNSQRFlow_t      *dnsqrflow);

gboolean mdExporterDPIGetIndexStr(
    mdFlowExporter_t *exporter,
    mdFullFlow_t     *flow);

fBuf_t *mdCollectorSpread(
    mdConfig_t        *md,
    GError            **err);

gboolean mdExporterConnectionReset(
    mdConfig_t       *md_config,
    GError           **err);

gboolean mdExportDNSRR(
    mdConfig_t       *cfg,
    mdFlowExporter_t *exporter,
    mdFullFlow_t     *flow,
    uint16_t         tid,
    GError           **err);

void mdExportSetMetadataExport(
    mdFlowExporter_t *exporter);

/** print functions */
int mdCustomFlowPrint(
    mdFieldList_t      *list,
    mdFullFlow_t       *fflow,
    mdFlowExporter_t   *exporter,
    GError             **err);

md_collect_node_t *mdCollectorGetNode(
    fBuf_t         *fbuf);

void mdCollectorUpdateStats(
    mdConfig_t        *cfg);

/* various types of printing functions for basic lists, varfields */

gboolean mdExportBLMultiFiles(
    mdFlowExporter_t *exporter,
    fbBasicList_t    *bl,
    char             *index_str,
    size_t           index_len,
    char             *label,
    gboolean         hex);
gboolean mdExportBL(
    mdFlowExporter_t *exporter,
    fbBasicList_t    *bl,
    char             *index_str,
    size_t           index_len,
    char             *label,
    gboolean         hex);

gboolean mdExportBLCustomList(
    mdFlowExporter_t *exporter,
    fbBasicList_t    *bl,
    char             *index_str,
    size_t           index_len,
    char             *label,
    gboolean         hex);

gboolean mdJsonizeBLElement(
    mdFlowExporter_t *exporter,
    fbBasicList_t    *bl,
    char             *index_str,
    size_t           index_len,
    char             *label,
    gboolean         hex);

gboolean mdJsonizeVLElement(
    mdFlowExporter_t    *exporter,
    uint8_t             *buf,
    char                *label,
    char             *index_str,
    size_t           index_len,
    uint16_t            id,
    size_t              buflen,
    gboolean            hex);

gboolean mdAppendDPIStr(
    mdFlowExporter_t  *exporter,
    uint8_t           *buf,
    char              *label,
    char             *index_str,
    size_t           index_len,
    uint16_t          id,
    size_t            buflen,
    gboolean          hex);

gboolean mdAppendDPIStrMultiFiles(
    mdFlowExporter_t  *exporter,
    uint8_t           *buf,
    char              *label,
    char             *index_str,
    size_t           index_len,
    uint16_t          id,
    size_t            buflen,
    gboolean          hex);

gboolean mdJsonifyNewSSLRecord(
    mdFlowExporter_t    *exporter,
    yfNewSSLFlow_t      *sslflow,
    gboolean            hex,
    gboolean            escape);

gboolean mdExporterTextNewSSLPrint(
    mdFlowExporter_t    *exporter,
    yfNewSSLFlow_t      *sslflow,
    char                *index_str,
    size_t              index_len);

gboolean mdExporterDedupFileOpen(
    mdConfig_t          *cfg,
    mdFlowExporter_t    *exporter,
    FILE                **file,
    char                **last_file,
    char                *prefix,
    uint64_t            *rotate);


void mdExporterDedupFileClose(
    mdFlowExporter_t *exporter,
    FILE             *fp,
    char             *last_file);

gboolean mdExporterSSLCertRecord(
    mdConfig_t           *cfg,
    mdFlowExporter_t     *exporter,
    FILE                 *cert_file,
    yfNewSSLCertFlow_t   *ssl,
    yfSSLFullCert_t      *fullcert,
    uint8_t              *issuer,
    size_t               issuer_len,
    uint8_t              cert_no,
    GError               **err);

gboolean mdExporterWriteSSLDedupRecord(
    mdConfig_t        *cfg,
    mdFlowExporter_t  *exporter,
    uint16_t          tid,
    uint8_t           *rec,
    size_t             rec_length,
    GError            **err);

gboolean mdExporterWriteDedupRecord(
    mdConfig_t           *cfg,
    md_export_node_t     *enode,
    FILE                 *fp,
    md_dedup_t           *rec,
    char                 *prefix,
    uint16_t             int_tid,
    uint16_t             ext_tid,
    GError               **err);

gboolean mdExporterSetSSLSHA1Hash(
    mdFlowExporter_t *exporter);

gboolean mdExporterSetSSLMD5Hash(
    mdFlowExporter_t *exporter);

char *mdExporterGetName(
    mdFlowExporter_t *exporter);

void mdExporterSetMovePath(
    mdFlowExporter_t *exporter,
    char           *path);

void mdExporterSetNoFlow(
    mdFlowExporter_t  *exporter);

gboolean mdExporterDedupOnly(
    mdFlowExporter_t *exporter);

gboolean mdExporterGetJson(
    mdFlowExporter_t *exporter);
