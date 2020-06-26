/**
 * @file mediator_ctx.h
 *
 * Yaf mediator for filtering, DNS deduplication, and other mediator-like
 * things
 *
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2012-2017 Carnegie Mellon University. All Rights Reserved.
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
 * University under this License, including, but not limited to, any
 * claims of product liability, personal injury, death, damage to
 * property, or violation of any laws or regulations.
 *
 * @OPENSOURCE_HEADER_END@
 * -----------------------------------------------------------
 */

#ifndef MD_CTX
#define MD_CTX


#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <stdarg.h>
#include <time.h>
#include <libgen.h>
#include <unistd.h>
#include <errno.h>
#include <glib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <assert.h>
#include <fixbuf/public.h>
#include "mediator_config.h"
#include "config.h"

#if ENABLE_SKIPSET
#include SKIPSET_HEADER_NAME
#endif

#define MAX_LIST 10
/* 30 sec */
#define MD_RESTART_MS 30000
#define PRINT_TIME_FMT "%04u-%02u-%02u %02u:%02u:%02u"
#define MD_MSGLEN_STD 65535
#define MAX_MAPS 100
typedef enum mdTransportType_en {
    NONE,
    TCP,
    UDP,
    SPREAD,
    FILEHANDLER,
    TEXT,
    DIRECTORY
} mdTransportType_t;

typedef enum fieldOperator_en {
    OPER_UNTOUCHED,
    IN_LIST,
    NOT_IN_LIST,
    EQUAL,
    NOT_EQUAL,
    LESS_THAN,
    LESS_THAN_OR_EQUAL,
    GREATER_THAN,
    GREATER_THAN_OR_EQUAL
} fieldOperator;

typedef enum mdAcceptFilterField_en {
    SIP_ANY,
    DIP_ANY,
    SIP_V4,
    DIP_V4,
    SPORT,
    DPORT,
    PROTOCOL,
    APPLICATION,
    SIP_V6,
    DIP_V6,
    ANY_IP6,
    ANY_IP,
    ANY_PORT,
    OBDOMAIN,
    IPVERSION,
    VLAN,
    FLOWKEYHASH,
    DURATION,
    STIME,
    ENDTIME,
    STIMEMS,
    ETIMEMS,
    SIP_INT,
    DIP_INT,
    RTT,
    PKTS,
    RPKTS,
    BYTES,
    RBYTES,
    IFLAGS,
    RIFLAGS,
    UFLAGS,
    RUFLAGS,
    ATTRIBUTES,
    RATTRIBUTES,
    MAC,
    DSTMAC,
    TCPSEQ,
    RTCPSEQ,
    ENTROPY,
    RENTROPY,
    END,
    OSNAME,
    OSVERSION,
    ROSNAME,
    ROSVERSION,
    FINGERPRINT,
    RFINGERPRINT,
    DHCPFP,
    DHCPVC,
    RDHCPFP,
    RDHCPVC,
    INGRESS,
    EGRESS,
    DATABYTES,
    RDATABYTES,
    ITIME,
    RITIME,
    STDITIME,
    RSTDITIME,
    TCPURG,
    RTCPURG,
    SMALLPKTS,
    RSMALLPKTS,
    LARGEPKTS,
    RLARGEPKTS,
    NONEMPTYPKTS,
    RNONEMPTYPKTS,
    MAXSIZE,
    RMAXSIZE,
    STDPAYLEN,
    RSTDPAYLEN,
    FIRSTEIGHT,
    DPI,
    VLANINT,
    TOS,
    RTOS,
    MPLS1,
    MPLS2,
    MPLS3,
    COLLECTOR,
    FIRSTNONEMPTY,
    RFIRSTNONEMPTY,
    MPTCPSEQ,
    MPTCPTOKEN,
    MPTCPMSS,
    MPTCPID,
    MPTCPFLAGS,
    PAYLOAD,
    RPAYLOAD,
    DHCPOPTIONS,
    RDHCPOPTIONS,
    NDPI_MASTER,
    NDPI_SUB,
    NONE_FIELD
} mdAcceptFilterField_t;

typedef enum mdLogLevel_en {
    MD_DEBUG,
    MESSAGE,
    WARNING,
    ERROR,
    QUIET
} mdLogLevel_t;

typedef struct mdConfig_st mdConfig_t;

/* configuration options */
extern int             myVersion;
extern int             md_stats_timeout;
extern mdConfig_t      md_config;
#if HAVE_SPREAD
char                   **md_out_groups;
extern int             num_out_groups;
#endif
extern char            *md_logfile;
extern char            *md_logdest;
extern char            *md_pidfile;
extern mdLogLevel_t    md_log_level;
extern uint16_t        dns_max_hit_count;
extern uint16_t        dns_flush_timeout;
extern gboolean        multi_file_mode;
extern fbInfoElement_t  *user_elements;

struct mdFlowCollector_st;
typedef struct mdFlowCollector_st mdFlowCollector_t;

struct mdFlowExporter_st;
typedef struct mdFlowExporter_st mdFlowExporter_t;

typedef struct mdDLL_st mdDLL_t;

struct mdDLL_st {
    mdDLL_t *next;
    mdDLL_t *prev;
};

typedef struct mdSLL_st mdSLL_t;

struct mdSLL_st {
    mdSLL_t *next;
};

typedef struct mdQueue_st {
    mdDLL_t *head;
    mdDLL_t *tail;
} mdQueue_t;

typedef struct smHashTable_st {
    size_t     len;
    GHashTable *table;
} smHashTable_t;

typedef struct smFieldMap_st smFieldMap_t;

struct smFieldMap_st {
    smFieldMap_t            *next;
    mdAcceptFilterField_t   field;
    smHashTable_t           *table;
    char                    *name;
    char                   **labels;
    size_t                  count;
    gboolean                discard;
};

typedef struct smFieldMapKV_st {
    uint32_t              val;
} smFieldMapKV_t;

typedef struct md_dns_node_st md_dns_node_t;

/* dns close queue */
typedef struct md_dns_cqueue_st {
    md_dns_node_t *head;
    md_dns_node_t *tail;
} md_dns_cqueue_t;

typedef struct md_dns_dedup_state_st md_dns_dedup_state_t;

typedef struct md_dedup_state_st md_dedup_state_t;
typedef struct md_dedup_str_node_st md_dedup_str_node_t;

typedef struct md_ssl_dedup_state_st md_ssl_dedup_state_t;

typedef struct md_filter_st md_filter_t;

struct md_filter_st {
    md_filter_t           *next;
    fieldOperator         oper;
    mdAcceptFilterField_t field;
#if ENABLE_SKIPSET
    skipset_t             *ipset;
#endif
    uint8_t               num_in_list;
    uint32_t              val[MAX_LIST];
};

typedef struct md_spread_filter_st md_spread_filter_t;

struct md_spread_filter_st {
    md_spread_filter_t     *next;
    char                   *group;
    md_filter_t            *filterList;
};

typedef struct md_export_node_st md_export_node_t;

struct md_export_node_st {
    md_export_node_t       *next;
    mdFlowExporter_t       *exp;
    md_filter_t            *filter;
    md_dns_dedup_state_t   *dns_dedup;
    md_dedup_state_t       *dedup;
    md_ssl_dedup_state_t   *ssl_dedup;
    gboolean               and_filter;
    gboolean               md5_hash;
    gboolean               sha1_hash;
};

typedef struct md_stats_st {
    uint64_t              recvd_flows;
    uint64_t              dns;
    uint64_t              recvd_filtered;
    uint64_t              recvd_stats;
    uint64_t              nonstd_flows;
    uint64_t              uniflows;
    uint32_t              files;
    uint16_t              restarts;
} md_stats_t;

typedef struct md_collect_node_st md_collect_node_t;

struct md_collect_node_st {
    md_collect_node_t      *next;
    mdFlowCollector_t      *coll;
    md_filter_t            *filter;
    fBuf_t                 *fbuf;
    md_stats_t             *stats;
    pthread_cond_t         cond;
    pthread_mutex_t        mutex;
    gboolean               and_filter;
    gboolean               active;
};

typedef struct mdBuf_st {
    char   *cp;
    char   *buf;
    size_t buflen;
} mdBuf_t;

struct mdConfig_st {
    md_collect_node_t       *flowsrc;
    md_export_node_t        *flowexit;
    smFieldMap_t            *maps;
    FILE                    *log;
    md_spread_filter_t      *mdspread;
    char                    *collector_name;
    pthread_cond_t          log_cond;
    pthread_mutex_t         log_mutex;
    gboolean                no_stats;
    gboolean                ipfixSpreadTrans;
    gboolean                lockmode;
    gboolean                dns_base64_encode;
    gboolean                dns_print_lastseen;
    gboolean                shared_filter;
    uint64_t                udp_template_timeout;
    uint64_t                ctime;
    uint32_t                current_domain;
    unsigned int            usec_sleep;
    uint8_t                 num_listeners;
    uint8_t                 collector_id;
#ifdef HAVE_SPREAD
    fbSpreadParams_t        out_spread;
#endif
};

#ifdef HAVE_SPREAD
#define MD_CONFIG_INIT { NULL, NULL, NULL, NULL, NULL, NULL, PTHREAD_COND_INITIALIZER, PTHREAD_MUTEX_INITIALIZER, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, 600, 0, 0, 0, 0, 0, FB_SPREADPARAMS_INIT}
#else
#define MD_CONFIG_INIT { NULL, NULL, NULL, NULL, NULL, NULL, PTHREAD_COND_INITIALIZER, PTHREAD_MUTEX_INITIALIZER, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, 600, 0, 0, 0, 0, 0}
#endif

typedef struct mdContext_st {
    mdConfig_t        *cfg;
    md_stats_t        *stats;
    GError            *err;
} mdContext_t;

#define MD_CTX_INIT { NULL, NULL, NULL }

#endif
