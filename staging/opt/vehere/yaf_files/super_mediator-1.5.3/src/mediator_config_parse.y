%{
#include <mediator/mediator_ctx.h>
#include <mediator/mediator_core.h>
#include <mediator/mediator_inf.h>
#include <mediator/mediator.h>
#include "mediator_dns.h"
#include "mediator_dedup.h"
#include "mediator_ssl.h"

/*Exporter stuff */
/* first in list */
md_export_node_t *ebeg = NULL;
/* used for processing various config blocks */
md_export_node_t *etemp = NULL;
mdFlowExporter_t *exp_temp = NULL;
mdTransportType_t md_ipfix_outtransport = NONE;
gboolean spread_exporter = FALSE;

/*Collector Stuff */
md_collect_node_t *ctemp = NULL;
mdFlowCollector_t *coll_temp = NULL;
mdTransportType_t md_ip_intransport = NONE;
#if HAVE_SPREAD
char              **md_in_groups;
int               num_in_groups;
#endif
/* Shared */
md_spread_filter_t *sftemp = NULL;
md_filter_t *ftemp = NULL;
gboolean and_filter = FALSE;
gboolean md5_filter = FALSE;
gboolean sha1_filter = FALSE;


gboolean default_tables = FALSE;
gboolean custom_tables = FALSE;
gboolean ssl_dedup_only = FALSE;

smFieldMap_t *maptemp = NULL;
smFieldMap_t *mapitem = NULL;
mdFieldList_t *temp_list = NULL;

int      valueListTemp[MAX_VALUE_LIST];
int      numValueList = 0;
int      numCustomList = 0;
int      numUserElements = 0;
int      valueListWild = 0;

char *dedup_temp_name = NULL;
int max_hit = 0;
int flush_timeout = 0;
int *dedup_type_list = NULL;
gboolean lastseen = FALSE;
gboolean exportname = FALSE;

#if ENABLE_SKIPSET
int      app_registered = 0;
#endif
/* parsing function defs */
static void validateConfFile(void);

 static void parseCollectorBegin(mdTransportType_t mode, char *name);
 static void parseCollectorEnd(void);
 static void parseCollectorPort(char *port);
 static void parseCollectorHost(char *host);
 static void parseCollectorFile(char *file);
 static void parseCollectorWatchDir(char *poll_time);
 static void parseCollectorSpreadDaemon(char *daemon_name);
 static void parseCollectorSpreadGroup(char *group);
 static void parseCollectorLock(void);
 static void parseCollectorMovePath(char *dir);
 static void parseCollectorDecompressDirectory(char *path);
 static void parseCollectorDelete(void);
 static void parseFilterBegin(void);
 static void parseFilterEnd(void);
 static void parseComparison(
     mdAcceptFilterField_t field,
     fieldOperator       oper,
     char               *val,
     int                 val_type);
 static void parseExporterBegin(mdTransportType_t mode, char *name);
 static void parseExporterEnd(void);
 static void parseExporterPort(char *port);
 static void parseExporterHost(char *host);
 static void parseExporterFile(char *file);
 static void parseExporterTextDelimiter(char *delim);
 static void parseExporterDPIDelimiter(char *delim);
 static void parseExporterSpreadDaemon(char *daemon_name);
 static void parseExporterSpreadGroup(char *group);
 static void parseExporterLock(void);
 static void parsePidFile(char *pid_file);
 static void parseExporterRotateSeconds(char *secs);
 static void parseExporterUDPTimeout(char *mins);
 static void parseExporterFlowOnly(void);
 static void parseExporterDPIOnly(void);
 static void parseExporterSetAndFilter(void);
 static void parseSpreadGroup(char *name);
 static void parseSpreadGroupEnd(void);
 static void parseStatisticsConfig(void);
 static void parseDNSDeDupConfig(void);
 static void parseExporterMovePath(char *dir);
 static void parseDNSDeDupOnly(void);
 static void parseSSLDeDupOnly(int mode);
 static void parseExporterPrintHeader(void);
 static void parseExporterEscapeChars(void);
 static void parseLogConfig(char *log_file);
 static void parseLogDir(char *log_dir);
 static void parseStatsTimeout(char *timeout);
 static void parseExporterNoStats(void);
 static void parseDNSMaxHitCount(char *count);
 static void parseDNSMaxFlushTime(char *flushtime);
 static void parseExporterRemoveEmpty(void);
 static void parseExporterAddStats(void);
 static void parseValueListItems(char  *val);
 static void parseFieldListItems(
     char                 *fint,
     mdAcceptFilterField_t field);
 static void parseTableList(char *table);
 static void parseTableListBegin(char *index_label);
 static void parseExporterMultiFiles(void);
 static void parseExporterNoIndex(void);
 static void parseExporterTimestamp(void);
 static void parseExporterNoFlowStats(void);
 static void parseMySQLParams(char *user, char *pw, char *db, char *host, char *table);
 static void parseExporterRemoveUploaded(void);
 static void parseUserInfoElement(char *num, char *name, char *app);
 static void parseExporterJson(void);
 static void parseExporterDNSRROnly(int mode);
 static void parseExporterDNSRespOnly(void);
 static void parseDedupRecordTypeList(void);
 static void parseDNSDedupConfigEnd(void);
 static void parseMapStmt(char *mapname);
 static void parseSSLConfigBegin(char *name);
 static void parseSSLIssuerTypeList(void);
 static void parseSSLSubjectTypeList(void);
 static void parseSSLOtherTypeList(void);
 static void parseSSLExtensionsTypeList(void);
 static void parseExporterDedupPerFlow(void);
 static void parseDedupConfig(char *exp_name);
 static void parseFileList(char *file, mdAcceptFilterField_t field, char* mapname);
 static void parseMaxHitCount(char *count);
 static void parseMaxFlushTime(char *flushtime);
 static void parseSSLCertDedup(void);
 static void parseSSLMaxHitCount(char *count);
 static void parseSSLMaxFlushTime(char *flushtime);
 static void parseSSLCertFile(char *filename);
 static void parseExporterSSLMD5Hash(void);
 static void parseExporterSSLSHA1Hash(void);
 static void parseExporterGzipFiles(void);
 static void parseExporterDedupOnly(void);
 static void parseExporterNoFlow(void);
 static void parseVlanMapBegin(char *name);
 static void parseObidMapBegin(char *name);
 static void parseVlanMapLine(char *label);
 static void parseObidMapLine(char *label);
 static void parseMapOther(char *name);
 static void parseMapDiscard(void);
 static void parseMapEnd(void);
 static void parseDedupAddExportName(void);
 static void parseExporterMetadataExport(void);

#define mdtimeCreate(bstc_seconds, bstc_milliseconds)                   \
    ((int64_t)(INT64_C(1000) * (bstc_seconds) + (bstc_milliseconds)))
/*
 *    Given a value containing seconds since the UNIX epoch (such as a
 *    time_t) and a millisecond count, return an bstime_t.  The second
 *    parameter can be any value containing milliseconds.  There is no
 *    restriction on the range of its value.
 */

%}

%union {
    char                   *str;
    uint32_t                integer;
    mdParserNumber_t        *number;
    mdTransportType_t       transport;
    mdAcceptFilterField_t   field;
    fieldOperator           oper;
    mdLogLevel_t            log_level;
}

%token EOS

%token COMMA
%token LEFT_SQ_BRACKET
%token RIGHT_SQ_BRACKET
%token LEFT_PAREN
%token RIGHT_PAREN
%token WILD

%token TOK_COLLECTOR TOK_EXPORTER TOK_DNS_DEDUP TOK_DNSDEDUP_ONLY TOK_NO_STATS
%token TOK_PORT TOK_HOST TOK_IP TOK_PATH TOK_DAEMON TOK_DELIM TOK_PRINT_HDR
%token TOK_GROUP TOK_MOVE TOK_DELETE TOK_LOCK TOK_UDP_TIMEOUT
%token TOK_ROTATE TOK_END TOK_MEDIATOR TOK_FILTER TOK_ANY TOK_LOG_FILE
%token TOK_FLOW_ONLY TOK_DPI_ONLY TOK_POLL TOK_MAX_HIT TOK_FLUSH_SECS
%token TOK_LOG_LEVEL TOK_BASE_64 TOK_LAST_SEEN TOK_RM_EMPTY TOK_STATS_ONLY
%token TOK_TABLE TOK_DPI_CONFIG TOK_MULTI_FILES TOK_ERR TOK_NO_INDEX
%token TOK_TIMESTAMP TOK_NO_FLOW_STATS TOK_PID_FILE TOK_MY_REMOVE
%token TOK_MY_USER TOK_MY_PW TOK_MY_DB TOK_MY_HOST TOK_MY_TABLE
%token TOK_FIELDS TOK_DPI_FIELD_LIST TOK_DPI_DELIMITER TOK_STATS_TO
%token TOK_USERIE TOK_AND_FILTER TOK_ESCAPE TOK_DNSRR_ONLY TOK_FULL
%token TOK_LOG_DIR TOK_JSON TOK_RECORDS TOK_RESP_ONLY TOK_SSL_CONFIG
%token TOK_ISSUER TOK_SUBJECT TOK_OTHER TOK_EXTENSIONS TOK_DEDUP_PER_FLOW
%token TOK_DEDUP_CONFIG TOK_FILE TOK_MERGE TOK_SSL_DEDUP TOK_CERT_FILE
%token TOK_SSL_DEDUP_ONLY TOK_MD5 TOK_SHA1 TOK_GZIP TOK_DNSRR
%token TOK_DEDUP_ONLY TOK_NO_FLOW TOK_OBID_MAP TOK_VLAN_MAP TOK_MAP
%token TOK_DISCARD TOK_ADD_EXPORT TOK_DECOMPRESS TOK_METADATA_EXPORT

 /* values returned from lex */

%token <str>        VAL_ATOM
%token <str>        VAL_DATETIME
%token <str>        VAL_DOUBLE
%token <str>        VAL_INTEGER
%token <str>        VAL_IP
%token <str>        VAL_QSTRING
%token <transport>  VAL_TRANSPORT
%token <dbType>     VAL_DB_TYPE
%token <oper>       VAL_OPER
%token <field>      VAL_FIELD
%token <log_level>   VAL_LOGLEVEL

 /* result of parsing statements */

%type <str>             atomOrQstring

%%
mediatorConfFile:           mediatorConf
{
    validateConfFile();
};

mediatorConf:             stmtList
;

stmtList:                 stmt
                        | stmtList stmt
;

stmt:                     collectorMode
                        | col_filter
                        | exporterMode
                        | spreadGroup
                        | statsConfig
                        | logConfig
                        | logLevelConfig
                        | logDirConfig
                        | pidConfig
                        | dnsdedupConfig
                        | dpiConfig
                        | sslConfig
                        | dedupConfig
                        | statsTimeout
                        | userIE
                        | vlanMap
                        | obidMap
                        | EOS
;

collectorMode:          collectorBegin collectorStmtList collectorEnd
{
};

collectorBegin:          collectorBeginName
                         | collectorBeginNoName
                         | EOS
;

collectorBeginNoName:         TOK_COLLECTOR VAL_TRANSPORT EOS
{
    parseCollectorBegin($2, NULL);
};

collectorBeginName:      TOK_COLLECTOR VAL_TRANSPORT VAL_QSTRING EOS
{
    parseCollectorBegin($2, $3);
}
                        | TOK_COLLECTOR VAL_TRANSPORT VAL_ATOM EOS
{
    parseCollectorBegin($2, $3);
};

collectorEnd:           TOK_COLLECTOR TOK_END EOS
{
    parseCollectorEnd();
};

collectorStmtList:      collectorStmt
                        | collectorStmtList collectorStmt
;

collectorStmt:          col_port
                        | col_host
                        | col_path
                        | col_watch
                        | col_daemon
                        | col_groups
                        | col_lock
                        | col_move_path
                        | col_delete
                        | col_decompress
                        | comparisonList
                        | col_and_filter
                        | EOS
;

col_port:             TOK_PORT VAL_INTEGER EOS
{
    parseCollectorPort($2);
};

col_host:              TOK_HOST atomOrQstring EOS
{
    parseCollectorHost($2);
};

col_path:              TOK_PATH atomOrQstring EOS
{
    parseCollectorFile($2);
};

col_watch:             TOK_POLL  VAL_INTEGER EOS
{
    parseCollectorWatchDir($2);
};

col_daemon:            TOK_DAEMON atomOrQstring EOS
{
    parseCollectorSpreadDaemon($2);
};

col_decompress:        TOK_DECOMPRESS atomOrQstring EOS
{
    parseCollectorDecompressDirectory($2);
};

col_groups:            col_group
                       | col_groups col_group
;

col_group:             TOK_GROUP atomOrQstring EOS
{
    parseCollectorSpreadGroup($2);
};

col_lock:              TOK_LOCK EOS
{
    parseCollectorLock();
}

col_move_path:          TOK_MOVE atomOrQstring EOS
{
    parseCollectorMovePath($2);
}

col_delete:             TOK_DELETE EOS
{
    parseCollectorDelete();
}

col_filter:             filterBegin filterStmtList filterEnd
;

filterStmtList:
                        | filterStmt
                        | filterStmtList filterStmt
;

filterStmt:             comparisonList
                        | col_and_filter
                        | EOS
;

filterBegin:            TOK_FILTER EOS
{
    parseFilterBegin();
};

filterEnd:              TOK_FILTER TOK_END EOS
{
    parseFilterEnd();
};

exp_dpi_field_list:     TOK_DPI_FIELD_LIST valueList EOS
{
};

/* '[' <item>, <item>, ..., <item> ']' */
valueList:                valueListStart valueListItems valueListEnd
;

valueListStart:           LEFT_SQ_BRACKET
{
    numValueList = 0;
    valueListWild = 0;
};
valueListEnd:             RIGHT_SQ_BRACKET
;
valueListItems:           VAL_INTEGER
{
    parseValueListItems($1);
}
                          | valueListItems COMMA VAL_INTEGER
{
    parseValueListItems($3);
}                         | WILD
{
    valueListWild = 1;
};

fieldList:                 fieldListItems
;

fieldListItems:            VAL_FIELD
{
    parseFieldListItems(NULL, $1);
}
                         | VAL_INTEGER
{
    parseFieldListItems($1, 0);
}
                         | TOK_COLLECTOR
{
    parseFieldListItems(0, COLLECTOR);
}
                         | fieldListItems COMMA VAL_INTEGER
{
    parseFieldListItems($3, 0);
}
                         | fieldListItems VAL_INTEGER
{
    parseFieldListItems($2, 0);
}
                         | fieldListItems COMMA VAL_FIELD
{
    parseFieldListItems(NULL, $3);
}
                        | fieldListItems VAL_FIELD
{
    parseFieldListItems(NULL, $2);
}
                        | fieldListItems COMMA TOK_COLLECTOR
{
    parseFieldListItems(0, COLLECTOR);
}
                       | fieldListItems TOK_COLLECTOR
{
    parseFieldListItems(0, COLLECTOR);
};

comparisonList:         comparison
                        | comparisonList comparison
;

comparison:             VAL_FIELD VAL_OPER VAL_INTEGER EOS
{
    parseComparison($1, $2, $3, VAL_INTEGER);
}
                         | VAL_FIELD VAL_OPER VAL_IP EOS
{
    parseComparison($1, $2, $3, VAL_IP);
}
                         | VAL_FIELD VAL_OPER VAL_QSTRING EOS
{
    /* ANY_IP IN_LIST "my_set.set" */
    parseComparison($1, $2, $3, VAL_QSTRING);
}
                         | TOK_COLLECTOR VAL_OPER VAL_QSTRING EOS
{
    parseComparison(80, $2, $3, VAL_QSTRING);
}
                         | TOK_COLLECTOR VAL_OPER VAL_ATOM EOS
{
    parseComparison(80, $2, $3, VAL_QSTRING);
};


/*                       | VAL_FIELD VAL_OPER valueList EOS
{
    parseComparison($1, $2, NULL, VAL_ATOM, NUM_FIELDS);
};*/

exporterMode:          exporterBegin exporterStmtList exporterEnd
{
};

exporterBegin:         TOK_EXPORTER VAL_TRANSPORT EOS
{
    parseExporterBegin($2, NULL);
}
                       | TOK_EXPORTER VAL_TRANSPORT VAL_QSTRING EOS
{
    parseExporterBegin($2, $3);
}
                       | TOK_EXPORTER VAL_TRANSPORT VAL_ATOM EOS
{
    parseExporterBegin($2, $3);
};

exporterEnd:           TOK_EXPORTER TOK_END EOS
{
    parseExporterEnd();
};

exporterStmtList:        exporterStmt
                        | exporterStmtList exporterStmt
                        ;

exporterStmt:            exp_port
                        | exp_host
                        | exp_path
                        | exp_daemon
                        | exp_groups
                        | exp_lock
                        | exp_delim
                        | exp_dpi_delim
                        | exp_rotate
                        | exp_udp_timeout
                        | exp_flow_only
                        | exp_dpi_only
                        | exp_no_stats
                        | exp_stats_only
                        | exp_dedup
                        | exp_dedup_flow
                        | exp_dns_dedup_only
                        | exp_remove_empty
                        | exp_print_headers
                        | exp_multi_files
                        | exp_no_index
                        | exp_timestamp
                        | exp_no_flow_stats
                        | exp_json
                        | comparisonList
                        | customList
                        | mysqlConfig
                        | exp_and_filter
                        | exp_dpi_field_list
                        | exp_remove_uploaded
                        | exp_escape
                        | exp_dns_rr_only
                        | exp_dns_rr
                        | exp_dns_resp_only
                        | exp_ssl_dedup_only
                        | exp_md5_hash
                        | exp_sha1_hash
                        | exp_gzip_files
                        | exp_move_path
                        | exp_no_flow
                        | exp_dedup_only
                        | exp_metadata_export
                        | EOS
;

exp_md5_hash:         TOK_MD5 EOS
{
    parseExporterSSLMD5Hash();
};

exp_sha1_hash:        TOK_SHA1 EOS
{
    parseExporterSSLSHA1Hash();
};

exp_move_path:          TOK_MOVE atomOrQstring EOS
{
    parseExporterMovePath($2);
}

exp_and_filter:       TOK_AND_FILTER EOS
{
    parseExporterSetAndFilter();
};

col_and_filter:       TOK_AND_FILTER EOS
{
    and_filter = TRUE;
};

exp_port:             TOK_PORT VAL_INTEGER EOS
{
    parseExporterPort($2);
};

exp_host:              TOK_HOST atomOrQstring EOS
{
    parseExporterHost($2);
};

exp_path:              TOK_PATH atomOrQstring EOS
{
    parseExporterFile($2);
};

exp_daemon:            TOK_DAEMON atomOrQstring EOS
{
    parseExporterSpreadDaemon($2);
};

exp_groups:            exp_group
                       | exp_groups exp_group
;

exp_group:             TOK_GROUP atomOrQstring EOS
{
    parseExporterSpreadGroup($2);
};

exp_delim:             TOK_DELIM  atomOrQstring EOS
{
    parseExporterTextDelimiter($2);
};

exp_dpi_delim:             TOK_DPI_DELIMITER atomOrQstring EOS
{
    parseExporterDPIDelimiter($2);
};

exp_lock:              TOK_LOCK EOS
{
    parseExporterLock();
};

exp_rotate:            TOK_ROTATE VAL_INTEGER EOS
{
    parseExporterRotateSeconds($2);
};

exp_udp_timeout:       TOK_UDP_TIMEOUT VAL_INTEGER EOS
{
    parseExporterUDPTimeout($2);
};

exp_flow_only:          TOK_FLOW_ONLY EOS
{
    parseExporterFlowOnly();
};

exp_dpi_only:           TOK_DPI_ONLY EOS
{
    parseExporterDPIOnly();
};

exp_no_stats:            TOK_NO_STATS EOS
{
    parseExporterNoStats();
};

exp_stats_only:          TOK_STATS_ONLY EOS
{
    parseExporterAddStats();
};

exp_remove_empty:        TOK_RM_EMPTY EOS
{
    parseExporterRemoveEmpty();
};

exp_multi_files:         TOK_MULTI_FILES EOS
{
    parseExporterMultiFiles();
};

exp_no_flow_stats:       TOK_NO_FLOW_STATS EOS
{
    parseExporterNoFlowStats();
};

exp_json:                TOK_JSON EOS
{
    parseExporterJson();
}

spreadGroup:           spreadBegin comparisonList spreadEnd
{
};

spreadBegin:           TOK_GROUP atomOrQstring EOS
{
    parseSpreadGroup($2);
};

spreadEnd:              TOK_GROUP TOK_END
{
    parseSpreadGroupEnd();
};

/* turns stats forwarding on*/
statsConfig:            TOK_NO_STATS EOS
{
    parseStatisticsConfig();
};

statsTimeout:          TOK_STATS_TO VAL_INTEGER EOS
{
    parseStatsTimeout($2);
};

exp_dedup:             TOK_DNS_DEDUP EOS
{
    parseDNSDeDupConfig();
};

exp_dns_dedup_only:        TOK_DNSDEDUP_ONLY EOS
{
    parseDNSDeDupOnly();
};

exp_ssl_dedup_only:    TOK_SSL_DEDUP_ONLY EOS
{
    parseSSLDeDupOnly(1);
}                      | TOK_SSL_DEDUP EOS
{
    parseSSLDeDupOnly(0);
};

exp_no_flow:           TOK_NO_FLOW EOS
{
    parseExporterNoFlow();
};

exp_dedup_only:        TOK_DEDUP_ONLY EOS
{
    parseExporterDedupOnly();
};

exp_print_headers:     TOK_PRINT_HDR EOS
{
    parseExporterPrintHeader();
};

exp_no_index:           TOK_NO_INDEX EOS
{
    parseExporterNoIndex();
};

exp_escape:             TOK_ESCAPE EOS
{
    parseExporterEscapeChars();
};

exp_dedup_flow:         TOK_DEDUP_PER_FLOW EOS
{
    parseExporterDedupPerFlow();
};

exp_timestamp:          TOK_TIMESTAMP EOS
{
    parseExporterTimestamp();
};
exp_dns_rr_only:        TOK_DNSRR_ONLY EOS
{
    parseExporterDNSRROnly(1);
}
                       | TOK_DNSRR_ONLY TOK_FULL EOS
{
    parseExporterDNSRROnly(2);
};
exp_dns_rr:             TOK_DNSRR EOS
{
    parseExporterDNSRROnly(3);
}
                       | TOK_DNSRR TOK_FULL EOS
{
    parseExporterDNSRROnly(4);
};
exp_dns_resp_only:      TOK_RESP_ONLY EOS
{
    parseExporterDNSRespOnly();
};

exp_gzip_files:        TOK_GZIP EOS
{
    parseExporterGzipFiles();
};

exp_metadata_export:            TOK_METADATA_EXPORT EOS
{
    parseExporterMetadataExport();
};

/* logging */
logConfig:             TOK_LOG_FILE atomOrQstring EOS
{
    parseLogConfig($2);
};

logDirConfig:          TOK_LOG_DIR atomOrQstring EOS
{
    parseLogDir($2);
};

logLevelConfig:        TOK_LOG_LEVEL VAL_LOGLEVEL EOS
{
    md_log_level = $2;
};

pidConfig:              TOK_PID_FILE atomOrQstring EOS
{
    parsePidFile($2);
};

recordList:            TOK_RECORDS valueList EOS
{
    parseDedupRecordTypeList();
};

dnsdedupConfig:           dns_dedup_begin dnsdedupList dns_dedup_end
{
};

dns_dedup_begin:     TOK_DNS_DEDUP atomOrQstring EOS
{
    dedup_temp_name = $2;
}
                     | TOK_DNS_DEDUP EOS
{
};
dns_dedup_end:       TOK_DNS_DEDUP TOK_END
{
    parseDNSDedupConfigEnd();
};

dedupConfig:           dedup_begin dedupList dedup_end
{
};

dedup_begin:           TOK_DEDUP_CONFIG atomOrQstring EOS
{
    parseDedupConfig($2);
}
                       | TOK_DEDUP_CONFIG EOS
{
    parseDedupConfig(NULL);
};

dedup_end:             TOK_DEDUP_CONFIG TOK_END
{
};

dedupList:             dedupStmt
                       | dedupList dedupStmt
;

dedupStmt:             | dedupHitConfig
                       | dedupFlushConfig
                       | dedupFileList
                       | dedupMergeTruncated
                       | dedupAddExport
                       | EOS
;

dedupFileList:          fileList
;

dedupHitConfig:             TOK_MAX_HIT VAL_INTEGER EOS
{
    parseMaxHitCount($2);
};

dedupFlushConfig:           TOK_FLUSH_SECS VAL_INTEGER EOS
{
    parseMaxFlushTime($2);
};

dedupAddExport:             TOK_ADD_EXPORT EOS
{
    parseDedupAddExportName();
};

dedupMergeTruncated:        TOK_MERGE EOS
{
    md_dedup_configure_state(etemp->dedup, 0, 0, TRUE, FALSE);
};

fileList:               fileStmt
                        | fileList fileStmt
;
fileStmt:              TOK_FILE atomOrQstring VAL_FIELD valueList EOS
{
    parseFileList($2, $3, NULL);
}
                       | TOK_FILE atomOrQstring valueList EOS
{
    /* SIP by default */
    parseFileList($2, 2, NULL);
}
                       | TOK_FILE atomOrQstring VAL_FIELD TOK_MAP LEFT_PAREN atomOrQstring RIGHT_PAREN valueList EOS
{
    parseFileList($2, $3, $6);
}                     | TOK_FILE atomOrQstring TOK_MAP LEFT_PAREN atomOrQstring RIGHT_PAREN valueList EOS
{
    parseFileList($2, 2, $5);
};

dnsdedupList:             dnsdedupStmt
                       | dnsdedupList dnsdedupStmt
;
dnsdedupStmt:
                       | hitConfig
                       | flushConfig
                       | base64Config
                       | lastSeenConfig
                       | recordList
                       | mapStmt
                       | dnsdedupAddExport
                       | EOS
;

mapStmt:               TOK_MAP LEFT_PAREN atomOrQstring RIGHT_PAREN EOS
{
    parseMapStmt($3);
};

dnsdedupAddExport:     TOK_ADD_EXPORT EOS
{
    exportname = TRUE;
};

hitConfig:             TOK_MAX_HIT VAL_INTEGER EOS
{
    parseDNSMaxHitCount($2);
};

flushConfig:           TOK_FLUSH_SECS VAL_INTEGER EOS
{
    parseDNSMaxFlushTime($2);
};

base64Config:          TOK_BASE_64 EOS
{
    md_config.dns_base64_encode = TRUE;
};

lastSeenConfig:        TOK_LAST_SEEN EOS
{
    lastseen = TRUE;
};

dpiConfig:              dpi_config_begin dpiList dpi_config_end
{
};

dpi_config_begin:       TOK_DPI_CONFIG EOS
{
    parseTableListBegin(NULL);
}
                        | TOK_DPI_CONFIG atomOrQstring EOS
{
    parseTableListBegin($2);
};

dpi_config_end:         TOK_DPI_CONFIG TOK_END EOS
{
    numValueList = 0;
};

customList:             TOK_FIELDS fieldList EOS
{
    numCustomList = 0;
};

dpiList:                tableList
                        | EOS
;
tableList:              tableStmt
                        | tableList tableStmt
;

tableStmt:              TOK_TABLE atomOrQstring valueList EOS
{
    parseTableList($2);
}                       | EOS
;

mysqlConfig:            TOK_MY_USER atomOrQstring EOS
{
    parseMySQLParams($2, NULL, NULL, NULL, NULL);
}
                        | TOK_MY_PW atomOrQstring EOS
{
    parseMySQLParams(NULL, $2, NULL, NULL, NULL);
}
                        | TOK_MY_DB atomOrQstring EOS
{
    parseMySQLParams(NULL, NULL, $2, NULL, NULL);
}
                       | TOK_MY_HOST atomOrQstring EOS
{
    parseMySQLParams(NULL, NULL, NULL, $2, NULL);
}
                       | TOK_MY_TABLE atomOrQstring EOS
{
    parseMySQLParams(NULL, NULL, NULL, NULL, $2);
};
userIE:                TOK_USERIE VAL_INTEGER atomOrQstring EOS
{
    parseUserInfoElement($2, $3, NULL);
}
                       | TOK_USERIE VAL_INTEGER atomOrQstring VAL_INTEGER EOS
{
    parseUserInfoElement($2, $3, $4);
};

exp_remove_uploaded:     TOK_MY_REMOVE EOS
{
    parseExporterRemoveUploaded();
};

sslConfig:           ssl_config_begin sslList ssl_config_end
{
};

ssl_config_begin:     TOK_SSL_CONFIG atomOrQstring EOS
{
    parseSSLConfigBegin($2);
};
ssl_config_end:       TOK_SSL_CONFIG TOK_END
{
    numValueList = 0;
};
sslList:               sslStmt
                       | sslList sslStmt
;
sslStmt:
                       | issuerList
                       | subjectList
                       | otherList
                       | extensionList
                       | sslCertDedup
                       | sslDedupHitConfig
                       | sslDedupFlushConfig
                       | sslCertFile
                       | ssldedupAddExportName
                       | sslMapStmt
                       | EOS
                       ;

ssldedupAddExportName: TOK_ADD_EXPORT EOS
{
    md_ssl_dedup_configure_state(etemp->ssl_dedup, 0, 0, NULL, NULL, TRUE);
};

sslMapStmt: TOK_MAP LEFT_PAREN atomOrQstring RIGHT_PAREN EOS
{
    parseMapStmt($3);
    md_ssl_dedup_configure_state(etemp->ssl_dedup, 0, 0, NULL, mapitem, FALSE);
    mapitem = NULL;
};

issuerList:            TOK_ISSUER valueList EOS
{
    parseSSLIssuerTypeList();
};

subjectList:           TOK_SUBJECT valueList EOS
{
    parseSSLSubjectTypeList();
};

otherList:             TOK_OTHER valueList EOS
{
    parseSSLOtherTypeList();
};

extensionList:         TOK_EXTENSIONS valueList EOS
{
    parseSSLExtensionsTypeList();
};

sslCertDedup:          TOK_SSL_DEDUP EOS
{
    parseSSLCertDedup();
}

sslDedupHitConfig:    TOK_MAX_HIT VAL_INTEGER EOS
{
    parseSSLMaxHitCount($2);
};

sslDedupFlushConfig:  TOK_FLUSH_SECS VAL_INTEGER EOS
{
    parseSSLMaxFlushTime($2);
};

sslCertFile:         TOK_CERT_FILE atomOrQstring EOS
{
    parseSSLCertFile($2);
};

vlanMap:           vlanMapBegin vlanConfig vlanMapEnd
{
};

vlanMapBegin:      TOK_VLAN_MAP atomOrQstring EOS
{
    parseVlanMapBegin($2);
};

vlanConfig:          vlanStmt
                     | vlanConfig vlanStmt

vlanStmt:            vlanListItem
                     | vlanListOther
                     | vlanListDiscard
                     | EOS
;

vlanListItem:       atomOrQstring valueList EOS
{
    parseVlanMapLine($1);
};

vlanMapEnd:         TOK_VLAN_MAP TOK_END
{
    parseMapEnd();
};

vlanListOther:      atomOrQstring TOK_OTHER EOS
{
    parseMapOther($1);
};

vlanListDiscard:    TOK_DISCARD EOS
{
    parseMapDiscard();
};

obidMap:           obidMapBegin obidConfig obidMapEnd
{
};

obidMapBegin:     TOK_OBID_MAP atomOrQstring EOS
{
    parseObidMapBegin($2);
};

obidConfig:        obidStmt
                   | obidConfig obidStmt
;

obidStmt:          obidListItem
                   | obidListOther
                   | obidListDiscard
                   | EOS
;

obidListItem:      atomOrQstring valueList EOS
{
    parseObidMapLine($1);
};

obidMapEnd:       TOK_OBID_MAP TOK_END
{
    parseMapEnd();
};

obidListOther:      atomOrQstring TOK_OTHER EOS
{
    parseMapOther($1);
};

obidListDiscard:     TOK_DISCARD EOS
{
    parseMapDiscard();
};

atomOrQstring:         VAL_ATOM | VAL_QSTRING
;

%%

static void validateConfFile(
    void)
{
    if (ebeg == NULL) {
        mediator_config_error("No Exporter Information Given. "
                              " Need an Exporter or DEDUP File.\n");
    }

    md_config.flowexit = ebeg;
    md_config.flowsrc = ctemp;
    md_config.maps = maptemp;

}

static void parseCollectorBegin(
    mdTransportType_t mode,
    char              *name)
{

    switch(mode) {
      case UDP:
        md_ip_intransport = UDP;
        break;
      case TCP:
        md_ip_intransport = TCP;
        break;
      case SPREAD:
        md_ip_intransport = SPREAD;
        break;
      case FILEHANDLER:
        md_ip_intransport = FILEHANDLER;
        break;
      case DIRECTORY:
        md_ip_intransport = DIRECTORY;
        break;
      default:
        mediator_config_error("Unacceptable transport mode for exporter");
    }

    coll_temp = mdNewFlowCollector(mode, name);
    free(name);

}

static void parseCollectorPort(
    char   *port)
{
    if ((md_ip_intransport == TCP) || (md_ip_intransport == UDP)) {

        if (atoi(port) < 1024) {
            mediator_config_error("Invalid Port.  Port must be above 1024.\n");
            free(port);
            return;
        }

        mdCollectorSetPort(coll_temp, port);
    } else {

        mediator_config_error("PORT only valid for TCP or UDP Collectors\n");
        free(port);
        return;
    }

    free(port);
}

static void parseCollectorHost(
    char   *host)
{
    if ((md_ip_intransport == TCP) || (md_ip_intransport == UDP) ||
        (md_ip_intransport == SPREAD)) {
        mdCollectorSetInSpec(coll_temp, host);
    } else {
        mediator_config_error("HOSTNAME only valid for TCP or UDP Collectors\n");
    }

    free(host);
}


static void parseCollectorFile(
    char   *file)
{
    if ((md_ip_intransport == TCP) || (md_ip_intransport == UDP) ||
        (md_ip_intransport == SPREAD)) {
        mediator_config_error("PATH and FILE only valid for FILEHANDLER Collectors\n");
    } else if (md_ip_intransport == DIRECTORY) {
        mdCollectorSetPollTime(coll_temp, "30");
        mdCollectorSetInSpec(coll_temp, file);
    } else {
        if (g_file_test(file, G_FILE_TEST_IS_DIR)) {
            mdCollectorSetPollTime(coll_temp, "30");
            mdCollectorSetInSpec(coll_temp, file);
        } else {
            mdCollectorSetInSpec(coll_temp, file);
        }
    }

    free(file);
}

static void parseCollectorWatchDir(
    char *poll_time)
{

    if ((md_ip_intransport == TCP || md_ip_intransport == UDP) ||
        (md_ip_intransport == SPREAD))
    {
        mediator_config_error("Invalid Keyword: POLL only valid for "
                "FILEHANDLER or DIR  Collectors\n");
    } else {
        if (atoi(poll_time) > 65535) {
            mediator_config_error("POLL has max of 65535\n");
        }
        mdCollectorSetPollTime(coll_temp, poll_time);
    }
    free(poll_time);
}

static void parseCollectorSpreadDaemon(
    char   *daemon_name)
{

    if ((md_ip_intransport != SPREAD)) {
        mediator_config_error("Invalid Keyword: Collector NOT configured for SPREAD.\n");
        return;
    }
#if HAVE_SPREAD
    mdCollectorSetInSpec(coll_temp, daemon_name);
#else
    mediator_config_error("Mediator not configured with Spread Support. \n"
           "Confirm Spread is installed.\n");
#endif
    free(daemon_name);
}

static void parseCollectorSpreadGroup(
    char   *group)
{
    if (md_ip_intransport != SPREAD) {
        mediator_config_error("Invalid keyword: Collector NOT configured for SPREAD.\n");
        return;
    }
#if HAVE_SPREAD
    mdCollectorAddSpreadGroup(coll_temp, group, num_in_groups);
    num_in_groups++;
#else
    mediator_config_error("Mediator not configured with Spread Support. \n"
           "Confirm Spread is installed.\n");
#endif
    free(group);
}

static void parseCollectorLock(
    void)
{

    if (md_ip_intransport != DIRECTORY) {
        mediator_config_error("Invalid Keyword: LOCK must be used with DIR Collector");
    } else {
        mdCollectorSetLockMode(coll_temp, TRUE);
    }

}

static void parseCollectorDecompressDirectory(
    char *path)
{
    if ((md_ip_intransport != FILEHANDLER) &&(md_ip_intransport != DIRECTORY))
    {
        mediator_config_error ("Invalid Keyword: DECOMPRESS must be used with a "
                               "FILEHANDLER or DIR Collector");
    }

    mdCollectorSetDecompressDir(coll_temp, path);

    free(path);
};

static void parseCollectorMovePath(
    char   *path)
{

    if ((md_ip_intransport != FILEHANDLER) &&(md_ip_intransport != DIRECTORY))
    {
        mediator_config_error ("Invalid Keyword: MOVE must be used with a "
                 "FILEHANDLER or DIR Collector");
    } else {
        if (!g_file_test(path, G_FILE_TEST_IS_DIR)) {
            mediator_config_error("MOVE expects a valid file directory");
        }

        mdCollectorSetMoveDir(coll_temp, path);
    }

    free(path);
}

static void parseCollectorDelete(
    void)
{

    if ((md_ip_intransport != FILEHANDLER) &&(md_ip_intransport != DIRECTORY))
    {
        mediator_config_error("Invalid Keyword: DELETE must be used "
                              "with FILEHANDLER or DIR Collector");
    } else {
        mdCollectorSetDeleteFiles(coll_temp, TRUE);
    }

}

static void parseCollectorEnd(
    void)
{

    md_collect_node_t *new_node;

    if (coll_temp == NULL) {
        mediator_config_error("Collector is undefined\n");
    }

    if (!mdCollectorVerifySetup(coll_temp, NULL)) {
        exit(-1);
    }

#if HAVE_SPREAD
    if (md_ip_intransport == SPREAD) {
        if (num_in_groups == 0) {
            mediator_config_error("SPREAD Collector Requires AT LEAST ONE group.");
        }
    }
#endif

    new_node = md_new_collect_node();
    new_node->coll = coll_temp;
    new_node->filter = ftemp;
    if (new_node->filter) {
        md_filter_t *nnode = NULL;
        md_filter_t *fnode = new_node->filter;

        while (fnode) {
            nnode = fnode->next;
            if (fnode->field == COLLECTOR) {
                mediator_config_error("FILTER invalid: COLLECTOR field not valid"
                                      " in COLLECTOR block.");
            }
            fnode = nnode;
        }
    }

    new_node->and_filter = and_filter;

    attachHeadToSLL((mdSLL_t **)&(ctemp), (mdSLL_t *)new_node);

    temp_list = NULL;
    coll_temp = NULL;
    ftemp = NULL;
    and_filter = FALSE;
    numValueList = 0;
    md_ip_intransport = NONE;
#if HAVE_SPREAD
    num_in_groups=0;
#endif
}

static void parseFilterBegin(
    void)
{
    g_warning("Filter blocks outside of COLLECTOR or EXPORTER blocks will "
              "apply to all COLLECTORS.");
}

static void parseFilterEnd(
    void)
{
    md_collect_node_t *cnode = NULL;

    if (ftemp == NULL) {
        mediator_config_error("No Filters Found\n");
    }

    for (cnode = ctemp; cnode; cnode = cnode->next) {
        if (!cnode->filter) {
            cnode->filter = ftemp;
        } else {
            md_filter_t *new_filter = md_new_filter_node();
            memcpy(new_filter, ftemp, sizeof(md_filter_t));
            attachHeadToSLL((mdSLL_t **)&(cnode->filter),
                            (mdSLL_t *)new_filter);
            /* remove next reference */
        }
    }

    md_config.shared_filter = TRUE;

    ftemp = NULL;
}


static void parseExporterBegin(
    mdTransportType_t mode,
    char              *name)
{

    switch (mode) {
      case TEXT:
        md_ipfix_outtransport = TEXT;
        break;
      case UDP:
        md_ipfix_outtransport = UDP;
        break;
      case TCP:
        md_ipfix_outtransport = TCP;
        break;
      case SPREAD:
        md_ipfix_outtransport = SPREAD;
        if (!spread_exporter) {
            spread_exporter = TRUE;
        } else {
            mediator_config_error("Error: Only ONE Spread Exporter Permitted");
        }
        break;
      case DIRECTORY:
      case FILEHANDLER:
        md_ipfix_outtransport = FILEHANDLER;
        break;
      default:
        mediator_config_error("Unacceptable transport mode for exporter");
    }

    exp_temp = mdNewFlowExporter(mode);
    if (name) {
        mdExporterSetName(exp_temp, name);
        free(name);
    }
    ssl_dedup_only = FALSE;
}

static void parseExporterPort(
    char   *port)
{

    if (exp_temp == NULL) {
        mediator_config_error("Flow Exporter Not Defined\n");
    }

    if ((md_ipfix_outtransport == TCP) || (md_ipfix_outtransport == UDP)) {

        if (atoi(port) < 1024) {
            free(port);
            mdExporterFree(exp_temp);
            mediator_config_error("Invalid Export Port.  "
                                  "Port must be above 1024.\n");
            return;
        }

        mdExporterSetPort(exp_temp, port);

    } else {
        free(port);
        mediator_config_error("Invalid Keyword: PORT only valid for "
                              "TCP or UDP Exporter\n");
        return;
    }

    free(port);
}

static void parseExporterHost(
    char   *host)
{
    if (exp_temp == NULL) {
        mediator_config_error("Flow Exporter Not Defined\n");
    }

    if ((md_ipfix_outtransport == TCP) || (md_ipfix_outtransport == UDP)) {

        mdExporterSetHost(exp_temp, host);

    } else {
        mediator_config_error("Invalid Keyword: HOSTNAME only valid "
                              "for TCP or UDP Collectors\n");
        mediatorconf_errors++;
    }

    free(host);
}

static void parseExporterFile(
    char   *file)
{
    if (exp_temp == NULL) {
        mediator_config_error("Flow Exporter Not Defined\n");
    }

    if (md_ipfix_outtransport == TEXT || md_ipfix_outtransport == FILEHANDLER) {
        mdExporterSetFileSpec(exp_temp, file);
    } else {
        mediator_config_error("Invalid Keyword PATH.  Not a defined "
                              "keyword for this Exporter\n");
    }

    free(file);
}

static void parseExporterSpreadDaemon(
    char   *daemon_name)
{
    if (exp_temp == NULL) {
        mediator_config_error("Flow Exporter Not Defined\n");
    }

    if ((md_ipfix_outtransport != SPREAD)) {
        mediator_config_error("Invalid keyword: DAEMON only valid for "
                              "SPREAD Exporter\n");
    }
#if HAVE_SPREAD
    mdExporterSetFileSpec(exp_temp, daemon_name);
#else
    mediator_config_error("Spread is not enabled. "
                          "Confirm Spread is Installed\n");
#endif

    free(daemon_name);
}

static void parseExporterSpreadGroup(
    char   *group)
{
    if (md_ipfix_outtransport != SPREAD) {
        mediator_config_error("Invalid keyword: Exporter NOT "
                              "configured for SPREAD.\n");
    }

#if HAVE_SPREAD
    if (md_config.out_spread.groups != NULL) {
        int     n = 0;
        n = num_out_groups + 2;
        md_out_groups = (char **)g_renew(char *, md_out_groups, n);
        md_out_groups[num_out_groups] = g_strdup(group);
        md_out_groups[n-1] = (char *)'\0';
        md_config.out_spread.groups = md_out_groups;
        sftemp = md_new_spread_node();
        sftemp->group = md_out_groups[num_out_groups];
        attachHeadToSLL((mdSLL_t **)&(md_config.mdspread),
                        (mdSLL_t *)sftemp);
        sftemp = NULL;
        num_out_groups++;
    } else {
        md_out_groups = (char **)g_new0(char *, 2);
        md_out_groups[0] = g_strdup(group);
        md_out_groups[1] = (char *)'\0';
        md_config.out_spread.groups = md_out_groups;
        sftemp = md_new_spread_node();
        sftemp->group = md_out_groups[num_out_groups];
        attachHeadToSLL((mdSLL_t **)&(md_config.mdspread),
                        (mdSLL_t *)sftemp);
        sftemp = NULL;
        num_out_groups++;
    }
#else
    mediator_config_error("Mediator not configured with Spread Support. \n"
            "Confirm Spread is installed.\n");
#endif
    free(group);
}

static void parseExporterLock(
    void)
{
    if (exp_temp == NULL) {
        mediator_config_error("Flow Exporter Not Defined\n");
    }

    if (md_ipfix_outtransport != FILEHANDLER && md_ipfix_outtransport != TEXT) {
        mediator_config_error("Invalid Keyword: LOCK only valid for "
                              "TEXT or FILEHANDLER Exporters.\n");
    }

    mdExporterSetLock(exp_temp);

}

static void parseExporterNoFlowStats(
    void)
{
    if (exp_temp == NULL) {
        mediator_config_error("Flow Exporter Not Defined\n");
    }

    mdExporterSetNoFlowStats(exp_temp);
}

static void parseExporterJson(
    void)
{
    if (exp_temp == NULL) {
        mediator_config_error("Flow Exporter Not Defined\n");
    }

    mdExporterSetJson(exp_temp);
}

static void parseExporterRotateSeconds(
    char     *secs)
{

    uint32_t rotate = 0;

    if (exp_temp == NULL) {
        mediator_config_error("Flow Exporter Not Defined\n");
    }

    if (md_ipfix_outtransport != FILEHANDLER && md_ipfix_outtransport != TEXT) {
        mediator_config_error("Invalid Keyword: ROTATE only valid for "
                              "TEXT or FILEHANDLER Exporters.\n");
    }

    rotate = atoi(secs);

    if (rotate <= 0) {
        mediator_config_error("Invalid ROTATE Seconds. "
                              "Must be greater than 0.\n");
    }

    mdExporterSetRotate(exp_temp, rotate);

    free(secs);
}

static void parseExporterUDPTimeout(
    char *mins)
{

    if (md_ipfix_outtransport != UDP) {
        mediator_config_error("Invalid Keyword: UDP TEMPLATE TIMEOUT "
                              "only valid for UDP Exporters.\n");
    } else {
        md_config.udp_template_timeout = atoi(mins);
    }

    if (md_config.udp_template_timeout <= 0) {
        mediator_config_error("Invalid UDP Timeout: Must be greater than "
                              "0 minutes.\n");
    }

    free(mins);
}

static void parseExporterEnd(
    void)
{
    md_export_node_t *new_node;
    gboolean dns_dedup;
    int i;

    if (exp_temp == NULL) {
        mediator_config_error("Exporter is Undefined\n");
    }

    dns_dedup = mdExporterGetDNSDedupStatus(exp_temp);

    new_node = md_new_export_node(dns_dedup, FALSE);
    new_node->exp = exp_temp;
    new_node->filter = ftemp;
    new_node->and_filter = and_filter;
    if (ssl_dedup_only) {
        new_node->ssl_dedup = md_ssl_new_dedup_state();
    }
    attachHeadToSLL((mdSLL_t **)&(ebeg),
                    (mdSLL_t *)new_node);

    if (temp_list) {
        mdExportCustomList(new_node->exp, temp_list);
    }

    if (numValueList > 0) {
        if (md_ipfix_outtransport != TEXT) {
            mediator_config_error("DPI_FIELD_LIST only valid for TEXT "
                                  "exporters.\n");
        }
        for (i = 0; i < numValueList; i++) {
            mdInsertDPIFieldItem(exp_temp, valueListTemp[i]);
        }
    }

    /*if (!mdExporterVerifySetup(exp_temp)) {
        exit(-1);
        }*/

    new_node->md5_hash = md5_filter;
    new_node->sha1_hash = sha1_filter;


    temp_list = NULL;
    exp_temp = NULL;
    ftemp = NULL;
    and_filter = FALSE;
    numValueList = 0;
    numCustomList = 0;
    md5_filter = FALSE;
    sha1_filter = FALSE;
    md_ipfix_outtransport = NONE;
    ssl_dedup_only = FALSE;
}

static void parseExporterTextDelimiter(
    char *delim)
{

    if (md_ipfix_outtransport != TEXT) {
        mediator_config_error("Invalid Keyword.  DELIMITER requires "
                              "TEXT Exporter.\n");
    }

    if (exp_temp == NULL) {
        mediator_config_error("Undefined Exporter\n");
    }

    if (strlen(delim) != 1) {
        mediator_config_error("Invalid Text Delimiter.  Text Delimiter "
                              "may only be 1 character.\n");
    }

    mdExporterSetDelim(exp_temp, delim);

    free(delim);
}

static void parseExporterDPIDelimiter(
    char *delim)
{

    if (md_ipfix_outtransport != TEXT) {
        mediator_config_error("Invalid Keyword.  DELIMITER requires "
                              "TEXT Exporter.\n");
    }

    if (exp_temp == NULL) {
        mediator_config_error("Undefined Exporter\n");
    }

    if (strlen(delim) != 1) {
        mediator_config_error("Invalid Text Delimiter.  Text Delimiter "
                              "may only be 1 character.\n");
    }

    mdExporterSetDPIDelim(exp_temp, delim);

    free(delim);
}

static void parseExporterFlowOnly(
    void)
{
    if (exp_temp == NULL) {
        mediator_config_error("Undefined Exporter\n");
    }

    if (!mdExporterSetFlowOnly(exp_temp)) {
        mediator_config_error("DPI_ONLY, DNS_DEDUP, SSL_DEDUP, "
                              " DEDUP_ONLY, or DNS_RR_ONLY also specified. "
                              " Only one can be listed for an exporter");
    }

}

static void parseExporterSetAndFilter(
    void)
{
    if (exp_temp == NULL) {
        mediator_config_error("Undefined Exporter\n");
    }

    and_filter = TRUE;

}

static void parseExporterDPIOnly(
    void)
{
    if (exp_temp == NULL) {
        mediator_config_error("Undefined Exporter\n");
    }

    if (!mdExporterSetDPIOnly(exp_temp)) {
        mediator_config_error("FLOW_ONLY or DNS_DEDUP_ONLY or"
                              " SSL_DEDUP_ONLY also specified.  "
                              "Only one can be listed for an exporter\n");
    }
}


static void parseExporterRemoveEmpty(
    void)
{

    if (exp_temp == NULL) {
        mediator_config_error("Undefined Exporter\n");
    }

    if (md_ipfix_outtransport != TEXT && md_ipfix_outtransport != FILEHANDLER){
        mediator_config_error("REMOVE_EMPTY_FILES only valid for TEXT "
                              "or FILEHANDLER Exporter\n");
    }

    mdExporterSetRemoveEmpty(exp_temp);
}

static void parseExporterNoStats(
    void)
{
    if (exp_temp == NULL) {
        mediator_config_error("Undefined Exporter\n");
    }

    mdExporterSetStats(exp_temp, 1);

}

static void parseExporterAddStats(
    void)
{
    if (exp_temp == NULL) {
        mediator_config_error("Undefined Exporter\n");
    }
    mdExporterSetStats(exp_temp, 2);
}

static void parseExporterPrintHeader(
    void)
{

    if (exp_temp == NULL) {
        mediator_config_error("Undefined Exporter\n");
    }

    if (md_ipfix_outtransport != TEXT) {
        mediator_config_error("PRINT_HEADER Keyword only available "
                              "for TEXT Exporter\n");
    }

    mdExporterSetPrintHeader(exp_temp);
}

static void parseExporterEscapeChars(
    void)
{
    if (exp_temp == NULL) {
        mediator_config_error("Undefined Exporter\n");
    }

    if (md_ipfix_outtransport != TEXT) {
        mediator_config_error("ESCAPE_CHARS keyword only available "
                              "for TEXT Exporters\n");
    }

    mdExporterSetEscapeChars(exp_temp);
}

static void parseExporterDNSRROnly(
    int              mode)
{
    if (exp_temp == NULL) {
        mediator_config_error("Undefined Exporter\n");
    }

    if (md_ipfix_outtransport == TEXT) {
        mediator_config_error("DNS_RR_ONLY keyword only available "
                              "for IPFIX (TCP, UDP, SPREAD, FILEHANDLER) "
                              "Exporters\n");
    }

    if (!mdExporterSetDNSRROnly(exp_temp, mode)) {
        mediator_config_error("FLOW_ONLY, DPI_ONLY, SSL_DEDUP_ONLY, "
                              "DNS_DEDUP_ONLY, or DEDUP_ONLY not permitted with "
                              "DNS_RR_ONLY");
    }
}

static void parseExporterDNSRespOnly(
    void)
{
    if (exp_temp == NULL) {
        mediator_config_error("Undefined Exporter\n");
    }

    mdExporterSetDNSRespOnly(exp_temp);
}

static void parseExporterDedupPerFlow(
    void)
{
    if (exp_temp == NULL) {
        mediator_config_error("Undefined Exporter\n");
    }

    mdExporterDedupPerFlow(exp_temp);
}

static void parseExporterNoIndex(
    void)
{
    if (exp_temp == NULL) {
        mediator_config_error("Undefined Exporter\n");
    }

    if (md_ipfix_outtransport != TEXT) {
        mediator_config_error("NO_INDEX Keyword only valid for "
                              "TEXT Exporters\n");
    }

    mdExporterSetNoIndex(exp_temp, TRUE);
}

static void parseExporterNoFlow(
    void)
{
    if (exp_temp == NULL) {
        mediator_config_error("Undefined Exporter\n");
    }

    mdExporterSetNoFlow(exp_temp);
}

static void parseExporterTimestamp(
    void)
{
    if (exp_temp == NULL) {
        mediator_config_error("Undefined Exporter\n");
    }

    if (md_ipfix_outtransport != TEXT) {
        mediator_config_error("TIMESTAMP_FILES Keyword only valid for "
                              "TEXT Exporters\n");
    }

    mdExporterSetTimestampFiles(exp_temp);
}


static void parseExporterMultiFiles(
    void)
{
    if (exp_temp == NULL) {
        mediator_config_error("Undefined exporter\n");
    }

    if (md_ipfix_outtransport != TEXT) {
        mediator_config_error("MULTI_FILES keyword only valid for TEXT "
                              "Exporters\n");
    }

    if (!mdExportMultiFiles(exp_temp)) {
        mediator_config_error("MULTI_FILES configuration error.\n");
    }
}

static void parseExporterMetadataExport(void)
{
    if (exp_temp == NULL) {
        mediator_config_error("Undefined Exporter\n");
    }
#if SM_ENABLE_METADATA_EXPORT
    mdExporterSetMetadataExport(exp_temp);
#else
    mediator_config_error("Mediator not configured with metadata(type) export enabled. \n");
#endif
}

static void parseSpreadGroup(
    char *name)
{

    gboolean found = FALSE;

    if (!spread_exporter) {
        mediator_config_error("Invalid Group Block.  One Exporter must be "
                              "configured for Spread Transport\n");
    }

    for (sftemp = md_config.mdspread; sftemp; sftemp = sftemp->next) {
        if (strcmp(name, sftemp->group) == 0) {
            found = TRUE;
            break;
        }
    }

    if (!found) {
        mediator_config_error("Group must exist in EXPORTER GROUP.\n");
    }

    ftemp = sftemp->filterList;

    free(name);
}

static void parseSpreadGroupEnd(
    void)
{

    if (ftemp == NULL) {
        mediator_config_error("No Spread Exporter Filters Found\n");
    }

    sftemp->filterList = ftemp;

    ftemp = NULL;
    sftemp = NULL;
}

static void parseStatsTimeout(
    char *timeout)
{
    md_stats_timeout = atoi(timeout);
    free(timeout);
}

static void parseLogConfig(
    char *log_file)
{
    md_logfile = g_strdup(log_file);
    free(log_file);
}

static void parseLogDir(
    char *log_dir)
{
    md_logdest = g_strdup(log_dir);
    free(log_dir);
}

static void parsePidFile(
    char *pid_file)
{
    md_pidfile = g_strdup(pid_file);
    free(pid_file);
}

static void parseStatisticsConfig(
    void)
{
    md_config.no_stats = TRUE;
}

static void parseDNSDeDupConfig(
    void)
{
    if (exp_temp == NULL) {
        mediator_config_error("Undefined Exporter\n");
    }

    mdExporterSetDNSDeDup(exp_temp);

}

static void parseDNSDeDupOnly(
    void)
{
    if (exp_temp == NULL) {
        mediator_config_error("Undefined Exporter\n");
    }

    if (!mdExporterSetDNSDeDupOnly(exp_temp)) {
        mediator_config_error("FLOW_ONLY OR DPI_ONLY not permitted with "
                              "DNS_DEDUP_ONLY");
    }
}

static void parseComparison(
    mdAcceptFilterField_t field,
    fieldOperator         oper,
    char                  *val,
    int                   val_type)
{
    int rv;
    uint32_t ip;
    uint8_t  ip6[16];
    md_collect_node_t *cnode = NULL;
    md_filter_t *filter = md_new_filter_node();

    if (field > 15) {
        if (field != INGRESS && field != EGRESS && field != COLLECTOR) {
            mediator_config_error("Invalid Filter Field.  "
                                  "Please refer to documentation for "
                                  "acceptable filter fields.");
        }
    }

    filter->field = field;

    filter->oper = oper;

    if (val_type == VAL_INTEGER) {
        filter->val[filter->num_in_list] = atoi(val);
    } else if (val_type == VAL_IP) {
        switch (field) {
          case SIP_V4:
          case DIP_V4:
          case ANY_IP:
          case SIP_ANY:
          case DIP_ANY:
            if ((inet_pton(AF_INET, val, (struct in_addr *)&ip) <= 0)) {
                mediator_config_error("Invalid IPv4 Address\n");
            }
            filter->val[filter->num_in_list] = g_ntohl(ip);
            break;
          case SIP_V6:
          case DIP_V6:
          case ANY_IP6:
            if (inet_pton(AF_INET6, val, ip6) <= 0) {
                mediator_config_error("Invalid IPv6 Address\n");
            }
            memcpy(filter->val, ip6, 16);
            break;
          default:
            mediator_config_error("Invalid Filter Field for IP Address");
        }
    } else if ((field == COLLECTOR) && !(oper == EQUAL || oper == NOT_EQUAL)) {
        mediator_config_error("COLLECTOR Filter must use EQUAL/NOT_EQUAL operator");
    } else if (val_type == VAL_QSTRING && (oper == IN_LIST || oper == NOT_IN_LIST)) {
        switch (field) {
          case SIP_V4:
          case DIP_V4:
          case ANY_IP:
          case SIP_V6:
          case DIP_V6:
          case ANY_IP6:
          case SIP_ANY:
          case DIP_ANY:
            break;
          default:
            mediator_config_error("Invalid Filter Field for "
                                  "IN_LIST/NOT_IN_LIST operator");
        }
#ifdef ENABLE_SKIPSET
        if (!g_file_test(val, G_FILE_TEST_EXISTS)) {
            mediator_config_error("Can't open file IPSET file.");
        }

        filter->ipset = NULL;

        if (!app_registered) {
            skAppRegister("super_mediator");
            app_registered++;
        }

        rv = skIPSetLoad((skipset_t **)&(filter->ipset), val);

        if (rv != SKIPSET_OK) {
            fprintf(stderr, "Could not load IPset: %s\n", skIPSetStrerror(rv));
            mediator_config_error("Error occured loading IPSet file.");
        }

        if (!skIPSetIsV6(filter->ipset)) {
            if ((field == SIP_V6) || (field == DIP_V6) || (field == ANY_IP6)) {
                mediator_config_error("Given IPSet not configured to store "
                                      "IPv6 Addresses");
            }
        } else {
            if ((field == SIP_V4) || (field == DIP_V4)) {
                g_warning("IPSet configured for IPv6 but filtering on IPv4 "
                          "Address.");
            }
        }

#else
        mediator_config_error("NO SUPPORT FOR IPSETs.  Please Install "
                              "SiLK IPSet Library.");
#endif

    } else if (field == COLLECTOR) {
        int num = 1;
        for (cnode = ctemp; cnode; cnode = cnode->next) {
            char *name = mdCollectorGetName(cnode);
            if (!(strcmp(name, val))) {
                filter->val[filter->num_in_list] = mdCollectorGetID(cnode);
            }
            num++;
        }
        if (filter->val[filter->num_in_list] == 0) {
            mediator_config_error("No COLLECTOR with given name.");
        }
    } else {
        mediator_config_error("Invalid comparison for filter.");
    }

    filter->num_in_list++;

    attachHeadToSLL((mdSLL_t **)&(ftemp),
                    (mdSLL_t *)filter);

    free(val);
}

static void parseMapStmt(
    char *mapname)
{
    smFieldMap_t *map = NULL;

    if (mapitem != NULL) {
        mediator_config_error("MAP already defined for this DEDUP config block.");
    }

    if (mapname) {
        map = maptemp;
        if (!map) {
            mediator_config_error("NO Previous MAPS defined in configuration file.");
        }
        do {
            if (strcmp(map->name, mapname) == 0) {
                break;
            }
        } while ((map = map->next));

        if (map == NULL) {
            mediator_config_error("NO MAPS defined with the name.");
        }

       free(mapname);
    }

    mapitem = map;
}



static void parseDNSMaxHitCount(
    char *count)
{
    int ct = atoi(count);

    if (ct <= 65535) {
        max_hit = ct;
    } else {
        mediator_config_error("MAX_HIT_COUNT has max of 65535");
    }
    free(count);
}

static void parseDNSMaxFlushTime(
    char *flushtime)
{
    int ti = atoi(flushtime);
    if (ti <= 65535) {
        flush_timeout = ti;
    } else {
        mediator_config_error("FLUSH_TIME has max of 65535");
    }
    free(flushtime);
}

static void parseTableListBegin(
    char *index_label)
{
    void *currentTable = NULL;

    if (default_tables) {
        mediator_config_error("Error: Default Tables already defined. "
                              "Remove application label from USER_IE line "
                              "to build custom tables.");
    }

    custom_tables = TRUE;

    if (index_label == NULL) {
        currentTable = mdNewTable(INDEX_DEFAULT);
    } else {
        currentTable = mdNewTable(index_label);
    }

    if (!mdInsertTableItem(currentTable, 0)) {
        mediator_config_error("Error Creating Index Table for DPI Config.");
    }

    if (index_label) {
        g_free(index_label);
    }
}


static void parseTableList(
    char *table)
{

    int i = 0;
    void *currentTable = NULL;

    if (numValueList == 0) {
        mediator_config_error("No items in List.");
    }

    currentTable = mdNewTable(table);

    for (i = 0; i < numValueList; i++) {
        if (!mdInsertTableItem(currentTable, valueListTemp[i])) {
            mediator_config_error("Item can not be present in another list.");
        }
    }

    free(table);
}


static void parseDedupRecordTypeList(
    void)
{
    int i;

    dedup_type_list = g_new0(int, 35);

    if (numValueList == 0) {
        mediator_config_error("No items in list.");
    }

    for (i = 0; i < numValueList; i++) {
        /* turn types of records "on" */
        if (valueListTemp[i] > 34) {
            mediator_config_error("Invalid RECORD Type. "
                                  "Valid Types: 0,1,2,5,6,12,15,16,28,33");
        }
        dedup_type_list[valueListTemp[i]] = 1;
    }

    numValueList = 0;

}

static void parseValueListItems(
    char  *val)
{
    int value = atoi(val);

    if (value < 0 || value > 65535) {
        mediator_config_error("Item too large for list. "
                              " Must be between 1 - 65535.");
    }

    valueListTemp[numValueList] = value;
    numValueList++;

    free(val);

}

static void parseFieldListItems(
    char                  *fint,
    mdAcceptFilterField_t field)
{

    mdFieldList_t *item = NULL;

    if (md_ipfix_outtransport != TEXT) {
        mediator_config_error("Custom List FIELDS only valid for "
                              "TEXT exporters.");
    }


    numCustomList++;

    if (fint) {
        field = atoi(fint);
    }

    if (field == DPI) {
        mdExporterCustomListDPI(exp_temp);
        return;
    }

    item = mdCreateFieldList(field);
    if (!item) {
        fprintf(stderr, "Invalid Custom Field Item. Item # %d in list (%d)\n",
                numCustomList, field);
        mediator_config_error("Invalid Custom Field Item");
    }


    if (temp_list == NULL) {
        temp_list = item;
    } else {
        mdFieldList_t *f = temp_list;
        while (f->next) {
            f = f->next;
            continue;
        }
        f->next = item;
    }

    if (fint) {
        free(fint);
    }
}


static void parseMySQLParams(
    char *user,
    char *pw,
    char *db,
    char *host,
    char *table)
{
    if (exp_temp == NULL) {
        mediator_config_error("Undefined Exporter\n");
    }

    if (!mdExporterAddMySQLInfo(exp_temp, user, pw, db, host, table)) {
        exit(-1);
    }
    free(user);
    free(pw);
    free(db);
    free(host);
    free(table);
}

static void parseExporterRemoveUploaded(
    void)
{

    if (exp_temp == NULL) {
        mediator_config_error("Undefined Exporter\n");
    }

    mdExporterSetRemoveUploaded(exp_temp);
}


static void parseUserInfoElement(
    char     *num,
    char     *name,
    char     *app)
{

    int ie_num = atoi(num);
    int app_num = 0;
    void *table = NULL;
    fbInfoElement_t add_element;

    if (app) {
        app_num = atoi(app);
    }

    if (ie_num > 65535) {
        mediator_config_error("Invalid Information Element ID number. "
                              "Number must be between 0 and 65535");
    }

    if (app_num > 65535) {
        mediator_config_error("Invalid Information Element ID number. "
                              "Number must be between 0 and 65535");
    }

    if (user_elements == NULL) {
        user_elements = g_new0(fbInfoElement_t, 50);
    } else if (numUserElements > 50) {
        mediator_config_error("Max Limit reached on adding user-defined"
                              " Information Elements");
    }

    memset(&add_element, 0, sizeof(fbInfoElement_t));

    add_element.num = ie_num;
    add_element.ent = 6871;
    add_element.len = FB_IE_VARLEN;
    add_element.ref.name = g_strdup(name);
    add_element.midx = 0;
    add_element.flags = 0;

    memcpy((user_elements + numUserElements), &add_element,
           sizeof(fbInfoElement_t));

    numUserElements++;

    if (app_num) {

        if (custom_tables) {
            mediator_config_error("Invalid application label for USER_IE "
                                  "Add Information Element Number to DPI_CONFIG tables.");
        }

        if (!default_tables) {
            mdBuildDefaultTableHash();
            default_tables = TRUE;
        }

        table = mdGetTable(app_num);

        if (!table) {
            mediator_config_error("Not a valid application label for USER_IE");
        }

        if (!mdInsertTableItem(table, ie_num)) {
            mediator_config_error("Information Element already defined.");
        }
    }

    free(num);
    free(app);
    free(name);
}


static void parseDNSDedupConfigEnd(
    void)
{
    gboolean found = FALSE;
    md_export_node_t *cnode = NULL;

    for (cnode = ebeg; cnode; cnode = cnode->next) {
        if (dedup_temp_name) {
            if (mdExporterCompareNames(cnode->exp, dedup_temp_name)) {
                if (cnode->dns_dedup) {
                    exp_temp = cnode->exp;
                    found = TRUE;
                    break;
                } else {
                    mediator_config_error("Exporter for DNS_DEDUP config"
                                          " block does not have DNS_DEDUP enabled.");
                }
            }
        } else if (cnode->dns_dedup) {
            exp_temp = cnode->exp;
            found = TRUE;
            break;
        }
    }

    if (!found) {
        mediator_config_error("Exporter name for DNS_DEDUP not found.");
    }

    md_ipfix_outtransport = mdExporterGetType(exp_temp);

    if (cnode->dedup && (md_ipfix_outtransport == TEXT) && !(mdExporterGetJson(exp_temp))) {
        mediator_config_error("Exporter already configured for DEDUP. "
                              "Define a separate TEXT EXPORTER for DNS_DEDUP");
    }

    md_dns_dedup_configure_state(cnode->dns_dedup, dedup_type_list, max_hit,
                                 flush_timeout, lastseen, mapitem, exportname);

    max_hit = 0;
    flush_timeout = 0;
    lastseen = FALSE;
    exportname = FALSE;
    dedup_type_list = NULL;
    free(dedup_temp_name);
    dedup_temp_name = NULL;
    mapitem = NULL;
}

static void parseSSLConfigBegin(
    char *exp_name)
{
    gboolean found = FALSE;
    md_export_node_t *cnode = NULL;

    for (cnode = ebeg; cnode; cnode = cnode->next) {
        if (mdExporterCompareNames(cnode->exp, exp_name)) {
            exp_temp = cnode->exp;
            found = TRUE;
            break;
        }
    }

    if (!found) {
        mediator_config_error("Exporter name for SSL_CONFIG not found.");
    }

    etemp = cnode;

    md_ipfix_outtransport = mdExporterGetType(cnode->exp);

    numValueList = 0;

    free(exp_name);
}

static void parseSSLIssuerTypeList(
    void)
{
    int i;
    int *sslIssuerlist;

    if (exp_temp == NULL) {
        mediator_config_error("Exporter for SSL_CONFIG not found.");
    }

    sslIssuerlist = g_new0(int, 255);

    if (valueListWild) {
        /* TURN THEM ALL ON */
        for (i = 0; i < 255; i++) {
            sslIssuerlist[i] = 1;
        }
        mdExporterSetSSLConfig(exp_temp, sslIssuerlist, 1);
        return;
    }

    if (numValueList == 0) {
        mediator_config_error("No items in ISSUER list.");
    }

    for (i = 0; i < numValueList; i++) {
        if (valueListTemp[i] > 254) {
            mediator_config_error("SSL Issuer List takes only values 0-254");
        }
        /* turn types of records "on" */
        sslIssuerlist[valueListTemp[i]] = 1;
    }


    mdExporterSetSSLConfig(exp_temp, sslIssuerlist, 1);
}

static void parseSSLSubjectTypeList(
    void)
{
    int i;
    int *sslSubjectlist;

    if (exp_temp == NULL) {
        mediator_config_error("Exporter for SSL_CONFIG not found.");
    }

    sslSubjectlist = g_new0(int, 255);

    if (valueListWild) {
        /* TURN THEM ALL ON */
        for (i = 0; i < 255; i++) {
            sslSubjectlist[i] = 1;
        }
        mdExporterSetSSLConfig(exp_temp, sslSubjectlist, 2);
        return;
    }

    if (numValueList == 0) {
        mediator_config_error("No items in SUBJECT list.");
    }

    for (i = 0; i < numValueList; i++) {
        if (valueListTemp[i] > 254) {
            mediator_config_error("SSL Subject List takes only values 0-254");
        }
        /* turn types of records "on" */
        sslSubjectlist[valueListTemp[i]] = 1;
    }

    mdExporterSetSSLConfig(exp_temp, sslSubjectlist, 2);
}


static void parseSSLOtherTypeList(
    void)
{
    int i;
    int *sslOtherList;

    if (exp_temp == NULL) {
        mediator_config_error("Exporter for SSL_CONFIG not found.");
    }

    sslOtherList = g_new0(int, 300);

    if (valueListWild) {
        /* TURN THEM ALL ON */
        for (i = 0; i < 299; i++) {
            sslOtherList[i] = 1;
        }
        mdExporterSetSSLConfig(exp_temp, sslOtherList, 3);
        return;
    }

    if (numValueList == 0) {
        mediator_config_error("No items in OTHER list.");
    }

    for (i = 0; i < numValueList; i++) {
        if (valueListTemp[i] > 299) {
            mediator_config_error("SSL Other List takes only values 0-299");
        }
        sslOtherList[valueListTemp[i]] = 1;
    }

    mdExporterSetSSLConfig(exp_temp, sslOtherList, 3);

}

static void parseSSLExtensionsTypeList(
    void)
{
    int i;
    int *sslExtList;

    if (exp_temp == NULL) {
        mediator_config_error("Exporter for SSL_CONFIG not found.");
    }

    /* yaf only exports id-ce 14-37 */
    sslExtList = g_new0(int, 50);

    if (valueListWild) {
        /* TURN THEM ALL ON */
        for (i = 0; i < 50; i++) {
            sslExtList[i] = 1;
        }
        mdExporterSetSSLConfig(exp_temp, sslExtList, 4);
        return;
    }

    if (numValueList == 0) {
        mediator_config_error("No items in Extensions list.");
    }

    for (i = 0; i < numValueList; i++) {
        if (valueListTemp[i] > 49) {
            mediator_config_error("SSL Extensions List takes only values 0-49");
        }
        switch (valueListTemp[i]) {
          case 14:
          case 15:
          case 16:
          case 17:
          case 18:
          case 29:
          case 31:
          case 32:
            sslExtList[valueListTemp[i]] = 1;
            continue;
          default:
            mediator_config_error("Invalid Extension in SSL EXTENSIONS List."
                                  " super_mediator accepts 14-18, 29, 31, 32");
        }
    }

    mdExporterSetSSLConfig(exp_temp, sslExtList, 4);

}

static void parseDedupConfig(
    char *exp_name)
{
    md_export_node_t *cnode = NULL;
    gboolean found = FALSE;

    for (cnode = ebeg; cnode; cnode = cnode->next) {
        if (exp_name) {
            if (mdExporterCompareNames(cnode->exp, exp_name)) {
                exp_temp = cnode->exp;
                found = TRUE;
                break;
            }
        } else {
            exp_temp = cnode->exp;
            found = TRUE;
            break;
        }
    }
    if (!found) {
        mediator_config_error("Exporter associated with DEDUP_CONFIG does not exist."
                              "  Ignoring DEDUP configuration\n");
    }
    /* set temp node */
    etemp = cnode;

    md_ipfix_outtransport = mdExporterGetType(exp_temp);

    if (cnode->dns_dedup && (md_ipfix_outtransport == TEXT) && !(mdExporterGetJson(exp_temp))) {
        mediator_config_error("Exporter already configured for DNS_DEDUP."
                              " Define a separate TEXT EXPORTER for DEDUP");
    } else if (cnode->ssl_dedup && (md_ipfix_outtransport == TEXT) && !(mdExporterGetJson(exp_temp))) {
        mediator_config_error("Exporter already configured for SSL_DEDUP."
                              " Define a separate TEXT EXPORTER for DEDUP");
    }

    etemp->dedup = md_dedup_new_dedup_state();

    mdExporterSetDeDupConfig(etemp->exp);

    if (exp_name) {
        g_free(exp_name);
    }

    numValueList = 0;
}

static void parseFileList(
    char *file,
    mdAcceptFilterField_t field,
    char *mapname)
{

    int i = 0;
    int sip = 1;
    md_dedup_ie_t *ietab = NULL;
    smFieldMap_t *map = NULL;

    if (numValueList == 0) {
        mediator_config_error("No items in FILE List.");
    }

    switch (field) {
      case SIP_V4:
      case SIP_ANY:
        break;
      case DIP_V4:
      case DIP_ANY:
        sip = 0;
        break;
      case FLOWKEYHASH:
        sip = 2;
        break;
      default:
        mediator_config_error("Invalid Field in DEDUP_CONFIG."
                              "  SIP, DIP, and FLOWKEYHASH are only valid fields.");
    }

    if (mapname) {
        map = maptemp;
        if (!map) {
            mediator_config_error("NO Previous MAPS defined in configuration file.");
        }
        do {
            if (strcmp(map->name, mapname) == 0) {
                break;
            }
        } while ((map = map->next));

        if (map == NULL) {
            mediator_config_error("NO MAPS defined with the name.");
        }
        free(mapname);
    }

    if (md_ipfix_outtransport != TEXT) {
        /* create a table for each element in the list bc it needs a template
           for each element in the list */
        for (i = 0; i < numValueList; i++) {
            ietab = md_dedup_add_ie_table(etemp->dedup, file, map, valueListTemp[i], sip);
            if (!ietab) {
                mediator_config_error("Information Element already in FILE Table.");
            }
        }
    } else {
        ietab = md_dedup_add_ie_table(etemp->dedup, file, map, valueListTemp[0], sip);
        if (!ietab) {
            mediator_config_error("Information Element already in FILE Table.");
        }
        if ((valueListTemp[0] == 244) && (numValueList > 1)) {
            mediator_config_error("244 (SSL) must exist in a list by itself.");
        }
        for (i = 1; i < numValueList; i++) {
            if (valueListTemp[i] == 244) {
                mediator_config_error("244 (SSL) must exist in a list by itself.");
            }
            md_dedup_add_ie(etemp->dedup, ietab, valueListTemp[i]);
        }
    }

    free(file);
    numValueList = 0;
}

static void parseMaxHitCount(
    char *count)
{
    int ct = atoi(count);

    md_dedup_configure_state(etemp->dedup, ct, 0, FALSE, FALSE);

    free(count);
}

static void parseMaxFlushTime(
    char *flushtime)
{
    int ti = atoi(flushtime);

    md_dedup_configure_state(etemp->dedup, 0, ti, FALSE, FALSE);

    free(flushtime);
}

static void parseDedupAddExportName(
    void)
{
    md_dedup_configure_state(etemp->dedup, 0, 0, FALSE, TRUE);
}

static void parseSSLCertDedup(
    void)
{
    if (etemp == NULL) {
        mediator_config_error("No Exporter defined for SSL_CONFIG.");
    }

    if (etemp->dns_dedup && (md_ipfix_outtransport == TEXT) && !(mdExporterGetJson(exp_temp))) {
        mediator_config_error("Exporter already configured for DNS_DEDUP."
                              " Define a separate TEXT EXPORTER for SSL_DEDUP");
    } else if (etemp->dedup && (md_ipfix_outtransport == TEXT) && !(mdExporterGetJson(exp_temp))) {
        mediator_config_error("Exporter already configured for DEDUP."
                              " Define a separate TEXT EXPORTER for SSL_DEDUP");
    }

    /* may have already been enabled with SSL_DEDUP_ONLY */
    if (etemp->ssl_dedup == NULL) {
        etemp->ssl_dedup = md_ssl_new_dedup_state();
        mdExporterSetSSLDeDupConfig(etemp->exp);
    }
}

static void parseSSLMaxHitCount(
    char *count)
{
    int ct = atoi(count);

    md_ssl_dedup_configure_state(etemp->ssl_dedup, ct, 0, NULL, NULL, FALSE);

    free(count);
}

static void parseSSLMaxFlushTime(
    char *flushtime)
{
    int ti = atoi(flushtime);

    md_ssl_dedup_configure_state(etemp->ssl_dedup, 0, ti, NULL, NULL, FALSE);

    free(flushtime);
}

static void parseSSLCertFile(
    char *filename)
{
    if (md_ipfix_outtransport != TEXT) {
        mediator_config_error("CERT_FILE only valid for TEXT Exporters.");
    }

    if (mdExporterGetJson(exp_temp)) {
        mediator_config_error("CERT_FILE not valid with JSON");
    }

    md_ssl_dedup_configure_state(etemp->ssl_dedup, 0, 0, filename, NULL,FALSE);



    free(filename);
}

static void parseSSLDeDupOnly(
    int mode)
{
    if (exp_temp == NULL) {
        mediator_config_error("Undefined Exporter\n");
    }

    if (!mdExporterSetSSLDeDupOnly(exp_temp, mode)) {
        mediator_config_error("FLOW_ONLY or DNS_DEDUP_ONLY or"
                              " DEDUP_ONLY or DNS_RR_ONLY also specified."
                              " Only one can be used per exporter.");
    }

    ssl_dedup_only = TRUE;

}


static void parseExporterDedupOnly(
    void)
{
    if (exp_temp == NULL) {
        mediator_config_error("Undefined Exporter\n");
    }


    if (!mdExporterDedupOnly(exp_temp)) {
        mediator_config_error("FLOW_ONLY or DNS_DEDUP_ONLY or"
                              " SSL_DEDUP_ONLY or DNS_RR_ONLY "
                              "also specified.  Only "
                              " can be used per exporter.");
    }

}

static void parseExporterSSLMD5Hash(
    void)
{
    if (exp_temp == NULL) {
        mediator_config_error("Undefined Exporter\n");
    }
#if HAVE_OPENSSL
    if (!mdExporterSetSSLMD5Hash(exp_temp)) {
        mediator_config_error("ERROR MD5: Exporter already configured with conflicting settings");
    }
    md5_filter = TRUE;

#else
    mediator_config_error("Super_mediator not configured with OpenSSL support");
#endif

}

static void parseExporterSSLSHA1Hash(
    void)
{
    if (exp_temp == NULL) {
        mediator_config_error("Undefined Exporter\n");
    }

#if HAVE_OPENSSL

    if (!mdExporterSetSSLSHA1Hash(exp_temp)) {
        mediator_config_error("ERROR SHA_1: Exporter already configured with conflicting settings");
    }

    sha1_filter = TRUE;
#else
    mediator_config_error("Super_mediator not configured with OpenSSL support");
#endif

}

static void parseExporterGzipFiles(
    void)
{
    if (exp_temp == NULL) {
        mediator_config_error("Undefined Exporter\n");
    }

    mdExporterGZIPFiles(exp_temp);
}

static void parseExporterMovePath(
    char   *path)
{
    if (exp_temp == NULL) {
        mediator_config_error("Undefined Exporter\n");
    }

    if ((md_ipfix_outtransport != FILEHANDLER) && (md_ipfix_outtransport != TEXT))
    {
        mediator_config_error ("Invalid Keyword: MOVE must be used with a "
                               "FILEHANDLER or TEXT EXPORTER");
    } else {
        if (!g_file_test(path, G_FILE_TEST_IS_DIR)) {
            mediator_config_error("MOVE expects a valid file directory");
        }

        mdExporterSetMovePath(exp_temp, path);
    }

    free(path);
}

static void parseVlanMapLine(
    char *label)
{
    uint32_t k = 0;
    uint32_t val = 0;
    smFieldMapKV_t *value;
    smFieldMapKV_t *key;
    int i;

    if (mapitem == NULL) {
        mediator_config_error("Something went wrong");
    }

    if (numValueList == 0) {
        mediator_config_error("No items in VLAN_MAP list.");
    }

    /* need to figure out if count > MAX_MAPS */

    if (mapitem->labels == NULL) {
        mapitem->labels = (char **)calloc(MAX_MAPS, sizeof(char *));
    }
    mapitem->labels[mapitem->count+1] = g_strdup(label);

    val = mapitem->count+1;

    for (i = 0; i < numValueList; i++) {
        k = (uint32_t)valueListTemp[i];
        key = g_slice_new0(smFieldMapKV_t);
        value = g_slice_new0(smFieldMapKV_t);
        value->val = val;
        key->val = k;
        smHashTableInsert(mapitem->table, (uint8_t*)key, (uint8_t*)value);
    }
    mapitem->count++;

    numValueList = 0;
}

static void parseObidMapLine(
    char *label)
{
    uint32_t k = 0;
    uint32_t val = 0;
    smFieldMapKV_t *value;
    smFieldMapKV_t *key;
    int i;

    if (mapitem == NULL) {
        mediator_config_error("Something went wrong");
    }

    if (numValueList == 0) {
        mediator_config_error("No items in VLAN_MAP list.");
    }

    /* need to figure out if count > MAX_MAPS */

    if (mapitem->labels == NULL) {
        mapitem->labels = (char **)calloc(MAX_MAPS, sizeof(char *));
    }

    mapitem->labels[mapitem->count+1] = g_strdup(label);

    val = mapitem->count+1;

    for (i = 0; i < numValueList; i++) {
        k = (uint32_t)valueListTemp[i];
        key = g_slice_new0(smFieldMapKV_t);
        value = g_slice_new0(smFieldMapKV_t);
        value->val = val;
        key->val = k;
        smHashTableInsert(mapitem->table, (uint8_t*)key, (uint8_t*)value);
    }
    mapitem->count++;

    numValueList = 0;
}

static void parseVlanMapBegin(
    char *name)
{
    mapitem = g_slice_new0(smFieldMap_t);

    mapitem->name = g_strdup(name);
    mapitem->table = smCreateHashTable(sizeof(uint32_t),
                                       md_free_hash_key, md_free_hash_key);
    mapitem->field = VLAN;
    numValueList = 0;
    attachHeadToSLL((mdSLL_t **)&(maptemp), (mdSLL_t *)mapitem);
    free(name);
}

static void parseObidMapBegin(
    char *name)
{
    mapitem = g_slice_new0(smFieldMap_t);
    mapitem->name = g_strdup(name);
    mapitem->field = OBDOMAIN;
    numValueList = 0;
    mapitem->table = smCreateHashTable(sizeof(uint32_t), md_free_hash_key,
                                       md_free_hash_key);
    attachHeadToSLL((mdSLL_t **)&(maptemp), (mdSLL_t *)mapitem);
    free(name);
}

static void parseMapEnd(void)
{
    if (mapitem == NULL) {
        mediator_config_error("Something went wrong");
    }

    if (mapitem->labels == NULL) {
        mediator_config_error("Error: No labels were created in MAP block.");
    }

    if ((mapitem->labels[0] == NULL) && !mapitem->discard) {
        mediator_config_error("Must specify either OTHER Map List or DISCARD_OTHER");
    }

    mapitem = NULL;
}

static void parseMapOther(
    char *name)
{
    if (mapitem == NULL) {
        mediator_config_error("Something went wrong");
    }

    if (mapitem->labels == NULL) {
        mapitem->labels = (char **)calloc(MAX_MAPS, sizeof(char *));
    }

    if (mapitem->discard) {
        mediator_config_error("DISCARD_OTHER not valid with OTHER list");
    }

    mapitem->labels[0] = g_strdup(name);
    mapitem->count++;

}

static void parseMapDiscard()

{

    if (mapitem == NULL) {
        mediator_config_error("Something went wrong");
    }

    if (mapitem->labels[0] != NULL) {
        mediator_config_error("OTHER is not valid with DISCARD_OTHER");
    }

    mapitem->discard = TRUE;

}


int yyerror(const char *s)
{

    /* mediator config error subtracts one */
    lineNumber++;
    mediator_config_error(s);
    return 0;
}

