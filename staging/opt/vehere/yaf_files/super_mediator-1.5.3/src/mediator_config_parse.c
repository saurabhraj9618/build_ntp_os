/* A Bison parser, made by GNU Bison 3.0.4.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "3.0.4"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1




/* Copy the first part of user declarations.  */
#line 1 "mediator_config_parse.y" /* yacc.c:339  */

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


#line 238 "mediator_config_parse.c" /* yacc.c:339  */

# ifndef YY_NULLPTR
#  if defined __cplusplus && 201103L <= __cplusplus
#   define YY_NULLPTR nullptr
#  else
#   define YY_NULLPTR 0
#  endif
# endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* In a future release of Bison, this section will be replaced
   by #include "y.tab.h".  */
#ifndef YY_YY_MEDIATOR_CONFIG_PARSE_H_INCLUDED
# define YY_YY_MEDIATOR_CONFIG_PARSE_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    EOS = 258,
    COMMA = 259,
    LEFT_SQ_BRACKET = 260,
    RIGHT_SQ_BRACKET = 261,
    LEFT_PAREN = 262,
    RIGHT_PAREN = 263,
    WILD = 264,
    TOK_COLLECTOR = 265,
    TOK_EXPORTER = 266,
    TOK_DNS_DEDUP = 267,
    TOK_DNSDEDUP_ONLY = 268,
    TOK_NO_STATS = 269,
    TOK_PORT = 270,
    TOK_HOST = 271,
    TOK_IP = 272,
    TOK_PATH = 273,
    TOK_DAEMON = 274,
    TOK_DELIM = 275,
    TOK_PRINT_HDR = 276,
    TOK_GROUP = 277,
    TOK_MOVE = 278,
    TOK_DELETE = 279,
    TOK_LOCK = 280,
    TOK_UDP_TIMEOUT = 281,
    TOK_ROTATE = 282,
    TOK_END = 283,
    TOK_MEDIATOR = 284,
    TOK_FILTER = 285,
    TOK_ANY = 286,
    TOK_LOG_FILE = 287,
    TOK_FLOW_ONLY = 288,
    TOK_DPI_ONLY = 289,
    TOK_POLL = 290,
    TOK_MAX_HIT = 291,
    TOK_FLUSH_SECS = 292,
    TOK_LOG_LEVEL = 293,
    TOK_BASE_64 = 294,
    TOK_LAST_SEEN = 295,
    TOK_RM_EMPTY = 296,
    TOK_STATS_ONLY = 297,
    TOK_TABLE = 298,
    TOK_DPI_CONFIG = 299,
    TOK_MULTI_FILES = 300,
    TOK_ERR = 301,
    TOK_NO_INDEX = 302,
    TOK_TIMESTAMP = 303,
    TOK_NO_FLOW_STATS = 304,
    TOK_PID_FILE = 305,
    TOK_MY_REMOVE = 306,
    TOK_MY_USER = 307,
    TOK_MY_PW = 308,
    TOK_MY_DB = 309,
    TOK_MY_HOST = 310,
    TOK_MY_TABLE = 311,
    TOK_FIELDS = 312,
    TOK_DPI_FIELD_LIST = 313,
    TOK_DPI_DELIMITER = 314,
    TOK_STATS_TO = 315,
    TOK_USERIE = 316,
    TOK_AND_FILTER = 317,
    TOK_ESCAPE = 318,
    TOK_DNSRR_ONLY = 319,
    TOK_FULL = 320,
    TOK_LOG_DIR = 321,
    TOK_JSON = 322,
    TOK_RECORDS = 323,
    TOK_RESP_ONLY = 324,
    TOK_SSL_CONFIG = 325,
    TOK_ISSUER = 326,
    TOK_SUBJECT = 327,
    TOK_OTHER = 328,
    TOK_EXTENSIONS = 329,
    TOK_DEDUP_PER_FLOW = 330,
    TOK_DEDUP_CONFIG = 331,
    TOK_FILE = 332,
    TOK_MERGE = 333,
    TOK_SSL_DEDUP = 334,
    TOK_CERT_FILE = 335,
    TOK_SSL_DEDUP_ONLY = 336,
    TOK_MD5 = 337,
    TOK_SHA1 = 338,
    TOK_GZIP = 339,
    TOK_DNSRR = 340,
    TOK_DEDUP_ONLY = 341,
    TOK_NO_FLOW = 342,
    TOK_OBID_MAP = 343,
    TOK_VLAN_MAP = 344,
    TOK_MAP = 345,
    TOK_DISCARD = 346,
    TOK_ADD_EXPORT = 347,
    TOK_DECOMPRESS = 348,
    TOK_METADATA_EXPORT = 349,
    VAL_ATOM = 350,
    VAL_DATETIME = 351,
    VAL_DOUBLE = 352,
    VAL_INTEGER = 353,
    VAL_IP = 354,
    VAL_QSTRING = 355,
    VAL_TRANSPORT = 356,
    VAL_DB_TYPE = 357,
    VAL_OPER = 358,
    VAL_FIELD = 359,
    VAL_LOGLEVEL = 360
  };
#endif
/* Tokens.  */
#define EOS 258
#define COMMA 259
#define LEFT_SQ_BRACKET 260
#define RIGHT_SQ_BRACKET 261
#define LEFT_PAREN 262
#define RIGHT_PAREN 263
#define WILD 264
#define TOK_COLLECTOR 265
#define TOK_EXPORTER 266
#define TOK_DNS_DEDUP 267
#define TOK_DNSDEDUP_ONLY 268
#define TOK_NO_STATS 269
#define TOK_PORT 270
#define TOK_HOST 271
#define TOK_IP 272
#define TOK_PATH 273
#define TOK_DAEMON 274
#define TOK_DELIM 275
#define TOK_PRINT_HDR 276
#define TOK_GROUP 277
#define TOK_MOVE 278
#define TOK_DELETE 279
#define TOK_LOCK 280
#define TOK_UDP_TIMEOUT 281
#define TOK_ROTATE 282
#define TOK_END 283
#define TOK_MEDIATOR 284
#define TOK_FILTER 285
#define TOK_ANY 286
#define TOK_LOG_FILE 287
#define TOK_FLOW_ONLY 288
#define TOK_DPI_ONLY 289
#define TOK_POLL 290
#define TOK_MAX_HIT 291
#define TOK_FLUSH_SECS 292
#define TOK_LOG_LEVEL 293
#define TOK_BASE_64 294
#define TOK_LAST_SEEN 295
#define TOK_RM_EMPTY 296
#define TOK_STATS_ONLY 297
#define TOK_TABLE 298
#define TOK_DPI_CONFIG 299
#define TOK_MULTI_FILES 300
#define TOK_ERR 301
#define TOK_NO_INDEX 302
#define TOK_TIMESTAMP 303
#define TOK_NO_FLOW_STATS 304
#define TOK_PID_FILE 305
#define TOK_MY_REMOVE 306
#define TOK_MY_USER 307
#define TOK_MY_PW 308
#define TOK_MY_DB 309
#define TOK_MY_HOST 310
#define TOK_MY_TABLE 311
#define TOK_FIELDS 312
#define TOK_DPI_FIELD_LIST 313
#define TOK_DPI_DELIMITER 314
#define TOK_STATS_TO 315
#define TOK_USERIE 316
#define TOK_AND_FILTER 317
#define TOK_ESCAPE 318
#define TOK_DNSRR_ONLY 319
#define TOK_FULL 320
#define TOK_LOG_DIR 321
#define TOK_JSON 322
#define TOK_RECORDS 323
#define TOK_RESP_ONLY 324
#define TOK_SSL_CONFIG 325
#define TOK_ISSUER 326
#define TOK_SUBJECT 327
#define TOK_OTHER 328
#define TOK_EXTENSIONS 329
#define TOK_DEDUP_PER_FLOW 330
#define TOK_DEDUP_CONFIG 331
#define TOK_FILE 332
#define TOK_MERGE 333
#define TOK_SSL_DEDUP 334
#define TOK_CERT_FILE 335
#define TOK_SSL_DEDUP_ONLY 336
#define TOK_MD5 337
#define TOK_SHA1 338
#define TOK_GZIP 339
#define TOK_DNSRR 340
#define TOK_DEDUP_ONLY 341
#define TOK_NO_FLOW 342
#define TOK_OBID_MAP 343
#define TOK_VLAN_MAP 344
#define TOK_MAP 345
#define TOK_DISCARD 346
#define TOK_ADD_EXPORT 347
#define TOK_DECOMPRESS 348
#define TOK_METADATA_EXPORT 349
#define VAL_ATOM 350
#define VAL_DATETIME 351
#define VAL_DOUBLE 352
#define VAL_INTEGER 353
#define VAL_IP 354
#define VAL_QSTRING 355
#define VAL_TRANSPORT 356
#define VAL_DB_TYPE 357
#define VAL_OPER 358
#define VAL_FIELD 359
#define VAL_LOGLEVEL 360

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED

union YYSTYPE
{
#line 173 "mediator_config_parse.y" /* yacc.c:355  */

    char                   *str;
    uint32_t                integer;
    mdParserNumber_t        *number;
    mdTransportType_t       transport;
    mdAcceptFilterField_t   field;
    fieldOperator           oper;
    mdLogLevel_t            log_level;

#line 498 "mediator_config_parse.c" /* yacc.c:355  */
};

typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;

int yyparse (void);

#endif /* !YY_YY_MEDIATOR_CONFIG_PARSE_H_INCLUDED  */

/* Copy the second part of user declarations.  */

#line 515 "mediator_config_parse.c" /* yacc.c:358  */

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif

#ifndef YY_ATTRIBUTE
# if (defined __GNUC__                                               \
      && (2 < __GNUC__ || (__GNUC__ == 2 && 96 <= __GNUC_MINOR__)))  \
     || defined __SUNPRO_C && 0x5110 <= __SUNPRO_C
#  define YY_ATTRIBUTE(Spec) __attribute__(Spec)
# else
#  define YY_ATTRIBUTE(Spec) /* empty */
# endif
#endif

#ifndef YY_ATTRIBUTE_PURE
# define YY_ATTRIBUTE_PURE   YY_ATTRIBUTE ((__pure__))
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# define YY_ATTRIBUTE_UNUSED YY_ATTRIBUTE ((__unused__))
#endif

#if !defined _Noreturn \
     && (!defined __STDC_VERSION__ || __STDC_VERSION__ < 201112)
# if defined _MSC_VER && 1200 <= _MSC_VER
#  define _Noreturn __declspec (noreturn)
# else
#  define _Noreturn YY_ATTRIBUTE ((__noreturn__))
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(E) ((void) (E))
#else
# define YYUSE(E) /* empty */
#endif

#if defined __GNUC__ && 407 <= __GNUC__ * 100 + __GNUC_MINOR__
/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN \
    _Pragma ("GCC diagnostic push") \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")\
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# define YY_IGNORE_MAYBE_UNINITIALIZED_END \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif


#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYSIZE_T yynewbytes;                                            \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / sizeof (*yyptr);                          \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, (Count) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYSIZE_T yyi;                         \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  74
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   531

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  106
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  156
/* YYNRULES -- Number of rules.  */
#define YYNRULES  311
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  542

/* YYTRANSLATE[YYX] -- Symbol number corresponding to YYX as returned
   by yylex, with out-of-bounds checking.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   360

#define YYTRANSLATE(YYX)                                                \
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, without out-of-bounds checking.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,    68,    69,    70,    71,    72,    73,    74,
      75,    76,    77,    78,    79,    80,    81,    82,    83,    84,
      85,    86,    87,    88,    89,    90,    91,    92,    93,    94,
      95,    96,    97,    98,    99,   100,   101,   102,   103,   104,
     105
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   229,   229,   234,   237,   238,   241,   242,   243,   244,
     245,   246,   247,   248,   249,   250,   251,   252,   253,   254,
     255,   256,   257,   258,   261,   265,   266,   267,   270,   275,
     279,   284,   289,   290,   293,   294,   295,   296,   297,   298,
     299,   300,   301,   302,   303,   304,   305,   308,   313,   318,
     323,   328,   333,   338,   339,   342,   347,   352,   357,   362,
     365,   366,   367,   370,   371,   372,   375,   380,   385,   390,
     393,   398,   400,   404,   407,   412,   415,   419,   423,   427,
     431,   435,   439,   443,   447,   452,   453,   456,   460,   464,
     469,   473,   484,   488,   492,   496,   501,   506,   507,   510,
     511,   512,   513,   514,   515,   516,   517,   518,   519,   520,
     521,   522,   523,   524,   525,   526,   527,   528,   529,   530,
     531,   532,   533,   534,   535,   536,   537,   538,   539,   540,
     541,   542,   543,   544,   545,   546,   547,   548,   549,   550,
     551,   552,   555,   560,   565,   570,   575,   580,   585,   590,
     595,   600,   601,   604,   609,   614,   619,   624,   629,   634,
     639,   644,   649,   654,   659,   664,   669,   674,   678,   683,
     689,   694,   699,   704,   709,   712,   717,   722,   727,   732,
     737,   742,   747,   751,   755,   759,   763,   767,   772,   777,
     783,   788,   793,   798,   803,   808,   812,   816,   819,   824,
     828,   832,   837,   841,   842,   845,   845,   846,   847,   848,
     849,   850,   853,   856,   861,   866,   871,   876,   877,   879,
     883,   888,   891,   896,   897,   899,   900,   901,   902,   903,
     904,   905,   906,   907,   910,   915,   920,   925,   930,   935,
     940,   944,   948,   953,   958,   963,   964,   966,   967,   970,
     973,   976,   980,   984,   988,   992,   996,  1000,  1005,  1010,
    1014,  1018,  1022,  1023,  1025,  1026,  1027,  1028,  1029,  1030,
    1031,  1032,  1033,  1034,  1035,  1036,  1039,  1044,  1051,  1056,
    1061,  1066,  1071,  1076,  1081,  1086,  1091,  1095,  1100,  1101,
    1103,  1104,  1105,  1106,  1109,  1114,  1119,  1124,  1129,  1133,
    1138,  1139,  1142,  1143,  1144,  1145,  1148,  1153,  1158,  1163,
    1168,  1168
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || 0
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "EOS", "COMMA", "LEFT_SQ_BRACKET",
  "RIGHT_SQ_BRACKET", "LEFT_PAREN", "RIGHT_PAREN", "WILD", "TOK_COLLECTOR",
  "TOK_EXPORTER", "TOK_DNS_DEDUP", "TOK_DNSDEDUP_ONLY", "TOK_NO_STATS",
  "TOK_PORT", "TOK_HOST", "TOK_IP", "TOK_PATH", "TOK_DAEMON", "TOK_DELIM",
  "TOK_PRINT_HDR", "TOK_GROUP", "TOK_MOVE", "TOK_DELETE", "TOK_LOCK",
  "TOK_UDP_TIMEOUT", "TOK_ROTATE", "TOK_END", "TOK_MEDIATOR", "TOK_FILTER",
  "TOK_ANY", "TOK_LOG_FILE", "TOK_FLOW_ONLY", "TOK_DPI_ONLY", "TOK_POLL",
  "TOK_MAX_HIT", "TOK_FLUSH_SECS", "TOK_LOG_LEVEL", "TOK_BASE_64",
  "TOK_LAST_SEEN", "TOK_RM_EMPTY", "TOK_STATS_ONLY", "TOK_TABLE",
  "TOK_DPI_CONFIG", "TOK_MULTI_FILES", "TOK_ERR", "TOK_NO_INDEX",
  "TOK_TIMESTAMP", "TOK_NO_FLOW_STATS", "TOK_PID_FILE", "TOK_MY_REMOVE",
  "TOK_MY_USER", "TOK_MY_PW", "TOK_MY_DB", "TOK_MY_HOST", "TOK_MY_TABLE",
  "TOK_FIELDS", "TOK_DPI_FIELD_LIST", "TOK_DPI_DELIMITER", "TOK_STATS_TO",
  "TOK_USERIE", "TOK_AND_FILTER", "TOK_ESCAPE", "TOK_DNSRR_ONLY",
  "TOK_FULL", "TOK_LOG_DIR", "TOK_JSON", "TOK_RECORDS", "TOK_RESP_ONLY",
  "TOK_SSL_CONFIG", "TOK_ISSUER", "TOK_SUBJECT", "TOK_OTHER",
  "TOK_EXTENSIONS", "TOK_DEDUP_PER_FLOW", "TOK_DEDUP_CONFIG", "TOK_FILE",
  "TOK_MERGE", "TOK_SSL_DEDUP", "TOK_CERT_FILE", "TOK_SSL_DEDUP_ONLY",
  "TOK_MD5", "TOK_SHA1", "TOK_GZIP", "TOK_DNSRR", "TOK_DEDUP_ONLY",
  "TOK_NO_FLOW", "TOK_OBID_MAP", "TOK_VLAN_MAP", "TOK_MAP", "TOK_DISCARD",
  "TOK_ADD_EXPORT", "TOK_DECOMPRESS", "TOK_METADATA_EXPORT", "VAL_ATOM",
  "VAL_DATETIME", "VAL_DOUBLE", "VAL_INTEGER", "VAL_IP", "VAL_QSTRING",
  "VAL_TRANSPORT", "VAL_DB_TYPE", "VAL_OPER", "VAL_FIELD", "VAL_LOGLEVEL",
  "$accept", "mediatorConfFile", "mediatorConf", "stmtList", "stmt",
  "collectorMode", "collectorBegin", "collectorBeginNoName",
  "collectorBeginName", "collectorEnd", "collectorStmtList",
  "collectorStmt", "col_port", "col_host", "col_path", "col_watch",
  "col_daemon", "col_decompress", "col_groups", "col_group", "col_lock",
  "col_move_path", "col_delete", "col_filter", "filterStmtList",
  "filterStmt", "filterBegin", "filterEnd", "exp_dpi_field_list",
  "valueList", "valueListStart", "valueListEnd", "valueListItems",
  "fieldList", "fieldListItems", "comparisonList", "comparison",
  "exporterMode", "exporterBegin", "exporterEnd", "exporterStmtList",
  "exporterStmt", "exp_md5_hash", "exp_sha1_hash", "exp_move_path",
  "exp_and_filter", "col_and_filter", "exp_port", "exp_host", "exp_path",
  "exp_daemon", "exp_groups", "exp_group", "exp_delim", "exp_dpi_delim",
  "exp_lock", "exp_rotate", "exp_udp_timeout", "exp_flow_only",
  "exp_dpi_only", "exp_no_stats", "exp_stats_only", "exp_remove_empty",
  "exp_multi_files", "exp_no_flow_stats", "exp_json", "spreadGroup",
  "spreadBegin", "spreadEnd", "statsConfig", "statsTimeout", "exp_dedup",
  "exp_dns_dedup_only", "exp_ssl_dedup_only", "exp_no_flow",
  "exp_dedup_only", "exp_print_headers", "exp_no_index", "exp_escape",
  "exp_dedup_flow", "exp_timestamp", "exp_dns_rr_only", "exp_dns_rr",
  "exp_dns_resp_only", "exp_gzip_files", "exp_metadata_export",
  "logConfig", "logDirConfig", "logLevelConfig", "pidConfig", "recordList",
  "dnsdedupConfig", "dns_dedup_begin", "dns_dedup_end", "dedupConfig",
  "dedup_begin", "dedup_end", "dedupList", "dedupStmt", "dedupFileList",
  "dedupHitConfig", "dedupFlushConfig", "dedupAddExport",
  "dedupMergeTruncated", "fileList", "fileStmt", "dnsdedupList",
  "dnsdedupStmt", "mapStmt", "dnsdedupAddExport", "hitConfig",
  "flushConfig", "base64Config", "lastSeenConfig", "dpiConfig",
  "dpi_config_begin", "dpi_config_end", "customList", "dpiList",
  "tableList", "tableStmt", "mysqlConfig", "userIE", "exp_remove_uploaded",
  "sslConfig", "ssl_config_begin", "ssl_config_end", "sslList", "sslStmt",
  "ssldedupAddExportName", "sslMapStmt", "issuerList", "subjectList",
  "otherList", "extensionList", "sslCertDedup", "sslDedupHitConfig",
  "sslDedupFlushConfig", "sslCertFile", "vlanMap", "vlanMapBegin",
  "vlanConfig", "vlanStmt", "vlanListItem", "vlanMapEnd", "vlanListOther",
  "vlanListDiscard", "obidMap", "obidMapBegin", "obidConfig", "obidStmt",
  "obidListItem", "obidMapEnd", "obidListOther", "obidListDiscard",
  "atomOrQstring", YY_NULLPTR
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[NUM] -- (External) token number corresponding to the
   (internal) symbol number NUM (which must be that of a token).  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313,   314,
     315,   316,   317,   318,   319,   320,   321,   322,   323,   324,
     325,   326,   327,   328,   329,   330,   331,   332,   333,   334,
     335,   336,   337,   338,   339,   340,   341,   342,   343,   344,
     345,   346,   347,   348,   349,   350,   351,   352,   353,   354,
     355,   356,   357,   358,   359,   360
};
# endif

#define YYPACT_NINF -207

#define yypact_value_is_default(Yystate) \
  (!!((Yystate) == (-207)))

#define YYTABLE_NINF -247

#define yytable_value_is_error(Yytable_value) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
     425,   345,   -74,   -57,    80,    47,   -41,    71,   -41,   -23,
     119,   -41,   -10,    -9,   -41,   -41,   139,   -41,   -41,    91,
    -207,   425,  -207,  -207,    33,  -207,  -207,  -207,    19,  -207,
     240,  -207,    16,  -207,  -207,  -207,  -207,  -207,  -207,  -207,
     364,  -207,   381,  -207,    29,  -207,  -207,   350,  -207,     6,
    -207,   113,   140,   141,  -207,  -207,  -207,    89,  -207,    90,
    -207,    93,   105,  -207,   106,   107,   137,   -41,   145,   148,
    -207,   149,   157,   164,  -207,  -207,  -207,    69,    75,   -41,
     -41,   -41,   -41,   -41,   176,   178,   111,   179,   -41,    86,
     327,  -207,  -207,  -207,  -207,  -207,  -207,  -207,   165,  -207,
    -207,  -207,  -207,    16,  -207,  -207,  -207,    -2,  -207,    16,
    -207,  -207,   200,   208,   212,   118,   -41,   -41,   -41,   -41,
     214,   -41,   -41,   218,   125,   133,   229,   235,   239,   241,
     243,   245,   246,   248,   254,   -41,   -41,   -41,   -41,   -41,
      23,   259,   -41,   265,   266,    34,   268,   269,   272,   273,
     274,   275,   276,   281,    84,   283,   287,   297,  -207,    16,
     143,  -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,
     279,  -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,
    -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,
    -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,
    -207,  -207,  -207,    24,  -207,   207,   210,   307,   308,   259,
     305,   310,  -207,   376,  -207,  -207,  -207,  -207,  -207,  -207,
    -207,  -207,   216,   220,   -41,   317,   325,   280,  -207,  -207,
    -207,  -207,  -207,  -207,   256,  -207,   291,   -41,   292,    42,
    -207,  -207,   233,   249,   259,   259,   259,   259,   335,   -41,
     334,   351,   303,  -207,  -207,  -207,  -207,  -207,  -207,  -207,
    -207,  -207,  -207,  -207,  -207,   352,    50,  -207,  -207,  -207,
    -207,    30,  -207,   356,    83,  -207,  -207,  -207,  -207,    56,
    -207,   362,   363,  -207,   368,   375,  -207,  -207,  -207,  -207,
    -207,  -207,  -207,    13,  -207,  -207,  -207,  -207,  -207,   -33,
     382,   387,   388,   389,   391,   393,  -207,  -207,   394,  -207,
     395,   -29,    -5,  -207,  -207,  -207,  -207,   320,  -207,  -207,
    -207,  -207,  -207,   396,   399,   402,   403,   406,  -207,   407,
     408,  -207,   411,   416,  -207,  -207,  -207,  -207,  -207,  -207,
    -207,  -207,  -207,   422,   423,   424,   430,   431,  -207,  -207,
    -207,   438,    21,  -207,   440,     9,   442,  -207,  -207,  -207,
     443,  -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,
     445,  -207,  -207,  -207,   432,  -207,  -207,  -207,   433,  -207,
     447,   448,  -207,  -207,   449,   -41,  -207,   434,  -207,  -207,
     450,   461,     0,  -207,  -207,   437,  -207,  -207,  -207,   259,
     439,  -207,  -207,  -207,   467,   468,   469,   471,   473,   474,
    -207,   475,   -41,  -207,   451,  -207,  -207,  -207,   452,  -207,
    -207,   478,   479,  -207,   455,  -207,  -207,   481,   484,  -207,
    -207,  -207,  -207,  -207,   485,   486,   487,  -207,  -207,  -207,
    -207,  -207,  -207,  -207,  -207,   489,   490,   491,   493,   494,
    -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,
    -207,  -207,  -207,  -207,  -207,    32,  -207,  -207,  -207,  -207,
    -207,  -207,    60,  -207,  -207,  -207,   495,  -207,  -207,  -207,
    -207,   492,  -207,  -207,  -207,   496,    15,   499,  -207,   501,
     502,  -207,  -207,  -207,  -207,  -207,  -207,  -207,   498,  -207,
    -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,
    -207,  -207,  -207,  -207,  -207,  -207,  -207,   401,  -207,  -207,
    -207,   504,   -41,   503,   505,  -207,  -207,  -207,   506,  -207,
    -207,   507,   -41,  -207,  -207,   259,   508,   509,   259,  -207,
     514,  -207
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_uint16 yydefact[] =
{
       0,    23,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       2,     3,     4,     6,     0,    26,    25,     7,    60,     8,
       0,     9,     0,    10,    19,    11,    13,    12,    14,    15,
     225,    18,   205,    16,     0,    20,    17,   264,    21,     0,
      22,     0,     0,     0,   197,   310,   311,     0,   170,     0,
      66,     0,     0,   241,     0,     0,     0,     0,     0,     0,
     201,     0,     0,     0,     1,     5,    46,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,    32,    34,    35,    36,    37,    38,    43,    39,    53,
      40,    41,    42,    44,    85,    45,    65,     0,    61,    63,
      64,   141,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   127,   123,
       0,    97,   134,   135,   137,   126,    99,   100,   101,   102,
     103,   151,   105,   106,   104,   107,   108,   109,   110,   111,
     112,   116,   118,   121,   122,   113,   115,   133,   138,   139,
     117,   119,   129,   114,   120,   130,   131,   132,   136,   140,
     124,   125,   128,     0,   233,     0,     0,     0,     0,     0,
       0,     0,   230,     0,   223,   231,   232,   226,   227,   228,
     229,   211,     0,     0,     0,     0,     0,     0,   203,   208,
     206,   207,   210,   209,   212,   217,   250,     0,     0,   245,
     247,   275,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   262,   273,   274,   265,   266,   267,   268,
     269,   270,   271,   272,   293,     0,     0,   288,   290,   291,
     292,     0,   305,     0,     0,   300,   302,   303,   304,     0,
      28,     0,     0,    93,     0,     0,   196,   168,   190,   192,
     242,   193,   171,     0,   191,   260,   200,   299,   287,     0,
       0,     0,     0,     0,     0,     0,    58,    56,     0,   146,
       0,     0,     0,    24,    33,    54,    86,     0,    62,    59,
     172,   173,   161,     0,     0,     0,     0,     0,   178,     0,
       0,   156,     0,     0,   159,   160,   163,   162,   164,   179,
     182,   165,   258,     0,     0,     0,     0,     0,    78,    77,
      76,     0,    75,    70,     0,     0,     0,   145,   180,   183,
       0,   166,   187,   181,   175,   174,   142,   143,   188,   185,
       0,   177,   176,   189,     0,    92,    98,   152,     0,   167,
       0,     0,   238,   239,     0,     0,   235,     0,   195,   224,
       0,     0,     0,   216,   215,     0,   199,   204,   218,     0,
       0,   240,   250,   248,     0,     0,     0,     0,     0,     0,
     282,     0,     0,   276,     0,   259,   263,   297,     0,   289,
     286,     0,     0,   309,     0,   301,   298,     0,     0,    30,
      29,    95,    94,   256,     0,     0,     0,    47,    48,    49,
      51,    55,    57,    50,    52,     0,     0,     0,     0,     0,
     147,   148,   149,   150,   154,   153,   144,   158,   157,   251,
     252,   253,   254,   255,   244,     0,    84,    80,    82,    68,
      74,    72,     0,   155,   184,   186,     0,   169,   236,   237,
     194,     0,   198,   213,   214,     0,     0,     0,   202,     0,
       0,   283,   284,   278,   279,   280,   281,   285,     0,   261,
     295,   296,   294,   307,   308,   306,   257,    91,    90,    87,
      88,    89,    31,    67,    83,    79,    81,     0,    71,    69,
      96,     0,     0,     0,     0,   220,   249,   243,     0,    73,
     234,     0,     0,   219,   277,     0,     0,     0,     0,   222,
       0,   221
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -207,  -207,  -207,  -207,   500,  -207,  -207,  -207,  -207,  -207,
    -207,   421,  -207,  -207,  -207,  -207,  -207,  -207,  -207,   426,
    -207,  -207,  -207,  -207,  -207,   412,  -207,  -207,  -207,  -206,
    -207,  -207,  -207,  -207,  -207,   -13,   -79,  -207,  -207,  -207,
    -207,   360,  -207,  -207,  -207,  -207,    -7,  -207,  -207,  -207,
    -207,  -207,   353,  -207,  -207,  -207,  -207,  -207,  -207,  -207,
    -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,
    -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,
    -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,
    -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,   295,  -207,
    -207,  -207,  -207,  -207,  -207,   293,  -207,   312,  -207,  -207,
    -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,
     290,  -207,  -207,  -207,  -207,  -207,  -207,  -207,   278,  -207,
    -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,  -207,
    -207,  -207,   260,  -207,  -207,  -207,  -207,  -207,  -207,  -207,
     257,  -207,  -207,  -207,  -207,    -4
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,    19,    20,    21,    22,    23,    24,    25,    26,   313,
      90,    91,    92,    93,    94,    95,    96,    97,    98,    99,
     100,   101,   102,    27,   107,   108,    28,   319,   158,   354,
     355,   519,   472,   351,   352,   103,   104,    29,    30,   375,
     160,   161,   162,   163,   164,   165,   105,   166,   167,   168,
     169,   170,   171,   172,   173,   174,   175,   176,   177,   178,
     179,   180,   181,   182,   183,   184,    31,    32,   379,    33,
      34,   185,   186,   187,   188,   189,   190,   191,   192,   193,
     194,   195,   196,   197,   198,   199,    35,    36,    37,    38,
     212,    39,    40,   388,    41,    42,   396,   227,   228,   229,
     230,   231,   232,   233,   234,   235,   213,   214,   215,   216,
     217,   218,   219,   220,    43,    44,   401,   200,   238,   239,
     240,   201,    45,   202,    46,    47,   415,   252,   253,   254,
     255,   256,   257,   258,   259,   260,   261,   262,   263,    48,
      49,   266,   267,   268,   420,   269,   270,    50,    51,   274,
     275,   276,   426,   277,   278,   271
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
      57,   106,    59,   384,    61,   353,    64,    65,    77,   264,
      68,    69,    71,    72,    73,   109,   433,   159,   470,   203,
     353,   110,   106,   448,   316,   465,    77,    52,   317,    77,
     316,   466,   236,   348,    77,   353,    76,   359,   406,   407,
     408,   409,   514,    77,    53,   402,   378,   279,    78,    79,
      58,    80,    81,   264,    55,    82,    83,    84,    85,    56,
      87,   353,   435,   293,   517,   422,   518,   436,    86,   445,
     446,   447,   237,   428,    60,   301,   302,   303,   304,   305,
     316,    87,    62,    54,   310,   237,   272,   369,    66,    67,
     485,    74,   286,   287,   109,    87,   288,   265,   299,   360,
     110,    55,    89,   421,   486,   523,    56,   471,   289,   290,
     291,   434,   324,   325,   326,   327,   272,   329,   330,   467,
      89,   349,    63,    89,   316,   468,    88,   350,    89,   427,
     515,   343,   344,   345,   346,   347,   516,    89,   356,   418,
     292,   265,    70,   280,   283,    55,   111,   159,   294,   370,
      56,   295,   296,    77,   374,   112,   113,   114,   115,   116,
     297,   117,   118,   119,   120,   121,   122,   298,   123,   124,
     125,   424,   299,   300,   273,    55,   126,   127,    55,   306,
      56,   307,   309,    56,   128,   129,   487,    82,   130,   311,
     131,   132,   133,   489,   134,   135,   136,   137,   138,   139,
     140,   141,   142,   320,   273,   143,   144,   145,    55,   308,
     146,   321,   147,    56,    55,   322,   323,   328,   148,    56,
     392,   331,   149,   332,   150,   151,   152,   153,   154,   155,
     156,   333,   334,   399,    55,   281,   284,   157,   335,    56,
     282,   285,   336,   111,   337,   411,   338,    89,   339,   340,
      77,   341,   112,   113,   114,   115,   116,   342,   117,   118,
     119,   120,   121,   122,   353,   123,   124,   125,   357,   358,
     279,   361,   362,   126,   127,   363,   364,   365,   366,   367,
     524,   128,   129,   221,   368,   130,   371,   131,   132,   133,
     372,   134,   135,   136,   137,   138,   139,   140,   141,   142,
     373,   121,   143,   144,   145,   380,   241,   146,   381,   147,
     382,   383,   385,   386,   390,   148,   222,   223,   391,   149,
     393,   150,   151,   152,   153,   154,   155,   156,   394,   537,
      76,   404,   540,   224,   157,  -246,   400,   312,   410,   242,
     243,   412,    78,    79,    89,    80,    81,   405,   449,    82,
      83,    84,    85,   241,   413,   417,   395,   224,   225,   423,
     -27,   -27,    86,   -27,   -27,   429,   430,   204,   -27,   -27,
     -27,   431,   226,   414,   244,   245,   246,   247,   432,   204,
     -27,   481,   248,   249,   221,   437,   242,   243,   387,    87,
     438,   439,   440,   250,   441,   251,   442,   443,   444,   450,
     205,   206,   451,   207,   208,   452,   453,   -27,   498,   454,
     455,   456,   205,   206,   457,   207,   208,   222,   223,   458,
      88,   244,   245,   246,   247,   459,   460,   461,     1,   248,
     249,    89,   209,   462,   463,     2,     3,     4,   -27,     5,
     250,   464,   251,   469,   209,   473,   474,     6,   475,   -27,
     478,   479,   480,   483,   210,     7,   211,     8,   224,   225,
     476,   477,   482,     9,   484,   488,   210,   490,   211,    10,
     491,   492,   493,   226,   494,    11,   495,   496,   497,   499,
     500,   501,   502,   503,   504,    12,    13,   505,   506,   507,
     508,    14,   509,   510,   511,    15,   512,   513,   520,   529,
     521,    16,   525,   522,   526,   527,   528,   530,   533,   534,
     532,   314,   539,    17,    18,   535,   538,   541,   531,   318,
     376,    75,   397,   377,   315,   389,   419,   398,   536,   403,
     416,   425
};

static const yytype_uint16 yycheck[] =
{
       4,     3,     6,   209,     8,     5,    10,    11,    10,     3,
      14,    15,    16,    17,    18,    28,     3,    30,     9,    32,
       5,    28,     3,    28,   103,     4,    10,   101,    30,    10,
     109,    10,     3,    10,    10,     5,     3,     3,   244,   245,
     246,   247,    10,    10,   101,     3,    22,    51,    15,    16,
       3,    18,    19,     3,    95,    22,    23,    24,    25,   100,
      62,     5,    95,    67,     4,   271,     6,   100,    35,    98,
      99,   100,    43,   279,     3,    79,    80,    81,    82,    83,
     159,    62,   105,     3,    88,    43,     3,     3,    98,    98,
      90,     0,     3,     3,   107,    62,     3,    91,   103,    65,
     107,    95,   104,    73,   104,    90,   100,    98,     3,     3,
       3,    98,   116,   117,   118,   119,     3,   121,   122,    98,
     104,    98,     3,   104,   203,   104,    93,   104,   104,    73,
      98,   135,   136,   137,   138,   139,   104,   104,   142,    89,
       3,    91,     3,     3,     3,    95,     3,   160,     3,    65,
     100,     3,     3,    10,    11,    12,    13,    14,    15,    16,
       3,    18,    19,    20,    21,    22,    23,     3,    25,    26,
      27,    88,   103,    98,    91,    95,    33,    34,    95,     3,
     100,     3,     3,   100,    41,    42,   392,    22,    45,   103,
      47,    48,    49,   399,    51,    52,    53,    54,    55,    56,
      57,    58,    59,     3,    91,    62,    63,    64,    95,    98,
      67,     3,    69,   100,    95,     3,    98,     3,    75,   100,
     224,     3,    79,    98,    81,    82,    83,    84,    85,    86,
      87,    98,     3,   237,    95,    95,    95,    94,     3,   100,
     100,   100,     3,     3,     3,   249,     3,   104,     3,     3,
      10,     3,    12,    13,    14,    15,    16,     3,    18,    19,
      20,    21,    22,    23,     5,    25,    26,    27,     3,     3,
     274,     3,     3,    33,    34,     3,     3,     3,     3,     3,
     486,    41,    42,     3,     3,    45,     3,    47,    48,    49,
       3,    51,    52,    53,    54,    55,    56,    57,    58,    59,
       3,    22,    62,    63,    64,    98,     3,    67,    98,    69,
       3,     3,     7,     3,    98,    75,    36,    37,    98,    79,
       3,    81,    82,    83,    84,    85,    86,    87,     3,   535,
       3,    98,   538,    77,    94,    44,    44,    10,     3,    36,
      37,     7,    15,    16,   104,    18,    19,    98,    28,    22,
      23,    24,    25,     3,     3,     3,    76,    77,    78,     3,
      15,    16,    35,    18,    19,     3,     3,     3,    23,    24,
      25,     3,    92,    70,    71,    72,    73,    74,     3,     3,
      35,   385,    79,    80,     3,     3,    36,    37,    12,    62,
       3,     3,     3,    90,     3,    92,     3,     3,     3,     3,
      36,    37,     3,    39,    40,     3,     3,    62,   412,     3,
       3,     3,    36,    37,     3,    39,    40,    36,    37,     3,
      93,    71,    72,    73,    74,     3,     3,     3,     3,    79,
      80,   104,    68,     3,     3,    10,    11,    12,    93,    14,
      90,     3,    92,     3,    68,     3,     3,    22,     3,   104,
       3,     3,     3,     3,    90,    30,    92,    32,    77,    78,
      28,    28,    28,    38,     3,    28,    90,    28,    92,    44,
       3,     3,     3,    92,     3,    50,     3,     3,     3,    28,
      28,     3,     3,    28,     3,    60,    61,     3,     3,     3,
       3,    66,     3,     3,     3,    70,     3,     3,     3,    98,
       8,    76,     3,     7,     3,     3,     8,     3,     3,     3,
       7,    90,     3,    88,    89,     8,     8,     3,   522,   107,
     160,    21,   227,   170,    98,   213,   266,   234,   532,   239,
     252,   274
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_uint16 yystos[] =
{
       0,     3,    10,    11,    12,    14,    22,    30,    32,    38,
      44,    50,    60,    61,    66,    70,    76,    88,    89,   107,
     108,   109,   110,   111,   112,   113,   114,   129,   132,   143,
     144,   172,   173,   175,   176,   192,   193,   194,   195,   197,
     198,   200,   201,   220,   221,   228,   230,   231,   245,   246,
     253,   254,   101,   101,     3,    95,   100,   261,     3,   261,
       3,   261,   105,     3,   261,   261,    98,    98,   261,   261,
       3,   261,   261,   261,     0,   110,     3,    10,    15,    16,
      18,    19,    22,    23,    24,    25,    35,    62,    93,   104,
     116,   117,   118,   119,   120,   121,   122,   123,   124,   125,
     126,   127,   128,   141,   142,   152,     3,   130,   131,   141,
     152,     3,    12,    13,    14,    15,    16,    18,    19,    20,
      21,    22,    23,    25,    26,    27,    33,    34,    41,    42,
      45,    47,    48,    49,    51,    52,    53,    54,    55,    56,
      57,    58,    59,    62,    63,    64,    67,    69,    75,    79,
      81,    82,    83,    84,    85,    86,    87,    94,   134,   141,
     146,   147,   148,   149,   150,   151,   153,   154,   155,   156,
     157,   158,   159,   160,   161,   162,   163,   164,   165,   166,
     167,   168,   169,   170,   171,   177,   178,   179,   180,   181,
     182,   183,   184,   185,   186,   187,   188,   189,   190,   191,
     223,   227,   229,   141,     3,    36,    37,    39,    40,    68,
      90,    92,   196,   212,   213,   214,   215,   216,   217,   218,
     219,     3,    36,    37,    77,    78,    92,   203,   204,   205,
     206,   207,   208,   209,   210,   211,     3,    43,   224,   225,
     226,     3,    36,    37,    71,    72,    73,    74,    79,    80,
      90,    92,   233,   234,   235,   236,   237,   238,   239,   240,
     241,   242,   243,   244,     3,    91,   247,   248,   249,   251,
     252,   261,     3,    91,   255,   256,   257,   259,   260,   261,
       3,    95,   100,     3,    95,   100,     3,     3,     3,     3,
       3,     3,     3,   261,     3,     3,     3,     3,     3,   103,
      98,   261,   261,   261,   261,   261,     3,     3,    98,     3,
     261,   103,    10,   115,   117,   125,   142,    30,   131,   133,
       3,     3,     3,    98,   261,   261,   261,   261,     3,   261,
     261,     3,    98,    98,     3,     3,     3,     3,     3,     3,
       3,     3,     3,   261,   261,   261,   261,   261,    10,    98,
     104,   139,   140,     5,   135,   136,   261,     3,     3,     3,
      65,     3,     3,     3,     3,     3,     3,     3,     3,     3,
      65,     3,     3,     3,    11,   145,   147,   158,    22,   174,
      98,    98,     3,     3,   135,     7,     3,    12,   199,   213,
      98,    98,   261,     3,     3,    76,   202,   204,   211,   261,
      44,   222,     3,   226,    98,    98,   135,   135,   135,   135,
       3,   261,     7,     3,    70,   232,   234,     3,    89,   248,
     250,    73,   135,     3,    88,   256,   258,    73,   135,     3,
       3,     3,     3,     3,    98,    95,   100,     3,     3,     3,
       3,     3,     3,     3,     3,    98,    99,   100,    28,    28,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     4,    10,    98,   104,     3,
       9,    98,   138,     3,     3,     3,    28,    28,     3,     3,
       3,   261,    28,     3,     3,    90,   104,   135,    28,   135,
      28,     3,     3,     3,     3,     3,     3,     3,   261,    28,
      28,     3,     3,    28,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,    10,    98,   104,     4,     6,   137,
       3,     8,     7,    90,   135,     3,     3,     3,     8,    98,
       3,   261,     7,     3,     3,     8,   261,   135,     8,     3,
     135,     3
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint16 yyr1[] =
{
       0,   106,   107,   108,   109,   109,   110,   110,   110,   110,
     110,   110,   110,   110,   110,   110,   110,   110,   110,   110,
     110,   110,   110,   110,   111,   112,   112,   112,   113,   114,
     114,   115,   116,   116,   117,   117,   117,   117,   117,   117,
     117,   117,   117,   117,   117,   117,   117,   118,   119,   120,
     121,   122,   123,   124,   124,   125,   126,   127,   128,   129,
     130,   130,   130,   131,   131,   131,   132,   133,   134,   135,
     136,   137,   138,   138,   138,   139,   140,   140,   140,   140,
     140,   140,   140,   140,   140,   141,   141,   142,   142,   142,
     142,   142,   143,   144,   144,   144,   145,   146,   146,   147,
     147,   147,   147,   147,   147,   147,   147,   147,   147,   147,
     147,   147,   147,   147,   147,   147,   147,   147,   147,   147,
     147,   147,   147,   147,   147,   147,   147,   147,   147,   147,
     147,   147,   147,   147,   147,   147,   147,   147,   147,   147,
     147,   147,   148,   149,   150,   151,   152,   153,   154,   155,
     156,   157,   157,   158,   159,   160,   161,   162,   163,   164,
     165,   166,   167,   168,   169,   170,   171,   172,   173,   174,
     175,   176,   177,   178,   179,   179,   180,   181,   182,   183,
     184,   185,   186,   187,   187,   188,   188,   189,   190,   191,
     192,   193,   194,   195,   196,   197,   198,   198,   199,   200,
     201,   201,   202,   203,   203,   204,   204,   204,   204,   204,
     204,   204,   205,   206,   207,   208,   209,   210,   210,   211,
     211,   211,   211,   212,   212,   213,   213,   213,   213,   213,
     213,   213,   213,   213,   214,   215,   216,   217,   218,   219,
     220,   221,   221,   222,   223,   224,   224,   225,   225,   226,
     226,   227,   227,   227,   227,   227,   228,   228,   229,   230,
     231,   232,   233,   233,   234,   234,   234,   234,   234,   234,
     234,   234,   234,   234,   234,   234,   235,   236,   237,   238,
     239,   240,   241,   242,   243,   244,   245,   246,   247,   247,
     248,   248,   248,   248,   249,   250,   251,   252,   253,   254,
     255,   255,   256,   256,   256,   256,   257,   258,   259,   260,
     261,   261
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     1,     1,     1,     2,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     3,     1,     1,     1,     3,     4,
       4,     3,     1,     2,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     3,     3,     3,
       3,     3,     3,     1,     2,     3,     2,     3,     2,     3,
       0,     1,     2,     1,     1,     1,     2,     3,     3,     3,
       1,     1,     1,     3,     1,     1,     1,     1,     1,     3,
       2,     3,     2,     3,     2,     1,     2,     4,     4,     4,
       4,     4,     3,     3,     4,     4,     3,     1,     2,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     2,     2,     3,     2,     2,     3,     3,     3,
       3,     1,     2,     3,     3,     3,     2,     3,     3,     2,
       2,     2,     2,     2,     2,     2,     2,     3,     3,     2,
       2,     3,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     3,     2,     3,     2,     2,     2,
       3,     3,     3,     3,     3,     3,     3,     2,     2,     3,
       3,     2,     2,     1,     2,     0,     1,     1,     1,     1,
       1,     1,     1,     3,     3,     2,     2,     1,     2,     5,
       4,     9,     8,     1,     2,     0,     1,     1,     1,     1,
       1,     1,     1,     1,     5,     2,     3,     3,     2,     2,
       3,     2,     3,     3,     3,     1,     1,     1,     2,     4,
       1,     3,     3,     3,     3,     3,     4,     5,     2,     3,
       3,     2,     1,     2,     0,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     2,     5,     3,     3,
       3,     3,     2,     3,     3,     3,     3,     3,     1,     2,
       1,     1,     1,     1,     3,     2,     3,     2,     3,     3,
       1,     2,     1,     1,     1,     1,     3,     2,     3,     2,
       1,     1
};


#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)
#define YYEMPTY         (-2)
#define YYEOF           0

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                  \
do                                                              \
  if (yychar == YYEMPTY)                                        \
    {                                                           \
      yychar = (Token);                                         \
      yylval = (Value);                                         \
      YYPOPSTACK (yylen);                                       \
      yystate = *yyssp;                                         \
      goto yybackup;                                            \
    }                                                           \
  else                                                          \
    {                                                           \
      yyerror (YY_("syntax error: cannot back up")); \
      YYERROR;                                                  \
    }                                                           \
while (0)

/* Error token number */
#define YYTERROR        1
#define YYERRCODE       256



/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)

/* This macro is provided for backward compatibility. */
#ifndef YY_LOCATION_PRINT
# define YY_LOCATION_PRINT(File, Loc) ((void) 0)
#endif


# define YY_SYMBOL_PRINT(Title, Type, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Type, Value); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*----------------------------------------.
| Print this symbol's value on YYOUTPUT.  |
`----------------------------------------*/

static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
{
  FILE *yyo = yyoutput;
  YYUSE (yyo);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# endif
  YYUSE (yytype);
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
{
  YYFPRINTF (yyoutput, "%s %s (",
             yytype < YYNTOKENS ? "token" : "nterm", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yytype_int16 *yybottom, yytype_int16 *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yytype_int16 *yyssp, YYSTYPE *yyvsp, int yyrule)
{
  unsigned long int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       yystos[yyssp[yyi + 1 - yynrhs]],
                       &(yyvsp[(yyi + 1) - (yynrhs)])
                                              );
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif


#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
yystrlen (const char *yystr)
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
yystpcpy (char *yydest, const char *yysrc)
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
        switch (*++yyp)
          {
          case '\'':
          case ',':
            goto do_not_strip_quotes;

          case '\\':
            if (*++yyp != '\\')
              goto do_not_strip_quotes;
            /* Fall through.  */
          default:
            if (yyres)
              yyres[yyn] = *yyp;
            yyn++;
            break;

          case '"':
            if (yyres)
              yyres[yyn] = '\0';
            return yyn;
          }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return 1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return 2 if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYSIZE_T *yymsg_alloc, char **yymsg,
                yytype_int16 *yyssp, int yytoken)
{
  YYSIZE_T yysize0 = yytnamerr (YY_NULLPTR, yytname[yytoken]);
  YYSIZE_T yysize = yysize0;
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat. */
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  /* Number of reported tokens (one for the "unexpected", one per
     "expected"). */
  int yycount = 0;

  /* There are many possibilities here to consider:
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yytoken != YYEMPTY)
    {
      int yyn = yypact[*yyssp];
      yyarg[yycount++] = yytname[yytoken];
      if (!yypact_value_is_default (yyn))
        {
          /* Start YYX at -YYN if negative to avoid negative indexes in
             YYCHECK.  In other words, skip the first -YYN actions for
             this state because they are default actions.  */
          int yyxbegin = yyn < 0 ? -yyn : 0;
          /* Stay within bounds of both yycheck and yytname.  */
          int yychecklim = YYLAST - yyn + 1;
          int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
          int yyx;

          for (yyx = yyxbegin; yyx < yyxend; ++yyx)
            if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR
                && !yytable_value_is_error (yytable[yyx + yyn]))
              {
                if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
                  {
                    yycount = 1;
                    yysize = yysize0;
                    break;
                  }
                yyarg[yycount++] = yytname[yyx];
                {
                  YYSIZE_T yysize1 = yysize + yytnamerr (YY_NULLPTR, yytname[yyx]);
                  if (! (yysize <= yysize1
                         && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
                    return 2;
                  yysize = yysize1;
                }
              }
        }
    }

  switch (yycount)
    {
# define YYCASE_(N, S)                      \
      case N:                               \
        yyformat = S;                       \
      break
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
# undef YYCASE_
    }

  {
    YYSIZE_T yysize1 = yysize + yystrlen (yyformat);
    if (! (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
      return 2;
    yysize = yysize1;
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return 1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yyarg[yyi++]);
          yyformat += 2;
        }
      else
        {
          yyp++;
          yyformat++;
        }
  }
  return 0;
}
#endif /* YYERROR_VERBOSE */

/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep)
{
  YYUSE (yyvaluep);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yytype);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}




/* The lookahead symbol.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;
/* Number of syntax errors so far.  */
int yynerrs;


/*----------.
| yyparse.  |
`----------*/

int
yyparse (void)
{
    int yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       'yyss': related to states.
       'yyvs': related to semantic values.

       Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yytype_int16 yyssa[YYINITDEPTH];
    yytype_int16 *yyss;
    yytype_int16 *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    YYSIZE_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yyssp = yyss = yyssa;
  yyvsp = yyvs = yyvsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */
  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        YYSTYPE *yyvs1 = yyvs;
        yytype_int16 *yyss1 = yyss;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * sizeof (*yyssp),
                    &yyvs1, yysize * sizeof (*yyvsp),
                    &yystacksize);

        yyss = yyss1;
        yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yytype_int16 *yyss1 = yyss;
        union yyalloc *yyptr =
          (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
        if (! yyptr)
          goto yyexhaustedlab;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
                  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = yylex ();
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token.  */
  yychar = YYEMPTY;

  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 2:
#line 230 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    validateConfFile();
}
#line 2053 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 24:
#line 262 "mediator_config_parse.y" /* yacc.c:1646  */
    {
}
#line 2060 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 28:
#line 271 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseCollectorBegin((yyvsp[-1].transport), NULL);
}
#line 2068 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 29:
#line 276 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseCollectorBegin((yyvsp[-2].transport), (yyvsp[-1].str));
}
#line 2076 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 30:
#line 280 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseCollectorBegin((yyvsp[-2].transport), (yyvsp[-1].str));
}
#line 2084 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 31:
#line 285 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseCollectorEnd();
}
#line 2092 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 47:
#line 309 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseCollectorPort((yyvsp[-1].str));
}
#line 2100 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 48:
#line 314 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseCollectorHost((yyvsp[-1].str));
}
#line 2108 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 49:
#line 319 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseCollectorFile((yyvsp[-1].str));
}
#line 2116 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 50:
#line 324 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseCollectorWatchDir((yyvsp[-1].str));
}
#line 2124 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 51:
#line 329 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseCollectorSpreadDaemon((yyvsp[-1].str));
}
#line 2132 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 52:
#line 334 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseCollectorDecompressDirectory((yyvsp[-1].str));
}
#line 2140 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 55:
#line 343 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseCollectorSpreadGroup((yyvsp[-1].str));
}
#line 2148 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 56:
#line 348 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseCollectorLock();
}
#line 2156 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 57:
#line 353 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseCollectorMovePath((yyvsp[-1].str));
}
#line 2164 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 58:
#line 358 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseCollectorDelete();
}
#line 2172 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 66:
#line 376 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseFilterBegin();
}
#line 2180 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 67:
#line 381 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseFilterEnd();
}
#line 2188 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 68:
#line 386 "mediator_config_parse.y" /* yacc.c:1646  */
    {
}
#line 2195 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 70:
#line 394 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    numValueList = 0;
    valueListWild = 0;
}
#line 2204 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 72:
#line 401 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseValueListItems((yyvsp[0].str));
}
#line 2212 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 73:
#line 405 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseValueListItems((yyvsp[0].str));
}
#line 2220 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 74:
#line 408 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    valueListWild = 1;
}
#line 2228 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 76:
#line 416 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseFieldListItems(NULL, (yyvsp[0].field));
}
#line 2236 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 77:
#line 420 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseFieldListItems((yyvsp[0].str), 0);
}
#line 2244 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 78:
#line 424 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseFieldListItems(0, COLLECTOR);
}
#line 2252 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 79:
#line 428 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseFieldListItems((yyvsp[0].str), 0);
}
#line 2260 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 80:
#line 432 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseFieldListItems((yyvsp[0].str), 0);
}
#line 2268 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 81:
#line 436 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseFieldListItems(NULL, (yyvsp[0].field));
}
#line 2276 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 82:
#line 440 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseFieldListItems(NULL, (yyvsp[0].field));
}
#line 2284 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 83:
#line 444 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseFieldListItems(0, COLLECTOR);
}
#line 2292 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 84:
#line 448 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseFieldListItems(0, COLLECTOR);
}
#line 2300 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 87:
#line 457 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseComparison((yyvsp[-3].field), (yyvsp[-2].oper), (yyvsp[-1].str), VAL_INTEGER);
}
#line 2308 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 88:
#line 461 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseComparison((yyvsp[-3].field), (yyvsp[-2].oper), (yyvsp[-1].str), VAL_IP);
}
#line 2316 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 89:
#line 465 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    /* ANY_IP IN_LIST "my_set.set" */
    parseComparison((yyvsp[-3].field), (yyvsp[-2].oper), (yyvsp[-1].str), VAL_QSTRING);
}
#line 2325 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 90:
#line 470 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseComparison(80, (yyvsp[-2].oper), (yyvsp[-1].str), VAL_QSTRING);
}
#line 2333 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 91:
#line 474 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseComparison(80, (yyvsp[-2].oper), (yyvsp[-1].str), VAL_QSTRING);
}
#line 2341 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 92:
#line 485 "mediator_config_parse.y" /* yacc.c:1646  */
    {
}
#line 2348 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 93:
#line 489 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterBegin((yyvsp[-1].transport), NULL);
}
#line 2356 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 94:
#line 493 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterBegin((yyvsp[-2].transport), (yyvsp[-1].str));
}
#line 2364 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 95:
#line 497 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterBegin((yyvsp[-2].transport), (yyvsp[-1].str));
}
#line 2372 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 96:
#line 502 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterEnd();
}
#line 2380 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 142:
#line 556 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterSSLMD5Hash();
}
#line 2388 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 143:
#line 561 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterSSLSHA1Hash();
}
#line 2396 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 144:
#line 566 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterMovePath((yyvsp[-1].str));
}
#line 2404 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 145:
#line 571 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterSetAndFilter();
}
#line 2412 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 146:
#line 576 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    and_filter = TRUE;
}
#line 2420 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 147:
#line 581 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterPort((yyvsp[-1].str));
}
#line 2428 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 148:
#line 586 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterHost((yyvsp[-1].str));
}
#line 2436 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 149:
#line 591 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterFile((yyvsp[-1].str));
}
#line 2444 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 150:
#line 596 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterSpreadDaemon((yyvsp[-1].str));
}
#line 2452 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 153:
#line 605 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterSpreadGroup((yyvsp[-1].str));
}
#line 2460 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 154:
#line 610 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterTextDelimiter((yyvsp[-1].str));
}
#line 2468 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 155:
#line 615 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterDPIDelimiter((yyvsp[-1].str));
}
#line 2476 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 156:
#line 620 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterLock();
}
#line 2484 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 157:
#line 625 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterRotateSeconds((yyvsp[-1].str));
}
#line 2492 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 158:
#line 630 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterUDPTimeout((yyvsp[-1].str));
}
#line 2500 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 159:
#line 635 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterFlowOnly();
}
#line 2508 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 160:
#line 640 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterDPIOnly();
}
#line 2516 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 161:
#line 645 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterNoStats();
}
#line 2524 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 162:
#line 650 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterAddStats();
}
#line 2532 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 163:
#line 655 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterRemoveEmpty();
}
#line 2540 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 164:
#line 660 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterMultiFiles();
}
#line 2548 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 165:
#line 665 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterNoFlowStats();
}
#line 2556 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 166:
#line 670 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterJson();
}
#line 2564 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 167:
#line 675 "mediator_config_parse.y" /* yacc.c:1646  */
    {
}
#line 2571 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 168:
#line 679 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseSpreadGroup((yyvsp[-1].str));
}
#line 2579 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 169:
#line 684 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseSpreadGroupEnd();
}
#line 2587 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 170:
#line 690 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseStatisticsConfig();
}
#line 2595 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 171:
#line 695 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseStatsTimeout((yyvsp[-1].str));
}
#line 2603 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 172:
#line 700 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseDNSDeDupConfig();
}
#line 2611 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 173:
#line 705 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseDNSDeDupOnly();
}
#line 2619 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 174:
#line 710 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseSSLDeDupOnly(1);
}
#line 2627 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 175:
#line 713 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseSSLDeDupOnly(0);
}
#line 2635 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 176:
#line 718 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterNoFlow();
}
#line 2643 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 177:
#line 723 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterDedupOnly();
}
#line 2651 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 178:
#line 728 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterPrintHeader();
}
#line 2659 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 179:
#line 733 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterNoIndex();
}
#line 2667 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 180:
#line 738 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterEscapeChars();
}
#line 2675 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 181:
#line 743 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterDedupPerFlow();
}
#line 2683 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 182:
#line 748 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterTimestamp();
}
#line 2691 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 183:
#line 752 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterDNSRROnly(1);
}
#line 2699 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 184:
#line 756 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterDNSRROnly(2);
}
#line 2707 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 185:
#line 760 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterDNSRROnly(3);
}
#line 2715 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 186:
#line 764 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterDNSRROnly(4);
}
#line 2723 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 187:
#line 768 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterDNSRespOnly();
}
#line 2731 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 188:
#line 773 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterGzipFiles();
}
#line 2739 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 189:
#line 778 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterMetadataExport();
}
#line 2747 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 190:
#line 784 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseLogConfig((yyvsp[-1].str));
}
#line 2755 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 191:
#line 789 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseLogDir((yyvsp[-1].str));
}
#line 2763 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 192:
#line 794 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    md_log_level = (yyvsp[-1].log_level);
}
#line 2771 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 193:
#line 799 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parsePidFile((yyvsp[-1].str));
}
#line 2779 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 194:
#line 804 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseDedupRecordTypeList();
}
#line 2787 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 195:
#line 809 "mediator_config_parse.y" /* yacc.c:1646  */
    {
}
#line 2794 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 196:
#line 813 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    dedup_temp_name = (yyvsp[-1].str);
}
#line 2802 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 197:
#line 817 "mediator_config_parse.y" /* yacc.c:1646  */
    {
}
#line 2809 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 198:
#line 820 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseDNSDedupConfigEnd();
}
#line 2817 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 199:
#line 825 "mediator_config_parse.y" /* yacc.c:1646  */
    {
}
#line 2824 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 200:
#line 829 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseDedupConfig((yyvsp[-1].str));
}
#line 2832 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 201:
#line 833 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseDedupConfig(NULL);
}
#line 2840 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 202:
#line 838 "mediator_config_parse.y" /* yacc.c:1646  */
    {
}
#line 2847 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 213:
#line 857 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseMaxHitCount((yyvsp[-1].str));
}
#line 2855 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 214:
#line 862 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseMaxFlushTime((yyvsp[-1].str));
}
#line 2863 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 215:
#line 867 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseDedupAddExportName();
}
#line 2871 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 216:
#line 872 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    md_dedup_configure_state(etemp->dedup, 0, 0, TRUE, FALSE);
}
#line 2879 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 219:
#line 880 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseFileList((yyvsp[-3].str), (yyvsp[-2].field), NULL);
}
#line 2887 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 220:
#line 884 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    /* SIP by default */
    parseFileList((yyvsp[-2].str), 2, NULL);
}
#line 2896 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 221:
#line 889 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseFileList((yyvsp[-7].str), (yyvsp[-6].field), (yyvsp[-3].str));
}
#line 2904 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 222:
#line 892 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseFileList((yyvsp[-6].str), 2, (yyvsp[-3].str));
}
#line 2912 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 234:
#line 911 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseMapStmt((yyvsp[-2].str));
}
#line 2920 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 235:
#line 916 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    exportname = TRUE;
}
#line 2928 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 236:
#line 921 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseDNSMaxHitCount((yyvsp[-1].str));
}
#line 2936 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 237:
#line 926 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseDNSMaxFlushTime((yyvsp[-1].str));
}
#line 2944 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 238:
#line 931 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    md_config.dns_base64_encode = TRUE;
}
#line 2952 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 239:
#line 936 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    lastseen = TRUE;
}
#line 2960 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 240:
#line 941 "mediator_config_parse.y" /* yacc.c:1646  */
    {
}
#line 2967 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 241:
#line 945 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseTableListBegin(NULL);
}
#line 2975 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 242:
#line 949 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseTableListBegin((yyvsp[-1].str));
}
#line 2983 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 243:
#line 954 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    numValueList = 0;
}
#line 2991 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 244:
#line 959 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    numCustomList = 0;
}
#line 2999 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 249:
#line 971 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseTableList((yyvsp[-2].str));
}
#line 3007 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 251:
#line 977 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseMySQLParams((yyvsp[-1].str), NULL, NULL, NULL, NULL);
}
#line 3015 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 252:
#line 981 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseMySQLParams(NULL, (yyvsp[-1].str), NULL, NULL, NULL);
}
#line 3023 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 253:
#line 985 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseMySQLParams(NULL, NULL, (yyvsp[-1].str), NULL, NULL);
}
#line 3031 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 254:
#line 989 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseMySQLParams(NULL, NULL, NULL, (yyvsp[-1].str), NULL);
}
#line 3039 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 255:
#line 993 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseMySQLParams(NULL, NULL, NULL, NULL, (yyvsp[-1].str));
}
#line 3047 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 256:
#line 997 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseUserInfoElement((yyvsp[-2].str), (yyvsp[-1].str), NULL);
}
#line 3055 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 257:
#line 1001 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseUserInfoElement((yyvsp[-3].str), (yyvsp[-2].str), (yyvsp[-1].str));
}
#line 3063 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 258:
#line 1006 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseExporterRemoveUploaded();
}
#line 3071 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 259:
#line 1011 "mediator_config_parse.y" /* yacc.c:1646  */
    {
}
#line 3078 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 260:
#line 1015 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseSSLConfigBegin((yyvsp[-1].str));
}
#line 3086 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 261:
#line 1019 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    numValueList = 0;
}
#line 3094 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 276:
#line 1040 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    md_ssl_dedup_configure_state(etemp->ssl_dedup, 0, 0, NULL, NULL, TRUE);
}
#line 3102 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 277:
#line 1045 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseMapStmt((yyvsp[-2].str));
    md_ssl_dedup_configure_state(etemp->ssl_dedup, 0, 0, NULL, mapitem, FALSE);
    mapitem = NULL;
}
#line 3112 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 278:
#line 1052 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseSSLIssuerTypeList();
}
#line 3120 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 279:
#line 1057 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseSSLSubjectTypeList();
}
#line 3128 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 280:
#line 1062 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseSSLOtherTypeList();
}
#line 3136 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 281:
#line 1067 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseSSLExtensionsTypeList();
}
#line 3144 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 282:
#line 1072 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseSSLCertDedup();
}
#line 3152 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 283:
#line 1077 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseSSLMaxHitCount((yyvsp[-1].str));
}
#line 3160 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 284:
#line 1082 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseSSLMaxFlushTime((yyvsp[-1].str));
}
#line 3168 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 285:
#line 1087 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseSSLCertFile((yyvsp[-1].str));
}
#line 3176 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 286:
#line 1092 "mediator_config_parse.y" /* yacc.c:1646  */
    {
}
#line 3183 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 287:
#line 1096 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseVlanMapBegin((yyvsp[-1].str));
}
#line 3191 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 294:
#line 1110 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseVlanMapLine((yyvsp[-2].str));
}
#line 3199 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 295:
#line 1115 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseMapEnd();
}
#line 3207 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 296:
#line 1120 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseMapOther((yyvsp[-2].str));
}
#line 3215 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 297:
#line 1125 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseMapDiscard();
}
#line 3223 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 298:
#line 1130 "mediator_config_parse.y" /* yacc.c:1646  */
    {
}
#line 3230 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 299:
#line 1134 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseObidMapBegin((yyvsp[-1].str));
}
#line 3238 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 306:
#line 1149 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseObidMapLine((yyvsp[-2].str));
}
#line 3246 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 307:
#line 1154 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseMapEnd();
}
#line 3254 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 308:
#line 1159 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseMapOther((yyvsp[-2].str));
}
#line 3262 "mediator_config_parse.c" /* yacc.c:1646  */
    break;

  case 309:
#line 1164 "mediator_config_parse.y" /* yacc.c:1646  */
    {
    parseMapDiscard();
}
#line 3270 "mediator_config_parse.c" /* yacc.c:1646  */
    break;


#line 3274 "mediator_config_parse.c" /* yacc.c:1646  */
      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYEMPTY : YYTRANSLATE (yychar);

  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (YY_("syntax error"));
#else
# define YYSYNTAX_ERROR yysyntax_error (&yymsg_alloc, &yymsg, \
                                        yyssp, yytoken)
      {
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = YYSYNTAX_ERROR;
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == 1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = (char *) YYSTACK_ALLOC (yymsg_alloc);
            if (!yymsg)
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = 2;
              }
            else
              {
                yysyntax_error_status = YYSYNTAX_ERROR;
                yymsgp = yymsg;
              }
          }
        yyerror (yymsgp);
        if (yysyntax_error_status == 2)
          goto yyexhaustedlab;
      }
# undef YYSYNTAX_ERROR
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == YYEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYTERROR;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;


      yydestruct ("Error: popping",
                  yystos[yystate], yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#if !defined yyoverflow || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  yystos[*yyssp], yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  return yyresult;
}
#line 1171 "mediator_config_parse.y" /* yacc.c:1906  */


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

