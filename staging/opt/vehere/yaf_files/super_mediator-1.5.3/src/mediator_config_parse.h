/* A Bison parser, made by GNU Bison 3.0.4.  */

/* Bison interface for Yacc-like parsers in C

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
#line 173 "mediator_config_parse.y" /* yacc.c:1909  */

    char                   *str;
    uint32_t                integer;
    mdParserNumber_t        *number;
    mdTransportType_t       transport;
    mdAcceptFilterField_t   field;
    fieldOperator           oper;
    mdLogLevel_t            log_level;

#line 274 "mediator_config_parse.h" /* yacc.c:1909  */
};

typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;

int yyparse (void);

#endif /* !YY_YY_MEDIATOR_CONFIG_PARSE_H_INCLUDED  */
