#ifndef _MEDCONFIG_H
#define _MEDCONFIG_H

typedef struct mdParserNumber_st {
    int                 type;
    char               *string_value;
    union value_un {
        uint32_t  u32;
        double    d;
    }                   value;
} mdParserNumber_t;

extern int mediatorconf_errors;
extern int lineNumber;

int mediator_config_error(const char *fmt);

/* Provide some grammar debugging info, if necessary */
#define YYDEBUG 1
#define YYERROR_VERBOSE 1

/* this list of definitions is from the automake info page */
#define MAX_VALUE_LIST    30
#define yymaxdepth  mediatorConfig_maxdepth
#define yyparse     mediatorConfig_parse
#define yylex       mediatorConfig_lex
#define yyerror     mediatorConfig_error
/*#define yylval      mediatorConfig_lval*/
#define yychar      mediatorConfig_char
#define yydebug     mediatorConfig_debug
#define yypact      mediatorConfig_pact
#define yyr1        mediatorConfig_r1
#define yyr2        mediatorConfig_r2
#define yydef       mediatorConfig_def
#define yychk       mediatorConfig_chk
#define yypgo       mediatorConfig_pgo
#define yyact       mediatorConfig_act
#define yyexca      mediatorConfig_exca
#define yyerrflag   mediatorConfig_errflag
#define yynerrs     mediatorConfig_nerrs
#define yyps        mediatorConfig_ps
#define yypv        mediatorConfig_pv
#define yys         mediatorConfig_s
#define yy_yys      mediatorConfig_yys
#define yystate     mediatorConfig_state
#define yytmp       mediatorConfig_tmp
#define yyv         mediatorConfig_v
#define yy_yyv      mediatorConfig_yyv
#define yyval       mediatorConfig_val
#define yylloc      mediatorConfig_lloc
#define yyreds      mediatorConfig_reds
#define yytoks      mediatorConfig_toks
#define yylhs       mediatorConfig_yylhs
#define yylen       mediatorConfig_yylen
#define yydefred    mediatorConfig_yydefred
#define yydgoto     mediatorConfig_yydgoto
#define yysindex    mediatorConfig_yysindex
#define yyrindex    mediatorConfig_yyrindex
#define yygindex    mediatorConfig_yygindex
#define yytable     mediatorConfig_yytable
#define yycheck     mediatorConfig_yycheck
#define yyname      mediatorConfig_yyname
#define yyrule      mediatorConfig_yyrule


int yyparse(void);
int yylex(void);
int yyerror(const char *s);

extern int yydebug;
extern FILE *yyin;

#endif /* _MEDIATORCONFIG_H */
