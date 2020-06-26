%{
#include <mediator/mediator_ctx.h>
#include <stdint.h>
#include <ctype.h>
#include <mediator/mediator_config.h>
#include "mediator_config_parse.h"

int mediatorconf_errors = 0;
int lineNumber       = 1;

#define BUF_SIZE 2048
static char pipeconf_buf[BUF_SIZE];
static char *pipeconf_buf_end = pipeconf_buf + BUF_SIZE - 1;
static char *pipeconf_buf_ptr;

#define STRING_CHECK                            \
    if (pipeconf_buf_ptr >= pipeconf_buf_end) { \
        *pipeconf_buf_end = '\0';               \
        printf("String too long");         \
        BEGIN(ST_STRING_ERR);                   \
    }

%}

%option never-interactive nounput

%x ST_STRING

    /* state to use when a quoted string is too long */

%x ST_STRING_ERR

    /* state for reading pysilk code.  we accept everything until a
     * line that begins with "end" */

    /* %x ST_PYSILK */

    /* state to use when parsing an argument and we come to the end of
     * the line. We delay incrementing the line count until after the
     * parser returns so errors are reported on the correct line. */

%x ST_NEWLINE


%x ST_TOKEN_ERR

     /* character classes */

wschar      [ \t\r]

wsopt       {wschar}*

ws          {wschar}+

comment     {wsopt}#.*\n

nl          {wsopt}\n

eol         {nl}|{comment}

    /* Atoms (symbols) without quotes */

atomchar    [-_/@A-Za-z0-9]
atom        {atomchar}+

    /* numbers */

number      [0-9]+
exponent    [Ee][-+]?{number}

    /* various forms for IP addresses */

ip4         [0-9]+\.[0-9]+\.[0-9\./]+
ip6         [0-9a-fA-F:]*:[0-9a-fA-F:]*:[0-9a-fA-F\.\:/]*
int_cidr    [0-9]+\/[0-9]+

ip          {ip4}|{ip6}|{int_cidr}

    /* date / time */

timestr     [0-9]+[-/][0-9]+[-/][0-9Tt:.]+

%%

{eol}                   {lineNumber++; return EOS;}
{ws}                    ;
"["                     {return LEFT_SQ_BRACKET;}
"]"                     {return RIGHT_SQ_BRACKET;}
"("                     {return LEFT_PAREN;}
")"                     {return RIGHT_PAREN;}
","                     {return COMMA;}
"*"                     {return WILD;}
MEDIATOR                {return TOK_MEDIATOR;}
END                     {return TOK_END;}
COLLECTOR               {return TOK_COLLECTOR;}
EXPORTER                {return TOK_EXPORTER;}
SPREAD                  {yylval.transport = SPREAD; return VAL_TRANSPORT;}
DECOMPRESS_DIRECTORY    {return TOK_DECOMPRESS;}
DECOMPRESS{ws}DIRECTORY {return TOK_DECOMPRESS;}
DECOMPRESS              {return TOK_DECOMPRESS;}
DNS_DEDUP               {return TOK_DNS_DEDUP;}
DNS{ws}DEDUP            {return TOK_DNS_DEDUP;}
DNS_DEDUP_ONLY          {return TOK_DNSDEDUP_ONLY;}
DNS{ws}DEDUP{ws}ONLY    {return TOK_DNSDEDUP_ONLY;}
DEDUP_PER_FLOW          {return TOK_DEDUP_PER_FLOW;}
DEDUP{ws}PER{ws}FLOW    {return TOK_DEDUP_PER_FLOW;}
DEDUP_CONFIG            {return TOK_DEDUP_CONFIG;}
DEDUP{ws}CONFIG         {return TOK_DEDUP_CONFIG;}
DEDUP_ONLY              {return TOK_DEDUP_ONLY;}
DEDUP{ws}ONLY           {return TOK_DEDUP_ONLY;}
NO_FLOW                 {return TOK_NO_FLOW;}
NO{ws}FLOW              {return TOK_NO_FLOW;}
MERGE_TRUNCATED         {return TOK_MERGE;}
MERGE{ws}TRUNCATED      {return TOK_MERGE;}
DPI_CONFIG              {return TOK_DPI_CONFIG;}
DPI{ws}CONFIG           {return TOK_DPI_CONFIG;}
FILE_PREFIX             {return TOK_FILE;}
PREFIX                  {return TOK_FILE;}
FILE{ws}PREFIX          {return TOK_FILE;}
SSL_CONFIG              {return TOK_SSL_CONFIG;}
SSL{ws}CONFIG           {return TOK_SSL_CONFIG;}
ISSUER                  {return TOK_ISSUER;}
SUBJECT                 {return TOK_SUBJECT;}
OTHER                   {return TOK_OTHER;}
EXTENSION               {return TOK_EXTENSIONS;}
EXTENSIONS              {return TOK_EXTENSIONS;}
SSL_CERT_DEDUP          {return TOK_SSL_DEDUP;}
SSL_DEDUP               {return TOK_SSL_DEDUP;}
SSL{ws}CERT{ws}DEDUP    {return TOK_SSL_DEDUP;}
SSL{ws}DEDUP            {return TOK_SSL_DEDUP;}
SSL_DEDUP_ONLY          {return TOK_SSL_DEDUP_ONLY;}
SSL{ws}DEDUP{ws}ONLY    {return TOK_SSL_DEDUP_ONLY;}
CERT_FILE               {return TOK_CERT_FILE;}
CERT{ws}FILE            {return TOK_CERT_FILE;}
SSL_CERT_HASH_SHA1      {return TOK_SHA1;}
SSL{ws}CERT{ws}HASH{ws}SHA1 {return TOK_SHA1;}
SHA1                    {return TOK_SHA1;}
SHA1_HASH               {return TOK_SHA1;}
SSL_CERT_HASH_MD5       {return TOK_MD5;}
SSL{ws}CERT{ws}HASH{ws}MD5 {return TOK_MD5;}
MD5                     {return TOK_MD5;}
MD5_HASH                {return TOK_MD5;}
DPI_FIELD_LIST          {return TOK_DPI_FIELD_LIST;}
DPI{ws}FIELD{ws}LIST    {return TOK_DPI_FIELD_LIST;}
DPI_FIELDS              {return TOK_DPI_FIELD_LIST;}
TABLE                   {return TOK_TABLE;}
MULTI                   {return TOK_MULTI_FILES;}
MULTI_FILES             {return TOK_MULTI_FILES;}
MULTI{ws}FILES          {return TOK_MULTI_FILES;}
JSON                    {return TOK_JSON;}
FILTER                  {return TOK_FILTER;}
NO_STATS                {return TOK_NO_STATS;}
NO{ws}STATS             {return TOK_NO_STATS;}
STATS_TIMEOUT           {return TOK_STATS_TO;}
STATS{ws}TIMEOUT        {return TOK_STATS_TO;}
HOSTNAME                {return TOK_HOST;}
HOST                    {return TOK_HOST;}
IP_ADDRESS              {return TOK_HOST;}
IP{ws}ADDRESS           {return TOK_HOST;}
FILEHANDLER             {yylval.transport = FILEHANDLER; return VAL_TRANSPORT;}
FILE                    {return TOK_PATH;}
PATH                    {return TOK_PATH;}
TEXT                    {yylval.transport = TEXT; return VAL_TRANSPORT;}
DIR                     {yylval.transport = DIRECTORY; return VAL_TRANSPORT;}
DIRECTORY               {yylval.transport = DIRECTORY; return VAL_TRANSPORT;}
POLL                    {return TOK_POLL;}
DAEMON                  {return TOK_DAEMON;}
GROUP                   {return TOK_GROUP;}
MOVE_PATH               {return TOK_MOVE;}
MOVE{ws}PATH            {return TOK_MOVE;}
MOVE                    {return TOK_MOVE;}
DELIMITER               {return TOK_DELIM;}
DELIM                   {return TOK_DELIM;}
DPI_DELIMITER           {return TOK_DPI_DELIMITER;}
DELETE                  {return TOK_DELETE;}
LOCK                    {return TOK_LOCK;}
LOG_FILE                {return TOK_LOG_FILE;}
LOG{ws}FILE             {return TOK_LOG_FILE;}
LOG                     {return TOK_LOG_FILE;}
LOG_DIRECTORY           {return TOK_LOG_DIR;}
LOG{ws}DIRECTORY        {return TOK_LOG_DIR;}
LOG_DIR                 {return TOK_LOG_DIR;}
LOG{ws}DIR              {return TOK_LOG_DIR;}
LOGDIR                  {return TOK_LOG_DIR;}
UDP_TEMPLATE_TIMEOUT    {return TOK_UDP_TIMEOUT;}
UDP{ws}TEMPLATE{ws}TIMEOUT {return TOK_UDP_TIMEOUT;}
UDP{ws}TIMEOUT          {return TOK_UDP_TIMEOUT;}
ROTATE                  {return TOK_ROTATE;}
PORT                    {return TOK_PORT;}
USER_IE                 {return TOK_USERIE;}
USER{ws}IE              {return TOK_USERIE;}
TCP                     {yylval.transport = TCP;  return VAL_TRANSPORT;}
UDP                     {yylval.transport = UDP;  return VAL_TRANSPORT;}
FLOW{ws}ONLY            {return TOK_FLOW_ONLY;}
FLOW_ONLY               {return TOK_FLOW_ONLY;}
DPI{ws}ONLY             {return TOK_DPI_ONLY;}
DPI_ONLY                {return TOK_DPI_ONLY;}
STATS_ONLY              {return TOK_STATS_ONLY;}
STATS{ws}ONLY           {return TOK_STATS_ONLY;}
STATS                   {return TOK_STATS_ONLY;}
DNS_RR_ONLY             {return TOK_DNSRR_ONLY;}
DNS{ws}RR{ws}ONLY       {return TOK_DNSRR_ONLY;}
DNS_RESPONSE_ONLY       {return TOK_RESP_ONLY;}
DNS_RR                  {return TOK_DNSRR;}
DNS{ws}RR               {return TOK_DNSRR;}
FULL                    {return TOK_FULL;}
full                    {return TOK_FULL;}
PRINT_HEADER            {return TOK_PRINT_HDR;}
PRINT{ws}HEADER         {return TOK_PRINT_HDR;}
NO_INDEX                {return TOK_NO_INDEX;}
NO{ws}INDEX             {return TOK_NO_INDEX;}
NO_FLOW_STATS           {return TOK_NO_FLOW_STATS;}
NO{ws}FLOW{ws}STATS     {return TOK_NO_FLOW_STATS;}
TIMESTAMP_FILES         {return TOK_TIMESTAMP;}
TIMESTAMP{ws}FILES      {return TOK_TIMESTAMP;}
FIELDS                  {return TOK_FIELDS;}
APPLICATION             {yylval.field = APPLICATION; return VAL_FIELD;}
application             {yylval.field = APPLICATION; return VAL_FIELD;}
app                     {yylval.field =APPLICATION; return VAL_FIELD;}
APP                     {yylval.field =APPLICATION; return VAL_FIELD;}
DIP                     {yylval.field = DIP_ANY; return VAL_FIELD;}
dip                     {yylval.field = DIP_ANY; return VAL_FIELD;}
DIP_INT                 {yylval.field = DIP_INT; return VAL_FIELD;}
DIPINT                  {yylval.field = DIP_INT; return VAL_FIELD;}
dipint                  {yylval.field = DIP_INT; return VAL_FIELD;}
DIP_V4                  {yylval.field = DIP_V4; return VAL_FIELD;}
DIP{ws}V4               {yylval.field = DIP_V4; return VAL_FIELD;}
DPORT                   {yylval.field = DPORT; return VAL_FIELD;}
dport                   {yylval.field = DPORT; return VAL_FIELD;}
ANY_IP                  {yylval.field = ANY_IP; return VAL_FIELD;}
ANY_IP6                 {yylval.field = ANY_IP6; return VAL_FIELD;}
IP                      {yylval.field = ANY_IP; return VAL_FIELD;}
ANY_PORT                {yylval.field = ANY_PORT; return VAL_FIELD;}
ANY{ws}PORT             {yylval.field = ANY_PORT; return VAL_FIELD;}
PROTOCOL                {yylval.field = PROTOCOL; return VAL_FIELD;}
protocol                {yylval.field = PROTOCOL; return VAL_FIELD;}
proto                   {yylval.field = PROTOCOL; return VAL_FIELD;}
SPORT                   {yylval.field = SPORT; return VAL_FIELD;}
sport                   {yylval.field = SPORT; return VAL_FIELD;}
SIP_V4                  {yylval.field = SIP_V4; return VAL_FIELD;}
SIP{ws}V4               {yylval.field = SIP_V4; return VAL_FIELD;}
SIP                     {yylval.field = SIP_ANY; return VAL_FIELD;}
sip                     {yylval.field = SIP_ANY; return VAL_FIELD;}
SIP_INT                 {yylval.field = SIP_INT; return VAL_FIELD;}
SIPINT                  {yylval.field = SIP_INT; return VAL_FIELD;}
sipint                  {yylval.field = SIP_INT; return VAL_FIELD;}
SIP_V6                  {yylval.field = SIP_V6; return VAL_FIELD;}
SIP{ws}V6               {yylval.field = SIP_V6; return VAL_FIELD;}
DIP_V6                  {yylval.field = DIP_V6; return VAL_FIELD;}
DIP{ws}V6               {yylval.field = DIP_V6; return VAL_FIELD;}
VERSION                 {yylval.field = IPVERSION; return VAL_FIELD;}
VLAN                    {yylval.field = VLAN; return VAL_FIELD;}
vlan                    {yylval.field = VLAN; return VAL_FIELD;}
VLANINT                 {yylval.field = VLANINT; return VAL_FIELD;}
vlanint                 {yylval.field = VLANINT; return VAL_FIELD;}
OBDOMAIN                {yylval.field = OBDOMAIN; return VAL_FIELD;}
obdomain                {yylval.field = OBDOMAIN; return VAL_FIELD;}
INGRESS                 {yylval.field = INGRESS; return VAL_FIELD;}
ingress                 {yylval.field = INGRESS; return VAL_FIELD;}
EGRESS                  {yylval.field = EGRESS; return VAL_FIELD;}
egress                  {yylval.field = EGRESS; return VAL_FIELD;}
DOMAIN                  {yylval.field = OBDOMAIN; return VAL_FIELD;}
domain                  {yylval.field = OBDOMAIN; return VAL_FIELD;}
DURATION                {yylval.field = DURATION; return VAL_FIELD;}
duration                {yylval.field = DURATION; return VAL_FIELD;}
dur                     {yylval.field = DURATION; return VAL_FIELD;}
STIME                   {yylval.field = STIME; return VAL_FIELD;}
stime                   {yylval.field = STIME; return VAL_FIELD;}
STIMEMS                 {yylval.field = STIMEMS; return VAL_FIELD;}
stimems                 {yylval.field = STIMEMS; return VAL_FIELD;}
ETIME                   {yylval.field = ENDTIME; return VAL_FIELD;}
etime                   {yylval.field = ENDTIME; return VAL_FIELD;}
ETIMEMS                 {yylval.field = ETIMEMS; return VAL_FIELD;}
etimems                 {yylval.field = ETIMEMS; return VAL_FIELD;}
RTT                     {yylval.field = RTT; return VAL_FIELD;}
rtt                     {yylval.field = RTT; return VAL_FIELD;}
PKTS                    {yylval.field = PKTS; return VAL_FIELD;}
pkts                    {yylval.field = PKTS; return VAL_FIELD;}
PACKETS                 {yylval.field = PKTS; return VAL_FIELD;}
packets                 {yylval.field = PKTS; return VAL_FIELD;}
RPKTS                   {yylval.field = RPKTS; return VAL_FIELD;}
rpkts                   {yylval.field = RPKTS; return VAL_FIELD;}
RPACKETS                {yylval.field = RPKTS; return VAL_FIELD;}
rpackets                {yylval.field = RPKTS; return VAL_FIELD;}
BYTES                   {yylval.field = BYTES; return VAL_FIELD;}
bytes                   {yylval.field = BYTES; return VAL_FIELD;}
RBYTES                  {yylval.field = RBYTES; return VAL_FIELD;}
rbytes                  {yylval.field = RBYTES; return VAL_FIELD;}
IFLAGS                  {yylval.field = IFLAGS; return VAL_FIELD;}
iflags                  {yylval.field = IFLAGS; return VAL_FIELD;}
RIFLAGS                 {yylval.field = RIFLAGS; return VAL_FIELD;}
riflags                 {yylval.field = RIFLAGS; return VAL_FIELD;}
UFLAGS                  {yylval.field = UFLAGS; return VAL_FIELD;}
uflags                  {yylval.field = UFLAGS; return VAL_FIELD;}
RUFLAGS                 {yylval.field = RUFLAGS; return VAL_FIELD;}
ruflags                 {yylval.field = RUFLAGS; return VAL_FIELD;}
ATTRIBUTES              {yylval.field = ATTRIBUTES; return VAL_FIELD;}
attributes              {yylval.field = ATTRIBUTES; return VAL_FIELD;}
RATTRIBUTES             {yylval.field = RATTRIBUTES; return VAL_FIELD;}
rattributes             {yylval.field = RATTRIBUTES; return VAL_FIELD;}
MAC                     {yylval.field = MAC; return VAL_FIELD;}
mac                     {yylval.field = MAC; return VAL_FIELD;}
DSTMAC                  {yylval.field = DSTMAC; return VAL_FIELD;}
dstmac                  {yylval.field = DSTMAC; return VAL_FIELD;}
TCPSEQ                  {yylval.field = TCPSEQ; return VAL_FIELD;}
tcpseq                  {yylval.field = TCPSEQ; return VAL_FIELD;}
RTCPSEQ                 {yylval.field = RTCPSEQ; return VAL_FIELD;}
rtcpseq                 {yylval.field = RTCPSEQ; return VAL_FIELD;}
ENTROPY                 {yylval.field = ENTROPY; return VAL_FIELD;}
entropy                 {yylval.field = ENTROPY; return VAL_FIELD;}
RENTROPY                {yylval.field = RENTROPY; return VAL_FIELD;}
rentropy                {yylval.field = RENTROPY; return VAL_FIELD;}
ENDREASON               {yylval.field = END; return VAL_FIELD;}
endreason               {yylval.field = END; return VAL_FIELD;}
OSNAME                  {yylval.field = OSNAME; return VAL_FIELD;}
osname                  {yylval.field = OSNAME; return VAL_FIELD;}
OSVERSION               {yylval.field = OSVERSION; return VAL_FIELD;}
osversion               {yylval.field = OSVERSION; return VAL_FIELD;}
ROSNAME                 {yylval.field = ROSNAME; return VAL_FIELD;}
rosname                 {yylval.field = ROSNAME; return VAL_FIELD;}
ROSVERSION              {yylval.field = ROSVERSION; return VAL_FIELD;}
rosversion              {yylval.field = ROSVERSION; return VAL_FIELD;}
FINGERPRINT             {yylval.field = FINGERPRINT; return VAL_FIELD;}
fingerprint             {yylval.field = FINGERPRINT; return VAL_FIELD;}
RFINGERPRINT            {yylval.field = RFINGERPRINT; return VAL_FIELD;}
rfingerprint            {yylval.field = RFINGERPRINT; return VAL_FIELD;}
OSFINGERPRINT           {yylval.field = FINGERPRINT; return VAL_FIELD;}
osfingerprint           {yylval.field = FINGERPRINT; return VAL_FIELD;}
ROSFINGERPRINT          {yylval.field = RFINGERPRINT; return VAL_FIELD;}
rosfingerprint          {yylval.field = RFINGERPRINT; return VAL_FIELD;}
DHCPFP                  {yylval.field = DHCPFP; return VAL_FIELD;}
dhcpfp                  {yylval.field = DHCPFP; return VAL_FIELD;}
DHCPVC                  {yylval.field = DHCPVC; return VAL_FIELD;}
dhcpvc                  {yylval.field = DHCPVC; return VAL_FIELD;}
RDHCPFP                 {yylval.field = RDHCPFP; return VAL_FIELD;}
rdhcpfp                 {yylval.field = RDHCPFP; return VAL_FIELD;}
RDHCPVC                 {yylval.field = RDHCPVC; return VAL_FIELD;}
rdhcpvc                 {yylval.field = RDHCPVC; return VAL_FIELD;}
DHCPOPTIONS             {yylval.field = DHCPOPTIONS; return VAL_FIELD;}
dhcpoptions             {yylval.field = DHCPOPTIONS; return VAL_FIELD;}
DHCPOPTION              {yylval.field = DHCPOPTIONS; return VAL_FIELD;}
dhcpoption              {yylval.field = DHCPOPTIONS; return VAL_FIELD;}
RDHCPOPTIONS            {yylval.field = RDHCPOPTIONS; return VAL_FIELD;}
rdhcpoptions            {yylval.field = RDHCPOPTIONS; return VAL_FIELD;}
rdhcpoption             {yylval.field = RDHCPOPTIONS; return VAL_FIELD;}
RDHCPOPTION             {yylval.field = RDHCPOPTIONS; return VAL_FIELD;}
DATABYTES               {yylval.field = DATABYTES; return VAL_FIELD;}
databytes               {yylval.field = DATABYTES; return VAL_FIELD;}
RDATABYTES              {yylval.field = RDATABYTES; return VAL_FIELD;}
rdatabytes              {yylval.field = RDATABYTES; return VAL_FIELD;}
ITIME                   {yylval.field = ITIME; return VAL_FIELD;}
itime                   {yylval.field = ITIME; return VAL_FIELD;}
RITIME                  {yylval.field = RITIME; return VAL_FIELD;}
ritime                  {yylval.field = RITIME; return VAL_FIELD;}
STDITIME                {yylval.field = STDITIME; return VAL_FIELD;}
stditime                {yylval.field = STDITIME; return VAL_FIELD;}
RSTDITIME               {yylval.field = RSTDITIME; return VAL_FIELD;}
rstditime               {yylval.field = RSTDITIME; return VAL_FIELD;}
TCPURG                  {yylval.field = TCPURG; return VAL_FIELD;}
tcpurg                  {yylval.field = TCPURG; return VAL_FIELD;}
RTCPURG                 {yylval.field = RTCPURG; return VAL_FIELD;}
rtcpurg                 {yylval.field = RTCPURG; return VAL_FIELD;}
SMALLPKTS               {yylval.field = SMALLPKTS; return VAL_FIELD;}
smallpkts               {yylval.field = SMALLPKTS; return VAL_FIELD;}
RSMALLPKTS              {yylval.field = RSMALLPKTS; return VAL_FIELD;}
rsmallpkts              {yylval.field = RSMALLPKTS; return VAL_FIELD;}
LARGEPKTS               {yylval.field = LARGEPKTS; return VAL_FIELD;}
largepkts               {yylval.field = LARGEPKTS; return VAL_FIELD;}
RLARGEPKTS              {yylval.field = RLARGEPKTS; return VAL_FIELD;}
rlargepkts              {yylval.field = RLARGEPKTS; return VAL_FIELD;}
NONEMPTYPKTS            {yylval.field = NONEMPTYPKTS; return VAL_FIELD;}
nonemptypkts            {yylval.field = NONEMPTYPKTS; return VAL_FIELD;}
RNONEMPTYPKTS           {yylval.field = RNONEMPTYPKTS; return VAL_FIELD;}
rnonemptypkts           {yylval.field = RNONEMPTYPKTS; return VAL_FIELD;}
FIRSTNONEMPTY           {yylval.field = FIRSTNONEMPTY; return VAL_FIELD;}
firstnonempty           {yylval.field = FIRSTNONEMPTY; return VAL_FIELD;}
RFIRSTNONEMPTY          {yylval.field = RFIRSTNONEMPTY; return VAL_FIELD;}
rfirstnonempty          {yylval.field = RFIRSTNONEMPTY; return VAL_FIELD;}
MAXSIZE                 {yylval.field = MAXSIZE; return VAL_FIELD;}
maxsize                 {yylval.field = MAXSIZE; return VAL_FIELD;}
RMAXSIZE                {yylval.field = RMAXSIZE; return VAL_FIELD;}
rmaxsize                {yylval.field = RMAXSIZE; return VAL_FIELD;}
STDPAYLEN               {yylval.field = STDPAYLEN; return VAL_FIELD;}
stdpaylen               {yylval.field = STDPAYLEN; return VAL_FIELD;}
RSTDPAYLEN              {yylval.field = RSTDPAYLEN; return VAL_FIELD;}
rstdpaylen              {yylval.field = RSTDPAYLEN; return VAL_FIELD;}
FIRSTEIGHT              {yylval.field = FIRSTEIGHT; return VAL_FIELD;}
firsteight              {yylval.field = FIRSTEIGHT; return VAL_FIELD;}
FLOWKEYHASH             {yylval.field = FLOWKEYHASH; return VAL_FIELD;}
flowkeyhash             {yylval.field = FLOWKEYHASH; return VAL_FIELD;}
HASH                    {yylval.field = FLOWKEYHASH; return VAL_FIELD;}
hash                    {yylval.field = FLOWKEYHASH; return VAL_FIELD;}
DPI                     {yylval.field = DPI; return VAL_FIELD;}
dpi                     {yylval.field = DPI; return VAL_FIELD;}
TOS                     {yylval.field = TOS; return VAL_FIELD;}
tos                     {yylval.field = TOS; return VAL_FIELD;}
RTOS                    {yylval.field = RTOS; return VAL_FIELD;}
rtos                    {yylval.field = RTOS; return VAL_FIELD;}
MPLS1                   {yylval.field = MPLS1; return VAL_FIELD;}
MPLS2                   {yylval.field = MPLS2; return VAL_FIELD;}
MPLS3                   {yylval.field = MPLS3; return VAL_FIELD;}
mpls1                   {yylval.field = MPLS1; return VAL_FIELD;}
mpls2                   {yylval.field = MPLS2; return VAL_FIELD;}
mpls3                   {yylval.field = MPLS3; return VAL_FIELD;}
collector               {yylval.field = COLLECTOR; return VAL_FIELD;}
MPTCPSEQ                {yylval.field = MPTCPSEQ; return VAL_FIELD;}
mptcpseq                {yylval.field = MPTCPSEQ; return VAL_FIELD;}
MPTCPTOKEN              {yylval.field = MPTCPTOKEN; return VAL_FIELD;}
mptcptoken              {yylval.field = MPTCPTOKEN; return VAL_FIELD;}
MPTCPMSS                {yylval.field = MPTCPMSS; return VAL_FIELD;}
mptcpmss                {yylval.field = MPTCPMSS; return VAL_FIELD;}
MPTCPID                 {yylval.field = MPTCPID; return VAL_FIELD;}
mptcpid                 {yylval.field = MPTCPID; return VAL_FIELD;}
MPTCPFLAGS              {yylval.field = MPTCPFLAGS; return VAL_FIELD;}
mptcpflags              {yylval.field = MPTCPFLAGS; return VAL_FIELD;}
PAYLOAD                 {yylval.field = PAYLOAD; return VAL_FIELD;}
payload                 {yylval.field = PAYLOAD; return VAL_FIELD;}
RPAYLOAD                {yylval.field = RPAYLOAD; return VAL_FIELD;}
rpayload                {yylval.field = RPAYLOAD; return VAL_FIELD;}
"=="                    {yylval.oper = EQUAL; return VAL_OPER;}
"!="                    {yylval.oper = NOT_EQUAL; return VAL_OPER;}
"<"                     {yylval.oper = LESS_THAN; return VAL_OPER;}
"<="                    {yylval.oper = LESS_THAN_OR_EQUAL; return VAL_OPER;}
">"                     {yylval.oper = GREATER_THAN; return VAL_OPER;}
">="                    {yylval.oper = GREATER_THAN_OR_EQUAL; return VAL_OPER;}
IN_LIST                 {yylval.oper = IN_LIST; return VAL_OPER;}
NOT_IN_LIST             {yylval.oper = NOT_IN_LIST; return VAL_OPER;}
MAX_HIT_COUNT           {return TOK_MAX_HIT;}
MAX{ws}HIT{ws}COUNT     {return TOK_MAX_HIT;}
FLUSH_TIME              {return TOK_FLUSH_SECS;}
FLUSH{ws}TIME           {return TOK_FLUSH_SECS;}
FLUSH_TIMEOUT           {return TOK_FLUSH_SECS;}
BASE64_ENCODE           {return TOK_BASE_64;}
BASE64{ws}ENCODE        {return TOK_BASE_64;}
LAST_SEEN               {return TOK_LAST_SEEN;}
LAST{ws}SEEN            {return TOK_LAST_SEEN;}
DEBUG                   {yylval.log_level = MD_DEBUG; return VAL_LOGLEVEL;}
MESSAGE                 {yylval.log_level = MESSAGE; return VAL_LOGLEVEL;}
QUIET                   {yylval.log_level = QUIET; return VAL_LOGLEVEL;}
WARNING                 {yylval.log_level = WARNING; return VAL_LOGLEVEL;}
ERROR                   {yylval.log_level = ERROR; return VAL_LOGLEVEL;}
LOGLEVEL                {return TOK_LOG_LEVEL;}
LOG{ws}LEVEL            {return TOK_LOG_LEVEL;}
LOG_LEVEL               {return TOK_LOG_LEVEL;}
PIDFILE                 {return TOK_PID_FILE;}
PID{ws}FILE             {return TOK_PID_FILE;}
REMOVE_EMPTY_FILES      {return TOK_RM_EMPTY;}
REMOVE{ws}EMPTY{ws}FILES {return TOK_RM_EMPTY;}
AND_FILTER              {return TOK_AND_FILTER;}
AND_FILTERS             {return TOK_AND_FILTER;}
AND{ws}FILTERS          {return TOK_AND_FILTER;}
AND{ws}FILTER           {return TOK_AND_FILTER;}
MYSQL_USER              {return TOK_MY_USER;}
MYSQL{ws}USER           {return TOK_MY_USER;}
MYSQL_PASSWORD          {return TOK_MY_PW;}
MYSQL{ws}PASSWORD       {return TOK_MY_PW;}
MYSQL_PASS              {return TOK_MY_PW;}
MYSQL_DATABASE          {return TOK_MY_DB;}
MYSQL{ws}DATABASE       {return TOK_MY_DB;}
MYSQL_DB                {return TOK_MY_DB;}
MYSQL_HOST              {return TOK_MY_HOST;}
MYSQL{ws}HOST           {return TOK_MY_HOST;}
MYSQL_TABLE             {return TOK_MY_TABLE;}
MYSQL{ws}TABLE          {return TOK_MY_TABLE;}
REMOVE_UPLOADED         {return TOK_MY_REMOVE;}
REMOVE{ws}UPLOADED      {return TOK_MY_REMOVE;}
ESCAPE_CHARS            {return TOK_ESCAPE;}
ESCAPE{ws}CHARS         {return TOK_ESCAPE;}
ESCAPE_CHARACTERS       {return TOK_ESCAPE;}
ESCAPE{ws}CHARACTERS    {return TOK_ESCAPE;}
ESCAPE                  {return TOK_ESCAPE;}
RECORDS                 {return TOK_RECORDS;}
GZIP_FILES              {return TOK_GZIP;}
GZIP{ws}FILES           {return TOK_GZIP;}
GZIP                    {return TOK_GZIP;}
VLAN_MAP                {return TOK_VLAN_MAP;}
VLAN{ws}MAP             {return TOK_VLAN_MAP;}
OBID_MAP                {return TOK_OBID_MAP;}
OBID{ws}MAP             {return TOK_OBID_MAP;}
MAP                     {return TOK_MAP;}
DISCARD_OTHER           {return TOK_DISCARD;}
DISCARD{ws}OTHER        {return TOK_DISCARD;}
DISCARD                 {return TOK_DISCARD;}
ADD_EXPORTER_NAME       {return TOK_ADD_EXPORT;}
ADD{ws}EXPORTER{ws}NAME {return TOK_ADD_EXPORT;}
ADD_EXPORTER            {return TOK_ADD_EXPORT;}
ADD{ws}EXPORTER         {return TOK_ADD_EXPORT;}
ADD_EXPORT              {return TOK_ADD_EXPORT;}
ADD_EXPORT_NAME         {return TOK_ADD_EXPORT;}
NDPI_MASTER             {yylval.field = NDPI_MASTER; return VAL_FIELD;}
ndpi_master             {yylval.field = NDPI_MASTER; return VAL_FIELD;}
NDPI_SUB                {yylval.field = NDPI_SUB; return VAL_FIELD;}
ndpi_sub                {yylval.field = NDPI_SUB; return VAL_FIELD;}
METADATA_EXPORT         {return TOK_METADATA_EXPORT;}

{ip}                    {yylval.str = strdup(yytext); return VAL_IP;}

{number}"."{number}     {yylval.str = strdup(yytext); return VAL_DOUBLE;}
"."{number}             {yylval.str = strdup(yytext); return VAL_DOUBLE;}
{number}"."             {yylval.str = strdup(yytext); return VAL_DOUBLE;}
{number}"."{number}{exponent}  {yylval.str = strdup(yytext);return VAL_DOUBLE;}
"."{number}{exponent}   {yylval.str = strdup(yytext); return VAL_DOUBLE;}
{number}"."{exponent}   {yylval.str = strdup(yytext); return VAL_DOUBLE;}
    
{number}                {yylval.str = strdup(yytext); return VAL_INTEGER;}

{atom}                  {yylval.str = strdup(yytext); return VAL_ATOM;}

\"                     {BEGIN(ST_STRING); pipeconf_buf_ptr = pipeconf_buf;}

<ST_STRING>\\n         {*pipeconf_buf_ptr++ = '\n'; STRING_CHECK;}
<ST_STRING>\\t         {*pipeconf_buf_ptr++ = '\t'; STRING_CHECK;}
<ST_STRING>\\r         {*pipeconf_buf_ptr++ = '\r'; STRING_CHECK;}
<ST_STRING>\\b         {*pipeconf_buf_ptr++ = '\b'; STRING_CHECK;}
<ST_STRING>\\f         {*pipeconf_buf_ptr++ = '\f'; STRING_CHECK;}
<ST_STRING>\\\n        {*pipeconf_buf_ptr++ = '\n'; STRING_CHECK;}
<ST_STRING>\\.         {*pipeconf_buf_ptr++ = yytext[1]; STRING_CHECK;}

<ST_STRING>[^\\\n\"]+  {if ((pipeconf_buf_ptr + yyleng) < pipeconf_buf_end ) {
                            memcpy(pipeconf_buf_ptr, yytext, yyleng);
                            pipeconf_buf_ptr += yyleng;
                        } else {
                            memcpy(pipeconf_buf_ptr, yytext,
                                   pipeconf_buf_end - pipeconf_buf_ptr);
                            *pipeconf_buf_end = '\0';
                            printf("String too long");
                            BEGIN(ST_STRING_ERR);
                        } }

<ST_STRING>\n          {BEGIN(INITIAL);
                        yyless(0);
                        printf("String missing closing \"");
                        *pipeconf_buf_ptr = '\0';
                        yylval.str = strdup(pipeconf_buf);
                        return VAL_QSTRING; }

<ST_STRING>\"          {BEGIN(INITIAL);
                        *pipeconf_buf_ptr = '\0';
                        yylval.str = strdup(pipeconf_buf);
                        return VAL_QSTRING; }

    /* ST_STRING_ERR state: Entered when a string is too long.
     * Accepts everything up to closing quote or the end of the
     * line. */

<ST_STRING_ERR>[^\\\n\"]+  ;
<ST_STRING_ERR>\\.         ;
<ST_STRING_ERR>\"      {BEGIN(INITIAL);
                        yylval.str = strdup(pipeconf_buf);
                        return VAL_QSTRING; }
<ST_STRING_ERR>\n      {BEGIN(INITIAL);
                        yyless(0);
                        printf("String missing closing \"");
                        yylval.str = strdup(pipeconf_buf);
                        return VAL_QSTRING; }

    /* Handle unknown keyword */

.                           {yyless(0); BEGIN(ST_TOKEN_ERR);}

<ST_TOKEN_ERR>[^ \t\r\n]+   {printf("Unrecognized token '%s'", yytext);
                             BEGIN(INITIAL); }


%%
int yywrap(void) {
    return 1;
}

int mediator_config_error(const char *fmt)
{
    lineNumber--; 
    mediatorconf_errors++;
    printf("Error on line: %d\n", lineNumber);
    printf("Error: %s\n", fmt);
    exit(-1); 
    return 0;
}
