/**
 * @file mediator.c
 *
 * Yaf mediator for filtering, DNS deduplication, and other mediator-like
 * things
 *
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2012-2017 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Emily Sarneso <netsa-help@cert.org>
 ** -----------------------------------------------------------------------
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


#include <mediator/mediator.h>
#include <mediator/mediator_inf.h>
#include <mediator/mediator_core.h>
#include <mediator/mediator_filter.h>
#include "mediator_dns.h"
#include "mediator_stat.h"
#include "mediator_log.h"
#include "mediator_dedup.h"
#include <glib.h>
#include <time.h>
#include <sys/time.h>
#include <pwd.h>
#include <grp.h>

/*#define MDLOG_TESTING_LOG 0*/

mdConfig_t                     md_config = MD_CONFIG_INIT;
char                           * md_iport = "18000";
char                           * md_logfile = NULL;
char                           * md_logdest = NULL;
char                           * md_pidfile = NULL;
char                           * last_logfile = NULL;
char                           * cur_logfile = NULL;
int                            md_stats_timeout = 300;
uint16_t                       dns_max_hit_count = 500;
uint16_t                       dns_flush_timeout = 300; /* 5 mins */
gboolean                       dns_dedup = FALSE;
mdTransportType_t              md_ipfix_intransport = NONE;
mdLogLevel_t                   md_log_level = WARNING;
time_t                         md_log_rolltime;
fbInfoElement_t                * user_elements = NULL;
#if HAVE_SPREAD
char                           **md_in_groups;
int                            num_in_groups = 0;
int                            num_out_groups = 0;
#endif
int                            md_quit = 0;
static gboolean                md_daemon = FALSE;
static char                    * md_eport = "18001";
static char                    * md_conf = NULL;
static char                    * md_in_str = NULL;
static char                    * md_out_str = NULL;
static char                    ** md_field_list;
static int                     rotate = 0;
static int                     sleep_usecs = 0;
static char                    * poll_time = NULL;
static mdTransportType_t       md_ipfix_outtransport = NONE;
static char                    *outspec = NULL;
static char                    *inspec = NULL;
static char                    *move_dir = NULL;
static GIOChannel              *logfile;
static GLogLevelFlags          level;
static gboolean                md_verbose = FALSE;
static gboolean                md_version = FALSE;
static gboolean                md_quiet = FALSE;
static gboolean                md_print_headers = FALSE;
static char                    *become_user = NULL;
static char                    *become_group = NULL;
static uid_t                   new_user = 0;
static gid_t                   new_group = 0;
static gboolean                did_become = FALSE;
static gboolean                md_metadata_export = FALSE;

typedef fBuf_t * (*mdLoop_fn)(mdConfig_t *md, GError **err);

static GOptionEntry md_core_option[] = {
    {"config", 'c', 0, G_OPTION_ARG_STRING, &md_conf,
     "specify the name of the config file []", "file_name"},
    {"in", 'i', 0, G_OPTION_ARG_STRING, &inspec,
     "File, Directory, or Host/I.P. to listen to [-]", "host"},
    {"out", 'o', 0, G_OPTION_ARG_STRING, &outspec,
     "File, Directory, or Host/IP to send output [-]", "host"},
    {"ipfix-port", 'p', 0, G_OPTION_ARG_STRING, &md_iport,
     "Select IPFIX Import port [18000]", "port"},
    {"ipfix-input", 0, 0, G_OPTION_ARG_STRING, &md_in_str,
     "Select mode of transport (TCP, UDP, SPREAD) []", "mode"},
    {"output-mode", 'm', 0, G_OPTION_ARG_STRING, &md_out_str,
     "Select mode of export transport \n\t\t\t\t "
     "(TCP, UDP, SPREAD, TEXT, JSON) []", "mode"},
    {"export-port", 0, 0, G_OPTION_ARG_STRING, &md_eport,
     "Select IPFIX Export port [18001]", "eport"},
    {"watch", 'w', 0, G_OPTION_ARG_STRING, &poll_time,
     "Specify how often to poll the directory for \n\t\t\t\t "
     "files that follow same pattern given to --in", "seconds"},
    {"move", 0, 0, G_OPTION_ARG_STRING, &move_dir,
     "Move incoming files to this directory after \n\t\t\t\t "
     "processing", "path"},
    {"lock", 0, 0, G_OPTION_ARG_NONE, &md_config.lockmode,
     "Don't read files that are locked", NULL},
    {"log", 'l', 0, G_OPTION_ARG_STRING, &md_logfile,
     "specify the name of the file to log errors, \n\t\t\t\t "
     "messages, etc", "logfile"},
    {"log-dir", 0, 0, G_OPTION_ARG_STRING, &md_logdest,
     "specify a valid directory where the log files \n\t\t\t\t"
     "are written.", "log path"},
    {"verbose", 'v', 0, G_OPTION_ARG_NONE, &md_verbose,
     "Change loglevel from default WARNING to DEBUG.", NULL},
    {"quiet", 'q', 0, G_OPTION_ARG_NONE, &md_quiet,
     "Change loglevel from default WARNING to QUIET.", NULL},
    {"rotate", 0, 0, G_OPTION_ARG_INT, &rotate,
     "rotate output files every n seconds to a \n\t\t\t\t "
     "directory[3600-1hr]", "sec"},
#if HAVE_SPREAD
    {"groups", 'g', 0, G_OPTION_ARG_STRING_ARRAY, &md_in_groups,
     "Names of the groups to subscribe to []", "groups"},
#endif
    {"udp-temp-timeout", 0, 0, G_OPTION_ARG_INT,
     &md_config.udp_template_timeout,
     "UDP Template Timeout Period [600, 10 min]", "seconds"},
    {"no-stats", 0, 0, G_OPTION_ARG_NONE, &md_config.no_stats,
     "Don't decode/export stats", NULL},
    {"dns-dedup", 0, 0, G_OPTION_ARG_NONE, &dns_dedup,
     "Perform DNS Deduplication on all DNS Resource Records", NULL},
    {"daemonize", 'd', 0, G_OPTION_ARG_NONE, &md_daemon,
     "Daemonize super mediator", NULL},
    {"pidfile", 0, 0, G_OPTION_ARG_STRING, &md_pidfile,
     "Complete path to the process ID file", NULL},
    {"fields", 'f', 0, G_OPTION_ARG_STRING_ARRAY, &md_field_list,
     "Flow fields to print in TEXT exporting mode.", "fields"},
    {"print-headers", 'h', 0, G_OPTION_ARG_NONE, &md_print_headers,
     "Print column headers for TEXT exporter.", NULL},
    {"sleep", 's', 0, G_OPTION_ARG_INT, &sleep_usecs,
     "Number of microseconds to sleep between \n\t\t\t\t exporting IPFIX"
     " messages.", NULL },
    {"become-user", 'U', 0, G_OPTION_ARG_STRING, &become_user,
     "Become user after setup if started as root", NULL},
    {"become-group", 0, 0, G_OPTION_ARG_STRING, &become_group,
     "Become group after setup if started as root", NULL },
#if SM_ENABLE_METADATA_EXPORT
    {"metadata-export", 0, 0, G_OPTION_ARG_NONE, &md_metadata_export,
     "Include information element and template metadata in output", NULL},
#endif
    {"version", 'V', 0, G_OPTION_ARG_NONE, &md_version,
     "Print application version and exit", NULL},
    { NULL }
};

#define TIMEOUT 300 /* 5 minutes in microseconds */

static void mdDaemonize(void);

static void mdParseOptions(
    int *argc,
    char **argv[]);

static void sigHandler(void);

static gboolean mdPrivc_Setup(
    GError **err);

static gboolean mdPrivc_Become(
    GError          **err);
/**
 * mdLogger
 *
 */
static void mdLogger(
    const char      *domain __attribute__((unused)),
    GLogLevelFlags  log_level,
    const char      *message,
    gpointer         user_data __attribute__((unused)))
{
    gsize            sz;
    char             timebuf[80];
    struct tm        time_tm;
    time_t           cur_time= time(NULL);

    gmtime_r(&cur_time, &time_tm);
    snprintf(timebuf, 80, PRINT_TIME_FMT,
             time_tm.tm_year + 1900,
             time_tm.tm_mon + 1,
             time_tm.tm_mday,
             time_tm.tm_hour,
             time_tm.tm_min,
             time_tm.tm_sec);

    g_io_channel_write_chars(logfile, "[", 1, &sz, NULL);
    g_io_channel_write_chars(logfile, timebuf, -1, &sz, NULL);
    g_io_channel_write_chars(logfile, "] ", 2, &sz, NULL);
    g_io_channel_write_chars(logfile, message, -1, &sz, NULL);
    g_io_channel_write_chars(logfile,"\n", 1, &sz, NULL);
    g_io_channel_flush(logfile, NULL);
}


/**
 * mdPrintVersion
 *
 *
 */
static void mdPrintVersion() {

    GString *resultString;

    resultString = g_string_new("");

    g_string_append_printf(resultString, "super_mediator version %s\n"
            "Build Configuration: \n",  VERSION);
#ifdef FIXBUF_VERSION
    g_string_append_printf(resultString, "    * %-32s  %s\n",
                           "Fixbuf version:",
                           FIXBUF_VERSION);
#endif
    g_string_append_printf(resultString, "    * %-32s  %s\n",
                           "Timezone support:",
#if ENABLE_LOCALTIME
                           "local"
#else
                           "UTC"
#endif
                           );
    g_string_append_printf(resultString, "    * %-32s  %s\n",
                           "MySQL support:",
#if HAVE_MYSQL
                           "YES"
#else
                           "NO"
#endif
                           );

    g_string_append_printf(resultString, "    * %-32s  %s\n",
                           "Spread support:",
#if HAVE_SPREAD
                           "YES"
#else
                           "NO"
#endif
                           );
    g_string_append_printf(resultString, "    * %-32s  %s\n",
                           "OpenSSL support:",
#if HAVE_OPENSSL
                           "YES"
#else
                           "NO"
#endif
                           );


    g_string_append_printf(resultString, "    * %-32s  %s\n",
                           "SiLK IPSet support:",
#if ENABLE_SKIPSET
                           "YES"
#else
                           "NO"
#endif
                           );

    g_string_append_printf(resultString,
                           "Copyright (C) 2012-2016 Carnegie Mellon University"
                           "\nGNU General Public License (GPL) Rights "
                           "pursuant to Version 2, June 1991\n");
    g_string_append_printf(resultString,
                           "Government Purpose License Rights (GPLR) "
                           "pursuant to DFARS 252.227-7013\n");
    g_string_append_printf(resultString,
                           "Send bug reports, feature requests, and comments"
                           " to netsa-help@cert.org.\n");

    fprintf(stderr, "%s", resultString->str);

    g_string_free(resultString, TRUE);
}

static GIOChannel *mdRotateLog(
    GError **err)
{
    char path[500];
    char date[32];
    time_t t;
    struct tm ts;
    int slog = 0;

    /* get current time */
    t = time(NULL);
    localtime_r(&t, &ts);
    strftime(date, sizeof(date), "%Y%m%d", &ts);

#ifndef MDLOG_TESTING_LOG
    ts.tm_hour = 23;
    ts.tm_min = 59;
    ts.tm_sec = 59;
    md_log_rolltime = mktime(&ts) + 1;
#else
    strftime(date, sizeof(date), "%Y%m%d:%H:%M", &ts);

    if (ts.tm_sec > 55) {
        ++ts.tm_min;
    }
    ts.tm_sec = 0;
    ++ts.tm_min;
    md_log_rolltime = mktime(&ts);
#endif
    snprintf(path, sizeof(path), "%s/sm-%s.log", md_logdest, date);
    if (cur_logfile) {
        if (last_logfile) {
            g_free(last_logfile);
        }
        last_logfile = cur_logfile;
    }
    cur_logfile = g_strdup(path);
    return md_log_setup(path, level, &slog, md_daemon, err);
}


/**
 * mdSetEmitTimer
 *
 * Separate thread that runs when the mediator is to run
 * forever.  This will emit the buffer and flush any
 * export files every 5 minutes in the case that we are not
 * receiving any data.
 * It will also print mediator stats if the mediator is
 * configured to do so.
 *
 */
static void *mdSetEmitTimer(
    void           *data)
{
    mdContext_t       *ctx = (mdContext_t *)data;
    mdConfig_t        *cfg = ctx->cfg;
    struct timespec   to;
    struct timeval    tp;
    time_t            now;
    time_t            then = time(NULL);
    time_t            sectime = time(NULL);
    int               seconds, rc;
    long              timeout = md_stats_timeout;
    GError            *err = NULL;

    /* we need to flush at least every 5 minutes */
    if (md_stats_timeout > TIMEOUT) timeout = TIMEOUT;

    gettimeofday(&tp, NULL);

    to.tv_sec = tp.tv_sec + timeout;
    to.tv_nsec = tp.tv_usec * 1000;

    pthread_mutex_lock(&cfg->log_mutex);

    while (!md_quit) {
        pthread_cond_timedwait(&cfg->log_cond, &cfg->log_mutex, &to);
        gettimeofday(&tp, NULL);
        to.tv_sec = tp.tv_sec + timeout;
        to.tv_nsec = tp.tv_usec * 1000;
        now = time(NULL);
        /* only flush every 5 minutes */
        seconds = difftime(now, then);
        if (seconds >= TIMEOUT) {
            then = time(NULL);
            mdExporterConnectionReset(cfg, &(ctx->err));
        }
        seconds = difftime(now, sectime);
        if (seconds >= md_stats_timeout) {
            sectime = time(NULL);
            if (!cfg->no_stats) {
                mdStatDump(cfg, ctx->stats);
            }
        }
        /* rotate log */
        if (md_logdest && md_log_rolltime < now) {
            g_message("Rotating Log File");
            rc = g_io_channel_shutdown(logfile, TRUE, &err);
            if (!rc) {
                g_warning("Unable to rotate log");
            } else {
                /* open new logfile */
                logfile = mdRotateLog(&err);
                /* compress old logfile */
                md_log_compress(last_logfile);
                if (!logfile) {
                    g_warning("Unable to open new log file: %s", err->message);
                }
            }
        }
    }

    pthread_mutex_unlock(&cfg->log_mutex);
    return NULL;
}


static void mdQuit() {

    md_quit++;
    mdInterruptListeners(&md_config);
}


/**
 * main
 *
 *
 */
int
main (
    int      argc,
    char     *argv[])
{

    mdContext_t           ctx = MD_CTX_INIT;
    GError                *error = NULL;
    pthread_t             to_thread;
    char                  *errmsg = NULL;

    ctx.cfg = &md_config;

    /* parse all the options */
    mdParseOptions(&argc, &argv);

    g_message("super_mediator starting");

    mdStatInit();

    /* set up mediator statistics */
    ctx.stats = g_slice_new0(md_stats_t);

    /**
       this program runs forever, until interrupted, handle
       the interrupt gracefully and exit by installing these
       handlers
    */

    sigHandler();

    /* open input */

    if (!mdCollectorsInit(ctx.cfg, ctx.cfg->flowsrc, &error)) {
        fprintf(stderr, "Fatal: %s\n", error->message);
        exit(1);
    }

    if (pthread_create(&to_thread, NULL, mdSetEmitTimer, &ctx)) {
        fprintf(stderr, "Fatal error starting statistics thread\n");
        exit(1);
    }

    /* set up output */

    if (!mdExportersInit(ctx.cfg, ctx.cfg->flowexit, &error)) {
        g_warning("Fatal: %s\n", error->message);
        exit(1);
    }

    g_debug("Initialization Successful, starting...");

    /** wait for connections*/
    while (!md_quit) {

        if (!mdCollectorStartListeners(ctx.cfg, ctx.cfg->flowsrc, &error)) {
            fprintf(stderr, "Couldn't start listener threads %s\n",
                    error->message);
            md_quit = 1;
            break;
        }

        if (!mdPrivc_Become(&error)) {
            if (g_error_matches(error, MD_ERROR_DOMAIN, MD_ERROR_NODROP)) {
                g_warning("running as root in --live mode, "
                          "but not dropping privilege");
                g_clear_error(&error);
            } else {
                md_quit = 1;
                g_warning("Cannot drop privilege: %s", error->message);
                break;
            }
        }

        if (!(mdCollectorWait(&ctx, &error))) {
            break;
        }
    }

    if (error) {
        errmsg = g_strdup_printf("super_mediator terminating on error: %s",
                                 error->message);
        g_clear_error(&error);
    }

    pthread_cancel(to_thread);
    pthread_join(to_thread, NULL);

    mdCollectorDestroy(ctx.cfg, TRUE);
    mdExporterDestroy(ctx.cfg, &error);
    smFreeMaps(ctx.cfg);

    if (user_elements) {
        fbInfoElement_t *tie = user_elements;
        for (; tie->ref.name; tie++) {
            /* free each name */
            g_free((char *)(tie->ref.name));
        }
        g_free(user_elements);
    }

    fbInfoModelFree(mdInfoModel());

    pthread_mutex_destroy(&ctx.cfg->log_mutex);
    pthread_cond_destroy(&ctx.cfg->log_cond);
    mdStatUpdate(ctx.stats);

    g_slice_free1(sizeof(md_stats_t), ctx.stats);

    if (errmsg) {
        g_warning("%s", errmsg);
        g_free(errmsg);
    } else {
        g_debug("super_mediator Terminating");
    }

    /** finished with no problems */
    return 0;
}

#if HAVE_SPREAD
/**
 * md_new_spread_node
 *
 *
 */
md_spread_filter_t *md_new_spread_node(
    void)
{
    md_spread_filter_t *ms = g_slice_new0(md_spread_filter_t);
    return ms;
}
#endif

/**
 * md_new_filter_node
 *
 */
md_filter_t *md_new_filter_node(
    void)
{
    md_filter_t *mf = g_slice_new0(md_filter_t);

    return mf;
}

/**
 * md_new_export_node
 *
 */
md_export_node_t *md_new_export_node(
    gboolean dnsdedup,
    gboolean dedup)
{

    md_export_node_t *en = g_slice_new0(md_export_node_t);
    en->next = NULL;

    if (dnsdedup) {
        en->dns_dedup = md_new_dns_dedup_state();
    }

    if (dedup) {
        en->dedup = md_dedup_new_dedup_state();
    }

    return en;
}

/**
 * md_new_collect_node
 *
 *
 */
md_collect_node_t *md_new_collect_node(
    void)
{
    md_collect_node_t *cn = g_slice_new0(md_collect_node_t);
    cn->next = NULL;

    return cn;
}


static mdFlowCollector_t *mdConfigureCollector(
                                               )
{
    mdFlowCollector_t *collector = NULL;

    collector = mdNewFlowCollector(md_ipfix_intransport,
                                   NULL);


    if (md_ipfix_intransport == SPREAD) {
#if HAVE_SPREAD
        int                n = 0;
        gchar              **sa;

        /* input should be Spread Daemon */
        /* test connections and subscribe to groups */
        if (md_in_groups == NULL) {
            fprintf(stderr, "Required: At Least 1 Spread Group Name to "
                    "Subscribe to, exiting...\n");
            exit(1);
        } else {
            sa = g_strsplit(*md_in_groups, ",", -1);
            while (sa[n] && *sa[n]) {
                ++n;
            }
            n = 0;
            while (sa[n] && *sa[n]) {
                if (isspace(sa[n][0])) {
                    mdCollectorAddSpreadGroup(collector, sa[n]+1, n);
                } else {
                    mdCollectorAddSpreadGroup(collector, sa[n], n);
                }
                ++n;
                }
            g_strfreev(sa);
        }
        mdCollectorSetInSpec(collector, inspec);
#else
        fprintf(stderr, "Spread not enabled, reconfigure with Spread...\n");
        exit(1);
#endif
    } else if (md_ipfix_intransport == TCP || md_ipfix_intransport == UDP) {

        mdCollectorSetInSpec(collector, inspec);
        if (atoi(md_iport) < 1024) {
            g_warning("Fatal: listening port for TCP traffic must be "
                      "above 1024, %d is invalid\n", atoi(md_iport));
            exit(1);
        }
        mdCollectorSetPort(collector, md_iport);

    } else {

        /* it's either a file or directory */
        if ((strlen(inspec) == 1) && inspec[0] == '-') {
            if (isatty(fileno(stdin))) {
                g_warning("Refusing to read from terminal on stdin");
                exit(1);
            }

        } else if (poll_time || move_dir) {
            /* input is a directory */
            if (poll_time) {
                mdCollectorSetPollTime(collector, poll_time);
            } else {
                mdCollectorSetPollTime(collector, "30");
            }
            if (move_dir) {
                if (!g_file_test(move_dir, G_FILE_TEST_IS_DIR)) {
                    g_warning("--move expects a valid file directory");
                    exit(1);
                }
                mdCollectorSetMoveDir(collector, move_dir);
            } else {
                g_warning("No Move Directory Specified.");
                g_warning("Incoming files will be deleted after processing.");
            }
        } else {
            if (g_file_test(inspec, G_FILE_TEST_EXISTS)) {
                /* input file */
                md_ipfix_intransport = FILEHANDLER;
            } else {
                g_warning("File %s does not exist.", inspec);
                exit(1);
            }
        }
        mdCollectorSetInSpec(collector, inspec);
    }

    return collector;
}

static mdFlowExporter_t * mdConfigureExporter(
    mdConfig_t            *cfg,
    gboolean              json)
{

    mdFlowExporter_t *exporter = NULL;
    gchar              **sa;
    int                n = 0;

    exporter =  mdNewFlowExporter(md_ipfix_outtransport);

    if (dns_dedup) {
        mdExporterSetDNSDeDup(exporter);
    }

    if (md_ipfix_outtransport == SPREAD) {
#if HAVE_SPREAD
        n = 0;
        mdExporterSetHost(md_config.flowexit->exp, outspec);
        g_free(outspec);
        /* output is spread */
        /* need spread groups */
        if (md_out_groups == NULL) {
            g_warning("Required: At Least 1 Spread Group Name to "
                      "Subscribe to, exit...");
            exit(1);
        } else if (md_config.out_spread.groups == NULL) {
            sa = g_strsplit(*md_out_groups, ",", -1);
            while (sa[n] && *sa[n]) {
                ++n;
            }
            md_out_groups = (char **)g_malloc0((sizeof(char *)*(n + 1)));
            n = 0;
            while (sa[n] && *sa[n]) {
                if (isspace(sa[n][0])) {
                    md_out_groups[n] = g_strdup(sa[n] + 1);
                } else {
                    md_out_groups[n] = g_strdup(sa[n]);
                }
                ++n;
            }
            md_config.out_spread.groups = md_out_groups;
            g_strfreev(sa);
        }
#else
        g_warning("Spread not enabled, reconfigure with Spread...");
        exit(1);
#endif

    } else if (md_ipfix_outtransport == TEXT) {

        mdExporterSetFileSpec(exporter, outspec);
        if (rotate > 0) {
            mdExporterSetRotate(exporter, rotate);
        }

        if (md_field_list) {
            gboolean dpi = FALSE;
            mdFieldList_t *item = NULL;
            mdFieldList_t *list = NULL;
            mdFieldList_t *first_item = NULL;
            mdAcceptFilterField_t field;
            sa = g_strsplit(*md_field_list, ",", -1);
            while (sa[n] && *sa[n]) {
                /* remove any leading whitespace */
                g_strchug(sa[n]);
                /* remove any trailing whitespace */
                g_strchomp(sa[n]);
                field = atoi(sa[n]);
                if (field == DPI) {
                    mdExporterCustomListDPI(exporter);
                    ++n;
                    dpi = TRUE;
                    continue;
                }
                item = mdCreateFieldList((mdAcceptFilterField_t)field);
                if (!item) {
                    g_warning("Invalid field item %s\n", sa[n]);
                    exit(1);
                }
                if (first_item == NULL) {
                    first_item = item;
                    list = item;
                } else {
                    list->next = item;
                    list = list->next;
                }
                ++n;
            }
            if (dpi && !item) {
                /* just DPI was chosen - create list and set to None */
                item = mdCreateFieldList(NONE_FIELD);
                first_item = item;
                mdExporterSetDPIOnly(exporter);
            }
            mdExportCustomList(exporter, first_item);
            g_strfreev(sa);
        }

        if (json) {
            mdExporterSetJson(exporter);
        }

    } else if (md_ipfix_outtransport == TCP || md_ipfix_outtransport == UDP) {

        if (atoi(md_eport) < 1024) {
            g_warning("Fatal: exporting port for TCP/UDP traffic must be "
                      " above 1024, %d is invalid\n", atoi(md_eport));
            exit(1);
        }

        mdExporterSetPort(exporter, md_eport);
        mdExporterSetHost(exporter, outspec);

        if (cfg->udp_template_timeout == 0) {
            cfg->udp_template_timeout = 600000;

        } else {
            cfg->udp_template_timeout = cfg->udp_template_timeout * 1000;
        }

    } else if (outspec)  {

        /* file or a directory or stdout */
        if ((strlen(outspec) == 1) && outspec[0] == '-') {
            if (isatty(fileno(stdout))) {
                g_warning("Refusing to write to terminal on stdout");
                exit(1);
            }
        }

        mdExporterSetFileSpec(exporter, outspec);

        if (rotate > 0) {
            mdExporterSetRotate(exporter, rotate);
        }

    }

    if (md_print_headers) {
        if (!md_field_list) {
            mdExporterSetPrintHeader(exporter);
        } else {
            g_warning("Not printing column headers for field list.");
        }
    }

    if (md_metadata_export) {
        mdExporterSetMetadataExport(exporter);
    }
    return exporter;
}



/**
 * mdParseOptions
 *
 * parses the command line options
 *
 */
static void mdParseOptions (
    int *argc,
    char **argv[])
{

    GOptionContext     *ctx = NULL;
    GError             *err = NULL;
    int                 slog = 0;
    gboolean            json = FALSE;
    md_export_node_t    *cnode = NULL;

    ctx = g_option_context_new(" - Mediator Options");

    g_option_context_add_main_entries(ctx, md_core_option, NULL);

    g_option_context_set_help_enabled(ctx, TRUE);

    if (!g_option_context_parse(ctx, argc, argv, &err)) {
        fprintf(stderr, "option parsing failed: %s\n", err->message);
        exit(1);
    }

    if (md_version) {
        mdPrintVersion();
        exit(-1);
    }

    if (!mdPrivc_Setup(&err)) {
        fprintf(stderr, "Error: %s\n", err->message);
        exit(1);
    }

    /* Configuration file trumps all */
    if (md_conf) {
        yyin = fopen(md_conf, "r");
        if (yyin) {
            while(!feof(yyin)) {
                (void)yyparse();
                if (mediatorconf_errors) {
                    yyerror(NULL);
                    exit(mediatorconf_errors);
                }
            }
        } else {
            fprintf(stderr, "Could not open configuration file: \"%s\" for "
                    "reading\n", md_conf);
        }
    }

    if (md_in_str) {
        if (!g_ascii_strcasecmp(md_in_str, "tcp")) {
            md_ipfix_intransport = TCP;
        } else if (!(g_ascii_strcasecmp(md_in_str, "udp"))) {
            md_ipfix_intransport = UDP;
        } else if (!(g_ascii_strcasecmp(md_in_str, "spread"))) {
            md_ipfix_intransport = SPREAD;
        }
    } else {
        md_ipfix_intransport = FILEHANDLER;
    }

    if (md_out_str) {
        if (!g_ascii_strcasecmp(md_out_str, "tcp")) {
            md_ipfix_outtransport = TCP;
        } else if (!(g_ascii_strcasecmp(md_out_str, "udp"))) {
            md_ipfix_outtransport = UDP;
        } else if (!(g_ascii_strcasecmp(md_out_str, "spread"))) {
            fprintf(stderr, "Spread is only available if configured using the "
                    "configuration file\n");
            exit(1);
        } else if (!(g_ascii_strcasecmp(md_out_str, "text"))) {
            md_ipfix_outtransport = TEXT;
        } else if (!(g_ascii_strcasecmp(md_out_str, "json"))) {
            md_ipfix_outtransport = TEXT;
            json = TRUE;
        }
    } else {
        md_ipfix_outtransport = FILEHANDLER;
    }

    /* Logging options */

    level = md_parse_log_level(md_log_level, md_verbose, md_quiet);

    if (md_logdest) {
        logfile = mdRotateLog(&err);
    } else {
        logfile = md_log_setup(md_logfile, level, &slog, md_daemon, &err);
    }

    if (!logfile && (slog == 0)) {
        fprintf(stderr, "Log option parsing failed: %s\n", err->message);
        exit(1);
    }

    if (!slog) {
        /* if not syslog, set default handler */
        g_log_set_handler(G_LOG_DOMAIN, level, mdLogger, NULL);
    }

    if (md_stats_timeout == 0) {
        g_warning("Turning off stats export.");
        md_stats_timeout = 300;
        md_config.no_stats = TRUE;
    }

    /* COLLECTOR OPTIONS */

    if (md_config.flowsrc == NULL || inspec != NULL) {
        if (md_config.flowsrc) {
            g_warning("WARNING: Overriding Collectors in configuration file "
                      "due to presence of command line arguments.");
            mdCollectorDestroy(&md_config, FALSE);
        }
        md_config.flowsrc = md_new_collect_node();
        if (inspec == NULL) {
            inspec = g_strdup("-");
            md_ipfix_intransport = FILEHANDLER;
        }
        md_config.flowsrc->coll = mdConfigureCollector();
    }

    if (sleep_usecs < 1000000) {
        md_config.usec_sleep = sleep_usecs;
    } else {
        g_warning("Maximum sleep time is 1000000");
        md_config.usec_sleep = sleep_usecs;
    }

    /* NOW TO EXPORT */
    // If no exporters are defined in the config file, configure one based on
    // command line options.
    if (md_config.flowexit == NULL) {
        md_config.flowexit = md_new_export_node(dns_dedup, FALSE);
        if (outspec == NULL) {
            outspec = "-";
            md_ipfix_outtransport = FILEHANDLER;
        }
        md_config.flowexit->exp = mdConfigureExporter(&md_config, json);
    } else {
        if (outspec) {
            g_warning("WARNING: WILL NOT Override Exporters in configuration file.");
        }
    }

    if (dns_dedup) {
        if (dns_max_hit_count == 0) {
            fprintf(stderr, "Invalid Hit Count of 0 (Must be > 0)\n");
            exit(1);
        }
        if (dns_flush_timeout == 0) {
            fprintf(stderr, "Invalid Flush Timeout of 0 (Must be > 0)\n");
            exit(1);
        }

        md_dns_dedup_configure_state(md_config.flowexit->dns_dedup, NULL,
                                     dns_max_hit_count, dns_flush_timeout,
                                     FALSE, NULL, FALSE);
    }

    if (!mdCollectorVerifySetup(md_config.flowsrc->coll, &err)) {
        fprintf(stderr, "Error Verifying Collector Setup\n");
        exit(1);
    }

    for (cnode = md_config.flowexit; cnode; cnode = cnode->next) {
        if (!mdExporterVerifySetup(cnode->exp)) {
            fprintf(stderr, "Error Verifying Export Setup\n");
            exit(1);
        }
    }

    if (md_daemon) {
        mdDaemonize();
    }

    g_option_context_free(ctx);

}




/**
 * smExit
 *
 * exit handler for super_mediator
 *
 */

void mdExit() {

    if (md_pidfile) {
        unlink(md_pidfile);
    }
}


/**
 * sigHandler
 *
 * this gets called from various system signal handlers.  It is used to
 * provide a way to exit this program cleanly when the user wants to
 * kill this program
 *
 * @param signalNumber the number of the signal that this handler is
 *        getting called for
 *
 */

static void
sigHandler ()
{

    struct sigaction sa, osa;

    sa.sa_handler = mdQuit;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGINT,&sa,&osa)) {
        g_error("sigaction(SIGINT) failed: %s", strerror(errno));
    }

    sa.sa_handler = mdQuit;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGTERM,&sa,&osa)) {
        g_error("sigaction(SIGTERM) failed: %s", strerror(errno));
    }

}

static void mdDaemonize()
{
    pid_t pid;
    int rv = -1;
    char str[256];
    int fp;

    if (chdir("/") == -1) {
        rv = errno;
        g_warning("Cannot change directory: %s", strerror(rv));
        exit(-1);
    }

    if ((pid = fork()) == -1) {
        rv = errno;
        g_warning("Cannot fork for daemon: %s", strerror(rv));
        exit(-1);
    } else if (pid != 0) {
        g_debug("Forked child %ld.  Parent exiting", (long)pid);
        _exit(EXIT_SUCCESS);
    }

    setsid();

    umask(0022);

    rv = atexit(mdExit);
    if (rv == -1) {
        g_warning("Unable to register function with atexit(): %s",
                  strerror(rv));
        exit(-1);
    }

    /* Close out the standard file descriptors */
    close(STDIN_FILENO);

    if (md_pidfile) {
        fp = open(md_pidfile, O_RDWR|O_CREAT, 0640);
        if (fp < 0) {
            g_warning("Unable to open pid file %s", md_pidfile);
            exit(1);
        }
        sprintf(str, "%d\n", getpid());
        if (!write(fp, str, strlen(str))) {
            g_warning("Unable to write pid to file");
        }
    } else {
        g_debug("pid: %d", getpid());
    }

}

gboolean mdListenerConnect(
    fbListener_t         *listener,
    void                 **ctx,
    int                  fd,
    struct sockaddr      *peer,
    size_t               peerlen,
    GError               **err)
{
    md_collect_node_t *collector;

    if (!peer) {
        /* this is UDP */
        return TRUE;
    }

    /* set context based on which listener this is */
    collector = mdCollectorFindListener(md_config.flowsrc, listener);

    if (!collector) {
        return FALSE;
    }

    if (peer->sa_family == AF_INET) {
        char *ip = inet_ntoa((((struct sockaddr_in *)peer)->sin_addr));
        pthread_mutex_lock(&md_config.log_mutex);
        g_message("%s: accepting connection from %s:%d",
                  mdCollectorGetName(collector), ip,
                  ((struct sockaddr_in *)peer)->sin_port);
        pthread_mutex_unlock(&md_config.log_mutex);
    } else if (peer->sa_family == AF_INET6) {
        char straddr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)peer)->sin6_addr), straddr,
                  sizeof(straddr));
        pthread_mutex_lock(&md_config.log_mutex);
        g_message("%s: accepting connection from %s:%d",
                  mdCollectorGetName(collector), straddr,
                  ((struct sockaddr_in6 *)peer)->sin6_port);
        pthread_mutex_unlock(&md_config.log_mutex);
    }

    collector->stats->restarts++;

    *ctx = (void *)collector;


    return TRUE;
}

void smFreeMaps(
    mdConfig_t *cfg)
{
    int i = 0;

    if (cfg->maps) {
        smFieldMap_t *cmap = NULL;
        smFieldMap_t *nmap = NULL;
        for (cmap = cfg->maps; cmap; cmap = cmap->next) {

            smHashTableFree(cmap->table);
            g_free(cmap->name);
            for (i = 0; i < cmap->count; i++) {
                g_free(cmap->labels[i]);
            }
            free(cmap->labels);
        }
        cmap = cfg->maps;
        while (cmap) {
            detachHeadOfSLL((mdSLL_t **)&(cfg->maps),
                            (mdSLL_t **)&cmap);
            nmap = cmap->next;
            g_slice_free(smFieldMap_t, cmap);
            cmap = nmap;
        }
     }
}

static gboolean mdPrivc_Setup(
    GError **err)
{

    struct passwd *pwe = NULL;
    struct group *gre = NULL;

    if (geteuid() == 0) {
        /* We're root. Parse user and group names. */
        if (become_user) {
            if (!(pwe = getpwnam(become_user))) {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                            "Cannot become user %s: %s.",
                            become_user, strerror(errno));
                return FALSE;
            }

            /* By default, become new user's user and group. */
            new_user = pwe->pw_uid;
            new_group = pwe->pw_gid;
            if (become_group) {
                if (!(gre = getgrnam(become_group))) {
                    g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                                "Cannot become group %s: %s.",
                                become_group, strerror(errno));
                    return FALSE;
                }

                /* Override new group if set */
                new_group = gre->gr_gid;
            }
        }
    } else {
        /* We're not root. If we have options, the user is confused, and
           we should straighten him out by killing the process. */
        if (become_user) {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "Cannot become user %s: not root.",
                        become_user);
            return FALSE;
        }
        if (become_group) {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "Cannot become group %s: not root.",
                        become_user);
            return FALSE;
        }
    }

    /* All done. */
    return TRUE;
}

static gboolean mdPrivc_Become(
    GError          **err)
{
    /* Die if we've already become */
    if (did_become) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "not dropping privileges, already did so");
        return FALSE;
    }

    /* Short circuit if we're not root */
    if (geteuid() != 0) return TRUE;

    /* Allow app to warn if not dropping */
    if (new_user == 0) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_NODROP,
                    "not dropping privileges (use --become-user to do so)");
        return FALSE;
    }

    /* Okay. Do the drop. */

    /* Drop ancillary group privileges while we're still root */
    if (setgroups(1, &new_group) < 0) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "couldn't drop ancillary groups: %s", strerror(errno));
        return FALSE;
    }
#if LINUX_PRIVHACK
    /* Change to group */
    if (setregid(new_group, new_group) < 0) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "couldn't become group %u: %s", new_group, strerror(errno));
        return FALSE;
    }

    /* Lose root privileges */
    if (setreuid(new_user, new_user) < 0) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "couldn't become user %u: %s", new_user, strerror(errno));
        return FALSE;
    }
#else
    /* Change to group */
    if (setgid(new_group) < 0) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "couldn't become group %u: %s", new_group, strerror(errno));
        return FALSE;
    }

    /* Lose root privileges */
    if (setuid(new_user) < 0) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "couldn't become user %u: %s", new_user, strerror(errno));
        return FALSE;
    }
#endif
    /* All done. */
    did_become = TRUE;
    return TRUE;
}
