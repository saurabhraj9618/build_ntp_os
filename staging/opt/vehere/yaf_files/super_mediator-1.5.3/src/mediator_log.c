/*
 * mediator_log.c
 * glib-based logging support for super_mediator (taken from libairfame)
 *
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2012-2017 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 * @OPENSOURCE_HEADER_START@
 * Use of this and related source code is subject to the terms
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
 * ------------------------------------------------------------------------
 */

#include "mediator_log.h"
#include <mediator/mediator_util.h>

static gint md_logc_syslog_level(
    GLogLevelFlags  level)
{

    if (level & G_LOG_LEVEL_DEBUG) return LOG_DEBUG;
    if (level & G_LOG_LEVEL_INFO) return LOG_INFO;
    if (level & G_LOG_LEVEL_MESSAGE) return LOG_NOTICE;
    if (level & G_LOG_LEVEL_WARNING) return LOG_WARNING;
    if (level & G_LOG_LEVEL_CRITICAL) return LOG_ERR;
    if (level & G_LOG_LEVEL_ERROR) return LOG_ERR;

    return LOG_DEBUG;
}

GLogLevelFlags md_parse_log_level(
    mdLogLevel_t        log_level,
    gboolean            debug,
    gboolean            quiet)
{
    GLogLevelFlags      level;

    if (log_level == ERROR) {
        level = G_LOG_FLAG_RECURSION |
                G_LOG_FLAG_FATAL |
                G_LOG_LEVEL_ERROR;
    } else if (log_level == WARNING) {
        level = G_LOG_FLAG_RECURSION |
                G_LOG_FLAG_FATAL |
                G_LOG_LEVEL_ERROR |
                G_LOG_LEVEL_CRITICAL |
                G_LOG_LEVEL_WARNING;
    } else if (log_level == MD_DEBUG) {
        level = G_LOG_FLAG_RECURSION |
                G_LOG_FLAG_FATAL |
                G_LOG_LEVEL_ERROR |
                G_LOG_LEVEL_CRITICAL |
                G_LOG_LEVEL_WARNING |
                G_LOG_LEVEL_MESSAGE |
                G_LOG_LEVEL_INFO |
                G_LOG_LEVEL_DEBUG;
    } else if (log_level == QUIET) {
        level = 0;
    } else {
        level = G_LOG_FLAG_RECURSION |
                G_LOG_FLAG_FATAL |
                G_LOG_LEVEL_ERROR |
                G_LOG_LEVEL_CRITICAL |
                G_LOG_LEVEL_WARNING |
                G_LOG_LEVEL_MESSAGE |
                G_LOG_LEVEL_INFO;
    }

    if (debug) {
        level = G_LOG_FLAG_RECURSION |
                G_LOG_FLAG_FATAL |
                G_LOG_LEVEL_ERROR |
                G_LOG_LEVEL_CRITICAL |
                G_LOG_LEVEL_WARNING |
                G_LOG_LEVEL_MESSAGE |
                G_LOG_LEVEL_INFO |
                G_LOG_LEVEL_DEBUG;
    }

    if (quiet) {
        level = 0;
    }

    return level;
}


static gboolean md_parse_syslog_facility(
    const char      *facstr,
    gint            *facility) {

#ifdef LOG_AUTH
    if (strcmp("auth",facstr) == 0) {
        *facility = LOG_AUTH;
        return TRUE;
    }
#endif

#ifdef LOG_AUTHPRIV
    if (strcmp("authpriv",facstr) == 0) {
        *facility = LOG_AUTHPRIV;
        return TRUE;
    }
#endif

#ifdef LOG_CONSOLE
    if (strcmp("console",facstr) == 0) {
        *facility = LOG_CONSOLE;
        return TRUE;
    }
#endif

#ifdef LOG_CRON
    if (strcmp("cron",facstr) == 0) {
        *facility = LOG_CRON;
        return TRUE;
    }
#endif

#ifdef LOG_DAEMON
    if (strcmp("daemon",facstr) == 0) {
        *facility = LOG_DAEMON;
        return TRUE;
    }
#endif

#ifdef LOG_FTP
    if (strcmp("ftp",facstr) == 0) {
        *facility = LOG_FTP;
        return TRUE;
    }
#endif

#ifdef LOG_LPR
    if (strcmp("lpr",facstr) == 0) {
        *facility = LOG_LPR;
        return TRUE;
    }
#endif

#ifdef LOG_MAIL
    if (strcmp("mail",facstr) == 0) {
        *facility = LOG_MAIL;
        return TRUE;
    }
#endif

#ifdef LOG_NEWS
    if (strcmp("news",facstr) == 0) {
        *facility = LOG_NEWS;
        return TRUE;
    }
#endif

#ifdef LOG_SECURITY
    if (strcmp("security",facstr) == 0) {
        *facility = LOG_SECURITY;
        return TRUE;
    }
#endif

#ifdef LOG_USER
    if (strcmp("user",facstr) == 0) {
        *facility = LOG_USER;
        return TRUE;
    }
#endif

#ifdef LOG_UUCP
    if (strcmp("uucp",facstr) == 0) {
        *facility = LOG_UUCP;
        return TRUE;
    }
#endif

#ifdef LOG_LOCAL0
    if (strcmp("local0",facstr) == 0) {
        *facility = LOG_LOCAL0;
        return TRUE;
    }
#endif

#ifdef LOG_LOCAL1
    if (strcmp("local1",facstr) == 0) {
        *facility = LOG_LOCAL1;
        return TRUE;
    }
#endif

#ifdef LOG_LOCAL2
    if (strcmp("local2",facstr) == 0) {
        *facility = LOG_LOCAL2;
        return TRUE;
    }
#endif

#ifdef LOG_LOCAL3
    if (strcmp("local3",facstr) == 0) {
        *facility = LOG_LOCAL3;
        return TRUE;
    }
#endif

#ifdef LOG_LOCAL4
    if (strcmp("local4",facstr) == 0) {
        *facility = LOG_LOCAL4;
        return TRUE;
    }
#endif

#ifdef LOG_LOCAL5
    if (strcmp("local5",facstr) == 0) {
        *facility = LOG_LOCAL5;
        return TRUE;
    }
#endif

#ifdef LOG_LOCAL6
    if (strcmp("local6",facstr) == 0) {
        *facility = LOG_LOCAL6;
        return TRUE;
    }
#endif

#ifdef LOG_LOCAL7
    if (strcmp("local7",facstr) == 0) {
        *facility = LOG_LOCAL7;
        return TRUE;
    }
#endif

    return FALSE;
}

static void md_logger_syslog(
    const char     *domain,
    GLogLevelFlags  log_level,
    const char     *message,
    gpointer        user_data)
{
    syslog(md_logc_syslog_level(log_level), "%s", message);
}

static void md_logger_null(
    const char     *domain,
    GLogLevelFlags  log_level,
    const char     *message,
    gpointer        user_data) {

    return;
}

GIOChannel *md_log_setup(
    char            *md_log_file,
    GLogLevelFlags  levels,
    int             *ret,
    gboolean        daemon_mode,
    GError          **err) {

    GIOChannel      *logfile = NULL;
    int             facility;


    if (!md_log_file || (strcmp(md_log_file, "stderr") == 0)) {
        if (daemon_mode) {
            g_set_error(err, MD_ERROR_DOMAIN,
                            MD_ERROR_SETUP,
                        "Can't log to stderr as daemon.");
            return NULL;
        }

        /* set log file to stderr */
        logfile = g_io_channel_unix_new(fileno(stderr));

    } else if (md_parse_syslog_facility(md_log_file, &facility)) {
        /* open log socket */
        openlog("super_mediator", LOG_CONS | LOG_PID, facility);

        /* use syslog logger */
        g_log_set_handler(G_LOG_DOMAIN, levels, md_logger_syslog, NULL);

        *ret = 1;

    } else {
        /* open log file */
        logfile = g_io_channel_new_file(md_log_file, "a", err);
        if (logfile == NULL) {
            fprintf(stderr, "Can't open log file '%s' or syslog(3) facility "
                    "not recognized: %s\n", md_log_file, (*err)->message);
            return NULL;
        }
    }

    /* set default log handler to eat messages */
    g_log_set_default_handler(md_logger_null, NULL);

    return logfile;

}

void md_log_compress(
    char         *file)
{
    if (file == NULL) {
        g_warning("md_log_compress passed NULL pointer");
        return;
    }

    md_util_compress_file(file);
}
