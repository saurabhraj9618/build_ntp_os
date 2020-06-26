/**
 * @file mediator_mysql.c
 *
 * This sets up the default database tables for super_mediator_0.4.0
 *
 * ------------------------------------------------------------------------
 * Copyright (C) 2012-2017 Carnegie Mellon University. All Rights Reserved.
 * -----------------------------------------------------------------------
 * Authors: Emily Sarneso
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


#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <glib.h>
#include <unistd.h>
#include <mediator/config.h>

#if HAVE_MYSQL

#include <mysql.h>

static char * md_ehost = "localhost";
static char * md_mysql_name = "root";
static char * md_mysql_pass = "";
static char * md_mysql_db = "super";
static gboolean md_version = FALSE;
static gboolean md_no_index = FALSE;
static gboolean md_flow_only = FALSE;
static gboolean md_dns_dedup = FALSE;
static gboolean md_dedup_last = FALSE;
static gboolean md_flow_stats = FALSE;
static gboolean md_yaf_stats = FALSE;
static gboolean md_dedup_flow = FALSE;
static gboolean md_ssl_dedup = FALSE;
static gboolean md_ssl_cert = FALSE;
static char *md_dedup = NULL;

static GOptionEntry md_core_option[] = {
    {"out", 'o', 0, G_OPTION_ARG_STRING, &md_ehost,
     "Select Hostname/I.P. \n\t\t\t\twhere MySQL DB exists [localhost]",
     "host"},
    {"name", 'n', 0, G_OPTION_ARG_STRING, &md_mysql_name,
     "Specify MySQL user name [root]", "user name"},
    {"pass", 'p', 0, G_OPTION_ARG_STRING, &md_mysql_pass,
     "Specify MySQL password []", "password"},
    {"database", 'd', 0, G_OPTION_ARG_STRING, &md_mysql_db,
     "Name of the database to create", "database"},
    {"version", 0, 0, G_OPTION_ARG_NONE, &md_version,
     "Print the version and exit", NULL},
    {"flow-only", 'f', 0, G_OPTION_ARG_NONE, &md_flow_only,
     "Create full flow table only. Use with FLOW_ONLY.", NULL},
    {"no-index", 0, 0, G_OPTION_ARG_NONE, &md_no_index,
     "Put flow index into each table, for use with \n\t\t\t\t"
     "--no-index option in super mediator", NULL},
    {"dns-dedup", 0, 0, G_OPTION_ARG_NONE, &md_dns_dedup,
     "Create DNS dedup default table and exit.", NULL},
    {"dedup-last-seen", 0, 0, G_OPTION_ARG_NONE, &md_dedup_last,
     "Create DNS dedup table with LAST_SEEN option \n\t\t\t\t and exit", NULL},
    {"flow-stats", 's', 0, G_OPTION_ARG_NONE, &md_flow_stats,
     "Create flow statistics table and exit.", NULL },
    {"yaf-stats", 'y', 0, G_OPTION_ARG_NONE, &md_yaf_stats,
     "Create yaf statistics table and exit.", NULL},
    {"dedupflow", 0, 0, G_OPTION_ARG_NONE, &md_dedup_flow,
     "Add count column to tables for DEDUP_PER_FLOW", NULL},
    {"dedup", 0, 0, G_OPTION_ARG_STRING, &md_dedup,
     "Specify dedup table name to create and exit", "name"},
    {"ssl-certs", 0, 0, G_OPTION_ARG_NONE, &md_ssl_cert,
     "Create ssl certificate de-dup tables and exit", NULL},
    {"ssl-dedup", 0, 0, G_OPTION_ARG_NONE, &md_ssl_dedup,
     "Create ssl IP, certificate chain de-dup table and exit", NULL},
    { NULL }
};


static void mdInsertDPIValues(
    MYSQL                 *conn);


/**
 * mdPrintVersion
 *
 *
 */
static void mdPrintVersion() {
    fprintf(stderr, "super_table_creator version %s (c) 2012 Carnegie "
            "Mellon University.\n", VERSION);
    fprintf(stderr, "Send bug reports, feature requests, and comments to "
            "netsa-help@cert.org.\n");
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

    GOptionContext *ctx = NULL;
    GError *err = NULL;

    ctx = g_option_context_new(" - super_table_creator Options");
    g_option_context_add_main_entries(ctx, md_core_option, NULL);
    g_option_context_set_help_enabled(ctx, TRUE);

    if (!g_option_context_parse(ctx, argc, argv, &err)) {
        g_error("option parsing failed: %s\n", err->message);
        exit(1);
    }

    if (md_version) {
        mdPrintVersion();
        exit(-1);
    }

    g_option_context_free(ctx);
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

    MYSQL    *conn = NULL;
    char     query[1400];
    int      rv;


    /* parse all the options */
    mdParseOptions(&argc, &argv);

    conn = mysql_init(NULL);
    if (conn == NULL) {
        fprintf(stderr, "Error Initializing Connection %u: %s\n",
                mysql_errno(conn), mysql_error(conn));
        exit(1);
    }

    if (mysql_real_connect(conn, md_ehost, md_mysql_name, md_mysql_pass, NULL,
                           0, NULL, 0) == NULL)
    {
        fprintf(stderr, "Error Connecting %u: %s\n", mysql_errno(conn),
                mysql_error(conn));
        exit(1);
    }

    sprintf(query, "create database %s", md_mysql_db);
    if (mysql_query(conn, query)) {
        fprintf(stderr, "Ignoring Warning: Database %s %u: %s\n", md_mysql_db,
                mysql_errno(conn), mysql_error(conn));
    }

    sprintf(query, "use %s", md_mysql_db);
    if (mysql_query(conn, query)) {
        fprintf(stderr, "Error %u: %s\n", mysql_errno(conn),mysql_error(conn));
        exit(1);
    }

    if (md_flow_only) {
        if (mysql_query(conn, "CREATE TABLE flow(stime DATETIME,"
                        "etime DATETIME, duration DECIMAL(10,3), rtt DECIMAL(10,3), "
                        "protocol TINYINT, sip VARCHAR(40), sport MEDIUMINT, "
                        "pkt BIGINT, oct BIGINT, att MEDIUMINT, "
                        "mac VARCHAR(18), dip VARCHAR(40), dport MEDIUMINT, "
                        "rpkt BIGINT, roct BIGINT, ratt MEDIUMINT, "
                        "rmac VARCHAR(18), iflags VARCHAR(10), uflags "
                        "VARCHAR(10), riflags VARCHAR(10), ruflags VARCHAR(10)"
                        ", isn VARCHAR(10), risn VARCHAR(10), ingress INT, egress INT, "
                        "vlan VARCHAR(3), app MEDIUMINT, tos VARCHAR(3), "
                        "reason VARCHAR(10), collector VARCHAR(100))"))
        {
            fprintf(stderr, "Error creating full flow table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "Successfully created full flow table.\n");
        }
        exit(0);
    }

    if (md_dns_dedup) {
        if (mysql_query(conn, "CREATE TABLE dns_dedup(first_seen DATETIME, rrtype MEDIUMINT,"
                        "rrname VARCHAR(270), rrval VARCHAR(300))")) {
            fprintf(stderr, "Error creating DNS dedup default table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "Successfully created DNS dedup table.\n");
        }
        exit(0);
    }

    if (md_dedup_last) {
        if (mysql_query(conn, "CREATE TABLE dns_dedup(first_seen DATETIME, last_seen DATETIME,"
                        "rrtype MEDIUMINT, rrname VARCHAR(270), hitcount INT, rrval VARCHAR(300))"))
        {
            fprintf(stderr, "Error Creating DNS dedup last seen table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "Successfully created DNS dedup last seen table.\n");
        }
        exit(0);
    }

    if (md_dedup) {
        rv = snprintf(query, sizeof(query), "CREATE TABLE %s(first_seen DATETIME, "
                      "last_seen DATETIME, ip VARCHAR(40), hash INT unsigned, "
                      "hitcount BIGINT unsigned, data VARCHAR(500))", md_dedup);
        if ((rv < 0) || (rv >= sizeof(query))) {
            fprintf(stderr, "Error creating dedup %s table.  Table name may be too"
                    " long.\n", md_dedup);
            exit(-1);
        }
        rv = mysql_query(conn, query);
        if (rv) {
            fprintf(stderr, "Error creating dedup %s table: %s\n", md_dedup,
                    mysql_error(conn));
        } else {
            fprintf(stderr, "%s table successfully created\n", md_dedup);
        }
        exit(0);
    }

    if (md_ssl_cert) {
        rv = mysql_query(conn, "CREATE TABLE certs(serial VARCHAR(150), issuer "
                         "VARCHAR(500), stime DATETIME, id INT, ISE VARCHAR(2),"
                         "cert_no SMALLINT, data VARCHAR(500))");
        if (rv) {
            fprintf(stderr, "Error creating ssl certs table: %s\n",
                    mysql_error(conn));
        } else {
           fprintf(stderr, "certs table successfully created\n");
        }
        rv = mysql_query(conn, "CREATE TABLE certs_dedup(first_seen DATETIME, "
                         "last_seen DATETIME, serial VARCHAR(150), hitcount "
                         "BIGINT unsigned, issuer VARCHAR(500))");
        if (rv) {
            fprintf(stderr, "Error creating certs_dedup table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "certs_dedup table successfully created\n");
        }
        exit(0);
    }

    if (md_ssl_dedup) {
        rv = mysql_query(conn, "CREATE TABLE ssl_ip_dedup(first_seen DATETIME, "
                         "last_seen DATETIME, ip VARCHAR(40), hash INT unsigned,"
                         "hitcount BIGINT, serial1 VARCHAR(150), issuer1 "
                         "VARCHAR(500), serial2 VARCHAR(150), issuer2 VARCHAR(500))");
        if (rv) {
            fprintf(stderr, "Error creating ssl_ip_dedup table: %s\n",
                    mysql_error(conn));
        } else {
           fprintf(stderr, "ssl_ip_dedup table successfully created\n");
        }
        exit(0);
    }

    if (md_flow_stats) {
        if (!md_no_index) {
            if (mysql_query(conn,"CREATE TABLE flowstats(flow_key INT unsigned"
                            ",stime BIGINT unsigned, obid INT unsigned, "
                            "tcpurg BIGINT unsigned, smallpkt BIGINT unsigned,"
                            "nonempty BIGINT unsigned,datalen BIGINT unsigned,"
                            "avgitime BIGINT unsigned,firstpktlen INT "
                            "unsigned, largepktct BIGINT unsigned, maxpktsize "
                            "INT unsigned, firsteight SMALLINT unsigned, "
                            "stddevlen BIGINT unsigned, stddevtime BIGINT "
                            "unsigned, avgdata BIGINT "
                            "unsigned, revtcpurg BIGINT unsigned, revsmallpkt "
                            "BIGINT unsigned, revnonempty BIGINT unsigned, "
                            "revdatalen BIGINT unsigned, revavgitime BIGINT "
                            "unsigned, revfirstpktlen INT unsigned, "
                            "revlargepktct BIGINT unsigned, revmaxpktsize INT "
                            "unsigned, revstddevlen BIGINT unsigned, "
                            "revstddevtime BIGINT unsigned, revavgdata BIGINT "
                            "unsigned)"))
            {
                fprintf(stderr, "Error creating flow statistics table: %s\n",
                        mysql_error(conn));
            } else {
               fprintf(stderr,"Successfully created Flow Statistics Table.\n");
            }
        } else {
            if (mysql_query(conn,"CREATE TABLE flowstats(stime DATETIME, sip "
                            "VARCHAR(40), dip VARCHAR(40), protocol TINYINT "
                            "unsigned, sport MEDIUMINT unsigned, dport "
                            "MEDIUMINT unsigned, vlan INT unsigned,"
                            " obid INT unsigned, "
                            "tcpurg BIGINT unsigned, smallpkt BIGINT unsigned,"
                            "nonempty BIGINT unsigned,datalen BIGINT unsigned,"
                            "avgitime BIGINT unsigned,firstpktlen INT "
                            "unsigned, largepktct BIGINT unsigned, maxpktsize "
                            "INT unsigned, firsteight SMALLINT unsigned, "
                            "stddevlen BIGINT unsigned, stddevtime BIGINT "
                            "unsigned, avgdata BIGINT "
                            "unsigned, revtcpurg BIGINT unsigned, revsmallpkt "
                            "BIGINT unsigned, revnonempty BIGINT unsigned, "
                            "revdatalen BIGINT unsigned, revavgitime BIGINT "
                            "unsigned, revfirstpktlen INT unsigned, "
                            "revlargepktct BIGINT unsigned, revmaxpktsize INT "
                            "unsigned, revstddevlen BIGINT unsigned, "
                            "revstddevtime BIGINT unsigned, revavgdata BIGINT "
                            "unsigned)"))
            {
                fprintf(stderr, "Error creating flow statistics table: %s\n",
                        mysql_error(conn));
            } else {
              fprintf(stderr, "Successfully created Flow Statistics Table.\n");
            }
        }
        exit(0);
    }

    if (md_yaf_stats) {
        if (mysql_query(conn, "CREATE table yaf_stats(ts TIMESTAMP, flows "
                        "BIGINT unsigned, packets BIGINT unsigned, dropped "
                        "BIGINT unsigned, ignored BIGINT unsigned, "
                        "expired_frags BIGINT unsigned, assembled_frags BIGINT"
                        " unsigned, flush_events INT unsigned, table_peak INT "
                        "unsigned, yaf_ip VARCHAR(40), yaf_id INT unsigned,"
                        "flow_rate INT unsigned, packet_rate INT unsigned, "
                        "collector VARCHAR (100))"))
        {
            fprintf(stderr, "Error creating yaf_stats table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "Successfully created yaf_stats Table.\n");
        }

        exit(0);
    }

    if (!md_no_index) {
        if (mysql_query(conn, "CREATE TABLE flow(flow_key INT unsigned, stime "
                        "BIGINT unsigned, sip VARCHAR(40), dip VARCHAR(40), "
                        "protocol TINYINT unsigned, sport MEDIUMINT unsigned,"
                        "dport MEDIUMINT unsigned, vlan INT unsigned, obid INT"
                        " unsigned)"))
        {
            fprintf(stderr, "Error creating flow index table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "Flow Index Table Created Successfully\n");
        }
    } else {
        fprintf(stderr,"Not creating flow index table [in --no-index mode]\n");
    }

    if (md_no_index) {
        if (mysql_query(conn, "CREATE TABLE dns(stime DATETIME, sip "
                    "VARCHAR(40), dip VARCHAR(40), protocol TINYINT unsigned, "
                        "sport MEDIUMINT unsigned, dport MEDIUMINT unsigned,"
                        " vlan INT unsigned,obid INT unsigned, qr VARCHAR(1), "
                    "id INT unsigned, section TINYINT unsigned, nx TINYINT "
                    "unsigned, auth TINYINT unsigned, type MEDIUMINT unsigned,"
                    "ttl INT unsigned, name VARCHAR(255), val VARCHAR(255))"))
        {
            fprintf(stderr, "Error creating DNS table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "DNS Table Created Successfully\n");
        }
    } else {
        if (mysql_query(conn, "CREATE TABLE dns(flow_key INT unsigned, stime "
                        "BIGINT unsigned, obid INT unsigned, qr VARCHAR(1), "
                        "id INT unsigned, section TINYINT unsigned, nx TINYINT "
                        "unsigned, auth TINYINT unsigned, type MEDIUMINT unsigned,"
                        "ttl INT unsigned, name VARCHAR(255), val VARCHAR(255))"))
        {
            fprintf(stderr, "Error creating DNS table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "DNS Table Created Successfully\n");
        }
    }

    if (md_no_index) {
        rv = mysql_query(conn, "CREATE TABLE http(stime DATETIME, sip "
                         "VARCHAR(40), dip VARCHAR(40), protocol TINYINT unsigned, "
                         "sport MEDIUMINT unsigned, dport MEDIUMINT unsigned, vlan INT unsigned,"
                         " obid INT unsigned, id MEDIUMINT unsigned, "
                         "data VARCHAR(500))");
    } else {
        rv = mysql_query(conn, "CREATE TABLE http(flow_key "
                         "INT unsigned, stime BIGINT unsigned, obid INT unsigned, "
                         "id MEDIUMINT unsigned, data VARCHAR(500))");
    }

    if (rv) {
        fprintf(stderr, "Error creating http table: %s\n", mysql_error(conn));
    } else {
        fprintf(stderr, "HTTP Table Created Successfully\n");
    }

    if (md_dedup_flow) {
        rv = mysql_query(conn, "ALTER TABLE http ADD count INT unsigned AFTER"
                         " id");
        if (rv) {
            fprintf(stderr, "Error modifying http table for DEDUP PER FLOW"
                    " %s\n", mysql_error(conn));
        }
    }

    if (md_no_index) {
        rv = mysql_query(conn, "CREATE TABLE tls(stime DATETIME, sip "
                         "VARCHAR(40), dip VARCHAR(40), protocol "
                         "TINYINT unsigned, sport MEDIUMINT unsigned, dport "
                         "MEDIUMINT unsigned, vlan INT unsigned,"
                         " obid INT unsigned, id MEDIUMINT unsigned, "
                         "cert_type VARCHAR(500), cert_no TINYINT unsigned, "
                         "data VARCHAR(500))");
    } else {
        rv = mysql_query(conn, "CREATE TABLE tls( "
                         "flow_key INT unsigned, stime BIGINT unsigned, obid "
                         "INT unsigned, id MEDIUMINT unsigned, cert_type VARCHAR(5), "
                         "cert_no TINYINT unsigned, data VARCHAR(500))");

    }

    if (rv) {
        fprintf(stderr, "Error creating tls table: %s\n", mysql_error(conn));
    } else {
        fprintf(stderr, "TLS Table Created Successfully\n");
    }

    if (md_no_index) {
        if (mysql_query(conn, "CREATE TABLE slp(stime DATETIME, sip "
                        "VARCHAR(40), dip VARCHAR(40), protocol TINYINT unsigned, "
                        "sport MEDIUMINT unsigned, dport MEDIUMINT unsigned, vlan INT unsigned,"
                        " obid INT unsigned, id MEDIUMINT unsigned, "
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating SLP table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "SLP Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn, "CREATE TABLE slp(flow_key "
                        "INT unsigned, stime BIGINT unsigned, obid INT unsigned, "
                        "id MEDIUMINT unsigned, data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating slp table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "SLP Table Created Successfully\n");
        }
    }

    if (md_dedup_flow) {
        rv = mysql_query(conn, "ALTER TABLE slp ADD count INT unsigned AFTER"
                         " id");
        if (rv) {
            fprintf(stderr,"Error modifying SLP table for DEDUP PER FLOW %s\n",
                    mysql_error(conn));
        }
    }

    if (md_no_index) {
        if (mysql_query(conn, "CREATE TABLE imap(stime DATETIME, sip "
                        "VARCHAR(40), dip VARCHAR(40), protocol TINYINT unsigned, "
                        "sport MEDIUMINT unsigned, dport MEDIUMINT unsigned, vlan INT unsigned,"
                        " obid INT unsigned, id MEDIUMINT unsigned, "
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating imap table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "IMAP Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn, "CREATE TABLE imap(flow_key "
                        "INT unsigned, stime BIGINT unsigned, obid INT unsigned, "
                        "id MEDIUMINT unsigned, data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating imap table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "IMAP Table Created Successfully\n");
        }
    }

    if (md_dedup_flow) {
        rv = mysql_query(conn, "ALTER TABLE imap ADD count INT unsigned AFTER"
                         " id");
        if (rv) {
            fprintf(stderr, "Error modifying imap table for DEDUP PER FLOW"
                    " %s\n", mysql_error(conn));
        }
    }

    if (md_no_index) {
        if (mysql_query(conn, "CREATE TABLE smtp(stime DATETIME, sip "
                        "VARCHAR(40), dip VARCHAR(40), protocol TINYINT unsigned, "
                        "sport MEDIUMINT unsigned, dport MEDIUMINT unsigned, vlan INT unsigned,"
                        " obid INT unsigned, id MEDIUMINT unsigned, "
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating smtp table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "SMTP Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn, "CREATE TABLE smtp(flow_key "
                        "INT unsigned, stime BIGINT unsigned, obid INT unsigned, "
                        "id MEDIUMINT unsigned, data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating smtp table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "SMTP Table Created Successfully\n");
        }
    }

    if (md_dedup_flow) {
        rv = mysql_query(conn, "ALTER TABLE smtp ADD count INT unsigned AFTER"
                         " id");
        if (rv) {
            fprintf(stderr, "Error modifying smtp table for DEDUP PER FLOW"
                    " %s\n", mysql_error(conn));
        }
    }

    if (md_no_index) {
        if (mysql_query(conn, "CREATE TABLE pop3(stime DATETIME, sip "
                        "VARCHAR(40), dip VARCHAR(40), protocol TINYINT unsigned, "
                        "sport MEDIUMINT unsigned, dport MEDIUMINT unsigned, vlan INT unsigned,"
                        " obid INT unsigned, id MEDIUMINT unsigned, "
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating pop3 table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "POP3 Table Created Successfully\n");
        }
    } else {
        if (mysql_query(conn, "CREATE TABLE pop3(flow_key "
                        "INT unsigned, stime BIGINT unsigned, obid INT unsigned, "
                        "id MEDIUMINT unsigned, data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating pop3 table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "POP3 Table Created Successfully\n");
        }
    }

    if (md_dedup_flow) {
        rv = mysql_query(conn, "ALTER TABLE pop3 ADD count INT unsigned AFTER"
                         " id");
        if (rv) {
            fprintf(stderr, "Error modifying pop3 table for DEDUP PER FLOW"
                    " %s\n", mysql_error(conn));
        }
    }

    if (md_no_index) {
        if (mysql_query(conn, "CREATE TABLE irc(stime DATETIME, sip "
                        "VARCHAR(40), dip VARCHAR(40), protocol TINYINT unsigned, "
                        "sport MEDIUMINT unsigned, dport MEDIUMINT unsigned, vlan INT unsigned,"
                        " obid INT unsigned, id MEDIUMINT unsigned, "
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating irc table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "IRC Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn, "CREATE TABLE irc(flow_key "
                        "INT unsigned, stime BIGINT unsigned, obid INT unsigned, "
                        "id MEDIUMINT unsigned, data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating irc table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "IRC Table Created Successfully\n");
        }
    }

    if (md_dedup_flow) {
        rv = mysql_query(conn, "ALTER TABLE irc ADD count INT unsigned AFTER"
                         " id");
        if (rv) {
            fprintf(stderr, "Error modifying irc table for DEDUP PER FLOW"
                    " %s\n", mysql_error(conn));
        }
    }

    if (md_no_index) {
        if (mysql_query(conn, "CREATE TABLE ftp(stime DATETIME, sip "
                        "VARCHAR(40), dip VARCHAR(40), protocol TINYINT unsigned, "
                        "sport MEDIUMINT unsigned, dport MEDIUMINT unsigned, vlan INT unsigned,"
                        " obid INT unsigned, id MEDIUMINT unsigned, "
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating ftp table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "FTP Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn, "CREATE TABLE ftp(flow_key "
                        "INT unsigned, stime BIGINT unsigned, obid INT unsigned, "
                        "id MEDIUMINT unsigned, data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating ftp table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "FTP Table Created Successfully\n");
        }
    }

    if (md_dedup_flow) {
        rv = mysql_query(conn, "ALTER TABLE ftp ADD count INT unsigned AFTER"
                         " id");
        if (rv) {
            fprintf(stderr, "Error modifying ftp table for DEDUP PER FLOW"
                    " %s\n", mysql_error(conn));
        }
    }

    if (md_no_index) {
        if (mysql_query(conn, "CREATE TABLE tftp(stime TIMESTAMP, sip "
                        "VARCHAR(40), dip VARCHAR(40), protocol TINYINT unsigned, "
                        "sport MEDIUMINT unsigned, dport MEDIUMINT unsigned, vlan INT unsigned,"
                        " obid INT unsigned, id MEDIUMINT unsigned, "
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating tftp table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "TFTP Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn, "CREATE TABLE tftp(flow_key "
                        "INT unsigned, stime BIGINT unsigned, obid INT unsigned, "
                        "id MEDIUMINT unsigned, data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating tftp table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "TFTP Table Created Successfully\n");
        }
    }

    if (md_no_index) {
        if (mysql_query(conn, "CREATE TABLE sip(stime DATETIME, sip "
                        "VARCHAR(40), dip VARCHAR(40), protocol TINYINT unsigned, "
                        "sport MEDIUMINT unsigned, dport MEDIUMINT unsigned, vlan INT unsigned,"
                        " obid INT unsigned, id MEDIUMINT unsigned, "
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating sip table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "SIP Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn, "CREATE TABLE sip(flow_key "
                        "INT unsigned, stime BIGINT unsigned, obid INT unsigned, "
                        "id MEDIUMINT unsigned, data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating sip table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "SIP Table Created Successfully\n");
        }

    }

    if (md_dedup_flow) {
        rv = mysql_query(conn, "ALTER TABLE sip ADD count INT unsigned AFTER"
                         " id");
        if (rv) {
            fprintf(stderr, "Error modifying sip table for DEDUP PER FLOW"
                    " %s\n", mysql_error(conn));
        }
    }

    if (md_no_index) {
        if (mysql_query(conn, "CREATE TABLE rtsp(stime DATETIME, sip "
                        "VARCHAR(40), dip VARCHAR(40), protocol TINYINT unsigned, "
                        "sport MEDIUMINT unsigned, dport MEDIUMINT unsigned, vlan INT unsigned,"
                        " obid INT unsigned, id MEDIUMINT unsigned, "
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating rtsp table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "RTSP Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn, "CREATE TABLE rtsp(flow_key "
                        "INT unsigned, stime BIGINT unsigned, obid INT unsigned, "
                        "id MEDIUMINT unsigned, data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating rtsp table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "RTSP Table Created Successfully\n");
        }
    }

    if (md_dedup_flow) {
        rv = mysql_query(conn, "ALTER TABLE rtsp ADD count INT unsigned AFTER"
                         " id");
        if (rv) {
            fprintf(stderr, "Error modifying rtsp table for DEDUP PER FLOW"
                    " %s\n", mysql_error(conn));
        }
    }

    if (md_no_index) {
        if (mysql_query(conn, "CREATE TABLE mysql(stime DATETIME, sip "
                        "VARCHAR(40), dip VARCHAR(40), protocol TINYINT unsigned, "
                        "sport MEDIUMINT unsigned, dport MEDIUMINT unsigned, vlan INT unsigned,"
                        " obid INT unsigned, id MEDIUMINT unsigned, "
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating mysql table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "MySQL Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn, "CREATE TABLE mysql(flow_key "
                        "INT unsigned, stime BIGINT unsigned, obid INT unsigned, "
                        "id MEDIUMINT unsigned, data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating mysql table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "MYSQL Table Created Successfully\n");
        }
    }

    if (md_no_index) {
        if (mysql_query(conn, "CREATE TABLE p0f(stime DATETIME, sip "
                        "VARCHAR(40), dip VARCHAR(40), protocol TINYINT unsigned, "
                        "sport MEDIUMINT unsigned, dport MEDIUMINT unsigned, vlan INT unsigned,"
                        " obid INT unsigned, id MEDIUMINT unsigned, "
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating p0f table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "p0f Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn, "CREATE TABLE p0f(flow_key "
                        "INT unsigned, stime BIGINT unsigned, obid INT unsigned, "
                        "id MEDIUMINT unsigned, data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating p0f table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "P0F Table Created Successfully\n");
        }
    }

    if (md_no_index) {
        if (mysql_query(conn, "CREATE TABLE dhcp(stime DATETIME, sip "
                        "VARCHAR(40), dip VARCHAR(40), protocol TINYINT unsigned, "
                        "sport MEDIUMINT unsigned, dport MEDIUMINT unsigned, vlan INT unsigned,"
                        " obid INT unsigned, id MEDIUMINT unsigned, "
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating dhcp table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "DHCP Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn, "CREATE TABLE dhcp(flow_key "
                        "INT unsigned, stime BIGINT unsigned, obid INT unsigned, "
                        "id MEDIUMINT unsigned, data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating dhcp table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "DHCP Table Created Successfully\n");
        }
    }

    if (md_no_index) {
        if (mysql_query(conn, "CREATE TABLE ssh(stime DATETIME, sip "
                        "VARCHAR(40), dip VARCHAR(40), protocol TINYINT unsigned, "
                        "sport MEDIUMINT unsigned, dport MEDIUMINT unsigned, vlan INT unsigned,"
                        " obid INT unsigned, id MEDIUMINT unsigned, "
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating ssh table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "SSH Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn, "CREATE TABLE ssh(flow_key "
                        "INT unsigned, stime BIGINT unsigned, obid INT unsigned, "
                        "id MEDIUMINT unsigned, data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating ssh table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "SSH Table Created Successfully\n");
        }
    }

    if (md_dedup_flow) {
        rv = mysql_query(conn, "ALTER TABLE ssh ADD count INT unsigned AFTER"
                         " id");
        if (rv) {
            fprintf(stderr, "Error modifying ssh table for DEDUP PER FLOW"
                    " %s\n", mysql_error(conn));
        }
    }

    if (md_no_index) {
        if (mysql_query(conn, "CREATE TABLE nntp(stime DATETIME, sip "
                        "VARCHAR(40), dip VARCHAR(40), protocol TINYINT unsigned, "
                        "sport MEDIUMINT unsigned, dport MEDIUMINT unsigned, vlan INT unsigned,"
                        " obid INT unsigned, id MEDIUMINT unsigned, "
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating nntp table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "NNTP Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn, "CREATE TABLE nntp(flow_key "
                        "INT unsigned, stime BIGINT unsigned, obid INT unsigned, "
                        "id MEDIUMINT unsigned, data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating nntp table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "NNTP Table Created Successfully\n");
        }
    }

    if (md_no_index) {
        if (mysql_query(conn, "CREATE TABLE rtp(stime DATETIME, sip "
                        "VARCHAR(40), dip VARCHAR(40), protocol TINYINT unsigned, "
                        "sport MEDIUMINT unsigned, dport MEDIUMINT unsigned, vlan INT unsigned,"
                        " obid INT unsigned, id MEDIUMINT unsigned, "
                        "paytype INT unsigned, revpaytype INT unsigned)"))
        {
            fprintf(stderr, "Error creating rtp table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "RTP Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn, "CREATE TABLE rtp(flow_key "
                        "INT unsigned, stime BIGINT unsigned, obid INT unsigned, "
                        "id MEDIUMINT unsigned, paytype INT unsigned, revpaytype INT unsigned)"))
        {
            fprintf(stderr, "Error creating rtp table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "RTP Table Created Successfully\n");
        }
    }

    if (md_no_index) {
        if (mysql_query(conn, "CREATE TABLE modbus(stime DATETIME, sip "
                        "VARCHAR(40), dip VARCHAR(40), protocol TINYINT unsigned, "
                        "sport MEDIUMINT unsigned, dport MEDIUMINT unsigned, vlan INT unsigned,"
                        " obid INT unsigned, id MEDIUMINT unsigned, "
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating modbus table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "Modbus Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn, "CREATE TABLE modbus(flow_key "
                        "INT unsigned, stime BIGINT unsigned, obid INT unsigned, "
                        "id MEDIUMINT unsigned, data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating modbus table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "Modbus Table Created Successfully\n");
        }
    }

    if (md_dedup_flow) {
        rv = mysql_query(conn,"ALTER TABLE modbus ADD count INT unsigned AFTER"
                         " id");
        if (rv) {
            fprintf(stderr, "Error modifying modbus table for DEDUP PER FLOW"
                    " %s\n", mysql_error(conn));
        }
    }

    if (md_no_index) {
        if (mysql_query(conn, "CREATE TABLE dnp3(stime DATETIME, sip "
                        "VARCHAR(40), dip VARCHAR(40), protocol TINYINT unsigned, "
                        "sport MEDIUMINT unsigned, dport MEDIUMINT unsigned, vlan INT unsigned,"
                        " obid INT unsigned, src MEDIUMINT unsigned, dst MEDIUMINT unsigned,"
                        "function TINYINT unsigned, data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating dnp3 table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "DNP3 Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn, "CREATE TABLE dnp3(flow_key "
                        "INT unsigned, stime BIGINT unsigned, obid INT unsigned, "
                        "id MEDIUMINT unsigned, src MEDIUMINT unsigned, dst MEDIUMINT unsigned, "
                        "function TINYINT unsigned, data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating dnp3 table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "DNP3 Table Created Successfully\n");
        }
    }

    if (md_no_index) {
        if (mysql_query(conn, "CREATE TABLE enip(stime DATETIME, sip "
                        "VARCHAR(40), dip VARCHAR(40), protocol TINYINT unsigned, "
                        "sport MEDIUMINT unsigned, dport MEDIUMINT unsigned, vlan INT unsigned,"
                        " obid INT unsigned, id MEDIUMINT unsigned, "
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating enip table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "ENIP Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn, "CREATE TABLE enip(flow_key "
                        "INT unsigned, stime BIGINT unsigned, obid INT unsigned, "
                        "id MEDIUMINT unsigned, data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating enip table: %s\n", mysql_error(conn));
        } else {
            fprintf(stderr, "ENIP Table Created Successfully\n");
        }
    }

    if (md_dedup_flow) {
        rv = mysql_query(conn, "ALTER TABLE enip ADD count INT unsigned AFTER"
                         " id");
        if (rv) {
            fprintf(stderr, "Error modifying enip table for DEDUP PER FLOW"
                    " %s\n", mysql_error(conn));
        }
    }

    /* create the dpi id table */
    if (mysql_query(conn, "CREATE TABLE dpi_id("
                    "id int NOT NULL, tab VARCHAR(30) NOT NULL,"
                    "description VARCHAR(255) NOT NULL)"))
    {
        fprintf(stderr, "Error creating dpi_id table: %s\n", mysql_error(conn));
    } else {
        fprintf(stderr, "DPI_ID table successfully created.\n");
        mdInsertDPIValues(conn);
    }

    mysql_close(conn);
    return 0;
}



/**
 * mdInsertDPIValues
 *
 */
static void mdInsertDPIValues(
    MYSQL                    *conn)
{

    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('1', 'dns', 'ARecord')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('2', 'dns', 'NSRecord')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('5', 'dns', 'CNAMERecord')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('6', 'dns', 'SOARecord')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('12', 'dns', 'MXRecord')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('15', 'dns', 'PTRRecord')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('16', 'dns', 'TXTRecord')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('28', 'dns', 'AAAARecord')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('33', 'dns', 'SRVRecord')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('43', 'dns', 'DSRecord')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('46', 'dns', 'RRSIGRecord')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('47', 'dns', 'NSECRecord')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('48', 'dns', 'DNSKEYRecord')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('50', 'dns', 'NSEC3Record')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('51', 'dns', 'NSEC3PARAMRecord')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('3', 'tls', 'commonname')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('6', 'tls', 'countryName')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('7', 'tls', 'localityName')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('8', 'tls', 'stateOrProvinceName')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('9', 'tls', 'streetAddress')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('10', 'tls', 'organization')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('11', 'tls', 'organizationalunit')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('12', 'tls', 'title')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('17', 'tls', 'postalCode')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('41', 'tls', 'name')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('185', 'tls', 'sslCipher')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('186', 'tls', 'sslClientVersion')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('187', 'tls', 'sslServerCipher')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('188', 'tls', 'sslCompressionMethod')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('189', 'tls', 'sslCertVersion')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('190', 'tls', 'sslCertSignature')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('247', 'tls', 'sslCertValidityNotBefore')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('248', 'tls', 'sslCertValidityNotAfter')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('249', 'tls', 'sslPublicKeyAlgorithm')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('250', 'tls', 'sslPublicKeyLength')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('289', 'tls', 'sslCertVersion')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('36', 'p0f', 'osName')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('37', 'p0f', 'osVersion')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('107', 'p0f', 'osFingerPrint')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('110', 'http', 'httpServerString')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('111', 'http', 'httpUserAgent')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('112', 'http', 'httpGet')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('113', 'http', 'httpConnection')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('114', 'http', 'httpVersion')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('115', 'http', 'httpReferer')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('116', 'http', 'httpLocation')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('117', 'http', 'httpHost')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('118', 'http', 'httpContentLength')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('119', 'http', 'httpAge')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('120', 'http', 'httpAccept')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('121', 'http', 'httpAcceptLanguage')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('122', 'http', 'httpContentType')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('123', 'http', 'httpResponse')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('220', 'http', 'httpCookie')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('221', 'http', 'httpSetCookie')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('257', 'http', 'httpIMEI')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('258', 'http', 'httpIMSI')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('259', 'http', 'httpMSISDN')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('260', 'http', 'httpSubscriber')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('255', 'http', 'httpExpires')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('261', 'http', 'httpAcceptCharset')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('262', 'http', 'httpAcceptEncoding')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('263', 'http', 'httpAllow')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('264', 'http', 'httpDate')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('265', 'http', 'httpExpect')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('266', 'http', 'httpFrom')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('267', 'http', 'httpProxyAuthentication')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('268', 'http', 'httpUpgrade')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('269', 'http', 'httpWarning')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('270', 'http', 'httpDNT')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('271', 'http', 'httpX-Forwarded-Proto')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('272', 'http', 'httpX-Forwarded-Host')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('273', 'http', 'httpX-Forwarded-Server')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('274', 'http', 'httpX-DeviceID')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('275', 'http', 'httpProfile')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('276', 'http', 'httpLastModified')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('277', 'http', 'httpContentEncoding')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('278', 'http', 'httpContentLanguage')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('279', 'http', 'httpContentLocation')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('280', 'http', 'httpX-UA-Compatible')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('124', 'pop3', 'pop3TextMessage')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('125', 'irc', 'ircTextMessage')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('126', 'tftp', 'tftpFilename')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('127', 'tftp', 'tftpMode')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('128', 'slp', 'slpVersion')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('129', 'slp', 'slpMessageType')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('130', 'slp', 'slpString')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('131', 'ftp', 'ftpReturn')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('132', 'ftp', 'ftpUser')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('133', 'ftp', 'ftpPass')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('134', 'ftp', 'ftpType')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('135', 'ftp', 'ftpRespCode')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('136', 'imap', 'imapCapability')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('137', 'imap', 'imapLogin')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('138', 'imap', 'imapStartTLS')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('139', 'imap', 'imapAuthenticate')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('140', 'imap', 'imapCommand')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('141', 'imap', 'imapExists')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('142', 'imap', 'imapRecent')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('143', 'rtsp', 'rtspURL')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('144', 'rtsp', 'rtspVersion')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('145', 'rtsp', 'rtspReturnCode')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('146', 'rtsp', 'rtspContentLength')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('147', 'rtsp', 'rtspCommand')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('148', 'rtsp', 'rtspContentType')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('149', 'rtsp', 'rtspTransport')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('150', 'rtsp', 'rtspCSeq')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('151', 'rtsp', 'rtspLocation')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('152', 'rtsp', 'rtspPacketsReceived')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('153', 'rtsp', 'rtspUserAgent')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('154', 'rtsp', 'rtspJitter')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('155', 'sip', 'sipInvite')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('156', 'sip', 'sipCommand')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('157', 'sip', 'sipVia')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('158', 'sip', 'sipMaxForwards')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('159', 'sip', 'sipAddress')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('160', 'sip', 'sipContentLength')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('161', 'sip', 'sipUserAgent')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('162', 'smtp', 'smtpHello')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('163', 'smtp', 'smtpFrom')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('164', 'smtp', 'smtpTo')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('165', 'smtp', 'smtpContentType')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('166', 'smtp', 'smtpSubject')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('167', 'smtp', 'smtpFilename')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('168', 'smtp', 'smtpContentDisposition')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('169', 'smtp', 'smtpResponse')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('170', 'smtp', 'smtpEnhanced')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('222', 'smtp', 'smtpSize')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('251', 'smtp', 'smtpDate')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('171', 'ssh', 'sshVersion')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('172', 'nntp', 'nntpResponse')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('173', 'nntp', 'nntpCommand')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('223', 'mysql', 'mysqlUsername')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('225', 'mysql', 'mysqlCommandText')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('242', 'dhcp', 'dhcpFingerPrint')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('243', 'dhcp', 'dhcpVendorCode')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('281', 'dnp3', 'dnp3SourceAddress')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('282', 'dnp3', 'dhp3DestinationAddress')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('283', 'dnp3', 'dhp3Function')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('284', 'dnp3', 'dhp3Object')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('285', 'modbus', 'modbusData')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('286', 'enip', 'ethernetIPData')");
    mysql_query(conn, "insert into dpi_id (id,tab,description) values ('287', 'rtp', 'rtpPayloadType')");
}



#endif
