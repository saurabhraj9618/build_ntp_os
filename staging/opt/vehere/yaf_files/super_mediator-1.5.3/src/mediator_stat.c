/**
 * @file mediator_stat.c
 *
 * Handles mediator/yaf stats
 *
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2012-2017 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 * Authors: Emily Sarneso <netsa-help@cert.org>
 * ------------------------------------------------------------------------
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

#include <mediator/mediator_inf.h>
#include <mediator/mediator_core.h>
#include <mediator/mediator_util.h>
#include "mediator_stat.h"

static GTimer *md_start = NULL;

/**
 * mdStatInit
 *
 *
 *
 */
void mdStatInit(
                )
{
    md_start = g_timer_new();
    g_timer_start(md_start);
}


/**
 * mdStatGetTimer
 *
 *
 */
GTimer *mdStatGetTimer()
{
    return md_start;
}


/**
 * mdLogStats
 *
 * Log YAF process statistics
 *
 */
void mdLogStats(
    yfIpfixStats_t *stats,
    char           *colname)
{

    char ipaddr[20];
    time_t cur_time = time(NULL);
    uint64_t ms = cur_time * 1000;
    uint64_t uptime = 0;
    uint64_t days = 0;
    uint64_t hours = 0;
    uint64_t mins = 0;

    if (ms > stats->sysInitTime) {
        uptime = (ms - stats->sysInitTime)/1000;
        days = uptime/86400;
        uptime -= (days * 86400);
        hours = (uptime/3600);
        uptime -= (hours * 3600);
        mins = (uptime/60);
        uptime -= (mins * 60);
    }

    md_util_print_ip4_addr(ipaddr, stats->exporterIPv4Address);
    g_message("%s: YAF ID: %d IP: %s Uptime: %"PRIu64"d:%"PRIu64"h:%"PRIu64"m:"
              "%"PRIu64"s", colname, stats->exportingProcessId, ipaddr,
              days, hours, mins, uptime);
    /*if (stats->sysInitTime) {
        g_message("%s: YAF Uptime: %llu Days, %llu Hours, %llu Minutes, "
                  "%llu Seconds", colname, days, hours, mins, uptime);
                  }*/
    g_message("%s: YAF Flows: %"PRIu64" Packets: %"PRIu64" Dropped: %"PRIu64
              " Ignored: %"PRIu64" Out of Sequence: %"PRIu64" Expired Frags:"
              " %u Assembled Frags: %u", colname,
              stats->exportedFlowTotalCount,
              stats->packetTotalCount, stats->droppedPacketTotalCount,
              stats->ignoredPacketTotalCount, stats->rejectedPacketTotalCount,
              stats->expiredFragmentCount, stats->assembledFragmentCount);

    /*g_message("Exported Flows: %llu", stats->exportedFlowTotalCount);
    g_message("Packets Processed: %llu", stats->packetTotalCount);
    g_message("Dropped Packets: %llu", stats->droppedPacketTotalCount);
    g_message("Ignored Packets: %llu", stats->ignoredPacketTotalCount);
    g_message("Rejected Out of Sequence Packets: %llu",
              stats->rejectedPacketTotalCount);
    g_message("Expired Fragments: %u", stats->expiredFragmentCount);
    g_message("Assembled Fragments: %u", stats->assembledFragmentCount);*/
}


/**
 * mdStatUpdate
 *
 * Log Mediator process statistics
 *
 */
void mdStatUpdate(
    md_stats_t *stats)
{

    uint64_t        seconds = g_timer_elapsed(md_start, NULL);
    uint64_t        uptime = seconds;
    uint64_t        days, hours, mins;

    days = uptime/86400;
    uptime -= (days * 86400);
    hours = uptime/3600;
    uptime -= (hours * 3600);
    mins = uptime/60;
    uptime -= (mins * 60);

    g_message("SM: Uptime: %"PRIu64"d:%"PRIu64"h:%"PRIu64"m:"
              "%"PRIu64"s, Total Flows: %"PRIu64", Filtered: %"PRIu64", "
              "Stats: %"PRIu64", DNS: %"PRIu64", Other: %"PRIu64", UDP-uniflows: %"PRIu64,
              days, hours, mins, uptime, stats->recvd_flows,
              stats->recvd_filtered, stats->recvd_stats, stats->dns,
              stats->nonstd_flows, stats->uniflows);
}


void mdStatDump(
    mdConfig_t *cfg,
    md_stats_t *stats)
{

    mdStatUpdate(stats);
    mdExporterUpdateStats(cfg, TRUE);
    mdCollectorUpdateStats(cfg);

}
