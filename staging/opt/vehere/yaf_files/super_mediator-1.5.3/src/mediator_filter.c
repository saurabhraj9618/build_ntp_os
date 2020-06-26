/**
 * @file mediator_filter.c
 *
 * Yaf mediator for filtering, DNS deduplication, and other mediator-like
 * things
 *
* -------------------------------------------------------------------------
 * Copyright (C) 2012-2017 Carnegie Mellon University. All Rights Reserved.
 * ------------------------------------------------------------------------
 * Authors: Emily Sarneso
 * ------------------------------------------------------------------------
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

#include <mediator/mediator_filter.h>

#if ENABLE_SKIPSET
#include SKIPSET_HEADER_NAME
#ifdef HAVE_SILK_SKIPADDR_H
#include <silk/skipaddr.h>
#endif
#endif




/**
 * mdComparison
 *
 * compare val_one to val_two with the given oper
 *
 * @param val_one - a value to be compared
 * @param val_two - the other value to be compared
 * @param oper - an operation such as '=', or '<'
 * @return TRUE - if the comparison is TRUE.
 *
 */
static gboolean mdComparison(
    uint64_t       val_one,
    uint64_t       val_two,
    fieldOperator  oper)
{

    switch(oper) {
      case EQUAL:
        if (val_one == val_two) {
            return TRUE;
        }
        return FALSE;
      case NOT_EQUAL:
        if (val_one != val_two) {
            return TRUE;
        }
        return FALSE;
      case LESS_THAN:
        if (val_one < val_two) {
            return TRUE;
        }
        return FALSE;
      case LESS_THAN_OR_EQUAL:
        if (val_one <= val_two) {
            return TRUE;
        }
        return FALSE;
      case GREATER_THAN:
        if (val_one > val_two) {
            return TRUE;
        }
        return FALSE;
      case GREATER_THAN_OR_EQUAL:
        if (val_one >= val_two) {
            return TRUE;
        }
        return FALSE;
      default:
        return FALSE;
    }

    return FALSE;
}

#if ENABLE_SKIPSET
/**
 * mdCompareIPSet
 *
 * @param flow - the basic flow record
 * @param filter - the filter node
 *
 * @return TRUE if the filter passed
 *
 */
static gboolean mdCompareIPSet(
    const mdRecord_t     *flow,
    const md_filter_t    *filter)
{

    skipaddr_t addr;

    if (flow->sourceIPv4Address || flow->destinationIPv4Address) {
        switch (filter->field) {
          case SIP_ANY:
          case SIP_V4:
            skipaddrSetV4(&addr, &(flow->sourceIPv4Address));
            if (skIPSetCheckAddress(filter->ipset, &addr)) {
                return TRUE;
            }
            return FALSE;
          case DIP_ANY:
          case DIP_V4:
            skipaddrSetV4(&addr, &(flow->destinationIPv4Address));
            if (skIPSetCheckAddress(filter->ipset, &addr)) {
                return TRUE;
            }
            return FALSE;
          case ANY_IP:
            skipaddrSetV4(&addr, &(flow->sourceIPv4Address));
            if (skIPSetCheckAddress(filter->ipset, &addr)) {
                return TRUE;
            }
            skipaddrSetV4(&addr, &(flow->destinationIPv4Address));
            if (skIPSetCheckAddress(filter->ipset, &addr)) {
                return TRUE;
            }
          default:
            return FALSE;
        }
    } else {
        switch (filter->field) {
          case SIP_ANY:
          case SIP_V6:
            if (skIPSetCheckAddress(filter->ipset,
                                    (const skipaddr_t *)&(flow->sourceIPv6Address)))
            {
                return TRUE;
            }
            return FALSE;
          case DIP_ANY:
          case DIP_V6:
            if (skIPSetCheckAddress(filter->ipset,
                                    (const skipaddr_t *)&(flow->destinationIPv6Address)))
            {
                return TRUE;
            }
            return FALSE;
          case ANY_IP:
          case ANY_IP6:
            if (skIPSetCheckAddress(filter->ipset,
                                    (const skipaddr_t *)&(flow->sourceIPv6Address)))
            {
                return TRUE;
            }
            if (skIPSetCheckAddress(filter->ipset,
                                    (const skipaddr_t *)&(flow->destinationIPv6Address)))
            {
                return TRUE;
            }
            return FALSE;
          default:
            return FALSE;
        }
    }

    return FALSE;
}

#endif


/**
 * mdCollectionFilter
 *
 * loop through the filters and compare the filters expressions
 * to the given flow record.
 * only one needs to result to TRUE to pass and break out of loop
 *
 * @param filter - a list of filters
 * @param flow - the basic flow record
 * @param obdomain - the observation domain
 * @return TRUE if one of the filters passed
 */
static gboolean mdCollectionFilter(
    const md_filter_t   *filter,
    const mdRecord_t    *flow,
    uint32_t            obdomain,
    uint8_t             collector_id)
{

    const md_filter_t *cfil = NULL;

    if (filter == NULL) {
        return TRUE;
    }

    for (cfil = filter; cfil != NULL; cfil = cfil->next) {

        /* stats record - only 2 fields apply */
        if (!flow) {
            if (cfil->field == OBDOMAIN) {
                if (mdComparison(obdomain, cfil->val[0], cfil->oper)) {
                    return TRUE;
                }
            } else if (cfil->field == COLLECTOR) {
                if (mdComparison(collector_id, cfil->val[0], cfil->oper)) {
                    return TRUE;
                }
            }
            continue;
        }

#if ENABLE_SKIPSET
        if (cfil->ipset) {
            if (cfil->oper == IN_LIST) {
                if (mdCompareIPSet(flow, cfil)) {
                    return TRUE;
                }
            } else if (cfil->oper == NOT_IN_LIST) {
                if (!mdCompareIPSet(flow, cfil)) {
                    return TRUE;
                }
            }
            continue;
        }
#endif
        switch (cfil->field) {
          case SIP_V4:
            if (mdComparison(flow->sourceIPv4Address, cfil->val[0],
                             cfil->oper))
            {
                return TRUE;
            }
            continue;
          case DIP_V4:
            if (mdComparison(flow->destinationIPv4Address, cfil->val[0],
                             cfil->oper))
            {
                return TRUE;
            }
            continue;
          case SPORT:
            if (mdComparison(flow->sourceTransportPort, cfil->val[0],
                             cfil->oper))
            {
                return TRUE;
            }
            continue;
          case DPORT:
            if (mdComparison(flow->destinationTransportPort, cfil->val[0],
                             cfil->oper))
            {
                return TRUE;
            }
            continue;
          case PROTOCOL:
            if (mdComparison(flow->protocolIdentifier, cfil->val[0],
                             cfil->oper))
            {
                return TRUE;
            }
            continue;
          case APPLICATION:
            if (mdComparison(flow->numAppLabel, cfil->val[0], cfil->oper)) {
                return TRUE;
            }
            continue;
          case SIP_V6:
            if (memcmp(flow->sourceIPv6Address, cfil->val, 16) == 0) {
                return TRUE;
            }
            continue;
          case DIP_V6:
            if (memcmp(flow->destinationIPv6Address, cfil->val, 16) == 0) {
                return TRUE;
            }
            continue;
          case ANY_IP6:
            if (memcmp(flow->sourceIPv6Address, cfil->val, 16) != 0) {
                if (memcmp(flow->destinationIPv6Address, cfil->val, 16) != 0) {
                    continue;
                }
            }
            return TRUE;
          case ANY_IP:
            if (!mdComparison(flow->sourceIPv4Address, cfil->val[0],
                              cfil->oper))
            {
                if (!mdComparison(flow->destinationIPv4Address,
                                  cfil->val[0], cfil->oper)) {
                    continue;
                }
            }
            return TRUE;
          case ANY_PORT:
            if (!mdComparison(flow->sourceTransportPort, cfil->val[0],
                                   cfil->oper))
            {
                if (!mdComparison(flow->destinationTransportPort,
                                  cfil->val[0], cfil->oper))
                {
                    continue;
                }
            }
            return TRUE;
          case OBDOMAIN:
            if (mdComparison(obdomain, cfil->val[0], cfil->oper)) {
                return TRUE;
            }
            continue;
          case VLAN:
            if (mdComparison(flow->vlanId, cfil->val[0], cfil->oper)) {
                return TRUE;
            }
            continue;
          case IPVERSION:
            if (flow->sourceIPv4Address || flow->destinationIPv4Address) {
                if (cfil->val[0] == 4) {
                    return TRUE;
                } else if (cfil->val[0] == 6) {
                    continue;
                }
            } else {
                if (cfil->val[0] == 4) {
                    continue;
                } else if (cfil->val[0] == 6) {
                    return TRUE;
                }
            }
            continue;
          case INGRESS:
            if (mdComparison(flow->ingressInterface, cfil->val[0], cfil->oper))
            {
                return TRUE;
            }
            continue;
          case EGRESS:
            if (mdComparison(flow->egressInterface, cfil->val[0], cfil->oper))
            {
                return TRUE;
            }
            continue;
          case COLLECTOR:
            if (mdComparison(collector_id, cfil->val[0], cfil->oper)) {
                return TRUE;
            }
            continue;
          default:
            g_log(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
                  "BAD KEYWORD in Filter .. Ignoring\n");
            continue;
        }
    }

    return FALSE;
}

/**
 * mdCollectionANDFilter
 *
 * loop through the filters and compare the filters expressions
 * to the given flow record.
 * Only one filter needs to FAIL to break out of the loop.
 *
 * @param filter - a list of filters
 * @param flow - the basic flow record
 * @param obdomain - the observation domain
 * @return TRUE if one of the filters passed
 */
static gboolean mdCollectionANDFilter(
    const md_filter_t   *filter,
    const mdRecord_t    *flow,
    uint32_t            obdomain,
    uint8_t             collector_id)
{

    const md_filter_t *cfil = NULL;

    if (filter == NULL) {
        return TRUE;
    }

    for (cfil = filter; cfil != NULL; cfil = cfil->next) {

        /* stats/dedup/dnsrr record - only 2 fields apply */
        if (!flow) {
            if (cfil->field == OBDOMAIN) {
                if (mdComparison(obdomain, cfil->val[0], cfil->oper)) {
                    continue;
                } else return FALSE;
            } else if (cfil->field == COLLECTOR) {
                if (mdComparison(collector_id, cfil->val[0], cfil->oper)) {
                    continue;
                } else return FALSE;
            }
            return FALSE;
        }

#if ENABLE_SKIPSET
        if (cfil->ipset) {
            if (cfil->oper == IN_LIST) {
                if (mdCompareIPSet(flow, cfil)) {
                    continue;
                }
            } else if (cfil->oper == NOT_IN_LIST) {
                if (!mdCompareIPSet(flow, cfil)) {
                    continue;
                }
            }
            return FALSE;
        }
#endif
        switch (cfil->field) {
          case SIP_V4:
            if (mdComparison(flow->sourceIPv4Address, cfil->val[0],
                             cfil->oper))
            {
                continue;
            }
            return FALSE;
          case DIP_V4:
            if (mdComparison(flow->destinationIPv4Address, cfil->val[0],
                             cfil->oper))
            {
                continue;
            }
            return FALSE;
          case SPORT:
            if (mdComparison(flow->sourceTransportPort, cfil->val[0],
                             cfil->oper))
            {
                continue;
            }
            return FALSE;
          case DPORT:
            if (mdComparison(flow->destinationTransportPort, cfil->val[0],
                             cfil->oper))
            {
                continue;
            }
            return FALSE;
          case PROTOCOL:
            if (mdComparison(flow->protocolIdentifier, cfil->val[0],
                             cfil->oper))
            {
                continue;
            }
            return FALSE;
          case APPLICATION:
            if (mdComparison(flow->numAppLabel, cfil->val[0], cfil->oper)) {
                continue;
            }
            return FALSE;
          case SIP_V6:
            if (memcmp(flow->sourceIPv6Address, cfil->val, 16) == 0) {
                continue;
            }
            return FALSE;
          case DIP_V6:
            if (memcmp(flow->destinationIPv6Address, cfil->val, 16) == 0) {
                continue;
            }
            return FALSE;
          case ANY_IP6:
            if (memcmp(flow->sourceIPv6Address, cfil->val, 16) != 0) {
                if (memcmp(flow->destinationIPv6Address, cfil->val, 16) != 0) {
                    return FALSE;
                }
            }
            continue;
          case ANY_IP:
            if (!mdComparison(flow->sourceIPv4Address, cfil->val[0],
                              cfil->oper))
            {
                if (!mdComparison(flow->destinationIPv4Address,
                                  cfil->val[0], cfil->oper)) {
                    return FALSE;
                }
            }
            continue;
          case ANY_PORT:
            if (!mdComparison(flow->sourceTransportPort, cfil->val[0],
                              cfil->oper))
            {
                if (!mdComparison(flow->destinationTransportPort,
                                  cfil->val[0], cfil->oper))
                {
                    return FALSE;
                }
            }
            continue;
          case OBDOMAIN:
            if (mdComparison(obdomain, cfil->val[0], cfil->oper)) {
                continue;
            }
            return FALSE;
          case VLAN:
            if (mdComparison(flow->vlanId, cfil->val[0], cfil->oper)) {
                continue;
            }
            return FALSE;
          case IPVERSION:
            if (flow->sourceIPv4Address || flow->destinationIPv4Address) {
                if (cfil->val[0] == 4) {
                    continue;
                } else if (cfil->val[0] == 6) {
                    return FALSE;
                }
            } else {
                if (cfil->val[0] == 4) {
                    return FALSE;
                } else if (cfil->val[0] == 6) {
                    continue;
                }
            }
            continue;
          case INGRESS:
            if (mdComparison(flow->ingressInterface, cfil->val[0], cfil->oper))
            {
                continue;
            }
            return FALSE;
          case EGRESS:
            if (mdComparison(flow->egressInterface, cfil->val[0], cfil->oper))
            {
                continue;
            }
            return FALSE;
          case COLLECTOR:
            if (mdComparison(collector_id, cfil->val[0], cfil->oper)) {
                continue;
            }
            return FALSE;
          default:
            g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO,
                  "BAD KEYWORD in Filter .. Ignoring\n");
            continue;
        }
    }

    return TRUE;
}

/**
 * mdFilter
 *
 * @param filter - a list of filters
 * @param flow - the basic flow record
 * @param obdomain - the observation domain
 * @param and_filter - true if filters should be ANDed
 * @return TRUE if one of the filters passed
 *
 */
gboolean mdFilter(
    const md_filter_t   *filter,
    const mdRecord_t    *flow,
    uint32_t            obdomain,
    gboolean            and_filter,
    uint8_t             collector_id)
{
    gboolean rc;

    if (and_filter) {
        rc = mdCollectionANDFilter(filter, flow, obdomain, collector_id);
    } else {
        rc = mdCollectionFilter(filter, flow, obdomain, collector_id);
    }

    return rc;
}



#ifdef HAVE_SPREAD
/**
 * mdSpreadExporterFilter
 *
 * loop through spread filters and add the groups
 * that should receive this flow.  If a group does not
 * have a filter, it automatically gets all flows.
 *
 */
int mdSpreadExporterFilter(
    const md_spread_filter_t *sf,
    const mdFullFlow_t       *md_flow,
    char                     **groups)
{

    const md_spread_filter_t *cfil;
    int num_groups = 0;
    mdRecord_t *flow = NULL;

    if (md_flow) {
        flow = md_flow->rec;
    }

    for (cfil = sf; cfil != NULL; cfil = cfil->next) {
        if (cfil->filterList == NULL) {
            /* there is no filter for this group so it gets everything */
            groups[num_groups] = cfil->group;
            num_groups++;
        } else {
            if (mdCollectionFilter(cfil->filterList, (mdRecord_t *)flow, 0, 0))
            {
                if (num_groups < 10) {
                    groups[num_groups] = cfil->group;
                    num_groups++;
                }
            }
        }
    }

    return num_groups;
}

#endif
