/**
 * @file mediator_core.h
 *
 * Yaf mediator for filtering, DNS deduplication, and other mediator-like
 * things
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2012-2017 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Emily Sarneso
 ** ------------------------------------------------------------------------
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
 *
 * Licensee hereby agrees to defend, indemnify, and hold harmless Carnegie
 * Mellon University, its trustees, officers, employees, and agents from
 * all claims or demands made against them (and any related losses,
 * expenses, or attorney's fees) arising out of, or relating to Licensee's
 * and/or its sub licensees' negligent use or willful misuse of or
 * negligent conduct or willful misconduct regarding the Software,
 * facilities, or other rights or assistance granted by Carnegie Mellon
 * University under this License, inluding, but not limited to, any
 * claims of product liability, personal injury, death, damage to
 * property, or violation of any laws or regulations.
 *
 * @OPENSOURCE_HEADER_END@
 * -----------------------------------------------------------
 */

#include "templates.h"
#include "mediator_inf.h"
#include "mediator_ctx.h"

typedef fbSession_t *(*md_sess_init_fn)(fbSession_t *,GError **, uint8_t, gboolean);

typedef struct mdTmplContext_st {
    uint16_t tid;
    uint16_t ie;
    size_t   num_elem;
} mdTmplContext_t;

fbInfoModel_t *mdInfoModel(void);

fbSession_t *mdInitExporterSession(
    fbSession_t  *session,
    GError       **err,
    uint8_t      stats,
    gboolean     metadata_export);

fbSession_t *mdInitExporterSessionDNSDedupOnly(
    fbSession_t  *session,
    GError       **err,
    uint8_t      stats,
    gboolean     metadata_export);

fbSession_t *mdInitExporterSessionDedupOnly(
    fbSession_t  *session,
    GError       **err,
    uint8_t      stats,
    gboolean     metadata_export);

fbSession_t *mdInitExporterSessionDNSRROnly(
    fbSession_t  *session,
    GError       **err,
    uint8_t      stats,
    gboolean     metadata_export);

fbSession_t *mdInitExporterSessionFlowOnly(
    fbSession_t  *session,
    GError       **err,
    uint8_t      stats,
    gboolean     metadata_export);

fbSession_t *mdInitExporterSessionSSLDedupOnly(
    fbSession_t     *session,
    GError           **err,
    uint8_t          stats,
    gboolean     metadata_export);

#if HAVE_SPREAD
fbSession_t *mdInitSpreadExporterSession(
    fbSession_t      *session,
    gboolean         dedup,
    GError           **err);
#endif
fbSession_t *mdInitCollectorSession(
    GError **err);

#if HAVE_SPREAD
gboolean mdSetSpreadExportTemplate(
    fBuf_t           *fbuf,
    fbSpreadParams_t *sp,
    uint16_t         tid,
    char             **groups,
    int              num_groups,
    GError           **err);
#endif

gboolean mdSetExportTemplate(
    fBuf_t *fbuf,
    uint16_t tid,
    GError **err);

void mdPrintIP4Address(
    char           *ipaddr_buf,
    uint32_t       ip);

gboolean mdOptionsCheck(
    fBuf_t         **fbuf,
    uint16_t       *tid,
    fbTemplate_t   **tmpl,
    GError         **err);

gboolean mdForwardOptions(
    mdContext_t    *ctx,
    fBuf_t         *fbuf,
    char           *colname,
    GError         **err);

gboolean mdIgnoreRecord(
    mdContext_t    *ctx,
    fBuf_t         *fbuf,
    GError         **err);

gboolean mdForwardDNSRR(
    mdContext_t *ctx,
    fBuf_t      *fbuf,
    GError      **err);

gboolean mdForwardDedup(
    mdContext_t *ctx,
    fBuf_t      *fbuf,
    GError      **err);

gboolean mdForwardDNSDedup(
    mdContext_t *ctx,
    fBuf_t      *fbuf,
    GError      **err);

gboolean mdForwardDedupCustom(
    mdContext_t      *ctx,
    mdTmplContext_t  *tctx,
    fBuf_t           *fbuf,
    GError           **err);

gboolean mdForwardSSLDedup(
    mdContext_t *ctx,
    fBuf_t      *fbuf,
    GError      **err);

gboolean mdForwardSSLCert(
    mdContext_t *ctx,
    fBuf_t      *fbuf,
    GError      **err);

uint16_t mdConvertToSiLK(
    mdRecord_t     *rec,
    uint16_t       tid);

gboolean mdForwardFlow(
    mdContext_t    *ctx,
    mdRecord_t     *rec,
    uint16_t       tid,
    GError         **err);

void mdDecodeAndClear(
    mdContext_t    *ctx,
    mdRecord_t     *rec);

void mdMainDecode(
    mdContext_t   *ctx,
    mdFullFlow_t  *md_flow);

void mdCleanUP(
    mdFullFlow_t  *md_flow);

void mdCleanUpSSLCert(
    yfNewSSLCertFlow_t *cert);

mdFieldList_t *mdCreateFieldList(
    mdAcceptFilterField_t    field);

void mdSetFieldListDecoratorJSON(
    mdFieldList_t *list);

void mdSetFieldListDecoratorCustom(
    mdFieldList_t *list,
    char          delimiter);

void mdSetFieldListDecoratorBasic(
    mdFieldList_t *list,
    char          delimiter);

mdFieldList_t *mdCreateBasicFlowList(
    gboolean payload);

mdFieldList_t *mdCreateIndexFlowList(void);

void attachHeadToDLL(
    mdDLL_t **head,
    mdDLL_t **tail,
    mdDLL_t *newEntry);

void detachThisEntryOfDLL(
    mdDLL_t **head,
    mdDLL_t **tail,
    mdDLL_t  *entryToDetach);

void detachHeadOfSLL(
    mdSLL_t **head,
    mdSLL_t **toRemove);

void attachHeadToSLL(
    mdSLL_t **head,
    mdSLL_t  *newEntry);
