/**
 * @file mediator_open.c
 *
 * All IPFIX collector functionality
 *
* -----------------------------------------------------------
 * Copyright (C) 2012-2017 Carnegie Mellon University. All Rights Reserved.
 * -----------------------------------------------------------
 * Authors: Emily Sarneso
 * -----------------------------------------------------------
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
 * University under this License, including, but not limited to, any
 * claims of product liability, personal injury, death, damage to
 * property, or violation of any laws or regulations.
 *
 * @OPENSOURCE_HEADER_END@
 * -----------------------------------------------------------
 */


#define LINE_BUF_SIZE 4096
/*RFC 1950 */
#define ZLIB_HEADER 0x9C78
/* RFC 1952 */
#define GZIP_HEADER 0x8B1F
#define SM_CHUNK 16384

#include <mediator/mediator_inf.h>
#include <mediator/mediator_core.h>
#include <mediator/mediator.h>
#include <mediator/mediator_filter.h>
#include <glob.h>
#include <sys/time.h>

#if SM_ENABLE_ZLIB
#include <zlib.h>
#endif

extern int md_quit;

static pthread_mutex_t global_listener_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_cond_t global_listener_cond = PTHREAD_COND_INITIALIZER;

static int num_collectors = 0;

struct mdFlowCollector_st {
    fbCollector_t     *collector;
    fbListener_t      *listener;
    FILE              *lfp;
    fbSession_t       *session;
    char              *name;
    char              *inspec;
    char              *move_dir;
    char              *decompress;
    GString           *fname_in;
    GString           *fname_lock;
    GError            *err;
    fbConnSpec_t      connspec;
    mdTransportType_t type;
    pthread_t         thread;
#if HAVE_SPREAD
    fbSpreadParams_t  spread;
#endif
    uint32_t          domain;
    uint16_t          poll_time;
    uint8_t           id;
    gboolean          active;
    gboolean          data;
    gboolean          restart;
    gboolean          std_in;
    gboolean          lockmode;
    gboolean          delete_files;
};


static void mdfBufFree(
    md_collect_node_t *collector)
{
    fBufFree(collector->fbuf);
    collector->fbuf = NULL;
}


void mdInterruptListeners(
    mdConfig_t        *cfg)
{
    md_collect_node_t *cnode = NULL;

    for (cnode = cfg->flowsrc; cnode; cnode = cnode->next) {
        if (cnode->active) {
#if HAVE_SPREAD
            if (cnode->coll->spread.session && cnode->coll->collector) {
                fbCollectorClose(cnode->coll->collector);
                continue;
            }
#endif
            if (cnode->coll->listener) {
                fbListenerInterrupt(cnode->coll->listener);
                pthread_cond_signal(&cnode->cond);
            }
        }
    }
    pthread_cond_signal(&global_listener_cond);
}

mdFlowCollector_t *mdNewFlowCollector(
    mdTransportType_t    mode,
    char                 *name)
{
    mdFlowCollector_t *collector;

    collector = g_slice_new0(mdFlowCollector_t);

    collector->type = mode;
    if (name) {
        collector->name = g_strdup(name);
    }

    memset(&collector->connspec, 0, sizeof(fbConnSpec_t));

    if (mode == TCP) {
        collector->connspec.transport = FB_TCP;
    } else if (mode == UDP) {
        collector->connspec.transport = FB_UDP;
    }

    num_collectors++;

    collector->id = num_collectors;

    return collector;

}

#if SM_ENABLE_ZLIB
static FILE *mdFileDecompress(
    FILE *src,
    const char *tmp_file_path)
{
    int ret;
    z_stream strm;
    unsigned int leftover;
    unsigned char in[SM_CHUNK];
    unsigned char out[SM_CHUNK];
    FILE *dst = NULL;
    int fd;
    char tmpname[SM_CHUNK];
    char temp_suffix[] = ".XXXXXX";

    /*allocate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    if (tmp_file_path) {
        snprintf(tmpname, SM_CHUNK, "%s/sm_def_tmp%s", tmp_file_path,
                 temp_suffix);
    } else if (getenv("TMPDIR")) {
        const char *env = getenv("TMPDIR");
        snprintf(tmpname, SM_CHUNK, "%s/sm_def_tmp%s", env, temp_suffix);
    } else {
        snprintf(tmpname, SM_CHUNK, "/tmp/sm_def_tmp%s", temp_suffix);
    }

    g_debug("Input file is compressed, attempting decompression ");

    fd = mkstemp(tmpname);
    if (fd == -1) {
        g_warning("Unable to open decompression tmp file '%s': %s",
                  tmpname, strerror(errno));
        return NULL;
    } else {
        dst = fdopen(fd, "wb+");
        if (!dst) {
            g_warning("Unable to open decompression tmp file '%s': %s",
                      tmpname, strerror(errno));
            return NULL;
        }
    }

    ret = inflateInit2(&strm, 16+MAX_WBITS);
    if (ret != Z_OK) {
        return NULL;
    }
    do {
        strm.avail_in = fread(in, 1, SM_CHUNK, src);
        if (ferror(src)) {
            (void)inflateEnd(&strm);
            return NULL;
        }

        if (strm.avail_in == 0) {
            break;
        }
        strm.next_in = in;

        do {
            strm.avail_out = SM_CHUNK;
            strm.next_out = out;

            ret = inflate(&strm, Z_NO_FLUSH);
            if (ret == Z_STREAM_ERROR) { return NULL; }
            leftover = SM_CHUNK - strm.avail_out;
            if (fwrite(out, 1, leftover, dst) != leftover || ferror(dst)) {
                (void)inflateEnd(&strm);
                return NULL;
            }
        } while(strm.avail_out == 0);

    } while (ret != Z_STREAM_END);

    (void)inflateEnd(&strm);

    rewind(dst);
    unlink(tmpname);

    return dst;
}
#endif


void mdCollectorSetInSpec(
    mdFlowCollector_t      *collector,
    char                   *inspec)
{
    collector->inspec = g_strdup(inspec);

    if (collector->type == TCP || collector->type == UDP) {
        collector->connspec.host = collector->inspec;
    }

}

void mdCollectorSetPollTime(
    mdFlowCollector_t      *collector,
    char                   *poll_time)
{
    collector->poll_time = atoi(poll_time);
    collector->type = DIRECTORY;
}

void mdCollectorSetMoveDir(
    mdFlowCollector_t      *collector,
    char                   *move_dir)
{

    collector->move_dir = g_strdup(move_dir);
}

void mdCollectorSetLockMode(
    mdFlowCollector_t      *collector,
    gboolean               lockmode)
{
    collector->lockmode = lockmode;
}

void mdCollectorSetPort(
    mdFlowCollector_t      *collector,
    char                   *port)
{
    collector->connspec.svc = g_strdup(port);
}

char *mdCollectorGetName(
    md_collect_node_t *node)
{
    return node->coll->name;
}

void mdCollectorSetDecompressDir(
    mdFlowCollector_t *collector,
    char              *path)
{
    collector->decompress = g_strdup(path);
}

uint8_t mdCollectorGetID(
    md_collect_node_t *node)
{
    return node->coll->id;
}

void mdCollectorSetDeleteFiles(
    mdFlowCollector_t        *collector,
    gboolean                 delete)
{
    collector->delete_files = delete;
}

void mdCollectorAddSpreadGroup(
    mdFlowCollector_t          *collector,
    char                     *group,
    int                      group_no)
{
#if HAVE_SPREAD
    if (group_no) {
        collector->spread.groups = (char **)g_renew(char *,
                                                    collector->spread.groups,
                                                    group_no + 2);
        collector->spread.groups[group_no] = g_strdup(group);
        /*collector->spread.groups[group_no+1] = '\0';*/
    } else {
        collector->spread.groups = (char **)g_new0(char *, 2);
        collector->spread.groups[0] = g_strdup(group);
        /*collector->spread.groups[1] = '\0';*/
    }
#endif
}

md_collect_node_t *mdCollectorGetNode(
    fBuf_t         *fbuf)
{
    fbCollector_t *collector = NULL;

    collector = fBufGetCollector(fbuf);

    return (md_collect_node_t *)fbCollectorGetContext(collector);
}

gboolean mdCollectorVerifySetup(
    mdFlowCollector_t       *collector,
    GError                  **err)
{
    switch (collector->type) {
      case SPREAD:
#if HAVE_SPREAD
        if (collector->inspec == NULL) {
            fprintf(stderr, "Missing DAEMON name for SPREAD collector %d.\n",
                    num_collectors+1);
            return FALSE;
        }
#endif
        break;
      case UDP:
      case TCP:
        if (!collector->connspec.svc) {
            collector->connspec.svc = g_strdup_printf("18000");
        }
        break;
      case FILEHANDLER:
        if (collector->inspec == NULL) {
            fprintf(stderr, "No input specificier.\n");
            return FALSE;
        }
        break;
      case DIRECTORY:
        if (collector->inspec == NULL) {
            fprintf(stderr, "No input specificier.\n");
            return FALSE;
        }
        if (!collector->move_dir && !collector->delete_files) {
            fprintf(stderr, "Error: Either MOVE or DELETE must be present "
                    "in DIRECTORY COLLECTOR block.\n");
            return FALSE;
        }
      default:
        break;
    }

    if (!collector->name) {
        collector->name = g_strdup_printf("C%d", collector->id);
    }

    return TRUE;
}

/**
 * mdFlowSourceClose
 *
 * close the file we were reading
 *
 */
static void mdFlowSourceClose(
    mdFlowCollector_t *collector)
{

    if (collector->lfp) {
        fclose(collector->lfp);
        collector->lfp = NULL;
    }

}


/**
 * mdFindListener
 *
 *
 */
md_collect_node_t *mdCollectorFindListener(
    md_collect_node_t *collector,
    fbListener_t      *listener)
{
    md_collect_node_t *cnode = NULL;


    for (cnode = collector; cnode; cnode = cnode->next) {
        if (cnode->coll->listener == listener) {
            cnode->active = TRUE;
            return cnode;
        }
    }

    return NULL;
}

/**
 * mdCollectorOpenFile
 *
 * open an IPFIX file to read
 *
 */
static fBuf_t *mdCollectorOpenFile(
    mdFlowCollector_t *collector,
    const char        *path,
    GError            **err)
{
    fBuf_t            *buf;

    if (collector->lfp || collector->std_in) {
        /* file is already open - close it & done */
        mdFlowSourceClose(collector);
        return NULL;
    }

    if ((strlen(path) == 1) && path[0] == '-') {
        collector->collector = fbCollectorAllocFile(NULL, path, err);
        collector->std_in = TRUE;
    } else {
#if SM_ENABLE_ZLIB
        FILE *tmp = fopen(path, "rb");
        if (tmp) {
            uint16_t header = 0;
            fread(&header, 1, 2, tmp);
            if ((header == ZLIB_HEADER) || (header == GZIP_HEADER)) {
                rewind(tmp);
                collector->lfp = mdFileDecompress(tmp, collector->decompress);
                fclose(tmp);
            } else {
                fclose(tmp);
                collector->lfp = fopen(path, "rb");
            }
        } else {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                        "Can not open file %s for reading", path);
            return NULL;
        }
#else
        collector->lfp = fopen(path, "rb");
#endif
        if ( collector->lfp == NULL ) {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                        "Can not open file %s for reading", path);
            return NULL;
        }

        collector->collector = fbCollectorAllocFP(NULL, collector->lfp);

    }

    if ( collector->collector == NULL ) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                    "Error creating the collector");
        return NULL;
    }


    collector->session = mdInitCollectorSession(err);

    if (collector->session == NULL) {
        return NULL;
    }

    buf = fBufAllocForCollection(collector->session, collector->collector);

    return buf;
}

/**
 * mdCollectorMoveFile
 *
 * move a file once we are done with it
 *
 */
static gboolean mdCollectorMoveFile(
    char *file,
    char *new_dir,
    GError **err)
{

    GString *new_file = NULL;
    char *filename;

    filename = g_strrstr(file, "/");

    new_file = g_string_new("");

    g_string_append_printf(new_file, "%s", new_dir);
    g_string_append_printf(new_file, "%s", filename);

    if (g_rename(file, new_file->str) != 0) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO, "Unable to move file "
                    "to %s", new_file->str);
        return FALSE;
    }

    g_string_free(new_file, TRUE);

    return TRUE;
}

/**
 * mdCollectorFileNext
 *
 * this does the polling for new files in a given directory
 *
 */
static void *mdCollectorFileNext(
    void             *data)
{
    md_collect_node_t  *node = (md_collect_node_t *)data;
    mdFlowCollector_t  *collector = node->coll;
    glob_t             gbuf;
    unsigned int       i;
    int                grc;
    gboolean           error = FALSE;

    while (!md_quit) {

        grc = glob(collector->inspec, 0, NULL, &gbuf);

        if (grc == GLOB_NOSPACE) {
            g_set_error(&collector->err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                        "Out of memory: glob allocation failure");
            return NULL;
        } else if (grc == GLOB_NOMATCH) {

            gbuf.gl_pathc = 0;
            gbuf.gl_pathv = NULL;
        }

        /* Iterate over paths */

        for (i = 0; i < gbuf.gl_pathc; i++) {

            collector->fname_in = g_string_new(gbuf.gl_pathv[i]);

            if (!g_file_test(collector->fname_in->str, G_FILE_TEST_IS_REGULAR)) {
                continue;
            }

            if (!strcmp(".lock", collector->fname_in->str +
                        strlen(collector->fname_in->str) - 5))
            {
                continue;
            }

            if (!collector->fname_lock) collector->fname_lock = g_string_new("");
            g_string_printf(collector->fname_lock, "%s.lock", collector->fname_in->str);

            if (g_file_test(collector->fname_lock->str, G_FILE_TEST_IS_REGULAR)) {
                /* file is locked */
                continue;
            }

            pthread_mutex_lock(&node->mutex);
            node->fbuf = mdCollectorOpenFile(collector,
                                             collector->fname_in->str,
                                             &collector->err);

            if (!node->fbuf) {
                pthread_mutex_unlock(&node->mutex);
                error = TRUE;
                break;
            }
            node->coll->data = TRUE;
            node->stats->files++;

            /* signal to main thread we have a file */
            pthread_mutex_lock(&global_listener_mutex);
            pthread_cond_signal(&global_listener_cond);
            pthread_mutex_unlock(&global_listener_mutex);

            while (node->fbuf) {
               pthread_cond_wait(&node->cond, &node->mutex);
            }

            pthread_mutex_unlock(&node->mutex);

        }

        if (error) {
            break;
        }

        sleep(collector->poll_time);
    }

    if (collector->fname_lock) {
        g_string_free(collector->fname_lock, TRUE);
        collector->fname_lock = NULL;
    }

    collector->active = FALSE;
    node->active = FALSE;
    pthread_mutex_lock(&global_listener_mutex);
    pthread_cond_signal(&global_listener_cond);
    pthread_mutex_unlock(&global_listener_mutex);

    /* this should run forever! */
    return NULL;
}

#if HAVE_SPREAD
/**
 * mdCollectorInitSpread
 *
 * subscribe to the spread daemon for a group(s)
 *
 */
static fBuf_t *mdCollectorInitSpread(
    mdConfig_t            *md,
    mdFlowCollector_t     *collector,
    GError                **err)
{
    fBuf_t          *fbuf = NULL;

    collector->session = mdInitCollectorSession(err);

    if (collector->session == NULL) {
        return NULL;
    }

    collector->spread.session = collector->session;

    collector->spread.daemon = collector->inspec;

    collector->collector = fbCollectorAllocSpread(0, &(collector->spread),
                                                  err);

    if (collector->collector == NULL) {
        return NULL;
    }

    fbuf = fBufAllocForCollection(collector->session, collector->collector);

    return fbuf;
}

#endif

/**
 * mdCollectorOpenListener
 *
 *
 */
static void *mdCollectorOpenListener(
    void   *data)
{
    md_collect_node_t *node = (md_collect_node_t *)data;
    mdFlowCollector_t *collector = node->coll;

    if (collector->type == UDP) {
        if (!fbListenerGetCollector(collector->listener,
                                    &collector->collector,
                                    &collector->err))
        {

            return NULL;
        }
        fbCollectorSetUDPMultiSession(collector->collector, TRUE);
        fbCollectorManageUDPStreamByPort(collector->collector, TRUE);
    }

    while (!md_quit) {

        pthread_mutex_lock(&node->mutex);
        node->fbuf = NULL;
        node->fbuf = fbListenerWait(collector->listener, &collector->err);
        if (md_quit) {
            g_clear_error(&collector->err);
            pthread_mutex_unlock(&node->mutex);
            /* exit immediately if interrupted*/
            break;
        }
        if (node->fbuf) {
            node->coll->data = TRUE;
            fBufSetAutomaticMode(node->fbuf, FALSE);
        }
        /* signal to main thread that we have an active fbuf */
        pthread_mutex_lock(&global_listener_mutex);
        pthread_cond_signal(&global_listener_cond);
        pthread_mutex_unlock(&global_listener_mutex);

        pthread_cond_wait(&node->cond, &node->mutex);
        pthread_mutex_unlock(&node->mutex);

    }
    node->active = FALSE;
    collector->active = FALSE;

    return NULL;
}


/**
 * mdCollectorPrepareFBuf
 *
 *
 */
static gboolean mdCollectorPrepareFBuf(
    mdConfig_t          *cfg,
    fBuf_t              *fbuf,
    mdFlowCollector_t   *collector,
    GError              **err)
{
    if (collector->type == UDP || collector->type == TCP ||
        collector->type == SPREAD)
    {
        fBufSetAutomaticMode(fbuf, FALSE);
    } else if (collector->type == FILEHANDLER) {
        pthread_mutex_lock(&cfg->log_mutex);
        g_message("%s: Opening file: %s", collector->name, collector->inspec);
        pthread_mutex_unlock(&cfg->log_mutex);
    } else if (collector->type == DIRECTORY) {
        pthread_mutex_lock(&cfg->log_mutex);
        g_message("%s: Opening file: %s", collector->name,
                  collector->fname_in->str);
        pthread_mutex_unlock(&cfg->log_mutex);
    }

    if (!fBufSetInternalTemplate(fbuf, YAF_SILK_FLOW_TID, err)) {
        return FALSE;
    }

    return TRUE;
}


/**
 * mdCollectorsInit
 *
 * open a TCP or UDP IPFIX listener via fixbuf or open a file
 *
 */
gboolean mdCollectorsInit(
    mdConfig_t            *md,
    md_collect_node_t     *collector,
    GError                **err)
{
    md_collect_node_t *cnode = NULL;


    for (cnode = collector; cnode; cnode = cnode->next) {

        if (cnode->coll->type == TCP || cnode->coll->type == UDP) {

            cnode->coll->session = mdInitCollectorSession(err);

            if (cnode->coll->session == NULL) {
                return FALSE;
            }

            cnode->coll->listener = fbListenerAlloc(&(cnode->coll->connspec),
                                                    cnode->coll->session,
                                                    mdListenerConnect, NULL,
                                                    err);

            if (cnode->coll->listener == NULL) {
                return FALSE;
            }

            pthread_mutex_init(&cnode->mutex, NULL);
            pthread_cond_init(&cnode->cond, NULL);
        } else if (cnode->coll->type == FILEHANDLER) {
            cnode->fbuf = mdCollectorOpenFile(cnode->coll, cnode->coll->inspec, err);
            if (cnode->fbuf == NULL) {
                return FALSE;
            }
            /* set active here because we don't start up a thread for files */
            cnode->active = TRUE;
            cnode->coll->data = TRUE;
            pthread_mutex_init(&cnode->mutex, NULL);
            pthread_cond_init(&cnode->cond, NULL);
        } else if (cnode->coll->type == SPREAD) {
#if HAVE_SPREAD
            cnode->coll->listener = (fbListener_t *)mdCollectorInitSpread(md,
                                                               cnode->coll, err);
            if (cnode->coll->listener == NULL) {
                return FALSE;
            }

            pthread_mutex_init(&cnode->mutex, NULL);
            pthread_cond_init(&cnode->cond, NULL);
#endif
        } else if (cnode->coll->type == DIRECTORY) {
            pthread_mutex_init(&cnode->mutex, NULL);
            pthread_cond_init(&cnode->cond, NULL);
        }

        cnode->stats = g_slice_new0(md_stats_t);
    }

    return TRUE;

}

static int mdOpenCollectors(
    md_collect_node_t *collector)
{
    md_collect_node_t *cnode = NULL;
    int active = 0;

    for (cnode = collector; cnode; cnode = cnode->next) {
        if (cnode->active) {
            active++;
        }
    }

    return active;
}

static gboolean mdCollectFBuf(
    mdContext_t       *ctx,
    md_collect_node_t *collector,
    GError            **err)
{
    uint16_t          tid;
    mdRecord_t        ipfixFullFlow;
    size_t            length;
    fbSession_t       *session;
    gboolean          reset, rv, rc;
    fbTemplate_t      *tmpl = NULL;
    mdTmplContext_t   *tmpl_ctx = NULL;

    rv = TRUE;

    length = sizeof(ipfixFullFlow);

    reset = FALSE;

    if (collector->coll->data == FALSE) {
        /* no data yet - don't call mdOptionsCheck */
        return TRUE;
    }

    if (!mdCollectorPrepareFBuf(ctx->cfg,collector->fbuf,collector->coll,err))
    {
        return FALSE;
    }

    /* set the current collector's name */
    ctx->cfg->collector_name = collector->coll->name;
    ctx->cfg->collector_id = collector->coll->id;

    while (1) {
        if (mdOptionsCheck(&(collector->fbuf), &tid, &tmpl, err)) {
            if (tid != 0) {
                ctx->stats->recvd_stats++;
                collector->stats->recvd_stats++;
                pthread_mutex_lock(&ctx->cfg->log_mutex);
                if (!mdForwardOptions(ctx, collector->fbuf,
                                      mdCollectorGetName(collector), err))
                {
                    g_warning("Error Forwarding Options:");
                    g_warning("Error: %s", (*err)->message);
                    rv = FALSE;
                    pthread_mutex_unlock(&ctx->cfg->log_mutex);
                    goto end;
                }

                pthread_mutex_unlock(&ctx->cfg->log_mutex);
            } else {
                if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_IPFIX)) {
                    pthread_mutex_lock(&ctx->cfg->log_mutex);
                    g_warning("%s: Ignoring Packet: %s", collector->coll->name,
                              (*err)->message);
                    pthread_mutex_unlock(&ctx->cfg->log_mutex);
                    collector->fbuf = NULL;
                } else if (g_error_matches(*err, FB_ERROR_DOMAIN,
                                           FB_ERROR_NLREAD))
                {
                    pthread_mutex_lock(&ctx->cfg->log_mutex);
                    g_warning("%s: Ignoring Connection: %s",
                              collector->coll->name, (*err)->message);
                    pthread_mutex_unlock(&ctx->cfg->log_mutex);
                    collector->fbuf = NULL;
                } else if (g_error_matches(*err, MD_ERROR_DOMAIN,
                                           MD_ERROR_TMPL))
                {
                    pthread_mutex_lock(&ctx->cfg->log_mutex);
                    mdIgnoreRecord(ctx, collector->fbuf, err);
                    g_warning("%s: Ignoring Options Record: %s",
                              collector->coll->name, (*err)->message);

                    pthread_mutex_unlock(&ctx->cfg->log_mutex);
                    g_clear_error(err);
                    continue;
                }
                g_clear_error(err);
                collector->coll->data = FALSE;
                goto end;
            }
            continue;
        } else {
            if (collector->fbuf == NULL) {
                pthread_mutex_lock(&ctx->cfg->log_mutex);
                if (!(g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_EOF))) {
                    g_warning("%s: Closing Connection: %s",
                              collector->coll->name, (*err)->message);
                } else {
                   g_message("%s: Closing Connection: %s",
                             collector->coll->name, (*err)->message);
                }
                if (collector->coll->type == SPREAD) {
                    collector->coll->listener = NULL;
                    g_message("%s: Retrying connection", collector->coll->name);
                }
                collector->coll->data = FALSE;
                pthread_mutex_unlock(&ctx->cfg->log_mutex);
                g_clear_error(err);
                rv = TRUE;
                reset = TRUE;
                break;
            }
        }

        pthread_mutex_lock(&ctx->cfg->log_mutex);

        session = fBufGetSession(collector->fbuf);
        ctx->cfg->current_domain = fbSessionGetDomain(session);

        tmpl_ctx = fbTemplateGetContext(tmpl);

        if (tmpl_ctx) {
            rc = mdForwardDedupCustom(ctx, tmpl_ctx, collector->fbuf, err);
            if (!rc) {
                g_warning("%s: Error Forwarding DEDUP Rec:",
                          collector->coll->name);
                g_warning("Error: %s", (*err)->message);
                rv = FALSE;
                pthread_mutex_unlock(&ctx->cfg->log_mutex);
                goto end;
            }
            collector->stats->nonstd_flows++;
            ctx->stats->nonstd_flows++;
            pthread_mutex_unlock(&ctx->cfg->log_mutex);
            continue;
        } else if ((tid & 0xFFF0) == MD_DNS_OUT) {
            rc = mdForwardDNSDedup(ctx, collector->fbuf, err);
            if (!rc) {
                g_warning("%s: Error Forwarding DNS Dedup Rec:",
                          collector->coll->name);
                g_warning("Error: %s", (*err)->message);
                rv = FALSE;
                pthread_mutex_unlock(&ctx->cfg->log_mutex);
                goto end;
            }
            collector->stats->nonstd_flows++;
            ctx->stats->nonstd_flows++;
            pthread_mutex_unlock(&ctx->cfg->log_mutex);
            continue;
        } else if ((tid & 0xF0F1) == MD_DNSRR) {
            rc = mdForwardDNSRR(ctx, collector->fbuf, err);
            if (!rc) {
                g_warning("%s: Error Forwarding DNS RR Rec:",
                          collector->coll->name);
                g_warning("Error: %s", (*err)->message);
                rv = FALSE;
                pthread_mutex_unlock(&ctx->cfg->log_mutex);
                goto end;
            }
            collector->stats->nonstd_flows++;
            ctx->stats->nonstd_flows++;
            pthread_mutex_unlock(&ctx->cfg->log_mutex);
            continue;
        } else if (tid == MD_SSL_TID) {
            rc = mdForwardSSLDedup(ctx, collector->fbuf, err);
            if (!rc) {
                g_warning("%s: Error Forwarding SSL DEDUP Rec:",
                          collector->coll->name);
                g_warning("Error: %s", (*err)->message);
                rv = FALSE;
                pthread_mutex_unlock(&ctx->cfg->log_mutex);
                goto end;
            }
            collector->stats->nonstd_flows++;
            ctx->stats->nonstd_flows++;
            pthread_mutex_unlock(&ctx->cfg->log_mutex);
            continue;
        } else if ((tid & 0xFFF8) == MD_DEDUP_TID) {
            rc = mdForwardDedup(ctx, collector->fbuf, err);
            if (!rc) {
                g_warning("%s: Error Forwarding DEDUP Rec:",
                          collector->coll->name);
                g_warning("Error: %s", (*err)->message);
                rv = FALSE;
                pthread_mutex_unlock(&ctx->cfg->log_mutex);
                goto end;
            }
            collector->stats->nonstd_flows++;
            ctx->stats->nonstd_flows++;
            pthread_mutex_unlock(&ctx->cfg->log_mutex);
            continue;
        } else if (tid == YAF_NEW_SSL_CERT_TID) {
            rc = mdForwardSSLCert(ctx, collector->fbuf, err);
            if (!rc) {
                g_warning("%s: Error Forwarding SSL CERT Rec:",
                          collector->coll->name);
                g_warning("Error: %s", (*err)->message);
                rv = FALSE;
                pthread_mutex_unlock(&ctx->cfg->log_mutex);
                goto end;
            }
            collector->stats->nonstd_flows++;
            ctx->stats->nonstd_flows++;
            pthread_mutex_unlock(&ctx->cfg->log_mutex);
            continue;
        }

        rc = fBufNext(collector->fbuf, (uint8_t *)&ipfixFullFlow, &length,
                      err);

        if (FALSE == rc) {
            if (!(g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_EOM)))
            {
                mdfBufFree(collector);
                g_warning("Error Receiving Flow %s", (*err)->message);
                reset = TRUE;
                rv = FALSE;
                pthread_mutex_unlock(&ctx->cfg->log_mutex);
                collector->coll->data = FALSE;
                break;
            }
            g_clear_error(err);
            rv = TRUE;
            collector->coll->data = FALSE;
            pthread_mutex_unlock(&ctx->cfg->log_mutex);
            break;
        }
        ctx->stats->recvd_flows++;


        if (ipfixFullFlow.flowEndMilliseconds > ctx->cfg->ctime) {
            ctx->cfg->ctime = ipfixFullFlow.flowEndMilliseconds;
        }

        if (collector->filter) {
            rc = mdFilter(collector->filter, &ipfixFullFlow,
                          ctx->cfg->current_domain,
                          collector->and_filter, 0);

            if (rc == FALSE) {
                ctx->stats->recvd_filtered++;
                collector->stats->recvd_filtered++;
                mdDecodeAndClear(ctx, &ipfixFullFlow);
                pthread_mutex_unlock(&ctx->cfg->log_mutex);
                continue;
            }
        }

        /* only count flows that the collector actually receives */
        collector->stats->recvd_flows++;

        if (!mdForwardFlow(ctx, &ipfixFullFlow, tid, err)) {
            g_warning("Error Forwarding Flow...");
            g_warning("Error: %s", (*err)->message);
            pthread_mutex_unlock(&ctx->cfg->log_mutex);
            rv = FALSE;
            goto end;
        }

        pthread_mutex_unlock(&ctx->cfg->log_mutex);
    }

    if (reset) {
        if (!mdExporterConnectionReset(ctx->cfg, err)) {
            pthread_mutex_lock(&ctx->cfg->log_mutex);
            g_warning("Error resetting %s\n", (*err)->message);
            pthread_mutex_unlock(&ctx->cfg->log_mutex);
            rv = FALSE;
        }
    }

  end:
    if (collector->coll->type == DIRECTORY) {
        /* Delete or move file for DIRECTORY collectors */
        if (collector->coll->lfp) {
            if (collector->coll->move_dir && collector->coll->fname_in) {
                if (!mdCollectorMoveFile(collector->coll->fname_in->str,
                                         collector->coll->move_dir, err))
                {
                    g_string_free(collector->coll->fname_in, TRUE);
                    return FALSE;
                }
            }
            mdFlowSourceClose(collector->coll);
            g_remove(collector->coll->fname_in->str);

            pthread_mutex_lock(&ctx->cfg->log_mutex);
            g_message("Deleting file %s", collector->coll->fname_in->str);
            pthread_mutex_unlock(&ctx->cfg->log_mutex);
            g_string_free(collector->coll->fname_in, TRUE);
        }
    }

    return rv;

}



gboolean mdCollectorWait(
    mdContext_t      *ctx,
    GError           **err)
{
    md_collect_node_t *clist = ctx->cfg->flowsrc;
    md_collect_node_t *cnode = NULL;
    gboolean active;
    int rv;
    int collectors = 0;
    struct timeval tp;
    struct timespec to;

    collectors = mdOpenCollectors(clist);

    if (!collectors) return FALSE;

    while (collectors && !md_quit) {
        active = FALSE;
        for (cnode = ctx->cfg->flowsrc; cnode; cnode = cnode->next) {
            if (cnode->active) {
                if (cnode->fbuf && cnode->coll->data) {
                    active = TRUE;
                    rv = pthread_mutex_trylock(&cnode->mutex);
                    if (rv != 0) continue;
                    if (!mdCollectFBuf(ctx, cnode, err)) {
                        pthread_cond_signal(&cnode->cond);
                        pthread_mutex_unlock(&cnode->mutex);
                        return FALSE;
                    }
                    if (cnode->coll->type == FILEHANDLER) {
                        cnode->active = FALSE;
                        cnode->coll->restart = TRUE;
                        collectors--;
                    }
                    pthread_cond_signal(&cnode->cond);
                    pthread_mutex_unlock(&cnode->mutex);
                }
            } else if (!cnode->coll->restart) {
                /* start this guy back up */
                pthread_mutex_lock(&ctx->cfg->log_mutex);
                g_warning("Collector \"%s\" Error: %s",
                          cnode->coll->name, cnode->coll->err->message);
                cnode->coll->restart = TRUE;
                g_clear_error(&cnode->coll->err);
                pthread_mutex_unlock(&ctx->cfg->log_mutex);
                if (!mdCollectorRestartListener(ctx->cfg, cnode, err)) {
                    pthread_mutex_lock(&ctx->cfg->log_mutex);
                    g_warning("Error restarting collector %s: %s",
                              cnode->coll->name, (*err)->message);
                    pthread_mutex_unlock(&ctx->cfg->log_mutex);
                    g_clear_error(err);
                    collectors--;
                }
            } else if (cnode->coll->err) {
                /* this collector is permanently inactive */
                pthread_mutex_lock(&ctx->cfg->log_mutex);
                g_warning("Could not restart collector %s: %s",
                          cnode->coll->name, cnode->coll->err->message);
                g_clear_error(&cnode->coll->err);
                g_warning("Collector \"%s\" is now inactive until program restart.",
                          cnode->coll->name);
                pthread_mutex_unlock(&ctx->cfg->log_mutex);
                collectors--;
            }
        }
        if (!active) {
            /* wait on listeners to collect something (timeout of 1 sec)*/
            gettimeofday(&tp, NULL);
            to.tv_sec = tp.tv_sec + 1;
            to.tv_nsec = tp.tv_usec * 1000;
            pthread_mutex_lock(&global_listener_mutex);
            pthread_cond_timedwait(&global_listener_cond, &global_listener_mutex, &to);
            pthread_mutex_unlock(&global_listener_mutex);
        }
    }

    return FALSE;
}


#if HAVE_SPREAD
static void *mdCollectorSpreadSubscribe(
    void *data)
{
    md_collect_node_t *node = (md_collect_node_t *)data;
    mdFlowCollector_t *collector = node->coll;
    fbTemplate_t      *tmpl = NULL;
    uint16_t          tid;
    int               restarts = 0;

    while (!md_quit) {

        pthread_mutex_lock(&node->mutex);

        if ((collector->listener == NULL) && (node->fbuf == NULL)) {
            /* Some type of error occurred (connection down?) */
            collector->restart = TRUE;
        }

        if (collector->restart) {
            /* try to connect to the spread daemon 10 times -
               after that forget it. */
            while (restarts < 10) {
                collector->listener = (fbListener_t *)mdCollectorInitSpread(NULL, collector,
                                                                            &collector->err);
                if (collector->listener) {
                    collector->restart = FALSE;
                    break;
                }
                sleep(30);
                restarts++;
                if (restarts == 5) {
                    collector->active = FALSE;
                    node->active = FALSE;
                    pthread_mutex_unlock(&node->mutex);
                    pthread_mutex_lock(&global_listener_mutex);
                    pthread_cond_signal(&global_listener_cond);
                    pthread_mutex_unlock(&global_listener_mutex);
                    return NULL;
                }
                g_clear_error(&collector->err);
            }
        }


        /* Spread is weird bc there is no listener. It basically hangs out
           in read until a message arrives, we don't want to use fBufNext
           because that will advance the buffer and we'll miss a record
           when we call fBufNext again */
        tmpl = fBufNextCollectionTemplate((fBuf_t *)node->coll->listener,
                                          &tid, &collector->err);

        if (!tmpl) {
            /* ignore eom */
            if (g_error_matches(collector->err, FB_ERROR_DOMAIN, FB_ERROR_EOM))
            {
                g_clear_error(&collector->err);
                pthread_mutex_unlock(&node->mutex);
                continue;
            } else if (g_error_matches(collector->err, FB_ERROR_DOMAIN,
                                       FB_ERROR_IO))
            {
                fBufFree((fBuf_t *)node->coll->listener);
                node->fbuf = NULL;
                pthread_mutex_unlock(&node->mutex);
                break;
            } else if (g_error_matches(collector->err, FB_ERROR_DOMAIN,
                                       FB_ERROR_CONN)) {
                fBufFree((fBuf_t *)node->coll->listener);
                node->fbuf = NULL;
                pthread_mutex_unlock(&node->mutex);
                break;
            }
        }

        node->fbuf = (fBuf_t *)node->coll->listener;
        node->coll->data = TRUE;
        if (md_quit) {
            /* exit immediately if interrupted*/
            break;
        }

        /* signal to main thread that we have an active fbuf */
        pthread_mutex_lock(&global_listener_mutex);
        pthread_cond_signal(&global_listener_cond);
        pthread_mutex_unlock(&global_listener_mutex);

        pthread_cond_wait(&node->cond, &node->mutex);
        pthread_mutex_unlock(&node->mutex);

    }

    collector->active = FALSE;
    node->active = FALSE;
    pthread_mutex_lock(&global_listener_mutex);
    pthread_cond_signal(&global_listener_cond);
    pthread_mutex_unlock(&global_listener_mutex);

    return NULL;
}
#endif

/**
 * mdCollectorRestartListener
 *
 */
gboolean mdCollectorRestartListener(
    mdConfig_t         *md,
    md_collect_node_t  *collector,
    GError             **err)
{
    md_collect_node_t *cnode = collector;

    if (cnode->active) {
        return TRUE;
    }

    if (cnode->coll->type == FILEHANDLER) {
        /* file is already open */
        return TRUE;
    }
    if (cnode->coll->type == DIRECTORY) {
        pthread_mutex_lock(&md->log_mutex);
        g_message("Restarting Directory Poller for %s",
                  cnode->coll->name);
        pthread_mutex_unlock(&md->log_mutex);
        cnode->coll->active = TRUE;
        if (pthread_create(&(cnode->coll->thread), NULL,
                           mdCollectorFileNext, cnode))
        {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                        "Couldn't open polling thread.");
            return FALSE;
        }
    } else if (cnode->coll->type == SPREAD) {
#if HAVE_SPREAD
        cnode->coll->active = TRUE;
        pthread_mutex_lock(&md->log_mutex);
        g_message("Restarting Spread Collector %s for Daemon %s",
                  cnode->coll->name, cnode->coll->inspec);
        pthread_mutex_unlock(&md->log_mutex);
        if (pthread_create(&(cnode->coll->thread), NULL,
                           mdCollectorSpreadSubscribe, cnode))
        {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                        "Couldn't open Spread Subscriber.");
            return FALSE;
        }
#endif
    } else {
        cnode->coll->active = TRUE;
        pthread_mutex_lock(&md->log_mutex);
        g_message("Restarting Listener for %s on %s:%s",
                  cnode->coll->name, cnode->coll->connspec.host,
                  cnode->coll->connspec.svc);
        pthread_mutex_unlock(&md->log_mutex);

        if (pthread_create(&(cnode->coll->thread), NULL,
                           mdCollectorOpenListener, cnode))
        {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                        "Couldn't open listening thread.");
            return FALSE;
        }

    }
    cnode->active = TRUE;

    return TRUE;
}



/**
 * mdCollectorStartListeners
 *
 */
gboolean mdCollectorStartListeners(
    mdConfig_t         *md,
    md_collect_node_t  *collector,
    GError             **err)
{
    md_collect_node_t *cnode = NULL;

    for (cnode = collector; cnode; cnode = cnode->next) {
        if (!cnode->active) {
            if (cnode->coll->type == FILEHANDLER) {
                /* file is already open */
                continue;
            }
            if (cnode->coll->type == DIRECTORY) {
                pthread_mutex_lock(&md->log_mutex);
                g_message("Starting Directory Poller for %s",
                          cnode->coll->name);
                pthread_mutex_unlock(&md->log_mutex);
                cnode->coll->active = TRUE;
                if (pthread_create(&(cnode->coll->thread), NULL,
                                   mdCollectorFileNext, cnode))
                {
                    g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                                "Couldn't open polling thread.");
                    return FALSE;
                }
            } else if (cnode->coll->type == SPREAD) {
#if HAVE_SPREAD
                cnode->coll->active = TRUE;
                pthread_mutex_lock(&md->log_mutex);
                g_message("Starting Spread Collector %s for Daemon %s",
                          cnode->coll->name, cnode->coll->inspec);
                pthread_mutex_unlock(&md->log_mutex);
                if (pthread_create(&(cnode->coll->thread), NULL,
                                   mdCollectorSpreadSubscribe, cnode))
                {
                    g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                                "Couldn't open Spread Subscriber.");
                    return FALSE;
                }
#endif
            } else {
                cnode->coll->active = TRUE;
                pthread_mutex_lock(&md->log_mutex);
                g_message("Starting Listener for %s on %s:%s",
                          cnode->coll->name, cnode->coll->connspec.host,
                          cnode->coll->connspec.svc);
                pthread_mutex_unlock(&md->log_mutex);
                if (pthread_create(&(cnode->coll->thread), NULL,
                                   mdCollectorOpenListener, cnode))
                {
                    g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                                "Couldn't open listening thread.");
                    return FALSE;
                }

            }
            cnode->active = TRUE;
        }
    }

    return TRUE;
}



/**
 * mdDestroyCollector
 *
 * remove the collector
 *
 */
static void mdDestroyCollector(
    mdFlowCollector_t *coll,
    gboolean          active)
{

#if HAVE_SPREAD
    int n = 0;
#endif

    if (coll->type == TCP || coll->type == UDP) {
        if (coll->session) {
            fbSessionFree(coll->session);
        }
    }

    if (coll->lfp) {
        mdFlowSourceClose(coll);
    }

    if (coll->inspec) {
        g_free(coll->inspec);
    }

    if (coll->decompress) {
        g_free(coll->decompress);
    }

    if (coll->type == TCP || coll->type == UDP) {
        g_free(coll->connspec.svc);
    }

    if (coll->move_dir) {
        g_free(coll->move_dir);
    }

    if (coll->active) {
        if (pthread_cancel(coll->thread)) {
            fprintf(stderr, "Error canceling %s collector thread\n", coll->name);
        }
    }

    /* if destroyed due to presence of command line options,
       calling pthread_join will cause segfault. */
    if (coll->type != FILEHANDLER && active) {
        pthread_join(coll->thread, NULL);
    }

    if (coll->name) {
        g_free(coll->name);
    }

#if HAVE_SPREAD
    if (coll->spread.session) {
        while (coll->spread.groups[n] && *coll->spread.groups[n]) {
            g_free(coll->spread.groups[n]);
            n++;
        }
        g_free(coll->spread.groups);
    }
#endif

}

static void mdCollectorFree(
    mdFlowCollector_t *collector)
{
    g_slice_free(mdFlowCollector_t, collector);
}


void mdCollectorDestroy(
    mdConfig_t    *cfg,
    gboolean      active)
{

    md_collect_node_t *cnode = NULL;
    gboolean do_once = FALSE;

    mdCollectorUpdateStats(cfg);

    for (cnode = cfg->flowsrc; cnode; cnode = cnode->next) {
        if (cnode->coll->active) {
            pthread_cond_signal(&cnode->cond);
        }
        mdDestroyCollector(cnode->coll, active);

        if (cnode->fbuf) {
            fBufFree(cnode->fbuf);
        }

        if (cnode->coll->type == TCP) {
            fbListenerFree(cnode->coll->listener);
        }

        pthread_cond_destroy(&cnode->cond);
        pthread_mutex_destroy(&cnode->mutex);

        /* if this is a shared filter - free the first time only */
        if (cfg->shared_filter && !do_once) {
            do_once = TRUE;
            if (cnode->filter) {
                md_filter_t *nnode = NULL;
                md_filter_t *fnode = cnode->filter;

                while (fnode) {
                    nnode = fnode->next;
                    detachHeadOfSLL((mdSLL_t **)&(cnode->filter),(mdSLL_t **)&fnode);
#if ENABLE_SKIPSET
                    if (fnode->ipset) {
                        skIPSetDestroy(&(fnode->ipset));
                    }
#endif
                    g_slice_free(md_filter_t, fnode);
                    fnode = nnode;
                }
#if ENABLE_SKIPSET
                skAppUnregister();
#endif
            }
        }
        mdCollectorFree(cnode->coll);
    }

    /* free md_collect_node_t */

}


void mdCollectorUpdateStats(
    mdConfig_t        *cfg)
{

    md_collect_node_t *cnode = NULL;
    char active[10];

    for (cnode = cfg->flowsrc; cnode; cnode = cnode->next) {
        if (cnode->active) {
            active[0] = '\0';
        } else {
            sprintf(active, "INACTIVE ");
        }
        if (cnode->stats == NULL) {
            continue;
        }
        if (cnode->coll->type == FILEHANDLER || cnode->coll->type == DIRECTORY)
        {
            g_message("%sCollector %s: %"PRIu64" flows, %"PRIu64" other flows, "
                      "%"PRIu64" stats, %"PRIu64
                      " filtered, %u files", active,
                      cnode->coll->name, cnode->stats->recvd_flows,
                      cnode->stats->nonstd_flows,
                      cnode->stats->recvd_stats, cnode->stats->recvd_filtered,
                      cnode->stats->files);
        } else if (cnode->coll->type == SPREAD) {
            g_message("%sCollector %s: %"PRIu64" flows, %"PRIu64" other flows, "
                      "%"PRIu64" stats, %"PRIu64
                      " filtered", active,
                      cnode->coll->name, cnode->stats->recvd_flows,
                      cnode->stats->nonstd_flows,
                      cnode->stats->recvd_stats, cnode->stats->recvd_filtered);
        } else {
            g_message("%sCollector %s: %"PRIu64" flows, %"PRIu64" other flows, "
                      "%"PRIu64" stats, %"PRIu64
                      " filtered, %d connections", active,
                      cnode->coll->name, cnode->stats->recvd_flows,
                      cnode->stats->nonstd_flows,
                      cnode->stats->recvd_stats, cnode->stats->recvd_filtered,
                      cnode->stats->restarts);
        }
    }
}
