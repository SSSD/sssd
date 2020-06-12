/*
    Copyright (C) 2016 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <talloc.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <sys/inotify.h>
#include <sys/time.h>

#include "util/inotify.h"
#include "util/util.h"

/* For parent directories, we want to know if a file was moved there or
 * created there
 */
#define PARENT_DIR_MASK (IN_CREATE | IN_MOVED_TO)

/* This structure is recreated if we need to rewatch the file and/or
 * directory
 */
struct snotify_watch_ctx {
    int inotify_fd;             /* The inotify_fd */
    struct tevent_fd *tfd;      /* Activity on the fd */

    struct snotify_ctx *snctx;  /* Pointer up to the main snotify struct */

    /* In case we're also watching the parent directory, otherwise -1.
     * We keep the variable here and not in snctx so that we're able
     * to catch even changes to the parent directory
     */
    int dir_wd;
    /* The file watch */
    int file_wd;
};

/* This is what we call when an event we're interested in arrives */
struct snotify_cb_ctx {
    snotify_cb_fn fn;
    const char *fn_name;
    uint32_t mask;
    void *pvt;
};

/* One instance of a callback. We hoard the inotify notifications
 * until timer fires in caught_flags
 */
struct snotify_dispatcher {
    struct tevent_timer *te;
    uint32_t caught_flags;
};

struct snotify_ctx {
    struct tevent_context *ev;

    /* The full path of the file we're watching,
     * its file and directory components */
    const char *filename;
    const char *dir_name;
    const char *base_name;

    /* Private pointer passed to the callback */
    struct snotify_cb_ctx cb;
    /* A singleton callback dispatcher */
    struct snotify_dispatcher *disp;

    /* Internal snotify flags */
    uint16_t snotify_flags;
    /* The caller might decide to batch the updates and receive
     * them all together with a delay
     */
    struct timeval delay;
    /* We keep the structure that actually does the work
     * separately to be able to reinitialize it when the
     * file is recreated or moved to the directory
     */
    struct snotify_watch_ctx *wctx;
};

struct flg2str {
    uint32_t flg;
    const char *str;
} flg_table[] = {
    { 0x00000001, "IN_ACCESS" },
    { 0x00000002, "IN_MODIFY" },
    { 0x00000004, "IN_ATTRIB" },
    { 0x00000008, "IN_CLOSE_WRITE" },
    { 0x00000010, "IN_CLOSE_NOWRITE" },
    { 0x00000020, "IN_OPEN" },
    { 0x00000040, "IN_MOVED_FROM" },
    { 0x00000080, "IN_MOVED_TO" },
    { 0x00000100, "IN_CREATE" },
    { 0x00000200, "IN_DELETE" },
    { 0x00000400, "IN_DELETE_SELF" },
    { 0x00000800, "IN_MOVE_SELF" },
    { 0x00002000, "IN_UNMOUNT" },
    { 0x00004000, "IN_Q_OVERFLOW" },
    { 0x00008000, "IN_IGNORED" },
    { 0x01000000, "IN_ONLYDIR" },
    { 0x02000000, "IN_DONT_FOLLOW" },
    { 0x04000000, "IN_EXCL_UNLINK" },
    { 0x20000000, "IN_MASK_ADD" },
    { 0x40000000, "IN_ISDIR" },
    { 0x80000000, "IN_ONESHOT" },
    { 0, NULL },
};

#if 0
static void debug_flags(uint32_t flags, const char *file)
{
    char msgbuf[1024];
    size_t total = 0;

    if (!DEBUG_IS_SET(SSSDBG_TRACE_LIBS)) {
        return;
    }

    for (int i = 0; flg_table[i].flg != 0; i++) {
        if (flags & flg_table[i].flg) {
            total += snprintf(msgbuf+total,
                              sizeof(msgbuf)-total,
                              "%s ", flg_table[i].str);
        }
    }

    if (total == 0) {
            snprintf(msgbuf, sizeof(msgbuf), "NONE\n");
    }
    DEBUG(SSSDBG_TRACE_LIBS, "Inotify event: %s on %s\n", msgbuf, file);
}
#endif

static void snotify_process_callbacks(struct tevent_context *ev,
                                      struct tevent_timer *te,
                                      struct timeval t,
                                      void *ptr)
{
    struct snotify_ctx *snctx;

    snctx = talloc_get_type(ptr, struct snotify_ctx);
    if (snctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Bad pointer\n");
        return;
    }

    snctx->cb.fn(snctx->filename,
                 snctx->disp->caught_flags,
                 snctx->cb.pvt);

    talloc_zfree(snctx->disp);
}

static struct snotify_dispatcher *create_dispatcher(struct snotify_ctx *snctx)
{
    struct snotify_dispatcher *disp;
    struct timeval tv;

    disp = talloc_zero(snctx, struct snotify_dispatcher);
    if (disp == NULL) {
        return NULL;
    }

    gettimeofday(&tv, NULL);
    tv.tv_sec += snctx->delay.tv_sec;
    tv.tv_usec += snctx->delay.tv_usec;

    DEBUG(SSSDBG_TRACE_FUNC,
          "Running a timer with delay %ld.%ld\n",
          (unsigned long) snctx->delay.tv_sec,
          (unsigned long) snctx->delay.tv_usec);

    disp->te = tevent_add_timer(snctx->ev, disp, tv,
                                snotify_process_callbacks,
                                snctx);
    if (disp->te == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to queue file update!\n");
        talloc_free(disp);
        return NULL;
    }

    return disp;
}

static struct snotify_dispatcher *get_dispatcher(struct snotify_ctx *snctx)
{
    if (snctx->disp != NULL) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "Reusing existing dispatcher\n");
        return snctx->disp;
    }

    return create_dispatcher(snctx);
}

static errno_t dispatch_event(struct snotify_ctx *snctx,
                              uint32_t ev_flags)
{
    struct snotify_dispatcher *disp;

    if ((snctx->cb.mask & ev_flags) == 0) {
        return EOK;
    }

    disp = get_dispatcher(snctx);
    if (disp == NULL) {
        return ENOMEM;
    }

    disp->caught_flags |= ev_flags;
    DEBUG(SSSDBG_TRACE_FUNC,
          "Dispatched an event with combined flags 0x%X\n",
          disp->caught_flags);

    snctx->disp = disp;
    return EOK;
}

static errno_t process_dir_event(struct snotify_ctx *snctx,
                                 const struct inotify_event *in_event)
{
    errno_t ret;

    DEBUG(SSSDBG_TRACE_ALL, "inotify name: %s\n", in_event->name);
    if (in_event->len == 0 \
            || strcmp(in_event->name, snctx->base_name) != 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "Not interested in %s\n", in_event->name);
        return EOK;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "received notification for watched file [%s] under %s\n",
          in_event->name, snctx->dir_name);

    /* file the event for the file to see if the caller is interested in it */
    ret = dispatch_event(snctx, in_event->mask);
    if (ret == EOK) {
        /* Tells the outer loop to re-initialize flags once the loop is finished.
         * However, finish reading all the events first to make sure we don't
         * miss any
         */
        return EAGAIN;
    }

    return ret;
}

static errno_t process_file_event(struct snotify_ctx *snctx,
                                  const struct inotify_event *in_event)
{
    if (in_event->mask & IN_IGNORED) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Will reopen moved or deleted file %s\n", snctx->filename);
        /* Notify caller of the event, don't quit */
        return EAGAIN;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "received notification for watched file %s\n", snctx->filename);

    return dispatch_event(snctx, in_event->mask);
}

static errno_t snotify_rewatch(struct snotify_ctx *snctx);

static void snotify_internal_cb(struct tevent_context *ev,
                                struct tevent_fd *fde,
                                uint16_t flags,
                                void *data)
{
    char ev_buf[sizeof(struct inotify_event) + PATH_MAX];
    const char *ptr;
    const struct inotify_event *in_event;
    struct snotify_ctx *snctx;
    ssize_t len;
    errno_t ret;
    bool rewatch = false;

    snctx = talloc_get_type(data, struct snotify_ctx);
    if (snctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Bad pointer\n");
        return;
    }

    while (1) {
        len = read(snctx->wctx->inotify_fd, ev_buf, sizeof(ev_buf));
        if (len == -1) {
            ret = errno;
            if (ret != EAGAIN) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Cannot read inotify_event [%d]: %s\n",
                      ret, strerror(ret));
            } else {
                DEBUG(SSSDBG_TRACE_INTERNAL, "All inotify events processed\n");
            }
            break;
        }

        if ((size_t) len < sizeof(struct inotify_event)) {
            /* Did not even read the required amount of data, move on.. */
            continue;
        }

        for (ptr = ev_buf;
             ptr < ev_buf + len;
             ptr += sizeof(struct inotify_event) + in_event->len) {

            in_event = (const struct inotify_event *) ptr;

#if 0
            debug_flags(in_event->mask, in_event->name);
#endif

            if (snctx->wctx->dir_wd == in_event->wd) {
                ret = process_dir_event(snctx, in_event);
            } else if (snctx->wctx->file_wd == in_event->wd) {
                ret = process_file_event(snctx, in_event);
            } else {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Unknown watch %d\n", in_event->wd);
                ret = EOK;
            }

            if (ret == EAGAIN) {
                rewatch = true;
                /* Continue with the loop and read all the events from
                 * this descriptor first, then rewatch when done
                 */
            } else if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Failed to process inotify event\n");
            }
        }
    }

    if (rewatch) {
        ret = snotify_rewatch(snctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to re-set watch");
        }
    }
}

static int watch_ctx_destructor(void *memptr)
{
    struct snotify_watch_ctx *wctx;

    wctx = talloc_get_type(memptr, struct snotify_watch_ctx);
    if (wctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Bad pointer\n");
        return 1;
    }

    /* We don't need to close the watches explicitly. man 7 inotify says:
     *   When all file descriptors referring to an inotify instance
     *   have been closed (using close(2)), the underlying object
     *   and its resources are freed for reuse by the kernel; all
     *   associated watches are automatically freed.
     */
    if (wctx->inotify_fd != -1) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Closing inotify fd %d\n", wctx->inotify_fd);
        close(wctx->inotify_fd);
    }

    return 0;
}

static errno_t resolve_filename(struct snotify_ctx *snctx,
                                const char *filename,
                                char *resolved,
                                size_t resolved_size)
{
    /* NOTE: The code below relies in the GNU extensions for realpath,
     * which will store in 'resolved' the prefix of 'filename' that does
     * not exists if realpath call fails and errno is set to ENOENT */
    if (realpath(filename, resolved) == NULL) {
        char fcopy[PATH_MAX + 1];
        char *p;
        struct stat st;

        if (errno != ENOENT) {
            return errno;
        }

        /* Check if the unique missing component is the basename. The
         * dirname must exist to be notified watching the parent dir. */
        strncpy(fcopy, filename, sizeof(fcopy) - 1);
        fcopy[PATH_MAX] = '\0';

        p = dirname(fcopy);
        if (p == NULL) {
            return EIO;
        }

        if (stat(p, &st) == -1) {
            return errno;
        }

        /* The basedir exist, check the caller requested to watch it.
         * Otherwise return error as never will be notified. */

        if ((snctx->snotify_flags & SNOTIFY_WATCH_DIR) == 0) {
            return ENOENT;
        }
    }

    return EOK;
}

static errno_t copy_filenames(struct snotify_ctx *snctx,
                              const char *filename)
{
    char *p;
    char resolved[PATH_MAX + 1];
    char fcopy[PATH_MAX + 1];
    errno_t ret;

    ret = resolve_filename(snctx, filename, resolved, sizeof(resolved));
    if (ret != EOK) {
		return ret;
    }

    strncpy(fcopy, resolved, sizeof(fcopy) - 1);
    fcopy[PATH_MAX] = '\0';

    p = dirname(fcopy);
    if (p == NULL) {
        return EIO;
    }

    snctx->dir_name = talloc_strdup(snctx, p);
    if (snctx->dir_name == NULL) {
        return ENOMEM;
    }

    strncpy(fcopy, resolved, sizeof(fcopy) - 1);
    fcopy[PATH_MAX] = '\0';

    p = basename(fcopy);
    if (p == NULL) {
        return EIO;
    }

    snctx->base_name = talloc_strdup(snctx, p);
    if (snctx->base_name == NULL) {
        return ENOMEM;
    }

    snctx->filename = talloc_strdup(snctx, resolved);
    if (snctx->filename == NULL) {
        return ENOMEM;
    }

    return EOK;
}

static struct snotify_watch_ctx *snotify_watch(struct snotify_ctx *snctx,
                                               uint32_t mask)
{
    struct snotify_watch_ctx *wctx;
    errno_t ret;

    wctx = talloc_zero(snctx, struct snotify_watch_ctx);
    if (wctx == NULL) {
        return NULL;
    }
    wctx->inotify_fd = -1;
    wctx->dir_wd = -1;
    wctx->file_wd = -1;
    wctx->snctx = snctx;
    talloc_set_destructor((TALLOC_CTX *)wctx, watch_ctx_destructor);

    wctx->inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (wctx->inotify_fd == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
               "inotify_init1 failed: %d: %s\n", ret, strerror(ret));
        goto fail;
    }
    DEBUG(SSSDBG_TRACE_INTERNAL, "Opened inotify fd %d\n", wctx->inotify_fd);

    wctx->tfd = tevent_add_fd(snctx->ev, wctx, wctx->inotify_fd,
                              TEVENT_FD_READ, snotify_internal_cb,
                              snctx);
    if (wctx->tfd == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot add tevent fd watch for %s\n",
              snctx->filename);
        goto fail;
    }

    wctx->file_wd = inotify_add_watch(wctx->inotify_fd, snctx->filename, mask);
    if (wctx->file_wd == -1) {
        ret = errno;
        if (ret != ENOENT || (!(snctx->snotify_flags & SNOTIFY_WATCH_DIR))) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "inotify_add_watch failed [%d]: %s\n",
                  ret, strerror(ret));
            goto fail;
        }
    }
    DEBUG(SSSDBG_TRACE_INTERNAL, "Opened file watch %d\n", wctx->file_wd);

    if (snctx->snotify_flags & SNOTIFY_WATCH_DIR) {
        /* Create a watch for the parent directory. This is useful for cases
         * where we start watching a file before it's created, but still want
         * a notification when the file is moved in
         */
        wctx->dir_wd = inotify_add_watch(wctx->inotify_fd,
                                         snctx->dir_name, PARENT_DIR_MASK);
        if (wctx->dir_wd == -1) {
            ret = errno;
            DEBUG(SSSDBG_MINOR_FAILURE,
                "inotify_add_watch failed [%d]: %s\n",
                ret, strerror(ret));
            goto fail;
        }
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Opened directory watch %d\n", wctx->dir_wd);
    }

    return wctx;

fail:
    talloc_free(wctx);
    return NULL;
}

static errno_t snotify_rewatch(struct snotify_ctx *snctx)
{
    talloc_free(snctx->wctx);

    snctx->wctx = snotify_watch(snctx, snctx->cb.mask);
    if (snctx->wctx == NULL) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Recreated watch\n");
    return EOK;
}

struct snotify_ctx *_snotify_create(TALLOC_CTX *mem_ctx,
                                    struct tevent_context *ev,
                                    uint16_t snotify_flags,
                                    const char *filename,
                                    struct timeval *delay,
                                    uint32_t mask,
                                    snotify_cb_fn fn,
                                    const char *fn_name,
                                    void *pvt)
{
    errno_t ret;
    struct snotify_ctx *snctx;

    snctx = talloc_zero(mem_ctx, struct snotify_ctx);
    if (snctx == NULL) {
        return NULL;
    }

    snctx->ev = ev;
    snctx->snotify_flags = snotify_flags;
    if (delay) {
        snctx->delay.tv_sec = delay->tv_sec;
        snctx->delay.tv_usec = delay->tv_usec;
    }

    snctx->cb.fn = fn;
    snctx->cb.fn_name = fn_name;
    snctx->cb.mask = mask;
    snctx->cb.pvt = pvt;

    ret = copy_filenames(snctx, filename);
    if (ret != EOK) {
        talloc_free(snctx);
        return NULL;
    }

    snctx->wctx = snotify_watch(snctx, mask);
    if (snctx->wctx == NULL) {
        talloc_free(snctx);
        return NULL;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Added a watch for %s with inotify flags 0x%X "
          "internal flags 0x%X "
          "using function %s after delay %ld.%ld\n",
          snctx->filename,
          mask,
          snotify_flags,
          fn_name,
          (unsigned long) snctx->delay.tv_sec,
          (unsigned long) snctx->delay.tv_usec);

    return snctx;
}
