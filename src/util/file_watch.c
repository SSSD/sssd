/*
 * Copyright (C) 2022, Red Hat Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>

#include "util/inotify.h"
#include "util/util.h"
#include "util/file_watch.h"



#define MISSING_FILE_POLL_TIME   10  /* seconds */
#define FILE_WATCH_POLL_INTERVAL  5  /* seconds */


struct file_watch_ctx {
    struct tevent_context *ev;
    const char *filename;
    bool use_inotify;

    struct config_file_inotify_check {
        struct snotify_ctx *snctx;
    } inotify_check;

    struct config_file_poll_check {
        struct tevent_timer *timer;
        time_t modified;
    } poll_check;

    fw_callback cb;
    void *cb_arg;
};


static void poll_watched_file(struct tevent_context *ev,
                             struct tevent_timer *te,
                             struct timeval t, void *ptr);

static errno_t create_poll_timer(struct file_watch_ctx *fw_ctx)
{
    struct timeval tv;

    tv = tevent_timeval_current_ofs(FILE_WATCH_POLL_INTERVAL, 0);

    fw_ctx->poll_check.timer = tevent_add_timer(fw_ctx->ev,
                                                fw_ctx,
                                                tv,
                                                poll_watched_file,
                                                fw_ctx);
    if (!fw_ctx->poll_check.timer) {
        return EIO;
    }

    return EOK;
}

static void poll_watched_file(struct tevent_context *ev,
                              struct tevent_timer *te,
                              struct timeval t, void *ptr)
{
    int ret, err;
    struct stat file_stat;
    struct file_watch_ctx *fw_ctx;

    fw_ctx = talloc_get_type(ptr, struct file_watch_ctx);

    ret = stat(fw_ctx->filename, &file_stat);
    if (ret < 0) {
        err = errno;
        DEBUG(SSSDBG_IMPORTANT_INFO,
              "Could not stat file [%s]. Error [%d:%s]\n",
              fw_ctx->filename, err, strerror(err));
        return;
    }

    if (file_stat.st_mtime != fw_ctx->poll_check.modified) {
        /* Parse the file and invoke the callback */
        /* Note: this will fire if the modification time changes into the past
         * as well as the future.
         */
        DEBUG(SSSDBG_TRACE_INTERNAL, "File [%s] changed\n", fw_ctx->filename);
        fw_ctx->poll_check.modified = file_stat.st_mtime;

        /* Tell the caller the file changed */
        fw_ctx->cb(fw_ctx->filename, fw_ctx->cb_arg);
    }

    ret = create_poll_timer(fw_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_IMPORTANT_INFO,
              "Error: File [%s] no longer monitored for changes!\n",
              fw_ctx->filename);
    }
}


static int watched_file_inotify_cb(const char *filename,
                                  uint32_t flags,
                                  void *pvt)
{
    static char received[PATH_MAX + 1];
    static char expected[PATH_MAX + 1];
    struct file_watch_ctx *fw_ctx;
    char *res;

    DEBUG(SSSDBG_TRACE_LIBS,
          "Received inotify notification for %s\n", filename);

    fw_ctx = talloc_get_type(pvt, struct file_watch_ctx);
    if (fw_ctx == NULL) {
        return EINVAL;
    }

    res = realpath(fw_ctx->filename, expected);
    if (res == NULL) {
         DEBUG(SSSDBG_TRACE_LIBS,
               "Normalization failed for expected %s. Skipping the callback.\n",
               fw_ctx->filename);
        goto done;
    }

    res = realpath(filename, received);
    if (res == NULL) {
         DEBUG(SSSDBG_TRACE_LIBS,
               "Normalization failed for received %s. Skipping the callback.\n",
               filename);
        goto done;
    }

    if (strcmp(expected, received) == 0) {
        if (access(received, F_OK) == 0) {
            fw_ctx->cb(received, fw_ctx->cb_arg);
        } else {
            DEBUG(SSSDBG_TRACE_LIBS,
                  "File %s is missing. Skipping the callback.\n", filename);
        }
    }

done:
    return EOK;
}


static int try_inotify(struct file_watch_ctx *fw_ctx)
{
#ifdef HAVE_INOTIFY
    struct snotify_ctx *snctx;
    /* We will queue the file for update in one second.
     * This way, if there is a script writing to the file
     * repeatedly, we won't be attempting to update multiple
     * times.
     */
    struct timeval delay = { .tv_sec = 1, .tv_usec = 0 };

    snctx = snotify_create(fw_ctx, fw_ctx->ev, SNOTIFY_WATCH_DIR,
                           fw_ctx->filename, &delay,
                           IN_DELETE_SELF | IN_CLOSE_WRITE | IN_MOVE_SELF | \
                           IN_CREATE | IN_MOVED_TO | IN_IGNORED,
                           watched_file_inotify_cb, fw_ctx);
    if (snctx == NULL) {
        return EIO;
    }

    return EOK;
#else
    return EINVAL;
#endif /* HAVE_INOTIFY */
}

static errno_t fw_watch_file_poll(struct file_watch_ctx *fw_ctx)
{
    struct stat file_stat;
    int ret, err;

    ret = stat(fw_ctx->filename, &file_stat);
    if (ret < 0) {
        err = errno;
        if (err == ENOENT) {
            DEBUG(SSSDBG_IMPORTANT_INFO,
                  "File [%s] is missing. Will try again later.\n",
                  fw_ctx->filename);
        } else {
            DEBUG(SSSDBG_IMPORTANT_INFO,
                  "Could not stat file [%s]. Error [%d:%s]\n",
                  fw_ctx->filename, err, strerror(err));
        }
        return err;
    }

    fw_ctx->poll_check.modified = file_stat.st_mtime;

    if(!fw_ctx->poll_check.timer) {
        ret = create_poll_timer(fw_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_TRACE_LIBS, "Cannot create poll timer\n");
            return ret;
        }
    }

    return EOK;
}


static int watch_file(struct file_watch_ctx *fw_ctx)
{
    int ret = EOK;
    bool use_inotify;

    use_inotify = fw_ctx->use_inotify;
    if (use_inotify) {
        ret = try_inotify(fw_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_TRACE_LIBS, "Falling back to polling\n");
            use_inotify = false;
        }
    }

    if (!use_inotify) {
        ret = fw_watch_file_poll(fw_ctx);
    }

    return ret;
}


static void set_file_watching(struct tevent_context *ev,
                              struct tevent_timer *te,
                              struct timeval tv, void *data)
{
    int ret;
    struct file_watch_ctx *fw_ctx = talloc_get_type(data, struct file_watch_ctx);

    ret = watch_file(fw_ctx);
    if (ret == EOK) {
        if (access(fw_ctx->filename, F_OK) == 0) {
            fw_ctx->cb(fw_ctx->filename, fw_ctx->cb_arg);
        }
    } else if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "%s missing. Waiting for it to appear.\n",
              fw_ctx->filename);
        tv = tevent_timeval_current_ofs(MISSING_FILE_POLL_TIME, 0);
        te = tevent_add_timer(fw_ctx->ev, fw_ctx, tv, set_file_watching, fw_ctx);
        if (te == NULL) {
            DEBUG(SSSDBG_IMPORTANT_INFO,
                  "tevent_add_timer failed. %s will be ignored.\n",
                  fw_ctx->filename);
        }
    } else {
        DEBUG(SSSDBG_IMPORTANT_INFO,
              "watch_file failed. %s will be ignored: [%i] %s\n",
              fw_ctx->filename, ret, sss_strerror(ret));
    }
}


struct file_watch_ctx *fw_watch_file(TALLOC_CTX *mem_ctx,
                                     struct tevent_context *ev,
                                     const char *filename,
                                     bool use_inotify,
                                     fw_callback cb,
                                     void *cb_arg)
{
    int ret;
    struct timeval tv;
    struct file_watch_ctx *fw_ctx;

    if (ev == NULL || filename == NULL || cb == NULL) {
        DEBUG(SSSDBG_TRACE_LIBS, "Invalid parameter\n");
        return NULL;
    }

    fw_ctx = talloc_zero(mem_ctx, struct file_watch_ctx);
    if (fw_ctx == NULL) {
        DEBUG(SSSDBG_IMPORTANT_INFO, "Failed to allocate the context\n");
        return NULL;
    }

    fw_ctx->ev = ev;
    fw_ctx->use_inotify = use_inotify;
    fw_ctx->cb = cb;
    fw_ctx->cb_arg = cb_arg;
    fw_ctx->filename = talloc_strdup(fw_ctx, filename);
    if (fw_ctx->filename == NULL) {
        DEBUG(SSSDBG_IMPORTANT_INFO, "talloc_strdup() failed\n");
        ret = ENOMEM;
        goto done;
    }

    /* Watch for changes to the requested file, and retry periodically
     * if the file does not exist */
    tv = tevent_timeval_current_ofs(0, 0); // Not actually used
    set_file_watching(fw_ctx->ev, NULL, tv, fw_ctx);
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(fw_ctx);
        fw_ctx = NULL;
    }

    return fw_ctx;
}
