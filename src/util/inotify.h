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

#ifndef __INOTIFY_H_
#define __INOTIFY_H_

#include <talloc.h>
#include <tevent.h>
#include <sys/inotify.h>


typedef int (*snotify_cb_fn)(const char *filename,
                             uint32_t caught_flags,
                             void *pvt);

#define SNOTIFY_WATCH_DIR   0x0001

/*
 * Set up an inotify watch for file at filename. When an inotify
 * event is caught, it must match the "mask" parameter. The watch
 * would then call snotify_cb_fn() and include the caught flags.
 *
 * If snotify_flags includes SNOTIFY_WATCH_DIR, also the parent directory
 * of this file would be watched to cover cases where the file might not
 * exist when the watch is created.
 *
 * If you wish to batch inotify requests to avoid hammering the caller
 * with several successive requests, use the delay parameter. The function
 * would then only send invoke the callback after the delay and the caught
 * flags would be OR-ed. By default, the callback is invoked immediately.
 *
 * Use the pvt parameter to pass a private context to the function
 */
struct snotify_ctx *_snotify_create(TALLOC_CTX *mem_ctx,
                                    struct tevent_context *ev,
                                    uint16_t snotify_flags,
                                    const char *filename,
                                    struct timeval *delay,
                                    uint32_t mask,
                                    snotify_cb_fn fn,
                                    const char *fn_name,
                                    void *pvt);

#define snotify_create(mem_ctx, ev, snotify_flags, filename, delay, mask, fn, pvt) \
        _snotify_create(mem_ctx, ev, snotify_flags, filename, delay, mask, fn, #fn, pvt);

#endif /*  __INOTIFY_H_ */
