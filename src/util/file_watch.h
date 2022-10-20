/*
 * Copyright (C) 2022 Red Hat Inc.
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

#ifndef _FILE_WATCH_H
#define _FILE_WATCH_H

#include <stdbool.h>
#include <talloc.h>
#include <tevent.h>


typedef void (*fw_callback)(const char *filename, void *arg);
struct file_watch_ctx;

/*
 * This function configures the watching of a file. When the file is created
 * or modified, the provided callback function is invoked.
 *
 * If the file exists at the moment this function is called, the callback
 * will be invoked once. A first processing of the file can be done in that
 * case. If the file does not exist at that moment, the callback will be
 * invoked when the file is created.
 *
 * inotify will be used to watch the file unless 'use_notify' is set to 'false'
 * in sssd.conf or inotify fails (not installed). In those two cases, the
 * file state will be polled every 10 seconds when the file doesn't exist
 * to detect its creation, and every 5 seconds when the file exists to detect
 * changes.
 */
struct file_watch_ctx *fw_watch_file(TALLOC_CTX *mem_ctx,
                                     struct tevent_context *ev,
                                     const char *filename,
                                     bool use_inotify,
                                     fw_callback cb,
                                     void *cb_arg);



#endif /* _FILE_WATCH_H */
