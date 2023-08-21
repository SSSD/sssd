/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2009 Red Hat

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

/*
 * This file incorporates work covered by the following copyright and
 * permission notice:
 *
 * Copyright (c) 1991 - 1994, Julianne Frances Haugh
 * Copyright (c) 1996 - 2001, Marek Michałkiewicz
 * Copyright (c) 2003 - 2006, Tomasz Kłoczko
 * Copyright (c) 2007 - 2008, Nicolas François
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the copyright holders or contributors may not be used to
 *    endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <talloc.h>

#include "util/util.h"

/* wrapper in order not to create a temporary context in
 * every iteration */
static int remove_tree_with_ctx(TALLOC_CTX *mem_ctx,
                                int parent_fd,
                                const char *dir_name,
                                dev_t parent_dev,
                                bool keep_root_dir);

int sss_remove_tree(const char *root)
{
    TALLOC_CTX *tmp_ctx = NULL;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = remove_tree_with_ctx(tmp_ctx, AT_FDCWD, root, 0, false);
    talloc_free(tmp_ctx);
    return ret;
}

int sss_remove_subtree(const char *root)
{
    TALLOC_CTX *tmp_ctx = NULL;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = remove_tree_with_ctx(tmp_ctx, AT_FDCWD, root, 0, true);
    talloc_free(tmp_ctx);
    return ret;
}

/*
 * The context is not freed in case of error
 * because this is a recursive function, will be freed when we
 * reach the top level remove_tree() again
 */
static int remove_tree_with_ctx(TALLOC_CTX *mem_ctx,
                                int parent_fd,
                                const char *dir_name,
                                dev_t parent_dev,
                                bool keep_root_dir)
{
    struct dirent *result;
    struct stat statres;
    DIR *rootdir = NULL;
    int ret, err;
    int dir_fd;
    int log_level;

    dir_fd = sss_openat_cloexec(parent_fd, dir_name,
                            O_RDONLY | O_DIRECTORY | O_NOFOLLOW, &ret);
    if (dir_fd == -1) {
        ret = errno;
        if (ret == ENOENT) {
            log_level = SSSDBG_TRACE_FUNC;
        } else {
            log_level = SSSDBG_MINOR_FAILURE;
        }
        DEBUG(log_level, "Cannot open %s: [%d]: %s\n",
              dir_name, ret, strerror(ret));
        return ret;
    }

    rootdir = fdopendir(dir_fd);
    if (rootdir == NULL) {
        ret = errno;
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Cannot open directory: [%d][%s]\n", ret, strerror(ret));
        close(dir_fd);
        goto fail;
    }

    while ((result = readdir(rootdir)) != NULL) {
        if (strcmp(result->d_name, ".") == 0 ||
            strcmp(result->d_name, "..") == 0) {
            continue;
        }

        ret = fstatat(dir_fd, result->d_name,
                      &statres, AT_SYMLINK_NOFOLLOW);
        if (ret != 0) {
            ret = errno;
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "stat failed: [%d][%s]\n", ret, strerror(ret));
            goto fail;
        }

        if (S_ISDIR(statres.st_mode)) {
            /* if directory, recursively descend, but check if on the same FS */
            if (parent_dev && parent_dev != statres.st_dev) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Directory %s is on different filesystem, "
                       "will not follow\n", result->d_name);
                ret = EFAULT;
                goto fail;
            }

            ret = remove_tree_with_ctx(mem_ctx, dir_fd, result->d_name,
                                       statres.st_dev, false);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Removing subdirectory failed: [%d][%s]\n",
                       ret, strerror(ret));
                goto fail;
            }
        } else {
            ret = unlinkat(dir_fd, result->d_name, 0);
            if (ret != 0) {
                ret = errno;
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Removing file failed '%s': [%d][%s]\n",
                      result->d_name, ret, strerror(ret));
                goto fail;
            }
        }
    }

    ret = closedir(rootdir);
    rootdir = NULL;
    if (ret != 0) {
        ret = errno;
        goto fail;
    }

    if (!keep_root_dir) {
        /* Remove also root directory. */
        ret = unlinkat(parent_fd, dir_name, AT_REMOVEDIR);
        if (ret == -1) {
            ret = errno;
        }
    }

    ret = EOK;
fail:
    if (rootdir) {  /* clean up on abnormal exit but retain return code */
        err = closedir(rootdir);
        if (err) {
            DEBUG(SSSDBG_MINOR_FAILURE, "closedir failed, bad dirp?\n");
        }
    }
    return ret;
}

int sss_create_dir(const char *parent_dir_path,
                   const char *dir_name,
                   mode_t mode,
                   uid_t uid, gid_t gid)
{
    TALLOC_CTX *tmp_ctx;
    char *dir_path;
    int ret = EOK;
    int parent_dir_fd = -1;
    int dir_fd = -1;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    parent_dir_fd = sss_open_cloexec(parent_dir_path, O_RDONLY | O_DIRECTORY,
                                     &ret);
    if (parent_dir_fd == -1) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Cannot open() directory '%s' [%d]: %s\n",
              parent_dir_path, ret, sss_strerror(ret));
        goto fail;
    }

    dir_path = talloc_asprintf(tmp_ctx, "%s/%s", parent_dir_path, dir_name);
    if (dir_path == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    errno = 0;
    ret = mkdirat(parent_dir_fd, dir_name, mode);
    if (ret == -1) {
        if (errno == EEXIST) {
            ret = EOK;
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Directory '%s' already created!\n", dir_path);
        } else {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Error reading '%s': %s\n", parent_dir_path, strerror(ret));
            goto fail;
        }
    }

    dir_fd = sss_open_cloexec(dir_path, O_RDONLY | O_DIRECTORY, &ret);
    if (dir_fd == -1) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Cannot open() directory '%s' [%d]: %s\n",
              dir_path, ret, sss_strerror(ret));
        goto fail;
    }

    errno = 0;
    ret = fchown(dir_fd, uid, gid);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to own the newly created directory '%s' [%d]: %s\n",
              dir_path, ret, sss_strerror(ret));
        goto fail;
    }

    ret = EOK;

fail:
    if (parent_dir_fd != -1) {
        close(parent_dir_fd);
    }
    if (dir_fd != -1) {
        close(dir_fd);
    }
    talloc_free(tmp_ctx);
    return ret;
}
