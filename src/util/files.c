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

#include "config.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <talloc.h>

#include "util/util.h"

struct copy_ctx {
    const char *src_orig;
    const char *dst_orig;
    dev_t       src_dev;
    uid_t       uid;
    gid_t       gid;
};

static int sss_timeat_set(int dir_fd, const char *path,
                          const struct stat *statp,
                          int flags)
{
    int ret;

#ifdef HAVE_UTIMENSAT
    struct timespec timebuf[2];

    timebuf[0] = statp->st_atim;
    timebuf[1] = statp->st_mtim;

    ret = utimensat(dir_fd, path, timebuf, flags);
#else
    struct timeval tv[2];

    tv[0].tv_sec  = statp->st_atime;
    tv[0].tv_usec = 0;
    tv[1].tv_sec = statp->st_mtime;
    tv[1].tv_usec = 0;

    ret = futimesat(dir_fd, path, tv);
#endif
    if (ret == -1) {
        return errno;
    }

    return EOK;
}

static int sss_futime_set(int fd, const struct stat *statp)
{
    int ret;

#ifdef HAVE_FUTIMENS
    struct timespec timebuf[2];

    timebuf[0] = statp->st_atim;
    timebuf[1] = statp->st_mtim;
    ret = futimens(fd, timebuf);
#else
    struct timeval tv[2];

    tv[0].tv_sec  = statp->st_atime;
    tv[0].tv_usec = 0;
    tv[1].tv_sec = statp->st_mtime;
    tv[1].tv_usec = 0;

    ret = futimes(fd, tv);
#endif
    if (ret == -1) {
        return errno;
    }

    return EOK;
}

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

static char *talloc_readlinkat(TALLOC_CTX *mem_ctx, int dir_fd,
                               const char *filename)
{
    size_t size = 1024;
    ssize_t nchars;
    char *buffer;
    char *new_buffer;

    buffer = talloc_array(mem_ctx, char, size);
    if (!buffer) {
        return NULL;
    }

    while (1) {
        nchars = readlinkat(dir_fd, filename, buffer, size);
        if (nchars < 0) {
            talloc_free(buffer);
            return NULL;
        }

        if ((size_t) nchars < size) {
            /* The buffer was large enough */
            break;
        }

        /* Try again with a bigger buffer */
        size *= 2;
        new_buffer = talloc_realloc(mem_ctx, buffer, char, size);
        if (!new_buffer) {
            talloc_free(buffer);
            return NULL;
        }
        buffer = new_buffer;
    }

    /* readlink does not nul-terminate */
    buffer[nchars] = '\0';
    return buffer;
}

static int
copy_symlink(int src_dir_fd,
             int dst_dir_fd,
             const char *file_name,
             const char *full_path,
             const struct stat *statp,
             uid_t uid, gid_t gid)
{
    char *buf;
    errno_t ret;

    buf = talloc_readlinkat(NULL, src_dir_fd, file_name);
    if (!buf) {
        return ENOMEM;
    }

    ret = selinux_file_context(full_path);
    if (ret != 0) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to set SELinux context for [%s]\n", full_path);
        /* Not fatal */
    }

    ret = symlinkat(buf, dst_dir_fd, file_name);
    talloc_free(buf);
    if (ret == -1) {
        ret = errno;
        if (ret == EEXIST) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "symlink pointing to already exists at '%s'\n", full_path);
            return EOK;
        }

        DEBUG(SSSDBG_CRIT_FAILURE, "symlinkat failed: %s\n", strerror(ret));
        return ret;
    }

    ret = fchownat(dst_dir_fd, file_name,
                   uid, gid, AT_SYMLINK_NOFOLLOW);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
             "fchownat failed: %s\n", strerror(ret));
        return ret;
    }

    ret = sss_timeat_set(dst_dir_fd, file_name, statp,
                         AT_SYMLINK_NOFOLLOW);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "utimensat failed [%d]: %s\n",
              ret, strerror(ret));
        /* Do not fail */
    }

    return EOK;
}

static int
copy_file_contents(int ifd,
                   int ofd,
                   mode_t mode,
                   uid_t uid, gid_t gid)
{
    errno_t ret;
    char buf[1024];
    ssize_t cnt, written;

    while ((cnt = sss_atomic_read_s(ifd, buf, sizeof(buf))) != 0) {
        if (cnt == -1) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot read() from source file: [%d][%s].\n",
                   ret, strerror(ret));
            goto done;
        }

        errno = 0;
        written = sss_atomic_write_s(ofd, buf, cnt);
        if (written == -1) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot write() to destination file: [%d][%s].\n",
                   ret, strerror(ret));
            goto done;
        }

        if (written != cnt) {
            ret = EINVAL;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Wrote %zd bytes, expected %zd\n", written, cnt);
            goto done;
        }
    }

    /* Set the ownership; permissions are still
     * restrictive. */
    ret = fchown(ofd, uid, gid);
    if (ret == -1 && errno != EPERM) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE,
              "Error changing owner: %s\n",
              strerror(ret));
        goto done;
    }

    /* Set the desired mode. */
    ret = fchmod(ofd, mode);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE, "Error changing mode: %s\n",
              strerror(ret));
              goto done;
    }

    ret = EOK;

done:
    return ret;
}


/* Copy bytes from input file descriptor ifd into file named
 * dst_named under directory with dest_dir_fd. Own the new file
 * by uid/gid
 */
static int
copy_file(int ifd,
          int dest_dir_fd,
          const char *file_name,
          const char *full_path,
          const struct stat *statp,
          uid_t uid, gid_t gid)
{
    int ofd = -1;
    errno_t ret;

    ret = selinux_file_context(full_path);
    if (ret != 0) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to set SELinux context for [%s]\n", full_path);
        /* Not fatal */
    }

    /* Start with absolutely restrictive permissions */
    ofd = openat(dest_dir_fd, file_name,
                 O_EXCL | O_CREAT | O_WRONLY | O_NOFOLLOW,
                 0);
    if (ofd < 0 && errno != EEXIST) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE,
               "Cannot open() destination file '%s': [%d][%s].\n",
               full_path, ret, strerror(ret));
        goto done;
    }

    ret = copy_file_contents(ifd, ofd, statp->st_mode, uid, gid);
    if (ret != EOK) goto done;


    ret = sss_futime_set(ofd, statp);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "sss_futime_set failed [%d]: %s\n",
              ret, strerror(ret));
        /* Do not fail */
    }
    ret = EOK;

done:
    if (ofd != -1) close(ofd);
    return ret;
}

int
sss_copy_file_secure(const char *src,
                     const char *dest,
                     mode_t mode,
                     uid_t uid, gid_t gid,
                     bool force)
{
    int ifd = -1;
    int ofd = -1;
    int dest_flags = 0;
    errno_t ret;

    ret = selinux_file_context(dest);
    if (ret != 0) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to set SELinux context for [%s]\n", dest);
        /* Not fatal */
    }

    /* Start with absolutely restrictive permissions */
    dest_flags = O_CREAT | O_WRONLY | O_NOFOLLOW;
    if (!force) {
        dest_flags |= O_EXCL;
    }

    ofd = open(dest, dest_flags, mode);
    if (ofd < 0) {
        DEBUG(SSSDBG_OP_FAILURE,
               "Cannot open() destination file '%s': [%d][%s].\n",
               dest, errno, strerror(errno));
        goto done;
    }

    ifd = sss_open_cloexec(src, O_RDONLY | O_NOFOLLOW, &ret);
    if (ifd < 0) {
        DEBUG(SSSDBG_OP_FAILURE,
               "Cannot open() source file '%s': [%d][%s].\n",
               src, ret, strerror(ret));
        goto done;
    }

    ret = copy_file_contents(ifd, ofd, mode, uid, gid);

done:
    if (ifd != -1) close(ifd);
    if (ofd != -1) close(ofd);
    return ret;
}

static errno_t
copy_dir(struct copy_ctx *cctx,
         int src_dir_fd, const char *src_dir_path,
         int dest_parent_fd, const char *dest_dir_name,
         const char *dest_dir_path,
         mode_t mode,
         const struct stat *src_dir_stat);

static errno_t
copy_entry(struct copy_ctx *cctx,
           int src_dir_fd,
           const char *src_dir_path,
           int dest_dir_fd,
           const char *dest_dir_path,
           const char *ent_name)
{
    char *src_ent_path = NULL;
    char *dest_ent_path = NULL;
    int ifd = -1;
    errno_t ret;
    struct stat st;

    /* Build the path of the source file or directory and its
     * corresponding member in the new tree. */
    src_ent_path = talloc_asprintf(cctx, "%s/%s", src_dir_path, ent_name);
    dest_ent_path = talloc_asprintf(cctx, "%s/%s", dest_dir_path, ent_name);
    if (!src_ent_path || !dest_ent_path) {
        ret = ENOMEM;
        goto done;
    }

    /* Open the input entry first, then we can fstat() it and be
     * certain that it is still the same file.  O_NONBLOCK protects
     * us against FIFOs and perhaps side-effects of the open() of a
     * device file if there ever was one here, and doesn't matter
     * for regular files or directories. */
    ifd = sss_openat_cloexec(src_dir_fd, ent_name,
                         O_RDONLY | O_NOFOLLOW | O_NONBLOCK, &ret);
    if (ifd == -1 && ret != ELOOP) {
        /* openat error */
        DEBUG(SSSDBG_CRIT_FAILURE, "openat failed on '%s': %s\n",
              src_ent_path, strerror(ret));
        goto done;
    } else if (ifd == -1 && ret == ELOOP) {
        /* Should be a symlink.. */
        ret = fstatat(src_dir_fd, ent_name, &st, AT_SYMLINK_NOFOLLOW);
        if (ret == -1) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE, "fstatat failed on '%s': %s\n",
                  src_ent_path, strerror(ret));
            goto done;
        }

        /* Handle symlinks */
        ret = copy_symlink(src_dir_fd, dest_dir_fd, ent_name,
                           dest_ent_path, &st, cctx->uid, cctx->gid);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Cannot copy '%s' to '%s'\n",
                  src_ent_path, dest_ent_path);
        }
        goto done;
    }

    ret = fstat(ifd, &st);
    if (ret != 0) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "couldn't stat '%s': %s\n", src_ent_path, strerror(ret));
        goto done;
    }

    if (S_ISDIR(st.st_mode)) {
        /* If it's a directory, descend into it. */
        ret = copy_dir(cctx, ifd, src_ent_path,
                       dest_dir_fd, ent_name,
                       dest_ent_path, st.st_mode & 07777,
                       &st);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                    "Couldn't recursively copy '%s' to '%s': %s\n",
                    src_ent_path, dest_ent_path, strerror(ret));
            goto done;
        }
    } else if (S_ISREG(st.st_mode)) {
        /* Copy a regular file */
        ret = copy_file(ifd, dest_dir_fd, ent_name, dest_ent_path,
                        &st, cctx->uid, cctx->gid);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE, "Cannot copy '%s' to '%s'\n",
                    src_ent_path, dest_ent_path);
            goto done;
        }
    } else {
        /* Is a special file */
        DEBUG(SSSDBG_FUNC_DATA, "'%s' is a special file, skipping.\n",
                  src_ent_path);
    }

    ret = EOK;
done:
    talloc_free(src_ent_path);
    talloc_free(dest_ent_path);
    if (ifd != -1) close(ifd);
    return ret;
}

static errno_t
copy_dir(struct copy_ctx *cctx,
         int src_dir_fd, const char *src_dir_path,
         int dest_parent_fd, const char *dest_dir_name,
         const char *dest_dir_path,
         mode_t mode,
         const struct stat *src_dir_stat)
{
    errno_t ret;
    errno_t dret;
    int dest_dir_fd = -1;
    DIR *dir = NULL;
    struct dirent *ent;

    if (!dest_dir_path) {
        return EINVAL;
    }

    dir = fdopendir(src_dir_fd);
    if (dir == NULL) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Error reading '%s': %s\n", src_dir_path, strerror(ret));
        goto done;
    }

    /* Create the directory.  It starts owned by us (presumably root), with
     * fairly restrictive permissions that still allow us to use the
     * directory.
     * */
    errno = 0;
    ret = mkdirat(dest_parent_fd, dest_dir_name, S_IRWXU);
    if (ret == -1 && errno != EEXIST) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Error reading '%s': %s\n", dest_dir_path, strerror(ret));
        goto done;
    }

    dest_dir_fd = sss_openat_cloexec(dest_parent_fd, dest_dir_name,
                                 O_RDONLY | O_DIRECTORY | O_NOFOLLOW, &ret);
    if (dest_dir_fd == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Error opening '%s': %s\n", dest_dir_path, strerror(ret));
        goto done;
    }

    while ((ent = readdir(dir)) != NULL) {
        /* Iterate through each item in the directory. */
        /* Skip over self and parent hard links. */
        if (strcmp(ent->d_name, ".") == 0 ||
            strcmp(ent->d_name, "..") == 0) {
            continue;
        }

        ret = copy_entry(cctx,
                         src_dir_fd, src_dir_path,
                         dest_dir_fd, dest_dir_path,
                         ent->d_name);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not copy [%s] to [%s]\n",
                  src_dir_path, dest_dir_path);
            goto done;
        }
    }

    /* Set the ownership on the directory.  Permissions are still
     * fairly restrictive. */
    ret = fchown(dest_dir_fd, cctx->uid, cctx->gid);
    if (ret == -1 && errno != EPERM) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE,
              "Error changing owner of '%s': %s\n",
              dest_dir_path, strerror(ret));
        goto done;
    }

    /* Set the desired mode. Do this explicitly to preserve S_ISGID and
     * other bits. Do this after chown, because chown is permitted to
     * reset these bits. */
    ret = fchmod(dest_dir_fd, mode);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE,
              "Error setting mode of '%s': %s\n",
              dest_dir_path, strerror(ret));
        goto done;
    }

    sss_futime_set(dest_dir_fd, src_dir_stat);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "sss_futime_set failed [%d]: %s\n",
              ret, strerror(ret));
        /* Do not fail */
    }

    ret = EOK;
done:
    if (dir) {
        dret = closedir(dir);
        if (dret != 0) {
            dret = errno;
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to close directory: %s.\n", strerror(dret));
        }
    }

    if (dest_dir_fd != -1) {
        close(dest_dir_fd);
    }
    return ret;
}

/* NOTE:
 * For several reasons, including the fact that we copy even special files
 * (pipes, etc) from the skeleton directory, the skeldir needs to be trusted
 */
int sss_copy_tree(const char *src_root,
                  const char *dst_root,
                  mode_t mode_root,
                  uid_t uid, gid_t gid)
{
    int ret = EOK;
    struct copy_ctx *cctx = NULL;
    int fd = -1;
    struct stat s_src;

    fd = sss_open_cloexec(src_root, O_RDONLY | O_DIRECTORY, &ret);
    if (fd == -1) {
        goto fail;
    }

    ret = fstat(fd, &s_src);
    if (ret == -1) {
        ret = errno;
        goto fail;
    }

    cctx = talloc_zero(NULL, struct copy_ctx);
    if (!cctx) {
        ret = ENOMEM;
        goto fail;
    }

    cctx->src_orig = src_root;
    cctx->dst_orig = dst_root;
    cctx->src_dev  = s_src.st_dev;
    cctx->uid      = uid;
    cctx->gid      = gid;

    ret = copy_dir(cctx, fd, src_root, AT_FDCWD,
                   dst_root, dst_root, mode_root, &s_src);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "copy_dir failed: [%d][%s]\n", ret, strerror(ret));
        goto fail;
    }

fail:
    if (fd != -1) close(fd);
    reset_selinux_file_context();
    talloc_free(cctx);
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
