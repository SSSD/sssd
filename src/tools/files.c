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

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <talloc.h>

#include "config.h"
#include "util/util.h"
#include "tools/tools_util.h"

int copy_tree(const char *src_root, const char *dst_root,
              uid_t uid, gid_t gid);

struct copy_ctx {
    const char *src_orig;
    const char *dst_orig;
    dev_t       src_dev;
};

/* wrapper in order not to create a temporary context in
 * every iteration */
static int remove_tree_with_ctx(TALLOC_CTX *mem_ctx,
                                dev_t parent_dev,
                                const char *root);

int remove_tree(const char *root)
{
    TALLOC_CTX *tmp_ctx = NULL;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = remove_tree_with_ctx(tmp_ctx, 0, root);
    talloc_free(tmp_ctx);
    return ret;
}

/*
 * The context is not freed in case of error
 * because this is a recursive function, will be freed when we
 * reach the top level remove_tree() again
 */
static int remove_tree_with_ctx(TALLOC_CTX *mem_ctx,
                                dev_t parent_dev,
                                const char *root)
{
    char *fullpath = NULL;
    struct dirent *result;
    struct dirent direntp;
    struct stat statres;
    DIR *rootdir = NULL;
    int ret, err;

    rootdir = opendir(root);
    if (rootdir == NULL) {
        ret = errno;
        DEBUG(1, ("Cannot open directory %s [%d][%s]\n",
                  root, ret, strerror(ret)));
        goto fail;
    }

    while (readdir_r(rootdir, &direntp, &result) == 0) {
        if (result == NULL) {
            /* End of directory */
            break;
        }

        if (strcmp (direntp.d_name, ".") == 0 ||
            strcmp (direntp.d_name, "..") == 0) {
            continue;
        }

        fullpath = talloc_asprintf(mem_ctx, "%s/%s", root, direntp.d_name);
        if (fullpath == NULL) {
            ret = ENOMEM;
            goto fail;
        }

        ret = lstat(fullpath, &statres);
        if (ret != 0) {
            ret = errno;
            DEBUG(1, ("Cannot stat %s: [%d][%s]\n",
                      fullpath, ret, strerror(ret)));
            goto fail;
        }

        if (S_ISDIR(statres.st_mode)) {
            /* if directory, recursively descend, but check if on the same FS */
            if (parent_dev && parent_dev != statres.st_dev) {
                DEBUG(1, ("Directory %s is on different filesystem, "
                          "will not follow\n", fullpath));
                ret = EFAULT;
                goto fail;
            }

            ret = remove_tree_with_ctx(mem_ctx, statres.st_dev, fullpath);
            if (ret != EOK) {
                DEBUG(1, ("Removing subdirectory %s failed: [%d][%s]\n",
                            fullpath, ret, strerror(ret)));
                goto fail;
            }
        } else {
            ret = unlink(fullpath);
            if (ret != 0) {
                ret = errno;
                DEBUG(1, ("Removing file %s failed: [%d][%s]\n",
                          fullpath, ret, strerror(ret)));
                goto fail;
            }
        }

        talloc_free(fullpath);
    }

    ret = closedir(rootdir);
    rootdir = NULL;
    if (ret != 0) {
        ret = errno;
        goto fail;
    }

    ret = rmdir(root);
    if (ret != 0) {
        ret = errno;
        goto fail;
    }

    ret = EOK;

fail:
    if (rootdir) {  /* clean up on abnormal exit but retain return code */
        err = closedir(rootdir);
        if (err) {
            DEBUG(1, ("closedir failed, bad dirp?\n"));
        }
    }
    return ret;
}

static int copy_dir(const char *src, const char *dst,
                    const struct stat *statp, const struct timeval mt[2],
                    uid_t uid, gid_t gid)
{
    int ret = 0;

    /*
     * Create a new target directory, make it owned by
     * the user and then recursively copy that directory.
     */
    selinux_file_context(dst);

    ret = mkdir(dst, statp->st_mode);
    if (ret != 0) {
        ret = errno;
        DEBUG(1, ("Cannot mkdir directory '%s': [%d][%s].\n",
                  dst, ret, strerror(ret)));
        return ret;
    }

    ret = chown(dst, uid, gid);
    if (ret != 0) {
        ret = errno;
        DEBUG(1, ("Cannot chown directory '%s': [%d][%s].\n",
                  dst, ret, strerror(ret)));
        return ret;
    }

    ret = chmod(dst, statp->st_mode);
    if (ret != 0) {
        ret = errno;
        DEBUG(1, ("Cannot chmod directory '%s': [%d][%s].\n",
                  dst, ret, strerror(ret)));
        return ret;
    }

    ret = copy_tree(src, dst, uid, gid);
    if (ret != 0) {
        ret = errno;
        DEBUG(1, ("Cannot copy directory from '%s' to '%s': [%d][%s].\n",
                  src, dst, ret, strerror(ret)));
        return ret;
    }

    ret = utimes(dst, mt);
    if (ret != 0) {
        ret = errno;
        DEBUG(1, ("Cannot set utimes on a directory '%s': [%d][%s].\n",
                  dst, ret, strerror(ret)));
        return ret;
    }

    return EOK;
}

static char *talloc_readlink(TALLOC_CTX *mem_ctx, const char *filename)
{
    size_t size = 1024;
    ssize_t nchars;
    char *buffer;

    buffer = talloc_array(mem_ctx, char, size);
    if (!buffer) {
        return NULL;
    }

    while (1) {
        nchars = readlink(filename, buffer, size);
        if (nchars < 0) {
            return NULL;
        }

        if ((size_t) nchars < size) {
            /* The buffer was large enough */
            break;
        }

        /* Try again with a bigger buffer */
        size *= 2;
        buffer = talloc_realloc(mem_ctx, buffer, char, size);
        if (!buffer) {
            return NULL;
        }
    }

    /* readlink does not nul-terminate */
    buffer[nchars] = '\0';
    return buffer;
}

static int copy_symlink(struct copy_ctx *cctx,
                        const char *src,
                        const char *dst,
                        const struct stat *statp,
                        const struct timeval mt[],
                        uid_t uid, gid_t gid)
{
    int ret;
    char *oldlink;
    char *tmp;
    TALLOC_CTX *tmp_ctx = NULL;

    tmp_ctx = talloc_new(cctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    /*
     * Get the name of the file which the link points
     * to.  If that name begins with the original
     * source directory name, that part of the link
     * name will be replaced with the original
     * destination directory name.
     */
    oldlink = talloc_readlink(tmp_ctx, src);
    if (oldlink == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* If src was a link to an entry of the src_orig directory itself,
     * create a link to the corresponding entry in the dst_orig
     * directory.
     * FIXME: This may change a relative link to an absolute link
     */
    if (strncmp(oldlink, cctx->src_orig, strlen(cctx->src_orig)) == 0) {
        tmp = talloc_asprintf(tmp_ctx, "%s%s", cctx->dst_orig, oldlink + strlen(cctx->src_orig));
        if (tmp == NULL) {
            ret = ENOMEM;
            goto done;
        }

        talloc_free(oldlink);
        oldlink = tmp;
    }

    selinux_file_context(dst);

    ret = symlink(oldlink, dst);
    if (ret != 0) {
        ret = errno;
        DEBUG(1, ("symlink() failed on file '%s': [%d][%s].\n",
                  dst, ret, strerror(ret)));
        goto done;
    }

    ret = lchown(dst, uid, gid);
    if (ret != 0) {
        ret = errno;
        DEBUG(1, ("lchown() failed on file '%s': [%d][%s].\n",
                  dst, ret, strerror(ret)));
        goto done;
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

static int copy_special(const char *dst,
                        const struct stat *statp,
                        const struct timeval mt[],
                        uid_t uid, gid_t gid)
{
    int ret = 0;

    selinux_file_context(dst);

    ret = mknod(dst, statp->st_mode & ~07777, statp->st_rdev);
    if (ret != 0) {
        ret = errno;
        DEBUG(1, ("Cannot mknod special file '%s': [%d][%s].\n",
                  dst, ret, strerror(ret)));
        return ret;
    }

    ret = chown(dst, uid, gid);
    if (ret != 0) {
        ret = errno;
        DEBUG(1, ("Cannot chown special file '%s': [%d][%s].\n",
                  dst, ret, strerror(ret)));
        return ret;
    }

    ret = chmod(dst, statp->st_mode & 07777);
    if (ret != 0) {
        ret = errno;
        DEBUG(1, ("Cannot chmod special file '%s': [%d][%s].\n",
                  dst, ret, strerror(ret)));
        return ret;
    }

    ret = utimes(dst, mt);
    if (ret != 0) {
        ret = errno;
        DEBUG(1, ("Cannot call utimes on special file '%s': [%d][%s].\n",
                  dst, ret, strerror(ret)));
        return ret;
    }

    return EOK;
}

static int copy_file(const char *src,
                     const char *dst,
                     const struct stat *statp,
                     const struct timeval mt[],
                     uid_t uid, gid_t gid)
{
    int ret;
    int ifd = -1;
    int ofd = -1;
    char buf[1024];
    ssize_t cnt, written, res;
    struct stat fstatbuf;

    ifd = open(src, O_RDONLY);
    if (ifd < 0) {
        ret = errno;
        DEBUG(1, ("Cannot open() source file '%s': [%d][%s].\n",
                  src, ret, strerror(ret)));
        goto fail;
    }

    ret = fstat(ifd, &fstatbuf);
    if (ret != 0) {
        ret = errno;
        DEBUG(1, ("Cannot fstat() source file '%s': [%d][%s].\n",
                  src, ret, strerror(ret)));
        goto fail;
    }

    if (statp->st_dev != fstatbuf.st_dev ||
        statp->st_ino != fstatbuf.st_ino) {
        DEBUG(1, ("File %s was modified between lstat and open.\n", src));
        ret = EIO;
        goto fail;
    }

    selinux_file_context(dst);

    ofd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, statp->st_mode & 07777);
    if (ofd < 0) {
        ret = errno;
        DEBUG(1, ("Cannot open() destination file '%s': [%d][%s].\n",
                  dst, ret, strerror(ret)));
        goto fail;
    }

    ret = fchown(ofd, uid, gid);
    if (ret != 0) {
        ret = errno;
        DEBUG(1, ("Cannot fchown() destination file '%s': [%d][%s].\n",
                  dst, ret, strerror(ret)));
        goto fail;
    }

    ret = fchmod(ofd, statp->st_mode & 07777);
    if (ret != 0) {
        ret = errno;
        DEBUG(1, ("Cannot fchmod() destination file '%s': [%d][%s].\n",
                  dst, ret, strerror(ret)));
        goto fail;
    }

    while ((cnt = read(ifd, buf, sizeof(buf))) != 0) {
        if (cnt == -1) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }

            DEBUG(1, ("Cannot read() from source file '%s': [%d][%s].\n",
                        src, ret, strerror(ret)));
            goto fail;
        }
        else if (cnt > 0) {
            /* Copy the buffer to the new file */
            written = 0;
            while (written < cnt) {
                res = write(ofd, buf+written, (size_t)cnt-written);
                if (res == -1) {
                    ret = errno;
                    if (ret == EINTR || ret == EAGAIN) {
                        /* retry the write */
                        continue;
                    }
                    DEBUG(1, ("Cannot write() to destination file '%s': [%d][%s].\n",
                                dst, ret, strerror(ret)));
                    goto fail;
                }
                else if (res <= 0) {
                    DEBUG(1, ("Unexpected result from write(): [%d]\n", res));
                    goto fail;
                }

                written += res;
            }
        }
        else {
            DEBUG(1, ("Unexpected return code of read [%d]\n", cnt));
            goto fail;
        }
    }

    ret = close(ifd);
    ifd = -1;
    if (ret != 0) {
        ret = errno;
        DEBUG(1, ("Cannot close() source file '%s': [%d][%s].\n",
                  dst, ret, strerror(ret)));
        goto fail;
    }

    ret = close(ofd);
    ifd = -1;
    if (ret != 0) {
        ret = errno;
        DEBUG(1, ("Cannot close() destination file '%s': [%d][%s].\n",
                  dst, ret, strerror(ret)));
        goto fail;
    }

    ret = utimes(dst, mt);
    if (ret != 0) {
        ret = errno;
        DEBUG(1, ("Cannot call utimes() on destination file '%s': [%d][%s].\n",
                  dst, ret, strerror(ret)));
        goto fail;
    }

    return EOK;

    /* Reachable by jump only */
fail:
    if (ifd != -1) close(ifd);
    if (ofd != -1) close(ofd);
    return ret;
}

/*
 * The context is not freed in case of error
 * because this is a recursive function, will be freed when we
 * reach the top level copy_tree() again
 */
static int copy_entry(struct copy_ctx *cctx,
                      const char *src,
                      const char *dst,
                      uid_t uid,
                      gid_t gid)
{
    int ret = EOK;
    struct stat sb;
    struct timeval mt[2];

    ret = lstat(src, &sb);
    if (ret == -1) {
        ret = errno;
        DEBUG(1, ("Cannot lstat() the source file '%s': [%d][%s].\n",
                  src, ret, strerror(ret)));
        return ret;
    }

    mt[0].tv_sec  = sb.st_atime;
    mt[0].tv_usec = 0;

    mt[1].tv_sec  = sb.st_mtime;
    mt[1].tv_usec = 0;

    if (S_ISLNK (sb.st_mode)) {
        ret = copy_symlink(cctx, src, dst, &sb, mt, uid, gid);
        if (ret != EOK) {
            DEBUG(1, ("Cannot copy symlink '%s' to '%s': [%d][%s]\n",
                      src, dst, ret, strerror(ret)));
        }
        return ret;
    }

    if (S_ISDIR(sb.st_mode)) {
        /* Check if we're still on the same FS */
        if (sb.st_dev != cctx->src_dev) {
            DEBUG(2, ("Will not descend to other FS\n"));
            /* Skip this without error */
            return EOK;
        }
        return copy_dir(src, dst, &sb, mt, uid, gid);
    } else if (!S_ISREG(sb.st_mode)) {
        /*
         * Deal with FIFOs and special files.  The user really
         * shouldn't have any of these, but it seems like it
         * would be nice to copy everything ...
         */
        return copy_special(dst, &sb, mt, uid, gid);
    } else {
        /*
         * Create the new file and copy the contents.  The new
         * file will be owned by the provided UID and GID values.
         */
        return copy_file(src, dst, &sb, mt, uid, gid);
    }

    return ret;
}

/*
 * The context is not freed in case of error
 * because this is a recursive function, will be freed when we
 * reach the top level copy_tree() again
 */
static int copy_tree_ctx(struct copy_ctx *cctx,
                         const char *src_root,
                         const char *dst_root,
                         uid_t uid,
                         gid_t gid)
{
    DIR *src_dir = NULL;
    int ret, err;
    struct dirent *result;
    struct dirent direntp;
    char *src_name, *dst_name;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(cctx);

    src_dir = opendir(src_root);
    if (src_dir == NULL) {
        ret = errno;
        DEBUG(1, ("Cannot open the source directory %s: [%d][%s].\n",
                  src_root, ret, strerror(ret)));
        goto fail;
    }

    while (readdir_r(src_dir, &direntp, &result) == 0) {
        if (result == NULL) {
            /* End of directory */
            break;
        }

        if (strcmp (direntp.d_name, ".") == 0 ||
            strcmp (direntp.d_name, "..") == 0) {
            continue;
        }

        /* build src and dst paths */
        src_name = talloc_asprintf(tmp_ctx, "%s/%s", src_root, direntp.d_name);
        dst_name = talloc_asprintf(tmp_ctx, "%s/%s", dst_root, direntp.d_name);
        if (dst_name == NULL || src_name == NULL) {
            ret = ENOMEM;
            goto fail;
        }

        /* copy */
        ret = copy_entry(cctx, src_name, dst_name, uid, gid);
        if (ret != EOK) {
            DEBUG(1, ("Cannot copy '%s' to '%s', error %d\n",
                      src_name, dst_name, ret));
            goto fail;
        }
        talloc_free(src_name);
        talloc_free(dst_name);
    }

    ret = closedir(src_dir);
    src_dir = NULL;
    if (ret != 0) {
        ret = errno;
        goto fail;
    }

    ret = EOK;
fail:
    if (src_dir) {  /* clean up on abnormal exit but retain return code */
        err = closedir(src_dir);
        if (err) {
            DEBUG(1, ("closedir failed, bad dirp?\n"));
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}

int copy_tree(const char *src_root, const char *dst_root,
              uid_t uid, gid_t gid)
{
    int ret = EOK;
    struct copy_ctx *cctx = NULL;
    struct stat s_src;

    cctx = talloc_zero(NULL, struct copy_ctx);

    ret = lstat(src_root, &s_src);
    if (ret != 0) {
        ret = errno;
        DEBUG(1, ("Cannot lstat the source directory '%s': [%d][%s]\n",
                  src_root, ret, strerror(ret)));
        goto fail;
    }

    cctx->src_orig = src_root;
    cctx->dst_orig = dst_root;
    cctx->src_dev  = s_src.st_dev;

    ret = copy_tree_ctx(cctx, src_root, dst_root, uid, gid);
    if (ret != EOK) {
        DEBUG(1, ("copy_tree_ctx failed: [%d][%s]\n", ret, strerror(ret)));
        goto fail;
    }

fail:
    reset_selinux_file_context();
    talloc_free(cctx);
    return ret;
}

