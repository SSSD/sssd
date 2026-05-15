/*
 SSSD

 Backup files

 Copyright (C) Simo Sorce	2009

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

#include "util/util.h"
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>

#define BUFFER_SIZE 65536

int backup_file(const char *src_file, int dbglvl)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char buf[BUFFER_SIZE];
    int src_fd = -1;
    int dst_fd = -1;
    char *dst_file;
    ssize_t numread;
    ssize_t written;
    int ret, i;

    src_fd = open(src_file, O_RDONLY);
    if (src_fd < 0) {
        ret = errno;
        DEBUG(dbglvl, "Error (%d [%s]) opening source file %s\n",
                       ret, strerror(ret), src_file);
        goto done;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        ret = ENOMEM;
        goto done;
    }

    /* try a few times to come up with a new backup file, then give up */
    for (i = 0; i < 10; i++) {
        if (i == 0) {
            dst_file = talloc_asprintf(tmp_ctx, "%s.bak", src_file);
        } else {
            dst_file = talloc_asprintf(tmp_ctx, "%s.bak%d", src_file, i);
        }
        if (!dst_file) {
            ret = ENOMEM;
            goto done;
        }

        errno = 0;
        dst_fd = open(dst_file, O_CREAT|O_EXCL|O_WRONLY, 0600);
        ret = errno;

        if (dst_fd >= 0) break;

        if (ret != EEXIST) {
            DEBUG(dbglvl, "Error (%d [%s]) opening destination file %s\n",
                           ret, strerror(ret), dst_file);
            goto done;
        }
    }
    if (ret != 0) {
        DEBUG(dbglvl, "Error (%d [%s]) opening destination file %s\n",
                       ret, strerror(ret), dst_file);
        goto done;
    }

    /* copy file contents */
    while (1) {
        errno = 0;
        numread = sss_atomic_read_s(src_fd, buf, BUFFER_SIZE);
        if (numread < 0) {
            ret = errno;
            DEBUG(dbglvl, "Error (%d [%s]) reading from source %s\n",
                           ret, strerror(ret), src_file);
            goto done;
        }
        if (numread == 0) break;

        errno = 0;
        written = sss_atomic_write_s(dst_fd, buf, numread);
        if (written == -1) {
            ret = errno;
            DEBUG(dbglvl, "Error (%d [%s]) writing to destination %s\n",
                            ret, strerror(ret), dst_file);
            goto done;
        }

        if (written != numread) {
            DEBUG(dbglvl, "Wrote %zd bytes expected %zd bytes\n",
                  written, numread);
            ret = EIO;
            goto done;
        }
    }

    ret = EOK;

done:
    if (src_fd != -1) close(src_fd);
    if (dst_fd != -1) close(dst_fd);
    talloc_free(tmp_ctx);
    return ret;
}
