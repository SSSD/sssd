/*
    SSSD

    Calls to manage the preauth indicator file

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2018 Red Hat

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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "util/util.h"
#include "sss_client/sss_cli.h"

static void cleanup_preauth_indicator(void)
{
    int ret;

    ret = unlink(PAM_PREAUTH_INDICATOR);
    if (ret != EOK && errno != ENOENT) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to remove preauth indicator file [%s] %d [%s].\n",
              PAM_PREAUTH_INDICATOR, ret, sss_strerror(ret));
    }
}

errno_t create_preauth_indicator(void)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    int fd;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    fd = open(PAM_PREAUTH_INDICATOR, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW,
              0644);
    if (fd < 0) {
        if (errno != EEXIST) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to create preauth indicator file [%s].\n",
                  PAM_PREAUTH_INDICATOR);
            ret = EOK;
            goto done;
        }

        DEBUG(SSSDBG_TRACE_FUNC,
              "Preauth indicator file [%s] already exists. Continuing.\n",
              PAM_PREAUTH_INDICATOR);
    } else {
        close(fd);
    }

    ret = atexit(cleanup_preauth_indicator);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "atexit failed. Continuing.\n");
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}
