/*
    Authors:
        Jan Cholasta <jcholast@redhat.com>

    Copyright (C) 2012 Red Hat

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

#include "db/sysdb_ssh.h"
#include "db/sysdb_private.h"

errno_t
sysdb_save_ssh_host(struct sysdb_ctx *sysdb_ctx,
                    const char *name,
                    struct sysdb_attrs *attrs)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;

    DEBUG(SSSDBG_TRACE_FUNC, ("Adding host %s\n", name));

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    if (!attrs) {
        attrs = sysdb_new_attrs(tmp_ctx);
        if (!attrs) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = sysdb_store_custom(sysdb_ctx, name, SSH_HOSTS_SUBDIR, attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("sysdb_store_custom failed [%d]: %s\n",
              ret, strerror(ret)));
        goto done;
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_delete_ssh_host(struct sysdb_ctx *sysdb_ctx,
                      const char *name)
{
    DEBUG(SSSDBG_TRACE_FUNC, ("Deleting host %s\n", name));
    return sysdb_delete_custom(sysdb_ctx, name, SSH_HOSTS_SUBDIR);
}

errno_t
sysdb_search_ssh_hosts(TALLOC_CTX *mem_ctx,
                       struct sysdb_ctx *sysdb,
                       const char *name,
                       const char **attrs,
                       struct ldb_message ***hosts,
                       size_t *host_count)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    const char *filter;
    size_t count;
    struct ldb_message **msgs;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    filter = talloc_asprintf(tmp_ctx, "(%s=%s)", SYSDB_NAME, name);
    if (!filter) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_custom(tmp_ctx, sysdb, filter, SSH_HOSTS_SUBDIR, attrs,
                              &count, &msgs);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Error looking up host [%s]", name));
        goto done;
    } if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, ("No such host\n"));
        *hosts = NULL;
        *host_count = 0;
        goto done;
    }

    *hosts = talloc_steal(mem_ctx, msgs);
    *host_count = count;
    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}
