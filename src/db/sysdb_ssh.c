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
sysdb_store_ssh_host(struct sysdb_ctx *sysdb,
                     const char *name,
                     const char *alias,
                     struct sysdb_attrs *attrs)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    struct ldb_message **hosts;
    size_t num_hosts;
    struct ldb_message_element *el;
    unsigned int i;
    const char *search_attrs[] = { SYSDB_NAME_ALIAS, NULL };
    bool in_transaction = false;

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

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to start transaction\n"));
        goto done;
    }

    in_transaction = true;

    ret = sysdb_search_ssh_hosts(tmp_ctx, sysdb, name, search_attrs,
                                 &hosts, &num_hosts);
    if (ret != EOK && ret != ENOENT) {
        goto done;
    }

    if (num_hosts > 1) {
        ret = EINVAL;
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Found more than one host with name [%s].\n", name));
        goto done;
    }

    ret = sysdb_delete_ssh_host(sysdb, name);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Failed to delete host [%s].\n", name));
        goto done;
    }

    if (num_hosts == 1) {
        el = ldb_msg_find_element(hosts[0], SYSDB_NAME_ALIAS);

        if (el) {
            for (i = 0; i < el->num_values; i++) {
                if (alias && strcmp((char *)el->values[i].data, alias) == 0) {
                    alias = NULL;
                }

                ret = sysdb_attrs_add_val(attrs,
                                          SYSDB_NAME_ALIAS, &el->values[i]);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          ("Could not add name alias [%s]\n",
                           el->values[i].data));
                    goto done;
                }
            }
        }
    }

    if (alias) {
        ret = sysdb_attrs_add_string(attrs, SYSDB_NAME_ALIAS, alias);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  ("Could not add name alias [%s]\n", alias));
            goto done;
        }
    }

    ret = sysdb_store_custom(sysdb, name, SSH_HOSTS_SUBDIR, attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("sysdb_store_custom failed [%d]: %s\n",
              ret, strerror(ret)));
        goto done;
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to commit transaction\n"));
        goto done;
    }

    in_transaction = false;
    ret = EOK;

done:
    if (in_transaction) {
        sysdb_transaction_cancel(sysdb);
    }

    talloc_free(tmp_ctx);

    return ret;
}

errno_t
sysdb_delete_ssh_host(struct sysdb_ctx *sysdb,
                      const char *name)
{
    DEBUG(SSSDBG_TRACE_FUNC, ("Deleting host %s\n", name));
    return sysdb_delete_custom(sysdb, name, SSH_HOSTS_SUBDIR);
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
