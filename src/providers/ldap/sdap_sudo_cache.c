/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2011 Red Hat

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

#include "db/sysdb.h"
#include "db/sysdb_sudo.h"
#include "providers/ldap/sdap_sudo_cache.h"

/* ==========  Functions specific for the native sudo LDAP schema ========== */
static errno_t sdap_sudo_get_usn(TALLOC_CTX *mem_ctx,
                                 struct sysdb_attrs *attrs,
                                 struct sdap_attr_map *map,
                                 const char *name,
                                 char **_usn)
{
    const char *usn;
    errno_t ret;

    if (_usn == NULL) {
        return EINVAL;
    }

    ret = sysdb_attrs_get_string(attrs, map[SDAP_AT_SUDO_USN].sys_name, &usn);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Failed to retrieve USN value: [%s]\n", strerror(ret)));

        return ret;
    }

    *_usn = talloc_strdup(mem_ctx, usn);
    if (*_usn == NULL) {
        return ENOMEM;
    }

    return EOK;
}

static errno_t
sdap_save_native_sudorule(TALLOC_CTX *mem_ctx,
                          struct sysdb_ctx *sysdb_ctx,
                          struct sdap_attr_map *map,
                          struct sysdb_attrs *attrs,
                          int cache_timeout,
                          time_t now,
                          char **_usn)
{
    errno_t ret;
    const char *rule_name;

    ret = sysdb_attrs_get_string(attrs, map[SDAP_AT_SUDO_NAME].sys_name,
                                 &rule_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not get rule name [%d]: %s\n",
              ret, strerror(ret)));
        return ret;
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_CACHE_EXPIRE,
                                 (cache_timeout ? (now + cache_timeout) : 0));
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not set sysdb cache expire [%d]: %s\n",
              ret, strerror(ret)));
        return ret;
    }

    ret = sdap_sudo_get_usn(mem_ctx, attrs, map, rule_name, _usn);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not read USN from %s\n", rule_name));
        return ret;
    }

    ret = sysdb_save_sudorule(sysdb_ctx, rule_name, attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not save sudorule %s\n", rule_name));
        return ret;
    }

    return ret;
}

errno_t
sdap_save_native_sudorule_list(TALLOC_CTX *mem_ctx,
                               struct sysdb_ctx *sysdb_ctx,
                               struct sdap_attr_map *map,
                               struct sysdb_attrs **replies,
                               size_t replies_count,
                               int cache_timeout,
                               time_t now,
                               char **_usn)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *higher_usn = NULL;
    char *usn_value = NULL;
    errno_t ret, tret;
    bool in_transaction = false;
    size_t i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL)  {
        DEBUG(SSSDBG_FATAL_FAILURE, ("talloc_new() failed\n"));
        return ENOMEM;
    }

    ret = sysdb_transaction_start(sysdb_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Could not start transaction\n"));
        goto fail;
    }
    in_transaction = true;

    for (i=0; i<replies_count; i++) {
        usn_value = NULL;
        ret = sdap_save_native_sudorule(tmp_ctx, sysdb_ctx, map, replies[i],
                                        cache_timeout, now, &usn_value);
        if (ret != EOK) {
            goto fail;
        }

        /* find highest usn */
        if (usn_value) {
            if (higher_usn) {
                if ((strlen(usn_value) > strlen(higher_usn)) ||
                    (strcmp(usn_value, higher_usn) > 0)) {
                    talloc_zfree(higher_usn);
                    higher_usn = usn_value;
                } else {
                    talloc_zfree(usn_value);
                }
            } else {
                higher_usn = usn_value;
            }
        }
    }

    ret = sysdb_transaction_commit(sysdb_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to commit transaction\n"));
        goto fail;
    }
    in_transaction = false;

    if (higher_usn != NULL) {
        *_usn = talloc_steal(mem_ctx, higher_usn);
    }

    ret = EOK;
fail:
    if (in_transaction) {
        tret = sysdb_transaction_cancel(sysdb_ctx);
        if (tret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Could not cancel transaction\n"));
        }
    }

    talloc_free(tmp_ctx);

    return ret;
}
