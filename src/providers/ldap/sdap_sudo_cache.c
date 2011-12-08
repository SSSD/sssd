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

#include "db/sysdb.h"
#include "db/sysdb_sudo.h"
#include "providers/ldap/sdap_sudo_cache.h"

/* ==========  Functions specific for the native sudo LDAP schema ========== */
static errno_t
sdap_save_native_sudorule(struct sysdb_ctx *sysdb_ctx,
                          struct sdap_attr_map *map,
                          struct sysdb_attrs *attrs)
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

    ret = sysdb_save_sudorule(sysdb_ctx, rule_name, attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not save sudorule %s\n", rule_name));
        return ret;
    }

    return ret;
}

errno_t
sdap_save_native_sudorule_list(struct sysdb_ctx *sysdb_ctx,
                               struct sdap_attr_map *map,
                               struct sysdb_attrs **replies,
                               size_t replies_count)
{
    errno_t ret, tret;
    bool in_transaction = false;
    size_t i;

    ret = sysdb_transaction_start(sysdb_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Could not start transaction\n"));
        goto fail;
    }
    in_transaction = true;

    for (i=0; i<replies_count; i++) {
        ret = sdap_save_native_sudorule(sysdb_ctx, map, replies[i]);
        if (ret != EOK) {
            goto fail;
        }
    }

    ret = sysdb_transaction_commit(sysdb_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to commit transaction\n"));
        goto fail;
    }
    in_transaction = false;

    ret = EOK;
fail:
    if (in_transaction) {
        tret = sysdb_transaction_cancel(sysdb_ctx);
        if (tret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Could not cancel transaction\n"));
        }
    }

    return ret;
}
