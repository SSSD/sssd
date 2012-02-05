/*
    SSSD

    IPA Backend Module -- SELinux common routines

    Authors:
        Jan Zeleny <jzeleny@redhat.com>

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

#include "db/sysdb_selinux.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ipa/ipa_selinux_common.h"


errno_t ipa_selinux_map_merge(struct sysdb_attrs *map,
                              struct sysdb_attrs *rule,
                              const char *attr)
{
    struct ldb_message_element *map_el;
    struct ldb_message_element *rule_el;
    size_t total_cnt;
    errno_t ret;
    int i = 0;

    ret = sysdb_attrs_get_el(map, attr, &map_el);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_attrs_get_el(rule, attr, &rule_el);
    if (ret != EOK) {
        goto done;
    }

    total_cnt = map_el->num_values + rule_el->num_values;
    map_el->values = talloc_realloc(map->a, map_el->values,
                                    struct ldb_val, total_cnt);
    if (map_el->values == NULL) {
        ret = ENOMEM;
        goto done;
    }

    while (map_el->num_values < total_cnt)
    {
        map_el->values[map_el->num_values] = ldb_val_dup(map_el->values,
                                                         &rule_el->values[i]);
        map_el->num_values++;
        i++;
    }

    ret = EOK;
done:
    return ret;
}

errno_t ipa_save_user_maps(struct sysdb_ctx *sysdb,
                           size_t map_count,
                           struct sysdb_attrs **maps)
{
    errno_t ret;
    int i;

    ret = sysdb_transaction_start(sysdb);
    if (ret) {
        goto done;
    }

    for (i = 0; i < map_count; i++) {
        ret = sysdb_store_selinux_usermap(sysdb, maps[i]);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("Failed to store user map %d. "
                                      "Ignoring.\n", i));
        } else {
            DEBUG(SSSDBG_TRACE_FUNC, ("User map %d processed.\n", i));
        }
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to commit transaction!\n"));
        goto done;
    }

    ret = EOK;

done:
    return ret;
}
