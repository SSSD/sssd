/*
    SSSD

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

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

#include "providers/ipa/ipa_rules_common.h"

static errno_t
ipa_common_save_list(struct sss_domain_info *domain,
                     bool delete_subdir,
                     const char *subdir,
                     const char *naming_attribute,
                     size_t count,
                     struct sysdb_attrs **list)
{
    int ret;
    size_t c;
    struct ldb_dn *base_dn;
    const char *object_name;
    struct ldb_message_element *el;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    if (delete_subdir) {
        base_dn = sysdb_custom_subtree_dn(tmp_ctx, domain, subdir);
        if (base_dn == NULL) {
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_delete_recursive(domain->sysdb, base_dn, true);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_delete_recursive failed.\n");
            goto done;
        }
    }

    for (c = 0; c < count; c++) {
        ret = sysdb_attrs_get_el(list[c], naming_attribute, &el);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_attrs_get_el failed.\n");
            goto done;
        }
        if (el->num_values == 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "[%s] not found.\n", naming_attribute);
            ret = EINVAL;
            goto done;
        }
        object_name = talloc_strndup(tmp_ctx, (const char *)el->values[0].data,
                                     el->values[0].length);
        if (object_name == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strndup failed.\n");
            ret = ENOMEM;
            goto done;
        }
        DEBUG(SSSDBG_TRACE_ALL, "Object name: [%s].\n", object_name);

        ret = sysdb_store_custom(domain, object_name, subdir, list[c]);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_store_custom failed.\n");
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
ipa_common_entries_and_groups_sysdb_save(struct sss_domain_info *domain,
                                         const char *primary_subdir,
                                         const char *attr_name,
                                         size_t primary_count,
                                         struct sysdb_attrs **primary,
                                         const char *group_subdir,
                                         const char *groupattr_name,
                                         size_t group_count,
                                         struct sysdb_attrs **groups)
{
    errno_t ret, sret;
    bool in_transaction = false;

    if ((primary_count == 0 || primary == NULL)
        || (group_count > 0 && groups == NULL)) {
        /* There always has to be at least one
         * primary entry.
         */
        return EINVAL;
    }

    /* Save the entries and groups to the cache */
    ret = sysdb_transaction_start(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto done;
    };
    in_transaction = true;

    /* First, save the specific entries */
    ret = ipa_common_save_list(domain, true, primary_subdir,
                               attr_name, primary_count, primary);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not save %s. [%d][%s]\n",
                  primary_subdir, ret, strerror(ret));
        goto done;
    }

    /* Second, save the groups */
    if (group_count > 0) {
        ret = ipa_common_save_list(domain, true, group_subdir,
                                   groupattr_name, group_count, groups);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not save %s. [%d][%s]\n",
                      group_subdir, ret, strerror(ret));
            goto done;
        }
    }

    ret = sysdb_transaction_commit(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction\n");
        goto done;
    }
    in_transaction = false;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(domain->sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE, "Could not cancel sysdb transaction\n");
        }
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Error [%d][%s]\n", ret, strerror(ret));
    }
    return ret;
}
