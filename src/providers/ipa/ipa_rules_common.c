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

errno_t
ipa_common_get_cached_rules(TALLOC_CTX *mem_ctx,
                            struct sss_domain_info *domain,
                            const char *rule,
                            const char *subtree_name,
                            const char **attrs,
                            size_t *_rule_count,
                            struct sysdb_attrs ***_rules)
{
    errno_t ret;
    struct ldb_message **msgs;
    struct sysdb_attrs **rules;
    size_t rule_count;
    TALLOC_CTX *tmp_ctx;
    char *filter;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    filter = talloc_asprintf(tmp_ctx, "(objectClass=%s)", rule);
    if (filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_custom(tmp_ctx, domain, filter,
                              subtree_name, attrs,
                              &rule_count, &msgs);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Error looking up HBAC rules\n");
        goto done;
    }

    if (ret == ENOENT) {
       rule_count = 0;
    }

    ret = sysdb_msg2attrs(tmp_ctx, rule_count, msgs, &rules);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not convert ldb message to sysdb_attrs\n");
        goto done;
    }

    if (_rules) {
        *_rules = talloc_steal(mem_ctx, rules);
    }

    if (_rule_count) {
        *_rule_count = rule_count;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
ipa_common_purge_rules(struct sss_domain_info *domain,
                       const char *subtree_name)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *base_dn;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    base_dn = sysdb_custom_subtree_dn(tmp_ctx, domain, subtree_name);
    if (base_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_delete_recursive(domain->sysdb, base_dn, true);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_delete_recursive failed.\n");
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t ipa_common_save_rules(struct sss_domain_info *domain,
                              struct ipa_common_entries *hosts,
                              struct ipa_common_entries *services,
                              struct ipa_common_entries *rules,
                              time_t *last_update)
{
    bool in_transaction = false;
    errno_t ret;
    errno_t sret;

    ret = sysdb_transaction_start(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not start transaction\n");
        goto done;
    }
    in_transaction = true;

    /* Save the hosts */
    if (hosts != NULL) {
        ret = ipa_common_entries_and_groups_sysdb_save(domain,
                                                       hosts->entry_subdir,
                                                       SYSDB_FQDN,
                                                       hosts->entry_count,
                                                       hosts->entries,
                                                       hosts->group_subdir,
                                                       SYSDB_NAME,
                                                       hosts->group_count,
                                                       hosts->groups);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Error saving hosts [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto done;
        }
    }

    /* Save the services */
    if (services != NULL) {
        ret = ipa_common_entries_and_groups_sysdb_save(domain,
                                                       services->entry_subdir,
                                                       IPA_CN,
                                                       services->entry_count,
                                                       services->entries,
                                                       services->group_subdir,
                                                       IPA_CN,
                                                       services->group_count,
                                                       services->groups);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Error saving services [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto done;
        }
    }

    /* Save the rules */
    if (rules != NULL) {
        ret = ipa_common_entries_and_groups_sysdb_save(domain,
                                                       rules->entry_subdir,
                                                       IPA_UNIQUE_ID,
                                                       rules->entry_count,
                                                       rules->entries,
                                                       NULL, NULL, 0, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Error saving rules [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto done;
        }
    }

    ret = sysdb_transaction_commit(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction\n");
        goto done;
    }
    in_transaction = false;

    *last_update = time(NULL);

    ret = EOK;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(domain->sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not cancel transaction\n");
        }
    }

    return ret;
}
