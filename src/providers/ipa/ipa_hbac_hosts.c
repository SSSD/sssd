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

#include "util/util.h"
#include "db/sysdb.h"
#include "providers/ipa/ipa_hbac_private.h"
#include "providers/ipa/ipa_rules_common.h"
#include "providers/ldap/sdap_async.h"

/*
 * Functions to convert sysdb_attrs to the hbac_rule format
 */
static errno_t hbac_host_attrs_to_rule(TALLOC_CTX *mem_ctx,
                                       struct sss_domain_info *domain,
                                       const char *rule_name,
                                       struct sysdb_attrs *rule_attrs,
                                       const char *category_attr,
                                       const char *member_attr,
                                       size_t *host_count,
                                       struct hbac_rule_element **hosts)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    struct hbac_rule_element *new_hosts;
    const char *attrs[] = { SYSDB_FQDN, SYSDB_NAME, NULL };
    struct ldb_message_element *el;
    size_t num_hosts = 0;
    size_t num_hostgroups = 0;
    size_t i;
    char *member_dn;
    char *filter;
    size_t count;
    struct ldb_message **msgs;
    const char *name;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) return ENOMEM;

    new_hosts = talloc_zero(tmp_ctx, struct hbac_rule_element);
    if (new_hosts == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* First check for host category */
    ret = hbac_get_category(rule_attrs, category_attr, &new_hosts->category);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not identify host categories\n");
        goto done;
    }
    if (new_hosts->category & HBAC_CATEGORY_ALL) {
        /* Short-cut to the exit */
        ret = EOK;
        goto done;
    }

    /* Get the list of DNs from the member_attr */
    ret = sysdb_attrs_get_el(rule_attrs, member_attr, &el);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_attrs_get_el failed.\n");
        goto done;
    }
    if (ret == ENOENT || el->num_values == 0) {
        el->num_values = 0;
        DEBUG(SSSDBG_CONF_SETTINGS,
              "No host specified, rule will never apply.\n");
    }

    /* Assume maximum size; We'll trim it later */
    new_hosts->names = talloc_array(new_hosts,
                                    const char *,
                                    el->num_values +1);
    if (new_hosts->names == NULL) {
        ret = ENOMEM;
        goto done;
    }

    new_hosts->groups = talloc_array(new_hosts,
                                     const char *,
                                     el->num_values + 1);
    if (new_hosts->groups == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < el->num_values; i++) {
        ret = sss_filter_sanitize(tmp_ctx,
                                  (const char *)el->values[i].data,
                                  &member_dn);
        if (ret != EOK) goto done;

        filter = talloc_asprintf(member_dn, "(%s=%s)",
                                 SYSDB_ORIG_DN, member_dn);
        if (filter == NULL) {
            ret = ENOMEM;
            goto done;
        }

        /* First check if this is a specific host */
        ret = sysdb_search_custom(tmp_ctx, domain, filter,
                                  HBAC_HOSTS_SUBDIR, attrs,
                                  &count, &msgs);
        if (ret != EOK && ret != ENOENT) goto done;
        if (ret == EOK && count == 0) {
            ret = ENOENT;
        }

        if (ret == EOK) {
            if (count > 1) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Original DN matched multiple hosts. Skipping \n");
                talloc_zfree(member_dn);
                continue;
            }

            /* Original DN matched a single host. Get the hostname */
            name = ldb_msg_find_attr_as_string(msgs[0],
                                               SYSDB_FQDN,
                                               NULL);
            if (name == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "FQDN is missing!\n");
                ret = EFAULT;
                goto done;
            }

            new_hosts->names[num_hosts] = talloc_strdup(new_hosts->names,
                                                        name);
            if (new_hosts->names[num_hosts] == NULL) {
                ret = ENOMEM;
                goto done;
            }
            DEBUG(SSSDBG_TRACE_INTERNAL, "Added host [%s] to rule [%s]\n",
                      name, rule_name);
            num_hosts++;
        } else { /* ret == ENOENT */
            /* Check if this is a hostgroup */
            ret = sysdb_search_custom(tmp_ctx, domain, filter,
                                      HBAC_HOSTGROUPS_SUBDIR, attrs,
                                      &count, &msgs);
            if (ret != EOK && ret != ENOENT) goto done;
            if (ret == EOK && count == 0) {
                ret = ENOENT;
            }

            if (ret == EOK) {
                if (count > 1) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Original DN matched multiple hostgroups. "
                              "Skipping\n");
                    talloc_zfree(member_dn);
                    continue;
                }

                /* Original DN matched a single group. Get the groupname */
                name = ldb_msg_find_attr_as_string(msgs[0], SYSDB_NAME, NULL);
                if (name == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "Hostgroup name is missing!\n");
                    ret = EFAULT;
                    goto done;
                }

                new_hosts->groups[num_hostgroups] =
                        talloc_strdup(new_hosts->groups, name);
                if (new_hosts->groups[num_hostgroups] == NULL) {
                    ret = ENOMEM;
                    goto done;
                }

                DEBUG(SSSDBG_TRACE_INTERNAL,
                      "Added hostgroup [%s] to rule [%s]\n",
                          name, rule_name);
                num_hostgroups++;
            } else { /* ret == ENOENT */
                /* Neither a host nor a hostgroup? Skip it */
                DEBUG(SSSDBG_TRACE_LIBS,
                      "[%s] does not map to either a host or hostgroup. "
                       "Skipping\n", member_dn);
            }
        }
        talloc_zfree(member_dn);
    }
    new_hosts->names[num_hosts] = NULL;
    new_hosts->groups[num_hostgroups] = NULL;

    /* Shrink the arrays down to their real sizes */
    new_hosts->names = talloc_realloc(new_hosts, new_hosts->names,
                                      const char *, num_hosts + 1);
    if (new_hosts->names == NULL) {
        ret = ENOMEM;
        goto done;
    }

    new_hosts->groups = talloc_realloc(new_hosts, new_hosts->groups,
                                       const char *, num_hostgroups + 1);
    if (new_hosts->groups == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;

done:
    if (ret == EOK) {
        *hosts = talloc_steal(mem_ctx, new_hosts);
        if (host_count) *host_count = num_hosts;
    }
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
hbac_thost_attrs_to_rule(TALLOC_CTX *mem_ctx,
                         struct sss_domain_info *domain,
                         const char *rule_name,
                         struct sysdb_attrs *rule_attrs,
                         struct hbac_rule_element **thosts)
{
    DEBUG(SSSDBG_TRACE_LIBS,
          "Processing target hosts for rule [%s]\n", rule_name);

    return hbac_host_attrs_to_rule(mem_ctx, domain,
                                   rule_name, rule_attrs,
                                   IPA_HOST_CATEGORY, IPA_MEMBER_HOST,
                                   NULL, thosts);
}

errno_t
hbac_shost_attrs_to_rule(TALLOC_CTX *mem_ctx,
                         struct sss_domain_info *domain,
                         const char *rule_name,
                         struct sysdb_attrs *rule_attrs,
                         bool support_srchost,
                         struct hbac_rule_element **source_hosts)
{
    errno_t ret;
    size_t host_count;
    TALLOC_CTX *tmp_ctx;
    size_t idx;
    struct ldb_message_element *el;
    struct hbac_rule_element *shosts;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) return ENOMEM;

    DEBUG(SSSDBG_TRACE_FUNC, "Processing source hosts for rule [%s]\n", rule_name);

    if (!support_srchost) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "Source hosts disabled, setting ALL\n");
        shosts = talloc_zero(tmp_ctx, struct hbac_rule_element);
        if (shosts == NULL) {
            ret = ENOMEM;
            goto done;
        }

        shosts->category = HBAC_CATEGORY_ALL;
        ret = EOK;
        goto done;
    } else {
        DEBUG(SSSDBG_MINOR_FAILURE, "WARNING: Using deprecated option "
                    "ipa_hbac_support_srchost.\n");
        sss_log(SSS_LOG_NOTICE, "WARNING: Using deprecated option "
                    "ipa_hbac_support_srchost.\n");
    }

    ret = hbac_host_attrs_to_rule(tmp_ctx, domain,
                                  rule_name, rule_attrs,
                                  IPA_SOURCE_HOST_CATEGORY, IPA_SOURCE_HOST,
                                  &host_count, &shosts);
    if (ret != EOK) {
        goto done;
    }

    if (shosts->category & HBAC_CATEGORY_ALL) {
        /* All hosts (including external) are
         * allowed.
         */
        goto done;
    }

    /* Include external (non-IPA-managed) source hosts */
    ret = sysdb_attrs_get_el(rule_attrs, IPA_EXTERNAL_HOST, &el);
    if (ret != EOK && ret != ENOENT) goto done;
    if (ret == EOK && el->num_values == 0) ret = ENOENT;

    if (ret != ENOENT) {
        shosts->names = talloc_realloc(shosts, shosts->names, const char *,
                                       host_count + el->num_values + 1);
        if (shosts->names == NULL) {
            ret = ENOMEM;
            goto done;
        }

        for (idx = host_count; idx < host_count + el->num_values; idx++) {
            shosts->names[idx] =
                    talloc_strdup(shosts->names,
                               (const char *)el->values[idx - host_count].data);
            if (shosts->names[idx] == NULL) {
                ret = ENOMEM;
                goto done;
            }
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "Added external source host [%s] to rule [%s]\n",
                      shosts->names[idx], rule_name);
        }
        shosts->names[idx] = NULL;
    }

    ret = EOK;

done:
    if (ret == EOK) {
        *source_hosts = talloc_steal(mem_ctx, shosts);
    }
    talloc_free(tmp_ctx);
    return ret;
}
