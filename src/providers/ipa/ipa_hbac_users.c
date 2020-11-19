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
#include "providers/ipa/ipa_rules_common.h"
#include "providers/ipa/ipa_hbac_private.h"
#include "providers/ldap/sdap_async.h"

/* Returns EOK and populates groupname if
 * the group_dn is actually a group.
 * Returns ENOENT if group_dn does not point
 * at a group.
 * Returns EINVAL if there is a parsing error.
 * Returns ENOMEM as appropriate
 */
errno_t
get_ipa_groupname(TALLOC_CTX *mem_ctx,
                  struct sysdb_ctx *sysdb,
                  const char *group_dn,
                  const char **groupname)
{
    errno_t ret;
    struct ldb_dn *dn;
    const char *rdn_name;
    const char *group_comp_name;
    const char *account_comp_name;
    const struct ldb_val *rdn_val;
    const struct ldb_val *group_comp_val;
    const struct ldb_val *account_comp_val;

    /* This is an IPA-specific hack. It may not
     * work for non-IPA servers and will need to
     * be changed if SSSD ever supports HBAC on
     * a non-IPA server.
     */
    *groupname = NULL;

    DEBUG(SSSDBG_TRACE_LIBS, "Parsing %s\n", group_dn);

    dn = ldb_dn_new(mem_ctx, sysdb_ctx_get_ldb(sysdb), group_dn);
    if (dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (!ldb_dn_validate(dn)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "DN %s does not validate\n", group_dn);
        ret = ERR_MALFORMED_ENTRY;
        goto done;
    }

    if (ldb_dn_get_comp_num(dn) < 4) {
        /* RDN, groups, accounts, and at least one DC= */
        /* If it's fewer, it's not a group DN */
        DEBUG(SSSDBG_CRIT_FAILURE, "DN %s has too few components\n", group_dn);
        ret = ERR_UNEXPECTED_ENTRY_TYPE;
        goto done;
    }

    /* If the RDN name is 'cn' */
    rdn_name = ldb_dn_get_rdn_name(dn);
    if (rdn_name == NULL) {
        /* Shouldn't happen if ldb_dn_validate()
         * passed, but we'll be careful.
         */
        DEBUG(SSSDBG_CRIT_FAILURE, "No RDN name in %s\n", group_dn);
        ret = ERR_MALFORMED_ENTRY;
        goto done;
    }

    if (strcasecmp("cn", rdn_name) != 0) {
        /* RDN has the wrong attribute name.
         * It's not a group.
         */
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Expected cn in RDN, got %s\n", rdn_name);
        ret = ERR_UNEXPECTED_ENTRY_TYPE;
        goto done;
    }

    /* and the second component is "cn=groups" */
    group_comp_name = ldb_dn_get_component_name(dn, 1);
    if (strcasecmp("cn", group_comp_name) != 0) {
        /* The second component name is not "cn" */
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Expected cn in second component, got %s\n", group_comp_name);
        ret = ERR_UNEXPECTED_ENTRY_TYPE;
        goto done;
    }

    group_comp_val = ldb_dn_get_component_val(dn, 1);
    if (strncasecmp("groups",
                    (const char *) group_comp_val->data,
                    group_comp_val->length) != 0) {
        /* The second component value is not "groups" */
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Expected groups second component, got %s\n",
              (const char *) group_comp_val->data);
        ret = ERR_UNEXPECTED_ENTRY_TYPE;
        goto done;
    }

    /* and the third component is "accounts" */
    account_comp_name = ldb_dn_get_component_name(dn, 2);
    if (strcasecmp("cn", account_comp_name) != 0) {
        /* The third component name is not "cn" */
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Expected cn in third component, got %s\n", account_comp_name);
        ret = ERR_UNEXPECTED_ENTRY_TYPE;
        goto done;
    }

    account_comp_val = ldb_dn_get_component_val(dn, 2);
    if (strncasecmp("accounts",
                    (const char *) account_comp_val->data,
                    account_comp_val->length) != 0) {
        /* The third component value is not "accounts" */
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Expected accounts third component, got %s\n",
              (const char *) account_comp_val->data);
        ret = ERR_UNEXPECTED_ENTRY_TYPE;
        goto done;
    }

    /* Then the value of the RDN is the group name */
    rdn_val = ldb_dn_get_rdn_val(dn);
    *groupname = talloc_strndup(mem_ctx,
                                (const char *)rdn_val->data,
                                rdn_val->length);
    if (*groupname == NULL) {
        ret = ENOMEM;
        goto done;
    }
    DEBUG(SSSDBG_TRACE_LIBS, "Parsed %s out of the DN\n", *groupname);

    ret = EOK;

done:
    talloc_free(dn);
    return ret;
}

errno_t
hbac_user_attrs_to_rule(TALLOC_CTX *mem_ctx,
                        struct sss_domain_info *domain,
                        const char *rule_name,
                        struct sysdb_attrs *rule_attrs,
                        struct hbac_rule_element **users)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx = NULL;
    struct hbac_rule_element *new_users = NULL;
    struct ldb_message_element *el = NULL;
    struct ldb_message **msgs = NULL;
    const char *member_dn;
    const char *attrs[] = { SYSDB_NAME, NULL };
    size_t num_users = 0;
    size_t num_groups = 0;
    const char *sysdb_name;
    char *shortname;

    size_t count;
    size_t i;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) return ENOMEM;

    new_users = talloc_zero(tmp_ctx, struct hbac_rule_element);
    if (new_users == NULL) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "Processing users for rule [%s]\n", rule_name);

    ret = hbac_get_category(rule_attrs, IPA_USER_CATEGORY,
                            &new_users->category);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not identify user categories\n");
        goto done;
    }
    if (new_users->category & HBAC_CATEGORY_ALL) {
        /* Short-cut to the exit */
        ret = EOK;
        goto done;
    }

    ret = sysdb_attrs_get_el(rule_attrs, IPA_MEMBER_USER, &el);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_attrs_get_el failed.\n");
        goto done;
    }
    if (ret == ENOENT || el->num_values == 0) {
        el->num_values = 0;
        DEBUG(SSSDBG_CONF_SETTINGS,
              "No user specified, rule will never apply.\n");
    }

    new_users->names = talloc_array(new_users,
                                    const char *,
                                    el->num_values + 1);
    if (new_users->names == NULL) {
        ret = ENOMEM;
        goto done;
    }

    new_users->groups = talloc_array(new_users,
                                     const char *,
                                     el->num_values + 1);
    if (new_users->groups == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < el->num_values; i++) {
        member_dn = (const char *)el->values[i].data;

        /* First check if this is a user */
        ret = sysdb_search_users_by_orig_dn(tmp_ctx, domain, member_dn, attrs,
                                            &count, &msgs);
        if (ret != EOK && ret != ENOENT) goto done;
        if (ret == EOK && count == 0) {
            ret = ENOENT;
        }

        if (ret == EOK) {
            if (count > 1) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Original DN matched multiple users. Skipping \n");
                continue;
            }

            /* Original DN matched a single user. Get the username */
            sysdb_name = ldb_msg_find_attr_as_string(msgs[0], SYSDB_NAME, NULL);
            if (sysdb_name == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Attribute is missing!\n");
                ret = EFAULT;
                goto done;
            }

            ret = sss_parse_internal_fqname(tmp_ctx, sysdb_name,
                                            &shortname, NULL);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Cannot parse %s, skipping\n", sysdb_name);
                continue;
            }

            new_users->names[num_users] = talloc_strdup(new_users->names,
                                                        shortname);
            if (new_users->names[num_users] == NULL) {
                ret = ENOMEM;
                goto done;
            }
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "Added user [%s] to rule [%s]\n", sysdb_name, rule_name);
            num_users++;
        } else {
            /* Check if it is a group instead */
            ret = sysdb_search_groups_by_orig_dn(tmp_ctx, domain, member_dn,
                                                 attrs, &count, &msgs);
            if (ret != EOK && ret != ENOENT) goto done;
            if (ret == EOK && count == 0) {
                ret = ENOENT;
            }

            if (ret == EOK) {
                if (count > 1) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Original DN matched multiple groups. "
                              "Skipping\n");
                    continue;
                }

                /* Original DN matched a single group. Get the groupname */
                sysdb_name = ldb_msg_find_attr_as_string(msgs[0],
                                                         SYSDB_NAME, NULL);
                if (sysdb_name == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "Attribute is missing!\n");
                    ret = EFAULT;
                    goto done;
                }

                ret = sss_parse_internal_fqname(tmp_ctx, sysdb_name,
                                                &shortname, NULL);
                if (ret != EOK) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                        "Cannot parse %s, skipping\n", sysdb_name);
                    continue;
                }

                new_users->groups[num_groups] =
                        talloc_strdup(new_users->groups, shortname);
                if (new_users->groups[num_groups] == NULL) {
                    ret = ENOMEM;
                    goto done;
                }
                DEBUG(SSSDBG_TRACE_INTERNAL,
                      "Added POSIX group [%s] to rule [%s]\n",
                       sysdb_name, rule_name);
                num_groups++;
            } else {
                /* If the group still matches the group pattern,
                 * we can assume it is a non-POSIX group.
                 */
                ret = get_ipa_groupname(new_users->groups, domain->sysdb,
                                        member_dn,
                                        &new_users->groups[num_groups]);
                if (ret == EOK) {
                    DEBUG(SSSDBG_TRACE_INTERNAL,
                          "Added non-POSIX group [%s] to rule [%s]\n",
                              new_users->groups[num_groups], rule_name);
                    num_groups++;
                } else {
                    /* Not a group, so we don't care about it */
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "[%s] does not map to either a user or group. "
                              "Skipping\n", member_dn);
                }
            }
        }
    }
    new_users->names[num_users] = NULL;
    new_users->groups[num_groups] = NULL;

    /* Shrink the arrays down to their real sizes */
    new_users->names = talloc_realloc(new_users, new_users->names,
                                      const char *, num_users + 1);
    if (new_users->names == NULL) {
        ret = ENOMEM;
        goto done;
    }

    new_users->groups = talloc_realloc(new_users, new_users->groups,
                                      const char *, num_groups + 1);
    if (new_users->groups == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;
done:
    if (ret == EOK) {
        *users = talloc_steal(mem_ctx, new_users);
    }
    talloc_free(tmp_ctx);

    return ret;
}
