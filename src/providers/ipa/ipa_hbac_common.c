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

#include "providers/ipa/ipa_hbac_private.h"
#include "providers/ipa/ipa_hbac.h"
#include "providers/ipa/ipa_common.h"

errno_t
ipa_hbac_save_list(struct sysdb_ctx *sysdb, bool delete_subdir,
                   const char *subdir, struct sss_domain_info *domain,
                   const char *naming_attribute, size_t count,
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
        DEBUG(1, ("talloc_new failed.\n"));
        return ENOMEM;
    }

    if (delete_subdir) {
        base_dn = sysdb_custom_subtree_dn(sysdb, tmp_ctx, domain->name, subdir);
        if (base_dn == NULL) {
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_delete_recursive(sysdb, base_dn, true);
        if (ret != EOK) {
            DEBUG(1, ("sysdb_delete_recursive failed.\n"));
            goto done;
        }
    }

    for (c = 0; c < count; c++) {
        ret = sysdb_attrs_get_el(list[c], naming_attribute, &el);
        if (ret != EOK) {
            DEBUG(1, ("sysdb_attrs_get_el failed.\n"));
            goto done;
        }
        if (el->num_values == 0) {
            DEBUG(1, ("[%s] not found.\n", naming_attribute));
            ret = EINVAL;
            goto done;
        }
        object_name = talloc_strndup(tmp_ctx, (const char *)el->values[0].data,
                                     el->values[0].length);
        if (object_name == NULL) {
            DEBUG(1, ("talloc_strndup failed.\n"));
            ret = ENOMEM;
            goto done;
        }
        DEBUG(9, ("Object name: [%s].\n", object_name));

        ret = sysdb_store_custom(sysdb, object_name, subdir, list[c]);
        if (ret != EOK) {
            DEBUG(1, ("sysdb_store_custom failed.\n"));
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
ipa_hbac_sysdb_save(struct sysdb_ctx *sysdb, struct sss_domain_info *domain,
                    const char *primary_subdir, const char *attr_name,
                    size_t primary_count, struct sysdb_attrs **primary,
                    const char *group_subdir, const char *groupattr_name,
                    size_t group_count, struct sysdb_attrs **groups)
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
    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to start transaction\n"));
        goto done;
    };
    in_transaction = true;

    /* First, save the specific entries */
    ret = ipa_hbac_save_list(sysdb, true,
                             primary_subdir,
                             domain,
                             attr_name,
                             primary_count,
                             primary);
    if (ret != EOK) {
        DEBUG(1, ("Could not save %s. [%d][%s]\n",
                  primary_subdir, ret, strerror(ret)));
        goto done;
    }

    /* Second, save the groups */
    if (group_count > 0) {
        ret = ipa_hbac_save_list(sysdb, true,
                                 group_subdir,
                                 domain,
                                 groupattr_name,
                                 group_count,
                                 groups);
        if (ret != EOK) {
            DEBUG(1, ("Could not save %s. [%d][%s]\n",
                      group_subdir, ret, strerror(ret)));
            goto done;
        }
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to commit transaction\n"));
        goto done;
    }
    in_transaction = false;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(0, ("Could not cancel sysdb transaction\n"));
        }
    }

    if (ret != EOK) {
        DEBUG(3, ("Error [%d][%s]\n", ret, strerror(ret)));
    }
    return ret;
}

errno_t
replace_attribute_name(const char *old_name,
                       const char *new_name, const size_t count,
                       struct sysdb_attrs **list)
{
    int ret;
    int i;

    for (i = 0; i < count; i++) {
        ret = sysdb_attrs_replace_name(list[i], old_name, new_name);
        if (ret != EOK) {
            DEBUG(1, ("sysdb_attrs_replace_name failed.\n"));
            return ret;
        }
    }

    return EOK;
}

static errno_t
create_empty_grouplist(struct hbac_request_element *el)
{
    el->groups = talloc_array(el, const char *, 1);
    if (!el->groups) return ENOMEM;

    el->groups[0] = NULL;
    return EOK;
}

/********************************************
 * Functions for handling conversion to the *
 * HBAC evaluator format                    *
 ********************************************/

static errno_t
hbac_attrs_to_rule(TALLOC_CTX *mem_ctx,
                   struct hbac_ctx *hbac_ctx,
                   size_t index,
                   struct hbac_rule **rule);

static errno_t
hbac_ctx_to_eval_request(TALLOC_CTX *mem_ctx,
                         struct hbac_ctx *hbac_ctx,
                         struct hbac_eval_req **request);

errno_t
hbac_ctx_to_rules(TALLOC_CTX *mem_ctx,
                  struct hbac_ctx *hbac_ctx,
                  struct hbac_rule ***rules,
                  struct hbac_eval_req **request)
{
    errno_t ret;
    struct hbac_rule **new_rules;
    struct hbac_eval_req *new_request;
    size_t i;
    TALLOC_CTX *tmp_ctx = NULL;

    if (!rules || !request) return EINVAL;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) return ENOMEM;

    /* First create an array of rules */
    new_rules = talloc_array(tmp_ctx, struct hbac_rule *,
                             hbac_ctx->rule_count + 1);
    if (new_rules == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Create each rule one at a time */
    for (i = 0; i < hbac_ctx->rule_count ; i++) {
        ret = hbac_attrs_to_rule(new_rules, hbac_ctx, i, &(new_rules[i]));
        if (ret == EPERM) {
            goto done;
        } else if (ret != EOK) {
            DEBUG(1, ("Could not construct rules\n"));
            goto done;
        }
    }
    new_rules[i] = NULL;

    /* Create the eval request */
    ret = hbac_ctx_to_eval_request(tmp_ctx, hbac_ctx, &new_request);
    if (ret != EOK) {
        DEBUG(1, ("Could not construct eval request\n"));
        goto done;
    }

    *rules = talloc_steal(mem_ctx, new_rules);
    *request = talloc_steal(mem_ctx, new_request);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
hbac_attrs_to_rule(TALLOC_CTX *mem_ctx,
                   struct hbac_ctx *hbac_ctx,
                   size_t idx,
                   struct hbac_rule **rule)
{
    errno_t ret;
    struct hbac_rule *new_rule;
    struct ldb_message_element *el;
    const char *rule_type;

    new_rule = talloc_zero(mem_ctx, struct hbac_rule);
    if (new_rule == NULL) return ENOMEM;

    ret = sysdb_attrs_get_el(hbac_ctx->rules[idx],
                             IPA_CN, &el);
    if (ret != EOK || el->num_values == 0) {
        DEBUG(4, ("rule has no name, assuming '(none)'.\n"));
        new_rule->name = talloc_strdup(new_rule, "(none)");
    } else {
        new_rule->name = talloc_strndup(new_rule,
                                        (const char*) el->values[0].data,
                                        el->values[0].length);
    }

    DEBUG(7, ("Processing rule [%s]\n", new_rule->name));

    ret = sysdb_attrs_get_bool(hbac_ctx->rules[idx], IPA_ENABLED_FLAG,
                               &new_rule->enabled);
    if (ret != EOK) goto done;

    if (!new_rule->enabled) {
        ret = EOK;
        goto done;
    }

    ret = sysdb_attrs_get_string(hbac_ctx->rules[idx],
                                 IPA_ACCESS_RULE_TYPE,
                                 &rule_type);
    if (ret != EOK) goto done;

    if (strcasecmp(rule_type, IPA_HBAC_ALLOW) != 0) {
        DEBUG(7, ("Rule [%s] is not an ALLOW rule\n", new_rule->name));
        ret = EPERM;
        goto done;
    }

    /* Get the users */
    ret = hbac_user_attrs_to_rule(new_rule,
                                  hbac_ctx_sysdb(hbac_ctx),
                                  new_rule->name,
                                  hbac_ctx->rules[idx],
                                  &new_rule->users);
    if (ret != EOK) {
        DEBUG(1, ("Could not parse users for rule [%s]\n",
                  new_rule->name));
        goto done;
    }

    /* Get the services */
    ret = hbac_service_attrs_to_rule(new_rule,
                                     hbac_ctx_sysdb(hbac_ctx),
                                     new_rule->name,
                                     hbac_ctx->rules[idx],
                                     &new_rule->services);
    if (ret != EOK) {
        DEBUG(1, ("Could not parse services for rule [%s]\n",
                  new_rule->name));
        goto done;
    }

    /* Get the target hosts */
    ret = hbac_thost_attrs_to_rule(new_rule,
                                   hbac_ctx_sysdb(hbac_ctx),
                                   new_rule->name,
                                   hbac_ctx->rules[idx],
                                   &new_rule->targethosts);
    if (ret != EOK) {
        DEBUG(1, ("Could not parse target hosts for rule [%s]\n",
                  new_rule->name));
        goto done;
    }

    /* Get the source hosts */

    ret = hbac_shost_attrs_to_rule(new_rule,
                                   hbac_ctx_sysdb(hbac_ctx),
                                   new_rule->name,
                                   hbac_ctx->rules[idx],
                                   dp_opt_get_bool(hbac_ctx->ipa_options,
                                                   IPA_HBAC_SUPPORT_SRCHOST),
                                   &new_rule->srchosts);
    if (ret != EOK) {
        DEBUG(1, ("Could not parse source hosts for rule [%s]\n",
                  new_rule->name));
        goto done;
    }

    *rule = new_rule;
    ret = EOK;

done:
    if (ret != EOK) talloc_free(new_rule);
    return ret;
}

errno_t
hbac_get_category(struct sysdb_attrs *attrs,
                  const char *category_attr,
                  uint32_t *_categories)
{
    errno_t ret;
    size_t i;
    uint32_t cats = HBAC_CATEGORY_NULL;
    const char **categories;

    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) return ENOMEM;

    ret = sysdb_attrs_get_string_array(attrs, category_attr,
                                       tmp_ctx, &categories);
    if (ret != EOK && ret != ENOENT) goto done;

    if (ret != ENOENT) {
        for (i = 0; categories[i]; i++) {
            if (strcasecmp("all", categories[i]) == 0) {
                DEBUG(5, ("Category is set to 'all'.\n"));
                cats |= HBAC_CATEGORY_ALL;
                continue;
            }
            DEBUG(9, ("Unsupported user category [%s].\n",
                      categories[i]));
        }
    }

    *_categories = cats;
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
hbac_eval_user_element(TALLOC_CTX *mem_ctx,
                       struct sysdb_ctx *sysdb,
                       const char *username,
                       struct hbac_request_element **user_element);

static errno_t
hbac_eval_service_element(TALLOC_CTX *mem_ctx,
                          struct sysdb_ctx *sysdb,
                          struct sss_domain_info *domain,
                          const char *servicename,
                          struct hbac_request_element **svc_element);

static errno_t
hbac_eval_host_element(TALLOC_CTX *mem_ctx,
                       struct sysdb_ctx *sysdb,
                       struct sss_domain_info *domain,
                       const char *hostname,
                       struct hbac_request_element **host_element);

static errno_t
hbac_ctx_to_eval_request(TALLOC_CTX *mem_ctx,
                         struct hbac_ctx *hbac_ctx,
                         struct hbac_eval_req **request)
{
    errno_t ret;
    struct pam_data *pd = hbac_ctx->pd;
    TALLOC_CTX *tmp_ctx;
    struct hbac_eval_req *eval_req;
    struct sysdb_ctx *sysdb = hbac_ctx_sysdb(hbac_ctx);
    struct sss_domain_info *domain = hbac_ctx_be(hbac_ctx)->domain;
    const char *rhost;
    const char *thost;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) return ENOMEM;

    eval_req = talloc_zero(tmp_ctx, struct hbac_eval_req);
    if (eval_req == NULL) {
        ret = ENOMEM;
        goto done;
    }

    eval_req->request_time = time(NULL);

    /* Get user the user name and groups */
    ret = hbac_eval_user_element(eval_req, sysdb,
                                 pd->user, &eval_req->user);
    if (ret != EOK) goto done;

    /* Get the PAM service and service groups */
    ret = hbac_eval_service_element(eval_req, sysdb, domain,
                                    pd->service, &eval_req->service);
    if (ret != EOK) goto done;

    /* Get the source host */
    if (pd->rhost == NULL || pd->rhost[0] == '\0') {
            /* If we haven't been passed an rhost,
             * the rhost is unknown. This will fail
             * to match any rule requiring the
             * source host.
             */
        rhost = NULL;
    } else {
        rhost = pd->rhost;
    }

    ret = hbac_eval_host_element(eval_req, sysdb, domain,
                                 rhost, &eval_req->srchost);
    if (ret != EOK) goto done;

    /* The target host is always the current machine */
    thost = dp_opt_get_cstring(hbac_ctx->ipa_options, IPA_HOSTNAME);
    if (thost == NULL) {
        DEBUG(1, ("Missing ipa_hostname, this should never happen.\n"));
        ret = EINVAL;
        goto done;
    }

    ret = hbac_eval_host_element(eval_req, sysdb, domain,
                                 thost, &eval_req->targethost);
    if (ret != EOK) goto done;

    *request = talloc_steal(mem_ctx, eval_req);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
hbac_eval_user_element(TALLOC_CTX *mem_ctx,
                       struct sysdb_ctx *sysdb,
                       const char *username,
                       struct hbac_request_element **user_element)
{
    errno_t ret;
    unsigned int i;
    unsigned int num_groups = 0;
    TALLOC_CTX *tmp_ctx;
    const char *member_dn;
    struct hbac_request_element *users;
    struct ldb_message *msg;
    struct ldb_message_element *el;
    const char *attrs[] = { SYSDB_ORIG_MEMBEROF, NULL };

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) return ENOMEM;

    users = talloc_zero(tmp_ctx, struct hbac_request_element);
    if (users == NULL) {
        ret = ENOMEM;
        goto done;
    }

    users->name = username;

    /* Read the originalMemberOf attribute
     * This will give us the list of both POSIX and
     * non-POSIX groups that this user belongs to.
     */
    ret = sysdb_search_user_by_name(tmp_ctx, sysdb, users->name, attrs, &msg);
    if (ret != EOK) {
        DEBUG(1, ("Could not determine user memberships for [%s]\n",
                  users->name));
        goto done;
    }

    el = ldb_msg_find_element(msg, SYSDB_ORIG_MEMBEROF);
    if (el == NULL || el->num_values == 0) {
        DEBUG(7, ("No groups for [%s]\n", users->name));
        ret = create_empty_grouplist(users);
        goto done;
    }
    DEBUG(7, ("[%d] groups for [%s]\n", el->num_values, users->name));

    users->groups = talloc_array(users, const char *, el->num_values + 1);
    if (users->groups == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < el->num_values; i++) {
        member_dn = (const char *)el->values[i].data;

        ret = get_ipa_groupname(users->groups, sysdb, member_dn,
                                &users->groups[num_groups]);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(3, ("Parse error on [%s]\n", member_dn));
            goto done;
        } else if (ret == EOK) {
            DEBUG(7, ("Added group [%s] for user [%s]\n",
                      users->groups[num_groups], users->name));
            num_groups++;
            continue;
        }
        /* Skip entries that are not groups */
        DEBUG(8, ("Skipping non-group memberOf [%s]\n", member_dn));
    }
    users->groups[num_groups] = NULL;

    if (num_groups < el->num_values) {
        /* Shrink the array memory */
        users->groups = talloc_realloc(users, users->groups, const char *,
                                       num_groups+1);
        if (users->groups == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = EOK;
done:
    if (ret == EOK) {
        *user_element = talloc_steal(mem_ctx, users);
    }
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
hbac_eval_service_element(TALLOC_CTX *mem_ctx,
                          struct sysdb_ctx *sysdb,
                          struct sss_domain_info *domain,
                          const char *servicename,
                          struct hbac_request_element **svc_element)
{
    errno_t ret;
    size_t i, j, count;
    TALLOC_CTX *tmp_ctx;
    struct hbac_request_element *svc;
    struct ldb_message **msgs;
    struct ldb_message_element *el;
    struct ldb_dn *svc_dn;
    const char *memberof_attrs[] = { SYSDB_ORIG_MEMBEROF, NULL };
    char *name;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) return ENOMEM;

    svc = talloc_zero(tmp_ctx, struct hbac_request_element);
    if (svc == NULL) {
        ret = ENOMEM;
        goto done;
    }

    svc->name = servicename;

    svc_dn = sysdb_custom_dn(sysdb, tmp_ctx, domain->name,
                             svc->name, HBAC_SERVICES_SUBDIR);
    if (svc_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Look up the service to get its originalMemberOf entries */
    ret = sysdb_search_entry(tmp_ctx, sysdb, svc_dn,
                             LDB_SCOPE_BASE, NULL,
                             memberof_attrs,
                             &count, &msgs);
    if (ret == ENOENT || count == 0) {
        /* We won't be able to identify any groups
         * This rule will only match the name or
         * a service category of ALL
         */
        ret = create_empty_grouplist(svc);
        goto done;
    } else if (ret != EOK) {
        goto done;
    } else if (count > 1) {
        DEBUG(1, ("More than one result for a BASE search!\n"));
        ret = EIO;
        goto done;
    }

    el = ldb_msg_find_element(msgs[0], SYSDB_ORIG_MEMBEROF);
    if (!el) {
        /* Service is not a member of any groups
         * This rule will only match the name or
         * a service category of ALL
         */
        ret = create_empty_grouplist(svc);
        goto done;
    }


    svc->groups = talloc_array(svc, const char *, el->num_values + 1);
    if (svc->groups == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = j = 0; i < el->num_values; i++) {
        ret = get_ipa_servicegroupname(tmp_ctx, sysdb,
                                       (const char *)el->values[i].data,
                                       &name);
        if (ret != EOK && ret != ENOENT) goto done;

        /* ENOENT means we had a memberOf entry that wasn't a
         * service group. We'll just ignore those (could be
         * HBAC rules)
         */

        if (ret == EOK) {
            svc->groups[j] = talloc_steal(svc->groups, name);
            j++;
        }
    }
    svc->groups[j] = NULL;

    ret = EOK;

done:
    if (ret == EOK) {
        *svc_element = talloc_steal(mem_ctx, svc);
    }
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
hbac_eval_host_element(TALLOC_CTX *mem_ctx,
                       struct sysdb_ctx *sysdb,
                       struct sss_domain_info *domain,
                       const char *hostname,
                       struct hbac_request_element **host_element)
{
    errno_t ret;
    size_t i, j, count;
    TALLOC_CTX *tmp_ctx;
    struct hbac_request_element *host;
    struct ldb_message **msgs;
    struct ldb_message_element *el;
    struct ldb_dn *host_dn;
    const char *memberof_attrs[] = { SYSDB_ORIG_MEMBEROF, NULL };
    char *name;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) return ENOMEM;

    host = talloc_zero(tmp_ctx, struct hbac_request_element);
    if (host == NULL) {
        ret = ENOMEM;
        goto done;
    }

    host->name = hostname;

    if (host->name == NULL) {
        /* We don't know the host (probably an rhost)
         * So we can't determine it's groups either.
         */
        ret = create_empty_grouplist(host);
        goto done;
    }

    host_dn = sysdb_custom_dn(sysdb, tmp_ctx, domain->name,
                              host->name, HBAC_HOSTS_SUBDIR);
    if (host_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Look up the host to get its originalMemberOf entries */
    ret = sysdb_search_entry(tmp_ctx, sysdb, host_dn,
                             LDB_SCOPE_BASE, NULL,
                             memberof_attrs,
                             &count, &msgs);
    if (ret == ENOENT || count == 0) {
        /* We won't be able to identify any groups
         * This rule will only match the name or
         * a host category of ALL
         */
        ret = create_empty_grouplist(host);
        goto done;
    } else if (ret != EOK) {
        goto done;
    } else if (count > 1) {
        DEBUG(1, ("More than one result for a BASE search!\n"));
        ret = EIO;
        goto done;
    }

    el = ldb_msg_find_element(msgs[0], SYSDB_ORIG_MEMBEROF);
    if (!el) {
        /* Host is not a member of any groups
         * This rule will only match the name or
         * a host category of ALL
         */
        ret = create_empty_grouplist(host);
        goto done;
    }


    host->groups = talloc_array(host, const char *, el->num_values + 1);
    if (host->groups == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = j = 0; i < el->num_values; i++) {
        ret = get_ipa_hostgroupname(tmp_ctx, sysdb,
                                    (const char *)el->values[i].data,
                                    &name);
        if (ret != EOK && ret != ENOENT) goto done;

        /* ENOENT means we had a memberOf entry that wasn't a
         * host group. We'll just ignore those (could be
         * HBAC rules)
         */

        if (ret == EOK) {
            host->groups[j] = talloc_steal(host->groups, name);
            j++;
        }
    }
    host->groups[j] = NULL;

    ret = EOK;

done:
    if (ret == EOK) {
        *host_element = talloc_steal(mem_ctx, host);
    }
    talloc_free(tmp_ctx);
    return ret;
}
