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

        ret = sysdb_delete_recursive(tmp_ctx, sysdb, base_dn, true);
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

        ret = sysdb_store_custom(tmp_ctx, sysdb, domain, object_name, subdir,
                                 list[c]);
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
    int lret;
    errno_t ret, sret;
    bool in_transaction = false;
    const char **orig_member_dns;
    size_t i, j, member_count;
    struct ldb_message **members;
    TALLOC_CTX *tmp_ctx = NULL;
    const char *member_dn;
    const char *group_id;
    struct ldb_message *msg;
    char *member_filter;

    if ((primary_count == 0 || primary == NULL)
        || (group_count > 0 && groups == NULL)) {
        /* There always has to be at least one
         * primary entry.
         */
        return EINVAL;
    }

    /* Save the entries and groups to the cache */
    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) return ret;
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

        /* Third, save the memberships */
        for (i = 0; i < group_count; i++) {
            if (!groups[i]) {
                ret = EINVAL;
                goto done;
            }

            talloc_free(tmp_ctx);
            tmp_ctx = talloc_new(NULL);
            if (tmp_ctx == NULL) {
                ret = ENOMEM;
                goto done;
            }

            ret = sysdb_attrs_get_string(groups[i],
                                         groupattr_name,
                                         &group_id);
            if (ret != EOK) {
                DEBUG(1, ("Could not determine group attribute name\n"));
                goto done;
            }

            msg = ldb_msg_new(tmp_ctx);
            if (msg == NULL) {
                ret = ENOMEM;
                goto done;
            }

            msg->dn = sysdb_custom_dn(sysdb, msg, domain->name,
                                      group_id, group_subdir);
            if (msg->dn == NULL) {
                ret = ENOMEM;
                goto done;
            }

            ret = sysdb_attrs_get_string_array(groups[i],
                                               SYSDB_ORIG_MEMBER,
                                               tmp_ctx,
                                               &orig_member_dns);

            if (ret == EOK) {
                /* One or more members were detected, prep the LDB message */
                lret = ldb_msg_add_empty(msg, SYSDB_MEMBER, LDB_FLAG_MOD_ADD, NULL);
                if (lret != LDB_SUCCESS) {
                    ret = sysdb_error_to_errno(lret);
                    goto done;
                }
            } else if (ret == ENOENT) {
                /* Useless group, has no members */
                orig_member_dns = talloc_array(tmp_ctx, const char *, 1);
                if (!orig_member_dns) {
                    ret = ENOMEM;
                    goto done;
                }

                /* Just set the member list to zero length so we skip
                 * processing it below
                 */
                orig_member_dns[0] = NULL;
            } else {
                DEBUG(1, ("Could not determine original members\n"));
                goto done;
            }

            for (j = 0; orig_member_dns[j]; j++) {
                member_filter = talloc_asprintf(tmp_ctx, "%s=%s",
                                                SYSDB_ORIG_DN,
                                                orig_member_dns[j]);
                if (member_filter == NULL) {
                    ret = ENOMEM;
                    goto done;
                }

                ret = sysdb_search_custom(tmp_ctx, sysdb, domain,
                                          member_filter, primary_subdir,
                                          NULL, &member_count, &members);
                talloc_zfree(member_filter);
                if (ret != EOK && ret != ENOENT) {
                    goto done;
                } else if (ret == ENOENT || member_count == 0) {
                    /* No member exists with this orig_dn. Skip it */
                    DEBUG(6, ("[%s] does not exist\n", orig_member_dns[j]));
                    continue;
                } else if (member_count > 1) {
                    /* This probably means corruption in the cache, but
                     * we'll try to proceed anyway.
                     */
                    DEBUG(1, ("More than one result for DN [%s], skipping\n"));
                    continue;
                }

                member_dn = ldb_dn_get_linearized(members[0]->dn);
                if (!member_dn) {
                    ret = ENOMEM;
                    goto done;
                }
                lret = ldb_msg_add_fmt(msg, SYSDB_MEMBER, "%s", member_dn);
                if (lret != LDB_SUCCESS) {
                    ret = sysdb_error_to_errno(lret);
                    goto done;
                }
            }

            lret = ldb_modify(sysdb_ctx_get_ldb(sysdb), msg);
            if (lret != LDB_SUCCESS) {
                ret = sysdb_error_to_errno(lret);
                goto done;
            }
        }
        talloc_zfree(tmp_ctx);
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret != EOK) goto done;
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
            DEBUG(1, ("Could not construct rules\n"))
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
                                  hbac_ctx_be(hbac_ctx)->domain,
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
                                     hbac_ctx_be(hbac_ctx)->domain,
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
                                   hbac_ctx_be(hbac_ctx)->domain,
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
                                   hbac_ctx_be(hbac_ctx)->domain,
                                   new_rule->name,
                                   hbac_ctx->rules[idx],
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
                       struct sss_domain_info *domain,
                       const char *username,
                       struct hbac_request_element **user_element);

static errno_t
hbac_eval_service_element(TALLOC_CTX *mem_ctx,
                          struct sysdb_ctx *sysdb,
                          struct sss_domain_info *domain,
                          const char *hostname,
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
    ret = hbac_eval_user_element(eval_req, sysdb, domain,
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
                       struct sss_domain_info *domain,
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
    ret = sysdb_search_user_by_name(tmp_ctx, sysdb, domain,
                                    users->name, attrs, &msg);
    if (ret != EOK) {
        DEBUG(1, ("Could not determine user memberships for [%s]\n",
                  users->name));
        goto done;
    }

    el = ldb_msg_find_element(msg, SYSDB_ORIG_MEMBEROF);
    if (el == NULL || el->num_values == 0) {
        DEBUG(7, ("No groups for [%s]\n", users->name));
        users->groups = talloc_array(users, const char *, 1);
        if (users->groups == NULL) {
            ret = ENOMEM;
            goto done;
        }
        users->groups[0] = NULL;
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
                          const char *hostname,
                          struct hbac_request_element **svc_element)
{
    errno_t ret;
    size_t i, count;
    TALLOC_CTX *tmp_ctx;
    struct hbac_request_element *svc;
    struct ldb_message **msgs;
    const char *group_name;
    struct ldb_dn *svc_dn;
    const char *attrs[] = { IPA_CN, NULL };
    const char *service_filter;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) return ENOMEM;

    svc = talloc_zero(tmp_ctx, struct hbac_request_element);
    if (svc == NULL) {
        ret = ENOMEM;
        goto done;
    }

    svc->name = hostname;

    service_filter = talloc_asprintf(tmp_ctx,
                                     "(objectClass=%s)",
                                     IPA_HBAC_SERVICE_GROUP);
    if (service_filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    svc_dn = sysdb_custom_dn(sysdb, tmp_ctx, domain->name,
                             svc->name, HBAC_SERVICES_SUBDIR);
    if (svc_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Find the service groups */
    ret = sysdb_asq_search(tmp_ctx, sysdb, domain, svc_dn,
                           service_filter, SYSDB_MEMBEROF,
                           attrs, &count, &msgs);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(1, ("Could not look up servicegroups\n"));
        goto done;
    } else if (ret == ENOENT) {
        count = 0;
    }

    svc->groups = talloc_array(svc, const char *, count + 1);
    if (svc->groups == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < count; i++) {
        group_name = ldb_msg_find_attr_as_string(msgs[i], IPA_CN, NULL);
        if (group_name == NULL) {
            DEBUG(1, ("Group with no name?\n"));
            ret = EINVAL;
            goto done;
        }
        svc->groups[i] = talloc_strdup(svc->groups,
                                       group_name);
        if (svc->groups[i] == NULL) {
            ret = ENOMEM;
            goto done;
        }

        DEBUG(6, ("Added service group [%s] to the eval request\n",
                  svc->groups[i]));
    }
    svc->groups[i] = NULL;

    *svc_element = talloc_steal(mem_ctx, svc);
    ret = EOK;

done:
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
    size_t i, count;
    TALLOC_CTX *tmp_ctx;
    struct hbac_request_element *host;
    struct ldb_message **msgs;
    const char *group_name;
    struct ldb_dn *host_dn;
    const char *attrs[] = { IPA_HOST_FQDN, NULL };
    const char *host_filter;

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
        host->groups = talloc_array(host, const char *, 1);
        if (host->groups == NULL) {
            ret = ENOMEM;
            goto done;
        }
        host->groups[0] = NULL;
        ret = EOK;
        goto done;
    }

    host_filter = talloc_asprintf(tmp_ctx,
                                  "(objectClass=%s)",
                                  IPA_HOSTGROUP);
    if (host_filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    host_dn = sysdb_custom_dn(sysdb, tmp_ctx, domain->name,
                             host->name, HBAC_SERVICES_SUBDIR);
    if (host_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Find the host groups */
    ret = sysdb_asq_search(tmp_ctx, sysdb, domain, host_dn,
                           host_filter, SYSDB_MEMBEROF,
                           attrs, &count, &msgs);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(1, ("Could not look up host groups\n"));
        goto done;
    } else if (ret == ENOENT) {
        count = 0;
    }

    host->groups = talloc_array(host, const char *, count + 1);
    if (host->groups == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < count; i++) {
        group_name = ldb_msg_find_attr_as_string(msgs[i],
                                                 IPA_HOST_FQDN,
                                                 NULL);
        if (group_name == NULL) {
            DEBUG(1, ("Group with no name?\n"));
            ret = EINVAL;
            goto done;
        }
        host->groups[i] = talloc_strdup(host->groups,
                                       group_name);
        if (host->groups[i] == NULL) {
            ret = ENOMEM;
            goto done;
        }

        DEBUG(6, ("Added host group [%s] to the eval request\n",
                  host->groups[i]));
    }
    host->groups[i] = NULL;

    ret = EOK;

done:
    if (ret == EOK) {
        *host_element = talloc_steal(mem_ctx, host);
    }
    talloc_free(tmp_ctx);
    return ret;
}
