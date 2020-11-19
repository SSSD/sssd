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
#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_rules_common.h"

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
            DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_attrs_replace_name failed.\n");
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
    struct hbac_eval_req *new_request = NULL;
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
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not construct rules\n");
            goto done;
        }
    }
    new_rules[i] = NULL;

    /* Create the eval request */
    ret = hbac_ctx_to_eval_request(tmp_ctx, hbac_ctx, &new_request);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not construct eval request\n");
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
        DEBUG(SSSDBG_CONF_SETTINGS, "rule has no name, assuming '(none)'.\n");
        new_rule->name = talloc_strdup(new_rule, "(none)");
    } else {
        new_rule->name = talloc_strndup(new_rule,
                                        (const char*) el->values[0].data,
                                        el->values[0].length);
    }

    DEBUG(SSSDBG_TRACE_LIBS, "Processing rule [%s]\n", new_rule->name);

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
        DEBUG(SSSDBG_TRACE_LIBS,
              "Rule [%s] is not an ALLOW rule\n", new_rule->name);
        ret = EPERM;
        goto done;
    }

    /* Get the users */
    ret = hbac_user_attrs_to_rule(new_rule, hbac_ctx->be_ctx->domain,
                                  new_rule->name,
                                  hbac_ctx->rules[idx],
                                  &new_rule->users);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not parse users for rule [%s]\n",
                  new_rule->name);
        goto done;
    }

    /* Get the services */
    ret = hbac_service_attrs_to_rule(new_rule, hbac_ctx->be_ctx->domain,
                                     new_rule->name,
                                     hbac_ctx->rules[idx],
                                     &new_rule->services);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not parse services for rule [%s]\n",
                  new_rule->name);
        goto done;
    }

    /* Get the target hosts */
    ret = hbac_thost_attrs_to_rule(new_rule, hbac_ctx->be_ctx->domain,
                                   new_rule->name,
                                   hbac_ctx->rules[idx],
                                   &new_rule->targethosts);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not parse target hosts for rule [%s]\n",
                  new_rule->name);
        goto done;
    }

    /* Get the source hosts */

    ret = hbac_shost_attrs_to_rule(new_rule, hbac_ctx->be_ctx->domain,
                                   new_rule->name,
                                   hbac_ctx->rules[idx],
                                   dp_opt_get_bool(hbac_ctx->ipa_options,
                                                   IPA_HBAC_SUPPORT_SRCHOST),
                                   &new_rule->srchosts);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not parse source hosts for rule [%s]\n",
                  new_rule->name);
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
                DEBUG(SSSDBG_FUNC_DATA, "Category is set to 'all'.\n");
                cats |= HBAC_CATEGORY_ALL;
                continue;
            }
            DEBUG(SSSDBG_TRACE_ALL, "Unsupported user category [%s].\n",
                      categories[i]);
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
                       struct sss_domain_info *domain,
                       const char *username,
                       struct hbac_request_element **user_element);

static errno_t
hbac_eval_service_element(TALLOC_CTX *mem_ctx,
                          struct sss_domain_info *domain,
                          const char *servicename,
                          struct hbac_request_element **svc_element);

static errno_t
hbac_eval_host_element(TALLOC_CTX *mem_ctx,
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
    struct sss_domain_info *domain = hbac_ctx->be_ctx->domain;
    const char *rhost;
    const char *thost;
    struct sss_domain_info *user_dom;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) return ENOMEM;

    eval_req = talloc_zero(tmp_ctx, struct hbac_eval_req);
    if (eval_req == NULL) {
        ret = ENOMEM;
        goto done;
    }

    eval_req->request_time = time(NULL);

    /* Get user the user name and groups,
     * take care of subdomain users as well */
    if (strcasecmp(pd->domain, domain->name) != 0) {
        user_dom = find_domain_by_name(domain, pd->domain, true);
        if (user_dom == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "find_domain_by_name failed.\n");
            ret = ENOMEM;
            goto done;
        }
        ret = hbac_eval_user_element(eval_req, user_dom, pd->user,
                                     &eval_req->user);
    } else {
        ret = hbac_eval_user_element(eval_req, domain, pd->user,
                                     &eval_req->user);
    }
    if (ret != EOK) goto done;

    /* Get the PAM service and service groups */
    ret = hbac_eval_service_element(eval_req, domain, pd->service,
                                    &eval_req->service);
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

    ret = hbac_eval_host_element(eval_req, domain, rhost,
                                 &eval_req->srchost);
    if (ret != EOK) goto done;

    /* The target host is always the current machine */
    thost = dp_opt_get_cstring(hbac_ctx->ipa_options, IPA_HOSTNAME);
    if (thost == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Missing ipa_hostname, this should never happen.\n");
        ret = EINVAL;
        goto done;
    }

    ret = hbac_eval_host_element(eval_req, domain, thost,
                                 &eval_req->targethost);
    if (ret != EOK) goto done;

    *request = talloc_steal(mem_ctx, eval_req);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
hbac_eval_user_element(TALLOC_CTX *mem_ctx,
                       struct sss_domain_info *domain,
                       const char *username,
                       struct hbac_request_element **user_element)
{
    errno_t ret;
    unsigned int num_groups = 0;
    TALLOC_CTX *tmp_ctx;
    struct hbac_request_element *users;
    char *shortname;
    const char *fqgroupname = NULL;
    struct sss_domain_info *ipa_domain;
    struct ldb_dn *ipa_groups_basedn;
    struct ldb_result *res;
    int exp_comp;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) return ENOMEM;

    users = talloc_zero(tmp_ctx, struct hbac_request_element);
    if (users == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_parse_internal_fqname(tmp_ctx, username, &shortname, NULL);
    if (ret != EOK) {
        ret = ERR_WRONG_NAME_FORMAT;
        goto done;
    }
    users->name = talloc_steal(users, shortname);

    ipa_domain = get_domains_head(domain);
    if (ipa_domain == NULL) {
        ret = EINVAL;
        goto done;
    }

    ipa_groups_basedn = ldb_dn_new_fmt(tmp_ctx, sysdb_ctx_get_ldb(domain->sysdb),
                                       SYSDB_TMPL_GROUP_BASE, ipa_domain->name);
    if (ipa_groups_basedn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* +1 because there will be a RDN preceding the base DN */
    exp_comp = ldb_dn_get_comp_num(ipa_groups_basedn) + 1;

    /*
     * Get all the groups the user is a member of.
     * This includes both POSIX and non-POSIX groups.
     */
    ret = sysdb_initgroups(tmp_ctx, domain, username, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sysdb_initgroups() failed [%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    if (res->count == 0) {
        /* This should not happen at this point */
        DEBUG(SSSDBG_MINOR_FAILURE,
              "User [%s] not found in cache.\n", username);
        ret = ENOENT;
        goto done;
    } else if (res->count == 1) {
        /* The first item is the user entry */
        DEBUG(SSSDBG_TRACE_LIBS, "No groups for [%s]\n", users->name);
        ret = create_empty_grouplist(users);
        goto done;
    }
    DEBUG(SSSDBG_TRACE_LIBS,
          "[%u] groups for [%s]\n", res->count - 1, username);

    /* This also includes the sentinel, b/c we'll skip the user entry below */
    users->groups = talloc_array(users, const char *, res->count);
    if (users->groups == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Start counting from 1 to exclude the user entry */
    for (size_t i = 1; i < res->count; i++) {
        /* Only groups from the IPA domain can be referenced from HBAC rules. To
         * avoid evaluating groups which might even have the same name, but come
         * from a trusted domain, we first copy the DN to a temporary one..
         */
        if (ldb_dn_get_comp_num(res->msgs[i]->dn) != exp_comp
                || ldb_dn_compare_base(ipa_groups_basedn,
                                       res->msgs[i]->dn) != 0) {
            DEBUG(SSSDBG_FUNC_DATA,
                  "Skipping non-IPA group %s\n",
                  ldb_dn_get_linearized(res->msgs[i]->dn));
            continue;
        }

        fqgroupname = ldb_msg_find_attr_as_string(res->msgs[i], SYSDB_NAME, NULL);
        if (fqgroupname == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Skipping malformed entry [%s]\n",
                  ldb_dn_get_linearized(res->msgs[i]->dn));
            continue;
        }

        ret = sss_parse_internal_fqname(tmp_ctx, fqgroupname,
                                        &shortname, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Malformed name %s, skipping!\n", fqgroupname);
            continue;
        }

        users->groups[num_groups] = talloc_steal(users->groups, shortname);
        DEBUG(SSSDBG_TRACE_LIBS, "Added group [%s] for user [%s]\n",
              users->groups[num_groups], users->name);
        num_groups++;
    }
    users->groups[num_groups] = NULL;

    if (num_groups < (res->count - 1)) {
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

    svc_dn = sysdb_custom_dn(tmp_ctx, domain, svc->name, HBAC_SERVICES_SUBDIR);
    if (svc_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Look up the service to get its originalMemberOf entries */
    ret = sysdb_search_entry(tmp_ctx, domain->sysdb, svc_dn,
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
        DEBUG(SSSDBG_CRIT_FAILURE, "More than one result for a BASE search!\n");
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
        ret = get_ipa_servicegroupname(tmp_ctx, domain->sysdb,
                                       (const char *)el->values[i].data,
                                       &name);
        if (ret != EOK && ret != ERR_UNEXPECTED_ENTRY_TYPE) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Skipping malformed entry [%s]\n",
                                        (const char *)el->values[i].data);
            continue;
        }

        /* ERR_UNEXPECTED_ENTRY_TYPE means we had a memberOf entry that wasn't a
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

    host_dn = sysdb_custom_dn(tmp_ctx, domain, host->name, HBAC_HOSTS_SUBDIR);
    if (host_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Look up the host to get its originalMemberOf entries */
    ret = sysdb_search_entry(tmp_ctx, domain->sysdb, host_dn,
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
        DEBUG(SSSDBG_CRIT_FAILURE, "More than one result for a BASE search!\n");
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
        ret = ipa_common_get_hostgroupname(tmp_ctx, domain->sysdb,
                                           (const char *)el->values[i].data,
                                           &name);
        if (ret != EOK && ret != ERR_UNEXPECTED_ENTRY_TYPE) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Skipping malformed entry [%s]\n",
                                        (const char *)el->values[i].data);
            continue;
        }

        /* ERR_UNEXPECTED_ENTRY_TYPE means we had a memberOf entry that wasn't a
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

const char **
hbac_get_attrs_to_get_cached_rules(TALLOC_CTX *mem_ctx)
{
    const char **attrs = talloc_zero_array(mem_ctx, const char *, 16);
    if (attrs == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero_array() failed\n");
        goto done;
    }

    attrs[0] = OBJECTCLASS;
    attrs[1] = IPA_CN;
    attrs[2] = SYSDB_ORIG_DN;
    attrs[3] = IPA_UNIQUE_ID;
    attrs[4] = IPA_ENABLED_FLAG;
    attrs[5] = IPA_ACCESS_RULE_TYPE;
    attrs[6] = IPA_MEMBER_USER;
    attrs[7] = IPA_USER_CATEGORY;
    attrs[8] = IPA_MEMBER_SERVICE;
    attrs[9] = IPA_SERVICE_CATEGORY;
    attrs[10] = IPA_SOURCE_HOST;
    attrs[11] = IPA_SOURCE_HOST_CATEGORY;
    attrs[12] = IPA_EXTERNAL_HOST;
    attrs[13] = IPA_MEMBER_HOST;
    attrs[14] = IPA_HOST_CATEGORY;
    attrs[15] = NULL;

done:
    return attrs;
}
