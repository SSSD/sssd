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
#include "providers/ldap/sdap_async.h"

struct ipa_hbac_host_state {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *dom;
    struct sdap_handle *sh;
    struct sdap_options *opts;
    const char *search_base;
    const char **attrs;

    /* Return values */
    size_t host_count;
    struct sysdb_attrs **hosts;

    size_t hostgroup_count;
    struct sysdb_attrs **hostgroups;
};

static void
ipa_hbac_host_info_done(struct tevent_req *subreq);

static void
ipa_hbac_hostgroup_info_done(struct tevent_req *subreq);

struct tevent_req *
ipa_hbac_host_info_send(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        struct sysdb_ctx *sysdb,
                        struct sss_domain_info *dom,
                        struct sdap_handle *sh,
                        struct sdap_options *opts,
                        const char *search_base)
{
    errno_t ret;
    struct ipa_hbac_host_state *state;
    struct tevent_req *req;
    struct tevent_req *subreq;
    char *host_filter;

    req = tevent_req_create(mem_ctx, &state, struct ipa_hbac_host_state);
    if (req == NULL) {
        return NULL;
    }

    state->ev = ev;
    state->sysdb = sysdb;
    state->dom = dom;
    state->sh = sh;
    state->opts = opts;
    state->search_base = search_base;

    host_filter = talloc_asprintf(state, "(objectClass=%s)", IPA_HOST);
    if (host_filter == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    state->attrs = talloc_array(state, const char *, 8);
    if (state->attrs == NULL) {
        DEBUG(1, ("Failed to allocate host attribute list.\n"));
        ret = ENOMEM;
        goto immediate;
    }
    state->attrs[0] = "objectClass";
    state->attrs[1] = IPA_HOST_SERVERHOSTNAME;
    state->attrs[2] = IPA_HOST_FQDN;
    state->attrs[3] = IPA_UNIQUE_ID;
    state->attrs[4] = IPA_MEMBER;
    state->attrs[5] = IPA_MEMBEROF;
    state->attrs[6] = IPA_CN;
    state->attrs[7] = NULL;

    subreq = sdap_get_generic_send(state, ev, opts, sh, search_base,
                                   LDAP_SCOPE_SUB, host_filter,
                                   state->attrs, NULL, 0,
                                   dp_opt_get_int(opts->basic,
                                                  SDAP_ENUM_SEARCH_TIMEOUT));
    if (subreq == NULL) {
        DEBUG(1, ("Error requesting host info\n"));
        ret = EIO;
        goto immediate;
    }
    tevent_req_set_callback(subreq, ipa_hbac_host_info_done, req);

    return req;

immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static void
ipa_hbac_host_info_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct ipa_hbac_host_state *state =
            tevent_req_data(req, struct ipa_hbac_host_state);
    char *hostgroup_filter;

    ret = sdap_get_generic_recv(subreq, state,
                                &state->host_count,
                                &state->hosts);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->host_count == 0) {
        tevent_req_error(req, ENOENT);
        return;
    }

    ret = replace_attribute_name(IPA_MEMBEROF, SYSDB_ORIG_MEMBEROF,
                                 state->host_count,
                                 state->hosts);
    if (ret != EOK) {
        DEBUG(1, ("Could not replace attribute names\n"));
        tevent_req_error(req, ret);
        return;
    }

    hostgroup_filter = talloc_asprintf(state, "(objectClass=%s)",
                                              IPA_HOSTGROUP);
    if (hostgroup_filter == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    /* Look up host groups */
    subreq = sdap_get_generic_send(state, state->ev, state->opts, state->sh,
                                   state->search_base, LDAP_SCOPE_SUB,
                                   hostgroup_filter, state->attrs, NULL, 0,
                                   dp_opt_get_int(state->opts->basic,
                                                  SDAP_ENUM_SEARCH_TIMEOUT));
    if (subreq == NULL) {
        DEBUG(1, ("Error requesting host info\n"));
        tevent_req_error(req, EIO);
        return;
    }
    tevent_req_set_callback(subreq, ipa_hbac_hostgroup_info_done, req);
}

static void
ipa_hbac_hostgroup_info_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct ipa_hbac_host_state *state =
            tevent_req_data(req, struct ipa_hbac_host_state);

    ret = sdap_get_generic_recv(subreq, state,
                                &state->hostgroup_count,
                                &state->hostgroups);
    talloc_zfree(subreq);
    if (ret != EOK) goto done;

    ret = replace_attribute_name(IPA_MEMBER, SYSDB_ORIG_MEMBER,
                                 state->hostgroup_count,
                                 state->hostgroups);
    if (ret != EOK) {
        DEBUG(1, ("Could not replace attribute names\n"));
        goto done;
    }

    ret = replace_attribute_name(IPA_MEMBEROF, SYSDB_ORIG_MEMBEROF,
                                 state->hostgroup_count,
                                 state->hostgroups);
    if (ret != EOK) {
        DEBUG(1, ("Could not replace attribute names\n"));
        goto done;
    }

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        DEBUG(3, ("Error [%d][%s]\n", ret, strerror(ret)));
        tevent_req_error(req, ret);
    }
}

errno_t
ipa_hbac_host_info_recv(struct tevent_req *req,
                        TALLOC_CTX *mem_ctx,
                        size_t *host_count,
                        struct sysdb_attrs ***hosts,
                        size_t *hostgroup_count,
                        struct sysdb_attrs ***hostgroups)
{
    size_t c;
    struct ipa_hbac_host_state *state =
            tevent_req_data(req, struct ipa_hbac_host_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *host_count = state->host_count;
    *hosts = talloc_steal(mem_ctx, state->hosts);
    for (c = 0; c < state->host_count; c++) {
        /* Guarantee the memory heirarchy of the list */
        talloc_steal(state->hosts, state->hosts[c]);
    }

    *hostgroup_count = state->hostgroup_count;
    *hostgroups = talloc_steal(mem_ctx, state->hostgroups);

    return EOK;
}

/*
 * Functions to convert sysdb_attrs to the hbac_rule format
 */
static errno_t hbac_host_attrs_to_rule(TALLOC_CTX *mem_ctx,
                                       struct sysdb_ctx *sysdb,
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
    const char *attrs[] = { IPA_HOST_FQDN, IPA_CN, NULL };
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
        DEBUG(1, ("Could not identify host categories\n"));
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
        DEBUG(1, ("sysdb_attrs_get_el failed.\n"));
        goto done;
    }
    if (ret == ENOENT || el->num_values == 0) {
        el->num_values = 0;
        DEBUG(4, ("No host specified, rule will never apply.\n"));
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
        ret = sysdb_search_custom(tmp_ctx, sysdb, domain, filter,
                                  HBAC_HOSTS_SUBDIR, attrs,
                                  &count, &msgs);
        if (ret != EOK && ret != ENOENT) goto done;
        if (ret == EOK && count == 0) {
            ret = ENOENT;
        }

        if (ret == EOK) {
            if (count > 1) {
                DEBUG(1, ("Original DN matched multiple hosts. Skipping \n"));
                talloc_zfree(member_dn);
                continue;
            }

            /* Original DN matched a single host. Get the hostname */
            name = ldb_msg_find_attr_as_string(msgs[0],
                                               IPA_HOST_FQDN,
                                               NULL);
            if (name == NULL) {
                DEBUG(1, ("FQDN is missing!\n"));
                ret = EFAULT;
                goto done;
            }

            new_hosts->names[num_hosts] = talloc_strdup(new_hosts->names,
                                                        name);
            if (new_hosts->names[num_hosts] == NULL) {
                ret = ENOMEM;
                goto done;
            }
            DEBUG(8, ("Added host [%s] to rule [%s]\n",
                      name, rule_name));
            num_hosts++;
        } else { /* ret == ENOENT */
            /* Check if this is a hostgroup */
            ret = sysdb_search_custom(tmp_ctx, sysdb, domain, filter,
                                      HBAC_HOSTGROUPS_SUBDIR, attrs,
                                      &count, &msgs);
            if (ret != EOK && ret != ENOENT) goto done;
            if (ret == EOK && count == 0) {
                ret = ENOENT;
            }

            if (ret == EOK) {
                if (count > 1) {
                    DEBUG(1, ("Original DN matched multiple hostgroups. "
                              "Skipping\n"));
                    talloc_zfree(member_dn);
                    continue;
                }

                /* Original DN matched a single group. Get the groupname */
                name = ldb_msg_find_attr_as_string(msgs[0], IPA_CN, NULL);
                if (name == NULL) {
                    DEBUG(1, ("Hostgroup name is missing!\n"));
                    ret = EFAULT;
                    goto done;
                }

                new_hosts->groups[num_hostgroups] =
                        talloc_strdup(new_hosts->groups, name);
                if (new_hosts->groups[num_hostgroups] == NULL) {
                    ret = ENOMEM;
                    goto done;
                }

                DEBUG(8, ("Added hostgroup [%s] to rule [%s]\n",
                          name, rule_name));
                num_hostgroups++;
            } else { /* ret == ENOENT */
                /* Neither a host nor a hostgroup? Skip it */
                DEBUG(1, ("[%s] does not map to either a host or hostgroup. "
                          "Skipping\n", member_dn));
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
                         struct sysdb_ctx *sysdb,
                         struct sss_domain_info *domain,
                         const char *rule_name,
                         struct sysdb_attrs *rule_attrs,
                         struct hbac_rule_element **thosts)
{
    DEBUG(7, ("Processing target hosts for rule [%s]\n", rule_name));

    return hbac_host_attrs_to_rule(mem_ctx, sysdb, domain,
                                   rule_name, rule_attrs,
                                   IPA_HOST_CATEGORY, IPA_MEMBER_HOST,
                                   NULL, thosts);
}

errno_t
hbac_shost_attrs_to_rule(TALLOC_CTX *mem_ctx,
                         struct sysdb_ctx *sysdb,
                         struct sss_domain_info *domain,
                         const char *rule_name,
                         struct sysdb_attrs *rule_attrs,
                         struct hbac_rule_element **source_hosts)
{
    errno_t ret;
    size_t host_count;
    TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
    size_t idx;
    struct ldb_message_element *el;
    struct hbac_rule_element *shosts;

    DEBUG(7, ("Processing source hosts for rule [%s]\n", rule_name));

    ret = hbac_host_attrs_to_rule(tmp_ctx, sysdb, domain,
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
            DEBUG(8, ("Added external source host [%s] to rule [%s]\n",
                      shosts->names[idx], rule_name));
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

errno_t
get_ipa_hostgroupname(TALLOC_CTX *mem_ctx,
                      struct sysdb_ctx *sysdb,
                      const char *host_dn,
                      char **hostgroupname)
{
    errno_t ret;
    struct ldb_dn *dn;
    const char *rdn_name;
    const char *hostgroup_comp_name;
    const char *account_comp_name;
    const struct ldb_val *rdn_val;
    const struct ldb_val *hostgroup_comp_val;
    const struct ldb_val *account_comp_val;

    /* This is an IPA-specific hack. It may not
     * work for non-IPA servers and will need to
     * be changed if SSSD ever supports HBAC on
     * a non-IPA server.
     */
    *hostgroupname = NULL;

    dn = ldb_dn_new(mem_ctx, sysdb_ctx_get_ldb(sysdb), host_dn);
    if (dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (!ldb_dn_validate(dn)) {
        ret = EINVAL;
        goto done;
    }

    if (ldb_dn_get_comp_num(dn) < 4) {
        /* RDN, hostgroups, accounts, and at least one DC= */
        /* If it's fewer, it's not a group DN */
        ret = ENOENT;
        goto done;
    }

    /* If the RDN name is 'cn' */
    rdn_name = ldb_dn_get_rdn_name(dn);
    if (rdn_name == NULL) {
        /* Shouldn't happen if ldb_dn_validate()
         * passed, but we'll be careful.
         */
        ret = EINVAL;
        goto done;
    }

    if (strcasecmp("cn", rdn_name) != 0) {
        /* RDN has the wrong attribute name.
         * It's not a host.
         */
        ret = ENOENT;
        goto done;
    }

    /* and the second component is "cn=hostgroups" */
    hostgroup_comp_name = ldb_dn_get_component_name(dn, 1);
    if (strcasecmp("cn", hostgroup_comp_name) != 0) {
        /* The second component name is not "cn" */
        ret = ENOENT;
        goto done;
    }

    hostgroup_comp_val = ldb_dn_get_component_val(dn, 1);
    if (strncasecmp("hostgroups",
                    (const char *) hostgroup_comp_val->data,
                    hostgroup_comp_val->length) != 0) {
        /* The second component value is not "hostgroups" */
        ret = ENOENT;
        goto done;
    }

    /* and the third component is "accounts" */
    account_comp_name = ldb_dn_get_component_name(dn, 2);
    if (strcasecmp("cn", account_comp_name) != 0) {
        /* The third component name is not "cn" */
        ret = ENOENT;
        goto done;
    }

    account_comp_val = ldb_dn_get_component_val(dn, 2);
    if (strncasecmp("accounts",
                    (const char *) account_comp_val->data,
                    account_comp_val->length) != 0) {
        /* The third component value is not "accounts" */
        ret = ENOENT;
        goto done;
    }

    /* Then the value of the RDN is the group name */
    rdn_val = ldb_dn_get_rdn_val(dn);
    *hostgroupname = talloc_strndup(mem_ctx,
                                    (const char *)rdn_val->data,
                                    rdn_val->length);
    if (*hostgroupname == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;

done:
    talloc_free(dn);
    return ret;
}
