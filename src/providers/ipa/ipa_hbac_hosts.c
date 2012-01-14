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
    struct sdap_handle *sh;
    struct sdap_options *opts;
    const char **attrs;

    struct sdap_search_base **search_bases;
    int search_base_iter;

    char *cur_filter;
    char *host_filter;

    bool support_srchost;
    const char *hostname;

    /* Return values */
    size_t host_count;
    struct sysdb_attrs **hosts;

    size_t hostgroup_count;
    struct sysdb_attrs **hostgroups;
    struct sdap_attr_map_info *hostgroup_map;
};

#define HOSTGROUP_MAP_ATTRS_COUNT 5
static struct sdap_attr_map hostgroup_map[] = {
    {"objectclass", "ipahostgroup", "hostgroup", NULL},
    {"name_attr", IPA_CN, IPA_CN, NULL},
    {"member", IPA_MEMBER, SYSDB_ORIG_MEMBER, NULL},
    {"memberof", IPA_MEMBEROF, SYSDB_ORIG_MEMBEROF, NULL},
    {"ipa_id", IPA_UNIQUE_ID, IPA_UNIQUE_ID, NULL}
};

static void
ipa_hbac_host_info_done(struct tevent_req *subreq);

static void
ipa_hbac_hostgroup_info_done(struct tevent_req *subreq);

static errno_t
ipa_hbac_host_info_next(struct tevent_req *req,
                        struct ipa_hbac_host_state *state);
static errno_t
ipa_hbac_hostgroup_info_next(struct tevent_req *req,
                             struct ipa_hbac_host_state *state);

struct tevent_req *
ipa_hbac_host_info_send(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        struct sysdb_ctx *sysdb,
                        struct sdap_handle *sh,
                        struct sdap_options *opts,
                        bool support_srchost,
                        const char *hostname,
                        struct sdap_search_base **search_bases)
{
    errno_t ret;
    struct ipa_hbac_host_state *state;
    struct tevent_req *req;

    req = tevent_req_create(mem_ctx, &state, struct ipa_hbac_host_state);
    if (req == NULL) {
        return NULL;
    }

    state->ev = ev;
    state->sysdb = sysdb;
    state->sh = sh;
    state->opts = opts;
    state->support_srchost = support_srchost;
    state->hostname = hostname;
    state->search_bases = search_bases;
    state->search_base_iter = 0;
    state->cur_filter = NULL;

    if (support_srchost) {
        state->host_filter = talloc_asprintf(state, "(objectClass=%s)",
                                             IPA_HOST);
    } else {
        if (hostname == NULL) {
            ret = EINVAL;
            goto immediate;
        }
        state->host_filter = talloc_asprintf(state, "(&(objectClass=%s)(%s=%s))",
                                             IPA_HOST, IPA_HOST_FQDN, hostname);
    }
    if (state->host_filter == NULL) {
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

    ret = ipa_hbac_host_info_next(req, state);
    if (ret == EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("No host search base configured?\n"));
        ret = EINVAL;
    }

    if (ret != EAGAIN) {
        goto immediate;
    }

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

static errno_t ipa_hbac_host_info_next(struct tevent_req *req,
                                       struct ipa_hbac_host_state *state)
{
    struct sdap_search_base *base;
    struct tevent_req *subreq;

    base = state->search_bases[state->search_base_iter];
    if (base == NULL) {
        return EOK;
    }

    talloc_zfree(state->cur_filter);
    state->cur_filter = sdap_get_id_specific_filter(state, state->host_filter,
                                                    base->filter);
    if (state->cur_filter == NULL) {
        return ENOMEM;
    }

    subreq = sdap_get_generic_send(state, state->ev, state->opts,
                                   state->sh, base->basedn,
                                   base->scope, state->cur_filter,
                                   state->attrs, NULL, 0,
                                   dp_opt_get_int(state->opts->basic,
                                                  SDAP_ENUM_SEARCH_TIMEOUT));
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Error requesting host info\n"));
        talloc_zfree(state->cur_filter);
        return EIO;
    }
    tevent_req_set_callback(subreq, ipa_hbac_host_info_done, req);

    return EAGAIN;
}

static void
ipa_hbac_host_info_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct ipa_hbac_host_state *state =
            tevent_req_data(req, struct ipa_hbac_host_state);
    const char *host_dn;
    int i;

    ret = sdap_get_generic_recv(subreq, state,
                                &state->host_count,
                                &state->hosts);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->host_count == 0) {
        state->search_base_iter++;
        ret = ipa_hbac_host_info_next(req, state);
        if (ret == EOK) {
            /* No more search bases to try */
            tevent_req_error(req, ENOENT);
        } else if (ret != EAGAIN) {
            tevent_req_error(req, ret);
        }
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

    /* Complete the map */
    for (i = 0; i < HOSTGROUP_MAP_ATTRS_COUNT; i++) {
        /* These are allocated on the state, so the next time they'll
         * have to be allocated again
         */
        hostgroup_map[i].name = talloc_strdup(state,
                                              hostgroup_map[i].def_name);
        if (hostgroup_map[i].name == NULL) {
            tevent_req_error(req, ret);
            return;
        }
    }

    /* Look up host groups */
    if (state->support_srchost) {
        talloc_zfree(state->host_filter);
        state->host_filter = talloc_asprintf(state, "(objectClass=%s)",
                                             IPA_HOSTGROUP);
        if (state->host_filter == NULL) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        state->search_base_iter = 0;

        ret = ipa_hbac_hostgroup_info_next(req, state);
        if (ret == EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("No host search base configured?\n"));
            tevent_req_error(req, EINVAL);
            return;
        } else if (ret != EAGAIN) {
            tevent_req_error(req, ret);
            return;
        }
    } else {
        state->hostgroup_map = talloc_zero(state, struct sdap_attr_map_info);
        if (state->hostgroup_map == NULL) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        state->hostgroup_map->map = hostgroup_map;
        state->hostgroup_map->num_attrs = HOSTGROUP_MAP_ATTRS_COUNT;

        ret = sysdb_attrs_get_string(state->hosts[0], SYSDB_ORIG_DN, &host_dn);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }

        subreq = sdap_deref_search_send(state, state->ev, state->opts, state->sh,
                                        host_dn, IPA_MEMBEROF, state->attrs,
                                        1, state->hostgroup_map,
                                        dp_opt_get_int(state->opts->basic,
                                                       SDAP_ENUM_SEARCH_TIMEOUT));
        if (subreq == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Error requesting host info\n"));
            tevent_req_error(req, EIO);
            return;
        }
    }
    tevent_req_set_callback(subreq, ipa_hbac_hostgroup_info_done, req);
}

static errno_t ipa_hbac_hostgroup_info_next(struct tevent_req *req,
                                            struct ipa_hbac_host_state *state)
{
    struct sdap_search_base *base;
    struct tevent_req *subreq;

    base = state->search_bases[state->search_base_iter];
    if (base == NULL) {
        return EOK;
    }

    talloc_zfree(state->cur_filter);
    state->cur_filter = sdap_get_id_specific_filter(state, state->host_filter,
                                                    base->filter);
    if (state->cur_filter == NULL) {
        return ENOMEM;
    }

    subreq = sdap_get_generic_send(state, state->ev, state->opts, state->sh,
                                   base->basedn, base->scope,
                                   state->cur_filter, state->attrs, hostgroup_map,
                                   HOSTGROUP_MAP_ATTRS_COUNT,
                                   dp_opt_get_int(state->opts->basic,
                                                  SDAP_ENUM_SEARCH_TIMEOUT));
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Error requesting hostgroup info\n"));
        talloc_zfree(state->cur_filter);
        return EIO;
    }
    tevent_req_set_callback(subreq, ipa_hbac_hostgroup_info_done, req);

    return EAGAIN;
}

static void
ipa_hbac_hostgroup_info_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct ipa_hbac_host_state *state =
            tevent_req_data(req, struct ipa_hbac_host_state);

    size_t hostgroups_total;
    size_t hostgroup_count;
    struct sysdb_attrs **hostgroups;
    struct sdap_deref_attrs **deref_result;
    const char *hostgroup_name;
    const char *hostgroup_dn;
    int i, j;

    if (state->support_srchost) {
        ret = sdap_get_generic_recv(subreq, state,
                                    &hostgroup_count,
                                    &hostgroups);
        talloc_zfree(subreq);

        /* Merge the two arrays */
        if (hostgroup_count > 0) {
            hostgroups_total = hostgroup_count + state->hostgroup_count;
            state->hostgroups = talloc_realloc(state, state->hostgroups,
                                               struct sysdb_attrs *,
                                               hostgroups_total);
            if (state->hostgroups == NULL) {
                tevent_req_error(req, ENOMEM);
                return;
            }

            i = 0;
            while(state->hostgroup_count < hostgroups_total) {
                state->hostgroups[state->hostgroup_count] = hostgroups[i];
                state->hostgroup_count++;
                i++;
            }
        }

        /* Now look in the next base */
        state->search_base_iter++;
        ret = ipa_hbac_hostgroup_info_next(req, state);
        if (ret != EOK && ret != EAGAIN) {
            tevent_req_error(req, ret);
        }

        if (ret != EOK) {
            /* Only continue if no error occurred
             * and no req was created */
            return;
        }
    } else {
        ret = sdap_deref_search_recv(subreq, state,
                                     &state->hostgroup_count,
                                     &deref_result);
        talloc_zfree(subreq);
        if (ret != EOK) goto done;

        if (state->hostgroup_count == 0) {
            DEBUG(SSSDBG_FUNC_DATA, ("No host groups were dereferenced\n"));
        } else {
            state->hostgroups = talloc_zero_array(state, struct sysdb_attrs *,
                                                  state->hostgroup_count);
            if (state->hostgroups == NULL) {
                ret = ENOMEM;
                goto done;
            }

            j = 0;
            for (i = 0; i < state->hostgroup_count; i++) {
                ret = sysdb_attrs_get_string(deref_result[i]->attrs,
                                             SYSDB_ORIG_DN, &hostgroup_dn);
                if (ret != EOK) goto done;

                if (!sss_ldap_dn_in_search_bases(state, hostgroup_dn,
                                                 state->search_bases,
                                                 NULL)) {
                    continue;
                }

                ret = sysdb_attrs_get_string(deref_result[i]->attrs,
                                             IPA_CN, &hostgroup_name);
                if (ret != EOK) goto done;

                DEBUG(SSSDBG_FUNC_DATA, ("Dereferenced host group: %s\n",
                                        hostgroup_name));
                state->hostgroups[j] = talloc_steal(state->hostgroups,
                                                    deref_result[i]->attrs);
                j++;
            }
            state->hostgroup_count = j;
        }
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
        ret = sysdb_search_custom(tmp_ctx, sysdb, filter,
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
            ret = sysdb_search_custom(tmp_ctx, sysdb, filter,
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
                DEBUG(SSSDBG_TRACE_LIBS,
                      ("[%s] does not map to either a host or hostgroup. "
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
                         const char *rule_name,
                         struct sysdb_attrs *rule_attrs,
                         struct hbac_rule_element **thosts)
{
    DEBUG(7, ("Processing target hosts for rule [%s]\n", rule_name));

    return hbac_host_attrs_to_rule(mem_ctx, sysdb,
                                   rule_name, rule_attrs,
                                   IPA_HOST_CATEGORY, IPA_MEMBER_HOST,
                                   NULL, thosts);
}

errno_t
hbac_shost_attrs_to_rule(TALLOC_CTX *mem_ctx,
                         struct sysdb_ctx *sysdb,
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

    DEBUG(SSSDBG_TRACE_FUNC, ("Processing source hosts for rule [%s]\n", rule_name));

    if (!support_srchost) {
        DEBUG(SSSDBG_TRACE_INTERNAL, ("Source hosts disabled, setting ALL\n"));
        shosts = talloc_zero(tmp_ctx, struct hbac_rule_element);
        if (shosts == NULL) {
            ret = ENOMEM;
            goto done;
        }

        shosts->category = HBAC_CATEGORY_ALL;
        ret = EOK;
        goto done;
    }

    ret = hbac_host_attrs_to_rule(tmp_ctx, sysdb,
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
