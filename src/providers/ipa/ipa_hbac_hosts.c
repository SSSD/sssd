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

    bool support_srchost;
    const char *hostname;

    /* Return values */
    size_t host_count;
    struct sysdb_attrs **hosts;

    size_t hostgroup_count;
    struct sysdb_attrs **hostgroups;
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

struct tevent_req *
ipa_hbac_host_info_send(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        struct sysdb_ctx *sysdb,
                        struct sss_domain_info *dom,
                        struct sdap_handle *sh,
                        struct sdap_options *opts,
                        bool support_srchost,
                        const char *hostname,
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
    state->support_srchost = support_srchost;
    state->hostname = hostname;
    state->search_base = search_base;

    if (support_srchost) {
        host_filter = talloc_asprintf(state, "(objectClass=%s)", IPA_HOST);
    } else {
        if (hostname == NULL) {
            ret = EINVAL;
            goto immediate;
        }
        host_filter = talloc_asprintf(state, "(&(objectClass=%s)(%s=%s))",
                                      IPA_HOST, IPA_HOST_FQDN, hostname);
    }
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
                                                  SDAP_ENUM_SEARCH_TIMEOUT),
                                   true);
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

static errno_t
ipa_hbac_get_hostgroups_recv(struct tevent_req *subreq,
                             TALLOC_CTX *mem_ctx,
                             size_t *count,
                             struct sysdb_attrs ***parents);

static struct tevent_req *
ipa_hbac_get_hostgroups_send(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev,
                             struct sdap_options *opts,
                             struct sdap_handle *sh,
                             size_t queue_len,
                             char **queued_parents);

static void
ipa_hbac_host_info_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct ipa_hbac_host_state *state =
            tevent_req_data(req, struct ipa_hbac_host_state);
    char *hostgroup_filter;
    const char *parent_dn;
    struct ldb_message_element *parent_el;
    char **queued_parents;
    size_t queue_len;
    int i;

    ret = sdap_get_generic_recv(subreq, state,
                                &state->host_count,
                                &state->hosts);
    talloc_zfree(subreq);
    if (ret != EOK) goto error;

    if (state->host_count == 0) goto error;

    ret = replace_attribute_name(IPA_MEMBEROF, SYSDB_ORIG_MEMBEROF,
                                 state->host_count,
                                 state->hosts);
    if (ret != EOK) {
        DEBUG(1, ("Could not replace attribute names\n"));
        goto error;
    }

    /* Complete the map */
    for (i = 0; i < HOSTGROUP_MAP_ATTRS_COUNT; i++) {
        /* These are allocated on the state, so the next time they'll
         * have to be allocated again
         */
        hostgroup_map[i].name = talloc_strdup(state,
                                              hostgroup_map[i].def_name);
        if (hostgroup_map[i].name == NULL) goto error;
    }

    /* Look up host groups */
    if (state->support_srchost) {
        hostgroup_filter = talloc_asprintf(state, "(objectClass=%s)",
                                                  IPA_HOSTGROUP);
        if (hostgroup_filter == NULL) goto error;

        subreq = sdap_get_generic_send(state, state->ev, state->opts, state->sh,
                                       state->search_base, LDAP_SCOPE_SUB,
                                       hostgroup_filter, state->attrs, hostgroup_map,
                                       HOSTGROUP_MAP_ATTRS_COUNT,
                                       dp_opt_get_int(state->opts->basic,
                                                      SDAP_ENUM_SEARCH_TIMEOUT),
                                       true);
        if (subreq == NULL) {
            DEBUG(1, ("Error requesting host info\n"));
            goto error;
        }
        tevent_req_set_callback(subreq, ipa_hbac_hostgroup_info_done, req);
        return;
    }

    /* Source host processing is disabled */

    ret = sysdb_attrs_get_el_ext(state->hosts[0],
                                 SYSDB_ORIG_MEMBEROF,
                                 false,
                                 &parent_el);
    if (ret != EOK && ret != ENOENT) goto error;

    if (ret == ENOENT) {
        queue_len = 0;
        queued_parents = NULL;
    } else {
        /* Iterate through the memberOf DNs and retrieve
         * the hostgroup entries in parallel
         */

        /* We'll assume that all parents are hostgroups for efficiency */
        queued_parents = talloc_array(state, char *,
                                      parent_el->num_values);
        if (!queued_parents) {
            ret = ENOMEM;
            goto error;
        }
        queue_len = 0;

        for (i=0; i < parent_el->num_values; i++) {
            parent_dn = (char *)parent_el->values[i].data;

            ret = get_ipa_hostgroupname(NULL, state->sysdb, parent_dn, NULL);
            if (ret == ENOENT) {
                /* Skip this entry, it's not a hostgroup */
                continue;
            } else if (ret != EOK) goto error;

            /* Enqueue this hostgroup for lookup */
            queued_parents[queue_len] =
                    talloc_strdup(queued_parents, parent_dn);
            if (!queued_parents[queue_len]) {
                ret = ENOMEM;
                goto error;
            }
            queue_len++;
        }
    }

    subreq = ipa_hbac_get_hostgroups_send(state,
                                          state->ev,
                                          state->opts,
                                          state->sh,
                                          queue_len,
                                          queued_parents);
    if (!subreq) {
        ret = ENOMEM;
        goto error;
    }

    tevent_req_set_callback(subreq, ipa_hbac_hostgroup_info_done, req);
    return;

error:
    DEBUG(3, ("Error: [%s]\n", strerror(ret)));
    tevent_req_error(req, ret);
}

#define HOSTGROUP_REQ_PARALLEL 50

struct ipa_hbac_get_hostgroups_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;

    const char **attrs;

    char **queued_parents;
    size_t queue_len;
    size_t queue_iter;
    size_t running;

    /* Results */
    struct sysdb_attrs **parents;
    size_t parent_count;
};

static void
ipa_hbac_get_hostgroups_done(struct tevent_req *subreq);

static struct tevent_req *
ipa_hbac_get_hostgroups_send(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev,
                             struct sdap_options *opts,
                             struct sdap_handle *sh,
                             size_t queue_len,
                             char **queued_parents)
{
    errno_t ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct ipa_hbac_get_hostgroups_state *state;

    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_hbac_get_hostgroups_state);
    if (!req) return NULL;

    if (queue_len == 0) {
        /* This host is not in any hostgroups */
        ret = ENOENT;
        goto error;
    }

    state->ev = ev;
    state->opts = opts;
    state->sh = sh;

    state->queued_parents = queued_parents;
    state->queue_len = queue_len;
    state->queue_iter = 0;
    state->running = 0;

    state->attrs = talloc_array(state, const char *, 6);
    if (state->attrs == NULL) {
        DEBUG(1, ("Failed to allocate hostgroup attribute list.\n"));
        ret = ENOMEM;
        goto error;
    }
    state->attrs[0] = "objectClass";
    state->attrs[1] = IPA_UNIQUE_ID;
    state->attrs[2] = IPA_MEMBER;
    state->attrs[3] = IPA_MEMBEROF;
    state->attrs[4] = IPA_CN;
    state->attrs[5] = NULL;

    /* Pre-create the result array assuming that all values
     * return results (which they should, since FreeIPA is
     * memberOf-guaranteed.
     */
    state->parents = talloc_array(state, struct sysdb_attrs *,
                                  state->queue_len);
    if (!state->parents) {
        ret = ENOMEM;
        goto error;
    }
    state->parent_count = 0;

    /* Process the parents in parallel */
    while (state->queue_iter < state->queue_len
            && state->running < HOSTGROUP_REQ_PARALLEL) {
        subreq = sdap_get_generic_send(
                    state, state->ev, state->opts, state->sh,
                    state->queued_parents[state->queue_iter],
                    LDAP_SCOPE_BASE, NULL, state->attrs,
                    hostgroup_map, HOSTGROUP_MAP_ATTRS_COUNT,
                    dp_opt_get_int(state->opts->basic,
                                   SDAP_ENUM_SEARCH_TIMEOUT),
                    false);
        if (!subreq) {
            ret = ENOMEM;
            goto error;
        }
        tevent_req_set_callback(subreq, ipa_hbac_get_hostgroups_done, req);
        state->queue_iter++;
        state->running++;
    }

    return req;

error:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void
ipa_hbac_get_hostgroups_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct ipa_hbac_get_hostgroups_state *state =
            tevent_req_data(req, struct ipa_hbac_get_hostgroups_state);
    size_t count;
    struct sysdb_attrs **hostgroup_attrs = NULL;

    /* Get the results and add them to the result array */
    state->running--;

    ret = sdap_get_generic_recv(subreq, NULL, &count, &hostgroup_attrs);
    talloc_zfree(subreq);
    if (ret != EOK || count != 1) {
        /* We got an error retrieving the host group.
         * We'll log it and continue. The worst-case
         * here is that we'll deny too aggressively.
         */
        if (ret == EOK) {
            /* We got back something other than a single entry on a
             * base search?
             */
            ret = ENOENT;
        }

        DEBUG(1, ("Error [%s] while processing hostgroups. Skipping.\n",
                  strerror(ret)));
        goto next;
    }

    /* Add this hostgroup to the array */
    state->parents[state->parent_count] =
            talloc_steal(state->parents, hostgroup_attrs[0]);
    state->parent_count++;

next:
    /* Check if there are more hostgroups to process */
    if (state->queue_iter < state->queue_len) {
        subreq = sdap_get_generic_send(
                    state, state->ev, state->opts, state->sh,
                    state->queued_parents[state->queue_iter],
                    LDAP_SCOPE_BASE, NULL, state->attrs,
                    hostgroup_map, HOSTGROUP_MAP_ATTRS_COUNT,
                    dp_opt_get_int(state->opts->basic,
                                   SDAP_ENUM_SEARCH_TIMEOUT),
                    false);
        if (!subreq) {
            ret = ENOMEM;
            goto done;
        }
        tevent_req_set_callback(subreq, ipa_hbac_get_hostgroups_done, req);
        state->queue_iter++;
        state->running++;
    }

    /* Continue processing until all parallel searches have
     * completed successfully.
     */
    if (state->running != 0) {
        /* There are still pending parallel requests.
         * Re-enter the mainloop.
         */
        talloc_free(hostgroup_attrs);
        return;
    }

    /* All searches are complete. Return the results */
    ret = EOK;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        DEBUG(3, ("Error [%d][%s]\n", ret, strerror(ret)));
        tevent_req_error(req, ret);
    }

    talloc_free(hostgroup_attrs);
    return;
}

static errno_t
ipa_hbac_get_hostgroups_recv(struct tevent_req *req,
                             TALLOC_CTX *mem_ctx,
                             size_t *reply_count,
                             struct sysdb_attrs ***parents)
{
    struct ipa_hbac_get_hostgroups_state *state =
            tevent_req_data(req, struct ipa_hbac_get_hostgroups_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *reply_count = state->parent_count;
    *parents = talloc_steal(mem_ctx, state->parents);

    return EOK;
}

static void
ipa_hbac_hostgroup_info_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct ipa_hbac_host_state *state =
            tevent_req_data(req, struct ipa_hbac_host_state);

    if (state->support_srchost) {
        ret = sdap_get_generic_recv(subreq, state,
                                    &state->hostgroup_count,
                                    &state->hostgroups);
    } else {
        ret = ipa_hbac_get_hostgroups_recv(subreq, state,
                                           &state->hostgroup_count,
                                           &state->hostgroups);
    }
    talloc_zfree(subreq);

    if (ret == ENOENT) {
        /* No hostgroups were found */
        state->hostgroup_count = 0;
        state->hostgroups = NULL;
        ret = EOK;
    }

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

    DEBUG(7, ("Processing source hosts for rule [%s]\n", rule_name));

    if (!support_srchost) {
        DEBUG(8, ("Source hosts disabled, setting ALL\n"));
        shosts = talloc_zero(tmp_ctx, struct hbac_rule_element);
        if (shosts == NULL) {
            ret = ENOMEM;
            goto done;
        }

        shosts->category = HBAC_CATEGORY_ALL;
        ret = EOK;
        goto done;
    }

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

    if (hostgroupname) {
        *hostgroupname = NULL;
    }

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

    if (hostgroupname) {
        *hostgroupname = talloc_strndup(mem_ctx,
                                        (const char *)rdn_val->data,
                                        rdn_val->length);
        if (*hostgroupname == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_free(dn);
    return ret;
}
