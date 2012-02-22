/*
    SSSD

    Authors:
        Jan Zeleny <jzeleny@redhat.com>

    Copyright (C) 2012 Red Hat

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
#include "providers/ldap/sdap_async.h"
#include "providers/ipa/ipa_hosts.h"
/* FIXME: this is temporary, use proper map instead */
#include "providers/ipa/ipa_hbac_private.h"

struct ipa_host_state {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sdap_handle *sh;
    struct sdap_options *opts;
    const char **attrs;
    struct sdap_attr_map *map;
    int map_num_attrs;

    struct sdap_search_base **search_bases;
    int search_base_iter;

    char *cur_filter;
    char *host_filter;

    const char *hostname;

    /* Return values */
    size_t host_count;
    struct sysdb_attrs **hosts;

    bool fetch_hostgroups;
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
ipa_host_info_done(struct tevent_req *subreq);

static void
ipa_hostgroup_info_done(struct tevent_req *subreq);

static errno_t
ipa_host_info_next(struct tevent_req *req,
                        struct ipa_host_state *state);
static errno_t
ipa_hostgroup_info_next(struct tevent_req *req,
                             struct ipa_host_state *state);

struct tevent_req *
ipa_host_info_send(TALLOC_CTX *mem_ctx,
                   struct tevent_context *ev,
                   struct sysdb_ctx *sysdb,
                   struct sdap_handle *sh,
                   struct sdap_options *opts,
                   const char *hostname,
                   const char **attrs,
                   struct sdap_attr_map *map,
                   int map_num_attrs,
                   bool fetch_hostgroups,
                   struct sdap_search_base **search_bases)
{
    errno_t ret;
    struct ipa_host_state *state;
    struct tevent_req *req;

    req = tevent_req_create(mem_ctx, &state, struct ipa_host_state);
    if (req == NULL) {
        return NULL;
    }

    state->ev = ev;
    state->sysdb = sysdb;
    state->sh = sh;
    state->opts = opts;
    state->hostname = hostname;
    state->search_bases = search_bases;
    state->search_base_iter = 0;
    state->cur_filter = NULL;
    state->attrs = attrs;
    state->map = map;
    state->map_num_attrs = map_num_attrs;
    state->fetch_hostgroups = fetch_hostgroups;

    if (hostname == NULL) {
        state->host_filter = talloc_asprintf(state, "(objectClass=%s)",
                                             IPA_HOST);
    } else {
        state->host_filter = talloc_asprintf(state, "(&(objectClass=%s)(%s=%s))",
                                             IPA_HOST, IPA_HOST_FQDN, hostname);
    }
    if (state->host_filter == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    ret = ipa_host_info_next(req, state);
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

static errno_t ipa_host_info_next(struct tevent_req *req,
                                       struct ipa_host_state *state)
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
                                   state->attrs, state->map,
                                   state->map_num_attrs,
                                   dp_opt_get_int(state->opts->basic,
                                                  SDAP_ENUM_SEARCH_TIMEOUT),
                                   true);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Error requesting host info\n"));
        talloc_zfree(state->cur_filter);
        return EIO;
    }
    tevent_req_set_callback(subreq, ipa_host_info_done, req);

    return EAGAIN;
}

static void
ipa_host_info_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct ipa_host_state *state =
            tevent_req_data(req, struct ipa_host_state);
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
        ret = ipa_host_info_next(req, state);
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
        DEBUG(SSSDBG_CRIT_FAILURE, ("Could not replace attribute names\n"));
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

    if (state->fetch_hostgroups) {
        /* Look up host groups */
        if (state->hostname == NULL) {
            talloc_zfree(state->host_filter);
            state->host_filter = talloc_asprintf(state, "(objectClass=%s)",
                                                 IPA_HOSTGROUP);
            if (state->host_filter == NULL) {
                tevent_req_error(req, ENOMEM);
                return;
            }
            state->search_base_iter = 0;

            ret = ipa_hostgroup_info_next(req, state);
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
        tevent_req_set_callback(subreq, ipa_hostgroup_info_done, req);
    } else {
        /* Nothing else to do, just complete the req */
        tevent_req_done(req);
    }
}

static errno_t ipa_hostgroup_info_next(struct tevent_req *req,
                                            struct ipa_host_state *state)
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
                                                  SDAP_ENUM_SEARCH_TIMEOUT),
                                   true);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Error requesting hostgroup info\n"));
        talloc_zfree(state->cur_filter);
        return EIO;
    }
    tevent_req_set_callback(subreq, ipa_hostgroup_info_done, req);

    return EAGAIN;
}

static void
ipa_hostgroup_info_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct ipa_host_state *state =
            tevent_req_data(req, struct ipa_host_state);

    size_t hostgroups_total;
    size_t hostgroup_count;
    struct sysdb_attrs **hostgroups;
    struct sdap_deref_attrs **deref_result;
    const char *hostgroup_name;
    const char *hostgroup_dn;
    int i, j;

    if (state->hostname == NULL) {
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
                state->hostgroups[state->hostgroup_count] =
                    talloc_steal(state->hostgroups, hostgroups[i]);
                state->hostgroup_count++;
                i++;
            }
        }

        /* Now look in the next base */
        state->search_base_iter++;
        ret = ipa_hostgroup_info_next(req, state);
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
        DEBUG(SSSDBG_OP_FAILURE, ("Error [%d][%s]\n", ret, strerror(ret)));
        tevent_req_error(req, ret);
    }
}

errno_t ipa_host_info_recv(struct tevent_req *req,
                           TALLOC_CTX *mem_ctx,
                           size_t *host_count,
                           struct sysdb_attrs ***hosts,
                           size_t *hostgroup_count,
                           struct sysdb_attrs ***hostgroups)
{
    size_t c;
    struct ipa_host_state *state =
            tevent_req_data(req, struct ipa_host_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *host_count = state->host_count;
    *hosts = talloc_steal(mem_ctx, state->hosts);
    for (c = 0; c < state->host_count; c++) {
        /* Guarantee the memory heirarchy of the list */
        talloc_steal(state->hosts, state->hosts[c]);
    }

    if (hostgroup_count) *hostgroup_count = state->hostgroup_count;
    if (hostgroups) *hostgroups = talloc_steal(mem_ctx, state->hostgroups);

    return EOK;
}
