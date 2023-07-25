/*
    SSSD

    Async IPA Helper routines for netgroups

    Authors:
        Jan Zeleny <jzeleny@redhat.com>

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
#include "providers/ldap/sdap_async_private.h"
#include "providers/ipa/ipa_id.h"
#include <ctype.h>

#define ENTITY_NG 1
#define ENTITY_USER 2
#define ENTITY_HOST 4

struct ipa_get_netgroups_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct ipa_options *ipa_opts;
    struct sdap_handle *sh;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *dom;
    const char **attrs;
    int timeout;

    char *filter;
    const char *base_filter;

    size_t netgr_base_iter;
    size_t host_base_iter;
    size_t user_base_iter;

    /* Entities which have been already asked for
     * and are scheduled for inspection */
    hash_table_t *new_netgroups;
    hash_table_t *new_users;
    hash_table_t *new_hosts;

    int current_entity;
    int entities_found;

    struct sysdb_attrs **netgroups;
    int netgroups_count;
};

static errno_t ipa_save_netgroup(TALLOC_CTX *mem_ctx,
                                 struct sss_domain_info *dom,
                                 struct sdap_options *opts,
                                 struct sysdb_attrs *attrs)
{
    struct ldb_message_element *el;
    struct sysdb_attrs *netgroup_attrs;
    const char *name = NULL;
    char **missing;
    int missing_index;
    int ret;
    int i;
    size_t c;

    ret = sysdb_attrs_get_el(attrs,
                             opts->netgroup_map[IPA_AT_NETGROUP_NAME].sys_name,
                             &el);
    if (ret) goto fail;
    if (el->num_values == 0) {
        ret = EINVAL;
        goto fail;
    }
    name = (const char *)el->values[0].data;
    DEBUG(SSSDBG_TRACE_INTERNAL, "Storing netgroup %s\n", name);

    netgroup_attrs = sysdb_new_attrs(mem_ctx);
    if (!netgroup_attrs) {
        ret = ENOMEM;
        goto fail;
    }

    missing = talloc_zero_array(netgroup_attrs, char *, attrs->num + 1);
    if (missing == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    for (i = 0, missing_index = 0; i < attrs->num; i++) {
        if (attrs->a[i].num_values == 0) {
            missing[missing_index] = talloc_strdup(missing, attrs->a[i].name);
            if (missing[missing_index] == NULL) {
                ret = ENOMEM;
                goto fail;
            }
            missing_index++;
        }
    }

    ret = sysdb_attrs_get_el(attrs, SYSDB_ORIG_DN, &el);
    if (ret) {
        goto fail;
    }
    if (el->num_values == 0) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "Original DN is not available for [%s].\n", name);
    } else {
        DEBUG(SSSDBG_TRACE_LIBS,
              "Adding original DN [%s] to attributes of [%s].\n",
                  el->values[0].data, name);
        ret = sysdb_attrs_add_string(netgroup_attrs, SYSDB_ORIG_DN,
                                     (const char *)el->values[0].data);
        if (ret) {
            goto fail;
        }
    }

    ret = sysdb_attrs_get_el(attrs, SYSDB_NETGROUP_TRIPLE, &el);
    if (ret) {
        goto fail;
    }
    if (el->num_values == 0) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "No netgroup triples for netgroup [%s].\n", name);
        ret = sysdb_attrs_get_el(netgroup_attrs, SYSDB_NETGROUP_TRIPLE, &el);
        if (ret != EOK) {
            goto fail;
        }
    } else {
        for(c = 0; c < el->num_values; c++) {
            ret = sysdb_attrs_add_string_safe(netgroup_attrs,
                                              SYSDB_NETGROUP_TRIPLE,
                                              (const char*)el->values[c].data);
            if (ret) {
                goto fail;
            }
        }
    }

    ret = sysdb_attrs_get_el(attrs,
                       opts->netgroup_map[IPA_AT_NETGROUP_MEMBER].sys_name,
                       &el);
    if (ret != EOK) {
        goto fail;
    }
    if (el->num_values == 0) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "No original members for netgroup [%s]\n", name);
    } else {
        DEBUG(SSSDBG_TRACE_LIBS,
              "Adding original members to netgroup [%s]\n", name);
        for(c = 0; c < el->num_values; c++) {
            ret = sysdb_attrs_add_string(netgroup_attrs,
                       opts->netgroup_map[IPA_AT_NETGROUP_MEMBER].sys_name,
                       (const char*)el->values[c].data);
            if (ret) {
                goto fail;
            }
        }
    }


    ret = sysdb_attrs_get_el(attrs, SYSDB_NETGROUP_MEMBER, &el);
    if (ret != EOK) {
        goto fail;
    }
    if (el->num_values == 0) {
        DEBUG(SSSDBG_TRACE_LIBS, "No members for netgroup [%s]\n", name);

    } else {
        DEBUG(SSSDBG_TRACE_LIBS, "Adding members to netgroup [%s]\n", name);
        for(c = 0; c < el->num_values; c++) {
            ret = sysdb_attrs_add_string(netgroup_attrs, SYSDB_NETGROUP_MEMBER,
                                         (const char*)el->values[c].data);
            if (ret) {
                goto fail;
            }
        }
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Storing info for netgroup %s\n", name);

    ret = sysdb_add_netgroup(dom, name, NULL, netgroup_attrs, missing,
                             dom->netgroup_timeout, 0);
    if (ret) goto fail;

    return EOK;

fail:
    DEBUG(SSSDBG_OP_FAILURE, "Failed to save netgroup %s\n", name);
    return ret;
}

static errno_t ipa_netgr_next_base(struct tevent_req *req);
static void ipa_get_netgroups_process(struct tevent_req *subreq);
static int ipa_netgr_process_all(struct ipa_get_netgroups_state *state);

struct tevent_req *ipa_get_netgroups_send(TALLOC_CTX *memctx,
                                          struct tevent_context *ev,
                                          struct sysdb_ctx *sysdb,
                                          struct sss_domain_info *dom,
                                          struct sdap_options *opts,
                                          struct ipa_options *ipa_options,
                                          struct sdap_handle *sh,
                                          const char **attrs,
                                          const char *filter,
                                          int timeout)
{
    struct tevent_req *req;
    struct ipa_get_netgroups_state *state;
    int ret;

    req = tevent_req_create(memctx, &state, struct ipa_get_netgroups_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->ipa_opts = ipa_options;
    state->sh = sh;
    state->sysdb = sysdb;
    state->attrs = attrs;
    state->timeout = timeout;
    state->base_filter = filter;
    state->netgr_base_iter = 0;
    state->dom = dom;

    if (!ipa_options->id->sdom->netgroup_search_bases) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Netgroup lookup request without a search base\n");
        ret = EINVAL;
        goto done;
    }

    ret = sss_hash_create(state, 0, &state->new_netgroups);
    if (ret != EOK) goto done;
    ret = sss_hash_create(state, 0, &state->new_users);
    if (ret != EOK) goto done;
    ret = sss_hash_create(state, 0, &state->new_hosts);
    if (ret != EOK) goto done;


    ret = ipa_netgr_next_base(req);

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static errno_t ipa_netgr_next_base(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct ipa_get_netgroups_state *state;
    struct sdap_search_base **netgr_bases;

    state = tevent_req_data(req, struct ipa_get_netgroups_state);
    netgr_bases = state->ipa_opts->id->sdom->netgroup_search_bases;

    talloc_zfree(state->filter);
    state->filter = sdap_combine_filters(
            state,
            state->base_filter,
            netgr_bases[state->netgr_base_iter]->filter);
    if (!state->filter) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
            "Searching for netgroups with base [%s]\n",
             netgr_bases[state->netgr_base_iter]->basedn);

    subreq = sdap_get_generic_send(
            state, state->ev, state->opts, state->sh,
            netgr_bases[state->netgr_base_iter]->basedn,
            netgr_bases[state->netgr_base_iter]->scope,
            state->filter, state->attrs,
            state->opts->netgroup_map, IPA_OPTS_NETGROUP,
            state->timeout,
            true);
    if (!subreq) {
        return ENOMEM;
    }
    tevent_req_set_callback(subreq, ipa_get_netgroups_process, req);

    return EOK;
}

static int ipa_netgr_fetch_netgroups(struct ipa_get_netgroups_state *state,
                                     struct tevent_req *req);
static int ipa_netgr_fetch_users(struct ipa_get_netgroups_state *state,
                                 struct tevent_req *req);
static int ipa_netgr_fetch_hosts(struct ipa_get_netgroups_state *state,
                                 struct tevent_req *req);
static void ipa_netgr_members_process(struct tevent_req *subreq);

static void ipa_get_netgroups_process(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ipa_get_netgroups_state *state = tevent_req_data(req,
                                               struct ipa_get_netgroups_state);
    int i, ret;
    struct ldb_message_element *el;
    struct sdap_search_base **netgr_bases;
    struct sysdb_attrs **netgroups;
    size_t netgroups_count;
    const char *orig_dn;
    char *dn;
    char *filter;
    bool fetch_members = false;
    hash_key_t key;
    hash_value_t value;

    netgr_bases = state->ipa_opts->id->sdom->netgroup_search_bases;

    ret = sdap_get_generic_recv(subreq, state, &netgroups_count, &netgroups);
    talloc_zfree(subreq);
    if (ret) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Search for netgroups, returned %zu results.\n",
                              netgroups_count);

    if (netgroups_count == 0) {
        /* No netgroups found in this search */
        state->netgr_base_iter++;
        if (netgr_bases[state->netgr_base_iter]) {
            /* There are more search bases to try */
            ret = ipa_netgr_next_base(req);
            if (ret != EOK) {
                tevent_req_error(req, ENOENT);
            }
            return;
        }

        ret = ENOENT;
        goto done;
    }

    filter = talloc_strdup(state, "(|");
    if (filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < netgroups_count; i++) {
        ret = sysdb_attrs_get_el(netgroups[i], SYSDB_ORIG_NETGROUP_MEMBER,
                                 &el);
        if (ret != EOK) goto done;
        if (el->num_values) state->entities_found |= ENTITY_NG;

        ret = sysdb_attrs_get_el(netgroups[i], SYSDB_ORIG_MEMBER_USER,
                                 &el);
        if (ret != EOK) goto done;
        if (el->num_values) state->entities_found |= ENTITY_USER;

        ret = sysdb_attrs_get_el(netgroups[i], SYSDB_ORIG_MEMBER_HOST,
                                 &el);
        if (ret != EOK) goto done;
        if (el->num_values) state->entities_found |= ENTITY_HOST;

        ret = sysdb_attrs_get_string(netgroups[i], SYSDB_ORIG_DN, &orig_dn);
        if (ret != EOK) {
            goto done;
        }

        key.type = HASH_KEY_STRING;
        value.type = HASH_VALUE_PTR;
        key.str = discard_const(orig_dn);
        value.ptr = netgroups[i];
        ret = hash_enter(state->new_netgroups, &key, &value);
        if (ret != HASH_SUCCESS) {
            ret = ENOMEM;
            goto done;
        }

        if (state->entities_found == 0) {
            continue;
        }

        ret = sss_filter_sanitize_dn(state, orig_dn, &dn);
        if (ret != EOK) {
            goto done;
        }
        /* Add this to the filter */
        filter = talloc_asprintf_append(filter, "(%s=%s)",
                            state->opts->netgroup_map[IPA_AT_NETGROUP_MEMBER_OF].name,
                            dn);
        if (filter == NULL) {
            ret = ENOMEM;
            goto done;
        }
        fetch_members = true;
    }

    if (!fetch_members) {
        ret = ipa_netgr_process_all(state);
        if (ret != EOK) {
            tevent_req_error(req, ret);
        } else {
            tevent_req_done(req);
        }
        return;
    }

    state->filter = talloc_asprintf_append(filter, ")");
    if (state->filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (state->entities_found & ENTITY_NG) {
        state->netgr_base_iter = 0;
        ret = ipa_netgr_fetch_netgroups(state, req);
        if (ret != EOK) goto done;
    } else if (state->entities_found & ENTITY_USER) {
        ret = ipa_netgr_fetch_users(state, req);
        if (ret != EOK) goto done;
    } else if (state->entities_found & ENTITY_HOST) {
        ret = ipa_netgr_fetch_hosts(state, req);
        if (ret != EOK) goto done;
    }

    return;
done:
    tevent_req_error(req, ret);
    return;
}

static int ipa_netgr_fetch_netgroups(struct ipa_get_netgroups_state *state,
                                     struct tevent_req *req)
{
    char *filter;
    const char *base_filter;
    struct tevent_req *subreq;
    struct sdap_search_base **bases;

    bases = state->ipa_opts->id->sdom->netgroup_search_bases;
    if (bases[state->netgr_base_iter] == NULL) {
        /* No more bases to try */
        return ENOENT;
    }
    base_filter = bases[state->netgr_base_iter]->filter;

    filter = talloc_asprintf(state, "(&%s%s(objectclass=%s))",
                             state->filter,
                             base_filter?base_filter:"",
                             state->opts->netgroup_map[SDAP_OC_NETGROUP].name);
    if (filter == NULL)
        return ENOMEM;

    subreq = sdap_get_generic_send(state, state->ev, state->opts, state->sh,
                                   bases[state->netgr_base_iter]->basedn,
                                   bases[state->netgr_base_iter]->scope,
                                   filter, state->attrs, state->opts->netgroup_map,
                                   IPA_OPTS_NETGROUP, state->timeout, true);

    state->current_entity = ENTITY_NG;
    if (subreq == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, ipa_netgr_members_process, req);

    return EOK;
}

static int ipa_netgr_fetch_users(struct ipa_get_netgroups_state *state,
                                 struct tevent_req *req)
{
    const char *attrs[] = { state->opts->user_map[SDAP_AT_USER_NAME].name,
                            state->opts->user_map[SDAP_AT_USER_MEMBEROF].name,
                            "objectclass", NULL };
    char *filter;
    const char *base_filter;
    struct tevent_req *subreq;
    struct sdap_search_base **bases;

    bases = state->ipa_opts->id->sdom->user_search_bases;
    if (bases[state->user_base_iter] == NULL) {
        return ENOENT;
    }
    base_filter = bases[state->user_base_iter]->filter;

    filter = talloc_asprintf(state, "(&%s%s(objectclass=%s))",
                             state->filter,
                             base_filter?base_filter:"",
                             state->opts->user_map[SDAP_OC_USER].name);
    if (filter == NULL)
        return ENOMEM;

    subreq = sdap_get_generic_send(state, state->ev, state->opts, state->sh,
                                   dp_opt_get_string(state->opts->basic,
                                                     SDAP_USER_SEARCH_BASE),
                                   LDAP_SCOPE_SUBTREE,
                                   filter, attrs, state->opts->user_map,
                                   state->opts->user_map_cnt,
                                   state->timeout, true);

    state->current_entity = ENTITY_USER;
    if (subreq == NULL) {
        talloc_free(attrs);
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, ipa_netgr_members_process, req);

    return EOK;
}

static int ipa_netgr_fetch_hosts(struct ipa_get_netgroups_state *state,
                                 struct tevent_req *req)
{
    const char **attrs;
    char *filter;
    const char *base_filter;
    struct tevent_req *subreq;
    int ret;
    struct sdap_search_base **bases;

    bases = state->ipa_opts->id->sdom->host_search_bases;
    if (bases[state->host_base_iter] == NULL) {
        return ENOENT;
    }
    base_filter = bases[state->host_base_iter]->filter;

    filter = talloc_asprintf(state, "(&%s%s(objectclass=%s))",
                             state->filter,
                             base_filter ? base_filter : "",
                             state->ipa_opts->id->host_map[SDAP_OC_HOST].name);
    if (filter == NULL)
        return ENOMEM;

    ret = build_attrs_from_map(state, state->ipa_opts->id->host_map,
                               SDAP_OPTS_HOST, NULL, &attrs, NULL);
    if (ret != EOK) {
        talloc_free(filter);
        return ret;
    }

    subreq = sdap_get_generic_send(state, state->ev, state->opts, state->sh,
                                   bases[state->host_base_iter]->basedn,
                                   bases[state->host_base_iter]->scope,
                                   filter, attrs, state->ipa_opts->id->host_map,
                                   SDAP_OPTS_HOST, state->timeout, true);

    state->current_entity = ENTITY_HOST;
    if (subreq == NULL) {
        talloc_free(filter);
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, ipa_netgr_members_process, req);

    return EOK;
}

static void ipa_netgr_members_process(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ipa_get_netgroups_state *state = tevent_req_data(req,
                                               struct ipa_get_netgroups_state);
    struct sysdb_attrs **entities;
    size_t count;
    int ret, i;
    const char *orig_dn;
    hash_table_t *table;
    hash_key_t key;
    hash_value_t value;
    int (* next_call)(struct ipa_get_netgroups_state *,
                      struct tevent_req *);
    bool next_batch_scheduled = false;

    ret = sdap_get_generic_recv(subreq, state, &count, &entities);
    talloc_zfree(subreq);
    if (ret) {
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Found %zu members in current search base\n",
                                  count);

    next_call = NULL;
    /* While processing a batch of entities from one search base,
     * schedule query for another search base if there is one
     *
     * If there is no other search base, another class of entities
     * will be scheduled for lookup after processing of current
     * batch. The order of lookup is: netgroups -> users -> hosts
     */
    if (state->current_entity == ENTITY_NG) {
        /* We just received a batch of netgroups */
        state->netgr_base_iter++;
        ret = ipa_netgr_fetch_netgroups(state, req);
        table = state->new_netgroups;
        /* If there is a member netgroup, we always have to
         * ask for both member users and hosts
         * -> now schedule users
         */
        next_call = ipa_netgr_fetch_users;
    } else if (state->current_entity == ENTITY_USER) {
        /* We just received a batch of users */
        state->user_base_iter++;
        ret = ipa_netgr_fetch_users(state, req);
        table = state->new_users;
        if (state->entities_found & ENTITY_HOST ||
            state->entities_found & ENTITY_NG) {
            next_call = ipa_netgr_fetch_hosts;
        }
    } else if (state->current_entity == ENTITY_HOST) {
        /* We just received a batch of hosts */
        state->host_base_iter++;
        ret = ipa_netgr_fetch_hosts(state, req);
        table = state->new_hosts;
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Invalid entity type given for processing: %d\n",
               state->current_entity);
        ret = EINVAL;
        goto fail;
    }

    if (ret == EOK) {
        /* Next search base has been scheduled for inspection,
         * don't try to look for other type of entities
         */
        next_batch_scheduled = true;
    } else if (ret != ENOENT) {
        goto fail;
    }

    /* Process all member entities and store them in the designated hash table */
    key.type = HASH_KEY_STRING;
    value.type = HASH_VALUE_PTR;
    for (i = 0; i < count; i++) {
        ret = sysdb_attrs_get_string(entities[i], SYSDB_ORIG_DN, &orig_dn);
        if (ret != EOK) {
            goto fail;
        }

        key.str = talloc_strdup(table, orig_dn);
        if (key.str == NULL) {
            ret = ENOMEM;
            goto fail;
        }

        value.ptr = entities[i];
        ret = hash_enter(table, &key, &value);
        if (ret !=  HASH_SUCCESS) {
            goto fail;
        }
    }

    if (next_batch_scheduled) {
        /* The next search base is already scheduled to be searched */
        return;
    }

    if (next_call) {
        /* There is another class of members that has to be retrieved
         * - schedule the lookup
         */
        ret = next_call(state, req);
        if (ret != EOK) goto fail;
    } else {
        /* All members, that could have been fetched, were fetched */
        ret = ipa_netgr_process_all(state);
        if (ret != EOK) goto fail;

        tevent_req_done(req);
    }

    return;

fail:
    tevent_req_error(req, ret);
    return;
}

static bool extract_netgroups(hash_entry_t *entry, void *pvt)
{
    struct ipa_get_netgroups_state *state;
    state = talloc_get_type(pvt, struct ipa_get_netgroups_state);

    state->netgroups[state->netgroups_count] = talloc_get_type(entry->value.ptr,
                                                               struct sysdb_attrs);
    state->netgroups_count++;

    return true;
}

struct extract_state {
    const char *group;
    const char *appropriateMemberOf;

    const char **entries;
    int entries_count;
};

static bool extract_entities(hash_entry_t *entry, void *pvt)
{
    int ret;
    struct extract_state *state;
    struct sysdb_attrs *member;
    struct ldb_message_element *el;
    struct ldb_message_element *name_el;

    state = talloc_get_type(pvt, struct extract_state);
    member = talloc_get_type(entry->value.ptr, struct sysdb_attrs);

    ret = sysdb_attrs_get_el(member, state->appropriateMemberOf, &el);
    if (ret != EOK) {
        return false;
    }

    ret = sysdb_attrs_get_el(member, SYSDB_NAME, &name_el);
    if (ret != EOK || name_el == NULL || name_el->num_values == 0) {
        return false;
    }

    for (int j = 0; j < el->num_values; j++) {
        if (strcmp((char *)el->values[j].data, state->group) == 0) {
            state->entries = talloc_realloc(state, state->entries,
                                            const char *,
                                            state->entries_count + 1);
            if (state->entries == NULL) {
                return false;
            }

            state->entries[state->entries_count] = (char *)name_el->values[0].data;
            state->entries_count++;
            break;
        }
    }

    return true;
}

static int extract_members(TALLOC_CTX *mem_ctx,
                           struct sysdb_attrs *netgroup,
                           const char *member_type,
                           const char *appropriateMemberOf,
                           hash_table_t *lookup_table,
                           const char ***_ret_array,
                           int *_ret_count)
{
    struct extract_state *state;
    struct ldb_message_element *el;
    struct sysdb_attrs *member;
    hash_key_t key;
    hash_value_t value;
    const char **process = NULL;
    const char **ret_array = NULL;
    int process_count = 0;
    int ret_count = 0;
    int ret, i, pi;

    key.type = HASH_KEY_STRING;
    value.type = HASH_VALUE_PTR;

    state = talloc_zero(mem_ctx, struct extract_state);
    if (state == NULL) {
        ret = ENOMEM;
        goto done;
    }

    state->appropriateMemberOf = appropriateMemberOf;

    ret = sysdb_attrs_get_el(netgroup, member_type, &el);
    if (ret != EOK && ret != ENOENT) {
        goto done;
    }

    if (ret == EOK) {
        for (i = 0; i < el->num_values; i++) {
            key.str = (char *)el->values[i].data;
            ret = hash_lookup(lookup_table, &key, &value);
            if (ret != HASH_SUCCESS && ret != HASH_ERROR_KEY_NOT_FOUND) {
                ret = ENOENT;
                goto done;
            }

            if (ret == HASH_ERROR_KEY_NOT_FOUND) {
                process = talloc_realloc(mem_ctx, process, const char *, process_count + 1);
                if (process == NULL) {
                    ret = ENOMEM;
                    goto done;
                }

                process[process_count] = (char *)el->values[i].data;
                process_count++;
            } else {
                ret_array = talloc_realloc(mem_ctx, ret_array, const char *, ret_count + 1);
                if (ret_array == NULL) {
                    ret = ENOMEM;
                    goto done;
                }
                member = talloc_get_type(value.ptr, struct sysdb_attrs);
                ret = sysdb_attrs_get_string(member, SYSDB_NAME, &ret_array[ret_count]);
                if (ret != EOK) {
                    goto done;
                }
                ret_count++;
            }

            for (pi = 0; pi < process_count; pi++) {
                state->group = process[pi];
                hash_iterate(lookup_table, extract_entities, state);
                if (state->entries_count > 0) {
                    ret_array = talloc_realloc(mem_ctx, ret_array, const char *,
                            ret_count + state->entries_count);
                    if (ret_array == NULL) {
                        ret = ENOMEM;
                        goto done;
                    }
                    memcpy(&ret_array[ret_count], state->entries,
                            state->entries_count*sizeof(const char *));
                    ret_count += state->entries_count;
                }
                state->entries_count = 0;
                talloc_zfree(state->entries);
            }
        }
    } else {
        ret_array = NULL;
    }

    *_ret_array = ret_array;
    *_ret_count = ret_count;
    ret = EOK;

done:
    return ret;
}

static int ipa_netgr_process_all(struct ipa_get_netgroups_state *state)
{
    int i, j, k, ret;
    const char **members;
    struct sysdb_attrs *member;
    const char *member_name;
    struct extract_state *extract_state;
    struct ldb_message_element *external_hosts;
    const char *dash[] = {"-"};
    const char **uids = NULL;
    const char **hosts = NULL;
    int uids_count = 0;
    int hosts_count = 0;
    hash_key_t key;
    hash_value_t value;
    const char *domain;
    char *triple;

    state->netgroups = talloc_zero_array(state, struct sysdb_attrs *,
                                         hash_count(state->new_netgroups));
    if (state->netgroups == NULL) {
        return ENOMEM;
    }

    extract_state = talloc_zero(state, struct extract_state);
    if (extract_state == NULL) {
        ret = ENOMEM;
        goto done;
    }

    key.type = HASH_KEY_STRING;
    value.type = HASH_VALUE_PTR;

    hash_iterate(state->new_netgroups, extract_netgroups, state);
    for (i = 0; i < state->netgroups_count; i++) {
        /* Make sure these attributes always exist, so we can remove them if
         * there are no members. */
        ret = sysdb_attrs_add_empty(state->netgroups[i], SYSDB_NETGROUP_MEMBER);
        if (ret != EOK) {
            goto done;
        }

        ret = sysdb_attrs_add_empty(state->netgroups[i], SYSDB_NETGROUP_TRIPLE);
        if (ret != EOK) {
            goto done;
        }

        /* load all its member netgroups, translate */
        DEBUG(SSSDBG_TRACE_INTERNAL, "Extracting netgroup members of netgroup %d\n", i);
        ret = sysdb_attrs_get_string_array(state->netgroups[i],
                                           SYSDB_ORIG_NETGROUP_MEMBER,
                                           state, &members);
        if (ret != EOK && ret != ENOENT) {
            goto done;
        }

        j = 0;
        if (ret == EOK) {
            for (j = 0; members[j]; j++) {
                key.str = discard_const(members[j]);
                ret = hash_lookup(state->new_netgroups, &key, &value);
                if (ret != HASH_SUCCESS) {
                    ret = ENOENT;
                    goto done;
                }

                member = talloc_get_type(value.ptr, struct sysdb_attrs);
                ret = sysdb_attrs_get_string(member, SYSDB_NAME, &member_name);
                if (ret != EOK) {
                    goto done;
                }

                ret = sysdb_attrs_add_string(state->netgroups[i],
                                             SYSDB_NETGROUP_MEMBER,
                                             member_name);
                if (ret != EOK) {
                    goto done;
                }
            }
            talloc_zfree(members);
        }
        DEBUG(SSSDBG_TRACE_INTERNAL, "Extracted %d netgroup members\n", j);

        /* Load all UIDs */
        DEBUG(SSSDBG_TRACE_ALL, "Extracting user members of netgroup %d\n", i);
        ret = extract_members(state, state->netgroups[i],
                              SYSDB_ORIG_MEMBER_USER,
                              state->ipa_opts->id->user_map[SDAP_AT_USER_MEMBEROF].sys_name,
                              state->new_users,
                              &uids, &uids_count);
        if (ret != EOK) {
            goto done;
        }
        DEBUG(SSSDBG_TRACE_INTERNAL, "Extracted %d user members\n", uids_count);

        DEBUG(SSSDBG_TRACE_ALL, "Extracting host members of netgroup %d\n", i);
        ret = extract_members(state, state->netgroups[i],
                              SYSDB_ORIG_MEMBER_HOST,
                              state->ipa_opts->id->host_map[SDAP_AT_HOST_MEMBER_OF].sys_name,
                              state->new_hosts,
                              &hosts, &hosts_count);
        if (ret != EOK) {
            goto done;
        }
        DEBUG(SSSDBG_TRACE_INTERNAL, "Extracted %d host members\n", hosts_count);

        ret = sysdb_attrs_get_el(state->netgroups[i],
                                 SYSDB_ORIG_NETGROUP_EXTERNAL_HOST,
                                 &external_hosts);
        if (ret != EOK) {
            goto done;
        }

        if (external_hosts->num_values > 0) {
            hosts = talloc_realloc(state, hosts, const char *,
                                   hosts_count + external_hosts->num_values);
            if (hosts == NULL) {
                ret = ENOMEM;
                goto done;
            }

            for (j = 0; j < external_hosts->num_values; j++) {
                hosts[hosts_count] = talloc_strdup(hosts, (char *)external_hosts->values[j].data);
                if (hosts[hosts_count] == NULL) {
                    ret = ENOMEM;
                    goto done;
                }
                hosts_count++;
            }
        }

        ret = sysdb_attrs_get_string(state->netgroups[i], SYSDB_NETGROUP_DOMAIN,
                                     &domain);
        if (ret == ENOENT) {
            domain = NULL;
        } else if (ret != EOK) {
            goto done;
        }

        if (uids_count > 0 || hosts_count > 0) {
            if (uids_count == 0) {
                uids_count = 1;
                uids = dash;
            }

            if (hosts_count == 0) {
                hosts_count = 1;
                hosts = dash;
            }

            DEBUG(SSSDBG_TRACE_INTERNAL, "Putting together triples of "
                                          "netgroup %d\n", i);
            for (j = 0; j < uids_count; j++) {
                for (k = 0; k < hosts_count; k++) {
                    triple = talloc_asprintf(state, "(%s,%s,%s)",
                                             hosts[k], uids[j],
                                             domain ? domain : "");
                    if (triple == NULL) {
                        ret = ENOMEM;
                        goto done;
                    }

                    ret = sysdb_attrs_add_string(state->netgroups[i],
                                                 SYSDB_NETGROUP_TRIPLE,
                                                 triple);
                    if (ret != EOK) {
                        goto done;
                    }
                }
            }
        }

        ret = ipa_save_netgroup(state, state->dom,
                                state->opts, state->netgroups[i]);
        if (ret != EOK) {
            goto done;
        }
    }

    ret = EOK;
done:
    return ret;
}

int ipa_get_netgroups_recv(struct tevent_req *req,
                           TALLOC_CTX *mem_ctx,
                           size_t *reply_count,
                           struct sysdb_attrs ***reply)
{
    struct ipa_get_netgroups_state *state = tevent_req_data(req,
                                               struct ipa_get_netgroups_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (reply_count) {
        *reply_count = state->netgroups_count;
    }

    if (reply) {
        *reply = talloc_steal(mem_ctx, state->netgroups);
    }

    return EOK;
}
