/*
    SSSD

    Async LDAP Helper routines for autofs

    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

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
#include "providers/ldap/sdap_async_private.h"
#include "db/sysdb_autofs.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_autofs.h"
#include "providers/ldap/sdap_ops.h"

/* ====== Utility functions ====== */
static const char *
get_autofs_map_name(struct sysdb_attrs *map, struct sdap_options *opts)
{
    errno_t ret;
    struct ldb_message_element *el;

    ret = sysdb_attrs_get_el(map,
            opts->autofs_mobject_map[SDAP_AT_AUTOFS_MAP_NAME].sys_name,
            &el);
    if (ret) return NULL;
    if (el->num_values == 0) return NULL;

    return (const char *)el->values[0].data;
}

static const char *
get_autofs_entry_attr(struct sysdb_attrs *entry, struct sdap_options *opts,
                      enum sdap_autofs_entry_attrs attr)
{
    errno_t ret;
    struct ldb_message_element *el;

    ret = sysdb_attrs_get_el(entry,
            opts->autofs_entry_map[attr].sys_name,
            &el);
    if (ret) return NULL;
    if (el->num_values != 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Expected one entry got %d\n", el->num_values);
        return NULL;
    }

    return (const char *)el->values[0].data;
}

static const char *
get_autofs_entry_key(struct sysdb_attrs *entry, struct sdap_options *opts)
{
    return get_autofs_entry_attr(entry, opts, SDAP_AT_AUTOFS_ENTRY_KEY);
}

static const char *
get_autofs_entry_value(struct sysdb_attrs *entry, struct sdap_options *opts)
{
    return get_autofs_entry_attr(entry, opts, SDAP_AT_AUTOFS_ENTRY_VALUE);
}

static errno_t
add_autofs_entry(struct sss_domain_info *domain,
                 const char *map,
                 struct sdap_options *opts,
                 struct sysdb_attrs *entry,
                 time_t now)
{
    const char *key;
    const char *value;

    key = get_autofs_entry_key(entry, opts);
    if (!key) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not get autofs entry key\n");
        return EINVAL;
    }

    value = get_autofs_entry_value(entry, opts);
    if (!value) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not get autofs entry value\n");
        return EINVAL;
    }

    return sysdb_save_autofsentry(domain, map, key, value, NULL,
                                  domain->autofsmap_timeout, now);
}

static errno_t
save_autofs_entries(struct sss_domain_info *domain,
                    struct sdap_options *opts,
                    const char *map,
                    char **add_dn_list,
                    hash_table_t *entry_hash)
{
    hash_key_t key;
    hash_value_t value;
    size_t i;
    int hret;
    errno_t ret;
    struct sysdb_attrs *entry;
    time_t now;

    if (!add_dn_list) {
        return EOK;
    }

    now = time(NULL);

    for (i=0; add_dn_list[i]; i++) {
        key.type = HASH_KEY_STRING;
        key.str = (char *) add_dn_list[i];

        hret = hash_lookup(entry_hash, &key, &value);
        if (hret != HASH_SUCCESS) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Cannot retrieve entry [%s] from hash\n", add_dn_list[i]);
            continue;
        }

        entry = talloc_get_type(value.ptr, struct sysdb_attrs);
        if (!entry) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Cannot retrieve entry [%s] from ptr\n", add_dn_list[i]);
            continue;
        }

        DEBUG(SSSDBG_TRACE_FUNC,
              "Saving autofs entry [%s]\n", add_dn_list[i]);
        ret = add_autofs_entry(domain, map, opts, entry, now);
        if (ret) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Cannot save entry [%s] to cache\n", add_dn_list[i]);
            continue;
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Saved entry [%s]\n", add_dn_list[i]);
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "All entries saved\n");
    return EOK;
}

static errno_t
del_autofs_entries(struct sss_domain_info *dom,
                   char **del_dn_list)
{
    size_t i;
    errno_t ret;

    for (i=0; del_dn_list[i]; i++) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Removing autofs entry [%s]\n", del_dn_list[i]);

        ret = sysdb_del_autofsentry(dom, del_dn_list[i]);
        if (ret) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Cannot delete entry %s\n", del_dn_list[i]);
            continue;
        }
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "All entries removed\n");
    return EOK;
}

static errno_t
save_autofs_map(struct sss_domain_info *dom,
                struct sdap_options *opts,
                struct sysdb_attrs *map,
                bool enumerated)
{
    const char *mapname;
    const char *origdn;
    errno_t ret;
    time_t now;

    mapname = get_autofs_map_name(map, opts);
    if (!mapname) return EINVAL;

    ret = sysdb_attrs_get_string(map, SYSDB_ORIG_DN, &origdn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get original dn [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    now = time(NULL);

    ret = sysdb_save_autofsmap(dom, mapname, mapname, origdn,
                               NULL, dom->autofsmap_timeout, now, enumerated);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

struct automntmaps_process_members_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;
    struct sss_domain_info *dom;
    int    timeout;

    const char *orig_dn;
    char *base_filter;
    char *filter;
    const char **attrs;
    size_t base_iter;
    struct sdap_search_base **search_bases;

    struct sysdb_attrs *map;

    struct sysdb_attrs **entries;
    size_t entries_count;
};

static void
automntmaps_process_members_done(struct tevent_req *subreq);
static errno_t
automntmaps_process_members_next_base(struct tevent_req *req);

static struct tevent_req *
automntmaps_process_members_send(TALLOC_CTX *mem_ctx,
                                 struct tevent_context *ev,
                                 struct sdap_options *opts,
                                 struct sdap_handle *sh,
                                 struct sss_domain_info *dom,
                                 struct sdap_search_base **search_bases,
                                 int    timeout,
                                 struct sysdb_attrs *map)
{
    errno_t ret;
    struct tevent_req *req;
    struct automntmaps_process_members_state *state;

    req = tevent_req_create(mem_ctx, &state,
                            struct automntmaps_process_members_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->dom = dom;
    state->sh = sh;
    state->timeout = timeout;
    state->base_iter = 0;
    state->map = map;
    state->search_bases = search_bases;

    state->base_filter = talloc_asprintf(state, "(&(%s=*)(objectclass=%s))",
                    opts->autofs_entry_map[SDAP_AT_AUTOFS_ENTRY_KEY].name,
                    opts->autofs_entry_map[SDAP_OC_AUTOFS_ENTRY].name);
    if (!state->base_filter) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to build filter\n");
        ret = ENOMEM;
        goto immediate;
    }

    ret = build_attrs_from_map(state, opts->autofs_entry_map,
                               SDAP_OPTS_AUTOFS_ENTRY, NULL,
                               &state->attrs, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to build attributes from map\n");
        ret = ENOMEM;
        goto immediate;
    }


    ret = sysdb_attrs_get_string(state->map, SYSDB_ORIG_DN, &state->orig_dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot get originalDN\n");
        goto immediate;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Examining autofs map [%s]\n", state->orig_dn);

    ret = automntmaps_process_members_next_base(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "search failed [%d]: %s\n", ret, strerror(ret));
        goto immediate;
    }

    return req;

immediate:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    } else {
        tevent_req_done(req);
    }
    tevent_req_post(req, ev);
    return req;
}

static errno_t
automntmaps_process_members_next_base(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct automntmaps_process_members_state *state =
        tevent_req_data(req, struct automntmaps_process_members_state);

    talloc_zfree(state->filter);
    state->filter = sdap_combine_filters(state, state->base_filter,
                        state->search_bases[state->base_iter]->filter);
    if (!state->filter) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Searching for automount map entries with base [%s]\n",
           state->search_bases[state->base_iter]->basedn);

    subreq = sdap_get_generic_send(state, state->ev, state->opts, state->sh,
                                   state->orig_dn,
                                   state->search_bases[state->base_iter]->scope,
                                   state->filter, state->attrs,
                                   state->opts->autofs_entry_map,
                                   SDAP_OPTS_AUTOFS_ENTRY,
                                   state->timeout, true);
    if (!subreq) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot start search for entries\n");
        return EIO;
    }
    tevent_req_set_callback(subreq, automntmaps_process_members_done, req);

    return EOK;
}

static void
automntmaps_process_members_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct automntmaps_process_members_state *state =
        tevent_req_data(req, struct automntmaps_process_members_state);
    errno_t ret;
    struct sysdb_attrs **entries;
    size_t entries_count, i;

    ret = sdap_get_generic_recv(subreq, state,
                                &entries_count, &entries);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    if (entries_count > 0) {
        state->entries = talloc_realloc(state, state->entries,
                                        struct sysdb_attrs *,
                                        state->entries_count + entries_count + 1);
        if (state->entries == NULL) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        for (i=0; i < entries_count; i++) {
            state->entries[state->entries_count + i] =
                talloc_steal(state->entries, entries[i]);
        }

        state->entries_count += entries_count;
        state->entries[state->entries_count] = NULL;
    }

    state->base_iter++;
    if (state->search_bases[state->base_iter]) {
        ret = automntmaps_process_members_next_base(req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "No more search bases to try\n");

    DEBUG(SSSDBG_TRACE_FUNC,
          "Search for autofs entries, returned %zu results.\n",
          state->entries_count);

    tevent_req_done(req);
    return;
}

static errno_t
automntmaps_process_members_recv(struct tevent_req *req,
                                 TALLOC_CTX *mem_ctx,
                                 size_t *entries_count,
                                 struct sysdb_attrs ***entries)
{
    struct automntmaps_process_members_state *state;
    state = tevent_req_data(req, struct automntmaps_process_members_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (entries_count) {
        *entries_count = state->entries_count;
    }

    if (entries) {
        *entries = talloc_steal(mem_ctx, state->entries);
    }

    return EOK;
}

struct sdap_get_automntmap_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;
    struct sss_domain_info *dom;
    const char **attrs;
    const char *base_filter;
    char *filter;
    int timeout;

    char *higher_timestamp;

    struct sysdb_attrs **map;
    size_t count;

    struct sysdb_attrs **entries;
    size_t entries_count;

    size_t base_iter;
    struct sdap_search_base **search_bases;
};

static errno_t
sdap_get_automntmap_next_base(struct tevent_req *req);
static void
sdap_get_automntmap_process(struct tevent_req *subreq);

static struct tevent_req *
sdap_get_automntmap_send(TALLOC_CTX *memctx,
                         struct tevent_context *ev,
                         struct sss_domain_info *dom,
                         struct sdap_options *opts,
                         struct sdap_search_base **search_bases,
                         struct sdap_handle *sh,
                         const char **attrs,
                         const char *filter,
                         int timeout)
{
    errno_t ret;
    struct tevent_req *req;
    struct sdap_get_automntmap_state *state;

    req = tevent_req_create(memctx, &state, struct sdap_get_automntmap_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->dom = dom;
    state->sh = sh;
    state->attrs = attrs;
    state->higher_timestamp = NULL;
    state->map =  NULL;
    state->count = 0;
    state->timeout = timeout;
    state->base_filter = filter;
    state->base_iter = 0;
    state->search_bases = search_bases;

    ret = sdap_get_automntmap_next_base(req);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, state->ev);
    }
    return req;
}

static errno_t
sdap_get_automntmap_next_base(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct sdap_get_automntmap_state *state;

    state = tevent_req_data(req, struct sdap_get_automntmap_state);

    talloc_zfree(state->filter);
    state->filter = sdap_combine_filters(state, state->base_filter,
                        state->search_bases[state->base_iter]->filter);
    if (!state->filter) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Searching for automount maps with base [%s]\n",
           state->search_bases[state->base_iter]->basedn);

    subreq = sdap_get_generic_send(
            state, state->ev, state->opts, state->sh,
            state->search_bases[state->base_iter]->basedn,
            state->search_bases[state->base_iter]->scope,
            state->filter, state->attrs,
            state->opts->autofs_mobject_map, SDAP_OPTS_AUTOFS_MAP,
            state->timeout,
            false);
    if (!subreq) {
        return EIO;
    }
    tevent_req_set_callback(subreq, sdap_get_automntmap_process, req);

    return EOK;
}

static void
sdap_get_automntmap_done(struct tevent_req *subreq);

static void
sdap_get_automntmap_process(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_automntmap_state *state = tevent_req_data(req,
                                               struct sdap_get_automntmap_state);
    errno_t ret;

    ret = sdap_get_generic_recv(subreq, state,
                                &state->count, &state->map);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Search for autofs maps, returned %zu results.\n", state->count);

    if (state->count == 0) {
        /* No maps found in this search */
        state->base_iter++;
        if (state->search_bases[state->base_iter]) {
            /* There are more search bases to try */
            ret = sdap_get_automntmap_next_base(req);
            if (ret != EOK) {
                tevent_req_error(req, ENOENT);
            }
            return;
        }

        tevent_req_error(req, ENOENT);
        return;
    } else if (state->count > 1) {
        DEBUG(SSSDBG_OP_FAILURE,
              "The search yielded more than one autofs map\n");
        tevent_req_error(req, EIO);
        return;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Processing autofs maps\n");
    subreq = automntmaps_process_members_send(state, state->ev, state->opts,
                                              state->sh, state->dom,
                                              state->search_bases,
                                              state->timeout,
                                              state->map[0]);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sdap_get_automntmap_done, req);

    return;
}

static void
sdap_get_automntmap_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_automntmap_state *state = tevent_req_data(req,
                                               struct sdap_get_automntmap_state);
    errno_t ret;

    ret = automntmaps_process_members_recv(subreq, state, &state->entries_count,
                                           &state->entries);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "automount map members received\n");
    tevent_req_done(req);
    return;
}

static errno_t
sdap_get_automntmap_recv(struct tevent_req *req,
                         TALLOC_CTX *mem_ctx,
                         struct sysdb_attrs **map,
                         size_t *entries_count,
                         struct sysdb_attrs ***entries)
{
    struct sdap_get_automntmap_state *state = tevent_req_data(req,
                                               struct sdap_get_automntmap_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (map) {
        *map = talloc_steal(mem_ctx, state->map[0]);
    }

    if (entries_count) {
        *entries_count = state->entries_count;
    }

    if (entries) {
        *entries = talloc_steal(mem_ctx, state->entries);
    }

    return EOK;
}

struct sdap_autofs_setautomntent_state {
    char *filter;
    const char **attrs;
    struct sdap_options *opts;
    struct sdap_handle *sh;
    struct sysdb_ctx *sysdb;
    struct sdap_id_op *sdap_op;
    struct sss_domain_info *dom;

    const char *mapname;
    struct sysdb_attrs *map;
    struct sysdb_attrs **entries;
    size_t entries_count;

    int dp_error;
};

static void
sdap_autofs_setautomntent_done(struct tevent_req *subreq);

struct tevent_req *
sdap_autofs_setautomntent_send(TALLOC_CTX *memctx,
                               struct tevent_context *ev,
                               struct sss_domain_info *dom,
                               struct sysdb_ctx *sysdb,
                               struct sdap_handle *sh,
                               struct sdap_id_op *op,
                               struct sdap_options *opts,
                               const char *mapname)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct sdap_autofs_setautomntent_state *state;
    char *clean_mapname;
    errno_t ret;

    req = tevent_req_create(memctx, &state,
                            struct sdap_autofs_setautomntent_state);
    if (!req) return NULL;

    if (!mapname) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No map name given\n");
        ret = EINVAL;
        goto fail;
    }

    state->sh = sh;
    state->sysdb = sysdb;
    state->opts = opts;
    state->sdap_op = op;
    state->dom = dom;
    state->mapname = mapname;

    ret = sss_filter_sanitize(state, mapname, &clean_mapname);
    if (ret != EOK) {
        goto fail;
    }

    state->filter = talloc_asprintf(state, "(&(%s=%s)(objectclass=%s))",
                    state->opts->autofs_mobject_map[SDAP_AT_AUTOFS_MAP_NAME].name,
                    clean_mapname,
                    state->opts->autofs_mobject_map[SDAP_OC_AUTOFS_MAP].name);
    if (!state->filter) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to build filter\n");
        ret = ENOMEM;
        goto fail;
    }
    talloc_free(clean_mapname);

    ret = build_attrs_from_map(state, state->opts->autofs_mobject_map,
                               SDAP_OPTS_AUTOFS_MAP, NULL,
                               &state->attrs, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to build attributes from map\n");
        ret = ENOMEM;
        goto fail;
    }

    subreq = sdap_get_automntmap_send(state, ev, dom,
                                      state->opts,
                                      state->opts->sdom->autofs_search_bases,
                                      state->sh,
                                      state->attrs, state->filter,
                                      dp_opt_get_int(state->opts->basic,
                                                     SDAP_SEARCH_TIMEOUT));
    if (!subreq) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sdap_get_automntmap_send failed\n");
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, sdap_autofs_setautomntent_done, req);
    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static errno_t
sdap_autofs_setautomntent_save(struct tevent_req *req);

static void
sdap_autofs_setautomntent_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_autofs_setautomntent_state *state = tevent_req_data(req,
                                    struct sdap_autofs_setautomntent_state);

    ret = sdap_get_automntmap_recv(subreq, state, &state->map,
                                   &state->entries_count, &state->entries);
    talloc_zfree(subreq);
    if (ret != EOK) {
        if (ret == ENOENT) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Could not find automount map\n");
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                "sdap_get_automntmap_recv failed [%d]: %s\n",
                ret, strerror(ret));
        }
        tevent_req_error(req, ret);
        return;
    }

    ret = sdap_autofs_setautomntent_save(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not save automount map\n");
        tevent_req_error(req, ret);
        return;
    }

    state->dp_error = DP_ERR_OK;
    tevent_req_done(req);
    return;
}

static errno_t
sdap_autofs_setautomntent_save(struct tevent_req *req)
{
    struct sdap_autofs_setautomntent_state *state = tevent_req_data(req,
                                    struct sdap_autofs_setautomntent_state);
    errno_t ret, tret;
    bool in_transaction = false;
    TALLOC_CTX *tmp_ctx;
    struct ldb_message **entries = NULL;
    size_t count;
    const char *key;
    const char *val;
    char **sysdb_entrylist = NULL;
    char **ldap_entrylist = NULL;
    char **add_entries = NULL;
    char **del_entries = NULL;
    size_t i, j;

    hash_table_t *entry_hash = NULL;
    hash_key_t hkey;
    hash_value_t value;
    int hret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    DEBUG(SSSDBG_TRACE_LIBS,
          "Got %zu map entries from LDAP\n", state->entries_count);
    if (state->entries_count == 0) {
        /* No entries for this map in LDAP.
         * We need to ensure that there are no entries
         * in the sysdb either.
         */
        ldap_entrylist = NULL;
    } else {
        ldap_entrylist = talloc_array(tmp_ctx, char *,
                                      state->entries_count+1);
        if (!ldap_entrylist) {
            ret = ENOMEM;
            goto done;
        }

        ret = sss_hash_create(state, 0, &entry_hash);
        if (ret) {
            goto done;
        }

        /* Get a list of the map members by DN */
        for (i=0, j=0; i < state->entries_count; i++) {
            key = get_autofs_entry_key(state->entries[i], state->opts);
            val = get_autofs_entry_value(state->entries[i], state->opts);
            if (!key || !val) {
                DEBUG(SSSDBG_MINOR_FAILURE, "Malformed entry, skipping\n");
                continue;
            }

            ldap_entrylist[j] = sysdb_autofsentry_strdn(ldap_entrylist,
                                                        state->dom,
                                                        state->mapname,
                                                        key, val);
            if (!ldap_entrylist[j]) {
                ret = ENOMEM;
                goto done;
            }

            hkey.type = HASH_KEY_STRING;
            hkey.str = ldap_entrylist[j];
            value.type = HASH_VALUE_PTR;
            value.ptr = state->entries[i];

            hret = hash_enter(entry_hash, &hkey, &value);
            if (hret != HASH_SUCCESS) {
                ret = EIO;
                goto done;
            }

            j++;
        }
        /* terminate array with NULL after the last retrieved entry */
        ldap_entrylist[j] = NULL;
    }

    ret = sysdb_autofs_entries_by_map(tmp_ctx, state->dom, state->mapname,
                                      &count, &entries);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE,
              "cache lookup for the map failed [%d]: %s\n",
               ret, strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "Got %zu map entries from sysdb\n", count);
    if (count == 0) {
        /* No map members for this map in sysdb currently */
        sysdb_entrylist = NULL;
    } else {
        sysdb_entrylist = talloc_array(state, char *, count+1);
        if (!sysdb_entrylist) {
            ret = ENOMEM;
            goto done;
        }

        /* Get a list of the map members by DN */
        for (i=0; i < count; i++) {
            sysdb_entrylist[i] = talloc_strdup(sysdb_entrylist,
                                        ldb_dn_get_linearized(entries[i]->dn));
            if (!sysdb_entrylist[i]) {
                ret = ENOMEM;
                goto done;
            }
        }
        sysdb_entrylist[count] = NULL;
    }

    /* Find the differences between the sysdb and LDAP lists
     * Entries in the sysdb only must be removed.
     */
    ret = diff_string_lists(tmp_ctx, ldap_entrylist, sysdb_entrylist,
                            &add_entries, &del_entries, NULL);
    if (ret != EOK) goto done;

    ret = sysdb_transaction_start(state->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
             "Cannot start sysdb transaction [%d]: %s\n",
              ret, strerror(ret));
        goto done;
    }
    in_transaction = true;

    /* Save the map itself */
    ret = save_autofs_map(state->dom, state->opts, state->map, true);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
             "Cannot save autofs map entry [%d]: %s\n",
              ret, strerror(ret));
        goto done;
    }

    /* Create entries that don't exist yet */
    if (add_entries && add_entries[0]) {
        ret = save_autofs_entries(state->dom, state->opts,
                                  state->mapname, add_entries,
                                  entry_hash);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Cannot save autofs entries [%d]: %s\n",
                  ret, strerror(ret));
            goto done;
        }
    }

    /* Delete entries that don't exist anymore */
    if (del_entries && del_entries[0]) {
        ret = del_autofs_entries(state->dom, del_entries);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Cannot delete autofs entries [%d]: %s\n",
                  ret, strerror(ret));
            goto done;
        }
    }


    ret = sysdb_transaction_commit(state->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
             "Cannot commit sysdb transaction [%d]: %s\n",
              ret, strerror(ret));
        goto done;
    }
    in_transaction = false;

    ret = EOK;
done:
    if (in_transaction) {
        tret = sysdb_transaction_cancel(state->sysdb);
        if (tret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                "Cannot cancel sysdb transaction [%d]: %s\n",
                ret, strerror(ret));
        }
    }
    talloc_zfree(tmp_ctx);
    return ret;
}

errno_t
sdap_autofs_setautomntent_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

struct sdap_autofs_get_map_state {
    struct sdap_id_ctx *id_ctx;
    struct sdap_options *opts;
    struct sdap_id_op *sdap_op;
    const char *mapname;
    int dp_error;
};

static errno_t sdap_autofs_get_map_retry(struct tevent_req *req);
static void sdap_autofs_get_map_connect_done(struct tevent_req *subreq);
static void sdap_autofs_get_map_done(struct tevent_req *subreq);

struct tevent_req *sdap_autofs_get_map_send(TALLOC_CTX *mem_ctx,
                                            struct sdap_id_ctx *id_ctx,
                                            const char *mapname)
{
    struct tevent_req *req;
    struct sdap_autofs_get_map_state *state;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sdap_autofs_get_map_state);
    if (!req) {
        return NULL;
    }

    state->id_ctx = id_ctx;
    state->opts = id_ctx->opts;
    state->mapname = mapname;
    state->dp_error = DP_ERR_FATAL;

    state->sdap_op = sdap_id_op_create(state, id_ctx->conn->conn_cache);
    if (!state->sdap_op) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create() failed\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sdap_autofs_get_map_retry(req);
    if (ret == EAGAIN) {
        /* asynchronous processing */
        return req;
    }

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, id_ctx->be->ev);

    return req;
}

static errno_t sdap_autofs_get_map_retry(struct tevent_req *req)
{
    struct sdap_autofs_get_map_state *state;
    struct tevent_req *subreq;
    int ret;

    state = tevent_req_data(req, struct sdap_autofs_get_map_state);

    subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sdap_id_op_connect_send() failed: "
                                   "%d(%s)\n", ret, strerror(ret));
        return ret;
    }

    tevent_req_set_callback(subreq, sdap_autofs_get_map_connect_done, req);

    return EAGAIN;
}

static void sdap_autofs_get_map_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct sdap_autofs_get_map_state *state;
    char *filter;
    char *safe_mapname;
    const char **attrs;
    int dp_error;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_autofs_get_map_state);

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "LDAP connection failed "
                                   "[%d]: %s\n", ret, strerror(ret));
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "LDAP connection successful\n");

    ret = sss_filter_sanitize(state, state->mapname, &safe_mapname);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    filter = talloc_asprintf(state, "(&(%s=%s)(objectclass=%s))",
                 state->opts->autofs_mobject_map[SDAP_AT_AUTOFS_MAP_NAME].name,
                 safe_mapname,
                 state->opts->autofs_mobject_map[SDAP_OC_AUTOFS_MAP].name);
    if (filter == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to build filter\n");
        tevent_req_error(req, ret);
        return;
    }

    ret = build_attrs_from_map(state, state->opts->autofs_mobject_map,
                               SDAP_OPTS_AUTOFS_MAP, NULL, &attrs, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to build attributes from map\n");
        tevent_req_error(req, ret);
        return;
    }

    subreq = sdap_search_bases_return_first_send(state, state->id_ctx->be->ev,
                    state->opts, sdap_id_op_handle(state->sdap_op),
                    state->opts->sdom->autofs_search_bases,
                    state->opts->autofs_mobject_map, false,
                    dp_opt_get_int(state->opts->basic, SDAP_SEARCH_TIMEOUT),
                    filter, attrs, NULL);
    if (subreq == NULL) {
        state->dp_error = DP_ERR_FATAL;
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, sdap_autofs_get_map_done, req);
}

static void sdap_autofs_get_map_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct sdap_autofs_get_map_state *state;
    struct sysdb_attrs **reply;
    size_t reply_count;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_autofs_get_map_state);

    ret = sdap_search_bases_return_first_recv(subreq, state, &reply_count,
                                              &reply);
    talloc_zfree(subreq);

    ret = sdap_id_op_done(state->sdap_op, ret, &state->dp_error);
    if (state->dp_error == DP_ERR_OK && ret != EOK) {
        /* retry */
        ret = sdap_autofs_get_map_retry(req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
        }
        return;
    } else if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    if (reply_count == 0) {
        ret = sysdb_delete_autofsmap(state->id_ctx->be->domain, state->mapname);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE,
                "Cannot delete autofs map %s [%d]: %s\n",
                 state->mapname, ret, strerror(ret));
            tevent_req_error(req, ret);
            return;
        }

        tevent_req_done(req);
        return;
    }

    ret = save_autofs_map(state->id_ctx->be->domain, state->opts, reply[0], false);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
             "Cannot save autofs map %s [%d]: %s\n",
              state->mapname, ret, strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t sdap_autofs_get_map_recv(struct tevent_req *req,
                                 int *dp_error)
{
    struct sdap_autofs_get_map_state *state;

    state = tevent_req_data(req, struct sdap_autofs_get_map_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *dp_error = state->dp_error;

    return EOK;
}

struct sdap_autofs_get_entry_state {
    struct sdap_id_ctx *id_ctx;
    struct sdap_options *opts;
    struct sdap_id_op *sdap_op;
    const char *mapname;
    const char *entryname;
    int dp_error;
};

static errno_t sdap_autofs_get_entry_retry(struct tevent_req *req);
static void sdap_autofs_get_entry_connect_done(struct tevent_req *subreq);
static void sdap_autofs_get_entry_done(struct tevent_req *subreq);

struct tevent_req *sdap_autofs_get_entry_send(TALLOC_CTX *mem_ctx,
                                              struct sdap_id_ctx *id_ctx,
                                              const char *mapname,
                                              const char *entryname)
{
    struct tevent_req *req;
    struct sdap_autofs_get_entry_state *state;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sdap_autofs_get_entry_state);
    if (!req) {
        return NULL;
    }

    state->id_ctx = id_ctx;
    state->opts = id_ctx->opts;
    state->mapname = mapname;
    state->entryname = entryname;
    state->dp_error = DP_ERR_FATAL;

    state->sdap_op = sdap_id_op_create(state, id_ctx->conn->conn_cache);
    if (!state->sdap_op) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create() failed\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sdap_autofs_get_entry_retry(req);
    if (ret == EAGAIN) {
        /* asynchronous processing */
        return req;
    }

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, id_ctx->be->ev);

    return req;
}

static errno_t sdap_autofs_get_entry_retry(struct tevent_req *req)
{
    struct sdap_autofs_get_entry_state *state;
    struct tevent_req *subreq;
    int ret;

    state = tevent_req_data(req, struct sdap_autofs_get_entry_state);

    subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sdap_id_op_connect_send() failed: "
                                   "%d(%s)\n", ret, strerror(ret));
        return ret;
    }

    tevent_req_set_callback(subreq, sdap_autofs_get_entry_connect_done, req);

    return EAGAIN;
}

static void sdap_autofs_get_entry_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct sdap_autofs_get_entry_state *state;
    struct ldb_message *map;
    char *filter;
    char *safe_entryname;
    const char **attrs;
    const char *base_dn;
    int dp_error;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_autofs_get_entry_state);

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "LDAP connection failed "
                                   "[%d]: %s\n", ret, strerror(ret));
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "LDAP connection successful\n");

    ret = sysdb_get_map_byname(state, state->id_ctx->be->domain,
                               state->mapname, &map);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Map %s does not exist!\n", state->mapname);
        tevent_req_error(req, ret);
        return;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get map %s [%d]: %s\n",
              state->mapname, ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    base_dn = ldb_msg_find_attr_as_string(map, SYSDB_ORIG_DN, NULL);
    if (base_dn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot get originalDN\n");
        tevent_req_error(req, ERR_INTERNAL);
        return;
    }

    ret = sss_filter_sanitize(state, state->entryname, &safe_entryname);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    filter = talloc_asprintf(state, "(&(%s=%s)(objectclass=%s))",
                 state->opts->autofs_entry_map[SDAP_AT_AUTOFS_ENTRY_KEY].name,
                 safe_entryname,
                 state->opts->autofs_entry_map[SDAP_OC_AUTOFS_ENTRY].name);
    if (filter == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to build filter\n");
        tevent_req_error(req, ret);
        return;
    }

    ret = build_attrs_from_map(state, state->opts->autofs_entry_map,
                               SDAP_OPTS_AUTOFS_ENTRY, NULL, &attrs, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to build attributes from map\n");
        tevent_req_error(req, ret);
        return;
    }

    subreq = sdap_search_bases_return_first_send(state, state->id_ctx->be->ev,
                    state->opts, sdap_id_op_handle(state->sdap_op),
                    state->opts->sdom->autofs_search_bases,
                    state->opts->autofs_entry_map, false,
                    dp_opt_get_int(state->opts->basic, SDAP_SEARCH_TIMEOUT),
                    filter, attrs, base_dn);
    if (subreq == NULL) {
        state->dp_error = DP_ERR_FATAL;
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, sdap_autofs_get_entry_done, req);
}

static errno_t sdap_autofs_save_entry(struct sss_domain_info *domain,
                                      struct sdap_options *opts,
                                      struct sysdb_attrs *newentry,
                                      const char *mapname,
                                      const char *entryname);

static void sdap_autofs_get_entry_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct sdap_autofs_get_entry_state *state;
    struct sysdb_attrs **reply;
    size_t reply_count;
    size_t i;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_autofs_get_entry_state);

    ret = sdap_search_bases_return_first_recv(subreq, state, &reply_count,
                                              &reply);
    talloc_zfree(subreq);

    ret = sdap_id_op_done(state->sdap_op, ret, &state->dp_error);
    if (state->dp_error == DP_ERR_OK && ret != EOK) {
        /* retry */
        ret = sdap_autofs_get_entry_retry(req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
        }
        return;
    } else if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    /* This will delete the entry if it already exist. */
    if (reply_count == 0) {
        ret = sdap_autofs_save_entry(state->id_ctx->be->domain, state->opts,
                                     NULL, state->mapname, state->entryname);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }

        goto done;
    }

    /* If other attribute then automountKey is in the distinguished name and
     * there are multiple entries with different casing then we may get more
     * then one result. */
    for (i = 0; i < reply_count; i++) {
        ret = sdap_autofs_save_entry(state->id_ctx->be->domain, state->opts,
                                     reply[i], state->mapname,
                                     state->entryname);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }
    }

done:
    tevent_req_done(req);
    return;
}

errno_t sdap_autofs_get_entry_recv(struct tevent_req *req,
                                   int *dp_error)
{
    struct sdap_autofs_get_entry_state *state;

    state = tevent_req_data(req, struct sdap_autofs_get_entry_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *dp_error = state->dp_error;

    return EOK;
}

static errno_t sdap_autofs_save_entry(struct sss_domain_info *domain,
                                      struct sdap_options *opts,
                                      struct sysdb_attrs *newentry,
                                      const char *mapname,
                                      const char *entryname)
{
    bool in_transaction = false;
    errno_t ret;
    int tret;

    ret = sysdb_transaction_start(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot start sysdb transaction [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }
    in_transaction = true;

    /* Delete existing entry to cover case where new entry has the same key
     * but different automountInformation. Because the dn is created from the
     * combination of key and information it would be possible to end up with
     * two entries with same key but different information otherwise.
     */
    ret = sysdb_del_autofsentry_by_key(domain, mapname, entryname);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Cannot delete entry %s:%s\n",
              mapname, entryname);
        goto done;
    }

    if (newentry != NULL) {
        ret = add_autofs_entry(domain, mapname, opts, newentry, time(NULL));
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Cannot save autofs entry %s:%s [%d]: %s\n",
                  mapname, entryname, ret, sss_strerror(ret));
            goto done;
        }
    }

    ret = sysdb_transaction_commit(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot commit sysdb transaction [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }
    in_transaction = false;

    ret = EOK;

done:
    if (in_transaction) {
        tret = sysdb_transaction_cancel(domain->sysdb);
        if (tret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Cannot cancel sysdb transaction "
                  "[%d]: %s\n", ret, sss_strerror(ret));
        }
    }

    return ret;
}
