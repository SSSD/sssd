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
get_autofs_entry_key(struct sysdb_attrs *entry, struct sdap_options *opts)
{
    errno_t ret;
    struct ldb_message_element *el;

    ret = sysdb_attrs_get_el(entry,
            opts->autofs_entry_map[SDAP_AT_AUTOFS_ENTRY_KEY].sys_name,
            &el);
    if (ret) return NULL;
    if (el->num_values == 0) return NULL;

    return (const char *)el->values[0].data;
}

static errno_t
save_autofs_entry(struct sysdb_ctx *sysdb,
                  struct sdap_options *opts,
                  struct sysdb_attrs *entry)
{
    const char *key;
    const char *value;
    struct ldb_message_element *el;
    errno_t ret;

    key = get_autofs_entry_key(entry, opts);
    if (!key) return EINVAL;

    ret = sysdb_attrs_get_el(entry,
            opts->autofs_entry_map[SDAP_AT_AUTOFS_ENTRY_VALUE].sys_name,
            &el);
    if (ret) return ret;
    if (el->num_values == 0) return EINVAL;
    else value = (const char *)el->values[0].data;

    ret = sysdb_save_autofsentry(sysdb, key, value, NULL);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

static errno_t
save_autofs_entries(struct sysdb_ctx *sysdb,
                    struct sdap_options *opts,
                    char **add_entries,
                    struct sysdb_attrs **entries,
                    size_t num_entries)
{
    errno_t ret, tret;
    const char *key;
    bool in_transaction = false;
    int i, j;

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
             ("Cannot start sysdb transaction [%d]: %s\n",
              ret, strerror(ret)));
        goto done;
    }
    in_transaction = true;

    for (i=0; add_entries[i]; i++) {
        for (j=0; j < num_entries; j++) {
            key = get_autofs_entry_key(entries[j], opts);
            if (!key) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      ("An entry without name? Skipping\n"));
                return EINVAL;
            }

            if (strcmp(add_entries[i], key)) {
                continue;
            }

            ret = save_autofs_entry(sysdb, opts, entries[j]);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                    ("Cannot save autofs entry [%d]: %s. Ignoring.\n",
                    ret, strerror(ret)));
                continue;
            }
        }
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
             ("Cannot commit sysdb transaction [%d]: %s\n",
              ret, strerror(ret)));
        goto done;
    }
    in_transaction = false;

    ret = EOK;
done:
    if (in_transaction) {
        tret = sysdb_transaction_cancel(sysdb);
        if (tret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                ("Cannot cancel sysdb transaction [%d]: %s\n",
                ret, strerror(ret)));
        }
    }
    return ret;
}

static errno_t
save_autofs_map(struct sysdb_ctx *sysdb,
                struct sss_domain_info *dom,
                struct sdap_options *opts,
                struct sysdb_attrs *map)
{
    const char *mapname;
    errno_t ret;
    time_t now;

    mapname = get_autofs_map_name(map, opts);
    if (!mapname) return EINVAL;

    now = time(NULL);

    ret = sysdb_save_autofsmap(sysdb, mapname, mapname,
                               NULL, dom->autofsmap_timeout, now);
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
    struct sysdb_ctx *sysdb;

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
                                 struct sysdb_ctx *sysdb,
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
    state->sysdb = sysdb;
    state->timeout = timeout;
    state->base_iter = 0;
    state->map = map;
    state->search_bases = search_bases;

    state->base_filter = talloc_asprintf(state, "(&(%s=*)(objectclass=%s))",
                    opts->autofs_entry_map[SDAP_AT_AUTOFS_ENTRY_KEY].name,
                    opts->autofs_entry_map[SDAP_OC_AUTOFS_ENTRY].name);
    if (!state->base_filter) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to build filter\n"));
        ret = ENOMEM;
        goto immediate;
    }

    ret = build_attrs_from_map(state, opts->autofs_entry_map,
                               SDAP_OPTS_AUTOFS_ENTRY, NULL,
                               &state->attrs, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to build attributes from map\n"));
        ret = ENOMEM;
        goto immediate;
    }


    ret = sysdb_attrs_get_string(state->map, SYSDB_ORIG_DN, &state->orig_dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Cannot get originalDN\n"));
        goto immediate;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          ("Examining autofs map [%s]\n", state->orig_dn));

    ret = automntmaps_process_members_next_base(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("search failed [%d]: %s\n", ret, strerror(ret)));
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
    state->filter = sdap_get_id_specific_filter(state,
                        state->base_filter,
                        state->search_bases[state->base_iter]->filter);
    if (!state->filter) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          ("Searching for automount map entries with base [%s]\n",
           state->search_bases[state->base_iter]->basedn));

    subreq = sdap_get_generic_send(state, state->ev, state->opts, state->sh,
                                   state->orig_dn,
                                   state->search_bases[state->base_iter]->scope,
                                   state->filter, state->attrs,
                                   state->opts->autofs_entry_map,
                                   SDAP_OPTS_AUTOFS_ENTRY,
                                   state->timeout, true);
    if (!subreq) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Cannot start search for entries\n"));
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

    DEBUG(SSSDBG_TRACE_INTERNAL, ("No more search bases to try\n"));

    DEBUG(SSSDBG_TRACE_FUNC,
          ("Search for autofs entries, returned %d results.\n",
          state->entries_count));

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
    struct sysdb_ctx *sysdb;
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
                         struct sysdb_ctx *sysdb,
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
    state->sysdb = sysdb;
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
    state->filter = sdap_get_id_specific_filter(state,
                        state->base_filter,
                        state->search_bases[state->base_iter]->filter);
    if (!state->filter) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          ("Searching for automount maps with base [%s]\n",
           state->search_bases[state->base_iter]->basedn));

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
          ("Search for autofs maps, returned %d results.\n", state->count));

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
              ("The search yielded more than one autofs map\n"));
        tevent_req_error(req, EIO);
        return;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, ("Processing autofs maps\n"));
    subreq = automntmaps_process_members_send(state, state->ev, state->opts,
                                              state->sh, state->dom,
                                              state->search_bases,
                                              state->timeout, state->sysdb,
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

    DEBUG(SSSDBG_TRACE_FUNC, ("automount map members received\n"));
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
        DEBUG(SSSDBG_CRIT_FAILURE, ("No map name given\n"));
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
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to build filter\n"));
        ret = ENOMEM;
        goto fail;
    }
    talloc_free(clean_mapname);

    ret = build_attrs_from_map(state, state->opts->autofs_mobject_map,
                               SDAP_OPTS_AUTOFS_MAP, NULL,
                               &state->attrs, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to build attributes from map\n"));
        ret = ENOMEM;
        goto fail;
    }

    subreq = sdap_get_automntmap_send(state, ev, dom,
                                      sysdb, state->opts,
                                      state->opts->autofs_search_bases,
                                      state->sh,
                                      state->attrs, state->filter,
                                      dp_opt_get_int(state->opts->basic,
                                                     SDAP_SEARCH_TIMEOUT));
    if (!subreq) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Out of memory\n"));
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
            DEBUG(SSSDBG_MINOR_FAILURE, ("Could not find automount map\n"));
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                ("sdap_get_automntmap_recv failed [%d]: %s\n",
                ret, strerror(ret)));
        }
        tevent_req_error(req, ret);
        return;
    }

    ret = sdap_autofs_setautomntent_save(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not save automount map\n"));
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
    struct ldb_message *sysdb_map;
    struct ldb_message_element *map_members = NULL;
    char **sysdb_entrylist;
    char **ldap_entrylist;
    char **add_entries;
    char **del_entries;
    size_t i;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    if (state->entries_count == 0) {
        /* No entries for this map in LDAP.
         * We need to ensure that there are no entries
         * in the sysdb either.
         */
        ldap_entrylist = NULL;
    } else {
        ret = sysdb_attrs_to_list(
                tmp_ctx, state->entries,
                state->entries_count,
                state->opts->autofs_entry_map[SDAP_AT_AUTOFS_ENTRY_KEY].sys_name,
                &ldap_entrylist);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  ("sysdb_attrs_primary_name_list failed [%d]: %s\n",
                   ret, strerror(ret)));
            goto done;
        }
    }

    ret = sysdb_get_map_byname(tmp_ctx, state->sysdb, state->mapname,
                               &sysdb_map);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("cache lookup for the map failed [%d]: %s\n",
               ret, strerror(ret)));
        goto done;
    }

    if (sysdb_map) {
        map_members = ldb_msg_find_element(sysdb_map, SYSDB_MEMBER);
    }

    if (!map_members || map_members->num_values == 0) {
        /* No map members for this map in sysdb currently */
        sysdb_entrylist = NULL;
    } else {
        sysdb_entrylist = talloc_array(state, char *, map_members->num_values+1);
        if (!sysdb_entrylist) {
            ret = ENOMEM;
            goto done;
        }

        /* Get a list of the map members by name only */
        for (i=0; i < map_members->num_values; i++) {
            ret = sysdb_map_entry_name(sysdb_entrylist, state->sysdb,
                                      (const char *) map_members->values[i].data,
                                      &sysdb_entrylist[i]);
            if (ret != EOK) {
                goto done;
            }
        }
        sysdb_entrylist[map_members->num_values] = NULL;
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
             ("Cannot start sysdb transaction [%d]: %s\n",
              ret, strerror(ret)));
        goto done;
    }
    in_transaction = true;

    /* Save the map itself */
    ret = save_autofs_map(state->sysdb, state->dom, state->opts, state->map);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
             ("Cannot save autofs map entry [%d]: %s\n",
              ret, strerror(ret)));
        goto done;
    }

    /* Create entries that don't exist yet */
    if (add_entries && add_entries[0]) {
        ret = save_autofs_entries(state->sysdb, state->opts,
                                  add_entries, state->entries,
                                  state->entries_count);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  ("Cannot save autofs entries [%d]: %s\n",
                  ret, strerror(ret)));
            goto done;
        }
    }

    /* Save the memberships */
    DEBUG(SSSDBG_TRACE_FUNC, ("Updating memberships for %s\n", state->mapname));
    ret = sysdb_autofs_map_update_members(state->sysdb, state->mapname,
                                          (const char *const *) add_entries,
                                          (const char *const *) del_entries);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Membership update failed [%d]: %s\n",
              ret, strerror(ret)));
        goto done;
    }

    ret = sysdb_transaction_commit(state->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
             ("Cannot commit sysdb transaction [%d]: %s\n",
              ret, strerror(ret)));
        goto done;
    }
    in_transaction = false;

    ret = EOK;
done:
    if (in_transaction) {
        tret = sysdb_transaction_cancel(state->sysdb);
        if (tret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                ("Cannot cancel sysdb transaction [%d]: %s\n",
                ret, strerror(ret)));
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

