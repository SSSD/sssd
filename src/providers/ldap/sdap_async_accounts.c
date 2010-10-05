/*
    SSSD

    Async LDAP Helper routines

    Copyright (C) Simo Sorce <ssorce@redhat.com> - 2009

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

/* ==Save-User-Entry====================================================== */

struct sdap_save_user_state {
    struct tevent_context *ev;
    struct sysdb_handle *handle;
    struct sdap_options *opts;

    struct sss_domain_info *dom;

    const char *name;
    struct sysdb_attrs *attrs;
    char *timestamp;
};

static void sdap_save_user_done(struct tevent_req *subreq);

    /* FIXME: support storing additional attributes */

static struct tevent_req *sdap_save_user_send(TALLOC_CTX *memctx,
                                              struct tevent_context *ev,
                                              struct sysdb_handle *handle,
                                              struct sdap_options *opts,
                                              struct sss_domain_info *dom,
                                              struct sysdb_attrs *attrs,
                                              bool is_initgr)
{
    struct tevent_req *req, *subreq;
    struct sdap_save_user_state *state;
    struct ldb_message_element *el;
    int ret;
    const char *pwd;
    const char *gecos;
    const char *homedir;
    const char *shell;
    long int l;
    uid_t uid;
    gid_t gid;
    struct sysdb_attrs *user_attrs;
    char *upn = NULL;
    int i;
    char *val = NULL;
    int cache_timeout;

    DEBUG(9, ("Save user\n"));

    req = tevent_req_create(memctx, &state, struct sdap_save_user_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->dom = dom;
    state->opts = opts;
    state->attrs = attrs;
    state->timestamp = NULL;

    ret = sysdb_attrs_get_el(state->attrs,
                             opts->user_map[SDAP_AT_USER_NAME].sys_name, &el);
    if (ret) goto fail;
    if (el->num_values == 0) {
        ret = EINVAL;
        goto fail;
    }
    state->name = (const char *)el->values[0].data;

    ret = sysdb_attrs_get_el(state->attrs,
                             opts->user_map[SDAP_AT_USER_PWD].sys_name, &el);
    if (ret) goto fail;
    if (el->num_values == 0) pwd = NULL;
    else pwd = (const char *)el->values[0].data;

    ret = sysdb_attrs_get_el(state->attrs,
                             opts->user_map[SDAP_AT_USER_GECOS].sys_name, &el);
    if (ret) goto fail;
    if (el->num_values == 0) gecos = NULL;
    else gecos = (const char *)el->values[0].data;

    ret = sysdb_attrs_get_el(state->attrs,
                             opts->user_map[SDAP_AT_USER_HOME].sys_name, &el);
    if (ret) goto fail;
    if (el->num_values == 0) homedir = NULL;
    else homedir = (const char *)el->values[0].data;

    ret = sysdb_attrs_get_el(state->attrs,
                             opts->user_map[SDAP_AT_USER_SHELL].sys_name, &el);
    if (ret) goto fail;
    if (el->num_values == 0) shell = NULL;
    else shell = (const char *)el->values[0].data;

    ret = sysdb_attrs_get_el(state->attrs,
                             opts->user_map[SDAP_AT_USER_UID].sys_name, &el);
    if (ret) goto fail;
    if (el->num_values == 0) {
        DEBUG(1, ("no uid provided for [%s] in domain [%s].\n",
                  state->name, dom->name));
        ret = EINVAL;
        goto fail;
    }
    errno = 0;
    l = strtol((const char *)el->values[0].data, NULL, 0);
    if (errno) {
        ret = EINVAL;
        goto fail;
    }
    uid = l;

    /* check that the uid is valid for this domain */
    if (OUT_OF_ID_RANGE(uid, dom->id_min, dom->id_max)) {
            DEBUG(2, ("User [%s] filtered out! (id out of range)\n",
                      state->name));
        ret = EINVAL;
        goto fail;
    }

    ret = sysdb_attrs_get_el(state->attrs,
                             opts->user_map[SDAP_AT_USER_GID].sys_name, &el);
    if (ret) goto fail;
    if (el->num_values == 0) {
        DEBUG(1, ("no gid provided for [%s] in domain [%s].\n",
                  state->name, dom->name));
        ret = EINVAL;
        goto fail;
    }
    errno = 0;
    l = strtol((const char *)el->values[0].data, NULL, 0);
    if (errno) {
        ret = EINVAL;
        goto fail;
    }
    gid = l;

    /* check that the gid is valid for this domain */
    if (OUT_OF_ID_RANGE(gid, dom->id_min, dom->id_max)) {
            DEBUG(2, ("User [%s] filtered out! (id out of range)\n",
                      state->name));
        ret = EINVAL;
        goto fail;
    }

    user_attrs = sysdb_new_attrs(state);
    if (user_attrs == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    ret = sysdb_attrs_get_el(state->attrs, SYSDB_ORIG_DN, &el);
    if (ret) {
        goto fail;
    }
    if (el->num_values == 0) {
        DEBUG(7, ("Original DN is not available for [%s].\n", state->name));
    } else {
        DEBUG(7, ("Adding original DN [%s] to attributes of [%s].\n",
                  el->values[0].data, state->name));
        ret = sysdb_attrs_add_string(user_attrs, SYSDB_ORIG_DN,
                                     (const char *) el->values[0].data);
        if (ret) {
            goto fail;
        }
    }

    ret = sysdb_attrs_get_el(state->attrs, SYSDB_MEMBEROF, &el);
    if (ret) {
        goto fail;
    }
    if (el->num_values == 0) {
        DEBUG(7, ("Original memberOf is not available for [%s].\n",
                  state->name));
    } else {
        DEBUG(7, ("Adding original memberOf attributes to [%s].\n",
                  state->name));
        for (i = 0; i < el->num_values; i++) {
            ret = sysdb_attrs_add_string(user_attrs, SYSDB_ORIG_MEMBEROF,
                                         (const char *) el->values[i].data);
            if (ret) {
                goto fail;
            }
        }
    }

    ret = sysdb_attrs_get_el(state->attrs,
                      opts->user_map[SDAP_AT_USER_MODSTAMP].sys_name, &el);
    if (ret) {
        goto fail;
    }
    if (el->num_values == 0) {
        DEBUG(7, ("Original mod-Timestamp is not available for [%s].\n",
                  state->name));
    } else {
        ret = sysdb_attrs_add_string(user_attrs,
                          opts->user_map[SDAP_AT_USER_MODSTAMP].sys_name,
                          (const char*)el->values[0].data);
        if (ret) {
            goto fail;
        }
        state->timestamp = talloc_strdup(state,
                                         (const char*)el->values[0].data);
        if (!state->timestamp) {
            ret = ENOMEM;
            goto fail;
        }
    }

    ret = sysdb_attrs_get_el(state->attrs,
                             opts->user_map[SDAP_AT_USER_PRINC].sys_name, &el);
    if (ret) {
        goto fail;
    }
    if (el->num_values == 0) {
        DEBUG(7, ("User principal is not available for [%s].\n", state->name));
    } else {
        upn = talloc_strdup(user_attrs, (const char*) el->values[0].data);
        if (!upn) {
            ret = ENOMEM;
            goto fail;
        }
        if (dp_opt_get_bool(opts->basic, SDAP_FORCE_UPPER_CASE_REALM)) {
            make_realm_upper_case(upn);
        }
        DEBUG(7, ("Adding user principal [%s] to attributes of [%s].\n",
                  upn, state->name));
        ret = sysdb_attrs_add_string(user_attrs, SYSDB_UPN, upn);
        if (ret) {
            goto fail;
        }
    }

    for (i = SDAP_FIRST_EXTRA_USER_AT; i < SDAP_OPTS_USER; i++) {
        ret = sysdb_attrs_get_el(state->attrs, opts->user_map[i].sys_name, &el);
        if (ret) {
            goto fail;
        }
        if (el->num_values > 0) {
            DEBUG(9, ("Adding [%s]=[%s] to user attributes.\n",
                      opts->user_map[i].sys_name,
                      (const char*) el->values[0].data));
            val = talloc_strdup(user_attrs, (const char*) el->values[0].data);
            if (val == NULL) {
                ret = ENOMEM;
                goto fail;
            }
            ret = sysdb_attrs_add_string(user_attrs,
                                         opts->user_map[i].sys_name, val);
            if (ret) {
                goto fail;
            }
        }
    }

    cache_timeout = dp_opt_get_int(opts->basic, SDAP_ENTRY_CACHE_TIMEOUT);

    if (is_initgr) {
        ret = sysdb_attrs_add_time_t(user_attrs, SYSDB_INITGR_EXPIRE,
                                     (cache_timeout ?
                                      (time(NULL) + cache_timeout) : 0));
        if (ret) {
            goto fail;
        }
    }

    DEBUG(6, ("Storing info for user %s\n", state->name));

    subreq = sysdb_store_user_send(state, state->ev, state->handle,
                                   state->dom, state->name, pwd,
                                   uid, gid, gecos, homedir, shell,
                                   user_attrs, cache_timeout);
    if (!subreq) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, sdap_save_user_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sdap_save_user_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_save_user_state *state = tevent_req_data(req,
                                            struct sdap_save_user_state);
    int ret;

    ret = sysdb_store_user_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        DEBUG(2, ("Failed to save user %s\n", state->name));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static int sdap_save_user_recv(struct tevent_req *req,
                               TALLOC_CTX *mem_ctx, char **timestamp)
{
    struct sdap_save_user_state *state = tevent_req_data(req,
                                            struct sdap_save_user_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (timestamp) {
        *timestamp = talloc_steal(mem_ctx, state->timestamp);
    }

    return EOK;
}


/* ==Generic-Function-to-save-multiple-users============================= */

struct sdap_save_users_state {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sdap_options *opts;
    struct sss_domain_info *dom;

    struct sysdb_attrs **users;
    int count;
    int cur;

    struct sysdb_handle *handle;

    char *higher_timestamp;
};

static void sdap_save_users_trans(struct tevent_req *subreq);
static void sdap_save_users_store(struct tevent_req *req);
static void sdap_save_users_process(struct tevent_req *subreq);
struct tevent_req *sdap_save_users_send(TALLOC_CTX *memctx,
                                         struct tevent_context *ev,
                                         struct sss_domain_info *dom,
                                         struct sysdb_ctx *sysdb,
                                         struct sdap_options *opts,
                                         struct sysdb_attrs **users,
                                         int num_users)
{
    struct tevent_req *req, *subreq;
    struct sdap_save_users_state *state;

    req = tevent_req_create(memctx, &state, struct sdap_save_users_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->sysdb = sysdb;
    state->dom = dom;
    state->users = users;
    state->count = num_users;
    state->cur = 0;
    state->handle = NULL;
    state->higher_timestamp = NULL;

    if (num_users == 0) {
        /* Nothing to do if there are no
         * users
         */
        tevent_req_done(req);
        tevent_req_post(req, ev);
        return req;
    }

    subreq = sysdb_transaction_send(state, state->ev, state->sysdb);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        tevent_req_post(req, ev);
        return req;
    }
    tevent_req_set_callback(subreq, sdap_save_users_trans, req);

    return req;
}

static void sdap_save_users_trans(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct sdap_save_users_state *state;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_save_users_state);

    ret = sysdb_transaction_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    sdap_save_users_store(req);
}

static void sdap_save_users_store(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct sdap_save_users_state *state;

    state = tevent_req_data(req, struct sdap_save_users_state);

    subreq = sdap_save_user_send(state, state->ev, state->handle,
                                  state->opts, state->dom,
                                  state->users[state->cur], false);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sdap_save_users_process, req);
}

static void sdap_save_users_process(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct sdap_save_users_state *state;
    char *timestamp = NULL;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_save_users_state);

    ret = sdap_save_user_recv(subreq, state, &timestamp);
    talloc_zfree(subreq);

    /* Do not fail completely on errors.
     * Just report the failure to save and go on */
    if (ret) {
        DEBUG(2, ("Failed to store user %d. Ignoring.\n", state->cur));
    } else {
        DEBUG(9, ("User %d processed!\n", state->cur));
    }

    if (timestamp) {
        if (state->higher_timestamp) {
            if (strcmp(timestamp, state->higher_timestamp) > 0) {
                talloc_zfree(state->higher_timestamp);
                state->higher_timestamp = timestamp;
            } else {
                talloc_zfree(timestamp);
            }
        } else {
            state->higher_timestamp = timestamp;
        }
    }

    state->cur++;
    if (state->cur < state->count) {
        sdap_save_users_store(req);
    } else {
        subreq = sysdb_transaction_commit_send(state, state->ev,
                                               state->handle);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        /* sysdb_transaction_complete will call tevent_req_done(req) */
        tevent_req_set_callback(subreq, sysdb_transaction_complete, req);
    }
}

static int sdap_save_users_recv(struct tevent_req *req,
                                TALLOC_CTX *mem_ctx, char **timestamp)
{
    struct sdap_save_users_state *state  = tevent_req_data(req,
                                               struct sdap_save_users_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (timestamp) {
        *timestamp = talloc_steal(mem_ctx, state->higher_timestamp);
    }

    return EOK;
}


/* ==Search-Users-with-filter============================================= */

struct sdap_get_users_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;
    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;
    const char **attrs;
    const char *filter;

    char *higher_timestamp;
    struct sysdb_attrs **users;
    size_t count;
};

static void sdap_get_users_process(struct tevent_req *subreq);
static void sdap_get_users_done(struct tevent_req *subreq);

struct tevent_req *sdap_get_users_send(TALLOC_CTX *memctx,
                                       struct tevent_context *ev,
                                       struct sss_domain_info *dom,
                                       struct sysdb_ctx *sysdb,
                                       struct sdap_options *opts,
                                       struct sdap_handle *sh,
                                       const char **attrs,
                                       const char *filter)
{
    struct tevent_req *req, *subreq;
    struct sdap_get_users_state *state;

    req = tevent_req_create(memctx, &state, struct sdap_get_users_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->dom = dom;
    state->sh = sh;
    state->sysdb = sysdb;
    state->filter = filter;
    state->attrs = attrs;
    state->higher_timestamp = NULL;
    state->users =  NULL;
    state->count = 0;

    subreq = sdap_get_generic_send(state, state->ev, state->opts, state->sh,
                                   dp_opt_get_string(state->opts->basic,
                                                     SDAP_USER_SEARCH_BASE),
                                   LDAP_SCOPE_SUBTREE,
                                   state->filter, state->attrs,
                                   state->opts->user_map, SDAP_OPTS_USER);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, sdap_get_users_process, req);

    return req;
}

static void sdap_get_users_process(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_users_state *state = tevent_req_data(req,
                                            struct sdap_get_users_state);
    int ret;

    ret = sdap_get_generic_recv(subreq, state,
                                &state->count, &state->users);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(6, ("Search for users, returned %d results.\n", state->count));

    if (state->count == 0) {
        tevent_req_error(req, ENOENT);
        return;
    }

    subreq = sdap_save_users_send(state, state->ev, state->dom,
                                  state->sysdb, state->opts,
                                  state->users, state->count);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sdap_get_users_done, req);
}

static void sdap_get_users_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_users_state *state = tevent_req_data(req,
                                            struct sdap_get_users_state);
    int ret;

    DEBUG(9, ("Saving %d Users - Done\n", state->count));

    ret = sdap_save_users_recv(subreq, state, &state->higher_timestamp);
    talloc_zfree(subreq);
    if (ret) {
        DEBUG(2, ("Failed to store users.\n"));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int sdap_get_users_recv(struct tevent_req *req,
                        TALLOC_CTX *mem_ctx, char **timestamp)
{
    struct sdap_get_users_state *state = tevent_req_data(req,
                                            struct sdap_get_users_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (timestamp) {
        *timestamp = talloc_steal(mem_ctx, state->higher_timestamp);
    }

    return EOK;
}

/* ==Group-Parsing Routines=============================================== */

struct sdap_orig_entry_state {
    int done;
};

static void sdap_find_entry_by_origDN_done(struct tevent_req *req)
{
    struct sdap_orig_entry_state *state = tevent_req_callback_data(req,
                                               struct sdap_orig_entry_state);
    state->done = 1;
}

/* WARNING: this is a sync routine for now */
static int sdap_find_entry_by_origDN(TALLOC_CTX *memctx,
                                     struct tevent_context *ev,
                                     struct sysdb_handle *handle,
                                     struct sss_domain_info *domain,
                                     const char *orig_dn,
                                     char **localdn)
{
    struct tevent_req *req;
    struct sdap_orig_entry_state *state;
    static const char *attrs[] = { NULL };
    struct ldb_dn *base_dn;
    char *filter;
    struct ldb_message **msgs;
    size_t num_msgs;
    int ret;

    state = talloc_zero(memctx, struct sdap_orig_entry_state);
    if (!state) {
        ret = ENOMEM;
        goto done;
    }

    filter = talloc_asprintf(state, "%s=%s", SYSDB_ORIG_DN, orig_dn);
    if (!filter) {
        ret = ENOMEM;
        goto done;
    }

    base_dn = sysdb_domain_dn(sysdb_handle_get_ctx(handle),
                              state, domain->name);
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    req = sysdb_search_entry_send(state, ev, handle, base_dn,
                                  LDB_SCOPE_SUBTREE, filter, attrs);
    if (!req) {
        ret = ENOMEM;
        goto done;
    }
    tevent_req_set_callback(req, sdap_find_entry_by_origDN_done, state);

    /* WARNING: SYNC LOOP HERE */
    tevent_loop_allow_nesting(ev);
    while (state->done == 0) {
        tevent_loop_once(ev);
    }

    ret = sysdb_search_entry_recv(req, state, &num_msgs, &msgs);
    if (ret) {
        goto done;
    }
    if (num_msgs != 1) {
        ret = ENOENT;
        goto done;
    }

    *localdn = talloc_strdup(memctx, ldb_dn_get_linearized(msgs[0]->dn));
    if (!*localdn) {
        ret = ENOENT;
        goto done;
    }

    ret = EOK;

done:
    talloc_zfree(state);
    return ret;
}

static int sdap_fill_memberships(struct sysdb_attrs *group_attrs,
                                 struct tevent_context *ev,
                                 struct sysdb_handle *handle,
                                 struct sdap_options *opts,
                                 struct sss_domain_info *domain,
                                 struct ldb_val *values,
                                 int num_values)
{
    struct ldb_message_element *el;
    int i, j;
    int ret;

    switch (opts->schema_type) {
    case SDAP_SCHEMA_RFC2307:
        DEBUG(9, ("[RFC2307 Schema]\n"));

        ret = sysdb_attrs_users_from_ldb_vals(group_attrs, SYSDB_MEMBER,
                                              domain->name,
                                              values, num_values);
        if (ret) {
            goto done;
        }

        break;

    case SDAP_SCHEMA_RFC2307BIS:
    case SDAP_SCHEMA_IPA_V1:
    case SDAP_SCHEMA_AD:
        DEBUG(9, ("[IPA or AD Schema]\n"));

        ret = sysdb_attrs_get_el(group_attrs, SYSDB_MEMBER, &el);
        if (ret) {
            goto done;
        }

        /* Just allocate both big enough to contain all members for now */
        el->values = talloc_realloc(el, el->values, struct ldb_val,
                                    el->num_values + num_values);
        if (!el->values) {
            ret = ENOMEM;
            goto done;
        }

        for (i = 0, j = el->num_values; i < num_values; i++) {

            /* sync search entry with this as origDN */
            ret = sdap_find_entry_by_origDN(el->values, ev,
                                            handle, domain,
                                            (char *)values[i].data,
                                            (char **)&el->values[j].data);
            if (ret != EOK) {
                if (ret != ENOENT) {
                    goto done;
                }

                DEBUG(7, ("    member #%d (%s): not found!\n",
                          i, (char *)values[i].data));
            } else {
                DEBUG(7, ("    member #%d (%s): [%s]\n",
                          i, (char *)values[i].data,
                          (char *)el->values[j].data));

                el->values[j].length = strlen((char *)el->values[j].data);
                j++;
            }
        }
        el->num_values = j;

        break;

    default:
        DEBUG(0, ("FATAL ERROR: Unhandled schema type! (%d)\n",
                  opts->schema_type));
        ret = EFAULT;
        goto done;
    }

    ret = EOK;

done:
    return ret;
}

/* ==Save-Group-Entry===================================================== */

struct sdap_save_group_state {
    struct tevent_context *ev;
    struct sysdb_handle *handle;
    struct sdap_options *opts;

    struct sss_domain_info *dom;

    const char *name;
    char *timestamp;
};

static void sdap_save_group_done(struct tevent_req *subreq);

    /* FIXME: support non legacy */
    /* FIXME: support storing additional attributes */

static struct tevent_req *sdap_save_group_send(TALLOC_CTX *memctx,
                                               struct tevent_context *ev,
                                               struct sysdb_handle *handle,
                                               struct sdap_options *opts,
                                               struct sss_domain_info *dom,
                                               struct sysdb_attrs *attrs,
                                               bool store_members,
                                               bool populate_members)
{
    struct tevent_req *req, *subreq;
    struct sdap_save_group_state *state;
    struct ldb_message_element *el;
    struct sysdb_attrs *group_attrs;
    long int l;
    gid_t gid;
    int ret;

    req = tevent_req_create(memctx, &state, struct sdap_save_group_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->dom = dom;
    state->opts = opts;
    state->timestamp = NULL;

    ret = sysdb_attrs_get_el(attrs,
                          opts->group_map[SDAP_AT_GROUP_NAME].sys_name, &el);
    if (ret) goto fail;
    if (el->num_values == 0) {
        ret = EINVAL;
        goto fail;
    }
    state->name = (const char *)el->values[0].data;

    ret = sysdb_attrs_get_el(attrs,
                          opts->group_map[SDAP_AT_GROUP_GID].sys_name, &el);
    if (ret) goto fail;
    if (el->num_values == 0) {
        DEBUG(1, ("no gid provided for [%s] in domain [%s].\n",
                  state->name, dom->name));
        ret = EINVAL;
        goto fail;
    }
    errno = 0;
    l = strtol((const char *)el->values[0].data, NULL, 0);
    if (errno) {
        ret = EINVAL;
        goto fail;
    }
    gid = l;

    /* check that the gid is valid for this domain */
    if (OUT_OF_ID_RANGE(gid, dom->id_min, dom->id_max)) {
            DEBUG(2, ("Group [%s] filtered out! (id out of range)\n",
                      state->name));
        ret = EINVAL;
        goto fail;
    }

    group_attrs = sysdb_new_attrs(state);
    if (!group_attrs) {
        ret = ENOMEM;
        goto fail;
    }

    ret = sysdb_attrs_get_el(attrs, SYSDB_ORIG_DN, &el);
    if (ret) {
        goto fail;
    }
    if (el->num_values == 0) {
        DEBUG(7, ("Original DN is not available for [%s].\n", state->name));
    } else {
        DEBUG(7, ("Adding original DN [%s] to attributes of [%s].\n",
                  el->values[0].data, state->name));
        ret = sysdb_attrs_add_string(group_attrs, SYSDB_ORIG_DN,
                                     (const char *)el->values[0].data);
        if (ret) {
            goto fail;
        }
    }

    ret = sysdb_attrs_get_el(attrs,
                      opts->group_map[SDAP_AT_GROUP_MODSTAMP].sys_name, &el);
    if (ret) {
        goto fail;
    }
    if (el->num_values == 0) {
        DEBUG(7, ("Original mod-Timestamp is not available for [%s].\n",
                  state->name));
    } else {
        ret = sysdb_attrs_add_string(group_attrs,
                          opts->group_map[SDAP_AT_GROUP_MODSTAMP].sys_name,
                          (const char*)el->values[0].data);
        if (ret) {
            goto fail;
        }
        state->timestamp = talloc_strdup(state,
                                         (const char*)el->values[0].data);
        if (!state->timestamp) {
            ret = ENOMEM;
            goto fail;
        }
    }

    if (populate_members) {
        struct ldb_message_element *el1;
        ret = sysdb_attrs_get_el(attrs,
                                 opts->group_map[SDAP_AT_GROUP_MEMBER].sys_name,
                                 &el1);
        if (ret != EOK) {
            goto fail;
        }

        ret = sysdb_attrs_get_el(group_attrs, SYSDB_MEMBER, &el);
        if (ret != EOK) {
            goto fail;
        }

        el->values = el1->values;
        el->num_values = el1->num_values;
    } else if (store_members) {
        ret = sysdb_attrs_get_el(attrs,
                        opts->group_map[SDAP_AT_GROUP_MEMBER].sys_name, &el);
        if (ret != EOK) {
            goto fail;
        }
        if (el->num_values == 0) {
            DEBUG(7, ("No members for group [%s]\n", state->name));

        } else {
            DEBUG(7, ("Adding member users to group [%s]\n", state->name));

            ret = sdap_fill_memberships(group_attrs, ev, handle, opts, dom,
                                        el->values, el->num_values);
            if (ret) {
                goto fail;
            }
        }
    }

    DEBUG(6, ("Storing info for group %s\n", state->name));

    subreq = sysdb_store_group_send(state, state->ev,
                                    state->handle, state->dom,
                                    state->name, gid,
                                    group_attrs,
                                    dp_opt_get_int(opts->basic,
                                                   SDAP_ENTRY_CACHE_TIMEOUT));
    if (!subreq) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, sdap_save_group_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sdap_save_group_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_save_group_state *state = tevent_req_data(req,
                                            struct sdap_save_group_state);
    int ret;

    ret = sysdb_store_group_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        DEBUG(2, ("Failed to save group %s [%d]\n", state->name, ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static int sdap_save_group_recv(struct tevent_req *req,
                                TALLOC_CTX *mem_ctx, char **timestamp)
{
    struct sdap_save_group_state *state = tevent_req_data(req,
                                            struct sdap_save_group_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if ( timestamp ) {
        *timestamp = talloc_steal(mem_ctx, state->timestamp);
    }

    return EOK;
}


/* ==Save-Group-Memebrs=================================================== */

struct sdap_save_grpmem_state {
    struct tevent_context *ev;
    struct sysdb_handle *handle;
    struct sdap_options *opts;

    struct sss_domain_info *dom;

    const char *name;
};

static void sdap_save_grpmem_done(struct tevent_req *subreq);

    /* FIXME: support non legacy */
    /* FIXME: support storing additional attributes */

static struct tevent_req *sdap_save_grpmem_send(TALLOC_CTX *memctx,
                                                struct tevent_context *ev,
                                                struct sysdb_handle *handle,
                                                struct sdap_options *opts,
                                                struct sss_domain_info *dom,
                                                struct sysdb_attrs *attrs)
{
    struct tevent_req *req, *subreq;
    struct sdap_save_grpmem_state *state;
    struct ldb_message_element *el;
    struct sysdb_attrs *group_attrs = NULL;
    int ret;

    req = tevent_req_create(memctx, &state, struct sdap_save_grpmem_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->dom = dom;
    state->opts = opts;

    ret = sysdb_attrs_get_string(attrs,
                                opts->group_map[SDAP_AT_GROUP_NAME].sys_name,
                                &state->name);
    if (ret != EOK) {
        goto fail;
    }

    ret = sysdb_attrs_get_el(attrs,
                    opts->group_map[SDAP_AT_GROUP_MEMBER].sys_name, &el);
    if (ret != EOK) {
        goto fail;
    }
    if (el->num_values == 0) {
        DEBUG(7, ("No members for group [%s]\n", state->name));

    } else {
        DEBUG(7, ("Adding member users to group [%s]\n", state->name));

        group_attrs = sysdb_new_attrs(state);
        if (!group_attrs) {
            ret = ENOMEM;
            goto fail;
        }

        ret = sdap_fill_memberships(group_attrs, ev, handle, opts, dom,
                                    el->values, el->num_values);
        if (ret) {
            goto fail;
        }
    }

    DEBUG(6, ("Storing members for group %s\n", state->name));

    subreq = sysdb_store_group_send(state, state->ev,
                                    state->handle, state->dom,
                                    state->name, 0,
                                    group_attrs,
                                    dp_opt_get_int(opts->basic,
                                               SDAP_ENTRY_CACHE_TIMEOUT));
    if (!subreq) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, sdap_save_grpmem_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sdap_save_grpmem_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_save_grpmem_state *state = tevent_req_data(req,
                                              struct sdap_save_grpmem_state);
    int ret;

    ret = sysdb_store_group_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        DEBUG(2, ("Failed to save group members for %s [%d]\n",
                  state->name, ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static int sdap_save_grpmem_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}


/* ==Generic-Function-to-save-multiple-groups============================= */

struct sdap_save_groups_state {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sdap_options *opts;
    struct sss_domain_info *dom;

    struct sysdb_attrs **groups;
    int count;
    int cur;
    bool twopass;
    bool populate_members;

    struct sysdb_handle *handle;

    char *higher_timestamp;
};

static void sdap_save_groups_trans(struct tevent_req *subreq);
static void sdap_save_groups_save(struct tevent_req *req);
static void sdap_save_groups_loop(struct tevent_req *subreq);
static void sdap_save_groups_mem_save(struct tevent_req *req);
static void sdap_save_groups_mem_loop(struct tevent_req *subreq);
struct tevent_req *sdap_save_groups_send(TALLOC_CTX *memctx,
                                         struct tevent_context *ev,
                                         struct sss_domain_info *dom,
                                         struct sysdb_ctx *sysdb,
                                         struct sdap_options *opts,
                                         struct sysdb_attrs **groups,
                                         bool populate_members,
                                         int num_groups)
{
    struct tevent_req *req, *subreq;
    struct sdap_save_groups_state *state;

    req = tevent_req_create(memctx, &state, struct sdap_save_groups_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->sysdb = sysdb;
    state->dom = dom;
    state->groups = groups;
    state->count = num_groups;
    state->cur = 0;
    state->handle = NULL;
    state->higher_timestamp = NULL;
    state->populate_members = populate_members;

    switch (opts->schema_type) {
    case SDAP_SCHEMA_RFC2307:
        state->twopass = false;
        break;

    case SDAP_SCHEMA_RFC2307BIS:
    case SDAP_SCHEMA_IPA_V1:
    case SDAP_SCHEMA_AD:
        state->twopass = true;
        break;

    default:
        tevent_req_error(req, EINVAL);
        tevent_req_post(req, ev);
        return req;
    }

    subreq = sysdb_transaction_send(state, state->ev, state->sysdb);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        tevent_req_post(req, ev);
        return req;
    }
    tevent_req_set_callback(subreq, sdap_save_groups_trans, req);

    return req;
}

static void sdap_save_groups_trans(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct sdap_save_groups_state *state;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_save_groups_state);

    ret = sysdb_transaction_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    sdap_save_groups_save(req);
}

static void sdap_save_groups_save(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct sdap_save_groups_state *state;

    state = tevent_req_data(req, struct sdap_save_groups_state);

    /* if 2 pass savemembers = false */
    subreq = sdap_save_group_send(state, state->ev, state->handle,
                                  state->opts, state->dom,
                                  state->groups[state->cur],
                                  (!state->twopass), state->populate_members);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sdap_save_groups_loop, req);
}

static void sdap_save_groups_loop(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct sdap_save_groups_state *state;
    char *timestamp = NULL;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_save_groups_state);

    ret = sdap_save_group_recv(subreq, state, &timestamp);
    talloc_zfree(subreq);

    /* Do not fail completely on errors.
     * Just report the failure to save and go on */
    if (ret) {
        DEBUG(2, ("Failed to store group %d. Ignoring.\n", state->cur));
    } else {
        DEBUG(9, ("Group %d processed!\n", state->cur));
    }

    if (timestamp) {
        if (state->higher_timestamp) {
            if (strcmp(timestamp, state->higher_timestamp) > 0) {
                talloc_zfree(state->higher_timestamp);
                state->higher_timestamp = timestamp;
            } else {
                talloc_zfree(timestamp);
            }
        } else {
            state->higher_timestamp = timestamp;
        }
    }

    state->cur++;
    if (state->cur < state->count) {

        sdap_save_groups_save(req);

    } else if (state->twopass && !state->populate_members) {

        state->cur = 0;
        sdap_save_groups_mem_save(req);

    } else {

        subreq = sysdb_transaction_commit_send(state, state->ev,
                                               state->handle);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        /* sysdb_transaction_complete will call tevent_req_done(req) */
        tevent_req_set_callback(subreq, sysdb_transaction_complete, req);
    }
}

static void sdap_save_groups_mem_save(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct sdap_save_groups_state *state;

    state = tevent_req_data(req, struct sdap_save_groups_state);

    subreq = sdap_save_grpmem_send(state, state->ev, state->handle,
                                  state->opts, state->dom,
                                  state->groups[state->cur]);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sdap_save_groups_mem_loop, req);
}

static void sdap_save_groups_mem_loop(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct sdap_save_groups_state *state;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_save_groups_state);

    ret = sdap_save_grpmem_recv(subreq);
    talloc_zfree(subreq);

    /* Do not fail completely on errors.
     * Just report the failure to save and go on */
    if (ret) {
        DEBUG(2, ("Failed to store group %d. Ignoring.\n", state->cur));
    }

    state->cur++;
    if (state->cur < state->count) {

        sdap_save_groups_mem_save(req);

    } else {

        subreq = sysdb_transaction_commit_send(state, state->ev,
                                               state->handle);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        /* sysdb_transaction_complete will call tevent_req_done(req) */
        tevent_req_set_callback(subreq, sysdb_transaction_complete, req);
    }
}

static int sdap_save_groups_recv(struct tevent_req *req,
                                 TALLOC_CTX *mem_ctx, char **timestamp)
{
    struct sdap_save_groups_state *state = tevent_req_data(req,
                                              struct sdap_save_groups_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (timestamp) {
        *timestamp = talloc_steal(mem_ctx, state->higher_timestamp);
    }

    return EOK;
}

/* ==Process-Groups======================================================= */

struct tevent_req *
sdap_process_group_members_2307_send(TALLOC_CTX *memctx,
                                     struct tevent_context *ev,
                                     struct sss_domain_info *dom,
                                     struct sysdb_ctx *sysdb,
                                     struct ldb_message_element *memberel,
                                     struct ldb_message_element *sysdb_dns);
static int sdap_process_group_members_2307_recv(struct tevent_req *req);

struct sdap_process_group_state {
    struct tevent_context *ev;
    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;
    struct sysdb_attrs *group;

    struct ldb_message_element *sysdb_dns;
    struct ldb_message_element *memberel;
};


static void sdap_process_group_2307_done(struct tevent_req *subreq);

struct tevent_req *sdap_process_group_send(TALLOC_CTX *memctx,
                                           struct tevent_context *ev,
                                           struct sss_domain_info *dom,
                                           struct sysdb_ctx *sysdb,
                                           struct sdap_options *opts,
                                           struct sysdb_attrs *group)
{
    struct sdap_process_group_state *grp_state;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq;
    const char **attrs;
    char* filter;
    int ret;

    req = tevent_req_create(memctx, &grp_state,
                            struct sdap_process_group_state);
    if (!req) return NULL;

    ret = build_attrs_from_map(grp_state, opts->user_map,
                               SDAP_OPTS_USER, &attrs);
    if (ret) {
        goto fail;
    }

    /* FIXME: we ignore nested rfc2307bis groups for now */
    filter = talloc_asprintf(grp_state, "(objectclass=%s)",
                             opts->user_map[SDAP_OC_USER].name);
    if (!filter) {
        talloc_zfree(req);
        return NULL;
    }

    grp_state->ev = ev;
    grp_state->dom = dom;
    grp_state->sysdb = sysdb;
    grp_state->group = group;

    ret = sysdb_attrs_get_el(group,
                             opts->group_map[SDAP_AT_GROUP_MEMBER].sys_name,
                             &grp_state->memberel);
    if (ret) {
        goto fail;
    }

    /* Group without members */
    if (grp_state->memberel->num_values == 0) {
        DEBUG(2, ("No Members. Done!\n"));
        tevent_req_done(req);
        tevent_req_post(req, ev);
        return req;
    }

    grp_state->sysdb_dns = talloc(grp_state,
                                  struct ldb_message_element);
    if (!grp_state->sysdb_dns) {
        ret = ENOMEM;
        goto fail;
    }
    grp_state->sysdb_dns->values = talloc_array(grp_state, struct ldb_val,
                                            grp_state->memberel->num_values);
    if (!grp_state->sysdb_dns->values) {
        ret = ENOMEM;
        goto fail;
    }
    grp_state->sysdb_dns->num_values = 0;

    switch (opts->schema_type) {
        case SDAP_SCHEMA_RFC2307:
            subreq = sdap_process_group_members_2307_send(grp_state,
                                                          grp_state->ev,
                                                          grp_state->dom,
                                                          grp_state->sysdb,
                                                          grp_state->memberel,
                                                          grp_state->sysdb_dns);
            if (!subreq) {
                ret = ENOMEM;
                goto fail;
            }
            tevent_req_set_callback(subreq, sdap_process_group_2307_done,
                                    req);
            break;

        case SDAP_SCHEMA_IPA_V1:
        case SDAP_SCHEMA_AD:
        case SDAP_SCHEMA_RFC2307BIS:
            DEBUG(2, ("Processing users for RFC2307BIS not yet implemeted\n"));
            tevent_req_done(req);
            tevent_req_post(req, ev);
            break;

        default:
            DEBUG(1, ("Unknown schema type %d\n", opts->schema_type));
            ret = EINVAL;
            goto fail;
    }

    return req;
fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sdap_process_group_2307_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_process_group_state *state =
        tevent_req_data(req, struct sdap_process_group_state);

    int ret;

    ret = sdap_process_group_members_2307_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    state->memberel->values = talloc_steal(state->group,
                                           state->sysdb_dns->values);
    state->memberel->num_values = state->sysdb_dns->num_values;
    tevent_req_done(req);
}

static int sdap_process_group_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

/*===Process-group-members-of-RFC2307-group============================*/

struct tevent_req *
sdap_process_missing_member_2307_send(TALLOC_CTX *memctx,
                                      struct tevent_context *ev,
                                      struct sss_domain_info *dom,
                                      struct sysdb_ctx *sysdb,
                                      struct sysdb_handle *handle,
                                      const char *username,
                                      struct ldb_message_element* sysdb_dns);
static int sdap_process_missing_member_2307_recv(struct tevent_req *req);

struct sdap_process_group_members_2307_state {
    struct tevent_context *ev;
    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;
    struct sysdb_handle *handle;

    struct ldb_message_element *sysdb_dns;
    struct ldb_message_element *memberel;
    int cur;

    const char **missing;
    int mi;
    int ai;
};

static void sdap_process_group_members_2307_added(struct tevent_req *subreq);
void sdap_process_group_members_2307_step(struct tevent_req *req);
static void sdap_process_group_members_2307_check_add(struct tevent_req *req);
static void
sdap_process_group_members_2307_trans(struct tevent_req *subreq);
static void sdap_process_group_members_2307_add(struct tevent_req *req);
static void sdap_process_group_members_2307_added(struct tevent_req *subreq);
static void sdap_process_group_members_2307_post(struct tevent_req *req);
static void sdap_process_group_members_2307_trans_done(struct tevent_req *subreq);

struct tevent_req *
sdap_process_group_members_2307_send(TALLOC_CTX *memctx,
                                     struct tevent_context *ev,
                                     struct sss_domain_info *dom,
                                     struct sysdb_ctx *sysdb,
                                     struct ldb_message_element *memberel,
                                     struct ldb_message_element *sysdb_dns)
{
    struct tevent_req *req = NULL;
    struct sdap_process_group_members_2307_state *state;
    struct tevent_req *subreq = NULL;

    req = tevent_req_create(memctx, &state,
                            struct sdap_process_group_members_2307_state);
    if (!req) return NULL;

    state->ev = ev;
    state->dom = dom;
    state->sysdb = sysdb;
    state->sysdb_dns = sysdb_dns;
    state->memberel = memberel;
    state->cur = 0;

    if (state->memberel->num_values == 0) {
        /* No members. Done. */
        tevent_req_done(req);
        tevent_req_post(req, ev);
        return req;
    }

    state->missing = talloc_array(state, const char *,
                                  state->memberel->num_values+1);
    if (!state->missing) {
        talloc_zfree(req);
        return NULL;
    }
    state->mi = 0;
    state->missing[state->mi] = NULL;

    subreq = sysdb_search_user_by_name_send(state, state->ev,
                        state->sysdb, NULL,
                        state->dom,
                        (const char *) state->memberel->values[state->cur].data,
                        NULL);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, sdap_process_group_members_2307_step, req);

    return req;
}

void sdap_process_group_members_2307_step(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_process_group_members_2307_state *state =
        tevent_req_data(req, struct sdap_process_group_members_2307_state);
    struct ldb_message *msg;
    char *strdn;
    int ret;

    ret = sysdb_search_user_recv(subreq, state, &msg);
    talloc_zfree(subreq);
    if (ret == EOK) {
        /*
         * User already cached in sysdb. Remember the sysdb DN for later
         * use by sdap_save_groups()
         */
        strdn = sysdb_user_strdn(state->sysdb_dns->values,
                    state->dom->name,
                    (const char *) state->memberel->values[state->cur].data);
        if (!strdn) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        DEBUG(7,("Member already cached in sysdb: %s\n", strdn));
        state->sysdb_dns->values[state->sysdb_dns->num_values].data =
            (uint8_t *) strdn;
        state->sysdb_dns->values[state->sysdb_dns->num_values].length =
            strlen(strdn);
        state->sysdb_dns->num_values++;
    } else if (ret == ENOENT) {
        /* The user is not in sysdb, need to add it */
        DEBUG(7, ("member #%d (%s): not found in sysdb\n",
                   state->cur,
                   (char *) state->memberel->values[state->cur].data));

        /* Just remember the name and store all the fake
         * entries later in one transaction */
        state->missing[state->mi] =
            (const char *) state->memberel->values[state->cur].data;
        state->mi++;
        state->missing[state->mi] = NULL;
    } else {
        DEBUG(1, ("Error checking cache for member #%d (%s):\n",
                   state->cur,
                   (char *) state->memberel->values[state->cur].data));
        tevent_req_error(req, ret);
        return;
    }


    state->cur++;
    if (state->cur == state->memberel->num_values) {
        /* All members processed. Add fake entries if needed. */
        state->ai = 0;
        sdap_process_group_members_2307_check_add(req);
        return;
    }

    /* Go to the next member */
    subreq = sysdb_search_user_by_name_send(state, state->ev,
                        state->sysdb, NULL,
                        state->dom,
                        (char *) state->memberel->values[state->cur].data,
                        NULL);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq,
                            sdap_process_group_members_2307_step,
                            req);
    return;
}

static void
sdap_process_group_members_2307_check_add(struct tevent_req *req)
{
    struct sdap_process_group_members_2307_state *state =
        tevent_req_data(req, struct sdap_process_group_members_2307_state);
    struct tevent_req *subreq;

    if (state->mi == 0) {
        /* Do not need to add any members. We are done. */
        tevent_req_done(req);
        return;
    }

    subreq = sysdb_transaction_send(state, state->ev, state->sysdb);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, sdap_process_group_members_2307_trans,
                            req);
}

static void
sdap_process_group_members_2307_trans(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_process_group_members_2307_state *state =
        tevent_req_data(req, struct sdap_process_group_members_2307_state);
    int ret;

    ret = sysdb_transaction_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    sdap_process_group_members_2307_add(req);
}

static void
sdap_process_group_members_2307_add(struct tevent_req *req)
{
    struct sdap_process_group_members_2307_state *state =
        tevent_req_data(req, struct sdap_process_group_members_2307_state);
    struct tevent_req *subreq;

    if (state->ai == state->mi) {
        sdap_process_group_members_2307_post(req);
        return;
    }

    subreq = sdap_process_missing_member_2307_send(state, state->ev,
                                                   state->dom,
                                                   state->sysdb,
                                                   state->handle,
                                                   state->missing[state->ai],
                                                   state->sysdb_dns);
    if (!subreq) {
        DEBUG(1, ("Error adding missing member #%d (%s):\n",
                    state->ai, state->missing[state->ai]));
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sdap_process_group_members_2307_added, req);
    return;
}

static void
sdap_process_group_members_2307_added(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_process_group_members_2307_state *state =
        tevent_req_data(req, struct sdap_process_group_members_2307_state);
    int ret;

    ret = sdap_process_missing_member_2307_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    state->ai++;
    sdap_process_group_members_2307_add(req);
}

static void
sdap_process_group_members_2307_post(struct tevent_req *req)
{
    struct sdap_process_group_members_2307_state *state =
        tevent_req_data(req, struct sdap_process_group_members_2307_state);
    struct tevent_req *subreq;

    /* Commit the transaction */
    subreq = sysdb_transaction_commit_send(state, state->ev, state->handle);
    if (!subreq) {
        tevent_req_error(req, EIO);
        return;
    }

    tevent_req_set_callback(subreq,
                            sdap_process_group_members_2307_trans_done,
                            req);
}

static void
sdap_process_group_members_2307_trans_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);

    ret = sysdb_transaction_commit_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    /* Processing completed. */
    tevent_req_done(req);
}

int sdap_process_group_members_2307_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

/*===Process-missing-group-member-of-RFC2307-group============================*/

struct sdap_process_missing_member_2307_state {
    struct tevent_context *ev;
    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;
    struct sysdb_handle *handle;

    const char *username;
    struct ldb_message_element* sysdb_dns;

};

static void sdap_process_missing_member_2307_done(struct tevent_req *subreq);

struct tevent_req *
sdap_process_missing_member_2307_send(TALLOC_CTX *memctx,
                                      struct tevent_context *ev,
                                      struct sss_domain_info *dom,
                                      struct sysdb_ctx *sysdb,
                                      struct sysdb_handle *handle,
                                      const char *username,
                                      struct ldb_message_element *sysdb_dns)
{
    struct sdap_process_missing_member_2307_state *state;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq;

    req = tevent_req_create(memctx, &state,
                            struct sdap_process_missing_member_2307_state);
    if (!req) return NULL;

    state->ev = ev;
    state->dom = dom;
    state->handle = handle;
    state->sysdb = sysdb;
    state->sysdb_dns = sysdb_dns;
    state->username = username;

    DEBUG(7, ("Adding a dummy entry\n"));
    subreq = sysdb_add_fake_user_send(state, state->ev, state->handle,
                                      state->dom, state->username);
    if (!subreq) {
        DEBUG(2, ("Cannot store fake user entry\n"));
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq,
                            sdap_process_missing_member_2307_done,
                            req);
    return req;
}

static void sdap_process_missing_member_2307_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_process_missing_member_2307_state *state =
                tevent_req_data(req,
                                struct sdap_process_missing_member_2307_state);
    int ret;
    struct ldb_dn *dn;
    char* dn_string;

    ret = sysdb_add_fake_user_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    /*
     * Convert the just received DN into the corresponding sysdb DN
     * for saving into member attribute of the group
     */
    dn = sysdb_user_dn(state->sysdb, state, state->dom->name,
                       state->username);
    if (!dn) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    dn_string = ldb_dn_alloc_linearized(state->sysdb_dns->values, dn);
    if (!dn_string) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    state->sysdb_dns->values[state->sysdb_dns->num_values].data =
        (uint8_t *) dn_string;
    state->sysdb_dns->values[state->sysdb_dns->num_values].length =
        strlen(dn_string);
    state->sysdb_dns->num_values++;

    tevent_req_done(req);
}

static int sdap_process_missing_member_2307_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

/* ==Search-Groups-with-filter============================================ */

struct sdap_get_groups_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;
    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;
    const char **attrs;
    const char *filter;

    char *higher_timestamp;
    struct sysdb_attrs **groups;
    size_t count;

    size_t check_count;

    hash_table_t *user_hash;
    hash_table_t *group_hash;
};

static void sdap_get_groups_process(struct tevent_req *subreq);
static void sdap_get_groups_processed(struct tevent_req *subreq);
static void sdap_get_groups_done(struct tevent_req *subreq);

struct tevent_req *sdap_get_groups_send(TALLOC_CTX *memctx,
                                       struct tevent_context *ev,
                                       struct sss_domain_info *dom,
                                       struct sysdb_ctx *sysdb,
                                       struct sdap_options *opts,
                                       struct sdap_handle *sh,
                                       const char **attrs,
                                       const char *filter)
{
    struct tevent_req *req, *subreq;
    struct sdap_get_groups_state *state;

    req = tevent_req_create(memctx, &state, struct sdap_get_groups_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->dom = dom;
    state->sh = sh;
    state->sysdb = sysdb;
    state->filter = filter;
    state->attrs = attrs;
    state->higher_timestamp = NULL;
    state->groups =  NULL;
    state->count = 0;

    subreq = sdap_get_generic_send(state, state->ev, state->opts, state->sh,
                                   dp_opt_get_string(state->opts->basic,
                                                     SDAP_GROUP_SEARCH_BASE),
                                   LDAP_SCOPE_SUBTREE,
                                   state->filter, state->attrs,
                                   state->opts->group_map, SDAP_OPTS_GROUP);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, sdap_get_groups_process, req);

    return req;
}

static struct tevent_req *sdap_nested_group_process_send(
        TALLOC_CTX *mem_ctx, struct tevent_context *ev,
        struct sss_domain_info *domain,
        struct sysdb_ctx *sysdb, struct sysdb_attrs *group,
        hash_table_t *users, hash_table_t *groups,
        struct sdap_options *opts, struct sdap_handle *sh,
        uint32_t nesting);
static void sdap_nested_done(struct tevent_req *req);
static errno_t sdap_nested_group_process_recv(struct tevent_req *req);
static void sdap_get_groups_process(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_groups_state *state = tevent_req_data(req,
                                            struct sdap_get_groups_state);
    int ret;
    int i;

    ret = sdap_get_generic_recv(subreq, state,
                                &state->count, &state->groups);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(6, ("Search for groups, returned %d results.\n", state->count));

    switch (state->count) {
    case 0:
        tevent_req_error(req, ENOENT);
        return;
    case 1:
        /* Single group search */

        if (state->opts->schema_type == SDAP_SCHEMA_RFC2307) {
            state->check_count = state->count;
            for (i=0; i < state->count; i++) {
                subreq = sdap_process_group_send(state, state->ev, state->dom,
                                                 state->sysdb, state->opts,
                                                 state->groups[i]);
                if (!subreq) {
                    tevent_req_error(req, ENOMEM);
                    return;
                }
                tevent_req_set_callback(subreq, sdap_get_groups_processed, req);
            }
            return;
        } else {

            /* Prepare hashes for nested user procesing */
            ret = sss_hash_create(state, 32, &state->user_hash);
            if (ret != EOK) {
                tevent_req_error(req, ret);
                return;
            }

            ret = sss_hash_create(state, 32, &state->group_hash);
            if (ret != EOK) {
                tevent_req_error(req, ret);
                return;
            }

            subreq = sdap_nested_group_process_send(state,
                                                    state->ev,
                                                    state->dom,
                                                    state->sysdb,
                                                    state->groups[0],
                                                    state->user_hash,
                                                    state->group_hash,
                                                    state->opts,
                                                    state->sh,
                                                    0);
            if (!subreq) {
                tevent_req_error(req, EIO);
                return;
            }

            tevent_req_set_callback(subreq, sdap_nested_done, req);
            return;
        }
        break;

    default:
        /* Enumeration */
        break;
    }

    subreq = sdap_save_groups_send(state, state->ev, state->dom,
                                   state->sysdb, state->opts,
                                   state->groups, false, state->count);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
    }
    tevent_req_set_callback(subreq, sdap_get_groups_done, req);
}

static void sdap_get_groups_processed(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_groups_state *state = tevent_req_data(req,
                                            struct sdap_get_groups_state);
    int ret;

    ret = sdap_process_group_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        DEBUG(2, ("Failed to process group.\n"));
        tevent_req_error(req, ret);
        return;
    }

    state->check_count--;
    DEBUG(9, ("Groups remaining: %d\n", state->check_count));

    if (state->check_count == 0) {
        subreq = sdap_save_groups_send(state, state->ev, state->dom,
                                       state->sysdb, state->opts,
                                       state->groups, true, state->count);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sdap_get_groups_done, req);
    }
}

static void sdap_nested_users_done(struct tevent_req *subreq);
static void sdap_nested_done(struct tevent_req *subreq)
{
    errno_t ret;
    int hret;
    unsigned long i;
    unsigned long count;
    hash_value_t *values;
    struct sysdb_attrs **users = NULL;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_groups_state *state = tevent_req_data(req,
                                            struct sdap_get_groups_state);

    ret = sdap_nested_group_process_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(1, ("Nested group processing failed: [%d][%s]\n",
                  ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    hret = hash_values(state->user_hash, &count, &values);
    if (hret != HASH_SUCCESS) {
        tevent_req_error(req, EIO);
    }

    if (count) {
        users = talloc_array(state, struct sysdb_attrs *, count);
        if (!users) {
            talloc_free(values);
            tevent_req_error(req, ENOMEM);
            return;
        }

        for (i = 0; i < count; i++) {
            users[i] = talloc_get_type(values[i].ptr, struct sysdb_attrs);
        }
        talloc_zfree(values);
    }

    /* Save all of the users first so that they are in
     * place for the groups to add them.
     */
    subreq = sdap_save_users_send(state, state->ev, state->dom,
                                  state->sysdb, state->opts,
                                  users, count);
    if (!subreq) {
        tevent_req_error(req, EIO);
        return;
    }
    tevent_req_set_callback(subreq, sdap_nested_users_done, req);
}

static void sdap_nested_users_done(struct tevent_req *subreq)
{
    errno_t ret;
    int hret;
    unsigned long i;
    unsigned long count;
    hash_value_t *values;
    struct sysdb_attrs **groups;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_groups_state *state = tevent_req_data(req,
                                            struct sdap_get_groups_state);

    ret = sdap_save_users_recv(subreq, NULL, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    /* Users are all saved. Now save groups */
    hret = hash_values(state->group_hash, &count, &values);
    if (hret != HASH_SUCCESS) {
        tevent_req_error(req, EIO);
        return;
    }

    groups = talloc_array(state, struct sysdb_attrs *, count);
    if (!groups) {
        talloc_free(values);
        tevent_req_error(req, ENOMEM);
        return;
    }

    for (i = 0; i < count; i++) {
        groups[i] = talloc_get_type(values[i].ptr, struct sysdb_attrs);
    }
    talloc_zfree(values);

    subreq = sdap_save_groups_send(state, state->ev, state->dom,
                                   state->sysdb, state->opts,
                                   groups, false, count);
    if (!subreq) {
        tevent_req_error(req, EIO);
        return;
    }
    tevent_req_set_callback(subreq, sdap_get_groups_done, req);
}

static void sdap_get_groups_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_groups_state *state = tevent_req_data(req,
                                            struct sdap_get_groups_state);
    int ret;

    DEBUG(9, ("Saving %d Groups - Done\n", state->count));

    ret = sdap_save_groups_recv(subreq, state, &state->higher_timestamp);
    talloc_zfree(subreq);
    if (ret) {
        DEBUG(2, ("Failed to store groups.\n"));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int sdap_get_groups_recv(struct tevent_req *req,
                         TALLOC_CTX *mem_ctx, char **timestamp)
{
    struct sdap_get_groups_state *state = tevent_req_data(req,
                                            struct sdap_get_groups_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (timestamp) {
        *timestamp = talloc_steal(mem_ctx, state->higher_timestamp);
    }

    return EOK;
}

/* ==Add-Incomplete-Groups====================================================== */
struct sdap_add_incomplete_groups_state {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sysdb_handle *handle;
    struct sss_domain_info *dom;

    char **groupnames;
    int cur;

    struct sysdb_attrs **ldap_groups;
    int ldap_groups_count;
};

static void sdap_add_incomplete_groups_next(struct tevent_req *subreq);
static void sdap_add_incomplete_groups_added(struct tevent_req *subreq);

static
struct tevent_req *sdap_add_incomplete_groups_send(TALLOC_CTX *memctx,
                                             struct tevent_context *ev,
                                             struct sysdb_ctx *sysdb,
                                             struct sysdb_handle *handle,
                                             struct sss_domain_info *dom,
                                             char **groupnames,
                                             struct sysdb_attrs **ldap_groups,
                                             int ldap_groups_count)
{
    struct tevent_req *req, *subreq;
    struct sdap_add_incomplete_groups_state *state;

    req = tevent_req_create(memctx, &state, struct sdap_add_incomplete_groups_state);
    if (!req) return NULL;

    state->ev = ev;
    state->sysdb = sysdb;
    state->handle = handle;
    state->dom = dom;
    state->groupnames = groupnames;
    state->ldap_groups = ldap_groups;
    state->ldap_groups_count = ldap_groups_count;
    state->cur = 0;

    subreq = sysdb_search_group_by_name_send(state, ev, sysdb, handle, dom,
                                             state->groupnames[state->cur],
                                             NULL);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, sdap_add_incomplete_groups_next, req);

    return req;
}

static void sdap_add_incomplete_groups_next(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_add_incomplete_groups_state *state = tevent_req_data(req,
                                           struct sdap_add_incomplete_groups_state);
    errno_t ret;
    int ai;
    const char *name;
    gid_t gid;
    struct ldb_message *msg = NULL;
    struct ldb_message_element *el;
    struct tevent_req *add_req = NULL;
    struct tevent_req *next_req = NULL;

    ret = sysdb_search_group_recv(subreq, state, &msg);
    talloc_zfree(subreq);
    if (ret == EOK) {
        state->cur++;
        if (state->groupnames[state->cur]) {
            next_req = sysdb_search_group_by_name_send(state, state->ev,
                                                    state->sysdb,
                                                    state->handle,
                                                    state->dom,
                                                    state->groupnames[state->cur],
                                                    NULL);
            if (!next_req) {
                tevent_req_error(req, EIO);
                return;
            }
            tevent_req_set_callback(next_req, sdap_add_incomplete_groups_next, req);
            return;
        }

        tevent_req_done(req);
        return;
    } else if (ret == ENOENT) {
        DEBUG(7, ("Group #%d [%s] is not cached, need to add a incomplete entry\n",
                    state->cur, state->groupnames[state->cur]));

        /* The group is not in sysdb, need to add an incomplete entry */
        for (ai=0; ai < state->ldap_groups_count; ai++) {
            ret = sysdb_attrs_get_el(state->ldap_groups[ai],
                                    SYSDB_NAME,
                                    &el);
            if (ret) {
                tevent_req_error(req, ret);
                return;
            }
            if (el->num_values == 0) {
                tevent_req_error(req, EINVAL);
                return;
            }
            name = (const char *)el->values[0].data;

            if (strcmp(name, state->groupnames[state->cur]) == 0) {
                ret = sysdb_attrs_get_el(state->ldap_groups[ai],
                                        SYSDB_GIDNUM,
                                        &el);
                if (ret) {
                    tevent_req_error(req, ret);
                    return;
                }
                if (el->num_values == 0) {
                    DEBUG(1, ("no gid provided for [%s]\n",
                                name));
                    tevent_req_error(req, EINVAL);
                    return;
                }

                errno = 0;
                gid = (gid_t) strtol((const char *)el->values[0].data, NULL, 0);
                if (errno) {
                    tevent_req_error(req, errno);
                    return;
                }

                add_req = sysdb_add_incomplete_group_send(state,
                                                    state->ev,
                                                    state->handle,
                                                    state->dom,
                                                    state->groupnames[state->cur],
                                                    gid);
                if (add_req == NULL) {
                    tevent_req_error(req, EIO);
                    return;
                }

                tevent_req_set_callback(add_req,
                                        sdap_add_incomplete_groups_added,
                                        req);
                return;
            }
        }

        if (ai == state->ldap_groups_count) {
            tevent_req_error(req, EINVAL);
            return;
        }
    }

    DEBUG(2, ("Search failed: %s (%d)\n", strerror(ret), ret));
    tevent_req_error(req, ret);
}

static void sdap_add_incomplete_groups_added(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_add_incomplete_groups_state *state = tevent_req_data(req,
                                           struct sdap_add_incomplete_groups_state);
    errno_t ret;
    struct tevent_req *next_req = NULL;

    ret = sysdb_add_incomplete_group_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    state->cur++;
    if (state->groupnames[state->cur]) {
        next_req = sysdb_search_group_by_name_send(state, state->ev,
                                                   state->sysdb, state->handle,
                                                   state->dom,
                                                   state->groupnames[state->cur],
                                                   NULL);
        if (!next_req) {
            tevent_req_error(req, EIO);
            return;
        }
        tevent_req_set_callback(next_req, sdap_add_incomplete_groups_next, req);
        return;
    }

    tevent_req_done(req);
    return;
}

int sdap_add_incomplete_groups_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

/* ==Initgr-call-(groups-a-user-is-member-of)-RFC2307-Classic/BIS========= */

struct sdap_initgr_rfc2307_state {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sdap_options *opts;
    struct sss_domain_info *dom;
    struct sdap_handle *sh;
    const char *name;

    struct sysdb_handle *handle;
    char **ldap_grouplist;

    struct sysdb_attrs **ldap_groups;
    size_t ldap_groups_count;

    char **add_groups;
    char **del_groups;

    struct sdap_op *op;
};

static void sdap_initgr_rfc2307_process(struct tevent_req *subreq);

static
struct tevent_req *sdap_initgr_rfc2307_send(TALLOC_CTX *memctx,
                                            struct tevent_context *ev,
                                            struct sdap_options *opts,
                                            struct sysdb_ctx *sysdb,
                                            struct sss_domain_info *dom,
                                            struct sdap_handle *sh,
                                            const char *base_dn,
                                            const char *name)
{
    struct tevent_req *req, *subreq;
    struct sdap_initgr_rfc2307_state *state;
    const char *filter;
    const char **attrs;
    errno_t ret;

    req = tevent_req_create(memctx, &state, struct sdap_initgr_rfc2307_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->sysdb = sysdb;
    state->dom = dom;
    state->sh = sh;
    state->op = NULL;
    state->name = talloc_strdup(state, name);
    if (!state->name) {
        talloc_zfree(req);
        return NULL;
    }

    ret = build_attrs_from_map(state, opts->group_map,
                               SDAP_OPTS_GROUP, &attrs);
    if (ret != EOK) {
        talloc_free(req);
        return NULL;
    }

    filter = talloc_asprintf(state, "(&(%s=%s)(objectclass=%s))",
                             opts->group_map[SDAP_AT_GROUP_MEMBER].name,
                             name, opts->group_map[SDAP_OC_GROUP].name);
    if (!filter) {
        talloc_zfree(req);
        return NULL;
    }

    subreq = sdap_get_generic_send(state, state->ev, state->opts,
                                   state->sh, base_dn, LDAP_SCOPE_SUBTREE,
                                   filter, attrs,
                                   state->opts->group_map, SDAP_OPTS_GROUP);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, sdap_initgr_rfc2307_process, req);

    return req;
}

static void sdap_initgr_rfc2307_get_sysdb_groups(struct tevent_req *subreq);
static void sdap_initgr_rfc2307_process(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct sdap_initgr_rfc2307_state *state;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_initgr_rfc2307_state);

    ret = sdap_get_generic_recv(subreq, state,
                                &state->ldap_groups_count,
                                &state->ldap_groups);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->ldap_groups_count == 0) {
        /* No groups for this user in LDAP
         * We need to ensure that there are no groups
         * in the sysdb either.
         */

        state->ldap_grouplist = NULL;
    }
    else {
        ret = sysdb_attrs_to_list(state,
                                  state->ldap_groups, state->ldap_groups_count,
                                  SYSDB_NAME,
                                  &state->ldap_grouplist);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }
    }
    /* Start a transaction to look up the groups in the sysdb
     * and update them with LDAP data
     */

    subreq = sysdb_transaction_send(state, state->ev, state->sysdb);
    if (!subreq) {
        tevent_req_error(req, EIO);
        return;
    }
    tevent_req_set_callback(subreq,
                            sdap_initgr_rfc2307_get_sysdb_groups,
                            req);
}

static void sdap_initgr_rfc2307_update_sysdb_groups(struct tevent_req *subreq);
static void sdap_initgr_rfc2307_get_sysdb_groups(struct tevent_req *subreq)
{
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_initgr_rfc2307_state *state =
            tevent_req_data(req, struct sdap_initgr_rfc2307_state);
    int ret;
    const char **attrs;

    ret = sysdb_transaction_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    attrs = talloc_array(state, const char *, 2);
    if (!attrs) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    attrs[0] = SYSDB_MEMBEROF;
    attrs[1] = NULL;

    /* Search for all groups for which this user is a member */
    subreq = sysdb_search_user_by_name_send(state, state->ev, state->sysdb,
                                            state->handle, state->dom,
                                            state->name, attrs);
    if (!subreq) {
        tevent_req_error(req, EIO);
        return;
    }

    tevent_req_set_callback(subreq,
                            sdap_initgr_rfc2307_update_sysdb_groups,
                            req);
}

static void
sdap_initgr_rfc2307_update_sysdb_groups_done(struct tevent_req *subreq);
static void
sdap_initgr_rfc2307_update_sysdb_groups_step(struct tevent_req *subreq);

static void sdap_initgr_rfc2307_update_sysdb_groups(struct tevent_req *subreq)
{
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_initgr_rfc2307_state *state =
            tevent_req_data(req, struct sdap_initgr_rfc2307_state);
    int ret, i;
    struct ldb_message *reply;
    struct ldb_message_element *groups;
    char **sysdb_grouplist;

    ret = sysdb_search_user_recv(subreq, state, &reply);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    groups = ldb_msg_find_element(reply, SYSDB_MEMBEROF);
    if (!groups || groups->num_values == 0) {
        DEBUG(6, ("User is not a member of any groups\n"));
        sysdb_grouplist = NULL;
    } else {
        sysdb_grouplist = talloc_array(state, char *,
                                       groups->num_values+1);
        if (!sysdb_grouplist) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        /* Get a list of the groups by groupname only */
        for (i=0; i < groups->num_values; i++) {
            ret = sysdb_group_dn_name(state->sysdb,
                    sysdb_grouplist,
                    (const char *)groups->values[i].data,
                    &sysdb_grouplist[i]);
            if (ret != EOK) {
                tevent_req_error(req, ENOMEM);
                return;
            }
        }

        sysdb_grouplist[groups->num_values] = NULL;
    }

    /* Find the differences between the sysdb and ldap lists
     * Groups in ldap only must be added to the sysdb;
     * groups in the sysdb only must be removed.
     */
    ret = diff_string_lists(state,
                            state->ldap_grouplist, sysdb_grouplist,
                            &state->add_groups, &state->del_groups, NULL);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->add_groups && state->add_groups[0]) {
        subreq = sdap_add_incomplete_groups_send(state, state->ev, state->sysdb,
                                                 state->handle, state->dom,
                                                 state->add_groups,
                                                 state->ldap_groups,
                                                 state->ldap_groups_count);
        if (!subreq) {
            tevent_req_error(req, EIO);
            return;
        }

        tevent_req_set_callback(subreq,
                                sdap_initgr_rfc2307_update_sysdb_groups_step,
                                req);
        return;
    }



    subreq = sysdb_update_members_send(state, state->ev, state->handle,
                                       state->dom, state->name,
                                       SYSDB_MEMBER_USER,
                                       state->add_groups, state->del_groups);
    if (!subreq) {
        tevent_req_error(req, EIO);
        return;
    }

    tevent_req_set_callback(subreq,
                            sdap_initgr_rfc2307_update_sysdb_groups_done,
                            req);
}

static void
sdap_initgr_rfc2307_update_sysdb_groups_step(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_initgr_rfc2307_state *state =
            tevent_req_data(req, struct sdap_initgr_rfc2307_state);
    struct tevent_req *updatereq;

    ret = sdap_add_incomplete_groups_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    updatereq = sysdb_update_members_send(state, state->ev, state->handle,
                                       state->dom, state->name,
                                       SYSDB_MEMBER_USER,
                                       state->add_groups, state->del_groups);
    if (!updatereq) {
        tevent_req_error(req, EIO);
        return;
    }

    tevent_req_set_callback(updatereq,
                            sdap_initgr_rfc2307_update_sysdb_groups_done,
                            req);
}

static void
sdap_initgr_rfc2307_transaction_done(struct tevent_req *subreq);
static void
sdap_initgr_rfc2307_update_sysdb_groups_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_initgr_rfc2307_state *state =
            tevent_req_data(req, struct sdap_initgr_rfc2307_state);

    ret = sysdb_update_members_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    /* Commit the transaction */
    subreq = sysdb_transaction_commit_send(state, state->ev, state->handle);
    if (!subreq) {
        tevent_req_error(req, EIO);
        return;
    }

    tevent_req_set_callback(subreq,
                            sdap_initgr_rfc2307_transaction_done,
                            req);
}

static void
sdap_initgr_rfc2307_transaction_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);

    ret = sysdb_transaction_commit_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    /* Processing completed. Return control to sdap_get_initgr_done() */
    tevent_req_done(req);
}

static int sdap_initgr_rfc2307_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}


/* ==Initgr-call-(groups-a-user-is-member-of)-nested-groups=============== */

struct sdap_initgr_nested_state {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sdap_options *opts;
    struct sss_domain_info *dom;
    struct sdap_handle *sh;

    const char **grp_attrs;

    char *filter;
    char **group_dns;
    int count;
    int cur;

    struct sdap_op *op;

    struct sysdb_attrs **groups;
    int groups_cur;
};

static void sdap_initgr_nested_search(struct tevent_req *subreq);
static void sdap_initgr_nested_store(struct tevent_req *req);
static void sdap_initgr_nested_done(struct tevent_req *subreq);
static struct tevent_req *sdap_initgr_nested_send(TALLOC_CTX *memctx,
                                                  struct tevent_context *ev,
                                                  struct sdap_options *opts,
                                                  struct sysdb_ctx *sysdb,
                                                  struct sss_domain_info *dom,
                                                  struct sdap_handle *sh,
                                                  struct sysdb_attrs *user,
                                                  const char **grp_attrs)
{
    struct tevent_req *req, *subreq;
    struct sdap_initgr_nested_state *state;
    struct ldb_message_element *el;
    int i, ret;

    req = tevent_req_create(memctx, &state, struct sdap_initgr_nested_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->sysdb = sysdb;
    state->dom = dom;
    state->sh = sh;
    state->grp_attrs = grp_attrs;
    state->op = NULL;

    state->filter = talloc_asprintf(state, "(objectclass=%s)",
                                    opts->group_map[SDAP_OC_GROUP].name);
    if (!state->filter) {
        talloc_zfree(req);
        return NULL;
    }

    /* TODO: test rootDSE for deref support and use it if available */
    /* TODO: or test rootDSE for ASQ support and use it if available */

    ret = sysdb_attrs_get_el(user, SYSDB_MEMBEROF, &el);
    if (ret || !el || el->num_values == 0) {
        DEBUG(4, ("User entry lacks original memberof ?\n"));
        /* user with no groups ? */
        tevent_req_error(req, ENOENT);
        tevent_req_post(req, ev);
        return req;
    }
    state->count = el->num_values;

    state->groups = talloc_zero_array(state, struct sysdb_attrs *,
                                      state->count + 1);;
    if (!state->groups) {
        talloc_zfree(req);
        return NULL;
    }
    state->groups_cur = 0;

    state->group_dns = talloc_array(state, char *, state->count + 1);
    if (!state->group_dns) {
        talloc_zfree(req);
        return NULL;
    }
    for (i = 0; i < state->count; i++) {
        state->group_dns[i] = talloc_strdup(state->group_dns,
                                            (char *)el->values[i].data);
        if (!state->group_dns[i]) {
            talloc_zfree(req);
            return NULL;
        }
    }
    state->group_dns[i] = NULL; /* terminate */
    state->cur = 0;

    subreq = sdap_get_generic_send(state, state->ev, state->opts, state->sh,
                                   state->group_dns[state->cur],
                                   LDAP_SCOPE_BASE,
                                   state->filter, state->grp_attrs,
                                   state->opts->group_map, SDAP_OPTS_GROUP);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, sdap_initgr_nested_search, req);

    return req;
}

static void sdap_initgr_nested_search(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct sdap_initgr_nested_state *state;
    struct sysdb_attrs **groups;
    size_t count;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_initgr_nested_state);

    ret = sdap_get_generic_recv(subreq, state, &count, &groups);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    if (count == 1) {
        state->groups[state->groups_cur] = groups[0];
        state->groups_cur++;
    } else {
        DEBUG(2, ("Search for group %s, returned %d results. Skipping\n",
                  state->group_dns[state->cur], count));
    }

    state->cur++;
    if (state->cur < state->count) {
        subreq = sdap_get_generic_send(state, state->ev,
                                       state->opts, state->sh,
                                       state->group_dns[state->cur],
                                       LDAP_SCOPE_BASE,
                                       state->filter, state->grp_attrs,
                                       state->opts->group_map,
                                       SDAP_OPTS_GROUP);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sdap_initgr_nested_search, req);
    } else {
        sdap_initgr_nested_store(req);
    }
}

static void sdap_initgr_nested_store(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct sdap_initgr_nested_state *state;

    state = tevent_req_data(req, struct sdap_initgr_nested_state);

    subreq = sdap_save_groups_send(state, state->ev, state->dom,
                                   state->sysdb, state->opts,
                                   state->groups, false, state->groups_cur);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sdap_initgr_nested_done, req);
}

static void sdap_initgr_nested_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    ret = sdap_save_groups_recv(subreq, NULL, NULL);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static int sdap_initgr_nested_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}


/* ==Initgr-call-(groups-a-user-is-member-of)============================= */

struct sdap_get_initgr_state {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sdap_options *opts;
    struct sss_domain_info *dom;
    struct sdap_handle *sh;
    const char *name;
    const char **grp_attrs;

    struct sysdb_attrs *orig_user;

    struct sysdb_handle *handle;
};

static void sdap_get_initgr_user(struct tevent_req *subreq);
static void sdap_get_initgr_store(struct tevent_req *subreq);
static void sdap_get_initgr_commit(struct tevent_req *subreq);
static void sdap_get_initgr_process(struct tevent_req *subreq);
static void sdap_get_initgr_done(struct tevent_req *subreq);

struct tevent_req *sdap_get_initgr_send(TALLOC_CTX *memctx,
                                        struct tevent_context *ev,
                                        struct sss_domain_info *dom,
                                        struct sysdb_ctx *sysdb,
                                        struct sdap_options *opts,
                                        struct sdap_handle *sh,
                                        const char *name,
                                        const char **grp_attrs)
{
    struct tevent_req *req, *subreq;
    struct sdap_get_initgr_state *state;
    const char *base_dn;
    char *filter;
    const char **attrs;
    int ret;

    DEBUG(9, ("Retrieving info for initgroups call\n"));

    req = tevent_req_create(memctx, &state, struct sdap_get_initgr_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->sysdb = sysdb;
    state->dom = dom;
    state->sh = sh;
    state->name = name;
    state->grp_attrs = grp_attrs;
    state->orig_user = NULL;

    filter = talloc_asprintf(state, "(&(%s=%s)(objectclass=%s))",
                        state->opts->user_map[SDAP_AT_USER_NAME].name,
                        state->name,
                        state->opts->user_map[SDAP_OC_USER].name);
    if (!filter) {
        talloc_zfree(req);
        return NULL;
    }

    base_dn = dp_opt_get_string(state->opts->basic,
                                SDAP_USER_SEARCH_BASE);
    if (!base_dn) {
        talloc_zfree(req);
        return NULL;
    }

    ret = build_attrs_from_map(state, state->opts->user_map,
                               SDAP_OPTS_USER, &attrs);
    if (ret) {
        talloc_zfree(req);
        return NULL;
    }

    subreq = sdap_get_generic_send(state, state->ev,
                                   state->opts, state->sh,
                                   base_dn, LDAP_SCOPE_SUBTREE,
                                   filter, attrs,
                                   state->opts->user_map, SDAP_OPTS_USER);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, sdap_get_initgr_user, req);

    return req;
}

static void sdap_get_initgr_user(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_initgr_state *state = tevent_req_data(req,
                                               struct sdap_get_initgr_state);
    struct sysdb_attrs **usr_attrs;
    size_t count;
    int ret;

    DEBUG(9, ("Receiving info for the user\n"));

    ret = sdap_get_generic_recv(subreq, state, &count, &usr_attrs);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    if (count != 1) {
        DEBUG(2, ("Expected one user entry and got %d\n", count));
        tevent_req_error(req, ENOENT);
        return;
    }

    state->orig_user = usr_attrs[0];

    subreq = sysdb_transaction_send(state, state->ev, state->sysdb);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sdap_get_initgr_store, req);
}

static void sdap_get_initgr_store(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_initgr_state *state = tevent_req_data(req,
                                               struct sdap_get_initgr_state);
    int ret;

    DEBUG(9, ("Storing the user\n"));

    ret = sysdb_transaction_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = sdap_save_user_send(state, state->ev, state->handle,
                                 state->opts, state->dom,
                                 state->orig_user, true);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sdap_get_initgr_commit, req);
}

static void sdap_get_initgr_commit(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_initgr_state *state = tevent_req_data(req,
                                               struct sdap_get_initgr_state);
    int ret;

    DEBUG(9, ("Commit change\n"));

    ret = sdap_save_user_recv(subreq, NULL, NULL);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = sysdb_transaction_commit_send(state, state->ev, state->handle);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sdap_get_initgr_process, req);
}

static struct tevent_req *sdap_initgr_rfc2307bis_send(
        TALLOC_CTX *memctx,
        struct tevent_context *ev,
        struct sdap_options *opts,
        struct sysdb_ctx *sysdb,
        struct sss_domain_info *dom,
        struct sdap_handle *sh,
        const char *base_dn,
        const char *name,
        const char *orig_dn);
static int sdap_initgr_rfc2307bis_recv(struct tevent_req *req);
static void sdap_get_initgr_process(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_initgr_state *state = tevent_req_data(req,
                                               struct sdap_get_initgr_state);
    int ret;
    const char *orig_dn;

    DEBUG(9, ("Process user's groups\n"));

    ret = sysdb_transaction_commit_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    switch (state->opts->schema_type) {
    case SDAP_SCHEMA_RFC2307:
        subreq = sdap_initgr_rfc2307_send(state, state->ev, state->opts,
                                    state->sysdb, state->dom, state->sh,
                                    dp_opt_get_string(state->opts->basic,
                                                  SDAP_GROUP_SEARCH_BASE),
                                    state->name);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sdap_get_initgr_done, req);
        break;

    case SDAP_SCHEMA_RFC2307BIS:
        ret = sysdb_attrs_get_string(state->orig_user,
                                     SYSDB_ORIG_DN,
                                     &orig_dn);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }

        subreq = sdap_initgr_rfc2307bis_send(
                state, state->ev, state->opts, state->sysdb, state->dom,
                state->sh, dp_opt_get_string(state->opts->basic,
                                             SDAP_GROUP_SEARCH_BASE),
                state->name, orig_dn);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        talloc_steal(subreq, orig_dn);
        tevent_req_set_callback(subreq, sdap_get_initgr_done, req);
        break;
    case SDAP_SCHEMA_IPA_V1:
    case SDAP_SCHEMA_AD:
        /* TODO: AD uses a different member/memberof schema
         *       We need an AD specific call that is able to unroll
         *       nested groups by doing extensive recursive searches */

        subreq = sdap_initgr_nested_send(state, state->ev, state->opts,
                                         state->sysdb, state->dom, state->sh,
                                         state->orig_user, state->grp_attrs);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sdap_get_initgr_done, req);
        return;

    default:
        tevent_req_error(req, EINVAL);
        return;
    }
}

static void sdap_get_initgr_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_initgr_state *state = tevent_req_data(req,
                                               struct sdap_get_initgr_state);
    int ret;

    DEBUG(9, ("Initgroups done\n"));

    switch (state->opts->schema_type) {
    case SDAP_SCHEMA_RFC2307:

        ret = sdap_initgr_rfc2307_recv(subreq);
        break;

    case SDAP_SCHEMA_RFC2307BIS:

        ret = sdap_initgr_rfc2307bis_recv(subreq);
        break;

    case SDAP_SCHEMA_IPA_V1:
    case SDAP_SCHEMA_AD:

        ret = sdap_initgr_nested_recv(subreq);
        break;

    default:

        ret = EINVAL;
        break;
    }

    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int sdap_get_initgr_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct sdap_nested_group_ctx {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;

    hash_table_t *users;
    hash_table_t *groups;

    struct sdap_options *opts;
    struct sdap_handle *sh;

    uint32_t nesting_level;

    struct ldb_message_element *members;
    uint32_t member_index;
    char *member_dn;
};

static errno_t sdap_nested_group_process_step(struct tevent_req *req);
static struct tevent_req *sdap_nested_group_process_send(
        TALLOC_CTX *mem_ctx, struct tevent_context *ev,
        struct sss_domain_info *domain,
        struct sysdb_ctx *sysdb, struct sysdb_attrs *group,
        hash_table_t *users, hash_table_t *groups,
        struct sdap_options *opts, struct sdap_handle *sh,
        uint32_t nesting)
{
    errno_t ret;
    int hret;
    struct tevent_req *req;
    struct sdap_nested_group_ctx *state;
    const char *groupname;
    hash_key_t key;
    hash_value_t value;

    req = tevent_req_create(mem_ctx, &state, struct sdap_nested_group_ctx);
    if (!req) {
        return NULL;
    }

    state->ev = ev;
    state->sysdb = sysdb;
    state->domain = domain;
    state->users = users;
    state->groups = groups;
    state->opts = opts;
    state->sh = sh;
    state->nesting_level = nesting;

    /* If this is too many levels deep, just return success */
    if (nesting > dp_opt_get_int(opts->basic, SDAP_NESTING_LEVEL)) {
        ret = EOK;
        goto immediate;
    }

    /* Add the current group to the groups hash so we don't
     * look it up more than once
     */
    key.type = HASH_KEY_STRING;

    ret = sysdb_attrs_get_string(
            group,
            opts->group_map[SDAP_AT_GROUP_NAME].sys_name,
            &groupname);
    if (ret != EOK) goto immediate;

    key.str = talloc_strdup(state, groupname);
    if (!key.str) {
        ret = ENOMEM;
        goto immediate;
    }

    if (hash_has_key(groups, &key)) {
        /* This group has already been processed
         * (or is in progress)
         * Skip it and just return success
         */
        ret = EOK;
        goto immediate;
    }

    value.type = HASH_VALUE_PTR;
    value.ptr = talloc_steal(groups, group);

    hret = hash_enter(groups, &key, &value);
    if (hret != HASH_SUCCESS) {
        ret = EIO;
        goto immediate;
    }
    talloc_free(key.str);

    /* Process group memberships */

    /* TODO: future enhancement, check for memberuid as well
     * See https://fedorahosted.org/sssd/ticket/445
     */

    ret = sysdb_attrs_get_el(
            group,
            opts->group_map[SDAP_AT_GROUP_MEMBER].sys_name,
            &state->members);
    if (ret != EOK) {
        if (ret == ENOENT) {
            /* No members to process */
            ret = EOK;
        }
        goto immediate;
    }

    state->member_index = 0;

    ret = sdap_nested_group_process_step(req);
    if (ret != EAGAIN) goto immediate;

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

static void sdap_nested_group_process_sysdb_users(struct tevent_req *subreq);
static errno_t sdap_nested_group_process_step(struct tevent_req *req)
{
    errno_t ret;
    struct sdap_nested_group_ctx *state =
            tevent_req_data(req, struct sdap_nested_group_ctx);
    struct tevent_req *subreq;
    char *filter;
    static const char *attrs[] = SYSDB_PW_ATTRS;
    bool has_key = false;
    hash_key_t key;
    uint8_t *data;

    do {
        if (state->member_index >= state->members->num_values) {
            /* No more entries to check. Return success */
            return EOK;
        }

        /* First check whether this origDN is present (and not expired)
         * in the sysdb
         */
        data = state->members->values[state->member_index].data;
        state->member_dn = talloc_strdup(state, (const char *)data);
        if (!state->member_dn) {
            ret = ENOMEM;
            goto error;
        }

        /* Check the user hash
         * If it's there, we can save ourselves a trip to the
         * sysdb and possibly LDAP as well
         */
        key.type = HASH_KEY_STRING;
        key.str = state->member_dn;
        has_key = hash_has_key(state->users, &key);
        if (has_key) {
            talloc_zfree(state->member_dn);
            state->member_index++;
            continue;
        }


    } while (has_key);

    /* Check for the specified origDN in the sysdb */
    filter = talloc_asprintf(NULL, "(%s=%s)",
                             SYSDB_ORIG_DN,
                             state->member_dn);
    if (!filter) {
        ret = ENOMEM;
        goto error;
    }

    /* Try users first */
    subreq = sysdb_search_users_send(state, state->ev, state->sysdb,
                                      NULL, state->domain, filter,
                                      attrs);
    if (!subreq) {
        ret = EIO;
        talloc_free(filter);
        goto error;
    }
    talloc_steal(subreq, filter);
    tevent_req_set_callback(subreq,
                            sdap_nested_group_process_sysdb_users,
                            req);

    return EAGAIN;

error:
    talloc_zfree(state->member_dn);
    return ret;
}

static void sdap_nested_group_process_user(struct tevent_req *subreq);
static void sdap_nested_group_process_group(struct tevent_req *subreq);
static void sdap_nested_group_process_sysdb_groups(struct tevent_req *subreq);
static errno_t sdap_nested_group_lookup_user(struct tevent_req *req,
                                             tevent_req_fn fn);
static void sdap_nested_group_process_sysdb_users(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_nested_group_ctx *state =
            tevent_req_data(req, struct sdap_nested_group_ctx);
    size_t count;
    struct ldb_message **msgs;
    uint64_t expiration;
    time_t now = time(NULL);
    char *filter;

    static const char *attrs[] = SYSDB_GRSRC_ATTRS;

    ret = sysdb_search_users_recv(subreq, state, &count, &msgs);
    talloc_zfree(subreq);
    if (ret != EOK && ret != ENOENT) {
        tevent_req_error(req, ret);
        return;
    } if (ret == ENOENT || count == 0) {
        /* It wasn't a user. Check whether it's a group */
        if (ret == EOK) talloc_zfree(msgs);

        filter = talloc_asprintf(NULL, "(%s=%s)",
                                 SYSDB_ORIG_DN,
                                 state->member_dn);
        if (!filter) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        subreq = sysdb_search_groups_send(state, state->ev, state->sysdb,
                                          NULL, state->domain, filter,
                                          attrs);
        if (!subreq) {
            talloc_free(filter);
            tevent_req_error(req, EIO);
            return;
        }
        talloc_steal(subreq, filter);
        tevent_req_set_callback(subreq,
                                sdap_nested_group_process_sysdb_groups,
                                req);
        return;
    }

    /* Check whether the entry is valid */
    if (count != 1) {
        DEBUG(1, ("More than one entry with this origDN? Skipping\n"));
        goto skip;
    }

    expiration = ldb_msg_find_attr_as_uint64(msgs[0],
                                             SYSDB_CACHE_EXPIRE,
                                             0);
    if (expiration && expiration > now) {
        DEBUG(6, ("Cached values are still valid. Skipping\n"));
        goto skip;
    }

    ret = sdap_nested_group_lookup_user(req, sdap_nested_group_process_user);
    if (ret != EOK) {
        tevent_req_error(req, ret);
    }
    return;

skip:
    state->member_index++;
    talloc_zfree(state->member_dn);
    ret = sdap_nested_group_process_step(req);
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    /* EAGAIN means that we should re-enter
     * the mainloop
     */
}

static errno_t sdap_nested_group_lookup_user(struct tevent_req *req,
                                             tevent_req_fn fn)
{
    errno_t ret;
    const char **sdap_attrs;
    char *filter;
    struct tevent_req *subreq;
    struct sdap_nested_group_ctx *state =
            tevent_req_data(req, struct sdap_nested_group_ctx);

    ret = build_attrs_from_map(state, state->opts->user_map,
                               SDAP_OPTS_USER, &sdap_attrs);
    if (ret != EOK) {
        return ret;
    }

    filter = talloc_asprintf(
            sdap_attrs, "(objectclass=%s)",
            state->opts->user_map[SDAP_OC_USER].name);
    if (!filter) {
        talloc_free(sdap_attrs);
        return ENOMEM;
    }

    subreq = sdap_get_generic_send(state, state->ev, state->opts,
                                   state->sh, state->member_dn,
                                   LDAP_SCOPE_BASE,
                                   filter, sdap_attrs,
                                   state->opts->user_map,
                                   SDAP_OPTS_USER);
    if (!subreq) {
        talloc_free(sdap_attrs);
        return EIO;
    }
    talloc_steal(subreq, sdap_attrs);

    tevent_req_set_callback(subreq, fn, req);
    return EOK;
}

static errno_t sdap_nested_group_lookup_group(struct tevent_req *req);
static void sdap_nested_group_process_ldap_user(struct tevent_req *subreq);
static void sdap_nested_group_process_sysdb_groups(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_nested_group_ctx *state =
            tevent_req_data(req, struct sdap_nested_group_ctx);
    size_t count;
    uint64_t expiration;
    struct ldb_message **msgs;
    time_t now = time(NULL);

    ret = sysdb_search_groups_recv(subreq, state, &count, &msgs);
    talloc_zfree(subreq);
    if (ret != EOK && ret != ENOENT) {
        tevent_req_error(req, ret);
        return;
    } if (ret == ENOENT || count == 0) {
        /* It wasn't found in the groups either
         * We'll have to do a blind lookup for both
         */

        /* Try users first */
        ret = sdap_nested_group_lookup_user(
                req, sdap_nested_group_process_ldap_user);
        if (ret != EOK) {
            tevent_req_error(req, ret);
        }
        return;
    }

    /* Check whether the entry is valid */
    if (count != 1) {
        DEBUG(1, ("More than one entry with this origDN? Skipping\n"));
        goto skip;
    }

    expiration = ldb_msg_find_attr_as_uint64(msgs[0],
                                             SYSDB_CACHE_EXPIRE,
                                             0);
    if (expiration && expiration > now) {
        DEBUG(6, ("Cached values are still valid. Skipping\n"));
        goto skip;
    }

    /* Look up the group in LDAP */
    ret = sdap_nested_group_lookup_group(req);
    if (ret != EOK) {
        tevent_req_error(req, ret);
    }
    return;

skip:
    state->member_index++;
    talloc_zfree(state->member_dn);
    ret = sdap_nested_group_process_step(req);
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }
}

static errno_t sdap_nested_group_lookup_group(struct tevent_req *req)
{
    errno_t ret;
    const char **sdap_attrs;
    char *filter;
    struct tevent_req *subreq;
    struct sdap_nested_group_ctx *state =
            tevent_req_data(req, struct sdap_nested_group_ctx);

    ret = build_attrs_from_map(state, state->opts->group_map,
                               SDAP_OPTS_GROUP, &sdap_attrs);
    if (ret != EOK) {
        return ret;
    }

    filter = talloc_asprintf(
            sdap_attrs, "(objectclass=%s)",
            state->opts->group_map[SDAP_OC_GROUP].name);
    if (!filter) {
        talloc_free(sdap_attrs);
        return ENOMEM;
    }

    subreq = sdap_get_generic_send(state, state->ev, state->opts,
                                   state->sh, state->member_dn,
                                   LDAP_SCOPE_BASE,
                                   filter, sdap_attrs,
                                   state->opts->group_map,
                                   SDAP_OPTS_GROUP);
    if (!subreq) {
        talloc_free(sdap_attrs);
        return EIO;
    }
    talloc_steal(subreq, sdap_attrs);

    tevent_req_set_callback(subreq, sdap_nested_group_process_group, req);
    return EOK;
}

static void sdap_nested_group_process_user(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_nested_group_ctx *state =
            tevent_req_data(req, struct sdap_nested_group_ctx);
    TALLOC_CTX *tmp_ctx;
    size_t count;
    struct sysdb_attrs **replies;
    int hret;
    hash_key_t key;
    hash_value_t value;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    ret = sdap_get_generic_recv(subreq, tmp_ctx, &count, &replies);
    talloc_zfree(subreq);
    if (ret != EOK && ret != ENOENT) {
        tevent_req_error(req, ret);
        goto done;
    } else if (ret == ENOENT || count == 0) {
        /* Nothing to do if the user doesn't exist */
        goto skip;
    }

    if (count != 1) {
        /* There should only ever be one reply for a
         * BASE search. If otherwise, it's a serious
         * error.
         */
        DEBUG(1,("Received multiple replies for a BASE search!\n"));
        tevent_req_error(req, EIO);
        goto done;
    }

    /* Save the user attributes to the user hash so we can store
     * them all at once later.
     */

    key.type = HASH_KEY_STRING;
    key.str = state->member_dn;

    value.type = HASH_VALUE_PTR;
    value.ptr = replies[0];

    hret = hash_enter(state->users, &key, &value);
    if (hret != HASH_SUCCESS) {
        tevent_req_error(req, EIO);
        goto done;
    }
    talloc_steal(state->users, replies[0]);

skip:
    state->member_index++;
    talloc_zfree(state->member_dn);
    ret = sdap_nested_group_process_step(req);
    if (ret == EOK) {
        /* EOK means it's complete */
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    /* EAGAIN means that we should re-enter
     * the mainloop
     */

done:
    talloc_free(tmp_ctx);
}

static void sdap_group_internal_nesting_done(struct tevent_req *subreq);
static void sdap_nested_group_process_group(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_nested_group_ctx *state =
            tevent_req_data(req, struct sdap_nested_group_ctx);
    TALLOC_CTX *tmp_ctx;
    size_t count;
    struct sysdb_attrs **replies;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    ret = sdap_get_generic_recv(subreq, tmp_ctx, &count, &replies);
    talloc_zfree(subreq);
    if (ret != EOK && ret != ENOENT) {
        tevent_req_error(req, ret);
        goto done;
    } else if (ret == ENOENT || count == 0) {
        /* Nothing to do if the group doesn't exist */
        goto skip;
    }

    if (count != 1) {
        /* There should only ever be one reply for a
         * BASE search. If otherwise, it's a serious
         * error.
         */
        DEBUG(1,("Received multiple replies for a BASE search!\n"));
        tevent_req_error(req, EIO);
        goto done;
    }

    /* Recurse down into the member group */
    subreq = sdap_nested_group_process_send(state, state->ev, state->domain,
                                            state->sysdb, replies[0],
                                            state->users, state->groups,
                                            state->opts, state->sh,
                                            state->nesting_level + 1);
    if (!subreq) {
        tevent_req_error(req, EIO);
        goto done;
    }
    tevent_req_set_callback(subreq, sdap_group_internal_nesting_done, req);

    talloc_free(tmp_ctx);
    return;

skip:
    state->member_index++;
    talloc_zfree(state->member_dn);
    ret = sdap_nested_group_process_step(req);
    if (ret == EOK) {
        /* EOK means it's complete */
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    /* EAGAIN means that we should re-enter
     * the mainloop
     */

done:
    talloc_free(tmp_ctx);
}

static void sdap_group_internal_nesting_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_nested_group_ctx *state =
            tevent_req_data(req, struct sdap_nested_group_ctx);

    ret = sdap_nested_group_process_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
    }

    state->member_index++;
    talloc_zfree(state->member_dn);
    ret = sdap_nested_group_process_step(req);
    if (ret == EOK) {
        /* EOK means it's complete */
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    /* EAGAIN means that we should re-enter
     * the mainloop
     */
}

static void sdap_nested_group_process_ldap_user(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_nested_group_ctx *state =
            tevent_req_data(req, struct sdap_nested_group_ctx);
    TALLOC_CTX *tmp_ctx;
    size_t count;
    struct sysdb_attrs **replies;
    int hret;
    hash_key_t key;
    hash_value_t value;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    ret = sdap_get_generic_recv(subreq, tmp_ctx, &count, &replies);
    talloc_zfree(subreq);
    if (ret != EOK && ret != ENOENT) {
        tevent_req_error(req, ret);
        goto done;
    } else if (ret == ENOENT || count == 0) {
        /* No user found. Assume it's a group */
        ret = sdap_nested_group_lookup_group(req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
        }
        goto done;
    }

    if (count != 1) {
        /* There should only ever be one reply for a
         * BASE search. If otherwise, it's a serious
         * error.
         */
        DEBUG(1,("Received multiple replies for a BASE search!\n"));
        tevent_req_error(req, EIO);
        goto done;
    }

    /* Save the user attributes to the user hash so we can store
     * them all at once later.
     */
    key.type = HASH_KEY_STRING;
    key.str = state->member_dn;

    value.type = HASH_VALUE_PTR;
    value.ptr = replies[0];

    hret = hash_enter(state->users, &key, &value);
    if (hret != HASH_SUCCESS) {
        tevent_req_error(req, EIO);
        goto done;
    }
    talloc_steal(state->users, replies[0]);

    /* Move on to the next member */
    state->member_index++;
    talloc_zfree(state->member_dn);
    ret = sdap_nested_group_process_step(req);
    if (ret == EOK) {
        /* EOK means it's complete */
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    /* EAGAIN means that we should re-enter
     * the mainloop
     */

done:
    talloc_free(tmp_ctx);
}

static errno_t sdap_nested_group_process_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static void sdap_initgr_rfc2307bis_process(struct tevent_req *subreq);
static struct tevent_req *sdap_initgr_rfc2307bis_send(
        TALLOC_CTX *memctx,
        struct tevent_context *ev,
        struct sdap_options *opts,
        struct sysdb_ctx *sysdb,
        struct sss_domain_info *dom,
        struct sdap_handle *sh,
        const char *base_dn,
        const char *name,
        const char *orig_dn)
{
    errno_t ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct sdap_initgr_rfc2307_state *state;
    const char *filter;
    const char **attrs;

    req = tevent_req_create(memctx, &state, struct sdap_initgr_rfc2307_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->sysdb = sysdb;
    state->dom = dom;
    state->sh = sh;
    state->op = NULL;
    state->name = name;

    ret = build_attrs_from_map(state, opts->group_map,
                               SDAP_OPTS_GROUP, &attrs);
    if (ret != EOK) {
        talloc_free(req);
        return NULL;
    }

    filter = talloc_asprintf(state, "(&(%s=%s)(objectclass=%s))",
                             opts->group_map[SDAP_AT_GROUP_MEMBER].name,
                             orig_dn, opts->group_map[SDAP_OC_GROUP].name);
    if (!filter) {
        talloc_zfree(req);
        return NULL;
    }

    DEBUG(6, ("Looking up parent groups for user [%s]\n", orig_dn));
    subreq = sdap_get_generic_send(state, state->ev, state->opts,
                                   state->sh, base_dn, LDAP_SCOPE_SUBTREE,
                                   filter, attrs,
                                   state->opts->group_map, SDAP_OPTS_GROUP);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, sdap_initgr_rfc2307bis_process, req);

    return req;

}

errno_t save_rfc2307bis_user_memberships(struct tevent_req *req);
struct tevent_req *rfc2307bis_nested_groups_send(
        TALLOC_CTX *mem_ctx, struct tevent_context *ev,
        struct sdap_options *opts, struct sysdb_ctx *sysdb,
        struct sss_domain_info *dom, struct sdap_handle *sh,
        struct sysdb_attrs **groups, size_t num_groups);
static void sdap_initgr_rfc2307bis_done(struct tevent_req *subreq);
static void sdap_initgr_rfc2307bis_process(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct sdap_initgr_rfc2307_state *state;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_initgr_rfc2307_state);

    ret = sdap_get_generic_recv(subreq, state,
                                &state->ldap_groups_count,
                                &state->ldap_groups);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->ldap_groups_count == 0) {
        /* Start a transaction to look up the groups in the sysdb
         * and update them with LDAP data
         */
        ret = save_rfc2307bis_user_memberships(req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
        }
        return;
    }

    subreq = rfc2307bis_nested_groups_send(state, state->ev, state->opts,
                                           state->sysdb, state->dom,
                                           state->sh, state->ldap_groups,
                                           state->ldap_groups_count);
    if (!subreq) {
        tevent_req_error(req, EIO);
        return;
    }
    tevent_req_set_callback(subreq, sdap_initgr_rfc2307bis_done, req);
}

static void sdap_initgr_rfc2307bis_get_sysdb_groups(struct tevent_req *subreq);
errno_t save_rfc2307bis_user_memberships(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct sdap_initgr_rfc2307_state *state =
            tevent_req_data(req, struct sdap_initgr_rfc2307_state);

    DEBUG(7, ("Save parent groups to sysdb\n"));
    subreq = sysdb_transaction_send(state, state->ev, state->sysdb);
    if (!subreq) {
        return EIO;
    }
    /* Save this user and their memberships */
    tevent_req_set_callback(subreq,
                            sdap_initgr_rfc2307bis_get_sysdb_groups,
                            req);
    return EOK;
}

static errno_t rfc2307bis_sysdb_member_lookup(TALLOC_CTX *mem_ctx,
                                              struct tevent_context *ev,
                                              struct sysdb_ctx *sysdb,
                                              struct sysdb_handle *handle,
                                              struct sss_domain_info *dom,
                                              enum sysdb_member_type type,
                                              const char *domainname,
                                              const char *name,
                                              tevent_req_fn fn,
                                              struct tevent_req *req);
static void sdap_initgr_rfc2307bis_update_sysdb_groups(
        struct tevent_req *subreq);
static void sdap_initgr_rfc2307bis_get_sysdb_groups(struct tevent_req *subreq)
{
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_initgr_rfc2307_state *state =
            tevent_req_data(req, struct sdap_initgr_rfc2307_state);
    int ret;

    ret = sysdb_transaction_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    ret = rfc2307bis_sysdb_member_lookup(
            state, state->ev, state->sysdb, state->handle, state->dom,
            SYSDB_MEMBER_USER, state->dom->name, state->name,
            sdap_initgr_rfc2307bis_update_sysdb_groups, req);
    if (ret != EOK) {
        tevent_req_error(req, ret);
    }
}
static errno_t rfc2307bis_sysdb_member_lookup(TALLOC_CTX *mem_ctx,
                                              struct tevent_context *ev,
                                              struct sysdb_ctx *sysdb,
                                              struct sysdb_handle *handle,
                                              struct sss_domain_info *dom,
                                              enum sysdb_member_type type,
                                              const char *domainname,
                                              const char *name,
                                              tevent_req_fn fn,
                                              struct tevent_req *req)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    char *member_dn;
    char *filter;
    const char **attrs;
    struct tevent_req *subreq;

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    attrs = talloc_array(tmp_ctx, const char *, 2);
    if (!attrs) {
        ret = ENOMEM;
        goto error;
    }
    attrs[0] = SYSDB_NAME;
    attrs[1] = NULL;

    if (type == SYSDB_MEMBER_USER) {
        member_dn = sysdb_user_strdn(tmp_ctx, domainname, name);
    } else if (type == SYSDB_MEMBER_GROUP) {
        member_dn = sysdb_group_strdn(tmp_ctx, domainname, name);
    } else {
        ret = EINVAL;
        goto error;
    }

    if (!member_dn) {
        ret = ENOMEM;
        goto error;
    }

    filter = talloc_asprintf(tmp_ctx, "(member=%s)", member_dn);
    if (!filter) {
        ret = ENOMEM;
        goto error;
    }
    talloc_free(member_dn);

    /* Search for all groups for which this user is a direct member */
    subreq = sysdb_search_groups_send(mem_ctx, ev, sysdb,
                                      handle, dom,
                                      filter, attrs);
    if (!subreq) {
        ret = EIO;
        goto error;
    }
    talloc_steal(subreq, tmp_ctx);

    tevent_req_set_callback(subreq, fn, req);
    return EOK;

error:
    talloc_free(tmp_ctx);
    return ret;
}

static void sdap_initgr_rfc2307bis_update_sysdb_groups_done(
        struct tevent_req *subreq);
static void sdap_initgr_rfc2307bis_update_sysdb_groups(
        struct tevent_req *subreq)
{
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_initgr_rfc2307_state *state =
            tevent_req_data(req, struct sdap_initgr_rfc2307_state);
    int ret, i;
    size_t reply_count;
    struct ldb_message **replies;
    char **sysdb_grouplist;
    const char *tmp_str;

    ret = sysdb_search_groups_recv(subreq, state, &reply_count, &replies);
    talloc_zfree(subreq);
    if (ret != EOK && ret != ENOENT) {
        tevent_req_error(req, ret);
        return;
    } else if (ret == ENOENT) {
        reply_count = 0;
    }

    if (reply_count == 0) {
        DEBUG(6, ("User [%s] is not a direct member of any groups\n",
                  state->name));
        sysdb_grouplist = NULL;
    } else {
        sysdb_grouplist = talloc_array(state, char *, reply_count+1);
        if (!sysdb_grouplist) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        for (i = 0; i < reply_count; i++) {
            tmp_str = ldb_msg_find_attr_as_string(replies[i],
                                                  SYSDB_NAME,
                                                  NULL);
            if (!tmp_str) {
                /* This should never happen, but if it
                 * does, just skip it.
                 */
                continue;
            }

            sysdb_grouplist[i] = talloc_strdup(sysdb_grouplist, tmp_str);
            if (!sysdb_grouplist[i]) {
                talloc_free(sysdb_grouplist);
                tevent_req_error(req, ENOMEM);
                return;
            }
        }
        sysdb_grouplist[reply_count] = NULL;
    }

    if (state->ldap_groups_count == 0) {
        state->ldap_grouplist = NULL;
    }
    else {
        ret = sysdb_attrs_to_list(state,
                                  state->ldap_groups, state->ldap_groups_count,
                                  SYSDB_NAME,
                                  &state->ldap_grouplist);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }
    }

    /* Find the differences between the sysdb and ldap lists
     * Groups in ldap only must be added to the sysdb;
     * groups in the sysdb only must be removed.
     */
    ret = diff_string_lists(state,
                            state->ldap_grouplist, sysdb_grouplist,
                            &state->add_groups, &state->del_groups, NULL);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = sysdb_update_members_send(state, state->ev, state->handle,
                                       state->dom, state->name,
                                       SYSDB_MEMBER_USER,
                                       state->add_groups, state->del_groups);
    if (!subreq) {
        tevent_req_error(req, EIO);
        return;
    }

    tevent_req_set_callback(subreq,
                            sdap_initgr_rfc2307bis_update_sysdb_groups_done,
                            req);
}

static void sdap_initgr_rfc2307bis_transaction_done(struct tevent_req *subreq);
static void sdap_initgr_rfc2307bis_update_sysdb_groups_done(
        struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_initgr_rfc2307_state *state =
            tevent_req_data(req, struct sdap_initgr_rfc2307_state);

    ret = sysdb_update_members_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    /* Commit the transaction */
    subreq = sysdb_transaction_commit_send(state, state->ev, state->handle);
    if (!subreq) {
        tevent_req_error(req, EIO);
        return;
    }

    tevent_req_set_callback(subreq,
                            sdap_initgr_rfc2307bis_transaction_done,
                            req);
}

static void sdap_initgr_rfc2307bis_transaction_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);

    ret = sysdb_transaction_commit_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    /* Processing completed. Return control to sdap_get_initgr_done() */
    tevent_req_done(req);
}

static errno_t rfc2307bis_nested_groups_recv(struct tevent_req *req);
static void sdap_initgr_rfc2307bis_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);

    ret = rfc2307bis_nested_groups_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    /* save the user memberships */
    ret = save_rfc2307bis_user_memberships(req);
    if (ret != EOK) {
        tevent_req_error(req, ret);
    }
    return;
}

struct sdap_rfc2307bis_nested_ctx {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *dom;
    struct sdap_handle *sh;
    struct sysdb_attrs **groups;
    size_t num_groups;

    size_t group_iter;
    struct sysdb_attrs **ldap_groups;
    size_t ldap_groups_count;

    struct sysdb_handle *handle;
};

static errno_t rfc2307bis_nested_groups_step(struct tevent_req *req);
struct tevent_req *rfc2307bis_nested_groups_send(
        TALLOC_CTX *mem_ctx, struct tevent_context *ev,
        struct sdap_options *opts, struct sysdb_ctx *sysdb,
        struct sss_domain_info *dom, struct sdap_handle *sh,
        struct sysdb_attrs **groups, size_t num_groups)
{
    errno_t ret;
    struct tevent_req *req;
    struct sdap_rfc2307bis_nested_ctx *state;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_rfc2307bis_nested_ctx);
    if (!req) return NULL;

    if (num_groups == 0) {
        /* No parent groups to process */
        tevent_req_done(req);
        tevent_req_post(req, ev);
        return req;
    }

    state->ev = ev;
    state->opts = opts;
    state->sysdb = sysdb;
    state->dom = dom;
    state->sh = sh;
    state->groups = groups;
    state->num_groups = num_groups;
    state->group_iter = 0;

    ret = rfc2307bis_nested_groups_step(req);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }
    return req;
}

static void rfc2307bis_nested_groups_incomplete_groups_save(
        struct tevent_req *subreq);
static errno_t rfc2307bis_nested_groups_step(struct tevent_req *req)
{
    errno_t ret;
    struct tevent_req *subreq;
    const char *name;
    struct sdap_rfc2307bis_nested_ctx *state =
            tevent_req_data(req, struct sdap_rfc2307bis_nested_ctx);

    if (debug_level >= 6) {
        ret = sysdb_attrs_get_string(state->groups[state->group_iter],
                                     SYSDB_NAME, &name);
        if (ret != EOK) {
            return ret;
        }

        DEBUG(6, ("Processing group [%s]\n", name));
    }

    subreq = sysdb_transaction_send(state, state->ev, state->sysdb);
    if (!subreq) {
        return EIO;
    }
    tevent_req_set_callback(subreq,
                            rfc2307bis_nested_groups_incomplete_groups_save,
                            req);
    return EOK;
}

static void rfc2307bis_nested_groups_incomplete_groups_done(
        struct tevent_req *subreq);
static void rfc2307bis_nested_groups_incomplete_groups_save(
        struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_rfc2307bis_nested_ctx *state =
            tevent_req_data(req, struct sdap_rfc2307bis_nested_ctx);
    const char *name;
    struct sysdb_attrs **grouplist;
    char **groupnamelist;
    TALLOC_CTX *tmp_ctx = NULL;

    ret = sysdb_transaction_recv(subreq, state, &state->handle);
    if (ret != EOK) goto error;

    tmp_ctx = talloc_new(state);
    if (!tmp_ctx) {
        ret = ENOMEM;
        goto error;
    }

    /* First, save the group we're processing to the sysdb
     * sdap_add_incomplete_groups_send will add them if needed
     */
    ret = sysdb_attrs_get_string(state->groups[state->group_iter],
                                 SYSDB_NAME, &name);

    /* sdap_add_incomplete_groups_send expects a list of groups */
    grouplist = talloc_array(tmp_ctx, struct sysdb_attrs *, 1);
    if (!grouplist) {
        ret = ENOMEM;
        goto error;
    }
    grouplist[0] = state->groups[state->group_iter];

    groupnamelist = talloc_array(tmp_ctx, char *, 2);
    if (!groupnamelist) {
        ret = ENOMEM;
        goto error;
    }
    groupnamelist[0] = talloc_strdup(groupnamelist, name);
    if (!groupnamelist[0]) {
        ret = ENOMEM;
        goto error;
    }
    groupnamelist[1] = NULL;

    DEBUG(6, ("Saving incomplete group [%s] to the sysdb\n",
              groupnamelist[0]));
    subreq = sdap_add_incomplete_groups_send(state, state->ev, state->sysdb,
                                             state->handle, state->dom,
                                             groupnamelist,
                                             grouplist,
                                             1);
    if (!subreq) {
        ret = EIO;
        goto error;
    }

    talloc_steal(subreq, tmp_ctx);
    tevent_req_set_callback(subreq,
                            rfc2307bis_nested_groups_incomplete_groups_done,
                            req);
    return;

error:
    talloc_free(tmp_ctx);
    tevent_req_error(req, ret);
}

static void rfc2307bis_nested_groups_get_parents(struct tevent_req *subreq);
static void rfc2307bis_nested_groups_incomplete_groups_done(
        struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_rfc2307bis_nested_ctx *state =
            tevent_req_data(req, struct sdap_rfc2307bis_nested_ctx);

    ret = sdap_add_incomplete_groups_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(7, ("sdap_add_incomplete_groups failed [%d][%s]\n",
                  ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    subreq = sysdb_transaction_commit_send(state, state->ev, state->handle);
    if (!subreq) {
        tevent_req_error(req, EIO);
        return;
    }
    tevent_req_set_callback(subreq,
                            rfc2307bis_nested_groups_get_parents,
                            req);
}

static void rfc2307bis_nested_groups_process(struct tevent_req *subreq);
static void rfc2307bis_nested_groups_get_parents(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_rfc2307bis_nested_ctx *state =
            tevent_req_data(req, struct sdap_rfc2307bis_nested_ctx);
    char *filter;
    const char *orig_dn;
    const char **attrs;
    TALLOC_CTX *tmp_ctx;

    ret = sysdb_transaction_commit_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(7, ("sysdb transaction failed [%d][%s]\n",
                  ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    /* Get any parent groups for this group */

    tmp_ctx = talloc_new(state);
    if (!tmp_ctx) {
        ret = ENOMEM;
        goto error;
    }

    ret = sysdb_attrs_get_string(state->groups[state->group_iter],
                                 SYSDB_ORIG_DN,
                                 &orig_dn);
    if (ret != EOK) {
        goto error;
    }

    ret = build_attrs_from_map(tmp_ctx, state->opts->group_map,
                               SDAP_OPTS_GROUP, &attrs);
    if (ret != EOK) {
        goto error;
    }

    filter = talloc_asprintf(
            tmp_ctx, "(&(%s=%s)(objectclass=%s))",
            state->opts->group_map[SDAP_AT_GROUP_MEMBER].name,
            orig_dn,
            state->opts->group_map[SDAP_OC_GROUP].name);
    if (!filter) {
        ret = ENOMEM;
        goto error;
    }

    DEBUG(6, ("Looking up parent groups for group [%s]\n", orig_dn));
    subreq = sdap_get_generic_send(state, state->ev, state->opts,
                                   state->sh,
                                   dp_opt_get_string(state->opts->basic,
                                                     SDAP_GROUP_SEARCH_BASE),
                                   LDAP_SCOPE_SUBTREE,
                                   filter, attrs,
                                   state->opts->group_map, SDAP_OPTS_GROUP);
    if (!subreq) {
        ret = EIO;
        goto error;
    }
    talloc_steal(subreq, tmp_ctx);
    tevent_req_set_callback(subreq,
                            rfc2307bis_nested_groups_process,
                            req);

    return;

error:
    talloc_free(tmp_ctx);
    tevent_req_error(req, ret);
}

static errno_t rfc2307bis_nested_groups_update_sysdb(struct tevent_req *req);
static void rfc2307bis_nested_groups_done(struct tevent_req *subreq);
static void rfc2307bis_nested_groups_process(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_rfc2307bis_nested_ctx *state =
            tevent_req_data(req, struct sdap_rfc2307bis_nested_ctx);

    ret = sdap_get_generic_recv(subreq, state,
                                &state->ldap_groups_count,
                                &state->ldap_groups);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->ldap_groups_count == 0) {
        /* No groups for this user in LDAP
         * We need to ensure that there are no groups
         * in the sysdb either.
         */

        ret = rfc2307bis_nested_groups_update_sysdb(req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
        }
        return;
    }

    /* Otherwise, recurse into the groups */
    subreq = rfc2307bis_nested_groups_send(
            state, state->ev, state->opts, state->sysdb,
            state->dom, state->sh,
            state->ldap_groups, state->ldap_groups_count);
    if (!subreq) {
        tevent_req_error(req, EIO);
        return;
    }
    tevent_req_set_callback(subreq, rfc2307bis_nested_groups_done, req);
}

static errno_t rfc2307bis_nested_groups_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

static void rfc2307bis_nested_groups_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);

    ret = rfc2307bis_nested_groups_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(6, ("rfc2307bis_nested failed [%d][%s]\n",
                  ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    /* All of the parent groups have been added
     * Now add the memberships
     */

    ret = rfc2307bis_nested_groups_update_sysdb(req);
    if (ret != EOK) {
        tevent_req_error(req, ret);
    }
    return;
}

static void rfc2307bis_get_sysdb_groups(struct tevent_req *subreq);
static errno_t rfc2307bis_nested_groups_update_sysdb(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct sdap_rfc2307bis_nested_ctx *state =
            tevent_req_data(req, struct sdap_rfc2307bis_nested_ctx);

    /* Start a transaction to look up the groups in the sysdb
     * and update them with LDAP data
     */

    subreq = sysdb_transaction_send(state, state->ev, state->sysdb);
    if (!subreq) {
        return EIO;
    }
    tevent_req_set_callback(subreq,
                            rfc2307bis_get_sysdb_groups,
                            req);
    return EOK;
}

static void rfc2307bis_update_sysdb_groups(struct tevent_req *subreq);
static void rfc2307bis_get_sysdb_groups(struct tevent_req *subreq)
{
    errno_t ret;
    const char *name;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_rfc2307bis_nested_ctx *state =
            tevent_req_data(req, struct sdap_rfc2307bis_nested_ctx);

    ret = sysdb_transaction_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    ret = sysdb_attrs_get_string(state->groups[state->group_iter],
                                 SYSDB_NAME, &name);

    ret = rfc2307bis_sysdb_member_lookup(
            state, state->ev, state->sysdb, state->handle, state->dom,
            SYSDB_MEMBER_GROUP, state->dom->name, name,
            rfc2307bis_update_sysdb_groups, req);
    if (ret != EOK) {
        tevent_req_error(req, ret);
    }
}

static void rfc2307bis_update_sysdb_groups_process(struct tevent_req *req);
static void rfc2307bis_update_sysdb_groups(struct tevent_req *subreq)
{
    errno_t ret;
    unsigned int i;
    size_t reply_count;
    struct ldb_message **replies;
    const char *name;
    TALLOC_CTX *tmp_ctx;
    const char *tmp_str;
    char **sysdb_grouplist;
    char **ldap_grouplist;
    char **add_groups;
    char **del_groups;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_rfc2307bis_nested_ctx *state =
            tevent_req_data(req, struct sdap_rfc2307bis_nested_ctx);

    ret = sysdb_search_groups_recv(subreq, state, &reply_count, &replies);
    talloc_zfree(subreq);
    if (ret != EOK && ret != ENOENT) {
        tevent_req_error(req, ret);
        return;
    } else if (ret == ENOENT) {
        reply_count = 0;
    }

    tmp_ctx = talloc_new(state);
    if (!tmp_ctx) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    ret = sysdb_attrs_get_string(state->groups[state->group_iter],
                                 SYSDB_NAME, &name);
    if (ret != EOK) goto error;

    /* Create a list of the groups in the sysdb */
    if (reply_count == 0) {
        DEBUG(6, ("Group [%s] is not a direct member of any groups\n",
                  name));
        sysdb_grouplist = NULL;
    } else {
        sysdb_grouplist = talloc_array(state, char *, reply_count+1);
        if (!sysdb_grouplist) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        for (i = 0; i < reply_count; i++) {
            tmp_str = ldb_msg_find_attr_as_string(replies[i],
                                                  SYSDB_NAME,
                                                  NULL);
            if (!tmp_str) {
                /* This should never happen, but if it
                 * does, just skip it.
                 */
                continue;
            }

            sysdb_grouplist[i] = talloc_strdup(sysdb_grouplist, tmp_str);
            if (!sysdb_grouplist[i]) {
                talloc_free(sysdb_grouplist);
                tevent_req_error(req, ENOMEM);
                return;
            }
        }
        sysdb_grouplist[reply_count] = NULL;
    }

    /* Create a list of the groups in LDAP */
    if (state->ldap_groups_count == 0) {
        /* No groups for this user in LDAP
         * We need to ensure that there are no groups
         * in the sysdb either.
         */

        ldap_grouplist = NULL;
    }
    else {
        ret = sysdb_attrs_to_list(tmp_ctx,
                                  state->ldap_groups,
                                  state->ldap_groups_count,
                                  SYSDB_NAME,
                                  &ldap_grouplist);
        if (ret != EOK) {
            goto error;
        }
    }

    /* Find the differences between the sysdb and ldap lists
     * Groups in ldap only must be added to the sysdb;
     * groups in the sysdb only must be removed.
     */
    ret = diff_string_lists(tmp_ctx,
                            ldap_grouplist, sysdb_grouplist,
                            &add_groups, &del_groups, NULL);
    if (ret != EOK) {
        goto error;
    }

    /* Since all of the groups were created by nested calls,
     * we don't need to step through sdap_add_incomplete_groups_send
     * here like we do in sdap_initgr_rfc2307_update_sysdb_groups
     *
     * We can just update the memberships and move on
     */
    subreq = sysdb_update_members_send(state, state->ev, state->handle,
                                       state->dom, name,
                                       SYSDB_MEMBER_GROUP,
                                       add_groups, del_groups);
    if (!subreq) {
        tevent_req_error(req, EIO);
        return;
    }
    talloc_steal(subreq, tmp_ctx);

    tevent_req_set_callback(subreq,
                            rfc2307bis_update_sysdb_groups_process,
                            req);

    return;

error:
    talloc_free(tmp_ctx);
    tevent_req_error(req, ret);
}
static void rfc2307bis_update_sysdb_groups_done(struct tevent_req *req);
static void rfc2307bis_update_sysdb_groups_process(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_rfc2307bis_nested_ctx *state =
            tevent_req_data(req, struct sdap_rfc2307bis_nested_ctx);

    ret = sysdb_update_members_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    /* Processing of this group is finished */
    subreq = sysdb_transaction_commit_send(state, state->ev, state->handle);
    if (!subreq) {
        tevent_req_error(req, EIO);
        return;
    }
    tevent_req_set_callback(subreq,
                            rfc2307bis_update_sysdb_groups_done,
                            req);
}

static void rfc2307bis_update_sysdb_groups_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_rfc2307bis_nested_ctx *state =
            tevent_req_data(req, struct sdap_rfc2307bis_nested_ctx);

    ret = sysdb_transaction_commit_recv(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    /* Continue processing groups at this level */
    state->group_iter++;
    if (state->group_iter < state->num_groups) {
        ret = rfc2307bis_nested_groups_step(req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
        }
        return;
    }

    /* All done in this nesting level */
    tevent_req_done(req);
}

static int sdap_initgr_rfc2307bis_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

