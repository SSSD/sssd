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
        DEBUG(7, ("User principle is not available for [%s].\n", state->name));
    } else {
        upn = talloc_strdup(user_attrs, (const char*) el->values[0].data);
        if (!upn) {
            ret = ENOMEM;
            goto fail;
        }
        if (dp_opt_get_bool(opts->basic, SDAP_FORCE_UPPER_CASE_REALM)) {
            make_realm_upper_case(upn);
        }
        DEBUG(7, ("Adding user principle [%s] to attributes of [%s].\n",
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
                                               bool store_members)
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

    if (store_members) {
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
                                  (!state->twopass));
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

    } else if (state->twopass) {

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
};

static void sdap_get_groups_process(struct tevent_req *subreq);
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

static void sdap_get_groups_process(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_groups_state *state = tevent_req_data(req,
                                            struct sdap_get_groups_state);
    int ret;

    ret = sdap_get_generic_recv(subreq, state,
                                &state->count, &state->groups);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(6, ("Search for groups, returned %d results.\n", state->count));

    if (state->count == 0) {
        tevent_req_error(req, ENOENT);
        return;
    }

    subreq = sdap_save_groups_send(state, state->ev, state->dom,
                                   state->sysdb, state->opts,
                                   state->groups, state->count);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
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


/* ==Initgr-call-(groups-a-user-is-member-of)-RFC2307-Classic/BIS========= */

struct sdap_initgr_rfc2307_state {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sdap_options *opts;
    struct sss_domain_info *dom;
    struct sdap_handle *sh;

    struct sdap_op *op;
};

static void sdap_initgr_rfc2307_process(struct tevent_req *subreq);
static void sdap_initgr_rfc2307_done(struct tevent_req *subreq);
struct tevent_req *sdap_initgr_rfc2307_send(TALLOC_CTX *memctx,
                                            struct tevent_context *ev,
                                            struct sdap_options *opts,
                                            struct sysdb_ctx *sysdb,
                                            struct sss_domain_info *dom,
                                            struct sdap_handle *sh,
                                            const char *base_dn,
                                            const char *name,
                                            const char **grp_attrs)
{
    struct tevent_req *req, *subreq;
    struct sdap_initgr_rfc2307_state *state;
    const char *filter;

    req = tevent_req_create(memctx, &state, struct sdap_initgr_rfc2307_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->sysdb = sysdb;
    state->dom = dom;
    state->sh = sh;
    state->op = NULL;

    filter = talloc_asprintf(state, "(&(%s=%s)(objectclass=%s))",
                             opts->group_map[SDAP_AT_GROUP_MEMBER].name,
                             name, opts->group_map[SDAP_OC_GROUP].name);
    if (!filter) {
        talloc_zfree(req);
        return NULL;
    }

    subreq = sdap_get_generic_send(state, state->ev, state->opts,
                                   state->sh, base_dn, LDAP_SCOPE_SUBTREE,
                                   filter, grp_attrs,
                                   state->opts->group_map, SDAP_OPTS_GROUP);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, sdap_initgr_rfc2307_process, req);

    return req;
}

static void sdap_initgr_rfc2307_process(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct sdap_initgr_rfc2307_state *state;
    struct sysdb_attrs **groups;
    size_t count;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_initgr_rfc2307_state);

    ret = sdap_get_generic_recv(subreq, state, &count, &groups);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    if (count == 0) {
        tevent_req_done(req);
        return;
    }

    subreq = sdap_save_groups_send(state, state->ev, state->dom,
                                   state->sysdb, state->opts,
                                   groups, count);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sdap_initgr_rfc2307_done, req);
}

static void sdap_initgr_rfc2307_done(struct tevent_req *subreq)
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
                                   state->groups, state->groups_cur);
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

static void sdap_get_initgr_process(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_initgr_state *state = tevent_req_data(req,
                                               struct sdap_get_initgr_state);
    int ret;

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
                                    state->name, state->grp_attrs);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sdap_get_initgr_done, req);
        break;

    case SDAP_SCHEMA_RFC2307BIS:
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

