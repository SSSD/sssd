/*
    SSSD

    Async LDAP Helper routines

    Copyright (C) Simo Sorce <ssorce@redhat.com> - 2009
    Copyright (C) 2010, Ralf Haferkamp <rhafer@suse.de>, Novell Inc.

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
#include "providers/ldap/ldap_common.h"

/* ==Save-User-Entry====================================================== */

/* FIXME: support storing additional attributes */

static int sdap_save_user(TALLOC_CTX *memctx,
                          struct sysdb_ctx *ctx,
                          struct sdap_options *opts,
                          struct sss_domain_info *dom,
                          struct sysdb_attrs *attrs,
                          const char **ldap_attrs,
                          bool is_initgr,
                          char **_usn_value)
{
    struct ldb_message_element *el;
    int ret;
    const char *name = NULL;
    const char *pwd;
    const char *gecos;
    const char *homedir;
    const char *shell;
    uid_t uid;
    gid_t gid;
    struct sysdb_attrs *user_attrs;
    char *upn = NULL;
    size_t i;
    char *val = NULL;
    int cache_timeout;
    char *usn_value = NULL;
    size_t c;
    char **missing = NULL;
    const char **aliases = NULL;
    TALLOC_CTX *tmpctx = NULL;

    DEBUG(9, ("Save user\n"));

    tmpctx = talloc_new(memctx);
    if (!tmpctx) {
        ret = ENOMEM;
        goto fail;
    }

    user_attrs = sysdb_new_attrs(tmpctx);
    if (user_attrs == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    ret = sysdb_attrs_primary_name(ctx, attrs,
                                   opts->user_map[SDAP_AT_USER_NAME].name,
                                   &name);
    if (ret != EOK) {
        DEBUG(1, ("Failed to save the user - entry has no name attribute\n"));
        goto fail;
    }

    ret = sysdb_attrs_get_el(attrs,
                             opts->user_map[SDAP_AT_USER_PWD].sys_name, &el);
    if (ret) goto fail;
    if (el->num_values == 0) pwd = NULL;
    else pwd = (const char *)el->values[0].data;

    ret = sysdb_attrs_get_el(attrs,
                             opts->user_map[SDAP_AT_USER_GECOS].sys_name, &el);
    if (ret) goto fail;
    if (el->num_values == 0) gecos = NULL;
    else gecos = (const char *)el->values[0].data;

    if (!gecos) {
        /* Fall back to the user's full name */
        ret = sysdb_attrs_get_el(
                attrs,
                opts->user_map[SDAP_AT_USER_FULLNAME].sys_name, &el);
        if (ret) goto fail;
        if (el->num_values > 0) gecos = (const char *)el->values[0].data;
    }

    ret = sysdb_attrs_get_el(attrs,
                             opts->user_map[SDAP_AT_USER_HOME].sys_name, &el);
    if (ret) goto fail;
    if (el->num_values == 0) homedir = NULL;
    else homedir = (const char *)el->values[0].data;

    ret = sysdb_attrs_get_el(attrs,
                             opts->user_map[SDAP_AT_USER_SHELL].sys_name, &el);
    if (ret) goto fail;
    if (el->num_values == 0) shell = NULL;
    else shell = (const char *)el->values[0].data;

    ret = sysdb_attrs_get_uint32_t(attrs,
                                   opts->user_map[SDAP_AT_USER_UID].sys_name,
                                   &uid);
    if (ret != EOK) {
        DEBUG(1, ("no uid provided for [%s] in domain [%s].\n",
                  name, dom->name));
        ret = EINVAL;
        goto fail;
    }

    /* check that the uid is valid for this domain */
    if (OUT_OF_ID_RANGE(uid, dom->id_min, dom->id_max)) {
            DEBUG(2, ("User [%s] filtered out! (id out of range)\n",
                      name));
        ret = EINVAL;
        goto fail;
    }

    ret = sysdb_attrs_get_uint32_t(attrs,
                                   opts->user_map[SDAP_AT_USER_GID].sys_name,
                                   &gid);
    if (ret != EOK) {
        DEBUG(1, ("no gid provided for [%s] in domain [%s].\n",
                  name, dom->name));
        ret = EINVAL;
        goto fail;
    }

    /* check that the gid is valid for this domain */
    if (OUT_OF_ID_RANGE(gid, dom->id_min, dom->id_max)) {
            DEBUG(2, ("User [%s] filtered out! (id out of range)\n",
                      name));
        ret = EINVAL;
        goto fail;
    }

    ret = sysdb_attrs_get_el(attrs, SYSDB_ORIG_DN, &el);
    if (ret) {
        goto fail;
    }
    if (el->num_values == 0) {
        DEBUG(7, ("Original DN is not available for [%s].\n", name));
    } else {
        DEBUG(7, ("Adding original DN [%s] to attributes of [%s].\n",
                  el->values[0].data, name));
        ret = sysdb_attrs_add_string(user_attrs, SYSDB_ORIG_DN,
                                     (const char *) el->values[0].data);
        if (ret) {
            goto fail;
        }
    }

    ret = sysdb_attrs_get_el(attrs, SYSDB_MEMBEROF, &el);
    if (ret) {
        goto fail;
    }
    if (el->num_values == 0) {
        DEBUG(7, ("Original memberOf is not available for [%s].\n",
                  name));
    } else {
        DEBUG(7, ("Adding original memberOf attributes to [%s].\n",
                  name));
        for (i = 0; i < el->num_values; i++) {
            ret = sysdb_attrs_add_string(user_attrs, SYSDB_ORIG_MEMBEROF,
                                         (const char *) el->values[i].data);
            if (ret) {
                goto fail;
            }
        }
    }

    ret = sysdb_attrs_get_el(attrs,
                      opts->user_map[SDAP_AT_USER_MODSTAMP].sys_name, &el);
    if (ret) {
        goto fail;
    }
    if (el->num_values == 0) {
        DEBUG(7, ("Original mod-Timestamp is not available for [%s].\n",
                  name));
    } else {
        ret = sysdb_attrs_add_string(user_attrs,
                          opts->user_map[SDAP_AT_USER_MODSTAMP].sys_name,
                          (const char*)el->values[0].data);
        if (ret) {
            goto fail;
        }
    }

    ret = sysdb_attrs_get_el(attrs,
                      opts->user_map[SDAP_AT_USER_USN].sys_name, &el);
    if (ret) {
        goto fail;
    }
    if (el->num_values == 0) {
        DEBUG(7, ("Original USN value is not available for [%s].\n",
                  name));
    } else {
        ret = sysdb_attrs_add_string(user_attrs,
                          opts->user_map[SDAP_AT_USER_USN].sys_name,
                          (const char*)el->values[0].data);
        if (ret) {
            goto fail;
        }
        usn_value = talloc_strdup(memctx, (const char*)el->values[0].data);
        if (!usn_value) {
            ret = ENOMEM;
            goto fail;
        }
    }

    ret = sysdb_attrs_get_el(attrs,
                             opts->user_map[SDAP_AT_USER_PRINC].sys_name, &el);
    if (ret) {
        goto fail;
    }
    if (el->num_values == 0) {
        DEBUG(7, ("User principal is not available for [%s].\n", name));
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
                  upn, name));
        ret = sysdb_attrs_add_string(user_attrs, SYSDB_UPN, upn);
        if (ret) {
            goto fail;
        }
    }

    for (i = SDAP_FIRST_EXTRA_USER_AT; i < SDAP_OPTS_USER; i++) {
        ret = sysdb_attrs_get_el(attrs, opts->user_map[i].sys_name, &el);
        if (ret) {
            goto fail;
        }
        if (el->num_values > 0) {
            for (c = 0; c < el->num_values; c++) {
                DEBUG(9, ("Adding [%s]=[%s] to user attributes.\n",
                          opts->user_map[i].sys_name,
                          (const char*) el->values[c].data));
                val = talloc_strdup(user_attrs, (const char*) el->values[c].data);
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

    ret = sysdb_attrs_get_aliases(tmpctx, attrs, name, &aliases);
    if (ret != EOK) {
        DEBUG(1, ("Failed to get the alias list"));
        goto fail;
    }

    for (i = 0; aliases[i]; i++) {
        ret = sysdb_attrs_add_string(user_attrs, SYSDB_NAME_ALIAS,
                                     aliases[i]);
        if (ret) {
            goto fail;
        }
    }

    /* Make sure that any attributes we requested from LDAP that we
     * did not receive are also removed from the sysdb
     */
    ret = list_missing_attrs(user_attrs, opts->user_map, SDAP_OPTS_USER,
                             ldap_attrs, attrs, &missing);
    if (ret != EOK) {
        goto fail;
    }

    /* Remove missing attributes */
    if (missing && !missing[0]) {
        /* Nothing to remove */
        talloc_zfree(missing);
    }

    DEBUG(6, ("Storing info for user %s\n", name));

    ret = sysdb_store_user(user_attrs, ctx, dom,
                           name, pwd, uid, gid, gecos, homedir, shell,
                           user_attrs, missing, cache_timeout);
    if (ret) goto fail;

    if (_usn_value) {
        *_usn_value = usn_value;
    }

    talloc_steal(memctx, user_attrs);
    talloc_free(tmpctx);
    return EOK;

fail:
    DEBUG(2, ("Failed to save user [%s]\n",
              name ? name : "Unknown"));
    talloc_free(tmpctx);
    return ret;
}


/* ==Generic-Function-to-save-multiple-users============================= */

static int sdap_save_users(TALLOC_CTX *memctx,
                           struct sysdb_ctx *sysdb,
                           const char **attrs,
                           struct sss_domain_info *dom,
                           struct sdap_options *opts,
                           struct sysdb_attrs **users,
                           int num_users,
                           char **_usn_value)
{
    TALLOC_CTX *tmpctx;
    char *higher_usn = NULL;
    char *usn_value;
    int ret;
    int i;

    if (num_users == 0) {
        /* Nothing to do if there are no users */
        return EOK;
    }

    tmpctx = talloc_new(memctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret) {
        goto done;
    }

    for (i = 0; i < num_users; i++) {
        usn_value = NULL;

        ret = sdap_save_user(tmpctx, sysdb, opts, dom,
                             users[i], attrs, false,
                             &usn_value);

        /* Do not fail completely on errors.
         * Just report the failure to save and go on */
        if (ret) {
            DEBUG(2, ("Failed to store user %d. Ignoring.\n", i));
        } else {
            DEBUG(9, ("User %d processed!\n", i));
        }

        ret = sdap_check_aliases(sysdb, users[i], dom,
                                 opts, true);
        if (ret) {
            DEBUG(2, ("Failed to check aliases for user %d. Ignoring.\n", i));
        }

        if (usn_value) {
            if (higher_usn) {
                if ((strlen(usn_value) > strlen(higher_usn)) ||
                    (strcmp(usn_value, higher_usn) > 0)) {
                    talloc_zfree(higher_usn);
                    higher_usn = usn_value;
                } else {
                    talloc_zfree(usn_value);
                }
            } else {
                higher_usn = usn_value;
            }
        }
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret) {
        DEBUG(1, ("Failed to commit transaction!\n"));
        goto done;
    }

    if (_usn_value) {
        *_usn_value = talloc_steal(memctx, higher_usn);
    }

done:
    talloc_zfree(tmpctx);
    return ret;
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

    char *higher_usn;
    struct sysdb_attrs **users;
    size_t count;
};

static void sdap_get_users_process(struct tevent_req *subreq);

struct tevent_req *sdap_get_users_send(TALLOC_CTX *memctx,
                                       struct tevent_context *ev,
                                       struct sss_domain_info *dom,
                                       struct sysdb_ctx *sysdb,
                                       struct sdap_options *opts,
                                       struct sdap_handle *sh,
                                       const char **attrs,
                                       const char *filter,
                                       int timeout)
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
    state->higher_usn = NULL;
    state->users =  NULL;
    state->count = 0;

    subreq = sdap_get_generic_send(state, state->ev, state->opts, state->sh,
                                   dp_opt_get_string(state->opts->basic,
                                                     SDAP_USER_SEARCH_BASE),
                                   LDAP_SCOPE_SUBTREE,
                                   state->filter, state->attrs,
                                   state->opts->user_map, SDAP_OPTS_USER,
                                   timeout);
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

    ret = sdap_save_users(state, state->sysdb,
                          state->attrs,
                          state->dom, state->opts,
                          state->users, state->count,
                          &state->higher_usn);
    if (ret) {
        DEBUG(2, ("Failed to store users.\n"));
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(9, ("Saving %d Users - Done\n", state->count));

    tevent_req_done(req);
}

int sdap_get_users_recv(struct tevent_req *req,
                        TALLOC_CTX *mem_ctx, char **usn_value)
{
    struct sdap_get_users_state *state = tevent_req_data(req,
                                            struct sdap_get_users_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (usn_value) {
        *usn_value = talloc_steal(mem_ctx, state->higher_usn);
    }

    return EOK;
}

/* ==Group-Parsing Routines=============================================== */

static int sdap_find_entry_by_origDN(TALLOC_CTX *memctx,
                                     struct sysdb_ctx *ctx,
                                     struct sss_domain_info *domain,
                                     const char *orig_dn,
                                     char **localdn)
{
    TALLOC_CTX *tmpctx;
    const char *no_attrs[] = { NULL };
    struct ldb_dn *base_dn;
    char *filter;
    struct ldb_message **msgs;
    size_t num_msgs;
    int ret;
    char *sanitized_dn;

    tmpctx = talloc_new(NULL);
    if (!tmpctx) {
        return ENOMEM;
    }

    ret = sss_filter_sanitize(tmpctx, orig_dn, &sanitized_dn);
    if (ret != EOK) {
        ret = ENOMEM;
        goto done;
    }

    filter = talloc_asprintf(tmpctx, "%s=%s", SYSDB_ORIG_DN, sanitized_dn);
    if (!filter) {
        ret = ENOMEM;
        goto done;
    }

    base_dn = sysdb_domain_dn(ctx, tmpctx, domain->name);
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(9, ("Searching cache for [%s].\n", sanitized_dn));
    ret = sysdb_search_entry(tmpctx, ctx,
                             base_dn, LDB_SCOPE_SUBTREE, filter, no_attrs,
                             &num_msgs, &msgs);
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
    talloc_zfree(tmpctx);
    return ret;
}

static int sdap_fill_memberships(struct sysdb_attrs *group_attrs,
                                 struct sysdb_ctx *ctx,
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
            ret = sdap_find_entry_by_origDN(el->values, ctx, domain,
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

    /* FIXME: support non legacy */
    /* FIXME: support storing additional attributes */

static errno_t
sdap_store_group_with_gid(TALLOC_CTX *mem_ctx,
                          struct sysdb_ctx *ctx,
                          struct sss_domain_info *domain,
                          const char *name,
                          gid_t gid,
                          struct sysdb_attrs *group_attrs,
                          uint64_t cache_timeout,
                          bool posix_group)
{
    errno_t ret;

    /* make sure that non-posix (empty or explicit gid=0) groups have the
     * gidNumber set to zero even if updating existing group */
    if (!posix_group) {
        ret = sysdb_attrs_add_uint32(group_attrs, SYSDB_GIDNUM, 0);
        if (ret) {
            DEBUG(2, ("Could not set explicit GID 0 for %s\n", name));
            return ret;
        }
    }

    ret = sysdb_store_group(mem_ctx, ctx, domain,
                            name, gid, group_attrs,
                            cache_timeout);
    if (ret) {
        DEBUG(2, ("Could not store group %s\n", name));
        return ret;
    }

    return ret;
}

static int sdap_save_group(TALLOC_CTX *memctx,
                           struct sysdb_ctx *ctx,
                           struct sdap_options *opts,
                           struct sss_domain_info *dom,
                           struct sysdb_attrs *attrs,
                           bool store_members,
                           bool populate_members,
                           char **_usn_value)
{
    struct ldb_message_element *el;
    struct sysdb_attrs *group_attrs;
    const char *name = NULL;
    gid_t gid;
    int ret;
    int i;
    char *usn_value = NULL;
    TALLOC_CTX *tmpctx = NULL;
    bool posix_group;
    const char **aliases = NULL;

    tmpctx = talloc_new(memctx);
    if (!tmpctx) {
        ret = ENOMEM;
        goto fail;
    }

    group_attrs = sysdb_new_attrs(tmpctx);
    if (group_attrs == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    ret = sysdb_attrs_primary_name(ctx, attrs,
                                   opts->group_map[SDAP_AT_GROUP_NAME].name,
                                   &name);
    if (ret != EOK) {
        DEBUG(1, ("Failed to save the group - entry has no name attribute\n"));
        goto fail;
    }

    ret = sysdb_attrs_get_bool(attrs, SYSDB_POSIX, &posix_group);
    if (ret == ENOENT) {
        posix_group = true;
    } else if (ret != EOK) {
        goto fail;
    }

    DEBUG(8, ("This is%s a posix group\n", (posix_group)?"":" not"));
    ret = sysdb_attrs_add_bool(group_attrs, SYSDB_POSIX, posix_group);
    if (ret != EOK) {
        goto fail;
    }

    ret = sysdb_attrs_get_uint32_t(attrs,
                                   opts->group_map[SDAP_AT_GROUP_GID].sys_name,
                                   &gid);
    if (ret != EOK) {
        DEBUG(1, ("no gid provided for [%s] in domain [%s].\n",
                  name, dom->name));
        ret = EINVAL;
        goto fail;
    }

    /* check that the gid is valid for this domain */
    if (posix_group) {
        if (OUT_OF_ID_RANGE(gid, dom->id_min, dom->id_max)) {
            DEBUG(2, ("Group [%s] filtered out! (id out of range)\n",
                      name));
            ret = EINVAL;
            goto fail;
        }
        /* Group ID OK */
    }

    ret = sysdb_attrs_get_el(attrs, SYSDB_ORIG_DN, &el);
    if (ret) {
        goto fail;
    }
    if (el->num_values == 0) {
        DEBUG(7, ("Original DN is not available for [%s].\n", name));
    } else {
        DEBUG(7, ("Adding original DN [%s] to attributes of [%s].\n",
                  el->values[0].data, name));
        ret = sysdb_attrs_add_string(group_attrs, SYSDB_ORIG_DN,
                                     (const char *) el->values[0].data);
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
                  name));
    } else {
        ret = sysdb_attrs_add_string(group_attrs,
                          opts->group_map[SDAP_AT_GROUP_MODSTAMP].sys_name,
                          (const char*)el->values[0].data);
        if (ret) {
            goto fail;
        }
    }

    ret = sysdb_attrs_get_el(attrs,
                      opts->group_map[SDAP_AT_GROUP_USN].sys_name, &el);
    if (ret) {
        goto fail;
    }
    if (el->num_values == 0) {
        DEBUG(7, ("Original USN value is not available for [%s].\n",
                  name));
    } else {
        ret = sysdb_attrs_add_string(group_attrs,
                          opts->group_map[SDAP_AT_GROUP_USN].sys_name,
                          (const char*)el->values[0].data);
        if (ret) {
            goto fail;
        }
        usn_value = talloc_strdup(tmpctx, (const char*)el->values[0].data);
        if (!usn_value) {
            ret = ENOMEM;
            goto fail;
        }
    }

    if (populate_members) {
        struct ldb_message_element *el1;
        ret = sysdb_attrs_get_el(attrs, opts->group_map[SDAP_AT_GROUP_MEMBER].sys_name, &el1);
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
            DEBUG(7, ("No members for group [%s]\n", name));

        } else {
            DEBUG(7, ("Adding member users to group [%s]\n", name));

            ret = sdap_fill_memberships(group_attrs, ctx, opts, dom,
                                        el->values, el->num_values);
            if (ret) {
                goto fail;
            }
        }
    }

    ret = sysdb_attrs_get_aliases(tmpctx, attrs, name, &aliases);
    if (ret != EOK) {
        DEBUG(1, ("Failed to get the alias list\n"));
        goto fail;
    }

    for (i = 0; aliases[i]; i++) {
        ret = sysdb_attrs_add_string(group_attrs, SYSDB_NAME_ALIAS,
                                        aliases[i]);
        if (ret) {
            goto fail;
        }
    }

    DEBUG(6, ("Storing info for group %s\n", name));

    ret = sdap_store_group_with_gid(group_attrs, ctx, dom,
                                    name, gid, group_attrs,
                                    dp_opt_get_int(opts->basic,
                                                   SDAP_ENTRY_CACHE_TIMEOUT),
                                    posix_group);
    if (ret) goto fail;

    if (_usn_value) {
        *_usn_value = talloc_steal(memctx, usn_value);
    }

    talloc_steal(memctx, group_attrs);
    talloc_free(tmpctx);
    return EOK;

fail:
    DEBUG(2, ("Failed to save group [%s]\n",
              name ? name : "Unknown"));
    talloc_free(tmpctx);
    return ret;
}


/* ==Save-Group-Memebrs=================================================== */

    /* FIXME: support non legacy */
    /* FIXME: support storing additional attributes */

static int sdap_save_grpmem(TALLOC_CTX *memctx,
                            struct sysdb_ctx *ctx,
                            struct sdap_options *opts,
                            struct sss_domain_info *dom,
                            struct sysdb_attrs *attrs)
{
    struct ldb_message_element *el;
    struct sysdb_attrs *group_attrs = NULL;
    const char *name;
    int ret;

    ret = sysdb_attrs_primary_name(ctx, attrs,
                                   opts->group_map[SDAP_AT_GROUP_NAME].name,
                                   &name);
    if (ret != EOK) {
        goto fail;
    }

    ret = sysdb_attrs_get_el(attrs,
                    opts->group_map[SDAP_AT_GROUP_MEMBER].sys_name, &el);
    if (ret != EOK) {
        goto fail;
    }
    if (el->num_values == 0) {
        DEBUG(7, ("No members for group [%s]\n", name));

    } else {
        DEBUG(7, ("Adding member users to group [%s]\n", name));

        group_attrs = sysdb_new_attrs(memctx);
        if (!group_attrs) {
            ret = ENOMEM;
            goto fail;
        }

        ret = sdap_fill_memberships(group_attrs, ctx, opts, dom,
                                    el->values, el->num_values);
        if (ret) {
            goto fail;
        }
    }

    DEBUG(6, ("Storing members for group %s\n", name));

    ret = sysdb_store_group(memctx, ctx, dom,
                            name, 0, group_attrs,
                            dp_opt_get_int(opts->basic,
                                           SDAP_ENTRY_CACHE_TIMEOUT));
    if (ret) goto fail;

    return EOK;

fail:
    DEBUG(2, ("Failed to save user %s\n", name));
    return ret;
}


/* ==Generic-Function-to-save-multiple-groups============================= */

static int sdap_save_groups(TALLOC_CTX *memctx,
                            struct sysdb_ctx *sysdb,
                            struct sss_domain_info *dom,
                            struct sdap_options *opts,
                            struct sysdb_attrs **groups,
                            int num_groups,
                            bool populate_members,
                            char **_usn_value)
{
    TALLOC_CTX *tmpctx;
    char *higher_usn = NULL;
    char *usn_value;
    bool twopass;
    int ret;
    int i;
    struct sysdb_attrs **saved_groups = NULL;
    int nsaved_groups = 0;

    switch (opts->schema_type) {
    case SDAP_SCHEMA_RFC2307:
        twopass = false;
        break;

    case SDAP_SCHEMA_RFC2307BIS:
    case SDAP_SCHEMA_IPA_V1:
    case SDAP_SCHEMA_AD:
        twopass = true;
        break;

    default:
        return EINVAL;
    }

    tmpctx = talloc_new(memctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret) {
        goto done;
    }

    if (twopass && !populate_members) {
        saved_groups = talloc_array(tmpctx, struct sysdb_attrs *,
                                    num_groups);
        if (!saved_groups) {
            ret = ENOMEM;
            goto done;
        }
    }

    for (i = 0; i < num_groups; i++) {
        usn_value = NULL;

        /* if 2 pass savemembers = false */
        ret = sdap_save_group(tmpctx, sysdb,
                              opts, dom, groups[i],
                              (!twopass), populate_members, &usn_value);

        /* Do not fail completely on errors.
         * Just report the failure to save and go on */
        if (ret) {
            DEBUG(2, ("Failed to store group %d. Ignoring.\n", i));
        } else {
            DEBUG(9, ("Group %d processed!\n", i));
            if (twopass && !populate_members) {
                saved_groups[nsaved_groups] = groups[i];
                nsaved_groups++;
            }
        }

        if (usn_value) {
            if (higher_usn) {
                if ((strlen(usn_value) > strlen(higher_usn)) ||
                    (strcmp(usn_value, higher_usn) > 0)) {
                    talloc_zfree(higher_usn);
                    higher_usn = usn_value;
                } else {
                    talloc_zfree(usn_value);
                }
            } else {
                higher_usn = usn_value;
            }
        }
    }

    if (twopass && !populate_members) {

        for (i = 0; i < nsaved_groups; i++) {

            ret = sdap_save_grpmem(tmpctx, sysdb, opts, dom, saved_groups[i]);
            /* Do not fail completely on errors.
             * Just report the failure to save and go on */
            if (ret) {
                DEBUG(2, ("Failed to store group %d members.\n", i));
            } else {
                DEBUG(9, ("Group %d members processed!\n", i));
            }
        }
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret) {
        DEBUG(1, ("Failed to commit transaction!\n"));
        goto done;
    }

    if (_usn_value) {
        *_usn_value = talloc_steal(memctx, higher_usn);
    }

done:
    talloc_zfree(tmpctx);
    return ret;
}


/* ==Process-Groups======================================================= */

struct sdap_process_group_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;
    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;

    struct sysdb_attrs *group;
    struct sysdb_attrs **new_members;
    struct ldb_message_element* sysdb_dns;
    char **queued_members;
    int queue_len;
    const char **attrs;
    const char *filter;
    size_t member_idx;
    size_t queue_idx;
    size_t count;
    size_t check_count;

    bool enumeration;
};

#define GROUPMEMBER_REQ_PARALLEL 50
static void sdap_process_group_members(struct tevent_req *subreq);

static int sdap_process_group_members_2307bis(struct tevent_req *req,
                                   struct sdap_process_group_state *state,
                                   struct ldb_message_element *memberel);
static int sdap_process_group_members_2307(struct sdap_process_group_state *state,
                                   struct ldb_message_element *memberel);

struct tevent_req *sdap_process_group_send(TALLOC_CTX *memctx,
                                           struct tevent_context *ev,
                                           struct sss_domain_info *dom,
                                           struct sysdb_ctx *sysdb,
                                           struct sdap_options *opts,
                                           struct sdap_handle *sh,
                                           struct sysdb_attrs *group,
                                           bool enumeration)
{
    struct ldb_message_element *el;
    struct sdap_process_group_state *grp_state;
    struct tevent_req *req = NULL;
    const char **attrs;
    char* filter;
    int ret;

    req = tevent_req_create(memctx, &grp_state,
                            struct sdap_process_group_state);
    if (!req) return NULL;

    ret = build_attrs_from_map(grp_state, opts->user_map, SDAP_OPTS_USER, &attrs);
    if (ret) {
        goto done;
    }

    /* FIXME: we ignore nested rfc2307bis groups for now */
    filter = talloc_asprintf(grp_state, "(objectclass=%s)",
                             opts->user_map[SDAP_OC_USER].name);
    if (!filter) {
        talloc_zfree(req);
        return NULL;
    }

    grp_state->ev = ev;
    grp_state->opts = opts;
    grp_state->dom = dom;
    grp_state->sh = sh;
    grp_state->sysdb = sysdb;
    grp_state->group =  group;
    grp_state->check_count = 0;
    grp_state->new_members = NULL;
    grp_state->member_idx = 0;
    grp_state->queue_idx = 0;
    grp_state->queued_members = NULL;
    grp_state->queue_len = 0;
    grp_state->filter = filter;
    grp_state->attrs = attrs;
    grp_state->enumeration = enumeration;

    ret = sysdb_attrs_get_el(group,
                             opts->group_map[SDAP_AT_GROUP_MEMBER].sys_name,
                             &el);
    if (ret) {
        goto done;
    }

    /* Group without members */
    if (el->num_values == 0) {
        DEBUG(2, ("No Members. Done!\n"));
        ret = EOK;
        goto done;
    }

    grp_state->sysdb_dns = talloc(grp_state, struct ldb_message_element);
    if (!grp_state->sysdb_dns) {
        talloc_zfree(req);
        return NULL;
    }
    grp_state->sysdb_dns->values = talloc_array(grp_state, struct ldb_val,
                                                el->num_values);
    if (!grp_state->sysdb_dns->values) {
        talloc_zfree(req);
        return NULL;
    }
    grp_state->sysdb_dns->num_values = 0;

    switch (opts->schema_type) {
        case SDAP_SCHEMA_RFC2307:
            ret = sdap_process_group_members_2307(grp_state, el);
            break;

        case SDAP_SCHEMA_IPA_V1:
        case SDAP_SCHEMA_AD:
        case SDAP_SCHEMA_RFC2307BIS:
            ret = sdap_process_group_members_2307bis(req, grp_state, el);
            break;

        default:
            DEBUG(1, ("Unknown schema type %d\n", opts->schema_type));
            ret = EINVAL;
            break;
    }

done:
    /* We managed to process all the entries */
    /* EBUSY means we need to wait for entries in LDAP */
    if (ret == EOK) {
        DEBUG(7, ("All group members processed\n"));
        tevent_req_done(req);
        tevent_req_post(req, ev);
    }

    if (ret != EOK && ret != EBUSY) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }
    return req;
}

static int
sdap_process_missing_member_2307bis(struct tevent_req *req,
                                    char *user_dn,
                                    int num_users);

static int
sdap_add_group_member_2307(struct sdap_process_group_state *state,
                           const char *username);

static int
sdap_process_group_members_2307bis(struct tevent_req *req,
                                   struct sdap_process_group_state *state,
                                   struct ldb_message_element *memberel)
{
    char *member_dn;
    char *strdn;
    int ret;
    int i;

    for (i=0; i < memberel->num_values; i++) {
        member_dn = (char *)memberel->values[i].data;

        ret = sdap_find_entry_by_origDN(state->sysdb_dns->values,
                                        state->sysdb,
                                        state->dom,
                                        member_dn,
                                        &strdn);
        if (ret == EOK) {
            /*
             * User already cached in sysdb. Remember the sysdb DN for later
             * use by sdap_save_groups()
             */
            DEBUG(7, ("sysdbdn: %s\n", strdn));
            state->sysdb_dns->values[state->sysdb_dns->num_values].data =
                (uint8_t*) strdn;
            state->sysdb_dns->values[state->sysdb_dns->num_values].length =
                strlen(strdn);
            state->sysdb_dns->num_values++;
        } else if (ret == ENOENT) {
            if (!state->enumeration) {
                /* The user is not in sysdb, need to add it
                 * We don't need to do this if we're in an enumeration,
                 * because all real members should all be populated
                 * already by the first pass of the enumeration.
                 * Also, we don't want to be holding the sysdb
                 * transaction while we're performing LDAP lookups.
                 */
                DEBUG(7, ("Searching LDAP for missing user entry\n"));
                ret = sdap_process_missing_member_2307bis(req,
                                                          member_dn,
                                                          memberel->num_values);
                if (ret != EOK) {
                    DEBUG(1, ("Error processing missing member #%d (%s):\n",
                              i, member_dn));
                    return ret;
                }
            }
        } else {
            DEBUG(1, ("Error checking cache for member #%d (%s):\n",
                       i, (char *)memberel->values[i].data));
            return ret;
        }
    }

    if (state->queue_len > 0) {
        state->queued_members[state->queue_len]=NULL;
    }

    if (state->check_count == 0) {
        /*
         * All group members are already cached in sysdb, we are done
         * with this group. To avoid redundant sysdb lookups, populate the
         * "member" attribute of the group entry with the sysdb DNs of
         * the members.
         */
        ret = EOK;
        memberel->values = talloc_steal(state->group, state->sysdb_dns->values);
        memberel->num_values = state->sysdb_dns->num_values;
    } else {
        state->count = state->check_count;
        state->new_members = talloc_zero_array(state,
                struct sysdb_attrs *,
                state->count + 1);
        if (!state->new_members) {
            return ENOMEM;
        }
        ret = EBUSY;
    }

    return ret;
}

static int
sdap_process_missing_member_2307(struct sdap_process_group_state *state,
                                 char *username, bool *in_transaction);

static int
sdap_process_group_members_2307(struct sdap_process_group_state *state,
                                struct ldb_message_element *memberel)
{
    struct ldb_message *msg;
    bool in_transaction = false;
    char *member_name;
    int ret;
    errno_t sret;
    int i;

    for (i=0; i < memberel->num_values; i++) {
        member_name = (char *)memberel->values[i].data;

        /* We need to skip over zero-length usernames */
        if (member_name[0] == '\0') continue;

        ret = sysdb_search_user_by_name(state, state->sysdb,
                                        state->dom, member_name,
                                        NULL, &msg);
        if (ret == EOK) {
            /*
             * User already cached in sysdb. Remember the sysdb DN for later
             * use by sdap_save_groups()
             */
            DEBUG(7, ("Member already cached in sysdb: %s\n", member_name));

            ret = sdap_add_group_member_2307(state, member_name);
            if (ret != EOK) {
                DEBUG(1, ("Could not add member %s into sysdb\n", member_name));
                goto done;
            }
        } else if (ret == ENOENT) {
            /* The user is not in sysdb, need to add it */
            DEBUG(7, ("member #%d (%s): not found in sysdb\n",
                       i, member_name));

            ret = sdap_process_missing_member_2307(state, member_name,
                                                   &in_transaction);
            if (ret != EOK) {
                DEBUG(1, ("Error processing missing member #%d (%s):\n",
                          i, member_name));
                goto done;
            }
        } else {
            DEBUG(1, ("Error checking cache for member #%d (%s):\n",
                       i, (char *) memberel->values[i].data));
            goto done;
        }
    }

    /* sdap_process_missing_member_2307 starts transaction */
    if (in_transaction) {
        ret = sysdb_transaction_commit(state->sysdb);
        if (ret) {
            DEBUG(2, ("Cannot commit sysdb transaction\n"));
            goto done;
        }
        in_transaction = false;
    }

    ret = EOK;
    memberel->values = talloc_steal(state->group, state->sysdb_dns->values);
    memberel->num_values = state->sysdb_dns->num_values;

done:
    if (in_transaction) {
        /* If the transaction is still active here, we need to cancel it */
        sret = sysdb_transaction_cancel(state->sysdb);
        if (sret != EOK) {
            DEBUG(0, ("Unable to cancel transaction! [%d][%s]\n",
                      sret, strerror(sret)));
        }
    }
    return ret;
}


static int
sdap_process_missing_member_2307bis(struct tevent_req *req,
                                    char *user_dn,
                                    int num_users)
{
    struct sdap_process_group_state *grp_state =
        tevent_req_data(req, struct sdap_process_group_state);
    struct tevent_req *subreq;

    /*
     * Issue at most GROUPMEMBER_REQ_PARALLEL LDAP searches at once.
     * The rest is sent while the results are being processed.
     * We limit the number as of request here, as the Server might
     * enforce limits on the number of pending operations per
     * connection.
     */
    if (grp_state->check_count > GROUPMEMBER_REQ_PARALLEL) {
        DEBUG(7, (" queueing search for: %s\n", user_dn));
        if (!grp_state->queued_members) {
            DEBUG(7, ("Allocating queue for %d members\n",
                      num_users - grp_state->check_count));

            grp_state->queued_members = talloc_array(grp_state, char *,
                    num_users - grp_state->check_count + 1);
            if (!grp_state->queued_members) {
                return ENOMEM;
            }
        }
        grp_state->queued_members[grp_state->queue_len] = user_dn;
        grp_state->queue_len++;
    } else {
        subreq = sdap_get_generic_send(grp_state,
                                       grp_state->ev,
                                       grp_state->opts,
                                       grp_state->sh,
                                       user_dn,
                                       LDAP_SCOPE_BASE,
                                       grp_state->filter,
                                       grp_state->attrs,
                                       grp_state->opts->user_map,
                                       SDAP_OPTS_USER,
                                       dp_opt_get_int(grp_state->opts->basic,
                                                      SDAP_SEARCH_TIMEOUT));
        if (!subreq) {
            return ENOMEM;
        }
        tevent_req_set_callback(subreq, sdap_process_group_members, req);
    }

    grp_state->check_count++;
    return EOK;
}

static int
sdap_add_group_member_2307(struct sdap_process_group_state *state,
                           const char *username)
{
    char *strdn;

    strdn = sysdb_user_strdn(state->sysdb_dns->values,
                             state->dom->name, username);
    if (!strdn) {
        return ENOMEM;
    }

    state->sysdb_dns->values[state->sysdb_dns->num_values].data =
            (uint8_t *) strdn;
    state->sysdb_dns->values[state->sysdb_dns->num_values].length =
            strlen(strdn);
    state->sysdb_dns->num_values++;

    return EOK;
}

static int
sdap_process_missing_member_2307(struct sdap_process_group_state *state,
                                 char *member_name, bool *in_transaction)
{
    int ret, sret;
    TALLOC_CTX *tmp_ctx;
    const char *filter;
    const char *username;
    size_t count;
    struct ldb_message **msgs = NULL;
    static const char *attrs[] = { SYSDB_NAME, NULL };

    if (!in_transaction) return EINVAL;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    /* Check for the alias in the sysdb */
    filter = talloc_asprintf(tmp_ctx, "(%s=%s)", SYSDB_NAME_ALIAS, member_name);
    if (!filter) {
        ret = ENOMEM;
        goto fail;
    }

    ret = sysdb_search_users(tmp_ctx, state->sysdb, state->dom,
                             filter, attrs, &count, &msgs);
    if (ret == EOK && count > 0) {
        /* Entry exists but the group references it with an alias. */

        if (count != 1) {
            DEBUG(1, ("More than one entry with this alias?\n"));
            ret = EIO;
            goto fail;
        }

        /* fill username with primary name */
        username = ldb_msg_find_attr_as_string(msgs[0], SYSDB_NAME, NULL);
        goto done;
    } else if (ret != EOK && ret != ENOENT) {
        ret = EIO;
        goto fail;
    }

    username = member_name;
    /* The entry really does not exist, add a fake entry */
    DEBUG(7, ("Adding a dummy entry\n"));

    if (!*in_transaction) {
        ret = sysdb_transaction_start(state->sysdb);
        if (ret != EOK) {
            DEBUG(1, ("Cannot start sysdb transaction: [%d]: %s\n",
                       ret, strerror(ret)));
            return ret;
        }
        *in_transaction = true;
    }

    ret = sysdb_add_fake_user(state->sysdb, state->dom, username);
    if (ret != EOK) {
        DEBUG(1, ("Cannot store fake user entry: [%d]: %s\n",
                  ret, strerror(ret)));
        goto fail;
    }

    /*
     * Convert the just received DN into the corresponding sysdb DN
     * for saving into member attribute of the group
     */
done:
    ret = sdap_add_group_member_2307(state, username);
    if (ret != EOK) {
        DEBUG(1, ("Could not add group member %s\n", username));
        goto fail;
    }

    talloc_free(tmp_ctx);
    return EOK;
fail:
    talloc_free(tmp_ctx);
    if (*in_transaction) {
        sret = sysdb_transaction_cancel(state->sysdb);
        if (sret == EOK) {
            *in_transaction = false;
        } else {
            DEBUG(0, ("Unable to cancel transaction! [%d][%s]\n",
                       sret, strerror(sret)));
        }
    }
    return ret;
}

static void sdap_process_group_members(struct tevent_req *subreq)
{
    struct sysdb_attrs **usr_attrs;
    size_t count;
    int ret;
    struct tevent_req *req =
                        tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_process_group_state *state =
                        tevent_req_data(req, struct sdap_process_group_state);
    struct ldb_message_element *el;
    struct ldb_dn *dn;
    char* dn_string;

    state->check_count--;
    DEBUG(9, ("Members remaining: %d\n", state->check_count));

    ret = sdap_get_generic_recv(subreq, state, &count, &usr_attrs);
    talloc_zfree(subreq);
    if (ret) {
        goto next;
    }
    if (count != 1) {
        ret = EINVAL;
        DEBUG(7, ("Expected one user entry and got %d\n", count));
        goto next;
    }
    ret = sysdb_attrs_get_el(usr_attrs[0],
            state->opts->user_map[SDAP_AT_USER_NAME].sys_name, &el);
    if (el->num_values == 0) {
        ret = EINVAL;
    }
    if (ret) {
        DEBUG(2, ("Failed to get the member's name\n"));
        goto next;
    }

    /*
     * Convert the just received DN into the corresponding sysdb DN
     * for later usage by sdap_save_groups()
     */
    dn = sysdb_user_dn(state->sysdb, state, state->dom->name,
                       (char*)el[0].values[0].data);
    if (!dn) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    dn_string = ldb_dn_alloc_linearized(state->group, dn);
    if (!dn_string) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    state->sysdb_dns->values[state->sysdb_dns->num_values].data =
            (uint8_t*)dn_string;
    state->sysdb_dns->values[state->sysdb_dns->num_values].length =
            strlen(dn_string);
    state->sysdb_dns->num_values++;

    state->new_members[state->member_idx] = usr_attrs[0];
    state->member_idx++;

next:
    if (ret) {
        DEBUG(7, ("Error reading group member. Skipping\n", ret));
        state->count--;
    }
    /* Are there more searches for uncached users to submit ? */
    if (state->queued_members && state->queued_members[state->queue_idx]) {
        subreq = sdap_get_generic_send(state,
                                       state->ev, state->opts, state->sh,
                                       state->queued_members[state->queue_idx],
                                       LDAP_SCOPE_BASE,
                                       state->filter,
                                       state->attrs,
                                       state->opts->user_map,
                                       SDAP_OPTS_USER,
                                       dp_opt_get_int(state->opts->basic,
                                                      SDAP_SEARCH_TIMEOUT));
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        tevent_req_set_callback(subreq,
                                sdap_process_group_members, req);
        state->queue_idx++;
    }

    if (state->check_count == 0) {
        ret = sdap_save_users(state, state->sysdb, state->attrs,
                              state->dom, state->opts,
                              state->new_members, state->count, NULL);
        if (ret) {
            DEBUG(2, ("Failed to store users.\n"));
            tevent_req_error(req, ret);
            return;
        }

        /*
         * To avoid redundant sysdb lookups, populate the "member" attribute
         * of the group entry with the sysdb DNs of the members.
         */
        ret = sysdb_attrs_get_el(state->group,
                state->opts->group_map[SDAP_AT_GROUP_MEMBER].sys_name, &el);
        el->values = talloc_steal(state->group, state->sysdb_dns->values);
        el->num_values = state->sysdb_dns->num_values;
        DEBUG(9, ("Processed Group - Done\n"));
        tevent_req_done(req);
    }
}

static int sdap_process_group_recv(struct tevent_req *req)
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

    char *higher_usn;
    struct sysdb_attrs **groups;
    size_t count;
    size_t check_count;

    hash_table_t *user_hash;
    hash_table_t *group_hash;
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
                                       const char *filter,
                                       int timeout)
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
    state->higher_usn = NULL;
    state->groups =  NULL;
    state->count = 0;

    subreq = sdap_get_generic_send(state, state->ev, state->opts, state->sh,
                                   dp_opt_get_string(state->opts->basic,
                                                     SDAP_GROUP_SEARCH_BASE),
                                   LDAP_SCOPE_SUBTREE,
                                   state->filter, state->attrs,
                                   state->opts->group_map, SDAP_OPTS_GROUP,
                                   timeout);
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
    struct tevent_req *req =
                        tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_get_groups_state *state =
                        tevent_req_data(req, struct sdap_get_groups_state);
    int ret;
    int i;
    bool enumeration = false;

    ret = sdap_get_generic_recv(subreq, state,
                                &state->count, &state->groups);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(6, ("Search for groups, returned %d results.\n", state->count));

    switch(state->count) {
    case 0:
        tevent_req_error(req, ENOENT);
        return;

    case 1:
        /* Single group search */
        if ((state->opts->schema_type == SDAP_SCHEMA_RFC2307) ||
            (dp_opt_get_int(state->opts->basic, SDAP_NESTING_LEVEL) == 0)) {
            /* Either this is RFC2307 or we have disabled nested group
             * support for RFC2307bis. Either way, we'll process the
             * groups in single-level, multiple-request mode.
             */
            break;
        }

        /* Prepare hashes for nested user processing */
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

    default:
        /* Enumeration */
        enumeration = true;
        break;
    }

    state->check_count = state->count;

    ret = sysdb_transaction_start(state->sysdb);
    if (ret != EOK) {
        DEBUG(0, ("Failed to start transaction\n"));
        tevent_req_error(req, ret);
        return;
    }

    if (enumeration && (state->opts->schema_type != SDAP_SCHEMA_RFC2307) &&
        (dp_opt_get_int(state->opts->basic, SDAP_NESTING_LEVEL) != 0)) {

        DEBUG(9, ("Saving groups without members first "
                  "to allow unrolling of nested groups.\n"));
        ret = sdap_save_groups(state, state->sysdb, state->dom, state->opts,
                               state->groups, state->count, false, NULL);
        if (ret) {
            DEBUG(2, ("Failed to store groups.\n"));
            tevent_req_error(req, ret);
            return;
        }
    }

    for (i = 0; i < state->count; i++) {
        subreq = sdap_process_group_send(state, state->ev, state->dom,
                                         state->sysdb, state->opts,
                                         state->sh, state->groups[i],
                                         enumeration);

        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sdap_get_groups_done, req);
    }
}

static void sdap_get_groups_done(struct tevent_req *subreq)
{
    struct tevent_req *req =
                        tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_get_groups_state *state =
                        tevent_req_data(req, struct sdap_get_groups_state);

    int ret;
    errno_t sysret;

    ret = sdap_process_group_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        sysret = sysdb_transaction_cancel(state->sysdb);
        if (sysret != EOK) {
            DEBUG(0, ("Could not cancel sysdb transaction\n"));
        }
        tevent_req_error(req, ret);
        return;
    }

    state->check_count--;
    DEBUG(9, ("Groups remaining: %d\n", state->check_count));


    if (state->check_count == 0) {
        DEBUG(9, ("All groups processed\n"));

        ret = sdap_save_groups(state, state->sysdb, state->dom, state->opts,
                               state->groups, state->count, true,
                               &state->higher_usn);
        if (ret) {
            DEBUG(2, ("Failed to store groups.\n"));
            tevent_req_error(req, ret);
            return;
        }
        DEBUG(9, ("Saving %d Groups - Done\n", state->count));
        sysret = sysdb_transaction_commit(state->sysdb);
        if (sysret != EOK) {
            DEBUG(0, ("Couldn't commit transaction\n"));
            tevent_req_error(req, sysret);
        } else {
            tevent_req_done(req);
        }
    }
}

int sdap_get_groups_recv(struct tevent_req *req,
                         TALLOC_CTX *mem_ctx, char **usn_value)
{
    struct sdap_get_groups_state *state = tevent_req_data(req,
                                            struct sdap_get_groups_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (usn_value) {
        *usn_value = talloc_steal(mem_ctx, state->higher_usn);
    }

    return EOK;
}

static void sdap_nested_done(struct tevent_req *subreq)
{
    errno_t ret;
    int hret;
    unsigned long i;
    unsigned long count;
    hash_value_t *values;
    struct sysdb_attrs **users = NULL;
    struct sysdb_attrs **groups = NULL;
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
    ret = sdap_save_users(state, state->sysdb, state->attrs,
                          state->dom, state->opts,
                          users, count, &state->higher_usn);
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

    ret = sdap_save_groups(state, state->sysdb, state->dom, state->opts,
                           groups, count, false, &state->higher_usn);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    /* Processing complete */
    tevent_req_done(req);
}


/* ==Save-fake-group-list=====================================*/
static errno_t sdap_add_incomplete_groups(struct sysdb_ctx *sysdb,
                                          struct sdap_options *opts,
                                          struct sss_domain_info *dom,
                                          char **groupnames,
                                          struct sysdb_attrs **ldap_groups,
                                          int ldap_groups_count)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *msg;
    int i, mi, ai;
    const char *name;
    const char *original_dn;
    char **missing;
    gid_t gid;
    int ret;
    bool in_transaction = false;
    bool posix;

    /* There are no groups in LDAP but we should add user to groups ?? */
    if (ldap_groups_count == 0) return EOK;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    missing = talloc_array(tmp_ctx, char *, ldap_groups_count+1);
    if (!missing) {
        ret = ENOMEM;
        goto fail;
    }
    mi = 0;

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        DEBUG(1, ("Cannot start sysdb transaction [%d]: %s\n",
                   ret, strerror(ret)));
        goto fail;
    }
    in_transaction = true;

    for (i=0; groupnames[i]; i++) {
        ret = sysdb_search_group_by_name(tmp_ctx, sysdb, dom,
                                         groupnames[i], NULL, &msg);
        if (ret == EOK) {
            continue;
        } else if (ret == ENOENT) {
            DEBUG(7, ("Group #%d [%s] is not cached, need to add a fake entry\n",
                       i, groupnames[i]));
            missing[mi] = groupnames[i];
            mi++;
            continue;
        } else if (ret != ENOENT) {
            DEBUG(1, ("search for group failed [%d]: %s\n",
                      ret, strerror(ret)));
            goto fail;
        }
    }
    missing[mi] = NULL;

    /* All groups are cached, nothing to do */
    if (mi == 0) {
        talloc_zfree(tmp_ctx);
        goto done;
    }

    for (i=0; missing[i]; i++) {
        /* The group is not in sysdb, need to add a fake entry */
        for (ai=0; ai < ldap_groups_count; ai++) {
            ret = sysdb_attrs_primary_name(sysdb, ldap_groups[ai],
                                           opts->group_map[SDAP_AT_GROUP_NAME].name,
                                           &name);
            if (ret != EOK) {
                DEBUG(1, ("The group has no name attribute\n"));
                goto fail;
            }

            if (strcmp(name, missing[i]) == 0) {
                posix = true;
                ret = sysdb_attrs_get_uint32_t(ldap_groups[ai],
                                               SYSDB_GIDNUM,
                                               &gid);
                if (ret == ENOENT || (ret == EOK && gid == 0)) {
                    DEBUG(9, ("The group %s gid was %s\n",
                              name, ret == ENOENT ? "missing" : "zero"));
                    DEBUG(8, ("Marking group %s as non-posix and setting GID=0!\n", name));
                    gid = 0;
                    posix = false;
                } else if (ret) {
                    DEBUG(1, ("The GID attribute is malformed\n"));
                    goto fail;
                }

                ret = sysdb_attrs_get_string(ldap_groups[ai],
                                             SYSDB_ORIG_DN,
                                             &original_dn);
                if (ret) {
                    DEBUG(5, ("The group has no name original DN\n"));
                    original_dn = NULL;
                }

                DEBUG(8, ("Adding fake group %s to sysdb\n", name));
                ret = sysdb_add_incomplete_group(sysdb, dom, name,
                                                 gid, original_dn, posix);
                if (ret != EOK) {
                    goto fail;
                }
                break;
            }
        }

        if (ai == ldap_groups_count) {
            DEBUG(2, ("Group %s not present in LDAP\n", missing[i]));
            ret = EINVAL;
            goto fail;
        }
    }

done:
    ret = sysdb_transaction_commit(sysdb);
    if (ret != EOK) {
        DEBUG(1, ("sysdb_transaction_commit failed.\n"));
        goto fail;
    }
    in_transaction = false;
    ret = EOK;
fail:
    if (in_transaction) {
        sysdb_transaction_cancel(sysdb);
    }
    talloc_free(tmp_ctx);
    return ret;
}

static int sdap_initgr_common_store(struct sysdb_ctx *sysdb,
                                    struct sdap_options *opts,
                                    struct sss_domain_info *dom,
                                    const char *name,
                                    enum sysdb_member_type type,
                                    char **sysdb_grouplist,
                                    struct sysdb_attrs **ldap_groups,
                                    int ldap_groups_count,
                                    bool add_fake)
{
    TALLOC_CTX *tmp_ctx;
    char **ldap_grouplist = NULL;
    char **add_groups;
    char **del_groups;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    if (ldap_groups_count == 0) {
        /* No groups for this user in LDAP.
         * We need to ensure that there are no groups
         * in the sysdb either.
         */
        ldap_grouplist = NULL;
    } else {
        ret = sysdb_attrs_primary_name_list(
                sysdb, tmp_ctx,
                ldap_groups, ldap_groups_count,
                opts->group_map[SDAP_AT_GROUP_NAME].name,
                &ldap_grouplist);
        if (ret != EOK) {
            DEBUG(1, ("sysdb_attrs_primary_name_list failed [%d]: %s\n",
                      ret, strerror(ret)));
            goto done;
        }
    }

    /* Find the differences between the sysdb and LDAP lists
     * Groups in the sysdb only must be removed.
     */
    ret = diff_string_lists(tmp_ctx, ldap_grouplist, sysdb_grouplist,
                            &add_groups, &del_groups, NULL);
    if (ret != EOK) goto done;

    /* Add fake entries for any groups the user should be added as
     * member of but that are not cached in sysdb
     */
    if (add_fake && add_groups && add_groups[0]) {
        ret = sdap_add_incomplete_groups(sysdb, opts, dom,
                                         add_groups, ldap_groups,
                                         ldap_groups_count);
        if (ret != EOK) {
            DEBUG(1, ("Adding incomplete users failed\n"));
            goto done;
        }
    }

    DEBUG(8, ("Updating memberships for %s\n", name));
    ret = sysdb_update_members(sysdb, dom, name,
                               type,
                               (const char *const *) add_groups,
                               (const char *const *) del_groups);
    if (ret != EOK) {
        DEBUG(1, ("Membership update failed [%d]: %s\n",
                  ret, strerror(ret)));
        goto done;
    }

    ret = EOK;
done:
    talloc_zfree(tmp_ctx);
    return ret;
}

/* ==Initgr-call-(groups-a-user-is-member-of)-RFC2307-Classic/BIS========= */

struct sdap_initgr_rfc2307_state {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sdap_options *opts;
    struct sss_domain_info *dom;
    struct sdap_handle *sh;
    const char *name;

    struct sdap_op *op;

    struct sysdb_attrs **ldap_groups;
    size_t ldap_groups_count;
};

static void sdap_initgr_rfc2307_process(struct tevent_req *subreq);
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
    char *clean_name;
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

    ret = sss_filter_sanitize(state, name, &clean_name);
    if (ret != EOK) {
        talloc_free(req);
        return NULL;
    }

    filter = talloc_asprintf(state,
                             "(&(%s=%s)(objectclass=%s)(%s=*)(&(%s=*)(!(%s=0))))",
                             opts->group_map[SDAP_AT_GROUP_MEMBER].name,
                             clean_name,
                             opts->group_map[SDAP_OC_GROUP].name,
                             opts->group_map[SDAP_AT_GROUP_NAME].name,
                             opts->group_map[SDAP_AT_GROUP_GID].name,
                             opts->group_map[SDAP_AT_GROUP_GID].name);
    if (!filter) {
        talloc_zfree(req);
        return NULL;
    }
    talloc_zfree(clean_name);

    subreq = sdap_get_generic_send(state, state->ev, state->opts,
                                   state->sh, base_dn, LDAP_SCOPE_SUBTREE,
                                   filter, attrs,
                                   state->opts->group_map, SDAP_OPTS_GROUP,
                                   dp_opt_get_int(state->opts->basic,
                                                  SDAP_SEARCH_TIMEOUT));
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
    struct sysdb_attrs **ldap_groups;
    char **sysdb_grouplist = NULL;
    struct ldb_message *msg;
    struct ldb_message_element *groups;
    size_t count;
    const char *attrs[2];
    int ret;
    int i;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_initgr_rfc2307_state);

    ret = sdap_get_generic_recv(subreq, state, &count, &ldap_groups);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    /* Search for all groups for which this user is a member */
    attrs[0] = SYSDB_MEMBEROF;
    attrs[1] = NULL;
    ret = sysdb_search_user_by_name(state, state->sysdb, state->dom,
                                    state->name, attrs, &msg);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    groups = ldb_msg_find_element(msg, SYSDB_MEMBEROF);
    if (!groups || groups->num_values == 0) {
        /* No groups for this user in sysdb currently */
        sysdb_grouplist = NULL;
    } else {
        sysdb_grouplist = talloc_array(state, char *, groups->num_values+1);
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
                tevent_req_error(req, ret);
                return;
            }
        }
        sysdb_grouplist[groups->num_values] = NULL;
    }

    /* There are no nested groups here so we can just update the
     * memberships */
    ret = sdap_initgr_common_store(state->sysdb, state->opts,
                                   state->dom, state->name,
                                   SYSDB_MEMBER_USER, sysdb_grouplist,
                                   ldap_groups, count, true);
    if (ret != EOK) {
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

/* ==Common code for pure RFC2307bis and IPA/AD========================= */
static errno_t
sdap_nested_groups_store(struct sysdb_ctx *sysdb,
                         struct sss_domain_info *dom,
                         struct sdap_options *opts,
                         struct sysdb_attrs **groups,
                         unsigned long count)
{
    errno_t ret, tret;
    TALLOC_CTX *tmp_ctx;
    char **groupnamelist = NULL;
    bool in_transaction = false;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    if (count > 0) {
        ret = sysdb_attrs_primary_name_list(sysdb, tmp_ctx,
                                            groups, count,
                                            opts->group_map[SDAP_AT_GROUP_NAME].name,
                                            &groupnamelist);
        if (ret != EOK) {
            DEBUG(3, ("sysdb_attrs_primary_name_list failed [%d]: %s\n",
                    ret, strerror(ret)));
            goto done;
        }
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        DEBUG(1, ("Failed to start transaction\n"));
        goto done;
    }
    in_transaction = true;

    ret = sdap_add_incomplete_groups(sysdb, opts, dom, groupnamelist,
                                     groups, count);
    if (ret != EOK) {
        DEBUG(6, ("Could not add incomplete groups [%d]: %s\n",
                   ret, strerror(ret)));
        goto done;
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret != EOK) {
        DEBUG(1, ("Failed to commit transaction\n"));
        goto done;
    }
    in_transaction = false;

    ret = EOK;
done:
    if (in_transaction) {
        tret = sysdb_transaction_cancel(sysdb);
        if (tret != EOK) {
            DEBUG(1, ("Failed to cancel transaction\n"));
        }
    }

    talloc_free(tmp_ctx);
    return ret;
}

struct membership_diff {
    struct membership_diff *prev;
    struct membership_diff *next;

    const char *name;
    char **add;
    char **del;
};

static errno_t
build_membership_diff(TALLOC_CTX *mem_ctx, const char *name,
                      char **ldap_parent_names, char **sysdb_parent_names,
                      struct membership_diff **_mdiff)
{
    TALLOC_CTX *tmp_ctx;
    struct membership_diff *mdiff;
    errno_t ret;
    char **add_groups;
    char **del_groups;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        ret = ENOMEM;
        goto done;
    }

    mdiff = talloc_zero(tmp_ctx, struct membership_diff);
    if (!mdiff) {
        ret = ENOMEM;
        goto done;
    }
    mdiff->name = talloc_strdup(mdiff, name);
    if (!mdiff->name) {
        ret = ENOMEM;
        goto done;
    }

    /* Find the differences between the sysdb and ldap lists
     * Groups in ldap only must be added to the sysdb;
     * groups in the sysdb only must be removed.
     */
    ret = diff_string_lists(tmp_ctx,
                            ldap_parent_names, sysdb_parent_names,
                            &add_groups, &del_groups, NULL);
    if (ret != EOK) {
        goto done;
    }
    mdiff->add = talloc_steal(mdiff, add_groups);
    mdiff->del = talloc_steal(mdiff, del_groups);

    ret = EOK;
    *_mdiff = talloc_steal(mem_ctx, mdiff);
done:
    talloc_free(tmp_ctx);
    return ret;
}

/* ==Initgr-call-(groups-a-user-is-member-of)-nested-groups=============== */

struct sdap_initgr_nested_state {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sdap_options *opts;
    struct sss_domain_info *dom;
    struct sdap_handle *sh;

    struct sysdb_attrs *user;
    const char *username;

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
    int i;
    errno_t ret;

    req = tevent_req_create(memctx, &state, struct sdap_initgr_nested_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->sysdb = sysdb;
    state->dom = dom;
    state->sh = sh;
    state->grp_attrs = grp_attrs;
    state->user = user;
    state->op = NULL;

    ret = sysdb_attrs_primary_name(sysdb, user,
                                   opts->user_map[SDAP_AT_USER_NAME].name,
                                   &state->username);
    if (ret != EOK) {
        DEBUG(1, ("User entry had no username\n"));
        talloc_free(req);
        return NULL;
    }

    state->filter = talloc_asprintf(state, "(&(objectclass=%s)(%s=*))",
                                    opts->group_map[SDAP_OC_GROUP].name,
                                    opts->group_map[SDAP_AT_GROUP_NAME].name);
    if (!state->filter) {
        talloc_zfree(req);
        return NULL;
    }

    /* TODO: test rootDSE for deref support and use it if available */
    /* TODO: or test rootDSE for ASQ support and use it if available */

    ret = sysdb_attrs_get_el(user, SYSDB_MEMBEROF, &el);
    if (ret || !el || el->num_values == 0) {
        DEBUG(4, ("User entry lacks original memberof ?\n"));
        /* We can't find any groups for this user, so we'll
         * have to assume there aren't any. Just return
         * success here.
         */
        tevent_req_done(req);
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
                                   state->opts->group_map, SDAP_OPTS_GROUP,
                                   dp_opt_get_int(state->opts->basic,
                                                  SDAP_SEARCH_TIMEOUT));
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
        state->groups[state->groups_cur] = talloc_steal(state->groups,
                                                        groups[0]);
        state->groups_cur++;
    } else {
        DEBUG(2, ("Search for group %s, returned %d results. Skipping\n",
                  state->group_dns[state->cur], count));
    }

    state->cur++;
    /* note that state->count is the count of original memberOf which might not
     * be only groups, but permissions, etc. Use state->groups_cur for
     * group index cap */
    if (state->cur < state->count) {
        subreq = sdap_get_generic_send(state, state->ev,
                                       state->opts, state->sh,
                                       state->group_dns[state->cur],
                                       LDAP_SCOPE_BASE,
                                       state->filter, state->grp_attrs,
                                       state->opts->group_map,
                                       SDAP_OPTS_GROUP,
                                       dp_opt_get_int(state->opts->basic,
                                                      SDAP_SEARCH_TIMEOUT));
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sdap_initgr_nested_search, req);
    } else {
        sdap_initgr_nested_store(req);
    }
}

static errno_t
sdap_initgr_store_groups(struct sdap_initgr_nested_state *state);
static errno_t
sdap_initgr_store_group_memberships(struct sdap_initgr_nested_state *state);
static errno_t
sdap_initgr_store_user_memberships(struct sdap_initgr_nested_state *state);

static void sdap_initgr_nested_store(struct tevent_req *req)
{
    errno_t ret;
    struct sdap_initgr_nested_state *state;
    bool in_transaction = false;
    errno_t tret;

    state = tevent_req_data(req, struct sdap_initgr_nested_state);

    ret = sysdb_transaction_start(state->sysdb);
    if (ret != EOK) {
        DEBUG(1, ("Failed to start transaction\n"));
        goto fail;
    }
    in_transaction = true;

    /* save the groups if they are not already */
    ret = sdap_initgr_store_groups(state);
    if (ret != EOK) {
        DEBUG(3, ("Could not save groups [%d]: %s\n",
                  ret, strerror(ret)));
        goto fail;
    }

    /* save the group memberships */
    ret = sdap_initgr_store_group_memberships(state);
    if (ret != EOK) {
        DEBUG(3, ("Could not save group memberships [%d]: %s\n",
                  ret, strerror(ret)));
        goto fail;
    }

    /* save the user memberships */
    ret = sdap_initgr_store_user_memberships(state);
    if (ret != EOK) {
        DEBUG(3, ("Could not save user memberships [%d]: %s\n",
                  ret, strerror(ret)));
        goto fail;
    }

    ret = sysdb_transaction_commit(state->sysdb);
    if (ret != EOK) {
        DEBUG(1, ("Failed to commit transaction\n"));
        goto fail;
    }
    in_transaction = false;

    tevent_req_done(req);
    return;

fail:
    if (in_transaction) {
        tret = sysdb_transaction_cancel(state->sysdb);
        if (tret != EOK) {
            DEBUG(1, ("Failed to cancel transaction\n"));
        }
    }
    tevent_req_error(req, ret);
    return;
}

static errno_t
sdap_initgr_store_groups(struct sdap_initgr_nested_state *state)
{
    return sdap_nested_groups_store(state->sysdb, state->dom,
                                    state->opts, state->groups,
                                    state->groups_cur);
}

static errno_t
sdap_initgr_nested_get_membership_diff(TALLOC_CTX *mem_ctx,
                                       struct sysdb_ctx *sysdb,
                                       struct sdap_options *opts,
                                       struct sss_domain_info *dom,
                                       struct sysdb_attrs *group,
                                       struct sysdb_attrs **all_groups,
                                       int groups_count,
                                       struct membership_diff **mdiff);

static int sdap_initgr_nested_get_direct_parents(TALLOC_CTX *mem_ctx,
                                                 struct sysdb_attrs *attrs,
                                                 struct sysdb_attrs **groups,
                                                 int ngroups,
                                                 struct sysdb_attrs ***_direct_parents,
                                                 int *_ndirect);

static errno_t
sdap_initgr_store_group_memberships(struct sdap_initgr_nested_state *state)
{
    errno_t ret;
    int i, tret;
    TALLOC_CTX *tmp_ctx;
    struct membership_diff *miter;
    struct membership_diff *memberships = NULL;
    bool in_transaction = false;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    /* Compute the diffs first in order to keep the transaction as small
     * as possible
     */
    for (i=0; i < state->groups_cur; i++) {
        ret = sdap_initgr_nested_get_membership_diff(tmp_ctx, state->sysdb,
                                                     state->opts, state->dom,
                                                     state->groups[i],
                                                     state->groups,
                                                     state->groups_cur,
                                                     &miter);
        if (ret) {
            DEBUG(3, ("Could not compute memberships for group %d [%d]: %s\n",
                      i, ret, strerror(ret)));
            goto done;
        }

        DLIST_ADD(memberships, miter);
    }

    ret = sysdb_transaction_start(state->sysdb);
    if (ret != EOK) {
        DEBUG(1, ("Failed to start transaction\n"));
        goto done;
    }
    in_transaction = true;

    DLIST_FOR_EACH(miter, memberships) {
        ret = sysdb_update_members(state->sysdb, state->dom,
                                   miter->name,
                                   SYSDB_MEMBER_GROUP,
                                   (const char *const *) miter->add,
                                   (const char *const *) miter->del);
        if (ret != EOK) {
            DEBUG(3, ("Failed to update memberships\n"));
            goto done;
        }
    }

    ret = sysdb_transaction_commit(state->sysdb);
    if (ret != EOK) {
        DEBUG(1, ("Failed to commit transaction\n"));
        goto done;
    }
    in_transaction = false;

    ret = EOK;
done:
    if (in_transaction) {
        tret = sysdb_transaction_cancel(state->sysdb);
        if (tret != EOK) {
            DEBUG(1, ("Failed to cancel transaction\n"));
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
sdap_initgr_store_user_memberships(struct sdap_initgr_nested_state *state)
{
    errno_t ret;
    int tret;
    const char *orig_dn;

    char **sysdb_parent_name_list = NULL;
    char **ldap_parent_name_list = NULL;

    int nparents;
    struct sysdb_attrs **ldap_parentlist;
    struct ldb_message_element *el;
    int i, mi;
    char **add_groups;
    char **del_groups;
    TALLOC_CTX *tmp_ctx;
    bool in_transaction = false;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        ret = ENOMEM;
        goto done;
    }

    /* Get direct LDAP parents */
    ret = sysdb_attrs_get_string(state->user, SYSDB_ORIG_DN, &orig_dn);
    if (ret != EOK) {
        DEBUG(2, ("The user has no original DN\n"));
        goto done;
    }

    ldap_parentlist = talloc_zero_array(tmp_ctx, struct sysdb_attrs *,
                                        state->groups_cur + 1);
    if (!ldap_parentlist) {
        ret = ENOMEM;
        goto done;
    }
    nparents = 0;

    for (i=0; i < state->groups_cur ; i++) {
        ret = sysdb_attrs_get_el(state->groups[i], SYSDB_MEMBER, &el);
        if (ret) {
            DEBUG(3, ("A group with no members during initgroups?\n"));
            goto done;
        }

        for (mi = 0; mi < el->num_values; mi++) {
            if (strcasecmp((const char *) el->values[mi].data, orig_dn) != 0) {
                continue;
            }

            ldap_parentlist[nparents] = state->groups[i];
            nparents++;
        }
    }

    DEBUG(7, ("The user %s is a direct member of %d LDAP groups\n",
              state->username, nparents));

    if (nparents == 0) {
        ldap_parent_name_list = NULL;
    } else {
        ret = sysdb_attrs_primary_name_list(state->sysdb, tmp_ctx,
                                            ldap_parentlist,
                                            nparents,
                                            state->opts->group_map[SDAP_AT_GROUP_NAME].name,
                                            &ldap_parent_name_list);
        if (ret != EOK) {
            DEBUG(1, ("sysdb_attrs_primary_name_list failed [%d]: %s\n",
                      ret, strerror(ret)));
            goto done;
        }
    }

    ret = sysdb_get_direct_parents(tmp_ctx, state->sysdb, state->dom,
                                   SYSDB_MEMBER_USER,
                                   state->username, &sysdb_parent_name_list);
    if (ret) {
        DEBUG(1, ("Could not get direct sysdb parents for %s: %d [%s]\n",
                   state->username, ret, strerror(ret)));
        goto done;
    }

    ret = diff_string_lists(tmp_ctx,
                            ldap_parent_name_list, sysdb_parent_name_list,
                            &add_groups, &del_groups, NULL);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_transaction_start(state->sysdb);
    if (ret != EOK) {
        DEBUG(1, ("Failed to start transaction\n"));
        goto done;
    }
    in_transaction = true;

    DEBUG(8, ("Updating memberships for %s\n", state->username));
    ret = sysdb_update_members(state->sysdb, state->dom,
                               state->username, SYSDB_MEMBER_USER,
                               (const char *const *) add_groups,
                               (const char *const *) del_groups);
    if (ret != EOK) {
        DEBUG(1, ("Could not update sysdb memberships for %s: %d [%s]\n",
                  state->username, ret, strerror(ret)));
        goto done;
    }

    ret = sysdb_transaction_commit(state->sysdb);
    if (ret != EOK) {
        goto done;
    }
    in_transaction = false;

    ret = EOK;
done:
    if (in_transaction) {
        tret = sysdb_transaction_cancel(state->sysdb);
        if (tret != EOK) {
            DEBUG(1, ("Failed to cancel transaction\n"));
        }
    }
    talloc_zfree(tmp_ctx);
    return ret;
}

static errno_t
sdap_initgr_nested_get_membership_diff(TALLOC_CTX *mem_ctx,
                                       struct sysdb_ctx *sysdb,
                                       struct sdap_options *opts,
                                       struct sss_domain_info *dom,
                                       struct sysdb_attrs *group,
                                       struct sysdb_attrs **all_groups,
                                       int groups_count,
                                       struct membership_diff **_mdiff)
{
    errno_t ret;
    struct membership_diff *mdiff;
    const char *group_name;

    struct sysdb_attrs **ldap_parentlist;
    int parents_count;

    char **ldap_parent_names_list = NULL;
    char **sysdb_parents_names_list = NULL;

    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        ret = ENOMEM;
        goto done;
    }

    /* Get direct sysdb parents */
    ret = sysdb_attrs_primary_name(sysdb, group,
                                   opts->group_map[SDAP_AT_GROUP_NAME].name,
                                   &group_name);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_get_direct_parents(tmp_ctx, sysdb, dom,
                                   SYSDB_MEMBER_GROUP,
                                   group_name, &sysdb_parents_names_list);
    if (ret) {
        DEBUG(1, ("Could not get direct sysdb parents for %s: %d [%s]\n",
                   group_name, ret, strerror(ret)));
        goto done;
    }

    /* For each group, filter only parents from full set */
    ret = sdap_initgr_nested_get_direct_parents(tmp_ctx,
                                                group,
                                                all_groups,
                                                groups_count,
                                                &ldap_parentlist,
                                                &parents_count);
    if (ret != EOK) {
        DEBUG(1, ("Cannot get parent groups for %s [%d]: %s\n",
                  group_name, ret, strerror(ret)));
        goto done;
    }
    DEBUG(7, ("The group %s is a direct member of %d LDAP groups\n",
               group_name, parents_count));

    if (parents_count > 0) {
        ret = sysdb_attrs_primary_name_list(sysdb, tmp_ctx,
                                            ldap_parentlist,
                                            parents_count,
                                            opts->group_map[SDAP_AT_GROUP_NAME].name,
                                            &ldap_parent_names_list);
        if (ret != EOK) {
            DEBUG(1, ("sysdb_attrs_primary_name_list failed [%d]: %s\n",
                        ret, strerror(ret)));
            goto done;
        }
    }

    ret = build_membership_diff(tmp_ctx, group_name, ldap_parent_names_list,
                                sysdb_parents_names_list, &mdiff);
    if (ret != EOK) {
        DEBUG(3, ("Could not build membership diff for %s [%d]: %s\n",
                  group_name, ret, strerror(ret)));
        goto done;
    }

    ret = EOK;
    *_mdiff = talloc_steal(mem_ctx, mdiff);
done:
    talloc_free(tmp_ctx);
    return ret;
}

static int sdap_initgr_nested_get_direct_parents(TALLOC_CTX *mem_ctx,
                                                 struct sysdb_attrs *attrs,
                                                 struct sysdb_attrs **groups,
                                                 int ngroups,
                                                 struct sysdb_attrs ***_direct_parents,
                                                 int *_ndirect)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message_element *member;
    int i, mi;
    int ret;
    const char *orig_dn;

    int ndirect;
    struct sysdb_attrs **direct_groups;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    direct_groups = talloc_zero_array(tmp_ctx, struct sysdb_attrs *,
                                      ngroups + 1);
    if (!direct_groups) {
        ret = ENOMEM;
        goto done;
    }
    ndirect = 0;

    ret = sysdb_attrs_get_string(attrs, SYSDB_ORIG_DN, &orig_dn);
    if (ret != EOK) {
        DEBUG(3, ("Missing originalDN\n"));
        goto done;
    }
    DEBUG(9, ("Looking up direct parents for group [%s]\n", orig_dn));

    /* FIXME - Filter only parents from full set to avoid searching
     * through all members of huge groups. That requires asking for memberOf
     * with the group LDAP search
     */

    /* Filter only direct parents from the list of all groups */
    for (i=0; i < ngroups; i++) {
        ret = sysdb_attrs_get_el(groups[i], SYSDB_MEMBER, &member);
        if (ret) {
            DEBUG(7, ("A group with no members during initgroups?\n"));
            continue;
        }

        for (mi = 0; mi < member->num_values; mi++) {
            if (strcasecmp((const char *) member->values[mi].data, orig_dn) != 0) {
                continue;
            }

            direct_groups[ndirect] = groups[i];
            ndirect++;
        }
    }
    direct_groups[ndirect] = NULL;

    DEBUG(9, ("The group [%s] has %d direct parents\n", orig_dn, ndirect));

    *_direct_parents = talloc_steal(mem_ctx, direct_groups);
    *_ndirect = ndirect;
    ret = EOK;
done:
    talloc_zfree(tmp_ctx);
    return ret;
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
    struct sdap_id_ctx *id_ctx;
    const char *name;
    const char **grp_attrs;
    const char **ldap_attrs;

    struct sysdb_attrs *orig_user;
};

static void sdap_get_initgr_user(struct tevent_req *subreq);
static void sdap_get_initgr_done(struct tevent_req *subreq);

struct tevent_req *sdap_get_initgr_send(TALLOC_CTX *memctx,
                                        struct tevent_context *ev,
                                        struct sdap_handle *sh,
                                        struct sdap_id_ctx *id_ctx,
                                        const char *name,
                                        const char **grp_attrs)
{
    struct tevent_req *req, *subreq;
    struct sdap_get_initgr_state *state;
    const char *base_dn;
    char *filter;
    int ret;
    char *clean_name;

    DEBUG(9, ("Retrieving info for initgroups call\n"));

    req = tevent_req_create(memctx, &state, struct sdap_get_initgr_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = id_ctx->opts;
    state->sysdb = id_ctx->be->sysdb;
    state->dom = id_ctx->be->domain;
    state->sh = sh;
    state->id_ctx = id_ctx;
    state->name = name;
    state->grp_attrs = grp_attrs;
    state->orig_user = NULL;

    ret = sss_filter_sanitize(state, name, &clean_name);
    if (ret != EOK) {
        return NULL;
    }

    filter = talloc_asprintf(state, "(&(%s=%s)(objectclass=%s))",
                        state->opts->user_map[SDAP_AT_USER_NAME].name,
                        clean_name,
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
                               SDAP_OPTS_USER, &state->ldap_attrs);
    if (ret) {
        talloc_zfree(req);
        return NULL;
    }

    subreq = sdap_get_generic_send(state, state->ev,
                                   state->opts, state->sh,
                                   base_dn, LDAP_SCOPE_SUBTREE,
                                   filter, state->ldap_attrs,
                                   state->opts->user_map, SDAP_OPTS_USER,
                                   dp_opt_get_int(state->opts->basic,
                                                  SDAP_SEARCH_TIMEOUT));
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, sdap_get_initgr_user, req);

    return req;
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
static void sdap_get_initgr_user(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_initgr_state *state = tevent_req_data(req,
                                               struct sdap_get_initgr_state);
    struct sysdb_attrs **usr_attrs;
    size_t count;
    int ret;
    const char *orig_dn;

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

    ret = sysdb_transaction_start(state->sysdb);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(9, ("Storing the user\n"));

    ret = sdap_save_user(state, state->sysdb,
                         state->opts, state->dom,
                         state->orig_user, state->ldap_attrs,
                         true, NULL);
    if (ret) {
        sysdb_transaction_cancel(state->sysdb);
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(9, ("Commit change\n"));

    ret = sysdb_transaction_commit(state->sysdb);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(9, ("Process user's groups\n"));

    switch (state->opts->schema_type) {
    case SDAP_SCHEMA_RFC2307:
        ret = sdap_check_aliases(state->sysdb, state->orig_user, state->dom,
                                 state->opts, false);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }

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
                state, state->ev, state->opts, state->sysdb,
                state->dom, state->sh,
                dp_opt_get_string(state->opts->basic,
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

static int sdap_initgr_rfc2307bis_recv(struct tevent_req *req);
static void sdap_get_initgr_pgid(struct tevent_req *req);
static void sdap_get_initgr_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_initgr_state *state = tevent_req_data(req,
                                               struct sdap_get_initgr_state);
    int ret;
    gid_t primary_gid;
    char *gid;

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
        DEBUG(9, ("Error in initgroups: [%d][%s]\n",
                  ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    /* We also need to update the user's primary group, since
     * the user may not be an explicit member of that group
     */
    ret = sysdb_attrs_get_uint32_t(state->orig_user, SYSDB_GIDNUM, &primary_gid);
    if (ret != EOK) {
        DEBUG(6, ("Could not find user's primary GID\n"));
        tevent_req_error(req, ret);
        return;
    }

    gid = talloc_asprintf(state, "%lu", (unsigned long)primary_gid);
    if (gid == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    subreq = groups_get_send(req, state->ev, state->id_ctx, gid,
                             BE_FILTER_IDNUM, BE_ATTR_ALL);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sdap_get_initgr_pgid, req);

    tevent_req_done(req);
}

static void sdap_get_initgr_pgid(struct tevent_req *subreq)
{
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    errno_t ret;

    ret = groups_get_recv(subreq, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
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
    gid_t gid;

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

    ret = sysdb_attrs_primary_name(sysdb, group,
                                   opts->group_map[SDAP_AT_GROUP_NAME].sys_name,
                                   &groupname);
    if (ret != EOK) {
        goto immediate;
    }

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

    ret = sysdb_attrs_get_uint32_t(group,
                                   opts->group_map[SDAP_AT_GROUP_GID].sys_name,
                                   &gid);
    if (ret == ENOENT || (ret == EOK && gid == 0)) {
        DEBUG(9, ("The group's gid was %s\n", ret == ENOENT ? "missing" : "zero"));
        DEBUG(8, ("Marking group as non-posix and setting GID=0!\n"));

        if (ret == ENOENT) {
            ret = sysdb_attrs_add_uint32(group,
                                      opts->group_map[SDAP_AT_GROUP_GID].sys_name,
                                      0);
            if (ret != EOK) {
                DEBUG(1, ("Failed to add a GID to non-posix group!\n"));
                goto immediate;
            }
        }

        ret = sysdb_attrs_add_bool(group, SYSDB_POSIX, false);
        if (ret != EOK) {
            DEBUG(2, ("Error: Failed to mark group as non-posix!\n"));
            goto immediate;
        }
    } else if (ret) {
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


static void sdap_nested_group_process_ldap_user(struct tevent_req *subreq);
static void sdap_nested_group_process_user(struct tevent_req *subreq);
static errno_t sdap_nested_group_lookup_user(struct tevent_req *req,
                                             tevent_req_fn fn);
static errno_t sdap_nested_group_lookup_group(struct tevent_req *req);
static errno_t sdap_nested_group_process_step(struct tevent_req *req)
{
    errno_t ret;
    struct sdap_nested_group_ctx *state =
            tevent_req_data(req, struct sdap_nested_group_ctx);
    char *member_dn;
    char *filter;
    static const char *attrs[] = SYSDB_PW_ATTRS;
    size_t count;
    struct ldb_message **msgs;
    uint64_t expiration;
    bool has_key = false;
    hash_key_t key;
    uint8_t *data;
    time_t now = time(NULL);

    while (true) {
        /* Continue to loop through until all entries have been
         * processed.
         */
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

        ret = sss_filter_sanitize(state, state->member_dn, &member_dn);
        if (ret != EOK) {
            goto error;
        }

        /* Check for the specified origDN in the sysdb */
        filter = talloc_asprintf(NULL, "(%s=%s)",
                                 SYSDB_ORIG_DN,
                                 member_dn);
        if (!filter) {
            ret = ENOMEM;
            goto error;
        }

        /* Try users first */
        ret = sysdb_search_users(state, state->sysdb, state->domain, filter,
                                 attrs, &count, &msgs);
        talloc_zfree(filter);
        if (ret != EOK && ret != ENOENT) {
            goto error;
        } if (ret == ENOENT || count == 0) {
            /* It wasn't a user. Check whether it's a group */
            if (ret == EOK) talloc_zfree(msgs);

            filter = talloc_asprintf(NULL, "(%s=%s)",
                                     SYSDB_ORIG_DN,
                                     member_dn);
            if (!filter) {
                ret = ENOMEM;
                goto error;
            }
            talloc_zfree(member_dn);

            ret = sysdb_search_groups(state, state->sysdb, state->domain,
                                      filter, attrs, &count, &msgs);
            talloc_zfree(filter);
            if (ret != EOK && ret != ENOENT) {
                ret = EIO;
                goto error;
            } else if (ret == ENOENT || count == 0) {
                if (ret == EOK) talloc_zfree(msgs);

                /* It wasn't found in the groups either
                 * We'll have to do a blind lookup for both
                 */

                /* Try users first */
                ret = sdap_nested_group_lookup_user(
                        req, sdap_nested_group_process_ldap_user);
                if (ret != EOK) {
                    goto error;
                }
                return EAGAIN;
            }

            /* We found a group with this origDN in the sysdb */

            /* Check whether the entry is valid */
            if (count != 1) {
                DEBUG(1, ("More than one entry with this origDN? Skipping\n"));
                state->member_index++;
                talloc_zfree(state->member_dn);
                continue;
            }

            expiration = ldb_msg_find_attr_as_uint64(msgs[0],
                                                     SYSDB_CACHE_EXPIRE,
                                                     0);
            if (expiration && expiration > now) {
                DEBUG(6, ("Cached values are still valid. Skipping\n"));
                state->member_index++;
                talloc_zfree(state->member_dn);
                continue;
            }

            /* Refresh the group from LDAP */
            ret = sdap_nested_group_lookup_group(req);
            if (ret != EOK)  goto error;

            return EAGAIN;
        }
        talloc_zfree(member_dn);

        /* We found a user with this origDN in the sysdb */

        /* Check whether the entry is valid */
        if (count != 1) {
            DEBUG(1, ("More than one entry with this origDN? Skipping\n"));
            state->member_index++;
            talloc_zfree(state->member_dn);
            continue;
        }

        expiration = ldb_msg_find_attr_as_uint64(msgs[0],
                                                 SYSDB_CACHE_EXPIRE,
                                                 0);
        if (expiration && expiration > now) {
            DEBUG(6, ("Cached values are still valid. Skipping\n"));
            state->member_index++;
            talloc_zfree(state->member_dn);
            continue;
        }

        /* Refresh the user from LDAP */
        ret = sdap_nested_group_lookup_user(
                req, sdap_nested_group_process_user);
        if (ret != EOK)  goto error;

        return EAGAIN;
    } /* while (true) */

error:
    talloc_zfree(state->member_dn);
    return ret;
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
                                   SDAP_OPTS_USER,
                                   dp_opt_get_int(state->opts->basic,
                                                  SDAP_SEARCH_TIMEOUT));
    if (!subreq) {
        talloc_free(sdap_attrs);
        return EIO;
    }
    talloc_steal(subreq, sdap_attrs);

    tevent_req_set_callback(subreq, fn, req);
    return EOK;
}

static void sdap_nested_group_process_group(struct tevent_req *subreq);
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
            sdap_attrs, "(&(objectclass=%s)(%s=*))",
            state->opts->group_map[SDAP_OC_GROUP].name,
            state->opts->group_map[SDAP_AT_GROUP_NAME].name);
    if (!filter) {
        talloc_free(sdap_attrs);
        return ENOMEM;
    }

    subreq = sdap_get_generic_send(state, state->ev, state->opts,
                                   state->sh, state->member_dn,
                                   LDAP_SCOPE_BASE,
                                   filter, sdap_attrs,
                                   state->opts->group_map,
                                   SDAP_OPTS_GROUP,
                                   dp_opt_get_int(state->opts->basic,
                                                  SDAP_SEARCH_TIMEOUT));
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
        return;
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

struct sdap_initgr_rfc2307bis_state {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sdap_options *opts;
    struct sss_domain_info *dom;
    struct sdap_handle *sh;
    const char *name;

    struct sdap_op *op;

    hash_table_t *group_hash;
    size_t num_direct_parents;
    struct sysdb_attrs **direct_groups;
};

struct sdap_nested_group {
    struct sysdb_attrs *group;
    struct sysdb_attrs **ldap_parents;
    size_t parents_count;
};

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
    struct sdap_initgr_rfc2307bis_state *state;
    const char *filter;
    const char **attrs;
    char *clean_orig_dn;

    req = tevent_req_create(memctx, &state,
                            struct sdap_initgr_rfc2307bis_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->sysdb = sysdb;
    state->dom = dom;
    state->sh = sh;
    state->op = NULL;
    state->name = name;

    ret = sss_hash_create(state, 32, &state->group_hash);
    if (ret != EOK) {
        talloc_free(req);
        return NULL;
    }

    ret = build_attrs_from_map(state, opts->group_map,
                               SDAP_OPTS_GROUP, &attrs);
    if (ret != EOK) {
        talloc_free(req);
        return NULL;
    }

    ret = sss_filter_sanitize(state, orig_dn, &clean_orig_dn);
    if (ret != EOK) {
        talloc_free(req);
        return NULL;
    }

    filter = talloc_asprintf(state, "(&(%s=%s)(objectclass=%s)(%s=*))",
                             opts->group_map[SDAP_AT_GROUP_MEMBER].name,
                             clean_orig_dn,
                             opts->group_map[SDAP_OC_GROUP].name,
                             opts->group_map[SDAP_AT_GROUP_NAME].name);
    if (!filter) {
        talloc_zfree(req);
        return NULL;
    }
    talloc_zfree(clean_orig_dn);

    DEBUG(6, ("Looking up parent groups for user [%s]\n", orig_dn));
    subreq = sdap_get_generic_send(state, state->ev, state->opts,
                                   state->sh, base_dn, LDAP_SCOPE_SUBTREE,
                                   filter, attrs,
                                   state->opts->group_map, SDAP_OPTS_GROUP,
                                   dp_opt_get_int(state->opts->basic,
                                                  SDAP_SEARCH_TIMEOUT));
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, sdap_initgr_rfc2307bis_process, req);

    return req;

}

errno_t save_rfc2307bis_user_memberships(
        struct sdap_initgr_rfc2307bis_state *state);
struct tevent_req *rfc2307bis_nested_groups_send(
        TALLOC_CTX *mem_ctx, struct tevent_context *ev,
        struct sdap_options *opts, struct sysdb_ctx *sysdb,
        struct sss_domain_info *dom, struct sdap_handle *sh,
        struct sysdb_attrs **groups, size_t num_groups,
        hash_table_t *group_hash, size_t nesting);
static void sdap_initgr_rfc2307bis_done(struct tevent_req *subreq);
static void sdap_initgr_rfc2307bis_process(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct sdap_initgr_rfc2307bis_state *state;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_initgr_rfc2307bis_state);

    ret = sdap_get_generic_recv(subreq, state,
                                &state->num_direct_parents,
                                &state->direct_groups);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->num_direct_parents == 0) {
        /* Start a transaction to look up the groups in the sysdb
         * and update them with LDAP data
         */
        ret = save_rfc2307bis_user_memberships(state);
        if (ret != EOK) {
            tevent_req_error(req, ret);
        } else {
            tevent_req_done(req);
        }
        return;
    }

    subreq = rfc2307bis_nested_groups_send(state, state->ev, state->opts,
                                           state->sysdb, state->dom,
                                           state->sh, state->direct_groups,
                                           state->num_direct_parents,
                                           state->group_hash, 0);
    if (!subreq) {
        tevent_req_error(req, EIO);
        return;
    }
    tevent_req_set_callback(subreq, sdap_initgr_rfc2307bis_done, req);
}

static errno_t rfc2307bis_nested_groups_recv(struct tevent_req *req);
static errno_t
save_rfc2307bis_groups(struct sdap_initgr_rfc2307bis_state *state);
static errno_t
save_rfc2307bis_group_memberships(struct sdap_initgr_rfc2307bis_state *state);

static void sdap_initgr_rfc2307bis_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_initgr_rfc2307bis_state *state =
            tevent_req_data(req, struct sdap_initgr_rfc2307bis_state);
    bool in_transaction = false;
    errno_t tret;

    ret = rfc2307bis_nested_groups_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    ret = sysdb_transaction_start(state->sysdb);
    if (ret != EOK) {
        DEBUG(1, ("Failed to start transaction\n"));
        goto fail;
    }
    in_transaction = true;

    /* save the groups if they are not cached */
    ret = save_rfc2307bis_groups(state);
    if (ret != EOK) {
        DEBUG(3, ("Could not save groups memberships [%d]", ret));
        goto fail;
    }

    /* save the group membership */
    ret = save_rfc2307bis_group_memberships(state);
    if (ret != EOK) {
        DEBUG(3, ("Could not save group memberships [%d]", ret));
        goto fail;
    }

    /* save the user memberships */
    ret = save_rfc2307bis_user_memberships(state);
    if (ret != EOK) {
        DEBUG(3, ("Could not save user memberships [%d]", ret));
        goto fail;
    }

    ret = sysdb_transaction_commit(state->sysdb);
    if (ret != EOK) {
        DEBUG(1, ("Failed to commit transaction\n"));
        goto fail;
    }
    in_transaction = false;

    tevent_req_done(req);
    return;

fail:
    if (in_transaction) {
        tret = sysdb_transaction_cancel(state->sysdb);
        if (tret != EOK) {
            DEBUG(1, ("Failed to cancel transaction\n"));
        }
    }
    tevent_req_error(req, ret);
    return;
}

struct rfc2307bis_group_memberships_state {
    struct sysdb_ctx *sysdb;
    struct sdap_options *opts;
    struct sss_domain_info *dom;

    hash_table_t *group_hash;

    struct membership_diff *memberships;

    int ret;
};

static errno_t
save_rfc2307bis_groups(struct sdap_initgr_rfc2307bis_state *state)
{
    struct sysdb_attrs **groups = NULL;
    unsigned long count;
    hash_value_t *values;
    int hret, i;
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    struct sdap_nested_group *gr;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    hret = hash_values(state->group_hash, &count, &values);
    if (hret != HASH_SUCCESS) {
        ret = EIO;
        goto done;
    }

    groups = talloc_array(tmp_ctx, struct sysdb_attrs *, count);
    if (!groups) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < count; i++) {
        gr = talloc_get_type(values[i].ptr,
                             struct sdap_nested_group);
        groups[i] = gr->group;
    }
    talloc_zfree(values);

    ret = sdap_nested_groups_store(state->sysdb, state->dom, state->opts,
                                   groups, count);
    if (ret != EOK) {
        DEBUG(3, ("Could not save groups [%d]: %s\n",
                  ret, strerror(ret)));
        goto done;
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static bool rfc2307bis_group_memberships_build(hash_entry_t *item, void *user_data);

static errno_t
save_rfc2307bis_group_memberships(struct sdap_initgr_rfc2307bis_state *state)
{
    errno_t ret, tret;
    int hret;
    TALLOC_CTX *tmp_ctx;
    struct rfc2307bis_group_memberships_state *membership_state;
    struct membership_diff *iter;
    bool in_transaction = false;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    membership_state = talloc_zero(tmp_ctx,
                                struct rfc2307bis_group_memberships_state);
    if (!membership_state) {
        ret = ENOMEM;
        goto done;
    }

    membership_state->sysdb = state->sysdb;
    membership_state->dom = state->dom;
    membership_state->opts = state->opts;
    membership_state->group_hash = state->group_hash;

    hret = hash_iterate(state->group_hash,
                        rfc2307bis_group_memberships_build,
                        membership_state);
    if (hret != HASH_SUCCESS) {
        ret = membership_state->ret;
        goto done;
    }

    ret = sysdb_transaction_start(state->sysdb);
    if (ret != EOK) {
        DEBUG(1, ("Failed to start transaction\n"));
        goto done;
    }
    in_transaction = true;

    DLIST_FOR_EACH(iter, membership_state->memberships) {
        ret = sysdb_update_members(state->sysdb,
                                   state->dom,
                                   iter->name,
                                   SYSDB_MEMBER_GROUP,
                                  (const char *const *) iter->add,
                                  (const char *const *) iter->del);
        if (ret != EOK) {
            DEBUG(3, ("Failed to update memberships\n"));
            goto done;
        }
    }

    ret = sysdb_transaction_commit(state->sysdb);
    if (ret != EOK) {
        DEBUG(1, ("Failed to commit transaction\n"));
        goto done;
    }
    in_transaction = false;

    ret = EOK;
done:
    if (in_transaction) {
        tret = sysdb_transaction_cancel(state->sysdb);
        if (tret != EOK) {
            DEBUG(1, ("Failed to cancel transaction\n"));
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}

static bool
rfc2307bis_group_memberships_build(hash_entry_t *item, void *user_data)
{
    struct rfc2307bis_group_memberships_state *mstate = talloc_get_type(
                        user_data, struct rfc2307bis_group_memberships_state);
    struct sdap_nested_group *group;
    char *group_name;
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    char **sysdb_parents_names_list;
    char **ldap_parents_names_list = NULL;

    struct membership_diff *mdiff;

    group_name = (char *) item->key.str;
    group = (struct sdap_nested_group *) item->value.ptr;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_get_direct_parents(tmp_ctx, mstate->sysdb, mstate->dom,
                                   SYSDB_MEMBER_GROUP,
                                   group_name, &sysdb_parents_names_list);
    if (ret) {
        DEBUG(1, ("Could not get direct sysdb parents for %s: %d [%s]\n",
                  group_name, ret, strerror(ret)));
        goto done;
    }

    if (group->parents_count > 0) {
        ret = sysdb_attrs_primary_name_list(mstate->sysdb, tmp_ctx,
                            group->ldap_parents, group->parents_count,
                            mstate->opts->group_map[SDAP_AT_GROUP_NAME].name,
                            &ldap_parents_names_list);
        if (ret != EOK) {
            goto done;
        }
    }

    ret = build_membership_diff(tmp_ctx, group_name, ldap_parents_names_list,
                                sysdb_parents_names_list, &mdiff);
    if (ret != EOK) {
        DEBUG(3, ("Could not build membership diff for %s [%d]: %s\n",
                  group_name, ret, strerror(ret)));
        goto done;
    }

    talloc_steal(mstate, mdiff);
    DLIST_ADD(mstate->memberships, mdiff);
    ret = EOK;
done:
    talloc_free(tmp_ctx);
    mstate->ret = ret;
    return ret == EOK ? true : false;
}

errno_t save_rfc2307bis_user_memberships(
        struct sdap_initgr_rfc2307bis_state *state)
{
    errno_t ret, tret;
    char **ldap_grouplist;
    char **sysdb_parent_name_list;
    char **add_groups;
    char **del_groups;
    bool in_transaction = false;

    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    if(!tmp_ctx) {
        return ENOMEM;
    }

    DEBUG(7, ("Save parent groups to sysdb\n"));
    ret = sysdb_transaction_start(state->sysdb);
    if (ret != EOK) {
        goto error;
    }
    in_transaction = true;

    ret = sysdb_get_direct_parents(tmp_ctx, state->sysdb, state->dom,
                                   SYSDB_MEMBER_USER,
                                   state->name, &sysdb_parent_name_list);
    if (ret) {
        DEBUG(1, ("Could not get direct sysdb parents for %s: %d [%s]\n",
                   state->name, ret, strerror(ret)));
        goto error;
    }

    if (state->num_direct_parents == 0) {
        ldap_grouplist = NULL;
    }
    else {
        ret = sysdb_attrs_primary_name_list(
                state->sysdb, tmp_ctx,
                state->direct_groups, state->num_direct_parents,
                state->opts->group_map[SDAP_AT_GROUP_NAME].name,
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
                            ldap_grouplist, sysdb_parent_name_list,
                            &add_groups, &del_groups, NULL);
    if (ret != EOK) {
        goto error;
    }

    DEBUG(8, ("Updating memberships for %s\n", state->name));
    ret = sysdb_update_members(state->sysdb, state->dom,
                               state->name, SYSDB_MEMBER_USER,
                               (const char *const *)add_groups,
                               (const char *const *)del_groups);
    if (ret != EOK) {
        goto error;
    }

    ret = sysdb_transaction_commit(state->sysdb);
    if (ret != EOK) {
        goto error;
    }
    in_transaction = false;

    talloc_free(tmp_ctx);
    return EOK;

error:
    if (in_transaction) {
        tret = sysdb_transaction_cancel(state->sysdb);
        if (tret != EOK) {
            DEBUG(1, ("Failed to cancel transaction\n"));
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}
struct sdap_rfc2307bis_nested_ctx {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *dom;
    struct sdap_handle *sh;
    struct sysdb_attrs **groups;
    size_t num_groups;

    size_t nesting_level;

    size_t group_iter;
    struct sysdb_attrs **ldap_parents;
    size_t parents_count;

    hash_table_t *group_hash;
    const char *primary_name;

    struct sysdb_handle *handle;
};

static errno_t rfc2307bis_nested_groups_step(struct tevent_req *req);
struct tevent_req *rfc2307bis_nested_groups_send(
        TALLOC_CTX *mem_ctx, struct tevent_context *ev,
        struct sdap_options *opts, struct sysdb_ctx *sysdb,
        struct sss_domain_info *dom, struct sdap_handle *sh,
        struct sysdb_attrs **groups, size_t num_groups,
        hash_table_t *group_hash, size_t nesting)
{
    errno_t ret;
    struct tevent_req *req;
    struct sdap_rfc2307bis_nested_ctx *state;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_rfc2307bis_nested_ctx);
    if (!req) return NULL;

    if ((num_groups == 0) ||
        (nesting > dp_opt_get_int(opts->basic, SDAP_NESTING_LEVEL))) {
        /* No parent groups to process or too deep*/
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
    state->nesting_level = nesting;
    state->group_hash = group_hash;

    ret = rfc2307bis_nested_groups_step(req);
    if (ret == EOK) {
        /* All parent groups were already processed */
        tevent_req_done(req);
        tevent_req_post(req, ev);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    /* EAGAIN means a lookup is in progress */
    return req;
}

static void rfc2307bis_nested_groups_process(struct tevent_req *subreq);
static errno_t rfc2307bis_nested_groups_step(struct tevent_req *req)
{
    errno_t ret;
    struct tevent_req *subreq;
    TALLOC_CTX *tmp_ctx = NULL;
    char *filter;
    const char *orig_dn;
    const char **attrs;
    char *clean_orig_dn;
    hash_key_t key;
    struct sdap_rfc2307bis_nested_ctx *state =
            tevent_req_data(req, struct sdap_rfc2307bis_nested_ctx);

    tmp_ctx = talloc_new(state);
    if (!tmp_ctx) {
        ret = ENOMEM;
        goto error;
    }

    ret = sysdb_attrs_primary_name(
            state->sysdb,
            state->groups[state->group_iter],
            state->opts->group_map[SDAP_AT_GROUP_NAME].name,
            &state->primary_name);
    if (ret != EOK) {
        goto error;
    }

    key.type = HASH_KEY_STRING;
    key.str = talloc_strdup(state, state->primary_name);
    if (!key.str) {
        ret = ENOMEM;
        goto error;
    }

    DEBUG(6, ("Processing group [%s]\n", state->primary_name));

    if (hash_has_key(state->group_hash, &key)) {
        talloc_free(key.str);
        talloc_free(tmp_ctx);
        return EOK;
    }

   /* Get any parent groups for this group */
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

    ret = sss_filter_sanitize(tmp_ctx, orig_dn, &clean_orig_dn);
    if (ret != EOK) {
        goto error;
    }

    filter = talloc_asprintf(
            tmp_ctx, "(&(%s=%s)(objectclass=%s)(%s=*))",
            state->opts->group_map[SDAP_AT_GROUP_MEMBER].name,
            clean_orig_dn,
            state->opts->group_map[SDAP_OC_GROUP].name,
            state->opts->group_map[SDAP_AT_GROUP_NAME].name);
    if (!filter) {
        ret = ENOMEM;
        goto error;
    }
    talloc_zfree(clean_orig_dn);

    DEBUG(6, ("Looking up parent groups for group [%s]\n", orig_dn));
    subreq = sdap_get_generic_send(state, state->ev, state->opts,
                                   state->sh,
                                   dp_opt_get_string(state->opts->basic,
                                                     SDAP_GROUP_SEARCH_BASE),
                                   LDAP_SCOPE_SUBTREE,
                                   filter, attrs,
                                   state->opts->group_map, SDAP_OPTS_GROUP,
                                   dp_opt_get_int(state->opts->basic,
                                                  SDAP_SEARCH_TIMEOUT));
    if (!subreq) {
        ret = EIO;
        goto error;
    }
    talloc_steal(subreq, tmp_ctx);
    tevent_req_set_callback(subreq,
                            rfc2307bis_nested_groups_process,
                            req);

    talloc_free(tmp_ctx);
    return EAGAIN;

error:
    talloc_free(tmp_ctx);
    return ret;
}

static void rfc2307bis_nested_groups_done(struct tevent_req *subreq);
static void rfc2307bis_nested_groups_process(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_rfc2307bis_nested_ctx *state =
            tevent_req_data(req, struct sdap_rfc2307bis_nested_ctx);
    struct sdap_nested_group *ngr;
    hash_value_t value;
    hash_key_t key;
    int hret;

    ret = sdap_get_generic_recv(subreq, state,
                                &state->parents_count,
                                &state->ldap_parents);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    ngr = talloc_zero(state->group_hash, struct sdap_nested_group);
    if (!ngr) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    ngr->group = talloc_steal(ngr, state->groups[state->group_iter]);
    ngr->ldap_parents = talloc_steal(ngr, state->ldap_parents);
    ngr->parents_count = state->parents_count;

    key.type = HASH_KEY_STRING;
    key.str = talloc_strdup(state, state->primary_name);
    if (!key.str) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    value.type = HASH_VALUE_PTR;
    value.ptr = ngr;

    hret = hash_enter(state->group_hash, &key, &value);
    if (hret != HASH_SUCCESS) {
        talloc_free(key.str);
        tevent_req_error(req, EIO);
        return;
    }
    talloc_free(key.str);

    if (state->parents_count == 0) {
        /* No parent groups for this group in LDAP
         * Move on to the next group
         */
        state->group_iter++;
        while (state->group_iter < state->num_groups) {
            ret = rfc2307bis_nested_groups_step(req);
            if (ret == EAGAIN) {
                /* Looking up parent groups.. */
                return;
            } else if (ret != EOK) {
                tevent_req_error(req, ret);
                return;
            }

            /* EOK means this group has already been processed
             * in another nesting level */
            state->group_iter++;
        }

        if (state->group_iter == state->num_groups) {
            /* All groups processed. Done. */
            tevent_req_done(req);
        }
        return;
    }

    /* Otherwise, recurse into the groups */
    subreq = rfc2307bis_nested_groups_send(
            state, state->ev, state->opts, state->sysdb,
            state->dom, state->sh,
            state->ldap_parents,
            state->parents_count,
            state->group_hash,
            state->nesting_level+1);
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
    struct sdap_rfc2307bis_nested_ctx *state =
            tevent_req_data(req, struct sdap_rfc2307bis_nested_ctx);

    ret = rfc2307bis_nested_groups_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(6, ("rfc2307bis_nested failed [%d][%s]\n",
                  ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    state->group_iter++;
    while (state->group_iter < state->num_groups) {
        ret = rfc2307bis_nested_groups_step(req);
        if (ret == EAGAIN) {
            /* Looking up parent groups.. */
            return;
        } else if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }

        /* EOK means this group has already been processed
         * in another nesting level */
        state->group_iter++;
    }

    if (state->group_iter == state->num_groups) {
        /* All groups processed. Done. */
        tevent_req_done(req);
        return;
    }
}

static int sdap_initgr_rfc2307bis_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}
