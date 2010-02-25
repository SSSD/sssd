/*
    SSSD

    LDAP Identity Cleanup Functions

    Authors:
        Simo Sorce <ssorce@redhat.com>

    Copyright (C) 2009 Red Hat

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

#include <errno.h>
#include <time.h>
#include <sys/time.h>

#include "util/util.h"
#include "util/find_uid.h"
#include "db/sysdb.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async.h"

/* ==Cleanup-Task========================================================= */

struct tevent_req *ldap_id_cleanup_send(TALLOC_CTX *memctx,
                                        struct tevent_context *ev,
                                        struct sdap_id_ctx *ctx);
static void ldap_id_cleanup_reschedule(struct tevent_req *req);

static void ldap_id_cleanup_timeout(struct tevent_context *ev,
                                      struct tevent_timer *te,
                                      struct timeval tv, void *pvt);

static void ldap_id_cleanup_timer(struct tevent_context *ev,
                                  struct tevent_timer *tt,
                                  struct timeval tv, void *pvt)
{
    struct sdap_id_ctx *ctx = talloc_get_type(pvt, struct sdap_id_ctx);
    struct tevent_timer *timeout;
    struct tevent_req *req;
    int delay;

    if (be_is_offline(ctx->be)) {
        DEBUG(4, ("Backend is marked offline, retry later!\n"));
        /* schedule starting from now, not the last run */
        delay = dp_opt_get_int(ctx->opts->basic, SDAP_CACHE_PURGE_TIMEOUT);
        tv = tevent_timeval_current_ofs(delay, 0);
        ldap_id_cleanup_set_timer(ctx, tv);
        return;
    }

    req = ldap_id_cleanup_send(ctx, ev, ctx);
    if (!req) {
        DEBUG(1, ("Failed to schedule cleanup, retrying later!\n"));
        /* schedule starting from now, not the last run */
        delay = dp_opt_get_int(ctx->opts->basic, SDAP_CACHE_PURGE_TIMEOUT);
        tv = tevent_timeval_current_ofs(delay, 0);
        ldap_id_cleanup_set_timer(ctx, tv);
        return;
    }
    tevent_req_set_callback(req, ldap_id_cleanup_reschedule, ctx);

    /* if cleanup takes so long, either we try to cleanup too
     * frequently, or something went seriously wrong */
    delay = dp_opt_get_int(ctx->opts->basic, SDAP_CACHE_PURGE_TIMEOUT);
    tv = tevent_timeval_current_ofs(delay, 0);
    timeout = tevent_add_timer(ctx->be->ev, req, tv,
                               ldap_id_cleanup_timeout, req);
    return;
}

static void ldap_id_cleanup_timeout(struct tevent_context *ev,
                                      struct tevent_timer *te,
                                      struct timeval tv, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_id_ctx *ctx = tevent_req_callback_data(req,
                                                       struct sdap_id_ctx);
    int delay;

    delay = dp_opt_get_int(ctx->opts->basic, SDAP_CACHE_PURGE_TIMEOUT);
    DEBUG(1, ("Cleanup timed out! Timeout too small? (%ds)!\n", delay));

    tv = tevent_timeval_current_ofs(delay, 0);
    ldap_id_cleanup_set_timer(ctx, tv);

    talloc_zfree(req);
}

static void ldap_id_cleanup_reschedule(struct tevent_req *req)
{
    struct sdap_id_ctx *ctx = tevent_req_callback_data(req,
                                                       struct sdap_id_ctx);
    enum tevent_req_state tstate;
    uint64_t err;
    struct timeval tv;
    int delay;

    if (tevent_req_is_error(req, &tstate, &err)) {
        /* On error schedule starting from now, not the last run */
        tv = tevent_timeval_current();
    } else {
        tv = ctx->last_purge;
    }
    talloc_zfree(req);

    delay = dp_opt_get_int(ctx->opts->basic, SDAP_CACHE_PURGE_TIMEOUT);
    tv = tevent_timeval_add(&tv, delay, 0);
    ldap_id_cleanup_set_timer(ctx, tv);
}



int ldap_id_cleanup_set_timer(struct sdap_id_ctx *ctx, struct timeval tv)
{
    struct tevent_timer *cleanup_task;

    DEBUG(6, ("Scheduling next cleanup at %ld.%ld\n",
              (long)tv.tv_sec, (long)tv.tv_usec));

    cleanup_task = tevent_add_timer(ctx->be->ev, ctx,
                                    tv, ldap_id_cleanup_timer, ctx);
    if (!cleanup_task) {
        DEBUG(0, ("FATAL: failed to setup cleanup task!\n"));
        return EFAULT;
    }

    return EOK;
}



struct global_cleanup_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;
};

static struct tevent_req *cleanup_users_send(TALLOC_CTX *memctx,
                                             struct tevent_context *ev,
                                             struct sdap_id_ctx *ctx);
static void ldap_id_cleanup_users_done(struct tevent_req *subreq);
static struct tevent_req *cleanup_groups_send(TALLOC_CTX *memctx,
                                          struct tevent_context *ev,
                                          struct sysdb_ctx *sysdb,
                                          struct sss_domain_info *domain);
static void ldap_id_cleanup_groups_done(struct tevent_req *subreq);

struct tevent_req *ldap_id_cleanup_send(TALLOC_CTX *memctx,
                                        struct tevent_context *ev,
                                        struct sdap_id_ctx *ctx)
{
    struct global_cleanup_state *state;
    struct tevent_req *req, *subreq;

    req = tevent_req_create(memctx, &state, struct global_cleanup_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;

    subreq = cleanup_users_send(state, ev, state->ctx);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, ldap_id_cleanup_users_done, req);

    ctx->last_purge = tevent_timeval_current();

    return req;
}

static void ldap_id_cleanup_users_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct global_cleanup_state *state = tevent_req_data(req,
                                                 struct global_cleanup_state);
    enum tevent_req_state tstate;
    uint64_t err = 0;

    if (tevent_req_is_error(subreq, &tstate, &err)) {
        if (tstate != TEVENT_REQ_USER_ERROR) {
            err = EIO;
        }
        if (err != ENOENT) {
            goto fail;
        }
    }
    talloc_zfree(subreq);

    subreq = cleanup_groups_send(state, state->ev,
                                 state->ctx->be->sysdb,
                                 state->ctx->be->domain);
    if (!subreq) {
        err = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, ldap_id_cleanup_groups_done, req);

    return;

fail:
    DEBUG(1, ("Failed to cleanup users (%d [%s]), retrying later!\n",
              (int)err, strerror(err)));
    tevent_req_done(req);
}

static void ldap_id_cleanup_groups_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(subreq, &tstate, &err)) {
        if (tstate != TEVENT_REQ_USER_ERROR) {
            err = EIO;
        }
        if (err != ENOENT) {
            goto fail;
        }
    }
    talloc_zfree(subreq);

    tevent_req_done(req);
    return;

fail:
    DEBUG(1, ("Failed to cleanup groups (%d [%s]), retrying later!\n",
              (int)err, strerror(err)));
    tevent_req_done(req);
}


/* ==User-Cleanup-Process================================================= */

struct cleanup_users_state {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;
    struct sdap_id_ctx *ctx;

    struct sysdb_handle *handle;

    hash_table_t *uid_table;

    struct ldb_message **msgs;
    size_t count;
    int cur;
};

static void cleanup_users_process(struct tevent_req *subreq);
static int cleanup_users_logged_in(hash_table_t *table,
                                   const struct ldb_message *msg);
static void cleanup_users_delete(struct tevent_req *req);
static void cleanup_users_next(struct tevent_req *req);
static void cleanup_users_delete_done(struct tevent_req *subreq);

static struct tevent_req *cleanup_users_send(TALLOC_CTX *memctx,
                                             struct tevent_context *ev,
                                             struct sdap_id_ctx *ctx)
{
    struct tevent_req *req, *subreq;
    struct cleanup_users_state *state;
    static const char *attrs[] = { SYSDB_NAME, SYSDB_UIDNUM, NULL };
    time_t now = time(NULL);
    char *subfilter = NULL;
    int account_cache_expiration;

    req = tevent_req_create(memctx, &state, struct cleanup_users_state);
    if (!req) {
        return NULL;
    }

    state->ev = ev;
    state->sysdb = ctx->be->sysdb;
    state->domain = ctx->be->domain;
    state->ctx  = ctx;
    state->msgs = NULL;
    state->count = 0;
    state->cur = 0;

    account_cache_expiration = dp_opt_get_int(state->ctx->opts->basic,
                                           SDAP_ACCOUNT_CACHE_EXPIRATION);
    DEBUG(9, ("Cache expiration is set to %d days\n",
              account_cache_expiration));

    if (account_cache_expiration > 0) {
        subfilter = talloc_asprintf(state,
                                    "(&(!(%s=0))(%s<=%ld)(|(!(%s=*))(%s<=%ld)))",
                                    SYSDB_CACHE_EXPIRE,
                                    SYSDB_CACHE_EXPIRE,
                                    (long) now,
                                    SYSDB_LAST_LOGIN,
                                    SYSDB_LAST_LOGIN,
                                    (long) (now - (account_cache_expiration * 86400)));
    } else {
        subfilter = talloc_asprintf(state,
                                    "(&(!(%s=0))(%s<=%ld)(!(%s=*)))",
                                    SYSDB_CACHE_EXPIRE,
                                    SYSDB_CACHE_EXPIRE,
                                    (long) now,
                                    SYSDB_LAST_LOGIN);
    }
    if (!subfilter) {
        DEBUG(2, ("Failed to build filter\n"));
        talloc_zfree(req);
        return NULL;
    }

    subreq = sysdb_search_users_send(state, state->ev,
                                     state->sysdb, NULL,
                                     state->domain, subfilter, attrs);
    if (!subreq) {
        DEBUG(2, ("Failed to send entry search\n"));
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, cleanup_users_process, req);
    return req;
}

static void cleanup_users_process(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct cleanup_users_state *state = tevent_req_data(req,
                                               struct cleanup_users_state);
    int ret;

    ret = sysdb_search_users_recv(subreq, state, &state->count, &state->msgs);
    talloc_zfree(subreq);
    if (ret) {
        if (ret == ENOENT) {
            tevent_req_done(req);
            return;
        }
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(4, ("Found %d expired user entries!\n", state->count));

    if (state->count == 0) {
        tevent_req_done(req);
    }

    ret = get_uid_table(state, &state->uid_table);
    /* get_uid_table returns ENOSYS on non-Linux platforms. We proceed with
     * the cleanup in that case
     */
    if (ret != EOK && ret != ENOSYS) {
        tevent_req_error(req, ret);
        return;
    }

    cleanup_users_delete(req);
}

static void cleanup_users_delete(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct cleanup_users_state *state = tevent_req_data(req,
                                               struct cleanup_users_state);
    const char *name;
    int ret;

    name = ldb_msg_find_attr_as_string(state->msgs[state->cur],
                                      SYSDB_NAME, NULL);
    if (!name) {
        DEBUG(2, ("Entry %s has no Name Attribute ?!?\n",
                  ldb_dn_get_linearized(state->msgs[state->cur]->dn)));
        tevent_req_error(req, EFAULT);
        return;
    }

    if (state->uid_table) {
        ret = cleanup_users_logged_in(state->uid_table, state->msgs[state->cur]);
        if (ret == EOK) {
            /* If the user is logged in, proceed to the next one */
            DEBUG(5, ("User %s is still logged in, keeping his data\n", name));
            cleanup_users_next(req);
            return;
        } else if (ret != ENOENT) {
            tevent_req_error(req, ret);
            return;
        }
    }

    /* If not logged in or cannot check the table, delete him */
    DEBUG(9, ("About to delete user %s\n", name));
    subreq = sysdb_delete_user_send(state, state->ev,
                                    state->sysdb, NULL,
                                    state->domain, name, 0);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, cleanup_users_delete_done, req);
    return;
}

static int cleanup_users_logged_in(hash_table_t *table,
                                   const struct ldb_message *msg)
{
    uid_t      uid;
    hash_key_t key;
    hash_value_t value;
    int        ret;

    uid = ldb_msg_find_attr_as_uint64(msg,
                                      SYSDB_UIDNUM, 0);
    if (!uid) {
        DEBUG(2, ("Entry %s has no UID Attribute ?!?\n",
                  ldb_dn_get_linearized(msg->dn)));
        return EFAULT;
    }

    key.type = HASH_KEY_ULONG;
    key.ul   = (unsigned long) uid;

    ret = hash_lookup(table, &key, &value);
    if (ret == HASH_SUCCESS) {
        return EOK;
    } else if (ret == HASH_ERROR_KEY_NOT_FOUND) {
        return ENOENT;
    }

    return EIO;
}

static void cleanup_users_next(struct tevent_req *req)
{
    struct cleanup_users_state *state = tevent_req_data(req,
                                               struct cleanup_users_state);

    state->cur++;
    if (state->cur < state->count) {
        cleanup_users_delete(req);
        return;
    }

    tevent_req_done(req);
}

static void cleanup_users_delete_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sysdb_delete_user_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        DEBUG(2, ("User delete returned %d (%s)\n",
                  ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    cleanup_users_next(req);
}

/* ==Group-Cleanup-Process================================================ */

struct cleanup_groups_state {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;

    struct sysdb_handle *handle;

    struct ldb_message **msgs;
    size_t count;
    int cur;
};

static void cleanup_groups_process(struct tevent_req *subreq);
static void cleanup_groups_check_users(struct tevent_req *req);
static void cleanup_groups_check_users_done(struct tevent_req *subreq);
static void cleanup_groups_next(struct tevent_req *req);
static void cleanup_groups_delete(struct tevent_req *req);
static void cleanup_groups_delete_done(struct tevent_req *subreq);

static struct tevent_req *cleanup_groups_send(TALLOC_CTX *memctx,
                                              struct tevent_context *ev,
                                              struct sysdb_ctx *sysdb,
                                              struct sss_domain_info *domain)
{
    struct tevent_req *req, *subreq;
    struct cleanup_groups_state *state;
    static const char *attrs[] = { SYSDB_NAME, NULL };
    time_t now = time(NULL);
    char *subfilter;

    req = tevent_req_create(memctx, &state, struct cleanup_groups_state);
    if (!req) {
        return NULL;
    }

    state->ev = ev;
    state->sysdb = sysdb;
    state->domain = domain;
    state->msgs = NULL;
    state->count = 0;
    state->cur = 0;

    subfilter = talloc_asprintf(state, "(&(!(%s=0))(%s<=%ld))",
                                SYSDB_CACHE_EXPIRE,
                                SYSDB_CACHE_EXPIRE, (long)now);
    if (!subfilter) {
        DEBUG(2, ("Failed to build filter\n"));
        talloc_zfree(req);
        return NULL;
    }

    subreq = sysdb_search_groups_send(state, state->ev,
                                      state->sysdb, NULL,
                                      state->domain, subfilter, attrs);
    if (!subreq) {
        DEBUG(2, ("Failed to send entry search\n"));
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, cleanup_groups_process, req);

    return req;
}

static void cleanup_groups_process(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct cleanup_groups_state *state = tevent_req_data(req,
                                               struct cleanup_groups_state);
    int ret;

    ret = sysdb_search_groups_recv(subreq, state, &state->count, &state->msgs);
    talloc_zfree(subreq);
    if (ret) {
        if (ret == ENOENT) {
            tevent_req_done(req);
            return;
        }
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(4, ("Found %d expired group entries!\n", state->count));

    if (state->count == 0) {
        tevent_req_done(req);
    }

    cleanup_groups_check_users(req);
}

static void cleanup_groups_check_users(struct tevent_req *req)
{
    struct cleanup_groups_state *state = tevent_req_data(req,
                                               struct cleanup_groups_state);
    struct tevent_req *subreq;
    const char *subfilter;
    const char *dn;

    dn = ldb_dn_get_linearized(state->msgs[state->cur]->dn);
    if (!dn) {
        tevent_req_error(req, EINVAL);
        return;
    }

    subfilter = talloc_asprintf(state, "(%s=%s)",
                                SYSDB_MEMBEROF, dn);
    if (!subfilter) {
        DEBUG(2, ("Failed to build filter\n"));
        tevent_req_error(req, ENOMEM);
    }

    subreq = sysdb_search_users_send(state, state->ev,
                                     state->sysdb, NULL,
                                     state->domain, subfilter, NULL);
    if (!subreq) {
        DEBUG(2, ("Failed to send entry search\n"));
        tevent_req_error(req, ENOMEM);
    }
    tevent_req_set_callback(subreq, cleanup_groups_check_users_done, req);
}

static void cleanup_groups_check_users_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct cleanup_groups_state *state = tevent_req_data(req,
                                               struct cleanup_groups_state);
    int ret;
    struct ldb_message **msgs;
    size_t count;

    ret = sysdb_search_users_recv(subreq, state, &count, &msgs);
    talloc_zfree(subreq);
    if (ret != EOK) {
        if (ret == ENOENT) {
            cleanup_groups_delete(req);
            return;
        }
        tevent_req_error(req, ret);
        return;
    }

    cleanup_groups_next(req);
}

static void cleanup_groups_next(struct tevent_req *req)
{
    struct cleanup_groups_state *state = tevent_req_data(req,
                                               struct cleanup_groups_state);

    state->cur++;
    if (state->cur < state->count) {
        cleanup_groups_check_users(req);
        return;
    }

    tevent_req_done(req);
}

static void cleanup_groups_delete(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct cleanup_groups_state *state = tevent_req_data(req,
                                               struct cleanup_groups_state);
    const char *name;

    name = ldb_msg_find_attr_as_string(state->msgs[state->cur],
                                      SYSDB_NAME, NULL);
    if (!name) {
        DEBUG(2, ("Entry %s has no Name Attribute ?!?\n",
                  ldb_dn_get_linearized(state->msgs[state->cur]->dn)));
        tevent_req_error(req, EFAULT);
        return;
    }

    DEBUG(8, ("About to delete group %s\n", name));
    subreq = sysdb_delete_group_send(state, state->ev,
                                     state->sysdb, NULL,
                                     state->domain, name, 0);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, cleanup_groups_delete_done, req);
}

static void cleanup_groups_delete_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sysdb_delete_group_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        DEBUG(2, ("Group delete returned %d (%s)\n", ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    cleanup_groups_next(req);
}

