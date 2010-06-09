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
    errno_t ret;

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
        ret = ldap_id_cleanup_set_timer(ctx, tv);
        if (ret != EOK) {
            DEBUG(1, ("Error setting up cleanup timer\n"));
        }
        return;
    }
    tevent_req_set_callback(req, ldap_id_cleanup_reschedule, ctx);

    /* if cleanup takes so long, either we try to cleanup too
     * frequently, or something went seriously wrong */
    delay = dp_opt_get_int(ctx->opts->basic, SDAP_CACHE_PURGE_TIMEOUT);
    tv = tevent_timeval_current_ofs(delay, 0);
    timeout = tevent_add_timer(ctx->be->ev, req, tv,
                               ldap_id_cleanup_timeout, req);
    if (timeout == NULL) {
        /* If we can't guarantee a timeout, we
         * need to cancel the request, to avoid
         * the possibility of starting another
         * concurrently
         */
        talloc_zfree(req);

        DEBUG(1, ("Failed to schedule cleanup, retrying later!\n"));
        /* schedule starting from now, not the last run */
        delay = dp_opt_get_int(ctx->opts->basic, SDAP_CACHE_PURGE_TIMEOUT);
        tv = tevent_timeval_current_ofs(delay, 0);
        ret = ldap_id_cleanup_set_timer(ctx, tv);
        if (ret != EOK) {
            DEBUG(1, ("Error setting up cleanup timer\n"));
        }
        return;
    }
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

static int cleanup_users(TALLOC_CTX *memctx, struct sdap_id_ctx *ctx);
static int cleanup_groups(TALLOC_CTX *memctx,
                          struct sysdb_ctx *sysdb,
                          struct sss_domain_info *domain);

struct tevent_req *ldap_id_cleanup_send(TALLOC_CTX *memctx,
                                        struct tevent_context *ev,
                                        struct sdap_id_ctx *ctx)
{
    struct global_cleanup_state *state;
    struct tevent_req *req;
    int ret;

    req = tevent_req_create(memctx, &state, struct global_cleanup_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;

    ctx->last_purge = tevent_timeval_current();

    ret = cleanup_users(state, state->ctx);
    if (ret && ret != ENOENT) {
        goto fail;
    }

    ret = cleanup_groups(state,
                         state->ctx->be->sysdb,
                         state->ctx->be->domain);
    if (ret) {
        goto fail;
    }

    tevent_req_done(req);
    tevent_req_post(req, ev);
    return req;

fail:
    DEBUG(1, ("Failed to cleanup caches (%d [%s]), retrying later!\n",
              (int)ret, strerror(ret)));
    tevent_req_done(req);
    tevent_req_post(req, ev);
    return req;
}


/* ==User-Cleanup-Process================================================= */

static int cleanup_users_logged_in(hash_table_t *table,
                                   const struct ldb_message *msg);

static int cleanup_users(TALLOC_CTX *memctx, struct sdap_id_ctx *ctx)
{
    TALLOC_CTX *tmpctx;
    struct sysdb_ctx *sysdb = ctx->be->sysdb;
    struct sss_domain_info *domain = ctx->be->domain;
    const char *attrs[] = { SYSDB_NAME, SYSDB_UIDNUM, NULL };
    time_t now = time(NULL);
    char *subfilter = NULL;
    int account_cache_expiration;
    hash_table_t *uid_table;
    struct ldb_message **msgs;
    size_t count;
    const char *name;
    int ret;
    int i;

    tmpctx = talloc_new(memctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    account_cache_expiration = dp_opt_get_int(ctx->opts->basic,
                                           SDAP_ACCOUNT_CACHE_EXPIRATION);
    DEBUG(9, ("Cache expiration is set to %d days\n",
              account_cache_expiration));

    if (account_cache_expiration > 0) {
        subfilter = talloc_asprintf(tmpctx,
                                    "(&(!(%s=0))(%s<=%ld)(|(!(%s=*))(%s<=%ld)))",
                                    SYSDB_CACHE_EXPIRE,
                                    SYSDB_CACHE_EXPIRE,
                                    (long) now,
                                    SYSDB_LAST_LOGIN,
                                    SYSDB_LAST_LOGIN,
                                    (long) (now - (account_cache_expiration * 86400)));
    } else {
        subfilter = talloc_asprintf(tmpctx,
                                    "(&(!(%s=0))(%s<=%ld)(!(%s=*)))",
                                    SYSDB_CACHE_EXPIRE,
                                    SYSDB_CACHE_EXPIRE,
                                    (long) now,
                                    SYSDB_LAST_LOGIN);
    }
    if (!subfilter) {
        DEBUG(2, ("Failed to build filter\n"));
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_users(tmpctx, sysdb,
                             domain, subfilter, attrs, &count, &msgs);
    if (ret) {
        if (ret == ENOENT) {
            ret = EOK;
        }
        goto done;
    }

    DEBUG(4, ("Found %d expired user entries!\n", count));

    if (count == 0) {
        ret = EOK;
        goto done;
    }

    ret = get_uid_table(tmpctx, &uid_table);
    /* get_uid_table returns ENOSYS on non-Linux platforms. We proceed with
     * the cleanup in that case
     */
    if (ret != EOK && ret != ENOSYS) {
        goto done;
    }

    for (i = 0; i < count; i++) {
        name = ldb_msg_find_attr_as_string(msgs[i], SYSDB_NAME, NULL);
        if (!name) {
            DEBUG(2, ("Entry %s has no Name Attribute ?!?\n",
                       ldb_dn_get_linearized(msgs[i]->dn)));
            ret = EFAULT;
            goto done;
        }

        if (uid_table) {
            ret = cleanup_users_logged_in(uid_table, msgs[i]);
            if (ret == EOK) {
                /* If the user is logged in, proceed to the next one */
                DEBUG(5, ("User %s is still logged in, keeping data\n", name));
                continue;
            } else if (ret != ENOENT) {
                goto done;
            }
        }

        /* If not logged in or cannot check the table, delete him */
        DEBUG(9, ("About to delete user %s\n", name));
        ret = sysdb_delete_user(tmpctx, sysdb, domain, name, 0);
        if (ret) {
            goto done;
        }
    }

done:
    talloc_zfree(tmpctx);
    return ret;
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

/* ==Group-Cleanup-Process================================================ */

static int cleanup_groups(TALLOC_CTX *memctx,
                          struct sysdb_ctx *sysdb,
                          struct sss_domain_info *domain)
{
    TALLOC_CTX *tmpctx;
    const char *attrs[] = { SYSDB_NAME, NULL };
    time_t now = time(NULL);
    char *subfilter;
    const char *dn;
    struct ldb_message **msgs;
    size_t count;
    struct ldb_message **u_msgs;
    size_t u_count;
    int ret;
    int i;

    tmpctx = talloc_new(memctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    subfilter = talloc_asprintf(tmpctx, "(&(!(%s=0))(%s<=%ld))",
                                SYSDB_CACHE_EXPIRE,
                                SYSDB_CACHE_EXPIRE, (long)now);
    if (!subfilter) {
        DEBUG(2, ("Failed to build filter\n"));
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_groups(tmpctx, sysdb,
                              domain, subfilter, attrs, &count, &msgs);
    if (ret) {
        if (ret == ENOENT) {
            ret = EOK;
        }
        goto done;
    }

    DEBUG(4, ("Found %d expired group entries!\n", count));

    if (count == 0) {
        ret = EOK;
        goto done;
    }

    for (i = 0; i < count; i++) {
        dn = ldb_dn_get_linearized(msgs[i]->dn);
        if (!dn) {
            ret = EFAULT;
            goto done;
        }

        subfilter = talloc_asprintf(tmpctx, "(%s=%s)", SYSDB_MEMBEROF, dn);
        if (!subfilter) {
            DEBUG(2, ("Failed to build filter\n"));
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_search_users(tmpctx, sysdb,
                                 domain, subfilter, NULL, &u_count, &u_msgs);
        if (ret == ENOENT) {
            const char *name;

            name = ldb_msg_find_attr_as_string(msgs[i], SYSDB_NAME, NULL);
            if (!name) {
                DEBUG(2, ("Entry %s has no Name Attribute ?!?\n",
                          ldb_dn_get_linearized(msgs[i]->dn)));
                ret = EFAULT;
                goto done;
            }

            DEBUG(8, ("About to delete group %s\n", name));
            ret = sysdb_delete_group(tmpctx, sysdb, domain, name, 0);
            if (ret) {
                DEBUG(2, ("Group delete returned %d (%s)\n",
                          ret, strerror(ret)));
                goto done;
            }
        }
        if (ret != EOK) {
            goto done;
        }
        talloc_zfree(u_msgs);
    }

done:
    talloc_zfree(tmpctx);
    return ret;
}
