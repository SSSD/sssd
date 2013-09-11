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
struct ldap_id_cleanup_ctx {
    struct sdap_id_ctx *ctx;
    struct sdap_domain *sdom;
};

static errno_t ldap_id_cleanup_set_timer(struct ldap_id_cleanup_ctx *cctx,
                                         struct timeval tv);

static void ldap_id_cleanup_timer(struct tevent_context *ev,
                                  struct tevent_timer *tt,
                                  struct timeval tv, void *pvt)
{
    struct ldap_id_cleanup_ctx *cctx = talloc_get_type(pvt,
                                                struct ldap_id_cleanup_ctx);
    int delay;
    errno_t ret;

    if (be_is_offline(cctx->ctx->be)) {
        DEBUG(SSSDBG_TRACE_FUNC, ("Backend is marked offline, retry later!\n"));
        /* schedule starting from now, not the last run */
        delay = dp_opt_get_int(cctx->ctx->opts->basic,
                               SDAP_CACHE_PURGE_TIMEOUT);
        tv = tevent_timeval_current_ofs(delay, 0);
        ldap_id_cleanup_set_timer(cctx, tv);
        return;
    }

    ret = ldap_id_cleanup(cctx->ctx->opts, cctx->sdom);
    if (ret != EOK) {
        /* On error schedule starting from now, not the last run */
        tv = tevent_timeval_current();
    } else {
        tv = cctx->sdom->last_purge;
    }

    delay = dp_opt_get_int(cctx->ctx->opts->basic, SDAP_CACHE_PURGE_TIMEOUT);
    tv = tevent_timeval_add(&tv, delay, 0);
    ldap_id_cleanup_set_timer(cctx, tv);
}

static errno_t ldap_id_cleanup_set_timer(struct ldap_id_cleanup_ctx *cctx,
                                         struct timeval tv)
{
    struct tevent_timer *cleanup_task;

    cleanup_task = tevent_add_timer(cctx->ctx->be->ev, cctx->ctx,
                                    tv, ldap_id_cleanup_timer, cctx);
    if (cleanup_task == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("FATAL: failed to setup cleanup task!\n"));
        return EFAULT;
    }

    return EOK;
}

int ldap_id_cleanup_create_timer(struct sdap_id_ctx *ctx,
                                 struct sdap_domain *sdom,
                                 struct timeval tv)
{
    struct ldap_id_cleanup_ctx *cctx;

    DEBUG(SSSDBG_FUNC_DATA,
          ("Scheduling next cleanup at %ld.%ld\n",
          (long)tv.tv_sec, (long)tv.tv_usec));

    cctx = talloc(ctx, struct ldap_id_cleanup_ctx);
    if (cctx == NULL) {
        return ENOMEM;
    }
    cctx->ctx = ctx;
    cctx->sdom = sdom;

    return ldap_id_cleanup_set_timer(cctx, tv);
}

static int cleanup_users(struct sdap_options *opts,
                         struct sss_domain_info *dom);
static int cleanup_groups(TALLOC_CTX *memctx,
                          struct sysdb_ctx *sysdb,
                          struct sss_domain_info *domain);

errno_t ldap_id_cleanup(struct sdap_options *opts,
                        struct sdap_domain *sdom)
{
    int ret, tret;
    bool in_transaction = false;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_transaction_start(sdom->dom->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to start transaction\n"));
        goto done;
    }
    in_transaction = true;

    ret = cleanup_users(opts, sdom->dom);
    if (ret && ret != ENOENT) {
        goto done;
    }

    ret = cleanup_groups(tmp_ctx, sdom->dom->sysdb, sdom->dom);
    if (ret) {
        goto done;
    }

    ret = sysdb_transaction_commit(sdom->dom->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to commit transaction\n"));
        goto done;
    }
    in_transaction = false;

    sdom->last_purge = tevent_timeval_current();
    ret = EOK;
done:
    if (in_transaction) {
        tret = sysdb_transaction_cancel(sdom->dom->sysdb);
        if (tret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Could not cancel transaction\n"));
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}


/* ==User-Cleanup-Process================================================= */

static int cleanup_users_logged_in(hash_table_t *table,
                                   const struct ldb_message *msg);

static int cleanup_users(struct sdap_options *opts,
                         struct sss_domain_info *dom)
{
    TALLOC_CTX *tmpctx;
    struct sysdb_ctx *sysdb = dom->sysdb;
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

    tmpctx = talloc_new(NULL);
    if (!tmpctx) {
        return ENOMEM;
    }

    account_cache_expiration = dp_opt_get_int(opts->basic, SDAP_ACCOUNT_CACHE_EXPIRATION);
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

    ret = sysdb_search_users(tmpctx, sysdb, dom,
                             subfilter, attrs, &count, &msgs);
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
                DEBUG(5, ("User %s is still logged in or a dummy entry, "
                          "keeping data\n", name));
                continue;
            } else if (ret != ENOENT) {
                goto done;
            }
        }

        /* If not logged in or cannot check the table, delete him */
        DEBUG(9, ("About to delete user %s\n", name));
        ret = sysdb_delete_user(sysdb, dom, name, 0);
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
        DEBUG(SSSDBG_OP_FAILURE, ("Entry %s has no UID Attribute!\n",
                  ldb_dn_get_linearized(msg->dn)));
        return ENOENT;
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
    const char *attrs[] = { SYSDB_NAME, SYSDB_GIDNUM, NULL };
    time_t now = time(NULL);
    char *subfilter;
    const char *dn;
    gid_t gid;
    struct ldb_message **msgs;
    size_t count;
    struct ldb_message **u_msgs;
    size_t u_count;
    int ret;
    int i;
    const char *posix;
    struct ldb_dn *base_dn;

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

    ret = sysdb_search_groups(tmpctx, sysdb, domain,
                              subfilter, attrs, &count, &msgs);
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

        posix = ldb_msg_find_attr_as_string(msgs[i], SYSDB_POSIX, NULL);
        if (!posix || strcmp(posix, "TRUE") == 0) {
            /* Search for users that are members of this group, or
             * that have this group as their primary GID.
             * Include subdomain users as well.
             */
            gid = (gid_t) ldb_msg_find_attr_as_uint(msgs[i], SYSDB_GIDNUM, 0);
            subfilter = talloc_asprintf(tmpctx, "(&(%s=%s)(|(%s=%s)(%s=%lu)))",
                                        SYSDB_OBJECTCLASS, SYSDB_USER_CLASS,
                                        SYSDB_MEMBEROF, dn,
                                        SYSDB_GIDNUM, (long unsigned) gid);
        } else {
            subfilter = talloc_asprintf(tmpctx, "(%s=%s)", SYSDB_MEMBEROF, dn);
        }
        if (!subfilter) {
            DEBUG(2, ("Failed to build filter\n"));
            ret = ENOMEM;
            goto done;
        }

        base_dn = sysdb_base_dn(sysdb, tmpctx);
        if (base_dn == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, ("Failed to build base dn\n"));
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_search_entry(tmpctx, sysdb, base_dn,
                                 LDB_SCOPE_SUBTREE, subfilter, NULL,
                                 &u_count, &u_msgs);
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
            ret = sysdb_delete_group(sysdb, domain, name, 0);
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
