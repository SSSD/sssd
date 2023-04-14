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

static errno_t ldap_cleanup_task(TALLOC_CTX *mem_ctx,
                                 struct tevent_context *ev,
                                 struct be_ctx *be_ctx,
                                 struct be_ptask *be_ptask,
                                 void *pvt)
{
    struct ldap_id_cleanup_ctx *cleanup_ctx = NULL;

    cleanup_ctx = talloc_get_type(pvt, struct ldap_id_cleanup_ctx);
    return ldap_id_cleanup(cleanup_ctx->ctx, cleanup_ctx->sdom);
}

errno_t ldap_id_setup_cleanup(struct sdap_id_ctx *id_ctx,
                              struct sdap_domain *sdom)
{
    errno_t ret;
    time_t first_delay;
    time_t period;
    time_t offset;
    struct ldap_id_cleanup_ctx *cleanup_ctx = NULL;
    char *name = NULL;

    period = dp_opt_get_int(id_ctx->opts->basic, SDAP_PURGE_CACHE_TIMEOUT);
    if (period == 0) {
        /* Cleanup has been explicitly disabled, so we won't
         * create any cleanup tasks. */
        ret = EOK;
        goto done;
    }
    offset = dp_opt_get_int(id_ctx->opts->basic, SDAP_PURGE_CACHE_OFFSET);

    /* Run the first one in a couple of seconds so that we have time to
     * finish initializations first. */
    first_delay = 10;

    cleanup_ctx = talloc_zero(sdom, struct ldap_id_cleanup_ctx);
    if (cleanup_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    cleanup_ctx->ctx = id_ctx;
    cleanup_ctx->sdom = sdom;

    name = talloc_asprintf(cleanup_ctx, "Cleanup [id] of %s", sdom->dom->name);
    if (name == NULL) {
        return ENOMEM;
    }

    ret = be_ptask_create_sync(id_ctx, id_ctx->be, period, first_delay,
                               5 /* enabled delay */, offset /* random offset */,
                               period /* timeout */, 0,
                               ldap_cleanup_task, cleanup_ctx, name,
                               BE_PTASK_OFFLINE_SKIP,
                               &id_ctx->task);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to initialize cleanup periodic "
                                     "task for %s\n", sdom->dom->name);
        goto done;
    }

    ret = EOK;

done:
    talloc_free(name);
    if (ret != EOK) {
        talloc_free(cleanup_ctx);
    }

    return ret;
}

static int cleanup_users(struct sdap_options *opts,
                         struct sss_domain_info *dom);
static int cleanup_groups(TALLOC_CTX *memctx,
                          struct sysdb_ctx *sysdb,
                          struct sss_domain_info *domain);

errno_t ldap_id_cleanup(struct sdap_id_ctx *ctx,
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
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto done;
    }
    in_transaction = true;

    ret = cleanup_users(ctx->opts, sdom->dom);
    if (ret && ret != ENOENT) {
        goto done;
    }

    ret = cleanup_groups(tmp_ctx, sdom->dom->sysdb, sdom->dom);
    if (ret) {
        goto done;
    }

    ret = sysdb_transaction_commit(sdom->dom->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction\n");
        goto done;
    }
    in_transaction = false;

    ctx->last_purge = tevent_timeval_current();
    ret = EOK;
done:
    if (in_transaction) {
        tret = sysdb_transaction_cancel(sdom->dom->sysdb);
        if (tret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not cancel transaction\n");
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}


/* ==User-Cleanup-Process================================================= */

static int cleanup_users_logged_in(hash_table_t *table,
                                   const struct ldb_message *msg);

static errno_t expire_memberof_target_groups(struct sss_domain_info *dom,
                                             struct ldb_message *user);

static int cleanup_users(struct sdap_options *opts,
                         struct sss_domain_info *dom)
{
    TALLOC_CTX *tmpctx;
    const char *attrs[] = { SYSDB_NAME, SYSDB_UIDNUM, SYSDB_MEMBEROF, NULL };
    time_t now = time(NULL);
    char *subfilter = NULL;
    char *ts_subfilter = NULL;
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
    DEBUG(SSSDBG_TRACE_ALL, "Cache expiration is set to %d days\n",
              account_cache_expiration);

    if (account_cache_expiration > 0) {
        subfilter = talloc_asprintf(tmpctx,
                                    "(&(!(%s=0))(|(!(%s=*))(%s<=%"SPRItime")))",
                                    SYSDB_CACHE_EXPIRE,
                                    SYSDB_LAST_LOGIN,
                                    SYSDB_LAST_LOGIN,
                                    (now - (account_cache_expiration * 86400)));

        ts_subfilter = talloc_asprintf(tmpctx,
                            "(&(!(%s=0))(%s<=%"SPRItime")(|(!(%s=*))(%s<=%"SPRItime")))",
                            SYSDB_CACHE_EXPIRE,
                            SYSDB_CACHE_EXPIRE,
                            now,
                            SYSDB_LAST_LOGIN,
                            SYSDB_LAST_LOGIN,
                            (now - (account_cache_expiration * 86400)));
    } else {
        subfilter = talloc_asprintf(tmpctx,
                                    "(&(!(%s=0))(!(%s=*)))",
                                    SYSDB_CACHE_EXPIRE,
                                    SYSDB_LAST_LOGIN);

        ts_subfilter = talloc_asprintf(tmpctx,
                                       "(&(!(%s=0))(%s<=%"SPRItime")(!(%s=*)))",
                                       SYSDB_CACHE_EXPIRE,
                                       SYSDB_CACHE_EXPIRE,
                                       now,
                                       SYSDB_LAST_LOGIN);
    }
    if (subfilter == NULL || ts_subfilter == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to build filter\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_users_by_timestamp(tmpctx, dom, subfilter, ts_subfilter,
                                          attrs, &count, &msgs);
    if (ret == ENOENT) {
        count = 0;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_search_users failed: %d\n", ret);
        goto done;
    }
    DEBUG(SSSDBG_FUNC_DATA, "Found %zu expired user entries!\n", count);

    if (count == 0) {
        ret = EOK;
        goto done;
    }

    ret = get_uid_table(tmpctx, &uid_table);
    /* get_uid_table returns ENOSYS on non-Linux platforms. We proceed with
     * the cleanup in that case
     */
    if (ret != EOK && ret != ENOSYS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "get_uid_table failed: %d\n", ret);
        goto done;
    }

    for (i = 0; i < count; i++) {
        name = ldb_msg_find_attr_as_string(msgs[i], SYSDB_NAME, NULL);
        if (!name) {
            DEBUG(SSSDBG_OP_FAILURE, "Entry %s has no Name Attribute ?!?\n",
                       ldb_dn_get_linearized(msgs[i]->dn));
            ret = EFAULT;
            goto done;
        }
        DEBUG(SSSDBG_TRACE_ALL, "Processing user %s\n", name);

        if (uid_table) {
            ret = cleanup_users_logged_in(uid_table, msgs[i]);
            if (ret == EOK) {
                /* If the user is logged in, proceed to the next one */
                DEBUG(SSSDBG_FUNC_DATA,
                      "User %s is still logged in or a dummy entry, "
                          "keeping data\n", name);
                continue;
            } else if (ret != ENOENT) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Cannot check if user is logged in: %d\n", ret);
                goto done;
            }
        }

        /* If not logged in or cannot check the table, delete him */
        DEBUG(SSSDBG_TRACE_ALL, "About to delete user %s\n", name);
        ret = sysdb_delete_user(dom, name, 0);
        if (ret) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_delete_user failed: %d\n", ret);
            goto done;
        }

        /* Mark all groups of which user was a member as expired in cache,
         * so that its ghost/member attributes are refreshed on next
         * request. */
        ret = expire_memberof_target_groups(dom, msgs[i]);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "expire_memberof_target_groups failed: [%d]:%s\n",
                  ret, sss_strerror(ret));
            goto done;
        }
    }

done:
    talloc_zfree(tmpctx);
    return ret;
}

static errno_t expire_memberof_target_groups(struct sss_domain_info *dom,
                                             struct ldb_message *user)
{
    struct ldb_message_element *memberof_el = NULL;
    errno_t ret;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    memberof_el = ldb_msg_find_element(user, SYSDB_MEMBEROF);
    if (memberof_el == NULL) {
        /* User has no cached groups. Nothing to be marked as expired. */
        ret = EOK;
        goto done;
    }

    for (unsigned int i = 0; i < memberof_el->num_values; i++) {
        ret = sysdb_mark_entry_as_expired_ldb_val(dom,
                                                  &memberof_el->values[i]);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "sysdb_mark_entry_as_expired_ldb_val failed: [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
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
        DEBUG(SSSDBG_OP_FAILURE, "Entry %s has no UID Attribute!\n",
                  ldb_dn_get_linearized(msg->dn));
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

    DEBUG(SSSDBG_OP_FAILURE, "hash_lookup failed: %d\n", ret);
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
    char *ts_subfilter;
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

    subfilter = talloc_asprintf(tmpctx, "(!(%s=0))", SYSDB_CACHE_EXPIRE);
    if (subfilter == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to build filter\n");
        ret = ENOMEM;
        goto done;
    }

    ts_subfilter = talloc_asprintf(tmpctx, "(&(!(%s=0))(%s<=%"SPRItime"))",
                                   SYSDB_CACHE_EXPIRE, SYSDB_CACHE_EXPIRE, now);
    if (ts_subfilter == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to build filter\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_groups_by_timestamp(tmpctx, domain, subfilter,
                                           ts_subfilter, attrs, &count, &msgs);
    if (ret == ENOENT) {
        count = 0;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_search_groups failed: %d\n", ret);
        goto done;
    }

    DEBUG(SSSDBG_FUNC_DATA, "Found %zu expired group entries!\n", count);

    if (count == 0) {
        ret = EOK;
        goto done;
    }

    for (i = 0; i < count; i++) {
        char *sanitized_dn;

        dn = ldb_dn_get_linearized(msgs[i]->dn);
        if (!dn) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Cannot linearize DN!\n");
            ret = EFAULT;
            goto done;
        }

        /* sanitize dn */
        ret = sss_filter_sanitize_dn(tmpctx, dn, &sanitized_dn);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "sss_filter_sanitize failed: %s:[%d]\n",
                  sss_strerror(ret), ret);
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
                                        SYSDB_OBJECTCATEGORY, SYSDB_USER_CLASS,
                                        SYSDB_MEMBEROF, sanitized_dn,
                                        SYSDB_GIDNUM, (long unsigned) gid);
        } else {
            subfilter = talloc_asprintf(tmpctx, "(%s=%s)", SYSDB_MEMBEROF,
                                        sanitized_dn);
        }
        talloc_zfree(sanitized_dn);

        if (!subfilter) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to build filter\n");
            ret = ENOMEM;
            goto done;
        }

        base_dn = sysdb_base_dn(sysdb, tmpctx);
        if (base_dn == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to build base dn\n");
            ret = ENOMEM;
            goto done;
        }

        DEBUG(SSSDBG_TRACE_LIBS, "Searching with: %s\n", subfilter);

        ret = sysdb_search_entry(tmpctx, sysdb, base_dn,
                                 LDB_SCOPE_SUBTREE, subfilter, NULL,
                                 &u_count, &u_msgs);
        if (ret == ENOENT) {
            const char *name;

            name = ldb_msg_find_attr_as_string(msgs[i], SYSDB_NAME, NULL);
            if (!name) {
                DEBUG(SSSDBG_OP_FAILURE, "Entry %s has no Name Attribute ?!?\n",
                          ldb_dn_get_linearized(msgs[i]->dn));
                ret = EFAULT;
                goto done;
            }

            DEBUG(SSSDBG_TRACE_INTERNAL, "About to delete group %s\n", name);
            ret = sysdb_delete_group(domain, name, 0);
            if (ret) {
                DEBUG(SSSDBG_OP_FAILURE, "Group delete returned %d (%s)\n",
                          ret, strerror(ret));
                goto done;
            }
        } else if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to search sysdb using %s: [%d] %s\n",
                  subfilter, ret, sss_strerror(ret));
            goto done;
        }
        talloc_zfree(u_msgs);
    }

done:
    talloc_zfree(tmpctx);
    return ret;
}
