/*
    SSSD

    Authors:
        Simo Sorce <ssorce@redhat.com>
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2008-2011 Simo Sorce <ssorce@redhat.com>
    Copyright (C) 2008-2011 Stephen Gallagher

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
#include "db/sysdb_private.h"
#include "db/sysdb_autofs.h"
#include "db/sysdb_iphosts.h"
#include "db/sysdb_ipnetworks.h"

struct upgrade_ctx {
    struct ldb_context *ldb;
    const char *new_version;
};

static errno_t commence_upgrade(TALLOC_CTX *mem_ctx, struct ldb_context *ldb,
                                const char *new_ver, struct upgrade_ctx **_ctx)
{
    struct upgrade_ctx *ctx;
    int ret;

    DEBUG(SSSDBG_IMPORTANT_INFO, "UPGRADING DB TO VERSION %s\n", new_ver);

    ctx = talloc(mem_ctx, struct upgrade_ctx);
    if (!ctx) {
        return ENOMEM;
    }

    ctx->ldb = ldb;
    ctx->new_version = new_ver;

    ret = ldb_transaction_start(ldb);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(ctx);
    } else {
        *_ctx = ctx;
    }
    return ret;
}

static errno_t update_version(struct upgrade_ctx *ctx)
{
    struct ldb_message *msg = NULL;
    errno_t ret;

    msg = ldb_msg_new(ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(msg, ctx->ldb, SYSDB_BASE);
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "version", LDB_FLAG_MOD_REPLACE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "version", ctx->new_version);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(ctx->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = EOK;

done:
    talloc_free(msg);
    return ret;
}

static int finish_upgrade(int ret, struct upgrade_ctx **ctx, const char **ver)
{
    int lret;

    if (ret == EOK) {
        lret = ldb_transaction_commit((*ctx)->ldb);
        ret = sysdb_error_to_errno(lret);
        if (ret == EOK) {
            *ver = (*ctx)->new_version;
        }
    }

    if (ret != EOK) {
        lret = ldb_transaction_cancel((*ctx)->ldb);
        if (lret != LDB_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Could not cancel transaction! [%s]\n",
                   ldb_strerror(lret));
            /* Do not overwrite ret here, we want to return
             * the original failure, not the failure of the
             * transaction cancellation.
             */
        }
    }

    talloc_zfree(*ctx);
    return ret;
}

/* serach all groups that have a memberUid attribute.
 * change it into a member attribute for a user of same domain.
 * remove the memberUid attribute
 * add the new member attribute
 * finally stop indexing memberUid
 * upgrade version to 0.2
 */
int sysdb_upgrade_01(struct ldb_context *ldb, const char **ver)
{
    struct ldb_message_element *el;
    struct ldb_result *res;
    struct ldb_dn *basedn;
    struct ldb_dn *mem_dn;
    struct ldb_message *msg;
    const struct ldb_val *val;
    /* No change needed because this version has objectclass group */
    const char *filter = "(&(memberUid=*)(objectclass=group))";
    const char *attrs[] = { "memberUid", NULL };
    const char *mdn;
    char *domain;
    int ret, i, j;
    TALLOC_CTX *tmp_ctx;
    struct upgrade_ctx *ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = commence_upgrade(tmp_ctx, ldb, SYSDB_VERSION_0_2, &ctx);
    if (ret) {
        talloc_free(tmp_ctx);
        return ret;
    }

    basedn = ldb_dn_new(tmp_ctx, ldb, SYSDB_BASE);
    if (!basedn) {
        ret = EIO;
        goto done;
    }

    ret = ldb_search(ldb, tmp_ctx, &res,
                     basedn, LDB_SCOPE_SUBTREE,
                     attrs, "%s", filter);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    for (i = 0; i < res->count; i++) {
        el = ldb_msg_find_element(res->msgs[i], "memberUid");
        if (!el) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "memberUid is missing from message [%s], skipping\n",
                      ldb_dn_get_linearized(res->msgs[i]->dn));
            continue;
        }

        /* create modification message */
        msg = ldb_msg_new(tmp_ctx);
        if (!msg) {
            ret = ENOMEM;
            goto done;
        }
        msg->dn = res->msgs[i]->dn;

        ret = ldb_msg_add_empty(msg, "memberUid", LDB_FLAG_MOD_DELETE, NULL);
        if (ret != LDB_SUCCESS) {
            ret = ENOMEM;
            goto done;
        }

        ret = ldb_msg_add_empty(msg, SYSDB_MEMBER, LDB_FLAG_MOD_ADD, NULL);
        if (ret != LDB_SUCCESS) {
            ret = ENOMEM;
            goto done;
        }

        /* get domain name component value */
        val = ldb_dn_get_component_val(res->msgs[i]->dn, 2);
        domain = talloc_strndup(tmp_ctx, (const char *)val->data, val->length);
        if (!domain) {
            ret = ENOMEM;
            goto done;
        }

        for (j = 0; j < el->num_values; j++) {
            mem_dn = ldb_dn_new_fmt(tmp_ctx, ldb, SYSDB_TMPL_USER,
                                    (const char *)el->values[j].data, domain);
            if (!mem_dn) {
                ret = ENOMEM;
                goto done;
            }

            mdn = talloc_strdup(msg, ldb_dn_get_linearized(mem_dn));
            if (!mdn) {
                ret = ENOMEM;
                goto done;
            }
            ret = ldb_msg_add_string(msg, SYSDB_MEMBER, mdn);
            if (ret != LDB_SUCCESS) {
                ret = ENOMEM;
                goto done;
            }

            talloc_zfree(mem_dn);
        }

        /* ok now we are ready to modify the entry */
        ret = ldb_modify(ldb, msg);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        talloc_zfree(msg);
    }

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_check_upgrade_02(struct sss_domain_info *domains,
                           const char *db_path)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct ldb_context *ldb;
    char *ldb_file;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *dom;
    struct ldb_message_element *el;
    struct ldb_message *msg;
    struct ldb_result *res;
    struct ldb_dn *verdn;
    const char *version = NULL;
    bool do_02_upgrade = false;
    bool ctx_trans = false;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ldb_file = talloc_asprintf(tmp_ctx, "%s/"LOCAL_SYSDB_FILE,
                               db_path);
    if (ldb_file == NULL) {
        ret = ENOMEM;
        goto exit;
    }

    ret = sysdb_ldb_connect(tmp_ctx, ldb_file, 0, &ldb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_ldb_connect failed.\n");
        return ret;
    }

    verdn = ldb_dn_new(tmp_ctx, ldb, SYSDB_BASE);
    if (!verdn) {
        ret = EIO;
        goto exit;
    }

    ret = ldb_search(ldb, tmp_ctx, &res,
                     verdn, LDB_SCOPE_BASE,
                     NULL, NULL);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto exit;
    }
    if (res->count > 1) {
        ret = EIO;
        goto exit;
    }

    if (res->count == 1) {
        el = ldb_msg_find_element(res->msgs[0], "version");
        if (el) {
            if (el->num_values != 1) {
                ret = EINVAL;
                goto exit;
            }
            version = talloc_strndup(tmp_ctx,
                                     (char *)(el->values[0].data),
                                     el->values[0].length);
            if (!version) {
                ret = ENOMEM;
                goto exit;
            }

            if (strcmp(version, SYSDB_VERSION) == 0) {
                /* all fine, return */
                ret = EOK;
                goto exit;
            }

            DEBUG(SSSDBG_CONF_SETTINGS,
                  "Upgrading DB from version: %s\n", version);

            if (strcmp(version, SYSDB_VERSION_0_1) == 0) {
                /* convert database */
                ret = sysdb_upgrade_01(ldb, &version);
                if (ret != EOK) goto exit;
            }

            if (strcmp(version, SYSDB_VERSION_0_2) == 0) {
                /* need to convert database to split files */
                do_02_upgrade = true;
            }

        }
    }

    if (!do_02_upgrade) {
        /* not a v2 upgrade, return and let the normal code take over any
        * further upgrade */
        ret = EOK;
        goto exit;
    }

    /* == V2->V3 UPGRADE == */

    DEBUG(SSSDBG_IMPORTANT_INFO,
          "UPGRADING DB TO VERSION %s\n", SYSDB_VERSION_0_3);

    /* ldb uses posix locks,
     * posix is stupid and kills all locks when you close *any* file
     * descriptor associated to the same file.
     * Therefore we must close and reopen the ldb file here */

    /* == Backup and reopen ldb == */

    /* close */
    talloc_zfree(ldb);

    /* backup*/
    ret = backup_file(ldb_file, SSSDBG_FATAL_FAILURE);
    if (ret != EOK) {
        goto exit;
    }

    /* reopen */
    ret = sysdb_ldb_connect(tmp_ctx, ldb_file, 0, &ldb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_ldb_connect failed.\n");
        return ret;
    }

    /* open a transaction */
    ret = ldb_transaction_start(ldb);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to start ldb transaction! (%d)\n", ret);
        ret = EIO;
        goto exit;
    }

    /* == Upgrade contents == */

    for (dom = domains; dom; dom = dom->next) {
        struct ldb_dn *domain_dn;
        struct ldb_dn *users_dn;
        struct ldb_dn *groups_dn;
        int i;

        /* create new dom db */
        ret = sysdb_domain_init_internal(tmp_ctx, dom,
                                         db_path, false, &sysdb);
        if (ret != EOK) {
            goto done;
        }

        ret = ldb_transaction_start(sysdb->ldb);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to start ldb transaction! (%d)\n", ret);
            ret = EIO;
            goto done;
        }
        ctx_trans = true;

        /* search all entries for this domain in local,
         * copy them all in the new database,
         * then remove them from local */

        domain_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                                   SYSDB_DOM_BASE, dom->name);
        if (!domain_dn) {
            ret = ENOMEM;
            goto done;
        }

        ret = ldb_search(ldb, tmp_ctx, &res,
                         domain_dn, LDB_SCOPE_SUBTREE,
                         NULL, NULL);
        if (ret != LDB_SUCCESS) {
            ret = EIO;
            goto done;
        }

        /*
         * dom->sysdb->ldb is not initialized,
         * so ldb_dn_new_fmt() shouldn't be changed to sysdb_*_base_dn()
         */
        users_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                                  SYSDB_TMPL_USER_BASE, dom->name);
        if (!users_dn) {
            ret = ENOMEM;
            goto done;
        }

        /*
         * dom->sysdb->ldb is not initialized,
         * so ldb_dn_new_fmt() shouldn't be changed to sysdb_*_base_dn()
         */
        groups_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                                   SYSDB_TMPL_GROUP_BASE, dom->name);
        if (!groups_dn) {
            ret = ENOMEM;
            goto done;
        }

        for (i = 0; i < res->count; i++) {

            struct ldb_dn *orig_dn;

            msg = res->msgs[i];

            /* skip pre-created congtainers */
            if ((ldb_dn_compare(msg->dn, domain_dn) == 0) ||
                (ldb_dn_compare(msg->dn, users_dn) == 0) ||
                (ldb_dn_compare(msg->dn, groups_dn) == 0)) {
                continue;
            }

            /* regenerate the DN against the new ldb as it may have different
             * casefolding rules (example: name changing from case insensitive
             * to case sensitive) */
            orig_dn = msg->dn;
            msg->dn = ldb_dn_new(msg, sysdb->ldb,
                                 ldb_dn_get_linearized(orig_dn));
            if (!msg->dn) {
                ret = ENOMEM;
                goto done;
            }

            ret = ldb_add(sysdb->ldb, msg);
            if (ret != LDB_SUCCESS) {
                DEBUG(SSSDBG_FATAL_FAILURE, "WARNING: Could not add entry %s,"
                          " to new ldb file! (%d [%s])\n",
                          ldb_dn_get_linearized(msg->dn),
                          ret, ldb_errstring(sysdb->ldb));
            }

            ret = ldb_delete(ldb, orig_dn);
            if (ret != LDB_SUCCESS) {
                DEBUG(SSSDBG_FATAL_FAILURE,
                      "WARNING: Could not remove entry %s,"
                          " from old ldb file! (%d [%s])\n",
                          ldb_dn_get_linearized(orig_dn),
                          ret, ldb_errstring(ldb));
            }
        }

        /* now remove the basic containers from local */
        /* these were optional so debug at level 9 in case
         * of failure just for tracing */
        ret = ldb_delete(ldb, groups_dn);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_TRACE_ALL, "WARNING: Could not remove entry %s,"
                      " from old ldb file! (%d [%s])\n",
                      ldb_dn_get_linearized(groups_dn),
                      ret, ldb_errstring(ldb));
        }
        ret = ldb_delete(ldb, users_dn);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_TRACE_ALL, "WARNING: Could not remove entry %s,"
                      " from old ldb file! (%d [%s])\n",
                      ldb_dn_get_linearized(users_dn),
                      ret, ldb_errstring(ldb));
        }
        ret = ldb_delete(ldb, domain_dn);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_TRACE_ALL, "WARNING: Could not remove entry %s,"
                      " from old ldb file! (%d [%s])\n",
                      ldb_dn_get_linearized(domain_dn),
                      ret, ldb_errstring(ldb));
        }

        ret = ldb_transaction_commit(sysdb->ldb);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to commit ldb transaction! (%d)\n", ret);
            ret = EIO;
            goto done;
        }
        ctx_trans = false;

        talloc_zfree(domain_dn);
        talloc_zfree(groups_dn);
        talloc_zfree(users_dn);
        talloc_zfree(res);
    }

    /* conversion done, upgrade version number */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, ldb, SYSDB_BASE);
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "version", LDB_FLAG_MOD_REPLACE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "version", SYSDB_VERSION_0_3);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = ldb_transaction_commit(ldb);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to commit ldb transaction! (%d)\n", ret);
        ret = EIO;
        goto exit;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        if (ctx_trans) {
            ret = ldb_transaction_cancel(sysdb->ldb);
            if (ret != LDB_SUCCESS) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Failed to cancel ldb transaction! (%d)\n", ret);
            }
        }
        ret = ldb_transaction_cancel(ldb);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to cancel ldb transaction! (%d)\n", ret);
        }
    }

exit:
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_upgrade_03(struct sysdb_ctx *sysdb, const char **ver)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_message *msg;
    struct upgrade_ctx *ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_4, &ctx);
    if (ret) {
        return ret;
    }

    /* Make this database case-sensitive */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, "@ATTRIBUTES");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "name", LDB_FLAG_MOD_DELETE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_upgrade_04(struct sysdb_ctx *sysdb, const char **ver)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_message *msg;
    struct upgrade_ctx *ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_5, &ctx);
    if (ret) {
        return ret;
    }

    /* Add new index */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, "@INDEXLIST");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "@IDXATTR", LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "@IDXATTR", "originalDN");
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* Rebuild memberuid and memberoif attributes */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, "@MEMBEROF-REBUILD");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_add(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_upgrade_05(struct sysdb_ctx *sysdb, const char **ver)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_message *msg;
    struct upgrade_ctx *ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_6, &ctx);
    if (ret) {
        return ret;
    }

    /* Add new indexes */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, "@INDEXLIST");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    /* Add Index for dataExpireTimestamp */
    ret = ldb_msg_add_empty(msg, "@IDXATTR", LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "@IDXATTR", "dataExpireTimestamp");
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    /* Add index to speed up ONELEVEL searches */
    ret = ldb_msg_add_empty(msg, "@IDXONE", LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "@IDXONE", "1");
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_upgrade_06(struct sysdb_ctx *sysdb, const char **ver)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_message *msg;
    struct upgrade_ctx *ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_7, &ctx);
    if (ret) {
        return ret;
    }

    /* Add new indexes */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, "@ATTRIBUTES");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    /* Case insensitive search for originalDN */
    ret = ldb_msg_add_empty(msg, SYSDB_ORIG_DN, LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, SYSDB_ORIG_DN, "CASE_INSENSITIVE");
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_upgrade_07(struct sysdb_ctx *sysdb, const char **ver)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_message *msg;
    struct upgrade_ctx *ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_8, &ctx);
    if (ret) {
        return ret;
    }

    /* Add new indexes */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, "@INDEXLIST");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    /* Add Index for nameAlias */
    ret = ldb_msg_add_empty(msg, "@IDXATTR", LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "@IDXATTR", "nameAlias");
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_upgrade_08(struct sysdb_ctx *sysdb, const char **ver)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_message *msg;
    struct upgrade_ctx *ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_9, &ctx);
    if (ret) {
        return ret;
    }

    /* Add new indexes */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, "@INDEXLIST");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    /* Add Index for servicePort and serviceProtocol */
    ret = ldb_msg_add_empty(msg, "@IDXATTR", LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "@IDXATTR", "servicePort");
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "@IDXATTR", "serviceProtocol");
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_upgrade_09(struct sysdb_ctx *sysdb, const char **ver)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_message *msg;
    struct upgrade_ctx *ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_10, &ctx);
    if (ret) {
        return ret;
    }

    /* Add new indexes */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, "@INDEXLIST");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    /* Add Index for ipHostNumber and ipNetworkNumber */
    ret = ldb_msg_add_empty(msg, "@IDXATTR", LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "@IDXATTR", "sudoUser");
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_upgrade_10(struct sysdb_ctx *sysdb, struct sss_domain_info *domain,
                     const char **ver)
{

    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_result *res;
    struct ldb_message *msg;
    struct ldb_message *user;
    struct ldb_message_element *memberof_el;
    const char *name;
    struct ldb_dn *basedn;
    /* No change needed because version 10 has objectclass user */
    const char *filter = "(&(objectClass=user)(!(uidNumber=*))(memberOf=*))";
    const char *attrs[] = { "name", "memberof", NULL };
    struct upgrade_ctx *ctx;
    int i, j;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_11, &ctx);
    if (ret) {
        return ret;
    }

    /*
     * dom->sysdb->ldb is not initialized,
     * so ldb_dn_new_fmt() shouldn't be changed to sysdb_*_base_dn()
     */
    basedn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                            SYSDB_TMPL_USER_BASE, domain->name);
    if (basedn == NULL) {
        ret = EIO;
        goto done;
    }

    ret = ldb_search(sysdb->ldb, tmp_ctx, &res, basedn, LDB_SCOPE_SUBTREE,
                     attrs, "%s", filter);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    for (i = 0; i < res->count; i++) {
        user = res->msgs[i];
        memberof_el = ldb_msg_find_element(user, "memberof");
        if (memberof_el == NULL) {
            ret = EINVAL;
            goto done;
        }

        name = ldb_msg_find_attr_as_string(user, "name", NULL);
        if (name == NULL) {
            ret = EIO;
            goto done;
        }

        DEBUG(SSSDBG_TRACE_LIBS, "User [%s] is a member of %d groups\n",
              name, memberof_el->num_values);

        for (j = 0; j < memberof_el->num_values; j++) {
            msg = ldb_msg_new(tmp_ctx);
            if (msg == NULL) {
                ret = ENOMEM;
                goto done;
            }

            msg->dn = ldb_dn_from_ldb_val(tmp_ctx, sysdb->ldb, &memberof_el->values[j]);
            if (msg->dn == NULL) {
                ret = ENOMEM;
                goto done;
            }

            if (!ldb_dn_validate(msg->dn)) {
                DEBUG(SSSDBG_MINOR_FAILURE, "DN validation failed during "
                                             "upgrade: [%s]\n",
                                             memberof_el->values[j].data);
                talloc_zfree(msg);
                continue;
            }

            ret = ldb_msg_add_empty(msg, "ghost", LDB_FLAG_MOD_ADD, NULL);
            if (ret != LDB_SUCCESS) {
                ret = ENOMEM;
                goto done;
            }
            ret = ldb_msg_add_string(msg, "ghost", name);
            if (ret != LDB_SUCCESS) {
                ret = ENOMEM;
                goto done;
            }

            DEBUG(SSSDBG_TRACE_FUNC, "Adding ghost [%s] to entry [%s]\n",
                  name, ldb_dn_get_linearized(msg->dn));

            ret = sss_ldb_modify_permissive(sysdb->ldb, msg);
            talloc_zfree(msg);
            if (ret == LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS) {
                /* If we failed adding the ghost user(s) because the values already
                 * exist, they were probably propagated from a parent that was
                 * upgraded before us. Mark the group as expired so that it is
                 * refreshed on next request.
                 */
                msg = ldb_msg_new(tmp_ctx);
                if (msg == NULL) {
                    ret = ENOMEM;
                    goto done;
                }

                msg->dn = ldb_dn_from_ldb_val(tmp_ctx, sysdb->ldb, &memberof_el->values[j]);
                if (msg->dn == NULL) {
                    ret = ENOMEM;
                    goto done;
                }

                ret = ldb_msg_add_empty(msg, SYSDB_CACHE_EXPIRE,
                                        LDB_FLAG_MOD_REPLACE, NULL);
                if (ret != LDB_SUCCESS) {
                    goto done;
                }

                ret = ldb_msg_add_string(msg, SYSDB_CACHE_EXPIRE, "1");
                if (ret != LDB_SUCCESS) {
                    goto done;
                }

                ret = sss_ldb_modify_permissive(sysdb->ldb, msg);
                talloc_zfree(msg);
                if (ret != LDB_SUCCESS) {
                    goto done;
                }
            } else if (ret != LDB_SUCCESS) {
                ret = sysdb_error_to_errno(ret);
                goto done;
            }
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Removing fake user [%s]\n",
              ldb_dn_get_linearized(user->dn));

        ret = ldb_delete(sysdb->ldb, user->dn);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_upgrade_11(struct sysdb_ctx *sysdb, struct sss_domain_info *domain,
                     const char **ver)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    struct ldb_result *res;
    struct ldb_message *entry;
    const char *key;
    const char *value;
    struct ldb_message_element *memberof_el;
    struct ldb_dn *memberof_dn;
    struct ldb_dn *basedn;
    const struct ldb_val *val;
    const char *attrs[] = { SYSDB_AUTOFS_ENTRY_KEY,
                            SYSDB_AUTOFS_ENTRY_VALUE,
                            SYSDB_MEMBEROF,
                            NULL };
    struct upgrade_ctx *ctx;
    size_t i, j;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_12, &ctx);
    if (ret) {
        return ret;
    }

    basedn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb, SYSDB_TMPL_CUSTOM_SUBTREE,
                            AUTOFS_ENTRY_SUBDIR, domain->name);
    if (basedn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_search(sysdb->ldb, tmp_ctx, &res, basedn, LDB_SCOPE_SUBTREE,
                     attrs, "(objectClass=%s)", SYSDB_AUTOFS_ENTRY_OC);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "Found %d autofs entries\n", res->count);

    for (i = 0; i < res->count; i++) {
        entry = res->msgs[i];
        key = ldb_msg_find_attr_as_string(entry,
                                          SYSDB_AUTOFS_ENTRY_KEY, NULL);
        value = ldb_msg_find_attr_as_string(entry,
                                            SYSDB_AUTOFS_ENTRY_VALUE, NULL);
        memberof_el = ldb_msg_find_element(entry, SYSDB_MEMBEROF);

        if (key && value && memberof_el) {
            for (j = 0; j < memberof_el->num_values; j++) {
                memberof_dn = ldb_dn_from_ldb_val(tmp_ctx, sysdb->ldb,
                                                  &(memberof_el->values[j]));
                if (!memberof_dn) {
                    DEBUG(SSSDBG_OP_FAILURE, "Cannot convert memberof into DN, skipping\n");
                    continue;
                }

                val = ldb_dn_get_rdn_val(memberof_dn);
                if (!val) {
                    DEBUG(SSSDBG_OP_FAILURE, "Cannot get map name from map DN\n");
                    continue;
                }

                ret = sysdb_save_autofsentry(domain,
                                             (const char *) val->data,
                                             key, value, NULL, 0, 0);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "Cannot save autofs entry [%s]-[%s] into map %s\n",
                           key, value, val->data);
                    continue;
                }
            }

        }

        /* Delete the old entry if it was either processed or incomplete */
        DEBUG(SSSDBG_TRACE_LIBS, "Deleting [%s]\n",
              ldb_dn_get_linearized(entry->dn));

        ret = ldb_delete(sysdb->ldb, entry->dn);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Cannot delete old autofs entry %s\n",
                  ldb_dn_get_linearized(entry->dn));
            continue;
        }
    }

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_upgrade_12(struct sysdb_ctx *sysdb, const char **ver)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_message *msg;
    struct upgrade_ctx *ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_13, &ctx);
    if (ret) {
        return ret;
    }

    /* add new indexes */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, "@INDEXLIST");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    /* add index for sshKnownHostsExpire */
    ret = ldb_msg_add_empty(msg, "@IDXATTR", LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "@IDXATTR", "sshKnownHostsExpire");
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_upgrade_13(struct sysdb_ctx *sysdb, const char **ver)
{
    struct upgrade_ctx *ctx;
    struct ldb_result *dom_res;
    struct ldb_result *res;
    struct ldb_dn *basedn;
    const char *attrs[] = { "cn", "name", NULL };
    const char *tmp_str;
    errno_t ret;
    int i, j, l, n;

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_14, &ctx);
    if (ret) {
        return ret;
    }

    basedn = ldb_dn_new(ctx, sysdb->ldb, SYSDB_BASE);
    if (!basedn) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to build base dn\n");
        ret = EIO;
        goto done;
    }

    ret = ldb_search(sysdb->ldb, ctx, &dom_res,
                     basedn, LDB_SCOPE_ONELEVEL,
                     attrs, "objectclass=%s", SYSDB_SUBDOMAIN_CLASS);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to search subdomains\n");
        ret = EIO;
        goto done;
    }

    for (i = 0; i < dom_res->count; i++) {

        tmp_str = ldb_msg_find_attr_as_string(dom_res->msgs[i], "cn", NULL);
        if (tmp_str == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "The object [%s] doesn't have a name\n",
                   ldb_dn_get_linearized(dom_res->msgs[i]->dn));
            continue;
        }

        basedn = ldb_dn_new_fmt(ctx, sysdb->ldb, SYSDB_DOM_BASE, tmp_str);
        if (!basedn) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to build base dn for subdomain %s\n", tmp_str);
            continue;
        }

        ret = ldb_search(sysdb->ldb, ctx, &res,
                         basedn, LDB_SCOPE_SUBTREE, attrs, NULL);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to search subdomain %s\n", tmp_str);
            talloc_free(basedn);
            continue;
        }

        l = ldb_dn_get_comp_num(basedn);
        for (j = 0; j < res->count; j++) {
            n = ldb_dn_get_comp_num(res->msgs[j]->dn);
            if (n <= l + 1) {
                /* Do not remove subdomain containers, only their contents */
                continue;
            }
            ret = ldb_delete(sysdb->ldb, res->msgs[j]->dn);
            if (ret) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to delete %s\n",
                       ldb_dn_get_linearized(res->msgs[j]->dn));
                continue;
            }
        }

        talloc_free(basedn);
        talloc_free(res);
    }

    talloc_free(dom_res);

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    return ret;
}

int sysdb_upgrade_14(struct sysdb_ctx *sysdb, const char **ver)
{
    struct upgrade_ctx *ctx;
    struct ldb_message *msg;
    struct ldb_result *res;
    struct ldb_dn *basedn;
    struct ldb_dn *newdn;
    const char *attrs[] = { SYSDB_NAME, NULL };
    const char *tmp_str;
    errno_t ret;
    int i;

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_15, &ctx);
    if (ret) {
        return ret;
    }

    basedn = ldb_dn_new(ctx, sysdb->ldb, SYSDB_BASE);
    if (!basedn) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to build base dn\n");
        ret = EIO;
        goto done;
    }

    /* create base ranges container */
    msg = ldb_msg_new(ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(msg, sysdb->ldb, SYSDB_TMPL_RANGE_BASE);
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "cn", "ranges");
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }
    /* do a synchronous add */
    ret = ldb_add(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to upgrade DB (%d, [%s])!\n",
               ret, ldb_errstring(sysdb->ldb));
        ret = EIO;
        goto done;
    }
    talloc_zfree(msg);

    ret = ldb_search(sysdb->ldb, ctx, &res,
                     basedn, LDB_SCOPE_SUBTREE, attrs,
                     "objectclass=%s", SYSDB_ID_RANGE_CLASS);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to search range objects\n");
        ret = EIO;
        goto done;
    }

    /* Failure to convert any range is not fatal. As long as there are no
     * left-over objects we can fail to move them around, as they will be
     * recreated on the next online access */
    for (i = 0; i < res->count; i++) {
        tmp_str = ldb_msg_find_attr_as_string(res->msgs[i], SYSDB_NAME, NULL);
        if (tmp_str == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "The object [%s] doesn't have a name\n",
                   ldb_dn_get_linearized(res->msgs[i]->dn));
            ret = ldb_delete(sysdb->ldb, res->msgs[i]->dn);
            if (ret) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to delete %s\n",
                       ldb_dn_get_linearized(res->msgs[i]->dn));
                ret = EIO;
                goto done;
            }
            continue;
        }

        newdn = ldb_dn_new_fmt(ctx, sysdb->ldb, SYSDB_TMPL_RANGE, tmp_str);
        if (!newdn) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to create new DN to move [%s]\n",
                   ldb_dn_get_linearized(res->msgs[i]->dn));
            ret = ENOMEM;
            goto done;
        }
        ret = ldb_rename(sysdb->ldb, res->msgs[i]->dn, newdn);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to move [%s] to [%s]\n",
                   ldb_dn_get_linearized(res->msgs[i]->dn),
                   ldb_dn_get_linearized(newdn));
            ret = ldb_delete(sysdb->ldb, res->msgs[i]->dn);
            if (ret) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to delete %s\n",
                       ldb_dn_get_linearized(res->msgs[i]->dn));
                ret = EIO;
                goto done;
            }
        }
        talloc_zfree(newdn);
    }

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    return ret;
}

int sysdb_upgrade_15(struct sysdb_ctx *sysdb, const char **ver)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_message *msg;
    struct upgrade_ctx *ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_16, &ctx);
    if (ret) {
        return ret;
    }

    /* Add new indexes */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, "@ATTRIBUTES");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    /* Case insensitive search for canonicalUserPrincipalName */
    ret = ldb_msg_add_empty(msg, SYSDB_CANONICAL_UPN, LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, SYSDB_CANONICAL_UPN, "CASE_INSENSITIVE");
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_upgrade_16(struct sysdb_ctx *sysdb, const char **ver)
{
    struct ldb_message *msg;
    struct upgrade_ctx *ctx;
    errno_t ret;

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_17, &ctx);
    if (ret) {
        return ret;
    }

    msg = ldb_msg_new(ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = ldb_dn_new(msg, sysdb->ldb, "@INDEXLIST");
    if (msg->dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* add index for objectSIDString */
    ret = ldb_msg_add_empty(msg, "@IDXATTR", LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "@IDXATTR", "objectSIDString");
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    return ret;
}

static char *object_domain_from_dn(TALLOC_CTX *mem_ctx,
                                   struct ldb_dn *dn,
                                   unsigned domain_index)
{
    const struct ldb_val *val;

    val = ldb_dn_get_component_val(dn, domain_index);
    if (val == NULL) {
        return NULL;
    }
    return talloc_strdup(mem_ctx, (const char *) val->data);
}

static char *object_domain(TALLOC_CTX *mem_ctx,
                           struct ldb_context *ldb,
                           struct ldb_message *msg,
                           const char *domain_attr,
                           unsigned domain_index)
{
    struct ldb_dn *dom_dn;

    if (domain_attr != NULL) {
        dom_dn = ldb_msg_find_attr_as_dn(ldb, mem_ctx, msg, domain_attr);
    } else {
        /* If no specific attribute to take the domain from is specified,
         * use the DN */
        dom_dn = msg->dn;
    }

    if (dom_dn == NULL) {
        return NULL;
    }

    return object_domain_from_dn(mem_ctx, dom_dn, domain_index);
}

/* Used for attributes like sudoUser which contain group or user name or
 * ID, depending on the value prefix */
typedef bool (*should_qualify_val_fn)(const char *val);

/* Qualifies a string attribute using domain_name. Optionally, if qfn is
 * given, only qualifies the name if qfn returns true */
static errno_t qualify_attr(struct ldb_message *msg,
                            struct ldb_message *mod_msg,
                            struct sss_names_ctx *names,
                            const char *domain_name,
                            const char *attrname,
                            should_qualify_val_fn qfn)
{
    struct ldb_message_element *el;
    struct ldb_message_element *mod_el;
    char *fqval;
    char *shortname;
    const char *rawname;
    int ret;
    struct ldb_val val;
    bool exists = false;

    el = ldb_msg_find_element(msg, attrname);
    if (el == NULL) {
        /* This entry does not have this element, fine */
        return EOK;
    }

    for (size_t c = 0; c < el->num_values; c++) {
        rawname = (const char *) el->values[c].data;

        if (qfn != NULL && qfn(rawname) == false) {
            continue;
        }

        ret = sss_parse_name(mod_msg, names, rawname, NULL, &shortname);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Cannot parse raw attribute %s\n", rawname);
            continue;
        }

        fqval = sss_create_internal_fqname(el->values, shortname, domain_name);
        talloc_free(shortname);
        if (fqval == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Cannot qualify %s@%s\n",
                  shortname, domain_name);
            continue;
        }


        mod_el = ldb_msg_find_element(mod_msg, attrname);
        if (mod_el != NULL) {
            val.data = (uint8_t *) fqval;
            val.length = strlen(fqval);

            if (ldb_msg_find_val(mod_el, &val) != NULL) {
                return true;
            }
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Qualified %s:%s into %s\n",
              attrname, rawname, fqval);

        if (!exists) {
            ret = ldb_msg_add_empty(mod_msg, attrname, LDB_FLAG_MOD_REPLACE, NULL);
            if (ret != LDB_SUCCESS) {
                continue;
            }

            exists = true;
        }

        ret = ldb_msg_add_steal_string(mod_msg, attrname, fqval);
        if (ret != LDB_SUCCESS) {
            continue;
        }
    }

    return EOK;
}

/* Returns a copy of old_dn_val with RDN qualified. The domain name
 * is read from the DN itself
 */
static struct ldb_dn *qualify_rdn(TALLOC_CTX *mem_ctx,
                                  struct ldb_context *ldb,
                                  struct sss_names_ctx *names,
                                  struct ldb_dn *old_dn_val)
{
    struct ldb_dn *parent_dn = NULL;
    const struct ldb_val *val = NULL;
    const char *rdn_name = NULL;
    struct ldb_dn *new_dn = NULL;
    char *fqrdn = NULL;
    char *shortname = NULL;
    char *dn_domain = NULL;
    TALLOC_CTX *tmp_ctx = NULL;
    int ret;

    rdn_name = ldb_dn_get_rdn_name(old_dn_val);
    if (rdn_name == NULL) {
        return NULL;
    }

    if (strcmp(rdn_name, SYSDB_NAME) != 0) {
        /* Only qualify DNs with name= rdn. This applies to overrideDNs mostly,
         * because those can contain either names or UUIDs
         */
        return ldb_dn_copy(mem_ctx, old_dn_val);
    }

    val = ldb_dn_get_rdn_val(old_dn_val);
    if (val == NULL) {
        return NULL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return NULL;
    }

    dn_domain = object_domain_from_dn(tmp_ctx, old_dn_val, 2);
    if (dn_domain == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot determine domain of %s\n",
              ldb_dn_get_linearized(old_dn_val));
        goto done;
    }

    ret = sss_parse_name(tmp_ctx, names, (const char *) val->data,
                         NULL, &shortname);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot parse raw RDN %s\n", (const char *) val->data);
        goto done;
    }

    fqrdn = sss_create_internal_fqname(tmp_ctx, shortname, dn_domain);
    if (fqrdn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot qualify %s@%s\n",
              shortname, dn_domain);
        goto done;
    }

    parent_dn = ldb_dn_get_parent(tmp_ctx, old_dn_val);
    if (parent_dn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get parent of %s\n",
              ldb_dn_get_linearized(old_dn_val));
        goto done;
    }

    new_dn = ldb_dn_new_fmt(mem_ctx, ldb, "%s=%s,%s",
                            rdn_name, fqrdn,
                            ldb_dn_get_linearized(parent_dn));
done:
    talloc_free(tmp_ctx);
    return new_dn;
}

static errno_t qualify_dn_attr(struct ldb_context *ldb,
                               struct ldb_message *msg,
                               struct ldb_message *mod_msg,
                               struct sss_names_ctx *names,
                               const char *attrname)
{
    struct ldb_message_element *el;
    struct ldb_message_element *mod_el;
    struct ldb_dn *attr_dn;
    struct ldb_dn *fqdn;
    errno_t ret;
    TALLOC_CTX *tmp_ctx = NULL;

    el = ldb_msg_find_element(msg, attrname);
    if (el == NULL || el->num_values == 0) {
        return EOK;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    for (size_t c = 0; c < el->num_values; c++) {
        attr_dn = ldb_dn_new(tmp_ctx, ldb, (const char *) el->values[c].data);
        if (attr_dn == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Cannot create DN from %s\n",
                  (const char *) el->values[c].data);
            continue;
        }

        if (!ldb_dn_validate(attr_dn)) {
            DEBUG(SSSDBG_OP_FAILURE, "DN %s does not validate\n",
                  (const char *) el->values[c].data);
            continue;
        }

        fqdn = qualify_rdn(tmp_ctx, ldb, names, attr_dn);
        if (fqdn == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Cannot qualify %s\n",
                  (const char *) el->values[c].data);
            continue;
        }

        ret = ldb_msg_add_linearized_dn(mod_msg, attrname, fqdn);
        if (ret != LDB_SUCCESS) {
            continue;
        }

        talloc_free(attr_dn);
        talloc_free(fqdn);
    }

    mod_el = ldb_msg_find_element(mod_msg, attrname);
    if (mod_el != NULL) {
        mod_el->flags = LDB_FLAG_MOD_REPLACE;
    }

    talloc_free(tmp_ctx);
    return EOK;
}

static errno_t expire_object(struct ldb_message *object,
                             struct ldb_message *mod_msg)
{
    errno_t ret;
    struct ldb_message_element *el;
    const char *attrs[] = { SYSDB_CACHE_EXPIRE,
                            SYSDB_LAST_UPDATE,
                            SYSDB_INITGR_EXPIRE,
                            NULL
    };

    for (size_t c = 0; attrs[c] != NULL; c++) {
        el = ldb_msg_find_element(object, attrs[c]);
        if (el == NULL) {
            continue;
        }

        ret = ldb_msg_add_empty(mod_msg, attrs[c], LDB_FLAG_MOD_REPLACE, NULL);
        if (ret != LDB_SUCCESS) {
            return ret;
        }

        ret = ldb_msg_add_fmt(mod_msg, attrs[c], "%d", 1);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
    }

    return EOK;
}

static errno_t qualify_object(TALLOC_CTX *mem_ctx,
                              struct ldb_context *ldb,
                              struct sss_names_ctx *names,
                              struct ldb_message *object,
                              bool qualify_dn,
                              const char *domain_attr,
                              unsigned domain_index,
                              const char *name_attrs[],
                              const char *dn_attrs[],
                              should_qualify_val_fn qfn)
{
    int ret;
    struct ldb_message *mod_msg = NULL;
    struct ldb_dn *new_object_dn = NULL;
    const char *dom_name;

    mod_msg = ldb_msg_new(mem_ctx);
    if (mod_msg == NULL) {
        return ENOMEM;
    }
    mod_msg->dn = object->dn;

    dom_name = object_domain(mod_msg, ldb, object, domain_attr, domain_index);
    if (dom_name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot determine domain of %s\n",
              ldb_dn_get_linearized(mod_msg->dn));
        return EINVAL;
    }

    if (name_attrs != NULL) {
        for (size_t c = 0; name_attrs[c]; c++) {
            ret = qualify_attr(object, mod_msg, names,
                               dom_name, name_attrs[c], qfn);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Cannot qualify %s of %s\n",
                      name_attrs[c], ldb_dn_get_linearized(object->dn));
                continue;
            }
        }
    }

    if (dn_attrs != NULL) {
        for (size_t c = 0; dn_attrs[c]; c++) {
            ret = qualify_dn_attr(ldb, object, mod_msg,
                                  names, dn_attrs[c]);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Cannot qualify %s of %s\n",
                      dn_attrs[c], ldb_dn_get_linearized(object->dn));
            }
        }
    }

    ret = expire_object(object, mod_msg);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot expire %s\n", ldb_dn_get_linearized(object->dn));
    }

    /* Override objects can contain both qualified and non-qualified names.
     * Need to use permissive modification here, otherwise we might attempt
     * to store duplicate qualified names
     */
    ret = sss_ldb_modify_permissive(ldb, mod_msg);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot modify %s\n",  ldb_dn_get_linearized(object->dn));
        goto done;
    }

    if (qualify_dn) {
        new_object_dn = qualify_rdn(mod_msg, ldb, names, mod_msg->dn);
        if (new_object_dn == NULL) {
            ret = EIO;
            goto done;
        }

        ret = ldb_rename(ldb, object->dn, new_object_dn);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Cannot rename %s to %s\n",
                  ldb_dn_get_linearized(object->dn),
                  ldb_dn_get_linearized(new_object_dn));
            goto done;
        }
    }

    ret = EOK;
done:
    talloc_free(mod_msg);
    return ret;
}

static void qualify_objects(struct upgrade_ctx *ctx,
                            struct ldb_context *ldb,
                            struct sss_names_ctx *names,
                            struct ldb_dn *base_dn,
                            bool qualify_dn,
                            const char *domain_attr,
                            unsigned domain_index,
                            const char *filter,
                            const char *name_attrs[],
                            const char *dn_attrs[],
                            should_qualify_val_fn qfn)
{
    errno_t ret;
    struct ldb_result *objects = NULL;
    const char *attrs[] = { "*", NULL };

    ret = ldb_search(ldb, ctx, &objects, base_dn,
                     LDB_SCOPE_SUBTREE, attrs, "%s", filter);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to search objects: %d\n", ret);
        return;
    }

    if (objects == NULL || objects->count == 0) {
        DEBUG(SSSDBG_TRACE_LIBS, "No match for: %s\n", filter);
        return;
    }

    for (size_t c = 0; c < objects->count; c++) {
        ret = qualify_object(ctx, ldb, names, objects->msgs[c],
                             qualify_dn, domain_attr, domain_index,
                             name_attrs, dn_attrs, qfn);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Could not qualify object %s: %d\n",
                  ldb_dn_get_linearized(objects->msgs[c]->dn), ret);
            continue;
        }
    }
    talloc_free(objects);
}

static void qualify_users(struct upgrade_ctx *ctx,
                          struct ldb_context *ldb,
                          struct sss_names_ctx *names,
                          struct ldb_dn *base_dn)
{
    /* No change needed because this version has objectclass user */
    const char *user_filter = "objectclass=user";
    const char *user_name_attrs[] = { SYSDB_NAME,
                                      SYSDB_NAME_ALIAS,
                                      SYSDB_DEFAULT_OVERRIDE_NAME,
                                      ORIGINALAD_PREFIX SYSDB_NAME,
                                      NULL
    };
    const char *user_dn_attrs[] = { SYSDB_MEMBEROF,
                                    SYSDB_OVERRIDE_DN,
                                    NULL
    };

    return qualify_objects(ctx, ldb, names, base_dn,
                           true,        /* qualify dn */
                           NULL,        /* no special domain attr, use DN */
                           2,           /* DN's domain is third RDN from top */
                           user_filter,
                           user_name_attrs, user_dn_attrs, NULL);
}

static void qualify_groups(struct upgrade_ctx *ctx,
                           struct ldb_context *ldb,
                           struct sss_names_ctx *names,
                           struct ldb_dn *base_dn)
{
    /* No change needed because this version has objectclass group */
    const char *group_filter = "objectclass=group";
    const char *group_name_attrs[] = { SYSDB_NAME,
                                       SYSDB_NAME_ALIAS,
                                       SYSDB_DEFAULT_OVERRIDE_NAME,
                                       ORIGINALAD_PREFIX SYSDB_NAME,
                                       SYSDB_MEMBERUID,
                                       SYSDB_GHOST,
                                       NULL
    };
    const char *group_dn_attrs[] = { SYSDB_MEMBER,
                                     SYSDB_MEMBEROF,
                                     SYSDB_OVERRIDE_DN,
                                     NULL
    };

    return qualify_objects(ctx, ldb, names, base_dn, true,
                           NULL, 2, group_filter,
                           group_name_attrs, group_dn_attrs, NULL);
}

static void qualify_user_overrides(struct upgrade_ctx *ctx,
                                   struct ldb_context *ldb,
                                   struct sss_names_ctx *names,
                                   struct ldb_dn *base_dn)
{
    const char *user_override_filter = "objectclass=userOverride";
    const char *user_ovr_name_attrs[] = { SYSDB_NAME,
                                          SYSDB_NAME_ALIAS,
                                          NULL
    };
    const char *user_ovr_dn_attrs[] = { SYSDB_OVERRIDE_OBJECT_DN,
                                        NULL
    };

    return qualify_objects(ctx, ldb, names, base_dn,
                           /* Don't qualify RDN of override DN */
                           false,
                           /* Read domain from override DN */
                           SYSDB_OVERRIDE_OBJECT_DN,
                           2, /* Third RDN from top is domain */
                           user_override_filter, user_ovr_name_attrs,
                           user_ovr_dn_attrs, NULL);
}

static void qualify_group_overrides(struct upgrade_ctx *ctx,
                                    struct ldb_context *ldb,
                                    struct sss_names_ctx *names,
                                    struct ldb_dn *base_dn)
{
    const char *group_override_filter = "objectclass=groupOverride";
    const char *group_ovr_name_attrs[] = { SYSDB_NAME,
                                           SYSDB_NAME_ALIAS,
                                           NULL
    };
    const char *group_ovr_dn_attrs[] = { SYSDB_OVERRIDE_OBJECT_DN,
                                         NULL
    };

    return qualify_objects(ctx, ldb, names, base_dn,
                           false, SYSDB_OVERRIDE_OBJECT_DN, 2,
                           group_override_filter, group_ovr_name_attrs,
                           group_ovr_dn_attrs, NULL);
}

static void qualify_sudo_rules(struct upgrade_ctx *ctx,
                               struct ldb_context *ldb,
                               struct sss_names_ctx *names,
                               struct ldb_dn *base_dn)
{
    const char *group_override_filter = "objectclass=sudoRule";
    const char *sudo_rule_name_attrs[] = { "sudoUser",
                                            NULL
    };

    return qualify_objects(ctx, ldb, names, base_dn,
                           false, NULL, 3,
                           group_override_filter, sudo_rule_name_attrs,
                           NULL, is_user_or_group_name);
}


int sysdb_upgrade_17(struct sysdb_ctx *sysdb,
                     struct sysdb_dom_upgrade_ctx *upgrade_ctx,
                     const char **ver)
{
    struct upgrade_ctx *ctx;
    errno_t ret, envret;
    struct ldb_dn *base_dn;
    struct sss_names_ctx *names = upgrade_ctx->names;

    if (names == NULL) {
        return EINVAL;
    }

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_18, &ctx);
    if (ret) {
        return ret;
    }

    /* Disable memberof plugin during this update */
    ret = setenv("SSSD_UPGRADE_DB", "1", 1);
    if (ret != 0) {
        goto done;
    }

    base_dn = ldb_dn_new_fmt(ctx, sysdb->ldb, SYSDB_BASE);
    if (base_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    qualify_users(ctx, sysdb->ldb, names, base_dn);
    qualify_groups(ctx, sysdb->ldb, names, base_dn);
    qualify_user_overrides(ctx, sysdb->ldb, names, base_dn);
    qualify_group_overrides(ctx, sysdb->ldb, names, base_dn);
    qualify_sudo_rules(ctx, sysdb->ldb, names, base_dn);

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    envret = unsetenv("SSSD_UPGRADE_DB");
    if (envret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot unset SSSD_UPGRADE_DB, SSSD might not work correctly\n");
    }
    return ret;
}

int sysdb_upgrade_18(struct sysdb_ctx *sysdb, const char **ver)
{
    struct upgrade_ctx *ctx;
    errno_t ret;
    struct ldb_message *msg = NULL;

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_19, &ctx);
    if (ret) {
        return ret;
    }

    /* Add missing indices */
    msg = ldb_msg_new(ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = ldb_dn_new(msg, sysdb->ldb, "@INDEXLIST");
    if (msg->dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "@IDXATTR", LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "@IDXATTR", SYSDB_GHOST);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "@IDXATTR", SYSDB_UPN);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "@IDXATTR", SYSDB_CANONICAL_UPN);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "@IDXATTR", SYSDB_UUID);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "@IDXATTR", SYSDB_USER_EMAIL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    talloc_free(msg);

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    return ret;
}

static errno_t add_object_category(struct ldb_context *ldb,
                                   struct upgrade_ctx *ctx)
{
    errno_t ret;
    struct ldb_result *objects = NULL;
    const char *attrs[] = { SYSDB_OBJECTCLASS, NULL };
    struct ldb_dn *base_dn;
    size_t c;
    const char *class_name;
    struct ldb_message *msg = NULL;
    struct ldb_message *del_msg = NULL;

    base_dn = ldb_dn_new(ctx, ldb, SYSDB_BASE);
    if (base_dn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed create base dn.\n");
        return ENOMEM;
    }

    ret = ldb_search(ldb, ctx, &objects, base_dn,
                     LDB_SCOPE_SUBTREE, attrs,
                     "(|("SYSDB_OBJECTCLASS"="SYSDB_USER_CLASS")"
                       "("SYSDB_OBJECTCLASS"="SYSDB_GROUP_CLASS"))");
    talloc_free(base_dn);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to search objects: %d\n", ret);
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    if (objects == NULL || objects->count == 0) {
        DEBUG(SSSDBG_TRACE_LIBS, "No objects found, nothing to do.\n");
        ret = EOK;
        goto done;
    }

    del_msg = ldb_msg_new(ctx);
    if (del_msg == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_new failed.\n");
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_empty(del_msg, SYSDB_OBJECTCLASS, LDB_FLAG_MOD_DELETE,
                            NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_add_empty failed.\n");
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    DEBUG(SSSDBG_TRACE_ALL, "Found [%d] objects.\n", objects->count);
    for (c = 0; c < objects->count; c++) {
        DEBUG(SSSDBG_TRACE_ALL, "Updating [%s].\n",
              ldb_dn_get_linearized(objects->msgs[c]->dn));

        class_name = ldb_msg_find_attr_as_string(objects->msgs[c],
                                                 SYSDB_OBJECTCLASS, NULL);
        if (class_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Searched objects by objectClass, "
                                     "but result does not have one.\n");
            ret = EINVAL;
            goto done;
        }

        talloc_free(msg);
        msg = ldb_msg_new(ctx);
        if (msg == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_new failed.\n");
            ret = ENOMEM;
            goto done;
        }

        msg->dn = objects->msgs[c]->dn;
        del_msg->dn = objects->msgs[c]->dn;

        ret = ldb_msg_add_empty(msg, SYSDB_OBJECTCATEGORY, LDB_FLAG_MOD_ADD,
                                NULL);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_add_empty failed.\n");
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_OBJECTCATEGORY, class_name);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_add_string failed.\n");
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        DEBUG(SSSDBG_TRACE_ALL, "Adding [%s] to [%s].\n", class_name,
              ldb_dn_get_linearized(objects->msgs[c]->dn));
        ret = ldb_modify(ldb, msg);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to add objectCategory to %s: %d.\n",
                  ldb_dn_get_linearized(objects->msgs[c]->dn),
                  sysdb_error_to_errno(ret));
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_modify(ldb, del_msg);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to remove objectClass from %s: %d.\n",
                  ldb_dn_get_linearized(objects->msgs[c]->dn),
                  sysdb_error_to_errno(ret));
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_free(msg);
    talloc_free(del_msg);
    talloc_free(objects);

    return ret;
}

int sysdb_upgrade_19(struct sysdb_ctx *sysdb, const char **ver)
{
    struct upgrade_ctx *ctx;
    errno_t ret;
    struct ldb_message *msg = NULL;

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_20, &ctx);
    if (ret) {
        return ret;
    }

    ret = add_object_category(sysdb->ldb, ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "add_object_category failed: %d\n", ret);
        goto done;
    }

    /* Remove @IDXONE from index */
    msg = ldb_msg_new(ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = ldb_dn_new(msg, sysdb->ldb, "@INDEXLIST");
    if (msg->dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "@IDXONE", LDB_FLAG_MOD_DELETE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "@IDXATTR", LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "@IDXATTR", SYSDB_USER_MAPPED_CERT);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    return ret;
}

int sysdb_upgrade_20(struct sysdb_ctx *sysdb, const char **ver)
{
    struct upgrade_ctx *ctx;
    errno_t ret;
    struct ldb_message *msg = NULL;

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_21, &ctx);
    if (ret) {
        return ret;
    }

    /* Add missing indices */
    msg = ldb_msg_new(ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = ldb_dn_new(msg, sysdb->ldb, "@INDEXLIST");
    if (msg->dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "@IDXATTR", LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "@IDXATTR", SYSDB_CCACHE_FILE);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    talloc_free(msg);

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    return ret;
}

int sysdb_upgrade_21(struct sysdb_ctx *sysdb, const char **ver)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_message *msg;
    struct upgrade_ctx *ctx;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_22, &ctx);
    if (ret) {
        return ret;
    }

    /* Case insensitive search for ipHostNumber and ipNetworkNumber */
    msg = ldb_msg_new(tmp_ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, "@ATTRIBUTES");
    if (msg->dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, SYSDB_IP_HOST_ATTR_ADDRESS, LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, SYSDB_IP_HOST_ATTR_ADDRESS, "CASE_INSENSITIVE");
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, SYSDB_IP_NETWORK_ATTR_NUMBER,
                            LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, SYSDB_IP_NETWORK_ATTR_NUMBER,
                             "CASE_INSENSITIVE");
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    talloc_zfree(msg);

    /* Add new indexes */
    msg = ldb_msg_new(tmp_ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, "@INDEXLIST");
    if (msg->dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Add Index for ipHostNumber */
    ret = ldb_msg_add_empty(msg, "@IDXATTR", LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "@IDXATTR", SYSDB_IP_HOST_ATTR_ADDRESS);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "@IDXATTR", SYSDB_IP_NETWORK_ATTR_NUMBER);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_upgrade_22(struct sysdb_ctx *sysdb, const char **ver)
{
    struct upgrade_ctx *ctx;
    errno_t ret;
    struct ldb_message *msg = NULL;

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_23, &ctx);
    if (ret) {
        return ret;
    }

    /* Add missing indices */
    msg = ldb_msg_new(ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = ldb_dn_new(msg, sysdb->ldb, "@INDEXLIST");
    if (msg->dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "@IDXATTR", LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "@IDXATTR", SYSDB_ORIG_AD_GID_NUMBER);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    talloc_free(msg);

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    return ret;
}

int sysdb_upgrade_23(struct sysdb_ctx *sysdb, const char **ver)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_message *msg;
    struct upgrade_ctx *ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_24, &ctx);
    if (ret) {
        return ret;
    }

    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, "@ATTRIBUTES");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    /* Case insensitive search for mail */
    ret = ldb_msg_add_empty(msg, SYSDB_USER_EMAIL, LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, SYSDB_USER_EMAIL, "CASE_INSENSITIVE");
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    /* Case insensitive search for gpoGUID */
    ret = ldb_msg_add_empty(msg, SYSDB_GPO_GUID_ATTR, LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, SYSDB_GPO_GUID_ATTR, "CASE_INSENSITIVE");
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    talloc_free(msg);

    /* Add new indices */
    msg = ldb_msg_new(ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = ldb_dn_new(msg, sysdb->ldb, "@INDEXLIST");
    if (msg->dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "@IDXATTR", LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "@IDXATTR", SYSDB_GPO_GUID_ATTR);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    talloc_free(msg);

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_upgrade_24(struct sysdb_ctx *sysdb, const char **ver)
{
    struct upgrade_ctx *ctx;
    errno_t ret;

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_25, &ctx);
    if (ret) {
        return ret;
    }

    ret = sysdb_ldb_mod_index(sysdb, SYSDB_IDX_DELETE, sysdb->ldb, "dataExpireTimestamp");
    if (ret == ENOENT) { /*nothing to delete */
        ret = EOK;
    }
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_FUNC, "sysdb_ldb_mod_index() failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    return ret;
}

/*
 * Example template for future upgrades.
 * Copy and change version numbers as appropriate.
 */
#if 0

int sysdb_upgrade_13(struct sysdb_ctx *sysdb, const char **ver)
{
    struct upgrade_ctx *ctx;
    errno_t ret;

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_14, &ctx);
    if (ret) {
        return ret;
    }

    /* DO STUFF HERE (use ctx, as the local temporary memory context) */

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    return ret;
}
#endif
