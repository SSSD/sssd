/*
   SSSD

   System Database

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2008

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
#include <time.h>

/* the following are all SYNCHRONOUS calls
 * TODO: make these asynchronous */

int sysdb_add_group_member(TALLOC_CTX *mem_ctx,
                           struct sysdb_ctx *sysdb,
                           struct ldb_dn *member_dn,
                           struct ldb_dn *group_dn)
{
    TALLOC_CTX *tmp_ctx;
    int ret, lret;
    struct ldb_message *msg;

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) return ENOMEM;

    /* Add the member_dn as a member of the group */
    msg = ldb_msg_new(tmp_ctx);
    if(msg == NULL) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = group_dn;
    lret = ldb_msg_add_empty(msg, SYSDB_GR_MEMBER,
                             LDB_FLAG_MOD_ADD, NULL);
    if (lret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    lret = ldb_msg_add_fmt(msg, SYSDB_GR_MEMBER, "%s",
                           ldb_dn_get_linearized(member_dn));
    if (lret != LDB_SUCCESS) {
        ret = EINVAL;
        goto done;
    }

    lret = ldb_modify(sysdb->ldb, msg);
    if (lret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to make modify request: %s(%d)[%s]\n",
                  ldb_strerror(lret), lret, ldb_errstring(sysdb->ldb)));
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_remove_group_member(TALLOC_CTX *mem_ctx,
                              struct sysdb_ctx *sysdb,
                              struct ldb_dn *member_dn,
                              struct ldb_dn *group_dn)
{
    TALLOC_CTX *tmp_ctx;
    int ret, lret;
    struct ldb_message *msg;

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) return ENOMEM;

    /* Add the member_dn as a member of the group */
    msg = ldb_msg_new(tmp_ctx);
    if(msg == NULL) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = group_dn;
    lret = ldb_msg_add_empty(msg, SYSDB_GR_MEMBER,
                             LDB_FLAG_MOD_DELETE, NULL);
    if (lret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    lret = ldb_msg_add_fmt(msg, SYSDB_GR_MEMBER, "%s",
                           ldb_dn_get_linearized(member_dn));
    if (lret != LDB_SUCCESS) {
        ret = EINVAL;
        goto done;
    }

    lret = ldb_modify(sysdb->ldb, msg);
    if (lret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to make modify request: %s(%d)[%s]\n",
                  ldb_strerror(lret), lret, ldb_errstring(sysdb->ldb)));
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

/* "sysdb_legacy_" functions
 * the set of functions named sysdb_legacy_* are used by modules
 * that only have access to strictly posix like databases where
 * user and groups names are retrieved as strings, groups can't
 * be nested and can't reference foreign sources */

int sysdb_legacy_store_user(TALLOC_CTX *memctx,
                            struct sysdb_ctx *sysdb,
                            const char *domain,
                            const char *name, const char *pwd,
                            uid_t uid, gid_t gid, const char *gecos,
                            const char *homedir, const char *shell)
{
    TALLOC_CTX *tmp_ctx;
    const char *attrs[] = { SYSDB_PW_NAME, NULL };
    struct ldb_dn *user_dn;
    struct ldb_message *msg;
    struct ldb_request *req;
	struct ldb_result *res;
    int lret, ret;
    int flags;

    tmp_ctx = talloc_new(memctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    user_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                                SYSDB_PW_NAME"=%s,"SYSDB_TMPL_USER_BASE,
                                name, domain);
    if (!user_dn) {
        talloc_free(tmp_ctx);
        return ENOMEM;
    }

    lret = ldb_transaction_start(sysdb->ldb);
    if (lret != LDB_SUCCESS) {
        DEBUG(1, ("Failed ldb transaction start !? (%d)\n", lret));
        ret = EIO;
        goto done;
    }

    lret = ldb_search(sysdb->ldb, tmp_ctx, &res, user_dn,
                      LDB_SCOPE_BASE, attrs, SYSDB_PWENT_FILTER);
    if (lret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to make search request: %s(%d)[%s]\n",
                  ldb_strerror(lret), lret, ldb_errstring(sysdb->ldb)));
        ret = EIO;
        goto done;
    }

    req = NULL;

    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = user_dn;

    switch (res->count) {
    case 0:
        flags = LDB_FLAG_MOD_ADD;
        break;
    case 1:
        flags = LDB_FLAG_MOD_REPLACE;
        break;
    default:
        DEBUG(0, ("Cache DB corrupted, base search returned %d results\n",
                  res->count));
        ret = EIO;
        goto done;
    }

    talloc_free(res);
    res = NULL;

    if (flags == LDB_FLAG_MOD_ADD) {
        /* TODO: retrieve user objectclass list from configuration */
        lret = ldb_msg_add_empty(msg, "objectClass", flags, NULL);
        if (lret == LDB_SUCCESS) {
            lret = ldb_msg_add_string(msg, "objectClass", "user");
        }
        if (lret != LDB_SUCCESS) {
            ret = ENOMEM;
            goto done;
        }

        /* TODO: retrieve user name attribute from configuration */
        lret = ldb_msg_add_empty(msg, SYSDB_PW_NAME, flags, NULL);
        if (lret == LDB_SUCCESS) {
            lret = ldb_msg_add_string(msg, SYSDB_PW_NAME, name);
        }
        if (lret != LDB_SUCCESS) {
            ret = ENOMEM;
            goto done;
        }
    }

    /* TODO: retrieve attribute name mappings from configuration */

    /* pwd */
    if (pwd && *pwd) {
        lret = ldb_msg_add_empty(msg, SYSDB_PW_PWD, flags, NULL);
        if (lret == LDB_SUCCESS) {
            lret = ldb_msg_add_string(msg, SYSDB_PW_PWD, pwd);
        }
    } else {
        lret = ldb_msg_add_empty(msg, SYSDB_PW_PWD,
                                 LDB_FLAG_MOD_DELETE, NULL);
    }
    if (lret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    /* uid */
    if (uid) {
        lret = ldb_msg_add_empty(msg, SYSDB_PW_UIDNUM, flags, NULL);
        if (lret == LDB_SUCCESS) {
            lret = ldb_msg_add_fmt(msg, SYSDB_PW_UIDNUM,
                                   "%lu", (unsigned long)uid);
        }
        if (lret != LDB_SUCCESS) {
            ret = ENOMEM;
            goto done;
        }
    } else {
        DEBUG(0, ("Cached users can't have UID == 0\n"));
        ret = EINVAL;
        goto done;
    }

    /* gid */
    if (gid) {
        lret = ldb_msg_add_empty(msg, SYSDB_PW_GIDNUM, flags, NULL);
        if (lret == LDB_SUCCESS) {
            lret = ldb_msg_add_fmt(msg, SYSDB_PW_GIDNUM,
                                   "%lu", (unsigned long)gid);
        }
        if (lret != LDB_SUCCESS) {
            ret = ENOMEM;
            goto done;
        }
    } else {
        DEBUG(0, ("Cached users can't have GID == 0\n"));
        ret = EINVAL;
        goto done;
    }

    /* gecos */
    if (gecos && *gecos) {
        lret = ldb_msg_add_empty(msg, SYSDB_PW_FULLNAME, flags, NULL);
        if (lret == LDB_SUCCESS) {
            lret = ldb_msg_add_string(msg, SYSDB_PW_FULLNAME, gecos);
        }
    } else {
        lret = ldb_msg_add_empty(msg, SYSDB_PW_FULLNAME,
                                 LDB_FLAG_MOD_DELETE, NULL);
    }
    if (lret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    /* homedir */
    if (homedir && *homedir) {
        lret = ldb_msg_add_empty(msg, SYSDB_PW_HOMEDIR, flags, NULL);
        if (lret == LDB_SUCCESS) {
            lret = ldb_msg_add_string(msg, SYSDB_PW_HOMEDIR, homedir);
        }
    } else {
        lret = ldb_msg_add_empty(msg, SYSDB_PW_HOMEDIR,
                                 LDB_FLAG_MOD_DELETE, NULL);
    }
    if (lret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    /* shell */
    if (shell && *shell) {
        lret = ldb_msg_add_empty(msg, SYSDB_PW_SHELL, flags, NULL);
        if (lret == LDB_SUCCESS) {
            lret = ldb_msg_add_string(msg, SYSDB_PW_SHELL, shell);
        }
    } else {
        lret = ldb_msg_add_empty(msg, SYSDB_PW_SHELL,
                                 LDB_FLAG_MOD_DELETE, NULL);
    }
    if (lret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    /* modification time */
    lret = ldb_msg_add_empty(msg, SYSDB_LAST_UPDATE, flags, NULL);
    if (lret == LDB_SUCCESS) {
        lret = ldb_msg_add_fmt(msg, SYSDB_LAST_UPDATE,
                               "%ld", (long int)time(NULL));
    }
    if (lret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    if (flags == LDB_FLAG_MOD_ADD) {
        lret = ldb_build_add_req(&req, sysdb->ldb, tmp_ctx, msg, NULL,
                                 NULL, ldb_op_default_callback, NULL);
    } else {
        lret = ldb_build_mod_req(&req, sysdb->ldb, tmp_ctx, msg, NULL,
                                 NULL, ldb_op_default_callback, NULL);
    }
    if (lret == LDB_SUCCESS) {
        lret = ldb_request(sysdb->ldb, req);
        if (lret == LDB_SUCCESS) {
            lret = ldb_wait(req->handle, LDB_WAIT_ALL);
        }
    }
    if (lret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to make modify request: %s(%d)[%s]\n",
                  ldb_strerror(lret), lret, ldb_errstring(sysdb->ldb)));
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    if (ret == EOK) {
        lret = ldb_transaction_commit(sysdb->ldb);
        if (lret != LDB_SUCCESS) {
            DEBUG(1, ("Failed ldb transaction start !? (%d)\n", lret));
            ret = EIO;
        }
    } else {
        lret = ldb_transaction_cancel(sysdb->ldb);
        if (lret != LDB_SUCCESS) {
            DEBUG(1, ("Failed to cancel ldb transaction (%d)\n", lret));
            ret = EIO;
        }
    }

    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_delete_user(TALLOC_CTX *memctx,
                      struct sysdb_ctx *sysdb,
                      const char *domain, const char *name)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *user_dn;
    int lret, ret = EOK;

    tmp_ctx = talloc_new(memctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    user_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                                SYSDB_PW_NAME"=%s,"SYSDB_TMPL_USER_BASE,
                                name, domain);
    if (!user_dn) {
        talloc_free(tmp_ctx);
        return ENOMEM;
    }

    lret = ldb_delete(sysdb->ldb, user_dn);

    if (lret != LDB_SUCCESS && lret != LDB_ERR_NO_SUCH_OBJECT) {
        DEBUG(2, ("LDB Error: %s(%d)\nError Message: [%s]\n",
              ldb_strerror(ret), ret, ldb_errstring(sysdb->ldb)));
        ret = EIO;
    }

    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_delete_user_by_uid(TALLOC_CTX *memctx,
                             struct sysdb_ctx *sysdb,
                             const char *domain, uid_t uid)
{
    TALLOC_CTX *tmp_ctx;
    const char *attrs[] = { SYSDB_PW_NAME, SYSDB_PW_UIDNUM, NULL };
    struct ldb_dn *base_dn;
    struct ldb_dn *user_dn;
	struct ldb_result *res;
    int lret, ret;

    tmp_ctx = talloc_new(memctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    base_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                             SYSDB_TMPL_USER_BASE, domain);
    if (!base_dn) {
        talloc_free(tmp_ctx);
        return ENOMEM;
    }

    lret = ldb_transaction_start(sysdb->ldb);
    if (lret != LDB_SUCCESS) {
        DEBUG(1, ("Failed ldb transaction start !? (%d)\n", lret));
        ret = EIO;
        goto done;
    }

    lret = ldb_search(sysdb->ldb, tmp_ctx, &res, base_dn,
                      LDB_SCOPE_ONELEVEL, attrs,
                      SYSDB_PWUID_FILTER,
                      (unsigned long)uid);
    if (lret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to make search request: %s(%d)[%s]\n",
                  ldb_strerror(lret), lret, ldb_errstring(sysdb->ldb)));
        ret = EIO;
        goto done;
    }

    if (res->count == 0) {
        DEBUG(7, ("Base search returned no results\n"));
        ret = EOK;
        goto done;
    }
    if (res->count > 1) {
        DEBUG(0, ("Cache DB corrupted, base search returned %d results\n",
                  res->count));
        ret = EIO;
        goto done;
    }

    user_dn = ldb_dn_copy(tmp_ctx, res->msgs[0]->dn);
    if (!user_dn) {
        ret = ENOMEM;
        goto done;
    }

    talloc_free(res);
    res = NULL;

    lret = ldb_delete(sysdb->ldb, user_dn);

    if (lret != LDB_SUCCESS && lret != LDB_ERR_NO_SUCH_OBJECT) {
        DEBUG(2, ("LDB Error: %s(%d)\nError Message: [%s]\n",
              ldb_strerror(ret), ret, ldb_errstring(sysdb->ldb)));
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    if (ret == EOK) {
        lret = ldb_transaction_commit(sysdb->ldb);
        if (lret != LDB_SUCCESS) {
            DEBUG(1, ("Failed ldb transaction commit !! (%d)\n", lret));
            ret = EIO;
        }
    } else {
        lret = ldb_transaction_cancel(sysdb->ldb);
        if (lret != LDB_SUCCESS) {
            DEBUG(1, ("Failed to cancel ldb transaction (%d)\n", lret));
            ret = EIO;
        }
    }

    talloc_free(tmp_ctx);
    return ret;
}

/* this function does not check that all user members are actually present */

int sysdb_legacy_store_group(TALLOC_CTX *memctx,
                             struct sysdb_ctx *sysdb,
                             const char *domain,
                             const char *name, gid_t gid,
                             char **members)
{
    TALLOC_CTX *tmp_ctx;
    const char *attrs[] = { SYSDB_GR_NAME, NULL };
    struct ldb_dn *group_dn;
    struct ldb_result *res;
    struct ldb_message *msg;
    int i, ret, lret;
    int flags;

    tmp_ctx = talloc_new(memctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    group_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                           SYSDB_GR_NAME"=%s,"SYSDB_TMPL_GROUP_BASE,
                           name, domain);
    if (group_dn == NULL) {
        talloc_free(tmp_ctx);
        return ENOMEM;
    }

    /* Start a transaction to ensure that nothing changes
     * underneath us while we're working
     */
    lret = ldb_transaction_start(sysdb->ldb);
    if (lret != LDB_SUCCESS) {
        DEBUG(1, ("Failed ldb transaction start !? (%d)\n", lret));
        talloc_free(tmp_ctx);
        return EIO;
    }

    /* Determine if the group already exists */
    lret = ldb_search(sysdb->ldb, tmp_ctx, &res, group_dn,
                      LDB_SCOPE_BASE, attrs, SYSDB_GRENT_FILTER);
    if (lret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to make search request: %s(%d)[%s]\b",
                ldb_strerror(lret), lret, ldb_errstring(sysdb->ldb)));
        ret = EIO;
        goto done;
    }

    switch(res->count) {
    case 0:
        flags = LDB_FLAG_MOD_ADD;
        DEBUG(7, ("Adding new entry\n"));
        break;
    case 1:
        flags = LDB_FLAG_MOD_REPLACE;
        DEBUG(7, ("Replacing existing entry\n"));
        break;
    default:
        DEBUG(0, ("Cache DB corrupted, base search returned %d results\n",
                  res->count));
        ret = EIO;
        goto done;
    }
    talloc_free(res);
    res = NULL;

    /* Set up the add/replace request */
    msg = ldb_msg_new(tmp_ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = group_dn;

    if (flags == LDB_FLAG_MOD_ADD) {
        lret = ldb_msg_add_empty(msg, "objectClass", flags, NULL);
        if (lret == LDB_SUCCESS) {
            lret = ldb_msg_add_string(msg, "objectClass", "group");
        }
        if (lret != LDB_SUCCESS) {
            ret = ENOMEM;
            goto done;
        }

        lret = ldb_msg_add_empty(msg, SYSDB_GR_NAME, flags, NULL);
        if (lret == LDB_SUCCESS) {
            lret = ldb_msg_add_string(msg, SYSDB_GR_NAME, name);
        }
        if (lret != LDB_SUCCESS) {
            ret = ENOMEM;
            goto done;
        }
    }

    /* gid */
    if (gid) {
        lret = ldb_msg_add_empty(msg, SYSDB_GR_GIDNUM, flags, NULL);
        if (lret == LDB_SUCCESS) {
            lret = ldb_msg_add_fmt(msg, SYSDB_GR_GIDNUM,
                                   "%lu", (unsigned long)gid);
        }
        if (lret != LDB_SUCCESS) {
            ret = ENOMEM;
            goto done;
        }
    } else {
        DEBUG(0, ("Cached groups can't have GID == 0\n"));
        ret = EINVAL;
        goto done;
    }

    /* modification time */
    lret = ldb_msg_add_empty(msg, SYSDB_LAST_UPDATE, flags, NULL);
    if (lret == LDB_SUCCESS) {
        lret = ldb_msg_add_fmt(msg, SYSDB_LAST_UPDATE,
                               "%ld", (long int)time(NULL));
    }
    if (lret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    /* members */
    if (members && members[0]) {
        lret = ldb_msg_add_empty(msg, SYSDB_LEGACY_MEMBER, flags, NULL);
        if (lret != LDB_SUCCESS) {
            ret = ENOMEM;
            goto done;
        }
        for (i = 0; members[i]; i++) {
            lret = ldb_msg_add_string(msg, SYSDB_LEGACY_MEMBER, members[i]);
            if (lret != LDB_SUCCESS) {
                ret = ENOMEM;
                goto done;
            }
        }
    }

    if (flags == LDB_FLAG_MOD_ADD) {
        lret = ldb_add(sysdb->ldb, msg);
    } else {
        lret = ldb_modify(sysdb->ldb, msg);
    }
    if (lret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to make modify request: %s(%d)[%s]\n",
                  ldb_strerror(lret), lret, ldb_errstring(sysdb->ldb)));
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    if (ret == EOK) {
        lret = ldb_transaction_commit(sysdb->ldb);
        if (lret != LDB_SUCCESS) {
            DEBUG(1, ("Failed ldb transaction start !? (%d)\n", lret));
            ret = EIO;
        }
    } else {
        lret = ldb_transaction_cancel(sysdb->ldb);
        if (lret != LDB_SUCCESS) {
            DEBUG(1, ("Failed to cancel ldb transaction (%d)\n", lret));
            ret = EIO;
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}

/* Wrapper around adding a user to a POSIX group */
int sysdb_add_user_to_group(TALLOC_CTX *mem_ctx,
                            struct sysdb_ctx *sysdb,
                            const char *domain,
                            const char *group,
                            const char *username)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_dn *user_dn;
    struct ldb_dn *group_dn;


    if (!sysdb || !domain || !group || !username) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    user_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                             SYSDB_PW_NAME"=%s,"SYSDB_TMPL_USER_BASE,
                             username, domain);
    if (!user_dn) {
        ret = ENOMEM;
        goto done;
    }

    group_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                              SYSDB_GR_NAME"=%s,"SYSDB_TMPL_GROUP_BASE,
                              group, domain);
    if (group_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_add_group_member(tmp_ctx, sysdb, user_dn, group_dn);

done:
    talloc_free(tmp_ctx);
    return ret;
}

/* Wrapper around adding a user to a POSIX group */
int sysdb_remove_user_from_group(TALLOC_CTX *mem_ctx,
                                 struct sysdb_ctx *sysdb,
                                 const char *domain,
                                 const char *group,
                                 const char *username)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_dn *user_dn;
    struct ldb_dn *group_dn;


    if (!sysdb || !domain || !group || !username) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    user_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                             SYSDB_PW_NAME"=%s,"SYSDB_TMPL_USER_BASE,
                             username, domain);
    if (!user_dn) {
        ret = ENOMEM;
        goto done;
    }

    group_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                              SYSDB_GR_NAME"=%s,"SYSDB_TMPL_GROUP_BASE,
                              group, domain);
    if (group_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_remove_group_member(tmp_ctx, sysdb, user_dn, group_dn);

done:
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_delete_group(TALLOC_CTX *memctx,
                       struct sysdb_ctx *sysdb,
                       const char *domain, const char *name)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *group_dn;
    int lret, ret = EOK;

    tmp_ctx = talloc_new(memctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    group_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                              SYSDB_GR_NAME"=%s,"SYSDB_TMPL_GROUP_BASE,
                              name, domain);
    if (!group_dn) {
        talloc_free(tmp_ctx);
        return ENOMEM;
    }

    lret = ldb_delete(sysdb->ldb, group_dn);

    if (lret != LDB_SUCCESS && lret != LDB_ERR_NO_SUCH_OBJECT) {
        DEBUG(2, ("LDB Error: %s(%d)\nError Message: [%s]\n",
              ldb_strerror(ret), ret, ldb_errstring(sysdb->ldb)));
        ret = EIO;
    }

    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_delete_group_by_gid(TALLOC_CTX *memctx,
                              struct sysdb_ctx *sysdb,
                              const char *domain, gid_t gid)
{
    TALLOC_CTX *tmp_ctx;
    const char *attrs[] = { SYSDB_GR_NAME, SYSDB_GR_GIDNUM, NULL };
    struct ldb_dn *base_dn;
    struct ldb_dn *group_dn;
    struct ldb_result *res;
    int lret, ret;

    tmp_ctx = talloc_new(memctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    base_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                             SYSDB_TMPL_GROUP_BASE, domain);
    if (!base_dn) {
        talloc_free(tmp_ctx);
        return ENOMEM;
    }

    lret = ldb_transaction_start(sysdb->ldb);
    if (lret != LDB_SUCCESS) {
        DEBUG(1, ("Failed ldb transaction start !? (%d)\n", lret));
        ret = EIO;
        goto done;
    }

    lret = ldb_search(sysdb->ldb, tmp_ctx, &res, base_dn,
                      LDB_SCOPE_ONELEVEL, attrs,
                      SYSDB_GRGID_FILTER,
                      (unsigned long)gid);
    if (lret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to make search request: %s(%d)[%s]\n",
                  ldb_strerror(lret), lret, ldb_errstring(sysdb->ldb)));
        ret = EIO;
        goto done;
    }

    if (res->count == 0) {
        DEBUG(7, ("Base search returned no results\n"));
        ret = EOK;
        goto done;
    }
    if (res->count > 1) {
        DEBUG(0, ("Cache DB corrupted, base search returned %d results\n",
                  res->count));
        ret = EIO;
        goto done;
    }

    group_dn = ldb_dn_copy(tmp_ctx, res->msgs[0]->dn);
    if (!group_dn) {
        ret = ENOMEM;
        goto done;
    }

    talloc_free(res);
    res = NULL;

    lret = ldb_delete(sysdb->ldb, group_dn);

    if (lret != LDB_SUCCESS && lret != LDB_ERR_NO_SUCH_OBJECT) {
        DEBUG(2, ("LDB Error: %s(%d)\nError Message: [%s]\n",
              ldb_strerror(ret), ret, ldb_errstring(sysdb->ldb)));
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    if (ret == EOK) {
        lret = ldb_transaction_commit(sysdb->ldb);
        if (lret != LDB_SUCCESS) {
            DEBUG(1, ("Failed ldb transaction commit !! (%d)\n", lret));
            ret = EIO;
        }
    } else {
        lret = ldb_transaction_cancel(sysdb->ldb);
        if (lret != LDB_SUCCESS) {
            DEBUG(1, ("Failed to cancel ldb transaction (%d)\n", lret));
            ret = EIO;
        }
    }

    talloc_free(tmp_ctx);
    return ret;
}

