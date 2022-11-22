/*
    Authors:
        Justin Stephenson <jstephen@redhat.com>

    Copyright (C) 2022 Red Hat

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

#include <ldb.h>

#include "db/sysdb.h"
#include "db/sysdb_private.h"

static errno_t
sysdb_get_passkey_user_verification_string_attr(TALLOC_CTX *mem_ctx,
                                                struct sysdb_ctx *sysdb,
                                                struct ldb_dn *dn,
                                                const char **_attr)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    const char *attr;
    const char *attrs[] = { SYSDB_PASSKEY_USER_VERIFICATION, NULL };
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = ldb_search(sysdb->ldb, tmp_ctx, &res, dn, LDB_SCOPE_BASE, attrs,
                     NULL);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    if (res->count > 1) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Base search returned [%d] results, expected 1.\n", res->count);
        ret = EINVAL;
        goto done;
    } else if (res->count == 0) {
        ret = ENOENT;
        goto done;
    } else {
        /* res->count == 1 */
        attr = ldb_msg_find_attr_as_string(res->msgs[0],
                                           SYSDB_PASSKEY_USER_VERIFICATION,
                                           NULL);
        if (attr == NULL) {
            ret = ENOENT;
            goto done;
        }
    }

    *_attr = talloc_steal(mem_ctx, attr);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_get_passkey_user_verification(TALLOC_CTX *mem_ctx,
                                    struct sysdb_ctx *sysdb,
                                    struct ldb_dn *dn,
                                    const char **_passkey_user_verification)
{
    TALLOC_CTX *tmp_ctx;
    const char *passkey_user_verification = NULL;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_get_passkey_user_verification_string_attr(
          tmp_ctx, sysdb, dn, &passkey_user_verification);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sysdb_get_passkey_user_verification_string_attr() failed "
              "[%d]: [%s]",
              ret, sss_strerror(ret));
        goto done;
    } else if (ret == ENOENT) {
        *_passkey_user_verification = NULL;
        goto done;
    } else {
        /* ret == EOK */
        *_passkey_user_verification = talloc_steal(mem_ctx,
                                                   passkey_user_verification);
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_update_passkey_user_verification(struct sysdb_ctx *sysdb,
                                       struct ldb_dn *dn,
                                       const char *passkey_user_verification)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *msg;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    msg = ldb_msg_new(tmp_ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = dn;

    ret = ldb_msg_add_empty(msg, SYSDB_PASSKEY_USER_VERIFICATION,
                            LDB_FLAG_MOD_REPLACE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    if (passkey_user_verification != NULL) {
        ret = ldb_msg_add_string(msg, SYSDB_PASSKEY_USER_VERIFICATION,
                                 passkey_user_verification);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ldb_modify()_failed: [%s][%d][%s]\n",
              ldb_strerror(ret), ret, ldb_errstring(sysdb->ldb));
        ret = sysdb_error_to_errno(ret);
        goto done;
    }


    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_domain_get_passkey_user_verification(TALLOC_CTX *mem_ctx,
                                           struct sysdb_ctx *sysdb,
                                           const char *domain_name,
                                           const char **_user_verification)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *dn;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb, SYSDB_DOM_BASE, domain_name);
    if (dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_get_passkey_user_verification(mem_ctx, sysdb, dn,
                                              _user_verification);

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_domain_update_passkey_user_verification(struct sysdb_ctx *sysdb,
                                              const char *domain_name,
                                              const char *user_verification)
{

    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *dn;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb, SYSDB_DOM_BASE, domain_name);
    if (dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_update_passkey_user_verification(sysdb, dn,
                                                 user_verification);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sysdb_update_passkey_user_verification() failed [%d]: [%s].\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}
