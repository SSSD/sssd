/*
    Authors:
        Fabiano Fidêncio <fidencio@redhat.com>

    Copyright (C) 2017 Red Hat

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
sysdb_get_domain_resolution_order_string_attr(TALLOC_CTX *mem_ctx,
                                              struct sysdb_ctx *sysdb,
                                              struct ldb_dn *dn,
                                              const char *const *attrs,
                                              const char **_attr)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    const char *attr;
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
        attr = ldb_msg_find_attr_as_string(res->msgs[0], attrs[0], NULL);
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
sysdb_get_domain_resolution_order(TALLOC_CTX *mem_ctx,
                                  struct sysdb_ctx *sysdb,
                                  struct ldb_dn *dn,
                                  const char **_domain_resolution_order)
{
    TALLOC_CTX *tmp_ctx;
    const char *domain_resolution_order = NULL;
    const char *attrs[] = { SYSDB_DOMAIN_RESOLUTION_ORDER, NULL };
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_get_domain_resolution_order_string_attr(
            tmp_ctx, sysdb, dn, attrs, &domain_resolution_order);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sysdb_get_domain_resolution_order_string_attr() failed "
              "[%d]: [%s]",
              ret, sss_strerror(ret));
        goto done;
    } else if (ret == ENOENT) {
        *_domain_resolution_order = NULL;
        goto done;
    } else {
        /* ret == EOK */
        *_domain_resolution_order = talloc_steal(mem_ctx,
                                                 domain_resolution_order);
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_update_domain_resolution_order(struct sysdb_ctx *sysdb,
                                     struct ldb_dn *dn,
                                     const char *domain_resolution_order)
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

    ret = ldb_msg_add_empty(msg, SYSDB_DOMAIN_RESOLUTION_ORDER,
                            LDB_FLAG_MOD_REPLACE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    if (domain_resolution_order != NULL) {
        ret = ldb_msg_add_string(msg, SYSDB_DOMAIN_RESOLUTION_ORDER,
                                 domain_resolution_order);
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
