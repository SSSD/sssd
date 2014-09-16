/*
   SSSD

   System Database - View and Override related calls

   Copyright (C) 2014 Sumit Bose <sbose@redhat.com>

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

/* In general is should not be possible that there is a view container without
 * a view name set. But to be on the safe side we return both information
 * separately. */
static errno_t sysdb_get_view_name_ex(TALLOC_CTX *mem_ctx,
                                      struct sysdb_ctx *sysdb,
                                      char **_view_name,
                                      bool *view_container_exists)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    const char *tmp_str;
    struct ldb_dn *view_base_dn;
    struct ldb_result *res;
    const char *attrs[] = {SYSDB_VIEW_NAME,
                           NULL};

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    view_base_dn = ldb_dn_new(tmp_ctx, sysdb->ldb, SYSDB_TMPL_VIEW_BASE);
    if (view_base_dn == NULL) {
        ret = EIO;
        goto done;
    }
    ret = ldb_search(sysdb->ldb, tmp_ctx, &res, view_base_dn, LDB_SCOPE_BASE,
                     attrs, NULL);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    if (res->count > 1) {
        DEBUG(SSSDBG_OP_FAILURE, "Base search returned [%d] results, "
                                 "expected 1.\n", res->count);
        ret = EINVAL;
        goto done;
    }

    if (res->count == 0) {
        *view_container_exists = false;
        ret = ENOENT;
        goto done;
    } else {
        *view_container_exists = true;
        tmp_str = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_VIEW_NAME,
                                              NULL);
        if (tmp_str == NULL) {
            ret = ENOENT;
            goto done;
        }
    }

    *_view_name = talloc_steal(mem_ctx, discard_const(tmp_str));
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_get_view_name(TALLOC_CTX *mem_ctx, struct sysdb_ctx *sysdb,
                            char **view_name)
{
    bool view_container_exists;

    return sysdb_get_view_name_ex(mem_ctx, sysdb, view_name,
                                  &view_container_exists);
}

errno_t sysdb_update_view_name(struct sysdb_ctx *sysdb,
                               const char *view_name)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    char *tmp_str;
    bool view_container_exists = false;
    bool add_view_name = false;
    struct ldb_message *msg;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_get_view_name_ex(tmp_ctx, sysdb, &tmp_str,
                                 &view_container_exists);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_get_view_name_ex failed.\n");
        goto done;
    }

    if (ret == EOK) {
        if (strcmp(tmp_str, view_name) == 0) {
            /* view name already known, nothing to do */
            DEBUG(SSSDBG_TRACE_ALL, "View name already in place.\n");
            ret = EOK;
            goto done;
        } else {
            /* view name changed */
            /* not supported atm */
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "View name changed from [%s] to [%s]. NOT SUPPORTED.\n",
                  tmp_str, view_name);
            ret = ENOTSUP;
            goto done;
        }
    }

    add_view_name = true;

    msg = ldb_msg_new(tmp_ctx);
    if (msg == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_new failed.\n");
        ret = ENOMEM;
        goto done;
    }

    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, SYSDB_TMPL_VIEW_BASE);
    if (msg->dn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new failed.\n");
        ret = EIO;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, SYSDB_VIEW_NAME,
                            add_view_name ? LDB_FLAG_MOD_ADD
                                          : LDB_FLAG_MOD_REPLACE,
                            NULL);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = ldb_msg_add_string(msg, SYSDB_VIEW_NAME, view_name);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    if (view_container_exists) {
        ret = ldb_modify(sysdb->ldb, msg);
    } else {
        ret = ldb_add(sysdb->ldb, msg);
    }
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to %s view container",
                                    view_container_exists ? "modify" : "add");
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}
