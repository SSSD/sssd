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

static errno_t add_aliases_for_name_override(struct sss_domain_info *domain,
                                             struct sysdb_attrs *attrs,
                                             const char *name_override)
{
    char *fq_name = NULL;
    int ret;

    if (strchr(name_override, '@') == NULL) {
        fq_name = sss_tc_fqname(attrs, domain->names, domain, name_override);
        if (fq_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "sss_tc_fqname failed.\n");
            return ENOMEM;
        }

        if (!domain->case_sensitive) {
            ret = sysdb_attrs_add_lc_name_alias(attrs, fq_name);
        } else {
            ret = sysdb_attrs_add_string(attrs, SYSDB_NAME_ALIAS,
                                         fq_name);
        }
        talloc_free(fq_name);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sysdb_attrs_add_lc_name_alias failed.\n");
            return ret;
        }
    }

    if (!domain->case_sensitive) {
        ret = sysdb_attrs_add_lc_name_alias(attrs, name_override);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sysdb_attrs_add_lc_name_alias failed.\n");
            return ret;
        }
    }

    return EOK;
}

errno_t sysdb_store_override(struct sss_domain_info *domain,
                             const char *view_name,
                             enum sysdb_member_type type,
                             struct sysdb_attrs *attrs, struct ldb_dn *obj_dn)
{
    TALLOC_CTX *tmp_ctx;
    const char *anchor;
    int ret;
    struct ldb_dn *override_dn;
    const char *override_dn_str;
    const char *obj_dn_str;
    const char *obj_attrs[] = { SYSDB_OBJECTCLASS,
                                SYSDB_OVERRIDE_DN,
                                NULL};
    size_t count = 0;
    struct ldb_message **msgs;
    struct ldb_message *msg = NULL;
    const char *obj_override_dn;
    bool add_ref = true;
    size_t c;
    bool in_transaction = false;
    bool has_override = true;
    const char *name_override;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (attrs != NULL) {
        has_override = true;
        ret = sysdb_attrs_get_string(attrs, SYSDB_OVERRIDE_ANCHOR_UUID,
                                     &anchor);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Missing anchor in override attributes.\n");
            ret = EINVAL;
            goto done;
        }

        override_dn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                                     SYSDB_TMPL_OVERRIDE, anchor, view_name);
        if (override_dn == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new_fmt failed.\n");
            ret = ENOMEM;
            goto done;
        }
    } else {
        /* if there is no override for the given object, just store the DN of
         * the object iself in the SYSDB_OVERRIDE_DN attribute to indicate
         * that it was checked if an override exists and none was found. */
        has_override = false;
        override_dn = obj_dn;
    }

    override_dn_str = ldb_dn_get_linearized(override_dn);
    obj_dn_str = ldb_dn_get_linearized(obj_dn);
    if (override_dn_str == NULL || obj_dn_str == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_get_linearized failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_entry(tmp_ctx, domain->sysdb, obj_dn, LDB_SCOPE_BASE,
                             NULL, obj_attrs, &count, &msgs);
    if (ret != EOK) {
        if (ret == ENOENT) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Object to override does not exists.\n");
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_search_entry failed.\n");
        }
        goto done;
    }
    if (count != 1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Base searched returned more than one object.\n");
        ret = EINVAL;
        goto done;
    }

    obj_override_dn = ldb_msg_find_attr_as_string(msgs[0], SYSDB_OVERRIDE_DN,
                                                  NULL);
    if (obj_override_dn != NULL) {
        if (strcmp(obj_override_dn, override_dn_str) != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Existing [%s] and new [%s] override DN do not match.\n",
                   obj_override_dn, override_dn_str);
            ret = EINVAL;
            goto done;
        }

        add_ref = false;
    }

    ret = ldb_transaction_start(domain->sysdb->ldb);
    if (ret != EOK) {
        return sysdb_error_to_errno(ret);
    }
    in_transaction = true;

    if (has_override) {
        ret = ldb_delete(domain->sysdb->ldb, override_dn);
        if (ret != EOK) {
            DEBUG(SSSDBG_TRACE_ALL,
                  "ldb_delete failed, maybe object did not exist. Ignoring.\n");
        }

        ret = sysdb_attrs_get_string(attrs, SYSDB_NAME, &name_override);
        if (ret == EOK) {
            ret = add_aliases_for_name_override(domain, attrs, name_override);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "add_aliases_for_name_override failed.\n");
                goto done;
            }
        } else if (ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }

        msg = ldb_msg_new(tmp_ctx);
        if (msg == NULL) {
            ret = ENOMEM;
            goto done;
        }

        msg->dn = override_dn;

        msg->elements = talloc_array(msg, struct ldb_message_element,
                                     attrs->num);
        if (msg->elements == NULL) {
            ret = ENOMEM;
            goto done;
        }

        for (c = 0; c < attrs->num; c++) {
            msg->elements[c] = attrs->a[c];
            msg->elements[c].flags = LDB_FLAG_MOD_ADD;
        }
        msg->num_elements = attrs->num;

        ret = ldb_msg_add_empty(msg, SYSDB_OBJECTCLASS, LDB_FLAG_MOD_ADD, NULL);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_add_empty failed.\n");
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        switch(type) {
        case SYSDB_MEMBER_USER:
            ret = ldb_msg_add_string(msg, SYSDB_OBJECTCLASS,
                                     SYSDB_OVERRIDE_USER_CLASS);
            break;
        case SYSDB_MEMBER_GROUP:
            ret = ldb_msg_add_string(msg, SYSDB_OBJECTCLASS,
                                     SYSDB_OVERRIDE_GROUP_CLASS);
            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected object type.\n");
            ret = EINVAL;
            goto done;
        }
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_empty(msg, SYSDB_OVERRIDE_OBJECT_DN, LDB_FLAG_MOD_ADD,
                                NULL);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_add_empty failed.\n");
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_OVERRIDE_OBJECT_DN, obj_dn_str);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_add(domain->sysdb->ldb, msg);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to store override entry: %s(%d)[%s]\n",
                  ldb_strerror(ret), ret, ldb_errstring(domain->sysdb->ldb));
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    if (add_ref) {
        talloc_free(msg);
        msg = ldb_msg_new(tmp_ctx);
        if (msg == NULL) {
            ret = ENOMEM;
            goto done;
        }

        msg->dn = obj_dn;

        ret = ldb_msg_add_empty(msg, SYSDB_OVERRIDE_DN, LDB_FLAG_MOD_ADD,
                                NULL);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_add_empty failed.\n");
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_OVERRIDE_DN, override_dn_str);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_modify(domain->sysdb->ldb, msg);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to store override DN: %s(%d)[%s]\n",
                  ldb_strerror(ret), ret, ldb_errstring(domain->sysdb->ldb));
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    ret = EOK;

done:
    if (in_transaction) {
        if (ret != EOK) {
            DEBUG(SSSDBG_TRACE_FUNC, "Error: %d (%s)\n", ret, strerror(ret));
            ldb_transaction_cancel(domain->sysdb->ldb);
        } else {
            ret = ldb_transaction_commit(domain->sysdb->ldb);
            ret = sysdb_error_to_errno(ret);
        }
    }

    talloc_zfree(tmp_ctx);
    return ret;
}
