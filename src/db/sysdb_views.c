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
#include "util/cert.h"
#include "db/sysdb_private.h"
#include "db/sysdb_domain_resolution_order.h"

#define SYSDB_VIEWS_BASE "cn=views,cn=sysdb"
#define SYSDB_DOMAIN_TEMPLATE_OVERRIDE_FILTER "(templateType=domain)"
#define SYSDB_GLOBAL_TEMPLATE_OVERRIDE_FILTER "(templateType=global)"
#define SYSDB_GLOBAL_TEMPLATE_SID "S-1-5-11"

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
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "View name changed from [%s] to [%s].\n", tmp_str, view_name);
        }
    } else {
        add_view_name = true;
    }

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
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to %s view container [%s](%d)[%s]\n",
              view_container_exists ? "modify" : "add",
              ldb_strerror(ret), ret, ldb_errstring(sysdb->ldb));
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_get_view_domain_resolution_order(TALLOC_CTX *mem_ctx,
                                       struct sysdb_ctx *sysdb,
                                       const char **_domain_resolution_order)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *dn;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    dn = ldb_dn_new(tmp_ctx, sysdb->ldb, SYSDB_VIEWS_BASE);
    if (dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_get_domain_resolution_order(mem_ctx, sysdb, dn,
                                            _domain_resolution_order);

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_update_view_domain_resolution_order(struct sysdb_ctx *sysdb,
                                          const char *domain_resolution_order)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *dn;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    dn = ldb_dn_new(tmp_ctx, sysdb->ldb, SYSDB_VIEWS_BASE);
    if (dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_update_domain_resolution_order(sysdb, dn,
                                               domain_resolution_order);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sysdb_update_domain_resolution_order() failed [%d]: [%s].\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_delete_view_tree(struct sysdb_ctx *sysdb, const char *view_name)
{
    struct ldb_dn *dn;
    TALLOC_CTX *tmp_ctx;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb, SYSDB_TMPL_VIEW_SEARCH_BASE,
                        view_name);
    if (dn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new_fmt failed.\n");
        ret = EIO;
        goto done;
    }

    ret = sysdb_delete_recursive(sysdb, dn, true);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_delete_recursive failed.\n");
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t invalidate_entry_override(struct sysdb_ctx *sysdb,
                                         struct ldb_dn *dn,
                                         struct ldb_message *msg_del,
                                         struct ldb_message *msg_repl)
{
    int ret;

    msg_del->dn = dn;
    msg_repl->dn = dn;

    ret = ldb_modify(sysdb->ldb, msg_del);
    if (ret != LDB_SUCCESS && ret != LDB_ERR_NO_SUCH_ATTRIBUTE) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ldb_modify failed: [%s](%d)[%s]\n",
              ldb_strerror(ret), ret, ldb_errstring(sysdb->ldb));
        return sysdb_error_to_errno(ret);
    }

    ret = ldb_modify(sysdb->ldb, msg_repl);
    if (ret != LDB_SUCCESS && ret != LDB_ERR_NO_SUCH_ATTRIBUTE) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ldb_modify failed: [%s](%d)[%s]\n",
              ldb_strerror(ret), ret, ldb_errstring(sysdb->ldb));
        return sysdb_error_to_errno(ret);
    }

    if (sysdb->ldb_ts != NULL) {
        ret = ldb_modify(sysdb->ldb_ts, msg_repl);
        if (ret != LDB_SUCCESS && ret != LDB_ERR_NO_SUCH_ATTRIBUTE) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "ldb_modify failed: [%s](%d)[%s]\n",
                  ldb_strerror(ret), ret, ldb_errstring(sysdb->ldb_ts));
            return sysdb_error_to_errno(ret);
        }
    }

    return EOK;
}

errno_t sysdb_invalidate_overrides(struct sysdb_ctx *sysdb)
{
    int ret;
    int sret;
    TALLOC_CTX *tmp_ctx;
    bool in_transaction = false;
    struct ldb_result *res;
    size_t c;
    struct ldb_message *msg_del;
    struct ldb_message *msg_repl;
    struct ldb_dn *base_dn;

    if (sysdb->ldb_ts == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Timestamp cache context not available, cache might not be "
              "invalidated completely. Please call 'sss_cache -E' or remove "
              "the cache file if there are issues after a view name change.\n");
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    base_dn = ldb_dn_new(tmp_ctx, sysdb->ldb, SYSDB_BASE);
    if (base_dn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new failed\n");
        ret = ENOMEM;
        goto done;
    }

    msg_del = ldb_msg_new(tmp_ctx);
    if (msg_del == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_new failed.\n");
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_empty(msg_del, SYSDB_OVERRIDE_DN, LDB_FLAG_MOD_DELETE,
                            NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_add_empty failed.\n");
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    msg_repl = ldb_msg_new(tmp_ctx);
    if (msg_repl == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_new failed.\n");
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_empty(msg_repl, SYSDB_CACHE_EXPIRE,
                            LDB_FLAG_MOD_REPLACE, NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_add_empty failed.\n");
        ret = sysdb_error_to_errno(ret);
        goto done;
    }
    ret = ldb_msg_add_string(msg_repl, SYSDB_CACHE_EXPIRE, "1");
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_add_string failed.\n");
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_transaction_start failed.\n");
        goto done;
    }
    in_transaction = true;

    ret = ldb_search(sysdb->ldb, tmp_ctx, &res, base_dn, LDB_SCOPE_SUBTREE,
                     NULL, "%s", SYSDB_UC);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_search_entry failed.\n");
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    for (c = 0; c < res->count; c++) {
        ret = invalidate_entry_override(sysdb, res->msgs[c]->dn, msg_del,
                                                                 msg_repl);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "invalidate_entry_override failed [%d][%s].\n",
                  ret, sss_strerror(ret));
            goto done;
        }
    }

    talloc_free(res);

    ret = ldb_search(sysdb->ldb, tmp_ctx, &res, base_dn, LDB_SCOPE_SUBTREE,
                     NULL, "%s", SYSDB_GC);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_search_entry failed.\n");
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    for (c = 0; c < res->count; c++) {
        ret = invalidate_entry_override(sysdb, res->msgs[c]->dn, msg_del,
                                                                 msg_repl);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "invalidate_entry_override failed [%d][%s].\n",
                  ret, sss_strerror(ret));
            goto done;
        }
    }

    ret = EOK;

done:
    if (in_transaction) {
        if (ret == EOK) {
            sret = sysdb_transaction_commit(sysdb);
            if (sret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_transaction_commit failed, " \
                                         "nothing we can do about.\n");
                ret = sret;
            }
        } else {
            sret = sysdb_transaction_cancel(sysdb);
            if (sret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_transaction_cancel failed, " \
                                         "nothing we can do about.\n");
            }
        }
    }

    talloc_free(tmp_ctx);

    return ret;
}

static errno_t
add_name_and_aliases_for_name_override(struct sss_domain_info *domain,
                                       struct sysdb_attrs *attrs,
                                       bool add_name,
                                       const char *name_override)
{
    int ret;

    if (add_name) {
        ret = sysdb_attrs_add_string(attrs, SYSDB_DEFAULT_OVERRIDE_NAME,
                                     name_override);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_add_lc_name_alias failed.\n");
            return ret;
        }
    }

    if (!domain->case_sensitive) {
        ret = sysdb_attrs_add_lc_name_alias(attrs, name_override);
    } else {
        ret = sysdb_attrs_add_string(attrs, SYSDB_NAME_ALIAS, name_override);
    }
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_add_lc_name_alias failed.\n");
        return ret;
    }

    return EOK;
}

static errno_t sysdb_add_template_values(struct sysdb_attrs *attrs,
                                         struct sss_domain_info *domain,
                                         const char *global_template_homedir,
                                         const char *global_template_shell,
                                         const char *override_dn,
                                         bool has_override)
{
    int ret;
    const char *classes[] = {"ipaOverrideAnchor", "top", "ipaUserOverride", "ipasshuser",
                             "ipaSshGroupOfPubKeys", NULL};

    if (attrs == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Expected sysdb attrs to populate\n");
        ret = EINVAL;
        goto done;
    }

    /* originalDN */
    ret = sysdb_attrs_add_string(attrs, SYSDB_ORIG_DN, override_dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Error setting SYSDB_ORIG_DN: [%s]\n",
                                 strerror(ret));
        goto done;
    }

    /* Original objectClass, existing override attrs already has these classes */
    if (!has_override) {
        for (int i = 0; classes[i] != NULL; i++) {
            ret = sysdb_attrs_add_string(attrs, SYSDB_ORIG_OBJECTCLASS, classes[i]);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE, "Error setting SYSDB_ORIG_OBJECTCLASS: [%s]\n",
                                         strerror(ret));
                goto done;
            }
        }
    }

    /* Apply homedir template values */
    if (domain->template_homedir != NULL) {
        ret = sysdb_attrs_add_string(attrs, SYSDB_HOMEDIR, domain->template_homedir);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Error setting domain template homedir: [%s]\n",
                                     strerror(ret));
            goto done;
        }
    } else if (global_template_homedir != NULL) {
        ret = sysdb_attrs_add_string(attrs, SYSDB_HOMEDIR, global_template_homedir);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Error setting global template homedir: [%s]\n",
                                     strerror(ret));
            goto done;
        }
    }

    /* Apply shell template values */
    if (domain->template_shell != NULL) {
        ret = sysdb_attrs_add_string(attrs, SYSDB_SHELL, domain->template_shell);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Error setting domain template shell: [%s]\n",
                                     strerror(ret));
            goto done;
        }
    } else if (global_template_shell != NULL ) {
        ret = sysdb_attrs_add_string(attrs, SYSDB_SHELL, global_template_shell);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Error setting global template shell: [%s]\n",
                                     strerror(ret));
            goto done;
        }
    }

    ret = EOK;

done:
    return ret;
}

errno_t sysdb_update_override_object(TALLOC_CTX *mem_ctx,
                                     struct sss_domain_info *domain,
                                     struct sysdb_attrs *attrs,
                                     enum sysdb_member_type type,
                                     struct ldb_dn *override_dn,
                                     struct ldb_dn *obj_dn,
                                     bool has_override,
                                     bool template)
{
    const char *override_dn_str;
    const char *obj_dn_str;
    int ret;
    size_t count = 0;
    const char *obj_attrs[] = { SYSDB_OBJECTCLASS,
                                SYSDB_OVERRIDE_DN,
                                NULL};
    struct ldb_message **msgs;
    struct ldb_message *msg = NULL;
    const char *obj_override_dn;
    bool add_ref = true;
    bool in_transaction = false;
    size_t c;
    const char *name_override;

    /* Add/Update override object in cache */
    override_dn_str = ldb_dn_get_linearized(override_dn);
    obj_dn_str = ldb_dn_get_linearized(obj_dn);
    if (override_dn_str == NULL || obj_dn_str == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_get_linearized failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_entry(mem_ctx, domain->sysdb, obj_dn, LDB_SCOPE_BASE,
                             NULL, obj_attrs, &count, &msgs);
    if (ret != EOK) {
        if (ret == ENOENT) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Object to override does not exists.\n");
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_search_entry failed.\n");
        }
        goto done;
    }
    if (count != 1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Base search returned more than one object.\n");
        ret = EINVAL;
        goto done;
    }

    obj_override_dn = ldb_msg_find_attr_as_string(msgs[0], SYSDB_OVERRIDE_DN,
                                                  NULL);
    if (obj_override_dn != NULL) {
        /* obj_override_dn can either point to the object itself, i.e there is
         * no override, or to a override object. This means it can change from
         * the object DN to a override DN and back but not from one override
         * DN to a different override DN. If the new and the old DN are the
         * same we do not need to update the original object.  */
        if (strcmp(obj_override_dn, override_dn_str) != 0) {
            if (strcmp(obj_override_dn, obj_dn_str) != 0
                    && strcmp(override_dn_str, obj_dn_str) != 0) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Existing [%s] and new [%s] override DN do not match.\n",
                       obj_override_dn, override_dn_str);
                ret = EINVAL;
                goto done;
            }
        } else {
            add_ref = false;
        }
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

        if (!template) {
            ret = sysdb_attrs_get_string(attrs, SYSDB_NAME, &name_override);
            if (ret == EOK) {
                ret = add_name_and_aliases_for_name_override(domain, attrs, false,
                                                             name_override);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "add_name_and_aliases_for_name_override failed.\n");
                    goto done;
                }
            } else if (ret != ENOENT) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
                goto done;
            }
        }

        msg = ldb_msg_new(mem_ctx);
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
            /* Set num_values to 1 because by default user and group overrides
             * use the same attribute name for the GID and this cause SSSD
             * machinery to add the same value twice */
            if (attrs->a[c].num_values > 1
                    && strcmp(attrs->a[c].name, SYSDB_GIDNUM) == 0) {
                attrs->a[c].num_values = 1;
            }
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
            DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected object type %d.\n", type);
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

    /* Update overrideDN value of actual user or group object to point to override */
    if (add_ref) {
        talloc_free(msg);
        msg = ldb_msg_new(mem_ctx);
        if (msg == NULL) {
            ret = ENOMEM;
            goto done;
        }

        msg->dn = obj_dn;

        ret = ldb_msg_add_empty(msg, SYSDB_OVERRIDE_DN,
                                obj_override_dn == NULL ? LDB_FLAG_MOD_ADD
                                                        : LDB_FLAG_MOD_REPLACE,
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

    return ret;
}

errno_t sysdb_store_override_template(struct sss_domain_info *domain,
                                      struct sysdb_attrs *override_attrs,
                                      const char *global_template_homedir,
                                      const char *global_template_shell,
                                      const char *view_name,
                                      struct ldb_dn *obj_dn)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_dn *override_dn;
    struct sysdb_attrs *attrs;
    const char *override_dn_str;
    const char *anchor;
    bool has_override = false;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (override_attrs != NULL) {
        has_override = true;
    }

    if (domain->template_homedir == NULL && domain->template_shell == NULL
        && global_template_homedir == NULL && global_template_shell == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "No template values to update.\n");
        ret = EOK;
        goto done;
    }

    /* If normal non-template ID override exists for this user, then update
     * the existing ID override object (adding template values ) */
    if (has_override) {
        ret = sysdb_attrs_get_string(override_attrs, SYSDB_OVERRIDE_ANCHOR_UUID,
                                     &anchor);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Missing anchor in override attributes.\n");
            ret = EINVAL;
            goto done;
        }
    /* Use domain SID for override DN, or global template SID */
    } else if (domain->template_homedir != NULL || domain->template_shell != NULL) {
        anchor = talloc_asprintf(tmp_ctx, "%s-545", domain->domain_id);
        if (anchor == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
            ret = ENOMEM;
            goto done;
        }
    } else {
        anchor = SYSDB_GLOBAL_TEMPLATE_SID;
    }

    override_dn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                                 SYSDB_TMPL_OVERRIDE, anchor,
                                 domain->view_name);

    if (!has_override) {
        attrs = sysdb_new_attrs(tmp_ctx);
        if (attrs == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_new_attrs failed.\n");
            ret = ENOMEM;
            goto done;
        }
    } else {
        attrs = override_attrs;
    }

    override_dn_str = ldb_dn_get_linearized(override_dn);
    if (override_dn_str == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "override_dn_str == NULL.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_add_template_values(attrs, domain,
                                    global_template_homedir, global_template_shell,
                                    override_dn_str, has_override);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Error adding template values: [%s]\n",
                                    strerror(ret));
        goto done;
    }

    ret = sysdb_update_override_object(tmp_ctx, domain, attrs,
                                       SYSDB_MEMBER_USER, override_dn,
                                       obj_dn, true, true);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sysdb_update_override_object failed.\n");
    }


    ret = EOK;

done:
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_FUNC, "Error: %d (%s)\n", ret, strerror(ret));
    }

    talloc_zfree(tmp_ctx);
    return ret;
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
    bool has_override = true;

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
        /* if there is no override for the given object, and no override
         * template, just store the DN of the object iself in the
         * SYSDB_OVERRIDE_DN attribute to indicate that it was checked
         * if an override exists and none was found. */
        has_override = false;
        override_dn = obj_dn;
    }

    ret = sysdb_update_override_object(tmp_ctx, domain, attrs, type,
                                       override_dn, obj_dn, has_override,
                                       false);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sysdb_update_override_object failed.\n");
    }

    ret = EOK;

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

static errno_t safe_original_attributes(struct sss_domain_info *domain,
                                        struct sysdb_attrs *attrs,
                                        struct ldb_dn *obj_dn,
                                        const char **allowed_attrs)
{
    int ret;
    size_t c;
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *orig_obj;
    char *orig_attr_name;
    struct ldb_message_element *el = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    ret = ldb_search(domain->sysdb->ldb, tmp_ctx, &orig_obj, obj_dn,
                     LDB_SCOPE_BASE, NULL, NULL);
    if (ret != EOK || orig_obj->count != 1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Original object not found.\n");
        goto done;
    }

    /* Safe original values in attributes prefixed by OriginalAD. */
    for (c = 0; allowed_attrs[c] != NULL; c++) {
        el = ldb_msg_find_element(orig_obj->msgs[0], allowed_attrs[c]);
        if (el != NULL) {
            orig_attr_name = talloc_asprintf(tmp_ctx, "%s%s",
                                             ORIGINALAD_PREFIX,
                                             allowed_attrs[c]);
            if (orig_attr_name == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
                ret = ENOMEM;
                goto done;
            }

            ret = sysdb_attrs_add_val(attrs, orig_attr_name,
                                      &el->values[0]);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "sysdb_attrs_add_val failed.\n");
                goto done;
            }
        } else {
            DEBUG(SSSDBG_TRACE_ALL,
                  "Original object does not have [%s] set.\n",
                  allowed_attrs[c]);
        }
    }

    /* Add existing aliases to new ones */
    el = ldb_msg_find_element(orig_obj->msgs[0], SYSDB_NAME_ALIAS);
    if (el != NULL) {
        for (c = 0; c < el->num_values; c++) {
            /* To avoid issue with ldb_modify if e.g. the original and the
             * override name are the same, we use the *_safe version here. */
            ret = sysdb_attrs_add_val_safe(attrs, SYSDB_NAME_ALIAS,
                                           &el->values[c]);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_add_val failed.\n");
                goto done;
            }
        }
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_apply_default_override(struct sss_domain_info *domain,
                                     struct sysdb_attrs *override_attrs,
                                     const char *global_template_homedir,
                                     const char *global_template_shell,
                                     struct ldb_dn *obj_dn)
{
    int ret;
    TALLOC_CTX *tmp_ctx;
    struct sysdb_attrs *attrs;
    struct sysdb_attrs *mapped_attrs = NULL;
    size_t c;
    size_t d;
    size_t num_values;
    struct ldb_message_element *el = NULL;
    const char *allowed_attrs[] = { SYSDB_UIDNUM,
                                    SYSDB_GIDNUM,
                                    SYSDB_GECOS,
                                    SYSDB_HOMEDIR,
                                    SYSDB_SHELL,
                                    SYSDB_NAME,
                                    SYSDB_SSH_PUBKEY,
                                    SYSDB_USER_CERT,
                                    NULL };
    bool override_attrs_found = false;
    bool is_cert = false;
    struct ldb_message_element el_del = { 0, SYSDB_SSH_PUBKEY, 0, NULL };
    struct sysdb_attrs del_attrs = { 1, &el_del };
    bool has_override = false;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    if (override_attrs != NULL) {
        has_override = true;
    }

    /* No overrides exist for the user, check templates */
    if (domain->template_homedir != NULL || domain->template_shell != NULL
        || global_template_homedir != NULL || global_template_shell != NULL) {

        if (!has_override) {
            override_attrs = sysdb_new_attrs(tmp_ctx);
            if (override_attrs == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_new_attrs failed.\n");
                return ENOMEM;
                goto done;
            }
        }

        ret = sysdb_add_template_values(override_attrs, domain, global_template_homedir,
                                        global_template_shell, ldb_dn_get_linearized(obj_dn),
                                        has_override);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Error adding template values: [%s]\n",
                                        strerror(ret));
            goto done;
        }
    /* No templates, nothing to do */
    } else {
        ret = EOK;
        goto done;
    }

    attrs = sysdb_new_attrs(tmp_ctx);
    if (attrs == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_new_attrs failed.\n");
        ret = ENOMEM;
        goto done;
    }

    for (c = 0; allowed_attrs[c] != NULL; c++) {
        ret = sysdb_attrs_get_el_ext(override_attrs, allowed_attrs[c], false,
                                     &el);
        if (ret == EOK) {
            override_attrs_found = true;

            if (strcmp(allowed_attrs[c], SYSDB_NAME) == 0) {
                if (el->values[0].data[el->values[0].length] != '\0') {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "String attribute does not end with \\0.\n");
                    ret = EINVAL;
                    goto done;
                }

                ret = add_name_and_aliases_for_name_override(domain, attrs,
                                                   true,
                                                   (char *) el->values[0].data);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "add_name_and_aliases_for_name_override failed.\n");
                    goto done;
                }
            } else {
                num_values = el->num_values;
                /* Only SYSDB_SSH_PUBKEY and SYSDB_USER_CERT are allowed to
                 * have multiple values. */
                if (strcmp(allowed_attrs[c], SYSDB_SSH_PUBKEY) != 0
                        && strcmp(allowed_attrs[c], SYSDB_USER_CERT) != 0
                        && num_values != 1) {
                    DEBUG(SSSDBG_MINOR_FAILURE,
                          "Override attribute for [%s] has more [%zd] " \
                          "than one value, using only the first.\n",
                          allowed_attrs[c], num_values);
                    num_values = 1;
                }

                is_cert = false;
                if (strcmp(allowed_attrs[c], SYSDB_USER_CERT) == 0) {
                    /* Certificates in overrides are explicitly used to map
                     * users to certificates, so we add them to
                     * SYSDB_USER_MAPPED_CERT as well. */
                    is_cert = true;

                    if (mapped_attrs == NULL) {
                        mapped_attrs = sysdb_new_attrs(tmp_ctx);
                        if (mapped_attrs == NULL) {
                            DEBUG(SSSDBG_OP_FAILURE,
                                  "sysdb_new_attrs failed.\n");
                            ret = ENOMEM;
                            goto done;
                        }
                    }
                }

                for (d = 0; d < num_values; d++) {
                    ret = sysdb_attrs_add_val(attrs,  allowed_attrs[c],
                                              &el->values[d]);
                    if (ret != EOK) {
                        DEBUG(SSSDBG_OP_FAILURE,
                              "sysdb_attrs_add_val failed.\n");
                        goto done;
                    }

                    if (is_cert) {
                        ret = sysdb_attrs_add_val(mapped_attrs,
                                                  SYSDB_USER_MAPPED_CERT,
                                                  &el->values[d]);
                        if (ret != EOK) {
                            DEBUG(SSSDBG_OP_FAILURE,
                                  "sysdb_attrs_add_val failed.\n");
                            goto done;
                        }
                    }

                    DEBUG(SSSDBG_TRACE_ALL,
                          "Override [%s] with [%.*s] for [%s].\n",
                          allowed_attrs[c], (int) el->values[d].length,
                          el->values[d].data, ldb_dn_get_linearized(obj_dn));
                }
            }
        } else if (ret == ENOENT) {
            if (strcmp(allowed_attrs[c], SYSDB_SSH_PUBKEY) == 0) {
                ret = sysdb_set_entry_attr(domain->sysdb, obj_dn, &del_attrs,
                                           SYSDB_MOD_DEL);
                if (ret != EOK && ret != ENOENT) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "sysdb_set_entry_attr failed.\n");
                    goto done;
                }
            }
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_el_ext failed.\n");
            goto done;
        }
    }

    if (override_attrs_found) {
        ret = safe_original_attributes(domain, attrs, obj_dn, allowed_attrs);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "safe_original_attributes failed.\n");
            goto done;
        }

        ret = sysdb_set_entry_attr(domain->sysdb, obj_dn, attrs, SYSDB_MOD_REP);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_set_entry_attr failed.\n");
            goto done;
        }

        if (mapped_attrs != NULL) {
            ret = sysdb_set_entry_attr(domain->sysdb, obj_dn, mapped_attrs,
                                       SYSDB_MOD_ADD);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "sysdb_set_entry_attr failed, ignored.\n");
            }
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}


#define SYSDB_USER_NAME_OVERRIDE_FILTER "(&(objectClass="SYSDB_OVERRIDE_USER_CLASS")(|("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME"=%s)))"
#define SYSDB_USER_UID_OVERRIDE_FILTER "(&(objectClass="SYSDB_OVERRIDE_USER_CLASS")("SYSDB_UIDNUM"=%lu))"
#define SYSDB_USER_CERT_OVERRIDE_FILTER "(&(objectClass="SYSDB_OVERRIDE_USER_CLASS")%s)"
#define SYSDB_GROUP_NAME_OVERRIDE_FILTER "(&(objectClass="SYSDB_OVERRIDE_GROUP_CLASS")(|("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME"=%s)))"
#define SYSDB_GROUP_GID_OVERRIDE_FILTER "(&(objectClass="SYSDB_OVERRIDE_GROUP_CLASS")("SYSDB_GIDNUM"=%lu))"

enum override_object_type {
    OO_TYPE_UNDEF = 0,
    OO_TYPE_USER,
    OO_TYPE_GROUP
};

errno_t sysdb_search_override_by_cert(TALLOC_CTX *mem_ctx,
                                      struct sss_domain_info *domain,
                                      const char *cert,
                                      const char **attrs,
                                      struct ldb_result **override_obj,
                                      struct ldb_result **orig_obj)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *base_dn;
    struct ldb_result *override_res;
    struct ldb_result *orig_res;
    char *cert_filter;
    int ret;
    const char *orig_obj_dn;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    base_dn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                             SYSDB_TMPL_VIEW_SEARCH_BASE, domain->view_name);
    if (base_dn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new_fmt failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_cert_derb64_to_ldap_filter(tmp_ctx, cert, SYSDB_USER_CERT,
                                           &cert_filter);

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_cert_derb64_to_ldap_filter failed.\n");
        goto done;
    }

    ret = ldb_search(domain->sysdb->ldb, tmp_ctx, &override_res, base_dn,
                     LDB_SCOPE_SUBTREE, attrs, SYSDB_USER_CERT_OVERRIDE_FILTER,
                     cert_filter);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    if (override_res->count == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "No user override found for cert [%s].\n",
                                 cert);
        ret = ENOENT;
        goto done;
    } else if (override_res->count > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Found more than one override for cert [%s].\n", cert);
        ret = EINVAL;
        goto done;
    }

    if (orig_obj != NULL) {
        orig_obj_dn = ldb_msg_find_attr_as_string(override_res->msgs[0],
                                                  SYSDB_OVERRIDE_OBJECT_DN,
                                                  NULL);
        if (orig_obj_dn == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Missing link to original object in override [%s].\n",
                  ldb_dn_get_linearized(override_res->msgs[0]->dn));
            ret = EINVAL;
            goto done;
        }

        base_dn = ldb_dn_new(tmp_ctx, domain->sysdb->ldb, orig_obj_dn);
        if (base_dn == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = ldb_search(domain->sysdb->ldb, tmp_ctx, &orig_res, base_dn,
                         LDB_SCOPE_BASE, attrs, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        *orig_obj = talloc_steal(mem_ctx, orig_res);
    }

    *override_obj = talloc_steal(mem_ctx, override_res);

    ret = EOK;

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

static errno_t sysdb_search_override_by_name(TALLOC_CTX *mem_ctx,
                                             struct sss_domain_info *domain,
                                             const char *name,
                                             const char *filter,
                                             const char **attrs,
                                             struct ldb_result **override_obj,
                                             struct ldb_result **orig_obj)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *base_dn;
    struct ldb_result *override_res;
    struct ldb_result *orig_res;
    char *sanitized_name;
    char *lc_sanitized_name;
    int ret;
    const char *orig_obj_dn;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    base_dn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                             SYSDB_TMPL_VIEW_SEARCH_BASE, domain->view_name);
    if (base_dn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new_fmt failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sss_filter_sanitize_for_dom(tmp_ctx, name, domain,
                                      &sanitized_name, &lc_sanitized_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_filter_sanitize_for_dom failed.\n");
        goto done;
    }

    ret = ldb_search(domain->sysdb->ldb, tmp_ctx, &override_res, base_dn,
                     LDB_SCOPE_SUBTREE, attrs, filter,
                     lc_sanitized_name,
                     sanitized_name, sanitized_name);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    if (override_res->count == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "No user override found for name [%s].\n",
                                 name);
        ret = ENOENT;
        goto done;
    } else if (override_res->count > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Found more than one override for name [%s].\n", name);
        ret = EINVAL;
        goto done;
    }

    if (orig_obj != NULL) {
        orig_obj_dn = ldb_msg_find_attr_as_string(override_res->msgs[0],
                                                  SYSDB_OVERRIDE_OBJECT_DN,
                                                  NULL);
        if (orig_obj_dn == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Missing link to original object in override [%s].\n",
                  ldb_dn_get_linearized(override_res->msgs[0]->dn));
            ret = EINVAL;
            goto done;
        }

        base_dn = ldb_dn_new(tmp_ctx, domain->sysdb->ldb, orig_obj_dn);
        if (base_dn == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = ldb_search(domain->sysdb->ldb, tmp_ctx, &orig_res, base_dn,
                         LDB_SCOPE_BASE, attrs, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        *orig_obj = talloc_steal(mem_ctx, orig_res);
    }


    *override_obj = talloc_steal(mem_ctx, override_res);

    ret = EOK;

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

errno_t sysdb_search_user_override_attrs_by_name(TALLOC_CTX *mem_ctx,
                                             struct sss_domain_info *domain,
                                             const char *name,
                                             const char **attrs,
                                             struct ldb_result **override_obj,
                                             struct ldb_result **orig_obj)
{

    return sysdb_search_override_by_name(mem_ctx, domain, name,
                                         SYSDB_USER_NAME_OVERRIDE_FILTER,
                                         attrs, override_obj, orig_obj);
}

errno_t sysdb_search_group_override_attrs_by_name(TALLOC_CTX *mem_ctx,
                                            struct sss_domain_info *domain,
                                            const char *name,
                                            const char **attrs,
                                            struct ldb_result **override_obj,
                                            struct ldb_result **orig_obj)
{
    return sysdb_search_override_by_name(mem_ctx, domain, name,
                                         SYSDB_GROUP_NAME_OVERRIDE_FILTER,
                                         attrs, override_obj, orig_obj);
}

errno_t sysdb_search_user_override_by_name(TALLOC_CTX *mem_ctx,
                                           struct sss_domain_info *domain,
                                           const char *name,
                                           struct ldb_result **override_obj,
                                           struct ldb_result **orig_obj)
{
    const char *attrs[] = SYSDB_PW_ATTRS;

    return sysdb_search_override_by_name(mem_ctx, domain, name,
                                         SYSDB_USER_NAME_OVERRIDE_FILTER,
                                         attrs, override_obj, orig_obj);
}

errno_t sysdb_search_group_override_by_name(TALLOC_CTX *mem_ctx,
                                            struct sss_domain_info *domain,
                                            const char *name,
                                            struct ldb_result **override_obj,
                                            struct ldb_result **orig_obj)
{
    const char **attrs = SYSDB_GRSRC_ATTRS(domain);

    return sysdb_search_override_by_name(mem_ctx, domain, name,
                                         SYSDB_GROUP_NAME_OVERRIDE_FILTER,
                                         attrs, override_obj, orig_obj);
}

static errno_t sysdb_search_override_by_id(TALLOC_CTX *mem_ctx,
                                           struct sss_domain_info *domain,
                                           unsigned long int id,
                                           enum override_object_type type,
                                           struct ldb_result **override_obj,
                                           struct ldb_result **orig_obj)
{
    TALLOC_CTX *tmp_ctx;
    static const char *user_attrs[] = SYSDB_PW_ATTRS;
    const char **group_attrs = SYSDB_GRSRC_ATTRS(domain);
    const char **attrs;
    struct ldb_dn *base_dn;
    struct ldb_result *override_res;
    struct ldb_result *orig_res;
    int ret;
    const char *orig_obj_dn;
    const char *filter;
    const struct ldb_val *orig_domain;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    base_dn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                             SYSDB_TMPL_VIEW_SEARCH_BASE, domain->view_name);
    if (base_dn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new_fmt failed.\n");
        ret = ENOMEM;
        goto done;
    }

    switch(type) {
    case OO_TYPE_USER:
        filter = SYSDB_USER_UID_OVERRIDE_FILTER;
        attrs = user_attrs;
        break;
    case OO_TYPE_GROUP:
        filter = SYSDB_GROUP_GID_OVERRIDE_FILTER;
        attrs = group_attrs;
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected override object type [%d].\n",
                                   type);
        ret = EINVAL;
        goto done;
    }

    ret = ldb_search(domain->sysdb->ldb, tmp_ctx, &override_res, base_dn,
                     LDB_SCOPE_SUBTREE, attrs, filter, id);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    if (override_res->count == 0) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "No user override found for %s with id [%lu].\n",
              (type == OO_TYPE_USER ? "user" : "group"), id);
        ret = ENOENT;
        goto done;
    } else if (override_res->count > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Found more than one override for id [%lu].\n", id);
        ret = EINVAL;
        goto done;
    }

    if (orig_obj != NULL) {
        orig_obj_dn = ldb_msg_find_attr_as_string(override_res->msgs[0],
                                                  SYSDB_OVERRIDE_OBJECT_DN,
                                                  NULL);
        if (orig_obj_dn == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Missing link to original object in override [%s].\n",
                  ldb_dn_get_linearized(override_res->msgs[0]->dn));
            ret = EINVAL;
            goto done;
        }

        base_dn = ldb_dn_new(tmp_ctx, domain->sysdb->ldb, orig_obj_dn);
        if (base_dn == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new failed.\n");
            ret = ENOMEM;
            goto done;
        }

        /* Check if the found override object belongs to an object in this
         * domain. The base dn is in the form:
         * name=user@domain,cn=users,cn=domain,cn=sysdb
         * = 0              = 1      = 2       = 3
         */
        orig_domain = ldb_dn_get_component_val(base_dn, 2);
        if (orig_domain == NULL || !orig_domain->length) {
            DEBUG(SSSDBG_OP_FAILURE, "Invalid original object DN\n");
            ret = EINVAL;
            goto done;
        }

        if (strcmp((const char*)orig_domain->data, domain->name) != 0) {
            ret = ENOENT;
            goto done;
        }

        ret = ldb_search(domain->sysdb->ldb, tmp_ctx, &orig_res, base_dn,
                         LDB_SCOPE_BASE, attrs, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        *orig_obj = talloc_steal(mem_ctx, orig_res);
    }


    *override_obj = talloc_steal(mem_ctx, override_res);

    ret = EOK;

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

errno_t sysdb_search_user_override_by_uid(TALLOC_CTX *mem_ctx,
                                          struct sss_domain_info *domain,
                                          uid_t uid,
                                           struct ldb_result **override_obj,
                                           struct ldb_result **orig_obj)
{
    return sysdb_search_override_by_id(mem_ctx, domain, uid, OO_TYPE_USER,
                                       override_obj, orig_obj);
}

errno_t sysdb_search_group_override_by_gid(TALLOC_CTX *mem_ctx,
                                            struct sss_domain_info *domain,
                                            gid_t gid,
                                            struct ldb_result **override_obj,
                                            struct ldb_result **orig_obj)
{
    return sysdb_search_override_by_id(mem_ctx, domain, gid, OO_TYPE_GROUP,
                                       override_obj, orig_obj);
}

/**
 * @brief Add override data to the original object
 *
 * @param[in] domain Domain struct, needed to access the cache
 * @oaram[in] obj The original object
 * @param[in] override_obj The object with the override data, may be NULL
 * @param[in] req_attrs List of attributes to be requested, if not set a
 *                      default list depending on the object type will be used
 *
 * @return EOK - Override data was added successfully
 * @return ENOMEM - There was insufficient memory to complete the operation
 * @return ENOENT - The original object did not have the SYSDB_OVERRIDE_DN
 *                  attribute or the value of the attribute points an object
 *                  which does not exists. Both conditions indicate that the
 *                  cache must be refreshed.
 */
errno_t sysdb_add_overrides_to_object(struct sss_domain_info *domain,
                                      struct ldb_message *obj,
                                      struct ldb_message *override_obj,
                                      const char **req_attrs)
{
    int ret;
    const char *override_dn_str;
    struct ldb_dn *override_dn;
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    struct ldb_message *override;
    uint64_t uid;
    static const char *user_attrs[] = SYSDB_PW_ATTRS;
    const char **group_attrs = SYSDB_GRSRC_ATTRS(domain); /* members don't matter */
    const char **attrs;
    struct attr_map {
        const char *attr;
        const char *new_attr;
    } attr_map[] = {
        {SYSDB_UIDNUM, OVERRIDE_PREFIX SYSDB_UIDNUM},
        {SYSDB_GIDNUM, OVERRIDE_PREFIX SYSDB_GIDNUM},
        {SYSDB_GECOS, OVERRIDE_PREFIX SYSDB_GECOS},
        {SYSDB_HOMEDIR, OVERRIDE_PREFIX SYSDB_HOMEDIR},
        {SYSDB_SHELL, OVERRIDE_PREFIX SYSDB_SHELL},
        {SYSDB_NAME, OVERRIDE_PREFIX SYSDB_NAME},
        {SYSDB_SSH_PUBKEY, OVERRIDE_PREFIX SYSDB_SSH_PUBKEY},
        {SYSDB_USER_CERT, OVERRIDE_PREFIX SYSDB_USER_CERT},
        {NULL, NULL}
    };
    size_t c;
    size_t d;
    struct ldb_message_element *tmp_el;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    if (override_obj == NULL) {
        override_dn_str = ldb_msg_find_attr_as_string(obj,
                                                      SYSDB_OVERRIDE_DN, NULL);
        if (override_dn_str == NULL) {
            if (is_local_view(domain->view_name)) {
                /* LOCAL view doesn't have to have overrideDN specified. */
                ret = EOK;
                goto done;
            }

            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Missing override DN for object [%s].\n",
                  ldb_dn_get_linearized(obj->dn));

            ret = ENOENT;
            goto done;
        }

        override_dn = ldb_dn_new(tmp_ctx, domain->sysdb->ldb, override_dn_str);
        if (override_dn == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new failed.\n");
            ret = ENOMEM;
            goto done;
        }

        if (ldb_dn_compare(obj->dn, override_dn) == 0) {
            DEBUG(SSSDBG_TRACE_ALL, "Object [%s] has no overrides.\n",
                                    ldb_dn_get_linearized(obj->dn));
            ret = EOK;
            goto done;
        }

        attrs = req_attrs;
        if (attrs == NULL) {
            uid = ldb_msg_find_attr_as_uint64(obj, SYSDB_UIDNUM, 0);
            if (uid == 0) {
                /* No UID hence group object */
                attrs = group_attrs;
            } else {
                attrs = user_attrs;
            }
        }

        ret = ldb_search(domain->sysdb->ldb, tmp_ctx, &res, override_dn,
                         LDB_SCOPE_BASE, attrs, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        if (res->count == 1) {
            override = res->msgs[0];
        } else if (res->count == 0) {
            DEBUG(SSSDBG_TRACE_FUNC, "Override object [%s] does not exists.\n",
                                     override_dn_str);
            ret = ENOENT;
            goto done;
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Base search for override object returned [%d] results.\n",
                  res->count);
            ret = EINVAL;
            goto done;
        }
    } else {
        override = override_obj;
    }

    for (c = 0; attr_map[c].attr != NULL; c++) {
        tmp_el = ldb_msg_find_element(override, attr_map[c].attr);
        if (tmp_el != NULL) {
            for (d = 0; d < tmp_el->num_values; d++) {
                ret = ldb_msg_add_steal_value(obj, attr_map[c].new_attr,
                                              &tmp_el->values[d]);
                if (ret != LDB_SUCCESS) {
                    DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_add_value failed.\n");
                    ret = sysdb_error_to_errno(ret);
                    goto done;
                }
            }
        }
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t get_user_members_recursively(TALLOC_CTX *mem_ctx,
                                            struct sss_domain_info *dom,
                                            struct ldb_dn *group_dn,
                                            struct ldb_result **members)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    size_t count;
    struct ldb_result *res;
    struct ldb_dn *base_dn;
    char *filter;
    char *sanitized_name;
    const char *attrs[] =
        {
            SYSDB_OVERRIDE_DN,
            SYSDB_NAME,
            SYSDB_DEFAULT_OVERRIDE_NAME,
            NULL
        };
    struct ldb_message **msgs;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    base_dn = sysdb_base_dn(dom->sysdb, tmp_ctx);
    if (base_dn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_base_dn failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sss_filter_sanitize(tmp_ctx, ldb_dn_get_linearized(group_dn),
                              &sanitized_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to sanitize the given name:'%s'.\n",
              ldb_dn_get_linearized(group_dn));
        goto done;
    }

    filter = talloc_asprintf(tmp_ctx,
                             "(&("SYSDB_UC")("SYSDB_MEMBEROF"=%s)("SYSDB_UIDNUM"=*))",
                             sanitized_name);
    if (filter == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_cache_search_entry(tmp_ctx, dom->sysdb->ldb, base_dn, LDB_SCOPE_SUBTREE,
                                   filter, attrs, &count, &msgs);
    if (ret != EOK) {
        goto done;
    }

    res = talloc_zero(tmp_ctx, struct ldb_result);
    if (res == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
        ret = ENOMEM;
        goto done;
    }

    res->count = count;
    res->msgs = talloc_steal(res, msgs);

    ret = EOK;

done:
    if (ret == EOK) {
        *members = talloc_steal(mem_ctx, res);
    } else if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, "No such entry\n");
    } else {
        DEBUG(SSSDBG_OP_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
    }
    talloc_free(tmp_ctx);
    return ret;
}

static inline int add_domain_name(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *domain,
                                  const char *orig_name,
                                  const char **_memberuid)
{
    int ret;
    char *orig_domain = NULL;
    struct sss_domain_info *orig_dom;

    ret = sss_parse_internal_fqname(mem_ctx, orig_name,
                                    NULL, &orig_domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
             "sss_parse_internal_fqname failed on [%s].\n", orig_name);
        return ret;
    }

    if (orig_domain != NULL) {
        orig_dom = find_domain_by_name(get_domains_head(domain),
                                       orig_domain, true);
        if (orig_dom == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot find domain with name [%s].\n",
                  orig_domain);
            return ERR_DOMAIN_NOT_FOUND;
        }
        *_memberuid = sss_create_internal_fqname(mem_ctx, *_memberuid,
                                                 orig_dom->name);
        if (*_memberuid == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sss_create_internal_fqname failed.\n");
            return ENOMEM;
        }
    }

    return EOK;
}

errno_t sysdb_add_group_member_overrides(struct sss_domain_info *domain,
                                         struct ldb_message *obj)
{
    bool expect_override_dn;
    int ret;
    size_t c;
    struct ldb_result *res_members;
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *override_obj;
    static const char *member_attrs[] = { SYSDB_NAME, NULL };
    struct ldb_dn *override_dn = NULL;
    const char *memberuid;
    const char *val;

    if (domain->ignore_group_members) {
        return EOK;
    }

    expect_override_dn = DOM_HAS_VIEWS(domain);

    if (!expect_override_dn
        && ((domain->provider == NULL) || (strcasecmp(domain->provider, "ipa") != 0))) {
        /* (no view defined) and (not IPA hence no SYSDB_DEFAULT_OVERRIDE_NAME) */
        return EOK;
    }

    if (ldb_msg_find_element(obj, SYSDB_MEMBERUID) == NULL) {
        /* empty memberUid list means there are no user objects in
         * the cache that would have 'memberOf = obj->dn',
         * so get_user_members_recursively() will return an empty list
         * anyway (but may consume a lot of CPU in case of a large cache)
         */
        return EOK;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    ret = get_user_members_recursively(tmp_ctx, domain, obj->dn,
                                             &res_members);
    if (ret == ENOENT) {
        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sysdb_get_user_members_recursively failed.\n");
        goto done;
    }

    for (c = 0; c < res_members->count; c++) {
        if (expect_override_dn) {
            /* Creates new DN object. */
            override_dn = ldb_msg_find_attr_as_dn(domain->sysdb->ldb, tmp_ctx,
                                                  res_members->msgs[c],
                                                  SYSDB_OVERRIDE_DN);

            if (override_dn == NULL) {
                if (is_local_view(domain->view_name)) {
                    /* LOCAL view doesn't have to have overrideDN specified. */
                    continue;
                }

                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Missing override DN for object [%s].\n",
                      ldb_dn_get_linearized(res_members->msgs[c]->dn));
                ret = ENOENT;
                goto done;
            }
        }

        /* start with default view name, if it exists or use NULL */
        memberuid = ldb_msg_find_attr_as_string(res_members->msgs[c],
                                                SYSDB_DEFAULT_OVERRIDE_NAME,
                                                NULL);

        /* If there is an override object, check if the name is overridden */
        if (expect_override_dn &&
            (ldb_dn_compare(res_members->msgs[c]->dn, override_dn) != 0)) {

            ret = ldb_search(domain->sysdb->ldb, res_members, &override_obj,
                             override_dn, LDB_SCOPE_BASE, member_attrs, NULL);
            if (ret != LDB_SUCCESS) {
                ret = sysdb_error_to_errno(ret);
                goto done;
            }

            if (override_obj->count != 1) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Base search for override object of [%s] returned [%d] results.\n",
                      ldb_dn_get_linearized(res_members->msgs[c]->dn), override_obj->count);
                ret = EINVAL;
                goto done;
            }

            memberuid = ldb_msg_find_attr_as_string(override_obj->msgs[0],
                                                    SYSDB_NAME,
                                                    memberuid);
        }

        if ((memberuid == NULL) || (strchr(memberuid, '@') == NULL)) {
            const char *orig_name = NULL;

            orig_name = ldb_msg_find_attr_as_string(res_members->msgs[c],
                                                    SYSDB_NAME,
                                                    NULL);
            if (orig_name == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Object [%s] has no name.\n",
                      ldb_dn_get_linearized(res_members->msgs[c]->dn));
                ret = EINVAL;
                goto done;
            }

            if (memberuid == NULL) {
                DEBUG_CONDITIONAL(SSSDBG_TRACE_ALL, "No override name available for %s.\n",
                                  orig_name);
                memberuid = orig_name;
            } else {
                /* add domain name if memberuid is a short name */
                ret = add_domain_name(tmp_ctx, domain, orig_name, &memberuid);
                if (ret != EOK) {
                    goto done;
                }
            }
        }

        val = talloc_steal(obj, memberuid);
        if (val == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_steal() failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = ldb_msg_add_string(obj, OVERRIDE_PREFIX SYSDB_MEMBERUID, val);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_add_string failed.\n");
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
        DEBUG_CONDITIONAL(SSSDBG_TRACE_ALL,
                          "Added [%s] to ["OVERRIDE_PREFIX SYSDB_MEMBERUID"].\n",
                          memberuid);
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

struct ldb_message_element *
sss_view_ldb_msg_find_element(struct sss_domain_info *dom,
                                              const struct ldb_message *msg,
                                              const char *attr_name)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct ldb_message_element *val;
    char *override_attr_name;

    if (DOM_HAS_VIEWS(dom)) {
        tmp_ctx = talloc_new(NULL);
        if (tmp_ctx == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
            val = NULL;
            goto done;
        }

        override_attr_name = talloc_asprintf(tmp_ctx, "%s%s", OVERRIDE_PREFIX,
                                                              attr_name);
        if (override_attr_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
            val = NULL;
            goto done;
        }

        val = ldb_msg_find_element(msg, override_attr_name);
        if (val != NULL) {
            goto done;
        }
    }

    val = ldb_msg_find_element(msg, attr_name);

done:
    talloc_free(tmp_ctx);
    return val;
}

uint64_t sss_view_ldb_msg_find_attr_as_uint64(struct sss_domain_info *dom,
                                              const struct ldb_message *msg,
                                              const char *attr_name,
                                              uint64_t default_value)
{
    TALLOC_CTX *tmp_ctx = NULL;
    uint64_t val;
    char *override_attr_name;

    if (DOM_HAS_VIEWS(dom)) {
        tmp_ctx = talloc_new(NULL);
        if (tmp_ctx == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
            val = default_value;
            goto done;
        }

        override_attr_name = talloc_asprintf(tmp_ctx, "%s%s", OVERRIDE_PREFIX,
                                                              attr_name);
        if (override_attr_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
            val = default_value;
            goto done;
        }

        if (ldb_msg_find_element(msg, override_attr_name) != NULL) {
            val = ldb_msg_find_attr_as_uint64(msg, override_attr_name,
                                              default_value);
            goto done;
        }
    }

    val = ldb_msg_find_attr_as_uint64(msg, attr_name, default_value);

done:
    talloc_free(tmp_ctx);
    return val;
}

const char *sss_view_ldb_msg_find_attr_as_string_ex(struct sss_domain_info *dom,
                                                  const struct ldb_message *msg,
                                                  const char *attr_name,
                                                  const char *default_value,
                                                  bool *is_override)
{
    TALLOC_CTX *tmp_ctx = NULL;
    const char *val;
    char *override_attr_name;

    if (is_override != NULL) {
        *is_override = false;
    }

    if (DOM_HAS_VIEWS(dom)) {
        tmp_ctx = talloc_new(NULL);
        if (tmp_ctx == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
            val = default_value;
            goto done;
        }

        override_attr_name = talloc_asprintf(tmp_ctx, "%s%s", OVERRIDE_PREFIX,
                                                              attr_name);
        if (override_attr_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
            val = default_value;
            goto done;
        }

        if (ldb_msg_find_element(msg, override_attr_name) != NULL) {
            val = ldb_msg_find_attr_as_string(msg, override_attr_name,
                                              default_value);
            if (is_override != NULL && val != default_value) {
                *is_override = true;
            }
            goto done;
        }
    }

    val = ldb_msg_find_attr_as_string(msg, attr_name, default_value);

done:
    talloc_free(tmp_ctx);
    return val;
}

const char *sss_view_ldb_msg_find_attr_as_string(struct sss_domain_info *dom,
                                                 const struct ldb_message *msg,
                                                 const char *attr_name,
                                                 const char *default_value)
{
    return sss_view_ldb_msg_find_attr_as_string_ex(dom, msg, attr_name,
                                                   default_value, NULL);
}

static errno_t sysdb_create_override_template(struct sysdb_ctx *sysdb,
                                              const char *template_dn,
                                              const char *anchor,
                                              const char *homedir,
                                              const char *shell)
{
    struct ldb_message *msg = NULL;
    errno_t ret;

    msg = ldb_msg_new(sysdb);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(msg, sysdb->ldb, template_dn);
    if (msg->dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, SYSDB_OBJECTCLASS,
                             SYSDB_OVERRIDE_ANCHOR);

    ret = ldb_msg_add_string(msg, SYSDB_OBJECTCLASS,
                             SYSDB_OVERRIDE_USER_CLASS);

    /* global templates always have anchor :SID:S-1-5-11 */
    if (strstr(anchor, SYSDB_GLOBAL_TEMPLATE_SID) != NULL) {
        ret = ldb_msg_add_string(msg, "templateType", "global");
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    /* domain template examples below in format :SID:$domainpart-545
     *     :SID:S-1-5-21-3044487217-4285925784-991641718-545
     *     :SID:S-1-5-21-644878228-3836315275-1841415914-545
     */
    } else if (strstr(anchor, "-545") != NULL) {
        ret = ldb_msg_add_string(msg, "templateType", "domain");
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    if (homedir != NULL) {
        ret = ldb_msg_add_string(msg, SYSDB_HOMEDIR, homedir);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    if (shell != NULL) {
        ret = ldb_msg_add_string(msg, SYSDB_SHELL, shell);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    ret = ldb_msg_add_string(msg, SYSDB_OVERRIDE_ANCHOR_UUID, anchor);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* do a synchronous add */
    ret = ldb_add(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to add domain template container (%d, [%s])!\n",
               ret, ldb_errstring(sysdb->ldb));
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    talloc_free(msg);

    return ret;
}

errno_t
sysdb_update_domain_template(struct sysdb_ctx *sysdb,
                             struct ldb_dn *dn,
                             const char *home_dir,
                             const char *login_shell)
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

    if (login_shell != NULL) {
        ret = ldb_msg_add_empty(msg, SYSDB_DOMAIN_TEMPLATE_SHELL,
                                LDB_FLAG_MOD_REPLACE, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_DOMAIN_TEMPLATE_SHELL,
                                 login_shell);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    if (home_dir != NULL) {
        ret = ldb_msg_add_empty(msg, SYSDB_DOMAIN_TEMPLATE_HOMEDIR,
                                LDB_FLAG_MOD_REPLACE, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_DOMAIN_TEMPLATE_HOMEDIR,
                                 home_dir);
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

errno_t sysdb_update_override_template(struct sysdb_ctx *sysdb,
                                       const char *view_name,
                                       const char *anchor,
                                       const char *homedir,
                                       const char *shell)
{
    struct ldb_dn *container_dn = NULL;
    TALLOC_CTX *tmp_ctx = NULL;
    bool in_transaction = false;
    int ret;
    const char *anchor_chopped;
    const char *template_dn;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    template_dn = talloc_asprintf(tmp_ctx, SYSDB_TMPL_OVERRIDE,
                                  anchor,
                                  view_name);
    if (template_dn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Preparing to add [%s] to sysdb\n",
                             template_dn);

    /* anchor begins with a : character, ldb treats strings beginning
     * with : as base64 so we need to remove it */
    anchor_chopped = anchor + 1;

    container_dn = ldb_dn_new(sysdb, sysdb->ldb, template_dn);
    if (container_dn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new failed.\n");
        return ENOMEM;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_transaction_start failed.\n");
        goto done;
    }
    in_transaction = true;

    ret = sysdb_delete_recursive(sysdb, container_dn, true);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_delete_recursive failed.\n");
        goto done;
    }
    ret = sysdb_create_override_template(sysdb, template_dn,
                                         anchor_chopped, homedir, shell);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_create_certmap_container failed.\n");
        goto done;
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_transaction_commit failed.\n");
        goto done;
    }
    in_transaction = false;

done:
    if (in_transaction) {
        ret = sysdb_transaction_cancel(sysdb);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not cancel transaction.\n");
        }
    }

    talloc_free(container_dn);
    talloc_free(tmp_ctx);

    return ret;
}
