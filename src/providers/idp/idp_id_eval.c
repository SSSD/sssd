/*
    SSSD

    IdP Identity Backend Module - evalute replies

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2024 Red Hat

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
#include <jansson.h>

#include "util/util.h"
#include "providers/idp/idp_id.h"

static errno_t store_json_user(struct idp_id_ctx *idp_id_ctx, json_t *user,
                               const char *group_name)
{
    errno_t ret;
    json_t *user_name = NULL;
    json_t *uuid = NULL;
    int cache_timeout;
    struct sss_domain_info *dom;
    uid_t uid;
    gid_t gid;
    char *fqdn = NULL;
    enum idmap_error_code err;
    struct sysdb_attrs *attrs = NULL;

    dom = idp_id_ctx->be_ctx->domain;


    user_name = json_object_get(user, "posixUsername");
    if (!json_is_string(user_name)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "JSON user object does not contain 'posixUsername' string.\n");
        ret = EINVAL;
        goto done;
    }

    fqdn = sss_create_internal_fqname(idp_id_ctx, json_string_value(user_name),
                                      dom->name);
    if (fqdn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate fully-qualified name.\n");
        ret = ENOMEM;
        goto done;
    }

    uuid = json_object_get(user, "id");
    if (!json_is_string(uuid)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "JSON user object does not contain 'id' string.\n");
        ret = EINVAL;
        goto done;
    }

    err = sss_idmap_gen_to_unix(idp_id_ctx->idmap_ctx,
                                idp_id_ctx->token_endpoint,
                                json_string_value(uuid), &uid);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate UID for [%s][%s].\n",
                                 fqdn, json_string_value(uuid));
        ret = EIO;
        goto done;
    }
    if (dom->mpg_mode != MPG_DISABLED) {
        gid = 0;
    } else {
        gid = uid;
    }

    attrs = sysdb_new_attrs(idp_id_ctx);
    if (attrs == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to allocate memory for extra attributes.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_UUID, json_string_value(uuid));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add UUID to user attributes.\n");
        goto done;
    }

    cache_timeout = dom->user_timeout;
    ret = sysdb_store_user(dom, fqdn, NULL,
                           uid, gid, NULL, NULL, NULL, NULL, attrs, NULL,
                           cache_timeout, 0);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to store user [%s].\n", fqdn);
        goto done;
    }

    if (group_name != NULL) {
        ret = sysdb_add_group_member(dom, group_name, fqdn, SYSDB_MEMBER_USER,
                                     false);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to store user [%s] as member of group [%s].\n",
                      fqdn, group_name);
                goto done;
            }
    }

done:
    talloc_free(attrs);
    talloc_free(fqdn);

    return ret;
}

static errno_t del_user(struct idp_id_ctx *idp_id_ctx, const char *user_name)
{
    DEBUG(SSSDBG_TRACE_LIBS, "Trying to delete user [%s].\n", user_name);
    return sysdb_delete_user(idp_id_ctx->be_ctx->domain, user_name, 0);
}

static errno_t store_json_group(struct idp_id_ctx *idp_id_ctx, json_t *group,
                                const char *user_name)
{
    errno_t ret;
    json_t *group_name = NULL;
    json_t *uuid = NULL;
    int cache_timeout;
    struct sss_domain_info *dom;
    gid_t gid;
    char *fqdn = NULL;
    enum idmap_error_code err;
    struct sysdb_attrs *attrs = NULL;

    dom = idp_id_ctx->be_ctx->domain;


    group_name = json_object_get(group, "posixGroupname");
    if (!json_is_string(group_name)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "JSON group object does not contain 'posixGroupname' string.\n");
        ret = EINVAL;
        goto done;
    }

    fqdn = sss_create_internal_fqname(idp_id_ctx, json_string_value(group_name),
                                      dom->name);
    if (fqdn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate fully-qualified name.\n");
        ret = ENOMEM;
        goto done;
    }

    uuid = json_object_get(group, "id");
    if (!json_is_string(uuid)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "JSON group object does not contain 'id' string.\n");
        ret = EINVAL;
        goto done;
    }

    err = sss_idmap_gen_to_unix(idp_id_ctx->idmap_ctx,
                                idp_id_ctx->token_endpoint,
                                json_string_value(uuid), &gid);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate GID for [%s][%s].\n",
                                 fqdn, json_string_value(uuid));
        ret = EIO;
        goto done;
    }

    attrs = sysdb_new_attrs(idp_id_ctx);
    if (attrs == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to allocate memory for extra attributes.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_UUID, json_string_value(uuid));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add UUID to group attributes.\n");
        goto done;
    }

    cache_timeout = dom->group_timeout;
    ret = sysdb_store_group(dom, fqdn, gid, attrs, cache_timeout, 0);

    if (user_name != NULL) {
        ret = sysdb_add_group_member(dom, fqdn, user_name, SYSDB_MEMBER_USER,
                                     false);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to store user [%s] as member of group [%s].\n",
                      user_name, fqdn);
                goto done;
            }
    }

done:
    talloc_free(attrs);
    talloc_free(fqdn);

    return ret;
}

static errno_t del_group(struct idp_id_ctx *idp_id_ctx, const char *group_name)
{
    DEBUG(SSSDBG_TRACE_LIBS, "Trying to delete group [%s].\n", group_name);
    return sysdb_delete_group(idp_id_ctx->be_ctx->domain, group_name, 0);
}

typedef errno_t (store_func_t)(struct idp_id_ctx *idp_id_ctx, json_t *obj,
                               const char *name);

typedef errno_t (del_func_t)(struct idp_id_ctx *idp_id_ctx, const char *name);

static errno_t eval_obj_buf(struct idp_id_ctx *idp_id_ctx,
                            const char *type, store_func_t *store_func,
                            del_func_t *del_func, const char *name,
                            const char *del_obj_name, bool noexist_delete,
                            const uint8_t *buf, ssize_t buflen)
{
    errno_t ret;
    json_t *data = NULL;
    json_error_t json_error;
    char *tmp = NULL;
    size_t index;
    json_t *obj;

    data = json_loadb((const char *) buf, buflen, 0, &json_error);
    if (data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to parse %s data on line [%d]: [%s].\n",
              type, json_error.line, json_error.text);
        ret = EINVAL;
        goto done;
    }

    if (!json_is_array(data)) {
        DEBUG(SSSDBG_OP_FAILURE, "Array of %ss expected.\n", type);
        ret = EINVAL;
        goto done;
    }

    if (DEBUG_IS_SET(SSSDBG_TRACE_ALL)) {
        tmp = json_dumps(data, 0);
        if (tmp != NULL) {
            DEBUG(SSSDBG_TRACE_ALL, "JSON: %s\n", tmp);
            free(tmp);
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "json_dumps() failed.\n");
        }
    }

    if (json_array_size(data) == 0 && noexist_delete) {
        ret = del_func(idp_id_ctx, del_obj_name);
        if (ret == ENOENT) {
            ret = EOK;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to delete %s [%s].\n",
                                     type, del_obj_name);
        }
        goto done;
    }

    json_array_foreach(data, index, obj) {
        ret = store_func(idp_id_ctx, obj, name);
        if (ret != EOK) {
            tmp = json_dumps(obj, 0);
            DEBUG(SSSDBG_OP_FAILURE, "Failed to store JSON %s [%s].\n", type,
                                                                        tmp);
            free(tmp);
        }
    }

    ret = EOK;
done:
    json_decref(data);

    return ret;
}

errno_t eval_user_buf(struct idp_id_ctx *idp_id_ctx,
                      const char *group_name,
                      const char *del_name,
                      bool noexist_delete,
                      uint8_t *buf, ssize_t buflen)
{
    return eval_obj_buf(idp_id_ctx, "user", store_json_user, del_user,
                        group_name, del_name, noexist_delete, buf, buflen);
}

errno_t eval_group_buf(struct idp_id_ctx *idp_id_ctx,
                       const char *user_name,
                       const char *del_name,
                       bool noexist_delete,
                       uint8_t *buf, ssize_t buflen)
{
    return eval_obj_buf(idp_id_ctx, "group", store_json_group, del_group,
                        user_name, del_name, noexist_delete, buf, buflen);
}
