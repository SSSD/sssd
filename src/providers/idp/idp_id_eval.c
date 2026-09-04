/*
    SSSD

    IdP Identity Backend Module - evaluate replies

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
        if (ret == EEXIST) {
            DEBUG(SSSDBG_FUNC_DATA,
                  "Group [%s] already has member [%s]. Skipping.\n",
                  group_name, fqdn);
            ret = EOK;
        } else if (ret != EOK) {
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

    /* If we just add a single member to a group (user_name != NULL) we do not
     * want to change the cache timeout. Calling `sysdb_add_incomplete_group()
     * will check if the group already exists (ret == ERR_GID_DUPLICATED) or
     * create an expired group object (ret == EOK). In both cases there will
     * be a cached group object where the user can be added as a member. */
    if (user_name == NULL) {
        ret = sysdb_store_group(dom, fqdn, gid, attrs, dom->group_timeout, 0);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to store group [%s].\n", fqdn);
            goto done;
        }
    } else {
        ret = sysdb_add_incomplete_group(dom, fqdn, gid, NULL, NULL,
                                         json_string_value(uuid),
                                         gid != 0, 0);
        if (ret != EOK && ret != ERR_GID_DUPLICATED) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to create incomplete group [%s].\n", fqdn);
            goto done;
        }

        ret = sysdb_add_group_member(dom, fqdn, user_name, SYSDB_MEMBER_USER,
                                     false);
        if (ret == EEXIST) {
            DEBUG(SSSDBG_FUNC_DATA,
                  "Group [%s] already has member [%s]. Skipping.\n",
                  fqdn, user_name);
            ret = EOK;
        } else if (ret != EOK) {
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

static errno_t parse_obj_buf(const char *type,
                             const uint8_t *buf, ssize_t buflen,
                             json_t **_data)
{
    json_error_t json_error;
    json_t *data = NULL;
    char *tmp = NULL;

    data = json_loadb((const char *) buf, buflen, 0, &json_error);
    if (data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to parse %s data on line [%d]: [%s].\n",
              type, json_error.line, json_error.text);
        return EINVAL;
    }

    if (!json_is_array(data)) {
        DEBUG(SSSDBG_OP_FAILURE, "Array of %ss expected.\n", type);
        json_decref(data);
        return EINVAL;
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

    *_data = data;
    return EOK;
}

static errno_t select_obj_type(json_t *data, const char *type,
                               json_t **_selected)
{
    json_t *selected = NULL;
    json_t *obj;
    json_t *obj_type;
    size_t index;
    errno_t ret;

    selected = json_array();
    if (selected == NULL) {
        return ENOMEM;
    }

    json_array_foreach(data, index, obj) {
        obj_type = json_object_get(obj, "posixObjectType");
        if (!json_is_string(obj_type)) {
            ret = EINVAL;
            goto done;
        }

        if (strcmp(json_string_value(obj_type), type) != 0) {
            continue;
        }

        ret = json_array_append(selected, obj);
        if (ret != 0) {
            ret = ENOMEM;
            goto done;
        }
    }

    *_selected = selected;
    return EOK;

done:
    json_decref(selected);
    return ret;
}

static errno_t eval_obj_buf(struct idp_id_ctx *idp_id_ctx,
                            const char *type, store_func_t *store_func,
                            del_func_t *del_func, const char *name,
                            const char *del_obj_name, bool noexist_delete,
                            const uint8_t *buf, ssize_t buflen)
{
    errno_t ret;
    json_t *data = NULL;
    char *tmp = NULL;
    size_t index;
    json_t *obj;

    ret = parse_obj_buf(type, buf, buflen, &data);
    if (ret != EOK) {
        goto done;
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

static errno_t update_group_members(struct idp_id_ctx *idp_id_ctx,
                                    const char *group_name,
                                    json_t *data)
{
    struct sss_domain_info *dom = idp_id_ctx->be_ctx->domain;
    TALLOC_CTX *tmp_ctx = NULL;
    const char *attrs[] = { SYSDB_NAME, NULL };
    struct ldb_message *msg = NULL;
    struct ldb_message **members = NULL;
    json_t *obj;
    json_t *user_name;
    char **idp_users = NULL;
    char **sysdb_users = NULL;
    char **add_users = NULL;
    char **del_users = NULL;
    const char *member_name;
    size_t index;
    size_t count;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    count = json_array_size(data);
    idp_users = talloc_zero_array(tmp_ctx, char *, count + 1);
    if (idp_users == NULL) {
        ret = ENOMEM;
        goto done;
    }

    json_array_foreach(data, index, obj) {
        user_name = json_object_get(obj, "posixUsername");
        if (!json_is_string(user_name)) {
            ret = EINVAL;
            goto done;
        }

        idp_users[index] = sss_create_internal_fqname(
                                            idp_users,
                                            json_string_value(user_name),
                                            dom->name);
        if (idp_users[index] == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = sysdb_search_group_by_name(tmp_ctx, dom, group_name, NULL, &msg);
    if (ret != EOK) {
        goto done;
    }

    /* A group can also contain groups; this lookup returns only direct
     * users. */
    ret = sysdb_asq_search(tmp_ctx, dom, msg->dn, "("SYSDB_UC")",
                           SYSDB_MEMBER, attrs, &count, &members);
    if (ret != EOK) {
        goto done;
    }

    sysdb_users = talloc_zero_array(tmp_ctx, char *, count + 1);
    if (sysdb_users == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (index = 0; index < count; index++) {
        member_name = ldb_msg_find_attr_as_string(members[index], SYSDB_NAME,
                                                  NULL);
        if (member_name == NULL) {
            ret = ERR_INTERNAL;
            goto done;
        }

        sysdb_users[index] = talloc_strdup(sysdb_users, member_name);
        if (sysdb_users[index] == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = diff_string_lists(tmp_ctx, idp_users, sysdb_users,
                            &add_users, &del_users, NULL);
    if (ret != EOK) {
        goto done;
    }

    for (index = 0; add_users != NULL && add_users[index] != NULL; index++) {
        ret = sysdb_add_group_member(dom, group_name, add_users[index],
                                     SYSDB_MEMBER_USER, false);
        if (ret != EOK) {
            goto done;
        }
    }

    for (index = 0; del_users != NULL && del_users[index] != NULL; index++) {
        ret = sysdb_remove_group_member(dom, group_name, del_users[index],
                                        SYSDB_MEMBER_USER, false);
        if (ret != EOK) {
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t update_user_groups(struct idp_id_ctx *idp_id_ctx,
                                  const char *user_name,
                                  json_t *data)
{
    struct sss_domain_info *dom = idp_id_ctx->be_ctx->domain;
    TALLOC_CTX *tmp_ctx = NULL;
    json_t *obj;
    json_t *group_name;
    char **idp_groups = NULL;
    char **sysdb_groups = NULL;
    char **add_groups = NULL;
    char **del_groups = NULL;
    size_t index;
    size_t count;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    count = json_array_size(data);
    idp_groups = talloc_zero_array(tmp_ctx, char *, count + 1);
    if (idp_groups == NULL) {
        ret = ENOMEM;
        goto done;
    }

    json_array_foreach(data, index, obj) {
        group_name = json_object_get(obj, "posixGroupname");
        if (!json_is_string(group_name)) {
            ret = EINVAL;
            goto done;
        }

        idp_groups[index] = sss_create_internal_fqname(
                                            idp_groups,
                                            json_string_value(group_name),
                                            dom->name);
        if (idp_groups[index] == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = sysdb_get_direct_parents(tmp_ctx, dom, dom, SYSDB_MEMBER_USER,
                                   user_name, &sysdb_groups);
    if (ret != EOK) {
        goto done;
    }

    ret = diff_string_lists(tmp_ctx, idp_groups, sysdb_groups,
                            &add_groups, &del_groups, NULL);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_update_members(dom, user_name, SYSDB_MEMBER_USER,
                               (const char *const *)add_groups,
                               (const char *const *)del_groups);

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t store_obj_array(struct idp_id_ctx *idp_id_ctx,
                               const char *type,
                               store_func_t *store_func,
                               const char *name,
                               json_t *data)
{
    json_t *obj;
    char *tmp = NULL;
    size_t index;
    errno_t ret;

    json_array_foreach(data, index, obj) {
        ret = store_func(idp_id_ctx, obj, name);
        if (ret != EOK) {
            tmp = json_dumps(obj, 0);
            DEBUG(SSSDBG_OP_FAILURE, "Failed to store JSON %s [%s].\n", type,
                                                                        tmp);
            free(tmp);
            return ret;
        }
    }

    return EOK;
}

errno_t eval_group_members_buf(struct idp_id_ctx *idp_id_ctx,
                               const char *group_name,
                               const uint8_t *buf, ssize_t buflen)
{
    struct sysdb_ctx *sysdb = idp_id_ctx->be_ctx->domain->sysdb;
    json_t *data = NULL;
    json_t *users = NULL;
    errno_t ret;
    errno_t sret;
    bool in_transaction = false;

    ret = parse_obj_buf("user", buf, buflen, &data);
    if (ret != EOK) {
        goto done;
    }

    ret = select_obj_type(data, "user", &users);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        goto done;
    }
    in_transaction = true;

    ret = store_obj_array(idp_id_ctx, "user", store_json_user, NULL, users);
    if (ret != EOK) {
        goto done;
    }

    ret = update_group_members(idp_id_ctx, group_name, users);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret == EOK) {
        in_transaction = false;
    }

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to cancel group membership transaction.\n");
        }
    }
    json_decref(users);
    json_decref(data);
    return ret;
}

errno_t eval_user_groups_buf(struct idp_id_ctx *idp_id_ctx,
                             const char *user_name,
                             const uint8_t *buf, ssize_t buflen)
{
    struct sysdb_ctx *sysdb = idp_id_ctx->be_ctx->domain->sysdb;
    json_t *data = NULL;
    errno_t ret;
    errno_t sret;
    bool in_transaction = false;

    ret = parse_obj_buf("group", buf, buflen, &data);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        goto done;
    }
    in_transaction = true;

    ret = store_obj_array(idp_id_ctx, "group", store_json_group,
                          user_name, data);
    if (ret != EOK) {
        goto done;
    }

    ret = update_user_groups(idp_id_ctx, user_name, data);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret == EOK) {
        in_transaction = false;
    }

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to cancel user membership transaction.\n");
        }
    }
    json_decref(data);
    return ret;
}

errno_t eval_user_buf(struct idp_id_ctx *idp_id_ctx,
                      const char *del_name,
                      bool noexist_delete,
                      uint8_t *buf, ssize_t buflen)
{
    return eval_obj_buf(idp_id_ctx, "user", store_json_user, del_user,
                        NULL, del_name, noexist_delete, buf, buflen);
}

errno_t eval_group_buf(struct idp_id_ctx *idp_id_ctx,
                       const char *del_name,
                       bool noexist_delete,
                       uint8_t *buf, ssize_t buflen)
{
    return eval_obj_buf(idp_id_ctx, "group", store_json_group, del_group,
                        NULL, del_name, noexist_delete, buf, buflen);
}
