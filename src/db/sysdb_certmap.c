/*
   SSSD

   System Database - certificate mapping rules related calls

   Copyright (C) 2017 Sumit Bose <sbose@redhat.com>

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
#include "lib/certmap/sss_certmap.h"

static errno_t sysdb_create_certmap_container(struct sysdb_ctx *sysdb,
                                              bool user_name_hint)
{
    struct ldb_message *msg = NULL;
    errno_t ret;

    msg = ldb_msg_new(sysdb);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(msg, sysdb->ldb, SYSDB_TMPL_CERTMAP_BASE);
    if (msg->dn == NULL) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "cn", "certmap");
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = ldb_msg_add_string(msg, SYSDB_CERTMAP_USER_NAME_HINT,
                             user_name_hint ? "TRUE" : "FALSE");
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* do a synchronous add */
    ret = ldb_add(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to add certmap container (%d, [%s])!\n",
               ret, ldb_errstring(sysdb->ldb));
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    talloc_free(msg);

    return ret;
}

static struct ldb_dn *sysdb_certmap_dn(TALLOC_CTX *mem_ctx,
                                       struct sysdb_ctx *sysdb,
                                       const char *name)
{
    int ret;
    char *clean_name;
    struct ldb_dn *dn = NULL;

    ret = sysdb_dn_sanitize(mem_ctx, name, &clean_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_dn_sanitize failed.\n");
        return NULL;
    }

    dn = ldb_dn_new_fmt(mem_ctx, sysdb->ldb, SYSDB_TMPL_CERTMAP, clean_name);
    talloc_free(clean_name);
    if (dn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new_fmt failed.\n");
        return NULL;
    }

    return dn;
}

static errno_t sysdb_certmap_add(struct sysdb_ctx *sysdb,
                                 struct certmap_info *certmap)
{
    struct ldb_message *msg;
    struct ldb_message_element *el;
    int ret;
    TALLOC_CTX *tmp_ctx;
    size_t c;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed");
        return ENOMEM;
    }

    msg = ldb_msg_new(tmp_ctx);
    if (msg == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_new failed.\n");
        ret = ENOMEM;
        goto done;
    }

    msg->dn = sysdb_certmap_dn(tmp_ctx, sysdb, certmap->name);
    if (msg->dn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_certmap_dn failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_add_string(msg, SYSDB_OBJECTCLASS, SYSDB_CERTMAP_CLASS);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_add_string failed.\n");
        goto done;
    }

    ret = sysdb_add_string(msg, SYSDB_NAME, certmap->name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_add_string failed.\n");
        goto done;
    }

    if (certmap->map_rule != NULL) {
        ret = sysdb_add_string(msg, SYSDB_CERTMAP_MAPPING_RULE,
                               certmap->map_rule);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_add_string failed.\n");
            goto done;
        }
    }

    if (certmap->match_rule != NULL) {
        ret = sysdb_add_string(msg, SYSDB_CERTMAP_MATCHING_RULE,
                               certmap->match_rule);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_add_string failed.\n");
            goto done;
        }
    }

    if (certmap->domains != NULL && certmap->domains[0] != NULL) {
        for (c = 0; certmap->domains[c] != NULL; c++);
        el = talloc_zero(tmp_ctx, struct ldb_message_element);
        if (el == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
            ret = ENOMEM;
            goto done;
        }

        el->name = talloc_strdup(el, SYSDB_CERTMAP_DOMAINS);
        if(el->name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }
        el->num_values = c;
        el->values = talloc_zero_array(el, struct ldb_val, c + 1);
        if (el->values == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_zero_array failed.\n");
            ret = ENOMEM;
            goto done;
        }

        for (c = 0; certmap->domains[c] != NULL; c++) {
            el->values[c].data = (uint8_t *) talloc_strdup(el->values,
                                                           certmap->domains[c]);
            if (el->values[c].data == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                ret = ENOMEM;
                goto done;
            }
            el->values[c].length = strlen(certmap->domains[c]);
        }

        ret = ldb_msg_add(msg, el, LDB_FLAG_MOD_ADD);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_add failed.\n");
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    ret = sysdb_add_ulong(msg, SYSDB_CERTMAP_PRIORITY,
                          (unsigned long)certmap->priority);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_add_ulong failed.\n");
        goto done;
    }

    ret = ldb_add(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_add failed.\n");
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = EOK;

done:
    if (ret) {
        DEBUG(SSSDBG_TRACE_FUNC, "Error: %d (%s)\n", ret, sss_strerror(ret));
    }
    talloc_zfree(tmp_ctx);
    return ret;
}

errno_t sysdb_update_certmap(struct sysdb_ctx *sysdb,
                             struct certmap_info **certmaps,
                             bool user_name_hint)
{
    size_t c;
    struct ldb_dn *container_dn = NULL;
    bool in_transaction = false;
    int ret;
    int sret;

    if (certmaps == NULL) {
        return EINVAL;
    }

    container_dn = ldb_dn_new(sysdb, sysdb->ldb, SYSDB_TMPL_CERTMAP_BASE);
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
    ret = sysdb_create_certmap_container(sysdb, user_name_hint);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_create_certmap_container failed.\n");
        goto done;
    }

    for (c = 0; certmaps[c] != NULL; c++) {
        ret = sysdb_certmap_add(sysdb, certmaps[c]);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_certmap_add failed.\n");
            goto done;
        }
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_transaction_commit failed.\n");
        goto done;
    }
    in_transaction = false;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not cancel transaction.\n");
        }
    }

    talloc_free(container_dn);

    return ret;
}

enum certmap_info_member {
    SSS_CMIM_NAME = 0,
    SSS_CMIM_MAPPING_RULE,
    SSS_CMIM_MATCHING_RULE,
    SSS_CMIM_PRIORITY,
    SSS_CMIM_DOMAINS,

    SSS_CMIM_SENTINEL
};

errno_t sysdb_ldb_msg_attr_to_certmap_info(TALLOC_CTX *mem_ctx,
                                           struct ldb_message *msg,
                                           const char **attr_map,
                                           struct certmap_info **certmap)
{
    int ret;
    size_t d;
    size_t num_values;
    struct certmap_info *map = NULL;
    const char *tmp_str;
    uint64_t tmp_uint;
    struct ldb_message_element *tmp_el;

    if (msg == NULL || attr_map == NULL || certmap == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid input.\n");
        return EINVAL;
    }

    for (d = 0; d < SSS_CMIM_SENTINEL; d++) {
        if (attr_map[d] == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Invalid attribute map");
            return EINVAL;
        }
    }

    map = talloc_zero(mem_ctx, struct certmap_info);
    if (map == NULL) {
        return ENOMEM;
    }

    tmp_str = ldb_msg_find_attr_as_string(msg, attr_map[SSS_CMIM_NAME], NULL);
    if (tmp_str == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "The object [%s] doesn't have a name.\n",
                                    ldb_dn_get_linearized(msg->dn));
        ret = EINVAL;
        goto done;
    }

    map->name = talloc_strdup(map, tmp_str);
    if (map->name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tmp_str = ldb_msg_find_attr_as_string(msg, attr_map[SSS_CMIM_MAPPING_RULE],
                                          NULL);
    if (tmp_str != NULL) {
        map->map_rule = talloc_strdup(map, tmp_str);
        if (map->map_rule == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    tmp_str = ldb_msg_find_attr_as_string(msg, attr_map[SSS_CMIM_MATCHING_RULE],
                                          NULL);
    if (tmp_str != NULL) {
        map->match_rule = talloc_strdup(map, tmp_str);
        if (map->match_rule == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    tmp_uint = ldb_msg_find_attr_as_uint64(msg, attr_map[SSS_CMIM_PRIORITY],
                                           (uint64_t) -1);
    if (tmp_uint != (uint64_t) -1) {
        if (tmp_uint > UINT32_MAX) {
            DEBUG(SSSDBG_OP_FAILURE, "Priority value [%lu] too large.\n",
                                     (unsigned long) tmp_uint);
            ret = EINVAL;
            goto done;
        }

        map->priority = (uint32_t) tmp_uint;
    } else {
        map->priority = SSS_CERTMAP_MIN_PRIO;
    }

    tmp_el = ldb_msg_find_element(msg, attr_map[SSS_CMIM_DOMAINS]);
    if (tmp_el != NULL) {
        num_values = tmp_el->num_values;
    } else {
        num_values = 0;
    }

    map->domains = talloc_zero_array(map, const char *, num_values + 1);
    if (map->domains == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero_array failed.\n");
        ret = ENOMEM;
        goto done;
    }

    for (d = 0; d < num_values; d++) {
        map->domains[d] = talloc_strndup(map->domains,
                                         (char *) tmp_el->values[d].data,
                                         tmp_el->values[d].length);
        if (map->domains[d] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strndup failed.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    *certmap = map;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(map);
    }

    return ret;
}

errno_t sysdb_get_certmap(TALLOC_CTX *mem_ctx, struct sysdb_ctx *sysdb,
                          struct certmap_info ***certmaps, bool *user_name_hint)
{
    size_t c;
    struct ldb_dn *container_dn = NULL;
    int ret;
    struct certmap_info **maps = NULL;
    TALLOC_CTX *tmp_ctx = NULL;
    struct ldb_result *res;
    const char *attrs[] = {SYSDB_NAME,
                           SYSDB_CERTMAP_MAPPING_RULE,
                           SYSDB_CERTMAP_MATCHING_RULE,
                           SYSDB_CERTMAP_PRIORITY,
                           SYSDB_CERTMAP_DOMAINS,
                           NULL};
    const char *config_attrs[] = {SYSDB_CERTMAP_USER_NAME_HINT,
                                  NULL};
    bool hint = false;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    container_dn = ldb_dn_new(tmp_ctx, sysdb->ldb, SYSDB_TMPL_CERTMAP_BASE);
    if (container_dn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_search(sysdb->ldb, tmp_ctx, &res, container_dn, LDB_SCOPE_BASE,
                     config_attrs, SYSDB_CERTMAP_USER_NAME_HINT"=*");
    if (ret != LDB_SUCCESS || res->count != 1) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Failed to read certmap config, skipping.\n");
    } else {
        hint = ldb_msg_find_attr_as_bool(res->msgs[0],
                                         SYSDB_CERTMAP_USER_NAME_HINT, false);
    }

    ret = ldb_search(sysdb->ldb, tmp_ctx, &res,
                     container_dn, LDB_SCOPE_SUBTREE,
                     attrs, "objectclass=%s", SYSDB_CERTMAP_CLASS);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_search failed.\n");
        ret = EIO;
        goto done;
    }

    if (res->count == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "No certificate maps found.\n");
        ret = EOK;
        goto done;
    }

    maps = talloc_zero_array(tmp_ctx, struct certmap_info *, res->count + 1);
    if (maps == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero_array failed.\n");
        ret = ENOMEM;
        goto done;
    }

    for (c = 0; c < res->count; c++) {
        ret = sysdb_ldb_msg_attr_to_certmap_info(maps, res->msgs[c], attrs,
                                                 &maps[c]);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sysdb_ldb_msg_attr_to_certmap_info failed.\n");
            goto done;
        }
    }

    ret = EOK;

done:
    if (ret == EOK) {
        *certmaps = talloc_steal(mem_ctx, maps);
        *user_name_hint = hint;
    }

    talloc_free(tmp_ctx);

    return ret;
}
