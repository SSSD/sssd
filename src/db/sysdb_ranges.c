/*
   SSSD

   System Database - ID ranges related calls

   Copyright (C) 2012 Sumit Bose <sbose@redhat.com>

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

static errno_t find_attr_as_uint32_t(const struct ldb_message *msg,
                                     const char *attr_name, uint32_t *result)
{
    uint64_t val;

    val = ldb_msg_find_attr_as_uint64(msg, attr_name, UINT64_MAX);

    if (val == UINT64_MAX) {
        return ENOENT;
    } else if (val >= UINT32_MAX) {
        return EINVAL;
    }

    *result = val;
    return EOK;
}

errno_t sysdb_get_ranges(TALLOC_CTX *mem_ctx, struct sysdb_ctx *sysdb,
                             size_t *range_count,
                             struct range_info ***range_list)
{
    size_t c;
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    const char *attrs[] = {SYSDB_NAME,
                           SYSDB_BASE_ID,
                           SYSDB_ID_RANGE_SIZE,
                           SYSDB_BASE_RID,
                           SYSDB_SECONDARY_BASE_RID,
                           SYSDB_DOMAIN_ID,
                           SYSDB_ID_RANGE_TYPE,
                           SYSDB_ID_RANGE_MPG,
                           NULL};
    struct range_info **list;
    struct ldb_dn *basedn;
    const char *tmp_str;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    basedn = ldb_dn_new(tmp_ctx, sysdb->ldb, SYSDB_TMPL_RANGE_BASE);
    if (basedn == NULL) {
        ret = EIO;
        goto done;
    }
    ret = ldb_search(sysdb->ldb, tmp_ctx, &res,
                     basedn, LDB_SCOPE_SUBTREE,
                     attrs, "objectclass=%s", SYSDB_ID_RANGE_CLASS);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    list = talloc_zero_array(tmp_ctx, struct range_info *, res->count + 1);
    if (list == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (c = 0; c < res->count; c++) {
        list[c] = talloc_zero(list, struct range_info);
        if (list[c] == NULL) {
            ret = ENOMEM;
            goto done;
        }
        tmp_str = ldb_msg_find_attr_as_string(res->msgs[c], SYSDB_NAME, NULL);
        if (tmp_str == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE, "The object [%s] doesn't have a name.\n",
                                       ldb_dn_get_linearized(res->msgs[c]->dn));
            ret = EINVAL;
            goto done;
        }

        list[c]->name = talloc_strdup(list, tmp_str);
        if (list[c]->name == NULL) {
            ret = ENOMEM;
            goto done;
        }

        tmp_str = ldb_msg_find_attr_as_string(res->msgs[c], SYSDB_DOMAIN_ID,
                                              NULL);
        if (tmp_str != NULL) {
            list[c]->trusted_dom_sid = talloc_strdup(list, tmp_str);
            if (list[c]->trusted_dom_sid == NULL) {
                ret = ENOMEM;
                goto done;
            }
        }

        ret = find_attr_as_uint32_t(res->msgs[c], SYSDB_BASE_ID,
                                    &list[c]->base_id);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_MINOR_FAILURE, "find_attr_as_uint32_t failed.\n");
            goto done;
        }

        ret = find_attr_as_uint32_t(res->msgs[c], SYSDB_ID_RANGE_SIZE,
                                    &list[c]->id_range_size);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_MINOR_FAILURE, "find_attr_as_uint32_t failed.\n");
            goto done;
        }

        ret = find_attr_as_uint32_t(res->msgs[c], SYSDB_BASE_RID,
                                    &list[c]->base_rid);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_MINOR_FAILURE, "find_attr_as_uint32_t failed.\n");
            goto done;
        }

        ret = find_attr_as_uint32_t(res->msgs[c], SYSDB_SECONDARY_BASE_RID,
                                    &list[c]->secondary_base_rid);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_MINOR_FAILURE, "find_attr_as_uint32_t failed.\n");
            goto done;
        }

        tmp_str = ldb_msg_find_attr_as_string(res->msgs[c], SYSDB_ID_RANGE_TYPE,
                                              NULL);
        if (tmp_str != NULL) {
            list[c]->range_type = talloc_strdup(list, tmp_str);
            if (list[c]->range_type == NULL) {
                ret = ENOMEM;
                goto done;
            }
        }

        tmp_str = ldb_msg_find_attr_as_string(res->msgs[c], SYSDB_ID_RANGE_MPG,
                                              "default");
        list[c]->mpg_mode = str_to_domain_mpg_mode(tmp_str);
    }
    list[res->count] = NULL;

    *range_count = res->count;
    *range_list = talloc_steal(mem_ctx, list);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_get_range(TALLOC_CTX *mem_ctx,
                        struct sysdb_ctx *sysdb,
                        const char *forest,
                        struct range_info **_range)
{
    struct range_info **list;
    struct range_info *range;
    size_t count;
    size_t i;
    errno_t ret;

    ret = sysdb_get_ranges(NULL, sysdb, &count, &list);
    if (ret != EOK) {
        return ret;
    }

    for (i = 0; i < count; i++) {
        range = list[i];
        if (range->trusted_dom_sid == NULL) {
            continue;
        }

        if (strcmp(range->trusted_dom_sid, forest) != 0) {
            continue;
        }

        *_range = talloc_steal(mem_ctx, range);
        ret = EOK;
        goto done;
    }

    ret = ENOENT;

done:
    talloc_free(list);
    return ret;
}

errno_t sysdb_range_create(struct sysdb_ctx *sysdb, struct range_info *range)
{
    struct ldb_message *msg;
    int ret;
    TALLOC_CTX *tmp_ctx;

    /* if both or none are set, skip */
    if ((range->trusted_dom_sid == NULL && range->secondary_base_rid == 0) ||
        (range->trusted_dom_sid != NULL && range->secondary_base_rid != 0)) {

        DEBUG(SSSDBG_OP_FAILURE, "Invalid range, skipping. Expected that "
                    "either the secondary base RID or the SID of the trusted "
                    "domain is set, but not both or none of them.\n");
        return EOK;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                             SYSDB_TMPL_RANGE, range->name);
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_add_string(msg, SYSDB_OBJECTCLASS, SYSDB_ID_RANGE_CLASS);
    if (ret) goto done;

    if (range->trusted_dom_sid == NULL && range->secondary_base_rid != 0) {
        ret = sysdb_add_string(msg, SYSDB_OBJECTCLASS,
                               SYSDB_DOMAIN_ID_RANGE_CLASS);
        if (ret) goto done;

        ret = sysdb_add_ulong(msg, SYSDB_SECONDARY_BASE_RID,
                              (unsigned long) range->secondary_base_rid);
        if (ret) goto done;
    } else if (range->trusted_dom_sid != NULL &&
               range->secondary_base_rid == 0) {
        ret = sysdb_add_string(msg, SYSDB_OBJECTCLASS,
                               SYSDB_TRUSTED_AD_DOMAIN_RANGE_CLASS);
        if (ret) goto done;

        ret = sysdb_add_string(msg, SYSDB_DOMAIN_ID, range->trusted_dom_sid);
        if (ret) goto done;
    }

    ret = sysdb_add_string(msg, SYSDB_NAME, range->name);
    if (ret) goto done;

    ret = sysdb_add_ulong(msg, SYSDB_BASE_ID, (unsigned long) range->base_id);
    if (ret) goto done;

    ret = sysdb_add_ulong(msg, SYSDB_ID_RANGE_SIZE,
                          (unsigned long) range->id_range_size);
    if (ret) goto done;

    ret = sysdb_add_ulong(msg, SYSDB_BASE_RID,
                          (unsigned long) range->base_rid);
    if (ret) goto done;

    ret = sysdb_add_ulong(msg, SYSDB_CREATE_TIME, (unsigned long)time(NULL));
    if (ret) goto done;

    ret = sysdb_add_string(msg, SYSDB_ID_RANGE_TYPE, range->range_type);
    if (ret) goto done;

    ret = sysdb_add_string(msg, SYSDB_ID_RANGE_MPG,
                           str_domain_mpg_mode(range->mpg_mode));
    if (ret) goto done;

    ret = ldb_add(sysdb->ldb, msg);
    if (ret) goto done;

    ret = sysdb_error_to_errno(ret);

done:
    if (ret) {
        DEBUG(SSSDBG_TRACE_FUNC, "Error: %d (%s)\n", ret, strerror(ret));
    }
    talloc_zfree(tmp_ctx);
    return ret;
}

errno_t sysdb_update_ranges(struct sysdb_ctx *sysdb,
                            struct range_info **ranges)
{
    int ret;
    int sret;
    size_t c;
    size_t d;
    TALLOC_CTX *tmp_ctx = NULL;
    size_t cur_range_count;
    struct range_info **cur_ranges;
    struct ldb_dn *dn;
    bool in_transaction = false;
    bool *keep_range;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Retrieve all ranges that are currently in sysdb */
    ret = sysdb_get_ranges(tmp_ctx, sysdb, &cur_range_count,
                               &cur_ranges);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_get_ranges failed.\n");
        goto done;
    }

    keep_range = talloc_zero_array(tmp_ctx, bool, cur_range_count);
    if (keep_range == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero_array failed.\n");
        goto done;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_transaction_start failed.\n");
        goto done;
    }
    in_transaction = true;

    /* Go through a list of retrieved ranges and:
     * - if a range already exists in sysdb, mark it for preservation
     * - if the range doesn't exist in sysdb, create it
     */
    for (c = 0; ranges[c] != NULL; c++) {
        for (d = 0; d < cur_range_count; d++) {
            if (strcasecmp(ranges[c]->name, cur_ranges[d]->name) == 0) {
                keep_range[d] = true;
                /* range already in cache, nothing to do */
                break;
            }
        }

        if (d == cur_range_count) {
            DEBUG(SSSDBG_TRACE_FUNC, "Adding range [%s].\n", ranges[c]->name);
            ret = sysdb_range_create(sysdb, ranges[c]);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_range_create failed.\n");
                goto done;
            }
        }
    }

    /* Now delete all ranges that have been in sysdb prior to
     * refreshing the list and are not marked for preservation
     * (i.e. they are not in the new list of ranges)
     */
    for (d = 0; d < cur_range_count; d++) {
        if (!keep_range[d]) {
            DEBUG(SSSDBG_TRACE_FUNC, "Removing range [%s].\n",
                                      cur_ranges[d]->name);
            dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                                SYSDB_TMPL_RANGE, cur_ranges[d]->name);
            if (dn == NULL) {
                ret = ENOMEM;
                goto done;
            }

            ret = sysdb_delete_entry(sysdb, dn, true);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_delete_entry failed.\n");
                goto done;
            }
        }
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not commit transaction\n");
        goto done;
    }
    in_transaction = false;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not cancel transaction\n");
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}
