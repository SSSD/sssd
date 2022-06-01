/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2016 Red Hat

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

#include "util/crypto/sss_crypto.h"
#include "responder/nss/nss_protocol.h"

static errno_t
find_sss_id_type(struct ldb_message *msg,
                 bool mpg,
                 enum sss_id_type *id_type)
{
    size_t c;
    struct ldb_message_element *el;
    struct ldb_val *val = NULL;

    el = ldb_msg_find_element(msg, SYSDB_OBJECTCATEGORY);
    if (el == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Objectcategory attribute not found.\n");
        return EINVAL;
    }

    for (c = 0; c < el->num_values; c++) {
        val = &(el->values[c]);
        if (strncasecmp(SYSDB_USER_CLASS,
                        (char *)val->data, val->length) == 0) {
            break;
        }
    }

    if (c == el->num_values) {
        *id_type = SSS_ID_TYPE_GID;
    } else {
        if (mpg) {
            *id_type = SSS_ID_TYPE_BOTH;
        } else {
            *id_type = SSS_ID_TYPE_UID;
        }
    }

    return EOK;
}

static errno_t
sss_nss_get_id_type(struct sss_nss_cmd_ctx *cmd_ctx,
                    struct cache_req_result *result,
                    enum sss_id_type *_type)
{
    errno_t ret;
    bool mpg;

    /* Well known objects are always groups. */
    if (result->well_known_object) {
        *_type = SSS_ID_TYPE_GID;
        return EOK;
    }

    mpg = sss_domain_is_mpg(result->domain) || sss_domain_is_hybrid(result->domain);
    ret = find_sss_id_type(result->msgs[0], mpg, _type);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to find ID type [%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    return EOK;
}

static errno_t
sss_nss_get_sid_id_type(struct sss_nss_cmd_ctx *cmd_ctx,
                        struct cache_req_result *result,
                        const char **_sid,
                        uint64_t *_id,
                        enum sss_id_type *_type)
{
    errno_t ret;
    size_t c;
    const char *tmp;
    const char *user_sid = NULL;
    const char *group_sid = NULL;
    uint64_t user_uid = 0;
    uint64_t user_gid = 0;
    uint64_t group_gid = 0;
    enum sss_id_type ltype;

    if (result->count == 1) {
        *_sid = ldb_msg_find_attr_as_string(result->msgs[0],
                                            SYSDB_SID_STR, NULL);
        if (*_sid == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Missing SID.\n");
            return EINVAL;
        }
        ret = sss_nss_get_id_type(cmd_ctx, result, _type);
        if (ret == EOK ) {
            if (*_type == SSS_ID_TYPE_GID) {
                *_id = ldb_msg_find_attr_as_uint64(result->msgs[0],
                                                   SYSDB_GIDNUM, 0);
            } else {
                *_id = ldb_msg_find_attr_as_uint64(result->msgs[0],
                                                   SYSDB_UIDNUM, 0);
            }
        }
        return ret;
    }

    for (c = 0; c < result->count; c++) {
        ret = find_sss_id_type(result->msgs[c],
                               false /* we are only interested in the type
                                      * of the object, so mpg setting can
                                      * be ignored */,
                               &ltype);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Unable to find ID type, ignored [%d][%s].\n",
                  ret, sss_strerror(ret));
            continue;
        }

        tmp = ldb_msg_find_attr_as_string(result->msgs[c],
                                           SYSDB_SID_STR, NULL);
        if (tmp == NULL) {
            continue;
        }

        if (ltype == SSS_ID_TYPE_GID) {
            if (tmp != NULL && group_sid != NULL) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Search for SID found multiple groups with SIDs: %s, %s;"
                      " request failed.\n", tmp, group_sid);
                return EINVAL;
            }
            group_sid = tmp;
            group_gid = ldb_msg_find_attr_as_uint64(result->msgs[c],
                                                    SYSDB_GIDNUM, 0);
        } else {
            if (tmp != NULL && user_sid != NULL) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Search for SID found multiple users with SIDs: %s, %s; "
                      "request failed.\n", tmp, user_sid);
                return EINVAL;
            }
            user_sid = tmp;
            user_uid = ldb_msg_find_attr_as_uint64(result->msgs[c],
                                                   SYSDB_UIDNUM, 0);
            user_gid = ldb_msg_find_attr_as_uint64(result->msgs[c],
                                                   SYSDB_GIDNUM, 0);
        }
    }

    if (user_sid == NULL && group_sid == NULL) {
        /* No SID in the results */
        return ENOENT;
    } else if (user_sid != NULL && group_sid == NULL) {
        /* There is only one user with a SID in the results */
        *_sid = user_sid;
        *_id = user_uid;
        *_type = SSS_ID_TYPE_UID;
    } else if (user_sid == NULL && group_sid != NULL) {
        /* There is only one group with a SID in the results */
        *_sid = group_sid;
        *_id = group_gid;
        *_type = SSS_ID_TYPE_GID;
    } else if (user_sid != NULL && group_sid != NULL && user_uid != 0
                    && user_uid == user_gid && user_gid == group_gid) {
        /* Manually created user-private-group */
        *_sid = user_sid;
        *_id = user_uid;
        *_type = SSS_ID_TYPE_UID;
    } else {
        DEBUG(SSSDBG_OP_FAILURE,
              "Found user with SID [%s] and group with SID [%s] during a "
              "single request, cannot handle this case.\n",
              user_sid, group_sid);
        /* Unrelated user and group both with SIDs are returned, we cannot
         * handle this case. */
        return EINVAL;
    }

    return EOK;
}

errno_t
sss_nss_protocol_fill_sid(struct sss_nss_ctx *nss_ctx,
                          struct sss_nss_cmd_ctx *cmd_ctx,
                          struct sss_packet *packet,
                          struct cache_req_result *result)
{
    struct sized_string sz_sid;
    enum sss_id_type id_type;
    const char *sid;
    uint64_t id;
    size_t rp = 0;
    size_t body_len;
    uint8_t *body;
    errno_t ret;

    ret = sss_nss_get_sid_id_type(cmd_ctx, result, &sid, &id, &id_type);
    if (ret != EOK) {
        return ret;
    }

    to_sized_string(&sz_sid, sid);

    ret = sss_packet_grow(packet, sz_sid.len + 3 * sizeof(uint32_t));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_packet_grow failed.\n");
        return ret;
    }

    sss_packet_get_body(packet, &body, &body_len);

    SAFEALIGN_SET_UINT32(&body[rp], 1, &rp); /* Num results. */
    SAFEALIGN_SET_UINT32(&body[rp], 0, &rp); /* Reserved. */
    SAFEALIGN_SET_UINT32(&body[rp], id_type, &rp);
    SAFEALIGN_SET_STRING(&body[rp], sz_sid.str, sz_sid.len, &rp);

    if (nss_ctx->sid_mc_ctx != NULL) {
        /* no need to check for SSS_NSS_EX_FLAG_INVALIDATE_CACHE since
         * SID related requests don't support 'flags'
         */
        if (id == 0 || id >= UINT32_MAX) {
            DEBUG(SSSDBG_OP_FAILURE, "Invalid POSIX ID %lu\n", id);
            return EOK;
        }
        ret = sss_mmap_cache_sid_store(&nss_ctx->sid_mc_ctx, &sz_sid,
                                       (uint32_t)id, id_type,
                                       cmd_ctx->type != CACHE_REQ_OBJECT_BY_ID);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to store SID='%s' / ID=%lu in mmap cache [%d]: %s!\n",
                  sz_sid.str, id, ret, sss_strerror(ret));
        }
    }

    return EOK;
}

static errno_t process_attr_list(TALLOC_CTX *mem_ctx, struct ldb_message *msg,
                                 const char **attr_list,
                                 struct sized_string **_keys,
                                 struct sized_string **_vals,
                                 size_t *array_size, size_t *sum,
                                 size_t *found)
{
    size_t c;
    size_t d;
    struct sized_string *keys;
    struct sized_string *vals;
    struct ldb_val val;
    struct ldb_message_element *el;
    bool use_base64;

    keys = *_keys;
    vals = *_vals;

    for (c = 0; attr_list[c] != NULL; c++) {
        el = ldb_msg_find_element(msg, attr_list[c]);
        if (el != NULL && el->num_values > 0) {
            if (el->num_values > 1) {
                *array_size += el->num_values;
                keys = talloc_realloc(mem_ctx, keys, struct sized_string,
                                      *array_size);
                vals = talloc_realloc(mem_ctx, vals, struct sized_string,
                                      *array_size);
                if (keys == NULL || vals == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
                    return ENOMEM;
                }
            }

            use_base64 = false;
            if (strcmp(attr_list[c], SYSDB_USER_CERT) == 0) {
                use_base64 = true;
            }

            for (d = 0; d < el->num_values; d++) {
                to_sized_string(&keys[*found], attr_list[c]);
                *sum += keys[*found].len;
                if (use_base64) {
                    val.data = (uint8_t *)sss_base64_encode(vals,
                                                         el->values[d].data,
                                                         el->values[d].length);
                    if (val.data != NULL) {
                        val.length = strlen((char *)val.data);
                    }
                } else {
                    val = el->values[d];
                }

                if (val.data == NULL || val.data[val.length] != '\0') {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Unexpected attribute value found for [%s].\n",
                          attr_list[c]);
                    return EINVAL;
                }
                to_sized_string(&vals[*found], (const char *)val.data);
                *sum += vals[*found].len;

                (*found)++;
            }
        }
    }

    *_keys = keys;
    *_vals = vals;

    return EOK;
}

errno_t
sss_nss_protocol_fill_orig(struct sss_nss_ctx *nss_ctx,
                           struct sss_nss_cmd_ctx *cmd_ctx,
                           struct sss_packet *packet,
                           struct cache_req_result *result)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *msg = result->msgs[0];
    const char **extra_attrs = NULL;
    enum sss_id_type id_type;
    struct sized_string *keys;
    struct sized_string *vals;
    size_t extra_attrs_count = 0;
    size_t array_size;
    size_t sum;
    size_t found;
    size_t i;
    size_t rp = 0;
    size_t body_len;
    uint8_t *body;
    errno_t ret;
    const char *orig_attrs[] = { SYSDB_SID_STR,
                                 ORIGINALAD_PREFIX SYSDB_NAME,
                                 ORIGINALAD_PREFIX SYSDB_UIDNUM,
                                 ORIGINALAD_PREFIX SYSDB_GIDNUM,
                                 ORIGINALAD_PREFIX SYSDB_HOMEDIR,
                                 ORIGINALAD_PREFIX SYSDB_GECOS,
                                 ORIGINALAD_PREFIX SYSDB_SHELL,
                                 SYSDB_UPN,
                                 SYSDB_DEFAULT_OVERRIDE_NAME,
                                 SYSDB_AD_ACCOUNT_EXPIRES,
                                 SYSDB_AD_USER_ACCOUNT_CONTROL,
                                 SYSDB_SSH_PUBKEY,
                                 SYSDB_USER_CERT,
                                 SYSDB_USER_EMAIL,
                                 SYSDB_ORIG_DN,
                                 SYSDB_ORIG_MEMBEROF,
                                 NULL };

    if (result->count != 1) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unexpected number of results [%u], expected [1].\n",
              result->count);
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sss_nss_get_id_type(cmd_ctx, result, &id_type);
    if (ret != EOK) {
        return ret;
    }

    if (nss_ctx->extra_attributes != NULL) {
        extra_attrs = nss_ctx->extra_attributes;
        for (extra_attrs_count = 0;
             extra_attrs[extra_attrs_count] != NULL;
             extra_attrs_count++);
    }

    array_size = sizeof(orig_attrs) + extra_attrs_count;
    keys = talloc_array(tmp_ctx, struct sized_string, array_size);
    vals = talloc_array(tmp_ctx, struct sized_string, array_size);
    if (keys == NULL || vals == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
        ret = ENOMEM;
        goto done;
    }

    sum = 0;
    found = 0;

    ret = process_attr_list(tmp_ctx, msg, orig_attrs, &keys, &vals,
                            &array_size, &sum, &found);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "process_attr_list failed.\n");
        goto done;
    }

    if (extra_attrs_count != 0) {
        ret = process_attr_list(tmp_ctx, msg, extra_attrs, &keys, &vals,
                                &array_size, &sum, &found);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "process_attr_list failed.\n");
            goto done;
        }
    }

    ret = sss_packet_grow(packet, sum + 3 * sizeof(uint32_t));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_packet_grow failed.\n");
        goto done;
    }

    sss_packet_get_body(packet, &body, &body_len);
    SAFEALIGN_SETMEM_UINT32(&body[rp], 1, &rp); /* Num results */
    SAFEALIGN_SETMEM_UINT32(&body[rp], 0, &rp); /* reserved */
    SAFEALIGN_COPY_UINT32(&body[rp], &id_type, &rp);
    for (i = 0; i < found; i++) {
        SAFEALIGN_SET_STRING(&body[rp], keys[i].str, keys[i].len, &rp);
        SAFEALIGN_SET_STRING(&body[rp], vals[i].str, vals[i].len, &rp);
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
sss_nss_get_well_known_name(TALLOC_CTX *mem_ctx,
                            struct resp_ctx *rctx,
                            struct cache_req_result *result,
                            struct sized_string **_sz_name)
{
    struct sized_string *sz_name;
    const char *fq_name = NULL;
    const char *domname;
    const char *name;

    name = result->lookup_name;
    if (name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing name.\n");
        return EINVAL;
    }

    sz_name = talloc_zero(mem_ctx, struct sized_string);
    if (sz_name == NULL) {
        return ENOMEM;
    }

    domname = result->domain != NULL
                  ? result->domain->name
                  : result->well_known_domain;

    if (domname != NULL) {
        fq_name = sss_tc_fqname2(sz_name, rctx->global_names,
                                 domname, domname, name);
        if (fq_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Conversion to fqname failed.\n");
            talloc_free(sz_name);
            return ENOMEM;
        }

        name = fq_name;
    }

    to_sized_string(sz_name, name);

    *_sz_name = sz_name;

    return EOK;
}

static errno_t
sss_nss_get_ad_name(TALLOC_CTX *mem_ctx,
                    struct resp_ctx *rctx,
                    struct cache_req_result *result,
                    struct sized_string **_sz_name)
{
    struct ldb_message *msg = result->msgs[0];
    const char *name;
    errno_t ret;

    if (result->well_known_object) {
        return sss_nss_get_well_known_name(mem_ctx, rctx, result, _sz_name);
    }

    name = ldb_msg_find_attr_as_string(msg, ORIGINALAD_PREFIX SYSDB_NAME,
                                       NULL);
    if (name == NULL) {
        name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
    }

    if (name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing name.\n");
        return EINVAL;
    }

    ret = sized_output_name(mem_ctx, rctx, name, result->domain, _sz_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to create sized name [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    return EOK;
}

errno_t
sss_nss_protocol_fill_single_name(struct sss_nss_ctx *nss_ctx,
                                  struct sss_nss_cmd_ctx *cmd_ctx,
                                  struct sss_packet *packet,
                                  struct cache_req_result *result)
{
    if (result->ldb_result->count > 1) {
        DEBUG(SSSDBG_TRACE_FUNC, "Lookup returned more than one result "
                                 "but only one was expected.\n");
        return EEXIST;
    }

    return sss_nss_protocol_fill_name(nss_ctx, cmd_ctx, packet, result);
}

errno_t
sss_nss_protocol_fill_name(struct sss_nss_ctx *nss_ctx,
                           struct sss_nss_cmd_ctx *cmd_ctx,
                           struct sss_packet *packet,
                           struct cache_req_result *result)
{
    struct sized_string *sz_name;
    enum sss_id_type id_type;
    size_t rp = 0;
    size_t body_len;
    uint8_t *body;
    errno_t ret;

    ret = sss_nss_get_id_type(cmd_ctx, result, &id_type);
    if (ret != EOK) {
        return ret;
    }

    ret = sss_nss_get_ad_name(cmd_ctx, nss_ctx->rctx, result, &sz_name);
    if (ret != EOK) {
        return ret;
    }

    ret = sss_packet_grow(packet, sz_name->len + 3 * sizeof(uint32_t));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_packet_grow failed.\n");
        talloc_free(sz_name);
        return ret;
    }

    sss_packet_get_body(packet, &body, &body_len);

    SAFEALIGN_SET_UINT32(&body[rp], 1, &rp); /* Num results. */
    SAFEALIGN_SET_UINT32(&body[rp], 0, &rp); /* Reserved. */
    SAFEALIGN_SET_UINT32(&body[rp], id_type, &rp);
    SAFEALIGN_SET_STRING(&body[rp], sz_name->str, sz_name->len, &rp);

    talloc_free(sz_name);

    return EOK;
}

errno_t
sss_nss_protocol_fill_id(struct sss_nss_ctx *nss_ctx,
                         struct sss_nss_cmd_ctx *cmd_ctx,
                         struct sss_packet *packet,
                         struct cache_req_result *result)
{
    struct ldb_message *msg = result->msgs[0];
    enum sss_id_type id_type;
    uint64_t id64;
    uint32_t id;
    const char *sid = NULL;
    struct sized_string sid_key;
    size_t rp = 0;
    size_t body_len;
    uint8_t *body;
    errno_t ret;

    if (result->ldb_result == NULL) {
        /* This was a well known SID. This is currently unsupported with id. */
        return EINVAL;
    }

    ret = sss_nss_get_id_type(cmd_ctx, result, &id_type);
    if (ret != EOK) {
        return ret;
    }

    if (id_type == SSS_ID_TYPE_GID) {
        id64 = ldb_msg_find_attr_as_uint64(msg, SYSDB_GIDNUM, 0);
    } else {
        id64 = ldb_msg_find_attr_as_uint64(msg, SYSDB_UIDNUM, 0);
    }

    if (id64 == 0 || id64 >= UINT32_MAX) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid POSIX ID.\n");
        return EINVAL;
    }

    id = (uint32_t)id64;

    ret = sss_packet_grow(packet, 4 * sizeof(uint32_t));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_packet_grow failed.\n");
        return ret;
    }

    sss_packet_get_body(packet, &body, &body_len);

    SAFEALIGN_SET_UINT32(&body[rp], 1, &rp); /* Num results. */
    SAFEALIGN_SET_UINT32(&body[rp], 0, &rp); /* Reserved. */
    SAFEALIGN_SET_UINT32(&body[rp], id_type, &rp);
    SAFEALIGN_SET_UINT32(&body[rp], id, &rp);

    if (nss_ctx->sid_mc_ctx != NULL) {
        /* no need to check for SSS_NSS_EX_FLAG_INVALIDATE_CACHE since
         * SID related requests don't support 'flags'
         */
        sid = ldb_msg_find_attr_as_string(msg, SYSDB_SID_STR, NULL);
        if (!sid) {
            DEBUG(SSSDBG_OP_FAILURE, "Missing SID?!\n");
            return EOK;
        }
        to_sized_string(&sid_key, sid);
        ret = sss_mmap_cache_sid_store(&nss_ctx->sid_mc_ctx, &sid_key, id, id_type,
                                       cmd_ctx->type != CACHE_REQ_OBJECT_BY_ID);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to store SID='%s' / ID=%d in mmap cache [%d]: %s!\n",
                  sid, id, ret, sss_strerror(ret));
        }
    }

    return EOK;
}

errno_t
sss_nss_protocol_fill_name_list_all_domains(struct sss_nss_ctx *nss_ctx,
                                            struct sss_nss_cmd_ctx *cmd_ctx,
                                            struct sss_packet *packet,
                                            struct cache_req_result **results)
{
    enum sss_id_type *id_types;
    size_t rp = 0;
    size_t body_len;
    uint8_t *body;
    errno_t ret;
    struct sized_string *sz_names;
    size_t len;
    size_t c;
    const char *tmp_str;
    size_t d;
    size_t total = 0;
    size_t iter = 0;

    if (results == NULL) {
        return EINVAL;
    }

    for (d = 0; results[d] != NULL; d++) {
        total += results[d]->count;
    }

    sz_names = talloc_array(cmd_ctx, struct sized_string, total);
    if (sz_names == NULL) {
        return ENOMEM;
    }

    id_types = talloc_array(cmd_ctx, enum sss_id_type, total);
    if (id_types == NULL) {
        return ENOMEM;
    }

    len = 0;
    for (d = 0; results[d] != NULL; d++) {
        for (c = 0; c < results[d]->count; c++) {
            ret = sss_nss_get_id_type(cmd_ctx, results[d], &(id_types[iter]));
            if (ret != EOK) {
                return ret;
            }

            tmp_str = sss_get_name_from_msg(results[d]->domain,
                                            results[d]->msgs[c]);
            if (tmp_str == NULL) {
                return EINVAL;
            }
            to_sized_string(&(sz_names[iter]), tmp_str);

            len += sz_names[iter].len;
            iter++;
        }
    }

    len += (2 + total) * sizeof(uint32_t);

    ret = sss_packet_grow(packet, len);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_packet_grow failed.\n");
        return ret;
    }

    sss_packet_get_body(packet, &body, &body_len);

    SAFEALIGN_SET_UINT32(&body[rp], total, &rp); /* Num results. */
    SAFEALIGN_SET_UINT32(&body[rp], 0, &rp); /* Reserved. */
    for (c = 0; c < total; c++) {
        SAFEALIGN_SET_UINT32(&body[rp], id_types[c], &rp);
        SAFEALIGN_SET_STRING(&body[rp], sz_names[c].str, sz_names[c].len,
                             &rp);
    }

    return EOK;
}
