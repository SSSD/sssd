/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2013 Red Hat

    InfoPipe responder: Utility functions

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

#include <sys/param.h>

#include "db/sysdb.h"
#include "responder/ifp/ifp_private.h"

#define IFP_USER_DEFAULT_ATTRS {SYSDB_NAME, SYSDB_UIDNUM,   \
                                SYSDB_GIDNUM, SYSDB_GECOS,  \
                                SYSDB_HOMEDIR, SYSDB_SHELL, \
                                "groups", "domain", "domainname", \
                                NULL}

errno_t ifp_req_create(struct sbus_request *dbus_req,
                       struct ifp_ctx *ifp_ctx,
                       struct ifp_req **_ifp_req)
{
    struct ifp_req *ireq = NULL;
    errno_t ret;

    if (ifp_ctx->sysbus == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Responder not connected to sysbus!\n");
        return EINVAL;
    }

    ireq = talloc_zero(dbus_req, struct ifp_req);
    if (ireq == NULL) {
        return ENOMEM;
    }

    ireq->ifp_ctx = ifp_ctx;
    ireq->dbus_req = dbus_req;

    if (dbus_req->client == -1) {
        /* We got a sysbus message but couldn't identify the
         * caller? Bail out! */
        DEBUG(SSSDBG_CRIT_FAILURE,
              "BUG: Received a message without a known caller!\n");
        ret = EACCES;
        goto done;
    }

    ret = check_allowed_uids(dbus_req->client,
                             ifp_ctx->rctx->allowed_uids_count,
                             ifp_ctx->rctx->allowed_uids);
    if (ret == EACCES) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "User %"PRIi64" not in ACL\n", dbus_req->client);
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot check if user %"PRIi64" is present in ACL\n",
              dbus_req->client);
        goto done;
    }

    *_ifp_req = ireq;
    ret = EOK;
done:
    if (ret != EOK) {
        talloc_free(ireq);
    }
    return ret;
}

int ifp_req_create_handle_failure(struct sbus_request *dbus_req, errno_t err)
{
    if (err == EACCES) {
        return sbus_request_fail_and_finish(dbus_req,
                               sbus_error_new(dbus_req,
                                              DBUS_ERROR_ACCESS_DENIED,
                                              "User %"PRIi64" not in ACL\n",
                                              dbus_req->client));
    }

    return sbus_request_fail_and_finish(dbus_req,
                                        sbus_error_new(dbus_req,
                                            DBUS_ERROR_FAILED,
                                            "Cannot create IFP request\n"));
}

errno_t ifp_add_value_to_dict(DBusMessageIter *iter_dict,
                              const char *key,
                              const char *value)
{
    DBusMessageIter iter_dict_entry;
    DBusMessageIter iter_dict_val;
    DBusMessageIter iter_array;
    dbus_bool_t dbret;

    if (value == NULL || key == NULL) {
        return EINVAL;
    }

    dbret = dbus_message_iter_open_container(iter_dict,
                                             DBUS_TYPE_DICT_ENTRY, NULL,
                                             &iter_dict_entry);
    if (!dbret) {
        return ENOMEM;
    }

    /* Start by appending the key */
    dbret = dbus_message_iter_append_basic(&iter_dict_entry,
                                           DBUS_TYPE_STRING, &key);
    if (!dbret) {
        return ENOMEM;
    }

    dbret = dbus_message_iter_open_container(&iter_dict_entry,
                                             DBUS_TYPE_VARIANT,
                                             DBUS_TYPE_ARRAY_AS_STRING
                                             DBUS_TYPE_STRING_AS_STRING,
                                             &iter_dict_val);
    if (!dbret) {
        return ENOMEM;
    }

    /* Open container for values */
    dbret = dbus_message_iter_open_container(&iter_dict_val,
                                 DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING,
                                 &iter_array);
    if (!dbret) {
        return ENOMEM;
    }

    dbret = dbus_message_iter_append_basic(&iter_array,
                                           DBUS_TYPE_STRING,
                                           &value);
    if (!dbret) {
        return ENOMEM;
    }

    dbret = dbus_message_iter_close_container(&iter_dict_val,
                                              &iter_array);
    if (!dbret) {
        return ENOMEM;
    }

    dbret = dbus_message_iter_close_container(&iter_dict_entry,
                                              &iter_dict_val);
    if (!dbret) {
        return ENOMEM;
    }

    dbret = dbus_message_iter_close_container(iter_dict,
                                              &iter_dict_entry);
    if (!dbret) {
        return ENOMEM;
    }

    return EOK;
}

errno_t ifp_add_ldb_el_to_dict(DBusMessageIter *iter_dict,
                               struct ldb_message_element *el)
{
    DBusMessageIter iter_dict_entry;
    DBusMessageIter iter_dict_val;
    DBusMessageIter iter_array;
    dbus_bool_t dbret;
    unsigned int i;

    if (el == NULL) {
        return EINVAL;
    }

    dbret = dbus_message_iter_open_container(iter_dict,
                                             DBUS_TYPE_DICT_ENTRY, NULL,
                                             &iter_dict_entry);
    if (!dbret) {
        return ENOMEM;
    }

    /* Start by appending the key */
    dbret = dbus_message_iter_append_basic(&iter_dict_entry,
                                           DBUS_TYPE_STRING, &(el->name));
    if (!dbret) {
        return ENOMEM;
    }

    dbret = dbus_message_iter_open_container(&iter_dict_entry,
                                             DBUS_TYPE_VARIANT,
                                             DBUS_TYPE_ARRAY_AS_STRING
                                             DBUS_TYPE_STRING_AS_STRING,
                                             &iter_dict_val);
    if (!dbret) {
        return ENOMEM;
    }

    /* Open container for values */
    dbret = dbus_message_iter_open_container(&iter_dict_val,
                                 DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING,
                                 &iter_array);
    if (!dbret) {
        return ENOMEM;
    }

    /* Now add all the values */
    for (i = 0; i < el->num_values; i++) {
        DEBUG(SSSDBG_TRACE_FUNC, "element [%s] has value [%s]\n",
              el->name, (const char *) el->values[i].data);

        dbret = dbus_message_iter_append_basic(&iter_array,
                                               DBUS_TYPE_STRING,
                                               &(el->values[i].data));
        if (!dbret) {
            return ENOMEM;
        }
    }

    dbret = dbus_message_iter_close_container(&iter_dict_val,
                                              &iter_array);
    if (!dbret) {
        return ENOMEM;
    }

    dbret = dbus_message_iter_close_container(&iter_dict_entry,
                                              &iter_dict_val);
    if (!dbret) {
        return ENOMEM;
    }

    dbret = dbus_message_iter_close_container(iter_dict,
                                              &iter_dict_entry);
    if (!dbret) {
        return ENOMEM;
    }

    return EOK;
}


bool
ifp_attr_allowed(const char *whitelist[], const char *attr)
{
    size_t i;

    if (whitelist == NULL) {
        return false;
    }

    for (i = 0; whitelist[i]; i++) {
        if (strcasecmp(whitelist[i], attr) == 0) {
            break;
        }
    }

    return (whitelist[i]) ? true : false;
}

const char **
ifp_parse_user_attr_list(TALLOC_CTX *mem_ctx, const char *csv)
{
    static const char *defaults[] = IFP_USER_DEFAULT_ATTRS;

    return parse_attr_list_ex(mem_ctx, csv, defaults);
}

const char **
ifp_get_user_extra_attributes(TALLOC_CTX *mem_ctx, struct ifp_ctx *ifp_ctx)
{
    TALLOC_CTX *tmp_ctx = NULL;
    const char *std[] = IFP_USER_DEFAULT_ATTRS;
    const char **whitelist = ifp_ctx->user_whitelist;
    const char **extra;
    bool found;
    int extra_num;
    int i, j;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return NULL;
    }

    for (i = 0; whitelist[i] != NULL; i++) {
        /* Just count number of attributes in whitelist. */
    }

    extra = talloc_zero_array(tmp_ctx, const char *, i + 1);
    if (extra == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero_array() failed\n");
        goto fail;
    }

    extra_num = 0;
    for (i = 0; whitelist[i] != NULL; i++) {
        found = false;
        for (j = 0; std[j] != NULL; j++) {
            if (strcmp(whitelist[i], std[j]) == 0) {
                found = true;
                break;
            }
        }

        if (!found) {
            extra[extra_num] = talloc_strdup(extra, whitelist[i]);
            if (extra[extra_num] == NULL) {
                goto fail;
            }

            extra_num++;
        }
    }

    extra = talloc_realloc(tmp_ctx, extra, const char *, extra_num + 1);
    if (extra == NULL) {
        goto fail;
    }

    talloc_steal(mem_ctx, extra);
    talloc_free(tmp_ctx);
    return extra;

fail:
    talloc_free(tmp_ctx);
    return NULL;
}

bool
ifp_is_user_attr_allowed(struct ifp_ctx *ifp_ctx, const char *attr)
{
    return ifp_attr_allowed(ifp_ctx->user_whitelist, attr);
}

static uint32_t ifp_list_limit(struct ifp_ctx *ctx, uint32_t limit)
{
    if (limit == 0) {
        return ctx->wildcard_limit;
    } else if (ctx->wildcard_limit) {
        return MIN(ctx->wildcard_limit, limit);
    } else {
        return limit;
    }
}

struct ifp_list_ctx *ifp_list_ctx_new(struct sbus_request *sbus_req,
                                      struct ifp_ctx *ctx,
                                      const char *filter,
                                      uint32_t limit)
{
    struct ifp_list_ctx *list_ctx;

    list_ctx = talloc_zero(sbus_req, struct ifp_list_ctx);
    if (list_ctx == NULL) {
        return NULL;
    }

    list_ctx->sbus_req = sbus_req;
    list_ctx->limit = ifp_list_limit(ctx, limit);
    list_ctx->ctx = ctx;
    list_ctx->dom = ctx->rctx->domains;
    list_ctx->filter = filter;
    list_ctx->paths = talloc_zero_array(list_ctx, const char *, limit);
    if (list_ctx->paths == NULL) {
        talloc_free(list_ctx);
        return NULL;
    }

    return list_ctx;
}

size_t ifp_list_ctx_remaining_capacity(struct ifp_list_ctx *list_ctx,
                                       size_t entries)
{
    size_t capacity = list_ctx->limit - list_ctx->path_count;

    if (capacity < entries) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "IFP list request has limit of %"PRIu32" entries but back end "
              "returned %zu entries\n", list_ctx->limit, entries);
        return capacity;
    } else {
        return entries;
    }
}

errno_t ifp_ldb_el_output_name(struct resp_ctx *rctx,
                               struct ldb_message *msg,
                               const char *el_name,
                               struct sss_domain_info *dom)
{
    struct ldb_message_element *el;
    char *in_name;
    char *out_name;
    errno_t ret;
    char *name;
    TALLOC_CTX *tmp_ctx;

    el = ldb_msg_find_element(msg, el_name);
    if (el == NULL) {
        return EOK;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    for (size_t c = 0; c < el->num_values; c++) {
        in_name = (char *) el->values[c].data;
        ret = sss_parse_internal_fqname(tmp_ctx, in_name, &name, NULL);
        if (ret != EOK) {
            goto done;
        }

        out_name = sss_output_name(tmp_ctx, in_name, dom->case_preserve,
                                   rctx->override_space);
        if (out_name == NULL) {
            ret = EIO;
            goto done;
        }

        if (dom->fqnames) {
            out_name = sss_tc_fqname(tmp_ctx, dom->names, dom, out_name);
            if (out_name == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "sss_tc_fqname failed\n");
                ret = ENOMEM;
                goto done;
            }
        }

        talloc_free(el->values[c].data);
        el->values[c].data = (uint8_t *) talloc_steal(el->values, out_name);
        el->values[c].length = strlen(out_name);
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

char *ifp_format_name_attr(TALLOC_CTX *mem_ctx, struct ifp_ctx *ifp_ctx,
                           const char *in_name, struct sss_domain_info *dom)
{
    TALLOC_CTX *tmp_ctx;
    char *out_name;
    char *ret_name = NULL;
    char *shortname;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return NULL;
    }

    ret = sss_parse_internal_fqname(tmp_ctx, in_name, &shortname, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unparseable name %s\n", in_name);
        goto done;
    }

    out_name = sss_output_name(tmp_ctx, in_name, dom->case_preserve,
                               ifp_ctx->rctx->override_space);
    if (out_name == NULL) {
        goto done;
    }

    if (dom->fqnames) {
        out_name = sss_tc_fqname(tmp_ctx, dom->names, dom, out_name);
        if (out_name == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sss_tc_fqname failed\n");
            goto done;
        }
    }

    ret_name = talloc_steal(mem_ctx, out_name);
done:
    talloc_free(tmp_ctx);
    return ret_name;
}
