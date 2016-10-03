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

#include <talloc.h>

#include "responder/common/cache_req/cache_req_private.h"

static struct cache_req_data *
cache_req_data_create(TALLOC_CTX *mem_ctx,
                      enum cache_req_type type,
                      struct cache_req_data *input)
{
    struct cache_req_data *data;
    errno_t ret;

    data = talloc_zero(mem_ctx, struct cache_req_data);
    if (data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero() failed\n");
        return NULL;
    }

    data->type = type;

    switch (type) {
    case CACHE_REQ_USER_BY_NAME:
    case CACHE_REQ_USER_BY_UPN:
    case CACHE_REQ_GROUP_BY_NAME:
    case CACHE_REQ_USER_BY_FILTER:
    case CACHE_REQ_GROUP_BY_FILTER:
    case CACHE_REQ_INITGROUPS:
    case CACHE_REQ_INITGROUPS_BY_UPN:
        if (input->name.input == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Bug: name cannot be NULL!\n");
            ret = ERR_INTERNAL;
            goto done;
        }

        data->name.input = talloc_strdup(data, input->name.input);
        if (data->name.input == NULL) {
            ret = ENOMEM;
            goto done;
        }
        break;
    case CACHE_REQ_USER_BY_CERT:
        if (input->cert == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Bug: certificate cannot be NULL!\n");
            ret = ERR_INTERNAL;
            goto done;
        }

        data->cert = talloc_strdup(data, input->cert);
        if (data->cert == NULL) {
            ret = ENOMEM;
            goto done;
        }
        break;
    case CACHE_REQ_USER_BY_ID:
    case CACHE_REQ_GROUP_BY_ID:
        if (input->id == 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Bug: id cannot be 0!\n");
            ret = ERR_INTERNAL;
            goto done;
        }

        data->id = input->id;
        break;
    case CACHE_REQ_OBJECT_BY_SID:
        if (input->sid == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Bug: SID cannot be NULL!\n");
            ret = ERR_INTERNAL;
            goto done;
        }

        data->sid = talloc_strdup(data, input->sid);
        if (data->sid == NULL) {
            ret = ENOMEM;
            goto done;
        }
        break;
    case CACHE_REQ_SENTINEL:
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid cache request type!\n");
        ret = ERR_INTERNAL;
        goto done;
    }

    if (input->attrs != NULL) {
        data->attrs = dup_string_list(data, input->attrs);
        if (data->attrs == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_zfree(data);
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create cache_req data "
              "[%d]: %s\n", ret, sss_strerror(ret));
        return NULL;
    }

    return data;
}

struct cache_req_data *
cache_req_data_name(TALLOC_CTX *mem_ctx,
                    enum cache_req_type type,
                    const char *name)
{
    struct cache_req_data input = {0};

    input.name.input = name;

    return cache_req_data_create(mem_ctx, type, &input);
}

struct cache_req_data *
cache_req_data_id(TALLOC_CTX *mem_ctx,
                  enum cache_req_type type,
                  uint32_t id)
{
    struct cache_req_data input = {0};

    input.id = id;

    return cache_req_data_create(mem_ctx, type, &input);
}

struct cache_req_data *
cache_req_data_cert(TALLOC_CTX *mem_ctx,
                    enum cache_req_type type,
                    const char *cert)
{
    struct cache_req_data input = {0};

    input.cert = cert;

    return cache_req_data_create(mem_ctx, type, &input);
}

struct cache_req_data *
cache_req_data_sid(TALLOC_CTX *mem_ctx,
                   enum cache_req_type type,
                   const char *sid,
                   const char **attrs)
{
    struct cache_req_data input = {0};

    input.sid = sid;
    input.attrs = attrs;

    return cache_req_data_create(mem_ctx, type, &input);
}
