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

#include "db/sysdb.h"
#include "responder/common/cache_req/cache_req_private.h"

static const char **
cache_req_data_create_attrs(TALLOC_CTX *mem_ctx,
                            const char **requested)
{
    static const char *defattrs[] = { SYSDB_DEFAULT_ATTRS, SYSDB_NAME,
                                      OVERRIDE_PREFIX SYSDB_NAME,
                                      SYSDB_DEFAULT_OVERRIDE_NAME };
    static size_t defnum = sizeof(defattrs) / sizeof(defattrs[0]);
    const char **attrs;
    size_t reqnum;
    size_t total;
    size_t i;

    for (reqnum = 0; requested[reqnum] != NULL; reqnum++);

    total = defnum + reqnum;

    /* We always want to get default attributes. */
    attrs = talloc_zero_array(mem_ctx, const char *, total + 1);
    if (attrs == NULL) {
        return NULL;
    }

    for (i = 0; i < reqnum; i++) {
        attrs[i] = talloc_strdup(attrs, requested[i]);
        if (attrs[i] == NULL) {
            talloc_free(attrs);
            return NULL;
        }
    }

    for (/* continue */; i < total; i++) {
        attrs[i] = talloc_strdup(attrs, defattrs[i - reqnum]);
        if (attrs[i] == NULL) {
            talloc_free(attrs);
            return NULL;
        }
    }

    return attrs;
}

static struct cache_req_data *
cache_req_data_create(TALLOC_CTX *mem_ctx,
                      enum cache_req_type type,
                      const struct cache_req_data *input)
{
    struct cache_req_data *data;
    errno_t ret;

    data = talloc_zero(mem_ctx, struct cache_req_data);
    if (data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero() failed\n");
        return NULL;
    }

    data->type = type;
    data->svc.name = &data->name;

    switch (type) {
    case CACHE_REQ_USER_BY_FILTER:
        if (input->name.attr == NULL) {
            data->name.attr = NULL;
        } else {
            data->name.attr = talloc_strdup(data, input->name.attr);
            if (data->name.attr == NULL) {
                ret = ENOMEM;
                goto done;
            }
        }
        /* Fallthrough */
    case CACHE_REQ_USER_BY_NAME:
    case CACHE_REQ_USER_BY_UPN:
    case CACHE_REQ_GROUP_BY_NAME:
    case CACHE_REQ_GROUP_BY_FILTER:
    case CACHE_REQ_INITGROUPS:
    case CACHE_REQ_INITGROUPS_BY_UPN:
#ifdef BUILD_SUBID
    case CACHE_REQ_SUBID_RANGES_BY_NAME:
#endif
    case CACHE_REQ_NETGROUP_BY_NAME:
    case CACHE_REQ_OBJECT_BY_NAME:
    case CACHE_REQ_AUTOFS_MAP_ENTRIES:
    case CACHE_REQ_AUTOFS_MAP_BY_NAME:
    case CACHE_REQ_IP_HOST_BY_NAME:
    case CACHE_REQ_IP_NETWORK_BY_NAME:
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
    case CACHE_REQ_IP_HOST_BY_ADDR:
    case CACHE_REQ_IP_NETWORK_BY_ADDR:
        data->addr.af = input->addr.af;
        data->addr.len = input->addr.len;
        data->addr.data = talloc_memdup(data, input->addr.data,
                                        input->addr.len);
        if (data->addr.data == NULL) {
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
    case CACHE_REQ_OBJECT_BY_ID:
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
    case CACHE_REQ_ENUM_USERS:
    case CACHE_REQ_ENUM_GROUPS:
    case CACHE_REQ_ENUM_SVC:
    case CACHE_REQ_ENUM_HOST:
    case CACHE_REQ_ENUM_IP_NETWORK:
        break;
    case CACHE_REQ_SVC_BY_NAME:
        if ((input->svc.name == NULL) || (input->svc.name->input == NULL)) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Bug: name cannot be NULL!\n");
            ret = ERR_INTERNAL;
            goto done;
        }

        data->svc.name->input = talloc_strdup(data, input->svc.name->input);
        if (data->svc.name->input == NULL) {
            ret = ENOMEM;
            goto done;
        }

        if (input->svc.protocol.name == NULL) {
            break;
        }

        data->svc.protocol.name = talloc_strdup(data, input->svc.protocol.name);
        if (data->svc.protocol.name == NULL) {
            ret = ENOMEM;
            goto done;
        }

        break;
    case CACHE_REQ_SVC_BY_PORT:
        if (input->svc.port == 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Bug: port cannot be 0!\n");
            ret = ERR_INTERNAL;
            goto done;
        }

        data->svc.port = input->svc.port;

        if (input->svc.protocol.name == NULL) {
            break;
        }

        data->svc.protocol.name = talloc_strdup(data, input->svc.protocol.name);
        if (data->svc.protocol.name == NULL) {
            ret = ENOMEM;
            goto done;
        }

        break;
    case CACHE_REQ_SSH_HOST_ID_BY_NAME:
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

        if (input->alias == NULL) {
            break;
        }

        data->alias = talloc_strdup(data, input->alias);
        if (data->alias == NULL) {
            ret = ENOMEM;
            goto done;
        }
        break;
    case CACHE_REQ_AUTOFS_ENTRY_BY_NAME:
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

        data->autofs_entry_name = talloc_strdup(data, input->autofs_entry_name);
        if (data->autofs_entry_name == NULL) {
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
        data->attrs = cache_req_data_create_attrs(data, input->attrs);
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
cache_req_data_name_attrs(TALLOC_CTX *mem_ctx,
                          enum cache_req_type type,
                          const char *name,
                          const char **attrs)
{
    struct cache_req_data input = { 0 };

    input.name.input = name;
    input.attrs = attrs;

    return cache_req_data_create(mem_ctx, type, &input);
}

struct cache_req_data *
cache_req_data_attr(TALLOC_CTX *mem_ctx,
                    enum cache_req_type type,
                    const char *attr,
                    const char *filter)
{
    struct cache_req_data input = {0};

    input.name.input = filter;
    input.name.attr = attr;

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
cache_req_data_id_attrs(TALLOC_CTX *mem_ctx,
                        enum cache_req_type type,
                        uint32_t id,
                        const char **attrs)
{
    struct cache_req_data input = { 0 };

    input.id = id;
    input.attrs = attrs;

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

struct cache_req_data *
cache_req_data_enum(TALLOC_CTX *mem_ctx,
                    enum cache_req_type type)
{
    struct cache_req_data input = { 0 };

    return cache_req_data_create(mem_ctx, type, &input);
}

struct cache_req_data *
cache_req_data_svc(TALLOC_CTX *mem_ctx,
                   enum cache_req_type type,
                   const char *name,
                   const char *protocol,
                   uint16_t port)
{
    struct cache_req_data input = { 0 };

    input.name.input = name;
    input.svc.name = &input.name;
    input.svc.protocol.name = protocol;
    input.svc.port = port;

    return cache_req_data_create(mem_ctx, type, &input);
}

struct cache_req_data *
cache_req_data_ssh_host_id(TALLOC_CTX *mem_ctx,
                           enum cache_req_type type,
                           const char *name,
                           const char *alias,
                           const char **attrs)
{
    struct cache_req_data input = {0};

    input.name.input = name;
    input.alias = alias;
    input.attrs = attrs;

    return cache_req_data_create(mem_ctx, type, &input);
}

struct cache_req_data *
cache_req_data_addr(TALLOC_CTX *mem_ctx,
                    enum cache_req_type type,
                    uint32_t af,
                    uint32_t addrlen,
                    uint8_t *addr)
{
    struct cache_req_data input = {0};

    input.addr.af = af;
    input.addr.len = addrlen;
    input.addr.data = addr;

    return cache_req_data_create(mem_ctx, type, &input);
}

struct cache_req_data *
cache_req_data_autofs_entry(TALLOC_CTX *mem_ctx,
                            enum cache_req_type type,
                            const char *mapname,
                            const char *entryname)
{
    struct cache_req_data input = {0};

    input.name.input = mapname;
    input.autofs_entry_name = entryname;

    return cache_req_data_create(mem_ctx, type, &input);
}

void
cache_req_data_set_bypass_cache(struct cache_req_data *data,
                                bool bypass_cache)
{
    if (data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "cache_req_data should never be NULL\n");
        return;
    }

    data->bypass_cache = bypass_cache;
}

void
cache_req_data_set_bypass_dp(struct cache_req_data *data,
                             bool bypass_dp)
{
    if (data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "cache_req_data should never be NULL\n");
        return;
    }

    data->bypass_dp = bypass_dp;
}

void
cache_req_data_set_requested_domains(struct cache_req_data *data,
                                     char **requested_domains)
{
    if (data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "cache_req_data should never be NULL\n");
        return;
    }

    data->requested_domains = requested_domains;
}

void
cache_req_data_set_propogate_offline_status(struct cache_req_data *data,
                                            bool propogate_offline_status)
{
    if (data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "cache_req_data should never be NULL\n");
        return;
    }

    data->propogate_offline_status = propogate_offline_status;
}

void
cache_req_data_set_hybrid_lookup(struct cache_req_data *data,
                                 bool hybrid_lookup)
{
    if (data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "cache_req_data should never be NULL\n");
        return;
    }

    data->hybrid_lookup = hybrid_lookup;
}


enum cache_req_type
cache_req_data_get_type(struct cache_req_data *data)
{
    if (data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "cache_req_data should never be NULL\n");
        return CACHE_REQ_SENTINEL;
    }

    return data->type;
}
