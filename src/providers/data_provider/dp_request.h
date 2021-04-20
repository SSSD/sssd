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

#ifndef _DP_REQUEST_H_
#define _DP_REQUEST_H_

#include <talloc.h>

#include "providers/data_provider/dp.h"

struct data_provider;
enum dp_targets;
enum dp_methods;

struct tevent_req *dp_req_send(TALLOC_CTX *mem_ctx,
                               struct data_provider *provider,
                               const char *domain,
                               const char *name,
                               uint32_t cli_id,
                               const char *sender_name,
                               enum dp_targets target,
                               enum dp_methods method,
                               uint32_t dp_flags,
                               void *request_data,
                               const char **_request_name);

errno_t _dp_req_recv(TALLOC_CTX *mem_ctx,
                     struct tevent_req *req,
                     const char *data_type,
                     void **_data);

/**
 * Returns value of output data.
 *
 * @example
 *     struct dp_reply_std reply;
 *     ret = dp_req_recv(mem_ctx, req, struct dp_reply_std, &reply);
 */
#define dp_req_recv(mem_ctx, req, data_type, _data)                        \
({                                                                         \
    data_type *__value = NULL;                                             \
    errno_t __ret;                                                         \
    __ret = _dp_req_recv(mem_ctx, req, #data_type, (void**)&__value);      \
    if (__ret == EOK) {                                                    \
        *(_data) = *__value;                                               \
    }                                                                      \
    __ret;                                                                 \
})

/**
 * Returns pointer to output data type.
 *
 * @example
 *     struct dp_reply_std *reply;
 *     ret = dp_req_recv_ptr(mem_ctx, req, struct dp_reply_std, &reply);
 */
#define dp_req_recv_ptr(mem_ctx, req, data_type, _data) \
    _dp_req_recv(mem_ctx, req, #data_type, (void**)_data)

/**
 * Recieves data provider request errno code when no output data is set.
 *
 * @example
 *     ret = dp_req_recv_no_output(req);
 */
#define dp_req_recv_no_output(req) \
    _dp_req_recv(req, req, "dp_no_output", NULL)

#endif /* _DP_REQUEST_H_ */
