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

#ifndef _RDP_H_
#define _RDP_H_

#include "responder/common/responder.h"
#include "providers/data_provider/dp_iface_generated.h"
#include "providers/data_provider/dp_iface.h"
#include "sbus/sssd_dbus.h"
#include "util/util.h"

struct be_conn;
struct resp_ctx;

struct tevent_req *_rdp_message_send(TALLOC_CTX *mem_ctx,
                                     struct resp_ctx *rctx,
                                     struct sss_domain_info *domain,
                                     const char *path,
                                     const char *iface,
                                     const char *method,
                                     int first_arg_type,
                                     ...);

#define rdp_message_send(mem_ctx, rctx, domain, path, iface,               \
                         method, ...)                                      \
    _rdp_message_send(mem_ctx, rctx, domain, path, iface, method,          \
                      ##__VA_ARGS__, DBUS_TYPE_INVALID)

/* D-Bus reply message is freed with tevent request. Since all output data
 * point inside D-Bus reply do not call talloc_free(req) unless
 * you are not accessing the data any longer. */
errno_t _rdp_message_recv(struct tevent_req *req,
                          int first_arg_type,
                          ...);

#define rdp_message_recv(req, ...)                                         \
    _rdp_message_recv(req, ##__VA_ARGS__, DBUS_TYPE_INVALID)

/**
 * Send D-Bus message to Data Provider but instead of returning the reply
 * to the caller it forwards the reply to the client request. No further
 * processing is required by the caller. In case of a failure the client
 * request is freed since there is nothing we can do.
 */
void _rdp_message_send_and_reply(struct sbus_request *sbus_req,
                                 struct resp_ctx *rctx,
                                 struct sss_domain_info *domain,
                                 const char *path,
                                 const char *iface,
                                 const char *method,
                                 int first_arg_type,
                                 ...);

#define rdp_message_send_and_reply(sbus_req, rctx, domain, path, iface,       \
                                   method, ...)                               \
    _rdp_message_send_and_reply(sbus_req, rctx, domain, path, iface, method,  \
                                ##__VA_ARGS__, DBUS_TYPE_INVALID)

errno_t rdp_register_client(struct be_conn *be_conn,
                            const char *client_name);

#endif /* _RDP_CALLS_H_ */
