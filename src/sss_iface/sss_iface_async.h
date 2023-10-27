/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2018 Red Hat

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

#ifndef _SSS_IFACE_ASYNC_H_
#define _SSS_IFACE_ASYNC_H_

#include <tevent.h>
#include <time.h>

#include "sss_iface/sbus_sss_server.h"
#include "sss_iface/sbus_sss_client_async.h"
#include "sss_iface/sss_iface.h"

/**
 * Connect to the SSSD private D-Bus server.
 */
errno_t
sss_sbus_connect(TALLOC_CTX *mem_ctx,
                 struct tevent_context *ev,
                 const char *conn_name,
                 time_t *last_request_time,
                 struct sbus_connection **_conn);

enum mt_svc_type {
    MT_SVC_SERVICE,
    MT_SVC_PROVIDER
};

errno_t
sss_monitor_register_service(TALLOC_CTX *mem_ctx,
                             struct sbus_connection *conn,
                             const char *svc_name,
                             uint16_t svc_version,
                             uint16_t svc_type);

#endif /* _SSS_IFACE_ASYNC_H_ */
