/*
    Authors:
        Pavel B??ezina <pbrezina@redhat.com>

    Copyright (C) 2013 Red Hat

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

#ifndef __FAIL_OVER_SRV_H__
#define __FAIL_OVER_SRV_H__

#include <talloc.h>
#include <tevent.h>

#include "resolv/async_resolv.h"

/* SRV lookup plugin interface */

struct fo_server_info {
    char *host;
    int port;
};

/*
 * If discovery_domain is NULL, it should be detected automatically.
 */
typedef struct tevent_req *
(*fo_srv_lookup_plugin_send_t)(TALLOC_CTX *mem_ctx,
                               struct tevent_context *ev,
                               const char *service,
                               const char *protocol,
                               const char *discovery_domain,
                               void *pvt);

/*
 * Returns:
 *   EOK - at least one primary or backup server was found
 *   ERR_SRV_NOT_FOUND - no primary nor backup server found
 *   ERR_SRV_LOOKUP_ERROR - error communicating with SRV database
 *   other code - depends on plugin
 *
 * If EOK is returned:
 * - and no primary server is found:
 *   *_primary_servers = NULL
 *   *_num_primary_servers = 0
 * - and no backup server is found:
 *   *_backup_servers = NULL
 *   *_num_backup_servers = 0
 * - *_dns_domain = DNS domain name where the servers were found
 */
typedef errno_t
(*fo_srv_lookup_plugin_recv_t)(TALLOC_CTX *mem_ctx,
                               struct tevent_req *req,
                               char **_dns_domain,
                               struct fo_server_info **_primary_servers,
                               size_t *_num_primary_servers,
                               struct fo_server_info **_backup_servers,
                               size_t *_num_backup_servers);

#endif /* __FAIL_OVER_SRV_H__ */
