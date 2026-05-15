/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

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
    unsigned short priority;
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
                               uint32_t *_ttl,
                               struct fo_server_info **_primary_servers,
                               size_t *_num_primary_servers,
                               struct fo_server_info **_backup_servers,
                               size_t *_num_backup_servers);

struct tevent_req *fo_discover_srv_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        struct resolv_ctx *resolv_ctx,
                                        const char *service,
                                        const char *protocol,
                                        const char **discovery_domains);

errno_t fo_discover_srv_recv(TALLOC_CTX *mem_ctx,
                             struct tevent_req *req,
                             char **_dns_domain,
                             uint32_t *_ttl,
                             struct fo_server_info **_servers,
                             size_t *_num_servers);

struct tevent_req *fo_discover_servers_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct resolv_ctx *resolv_ctx,
                                            const char *service,
                                            const char *protocol,
                                            const char *primary_domain,
                                            const char *backup_domain);

errno_t fo_discover_servers_recv(TALLOC_CTX *mem_ctx,
                                 struct tevent_req *req,
                                 char **_dns_domain,
                                 uint32_t *_ttl,
                                 struct fo_server_info **_primary_servers,
                                 size_t *_num_primary_servers,
                                 struct fo_server_info **_backup_servers,
                                 size_t *_num_backup_servers);

/* Simple SRV lookup plugin */

struct fo_resolve_srv_dns_ctx;

struct fo_resolve_srv_dns_ctx *
fo_resolve_srv_dns_ctx_init(TALLOC_CTX *mem_ctx,
                            struct resolv_ctx *resolv_ctx,
                            enum restrict_family family_order,
                            enum host_database *host_dbs,
                            const char *hostname,
                            const char *sssd_domain);

struct tevent_req *fo_resolve_srv_dns_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           const char *service,
                                           const char *protocol,
                                           const char *discovery_domain,
                                           void *pvt);

errno_t fo_resolve_srv_dns_recv(TALLOC_CTX *mem_ctx,
                                struct tevent_req *req,
                                char **_dns_domain,
                                uint32_t *_ttl,
                                struct fo_server_info **_primary_servers,
                                size_t *_num_primary_servers,
                                struct fo_server_info **_backup_servers,
                                size_t *_num_backup_servers);

#endif /* __FAIL_OVER_SRV_H__ */
