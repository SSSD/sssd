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

#ifndef __IPA_SRV_H__
#define __IPA_SRV_H__

struct ipa_srv_plugin_ctx;

struct ipa_srv_plugin_ctx *
ipa_srv_plugin_ctx_init(TALLOC_CTX *mem_ctx,
                        struct resolv_ctx *resolv_ctx,
                        const char *hostname,
                        const char *ipa_domain);

struct tevent_req *ipa_srv_plugin_send(TALLOC_CTX *mem_ctx,
                                       struct tevent_context *ev,
                                       const char *service,
                                       const char *protocol,
                                       const char *discovery_domain,
                                       void *pvt);

errno_t ipa_srv_plugin_recv(TALLOC_CTX *mem_ctx,
                            struct tevent_req *req,
                            char **_dns_domain,
                            uint32_t *_ttl,
                            struct fo_server_info **_primary_servers,
                            size_t *_num_primary_servers,
                            struct fo_server_info **_backup_servers,
                            size_t *_num_backup_servers);

#endif /* __IPA_SRV_H__ */
