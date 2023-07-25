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

#ifndef __AD_SRV_H__
#define __AD_SRV_H__

struct ad_srv_plugin_ctx {
    struct be_ctx *be_ctx;
    struct be_resolv_ctx *be_res;
    enum host_database *host_dbs;
    struct sdap_options *opts;
    struct ad_options *ad_options;
    const char *hostname;
    const char *ad_domain;
    const char *ad_site_override;

    bool renew_site;
};

struct ad_srv_plugin_ctx *
ad_srv_plugin_ctx_init(TALLOC_CTX *mem_ctx,
                       struct be_ctx *be_ctx,
                       struct be_resolv_ctx *be_res,
                       enum host_database *host_dbs,
                       struct sdap_options *opts,
                       struct ad_options *ad_options,
                       const char *hostname,
                       const char *ad_domain,
                       const char *ad_site_override);

struct tevent_req *ad_srv_plugin_send(TALLOC_CTX *mem_ctx,
                                       struct tevent_context *ev,
                                       const char *service,
                                       const char *protocol,
                                       const char *discovery_domain,
                                       void *pvt);

errno_t ad_srv_plugin_recv(TALLOC_CTX *mem_ctx,
                            struct tevent_req *req,
                            char **_dns_domain,
                            uint32_t *_ttl,
                            struct fo_server_info **_primary_servers,
                            size_t *_num_primary_servers,
                            struct fo_server_info **_backup_servers,
                            size_t *_num_backup_servers);

char *ad_site_dns_discovery_domain(TALLOC_CTX *mem_ctx,
                                   const char *site,
                                   const char *domain);

struct tevent_req *ad_cldap_ping_send(TALLOC_CTX *mem_ctx,
                                      struct tevent_context *ev,
                                      struct ad_srv_plugin_ctx *srv_ctx,
                                      const char *discovery_domain);

errno_t ad_cldap_ping_recv(TALLOC_CTX *mem_ctx,
                           struct tevent_req *req,
                           const char **_site,
                           const char **_forest);

#endif /* __AD_SRV_H__ */
