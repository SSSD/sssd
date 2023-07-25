/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2014 Red Hat

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

#ifndef IFP_DOMAINS_H_
#define IFP_DOMAINS_H_

#include "responder/ifp/ifp_private.h"

/* org.freedesktop.sssd.infopipe */

struct tevent_req *
ifp_list_domains_send(TALLOC_CTX *mem_ctx,
                      struct tevent_context *ev,
                      struct sbus_request *sbus_req,
                      struct ifp_ctx *ifp_ctx);

errno_t ifp_list_domains_recv(TALLOC_CTX *mem_ctx,
                              struct tevent_req *req,
                              const char ***_paths);

struct tevent_req *
ifp_find_domain_by_name_send(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev,
                             struct sbus_request *sbus_req,
                             struct ifp_ctx *ifp_ctx,
                             const char *name);

errno_t
ifp_find_domain_by_name_recv(TALLOC_CTX *mem_ctx,
                             struct tevent_req *req,
                             const char **_path);

/* org.freedesktop.sssd.infopipe.Domains */

errno_t
ifp_dom_get_name(TALLOC_CTX *mem_ctx,
                 struct sbus_request *sbus_req,
                 struct ifp_ctx *ctx,
                 const char **_out);

errno_t
ifp_dom_get_provider(TALLOC_CTX *mem_ctx,
                     struct sbus_request *sbus_req,
                     struct ifp_ctx *ctx,
                     const char **_out);

errno_t
ifp_dom_get_primary_servers(TALLOC_CTX *mem_ctx,
                            struct sbus_request *sbus_req,
                            struct ifp_ctx *ctx,
                            const char ***_out);

errno_t
ifp_dom_get_backup_servers(TALLOC_CTX *mem_ctx,
                           struct sbus_request *sbus_req,
                           struct ifp_ctx *ctx,
                           const char ***_out);

errno_t
ifp_dom_get_min_id(TALLOC_CTX *mem_ctx,
                           struct sbus_request *sbus_req,
                           struct ifp_ctx *ctx,
                           uint32_t *_out);

errno_t
ifp_dom_get_max_id(TALLOC_CTX *mem_ctx,
                           struct sbus_request *sbus_req,
                           struct ifp_ctx *ctx,
                           uint32_t *_out);

errno_t
ifp_dom_get_realm(TALLOC_CTX *mem_ctx,
                  struct sbus_request *sbus_req,
                  struct ifp_ctx *ctx,
                  const char **_out);

errno_t
ifp_dom_get_forest(TALLOC_CTX *mem_ctx,
                   struct sbus_request *sbus_req,
                   struct ifp_ctx *ctx,
                   const char **_out);

errno_t
ifp_dom_get_login_format(TALLOC_CTX *mem_ctx,
                         struct sbus_request *sbus_req,
                         struct ifp_ctx *ctx,
                         const char **_out);

errno_t
ifp_dom_get_fqdn_format(TALLOC_CTX *mem_ctx,
                        struct sbus_request *sbus_req,
                        struct ifp_ctx *ctx,
                        const char **_out);

errno_t
ifp_dom_get_enumerable(TALLOC_CTX *mem_ctx,
                       struct sbus_request *sbus_req,
                       struct ifp_ctx *ctx,
                       bool *_out);

errno_t
ifp_dom_get_use_fqdn(TALLOC_CTX *mem_ctx,
                     struct sbus_request *sbus_req,
                     struct ifp_ctx *ctx,
                     bool *_out);

errno_t
ifp_dom_get_subdomain(TALLOC_CTX *mem_ctx,
                      struct sbus_request *sbus_req,
                      struct ifp_ctx *ctx,
                      bool *_out);

errno_t
ifp_dom_get_parent_domain(TALLOC_CTX *mem_ctx,
                          struct sbus_request *sbus_req,
                          struct ifp_ctx *ctx,
                          const char **_out);

struct tevent_req *
ifp_domains_domain_is_online_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct sbus_request *sbus_req,
                                  struct ifp_ctx *ifp_ctx);

errno_t
ifp_domains_domain_is_online_recv(TALLOC_CTX *mem_ctx,
                                  struct tevent_req *req,
                                  bool *_is_online);

struct tevent_req *
ifp_domains_domain_list_services_send(TALLOC_CTX *mem_ctx,
                                      struct tevent_context *ev,
                                      struct sbus_request *sbus_req,
                                      struct ifp_ctx *ifp_ctx);

errno_t
ifp_domains_domain_list_services_recv(TALLOC_CTX *mem_ctx,
                                      struct tevent_req *req,
                                      const char ***_services);

struct tevent_req *
ifp_domains_domain_active_server_send(TALLOC_CTX *mem_ctx,
                                      struct tevent_context *ev,
                                      struct sbus_request *sbus_req,
                                      struct ifp_ctx *ifp_ctx,
                                      const char *service);

errno_t
ifp_domains_domain_active_server_recv(TALLOC_CTX *mem_ctx,
                                      struct tevent_req *req,
                                      const char **_server);

struct tevent_req *
ifp_domains_domain_list_servers_send(TALLOC_CTX *mem_ctx,
                                     struct tevent_context *ev,
                                     struct sbus_request *sbus_req,
                                     struct ifp_ctx *ifp_ctx,
                                     const char *service);

errno_t
ifp_domains_domain_list_servers_recv(TALLOC_CTX *mem_ctx,
                                      struct tevent_req *req,
                                      const char ***_servers);

struct tevent_req *
ifp_domains_domain_refresh_access_rules_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct sbus_request *sbus_req,
                                             struct ifp_ctx *ifp_ctx);

errno_t
ifp_domains_domain_refresh_access_rules_recv(TALLOC_CTX *mem_ctx,
                                             struct tevent_req *req);

#endif /* IFP_DOMAINS_H_ */
