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

#ifndef DP_IFACE_H_
#define DP_IFACE_H_

#include "sbus/sbus_request.h"
#include "providers/data_provider/dp_private.h"
#include "providers/data_provider/dp.h"

struct tevent_req *
dp_get_account_info_send(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct sbus_request *sbus_req,
                         struct data_provider *provider,
                         uint32_t dp_flags,
                         uint32_t entry_type,
                         const char *filter,
                         const char *domain,
                         const char *extra,
                         uint32_t cli_id);

errno_t
dp_get_account_info_recv(TALLOC_CTX *mem_ctx,
                         struct tevent_req *req,
                         uint16_t *_dp_error,
                         uint32_t *_error,
                         const char **_err_msg);

struct tevent_req *
dp_pam_handler_send(TALLOC_CTX *mem_ctx,
                    struct tevent_context *ev,
                    struct sbus_request *sbus_req,
                    struct data_provider *provider,
                    struct pam_data *pd);

errno_t
dp_pam_handler_recv(TALLOC_CTX *mem_ctx,
                    struct tevent_req *req,
                    struct pam_data **_pd);

struct tevent_req *
dp_sudo_handler_send(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct sbus_request *sbus_req,
                     struct data_provider *provider,
                     DBusMessageIter *read_iter);

errno_t
dp_sudo_handler_recv(TALLOC_CTX *mem_ctx,
                     struct tevent_req *req,
                     uint16_t *_dp_error,
                     uint32_t *_error,
                     const char **_err_msg);

struct tevent_req *
dp_host_handler_send(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct sbus_request *sbus_req,
                     struct data_provider *provider,
                     uint32_t dp_flags,
                     const char *name,
                     const char *alias,
                     uint32_t cli_id);

errno_t
dp_host_handler_recv(TALLOC_CTX *mem_ctx,
                     struct tevent_req *req,
                     uint16_t *_dp_error,
                     uint32_t *_error,
                     const char **_err_msg);

struct tevent_req *
dp_autofs_handler_send(TALLOC_CTX *mem_ctx,
                       struct tevent_context *ev,
                       struct sbus_request *sbus_req,
                       struct data_provider *provider,
                       uint32_t dp_flags,
                       const char *mapname);

errno_t
dp_autofs_handler_recv(TALLOC_CTX *mem_ctx,
                       struct tevent_req *req,
                       uint16_t *_dp_error,
                       uint32_t *_error,
                       const char **_err_msg);

struct tevent_req *
dp_autofs_get_map_send(TALLOC_CTX *mem_ctx,
                       struct tevent_context *ev,
                       struct sbus_request *sbus_req,
                       struct data_provider *provider,
                       uint32_t dp_flags,
                       const char *mapname,
                       uint32_t cli_id);

errno_t dp_autofs_get_map_recv(TALLOC_CTX *mem_ctx, struct tevent_req *req);

struct tevent_req *
dp_autofs_get_entry_send(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct sbus_request *sbus_req,
                         struct data_provider *provider,
                         uint32_t dp_flags,
                         const char *mapname,
                         const char *entryname,
                         uint32_t cli_id);

errno_t dp_autofs_get_entry_recv(TALLOC_CTX *mem_ctx, struct tevent_req *req);

struct tevent_req *
dp_autofs_enumerate_send(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct sbus_request *sbus_req,
                         struct data_provider *provider,
                         uint32_t dp_flags,
                         const char *mapname,
                         uint32_t cli_id);

errno_t dp_autofs_enumerate_recv(TALLOC_CTX *mem_ctx, struct tevent_req *req);

struct tevent_req *
dp_subdomains_handler_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct sbus_request *sbus_req,
                           struct data_provider *provider,
                           const char *domain_hint);

errno_t
dp_subdomains_handler_recv(TALLOC_CTX *mem_ctx,
                           struct tevent_req *req,
                           uint16_t *_dp_error,
                           uint32_t *_error,
                           const char **_err_msg);

struct tevent_req *
dp_resolver_handler_send(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct sbus_request *sbus_req,
                         struct data_provider *provider,
                         uint32_t dp_flags,
                         uint32_t entry_type,
                         uint32_t filter_type,
                         const char *filter_value,
                         uint32_t cli_id);

errno_t
dp_resolver_handler_recv(TALLOC_CTX *mem_ctx,
                         struct tevent_req *req,
                         uint16_t *_dp_error,
                         uint32_t *_error,
                         const char **_err_msg);

/*
 * Return a domain the account belongs to.
 *
 * The request uses the dp_reply_std structure for reply, with the following
 * semantics:
 *  - DP_ERR_OK - it is expected that the string message contains the domain name
 *                the entry was found in. A 'negative' reply where the
 *                request returns DP_ERR_OK, but no domain should be treated
 *                as authoritative, as if the entry does not exist.
 *  - DP_ERR_*  - the string message contains error string that corresponds
 *                to the errno field in dp_reply_std().
 */
struct tevent_req *
dp_get_account_domain_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct sbus_request *sbus_req,
                           struct data_provider *provider,
                           uint32_t dp_flags,
                           uint32_t entry_type,
                           const char *filter,
                           uint32_t cli_id);

errno_t
dp_get_account_domain_recv(TALLOC_CTX *mem_ctx,
                           struct tevent_req *req,
                           uint16_t *_dp_error,
                           uint32_t *_error,
                           const char **_err_msg);

/* sssd.DataProvider.Client */
errno_t
dp_client_register(TALLOC_CTX *mem_ctx,
                   struct sbus_request *sbus_req,
                   struct data_provider *provider,
                   const char *name);

/* sssd.DataProvider.Backend */
errno_t dp_backend_is_online(TALLOC_CTX *mem_ctx,
                             struct sbus_request *sbus_req,
                             struct be_ctx *be_ctx,
                             const char *domname,
                             bool *_is_online);

/* sssd.DataProvider.Failover */
errno_t
dp_failover_list_services(TALLOC_CTX *mem_ctx,
                          struct sbus_request *sbus_req,
                          struct be_ctx *be_ctx,
                          const char *domname,
                          const char ***_services);

errno_t
dp_failover_active_server(TALLOC_CTX *mem_ctx,
                          struct sbus_request *sbus_req,
                          struct be_ctx *be_ctx,
                          const char *service_name,
                          const char **_server);

errno_t
dp_failover_list_servers(TALLOC_CTX *mem_ctx,
                         struct sbus_request *sbus_req,
                         struct be_ctx *be_ctx,
                         const char *service_name,
                         const char ***_servers);

/* sssd.DataProvider.AccessControl */
struct tevent_req *
dp_access_control_refresh_rules_send(TALLOC_CTX *mem_ctx,
                                     struct tevent_context *ev,
                                     struct sbus_request *sbus_req,
                                     struct data_provider *provider);

errno_t
dp_access_control_refresh_rules_recv(TALLOC_CTX *mem_ctx,
                                     struct tevent_req *req);


errno_t
dp_add_sr_attribute(struct be_ctx *be_ctx);
#endif /* DP_IFACE_H_ */
