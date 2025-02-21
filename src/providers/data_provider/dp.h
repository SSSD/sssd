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

#ifndef _DP_H_
#define _DP_H_

#include <stdint.h>
#include <string.h>

#include "providers/backend.h"
#include "providers/data_provider/dp_request.h"
#include "providers/data_provider/dp_custom_data.h"
#include "providers/data_provider/dp_flags.h"
#include "sbus/sbus.h"

struct data_provider;
struct dp_method;

/**
 * Module constructor.
 *
 * It is possible to create a module data that is passed into all
 * target initialization functions.
 */
typedef errno_t (*dp_module_init_fn)(TALLOC_CTX *mem_ctx,
                                     struct be_ctx *be_ctx,
                                     struct data_provider *provider,
                                     const char *module_name,
                                     void **_module_data);

/**
 * Target initialization function.
 *
 * Pointer to dp_method is unique for all targets. Make sure that
 * dp_set_method is called in all targets even if you are reusing
 * some existing context or initialization function.
 */
typedef errno_t (*dp_target_init_fn)(TALLOC_CTX *mem_ctx,
                                     struct be_ctx *be_ctx,
                                     void *module_data,
                                     struct dp_method *dp_methods);

enum dp_targets {
    DPT_ID,
    DPT_AUTH,
    DPT_ACCESS,
    DPT_CHPASS,
    DPT_SUDO,
    DPT_AUTOFS,
    DPT_SELINUX,
    DPT_HOSTID,
    DPT_SUBDOMAINS,
    DPT_SESSION,
    DPT_RESOLVER,

    DP_TARGET_SENTINEL
};

enum dp_methods {
    DPM_CHECK_ONLINE,
    DPM_ACCOUNT_HANDLER,
    DPM_AUTH_HANDLER,
    DPM_ACCESS_HANDLER,
    DPM_SELINUX_HANDLER,
    DPM_SUDO_HANDLER,
    DPM_HOSTID_HANDLER,
    DPM_DOMAINS_HANDLER,
    DPM_SESSION_HANDLER,
    DPM_ACCT_DOMAIN_HANDLER,
    DPM_RESOLVER_HOSTS_HANDLER,
    DPM_RESOLVER_IP_NETWORK_HANDLER,

    DPM_REFRESH_ACCESS_RULES,

    DPM_AUTOFS_GET_MAP,
    DPM_AUTOFS_GET_ENTRY,
    DPM_AUTOFS_ENUMERATE,

    DP_METHOD_SENTINEL
};

/* Method handler. */

struct dp_req_params {
    struct tevent_context *ev;
    struct be_ctx *be_ctx;
    struct sss_domain_info *domain;
    enum dp_targets target;
    enum dp_methods method;
};

typedef struct tevent_req *
(*dp_req_send_fn)(TALLOC_CTX *mem_ctx, void *method_data, void *request_data,
                  struct dp_req_params *params);

typedef errno_t
(*dp_req_recv_fn)(TALLOC_CTX *mem_ctx, struct tevent_req *req, void *data);

typedef char dp_no_output;

/* Data provider initialization. */

errno_t
dp_init(struct tevent_context *ev,
        struct be_ctx *be_ctx,
        const char *sbus_name);

bool _dp_target_enabled(struct data_provider *provider,
                        const char *module_name,
                        ...);

#define dp_target_enabled(provider, module_name, ...) \
    _dp_target_enabled(provider, module_name, ##__VA_ARGS__, DP_TARGET_SENTINEL)

struct dp_module *dp_target_module(struct data_provider *provider,
                                   enum dp_targets target);

void *dp_get_module_data(struct dp_module *dp_module);

void _dp_set_method(struct dp_method *methods,
                    enum dp_methods method,
                    dp_req_send_fn send_fn,
                    dp_req_recv_fn recv_fn,
                    void *method_data,
                    const char *method_dtype,
                    const char *request_dtype,
                    const char *output_dtype,
                    uint32_t output_size);

/* We check function headers on compile time and data types on run time. This
 * check requires that both method and request private data are talloc-created
 * with talloc name set to data type name (which is done by talloc unless
 * you use _size variations of talloc functions.
 *
 * This way we ensure that we always pass correct data and we can access them
 * directly in request handler without the need to cast them explicitly
 * from void pointer. */
#define dp_set_method(methods, method, send_fn, recv_fn, method_data,         \
                      method_dtype, req_dtype, output_dtype)                  \
    do {                                                                      \
        /* Check _send function parameter types. */                           \
        struct tevent_req *(*__send_fn)(TALLOC_CTX *, method_dtype *,         \
            req_dtype *, struct dp_req_params *params) = (send_fn);           \
                                                                              \
        /* Check _recv function parameter types. */                           \
        /* With output parameter. */                                          \
        errno_t (*__recv_fn)(TALLOC_CTX *, struct tevent_req *,               \
            output_dtype *) = (recv_fn);                                      \
        _dp_set_method(methods, method, (dp_req_send_fn)__send_fn,            \
                       (dp_req_recv_fn)__recv_fn, method_data,                \
                       #method_dtype, #req_dtype,                             \
                       #output_dtype, sizeof(output_dtype));                  \
    } while (0)

bool dp_method_enabled(struct data_provider *provider,
                       enum dp_targets target,
                       enum dp_methods method);

void dp_terminate_domain_requests(struct data_provider *provider,
                                  const char *domain);

void dp_sbus_reset_users_ncache(struct data_provider *provider,
                                struct sss_domain_info *dom);
void dp_sbus_reset_groups_ncache(struct data_provider *provider,
                                 struct sss_domain_info *dom);

void dp_sbus_reset_users_memcache(struct data_provider *provider);
void dp_sbus_reset_groups_memcache(struct data_provider *provider);
void dp_sbus_reset_initgr_memcache(struct data_provider *provider);
void dp_sbus_invalidate_group_memcache(struct data_provider *provider,
                                       gid_t gid);

/*
 * A dummy handler for DPM_ACCT_DOMAIN_HANDLER.
 *
 * Its purpose is to always return ERR_GET_ACCT_DOM_NOT_SUPPORTED
 * which the responder should evaluate as "this back end does not
 * support locating entries' domain" and never call
 * DPM_ACCT_DOMAIN_HANDLER again
 *
 * This request cannot fail, except for critical errors like OOM.
 */
struct tevent_req *
default_account_domain_send(TALLOC_CTX *mem_ctx,
                            void *unused_ctx,
                            struct dp_get_acct_domain_data *data,
                            struct dp_req_params *params);
errno_t default_account_domain_recv(TALLOC_CTX *mem_ctx,
                                    struct tevent_req *req,
                                    struct dp_reply_std *data);

struct sbus_connection *
dp_sbus_conn(struct data_provider *provider);

struct sbus_server *
dp_sbus_server(struct data_provider *provider);

#endif /* _DP_H_ */
