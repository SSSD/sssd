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

#ifndef _DP_PRIVATE_H_
#define _DP_PRIVATE_H_

#include <tevent.h>
#include <dhash.h>
#include "sbus/sssd_dbus.h"
#include "providers/data_provider/dp.h"
#include "util/util.h"

#define DP_REQ_DEBUG(level, name, fmt, ...) \
    DEBUG(level, "DP Request [%s]: " fmt "\n", (name ?: "Unknown"), ##__VA_ARGS__)

enum dp_clients {
    DPC_NSS,
    DPC_PAM,
    DPC_IFP,
    DPC_PAC,
    DPC_SUDO,
    DPC_HOST,
    DPC_AUTOFS,

    DP_CLIENT_SENTINEL
};

struct dp_req;
struct dp_client;

struct dp_module {
    bool initialized;
    const char *name;
    void *module_data;
    void *libhandle;
};

struct dp_target {
    const char *name;
    const char *module_name;
    bool explicitly_configured;

    bool initialized;
    enum dp_targets target;
    struct dp_module *module;
    struct dp_method *methods;
};

struct dp_method {
    dp_req_send_fn send_fn;
    dp_req_recv_fn recv_fn;
    void *method_data;
    const char *method_dtype;
    const char *request_dtype;
    const char *output_dtype;
    uint32_t output_size;
};

struct data_provider {
    uid_t uid;
    gid_t gid;
    struct be_ctx *be_ctx;
    struct tevent_context *ev;
    struct sbus_connection *srv_conn;
    struct dp_client *clients[DP_CLIENT_SENTINEL];
    bool terminating;

    struct {
        /* Numeric identificator that will be assigned to next request. */
        uint32_t index;

        /* List of all ongoing requests. */
        uint32_t num_active;
        struct dp_req *active;

        /* Table containing list of sbus_requests where DP sends reply when
         * a request is finished. Value of this table is pair
         * <tevent_req, list of sbus_request>
         */
        hash_table_t *reply_table;
    } requests;

    struct dp_module **modules;
    struct dp_target **targets;
};

errno_t dp_find_method(struct data_provider *provider,
                       enum dp_targets target,
                       enum dp_methods method,
                       struct dp_method **_execute);

struct dp_module *dp_load_module(TALLOC_CTX *mem_ctx,
                                 struct be_ctx *be_ctx,
                                 struct data_provider *provider,
                                 struct dp_module **modules,
                                 const char *name);

errno_t dp_init_modules(TALLOC_CTX *mem_ctx, struct dp_module ***_modules);

const char *dp_target_to_string(enum dp_targets target);

bool dp_target_initialized(struct dp_target **targets, enum dp_targets type);

errno_t dp_init_targets(TALLOC_CTX *mem_ctx,
                        struct be_ctx *be_ctx,
                        struct data_provider *provider,
                        struct dp_module **modules);

/* Reply callbacks. */

typedef void (*dp_req_post_fn)(const char *req_name,
                               struct data_provider *provider,
                               void *post_data,
                               void *reply_data);

typedef void (*dp_req_reply_fn)(const char *req_name,
                                struct sbus_request *sbus_req,
                                void *data);

void dp_req_reply_default(const char *req_name,
                          struct sbus_request *sbus_req,
                          void *data);

/* Data provider request table. */

struct dp_sbus_req_item;

struct dp_table_value {
    hash_table_t *table;
    const char *key;

    struct tevent_req *req;
    struct dp_sbus_req_item *list;
};

struct dp_sbus_req_item {
    struct dp_table_value *parent;
    struct sbus_request *sbus_req;

    struct dp_sbus_req_item *prev;
    struct dp_sbus_req_item *next;
};

char *dp_req_table_key(TALLOC_CTX *mem_ctx,
                       enum dp_targets target,
                       enum dp_methods method,
                       uint32_t dp_flags,
                       const char *custom_part);

errno_t dp_req_table_init(TALLOC_CTX *mem_ctx, hash_table_t **_table);

struct dp_table_value *dp_req_table_lookup(hash_table_t *table,
                                           const char *key);

errno_t dp_req_table_add(hash_table_t *table,
                         const char *key,
                         struct tevent_req *req,
                         struct sbus_request *sbus_req);

void dp_req_table_del(hash_table_t *table,
                      const char *key);

void dp_req_table_del_and_free(hash_table_t *table,
                               const char *key);

bool dp_req_table_has_key(hash_table_t *table,
                          const char *key);

/* Data provider request. */

void dp_terminate_active_requests(struct data_provider *provider);

void dp_req_reply_error(struct sbus_request *sbus_req,
                        const char *req_name,
                        errno_t ret);

void _dp_req_with_reply(struct dp_client *dp_cli,
                        const char *domain,
                        const char *request_name,
                        const char *custom_key,
                        struct sbus_request *sbus_req,
                        enum dp_targets target,
                        enum dp_methods method,
                        uint32_t dp_flags,
                        void *request_data,
                        dp_req_post_fn postprocess_fn,
                        void *postprocess_data,
                        dp_req_reply_fn reply_fn,
                        const char *output_dtype);

/**
 * If @domain is NULL, be_ctx->domain is used.
 * If req_key is NULL, address of sbus_req is used.
 *
 * If @pp_fn (post process function) is set it is call on a successful
 * DP request before reply is sent.
 */
#define dp_req_with_reply_pp(dp_cli, domain, req_name, req_key, sbus_req,     \
                             target, method, dp_flags, req_data, pp_fn,       \
                             pp_data, pp_dtype, reply_fn, output_dtype)       \
    do {                                                                      \
        /* Check postprocess function parameter types. */                     \
        void (*__pp_fn)(const char *, struct data_provider *,                 \
            pp_dtype *, output_dtype *) = (pp_fn);                            \
        pp_dtype *__pp_data = (pp_data);                                      \
                                                                              \
        /* Check reply function parameter types. */                           \
        void (*__reply_fn)(const char *, struct sbus_request *,               \
            output_dtype *) = (reply_fn);                                     \
                                                                              \
        _dp_req_with_reply(dp_cli, domain, req_name, req_key, sbus_req,       \
                           target, method, dp_flags, req_data,                \
                           (dp_req_post_fn)__pp_fn, __pp_data,                \
                           (dp_req_reply_fn)__reply_fn, #output_dtype);       \
    } while(0)

#define dp_req_with_reply(dp_cli, domain, req_name, req_key, sbus_req, target,\
                          method, dp_flags, req_data, reply_fn,               \
                          output_dtype)                                       \
    dp_req_with_reply_pp(dp_cli, domain, req_name, req_key, sbus_req, target, \
                         method, dp_flags, req_data, NULL, NULL, void,        \
                         reply_fn, output_dtype)

/* Client shared functions. */

errno_t dp_client_init(struct sbus_connection *conn, void *data);
struct data_provider *dp_client_provider(struct dp_client *dp_cli);
struct be_ctx *dp_client_be(struct dp_client *dp_cli);
struct sbus_connection *dp_client_conn(struct dp_client *dp_cli);

#endif /* _DP_PRIVATE_H_ */
