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
    struct sbus_server *sbus_server;
    struct sbus_connection *sbus_conn;
    struct dp_client *clients[DP_CLIENT_SENTINEL];
    bool terminating;

    struct {
        /* Numeric identificator that will be assigned to next request. */
        uint32_t index;

        /* List of all ongoing requests. */
        uint32_t num_active;
        struct dp_req *active;
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

/* Data provider request. */

void dp_terminate_active_requests(struct data_provider *provider);

/* Client shared functions. */

errno_t
dp_client_init(struct sbus_connection *cli_conn,
               struct data_provider *provider);

struct data_provider *dp_client_provider(struct dp_client *dp_cli);
struct be_ctx *dp_client_be(struct dp_client *dp_cli);
struct sbus_connection *dp_client_conn(struct dp_client *dp_cli);

#endif /* _DP_PRIVATE_H_ */
