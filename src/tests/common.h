/*
   SSSD

   Common utilities for check-based tests using talloc.

   Authors:
        Martin Nagy <mnagy@redhat.com>

   Copyright (C) Red Hat, Inc 2009

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

#ifndef __TESTS_COMMON_H__
#define __TESTS_COMMON_H__

#include <talloc.h>
#include "util/util.h"
#include "providers/data_provider.h"
#include "providers/ldap/sdap.h"

extern TALLOC_CTX *global_talloc_context;

#define check_leaks(ctx, bytes) _check_leaks((ctx), (bytes), __location__)
bool _check_leaks(TALLOC_CTX *ctx,
                  size_t bytes,
                  const char *location);

void check_leaks_push(TALLOC_CTX *ctx);

#define check_leaks_pop(ctx) _check_leaks_pop((ctx), __location__)
bool _check_leaks_pop(TALLOC_CTX *ctx, const char *location);

bool leak_check_setup(void);
bool leak_check_teardown(void);
const char *check_leaks_err_msg(void);

void tests_set_cwd(void);

errno_t
compare_dp_options(struct dp_option *map1, size_t size1,
                   struct dp_option *map2);

errno_t
compare_sdap_attr_maps(struct sdap_attr_map *map1, size_t size1,
                       struct sdap_attr_map *map2);

/* A common test structure for tests that require a domain to be set up. */
struct sss_test_ctx {
    struct sysdb_ctx *sysdb;
    struct confdb_ctx *confdb;
    struct tevent_context *ev;
    struct sss_domain_info *dom;
    struct sss_names_ctx *nctx;
    char *confdb_path;
    char *conf_dom_path;

    bool done;
    int error;
};

struct sss_test_conf_param {
    const char *key;
    const char *value;
};

struct sss_test_ctx *create_ev_test_ctx(TALLOC_CTX *mem_ctx);

struct sss_test_ctx *
create_dom_test_ctx(TALLOC_CTX *mem_ctx,
                    const char *tests_path,
                    const char *confdb_path,
                    const char *domain_name,
                    const char *id_provider,
                    struct sss_test_conf_param *params);

void test_dom_suite_setup(const char *tests_path);

void test_dom_suite_cleanup(const char *tests_path,
                            const char *confdb_path,
                            const char *sysdb_path);

struct tevent_req *
test_request_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev, errno_t err);

#define test_req_succeed_send(mem_ctx, ev) test_request_send(mem_ctx, ev, 0)

errno_t test_request_recv(struct tevent_req *req);

int test_ev_loop(struct sss_test_ctx *tctx);

bool ldb_modules_path_is_set(void);

DBusConnection *
test_dbus_setup_mock(TALLOC_CTX *mem_ctx,
                     struct tevent_context *loop,
                     sbus_server_conn_init_fn init_fn,
                     void *init_pvt_data);

DBusMessage *
test_dbus_call_sync(DBusConnection *conn,
                    const char *object_path,
                    const char *interface,
                    const char *method,
                    DBusError *error,
                    int first_arg_type,
                    ...);

#endif /* !__TESTS_COMMON_H__ */
