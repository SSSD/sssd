/*
   SSSD

   Fail over tests.

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

#include <arpa/inet.h>

#include <check.h>
#include <popt.h>
#include <stdlib.h>
#include <stdio.h>
#include <talloc.h>
#include <tevent.h>

#include "resolv/async_resolv.h"
#include "tests/common.h"
#include "util/util.h"

/* Interface under test */
#include "providers/fail_over.h"

int use_net_test;

struct test_ctx {
    struct tevent_context *ev;
    struct resolv_ctx *resolv;
    struct fo_ctx *fo_ctx;
    int tasks;
};

struct task {
    struct test_ctx *test_ctx;
    const char *location;
    int recv;
    int port;
    int new_server_status;
    int new_port_status;
};

static struct test_ctx *
setup_test(void)
{
    struct test_ctx *ctx;
    struct fo_options fopts;
    int ret;

    ctx = talloc_zero(global_talloc_context, struct test_ctx);
    fail_if(ctx == NULL, "Could not allocate memory for test context");

    ctx->ev = tevent_context_init(ctx);
    if (ctx->ev == NULL) {
        talloc_free(ctx);
        fail("Could not init tevent context");
    }

    ret = resolv_init(ctx, ctx->ev, 5, &ctx->resolv);
    if (ret != EOK) {
        talloc_free(ctx);
        fail("Could not init resolv context");
    }

    memset(&fopts, 0, sizeof(fopts));
    fopts.retry_timeout = 30;
    fopts.family_order  = IPV4_FIRST;

    ctx->fo_ctx = fo_context_init(ctx, &fopts);
    if (ctx->fo_ctx == NULL) {
        talloc_free(ctx);
        fail("Could not init fail over context");
    }

    return ctx;
}

static void
test_loop(struct test_ctx *data)
{
    while (data->tasks != 0)
        tevent_loop_once(data->ev);
}

START_TEST(test_fo_new_service)
{
    int i;
    int ret;
    struct test_ctx *ctx;
    struct fo_service *service;
    struct fo_service *services[10];

    ctx = setup_test();
    check_leaks_push(ctx);

    for (i = 0; i < 10; i++) {
        char buf[16];
        sprintf(buf, "service_%d", i);

        check_leaks_push(ctx);
        ret = fo_new_service(ctx->fo_ctx, buf, &services[i]);
        fail_if(ret != EOK);
    }

    ret = fo_new_service(ctx->fo_ctx, "service_3", &service);
    fail_if(ret != EEXIST);

    for (i = 9; i >= 0; i--) {
        char buf[16];
        sprintf(buf, "service_%d", i);

        ret = fo_get_service(ctx->fo_ctx, buf, &service);
        fail_if(ret != EOK);
        fail_if(service != services[i]);
        talloc_free(service);
        check_leaks_pop(ctx);

        ret = fo_get_service(ctx->fo_ctx, buf, &service);
        fail_if(ret != ENOENT);
    }

    check_leaks_pop(ctx);
    talloc_free(ctx);
}
END_TEST

static void
test_resolve_service_callback(struct tevent_req *req)
{
    uint64_t recv_status;
    int port;
    struct task *task;
    struct fo_server *server = NULL;
    struct resolv_hostent *he;
    int i;

    task = tevent_req_callback_data(req, struct task);

    task->test_ctx->tasks--;

    recv_status = fo_resolve_service_recv(req, &server);
    talloc_free(req);
    fail_if(recv_status != task->recv, "%s: Expected return of %d, got %d",
            task->location, task->recv, recv_status);
    if (recv_status != EOK)
        return;
    fail_if(server == NULL);
    port = fo_get_server_port(server);
    fail_if(port != task->port, "%s: Expected port %d, got %d", task->location,
            task->port, port);

    if (task->new_port_status >= 0)
        fo_set_port_status(server, task->new_port_status);
    if (task->new_server_status >= 0)
        fo_set_server_status(server, task->new_server_status);

    if (fo_get_server_name(server) != NULL) {
        he = fo_get_server_hostent(server);
        fail_if(he == NULL, "%s: fo_get_server_hostent() returned NULL");
        for (i = 0; he->addr_list[i]; i++) {
            char buf[256];

            inet_ntop(he->family, he->addr_list[i]->ipaddr, buf, sizeof(buf));
            fail_if(strcmp(buf, "127.0.0.1") != 0 && strcmp(buf, "::1") != 0);
        }
    }

}

#define get_request(a, b, c, d, e, f) \
       _get_request(a, b, c, d, e, f, __location__)

static void
_get_request(struct test_ctx *test_ctx, struct fo_service *service,
             int expected_recv, int expected_port, int new_port_status,
             int new_server_status, const char *location)
{
    struct tevent_req *req;
    struct task *task;

    task = talloc(test_ctx, struct task);
    fail_if(task == NULL);

    task->test_ctx = test_ctx;
    task->recv = expected_recv;
    task->port = expected_port;
    task->new_port_status = new_port_status;
    task->new_server_status = new_server_status;
    task->location = location;
    test_ctx->tasks++;

    req = fo_resolve_service_send(test_ctx, test_ctx->ev,
                                  test_ctx->resolv,
                                  test_ctx->fo_ctx, service);
    fail_if(req == NULL, "%s: fo_resolve_service_send() failed", location);

    tevent_req_set_callback(req, test_resolve_service_callback, task);
    test_loop(test_ctx);
}

START_TEST(test_fo_resolve_service)
{
    struct test_ctx *ctx;
    struct fo_service *service[3];

    ctx = setup_test();
    fail_if(ctx == NULL);

    /* Add service. */
    fail_if(fo_new_service(ctx->fo_ctx, "http", &service[0]) != EOK);

    fail_if(fo_new_service(ctx->fo_ctx, "ldap", &service[1]) != EOK);

    fail_if(fo_new_service(ctx->fo_ctx, "ntp", &service[2]) != EOK);

    /* Add servers. */
    fail_if(fo_add_server(service[0], "localhost", 20, NULL, true) != EOK);
    fail_if(fo_add_server(service[0], "127.0.0.1", 80, NULL, false) != EOK);

    fail_if(fo_add_server(service[1], "localhost", 30, NULL, false) != EOK);
    fail_if(fo_add_server(service[1], "127.0.0.1", 389, NULL, true) != EOK);
    fail_if(fo_add_server(service[1], "127.0.0.1", 389, NULL, true) != EEXIST);
    fail_if(fo_add_server(service[1], "127.0.0.1", 389, NULL, false) != EEXIST);

    fail_if(fo_add_server(service[2], NULL, 123, NULL, true) != EOK);

    /* Make requests. */
    get_request(ctx, service[0], EOK, 20, PORT_WORKING, -1);
    get_request(ctx, service[0], EOK, 20, -1, SERVER_NOT_WORKING);
    get_request(ctx, service[0], EOK, 80, PORT_WORKING, -1);
    get_request(ctx, service[0], EOK, 80, PORT_NOT_WORKING, -1);
    get_request(ctx, service[0], ENOENT, 0, -1, -1);

    get_request(ctx, service[1], EOK, 389, PORT_WORKING, -1);
    get_request(ctx, service[1], EOK, 389, -1, SERVER_NOT_WORKING);
    get_request(ctx, service[1], ENOENT, 0, -1, -1);

    get_request(ctx, service[2], EOK, 123, -1, -1);

    talloc_free(ctx);
}
END_TEST

Suite *
create_suite(void)
{
    Suite *s = suite_create("fail_over");

    TCase *tc = tcase_create("FAIL_OVER Tests");

    tcase_add_checked_fixture(tc, leak_check_setup, leak_check_teardown);
    /* Do some testing */
    tcase_add_test(tc, test_fo_new_service);
    tcase_add_test(tc, test_fo_resolve_service);
    if (use_net_test) {
    }
    /* Add all test cases to the test suite */
    suite_add_tcase(s, tc);

    return s;
}

int
main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    int failure_count;
    Suite *suite;
    SRunner *sr;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug-level", 'd', POPT_ARG_INT, &debug_level, 0, "Set debug level", NULL },
        { "use-net-test", 'n', POPT_ARG_NONE, 0, 'n', "Run tests that need an active internet connection", NULL },
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can deside if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        case 'n':
            use_net_test = 1;
            break;

        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                    poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }
    poptFreeContext(pc);

    CONVERT_AND_SET_DEBUG_LEVEL(debug_level);

    tests_set_cwd();

    suite = create_suite();
    sr = srunner_create(suite);
    /* If CK_VERBOSITY is set, use that, otherwise it defaults to CK_NORMAL */
    srunner_run_all(sr, CK_ENV);
    failure_count = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (failure_count == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
