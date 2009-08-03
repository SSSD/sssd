/*
   SSSD

   Async resolver tests

   Authors:
        Martin Nagy <mnagy@redhat.com>
        Jakub Hrozek <jhrozek@redhat.com>

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

#include <stdlib.h>
#include <check.h>
#include <talloc.h>
#include <tevent.h>
#include <popt.h>
#include <arpa/inet.h>

#include "util/util.h"

/* Interface under test */
#include "resolv/async_resolv.h"

int use_net_test;

struct resolv_test_ctx {
    struct tevent_context *ev;
    struct resolv_ctx *resolv;

    int error;
    bool done;
};

static int setup_resolv_test(struct resolv_test_ctx **ctx)
{
    struct resolv_test_ctx *test_ctx;
    int ret;

    test_ctx = talloc_zero(NULL, struct resolv_test_ctx);
    if (test_ctx == NULL) {
        fail("Could not allocate memory for test context");
        talloc_free(test_ctx);
        return ENOMEM;
    }

    test_ctx->ev = tevent_context_init(NULL);
    if (test_ctx->ev == NULL) {
        fail("Could not init tevent context");
        talloc_free(test_ctx);
        return EFAULT;
    }

    ret = resolv_init(NULL, test_ctx->ev, &test_ctx->resolv);
    if (ret != EOK) {
        fail("Could not init resolv context");
        talloc_free(test_ctx);
        return ret;
    }

    *ctx = test_ctx;
    return EOK;
}

static int test_loop(struct resolv_test_ctx *data)
{
    while (!data->done)
        tevent_loop_once(data->ev);

    return data->error;
}

static void test_localhost(struct tevent_req *req)
{
     int recv_status;
     int status;
     const struct hostent *hostent;
     int i;
     struct resolv_test_ctx *test_ctx = tevent_req_callback_data(req,
                                                                 struct resolv_test_ctx);

     test_ctx->done = true;

     recv_status = resolv_gethostbyname_recv(req, &status, NULL, &hostent);
     if (recv_status != EOK) {
         DEBUG(2, ("resolv_gethostbyname_recv failed: %d\n", recv_status));
         test_ctx->error = recv_status;
         return;
     }
     DEBUG(7, ("resolv_gethostbyname_recv status: %d\n", status));

     test_ctx->error = ENOENT;
     for (i = 0; hostent->h_addr_list[i]; i++) {
         char addr_buf[256];
         inet_ntop(hostent->h_addrtype, hostent->h_addr_list[i], addr_buf, sizeof(addr_buf));

         /* test that localhost resolves to 127.0.0.1 or ::1 */
         if (strcmp(addr_buf, "127.0.0.1") == 0 || strcmp(addr_buf, "::1") == 0) {
             test_ctx->error = EOK;
         }
     }
}

START_TEST(test_resolv_localhost)
{
    struct resolv_test_ctx *test_ctx;
    int ret = EOK;
    struct tevent_req *req;
    const char *hostname = "localhost.localdomain";

    ret = setup_resolv_test(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up test");
        return;
    }

    req = resolv_gethostbyname_send(test_ctx->ev, test_ctx->ev, test_ctx->resolv, hostname, AF_INET);
    DEBUG(7, ("Sent resolv_gethostbyname\n"));
    if (req == NULL) {
        ret = ENOMEM;
    }

    if (ret == EOK) {
        tevent_req_set_callback(req, test_localhost, test_ctx);
        ret = test_loop(test_ctx);
    }

    fail_unless(ret == EOK);

    talloc_zfree(test_ctx);
}
END_TEST

static void test_negative(struct tevent_req *req)
{
     int recv_status;
     int status;
     const struct hostent *hostent;
     struct resolv_test_ctx *test_ctx;

     test_ctx = tevent_req_callback_data(req, struct resolv_test_ctx);
     test_ctx->done = true;

     recv_status = resolv_gethostbyname_recv(req, &status, NULL, &hostent);
     if (recv_status == EOK) {
         DEBUG(7, ("resolv_gethostbyname_recv succeeded in a negative test"));
         return;
     }

     test_ctx->error = status;
     DEBUG(2, ("resolv_gethostbyname_recv status: %d: %s\n", status, resolv_strerror(status)));
}

START_TEST(test_resolv_negative)
{
    int ret = EOK;
    struct tevent_req *req;
    const char *hostname = "sssd.foo";
    struct resolv_test_ctx *test_ctx;

    ret = setup_resolv_test(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up test");
        return;
    }

    req = resolv_gethostbyname_send(test_ctx->ev, test_ctx->ev, test_ctx->resolv, hostname, AF_INET);
    DEBUG(7, ("Sent resolv_gethostbyname\n"));
    if (req == NULL) {
        ret = ENOMEM;
    }

    if (ret == EOK) {
        tevent_req_set_callback(req, test_negative, test_ctx);
        ret = test_loop(test_ctx);
    }

    fail_unless(ret != EOK);
    fail_unless(test_ctx->error == ARES_ENOTFOUND);
    talloc_zfree(test_ctx);
}
END_TEST

static void test_internet(struct tevent_req *req)
{
     int recv_status;
     int status;
     const struct hostent *hostent;
     struct resolv_test_ctx *test_ctx = tevent_req_callback_data(req,
                                                                 struct resolv_test_ctx);

     test_ctx->done = true;

     recv_status = resolv_gethostbyname_recv(req, &status, NULL, &hostent);
     if (recv_status != EOK) {
         DEBUG(2, ("resolv_gethostbyname_recv failed: %d\n", recv_status));
         test_ctx->error = recv_status;
         return;
     }
     DEBUG(7, ("resolv_gethostbyname_recv status: %d\n", status));

     test_ctx->error = (hostent->h_length == 0) ? ENOENT : EOK;
}

START_TEST(test_resolv_internet)
{
    int ret = EOK;
    struct tevent_req *req;
    const char *hostname = "redhat.com";
    struct resolv_test_ctx *test_ctx;

    ret = setup_resolv_test(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up test");
        return;
    }

    req = resolv_gethostbyname_send(test_ctx->ev, test_ctx->ev, test_ctx->resolv, hostname, AF_INET);
    DEBUG(7, ("Sent resolv_gethostbyname\n"));
    if (req == NULL) {
        ret = ENOMEM;
    }

    if (ret == EOK) {
        tevent_req_set_callback(req, test_internet, test_ctx);
        ret = test_loop(test_ctx);
    }

    fail_unless(ret == EOK);
    talloc_zfree(test_ctx);
}
END_TEST

static void resolv_free_context(struct tevent_context *ev,
                                struct tevent_timer *te,
                                struct timeval t, void *ptr)
{
    struct resolv_ctx *rctx = talloc_get_type(ptr, struct resolv_ctx);
    DEBUG(7, ("freeing the context\n"));

    talloc_free(rctx);
}

static void resolv_free_done(struct tevent_context *ev,
                             struct tevent_timer *te,
                             struct timeval t, void *ptr)
{
    struct resolv_test_ctx *tctx = talloc_get_type(ptr, struct resolv_test_ctx);
    DEBUG(7, ("marking test as done\n"));

    tctx->error = EOK;
    tctx->done = true;
}

START_TEST(test_resolv_free_context)
{
    int ret = EOK;
    struct tevent_req *req;
    const char *hostname = "redhat.com";
    struct resolv_test_ctx *test_ctx;
    struct tevent_timer *free_timer, *terminate_timer;
    struct timeval free_tv, terminate_tv;

    ret = setup_resolv_test(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up test");
        return;
    }

    req = resolv_gethostbyname_send(test_ctx, test_ctx->ev, test_ctx->resolv, hostname, AF_INET);
    DEBUG(7, ("Sent resolv_gethostbyname\n"));
    if (req == NULL) {
        fail("Error calling resolv_gethostbyname_send");
        return;
    }

    gettimeofday(&free_tv, NULL);
    free_tv.tv_sec += 1;
    free_tv.tv_usec = 0;
    terminate_tv.tv_sec  = free_tv.tv_sec + 1;
    terminate_tv.tv_usec = 0;

    free_timer = tevent_add_timer(test_ctx->ev, test_ctx, free_tv, resolv_free_context, test_ctx->resolv);
    if (free_timer == NULL) {
        fail("Error calling tevent_add_timer");
        return;
    }

    terminate_timer = tevent_add_timer(test_ctx->ev, test_ctx, terminate_tv, resolv_free_done, test_ctx);
    if (terminate_timer == NULL) {
        fail("Error calling tevent_add_timer");
        return;
    }

    ret = test_loop(test_ctx);
    fail_unless(ret == EOK);

    talloc_zfree(test_ctx);
}
END_TEST

static void resolv_free_req(struct tevent_context *ev,
                            struct tevent_timer *te,
                            struct timeval t, void *ptr)
{
    struct tevent_req *req = talloc_get_type(ptr, struct tevent_req);
    DEBUG(7, ("freeing the request\n"));

    talloc_free(req);
}

START_TEST(test_resolv_free_req)
{
    int ret = EOK;
    struct tevent_req *req;
    const char *hostname = "redhat.com";
    struct resolv_test_ctx *test_ctx;
    struct tevent_timer *free_timer, *terminate_timer;
    struct timeval free_tv, terminate_tv;

    ret = setup_resolv_test(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up test");
        return;
    }

    req = resolv_gethostbyname_send(test_ctx, test_ctx->ev, test_ctx->resolv, hostname, AF_INET);
    DEBUG(7, ("Sent resolv_gethostbyname\n"));
    if (req == NULL) {
        fail("Error calling resolv_gethostbyname_send");
        return;
    }

    gettimeofday(&free_tv, NULL);
    free_tv.tv_sec += 1;
    free_tv.tv_usec = 0;
    terminate_tv.tv_sec  = free_tv.tv_sec + 1;
    terminate_tv.tv_usec = 0;

    free_timer = tevent_add_timer(test_ctx->ev, test_ctx, free_tv, resolv_free_req, req);
    if (free_timer == NULL) {
        fail("Error calling tevent_add_timer");
        return;
    }

    terminate_timer = tevent_add_timer(test_ctx->ev, test_ctx, terminate_tv, resolv_free_done, test_ctx);
    if (terminate_timer == NULL) {
        fail("Error calling tevent_add_timer");
        return;
    }

    ret = test_loop(test_ctx);
    fail_unless(ret == EOK);

    talloc_zfree(test_ctx);
}
END_TEST

Suite *create_resolv_suite(void)
{
    Suite *s = suite_create("resolv");

    TCase *tc_resolv = tcase_create("RESOLV Tests");

    /* Do some testing */
    tcase_add_test(tc_resolv, test_resolv_localhost);
    tcase_add_test(tc_resolv, test_resolv_negative);
    if (use_net_test) {
        tcase_add_test(tc_resolv, test_resolv_internet);
    }
    tcase_add_test(tc_resolv, test_resolv_free_context);
    tcase_add_test(tc_resolv, test_resolv_free_req);

    /* Add all test cases to the test suite */
    suite_add_tcase(s, tc_resolv);

    return s;
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    int failure_count;
    Suite *resolv_suite;
    SRunner *sr;
    int debug;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug-level", 'd', POPT_ARG_INT, &debug, 0, "Set debug level", NULL },
        { "use-net-test", 'n', POPT_ARG_NONE, 0, 'n', "Run tests that need an active internet connection", NULL },
        POPT_TABLEEND
    };

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
    debug_level = debug;

    resolv_suite = create_resolv_suite();
    sr = srunner_create(resolv_suite);
    srunner_run_all(sr, CK_VERBOSE);
    failure_count = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (failure_count==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

