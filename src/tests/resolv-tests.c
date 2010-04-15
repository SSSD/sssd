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
#include <string.h>
#include <talloc.h>
#include <tevent.h>
#include <popt.h>
#include <arpa/inet.h>

#include "tests/common.h"
#include "util/util.h"

/* Interface under test */
#include "resolv/async_resolv.h"

static int use_net_test;
static char *txt_host;
static char *srv_host;

struct resolv_test_ctx {
    struct tevent_context *ev;
    struct resolv_ctx *resolv;

    enum {
        TESTING_HOSTNAME,
        TESTING_TXT,
        TESTING_SRV,
    } tested_function;

    int error;
    bool done;
};

static int setup_resolv_test(struct resolv_test_ctx **ctx)
{
    struct resolv_test_ctx *test_ctx;
    int ret;

    test_ctx = talloc_zero(global_talloc_context, struct resolv_test_ctx);
    if (test_ctx == NULL) {
        fail("Could not allocate memory for test context");
        return ENOMEM;
    }

    test_ctx->ev = tevent_context_init(test_ctx);
    if (test_ctx->ev == NULL) {
        fail("Could not init tevent context");
        talloc_free(test_ctx);
        return EFAULT;
    }

    ret = resolv_init(test_ctx, test_ctx->ev, 5, &test_ctx->resolv);
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

START_TEST(test_copy_hostent)
{
    void *ctx;
    struct hostent *new_he;

    char name[] = "foo.example.com";
    char alias_1[] = "bar.example.com";
    char alias_2[] = "baz.example.com";
    char *aliases[] = { alias_1, alias_2, NULL };
    char addr_1[] = { 1, 2, 3, 4 };
    char addr_2[] = { 4, 3, 2, 1 };
    char *addr_list[] = { addr_1, addr_2, NULL };
    struct hostent he = {
            name, aliases, 123 /* Whatever. */,
            sizeof(addr_1), addr_list
    };

    ctx = talloc_new(global_talloc_context);
    fail_if(ctx == NULL);

    check_leaks_push(ctx);
    new_he = resolv_copy_hostent(ctx, &he);
    fail_if(new_he == NULL);
    fail_if(strcmp(new_he->h_name, name));
    fail_if(strcmp(new_he->h_aliases[0], alias_1));
    fail_if(strcmp(new_he->h_aliases[1], alias_2));
    fail_if(new_he->h_aliases[2] != NULL);
    fail_if(new_he->h_addrtype != 123);
    fail_if(new_he->h_length != sizeof(addr_1));
    fail_if(memcmp(new_he->h_addr_list[0], addr_1, sizeof(addr_1)));
    fail_if(memcmp(new_he->h_addr_list[1], addr_2, sizeof(addr_1)));
    fail_if(new_he->h_addr_list[2] != NULL);

    talloc_free(new_he);
    check_leaks_pop(ctx);
}
END_TEST

static void test_ip_addr(struct tevent_req *req)
{
    int recv_status;
    int status;
    struct hostent *hostent;
    int i;
    struct resolv_test_ctx *test_ctx = tevent_req_callback_data(req,
                                                                struct resolv_test_ctx);

    test_ctx->done = true;

    recv_status = resolv_gethostbyname_recv(req, test_ctx,
                                            &status, NULL, &hostent);
    talloc_zfree(req);
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

        if (strcmp(addr_buf, "127.0.0.1") == 0) {
            test_ctx->error = EOK;
        }
    }
    talloc_free(hostent);
}

START_TEST(test_resolv_ip_addr)
{
    struct resolv_test_ctx *test_ctx;
    int ret = EOK;
    struct tevent_req *req;
    const char *hostname = "127.0.0.1";

    ret = setup_resolv_test(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up test");
        return;
    }

    check_leaks_push(test_ctx);
    req = resolv_gethostbyname_send(test_ctx, test_ctx->ev,
                                    test_ctx->resolv, hostname, IPV4_ONLY);
    DEBUG(7, ("Sent resolv_gethostbyname\n"));
    if (req == NULL) {
        ret = ENOMEM;
    }

    if (ret == EOK) {
        tevent_req_set_callback(req, test_ip_addr, test_ctx);
        ret = test_loop(test_ctx);
    }

    check_leaks_pop(test_ctx);
    fail_unless(ret == EOK);

    talloc_zfree(test_ctx);
}
END_TEST

static void test_localhost(struct tevent_req *req)
{
    int recv_status;
    int status;
    struct hostent *hostent;
    int i;
    struct resolv_test_ctx *test_ctx = tevent_req_callback_data(req,
                                                                struct resolv_test_ctx);

    test_ctx->done = true;

    recv_status = resolv_gethostbyname_recv(req, test_ctx,
                                            &status, NULL, &hostent);
    talloc_zfree(req);
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
    talloc_free(hostent);
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

    check_leaks_push(test_ctx);
    req = resolv_gethostbyname_send(test_ctx, test_ctx->ev,
                                    test_ctx->resolv, hostname, IPV4_FIRST);
    DEBUG(7, ("Sent resolv_gethostbyname\n"));
    if (req == NULL) {
        ret = ENOMEM;
    }

    if (ret == EOK) {
        tevent_req_set_callback(req, test_localhost, test_ctx);
        ret = test_loop(test_ctx);
    }

    check_leaks_pop(test_ctx);
    fail_unless(ret == EOK);

    talloc_zfree(test_ctx);
}
END_TEST

static void test_negative(struct tevent_req *req)
{
     int recv_status;
     int status;
     struct hostent *hostent;
     struct resolv_test_ctx *test_ctx;

     test_ctx = tevent_req_callback_data(req, struct resolv_test_ctx);
     test_ctx->done = true;

     recv_status = resolv_gethostbyname_recv(req, test_ctx,
                                             &status, NULL, &hostent);
     talloc_zfree(req);
     if (recv_status == EOK) {
         DEBUG(7, ("resolv_gethostbyname_recv succeeded in a negative test\n"));
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

    check_leaks_push(test_ctx);
    req = resolv_gethostbyname_send(test_ctx, test_ctx->ev,
                                    test_ctx->resolv, hostname, IPV4_FIRST);
    DEBUG(7, ("Sent resolv_gethostbyname\n"));
    if (req == NULL) {
        ret = ENOMEM;
    }

    if (ret == EOK) {
        tevent_req_set_callback(req, test_negative, test_ctx);
        ret = test_loop(test_ctx);
    }

    check_leaks_pop(test_ctx);

    fail_unless(ret != EOK);
    fail_unless(test_ctx->error == ARES_ENOTFOUND);
    talloc_zfree(test_ctx);
}
END_TEST

static void test_internet(struct tevent_req *req)
{
    int recv_status;
    int status;
    struct resolv_test_ctx *test_ctx;
    void *tmp_ctx;
    struct hostent *hostent = NULL;
    struct ares_txt_reply *txt_replies = NULL, *txtptr;
    struct ares_srv_reply *srv_replies = NULL, *srvptr;

    test_ctx = tevent_req_callback_data(req, struct resolv_test_ctx);

    test_ctx->done = true;

    tmp_ctx = talloc_new(test_ctx);
    check_leaks_push(tmp_ctx);

    switch (test_ctx->tested_function) {
    case TESTING_HOSTNAME:
        recv_status = resolv_gethostbyname_recv(req, tmp_ctx,
                                                &status, NULL, &hostent);
        test_ctx->error = (hostent->h_length == 0) ? ENOENT : EOK;
        break;
    case TESTING_TXT:
        recv_status = resolv_gettxt_recv(tmp_ctx, req, &status, NULL,
                                         &txt_replies);
        test_ctx->error = (txt_replies == NULL) ? ENOENT : EOK;
        for (txtptr = txt_replies; txtptr != NULL; txtptr = txtptr->next) {
            DEBUG(2, ("TXT Record: %s\n", txtptr->txt));
        }
        break;
    case TESTING_SRV:
        recv_status = resolv_getsrv_recv(tmp_ctx, req, &status, NULL,
                                         &srv_replies);
        test_ctx->error = (srv_replies == NULL) ? ENOENT : EOK;
        for (srvptr = srv_replies; srvptr != NULL; srvptr = srvptr->next) {
            DEBUG(2, ("SRV Record: %d %d %d %s\n", srvptr->weight,
                      srvptr->priority, srvptr->port,
                      srvptr->host));
        }
        break;
    default:
        recv_status = EINVAL;
        break;
    }
    talloc_zfree(req);
    fail_if(recv_status != EOK, "The recv function failed: %d", recv_status);
    DEBUG(7, ("recv status: %d\n", status));

    if (hostent != NULL) {
        talloc_free(hostent);
    } else if (txt_replies != NULL) {
        talloc_free(txt_replies);
    } else if (srv_replies != NULL) {
        talloc_free(srv_replies);
    }
    check_leaks_pop(tmp_ctx);
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
    test_ctx->tested_function = TESTING_HOSTNAME;

    check_leaks_push(test_ctx);
    req = resolv_gethostbyname_send(test_ctx, test_ctx->ev,
                                    test_ctx->resolv, hostname, IPV4_FIRST);
    DEBUG(7, ("Sent resolv_gethostbyname\n"));
    if (req == NULL) {
        ret = ENOMEM;
    }

    if (ret == EOK) {
        tevent_req_set_callback(req, test_internet, test_ctx);
        ret = test_loop(test_ctx);
    }

    fail_unless(ret == EOK);
    check_leaks_pop(test_ctx);
    talloc_zfree(test_ctx);
}
END_TEST

START_TEST(test_resolv_internet_txt)
{
    int ret;
    struct tevent_req *req;
    struct resolv_test_ctx *test_ctx;

    ret = setup_resolv_test(&test_ctx);
    fail_if(ret != EOK, "Could not set up test");
    test_ctx->tested_function = TESTING_TXT;

    check_leaks_push(test_ctx);

    req = resolv_gettxt_send(test_ctx, test_ctx->ev, test_ctx->resolv, txt_host);
    fail_if(req == NULL, "Function resolv_gettxt_send failed");

    tevent_req_set_callback(req, test_internet, test_ctx);
    ret = test_loop(test_ctx);
    fail_unless(ret == EOK);

    check_leaks_pop(test_ctx);

    talloc_zfree(test_ctx);
}
END_TEST

START_TEST(test_resolv_internet_srv)
{
    int ret;
    struct tevent_req *req;
    struct resolv_test_ctx *test_ctx;

    ret = setup_resolv_test(&test_ctx);
    fail_if(ret != EOK, "Could not set up test");
    test_ctx->tested_function = TESTING_SRV;

    check_leaks_push(test_ctx);

    req = resolv_getsrv_send(test_ctx, test_ctx->ev, test_ctx->resolv, srv_host);
    fail_if(req == NULL, "Function resolv_getsrv_send failed");

    tevent_req_set_callback(req, test_internet, test_ctx);
    ret = test_loop(test_ctx);
    fail_unless(ret == EOK);

    check_leaks_pop(test_ctx);

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

    req = resolv_gethostbyname_send(test_ctx, test_ctx->ev,
                                    test_ctx->resolv, hostname, IPV4_FIRST);
    DEBUG(7, ("Sent resolv_gethostbyname\n"));
    if (req == NULL) {
        fail("Error calling resolv_gethostbyname_send");
        goto done;
    }

    gettimeofday(&free_tv, NULL);
    free_tv.tv_sec += 1;
    free_tv.tv_usec = 0;
    terminate_tv.tv_sec  = free_tv.tv_sec + 1;
    terminate_tv.tv_usec = 0;

    free_timer = tevent_add_timer(test_ctx->ev, test_ctx, free_tv, resolv_free_context, test_ctx->resolv);
    if (free_timer == NULL) {
        fail("Error calling tevent_add_timer");
        goto done;
    }

    terminate_timer = tevent_add_timer(test_ctx->ev, test_ctx, terminate_tv, resolv_free_done, test_ctx);
    if (terminate_timer == NULL) {
        fail("Error calling tevent_add_timer");
        goto done;
    }

    ret = test_loop(test_ctx);
    fail_unless(ret == EOK);

done:
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

START_TEST(test_resolv_sort_srv_reply)
{
    int ret;
    struct ares_srv_reply *replies = NULL;
    struct ares_srv_reply *r, *prev = NULL;
    struct resolv_test_ctx *test_ctx;
    int num_replies = 3;
    int i;

    ret = setup_resolv_test(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up test");
        return;
    }

    check_leaks_push(test_ctx);

    /* prepare linked list with reversed values */
    for (i = 0; i<num_replies; i++) {
        r = talloc_zero(test_ctx, struct ares_srv_reply);
        fail_if(r == NULL);
        r->priority = num_replies-i;
        r->weight   = i;

        if (!replies) {
            replies = r;
            prev = r;
        } else {
            prev->next = r;
            prev = prev->next;
        }
    }

    /* do the sort */
    ret = resolv_sort_srv_reply(test_ctx, &replies);
    fail_if(ret != EOK);

    /* check if the list is sorted */
    prev = NULL;
    for (i = 1, r = replies; r; r=r->next, i++) {
        talloc_zfree(prev);
        prev = r;
        fail_unless(r->priority == i);
    }
    talloc_zfree(prev);

    /* check if the list is complete */
    fail_unless(i-1 == num_replies);

    /* test if the weighting algorithm runs..not much do
     * deterministically test here since it is based on
     * random weight-selection */
    replies = NULL;
    for (i = 0; i<num_replies; i++) {
        r = talloc_zero(test_ctx, struct ares_srv_reply);
        fail_if(r == NULL);
        r->priority = i % 2 + 1;
        r->weight   = i;

        if (!replies) {
            replies = r;
            prev = r;
        } else {
            prev->next = r;
            prev = prev->next;
        }
    }

    /* do the sort */
    ret = resolv_sort_srv_reply(test_ctx, &replies);
    fail_if(ret != EOK);

    /* clean up */
    prev = NULL;
    for (i = 1, r = replies; r; r=r->next, i++) {
        talloc_zfree(prev);
        prev = r;
    }
    talloc_zfree(prev);


    /* check for leaks */
    check_leaks_pop(test_ctx);
    talloc_zfree(test_ctx);
}
END_TEST

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

    check_leaks_push(test_ctx);
    req = resolv_gethostbyname_send(test_ctx, test_ctx->ev,
                                    test_ctx->resolv, hostname, IPV4_FIRST);
    DEBUG(7, ("Sent resolv_gethostbyname\n"));
    if (req == NULL) {
        fail("Error calling resolv_gethostbyname_send");
        goto done;
    }

    gettimeofday(&free_tv, NULL);
    free_tv.tv_sec += 1;
    free_tv.tv_usec = 0;
    terminate_tv.tv_sec  = free_tv.tv_sec + 1;
    terminate_tv.tv_usec = 0;

    free_timer = tevent_add_timer(test_ctx->ev, test_ctx, free_tv, resolv_free_req, req);
    if (free_timer == NULL) {
        fail("Error calling tevent_add_timer");
        goto done;
    }

    terminate_timer = tevent_add_timer(test_ctx->ev, test_ctx, terminate_tv, resolv_free_done, test_ctx);
    if (terminate_timer == NULL) {
        fail("Error calling tevent_add_timer");
        goto done;
    }

    ret = test_loop(test_ctx);
    check_leaks_pop(test_ctx);
    fail_unless(ret == EOK);

done:
    talloc_zfree(test_ctx);
}
END_TEST

Suite *create_resolv_suite(void)
{
    Suite *s = suite_create("resolv");

    TCase *tc_resolv = tcase_create("RESOLV Tests");

    tcase_add_checked_fixture(tc_resolv, leak_check_setup, leak_check_teardown);
    /* Do some testing */
    tcase_add_test(tc_resolv, test_copy_hostent);
    tcase_add_test(tc_resolv, test_resolv_ip_addr);
    tcase_add_test(tc_resolv, test_resolv_sort_srv_reply);
    if (use_net_test) {
        tcase_add_test(tc_resolv, test_resolv_internet);
        tcase_add_test(tc_resolv, test_resolv_negative);
        tcase_add_test(tc_resolv, test_resolv_localhost);
        if (txt_host != NULL) {
            tcase_add_test(tc_resolv, test_resolv_internet_txt);
        }
        if (srv_host != NULL) {
            tcase_add_test(tc_resolv, test_resolv_internet_srv);
        }
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
    int debug = 0;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug-level", 'd', POPT_ARG_INT, &debug, 0, "Set debug level", NULL },
        { "use-net-test", 'n', POPT_ARG_NONE, 0, 'n', "Run tests that need an active internet connection", NULL },
        { "txt-host", 't', POPT_ARG_STRING, 0, 't', "Specify the host used for TXT record testing", NULL },
        { "srv-host", 's', POPT_ARG_STRING, 0, 's', "Specify the host used for SRV record testing", NULL },
        POPT_TABLEEND
    };

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        case 'n':
            use_net_test = 1;
            break;
        case 't':
            txt_host = poptGetOptArg(pc);
            break;
        case 's':
            srv_host = poptGetOptArg(pc);
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

    if (!use_net_test) {
        printf("Network tests disabled. Rerun with the \"-n\" "
               "option to run the full suite of tests\n");
    }

    resolv_suite = create_resolv_suite();
    sr = srunner_create(resolv_suite);
    /* If CK_VERBOSITY is set, use that, otherwise it defaults to CK_NORMAL */
    srunner_run_all(sr, CK_ENV);
    failure_count = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (failure_count==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

