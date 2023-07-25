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
#include "tests/common_check.h"

/* Interface under test */
#include "resolv/async_resolv.h"

#define RESOLV_DEFAULT_TIMEOUT 6

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

static int setup_resolv_test(int timeout, struct resolv_test_ctx **ctx)
{
    struct resolv_test_ctx *test_ctx;
    int ret;

    test_ctx = talloc_zero(global_talloc_context, struct resolv_test_ctx);
    if (test_ctx == NULL) {
        ck_abort_msg("Could not allocate memory for test context");
        return ENOMEM;
    }

    test_ctx->ev = tevent_context_init(test_ctx);
    if (test_ctx->ev == NULL) {
        ck_abort_msg("Could not init tevent context");
        talloc_free(test_ctx);
        return EFAULT;
    }

    ret = resolv_init(test_ctx, test_ctx->ev, timeout, 2000, true, &test_ctx->resolv);
    if (ret != EOK) {
        ck_abort_msg("Could not init resolv context");
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

struct resolv_hostent *
test_create_rhostent(TALLOC_CTX *mem_ctx,
                     const char *hostname, const char *address)
{
    struct resolv_hostent *rhostent;
    int ret;
    int family;

    rhostent = talloc_zero(mem_ctx, struct resolv_hostent);
    if (!rhostent) {
        return NULL;
    }

    rhostent->name = talloc_strdup(rhostent, hostname);
    rhostent->addr_list = talloc_array(rhostent, struct resolv_addr *, 2);
    if (!rhostent->name ||
        !rhostent->addr_list) {
        goto fail;
    }

    rhostent->addr_list[0] = talloc_zero(rhostent->addr_list,
                                         struct resolv_addr);
    if (!rhostent->addr_list[0]) {
        goto fail;
    }
    rhostent->addr_list[0]->ipaddr = talloc_array(rhostent->addr_list[0],
                                                  uint8_t,
                                                  sizeof(struct in6_addr));
    if (!rhostent->addr_list[0]->ipaddr) {
        goto fail;
    }

    family = AF_INET;
    ret = inet_pton(family, address,
                    rhostent->addr_list[0]->ipaddr);
    if (ret != 1) {
        family = AF_INET6;
        ret = inet_pton(family, address,
                        rhostent->addr_list[0]->ipaddr);
        if (ret != 1) {
            goto fail;
        }
    }

    rhostent->addr_list[0]->ttl = RESOLV_DEFAULT_TTL;
    rhostent->addr_list[1] = NULL;
    rhostent->family = family;
    rhostent->aliases = NULL;

    return rhostent;

fail:
    talloc_free(rhostent);
    return NULL;
}

START_TEST(test_copy_hostent)
{
    void *ctx;
    struct resolv_hostent *rhe;

    char name[] = "foo.example.com";
    char alias_1[] = "bar.example.com";
    char alias_2[] = "baz.example.com";
    char *aliases[] = { alias_1, alias_2, NULL };
    struct in_addr addr_1 = { 1234 };
    struct in_addr addr_2 = { 5678 };
    int ttl_1 = 12;
    int ttl_2 = 34;
    char *addr_list[] = { (char *) &addr_2, (char *) &addr_1, NULL };
    struct hostent he = {
            name, aliases, AF_INET,
            sizeof(addr_1), addr_list
    };
    struct ares_addrttl attl[] = { { addr_1, ttl_1 }, { addr_2, ttl_2 } };

    ctx = talloc_new(global_talloc_context);
    sss_ck_fail_if_msg(ctx == NULL, "Failed to allocate memory");

    ck_leaks_push(ctx);

    rhe = resolv_copy_hostent_ares(ctx, &he, AF_INET, &attl, 2);

    sss_ck_fail_if_msg(rhe == NULL, "Failed to allocate memory");
    sss_ck_fail_if_msg(strcmp(rhe->name, name),
            "Unexpectag value for name. Got: %s expecting: %s",
             rhe->name, name);
    sss_ck_fail_if_msg(strcmp(rhe->aliases[0], alias_1),
            "Unexpectag value for 1st alias. Got: %s expecting: %s",
            rhe->aliases[0], alias_1);
    sss_ck_fail_if_msg(strcmp(rhe->aliases[1], alias_2),
            "Unexpectag value for 2nd alias. Got: %s expecting: %s",
            rhe->aliases[1], alias_2);
    sss_ck_fail_if_msg(rhe->aliases[2] != NULL,
            "Just 2 aliases are expected. Got: %s", rhe->aliases[2]);
    ck_assert_int_eq(rhe->family, AF_INET);
    sss_ck_fail_if_msg(memcmp(rhe->addr_list[0]->ipaddr, &addr_1, sizeof(addr_1)),
                   "Unexpected binary value for addr_list[0]->ipaddr");
    ck_assert_int_eq(rhe->addr_list[0]->ttl, ttl_1);
    sss_ck_fail_if_msg(memcmp(rhe->addr_list[1]->ipaddr, &addr_2, sizeof(addr_2)),
                   "Unexpected binary value for rhe->addr_list[1]->ipaddr");
    ck_assert_int_eq(rhe->addr_list[1]->ttl, ttl_2);
    sss_ck_fail_if_msg(rhe->addr_list[2] != NULL,
            "Just 2 ip addresses are expected. 3rd has to be NULL");

    talloc_zfree(rhe);

    rhe = resolv_copy_hostent(ctx, &he);
    sss_ck_fail_if_msg(rhe == NULL, "Failed to allocate memory");
    sss_ck_fail_if_msg(strcmp(rhe->name, name),
            "Unexpectag value for name. Got: %s expecting: %s",
            rhe->name, name);
    sss_ck_fail_if_msg(strcmp(rhe->aliases[0], alias_1),
            "Unexpectag value for 1st alias. Got: %s expecting: %s",
            rhe->aliases[0], alias_1);
    sss_ck_fail_if_msg(strcmp(rhe->aliases[1], alias_2),
            "Unexpectag value for 2nd alias. Got: %s expecting: %s",
            rhe->aliases[1], alias_2);
    sss_ck_fail_if_msg(rhe->aliases[2] != NULL,
            "Just 2 aliases are expected. Got: %s", rhe->aliases[2]);
    ck_assert_int_eq(rhe->family, AF_INET);
    sss_ck_fail_if_msg(memcmp(rhe->addr_list[0]->ipaddr, &addr_2, sizeof(addr_1)),
                   "Unexpected binary value for addr_list[0]->ipaddr");
    ck_assert_int_eq(rhe->addr_list[0]->ttl, RESOLV_DEFAULT_TTL);
    sss_ck_fail_if_msg(memcmp(rhe->addr_list[1]->ipaddr, &addr_1, sizeof(addr_2)),
                   "Unexpected binary value for addr_list[1]->ipaddr");
    ck_assert_int_eq(rhe->addr_list[1]->ttl, RESOLV_DEFAULT_TTL);
    sss_ck_fail_if_msg(rhe->addr_list[2] != NULL,
            "Just 2 ip addresses are expected. 3rd has to be NULL");

    talloc_free(rhe);

    ck_leaks_pop(ctx);
}
END_TEST

START_TEST(test_address_to_string)
{
    void *ctx;
    struct resolv_hostent *rhe;
    char *str_addr;
    char *ptr_addr;

    ctx = talloc_new(global_talloc_context);
    sss_ck_fail_if_msg(ctx == NULL, "Failed to allocate memory");
    ck_leaks_push(ctx);

    rhe = test_create_rhostent(ctx, "www.example.com", "1.2.3.4");
    sss_ck_fail_if_msg(rhe == NULL, "Failed to allocate memory");

    str_addr = resolv_get_string_address_index(ctx, rhe, 0);
    sss_ck_fail_if_msg(str_addr == NULL, "Failed to allocate memory");
    ck_assert_msg(strcmp(str_addr, "1.2.3.4") == 0, "Unexpected address\n");
    talloc_free(str_addr);

    ptr_addr = resolv_get_string_ptr_address(ctx, rhe->family,
                                             rhe->addr_list[0]->ipaddr);
    sss_ck_fail_if_msg(ptr_addr == NULL, "Failed to allocate memory");
    ck_assert_msg(strcmp(ptr_addr, "4.3.2.1.in-addr.arpa.") == 0, "Unexpected PTR address\n");
    talloc_free(ptr_addr);

    talloc_free(rhe);

    rhe = test_create_rhostent(ctx, "www6.example.com", "2607:f8b0:400c:c03::6a");
    sss_ck_fail_if_msg(rhe == NULL, "Failed to allocate memory");

    str_addr = resolv_get_string_address_index(ctx, rhe, 0);
    sss_ck_fail_if_msg(str_addr == NULL, "resolv_get_string_address_index failed");
    ck_assert_msg(strcmp(str_addr, "2607:f8b0:400c:c03::6a") == 0, "Unexpected address\n");
    talloc_free(str_addr);

    ptr_addr = resolv_get_string_ptr_address(ctx, rhe->family,
                                             rhe->addr_list[0]->ipaddr);
    sss_ck_fail_if_msg(ptr_addr == NULL, "resolv_get_string_ptr_address failed");
    ck_assert_msg(strcmp(ptr_addr,
                       "a.6.0.0.0.0.0.0.0.0.0.0.0.0.0.0.3.0.c.0.c.0.0.4.0.b.8.f.7.0.6.2.ip6.arpa.") == 0, "Unexpected PTR address\n");
    talloc_free(ptr_addr);

    talloc_free(rhe);
    ck_leaks_pop(ctx);
}
END_TEST

static void test_ip_addr(struct tevent_req *req)
{
    int recv_status;
    int status;
    struct resolv_hostent *rhostent;
    int i;
    struct resolv_test_ctx *test_ctx = tevent_req_callback_data(req,
                                                                struct resolv_test_ctx);

    test_ctx->done = true;

    recv_status = resolv_gethostbyname_recv(req, test_ctx,
                                            &status, NULL, &rhostent);
    talloc_zfree(req);
    if (recv_status != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "resolv_gethostbyname_recv failed: %d\n", recv_status);
        test_ctx->error = recv_status;
        return;
    }
    DEBUG(SSSDBG_TRACE_LIBS, "resolv_gethostbyname_recv status: %d\n", status);

    test_ctx->error = ENOENT;
    for (i = 0; rhostent->addr_list[i]; i++) {
        char addr_buf[256];
        inet_ntop(rhostent->family,
                  rhostent->addr_list[i]->ipaddr,
                  addr_buf, sizeof(addr_buf));

        if (strcmp(addr_buf, "127.0.0.1") == 0) {
            test_ctx->error = EOK;
        }
    }
    talloc_free(rhostent);
}

START_TEST(test_resolv_ip_addr)
{
    struct resolv_test_ctx *test_ctx;
    int ret = EOK;
    struct tevent_req *req;
    const char *hostname = "127.0.0.1";

    ret = setup_resolv_test(RESOLV_DEFAULT_TIMEOUT, &test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up test");
        return;
    }

    ck_leaks_push(test_ctx);
    req = resolv_gethostbyname_send(test_ctx, test_ctx->ev,
                                    test_ctx->resolv, hostname, IPV4_ONLY,
                                    default_host_dbs);
    DEBUG(SSSDBG_TRACE_LIBS, "Sent resolv_gethostbyname\n");
    if (req == NULL) {
        ret = ENOMEM;
    }

    if (ret == EOK) {
        tevent_req_set_callback(req, test_ip_addr, test_ctx);
        ret = test_loop(test_ctx);
    }

    ck_leaks_pop(test_ctx);
    ck_assert_msg(ret == EOK, "test_loop failed with error: %d", ret);

    talloc_zfree(test_ctx);
}
END_TEST

static void test_unix(struct tevent_req *req)
{
    int recv_status;
    int status;
    struct resolv_hostent *rhostent;
    struct resolv_test_ctx *test_ctx = tevent_req_callback_data(req,
                                                                struct resolv_test_ctx);

    test_ctx->done = true;

    recv_status = resolv_gethostbyname_recv(req, test_ctx,
                                            &status, NULL, &rhostent);
    talloc_zfree(req);
    if (recv_status != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "resolv_gethostbyname_recv failed: %d\n", recv_status);
        test_ctx->error = recv_status;
        return;
    }
    DEBUG(SSSDBG_TRACE_LIBS, "resolv_gethostbyname_recv status: %d\n", status);

    test_ctx->error = ENOENT;
    if (rhostent->addr_list[0] == NULL) {
        test_ctx->error = EOK;
    }
    talloc_free(rhostent);
}

START_TEST(test_resolv_unix)
{
    struct resolv_test_ctx *test_ctx;
    int ret = EOK;
    struct tevent_req *req;
    const char *path = "/tmp/socket";

    ret = setup_resolv_test(RESOLV_DEFAULT_TIMEOUT, &test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up test");
        return;
    }

    ck_leaks_push(test_ctx);
    req = resolv_gethostbyname_send(test_ctx, test_ctx->ev,
                                    test_ctx->resolv, path, IPV4_ONLY,
                                    default_host_dbs);
    DEBUG(SSSDBG_TRACE_LIBS, "Sent resolv_gethostbyname\n");
    if (req == NULL) {
        ret = ENOMEM;
    }

    if (ret == EOK) {
        tevent_req_set_callback(req, test_unix, test_ctx);
        ret = test_loop(test_ctx);
    }

    ck_leaks_pop(test_ctx);
    ck_assert_msg(ret == EOK, "test_loop failed with error: %d", ret);

    talloc_zfree(test_ctx);
}
END_TEST

static void test_localhost(struct tevent_req *req)
{
    int recv_status;
    int status;
    struct resolv_hostent *rhostent;
    int i;
    struct resolv_test_ctx *test_ctx = tevent_req_callback_data(req,
                                                                struct resolv_test_ctx);

    test_ctx->done = true;

    recv_status = resolv_gethostbyname_recv(req, test_ctx,
                                            &status, NULL, &rhostent);
    talloc_zfree(req);
    if (recv_status != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "resolv_gethostbyname_recv failed: %d\n", recv_status);
        test_ctx->error = recv_status;
        return;
    }
    DEBUG(SSSDBG_TRACE_LIBS, "resolv_gethostbyname_recv status: %d\n", status);

    test_ctx->error = ENOENT;
    for (i = 0; rhostent->addr_list[i]; i++) {
        char addr_buf[256];
        inet_ntop(rhostent->family, rhostent->addr_list[i]->ipaddr,
                  addr_buf, sizeof(addr_buf));

        /* test that localhost resolves to 127.0.0.1 or ::1 */
        if (strcmp(addr_buf, "127.0.0.1") == 0 || strcmp(addr_buf, "::1") == 0) {
            test_ctx->error = EOK;
        }
    }
    talloc_free(rhostent);
}

START_TEST(test_resolv_localhost)
{
    struct resolv_test_ctx *test_ctx;
    int ret = EOK;
    struct tevent_req *req;
    const char *hostname = "localhost.localdomain";

    ret = setup_resolv_test(RESOLV_DEFAULT_TIMEOUT, &test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up test");
        return;
    }

    ck_leaks_push(test_ctx);
    req = resolv_gethostbyname_send(test_ctx, test_ctx->ev,
                                    test_ctx->resolv, hostname, IPV4_FIRST,
                                    default_host_dbs);
    DEBUG(SSSDBG_TRACE_LIBS, "Sent resolv_gethostbyname\n");
    if (req == NULL) {
        ret = ENOMEM;
    }

    if (ret == EOK) {
        tevent_req_set_callback(req, test_localhost, test_ctx);
        ret = test_loop(test_ctx);
    }

    ck_leaks_pop(test_ctx);
    ck_assert_msg(ret == EOK, "test_loop failed with error: %d", ret);

    talloc_zfree(test_ctx);
}
END_TEST

static void test_negative(struct tevent_req *req)
{
     int recv_status;
     int status;
     struct resolv_hostent *hostent;
     struct resolv_test_ctx *test_ctx;

     test_ctx = tevent_req_callback_data(req, struct resolv_test_ctx);
     test_ctx->done = true;

     recv_status = resolv_gethostbyname_recv(req, test_ctx,
                                             &status, NULL, &hostent);
     talloc_zfree(req);
     if (recv_status == EOK) {
         DEBUG(SSSDBG_TRACE_LIBS,
               "resolv_gethostbyname_recv succeeded in a negative test\n");
         return;
     }

     test_ctx->error = status;
     DEBUG(SSSDBG_OP_FAILURE,
           "resolv_gethostbyname_recv status: %d: %s\n", status, resolv_strerror(status));
}

START_TEST(test_resolv_negative)
{
    int ret = EOK;
    struct tevent_req *req;
    const char *hostname = "sssd.foo";
    struct resolv_test_ctx *test_ctx;

    ret = setup_resolv_test(RESOLV_DEFAULT_TIMEOUT, &test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up test");
        return;
    }

    ck_leaks_push(test_ctx);
    req = resolv_gethostbyname_send(test_ctx, test_ctx->ev,
                                    test_ctx->resolv, hostname, IPV4_FIRST,
                                    default_host_dbs);
    DEBUG(SSSDBG_TRACE_LIBS, "Sent resolv_gethostbyname\n");
    if (req == NULL) {
        ret = ENOMEM;
    }

    if (ret == EOK) {
        tevent_req_set_callback(req, test_negative, test_ctx);
        ret = test_loop(test_ctx);
    }

    ck_leaks_pop(test_ctx);

    ck_assert_msg(ret != EOK, "test_loop must failed but got: EOK");
    ck_assert_int_eq(test_ctx->error, ARES_ENOTFOUND);
    talloc_zfree(test_ctx);
}
END_TEST

static void test_internet(struct tevent_req *req)
{
    int recv_status;
    int status;
    struct resolv_test_ctx *test_ctx;
    void *tmp_ctx;
    struct resolv_hostent *rhostent = NULL;
    struct ares_txt_reply *txt_replies = NULL, *txtptr;
    struct ares_srv_reply *srv_replies = NULL, *srvptr;
    int i;

    test_ctx = tevent_req_callback_data(req, struct resolv_test_ctx);

    test_ctx->done = true;

    tmp_ctx = talloc_new(test_ctx);
    ck_leaks_push(tmp_ctx);

    switch (test_ctx->tested_function) {
    case TESTING_HOSTNAME:
        recv_status = resolv_gethostbyname_recv(req, tmp_ctx,
                                                &status, NULL, &rhostent);
        test_ctx->error = (rhostent->name == NULL) ? ENOENT : EOK;
        if (test_ctx->error == EOK) {
            char addr_buf[256];
            for (i=0; rhostent->addr_list[i]; i++) {
                inet_ntop(rhostent->family,
                          rhostent->addr_list[i]->ipaddr,
                          addr_buf, sizeof(addr_buf));
                DEBUG(SSSDBG_OP_FAILURE, "Found address %s with TTL %d\n",
                          addr_buf, rhostent->addr_list[i]->ttl);
            }
        }
        break;
    case TESTING_TXT:
        recv_status = resolv_gettxt_recv(tmp_ctx, req, &status, NULL,
                                         &txt_replies);
        test_ctx->error = (txt_replies == NULL) ? ENOENT : EOK;
        for (txtptr = txt_replies; txtptr != NULL; txtptr = txtptr->next) {
            DEBUG(SSSDBG_OP_FAILURE, "TXT Record: %s\n", txtptr->txt);
        }
        break;
    case TESTING_SRV:
        recv_status = resolv_getsrv_recv(tmp_ctx, req, &status, NULL,
                                         &srv_replies, NULL);
        test_ctx->error = (srv_replies == NULL) ? ENOENT : EOK;
        for (srvptr = srv_replies; srvptr != NULL; srvptr = srvptr->next) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "SRV Record: %d %d %d %s\n", srvptr->weight,
                      srvptr->priority, srvptr->port,
                      srvptr->host);
        }
        break;
    default:
        recv_status = EINVAL;
        break;
    }
    talloc_zfree(req);
    sss_ck_fail_if_msg(recv_status != EOK, "The recv function failed: %d", recv_status);
    DEBUG(SSSDBG_TRACE_LIBS, "recv status: %d\n", status);

    if (rhostent != NULL) {
        talloc_free(rhostent);
    } else if (txt_replies != NULL) {
        talloc_free(txt_replies);
    } else if (srv_replies != NULL) {
        talloc_free(srv_replies);
    }
    ck_leaks_pop(tmp_ctx);
}

START_TEST(test_resolv_internet)
{
    int ret = EOK;
    struct tevent_req *req;
    const char *hostname = "redhat.com";
    struct resolv_test_ctx *test_ctx;

    ret = setup_resolv_test(RESOLV_DEFAULT_TIMEOUT, &test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up test");
        return;
    }
    test_ctx->tested_function = TESTING_HOSTNAME;

    ck_leaks_push(test_ctx);
    req = resolv_gethostbyname_send(test_ctx, test_ctx->ev,
                                    test_ctx->resolv, hostname, IPV4_FIRST,
                                    default_host_dbs);
    DEBUG(SSSDBG_TRACE_LIBS, "Sent resolv_gethostbyname\n");
    if (req == NULL) {
        ret = ENOMEM;
    }

    if (ret == EOK) {
        tevent_req_set_callback(req, test_internet, test_ctx);
        ret = test_loop(test_ctx);
    }

    ck_assert_msg(ret == EOK, "test_loop failed with error: %d", ret);
    ck_leaks_pop(test_ctx);
    talloc_zfree(test_ctx);
}
END_TEST

START_TEST(test_resolv_internet_txt)
{
    int ret;
    struct tevent_req *req;
    struct resolv_test_ctx *test_ctx;

    ret = setup_resolv_test(RESOLV_DEFAULT_TIMEOUT, &test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up test");
    test_ctx->tested_function = TESTING_TXT;

    ck_leaks_push(test_ctx);

    req = resolv_gettxt_send(test_ctx, test_ctx->ev, test_ctx->resolv, txt_host);
    sss_ck_fail_if_msg(req == NULL, "Function resolv_gettxt_send failed");

    tevent_req_set_callback(req, test_internet, test_ctx);
    ret = test_loop(test_ctx);
    ck_assert_msg(ret == EOK, "test_loop failed with error: %d", ret);

    ck_leaks_pop(test_ctx);

    talloc_zfree(test_ctx);
}
END_TEST

START_TEST(test_resolv_internet_srv)
{
    int ret;
    struct tevent_req *req;
    struct resolv_test_ctx *test_ctx;

    ret = setup_resolv_test(RESOLV_DEFAULT_TIMEOUT, &test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up test");
    test_ctx->tested_function = TESTING_SRV;

    ck_leaks_push(test_ctx);

    req = resolv_getsrv_send(test_ctx, test_ctx->ev, test_ctx->resolv, srv_host);
    sss_ck_fail_if_msg(req == NULL, "Function resolv_getsrv_send failed");

    tevent_req_set_callback(req, test_internet, test_ctx);
    ret = test_loop(test_ctx);
    ck_assert_msg(ret == EOK, "test_loop failed with error: %d", ret);

    ck_leaks_pop(test_ctx);

    talloc_zfree(test_ctx);
}
END_TEST

static void resolv_free_context(struct tevent_context *ev,
                                struct tevent_timer *te,
                                struct timeval t, void *ptr)
{
    struct resolv_ctx *rctx = talloc_get_type(ptr, struct resolv_ctx);
    DEBUG(SSSDBG_TRACE_LIBS, "freeing the context\n");

    talloc_free(rctx);
}

static void resolv_free_done(struct tevent_context *ev,
                             struct tevent_timer *te,
                             struct timeval t, void *ptr)
{
    struct resolv_test_ctx *tctx = talloc_get_type(ptr, struct resolv_test_ctx);
    DEBUG(SSSDBG_TRACE_LIBS, "marking test as done\n");

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

    ret = setup_resolv_test(RESOLV_DEFAULT_TIMEOUT, &test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up test");
        return;
    }

    req = resolv_gethostbyname_send(test_ctx, test_ctx->ev,
                                    test_ctx->resolv, hostname, IPV4_FIRST,
                                    default_host_dbs);
    DEBUG(SSSDBG_TRACE_LIBS, "Sent resolv_gethostbyname\n");
    if (req == NULL) {
        ck_abort_msg("Error calling resolv_gethostbyname_send");
        goto done;
    }

    gettimeofday(&free_tv, NULL);
    free_tv.tv_sec += 1;
    free_tv.tv_usec = 0;
    terminate_tv.tv_sec  = free_tv.tv_sec + 1;
    terminate_tv.tv_usec = 0;

    free_timer = tevent_add_timer(test_ctx->ev, test_ctx, free_tv, resolv_free_context, test_ctx->resolv);
    if (free_timer == NULL) {
        ck_abort_msg("Error calling tevent_add_timer");
        goto done;
    }

    terminate_timer = tevent_add_timer(test_ctx->ev, test_ctx, terminate_tv, resolv_free_done, test_ctx);
    if (terminate_timer == NULL) {
        ck_abort_msg("Error calling tevent_add_timer");
        goto done;
    }

    ret = test_loop(test_ctx);
    ck_assert_msg(ret == EOK, "test_loop failed with error: %d", ret);

done:
    talloc_zfree(test_ctx);
}
END_TEST

static void resolv_free_req(struct tevent_context *ev,
                            struct tevent_timer *te,
                            struct timeval t, void *ptr)
{
    struct tevent_req *req = talloc_get_type(ptr, struct tevent_req);
    DEBUG(SSSDBG_TRACE_LIBS, "freeing the request\n");

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

    ret = setup_resolv_test(RESOLV_DEFAULT_TIMEOUT, &test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up test");
        return;
    }

    ck_leaks_push(test_ctx);

    /* prepare linked list with reversed values */
    for (i = 0; i<num_replies; i++) {
        r = talloc_zero(test_ctx, struct ares_srv_reply);
        sss_ck_fail_if_msg(r == NULL, "Failed to allocate memory");
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
    ret = resolv_sort_srv_reply(&replies);
    sss_ck_fail_if_msg(ret != EOK, "resolv_sort_srv_reply failed with error: %d", ret);

    /* check if the list is sorted */
    prev = NULL;
    for (i = 1, r = replies; r; r=r->next, i++) {
        talloc_zfree(prev);
        prev = r;
        ck_assert_int_eq(r->priority, i);
    }
    talloc_zfree(prev);

    /* check if the list is complete */
    ck_assert_int_eq(i - 1, num_replies);

    /* test if the weighting algorithm runs..not much do
     * deterministically test here since it is based on
     * random weight-selection */
    replies = NULL;
    for (i = 0; i<num_replies; i++) {
        r = talloc_zero(test_ctx, struct ares_srv_reply);
        sss_ck_fail_if_msg(r == NULL, "Failed to allocate memory");
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
    ret = resolv_sort_srv_reply(&replies);
    sss_ck_fail_if_msg(ret != EOK, "resolv_sort_srv_reply failed with error: %d", ret);

    /* clean up */
    prev = NULL;
    for (r = replies; r; r=r->next) {
        talloc_zfree(prev);
        prev = r;
    }
    talloc_zfree(prev);


    /* check for leaks */
    ck_leaks_pop(test_ctx);
    talloc_zfree(test_ctx);
}
END_TEST

START_TEST(test_resolv_sort_srv_reply_zero_weight)
{
    int ret;
    struct ares_srv_reply *replies = NULL;
    struct ares_srv_reply *r, *prev = NULL;
    struct resolv_test_ctx *test_ctx;
    int num_replies = 6;
    int i;

    ret = setup_resolv_test(RESOLV_DEFAULT_TIMEOUT, &test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up test");
        return;
    }

    ck_leaks_push(test_ctx);

    /* prepare linked list */
    for (i = 0; i < num_replies; i++) {
        r = talloc_zero(test_ctx, struct ares_srv_reply);
        sss_ck_fail_if_msg(r == NULL, "Failed to allocate memory");

        r->priority = 20;
        r->priority = i <= 3 ? 10 : r->priority;
        r->priority = i <= 1 ? 0 : r->priority;
        r->weight   = 0;

        if (replies == NULL) {
            replies = r;
            prev = r;
        } else {
            prev->next = r;
            prev = prev->next;
        }
    }

    /* do the sort */
    ret = resolv_sort_srv_reply(&replies);
    sss_ck_fail_if_msg(ret != EOK, "resolv_sort_srv_reply failed with error: %d", ret);

    /* check if the list contains all values and is sorted */
    for (i = 0, r = replies; r != NULL; r = r->next, i++) {
        if (r->next != NULL) {
            ck_assert_msg(r->priority <= r->next->priority,
                        "Got unsorted values. %d <= %d",
                        r->priority, r->next->priority);
        }
    }
    ck_assert_int_eq(i, num_replies);

    /* clean up */
    prev = NULL;
    for (r = replies; r != NULL; r=r->next) {
        talloc_zfree(prev);
        prev = r;
    }
    talloc_zfree(prev);


    /* check for leaks */
    ck_leaks_pop(test_ctx);
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

    ret = setup_resolv_test(RESOLV_DEFAULT_TIMEOUT, &test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up test");
        return;
    }

    ck_leaks_push(test_ctx);
    req = resolv_gethostbyname_send(test_ctx, test_ctx->ev,
                                    test_ctx->resolv, hostname, IPV4_FIRST,
                                    default_host_dbs);
    DEBUG(SSSDBG_TRACE_LIBS, "Sent resolv_gethostbyname\n");
    if (req == NULL) {
        ck_abort_msg("Error calling resolv_gethostbyname_send");
        goto done;
    }

    gettimeofday(&free_tv, NULL);
    free_tv.tv_sec += 1;
    free_tv.tv_usec = 0;
    /* Give enough time for c-ares request to terminate */
    terminate_tv.tv_sec  = free_tv.tv_sec + 6;
    terminate_tv.tv_usec = 0;

    free_timer = tevent_add_timer(test_ctx->ev, test_ctx, free_tv, resolv_free_req, req);
    if (free_timer == NULL) {
        ck_abort_msg("Error calling tevent_add_timer");
        goto done;
    }

    terminate_timer = tevent_add_timer(test_ctx->ev, test_ctx, terminate_tv, resolv_free_done, test_ctx);
    if (terminate_timer == NULL) {
        ck_abort_msg("Error calling tevent_add_timer");
        goto done;
    }

    ret = test_loop(test_ctx);
    ck_leaks_pop(test_ctx);
    ck_assert_msg(ret == EOK, "test_loop failed with error: %d", ret);

done:
    talloc_zfree(test_ctx);
}
END_TEST

static void test_timeout(struct tevent_req *req)
{
    int recv_status;
    int status;
    struct resolv_test_ctx *test_ctx;
    TALLOC_CTX *tmp_ctx;
    struct resolv_hostent *rhostent = NULL;

    test_ctx = tevent_req_callback_data(req, struct resolv_test_ctx);

    test_ctx->done = true;

    tmp_ctx = talloc_new(test_ctx);
    ck_leaks_push(tmp_ctx);

    ck_assert_int_eq(test_ctx->tested_function, TESTING_HOSTNAME);
    recv_status = resolv_gethostbyname_recv(req, tmp_ctx,
                                            &status, NULL, &rhostent);
    talloc_zfree(req);
    ck_assert_int_eq(recv_status, ETIMEDOUT);
    ck_assert_int_eq(status, ARES_ETIMEOUT);
    ck_leaks_pop(tmp_ctx);
    talloc_free(tmp_ctx);
}

START_TEST(test_resolv_timeout)
{
    struct resolv_test_ctx *test_ctx;
    errno_t ret;
    struct tevent_req *req;
    const char *hostname = "redhat.com";

    ret = setup_resolv_test(0, &test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up test");
        return;
    }

    test_ctx->tested_function = TESTING_HOSTNAME;

    req = resolv_gethostbyname_send(test_ctx, test_ctx->ev,
                                    test_ctx->resolv, hostname, IPV4_FIRST,
                                    default_host_dbs);
    DEBUG(SSSDBG_TRACE_LIBS, "Sent resolv_gethostbyname\n");
    if (req == NULL) {
        ret = ENOMEM;
    }

    if (ret == EOK) {
        tevent_req_set_callback(req, test_timeout, test_ctx);
        ret = test_loop(test_ctx);
    }

    ck_assert_msg(ret == EOK, "test_loop failed with error: %d", ret);
    talloc_zfree(test_ctx);
}
END_TEST

Suite *create_resolv_suite(void)
{
    Suite *s = suite_create("resolv");

    TCase *tc_resolv = tcase_create("RESOLV Tests");
    tcase_set_timeout(tc_resolv, 8);

    tcase_add_checked_fixture(tc_resolv, ck_leak_check_setup, ck_leak_check_teardown);
    /* Do some testing */
    tcase_add_test(tc_resolv, test_copy_hostent);
    tcase_add_test(tc_resolv, test_address_to_string);
    tcase_add_test(tc_resolv, test_resolv_ip_addr);
    tcase_add_test(tc_resolv, test_resolv_unix);
    tcase_add_test(tc_resolv, test_resolv_sort_srv_reply);
    tcase_add_test(tc_resolv, test_resolv_sort_srv_reply_zero_weight);
    if (use_net_test) {
        tcase_add_test(tc_resolv, test_resolv_internet);
        tcase_add_test(tc_resolv, test_resolv_negative);
        tcase_add_test(tc_resolv, test_resolv_localhost);
        tcase_add_test(tc_resolv, test_resolv_timeout);
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
        SSSD_DEBUG_OPTS
        { "use-net-test", 'n', POPT_ARG_NONE, 0, 'n', "Run tests that need an active internet connection", NULL },
        { "txt-host", 't', POPT_ARG_STRING, 0, 't', "Specify the host used for TXT record testing", NULL },
        { "srv-host", 's', POPT_ARG_STRING, 0, 's', "Specify the host used for SRV record testing", NULL },
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

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

    DEBUG_CLI_INIT(debug);

    if (!use_net_test) {
        printf("Network tests disabled. Rerun with the \"-n\" "
               "option to run the full suite of tests\n");
    }

    tests_set_cwd();

    resolv_suite = create_resolv_suite();
    sr = srunner_create(resolv_suite);
    /* If CK_VERBOSITY is set, use that, otherwise it defaults to CK_NORMAL */
    srunner_run_all(sr, CK_ENV);
    failure_count = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (failure_count==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
