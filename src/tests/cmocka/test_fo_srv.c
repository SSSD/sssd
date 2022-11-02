/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2014 Red Hat

    SSSD tests: Resolver tests using a fake resolver library

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

#include <talloc.h>
#include <tevent.h>
#include <errno.h>
#include <popt.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <stdarg.h>
#include <stdlib.h>

#include "providers/fail_over_srv.h"
#include "tests/cmocka/common_mock.h"
#include "tests/cmocka/common_mock_resp.h"

#define TEST_RESOLV_TIMEOUT 5
#define TEST_FO_TIMEOUT     3000
#define TEST_SRV_TTL        500
#define TEST_SRV_SHORT_TTL  2

static TALLOC_CTX *global_mock_context = NULL;

enum host_database default_host_dbs[] = { DB_FILES, DB_DNS, DB_SENTINEL };

struct resolv_ctx {
    int foo;
};

/* mock resolver interface. The resolver test is separate */
int resolv_init(TALLOC_CTX *mem_ctx, struct tevent_context *ev_ctx,
                int timeout, int ares_timeout, bool use_search_list,
                struct resolv_ctx **ctxp)
{
    *ctxp = talloc(mem_ctx, struct resolv_ctx);
    return EOK;
}

struct tevent_req *
resolv_gethostbyname_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
                          struct resolv_ctx *ctx, const char *name,
                          enum restrict_family family_order,
                          enum host_database *db)
{
    return test_req_succeed_send(mem_ctx, ev);
}

int resolv_gethostbyname_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                              int *status, int *timeouts,
                              struct resolv_hostent **rhostent)
{
    return test_request_recv(req);
}

const char *resolv_strerror(int ares_code)
{
    return NULL;
}

struct tevent_req *resolv_discover_srv_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct resolv_ctx *resolv_ctx,
                                            const char *service,
                                            const char *protocol,
                                            const char **discovery_domains)
{
    return test_req_succeed_send(mem_ctx, ev);
}

errno_t resolv_discover_srv_recv(TALLOC_CTX *mem_ctx,
                                 struct tevent_req *req,
                                 struct ares_srv_reply **_reply_list,
                                 uint32_t *_ttl,
                                 char **_dns_domain)
{
    struct ares_srv_reply *reply_list;
    uint32_t ttl;
    char *dns_domain;

    /* Need to always consume all mocked values */
    reply_list = sss_mock_ptr_type(struct ares_srv_reply *);
    ttl = sss_mock_ptr_type(uint32_t);
    dns_domain = sss_mock_ptr_type(char *);

    if (_reply_list != NULL) {
        *_reply_list = reply_list;
    }

    if (_ttl != NULL) {
        *_ttl = ttl;
    }

    if (_dns_domain != NULL) {
        *_dns_domain = dns_domain;
    }

    return test_request_recv(req);
}

struct ares_srv_reply *pop_lowest_prio(struct ares_srv_reply **r)
{
    struct ares_srv_reply *lowest;
    struct ares_srv_reply *iter;
    struct ares_srv_reply *prev;

    lowest = *r;
    iter = lowest;
    while (iter != NULL) {
        if (iter->priority < lowest->priority) {
            lowest = iter;
        }

        iter = iter->next;
    }

    prev = NULL;
    iter = *r;
    while (iter != lowest) {
        prev = iter;
        iter = iter->next;
    }

    /* iter points to the lowest prio. Prev points to the item before */
    if (prev) {
        prev->next = lowest->next;
    } else {
        *r = lowest->next;
    }

    return lowest;
}

int resolv_sort_srv_reply(struct ares_srv_reply **reply)
{
    struct ares_srv_reply *r;
    struct ares_srv_reply *lowest;
    struct ares_srv_reply *sorted = NULL;
    struct ares_srv_reply *sorted_head = NULL;

    r = *reply;
    if (r == NULL || r->next == NULL) {
        return EOK;
    }

    do {
        lowest = pop_lowest_prio(&r);
        if (sorted) {
            sorted->next = lowest;
            sorted = sorted->next;
        } else {
            sorted = lowest;
            sorted_head = sorted;
        }
    } while (r != NULL);

    *reply = sorted_head;
    return EOK;
}

struct tevent_req *resolv_get_domain_send(TALLOC_CTX *mem_ctx,
                                          struct tevent_context *ev,
                                          struct resolv_ctx *resolv_ctx,
                                          const char *hostname,
                                          enum host_database *host_dbs,
                                          enum restrict_family family_order)
{
    return test_req_succeed_send(mem_ctx, ev);
}

errno_t resolv_get_domain_recv(TALLOC_CTX *mem_ctx,
                               struct tevent_req *req,
                               char **_dns_domain)
{
    return test_request_recv(req);
}

/* The unit test */
struct test_fo_ctx {
    struct resolv_ctx *resolv;
    struct fo_ctx *fo_ctx;
    struct fo_resolve_srv_dns_ctx *srv_ctx;
    struct fo_service *fo_svc;
    struct sss_test_ctx *ctx;
    int ttl;

    struct fo_server *srv;

    int num_done;
};

int test_fo_srv_data_cmp(void *ud1, void *ud2)
{
    return strcasecmp((char*) ud1, (char*) ud2);
}

static int test_fo_setup(void **state)
{
    struct test_fo_ctx *test_ctx;
    errno_t ret;
    struct fo_options fopts;

    assert_true(leak_check_setup());
    global_mock_context = talloc_new(global_talloc_context);
    assert_non_null(global_mock_context);

    test_ctx = talloc_zero(global_mock_context,
                           struct test_fo_ctx);
    assert_non_null(test_ctx);

    test_ctx->ctx = create_ev_test_ctx(test_ctx);
    assert_non_null(test_ctx->ctx);

    ret = resolv_init(test_ctx, test_ctx->ctx->ev,
                      TEST_RESOLV_TIMEOUT, 2000, true, &test_ctx->resolv);
    assert_non_null(test_ctx->resolv);

    memset(&fopts, 0, sizeof(fopts));
    fopts.retry_timeout = TEST_FO_TIMEOUT;
    fopts.family_order  = IPV4_FIRST;

    test_ctx->fo_ctx = fo_context_init(test_ctx, &fopts);
    assert_non_null(test_ctx->fo_ctx);

    ret = fo_new_service(test_ctx->fo_ctx, "ldap",
                         test_fo_srv_data_cmp,
                         &test_ctx->fo_svc);
    assert_int_equal(ret, ERR_OK);

    *state = test_ctx;
    return 0;
}

static int test_fo_teardown(void **state)
{
    struct test_fo_ctx *test_ctx =
        talloc_get_type(*state, struct test_fo_ctx);

    talloc_free(test_ctx);
    talloc_free(global_mock_context);
    assert_true(leak_check_teardown());
    return 0;
}

static int test_fo_srv_setup(void **state)
{
    struct test_fo_ctx *test_ctx;
    bool ok;

    test_fo_setup(state);
    test_ctx = *state;

    test_ctx->srv_ctx = fo_resolve_srv_dns_ctx_init(test_ctx, test_ctx->resolv,
                                                    IPV4_FIRST, default_host_dbs,
                                                    "client.sssd.com", "sssd.local");
    assert_non_null(test_ctx->srv_ctx);

    ok = fo_set_srv_lookup_plugin(test_ctx->fo_ctx,
                                  fo_resolve_srv_dns_send,
                                  fo_resolve_srv_dns_recv,
                                  test_ctx->srv_ctx);
    assert_true(ok);

    *state = test_ctx;
    return 0;
}

static int test_fo_srv_teardown(void **state)
{
    test_fo_teardown(state);
    return 0;
}

/* reply_list and dns_domain must be a talloc context so it can be used as
 * talloc_steal argument later
 */
static void mock_srv_results(struct ares_srv_reply *reply_list,
                             uint32_t ttl,
                             char *dns_domain)
{
    will_return(resolv_discover_srv_recv, reply_list);
    will_return(resolv_discover_srv_recv, ttl);
    will_return(resolv_discover_srv_recv, dns_domain);
}

static void check_server(struct test_fo_ctx *ctx,
                         struct fo_server *srv,
                         int port,
                         const char *name)
{
    assert_non_null(srv);
    assert_int_equal(fo_get_server_port(srv), port);
    assert_string_equal(fo_get_server_name(srv), name);


    if (ctx->srv_ctx) {
        assert_true(fo_is_srv_lookup(srv));
    }
}

static void test_fo_srv_step1(struct test_fo_ctx *test_ctx);
static void test_fo_srv_done1(struct tevent_req *req);
static void test_fo_srv_done2(struct tevent_req *req);
static void test_fo_srv_done3(struct tevent_req *req);
static void test_fo_srv_done4(struct tevent_req *req);
static void test_fo_srv_done5(struct tevent_req *req);


struct ares_srv_reply *
mock_ares_reply(TALLOC_CTX *mem_ctx, const char *hostname,
                int weight, int priority, int port)
{
    struct ares_srv_reply *s;

    s = talloc_zero(mem_ctx, struct ares_srv_reply);
    if (s == NULL) {
        return NULL;
    }

    s->host = talloc_strdup(s, hostname);
    if (s->host == NULL) {
        talloc_free(s);
        return NULL;
    }

    s->weight = weight;
    s->priority = priority;
    s->port = port;

    return s;
}

static void test_fo_srv_mock_dns(struct test_fo_ctx *test_ctx,
                                 int ttl)
{
    struct ares_srv_reply *s1;
    struct ares_srv_reply *s2;
    char *dns_domain;

    s1 = mock_ares_reply(test_ctx, "ldap1.sssd.com", 100, 1, 389);
    assert_non_null(s1);

    s2 = mock_ares_reply(test_ctx, "ldap2.sssd.com", 100, 2, 389);
    assert_non_null(s2);

    s1->next = s2;

    dns_domain = talloc_strdup(test_ctx, "sssd.com");
    assert_non_null(dns_domain);

    mock_srv_results(s1, ttl, dns_domain);
}

static void test_fo_srv(void **state)
{
    errno_t ret;
    struct test_fo_ctx *test_ctx =
        talloc_get_type(*state, struct test_fo_ctx);

    test_fo_srv_mock_dns(test_ctx, TEST_SRV_TTL);

    ret = fo_add_srv_server(test_ctx->fo_svc, "_ldap", "sssd.com",
                            "sssd.local", "tcp", test_ctx);
    assert_int_equal(ret, ERR_OK);

    test_fo_srv_step1(test_ctx);

    ret = test_ev_loop(test_ctx->ctx);
    assert_int_equal(ret, ERR_OK);
}

static void test_fo_srv_step1(struct test_fo_ctx *test_ctx)
{
    struct tevent_req *req;

    req = fo_resolve_service_send(test_ctx, test_ctx->ctx->ev,
                                  test_ctx->resolv, test_ctx->fo_ctx,
                                  test_ctx->fo_svc);
    assert_non_null(req);
    tevent_req_set_callback(req, test_fo_srv_done1, test_ctx);
}

static void test_fo_srv_done1(struct tevent_req *req)
{
    struct test_fo_ctx *test_ctx = \
        tevent_req_callback_data(req, struct test_fo_ctx);
    struct fo_server *srv;
    errno_t ret;

    ret = fo_resolve_service_recv(req, req, &srv);
    talloc_zfree(req);
    assert_int_equal(ret, ERR_OK);

    /* ldap1.sssd.com has lower priority, it must always be first */
    check_server(test_ctx, srv, 389, "ldap1.sssd.com");

    /* Mark the server as working and request the service again. The same server
     * must be returned */
    fo_set_server_status(srv, SERVER_WORKING);

    req = fo_resolve_service_send(test_ctx, test_ctx->ctx->ev,
                                  test_ctx->resolv, test_ctx->fo_ctx,
                                  test_ctx->fo_svc);
    assert_non_null(req);
    tevent_req_set_callback(req, test_fo_srv_done2, test_ctx);
}

static void test_fo_srv_done2(struct tevent_req *req)
{
    struct test_fo_ctx *test_ctx = \
        tevent_req_callback_data(req, struct test_fo_ctx);
    struct fo_server *srv;
    errno_t ret;

    ret = fo_resolve_service_recv(req, req, &srv);
    talloc_zfree(req);
    assert_int_equal(ret, ERR_OK);

    /* Must be ldap1 again */
    check_server(test_ctx, srv, 389, "ldap1.sssd.com");

    /* Mark it at wrong, next lookup should yield ldap2 */
    fo_set_server_status(srv, SERVER_NOT_WORKING);

    req = fo_resolve_service_send(test_ctx, test_ctx->ctx->ev,
                                  test_ctx->resolv, test_ctx->fo_ctx,
                                  test_ctx->fo_svc);
    assert_non_null(req);
    tevent_req_set_callback(req, test_fo_srv_done3, test_ctx);
}

static void test_fo_srv_done3(struct tevent_req *req)
{
    struct test_fo_ctx *test_ctx = \
        tevent_req_callback_data(req, struct test_fo_ctx);
    struct fo_server *srv;
    errno_t ret;

    ret = fo_resolve_service_recv(req, req, &srv);
    talloc_zfree(req);
    assert_int_equal(ret, ERR_OK);

    /* Must be ldap2 now */
    check_server(test_ctx, srv, 389, "ldap2.sssd.com");

    /* Mark is at wrong, next lookup must reach the end of the server list */
    fo_set_server_status(srv, SERVER_NOT_WORKING);

    req = fo_resolve_service_send(test_ctx, test_ctx->ctx->ev,
                                  test_ctx->resolv, test_ctx->fo_ctx,
                                  test_ctx->fo_svc);
    assert_non_null(req);
    tevent_req_set_callback(req, test_fo_srv_done4, test_ctx);
}

static void test_fo_srv_done4(struct tevent_req *req)
{
    struct test_fo_ctx *test_ctx = \
        tevent_req_callback_data(req, struct test_fo_ctx);
    struct fo_server *srv;
    errno_t ret;

    ret = fo_resolve_service_recv(req, req, &srv);
    talloc_zfree(req);
    /* No servers are left..*/
    assert_int_equal(ret, ENOENT);

    /* reset the server status and try again.. */
    fo_reset_servers(test_ctx->fo_svc);
    if (test_ctx->srv_ctx) {
        test_fo_srv_mock_dns(test_ctx, TEST_SRV_TTL);
    }

    req = fo_resolve_service_send(test_ctx, test_ctx->ctx->ev,
                                  test_ctx->resolv, test_ctx->fo_ctx,
                                  test_ctx->fo_svc);
    assert_non_null(req);
    tevent_req_set_callback(req, test_fo_srv_done5, test_ctx);
}

static void test_fo_srv_done5(struct tevent_req *req)
{
    struct test_fo_ctx *test_ctx = \
        tevent_req_callback_data(req, struct test_fo_ctx);
    struct fo_server *srv;
    errno_t ret;

    ret = fo_resolve_service_recv(req, req, &srv);
    talloc_zfree(req);

    assert_int_equal(ret, ERR_OK);

    /* ldap1.sssd.com has lower priority, it must always be first */
    check_server(test_ctx, srv, 389, "ldap1.sssd.com");

    /* OK, we made a full circle with the test, done */
    test_ctx->ctx->error = ERR_OK;
    test_ctx->ctx->done = true;
}

/* Make sure that two queries more than TTL seconds apart resolve
 * into two different lists
 */
static void test_fo_srv_ttl_change_step(struct test_fo_ctx *test_ctx);
static void test_fo_srv_before(struct tevent_req *req);
static void test_fo_srv_after(struct tevent_req *req);

void test_fo_srv_ttl_change(void **state)
{
    struct test_fo_ctx *test_ctx =
        talloc_get_type(*state, struct test_fo_ctx);

    test_ctx->ttl = TEST_SRV_SHORT_TTL;
    test_fo_srv_ttl_change_step(test_ctx);
}

static void test_fo_srv_ttl_change_step(struct test_fo_ctx *test_ctx)
{
    errno_t ret;
    struct tevent_req *req;

    test_fo_srv_mock_dns(test_ctx, test_ctx->ttl);

    ret = fo_add_srv_server(test_ctx->fo_svc, "_ldap", "sssd.com",
                            "sssd.local", "tcp", test_ctx);
    assert_int_equal(ret, ERR_OK);

    ret = fo_add_server(test_ctx->fo_svc, "ldap1.sssd.com",
                        389, (void *) discard_const("ldap://ldap1.sssd.com"),
                        true);
    assert_int_equal(ret, ERR_OK);

    req = fo_resolve_service_send(test_ctx, test_ctx->ctx->ev,
                                  test_ctx->resolv, test_ctx->fo_ctx,
                                  test_ctx->fo_svc);
    assert_non_null(req);
    tevent_req_set_callback(req, test_fo_srv_before, test_ctx);

    ret = test_ev_loop(test_ctx->ctx);
    assert_int_equal(ret, ERR_OK);
}

static void test_fo_srv_before(struct tevent_req *req)
{
    struct test_fo_ctx *test_ctx = \
        tevent_req_callback_data(req, struct test_fo_ctx);
    struct ares_srv_reply *s1;
    struct ares_srv_reply *s2;
    char *dns_domain;
    errno_t ret;

    ret = fo_resolve_service_recv(req, test_ctx, &test_ctx->srv);
    talloc_zfree(req);
    assert_int_equal(ret, ERR_OK);

    DEBUG(SSSDBG_TRACE_FUNC, "Before TTL change\n");

    check_server(test_ctx, test_ctx->srv, 389, "ldap1.sssd.com");
    fo_set_server_status(test_ctx->srv, SERVER_WORKING);

    /* Simulate changing the DNS environment. Change the host names */
    s1 = mock_ares_reply(test_ctx, "ldap1.sssd.com", 100, 2, 389);
    assert_non_null(s1);

    s2 = mock_ares_reply(test_ctx, "ldap2.sssd.com", 100, 1, 389);
    assert_non_null(s2);

    s1->next = s2;

    dns_domain = talloc_strdup(test_ctx, "sssd.com");
    assert_non_null(dns_domain);

    mock_srv_results(s1, test_ctx->ttl, dns_domain);
    sleep(test_ctx->ttl + 1);

    req = fo_resolve_service_send(test_ctx, test_ctx->ctx->ev,
                                  test_ctx->resolv, test_ctx->fo_ctx,
                                  test_ctx->fo_svc);
    assert_non_null(req);
    tevent_req_set_callback(req, test_fo_srv_after, test_ctx);
}

static void test_fo_srv_after2(struct tevent_req *req);

static void test_fo_srv_after(struct tevent_req *req)
{
    struct test_fo_ctx *test_ctx = \
        tevent_req_callback_data(req, struct test_fo_ctx);
    struct fo_server *srv;
    errno_t ret;
    struct ares_srv_reply *s1;
    struct ares_srv_reply *s2;
    char *dns_domain;

    ret = fo_resolve_service_recv(req, req, &srv);
    talloc_zfree(req);
    assert_int_equal(ret, ERR_OK);

    /* Try accessing server from a previous iteration. The
     * server should be collapsed, but at least we shouldn't crash
     */
    fo_set_server_status(test_ctx->srv, SERVER_WORKING);

    sleep(test_ctx->ttl + 1);

    /* Must be a different server now */
    check_server(test_ctx, srv, 389, "ldap2.sssd.com");

    /* Simulate changing the DNS environment. Change the host names */
    s1 = mock_ares_reply(test_ctx, "ldap1.sssd.com", 100, 1, 389);
    assert_non_null(s1);

    s2 = mock_ares_reply(test_ctx, "ldap2.sssd.com", 100, 2, 389);
    assert_non_null(s2);

    s1->next = s2;

    dns_domain = talloc_strdup(test_ctx, "sssd.com");
    assert_non_null(dns_domain);

    mock_srv_results(s1, test_ctx->ttl, dns_domain);
    sleep(test_ctx->ttl + 1);

    req = fo_resolve_service_send(test_ctx, test_ctx->ctx->ev,
                                  test_ctx->resolv, test_ctx->fo_ctx,
                                  test_ctx->fo_svc);
    assert_non_null(req);
    tevent_req_set_callback(req, test_fo_srv_after2, test_ctx);
}

static void test_fo_srv_after2(struct tevent_req *req)
{
    struct test_fo_ctx *test_ctx = \
        tevent_req_callback_data(req, struct test_fo_ctx);
    struct fo_server *srv;
    errno_t ret;

    ret = fo_resolve_service_recv(req, req, &srv);
    talloc_zfree(req);
    assert_int_equal(ret, ERR_OK);

    /* Must be a different server now */
    check_server(test_ctx, srv, 389, "ldap1.sssd.com");

    test_ctx->ctx->error = ERR_OK;
    test_ctx->ctx->done = true;
}

void test_fo_srv_ttl_zero(void **state)
{
    struct test_fo_ctx *test_ctx =
        talloc_get_type(*state, struct test_fo_ctx);

    test_ctx->ttl = 0;
    test_fo_srv_ttl_change_step(test_ctx);
}

static void test_fo_hostlist(void **state)
{
    errno_t ret;
    struct test_fo_ctx *test_ctx =
        talloc_get_type(*state, struct test_fo_ctx);

    ret = fo_add_server(test_ctx->fo_svc,
                        "ldap1.sssd.com", 389, test_ctx, true);
    assert_int_equal(ret, ERR_OK);

    ret = fo_add_server(test_ctx->fo_svc,
                        "ldap2.sssd.com", 389, test_ctx, true);
    assert_int_equal(ret, ERR_OK);

    test_fo_srv_step1(test_ctx);

    ret = test_ev_loop(test_ctx->ctx);
    assert_int_equal(ret, ERR_OK);
}

static void test_fo_srv_dup_done(struct tevent_req *req);

/* Test that running two parallel SRV queries doesn't return an error.
 * This is a regression test for https://fedorahosted.org/sssd/ticket/3131
 */
void test_fo_srv_duplicates(void **state)
{
    errno_t ret;
    struct tevent_req *req;
    struct test_fo_ctx *test_ctx =
        talloc_get_type(*state, struct test_fo_ctx);

    test_fo_srv_mock_dns(test_ctx, test_ctx->ttl);
    test_fo_srv_mock_dns(test_ctx, test_ctx->ttl);

    ret = fo_add_srv_server(test_ctx->fo_svc, "_ldap", "sssd.com",
                            "sssd.local", "tcp", test_ctx);
    assert_int_equal(ret, ERR_OK);

    ret = fo_add_server(test_ctx->fo_svc, "ldap1.sssd.com",
                        389, (void *) discard_const("ldap://ldap1.sssd.com"),
                        true);
    assert_int_equal(ret, ERR_OK);

    req = fo_resolve_service_send(test_ctx, test_ctx->ctx->ev,
                                  test_ctx->resolv, test_ctx->fo_ctx,
                                  test_ctx->fo_svc);
    assert_non_null(req);
    tevent_req_set_callback(req, test_fo_srv_dup_done, test_ctx);

    req = fo_resolve_service_send(test_ctx, test_ctx->ctx->ev,
                                  test_ctx->resolv, test_ctx->fo_ctx,
                                  test_ctx->fo_svc);
    assert_non_null(req);
    tevent_req_set_callback(req, test_fo_srv_dup_done, test_ctx);

    ret = test_ev_loop(test_ctx->ctx);
    assert_int_equal(ret, ERR_OK);
}

static void test_fo_srv_dup_done(struct tevent_req *req)
{
    struct test_fo_ctx *test_ctx = \
        tevent_req_callback_data(req, struct test_fo_ctx);
    errno_t ret;
    const char *name;

    ret = fo_resolve_service_recv(req, test_ctx, &test_ctx->srv);
    talloc_zfree(req);
    assert_int_equal(ret, EOK);

    name = fo_get_server_name(test_ctx->srv);
    assert_string_equal(name, "ldap1.sssd.com");

    test_ctx->num_done++;
    if (test_ctx->num_done == 2) {
        test_ctx->ctx->error = ERR_OK;
        test_ctx->ctx->done = true;
    }
}

int main(int argc, const char *argv[])
{
    int rv;
    poptContext pc;
    int opt;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_fo_hostlist,
                                        test_fo_setup,
                                        test_fo_teardown),
        cmocka_unit_test_setup_teardown(test_fo_srv,
                                        test_fo_srv_setup,
                                        test_fo_srv_teardown),
        cmocka_unit_test_setup_teardown(test_fo_srv_ttl_change,
                                        test_fo_srv_setup,
                                        test_fo_srv_teardown),
        cmocka_unit_test_setup_teardown(test_fo_srv_ttl_zero,
                                        test_fo_srv_setup,
                                        test_fo_srv_teardown),
        cmocka_unit_test_setup_teardown(test_fo_srv_duplicates,
                                        test_fo_srv_setup,
                                        test_fo_srv_teardown),
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                    poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }
    poptFreeContext(pc);

    DEBUG_CLI_INIT(debug_level);

    /* Even though normally the tests should clean up after themselves
     * they might not after a failed run. Remove the old DB to be sure */
    tests_set_cwd();

    rv = cmocka_run_group_tests(tests, NULL, NULL);
    return rv;
}
