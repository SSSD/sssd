/*
    Copyright (C) 2025 Red Hat

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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <talloc.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <time.h>

#include "tests/cmocka/common_mock.h"
#include "providers/failover/failover_server.h"
#include "resolv/async_resolv.h"

static int setup(void **state)
{
    TALLOC_CTX *test_ctx = NULL;

    assert_true(leak_check_setup());
    test_ctx = talloc_new(global_talloc_context);
    assert_non_null(test_ctx);
    check_leaks_push(test_ctx);

    *state = test_ctx;

    return 0;
}

static int teardown(void **state)
{
    TALLOC_CTX *test_ctx = (TALLOC_CTX*)*state;
    assert_true(check_leaks_pop(test_ctx));
    talloc_free(test_ctx);
    assert_true(leak_check_teardown());

    return 0;
}

static uint8_t *mock_ip4_addr(TALLOC_CTX *mem_ctx, const char *addr)
{
    struct in_addr net_addr;
    uint8_t *buf;
    int ret;

    if (addr == NULL) {
        return NULL;
    }

    ret = inet_pton(AF_INET, addr, &net_addr);
    assert_int_equal(ret, 1);
    buf = talloc_memdup(mem_ctx, &net_addr, sizeof(struct in_addr));
    assert_non_null(buf);

    return buf;
}

static uint8_t *mock_ip6_addr(TALLOC_CTX *mem_ctx, const char *addr)
{
    struct in6_addr net_addr;
    uint8_t *buf;
    int ret;

    if (addr == NULL) {
        return NULL;
    }

    ret = inet_pton(AF_INET6, addr, &net_addr);
    assert_int_equal(ret, 1);
    buf = talloc_memdup(mem_ctx, &net_addr, sizeof(struct in6_addr));
    assert_non_null(buf);

    return buf;
}

/* Test: Successfully create a failover server */
static void test_sss_failover_server_new(void **state)
{
    TALLOC_CTX *test_ctx = (TALLOC_CTX*)*state;
    struct sss_failover_server *srv;

    srv = sss_failover_server_new(test_ctx, "server.ipa.test",
                                  "ldap://server.ipa.test", 389, 10, 100);
    assert_non_null(srv);
    assert_non_null(srv->name);
    assert_string_equal(srv->name, "server.ipa.test");
    assert_non_null(srv->uri);
    assert_string_equal(srv->uri, "ldap://server.ipa.test");
    assert_int_equal(srv->port, 389);

    assert_null(srv->addr);
    assert_int_equal(srv->priority, 10);
    assert_int_equal(srv->weight, 100);

    talloc_free(srv);
}

/* Test: NULL hostname does not crash */
static void test_sss_failover_server_new__null(void **state)
{
    TALLOC_CTX *test_ctx = (TALLOC_CTX*)*state;
    struct sss_failover_server *srv;

    srv = sss_failover_server_new(test_ctx, NULL, "ldap://server.ipa.test", 389,
                                  10, 100);
    assert_null(srv);
}

/* Test: Successfully create a failover server with IPv4 address */
static void test_sss_failover_server_set_address__ipv4(void **state)
{
    TALLOC_CTX *test_ctx = (TALLOC_CTX*)*state;
    struct sss_failover_server *srv;
    struct in_addr expected_addr;
    struct sockaddr_in *sa_in;
    const char *hostname = "server.ipa.test";
    const char *addr = "192.168.1.100";
    uint8_t *net_addr;
    errno_t ret;
    time_t now;

    net_addr = mock_ip4_addr(test_ctx, addr);
    assert_non_null(net_addr);

    srv = sss_failover_server_new(test_ctx, hostname, "ldap://server.ipa.test",
                                  389, 10, 100);
    assert_non_null(srv);

    now = time(NULL);
    ret = sss_failover_server_set_address(srv, AF_INET, 10, net_addr);
    assert_int_equal(ret, EOK);

    assert_non_null(srv->addr);
    assert_int_equal(srv->addr->family, AF_INET);
    assert_non_null(srv->addr->human);
    assert_string_equal(srv->addr->human, addr);
    assert_true(srv->addr->expire - now >= 10);

    ret = inet_pton(AF_INET, addr, &expected_addr);
    assert_int_equal(ret, 1);
    assert_non_null(srv->addr->binary);
    assert_ptr_not_equal(srv->addr->binary, net_addr);
    assert_memory_equal(srv->addr->binary, &expected_addr,
                        sizeof(struct in_addr));
    assert_int_equal(srv->addr->binary_len, sizeof(struct in_addr));

    /* Verify sockaddr is properly set */
    assert_non_null(srv->addr->sockaddr);
    assert_int_equal(srv->addr->sockaddr_len, sizeof(struct sockaddr_in));
    sa_in = (struct sockaddr_in *)srv->addr->sockaddr;
    assert_int_equal(sa_in->sin_family, AF_INET);
    assert_int_equal(ntohs(sa_in->sin_port), 389);
    assert_memory_equal(&sa_in->sin_addr, &expected_addr, sizeof(struct in_addr));

    talloc_free(net_addr);
    talloc_free(srv);
}

/* Test: Successfully create a failover server with IPv6 address */
static void test_sss_failover_server_set_address__ipv6(void **state)
{
    TALLOC_CTX *test_ctx = (TALLOC_CTX*)*state;
    struct sss_failover_server *srv;
    struct in6_addr expected_addr;
    struct sockaddr_in6 *sa_in6;
    const char *hostname = "server.ipa.test";
    const char *addr = "2a00:102a:403a:c7a7:e05e:11e6:3189:3326";
    uint8_t *net_addr;
    errno_t ret;
    time_t now;

    net_addr = mock_ip6_addr(test_ctx, addr);
    assert_non_null(net_addr);

    srv = sss_failover_server_new(test_ctx, hostname, "ldap://server.ipa.test",
                                  389, 10, 100);
    assert_non_null(srv);

    now = time(NULL);
    ret = sss_failover_server_set_address(srv, AF_INET6, 10, net_addr);
    assert_int_equal(ret, EOK);

    assert_non_null(srv->addr);
    assert_int_equal(srv->addr->family, AF_INET6);
    assert_non_null(srv->addr->human);
    assert_string_equal(srv->addr->human, addr);
    assert_true(srv->addr->expire - now >= 10);

    ret = inet_pton(AF_INET6, addr, &expected_addr);
    assert_int_equal(ret, 1);
    assert_non_null(srv->addr->binary);
    assert_ptr_not_equal(srv->addr->binary, net_addr);
    assert_memory_equal(srv->addr->binary, &expected_addr,
                        sizeof(struct in6_addr));
    assert_int_equal(srv->addr->binary_len, sizeof(struct in6_addr));

    /* Verify sockaddr is properly set */
    assert_non_null(srv->addr->sockaddr);
    assert_int_equal(srv->addr->sockaddr_len, sizeof(struct sockaddr_in6));
    sa_in6 = (struct sockaddr_in6 *)srv->addr->sockaddr;
    assert_int_equal(sa_in6->sin6_family, AF_INET6);
    assert_int_equal(ntohs(sa_in6->sin6_port), 389);
    assert_memory_equal(&sa_in6->sin6_addr, &expected_addr, sizeof(struct in6_addr));

    talloc_free(net_addr);
    talloc_free(srv);
}

/* Test: Error out if invalid family is given */
static void test_sss_failover_server_set_address__invalid_family(void **state)
{
    TALLOC_CTX *test_ctx = (TALLOC_CTX*)*state;
    struct sss_failover_server *srv;
    const char *hostname = "server.ipa.test";
    const char *addr = "192.168.1.100";
    uint8_t *net_addr;
    errno_t ret;

    net_addr = mock_ip4_addr(test_ctx, addr);
    assert_non_null(net_addr);

    srv = sss_failover_server_new(test_ctx, hostname, "ldap://server.ipa.test",
                                  389, 10, 100);
    assert_non_null(srv);

    ret = sss_failover_server_set_address(srv, AF_UNIX, 10, net_addr);
    assert_int_equal(ret, EINVAL);

    talloc_free(net_addr);
    talloc_free(srv);
}

/* Test: Error out if invalid address is given */
static void test_sss_failover_server_set_address__null_addr(void **state)
{
    TALLOC_CTX *test_ctx = (TALLOC_CTX*)*state;
    struct sss_failover_server *srv;
    const char *hostname = "server.ipa.test";
    errno_t ret;

    srv = sss_failover_server_new(test_ctx, hostname, "ldap://server.ipa.test",
                                  389, 10, 100);
    assert_non_null(srv);

    ret = sss_failover_server_set_address(srv, AF_INET, 10, NULL);
    assert_int_equal(ret, EINVAL);

    talloc_free(srv);
}

/* Test: Successfully clone a failover server with IPv4 address */
static void test_sss_failover_server_clone__ipv4(void **state)
{
    TALLOC_CTX *test_ctx = (TALLOC_CTX*)*state;
    struct sss_failover_server *srv;
    struct sss_failover_server *clone;
    const char *hostname = "server.ipa.test";
    const char *addr = "192.168.1.100";
    uint8_t *net_addr;
    errno_t ret;

    net_addr = mock_ip4_addr(test_ctx, addr);
    assert_non_null(net_addr);

    srv = sss_failover_server_new(test_ctx, hostname, "ldap://server.ipa.test",
                                  389, 10, 100);
    assert_non_null(srv);

    ret = sss_failover_server_set_address(srv, AF_INET, 10, net_addr);
    assert_int_equal(ret, EOK);

    clone = sss_failover_server_clone(test_ctx, srv);
    assert_non_null(clone);

    /* Verify name is cloned */
    assert_non_null(clone->name);
    assert_string_equal(clone->name, srv->name);

    /* Verify priority and weight are cloned */
    assert_int_equal(clone->priority, srv->priority);
    assert_int_equal(clone->weight, srv->weight);

    /* Verify address is cloned */
    assert_non_null(clone->addr);
    assert_int_equal(clone->addr->family, srv->addr->family);
    assert_int_equal(clone->addr->expire, srv->addr->expire);
    assert_non_null(clone->addr->human);
    assert_string_equal(clone->addr->human, srv->addr->human);
    assert_non_null(clone->addr->binary);
    assert_memory_equal(clone->addr->binary, srv->addr->binary,
                        sizeof(struct in_addr));
    assert_int_equal(clone->addr->binary_len, srv->addr->binary_len);
    assert_non_null(clone->addr->sockaddr);
    assert_int_equal(clone->addr->sockaddr_len, srv->addr->sockaddr_len);

    /* Verify clone is independent (different memory) */
    assert_ptr_not_equal(clone, srv);
    assert_ptr_not_equal(clone->name, srv->name);
    assert_ptr_not_equal(clone->addr, srv->addr);
    assert_ptr_not_equal(clone->addr->binary, srv->addr->binary);
    assert_ptr_not_equal(clone->addr->human, srv->addr->human);
    assert_ptr_not_equal(clone->addr->sockaddr, srv->addr->sockaddr);

    talloc_free(net_addr);
    talloc_free(srv);
    talloc_free(clone);
}

/* Test: Successfully clone a failover server with IPv6 address */
static void test_sss_failover_server_clone__ipv6(void **state)
{
    TALLOC_CTX *test_ctx = (TALLOC_CTX*)*state;
    struct sss_failover_server *srv;
    struct sss_failover_server *clone;
    const char *hostname = "server1.ipa.test";
    const char *addr = "2a00:102a:403a:c7a7:e05e:11e6:3189:3326";
    uint8_t *net_addr;
    errno_t ret;

    net_addr = mock_ip6_addr(test_ctx, addr);
    assert_non_null(net_addr);

    srv = sss_failover_server_new(test_ctx, hostname, "ldap://server1.ipa.test",
                                  389, 10, 100);
    assert_non_null(srv);

    ret = sss_failover_server_set_address(srv, AF_INET6, 10, net_addr);
    assert_int_equal(ret, EOK);

    clone = sss_failover_server_clone(test_ctx, srv);
    assert_non_null(clone);

    /* Verify name is cloned */
    assert_non_null(clone->name);
    assert_string_equal(clone->name, srv->name);

    /* Verify priority and weight are cloned */
    assert_int_equal(clone->priority, srv->priority);
    assert_int_equal(clone->weight, srv->weight);

    /* Verify address is cloned */
    assert_non_null(clone->addr);
    assert_int_equal(clone->addr->family, srv->addr->family);
    assert_int_equal(clone->addr->expire, srv->addr->expire);
    assert_non_null(clone->addr->human);
    assert_string_equal(clone->addr->human, srv->addr->human);
    assert_non_null(clone->addr->binary);
    assert_memory_equal(clone->addr->binary, srv->addr->binary,
                        sizeof(struct in6_addr));
    assert_int_equal(clone->addr->binary_len, srv->addr->binary_len);
    assert_non_null(clone->addr->sockaddr);
    assert_int_equal(clone->addr->sockaddr_len, srv->addr->sockaddr_len);

    /* Verify clone is independent (different memory) */
    assert_ptr_not_equal(clone, srv);
    assert_ptr_not_equal(clone->name, srv->name);
    assert_ptr_not_equal(clone->addr, srv->addr);
    assert_ptr_not_equal(clone->addr->binary, srv->addr->binary);
    assert_ptr_not_equal(clone->addr->human, srv->addr->human);
    assert_ptr_not_equal(clone->addr->sockaddr, srv->addr->sockaddr);

    talloc_free(net_addr);
    talloc_free(srv);
    talloc_free(clone);
}

/* Test: Successfully clone a failover server with empty address */
static void test_sss_failover_server_clone__null_addr(void **state)
{
    TALLOC_CTX *test_ctx = (TALLOC_CTX*)*state;
    struct sss_failover_server *srv;
    struct sss_failover_server *clone;
    const char *hostname = "server.ipa.test";

    srv = sss_failover_server_new(test_ctx, hostname, "ldap://server.ipa.test",
                                  389, 10, 100);
    assert_non_null(srv);

    clone = sss_failover_server_clone(test_ctx, srv);
    assert_non_null(clone);

    /* Verify name is cloned */
    assert_non_null(clone->name);
    assert_string_equal(clone->name, srv->name);

    /* Verify priority and weight are cloned */
    assert_int_equal(clone->priority, srv->priority);
    assert_int_equal(clone->weight, srv->weight);

    /* Verify address is cloned */
    assert_null(clone->addr);

    /* Verify clone is independent (different memory) */
    assert_ptr_not_equal(clone, srv);
    assert_ptr_not_equal(clone->name, srv->name);

    talloc_free(srv);
    talloc_free(clone);
}

/* Test: Fail when cloning NULL server */
static void test_sss_failover_server_clone__null_server(void **state)
{
    TALLOC_CTX *test_ctx = (TALLOC_CTX*)*state;
    struct sss_failover_server *clone;

    clone = sss_failover_server_clone(test_ctx, NULL);
    assert_null(clone);
}

/* Test: Server state transitions */
static void test_sss_failover_server_state_management(void **state)
{
    TALLOC_CTX *test_ctx = (TALLOC_CTX*)*state;
    struct sss_failover_server *srv;

    srv = sss_failover_server_new(test_ctx, "server.ipa.test",
                                  "ldap://server.ipa.test", 389, 10, 100);
    assert_non_null(srv);

    /* Initial state should be UNKNOWN */
    assert_int_equal(srv->state, SSS_FAILOVER_SERVER_STATE_UNKNOWN);
    assert_true(sss_failover_server_maybe_working(srv));

    /* Mark as reachable */
    sss_failover_server_mark_reachable(srv);
    assert_int_equal(srv->state, SSS_FAILOVER_SERVER_STATE_REACHABLE);
    assert_true(sss_failover_server_maybe_working(srv));

    /* Mark as working */
    sss_failover_server_mark_working(srv);
    assert_int_equal(srv->state, SSS_FAILOVER_SERVER_STATE_WORKING);
    assert_true(sss_failover_server_maybe_working(srv));

    /* Mark as offline */
    sss_failover_server_mark_offline(srv);
    assert_int_equal(srv->state, SSS_FAILOVER_SERVER_STATE_OFFLINE);
    assert_false(sss_failover_server_maybe_working(srv));

    /* Mark as unknown again */
    sss_failover_server_mark_unknown(srv);
    assert_int_equal(srv->state, SSS_FAILOVER_SERVER_STATE_UNKNOWN);
    assert_true(sss_failover_server_maybe_working(srv));

    /* Mark as resolver error */
    sss_failover_server_mark_resolver_error(srv);
    assert_int_equal(srv->state, SSS_FAILOVER_SERVER_STATE_RESOLVER_ERROR);
    assert_false(sss_failover_server_maybe_working(srv));

    talloc_free(srv);
}

/* Test: Compare two equal servers */
static void test_sss_failover_server_equal__same(void **state)
{
    TALLOC_CTX *test_ctx = (TALLOC_CTX*)*state;
    struct sss_failover_server *srv1;
    struct sss_failover_server *srv2;

    srv1 = sss_failover_server_new(test_ctx, "server.ipa.test",
                                   "ldap://server.ipa.test", 389, 10, 100);
    assert_non_null(srv1);

    srv2 = sss_failover_server_new(test_ctx, "server.ipa.test",
                                   "ldap://server.ipa.test", 389, 20, 200);
    assert_non_null(srv2);

    /* Should be equal (only name and port matter) */
    assert_true(sss_failover_server_equal(srv1, srv2));

    talloc_free(srv1);
    talloc_free(srv2);
}

/* Test: Compare two servers with different names */
static void test_sss_failover_server_equal__different_name(void **state)
{
    TALLOC_CTX *test_ctx = (TALLOC_CTX*)*state;
    struct sss_failover_server *srv1;
    struct sss_failover_server *srv2;

    srv1 = sss_failover_server_new(test_ctx, "server1.ipa.test",
                                   "ldap://server1.ipa.test", 389, 10, 100);
    assert_non_null(srv1);

    srv2 = sss_failover_server_new(test_ctx, "server2.ipa.test",
                                   "ldap://server2.ipa.test", 389, 10, 100);
    assert_non_null(srv2);

    /* Should not be equal (different names) */
    assert_false(sss_failover_server_equal(srv1, srv2));

    talloc_free(srv1);
    talloc_free(srv2);
}

/* Test: Compare two servers with different ports */
static void
test_sss_failover_server_equal__different_port(void **state)
{
    TALLOC_CTX *test_ctx = (TALLOC_CTX *)*state;
    struct sss_failover_server *srv1;
    struct sss_failover_server *srv2;

    srv1 = sss_failover_server_new(test_ctx, "server.ipa.test",
                                   "ldap://server.ipa.test", 389, 10, 100);
    assert_non_null(srv1);

    srv2 = sss_failover_server_new(test_ctx, "server.ipa.test",
                                   "ldaps://server.ipa.test", 636, 10, 100);
    assert_non_null(srv2);

    /* Should not be equal (different ports) */
    assert_false(sss_failover_server_equal(srv1, srv2));

    talloc_free(srv1);
    talloc_free(srv2);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_sss_failover_server_new,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_failover_server_new__null,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_failover_server_set_address__ipv4,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_failover_server_set_address__ipv6,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_failover_server_set_address__invalid_family,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_failover_server_set_address__null_addr,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_failover_server_clone__ipv4,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_failover_server_clone__ipv6,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_failover_server_clone__null_addr,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_failover_server_clone__null_server,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_failover_server_state_management,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_failover_server_equal__same,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_failover_server_equal__different_name,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_failover_server_equal__different_port,
                                        setup, teardown)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
