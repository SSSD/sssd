/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2013 Red Hat

    SSSD tests: Dynamic DNS tests

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
#include <unistd.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

/* In order to access opaque types */
#include "providers/be_dyndns.c"

#include "tests/cmocka/common_mock.h"
#include "tests/cmocka/common_mock_be.h"
#include "src/providers/be_dyndns.h"
#include "util/util.h"

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_DB "test_dyndns_conf.ldb"
#define TEST_DOM_NAME "dyndns_test"
#define TEST_ID_PROVIDER "ldap"

enum mock_nsupdate_states {
    MOCK_NSUPDATE_OK,
    MOCK_NSUPDATE_ERR,
    MOCK_NSUPDATE_TIMEOUT,
};

static TALLOC_CTX *global_mock_context = NULL;

struct dyndns_test_ctx {
    struct sss_test_ctx *tctx;

    struct be_ctx *be_ctx;
    struct be_nsupdate_ctx *update_ctx;

    enum mock_nsupdate_states state;
    int child_status;
    int child_retval;
};

static struct dyndns_test_ctx *dyndns_test_ctx;

void __wrap_execv(const char *path, char *const argv[])
{
    int err;

    switch (dyndns_test_ctx->state) {
        case MOCK_NSUPDATE_OK:
            DEBUG(SSSDBG_FUNC_DATA, "nsupdate success test case\n");
            err = 0;
            usleep(50000); /* 50 milliseconds */
            break;
        case MOCK_NSUPDATE_ERR:
            DEBUG(SSSDBG_FUNC_DATA, "nsupdate error test case\n");
            err = 1;
            usleep(50000); /* 50 milliseconds */
            break;
        case MOCK_NSUPDATE_TIMEOUT:
            DEBUG(SSSDBG_FUNC_DATA, "nsupdate timeout test case\n");
            err = 2;
            sleep(3);
            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE, "unknown test case\n");
            err = 255;
            break;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "Child exiting with status %d\n", err);
    _exit(err);
}

int __wrap_getifaddrs(struct ifaddrs **_ifap)
{
    struct ifaddrs *ifap = NULL;
    struct ifaddrs *ifap_prev = NULL;
    struct ifaddrs *ifap_head = NULL;
    char *name;
    char *straddr;
    int ad_family;
    struct sockaddr_in *sa;
    void *dst;

    while ((name = sss_mock_ptr_type(char *)) != NULL) {
        straddr = sss_mock_ptr_type(char *);
        if (straddr == NULL) {
            errno = EINVAL;
            goto fail;
        }
        ad_family = sss_mock_type(int);

        ifap = talloc_zero(global_mock_context, struct ifaddrs);
        if (ifap == NULL) {
            errno = ENOMEM;    /* getifaddrs sets errno, too */
            goto fail;
        }

        if (ifap_prev) {
            ifap_prev->ifa_next = ifap;
        } else {
            ifap_head = ifap;
        }
        ifap_prev = ifap;

        ifap->ifa_name = talloc_strdup(ifap, name);
        if (ifap->ifa_name == NULL) {
            errno = ENOMEM;
            goto fail;
        }

        /* Do not allocate directly on ifap->ifa_addr to
         * avoid alignment warnings */
        if (ad_family == AF_INET) {
            sa = talloc(ifap, struct sockaddr_in);
        } else if (ad_family == AF_INET6) {
            sa = (struct sockaddr_in *) talloc(ifap, struct sockaddr_in6);
        } else {
            errno = EINVAL;
            goto fail;
        }

        if (sa == NULL) {
            errno = ENOMEM;
            goto fail;
        }

        sa->sin_family = ad_family;

        if (ad_family == AF_INET) {
            dst = &sa->sin_addr;
        } else if (ad_family == AF_INET6) {
            dst = &((struct sockaddr_in6 *)sa)->sin6_addr;
        } else {
            errno = EINVAL;
            goto fail;
        }

        /* convert straddr into ifa_addr */
        if (inet_pton(ad_family, straddr, dst) != 1) {
            goto fail;
        }

        ifap->ifa_addr = (struct sockaddr *) sa;
    }

    *_ifap = ifap_head;
    return 0;

fail:
    talloc_free(ifap);
    return -1;
}

void __wrap_freeifaddrs(struct ifaddrs *ifap)
{
    talloc_free(ifap);
}

static void dyndns_test_done(struct tevent_req *req)
{
    struct dyndns_test_ctx *ctx =
            tevent_req_callback_data(req, struct dyndns_test_ctx);

    ctx->child_retval = -1;
    ctx->tctx->error = be_nsupdate_recv(req, &ctx->child_status);
    talloc_zfree(req);

    ctx->tctx->done = true;
}

void will_return_getifaddrs(const char *ifname, const char *straddr,
                            int af_family)
{
    will_return(__wrap_getifaddrs, ifname);
    if (ifname) {
        will_return(__wrap_getifaddrs, straddr);
    }
    if (straddr) {
        will_return(__wrap_getifaddrs, af_family);
    }
}

void dyndns_test_sss_iface_addr_get_misc(void **state)
{
    struct sss_iface_addr addrs[3];
    struct sockaddr ss[3];

    addrs[0].prev = NULL;
    addrs[0].next = &addrs[1];
    addrs[0].addr = &ss[0];
    addrs[1].prev = &addrs[0];
    addrs[1].next = &addrs[2];
    addrs[1].addr = &ss[1];
    addrs[2].prev = &addrs[1];
    addrs[2].next = NULL;
    addrs[2].addr = &ss[2];

    assert_ptr_equal(sss_iface_addr_get_address(NULL), NULL);
    assert_ptr_equal(sss_iface_addr_get_address(&addrs[0]), &ss[0]);
    assert_ptr_equal(sss_iface_addr_get_address(&addrs[1]), &ss[1]);
    assert_ptr_equal(sss_iface_addr_get_address(&addrs[2]), &ss[2]);

    assert_ptr_equal(sss_iface_addr_get_next(NULL), NULL);
    assert_ptr_equal(sss_iface_addr_get_next(&addrs[0]), &addrs[1]);
    assert_ptr_equal(sss_iface_addr_get_next(&addrs[1]), &addrs[2]);
    assert_ptr_equal(sss_iface_addr_get_next(&addrs[2]), NULL);
}

void dyndns_test_get_ifaddr(void **state)
{
    errno_t ret;
    struct sss_iface_addr *addrlist;
    char straddr[128];

    check_leaks_push(dyndns_test_ctx);
    will_return_getifaddrs("eth0", "192.168.0.1", AF_INET);
    will_return_getifaddrs("eth1", "192.168.0.2", AF_INET);
    will_return_getifaddrs(NULL, NULL, 0); /* sentinel */
    ret = sss_iface_addr_list_get(dyndns_test_ctx, "eth0", &addrlist);
    assert_int_equal(ret, EOK);

    /* There must be only one address with the correct value */
    assert_non_null(addrlist);
    assert_non_null(addrlist->addr);
    assert_null(addrlist->next);
    assert_null(addrlist->prev);

    assert_non_null(inet_ntop(AF_INET,
                              &((struct sockaddr_in *) addrlist->addr)->sin_addr,
                              straddr, INET_ADDRSTRLEN));
    assert_string_equal(straddr, "192.168.0.1");

    talloc_free(addrlist);

    assert_true(check_leaks_pop(dyndns_test_ctx) == true);
}

void dyndns_test_get_multi_ifaddr(void **state)
{
    errno_t ret;
    struct sss_iface_addr *addrlist;
    struct sss_iface_addr *sss_if_addr;
    char straddr[128];

    check_leaks_push(dyndns_test_ctx);
    will_return_getifaddrs("eth0", "192.168.0.2", AF_INET);
    will_return_getifaddrs("eth0", "192.168.0.1", AF_INET);
    will_return_getifaddrs(NULL, NULL, 0); /* sentinel */
    ret = sss_iface_addr_list_get(dyndns_test_ctx, "eth0", &addrlist);
    assert_int_equal(ret, EOK);

    sss_if_addr = addrlist;
    assert_non_null(sss_if_addr);
    assert_non_null(sss_if_addr->addr);
    assert_non_null(sss_if_addr->next);
    assert_null(sss_if_addr->prev);

    assert_non_null(inet_ntop(AF_INET,
                              &((struct sockaddr_in *) sss_if_addr->addr)->sin_addr,
                              straddr, INET_ADDRSTRLEN));
    /* ip addresses are returned in different order */
    assert_string_equal(straddr, "192.168.0.1");

    sss_if_addr = addrlist->next;
    assert_non_null(sss_if_addr);
    assert_non_null(sss_if_addr->addr);
    assert_null(sss_if_addr->next);
    assert_non_null(sss_if_addr->prev);

    assert_non_null(inet_ntop(AF_INET,
                              &((struct sockaddr_in *) sss_if_addr->addr)->sin_addr,
                              straddr, INET_ADDRSTRLEN));
    /* ip addresses are returned in different order */
    assert_string_equal(straddr, "192.168.0.2");

    talloc_free(addrlist);

    assert_true(check_leaks_pop(dyndns_test_ctx) == true);
}

void dyndns_test_get_ifaddr_enoent(void **state)
{
    errno_t ret;
    struct sss_iface_addr *addrlist = NULL;

    check_leaks_push(dyndns_test_ctx);
    will_return_getifaddrs("eth0", "192.168.0.1", AF_INET);
    will_return_getifaddrs("eth1", "192.168.0.2", AF_INET);
    will_return_getifaddrs(NULL, NULL, 0); /* sentinel */
    ret = sss_iface_addr_list_get(dyndns_test_ctx, "non_existing_interface",
                                  &addrlist);
    assert_int_equal(ret, ENOENT);
    talloc_free(addrlist);

    assert_true(check_leaks_pop(dyndns_test_ctx) == true);
}

void dyndns_test_addr_list_as_str_list(void **state)
{
    int i;
    char **output;
    errno_t ret;
    struct sss_iface_addr *addrlist;
    struct {
        const char* addr;
        int af;
    } input[] = {
        {"2001:cdba::555", AF_INET6},
        {"192.168.0.1", AF_INET},
        {"192.168.0.2", AF_INET},
        {"2001:cdba::444", AF_INET6}
    };
    int size = 4;

    check_leaks_push(dyndns_test_ctx);

    for (i = 0; i < size; i++) {
        will_return_getifaddrs("eth0", input[i].addr, input[i].af);
    }
    will_return_getifaddrs(NULL, NULL, 0); /* sentinel */

    ret = sss_iface_addr_list_get(dyndns_test_ctx, "eth0", &addrlist);
    assert_int_equal(ret, EOK);

    ret = sss_iface_addr_list_as_str_list(dyndns_test_ctx, addrlist, &output);
    assert_int_equal(ret, EOK);
    for (i = 0; i < size; i++) {
        /* addresses are returned in reversed order */
        assert_int_equal(strcmp(input[i].addr, output[size - 1 - i]), 0);
    }

    talloc_free(addrlist);
    talloc_free(output);
    assert_true(check_leaks_pop(dyndns_test_ctx) == true);
}

void dyndns_test_create_fwd_msg(void **state)
{
    errno_t ret;
    char *msg;
    struct sss_iface_addr *addrlist;
    struct sss_parsed_dns_uri *uri;
    int i;

    check_leaks_push(dyndns_test_ctx);

    /* getifaddrs is called twice in sss_get_dualstack_addresses() */
    for (i = 0; i < 2; i++) {
        will_return_getifaddrs("eth0", "192.168.0.2", AF_INET);
        will_return_getifaddrs("eth1", "192.168.0.1", AF_INET);
        will_return_getifaddrs("eth0", "2001:cdba::555", AF_INET6);
        will_return_getifaddrs("eth1", "2001:cdba::444", AF_INET6);
        will_return_getifaddrs(NULL, NULL, 0); /* sentinel */
    }

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof (sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr ("192.168.0.2");
    ret = sss_get_dualstack_addresses(dyndns_test_ctx,
                                      (struct sockaddr *) &sin,
                                      &addrlist);
    assert_int_equal(ret, EOK);

    ret = be_nsupdate_create_fwd_msg(dyndns_test_ctx, NULL, NULL, "bran_stark",
                                     1234, DYNDNS_REMOVE_A | DYNDNS_REMOVE_AAAA,
                                     addrlist, true, &msg);
    assert_int_equal(ret, EOK);

    assert_string_equal(msg,
                        "\nupdate delete bran_stark. in A\n"
                        "update add bran_stark. 1234 in A 192.168.0.2\n"
                        "send\n"
                        "update delete bran_stark. in AAAA\n"
                        "update add bran_stark. 1234 in AAAA 2001:cdba::555\n"
                        "send\n");
    talloc_zfree(msg);

    ret = be_nsupdate_create_fwd_msg(dyndns_test_ctx, NULL, NULL, "bran_stark",
                                     1234, DYNDNS_REMOVE_A | DYNDNS_REMOVE_AAAA,
                                     addrlist, false, &msg);
    assert_int_equal(ret, EOK);

    assert_string_equal(msg,
                        "\nupdate delete bran_stark. in A\n"
                        "update add bran_stark. 1234 in A 192.168.0.2\n"
                        "update delete bran_stark. in AAAA\n"
                        "update add bran_stark. 1234 in AAAA 2001:cdba::555\n"
                        "send\n");
    talloc_zfree(msg);

    /* fallback case realm and server */
    sss_parse_dns_uri(dyndns_test_ctx, "Winterfell", &uri);
    ret = be_nsupdate_create_fwd_msg(dyndns_test_ctx, "North", uri,
                                     "bran_stark",
                                     1234, DYNDNS_REMOVE_A | DYNDNS_REMOVE_AAAA,
                                     addrlist, true, &msg);
    assert_int_equal(ret, EOK);

    assert_string_equal(msg,
                        "server Winterfell 53\n"
                        "realm North\n"
                        "update delete bran_stark. in A\n"
                        "update add bran_stark. 1234 in A 192.168.0.2\n"
                        "send\n"
                        "update delete bran_stark. in AAAA\n"
                        "update add bran_stark. 1234 in AAAA 2001:cdba::555\n"
                        "send\n");
    talloc_zfree(msg);

    /* just realm */
    ret = be_nsupdate_create_fwd_msg(dyndns_test_ctx, "North", NULL,
                                     "bran_stark",
                                     1234, DYNDNS_REMOVE_A | DYNDNS_REMOVE_AAAA,
                                     addrlist, true, &msg);
    assert_int_equal(ret, EOK);

    assert_string_equal(msg,
                        "realm North\n"
                        "update delete bran_stark. in A\n"
                        "update add bran_stark. 1234 in A 192.168.0.2\n"
                        "send\n"
                        "update delete bran_stark. in AAAA\n"
                        "update add bran_stark. 1234 in AAAA 2001:cdba::555\n"
                        "send\n");
    talloc_zfree(msg);

    /* just server */
    ret = be_nsupdate_create_fwd_msg(dyndns_test_ctx, NULL, uri,
                                     "bran_stark",
                                     1234, DYNDNS_REMOVE_A | DYNDNS_REMOVE_AAAA,
                                     addrlist, true, &msg);
    assert_int_equal(ret, EOK);

    assert_string_equal(msg,
                        "server Winterfell 53\n"
                        "\n"
                        "update delete bran_stark. in A\n"
                        "update add bran_stark. 1234 in A 192.168.0.2\n"
                        "send\n"
                        "update delete bran_stark. in AAAA\n"
                        "update add bran_stark. 1234 in AAAA 2001:cdba::555\n"
                        "send\n");
    talloc_zfree(msg);

    /* remove just A */
    ret = be_nsupdate_create_fwd_msg(dyndns_test_ctx, NULL, NULL, "bran_stark",
                                     1234, DYNDNS_REMOVE_A,
                                     addrlist, true, &msg);
    assert_int_equal(ret, EOK);

    assert_string_equal(msg,
                        "\nupdate delete bran_stark. in A\n"
                        "update add bran_stark. 1234 in A 192.168.0.2\n"
                        "send\n"
                        "update add bran_stark. 1234 in AAAA 2001:cdba::555\n"
                        "send\n");
    talloc_zfree(msg);

    /* remove just AAAA */
    ret = be_nsupdate_create_fwd_msg(dyndns_test_ctx, NULL, NULL, "bran_stark",
                                     1234, DYNDNS_REMOVE_AAAA,
                                     addrlist, true, &msg);
    assert_int_equal(ret, EOK);

    assert_string_equal(msg,
                        "\nupdate add bran_stark. 1234 in A 192.168.0.2\n"
                        "send\n"
                        "update delete bran_stark. in AAAA\n"
                        "update add bran_stark. 1234 in AAAA 2001:cdba::555\n"
                        "send\n");
    talloc_zfree(msg);

    talloc_free(addrlist);
    talloc_free(uri);
    assert_true(check_leaks_pop(dyndns_test_ctx) == true);
}

void dyndns_test_create_fwd_msg_mult(void **state)
{
    errno_t ret;
    char *msg;
    struct sss_iface_addr *addrlist;
    int i;

    check_leaks_push(dyndns_test_ctx);

    /* getifaddrs is called twice in sss_get_dualstack_addresses() */
    for (i = 0; i < 2; i++) {
        will_return_getifaddrs("eth0", "192.168.0.2", AF_INET);
        will_return_getifaddrs("eth0", "192.168.0.1", AF_INET);
        will_return_getifaddrs("eth0", "2001:cdba::555", AF_INET6);
        will_return_getifaddrs("eth0", "2001:cdba::444", AF_INET6);
        will_return_getifaddrs(NULL, NULL, 0); /* sentinel */
    }

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof (sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr ("192.168.0.2");
    ret = sss_get_dualstack_addresses(dyndns_test_ctx,
                                      (struct sockaddr *) &sin,
                                      &addrlist);
    assert_int_equal(ret, EOK);

    ret = be_nsupdate_create_fwd_msg(dyndns_test_ctx, NULL, NULL, "bran_stark",
                                     1234, DYNDNS_REMOVE_A | DYNDNS_REMOVE_AAAA,
                                     addrlist, true, &msg);
    assert_int_equal(ret, EOK);

    assert_string_equal(msg,
                        "\nupdate delete bran_stark. in A\n"
                        "update add bran_stark. 1234 in A 192.168.0.1\n"
                        "update add bran_stark. 1234 in A 192.168.0.2\n"
                        "send\n"
                        "update delete bran_stark. in AAAA\n"
                        "update add bran_stark. 1234 in AAAA 2001:cdba::444\n"
                        "update add bran_stark. 1234 in AAAA 2001:cdba::555\n"
                        "send\n");
    talloc_zfree(msg);

    talloc_free(addrlist);
    assert_true(check_leaks_pop(dyndns_test_ctx) == true);
}

void dyndns_test_create_fwd_msg_A(void **state)
{
    errno_t ret;
    char *msg;
    struct sss_iface_addr *addrlist;
    int i;

    check_leaks_push(dyndns_test_ctx);

    /* getifaddrs is called twice in sss_get_dualstack_addresses() */
    for (i = 0; i < 2; i++) {
        will_return_getifaddrs("eth0", "192.168.0.2", AF_INET);
        will_return_getifaddrs("eth0", "192.168.0.1", AF_INET);
        will_return_getifaddrs(NULL, NULL, 0); /* sentinel */
    }

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof (sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr ("192.168.0.2");
    ret = sss_get_dualstack_addresses(dyndns_test_ctx,
                                      (struct sockaddr *) &sin,
                                      &addrlist);
    assert_int_equal(ret, EOK);

    ret = be_nsupdate_create_fwd_msg(dyndns_test_ctx, NULL, NULL, "bran_stark",
                                     1234, DYNDNS_REMOVE_A | DYNDNS_REMOVE_AAAA,
                                     addrlist, true, &msg);
    assert_int_equal(ret, EOK);

    assert_string_equal(msg,
                        "\nupdate delete bran_stark. in A\n"
                        "update add bran_stark. 1234 in A 192.168.0.1\n"
                        "update add bran_stark. 1234 in A 192.168.0.2\n"
                        "send\n"
                        "update delete bran_stark. in AAAA\n"
                        "send\n");
    talloc_zfree(msg);

    talloc_free(addrlist);
    assert_true(check_leaks_pop(dyndns_test_ctx) == true);
}

void dyndns_test_create_fwd_msg_AAAA(void **state)
{
    errno_t ret;
    char *msg;
    struct sss_iface_addr *addrlist;
    int i;

    check_leaks_push(dyndns_test_ctx);

    /* getifaddrs is called twice in sss_get_dualstack_addresses() */
    for (i = 0; i < 2; i++) {
        will_return_getifaddrs("eth0", "2001:cdba::555", AF_INET6);
        will_return_getifaddrs("eth0", "2001:cdba::444", AF_INET6);
        will_return_getifaddrs(NULL, NULL, 0); /* sentinel */
    }

    struct sockaddr_in6 sin;
    memset(&sin, 0, sizeof (sin));
    sin.sin6_family = AF_INET6;
    ret = inet_pton(AF_INET6, "2001:cdba::555", &sin.sin6_addr.s6_addr);
    assert_int_equal(ret, 1);
    ret = sss_get_dualstack_addresses(dyndns_test_ctx,
                                      (struct sockaddr *) &sin,
                                      &addrlist);
    assert_int_equal(ret, EOK);

    ret = be_nsupdate_create_fwd_msg(dyndns_test_ctx, NULL, NULL, "bran_stark",
                                     1234, DYNDNS_REMOVE_A | DYNDNS_REMOVE_AAAA,
                                     addrlist, true, &msg);
    assert_int_equal(ret, EOK);

    assert_string_equal(msg,
                        "\nupdate delete bran_stark. in A\n"
                        "send\n"
                        "update delete bran_stark. in AAAA\n"
                        "update add bran_stark. 1234 in AAAA 2001:cdba::444\n"
                        "update add bran_stark. 1234 in AAAA 2001:cdba::555\n"
                        "send\n");
    talloc_zfree(msg);

    talloc_free(addrlist);
    assert_true(check_leaks_pop(dyndns_test_ctx) == true);
}

void dyndns_test_create_ptr_msg(void **state)
{
    errno_t ret;
    char *msg;
    struct sss_iface_addr *addrlist;
    int i;

    check_leaks_push(dyndns_test_ctx);

     /* getifaddrs is called twice in sss_get_dualstack_addresses() */
    for (i = 0; i < 2; i++) {
        will_return_getifaddrs("eth0", "192.168.0.2", AF_INET);
        will_return_getifaddrs("eth0", "192.168.0.1", AF_INET);
        will_return_getifaddrs("eth0", "2001:cdba::555", AF_INET6);
        will_return_getifaddrs("eth0", "2001:cdba::444", AF_INET6);
        will_return_getifaddrs(NULL, NULL, 0); /* sentinel */
    }

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof (sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr ("192.168.0.2");
    ret = sss_get_dualstack_addresses(dyndns_test_ctx,
                                      (struct sockaddr *) &sin,
                                      &addrlist);
    assert_int_equal(ret, EOK);

    ret = be_nsupdate_create_ptr_msg(dyndns_test_ctx, NULL, NULL, "bran_stark",
                                     1234, DYNDNS_REMOVE_A | DYNDNS_REMOVE_AAAA,
                                     addrlist, true, &msg);
    assert_int_equal(ret, EOK);
    assert_string_equal(msg,
                        "\nupdate delete 1.0.168.192.in-addr.arpa. in PTR\n"
                        "update add 1.0.168.192.in-addr.arpa. 1234 in PTR bran_stark.\n"
                        "send\n"
                        "update delete 2.0.168.192.in-addr.arpa. in PTR\n"
                        "update add 2.0.168.192.in-addr.arpa. 1234 in PTR bran_stark.\n"
                        "send\n"
                        "update delete 4.4.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.a.b.d.c.1.0.0.2.ip6.arpa. in PTR\n"
                        "update add 4.4.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.a.b.d.c.1.0.0.2.ip6.arpa. 1234 in PTR bran_stark.\n"
                        "send\n"
                        "update delete 5.5.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.a.b.d.c.1.0.0.2.ip6.arpa. in PTR\n"
                        "update add 5.5.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.a.b.d.c.1.0.0.2.ip6.arpa. 1234 in PTR bran_stark.\n"
                        "send\n");
    talloc_zfree(msg);

    ret = be_nsupdate_create_ptr_msg(dyndns_test_ctx, NULL, NULL, "bran_stark",
                                     1234, DYNDNS_REMOVE_A | DYNDNS_REMOVE_AAAA,
                                     addrlist, false, &msg);
    assert_int_equal(ret, EOK);
    assert_string_equal(msg,
                        "\nupdate delete 1.0.168.192.in-addr.arpa. in PTR\n"
                        "update add 1.0.168.192.in-addr.arpa. 1234 in PTR bran_stark.\n"
                        "send\n"
                        "update delete 2.0.168.192.in-addr.arpa. in PTR\n"
                        "update add 2.0.168.192.in-addr.arpa. 1234 in PTR bran_stark.\n"
                        "send\n"
                        "update delete 4.4.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.a.b.d.c.1.0.0.2.ip6.arpa. in PTR\n"
                        "update add 4.4.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.a.b.d.c.1.0.0.2.ip6.arpa. 1234 in PTR bran_stark.\n"
                        "send\n"
                        "update delete 5.5.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.a.b.d.c.1.0.0.2.ip6.arpa. in PTR\n"
                        "update add 5.5.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.a.b.d.c.1.0.0.2.ip6.arpa. 1234 in PTR bran_stark.\n"
                        "send\n");
    talloc_zfree(msg);

    talloc_free(addrlist);
    assert_true(check_leaks_pop(dyndns_test_ctx) == true);
}

void dyndns_test_dualstack(void **state)
{
    errno_t ret;
    struct sss_iface_addr *addrlist;
    struct sss_iface_addr *sss_if_addrs;
    char straddr[128];
    int i;

    check_leaks_push(dyndns_test_ctx);

    /* getifaddrs is called twice in sss_get_dualstack_addresses() */
    for (i = 0; i < 2; i++) {
        will_return_getifaddrs("eth0", "192.168.0.2", AF_INET);
        will_return_getifaddrs("eth1", "192.168.0.1", AF_INET);
        will_return_getifaddrs("eth0", "2001:cdba::555", AF_INET6);
        will_return_getifaddrs("eth1", "2001:cdba::444", AF_INET6);
        will_return_getifaddrs(NULL, NULL, 0); /* sentinel */
    }

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof (sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr ("192.168.0.2");
    ret = sss_get_dualstack_addresses(dyndns_test_ctx,
                                      (struct sockaddr *) &sin,
                                      &addrlist);
    assert_int_equal(ret, EOK);

    sss_if_addrs = addrlist;
    assert_non_null(sss_if_addrs);
    assert_non_null(sss_if_addrs->addr);
    assert_non_null(sss_if_addrs->next);
    assert_null(sss_if_addrs->prev);

    assert_non_null(inet_ntop(AF_INET6,
                              &((struct sockaddr_in6 *) sss_if_addrs->addr)->sin6_addr,
                              straddr, INET6_ADDRSTRLEN));
    /* ip addresses are returned in different order */
    assert_string_equal(straddr, "2001:cdba::555");

    sss_if_addrs = addrlist->next;
    assert_non_null(sss_if_addrs);
    assert_non_null(sss_if_addrs->addr);
    assert_null(sss_if_addrs->next);
    assert_non_null(sss_if_addrs->prev);

    assert_non_null(inet_ntop(AF_INET,
                              &((struct sockaddr_in *) sss_if_addrs->addr)->sin_addr,
                              straddr, INET_ADDRSTRLEN));
    /* ip addresses are returned in different order */
    assert_string_equal(straddr, "192.168.0.2");

    talloc_free(addrlist);

    assert_true(check_leaks_pop(dyndns_test_ctx) == true);
}

void dyndns_test_dualstack_multiple_addresses(void **state)
{
    errno_t ret;
    struct sss_iface_addr *addrlist;
    struct sss_iface_addr *sss_if_addrs;
    char straddr[128];
    int i;

    check_leaks_push(dyndns_test_ctx);

    /* getifaddrs is called twice in sss_get_dualstack_addresses() */
    for (i = 0; i < 2; i++) {
        will_return_getifaddrs("eth0", "192.168.0.2", AF_INET);
        will_return_getifaddrs("eth0", "192.168.0.1", AF_INET);
        /* loopback - invalid for DNS (should be skipped) */
        will_return_getifaddrs("eth0", "::1", AF_INET6);
        /* linklocal - invalid for DNS (should be skipped) */
        will_return_getifaddrs("eth0", "fe80::5054:ff:fe4a:65ae", AF_INET6);
        will_return_getifaddrs("eth0", "2001:cdba::555", AF_INET6);
        will_return_getifaddrs("eth0", "2001:cdba::444", AF_INET6);
        will_return_getifaddrs(NULL, NULL, 0); /* sentinel */
    }

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof (sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr ("192.168.0.2");
    ret = sss_get_dualstack_addresses(dyndns_test_ctx,
                                      (struct sockaddr *) &sin,
                                      &addrlist);
    assert_int_equal(ret, EOK);

    sss_if_addrs = addrlist;
    assert_non_null(sss_if_addrs);
    assert_non_null(sss_if_addrs->addr);
    assert_non_null(sss_if_addrs->next);
    assert_null(sss_if_addrs->prev);

    assert_non_null(inet_ntop(AF_INET6,
                              &((struct sockaddr_in6 *) sss_if_addrs->addr)->sin6_addr,
                              straddr, INET6_ADDRSTRLEN));
    /* ip addresses are returned in different order */
    assert_string_equal(straddr, "2001:cdba::444");

    sss_if_addrs = sss_if_addrs->next;
    assert_non_null(sss_if_addrs);
    assert_non_null(sss_if_addrs->addr);
    assert_non_null(sss_if_addrs->prev);
    assert_non_null(sss_if_addrs->next);

    assert_non_null(inet_ntop(AF_INET6,
                              &((struct sockaddr_in6 *) sss_if_addrs->addr)->sin6_addr,
                              straddr, INET6_ADDRSTRLEN));
    /* ip addresses are returned in different order */
    assert_string_equal(straddr, "2001:cdba::555");

    sss_if_addrs = sss_if_addrs->next;
    assert_non_null(sss_if_addrs);
    assert_non_null(sss_if_addrs->addr);
    assert_non_null(sss_if_addrs->next);
    assert_non_null(sss_if_addrs->prev);

    assert_non_null(inet_ntop(AF_INET,
                              &((struct sockaddr_in *) sss_if_addrs->addr)->sin_addr,
                              straddr, INET_ADDRSTRLEN));
    /* ip addresses are returned in different order */
    assert_string_equal(straddr, "192.168.0.1");

    sss_if_addrs = sss_if_addrs->next;
    assert_non_null(sss_if_addrs);
    assert_non_null(sss_if_addrs->addr);
    assert_null(sss_if_addrs->next);
    assert_non_null(sss_if_addrs->prev);

    assert_non_null(inet_ntop(AF_INET,
                              &((struct sockaddr_in *) sss_if_addrs->addr)->sin_addr,
                              straddr, INET_ADDRSTRLEN));
    /* ip addresses are returned in different order */
    assert_string_equal(straddr, "192.168.0.2");

    talloc_free(addrlist);

    assert_true(check_leaks_pop(dyndns_test_ctx) == true);
}

void dyndns_test_dualstack_no_iface(void **state)
{
    errno_t ret;
    struct sss_iface_addr *addrlist;

    check_leaks_push(dyndns_test_ctx);

    will_return_getifaddrs("eth0", "192.168.0.2", AF_INET);
    will_return_getifaddrs("eth1", "192.168.0.1", AF_INET);
    will_return_getifaddrs("eth0", "2001:cdba::555", AF_INET6);
    will_return_getifaddrs("eth1", "2001:cdba::444", AF_INET6);
    will_return_getifaddrs(NULL, NULL, 0); /* sentinel */

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof (sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr ("192.168.0.3");
    ret = sss_get_dualstack_addresses(dyndns_test_ctx,
                                      (struct sockaddr *) &sin,
                                      &addrlist);
    assert_int_equal(ret, ENOENT);

    assert_true(check_leaks_pop(dyndns_test_ctx) == true);
}

void dyndns_test_ok(void **state)
{
    struct tevent_req *req;
    errno_t ret;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(global_talloc_context);
    assert_non_null(tmp_ctx);
    check_leaks_push(tmp_ctx);

    dyndns_test_ctx->state = MOCK_NSUPDATE_OK;

    req = be_nsupdate_send(tmp_ctx, dyndns_test_ctx->tctx->ev,
                           BE_NSUPDATE_AUTH_GSS_TSIG,
                           discard_const("test message"), false,
                           false, NULL, NULL, NULL);
    assert_non_null(req);
    tevent_req_set_callback(req, dyndns_test_done, dyndns_test_ctx);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(dyndns_test_ctx->tctx);
    DEBUG(SSSDBG_TRACE_LIBS,
          "Child request returned [%d]: %s\n", ret, strerror(ret));
    assert_int_equal(ret, EOK);

    assert_true(WIFEXITED(dyndns_test_ctx->child_status));
    assert_int_equal(WEXITSTATUS(dyndns_test_ctx->child_status), 0);

    assert_true(check_leaks_pop(tmp_ctx) == true);
    talloc_free(tmp_ctx);
}

void dyndns_test_error(void **state)
{
    struct tevent_req *req;
    errno_t ret;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(global_talloc_context);
    assert_non_null(tmp_ctx);
    check_leaks_push(tmp_ctx);

    dyndns_test_ctx->state = MOCK_NSUPDATE_ERR;

    req = be_nsupdate_send(tmp_ctx, dyndns_test_ctx->tctx->ev,
                           BE_NSUPDATE_AUTH_GSS_TSIG,
                           discard_const("test message"), false,
                           false, NULL, NULL, NULL);
    assert_non_null(req);
    tevent_req_set_callback(req, dyndns_test_done, dyndns_test_ctx);

    /* Wait until the test finishes with EIO (child error) */
    ret = test_ev_loop(dyndns_test_ctx->tctx);
    DEBUG(SSSDBG_TRACE_LIBS,
          "Child request returned [%d]: %s\n", ret, strerror(ret));
    assert_int_equal(ret, ERR_DYNDNS_FAILED);

    assert_true(WIFEXITED(dyndns_test_ctx->child_status));
    assert_int_equal(WEXITSTATUS(dyndns_test_ctx->child_status), 1);

    assert_true(check_leaks_pop(tmp_ctx) == true);
    talloc_free(tmp_ctx);
}

void dyndns_test_timeout(void **state)
{
    struct tevent_req *req;
    errno_t ret;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(global_talloc_context);
    assert_non_null(tmp_ctx);
    check_leaks_push(tmp_ctx);

    dyndns_test_ctx->state = MOCK_NSUPDATE_TIMEOUT;

    req = be_nsupdate_send(tmp_ctx, dyndns_test_ctx->tctx->ev,
                           BE_NSUPDATE_AUTH_GSS_TSIG,
                           discard_const("test message"), false,
                           false, NULL, NULL, NULL);
    assert_non_null(req);
    tevent_req_set_callback(req, dyndns_test_done, dyndns_test_ctx);

    /* Wait until the test finishes with EIO (child error) */
    ret = test_ev_loop(dyndns_test_ctx->tctx);

    /* The event queue may not be empty. We need to make sure that all events
     * are processed.
     */
    tevent_loop_wait(dyndns_test_ctx->tctx->ev);

    DEBUG(SSSDBG_TRACE_LIBS,
          "Child request returned [%d]: %s\n", ret, strerror(ret));
    assert_int_equal(ret, ERR_DYNDNS_TIMEOUT);

    assert_true(check_leaks_pop(tmp_ctx) == true);
    talloc_free(tmp_ctx);
}

/* Testsuite setup and teardown */
static int dyndns_test_setup(void **state)
{
    struct sss_test_conf_param params[] = {
        { "dyndns_update", "true" },
        { "dyndns_refresh_interval", "2" },
        { NULL, NULL },             /* Sentinel */
    };

    assert_true(leak_check_setup());
    global_mock_context = talloc_new(global_talloc_context);
    assert_non_null(global_mock_context);

    dyndns_test_ctx = talloc_zero(global_talloc_context, struct dyndns_test_ctx);
    assert_non_null(dyndns_test_ctx);

    dyndns_test_ctx->tctx = create_dom_test_ctx(dyndns_test_ctx, TESTS_PATH,
                                                TEST_CONF_DB, TEST_DOM_NAME,
                                                TEST_ID_PROVIDER, params);
    assert_non_null(dyndns_test_ctx->tctx);

    dyndns_test_ctx->be_ctx = mock_be_ctx(dyndns_test_ctx, dyndns_test_ctx->tctx);
    assert_non_null(dyndns_test_ctx->be_ctx);

    return 0;
}

static int dyndns_test_simple_setup(void **state)
{
    assert_true(leak_check_setup());
    global_mock_context = talloc_new(global_talloc_context);
    assert_non_null(global_mock_context);

    dyndns_test_ctx = talloc_zero(global_talloc_context, struct dyndns_test_ctx);
    assert_non_null(dyndns_test_ctx);
    return 0;
}

static int dyndns_test_teardown(void **state)
{
    talloc_free(dyndns_test_ctx);
    talloc_free(global_mock_context);
    assert_true(leak_check_teardown());
    return 0;
}

int main(int argc, const char *argv[])
{
    int rv;
    int no_cleanup = 0;
    poptContext pc;
    int opt;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        {"no-cleanup", 'n', POPT_ARG_NONE, &no_cleanup, 0,
         _("Do not delete the test database after a test run"), NULL },
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        /* Utility functions unit test */
        cmocka_unit_test_setup_teardown(dyndns_test_sss_iface_addr_get_misc,
                                        dyndns_test_simple_setup,
                                        dyndns_test_teardown),
        cmocka_unit_test_setup_teardown(dyndns_test_get_ifaddr,
                                        dyndns_test_simple_setup,
                                        dyndns_test_teardown),
        cmocka_unit_test_setup_teardown(dyndns_test_get_multi_ifaddr,
                                        dyndns_test_simple_setup,
                                        dyndns_test_teardown),
        cmocka_unit_test_setup_teardown(dyndns_test_get_ifaddr_enoent,
                                        dyndns_test_simple_setup,
                                        dyndns_test_teardown),
        cmocka_unit_test_setup_teardown(dyndns_test_addr_list_as_str_list,
                                        dyndns_test_simple_setup,
                                        dyndns_test_teardown),

        /* Dynamic DNS update unit tests*/
        cmocka_unit_test_setup_teardown(dyndns_test_ok,
                                        dyndns_test_setup,
                                        dyndns_test_teardown),
        cmocka_unit_test_setup_teardown(dyndns_test_error,
                                        dyndns_test_setup,
                                        dyndns_test_teardown),
        cmocka_unit_test_setup_teardown(dyndns_test_timeout,
                                        dyndns_test_setup,
                                        dyndns_test_teardown),

        /* Dynamic DNS dualstack unit tests*/
        cmocka_unit_test_setup_teardown(dyndns_test_dualstack,
                                        dyndns_test_simple_setup,
                                        dyndns_test_teardown),
        cmocka_unit_test_setup_teardown(dyndns_test_dualstack_multiple_addresses,
                                        dyndns_test_simple_setup,
                                        dyndns_test_teardown),
        cmocka_unit_test_setup_teardown(dyndns_test_dualstack_no_iface,
                                        dyndns_test_simple_setup,
                                        dyndns_test_teardown),

        /* Messages for nsupdate */
        cmocka_unit_test_setup_teardown(dyndns_test_create_fwd_msg,
                                        dyndns_test_setup,
                                        dyndns_test_teardown),
        cmocka_unit_test_setup_teardown(dyndns_test_create_fwd_msg_mult,
                                        dyndns_test_setup,
                                        dyndns_test_teardown),
        cmocka_unit_test_setup_teardown(dyndns_test_create_fwd_msg_A,
                                        dyndns_test_setup,
                                        dyndns_test_teardown),
        cmocka_unit_test_setup_teardown(dyndns_test_create_fwd_msg_AAAA,
                                        dyndns_test_setup,
                                        dyndns_test_teardown),
        cmocka_unit_test_setup_teardown(dyndns_test_create_ptr_msg,
                                        dyndns_test_setup,
                                        dyndns_test_teardown),
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
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);
    test_dom_suite_setup(TESTS_PATH);

    rv = cmocka_run_group_tests(tests, NULL, NULL);
    if (rv == 0 && !no_cleanup) {
        test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);
    }
    return rv;
}
