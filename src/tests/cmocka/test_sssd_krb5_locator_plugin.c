/*
    SSSD

    Unit test for SSSD's MIT Kerberos locator plugin

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2018 Red Hat

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
#include "config.h"

#include <popt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <netdb.h>
#include <krb5/krb5.h>
#include <krb5/locate_plugin.h>

#include "tests/cmocka/common_mock.h"

#define TEST_REALM "TEST.REALM"
#define TEST_IP_1 "123.231.132.213"
#define TEST_IPV6_1_PURE "7025:4d2d:2b06:e321:d971:16c0:6eeb:cc41"
#define TEST_IPV6_1 "["TEST_IPV6_1_PURE"]"
#define TEST_SERVICE_1 "22334"
#define TEST_SERVICE_2 "54321"
#define TEST_IP_1_WITH_SERVICE TEST_IP_1":"TEST_SERVICE_1
#define TEST_IPV6_1_WITH_SERVICE TEST_IPV6_1":"TEST_SERVICE_2

#define TEST_IP_1_WITH_SERVICE_2 TEST_IP_1":"TEST_SERVICE_2
#define TEST_IPV6_1_WITH_SERVICE_1 TEST_IPV6_1":"TEST_SERVICE_1

struct test_state {
    void *dummy;
};

static int setup(void **state)
{
    struct test_state *ts = NULL;

    assert_true(leak_check_setup());

    ts = talloc(global_talloc_context, struct test_state);
    assert_non_null(ts);

    check_leaks_push(ts);
    *state = (void *)ts;

    unlink(TEST_PUBCONF_PATH"/kdcinfo."TEST_REALM);
    unlink(TEST_PUBCONF_PATH"/kpasswdinfo."TEST_REALM);
    rmdir(TEST_PUBCONF_PATH);

    return 0;
}

static int teardown(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);

    assert_non_null(ts);

    assert_true(check_leaks_pop(ts));
    talloc_free(ts);
    assert_true(leak_check_teardown());
    return 0;
}

/* Taken from MIT Kerberos src/lib/krb5/os/locate_kdc.c and
 * lib/krb5/os/os-proto.h */

typedef enum {
    TCP_OR_UDP = 0,
    TCP,
    UDP,
    HTTPS,
} k5_transport;

/* A single server hostname or address. */
struct server_entry {
    char *hostname;             /* NULL -> use addrlen/addr instead */
    int port;                   /* Used only if hostname set */
    k5_transport transport;     /* May be 0 for UDP/TCP if hostname set */
    char *uri_path;             /* Used only if transport is HTTPS */
    int family;                 /* May be 0 (aka AF_UNSPEC) if hostname set */
    int master;                 /* True, false, or -1 for unknown. */
    size_t addrlen;
    struct sockaddr_storage addr;
};

/* A list of server hostnames/addresses. */
struct serverlist {
    struct server_entry *servers;
    size_t nservers;
};
#define SERVERLIST_INIT { NULL, 0 }

/* Free up everything pointed to by the serverlist structure, but don't
 *  * free the structure itself. */
void
k5_free_serverlist (struct serverlist *list)
{
    size_t i;

    for (i = 0; i < list->nservers; i++) {
        free(list->servers[i].hostname);
        free(list->servers[i].uri_path);
    }
    free(list->servers);
    list->servers = NULL;
    list->nservers = 0;
}

/* Make room for a new server entry in list and return a pointer to the new
 * entry.  (Do not increment list->nservers.) */
static struct server_entry *
new_server_entry(struct serverlist *list)
{
    struct server_entry *newservers, *entry;
    size_t newspace = (list->nservers + 1) * sizeof(struct server_entry);

    newservers = realloc(list->servers, newspace);
    if (newservers == NULL)
        return NULL;
    list->servers = newservers;
    entry = &newservers[list->nservers];
    memset(entry, 0, sizeof(*entry));
    entry->master = -1;
    return entry;
}

/* Add an address entry to list. */
static int
add_addr_to_list(struct serverlist *list, k5_transport transport, int family,
                 size_t addrlen, struct sockaddr *addr)
{
    struct server_entry *entry;

    entry = new_server_entry(list);
    if (entry == NULL)
        return ENOMEM;
    entry->transport = transport;
    entry->family = family;
    entry->hostname = NULL;
    entry->uri_path = NULL;
    entry->addrlen = addrlen;
    memcpy(&entry->addr, addr, addrlen);
    list->nservers++;
    return 0;
}

struct module_callback_data {
    int out_of_mem;
    struct serverlist *list;
};

static int
module_callback(void *cbdata, int socktype, struct sockaddr *sa)
{
    struct module_callback_data *d = cbdata;
    size_t addrlen;
    k5_transport transport;

    if (socktype != SOCK_STREAM && socktype != SOCK_DGRAM)
        return 0;
    if (sa->sa_family == AF_INET)
        addrlen = sizeof(struct sockaddr_in);
    else if (sa->sa_family == AF_INET6)
        addrlen = sizeof(struct sockaddr_in6);
    else
        return 0;
    transport = (socktype == SOCK_STREAM) ? TCP : UDP;
    if (add_addr_to_list(d->list, transport, sa->sa_family, addrlen,
                         sa) != 0) {
        /* Assumes only error is ENOMEM.  */
        d->out_of_mem = 1;
        return 1;
    }
    return 0;
}

krb5_error_code sssd_krb5_locator_init(krb5_context context,
                                       void **private_data);
void sssd_krb5_locator_close(void *private_data);

krb5_error_code sssd_krb5_locator_lookup(void *private_data,
                    enum locate_service_type svc,
                    const char *realm,
                    int socktype,
                    int family,
                    int (*cbfunc)(void *, int, struct sockaddr *),
                    void *cbdata);

void test_init(void **state)
{
    krb5_context ctx;
    krb5_error_code kerr;
    void *priv;

    kerr = krb5_init_context (&ctx);
    assert_int_equal(kerr, 0);

    kerr = sssd_krb5_locator_init(ctx, &priv);
    assert_int_equal(kerr, 0);

    sssd_krb5_locator_close(priv);

    krb5_free_context(ctx);
}

void test_failed_lookup(void **state)
{
    krb5_context ctx;
    krb5_error_code kerr;
    void *priv;
    struct module_callback_data cbdata = { 0 };


    kerr = krb5_init_context (&ctx);
    assert_int_equal(kerr, 0);

    kerr = sssd_krb5_locator_init(ctx, &priv);
    assert_int_equal(kerr, 0);

    kerr = sssd_krb5_locator_lookup(NULL, -1, NULL, -1, -1, NULL, NULL);
    assert_int_equal(kerr, KRB5_PLUGIN_NO_HANDLE);

    kerr = sssd_krb5_locator_lookup(priv, -1, NULL, -1, -1, NULL, NULL);
    assert_int_equal(kerr, KRB5_PLUGIN_NO_HANDLE);

    kerr = sssd_krb5_locator_lookup(priv, locate_service_kdc , NULL, -1, -1,
                                    NULL, NULL);
    assert_int_equal(kerr, KRB5_PLUGIN_NO_HANDLE);

    kerr = sssd_krb5_locator_lookup(priv, locate_service_kdc , TEST_REALM, -1,
                                    -1, NULL, NULL);
    assert_int_equal(kerr, KRB5_PLUGIN_NO_HANDLE);

    kerr = sssd_krb5_locator_lookup(priv, locate_service_kdc , TEST_REALM,
                                    SOCK_DGRAM, -1, NULL, NULL);
    assert_int_equal(kerr, KRB5_PLUGIN_NO_HANDLE);

    kerr = sssd_krb5_locator_lookup(priv, locate_service_kdc , TEST_REALM,
                                    SOCK_DGRAM, AF_INET6, NULL, NULL);
    assert_int_equal(kerr, KRB5_PLUGIN_NO_HANDLE);

    kerr = sssd_krb5_locator_lookup(priv, locate_service_kdc , TEST_REALM,
                                    SOCK_DGRAM, AF_INET6, module_callback,
                                    NULL);
    assert_int_equal(kerr, KRB5_PLUGIN_NO_HANDLE);

    kerr = sssd_krb5_locator_lookup(priv, locate_service_kdc , TEST_REALM,
                                    SOCK_DGRAM, AF_INET6, module_callback,
                                    &cbdata);
    assert_int_equal(kerr, KRB5_PLUGIN_NO_HANDLE);

    sssd_krb5_locator_close(priv);

    krb5_free_context(ctx);
}

void test_empty(void **state)
{
    krb5_context ctx;
    krb5_error_code kerr;
    void *priv;
    int fd;
    struct module_callback_data cbdata = { 0 };

    kerr = krb5_init_context (&ctx);
    assert_int_equal(kerr, 0);

    kerr = sssd_krb5_locator_init(ctx, &priv);
    assert_int_equal(kerr, 0);

    mkdir(TEST_PUBCONF_PATH, 0777);
    fd = open(TEST_PUBCONF_PATH"/kdcinfo."TEST_REALM, O_CREAT, 0777);
    assert_int_not_equal(fd, -1);
    close(fd);

    kerr = sssd_krb5_locator_lookup(priv, locate_service_kdc , TEST_REALM,
                                    SOCK_DGRAM, AF_INET6, module_callback,
                                    &cbdata);
    assert_int_equal(kerr, KRB5_PLUGIN_NO_HANDLE);
    unlink(TEST_PUBCONF_PATH"/kdcinfo."TEST_REALM);
    rmdir(TEST_PUBCONF_PATH);

    sssd_krb5_locator_close(priv);

    krb5_free_context(ctx);
}

void test_single(void **state)
{
    krb5_context ctx;
    krb5_error_code kerr;
    void *priv;
    int fd;
    struct serverlist list = SERVERLIST_INIT;
    struct module_callback_data cbdata = { 0 };
    ssize_t s;
    int ret;
    char host[NI_MAXHOST];
    char service[NI_MAXSERV];

    cbdata.list = &list;

    kerr = krb5_init_context (&ctx);
    assert_int_equal(kerr, 0);

    kerr = sssd_krb5_locator_init(ctx, &priv);
    assert_int_equal(kerr, 0);

    mkdir(TEST_PUBCONF_PATH, 0777);
    fd = open(TEST_PUBCONF_PATH"/kdcinfo."TEST_REALM, O_CREAT|O_RDWR, 0777);
    assert_int_not_equal(fd, -1);
    s = write(fd, TEST_IP_1, sizeof(TEST_IP_1));
    assert_int_equal(s, sizeof(TEST_IP_1));
    close(fd);

    kerr = sssd_krb5_locator_lookup(priv, locate_service_kdc , TEST_REALM,
                                    SOCK_DGRAM, AF_INET6, module_callback,
                                    &cbdata);
    assert_int_equal(kerr, 0);

    /* We asked for AF_INET6, but TEST_IP_1 is IPv4 */
    assert_int_equal(list.nservers, 0);
    assert_null(list.servers);

    kerr = sssd_krb5_locator_lookup(priv, locate_service_kdc , TEST_REALM,
                                    SOCK_DGRAM, AF_INET, module_callback,
                                    &cbdata);
    assert_int_equal(kerr, 0);
    assert_int_equal(list.nservers, 1);
    assert_non_null(list.servers);
    assert_int_equal(list.servers[0].addrlen, 16);
    ret = getnameinfo((struct sockaddr *) &list.servers[0].addr,
                      list.servers[0].addrlen,
                      host, sizeof(host), service, sizeof(service),
                      NI_NUMERICHOST|NI_NUMERICSERV);
    assert_int_equal(ret, 0);
    assert_string_equal(TEST_IP_1, host);
    assert_string_equal("88", service);

    k5_free_serverlist(&list);

    kerr = sssd_krb5_locator_lookup(priv, locate_service_kdc , TEST_REALM,
                                    SOCK_DGRAM, AF_UNSPEC, module_callback,
                                    &cbdata);
    assert_int_equal(kerr, 0);
    assert_int_equal(list.nservers, 1);
    assert_non_null(list.servers);
    assert_int_equal(list.servers[0].addrlen, 16);
    ret = getnameinfo((struct sockaddr *) &list.servers[0].addr,
                      list.servers[0].addrlen,
                      host, sizeof(host), service, sizeof(service),
                      NI_NUMERICHOST|NI_NUMERICSERV);
    assert_int_equal(ret, 0);
    assert_string_equal(TEST_IP_1, host);
    assert_string_equal("88", service);

    k5_free_serverlist(&list);

    unlink(TEST_PUBCONF_PATH"/kdcinfo."TEST_REALM);
    rmdir(TEST_PUBCONF_PATH);
    sssd_krb5_locator_close(priv);

    krb5_free_context(ctx);
}

struct test_data {
    const char *ip;
    bool found;
};

void test_multi_check_results(struct test_data *test_data,
                              struct serverlist *list,
                              const char *exp_service)
{
    int ret;
    char host[NI_MAXHOST];
    char service[NI_MAXSERV];
    size_t c;
    size_t d;

    /* To make sure each result from list has a matching entry in test_data we
     * use a flag to mark found entries, this way we can properly detect is
     * the same address is used multiple times. */
    for (d = 0; test_data[d].ip != NULL; d++) {
        test_data[d].found = false;
    }

    for (c = 0; c < list->nservers; c++) {
        ret = getnameinfo((struct sockaddr *) &list->servers[c].addr,
                          list->servers[c].addrlen,
                          host, sizeof(host), service, sizeof(service),
                          NI_NUMERICHOST|NI_NUMERICSERV);
        assert_int_equal(ret, 0);
        assert_string_equal(exp_service, service);
        for (d = 0; test_data[d].ip != NULL; d++) {
            /* Compare result with test_data, be aware that the test_data has
             * '[]' around IPv& addresses */
            if (strncmp(host,
                        test_data[d].ip + (test_data[d].ip[0] == '[' ? 1 : 0),
                        strlen(host)) == 0 && !test_data[d].found) {
                test_data[d].found = true;
                break;
            }
        }
        /* Make sure we found the result in the list */
        assert_non_null(test_data[d].ip);
    }
}

void test_multi(void **state)
{
    krb5_context ctx;
    krb5_error_code kerr;
    void *priv;
    int fd;
    struct serverlist list = SERVERLIST_INIT;
    struct module_callback_data cbdata = { 0 };
    ssize_t s;
    size_t c;
    struct test_data test_data[] = {
                           {TEST_IP_1, false},
                           {TEST_IPV6_1, false},
                           {"[c89a:565b:4510:5b9f:41fe:ea81:87a0:f21b]", false},
                           {"155.42.66.53", false},
                           {"[f812:5941:ba69:2bae:e806:3b68:770d:d75e]", false},
                           {"[3ad3:9dda:50e4:3c82:548f:eaa1:e120:6dd]", false},
                           {"55.116.79.183", false},
                           {"[ce8a:ee99:98cd:d8cd:218d:393e:d5a9:dc52]", false},
                           /* the following address is added twice to check if
                            * an address can be added more than once. */
                           {"37.230.88.162", false},
                           {"37.230.88.162", false},
                           {NULL, false} };

    cbdata.list = &list;

    kerr = krb5_init_context (&ctx);
    assert_int_equal(kerr, 0);

    kerr = sssd_krb5_locator_init(ctx, &priv);
    assert_int_equal(kerr, 0);

    mkdir(TEST_PUBCONF_PATH, 0777);
    fd = open(TEST_PUBCONF_PATH"/kdcinfo."TEST_REALM, O_CREAT|O_RDWR, 0777);
    assert_int_not_equal(fd, -1);
    for (c = 0; test_data[c].ip != NULL; c++) {
        s = write(fd, test_data[c].ip, strlen(test_data[c].ip));
        assert_int_equal(s, strlen(test_data[c].ip));
        s = write(fd, "\n", 1);
        assert_int_equal(s, 1);
    }
    close(fd);

    kerr = sssd_krb5_locator_lookup(priv, locate_service_kdc , TEST_REALM,
                                    SOCK_DGRAM, AF_INET6, module_callback,
                                    &cbdata);
    assert_int_equal(kerr, 0);

    assert_int_equal(list.nservers, 5);
    assert_non_null(list.servers);
    test_multi_check_results(test_data, &list, "88");

    k5_free_serverlist(&list);

    kerr = sssd_krb5_locator_lookup(priv, locate_service_kdc , TEST_REALM,
                                    SOCK_DGRAM, AF_INET, module_callback,
                                    &cbdata);
    assert_int_equal(kerr, 0);

    assert_int_equal(list.nservers, 5);
    assert_non_null(list.servers);
    test_multi_check_results(test_data, &list, "88");


    k5_free_serverlist(&list);

    kerr = sssd_krb5_locator_lookup(priv, locate_service_kdc , TEST_REALM,
                                    SOCK_DGRAM, AF_UNSPEC, module_callback,
                                    &cbdata);
    assert_int_equal(kerr, 0);

    assert_int_equal(list.nservers, 10);
    assert_non_null(list.servers);
    test_multi_check_results(test_data, &list, "88");

    k5_free_serverlist(&list);

    unlink(TEST_PUBCONF_PATH"/kdcinfo."TEST_REALM);
    rmdir(TEST_PUBCONF_PATH);
    sssd_krb5_locator_close(priv);

    krb5_free_context(ctx);
}

void test_service(void **state)
{
    krb5_context ctx;
    krb5_error_code kerr;
    void *priv;
    int fd;
    struct serverlist list = SERVERLIST_INIT;
    struct module_callback_data cbdata = { 0 };
    ssize_t s;
    int ret;
    char host[NI_MAXHOST];
    char service[NI_MAXSERV];

    cbdata.list = &list;

    kerr = krb5_init_context (&ctx);
    assert_int_equal(kerr, 0);

    kerr = sssd_krb5_locator_init(ctx, &priv);
    assert_int_equal(kerr, 0);

    mkdir(TEST_PUBCONF_PATH, 0777);
    fd = open(TEST_PUBCONF_PATH"/kdcinfo."TEST_REALM, O_CREAT|O_RDWR, 0777);
    assert_int_not_equal(fd, -1);
    s = write(fd, TEST_IP_1_WITH_SERVICE, sizeof(TEST_IP_1_WITH_SERVICE));
    assert_int_equal(s, sizeof(TEST_IP_1_WITH_SERVICE));
    s = write(fd, "\n", 1);
    assert_int_equal(s, 1);
    s = write(fd, TEST_IPV6_1_WITH_SERVICE, sizeof(TEST_IPV6_1_WITH_SERVICE));
    assert_int_equal(s, sizeof(TEST_IPV6_1_WITH_SERVICE));
    close(fd);

    kerr = sssd_krb5_locator_lookup(priv, locate_service_kdc , TEST_REALM,
                                    SOCK_DGRAM, AF_INET6, module_callback,
                                    &cbdata);
    assert_int_equal(kerr, 0);

    assert_int_equal(list.nservers, 1);
    assert_non_null(list.servers);
    ret = getnameinfo((struct sockaddr *) &list.servers[0].addr,
                      list.servers[0].addrlen,
                      host, sizeof(host), service, sizeof(service),
                      NI_NUMERICHOST|NI_NUMERICSERV);
    assert_int_equal(ret, 0);
    assert_string_equal(TEST_IPV6_1_PURE, host);
    assert_string_equal(TEST_SERVICE_2, service);

    k5_free_serverlist(&list);

    kerr = sssd_krb5_locator_lookup(priv, locate_service_kdc , TEST_REALM,
                                    SOCK_DGRAM, AF_INET, module_callback,
                                    &cbdata);
    assert_int_equal(kerr, 0);
    assert_int_equal(list.nservers, 1);
    assert_non_null(list.servers);
    ret = getnameinfo((struct sockaddr *) &list.servers[0].addr,
                      list.servers[0].addrlen,
                      host, sizeof(host), service, sizeof(service),
                      NI_NUMERICHOST|NI_NUMERICSERV);
    assert_int_equal(ret, 0);
    assert_string_equal(TEST_IP_1, host);
    assert_string_equal(TEST_SERVICE_1, service);

    k5_free_serverlist(&list);

    /* locate_service_master_kdc should get the default port 88 if kpasswdinfo
     * does not exists. */
    kerr = sssd_krb5_locator_lookup(priv, locate_service_master_kdc, TEST_REALM,
                                    SOCK_DGRAM, AF_INET, module_callback,
                                    &cbdata);
    assert_int_equal(kerr, 0);
    assert_int_equal(list.nservers, 1);
    assert_non_null(list.servers);
    ret = getnameinfo((struct sockaddr *) &list.servers[0].addr,
                      list.servers[0].addrlen,
                      host, sizeof(host), service, sizeof(service),
                      NI_NUMERICHOST|NI_NUMERICSERV);
    assert_int_equal(ret, 0);
    assert_string_equal(TEST_IP_1, host);
    assert_string_equal("88", service);

    k5_free_serverlist(&list);

    kerr = sssd_krb5_locator_lookup(priv, locate_service_master_kdc, TEST_REALM,
                                    SOCK_DGRAM, AF_INET6, module_callback,
                                    &cbdata);
    assert_int_equal(kerr, 0);
    assert_int_equal(list.nservers, 1);
    assert_non_null(list.servers);
    ret = getnameinfo((struct sockaddr *) &list.servers[0].addr,
                      list.servers[0].addrlen,
                      host, sizeof(host), service, sizeof(service),
                      NI_NUMERICHOST|NI_NUMERICSERV);
    assert_int_equal(ret, 0);
    assert_string_equal(TEST_IPV6_1_PURE, host);
    assert_string_equal("88", service);

    k5_free_serverlist(&list);

    unlink(TEST_PUBCONF_PATH"/kdcinfo."TEST_REALM);
    rmdir(TEST_PUBCONF_PATH);
    sssd_krb5_locator_close(priv);

    krb5_free_context(ctx);
}

void test_kpasswd_and_master_kdc(void **state)
{
    krb5_context ctx;
    krb5_error_code kerr;
    void *priv;
    int fd;
    struct serverlist list = SERVERLIST_INIT;
    struct module_callback_data cbdata = { 0 };
    ssize_t s;
    int ret;
    char host[NI_MAXHOST];
    char service[NI_MAXSERV];

    cbdata.list = &list;

    kerr = krb5_init_context (&ctx);
    assert_int_equal(kerr, 0);

    kerr = sssd_krb5_locator_init(ctx, &priv);
    assert_int_equal(kerr, 0);

    mkdir(TEST_PUBCONF_PATH, 0777);
    fd = open(TEST_PUBCONF_PATH"/kdcinfo."TEST_REALM, O_CREAT|O_RDWR, 0777);
    assert_int_not_equal(fd, -1);
    s = write(fd, TEST_IP_1_WITH_SERVICE, sizeof(TEST_IP_1_WITH_SERVICE));
    assert_int_equal(s, sizeof(TEST_IP_1_WITH_SERVICE));
    s = write(fd, "\n", 1);
    assert_int_equal(s, 1);
    s = write(fd, TEST_IPV6_1_WITH_SERVICE, sizeof(TEST_IPV6_1_WITH_SERVICE));
    assert_int_equal(s, sizeof(TEST_IPV6_1_WITH_SERVICE));
    close(fd);
    fd = open(TEST_PUBCONF_PATH"/kpasswdinfo."TEST_REALM, O_CREAT|O_RDWR, 0777);
    assert_int_not_equal(fd, -1);
    s = write(fd, TEST_IP_1_WITH_SERVICE_2, sizeof(TEST_IP_1_WITH_SERVICE_2));
    assert_int_equal(s, sizeof(TEST_IP_1_WITH_SERVICE_2));
    s = write(fd, "\n", 1);
    assert_int_equal(s, 1);
    s = write(fd, TEST_IPV6_1_WITH_SERVICE_1,
              sizeof(TEST_IPV6_1_WITH_SERVICE_1));
    assert_int_equal(s, sizeof(TEST_IPV6_1_WITH_SERVICE_1));
    close(fd);

    kerr = sssd_krb5_locator_lookup(priv, locate_service_kpasswd, TEST_REALM,
                                    SOCK_DGRAM, AF_INET, module_callback,
                                    &cbdata);
    assert_int_equal(kerr, 0);
    assert_int_equal(list.nservers, 1);
    assert_non_null(list.servers);
    ret = getnameinfo((struct sockaddr *) &list.servers[0].addr,
                      list.servers[0].addrlen,
                      host, sizeof(host), service, sizeof(service),
                      NI_NUMERICHOST|NI_NUMERICSERV);
    assert_int_equal(ret, 0);
    assert_string_equal(TEST_IP_1, host);
    assert_string_equal(TEST_SERVICE_2, service);

    k5_free_serverlist(&list);

    kerr = sssd_krb5_locator_lookup(priv, locate_service_kpasswd , TEST_REALM,
                                    SOCK_DGRAM, AF_INET6, module_callback,
                                    &cbdata);
    assert_int_equal(kerr, 0);

    assert_int_equal(list.nservers, 1);
    assert_non_null(list.servers);
    ret = getnameinfo((struct sockaddr *) &list.servers[0].addr,
                      list.servers[0].addrlen,
                      host, sizeof(host), service, sizeof(service),
                      NI_NUMERICHOST|NI_NUMERICSERV);
    assert_int_equal(ret, 0);
    assert_string_equal(TEST_IPV6_1_PURE, host);
    assert_string_equal(TEST_SERVICE_1, service);

    k5_free_serverlist(&list);

    /* locate_service_master_kdc should use the default KDC port 88 and not
     * the one set in the kpasswdinfo file. */
    kerr = sssd_krb5_locator_lookup(priv, locate_service_master_kdc, TEST_REALM,
                                    SOCK_DGRAM, AF_INET, module_callback,
                                    &cbdata);
    assert_int_equal(kerr, 0);
    assert_int_equal(list.nservers, 1);
    assert_non_null(list.servers);
    ret = getnameinfo((struct sockaddr *) &list.servers[0].addr,
                      list.servers[0].addrlen,
                      host, sizeof(host), service, sizeof(service),
                      NI_NUMERICHOST|NI_NUMERICSERV);
    assert_int_equal(ret, 0);
    assert_string_equal(TEST_IP_1, host);
    assert_string_equal("88", service);

    k5_free_serverlist(&list);

    kerr = sssd_krb5_locator_lookup(priv, locate_service_master_kdc, TEST_REALM,
                                    SOCK_DGRAM, AF_INET6, module_callback,
                                    &cbdata);
    assert_int_equal(kerr, 0);
    assert_int_equal(list.nservers, 1);
    assert_non_null(list.servers);
    ret = getnameinfo((struct sockaddr *) &list.servers[0].addr,
                      list.servers[0].addrlen,
                      host, sizeof(host), service, sizeof(service),
                      NI_NUMERICHOST|NI_NUMERICSERV);
    assert_int_equal(ret, 0);
    assert_string_equal(TEST_IPV6_1_PURE, host);
    assert_string_equal("88", service);

    k5_free_serverlist(&list);

    unlink(TEST_PUBCONF_PATH"/kpasswdinfo."TEST_REALM);
    unlink(TEST_PUBCONF_PATH"/kdcinfo."TEST_REALM);
    rmdir(TEST_PUBCONF_PATH);
    sssd_krb5_locator_close(priv);

    krb5_free_context(ctx);
}

int main(int argc, const char *argv[])
{
    poptContext pc;
    int opt;
    int ret;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_init,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_failed_lookup,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_empty,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_single,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_multi,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_service,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_kpasswd_and_master_kdc,
                                        setup, teardown),
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

    ret = cmocka_run_group_tests(tests, NULL, NULL);

    return ret;
}
