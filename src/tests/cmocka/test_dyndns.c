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
#include "providers/dp_dyndns.c"

#include "tests/cmocka/common_mock.h"
#include "src/providers/dp_dyndns.h"

enum mock_nsupdate_states {
    MOCK_NSUPDATE_OK,
    MOCK_NSUPDATE_ERR,
    MOCK_NSUPDATE_TIMEOUT,
};

struct dyndns_test_ctx {
    struct sss_test_ctx *tctx;

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
            DEBUG(SSSDBG_FUNC_DATA, ("nsupdate success test case\n"));
            err = 0;
            break;
        case MOCK_NSUPDATE_ERR:
            DEBUG(SSSDBG_FUNC_DATA, ("nsupdate error test case\n"));
            err = 1;
            break;
        case MOCK_NSUPDATE_TIMEOUT:
            DEBUG(SSSDBG_FUNC_DATA, ("nsupdate timeout test case\n"));
            err = 2;
            sleep(3);
            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE, ("unknown test case\n"));
            err = 255;
            break;
    }

    DEBUG(SSSDBG_TRACE_LIBS, ("Child exiting with status %d\n", err));
    _exit(err);
}

int __wrap_getifaddrs(struct ifaddrs **_ifap)
{
    struct ifaddrs *ifap;
    struct ifaddrs *ifap_prev = NULL;
    struct ifaddrs *ifap_head = NULL;
    char *name;
    char *straddr;

    while ((name = sss_mock_ptr_type(char *)) != NULL) {
        straddr = sss_mock_ptr_type(char *);
        if (straddr == NULL) {
            errno = EINVAL;
            goto fail;
        }

        ifap = talloc_zero(global_talloc_context, struct ifaddrs);
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
        if (ifap == NULL) {
            errno = ENOMEM;
            goto fail;
        }

        ifap->ifa_addr = (struct sockaddr *) talloc(ifap, struct sockaddr_in);
        if (ifap->ifa_addr == NULL) {
            errno = ENOMEM;
            goto fail;
        }
        ((struct sockaddr_in *) ifap->ifa_addr)->sin_family = AF_INET;

        /* convert straddr into ifa_addr */
        if (inet_pton(AF_INET, straddr,
                      &(((struct sockaddr_in *) ifap->ifa_addr)->sin_addr)) != 1) {
            goto fail;
        }
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

void will_return_getifaddrs(const char *ifname, const char *straddr)
{
    will_return(__wrap_getifaddrs, ifname);
    if (ifname) {
        will_return(__wrap_getifaddrs, straddr);
    }
}

void dyndns_test_get_ifaddr(void **state)
{
    errno_t ret;
    struct sss_iface_addr *addrlist;
    char straddr[128];

    check_leaks_push(dyndns_test_ctx);
    will_return_getifaddrs("eth0", "192.168.0.1");
    will_return_getifaddrs("eth1", "192.168.0.2");
    will_return_getifaddrs(NULL, NULL); /* sentinel */
    ret = sss_iface_addr_list_get(dyndns_test_ctx, "eth0", &addrlist);
    assert_int_equal(ret, EOK);

    /* There must be only one address with the correct value */
    assert_non_null(addrlist);
    assert_non_null(addrlist->addr);
    assert_null(addrlist->next);
    assert_null(addrlist->prev);

    assert_non_null(inet_ntop(AF_INET,
                              &((struct sockaddr_in *) addrlist->addr)->sin_addr,
                              straddr, INET6_ADDRSTRLEN));
    assert_string_equal(straddr, "192.168.0.1");

    talloc_free(addrlist);
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
                           discard_const("test message"));
    assert_non_null(req);
    tevent_req_set_callback(req, dyndns_test_done, dyndns_test_ctx);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(dyndns_test_ctx->tctx);
    DEBUG(SSSDBG_TRACE_LIBS,
          ("Child request returned [%d]: %s\n", ret, strerror(ret)));
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
                           discard_const("test message"));
    assert_non_null(req);
    tevent_req_set_callback(req, dyndns_test_done, dyndns_test_ctx);

    /* Wait until the test finishes with EIO (child error) */
    ret = test_ev_loop(dyndns_test_ctx->tctx);
    DEBUG(SSSDBG_TRACE_LIBS,
          ("Child request returned [%d]: %s\n", ret, strerror(ret)));
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
                           discard_const("test message"));
    assert_non_null(req);
    tevent_req_set_callback(req, dyndns_test_done, dyndns_test_ctx);

    /* Wait until the test finishes with EIO (child error) */
    ret = test_ev_loop(dyndns_test_ctx->tctx);
    DEBUG(SSSDBG_TRACE_LIBS,
          ("Child request returned [%d]: %s\n", ret, strerror(ret)));
    assert_int_equal(ret, ERR_DYNDNS_TIMEOUT);

    assert_true(check_leaks_pop(tmp_ctx) == true);
    talloc_free(tmp_ctx);
}

/* Testsuite setup and teardown */
void dyndns_test_setup(void **state)
{
    assert_true(leak_check_setup());
    dyndns_test_ctx = talloc_zero(global_talloc_context, struct dyndns_test_ctx);
    assert_non_null(dyndns_test_ctx);

    dyndns_test_ctx->tctx = create_ev_test_ctx(dyndns_test_ctx);
    assert_non_null(dyndns_test_ctx->tctx);
}

void dyndns_test_teardown(void **state)
{
    talloc_free(dyndns_test_ctx);
    assert_true(leak_check_teardown());
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

    const UnitTest tests[] = {
        /* Utility functions unit test */
        unit_test(dyndns_test_get_ifaddr),

        /* Dynamic DNS update unit tests*/
        unit_test_setup_teardown(dyndns_test_ok,
                                 dyndns_test_setup, dyndns_test_teardown),
        unit_test_setup_teardown(dyndns_test_error,
                                 dyndns_test_setup, dyndns_test_teardown),
        unit_test_setup_teardown(dyndns_test_timeout,
                                 dyndns_test_setup, dyndns_test_teardown),
    };

    /* Set debug level to invalid value so we can deside if -d 0 was used. */
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

    DEBUG_INIT(debug_level);
    tests_set_cwd();
    rv = run_tests(tests);

    return rv;
}
