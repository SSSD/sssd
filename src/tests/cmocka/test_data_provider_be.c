/*
    Copyright (C) 2015 Red Hat

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
#include <time.h>

#include "providers/backend.h"
#include "tests/cmocka/common_mock.h"
#include "tests/cmocka/common_mock_be.h"
#include "tests/common.h"

#define TESTS_PATH "tests_dp_be"
#define TEST_CONF_DB "test_dp_be_conf.ldb"
#define TEST_DOM_NAME "dp_be_test"
#define TEST_ID_PROVIDER "ldap"

#define OFFLINE_TIMEOUT 2

static TALLOC_CTX *global_mock_context = NULL;
static bool global_timer_added;

struct tevent_timer *__real__tevent_add_timer(struct tevent_context *ev,
                                              TALLOC_CTX *mem_ctx,
                                              struct timeval next_event,
                                              tevent_timer_handler_t handler,
                                              void *private_data,
                                              const char *handler_name,
                                              const char *location);

struct tevent_timer *__wrap__tevent_add_timer(struct tevent_context *ev,
                                              TALLOC_CTX *mem_ctx,
                                              struct timeval next_event,
                                              tevent_timer_handler_t handler,
                                              void *private_data,
                                              const char *handler_name,
                                              const char *location)
{
    global_timer_added = true;

    return __real__tevent_add_timer(ev, mem_ctx, next_event,
                                    handler, private_data, handler_name,
                                    location);
}


struct test_ctx {
    struct sss_test_ctx *tctx;
    struct be_ctx *be_ctx;
};

static int test_setup(void **state)
{
    struct test_ctx *test_ctx = NULL;
    struct sss_test_conf_param params[] = {
        { "offline_timeout", AS_STR(OFFLINE_TIMEOUT) },
        { NULL, NULL },             /* Sentinel */
    };

    assert_true(leak_check_setup());
    global_mock_context = talloc_new(global_talloc_context);
    assert_non_null(global_mock_context);

    test_ctx = talloc_zero(global_talloc_context, struct test_ctx);
    assert_non_null(test_ctx);

    test_ctx->tctx = create_dom_test_ctx(test_ctx, TESTS_PATH,
                                         TEST_CONF_DB, TEST_DOM_NAME,
                                         TEST_ID_PROVIDER, params);
    assert_non_null(test_ctx->tctx);

    test_ctx->be_ctx = mock_be_ctx(test_ctx, test_ctx->tctx);
    assert_non_null(test_ctx->be_ctx);

    test_ctx->be_ctx->domain->subdomains = named_domain(test_ctx,
                                                        "subdomains",
                                                        test_ctx->be_ctx->domain);
    assert_non_null(test_ctx->be_ctx->domain->subdomains);

    *state = test_ctx;

    return 0;
}

static int test_teardown(void **state)
{
    talloc_zfree(*state);
    assert_true(leak_check_teardown());
    return 0;
}

static void assert_domain_state(struct sss_domain_info *dom,
                                enum sss_domain_state expected_state)
{
    enum sss_domain_state dom_state;

    dom_state = sss_domain_get_state(dom);
    assert_int_equal(dom_state, expected_state);
}

static void test_mark_subdom_offline_check(struct tevent_context *ev,
                                           struct tevent_timer *te,
                                           struct timeval current_time,
                                           void *pvt)
{
    struct test_ctx *test_ctx = talloc_get_type(pvt, struct test_ctx);

    assert_domain_state(test_ctx->be_ctx->domain->subdomains,
                        DOM_ACTIVE);

    test_ctx->tctx->done = true;
    test_ctx->tctx->error = EOK;
}

static void test_mark_dom_offline(void **state)
{
    struct test_ctx *test_ctx = talloc_get_type(*state, struct test_ctx);

    assert_domain_state(test_ctx->be_ctx->domain, DOM_ACTIVE);
    assert_false(be_is_offline(test_ctx->be_ctx));

    be_mark_dom_offline(test_ctx->be_ctx->domain, test_ctx->be_ctx);

    assert_true(be_is_offline(test_ctx->be_ctx));
    assert_domain_state(test_ctx->be_ctx->domain, DOM_ACTIVE);
}

static void test_mark_subdom_offline(void **state)
{
    struct timeval tv;
    struct tevent_timer *check_ev = NULL;
    struct test_ctx *test_ctx = talloc_get_type(*state, struct test_ctx);
    errno_t ret;

    assert_domain_state(test_ctx->be_ctx->domain->subdomains,
                        DOM_ACTIVE);
    assert_false(be_is_offline(test_ctx->be_ctx));

    global_timer_added = false;
    be_mark_dom_offline(test_ctx->be_ctx->domain->subdomains, test_ctx->be_ctx);
    assert_domain_state(test_ctx->be_ctx->domain->subdomains,
                        DOM_INACTIVE);

    /* A timer must be added that resets the state back */
    assert_true(global_timer_added);

    /* Global offline state must not change */
    assert_false(be_is_offline(test_ctx->be_ctx));

    /* Make sure we don't add a second timer */
    global_timer_added = false;
    be_mark_dom_offline(test_ctx->be_ctx->domain->subdomains, test_ctx->be_ctx);
    assert_domain_state(test_ctx->be_ctx->domain->subdomains,
                        DOM_INACTIVE);
    assert_false(global_timer_added);

    /* Wait for the internal timer to reset our subdomain back */
    tv = tevent_timeval_current_ofs(OFFLINE_TIMEOUT + 1, 0);

    check_ev = tevent_add_timer(test_ctx->tctx->ev, test_ctx, tv,
                                test_mark_subdom_offline_check,
                                test_ctx);
    if (check_ev == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot create timer\n");
        return;
    }

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

static void test_mark_subdom_offline_disabled(void **state)
{
    struct test_ctx *test_ctx = talloc_get_type(*state, struct test_ctx);

    sss_domain_set_state(test_ctx->be_ctx->domain->subdomains, DOM_DISABLED);
    assert_domain_state(test_ctx->be_ctx->domain->subdomains,
                        DOM_DISABLED);

    be_mark_dom_offline(test_ctx->be_ctx->domain->subdomains, test_ctx->be_ctx);
    assert_domain_state(test_ctx->be_ctx->domain->subdomains,
                        DOM_DISABLED);
}

int main(int argc, const char *argv[])
{
    poptContext pc;
    int opt;
    int rv;
    int no_cleanup = 0;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        {"no-cleanup", 'n', POPT_ARG_NONE, &no_cleanup, 0,
         _("Do not delete the test database after a test run"), NULL },
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_mark_dom_offline,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_mark_subdom_offline,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_mark_subdom_offline_disabled,
                                        test_setup,
                                        test_teardown),
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

    return cmocka_run_group_tests(tests, NULL, NULL);
}
