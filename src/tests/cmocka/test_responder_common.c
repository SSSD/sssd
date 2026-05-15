/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2014 Red Hat

    SSSD tests: Common responder code tests

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

#include "tests/cmocka/common_mock.h"
#include "tests/cmocka/common_mock_resp.h"

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_DB "test_responder_conf.ldb"
#define TEST_DOM_NAME "responder_test"
#define TEST_ID_PROVIDER "ldap"

#define NAME "username"

/* register_cli_protocol_version is required in test since it links with
 * responder_common.c module
 */
struct cli_protocol_version *register_cli_protocol_version(void)
{
    static struct cli_protocol_version responder_test_cli_protocol_version[] = {
        { 0, NULL, NULL }
    };

    return responder_test_cli_protocol_version;
}

struct parse_inp_test_ctx {
    struct sss_test_ctx *tctx;
    struct resp_ctx *rctx;
};

static int parse_inp_test_setup(void **state)
{
    struct parse_inp_test_ctx *parse_inp_ctx;
    int ret;

    assert_true(leak_check_setup());
    parse_inp_ctx = talloc_zero(global_talloc_context, struct parse_inp_test_ctx);
    assert_non_null(parse_inp_ctx);

    parse_inp_ctx->tctx = create_dom_test_ctx(parse_inp_ctx, TESTS_PATH,
                                              TEST_CONF_DB, TEST_DOM_NAME,
                                              TEST_ID_PROVIDER, NULL);
    assert_non_null(parse_inp_ctx->tctx);

    parse_inp_ctx->rctx = mock_rctx(parse_inp_ctx,
                                    parse_inp_ctx->tctx->ev,
                                    parse_inp_ctx->tctx->dom,
                                    parse_inp_ctx);
    assert_non_null(parse_inp_ctx->rctx);

    /* Testing the request race condition should be a special case */
    gettimeofday(&parse_inp_ctx->rctx->get_domains_last_call, NULL);

    /* sysdb_master_domain_update sets the view name, if we do not call it
     * here we get a leak check warning when sysdb_master_domain_update is
     * called later while processing the tests. */
    ret = sysdb_master_domain_update(parse_inp_ctx->tctx->dom);
    assert_int_equal(ret, EOK);

    check_leaks_push(parse_inp_ctx);
    *state = parse_inp_ctx;
    return 0;
}

static int parse_inp_test_teardown(void **state)
{
    struct parse_inp_test_ctx *parse_inp_ctx = talloc_get_type(*state,
                                                   struct parse_inp_test_ctx);

    assert_true(check_leaks_pop(parse_inp_ctx) == true);

    talloc_free(parse_inp_ctx);
    assert_true(leak_check_teardown());
    return 0;
}

int __real_sss_parse_name_for_domains(TALLOC_CTX *memctx,
                                      struct sss_domain_info *domains,
                                      const char *default_domain,
                                      const char *orig, char **domain, char **name);

int __wrap_sss_parse_name_for_domains(TALLOC_CTX *memctx,
                                      struct sss_domain_info *domains,
                                      const char *default_domain,
                                      const char *orig, char **domain, char **name)
{
    enum sss_test_wrapper_call wtype = sss_mock_type(enum sss_test_wrapper_call);
    errno_t ret;

    if (wtype == WRAP_CALL_REAL) {
        return __real_sss_parse_name_for_domains(memctx, domains,
                                                 default_domain, orig,
                                                 domain, name);
    }

    ret = sss_mock_type(errno_t);
    return ret;
}

void parse_inp_simple_done(struct tevent_req *req)
{
    errno_t ret;
    struct parse_inp_test_ctx *parse_inp_ctx =
        tevent_req_callback_data(req, struct parse_inp_test_ctx);
    char *name = NULL;
    char *domname = NULL;

    ret = sss_parse_inp_recv(req, parse_inp_ctx, &name, &domname);
    assert_int_equal(ret, EOK);

    test_ev_done(parse_inp_ctx->tctx, EOK);
    talloc_free(req);

    assert_string_equal(name, NAME);
    assert_null(domname);
    talloc_free(name);
}

void parse_inp_simple(void **state)
{
    struct parse_inp_test_ctx *parse_inp_ctx = talloc_get_type(*state,
                                                   struct parse_inp_test_ctx);
    struct tevent_req *req;
    errno_t ret;

    will_return(__wrap_sss_parse_name_for_domains, WRAP_CALL_REAL);

    req = sss_parse_inp_send(parse_inp_ctx, parse_inp_ctx->rctx,
                             parse_inp_ctx->rctx->default_domain, NAME);
    assert_non_null(req);
    tevent_req_set_callback(req, parse_inp_simple_done, parse_inp_ctx);

    ret = test_ev_loop(parse_inp_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void parse_inp_call_dp(void **state)
{
    struct parse_inp_test_ctx *parse_inp_ctx = talloc_get_type(*state,
                                                   struct parse_inp_test_ctx);
    struct tevent_req *req;
    errno_t ret;

    /* First call will indicate we need to go to DP */
    will_return(__wrap_sss_parse_name_for_domains, WRAP_CALL_WRAPPER);
    will_return(__wrap_sss_parse_name_for_domains, EAGAIN);
    /* The second one will succeed as the domains are up-to-date */
    will_return(__wrap_sss_parse_name_for_domains, WRAP_CALL_REAL);

    req = sss_parse_inp_send(parse_inp_ctx, parse_inp_ctx->rctx,
                             parse_inp_ctx->rctx->default_domain, NAME);
    assert_non_null(req);
    tevent_req_set_callback(req, parse_inp_simple_done, parse_inp_ctx);

    ret = test_ev_loop(parse_inp_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void parse_inp_call_attach(void **state)
{
    struct parse_inp_test_ctx *parse_inp_ctx = talloc_get_type(*state,
                                                   struct parse_inp_test_ctx);
    struct tevent_req *req;
    errno_t ret;

    /* simulate responder startup */
    parse_inp_ctx->rctx->get_domains_last_call.tv_sec = 0;

    /* The first parse wouldn't be called, the second one will succeed
     * as the domains are up-to-date */
    will_return(__wrap_sss_parse_name_for_domains, WRAP_CALL_REAL);

    req = sss_parse_inp_send(parse_inp_ctx, parse_inp_ctx->rctx,
                             parse_inp_ctx->rctx->default_domain, NAME);
    assert_non_null(req);
    tevent_req_set_callback(req, parse_inp_simple_done, parse_inp_ctx);

    ret = test_ev_loop(parse_inp_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void parse_inp_neg_done(struct tevent_req *req)
{
    errno_t ret;
    struct parse_inp_test_ctx *parse_inp_ctx =
        tevent_req_callback_data(req, struct parse_inp_test_ctx);
    char *name = NULL;
    char *domname = NULL;

    ret = sss_parse_inp_recv(req, parse_inp_ctx, &name, &domname);
    assert_int_equal(ret, ERR_INPUT_PARSE);
    test_ev_done(parse_inp_ctx->tctx, EOK);
    talloc_free(req);

    assert_null(name);
    assert_null(domname);
}

void parse_inp_call_neg(void **state)
{
    struct parse_inp_test_ctx *parse_inp_ctx = talloc_get_type(*state,
                                                   struct parse_inp_test_ctx);
    struct tevent_req *req;
    errno_t ret;

    /* Simulate an error */
    will_return(__wrap_sss_parse_name_for_domains, WRAP_CALL_WRAPPER);
    will_return(__wrap_sss_parse_name_for_domains, EINVAL);

    req = sss_parse_inp_send(parse_inp_ctx, parse_inp_ctx->rctx,
                             parse_inp_ctx->rctx->default_domain, NAME);
    assert_non_null(req);
    tevent_req_set_callback(req, parse_inp_neg_done, parse_inp_ctx);

    ret = test_ev_loop(parse_inp_ctx->tctx);
    assert_int_equal(ret, EOK);
}

struct sss_nc_ctx {
    struct parse_inp_test_ctx *pctx;
};

errno_t __wrap_sss_ncache_reset_repopulate_permanent(struct resp_ctx *rctx,
                                                     struct sss_nc_ctx *dummy_ncache_ptr)
{
    test_ev_done(dummy_ncache_ptr->pctx->tctx, EOK);
    return EOK;
}

void test_schedule_get_domains_task(void **state)
{
    struct parse_inp_test_ctx *parse_inp_ctx = talloc_get_type(*state,
                                                   struct parse_inp_test_ctx);
    errno_t ret;
    struct sss_nc_ctx *dummy_ncache_ptr;

    dummy_ncache_ptr = talloc(parse_inp_ctx, struct sss_nc_ctx);
    assert_non_null(dummy_ncache_ptr);
    dummy_ncache_ptr->pctx = parse_inp_ctx;

    ret = schedule_get_domains_task(dummy_ncache_ptr,
                                    parse_inp_ctx->rctx->ev,
                                    parse_inp_ctx->rctx,
                                    dummy_ncache_ptr, NULL, NULL);
    assert_int_equal(ret, EOK);

    ret = test_ev_loop(parse_inp_ctx->tctx);
    assert_int_equal(ret, EOK);
    talloc_free(dummy_ncache_ptr);
}

void test_sss_output_fqname(void **state)
{
    struct parse_inp_test_ctx *parse_inp_ctx = talloc_get_type(*state,
                                                   struct parse_inp_test_ctx);
    errno_t ret;
    struct sized_string *res = NULL;

    ret = sized_output_name(parse_inp_ctx, parse_inp_ctx->rctx, "dummy",
                            parse_inp_ctx->tctx->dom, &res);
    assert_int_equal(ret, EOK);
    assert_non_null(res);
    assert_string_equal("dummy", res->str);
    assert_int_equal(6, res->len);

    talloc_zfree(res);
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
        cmocka_unit_test_setup_teardown(parse_inp_simple,
                                        parse_inp_test_setup,
                                        parse_inp_test_teardown),
// TODO fix these tests, see:
// https://github.com/SSSD/sssd/issues/4801
//        cmocka_unit_test_setup_teardown(parse_inp_call_dp,
//                                        parse_inp_test_setup,
//                                        parse_inp_test_teardown),
//        cmocka_unit_test_setup_teardown(parse_inp_call_attach,
//                                        parse_inp_test_setup,
//                                        parse_inp_test_teardown),
        cmocka_unit_test_setup_teardown(parse_inp_call_neg,
                                        parse_inp_test_setup,
                                        parse_inp_test_teardown),
        cmocka_unit_test_setup_teardown(test_schedule_get_domains_task,
                                        parse_inp_test_setup,
                                        parse_inp_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_output_fqname,
                                        parse_inp_test_setup,
                                        parse_inp_test_teardown),
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
