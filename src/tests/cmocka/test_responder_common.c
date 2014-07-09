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

#define TESTS_PATH "tests_responder"
#define TEST_CONF_DB "test_responder_conf.ldb"
#define TEST_DOM_NAME "responder_test"
#define TEST_SYSDB_FILE "cache_"TEST_DOM_NAME".ldb"
#define TEST_ID_PROVIDER "ldap"

#define NAME "username"

static void
mock_sss_dp_done(struct tevent_context *ev,
                 struct tevent_immediate *imm,
                 void *pvt);

errno_t
sss_dp_issue_request(TALLOC_CTX *mem_ctx, struct resp_ctx *rctx,
                     const char *strkey, struct sss_domain_info *dom,
                     dbus_msg_constructor msg_create, void *pvt,
                     struct tevent_req *nreq)
{
    struct tevent_immediate *imm;

    imm = tevent_create_immediate(rctx->ev);
    if (imm == NULL) {
        return ENOMEM;
    }
    tevent_schedule_immediate(imm, rctx->ev, mock_sss_dp_done, nreq);
    return EOK;
}

static void
mock_sss_dp_done(struct tevent_context *ev,
                 struct tevent_immediate *imm,
                 void *pvt)
{
    struct tevent_req *req;

    talloc_free(imm);
    req = talloc_get_type(pvt, struct tevent_req);
    tevent_req_done(req);
}

errno_t
sss_dp_req_recv(TALLOC_CTX *mem_ctx,
                struct tevent_req *sidereq,
                dbus_uint16_t *dp_err,
                dbus_uint32_t *dp_ret,
                char **err_msg)
{
    return EOK;
}

struct parse_inp_test_ctx {
    struct sss_test_ctx *tctx;
    struct resp_ctx *rctx;
};

void parse_inp_test_setup(void **state)
{
    struct parse_inp_test_ctx *parse_inp_ctx;

    check_leaks_push(global_talloc_context);

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

    check_leaks_push(parse_inp_ctx);
    *state = parse_inp_ctx;
}

void parse_inp_test_teardown(void **state)
{
    struct parse_inp_test_ctx *parse_inp_ctx = talloc_get_type(*state,
                                                   struct parse_inp_test_ctx);

    assert_true(check_leaks_pop(parse_inp_ctx) == true);

    talloc_free(parse_inp_ctx);
    assert_true(check_leaks_pop(global_talloc_context) == true);
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
    parse_inp_ctx->tctx->done = true;
    assert_int_equal(ret, EOK);
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

    req = sss_parse_inp_send(parse_inp_ctx, parse_inp_ctx->rctx, NAME);
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

    req = sss_parse_inp_send(parse_inp_ctx, parse_inp_ctx->rctx, NAME);
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

    req = sss_parse_inp_send(parse_inp_ctx, parse_inp_ctx->rctx, NAME);
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
    parse_inp_ctx->tctx->done = true;
    assert_int_equal(ret, ERR_INPUT_PARSE);
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

    req = sss_parse_inp_send(parse_inp_ctx, parse_inp_ctx->rctx, NAME);
    assert_non_null(req);
    tevent_req_set_callback(req, parse_inp_neg_done, parse_inp_ctx);

    ret = test_ev_loop(parse_inp_ctx->tctx);
    assert_int_equal(ret, EOK);
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

    const UnitTest tests[] = {
        unit_test_setup_teardown(parse_inp_simple,
                                 parse_inp_test_setup,
                                 parse_inp_test_teardown),
        unit_test_setup_teardown(parse_inp_call_dp,
                                 parse_inp_test_setup,
                                 parse_inp_test_teardown),
        unit_test_setup_teardown(parse_inp_call_attach,
                                 parse_inp_test_setup,
                                 parse_inp_test_teardown),
        unit_test_setup_teardown(parse_inp_call_neg,
                                 parse_inp_test_setup,
                                 parse_inp_test_teardown),
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

    DEBUG_CLI_INIT(debug_level);

    /* Even though normally the tests should clean up after themselves
     * they might not after a failed run. Remove the old db to be sure */
    tests_set_cwd();
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_SYSDB_FILE);
    test_dom_suite_setup(TESTS_PATH);

    rv = run_tests(tests);
    if (rv == 0 && !no_cleanup) {
        test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_SYSDB_FILE);
    }
    return rv;
}
