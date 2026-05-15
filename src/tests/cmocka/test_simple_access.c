/*
    Copyright (C) 2015 Red Hat

    SSSD tests: Simple access provider tests

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
#include <security/pam_appl.h>

#include "tests/cmocka/common_mock.h"
#include "tests/cmocka/common_mock_be.h"
#include "tests/cmocka/common_mock_resp.h"
#include "db/sysdb_private.h"   /* new_subdomain() */
#include "providers/simple/simple_access.h"
#include "providers/simple/simple_access_pvt.h"

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_DB "test_simple_conf.ldb"
#define TEST_DOM_NAME "simple_test"
#define TEST_SUBDOM_NAME "test.subdomain"
#define TEST_ID_PROVIDER "ldap"

struct simple_test_ctx {
    struct sss_test_ctx *tctx;
    struct be_ctx *be_ctx;
    struct sss_domain_info *subdom;

    bool access_granted;
    struct simple_ctx *ctx;
    struct pam_data *pd;
    struct dp_req_params *params;
};

static int test_simple_setup(struct sss_test_conf_param params[], void **state)
{
    struct simple_test_ctx *simple_test_ctx;
    int ret;

    simple_test_ctx = talloc_zero(NULL, struct simple_test_ctx);
    if (simple_test_ctx == NULL) {
        return ENOMEM;
    }

    simple_test_ctx->tctx = create_dom_test_ctx(simple_test_ctx, TESTS_PATH,
                                                TEST_CONF_DB, TEST_DOM_NAME,
                                                TEST_ID_PROVIDER, params);
    assert_non_null(simple_test_ctx->tctx);
    if (simple_test_ctx->tctx == NULL) {
        return ENOMEM;
    }

    ret = sss_names_init(simple_test_ctx, simple_test_ctx->tctx->confdb,
                         TEST_DOM_NAME, &simple_test_ctx->tctx->dom->names);
    if (ret != EOK) {
        return ENOMEM;
    }

    simple_test_ctx->be_ctx = mock_be_ctx(simple_test_ctx,
                                          simple_test_ctx->tctx);
    if (simple_test_ctx->be_ctx == NULL) {
        return ENOMEM;
    }

    simple_test_ctx->pd = talloc_zero(simple_test_ctx, struct pam_data);
    if (simple_test_ctx->pd == NULL) {
        return ENOMEM;
    }
    simple_test_ctx->pd->cmd = SSS_PAM_ACCT_MGMT;

    simple_test_ctx->params = talloc_zero(simple_test_ctx,
                                          struct dp_req_params);
    if (simple_test_ctx->params == NULL) {
        return ENOMEM;
    }
    simple_test_ctx->params->ev = simple_test_ctx->tctx->ev;

    *state = simple_test_ctx;
    return 0;
}

static int set_simple_lists(struct simple_test_ctx *test_ctx,
                            struct sss_domain_info *dom,
                            struct sss_test_conf_param params[])
{
    errno_t ret;
    const char *val[2] = { NULL, NULL };
    char *cdb_path;

    cdb_path = talloc_asprintf(test_ctx, CONFDB_DOMAIN_PATH_TMPL, dom->name);
    if (cdb_path == NULL) {
        return ENOMEM;
    }

    ret = EOK;

    if (params != NULL) {
        for (int i = 0; params[i].key != NULL; i++) {
            val[0] = params[i].value;
            ret = confdb_add_param(test_ctx->tctx->confdb,
                                   true, cdb_path, params[i].key, val);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Unable to add parameter %s [%d]: "
                      "%s\n", params[i].key, ret, sss_strerror(ret));
                break;
            }
        }
    }

    talloc_free(cdb_path);
    return ret;
}

static int setup_with_params(struct simple_test_ctx *test_ctx,
                             struct sss_domain_info *dom,
                             struct sss_test_conf_param params[])
{
    errno_t ret;

    ret = set_simple_lists(test_ctx, dom, params);
    if (ret != EOK) {
        return ret;
    }

    test_ctx->ctx = talloc_zero(test_ctx, struct simple_ctx);
    if (test_ctx->ctx == NULL) {
        return ENOMEM;
    }

    test_ctx->ctx->be_ctx = test_ctx->be_ctx;
    test_ctx->ctx->domain = test_ctx->tctx->dom;

    return EOK;
}

static int simple_test_setup(void **state)
{
    test_dom_suite_setup(TESTS_PATH);
    return test_simple_setup(NULL, state);
}

static int simple_test_teardown(void **state)
{
    struct simple_test_ctx *simple_test_ctx = \
                            talloc_get_type(*state, struct simple_test_ctx);

    /* make sure there are no leftovers from previous tests */
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);
    talloc_free(simple_test_ctx);
    return 0;
}

static void simple_access_handler_done(struct tevent_req *req)
{
    struct simple_test_ctx *simple_test_ctx =
                        tevent_req_callback_data(req, struct simple_test_ctx);

    simple_test_ctx->tctx->error = simple_access_handler_recv(simple_test_ctx,
                                                    req, &simple_test_ctx->pd);
    simple_test_ctx->access_granted = (simple_test_ctx->pd->pam_status == PAM_SUCCESS);
    talloc_free(req);
    simple_test_ctx->tctx->done = true;
}

static void run_simple_access_check(struct simple_test_ctx *simple_test_ctx,
                                    const char *username,
                                    int expected_rv,
                                    bool allow_access)
{
    int ret;
    struct tevent_req *req;

    simple_test_ctx->tctx->done = false;
    simple_test_ctx->pd->user = discard_const(username);
    req = simple_access_handler_send(simple_test_ctx,
                                     simple_test_ctx->ctx,
                                     simple_test_ctx->pd,
                                     simple_test_ctx->params);
    assert_non_null(req);
    tevent_req_set_callback(req, simple_access_handler_done, simple_test_ctx);

    ret = test_ev_loop(simple_test_ctx->tctx);
    assert_int_equal(ret, expected_rv);

    /* otherwise the output is undefined */
    if (expected_rv == EOK) {
        assert_true(simple_test_ctx->access_granted == allow_access);
    }
}

static void test_both_empty(void **state)
{
    errno_t ret;
    struct simple_test_ctx *simple_test_ctx = \
                            talloc_get_type(*state, struct simple_test_ctx);

    ret = setup_with_params(simple_test_ctx, simple_test_ctx->tctx->dom, NULL);
    assert_int_equal(ret, EOK);

    run_simple_access_check(simple_test_ctx, "u1@simple_test", EOK, true);
}

static void test_allow_empty(void **state)
{
    errno_t ret;
    struct simple_test_ctx *simple_test_ctx = \
                            talloc_get_type(*state, struct simple_test_ctx);
    struct sss_test_conf_param params[] = {
        { "simple_deny_users", "u1, u2" },
        { NULL, NULL },
    };

    ret = setup_with_params(simple_test_ctx, simple_test_ctx->tctx->dom, params);
    assert_int_equal(ret, EOK);

    run_simple_access_check(simple_test_ctx, "u1@simple_test", EOK, false);
    run_simple_access_check(simple_test_ctx, "u3@simple_test", EOK, true);
}

static void test_deny_empty(void **state)
{
    errno_t ret;
    struct simple_test_ctx *simple_test_ctx = \
                            talloc_get_type(*state, struct simple_test_ctx);
    struct sss_test_conf_param params[] = {
        { "simple_allow_users", "u1, u2" },
        { NULL, NULL },
    };
    ret = setup_with_params(simple_test_ctx, simple_test_ctx->tctx->dom, params);
    assert_int_equal(ret, EOK);

    run_simple_access_check(simple_test_ctx, "u1@simple_test", EOK, true);
    run_simple_access_check(simple_test_ctx, "u3@simple_test", EOK, false);
}

static void test_both_set(void **state)
{
    errno_t ret;
    struct simple_test_ctx *simple_test_ctx = \
                            talloc_get_type(*state, struct simple_test_ctx);
    struct sss_test_conf_param params[] = {
        { "simple_allow_users", "u1, u2" },
        { "simple_deny_users", "u1, u2" },
        { NULL, NULL },
    };

    ret = setup_with_params(simple_test_ctx,
                            simple_test_ctx->tctx->dom,
                            params);
    assert_int_equal(ret, EOK);

    run_simple_access_check(simple_test_ctx, "u1@simple_test", EOK, false);
    run_simple_access_check(simple_test_ctx, "u3@simple_test", EOK, false);
}

static void test_deny_wrong_case(void **state)
{
    errno_t ret;
    struct simple_test_ctx *simple_test_ctx = \
                            talloc_get_type(*state, struct simple_test_ctx);
    struct sss_test_conf_param params[] = {
        { "simple_allow_users", "u1, u2" },
        { NULL, NULL },
    };

    ret = setup_with_params(simple_test_ctx,
                            simple_test_ctx->tctx->dom,
                            params);
    assert_int_equal(ret, EOK);

    run_simple_access_check(simple_test_ctx, "U1@simple_test", EOK, false);
}

static void test_allow_case_insensitive(void **state)
{
    errno_t ret;
    struct simple_test_ctx *simple_test_ctx = \
                            talloc_get_type(*state, struct simple_test_ctx);
    struct sss_test_conf_param params[] = {
        { "simple_allow_users", "u1, u2" },
        { NULL, NULL },
    };

    ret = setup_with_params(simple_test_ctx,
                            simple_test_ctx->tctx->dom,
                            params);
    assert_int_equal(ret, EOK);

    simple_test_ctx->tctx->dom->case_sensitive = false;
    run_simple_access_check(simple_test_ctx, "U1@simple_test", EOK, true);
}

static void test_unknown_user(void **state)
{
    errno_t ret;
    struct simple_test_ctx *simple_test_ctx = \
                            talloc_get_type(*state, struct simple_test_ctx);
    struct sss_test_conf_param params[] = {
        { "simple_allow_users", "u1, u2" },
        { NULL, NULL },
    };

    ret = setup_with_params(simple_test_ctx,
                            simple_test_ctx->tctx->dom,
                            params);
    assert_int_equal(ret, EOK);

    run_simple_access_check(simple_test_ctx, "foo@simple_test", EOK, false);
}

static void test_space(void **state)
{
    errno_t ret;
    struct simple_test_ctx *simple_test_ctx = \
                            talloc_get_type(*state, struct simple_test_ctx);
    struct sss_test_conf_param params[] = {
        { "simple_allow_users", "space user, another user@simple_test" },
        { NULL, NULL },
    };

    ret = setup_with_params(simple_test_ctx, simple_test_ctx->tctx->dom, params);
    assert_int_equal(ret, EOK);

    run_simple_access_check(simple_test_ctx, "space user@simple_test", EOK, true);
    run_simple_access_check(simple_test_ctx, "another user@simple_test", EOK, true);
    run_simple_access_check(simple_test_ctx, "not allowed@simple_test", EOK, false);
}

static int simple_group_test_setup(void **state)
{
    int ret;
    char *u1;
    char *u2;
    char *u3;
    char *g1;
    char *g2;
    char *sp;
    char *sp2;
    char *pvt;
    struct simple_test_ctx *test_ctx;

    ret = simple_test_setup((void **) &test_ctx);
    if (ret != EOK) {
        return 1;
    }

    u1 = sss_create_internal_fqname(test_ctx, "u1",
                                    test_ctx->be_ctx->domain->name);
    u2 = sss_create_internal_fqname(test_ctx, "u2",
                                    test_ctx->be_ctx->domain->name);
    u3 = sss_create_internal_fqname(test_ctx, "u3",
                                    test_ctx->be_ctx->domain->name);
    g1 = sss_create_internal_fqname(test_ctx, "g1",
                                    test_ctx->be_ctx->domain->name);
    g2 = sss_create_internal_fqname(test_ctx, "g2",
                                    test_ctx->be_ctx->domain->name);
    sp = sss_create_internal_fqname(test_ctx, "space group",
                                    test_ctx->be_ctx->domain->name);
    sp2 = sss_create_internal_fqname(test_ctx, "another space",
                                     test_ctx->be_ctx->domain->name);
    pvt = sss_create_internal_fqname(test_ctx, "pvt",
                                     test_ctx->be_ctx->domain->name);
    if (u1 == NULL || u2 == NULL || u3 == NULL
            || g1 == NULL || g2 == NULL || pvt == NULL
            || sp == NULL || sp2 == NULL) {
        return 1;
    }

    ret = sysdb_add_group(test_ctx->be_ctx->domain, pvt, 999, NULL, 0, 0);
    if (ret != EOK) return 1;

    ret = sysdb_store_user(test_ctx->be_ctx->domain,
                           u1, NULL, 123, 999, "u1", "/home/u1",
                           "/bin/bash", NULL, NULL, NULL, -1, 0);
    if (ret != EOK) return 1;

    ret = sysdb_store_user(test_ctx->be_ctx->domain,
                           u2, NULL, 456, 999, "u1", "/home/u1",
                           "/bin/bash", NULL, NULL, NULL, -1, 0);
    if (ret != EOK) return 1;

    ret = sysdb_store_user(test_ctx->be_ctx->domain,
                           u3, NULL, 789, 999, "u1", "/home/u1",
                           "/bin/bash", NULL, NULL, NULL, -1, 0);
    if (ret != EOK) return 1;

    ret = sysdb_add_group(test_ctx->be_ctx->domain, g1, 321, NULL, 0, 0);
    if (ret != EOK) return 1;

    ret = sysdb_add_group(test_ctx->be_ctx->domain, g2, 654, NULL, 0, 0);
    if (ret != EOK) return 1;

    ret = sysdb_add_group(test_ctx->be_ctx->domain, sp, 1234, NULL, 0, 0);
    if (ret != EOK) return 1;

    ret = sysdb_add_group(test_ctx->be_ctx->domain, sp2, 5678, NULL, 0, 0);
    if (ret != EOK) return 1;

    ret = sysdb_add_group_member(test_ctx->be_ctx->domain,
                                 g1, u1, SYSDB_MEMBER_USER, false);
    if (ret != EOK) return 1;

    ret = sysdb_add_group_member(test_ctx->be_ctx->domain,
                                 sp, u1, SYSDB_MEMBER_USER, false);
    if (ret != EOK) return 1;

    ret = sysdb_add_group_member(test_ctx->be_ctx->domain,
                                 g2, u2, SYSDB_MEMBER_USER, false);
    if (ret != EOK) return 1;

    ret = sysdb_add_group_member(test_ctx->be_ctx->domain,
                                 sp2, u2, SYSDB_MEMBER_USER, false);
    if (ret != EOK) return 1;

    *state = test_ctx;
    return 0;
}

static int simple_group_test_teardown(void **state)
{
    int ret;
    char *u1;
    char *u2;
    char *u3;
    char *g1;
    char *g2;
    char *sp;
    char *sp2;
    char *pvt;
    struct simple_test_ctx *test_ctx = \
                            talloc_get_type(*state, struct simple_test_ctx);

    u1 = sss_create_internal_fqname(test_ctx, "u1",
                                    test_ctx->be_ctx->domain->name);
    u2 = sss_create_internal_fqname(test_ctx, "u2",
                                    test_ctx->be_ctx->domain->name);
    u3 = sss_create_internal_fqname(test_ctx, "u3",
                                    test_ctx->be_ctx->domain->name);
    g1 = sss_create_internal_fqname(test_ctx, "g1",
                                    test_ctx->be_ctx->domain->name);
    g2 = sss_create_internal_fqname(test_ctx, "g2",
                                    test_ctx->be_ctx->domain->name);
    sp = sss_create_internal_fqname(test_ctx, "space group",
                                    test_ctx->be_ctx->domain->name);
    sp2 = sss_create_internal_fqname(test_ctx, "another space",
                                     test_ctx->be_ctx->domain->name);
    pvt = sss_create_internal_fqname(test_ctx, "pvt",
                                     test_ctx->be_ctx->domain->name);
    if (u1 == NULL || u2 == NULL || u3 == NULL
            || g1 == NULL || g2 == NULL || pvt == NULL
            || sp == NULL || sp2 == NULL) {
        return 1;
    }

    ret = sysdb_delete_user(test_ctx->be_ctx->domain, u1, 0);
    if (ret != EOK) return 1;
    ret = sysdb_delete_user(test_ctx->be_ctx->domain, u2, 0);
    if (ret != EOK) return 1;
    ret = sysdb_delete_user(test_ctx->be_ctx->domain, u3, 0);
    if (ret != EOK) return 1;
    ret = sysdb_delete_group(test_ctx->be_ctx->domain, g1, 0);
    if (ret != EOK) return 1;
    ret = sysdb_delete_group(test_ctx->be_ctx->domain, g2, 0);
    if (ret != EOK) return 1;
    ret = sysdb_delete_group(test_ctx->be_ctx->domain, sp, 0);
    if (ret != EOK) return 1;
    ret = sysdb_delete_group(test_ctx->be_ctx->domain, sp2, 0);
    if (ret != EOK) return 1;
    ret = sysdb_delete_group(test_ctx->be_ctx->domain, pvt, 0);
    if (ret != EOK) return 1;

    /* make sure there are no leftovers from previous tests */
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);
    talloc_free(test_ctx);
    return 0;
}

static void test_group_allow_empty(void **state)
{
    errno_t ret;
    struct tevent_req *req;
    struct simple_test_ctx *simple_test_ctx = \
                            talloc_get_type(*state, struct simple_test_ctx);
    struct sss_test_conf_param params[] = {
        { "simple_deny_groups", "g1, g2" },
        { NULL, NULL },
    };

    ret = setup_with_params(simple_test_ctx,
                            simple_test_ctx->tctx->dom,
                            params);
    assert_int_equal(ret, EOK);

    simple_test_ctx->pd->user = discard_const("u1@simple_test");
    req = simple_access_handler_send(simple_test_ctx, simple_test_ctx->ctx,
                                     simple_test_ctx->pd,
                                     simple_test_ctx->params);
    assert_non_null(req);
    tevent_req_set_callback(req, simple_access_handler_done, simple_test_ctx);

    ret = test_ev_loop(simple_test_ctx->tctx);
    assert_int_equal(ret, EOK);
    assert_false(simple_test_ctx->access_granted);

    simple_test_ctx->tctx->done = false;
    simple_test_ctx->pd->user = discard_const("u3@simple_test");
    req = simple_access_handler_send(simple_test_ctx, simple_test_ctx->ctx,
                                     simple_test_ctx->pd,
                                     simple_test_ctx->params);
    assert_non_null(req);
    tevent_req_set_callback(req, simple_access_handler_done, simple_test_ctx);

    ret = test_ev_loop(simple_test_ctx->tctx);
    assert_int_equal(ret, EOK);
    assert_true(simple_test_ctx->access_granted);
}

static void test_group_deny_empty(void **state)
{
    errno_t ret;
    struct simple_test_ctx *simple_test_ctx = \
                            talloc_get_type(*state, struct simple_test_ctx);
    struct sss_test_conf_param params[] = {
        { "simple_allow_groups", "g1, g2" },
        { NULL, NULL },
    };

    ret = setup_with_params(simple_test_ctx, simple_test_ctx->tctx->dom, params);
    assert_int_equal(ret, EOK);

    run_simple_access_check(simple_test_ctx, "u1@simple_test", EOK, true);
    run_simple_access_check(simple_test_ctx, "u3@simple_test", EOK, false);
}

static void test_group_both_set(void **state)
{
    errno_t ret;
    struct simple_test_ctx *simple_test_ctx = \
                            talloc_get_type(*state, struct simple_test_ctx);
    struct sss_test_conf_param params[] = {
        { "simple_allow_groups", "g1, g2" },
        { "simple_deny_groups", "g1, g2" },
        { NULL, NULL },
    };

    ret = setup_with_params(simple_test_ctx, simple_test_ctx->tctx->dom, params);
    assert_int_equal(ret, EOK);

    run_simple_access_check(simple_test_ctx, "u1@simple_test", EOK, false);
    run_simple_access_check(simple_test_ctx, "u3@simple_test", EOK, false);
}

static void test_group_deny_wrong_case(void **state)
{
    errno_t ret;
    struct simple_test_ctx *simple_test_ctx = \
                            talloc_get_type(*state, struct simple_test_ctx);
    struct sss_test_conf_param params[] = {
        { "simple_allow_groups", "G1, G2" },
        { NULL, NULL },
    };

    ret = setup_with_params(simple_test_ctx,
                            simple_test_ctx->tctx->dom,
                            params);
    assert_int_equal(ret, EOK);

    run_simple_access_check(simple_test_ctx, "u1@simple_test", EOK, false);
}

static void test_group_allow_case_insensitive(void **state)
{
    errno_t ret;
    struct simple_test_ctx *simple_test_ctx = \
                            talloc_get_type(*state, struct simple_test_ctx);
    struct sss_test_conf_param params[] = {
        { "simple_allow_groups", "G1, G2" },
        { NULL, NULL },
    };

    ret = setup_with_params(simple_test_ctx,
                            simple_test_ctx->tctx->dom,
                            params);
    assert_int_equal(ret, EOK);

    /* Case-sensitive domain, wrong case */
    simple_test_ctx->tctx->done = false;
    simple_test_ctx->tctx->dom->case_sensitive = false;
    run_simple_access_check(simple_test_ctx, "u1@simple_test", EOK, true);
}

static void test_unparseable_allow_user(void **state)
{
    errno_t ret;
    struct simple_test_ctx *simple_test_ctx = \
                            talloc_get_type(*state, struct simple_test_ctx);
    struct sss_test_conf_param params[] = {
        { "simple_allow_users", "u1, user@no.such.domain" },
        { NULL, NULL },
    };

    ret = setup_with_params(simple_test_ctx,
                            simple_test_ctx->tctx->dom,
                            params);
    assert_int_equal(ret, EOK);

    /* Case-sensitive domain, wrong case */
    simple_test_ctx->tctx->done = false;
    simple_test_ctx->tctx->dom->case_sensitive = false;
    /* A user that would normally be denied access will be denied because
     * the access list can't be parsed
     */
    run_simple_access_check(simple_test_ctx, "u2@simple_test", EOK, false);
    /* A user that would normally be allowed access will be denied because
     * the access list can't be parsed
     */
    run_simple_access_check(simple_test_ctx, "u1@simple_test", EOK, false);
}

static void test_unparseable_deny_user(void **state)
{
    errno_t ret;
    struct simple_test_ctx *simple_test_ctx = \
                            talloc_get_type(*state, struct simple_test_ctx);
    struct sss_test_conf_param params[] = {
        { "simple_deny_users", "u2, user@no.such.domain" },
        { NULL, NULL },
    };

    ret = setup_with_params(simple_test_ctx,
                            simple_test_ctx->tctx->dom,
                            params);
    assert_int_equal(ret, EOK);

    /* Case-sensitive domain, wrong case */
    simple_test_ctx->tctx->done = false;
    simple_test_ctx->tctx->dom->case_sensitive = false;
    /* A user that would normally be denied access will be denied because
     * the access list can't be parsed
     */
    run_simple_access_check(simple_test_ctx, "u2@simple_test", EOK, false);
    /* A user that would normally be allowed access will be denied because
     * the access list can't be parsed
     */
    run_simple_access_check(simple_test_ctx, "u1@simple_test", EOK, false);
}

static void test_unparseable_allow_group(void **state)
{
    errno_t ret;
    struct simple_test_ctx *simple_test_ctx = \
                            talloc_get_type(*state, struct simple_test_ctx);
    struct sss_test_conf_param params[] = {
        { "simple_allow_groups", "g1, group@no.such.domain" },
        { NULL, NULL },
    };

    ret = setup_with_params(simple_test_ctx,
                            simple_test_ctx->tctx->dom,
                            params);
    assert_int_equal(ret, EOK);

    /* Case-sensitive domain, wrong case */
    simple_test_ctx->tctx->done = false;
    simple_test_ctx->tctx->dom->case_sensitive = false;
    /* A group that would normally be denied access will be denied because
     * the access list can't be parsed
     */
    run_simple_access_check(simple_test_ctx, "u2@simple_test", EOK, false);
    /* A group that would normally be allowed access will be denied because
     * the access list can't be parsed
     */
    run_simple_access_check(simple_test_ctx, "u1@simple_test", EOK, false);
}

static void test_unparseable_deny_group(void **state)
{
    errno_t ret;
    struct simple_test_ctx *simple_test_ctx = \
                            talloc_get_type(*state, struct simple_test_ctx);
    struct sss_test_conf_param params[] = {
        { "simple_deny_groups", "g2, group@no.such.domain" },
        { NULL, NULL },
    };

    ret = setup_with_params(simple_test_ctx,
                            simple_test_ctx->tctx->dom,
                            params);
    assert_int_equal(ret, EOK);

    /* Case-sensitive domain, wrong case */
    simple_test_ctx->tctx->done = false;
    simple_test_ctx->tctx->dom->case_sensitive = false;
    /* A group that would normally be denied access will be denied because
     * the access list can't be parsed
     */
    run_simple_access_check(simple_test_ctx, "u2@simple_test", EOK, false);
    /* A group that would normally be allowed access will be denied because
     * the access list can't be parsed
     */
    run_simple_access_check(simple_test_ctx, "u1@simple_test", EOK, false);
}

static void test_group_space(void **state)
{
    errno_t ret;
    struct simple_test_ctx *simple_test_ctx = \
                            talloc_get_type(*state, struct simple_test_ctx);
    struct sss_test_conf_param params[] = {
        { "simple_allow_groups", "space group, another space@simple_test" },
        { NULL, NULL },
    };

    ret = setup_with_params(simple_test_ctx, simple_test_ctx->tctx->dom, params);
    assert_int_equal(ret, EOK);

    run_simple_access_check(simple_test_ctx, "u1@simple_test", EOK, true);
    run_simple_access_check(simple_test_ctx, "u2@simple_test", EOK, true);
    run_simple_access_check(simple_test_ctx, "u3@simple_test", EOK, false);
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
        cmocka_unit_test_setup_teardown(test_both_empty,
                                        simple_test_setup,
                                        simple_test_teardown),
        cmocka_unit_test_setup_teardown(test_allow_empty,
                                        simple_test_setup,
                                        simple_test_teardown),
        cmocka_unit_test_setup_teardown(test_deny_empty,
                                        simple_test_setup,
                                        simple_test_teardown),
        cmocka_unit_test_setup_teardown(test_both_set,
                                        simple_test_setup,
                                        simple_test_teardown),
        cmocka_unit_test_setup_teardown(test_deny_wrong_case,
                                        simple_test_setup,
                                        simple_test_teardown),
        cmocka_unit_test_setup_teardown(test_allow_case_insensitive,
                                        simple_test_setup,
                                        simple_test_teardown),
        cmocka_unit_test_setup_teardown(test_unknown_user,
                                        simple_test_setup,
                                        simple_test_teardown),
        cmocka_unit_test_setup_teardown(test_space,
                                        simple_test_setup,
                                        simple_test_teardown),
        cmocka_unit_test_setup_teardown(test_group_allow_empty,
                                        simple_group_test_setup,
                                        simple_group_test_teardown),
        cmocka_unit_test_setup_teardown(test_group_deny_empty,
                                        simple_group_test_setup,
                                        simple_group_test_teardown),
        cmocka_unit_test_setup_teardown(test_group_both_set,
                                        simple_group_test_setup,
                                        simple_group_test_teardown),
        cmocka_unit_test_setup_teardown(test_group_deny_wrong_case,
                                        simple_group_test_setup,
                                        simple_group_test_teardown),
        cmocka_unit_test_setup_teardown(test_group_allow_case_insensitive,
                                        simple_group_test_setup,
                                        simple_group_test_teardown),
        cmocka_unit_test_setup_teardown(test_group_space,
                                        simple_group_test_setup,
                                        simple_group_test_teardown),
        cmocka_unit_test_setup_teardown(test_unparseable_allow_user,
                                        simple_test_setup,
                                        simple_test_teardown),
        cmocka_unit_test_setup_teardown(test_unparseable_deny_user,
                                        simple_test_setup,
                                        simple_test_teardown),
        cmocka_unit_test_setup_teardown(test_unparseable_allow_group,
                                        simple_test_setup,
                                        simple_test_teardown),
        cmocka_unit_test_setup_teardown(test_unparseable_deny_group,
                                        simple_test_setup,
                                        simple_test_teardown),
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
