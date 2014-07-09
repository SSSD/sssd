/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2013 Red Hat

    SSSD tests: Tests for utility functions

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

#include <popt.h>

#include "tests/cmocka/common_mock.h"
#include "util/sss_nss.h"

#define TESTS_PATH "tests_utils"
#define TEST_CONF_DB "test_utils_conf.ldb"
#define TEST_SYSDB_FILE "cache_utils_test.ldb"

#define DOM_COUNT 10
#define DOMNAME_TMPL "name_%zu.dom"
#define FLATNAME_TMPL "name_%zu"
#define SID_TMPL "S-1-5-21-1-2-%zu"

#define MACRO_EXPAND(tok) #tok
#define STR(tok) MACRO_EXPAND(tok)

#define USERNAME "sssduser"
#define UID      1234
#define DOMAIN   "sssddomain"
#define ORIGINAL_HOME "/home/user"
#define FLATNAME "flatname"
#define HOMEDIR_SUBSTR "/mnt/home"

#define DUMMY "dummy"
#define DUMMY2 "dummy2"

struct dom_list_test_ctx {
    size_t dom_count;
    struct sss_domain_info *dom_list;
};

void test_textual_public_key(void **state);

void setup_dom_list(void **state)
{
    struct dom_list_test_ctx *test_ctx;
    struct sss_domain_info *dom = NULL;
    size_t c;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context, struct dom_list_test_ctx);
    assert_non_null(test_ctx);

    test_ctx->dom_count = DOM_COUNT;

    for (c = 0; c < test_ctx->dom_count; c++) {
        dom = talloc_zero(test_ctx, struct sss_domain_info);
        assert_non_null(dom);

        dom->name = talloc_asprintf(dom, DOMNAME_TMPL, c);
        assert_non_null(dom->name);

        dom->flat_name = talloc_asprintf(dom, FLATNAME_TMPL, c);
        assert_non_null(dom->flat_name);

        dom->domain_id = talloc_asprintf(dom, SID_TMPL, c);
        assert_non_null(dom->domain_id);

        DLIST_ADD(test_ctx->dom_list, dom);
    }

    check_leaks_push(test_ctx);
    *state = test_ctx;
}

void teardown_dom_list(void **state)
{
    struct dom_list_test_ctx *test_ctx = talloc_get_type(*state,
                                                      struct dom_list_test_ctx);
    if (test_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Type mismatch\n");
        return;
    }

    assert_true(check_leaks_pop(test_ctx) == true);
    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
}

void test_find_subdomain_by_name_null(void **state)
{
    struct dom_list_test_ctx *test_ctx = talloc_get_type(*state,
                                                      struct dom_list_test_ctx);
    struct sss_domain_info *dom;

    dom = find_subdomain_by_name(NULL, NULL, false);
    assert_null(dom);

    dom = find_subdomain_by_name(test_ctx->dom_list, NULL, false);
    assert_null(dom);

    dom = find_subdomain_by_name(NULL, "test", false);
    assert_null(dom);
}

void test_find_subdomain_by_name(void **state)
{
    struct dom_list_test_ctx *test_ctx = talloc_get_type(*state,
                                                      struct dom_list_test_ctx);
    struct sss_domain_info *dom;
    size_t c;
    char *name;
    char *flat_name;
    char *sid;

    for (c = 0; c < test_ctx->dom_count; c++) {
        name = talloc_asprintf(global_talloc_context, DOMNAME_TMPL, c);
        assert_non_null(name);

        flat_name = talloc_asprintf(global_talloc_context, FLATNAME_TMPL, c);
        assert_non_null(flat_name);

        sid = talloc_asprintf(global_talloc_context, SID_TMPL, c);
        assert_non_null(sid);

        dom = find_subdomain_by_name(test_ctx->dom_list, name, false);
        assert_non_null(dom);
        assert_string_equal(name, dom->name);
        assert_string_equal(flat_name, dom->flat_name);
        assert_string_equal(sid, dom->domain_id);

        dom = find_subdomain_by_name(test_ctx->dom_list, name, true);
        assert_non_null(dom);
        assert_string_equal(name, dom->name);
        assert_string_equal(flat_name, dom->flat_name);
        assert_string_equal(sid, dom->domain_id);

        dom = find_subdomain_by_name(test_ctx->dom_list, flat_name, true);
        assert_non_null(dom);
        assert_string_equal(name, dom->name);
        assert_string_equal(flat_name, dom->flat_name);
        assert_string_equal(sid, dom->domain_id);

        dom = find_subdomain_by_name(test_ctx->dom_list, flat_name, false);
        assert_null(dom);

        talloc_free(name);
        talloc_free(flat_name);
        talloc_free(sid);
    }
}

void test_find_subdomain_by_name_missing_flat_name(void **state)
{
    struct dom_list_test_ctx *test_ctx = talloc_get_type(*state,
                                                      struct dom_list_test_ctx);
    struct sss_domain_info *dom;
    size_t c;
    char *name;
    char *flat_name;
    char *sid;
    size_t mis;

    mis = test_ctx->dom_count/2;
    assert_true((mis >= 1 && mis < test_ctx->dom_count));

    dom = test_ctx->dom_list;
    for (c = 0; c < mis; c++) {
        assert_non_null(dom);
        dom = dom->next;
    }
    assert_non_null(dom);
    dom->flat_name = NULL;

    for (c = 0; c < test_ctx->dom_count; c++) {
        name = talloc_asprintf(global_talloc_context, DOMNAME_TMPL, c);
        assert_non_null(name);

        flat_name = talloc_asprintf(global_talloc_context, FLATNAME_TMPL, c);
        assert_non_null(flat_name);

        sid = talloc_asprintf(global_talloc_context, SID_TMPL, c);
        assert_non_null(sid);

        dom = find_subdomain_by_name(test_ctx->dom_list, name, true);
        assert_non_null(dom);
        assert_string_equal(name, dom->name);
        if (c == mis - 1) {
            assert_null(dom->flat_name);
        } else {
            assert_string_equal(flat_name, dom->flat_name);
        }
        assert_string_equal(sid, dom->domain_id);

        dom = find_subdomain_by_name(test_ctx->dom_list, name, false);
        assert_non_null(dom);
        assert_string_equal(name, dom->name);
        if (c == mis - 1) {
            assert_null(dom->flat_name);
        } else {
            assert_string_equal(flat_name, dom->flat_name);
        }
        assert_string_equal(sid, dom->domain_id);

        dom = find_subdomain_by_name(test_ctx->dom_list, flat_name, true);
        if (c == mis - 1) {
            assert_null(dom);
        } else {
            assert_non_null(dom);
            assert_string_equal(name, dom->name);
            assert_string_equal(flat_name, dom->flat_name);
            assert_string_equal(sid, dom->domain_id);
        }

        dom = find_subdomain_by_name(test_ctx->dom_list, flat_name, false);
        assert_null(dom);

        talloc_free(name);
        talloc_free(flat_name);
        talloc_free(sid);
    }
}

void test_find_subdomain_by_name_disabled(void **state)
{
    struct dom_list_test_ctx *test_ctx = talloc_get_type(*state,
                                                      struct dom_list_test_ctx);
    struct sss_domain_info *dom;
    size_t c;
    char *name;
    char *flat_name;
    char *sid;
    size_t mis;

    mis = test_ctx->dom_count/2;
    assert_true((mis >= 1 && mis < test_ctx->dom_count));

    dom = test_ctx->dom_list;
    for (c = 0; c < mis; c++) {
        assert_non_null(dom);
        dom = dom->next;
    }
    assert_non_null(dom);
    dom->disabled = true;

    for (c = 0; c < test_ctx->dom_count; c++) {
        name = talloc_asprintf(global_talloc_context, DOMNAME_TMPL, c);
        assert_non_null(name);

        flat_name = talloc_asprintf(global_talloc_context, FLATNAME_TMPL, c);
        assert_non_null(flat_name);

        sid = talloc_asprintf(global_talloc_context, SID_TMPL, c);
        assert_non_null(sid);

        dom = find_subdomain_by_name(test_ctx->dom_list, name, true);
        if (c == mis - 1) {
            assert_null(dom);
        } else {
            assert_non_null(dom);
            assert_string_equal(name, dom->name);
            assert_string_equal(flat_name, dom->flat_name);
            assert_string_equal(sid, dom->domain_id);
        }

        dom = find_subdomain_by_name(test_ctx->dom_list, name, false);
        if (c == mis - 1) {
            assert_null(dom);
        } else {
            assert_non_null(dom);
            assert_string_equal(name, dom->name);
            assert_string_equal(flat_name, dom->flat_name);
            assert_string_equal(sid, dom->domain_id);
        }

        dom = find_subdomain_by_name(test_ctx->dom_list, flat_name, true);
        if (c == mis - 1) {
            assert_null(dom);
        } else {
            assert_non_null(dom);
            assert_string_equal(name, dom->name);
            assert_string_equal(flat_name, dom->flat_name);
            assert_string_equal(sid, dom->domain_id);
        }

        dom = find_subdomain_by_name(test_ctx->dom_list, flat_name, false);
        assert_null(dom);

        talloc_free(name);
        talloc_free(flat_name);
        talloc_free(sid);
    }
}

void test_find_subdomain_by_sid_null(void **state)
{
    struct dom_list_test_ctx *test_ctx = talloc_get_type(*state,
                                                      struct dom_list_test_ctx);
    struct sss_domain_info *dom;

    dom = find_subdomain_by_sid(NULL, NULL);
    assert_null(dom);

    dom = find_subdomain_by_sid(test_ctx->dom_list, NULL);
    assert_null(dom);

    dom = find_subdomain_by_sid(NULL, "S-1-5-21-1-2-3");
    assert_null(dom);
}

void test_find_subdomain_by_sid(void **state)
{
    struct dom_list_test_ctx *test_ctx = talloc_get_type(*state,
                                                      struct dom_list_test_ctx);
    struct sss_domain_info *dom;
    size_t c;
    char *name;
    char *flat_name;
    char *sid;

    for (c = 0; c < test_ctx->dom_count; c++) {
        name = talloc_asprintf(global_talloc_context, DOMNAME_TMPL, c);
        assert_non_null(name);

        flat_name = talloc_asprintf(global_talloc_context, FLATNAME_TMPL, c);
        assert_non_null(flat_name);

        sid = talloc_asprintf(global_talloc_context, SID_TMPL, c);
        assert_non_null(sid);

        dom = find_subdomain_by_sid(test_ctx->dom_list, sid);
        assert_non_null(dom);
        assert_string_equal(name, dom->name);
        assert_string_equal(flat_name, dom->flat_name);
        assert_string_equal(sid, dom->domain_id);

        talloc_free(name);
        talloc_free(flat_name);
        talloc_free(sid);
    }
}

void test_find_subdomain_by_sid_missing_sid(void **state)
{
    struct dom_list_test_ctx *test_ctx = talloc_get_type(*state,
                                                      struct dom_list_test_ctx);
    struct sss_domain_info *dom;
    size_t c;
    char *name;
    char *flat_name;
    char *sid;
    size_t mis;

    mis = test_ctx->dom_count/2;
    assert_true((mis >= 1 && mis < test_ctx->dom_count));

    dom = test_ctx->dom_list;
    for (c = 0; c < mis; c++) {
        assert_non_null(dom);
        dom = dom->next;
    }
    assert_non_null(dom);
    dom->domain_id = NULL;

    for (c = 0; c < test_ctx->dom_count; c++) {
        name = talloc_asprintf(global_talloc_context, DOMNAME_TMPL, c);
        assert_non_null(name);

        flat_name = talloc_asprintf(global_talloc_context, FLATNAME_TMPL, c);
        assert_non_null(flat_name);

        sid = talloc_asprintf(global_talloc_context, SID_TMPL, c);
        assert_non_null(sid);

        dom = find_subdomain_by_sid(test_ctx->dom_list, sid);
        if (c == mis - 1) {
            assert_null(dom);
        } else {
            assert_non_null(dom);
            assert_string_equal(name, dom->name);
            assert_string_equal(flat_name, dom->flat_name);
            assert_string_equal(sid, dom->domain_id);
        }

        talloc_free(name);
        talloc_free(flat_name);
        talloc_free(sid);
    }
}

void test_find_subdomain_by_sid_disabled(void **state)
{
    struct dom_list_test_ctx *test_ctx = talloc_get_type(*state,
                                                      struct dom_list_test_ctx);
    struct sss_domain_info *dom;
    size_t c;
    char *name;
    char *flat_name;
    char *sid;
    size_t mis;

    mis = test_ctx->dom_count/2;
    assert_true((mis >= 1 && mis < test_ctx->dom_count));

    dom = test_ctx->dom_list;
    for (c = 0; c < mis; c++) {
        assert_non_null(dom);
        dom = dom->next;
    }
    assert_non_null(dom);
    dom->disabled = true;

    for (c = 0; c < test_ctx->dom_count; c++) {
        name = talloc_asprintf(global_talloc_context, DOMNAME_TMPL, c);
        assert_non_null(name);

        flat_name = talloc_asprintf(global_talloc_context, FLATNAME_TMPL, c);
        assert_non_null(flat_name);

        sid = talloc_asprintf(global_talloc_context, SID_TMPL, c);
        assert_non_null(sid);

        dom = find_subdomain_by_sid(test_ctx->dom_list, sid);
        if (c == mis - 1) {
            assert_null(dom);
        } else {
            assert_non_null(dom);
            assert_string_equal(name, dom->name);
            assert_string_equal(flat_name, dom->flat_name);
            assert_string_equal(sid, dom->domain_id);
        }

        talloc_free(name);
        talloc_free(flat_name);
        talloc_free(sid);
    }
}

struct name_init_test_ctx {
    struct confdb_ctx *confdb;
};

#define GLOBAL_FULL_NAME_FORMAT "%1$s@%2$s"
#define GLOBAL_RE_EXPRESSION "(?P<name>[^@]+)@?(?P<domain>[^@]*$)"

#define TEST_DOMAIN_NAME "test.dom"
#define DOMAIN_FULL_NAME_FORMAT "%3$s\\%1$s"
#define DOMAIN_RE_EXPRESSION "(((?P<domain>[^\\\\]+)\\\\(?P<name>.+$))|" \
                             "((?P<name>[^@]+)@(?P<domain>.+$))|" \
                             "(^(?P<name>[^@\\\\]+)$))"

void confdb_test_setup(void **state)
{
    struct name_init_test_ctx *test_ctx;
    char *conf_db = NULL;
    char *dompath = NULL;
    int ret;
    const char *val[2];
    val[1] = NULL;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context, struct name_init_test_ctx);
    assert_non_null(test_ctx);

    conf_db = talloc_asprintf(test_ctx, "%s/%s", TESTS_PATH, TEST_CONF_DB);
    assert_non_null(conf_db);

    ret = confdb_init(test_ctx, &test_ctx->confdb, conf_db);
    assert_int_equal(ret, EOK);

    talloc_free(conf_db);

    val[0] = TEST_DOMAIN_NAME;
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/sssd", "domains", val);
    assert_int_equal(ret, EOK);

    val[0] = GLOBAL_FULL_NAME_FORMAT;
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/sssd", "full_name_format", val);
    assert_int_equal(ret, EOK);

    val[0] = GLOBAL_RE_EXPRESSION;
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/sssd", "re_expression", val);
    assert_int_equal(ret, EOK);

    dompath = talloc_asprintf(test_ctx, "config/domain/%s", TEST_DOMAIN_NAME);
    assert_non_null(dompath);

    val[0] = "ldap";
    ret = confdb_add_param(test_ctx->confdb, true,
                           dompath, "id_provider", val);
    assert_int_equal(ret, EOK);

    val[0] = DOMAIN_FULL_NAME_FORMAT;
    ret = confdb_add_param(test_ctx->confdb, true,
                           dompath, "full_name_format", val);
    assert_int_equal(ret, EOK);

    val[0] = DOMAIN_RE_EXPRESSION;
    ret = confdb_add_param(test_ctx->confdb, true,
                           dompath, "re_expression", val);
    assert_int_equal(ret, EOK);

    talloc_free(dompath);

    check_leaks_push(test_ctx);
    *state = test_ctx;
}

void confdb_test_teardown(void **state)
{
    struct name_init_test_ctx *test_ctx;

    test_ctx = talloc_get_type(*state, struct name_init_test_ctx);

    assert_true(check_leaks_pop(test_ctx) == true);
    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
}

void test_sss_names_init(void **state)
{
    struct name_init_test_ctx *test_ctx;
    struct sss_names_ctx *names_ctx;
    int ret;

    test_ctx = talloc_get_type(*state, struct name_init_test_ctx);

    ret = sss_names_init(test_ctx, test_ctx->confdb, NULL, &names_ctx);
    assert_int_equal(ret, EOK);
    assert_non_null(names_ctx);
    assert_string_equal(names_ctx->re_pattern, GLOBAL_RE_EXPRESSION);
    assert_string_equal(names_ctx->fq_fmt, GLOBAL_FULL_NAME_FORMAT);

    talloc_free(names_ctx);

    ret = sss_names_init(test_ctx, test_ctx->confdb, TEST_DOMAIN_NAME,
                         &names_ctx);
    assert_int_equal(ret, EOK);
    assert_non_null(names_ctx);
    assert_string_equal(names_ctx->re_pattern, DOMAIN_RE_EXPRESSION);
    assert_string_equal(names_ctx->fq_fmt, DOMAIN_FULL_NAME_FORMAT);

    talloc_free(names_ctx);
}

void test_well_known_sid_to_name(void **state)
{
    int ret;
    const char *name;
    const char *dom;

    ret = well_known_sid_to_name(NULL, NULL, NULL);
    assert_int_equal(ret, EINVAL);

    ret = well_known_sid_to_name("abc", &dom, &name);
    assert_int_equal(ret, EINVAL);

    ret = well_known_sid_to_name("S-1", &dom, &name);
    assert_int_equal(ret, EINVAL);

    ret = well_known_sid_to_name("S-1-", &dom, &name);
    assert_int_equal(ret, EINVAL);

    ret = well_known_sid_to_name("S-1-0", &dom, &name);
    assert_int_equal(ret, EINVAL);

    ret = well_known_sid_to_name("S-1-0-", &dom, &name);
    assert_int_equal(ret, EINVAL);

    ret = well_known_sid_to_name("S-1-0-0", &dom, &name);
    assert_int_equal(ret, EOK);
    assert_string_equal(dom, "NULL AUTHORITY");
    assert_string_equal(name, "NULL SID");

    ret = well_known_sid_to_name("S-1-0-0-", &dom, &name);
    assert_int_equal(ret, EINVAL);

    ret = well_known_sid_to_name("S-1-5", &dom, &name);
    assert_int_equal(ret, EINVAL);

    ret = well_known_sid_to_name("S-1-5-", &dom, &name);
    assert_int_equal(ret, EINVAL);

    ret = well_known_sid_to_name("S-1-5-6", &dom, &name);
    assert_int_equal(ret, EOK);
    assert_string_equal(dom, "NT AUTHORITY");
    assert_string_equal(name, "SERVICE");

    ret = well_known_sid_to_name("S-1-5-6-", &dom, &name);
    assert_int_equal(ret, EINVAL);

    ret = well_known_sid_to_name("S-1-5-21", &dom, &name);
    assert_int_equal(ret, EINVAL);

    ret = well_known_sid_to_name("S-1-5-21-", &dom, &name);
    assert_int_equal(ret, ENOENT);

    ret = well_known_sid_to_name("S-1-5-21-abc", &dom, &name);
    assert_int_equal(ret, ENOENT);

    ret = well_known_sid_to_name("S-1-5-32", &dom, &name);
    assert_int_equal(ret, EINVAL);

    ret = well_known_sid_to_name("S-1-5-32-", &dom, &name);
    assert_int_equal(ret, EINVAL);

    ret = well_known_sid_to_name("S-1-5-32-551", &dom, &name);
    assert_int_equal(ret, EOK);
    assert_string_equal(dom, "BUILTIN");
    assert_string_equal(name, "Backup Operators");

    ret = well_known_sid_to_name("S-1-5-32-551-", &dom, &name);
    assert_int_equal(ret, EINVAL);

}

void test_name_to_well_known_sid(void **state)
{
    int ret;
    const char *sid;

    ret = name_to_well_known_sid(NULL, NULL, NULL);
    assert_int_equal(ret, EINVAL);

    ret = name_to_well_known_sid("abc", "def", &sid);
    assert_int_equal(ret, ENOENT);

    ret = name_to_well_known_sid("", "def", &sid);
    assert_int_equal(ret, ENOENT);

    ret = name_to_well_known_sid("BUILTIN", "def", &sid);
    assert_int_equal(ret, EINVAL);

    ret = name_to_well_known_sid("NT AUTHORITY", "def", &sid);
    assert_int_equal(ret, EINVAL);

    ret = name_to_well_known_sid("LOCAL AUTHORITY", "LOCAL", &sid);
    assert_int_equal(ret, EOK);
    assert_string_equal(sid, "S-1-2-0");

    ret = name_to_well_known_sid(NULL, "LOCAL", &sid);
    assert_int_equal(ret, EINVAL);

    ret = name_to_well_known_sid("BUILTIN", "Cryptographic Operators", &sid);
    assert_int_equal(ret, EOK);
    assert_string_equal(sid, "S-1-5-32-569");

    ret = name_to_well_known_sid("NT AUTHORITY", "DIALUP", &sid);
    assert_int_equal(ret, EOK);
    assert_string_equal(sid, "S-1-5-1");
}

#define TEST_SANITIZE_INPUT "TestUser@Test.Domain"
#define TEST_SANITIZE_LC_INPUT "testuser@test.domain"

void test_sss_filter_sanitize_for_dom(void **state)
{
    struct dom_list_test_ctx *test_ctx;
    int ret;
    char *sanitized;
    char *lc_sanitized;
    struct sss_domain_info *dom;

    test_ctx = talloc_get_type(*state, struct dom_list_test_ctx);
    dom = test_ctx->dom_list;

    dom->case_sensitive = true;

    ret = sss_filter_sanitize_for_dom(test_ctx, TEST_SANITIZE_INPUT, dom,
                                      &sanitized, &lc_sanitized);
    assert_int_equal(ret, EOK);
    assert_string_equal(sanitized, TEST_SANITIZE_INPUT);
    assert_string_equal(lc_sanitized, TEST_SANITIZE_INPUT);
    talloc_free(sanitized);
    talloc_free(lc_sanitized);

    dom->case_sensitive = false;

    ret = sss_filter_sanitize_for_dom(test_ctx, TEST_SANITIZE_INPUT, dom,
                                      &sanitized, &lc_sanitized);
    assert_int_equal(ret, EOK);
    assert_string_equal(sanitized, TEST_SANITIZE_INPUT);
    assert_string_equal(lc_sanitized, TEST_SANITIZE_LC_INPUT);
    talloc_free(sanitized);
    talloc_free(lc_sanitized);
}

void check_expanded_value(TALLOC_CTX *tmp_ctx,
                          struct sss_nss_homedir_ctx *homedir_ctx,
                          const char *template, const char *exp_val)
{
    char *homedir;

    homedir = expand_homedir_template(tmp_ctx, template, homedir_ctx);
    if (exp_val != NULL) {
        assert_string_equal(homedir, exp_val);
    } else {
        assert_null(homedir);
    }

    talloc_free(homedir);
}

void setup_homedir_ctx(void **state)
{
    struct sss_nss_homedir_ctx *homedir_ctx;

    assert_true(leak_check_setup());

    homedir_ctx= talloc_zero(global_talloc_context,
                             struct sss_nss_homedir_ctx);
    assert_non_null(homedir_ctx);

    homedir_ctx->username = USERNAME;
    homedir_ctx->uid = UID;
    homedir_ctx->original = ORIGINAL_HOME;
    homedir_ctx->domain = DOMAIN;
    homedir_ctx->flatname = FLATNAME;
    homedir_ctx->config_homedir_substr = HOMEDIR_SUBSTR;

    check_leaks_push(homedir_ctx);
    *state = homedir_ctx;
}

void teardown_homedir_ctx(void **state)
{
    struct sss_nss_homedir_ctx *homedir_ctx = talloc_get_type(*state,
                                                 struct sss_nss_homedir_ctx);
    if (homedir_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Type mismatch\n");
        return;
    }

    assert_true(check_leaks_pop(homedir_ctx) == true);
    talloc_free(homedir_ctx);
    assert_true(leak_check_teardown());
}

void test_expand_homedir_template_NULL(void **state)
{
    TALLOC_CTX *tmp_ctx;
    char *homedir;
    struct sss_nss_homedir_ctx *homedir_ctx;

    /* following format strings requires data in homedir_ctx */
    const char *format_strings[] = { "%u", "%U", "%d", "%f", "%F", "%H",
                                     NULL };
    int i;

    tmp_ctx = talloc_new(NULL);
    assert_non_null(tmp_ctx);

    homedir_ctx = talloc_zero(tmp_ctx, struct sss_nss_homedir_ctx);
    assert_non_null(homedir_ctx);

    homedir = expand_homedir_template(tmp_ctx, NULL, NULL);
    assert_null(homedir);

    homedir = expand_homedir_template(tmp_ctx, "template", NULL);
    assert_null(homedir);

    /* missing data in homedir_ctx */
    check_expanded_value(tmp_ctx, homedir_ctx, "%%", "%");
    check_expanded_value(tmp_ctx, homedir_ctx, "%o", "");

    for (i = 0; format_strings[i] != NULL; ++i) {
        check_expanded_value(tmp_ctx, homedir_ctx, format_strings[i], NULL);
    }

    /* flatname requires domain and username */
    homedir_ctx->username = DUMMY;
    check_expanded_value(tmp_ctx, homedir_ctx, "%f", NULL);

    homedir_ctx->username = NULL;
    homedir_ctx->domain = DUMMY;
    check_expanded_value(tmp_ctx, homedir_ctx, "%f", NULL);

    /* test unknown format string */
    check_expanded_value(tmp_ctx, homedir_ctx, "%x", NULL);

    /* test malformed format string */
    check_expanded_value(tmp_ctx, homedir_ctx, "%", NULL);

    talloc_free(tmp_ctx);
}

void test_expand_homedir_template(void **state)
{
    struct sss_nss_homedir_ctx *homedir_ctx = talloc_get_type(*state,
                                                 struct sss_nss_homedir_ctx);
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    assert_non_null(tmp_ctx);

    /* string without template */
    check_expanded_value(tmp_ctx, homedir_ctx, DUMMY, DUMMY);

    check_expanded_value(tmp_ctx, homedir_ctx, "%u", USERNAME);
    check_expanded_value(tmp_ctx, homedir_ctx, DUMMY"%u", DUMMY USERNAME);
    check_expanded_value(tmp_ctx, homedir_ctx, "%u"DUMMY, USERNAME DUMMY);
    check_expanded_value(tmp_ctx, homedir_ctx, DUMMY"%u"DUMMY2,
                                               DUMMY USERNAME DUMMY2);

    check_expanded_value(tmp_ctx, homedir_ctx, "%U", STR(UID));
    check_expanded_value(tmp_ctx, homedir_ctx, DUMMY"%U", DUMMY STR(UID));
    check_expanded_value(tmp_ctx, homedir_ctx, "%U"DUMMY, STR(UID) DUMMY);
    check_expanded_value(tmp_ctx, homedir_ctx, DUMMY"%U"DUMMY2,
                                               DUMMY STR(UID) DUMMY2);

    check_expanded_value(tmp_ctx, homedir_ctx, "%d", DOMAIN);
    check_expanded_value(tmp_ctx, homedir_ctx, DUMMY"%d", DUMMY DOMAIN);
    check_expanded_value(tmp_ctx, homedir_ctx, "%d"DUMMY, DOMAIN DUMMY);
    check_expanded_value(tmp_ctx, homedir_ctx, DUMMY"%d"DUMMY2,
                                               DUMMY DOMAIN DUMMY2);

    check_expanded_value(tmp_ctx, homedir_ctx, "%f", USERNAME"@"DOMAIN);
    check_expanded_value(tmp_ctx, homedir_ctx, DUMMY"%f",
                                               DUMMY USERNAME"@"DOMAIN);
    check_expanded_value(tmp_ctx, homedir_ctx, "%f"DUMMY,
                                               USERNAME"@"DOMAIN DUMMY);
    check_expanded_value(tmp_ctx, homedir_ctx, DUMMY"%f"DUMMY2,
                                               DUMMY USERNAME"@"DOMAIN DUMMY2);

    check_expanded_value(tmp_ctx, homedir_ctx, "%o", ORIGINAL_HOME);
    check_expanded_value(tmp_ctx, homedir_ctx, DUMMY"%o", DUMMY ORIGINAL_HOME);
    check_expanded_value(tmp_ctx, homedir_ctx, "%o"DUMMY, ORIGINAL_HOME DUMMY);
    check_expanded_value(tmp_ctx, homedir_ctx, DUMMY"%o"DUMMY2,
                                               DUMMY ORIGINAL_HOME DUMMY2);

    check_expanded_value(tmp_ctx, homedir_ctx, "%F", FLATNAME);
    check_expanded_value(tmp_ctx, homedir_ctx, DUMMY"%F", DUMMY FLATNAME);
    check_expanded_value(tmp_ctx, homedir_ctx, "%F"DUMMY, FLATNAME DUMMY);
    check_expanded_value(tmp_ctx, homedir_ctx, DUMMY"%F"DUMMY2,
                                               DUMMY FLATNAME DUMMY2);

    check_expanded_value(tmp_ctx, homedir_ctx, "%H", HOMEDIR_SUBSTR);
    check_expanded_value(tmp_ctx, homedir_ctx, DUMMY"%H",
                                               DUMMY HOMEDIR_SUBSTR);
    check_expanded_value(tmp_ctx, homedir_ctx, "%H"DUMMY,
                                               HOMEDIR_SUBSTR DUMMY);
    check_expanded_value(tmp_ctx, homedir_ctx, DUMMY"%H"DUMMY2,
                                               DUMMY HOMEDIR_SUBSTR DUMMY2);

    check_expanded_value(tmp_ctx, homedir_ctx, "%%", "%");
    check_expanded_value(tmp_ctx, homedir_ctx, DUMMY"%%", DUMMY"%");
    check_expanded_value(tmp_ctx, homedir_ctx, "%%"DUMMY, "%"DUMMY);
    check_expanded_value(tmp_ctx, homedir_ctx, DUMMY"%%"DUMMY2,
                                               DUMMY"%"DUMMY2);

    /* test all format strings */
    check_expanded_value(tmp_ctx, homedir_ctx,
                         DUMMY"/%u/%U/%d/%f/%o/%F/%%/%H/"DUMMY2,
                         DUMMY"/"USERNAME"/" STR(UID) "/"DOMAIN"/"
                         USERNAME"@"DOMAIN"/"ORIGINAL_HOME"/"FLATNAME"/%/"
                         HOMEDIR_SUBSTR"/"DUMMY2);
    talloc_free(tmp_ctx);
}

int main(int argc, const char *argv[])
{
    poptContext pc;
    int opt;
    int rv;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
    };

    const UnitTest tests[] = {
        unit_test_setup_teardown(test_find_subdomain_by_sid_null,
                                 setup_dom_list, teardown_dom_list),
        unit_test_setup_teardown(test_find_subdomain_by_sid,
                                 setup_dom_list, teardown_dom_list),
        unit_test_setup_teardown(test_find_subdomain_by_sid_missing_sid,
                                 setup_dom_list, teardown_dom_list),
        unit_test_setup_teardown(test_find_subdomain_by_sid_disabled,
                                 setup_dom_list, teardown_dom_list),
        unit_test_setup_teardown(test_find_subdomain_by_name_null,
                                 setup_dom_list, teardown_dom_list),
        unit_test_setup_teardown(test_find_subdomain_by_name,
                                 setup_dom_list, teardown_dom_list),
        unit_test_setup_teardown(test_find_subdomain_by_name_missing_flat_name,
                                 setup_dom_list, teardown_dom_list),
        unit_test_setup_teardown(test_find_subdomain_by_name_disabled,
                                 setup_dom_list, teardown_dom_list),

        unit_test_setup_teardown(test_sss_names_init,
                                 confdb_test_setup, confdb_test_teardown),

        unit_test(test_well_known_sid_to_name),
        unit_test(test_name_to_well_known_sid),

        unit_test_setup_teardown(test_sss_filter_sanitize_for_dom,
                                 setup_dom_list, teardown_dom_list),

        unit_test(test_expand_homedir_template_NULL),
        unit_test_setup_teardown(test_expand_homedir_template,
                                 setup_homedir_ctx, teardown_homedir_ctx),
        unit_test(test_textual_public_key),
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
    if (rv == 0) {
        test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_SYSDB_FILE);
    }
    return rv;
}
