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

#define _GNU_SOURCE
#include <stdio.h>
#include <popt.h>

#include "tests/cmocka/common_mock.h"
#include "util/sss_nss.h"
#include "p11_child/p11_child.h"
#include "test_utils.h"

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_DB "test_utils_conf.ldb"
#define TEST_DOM_NAME "utils_test.ldb"

#define DOM_COUNT 10
#define DOMNAME_TMPL "name_%zu.dom"
#define FLATNAME_TMPL "name_%zu"
#define SID_TMPL "S-1-5-21-1-2-%zu"

#define MACRO_EXPAND(tok) #tok
#define STR(tok) MACRO_EXPAND(tok)

#define USERNAME "sssduser"
#define FIRST_LETTER "s"
#define UID      1234
#define DOMAIN   "sssddomain"
#define ORIGINAL_HOME "/home/USER"
#define LOWERCASE_HOME "/home/user"
#define FLATNAME "flatname"
#define HOMEDIR_SUBSTR "/mnt/home"

#define DUMMY "dummy"
#define DUMMY2 "dummy2"

struct dom_list_test_ctx {
    size_t dom_count;
    struct sss_domain_info *dom_list;
};

static int setup_dom_list_with_subdomains(void **state)
{
    struct dom_list_test_ctx *test_ctx;
    struct sss_domain_info *dom = NULL;
    struct sss_domain_info *c = NULL;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context, struct dom_list_test_ctx);
    assert_non_null(test_ctx);

    dom = talloc_zero(test_ctx, struct sss_domain_info);
    assert_non_null(dom);

    dom->name = talloc_asprintf(dom, "configured.dom");
    assert_non_null(dom->name);

    dom->realm = talloc_asprintf(dom, "CONFIGURED.DOM");
    assert_non_null(dom->realm);

    dom->flat_name = talloc_asprintf(dom, "CONFIGURED");
    assert_non_null(dom->flat_name);

    dom->domain_id = talloc_asprintf(dom, "S-1-5-21-1-2-1");
    assert_non_null(dom->domain_id);

    DLIST_ADD(test_ctx->dom_list, dom);

    c = talloc_zero(test_ctx, struct sss_domain_info);
    assert_non_null(c);

    c->name = talloc_asprintf(c, "subdom1.dom");
    assert_non_null(c->name);

    c->realm = talloc_asprintf(c, "SUBDOM1.DOM");
    assert_non_null(c->realm);

    c->flat_name = talloc_asprintf(c, "subdom1");
    assert_non_null(c->flat_name);

    c->domain_id = talloc_asprintf(c, "S-1-5-21-1-2-2");
    assert_non_null(c->domain_id);

    c->parent = dom;

    DLIST_ADD_END(test_ctx->dom_list, c, struct sss_domain_info *);

    c = talloc_zero(test_ctx, struct sss_domain_info);
    assert_non_null(c);

    c->name = talloc_asprintf(c, "subdom2.dom");
    assert_non_null(c->name);

    c->realm = talloc_asprintf(c, "SUBDOM2.DOM");
    assert_non_null(c->realm);

    c->flat_name = talloc_asprintf(c, "subdom2");
    assert_non_null(c->flat_name);

    c->domain_id = talloc_asprintf(c, "S-1-5-21-1-2-3");
    assert_non_null(c->domain_id);

    c->parent = dom;

    DLIST_ADD_END(test_ctx->dom_list, c, struct sss_domain_info *);

    c = talloc_zero(test_ctx, struct sss_domain_info);
    assert_non_null(c);

    c->name = talloc_asprintf(c, "subdom3.dom");
    assert_non_null(c->name);

    c->realm = talloc_asprintf(c, "SUBDOM3.DOM");
    assert_non_null(c->realm);

    c->flat_name = talloc_asprintf(c, "subdom3");
    assert_non_null(c->flat_name);

    c->domain_id = talloc_asprintf(c, "S-1-5-21-1-2-4");
    assert_non_null(c->domain_id);

    c->parent = dom;

    DLIST_ADD_END(test_ctx->dom_list, c, struct sss_domain_info *);

    check_leaks_push(test_ctx);
    *state = test_ctx;
    return 0;
}

static int setup_dom_list(void **state)
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
    return 0;
}

static int teardown_dom_list(void **state)
{
    struct dom_list_test_ctx *test_ctx = talloc_get_type(*state,
                                                      struct dom_list_test_ctx);
    if (test_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Type mismatch\n");
        return 1;
    }

    assert_true(check_leaks_pop(test_ctx) == true);
    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
    return 0;
}

void test_find_domain_by_name_null(void **state)
{
    struct dom_list_test_ctx *test_ctx = talloc_get_type(*state,
                                                      struct dom_list_test_ctx);
    struct sss_domain_info *dom;

    dom = find_domain_by_name(NULL, NULL, false);
    assert_null(dom);

    dom = find_domain_by_name(test_ctx->dom_list, NULL, false);
    assert_null(dom);

    dom = find_domain_by_name(NULL, "test", false);
    assert_null(dom);
}

void test_find_domain_by_name(void **state)
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

        dom = find_domain_by_name(test_ctx->dom_list, name, false);
        assert_non_null(dom);
        assert_string_equal(name, dom->name);
        assert_string_equal(flat_name, dom->flat_name);
        assert_string_equal(sid, dom->domain_id);

        dom = find_domain_by_name(test_ctx->dom_list, name, true);
        assert_non_null(dom);
        assert_string_equal(name, dom->name);
        assert_string_equal(flat_name, dom->flat_name);
        assert_string_equal(sid, dom->domain_id);

        dom = find_domain_by_name(test_ctx->dom_list, flat_name, true);
        assert_non_null(dom);
        assert_string_equal(name, dom->name);
        assert_string_equal(flat_name, dom->flat_name);
        assert_string_equal(sid, dom->domain_id);

        dom = find_domain_by_name(test_ctx->dom_list, flat_name, false);
        assert_null(dom);

        talloc_free(name);
        talloc_free(flat_name);
        talloc_free(sid);
    }
}

void test_find_domain_by_name_missing_flat_name(void **state)
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

        dom = find_domain_by_name(test_ctx->dom_list, name, true);
        assert_non_null(dom);
        assert_string_equal(name, dom->name);
        if (c == mis - 1) {
            assert_null(dom->flat_name);
        } else {
            assert_string_equal(flat_name, dom->flat_name);
        }
        assert_string_equal(sid, dom->domain_id);

        dom = find_domain_by_name(test_ctx->dom_list, name, false);
        assert_non_null(dom);
        assert_string_equal(name, dom->name);
        if (c == mis - 1) {
            assert_null(dom->flat_name);
        } else {
            assert_string_equal(flat_name, dom->flat_name);
        }
        assert_string_equal(sid, dom->domain_id);

        dom = find_domain_by_name(test_ctx->dom_list, flat_name, true);
        if (c == mis - 1) {
            assert_null(dom);
        } else {
            assert_non_null(dom);
            assert_string_equal(name, dom->name);
            assert_string_equal(flat_name, dom->flat_name);
            assert_string_equal(sid, dom->domain_id);
        }

        dom = find_domain_by_name(test_ctx->dom_list, flat_name, false);
        assert_null(dom);

        talloc_free(name);
        talloc_free(flat_name);
        talloc_free(sid);
    }
}

void test_find_domain_by_name_disabled(void **state)
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
    sss_domain_set_state(dom, DOM_DISABLED);

    for (c = 0; c < test_ctx->dom_count; c++) {
        name = talloc_asprintf(global_talloc_context, DOMNAME_TMPL, c);
        assert_non_null(name);

        flat_name = talloc_asprintf(global_talloc_context, FLATNAME_TMPL, c);
        assert_non_null(flat_name);

        sid = talloc_asprintf(global_talloc_context, SID_TMPL, c);
        assert_non_null(sid);

        dom = find_domain_by_name(test_ctx->dom_list, name, true);
        if (c == mis - 1) {
            assert_null(dom);
        } else {
            assert_non_null(dom);
            assert_string_equal(name, dom->name);
            assert_string_equal(flat_name, dom->flat_name);
            assert_string_equal(sid, dom->domain_id);
        }

        dom = find_domain_by_name(test_ctx->dom_list, name, false);
        if (c == mis - 1) {
            assert_null(dom);
        } else {
            assert_non_null(dom);
            assert_string_equal(name, dom->name);
            assert_string_equal(flat_name, dom->flat_name);
            assert_string_equal(sid, dom->domain_id);
        }

        dom = find_domain_by_name(test_ctx->dom_list, flat_name, true);
        if (c == mis - 1) {
            assert_null(dom);
        } else {
            assert_non_null(dom);
            assert_string_equal(name, dom->name);
            assert_string_equal(flat_name, dom->flat_name);
            assert_string_equal(sid, dom->domain_id);
        }

        dom = find_domain_by_name(test_ctx->dom_list, flat_name, false);
        assert_null(dom);

        talloc_free(name);
        talloc_free(flat_name);
        talloc_free(sid);
    }
}

void test_find_domain_by_name_ex_disabled(void **state)
{
    struct dom_list_test_ctx *test_ctx = talloc_get_type(*state,
                                                      struct dom_list_test_ctx);
    struct sss_domain_info *dom;
    struct sss_domain_info *disabled_dom;
    size_t c;
    size_t mis;

    mis = test_ctx->dom_count/2;
    assert_true((mis >= 1 && mis < test_ctx->dom_count));

    dom = test_ctx->dom_list;
    for (c = 0; c < mis; c++) {
        assert_non_null(dom);
        dom = dom->next;
    }
    assert_non_null(dom);
    sss_domain_set_state(dom, DOM_DISABLED);
    disabled_dom = dom;

    dom = find_domain_by_name(test_ctx->dom_list, disabled_dom->name, true);
    assert_null(dom);

    dom = find_domain_by_name_ex(test_ctx->dom_list, disabled_dom->name, true,
                                 SSS_GND_DESCEND);
    assert_null(dom);

    dom = find_domain_by_name_ex(test_ctx->dom_list, disabled_dom->name, true,
                                 SSS_GND_DESCEND | SSS_GND_INCLUDE_DISABLED);
    assert_non_null(dom);
    assert_ptr_equal(disabled_dom, dom);

    dom = find_domain_by_name_ex(test_ctx->dom_list, disabled_dom->name, true,
                                 SSS_GND_ALL_DOMAINS);
    assert_non_null(dom);
    assert_ptr_equal(disabled_dom, dom);
}

void test_find_domain_by_object_name_ex(void **state)
{
    struct dom_list_test_ctx *test_ctx = talloc_get_type(*state,
                                                      struct dom_list_test_ctx);
    struct sss_domain_info *dom;
    struct sss_domain_info *disabled_dom;
    size_t c;
    size_t mis;
    char *obj_name;

    mis = test_ctx->dom_count/2;
    assert_true((mis >= 1 && mis < test_ctx->dom_count));

    dom = test_ctx->dom_list;
    for (c = 0; c < mis; c++) {
        assert_non_null(dom);
        dom = dom->next;
    }
    assert_non_null(dom);
    sss_domain_set_state(dom, DOM_DISABLED);
    disabled_dom = dom;

    obj_name = talloc_asprintf(global_talloc_context, "myname@%s",
                               disabled_dom->name);
    assert_non_null(obj_name);


    dom = find_domain_by_object_name(test_ctx->dom_list, obj_name);
    assert_null(dom);

    dom = find_domain_by_object_name_ex(test_ctx->dom_list, obj_name, true,
                                        SSS_GND_DESCEND);
    assert_null(dom);

    dom = find_domain_by_object_name_ex(test_ctx->dom_list, obj_name, true,
                                    SSS_GND_DESCEND | SSS_GND_INCLUDE_DISABLED);
    assert_non_null(dom);
    assert_ptr_equal(disabled_dom, dom);

    dom = find_domain_by_object_name_ex(test_ctx->dom_list, obj_name, true,
                                        SSS_GND_ALL_DOMAINS);
    assert_non_null(dom);
    assert_ptr_equal(disabled_dom, dom);

    talloc_free(obj_name);
}

void test_find_domain_by_sid_null(void **state)
{
    struct dom_list_test_ctx *test_ctx = talloc_get_type(*state,
                                                      struct dom_list_test_ctx);
    struct sss_domain_info *dom;

    dom = find_domain_by_sid(NULL, NULL);
    assert_null(dom);

    dom = find_domain_by_sid(test_ctx->dom_list, NULL);
    assert_null(dom);

    dom = find_domain_by_sid(NULL, "S-1-5-21-1-2-3");
    assert_null(dom);
}

void test_find_domain_by_sid(void **state)
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

        dom = find_domain_by_sid(test_ctx->dom_list, sid);
        assert_non_null(dom);
        assert_string_equal(name, dom->name);
        assert_string_equal(flat_name, dom->flat_name);
        assert_string_equal(sid, dom->domain_id);

        talloc_free(name);
        talloc_free(flat_name);
        talloc_free(sid);
    }
}

void test_find_domain_by_sid_missing_sid(void **state)
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

        dom = find_domain_by_sid(test_ctx->dom_list, sid);
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

void test_find_domain_by_sid_disabled(void **state)
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
    sss_domain_set_state(dom, DOM_DISABLED);

    for (c = 0; c < test_ctx->dom_count; c++) {
        name = talloc_asprintf(global_talloc_context, DOMNAME_TMPL, c);
        assert_non_null(name);

        flat_name = talloc_asprintf(global_talloc_context, FLATNAME_TMPL, c);
        assert_non_null(flat_name);

        sid = talloc_asprintf(global_talloc_context, SID_TMPL, c);
        assert_non_null(sid);

        dom = find_domain_by_sid(test_ctx->dom_list, sid);
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

/*
 * dom1 -> sub1a
 *  |
 * dom2 -> sub2a -> sub2b
 *
 */
static int setup_dom_tree(void **state)
{
    struct dom_list_test_ctx *test_ctx;
    struct sss_domain_info *head = NULL;
    struct sss_domain_info *dom = NULL;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context, struct dom_list_test_ctx);
    assert_non_null(test_ctx);

    dom = named_domain(test_ctx, "dom1", NULL);
    assert_non_null(dom);
    head = dom;

    dom = named_domain(test_ctx, "sub1a", head);
    assert_non_null(dom);
    head->subdomains = dom;

    dom = named_domain(test_ctx, "dom2", NULL);
    assert_non_null(dom);
    head->next = dom;

    dom = named_domain(test_ctx, "sub2a", head->next);
    assert_non_null(dom);
    head->next->subdomains = dom;

    dom = named_domain(test_ctx, "sub2b", head->next);
    assert_non_null(dom);
    head->next->subdomains->next = dom;

    test_ctx->dom_count = 2;
    test_ctx->dom_list = head;

    check_leaks_push(test_ctx);
    *state = test_ctx;
    return 0;
}

static int teardown_dom_tree(void **state)
{
    struct dom_list_test_ctx *test_ctx = talloc_get_type(*state,
                                                      struct dom_list_test_ctx);
    if (test_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Type mismatch\n");
        return 1;
    }

    assert_true(check_leaks_pop(test_ctx));
    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
    return 0;
}

static void test_get_next_domain(void **state)
{
    struct dom_list_test_ctx *test_ctx = talloc_get_type(*state,
                                                      struct dom_list_test_ctx);
    struct sss_domain_info *dom = NULL;

    dom = get_next_domain(test_ctx->dom_list, 0);
    assert_non_null(dom);
    assert_string_equal(dom->name, "dom2");

    dom = get_next_domain(dom, 0);
    assert_null(dom);
}

static void test_get_next_domain_descend(void **state)
{
    struct dom_list_test_ctx *test_ctx = talloc_get_type(*state,
                                                      struct dom_list_test_ctx);
    struct sss_domain_info *dom = NULL;

    dom = get_next_domain(test_ctx->dom_list, SSS_GND_DESCEND);
    assert_non_null(dom);
    assert_string_equal(dom->name, "sub1a");

    dom = get_next_domain(dom, SSS_GND_DESCEND);
    assert_non_null(dom);
    assert_string_equal(dom->name, "dom2");

    dom = get_next_domain(dom, SSS_GND_DESCEND);
    assert_non_null(dom);
    assert_string_equal(dom->name, "sub2a");

    dom = get_next_domain(dom, SSS_GND_DESCEND);
    assert_non_null(dom);
    assert_string_equal(dom->name, "sub2b");

    dom = get_next_domain(dom, 0);
    assert_null(dom);
}

static void test_get_next_domain_disabled(void **state)
{
    struct dom_list_test_ctx *test_ctx = talloc_get_type(*state,
                                                      struct dom_list_test_ctx);
    struct sss_domain_info *dom = NULL;

    for (dom = test_ctx->dom_list; dom;
            dom = get_next_domain(dom, SSS_GND_DESCEND)) {
        sss_domain_set_state(dom, DOM_DISABLED);
    }

    dom = get_next_domain(test_ctx->dom_list, SSS_GND_DESCEND);
    assert_null(dom);
}

static void test_get_next_domain_flags(void **state)
{
    struct dom_list_test_ctx *test_ctx = talloc_get_type(*state,
                                                      struct dom_list_test_ctx);
    struct sss_domain_info *dom = NULL;
    uint32_t gnd_flags;

    /* No flags; all doms enabled */
    gnd_flags = 0;

    dom = get_next_domain(test_ctx->dom_list, gnd_flags);
    assert_non_null(dom);
    assert_string_equal(dom->name, "dom2");

    dom = get_next_domain(dom, gnd_flags);
    assert_null(dom);

    /* Descend flag only; all doms enabled */
    gnd_flags = SSS_GND_DESCEND;

    dom = get_next_domain(test_ctx->dom_list, gnd_flags);
    assert_non_null(dom);
    assert_string_equal(dom->name, "sub1a");

    dom = get_next_domain(dom, gnd_flags);
    assert_non_null(dom);
    assert_string_equal(dom->name, "dom2");

    dom = get_next_domain(dom, gnd_flags);
    assert_non_null(dom);
    assert_string_equal(dom->name, "sub2a");

    dom = get_next_domain(dom, gnd_flags);
    assert_non_null(dom);
    assert_string_equal(dom->name, "sub2b");

    dom = get_next_domain(dom, gnd_flags);
    assert_null(dom);

    /* Incl. disabled flag only; all doms enabled */
    gnd_flags = SSS_GND_INCLUDE_DISABLED;

    dom = get_next_domain(test_ctx->dom_list, gnd_flags);
    assert_non_null(dom);
    assert_string_equal(dom->name, "dom2");

    dom = get_next_domain(dom, gnd_flags);
    assert_null(dom);

    /* Descend and include disabled; all doms enabled */
    gnd_flags = SSS_GND_DESCEND | SSS_GND_INCLUDE_DISABLED;

    dom = get_next_domain(test_ctx->dom_list, gnd_flags);
    assert_non_null(dom);
    assert_string_equal(dom->name, "sub1a");

    dom = get_next_domain(dom, gnd_flags);
    assert_non_null(dom);
    assert_string_equal(dom->name, "dom2");

    dom = get_next_domain(dom, gnd_flags);
    assert_non_null(dom);
    assert_string_equal(dom->name, "sub2a");

    dom = get_next_domain(dom, gnd_flags);
    assert_non_null(dom);
    assert_string_equal(dom->name, "sub2b");

    dom = get_next_domain(dom, gnd_flags);
    assert_null(dom);

    /* Now disable dom2 and sub2a */
    dom = find_domain_by_name(test_ctx->dom_list, "dom2", false);
    assert_non_null(dom);
    sss_domain_set_state(dom, DOM_DISABLED);

    dom = find_domain_by_name(test_ctx->dom_list, "sub2a", false);
    assert_non_null(dom);
    sss_domain_set_state(dom, DOM_DISABLED);

    /* No flags; dom2 and sub2a disabled */
    gnd_flags = 0;

    dom = get_next_domain(test_ctx->dom_list, gnd_flags);
    assert_null(dom);

    /* Descend flag only; dom2 and sub2a disabled */
    gnd_flags = SSS_GND_DESCEND;

    dom = get_next_domain(test_ctx->dom_list, gnd_flags);
    assert_non_null(dom);
    assert_string_equal(dom->name, "sub1a");

    dom = get_next_domain(dom, gnd_flags);
    assert_non_null(dom);
    assert_string_equal(dom->name, "sub2b");

    dom = get_next_domain(dom, gnd_flags);
    assert_null(dom);

    /* Incl. disabled flag only; dom2 and sub2a disabled */
    gnd_flags = SSS_GND_INCLUDE_DISABLED;

    dom = get_next_domain(test_ctx->dom_list, gnd_flags);
    assert_non_null(dom);
    assert_string_equal(dom->name, "dom2");

    dom = get_next_domain(dom, gnd_flags);
    assert_null(dom);

    /* Descend and include disabled; dom2 and sub2a disabled */
    gnd_flags = SSS_GND_DESCEND | SSS_GND_INCLUDE_DISABLED;

    dom = get_next_domain(test_ctx->dom_list, gnd_flags);
    assert_non_null(dom);
    assert_string_equal(dom->name, "sub1a");

    dom = get_next_domain(dom, gnd_flags);
    assert_non_null(dom);
    assert_string_equal(dom->name, "dom2");

    dom = get_next_domain(dom, gnd_flags);
    assert_non_null(dom);
    assert_string_equal(dom->name, "sub2a");

    dom = get_next_domain(dom, gnd_flags);
    assert_non_null(dom);
    assert_string_equal(dom->name, "sub2b");

    dom = get_next_domain(dom, gnd_flags);
    assert_null(dom);

    /* Descend only to subdomains */
    gnd_flags = SSS_GND_SUBDOMAINS | SSS_GND_INCLUDE_DISABLED;

    dom = get_next_domain(test_ctx->dom_list, gnd_flags);
    assert_non_null(dom);
    assert_string_equal(dom->name, "sub1a");

    dom = get_next_domain(dom, gnd_flags);
    assert_null(dom);

    dom = find_domain_by_name_ex(test_ctx->dom_list, "dom2", true,
                                 SSS_GND_ALL_DOMAINS);
    assert_non_null(dom);
    assert_string_equal(dom->name, "dom2");

    dom = get_next_domain(dom, gnd_flags);
    assert_non_null(dom);
    assert_string_equal(dom->name, "sub2a");

    dom = get_next_domain(dom, gnd_flags);
    assert_non_null(dom);
    assert_string_equal(dom->name, "sub2b");

    dom = get_next_domain(dom, gnd_flags);
    assert_null(dom);

    /* Expect NULL if the domain has no sub-domains */
    test_ctx->dom_list->subdomains = NULL;
    dom = get_next_domain(test_ctx->dom_list, gnd_flags);
    assert_null(dom);
}

struct name_init_test_ctx {
    struct confdb_ctx *confdb;
};

#define GLOBAL_FULL_NAME_FORMAT "%1$s@%2$s"
#define TEST_DOMAIN_NAME_LDAP "test.dom"
#define TEST_DOMAIN_NAME_IPA "test.ipa"
#define TEST_DOMAIN_NAMES TEST_DOMAIN_NAME_LDAP "," TEST_DOMAIN_NAME_IPA
#define DOMAIN_FULL_NAME_FORMAT "%3$s\\%1$s"
#define DOMAIN_RE_EXPRESSION "(((?P<name>[^@]+)@(?P<domain>.+$))|" \
                             "(^(?P<name>[^@\\\\]+)$))"

static int confdb_test_setup(void **state)
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

    val[0] = TEST_DOMAIN_NAMES;
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/sssd", "domains", val);
    assert_int_equal(ret, EOK);

    val[0] = GLOBAL_FULL_NAME_FORMAT;
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/sssd", "full_name_format", val);
    assert_int_equal(ret, EOK);

    val[0] = SSS_DEFAULT_RE;
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/sssd", "re_expression", val);
    assert_int_equal(ret, EOK);

    dompath = talloc_asprintf(test_ctx, "config/domain/%s", TEST_DOMAIN_NAME_LDAP);
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

    dompath = talloc_asprintf(test_ctx, "config/domain/%s", TEST_DOMAIN_NAME_IPA);
    assert_non_null(dompath);

    val[0] = "ipa";
    ret = confdb_add_param(test_ctx->confdb, true,
                           dompath, "id_provider", val);
    assert_int_equal(ret, EOK);

    val[0] = DOMAIN_FULL_NAME_FORMAT;
    ret = confdb_add_param(test_ctx->confdb, true,
                           dompath, "full_name_format", val);
    assert_int_equal(ret, EOK);

    val[0] = SSS_IPA_AD_DEFAULT_RE;
    ret = confdb_add_param(test_ctx->confdb, true,
                           dompath, "re_expression", val);
    assert_int_equal(ret, EOK);

    talloc_free(dompath);

    check_leaks_push(test_ctx);
    *state = test_ctx;
    return 0;
}

static int confdb_test_teardown(void **state)
{
    struct name_init_test_ctx *test_ctx;

    test_ctx = talloc_get_type(*state, struct name_init_test_ctx);

    assert_true(check_leaks_pop(test_ctx) == true);
    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
    return 0;
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
    assert_string_equal(names_ctx->re_pattern, SSS_DEFAULT_RE);
    assert_string_equal(names_ctx->fq_fmt, GLOBAL_FULL_NAME_FORMAT);

    talloc_free(names_ctx);

    ret = sss_names_init(test_ctx, test_ctx->confdb, TEST_DOMAIN_NAME_LDAP,
                         &names_ctx);
    assert_int_equal(ret, EOK);
    assert_non_null(names_ctx);
    assert_string_equal(names_ctx->re_pattern, DOMAIN_RE_EXPRESSION);
    assert_string_equal(names_ctx->fq_fmt, DOMAIN_FULL_NAME_FORMAT);

    talloc_free(names_ctx);
}

void test_sss_names_ipa_ad_regexp(void **state)
{
    struct name_init_test_ctx *test_ctx;
    struct sss_names_ctx *names_ctx;
    char *name;
    char *domain;
    int ret;

    test_ctx = talloc_get_type(*state, struct name_init_test_ctx);

    ret = sss_names_init(test_ctx, test_ctx->confdb, TEST_DOMAIN_NAME_IPA,
                         &names_ctx);
    assert_int_equal(ret, EOK);
    assert_non_null(names_ctx);
    assert_non_null(names_ctx->re_pattern);

    ret = sss_parse_name(names_ctx, names_ctx, "user@domain", &domain, &name);
    assert_int_equal(ret, EOK);
    assert_string_equal(name, "user");
    assert_string_equal(domain, "domain");
    talloc_free(name);
    talloc_free(domain);

    ret = sss_parse_name(names_ctx, names_ctx, "mail@group@domain", &domain, &name);
    assert_int_equal(ret, EOK);
    assert_string_equal(name, "mail@group");
    assert_string_equal(domain, "domain");
    talloc_free(name);
    talloc_free(domain);

    ret = sss_parse_name(names_ctx, names_ctx, "domain\\user", &domain, &name);
    assert_int_equal(ret, EOK);
    assert_string_equal(name, "user");
    assert_string_equal(domain, "domain");
    talloc_free(name);
    talloc_free(domain);

    ret = sss_parse_name(names_ctx, names_ctx, "user", &domain, &name);
    assert_int_equal(ret, EOK);
    assert_string_equal(name, "user");
    assert_null(domain);
    talloc_free(name);

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

    ret = well_known_sid_to_name("S-1-3", &dom, &name);
    assert_int_equal(ret, EINVAL);

    ret = well_known_sid_to_name("S-1-3-", &dom, &name);
    assert_int_equal(ret, EINVAL);

    ret = well_known_sid_to_name("S-1-3-4", &dom, &name);
    assert_int_equal(ret, EOK);
    assert_string_equal(dom, "CREATOR AUTHORITY");
    assert_string_equal(name, "OWNER RIGHTS");

    ret = well_known_sid_to_name("S-1-16", &dom, &name);
    assert_int_equal(ret, EINVAL);

    ret = well_known_sid_to_name("S-1-16-", &dom, &name);
    assert_int_equal(ret, EINVAL);

    ret = well_known_sid_to_name("S-1-16-8192", &dom, &name);
    assert_int_equal(ret, EOK);
    assert_string_equal(dom, "MANDATORY LABEL AUTHORITY");
    assert_string_equal(name, "MEDIUM");

    ret = well_known_sid_to_name("S-1-18", &dom, &name);
    assert_int_equal(ret, EINVAL);

    ret = well_known_sid_to_name("S-1-18-", &dom, &name);
    assert_int_equal(ret, EINVAL);

    ret = well_known_sid_to_name("S-1-18-1", &dom, &name);
    assert_int_equal(ret, EOK);
    assert_string_equal(dom, "AUTHENTICATION AUTHORITY");
    assert_string_equal(name, "AUTHENTICATION ASSERTION");

    ret = well_known_sid_to_name("S-1-5", &dom, &name);
    assert_int_equal(ret, EINVAL);

    ret = well_known_sid_to_name("S-1-5-", &dom, &name);
    assert_int_equal(ret, EINVAL);

    ret = well_known_sid_to_name("S-1-5-5", &dom, &name);
    assert_int_equal(ret, EINVAL);

    ret = well_known_sid_to_name("S-1-5-5-", &dom, &name);
    assert_int_equal(ret, EINVAL);

    ret = well_known_sid_to_name("S-1-5-5-7", &dom, &name);
    assert_int_equal(ret, EINVAL);

    ret = well_known_sid_to_name("S-1-5-5-7-", &dom, &name);
    assert_int_equal(ret, EINVAL);

    ret = well_known_sid_to_name("S-1-5-5-7-8-", &dom, &name);
    assert_int_equal(ret, EINVAL);

    ret = well_known_sid_to_name("S-1-5-5-7-8", &dom, &name);
    assert_int_equal(ret, EOK);
    assert_string_equal(dom, "NT AUTHORITY");
    assert_string_equal(name, "LOGON ID");

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

    ret = well_known_sid_to_name("S-1-5-64", &dom, &name);
    assert_int_equal(ret, EINVAL);

    ret = well_known_sid_to_name("S-1-5-64-", &dom, &name);
    assert_int_equal(ret, EINVAL);

    ret = well_known_sid_to_name("S-1-5-64-10", &dom, &name);
    assert_int_equal(ret, EOK);
    assert_string_equal(dom, "NT AUTHORITY");
    assert_string_equal(name, "NTLM AUTHENTICATION");

    ret = well_known_sid_to_name("S-1-5-64-10-", &dom, &name);
    assert_int_equal(ret, EINVAL);

    ret = well_known_sid_to_name("S-1-5-65", &dom, &name);
    assert_int_equal(ret, EINVAL);

    ret = well_known_sid_to_name("S-1-5-65-", &dom, &name);
    assert_int_equal(ret, EINVAL);

    ret = well_known_sid_to_name("S-1-5-65-1", &dom, &name);
    assert_int_equal(ret, EOK);
    assert_string_equal(dom, "NT AUTHORITY");
    assert_string_equal(name, "THIS ORGANIZATION CERTIFICATE");

    ret = well_known_sid_to_name("S-1-5-65-1-", &dom, &name);
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

    ret = name_to_well_known_sid("NT AUTHORITY", "NTLM AUTHENTICATION", &sid);
    assert_int_equal(ret, EOK);
    assert_string_equal(sid, "S-1-5-64-10");

    ret = name_to_well_known_sid("NT AUTHORITY", "THIS ORGANIZATION CERTIFICATE", &sid);
    assert_int_equal(ret, EOK);
    assert_string_equal(sid, "S-1-5-65-1");

    ret = name_to_well_known_sid("NT AUTHORITY", "LOGON ID", &sid);
    assert_int_equal(ret, EOK);
    assert_string_equal(sid, "S-1-5-5-0-0");

    ret = name_to_well_known_sid("MANDATORY LABEL AUTHORITY", "MEDIUM", &sid);
    assert_int_equal(ret, EOK);
    assert_string_equal(sid, "S-1-16-8192");

    ret = name_to_well_known_sid("AUTHENTICATION AUTHORITY", "KEY_TRUST_IDENTITY", &sid);
    assert_int_equal(ret, EOK);
    assert_string_equal(sid, "S-1-18-4");
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

    homedir = expand_homedir_template(tmp_ctx, template, false, homedir_ctx);
    if (exp_val != NULL) {
        assert_string_equal(homedir, exp_val);
    } else {
        assert_null(homedir);
    }

    talloc_free(homedir);
}

static int setup_homedir_ctx(void **state)
{
    struct sss_nss_homedir_ctx *homedir_ctx;

    assert_true(leak_check_setup());

    homedir_ctx= talloc_zero(global_talloc_context,
                             struct sss_nss_homedir_ctx);
    assert_non_null(homedir_ctx);

    homedir_ctx->username = sss_create_internal_fqname(homedir_ctx,
                                                       USERNAME, DOMAIN);
    if (homedir_ctx->username == NULL) {
        talloc_free(homedir_ctx);
        return 1;
    }

    homedir_ctx->uid = UID;
    homedir_ctx->original = ORIGINAL_HOME;
    homedir_ctx->domain = DOMAIN;
    homedir_ctx->flatname = FLATNAME;
    homedir_ctx->config_homedir_substr = HOMEDIR_SUBSTR;

    check_leaks_push(homedir_ctx);
    *state = homedir_ctx;
    return 0;
}

static int teardown_homedir_ctx(void **state)
{
    struct sss_nss_homedir_ctx *homedir_ctx = talloc_get_type(*state,
                                                 struct sss_nss_homedir_ctx);
    if (homedir_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Type mismatch\n");
        return 1;
    }

    assert_true(check_leaks_pop(homedir_ctx) == true);
    talloc_free(homedir_ctx);
    assert_true(leak_check_teardown());
    return 0;
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

    homedir = expand_homedir_template(tmp_ctx, NULL, false, NULL);
    assert_null(homedir);

    homedir = expand_homedir_template(tmp_ctx, "template", false, NULL);
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

    check_expanded_value(tmp_ctx, homedir_ctx, "%h", LOWERCASE_HOME);
    check_expanded_value(tmp_ctx, homedir_ctx, DUMMY"%h", DUMMY LOWERCASE_HOME);
    check_expanded_value(tmp_ctx, homedir_ctx, "%h"DUMMY, LOWERCASE_HOME DUMMY);
    check_expanded_value(tmp_ctx, homedir_ctx, DUMMY"%h"DUMMY2,
                                               DUMMY LOWERCASE_HOME DUMMY2);

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

    check_expanded_value(tmp_ctx, homedir_ctx, "%l", FIRST_LETTER);
    check_expanded_value(tmp_ctx, homedir_ctx, DUMMY"%l", DUMMY FIRST_LETTER);
    check_expanded_value(tmp_ctx, homedir_ctx, "%l"DUMMY, FIRST_LETTER DUMMY);
    check_expanded_value(tmp_ctx, homedir_ctx, DUMMY"%l"DUMMY2,
                                               DUMMY FIRST_LETTER DUMMY2);

    /* test all format strings */
    check_expanded_value(tmp_ctx, homedir_ctx,
                         DUMMY"/%u/%U/%d/%f/%o/%F/%%/%H/%l/"DUMMY2,
                         DUMMY"/"USERNAME"/" STR(UID) "/"DOMAIN"/"
                         USERNAME"@"DOMAIN"/"ORIGINAL_HOME"/"FLATNAME"/%/"
                         HOMEDIR_SUBSTR"/"FIRST_LETTER"/"DUMMY2);
    talloc_free(tmp_ctx);
}

static int setup_leak_tests(void **state)
{
    assert_true(leak_check_setup());

    return 0;
}

static int teardown_leak_tests(void **state)
{
    assert_true(leak_check_teardown());
    return 0;
}

void test_add_strings_lists(void **state)
{
    const char *l1[] = {"a", "b", "c", NULL};
    const char *l2[] = {"1", "2", "3", NULL};
    char **res;
    int ret;
    size_t c;
    size_t d;

    ret = add_strings_lists(global_talloc_context, NULL, NULL, true, &res);
    assert_int_equal(ret, EOK);
    assert_non_null(res);
    assert_null(res[0]);
    talloc_free(res);

    ret = add_strings_lists(global_talloc_context, NULL, NULL, false, &res);
    assert_int_equal(ret, EOK);
    assert_non_null(res);
    assert_null(res[0]);
    talloc_free(res);

    ret = add_strings_lists(global_talloc_context, l1, NULL, false, &res);
    assert_int_equal(ret, EOK);
    assert_non_null(res);
    for (c = 0; l1[c] != NULL; c++) {
        /* 'copy_strings' is 'false', pointers must be equal */
        assert_int_equal(memcmp(&l1[c], &res[c], sizeof(char *)), 0);
    }
    assert_null(res[c]);
    talloc_free(res);

    ret = add_strings_lists(global_talloc_context, l1, NULL, true, &res);
    assert_int_equal(ret, EOK);
    assert_non_null(res);
    for (c = 0; l1[c] != NULL; c++) {
        /* 'copy_strings' is 'true', pointers must be different, but strings
         * must be equal */
        assert_int_not_equal(memcmp(&l1[c], &res[c], sizeof(char *)), 0);
        assert_string_equal(l1[c], res[c]);
    }
    assert_null(res[c]);
    talloc_free(res);

    ret = add_strings_lists(global_talloc_context, NULL, l1, false, &res);
    assert_int_equal(ret, EOK);
    assert_non_null(res);
    for (c = 0; l1[c] != NULL; c++) {
        /* 'copy_strings' is 'false', pointers must be equal */
        assert_int_equal(memcmp(&l1[c], &res[c], sizeof(char *)), 0);
    }
    assert_null(res[c]);
    talloc_free(res);

    ret = add_strings_lists(global_talloc_context, NULL, l1, true, &res);
    assert_int_equal(ret, EOK);
    assert_non_null(res);
    for (c = 0; l1[c] != NULL; c++) {
        /* 'copy_strings' is 'true', pointers must be different, but strings
         * must be equal */
        assert_int_not_equal(memcmp(&l1[c], &res[c], sizeof(char *)), 0);
        assert_string_equal(l1[c], res[c]);
    }
    assert_null(res[c]);
    talloc_free(res);

    ret = add_strings_lists(global_talloc_context, l1, l2, false, &res);
    assert_int_equal(ret, EOK);
    assert_non_null(res);
    for (c = 0; l1[c] != NULL; c++) {
        /* 'copy_strings' is 'false', pointers must be equal */
        assert_int_equal(memcmp(&l1[c], &res[c], sizeof(char *)), 0);
    }
    for (d = 0; l2[d] != NULL; d++) {
        assert_int_equal(memcmp(&l2[d], &res[c+d], sizeof(char *)), 0);
    }
    assert_null(res[c+d]);
    talloc_free(res);

    ret = add_strings_lists(global_talloc_context, l1, l2, true, &res);
    assert_int_equal(ret, EOK);
    assert_non_null(res);
    for (c = 0; l1[c] != NULL; c++) {
        /* 'copy_strings' is 'true', pointers must be different, but strings
         * must be equal */
        assert_int_not_equal(memcmp(&l1[c], &res[c], sizeof(char *)), 0);
        assert_string_equal(l1[c], res[c]);
    }
    for (d = 0; l2[d] != NULL; d++) {
        assert_int_not_equal(memcmp(&l2[d], &res[c+d], sizeof(char *)), 0);
        assert_string_equal(l2[d], res[c+d]);
    }
    assert_null(res[c+d]);
    talloc_free(res);
}

void test_sss_write_krb5_conf_snippet(void **state)
{
    int ret;
    char buf[PATH_MAX];
    char *cwd;
    char *path;
    char *file;
    char *file_krb5_libdefaults;

    ret = sss_write_krb5_conf_snippet(NULL, false, false);
    assert_int_equal(ret, EINVAL);

    ret = sss_write_krb5_conf_snippet("abc", false, false);
    assert_int_equal(ret, EINVAL);

    ret = sss_write_krb5_conf_snippet("", false, false);
    assert_int_equal(ret, EOK);

    ret = sss_write_krb5_conf_snippet("none", false, false);
    assert_int_equal(ret, EOK);

    cwd = getcwd(buf, PATH_MAX);
    assert_non_null(cwd);

    ret = asprintf(&path, "%s/%s", cwd, TESTS_PATH);
    assert_true(ret > 0);

    ret = asprintf(&file, "%s/%s/localauth_plugin", cwd, TESTS_PATH);
    assert_true(ret > 0);

    ret = asprintf(&file_krb5_libdefaults,
                   "%s/%s/krb5_libdefaults", cwd, TESTS_PATH);
    assert_true(ret > 0);

    ret = sss_write_krb5_conf_snippet(path, true, true);
    assert_int_equal(ret, EOK);

    /* Check if writing a second time will work as well */
    ret = sss_write_krb5_conf_snippet(path, true, true);
    assert_int_equal(ret, EOK);

#ifdef HAVE_KRB5_LOCALAUTH_PLUGIN
    ret = unlink(file);
    assert_int_equal(ret, EOK);
#endif

    ret = unlink(file_krb5_libdefaults);
    assert_int_equal(ret, EOK);

    free(file);
    free(file_krb5_libdefaults);
    free(path);
}

void test_get_hidden_path(void **state)
{
    char *s;

    assert_null(get_hidden_tmp_path(NULL, NULL));
    assert_null(get_hidden_tmp_path(NULL, "/"));
    assert_null(get_hidden_tmp_path(NULL, "/abc/"));

    s = get_hidden_tmp_path(NULL, "abc");
    assert_string_equal(s, ".abcXXXXXX");
    talloc_free(s);

    s = get_hidden_tmp_path(NULL, "/abc");
    assert_string_equal(s, "/.abcXXXXXX");
    talloc_free(s);

    s = get_hidden_tmp_path(NULL, "/xyz/xyz/xyz//abc");
    assert_string_equal(s, "/xyz/xyz/xyz//.abcXXXXXX");
    talloc_free(s);
}

struct unique_file_test_ctx {
    char *filename;
};

static int unique_file_test_setup(void **state)
{
    struct unique_file_test_ctx *test_ctx;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context, struct unique_file_test_ctx);
    assert_non_null(test_ctx);

    test_ctx->filename = talloc_strdup(test_ctx, "test_unique_file_XXXXXX");
    assert_non_null(test_ctx);

    *state = test_ctx;
    return 0;
}

static int unique_file_test_teardown(void **state)
{
    struct unique_file_test_ctx *test_ctx;
    errno_t ret;

    test_ctx = talloc_get_type(*state, struct unique_file_test_ctx);

    errno = 0;
    ret = unlink(test_ctx->filename);
    if (ret != 0 && errno != ENOENT) {
        fail();
    }

    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
    return 0;
}

static void assert_destructor(TALLOC_CTX *owner,
                              struct unique_file_test_ctx *test_ctx)
{
    errno_t ret;
    char *check_filename;

    /* Test that the destructor works */
    if (owner == NULL) {
        return;
    }

    check_filename = talloc_strdup(test_ctx, test_ctx->filename);
    assert_non_null(check_filename);

    talloc_free(owner);

    ret = check_file(check_filename, geteuid(), getegid(),
                     (S_IRUSR | S_IWUSR | S_IFREG), 0, NULL, true);
    assert_int_not_equal(ret, EOK);
}

static void sss_unique_file_test(struct unique_file_test_ctx *test_ctx,
                                 bool test_destructor)
{
    int fd;
    errno_t ret;
    TALLOC_CTX *owner = NULL;

    if (test_destructor) {
        owner = talloc_new(test_ctx);
        assert_non_null(owner);
    }

    fd = sss_unique_file(owner, test_ctx->filename, &ret);
    assert_int_not_equal(fd, -1);
    assert_int_equal(ret, EOK);

    ret = check_file(test_ctx->filename, geteuid(), getegid(),
                     (S_IRUSR | S_IWUSR | S_IFREG), 0, NULL, false);
    close(fd);
    assert_int_equal(ret, EOK);

    assert_destructor(owner, test_ctx);
}

static void test_sss_unique_file(void **state)
{
    struct unique_file_test_ctx *test_ctx;
    test_ctx = talloc_get_type(*state, struct unique_file_test_ctx);
    sss_unique_file_test(test_ctx, false);
}

static void test_sss_unique_file_destruct(void **state)
{
    struct unique_file_test_ctx *test_ctx;
    test_ctx = talloc_get_type(*state, struct unique_file_test_ctx);
    sss_unique_file_test(test_ctx, true);
}

static void test_sss_unique_file_neg(void **state)
{
    int fd;
    errno_t ret;

    fd = sss_unique_file(NULL, discard_const("badpattern"), &ret);
    assert_int_equal(fd, -1);
    assert_int_equal(ret, EINVAL);
}

static void sss_unique_filename_test(struct unique_file_test_ctx *test_ctx,
                                     bool test_destructor)
{
    errno_t ret;
    char *tmp_filename;
    TALLOC_CTX *owner = NULL;

    tmp_filename = talloc_strdup(test_ctx, test_ctx->filename);
    assert_non_null(tmp_filename);

    if (test_destructor) {
        owner = talloc_new(test_ctx);
        assert_non_null(owner);
    }

    ret = sss_unique_filename(owner, test_ctx->filename);
    assert_int_equal(ret, EOK);

    assert_int_equal(strncmp(test_ctx->filename,
                             tmp_filename,
                             strlen(tmp_filename) - sizeof("XXXXXX")),
                     0);

    ret = check_file(test_ctx->filename, geteuid(), getegid(),
                     (S_IRUSR | S_IWUSR | S_IFREG), 0, NULL, true);
    assert_int_equal(ret, EOK);

    assert_destructor(owner, test_ctx);
}

static void test_sss_unique_filename(void **state)
{
    struct unique_file_test_ctx *test_ctx;

    test_ctx = talloc_get_type(*state, struct unique_file_test_ctx);
    sss_unique_filename_test(test_ctx, false);
}

static void test_sss_unique_filename_destruct(void **state)
{
    struct unique_file_test_ctx *test_ctx;

    test_ctx = talloc_get_type(*state, struct unique_file_test_ctx);
    sss_unique_filename_test(test_ctx, true);
}

static void test_parse_cert_verify_opts(void **state)
{
    int ret;
    struct cert_verify_opts *cv_opts;

    ret = parse_cert_verify_opts(global_talloc_context, NULL, &cv_opts);
    assert_int_equal(ret, EOK);
    assert_true(cv_opts->do_verification);
    assert_false(cv_opts->verification_partial_chain);
    assert_true(cv_opts->do_ocsp);
    assert_null(cv_opts->ocsp_default_responder);
    assert_null(cv_opts->ocsp_default_responder_signing_cert);
    assert_null(cv_opts->crl_files);
    talloc_free(cv_opts);

    ret = parse_cert_verify_opts(global_talloc_context, "wedfkwefjk", &cv_opts);
    assert_int_equal(ret, EOK);
    assert_true(cv_opts->do_verification);
    assert_false(cv_opts->verification_partial_chain);
    assert_true(cv_opts->do_ocsp);
    assert_null(cv_opts->ocsp_default_responder);
    assert_null(cv_opts->ocsp_default_responder_signing_cert);
    assert_null(cv_opts->crl_files);
    talloc_free(cv_opts);

    ret = parse_cert_verify_opts(global_talloc_context, "no_ocsp", &cv_opts);
    assert_int_equal(ret, EOK);
    assert_true(cv_opts->do_verification);
    assert_false(cv_opts->verification_partial_chain);
    assert_false(cv_opts->do_ocsp);
    assert_null(cv_opts->ocsp_default_responder);
    assert_null(cv_opts->ocsp_default_responder_signing_cert);
    assert_null(cv_opts->crl_files);
    talloc_free(cv_opts);

    ret = parse_cert_verify_opts(global_talloc_context, "no_verification",
                                 &cv_opts);
    assert_int_equal(ret, EOK);
    assert_false(cv_opts->do_verification);
    assert_false(cv_opts->verification_partial_chain);
    assert_true(cv_opts->do_ocsp);
    assert_null(cv_opts->ocsp_default_responder);
    assert_null(cv_opts->ocsp_default_responder_signing_cert);
    assert_null(cv_opts->crl_files);
    talloc_free(cv_opts);

    ret = parse_cert_verify_opts(global_talloc_context,
                                 "no_ocsp,no_verification", &cv_opts);
    assert_int_equal(ret, EOK);
    assert_false(cv_opts->do_verification);
    assert_false(cv_opts->verification_partial_chain);
    assert_false(cv_opts->do_ocsp);
    assert_null(cv_opts->ocsp_default_responder);
    assert_null(cv_opts->ocsp_default_responder_signing_cert);
    assert_null(cv_opts->crl_files);
    talloc_free(cv_opts);

    ret = parse_cert_verify_opts(global_talloc_context,
                                 "ocsp_default_responder=", &cv_opts);
    assert_int_equal(ret, EINVAL);

    ret = parse_cert_verify_opts(global_talloc_context,
                                 "ocsp_default_responder_signing_cert=",
                                 &cv_opts);
    assert_int_equal(ret, EINVAL);

    ret = parse_cert_verify_opts(global_talloc_context,
                                 "ocsp_default_responder=abc,"
                                 "ocsp_default_responder_signing_cert=def",
                                 &cv_opts);
    assert_int_equal(ret, EOK);
    assert_true(cv_opts->do_verification);
    assert_false(cv_opts->verification_partial_chain);
    assert_true(cv_opts->do_ocsp);
    assert_string_equal(cv_opts->ocsp_default_responder, "abc");
    assert_string_equal(cv_opts->ocsp_default_responder_signing_cert, "def");
    assert_null(cv_opts->crl_files);
    talloc_free(cv_opts);

    ret = parse_cert_verify_opts(global_talloc_context, "crl_file=hij",
                                 &cv_opts);
    assert_int_equal(ret, EOK);
    assert_true(cv_opts->do_verification);
    assert_false(cv_opts->verification_partial_chain);
    assert_true(cv_opts->do_ocsp);
    assert_null(cv_opts->ocsp_default_responder);
    assert_null(cv_opts->ocsp_default_responder_signing_cert);
    assert_string_equal(cv_opts->crl_files[0], "hij");
    talloc_free(cv_opts);

    ret = parse_cert_verify_opts(global_talloc_context,
                                 "crl_file=file1.pem,crl_file=file2.pem",
                                 &cv_opts);
    assert_int_equal(ret, EOK);
    assert_true(cv_opts->do_verification);
    assert_false(cv_opts->verification_partial_chain);
    assert_true(cv_opts->do_ocsp);
    assert_null(cv_opts->ocsp_default_responder);
    assert_null(cv_opts->ocsp_default_responder_signing_cert);
    assert_string_equal(cv_opts->crl_files[0], "file1.pem");
    assert_string_equal(cv_opts->crl_files[1], "file2.pem");
    talloc_free(cv_opts);

    ret = parse_cert_verify_opts(global_talloc_context, "partial_chain", &cv_opts);
    assert_int_equal(ret, EOK);
    assert_true(cv_opts->do_verification);
    assert_true(cv_opts->verification_partial_chain);
    assert_true(cv_opts->do_ocsp);
    assert_null(cv_opts->ocsp_default_responder);
    assert_null(cv_opts->ocsp_default_responder_signing_cert);
    assert_null(cv_opts->crl_files);
    talloc_free(cv_opts);
}

static void assert_parse_fqname(const char *fqname,
                                const char *exp_shortname,
                                const char *exp_domname)
{
    errno_t ret;
    char *shortname = NULL;
    char *domname = NULL;

    check_leaks_push(global_talloc_context);

    ret = sss_parse_internal_fqname(global_talloc_context, fqname,
                                    exp_shortname ? &shortname : NULL,
                                    exp_domname ? &domname : NULL);
    assert_int_equal(ret, EOK);

    if (exp_shortname) {
        assert_string_equal(shortname, exp_shortname);
    }
    if (exp_domname) {
        assert_string_equal(domname, exp_domname);
    }

    talloc_free(shortname);
    talloc_free(domname);

    assert_true(check_leaks_pop(global_talloc_context) == true);
}

static void assert_fqname_unparseable(const char *fqname, errno_t retval)
{
    errno_t ret;
    char *shortname = NULL;
    char *domname = NULL;

    check_leaks_push(global_talloc_context);

    ret = sss_parse_internal_fqname(global_talloc_context, fqname,
                                    &shortname, &domname);
    assert_int_equal(ret, retval);
    assert_null(shortname);
    assert_null(domname);

    assert_true(check_leaks_pop(global_talloc_context) == true);
}

static void test_sss_parse_internal_fqname(void **state)
{
    assert_parse_fqname("foo@bar", "foo", "bar");
    assert_parse_fqname("foo@bar", NULL, "bar");
    assert_parse_fqname("foo@bar", "foo", NULL);
    assert_parse_fqname("foo@bar", NULL, NULL);
    assert_parse_fqname("foo@bar@baz", "foo@bar", "baz");

    assert_fqname_unparseable("foo", ERR_WRONG_NAME_FORMAT);
    assert_fqname_unparseable("foo@", ERR_WRONG_NAME_FORMAT);
    assert_fqname_unparseable("@", ERR_WRONG_NAME_FORMAT);
    assert_fqname_unparseable("@bar", ERR_WRONG_NAME_FORMAT);
    assert_fqname_unparseable(NULL, EINVAL);
}

static void test_sss_create_internal_fqname(void **state)
{
    char *fqname = NULL;

    check_leaks_push(global_talloc_context);

    fqname = sss_create_internal_fqname(global_talloc_context, "foo", "bar");
    assert_string_equal(fqname, "foo@bar");
    talloc_zfree(fqname);

    fqname = sss_create_internal_fqname(global_talloc_context, "foo", "BAR");
    assert_string_equal(fqname, "foo@bar");
    talloc_zfree(fqname);

    fqname = sss_create_internal_fqname(global_talloc_context, "foo", NULL);
    assert_null(fqname);

    fqname = sss_create_internal_fqname(global_talloc_context, NULL, "bar");
    assert_null(fqname);

    fqname = sss_create_internal_fqname(global_talloc_context, NULL, NULL);
    assert_null(fqname);

    assert_true(check_leaks_pop(global_talloc_context) == true);
}

static void test_sss_create_internal_fqname_list(void **state)
{
    char **fqlist = NULL;
    const char *in_list1[] = { "aaa", "bbb", NULL };

    check_leaks_push(global_talloc_context);

    fqlist = sss_create_internal_fqname_list(global_talloc_context,
                                             in_list1, "DOM");
    assert_string_equal(fqlist[0], "aaa@dom");
    assert_string_equal(fqlist[1], "bbb@dom");
    assert_null(fqlist[2]);
    talloc_zfree(fqlist);

    fqlist = sss_create_internal_fqname_list(global_talloc_context,
                                             in_list1, NULL);
    assert_null(fqlist);

    fqlist = sss_create_internal_fqname_list(global_talloc_context,
                                             NULL, "DOM");
    assert_null(fqlist);

    fqlist = sss_create_internal_fqname_list(global_talloc_context,
                                             NULL, NULL);
    assert_null(fqlist);

    assert_true(check_leaks_pop(global_talloc_context) == true);
}

static void test_sss_output_name(void **state)
{
    char *outname;
    char *fqname;

    check_leaks_push(global_talloc_context);

    fqname = sss_create_internal_fqname(global_talloc_context,
                                        "Foo Bar", "DOM");
    assert_non_null(fqname);

    outname = sss_output_name(global_talloc_context, fqname, true, 0);
    assert_non_null(outname);
    assert_string_equal(outname, "Foo Bar");
    talloc_zfree(outname);

    outname = sss_output_name(global_talloc_context, fqname, false, 0);
    assert_non_null(outname);
    assert_string_equal(outname, "foo bar");
    talloc_zfree(outname);

    outname = sss_output_name(global_talloc_context, fqname, false, '-');
    assert_non_null(outname);
    assert_string_equal(outname, "foo-bar");
    talloc_zfree(outname);

    talloc_free(fqname);
    assert_true(check_leaks_pop(global_talloc_context) == true);
}

static void test_sss_get_domain_mappings_content(void **state)
{
    struct dom_list_test_ctx *test_ctx;
    int ret;
    struct sss_domain_info *dom;
    char *content;
    struct sss_domain_info *c;

    ret = sss_get_domain_mappings_content(NULL, NULL, NULL);
    assert_int_equal(ret, EINVAL);

    test_ctx = talloc_get_type(*state, struct dom_list_test_ctx);
    assert_non_null(test_ctx);

    dom = get_domains_head(test_ctx->dom_list);
    assert_non_null(dom);

    /* no forest */
    ret = sss_get_domain_mappings_content(test_ctx, dom, &content);
    assert_int_equal(ret, EOK);
    assert_string_equal(content,
                        "[domain_realm]\n"
                        ".configured.dom = CONFIGURED.DOM\n"
                        "configured.dom = CONFIGURED.DOM\n"
                        ".subdom1.dom = SUBDOM1.DOM\n"
                        "subdom1.dom = SUBDOM1.DOM\n"
                        ".subdom2.dom = SUBDOM2.DOM\n"
                        "subdom2.dom = SUBDOM2.DOM\n"
                        ".subdom3.dom = SUBDOM3.DOM\n"
                        "subdom3.dom = SUBDOM3.DOM\n");
    talloc_free(content);

    /* IPA with forest */
    c = find_domain_by_name(dom, "subdom2.dom", true);
    assert_non_null(c);
    c->forest_root = find_domain_by_name(dom, "subdom1.dom", true);
    assert_non_null(c->forest_root);
    c->forest = discard_const_p(char, "subdom1.dom");

    c = find_domain_by_name(dom, "subdom3.dom", true);
    assert_non_null(c);
    c->forest_root = find_domain_by_name(dom, "subdom1.dom", true);
    assert_non_null(c->forest_root);
    c->forest = discard_const_p(char, "subdom1.dom");

    ret = sss_get_domain_mappings_content(test_ctx, dom, &content);
    assert_int_equal(ret, EOK);
    assert_string_equal(content,
                        "[domain_realm]\n"
                        ".configured.dom = CONFIGURED.DOM\n"
                        "configured.dom = CONFIGURED.DOM\n"
                        ".subdom1.dom = SUBDOM1.DOM\n"
                        "subdom1.dom = SUBDOM1.DOM\n"
                        ".subdom2.dom = SUBDOM2.DOM\n"
                        "subdom2.dom = SUBDOM2.DOM\n"
                        ".subdom3.dom = SUBDOM3.DOM\n"
                        "subdom3.dom = SUBDOM3.DOM\n"
                        "[capaths]\n"
                        "SUBDOM2.DOM = {\n"
                        "  CONFIGURED.DOM = SUBDOM1.DOM\n"
                        "}\n"
                        "SUBDOM3.DOM = {\n"
                        "  CONFIGURED.DOM = SUBDOM1.DOM\n"
                        "}\n"
                        "CONFIGURED.DOM = {\n"
                        "  SUBDOM2.DOM = SUBDOM1.DOM\n"
                        "  SUBDOM3.DOM = SUBDOM1.DOM\n"
                        "}\n");
    talloc_free(content);

    /* Next steps, test AD domain setup. If we join a child domain we have a
     * similar case as with IPA but if we join the forest root the generate
     * capaths might not be as expected. */
}


static void test_sss_filter_sanitize_dn(void **state)
{
    TALLOC_CTX *tmp_ctx;
    char *trimmed;
    int ret;
    const char *DN = "cn=user,ou=people,dc=example,dc=com";

    tmp_ctx = talloc_new(NULL);
    assert_non_null(tmp_ctx);

    /* test that we remove spaces around '=' and ','*/
    ret = sss_filter_sanitize_dn(tmp_ctx, DN, &trimmed);
    assert_int_equal(ret, EOK);
    assert_string_equal(DN, trimmed);
    talloc_free(trimmed);

    ret = sss_filter_sanitize_dn(tmp_ctx, "cn=user,ou=people,dc=example,dc=com", &trimmed);
    assert_int_equal(ret, EOK);
    assert_string_equal(DN, trimmed);
    talloc_free(trimmed);

    ret = sss_filter_sanitize_dn(tmp_ctx, "cn= user,ou =people,dc = example,dc  =  com", &trimmed);
    assert_int_equal(ret, EOK);
    assert_string_equal(DN, trimmed);
    talloc_free(trimmed);

    ret = sss_filter_sanitize_dn(tmp_ctx, "cn=user, ou=people ,dc=example , dc=com", &trimmed);
    assert_int_equal(ret, EOK);
    assert_string_equal(DN, trimmed);
    talloc_free(trimmed);

    ret = sss_filter_sanitize_dn(tmp_ctx, "cn=user,  ou=people  ,dc=example  ,   dc=com", &trimmed);
    assert_int_equal(ret, EOK);
    assert_string_equal(DN, trimmed);
    talloc_free(trimmed);

    ret = sss_filter_sanitize_dn(tmp_ctx, "cn= user, ou =people ,dc = example  ,  dc  = com", &trimmed);
    assert_int_equal(ret, EOK);
    assert_string_equal(DN, trimmed);
    talloc_free(trimmed);

    ret = sss_filter_sanitize_dn(tmp_ctx, " cn=user,ou=people,dc=example,dc=com ", &trimmed);
    assert_int_equal(ret, EOK);
    assert_string_equal(DN, trimmed);
    talloc_free(trimmed);

    ret = sss_filter_sanitize_dn(tmp_ctx, "  cn=user, ou=people, dc=example, dc=com  ", &trimmed);
    assert_int_equal(ret, EOK);
    assert_string_equal(DN, trimmed);
    talloc_free(trimmed);

    /* test that we keep spaces inside a value */
    ret = sss_filter_sanitize_dn(tmp_ctx, "cn = user one, ou=people  branch, dc=example, dc=com", &trimmed);
    assert_int_equal(ret, EOK);
    assert_string_equal("cn=user\\20one,ou=people\\20\\20branch,dc=example,dc=com", trimmed);
    talloc_free(trimmed);

    /* test that we keep escape special chars like () */
    ret = sss_filter_sanitize_dn(tmp_ctx, "cn = user one, ou=p(e)ople, dc=example, dc=com", &trimmed);
    assert_int_equal(ret, EOK);
    assert_string_equal("cn=user\\20one,ou=p\\28e\\29ople,dc=example,dc=com", trimmed);
    talloc_free(trimmed);

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

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_find_domain_by_sid_null,
                                        setup_dom_list, teardown_dom_list),
        cmocka_unit_test_setup_teardown(test_find_domain_by_sid,
                                        setup_dom_list, teardown_dom_list),
        cmocka_unit_test_setup_teardown(test_find_domain_by_sid_missing_sid,
                                        setup_dom_list, teardown_dom_list),
        cmocka_unit_test_setup_teardown(test_find_domain_by_sid_disabled,
                                        setup_dom_list, teardown_dom_list),
        cmocka_unit_test_setup_teardown(test_find_domain_by_name_null,
                                        setup_dom_list, teardown_dom_list),
        cmocka_unit_test_setup_teardown(test_find_domain_by_name,
                                        setup_dom_list, teardown_dom_list),
        cmocka_unit_test_setup_teardown(test_find_domain_by_name_missing_flat_name,
                                        setup_dom_list, teardown_dom_list),
        cmocka_unit_test_setup_teardown(test_find_domain_by_name_disabled,
                                        setup_dom_list, teardown_dom_list),
        cmocka_unit_test_setup_teardown(test_find_domain_by_name_ex_disabled,
                                        setup_dom_list, teardown_dom_list),
        cmocka_unit_test_setup_teardown(test_find_domain_by_object_name_ex,
                                        setup_dom_list, teardown_dom_list),

        cmocka_unit_test_setup_teardown(test_sss_names_init,
                                        confdb_test_setup,
                                        confdb_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_names_ipa_ad_regexp,
                                        confdb_test_setup,
                                        confdb_test_teardown),

        cmocka_unit_test_setup_teardown(test_get_next_domain,
                                        setup_dom_tree, teardown_dom_tree),
        cmocka_unit_test_setup_teardown(test_get_next_domain_descend,
                                        setup_dom_tree, teardown_dom_tree),
        cmocka_unit_test_setup_teardown(test_get_next_domain_disabled,
                                        setup_dom_tree, teardown_dom_tree),
        cmocka_unit_test_setup_teardown(test_get_next_domain_flags,
                                        setup_dom_tree, teardown_dom_tree),

        cmocka_unit_test(test_well_known_sid_to_name),
        cmocka_unit_test(test_name_to_well_known_sid),

        cmocka_unit_test_setup_teardown(test_sss_filter_sanitize_for_dom,
                                        setup_dom_list,
                                        teardown_dom_list),

        cmocka_unit_test(test_expand_homedir_template_NULL),
        cmocka_unit_test_setup_teardown(test_expand_homedir_template,
                                        setup_homedir_ctx,
                                        teardown_homedir_ctx),
#ifdef BUILD_SSH
        cmocka_unit_test(test_textual_public_key),
#endif
        cmocka_unit_test(test_replace_whitespaces),
        cmocka_unit_test(test_reverse_replace_whitespaces),
        cmocka_unit_test(test_guid_blob_to_string_buf),
        cmocka_unit_test(test_get_last_x_chars),
        cmocka_unit_test(test_concatenate_string_array),
        cmocka_unit_test_setup_teardown(test_add_strings_lists,
                                        setup_leak_tests,
                                        teardown_leak_tests),
        cmocka_unit_test(test_sss_write_krb5_conf_snippet),
        cmocka_unit_test(test_get_hidden_path),
        cmocka_unit_test_setup_teardown(test_sss_unique_file,
                                        unique_file_test_setup,
                                        unique_file_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_unique_file_destruct,
                                        unique_file_test_setup,
                                        unique_file_test_teardown),
        cmocka_unit_test(test_sss_unique_file_neg),
        cmocka_unit_test_setup_teardown(test_sss_unique_filename,
                                        unique_file_test_setup,
                                        unique_file_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_unique_filename_destruct,
                                        unique_file_test_setup,
                                        unique_file_test_teardown),
        cmocka_unit_test_setup_teardown(test_parse_cert_verify_opts,
                                        setup_leak_tests,
                                        teardown_leak_tests),
        cmocka_unit_test_setup_teardown(test_sss_parse_internal_fqname,
                                        setup_leak_tests,
                                        teardown_leak_tests),
        cmocka_unit_test_setup_teardown(test_sss_create_internal_fqname,
                                        setup_leak_tests,
                                        teardown_leak_tests),
        cmocka_unit_test_setup_teardown(test_sss_create_internal_fqname_list,
                                        setup_leak_tests,
                                        teardown_leak_tests),
        cmocka_unit_test_setup_teardown(test_sss_output_name,
                                        setup_leak_tests,
                                        teardown_leak_tests),
        cmocka_unit_test_setup_teardown(test_sss_get_domain_mappings_content,
                                        setup_dom_list_with_subdomains,
                                        teardown_dom_list),
        cmocka_unit_test_setup_teardown(test_sss_ptr_hash_with_free_cb,
                                        setup_leak_tests,
                                        teardown_leak_tests),
        cmocka_unit_test_setup_teardown(test_sss_ptr_hash_overwrite_with_free_cb,
                                        setup_leak_tests,
                                        teardown_leak_tests),
        cmocka_unit_test_setup_teardown(test_sss_ptr_hash_with_lookup_cb,
                                        setup_leak_tests,
                                        teardown_leak_tests),
        cmocka_unit_test_setup_teardown(test_sss_ptr_hash_without_cb,
                                        setup_leak_tests,
                                        teardown_leak_tests),
        cmocka_unit_test_setup_teardown(test_sss_filter_sanitize_dn,
                                        setup_leak_tests,
                                        teardown_leak_tests),
        cmocka_unit_test_setup_teardown(test_mod_defaults_list,
                                        setup_leak_tests,
                                        teardown_leak_tests),
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
    if (rv == 0) {
        test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);
    }
    return rv;
}
