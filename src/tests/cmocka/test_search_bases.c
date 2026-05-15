/*
    Authors:
        Pavel Reichl <preichl@redhat.com>

    Copyright (C) 2013 Red Hat

    SSSD tests - Search bases

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
#include <stdlib.h>
#include <stddef.h>
#include <setjmp.h>
#include <unistd.h>
#include <sys/types.h>
#include <cmocka.h>
#include <ldap.h>

#include "util/find_uid.h"
#include "util/sss_ldap.h"
#include "tests/common.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap.h"
#include "dhash.h"

enum sss_test_get_by_dn {
    DN_NOT_IN_DOMS, /* dn is not in any domain           */
    DN_IN_DOM1,     /* dn is in the domain based on dns  */
    DN_IN_DOM2,     /* dn is in the domain based on dns2 */
};

struct test_ctx {
    struct ldb_context *ldb;
};

static int test_setup(void **state)
{
    struct test_ctx *test_ctx;

    test_ctx = talloc_zero(global_talloc_context, struct test_ctx);
    assert_non_null(test_ctx);

    test_ctx->ldb = ldb_init(test_ctx, NULL);
    assert_non_null(test_ctx->ldb);

    *state = test_ctx;
    return 0;
}

static int test_teardown(void **state)
{
    struct test_ctx *test_ctx = talloc_get_type(*state, struct test_ctx);

    talloc_free(test_ctx);
    return 0;
}

static struct sdap_search_base** generate_bases(TALLOC_CTX *mem_ctx,
                                                struct ldb_context *ldb,
                                                const char** dns, size_t n)
{
    struct sdap_search_base **search_bases;
    errno_t err;
    int i;

    search_bases = talloc_array(mem_ctx, struct sdap_search_base *, n + 1);
    assert_non_null(search_bases);

    for (i=0; i < n; ++i) {
        err = sdap_create_search_base(mem_ctx, ldb, dns[i], LDAP_SCOPE_SUBTREE,
                                      NULL, &search_bases[i]);
        if (err != EOK) {
            fprintf(stderr, "Failed to create search base\n");
        }
        assert_int_equal(err, EOK);
    }
    search_bases[n] = NULL;
    return search_bases;
}

static bool do_test_search_bases(struct test_ctx *test_ctx, const char* dn,
                                 const char** dns, size_t n)
{
    TALLOC_CTX *tmp_ctx;
    struct sdap_search_base **search_bases;
    bool ret;

    tmp_ctx = talloc_new(NULL);
    assert_non_null(tmp_ctx);

    search_bases = generate_bases(tmp_ctx, test_ctx->ldb, dns, n);
    check_leaks_push(tmp_ctx);
    ret = sss_ldap_dn_in_search_bases(tmp_ctx, dn, search_bases, NULL);
    assert_true(check_leaks_pop(tmp_ctx) == true);

    talloc_free(tmp_ctx);
    return ret;
}

void test_search_bases_fail(void **state)
{
    const char *dn = "cn=user, dc=sub, dc=ad, dc=pb";
    const char *dns[] = {"dc=example, dc=com", "dc=subdom, dc=ad, dc=pb"};
    struct test_ctx *test_ctx = talloc_get_type(*state, struct test_ctx);
    bool ret;

    ret = do_test_search_bases(test_ctx, dn, dns, 2);
    assert_false(ret);
}

void test_search_bases_success(void **state)
{
    const char *dn = "cn=user, dc=sub, dc=ad, dc=pb";
    const char *dns[] = {"", "dc=ad, dc=pb", "dc=sub, dc=ad, dc=pb"};
    struct test_ctx *test_ctx = talloc_get_type(*state, struct test_ctx);
    bool ret;

    ret = do_test_search_bases(test_ctx, dn, dns, 3);
    assert_true(ret);
}

static void do_test_get_by_dn(struct test_ctx *test_ctx, const char *dn,
                              const char **dns, size_t n,
                              const char **dns2, size_t n2, int expected_result)
{
    TALLOC_CTX *tmp_ctx;
    struct sdap_options *opts;
    struct sdap_domain *sdom;
    struct sdap_domain *sdom2;
    struct sdap_domain *res_sdom;
    struct sdap_search_base **search_bases;
    struct sdap_search_base **search_bases2;
    tmp_ctx = talloc_new(NULL);
    assert_non_null(tmp_ctx);

    search_bases = generate_bases(tmp_ctx, test_ctx->ldb, dns, n);
    search_bases2 = generate_bases(tmp_ctx, test_ctx->ldb, dns2, n2);
    sdom = talloc_zero(tmp_ctx, struct sdap_domain);
    assert_non_null(sdom);
    sdom2 = talloc_zero(tmp_ctx, struct sdap_domain);
    assert_non_null(sdom2);

    sdom->search_bases = search_bases;
    sdom->next = sdom2;
    sdom->prev = NULL;
    sdom2->search_bases = search_bases2;
    sdom2->next = NULL;
    sdom2->prev = sdom;

    opts = talloc(tmp_ctx, struct sdap_options);
    assert_non_null(opts);
    opts->sdom = sdom;
    res_sdom = sdap_domain_get_by_dn(opts, dn);

    switch (expected_result) {
    case DN_NOT_IN_DOMS:
        assert_null(res_sdom);
        break;
    case DN_IN_DOM1:
        assert_true(res_sdom == sdom);
        break;
    case DN_IN_DOM2:
        assert_true(res_sdom == sdom2);
        break;
    }

    talloc_free(tmp_ctx);
}

void test_get_by_dn(void **state)
{
    const char *dn = "cn=user, dc=sub, dc=ad, dc=pb";
    const char *dns[] = {"dc=ad, dc=pb"};
    const char *dns2[] = {"dc=sub, dc=ad, dc=pb"};
    struct test_ctx *test_ctx = talloc_get_type(*state, struct test_ctx);

    do_test_get_by_dn(test_ctx, dn, dns, 1, dns2, 1, DN_IN_DOM2);
}

void test_get_by_dn2(void **state)
{
    const char *dn = "cn=user, dc=ad, dc=com";
    const char *dns[] = {"dc=ad, dc=com"};
    const char *dns2[] = {"dc=sub, dc=ad, dc=pb"};
    struct test_ctx *test_ctx = talloc_get_type(*state, struct test_ctx);

    do_test_get_by_dn(test_ctx, dn, dns, 1, dns2, 1, DN_IN_DOM1);
}

void test_get_by_dn_fail(void **state)
{
    const char *dn = "cn=user, dc=sub, dc=example, dc=com";
    const char *dns[] = {"dc=ad, dc=pb"};
    const char *dns2[] = {"dc=sub, dc=ad, dc=pb"};
    struct test_ctx *test_ctx = talloc_get_type(*state, struct test_ctx);

    do_test_get_by_dn(test_ctx, dn, dns, 1, dns2, 1, DN_NOT_IN_DOMS);
}

void test_sdap_domain_get_by_name(void **state)
{
    struct sdap_options *opts;
    struct sss_domain_info dom1 = { 0 };
    dom1.name  = discard_const("dom1");
    struct sss_domain_info dom2 = { 0 };
    dom2.name  = discard_const("dom2");
    struct sss_domain_info dom3 = { 0 };
    dom3.name  = discard_const("dom3");
    int ret;
    struct sdap_domain *sdom;

    opts = talloc_zero(NULL, struct sdap_options);
    assert_non_null(opts);

    ret = sdap_domain_add(opts, &dom1, NULL);
    assert_int_equal(ret, EOK);

    ret = sdap_domain_add(opts, &dom2, NULL);
    assert_int_equal(ret, EOK);

    ret = sdap_domain_add(opts, &dom3, NULL);
    assert_int_equal(ret, EOK);

    sdom = sdap_domain_get_by_name(opts, NULL);
    assert_null(sdom);

    sdom = sdap_domain_get_by_name(opts, "abc");
    assert_null(sdom);

    sdom = sdap_domain_get_by_name(opts, "dom1");
    assert_non_null(sdom);
    assert_ptr_equal(sdom->dom, &dom1);

    sdom = sdap_domain_get_by_name(opts, "dom2");
    assert_non_null(sdom);
    assert_ptr_equal(sdom->dom, &dom2);

    sdom = sdap_domain_get_by_name(opts, "dom3");
    assert_non_null(sdom);
    assert_ptr_equal(sdom->dom, &dom3);

    talloc_free(opts);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_search_bases_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_search_bases_success,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_get_by_dn_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_get_by_dn,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_get_by_dn2,
                                        test_setup,
                                        test_teardown),

        cmocka_unit_test(test_sdap_domain_get_by_name)
     };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
