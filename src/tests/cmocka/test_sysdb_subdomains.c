/*
    SSSD

    sysdb_subdomains - Tests for subdomains and related calls

    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <popt.h>

#include "tests/cmocka/common_mock.h"
#include "tests/common.h"
#include "providers/ipa/ipa_subdomains.h"
#include "db/sysdb_private.h" /* for sysdb->ldb member */

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_DB "test_sysdb_subdomains.ldb"

#define TEST_DOM1_NAME "test_sysdb_subdomains_1"

#define TEST_FLAT_NAME "TEST_1"
#define TEST_SID    "S-1"
#define TEST_REALM "TEST_SYSDB_SUBDOMAINS"
#define TEST_FOREST TEST_REALM
#define TEST_ID_PROVIDER "ldap"

#define TEST_DOM2_NAME "child2.test_sysdb_subdomains_2"
#define TEST_FLAT_NAME2 "CHILD2"
#define TEST_SID2    "S-2"
#define TEST_REALM2 "TEST_SYSDB_SUBDOMAINS2"
#define TEST_FOREST2 TEST_REALM2

const char *domains[] = { TEST_DOM1_NAME,
                          TEST_DOM2_NAME,
                          NULL };

struct subdom_test_ctx {
    struct sss_test_ctx *tctx;
};

static int test_sysdb_subdom_setup(void **state)
{
    struct subdom_test_ctx *test_ctx;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context,
                           struct subdom_test_ctx);
    assert_non_null(test_ctx);

    test_dom_suite_setup(TESTS_PATH);

    test_ctx->tctx = create_multidom_test_ctx(test_ctx, TESTS_PATH,
                                              TEST_CONF_DB, domains,
                                              TEST_ID_PROVIDER, NULL);
    assert_non_null(test_ctx->tctx);

    *state = test_ctx;
    return 0;
}

static int test_sysdb_subdom_teardown(void **state)
{
    struct subdom_test_ctx *test_ctx =
        talloc_get_type(*state, struct subdom_test_ctx);

    test_multidom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, domains);
    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
    return 0;
}

static void test_sysdb_subdomain_create(void **state)
{
    errno_t ret;
    struct subdom_test_ctx *test_ctx =
        talloc_get_type(*state, struct subdom_test_ctx);

    const char *const dom1[4] = { "dom1.sub", "DOM1.SUB", "dom1", "S-1" };
    const char *const dom2[4] = { "dom2.sub", "DOM2.SUB", "dom2", "S-2" };

    ret = sysdb_subdomain_store(test_ctx->tctx->sysdb,
                                dom1[0], dom1[1], dom1[2], dom1[0], dom1[3],
                                MPG_DISABLED, false, NULL, 0, IPA_TRUST_UNKNOWN,
                                NULL);
    assert_int_equal(ret, EOK);

    ret = sysdb_update_subdomains(test_ctx->tctx->dom, test_ctx->tctx->confdb);
    assert_int_equal(ret, EOK);

    assert_non_null(test_ctx->tctx->dom->subdomains);
    assert_string_equal(test_ctx->tctx->dom->subdomains->name, dom1[0]);
    assert_int_equal(test_ctx->tctx->dom->subdomains->trust_direction, 0);
    assert_true(test_ctx->tctx->dom->subdomains->mpg_mode == MPG_DISABLED);

    ret = sysdb_subdomain_store(test_ctx->tctx->sysdb,
                                dom2[0], dom2[1], dom2[2], dom2[0], dom2[3],
                                MPG_DISABLED, false, NULL, 1, IPA_TRUST_UNKNOWN,
                                NULL);
    assert_int_equal(ret, EOK);

    ret = sysdb_update_subdomains(test_ctx->tctx->dom, test_ctx->tctx->confdb);
    assert_int_equal(ret, EOK);

    assert_non_null(test_ctx->tctx->dom->subdomains->next);
    assert_string_equal(test_ctx->tctx->dom->subdomains->next->name, dom2[0]);
    assert_int_equal(test_ctx->tctx->dom->subdomains->next->trust_direction, 1);
    assert_true(test_ctx->tctx->dom->subdomains->next->mpg_mode == MPG_DISABLED);

    /* Reverse the trust directions */
    ret = sysdb_subdomain_store(test_ctx->tctx->sysdb,
                                dom1[0], dom1[1], dom1[2], dom1[0], dom1[3],
                                MPG_DISABLED, false, NULL, 1, IPA_TRUST_UNKNOWN,
                                NULL);
    assert_int_equal(ret, EOK);

    ret = sysdb_subdomain_store(test_ctx->tctx->sysdb,
                                dom2[0], dom2[1], dom2[2], dom2[0], dom2[3],
                                MPG_DISABLED, false, NULL, 0, IPA_TRUST_UNKNOWN,
                                NULL);
    assert_int_equal(ret, EOK);

    ret = sysdb_update_subdomains(test_ctx->tctx->dom, test_ctx->tctx->confdb);
    assert_int_equal(ret, EOK);

    assert_int_equal(test_ctx->tctx->dom->subdomains->trust_direction, 1);
    assert_int_equal(test_ctx->tctx->dom->subdomains->next->trust_direction, 0);

    ret = sysdb_subdomain_delete(test_ctx->tctx->sysdb, dom2[0]);
    assert_int_equal(ret, EOK);

    ret = sysdb_subdomain_delete(test_ctx->tctx->sysdb, dom1[0]);
    assert_int_equal(ret, EOK);

    ret = sysdb_update_subdomains(test_ctx->tctx->dom, test_ctx->tctx->confdb);
    assert_int_equal(ret, EOK);

    assert_int_equal(sss_domain_get_state(test_ctx->tctx->dom->subdomains),
                     DOM_DISABLED);
    assert_int_equal(
            sss_domain_get_state(test_ctx->tctx->dom->subdomains->next),
            DOM_DISABLED);

    /* Test that changing the MPG status works */
    ret = sysdb_subdomain_store(test_ctx->tctx->sysdb,
                                dom1[0], dom1[1], dom1[2], dom1[0], dom1[3],
                                MPG_ENABLED, false, NULL, 1, IPA_TRUST_UNKNOWN,
                                NULL);
    assert_int_equal(ret, EOK);

    ret = sysdb_subdomain_store(test_ctx->tctx->sysdb,
                                dom2[0], dom2[1], dom2[2], dom2[0], dom2[3],
                                MPG_ENABLED, false, NULL, 0, IPA_TRUST_UNKNOWN,
                                NULL);
    assert_int_equal(ret, EOK);

    ret = sysdb_update_subdomains(test_ctx->tctx->dom, test_ctx->tctx->confdb);
    assert_int_equal(ret, EOK);

    assert_true(test_ctx->tctx->dom->subdomains->mpg_mode == MPG_ENABLED);
    assert_true(test_ctx->tctx->dom->subdomains->next->mpg_mode == MPG_ENABLED);

    ret = sysdb_subdomain_store(test_ctx->tctx->sysdb,
                                dom1[0], dom1[1], dom1[2], dom1[0], dom1[3],
                                MPG_HYBRID, false, NULL, 1, IPA_TRUST_UNKNOWN,
                                NULL);
    assert_int_equal(ret, EOK);

    ret = sysdb_subdomain_store(test_ctx->tctx->sysdb,
                                dom2[0], dom2[1], dom2[2], dom2[0], dom2[3],
                                MPG_HYBRID, false, NULL, 0, IPA_TRUST_UNKNOWN,
                                NULL);
    assert_int_equal(ret, EOK);

    ret = sysdb_update_subdomains(test_ctx->tctx->dom, test_ctx->tctx->confdb);
    assert_int_equal(ret, EOK);

    assert_true(test_ctx->tctx->dom->subdomains->mpg_mode == MPG_HYBRID);
    assert_true(test_ctx->tctx->dom->subdomains->next->mpg_mode == MPG_HYBRID);
}

static void test_sysdb_master_domain_ops(void **state)
{
    errno_t ret;
    struct subdom_test_ctx *test_ctx =
        talloc_get_type(*state, struct subdom_test_ctx);

    ret = sysdb_master_domain_add_info(test_ctx->tctx->dom,
                                       "realm1", "flat1", "realm1", "id1", "forest1",
                                       NULL);
    assert_int_equal(ret, EOK);

    ret = sysdb_master_domain_update(test_ctx->tctx->dom);
    assert_int_equal(ret, EOK);

    assert_string_equal(test_ctx->tctx->dom->realm, "realm1");
    assert_string_equal(test_ctx->tctx->dom->flat_name, "flat1");
    assert_string_equal(test_ctx->tctx->dom->domain_id, "id1");
    assert_string_equal(test_ctx->tctx->dom->forest, "forest1");

    ret = sysdb_master_domain_add_info(test_ctx->tctx->dom,
                                       "realm2", "flat2", "realm2", "id2", "forest2",
                                       NULL);
    assert_int_equal(ret, EOK);

    ret = sysdb_master_domain_update(test_ctx->tctx->dom);
    assert_int_equal(ret, EOK);

    assert_string_equal(test_ctx->tctx->dom->realm, "realm2");
    assert_string_equal(test_ctx->tctx->dom->flat_name, "flat2");
    assert_string_equal(test_ctx->tctx->dom->domain_id, "id2");
    assert_string_equal(test_ctx->tctx->dom->forest, "forest2");
}

/* Parent domain totally separate from subdomains that imitate
 * IPA domain and two forests
 */
static void test_sysdb_link_forest_root_ipa(void **state)
{
    errno_t ret;
    struct subdom_test_ctx *test_ctx =
        talloc_get_type(*state, struct subdom_test_ctx);
    struct sss_domain_info *main_dom;
    struct sss_domain_info *sub;
    struct sss_domain_info *child;

    /* name, realm, flat, SID, forest */
    const char *const dom1[5] = { "dom1.sub", "DOM1.SUB",
                                  "DOM1", "S-1", "DOM1.SUB" };
    const char *const child_dom1[5] = { "child1.dom1.sub", "CHILD1.DOM1.SUB",
                                        "CHILD1.DOM1", "S-1-2", "DOM1.SUB" };
    const char *const dom2[5] = { "dom2.sub", "DOM2.SUB",
                                  "DOM2", "S-2", "DOM2.SUB" };
    const char *const child_dom2[5] = { "child2.dom2.sub", "CHILD2.DOM1.SUB",
                                        "CHILD2.DOM1", "S-2-2", "DOM2.SUB" };

    ret = sysdb_subdomain_store(test_ctx->tctx->sysdb,
                                dom1[0], dom1[1], dom1[2], dom1[0], dom1[3],
                                MPG_DISABLED, false, dom1[4], 0, IPA_TRUST_UNKNOWN,
                                NULL);
    assert_int_equal(ret, EOK);

    ret = sysdb_subdomain_store(test_ctx->tctx->sysdb,
                                child_dom1[0], child_dom1[1],
                                child_dom1[2], child_dom1[0], child_dom1[3],
                                MPG_DISABLED, false, child_dom1[4],
                                0, IPA_TRUST_UNKNOWN, NULL);
    assert_int_equal(ret, EOK);

    ret = sysdb_subdomain_store(test_ctx->tctx->sysdb,
                                dom2[0], dom2[1], dom2[2], dom2[0], dom2[3],
                                MPG_DISABLED, false, dom2[4],
                                0, IPA_TRUST_UNKNOWN, NULL);
    assert_int_equal(ret, EOK);

    ret = sysdb_subdomain_store(test_ctx->tctx->sysdb,
                                child_dom2[0], child_dom2[1],
                                child_dom2[2], child_dom2[0], child_dom2[3],
                                MPG_DISABLED, false, child_dom2[4],
                                0, IPA_TRUST_UNKNOWN, NULL);
    assert_int_equal(ret, EOK);

    ret = sysdb_update_subdomains(test_ctx->tctx->dom, test_ctx->tctx->confdb);
    assert_int_equal(ret, EOK);

    /* Also update dom2 */
    ret = sysdb_update_subdomains(test_ctx->tctx->dom->next, test_ctx->tctx->confdb);
    assert_int_equal(ret, EOK);

    sub = find_domain_by_name(test_ctx->tctx->dom, dom1[0], true);
    assert_non_null(sub->forest_root);
    assert_ptr_equal(sub->forest_root, sub);

    child = find_domain_by_name(test_ctx->tctx->dom, child_dom1[0], true);
    assert_non_null(child->forest_root);
    assert_ptr_equal(child->forest_root, sub);

    sub = find_domain_by_name(test_ctx->tctx->dom, dom2[0], true);
    assert_non_null(sub->forest_root);
    assert_ptr_equal(sub->forest_root, sub);

    child = find_domain_by_name(test_ctx->tctx->dom, child_dom2[0], true);
    assert_non_null(child->forest_root);
    assert_ptr_equal(child->forest_root, sub);

    main_dom = find_domain_by_name(test_ctx->tctx->dom, TEST_DOM1_NAME, true);
    assert_non_null(main_dom);
    assert_non_null(main_dom->forest_root);
    assert_true(main_dom->forest_root == main_dom);

    main_dom = find_domain_by_name(test_ctx->tctx->dom, TEST_DOM2_NAME, true);
    assert_non_null(main_dom);
    assert_non_null(main_dom->forest_root);
    assert_true(main_dom->forest_root == main_dom);
}

/* Parent domain is an AD forest root and there are two subdomains
 * child and parallel
 */
static void test_sysdb_link_forest_root_ad(void **state)
{
    errno_t ret;
    struct subdom_test_ctx *test_ctx =
        talloc_get_type(*state, struct subdom_test_ctx);
    struct sss_domain_info *main_dom;
    struct sss_domain_info *sub;
    struct sss_domain_info *child;

    const char *const child_dom[5] = { "child.test_sysdb_subdomains",/* name  */
                                       "CHILD.TEST_SYSDB_SUBDOMAINS",/* realm */
                                       "CHILD",                      /* flat  */
                                       "S-1-2",                      /* sid   */
                                       TEST_FOREST };               /* forest */

    const char *const sub_dom[5] = { "another.subdomain",         /* name   */
                                     "ANOTHER.SUBDOMAIN",         /* realm  */
                                     "ANOTHER",                   /* flat   */
                                     "S-1-3",                     /* sid    */
                                     TEST_FOREST };               /* forest */

    ret = sysdb_master_domain_add_info(test_ctx->tctx->dom,
                                       TEST_REALM,
                                       TEST_FLAT_NAME,
                                       TEST_REALM,
                                       TEST_SID,
                                       TEST_FOREST,
                                       NULL);
    assert_int_equal(ret, EOK);

    ret = sysdb_subdomain_store(test_ctx->tctx->sysdb,
                                child_dom[0], child_dom[1],
                                child_dom[2], child_dom[0], child_dom[3],
                                MPG_DISABLED, false, child_dom[4],
                                0, IPA_TRUST_UNKNOWN, NULL);
    assert_int_equal(ret, EOK);

    ret = sysdb_subdomain_store(test_ctx->tctx->sysdb,
                                sub_dom[0], sub_dom[1],
                                sub_dom[2], sub_dom[0], sub_dom[3],
                                MPG_DISABLED, false, sub_dom[4],
                                0, IPA_TRUST_UNKNOWN, NULL);
    assert_int_equal(ret, EOK);

    ret = sysdb_update_subdomains(test_ctx->tctx->dom, test_ctx->tctx->confdb);
    assert_int_equal(ret, EOK);

    /* Also update dom2 */
    ret = sysdb_update_subdomains(test_ctx->tctx->dom->next, test_ctx->tctx->confdb);
    assert_int_equal(ret, EOK);

    assert_non_null(test_ctx->tctx->dom->forest_root);
    assert_true(test_ctx->tctx->dom->forest_root == test_ctx->tctx->dom);
    assert_string_equal(test_ctx->tctx->dom->name, TEST_DOM1_NAME);

    child = find_domain_by_name(test_ctx->tctx->dom, child_dom[0], true);
    assert_non_null(child->forest_root);
    assert_ptr_equal(child->forest_root, test_ctx->tctx->dom);

    sub = find_domain_by_name(test_ctx->tctx->dom, sub_dom[0], true);
    assert_non_null(sub->forest_root);
    assert_ptr_equal(sub->forest_root, test_ctx->tctx->dom);

    /* Another separate domain is a forest of its own */
    main_dom = find_domain_by_name(test_ctx->tctx->dom, TEST_DOM2_NAME, true);
    assert_non_null(main_dom);
    assert_non_null(main_dom->forest_root);
    assert_true(main_dom->forest_root == main_dom);
}

/* Parent domain is an AD member domain connected to a root domain
 */
static void test_sysdb_link_forest_member_ad(void **state)
{
    errno_t ret;
    struct subdom_test_ctx *test_ctx =
        talloc_get_type(*state, struct subdom_test_ctx);
    struct sss_domain_info *main_dom;
    struct sss_domain_info *sub;
    struct sss_domain_info *root;

    const char *const forest_root[5] = { test_ctx->tctx->dom->name, /* name  */
                                         TEST_FOREST,               /* realm */
                                         TEST_FLAT_NAME,            /* flat  */
                                         TEST_SID,                  /* sid   */
                                         TEST_FOREST };               /* forest */

    const char *const child_dom[5] = { "child.test_sysdb_subdomains",/* name  */
                                       "CHILD.TEST_SYSDB_SUBDOMAINS",/* realm */
                                       "CHILD",                      /* flat  */
                                       "S-1-2",                      /* sid   */
                                       TEST_FOREST };               /* forest */

    const char *const sub_dom[5] = { "another.subdomain",         /* name   */
                                     "ANOTHER.SUBDOMAIN",         /* realm  */
                                     "ANOTHER",                   /* flat   */
                                     "S-1-3",                     /* sid    */
                                     TEST_FOREST };               /* forest */

    ret = sysdb_master_domain_add_info(test_ctx->tctx->dom,
                                       child_dom[1],
                                       child_dom[2],
                                       child_dom[0],
                                       child_dom[3],
                                       TEST_FOREST,
                                       NULL);
    assert_int_equal(ret, EOK);

    ret = sysdb_subdomain_store(test_ctx->tctx->sysdb,
                                sub_dom[0], sub_dom[1],
                                sub_dom[2], sub_dom[0], sub_dom[3],
                                MPG_DISABLED, false, sub_dom[4],
                                0, IPA_TRUST_UNKNOWN, NULL);
    assert_int_equal(ret, EOK);

    ret = sysdb_subdomain_store(test_ctx->tctx->sysdb,
                                forest_root[0], forest_root[1],
                                forest_root[2], forest_root[0], forest_root[3],
                                MPG_DISABLED, false, forest_root[4],
                                0, IPA_TRUST_UNKNOWN, NULL);
    assert_int_equal(ret, EOK);

    ret = sysdb_master_domain_update(test_ctx->tctx->dom);
    assert_int_equal(ret, EOK);

    ret = sysdb_update_subdomains(test_ctx->tctx->dom, test_ctx->tctx->confdb);
    assert_int_equal(ret, EOK);

    /* Also update dom2 */
    ret = sysdb_master_domain_update(test_ctx->tctx->dom->next);
    assert_int_equal(ret, EOK);

    ret = sysdb_update_subdomains(test_ctx->tctx->dom->next,
                                  test_ctx->tctx->confdb);
    assert_int_equal(ret, EOK);

    /* Checks */
    root = find_domain_by_name(test_ctx->tctx->dom, forest_root[0], true);
    assert_non_null(root->forest_root);
    assert_ptr_equal(root->forest_root, root);

    assert_non_null(test_ctx->tctx->dom->forest_root);
    assert_true(test_ctx->tctx->dom->forest_root == root);

    sub = find_domain_by_name(test_ctx->tctx->dom, sub_dom[0], true);
    assert_non_null(sub->forest_root);
    assert_ptr_equal(sub->forest_root, root);

    /* Another separate domain is a forest of its own */
    main_dom = find_domain_by_name(test_ctx->tctx->dom, TEST_DOM2_NAME, true);
    assert_non_null(main_dom);
    assert_non_null(main_dom->forest_root);
    assert_true(main_dom->forest_root == main_dom);
}


/* Each parent domain has a subdomain. One parent domain is a root domain,
 * the other is not.
 */
static void test_sysdb_link_ad_multidom(void **state)
{
    errno_t ret;
    struct subdom_test_ctx *test_ctx =
        talloc_get_type(*state, struct subdom_test_ctx);
    struct sss_domain_info *main_dom1;
    struct sss_domain_info *main_dom2;
    struct sss_domain_info *root;

    const char *const child_dom[5] = { "child.test_sysdb_subdomains",/* name  */
                                       "CHILD.TEST_SYSDB_SUBDOMAINS",/* realm */
                                       "CHILD",                      /* flat  */
                                       "S-1-2",                      /* sid   */
                                       TEST_FOREST };               /* forest */

    const char *const dom2_forest_root[5] = \
                                  { "test_sysdb_subdomains_2", /* name  */
                                     TEST_FOREST2,             /* realm */
                                     "TEST2",                  /* flat  */
                                     TEST_SID2,                /* sid   */
                                     TEST_FOREST2 };           /* forest */


    main_dom1 = find_domain_by_name(test_ctx->tctx->dom, TEST_DOM1_NAME, true);
    main_dom2 = find_domain_by_name(test_ctx->tctx->dom, TEST_DOM2_NAME, true);

    ret = sysdb_master_domain_add_info(main_dom1,
                                       TEST_REALM,
                                       TEST_FLAT_NAME,
                                       TEST_REALM,
                                       TEST_SID,
                                       TEST_FOREST,
                                       NULL);
    assert_int_equal(ret, EOK);

    ret = sysdb_subdomain_store(main_dom1->sysdb,
                                child_dom[0], child_dom[1],
                                child_dom[2], child_dom[0], child_dom[3],
                                MPG_DISABLED, false, child_dom[4],
                                0, IPA_TRUST_UNKNOWN, NULL);
    assert_int_equal(ret, EOK);

    ret = sysdb_master_domain_update(main_dom1);
    assert_int_equal(ret, EOK);

    ret = sysdb_update_subdomains(main_dom1, NULL);
    assert_int_equal(ret, EOK);

    ret = sysdb_master_domain_add_info(main_dom2,
                                       TEST_REALM2,
                                       TEST_FLAT_NAME2,
                                       TEST_REALM2,
                                       TEST_SID2,
                                       TEST_FOREST2,
                                       NULL);
    assert_int_equal(ret, EOK);

    ret = sysdb_subdomain_store(main_dom2->sysdb,
                                dom2_forest_root[0], dom2_forest_root[1],
                                dom2_forest_root[2], dom2_forest_root[0], dom2_forest_root[3],
                                MPG_DISABLED, false, dom2_forest_root[4], 0, IPA_TRUST_UNKNOWN,
                                NULL);
    assert_int_equal(ret, EOK);

    ret = sysdb_master_domain_update(main_dom2);
    assert_int_equal(ret, EOK);

    ret = sysdb_update_subdomains(main_dom2, NULL);
    assert_int_equal(ret, EOK);

    main_dom1 = find_domain_by_name(test_ctx->tctx->dom, TEST_DOM1_NAME, true);
    assert_non_null(main_dom1);
    assert_non_null(main_dom1->forest_root);
    assert_true(main_dom1->forest_root == main_dom1);

    main_dom2 = find_domain_by_name(test_ctx->tctx->dom, TEST_DOM2_NAME, true);
    assert_non_null(main_dom1);
    assert_non_null(main_dom1->forest_root);
    assert_true(main_dom1->forest_root == main_dom1);

    root = find_domain_by_name(test_ctx->tctx->dom, dom2_forest_root[0], true);
    assert_non_null(root);
    assert_non_null(root->forest_root);
    assert_ptr_equal(root->forest_root, main_dom2);

}

static void test_sysdb_set_and_get_site(void **state)
{
    TALLOC_CTX *tmp_ctx;
    struct subdom_test_ctx *test_ctx =
        talloc_get_type(*state, struct subdom_test_ctx);
    const char *site;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);

    ret = sysdb_get_site(test_ctx, test_ctx->tctx->dom, &site);
    assert_int_equal(ret, EOK);
    assert_null(site);

    ret = sysdb_set_site(test_ctx->tctx->dom, "TestSite");
    assert_int_equal(ret, EOK);

    ret = sysdb_get_site(tmp_ctx, test_ctx->tctx->dom, &site);
    assert_int_equal(ret, EOK);
    assert_string_equal(site, "TestSite");

    talloc_free(tmp_ctx);
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
        cmocka_unit_test_setup_teardown(test_sysdb_master_domain_ops,
                                        test_sysdb_subdom_setup,
                                        test_sysdb_subdom_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_subdomain_create,
                                        test_sysdb_subdom_setup,
                                        test_sysdb_subdom_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_link_forest_root_ipa,
                                        test_sysdb_subdom_setup,
                                        test_sysdb_subdom_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_link_forest_root_ad,
                                        test_sysdb_subdom_setup,
                                        test_sysdb_subdom_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_link_forest_member_ad,
                                        test_sysdb_subdom_setup,
                                        test_sysdb_subdom_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_link_ad_multidom,
                                        test_sysdb_subdom_setup,
                                        test_sysdb_subdom_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_set_and_get_site,
                                        test_sysdb_subdom_setup,
                                        test_sysdb_subdom_teardown),
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

    tests_set_cwd();
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, NULL);
    test_dom_suite_setup(TESTS_PATH);
    rv = cmocka_run_group_tests(tests, NULL, NULL);

    if (rv == 0 && no_cleanup == 0) {
        test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, NULL);
    }
    return rv;
}
