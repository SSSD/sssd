/*
 SSSD

     NSS Responder

     Authors:
         Pallavi Jha <pallavikumarijha@gmail.com>

         Copyright (C) 2013 Red Hat

         This program is free software; you can redistribute it and/or modify
         it under the terms of the GNU General Public License as published by
         the Free Software Foundation; either version 3 of the License, or
         (at your option) any later version.

         This program is distributed in the hope that it will be useful,
         but WITHOUT ANY WARRANTY; without even the implied warranty of
         MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
         GNU General Public License for more details.
         You should have received a copy of the GNU General Public License
         along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdarg.h>
#include <stdlib.h>
#include <stddef.h>
#include <setjmp.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <inttypes.h>
#include <cmocka.h>

#include "tests/cmocka/common_mock.h"
#include "tests/cmocka/common_mock_resp.h"
#include "responder/nss/nsssrv.h"
#include "responder/nss/nsssrv_private.h"
#include "sss_client/idmap/sss_nss_idmap.h"
#include "util/util_sss_idmap.h"
#include "lib/idmap/sss_idmap.h"
#include "util/util.h"
#include "util/util_sss_idmap.h"
#include "responder/common/responder.h"
#include "responder/common/negcache.h"

#define PORT 21
#define SID "S-1-2-3-4-5"
#define PROTO "TCP"
#define LIFETIME 200
#define SHORTSPAN 1
#define NAME "foo_name"
#define TESTS_PATH "tests_ncache"
#define TEST_CONF_DB "test_nss_conf.ldb"
#define TEST_DOM_NAME "nss_test"
#define TEST_SYSDB_FILE "cache_"TEST_DOM_NAME".ldb"
#define TEST_ID_PROVIDER "ldap"

/* register_cli_protocol_version is required in test since it links with
 * responder_common.c module
 */
struct cli_protocol_version *register_cli_protocol_version(void)
{
    static struct cli_protocol_version responder_test_cli_protocol_version[] = {
        {0, NULL, NULL}
    };

    return responder_test_cli_protocol_version;
}

/* Mock NSS structure */
static struct nss_ctx *
mock_nctx(TALLOC_CTX *mem_ctx)
{
    struct nss_ctx *nctx;
    errno_t ret;
    enum idmap_error_code err;

    nctx = talloc_zero(mem_ctx, struct nss_ctx);
    if (!nctx) {
        return NULL;
    }

    ret = sss_ncache_init(nctx, &nctx->ncache);
    if (ret != EOK) {
        talloc_free(nctx);
        return NULL;
    }
    nctx->neg_timeout = 10;
    nctx->pwfield = discard_const("*");

    err = sss_idmap_init(sss_idmap_talloc, nctx, sss_idmap_talloc_free,
                         &nctx->idmap_ctx);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("sss_idmap_init failed.\n"));
        talloc_free(nctx);
        return NULL;
    }
    return nctx;
}

/* responder context is duplicated here because linking
 * with common_mock_resp.c would get us duplicates
 */

struct resp_ctx *
mock_rctx(TALLOC_CTX *mem_ctx,
          struct tevent_context *ev,
          struct sss_domain_info *domains,
          void *pvt_ctx)
{
    struct resp_ctx *rctx;
    errno_t ret;

    rctx = talloc_zero(mem_ctx, struct resp_ctx);
    if (!rctx) return NULL;

    ret = sss_hash_create(rctx, 30, &rctx->dp_request_table);
    if (ret != EOK) {
        talloc_free(rctx);
        return NULL;
    }

    rctx->ev = ev;
    rctx->domains = domains;
    rctx->pvt_ctx = pvt_ctx;
    return rctx;
}

struct test_state {
    struct sss_nc_ctx *ctx;
    struct nss_ctx *nctx;
    struct resp_ctx *rctx;
};

static void setup(void **state)
{
    int ret;
    struct test_state *ts;

    ts = talloc(NULL, struct test_state);
    assert_non_null(ts);

    ret  = sss_ncache_init(ts, &ts->ctx);
    assert_int_equal(ret, EOK);
    assert_non_null(ts->ctx);

    *state = (void *)ts;
}

static void teardown(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    talloc_free(ts);
}

static void test_sss_ncache_init(void **state)
{
    int ret;
    TALLOC_CTX *memctx;
    struct sss_nc_ctx *ctx;

    memctx = talloc_new(NULL);
    assert_non_null(memctx);

    ret = sss_ncache_init(memctx, &ctx );
    assert_int_equal(ret, EOK);
    assert_non_null(ctx);

    talloc_free(memctx);
}

/* @test_sss_ncache_uid : test following functions
 * sss_ncache_set_uid
 * sss_ncache_check_uid
 */
static void test_sss_ncache_uid(void **state)
{
    uid_t uid;
    int ret, ttl;
    bool permanent;
    struct test_state *ts;

    ttl = LIFETIME;
    uid = getuid();

    ts = talloc_get_type_abort(*state, struct test_state);

    /* test when uid not present in database */
    ret = sss_ncache_check_uid(ts->ctx, ttl, uid);
    assert_int_equal(ret, ENOENT);

    /* test when uid is present in database */
    permanent = true;

    ret = sss_ncache_reset_permanent(ts->ctx);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_set_uid(ts->ctx, permanent, uid);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_uid(ts->ctx, ttl, uid);
    assert_int_equal(ret, EEXIST);

    ttl = SHORTSPAN;
    ret = sss_ncache_set_uid(ts->ctx, permanent, uid);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_uid(ts->ctx, ttl, uid);
    assert_int_equal(ret, EEXIST);

    sleep(SHORTSPAN + 1);

    ret = sss_ncache_check_uid(ts->ctx, ttl, uid);
    assert_int_equal(ret, EEXIST);

    permanent = false;

    ret = sss_ncache_set_uid(ts->ctx, permanent, uid);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_uid(ts->ctx, ttl, uid);
    assert_int_equal(ret, EEXIST);

    sleep(SHORTSPAN + 1);

    ret = sss_ncache_check_uid(ts->ctx, ttl, uid);
    assert_int_equal(ret, ENOENT);

    ret = sss_ncache_set_uid(ts->ctx, permanent, uid);
    assert_int_equal(ret, EOK);

    /* test when ttl is -1 with uid present in database*/
    ttl = -1;
    ret = sss_ncache_check_uid(ts->ctx, ttl, uid);
    assert_int_equal(ret, EEXIST);
}

/* @test_sss_ncache_gid : test following functions
 * sss_ncache_set_gid
 * sss_ncache_check_gid
 */
static void test_sss_ncache_gid(void **state)
{
    gid_t gid;
    int ret, ttl;
    bool permanent;
    struct test_state *ts;

    ttl = LIFETIME;
    gid = getgid();
    ts = talloc_get_type_abort(*state, struct test_state);

    /* test when gid is not present in database */
    ret = sss_ncache_check_gid(ts->ctx, ttl, gid);
    assert_int_equal(ret, ENOENT);

    /* test when gid is present in database */
    permanent = true;
    ret = sss_ncache_set_gid(ts->ctx, permanent, gid);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_gid(ts->ctx, ttl, gid);
    assert_int_equal(ret, EEXIST);

    permanent = false;
    ret = sss_ncache_set_uid(ts->ctx, permanent, gid);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_uid(ts->ctx, ttl, gid);
    assert_int_equal(ret, EEXIST);

    /* test when ttl is -1 with gid present in database*/
    ttl = -1;
    ret = sss_ncache_check_gid(ts->ctx, ttl, gid);
    assert_int_equal(ret, EEXIST);
}


/* @test_sss_ncache_sid : test following functions
 * sss_ncache_set_sid
 * sss_ncache_check_sid
 */
static void test_sss_ncache_sid(void **state)
{
    int ret, ttl;
    bool permanent;
    const char *sid = NULL;
    struct test_state *ts;

    ttl = LIFETIME;
    sid = SID;
    ts = talloc_get_type_abort(*state, struct test_state);

    /*test when sid in not present in database */
    ret = sss_ncache_check_sid(ts->ctx, ttl, sid);
    assert_int_equal(ret, ENOENT);

    /* test when sid is present in database */
    permanent = true;
    ret = sss_ncache_set_sid(ts->ctx, permanent, sid);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_sid(ts->ctx, ttl, sid);
    assert_int_equal(ret, EEXIST);

    permanent = false;
    ret = sss_ncache_set_sid(ts->ctx, permanent, sid);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_sid(ts->ctx, ttl, sid);
    assert_int_equal(ret, EEXIST);

    /* test when ttl is -1 with sid present in database*/
    ttl = -1;
    ret = sss_ncache_check_sid(ts->ctx, ttl, sid);
    assert_int_equal(ret, EEXIST);
}

/* @test_sss_ncache_user : test following functions
 * sss_ncache_check_user
 * sss_ncache_set_user
 */
static void test_sss_ncache_user(void **state)
{
    int ret, ttl;
    bool permanent;
    const char *name = NAME;
    struct test_state *ts;
    struct sss_domain_info *dom;

    ttl = LIFETIME;
    ts = talloc_get_type_abort(*state, struct test_state);
    dom = talloc(ts, struct sss_domain_info);
    dom->name = discard_const_p(char, TEST_DOM_NAME);

    /* test when domain name is not present in database */
    dom->case_sensitive = false;
    ret = sss_ncache_check_user(ts->ctx, ttl, dom, name);
    assert_int_equal(ret, ENOENT);

    dom->case_sensitive = true;
    ret = sss_ncache_check_user(ts->ctx, ttl, dom, name);
    assert_int_equal(ret, ENOENT);

    /* test when domain name is present in database */
    permanent = true;
    ret = sss_ncache_set_user(ts->ctx, permanent, dom, name);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_user(ts->ctx, ttl, dom, name);
    assert_int_equal(ret, EEXIST);

    permanent = false;
    ret = sss_ncache_set_user(ts->ctx, permanent, dom, name);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_user(ts->ctx, ttl, dom, name);
    assert_int_equal(ret, EEXIST);

    /* test when ttl is -1 with domain name present in database */
    ttl = -1;
    ret = sss_ncache_check_user(ts->ctx, ttl, dom, name);
    assert_int_equal(ret, EEXIST);
}

/* @test_sss_ncache_group : test following functions
 * sss_ncache_check_group
 * sss_ncache_set_group
 */
static void test_sss_ncache_group(void **state)
{
    int ret, ttl;
    bool permanent;
    const char *name = NAME;
    struct test_state *ts;
    struct sss_domain_info *dom;

    ttl = LIFETIME;
    ts = talloc_get_type_abort(*state, struct test_state);
    dom = talloc(ts, struct sss_domain_info);
    dom->name = discard_const_p(char, TEST_DOM_NAME);

    /* test when domain name is not present in database */
    dom->case_sensitive = false;
    ret = sss_ncache_check_group(ts->ctx, ttl, dom, name);
    assert_int_equal(ret, ENOENT);

    dom->case_sensitive = true;
    ret = sss_ncache_check_group(ts->ctx, ttl, dom, name);
    assert_int_equal(ret, ENOENT);

    /* test when domain name is present in database */
    permanent = true;
    ret = sss_ncache_set_group(ts->ctx, permanent, dom, name);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_group(ts->ctx, ttl, dom, name);
    assert_int_equal(ret, EEXIST);

    permanent = false;
    ret = sss_ncache_set_group(ts->ctx, permanent, dom, name);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_group(ts->ctx, ttl, dom, name);
    assert_int_equal(ret, EEXIST);

    /* test when ttl is -1 with domain name present in database */
    ttl = -1;
    ret = sss_ncache_check_group(ts->ctx, ttl, dom, name);
    assert_int_equal(ret, EEXIST);
}

/* @test_sss_ncache_netgr : test following functions
 * sss_ncache_check_netgr
 * sss_ncache_set_netgr
 */
static void test_sss_ncache_netgr(void **state)
{
    int ret, ttl;
    bool permanent;
    const char *name = NAME;
    struct test_state *ts;
    struct sss_domain_info *dom;

    ttl = LIFETIME;
    ts = talloc_get_type_abort(*state, struct test_state);
    dom = talloc(ts, struct sss_domain_info);
    dom->name = discard_const_p(char, TEST_DOM_NAME);

    /* test when domain name is not present in database */
    dom->case_sensitive = false;
    ret = sss_ncache_check_netgr(ts->ctx, ttl, dom, name);
    assert_int_equal(ret, ENOENT);

    dom->case_sensitive = true;
    ret = sss_ncache_check_netgr(ts->ctx, ttl, dom, name);
    assert_int_equal(ret, ENOENT);

    /* test when domain name is present in database */
    permanent = true;
    ret = sss_ncache_set_netgr(ts->ctx, permanent, dom, name);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_netgr(ts->ctx, ttl, dom, name);
    assert_int_equal(ret, EEXIST);

    permanent = false;
    ret = sss_ncache_set_netgr(ts->ctx, permanent, dom, name);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_netgr(ts->ctx, ttl, dom, name);
    assert_int_equal(ret, EEXIST);

    /* test when ttl is -1 with domain name present in database */
    ttl = -1;
    ret = sss_ncache_check_netgr(ts->ctx, ttl, dom, name);
    assert_int_equal(ret, EEXIST);
}

/* @test_sss_ncache_service_name : test following functions
 * sss_ncache_check_service
 * sss_ncache_set_service_name
 */
static void test_sss_ncache_service_name(void **state)
{
    int ret, ttl;
    bool permanent;
    const char *name = NAME;
    struct test_state *ts;
    struct sss_domain_info *dom;

    ttl = LIFETIME;
    ts = talloc_get_type_abort(*state, struct test_state);
    dom = talloc(ts, struct sss_domain_info);
    dom->name = discard_const_p(char, TEST_DOM_NAME);

    /* test when domain name and protocol are not present in database */
    dom->case_sensitive = false;
    ret = sss_ncache_check_service(ts->ctx, ttl, dom, name, PROTO);
    assert_int_equal(ret, ENOENT);

    dom->case_sensitive = true;
    ret = sss_ncache_check_service(ts->ctx, ttl, dom, name, PROTO);
    assert_int_equal(ret, ENOENT);

    /* test when domain name and protocol are present in database */
    permanent = true;
    ret = sss_ncache_set_service_name(ts->ctx, permanent, dom, name, PROTO);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_service(ts->ctx, ttl, dom, name, PROTO);
    assert_int_equal(ret, EEXIST);

    permanent = false;
    ret = sss_ncache_set_service_name(ts->ctx, permanent, dom, name, PROTO);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_service(ts->ctx, ttl, dom, name, PROTO);
    assert_int_equal(ret, EEXIST);

    /* test when ttl is -1 with domain name present in database */
    ttl = -1;
    ret = sss_ncache_check_service(ts->ctx, ttl, dom, name, PROTO);
    assert_int_equal(ret, EEXIST);
}

/* @test_sss_ncache_service_port : test following functions
 * sss_ncache_check_service_port
 * sss_ncache_set_service_port
 */
static void test_sss_ncache_service_port(void **state)
{
    int ret, ttl;
    bool permanent;
    struct test_state *ts;
    struct sss_domain_info *dom;

    ttl = LIFETIME;
    ts = talloc_get_type_abort(*state, struct test_state);
    dom = talloc(ts, struct sss_domain_info);
    dom->name = discard_const_p(char, TEST_DOM_NAME);

    /* test when domain name, port and protocol are not present in database */
    dom->case_sensitive = false;
    ret = sss_ncache_check_service_port(ts->ctx, ttl, dom, (uint16_t)PORT,
                                        PROTO);
    assert_int_equal(ret, ENOENT);

    dom->case_sensitive = true;
    ret = sss_ncache_check_service_port(ts->ctx, ttl, dom, (uint16_t)PORT,
                                        PROTO);
    assert_int_equal(ret, ENOENT);

    /* test when domain name, port and protocol are present in database */
    permanent = true;
    ret = sss_ncache_set_service_port(ts->ctx, permanent, dom, (uint16_t)PORT,
                                      PROTO);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_service_port(ts->ctx, ttl, dom, (uint16_t)PORT,
                                        PROTO);
    assert_int_equal(ret, EEXIST);

    permanent = false;
    ret = sss_ncache_set_service_port(ts->ctx, permanent, dom, (uint16_t)PORT,
                                      PROTO);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_service_port(ts->ctx, ttl, dom, (uint16_t)PORT,
                                        PROTO);
    assert_int_equal(ret, EEXIST);

    /* test when ttl is -1 with domain name present in database */
    ttl = -1;
    ret = sss_ncache_check_service_port(ts->ctx, ttl, dom, (uint16_t)PORT,
                                        PROTO);
    assert_int_equal(ret, EEXIST);
}


static void test_sss_ncache_reset_permanent(void **state)
{
    int ret;
    struct test_state *ts;

    ts = talloc_get_type_abort(*state, struct test_state);
    ret = sss_ncache_reset_permanent(ts->ctx);
    assert_int_equal(ret, EOK);
}

static void test_sss_ncache_prepopulate(void **state)
{
    int ret;
    struct test_state *ts;
    struct tevent_context *ev;
    struct sss_nc_ctx *ncache;
    struct sss_test_ctx *tc;
    struct sss_domain_info *dom;

    struct sss_test_conf_param params[] = {
        { "filter_users", "testuser1" },
        { "filter_groups", "testgroup1" },
        { NULL, NULL },
    };

    ts = talloc_get_type_abort(*state, struct test_state);

    ev = tevent_context_init(ts);
    assert_non_null(ev);

    dom = talloc_zero(ts, struct sss_domain_info);
    assert_non_null(dom);
    dom->name = discard_const_p(char, TEST_DOM_NAME);

    ts->nctx = mock_nctx(ts);
    assert_non_null(ts->nctx);

    tc = create_dom_test_ctx(ts, TESTS_PATH, TEST_CONF_DB,
                             TEST_DOM_NAME, TEST_ID_PROVIDER, params);
    assert_non_null(tc);

    ncache = ts->ctx;
    ts->rctx = mock_rctx(ts, ev, dom, ts->nctx);
    assert_non_null(ts->rctx);

    ret = sss_names_init(ts, tc->confdb, TEST_DOM_NAME, &dom->names);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_prepopulate(ncache, tc->confdb, ts->rctx);
    assert_int_equal(ret, EOK);

    sleep(SHORTSPAN);

    ret = sss_ncache_check_user(ncache, 1, dom, "testuser1");
    assert_int_equal(ret, EEXIST);

    ret = sss_ncache_check_group(ncache, 1, dom, "testgroup1");
    assert_int_equal(ret, EEXIST);
}

int main(void)
{
    int rv;
    const UnitTest tests[] = {
        unit_test(test_sss_ncache_init),
        unit_test_setup_teardown(test_sss_ncache_uid, setup, teardown),
        unit_test_setup_teardown(test_sss_ncache_gid, setup, teardown),
        unit_test_setup_teardown(test_sss_ncache_sid, setup, teardown),
        unit_test_setup_teardown(test_sss_ncache_user, setup, teardown),
        unit_test_setup_teardown(test_sss_ncache_group, setup, teardown),
        unit_test_setup_teardown(test_sss_ncache_netgr, setup, teardown),
        unit_test_setup_teardown(test_sss_ncache_service_name, setup,
                                 teardown),
        unit_test_setup_teardown(test_sss_ncache_service_port, setup,
                                  teardown),
        unit_test_setup_teardown(test_sss_ncache_reset_permanent, setup,
                                  teardown),
        unit_test_setup_teardown(test_sss_ncache_prepopulate, setup, teardown)
    };

    tests_set_cwd();
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_SYSDB_FILE);
    test_dom_suite_setup(TESTS_PATH);

    rv = run_tests(tests);
    if (rv == 0) {
        test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_SYSDB_FILE);
    }
    return rv;
}
