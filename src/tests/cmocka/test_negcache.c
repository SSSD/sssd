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
#include "responder/nss/nss_private.h"
#include "sss_client/idmap/sss_nss_idmap.h"
#include "util/util_sss_idmap.h"
#include "lib/idmap/sss_idmap.h"
#include "util/util.h"
#include "responder/common/responder.h"
#include "responder/common/negcache.h"
#include "providers/ipa/ipa_subdomains.h"

int test_ncache_setup(void **state);
int test_ncache_teardown(void **state);
void test_ncache_nocache_user(void **state);
void test_ncache_local_user(void **state);
void test_ncache_domain_user(void **state);
void test_ncache_both_user(void **state);
void test_ncache_nocache_uid(void **state);
void test_ncache_local_uid(void **state);
void test_ncache_domain_uid(void **state);
void test_ncache_both_uid(void **state);
void test_ncache_nocache_group(void **state);
void test_ncache_local_group(void **state);
void test_ncache_domain_group(void **state);
void test_ncache_both_group(void **state);
void test_ncache_nocache_gid(void **state);
void test_ncache_local_gid(void **state);
void test_ncache_domain_gid(void **state);
void test_ncache_both_gid(void **state);

#define PORT 21
#define SID "S-1-2-3-4-5"
#define CERT "MIIECTCCAvGgAwIBAgIBCTANBgkqhkiG9w0BAQsFADA0MRIwEAYDVQQKDAlJUEEuREVWRUwxHjAcBgNVBAMMFUNlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0xNTA0MjgxMDIxMTFaFw0xNzA0MjgxMDIxMTFaMDIxEjAQBgNVBAoMCUlQQS5ERVZFTDEcMBoGA1UEAwwTaXBhLWRldmVsLmlwYS5kZXZlbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALIykqtHuAwTVEofHikG/9BQy/dfeZFlsTkBg2qtnnc78w3XufbcnkpJp9Bmcsy/d9beqf5nlsxJ8TcjLsRQ9Ou6YtQjTfM3OILuOz8s0ICbF6qb66bd9hX/BrLO/9+KnpWFSR+E/YEmzgYyDTbKfBWBaGuPPrOi/K6vwkRYFZVA/FYZkYDtQhFmBO884HYzS4P6frRH3PvtRqWNCmaHpe97dGKsvnM2ybT+IMSB8/54GajQr3+BciRh2XaT4wvSTxkXM1fUgrDxqAP2AZmpuIyDyboZh+rWOwbrTPfx5SipELZG3uHhP8HMcr4qQ8b20LWgxCRuT73sIooHET350xUCAwEAAaOCASYwggEiMB8GA1UdIwQYMBaAFPKdQk4PxEglWC8czg+hPyLIVciRMDsGCCsGAQUFBwEBBC8wLTArBggrBgEFBQcwAYYfaHR0cDovL2lwYS1jYS5pcGEuZGV2ZWwvY2Evb2NzcDAOBgNVHQ8BAf8EBAMCBPAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMHQGA1UdHwRtMGswaaAxoC+GLWh0dHA6Ly9pcGEtY2EuaXBhLmRldmVsL2lwYS9jcmwvTWFzdGVyQ1JMLmJpbqI0pDIwMDEOMAwGA1UECgwFaXBhY2ExHjAcBgNVBAMMFUNlcnRpZmljYXRlIEF1dGhvcml0eTAdBgNVHQ4EFgQULSs/y/Wy/zIsqMIc3b2MgB7dMYIwDQYJKoZIhvcNAQELBQADggEBAJpHLlCnTR1TD8lxQgzl2n1JZOeryN/fAsGH0Vve2m8r5PC+ugnfAoULiuabBn1pOGxy/0x7Kg0/Iy8WRv8Fk7DqJCjXEqFXuFkZJfNDCtP9DzeNuMoV50iKoMfHS38BPFjXN+X/fSsBrA2fUWrlQCTmXlUN97gvQqxt5Slrxgukvxm9OSfu/sWz22LUvtJHupYwWv1iALgnXS86lAuVNYVALLxn34r58XsZlj5CSBMjBJWpaxEzgUdag3L2IPqOQXuPd0d8x11G9E/9gQquOSe2aiZjsdO/VYOCmzZsM2QPUMBVlBPDhfTVcWXQwN385uycW/ARtSzzSME2jKKWSIQ="
#define PROTO "TCP"
#define SHORTSPAN 1
#define NAME "foo_name"
#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_DB "test_nss_conf.ldb"
#define TEST_DOM_NAME "nss_test"
#define TEST_ID_PROVIDER "ldap"
#define TEST_SUBDOM_NAME "test.subdomain"

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
static struct sss_nss_ctx *
mock_nctx(TALLOC_CTX *mem_ctx)
{
    struct sss_nss_ctx *nctx;
    enum idmap_error_code err;

    nctx = talloc_zero(mem_ctx, struct sss_nss_ctx);
    if (!nctx) {
        return NULL;
    }

    nctx->pwfield = discard_const("*");

    err = sss_idmap_init(sss_idmap_talloc, nctx, sss_idmap_talloc_free,
                         &nctx->idmap_ctx);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_FATAL_FAILURE, "sss_idmap_init failed.\n");
        talloc_free(nctx);
        return NULL;
    }
    return nctx;
}

struct test_state {
    struct sss_nc_ctx *ctx;
    struct sss_nss_ctx *nctx;
    struct resp_ctx *rctx;
};

static int setup(void **state)
{
    int ret;
    struct test_state *ts;

    test_dom_suite_setup(TESTS_PATH);

    ts = talloc(NULL, struct test_state);
    assert_non_null(ts);

    ret = sss_ncache_init(ts, SHORTSPAN, 0, &ts->ctx);
    assert_int_equal(ret, EOK);
    assert_non_null(ts->ctx);

    *state = (void *)ts;
    return 0;
}

static int teardown(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);
    talloc_free(ts);
    return 0;
}

static void test_sss_ncache_init(void **state)
{
    int ret;
    TALLOC_CTX *memctx;
    struct sss_nc_ctx *ctx;

    memctx = talloc_new(NULL);
    assert_non_null(memctx);

    ret = sss_ncache_init(memctx, SHORTSPAN, 0, &ctx);
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
    int ret;
    bool permanent;
    struct test_state *ts;

    uid = getuid();

    ts = talloc_get_type_abort(*state, struct test_state);

    /* test when uid not present in database */
    ret = sss_ncache_check_uid(ts->ctx, NULL, uid);
    assert_int_equal(ret, ENOENT);

    /* test when uid is present in database */
    permanent = true;

    ret = sss_ncache_reset_permanent(ts->ctx);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_set_uid(ts->ctx, permanent, NULL, uid);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_uid(ts->ctx, NULL, uid);
    assert_int_equal(ret, EEXIST);

    ret = sss_ncache_set_uid(ts->ctx, permanent, NULL, uid);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_uid(ts->ctx, NULL, uid);
    assert_int_equal(ret, EEXIST);

    sleep(SHORTSPAN + 1);

    ret = sss_ncache_check_uid(ts->ctx, NULL, uid);
    assert_int_equal(ret, EEXIST);

    permanent = false;

    ret = sss_ncache_set_uid(ts->ctx, permanent, NULL, uid);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_uid(ts->ctx, NULL, uid);
    assert_int_equal(ret, EEXIST);

    sleep(SHORTSPAN + 1);

    ret = sss_ncache_check_uid(ts->ctx, NULL, uid);
    assert_int_equal(ret, ENOENT);

    ret = sss_ncache_set_uid(ts->ctx, permanent, NULL, uid);
    assert_int_equal(ret, EOK);
}

/* @test_sss_ncache_gid : test following functions
 * sss_ncache_set_gid
 * sss_ncache_check_gid
 */
static void test_sss_ncache_gid(void **state)
{
    gid_t gid;
    int ret;
    bool permanent;
    struct test_state *ts;

    gid = getgid();
    ts = talloc_get_type_abort(*state, struct test_state);

    /* test when gid is not present in database */
    ret = sss_ncache_check_gid(ts->ctx, NULL, gid);
    assert_int_equal(ret, ENOENT);

    /* test when gid is present in database */
    permanent = true;
    ret = sss_ncache_set_gid(ts->ctx, permanent, NULL, gid);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_gid(ts->ctx, NULL, gid);
    assert_int_equal(ret, EEXIST);

    permanent = false;
    ret = sss_ncache_set_gid(ts->ctx, permanent, NULL, gid);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_gid(ts->ctx, NULL, gid);
    assert_int_equal(ret, EEXIST);
}


/* @test_sss_ncache_sid : test following functions
 * sss_ncache_set_sid
 * sss_ncache_check_sid
 */
static void test_sss_ncache_sid(void **state)
{
    int ret;
    bool permanent;
    const char *sid = NULL;
    struct test_state *ts;

    sid = SID;
    ts = talloc_get_type_abort(*state, struct test_state);

    /*test when sid in not present in database */
    ret = sss_ncache_check_sid(ts->ctx, NULL, sid);
    assert_int_equal(ret, ENOENT);

    /* test when sid is present in database */
    permanent = true;
    ret = sss_ncache_set_sid(ts->ctx, permanent, NULL, sid);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_sid(ts->ctx, NULL, sid);
    assert_int_equal(ret, EEXIST);

    permanent = false;
    ret = sss_ncache_set_sid(ts->ctx, permanent, NULL, sid);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_sid(ts->ctx, NULL, sid);
    assert_int_equal(ret, EEXIST);
}

/* @test_sss_ncache_cert : test following functions
 * sss_ncache_set_cert
 * sss_ncache_check_cert_
 */
static void test_sss_ncache_cert(void **state)
{
    int ret;
    bool permanent;
    const char *cert = NULL;
    struct test_state *ts;

    cert = CERT;
    ts = talloc_get_type_abort(*state, struct test_state);

    /*test when cert in not present in database */
    ret = sss_ncache_check_cert(ts->ctx, cert);
    assert_int_equal(ret, ENOENT);

    /* test when cert is present in database */
    permanent = true;
    ret = sss_ncache_set_cert(ts->ctx, permanent, cert);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_cert(ts->ctx, cert);
    assert_int_equal(ret, EEXIST);

    permanent = false;
    ret = sss_ncache_set_cert(ts->ctx, permanent, cert);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_cert(ts->ctx, cert);
    assert_int_equal(ret, EEXIST);
}

/* @test_sss_ncache_user : test following functions
 * sss_ncache_check_user
 * sss_ncache_set_user
 */
static void test_sss_ncache_user(void **state)
{
    int ret;
    bool permanent;
    char *name;
    struct test_state *ts;
    struct sss_domain_info *dom;

    ts = talloc_get_type_abort(*state, struct test_state);
    dom = talloc(ts, struct sss_domain_info);
    dom->name = discard_const_p(char, TEST_DOM_NAME);

    name = sss_create_internal_fqname(ts, NAME, dom->name);
    assert_non_null(name);

    /* test when domain name is not present in database */
    dom->case_sensitive = false;
    ret = sss_ncache_check_user(ts->ctx, dom, name);
    assert_int_equal(ret, ENOENT);

    dom->case_sensitive = true;
    ret = sss_ncache_check_user(ts->ctx, dom, name);
    assert_int_equal(ret, ENOENT);

    /* test when domain name is present in database */
    permanent = true;
    ret = sss_ncache_set_user(ts->ctx, permanent, dom, name);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_user(ts->ctx, dom, name);
    assert_int_equal(ret, EEXIST);

    permanent = false;
    ret = sss_ncache_set_user(ts->ctx, permanent, dom, name);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_user(ts->ctx, dom, name);
    assert_int_equal(ret, EEXIST);

    talloc_free(name);
}

/* @test_sss_ncache_group : test following functions
 * sss_ncache_check_group
 * sss_ncache_set_group
 */
static void test_sss_ncache_group(void **state)
{
    int ret;
    bool permanent;
    char *name;
    struct test_state *ts;
    struct sss_domain_info *dom;

    ts = talloc_get_type_abort(*state, struct test_state);
    dom = talloc(ts, struct sss_domain_info);
    dom->name = discard_const_p(char, TEST_DOM_NAME);

    name = sss_create_internal_fqname(ts, NAME, dom->name);
    assert_non_null(name);

    /* test when domain name is not present in database */
    dom->case_sensitive = false;
    ret = sss_ncache_check_group(ts->ctx, dom, name);
    assert_int_equal(ret, ENOENT);

    dom->case_sensitive = true;
    ret = sss_ncache_check_group(ts->ctx, dom, name);
    assert_int_equal(ret, ENOENT);

    /* test when domain name is present in database */
    permanent = true;
    ret = sss_ncache_set_group(ts->ctx, permanent, dom, name);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_group(ts->ctx, dom, name);
    assert_int_equal(ret, EEXIST);

    permanent = false;
    ret = sss_ncache_set_group(ts->ctx, permanent, dom, name);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_group(ts->ctx, dom, name);
    assert_int_equal(ret, EEXIST);

    talloc_free(name);
}

/* @test_sss_ncache_netgr : test following functions
 * sss_ncache_check_netgr
 * sss_ncache_set_netgr
 */
static void test_sss_ncache_netgr(void **state)
{
    int ret;
    bool permanent;
    const char *name = NAME;
    struct test_state *ts;
    struct sss_domain_info *dom;

    ts = talloc_get_type_abort(*state, struct test_state);
    dom = talloc(ts, struct sss_domain_info);
    dom->name = discard_const_p(char, TEST_DOM_NAME);

    /* test when domain name is not present in database */
    dom->case_sensitive = false;
    ret = sss_ncache_check_netgr(ts->ctx, dom, name);
    assert_int_equal(ret, ENOENT);

    dom->case_sensitive = true;
    ret = sss_ncache_check_netgr(ts->ctx, dom, name);
    assert_int_equal(ret, ENOENT);

    /* test when domain name is present in database */
    permanent = true;
    ret = sss_ncache_set_netgr(ts->ctx, permanent, dom, name);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_netgr(ts->ctx, dom, name);
    assert_int_equal(ret, EEXIST);

    permanent = false;
    ret = sss_ncache_set_netgr(ts->ctx, permanent, dom, name);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_netgr(ts->ctx, dom, name);
    assert_int_equal(ret, EEXIST);
}

/* @test_sss_ncache_service_name : test following functions
 * sss_ncache_check_service
 * sss_ncache_set_service_name
 */
static void test_sss_ncache_service_name(void **state)
{
    int ret;
    bool permanent;
    const char *name = NAME;
    struct test_state *ts;
    struct sss_domain_info *dom;

    ts = talloc_get_type_abort(*state, struct test_state);
    dom = talloc(ts, struct sss_domain_info);
    dom->name = discard_const_p(char, TEST_DOM_NAME);

    /* test when domain name and protocol are not present in database */
    dom->case_sensitive = false;
    ret = sss_ncache_check_service(ts->ctx, dom, name, PROTO);
    assert_int_equal(ret, ENOENT);

    dom->case_sensitive = true;
    ret = sss_ncache_check_service(ts->ctx, dom, name, PROTO);
    assert_int_equal(ret, ENOENT);

    /* test when domain name and protocol are present in database */
    permanent = true;
    ret = sss_ncache_set_service_name(ts->ctx, permanent, dom, name, PROTO);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_service(ts->ctx, dom, name, PROTO);
    assert_int_equal(ret, EEXIST);

    permanent = false;
    ret = sss_ncache_set_service_name(ts->ctx, permanent, dom, name, PROTO);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_service(ts->ctx, dom, name, PROTO);
    assert_int_equal(ret, EEXIST);
}

/* @test_sss_ncache_service_port : test following functions
 * sss_ncache_check_service_port
 * sss_ncache_set_service_port
 */
static void test_sss_ncache_service_port(void **state)
{
    int ret;
    bool permanent;
    struct test_state *ts;
    struct sss_domain_info *dom;

    ts = talloc_get_type_abort(*state, struct test_state);
    dom = talloc(ts, struct sss_domain_info);
    dom->name = discard_const_p(char, TEST_DOM_NAME);

    /* test when domain name, port and protocol are not present in database */
    dom->case_sensitive = false;
    ret = sss_ncache_check_service_port(ts->ctx, dom, (uint16_t)PORT,
                                        PROTO);
    assert_int_equal(ret, ENOENT);

    dom->case_sensitive = true;
    ret = sss_ncache_check_service_port(ts->ctx, dom, (uint16_t)PORT,
                                        PROTO);
    assert_int_equal(ret, ENOENT);

    /* test when domain name, port and protocol are present in database */
    permanent = true;
    ret = sss_ncache_set_service_port(ts->ctx, permanent, dom, (uint16_t)PORT,
                                      PROTO);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_service_port(ts->ctx, dom, (uint16_t)PORT,
                                        PROTO);
    assert_int_equal(ret, EEXIST);

    permanent = false;
    ret = sss_ncache_set_service_port(ts->ctx, permanent, dom, (uint16_t)PORT,
                                      PROTO);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_service_port(ts->ctx, dom, (uint16_t)PORT,
                                        PROTO);
    assert_int_equal(ret, EEXIST);
}


static void test_sss_ncache_reset_permanent(void **state)
{
    int ret;
    struct test_state *ts;
    const bool permanent = true;

    ts = talloc_get_type_abort(*state, struct test_state);

    ret = sss_ncache_set_uid(ts->ctx, permanent, NULL, 0);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_uid(ts->ctx, NULL, 0);
    assert_int_equal(ret, EEXIST);

    ret = sss_ncache_reset_permanent(ts->ctx);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_uid(ts->ctx, NULL, 0);
    assert_int_equal(ret, ENOENT);
}

static int check_user_in_ncache(struct sss_nc_ctx *ctx,
                                struct sss_domain_info *dom,
                                const char *name)
{
    char *fqdn;
    int ret;

    fqdn = sss_create_internal_fqname(ctx, name, dom->name);
    ret = sss_ncache_check_user(ctx, dom, fqdn);
    talloc_free(fqdn);
    return ret;
}

static int check_group_in_ncache(struct sss_nc_ctx *ctx,
                                 struct sss_domain_info *dom,
                                 const char *name)
{
    char *fqdn;
    int ret;

    fqdn = sss_create_internal_fqname(ctx, name, dom->name);
    ret = sss_ncache_check_group(ctx, dom, fqdn);
    talloc_free(fqdn);
    return ret;
}

static int check_uid_in_ncache(struct sss_nc_ctx *ctx,
                               uid_t uid)
{
    int ret;

    ret = sss_ncache_check_uid(ctx, NULL, uid);
    return ret;
}

static int check_gid_in_ncache(struct sss_nc_ctx *ctx,
                               gid_t gid)
{
    int ret;

    ret = sss_ncache_check_gid(ctx, NULL, gid);
    return ret;
}

static int add_confdb_params(struct sss_test_conf_param params[],
                             struct confdb_ctx *cdb, const char *section)
{
    const char *val[2];
    int ret;

    val[1] = NULL;

    for (int i = 0; params[i].key; i++) {
        val[0] = params[i].value;
        ret = confdb_add_param(cdb, true, section, params[i].key, val);
        assert_int_equal(ret, EOK);
    }

    return EOK;
}

static int add_nss_params(struct sss_test_conf_param nss_params[],
                          struct confdb_ctx *cdb)
{
    return add_confdb_params(nss_params, cdb, CONFDB_NSS_CONF_ENTRY);
}

static void test_sss_ncache_prepopulate(void **state)
{
    int ret;
    struct test_state *ts;
    struct tevent_context *ev;
    struct sss_nc_ctx *ncache;
    struct sss_test_ctx *tc;
    const char *const testdom[4] = { TEST_SUBDOM_NAME, "TEST.SUB", "test", "S-3" };
    struct sss_domain_info *subdomain;

    struct sss_test_conf_param nss_params[] = {
        { "filter_users", "testuser_nss@UPN.REALM, testuser_nss_short, all_dom_upn@"TEST_DOM_NAME },
        { NULL, NULL },
    };
    struct sss_test_conf_param dom_params[] = {
        { "filter_users", "testuser1, testuser2@"TEST_DOM_NAME", testuser3@somedomain" },
        { "filter_groups", "testgroup1, testgroup2@"TEST_DOM_NAME", testgroup3@somedomain" },
        { NULL, NULL },
    };

    ts = talloc_get_type_abort(*state, struct test_state);

    ev = tevent_context_init(ts);
    assert_non_null(ev);

    ts->nctx = mock_nctx(ts);
    assert_non_null(ts->nctx);

    tc = create_dom_test_ctx(ts, TESTS_PATH, TEST_CONF_DB,
                             TEST_DOM_NAME, TEST_ID_PROVIDER, dom_params);
    assert_non_null(tc);

    ret = add_nss_params(nss_params, tc->confdb);
    assert_int_equal(ret, EOK);

    subdomain = new_subdomain(tc, tc->dom,
                              testdom[0], testdom[1], testdom[2], testdom[0],
                              testdom[3], false, false, NULL, NULL, 0,
                              IPA_TRUST_UNKNOWN, tc->confdb, true);
    assert_non_null(subdomain);

    ret = sysdb_subdomain_store(tc->sysdb,
                                testdom[0], testdom[1], testdom[2], testdom[0],
                                testdom[3], false, false, NULL, 0,
                                IPA_TRUST_UNKNOWN, NULL);
    assert_int_equal(ret, EOK);

    ret = sysdb_update_subdomains(tc->dom, tc->confdb);
    assert_int_equal(ret, EOK);

    ncache = ts->ctx;
    ts->rctx = mock_rctx(ts, ev, tc->dom, ts->nctx);
    assert_non_null(ts->rctx);

    ret = sss_names_init(ts, tc->confdb, TEST_DOM_NAME, &tc->dom->names);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_prepopulate(ncache, tc->confdb, ts->rctx);
    assert_int_equal(ret, EOK);

    sleep(SHORTSPAN);

    ret = check_user_in_ncache(ncache, tc->dom, "testuser1");
    assert_int_equal(ret, EEXIST);

    ret = check_group_in_ncache(ncache, tc->dom, "testgroup1");
    assert_int_equal(ret, EEXIST);

    ret = check_user_in_ncache(ncache, tc->dom, "testuser2");
    assert_int_equal(ret, EEXIST);

    ret = check_group_in_ncache(ncache, tc->dom, "testgroup2");
    assert_int_equal(ret, EEXIST);

    ret = check_user_in_ncache(ncache, tc->dom, "testuser3");
    assert_int_equal(ret, ENOENT);

    ret = check_group_in_ncache(ncache, tc->dom, "testgroup3");
    assert_int_equal(ret, ENOENT);

    ret = check_user_in_ncache(ncache, tc->dom, "testuser3@somedomain");
    assert_int_equal(ret, ENOENT);

    ret = sss_ncache_check_upn(ncache, tc->dom, "testuser3@somedomain");
    assert_int_equal(ret, EEXIST);

    ret = check_group_in_ncache(ncache, tc->dom, "testgroup3@somedomain");
    assert_int_equal(ret, ENOENT);

    ret = check_user_in_ncache(ncache, tc->dom, "root");
    assert_int_equal(ret, EEXIST);

    ret = check_group_in_ncache(ncache, tc->dom, "root");
    assert_int_equal(ret, EEXIST);

    ret = check_uid_in_ncache(ncache, 0);
    assert_int_equal(ret, EEXIST);

    ret = check_gid_in_ncache(ncache, 0);
    assert_int_equal(ret, EEXIST);

    ret = sss_ncache_check_upn(ncache, tc->dom, "testuser_nss@UPN.REALM");
    assert_int_equal(ret, EEXIST);

    ret = sss_ncache_check_upn(ncache, tc->dom->subdomains, "testuser_nss@UPN.REALM");
    assert_int_equal(ret, EEXIST);

    ret = sss_ncache_check_upn(ncache, tc->dom, "testuser_nss_short@" TEST_DOM_NAME);
    assert_int_equal(ret, EEXIST);

    ret = sss_ncache_check_upn(ncache, tc->dom->subdomains, "testuser_nss_short@" TEST_SUBDOM_NAME);
    assert_int_equal(ret, EEXIST);

    ret = check_user_in_ncache(ncache, tc->dom, "testuser_nss_short");
    assert_int_equal(ret, EEXIST);

    ret = check_user_in_ncache(ncache, tc->dom->subdomains, "testuser_nss_short");
    assert_int_equal(ret, EEXIST);

    ret = sss_ncache_check_upn(ncache, tc->dom, "testuser1@" TEST_DOM_NAME);
    assert_int_equal(ret, EEXIST);

    ret = sss_ncache_check_upn(ncache, tc->dom, "testuser2@" TEST_DOM_NAME);
    assert_int_equal(ret, EEXIST);

    ret = sss_ncache_check_upn(ncache, tc->dom, "testuser3@somedomain");
    assert_int_equal(ret, EEXIST);

    /* Fully qualified names with a known domain part should be added to all
     * negative UPN caches and to the negative cache of the know domain. */
    ret = sss_ncache_check_upn(ncache, tc->dom, "all_dom_upn@"TEST_DOM_NAME);
    assert_int_equal(ret, EEXIST);

    ret = sss_ncache_check_upn(ncache, tc->dom->subdomains,
                               "all_dom_upn@"TEST_DOM_NAME);
    assert_int_equal(ret, EEXIST);

    ret = check_user_in_ncache(ncache, tc->dom, "all_dom_upn");
    assert_int_equal(ret, EEXIST);

    ret = check_user_in_ncache(ncache, tc->dom->subdomains, "all_dom_upn");
    assert_int_equal(ret, ENOENT);
}

static void test_sss_ncache_default_domain_suffix(void **state)
{
    int ret;
    struct test_state *ts;
    struct tevent_context *ev;
    struct sss_nc_ctx *ncache;
    struct sss_test_ctx *tc;
    struct sss_domain_info *dom;

    struct sss_test_conf_param params[] = {
        { "filter_users", "testuser1, testuser2@"TEST_DOM_NAME", testuser3@somedomain" },
        { "filter_groups", "testgroup1, testgroup2@"TEST_DOM_NAME", testgroup3@somedomain" },
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
    ts->rctx->default_domain = discard_const(TEST_DOM_NAME);

    ret = sss_names_init(ts, tc->confdb, TEST_DOM_NAME, &dom->names);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_prepopulate(ncache, tc->confdb, ts->rctx);
    assert_int_equal(ret, EOK);

    ret = check_user_in_ncache(ncache, dom, "testuser1");
    assert_int_equal(ret, EEXIST);

    ret = check_group_in_ncache(ncache, dom, "testgroup1");
    assert_int_equal(ret, EEXIST);

    ret = check_user_in_ncache(ncache, dom, "testuser2");
    assert_int_equal(ret, EEXIST);

    ret = check_group_in_ncache(ncache, dom, "testgroup2");
    assert_int_equal(ret, EEXIST);

    ret = check_user_in_ncache(ncache, dom, "testuser3");
    assert_int_equal(ret, ENOENT);

    ret = check_group_in_ncache(ncache, dom, "testgroup3");
    assert_int_equal(ret, ENOENT);

}

static void test_sss_ncache_reset_prepopulate(void **state)
{
    int ret;
    struct test_state *ts;
    struct tevent_context *ev;
    struct sss_nc_ctx *ncache;
    struct sss_test_ctx *tc;
    struct sss_domain_info *dom;
    struct sss_domain_info *dom2;

    struct sss_test_conf_param params[] = {
        { "filter_users", "testuser1@"TEST_DOM_NAME", testuser2@"TEST_DOM_NAME"2" },
        { "filter_groups", "testgroup1@"TEST_DOM_NAME", testgroup2@"TEST_DOM_NAME"2" },
        { NULL, NULL },
    };

    const char *sss_nss_filter_users[] = { params[0].value, NULL};
    const char *sss_nss_filter_groups[] = { params[1].value, NULL};

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

    ret = confdb_add_param(tc->confdb, true, "config/nss",
                           "filter_users", sss_nss_filter_users);
    assert_int_equal(ret, EOK);

    ret = confdb_add_param(tc->confdb, true, "config/nss",
                           "filter_groups", sss_nss_filter_groups);
    assert_int_equal(ret, EOK);

    ncache = ts->ctx;
    ts->rctx = mock_rctx(ts, ev, dom, ts->nctx);
    assert_non_null(ts->rctx);
    ts->rctx->default_domain = discard_const(TEST_DOM_NAME);
    ts->rctx->cdb = tc->confdb;

    ret = sss_names_init(ts, tc->confdb, TEST_DOM_NAME, &dom->names);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_reset_repopulate_permanent(ts->rctx, ncache);
    assert_int_equal(ret, EOK);

    /* Add another domain */
    dom2 = talloc_zero(ts, struct sss_domain_info);
    assert_non_null(dom2);
    dom2->name = discard_const_p(char, TEST_DOM_NAME"2");
    dom->next = dom2;
    dom2->names = dom->names;

    /* First domain should not be known, the second not */
    ret = check_user_in_ncache(ncache, dom, "testuser1");
    assert_int_equal(ret, EEXIST);

    ret = check_group_in_ncache(ncache, dom, "testgroup1");
    assert_int_equal(ret, EEXIST);

    ret = check_user_in_ncache(ncache, dom2, "testuser2");
    assert_int_equal(ret, ENOENT);

    ret = check_group_in_ncache(ncache, dom2, "testgroup2");
    assert_int_equal(ret, ENOENT);

    ret = sss_ncache_reset_repopulate_permanent(ts->rctx, ncache);
    assert_int_equal(ret, EOK);

    /* First domain should not be known, the second not */
    ret = check_user_in_ncache(ncache, dom, "testuser1");
    assert_int_equal(ret, EEXIST);

    ret = check_group_in_ncache(ncache, dom, "testgroup1");
    assert_int_equal(ret, EEXIST);

    ret = check_user_in_ncache(ncache, dom2, "testuser2");
    assert_int_equal(ret, EEXIST);

    ret = check_group_in_ncache(ncache, dom2, "testgroup2");
    assert_int_equal(ret, EEXIST);
}

/* The main purpose of test_sss_ncache_short_name_in_domain is to test that
 * short names in the filter_users or filter_groups options in a [domain/...]
 * section are properly added to the related sub-domains as well (if there are
 * any) and not added to domains from other [domain/...] sections. For
 * completeness entries with fully-qualified names of the parent and the
 * sub-domain and the generic UPN are added as well.
 *
 * The result should of course be independent of the present domains. To
 * verify this the domains are added one after the other and the negative
 * cache is repopulated each time. The result should be also independent of
 * the setting of default_domain_suffix option which is tested by
 * test_sss_ncache_short_name_in_domain_with_prefix.
 *
 * With the given domains, users and group we have to following expectations:
 *  - the short name entry will be added to the domain and all sub-domains as
 *    name and as upn by expanding it to a fully-qualified name with the
 *    domain name or sub-domain name respectively
 *  - the fully-qualified name from the parent domain is added as name and upn
 *    to the parent domain and as upn to all sub-domains
 *  - the fully-qualified name from the sub-domain is added as name to the
 *    sub-domain and as upn to the parent and all sub-domains
 *  - the generic upn is nowhere added as name and as upn to the parent and all
 *    sub-domains
 *  - none of the names is added to a different parent domain
 *
 * The following table should illustrated the expectations:
 *
 * user (name):
 *                 | shortuser | parentu@TEST_DOM_NAME | subdomu@subTEST_DOM_NAME | upn@upn.dom
 *-----------------+-----------+-----------------------+--------------------------+------------
 * TEST_DOM_NAME   |  PRESENT  |  PRESENT              |  MISSING                 |  MISSING
 * subTEST_DOM_NAME|  PRESENT  |  MISSING              |  PRESENT                 |  MISSING
 * TEST_DOM_NAME2  |  MISSING  |  MISSING              |  MISSING                 |  MISSING
 *
 * user (upn):
 *                 | shortuser | parentu@TEST_DOM_NAME | subdomu@subTEST_DOM_NAME | upn@upn.dom
 *-----------------+-----------+-----------------------+--------------------------+------------
 * TEST_DOM_NAME   |  PRESENT  |  PRESENT              |  PRESENT                 |  PRESENT
 * subTEST_DOM_NAME|  PRESENT  |  PRESENT              |  PRESENT                 |  PRESENT
 * TEST_DOM_NAME2  |  MISSING  |  MISSING              |  MISSING                 |  MISSING
 *
 *
 *
 * groups:
 *                 | shortgroup | parentg@TEST_DOM_NAME | subdomg@subTEST_DOM_NAME
 *-----------------+------------+-----------------------+-------------------------
 * TEST_DOM_NAME   |  PRESENT   |  PRESENT              |  MISSING
 * subTEST_DOM_NAME|  PRESENT   |  MISSING              |  PRESENT
 * TEST_DOM_NAME2  |  MISSING   |  MISSING              |  MISSING
 *
 *
 * The following expect_*() implement checks for the expextations:
 */

static void expect_in_parent(struct sss_nc_ctx *ncache,
                             struct sss_domain_info *dom)
{
    int ret;

    ret = check_user_in_ncache(ncache, dom, "shortuser");
    assert_int_equal(ret, EEXIST);
    ret = sss_ncache_check_upn(ncache, dom, "shortuser@"TEST_DOM_NAME);
    assert_int_equal(ret, EEXIST);

    ret = check_user_in_ncache(ncache, dom, "parentu");
    assert_int_equal(ret, EEXIST);
    ret = sss_ncache_check_upn(ncache, dom, "parentu@"TEST_DOM_NAME);
    assert_int_equal(ret, EEXIST);

    ret = check_user_in_ncache(ncache, dom, "subdomu");
    assert_int_equal(ret, ENOENT);
    ret = sss_ncache_check_upn(ncache, dom, "subdomu@sub"TEST_DOM_NAME);
    assert_int_equal(ret, EEXIST);

    ret = check_user_in_ncache(ncache, dom, "upn");
    assert_int_equal(ret, ENOENT);
    ret = sss_ncache_check_upn(ncache, dom, "upn@upn.dom");
    assert_int_equal(ret, EEXIST);

    ret = check_group_in_ncache(ncache, dom, "shortgroup");
    assert_int_equal(ret, EEXIST);

    ret = check_group_in_ncache(ncache, dom, "parentg");
    assert_int_equal(ret, EEXIST);

    ret = check_group_in_ncache(ncache, dom, "subdomg");
    assert_int_equal(ret, ENOENT);
}

static void expect_in_subdomain(struct sss_nc_ctx *ncache,
                                struct sss_domain_info *sub_dom)
{
    int ret;

    ret = check_user_in_ncache(ncache, sub_dom, "shortuser");
    assert_int_equal(ret, EEXIST);
    ret = sss_ncache_check_upn(ncache, sub_dom, "shortuser@sub"TEST_DOM_NAME);
    assert_int_equal(ret, EEXIST);

    ret = check_user_in_ncache(ncache, sub_dom, "subdomu");
    assert_int_equal(ret, EEXIST);
    ret = sss_ncache_check_upn(ncache, sub_dom, "subdomu@sub"TEST_DOM_NAME);
    assert_int_equal(ret, EEXIST);

    ret = check_user_in_ncache(ncache, sub_dom, "upn");
    assert_int_equal(ret, ENOENT);
    ret = sss_ncache_check_upn(ncache, sub_dom, "upn@upn.dom");
    assert_int_equal(ret, EEXIST);

    ret = check_user_in_ncache(ncache, sub_dom, "parentu");
    assert_int_equal(ret, ENOENT);
    ret = sss_ncache_check_upn(ncache, sub_dom, "parentu@"TEST_DOM_NAME);
    assert_int_equal(ret, EEXIST);


    ret = check_group_in_ncache(ncache, sub_dom, "shortgroup");
    assert_int_equal(ret, EEXIST);

    ret = check_group_in_ncache(ncache, sub_dom, "parentg");
    assert_int_equal(ret, ENOENT);

    ret = check_group_in_ncache(ncache, sub_dom, "subdomg");
    assert_int_equal(ret, EEXIST);
}
static void expect_no_entries_in_dom(struct sss_nc_ctx *ncache,
                                     struct sss_domain_info *dom2)
{
    int ret;

    ret = check_user_in_ncache(ncache, dom2, "shortuser");
    assert_int_equal(ret, ENOENT);
    ret = sss_ncache_check_upn(ncache, dom2, "shortuser"TEST_DOM_NAME);
    assert_int_equal(ret, ENOENT);

    ret = check_user_in_ncache(ncache, dom2, "parentu");
    assert_int_equal(ret, ENOENT);
    ret = sss_ncache_check_upn(ncache, dom2, "parentu@"TEST_DOM_NAME);
    assert_int_equal(ret, ENOENT);

    ret = check_user_in_ncache(ncache, dom2, "subdomu");
    assert_int_equal(ret, ENOENT);
    ret = sss_ncache_check_upn(ncache, dom2, "subdomu@sub"TEST_DOM_NAME);
    assert_int_equal(ret, ENOENT);

    ret = check_user_in_ncache(ncache, dom2, "upn");
    assert_int_equal(ret, ENOENT);
    ret = sss_ncache_check_upn(ncache, dom2, "upn@upn.dom");
    assert_int_equal(ret, ENOENT);

    ret = check_group_in_ncache(ncache, dom2, "shortgroup");
    assert_int_equal(ret, ENOENT);

    ret = check_group_in_ncache(ncache, dom2, "parentg");
    assert_int_equal(ret, ENOENT);

    ret = check_group_in_ncache(ncache, dom2, "subdomg");
    assert_int_equal(ret, ENOENT);
}

static void run_sss_ncache_short_name_in_domain(void **state,
                                                bool use_default_domain_prefix)
{
    int ret;
    struct test_state *ts;
    struct tevent_context *ev;
    struct sss_nc_ctx *ncache;
    struct sss_test_ctx *tc;
    struct sss_domain_info *dom;
    struct sss_domain_info *dom2;
    struct sss_domain_info *sub_dom;

    struct sss_test_conf_param params[] = {
        { "filter_users", "shortuser, parentu@"TEST_DOM_NAME", "
          "subdomu@sub"TEST_DOM_NAME", upn@upn.dom" },
        { "filter_groups", "shortgroup, parentg@"TEST_DOM_NAME", "
          "subdomg@sub"TEST_DOM_NAME },
        { NULL, NULL },
    };

    const char *sss_nss_filter_users[] = { params[0].value, NULL};
    const char *sss_nss_filter_groups[] = { params[1].value, NULL};

    ts = talloc_get_type_abort(*state, struct test_state);

    ev = tevent_context_init(ts);
    assert_non_null(ev);

    dom = talloc_zero(ts, struct sss_domain_info);
    assert_non_null(dom);
    dom->name = discard_const_p(char, TEST_DOM_NAME);
    sss_domain_set_state(dom, DOM_ACTIVE);

    ts->nctx = mock_nctx(ts);
    assert_non_null(ts->nctx);

    tc = create_dom_test_ctx(ts, TESTS_PATH, TEST_CONF_DB,
                             TEST_DOM_NAME, TEST_ID_PROVIDER, params);
    assert_non_null(tc);

    ret = confdb_add_param(tc->confdb, true, "config/domain/"TEST_DOM_NAME,
                           "filter_users", sss_nss_filter_users);
    assert_int_equal(ret, EOK);

    ret = confdb_add_param(tc->confdb, true, "config/domain"TEST_DOM_NAME,
                           "filter_groups", sss_nss_filter_groups);
    assert_int_equal(ret, EOK);

    ncache = ts->ctx;
    ts->rctx = mock_rctx(ts, ev, dom, ts->nctx);
    assert_non_null(ts->rctx);
    if (use_default_domain_prefix) {
        ts->rctx->default_domain = discard_const(TEST_DOM_NAME);
    }
    ts->rctx->cdb = tc->confdb;

    ret = sss_names_init(ts, tc->confdb, TEST_DOM_NAME, &dom->names);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_reset_repopulate_permanent(ts->rctx, ncache);
    assert_int_equal(ret, EOK);

    /* Add another domain */
    dom2 = talloc_zero(ts, struct sss_domain_info);
    assert_non_null(dom2);
    dom2->name = discard_const_p(char, TEST_DOM_NAME"2");
    sss_domain_set_state(dom2, DOM_ACTIVE);
    dom->next = dom2;
    dom2->names = dom->names;

    expect_in_parent(ncache, dom);
    expect_no_entries_in_dom(ncache, dom2);

    ret = sss_ncache_reset_repopulate_permanent(ts->rctx, ncache);
    assert_int_equal(ret, EOK);

    expect_in_parent(ncache, dom);
    expect_no_entries_in_dom(ncache, dom2);

    /* Add a sub domain */
    sub_dom = talloc_zero(ts, struct sss_domain_info);
    assert_non_null(sub_dom);
    sub_dom->name = discard_const_p(char, "sub"TEST_DOM_NAME);
    sss_domain_set_state(sub_dom, DOM_ACTIVE);
    sub_dom->parent = dom;
    dom->subdomains = sub_dom;
    sub_dom->names = dom->names;

    ret = sss_ncache_reset_repopulate_permanent(ts->rctx, ncache);
    assert_int_equal(ret, EOK);

    expect_in_parent(ncache, dom);
    expect_in_subdomain(ncache, sub_dom);
    expect_no_entries_in_dom(ncache, dom2);
}

static void test_sss_ncache_short_name_in_domain(void **state)
{
    run_sss_ncache_short_name_in_domain(state, false);
}

static void test_sss_ncache_short_name_in_domain_with_prefix(void **state)
{
    run_sss_ncache_short_name_in_domain(state, true);
}

static void test_sss_ncache_reset(void **state)
{
    errno_t ret;
    struct test_state *ts;
    struct sss_domain_info *dom;

    ts = talloc_get_type_abort(*state, struct test_state);
    dom = talloc(ts, struct sss_domain_info);
    assert_non_null(dom);
    dom->case_sensitive = true;

    dom->name = discard_const_p(char, TEST_DOM_NAME);

    /* Set users */
    ret = sss_ncache_check_uid(ts->ctx, NULL, 123);
    assert_int_equal(ret, ENOENT);
    ret = sss_ncache_set_uid(ts->ctx, false, NULL, 123);
    assert_int_equal(ret, EOK);
    ret = sss_ncache_check_uid(ts->ctx, NULL, 123);
    assert_int_equal(ret, EEXIST);

    ret = sss_ncache_check_user(ts->ctx, dom, "foo");
    assert_int_equal(ret, ENOENT);
    ret = sss_ncache_set_user(ts->ctx, false, dom, "foo");
    assert_int_equal(ret, EOK);
    ret = sss_ncache_check_user(ts->ctx, dom, "foo");
    assert_int_equal(ret, EEXIST);

    /* Set groups */
    ret = sss_ncache_check_gid(ts->ctx, NULL, 456);
    assert_int_equal(ret, ENOENT);
    ret = sss_ncache_set_gid(ts->ctx, false, NULL, 456);
    assert_int_equal(ret, EOK);
    ret = sss_ncache_check_gid(ts->ctx, NULL, 456);
    assert_int_equal(ret, EEXIST);

    ret = sss_ncache_check_group(ts->ctx, dom, "bar");
    assert_int_equal(ret, ENOENT);
    ret = sss_ncache_set_group(ts->ctx, false, dom, "bar");
    assert_int_equal(ret, EOK);
    ret = sss_ncache_check_group(ts->ctx, dom, "bar");
    assert_int_equal(ret, EEXIST);

    ret = sss_ncache_reset_users(ts->ctx);
    assert_int_equal(ret, EOK);

    /* Users are no longer negatively cached */
    ret = sss_ncache_check_user(ts->ctx, dom, "foo");
    assert_int_equal(ret, ENOENT);
    ret = sss_ncache_check_uid(ts->ctx, NULL, 123);
    assert_int_equal(ret, ENOENT);

    /* Groups still are */
    ret = sss_ncache_check_gid(ts->ctx, NULL, 456);
    assert_int_equal(ret, EEXIST);
    ret = sss_ncache_check_group(ts->ctx, dom, "bar");
    assert_int_equal(ret, EEXIST);

    ret = sss_ncache_reset_groups(ts->ctx);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_gid(ts->ctx, NULL, 456);
    assert_int_equal(ret, ENOENT);
    ret = sss_ncache_check_group(ts->ctx, dom, "bar");
    assert_int_equal(ret, ENOENT);
}

static void test_sss_ncache_locate_uid_gid_sid(void **state)
{
    uid_t uid;
    gid_t gid;
    const char *sid = "S-1-3-0-9999-9999-99";
    int ret;
    struct test_state *ts;
    struct sss_domain_info *dom;
    struct sss_domain_info *dom2;

    ts = talloc_get_type_abort(*state, struct test_state);

    uid = getuid();
    gid = getgid();

    dom = talloc(ts, struct sss_domain_info);
    assert_non_null(dom);
    dom->name = discard_const_p(char, TEST_DOM_NAME);

    dom2 = talloc(ts, struct sss_domain_info);
    assert_non_null(dom2);
    dom2->name = discard_const_p(char, TEST_DOM_NAME"2");

    ret = sss_ncache_check_locate_gid(ts->ctx, dom, gid);
    assert_int_equal(ret, ENOENT);
    ret = sss_ncache_check_locate_uid(ts->ctx, dom, uid);
    assert_int_equal(ret, ENOENT);
    ret = sss_ncache_check_locate_sid(ts->ctx, dom, sid);
    assert_int_equal(ret, ENOENT);

    ret = sss_ncache_set_locate_gid(ts->ctx, dom, gid);
    assert_int_equal(ret, EOK);
    ret = sss_ncache_set_locate_uid(ts->ctx, dom, uid);
    assert_int_equal(ret, EOK);
    ret = sss_ncache_set_locate_sid(ts->ctx, dom, sid);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_locate_gid(ts->ctx, dom, gid);
    assert_int_equal(ret, EEXIST);
    ret = sss_ncache_check_locate_uid(ts->ctx, dom, uid);
    assert_int_equal(ret, EEXIST);
    ret = sss_ncache_check_locate_sid(ts->ctx, dom, sid);
    assert_int_equal(ret, EEXIST);

    ret = sss_ncache_check_locate_gid(ts->ctx, dom2, gid);
    assert_int_equal(ret, ENOENT);
    ret = sss_ncache_check_locate_uid(ts->ctx, dom2, uid);
    assert_int_equal(ret, ENOENT);
    ret = sss_ncache_check_locate_sid(ts->ctx, dom2, sid);
    assert_int_equal(ret, ENOENT);
}

static void test_sss_ncache_domain_locate_type(void **state)
{
    int ret;
    struct test_state *ts;
    struct sss_domain_info *dom;
    struct sss_domain_info *dom2;

    ts = talloc_get_type_abort(*state, struct test_state);

    dom = talloc(ts, struct sss_domain_info);
    assert_non_null(dom);
    dom->name = discard_const_p(char, TEST_DOM_NAME);

    dom2 = talloc(ts, struct sss_domain_info);
    assert_non_null(dom2);
    dom2->name = discard_const_p(char, TEST_DOM_NAME"2");

    ret = sss_ncache_check_domain_locate_type(ts->ctx, dom, "foo");
    assert_int_equal(ret, ENOENT);
    ret = sss_ncache_set_domain_locate_type(ts->ctx, dom, "foo");
    assert_int_equal(ret, EOK);
    ret = sss_ncache_check_domain_locate_type(ts->ctx, dom, "foo");
    assert_int_equal(ret, EEXIST);

    ret = sss_ncache_check_domain_locate_type(ts->ctx, dom2, "foo");
    assert_int_equal(ret, ENOENT);
}

int main(void)
{
    int rv;
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sss_ncache_init),
        cmocka_unit_test_setup_teardown(test_sss_ncache_uid, setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_ncache_gid, setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_ncache_sid, setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_ncache_cert, setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_ncache_user, setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_ncache_group, setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_ncache_netgr, setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_ncache_service_name, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_sss_ncache_service_port,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_ncache_reset_permanent, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_sss_ncache_prepopulate,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_ncache_default_domain_suffix,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_ncache_reset_prepopulate,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_ncache_short_name_in_domain,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_ncache_short_name_in_domain_with_prefix,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_ncache_reset,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_ncache_locate_uid_gid_sid,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_ncache_domain_locate_type,
                                        setup, teardown),

        /* user */
        cmocka_unit_test_setup_teardown(test_ncache_nocache_user,
                                        test_ncache_setup,
                                        test_ncache_teardown),
        cmocka_unit_test_setup_teardown(test_ncache_local_user,
                                        test_ncache_setup,
                                        test_ncache_teardown),
        cmocka_unit_test_setup_teardown(test_ncache_domain_user,
                                        test_ncache_setup,
                                        test_ncache_teardown),
        cmocka_unit_test_setup_teardown(test_ncache_both_user,
                                        test_ncache_setup,
                                        test_ncache_teardown),
        /* uid */
        cmocka_unit_test_setup_teardown(test_ncache_nocache_uid,
                                        test_ncache_setup,
                                        test_ncache_teardown),
        cmocka_unit_test_setup_teardown(test_ncache_local_uid,
                                        test_ncache_setup,
                                        test_ncache_teardown),
        cmocka_unit_test_setup_teardown(test_ncache_domain_uid,
                                        test_ncache_setup,
                                        test_ncache_teardown),
        cmocka_unit_test_setup_teardown(test_ncache_both_uid,
                                        test_ncache_setup,
                                        test_ncache_teardown),
        /* group */
        cmocka_unit_test_setup_teardown(test_ncache_nocache_group,
                                        test_ncache_setup,
                                        test_ncache_teardown),
        cmocka_unit_test_setup_teardown(test_ncache_local_group,
                                        test_ncache_setup,
                                        test_ncache_teardown),
        cmocka_unit_test_setup_teardown(test_ncache_domain_group,
                                        test_ncache_setup,
                                        test_ncache_teardown),
        cmocka_unit_test_setup_teardown(test_ncache_both_group,
                                        test_ncache_setup,
                                        test_ncache_teardown),
        /* gid */
        cmocka_unit_test_setup_teardown(test_ncache_nocache_gid,
                                        test_ncache_setup,
                                        test_ncache_teardown),
        cmocka_unit_test_setup_teardown(test_ncache_local_gid,
                                        test_ncache_setup,
                                        test_ncache_teardown),
        cmocka_unit_test_setup_teardown(test_ncache_domain_gid,
                                        test_ncache_setup,
                                        test_ncache_teardown),
        cmocka_unit_test_setup_teardown(test_ncache_both_gid,
                                        test_ncache_setup,
                                        test_ncache_teardown),
    };

    tests_set_cwd();
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);
    test_dom_suite_setup(TESTS_PATH);

    rv = cmocka_run_group_tests(tests, NULL, NULL);
    if (rv == 0) {
        test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);
    }
    return rv;
}
