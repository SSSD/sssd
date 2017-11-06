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
#include "util/util_sss_idmap.h"
#include "responder/common/responder.h"
#include "responder/common/negcache.h"

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
    enum idmap_error_code err;

    nctx = talloc_zero(mem_ctx, struct nss_ctx);
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
    struct nss_ctx *nctx;
    struct resp_ctx *rctx;
};

static int setup(void **state)
{
    int ret;
    struct test_state *ts;

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
    ret = sss_ncache_check_sid(ts->ctx, sid);
    assert_int_equal(ret, ENOENT);

    /* test when sid is present in database */
    permanent = true;
    ret = sss_ncache_set_sid(ts->ctx, permanent, sid);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_sid(ts->ctx, sid);
    assert_int_equal(ret, EEXIST);

    permanent = false;
    ret = sss_ncache_set_sid(ts->ctx, permanent, sid);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_sid(ts->ctx, sid);
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

static void test_sss_ncache_prepopulate(void **state)
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

    ret = sss_names_init(ts, tc->confdb, TEST_DOM_NAME, &dom->names);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_prepopulate(ncache, tc->confdb, ts->rctx);
    assert_int_equal(ret, EOK);

    sleep(SHORTSPAN);

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

    ret = check_user_in_ncache(ncache, dom, "testuser3@somedomain");
    assert_int_equal(ret, ENOENT);

    ret = check_group_in_ncache(ncache, dom, "testgroup3@somedomain");
    assert_int_equal(ret, ENOENT);

    ret = check_user_in_ncache(ncache, dom, "root");
    assert_int_equal(ret, EEXIST);

    ret = check_group_in_ncache(ncache, dom, "root");
    assert_int_equal(ret, EEXIST);

    ret = check_uid_in_ncache(ncache, 0);
    assert_int_equal(ret, EEXIST);

    ret = check_gid_in_ncache(ncache, 0);
    assert_int_equal(ret, EEXIST);
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

    const char *nss_filter_users[] = { params[0].value, NULL};
    const char *nss_filter_groups[] = { params[1].value, NULL};

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
                           "filter_users", nss_filter_users);
    assert_int_equal(ret, EOK);

    ret = confdb_add_param(tc->confdb, true, "config/nss",
                           "filter_groups", nss_filter_groups);
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

static void test_sss_ncache_locate_uid_gid(void **state)
{
    uid_t uid;
    gid_t gid;
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

    ret = sss_ncache_set_locate_gid(ts->ctx, dom, gid);
    assert_int_equal(ret, EOK);
    ret = sss_ncache_set_locate_uid(ts->ctx, dom, uid);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_check_locate_gid(ts->ctx, dom, gid);
    assert_int_equal(ret, EEXIST);
    ret = sss_ncache_check_locate_uid(ts->ctx, dom, uid);
    assert_int_equal(ret, EEXIST);

    ret = sss_ncache_check_locate_gid(ts->ctx, dom2, gid);
    assert_int_equal(ret, ENOENT);
    ret = sss_ncache_check_locate_uid(ts->ctx, dom2, uid);
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
        cmocka_unit_test_setup_teardown(test_sss_ncache_reset,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_ncache_locate_uid_gid,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_ncache_domain_locate_type,
                                        setup, teardown),
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
