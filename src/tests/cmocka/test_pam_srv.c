/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2015 Red Hat

    SSSD tests: PAM responder tests

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

#include <security/pam_modules.h>
#include <popt.h>
#include <stdlib.h> /* putenv */
#include <sys/wait.h>

#include "tests/cmocka/common_mock.h"
#include "tests/cmocka/common_mock_resp.h"
#include "responder/common/responder_packet.h"
#include "responder/common/negcache.h"
#include "responder/pam/pamsrv.h"
#include "responder/pam/pam_helpers.h"
#include "sss_client/pam_message.h"
#include "sss_client/sss_cli.h"
#include "confdb/confdb.h"
#ifdef BUILD_PASSKEY
#include "src/responder/pam/pamsrv_passkey.h"
#include "db/sysdb_passkey_user_verification.h"
#endif

#include "util/crypto/sss_crypto.h"

/* OpenPAM compat */
#ifndef _PAM_RETURN_VALUES
#define _PAM_RETURN_VALUES PAM_NUM_ERRORS
#endif

#ifdef HAVE_TEST_CA
#include "tests/test_CA/SSSD_test_cert_x509_0001.h"
#include "tests/test_CA/SSSD_test_cert_x509_0002.h"
#include "tests/test_CA/SSSD_test_cert_x509_0005.h"
#include "tests/test_CA/SSSD_test_cert_x509_0006.h"
#include "tests/test_CA/SSSD_test_cert_x509_0007.h"
#ifdef HAVE_FAKETIME
#include "tests/test_CA/SSSD_test_cert_x509_0008.h"
#else
#define SSSD_TEST_CERT_0008 ""
#endif
#include "tests/test_CA/SSSD_test_cert_x509_0009.h"
#include "tests/test_CA/intermediate_CA/SSSD_test_intermediate_CA_cert_x509_0001.h"
#include "tests/test_ECC_CA/SSSD_test_ECC_cert_x509_0001.h"
#else
#define SSSD_TEST_CERT_0001 ""
#define SSSD_TEST_CERT_0002 ""
#define SSSD_TEST_CERT_0005 ""
#define SSSD_TEST_CERT_0006 ""
#define SSSD_TEST_CERT_0007 ""
#define SSSD_TEST_CERT_0008 ""
#define SSSD_TEST_CERT_0009 ""
#define SSSD_TEST_INTERMEDIATE_CA_CERT_0001 ""
#define SSSD_TEST_ECC_CERT_0001 ""
#endif

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_DB "test_pam_conf.ldb"
#define TEST_DOM_NAME "pam_test"
#define TEST_SUBDOM_NAME "test.subdomain"
#define TEST_ID_PROVIDER "ldap"

#define CA_DB ABS_BUILD_DIR"/src/tests/test_CA/SSSD_test_CA.pem"
#define INTERMEDIATE_CA_DB \
    ABS_BUILD_DIR"/src/tests/test_CA/intermediate_CA/SSSD_test_intermediate_CA.pem"
#define INTERMEDIATE_FULL_CA_DB \
    ABS_BUILD_DIR"/src/tests/test_CA/intermediate_CA/SSSD_test_intermediate_CA_full_db.pem"
#define ECC_CA_DB ABS_BUILD_DIR"/src/tests/test_ECC_CA/SSSD_test_ECC_CA.pem"

#define TEST_TOKEN_NAME "SSSD Test Token"
#define TEST_TOKEN2_NAME "SSSD Test Token Number 2"
#define TEST_KEY_ID "C554C9F82C2A9D58B70921C143304153A8A42F17"
#define TEST_LABEL "SSSD test cert 0001"
#define TEST_MODULE_NAME SOFTHSM2_PATH
#define TEST_PROMPT "SSSD test cert 0001\nCN=SSSD test cert 0001,OU=SSSD test,O=SSSD"
#define TEST2_PROMPT "SSSD test cert 0002\nCN=SSSD test cert 0002,OU=SSSD test,O=SSSD"
#define TEST5_PROMPT "SSSD test cert 0005\nCN=SSSD test cert 0005,OU=SSSD test,O=SSSD"

#define TEST2_KEY_ID "5405842D56CF31F0BB025A695C5F3E907051C5B9"
#define TEST2_LABEL "SSSD test cert 0002"
#define TEST5_KEY_ID "1195833C424AB00297F582FC43FFFFAB47A64CC9"
#define TEST5_LABEL "SSSD test cert 0005"


#define TEST8_TOKEN_NAME "SSSD Test Token Expired"
#define TEST8_PROMPT "SSSD test cert 0008\nCN=SSSD test cert 0008 expired,OU=SSSD test,O=SSSD"
#define TEST8_KEY_ID "123456"
#define TEST8_LABEL "SSSD test cert 0008"

#define TEST9_TOKEN_NAME "SSSD Test Token Revoked"
#define TEST9_PROMPT "SSSD test cert 0009\nCN=SSSD test cert 0009 - revoked,OU=SSSD test,O=SSSD"
#define TEST9_KEY_ID "123456"
#define TEST9_LABEL "SSSD test cert 0009"

#define SSSD_TEST_PASSKEY \
     "passkey:zO7lzqHPkVgsWkMTuJ17E+9OTcPtYUZJFHDs3xPSDgjcsHp/yLHkiRRNJ2IMU278" \
     "wdzGuHmSI4rOnyZ0VcJ/kA==,MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEKhSQWMPgAU" \
	 "cz4d7Fjz2hZK7QUlnAttuEW5XrxD06VBaQvIRYJT7e6wM+vFU4z+uQgU9B5ERbgMiBVe99rB" \
	 "L9w=="
#define SSSD_TEST_PASSKEY_TWO \
     "passkey:amLLQX2dYGPKCKB5QO7mjLy4ndHCxFr2GXpr0hnb/KZ4X0W3+Dza8nmux+vXmZR4Z" \
     "EPYIb7a2wbK6Wo67uScXA==,MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/xrLQPGeZS7Hh" \
     "7T2zrJK/LSAOoYFTHx9YiO+IIk3v7Tbgbbi7HoQJdDf8pyAKIgzM4S/kDy0eEymxDLgT4/7Zw" \
     "=="

#define SSSD_TEST_PASSKEY_PK \
     "zO7lzqHPkVgsWkMTuJ17E+9OTcPtYUZJFHDs3xPSDgjcsHp/yLHkiRRNJ2IMU278" \
      "wdzGuHmSI4rOnyZ0VcJ/kA=="

#define SSSD_TEST_PASSKEY_KEY_HANDLE \
     "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEKhSQWMPgAUcz4d7Fjz2hZK7QUlnAttuEW5Xr" \
     "xD06VBaQvIRYJT7e6wM+vFU4z+uQgU9B5ERbgMiBVe99rBL9w=="

#define SSSD_TEST_PUBKEY \
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCa+l8uZ6Q5G58PVMe1na7NrOMTzo2wOZfFwo" \
    "0fM3RbvfAdlz/wsGwln2+EXA19FiXu/nNj4EwYGP9hymKuYaXzpq40k0VbhEL1v/qzXQvuKZgN" \
    "x42vxi7NITaaAXuYj8OZQsZTvv+xgkREZmhQ6YqEjTJ0JzpD9fj8Gf8Mgn8pdsb/ZODLMAwEKt" \
    "Q2DaWqH5jCqzoGEJlRl+kRbnrHc+RQrmj7NnY1voEJNrmzCyJFH5awZyBl/ZdbvpnwCKnVEleB" \
    "FULrOIfJ9lc/QMmURCMa6RfW5CFrxdtjUwiIxfMiHe+zUY5T9L0Q6FWnlfNz/63Xdcrw1Gc90O" \
    "CZKcqf/4P9N5flGSGSfiO5fD8gCCJ0c3WhxSVMREDP3ibKDsz8yhw2OuyGcfRo4nnchxy9G703" \
    "1m2t9rUXc12eS1EKGJiPiT9IuTQ9nCG2PslkqR+KUMiYoS9MqTsAj9HhuTMkFhcYFyufxFmt/S" \
    "4rIqVwmP8lY4GwwJwOnZwNLj/I2HwC+pk= testuser@fedora.test.local"

#define SSSD_TEST_CERT \
    "X509:<I>O=Red Hat,OU=prod,CN=Certificate Authority<S>DC=com,DC=redhat,OU=users" \
    ",OID.0.9.2342.19200300.100.1.1=jstephen,E=jstephen@redhat.com" \
    "m,CN=Justin Stephenson Justin Stephenson"


int no_cleanup;

static char CACHED_AUTH_TIMEOUT_STR[] = "4";
static const int CACHED_AUTH_TIMEOUT = 4;

struct pam_test_ctx {
    struct sss_test_ctx *tctx;
    struct sss_domain_info *subdom;

    struct resp_ctx *rctx;
    struct cli_ctx *cctx;
    struct sss_cmd_table *pam_cmds;
    struct pam_ctx *pctx;

    int ncache_hits;
    int exp_pam_status;
    enum prompt_config_type exp_prompt_config_type;
    const char *exp_touch_prompt;
    struct pam_data *pd;
    bool provider_contacted;

    const char *pam_user_fqdn;
    const char *wrong_user_fqdn;
    int child_status;
};

/* Must be global because it is needed in some wrappers */
struct pam_test_ctx *pam_test_ctx;

struct pam_ctx *mock_pctx(TALLOC_CTX *mem_ctx)
{
    struct pam_ctx *pctx;
    errno_t ret;

    pctx = talloc_zero(mem_ctx, struct pam_ctx);
    assert_non_null(pctx);

    ret = sss_hash_create(pctx, 10, &pctx->id_table);
    assert_int_equal(ret, EOK);

    /* Two NULLs so that tests can just assign a const to the first slot
     * should they need it. The code iterates until first NULL anyway
     */
    pctx->app_services = talloc_zero_array(pctx, char *, 2);
    if (pctx->app_services == NULL) {
        talloc_free(pctx);
        return NULL;
    }

    ret = p11_refresh_certmap_ctx(pctx, NULL);
    assert_int_equal(ret, 0);

    pctx->initgroups_scheme = PAM_INITGR_NO_SESSION;

    return pctx;
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

static int add_pam_params(struct sss_test_conf_param pam_params[],
                          struct confdb_ctx *cdb)
{
    return add_confdb_params(pam_params, cdb, CONFDB_PAM_CONF_ENTRY);
}

static int add_monitor_params(struct sss_test_conf_param monitor_params[],
                              struct confdb_ctx *cdb)
{
    return add_confdb_params(monitor_params, cdb, CONFDB_MONITOR_CONF_ENTRY);
}

void test_pam_setup(struct sss_test_conf_param dom_params[],
                    struct sss_test_conf_param pam_params[],
                    struct sss_test_conf_param monitor_params[],
                    void **state)
{
    struct cli_protocol *prctx;
    errno_t ret;

    pam_test_ctx = talloc_zero(NULL, struct pam_test_ctx);
    assert_non_null(pam_test_ctx);

    test_dom_suite_setup(TESTS_PATH);
    pam_test_ctx->tctx = create_dom_test_ctx(pam_test_ctx, TESTS_PATH,
                                             TEST_CONF_DB, TEST_DOM_NAME,
                                             TEST_ID_PROVIDER, dom_params);
    assert_non_null(pam_test_ctx->tctx);

    pam_test_ctx->pam_cmds = get_pam_cmds();
    assert_non_null(pam_test_ctx->pam_cmds);
    pam_test_ctx->tctx->dom->dns_name = talloc_strdup(pam_test_ctx, TEST_DOM_NAME);

    /* FIXME - perhaps this should be folded into sssd_domain_init or strictly
     * used together
     */
    ret = sss_names_init(pam_test_ctx, pam_test_ctx->tctx->confdb,
                         TEST_DOM_NAME, &pam_test_ctx->tctx->dom->names);
    assert_int_equal(ret, EOK);

    /* Initialize the PAM responder */
    pam_test_ctx->pctx = mock_pctx(pam_test_ctx);
    assert_non_null(pam_test_ctx->pctx);

    pam_test_ctx->rctx = mock_rctx(pam_test_ctx, pam_test_ctx->tctx->ev,
                                   pam_test_ctx->tctx->dom, pam_test_ctx->pctx);
    assert_non_null(pam_test_ctx->rctx);
    pam_test_ctx->rctx->cdb = pam_test_ctx->tctx->confdb;
    pam_test_ctx->pctx->rctx = pam_test_ctx->rctx;

    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = add_monitor_params(monitor_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    /* Create client context */
    pam_test_ctx->cctx = mock_cctx(pam_test_ctx, pam_test_ctx->rctx);
    assert_non_null(pam_test_ctx->cctx);
    pam_test_ctx->cctx->ev = pam_test_ctx->tctx->ev;

    prctx = mock_prctx(pam_test_ctx->cctx);
    assert_non_null(prctx);
    pam_test_ctx->cctx->protocol_ctx = prctx;
    prctx->cli_protocol_version = register_cli_protocol_version();

    pam_test_ctx->pd = create_pam_data(pam_test_ctx);
    assert_non_null(pam_test_ctx->pd);
}

static void pam_test_setup_common(void)
{
    errno_t ret;
    time_t now;

    putenv(discard_const("SOFTHSM2_CONF=" ABS_BUILD_DIR "/src/tests/test_CA/softhsm2_one.conf"));

    pam_test_ctx->pam_user_fqdn = \
                    sss_create_internal_fqname(pam_test_ctx,
                                               "pamuser",
                                               pam_test_ctx->tctx->dom->name);
    assert_non_null(pam_test_ctx->pam_user_fqdn);

    pam_test_ctx->wrong_user_fqdn = \
                    sss_create_internal_fqname(pam_test_ctx,
                                               "wronguser",
                                               pam_test_ctx->tctx->dom->name);
    assert_non_null(pam_test_ctx->wrong_user_fqdn);

    /* integer values cannot be set by pam_params, since we are expecting that
     * the PAM id cache stay valid during a test we have to make sure the
     * timeout is long enough that even a run e.g. delayed by running with
     * valgrind can pass. */
    pam_test_ctx->pctx->id_timeout = 60;

    now = time(NULL);
    /* Prime the cache with a valid user */
    ret = sysdb_add_user(pam_test_ctx->tctx->dom,
                         pam_test_ctx->pam_user_fqdn,
                         123, 456, "pam user",
                         "/home/pamuser", "/bin/sh", NULL,
                         NULL, 300, now);
    assert_int_equal(ret, EOK);
    ret = sysdb_set_initgr_expire_timestamp(pam_test_ctx->tctx->dom,
                                            pam_test_ctx->pam_user_fqdn);
    assert_int_equal(ret, EOK);

    /* Add entry to the initgr cache to make sure no initgr request is sent to
     * the backend */
    ret = pam_initgr_cache_set(pam_test_ctx->pctx->rctx->ev,
                               pam_test_ctx->pctx->id_table,
                               discard_const("pamuser"),
                               pam_test_ctx->pctx->id_timeout);
    assert_int_equal(ret, EOK);

    /* Prime the cache with a user for wrong matches */
    ret = sysdb_add_user(pam_test_ctx->tctx->dom,
                         pam_test_ctx->wrong_user_fqdn,
                         321, 654, "wrong user",
                         "/home/wronguser", "/bin/sh", NULL,
                         NULL, 300, now);
    assert_int_equal(ret, EOK);
    ret = sysdb_set_initgr_expire_timestamp(pam_test_ctx->tctx->dom,
                                            pam_test_ctx->wrong_user_fqdn);
    assert_int_equal(ret, EOK);

    /* Add entry to the initgr cache to make sure no initgr request is sent to
     * the backend */
    ret = pam_initgr_cache_set(pam_test_ctx->pctx->rctx->ev,
                               pam_test_ctx->pctx->id_table,
                               discard_const("wronguser"),
                               pam_test_ctx->pctx->id_timeout);
    assert_int_equal(ret, EOK);
}

static int pam_test_setup(void **state)
{
    struct sss_test_conf_param dom_params[] = {
        { "enumerate", "false" },
        { "cache_credentials", "true" },
        { "entry_cache_timeout", "300" },
        { "local_auth_policy", "enable:smartcard" }, /* Needed to allow local sc auth */
        { NULL, NULL },             /* Sentinel */
    };

    struct sss_test_conf_param pam_params[] = {
        { CONFDB_PAM_P11_URI, "pkcs11:manufacturer=SoftHSM%20project" },
        { "p11_child_timeout", "30" },
        { "pam_cert_verification", NULL },
        { NULL, NULL },             /* Sentinel */
    };

    struct sss_test_conf_param monitor_params[] = {
        { "certificate_verification", "no_ocsp"},
        { NULL, NULL },             /* Sentinel */
    };

    test_pam_setup(dom_params, pam_params, monitor_params, state);

    pam_test_setup_common();
    return 0;
}

#ifdef BUILD_PASSKEY
static int pam_test_setup_passkey(void **state)
{
    struct sss_test_conf_param dom_params[] = {
        { "enumerate", "false" },
        { "cache_credentials", "true" },
        { "entry_cache_timeout", "300" },
        { "local_auth_policy", "enable:passkey" }, /* Needed to allow local passkey auth */
        { NULL, NULL },             /* Sentinel */
    };

    struct sss_test_conf_param pam_params[] = {
        { CONFDB_PAM_P11_URI, "pkcs11:manufacturer=SoftHSM%20project" },
        { "p11_child_timeout", "30" },
        { "pam_cert_verification", NULL },
        { NULL, NULL },             /* Sentinel */
    };

    struct sss_test_conf_param monitor_params[] = {
        { "certificate_verification", "no_ocsp"},
        { NULL, NULL },             /* Sentinel */
    };

    test_pam_setup(dom_params, pam_params, monitor_params, state);

    pam_test_setup_common();
    return 0;
}
#endif

#ifdef HAVE_TEST_CA
static int pam_test_setup_no_verification(void **state)
{
    struct sss_test_conf_param dom_params[] = {
        { "enumerate", "false" },
        { "cache_credentials", "true" },
        { "local_auth_policy", "enable:smartcard" }, /* Needed to allow local sc auth */
        { NULL, NULL }, /* Sentinel */
    };

    struct sss_test_conf_param pam_params[] = {
        { CONFDB_PAM_P11_URI, "pkcs11:manufacturer=SoftHSM%20project" },
        { "p11_child_timeout", "30" },
        { NULL, NULL }, /* Sentinel */
    };

    struct sss_test_conf_param monitor_params[] = {
        { "certificate_verification", "no_verification" },
        { NULL, NULL }, /* Sentinel */
    };

    test_pam_setup(dom_params, pam_params, monitor_params, state);

    pam_test_setup_common();
    return 0;
}

static int pam_test_setup_mech_rsa_pkcs(void **state)
{
    int rc = pam_test_setup_no_verification(state);
    if (rc != 0) {
        return rc;
    }
    return putenv(discard_const("SOFTHSM2_CONF=" ABS_BUILD_DIR "/src/tests/test_CA/softhsm2_mech_rsa_pkcs.conf"));
}

static int pam_test_setup_mech_rsa_sha384_pkcs(void **state)
{
    int rc = pam_test_setup_no_verification(state);
    if (rc != 0) {
        return rc;
    }
    return putenv(discard_const("SOFTHSM2_CONF=" ABS_BUILD_DIR "/src/tests/test_CA/softhsm2_mech_rsa_sha384_pkcs.conf"));
}
#endif /* HAVE_TEST_CA */

static int pam_cached_test_setup(void **state)
{
    struct sss_test_conf_param dom_params[] = {
        { "enumerate", "false" },
        { "cache_credentials", "true" },
        { "cached_auth_timeout", CACHED_AUTH_TIMEOUT_STR },
        { "local_auth_policy", "enable:smartcard" }, /* Needed to allow local sc auth */
        { NULL, NULL },             /* Sentinel */
    };

    struct sss_test_conf_param pam_params[] = {
        { "p11_child_timeout", "30" },
        { NULL, NULL },             /* Sentinel */
    };

    struct sss_test_conf_param monitor_params[] = {
        { "certificate_verification", "no_ocsp"},
        { NULL, NULL },             /* Sentinel */
    };

    test_pam_setup(dom_params, pam_params, monitor_params, state);

    pam_test_setup_common();
    return 0;
}

static int pam_test_teardown(void **state)
{
    int ret;

    ret = sysdb_delete_user(pam_test_ctx->tctx->dom,
                            pam_test_ctx->pam_user_fqdn, 0);
    assert_int_equal(ret, EOK);

    ret = sysdb_delete_user(pam_test_ctx->tctx->dom,
                            pam_test_ctx->wrong_user_fqdn, 0);
    assert_int_equal(ret, EOK);

    if (!no_cleanup) {
        test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);
    }

    talloc_free(pam_test_ctx);
    return 0;
}

typedef int (*cmd_cb_fn_t)(uint32_t, uint8_t *, size_t);


int __real_read_pipe_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                          uint8_t **buf, ssize_t *len);

void __real_sss_packet_get_body(struct sss_packet *packet,
                                uint8_t **body, size_t *blen);

void __wrap_sss_packet_get_body(struct sss_packet *packet,
                                uint8_t **body, size_t *blen)
{
    enum sss_test_wrapper_call wtype = sss_mock_type(enum sss_test_wrapper_call);
    size_t len;

    if (wtype == WRAP_CALL_REAL) {
        return __real_sss_packet_get_body(packet, body, blen);
    }

    *body = sss_mock_ptr_type(uint8_t *);
    len = sss_mock_type(size_t);
    if (len == 0) {
        len = strlen((const char *) *body) + 1;
    }
    *blen = len;
    return;
}

void __real_sss_packet_get_body(struct sss_packet *packet,
                                uint8_t **body, size_t *blen);

void __wrap_sss_cmd_done(struct cli_ctx *cctx, void *freectx)
{
    struct cli_protocol *prctx;
    struct sss_packet *packet;
    uint8_t *body;
    size_t blen;
    cmd_cb_fn_t check_cb;

    prctx = talloc_get_type(cctx->protocol_ctx, struct cli_protocol);
    packet = prctx->creq->out;
    assert_non_null(packet);

    check_cb = sss_mock_ptr_type(cmd_cb_fn_t);

    __real_sss_packet_get_body(packet, &body, &blen);

    pam_test_ctx->tctx->error = check_cb(sss_packet_get_status(packet),
                                         body, blen);
    pam_test_ctx->tctx->done = true;
}

enum sss_cli_command __wrap_sss_packet_get_cmd(struct sss_packet *packet)
{
    return sss_mock_type(enum sss_cli_command);
}

int __wrap_sss_cmd_send_empty(struct cli_ctx *cctx, TALLOC_CTX *freectx)
{
    pam_test_ctx->tctx->done = true;
    pam_test_ctx->tctx->error = ENOENT;
    return EOK;
}

static void set_cmd_cb(cmd_cb_fn_t fn)
{
    will_return(__wrap_sss_cmd_done, fn);
}

int __wrap_pam_dp_send_req(struct pam_auth_req *preq, int timeout)
{
    pam_test_ctx->provider_contacted = true;

    /* Set expected status */
    preq->pd->pam_status = pam_test_ctx->exp_pam_status;
    if (pam_test_ctx->pd->resp_list != NULL) {
        preq->pd->resp_list = pam_test_ctx->pd->resp_list;
    }

    preq->callback(preq);

    return EOK;
}

#ifdef BUILD_PASSKEY
static void passkey_test_done(struct tevent_req *req)
{
    struct pam_test_ctx *ctx =
            tevent_req_callback_data(req, struct pam_test_ctx);

    pam_passkey_auth_recv(req, &pam_test_ctx->child_status);
    talloc_zfree(req);

    /* No actual fido2 device available, overwrite the child status to successful.
     * as we are faking authentication */
    if (pam_test_ctx->child_status == 1) {
        pam_test_ctx->child_status = 0;
    }

    ctx->tctx->done = true;
}

static void mock_input_pam_passkey(TALLOC_CTX *mem_ctx,
                                   const char *name,
                                   const char *pin,
                                   const char *svc,
                                   acct_cb_t acct_cb,
                                   const char *passkey)
{
    size_t buf_size;
    uint8_t *m_buf;
    uint8_t *buf;
    struct pam_items pi = { 0 };
    int ret;
    char *s_name;
    char *dom;

    if (name != NULL) {
        pi.pam_user = name;
        pi.pam_user_size = strlen(pi.pam_user) + 1;
    } else {
        pi.pam_user = "";
        pi.pam_user_size = 0;
    }

    if (pin != NULL) {
         pi.pam_authtok = discard_const(pin);
         pi.pam_authtok_size = strlen(pi.pam_authtok) + 1;
         pi.pam_authtok_type = SSS_AUTHTOK_TYPE_PASSKEY;
    }

    if (svc == NULL) {
        svc = "pam_test_service";
    }
    pi.pam_service = svc;
    pi.pam_service_size = strlen(pi.pam_service) + 1;
    pi.pam_tty = "/dev/tty";
    pi.pam_tty_size = strlen(pi.pam_tty) + 1;
    pi.pam_ruser = "remuser";
    pi.pam_ruser_size = strlen(pi.pam_ruser) + 1;
    pi.pam_rhost = "remhost";
    pi.pam_rhost_size = strlen(pi.pam_rhost) + 1;
    pi.requested_domains = "";
    pi.cli_pid = 12345;

    ret = pack_message_v3(&pi, &buf_size, &m_buf);
    assert_int_equal(ret, 0);

    buf = talloc_memdup(mem_ctx, m_buf, buf_size);
    free(m_buf);
    assert_non_null(buf);

    will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
    will_return(__wrap_sss_packet_get_body, buf);
    will_return(__wrap_sss_packet_get_body, buf_size);

    if (strrchr(name, '@') == NULL) {
        mock_parse_inp(name, NULL, EOK);
    } else {
        ret = sss_parse_internal_fqname(mem_ctx, name, &s_name, &dom);
        mock_parse_inp(s_name, dom, EOK);
    }

    if (acct_cb != NULL) {
        mock_account_recv(0, 0, NULL, acct_cb, discard_const(passkey));
    }
}

static int test_pam_passkey_auth_check(uint32_t status, uint8_t *body, size_t blen)
{
    return EOK;
}

static void set_passkey_auth_param(struct pam_ctx *pctx)
{
    pam_test_ctx->pctx->passkey_auth = true;
}
#endif

static void mock_input_pam_ex(TALLOC_CTX *mem_ctx,
                              const char *name,
                              const char *pwd,
                              const char *fa2,
                              const char *svc,
                              bool contact_dp)
{
    size_t buf_size;
    uint8_t *m_buf;
    uint8_t *buf;
    struct pam_items pi = { 0 };
    int ret;
    size_t needed_size;
    uint8_t *authtok;
    char *s_name;
    char *dom;

    if (name != NULL) {
        pi.pam_user = name;
        pi.pam_user_size = strlen(pi.pam_user) + 1;
    } else {
        pi.pam_user = "";
        pi.pam_user_size = 0;
    }

    if (pwd != NULL) {
        if (fa2 != NULL) {
            ret = sss_auth_pack_2fa_blob(pwd, 0, fa2, 0, NULL, 0, &needed_size);
            assert_int_equal(ret, EAGAIN);

            authtok = talloc_size(mem_ctx, needed_size);
            assert_non_null(authtok);

            ret = sss_auth_pack_2fa_blob(pwd, 0, fa2, 0, authtok,
                                         needed_size, &needed_size);
            assert_int_equal(ret, EOK);

            pi.pam_authtok = (char *) authtok;
            pi.pam_authtok_size = needed_size;
            pi.pam_authtok_type = SSS_AUTHTOK_TYPE_2FA;
        } else {
            pi.pam_authtok = discard_const(pwd);
            pi.pam_authtok_size = strlen(pi.pam_authtok) + 1;
            pi.pam_authtok_type = SSS_AUTHTOK_TYPE_PASSWORD;
        }
    }

    if (svc == NULL) {
        svc = "pam_test_service";
    }
    pi.pam_service = svc;
    pi.pam_service_size = strlen(pi.pam_service) + 1;
    pi.pam_tty = "/dev/tty";
    pi.pam_tty_size = strlen(pi.pam_tty) + 1;
    pi.pam_ruser = "remuser";
    pi.pam_ruser_size = strlen(pi.pam_ruser) + 1;
    pi.pam_rhost = "remhost";
    pi.pam_rhost_size = strlen(pi.pam_rhost) + 1;
    pi.requested_domains = "";
    pi.cli_pid = 12345;

    ret = pack_message_v3(&pi, &buf_size, &m_buf);
    assert_int_equal(ret, 0);

    buf = talloc_memdup(mem_ctx, m_buf, buf_size);
    free(m_buf);
    assert_non_null(buf);

    will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
    will_return(__wrap_sss_packet_get_body, buf);
    will_return(__wrap_sss_packet_get_body, buf_size);

    if (strrchr(name, '@') == NULL) {
        mock_parse_inp(name, NULL, EOK);
    } else {
        ret = sss_parse_internal_fqname(mem_ctx, name, &s_name, &dom);
        mock_parse_inp(s_name, dom, EOK);
    }

    if (contact_dp) {
        mock_account_recv_simple();
    }
}

static void mock_input_pam(TALLOC_CTX *mem_ctx,
                           const char *name,
                           const char *pwd,
                           const char *fa2)
{
    return mock_input_pam_ex(mem_ctx, name, pwd, fa2, NULL, false);
}

static void mock_input_pam_cert(TALLOC_CTX *mem_ctx, const char *name,
                                const char *pin, const char *token_name,
                                const char *module_name, const char *key_id,
                                const char *label, const char *service,
                                acct_cb_t acct_cb, const char *cert)
{
    size_t buf_size;
    uint8_t *m_buf;
    uint8_t *buf;
    struct pam_items pi = { 0 };
    int ret;
    size_t needed_size;

    if (name != NULL) {
        pi.pam_user = name;
        pi.pam_user_size = strlen(pi.pam_user) + 1;
    } else {
        pi.pam_user = "";
        pi.pam_user_size = 0;
    }

    if (pin != NULL) {
        ret = sss_auth_pack_sc_blob(pin, 0, token_name, 0, module_name, 0,
                                    key_id, 0, label, 0, NULL, 0, &needed_size);
        assert_int_equal(ret, EAGAIN);

        pi.pam_authtok = malloc(needed_size);
        assert_non_null(pi.pam_authtok);

        ret = sss_auth_pack_sc_blob(pin, 0, token_name, 0, module_name, 0,
                                    key_id, 0, label, 0,
                                    (uint8_t *)pi.pam_authtok, needed_size,
                                    &needed_size);
        assert_int_equal(ret, EOK);

        pi.pam_authtok_type = SSS_AUTHTOK_TYPE_SC_PIN;
        pi.pam_authtok_size = needed_size;
    }

    pi.pam_service = service == NULL ? "login" : service;
    pi.pam_service_size = strlen(pi.pam_service) + 1;
    pi.pam_tty = "/dev/tty";
    pi.pam_tty_size = strlen(pi.pam_tty) + 1;
    pi.pam_ruser = "remuser";
    pi.pam_ruser_size = strlen(pi.pam_ruser) + 1;
    pi.pam_rhost = "remhost";
    pi.pam_rhost_size = strlen(pi.pam_rhost) + 1;
    pi.requested_domains = "";
    pi.cli_pid = 12345;

    ret = pack_message_v3(&pi, &buf_size, &m_buf);
    free(pi.pam_authtok);
    assert_int_equal(ret, 0);

    buf = talloc_memdup(mem_ctx, m_buf, buf_size);
    free(m_buf);
    assert_non_null(buf);

    will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
    will_return(__wrap_sss_packet_get_body, buf);
    will_return(__wrap_sss_packet_get_body, buf_size);

    if (acct_cb != NULL) {
        mock_account_recv(0, 0, NULL, acct_cb, discard_const(cert));
    }

    if (name != NULL) {
        mock_parse_inp(name, NULL, EOK);
    }
}

#ifdef BUILD_PASSKEY
static int test_pam_passkey_preauth_check(uint32_t status, uint8_t *body, size_t blen)
{
    size_t rp = 0;
    uint32_t val;

    assert_int_equal(status, 0);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, pam_test_ctx->exp_pam_status);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, 2);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, SSS_PAM_DOMAIN_NAME);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, 9);

    assert_int_equal(*(body + rp + val - 1), 0);
    assert_string_equal((char *)(body + rp), TEST_DOM_NAME);

    return EOK;
}

static int test_pam_passkey_found_preauth_check(uint32_t status, uint8_t *body, size_t blen)
{
    size_t rp = 0;
    uint32_t val;

    assert_int_equal(status, 0);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, pam_test_ctx->exp_pam_status);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, 3);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, SSS_PAM_DOMAIN_NAME);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, 9);

    assert_int_equal(*(body + rp + val - 1), 0);
    assert_string_equal((char *)(body + rp), TEST_DOM_NAME);

    return EOK;
}

void test_passkey_process_data_simple(void **state)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct pk_child_user_data *pk_data;
    struct ldb_message *user_msg;

    tmp_ctx = talloc_new(NULL);
    assert_non_null(tmp_ctx);

    user_msg = ldb_msg_new(tmp_ctx);
    assert_non_null(user_msg);

    ret = ldb_msg_add_string(user_msg, SYSDB_USER_PASSKEY, SSSD_TEST_PASSKEY);
    assert_int_equal(ret, EOK);

    pk_data = talloc_zero(tmp_ctx, struct pk_child_user_data);
    assert_non_null(pk_data);

    ret = process_passkey_data(tmp_ctx, user_msg, TEST_DOM_NAME, pk_data);
    assert_int_equal(ret, EOK);
    assert_int_equal(pk_data->num_credentials, 1);
    for (int i = 0; i < pk_data->num_credentials; i++) {
        assert_non_null(pk_data->key_handles[i]);
        assert_non_null(pk_data->public_keys[i]);
    }
}

void test_passkey_process_data_multi(void **state)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct pk_child_user_data *pk_data;
    struct ldb_message *user_msg;

    tmp_ctx = talloc_new(NULL);
    assert_non_null(tmp_ctx);

    user_msg = ldb_msg_new(tmp_ctx);
    assert_non_null(user_msg);

    /* Two passkey mappings */
    ret = ldb_msg_add_string(user_msg, SYSDB_USER_PASSKEY, SSSD_TEST_PASSKEY);
    assert_int_equal(ret, EOK);

    ret = ldb_msg_add_string(user_msg, SYSDB_USER_PASSKEY, SSSD_TEST_PASSKEY_TWO);
    assert_int_equal(ret, EOK);

    /* Invalid public key to be ignored */
    ret = ldb_msg_add_string(user_msg, SYSDB_USER_PASSKEY, SSSD_TEST_PUBKEY);
    assert_int_equal(ret, EOK);

    /* smartcard cert */
    ret = ldb_msg_add_string(user_msg, SYSDB_USER_PASSKEY, SSSD_TEST_CERT);
    assert_int_equal(ret, EOK);

    pk_data = talloc_zero(tmp_ctx, struct pk_child_user_data);
    assert_non_null(pk_data);

    ret = process_passkey_data(tmp_ctx, user_msg, TEST_DOM_NAME, pk_data);
    assert_int_equal(ret, EOK);
    assert_int_equal(pk_data->num_credentials, 2);
    for (int i = 0; i < pk_data->num_credentials; i++) {
        assert_non_null(pk_data->key_handles[i]);
        assert_non_null(pk_data->public_keys[i]);
    }
}

void test_passkey_process_data_invalid(void **state)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct pk_child_user_data *pk_data;
    struct ldb_message *user_msg;
    struct ldb_message *user_msg2;

    tmp_ctx = talloc_new(NULL);
    assert_non_null(tmp_ctx);

    user_msg = ldb_msg_new(tmp_ctx);
    assert_non_null(user_msg);

    /* Invalid - key handle part of mapping only */
    ret = ldb_msg_add_string(user_msg, SYSDB_USER_PASSKEY, SSSD_TEST_PASSKEY_KEY_HANDLE);
    assert_int_equal(ret, EOK);

    pk_data = talloc_zero(tmp_ctx, struct pk_child_user_data);
    assert_non_null(pk_data);

    ret = process_passkey_data(tmp_ctx, user_msg, TEST_DOM_NAME, pk_data);
    assert_int_equal(ret, ENOENT);
    assert_int_equal(pk_data->num_credentials, 0);

    user_msg2 = ldb_msg_new(tmp_ctx);
    assert_non_null(user_msg2);

    /* Public key only */
    ret = ldb_msg_add_string(user_msg, SYSDB_USER_PASSKEY, SSSD_TEST_PUBKEY);
    assert_int_equal(ret, EOK);
    assert_int_equal(pk_data->num_credentials, 0);
}
#endif /* BUILD_PASSKEY */

static int test_pam_simple_check(uint32_t status, uint8_t *body, size_t blen)
{
    size_t rp = 0;
    uint32_t val;

    assert_int_equal(status, 0);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, pam_test_ctx->exp_pam_status);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, 1);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, SSS_PAM_DOMAIN_NAME);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, 9);

    assert_int_equal(*(body + rp + val - 1), 0);
    assert_string_equal((char *)(body + rp), TEST_DOM_NAME);

    return EOK;
}

#define PKCS11_LOGIN_TOKEN_ENV_NAME "PKCS11_LOGIN_TOKEN_NAME"

static int test_pam_cert_check_gdm_smartcard(uint32_t status, uint8_t *body,
                                             size_t blen)
{
    size_t rp = 0;
    uint32_t val;

    assert_int_equal(status, 0);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, pam_test_ctx->exp_pam_status);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, 3);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, SSS_PAM_DOMAIN_NAME);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, 9);

    assert_int_equal(*(body + rp + val - 1), 0);
    assert_string_equal((char *)(body + rp), TEST_DOM_NAME);
    rp += val;

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, SSS_PAM_ENV_ITEM);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, (strlen(PKCS11_LOGIN_TOKEN_ENV_NAME "=")
                           + sizeof(TEST_TOKEN_NAME)));
    assert_string_equal((char *)(body + rp),
                        PKCS11_LOGIN_TOKEN_ENV_NAME "=" TEST_TOKEN_NAME);
    rp += val;

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, SSS_PAM_CERT_INFO);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, (sizeof("pamuser@"TEST_DOM_NAME)
                                + sizeof(TEST_TOKEN_NAME)
                                + sizeof(TEST_MODULE_NAME)
                                + sizeof(TEST_KEY_ID)
                                + sizeof(TEST_LABEL)
                                + sizeof(TEST_PROMPT)
                                + sizeof("pamuser")));

    assert_int_equal(*(body + rp + sizeof("pamuser@"TEST_DOM_NAME) - 1), 0);
    assert_string_equal((char *)(body + rp), "pamuser@"TEST_DOM_NAME);
    rp += sizeof("pamuser@"TEST_DOM_NAME);

    assert_int_equal(*(body + rp + sizeof(TEST_TOKEN_NAME) - 1), 0);
    assert_string_equal((char *)(body + rp), TEST_TOKEN_NAME);
    rp += sizeof(TEST_TOKEN_NAME);

    assert_int_equal(*(body + rp + sizeof(TEST_MODULE_NAME) - 1), 0);
    assert_string_equal((char *)(body + rp), TEST_MODULE_NAME);
    rp += sizeof(TEST_MODULE_NAME);

    assert_int_equal(*(body + rp + sizeof(TEST_KEY_ID) - 1), 0);
    assert_string_equal((char *)(body + rp), TEST_KEY_ID);
    rp += sizeof(TEST_KEY_ID);

    assert_int_equal(*(body + rp + sizeof(TEST_LABEL) - 1), 0);
    assert_string_equal((char *)(body + rp), TEST_LABEL);
    rp += sizeof(TEST_LABEL);

    assert_int_equal(*(body + rp + sizeof(TEST_PROMPT) - 1), 0);
    assert_string_equal((char *)(body + rp), TEST_PROMPT);
    rp += sizeof(TEST_PROMPT);

    assert_int_equal(*(body + rp + sizeof("pamuser") - 1), 0);
    assert_string_equal((char *)(body + rp), "pamuser");
    rp += sizeof("pamuser");

    assert_int_equal(rp, blen);
    return EOK;
}

static void check_string_array(const char **strs, uint8_t *body, size_t *rp)
{
    size_t c;

    for (c = 0; strs[c] != NULL; c++) {
        assert_int_equal(*(body + *rp + strlen(strs[c])), 0);
        assert_string_equal((char *)(body + *rp), strs[c]);
        *rp += strlen(strs[c]) + 1;
    }
}

static size_t check_string_array_len(const char **strs)
{
    size_t c;
    size_t sum = 0;

    for (c = 0; strs[c] != NULL; c++) {
        sum += strlen(strs[c]) + 1;
    }

    return sum;
}

static int test_pam_cert_check_ex(uint32_t status, uint8_t *body, size_t blen,
                                  enum response_type type, const char *name,
                                  const char *name2, const char *nss_name)
{
    size_t rp = 0;
    uint32_t val;
    bool test2_first = false;

    size_t check_len = 0;
    char const *check_strings[] = { NULL,
                                    TEST_TOKEN_NAME,
                                    TEST_MODULE_NAME,
                                    TEST_KEY_ID,
                                    TEST_LABEL,
                                    TEST_PROMPT,
                                    NULL,
                                    NULL };

    size_t check2_len = 0;
    char const *check2_strings[] = { NULL,
                                     TEST_TOKEN_NAME,
                                     TEST_MODULE_NAME,
                                     TEST2_KEY_ID,
                                     TEST2_LABEL,
                                     TEST2_PROMPT,
                                     NULL,
                                     NULL };

    assert_int_equal(status, 0);

    check_strings[0] = name;
    check_strings[6] = nss_name;
    check_len = check_string_array_len(check_strings);
    check2_strings[0] = name;
    check2_strings[6] = nss_name;
    check2_len = check_string_array_len(check2_strings);


    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, pam_test_ctx->exp_pam_status);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    if (name == NULL || *name == '\0') {
        assert_int_equal(val, 1);
    } else {
        if (name2 == NULL || *name2 == '\0') {
            assert_int_equal(val, 2);
        } else {
            assert_int_equal(val, 3);
        }

        SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
        assert_int_equal(val, SSS_PAM_DOMAIN_NAME);

        SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
        assert_int_equal(val, 9);

        assert_int_equal(*(body + rp + val - 1), 0);
        assert_string_equal((char *)(body + rp), TEST_DOM_NAME);
        rp += val;
    }

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, type);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);

    /* look ahead to check if the certificate #2 comes first */
    if (name2 != NULL && *name2 != '\0'
            && val == check2_len
            && strncmp((char *) body + rp + strlen(name) + 1
                                + sizeof(TEST_TOKEN_NAME)
                                + sizeof(TEST_MODULE_NAME),
                       TEST2_KEY_ID,
                       sizeof(TEST2_KEY_ID)) == 0 ) {
        test2_first = true;

        assert_int_equal(val, check2_len);

        check_string_array(check2_strings, body, &rp);

        SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
        assert_int_equal(val, type);

        SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    }

    assert_int_equal(val, check_len);

    check_string_array(check_strings, body, &rp);

    if (name2 != NULL && *name2 != '\0' && !test2_first) {
        SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
        assert_int_equal(val, type);

        SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
        assert_int_equal(val, check2_len);

        check_string_array(check2_strings, body, &rp);
    }

    assert_int_equal(rp, blen);

    return EOK;
}

static int test_pam_cert2_token2_check_ex(uint32_t status, uint8_t *body,
                                          size_t blen, enum response_type type,
                                          const char *name,
                                          const char *nss_name)
{
    size_t rp = 0;
    uint32_t val;
    size_t check2_len = 0;
    char const *check2_strings[] = { NULL,
                                     TEST_TOKEN2_NAME,
                                     TEST_MODULE_NAME,
                                     TEST2_KEY_ID,
                                     TEST2_LABEL,
                                     TEST2_PROMPT,
                                     NULL,
                                     NULL };

    assert_int_equal(status, 0);

    check2_strings[0] = name;
    check2_strings[6] = nss_name;
    check2_len = check_string_array_len(check2_strings);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, pam_test_ctx->exp_pam_status);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, 2);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, SSS_PAM_DOMAIN_NAME);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, 9);

    assert_int_equal(*(body + rp + val - 1), 0);
    assert_string_equal((char *)(body + rp), TEST_DOM_NAME);
    rp += val;

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, type);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, check2_len);

    check_string_array(check2_strings, body, &rp);

    assert_int_equal(rp, blen);

    return EOK;
}

static int test_pam_cert_X_token_X_check_ex(uint32_t status, uint8_t *body,
                                          size_t blen, enum response_type type,
                                          const char *name,
                                          const char *nss_name,
                                          char const *check_strings[])
{
    size_t rp = 0;
    uint32_t val;
    size_t check_len = 0;

    assert_int_equal(status, 0);

    check_strings[0] = name;
    check_strings[6] = nss_name;
    check_len = check_string_array_len(check_strings);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, pam_test_ctx->exp_pam_status);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, 2);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, SSS_PAM_DOMAIN_NAME);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, 9);

    assert_int_equal(*(body + rp + val - 1), 0);
    assert_string_equal((char *)(body + rp), TEST_DOM_NAME);
    rp += val;

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, type);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, check_len);

    check_string_array(check_strings, body, &rp);

    assert_int_equal(rp, blen);

    return EOK;
}

static int test_pam_cert_check(uint32_t status, uint8_t *body, size_t blen)
{
    return test_pam_cert_check_ex(status, body, blen,
                                  SSS_PAM_CERT_INFO, "pamuser@"TEST_DOM_NAME,
                                  NULL, "pamuser");
}

static int test_pam_cert2_check(uint32_t status, uint8_t *body, size_t blen)
{
    return test_pam_cert2_token2_check_ex(status, body, blen, SSS_PAM_CERT_INFO,
                                          "pamuser@"TEST_DOM_NAME, "pamuser");
}

static int test_pam_cert5_check(uint32_t status, uint8_t *body, size_t blen)
{
    char const *check5_strings[] = { NULL,
                                     TEST_TOKEN_NAME,
                                     TEST_MODULE_NAME,
                                     TEST5_KEY_ID,
                                     TEST5_LABEL,
                                     TEST5_PROMPT,
                                     NULL,
                                     NULL };
    return test_pam_cert_X_token_X_check_ex(status, body, blen,
                                            SSS_PAM_CERT_INFO,
                                          "pamuser@"TEST_DOM_NAME, "pamuser",
                                          check5_strings);
}

static int test_pam_cert8_check(uint32_t status, uint8_t *body, size_t blen)
{
    char const *check5_strings[] = { NULL,
                                     TEST8_TOKEN_NAME,
                                     TEST_MODULE_NAME,
                                     TEST8_KEY_ID,
                                     TEST8_LABEL,
                                     TEST8_PROMPT,
                                     NULL,
                                     NULL };
    return test_pam_cert_X_token_X_check_ex(status, body, blen,
                                            SSS_PAM_CERT_INFO,
                                            "pamuser@"TEST_DOM_NAME, "pamuser",
                                            check5_strings);
}

static int test_pam_cert9_check(uint32_t status, uint8_t *body, size_t blen)
{
    char const *check5_strings[] = { NULL,
                                     TEST9_TOKEN_NAME,
                                     TEST_MODULE_NAME,
                                     TEST9_KEY_ID,
                                     TEST9_LABEL,
                                     TEST9_PROMPT,
                                     NULL,
                                     NULL };
    return test_pam_cert_X_token_X_check_ex(status, body, blen,
                                            SSS_PAM_CERT_INFO,
                                            "pamuser@"TEST_DOM_NAME, "pamuser",
                                            check5_strings);
}

static int test_pam_cert_check_auth_success(uint32_t status, uint8_t *body,
                                            size_t blen)
{
    assert_int_equal(pam_test_ctx->exp_pam_status, PAM_BAD_ITEM);
    pam_test_ctx->exp_pam_status = PAM_SUCCESS;
    return test_pam_cert_check_ex(status, body, blen,
                                  SSS_PAM_CERT_INFO, "pamuser@"TEST_DOM_NAME,
                                  NULL, "pamuser");
}

static int test_pam_cert_check_with_hint(uint32_t status, uint8_t *body,
                                         size_t blen)
{
    return test_pam_cert_check_ex(status, body, blen,
                                  SSS_PAM_CERT_INFO_WITH_HINT,
                                  "pamuser@"TEST_DOM_NAME, NULL,
                                  "pamuser");
}

static int test_pam_cert_check_with_hint_no_user(uint32_t status, uint8_t *body,
                                                 size_t blen)
{
    return test_pam_cert_check_ex(status, body, blen,
                                  SSS_PAM_CERT_INFO_WITH_HINT, "", NULL, "");
}

static int test_pam_cert_check_2certs(uint32_t status, uint8_t *body,
                                      size_t blen)
{
    return test_pam_cert_check_ex(status, body, blen,
                                  SSS_PAM_CERT_INFO, "pamuser@"TEST_DOM_NAME,
                                  "pamuser@"TEST_DOM_NAME,
                                  "pamuser");
}



static int test_pam_offline_chauthtok_check(uint32_t status,
                                            uint8_t *body, size_t blen)
{
    size_t rp = 0;
    uint32_t val;

    pam_test_ctx->exp_pam_status = PAM_AUTHTOK_ERR;

    assert_int_equal(status, 0);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, pam_test_ctx->exp_pam_status);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, 2);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, SSS_PAM_DOMAIN_NAME);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, 9);

    assert_int_equal(*(body + rp + val - 1), 0);
    assert_string_equal((char *)(body + rp), TEST_DOM_NAME);
    rp += val;

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, SSS_PAM_USER_INFO);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, 4);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, SSS_PAM_USER_INFO_OFFLINE_CHPASS);

    return EOK;
}


static int test_pam_failed_offline_auth_check(uint32_t status, uint8_t *body,
                                              size_t blen)
{
    pam_test_ctx->exp_pam_status = PAM_PERM_DENIED;
    return test_pam_simple_check(status, body, blen);
}

static int test_pam_successful_offline_auth_check(uint32_t status,
                                                  uint8_t *body, size_t blen)
{
    pam_test_ctx->exp_pam_status = PAM_SUCCESS;
    return test_pam_simple_check(status, body, blen);
}

static int test_pam_successful_cached_auth_check(uint32_t status,
                                                 uint8_t *body, size_t blen)
{
    pam_test_ctx->exp_pam_status = PAM_SUCCESS;
    return test_pam_simple_check(status, body, blen);
}

static int test_pam_wrong_pw_offline_auth_check(uint32_t status,
                                                uint8_t *body, size_t blen)
{
    pam_test_ctx->exp_pam_status = PAM_AUTH_ERR;
    return test_pam_simple_check(status, body, blen);
}

static int test_pam_simple_check_success(uint32_t status,
                                                uint8_t *body, size_t blen)
{
    pam_test_ctx->exp_pam_status = PAM_SUCCESS;
    return test_pam_simple_check(status, body, blen);
}

static int test_pam_creds_insufficient_check(uint32_t status,
                                             uint8_t *body, size_t blen)
{
    size_t rp = 0;
    uint32_t val;

    assert_int_equal(status, 0);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, PAM_CRED_INSUFFICIENT);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, 0);

    return EOK;
}

static int test_pam_auth_err_check(uint32_t status, uint8_t *body, size_t blen)
{
    /* PAM_AUTH_ERR is returned for different types of error, we use different
     * names for the check functions to make the purpose more clear. */
    return test_pam_wrong_pw_offline_auth_check(status, body, blen);
}

static int test_pam_user_unknown_check(uint32_t status,
                                       uint8_t *body, size_t blen)
{
    size_t rp = 0;
    uint32_t val;

    assert_int_equal(status, 0);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, PAM_USER_UNKNOWN);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, 0);

    return EOK;
}

void test_pam_authenticate(void **state)
{
    int ret;

    mock_input_pam(pam_test_ctx, "pamuser", NULL, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_simple_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_setcreds(void **state)
{
    int ret;

    mock_input_pam(pam_test_ctx, "pamuser", NULL, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_SETCRED);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_simple_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_SETCRED,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_acct_mgmt(void **state)
{
    int ret;

    mock_input_pam(pam_test_ctx, "pamuser", NULL, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_ACCT_MGMT);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_simple_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_ACCT_MGMT,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_open_session(void **state)
{
    int ret;

    mock_input_pam(pam_test_ctx, "pamuser", NULL, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_OPEN_SESSION);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* make sure pam_status is not touched by setting it to a value which is
     * not used by SSSD. */
    pam_test_ctx->exp_pam_status = _PAM_RETURN_VALUES;
    set_cmd_cb(test_pam_simple_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_OPEN_SESSION,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_close_session(void **state)
{
    int ret;

    mock_input_pam(pam_test_ctx, "pamuser", NULL, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_CLOSE_SESSION);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_simple_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_CLOSE_SESSION,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_chauthtok(void **state)
{
    int ret;

    mock_input_pam(pam_test_ctx, "pamuser", NULL, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_CHAUTHTOK);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_simple_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_CHAUTHTOK,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_chauthtok_prelim(void **state)
{
    int ret;

    mock_input_pam(pam_test_ctx, "pamuser", NULL, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_CHAUTHTOK_PRELIM);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_simple_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_CHAUTHTOK_PRELIM,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_preauth(void **state)
{
    int ret;

    mock_input_pam(pam_test_ctx, "pamuser", NULL, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_simple_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

/* Cached on-line authentication */

static void common_test_pam_cached_auth(const char *pwd)
{
    int ret;

    mock_input_pam(pam_test_ctx, "pamuser", pwd, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_SUCCESS;
    set_cmd_cb(test_pam_successful_cached_auth_check);

    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_cached_auth_success(void **state)
{
    int ret;

    common_test_pam_cached_auth("12345");

    /* Back end should be contacted */
    assert_true(pam_test_ctx->provider_contacted);

    ret = sysdb_cache_password(pam_test_ctx->tctx->dom,
                               pam_test_ctx->pam_user_fqdn,
                               "12345");
    assert_int_equal(ret, EOK);

    /* Reset before next call */
    pam_test_ctx->provider_contacted = false;

    pam_test_ctx->tctx->done = false;

    common_test_pam_cached_auth("12345");

    /* Back end should not be contacted */
    assert_false(pam_test_ctx->provider_contacted);
}

void test_pam_cached_auth_wrong_pw(void **state)
{
    int ret;

    ret = sysdb_cache_password(pam_test_ctx->tctx->dom,
                               pam_test_ctx->pam_user_fqdn,
                               "12345");
    assert_int_equal(ret, EOK);

    ret = pam_set_last_online_auth_with_curr_token(pam_test_ctx->tctx->dom,
                                                   pam_test_ctx->pam_user_fqdn,
                                                   time(NULL));
    assert_int_equal(ret, EOK);

    common_test_pam_cached_auth("11111");

    /* Back end should be contacted */
    assert_true(pam_test_ctx->provider_contacted);
}

/* test cached_auth_timeout option */
void test_pam_cached_auth_opt_timeout(void **state)
{
    int ret;
    uint64_t last_online;

    ret = sysdb_cache_password(pam_test_ctx->tctx->dom,
                               pam_test_ctx->pam_user_fqdn,
                               "12345");
    assert_int_equal(ret, EOK);

    last_online = time(NULL) - CACHED_AUTH_TIMEOUT - 1;
    ret = pam_set_last_online_auth_with_curr_token(pam_test_ctx->tctx->dom,
                                                   pam_test_ctx->pam_user_fqdn,
                                                   last_online);
    assert_int_equal(ret, EOK);

    common_test_pam_cached_auth("12345");

    /* Back end should be contacted */
    assert_true(pam_test_ctx->provider_contacted);
}

/* too long since last on-line authentication */
void test_pam_cached_auth_timeout(void **state)
{
    int ret;

    ret = sysdb_cache_password(pam_test_ctx->tctx->dom,
                               pam_test_ctx->pam_user_fqdn,
                               "12345");
    assert_int_equal(ret, EOK);

    ret = pam_set_last_online_auth_with_curr_token(pam_test_ctx->tctx->dom,
                                                   pam_test_ctx->pam_user_fqdn,
                                                   0);
    assert_int_equal(ret, EOK);

    common_test_pam_cached_auth("12345");

    /* Back end should be contacted */
    assert_true(pam_test_ctx->provider_contacted);
}

void test_pam_cached_auth_success_combined_pw_with_cached_2fa(void **state)
{
    int ret;

    common_test_pam_cached_auth("12345678");

    assert_true(pam_test_ctx->provider_contacted);

    ret = sysdb_cache_password_ex(pam_test_ctx->tctx->dom,
                                  pam_test_ctx->pam_user_fqdn,
                                  "12345678", SSS_AUTHTOK_TYPE_2FA, 5);
    assert_int_equal(ret, EOK);

    /* Reset before next call */
    pam_test_ctx->provider_contacted = false;

    pam_test_ctx->tctx->done = false;

    common_test_pam_cached_auth("12345678");

    assert_false(pam_test_ctx->provider_contacted);
}

void test_pam_cached_auth_failed_combined_pw_with_cached_2fa(void **state)
{
    int ret;

    ret = sysdb_cache_password_ex(pam_test_ctx->tctx->dom,
                                  pam_test_ctx->pam_user_fqdn,
                                  "12345678", SSS_AUTHTOK_TYPE_2FA, 5);
    assert_int_equal(ret, EOK);
    ret = pam_set_last_online_auth_with_curr_token(pam_test_ctx->tctx->dom,
                                                   pam_test_ctx->pam_user_fqdn,
                                                   time(NULL));
    assert_int_equal(ret, EOK);

    common_test_pam_cached_auth("1111abcde");

    assert_true(pam_test_ctx->provider_contacted);
}

/* Off-line authentication */

void test_pam_offline_auth_no_hash(void **state)
{
    int ret;

    mock_input_pam(pam_test_ctx, "pamuser", "12345", NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_AUTHINFO_UNAVAIL;

    set_cmd_cb(test_pam_failed_offline_auth_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_offline_auth_success(void **state)
{
    int ret;

    ret = sysdb_cache_password(pam_test_ctx->tctx->dom,
                               pam_test_ctx->pam_user_fqdn,
                               "12345");
    assert_int_equal(ret, EOK);

    mock_input_pam(pam_test_ctx, "pamuser", "12345", NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_AUTHINFO_UNAVAIL;

    set_cmd_cb(test_pam_successful_offline_auth_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_offline_auth_wrong_pw(void **state)
{
    int ret;

    ret = sysdb_cache_password(pam_test_ctx->tctx->dom,
                               pam_test_ctx->pam_user_fqdn,
                               "12345");
    assert_int_equal(ret, EOK);

    mock_input_pam(pam_test_ctx, "pamuser", "11111", NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_AUTHINFO_UNAVAIL;

    set_cmd_cb(test_pam_wrong_pw_offline_auth_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_offline_auth_success_2fa(void **state)
{
    int ret;

    ret = sysdb_cache_password(pam_test_ctx->tctx->dom,
                               pam_test_ctx->pam_user_fqdn,
                               "12345");
    assert_int_equal(ret, EOK);

    mock_input_pam(pam_test_ctx, "pamuser", "12345", "abcde");

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_AUTHINFO_UNAVAIL;

    set_cmd_cb(test_pam_successful_offline_auth_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_offline_auth_failed_2fa(void **state)
{
    int ret;

    ret = sysdb_cache_password(pam_test_ctx->tctx->dom,
                               pam_test_ctx->pam_user_fqdn,
                               "12345");
    assert_int_equal(ret, EOK);

    mock_input_pam(pam_test_ctx, "pamuser", "11111", "abcde");

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_AUTHINFO_UNAVAIL;

    set_cmd_cb(test_pam_wrong_pw_offline_auth_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_offline_auth_success_2fa_with_cached_2fa(void **state)
{
    int ret;

    ret = sysdb_cache_password_ex(pam_test_ctx->tctx->dom,
                                  pam_test_ctx->pam_user_fqdn,
                                  "12345",
                                  SSS_AUTHTOK_TYPE_2FA, 5);
    assert_int_equal(ret, EOK);

    mock_input_pam(pam_test_ctx, "pamuser", "12345", "abcde");

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_AUTHINFO_UNAVAIL;

    set_cmd_cb(test_pam_successful_offline_auth_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_offline_auth_failed_2fa_with_cached_2fa(void **state)
{
    int ret;

    ret = sysdb_cache_password_ex(pam_test_ctx->tctx->dom,
                                  pam_test_ctx->pam_user_fqdn,
                                  "12345",
                                  SSS_AUTHTOK_TYPE_2FA, 5);
    assert_int_equal(ret, EOK);

    mock_input_pam(pam_test_ctx, "pamuser", "11111", "abcde");

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_AUTHINFO_UNAVAIL;

    set_cmd_cb(test_pam_wrong_pw_offline_auth_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_offline_auth_success_pw_with_cached_2fa(void **state)
{
    int ret;

    ret = sysdb_cache_password_ex(pam_test_ctx->tctx->dom,
                                  pam_test_ctx->pam_user_fqdn,
                                  "12345",
                                  SSS_AUTHTOK_TYPE_2FA, 5);
    assert_int_equal(ret, EOK);

    mock_input_pam(pam_test_ctx, "pamuser", "12345", NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_AUTHINFO_UNAVAIL;

    set_cmd_cb(test_pam_successful_offline_auth_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_offline_auth_failed_pw_with_cached_2fa(void **state)
{
    int ret;

    ret = sysdb_cache_password_ex(pam_test_ctx->tctx->dom,
                                  pam_test_ctx->pam_user_fqdn,
                                  "12345",
                                  SSS_AUTHTOK_TYPE_2FA, 5);
    assert_int_equal(ret, EOK);

    mock_input_pam(pam_test_ctx, "pamuser", "11111", NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_AUTHINFO_UNAVAIL;

    set_cmd_cb(test_pam_wrong_pw_offline_auth_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_offline_auth_success_combined_pw_with_cached_2fa(void **state)
{
    int ret;

    ret = sysdb_cache_password_ex(pam_test_ctx->tctx->dom,
                                  pam_test_ctx->pam_user_fqdn,
                                  "12345678", SSS_AUTHTOK_TYPE_2FA, 5);
    assert_int_equal(ret, EOK);

    mock_input_pam(pam_test_ctx, "pamuser", "12345678abcde", NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_AUTHINFO_UNAVAIL;

    set_cmd_cb(test_pam_successful_offline_auth_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_offline_auth_failed_combined_pw_with_cached_2fa(void **state)
{
    int ret;

    ret = sysdb_cache_password_ex(pam_test_ctx->tctx->dom,
                                  pam_test_ctx->pam_user_fqdn,
                                  "12345678", SSS_AUTHTOK_TYPE_2FA, 5);
    assert_int_equal(ret, EOK);

    mock_input_pam(pam_test_ctx, "pamuser", "11111111abcde", NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_AUTHINFO_UNAVAIL;

    set_cmd_cb(test_pam_wrong_pw_offline_auth_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_offline_auth_failed_wrong_2fa_size_with_cached_2fa(void **state)
{
    int ret;

    ret = sysdb_cache_password_ex(pam_test_ctx->tctx->dom,
                                  pam_test_ctx->pam_user_fqdn,
                                  "12345678", SSS_AUTHTOK_TYPE_2FA, 5);
    assert_int_equal(ret, EOK);

    mock_input_pam(pam_test_ctx, "pamuser", "12345678abcd", NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_AUTHINFO_UNAVAIL;

    set_cmd_cb(test_pam_wrong_pw_offline_auth_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_offline_chauthtok_prelim(void **state)
{
    int ret;

    mock_input_pam(pam_test_ctx, "pamuser", NULL, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_CHAUTHTOK_PRELIM);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_AUTHINFO_UNAVAIL;

    set_cmd_cb(test_pam_offline_chauthtok_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_CHAUTHTOK_PRELIM,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_offline_chauthtok(void **state)
{
    int ret;

    mock_input_pam(pam_test_ctx, "pamuser", NULL, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_CHAUTHTOK);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_AUTHINFO_UNAVAIL;

    set_cmd_cb(test_pam_offline_chauthtok_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_CHAUTHTOK,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_preauth_no_logon_name(void **state)
{
    int ret;

    mock_input_pam_cert(pam_test_ctx, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                        NULL, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_creds_insufficient_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_auth_no_upn_logon_name(void **state)
{
    int ret;

    ret = sysdb_cache_password(pam_test_ctx->tctx->dom,
                               pam_test_ctx->pam_user_fqdn,
                               "12345");
    assert_int_equal(ret, EOK);

    mock_input_pam_ex(pam_test_ctx, "upn@"TEST_DOM_NAME, "12345", NULL, NULL,
                      false);
    mock_account_recv_simple();
    mock_parse_inp("upn@"TEST_DOM_NAME, NULL, EOK);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_USER_UNKNOWN;
    set_cmd_cb(test_pam_simple_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_auth_upn_logon_name(void **state)
{
    int ret;
    struct sysdb_attrs *attrs;

    ret = sysdb_cache_password(pam_test_ctx->tctx->dom,
                               pam_test_ctx->pam_user_fqdn,
                               "12345");
    assert_int_equal(ret, EOK);
    attrs = sysdb_new_attrs(pam_test_ctx);
    assert_non_null(attrs);
    ret = sysdb_attrs_add_string(attrs, SYSDB_UPN, "upn@"TEST_DOM_NAME);
    assert_int_equal(ret, EOK);

    ret = sysdb_set_user_attr(pam_test_ctx->tctx->dom,
                              pam_test_ctx->pam_user_fqdn,
                              attrs,
                              LDB_FLAG_MOD_ADD);
    assert_int_equal(ret, EOK);

    mock_input_pam_ex(pam_test_ctx, "upn@"TEST_DOM_NAME, "12345", NULL, NULL,
                      true);

    mock_parse_inp("pamuser", NULL, EOK);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_successful_offline_auth_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}



static void set_cert_auth_param(struct pam_ctx *pctx, const char *dbpath)
{
    pam_test_ctx->pctx->cert_auth = true;
    pam_test_ctx->pctx->ca_db = discard_const(dbpath);
}

void test_pam_preauth_cert_nocert(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);
    unsetenv("SOFTHSM2_CONF");

    mock_input_pam_cert(pam_test_ctx, "pamuser", NULL, NULL, NULL, NULL, NULL,
                        NULL, NULL, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_simple_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

static int test_lookup_by_cert_cb(void *pvt)
{
    int ret;
    struct sysdb_attrs *attrs;
    unsigned char *der = NULL;
    size_t der_size;

    if (pvt != NULL) {

        attrs = sysdb_new_attrs(pam_test_ctx);
        assert_non_null(attrs);

        der = sss_base64_decode(pam_test_ctx, pvt, &der_size);
        assert_non_null(der);

        ret = sysdb_attrs_add_mem(attrs, SYSDB_USER_MAPPED_CERT, der, der_size);
        talloc_free(der);
        assert_int_equal(ret, EOK);

        ret = sysdb_set_user_attr(pam_test_ctx->tctx->dom,
                                  pam_test_ctx->pam_user_fqdn,
                                  attrs,
                                  LDB_FLAG_MOD_ADD);
        assert_int_equal(ret, EOK);
    }

    return EOK;
}

static int test_lookup_by_cert_cb_2nd_cert_same_user(void *pvt)
{
    int ret;
    struct sysdb_attrs *attrs;
    unsigned char *der = NULL;
    size_t der_size;

    test_lookup_by_cert_cb(pvt);

    attrs = sysdb_new_attrs(pam_test_ctx);
    assert_non_null(attrs);

    der = sss_base64_decode(pam_test_ctx, SSSD_TEST_CERT_0002, &der_size);
    assert_non_null(der);

    ret = sysdb_attrs_add_mem(attrs, SYSDB_USER_MAPPED_CERT, der, der_size);
    talloc_free(der);
    assert_int_equal(ret, EOK);

    ret = sysdb_set_user_attr(pam_test_ctx->tctx->dom,
                              pam_test_ctx->pam_user_fqdn,
                              attrs,
                              LDB_FLAG_MOD_ADD);
    assert_int_equal(ret, EOK);

    return EOK;
}

static int test_lookup_by_cert_double_cb(void *pvt)
{
    int ret;
    struct sysdb_attrs *attrs;
    unsigned char *der = NULL;
    size_t der_size;

    if (pvt != NULL) {

        ret = test_lookup_by_cert_cb(pvt);
        assert_int_equal(ret, EOK);

        attrs = sysdb_new_attrs(pam_test_ctx);
        assert_non_null(attrs);

        der = sss_base64_decode(pam_test_ctx, pvt, &der_size);
        assert_non_null(der);

        ret = sysdb_attrs_add_mem(attrs, SYSDB_USER_MAPPED_CERT, der, der_size);
        talloc_free(der);
        assert_int_equal(ret, EOK);

        ret = sysdb_set_user_attr(pam_test_ctx->tctx->dom,
                                  pam_test_ctx->wrong_user_fqdn,
                                  attrs,
                                  LDB_FLAG_MOD_ADD);
        assert_int_equal(ret, EOK);
    }

    return EOK;
}

static int test_lookup_by_cert_wrong_user_cb(void *pvt)
{
    int ret;
    struct sysdb_attrs *attrs;
    unsigned char *der = NULL;
    size_t der_size;

    if (pvt != NULL) {
        attrs = sysdb_new_attrs(pam_test_ctx);
        assert_non_null(attrs);

        der = sss_base64_decode(pam_test_ctx, pvt, &der_size);
        assert_non_null(der);

        ret = sysdb_attrs_add_mem(attrs, SYSDB_USER_MAPPED_CERT, der, der_size);
        talloc_free(der);
        assert_int_equal(ret, EOK);

        ret = sysdb_set_user_attr(pam_test_ctx->tctx->dom,
                                  pam_test_ctx->wrong_user_fqdn,
                                  attrs,
                                  LDB_FLAG_MOD_ADD);
        assert_int_equal(ret, EOK);
    }

    return EOK;
}

static void pam_preauth(struct sss_test_conf_param monitor_params[],
                        acct_cb_t acct_cb, const char *cert,
                        cmd_cb_fn_t fn)
{
    int ret;

    ret = add_monitor_params(monitor_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);

    mock_input_pam_cert(pam_test_ctx, "pamuser", NULL, NULL, NULL, NULL, NULL,
                        NULL, acct_cb, cert);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(fn);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}


void test_pam_preauth_cert_nomatch(void **state)
{
    int ret;

    putenv(discard_const("SOFTHSM2_CONF=" ABS_BUILD_DIR "/src/tests/test_CA/softhsm2_one.conf"));

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);

    mock_input_pam_cert(pam_test_ctx, "pamuser", NULL, NULL, NULL, NULL, NULL,
                        NULL, test_lookup_by_cert_cb, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_simple_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_preauth_cert_match(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);

    mock_input_pam_cert(pam_test_ctx, "pamuser", NULL, NULL, NULL, NULL, NULL,
                        NULL, test_lookup_by_cert_cb, SSSD_TEST_CERT_0001);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_cert_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

/* Test if PKCS11_LOGIN_TOKEN_NAME is added for the gdm-smartcard service */
void test_pam_preauth_cert_match_gdm_smartcard(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);

    mock_input_pam_cert(pam_test_ctx, "pamuser", NULL, NULL, NULL, NULL, NULL,
                        "gdm-smartcard", test_lookup_by_cert_cb,
                        SSSD_TEST_CERT_0001);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_cert_check_gdm_smartcard);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_preauth_cert_match_wrong_user(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);

    mock_input_pam_cert(pam_test_ctx, "pamuser", NULL, NULL, NULL, NULL, NULL,
                        NULL, test_lookup_by_cert_wrong_user_cb,
                        SSSD_TEST_CERT_0001);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_simple_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}


void test_pam_preauth_cert_no_logon_name(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);

    /* If no logon name is given the user is looked by certificate first.
     * Since there is a matching user the upcoming lookup by name will find
     * the user entry. But since we force the lookup by name to go to the
     * backend to make sure the group-membership data is up to date the
     * backend response has to be mocked twice.
     * Additionally sss_parse_inp_recv() must be mocked because the cache
     * request will be done with the username found by the certificate
     * lookup. */
    mock_input_pam_cert(pam_test_ctx, NULL, NULL, NULL, NULL, NULL, NULL,
                        NULL, test_lookup_by_cert_cb, SSSD_TEST_CERT_0001);
    mock_account_recv_simple();
    mock_parse_inp("pamuser", NULL, EOK);
    mock_parse_inp("pamuser", NULL, EOK);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_cert_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_preauth_cert_no_logon_name_with_hint(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);
    pam_test_ctx->rctx->domains->user_name_hint = true;

    /* If no logon name is given the user is looked by certificate first.
     * Since user name hint is enabled we do not have to search the user
     * during pre-auth and there is no need for an extra mocked response as in
     * test_pam_preauth_cert_no_logon_name. */
    mock_input_pam_cert(pam_test_ctx, NULL, NULL, NULL, NULL, NULL, NULL,
                        NULL, test_lookup_by_cert_cb, SSSD_TEST_CERT_0001);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_cert_check_with_hint);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_preauth_cert_no_logon_name_double_cert(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);

    mock_input_pam_cert(pam_test_ctx, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                        test_lookup_by_cert_double_cb, SSSD_TEST_CERT_0001);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_creds_insufficient_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_preauth_cert_no_logon_name_double_cert_with_hint(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);
    pam_test_ctx->rctx->domains->user_name_hint = true;

    mock_input_pam_cert(pam_test_ctx, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                        test_lookup_by_cert_double_cb, SSSD_TEST_CERT_0001);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_cert_check_with_hint_no_user);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_preauth_no_cert_no_logon_name(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, "/no/path");

    mock_input_pam_cert(pam_test_ctx, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                        NULL, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_user_unknown_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_preauth_cert_no_logon_name_no_match(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);

    mock_input_pam_cert(pam_test_ctx, NULL, NULL, NULL, NULL, NULL, NULL,
                        NULL, test_lookup_by_cert_cb, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_user_unknown_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_cert_auth(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);

    /* Here the last option must be set to true because the backend is only
     * connected once. During authentication the backend is connected first to
     * see if it can handle Smartcard authentication, but before that the user
     * is looked up. Since the first mocked reply already adds the certificate
     * to the user entry the lookup by certificate will already find the user
     * in the cache and no second request to the backend is needed. */
    mock_input_pam_cert(pam_test_ctx, "pamuser", "123456", "SSSD Test Token",
                        TEST_MODULE_NAME,
                        "C554C9F82C2A9D58B70921C143304153A8A42F17",
                        "SSSD test cert 0001", NULL,
                        test_lookup_by_cert_cb, SSSD_TEST_CERT_0001);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Assume backend cannot handle Smartcard credentials */
    pam_test_ctx->exp_pam_status = PAM_BAD_ITEM;


    set_cmd_cb(test_pam_simple_check_success);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_pss_cert_auth(void **state)
{
    int ret;

    putenv(discard_const("SOFTHSM2_CONF=" ABS_BUILD_DIR "/src/tests/test_CA/softhsm2_pss_one.conf"));
    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);

    /* Here the last option must be set to true because the backend is only
     * connected once. During authentication the backend is connected first to
     * see if it can handle Smartcard authentication, but before that the user
     * is looked up. Since the first mocked reply already adds the certificate
     * to the user entry the lookup by certificate will already find the user
     * in the cache and no second request to the backend is needed. */
    mock_input_pam_cert(pam_test_ctx, "pamuser", "123456", "SSSD Test Token",
                        TEST_MODULE_NAME,
                        "C554C9F82C2A9D58B70921C143304153A8A42F17",
                        "SSSD test cert 0007", NULL,
                        test_lookup_by_cert_cb, SSSD_TEST_CERT_0007);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Assume backend cannot handle Smartcard credentials */
    pam_test_ctx->exp_pam_status = PAM_BAD_ITEM;


    set_cmd_cb(test_pam_simple_check_success);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_ecc_cert_auth(void **state)
{
    int ret;

    putenv(discard_const("SOFTHSM2_CONF=" ABS_BUILD_DIR "/src/tests/test_ECC_CA/softhsm2_ecc_one.conf"));

    set_cert_auth_param(pam_test_ctx->pctx, ECC_CA_DB);

    /* Here the last option must be set to true because the backend is only
     * connected once. During authentication the backend is connected first to
     * see if it can handle Smartcard authentication, but before that the user
     * is looked up. Since the first mocked reply already adds the certificate
     * to the user entry the lookup by certificate will already find the user
     * in the cache and no second request to the backend is needed. */
    mock_input_pam_cert(pam_test_ctx, "pamuser", "123456",
                        "SSSD Test ECC Token",
                        TEST_MODULE_NAME,
                        "190E513C9A3DFAACDE5D2D0592F0FDFF559C10CB",
                        "SSSD test ECC cert 0001", NULL,
                        test_lookup_by_cert_cb, SSSD_TEST_ECC_CERT_0001);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Assume backend cannot handle Smartcard credentials */
    pam_test_ctx->exp_pam_status = PAM_BAD_ITEM;


    set_cmd_cb(test_pam_simple_check_success);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_intermediate_ca_cert_auth_with_full_certs(void **state)
{
    int ret;

    putenv(discard_const("SOFTHSM2_CONF=" ABS_BUILD_DIR "/src/tests/test_CA/intermediate_CA/softhsm2_intermediate_one.conf"));

    set_cert_auth_param(pam_test_ctx->pctx, INTERMEDIATE_FULL_CA_DB);

    /* Here the last option must be set to true because the backend is only
     * connected once. During authentication the backend is connected first to
     * see if it can handle Smartcard authentication, but before that the user
     * is looked up. Since the first mocked reply already adds the certificate
     * to the user entry the lookup by certificate will already find the user
     * in the cache and no second request to the backend is needed. */
    mock_input_pam_cert(pam_test_ctx, "pamuser", "123456",
                        "SSSD Test intermediate CA Token",
                        TEST_MODULE_NAME,
                        "190E513C9A3DFAACDE5D2D0592F0FDFF559C10CB",
                        "SSSD test intermediate cert 0001", NULL,
                        test_lookup_by_cert_cb,
                        SSSD_TEST_INTERMEDIATE_CA_CERT_0001);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Assume backend cannot handle Smartcard credentials */
    pam_test_ctx->exp_pam_status = PAM_BAD_ITEM;

    set_cmd_cb(test_pam_simple_check_success);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_intermediate_ca_cert_auth_fails_with_incomplete_db(void **state)
{
    int ret;

    putenv(discard_const("SOFTHSM2_CONF=" ABS_BUILD_DIR "/src/tests/test_CA/intermediate_CA/softhsm2_intermediate_one.conf"));

    set_cert_auth_param(pam_test_ctx->pctx, INTERMEDIATE_CA_DB);

    /* Here the last option must be set to true because the backend is only
     * connected once. During authentication the backend is connected first to
     * see if it can handle Smartcard authentication, but before that the user
     * is looked up. Since the first mocked reply already adds the certificate
     * to the user entry the lookup by certificate will already find the user
     * in the cache and no second request to the backend is needed. */
    mock_input_pam_cert(pam_test_ctx, "pamuser", "123456",
                        "SSSD Test intermediate CA Token",
                        TEST_MODULE_NAME,
                        "1234567890",
                        NULL, NULL, NULL,
                        SSSD_TEST_INTERMEDIATE_CA_CERT_0001);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Assume backend cannot handle Smartcard credentials */
    pam_test_ctx->exp_pam_status = PAM_BAD_ITEM;

    set_cmd_cb(test_pam_auth_err_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_intermediate_ca_cert_auth_with_partial_chain(void **state)
{
    int ret;

    struct sss_test_conf_param monitor_params[] = {
        { "certificate_verification", "partial_chain" },
        { NULL, NULL }, /* Sentinel */
    };

    ret = add_monitor_params(monitor_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    putenv(discard_const("SOFTHSM2_CONF=" ABS_BUILD_DIR "/src/tests/test_CA/intermediate_CA/softhsm2_intermediate_one.conf"));

    set_cert_auth_param(pam_test_ctx->pctx, INTERMEDIATE_CA_DB);

    /* Here the last option must be set to true because the backend is only
     * connected once. During authentication the backend is connected first to
     * see if it can handle Smartcard authentication, but before that the user
     * is looked up. Since the first mocked reply already adds the certificate
     * to the user entry the lookup by certificate will already find the user
     * in the cache and no second request to the backend is needed. */
    mock_input_pam_cert(pam_test_ctx, "pamuser", "123456",
                        "SSSD Test intermediate CA Token",
                        TEST_MODULE_NAME,
                        "190E513C9A3DFAACDE5D2D0592F0FDFF559C10CB",
                        "SSSD test intermediate cert 0001", NULL,
                        test_lookup_by_cert_cb,
                        SSSD_TEST_INTERMEDIATE_CA_CERT_0001);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Assume backend cannot handle Smartcard credentials */
    pam_test_ctx->exp_pam_status = PAM_BAD_ITEM;

    set_cmd_cb(test_pam_simple_check_success);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_intermediate_ca_cert_auth_with_full_certs_and_partial_chain(void **state)
{
    int ret;

    struct sss_test_conf_param monitor_params[] = {
        { "certificate_verification", "partial_chain" },
        { NULL, NULL }, /* Sentinel */
    };

    ret = add_monitor_params(monitor_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    putenv(discard_const("SOFTHSM2_CONF=" ABS_BUILD_DIR "/src/tests/test_CA/intermediate_CA/softhsm2_intermediate_one.conf"));

    set_cert_auth_param(pam_test_ctx->pctx, INTERMEDIATE_FULL_CA_DB);

    /* Here the last option must be set to true because the backend is only
     * connected once. During authentication the backend is connected first to
     * see if it can handle Smartcard authentication, but before that the user
     * is looked up. Since the first mocked reply already adds the certificate
     * to the user entry the lookup by certificate will already find the user
     * in the cache and no second request to the backend is needed. */
    mock_input_pam_cert(pam_test_ctx, "pamuser", "123456",
                        "SSSD Test intermediate CA Token",
                        TEST_MODULE_NAME,
                        "190E513C9A3DFAACDE5D2D0592F0FDFF559C10CB",
                        "SSSD test intermediate cert 0001", NULL,
                        test_lookup_by_cert_cb,
                        SSSD_TEST_INTERMEDIATE_CA_CERT_0001);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Assume backend cannot handle Smartcard credentials */
    pam_test_ctx->exp_pam_status = PAM_BAD_ITEM;

    set_cmd_cb(test_pam_simple_check_success);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_intermediate_ca_cert_auth_fails_with_root_and_partial_chain(void **state)
{
    int ret;

    struct sss_test_conf_param monitor_params[] = {
        { "certificate_verification", "partial_chain" },
        { NULL, NULL }, /* Sentinel */
    };

    ret = add_monitor_params(monitor_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    putenv(discard_const("SOFTHSM2_CONF=" ABS_BUILD_DIR "/src/tests/test_CA/intermediate_CA/softhsm2_intermediate_one.conf"));

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);

    /* Here the last option must be set to true because the backend is only
     * connected once. During authentication the backend is connected first to
     * see if it can handle Smartcard authentication, but before that the user
     * is looked up. Since the first mocked reply already adds the certificate
     * to the user entry the lookup by certificate will already find the user
     * in the cache and no second request to the backend is needed. */
    mock_input_pam_cert(pam_test_ctx, "pamuser", "123456",
                        "SSSD Test intermediate CA Token",
                        TEST_MODULE_NAME,
                        "9876543210",
                        NULL, NULL, NULL,
                        SSSD_TEST_INTERMEDIATE_CA_CERT_0001);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Assume backend cannot handle Smartcard credentials */
    pam_test_ctx->exp_pam_status = PAM_BAD_ITEM;

    set_cmd_cb(test_pam_auth_err_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_intermediate_ca_cert_auth_with_partial_chain_pam_option(void **state)
{
    int ret;

    struct sss_test_conf_param pam_params[] = {
        { "pam_cert_verification", "no_ocsp, partial_chain" },
        { NULL, NULL }, /* Sentinel */
    };

    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    putenv(discard_const("SOFTHSM2_CONF=" ABS_BUILD_DIR "/src/tests/test_CA/intermediate_CA/softhsm2_intermediate_one.conf"));

    set_cert_auth_param(pam_test_ctx->pctx, INTERMEDIATE_CA_DB);

    /* Here the last option must be set to true because the backend is only
     * connected once. During authentication the backend is connected first to
     * see if it can handle Smartcard authentication, but before that the user
     * is looked up. Since the first mocked reply already adds the certificate
     * to the user entry the lookup by certificate will already find the user
     * in the cache and no second request to the backend is needed. */
    mock_input_pam_cert(pam_test_ctx, "pamuser", "123456",
                        "SSSD Test intermediate CA Token",
                        TEST_MODULE_NAME,
                        "190E513C9A3DFAACDE5D2D0592F0FDFF559C10CB",
                        "SSSD test intermediate cert 0001", NULL,
                        test_lookup_by_cert_cb,
                        SSSD_TEST_INTERMEDIATE_CA_CERT_0001);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Assume backend cannot handle Smartcard credentials */
    pam_test_ctx->exp_pam_status = PAM_BAD_ITEM;

    set_cmd_cb(test_pam_simple_check_success);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_cert_auth_no_logon_name(void **state)
{
    int ret;

    putenv(discard_const("SOFTHSM2_CONF=" ABS_BUILD_DIR "/src/tests/test_CA/softhsm2_one.conf"));
    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);

    /* Here the last option must be set to true because the backend is only
     * connected once. During authentication the backend is connected first to
     * see if it can handle Smartcard authentication, but before that the user
     * is looked up. Since the first mocked reply already adds the certificate
     * to the user entry the lookup by certificate will already find the user
     * in the cache and no second request to the backend is needed. */
    mock_input_pam_cert(pam_test_ctx, NULL, "123456", "SSSD Test Token",
                        TEST_MODULE_NAME,
                        "C554C9F82C2A9D58B70921C143304153A8A42F17",
                        "SSSD test cert 0001", NULL,
                        test_lookup_by_cert_cb, SSSD_TEST_CERT_0001);

    mock_account_recv_simple();
    mock_parse_inp("pamuser", NULL, EOK);
    mock_parse_inp("pamuser", NULL, EOK);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Assume backend cannot handle Smartcard credentials */
    pam_test_ctx->exp_pam_status = PAM_BAD_ITEM;

    set_cmd_cb(test_pam_cert_check_auth_success);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_cert_auth_no_logon_name_no_key_id(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);

    /* Here the last option must be set to true because the backend is only
     * connected once. During authentication the backend is connected first to
     * see if it can handle Smartcard authentication, but before that the user
     * is looked up. Since the first mocked reply already adds the certificate
     * to the user entry the lookup by certificate will already find the user
     * in the cache and no second request to the backend is needed. */
    mock_input_pam_cert(pam_test_ctx, NULL, "123456", "SSSD Test Token",
                        TEST_MODULE_NAME, NULL, NULL, NULL,
                        NULL, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Assume backend cannot handle Smartcard credentials */
    pam_test_ctx->exp_pam_status = PAM_BAD_ITEM;

    set_cmd_cb(test_pam_creds_insufficient_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_cert_auth_double_cert(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);

    mock_input_pam_cert(pam_test_ctx, "pamuser", "123456", "SSSD Test Token",
                        TEST_MODULE_NAME,
                        "C554C9F82C2A9D58B70921C143304153A8A42F17",
                        "SSSD test cert 0001", NULL,
                        test_lookup_by_cert_double_cb, SSSD_TEST_CERT_0001);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Assume backend cannot handle Smartcard credentials */
    pam_test_ctx->exp_pam_status = PAM_BAD_ITEM;

    set_cmd_cb(test_pam_simple_check_success);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_cert_preauth_2certs_one_mapping(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);
    putenv(discard_const("SOFTHSM2_CONF=" ABS_BUILD_DIR "/src/tests/test_CA/softhsm2_two.conf"));

    ret = test_lookup_by_cert_cb(discard_const(SSSD_TEST_CERT_0001));
    assert_int_equal(ret, EOK);
    mock_input_pam_cert(pam_test_ctx, "pamuser", NULL, NULL, NULL, NULL, NULL,
                        NULL, test_lookup_by_cert_cb, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_cert_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_cert_preauth_2certs_two_mappings(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);
    putenv(discard_const("SOFTHSM2_CONF=" ABS_BUILD_DIR "/src/tests/test_CA/softhsm2_two.conf"));

    mock_input_pam_cert(pam_test_ctx, "pamuser", NULL, NULL, NULL, NULL, NULL,
                        NULL, test_lookup_by_cert_cb_2nd_cert_same_user,
                        SSSD_TEST_CERT_0001);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_cert_check_2certs);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_cert_auth_2certs_one_mapping(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);
    putenv(discard_const("SOFTHSM2_CONF=" ABS_BUILD_DIR "/src/tests/test_CA/softhsm2_two.conf"));

    mock_input_pam_cert(pam_test_ctx, "pamuser", "123456", "SSSD Test Token",
                        TEST_MODULE_NAME,
                        "C554C9F82C2A9D58B70921C143304153A8A42F17",
                        "SSSD test cert 0001", NULL,
                        test_lookup_by_cert_double_cb, SSSD_TEST_CERT_0001);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Assume backend cannot handle Smartcard credentials */
    pam_test_ctx->exp_pam_status = PAM_BAD_ITEM;

    set_cmd_cb(test_pam_simple_check_success);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

/* The following three tests cover a use case where multiple certificates are
 * using the same key-pair. According to PKCS#11 specs "The CKA_ID field is
 * intended to distinguish among multiple keys. In the case of public and
 * private keys, this field assists in handling multiple keys held by the same
 * subject; the key identifier for a public key and its corresponding private
 * key should be the same. The key identifier should also be the same as for
 * the corresponding certificate, if one exists. Cryptoki does not enforce
 * these associations, however." As a result certificates sharing the same
 * key-pair will have the same id on the Smartcard. This means a second
 * parameter is needed to distinguish them. We use the label here.
 *
 * The first test makes sure authentication fails is the label is missing, the
 * second and third test make sure that each certificate can be selected with
 * the proper label. */
void test_pam_cert_auth_2certs_same_id_no_label(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);
    putenv(discard_const("SOFTHSM2_CONF=" ABS_BUILD_DIR "/src/tests/test_CA/softhsm2_2certs_same_id.conf"));

    mock_input_pam_cert(pam_test_ctx, "pamuser", "123456", "SSSD Test Token",
                        TEST_MODULE_NAME,
                        "11111111",
                        NULL, NULL,
                        NULL, SSSD_TEST_CERT_0001);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Assume backend cannot handle Smartcard credentials */
    pam_test_ctx->exp_pam_status = PAM_BAD_ITEM;

    set_cmd_cb(test_pam_auth_err_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_cert_auth_2certs_same_id_with_label_1(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);
    putenv(discard_const("SOFTHSM2_CONF=" ABS_BUILD_DIR "/src/tests/test_CA/softhsm2_2certs_same_id.conf"));

    mock_input_pam_cert(pam_test_ctx, "pamuser", "123456", "SSSD Test Token",
                        TEST_MODULE_NAME,
                        "11111111",
                        "SSSD test cert 0001", NULL,
                        test_lookup_by_cert_double_cb, SSSD_TEST_CERT_0001);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Assume backend cannot handle Smartcard credentials */
    pam_test_ctx->exp_pam_status = PAM_BAD_ITEM;

    set_cmd_cb(test_pam_simple_check_success);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_cert_auth_2certs_same_id_with_label_6(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);
    putenv(discard_const("SOFTHSM2_CONF=" ABS_BUILD_DIR "/src/tests/test_CA/softhsm2_2certs_same_id.conf"));

    mock_input_pam_cert(pam_test_ctx, "pamuser", "123456", "SSSD Test Token",
                        TEST_MODULE_NAME,
                        "11111111",
                        "SSSD test cert 0006", NULL,
                        test_lookup_by_cert_double_cb, SSSD_TEST_CERT_0006);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Assume backend cannot handle Smartcard credentials */
    pam_test_ctx->exp_pam_status = PAM_BAD_ITEM;

    set_cmd_cb(test_pam_simple_check_success);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_cert_preauth_uri_token1(void **state)
{
    int ret;

    struct sss_test_conf_param pam_params[] = {
        { CONFDB_PAM_P11_URI, "pkcs11:token=SSSD%20Test%20Token" },
        { NULL, NULL },             /* Sentinel */
    };

    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);
    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);
    putenv(discard_const("SOFTHSM2_CONF=" ABS_BUILD_DIR "/src/tests/test_CA/softhsm2_2tokens.conf"));

    mock_input_pam_cert(pam_test_ctx, "pamuser", NULL, NULL, NULL, NULL, NULL,
                        NULL, test_lookup_by_cert_cb, SSSD_TEST_CERT_0001);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_cert_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_cert_preauth_uri_token2(void **state)
{
    int ret;

    struct sss_test_conf_param pam_params[] = {
        { CONFDB_PAM_P11_URI, "pkcs11:token=SSSD%20Test%20Token%20Number%202" },
        { NULL, NULL },             /* Sentinel */
    };

    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);
    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);
    putenv(discard_const("SOFTHSM2_CONF=" ABS_BUILD_DIR "/src/tests/test_CA/softhsm2_2tokens.conf"));

    mock_input_pam_cert(pam_test_ctx, "pamuser", NULL, NULL, NULL, NULL, NULL,
                        NULL, test_lookup_by_cert_cb, SSSD_TEST_CERT_0002);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_cert2_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

/* with an expired CRL file no certificate should be returned */
void test_pam_preauth_expired_crl_file(void **state)
{
    int ret;

    struct sss_test_conf_param monitor_params[] = {
        { "certificate_verification", "crl_file=" ABS_BUILD_DIR "/src/tests/test_CA/SSSD_test_CA_expired_crl.pem" },
        { NULL, NULL }, /* Sentinel */
    };

    struct sss_test_conf_param pam_params[] = {
        { CONFDB_PAM_P11_URI, NULL },
        { NULL, NULL },             /* Sentinel */
    };

    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = add_monitor_params(monitor_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);

    mock_input_pam_cert(pam_test_ctx, "pamuser", NULL, NULL, NULL, NULL, NULL,
                        NULL, NULL, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_simple_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_preauth_expired_crl_file_soft(void **state)
{
    int ret;

    struct sss_test_conf_param monitor_params[] = {
        { "certificate_verification", "soft_crl,crl_file=" ABS_BUILD_DIR "/src/tests/test_CA/SSSD_test_CA_expired_crl.pem" },
        { NULL, NULL }, /* Sentinel */
    };

    putenv(discard_const("SOFTHSM2_CONF=" ABS_BUILD_DIR "/src/tests/test_CA/softhsm2_one.conf"));

    ret = add_monitor_params(monitor_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);

    mock_input_pam_cert(pam_test_ctx, "pamuser", NULL, NULL, NULL, NULL, NULL,
                        NULL, test_lookup_by_cert_cb, SSSD_TEST_CERT_0001);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_cert_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

/* with enabled OCSP no certificate should be returned becasuse there is not
 * OCSP responder available. */
void test_pam_preauth_ocsp(void **state)
{
    int ret;

    struct sss_test_conf_param monitor_params[] = {
        { "certificate_verification", NULL },
        { NULL, NULL }, /* Sentinel */
    };

    ret = add_monitor_params(monitor_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);
    putenv(discard_const("SOFTHSM2_CONF=" ABS_BUILD_DIR "/src/tests/test_CA/softhsm2_ocsp.conf"));

    mock_input_pam_cert(pam_test_ctx, "pamuser", NULL, NULL, NULL, NULL, NULL,
                        NULL, NULL, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_simple_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

/* If no_ocsp is set, there should be a certificate returned even if a OCSP
 * URI is set in the certificate. */
void test_pam_preauth_ocsp_no_ocsp(void **state)
{
    int ret;

    struct sss_test_conf_param monitor_params[] = {
        { "certificate_verification", "no_ocsp" },
        { NULL, NULL }, /* Sentinel */
    };

    struct sss_test_conf_param pam_params[] = {
        { CONFDB_PAM_P11_URI, "pkcs11:manufacturer=SoftHSM%20project" },
        { NULL, NULL },             /* Sentinel */
    };

    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);


    ret = add_monitor_params(monitor_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);
    putenv(discard_const("SOFTHSM2_CONF=" ABS_BUILD_DIR "/src/tests/test_CA/softhsm2_ocsp.conf"));

    mock_input_pam_cert(pam_test_ctx, "pamuser", NULL, NULL, NULL, NULL, NULL,
                        NULL, test_lookup_by_cert_cb, SSSD_TEST_CERT_0005);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_cert5_check);

    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

/* If soft_ocsp is set, there should be a certificate returned even if a OCSP
 * URI is set in the certificate. */
void test_pam_preauth_ocsp_soft_ocsp(void **state)
{
    int ret;

    struct sss_test_conf_param monitor_params[] = {
        { "certificate_verification", "soft_ocsp" },
        { NULL, NULL }, /* Sentinel */
    };

    ret = add_monitor_params(monitor_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);
    putenv(discard_const("SOFTHSM2_CONF=" ABS_BUILD_DIR "/src/tests/test_CA/softhsm2_ocsp.conf"));

    mock_input_pam_cert(pam_test_ctx, "pamuser", NULL, NULL, NULL, NULL, NULL,
                        NULL, test_lookup_by_cert_cb, SSSD_TEST_CERT_0005);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_cert5_check);

    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

/* With one valid and one invalid CRL files,
 * a certificate should be returned */
void test_pam_preauth_crl_valid_crl_invalid_files(void **state)
{
    struct sss_test_conf_param monitor_params[] = {
        { "certificate_verification",
            "crl_file=" ABS_BUILD_DIR "/src/tests/test_CA/SSSD_test_CA_crl.pem,"
            "crl_file=" ABS_BUILD_DIR "/src/tests/test_CA/SSSD_test_CA_expired_crl.pem" },
        { NULL, NULL }, /* Sentinel */
    };

    pam_preauth(monitor_params, test_lookup_by_cert_cb, SSSD_TEST_CERT_0001,
                test_pam_cert_check);
}

/* With one CRL from another CA and the other one from the same CA but invalid,
 * no certificate should be returned */
void test_pam_preauth_crl_another_ca_crl_invalid_files(void **state)
{
    struct sss_test_conf_param monitor_params[] = {
        { "certificate_verification",
            "crl_file=" ABS_BUILD_DIR "/src/tests/test_ECC_CA/SSSD_test_ECC_crl.pem,"
            "crl_file=" ABS_BUILD_DIR "/src/tests/test_CA/SSSD_test_CA_expired_crl.pem" },
        { NULL, NULL }, /* Sentinel */
    };

    pam_preauth(monitor_params, NULL, NULL, test_pam_simple_check);
}

/* With one CRL from the same CA but invalid and the other one from another CA,
 * no certificate should be returned */
void test_pam_preauth_crl_invalid_crl_another_ca_files(void **state)
{
    struct sss_test_conf_param monitor_params[] = {
        { "certificate_verification",
            "crl_file=" ABS_BUILD_DIR "/src/tests/test_CA/SSSD_test_CA_expired_crl.pem,"
            "crl_file=" ABS_BUILD_DIR "/src/tests/test_ECC_CA/SSSD_test_ECC_crl.pem" },
        { NULL, NULL }, /* Sentinel */
    };

    pam_preauth(monitor_params, NULL, NULL, test_pam_simple_check);
}

/* With two valid CRL files,
 * the first one from another CA and the second from the same CA,
 * a certificate should be returned */
void test_pam_preauth_first_crl_another_ca_files(void **state)
{
    struct sss_test_conf_param monitor_params[] = {
        { "certificate_verification",
            "crl_file=" ABS_BUILD_DIR "/src/tests/test_ECC_CA/SSSD_test_ECC_crl.pem,"
            "crl_file=" ABS_BUILD_DIR "/src/tests/test_CA/SSSD_test_CA_crl.pem" },
        { NULL, NULL }, /* Sentinel */
    };

    pam_preauth(monitor_params, test_lookup_by_cert_cb, SSSD_TEST_CERT_0001,
                test_pam_cert_check);
}

/* With two valid CRL files,
 * the first one from the same CA and the second from another CA,
 * a certificate should be returned */
void test_pam_preauth_last_crl_another_ca_files(void **state)
{
    struct sss_test_conf_param monitor_params[] = {
        { "certificate_verification",
            "crl_file=" ABS_BUILD_DIR "/src/tests/test_CA/SSSD_test_CA_crl.pem,"
            "crl_file=" ABS_BUILD_DIR "/src/tests/test_ECC_CA/SSSD_test_ECC_crl.pem" },
        { NULL, NULL }, /* Sentinel */
    };

    pam_preauth(monitor_params, test_lookup_by_cert_cb, SSSD_TEST_CERT_0001,
                test_pam_cert_check);
}

/* Expired certificates should always be rejected
 * (test_pam_preauth_cert_expired), only if 'no_verification'
 * is set expired certificates will be allowed
 * (test_pam_preauth_cert_expired_no_verification).
 *
 * The 'soft_crl' option is explicitly tested with expired certificates
 * because it involves a step where all expiration times are ignored. To make
 * sure that expired certificates are still rejected in this case this is
 * tested explicitly (test_pam_preauth_cert_expired_soft_crl). */

void test_pam_preauth_cert_expired(void **state)
{
    int ret;

    putenv(discard_const("SOFTHSM2_CONF=" ABS_BUILD_DIR "/src/tests/test_CA/softhsm2_expired.conf"));

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);

    mock_input_pam_cert(pam_test_ctx, "pamuser", NULL, NULL, NULL, NULL, NULL,
                        NULL, NULL, SSSD_TEST_CERT_0008);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_simple_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_preauth_cert_expired_soft_crl(void **state)
{
    int ret;

    struct sss_test_conf_param monitor_params[] = {
        { "certificate_verification", "soft_crl,crl_file=" ABS_BUILD_DIR "/src/tests/test_CA/SSSD_test_CA_expired_crl.pem" },
        { NULL, NULL }, /* Sentinel */
    };

    putenv(discard_const("SOFTHSM2_CONF=" ABS_BUILD_DIR "/src/tests/test_CA/softhsm2_expired.conf"));

    ret = add_monitor_params(monitor_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);

    mock_input_pam_cert(pam_test_ctx, "pamuser", NULL, NULL, NULL, NULL, NULL,
                        NULL, NULL, SSSD_TEST_CERT_0008);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_simple_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_preauth_cert_expired_no_verification(void **state)
{
    int ret;

    struct sss_test_conf_param monitor_params[] = {
        { "certificate_verification", "no_verification" },
        { NULL, NULL }, /* Sentinel */
    };

    putenv(discard_const("SOFTHSM2_CONF=" ABS_BUILD_DIR "/src/tests/test_CA/softhsm2_expired.conf"));

    ret = add_monitor_params(monitor_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);

    mock_input_pam_cert(pam_test_ctx, "pamuser", NULL, NULL, NULL, NULL, NULL,
                        NULL, test_lookup_by_cert_cb, SSSD_TEST_CERT_0008);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_cert8_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

/* Revoked certificates should be rejected if a CRL listing those certificates
 * as revoked is used (test_pam_preauth_cert_revoked_crl). Even if the CRL is
 * expired and the 'soft_crl' option is used a certificate should be rejected
 * if it is listed in the expired CRL
 * (test_pam_preauth_cert_revoked_soft_crl). Only is no CRL is used the
 * revoked certificate should be allowed as long as it is valid otherwise
 * (test_pam_preauth_cert_revoked).
 * OCSP is not covered by this unit tests. */

void test_pam_preauth_cert_revoked(void **state)
{
    int ret;

    putenv(discard_const("SOFTHSM2_CONF=" ABS_BUILD_DIR "/src/tests/test_CA/softhsm2_revoked.conf"));

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);

    mock_input_pam_cert(pam_test_ctx, "pamuser", NULL, NULL, NULL, NULL, NULL,
                        NULL, test_lookup_by_cert_cb, SSSD_TEST_CERT_0009);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_cert9_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_preauth_cert_revoked_crl(void **state)
{
    int ret;

    struct sss_test_conf_param monitor_params[] = {
        { "certificate_verification", "crl_file=" ABS_BUILD_DIR "/src/tests/test_CA/SSSD_test_CA_crl.pem" },
        { NULL, NULL }, /* Sentinel */
    };

    putenv(discard_const("SOFTHSM2_CONF=" ABS_BUILD_DIR "/src/tests/test_CA/softhsm2_revoked.conf"));

    ret = add_monitor_params(monitor_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);

    mock_input_pam_cert(pam_test_ctx, "pamuser", NULL, NULL, NULL, NULL, NULL,
                        NULL, NULL, SSSD_TEST_CERT_0009);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_simple_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_preauth_cert_revoked_soft_crl(void **state)
{
    int ret;

    struct sss_test_conf_param monitor_params[] = {
        { "certificate_verification", "soft_crl,crl_file=" ABS_BUILD_DIR "/src/tests/test_CA/SSSD_test_CA_expired_crl.pem" },
        { NULL, NULL }, /* Sentinel */
    };

    putenv(discard_const("SOFTHSM2_CONF=" ABS_BUILD_DIR "/src/tests/test_CA/softhsm2_revoked.conf"));

    ret = add_monitor_params(monitor_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    set_cert_auth_param(pam_test_ctx->pctx, CA_DB);

    mock_input_pam_cert(pam_test_ctx, "pamuser", NULL, NULL, NULL, NULL, NULL,
                        NULL, NULL, SSSD_TEST_CERT_0009);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_simple_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_filter_response(void **state)
{
    int ret;
    struct pam_data *pd;
    uint8_t offline_auth_data[(sizeof(uint32_t) + sizeof(int64_t))];
    uint32_t info_type;
    char *env;

    struct sss_test_conf_param pam_params[] = {
        { CONFDB_PAM_VERBOSITY, "1" },
        { CONFDB_PAM_RESPONSE_FILTER, NULL },
        { NULL, NULL },             /* Sentinel */
    };

    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    pd = talloc_zero(pam_test_ctx, struct pam_data);
    assert_non_null(pd);

    pd->service = discard_const("MyService");

    env = talloc_asprintf(pd, "%s=%s", "MyEnv", "abcdef");
    assert_non_null(env);

    ret = pam_add_response(pd, SSS_PAM_ENV_ITEM,
                           strlen(env) + 1, (uint8_t *) env);
    assert_int_equal(ret, EOK);

    info_type = SSS_PAM_USER_INFO_OFFLINE_AUTH;
    memset(offline_auth_data, 0, sizeof(offline_auth_data));
    memcpy(offline_auth_data, &info_type, sizeof(uint32_t));
    ret = pam_add_response(pd, SSS_PAM_USER_INFO,
                           sizeof(offline_auth_data), offline_auth_data);
    assert_int_equal(ret, EOK);

    /* pd->resp_list points to the SSS_PAM_USER_INFO and pd->resp_list->next
     * to the SSS_PAM_ENV_ITEM message. */

    pam_test_ctx->pctx->rctx = pam_test_ctx->rctx;

    /* Test CONFDB_PAM_VERBOSITY option */
    ret = filter_responses(pam_test_ctx->pctx, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_true(pd->resp_list->do_not_send_to_client);
    assert_false(pd->resp_list->next->do_not_send_to_client);

    /* SSS_PAM_USER_INFO_OFFLINE_AUTH message will only be shown with
     * pam_verbosity 2 or above if cache password never expires. */
    pam_params[0].value = "2";
    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = filter_responses(pam_test_ctx->pctx, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_false(pd->resp_list->do_not_send_to_client);
    assert_false(pd->resp_list->next->do_not_send_to_client);

    pam_params[0].value = "0";
    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = filter_responses(pam_test_ctx->pctx, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_true(pd->resp_list->do_not_send_to_client);
    assert_false(pd->resp_list->next->do_not_send_to_client);

    /* Test CONFDB_PAM_RESPONSE_FILTER option */
    talloc_zfree(pam_test_ctx->pctx->pam_filter_opts);
    pam_params[1].value = "NoSuchOption";
    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = filter_responses(pam_test_ctx->pctx, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_true(pd->resp_list->do_not_send_to_client);
    assert_false(pd->resp_list->next->do_not_send_to_client);

    talloc_zfree(pam_test_ctx->pctx->pam_filter_opts);
    pam_params[1].value = "ENV"; /* filter all environment variables */
                                 /* for all services */
    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = filter_responses(pam_test_ctx->pctx, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_true(pd->resp_list->do_not_send_to_client);
    assert_true(pd->resp_list->next->do_not_send_to_client);

    talloc_zfree(pam_test_ctx->pctx->pam_filter_opts);
    pam_params[1].value = "ENV:"; /* filter all environment variables */
    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = filter_responses(pam_test_ctx->pctx, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_true(pd->resp_list->do_not_send_to_client);
    assert_true(pd->resp_list->next->do_not_send_to_client);

    talloc_zfree(pam_test_ctx->pctx->pam_filter_opts);
    pam_params[1].value = "ENV::"; /* filter all environment variables */
    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = filter_responses(pam_test_ctx->pctx, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_true(pd->resp_list->do_not_send_to_client);
    assert_true(pd->resp_list->next->do_not_send_to_client);

    talloc_zfree(pam_test_ctx->pctx->pam_filter_opts);
    pam_params[1].value = "ENV:abc:"; /* variable name does not match */
    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = filter_responses(pam_test_ctx->pctx, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_true(pd->resp_list->do_not_send_to_client);
    assert_false(pd->resp_list->next->do_not_send_to_client);

    talloc_zfree(pam_test_ctx->pctx->pam_filter_opts);
    pam_params[1].value = "ENV:abc:MyService"; /* variable name does not match */
    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = filter_responses(pam_test_ctx->pctx, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_true(pd->resp_list->do_not_send_to_client);
    assert_false(pd->resp_list->next->do_not_send_to_client);

    talloc_zfree(pam_test_ctx->pctx->pam_filter_opts);
    pam_params[1].value = "ENV::abc"; /* service name does not match */
    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = filter_responses(pam_test_ctx->pctx, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_true(pd->resp_list->do_not_send_to_client);
    assert_false(pd->resp_list->next->do_not_send_to_client);

    /* service name does not match */
    talloc_zfree(pam_test_ctx->pctx->pam_filter_opts);
    pam_params[1].value = "ENV:MyEnv:abc";
    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = filter_responses(pam_test_ctx->pctx, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_true(pd->resp_list->do_not_send_to_client);
    assert_false(pd->resp_list->next->do_not_send_to_client);

    talloc_zfree(pam_test_ctx->pctx->pam_filter_opts);
    pam_params[1].value = "ENV:MyEnv"; /* match */
    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = filter_responses(pam_test_ctx->pctx, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_true(pd->resp_list->do_not_send_to_client);
    assert_true(pd->resp_list->next->do_not_send_to_client);

    talloc_zfree(pam_test_ctx->pctx->pam_filter_opts);
    pam_params[1].value = "ENV:MyEnv:"; /* match */
    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = filter_responses(pam_test_ctx->pctx, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_true(pd->resp_list->do_not_send_to_client);
    assert_true(pd->resp_list->next->do_not_send_to_client);

    talloc_zfree(pam_test_ctx->pctx->pam_filter_opts);
    pam_params[1].value = "ENV:MyEnv:MyService"; /* match */
    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = filter_responses(pam_test_ctx->pctx, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_true(pd->resp_list->do_not_send_to_client);
    assert_true(pd->resp_list->next->do_not_send_to_client);

    /* multiple rules with a match */
    talloc_zfree(pam_test_ctx->pctx->pam_filter_opts);
    pam_params[1].value = "ENV:abc:def, "
                          "ENV:MyEnv:MyService, "
                          "ENV:stu:xyz";
    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = filter_responses(pam_test_ctx->pctx, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_true(pd->resp_list->do_not_send_to_client);
    assert_true(pd->resp_list->next->do_not_send_to_client);

    talloc_free(pd);
}

#define ENV_1 "MyEnv=abcdef"
#define ENV_2 "KRB5CCNAME=abc"
void test_filter_response_defaults(void **state)
{
    int ret;
    struct pam_data *pd;
    uint8_t offline_auth_data[(sizeof(uint32_t) + sizeof(int64_t))];
    uint32_t info_type;

    struct sss_test_conf_param pam_params[] = {
        { CONFDB_PAM_VERBOSITY, "1" },
        { CONFDB_PAM_RESPONSE_FILTER, NULL },
        { NULL, NULL },             /* Sentinel */
    };

    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    pd = talloc_zero(pam_test_ctx, struct pam_data);
    assert_non_null(pd);

    /* Currently only KRB5CCNAME is filtered for sudo and sudo-i, so all other
     * environment variables and all other services should not be affected */
    pd->service = discard_const("MyService");

    ret = pam_add_response(pd, SSS_PAM_ENV_ITEM,
                           strlen(ENV_1) + 1, (const uint8_t *) ENV_1);
    assert_int_equal(ret, EOK);

    ret = pam_add_response(pd, SSS_PAM_ENV_ITEM,
                           strlen(ENV_2) + 1, (const uint8_t *) ENV_2);
    assert_int_equal(ret, EOK);

    info_type = SSS_PAM_USER_INFO_OFFLINE_AUTH;
    memset(offline_auth_data, 0, sizeof(offline_auth_data));
    memcpy(offline_auth_data, &info_type, sizeof(uint32_t));
    ret = pam_add_response(pd, SSS_PAM_USER_INFO,
                           sizeof(offline_auth_data), offline_auth_data);
    assert_int_equal(ret, EOK);

    /* pd->resp_list points to the SSS_PAM_USER_INFO and pd->resp_list->next
     * to the SSS_PAM_ENV_ITEM message with KRB5CCNAME and
     * pd->resp_list->next->next to the SSS_PAM_ENV_ITEM message with MyEnv. */

    pam_test_ctx->pctx->rctx = pam_test_ctx->rctx;


    ret = filter_responses(pam_test_ctx->pctx, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_true(pd->resp_list->do_not_send_to_client);
    assert_false(pd->resp_list->next->do_not_send_to_client);
    assert_false(pd->resp_list->next->next->do_not_send_to_client);

    pd->service = discard_const("sudo");
    ret = filter_responses(pam_test_ctx->pctx, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_true(pd->resp_list->do_not_send_to_client);
    assert_true(pd->resp_list->next->do_not_send_to_client);
    assert_false(pd->resp_list->next->next->do_not_send_to_client);

    pd->service = discard_const("sudo-i");
    ret = filter_responses(pam_test_ctx->pctx, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_true(pd->resp_list->do_not_send_to_client);
    assert_true(pd->resp_list->next->do_not_send_to_client);
    assert_false(pd->resp_list->next->next->do_not_send_to_client);

    talloc_free(pd);
}

static int pam_test_setup_appsvc_posix_dom(void **state)
{
    int ret;

    ret = pam_test_setup(state);
    if (ret != EOK) {
        return ret;
    }

    /* This config option is only read on startup, which is not executed
     * in test, so we can't just pass in a param
     */
    pam_test_ctx->pctx->app_services[0] = discard_const("app_svc");
    return 0;
}

void test_appsvc_posix_dom(void **state)
{
    int ret;

    /* The domain is POSIX, the request will skip over it */
    mock_input_pam_ex(pam_test_ctx, "pamuser", NULL, NULL, "app_svc", false);
    mock_parse_inp("pamuser", NULL, EOK);
    pam_test_ctx->exp_pam_status = PAM_USER_UNKNOWN;

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_user_unknown_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_not_appsvc_posix_dom(void **state)
{
    int ret;

    /* A different service than the app one can authenticate against a POSIX domain */
    mock_input_pam_ex(pam_test_ctx, "pamuser", NULL, NULL, "not_app_svc", false);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_simple_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

static int pam_test_setup_appsvc_app_dom(void **state)
{
    struct sss_test_conf_param dom_params[] = {
        { "domain_type", "application" },
        { NULL, NULL },             /* Sentinel */
    };
    struct sss_test_conf_param pam_params[] = {
        { NULL, NULL },             /* Sentinel */
    };
    struct sss_test_conf_param monitor_params[] = {
        { NULL, NULL },             /* Sentinel */
    };


    test_pam_setup(dom_params, pam_params, monitor_params, state);
    pam_test_setup_common();

    /* This config option is only read on startup, which is not executed
     * in test, so we can't just pass in a param
     */
    pam_test_ctx->pctx->app_services[0] = discard_const("app_svc");
    return 0;
}

void test_appsvc_app_dom(void **state)
{
    int ret;

    /* The domain is POSIX, the request will skip over it */
    mock_input_pam_ex(pam_test_ctx, "pamuser", NULL, NULL, "app_svc", false);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_simple_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_not_appsvc_app_dom(void **state)
{
    int ret;

    /* A different service than the app one can authenticate against a POSIX domain */
    mock_input_pam_ex(pam_test_ctx, "pamuser", NULL, NULL, "not_app_svc", false);
    mock_parse_inp("pamuser", NULL, EOK);

    pam_test_ctx->exp_pam_status = PAM_USER_UNKNOWN;

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_user_unknown_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

#define MY_PW_PROMPT "my_pw_prompt"
#define MY_2FA_SINGLE_PROMPT "my_2fa_single_prompt"
#define MY_FIRST_PROMPT "my_first_prompt"
#define MY_SECOND_PROMPT "my_second_prompt"
#define MY_PASSKEY_INTERACTIVE_PROMPT "my_passkey_interactive_prompt"
#define MY_PASSKEY_TOUCH_PROMPT "my_passkey_touch_prompt"
#define MY_SERVICE "my_service"

static int pam_test_setup_pw_prompt(void **state)
{
    int ret;

    struct sss_test_conf_param prompt_params[] = {
        { "password_prompt", MY_PW_PROMPT},
        { NULL, NULL },             /* Sentinel */
    };

    ret = pam_test_setup(state);
    assert_int_equal(ret, EOK);

    ret = add_confdb_params(prompt_params, pam_test_ctx->rctx->cdb, CONFDB_PC_CONF_ENTRY "/" CONFDB_PC_TYPE_PASSWORD);
    assert_int_equal(ret, EOK);

    return 0;
}

static int test_pam_prompt_check(uint32_t status, uint8_t *body, size_t blen)
{
    size_t rp = 0;
    uint32_t val;
    uint8_t val8t;
    int ret;
    struct prompt_config **pc = NULL;

    assert_int_equal(status, 0);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, pam_test_ctx->exp_pam_status);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, 3);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, SSS_PAM_PROMPT_CONFIG);
    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    ret = pc_list_from_response(val, body + rp, &pc);
    assert_int_equal(ret, EOK);
    assert_non_null(pc[0]);
    assert_int_equal(pc_get_type(pc[0]), pam_test_ctx->exp_prompt_config_type);
    switch (pam_test_ctx->exp_prompt_config_type) {
    case PC_TYPE_PASSWORD:
        assert_string_equal(pc_get_password_prompt(pc[0]), MY_PW_PROMPT);
        break;
    case PC_TYPE_2FA_SINGLE:
        assert_string_equal(pc_get_2fa_single_prompt(pc[0]), MY_2FA_SINGLE_PROMPT);
        break;
    case PC_TYPE_2FA:
        assert_string_equal(pc_get_2fa_1st_prompt(pc[0]), MY_FIRST_PROMPT);
        assert_string_equal(pc_get_2fa_2nd_prompt(pc[0]), MY_SECOND_PROMPT);
        break;
#ifdef BUILD_PASSKEY
    case PC_TYPE_PASSKEY:
        assert_string_equal(pc_get_passkey_inter_prompt(pc[0]), MY_PASSKEY_INTERACTIVE_PROMPT);
        assert_string_equal(pc_get_passkey_touch_prompt(pc[0]), pam_test_ctx->exp_touch_prompt);
        break;
#endif
    default:
        assert_false(true);
    }
    assert_null(pc[1]);
    pc_list_free(pc);
    rp += val;

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, SSS_PAM_DOMAIN_NAME);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, 9);
    assert_string_equal((char *)(body + rp), TEST_DOM_NAME);
    rp += val;


    switch (pam_test_ctx->exp_prompt_config_type) {
    case PC_TYPE_PASSWORD:
        SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
        assert_int_equal(val, SSS_PASSWORD_PROMPTING);
        SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
        assert_int_equal(val, 0);
        break;
    case PC_TYPE_2FA_SINGLE:
    case PC_TYPE_2FA:
        SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
        assert_int_equal(val, SSS_PAM_OTP_INFO);
        SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
        assert_int_equal(val, 3);
        SAFEALIGN_COPY_UINT8_CHECK(&val8t, body + rp, blen, &rp);
        assert_int_equal(val8t, 0);
        SAFEALIGN_COPY_UINT8_CHECK(&val8t, body + rp, blen, &rp);
        assert_int_equal(val8t, 0);
        SAFEALIGN_COPY_UINT8_CHECK(&val8t, body + rp, blen, &rp);
        assert_int_equal(val8t, 0);
        break;
#ifdef BUILD_PASSKEY
    case PC_TYPE_PASSKEY:
        SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
        assert_int_equal(val, SSS_PAM_PASSKEY_INFO);
        SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
        assert_int_equal(val, 5);
        rp += val;
        break;
#endif
    default:
        assert_false(true);
    }

    assert_int_equal(rp, blen);

    return EOK;
}

void test_pam_prompting_password(void **state)
{
    int ret;

    pam_test_ctx->pctx->prompting_config_sections = NULL;
    pam_test_ctx->pctx->num_prompting_config_sections = 0;
    ret = confdb_get_sub_sections(pam_test_ctx->pctx, pam_test_ctx->pctx->rctx->cdb, CONFDB_PC_CONF_ENTRY,
                                  &pam_test_ctx->pctx->prompting_config_sections,
                                  &pam_test_ctx->pctx->num_prompting_config_sections);
    assert_int_equal(ret, EOK);

    ret = pam_add_response(pam_test_ctx->pd, SSS_PASSWORD_PROMPTING, 0, NULL);
    assert_int_equal(ret, EOK);

    mock_input_pam(pam_test_ctx, "pamuser", NULL, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_prompt_config_type = PC_TYPE_PASSWORD;
    set_cmd_cb(test_pam_prompt_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

static int pam_test_setup_2fa_single_prompt(void **state)
{
    int ret;

    struct sss_test_conf_param prompt_params[] = {
        { "first_prompt", MY_2FA_SINGLE_PROMPT},
        { "single_prompt", "true"},
        { NULL, NULL },             /* Sentinel */
    };

    ret = pam_test_setup(state);
    assert_int_equal(ret, EOK);

    ret = add_confdb_params(prompt_params, pam_test_ctx->rctx->cdb, CONFDB_PC_CONF_ENTRY "/" CONFDB_PC_TYPE_2FA);
    assert_int_equal(ret, EOK);

    return 0;
}

void test_pam_prompting_2fa_single(void **state)
{
    int ret;
    uint8_t otp_info[3] = { '\0' };

    pam_test_ctx->pctx->prompting_config_sections = NULL;
    pam_test_ctx->pctx->num_prompting_config_sections = 0;
    ret = confdb_get_sub_sections(pam_test_ctx->pctx, pam_test_ctx->pctx->rctx->cdb, CONFDB_PC_CONF_ENTRY,
                                  &pam_test_ctx->pctx->prompting_config_sections,
                                  &pam_test_ctx->pctx->num_prompting_config_sections);
    assert_int_equal(ret, EOK);

    ret = pam_add_response(pam_test_ctx->pd, SSS_PAM_OTP_INFO, 3, otp_info);
    assert_int_equal(ret, EOK);

    mock_input_pam(pam_test_ctx, "pamuser", NULL, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_prompt_config_type = PC_TYPE_2FA_SINGLE;
    set_cmd_cb(test_pam_prompt_check);

    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

static int pam_test_setup_2fa_single_and_service_prompt(void **state)
{
    int ret;

    struct sss_test_conf_param prompt_service_params[] = {
        { "first_prompt", MY_FIRST_PROMPT},
        { "second_prompt", MY_SECOND_PROMPT},
        { NULL, NULL },             /* Sentinel */
    };

    ret = pam_test_setup_2fa_single_prompt(state);
    assert_int_equal(ret, EOK);

    ret = add_confdb_params(prompt_service_params, pam_test_ctx->rctx->cdb, CONFDB_PC_CONF_ENTRY "/" CONFDB_PC_TYPE_2FA "/" MY_SERVICE);
    assert_int_equal(ret, EOK);

    return 0;
}

void test_pam_prompting_2fa_single_and_service_glob(void **state)
{
    int ret;
    uint8_t otp_info[3] = { '\0' };

    pam_test_ctx->pctx->prompting_config_sections = NULL;
    pam_test_ctx->pctx->num_prompting_config_sections = 0;
    ret = confdb_get_sub_sections(pam_test_ctx->pctx, pam_test_ctx->pctx->rctx->cdb, CONFDB_PC_CONF_ENTRY,
                                  &pam_test_ctx->pctx->prompting_config_sections,
                                  &pam_test_ctx->pctx->num_prompting_config_sections);
    assert_int_equal(ret, EOK);

    ret = pam_add_response(pam_test_ctx->pd, SSS_PAM_OTP_INFO, 3, otp_info);
    assert_int_equal(ret, EOK);

    mock_input_pam(pam_test_ctx, "pamuser", NULL, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_prompt_config_type = PC_TYPE_2FA_SINGLE;
    set_cmd_cb(test_pam_prompt_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_prompting_2fa_single_and_service_srv(void **state)
{
    int ret;
    uint8_t otp_info[3] = { '\0' };

    pam_test_ctx->pctx->prompting_config_sections = NULL;
    pam_test_ctx->pctx->num_prompting_config_sections = 0;
    ret = confdb_get_sub_sections(pam_test_ctx->pctx, pam_test_ctx->pctx->rctx->cdb, CONFDB_PC_CONF_ENTRY,
                                  &pam_test_ctx->pctx->prompting_config_sections,
                                  &pam_test_ctx->pctx->num_prompting_config_sections);
    assert_int_equal(ret, EOK);

    ret = pam_add_response(pam_test_ctx->pd, SSS_PAM_OTP_INFO, 3, otp_info);
    assert_int_equal(ret, EOK);

    mock_input_pam_ex(pam_test_ctx, "pamuser", NULL, NULL, MY_SERVICE, false);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_prompt_config_type = PC_TYPE_2FA;
    set_cmd_cb(test_pam_prompt_check);

    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

#ifdef BUILD_PASSKEY
static int pam_test_setup_passkey_interactive_and_touch_prompt(void **state)
{
    int ret;

    struct sss_test_conf_param prompt_params[] = {
        { "interactive", "true"},
        { "interactive_prompt", MY_PASSKEY_INTERACTIVE_PROMPT},
        { "touch", "true"},
        { "touch_prompt", MY_PASSKEY_TOUCH_PROMPT},
        { NULL, NULL },             /* Sentinel */
    };

    ret = pam_test_setup(state);
    assert_int_equal(ret, EOK);

    ret = add_confdb_params(prompt_params, pam_test_ctx->rctx->cdb, CONFDB_PC_CONF_ENTRY "/" CONFDB_PC_TYPE_PASSKEY);
    assert_int_equal(ret, EOK);

    return 0;
}

static int pam_test_setup_passkey_interactive_prompt(void **state)
{
    int ret;

    struct sss_test_conf_param prompt_params[] = {
        { "interactive", "true"},
        { "interactive_prompt", MY_PASSKEY_INTERACTIVE_PROMPT},
        { NULL, NULL },             /* Sentinel */
    };

    ret = pam_test_setup(state);
    assert_int_equal(ret, EOK);

    ret = add_confdb_params(prompt_params, pam_test_ctx->rctx->cdb, CONFDB_PC_CONF_ENTRY "/" CONFDB_PC_TYPE_PASSKEY);
    assert_int_equal(ret, EOK);

    return 0;
}

void test_pam_prompting_passkey_interactive(void **state)
{
    int ret;
    const char *prompt_pin = "true";

    pam_test_ctx->pctx->prompting_config_sections = NULL;
    pam_test_ctx->pctx->num_prompting_config_sections = 0;
    ret = confdb_get_sub_sections(pam_test_ctx->pctx, pam_test_ctx->pctx->rctx->cdb, CONFDB_PC_CONF_ENTRY,
                                  &pam_test_ctx->pctx->prompting_config_sections,
                                  &pam_test_ctx->pctx->num_prompting_config_sections);
    assert_int_equal(ret, EOK);

    ret = pam_add_response(pam_test_ctx->pd, SSS_PAM_PASSKEY_INFO, strlen(prompt_pin) + 1,
                           (const uint8_t *)prompt_pin);
    assert_int_equal(ret, EOK);

    mock_input_pam(pam_test_ctx, "pamuser", NULL, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_prompt_config_type = PC_TYPE_PASSKEY;
    pam_test_ctx->exp_touch_prompt = "";
    set_cmd_cb(test_pam_prompt_check);

    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_prompting_passkey_interactive_and_touch(void **state)
{
    int ret;
    const char *prompt_pin = "true";

    pam_test_ctx->pctx->prompting_config_sections = NULL;
    pam_test_ctx->pctx->num_prompting_config_sections = 0;
    ret = confdb_get_sub_sections(pam_test_ctx->pctx, pam_test_ctx->pctx->rctx->cdb, CONFDB_PC_CONF_ENTRY,
                                  &pam_test_ctx->pctx->prompting_config_sections,
                                  &pam_test_ctx->pctx->num_prompting_config_sections);
    assert_int_equal(ret, EOK);

    ret = pam_add_response(pam_test_ctx->pd, SSS_PAM_PASSKEY_INFO, strlen(prompt_pin) + 1,
                           (const uint8_t *)prompt_pin);
    assert_int_equal(ret, EOK);

    mock_input_pam(pam_test_ctx, "pamuser", NULL, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_prompt_config_type = PC_TYPE_PASSKEY;
    pam_test_ctx->exp_touch_prompt = MY_PASSKEY_TOUCH_PROMPT;
    set_cmd_cb(test_pam_prompt_check);

    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_passkey_preauth_no_passkey(void **state)
{
    int ret;

    set_passkey_auth_param(pam_test_ctx->pctx);

    mock_input_pam_passkey(pam_test_ctx, "pamuser", "1234",
                                         NULL, NULL, NULL);

    /* sss_parse_inp_recv() is called twice
     * multiple cache req calls */
    mock_parse_inp("pamuser", NULL, EOK);
    mock_parse_inp("pamuser", NULL, EOK);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_SUCCESS;
    set_cmd_cb(test_pam_passkey_preauth_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_passkey_preauth_found(void **state)
{
    int ret;
    struct sysdb_attrs *attrs;
    const char *passkey = SSSD_TEST_PASSKEY;
    size_t pk_size;
    const char *user_verification = "on";

    set_passkey_auth_param(pam_test_ctx->pctx);

    /* Add user verification attribute */
    ret = sysdb_domain_update_passkey_user_verification(
                        pam_test_ctx->tctx->dom->sysdb,
                        pam_test_ctx->tctx->dom->name,
                        user_verification);
    assert_int_equal(ret, EOK);

    mock_input_pam_passkey(pam_test_ctx, "pamuser", "1234", NULL,
                                         NULL, SSSD_TEST_PASSKEY);
    mock_parse_inp("pamuser", NULL, EOK);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);


    /* Add the test passkey data for this user */
    pk_size = strlen(passkey) + 1;

    attrs = sysdb_new_attrs(pam_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_mem(attrs, SYSDB_USER_PASSKEY, passkey, pk_size);
    assert_int_equal(ret, EOK);

    ret = sysdb_set_user_attr(pam_test_ctx->tctx->dom,
                              pam_test_ctx->pam_user_fqdn,
                              attrs,
                              LDB_FLAG_MOD_ADD);
    assert_int_equal(ret, EOK);

    pam_test_ctx->exp_pam_status = PAM_SUCCESS;
    set_cmd_cb(test_pam_passkey_found_preauth_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_passkey_auth(void **state)
{
    int ret;
    struct sysdb_attrs *attrs;
    const char *passkey = SSSD_TEST_PASSKEY;
    size_t pk_size;
    const char *user_verification = "on";

    set_passkey_auth_param(pam_test_ctx->pctx);

    /* Add user verification attribute  */
    ret = sysdb_domain_update_passkey_user_verification(
                        pam_test_ctx->tctx->dom->sysdb,
                        pam_test_ctx->tctx->dom->name,
                        user_verification);
    assert_int_equal(ret, EOK);

    mock_input_pam_passkey(pam_test_ctx, "pamuser", "1234", NULL,
                                         NULL, SSSD_TEST_PASSKEY);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Add the test passkey data for this user */
    pk_size = strlen(passkey) + 1;

    attrs = sysdb_new_attrs(pam_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_mem(attrs, SYSDB_USER_PASSKEY, passkey, pk_size);
    assert_int_equal(ret, EOK);

    ret = sysdb_set_user_attr(pam_test_ctx->tctx->dom,
                              pam_test_ctx->pam_user_fqdn,
                              attrs,
                              LDB_FLAG_MOD_ADD);
    assert_int_equal(ret, EOK);

    pam_test_ctx->exp_pam_status = PAM_SUCCESS;
    set_cmd_cb(test_pam_passkey_auth_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_passkey_pubkey_mapping(void **state)
{
    int ret;
    struct sysdb_attrs *attrs;
    const char *pubkey = SSSD_TEST_PUBKEY;
    size_t pk_size;
    const char *user_verification = "on";

    set_passkey_auth_param(pam_test_ctx->pctx);

    /* Add user verification attribute  */
    ret = sysdb_domain_update_passkey_user_verification(
                        pam_test_ctx->tctx->dom->sysdb,
                        pam_test_ctx->tctx->dom->name,
                        user_verification);
    assert_int_equal(ret, EOK);

    mock_input_pam_passkey(pam_test_ctx, "pamuser", "1234", NULL,
                                         NULL, SSSD_TEST_PASSKEY);
    mock_parse_inp("pamuser", NULL, EOK);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Add the test invalid pubkey data for this user */
    pk_size = strlen(pubkey) + 1;

    attrs = sysdb_new_attrs(pam_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_mem(attrs, SYSDB_USER_PASSKEY, pubkey, pk_size);
    assert_int_equal(ret, EOK);

    ret = sysdb_set_user_attr(pam_test_ctx->tctx->dom,
                              pam_test_ctx->pam_user_fqdn,
                              attrs,
                              LDB_FLAG_MOD_ADD);
    assert_int_equal(ret, EOK);

    pam_test_ctx->exp_pam_status = PAM_SUCCESS;
    set_cmd_cb(test_pam_passkey_auth_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_passkey_preauth_mapping_multi(void **state)
{
    int ret;
    const char *user_verification = "on";
    struct sysdb_attrs *attrs;
    const char *passkey = SSSD_TEST_PASSKEY;
    const char *pubkey = SSSD_TEST_PUBKEY;
    size_t passkey_size;
    size_t pubkey_size;

    set_passkey_auth_param(pam_test_ctx->pctx);

    /* Add user verification attribute  */
    ret = sysdb_domain_update_passkey_user_verification(
                        pam_test_ctx->tctx->dom->sysdb,
                        pam_test_ctx->tctx->dom->name,
                        user_verification);
    assert_int_equal(ret, EOK);

    mock_input_pam_passkey(pam_test_ctx, "pamuser", "1234",
                                         NULL, NULL, SSSD_TEST_PASSKEY);

    mock_parse_inp("pamuser", NULL, EOK);

    /* Add passkey data first, then pubkey mapping data */
    passkey_size = strlen(passkey) + 1;
    pubkey_size = strlen(pubkey) + 1;

    attrs = sysdb_new_attrs(pam_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_mem(attrs, SYSDB_USER_PASSKEY, passkey, passkey_size);
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_mem(attrs, SYSDB_USER_PASSKEY, pubkey, pubkey_size);
    assert_int_equal(ret, EOK);

    ret = sysdb_set_user_attr(pam_test_ctx->tctx->dom,
                              pam_test_ctx->pam_user_fqdn,
                              attrs,
                              LDB_FLAG_MOD_ADD);
    assert_int_equal(ret, EOK);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_SUCCESS;
    set_cmd_cb(test_pam_passkey_found_preauth_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_passkey_auth_send(void **state)
{
    enum passkey_user_verification uv = PAM_PASSKEY_VERIFICATION_ON;
    struct tevent_req *req;
    struct pk_child_user_data *pk_data;
    struct pam_items pi = { 0 };
    errno_t ret;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(global_talloc_context);
    assert_non_null(tmp_ctx);
    check_leaks_push(tmp_ctx);

    pk_data = talloc_zero(tmp_ctx, struct pk_child_user_data);
    assert_non_null(pk_data);
    pk_data->public_keys = talloc_zero_array(pk_data, const char *, 2);
    pk_data->public_keys[0] = talloc_strdup(pk_data->public_keys, SSSD_TEST_PASSKEY_PK);
    pk_data->key_handles = talloc_zero_array(pk_data, const char *, 2);
    pk_data->key_handles[0] = talloc_strdup(pk_data->key_handles, SSSD_TEST_PASSKEY_KEY_HANDLE);

    /* pam data */
    pi.pam_authtok = discard_const("1234");
    pi.pam_authtok_size = strlen(pi.pam_authtok) + 1;
    pi.pam_authtok_type = SSS_AUTHTOK_TYPE_PASSKEY;
    pam_test_ctx->pd->user = discard_const("pamuser");
    pi.pam_user = "pamuser";
    pi.pam_user_size = strlen(pi.pam_user) + 1;

    req = pam_passkey_auth_send(tmp_ctx, pam_test_ctx->tctx->ev,
                                10, false, uv, pam_test_ctx->pd,
                                pk_data, false);
    assert_non_null(req);
    tevent_req_set_callback(req, passkey_test_done, pam_test_ctx);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
    assert_true(WIFEXITED(pam_test_ctx->child_status));
    assert_int_equal(WEXITSTATUS(pam_test_ctx->child_status), 0);

    talloc_free(tmp_ctx);
}
#endif
int main(int argc, const char *argv[])
{
    poptContext pc;
    int opt;
    int res;
    const char *single = NULL;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        { "no-cleanup", 'n', POPT_ARG_NONE, &no_cleanup, 0,
          _("Do not delete the test database after a single test is run"),
          NULL },
        { "list-tests", 'l', POPT_ARG_NONE, NULL, 'l',
          _("Show all available tests"),
          NULL },
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_pam_authenticate,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_setcreds,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_acct_mgmt,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_open_session,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_close_session,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_chauthtok,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_chauthtok_prelim,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_preauth,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_offline_auth_no_hash,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_offline_auth_success,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_offline_auth_wrong_pw,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_offline_auth_success_2fa,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_offline_auth_failed_2fa,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(
                              test_pam_offline_auth_success_2fa_with_cached_2fa,
                              pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(
                               test_pam_offline_auth_failed_2fa_with_cached_2fa,
                               pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(
                               test_pam_offline_auth_success_pw_with_cached_2fa,
                               pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(
                                test_pam_offline_auth_failed_pw_with_cached_2fa,
                                pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(
                      test_pam_offline_auth_success_combined_pw_with_cached_2fa,
                      pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(
                       test_pam_offline_auth_failed_combined_pw_with_cached_2fa,
                       pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(
                    test_pam_offline_auth_failed_wrong_2fa_size_with_cached_2fa,
                    pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_offline_chauthtok_prelim,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_offline_chauthtok,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_preauth_no_logon_name,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_auth_no_upn_logon_name,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_auth_upn_logon_name,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_cached_auth_success,
                                        pam_cached_test_setup,
                                        pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_cached_auth_wrong_pw,
                                        pam_cached_test_setup,
                                        pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_cached_auth_opt_timeout,
                                        pam_cached_test_setup,
                                        pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_cached_auth_timeout,
                                        pam_cached_test_setup,
                                        pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_cached_auth_success_combined_pw_with_cached_2fa,
                                        pam_cached_test_setup,
                                        pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_cached_auth_failed_combined_pw_with_cached_2fa,
                                        pam_cached_test_setup,
                                        pam_test_teardown),
#ifdef HAVE_TEST_CA
        cmocka_unit_test_setup_teardown(test_pam_preauth_cert_nocert,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_preauth_cert_nomatch,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_preauth_cert_match,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_preauth_cert_match_gdm_smartcard,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_preauth_cert_match_wrong_user,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_preauth_cert_no_logon_name,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(
                                  test_pam_preauth_cert_no_logon_name_with_hint,
                                  pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(
                                test_pam_preauth_cert_no_logon_name_double_cert,
                                pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(
                      test_pam_preauth_cert_no_logon_name_double_cert_with_hint,
                      pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_preauth_no_cert_no_logon_name,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(
                                   test_pam_preauth_cert_no_logon_name_no_match,
                                   pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_cert_auth,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_cert_auth,
                                        pam_test_setup_no_verification,
                                        pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_cert_auth,
                                        pam_test_setup_mech_rsa_pkcs,
                                        pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_cert_auth,
                                        pam_test_setup_mech_rsa_sha384_pkcs,
                                        pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_pss_cert_auth,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_ecc_cert_auth,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(
                             test_pam_intermediate_ca_cert_auth_with_full_certs,
                             pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(
                    test_pam_intermediate_ca_cert_auth_fails_with_incomplete_db,
                    pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(
                          test_pam_intermediate_ca_cert_auth_with_partial_chain,
                          pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(
           test_pam_intermediate_ca_cert_auth_with_full_certs_and_partial_chain,
           pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(
           test_pam_intermediate_ca_cert_auth_fails_with_root_and_partial_chain,
           pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(
               test_pam_intermediate_ca_cert_auth_with_partial_chain_pam_option,
               pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_cert_auth_double_cert,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_cert_preauth_2certs_one_mapping,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_cert_preauth_2certs_two_mappings,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_cert_auth_2certs_one_mapping,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_cert_auth_2certs_same_id_no_label,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_cert_auth_2certs_same_id_with_label_1,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_cert_auth_2certs_same_id_with_label_6,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_cert_auth_no_logon_name,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_cert_auth_no_logon_name_no_key_id,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_cert_preauth_uri_token1,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_cert_preauth_uri_token2,
                                        pam_test_setup, pam_test_teardown),
#ifdef BUILD_PASSKEY
        cmocka_unit_test_setup_teardown(test_pam_passkey_preauth_no_passkey,
                                        pam_test_setup_passkey, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_passkey_preauth_found,
                                        pam_test_setup_passkey, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_passkey_auth,
                                        pam_test_setup_passkey, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_passkey_pubkey_mapping,
                                        pam_test_setup_passkey, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_passkey_preauth_mapping_multi,
                                        pam_test_setup_passkey, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_passkey_auth_send,
                                        pam_test_setup_passkey, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_prompting_passkey_interactive,
                                        pam_test_setup_passkey_interactive_prompt, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_prompting_passkey_interactive_and_touch,
                                        pam_test_setup_passkey_interactive_and_touch_prompt, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_passkey_process_data_simple,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_passkey_process_data_multi,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_passkey_process_data_invalid,
                                        pam_test_setup, pam_test_teardown),
#endif /* BUILD_PASSKEY */

#ifdef HAVE_FAKETIME
        cmocka_unit_test_setup_teardown(test_pam_preauth_expired_crl_file,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_preauth_expired_crl_file_soft,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_preauth_crl_valid_crl_invalid_files,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_preauth_crl_another_ca_crl_invalid_files,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_preauth_crl_invalid_crl_another_ca_files,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_preauth_cert_expired,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_preauth_cert_expired_soft_crl,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_preauth_cert_expired_no_verification,
                                        pam_test_setup, pam_test_teardown),
#endif /* HAVE_FAKETIME */
        cmocka_unit_test_setup_teardown(test_pam_preauth_ocsp,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_preauth_ocsp_no_ocsp,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_preauth_ocsp_soft_ocsp,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_preauth_first_crl_another_ca_files,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_preauth_last_crl_another_ca_files,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_preauth_cert_revoked,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_preauth_cert_revoked_crl,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_preauth_cert_revoked_soft_crl,
                                        pam_test_setup, pam_test_teardown),
#endif /* HAVE_TEST_CA */

        cmocka_unit_test_setup_teardown(test_filter_response,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_filter_response_defaults,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_appsvc_posix_dom,
                                        pam_test_setup_appsvc_posix_dom,
                                        pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_not_appsvc_posix_dom,
                                        pam_test_setup_appsvc_posix_dom,
                                        pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_appsvc_app_dom,
                                        pam_test_setup_appsvc_app_dom,
                                        pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_not_appsvc_app_dom,
                                        pam_test_setup_appsvc_app_dom,
                                        pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_prompting_password,
                                        pam_test_setup_pw_prompt, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_prompting_2fa_single,
                                        pam_test_setup_2fa_single_prompt, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_prompting_2fa_single_and_service_glob,
                                        pam_test_setup_2fa_single_and_service_prompt, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_prompting_2fa_single_and_service_srv,
                                        pam_test_setup_2fa_single_and_service_prompt, pam_test_teardown),
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    poptSetOtherOptionHelp(pc, "[OPTION...] [name_of_a_single_test]");
    while ((opt = poptGetNextOpt(pc)) != -1) {
        switch (opt) {
        case 'l':
            fprintf(stderr, "\nAvailable tests:\n");
            list_tests(stderr, " -", tests, sizeof(tests)/sizeof(tests[0]));
            return 0;
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                    poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }

    single = poptGetArg(pc);

    if (single == NULL && no_cleanup) {
        fprintf(stderr, "\nThe --no-cleanup makes only sense when running "
                        "a single test.\n\n");
        poptPrintUsage(pc, stderr, 0);
        return 1;
    }

    DEBUG_CLI_INIT(debug_level);

    /* Even though normally the tests should clean up after themselves
     * they might not after a failed run. Remove the old DB to be sure */
    tests_set_cwd();
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);

    res = sss_cmocka_run_group_tests(tests, sizeof(tests)/sizeof(tests[0]),
                                     single);
    poptFreeContext(pc);
    return res;
}
