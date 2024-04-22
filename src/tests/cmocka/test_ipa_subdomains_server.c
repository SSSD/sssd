/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2015 Red Hat

    SSSD tests: IPA subdomain server utils tests

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
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

#define TESTS_PATH "tp_" BASE_FILE_STEM

#include "providers/ipa/ipa_subdomains.h"
#include "providers/ipa/ipa_opts.h"
#include "providers/data_provider.h"
#include "tests/cmocka/common_mock.h"
#include "tests/cmocka/common_mock_resp.h"
#include "tests/cmocka/common_mock_krb5.h"
#include "tests/cmocka/common_mock_sdap.h"
#include "tests/cmocka/common_mock_be.h"

#define DOM_REALM       "DOM.MAIN"
#define HOSTNAME        "ipaserver.dom.main"
#define DOM_FLAT        "DOM"

#define TEST_AUTHID       "host/"HOSTNAME
#define KEYTAB_TEST_PRINC TEST_AUTHID"@"DOM_REALM
#define KEYTAB_PATH       TEST_DIR"/"TESTS_PATH"/keytab_test.keytab"

#define SUBDOM_NAME  "twoway.subdom.test"
#define SUBDOM_REALM "TWOWAY.SUBDOM.TEST"
#define SUBDOM_FLAT  "TWOWAY"
#define SUBDOM_SID   "S-1-2-3"

#define CHILD_NAME  "child."SUBDOM_NAME
#define CHILD_REALM "CHILD."SUBDOM_REALM
#define CHILD_FLAT  "CHILD"
#define CHILD_SID   "S-1-2-3-4"

#define TEST_CONF_DB "test_ipa_subdom_server.ldb"
#define TEST_DOM_NAME "ipa_subdom_server_test"
#define TEST_ID_PROVIDER "ipa"

#define ONEWAY_KEYTAB   TEST_DIR"/"TESTS_PATH"/"SUBDOM_REALM".keytab"
#define ONEWAY_PRINC    DOM_FLAT"$"
#define ONEWAY_AUTHID   ONEWAY_PRINC"@"SUBDOM_REALM

static bool global_rename_called;

#ifdef HAVE_SELINUX
/* Provide faster implementation of Kerberos function
 * krb5int_labeled_[f]?open. Real functions take care also
 * about SELinux context which is very expensive operation
 * and cause failures due to timeout when executing with Valgrind.
 * It's approximately 40 times slower with real function
 */
FILE *
krb5int_labeled_fopen(const char *path, const char *mode)
{
    return fopen(path, mode);
}

int
krb5int_labeled_open(const char *path, int flags, mode_t mode)
{
    return open(path, flags, mode);
}
#endif /* HAVE_SELINUX */

krb5_error_code __wrap_krb5_kt_default(krb5_context context, krb5_keytab *id)
{
    return krb5_kt_resolve(context, KEYTAB_PATH, id);
}

static void create_dummy_keytab(const char *dummy_kt)
{
    errno_t ret;

    assert_non_null(dummy_kt);
    mock_keytab_with_contents(global_talloc_context,
                              dummy_kt, ONEWAY_AUTHID);

    ret = access(dummy_kt, R_OK);
    assert_int_equal(ret, 0);
}

static int wrap_exec(void)
{
    const char *test_kt;
    const char *fail_creating_kt;

    test_kt = getenv("TEST_KT_ENV");
    if (test_kt == NULL) {
        _exit(1);
    }
    unsetenv("TEST_KT_ENV");

    fail_creating_kt = getenv("KT_CREATE_FAIL");
    if (fail_creating_kt != NULL) {
        _exit(1);
    }

    create_dummy_keytab(test_kt);
    _exit(0);

    return 1;   /* Should not happen */
}

int __wrap_execle(const char *path, const char *arg, ...)
{
    return wrap_exec();
}

int __wrap_execve(const char *path, const char *arg, ...)
{
    return wrap_exec();
}

errno_t __real_sss_unique_filename(TALLOC_CTX *owner, char *path_tmpl);

errno_t __wrap_sss_unique_filename(TALLOC_CTX *owner, char *path_tmpl)
{
    int ret;
    int sret;

    ret = __real_sss_unique_filename(owner, path_tmpl);
    if (ret == EOK) {

        sret = setenv("TEST_KT_ENV", path_tmpl, 1);
        assert_int_equal(sret, 0);
    }
    return ret;
}

errno_t __wrap_sdap_select_principal_from_keytab_sync(TALLOC_CTX *mem_ctx,
                                               const char *princ_str,
                                               const char *realm_str,
                                               const char *keytab_name,
                                               char **sasl_primary,
                                               char **sasl_realm)
{
    *sasl_primary = talloc_strdup(mem_ctx, princ_str);
    *sasl_realm = talloc_strdup(mem_ctx, realm_str);
    return 0;
}

int __real_rename(const char *old, const char *new);

int __wrap_rename(const char *old, const char *new)
{
    global_rename_called = true;
    return __real_rename(old, new);
}

struct trust_test_ctx {
    struct sss_test_ctx *tctx;
    struct be_ctx *be_ctx;

    struct ipa_id_ctx *ipa_ctx;
    bool expect_rename;
};

static struct ipa_id_ctx *mock_ipa_ctx(TALLOC_CTX *mem_ctx,
                                       struct be_ctx *be_ctx,
                                       struct sss_test_ctx *tctx,
                                       const char *krb5_realm,
                                       const char *hostname)
{
    struct ipa_id_ctx *ipa_ctx;
    errno_t ret;

    ipa_ctx = talloc_zero(mem_ctx, struct ipa_id_ctx);
    assert_non_null(ipa_ctx);

    ipa_ctx->ipa_options = talloc_zero(ipa_ctx, struct ipa_options);
    assert_non_null(ipa_ctx->ipa_options);

    ipa_ctx->ipa_options->id = talloc_zero(ipa_ctx->ipa_options,
                                           struct sdap_options);
    assert_non_null(ipa_ctx->ipa_options->id);

    ret = sdap_copy_map(ipa_ctx->ipa_options->id,
                        ipa_user_map,
                        SDAP_OPTS_USER,
                        &ipa_ctx->ipa_options->id->user_map);
    assert_int_equal(ret, ERR_OK);

    ret = dp_get_options(ipa_ctx->ipa_options->id,
                         tctx->confdb,
                         tctx->conf_dom_path,
                         ipa_def_ldap_opts,
                         SDAP_OPTS_BASIC,
                         &ipa_ctx->ipa_options->id->basic);
    assert_int_equal(ret, EOK);

    ret = dp_get_options(ipa_ctx->ipa_options->basic,
                         tctx->confdb,
                         tctx->conf_dom_path,
                         ipa_basic_opts,
                         IPA_OPTS_BASIC,
                         &ipa_ctx->ipa_options->basic);
    assert_int_equal(ret, EOK);

    ret = dp_opt_set_string(ipa_ctx->ipa_options->basic,
                            IPA_KRB5_REALM, krb5_realm);
    assert_int_equal(ret, EOK);

    ret = dp_opt_set_string(ipa_ctx->ipa_options->basic,
                            IPA_HOSTNAME, hostname);
    assert_int_equal(ret, EOK);

    ret = dp_opt_set_bool(ipa_ctx->ipa_options->basic,
                          IPA_SERVER_MODE, true);
    assert_int_equal(ret, EOK);

    ipa_ctx->sdap_id_ctx = mock_sdap_id_ctx(ipa_ctx, be_ctx,
                                            ipa_ctx->ipa_options->id);
    assert_non_null(ipa_ctx->sdap_id_ctx);

    return ipa_ctx;
}

static struct ipa_server_mode_ctx *mock_server_mode(TALLOC_CTX *mem_ctx)
{
    struct ipa_server_mode_ctx *server_mode;

    server_mode = talloc_zero(mem_ctx, struct ipa_server_mode_ctx);
    assert_non_null(server_mode);

    server_mode->hostname = HOSTNAME;
    server_mode->realm = DOM_REALM;

    return server_mode;
}

static void add_test_subdomains(struct trust_test_ctx *test_ctx,
                                uint32_t direction)
{
    errno_t

    /* Add two subdomains */
    ret = sysdb_subdomain_store(test_ctx->tctx->sysdb,
                                SUBDOM_NAME, SUBDOM_REALM,
                                NULL, SUBDOM_NAME, SUBDOM_SID,
                                MPG_ENABLED, false, SUBDOM_REALM,
                                direction, IPA_TRUST_AD, NULL);
    assert_int_equal(ret, EOK);

    ret = sysdb_subdomain_store(test_ctx->tctx->sysdb,
                                CHILD_NAME, CHILD_REALM,
                                CHILD_FLAT, CHILD_NAME, CHILD_SID,
                                MPG_ENABLED, false, SUBDOM_REALM,
                                direction, IPA_TRUST_AD, NULL);
    assert_int_equal(ret, EOK);

    ret = sysdb_update_subdomains(test_ctx->tctx->dom, test_ctx->tctx->confdb);
    assert_int_equal(ret, EOK);

}

static void add_test_2way_subdomains(struct trust_test_ctx *test_ctx)
{
    return add_test_subdomains(test_ctx, 0x1 | 0x2);
}

static void add_test_1way_subdomains(struct trust_test_ctx *test_ctx)
{
    return add_test_subdomains(test_ctx, 0x1);
}

static int test_ipa_server_create_trusts_setup(void **state)
{
    errno_t ret;
    struct trust_test_ctx *test_ctx;
    struct sss_test_conf_param params[] = {
        { NULL, NULL },             /* Sentinel */
    };

    test_ctx = talloc_zero(NULL,
                           struct trust_test_ctx);
    assert_non_null(test_ctx);

    test_ctx->tctx = create_dom_test_ctx(test_ctx, TESTS_PATH,
                                         TEST_CONF_DB, TEST_DOM_NAME,
                                         TEST_ID_PROVIDER, params);
    assert_non_null(test_ctx->tctx);
    test_ctx->tctx->dom->flat_name = discard_const(DOM_FLAT);
    test_ctx->tctx->dom->realm = discard_const(DOM_REALM);

    test_ctx->be_ctx = mock_be_ctx(test_ctx, test_ctx->tctx);
    assert_non_null(test_ctx->be_ctx);

    test_ctx->ipa_ctx = mock_ipa_ctx(test_ctx, test_ctx->be_ctx, test_ctx->tctx,
                                     DOM_REALM, HOSTNAME);
    assert_non_null(test_ctx->tctx);

    test_ctx->ipa_ctx->server_mode = mock_server_mode(test_ctx->ipa_ctx);
    assert_non_null(test_ctx->ipa_ctx->server_mode);

    ret = be_init_failover(test_ctx->be_ctx);
    assert_int_equal(ret, EOK);

    mock_keytab_with_contents(test_ctx, KEYTAB_PATH, KEYTAB_TEST_PRINC);

    global_rename_called = false;

    *state = test_ctx;
    return 0;
}

static int test_ipa_server_create_trusts_teardown(void **state)
{
    struct trust_test_ctx *test_ctx =
        talloc_get_type(*state, struct trust_test_ctx);
    errno_t ret;

    ret = unlink(KEYTAB_PATH);
    assert_int_equal(ret, 0);

    unlink(ONEWAY_KEYTAB);
    /* Ignore failures */

    /* If a test needs this variable, it should be set again in
     * each test
     */
    unsetenv("KT_CREATE_FAIL");

    talloc_free(test_ctx);
    return 0;
}

static void test_ipa_server_create_trusts_none(struct tevent_req *req);
static void test_ipa_server_create_trusts_twoway(struct tevent_req *req);

static void test_ipa_server_create_trusts(void **state)
{
    struct trust_test_ctx *test_ctx =
        talloc_get_type(*state, struct trust_test_ctx);
    struct tevent_req *req;
    errno_t ret;

    req = ipa_server_create_trusts_send(test_ctx,
                                        test_ctx->tctx->ev,
                                        test_ctx->be_ctx,
                                        test_ctx->ipa_ctx,
                                        test_ctx->be_ctx->domain);
    assert_non_null(req);

    tevent_req_set_callback(req, test_ipa_server_create_trusts_none, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
}

static void test_ipa_server_create_trusts_none(struct tevent_req *req)
{
    struct trust_test_ctx *test_ctx = \
        tevent_req_callback_data(req, struct trust_test_ctx);
    errno_t ret;

    ret = ipa_server_create_trusts_recv(req);
    talloc_zfree(req);
    assert_int_equal(ret, EOK);

    /* Add two subdomains */
    add_test_2way_subdomains(test_ctx);

    req = ipa_server_create_trusts_send(test_ctx,
                                        test_ctx->tctx->ev,
                                        test_ctx->be_ctx,
                                        test_ctx->ipa_ctx,
                                        test_ctx->be_ctx->domain);
    assert_non_null(req);

    tevent_req_set_callback(req, test_ipa_server_create_trusts_twoway, test_ctx);

}

static void assert_trust_object(struct ipa_subdom_server_ctx *trust,
                                const char *dom_name,
                                const char *dom_realm,
                                const char *sid,
                                const char *keytab,
                                const char *authid,
                                const char *sdap_realm)
{
    const char *s;

    assert_non_null(trust);
    assert_non_null(trust->dom);
    assert_string_equal(trust->dom->name, dom_name);
    assert_string_equal(trust->dom->domain_id, sid);

    s = dp_opt_get_string(trust->id_ctx.ad_id_ctx->ad_options->basic,
                          AD_KRB5_REALM);
    if (dom_realm != NULL) {
        assert_non_null(s);
        assert_string_equal(s, dom_realm);
    } else {
        assert_null(s);
    }

    s = dp_opt_get_string(trust->id_ctx.ad_id_ctx->ad_options->basic,
                          AD_DOMAIN);
    if (dom_name != NULL) {
        assert_non_null(s);
        assert_string_equal(s, dom_name);
    } else {
        assert_null(s);
    }

    /* both one-way and two-way trust uses specialized keytab */
    s = dp_opt_get_string(trust->id_ctx.ad_id_ctx->ad_options->id->basic,
                          SDAP_KRB5_KEYTAB);
    if (keytab != NULL) {
        assert_non_null(s);
        assert_string_equal(s, keytab);
    } else {
        assert_null(s);
    }

    s = dp_opt_get_string(trust->id_ctx.ad_id_ctx->ad_options->id->basic,
                          SDAP_SASL_REALM);
    if (sdap_realm != NULL) {
        assert_non_null(s);
        assert_string_equal(s, sdap_realm);
    } else {
        assert_null(s);
    }

    s = dp_opt_get_string(trust->id_ctx.ad_id_ctx->ad_options->id->basic,
                          SDAP_SASL_AUTHID);
    if (authid != NULL) {
        assert_non_null(s);
        assert_string_equal(s, authid);
    } else {
        assert_null(s);
    }
}

static void test_ipa_server_create_trusts_twoway(struct tevent_req *req)
{
    struct trust_test_ctx *test_ctx = \
        tevent_req_callback_data(req, struct trust_test_ctx);
    errno_t ret;
    struct sss_domain_info *child_dom;
    struct ipa_subdom_server_ctx *s_trust;
    struct ipa_subdom_server_ctx *c_trust;

    ret = ipa_server_create_trusts_recv(req);
    talloc_zfree(req);
    assert_int_equal(ret, EOK);

    /* Trust object should be around now */
    assert_non_null(test_ctx->ipa_ctx->server_mode->trusts);
    assert_non_null(test_ctx->ipa_ctx->server_mode->trusts->next);

    if (strcmp(test_ctx->ipa_ctx->server_mode->trusts->dom->name,
               SUBDOM_NAME) == 0) {
        s_trust = test_ctx->ipa_ctx->server_mode->trusts;
        c_trust = test_ctx->ipa_ctx->server_mode->trusts->next;
    } else {
        s_trust = test_ctx->ipa_ctx->server_mode->trusts->next;
        c_trust = test_ctx->ipa_ctx->server_mode->trusts;
    }
    assert_trust_object(c_trust,
                        CHILD_NAME,
                        CHILD_REALM,
                        CHILD_SID,
                        ONEWAY_KEYTAB,
                        ONEWAY_PRINC,
                        SUBDOM_REALM);


    assert_trust_object(s_trust,
                        SUBDOM_NAME,
                        SUBDOM_REALM,
                        SUBDOM_SID,
                        ONEWAY_KEYTAB,
                        ONEWAY_PRINC,
                        SUBDOM_REALM);

    /* No more trust objects */
    assert_null(test_ctx->ipa_ctx->server_mode->trusts->next->next);

    ret = sysdb_subdomain_delete(test_ctx->tctx->sysdb, CHILD_NAME);
    assert_int_equal(ret, EOK);

    child_dom = find_domain_by_name(test_ctx->be_ctx->domain, CHILD_NAME, true);
    assert_non_null(child_dom);

    ipa_ad_subdom_remove(test_ctx->be_ctx, test_ctx->ipa_ctx, child_dom);

    assert_trust_object(test_ctx->ipa_ctx->server_mode->trusts,
                        SUBDOM_NAME,
                        SUBDOM_REALM,
                        SUBDOM_SID,
                        ONEWAY_KEYTAB,
                        ONEWAY_PRINC,
                        SUBDOM_REALM);
    assert_null(test_ctx->ipa_ctx->server_mode->trusts->next);

    test_ev_done(test_ctx->tctx, EOK);
}

static void
ipa_server_init_done(struct tevent_context *ev,
                     struct tevent_timer *te,
                     struct timeval tv, void *pvt)
{
    struct trust_test_ctx *test_ctx =
        talloc_get_type(pvt, struct trust_test_ctx);

    test_ctx->tctx->done = true;
}

static void test_ipa_server_trust_init(void **state)
{
    struct trust_test_ctx *test_ctx =
        talloc_get_type(*state, struct trust_test_ctx);
    errno_t ret;
    struct tevent_timer *timeout_handler;
    struct timeval tv;
    struct ipa_subdom_server_ctx *s_trust;
    struct ipa_subdom_server_ctx *c_trust;

    add_test_2way_subdomains(test_ctx);

    ret = ipa_trusted_subdom_init(test_ctx->be_ctx, test_ctx->ipa_ctx);
    assert_int_equal(ret, EOK);

    tv = tevent_timeval_current_ofs(1, 0);
    timeout_handler = tevent_add_timer(test_ctx->tctx->ev, test_ctx, tv,
                                       ipa_server_init_done, test_ctx);
    assert_non_null(timeout_handler);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);

    /* Trust object should be around now */
    assert_non_null(test_ctx->ipa_ctx->server_mode->trusts);
    assert_non_null(test_ctx->ipa_ctx->server_mode->trusts->next);

    if (strcmp(test_ctx->ipa_ctx->server_mode->trusts->dom->name,
               SUBDOM_NAME) == 0) {
        s_trust = test_ctx->ipa_ctx->server_mode->trusts;
        c_trust = test_ctx->ipa_ctx->server_mode->trusts->next;
    } else {
        s_trust = test_ctx->ipa_ctx->server_mode->trusts->next;
        c_trust = test_ctx->ipa_ctx->server_mode->trusts;
    }

    assert_trust_object(c_trust,
                        CHILD_NAME,
                        CHILD_REALM,
                        CHILD_SID,
                        ONEWAY_KEYTAB,
                        ONEWAY_PRINC,
                        SUBDOM_REALM);

    assert_trust_object(s_trust,
                        SUBDOM_NAME,
                        SUBDOM_REALM,
                        SUBDOM_SID,
                        ONEWAY_KEYTAB,
                        ONEWAY_PRINC,
                        SUBDOM_REALM);

    /* No more trust objects */
    assert_null(test_ctx->ipa_ctx->server_mode->trusts->next->next);
}

struct dir_test_ctx {
    struct ldb_context *ldb;
    struct sysdb_attrs *tdo;
};

static int test_get_trust_direction_setup(void **state)
{
    struct dir_test_ctx *test_ctx;

    test_ctx = talloc_zero(global_talloc_context,
                           struct dir_test_ctx);
    assert_non_null(test_ctx);

    test_ctx->ldb = ldb_init(test_ctx, NULL);
    assert_non_null(test_ctx->ldb);

    test_ctx->tdo = sysdb_new_attrs(test_ctx);
    assert_non_null(test_ctx->tdo);

    *state = test_ctx;
    return 0;
}

static int test_get_trust_direction_teardown(void **state)
{
    struct dir_test_ctx *test_ctx =
        talloc_get_type(*state, struct dir_test_ctx);

    talloc_free(test_ctx);
    return 0;
}

/* These are stupid tests, but test real data */
static void test_trust_dir_getset(struct dir_test_ctx *test_ctx,
                                  uint32_t dir_in)
{
    errno_t ret;
    uint32_t dir;

    ret = sysdb_attrs_add_uint32(test_ctx->tdo, IPA_TRUST_DIRECTION, dir_in);
    assert_int_equal(ret, EOK);

    ret = ipa_server_get_trust_direction(test_ctx->tdo, test_ctx->ldb, &dir);
    assert_int_equal(ret, EOK);
    assert_int_equal(dir, dir_in);
}

static void test_get_trust_direction_inbound(void **state)
{
    struct dir_test_ctx *test_ctx =
        talloc_get_type(*state, struct dir_test_ctx);

    test_trust_dir_getset(test_ctx, 0x1);
}

static void test_get_trust_direction_outbound(void **state)
{
    struct dir_test_ctx *test_ctx =
        talloc_get_type(*state, struct dir_test_ctx);

    test_trust_dir_getset(test_ctx, 0x2);
}

static void test_get_trust_direction_twoway(void **state)
{
    struct dir_test_ctx *test_ctx =
        talloc_get_type(*state, struct dir_test_ctx);

    test_trust_dir_getset(test_ctx, 0x1 | 0x2);
}

static void test_get_trust_direction_notset_root(void **state)
{
    errno_t ret;
    uint32_t dir;
    struct dir_test_ctx *test_ctx =
        talloc_get_type(*state, struct dir_test_ctx);

    ret = sysdb_attrs_add_string(test_ctx->tdo, SYSDB_ORIG_DN,
                                 "cn=AD.DOM,cn=ad,cn=trusts,dc=example,dc=com");
    assert_int_equal(ret, EOK);

    ret = ipa_server_get_trust_direction(test_ctx->tdo, test_ctx->ldb, &dir);
    assert_int_equal(ret, EOK);

    /* With root domains we assume two-way trust */
    assert_int_equal(dir, 0x1 | 0x2);
}

static void test_get_trust_direction_notset_member(void **state)
{
    errno_t ret;
    uint32_t dir;
    struct dir_test_ctx *test_ctx =
        talloc_get_type(*state, struct dir_test_ctx);

    ret = sysdb_attrs_add_string(test_ctx->tdo, SYSDB_ORIG_DN,
                   "cn=SUB.AD.DOM,cn=AD.DOM,cn=ad,cn=trusts,dc=example,dc=com");
    assert_int_equal(ret, EOK);

    ret = ipa_server_get_trust_direction(test_ctx->tdo, test_ctx->ldb, &dir);
    assert_int_equal(ret, EOK);

    /* With members we set zero and take a look at the parent */
    assert_int_equal(dir, 0);
}

static void test_ipa_server_create_trusts_oneway(struct tevent_req *req);

static void test_ipa_server_create_oneway(void **state)
{
    struct trust_test_ctx *test_ctx =
        talloc_get_type(*state, struct trust_test_ctx);
    struct tevent_req *req;
    errno_t ret;

    add_test_1way_subdomains(test_ctx);

    ret = access(ONEWAY_KEYTAB, R_OK);
    assert_int_not_equal(ret, 0);

    assert_null(test_ctx->ipa_ctx->server_mode->trusts);

    test_ctx->expect_rename = true;

    req = ipa_server_create_trusts_send(test_ctx,
                                        test_ctx->tctx->ev,
                                        test_ctx->be_ctx,
                                        test_ctx->ipa_ctx,
                                        test_ctx->be_ctx->domain);
    assert_non_null(req);

    tevent_req_set_callback(req, test_ipa_server_create_trusts_oneway, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
}

static void test_ipa_server_create_trusts_oneway(struct tevent_req *req)
{
    struct trust_test_ctx *test_ctx = \
        tevent_req_callback_data(req, struct trust_test_ctx);
    errno_t ret;
    struct ipa_subdom_server_ctx *s_trust;
    struct ipa_subdom_server_ctx *c_trust;

    ret = ipa_server_create_trusts_recv(req);
    talloc_zfree(req);
    assert_int_equal(ret, EOK);

    assert_true(test_ctx->expect_rename == global_rename_called);

    ret = access(ONEWAY_KEYTAB, R_OK);
    assert_int_equal(ret, 0);

    /* Trust object should be around now */
    assert_non_null(test_ctx->ipa_ctx->server_mode->trusts);
    assert_non_null(test_ctx->ipa_ctx->server_mode->trusts->next);

    if (strcmp(test_ctx->ipa_ctx->server_mode->trusts->dom->name,
               SUBDOM_NAME) == 0) {
        s_trust = test_ctx->ipa_ctx->server_mode->trusts;
        c_trust = test_ctx->ipa_ctx->server_mode->trusts->next;
    } else {
        s_trust = test_ctx->ipa_ctx->server_mode->trusts->next;
        c_trust = test_ctx->ipa_ctx->server_mode->trusts;
    }

    assert_trust_object(
        c_trust,
        CHILD_NAME,    /* AD domain name */
        CHILD_REALM,   /* AD realm can be child if SDAP realm is parent's */
        CHILD_SID,
        ONEWAY_KEYTAB,    /* Keytab shared with parent AD dom */
        ONEWAY_PRINC,     /* Principal shared with parent AD dom */
        SUBDOM_REALM); /* SDAP realm must be AD root domain */

    /* Here all properties point to the AD domain */
    assert_trust_object(s_trust,
                        SUBDOM_NAME,
                        SUBDOM_REALM,
                        SUBDOM_SID,
                        ONEWAY_KEYTAB,
                        ONEWAY_PRINC,
                        SUBDOM_REALM);

    assert_null(test_ctx->ipa_ctx->server_mode->trusts->next->next);
    test_ev_done(test_ctx->tctx, EOK);
}

static void test_ipa_server_create_oneway_kt_exists(void **state)
{
    struct trust_test_ctx *test_ctx =
        talloc_get_type(*state, struct trust_test_ctx);
    struct tevent_req *req;
    errno_t ret;

    add_test_1way_subdomains(test_ctx);

    create_dummy_keytab(ONEWAY_KEYTAB);
    ret = access(ONEWAY_KEYTAB, R_OK);
    assert_int_equal(ret, 0);

    test_ctx->expect_rename = true;

    assert_null(test_ctx->ipa_ctx->server_mode->trusts);

    req = ipa_server_create_trusts_send(test_ctx,
                                        test_ctx->tctx->ev,
                                        test_ctx->be_ctx,
                                        test_ctx->ipa_ctx,
                                        test_ctx->be_ctx->domain);
    assert_non_null(req);

    tevent_req_set_callback(req, test_ipa_server_create_trusts_oneway, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
}

/* Test scenario where a keytab already exists, but refresh fails. In this case,
 * sssd should attempt to reuse the previous keytab
 */
static void test_ipa_server_create_oneway_kt_refresh_fallback(void **state)
{
    struct trust_test_ctx *test_ctx =
        talloc_get_type(*state, struct trust_test_ctx);
    struct tevent_req *req;
    errno_t ret;

    add_test_1way_subdomains(test_ctx);

    create_dummy_keytab(ONEWAY_KEYTAB);
    ret = access(ONEWAY_KEYTAB, R_OK);
    assert_int_equal(ret, 0);

    setenv("KT_CREATE_FAIL", "1", 1);
    test_ctx->expect_rename = false;

    assert_null(test_ctx->ipa_ctx->server_mode->trusts);

    req = ipa_server_create_trusts_send(test_ctx,
                                        test_ctx->tctx->ev,
                                        test_ctx->be_ctx,
                                        test_ctx->ipa_ctx,
                                        test_ctx->be_ctx->domain);
    assert_non_null(req);

    tevent_req_set_callback(req, test_ipa_server_create_trusts_oneway, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
}

/* Tests case where there's no keytab and retrieving fails. Just fail the
 * request in that case
 */
static void test_ipa_server_create_trusts_oneway_fail(struct tevent_req *req);

static void test_ipa_server_create_oneway_kt_refresh_fail(void **state)
{
    struct trust_test_ctx *test_ctx =
        talloc_get_type(*state, struct trust_test_ctx);
    struct tevent_req *req;
    errno_t ret;

    add_test_1way_subdomains(test_ctx);

    setenv("KT_CREATE_FAIL", "1", 1);
    test_ctx->expect_rename = false;

    assert_null(test_ctx->ipa_ctx->server_mode->trusts);

    req = ipa_server_create_trusts_send(test_ctx,
                                        test_ctx->tctx->ev,
                                        test_ctx->be_ctx,
                                        test_ctx->ipa_ctx,
                                        test_ctx->be_ctx->domain);
    assert_non_null(req);

    tevent_req_set_callback(req,
                            test_ipa_server_create_trusts_oneway_fail,
                            test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
}

static void test_ipa_server_create_trusts_oneway_fail(struct tevent_req *req)
{
    struct trust_test_ctx *test_ctx = \
        tevent_req_callback_data(req, struct trust_test_ctx);
    errno_t ret;

    ret = ipa_server_create_trusts_recv(req);
    assert_int_not_equal(ret, EOK);

    assert_true(test_ctx->expect_rename == global_rename_called);

    test_ev_done(test_ctx->tctx, EOK);
}

static void test_ipa_server_trust_oneway_init(void **state)
{
    struct trust_test_ctx *test_ctx =
        talloc_get_type(*state, struct trust_test_ctx);
    errno_t ret;
    struct tevent_timer *timeout_handler;
    struct timeval tv;

    add_test_1way_subdomains(test_ctx);

    ret = ipa_trusted_subdom_init(test_ctx->be_ctx, test_ctx->ipa_ctx);
    assert_int_equal(ret, EOK);

    tv = tevent_timeval_current_ofs(1, 0);
    timeout_handler = tevent_add_timer(test_ctx->tctx->ev, test_ctx, tv,
                                       ipa_server_init_done, test_ctx);
    assert_non_null(timeout_handler);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);

    assert_non_null(test_ctx->ipa_ctx->server_mode->trusts);
}

static void test_ipa_trust_dir2str(void **state)
{
    /* Just make sure the caller can rely on getting a valid string.. */
    assert_non_null(ipa_trust_dir2str(0x00));
    assert_non_null(ipa_trust_dir2str(0x01));
    assert_non_null(ipa_trust_dir2str(0x02));
    assert_non_null(ipa_trust_dir2str(0x80));
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
        { "no-cleanup", 'n', POPT_ARG_NONE, &no_cleanup, 0,
          _("Do not delete the test database after a test run"), NULL },
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ipa_trust_dir2str),

        cmocka_unit_test_setup_teardown(test_ipa_server_create_oneway,
                                        test_ipa_server_create_trusts_setup,
                                        test_ipa_server_create_trusts_teardown),
        cmocka_unit_test_setup_teardown(test_ipa_server_create_oneway_kt_exists,
                                        test_ipa_server_create_trusts_setup,
                                        test_ipa_server_create_trusts_teardown),
        cmocka_unit_test_setup_teardown(test_ipa_server_create_oneway_kt_refresh_fallback,
                                        test_ipa_server_create_trusts_setup,
                                        test_ipa_server_create_trusts_teardown),
        cmocka_unit_test_setup_teardown(test_ipa_server_create_oneway_kt_refresh_fail,
                                        test_ipa_server_create_trusts_setup,
                                        test_ipa_server_create_trusts_teardown),
        cmocka_unit_test_setup_teardown(test_ipa_server_trust_oneway_init,
                                        test_ipa_server_create_trusts_setup,
                                        test_ipa_server_create_trusts_teardown),

        cmocka_unit_test_setup_teardown(test_ipa_server_trust_init,
                                        test_ipa_server_create_trusts_setup,
                                        test_ipa_server_create_trusts_teardown),
        cmocka_unit_test_setup_teardown(test_ipa_server_create_trusts,
                                        test_ipa_server_create_trusts_setup,
                                        test_ipa_server_create_trusts_teardown),

        cmocka_unit_test_setup_teardown(test_get_trust_direction_inbound,
                                        test_get_trust_direction_setup,
                                        test_get_trust_direction_teardown),
        cmocka_unit_test_setup_teardown(test_get_trust_direction_outbound,
                                        test_get_trust_direction_setup,
                                        test_get_trust_direction_teardown),
        cmocka_unit_test_setup_teardown(test_get_trust_direction_twoway,
                                        test_get_trust_direction_setup,
                                        test_get_trust_direction_teardown),
        cmocka_unit_test_setup_teardown(test_get_trust_direction_notset_root,
                                        test_get_trust_direction_setup,
                                        test_get_trust_direction_teardown),
        cmocka_unit_test_setup_teardown(test_get_trust_direction_notset_member,
                                        test_get_trust_direction_setup,
                                        test_get_trust_direction_teardown),
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
