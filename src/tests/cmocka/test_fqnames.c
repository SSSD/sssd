/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2013 Red Hat

    SSSD tests: Fully Qualified Names Tests

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

#include "db/sysdb_private.h"
#include "providers/ipa/ipa_subdomains.h"
#include "tests/cmocka/common_mock.h"

#define NAME        "name"
#define DOMNAME     "domname"
#define FLATNAME    "flatname"
#define SPECIALNAME "[]{}();:'|\",<.>/?!#$%^&*_+~`"
#define PROVIDER    "proxy"
#define CONNNAME    "conn"

#define DOMNAME2    "domname2"
#define FLATNAME2   "flatname2"

#define SUBDOMNAME    "subdomname"
#define SUBFLATNAME   "subflatname"

static struct sss_domain_info *create_test_domain(TALLOC_CTX *mem_ctx,
                                                  const char *name,
                                                  const char *flatname,
                                                  struct sss_domain_info *parent,
                                                  struct sss_names_ctx *nctx)
{
    struct sss_domain_info *dom;

    dom = talloc_zero(mem_ctx, struct sss_domain_info);
    assert_non_null(dom);

    /* just to make new_subdomain happy */
    dom->sysdb = talloc_zero(dom, struct sysdb_ctx);
    assert_non_null(dom->sysdb);

    dom->name = discard_const(name);
    dom->flat_name = discard_const(flatname);
    dom->parent = parent;
    dom->names = nctx;
    dom->provider = discard_const(PROVIDER);
    dom->conn_name = discard_const(CONNNAME);

    return dom;
}

struct fqdn_test_ctx {
    struct sss_domain_info *dom;

    struct sss_names_ctx *nctx;
};

static int fqdn_test_setup(void **state)
{
    struct fqdn_test_ctx *test_ctx;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context, struct fqdn_test_ctx);
    assert_non_null(test_ctx);

    test_ctx->dom = create_test_domain(test_ctx, DOMNAME, FLATNAME,
                                       NULL, NULL);

    check_leaks_push(test_ctx);
    *state = test_ctx;
    return 0;
}

static int fqdn_test_teardown(void **state)
{
    struct fqdn_test_ctx *test_ctx = talloc_get_type(*state,
                                                     struct fqdn_test_ctx);

    if (test_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Type mismatch\n");
        return 1;
    }

    assert_true(check_leaks_pop(test_ctx) == true);
    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
    return 0;
}

void test_default(void **state)
{
    struct fqdn_test_ctx *test_ctx = talloc_get_type(*state,
                                                     struct fqdn_test_ctx);
    errno_t ret;

    char *fqdn;
    const int fqdn_size = 255;
    char fqdn_s[fqdn_size];

    if (test_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Type mismatch\n");
        return;
    }

    ret = sss_names_init_from_args(test_ctx,
                                   SSS_DEFAULT_RE,
                                   "%1$s@%2$s", &test_ctx->nctx);
    assert_int_equal(ret, EOK);

    fqdn = sss_tc_fqname(test_ctx, test_ctx->nctx, test_ctx->dom, NAME);
    assert_non_null(fqdn);
    assert_string_equal(fqdn, NAME"@"DOMNAME);
    talloc_free(fqdn);

    ret = sss_fqname(fqdn_s, fqdn_size, test_ctx->nctx, test_ctx->dom, NAME);
    assert_int_equal(ret + 1, sizeof(NAME"@"DOMNAME));
    assert_string_equal(fqdn_s, NAME"@"DOMNAME);

    talloc_free(test_ctx->nctx);
}

void test_all(void **state)
{
    struct fqdn_test_ctx *test_ctx = talloc_get_type(*state,
                                                     struct fqdn_test_ctx);
    errno_t ret;

    char *fqdn;
    const int fqdn_size = 255;
    char fqdn_s[fqdn_size];

    if (test_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Type mismatch\n");
        return;
    }

    ret = sss_names_init_from_args(test_ctx,
                                   SSS_DEFAULT_RE,
                                   "%1$s@%2$s@%3$s", &test_ctx->nctx);
    assert_int_equal(ret, EOK);

    fqdn = sss_tc_fqname(test_ctx, test_ctx->nctx, test_ctx->dom, NAME);
    assert_non_null(fqdn);
    assert_string_equal(fqdn, NAME"@"DOMNAME"@"FLATNAME);
    talloc_free(fqdn);

    ret = sss_fqname(fqdn_s, fqdn_size, test_ctx->nctx, test_ctx->dom, NAME);
    assert_int_equal(ret + 1, sizeof(NAME"@"DOMNAME"@"FLATNAME));
    assert_string_equal(fqdn_s, NAME"@"DOMNAME"@"FLATNAME);

    talloc_free(test_ctx->nctx);
}

void test_flat(void **state)
{
    struct fqdn_test_ctx *test_ctx = talloc_get_type(*state,
                                                     struct fqdn_test_ctx);
    errno_t ret;

    char *fqdn;
    const int fqdn_size = 255;
    char fqdn_s[fqdn_size];

    if (test_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Type mismatch\n");
        return;
    }

    ret = sss_names_init_from_args(test_ctx,
                                   SSS_DEFAULT_RE,
                                   "%1$s@%3$s", &test_ctx->nctx);
    assert_int_equal(ret, EOK);

    fqdn = sss_tc_fqname(test_ctx, test_ctx->nctx, test_ctx->dom, NAME);
    assert_non_null(fqdn);
    assert_string_equal(fqdn, NAME"@"FLATNAME);
    talloc_free(fqdn);

    ret = sss_fqname(fqdn_s, fqdn_size, test_ctx->nctx, test_ctx->dom, NAME);
    assert_int_equal(ret + 1, sizeof(NAME"@"FLATNAME));
    assert_string_equal(fqdn_s, NAME"@"FLATNAME);

    talloc_free(test_ctx->nctx);
}

void test_flat_fallback(void **state)
{
    struct fqdn_test_ctx *test_ctx = talloc_get_type(*state,
                                                     struct fqdn_test_ctx);
    errno_t ret;

    char *fqdn;
    const int fqdn_size = 255;
    char fqdn_s[fqdn_size];

    if (test_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Type mismatch\n");
        return;
    }

    ret = sss_names_init_from_args(test_ctx,
                                   SSS_DEFAULT_RE,
                                   "%1$s@%3$s", &test_ctx->nctx);
    assert_int_equal(ret, EOK);

    test_ctx->dom->flat_name = NULL;

    /* If flat name is requested but does not exist, the code falls back to domain
     * name
     */
    fqdn = sss_tc_fqname(test_ctx, test_ctx->nctx, test_ctx->dom, NAME);
    assert_non_null(fqdn);
    assert_string_equal(fqdn, NAME"@"DOMNAME);
    talloc_free(fqdn);

    ret = sss_fqname(fqdn_s, fqdn_size, test_ctx->nctx, test_ctx->dom, NAME);
    assert_int_equal(ret + 1, sizeof(NAME"@"DOMNAME));
    assert_string_equal(fqdn_s, NAME"@"DOMNAME);

    talloc_free(test_ctx->nctx);
}

struct parse_name_test_ctx {
    struct sss_domain_info *dom;
    struct sss_domain_info *subdom;
    struct sss_names_ctx *nctx;
};

void parse_name_check(struct parse_name_test_ctx *test_ctx,
                      const char *full_name,
                      const char *default_domain,
                      const char exp_ret,
                      const char *exp_name,
                      const char *exp_domain)
{
    errno_t ret;
    char *domain = NULL;
    char *name = NULL;

    check_leaks_push(test_ctx);
    ret = sss_parse_name_for_domains(test_ctx, test_ctx->dom, default_domain,
                                     full_name, &domain, &name);
    assert_int_equal(ret, exp_ret);

    if (exp_name) {
        assert_non_null(name);
        assert_string_equal(name, exp_name);
    }

    if (exp_domain) {
        assert_non_null(domain);
        assert_string_equal(domain, exp_domain);
    }

    talloc_free(name);
    talloc_free(domain);
    assert_true(check_leaks_pop(test_ctx) == true);
}

static int parse_name_test_setup_re(void **state, const char *regexp)
{
    struct parse_name_test_ctx *test_ctx;
    struct sss_domain_info *dom;
    errno_t ret;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context, struct parse_name_test_ctx);
    assert_non_null(test_ctx);

    /* Init with an AD-style regex to be able to test flat name */
    ret = sss_names_init_from_args(test_ctx,
                                   regexp,
                                   "%1$s@%2$s", &test_ctx->nctx);
    assert_int_equal(ret, EOK);

    /* The setup is two domains, first one with no subdomains,
     * second one with a single subdomain
     */
    dom = create_test_domain(test_ctx, DOMNAME, FLATNAME,
                                       NULL, test_ctx->nctx);
    assert_non_null(dom);
    DLIST_ADD_END(test_ctx->dom, dom, struct sss_domain_info *);

    dom = create_test_domain(test_ctx, DOMNAME2,
                             FLATNAME2, NULL, test_ctx->nctx);
    assert_non_null(dom);
    DLIST_ADD_END(test_ctx->dom, dom, struct sss_domain_info *);

    /* Create the subdomain, but don't add it yet, we want to be able to
     * test sss_parse_name_for_domains() signaling that domains must be
     * discovered
     */
    test_ctx->subdom = new_subdomain(dom, dom, SUBDOMNAME, NULL, SUBFLATNAME,
                                     SUBDOMNAME, NULL, MPG_DISABLED, false,
                                     NULL, NULL, 0, IPA_TRUST_UNKNOWN,
                                     NULL, true);
    assert_non_null(test_ctx->subdom);

    check_leaks_push(test_ctx);
    *state = test_ctx;
    return 0;
}

static int parse_name_test_setup_ipa_ad(void **state)
{
    return parse_name_test_setup_re(state, SSS_IPA_AD_DEFAULT_RE);
}

static int parse_name_test_setup_default(void **state)
{
    return parse_name_test_setup_re(state, SSS_DEFAULT_RE);
}

static int parse_name_test_two_names_ctx_setup(void **state)
{
    struct parse_name_test_ctx *test_ctx;
    struct sss_names_ctx *nctx1 = NULL;
    struct sss_names_ctx *nctx2 = NULL;
    struct sss_domain_info *dom;
    int ret;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context, struct parse_name_test_ctx);
    assert_non_null(test_ctx);

    ret = sss_names_init_from_args(test_ctx, SSS_DEFAULT_RE,
                                   "%1$s@%2$s", &nctx1);
    assert_int_equal(ret, EOK);

    ret = sss_names_init_from_args(test_ctx, SSS_IPA_AD_DEFAULT_RE,
                                   "%1$s@%2$s", &nctx2);
    assert_int_equal(ret, EOK);

    test_ctx->dom = create_test_domain(test_ctx, DOMNAME, FLATNAME,
                                       NULL, nctx1);
    assert_non_null(test_ctx->dom);

    dom = create_test_domain(test_ctx, DOMNAME2, FLATNAME2,
                                       NULL, nctx2);
    assert_non_null(dom);
    DLIST_ADD_END(test_ctx->dom, dom, struct sss_domain_info *);

    check_leaks_push(test_ctx);
    *state = test_ctx;
    return 0;
}

static int parse_name_test_teardown(void **state)
{
    struct parse_name_test_ctx *test_ctx = talloc_get_type(*state,
                                                           struct parse_name_test_ctx);

    assert_true(check_leaks_pop(test_ctx) == true);
    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
    return 0;
}

void sss_parse_name_check(struct parse_name_test_ctx *test_ctx,
                          const char *input_name,
                          const int exp_ret,
                          const char *exp_name,
                          const char *exp_domain)
{
    errno_t ret;
    char *domain = NULL;
    char *name = NULL;

    check_leaks_push(test_ctx);
    ret = sss_parse_name(test_ctx, test_ctx->nctx, input_name,
                         &domain, &name);
    assert_int_equal(ret, exp_ret);

    if (exp_name) {
        assert_non_null(name);
        assert_string_equal(name, exp_name);
    }

    if (exp_domain) {
        assert_non_null(domain);
        assert_string_equal(domain, exp_domain);
    }

    talloc_zfree(name);
    talloc_zfree(domain);

    assert_true(check_leaks_pop(test_ctx) == true);
}

void parse_name_plain(void **state)
{
    struct parse_name_test_ctx *test_ctx = talloc_get_type(*state,
                                                           struct parse_name_test_ctx);
    int ret;

    parse_name_check(test_ctx, NAME, NULL, EOK, NAME, NULL);

    ret = sss_parse_name(test_ctx, test_ctx->nctx, NAME,
                         NULL, NULL);
    assert_int_equal(ret, EOK);

    sss_parse_name_check(test_ctx, NAME, EOK, NAME, NULL);
    sss_parse_name_check(test_ctx, SPECIALNAME, EOK, SPECIALNAME, NULL);
}

void parse_name_fqdn(void **state)
{
    struct parse_name_test_ctx *test_ctx = talloc_get_type(*state,
                                                           struct parse_name_test_ctx);
    parse_name_check(test_ctx, NAME"@"DOMNAME, NULL, EOK, NAME, DOMNAME);
    parse_name_check(test_ctx, NAME"@"DOMNAME2, NULL, EOK, NAME, DOMNAME2);

    sss_parse_name_check(test_ctx, NAME"@"DOMNAME, EOK, NAME, DOMNAME);
    sss_parse_name_check(test_ctx, NAME"@"DOMNAME2, EOK, NAME, DOMNAME2);
    sss_parse_name_check(test_ctx, "@"NAME"@"DOMNAME, EOK, "@"NAME, DOMNAME);
    sss_parse_name_check(test_ctx, "@"NAME"@"DOMNAME2, EOK, "@"NAME, DOMNAME2);
    sss_parse_name_check(test_ctx, DOMNAME"\\"NAME, EOK, NAME, DOMNAME);
    sss_parse_name_check(test_ctx, DOMNAME2"\\"NAME, EOK, NAME, DOMNAME2);
}

void parse_name_sub(void **state)
{
    struct parse_name_test_ctx *test_ctx = talloc_get_type(*state,
                                                           struct parse_name_test_ctx);
    /* The subdomain name is valid, but not known */
    parse_name_check(test_ctx, NAME"@"SUBDOMNAME, NULL, EAGAIN, NULL, NULL);

    /* Link the subdomain (simulating subdom handler) and retry */
    test_ctx->dom->subdomains = test_ctx->subdom;
    parse_name_check(test_ctx, NAME"@"SUBDOMNAME, NULL, EOK, NAME, SUBDOMNAME);
}

void parse_name_flat(void **state)
{
    struct parse_name_test_ctx *test_ctx = talloc_get_type(*state,
                                                           struct parse_name_test_ctx);

    /* Link the subdomain (simulating subdom handler) */
    parse_name_check(test_ctx, FLATNAME"\\"NAME, NULL, EOK, NAME, DOMNAME);
    parse_name_check(test_ctx, FLATNAME2"\\"NAME, NULL, EOK, NAME, DOMNAME2);

    /* The subdomain name is valid, but not known */
    parse_name_check(test_ctx, SUBFLATNAME"\\"NAME, NULL, EAGAIN, NULL, NULL);
    test_ctx->dom->subdomains = test_ctx->subdom;
    parse_name_check(test_ctx, SUBFLATNAME"\\"NAME, NULL, EOK, NAME, SUBDOMNAME);
}

void parse_name_default(void **state)
{
    struct parse_name_test_ctx *test_ctx = talloc_get_type(*state,
                                                           struct parse_name_test_ctx);
    struct sss_domain_info *dom2;

    parse_name_check(test_ctx, NAME, DOMNAME2, EOK, NAME, DOMNAME2);
    dom2 = test_ctx->dom->next;

    /* Simulate unknown default domain */
    DLIST_REMOVE(test_ctx->dom, dom2);
    parse_name_check(test_ctx, NAME, DOMNAME2, EAGAIN, NULL, NULL);
}

void test_init_nouser(void **state)
{
    struct fqdn_test_ctx *test_ctx = talloc_get_type(*state,
                                                     struct fqdn_test_ctx);
    errno_t ret;

    if (test_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Type mismatch\n");
        return;
    }

    ret = sss_names_init_from_args(test_ctx,
                                   SSS_DEFAULT_RE,
                                   "%2$s@%3$s", &test_ctx->nctx);
    /* Initialization with no user name must fail */
    assert_int_not_equal(ret, EOK);
}

void test_different_regexps(void **state)
{
    struct parse_name_test_ctx *test_ctx = talloc_get_type(*state,
                                                     struct parse_name_test_ctx);
    parse_name_check(test_ctx, NAME"@"DOMNAME, NULL, EOK, NAME, DOMNAME);
    parse_name_check(test_ctx, NAME"@"DOMNAME2, NULL, EOK, NAME, DOMNAME2);
    parse_name_check(test_ctx, NAME"@WITH_AT@"DOMNAME2, NULL, EOK, NAME"@WITH_AT", DOMNAME2);
    parse_name_check(test_ctx, "@LEADING_AT"NAME"@"DOMNAME, NULL, EOK, "@LEADING_AT"NAME, DOMNAME);
    parse_name_check(test_ctx, "@LEADING_AT"NAME"@"DOMNAME2, NULL, EOK, "@LEADING_AT"NAME, DOMNAME2);
    parse_name_check(test_ctx, "@LEADING_AT"NAME"@WITH_AT@"DOMNAME, NULL, EOK, "@LEADING_AT"NAME"@WITH_AT", DOMNAME);
    parse_name_check(test_ctx, "@LEADING_AT"NAME"@WITH_AT@"DOMNAME2, NULL, EOK, "@LEADING_AT"NAME"@WITH_AT", DOMNAME2);
    parse_name_check(test_ctx, FLATNAME"\\"NAME, NULL, EOK, FLATNAME"\\"NAME, NULL);
    parse_name_check(test_ctx, FLATNAME2"\\"NAME, NULL, EOK, NAME, DOMNAME2);
    parse_name_check(test_ctx, FLATNAME2"\\"NAME"@WITH_AT", NULL, EOK, NAME"@WITH_AT", DOMNAME2);
}

void sss_parse_name_fail_ipa_ad(void **state)
{
    struct parse_name_test_ctx *test_ctx = talloc_get_type(*state,
                                                           struct parse_name_test_ctx);

    sss_parse_name_check(test_ctx, "", ERR_REGEX_NOMATCH, NULL, NULL);
    sss_parse_name_check(test_ctx, "@", ERR_REGEX_NOMATCH, NULL, NULL);
    sss_parse_name_check(test_ctx, "\\", ERR_REGEX_NOMATCH, NULL, NULL);
    sss_parse_name_check(test_ctx, "\\"NAME, ERR_REGEX_NOMATCH, NULL, NULL);
    sss_parse_name_check(test_ctx, "@"NAME, ERR_REGEX_NOMATCH, NULL, NULL);
    sss_parse_name_check(test_ctx, NAME"@", ERR_REGEX_NOMATCH, NULL, NULL);
    sss_parse_name_check(test_ctx, NAME"\\", ERR_REGEX_NOMATCH, NULL, NULL);
}

void sss_parse_name_fail_default(void **state)
{
    struct parse_name_test_ctx *test_ctx = talloc_get_type(*state,
                                                           struct parse_name_test_ctx);

    sss_parse_name_check(test_ctx, "", ERR_REGEX_NOMATCH, NULL, NULL);
    sss_parse_name_check(test_ctx, "@", ERR_REGEX_NOMATCH, NULL, NULL);
    sss_parse_name_check(test_ctx, "@"NAME, ERR_REGEX_NOMATCH, NULL, NULL);
    sss_parse_name_check(test_ctx, NAME"@", ERR_REGEX_NOMATCH, NULL, NULL);
}

int main(int argc, const char *argv[])
{
    poptContext pc;
    int opt;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_default,
                                        fqdn_test_setup, fqdn_test_teardown),
        cmocka_unit_test_setup_teardown(test_all,
                                        fqdn_test_setup, fqdn_test_teardown),
        cmocka_unit_test_setup_teardown(test_flat,
                                        fqdn_test_setup, fqdn_test_teardown),
        cmocka_unit_test_setup_teardown(test_flat_fallback,
                                        fqdn_test_setup, fqdn_test_teardown),
        cmocka_unit_test_setup_teardown(test_init_nouser,
                                        fqdn_test_setup, fqdn_test_teardown),

        cmocka_unit_test_setup_teardown(parse_name_plain,
                                        parse_name_test_setup_ipa_ad,
                                        parse_name_test_teardown),
        cmocka_unit_test_setup_teardown(parse_name_fqdn,
                                        parse_name_test_setup_ipa_ad,
                                        parse_name_test_teardown),
        cmocka_unit_test_setup_teardown(parse_name_sub,
                                        parse_name_test_setup_ipa_ad,
                                        parse_name_test_teardown),
        cmocka_unit_test_setup_teardown(parse_name_flat,
                                        parse_name_test_setup_ipa_ad,
                                        parse_name_test_teardown),
        cmocka_unit_test_setup_teardown(parse_name_default,
                                        parse_name_test_setup_ipa_ad,
                                        parse_name_test_teardown),
        cmocka_unit_test_setup_teardown(sss_parse_name_fail_ipa_ad,
                                        parse_name_test_setup_ipa_ad,
                                        parse_name_test_teardown),
        cmocka_unit_test_setup_teardown(sss_parse_name_fail_default,
                                        parse_name_test_setup_default,
                                        parse_name_test_teardown),
        cmocka_unit_test_setup_teardown(test_different_regexps,
                                        parse_name_test_two_names_ctx_setup,
                                        parse_name_test_teardown),
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

    return cmocka_run_group_tests(tests, NULL, NULL);
}
