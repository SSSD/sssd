/*
    SSSD

    certmap - Tests for SSSD's certificate mapping library

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2017 Red Hat

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

#include "lib/certmap/sss_certmap.h"
#include "lib/certmap/sss_certmap_int.h"

#include "util/crypto/sss_crypto.h"

#include "tests/cmocka/common_mock.h"
#include "tests/common.h"

#include <openssl/crypto.h>

#ifdef HAVE_TEST_CA
#include "tests/test_CA/SSSD_test_cert_x509_0001.h"
#include "tests/test_CA/SSSD_test_cert_x509_0003.h"
#include "tests/test_CA/SSSD_test_cert_x509_0004.h"
#else
#define SSSD_TEST_CERT_0001 ""
#define SSSD_TEST_CERT_0003 ""
#define SSSD_TEST_CERT_0004 ""
#endif

struct priv_sss_debug {
    int level;
};

void ext_debug(void *private, const char *file, long line, const char *function,
               const char *format, ...)
{
    va_list ap;
    struct priv_sss_debug *data = private;
    int level = SSSDBG_OP_FAILURE;

    if (data != NULL) {
        level = data->level;
    }

    if (DEBUG_IS_SET(level)) {
        va_start(ap, format);
        sss_vdebug_fn(file, line, function, level, APPEND_LINE_FEED,
                      format, ap);
        va_end(ap);
    }
}

static void test_sss_certmap_init(void **state)
{
    int ret;
    struct sss_certmap_ctx *ctx;

    ret = sss_certmap_init(NULL, ext_debug, NULL, NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_init(NULL, ext_debug, NULL, &ctx);
    assert_int_equal(ret, EOK);

    sss_certmap_free_ctx(ctx);
}

static struct sss_certmap_ctx *setup_prio(const int *l)
{
    int ret;
    size_t c;
    struct sss_certmap_ctx *ctx;

    ret = sss_certmap_init(NULL, ext_debug, NULL, &ctx);
    assert_int_equal(ret, EOK);
    assert_non_null(ctx);

    for (c = 0; c < 10; c++) {
        ret = sss_certmap_add_rule(ctx, l[c], NULL, NULL, NULL);
        assert_int_equal(ret, EOK);
    }

    return ctx;
}

static void test_sss_certmap_add_rule(void **state)
{
    struct sss_certmap_ctx *ctx;
    int i;
    struct priority_list *p;
    struct priority_list *last;
    size_t c;

    const int tests_a[][10] = {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
                               {9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
                               {1, 3, 5 ,7, 9, 0, 2, 4, 6, 8},
                               {0, 2, 4, 6, 8, 1, 3, 5, 7, 9},
                               {0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};

    const int tests_b[][10] = {{0, 0, 0, 0, 1, 1, 1, 2, 2, 2},
                               {2, 2, 2, 1, 1, 1, 0, 0, 0, 0},
                               {0, 1, 2, 0, 1, 2, 0, 1, 2, 0},
                               {0, 2, 1, 0, 2, 1, 0, 2, 1, 0},
                               {0, 1, 2, 0, 2, 1, 0, 0, 1, 2},
                               {0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};

    for (c = 0; tests_a[c][0] != 0 || tests_a[c][9] != 0; c++) {
        ctx = setup_prio(tests_a[0]);
        assert_non_null(ctx);
        i = 0;
        for (p = ctx->prio_list; p != NULL; p = p->next) {
            assert_int_equal(i, p->priority);
            assert_non_null(p->rule_list);
            assert_int_equal(i, p->rule_list->priority);
            assert_null(p->rule_list->prev);
            assert_null(p->rule_list->next);
            i++;
        }

        i = 9;
        for (last = ctx->prio_list; last->next != NULL; last = last->next);
        for (p = last; p != NULL; p = p->prev) {
            assert_int_equal(i, p->priority);
            assert_int_equal(i, p->rule_list->priority);
            i--;
        }

        sss_certmap_free_ctx(ctx);
    }
    for (c = 0; tests_b[c][0] != 0 || tests_b[c][9] != 0; c++) {
        ctx = setup_prio(tests_b[0]);
        assert_non_null(ctx);
        i = 0;
        for (p = ctx->prio_list; p != NULL; p = p->next) {
            assert_int_equal(i, p->priority);
            assert_non_null(p->rule_list);
            assert_int_equal(i, p->rule_list->priority);
            assert_null(p->rule_list->prev);
            assert_non_null(p->rule_list->next);
            assert_ptr_equal(p->rule_list, p->rule_list->next->prev);
            assert_non_null(p->rule_list->next->next);
            assert_ptr_equal(p->rule_list->next,
                             p->rule_list->next->next->prev);
            if (i == 0) {
                assert_non_null(p->rule_list->next->next->next);
                assert_ptr_equal(p->rule_list->next->next,
                                 p->rule_list->next->next->next->prev);
                assert_null(p->rule_list->next->next->next->next);
            } else {
                assert_null(p->rule_list->next->next->next);
            }
            i++;
        }
        sss_certmap_free_ctx(ctx);
    }
}

static void test_sss_certmap_add_matching_rule(void **state)
{
    struct sss_certmap_ctx *ctx;
    int ret;

    ret = sss_certmap_init(NULL, ext_debug, NULL, &ctx);
    assert_int_equal(ret, EOK);
    assert_non_null(ctx);
    assert_null(ctx->prio_list);

    ret = sss_certmap_add_rule(ctx, 1, "fsdf", NULL, NULL);
    assert_int_equal(ret, EINVAL);
    assert_null(ctx->prio_list);

    ret = sss_certmap_add_rule(ctx, 1, "FDSF:fsdf", NULL, NULL);
    assert_int_equal(ret, ESRCH);
    assert_null(ctx->prio_list);

    ret = sss_certmap_add_rule(ctx, 1, "<rgerge>", NULL, NULL);
    assert_int_equal(ret, EINVAL);
    assert_null(ctx->prio_list);

    ret = sss_certmap_add_rule(ctx, 1, "KRB5:<rgerge>", NULL, NULL);
    assert_int_equal(ret, EINVAL);
    assert_null(ctx->prio_list);

    ret = sss_certmap_add_rule(ctx, 1, "<ISSUER>", NULL, NULL);
    assert_int_equal(ret, EINVAL);
    assert_null(ctx->prio_list);

    ret = sss_certmap_add_rule(ctx, 1, "<SUBJECT>", NULL, NULL);
    assert_int_equal(ret, EINVAL);
    assert_null(ctx->prio_list);

    ret = sss_certmap_add_rule(ctx, 1, "<KU>", NULL, NULL);
    assert_int_equal(ret, EINVAL);
    assert_null(ctx->prio_list);

    ret = sss_certmap_add_rule(ctx, 1, "<KU>ddqwdq", NULL, NULL);
    assert_int_equal(ret, EINVAL);
    assert_null(ctx->prio_list);

    ret = sss_certmap_add_rule(ctx, 1, "<KU>digitalSignature,dddq", NULL, NULL);
    assert_int_equal(ret, EINVAL);
    assert_null(ctx->prio_list);


    ret = sss_certmap_add_rule(ctx, 1, "<EKU>", NULL, NULL);
    assert_int_equal(ret, EINVAL);
    assert_null(ctx->prio_list);

    ret = sss_certmap_add_rule(ctx, 1, "<EKU>dwqwqw", NULL, NULL);
    assert_int_equal(ret, EINVAL);
    assert_null(ctx->prio_list);

    ret = sss_certmap_add_rule(ctx, 1, "<EKU>.", NULL, NULL);
    assert_int_equal(ret, EINVAL);
    assert_null(ctx->prio_list);

    ret = sss_certmap_add_rule(ctx, 1, "<EKU>.1.2.3", NULL, NULL);
    assert_int_equal(ret, EINVAL);
    assert_null(ctx->prio_list);

    ret = sss_certmap_add_rule(ctx, 1, "<EKU>1.2.3.", NULL, NULL);
    assert_int_equal(ret, EINVAL);
    assert_null(ctx->prio_list);

    ret = sss_certmap_add_rule(ctx, 1, "<EKU>1.a.3", NULL, NULL);
    assert_int_equal(ret, EINVAL);
    assert_null(ctx->prio_list);

    ret = sss_certmap_add_rule(ctx, 1, "<SAN:fwfwef>", NULL, NULL);
    assert_int_equal(ret, EINVAL);
    assert_null(ctx->prio_list);

    ret = sss_certmap_add_rule(ctx, 1, "<SAN:rfc822Name", NULL, NULL);
    assert_int_equal(ret, EINVAL);
    assert_null(ctx->prio_list);

    /* invalid base64 input */
    ret = sss_certmap_add_rule(ctx, 1, "<SAN:ediPartyName>...", NULL, NULL);
    assert_int_equal(ret, EINVAL);
    assert_null(ctx->prio_list);

    /* invalid OID input */
    ret = sss_certmap_add_rule(ctx, 1, "<SAN:.>dqq", NULL, NULL);
    assert_int_equal(ret, EINVAL);
    assert_null(ctx->prio_list);

    ret = sss_certmap_add_rule(ctx, 1, "<SAN:.1>dqq", NULL, NULL);
    assert_int_equal(ret, EINVAL);
    assert_null(ctx->prio_list);

    ret = sss_certmap_add_rule(ctx, 1, "<SAN:1.>dqq", NULL, NULL);
    assert_int_equal(ret, EINVAL);
    assert_null(ctx->prio_list);

    ret = sss_certmap_add_rule(ctx, 1, "<SAN:11>dqq", NULL, NULL);
    assert_int_equal(ret, EINVAL);
    assert_null(ctx->prio_list);

    ret = sss_certmap_add_rule(ctx, 1, "<ISSUER>a", NULL, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(ctx->prio_list);
    assert_non_null(ctx->prio_list->rule_list);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule);
    assert_int_equal(ctx->prio_list->rule_list->parsed_match_rule->r,
                     relation_and);
    assert_null(ctx->prio_list->rule_list->parsed_match_rule->subject);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule->issuer);
    assert_string_equal("a",
                     ctx->prio_list->rule_list->parsed_match_rule->issuer->val);
    talloc_free(ctx);

    ret = sss_certmap_init(NULL, ext_debug, NULL, &ctx);
    assert_int_equal(ret, EOK);
    assert_non_null(ctx);
    assert_null(ctx->prio_list);
    ret = sss_certmap_add_rule(ctx, 1, "&&<ISSUER>a", NULL, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(ctx->prio_list);
    assert_non_null(ctx->prio_list->rule_list);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule);
    assert_int_equal(ctx->prio_list->rule_list->parsed_match_rule->r,
                     relation_and);
    assert_null(ctx->prio_list->rule_list->parsed_match_rule->subject);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule->issuer);
    assert_string_equal("a",
                     ctx->prio_list->rule_list->parsed_match_rule->issuer->val);
    talloc_free(ctx);

    ret = sss_certmap_init(NULL, ext_debug, NULL, &ctx);
    assert_int_equal(ret, EOK);
    assert_non_null(ctx);
    assert_null(ctx->prio_list);
    ret = sss_certmap_add_rule(ctx, 1, "KRB5:||<ISSUER>a", NULL, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(ctx->prio_list);
    assert_non_null(ctx->prio_list->rule_list);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule);
    assert_int_equal(ctx->prio_list->rule_list->parsed_match_rule->r,
                     relation_or);
    assert_null(ctx->prio_list->rule_list->parsed_match_rule->subject);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule->issuer);
    assert_string_equal("a",
                     ctx->prio_list->rule_list->parsed_match_rule->issuer->val);
    talloc_free(ctx);

    ret = sss_certmap_init(NULL, ext_debug, NULL, &ctx);
    assert_int_equal(ret, EOK);
    assert_non_null(ctx);
    assert_null(ctx->prio_list);
    ret = sss_certmap_add_rule(ctx, 1, "KRB5:<ISSUER>a<SUBJECT>b", NULL, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(ctx->prio_list);
    assert_non_null(ctx->prio_list->rule_list);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule);
    assert_int_equal(ctx->prio_list->rule_list->parsed_match_rule->r,
                     relation_and);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule->subject);
    assert_string_equal("b",
                    ctx->prio_list->rule_list->parsed_match_rule->subject->val);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule->issuer);
    assert_string_equal("a",
                     ctx->prio_list->rule_list->parsed_match_rule->issuer->val);
    talloc_free(ctx);

    ret = sss_certmap_init(NULL, ext_debug, NULL, &ctx);
    assert_int_equal(ret, EOK);
    assert_non_null(ctx);
    assert_null(ctx->prio_list);
    ret = sss_certmap_add_rule(ctx, 1000,
                               "KRB5:<ISSUER>a<SUBJECT>b<ISSUER>c<SUBJECT>d",
                               NULL, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(ctx->prio_list);
    assert_non_null(ctx->prio_list->rule_list);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule);
    assert_int_equal(ctx->prio_list->rule_list->parsed_match_rule->r,
                     relation_and);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule->subject);
    assert_string_equal("d",
                    ctx->prio_list->rule_list->parsed_match_rule->subject->val);
    assert_string_equal("b",
              ctx->prio_list->rule_list->parsed_match_rule->subject->next->val);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule->issuer);
    assert_string_equal("c",
                     ctx->prio_list->rule_list->parsed_match_rule->issuer->val);
    assert_string_equal("a",
               ctx->prio_list->rule_list->parsed_match_rule->issuer->next->val);

    ret = sss_certmap_add_rule(ctx, 99,
                               "KRB5:<ISSUER>a<SUBJECT>b"
                               "<KU>dataEncipherment,cRLSign<ISSUER>c"
                               "<SUBJECT>d",
                               NULL, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(ctx->prio_list);
    assert_non_null(ctx->prio_list->rule_list);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule);
    assert_int_equal(ctx->prio_list->rule_list->parsed_match_rule->r,
                     relation_and);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule->subject);
    assert_string_equal("d",
                    ctx->prio_list->rule_list->parsed_match_rule->subject->val);
    assert_string_equal("b",
              ctx->prio_list->rule_list->parsed_match_rule->subject->next->val);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule->issuer);
    assert_string_equal("c",
                     ctx->prio_list->rule_list->parsed_match_rule->issuer->val);
    assert_string_equal("a",
               ctx->prio_list->rule_list->parsed_match_rule->issuer->next->val);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule->ku);
    assert_int_equal(SSS_KU_CRL_SIGN|SSS_KU_DATA_ENCIPHERMENT,
               ctx->prio_list->rule_list->parsed_match_rule->ku->ku);

    ret = sss_certmap_add_rule(ctx, 98,
                               "KRB5:<ISSUER>a<SUBJECT>b"
                               "<KU>dataEncipherment,cRLSign<ISSUER>c"
                               "<EKU>clientAuth,emailProtection"
                               "<SUBJECT>d",
                               NULL, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(ctx->prio_list);
    assert_non_null(ctx->prio_list->rule_list);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule);
    assert_int_equal(ctx->prio_list->rule_list->parsed_match_rule->r,
                     relation_and);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule->subject);
    assert_string_equal("d",
                    ctx->prio_list->rule_list->parsed_match_rule->subject->val);
    assert_string_equal("b",
              ctx->prio_list->rule_list->parsed_match_rule->subject->next->val);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule->issuer);
    assert_string_equal("c",
                     ctx->prio_list->rule_list->parsed_match_rule->issuer->val);
    assert_string_equal("a",
               ctx->prio_list->rule_list->parsed_match_rule->issuer->next->val);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule->ku);
    assert_int_equal(SSS_KU_CRL_SIGN|SSS_KU_DATA_ENCIPHERMENT,
               ctx->prio_list->rule_list->parsed_match_rule->ku->ku);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule->eku);
    assert_true(string_in_list("1.3.6.1.5.5.7.3.2",
              discard_const(
               ctx->prio_list->rule_list->parsed_match_rule->eku->eku_oid_list),
              true));
    assert_true(string_in_list("1.3.6.1.5.5.7.3.4",
              discard_const(
               ctx->prio_list->rule_list->parsed_match_rule->eku->eku_oid_list),
              true));
    assert_null(
            ctx->prio_list->rule_list->parsed_match_rule->eku->eku_oid_list[2]);

    ret = sss_certmap_add_rule(ctx, 97,
                               "KRB5:<EKU>clientAuth,1.2.3,emailProtection",
                               NULL, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(ctx->prio_list);
    assert_non_null(ctx->prio_list->rule_list);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule);
    assert_int_equal(ctx->prio_list->rule_list->parsed_match_rule->r,
                     relation_and);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule->eku);
    assert_true(string_in_list("1.3.6.1.5.5.7.3.2",
              discard_const(
               ctx->prio_list->rule_list->parsed_match_rule->eku->eku_oid_list),
              true));
    assert_true(string_in_list("1.3.6.1.5.5.7.3.4",
              discard_const(
               ctx->prio_list->rule_list->parsed_match_rule->eku->eku_oid_list),
              true));
    assert_true(string_in_list("1.2.3",
              discard_const(
               ctx->prio_list->rule_list->parsed_match_rule->eku->eku_oid_list),
              true));
    assert_null(
            ctx->prio_list->rule_list->parsed_match_rule->eku->eku_oid_list[3]);

    ret = sss_certmap_add_rule(ctx, 96,
                               "KRB5:<EKU>1.2.3",
                               NULL, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(ctx->prio_list);
    assert_non_null(ctx->prio_list->rule_list);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule);
    assert_int_equal(ctx->prio_list->rule_list->parsed_match_rule->r,
                     relation_and);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule->eku);
    assert_true(string_in_list("1.2.3",
              discard_const(
               ctx->prio_list->rule_list->parsed_match_rule->eku->eku_oid_list),
              true));
    assert_null(
            ctx->prio_list->rule_list->parsed_match_rule->eku->eku_oid_list[1]);

    /* SAN tests */
    ret = sss_certmap_add_rule(ctx, 89, "KRB5:<SAN>abc", NULL, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(ctx->prio_list);
    assert_non_null(ctx->prio_list->rule_list);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule);
    assert_int_equal(ctx->prio_list->rule_list->parsed_match_rule->r,
                     relation_and);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule->san);
    assert_int_equal(ctx->prio_list->rule_list->parsed_match_rule->san->san_opt,
                     SAN_PRINCIPAL);
    assert_string_equal(ctx->prio_list->rule_list->parsed_match_rule->san->val,
                        "abc");

    ret = sss_certmap_add_rule(ctx, 88, "KRB5:<SAN:dnsName>def", NULL, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(ctx->prio_list);
    assert_non_null(ctx->prio_list->rule_list);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule);
    assert_int_equal(ctx->prio_list->rule_list->parsed_match_rule->r,
                     relation_and);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule->san);
    assert_int_equal(ctx->prio_list->rule_list->parsed_match_rule->san->san_opt,
                     SAN_DNS_NAME);
    assert_string_equal(ctx->prio_list->rule_list->parsed_match_rule->san->val,
                        "def");

    ret = sss_certmap_add_rule(ctx, 87, "KRB5:<SAN:x400Address>aGlq",
                               NULL, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(ctx->prio_list);
    assert_non_null(ctx->prio_list->rule_list);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule);
    assert_int_equal(ctx->prio_list->rule_list->parsed_match_rule->r,
                     relation_and);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule->san);
    assert_int_equal(ctx->prio_list->rule_list->parsed_match_rule->san->san_opt,
                     SAN_X400_ADDRESS);
    assert_int_equal(
                 ctx->prio_list->rule_list->parsed_match_rule->san->bin_val_len,
                 3);
    assert_memory_equal(
                     ctx->prio_list->rule_list->parsed_match_rule->san->bin_val,
                     "hij", 3);

    ret = sss_certmap_add_rule(ctx, 86, "KRB5:<SAN:1.2.3.4>klm",
                               NULL, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(ctx->prio_list);
    assert_non_null(ctx->prio_list->rule_list);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule);
    assert_int_equal(ctx->prio_list->rule_list->parsed_match_rule->r,
                     relation_and);
    assert_non_null(ctx->prio_list->rule_list->parsed_match_rule->san);
    assert_int_equal(ctx->prio_list->rule_list->parsed_match_rule->san->san_opt,
                     SAN_STRING_OTHER_NAME);
    assert_string_equal(ctx->prio_list->rule_list->parsed_match_rule->san->val,
                        "klm");
    assert_string_equal("1.2.3.4",
         ctx->prio_list->rule_list->parsed_match_rule->san->str_other_name_oid);

    talloc_free(ctx);
}

static void test_check_ad_attr_name(void **state)
{
    char *res;

    res = check_ad_attr_name(NULL, NULL);
    assert_null(res);

    res = check_ad_attr_name(NULL, "");
    assert_null(res);

    res = check_ad_attr_name(NULL, "dsddqwdas");
    assert_null(res);

    res = check_ad_attr_name(NULL, "dsddq=wdas");
    assert_null(res);

    res = check_ad_attr_name(NULL, "CN=abc");
    assert_null(res);

    res = check_ad_attr_name(NULL, "O=xyz");
    assert_null(res);

    res = check_ad_attr_name(NULL, "ST=def");
    assert_non_null(res);
    assert_string_equal(res, "S=def");
    talloc_free(res);
}

const uint8_t test_cert_der[] = {
0x30, 0x82, 0x04, 0x09, 0x30, 0x82, 0x02, 0xf1, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x09,
0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30,
0x34, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x09, 0x49, 0x50, 0x41, 0x2e,
0x44, 0x45, 0x56, 0x45, 0x4c, 0x31, 0x1e, 0x30, 0x1c, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x15,
0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x20, 0x41, 0x75, 0x74, 0x68,
0x6f, 0x72, 0x69, 0x74, 0x79, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x35, 0x30, 0x34, 0x32, 0x38, 0x31,
0x30, 0x32, 0x31, 0x31, 0x31, 0x5a, 0x17, 0x0d, 0x31, 0x37, 0x30, 0x34, 0x32, 0x38, 0x31, 0x30,
0x32, 0x31, 0x31, 0x31, 0x5a, 0x30, 0x32, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a,
0x0c, 0x09, 0x49, 0x50, 0x41, 0x2e, 0x44, 0x45, 0x56, 0x45, 0x4c, 0x31, 0x1c, 0x30, 0x1a, 0x06,
0x03, 0x55, 0x04, 0x03, 0x0c, 0x13, 0x69, 0x70, 0x61, 0x2d, 0x64, 0x65, 0x76, 0x65, 0x6c, 0x2e,
0x69, 0x70, 0x61, 0x2e, 0x64, 0x65, 0x76, 0x65, 0x6c, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06,
0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f,
0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xb2, 0x32, 0x92, 0xab, 0x47, 0xb8,
0x0c, 0x13, 0x54, 0x4a, 0x1f, 0x1e, 0x29, 0x06, 0xff, 0xd0, 0x50, 0xcb, 0xf7, 0x5f, 0x79, 0x91,
0x65, 0xb1, 0x39, 0x01, 0x83, 0x6a, 0xad, 0x9e, 0x77, 0x3b, 0xf3, 0x0d, 0xd7, 0xb9, 0xf6, 0xdc,
0x9e, 0x4a, 0x49, 0xa7, 0xd0, 0x66, 0x72, 0xcc, 0xbf, 0x77, 0xd6, 0xde, 0xa9, 0xfe, 0x67, 0x96,
0xcc, 0x49, 0xf1, 0x37, 0x23, 0x2e, 0xc4, 0x50, 0xf4, 0xeb, 0xba, 0x62, 0xd4, 0x23, 0x4d, 0xf3,
0x37, 0x38, 0x82, 0xee, 0x3b, 0x3f, 0x2c, 0xd0, 0x80, 0x9b, 0x17, 0xaa, 0x9b, 0xeb, 0xa6, 0xdd,
0xf6, 0x15, 0xff, 0x06, 0xb2, 0xce, 0xff, 0xdf, 0x8a, 0x9e, 0x95, 0x85, 0x49, 0x1f, 0x84, 0xfd,
0x81, 0x26, 0xce, 0x06, 0x32, 0x0d, 0x36, 0xca, 0x7c, 0x15, 0x81, 0x68, 0x6b, 0x8f, 0x3e, 0xb3,
0xa2, 0xfc, 0xae, 0xaf, 0xc2, 0x44, 0x58, 0x15, 0x95, 0x40, 0xfc, 0x56, 0x19, 0x91, 0x80, 0xed,
0x42, 0x11, 0x66, 0x04, 0xef, 0x3c, 0xe0, 0x76, 0x33, 0x4b, 0x83, 0xfa, 0x7e, 0xb4, 0x47, 0xdc,
0xfb, 0xed, 0x46, 0xa5, 0x8d, 0x0a, 0x66, 0x87, 0xa5, 0xef, 0x7b, 0x74, 0x62, 0xac, 0xbe, 0x73,
0x36, 0xc9, 0xb4, 0xfe, 0x20, 0xc4, 0x81, 0xf3, 0xfe, 0x78, 0x19, 0xa8, 0xd0, 0xaf, 0x7f, 0x81,
0x72, 0x24, 0x61, 0xd9, 0x76, 0x93, 0xe3, 0x0b, 0xd2, 0x4f, 0x19, 0x17, 0x33, 0x57, 0xd4, 0x82,
0xb0, 0xf1, 0xa8, 0x03, 0xf6, 0x01, 0x99, 0xa9, 0xb8, 0x8c, 0x83, 0xc9, 0xba, 0x19, 0x87, 0xea,
0xd6, 0x3b, 0x06, 0xeb, 0x4c, 0xf7, 0xf1, 0xe5, 0x28, 0xa9, 0x10, 0xb6, 0x46, 0xde, 0xe1, 0xe1,
0x3f, 0xc1, 0xcc, 0x72, 0xbe, 0x2a, 0x43, 0xc6, 0xf6, 0xd0, 0xb5, 0xa0, 0xc4, 0x24, 0x6e, 0x4f,
0xbd, 0xec, 0x22, 0x8a, 0x07, 0x11, 0x3d, 0xf9, 0xd3, 0x15, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3,
0x82, 0x01, 0x26, 0x30, 0x82, 0x01, 0x22, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18,
0x30, 0x16, 0x80, 0x14, 0xf2, 0x9d, 0x42, 0x4e, 0x0f, 0xc4, 0x48, 0x25, 0x58, 0x2f, 0x1c, 0xce,
0x0f, 0xa1, 0x3f, 0x22, 0xc8, 0x55, 0xc8, 0x91, 0x30, 0x3b, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
0x05, 0x07, 0x01, 0x01, 0x04, 0x2f, 0x30, 0x2d, 0x30, 0x2b, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
0x05, 0x07, 0x30, 0x01, 0x86, 0x1f, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x69, 0x70, 0x61,
0x2d, 0x63, 0x61, 0x2e, 0x69, 0x70, 0x61, 0x2e, 0x64, 0x65, 0x76, 0x65, 0x6c, 0x2f, 0x63, 0x61,
0x2f, 0x6f, 0x63, 0x73, 0x70, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04,
0x04, 0x03, 0x02, 0x04, 0xf0, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x16, 0x30, 0x14,
0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
0x05, 0x07, 0x03, 0x02, 0x30, 0x74, 0x06, 0x03, 0x55, 0x1d, 0x1f, 0x04, 0x6d, 0x30, 0x6b, 0x30,
0x69, 0xa0, 0x31, 0xa0, 0x2f, 0x86, 0x2d, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x69, 0x70,
0x61, 0x2d, 0x63, 0x61, 0x2e, 0x69, 0x70, 0x61, 0x2e, 0x64, 0x65, 0x76, 0x65, 0x6c, 0x2f, 0x69,
0x70, 0x61, 0x2f, 0x63, 0x72, 0x6c, 0x2f, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x43, 0x52, 0x4c,
0x2e, 0x62, 0x69, 0x6e, 0xa2, 0x34, 0xa4, 0x32, 0x30, 0x30, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03,
0x55, 0x04, 0x0a, 0x0c, 0x05, 0x69, 0x70, 0x61, 0x63, 0x61, 0x31, 0x1e, 0x30, 0x1c, 0x06, 0x03,
0x55, 0x04, 0x03, 0x0c, 0x15, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65,
0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d,
0x0e, 0x04, 0x16, 0x04, 0x14, 0x2d, 0x2b, 0x3f, 0xcb, 0xf5, 0xb2, 0xff, 0x32, 0x2c, 0xa8, 0xc2,
0x1c, 0xdd, 0xbd, 0x8c, 0x80, 0x1e, 0xdd, 0x31, 0x82, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x9a, 0x47, 0x2e,
0x50, 0xa7, 0x4d, 0x1d, 0x53, 0x0f, 0xc9, 0x71, 0x42, 0x0c, 0xe5, 0xda, 0x7d, 0x49, 0x64, 0xe7,
0xab, 0xc8, 0xdf, 0xdf, 0x02, 0xc1, 0x87, 0xd1, 0x5b, 0xde, 0xda, 0x6f, 0x2b, 0xe4, 0xf0, 0xbe,
0xba, 0x09, 0xdf, 0x02, 0x85, 0x0b, 0x8a, 0xe6, 0x9b, 0x06, 0x7d, 0x69, 0x38, 0x6c, 0x72, 0xff,
0x4c, 0x7b, 0x2a, 0x0d, 0x3f, 0x23, 0x2f, 0x16, 0x46, 0xff, 0x05, 0x93, 0xb0, 0xea, 0x24, 0x28,
0xd7, 0x12, 0xa1, 0x57, 0xb8, 0x59, 0x19, 0x25, 0xf3, 0x43, 0x0a, 0xd3, 0xfd, 0x0f, 0x37, 0x8d,
0xb8, 0xca, 0x15, 0xe7, 0x48, 0x8a, 0xa0, 0xc7, 0xc7, 0x4b, 0x7f, 0x01, 0x3c, 0x58, 0xd7, 0x37,
0xe5, 0xff, 0x7d, 0x2b, 0x01, 0xac, 0x0d, 0x9f, 0x51, 0x6a, 0xe5, 0x40, 0x24, 0xe6, 0x5e, 0x55,
0x0d, 0xf7, 0xb8, 0x2f, 0x42, 0xac, 0x6d, 0xe5, 0x29, 0x6b, 0xc6, 0x0b, 0xa4, 0xbf, 0x19, 0xbd,
0x39, 0x27, 0xee, 0xfe, 0xc5, 0xb3, 0xdb, 0x62, 0xd4, 0xbe, 0xd2, 0x47, 0xba, 0x96, 0x30, 0x5a,
0xfd, 0x62, 0x00, 0xb8, 0x27, 0x5d, 0x2f, 0x3a, 0x94, 0x0b, 0x95, 0x35, 0x85, 0x40, 0x2c, 0xbc,
0x67, 0xdf, 0x8a, 0xf9, 0xf1, 0x7b, 0x19, 0x96, 0x3e, 0x42, 0x48, 0x13, 0x23, 0x04, 0x95, 0xa9,
0x6b, 0x11, 0x33, 0x81, 0x47, 0x5a, 0x83, 0x72, 0xf6, 0x20, 0xfa, 0x8e, 0x41, 0x7b, 0x8f, 0x77,
0x47, 0x7c, 0xc7, 0x5d, 0x46, 0xf4, 0x4f, 0xfd, 0x81, 0x0a, 0xae, 0x39, 0x27, 0xb6, 0x6a, 0x26,
0x63, 0xb1, 0xd3, 0xbf, 0x55, 0x83, 0x82, 0x9b, 0x36, 0x6c, 0x33, 0x64, 0x0f, 0x50, 0xc0, 0x55,
0x94, 0x13, 0xc3, 0x85, 0xf4, 0xd5, 0x71, 0x65, 0xd0, 0xc0, 0xdd, 0xfc, 0xe6, 0xec, 0x9c, 0x5b,
0xf0, 0x11, 0xb5, 0x2c, 0xf3, 0x48, 0xc1, 0x36, 0x8c, 0xa2, 0x96, 0x48, 0x84};

const uint8_t test_cert2_der[] = {
0x30, 0x82, 0x06, 0x98, 0x30, 0x82, 0x05, 0x80, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x0a, 0x61,
0x22, 0x88, 0xc2, 0x00, 0x00, 0x00, 0x00, 0x02, 0xa6, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x45, 0x31, 0x15, 0x30, 0x13, 0x06, 0x0a,
0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19, 0x16, 0x05, 0x64, 0x65, 0x76, 0x65,
0x6c, 0x31, 0x12, 0x30, 0x10, 0x06, 0x0a, 0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01,
0x19, 0x16, 0x02, 0x61, 0x64, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0f,
0x61, 0x64, 0x2d, 0x41, 0x44, 0x2d, 0x53, 0x45, 0x52, 0x56, 0x45, 0x52, 0x2d, 0x43, 0x41, 0x30,
0x1e, 0x17, 0x0d, 0x31, 0x36, 0x31, 0x31, 0x31, 0x31, 0x31, 0x33, 0x35, 0x31, 0x31, 0x31, 0x5a,
0x17, 0x0d, 0x31, 0x37, 0x31, 0x31, 0x31, 0x31, 0x31, 0x33, 0x35, 0x31, 0x31, 0x31, 0x5a, 0x30,
0x70, 0x31, 0x15, 0x30, 0x13, 0x06, 0x0a, 0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01,
0x19, 0x16, 0x05, 0x64, 0x65, 0x76, 0x65, 0x6c, 0x31, 0x12, 0x30, 0x10, 0x06, 0x0a, 0x09, 0x92,
0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19, 0x16, 0x02, 0x61, 0x64, 0x31, 0x0e, 0x30, 0x0c,
0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x05, 0x55, 0x73, 0x65, 0x72, 0x73, 0x31, 0x0c, 0x30, 0x0a,
0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x03, 0x74, 0x20, 0x75, 0x31, 0x25, 0x30, 0x23, 0x06, 0x09,
0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x16, 0x74, 0x65, 0x73, 0x74, 0x2e,
0x75, 0x73, 0x65, 0x72, 0x40, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x2e, 0x64, 0x6f, 0x6d, 0x61, 0x69,
0x6e, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01,
0x01, 0x00, 0x9c, 0xcf, 0x36, 0x99, 0xde, 0x63, 0x74, 0x2b, 0x77, 0x25, 0x9e, 0x24, 0xd9, 0x77,
0x4b, 0x5f, 0x98, 0xc0, 0x8c, 0xd7, 0x20, 0x91, 0xc0, 0x1c, 0xe8, 0x37, 0x45, 0xbf, 0x3c, 0xd9,
0x33, 0xbd, 0xe9, 0xde, 0xc9, 0x5d, 0xd4, 0xcd, 0x06, 0x0a, 0x0d, 0xd4, 0xf1, 0x7c, 0x74, 0x5b,
0x29, 0xd5, 0x66, 0x9c, 0x2c, 0x9f, 0x6b, 0x1a, 0x0f, 0x0d, 0xe6, 0x6c, 0x62, 0xa5, 0x41, 0x4f,
0xc3, 0xa4, 0x88, 0x27, 0x11, 0x5d, 0xb7, 0xb1, 0xfb, 0xf8, 0x8d, 0xee, 0x43, 0x8d, 0x93, 0xb5,
0x8c, 0xb4, 0x34, 0x06, 0xf5, 0xe9, 0x2f, 0x5a, 0x26, 0x68, 0xd7, 0x43, 0x60, 0x82, 0x5e, 0x22,
0xa7, 0xc6, 0x34, 0x40, 0x19, 0xa5, 0x8e, 0xf0, 0x58, 0x9f, 0x16, 0x2d, 0x43, 0x3f, 0x0c, 0xda,
0xe2, 0x23, 0xf6, 0x09, 0x2a, 0x5e, 0xbd, 0x84, 0x27, 0xc8, 0xab, 0xd5, 0x70, 0xf8, 0x3d, 0x9c,
0x14, 0xc2, 0xc2, 0xa2, 0x77, 0xe8, 0x44, 0x73, 0x10, 0x01, 0x34, 0x40, 0x1f, 0xc6, 0x2f, 0xa0,
0x70, 0xee, 0x2f, 0xd5, 0x4b, 0xbe, 0x4c, 0xc7, 0x45, 0xf7, 0xac, 0x9c, 0xc3, 0x68, 0x5b, 0x1d,
0x5a, 0x4b, 0x77, 0x65, 0x76, 0xe4, 0xb3, 0x92, 0xf4, 0x84, 0x0a, 0x9e, 0x6a, 0x9c, 0xc9, 0x53,
0x42, 0x9f, 0x6d, 0xfe, 0xf9, 0xf5, 0xf2, 0x9a, 0x15, 0x50, 0x47, 0xef, 0xf4, 0x06, 0x59, 0xc8,
0x50, 0x48, 0x4b, 0x46, 0x95, 0x68, 0x25, 0xc5, 0xbd, 0x4f, 0x65, 0x34, 0x00, 0xfc, 0x31, 0x69,
0xf8, 0x3e, 0xe0, 0x20, 0x83, 0x41, 0x27, 0x0b, 0x5c, 0x46, 0x98, 0x14, 0xf0, 0x07, 0xde, 0x02,
0x17, 0xb1, 0xd2, 0x9c, 0xbe, 0x1c, 0x0d, 0x56, 0x22, 0x1b, 0x02, 0xfe, 0xda, 0x69, 0xb9, 0xef,
0x91, 0x37, 0x39, 0x7f, 0x24, 0xda, 0xc4, 0x81, 0x5e, 0x82, 0x31, 0x2f, 0x98, 0x1d, 0xf7, 0x73,
0x5b, 0x23, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x82, 0x03, 0x5d, 0x30, 0x82, 0x03, 0x59, 0x30,
0x3d, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x07, 0x04, 0x30, 0x30, 0x2e,
0x06, 0x26, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x08, 0x87, 0x85, 0xa1, 0x23, 0x84,
0xc8, 0xb2, 0x26, 0x83, 0x9d, 0x9d, 0x21, 0x82, 0xd4, 0xa6, 0x1b, 0x86, 0xa3, 0xba, 0x37, 0x81,
0x10, 0x85, 0x89, 0xd5, 0x02, 0xd6, 0x8f, 0x24, 0x02, 0x01, 0x64, 0x02, 0x01, 0x02, 0x30, 0x29,
0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x22, 0x30, 0x20, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05,
0x07, 0x03, 0x02, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04, 0x06, 0x0a, 0x2b,
0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0a, 0x03, 0x04, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f,
0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x05, 0xa0, 0x30, 0x35, 0x06, 0x09, 0x2b, 0x06, 0x01,
0x04, 0x01, 0x82, 0x37, 0x15, 0x0a, 0x04, 0x28, 0x30, 0x26, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06,
0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
0x03, 0x04, 0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0a, 0x03, 0x04,
0x30, 0x81, 0x94, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0f, 0x04, 0x81,
0x86, 0x30, 0x81, 0x83, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01,
0x2a, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2d, 0x30, 0x0b,
0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16, 0x30, 0x0b, 0x06, 0x09, 0x60,
0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x19, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
0x65, 0x03, 0x04, 0x01, 0x02, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
0x01, 0x05, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x07, 0x30, 0x07,
0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x07, 0x30, 0x0e, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7,
0x0d, 0x03, 0x02, 0x02, 0x02, 0x00, 0x80, 0x30, 0x0e, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7,
0x0d, 0x03, 0x04, 0x02, 0x02, 0x02, 0x00, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16,
0x04, 0x14, 0x49, 0xac, 0xad, 0xe0, 0x65, 0x30, 0xc4, 0xce, 0xa0, 0x09, 0x03, 0x5b, 0xad, 0x4a,
0x7b, 0x49, 0x5e, 0xc9, 0x6c, 0xb4, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30,
0x16, 0x80, 0x14, 0x62, 0x50, 0xb6, 0x8d, 0xa1, 0xe6, 0x2d, 0x91, 0xbf, 0xb0, 0x54, 0x4d, 0x8f,
0xa8, 0xca, 0x10, 0xae, 0xb8, 0xdd, 0x54, 0x30, 0x81, 0xcc, 0x06, 0x03, 0x55, 0x1d, 0x1f, 0x04,
0x81, 0xc4, 0x30, 0x81, 0xc1, 0x30, 0x81, 0xbe, 0xa0, 0x81, 0xbb, 0xa0, 0x81, 0xb8, 0x86, 0x81,
0xb5, 0x6c, 0x64, 0x61, 0x70, 0x3a, 0x2f, 0x2f, 0x2f, 0x43, 0x4e, 0x3d, 0x61, 0x64, 0x2d, 0x41,
0x44, 0x2d, 0x53, 0x45, 0x52, 0x56, 0x45, 0x52, 0x2d, 0x43, 0x41, 0x2c, 0x43, 0x4e, 0x3d, 0x61,
0x64, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2c, 0x43, 0x4e, 0x3d, 0x43, 0x44, 0x50, 0x2c,
0x43, 0x4e, 0x3d, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x25, 0x32, 0x30, 0x4b, 0x65, 0x79, 0x25,
0x32, 0x30, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2c, 0x43, 0x4e, 0x3d, 0x53, 0x65,
0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2c, 0x43, 0x4e, 0x3d, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67,
0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2c, 0x44, 0x43, 0x3d, 0x61, 0x64, 0x2c, 0x44, 0x43,
0x3d, 0x64, 0x65, 0x76, 0x65, 0x6c, 0x3f, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61,
0x74, 0x65, 0x52, 0x65, 0x76, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4c, 0x69, 0x73, 0x74,
0x3f, 0x62, 0x61, 0x73, 0x65, 0x3f, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73,
0x73, 0x3d, 0x63, 0x52, 0x4c, 0x44, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x69, 0x6f,
0x6e, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x30, 0x81, 0xbe, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05,
0x07, 0x01, 0x01, 0x04, 0x81, 0xb1, 0x30, 0x81, 0xae, 0x30, 0x81, 0xab, 0x06, 0x08, 0x2b, 0x06,
0x01, 0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x81, 0x9e, 0x6c, 0x64, 0x61, 0x70, 0x3a, 0x2f, 0x2f,
0x2f, 0x43, 0x4e, 0x3d, 0x61, 0x64, 0x2d, 0x41, 0x44, 0x2d, 0x53, 0x45, 0x52, 0x56, 0x45, 0x52,
0x2d, 0x43, 0x41, 0x2c, 0x43, 0x4e, 0x3d, 0x41, 0x49, 0x41, 0x2c, 0x43, 0x4e, 0x3d, 0x50, 0x75,
0x62, 0x6c, 0x69, 0x63, 0x25, 0x32, 0x30, 0x4b, 0x65, 0x79, 0x25, 0x32, 0x30, 0x53, 0x65, 0x72,
0x76, 0x69, 0x63, 0x65, 0x73, 0x2c, 0x43, 0x4e, 0x3d, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
0x73, 0x2c, 0x43, 0x4e, 0x3d, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69,
0x6f, 0x6e, 0x2c, 0x44, 0x43, 0x3d, 0x61, 0x64, 0x2c, 0x44, 0x43, 0x3d, 0x64, 0x65, 0x76, 0x65,
0x6c, 0x3f, 0x63, 0x41, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x3f,
0x62, 0x61, 0x73, 0x65, 0x3f, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73,
0x3d, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x41, 0x75,
0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x30, 0x3f, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x38,
0x30, 0x36, 0xa0, 0x1c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03,
0xa0, 0x0e, 0x0c, 0x0c, 0x74, 0x75, 0x31, 0x40, 0x61, 0x64, 0x2e, 0x64, 0x65, 0x76, 0x65, 0x6c,
0x81, 0x16, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x75, 0x73, 0x65, 0x72, 0x40, 0x65, 0x6d, 0x61, 0x69,
0x6c, 0x2e, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x41, 0x45, 0x0a, 0x6d,
0xbb, 0x7f, 0x5c, 0x07, 0x0c, 0xc9, 0xb0, 0x39, 0x55, 0x6d, 0x7c, 0xb5, 0x02, 0xcd, 0xe8, 0xb2,
0xe5, 0x02, 0x94, 0x77, 0x60, 0xdb, 0xd1, 0xaf, 0x1d, 0xdb, 0x44, 0x5f, 0xce, 0x83, 0xdb, 0x80,
0x2e, 0xe2, 0xb2, 0x08, 0x25, 0x82, 0x14, 0xcb, 0x48, 0x95, 0x20, 0x13, 0x6c, 0xa9, 0xaa, 0xf8,
0x31, 0x56, 0xed, 0xc0, 0x3b, 0xd4, 0xae, 0x2e, 0xe3, 0x8f, 0x05, 0xfc, 0xab, 0x5f, 0x2a, 0x69,
0x23, 0xbc, 0xb8, 0x8c, 0xec, 0x2d, 0xa9, 0x0b, 0x86, 0x95, 0x73, 0x73, 0xdb, 0x17, 0xce, 0xc6,
0xae, 0xc5, 0xb4, 0xc1, 0x25, 0x87, 0x3b, 0x67, 0x43, 0x9e, 0x87, 0x5a, 0xe6, 0xb9, 0xa0, 0x28,
0x12, 0x3d, 0xa8, 0x2e, 0xd7, 0x5e, 0xef, 0x65, 0x2d, 0xe6, 0xa5, 0x67, 0x84, 0xac, 0xfd, 0x31,
0xc1, 0x78, 0xd8, 0x72, 0x51, 0xa2, 0x88, 0x55, 0x0f, 0x97, 0x47, 0x93, 0x07, 0xea, 0x8a, 0x53,
0x27, 0x4e, 0x34, 0x54, 0x34, 0x1f, 0xa0, 0x6a, 0x03, 0x44, 0xfb, 0x23, 0x61, 0x8e, 0x87, 0x8e,
0x3c, 0xd0, 0x8f, 0xae, 0xe4, 0xcf, 0xee, 0x65, 0xa8, 0xba, 0x96, 0x68, 0x08, 0x1c, 0x60, 0xe2,
0x4e, 0x11, 0xa3, 0x74, 0xb8, 0xa5, 0x4e, 0xea, 0x6a, 0x82, 0x4c, 0xc2, 0x4d, 0x63, 0x8e, 0x9f,
0x7c, 0x2f, 0xa8, 0xc0, 0x62, 0xf8, 0xf7, 0xd9, 0x25, 0xc4, 0x91, 0xab, 0x4d, 0x6a, 0x44, 0xaf,
0x75, 0x93, 0x53, 0x03, 0xa4, 0x99, 0xc8, 0xcd, 0x91, 0x89, 0x60, 0x75, 0x30, 0x99, 0x76, 0x05,
0x5a, 0xa0, 0x03, 0xa7, 0xa1, 0x2c, 0x03, 0x04, 0x8f, 0xd4, 0x5a, 0x31, 0x52, 0x28, 0x5a, 0xe6,
0xa2, 0xd3, 0x43, 0x21, 0x5b, 0xdc, 0xa2, 0x1d, 0x55, 0xa9, 0x48, 0xc5, 0xc4, 0xaa, 0xf3, 0x8b,
0xe6, 0x3e, 0x75, 0x96, 0xe4, 0x3e, 0x64, 0xaf, 0xe8, 0xa7, 0x6a, 0xb6};

/* used to test SAN principal encoding according to RFC4556 */
const uint8_t test_cert3_der[] = {
0x30, 0x82, 0x03, 0x70, 0x30, 0x82, 0x02, 0x58, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00,
0xe5, 0x8f, 0x16, 0xfe, 0x23, 0x4d, 0xc5, 0xd6, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x1a, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55,
0x04, 0x03, 0x0c, 0x0f, 0x6b, 0x72, 0x62, 0x35, 0x5f, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x5f, 0x74,
0x65, 0x73, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x37, 0x30, 0x37, 0x31, 0x32, 0x30, 0x39, 0x32,
0x34, 0x31, 0x38, 0x5a, 0x17, 0x0d, 0x32, 0x30, 0x30, 0x34, 0x30, 0x37, 0x30, 0x39, 0x32, 0x34,
0x31, 0x38, 0x5a, 0x30, 0x1a, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0f,
0x6b, 0x72, 0x62, 0x35, 0x5f, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x5f, 0x74, 0x65, 0x73, 0x74, 0x30,
0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00,
0xbf, 0x84, 0x34, 0x46, 0x37, 0x50, 0xb1, 0xca, 0x14, 0x4c, 0x6b, 0x0d, 0xe4, 0xab, 0xc1, 0xce,
0xf4, 0xd1, 0xde, 0xca, 0xf5, 0x50, 0x46, 0x3c, 0x63, 0x0f, 0x8e, 0xb8, 0xe9, 0xf9, 0x3e, 0xc4,
0xf3, 0x24, 0xc1, 0xe4, 0x78, 0xf6, 0xa4, 0x39, 0x6f, 0xc1, 0xd8, 0x9c, 0x1c, 0xa7, 0x47, 0xe4,
0xc8, 0x71, 0x32, 0x9a, 0x1d, 0x1d, 0xfb, 0x30, 0x0f, 0xf9, 0x85, 0x48, 0xf8, 0x1f, 0xa7, 0xbd,
0xda, 0x39, 0xd4, 0xc7, 0x27, 0x4f, 0xf5, 0x34, 0xee, 0x4a, 0x59, 0x0c, 0x7a, 0xec, 0x2b, 0xaf,
0x81, 0x8e, 0x41, 0x54, 0x6f, 0xcc, 0x91, 0x61, 0x4c, 0x61, 0x80, 0xca, 0x37, 0xab, 0x2c, 0x63,
0x8d, 0xce, 0x07, 0xcd, 0x61, 0x11, 0x10, 0xa0, 0xe4, 0x08, 0x7d, 0x1d, 0x10, 0x85, 0xb1, 0x64,
0x33, 0x6b, 0x4d, 0x8d, 0xd2, 0x9d, 0xd7, 0x0b, 0x21, 0xbc, 0x15, 0xcd, 0xed, 0xaa, 0xc0, 0x01,
0x67, 0xe1, 0x7c, 0xd4, 0xf7, 0xdd, 0xf8, 0x28, 0x92, 0xce, 0x8b, 0x7f, 0x08, 0x29, 0x76, 0x6e,
0xa5, 0xe6, 0xcd, 0xeb, 0x9c, 0x13, 0x78, 0xa3, 0x08, 0xb5, 0xdc, 0x7f, 0xc2, 0x60, 0xc3, 0xac,
0x68, 0x30, 0x37, 0xe1, 0x54, 0x6a, 0xa9, 0x34, 0x3e, 0x43, 0x8d, 0x6f, 0x9b, 0xe5, 0x8a, 0xf9,
0xa4, 0x22, 0xab, 0x33, 0x01, 0x32, 0xaf, 0xc4, 0x9f, 0xb1, 0x27, 0xba, 0xae, 0x20, 0x60, 0xd7,
0x16, 0x48, 0x66, 0x2b, 0x36, 0x9c, 0x54, 0xd0, 0x6e, 0x45, 0xd3, 0x23, 0x3f, 0x17, 0x2e, 0xee,
0xd4, 0x55, 0xa7, 0x75, 0x2f, 0x28, 0xa9, 0x40, 0x3b, 0xbc, 0x79, 0x69, 0xea, 0x58, 0xc2, 0x3c,
0x4c, 0x70, 0x4b, 0x93, 0xd8, 0xa4, 0xb6, 0x59, 0x24, 0x77, 0x10, 0xb3, 0xc7, 0x34, 0x99, 0x6b,
0x28, 0xbd, 0x03, 0xdb, 0xda, 0xea, 0x23, 0x19, 0x10, 0x56, 0x7e, 0xa4, 0x28, 0x04, 0x5a, 0x53,
0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x81, 0xb8, 0x30, 0x81, 0xb5, 0x30, 0x09, 0x06, 0x03, 0x55,
0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x04, 0x04, 0x03,
0x02, 0x03, 0xa8, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x0b, 0x30, 0x09, 0x06, 0x07,
0x2b, 0x06, 0x01, 0x05, 0x02, 0x03, 0x04, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16,
0x04, 0x14, 0xea, 0xd4, 0x30, 0xd7, 0x7d, 0x3b, 0xc7, 0xb4, 0x83, 0x53, 0x2c, 0xa5, 0xb9, 0xd8,
0x1a, 0x47, 0x6b, 0xb5, 0xe5, 0x9d, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30,
0x16, 0x80, 0x14, 0xea, 0xd4, 0x30, 0xd7, 0x7d, 0x3b, 0xc7, 0xb4, 0x83, 0x53, 0x2c, 0xa5, 0xb9,
0xd8, 0x1a, 0x47, 0x6b, 0xb5, 0xe5, 0x9d, 0x30, 0x47, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x40,
0x30, 0x3e, 0xa0, 0x3c, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x02, 0x02, 0xa0, 0x32, 0x30, 0x30,
0xa0, 0x0b, 0x1b, 0x09, 0x53, 0x53, 0x53, 0x44, 0x2e, 0x54, 0x45, 0x53, 0x54, 0xa1, 0x21, 0x30,
0x1f, 0xa0, 0x03, 0x02, 0x01, 0x01, 0xa1, 0x18, 0x30, 0x16, 0x1b, 0x04, 0x74, 0x65, 0x73, 0x74,
0x1b, 0x05, 0x63, 0x6f, 0x6d, 0x70, 0x32, 0x1b, 0x07, 0x61, 0x6e, 0x6f, 0x74, 0x68, 0x65, 0x72,
0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03,
0x82, 0x01, 0x01, 0x00, 0x08, 0x64, 0x63, 0x89, 0x6d, 0x3d, 0x66, 0x77, 0xe3, 0xb6, 0x40, 0x54,
0xd7, 0xe2, 0xc5, 0x99, 0xac, 0x98, 0x6e, 0xf8, 0xcd, 0x62, 0xa4, 0xf8, 0xd9, 0xaf, 0xdb, 0xef,
0xb7, 0x10, 0x8e, 0x45, 0x42, 0x53, 0x5c, 0x3f, 0x6a, 0x8d, 0xa8, 0x8a, 0x6d, 0x76, 0x51, 0x1a,
0xf4, 0x71, 0x54, 0x27, 0x27, 0xe2, 0x45, 0xe8, 0xa8, 0xd2, 0xa9, 0xcd, 0x62, 0x0d, 0xfc, 0x0d,
0x28, 0x46, 0x9e, 0x4e, 0x5a, 0x57, 0x72, 0xb4, 0xf2, 0x35, 0x91, 0x57, 0x11, 0xae, 0x2b, 0x9c,
0x6a, 0x80, 0x21, 0x8e, 0x4c, 0x19, 0x4a, 0x2d, 0xe0, 0xd2, 0xdf, 0x83, 0x9d, 0x65, 0x49, 0xd1,
0x34, 0x34, 0x14, 0xa0, 0xbb, 0x1c, 0xa8, 0x12, 0xb0, 0xe3, 0x5e, 0x82, 0x36, 0x41, 0x4c, 0x87,
0xd1, 0x1e, 0x1a, 0xe9, 0xff, 0x55, 0xef, 0xb5, 0x2d, 0x20, 0xc5, 0xa7, 0xe5, 0x5a, 0xf2, 0xfc,
0xf7, 0xd2, 0x21, 0xc5, 0x32, 0xb4, 0x07, 0x8f, 0xc4, 0x94, 0x56, 0xa6, 0x21, 0x6a, 0xb6, 0x26,
0x05, 0x48, 0x90, 0xe0, 0x6b, 0x22, 0x35, 0x00, 0x51, 0x2e, 0xd7, 0xe8, 0x3a, 0x56, 0xa8, 0x70,
0x7d, 0x0f, 0x9a, 0x97, 0x5a, 0xb8, 0x7f, 0x33, 0xc1, 0xe0, 0x92, 0x0f, 0xb3, 0xfe, 0x36, 0xe6,
0x8b, 0x97, 0x58, 0x42, 0x49, 0xcb, 0x74, 0xde, 0x19, 0x59, 0x90, 0xb6, 0x36, 0x38, 0x07, 0x48,
0x5d, 0x5b, 0xab, 0x08, 0xf0, 0x69, 0x22, 0x42, 0x08, 0x29, 0xfe, 0x43, 0xab, 0x83, 0x73, 0x74,
0x5a, 0x3f, 0x3b, 0x5d, 0x8e, 0xca, 0x6f, 0x2d, 0xad, 0xa1, 0x6e, 0x80, 0x80, 0xd2, 0xc8, 0x16,
0xb7, 0x67, 0x1a, 0x2d, 0x37, 0x8c, 0x20, 0x3b, 0x15, 0xef, 0xb2, 0x94, 0x86, 0x5c, 0xaf, 0xa2,
0x61, 0x8b, 0xc7, 0xc1, 0xe4, 0xbe, 0x60, 0x5a, 0x86, 0x5c, 0x86, 0xba, 0x59, 0x97, 0x83, 0x1b,
0x79, 0x1c, 0x7c, 0x26};

#define TEST_CERT_WITH_SID_EXT \
    "MIIGFDCCBPygAwIBAgITcgAAAAIq7mYIPbH8OgAAAAAAAjANBgkqhkiG9w0BAQsF" \
    "ADBAMRIwEAYKCZImiZPyLGQBGRYCdm0xEjAQBgoJkiaJk/IsZAEZFgJhZDEWMBQG" \
    "A1UEAxMNYWQtUk9PVC1EQy1DQTAeFw0yMjA4MzEwOTA5NDFaFw0yMzA4MzEwOTA5" \
    "NDFaMBgxFjAUBgNVBAMTDXJvb3QtZGMuYWQudm0wggEiMA0GCSqGSIb3DQEBAQUA" \
    "A4IBDwAwggEKAoIBAQCrFS4l2bf9VwFl5NSFOKNcASgUwlxbdobpPQ1mB0Vso3fj" \
    "zo82O8P+zGA9E0ZcrC02w/7MUI7P2HFAyr/TFVBdSa9HM5CIT1CupzJJuLhZQ4/O" \
    "3gdy1W8aSBosorpVwS5EQYvaLrQascryTiWRu8jBNt2+/9WveMBvTXLDkj/fNK/f" \
    "7yGIFrWSjCUk37nZGpLUJQbC+0aEiOuyJn7bs2K9fN3dmZmgbwqsWBREQwhqgbCZ" \
    "5ZWbgs95JGJXScR4S4YKIkHK/hdaOEiqTCTJEpgszKBLdil6Yqt6/66b7Xun64/W" \
    "I4TfScup292WKRlfB0KVMXYxGPo2kPiI8aVwcqNJAgMBAAGjggMtMIIDKTAvBgkr" \
    "BgEEAYI3FAIEIh4gAEQAbwBtAGEAaQBuAEMAbwBuAHQAcgBvAGwAbABlAHIwHQYD" \
    "VR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIFoDB4Bgkq" \
    "hkiG9w0BCQ8EazBpMA4GCCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwCwYJ" \
    "YIZIAWUDBAEqMAsGCWCGSAFlAwQBLTALBglghkgBZQMEAQIwCwYJYIZIAWUDBAEF" \
    "MAcGBSsOAwIHMAoGCCqGSIb3DQMHMB0GA1UdDgQWBBQURvUMyxhOgBeuK0FniBLp" \
    "ZfbqwTAfBgNVHSMEGDAWgBQbcHqjwjfOyWv8FEmhCu5zuhB8nzCBxQYDVR0fBIG9" \
    "MIG6MIG3oIG0oIGxhoGubGRhcDovLy9DTj1hZC1ST09ULURDLUNBLENOPXJvb3Qt" \
    "ZGMsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2Vz" \
    "LENOPUNvbmZpZ3VyYXRpb24sREM9YWQsREM9dm0/Y2VydGlmaWNhdGVSZXZvY2F0" \
    "aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIG5" \
    "BggrBgEFBQcBAQSBrDCBqTCBpgYIKwYBBQUHMAKGgZlsZGFwOi8vL0NOPWFkLVJP" \
    "T1QtREMtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl" \
    "cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9YWQsREM9dm0/Y0FDZXJ0aWZpY2F0" \
    "ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwOQYDVR0R" \
    "BDIwMKAfBgkrBgEEAYI3GQGgEgQQpJvI9IWOiU2FjSe9Y6qTk4INcm9vdC1kYy5h" \
    "ZC52bTBOBgkrBgEEAYI3GQIEQTA/oD0GCisGAQQBgjcZAgGgLwQtUy0xLTUtMjEt" \
    "Mjk0MDI2MTI2LTMzNzgyNDUwMTgtMTIwMzEwMzk0OS0xMDAxMA0GCSqGSIb3DQEB" \
    "CwUAA4IBAQBijGUmixRQ5ZY3g0+ppTcMRKKST0HE+UEUnuoBlnG3cBM4yTBBUWSg" \
    "elzAglwbZbFRWT2ieX7rZzPALNLIyr43eZFpXelZElRGnTNISj9bWV+YEQ1DVGG4" \
    "b0Z3WsrPS1DiKprgf6mNEg7bmNUcD2AYJzuFOUVVHQu+pwIOpWjVAri8MgU37f+o" \
    "eY4fwbgbYQoTb6VGk53QPajONCa0sICDasvC0BNgkfLFUsL4y7xmWEtKJl7o+3Bo" \
    "d+GO2zfbNX8oS/LjZ5f/Vpmiu04VPdiifdYAbfCQez3bevYBQn4D/bq/xVHoHSLY" \
    "x0N7c7iPuFTCbg+OVrkH3OtPuRT/4kTn"

void test_sss_cert_get_content(void **state)
{
    int ret;
    struct sss_cert_content *content;

    ret = sss_cert_get_content(NULL, test_cert_der, sizeof(test_cert_der),
                               &content);
    assert_int_equal(ret , 0);
    assert_non_null(content);
    assert_non_null(content->issuer_str);
    assert_string_equal(content->issuer_str, "CN=Certificate Authority,O=IPA.DEVEL");
    assert_non_null(content->subject_str);
    assert_string_equal(content->subject_str, "CN=ipa-devel.ipa.devel,O=IPA.DEVEL");
    assert_int_equal(content->key_usage, SSS_KU_DIGITAL_SIGNATURE
                                            |SSS_KU_NON_REPUDIATION
                                            |SSS_KU_KEY_ENCIPHERMENT
                                            |SSS_KU_DATA_ENCIPHERMENT);
    assert_non_null(content->extended_key_usage_oids);
    assert_non_null(content->extended_key_usage_oids[0]);
    assert_true(string_in_list("1.3.6.1.5.5.7.3.1",
                discard_const(content->extended_key_usage_oids), true));
    assert_true(string_in_list("1.3.6.1.5.5.7.3.2",
                discard_const(content->extended_key_usage_oids), true));
    assert_null(content->extended_key_usage_oids[2]);
    assert_int_equal(content->cert_der_size, sizeof(test_cert_der));
    assert_memory_equal(content->cert_der, test_cert_der, sizeof(test_cert_der));

    assert_non_null(content->issuer_rdn_list);
    assert_string_equal(content->issuer_rdn_list[0], "O=IPA.DEVEL");
    assert_string_equal(content->issuer_rdn_list[1], "CN=Certificate Authority");
    assert_null(content->issuer_rdn_list[2]);

    assert_non_null(content->subject_rdn_list);
    assert_string_equal(content->subject_rdn_list[0], "O=IPA.DEVEL");
    assert_string_equal(content->subject_rdn_list[1], "CN=ipa-devel.ipa.devel");
    assert_null(content->subject_rdn_list[2]);

    assert_int_equal(content->serial_number_size, 1);
    assert_non_null(content->serial_number);
    assert_memory_equal(content->serial_number, "\x09", 1);
    assert_string_equal(content->serial_number_dec_str, "9");

    assert_int_equal(content->subject_key_id_size, 20);
    assert_non_null(content->subject_key_id);
    assert_memory_equal(content->subject_key_id, "\x2D\x2B\x3F\xCB\xF5\xB2\xFF\x32\x2C\xA8\xC2\x1C\xDD\xBD\x8C\x80\x1E\xDD\x31\x82", 20);

    talloc_free(content);
}

void test_sss_cert_get_content_2(void **state)
{
    int ret;
    struct sss_cert_content *content;
    struct san_list *i;

    ret = sss_cert_get_content(NULL, test_cert2_der, sizeof(test_cert2_der),
                               &content);
    assert_int_equal(ret, 0);
    assert_non_null(content);
    assert_non_null(content->issuer_str);
    assert_string_equal(content->issuer_str,
                        "CN=ad-AD-SERVER-CA,DC=ad,DC=devel");
    assert_non_null(content->subject_str);
#if 0
FIXME:
    assert_string_equal(content->subject_str,
      "E=test.user@email.domain,CN=t u,CN=Users,DC=ad,DC=devel,DC=ad,DC=devel");
      //"CN=t u/emailAddress=test.user@email.domain,DC=ad,DC=devel");
#endif
    assert_int_equal(content->key_usage, SSS_KU_DIGITAL_SIGNATURE
                                            |SSS_KU_KEY_ENCIPHERMENT);
    assert_non_null(content->extended_key_usage_oids);
    assert_non_null(content->extended_key_usage_oids[0]);
    assert_true(string_in_list("1.3.6.1.5.5.7.3.2",
                discard_const(content->extended_key_usage_oids), true));
    assert_true(string_in_list("1.3.6.1.5.5.7.3.4",
                discard_const(content->extended_key_usage_oids), true));
    /* Can use Microsoft Encrypted File System OID */
    assert_true(string_in_list("1.3.6.1.4.1.311.10.3.4",
                discard_const(content->extended_key_usage_oids), true));
    assert_null(content->extended_key_usage_oids[3]);
    assert_int_equal(content->cert_der_size, sizeof(test_cert2_der));
    assert_memory_equal(content->cert_der, test_cert2_der,
                        sizeof(test_cert2_der));

    assert_non_null(content->issuer_rdn_list);
    assert_string_equal(content->issuer_rdn_list[0], "DC=devel");
    assert_string_equal(content->issuer_rdn_list[1], "DC=ad");
    assert_string_equal(content->issuer_rdn_list[2], "CN=ad-AD-SERVER-CA");
    assert_null(content->issuer_rdn_list[3]);

    assert_non_null(content->subject_rdn_list);
    assert_string_equal(content->subject_rdn_list[0], "DC=devel");
    assert_string_equal(content->subject_rdn_list[1], "DC=ad");
    assert_string_equal(content->subject_rdn_list[2], "CN=Users");
    assert_string_equal(content->subject_rdn_list[3], "CN=t u");
    assert_string_equal(content->subject_rdn_list[4],
                                                    "E=test.user@email.domain");
    assert_null(content->subject_rdn_list[5]);

    assert_non_null(content->san_list);

    DLIST_FOR_EACH(i, content->san_list) {
        switch (i->san_opt) {
        case SAN_RFC822_NAME:
            assert_string_equal(i->val, "test.user@email.domain");
            assert_string_equal(i->short_name, "test.user");
            break;
        case SAN_STRING_OTHER_NAME:
            assert_string_equal(i->other_name_oid, "1.3.6.1.4.1.311.20.2.3");
            assert_int_equal(i->bin_val_len, 14);
            assert_memory_equal(i->bin_val, "\f\ftu1@ad.devel", 14);
            break;
        case SAN_NT:
        case SAN_PRINCIPAL:
            assert_string_equal(i->val, "tu1@ad.devel");
            assert_string_equal(i->short_name, "tu1");
            break;
        default:
            assert_true(false);
        }
    }

    assert_int_equal(content->serial_number_size, 10);
    assert_non_null(content->serial_number);
    assert_memory_equal(content->serial_number, "\x61\x22\x88\xc2\x00\x00\x00\x00\x02\xa6", 10);
    assert_string_equal(content->serial_number_dec_str, "458706592575796350550694");

    assert_int_equal(content->subject_key_id_size, 20);
    assert_non_null(content->subject_key_id);
    assert_memory_equal(content->subject_key_id, "\x49\xAC\xAD\xE0\x65\x30\xC4\xCE\xA0\x09\x03\x5B\xAD\x4A\x7B\x49\x5E\xC9\x6C\xB4", 20);

    talloc_free(content);
}

void test_sss_cert_get_content_test_cert_0003(void **state)
{
    int ret;
    uint8_t *der;
    size_t der_size;
    struct sss_cert_content *content;

    der = sss_base64_decode(NULL, SSSD_TEST_CERT_0003, &der_size);
    assert_non_null(der);

    ret = sss_cert_get_content(NULL, der, der_size, &content);
    talloc_free(der);
    assert_int_equal(ret, 0);
    assert_non_null(content);
    assert_non_null(content->issuer_str);
    assert_string_equal(content->issuer_str,
                        "CN=SSSD test CA,OU=SSSD test,O=SSSD");

    assert_non_null(content->issuer_rdn_list);
    assert_string_equal(content->issuer_rdn_list[0], "O=SSSD");
    assert_string_equal(content->issuer_rdn_list[1], "OU=SSSD test");
    assert_string_equal(content->issuer_rdn_list[2], "CN=SSSD test CA");
    assert_null(content->issuer_rdn_list[3]);

    assert_non_null(content->subject_str);
    assert_string_equal(content->subject_str,
                        "CN=SSSD test cert 0003,OU=SSSD test,O=SSSD");

    assert_non_null(content->subject_rdn_list);
    assert_string_equal(content->issuer_rdn_list[0], "O=SSSD");
    assert_string_equal(content->issuer_rdn_list[1], "OU=SSSD test");
    assert_string_equal(content->subject_rdn_list[2], "CN=SSSD test cert 0003");
    assert_null(content->subject_rdn_list[3]);

    assert_int_equal(content->key_usage, SSS_KU_DIGITAL_SIGNATURE
                                            |SSS_KU_KEY_ENCIPHERMENT);

    assert_non_null(content->extended_key_usage_oids);
    assert_null(content->extended_key_usage_oids[0]);

    assert_null(content->san_list);

    assert_int_equal(content->serial_number_size, 1);
    assert_non_null(content->serial_number);
    assert_memory_equal(content->serial_number, SSSD_TEST_CERT_SERIAL_0003, 1);
    assert_string_equal(content->serial_number_dec_str, SSSD_TEST_CERT_DEC_SERIAL_0003);

    assert_int_equal(content->subject_key_id_size, 20);
    assert_non_null(content->subject_key_id);
    assert_memory_equal(content->subject_key_id, "\x28\x3E\xBB\xD6\xD9\x5C\xFE\xC1\xFB\x7C\x49\x3B\x19\xB4\xD6\x63\xB2\x44\x8C\x41", 20);

    talloc_free(content);
}

void test_sss_cert_get_content_test_cert_0004(void **state)
{
    int ret;
    uint8_t *der;
    size_t der_size;
    struct sss_cert_content *content;

    der = sss_base64_decode(NULL, SSSD_TEST_CERT_0004, &der_size);
    assert_non_null(der);

    ret = sss_cert_get_content(NULL, der, der_size, &content);
    talloc_free(der);
    assert_int_equal(ret, 0);
    assert_non_null(content);
    assert_non_null(content->issuer_str);
    assert_string_equal(content->issuer_str,
                        "CN=SSSD test CA,OU=SSSD test,O=SSSD");

    assert_non_null(content->issuer_rdn_list);
    assert_string_equal(content->issuer_rdn_list[0], "O=SSSD");
    assert_string_equal(content->issuer_rdn_list[1], "OU=SSSD test");
    assert_string_equal(content->issuer_rdn_list[2], "CN=SSSD test CA");
    assert_null(content->issuer_rdn_list[3]);

    assert_non_null(content->subject_str);
    assert_string_equal(content->subject_str,
                        "CN=SSSD test cert 0004,OU=SSSD test,O=SSSD");

    assert_non_null(content->subject_rdn_list);
    assert_string_equal(content->issuer_rdn_list[0], "O=SSSD");
    assert_string_equal(content->issuer_rdn_list[1], "OU=SSSD test");
    assert_string_equal(content->subject_rdn_list[2], "CN=SSSD test cert 0004");
    assert_null(content->subject_rdn_list[3]);

    assert_int_equal(content->key_usage, UINT32_MAX);

    assert_non_null(content->extended_key_usage_oids);
    assert_null(content->extended_key_usage_oids[0]);

    assert_null(content->san_list);

    assert_int_equal(content->serial_number_size, 1);
    assert_non_null(content->serial_number);
    assert_memory_equal(content->serial_number, SSSD_TEST_CERT_SERIAL_0004, 1);
    assert_string_equal(content->serial_number_dec_str, SSSD_TEST_CERT_DEC_SERIAL_0004);

    assert_int_equal(content->subject_key_id_size, 20);
    assert_non_null(content->subject_key_id);
    assert_memory_equal(content->subject_key_id, "\xDD\x09\x78\x8E\xE6\x50\xB3\xE3\x3B\x0D\xFB\x9F\xCB\x6D\x66\x48\x95\x1D\xAA\x52", 20);

    talloc_free(content);
}

void test_sss_cert_get_content_test_cert_0001(void **state)
{
    int ret;
    uint8_t *der;
    size_t der_size;
    struct sss_cert_content *content;
    struct san_list *i;
    uint32_t check = 0;

    der = sss_base64_decode(NULL, SSSD_TEST_CERT_0001, &der_size);
    assert_non_null(der);

    ret = sss_cert_get_content(NULL, der, der_size, &content);
    talloc_free(der);
    assert_int_equal(ret, 0);
    assert_non_null(content);

    assert_non_null(content->san_list);
    DLIST_FOR_EACH(i, content->san_list) {
        switch (i->san_opt) {
        case SAN_RFC822_NAME:
            assert_string_equal(i->val, "sssd-devel@lists.fedorahosted.org");
            assert_string_equal(i->short_name, "sssd-devel");
            check |= 1;
            break;
        case SAN_URI:
            assert_string_equal(i->val, "https://github.com/SSSD/sssd//");
            check |= 2;
            break;
        default:
            assert_true(false);
        }
    }
    assert_int_equal(check, 3);

    talloc_free(content);
}

void test_sss_cert_get_content_test_cert_with_sid_ext(void **state)
{
    int ret;
    uint8_t *der;
    size_t der_size;
    struct sss_cert_content *content;

    der = sss_base64_decode(NULL, TEST_CERT_WITH_SID_EXT, &der_size);
    assert_non_null(der);

    ret = sss_cert_get_content(NULL, der, der_size, &content);
    talloc_free(der);
    assert_int_equal(ret, 0);
    assert_non_null(content);

    assert_non_null(content->sid_ext);
    assert_string_equal(content->sid_ext, "S-1-5-21-294026126-3378245018-1203103949-1001");
    talloc_free(content);
}

static void test_sss_certmap_match_cert(void **state)
{
    struct sss_certmap_ctx *ctx;
    int ret;
    size_t c;

    struct match_tests {
        const char *rule;
        int result;
    } match_tests[] = {
        {"KRB5:<KU>digitalSignature", 0},
        {"KRB5:<KU>digitalSignature,nonRepudiation", 0},
        {"KRB5:<KU>digitalSignature,cRLSign", ENOENT},
        {"KRB5:<EKU>clientAuth", 0},
        {"KRB5:<EKU>clientAuth,OCSPSigning", ENOENT},
        {"KRB5:<EKU>clientAuth,serverAuth", 0},
        {NULL, 0}
    };

    struct match_tests match_tests_2[] = {
        {"KRB5:<KU>digitalSignature", 0},
        {"KRB5:<KU>keyEncipherment", 0},
        {"KRB5:<KU>digitalSignature,keyEncipherment", 0},
        {"KRB5:<KU>digitalSignature,keyEncipherment,cRLSign", ENOENT},
        {"KRB5:<EKU>clientAuth", 0},
        {"KRB5:<EKU>clientAuth,1.3.6.1.4.1.311.10.3.4", 0},
        {"KRB5:<EKU>clientAuth,1.3.6.1.4.1.311.10.3.41", ENOENT},
        {"KRB5:<SAN>tu1", 0},
        {"KRB5:<SAN:Principal>tu1", 0},
        {"KRB5:<SAN:ntPrincipalName>tu1", 0},
        {"KRB5:<SAN:pkinitSAN>tu1", ENOENT},
        {"KRB5:<SAN:Principal>^tu1@ad.devel$", 0},
        {"KRB5:<SAN:rfc822Name>tu", ENOENT},
        {"KRB5:<SAN:rfc822Name>test.user", 0},
        {"KRB5:<SAN:rfc822Name>test.user<SAN>tu1", 0},
        {"KRB5:||<SAN:rfc822Name>test.user<SAN>tu1", 0},
        {"KRB5:&&<SAN:rfc822Name>tu1<SAN>tu1", ENOENT},
        {"KRB5:||<SAN:rfc822Name>tu1<SAN>tu1", 0},
        {"KRB5:<SAN:otherName>MTIz", ENOENT}, /* 123 */
        {"KRB5:<SAN:otherName>DAx0dTFAYWQuZGV2ZWw=", 0}, /* "\f\ftu1@ad.devel" */
        {"KRB5:<SAN:otherName>DAx0dTFAYWQuZGV2ZWx4", ENOENT}, /* "\f\ftu1@ad.develx" */
        {"KRB5:<SAN:otherName>dHUxQGFkLmRldmVs", 0}, /* "tu1@ad.devel" */
        {"KRB5:<SAN:1.3.6.1.4.1.311.20.2.3>test", ENOENT},
        {"KRB5:<SAN:1.3.6.1.4.1.311.20.2.3>tu1@ad", 0},
        /* Fails because the NT principal SAN starts with binary values */
        {"KRB5:<SAN:1.3.6.1.4.1.311.20.2.3>^tu1@ad.devel$", ENOENT},
        {NULL, 0}
    };

    struct match_tests match_tests_3[] = {
        {"KRB5:<KU>digitalSignature", 0},
        {"KRB5:<KU>keyEncipherment", 0},
        {"KRB5:<KU>keyAgreement", 0},
        {"KRB5:<KU>digitalSignature,keyAgreement,keyEncipherment", 0},
        {"KRB5:<SAN:Principal>test", 0},
        {"KRB5:<SAN:ntPrincipal>test", ENOENT},
        {"KRB5:<SAN:Principal>comp2", 0},
        {"KRB5:<SAN:Principal>another", 0},
        {"KRB5:<SAN:Principal>test/comp2/another@SSSD.TEST", 0},
        {"KRB5:<SAN:Principal>^test/comp2/another@SSSD.TEST$", 0},
        {"KRB5:<SAN:pkinitSAN>^test/comp2/another@SSSD.TEST$", 0},
        {NULL, 0}
    };

    ret = sss_certmap_init(NULL, ext_debug, NULL, &ctx);
    assert_int_equal(ret, EOK);
    assert_non_null(ctx);
    assert_null(ctx->prio_list);

    ret = sss_certmap_add_rule(ctx, 1, "KRB5:<ISSUER>xyz<SUBJECT>xyz",
                               NULL, NULL);
    assert_int_equal(ret, EOK);

    ret = sss_certmap_match_cert(ctx, discard_const(test_cert_der),
                                 sizeof(test_cert_der));
    assert_int_equal(ret, ENOENT);

    ret = sss_certmap_add_rule(ctx, 1,
                            "KRB5:<ISSUER>CN=Certificate Authority,O=IPA.DEVEL",
                            NULL, NULL);
    assert_int_equal(ret, EOK);

    ret = sss_certmap_match_cert(ctx, discard_const(test_cert_der),
                                 sizeof(test_cert_der));
    assert_int_equal(ret, 0);

    sss_certmap_free_ctx(ctx);

    for (c = 0; match_tests[c].rule != NULL; c++) {
        ret = sss_certmap_init(NULL, ext_debug, NULL, &ctx);
        assert_int_equal(ret, EOK);
        assert_non_null(ctx);
        assert_null(ctx->prio_list);

        ret = sss_certmap_add_rule(ctx, 1, match_tests[c].rule, NULL, NULL);
        assert_int_equal(ret, EOK);

        ret = sss_certmap_match_cert(ctx, discard_const(test_cert_der),
                                     sizeof(test_cert_der));
        assert_int_equal(ret, match_tests[c].result);

        sss_certmap_free_ctx(ctx);
    }

    for (c = 0; match_tests_2[c].rule != NULL; c++) {
        ret = sss_certmap_init(NULL, ext_debug, NULL, &ctx);
        assert_int_equal(ret, EOK);
        assert_non_null(ctx);
        assert_null(ctx->prio_list);

        print_error("Checking matching rule [%s]\n", match_tests_2[c].rule);

        ret = sss_certmap_add_rule(ctx, 1, match_tests_2[c].rule, NULL, NULL);
        assert_int_equal(ret, EOK);

        ret = sss_certmap_match_cert(ctx, discard_const(test_cert2_der),
                                     sizeof(test_cert2_der));
        assert_int_equal(ret, match_tests_2[c].result);

        sss_certmap_free_ctx(ctx);
    }

    for (c = 0; match_tests_3[c].rule != NULL; c++) {
        ret = sss_certmap_init(NULL, ext_debug, NULL, &ctx);
        assert_int_equal(ret, EOK);
        assert_non_null(ctx);
        assert_null(ctx->prio_list);

        print_error("Checking matching rule [%s]\n", match_tests_3[c].rule);

        ret = sss_certmap_add_rule(ctx, 1, match_tests_3[c].rule, NULL, NULL);
        assert_int_equal(ret, EOK);

        ret = sss_certmap_match_cert(ctx, discard_const(test_cert3_der),
                                     sizeof(test_cert3_der));
        assert_int_equal(ret, match_tests_3[c].result);

        sss_certmap_free_ctx(ctx);
    }
}

static void test_sss_certmap_add_mapping_rule(void **state)
{
    struct sss_certmap_ctx *ctx;
    int ret;

    ret = sss_certmap_init(NULL, ext_debug, NULL, &ctx);
    assert_int_equal(ret, EOK);
    assert_non_null(ctx);
    assert_null(ctx->prio_list);

    ret = sss_certmap_add_rule(ctx, 1, NULL, "FWEAWEF:fwefwe", NULL);
    assert_int_equal(ret, ESRCH);

    ret = sss_certmap_add_rule(ctx, 1, NULL, "LDAP:abc", NULL);
    assert_int_equal(ret, 0);
    assert_non_null(ctx->prio_list);
    assert_non_null(ctx->prio_list->rule_list);
    assert_non_null(ctx->prio_list->rule_list->parsed_mapping_rule);
    assert_non_null(ctx->prio_list->rule_list->parsed_mapping_rule->list);
    assert_int_equal(comp_string,
                    ctx->prio_list->rule_list->parsed_mapping_rule->list->type);
    assert_string_equal("abc",
                     ctx->prio_list->rule_list->parsed_mapping_rule->list->val);
    talloc_free(ctx);

    ret = sss_certmap_init(NULL, ext_debug, NULL, &ctx);
    assert_int_equal(ret, EOK);
    assert_non_null(ctx);
    assert_null(ctx->prio_list);
    ret = sss_certmap_add_rule(ctx, 1, NULL, "LDAP:abc{issuer_dn}", NULL);
    assert_int_equal(ret, 0);
    assert_non_null(ctx->prio_list);
    assert_non_null(ctx->prio_list->rule_list);
    assert_non_null(ctx->prio_list->rule_list->parsed_mapping_rule);
    assert_non_null(ctx->prio_list->rule_list->parsed_mapping_rule->list);
    assert_int_equal(comp_string,
                    ctx->prio_list->rule_list->parsed_mapping_rule->list->type);
    assert_string_equal("abc",
                     ctx->prio_list->rule_list->parsed_mapping_rule->list->val);
    assert_int_equal(comp_template,
              ctx->prio_list->rule_list->parsed_mapping_rule->list->next->type);
    assert_string_equal("issuer_dn",
               ctx->prio_list->rule_list->parsed_mapping_rule->list->next->val);
    talloc_free(ctx);

    ret = sss_certmap_init(NULL, ext_debug, NULL, &ctx);
    assert_int_equal(ret, EOK);
    assert_non_null(ctx);
    assert_null(ctx->prio_list);
    ret = sss_certmap_add_rule(ctx, 1, NULL, "{issuer_dn}a:b{{c}}", NULL);
    assert_int_equal(ret, 0);
    assert_non_null(ctx->prio_list);
    assert_non_null(ctx->prio_list->rule_list);
    assert_non_null(ctx->prio_list->rule_list->parsed_mapping_rule);
    assert_non_null(ctx->prio_list->rule_list->parsed_mapping_rule->list);
    assert_int_equal(comp_template,
                    ctx->prio_list->rule_list->parsed_mapping_rule->list->type);
    assert_string_equal("issuer_dn",
                     ctx->prio_list->rule_list->parsed_mapping_rule->list->val);
    assert_int_equal(comp_string,
              ctx->prio_list->rule_list->parsed_mapping_rule->list->next->type);
    assert_string_equal("a:b{c}",
               ctx->prio_list->rule_list->parsed_mapping_rule->list->next->val);
    talloc_free(ctx);

    ret = sss_certmap_init(NULL, ext_debug, NULL, &ctx);
    assert_int_equal(ret, EOK);
    assert_non_null(ctx);
    assert_null(ctx->prio_list);
    ret = sss_certmap_add_rule(ctx, 1, NULL, "LDAP:{issuer_dn}{subject_dn}",
                               NULL);
    assert_int_equal(ret, 0);
    assert_non_null(ctx->prio_list);
    assert_non_null(ctx->prio_list->rule_list);
    assert_non_null(ctx->prio_list->rule_list->parsed_mapping_rule);
    assert_non_null(ctx->prio_list->rule_list->parsed_mapping_rule->list);
    assert_int_equal(comp_template,
                    ctx->prio_list->rule_list->parsed_mapping_rule->list->type);
    assert_string_equal("issuer_dn",
                     ctx->prio_list->rule_list->parsed_mapping_rule->list->val);
    assert_int_equal(comp_template,
              ctx->prio_list->rule_list->parsed_mapping_rule->list->next->type);
    assert_string_equal("subject_dn",
               ctx->prio_list->rule_list->parsed_mapping_rule->list->next->val);
    talloc_free(ctx);
}

#define TEST_CERT_BIN \
            "\\30\\82\\04\\09\\30\\82\\02\\f1\\a0\\03\\02\\01\\02\\02\\01\\09" \
            "\\30\\0d\\06\\09\\2a\\86\\48\\86\\f7\\0d\\01\\01\\0b\\05\\00\\30" \
            "\\34\\31\\12\\30\\10\\06\\03\\55\\04\\0a\\0c\\09\\49\\50\\41\\2e" \
            "\\44\\45\\56\\45\\4c\\31\\1e\\30\\1c\\06\\03\\55\\04\\03\\0c\\15" \
            "\\43\\65\\72\\74\\69\\66\\69\\63\\61\\74\\65\\20\\41\\75\\74\\68" \
            "\\6f\\72\\69\\74\\79\\30\\1e\\17\\0d\\31\\35\\30\\34\\32\\38\\31" \
            "\\30\\32\\31\\31\\31\\5a\\17\\0d\\31\\37\\30\\34\\32\\38\\31\\30" \
            "\\32\\31\\31\\31\\5a\\30\\32\\31\\12\\30\\10\\06\\03\\55\\04\\0a" \
            "\\0c\\09\\49\\50\\41\\2e\\44\\45\\56\\45\\4c\\31\\1c\\30\\1a\\06" \
            "\\03\\55\\04\\03\\0c\\13\\69\\70\\61\\2d\\64\\65\\76\\65\\6c\\2e" \
            "\\69\\70\\61\\2e\\64\\65\\76\\65\\6c\\30\\82\\01\\22\\30\\0d\\06" \
            "\\09\\2a\\86\\48\\86\\f7\\0d\\01\\01\\01\\05\\00\\03\\82\\01\\0f" \
            "\\00\\30\\82\\01\\0a\\02\\82\\01\\01\\00\\b2\\32\\92\\ab\\47\\b8" \
            "\\0c\\13\\54\\4a\\1f\\1e\\29\\06\\ff\\d0\\50\\cb\\f7\\5f\\79\\91" \
            "\\65\\b1\\39\\01\\83\\6a\\ad\\9e\\77\\3b\\f3\\0d\\d7\\b9\\f6\\dc" \
            "\\9e\\4a\\49\\a7\\d0\\66\\72\\cc\\bf\\77\\d6\\de\\a9\\fe\\67\\96" \
            "\\cc\\49\\f1\\37\\23\\2e\\c4\\50\\f4\\eb\\ba\\62\\d4\\23\\4d\\f3" \
            "\\37\\38\\82\\ee\\3b\\3f\\2c\\d0\\80\\9b\\17\\aa\\9b\\eb\\a6\\dd" \
            "\\f6\\15\\ff\\06\\b2\\ce\\ff\\df\\8a\\9e\\95\\85\\49\\1f\\84\\fd" \
            "\\81\\26\\ce\\06\\32\\0d\\36\\ca\\7c\\15\\81\\68\\6b\\8f\\3e\\b3" \
            "\\a2\\fc\\ae\\af\\c2\\44\\58\\15\\95\\40\\fc\\56\\19\\91\\80\\ed" \
            "\\42\\11\\66\\04\\ef\\3c\\e0\\76\\33\\4b\\83\\fa\\7e\\b4\\47\\dc" \
            "\\fb\\ed\\46\\a5\\8d\\0a\\66\\87\\a5\\ef\\7b\\74\\62\\ac\\be\\73" \
            "\\36\\c9\\b4\\fe\\20\\c4\\81\\f3\\fe\\78\\19\\a8\\d0\\af\\7f\\81" \
            "\\72\\24\\61\\d9\\76\\93\\e3\\0b\\d2\\4f\\19\\17\\33\\57\\d4\\82" \
            "\\b0\\f1\\a8\\03\\f6\\01\\99\\a9\\b8\\8c\\83\\c9\\ba\\19\\87\\ea" \
            "\\d6\\3b\\06\\eb\\4c\\f7\\f1\\e5\\28\\a9\\10\\b6\\46\\de\\e1\\e1" \
            "\\3f\\c1\\cc\\72\\be\\2a\\43\\c6\\f6\\d0\\b5\\a0\\c4\\24\\6e\\4f" \
            "\\bd\\ec\\22\\8a\\07\\11\\3d\\f9\\d3\\15\\02\\03\\01\\00\\01\\a3" \
            "\\82\\01\\26\\30\\82\\01\\22\\30\\1f\\06\\03\\55\\1d\\23\\04\\18" \
            "\\30\\16\\80\\14\\f2\\9d\\42\\4e\\0f\\c4\\48\\25\\58\\2f\\1c\\ce" \
            "\\0f\\a1\\3f\\22\\c8\\55\\c8\\91\\30\\3b\\06\\08\\2b\\06\\01\\05" \
            "\\05\\07\\01\\01\\04\\2f\\30\\2d\\30\\2b\\06\\08\\2b\\06\\01\\05" \
            "\\05\\07\\30\\01\\86\\1f\\68\\74\\74\\70\\3a\\2f\\2f\\69\\70\\61" \
            "\\2d\\63\\61\\2e\\69\\70\\61\\2e\\64\\65\\76\\65\\6c\\2f\\63\\61" \
            "\\2f\\6f\\63\\73\\70\\30\\0e\\06\\03\\55\\1d\\0f\\01\\01\\ff\\04" \
            "\\04\\03\\02\\04\\f0\\30\\1d\\06\\03\\55\\1d\\25\\04\\16\\30\\14" \
            "\\06\\08\\2b\\06\\01\\05\\05\\07\\03\\01\\06\\08\\2b\\06\\01\\05" \
            "\\05\\07\\03\\02\\30\\74\\06\\03\\55\\1d\\1f\\04\\6d\\30\\6b\\30" \
            "\\69\\a0\\31\\a0\\2f\\86\\2d\\68\\74\\74\\70\\3a\\2f\\2f\\69\\70" \
            "\\61\\2d\\63\\61\\2e\\69\\70\\61\\2e\\64\\65\\76\\65\\6c\\2f\\69" \
            "\\70\\61\\2f\\63\\72\\6c\\2f\\4d\\61\\73\\74\\65\\72\\43\\52\\4c" \
            "\\2e\\62\\69\\6e\\a2\\34\\a4\\32\\30\\30\\31\\0e\\30\\0c\\06\\03" \
            "\\55\\04\\0a\\0c\\05\\69\\70\\61\\63\\61\\31\\1e\\30\\1c\\06\\03" \
            "\\55\\04\\03\\0c\\15\\43\\65\\72\\74\\69\\66\\69\\63\\61\\74\\65" \
            "\\20\\41\\75\\74\\68\\6f\\72\\69\\74\\79\\30\\1d\\06\\03\\55\\1d" \
            "\\0e\\04\\16\\04\\14\\2d\\2b\\3f\\cb\\f5\\b2\\ff\\32\\2c\\a8\\c2" \
            "\\1c\\dd\\bd\\8c\\80\\1e\\dd\\31\\82\\30\\0d\\06\\09\\2a\\86\\48" \
            "\\86\\f7\\0d\\01\\01\\0b\\05\\00\\03\\82\\01\\01\\00\\9a\\47\\2e" \
            "\\50\\a7\\4d\\1d\\53\\0f\\c9\\71\\42\\0c\\e5\\da\\7d\\49\\64\\e7" \
            "\\ab\\c8\\df\\df\\02\\c1\\87\\d1\\5b\\de\\da\\6f\\2b\\e4\\f0\\be" \
            "\\ba\\09\\df\\02\\85\\0b\\8a\\e6\\9b\\06\\7d\\69\\38\\6c\\72\\ff" \
            "\\4c\\7b\\2a\\0d\\3f\\23\\2f\\16\\46\\ff\\05\\93\\b0\\ea\\24\\28" \
            "\\d7\\12\\a1\\57\\b8\\59\\19\\25\\f3\\43\\0a\\d3\\fd\\0f\\37\\8d" \
            "\\b8\\ca\\15\\e7\\48\\8a\\a0\\c7\\c7\\4b\\7f\\01\\3c\\58\\d7\\37" \
            "\\e5\\ff\\7d\\2b\\01\\ac\\0d\\9f\\51\\6a\\e5\\40\\24\\e6\\5e\\55" \
            "\\0d\\f7\\b8\\2f\\42\\ac\\6d\\e5\\29\\6b\\c6\\0b\\a4\\bf\\19\\bd" \
            "\\39\\27\\ee\\fe\\c5\\b3\\db\\62\\d4\\be\\d2\\47\\ba\\96\\30\\5a" \
            "\\fd\\62\\00\\b8\\27\\5d\\2f\\3a\\94\\0b\\95\\35\\85\\40\\2c\\bc" \
            "\\67\\df\\8a\\f9\\f1\\7b\\19\\96\\3e\\42\\48\\13\\23\\04\\95\\a9" \
            "\\6b\\11\\33\\81\\47\\5a\\83\\72\\f6\\20\\fa\\8e\\41\\7b\\8f\\77" \
            "\\47\\7c\\c7\\5d\\46\\f4\\4f\\fd\\81\\0a\\ae\\39\\27\\b6\\6a\\26" \
            "\\63\\b1\\d3\\bf\\55\\83\\82\\9b\\36\\6c\\33\\64\\0f\\50\\c0\\55" \
            "\\94\\13\\c3\\85\\f4\\d5\\71\\65\\d0\\c0\\dd\\fc\\e6\\ec\\9c\\5b" \
            "\\f0\\11\\b5\\2c\\f3\\48\\c1\\36\\8c\\a2\\96\\48\\84"

#define TEST_CERT2_BIN \
            "\\30\\82\\06\\98\\30\\82\\05\\80\\a0\\03\\02\\01\\02\\02\\0a\\61" \
            "\\22\\88\\c2\\00\\00\\00\\00\\02\\a6\\30\\0d\\06\\09\\2a\\86\\48" \
            "\\86\\f7\\0d\\01\\01\\05\\05\\00\\30\\45\\31\\15\\30\\13\\06\\0a" \
            "\\09\\92\\26\\89\\93\\f2\\2c\\64\\01\\19\\16\\05\\64\\65\\76\\65" \
            "\\6c\\31\\12\\30\\10\\06\\0a\\09\\92\\26\\89\\93\\f2\\2c\\64\\01" \
            "\\19\\16\\02\\61\\64\\31\\18\\30\\16\\06\\03\\55\\04\\03\\13\\0f" \
            "\\61\\64\\2d\\41\\44\\2d\\53\\45\\52\\56\\45\\52\\2d\\43\\41\\30" \
            "\\1e\\17\\0d\\31\\36\\31\\31\\31\\31\\31\\33\\35\\31\\31\\31\\5a" \
            "\\17\\0d\\31\\37\\31\\31\\31\\31\\31\\33\\35\\31\\31\\31\\5a\\30" \
            "\\70\\31\\15\\30\\13\\06\\0a\\09\\92\\26\\89\\93\\f2\\2c\\64\\01" \
            "\\19\\16\\05\\64\\65\\76\\65\\6c\\31\\12\\30\\10\\06\\0a\\09\\92" \
            "\\26\\89\\93\\f2\\2c\\64\\01\\19\\16\\02\\61\\64\\31\\0e\\30\\0c" \
            "\\06\\03\\55\\04\\03\\13\\05\\55\\73\\65\\72\\73\\31\\0c\\30\\0a" \
            "\\06\\03\\55\\04\\03\\13\\03\\74\\20\\75\\31\\25\\30\\23\\06\\09" \
            "\\2a\\86\\48\\86\\f7\\0d\\01\\09\\01\\16\\16\\74\\65\\73\\74\\2e" \
            "\\75\\73\\65\\72\\40\\65\\6d\\61\\69\\6c\\2e\\64\\6f\\6d\\61\\69" \
            "\\6e\\30\\82\\01\\22\\30\\0d\\06\\09\\2a\\86\\48\\86\\f7\\0d\\01" \
            "\\01\\01\\05\\00\\03\\82\\01\\0f\\00\\30\\82\\01\\0a\\02\\82\\01" \
            "\\01\\00\\9c\\cf\\36\\99\\de\\63\\74\\2b\\77\\25\\9e\\24\\d9\\77" \
            "\\4b\\5f\\98\\c0\\8c\\d7\\20\\91\\c0\\1c\\e8\\37\\45\\bf\\3c\\d9" \
            "\\33\\bd\\e9\\de\\c9\\5d\\d4\\cd\\06\\0a\\0d\\d4\\f1\\7c\\74\\5b" \
            "\\29\\d5\\66\\9c\\2c\\9f\\6b\\1a\\0f\\0d\\e6\\6c\\62\\a5\\41\\4f" \
            "\\c3\\a4\\88\\27\\11\\5d\\b7\\b1\\fb\\f8\\8d\\ee\\43\\8d\\93\\b5" \
            "\\8c\\b4\\34\\06\\f5\\e9\\2f\\5a\\26\\68\\d7\\43\\60\\82\\5e\\22" \
            "\\a7\\c6\\34\\40\\19\\a5\\8e\\f0\\58\\9f\\16\\2d\\43\\3f\\0c\\da" \
            "\\e2\\23\\f6\\09\\2a\\5e\\bd\\84\\27\\c8\\ab\\d5\\70\\f8\\3d\\9c" \
            "\\14\\c2\\c2\\a2\\77\\e8\\44\\73\\10\\01\\34\\40\\1f\\c6\\2f\\a0" \
            "\\70\\ee\\2f\\d5\\4b\\be\\4c\\c7\\45\\f7\\ac\\9c\\c3\\68\\5b\\1d" \
            "\\5a\\4b\\77\\65\\76\\e4\\b3\\92\\f4\\84\\0a\\9e\\6a\\9c\\c9\\53" \
            "\\42\\9f\\6d\\fe\\f9\\f5\\f2\\9a\\15\\50\\47\\ef\\f4\\06\\59\\c8" \
            "\\50\\48\\4b\\46\\95\\68\\25\\c5\\bd\\4f\\65\\34\\00\\fc\\31\\69" \
            "\\f8\\3e\\e0\\20\\83\\41\\27\\0b\\5c\\46\\98\\14\\f0\\07\\de\\02" \
            "\\17\\b1\\d2\\9c\\be\\1c\\0d\\56\\22\\1b\\02\\fe\\da\\69\\b9\\ef" \
            "\\91\\37\\39\\7f\\24\\da\\c4\\81\\5e\\82\\31\\2f\\98\\1d\\f7\\73" \
            "\\5b\\23\\02\\03\\01\\00\\01\\a3\\82\\03\\5d\\30\\82\\03\\59\\30" \
            "\\3d\\06\\09\\2b\\06\\01\\04\\01\\82\\37\\15\\07\\04\\30\\30\\2e" \
            "\\06\\26\\2b\\06\\01\\04\\01\\82\\37\\15\\08\\87\\85\\a1\\23\\84" \
            "\\c8\\b2\\26\\83\\9d\\9d\\21\\82\\d4\\a6\\1b\\86\\a3\\ba\\37\\81" \
            "\\10\\85\\89\\d5\\02\\d6\\8f\\24\\02\\01\\64\\02\\01\\02\\30\\29" \
            "\\06\\03\\55\\1d\\25\\04\\22\\30\\20\\06\\08\\2b\\06\\01\\05\\05" \
            "\\07\\03\\02\\06\\08\\2b\\06\\01\\05\\05\\07\\03\\04\\06\\0a\\2b" \
            "\\06\\01\\04\\01\\82\\37\\0a\\03\\04\\30\\0e\\06\\03\\55\\1d\\0f" \
            "\\01\\01\\ff\\04\\04\\03\\02\\05\\a0\\30\\35\\06\\09\\2b\\06\\01" \
            "\\04\\01\\82\\37\\15\\0a\\04\\28\\30\\26\\30\\0a\\06\\08\\2b\\06" \
            "\\01\\05\\05\\07\\03\\02\\30\\0a\\06\\08\\2b\\06\\01\\05\\05\\07" \
            "\\03\\04\\30\\0c\\06\\0a\\2b\\06\\01\\04\\01\\82\\37\\0a\\03\\04" \
            "\\30\\81\\94\\06\\09\\2a\\86\\48\\86\\f7\\0d\\01\\09\\0f\\04\\81" \
            "\\86\\30\\81\\83\\30\\0b\\06\\09\\60\\86\\48\\01\\65\\03\\04\\01" \
            "\\2a\\30\\0b\\06\\09\\60\\86\\48\\01\\65\\03\\04\\01\\2d\\30\\0b" \
            "\\06\\09\\60\\86\\48\\01\\65\\03\\04\\01\\16\\30\\0b\\06\\09\\60" \
            "\\86\\48\\01\\65\\03\\04\\01\\19\\30\\0b\\06\\09\\60\\86\\48\\01" \
            "\\65\\03\\04\\01\\02\\30\\0b\\06\\09\\60\\86\\48\\01\\65\\03\\04" \
            "\\01\\05\\30\\0a\\06\\08\\2a\\86\\48\\86\\f7\\0d\\03\\07\\30\\07" \
            "\\06\\05\\2b\\0e\\03\\02\\07\\30\\0e\\06\\08\\2a\\86\\48\\86\\f7" \
            "\\0d\\03\\02\\02\\02\\00\\80\\30\\0e\\06\\08\\2a\\86\\48\\86\\f7" \
            "\\0d\\03\\04\\02\\02\\02\\00\\30\\1d\\06\\03\\55\\1d\\0e\\04\\16" \
            "\\04\\14\\49\\ac\\ad\\e0\\65\\30\\c4\\ce\\a0\\09\\03\\5b\\ad\\4a" \
            "\\7b\\49\\5e\\c9\\6c\\b4\\30\\1f\\06\\03\\55\\1d\\23\\04\\18\\30" \
            "\\16\\80\\14\\62\\50\\b6\\8d\\a1\\e6\\2d\\91\\bf\\b0\\54\\4d\\8f" \
            "\\a8\\ca\\10\\ae\\b8\\dd\\54\\30\\81\\cc\\06\\03\\55\\1d\\1f\\04" \
            "\\81\\c4\\30\\81\\c1\\30\\81\\be\\a0\\81\\bb\\a0\\81\\b8\\86\\81" \
            "\\b5\\6c\\64\\61\\70\\3a\\2f\\2f\\2f\\43\\4e\\3d\\61\\64\\2d\\41" \
            "\\44\\2d\\53\\45\\52\\56\\45\\52\\2d\\43\\41\\2c\\43\\4e\\3d\\61" \
            "\\64\\2d\\73\\65\\72\\76\\65\\72\\2c\\43\\4e\\3d\\43\\44\\50\\2c" \
            "\\43\\4e\\3d\\50\\75\\62\\6c\\69\\63\\25\\32\\30\\4b\\65\\79\\25" \
            "\\32\\30\\53\\65\\72\\76\\69\\63\\65\\73\\2c\\43\\4e\\3d\\53\\65" \
            "\\72\\76\\69\\63\\65\\73\\2c\\43\\4e\\3d\\43\\6f\\6e\\66\\69\\67" \
            "\\75\\72\\61\\74\\69\\6f\\6e\\2c\\44\\43\\3d\\61\\64\\2c\\44\\43" \
            "\\3d\\64\\65\\76\\65\\6c\\3f\\63\\65\\72\\74\\69\\66\\69\\63\\61" \
            "\\74\\65\\52\\65\\76\\6f\\63\\61\\74\\69\\6f\\6e\\4c\\69\\73\\74" \
            "\\3f\\62\\61\\73\\65\\3f\\6f\\62\\6a\\65\\63\\74\\43\\6c\\61\\73" \
            "\\73\\3d\\63\\52\\4c\\44\\69\\73\\74\\72\\69\\62\\75\\74\\69\\6f" \
            "\\6e\\50\\6f\\69\\6e\\74\\30\\81\\be\\06\\08\\2b\\06\\01\\05\\05" \
            "\\07\\01\\01\\04\\81\\b1\\30\\81\\ae\\30\\81\\ab\\06\\08\\2b\\06" \
            "\\01\\05\\05\\07\\30\\02\\86\\81\\9e\\6c\\64\\61\\70\\3a\\2f\\2f" \
            "\\2f\\43\\4e\\3d\\61\\64\\2d\\41\\44\\2d\\53\\45\\52\\56\\45\\52" \
            "\\2d\\43\\41\\2c\\43\\4e\\3d\\41\\49\\41\\2c\\43\\4e\\3d\\50\\75" \
            "\\62\\6c\\69\\63\\25\\32\\30\\4b\\65\\79\\25\\32\\30\\53\\65\\72" \
            "\\76\\69\\63\\65\\73\\2c\\43\\4e\\3d\\53\\65\\72\\76\\69\\63\\65" \
            "\\73\\2c\\43\\4e\\3d\\43\\6f\\6e\\66\\69\\67\\75\\72\\61\\74\\69" \
            "\\6f\\6e\\2c\\44\\43\\3d\\61\\64\\2c\\44\\43\\3d\\64\\65\\76\\65" \
            "\\6c\\3f\\63\\41\\43\\65\\72\\74\\69\\66\\69\\63\\61\\74\\65\\3f" \
            "\\62\\61\\73\\65\\3f\\6f\\62\\6a\\65\\63\\74\\43\\6c\\61\\73\\73" \
            "\\3d\\63\\65\\72\\74\\69\\66\\69\\63\\61\\74\\69\\6f\\6e\\41\\75" \
            "\\74\\68\\6f\\72\\69\\74\\79\\30\\3f\\06\\03\\55\\1d\\11\\04\\38" \
            "\\30\\36\\a0\\1c\\06\\0a\\2b\\06\\01\\04\\01\\82\\37\\14\\02\\03" \
            "\\a0\\0e\\0c\\0c\\74\\75\\31\\40\\61\\64\\2e\\64\\65\\76\\65\\6c" \
            "\\81\\16\\74\\65\\73\\74\\2e\\75\\73\\65\\72\\40\\65\\6d\\61\\69" \
            "\\6c\\2e\\64\\6f\\6d\\61\\69\\6e\\30\\0d\\06\\09\\2a\\86\\48\\86" \
            "\\f7\\0d\\01\\01\\05\\05\\00\\03\\82\\01\\01\\00\\41\\45\\0a\\6d" \
            "\\bb\\7f\\5c\\07\\0c\\c9\\b0\\39\\55\\6d\\7c\\b5\\02\\cd\\e8\\b2" \
            "\\e5\\02\\94\\77\\60\\db\\d1\\af\\1d\\db\\44\\5f\\ce\\83\\db\\80" \
            "\\2e\\e2\\b2\\08\\25\\82\\14\\cb\\48\\95\\20\\13\\6c\\a9\\aa\\f8" \
            "\\31\\56\\ed\\c0\\3b\\d4\\ae\\2e\\e3\\8f\\05\\fc\\ab\\5f\\2a\\69" \
            "\\23\\bc\\b8\\8c\\ec\\2d\\a9\\0b\\86\\95\\73\\73\\db\\17\\ce\\c6" \
            "\\ae\\c5\\b4\\c1\\25\\87\\3b\\67\\43\\9e\\87\\5a\\e6\\b9\\a0\\28" \
            "\\12\\3d\\a8\\2e\\d7\\5e\\ef\\65\\2d\\e6\\a5\\67\\84\\ac\\fd\\31" \
            "\\c1\\78\\d8\\72\\51\\a2\\88\\55\\0f\\97\\47\\93\\07\\ea\\8a\\53" \
            "\\27\\4e\\34\\54\\34\\1f\\a0\\6a\\03\\44\\fb\\23\\61\\8e\\87\\8e" \
            "\\3c\\d0\\8f\\ae\\e4\\cf\\ee\\65\\a8\\ba\\96\\68\\08\\1c\\60\\e2" \
            "\\4e\\11\\a3\\74\\b8\\a5\\4e\\ea\\6a\\82\\4c\\c2\\4d\\63\\8e\\9f" \
            "\\7c\\2f\\a8\\c0\\62\\f8\\f7\\d9\\25\\c4\\91\\ab\\4d\\6a\\44\\af" \
            "\\75\\93\\53\\03\\a4\\99\\c8\\cd\\91\\89\\60\\75\\30\\99\\76\\05" \
            "\\5a\\a0\\03\\a7\\a1\\2c\\03\\04\\8f\\d4\\5a\\31\\52\\28\\5a\\e6" \
            "\\a2\\d3\\43\\21\\5b\\dc\\a2\\1d\\55\\a9\\48\\c5\\c4\\aa\\f3\\8b" \
            "\\e6\\3e\\75\\96\\e4\\3e\\64\\af\\e8\\a7\\6a\\b6"

static void test_sss_certmap_get_search_filter(void **state)
{
    int ret;
    struct sss_certmap_ctx *ctx;
    char *filter;
    char **domains;
    const char *dom_list[] = {"test.dom", NULL};

    ret = sss_certmap_init(NULL, ext_debug, NULL, &ctx);
    assert_int_equal(ret, EOK);
    assert_non_null(ctx);
    assert_null(ctx->prio_list);

    ret = sss_certmap_add_rule(ctx, 100,
                            "KRB5:<ISSUER>CN=Certificate Authority,O=IPA.DEVEL",
                            "LDAP:rule100=<I>{issuer_dn}<S>{subject_dn}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert_der),
                                        sizeof(test_cert_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule100=<I>CN=Certificate\\20Authority,O=IPA.DEVEL"
                                "<S>CN=ipa-devel.ipa.devel,O=IPA.DEVEL");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert_der),
                                          sizeof(test_cert_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule100=<I>CN=Certificate Authority,O=IPA.DEVEL"
                                "<S>CN=ipa-devel.ipa.devel,O=IPA.DEVEL");
    assert_null(domains);

    ret = sss_certmap_add_rule(ctx, 99,
                            "KRB5:<ISSUER>CN=Certificate Authority,O=IPA.DEVEL",
                            "LDAP:rule99=<I>{issuer_dn}<S>{subject_dn}",
                            dom_list);
    assert_int_equal(ret, 0);
    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert_der),
                                        sizeof(test_cert_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule99=<I>CN=Certificate\\20Authority,O=IPA.DEVEL"
                                "<S>CN=ipa-devel.ipa.devel,O=IPA.DEVEL");
    assert_non_null(domains);
    assert_string_equal(domains[0], "test.dom");
    assert_null(domains[1]);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert_der),
                                          sizeof(test_cert_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule99=<I>CN=Certificate Authority,O=IPA.DEVEL"
                                "<S>CN=ipa-devel.ipa.devel,O=IPA.DEVEL");
    assert_non_null(domains);
    assert_string_equal(domains[0], "test.dom");
    assert_null(domains[1]);

    ret = sss_certmap_add_rule(ctx, 98,
                            "KRB5:<ISSUER>CN=Certificate Authority,O=IPA.DEVEL",
                            "LDAP:rule98=userCertificate;binary={cert!bin}",
                            dom_list);
    assert_int_equal(ret, 0);
    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert_der),
                                        sizeof(test_cert_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule98=userCertificate;binary=" TEST_CERT_BIN);
    assert_non_null(domains);
    assert_string_equal(domains[0], "test.dom");
    assert_null(domains[1]);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert_der),
                                          sizeof(test_cert_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule98=userCertificate;binary=" TEST_CERT_BIN);
    assert_non_null(domains);
    assert_string_equal(domains[0], "test.dom");
    assert_null(domains[1]);

    ret = sss_certmap_add_rule(ctx, 97,
                            "KRB5:<ISSUER>CN=Certificate Authority,O=IPA.DEVEL",
                            "LDAP:rule97=<I>{issuer_dn!nss_x500}<S>{subject_dn}",
                            dom_list);
    assert_int_equal(ret, 0);
    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert_der),
                                        sizeof(test_cert_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule97=<I>O=IPA.DEVEL,CN=Certificate\\20Authority"
                                "<S>CN=ipa-devel.ipa.devel,O=IPA.DEVEL");
    assert_non_null(domains);
    assert_string_equal(domains[0], "test.dom");
    assert_null(domains[1]);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert_der),
                                          sizeof(test_cert_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule97=<I>O=IPA.DEVEL,CN=Certificate Authority"
                                "<S>CN=ipa-devel.ipa.devel,O=IPA.DEVEL");
    assert_non_null(domains);
    assert_string_equal(domains[0], "test.dom");
    assert_null(domains[1]);

    ret = sss_certmap_add_rule(ctx, 96,
                            "KRB5:<ISSUER>CN=Certificate Authority,O=IPA.DEVEL",
                            "LDAP:rule96=<I>{issuer_dn!nss_x500}<S>{subject_dn!nss_x500}",
                            dom_list);
    assert_int_equal(ret, 0);
    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert_der),
                                        sizeof(test_cert_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule96=<I>O=IPA.DEVEL,CN=Certificate\\20Authority"
                                "<S>O=IPA.DEVEL,CN=ipa-devel.ipa.devel");
    assert_non_null(domains);
    assert_string_equal(domains[0], "test.dom");
    assert_null(domains[1]);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert_der),
                                          sizeof(test_cert_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule96=<I>O=IPA.DEVEL,CN=Certificate Authority"
                                "<S>O=IPA.DEVEL,CN=ipa-devel.ipa.devel");
    assert_non_null(domains);
    assert_string_equal(domains[0], "test.dom");
    assert_null(domains[1]);

    ret = sss_certmap_add_rule(ctx, 95,
                            "KRB5:<ISSUER>CN=Certificate Authority,O=IPA.DEVEL",
                            NULL, NULL);
    assert_int_equal(ret, 0);
    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert_der),
                                        sizeof(test_cert_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "(userCertificate;binary=" TEST_CERT_BIN ")");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert_der),
                                          sizeof(test_cert_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "(userCertificate;binary=" TEST_CERT_BIN ")");
    assert_null(domains);

    ret = sss_certmap_add_rule(ctx, 94,
                      "KRB5:<ISSUER>CN=Certificate Authority,O=IPA.DEVEL",
                      "LDAP:rule94=<I>{issuer_dn!ad_x500}<S>{subject_dn!ad_x500}",
                            dom_list);
    assert_int_equal(ret, 0);
    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert_der),
                                        sizeof(test_cert_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule94=<I>O=IPA.DEVEL,CN=Certificate\\20Authority"
                                "<S>O=IPA.DEVEL,CN=ipa-devel.ipa.devel");
    assert_non_null(domains);
    assert_string_equal(domains[0], "test.dom");
    assert_null(domains[1]);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert_der),
                                          sizeof(test_cert_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule94=<I>O=IPA.DEVEL,CN=Certificate Authority"
                                "<S>O=IPA.DEVEL,CN=ipa-devel.ipa.devel");
    assert_non_null(domains);
    assert_string_equal(domains[0], "test.dom");
    assert_null(domains[1]);

    ret = sss_certmap_add_rule(ctx, 89, NULL,
                            "(rule89={subject_nt_principal})",
                            NULL);
    assert_int_equal(ret, 0);
    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "(rule89=tu1@ad.devel)");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "(rule89=tu1@ad.devel)");
    assert_null(domains);

    ret = sss_certmap_add_rule(ctx, 88, NULL,
                            "(rule88={subject_nt_principal.short_name})",
                            NULL);
    assert_int_equal(ret, 0);
    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "(rule88=tu1)");
    assert_null(domains);

    ret = sss_certmap_add_rule(ctx, 87, NULL,
                          "LDAP:rule87=<I>{issuer_dn!nss_x500}<S>{subject_dn!nss_x500}",
                          NULL);
    assert_int_equal(ret, 0);
    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule87=<I>DC=devel,DC=ad,CN=ad-AD-SERVER-CA"
                  "<S>DC=devel,DC=ad,CN=Users,CN=t\\20u,E=test.user@email.domain");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule87=<I>DC=devel,DC=ad,CN=ad-AD-SERVER-CA"
                  "<S>DC=devel,DC=ad,CN=Users,CN=t u,E=test.user@email.domain");
    assert_null(domains);

    ret = sss_certmap_add_rule(ctx, 86, NULL,
                      "LDAP:rule86=<I>{issuer_dn!ad_x500}<S>{subject_dn!ad_x500}",
                      NULL);
    assert_int_equal(ret, 0);
    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule86=<I>DC=devel,DC=ad,CN=ad-AD-SERVER-CA"
                  "<S>DC=devel,DC=ad,CN=Users,CN=t\\20u,E=test.user@email.domain");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule86=<I>DC=devel,DC=ad,CN=ad-AD-SERVER-CA"
                  "<S>DC=devel,DC=ad,CN=Users,CN=t u,E=test.user@email.domain");
    assert_null(domains);


    sss_certmap_free_ctx(ctx);

    /* check defaults when no rules are added yet */
    ret = sss_certmap_init(NULL, ext_debug, NULL, &ctx);
    assert_int_equal(ret, EOK);
    assert_non_null(ctx);
    assert_null(ctx->prio_list);
    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "(userCertificate;binary=" TEST_CERT2_BIN")");
    assert_null(domains);

    sss_certmap_free_ctx(ctx);
}

static void test_sss_certmap_ldapu1_serial_number(void **state)
{
    int ret;
    struct sss_certmap_ctx *ctx;
    char *filter;
    char **domains;

    ret = sss_certmap_init(NULL, ext_debug, NULL, &ctx);
    assert_int_equal(ret, EOK);
    assert_non_null(ctx);
    assert_null(ctx->prio_list);

    ret = sss_certmap_add_rule(ctx, 100,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule100={serial_number}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 100,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule100={serial_number}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule100=612288c20000000002a6");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule100=612288c20000000002a6");
    assert_null(domains);


    ret = sss_certmap_add_rule(ctx, 99,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule99={serial_number!HEX_U}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 99,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule99={serial_number!HEX_U}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule99=612288C20000000002A6");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule99=612288C20000000002A6");
    assert_null(domains);


    ret = sss_certmap_add_rule(ctx, 98,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule98={serial_number!HEX_UC}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 98,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule98={serial_number!HEX_UC}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule98=61:22:88:C2:00:00:00:00:02:A6");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule98=61:22:88:C2:00:00:00:00:02:A6");
    assert_null(domains);


    ret = sss_certmap_add_rule(ctx, 97,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule97={serial_number!hex_c}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 97,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule97={serial_number!hex_c}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule97=61:22:88:c2:00:00:00:00:02:a6");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule97=61:22:88:c2:00:00:00:00:02:a6");
    assert_null(domains);


    ret = sss_certmap_add_rule(ctx, 96,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule96={serial_number!hex}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 96,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule96={serial_number!hex}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule96=612288c20000000002a6");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule96=612288c20000000002a6");
    assert_null(domains);


    ret = sss_certmap_add_rule(ctx, 95,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule95={serial_number!dec}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 95,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule95={serial_number!dec}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule95=458706592575796350550694");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule95=458706592575796350550694");
    assert_null(domains);

    /* Conversion specifiers are not supported for 'dec' */
    ret = sss_certmap_add_rule(ctx, 94,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule94={serial_number!dec_u}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 94,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule94={serial_number!dec_u}", NULL);
    assert_int_equal(ret, EINVAL);

    sss_certmap_free_ctx(ctx);
}

static void test_sss_certmap_ldapu1_subject_key_id(void **state)
{
    int ret;
    struct sss_certmap_ctx *ctx;
    char *filter;
    char **domains;

    ret = sss_certmap_init(NULL, ext_debug, NULL, &ctx);
    assert_int_equal(ret, EOK);
    assert_non_null(ctx);
    assert_null(ctx->prio_list);

    /* subject_key_id */
    ret = sss_certmap_add_rule(ctx, 94,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule94={subject_key_id}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 94,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule94={subject_key_id}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule94=49acade06530c4cea009035bad4a7b495ec96cb4");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule94=49acade06530c4cea009035bad4a7b495ec96cb4");
    assert_null(domains);


    /* subject_key_id!HEX */
    ret = sss_certmap_add_rule(ctx, 93,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule93={subject_key_id!HEX_U}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 93,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule93={subject_key_id!HEX_U}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule93=49ACADE06530C4CEA009035BAD4A7B495EC96CB4");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule93=49ACADE06530C4CEA009035BAD4A7B495EC96CB4");
    assert_null(domains);


    /* subject_key_id!HEX_COLON */
    ret = sss_certmap_add_rule(ctx, 92,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule92={subject_key_id!HEX_CU}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 92,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule92={subject_key_id!HEX_CU}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule92=49:AC:AD:E0:65:30:C4:CE:A0:09:03:5B:AD:4A:7B:49:5E:C9:6C:B4");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule92=49:AC:AD:E0:65:30:C4:CE:A0:09:03:5B:AD:4A:7B:49:5E:C9:6C:B4");
    assert_null(domains);


    /* subject_key_id!hex_colon */
    ret = sss_certmap_add_rule(ctx, 91,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule91={subject_key_id!hex_c}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 91,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule91={subject_key_id!hex_c}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule91=49:ac:ad:e0:65:30:c4:ce:a0:09:03:5b:ad:4a:7b:49:5e:c9:6c:b4");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule91=49:ac:ad:e0:65:30:c4:ce:a0:09:03:5b:ad:4a:7b:49:5e:c9:6c:b4");
    assert_null(domains);


    /* subject_key_id!hex */
    ret = sss_certmap_add_rule(ctx, 90,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule90={subject_key_id!hex}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 90,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule90={subject_key_id!hex}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule90=49acade06530c4cea009035bad4a7b495ec96cb4");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule90=49acade06530c4cea009035bad4a7b495ec96cb4");
    assert_null(domains);


    /* UNSUPPORTED subject_key_id!dec */
    ret = sss_certmap_add_rule(ctx, 89,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule89={subject_key_id!dec}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 89,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule89={subject_key_id!dec}", NULL);
    assert_int_equal(ret, EINVAL);

    sss_certmap_free_ctx(ctx);
}

static void test_sss_certmap_ldapu1_cert(void **state)
{
    int ret;
    struct sss_certmap_ctx *ctx;
    char *filter;
    char **domains;

    ret = sss_certmap_init(NULL, ext_debug, NULL, &ctx);
    assert_int_equal(ret, EOK);
    assert_non_null(ctx);
    assert_null(ctx->prio_list);

    /* cert!sha555 */
    ret = sss_certmap_add_rule(ctx, 89,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule89={cert!sha555}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 89,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule89={cert!sha555}", NULL);
    assert_int_equal(ret, EINVAL);

    /* cert!sha512 */
    ret = sss_certmap_add_rule(ctx, 88,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule88={cert!sha512}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 88,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule88={cert!sha512}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule88=3ee0583237ae9e6ec7d92dd4a029a9d54147bad48b1b0bad0e4e63380bc9a18ae7b447a03a05b35ad605494a57c359400c0ff3f411c71b96e500f8f2765f6fa3");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule88=3ee0583237ae9e6ec7d92dd4a029a9d54147bad48b1b0bad0e4e63380bc9a18ae7b447a03a05b35ad605494a57c359400c0ff3f411c71b96e500f8f2765f6fa3");
    assert_null(domains);

    /* cert!sha512_u */
    ret = sss_certmap_add_rule(ctx, 68,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule68={cert!sha512_u}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 68,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule68={cert!sha512_u}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule68=3EE0583237AE9E6EC7D92DD4A029A9D54147BAD48B1B0BAD0E4E63380BC9A18AE7B447A03A05B35AD605494A57C359400C0FF3F411C71B96E500F8F2765F6FA3");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule68=3EE0583237AE9E6EC7D92DD4A029A9D54147BAD48B1B0BAD0E4E63380BC9A18AE7B447A03A05B35AD605494A57C359400C0FF3F411C71B96E500F8F2765F6FA3");
    assert_null(domains);

    /* cert!SHA512_CU */
    ret = sss_certmap_add_rule(ctx, 67,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule67={cert!SHA512_CU}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 67,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule67={cert!SHA512_CU}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule67=3E:E0:58:32:37:AE:9E:6E:C7:D9:2D:D4:A0:29:A9:D5:41:47:BA:D4:8B:1B:0B:AD:0E:4E:63:38:0B:C9:A1:8A:E7:B4:47:A0:3A:05:B3:5A:D6:05:49:4A:57:C3:59:40:0C:0F:F3:F4:11:C7:1B:96:E5:00:F8:F2:76:5F:6F:A3");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule67=3E:E0:58:32:37:AE:9E:6E:C7:D9:2D:D4:A0:29:A9:D5:41:47:BA:D4:8B:1B:0B:AD:0E:4E:63:38:0B:C9:A1:8A:E7:B4:47:A0:3A:05:B3:5A:D6:05:49:4A:57:C3:59:40:0C:0F:F3:F4:11:C7:1B:96:E5:00:F8:F2:76:5F:6F:A3");
    assert_null(domains);

    /* cert!SHA512_CRU */
    ret = sss_certmap_add_rule(ctx, 66,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule66={cert!SHA512_CRU}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 66,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule66={cert!SHA512_CRU}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule66=A3:6F:5F:76:F2:F8:00:E5:96:1B:C7:11:F4:F3:0F:0C:40:59:C3:57:4A:49:05:D6:5A:B3:05:3A:A0:47:B4:E7:8A:A1:C9:0B:38:63:4E:0E:AD:0B:1B:8B:D4:BA:47:41:D5:A9:29:A0:D4:2D:D9:C7:6E:9E:AE:37:32:58:E0:3E");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule66=A3:6F:5F:76:F2:F8:00:E5:96:1B:C7:11:F4:F3:0F:0C:40:59:C3:57:4A:49:05:D6:5A:B3:05:3A:A0:47:B4:E7:8A:A1:C9:0B:38:63:4E:0E:AD:0B:1B:8B:D4:BA:47:41:D5:A9:29:A0:D4:2D:D9:C7:6E:9E:AE:37:32:58:E0:3E");
    assert_null(domains);

    sss_certmap_free_ctx(ctx);
}

static void test_sss_certmap_ldapu1_subject_dn_component(void **state)
{
    int ret;
    struct sss_certmap_ctx *ctx;
    char *filter;
    char **domains;

    ret = sss_certmap_init(NULL, ext_debug, NULL, &ctx);
    assert_int_equal(ret, EOK);
    assert_non_null(ctx);
    assert_null(ctx->prio_list);

    /* subject_dn_component */
    ret = sss_certmap_add_rule(ctx, 77,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule77={subject_dn_component}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 77,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule77={subject_dn_component}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule77=test.user@email.domain");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule77=test.user@email.domain");
    assert_null(domains);

    /* subject_dn_component.[...] */
    ret = sss_certmap_add_rule(ctx, 76,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule76={subject_dn_component.[1]}--{subject_dn_component.[2]}--{subject_dn_component.[3]}--{subject_dn_component.[4]}--{subject_dn_component.[5]}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 76,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule76={subject_dn_component.[1]}--{subject_dn_component.[2]}--{subject_dn_component.[3]}--{subject_dn_component.[4]}--{subject_dn_component.[5]}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule76=test.user@email.domain--t\\20u--Users--ad--devel");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule76=test.user@email.domain--t u--Users--ad--devel");
    assert_null(domains);

    /* subject_dn_component.[-...] */
    ret = sss_certmap_add_rule(ctx, 75,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule75={subject_dn_component.[-5]}--{subject_dn_component.[-4]}--{subject_dn_component.[-3]}--{subject_dn_component.[-2]}--{subject_dn_component.[-1]}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 75,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule75={subject_dn_component.[-5]}--{subject_dn_component.[-4]}--{subject_dn_component.[-3]}--{subject_dn_component.[-2]}--{subject_dn_component.[-1]}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule75=test.user@email.domain--t\\20u--Users--ad--devel");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule75=test.user@email.domain--t u--Users--ad--devel");
    assert_null(domains);

    /* subject_dn_component.[6] */
    ret = sss_certmap_add_rule(ctx, 74,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule74={subject_dn_component.[6]}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 74,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule74={subject_dn_component.[6]}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, EINVAL);

    /* subject_dn_component.[-6] */
    ret = sss_certmap_add_rule(ctx, 73,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule73={subject_dn_component.[-6]}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 73,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule73={subject_dn_component.[-6]}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, EINVAL);

    /* subject_dn_component.e */
    ret = sss_certmap_add_rule(ctx, 72,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule72={subject_dn_component.e}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 72,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule72={subject_dn_component.e}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule72=test.user@email.domain");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule72=test.user@email.domain");
    assert_null(domains);

    /* subject_dn_component.cn */
    ret = sss_certmap_add_rule(ctx, 71,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule71={subject_dn_component.cn}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 71,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule71={subject_dn_component.cn}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule71=t\\20u");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule71=t u");
    assert_null(domains);

    /* subject_dn_component.cn[2] */
    ret = sss_certmap_add_rule(ctx, 70,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule70={subject_dn_component.cn[2]}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 70,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule70={subject_dn_component.cn[2]}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule70=t\\20u");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule70=t u");
    assert_null(domains);

    /* subject_dn_component.cn[1] */
    ret = sss_certmap_add_rule(ctx, 69,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule69={subject_dn_component.cn[1]}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 69,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule60={subject_dn_component.cn[1]}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, EINVAL);

    sss_certmap_free_ctx(ctx);
}

static void test_sss_certmap_ldapu1_issuer_dn_component(void **state)
{
    int ret;
    struct sss_certmap_ctx *ctx;
    char *filter;
    char **domains;

    ret = sss_certmap_init(NULL, ext_debug, NULL, &ctx);
    assert_int_equal(ret, EOK);
    assert_non_null(ctx);
    assert_null(ctx->prio_list);

    /* issuer_dn_component */
    ret = sss_certmap_add_rule(ctx, 87,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule87={issuer_dn_component}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 87,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule87={issuer_dn_component}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule87=ad-AD-SERVER-CA");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule87=ad-AD-SERVER-CA");
    assert_null(domains);

    /* issuer_dn_component.[0] */
    ret = sss_certmap_add_rule(ctx, 86,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule86={issuer_dn_component.[0]}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 86,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule86={issuer_dn_component.[0]}", NULL);
    assert_int_equal(ret, EINVAL);

    /* issuer_dn_component.[1] */
    ret = sss_certmap_add_rule(ctx, 85,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule85={issuer_dn_component.[1]}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 85,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule85={issuer_dn_component.[1]}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule85=ad-AD-SERVER-CA");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule85=ad-AD-SERVER-CA");
    assert_null(domains);

    /* issuer_dn_component.[-1] */
    ret = sss_certmap_add_rule(ctx, 84,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule84={issuer_dn_component.[-1]}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 84,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule84={issuer_dn_component.[-1]}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule84=devel");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule84=devel");
    assert_null(domains);

    /* issuer_dn_component.[2] */
    ret = sss_certmap_add_rule(ctx, 83,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule83={issuer_dn_component.[2]}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 83,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule83={issuer_dn_component.[2]}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule83=ad");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule83=ad");
    assert_null(domains);

    /* issuer_dn_component.[-2] */
    ret = sss_certmap_add_rule(ctx, 82,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule82={issuer_dn_component.[-2]}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 82,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule82={issuer_dn_component.[-2]}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule82=ad");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule82=ad");
    assert_null(domains);

    /* issuer_dn_component.[3] */
    ret = sss_certmap_add_rule(ctx, 81,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule81={issuer_dn_component.[3]}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 81,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule81={issuer_dn_component.[3]}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule81=devel");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule81=devel");
    assert_null(domains);

    /* issuer_dn_component.[-3] */
    ret = sss_certmap_add_rule(ctx, 80,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule80={issuer_dn_component.[-3]}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 80,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule80={issuer_dn_component.[-3]}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule80=ad-AD-SERVER-CA");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, discard_const(test_cert2_der),
                                          sizeof(test_cert2_der),
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule80=ad-AD-SERVER-CA");
    assert_null(domains);

    /* issuer_dn_component.[4] */
    ret = sss_certmap_add_rule(ctx, 79,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule79={issuer_dn_component.[4]}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 79,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule79={issuer_dn_component.[4]}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, EINVAL);

    /* issuer_dn_component.[-4] */
    ret = sss_certmap_add_rule(ctx, 78,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule78={issuer_dn_component.[-4]}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 78,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule78={issuer_dn_component.[-4]}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, discard_const(test_cert2_der),
                                        sizeof(test_cert2_der),
                                        &filter, &domains);
    assert_int_equal(ret, EINVAL);

    sss_certmap_free_ctx(ctx);
}

static void test_sss_certmap_ldapu1_sid(void **state)
{
    int ret;
    struct sss_certmap_ctx *ctx;
    char *filter;
    char **domains;

    uint8_t *der;
    size_t der_size;

    der = sss_base64_decode(NULL, TEST_CERT_WITH_SID_EXT, &der_size);
    assert_non_null(der);

    ret = sss_certmap_init(NULL, ext_debug, NULL, &ctx);
    assert_int_equal(ret, EOK);
    assert_non_null(ctx);
    assert_null(ctx->prio_list);

    /* full sid */
    ret = sss_certmap_add_rule(ctx, 100,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule100={sid}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 100,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule100={sid}", NULL);
    assert_int_equal(ret, 0);

    ret = sss_certmap_get_search_filter(ctx, der, der_size,
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule100=S-1-5-21-294026126-3378245018-1203103949-1001");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, der, der_size,
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule100=S-1-5-21-294026126-3378245018-1203103949-1001");
    assert_null(domains);

    /* invalid component */
    ret = sss_certmap_add_rule(ctx, 99,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule99={sid.abc}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 99,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule99={sid.abc}", NULL);
    assert_int_equal(ret, EINVAL);

    /* rid component */
    ret = sss_certmap_add_rule(ctx, 98,
                            "KRB5:<ISSUER>.*",
                            "LDAP:rule98={sid.rid}", NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_certmap_add_rule(ctx, 98,
                            "KRB5:<ISSUER>.*",
                            "LDAPU1:rule98={sid.rid}", NULL);
    assert_int_equal(ret, 0);
    ret = sss_certmap_get_search_filter(ctx, der, der_size,
                                        &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule98=1001");
    assert_null(domains);

    ret = sss_certmap_expand_mapping_rule(ctx, der, der_size,
                                          &filter, &domains);
    assert_int_equal(ret, 0);
    assert_non_null(filter);
    assert_string_equal(filter, "rule98=1001");
    assert_null(domains);

    sss_certmap_free_ctx(ctx);
}


int main(int argc, const char *argv[])
{
    int rv;
    poptContext pc;
    int opt;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sss_certmap_init),
        cmocka_unit_test(test_sss_certmap_add_rule),
        cmocka_unit_test(test_sss_certmap_add_matching_rule),
        cmocka_unit_test(test_check_ad_attr_name),
        cmocka_unit_test(test_sss_cert_get_content),
        cmocka_unit_test(test_sss_cert_get_content_2),
#ifdef HAVE_TEST_CA
        cmocka_unit_test(test_sss_cert_get_content_test_cert_0003),
        cmocka_unit_test(test_sss_cert_get_content_test_cert_0004),
        cmocka_unit_test(test_sss_cert_get_content_test_cert_0001),
#endif
        cmocka_unit_test(test_sss_cert_get_content_test_cert_with_sid_ext),
        cmocka_unit_test(test_sss_certmap_match_cert),
        cmocka_unit_test(test_sss_certmap_add_mapping_rule),
        cmocka_unit_test(test_sss_certmap_get_search_filter),
        cmocka_unit_test(test_sss_certmap_ldapu1_serial_number),
        cmocka_unit_test(test_sss_certmap_ldapu1_subject_key_id),
        cmocka_unit_test(test_sss_certmap_ldapu1_cert),
        cmocka_unit_test(test_sss_certmap_ldapu1_subject_dn_component),
        cmocka_unit_test(test_sss_certmap_ldapu1_issuer_dn_component),
        cmocka_unit_test(test_sss_certmap_ldapu1_sid),
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
    rv = cmocka_run_group_tests(tests, NULL, NULL);

    CRYPTO_cleanup_all_ex_data(); /* to make Valgrind happy */

    return rv;
}
