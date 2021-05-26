/*
    Authors:
        Pavel Reichl <preichl@redhat.com>

    Copyright (C) 2015 Red Hat

    SSSD tests - sdap access

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
#include <ldb.h>

#include "tests/common.h"
#include "tests/cmocka/test_expire_common.h"
#include "tests/cmocka/test_sdap_access.h"

/* linking against function from sdap_access.c module */
extern bool nds_check_expired(const char *exp_time_str);
extern errno_t sdap_access_rhost(struct ldb_message *user_entry, char *pam_rhost);

static void nds_check_expired_wrap(void *in, void *_out)
{
    *(bool*)_out = nds_check_expired((const char*)in);
}

void test_nds_check_expire(void **state)
{
    struct expire_test_ctx *tc;
    bool res;

    tc = talloc_get_type(*state, struct expire_test_ctx);
    assert_non_null(tc);

    assert_false(nds_check_expired(NULL));
    assert_true(nds_check_expired(tc->invalid_longer_format));
    assert_true(nds_check_expired(tc->invalid_format));
    assert_true(nds_check_expired(tc->past_time));
    assert_false(nds_check_expired(tc->future_time));

    /* changing time zone has no effect as time of expiration is in UTC */
    expire_test_tz("GST+2", nds_check_expired_wrap, (void*)tc->future_time,
                   (void*)&res);
    assert_false(res);
    expire_test_tz("GST-2", nds_check_expired_wrap, (void*)tc->future_time,
                   (void*)&res);
    assert_false(res);
}

static int test_sdap_access_rhost_setup(void **state)
{
    TALLOC_CTX *mem_ctx;
    struct test_sdap_access_rhost_ctx *test_ctx;
    struct ldb_message *user_no_rhost;
    struct ldb_message *user_allow_somehost;
    struct ldb_message *user_deny_somehost;
    struct ldb_message *user_allow_all;
    struct ldb_message *user_allow_all_deny_somehost;
    struct ldb_message *user_allow_all_allow_somehost_deny_somehost;

    mem_ctx = talloc_new(NULL);
    assert_non_null(mem_ctx);

    test_ctx = talloc(mem_ctx, struct test_sdap_access_rhost_ctx);
    assert_non_null(test_ctx);

    /* Setup empty user entry (with 0 entries for rhost) */
    user_no_rhost = ldb_msg_new(test_ctx);
    assert_non_null(user_no_rhost);
    user_no_rhost->num_elements = 0;

    /* Setup user entry with allow somehost */
    user_allow_somehost = ldb_msg_new(test_ctx);
    assert_non_null(user_allow_somehost);
    ldb_msg_add_string(user_allow_somehost,
                       SYSDB_AUTHORIZED_RHOST,
                       "somehost");

    /* Setup user entry with deny somehost */
    user_deny_somehost = ldb_msg_new(test_ctx);
    assert_non_null(user_deny_somehost);
    ldb_msg_add_string(user_deny_somehost,
                       SYSDB_AUTHORIZED_RHOST,
                       "!somehost");

    /* Setup user entry with allow all */
    user_allow_all = ldb_msg_new(test_ctx);
    assert_non_null(user_allow_all);
    ldb_msg_add_string(user_allow_all,
                       SYSDB_AUTHORIZED_RHOST,
                       "*");

    /* Setup user entry with allow all and deny somehost */
    user_allow_all_deny_somehost = ldb_msg_new(test_ctx);
    assert_non_null(user_allow_all_deny_somehost);
    ldb_msg_add_string(user_allow_all_deny_somehost,
                       SYSDB_AUTHORIZED_RHOST,
                       "*");
    ldb_msg_add_string(user_allow_all_deny_somehost,
                       SYSDB_AUTHORIZED_RHOST,
                       "!somehost");

    /* Setup user entry with allow all, allow somehost and deny somehost */
    user_allow_all_allow_somehost_deny_somehost = ldb_msg_new(test_ctx);
    assert_non_null(user_allow_all_allow_somehost_deny_somehost);
    ldb_msg_add_string(user_allow_all_allow_somehost_deny_somehost,
                       SYSDB_AUTHORIZED_RHOST,
                       "*");
    ldb_msg_add_string(user_allow_all_allow_somehost_deny_somehost,
                       SYSDB_AUTHORIZED_RHOST,
                       "!somehost");
    ldb_msg_add_string(user_allow_all_allow_somehost_deny_somehost,
                       SYSDB_AUTHORIZED_RHOST,
                       "somehost");

    /* Setup test context */
    test_ctx->user_no_rhost = user_no_rhost;
    test_ctx->user_allow_somehost = user_allow_somehost;
    test_ctx->user_deny_somehost = user_deny_somehost;
    test_ctx->user_allow_all = user_allow_all;
    test_ctx->user_allow_all_deny_somehost = user_allow_all_deny_somehost;
    test_ctx->user_allow_all_allow_somehost_deny_somehost = \
                                    user_allow_all_allow_somehost_deny_somehost;

    *state = test_ctx;

    return 0;
}

static int test_sdap_access_rhost_teardown(void **state)
{
    struct test_sdap_access_rhost_ctx *test_ctx;

    test_ctx = talloc_get_type(*state, struct test_sdap_access_rhost_ctx);
    assert_non_null(test_ctx);

    talloc_free(test_ctx);

    return 0;
}

static void test_sdap_access_rhost(void **state)
{
    struct test_sdap_access_rhost_ctx *test_ctx;
    errno_t ret;

    test_ctx = talloc_get_type(*state, struct test_sdap_access_rhost_ctx);
    assert_non_null(test_ctx);

    char pam_rhost_mock_empty[] = "";
    char pam_rhost_mock_somehost[] = "somehost";
    char pam_rhost_mock_someotherhost[] = "someotherhost";

    /* Test both arguments as NULL */
    ret = sdap_access_rhost(NULL, NULL);
    assert_int_equal(ERR_ACCESS_DENIED, ret); /* Expected access granted */

    /* Test with user_entry == NULL and rhost == "somehost" */
    ret = sdap_access_rhost(NULL, pam_rhost_mock_somehost);
    assert_int_equal(ERR_ACCESS_DENIED, ret); /* Expected access denied */

    /* Test with user_no_rhost and rhost == NULL */
    ret = sdap_access_rhost(test_ctx->user_no_rhost, NULL);
    assert_int_equal(EOK, ret); /* Expected access granted */

    /* Test with user_no_rhost and rhost == "" (local access) */
    ret = sdap_access_rhost(test_ctx->user_no_rhost, pam_rhost_mock_empty);
    assert_int_equal(EOK, ret); /* Expected access granted */

    /* Test with user_no_rhost and rhost == "somehost" */
    ret = sdap_access_rhost(test_ctx->user_no_rhost, pam_rhost_mock_somehost);
    assert_int_equal(ERR_ACCESS_DENIED, ret); /* Expected access denied */

    /* Test with user_allow_somehost and rhost == "somehost" */
    ret = sdap_access_rhost(test_ctx->user_allow_somehost,
                            pam_rhost_mock_somehost);
    assert_int_equal(EOK, ret); /* Expected access allowed */

    /* Test with user_deny_somehost and rhost == "somehost" */
    ret = sdap_access_rhost(test_ctx->user_deny_somehost,
                            pam_rhost_mock_somehost);
    assert_int_equal(ERR_ACCESS_DENIED, ret); /* Expected access denied */

    /* Test with user_allow_all and rhost == "somehost" */
    ret = sdap_access_rhost(test_ctx->user_allow_all,
                            pam_rhost_mock_somehost);
    assert_int_equal(EOK, ret); /* Expected access allowed */

    /* Test with user_allow_all_deny_somehost and rhost == "somehost" */
    ret = sdap_access_rhost(test_ctx->user_allow_all_deny_somehost,
                            pam_rhost_mock_somehost);
    assert_int_equal(ERR_ACCESS_DENIED, ret); /* Expected access denied */

    /* Test with user_allow_all_allow_somehost_deny_somehost
     * and rhost == "somehost" */
    ret = sdap_access_rhost(
        test_ctx->user_allow_all_allow_somehost_deny_somehost,
        pam_rhost_mock_somehost);
    assert_int_equal(ERR_ACCESS_DENIED, ret); /* Expected access denied */

    /* Test with user_no_rhost and rhost == "someotherhost" */
    ret = sdap_access_rhost(test_ctx->user_no_rhost,
                            pam_rhost_mock_someotherhost);
    assert_int_equal(ERR_ACCESS_DENIED, ret); /* Expected access denied */

    /* Test with user_allow_somehost and rhost == "someotherhost" */
    ret = sdap_access_rhost(test_ctx->user_allow_somehost,
                            pam_rhost_mock_someotherhost);
    assert_int_equal(ERR_ACCESS_DENIED, ret); /* Expected access denied */

    /* Test with user_deny_somehost and rhost == "someotherhost" */
    ret = sdap_access_rhost(test_ctx->user_deny_somehost,
                            pam_rhost_mock_someotherhost);
    assert_int_equal(ERR_ACCESS_DENIED, ret); /* Expected access denied */

    /* Test with user_allow_all and rhost == "someotherhost" */
    ret = sdap_access_rhost(test_ctx->user_allow_all,
                            pam_rhost_mock_someotherhost);
    assert_int_equal(EOK, ret); /* Expected access allowed */

    /* Test with user_allow_all_deny_somehost and rhost == "someotherhost" */
    ret = sdap_access_rhost(test_ctx->user_allow_all_deny_somehost,
                            pam_rhost_mock_someotherhost);
    assert_int_equal(EOK, ret); /* Expected access allowed */

    /* Test with user_allow_all_allow_somehost_deny_somehost
     * and rhost == "someotherhost" */
    ret = sdap_access_rhost(
        test_ctx->user_allow_all_allow_somehost_deny_somehost,
        pam_rhost_mock_someotherhost);
    assert_int_equal(EOK, ret); /* Expected access allowed */
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_nds_check_expire,
                                        expire_test_setup,
                                        expire_test_teardown),
        cmocka_unit_test_setup_teardown(test_sdap_access_rhost,
                                        test_sdap_access_rhost_setup,
                                        test_sdap_access_rhost_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
