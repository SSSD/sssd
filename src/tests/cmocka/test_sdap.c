/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2014 Red Hat

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

#include "tests/cmocka/common_mock.h"
#include "providers/ldap/ldap_opts.h"
#include "providers/ipa/ipa_opts.h"
#include "util/crypto/sss_crypto.h"

/* mock an LDAP entry */
struct mock_ldap_attr {
    const char *name;
    const char **values;
};

struct mock_ldap_entry {
    const char *dn;
    struct mock_ldap_attr *attrs;
};

struct mock_ldap_entry *global_ldap_entry;

static int mock_ldap_entry_iter(void)
{
    return sss_mock_type(int);
}

static struct mock_ldap_entry *mock_ldap_entry_get(void)
{
    return sss_mock_ptr_type(struct mock_ldap_entry *);
}

void set_entry_parse(struct mock_ldap_entry *entry)
{
    will_return_always(mock_ldap_entry_get, entry);
}

/* libldap wrappers */
int __wrap_ldap_set_option(LDAP *ld,
                           int option,
                           void *invalue)
{
    return LDAP_OPT_SUCCESS;
}

char *__wrap_ldap_get_dn(LDAP *ld, LDAPMessage *entry)
{
    struct mock_ldap_entry *ldap_entry = mock_ldap_entry_get();
    return discard_const(ldap_entry->dn);
}

void __wrap_ldap_memfree(void *p)
{
    return;
}

struct berval **__wrap_ldap_get_values_len(LDAP *ld,
                                           LDAPMessage *entry,
                                           LDAP_CONST char *target)
{
    size_t count, i;
    struct berval **vals;
    const char **attrvals;
    struct mock_ldap_entry *ldap_entry = mock_ldap_entry_get();

    if (target == NULL) return NULL;
    if (ldap_entry == NULL) return NULL;
    /* Should we return empty array here? */
    if (ldap_entry->attrs == NULL) return NULL;

    attrvals = NULL;
    for (i = 0; ldap_entry->attrs[i].name != NULL; i++) {
        if (strcmp(ldap_entry->attrs[i].name, target) == 0) {
            attrvals = ldap_entry->attrs[i].values;
            break;
        }
    }

    if (attrvals == NULL) {
        return NULL;
    }

    count = 0;
    for (i = 0; attrvals[i]; i++) {
        count++;
    }

    vals = talloc_zero_array(global_talloc_context,
                             struct berval *,
                             count + 1);
    assert_non_null(vals);

    for (i = 0; attrvals[i]; i++) {
        vals[i] = talloc_zero(vals, struct berval);
        assert_non_null(vals[i]);

        vals[i]->bv_val = talloc_strdup(vals[i], attrvals[i]);
        if (vals[i]->bv_val == NULL) {
            talloc_free(vals);
            return NULL;
        }
        vals[i]->bv_len = strlen(attrvals[i]);
        assert_non_null(vals[i]->bv_len);
    }

    return vals;
}

void __wrap_ldap_value_free_len(struct berval **vals)
{
    talloc_free(vals);  /* Allocated on global_talloc_context */
}

char *__wrap_ldap_first_attribute(LDAP *ld,
                                  LDAPMessage *entry,
                                  BerElement **berout)
{
    struct mock_ldap_entry *ldap_entry = mock_ldap_entry_get();

    if (ldap_entry == NULL) return NULL;
    if (ldap_entry->attrs == NULL) return NULL;

    will_return(mock_ldap_entry_iter, 1);
    return discard_const(ldap_entry->attrs[0].name);
}

char *__wrap_ldap_next_attribute(LDAP *ld,
                                 LDAPMessage *entry,
                                 BerElement *ber)
{
    struct mock_ldap_entry *ldap_entry = mock_ldap_entry_get();

    int index = mock_ldap_entry_iter();
    char *val;

    val = discard_const(ldap_entry->attrs[index].name);
    if (val != NULL) {
        will_return(mock_ldap_entry_iter, index+1);
    }
    return val;
}

/* Mock parsing search base without overlinking the test */
errno_t sdap_parse_search_base(TALLOC_CTX *mem_ctx,
                               struct dp_option *opts, int class,
                               struct sdap_search_base ***_search_bases)
{
    return EOK;
}

/* Utility function */
void assert_entry_has_attr(struct sysdb_attrs *attrs,
                           const char *attr,
                           const char *value)
{
    const char *v;
    int ret;

    ret = sysdb_attrs_get_string(attrs, attr, &v);
    assert_int_equal(ret, ERR_OK);
    assert_non_null(v);
    assert_string_equal(v, value);
}

void assert_entry_has_no_attr(struct sysdb_attrs *attrs,
                              const char *attr)
{
    int ret;
    const char *v;
    ret = sysdb_attrs_get_string(attrs, attr, &v);
    assert_int_equal(ret, ENOENT);
}

struct parse_test_ctx {
    struct sdap_handle sh;
    struct sdap_msg sm;
};

void parse_entry_test_setup(void **state)
{
    struct parse_test_ctx *test_ctx;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context, struct parse_test_ctx);
    assert_non_null(test_ctx);

    check_leaks_push(test_ctx);
    *state = test_ctx;
}

void parse_entry_test_teardown(void **state)
{
    struct parse_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                      struct parse_test_ctx);

    assert_true(check_leaks_pop(test_ctx) == true);
    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
}

void test_parse_with_map(void **state)
{
    int ret;
    struct sysdb_attrs *attrs;
    struct parse_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                      struct parse_test_ctx);
    struct mock_ldap_entry test_ipa_user;
    struct sdap_attr_map *map;
    struct ldb_message_element *el;
    uint8_t *decoded_key;
    size_t key_len;

    const char *oc_values[] = { "posixAccount", NULL };
    const char *uid_values[] = { "tuser1", NULL };
    const char *extra_values[] = { "extra", NULL };
    const char *multi_values[] = { "svc1", "svc2", NULL };
    const char *ssh_values[] = { "1234", NULL };
    struct mock_ldap_attr test_ipa_user_attrs[] = {
        { .name = "objectClass", .values = oc_values },
        { .name = "uid", .values = uid_values },
        { .name = "extra", .values = extra_values },
        { .name = "authorizedService", .values = multi_values },
        { .name = "ipaSshPubKey", .values = ssh_values },
        { NULL, NULL }
    };

    test_ipa_user.dn = "cn=testuser,dc=example,dc=com";
    test_ipa_user.attrs = test_ipa_user_attrs;
    set_entry_parse(&test_ipa_user);

    ret = sdap_copy_map(test_ctx, ipa_user_map, SDAP_OPTS_USER, &map);
    assert_int_equal(ret, ERR_OK);

    ret = sdap_parse_entry(test_ctx, &test_ctx->sh, &test_ctx->sm,
                           map, SDAP_OPTS_USER,
                           &attrs, false);
    assert_int_equal(ret, ERR_OK);

    assert_int_equal(attrs->num, 4);

    /* Every entry has a DN */
    assert_entry_has_attr(attrs, SYSDB_ORIG_DN,
                          "cn=testuser,dc=example,dc=com");
    /* Test the single-valued attribute */
    assert_entry_has_attr(attrs, SYSDB_NAME, "tuser1");

    /* Multivalued attributes must return all values */
    ret = sysdb_attrs_get_el_ext(attrs, SYSDB_AUTHORIZED_SERVICE, false, &el);
    assert_int_equal(ret, ERR_OK);
    assert_int_equal(el->num_values, 2);
    assert_true((strcmp((const char *) el->values[0].data, "svc1") == 0 &&
                    strcmp((const char *) el->values[1].data, "svc2") == 0) ||
                (strcmp((const char *) el->values[1].data, "svc1") == 0 &&
                    strcmp((const char *) el->values[0].data, "svc2") == 0));

    /* The SSH attribute must be base64 encoded */
    ret = sysdb_attrs_get_el_ext(attrs, SYSDB_SSH_PUBKEY, false, &el);
    assert_int_equal(ret, ERR_OK);
    assert_int_equal(el->num_values, 1);
    decoded_key = sss_base64_decode(test_ctx,
                                    (const char *)el->values[0].data,
                                    &key_len);
    assert_non_null(decoded_key);
    assert_memory_equal(decoded_key, "1234", key_len);

    /* The extra attribute must not be downloaded, it's not present in map */
    assert_entry_has_no_attr(attrs, "extra");

    talloc_free(decoded_key);
    talloc_free(map);
    talloc_free(attrs);
}

/* Some searches, like rootDSE search do not use any map */
void test_parse_no_map(void **state)
{
    int ret;
    struct sysdb_attrs *attrs;
    struct parse_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                      struct parse_test_ctx);
    struct mock_ldap_entry test_nomap_entry;
    struct ldb_message_element *el;

    const char *foo_values[] = { "fooval1", "fooval2", NULL };
    const char *bar_values[] = { "barval1", NULL };
    struct mock_ldap_attr test_nomap_entry_attrs[] = {
        { .name = "foo", .values = foo_values },
        { .name = "bar", .values = bar_values },
        { NULL, NULL }
    };

    test_nomap_entry.dn = "cn=testentry,dc=example,dc=com";
    test_nomap_entry.attrs = test_nomap_entry_attrs;
    set_entry_parse(&test_nomap_entry);

    ret = sdap_parse_entry(test_ctx, &test_ctx->sh, &test_ctx->sm,
                           NULL, 0, &attrs, false);
    assert_int_equal(ret, ERR_OK);

    assert_int_equal(attrs->num, 3);
    assert_entry_has_attr(attrs, SYSDB_ORIG_DN,
                          "cn=testentry,dc=example,dc=com");
    assert_entry_has_attr(attrs, "bar", "barval1");
    /* Multivalued attributes must return all values */
    ret = sysdb_attrs_get_el_ext(attrs, "foo", false, &el);
    assert_int_equal(ret, ERR_OK);
    assert_int_equal(el->num_values, 2);
    assert_true((strcmp((const char *) el->values[0].data, "fooval1") == 0 &&
                    strcmp((const char *) el->values[1].data, "fooval2") == 0) ||
                (strcmp((const char *) el->values[1].data, "fooval1") == 0 &&
                    strcmp((const char *) el->values[0].data, "fooval2") == 0));


    talloc_free(attrs);
}

/* Only DN and OC, no real attributes */
void test_parse_no_attrs(void **state)
{
    int ret;
    struct sysdb_attrs *attrs;
    struct parse_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                      struct parse_test_ctx);
    struct mock_ldap_entry test_rfc2307_user;
    struct sdap_attr_map *map;

    const char *oc_values[] = { "posixAccount", NULL };
    struct mock_ldap_attr test_rfc2307_user_attrs[] = {
        { .name = "objectClass", .values = oc_values },
        { NULL, NULL }
    };

    test_rfc2307_user.dn = "cn=testuser,dc=example,dc=com";
    test_rfc2307_user.attrs = test_rfc2307_user_attrs;
    set_entry_parse(&test_rfc2307_user);

    ret = sdap_copy_map(test_ctx, rfc2307_user_map, SDAP_OPTS_USER, &map);
    assert_int_equal(ret, ERR_OK);

    ret = sdap_parse_entry(test_ctx, &test_ctx->sh, &test_ctx->sm,
                           map, SDAP_OPTS_USER,
                           &attrs, false);
    assert_int_equal(ret, ERR_OK);

    assert_int_equal(attrs->num, 1);
    assert_entry_has_attr(attrs, SYSDB_ORIG_DN,
                          "cn=testuser,dc=example,dc=com");

    talloc_free(map);
    talloc_free(attrs);
}

void test_parse_dups(void **state)
{
    int ret;
    struct sysdb_attrs *attrs;
    struct parse_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                      struct parse_test_ctx);
    struct mock_ldap_entry test_dupattr_user;
    struct sdap_attr_map *map;
    int i;

    const char *oc_values[] = { "posixAccount", NULL };
    const char *uid_values[] = { "1234", NULL };
    struct mock_ldap_attr test_dupattr_attrs[] = {
        { .name = "objectClass", .values = oc_values },
        { .name = "idNumber", .values = uid_values },
        { NULL, NULL }
    };

    test_dupattr_user.dn = "cn=dupuser,dc=example,dc=com";
    test_dupattr_user.attrs = test_dupattr_attrs;
    set_entry_parse(&test_dupattr_user);

    ret = sdap_copy_map(test_ctx, rfc2307_user_map, SDAP_OPTS_USER, &map);
    assert_int_equal(ret, ERR_OK);
    /* Set both uidNumber and gidNumber to idNumber */
    for (i = 0; i < SDAP_OPTS_USER; i++) {
        if (map[i].name == NULL) continue;

        if (strcmp(map[i].name, "uidNumber") == 0
             || strcmp(map[i].name, "gidNumber") == 0) {
            map[i].name = discard_const("idNumber");
        }
    }

    ret = sdap_parse_entry(test_ctx, &test_ctx->sh, &test_ctx->sm,
                           map, SDAP_OPTS_USER,
                           &attrs, false);
    assert_int_equal(ret, ERR_OK);

    assert_int_equal(attrs->num, 3);

    /* Every entry has a DN */
    assert_entry_has_attr(attrs, SYSDB_ORIG_DN,
                          "cn=dupuser,dc=example,dc=com");
    /* Test the single-valued attribute */
    assert_entry_has_attr(attrs, SYSDB_UIDNUM, "1234");
    assert_entry_has_attr(attrs, SYSDB_GIDNUM, "1234");

    talloc_free(map);
    talloc_free(attrs);
}

/* Negative test - objectclass doesn't match the map */
void test_parse_bad_oc(void **state)
{
    int ret;
    struct sysdb_attrs *attrs;
    struct parse_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                      struct parse_test_ctx);
    struct mock_ldap_entry test_rfc2307_user;
    struct sdap_attr_map *map;

    const char *oc_values[] = { "someRandomValueWhoCaresItsAUnitTest", NULL };
    const char *uid_values[] = { "tuser1", NULL };
    struct mock_ldap_attr test_rfc2307_user_attrs[] = {
        { .name = "objectClass", .values = oc_values },
        { .name = "uid", .values = uid_values },
        { NULL, NULL }
    };

    test_rfc2307_user.dn = "cn=testuser,dc=example,dc=com";
    test_rfc2307_user.attrs = test_rfc2307_user_attrs;
    set_entry_parse(&test_rfc2307_user);

    ret = sdap_copy_map(test_ctx, rfc2307_user_map, SDAP_OPTS_USER, &map);
    assert_int_equal(ret, ERR_OK);

    ret = sdap_parse_entry(test_ctx, &test_ctx->sh, &test_ctx->sm,
                           map, SDAP_OPTS_USER,
                           &attrs, false);
    assert_int_not_equal(ret, ERR_OK);

    talloc_free(map);
}

/* Negative test - the entry has no objectClass. Just make sure
 * we don't crash
 */
void test_parse_no_oc(void **state)
{
    int ret;
    struct sysdb_attrs *attrs;
    struct parse_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                      struct parse_test_ctx);
    struct mock_ldap_entry test_rfc2307_user;
    struct sdap_attr_map *map;

    const char *uid_values[] = { "tuser1", NULL };
    struct mock_ldap_attr test_rfc2307_user_attrs[] = {
        { .name = "uid", .values = uid_values },
        { NULL, NULL }
    };

    test_rfc2307_user.dn = "cn=testuser,dc=example,dc=com";
    test_rfc2307_user.attrs = test_rfc2307_user_attrs;
    set_entry_parse(&test_rfc2307_user);

    ret = sdap_copy_map(test_ctx, rfc2307_user_map, SDAP_OPTS_USER, &map);
    assert_int_equal(ret, ERR_OK);

    ret = sdap_parse_entry(test_ctx, &test_ctx->sh, &test_ctx->sm,
                           map, SDAP_OPTS_USER,
                           &attrs, false);
    assert_int_not_equal(ret, ERR_OK);

    talloc_free(map);
}

/* Negative test - the entry has no DN. Just make sure
 * we don't crash and detect the failure.
 */
void test_parse_no_dn(void **state)
{
    int ret;
    struct sysdb_attrs *attrs;
    struct parse_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                      struct parse_test_ctx);
    struct mock_ldap_entry test_rfc2307_user;
    struct sdap_attr_map *map;

    const char *oc_values[] = { "posixAccount", NULL };
    const char *uid_values[] = { "tuser1", NULL };
    struct mock_ldap_attr test_rfc2307_user_attrs[] = {
        { .name = "objectClass", .values = oc_values },
        { .name = "uid", .values = uid_values },
        { NULL, NULL }
    };

    test_rfc2307_user.dn = NULL;        /* Test */
    test_rfc2307_user.attrs = test_rfc2307_user_attrs;
    set_entry_parse(&test_rfc2307_user);

    ret = sdap_copy_map(test_ctx, rfc2307_user_map, SDAP_OPTS_USER, &map);
    assert_int_equal(ret, ERR_OK);

    ret = sdap_parse_entry(test_ctx, &test_ctx->sh, &test_ctx->sm,
                           map, SDAP_OPTS_USER,
                           &attrs, false);
    assert_int_not_equal(ret, ERR_OK);

    talloc_free(map);
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

    const UnitTest tests[] = {
        unit_test_setup_teardown(test_parse_with_map,
                                 parse_entry_test_setup,
                                 parse_entry_test_teardown),
        unit_test_setup_teardown(test_parse_no_map,
                                 parse_entry_test_setup,
                                 parse_entry_test_teardown),
        unit_test_setup_teardown(test_parse_no_attrs,
                                 parse_entry_test_setup,
                                 parse_entry_test_teardown),
        unit_test_setup_teardown(test_parse_dups,
                                 parse_entry_test_setup,
                                 parse_entry_test_teardown),
        /* Negative tests */
        unit_test_setup_teardown(test_parse_no_oc,
                                 parse_entry_test_setup,
                                 parse_entry_test_teardown),
        unit_test_setup_teardown(test_parse_bad_oc,
                                 parse_entry_test_setup,
                                 parse_entry_test_teardown),
        unit_test_setup_teardown(test_parse_no_dn,
                                 parse_entry_test_setup,
                                 parse_entry_test_teardown),
    };

    /* Set debug level to invalid value so we can deside if -d 0 was used. */
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
     * they might not after a failed run. Remove the old db to be sure */
    tests_set_cwd();

    return run_tests(tests);
}
