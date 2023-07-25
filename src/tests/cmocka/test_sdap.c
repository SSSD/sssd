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
#include "db/sysdb_iphosts.h"

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

LDAPDerefRes *mock_deref_res(TALLOC_CTX *mem_ctx,
                             struct mock_ldap_entry *entry)
{
    LDAPDerefRes *dref;
    LDAPDerefVal *dval, *dvaltail = NULL;
    size_t nattr;
    size_t nval;

    dref = talloc_zero(mem_ctx, LDAPDerefRes);
    assert_non_null(dref);

    dref->derefVal.bv_val = talloc_strdup(dref, entry->dn);
    assert_non_null(dref->derefVal.bv_val);
    dref->derefVal.bv_len = strlen(entry->dn);

    if (entry->attrs == NULL) {
        /* no attributes, done */
        return dref;
    }

    for (nattr = 0; entry->attrs[nattr].name; nattr++) {
        dval = talloc_zero(dref, LDAPDerefVal);
        assert_non_null(dval);

        dval->type = talloc_strdup(dval, entry->attrs[nattr].name);
        assert_non_null(dval->type);

        for (nval = 0; entry->attrs[nattr].values[nval]; nval++);

        dval->vals = talloc_zero_array(dval, struct berval, nval+1);
        assert_non_null(dval->vals);
        for (nval = 0; entry->attrs[nattr].values[nval]; nval++) {
            dval->vals[nval].bv_val = talloc_strdup(dval->vals,
                                             entry->attrs[nattr].values[nval]);
            assert_non_null(dval->vals[nval].bv_val);
            dval->vals[nval].bv_len = strlen(dval->vals[nval].bv_val);
        }

        if (dvaltail != NULL) {
            dvaltail->next = dval;
            dvaltail = dvaltail->next;
        } else {
            dvaltail = dval;
            dref->attrVals = dval;
        }
    }

    return dref;
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

    int idx = mock_ldap_entry_iter();
    char *val;

    val = discard_const(ldap_entry->attrs[idx].name);
    if (val != NULL) {
        will_return(mock_ldap_entry_iter, idx + 1);
    }
    return val;
}

/* Mock parsing search base without overlinking the test */
errno_t sdap_parse_search_base(TALLOC_CTX *mem_ctx, struct ldb_context *ldb,
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

static int parse_entry_test_setup(void **state)
{
    struct parse_test_ctx *test_ctx;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context, struct parse_test_ctx);
    assert_non_null(test_ctx);

    check_leaks_push(test_ctx);
    *state = test_ctx;
    return 0;
}

static int parse_entry_test_teardown(void **state)
{
    struct parse_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                      struct parse_test_ctx);

    assert_true(check_leaks_pop(test_ctx) == true);
    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
    return 0;
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

void test_parse_deref(void **state)
{
    errno_t ret;
    struct sdap_attr_map_info minfo;
    struct parse_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                      struct parse_test_ctx);
    struct sdap_deref_attrs **res;
    LDAPDerefRes *dref;

    const char *oc_values[] = { "posixAccount", NULL };
    const char *uid_values[] = { "tuser1", NULL };
    const char *extra_values[] = { "extra", NULL };
    struct mock_ldap_attr test_ipa_user_attrs[] = {
        { .name = "objectClass", .values = oc_values },
        { .name = "uid", .values = uid_values },
        { .name = "extra", .values = extra_values },
        { NULL, NULL }
    };
    struct mock_ldap_entry test_ipa_user;
    test_ipa_user.dn = "cn=testuser,dc=example,dc=com";
    test_ipa_user.attrs = test_ipa_user_attrs;

    ret = sdap_copy_map(test_ctx, rfc2307_user_map, SDAP_OPTS_USER, &minfo.map);
    minfo.num_attrs = SDAP_OPTS_USER;
    assert_int_equal(ret, ERR_OK);

    dref = mock_deref_res(test_ctx, &test_ipa_user);
    assert_non_null(dref);

    ret = sdap_parse_deref(test_ctx, &minfo, 1, dref, &res);
    talloc_free(dref);
    talloc_free(minfo.map);
    assert_int_equal(ret, ERR_OK);
    assert_non_null(res);

    /* The extra attribute must not be downloaded, it's not present in map */
    assert_non_null(res[0]);
    assert_true(res[0]->map == minfo.map);

    assert_entry_has_attr(res[0]->attrs, SYSDB_ORIG_DN,
                          "cn=testuser,dc=example,dc=com");
    assert_entry_has_attr(res[0]->attrs, SYSDB_NAME, "tuser1");
    assert_entry_has_no_attr(res[0]->attrs, "extra");
    talloc_free(res);
}

void test_parse_deref_no_attrs(void **state)
{
    errno_t ret;
    struct sdap_attr_map_info minfo;
    struct parse_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                      struct parse_test_ctx);
    struct sdap_deref_attrs **res;
    LDAPDerefRes *dref;

    struct mock_ldap_entry test_ipa_user;
    test_ipa_user.dn = "cn=testuser,dc=example,dc=com";
    test_ipa_user.attrs = NULL;

    ret = sdap_copy_map(test_ctx, rfc2307_user_map, SDAP_OPTS_USER, &minfo.map);
    minfo.num_attrs = SDAP_OPTS_USER;
    assert_int_equal(ret, ERR_OK);

    dref = mock_deref_res(test_ctx, &test_ipa_user);
    assert_non_null(dref);

    ret = sdap_parse_deref(test_ctx, &minfo, 1, dref, &res);
    talloc_free(dref);
    talloc_free(minfo.map);
    assert_int_equal(ret, ERR_OK);
    assert_null(res); /* res must be NULL on receiving no attributes */
}

void test_parse_deref_map_mismatch(void **state)
{
    errno_t ret;
    struct sdap_attr_map_info minfo;
    struct parse_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                      struct parse_test_ctx);
    struct sdap_deref_attrs **res;
    LDAPDerefRes *dref;

    const char *oc_values[] = { "posixAccount", NULL };
    const char *uid_values[] = { "tuser1", NULL };
    struct mock_ldap_attr test_ipa_user_attrs[] = {
        { .name = "objectClass", .values = oc_values },
        { .name = "uid", .values = uid_values },
        { NULL, NULL }
    };
    struct mock_ldap_entry test_ipa_user;
    test_ipa_user.dn = "cn=testuser,dc=example,dc=com";
    test_ipa_user.attrs = test_ipa_user_attrs;

    ret = sdap_copy_map(test_ctx, rfc2307_group_map, SDAP_OPTS_GROUP, &minfo.map);
    minfo.num_attrs = SDAP_OPTS_GROUP;
    assert_int_equal(ret, ERR_OK);

    dref = mock_deref_res(test_ctx, &test_ipa_user);
    assert_non_null(dref);

    ret = sdap_parse_deref(test_ctx, &minfo, 1, dref, &res);
    talloc_free(dref);
    talloc_free(minfo.map);
    assert_int_equal(ret, ERR_OK);
    assert_non_null(res);
    /* the group map didn't match, so no attrs will be parsed out of the map */
    assert_null(res[0]->attrs);
    talloc_free(res);
}

void test_parse_secondary_oc(void **state)
{
    int ret;
    struct sysdb_attrs *attrs;
    struct parse_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                      struct parse_test_ctx);
    struct mock_ldap_entry test_rfc2307_group;
    struct sdap_attr_map *map;

    const char *oc_values[] = { "secondaryOC", NULL };
    const char *uid_values[] = { "tgroup1", NULL };
    struct mock_ldap_attr test_rfc2307_group_attrs[] = {
        { .name = "objectClass", .values = oc_values },
        { .name = "uid", .values = uid_values },
        { NULL, NULL }
    };

    test_rfc2307_group.dn = "cn=testgroup,dc=example,dc=com";
    test_rfc2307_group.attrs = test_rfc2307_group_attrs;
    set_entry_parse(&test_rfc2307_group);

    ret = sdap_copy_map(test_ctx, rfc2307_group_map, SDAP_OPTS_GROUP, &map);
    assert_int_equal(ret, ERR_OK);
    map[SDAP_OC_GROUP_ALT].name = discard_const("secondaryOC");

    ret = sdap_parse_entry(test_ctx, &test_ctx->sh, &test_ctx->sm,
                           map, SDAP_OPTS_GROUP,
                           &attrs, false);
    assert_int_equal(ret, ERR_OK);

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

struct copy_map_entry_test_ctx {
    struct sdap_attr_map *src_map;
    struct sdap_attr_map *dst_map;
};

static int copy_map_entry_test_setup(void **state)
{
    int ret;
    struct copy_map_entry_test_ctx *test_ctx;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context,
                           struct copy_map_entry_test_ctx);
    assert_non_null(test_ctx);

    ret = sdap_copy_map(test_ctx, rfc2307_user_map,
                        SDAP_OPTS_USER, &test_ctx->src_map);
    assert_int_equal(ret, ERR_OK);

    ret = sdap_copy_map(test_ctx, rfc2307_user_map,
                        SDAP_OPTS_USER, &test_ctx->dst_map);
    assert_int_equal(ret, ERR_OK);

    check_leaks_push(test_ctx);
    *state = test_ctx;
    return 0;
}

static int copy_map_entry_test_teardown(void **state)
{
    struct copy_map_entry_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                               struct copy_map_entry_test_ctx);
    assert_true(check_leaks_pop(test_ctx) == true);
    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
    return 0;
}

static const char *copy_uuid(struct copy_map_entry_test_ctx *test_ctx)
{
    errno_t ret;

    assert_null(test_ctx->dst_map[SDAP_AT_USER_UUID].name);
    ret = sdap_copy_map_entry(test_ctx->src_map, test_ctx->dst_map,
                              SDAP_AT_USER_UUID);
    assert_int_equal(ret, EOK);
    return test_ctx->dst_map[SDAP_AT_USER_UUID].name;
}

static void test_sdap_copy_map_entry(void **state)
{
    struct copy_map_entry_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                               struct copy_map_entry_test_ctx);
    const char *uuid_set_val = "test_uuid_val";
    const char *uuid_val = NULL;

    test_ctx->src_map[SDAP_AT_USER_UUID].name = discard_const(uuid_set_val);

    uuid_val = copy_uuid(test_ctx);
    assert_non_null(uuid_val);
    assert_string_equal(uuid_val, uuid_set_val);
    talloc_free(test_ctx->dst_map[SDAP_AT_USER_UUID].name);
}

static void test_sdap_copy_map_entry_null_name(void **state)
{
    struct copy_map_entry_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                               struct copy_map_entry_test_ctx);
    const char *uuid_val = NULL;

    uuid_val = copy_uuid(test_ctx);
    assert_null(uuid_val);
}

struct test_sdap_inherit_ctx {
    struct sdap_options *parent_sdap_opts;
    struct sdap_options *child_sdap_opts;
};

struct sdap_options *mock_sdap_opts(TALLOC_CTX *mem_ctx)
{
    int ret;
    struct sdap_options *opts;

    opts = talloc_zero(mem_ctx, struct sdap_options);
    assert_non_null(opts);

    ret = sdap_copy_map(opts, rfc2307_user_map,
                        SDAP_OPTS_USER, &opts->user_map);
    assert_int_equal(ret, ERR_OK);

    ret = dp_copy_defaults(opts, default_basic_opts,
                           SDAP_OPTS_BASIC, &opts->basic);
    assert_int_equal(ret, ERR_OK);

    return opts;
}

static int test_sdap_inherit_option_setup(void **state)
{
    int ret;
    struct test_sdap_inherit_ctx *test_ctx;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context,
                           struct test_sdap_inherit_ctx);
    assert_non_null(test_ctx);

    test_ctx->child_sdap_opts = talloc_zero(test_ctx, struct sdap_options);

    test_ctx->parent_sdap_opts = mock_sdap_opts(test_ctx);
    assert_non_null(test_ctx->parent_sdap_opts);
    test_ctx->child_sdap_opts = mock_sdap_opts(test_ctx);
    assert_non_null(test_ctx->child_sdap_opts);

    test_ctx->parent_sdap_opts->user_map[SDAP_AT_USER_PRINC].name = \
                                                  discard_const("test_princ");

    ret = dp_opt_set_int(test_ctx->parent_sdap_opts->basic,
                         SDAP_PURGE_CACHE_TIMEOUT, 123);
    assert_int_equal(ret, EOK);

    *state = test_ctx;
    return 0;
}

static int test_sdap_inherit_option_teardown(void **state)
{
    struct test_sdap_inherit_ctx *test_ctx = \
                talloc_get_type_abort(*state, struct test_sdap_inherit_ctx);

    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
    return 0;
}

static void test_sdap_inherit_option_null(void **state)
{
    struct test_sdap_inherit_ctx *test_ctx = \
                talloc_get_type_abort(*state, struct test_sdap_inherit_ctx);
    int val;

    val = dp_opt_get_int(test_ctx->child_sdap_opts->basic,
                         SDAP_PURGE_CACHE_TIMEOUT);
    assert_int_equal(val, 0);

    sdap_inherit_options(NULL,
                         test_ctx->parent_sdap_opts,
                         test_ctx->child_sdap_opts);

    val = dp_opt_get_int(test_ctx->child_sdap_opts->basic,
                         SDAP_PURGE_CACHE_TIMEOUT);
    assert_int_equal(val, 0);
}

static void test_sdap_inherit_option_notset(void **state)
{
    struct test_sdap_inherit_ctx *test_ctx = \
                talloc_get_type_abort(*state, struct test_sdap_inherit_ctx);
    int val;
    const char *inherit_options[] = { "ldap_use_tokengroups", NULL };

    val = dp_opt_get_int(test_ctx->child_sdap_opts->basic,
                         SDAP_PURGE_CACHE_TIMEOUT);
    assert_int_equal(val, 0);

    /* parent has nondefault, but it's not supposed to be inherited */
    sdap_inherit_options(discard_const(inherit_options),
                         test_ctx->parent_sdap_opts,
                         test_ctx->child_sdap_opts);

    val = dp_opt_get_int(test_ctx->child_sdap_opts->basic,
                         SDAP_PURGE_CACHE_TIMEOUT);
    assert_int_equal(val, 0);
}

static void test_sdap_inherit_option_basic(void **state)
{
    struct test_sdap_inherit_ctx *test_ctx = \
                talloc_get_type_abort(*state, struct test_sdap_inherit_ctx);
    int val;
    const char *inherit_options[] = { "ldap_purge_cache_timeout", NULL };

    val = dp_opt_get_int(test_ctx->child_sdap_opts->basic,
                         SDAP_PURGE_CACHE_TIMEOUT);
    assert_int_equal(val, 0);

    /* parent has nondefault, but it's not supposed to be inherited */
    sdap_inherit_options(discard_const(inherit_options),
                         test_ctx->parent_sdap_opts,
                         test_ctx->child_sdap_opts);

    val = dp_opt_get_int(test_ctx->child_sdap_opts->basic,
                         SDAP_PURGE_CACHE_TIMEOUT);
    assert_int_equal(val, 123);
}

static void test_sdap_inherit_option_user(void **state)
{
    struct test_sdap_inherit_ctx *test_ctx = \
                talloc_get_type_abort(*state, struct test_sdap_inherit_ctx);
    const char *inherit_options[] = { "ldap_user_principal", NULL };

    assert_string_equal(
            test_ctx->child_sdap_opts->user_map[SDAP_AT_USER_PRINC].name,
            "krbPrincipalName");

    /* parent has nondefault, but it's not supposed to be inherited */
    sdap_inherit_options(discard_const(inherit_options),
                         test_ctx->parent_sdap_opts,
                         test_ctx->child_sdap_opts);

    assert_string_equal(
            test_ctx->child_sdap_opts->user_map[SDAP_AT_USER_PRINC].name,
            "test_princ");

    talloc_free(test_ctx->child_sdap_opts->user_map[SDAP_AT_USER_PRINC].name);
}

struct copy_dom_obj_test_ctx {
    struct sdap_options *opts;

    struct sss_domain_info *parent;
    struct sss_domain_info *child;

    struct sdap_domain *parent_sd;
    struct sdap_domain *child_sd;

    struct sysdb_attrs **ldap_objects;
    struct sysdb_attrs **dom_objects;
};

static struct sysdb_attrs *test_obj(TALLOC_CTX *mem_ctx,
                                    const char *name,
                                    const char *basedn)
{
    errno_t ret;
    const char *orig_dn;
    struct sysdb_attrs *obj;

    obj = sysdb_new_attrs(mem_ctx);
    assert_non_null(obj);

    orig_dn = talloc_asprintf(obj, "CN=%s,%s", name, basedn);
    assert_non_null(orig_dn);

    ret = sysdb_attrs_add_string(obj, SYSDB_ORIG_DN, orig_dn);
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_string(obj, SYSDB_NAME, name);
    assert_int_equal(ret, EOK);

    return obj;
}

static struct sdap_domain *create_sdap_domain(struct sdap_options *opts,
                                              struct sss_domain_info *dom)
{
    errno_t ret;
    struct sdap_domain *sdom;
    struct ldb_context *ldb;

    ret = sdap_domain_add(opts, dom, &sdom);
    assert_int_equal(ret, EOK);

    sdom->search_bases = talloc_array(sdom, struct sdap_search_base *, 2);
    assert_non_null(sdom->search_bases);
    sdom->search_bases[1] = NULL;

    ldb = ldb_init(sdom, NULL);
    assert_non_null(ldb);

    ret = sdap_create_search_base(sdom, ldb, sdom->basedn,
                                  LDAP_SCOPE_SUBTREE,
                                  NULL,
                                  &sdom->search_bases[0]);
    assert_int_equal(ret, EOK);

    return sdom;
}

static int sdap_copy_objects_in_dom_setup(void **state)
{
    struct copy_dom_obj_test_ctx *test_ctx;

    test_ctx = talloc_zero(NULL,
                           struct copy_dom_obj_test_ctx);
    assert_non_null(test_ctx);

    test_ctx->opts = talloc_zero(test_ctx, struct sdap_options);
    assert_non_null(test_ctx->opts);

    test_ctx->parent = named_domain(test_ctx, "win.trust.test", NULL);
    assert_non_null(test_ctx->parent);

    test_ctx->child = named_domain(test_ctx, "child.win.trust.test",
                                   test_ctx->parent);
    assert_non_null(test_ctx->child);

    test_ctx->parent_sd = create_sdap_domain(test_ctx->opts,
                                             test_ctx->parent);
    assert_non_null(test_ctx->parent_sd);

    test_ctx->child_sd = create_sdap_domain(test_ctx->opts,
                                            test_ctx->child);
    assert_non_null(test_ctx->child_sd);

    /* These two objects were 'returned by LDAP' */
    test_ctx->ldap_objects = talloc_zero_array(test_ctx,
                                               struct sysdb_attrs *, 2);
    assert_non_null(test_ctx->ldap_objects);

    test_ctx->ldap_objects[0] = test_obj(test_ctx->ldap_objects, "parent",
                                         test_ctx->parent_sd->basedn);
    assert_non_null(test_ctx->ldap_objects[0]);

    test_ctx->ldap_objects[1] = test_obj(test_ctx->ldap_objects, "child",
                                         test_ctx->child_sd->basedn);
    assert_non_null(test_ctx->ldap_objects[1]);

    /* This is the array we'll filter to */
    test_ctx->dom_objects = talloc_zero_array(test_ctx,
                                              struct sysdb_attrs *, 2);
    assert_non_null(test_ctx->dom_objects);

    *state = test_ctx;
    return 0;
}

static int sdap_copy_objects_in_dom_teardown(void **state)
{
    struct copy_dom_obj_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                 struct copy_dom_obj_test_ctx);

    talloc_free(test_ctx);
    return 0;
}

static void test_sdap_copy_objects_in_dom(void **state)
{
    struct copy_dom_obj_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                 struct copy_dom_obj_test_ctx);
    size_t count;

    assert_ptr_equal(talloc_parent(test_ctx->ldap_objects[0]),
                     test_ctx->ldap_objects);
    assert_ptr_equal(talloc_parent(test_ctx->ldap_objects[1]),
                     test_ctx->ldap_objects);

    assert_null(test_ctx->dom_objects[0]);
    assert_null(test_ctx->dom_objects[1]);

    count = sdap_steal_objects_in_dom(test_ctx->opts,
                                      test_ctx->dom_objects,
                                      0,
                                      test_ctx->parent,
                                      test_ctx->ldap_objects,
                                      2, true);
    assert_int_equal(count, 1);

    assert_non_null(test_ctx->dom_objects[0]);
    assert_non_null(test_ctx->dom_objects[0] == test_ctx->ldap_objects[0]);
    assert_null(test_ctx->dom_objects[1]);

    assert_ptr_equal(talloc_parent(test_ctx->ldap_objects[0]),
                     test_ctx->dom_objects);

    count = sdap_steal_objects_in_dom(test_ctx->opts,
                                      test_ctx->dom_objects,
                                      1,
                                      test_ctx->child,
                                      test_ctx->ldap_objects,
                                      2, true);
    assert_int_equal(count, 1);

    assert_non_null(test_ctx->dom_objects[1]);
    assert_non_null(test_ctx->dom_objects[1] == test_ctx->ldap_objects[1]);
    assert_ptr_equal(talloc_parent(test_ctx->ldap_objects[1]),
                     test_ctx->dom_objects);
}

static void test_sdap_copy_objects_in_dom_nofilter(void **state)
{
    struct copy_dom_obj_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                 struct copy_dom_obj_test_ctx);
    size_t count;

    count = sdap_steal_objects_in_dom(test_ctx->opts,
                                      test_ctx->dom_objects,
                                      0,
                                      test_ctx->parent,
                                      test_ctx->ldap_objects,
                                      2, false);
    assert_int_equal(count, 2);

    assert_ptr_equal(talloc_parent(test_ctx->ldap_objects[0]),
                     test_ctx->dom_objects);
    assert_ptr_equal(talloc_parent(test_ctx->ldap_objects[1]),
                     test_ctx->dom_objects);
}

#define ORIG_DN "cn=host.example.com+ipHostNumber=192.168.1.1,ou=hosts,dc=example,dc=com"
#define ALT_ORIG_DN "cn=host+ipHostNumber=192.168.1.1,ou=hosts,dc=example,dc=com"
#define ALT2_ORIG_DN "cn=foo+ipHostNumber=192.168.1.1,ou=hosts,dc=example,dc=com"
static void test_sdap_get_primary_name(void **state)
{
    int ret;
    const char *out = NULL;

    struct sysdb_attrs *attrs;
    struct parse_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                      struct parse_test_ctx);
    struct mock_ldap_entry test_nomap_entry;
    struct ldb_message_element *el;
    struct sdap_attr_map *map;
    const char *first_name_in_list = NULL;

    const char *cn_values[] = { "host.example.com", "host", NULL };
    const char *ip_values[] = { "192.168.1.1", NULL };

    const char *oc_values[] = { "ipHost", NULL };
    struct mock_ldap_attr test_nomap_entry_attrs[] = {
        { .name = "objectClass", .values = oc_values },
        { .name = "cn", .values = cn_values },
        { .name = "ipHostNumber", .values = ip_values },
        { NULL, NULL }
    };

    test_nomap_entry.dn = ORIG_DN;
    test_nomap_entry.attrs = test_nomap_entry_attrs;
    set_entry_parse(&test_nomap_entry);

    ret = sdap_copy_map(test_ctx, iphost_map, SDAP_OPTS_IPHOST, &map);
    assert_int_equal(ret, ERR_OK);

    ret = sdap_parse_entry(test_ctx, &test_ctx->sh, &test_ctx->sm,
                           map, SDAP_OPTS_IPHOST, &attrs, false);
    assert_int_equal(ret, ERR_OK);

    assert_int_equal(attrs->num, 3);
    assert_entry_has_attr(attrs, SYSDB_ORIG_DN, ORIG_DN);
    assert_entry_has_attr(attrs, SYSDB_IP_HOST_ATTR_ADDRESS, "192.168.1.1");
    /* Multivalued attributes must return all values */
    ret = sysdb_attrs_get_el_ext(attrs, SYSDB_NAME, false, &el);
    assert_int_equal(ret, ERR_OK);
    assert_int_equal(el->num_values, 2);
    assert_true((strcmp((const char *) el->values[0].data, "host.example.com") == 0 &&
                    strcmp((const char *) el->values[1].data, "host") == 0) ||
                (strcmp((const char *) el->values[1].data, "host.example.com") == 0 &&
                    strcmp((const char *) el->values[0].data, "host") == 0));
    first_name_in_list = (const char *) el->values[0].data;


    ret = sdap_get_primary_name("cn", attrs, &out);
    assert_int_equal(ret, EOK);
    assert_string_equal(out, "host.example.com");

    /* check that the first name is returned if there is no matching
     * attribute name in the RDN */
    ret = sdap_get_primary_name("foo", attrs, &out);
    assert_int_equal(ret, EOK);
    assert_string_equal(out, first_name_in_list);

    /* check with the second name value in the RDN */
    sysdb_attrs_get_el(attrs, SYSDB_ORIG_DN, &el);
    assert_int_equal(ret, ERR_OK);
    assert_int_equal(el->num_values, 1);
    assert_string_equal(ORIG_DN, (const char *) el->values[0].data);
    talloc_free(el->values[0].data);
    el->values[0].data = (uint8_t *) talloc_strdup(el, ALT_ORIG_DN);
    assert_non_null(el->values[0].data);
    el->values[0].length = sizeof(ALT_ORIG_DN);

    ret = sdap_get_primary_name("cn", attrs, &out);
    assert_int_equal(ret, EOK);
    assert_string_equal(out, "host");

    /* check that the first name is returned if there is no matching
     * attribute name in the RDN */
    ret = sdap_get_primary_name("foo", attrs, &out);
    assert_int_equal(ret, EOK);
    assert_string_equal(out, first_name_in_list);

    /* Check with an unexpected name in the DN which is not in the name list */
    sysdb_attrs_get_el(attrs, SYSDB_ORIG_DN, &el);
    assert_int_equal(ret, ERR_OK);
    assert_int_equal(el->num_values, 1);
    assert_string_equal(ALT_ORIG_DN, (const char *) el->values[0].data);
    talloc_free(el->values[0].data);
    el->values[0].data = (uint8_t *) talloc_strdup(el, ALT2_ORIG_DN);
    assert_non_null(el->values[0].data);
    el->values[0].length = sizeof(ALT2_ORIG_DN);

    ret = sdap_get_primary_name("cn", attrs, &out);
    assert_int_equal(ret, EINVAL);

    talloc_free(map);
    talloc_free(attrs);
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
        cmocka_unit_test_setup_teardown(test_parse_with_map,
                                        parse_entry_test_setup,
                                        parse_entry_test_teardown),
        cmocka_unit_test_setup_teardown(test_parse_no_map,
                                        parse_entry_test_setup,
                                        parse_entry_test_teardown),
        cmocka_unit_test_setup_teardown(test_parse_no_attrs,
                                        parse_entry_test_setup,
                                        parse_entry_test_teardown),
        cmocka_unit_test_setup_teardown(test_parse_dups,
                                        parse_entry_test_setup,
                                        parse_entry_test_teardown),
        cmocka_unit_test_setup_teardown(test_parse_deref,
                                        parse_entry_test_setup,
                                        parse_entry_test_teardown),
        cmocka_unit_test_setup_teardown(test_parse_deref_no_attrs,
                                        parse_entry_test_setup,
                                        parse_entry_test_teardown),
        cmocka_unit_test_setup_teardown(test_parse_secondary_oc,
                                        parse_entry_test_setup,
                                        parse_entry_test_teardown),
        /* Negative tests */
        cmocka_unit_test_setup_teardown(test_parse_no_oc,
                                        parse_entry_test_setup,
                                        parse_entry_test_teardown),
        cmocka_unit_test_setup_teardown(test_parse_bad_oc,
                                        parse_entry_test_setup,
                                        parse_entry_test_teardown),
        cmocka_unit_test_setup_teardown(test_parse_no_dn,
                                        parse_entry_test_setup,
                                        parse_entry_test_teardown),
        cmocka_unit_test_setup_teardown(test_parse_deref_map_mismatch,
                                        parse_entry_test_setup,
                                        parse_entry_test_teardown),

        /* Map option tests */
        cmocka_unit_test_setup_teardown(test_sdap_copy_map_entry,
                                        copy_map_entry_test_setup,
                                        copy_map_entry_test_teardown),
        cmocka_unit_test_setup_teardown(test_sdap_copy_map_entry_null_name,
                                        copy_map_entry_test_setup,
                                        copy_map_entry_test_teardown),

        /* Option inherit tests */
        cmocka_unit_test_setup_teardown(test_sdap_inherit_option_null,
                                        test_sdap_inherit_option_setup,
                                        test_sdap_inherit_option_teardown),
        cmocka_unit_test_setup_teardown(test_sdap_inherit_option_notset,
                                        test_sdap_inherit_option_setup,
                                        test_sdap_inherit_option_teardown),
        cmocka_unit_test_setup_teardown(test_sdap_inherit_option_basic,
                                        test_sdap_inherit_option_setup,
                                        test_sdap_inherit_option_teardown),
        cmocka_unit_test_setup_teardown(test_sdap_inherit_option_user,
                                        test_sdap_inherit_option_setup,
                                        test_sdap_inherit_option_teardown),

        /* Per-domain object filter tests */
        cmocka_unit_test_setup_teardown(test_sdap_copy_objects_in_dom,
                                        sdap_copy_objects_in_dom_setup,
                                        sdap_copy_objects_in_dom_teardown),
        cmocka_unit_test_setup_teardown(test_sdap_copy_objects_in_dom_nofilter,
                                        sdap_copy_objects_in_dom_setup,
                                        sdap_copy_objects_in_dom_teardown),

        cmocka_unit_test_setup_teardown(test_sdap_get_primary_name,
                                        parse_entry_test_setup,
                                        parse_entry_test_teardown),
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
