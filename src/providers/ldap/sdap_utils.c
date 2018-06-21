/*
    Authors:
        Simo Sorce <ssorce@redhat.com>

    Copyright (C) 2013 Red Hat

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

#include <ctype.h>
#include "util/util.h"
#include "providers/ldap/sdap_async.h"

errno_t
sdap_attrs_add_ldap_attr(struct sysdb_attrs *ldap_attrs,
                         const char *attr_name,
                         const char *attr_desc,
                         bool multivalued,
                         const char *name,
                         struct sysdb_attrs *attrs)
{
    errno_t ret;
    struct ldb_message_element *el;
    const char *objname = name ?: "object";
    const char *desc = attr_desc ?: attr_name;
    unsigned int num_values, i;
    char *printable;

    ret = sysdb_attrs_get_el(ldap_attrs, attr_name, &el);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not get %s from the "
              "list of the LDAP attributes [%d]: %s\n",
              attr_name, ret, strerror(ret));
        return ret;
    }

    if (el->num_values == 0) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "%s is not available "
              "for [%s].\n", desc, objname);
    } else {
        num_values = multivalued ? el->num_values : 1;
        for (i = 0; i < num_values; i++) {
            printable = ldb_binary_encode(ldap_attrs, el->values[i]);
            if (printable == NULL) {
                DEBUG(SSSDBG_MINOR_FAILURE, "ldb_binary_encode failed..\n");
                continue;
            }

            DEBUG(SSSDBG_TRACE_INTERNAL, "Adding %s [%s] to attributes "
                  "of [%s].\n", desc, printable, objname);

            talloc_zfree(printable);

            ret = sysdb_attrs_add_mem(attrs, attr_name, el->values[i].data,
                                      el->values[i].length);
            if (ret) {
                return ret;
            }
        }
    }

    return EOK;
}

errno_t
sdap_save_all_names(const char *name,
                    struct sysdb_attrs *ldap_attrs,
                    struct sss_domain_info *dom,
                    enum sysdb_member_type entry_type,
                    struct sysdb_attrs *attrs)
{
    const char **aliases = NULL;
    const char *sysdb_alias;
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    int i;
    bool lowercase = !dom->case_sensitive;
    bool store_as_fqdn;

    switch (entry_type) {
    case SYSDB_MEMBER_USER:
    case SYSDB_MEMBER_GROUP:
        store_as_fqdn = true;
        break;
    default:
        store_as_fqdn = false;
        break;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_get_aliases(tmp_ctx, ldap_attrs, name,
                                  lowercase, &aliases);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get the alias list\n");
        goto done;
    }

    for (i = 0; aliases[i]; i++) {
        if (store_as_fqdn) {
            sysdb_alias = sss_create_internal_fqname(tmp_ctx, aliases[i],
                                                 dom->name);
        } else {
            sysdb_alias = aliases[i];
        }

        if (sysdb_alias == NULL) {
            ret = ENOMEM;
            goto done;
        }

        if (lowercase) {
            ret = sysdb_attrs_add_lc_name_alias(attrs, sysdb_alias);
            if (ret) {
                DEBUG(SSSDBG_OP_FAILURE, "Failed to add lower-cased version "
                                          "of alias [%s] into the "
                                          "attribute list\n", aliases[i]);
                goto done;
            }
        } else {
            ret = sysdb_attrs_add_string(attrs, SYSDB_NAME_ALIAS, sysdb_alias);
            if (ret) {
                DEBUG(SSSDBG_OP_FAILURE, "Failed to add alias [%s] into the "
                                          "attribute list\n", aliases[i]);
                goto done;
            }
        }

    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t deref_string_to_val(const char *str, int *val)
{
    if (strcasecmp(str, "never") == 0) {
        *val = LDAP_DEREF_NEVER;
    } else if (strcasecmp(str, "searching") == 0) {
        *val = LDAP_DEREF_SEARCHING;
    } else if (strcasecmp(str, "finding") == 0) {
        *val = LDAP_DEREF_FINDING;
    } else if (strcasecmp(str, "always") == 0) {
        *val = LDAP_DEREF_ALWAYS;
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "Illegal deref option [%s].\n", str);
        return EINVAL;
    }

    return EOK;
}

static char *
sdap_combine_filters_ex(TALLOC_CTX *mem_ctx,
                        char operator,
                        const char *base_filter,
                        const char *extra_filter)
{
    char *filter = NULL;

    if (extra_filter == NULL || extra_filter[0] == '\0') {
        return talloc_strdup(mem_ctx, base_filter);
    } else if (base_filter == NULL || base_filter[0] == '\0') {
        return talloc_strdup(mem_ctx, extra_filter);
    }

    if (extra_filter[0] == '(') {
        filter = talloc_asprintf(mem_ctx, "(%c%s%s)",
                                 operator, base_filter, extra_filter);
    } else {
        filter = talloc_asprintf(mem_ctx, "(%c%s(%s))",
                                 operator, base_filter, extra_filter);
    }

    return filter; /* NULL or not */
}

char *sdap_or_filters(TALLOC_CTX *mem_ctx,
                      const char *base_filter,
                      const char *extra_filter)
{
    return sdap_combine_filters_ex(mem_ctx, '|', base_filter, extra_filter);
}

char *sdap_combine_filters(TALLOC_CTX *mem_ctx,
                           const char *base_filter,
                           const char *extra_filter)
{
    return sdap_combine_filters_ex(mem_ctx, '&', base_filter, extra_filter);
}

char *get_enterprise_principal_string_filter(TALLOC_CTX *mem_ctx,
                                             const char *attr_name,
                                             const char *princ,
                                             struct dp_option *sdap_basic_opts)
{
    const char *realm;
    char *p;

    if (attr_name == NULL || princ == NULL || sdap_basic_opts == NULL) {
        return NULL;
    }

    realm = dp_opt_get_cstring(sdap_basic_opts, SDAP_KRB5_REALM);
    if (realm == NULL) {
        return NULL;
    }

    p = strchr(princ, '@');
    if (p == NULL) {
        return NULL;
    }

    return talloc_asprintf(mem_ctx, "(%s=%.*s\\\\@%s@%s)", attr_name,
                                                           (int) (p - princ),
                                                           princ,
                                                           p + 1, realm);
}
