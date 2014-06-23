/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

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

#include "util/util.h"
#include "db/sysdb.h"
#include "tests/cmocka/common_mock.h"
#include "tests/cmocka/common_mock_sysdb_objects.h"

enum sysdb_attr_type {
    SYSDB_ATTR_TYPE_BOOL,
    SYSDB_ATTR_TYPE_LONG,
    SYSDB_ATTR_TYPE_UINT32,
    SYSDB_ATTR_TYPE_TIME,
    SYSDB_ATTR_TYPE_STRING
};

static enum sysdb_attr_type
get_attr_type(const char *attr)
{
    /* Most attributes in sysdb are strings. Since this is only for the purpose
     * of unit tests, we can safe ourselves some time and handle all attributes
     * that are not listed amongst other types as string instead of invalid
     * or unknown.
     */

    static const char *table_bool[] = {
        SYSDB_POSIX,
        NULL
    };

    static const char *table_long[] = {
        NULL
    };

    static const char *table_uint32[] = {
        SYSDB_UIDNUM, SYSDB_GIDNUM,
        NULL
    };

    static const char *table_time[] = {
        SYSDB_CACHE_EXPIRE,
        NULL
    };

    static const char **tables[SYSDB_ATTR_TYPE_STRING] = {
        table_bool, table_long, table_uint32, table_time
    };

    enum sysdb_attr_type type;
    int i;

    for (type = 0; type < SYSDB_ATTR_TYPE_STRING; type++) {
        for (i = 0; tables[type][i] != NULL; i++) {
            if (strcmp(attr, tables[type][i]) == 0) {
                return type;
            }
        }
    }

    /* we didn't find the attribute, consider it as string */
    return SYSDB_ATTR_TYPE_STRING;
}

static errno_t
fill_attrs(struct sysdb_attrs *attrs, va_list in_ap)
{
    va_list ap;
    const char *attr = NULL;
    errno_t ret;

    va_copy(ap, in_ap);
    while ((attr = va_arg(ap, const char *)) != NULL) {
        switch (get_attr_type(attr)) {
        case SYSDB_ATTR_TYPE_STRING:
            ret = sysdb_attrs_add_string(attrs, attr, va_arg(ap, const char *));
            break;
        case SYSDB_ATTR_TYPE_BOOL:
            /* _Bool is implicitly promoted to int in variadic functions */
            ret = sysdb_attrs_add_bool(attrs, attr, va_arg(ap, int));
            break;
        case SYSDB_ATTR_TYPE_LONG:
            ret = sysdb_attrs_add_long(attrs, attr, va_arg(ap, long int));
            break;
        case SYSDB_ATTR_TYPE_UINT32:
            ret = sysdb_attrs_add_uint32(attrs, attr, va_arg(ap, uint32_t));
            break;
        case SYSDB_ATTR_TYPE_TIME:
            ret = sysdb_attrs_add_time_t(attrs, attr, va_arg(ap, time_t));
            break;
        }

        if (ret != EOK) {
            return ret;
        }
    }
    va_end(ap);

    return EOK;
}

struct sysdb_attrs *
_mock_sysdb_object(TALLOC_CTX *mem_ctx,
                   const char *base_dn,
                   const char *name,
                   ...)
{
    va_list ap;
    struct sysdb_attrs *attrs = NULL;
    char *orig_dn = NULL;
    errno_t ret;

    attrs = sysdb_new_attrs(mem_ctx);
    if (attrs == NULL) {
        goto fail;
    }

    orig_dn = talloc_asprintf(attrs, "cn=%s,%s", name, base_dn);
    if (orig_dn == NULL) {
        goto fail;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_ORIG_DN, orig_dn);
    if (ret != EOK) {
        goto fail;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_NAME, name);
    if (ret != EOK) {
        goto fail;
    }

    va_start(ap, name);
    ret = fill_attrs(attrs, ap);
    va_end(ap);

    if (ret != EOK) {
        goto fail;
    }

    talloc_free(orig_dn);
    return attrs;

fail:
    talloc_free(attrs);
    return NULL;
}

struct sysdb_attrs *
mock_sysdb_group_rfc2307bis(TALLOC_CTX *mem_ctx,
                            const char *base_dn,
                            gid_t gid,
                            const char *name,
                            const char **members)
{
    struct sysdb_attrs *attrs = NULL;
    errno_t ret;
    int i;

    attrs = mock_sysdb_object(mem_ctx, base_dn, name,
                              SYSDB_GIDNUM, gid);
    if (attrs == NULL) {
        return NULL;
    }

    if (members != NULL) {
        for (i = 0; members[i] != NULL; i++) {
            ret = sysdb_attrs_add_string(attrs, SYSDB_MEMBER, members[i]);
            if (ret != EOK) {
                talloc_zfree(attrs);
                return NULL;
            }
        }
    }

    return attrs;
}

struct sysdb_attrs *
mock_sysdb_user(TALLOC_CTX *mem_ctx,
                const char *base_dn,
                uid_t uid,
                const char *name)
{
    return mock_sysdb_object(mem_ctx, base_dn, name,
                             SYSDB_UIDNUM, uid);
}
