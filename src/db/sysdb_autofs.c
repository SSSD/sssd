/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2012 Red Hat

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

#include "db/sysdb.h"
#include "db/sysdb_private.h"
#include "db/sysdb_autofs.h"

#define SYSDB_TMPL_AUTOFS_ENTRY SYSDB_NAME"=%s,"SYSDB_TMPL_CUSTOM

static struct ldb_dn *
sysdb_autofsmap_dn(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *sysdb,
                   const char *map_name)
{
    return sysdb_custom_dn(sysdb, mem_ctx, map_name, AUTOFS_MAP_SUBDIR);
}

static struct ldb_dn *
sysdb_autofsentry_dn(TALLOC_CTX *mem_ctx,
                     struct sysdb_ctx *sysdb,
                     const char *map_name,
                     const char *entry_name,
                     const char *entry_value)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    char *clean_name;
    char *clean_value;
    const char *rdn;
    struct ldb_dn *dn = NULL;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return NULL;
    }

    ret = sysdb_dn_sanitize(tmp_ctx, entry_name, &clean_name);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_dn_sanitize(tmp_ctx, entry_value, &clean_value);
    if (ret != EOK) {
        goto done;
    }

    rdn = talloc_asprintf(tmp_ctx, "%s%s", clean_name, clean_value);
    if (!rdn) {
        goto done;
    }

    dn = ldb_dn_new_fmt(mem_ctx, sysdb->ldb, SYSDB_TMPL_AUTOFS_ENTRY,
                        rdn, map_name, AUTOFS_MAP_SUBDIR,
                        sysdb->domain->name);

done:
    talloc_free(tmp_ctx);
    return dn;
}

errno_t
sysdb_save_autofsmap(struct sysdb_ctx *sysdb_ctx,
                     const char *name,
                     const char *autofsmapname,
                     struct sysdb_attrs *attrs,
                     int cache_timeout,
                     time_t now)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;

    DEBUG(SSSDBG_TRACE_FUNC, ("Adding autofs map %s\n", autofsmapname));

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    if (!attrs) {
        attrs = sysdb_new_attrs(tmp_ctx);
        if (!attrs) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_OBJECTCLASS,
                                 SYSDB_AUTOFS_MAP_OC);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not set map object class [%d]: %s\n",
              ret, strerror(ret)));
        goto done;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_AUTOFS_MAP_NAME, autofsmapname);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not set map name [%d]: %s\n",
              ret, strerror(ret)));
        goto done;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_NAME, name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not set name attribute [%d]: %s\n",
              ret, strerror(ret)));
        goto done;
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_LAST_UPDATE, now);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not set sysdb lastUpdate [%d]: %s\n",
              ret, strerror(ret)));
        goto done;
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_CACHE_EXPIRE,
                                 ((cache_timeout) ?
                                  (now + cache_timeout) : 0));
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not set sysdb cache expire [%d]: %s\n",
              ret, strerror(ret)));
        goto done;
    }

    ret = sysdb_store_custom(sysdb_ctx, name, AUTOFS_MAP_SUBDIR, attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("sysdb_store_custom failed [%d]: %s\n",
              ret, strerror(ret)));
        goto done;
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_delete_autofsmap(struct sysdb_ctx *sysdb_ctx,
                       const char *name)
{
    DEBUG(SSSDBG_TRACE_FUNC, ("Deleting autofs map %s\n", name));
    return sysdb_delete_custom(sysdb_ctx, name, AUTOFS_MAP_SUBDIR);
}

errno_t
sysdb_get_map_byname(TALLOC_CTX *mem_ctx,
                     struct sysdb_ctx *sysdb,
                     const char *map_name,
                     struct ldb_message **_map)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    const char *filter;
    char *safe_map_name;
    size_t count;
    struct ldb_message **msgs;
    const char *attrs[] = { SYSDB_OBJECTCLASS,
                            SYSDB_CACHE_EXPIRE,
                            SYSDB_LAST_UPDATE,
                            SYSDB_AUTOFS_MAP_NAME,
                            SYSDB_MEMBER,
                            NULL };

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    ret = sss_filter_sanitize(tmp_ctx, map_name, &safe_map_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Cannot sanitize map [%s] error [%d]: %s\n",
               map_name, ret, strerror(ret)));
        goto done;
    }

    filter = talloc_asprintf(tmp_ctx, "(&(objectclass=%s)(%s=%s))",
                             SYSDB_AUTOFS_MAP_OC, SYSDB_NAME, safe_map_name);
    if (!filter) {
        ret = EOK;
        goto done;
    }

    ret = sysdb_search_custom(tmp_ctx, sysdb, filter,
                              AUTOFS_MAP_SUBDIR, attrs,
                              &count, &msgs);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Error looking up autofs map [%s]", safe_map_name));
        goto done;
    } else if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, ("No such map\n"));
        *_map = NULL;
        goto done;
    }

    if (count != 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("More than one map named %s\n", safe_map_name));
        goto done;
    }

    *_map = talloc_steal(mem_ctx, msgs[0]);
    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_save_autofsentry(struct sysdb_ctx *sysdb_ctx,
                       const char *map,
                       const char *key,
                       const char *value,
                       struct sysdb_attrs *attrs)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *msg;
    struct ldb_dn *dn;
    const char *name;

    DEBUG(SSSDBG_TRACE_FUNC,
          ("Adding autofs entry [%s] - [%s]\n", key, value));

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    if (!attrs) {
        attrs = sysdb_new_attrs(tmp_ctx);
        if (!attrs) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_OBJECTCLASS,
                                 SYSDB_AUTOFS_ENTRY_OC);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not set entry object class [%d]: %s\n",
              ret, strerror(ret)));
        goto done;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_AUTOFS_ENTRY_KEY, key);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not set entry key [%d]: %s\n",
              ret, strerror(ret)));
        goto done;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_AUTOFS_ENTRY_VALUE, value);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not set entry key [%d]: %s\n",
              ret, strerror(ret)));
        goto done;
    }

    name = talloc_asprintf(tmp_ctx, "%s%s", key, value);
    if (!name) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_NAME, name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not set name attribute [%d]: %s\n",
              ret, strerror(ret)));
        goto done;
    }

    dn = sysdb_autofsentry_dn(tmp_ctx, sysdb_ctx, map, key, value);
    if (!dn) {
        ret = ENOMEM;
        goto done;
    }

    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = dn;
    msg->elements = attrs->a;
    msg->num_elements = attrs->num;

    ret = ldb_add(sysdb_ctx->ldb, msg);
    ret = sysdb_error_to_errno(ret);
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_del_autofsentry(struct sysdb_ctx *sysdb_ctx,
                      const char *map,
                      const char *key,
                      const char *value)
{
    struct ldb_dn *dn;
    errno_t ret;

    dn = sysdb_autofsentry_dn(sysdb_ctx, sysdb_ctx, map, key, value);
    if (!dn) {
        return ENOMEM;
    }

    ret = sysdb_delete_entry(sysdb_ctx, dn, true);
    talloc_free(dn);
    return ret;
}

errno_t
sysdb_autofs_entries_by_map(TALLOC_CTX *mem_ctx,
                            struct sysdb_ctx *sysdb,
                            const char *mapname,
                            size_t *_count,
                            struct ldb_message ***_entries)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    char *filter;
    const char *attrs[] = { SYSDB_AUTOFS_ENTRY_KEY,
                            SYSDB_AUTOFS_ENTRY_VALUE,
                            NULL };
    size_t count;
    struct ldb_message **msgs;
    struct ldb_dn *mapdn;

    DEBUG(SSSDBG_TRACE_FUNC, ("Getting entries for map %s\n", mapname));

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    mapdn = sysdb_autofsmap_dn(tmp_ctx, sysdb, mapname);
    if (!mapdn) {
        ret = ENOMEM;
        goto done;
    }

    filter = talloc_asprintf(tmp_ctx, "(objectclass=%s)",
                             SYSDB_AUTOFS_ENTRY_OC);
    if (!filter) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_entry(tmp_ctx, sysdb, mapdn, LDB_SCOPE_ONELEVEL,
                             filter, attrs, &count, &msgs);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, ("sysdb search failed: %d\n", ret));
        goto done;
    } else if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, ("No entries for the map\n"));
        *_count = 0;
        *_entries = NULL;
        goto done;
    }

    *_count = count;
    *_entries = talloc_steal(mem_ctx, msgs);
    ret = EOK;
    DEBUG(SSSDBG_TRACE_INTERNAL, ("found %d entries for map %s\n",
                                   count, mapname));
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_set_autofsmap_attr(struct sysdb_ctx *sysdb,
                         const char *name,
                         struct sysdb_attrs *attrs,
                         int mod_op)
{
    errno_t ret;
    struct ldb_dn *dn;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    dn = sysdb_autofsmap_dn(tmp_ctx, sysdb, name);
    if (!dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_set_entry_attr(sysdb, dn, attrs, mod_op);

done:
    talloc_free(tmp_ctx);
    return ret;
}
