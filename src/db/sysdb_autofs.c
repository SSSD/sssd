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

struct ldb_dn *
sysdb_autofsmap_dn(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *sysdb,
                   const char *map_name)
{
    return sysdb_custom_dn(sysdb, mem_ctx, sysdb->domain->name,
                           map_name, AUTOFS_MAP_SUBDIR);
}

struct ldb_dn *
sysdb_autofsentry_dn(TALLOC_CTX *mem_ctx,
                     struct sysdb_ctx *sysdb,
                     const char *entry_name)
{
    return sysdb_custom_dn(sysdb, mem_ctx, sysdb->domain->name,
                           entry_name, AUTOFS_ENTRY_SUBDIR);
}

static char *
sysdb_autofsmap_strdn(TALLOC_CTX *mem_ctx,
                      struct sysdb_ctx *sysdb,
                      const char *map_name)
{
    struct ldb_dn *dn;
    char *strdn;

    dn = sysdb_autofsmap_dn(mem_ctx, sysdb, map_name);
    if (!dn) return NULL;

    strdn = talloc_strdup(mem_ctx, ldb_dn_get_linearized(dn));
    talloc_free(dn);
    return strdn;
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
                       const char *key,
                       const char *value,
                       struct sysdb_attrs *attrs)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;

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

    ret = sysdb_attrs_add_string(attrs, SYSDB_NAME, key);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not set name attribute [%d]: %s\n",
              ret, strerror(ret)));
        goto done;
    }

    ret = sysdb_store_custom(sysdb_ctx, key, AUTOFS_ENTRY_SUBDIR, attrs);
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
    char *mapdn;

    DEBUG(SSSDBG_TRACE_FUNC, ("Getting entries for map %s\n", mapname));

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    mapdn = sysdb_autofsmap_strdn(tmp_ctx, sysdb, mapname);
    if (!mapdn) {
        ret = ENOMEM;
        goto done;
    }

    filter = talloc_asprintf(tmp_ctx, "(&(objectclass=%s)(%s=%s))",
                             SYSDB_AUTOFS_ENTRY_OC, SYSDB_MEMBEROF, mapdn);
    if (!filter) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_custom(tmp_ctx, sysdb, filter, AUTOFS_ENTRY_SUBDIR,
                              attrs, &count, &msgs);
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
sysdb_map_entry_name(TALLOC_CTX *mem_ctx, struct sysdb_ctx *sysdb,
                     const char *entry_dn, char **_name)
{
    return sysdb_get_rdn(sysdb, mem_ctx, entry_dn, NULL, _name);
}

errno_t
sysdb_autofs_map_update_members(struct sysdb_ctx *sysdb,
                                const char *mapname,
                                const char *const *add_entries,
                                const char *const *del_entries)
{
    errno_t ret, sret;
    int i;
    bool in_transaction = false;

    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    if(!tmp_ctx) {
        return ENOMEM;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Failed to start update transaction\n"));
        goto done;
    }

    in_transaction = true;

    if (add_entries) {
        /* Add the all te add_entries to the map */
        for (i = 0; add_entries[i]; i++) {
            ret = sysdb_add_group_member(sysdb, mapname, add_entries[i],
                                         SYSDB_MEMBER_AUTOFSENTRY);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      ("Could not add entry [%s] to map [%s]. "
                       "Skipping.\n", add_entries[i], mapname));
                /* Continue on, we should try to finish the rest */
            }
        }
    }

    if (del_entries) {
        /* Add the all te del_entries to the map */
        for (i = 0; del_entries[i]; i++) {
            ret = sysdb_remove_group_member(sysdb, mapname, del_entries[i],
                                            SYSDB_MEMBER_AUTOFSENTRY);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      ("Could not del entry [%s] to map [%s]. "
                       "Skipping.\n", del_entries[i], mapname));
                /* Continue on, we should try to finish the rest */
            }
        }
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to commit transaction\n"));
        goto done;
    }

    in_transaction = false;
    ret = EOK;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Could not cancel transaction\n"));
        }
    }
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
