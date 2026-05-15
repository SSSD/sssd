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
                   struct sss_domain_info *domain,
                   const char *map_name)
{
    return sysdb_custom_dn(mem_ctx, domain, map_name, AUTOFS_MAP_SUBDIR);
}

static struct ldb_dn *
sysdb_autofsentry_dn(TALLOC_CTX *mem_ctx,
                     struct sss_domain_info *domain,
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

    dn = ldb_dn_new_fmt(mem_ctx, domain->sysdb->ldb, SYSDB_TMPL_AUTOFS_ENTRY,
                        rdn, map_name, AUTOFS_MAP_SUBDIR, domain->name);

done:
    talloc_free(tmp_ctx);
    return dn;
}

char *
sysdb_autofsentry_strdn(TALLOC_CTX *mem_ctx,
                        struct sss_domain_info *domain,
                        const char *map_name,
                        const char *entry_name,
                        const char *entry_value)
{
    struct ldb_dn *dn;
    char *strdn;

    dn = sysdb_autofsentry_dn(mem_ctx, domain,
                              map_name, entry_name, entry_value);
    if (!dn) return NULL;

    strdn = talloc_strdup(mem_ctx, ldb_dn_get_linearized(dn));
    talloc_free(dn);
    return strdn;
}

errno_t
sysdb_save_autofsmap(struct sss_domain_info *domain,
                     const char *name,
                     const char *autofsmapname,
                     const char *origdn,
                     struct sysdb_attrs *attrs,
                     int cache_timeout,
                     time_t now,
                     bool enumerated)
{
    time_t expiration = cache_timeout ? now + cache_timeout : 0;
    errno_t ret;
    TALLOC_CTX *tmp_ctx;

    DEBUG(SSSDBG_TRACE_FUNC, "Adding autofs map %s\n", autofsmapname);

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
        DEBUG(SSSDBG_OP_FAILURE, "Could not set map object class [%d]: %s\n",
              ret, strerror(ret));
        goto done;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_AUTOFS_MAP_NAME, autofsmapname);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not set map name [%d]: %s\n",
              ret, strerror(ret));
        goto done;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_ORIG_DN, origdn);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not set origdn [%d]: %s\n",
              ret, strerror(ret));
        goto done;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_NAME, name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not set name attribute [%d]: %s\n",
              ret, strerror(ret));
        goto done;
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_LAST_UPDATE, now);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not set sysdb lastUpdate [%d]: %s\n",
              ret, strerror(ret));
        goto done;
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_CACHE_EXPIRE, expiration);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not set sysdb cache expire [%d]: %s\n",
              ret, strerror(ret));
        goto done;
    }

    if (enumerated) {
        ret = sysdb_attrs_add_time_t(attrs, SYSDB_ENUM_EXPIRE, expiration);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not set sysdb enum expire [%d]: %s\n",
                  ret, strerror(ret));
            goto done;
        }
    }

    ret = sysdb_store_custom(domain, name, AUTOFS_MAP_SUBDIR, attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_store_custom failed [%d]: %s\n",
              ret, strerror(ret));
        goto done;
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_delete_autofsmap(struct sss_domain_info *domain,
                       const char *name)
{
    DEBUG(SSSDBG_TRACE_FUNC, "Deleting autofs map %s\n", name);
    return sysdb_delete_custom(domain, name, AUTOFS_MAP_SUBDIR);
}

errno_t
sysdb_get_map_byname(TALLOC_CTX *mem_ctx,
                     struct sss_domain_info *domain,
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
                            SYSDB_ORIG_DN,
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
              "Cannot sanitize map [%s] error [%d]: %s\n",
               map_name, ret, strerror(ret));
        goto done;
    }

    filter = talloc_asprintf(tmp_ctx, "(&(objectclass=%s)(%s=%s))",
                             SYSDB_AUTOFS_MAP_OC, SYSDB_NAME, safe_map_name);
    if (!filter) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_custom(tmp_ctx, domain, filter,
                              AUTOFS_MAP_SUBDIR, attrs,
                              &count, &msgs);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Error looking up autofs map [%s]\n", safe_map_name);
        goto done;
    } else if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, "No such map [%s]\n", safe_map_name);
        *_map = NULL;
        goto done;
    }

    if (count != 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "More than one map named [%s]\n", safe_map_name);
        goto done;
    }

    *_map = talloc_steal(mem_ctx, msgs[0]);
    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_save_autofsentry(struct sss_domain_info *domain,
                       const char *map,
                       const char *key,
                       const char *value,
                       struct sysdb_attrs *attrs,
                       int cache_timeout,
                       time_t now)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *msg;
    struct ldb_dn *dn;
    const char *name;

    DEBUG(SSSDBG_TRACE_FUNC,
          "Adding autofs entry [%s] - [%s]\n", key, value);

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
        DEBUG(SSSDBG_OP_FAILURE, "Could not set entry object class [%d]: %s\n",
              ret, strerror(ret));
        goto done;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_AUTOFS_ENTRY_KEY, key);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not set entry key [%d]: %s\n",
              ret, strerror(ret));
        goto done;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_AUTOFS_ENTRY_VALUE, value);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not set entry key [%d]: %s\n",
              ret, strerror(ret));
        goto done;
    }

    name = talloc_asprintf(tmp_ctx, "%s%s", key, value);
    if (!name) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_NAME, name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not set name attribute [%d]: %s\n",
              ret, strerror(ret));
        goto done;
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_CACHE_EXPIRE,
                                 ((cache_timeout) ?
                                  (now + cache_timeout) : 0));
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not set sysdb cache expire [%d]: %s\n",
              ret, strerror(ret));
        goto done;
    }

    dn = sysdb_autofsentry_dn(tmp_ctx, domain, map, key, value);
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

    ret = ldb_add(domain->sysdb->ldb, msg);
    ret = sysdb_error_to_errno(ret);
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_get_autofsentry(TALLOC_CTX *mem_ctx,
                      struct sss_domain_info *domain,
                      const char *map_name,
                      const char *entry_name,
                      struct ldb_message **_entry)
{
    TALLOC_CTX *tmp_ctx;
    char *safe_entryname;
    char *filter;
    struct ldb_dn *mapdn;
    size_t count;
    struct ldb_message **msgs;
    errno_t ret;
    const char *attrs[] = { SYSDB_AUTOFS_ENTRY_KEY,
                            SYSDB_AUTOFS_ENTRY_VALUE,
                            SYSDB_CACHE_EXPIRE,
                            NULL };

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    ret = sss_filter_sanitize(tmp_ctx, entry_name, &safe_entryname);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot sanitize map [%s] error [%d]: %s\n",
               map_name, ret, strerror(ret));
        goto done;
    }

    filter = talloc_asprintf(tmp_ctx, "(&(objectclass=%s)(%s=%s))",
                             SYSDB_AUTOFS_ENTRY_OC, SYSDB_AUTOFS_ENTRY_KEY,
                             safe_entryname);
    if (filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    mapdn = sysdb_autofsmap_dn(tmp_ctx, domain, map_name);
    if (!mapdn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_entry(tmp_ctx, domain->sysdb, mapdn, LDB_SCOPE_SUBTREE,
                             filter, attrs, &count, &msgs);
    if (ret == ENOENT) {
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb search failed: %d\n", ret);
        goto done;
    }

    if (count != 1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "More than one entry %s:%s found\n",
              map_name, entry_name);
        ret = ERR_INTERNAL;
        goto done;
    }

    *_entry = talloc_steal(mem_ctx, msgs[0]);

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
sysdb_del_autofsentry(struct sss_domain_info *domain,
                      const char *entry_dn)
{
    struct ldb_dn *dn;
    errno_t ret;

    dn = ldb_dn_new(NULL, sysdb_ctx_get_ldb(domain->sysdb), entry_dn);
    if (!dn) {
        return ENOMEM;
    }

    ret = sysdb_delete_entry(domain->sysdb, dn, true);
    talloc_free(dn);
    return ret;
}

errno_t
sysdb_del_autofsentry_by_key(struct sss_domain_info *domain,
                             const char *map_name,
                             const char *entry_key)
{
    struct ldb_message *entry;
    errno_t ret;

    ret = sysdb_get_autofsentry(NULL, domain, map_name, entry_key, &entry);
    if (ret == ENOENT) {
        return EOK;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to get autofs entry [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    ret = sysdb_delete_entry(domain->sysdb, entry->dn, true);
    talloc_free(entry);
    return ret;
}

errno_t
sysdb_autofs_entries_by_map(TALLOC_CTX *mem_ctx,
                            struct sss_domain_info *domain,
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

    DEBUG(SSSDBG_TRACE_FUNC, "Getting entries for map %s\n", mapname);

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    mapdn = sysdb_autofsmap_dn(tmp_ctx, domain, mapname);
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

    ret = sysdb_search_entry(tmp_ctx, domain->sysdb, mapdn, LDB_SCOPE_SUBTREE,
                             filter, attrs, &count, &msgs);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb search failed: %d\n", ret);
        goto done;
    } else if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, "No entries for the map\n");
        *_count = 0;
        *_entries = NULL;
        goto done;
    }

    *_count = count;
    *_entries = talloc_steal(mem_ctx, msgs);
    ret = EOK;
    DEBUG(SSSDBG_TRACE_INTERNAL, "found %zu entries for map %s\n",
                                   count, mapname);
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_set_autofsentry_attr(struct sss_domain_info *domain,
                           const char *mapname,
                           const char *key,
                           const char *value,
                           struct sysdb_attrs *attrs,
                           int mod_op)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *dn;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    dn = sysdb_autofsentry_dn(tmp_ctx, domain, mapname, key, value);
    if (dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_set_entry_attr(domain->sysdb, dn, attrs, mod_op);

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_set_autofsmap_attr(struct sss_domain_info *domain,
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

    dn = sysdb_autofsmap_dn(tmp_ctx, domain, name);
    if (!dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_set_entry_attr(domain->sysdb, dn, attrs, mod_op);

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_invalidate_autofs_entries(struct sss_domain_info *domain,
                                const char *mapname)
{
    TALLOC_CTX *tmp_ctx;
    bool in_transaction = false;
    struct ldb_message **entries;
    struct sysdb_attrs *attrs;
    const char *value;
    const char *key;
    size_t count;
    errno_t ret;
    size_t i;
    int sret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    ret = sysdb_autofs_entries_by_map(tmp_ctx, domain, mapname,
                                      &count, &entries);
    if (ret == ENOENT) {
        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        goto done;
    }

    attrs = sysdb_new_attrs(tmp_ctx);
    if (attrs == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_CACHE_EXPIRE, 1);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_transaction_start(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto done;
    }
    in_transaction = true;

    for (i = 0; i < count; i++) {
        key = ldb_msg_find_attr_as_string(entries[i], SYSDB_AUTOFS_ENTRY_KEY,
                                          NULL);
        if (key == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE, "An entry with no key?\n");
            continue;
        }

        value = ldb_msg_find_attr_as_string(entries[i],
                                            SYSDB_AUTOFS_ENTRY_VALUE,
                                            NULL);
        if (value == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE, "An entry with no value?\n");
            continue;
        }

        ret = sysdb_set_autofsentry_attr(domain, mapname, key, value,
                                         attrs, SYSDB_MOD_REP);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Could not expire entry %s\n", key);
            continue;
        }
    }

    ret = sysdb_transaction_commit(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not commit transaction\n");
        goto done;
    }
    in_transaction = false;

    ret = EOK;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(domain->sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not cancel transaction\n");
        }
    }

    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_invalidate_autofs_maps(struct sss_domain_info *domain)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    const char *filter;
    struct sysdb_attrs *sys_attrs = NULL;
    const char *attrs[] = { SYSDB_OBJECTCLASS,
                            SYSDB_NAME,
                            SYSDB_CACHE_EXPIRE,
                            NULL };
    size_t count;
    struct ldb_message **msgs;
    const char *name;
    bool in_transaction = false;
    int sret;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    filter = talloc_asprintf(tmp_ctx, "(&(objectclass=%s)(%s=*))",
                             SYSDB_AUTOFS_MAP_OC, SYSDB_NAME);
    if (!filter) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_custom(tmp_ctx, domain, filter,
                              AUTOFS_MAP_SUBDIR, attrs,
                              &count, &msgs);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Error looking up autofs maps\n");
        goto done;
    } else if (ret == ENOENT) {
        ret = EOK;
        goto done;
    }

    sys_attrs = sysdb_new_attrs(tmp_ctx);
    if (!sys_attrs) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_add_time_t(sys_attrs, SYSDB_CACHE_EXPIRE, 1);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_attrs_add_time_t(sys_attrs, SYSDB_ENUM_EXPIRE, 1);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_transaction_start(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto done;
    }
    in_transaction = true;

    for (i = 0; i < count; i++) {
        name = ldb_msg_find_attr_as_string(msgs[i], SYSDB_NAME, NULL);
        if (!name) {
            DEBUG(SSSDBG_MINOR_FAILURE, "A map with no name?\n");
            continue;
        }

        ret = sysdb_set_autofsmap_attr(domain, name,
                                       sys_attrs, SYSDB_MOD_REP);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Could not expire map %s\n", name);
            continue;
        }

        ret =  sysdb_invalidate_autofs_entries(domain, name);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Could not expire map entries %s\n",
                  name);
            continue;
        }
    }

    ret = sysdb_transaction_commit(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not commit transaction\n");
        goto done;
    }
    in_transaction = false;

    ret = EOK;
done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(domain->sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not cancel transaction\n");
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}
