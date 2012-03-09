/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2011 Red Hat

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
#include <dhash.h>
#include <time.h>

#include "util/util.h"
#include "confdb/confdb.h"
#include "db/sysdb.h"
#include "responder/sudo/sudosrv_private.h"

static void sudosrv_cache_remove(struct tevent_context *ev,
                                 struct tevent_timer *te,
                                 struct timeval tv,
                                 void *pvt);

struct sudo_cache_entry {
    hash_table_t *table;
    hash_key_t *key;
    size_t num_rules;
    struct sysdb_attrs **rules;

    struct sudo_ctx *sudo_ctx;
};

errno_t sudosrv_cache_init(TALLOC_CTX *mem_ctx,
                           unsigned long count,
                           hash_table_t **table)
{
    return sss_hash_create(mem_ctx, count, table);
}

static errno_t
sudosrv_cache_reinit(struct sudo_ctx *sudo_ctx)
{
    errno_t ret;

    talloc_free(sudo_ctx->cache);

    ret = sudosrv_cache_init(sudo_ctx, 10, &sudo_ctx->cache);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
                ("Could not re-initialize hash table: [%s]", strerror(ret)));
    }
    return ret;
}

static hash_key_t *sudosrv_cache_create_key(TALLOC_CTX *mem_ctx,
                                            struct sss_domain_info *domain,
                                            const char *username)
{
    hash_key_t *key = talloc_zero(NULL, hash_key_t);
    if (key == NULL) {
        return NULL;
    }

    key->type = HASH_KEY_STRING;
    if (username == NULL) {
        key->str = talloc_strdup(key, domain->name);
    } else {
        key->str = talloc_asprintf(key, "%s:%s", domain->name, username);
    }

    if (key->str == NULL) {
        talloc_free(key);
        return NULL;
    }

    return talloc_steal(mem_ctx, key);
}

errno_t sudosrv_cache_set_entry(struct tevent_context *ev,
                                struct sudo_ctx *sudo_ctx,
                                hash_table_t *table,
                                struct sss_domain_info *domain,
                                const char *username,
                                size_t num_rules,
                                struct sysdb_attrs **rules,
                                time_t timeout)
{
    struct sudo_cache_entry *cache_entry = NULL;
    hash_key_t *key = NULL;
    hash_value_t value;
    TALLOC_CTX *tmp_ctx = NULL;
    struct tevent_timer *timer = NULL;
    struct timeval tv;
    errno_t ret;
    int hret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* create key */
    key = sudosrv_cache_create_key(tmp_ctx, domain, username);
    if (key == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Unable to create hash key.\n"));
        ret = ENOMEM;
        goto done;
    }

    /* create value */
    cache_entry = talloc_zero(tmp_ctx, struct sudo_cache_entry);
    if (cache_entry == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Unable to create hash value.\n"));
        ret = ENOMEM;
        goto done;
    }
    cache_entry->table = table;
    cache_entry->key = key;
    cache_entry->num_rules = num_rules;
    cache_entry->rules = rules;
    cache_entry->sudo_ctx = sudo_ctx;

    value.type = HASH_VALUE_PTR;
    value.ptr = cache_entry;

    /* insert value */
    hret = hash_enter(table, key, &value);
    if (hret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Unable to add [%s] to SUDO cache", key->str));
        DEBUG(SSSDBG_TRACE_LIBS,
              ("Hash error [%d][%s]", hret, hash_error_string(hret)));
        ret = EIO;
        goto done;
    }

    /* Create a timer event to remove the entry from the cache */
    tv = tevent_timeval_current_ofs(timeout, 0);
    timer = tevent_add_timer(ev, cache_entry, tv,
                             sudosrv_cache_remove,
                             cache_entry);
    if (timer == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* everythig is ok, steal the pointers */
    talloc_steal(cache_entry, key);
    talloc_steal(cache_entry, rules);
    talloc_steal(table, cache_entry);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static void free_cache_entry_cb(struct tevent_context *ev,
                                struct tevent_immediate *imm,
                                void *pvt)
{
    struct sudo_cache_entry *cache_entry =
        talloc_get_type(pvt, struct sudo_cache_entry);
    talloc_free(cache_entry);
}

static void sudosrv_cache_remove(struct tevent_context *ev,
                                 struct tevent_timer *te,
                                 struct timeval tv,
                                 void *pvt)
{
    int hret;
    hash_key_t *key;
    struct sudo_cache_entry *cache_entry;
    struct tevent_immediate *imm;

    cache_entry = talloc_get_type(pvt, struct sudo_cache_entry);
    key = cache_entry->key;

    hret = hash_delete(cache_entry->table, key);
    if (hret != HASH_SUCCESS && hret != HASH_ERROR_KEY_NOT_FOUND
        && hret != HASH_ERROR_BAD_KEY_TYPE) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Could not clear [%s] from SUDO cache.\n", key->str));
        DEBUG(SSSDBG_TRACE_LIBS,
               ("Hash error [%d][%s]", hret, hash_error_string(hret)));

        /* corrupted memory, re-initialize table */
        sudosrv_cache_reinit(cache_entry->sudo_ctx);
    } else {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              ("[%s] removed from SUDO cache\n", key->str));

        imm = tevent_create_immediate(ev);
        if (imm == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Out of memory\n"));
            return;
        }
        tevent_schedule_immediate(imm, ev, free_cache_entry_cb, cache_entry);
    }
}

static errno_t sudosrv_cache_lookup_internal(hash_table_t *table,
                                             struct sss_domain_info *domain,
                                             const char *username,
                                             size_t *num_rules,
                                             struct sysdb_attrs ***rules)
{
    struct sudo_cache_entry *cache_entry = NULL;
    hash_key_t *key = NULL;
    hash_value_t value;
    TALLOC_CTX *tmp_ctx = NULL;
    errno_t ret;
    int hret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* create key */
    key = sudosrv_cache_create_key(tmp_ctx, domain, username);
    if (key == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Unable to create hash key.\n"));
        ret = ENOMEM;
        goto done;
    }

    hret = hash_lookup(table, key, &value);
    if (hret == HASH_SUCCESS) {
        /* cache hit */
        cache_entry = value.ptr;
        *num_rules = cache_entry->num_rules;
        *rules = cache_entry->rules;
        ret = EOK;
    } else if (hret == HASH_ERROR_KEY_NOT_FOUND) {
        /* cache miss */
        ret = ENOENT;
    } else {
        /* error */
        ret = EIO;
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sudosrv_cache_lookup(hash_table_t *table,
                             struct sudo_dom_ctx *dctx,
                             bool check_next,
                             const char *username,
                             size_t *num_rules,
                             struct sysdb_attrs ***rules)
{
    struct sss_domain_info *domain = dctx->domain;
    char *name = NULL;
    errno_t ret;

    if (!check_next) {
        if (username != NULL) {
            name = sss_get_cased_name(NULL, username,
                                      dctx->domain->case_sensitive);
            if (name == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, ("Out of memory\n"));
                ret = ENOMEM;
                goto done;
            }
        }

        ret = sudosrv_cache_lookup_internal(table, dctx->domain, name,
                                            num_rules, rules);
        goto done;
    }

    while (domain != NULL) {
        if (domain->fqnames) {
            domain = domain->next;
            continue;
        }

        if (username != NULL) {
            talloc_free(name);
            name = sss_get_cased_name(NULL, username,
                                      dctx->domain->case_sensitive);
            if (name == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, ("Out of memory\n"));
                ret = ENOMEM;
                goto done;
            }
        }

        ret = sudosrv_cache_lookup_internal(table, domain, name,
                                            num_rules, rules);
        if (ret == EOK) {
            /* user is in this domain */
            dctx->domain = domain;
            goto done;
        } else if (ret != ENOENT) {
            /* error */
            goto done;
        }

        /* user is not in this domain cache, check next */
        domain = domain->next;
    }

    /* user is not in cache */
    ret = ENOENT;

done:
    talloc_free(name);
    return ret;
}
