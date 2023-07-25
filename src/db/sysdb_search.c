/*
   SSSD

   System Database

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2008

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
#include "db/sysdb_private.h"
#include "confdb/confdb.h"
#include <time.h>
#include <ctype.h>


static inline bool is_sysdb_name(const char *attr)
{
    return (attr != NULL && strcmp(attr, SYSDB_NAME) == 0);
}

/* helpers */
static errno_t merge_ts_attr(struct ldb_message *ts_msg,
                             struct ldb_message *sysdb_msg,
                             const char *ts_attr,
                             const char *want_attrs[])
{
    errno_t ret;
    bool include = true;
    struct ldb_message_element *ts_el;
    struct ldb_message_element *sysdb_el;

    if (want_attrs != NULL) {
        /* Otherwise merge all ts attrs */
        include = string_in_list(ts_attr, discard_const(want_attrs), true);
    }
    if (include == false) {
        return EOK;
    }

    ts_el = ldb_msg_find_element(ts_msg, ts_attr);
    if (ts_el == NULL || ts_el->num_values == 0) {
        return EOK;
    }

    if (ts_el->num_values > 1) {
        return EIO;
    }

    sysdb_el = ldb_msg_find_element(sysdb_msg, ts_attr);
    if (sysdb_el == NULL || sysdb_el->num_values == 0) {
        ret = ldb_msg_add_steal_value(sysdb_msg, ts_attr, &ts_el->values[0]);
        if (ret != EOK) {
            return sysdb_error_to_errno(ret);
        }
    } else {
        /* Assumes the timestamps cache only holds single-valued
         * attributes */
        sysdb_el->values = talloc_steal(sysdb_el->values, ts_el->values);
    }

    return EOK;
}

static errno_t merge_all_ts_attrs(struct ldb_message *ts_msg,
                                  struct ldb_message *sysdb_msg,
                                  const char *want_attrs[])
{
    int ret;

    /* Deliberately start from 2 in order to not merge
     * objectclass/objectcategory and avoid breaking MPGs where the OC might
     * be made up
     */
    for (size_t c = 2; sysdb_ts_cache_attrs[c]; c++) {
        ret = merge_ts_attr(ts_msg, sysdb_msg,
                            sysdb_ts_cache_attrs[c], want_attrs);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Cannot merge ts attr %s\n", sysdb_ts_cache_attrs[c]);
            return ret;
        }
    }

    return EOK;
}

static errno_t merge_msg_ts_attrs(struct sysdb_ctx *sysdb,
                                  struct ldb_message *sysdb_msg,
                                  const char *attrs[])
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    size_t msgs_count;
    struct ldb_message **ts_msgs;
    bool ts_dn;

    ts_dn = is_ts_ldb_dn(sysdb_msg->dn);
    if (ts_dn == false) {
        return ERR_NO_TS;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_search_ts_entry(tmp_ctx, sysdb, sysdb_msg->dn,
                                LDB_SCOPE_BASE,
                                NULL,
                                sysdb_ts_cache_attrs,
                                &msgs_count,
                                &ts_msgs);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "No such DN in the timestamp cache: %s\n",
              ldb_dn_get_linearized(sysdb_msg->dn));
        ret = ERR_TS_CACHE_MISS;
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Cannot find TS cache entry for [%s]: [%d]: %s\n",
              ldb_dn_get_linearized(sysdb_msg->dn),
              ret, sss_strerror(ret));
        goto done;
    }

    if (msgs_count != 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Expected 1 result for base search, got %zu\n", msgs_count);
        return EIO;
    }

    ret = merge_all_ts_attrs(ts_msgs[0], sysdb_msg, attrs);
done:
    talloc_zfree(tmp_ctx);
    return ret;
}

static errno_t merge_msg_sysdb_attrs(TALLOC_CTX *mem_ctx,
                                     struct sysdb_ctx *sysdb,
                                     struct ldb_message *ts_msg,
                                     struct ldb_message **_sysdb_msg,
                                     const char *attrs[])
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    size_t msgs_count;
    struct ldb_message **sysdb_msgs;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_cache_search_entry(tmp_ctx, sysdb->ldb, ts_msg->dn, LDB_SCOPE_BASE,
                                   NULL, attrs, &msgs_count, &sysdb_msgs);
    if (ret != EOK) {
        goto done;
    }

    if (msgs_count != 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Expected 1 result for base search, got %zu\n", msgs_count);
        goto done;
    }

    ret = merge_all_ts_attrs(ts_msg, sysdb_msgs[0], attrs);
    if (ret != EOK) {
        goto done;
    }

    *_sysdb_msg = talloc_steal(mem_ctx, sysdb_msgs[0]);
done:
    talloc_zfree(tmp_ctx);
    return ret;
}

errno_t sysdb_merge_res_ts_attrs(struct sysdb_ctx *ctx,
                                 struct ldb_result *res,
                                 const char *attrs[])
{
    errno_t ret;

    if (res == NULL || ctx->ldb_ts == NULL) {
        return EOK;
    }

    for (size_t c = 0; c < res->count; c++) {
        ret = merge_msg_ts_attrs(ctx, res->msgs[c], attrs);
        if (ret == ERR_NO_TS) {
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "TS cache doesn't handle this DN type, skipping\n");
            continue;
        } else if (ret == ERR_TS_CACHE_MISS) {
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "TS cache doesn't contain this DN, skipping\n");
            continue;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Cannot merge timestamp cache values for %s\n",
                  ldb_dn_get_linearized(res->msgs[c]->dn));
            /* non-fatal */
            continue;
        }
    }

    return EOK;
}

static errno_t merge_res_sysdb_attrs(TALLOC_CTX *mem_ctx,
                                     struct sysdb_ctx *ctx,
                                     struct ldb_result *ts_res,
                                     struct ldb_result **_ts_cache_res,
                                     const char *attrs[])
{
    errno_t ret;
    size_t ts_cache_res_count = 0;
    struct ldb_result *ts_cache_res = NULL;

    if (ts_res == NULL || ctx->ldb_ts == NULL) {
        return EOK;
    }

    ts_cache_res = talloc_zero(mem_ctx, struct ldb_result);
    if (ts_cache_res == NULL) {
        return ENOMEM;
    }
    ts_cache_res->msgs = talloc_zero_array(ts_cache_res,
                                           struct ldb_message *,
                                           ts_res->count);
    if (ts_cache_res->msgs == NULL) {
        talloc_free(ts_cache_res);
        return ENOMEM;
    }

    for (size_t c = 0; c < ts_res->count; c++) {
        ret = merge_msg_sysdb_attrs(ts_cache_res->msgs,
                                    ctx,
                                    ts_res->msgs[c],
                                    &ts_cache_res->msgs[ts_cache_res_count],
                                    attrs);
        if ((ret != EOK) || (ts_cache_res->msgs[ts_cache_res_count] == NULL)) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Cannot merge sysdb cache values for %s\n",
                  ldb_dn_get_linearized(ts_res->msgs[c]->dn));
            /* non-fatal, just skip */
            continue;
        }
        ts_cache_res_count += 1;
    }
    ts_cache_res->count = ts_cache_res_count;

    *_ts_cache_res = ts_cache_res;
    return EOK;
}

errno_t sysdb_merge_msg_list_ts_attrs(struct sysdb_ctx *ctx,
                                      size_t msgs_count,
                                      struct ldb_message **msgs,
                                      const char *attrs[])
{
    struct ldb_result res;

    res.count = msgs_count;
    res.msgs = msgs;
    return sysdb_merge_res_ts_attrs(ctx, &res, attrs);
}

/* users */

int sysdb_getpwnam(TALLOC_CTX *mem_ctx,
                   struct sss_domain_info *domain,
                   const char *name,
                   struct ldb_result **_res)
{
    TALLOC_CTX *tmp_ctx;
    static const char *attrs[] = SYSDB_PW_ATTRS;
    struct ldb_dn *base_dn;
    struct ldb_result *res;
    char *sanitized_name;
    char *lc_sanitized_name;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    base_dn = sysdb_user_base_dn(tmp_ctx, domain);
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_filter_sanitize_for_dom(tmp_ctx, name, domain,
                                      &sanitized_name, &lc_sanitized_name);
    if (ret != EOK) {
        goto done;
    }

    ret = ldb_search(domain->sysdb->ldb, tmp_ctx, &res, base_dn,
                     LDB_SCOPE_SUBTREE, attrs, SYSDB_PWNAM_FILTER,
                     lc_sanitized_name,
                     sanitized_name, sanitized_name);
    if (ret) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    if (res->count > 1) {
        /* We expected either 0 or 1 result for search with
         * SYSDB_PWNAM_FILTER, but we got more. This error
         * is handled individually depending on what function
         * called sysdb_getpwnam, so we just print a message
         * here and let the caller decide what error code to
         * propagate based on res->count > 1. */
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Search for [%s] returned multiple results. It can be an email "
              "address shared among multiple users or an email address of a "
              "user that conflicts with another user's fully qualified name. "
              "SSSD will not be able to handle those users properly.\n",
              sanitized_name);
    }

    /* Merge in the timestamps from the fast ts db */
    ret = sysdb_merge_res_ts_attrs(domain->sysdb, res, attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Cannot merge timestamp cache values\n");
        /* non-fatal */
        ret = EOK;
    }

    *_res = talloc_steal(mem_ctx, res);

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

errno_t sysdb_getpwnam_with_views(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *domain,
                                  const char *name,
                                  struct ldb_result **res)
{
    int ret;
    struct ldb_result *orig_obj = NULL;
    struct ldb_result *override_obj = NULL;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    /* If there are views we first have to search the overrides for matches */
    if (DOM_HAS_VIEWS(domain)) {
        ret = sysdb_search_user_override_by_name(tmp_ctx, domain, name,
                                                 &override_obj, &orig_obj);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sysdb_search_override_by_name failed.\n");
            goto done;
        }
    }

    /* If there are no views or nothing was found in the overrides the
     * original objects are searched. */
    if (orig_obj == NULL) {
        ret = sysdb_getpwnam(tmp_ctx, domain, name, &orig_obj);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_getpwnam failed.\n");
            goto done;
        }
    }

    /* If there are views we have to check if override values must be added to
     * the original object. */
    if (DOM_HAS_VIEWS(domain) && orig_obj->count == 1) {
        ret = sysdb_add_overrides_to_object(domain, orig_obj->msgs[0],
                          override_obj == NULL ? NULL : override_obj->msgs[0],
                          NULL);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_add_overrides_to_object failed.\n");
            goto done;
        }

        if (ret == ENOENT) {
            *res = talloc_zero(mem_ctx, struct ldb_result);
            if (*res == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
                ret = ENOMEM;
            } else {
                ret = EOK;
            }
            goto done;
        }
    }

    *res = talloc_steal(mem_ctx, orig_obj);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_getpwuid(TALLOC_CTX *mem_ctx,
                   struct sss_domain_info *domain,
                   uid_t uid,
                   struct ldb_result **_res)
{
    TALLOC_CTX *tmp_ctx;
    unsigned long int ul_uid = uid;
    static const char *attrs[] = SYSDB_PW_ATTRS;
    struct ldb_dn *base_dn;
    struct ldb_result *res;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    base_dn = sysdb_user_base_dn(tmp_ctx, domain);
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_search(domain->sysdb->ldb, tmp_ctx, &res, base_dn,
                     LDB_SCOPE_SUBTREE, attrs, SYSDB_PWUID_FILTER, ul_uid);
    if (ret) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* Merge in the timestamps from the fast ts db */
    ret = sysdb_merge_res_ts_attrs(domain->sysdb, res, attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Cannot merge timestamp cache values\n");
        /* non-fatal */
        ret = EOK;
    }

    *_res = talloc_steal(mem_ctx, res);

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

errno_t sysdb_getpwuid_with_views(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *domain,
                                  uid_t uid,
                                  struct ldb_result **res)
{
    int ret;
    struct ldb_result *orig_obj = NULL;
    struct ldb_result *override_obj = NULL;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    /* If there are views we first have to search the overrides for matches */
    if (DOM_HAS_VIEWS(domain)) {
        ret = sysdb_search_user_override_by_uid(tmp_ctx, domain, uid,
                                                &override_obj, &orig_obj);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sysdb_search_user_override_by_uid failed.\n");
            goto done;
        }
    }

    /* If there are no views or nothing was found in the overrides the
     * original objects are searched. */
    if (orig_obj == NULL) {
        ret = sysdb_getpwuid(tmp_ctx, domain, uid, &orig_obj);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_getpwuid failed.\n");
            goto done;
        }
    }

    /* If there are views we have to check if override values must be added to
     * the original object. */
    if (DOM_HAS_VIEWS(domain) && orig_obj->count == 1) {
        ret = sysdb_add_overrides_to_object(domain, orig_obj->msgs[0],
                           override_obj == NULL ? NULL : override_obj->msgs[0],
                           NULL);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_add_overrides_to_object failed.\n");
            goto done;
        }

        if (ret == ENOENT) {
            *res = talloc_zero(mem_ctx, struct ldb_result);
            if (*res == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
                ret = ENOMEM;
            } else {
                ret = EOK;
            }
            goto done;
        }
    }

    *res = talloc_steal(mem_ctx, orig_obj);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static char *filter_attribute(TALLOC_CTX *mem_ctx,
                              const char *attr,
                              const char *attr_filter,
                              const char *domain,
                              char *filter)
{
    char *new_filter = NULL;
    const char *value;

    if (filter == NULL) {
        return NULL;
    }

    if (domain != NULL && is_sysdb_name(attr)) {
        value = sss_create_internal_fqname(mem_ctx, attr_filter, domain);
    } else {
        value = attr_filter;
    }

    if (value != NULL) {
        new_filter = talloc_asprintf_append(filter, "(%s=%s)", attr, value);
    }

    return new_filter;
}

static char *enum_filter(TALLOC_CTX *mem_ctx,
                         const char *base_filter,
                         const char *attr,
                         const char *attr_filter,
                         const char *domain,
                         const char *addtl_filter)
{
    char *filter;
    TALLOC_CTX *tmp_ctx = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return NULL;
    }

    if ((attr == NULL || attr_filter == NULL) && addtl_filter == NULL) {
        filter = talloc_strdup(tmp_ctx, base_filter);
    } else {
        filter = talloc_asprintf(tmp_ctx, "(&%s", base_filter);

        if (filter != NULL && attr != NULL && attr_filter != NULL) {
            filter = filter_attribute(tmp_ctx, attr, attr_filter, domain, filter);
        }

        if (filter != NULL && addtl_filter != NULL) {
            filter = talloc_asprintf_append(filter, "%s", addtl_filter);
        }

        if (filter != NULL) {
            filter = talloc_asprintf_append(filter, ")");
        }
    }

    if (filter) {
        talloc_steal(mem_ctx, filter);
    }

    talloc_free(tmp_ctx);
    return filter;
}

int sysdb_getpwupn(TALLOC_CTX *mem_ctx,
                   struct sss_domain_info *domain,
                   bool domain_scope,
                   const char *upn,
                   struct ldb_result **_res)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    static const char *attrs[] = SYSDB_PW_ATTRS;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    ret = sysdb_search_user_by_upn_res(tmp_ctx, domain, domain_scope, upn, attrs, &res);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_search_user_by_upn_res() failed.\n");
        goto done;
    }

    *_res = talloc_steal(mem_ctx, res);

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_search_ts_matches(TALLOC_CTX *mem_ctx,
                                struct sysdb_ctx *sysdb,
                                const char *attrs[],
                                struct ldb_result *ts_res,
                                const char *filter,
                                struct ldb_result **_res)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct ldb_result *res;
    errno_t ret;

    if (ts_res->count == 0) {
        *_res = NULL;
        ret = EOK;
        goto done;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    res = talloc_zero(tmp_ctx, struct ldb_result);
    if (res == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_search(sysdb->ldb, tmp_ctx, &res, NULL,
                     LDB_SCOPE_SUBTREE, attrs, "%s", filter);
    if (ret) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    *_res = talloc_steal(mem_ctx, res);
    ret = EOK;

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

errno_t sysdb_search_with_ts_attr(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *domain,
                                  struct ldb_dn *base_dn,
                                  enum ldb_scope scope,
                                  enum sysdb_cache_type search_cache,
                                  const char *filter,
                                  const char *attrs[],
                                  struct ldb_result **_res)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct ldb_result *res;
    errno_t ret;
    struct ldb_message **ts_msgs = NULL;
    struct ldb_result *ts_cache_res = NULL;
    size_t ts_count;

    if (filter == NULL) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    res = talloc_zero(tmp_ctx, struct ldb_result);
    if (res == NULL) {
        ret = ENOMEM;
        goto done;
    }

    switch (search_cache) {
    case SYSDB_CACHE_TYPE_PERSISTENT: {
        /* We only care about searching the persistent db */
        ts_cache_res = talloc_zero(tmp_ctx, struct ldb_result);
        if (ts_cache_res == NULL) {
            ret = ENOMEM;
            goto done;
        }
        ts_cache_res->count = 0;
        ts_cache_res->msgs = NULL;

        break;
    }

    case SYSDB_CACHE_TYPE_TIMESTAMP:
        /* FALLTHOUGH*/
        SSS_ATTRIBUTE_FALLTHROUGH;
    default: {
        /* Because the timestamp database does not contain all the
         * attributes, we need to search the persistent db for each
         * of the entries found and merge the results
         */
        struct ldb_result ts_res;

        /* We assume that some of the attributes are more up-to-date in
         * timestamps db and we're supposed to search by them, so let's
         * first search the timestamp db
         */
        ret = sysdb_search_ts_entry(tmp_ctx, domain->sysdb, base_dn,
                                    scope, filter, attrs,
                                    &ts_count, &ts_msgs);
        if (ret == ENOENT) {
            ts_count = 0;
        } else if (ret != EOK) {
            goto done;
        }

        memset(&ts_res, 0, sizeof(struct ldb_result));
        ts_res.count = ts_count;
        ts_res.msgs = ts_msgs;

        /* Overlay the results from the main cache with the ts attrs */
        ret = merge_res_sysdb_attrs(tmp_ctx,
                                    domain->sysdb,
                                    &ts_res,
                                    &ts_cache_res,
                                    attrs);
        if (ret != EOK) {
            goto done;
        }

        break;
    }
    }

    switch (search_cache) {
    case SYSDB_CACHE_TYPE_TIMESTAMP: {
        /* The filter only contains timestamp attrs, no need to search the
         * persistent db
         */
        if (ts_cache_res) {
            res->count = ts_cache_res->count;
            res->msgs = talloc_steal(res, ts_cache_res->msgs);
        }

        break;
    }

    case SYSDB_CACHE_TYPE_PERSISTENT:
        /* FALLTHOUGH*/
        SSS_ATTRIBUTE_FALLTHROUGH;
    default: {
        /* Because some of the attributes being searched might exist in the persistent
         * database only, we also search the persistent db
         */
        size_t count;

        ret = sysdb_search_entry(res, domain->sysdb, base_dn, scope,
                                 filter, attrs, &count, &res->msgs);
        if (ret == ENOENT) {
            res->count = 0;
        } else if (ret != EOK) {
            goto done;
        }
        res->count = count; /* Just to cleanly assign size_t to unsigned */

        res = sss_merge_ldb_results(res, ts_cache_res);
        if (res == NULL) {
            ret = ENOMEM;
            goto done;
        }

        break;
    }
    }

    *_res = talloc_steal(mem_ctx, res);
    ret = EOK;

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

static errno_t sysdb_enum_dn_filter(TALLOC_CTX *mem_ctx,
                                    struct ldb_result *ts_res,
                                    const char *name_filter,
                                    const char *domain,
                                    char **_dn_filter)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *dn_filter;
    const char *fqname;
    errno_t ret;

    if (ts_res->count == 0) {
        *_dn_filter = NULL;
        ret = EOK;
        goto done;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    if (name_filter == NULL) {
        dn_filter = talloc_asprintf(tmp_ctx, "(|");
    } else {
        fqname = sss_create_internal_fqname(tmp_ctx, name_filter, domain);
        if (fqname == NULL) {
            ret = ENOMEM;
            goto done;
        }
        dn_filter = talloc_asprintf(tmp_ctx, "(&(%s=%s)(|", SYSDB_NAME, fqname);
    }
    if (dn_filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (size_t i = 0; i < ts_res->count; i++) {
        dn_filter = talloc_asprintf_append(
                                  dn_filter,
                                  "(%s=%s)",
                                  SYSDB_DN,
                                  ldb_dn_get_linearized(ts_res->msgs[i]->dn));
        if (dn_filter == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    dn_filter = talloc_asprintf_append(dn_filter, (name_filter == NULL ? ")" : "))"));
    if (dn_filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    *_dn_filter = talloc_steal(mem_ctx, dn_filter);
    ret = EOK;

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

int sysdb_enumpwent_filter(TALLOC_CTX *mem_ctx,
                           struct sss_domain_info *domain,
                           const char *attr,
                           const char *attr_filter,
                           const char *addtl_filter,
                           struct ldb_result **_res)
{
    TALLOC_CTX *tmp_ctx;
    static const char *attrs[] = SYSDB_PW_ATTRS;
    char *filter = NULL;
    char *dn_filter = NULL;
    const char *ts_filter = NULL;
    struct ldb_dn *base_dn;
    struct ldb_result *res;
    struct ldb_result ts_res;
    struct ldb_result *ts_cache_res = NULL;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    base_dn = sysdb_user_base_dn(tmp_ctx, domain);
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    /* Do not look for the user's attribute in the timestamp db as it could
     * not be present. Only look for the name. */
    if (attr == NULL || is_sysdb_name(attr)) {
        ts_filter = enum_filter(tmp_ctx, SYSDB_PWENT_FILTER,
                                NULL, NULL, NULL, addtl_filter);
        if (ts_filter == NULL) {
            ret = ENOMEM;
            goto done;
        }
        DEBUG(SSSDBG_TRACE_LIBS, "Searching timestamp cache with [%s]\n",
              ts_filter);

        ret = sysdb_search_ts_users(tmp_ctx, domain, ts_filter,
                                    sysdb_ts_cache_attrs,
                                    &ts_res);
        if (ret == ERR_NO_TS) {
            ret = ENOENT;
        }

        if (ret != EOK && ret != ENOENT) {
            goto done;
        }

        ret = sysdb_enum_dn_filter(tmp_ctx, &ts_res, attr_filter, domain->name,
                                   &dn_filter);
        if (ret != EOK) {
            goto done;
        }

        DEBUG(SSSDBG_TRACE_LIBS, "Searching timestamp entries with [%s]\n",
              dn_filter);

        ret = sysdb_search_ts_matches(tmp_ctx, domain->sysdb, attrs, &ts_res,
                                      dn_filter, &ts_cache_res);
        if (ret != EOK && ret != ENOENT) {
            goto done;
        }
    }

    filter = enum_filter(tmp_ctx, SYSDB_PWENT_FILTER,
                         attr, attr_filter, domain->name, addtl_filter);
    if (filter == NULL) {
        ret = ENOMEM;
        goto done;
    }
    DEBUG(SSSDBG_TRACE_LIBS, "Searching cache with [%s]\n", filter);

    ret = ldb_search(domain->sysdb->ldb, tmp_ctx, &res, base_dn,
                     LDB_SCOPE_SUBTREE, attrs, "%s", filter);
    if (ret) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* Merge in the timestamps from the fast ts db */
    ret = sysdb_merge_res_ts_attrs(domain->sysdb, res, attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Cannot merge timestamp cache values\n");
        /* non-fatal */
        ret = EOK;
    }

    if (ts_cache_res != NULL) {
        res = sss_merge_ldb_results(res, ts_cache_res);
        if (res == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    *_res = talloc_steal(mem_ctx, res);

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

int sysdb_enumpwent(TALLOC_CTX *mem_ctx,
                    struct sss_domain_info *domain,
                    struct ldb_result **_res)
{
    return sysdb_enumpwent_filter(mem_ctx, domain, NULL, NULL, NULL, _res);
}

int sysdb_enumpwent_filter_with_views(TALLOC_CTX *mem_ctx,
                                      struct sss_domain_info *domain,
                                      const char *attr,
                                      const char *attr_filter,
                                      const char *addtl_filter,
                                      struct ldb_result **_res)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    size_t c;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    ret = sysdb_enumpwent_filter(tmp_ctx, domain, attr, attr_filter,
                                 addtl_filter, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_enumpwent failed.\n");
        goto done;
    }

    if (DOM_HAS_VIEWS(domain)) {
        for (c = 0; c < res->count; c++) {
            ret = sysdb_add_overrides_to_object(domain, res->msgs[c], NULL,
                                                NULL);
            /* enumeration assumes that the cache is up-to-date, hence we do not
             * need to handle ENOENT separately. */
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_add_overrides_to_object failed.\n");
                goto done;
            }
        }
    }

    *_res = talloc_steal(mem_ctx, res);

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

int sysdb_enumpwent_with_views(TALLOC_CTX *mem_ctx,
                               struct sss_domain_info *domain,
                               struct ldb_result **_res)
{
    return sysdb_enumpwent_filter_with_views(mem_ctx, domain, NULL, NULL, NULL, _res);
}

/* groups */

static int mpg_convert(struct ldb_message *msg)
{
    struct ldb_message_element *el;
    struct ldb_val *val = NULL;
    int i;

    el = ldb_msg_find_element(msg, SYSDB_OBJECTCATEGORY);
    if (!el) return EINVAL;

    /* see if this is a user to convert to a group */
    for (i = 0; i < el->num_values; i++) {
        val = &(el->values[i]);
        if (strncasecmp(SYSDB_USER_CLASS,
                        (char *)val->data, val->length) == 0) {
            break;
        }
    }
    /* no, leave as is */
    if (i == el->num_values) return EOK;

    /* yes, convert */
    val->data = (uint8_t *)talloc_strdup(msg, SYSDB_GROUP_CLASS);
    if (val->data == NULL) return ENOMEM;
    val->length = strlen(SYSDB_GROUP_CLASS);

    return EOK;
}

static int mpg_res_convert(struct ldb_result *res)
{
    int ret;
    int i;

    for (i = 0; i < res->count; i++) {
        ret = mpg_convert(res->msgs[i]);
        if (ret) {
            return ret;
        }
    }
    return EOK;
}

int sysdb_getgrnam_with_views(TALLOC_CTX *mem_ctx,
                              struct sss_domain_info *domain,
                              const char *name,
                              struct ldb_result **res)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_result *orig_obj = NULL;
    struct ldb_result *override_obj = NULL;
    struct ldb_message_element *el;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    /* If there are views we first have to search the overrides for matches */
    if (DOM_HAS_VIEWS(domain)) {
        ret = sysdb_search_group_override_by_name(tmp_ctx, domain, name,
                                                  &override_obj, &orig_obj);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sysdb_search_group_override_by_name failed.\n");
            goto done;
        }
    }

    /* If there are no views or nothing was found in the overrides the
     * original objects are searched. */
    if (orig_obj == NULL) {
        ret = sysdb_getgrnam(tmp_ctx, domain, name, &orig_obj);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_getgrnam failed.\n");
            goto done;
        }
    }

    /* If there are views we have to check if override values must be added to
     * the original object. */
    if (orig_obj->count == 1) {
        if (DOM_HAS_VIEWS(domain)) {
            if (!is_local_view(domain->view_name)) {
                el = ldb_msg_find_element(orig_obj->msgs[0], SYSDB_GHOST);
                if (el != NULL && el->num_values != 0) {
                    DEBUG(SSSDBG_TRACE_ALL, "Group object [%s], contains ghost "
                          "entries which must be resolved before overrides can be "
                          "applied.\n",
                          ldb_dn_get_linearized(orig_obj->msgs[0]->dn));
                    ret = ENOENT;
                    goto done;
                }
            }

            ret = sysdb_add_overrides_to_object(domain, orig_obj->msgs[0],
                           override_obj == NULL ? NULL : override_obj ->msgs[0],
                           NULL);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_add_overrides_to_object failed.\n");
                goto done;
            }
        }

        /* Must be called even without views to check to
         * SYSDB_DEFAULT_OVERRIDE_NAME */
        ret = sysdb_add_group_member_overrides(domain, orig_obj->msgs[0],
                                               DOM_HAS_VIEWS(domain));
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sysdb_add_group_member_overrides failed.\n");
            goto done;
        }
    }

    *res = talloc_steal(mem_ctx, orig_obj);
    ret = EOK;

done:
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_ALL, "Returning empty result.\n");
        *res = talloc_zero(mem_ctx, struct ldb_result);
        if (*res == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
            ret = ENOMEM;
        } else {
            ret = EOK;
        }
    }

    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_getgrnam(TALLOC_CTX *mem_ctx,
                   struct sss_domain_info *domain,
                   const char *name,
                   struct ldb_result **_res)
{
    TALLOC_CTX *tmp_ctx;
    static const char *attrs[] = SYSDB_GRSRC_ATTRS;
    const char *fmt_filter;
    char *sanitized_name;
    struct ldb_dn *base_dn;
    struct ldb_result *res = NULL;
    char *lc_sanitized_name;
    const char *originalad_sanitized_name;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = sss_filter_sanitize_for_dom(tmp_ctx, name, domain,
                                      &sanitized_name, &lc_sanitized_name);
    if (ret != EOK) {
        goto done;
    }

    if (sss_domain_is_mpg(domain)) {
        /* In case the domain supports magic private groups we *must*
         * check whether the searched name is the very same as the
         * originalADname attribute.
         *
         * In case those are not the same, we're dealing with an
         * override and in order to return the proper overridden group
         * we must use the very same search used by a non-mpg domain
         */
        fmt_filter = SYSDB_GRNAM_MPG_FILTER;
        base_dn = sysdb_domain_dn(tmp_ctx, domain);
        if (base_dn == NULL) {
            ret = ENOMEM;
            goto done;
        }

        ret = ldb_search(domain->sysdb->ldb, tmp_ctx, &res, base_dn,
                         LDB_SCOPE_SUBTREE, attrs, fmt_filter,
                         lc_sanitized_name, sanitized_name, sanitized_name);
        if (ret != EOK) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        if (res->count > 0) {
            originalad_sanitized_name = ldb_msg_find_attr_as_string(
                    res->msgs[0], ORIGINALAD_PREFIX SYSDB_NAME, NULL);

            if (originalad_sanitized_name != NULL
                    && !sss_string_equal(domain->case_sensitive,
                                         originalad_sanitized_name,
                                         sanitized_name)) {
                fmt_filter = SYSDB_GRNAM_FILTER;
                base_dn = sysdb_group_base_dn(tmp_ctx, domain);
                res = NULL;
            }
        }
    } else {
        fmt_filter = SYSDB_GRNAM_FILTER;
        base_dn = sysdb_group_base_dn(tmp_ctx, domain);
    }
    if (base_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* We just do the ldb_search here in case domain is *not* a MPG *or*
     * it's a MPG and we're dealing with a overridden group, which has to
     * use the very same filter as a non MPG domain. */
    if (res == NULL) {
        ret = ldb_search(domain->sysdb->ldb, tmp_ctx, &res, base_dn,
                         LDB_SCOPE_SUBTREE, attrs, fmt_filter,
                         lc_sanitized_name, sanitized_name, sanitized_name);
        if (ret != EOK) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    ret = mpg_res_convert(res);
    if (ret) {
        goto done;
    }

    ret = sysdb_merge_res_ts_attrs(domain->sysdb, res, attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Cannot merge timestamp cache values\n");
        /* non-fatal */
    }

    *_res = talloc_steal(mem_ctx, res);

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

int sysdb_getgrgid_with_views(TALLOC_CTX *mem_ctx,
                              struct sss_domain_info *domain,
                              gid_t gid,
                              struct ldb_result **res)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_result *orig_obj = NULL;
    struct ldb_result *override_obj = NULL;
    struct ldb_message_element *el;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    /* If there are views we first have to search the overrides for matches */
    if (DOM_HAS_VIEWS(domain)) {
        ret = sysdb_search_group_override_by_gid(tmp_ctx, domain, gid,
                                                 &override_obj, &orig_obj);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sysdb_search_group_override_by_gid failed.\n");
            goto done;
        }
    }

    /* If there are no views or nothing was found in the overrides the
     * original objects are searched. */
    if (orig_obj == NULL) {
        ret = sysdb_getgrgid(tmp_ctx, domain, gid, &orig_obj);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_getgrgid failed.\n");
            goto done;
        }
    }

    /* If there are views we have to check if override values must be added to
     * the original object. */
    if (orig_obj->count == 1) {
        if (DOM_HAS_VIEWS(domain)) {
            if (!is_local_view(domain->view_name)) {
                el = ldb_msg_find_element(orig_obj->msgs[0], SYSDB_GHOST);
                if (el != NULL && el->num_values != 0) {
                    DEBUG(SSSDBG_TRACE_ALL, "Group object [%s], contains ghost "
                          "entries which must be resolved before overrides can be "
                          "applied.\n",
                          ldb_dn_get_linearized(orig_obj->msgs[0]->dn));
                    ret = ENOENT;
                    goto done;
                }
            }

            ret = sysdb_add_overrides_to_object(domain, orig_obj->msgs[0],
                              override_obj == NULL ? NULL : override_obj ->msgs[0],
                              NULL);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_add_overrides_to_object failed.\n");
                goto done;
            }
        }

        /* Must be called even without views to check to
         * SYSDB_DEFAULT_OVERRIDE_NAME */
        ret = sysdb_add_group_member_overrides(domain, orig_obj->msgs[0],
                                               DOM_HAS_VIEWS(domain));
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sysdb_add_group_member_overrides failed.\n");
            goto done;
        }
    }

    *res = talloc_steal(mem_ctx, orig_obj);
    ret = EOK;

done:
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_ALL, "Returning empty result.\n");
        *res = talloc_zero(mem_ctx, struct ldb_result);
        if (*res == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
            ret = ENOMEM;
        } else {
            ret = EOK;
        }
    }

    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_getgrgid_attrs(TALLOC_CTX *mem_ctx,
                         struct sss_domain_info *domain,
                         gid_t gid,
                         const char **additional_attrs,
                         struct ldb_result **_res)
{
    TALLOC_CTX *tmp_ctx;
    unsigned long int ul_gid = gid;
    unsigned long int ul_originalad_gid;
    const char *fmt_filter;
    struct ldb_dn *base_dn;
    struct ldb_result *res = NULL;
    int ret;
    static const char *default_attrs[] = SYSDB_GRSRC_ATTRS;
    const char **attrs = NULL;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    if (additional_attrs == NULL) {
        attrs = default_attrs;
    } else {
        ret = add_strings_lists(tmp_ctx, additional_attrs, default_attrs,
                                false, discard_const(&attrs));
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "add_strings_lists failed.\n");
            goto done;
        }
    }

    if (sss_domain_is_mpg(domain)) {
        /* In case the domain supports magic private groups we *must*
         * check whether the searched gid is the very same as the
         * originalADgidNumber attribute.
         *
         * In case those are not the same, we're dealing with an
         * override and in order to return the proper overridden group
         * we must use the very same search used by a non-mpg domain
         */
        fmt_filter = SYSDB_GRGID_MPG_FILTER;
        base_dn = sysdb_domain_dn(tmp_ctx, domain);
        if (base_dn == NULL) {
            ret = ENOMEM;
            goto done;
        }

        ret = ldb_search(domain->sysdb->ldb, tmp_ctx, &res, base_dn,
                         LDB_SCOPE_SUBTREE, attrs, fmt_filter, ul_gid, ul_gid, ul_gid);
        if (ret != EOK) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        if (res->count > 0) {
            ul_originalad_gid = ldb_msg_find_attr_as_uint64(
                    res->msgs[0], ORIGINALAD_PREFIX SYSDB_GIDNUM, 0);

            if (ul_originalad_gid != 0 && ul_originalad_gid != ul_gid) {
                fmt_filter = SYSDB_GRGID_FILTER;
                base_dn = sysdb_group_base_dn(tmp_ctx, domain);
                res = NULL;
            }
        }
    } else {
        fmt_filter = SYSDB_GRGID_FILTER;
        base_dn = sysdb_group_base_dn(tmp_ctx, domain);
    }
    if (base_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* We just do the ldb_search here in case domain is *not* a MPG *or*
     * it's a MPG and we're dealing with a overridden group, which has to
     * use the very same filter as a non MPG domain. */
    if (res == NULL) {
        ret = ldb_search(domain->sysdb->ldb, tmp_ctx, &res, base_dn,
                         LDB_SCOPE_SUBTREE, attrs, fmt_filter, ul_gid);
        if (ret != EOK) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    ret = mpg_res_convert(res);
    if (ret) {
        goto done;
    }

    ret = sysdb_merge_res_ts_attrs(domain->sysdb, res, attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Cannot merge timestamp cache values\n");
        /* non-fatal */
    }

    *_res = talloc_steal(mem_ctx, res);

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

int sysdb_getgrgid(TALLOC_CTX *mem_ctx,
                   struct sss_domain_info *domain,
                   gid_t gid,
                   struct ldb_result **_res)
{
    return sysdb_getgrgid_attrs(mem_ctx, domain, gid, NULL, _res);
}

int sysdb_enumgrent_filter(TALLOC_CTX *mem_ctx,
                           struct sss_domain_info *domain,
                           const char *name_filter,
                           const char *addtl_filter,
                           struct ldb_result **_res)
{
    TALLOC_CTX *tmp_ctx;
    static const char *attrs[] = SYSDB_GRSRC_ATTRS;
    const char *filter = NULL;
    const char *ts_filter = NULL;
    const char *base_filter;
    char *dn_filter = NULL;
    struct ldb_dn *base_dn;
    struct ldb_result *res;
    struct ldb_result ts_res;
    struct ldb_result *ts_cache_res;
    int ret, lret;

    if (_res == NULL) {
        return EINVAL;
    }
    *_res = NULL;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    if (sss_domain_is_mpg(domain)) {
        base_filter = SYSDB_GRENT_MPG_FILTER;
        base_dn = sysdb_domain_dn(tmp_ctx, domain);
    } else {
        base_filter = SYSDB_GRENT_FILTER;
        base_dn = sysdb_group_base_dn(tmp_ctx, domain);
    }
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    ts_filter = enum_filter(tmp_ctx, base_filter,
                            NULL, NULL, NULL, addtl_filter);
    if (ts_filter == NULL) {
        ret = ENOMEM;
        goto done;
    }
    DEBUG(SSSDBG_TRACE_LIBS, "Searching timestamp cache with [%s]\n", ts_filter);

    ret = sysdb_search_ts_groups(tmp_ctx, domain, ts_filter,
                                 sysdb_ts_cache_attrs,
                                 &ts_res);
    if (ret == ERR_NO_TS) {
        ret = ENOENT;
    }

    if (ret != EOK && ret != ENOENT) {
        goto done;
    }

    ret = sysdb_enum_dn_filter(tmp_ctx, &ts_res, name_filter, domain->name,
                               &dn_filter);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_search_ts_matches(tmp_ctx, domain->sysdb, attrs, &ts_res,
                                  dn_filter, &ts_cache_res);
    if (ret != EOK && ret != ENOENT) {
        goto done;
    }

    filter = enum_filter(tmp_ctx, base_filter,
                         SYSDB_NAME, name_filter, domain->name, addtl_filter);
    if (filter == NULL) {
        ret = ENOMEM;
        goto done;
    }
    DEBUG(SSSDBG_TRACE_LIBS, "Searching cache with [%s]\n", filter);

    lret = ldb_search(domain->sysdb->ldb, tmp_ctx, &res, base_dn,
                      LDB_SCOPE_SUBTREE, attrs, "%s", filter);
    if (lret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(lret);
        goto done;
    }

    ret = mpg_res_convert(res);
    if (ret) {
        goto done;
    }

    /* Merge in the timestamps from the fast ts db */
    ret = sysdb_merge_res_ts_attrs(domain->sysdb, res, attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Cannot merge timestamp cache values\n");
        /* non-fatal */
        ret = EOK;
    }

    res = sss_merge_ldb_results(res, ts_cache_res);
    if (res == NULL) {
        ret = ENOMEM;
        goto done;
    }

    *_res = talloc_steal(mem_ctx, res);

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

int sysdb_enumgrent(TALLOC_CTX *mem_ctx,
                    struct sss_domain_info *domain,
                    struct ldb_result **_res)
{
    return sysdb_enumgrent_filter(mem_ctx, domain, NULL, 0, _res);
}

int sysdb_enumgrent_filter_with_views(TALLOC_CTX *mem_ctx,
                                      struct sss_domain_info *domain,
                                      const char *name_filter,
                                      const char *addtl_filter,
                                      struct ldb_result **_res)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    size_t c;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    ret = sysdb_enumgrent_filter(tmp_ctx, domain, name_filter, addtl_filter, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_enumgrent failed.\n");
        goto done;
    }

    for (c = 0; c < res->count; c++) {
        if (DOM_HAS_VIEWS(domain)) {
            ret = sysdb_add_overrides_to_object(domain, res->msgs[c], NULL,
                                                NULL);
            /* enumeration assumes that the cache is up-to-date, hence we do not
             * need to handle ENOENT separately. */
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_add_overrides_to_object failed.\n");
                goto done;
            }
        }

        ret = sysdb_add_group_member_overrides(domain, res->msgs[c],
                                               DOM_HAS_VIEWS(domain));
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sysdb_add_group_member_overrides failed.\n");
            goto done;
        }
    }


    *_res = talloc_steal(mem_ctx, res);

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

int sysdb_enumgrent_with_views(TALLOC_CTX *mem_ctx,
                               struct sss_domain_info *domain,
                               struct ldb_result **_res)
{
    return sysdb_enumgrent_filter_with_views(mem_ctx, domain, NULL, NULL, _res);
}

int sysdb_initgroups(TALLOC_CTX *mem_ctx,
                     struct sss_domain_info *domain,
                     const char *name,
                     struct ldb_result **_res)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    struct ldb_dn *user_dn;
    struct ldb_request *req;
    struct ldb_control **ctrl;
    struct ldb_asq_control *control;
    static const char *attrs[] = SYSDB_INITGR_ATTRS;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = sysdb_getpwnam(tmp_ctx, domain, name, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_getpwnam failed: [%d][%s]\n",
                  ret, strerror(ret));
        goto done;
    }

    if (res->count == 0) {
        /* User is not cached yet */
        *_res = talloc_steal(mem_ctx, res);
        ret = EOK;
        goto done;

    } else if (res->count != 1) {
        ret = EIO;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sysdb_getpwnam returned count: [%d]\n", res->count);
        goto done;
    }

    /* no need to steal the dn, we are not freeing the result */
    user_dn = res->msgs[0]->dn;

    /* note we count on the fact that the default search callback
     * will just keep appending values. This is by design and can't
     * change so it is ok to already have a result (from the getpwnam)
     * even before we call the next search */

    ctrl = talloc_array(tmp_ctx, struct ldb_control *, 2);
    if (!ctrl) {
        ret = ENOMEM;
        goto done;
    }
    ctrl[1] = NULL;
    ctrl[0] = talloc(ctrl, struct ldb_control);
    if (!ctrl[0]) {
        ret = ENOMEM;
        goto done;
    }
    ctrl[0]->oid = LDB_CONTROL_ASQ_OID;
    ctrl[0]->critical = 1;
    control = talloc(ctrl[0], struct ldb_asq_control);
    if (!control) {
        ret = ENOMEM;
        goto done;
    }
    control->request = 1;
    control->source_attribute = talloc_strdup(control, SYSDB_INITGR_ATTR);
    if (!control->source_attribute) {
        ret = ENOMEM;
        goto done;
    }
    control->src_attr_len = strlen(control->source_attribute);
    ctrl[0]->data = control;

    ret = ldb_build_search_req(&req, domain->sysdb->ldb, tmp_ctx,
                               user_dn, LDB_SCOPE_BASE,
                               SYSDB_INITGR_FILTER, attrs, ctrl,
                               res, ldb_search_default_callback,
                               NULL);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = ldb_request(domain->sysdb->ldb, req);
    if (ret == LDB_SUCCESS) {
        ret = ldb_wait(req->handle, LDB_WAIT_ALL);
    }
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    *_res = talloc_steal(mem_ctx, res);

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

int sysdb_initgroups_by_upn(TALLOC_CTX *mem_ctx,
                             struct sss_domain_info *domain,
                             const char *upn,
                             struct ldb_result **_res)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *msg;
    struct ldb_result *res;
    const char *sysdb_name;
    static const char *attrs[] = SYSDB_INITGR_ATTRS;
    size_t i;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    ret = sysdb_search_user_by_upn(tmp_ctx, domain, false, upn, attrs, &msg);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_search_user_by_upn() failed.\n");
        goto done;
    }

    res = talloc_zero(tmp_ctx, struct ldb_result);
    if (res == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero() failed.\n");
        ret = ENOMEM;
        goto done;
    }

    if (ret == ENOENT) {
        res->count = 0;
        res->msgs = NULL;
    } else {
        sysdb_name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
        if (sysdb_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Sysdb entry does not have a name.\n");
            return EINVAL;
        }

        ret = sysdb_initgroups(tmp_ctx, domain, sysdb_name, &res);
        if (ret == EOK && DOM_HAS_VIEWS(domain)) {
            for (i = 0; i < res->count; i++) {
                ret = sysdb_add_overrides_to_object(domain, res->msgs[i],
                                                    NULL, NULL);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                        "sysdb_add_overrides_to_object() failed.\n");
                    return ret;
                }
            }
        }
    }

    *_res = talloc_steal(mem_ctx, res);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_initgroups_with_views(TALLOC_CTX *mem_ctx,
                                struct sss_domain_info *domain,
                                const char *name,
                                struct ldb_result **_res)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    struct ldb_dn *user_dn;
    struct ldb_request *req;
    struct ldb_control **ctrl;
    struct ldb_asq_control *control;
    static const char *attrs[] = SYSDB_INITGR_ATTRS;
    int ret;
    size_t c;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = sysdb_getpwnam_with_views(tmp_ctx, domain, name, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_getpwnam failed: [%d][%s]\n",
                  ret, strerror(ret));
        goto done;
    }

    if (res->count == 0) {
        /* User is not cached yet */
        *_res = talloc_steal(mem_ctx, res);
        ret = EOK;
        goto done;

    } else if (res->count != 1) {
        ret = EIO;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sysdb_getpwnam returned count: [%d]\n", res->count);
        goto done;
    }

    /* no need to steal the dn, we are not freeing the result */
    user_dn = res->msgs[0]->dn;

    /* note we count on the fact that the default search callback
     * will just keep appending values. This is by design and can't
     * change so it is ok to already have a result (from the getpwnam)
     * even before we call the next search */

    ctrl = talloc_array(tmp_ctx, struct ldb_control *, 2);
    if (!ctrl) {
        ret = ENOMEM;
        goto done;
    }
    ctrl[1] = NULL;
    ctrl[0] = talloc(ctrl, struct ldb_control);
    if (!ctrl[0]) {
        ret = ENOMEM;
        goto done;
    }
    ctrl[0]->oid = LDB_CONTROL_ASQ_OID;
    ctrl[0]->critical = 1;
    control = talloc(ctrl[0], struct ldb_asq_control);
    if (!control) {
        ret = ENOMEM;
        goto done;
    }
    control->request = 1;
    control->source_attribute = talloc_strdup(control, SYSDB_INITGR_ATTR);
    if (!control->source_attribute) {
        ret = ENOMEM;
        goto done;
    }
    control->src_attr_len = strlen(control->source_attribute);
    ctrl[0]->data = control;

    ret = ldb_build_search_req(&req, domain->sysdb->ldb, tmp_ctx,
                               user_dn, LDB_SCOPE_BASE,
                               SYSDB_INITGR_FILTER, attrs, ctrl,
                               res, ldb_search_default_callback,
                               NULL);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = ldb_request(domain->sysdb->ldb, req);
    if (ret == LDB_SUCCESS) {
        ret = ldb_wait(req->handle, LDB_WAIT_ALL);
    }
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    if (DOM_HAS_VIEWS(domain)) {
        /* Skip user entry because it already has override values added */
        for (c = 1; c < res->count; c++) {
            ret = sysdb_add_overrides_to_object(domain, res->msgs[c], NULL,
                                                NULL);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "sysdb_add_overrides_to_object failed.\n");
                goto done;
            }
        }
    }

    *_res = talloc_steal(mem_ctx, res);

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

int sysdb_get_user_attr(TALLOC_CTX *mem_ctx,
                        struct sss_domain_info *domain,
                        const char *name,
                        const char **attributes,
                        struct ldb_result **_res)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *base_dn;
    struct ldb_result *res;
    char *sanitized_name;
    char *lc_sanitized_name;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    base_dn = sysdb_user_base_dn(tmp_ctx, domain);
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_filter_sanitize_for_dom(tmp_ctx, name, domain,
                                      &sanitized_name, &lc_sanitized_name);
    if (ret != EOK) {
        goto done;
    }

    ret = ldb_search(domain->sysdb->ldb, tmp_ctx, &res, base_dn,
                     LDB_SCOPE_SUBTREE, attributes,
                     SYSDB_PWNAM_FILTER, lc_sanitized_name, sanitized_name,
                     sanitized_name);
    if (ret) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* Merge in the timestamps from the fast ts db */
    ret = sysdb_merge_res_ts_attrs(domain->sysdb, res, attributes);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Cannot merge timestamp cache values\n");
        /* non-fatal */
        ret = EOK;
    }

    *_res = talloc_steal(mem_ctx, res);

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

int sysdb_get_user_attr_with_views(TALLOC_CTX *mem_ctx,
                                   struct sss_domain_info *domain,
                                   const char *name,
                                   const char **attributes,
                                   struct ldb_result **_res)
{
    int ret;
    struct ldb_result *orig_obj = NULL;
    struct ldb_result *override_obj = NULL;
    const char **attrs = NULL;
    const char *mandatory_override_attrs[] = {SYSDB_OVERRIDE_DN,
                                              SYSDB_OVERRIDE_OBJECT_DN,
                                              NULL};
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    attrs = attributes;

    /* If there are views we first have to search the overrides for matches */
    if (DOM_HAS_VIEWS(domain)) {
        ret = add_strings_lists(tmp_ctx, attributes, mandatory_override_attrs,
                                false, discard_const(&attrs));
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "add_strings_lists failed.\n");
            goto done;
        }

        ret = sysdb_search_user_override_attrs_by_name(tmp_ctx, domain, name,
                                            attrs, &override_obj, &orig_obj);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sysdb_search_user_override_attrs_by_name failed.\n");
            return ret;
        }
    }

    /* If there are no views or nothing was found in the overrides the
     * original objects are searched. */
    if (orig_obj == NULL) {
        ret = sysdb_get_user_attr(tmp_ctx, domain, name, attrs, &orig_obj);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_get_user_attr failed.\n");
            return ret;
        }
    }

    /* If there are views we have to check if override values must be added to
     * the original object. */
    if (DOM_HAS_VIEWS(domain) && orig_obj->count == 1) {
        ret = sysdb_add_overrides_to_object(domain, orig_obj->msgs[0],
                          override_obj == NULL ? NULL : override_obj ->msgs[0],
                          attrs);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_add_overrides_to_object failed.\n");
            return ret;
        }

        if (ret == ENOENT) {
            *_res = talloc_zero(mem_ctx, struct ldb_result);
            if (*_res == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
                ret = ENOMEM;
            } else {
                ret = EOK;
            }
            goto done;
        }
    }

    *_res = talloc_steal(mem_ctx, orig_obj);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}


/* Get string until the first delimiter and strip out
 * leading and trailing whitespaces.
 */
static errno_t sysdb_netgr_split_triple_string(TALLOC_CTX *mem_ctx,
                                               const char **in,
                                               const char delimiter,
                                               char **out)
{
    size_t len;
    const char *p = *in;
    const char *begin;

    /* Remove any leading whitespace */
    while (*p && isspace(*p)) p++;
    begin = p;

    /* Find the delimiter */
    while (*p && *p != delimiter) p++;

    if (!*p) {
        /* No delimiter was found: parse error */
        return EINVAL;
    }

    len = p - begin;
    /* Remove trailing spaces */
    while (len > 0 && isspace(begin[len - 1])) len--;

    *out = NULL;
    if (len > 0) {
        /* Copy the output string */
        *out = talloc_strndup(mem_ctx, begin, len);
        if (!*out) {
            return ENOMEM;
        }
    }
    p++;

    *in = p;
    return EOK;
}



/* This function splits a three-tuple into three strings
 * It strips out any whitespace between the parentheses
 * and commas. Leading and trailing whitespace is
 * ignored.
 *
 * This behavior is compatible with nss_ldap's
 * implementation.
 */
static errno_t sysdb_netgr_split_triple(TALLOC_CTX *mem_ctx,
                                        const char *triple,
                                        char **hostname,
                                        char **username,
                                        char **domainname)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    const char *p = triple;

    char *host = NULL;
    char *user = NULL;
    char *domain = NULL;

    /* Pre-set the values to NULL here so if they are not
     * copied, we don't return garbage below.
     */
    *hostname = NULL;
    *username = NULL;
    *domainname = NULL;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    /* Remove any leading whitespace */
    while (*p && isspace(*p)) p++;

    if (*p != '(') {
        /* Triple must start and end with parentheses */
        ret = EINVAL;
        goto done;
    }
    p++;

    ret = sysdb_netgr_split_triple_string(tmp_ctx, &p, ',', &host);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_netgr_split_triple_string(tmp_ctx, &p, ',', &user);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_netgr_split_triple_string(tmp_ctx, &p, ')', &domain);
    if (ret != EOK) {
        goto done;
    }

    /* skip trailing whitespace */
    while (*p && isspace(*p)) p++;

    if (*p) {
        /* Extra data after the closing parenthesis
         * is a parse error
         */
        ret = EINVAL;
        goto done;
    }

    /* Return any non-NULL values */
    if (host) {
        *hostname = talloc_steal(mem_ctx, host);
    }

    if (user) {
        *username = talloc_steal(mem_ctx, user);
    }

    if (domain) {
        *domainname = talloc_steal(mem_ctx, domain);
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_netgr_to_entries(TALLOC_CTX *mem_ctx,
                               struct ldb_result *res,
                               struct sysdb_netgroup_ctx ***entries,
                               size_t *netgroup_count)
{
    errno_t ret;
    size_t size = 0;
    size_t c = 0;
    char *triple_str;
    TALLOC_CTX *tmp_ctx;
    struct sysdb_netgroup_ctx **tmp_entry = NULL;
    struct ldb_message_element *el;
    int i, j;

    if(!res || res->count == 0) {
        return ENOENT;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    for (i=0; i < res->count; i++) {
        el = ldb_msg_find_element(res->msgs[i], SYSDB_NETGROUP_TRIPLE);
        if (el != NULL) {
            size += el->num_values;
        }
        el = ldb_msg_find_element(res->msgs[i], SYSDB_NETGROUP_MEMBER);
        if (el != NULL) {
            size += el->num_values;
        }
    }

    tmp_entry = talloc_array(tmp_ctx, struct sysdb_netgroup_ctx *, size + 1);
    if (tmp_entry == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (size != 0) {
        for (i=0; i < res->count; i++) {
            el = ldb_msg_find_element(res->msgs[i], SYSDB_NETGROUP_TRIPLE);
            if (el != NULL) {
                /* Copy in all of the entries */
                for(j = 0; j < el->num_values; j++) {
                    triple_str = talloc_strndup(tmp_ctx,
                                                (const char *)el->values[j].data,
                                                el->values[j].length);
                    if (!triple_str) {
                        ret = ENOMEM;
                        goto done;
                    }

                    tmp_entry[c] = talloc_zero(tmp_entry,
                                                  struct sysdb_netgroup_ctx);
                    if (!tmp_entry[c]) {
                        ret = ENOMEM;
                        goto done;
                    }

                    tmp_entry[c]->type = SYSDB_NETGROUP_TRIPLE_VAL;
                    ret = sysdb_netgr_split_triple(tmp_entry[c],
                                        triple_str,
                                        &tmp_entry[c]->value.triple.hostname,
                                        &tmp_entry[c]->value.triple.username,
                                        &tmp_entry[c]->value.triple.domainname);
                    if (ret != EOK) {
                        DEBUG(SSSDBG_IMPORTANT_INFO,
                              "Cannot split netgroup triple [%s], "
                               "this attribute will be skipped \n",
                               triple_str);
                        continue;
                    }

                    c++;
                }
            }
            el = ldb_msg_find_element(res->msgs[i], SYSDB_NETGROUP_MEMBER);
            if (el != NULL) {
                for(j = 0; j < el->num_values; j++) {
                    tmp_entry[c] = talloc_zero(tmp_entry,
                                                  struct sysdb_netgroup_ctx);
                    if (!tmp_entry[c]) {
                        ret = ENOMEM;
                        goto done;
                    }

                    tmp_entry[c]->type = SYSDB_NETGROUP_GROUP_VAL;
                    tmp_entry[c]->value.groupname = talloc_strndup(tmp_entry[c],
                                               (const char *)el->values[j].data,
                                               el->values[j].length);
                    if (tmp_entry[c]->value.groupname == NULL) {
                        ret = ENOMEM;
                        goto done;
                    }

                    c++;
                }
            }
        }
    }

    /* Add NULL terminator */
    tmp_entry[c] = NULL;

    *entries = talloc_steal(mem_ctx, tmp_entry);
    *netgroup_count = c;

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_getnetgr(TALLOC_CTX *mem_ctx,
                       struct sss_domain_info *domain,
                       const char *netgroup,
                       struct ldb_result **res)
{
    TALLOC_CTX *tmp_ctx;
    static const char *attrs[] = SYSDB_NETGR_ATTRS;
    struct ldb_dn *base_dn;
    struct ldb_result *result = NULL;
    char *sanitized_netgroup;
    char *lc_sanitized_netgroup;
    char *netgroup_dn;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    base_dn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                             SYSDB_TMPL_NETGROUP_BASE,
                             domain->name);
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_filter_sanitize_for_dom(tmp_ctx, netgroup, domain,
                                      &sanitized_netgroup,
                                      &lc_sanitized_netgroup);
    if (ret != EOK) {
        goto done;
    }

    netgroup_dn = talloc_asprintf(tmp_ctx, SYSDB_TMPL_NETGROUP,
                                  sanitized_netgroup, domain->name);
    if (!netgroup_dn) {
        ret = ENOMEM;
        goto done;
    }

    SSS_LDB_SEARCH(ret, domain->sysdb->ldb, tmp_ctx, &result, base_dn,
                   LDB_SCOPE_SUBTREE, attrs,
                   SYSDB_NETGR_TRIPLES_FILTER, lc_sanitized_netgroup,
                   sanitized_netgroup, sanitized_netgroup,
                   netgroup_dn);

    if (ret == EOK || ret == ENOENT) {
        *res = talloc_steal(mem_ctx, result);
    }

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

int sysdb_get_netgroup_attr(TALLOC_CTX *mem_ctx,
                            struct sss_domain_info *domain,
                            const char *netgrname,
                            const char **attributes,
                            struct ldb_result **res)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *base_dn;
    struct ldb_result *result;
    char *sanitized_netgroup;
    char *lc_sanitized_netgroup;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    base_dn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                             SYSDB_TMPL_NETGROUP_BASE, domain->name);
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_filter_sanitize_for_dom(tmp_ctx, netgrname, domain,
                                      &sanitized_netgroup,
                                      &lc_sanitized_netgroup);
    if (ret != EOK) {
        goto done;
    }

    ret = ldb_search(domain->sysdb->ldb, tmp_ctx, &result, base_dn,
                     LDB_SCOPE_SUBTREE, attributes,
                     SYSDB_NETGR_FILTER,
                     lc_sanitized_netgroup,
                     sanitized_netgroup,
                     sanitized_netgroup);
    if (ret) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    *res = talloc_steal(mem_ctx, result);
done:
    talloc_zfree(tmp_ctx);
    return ret;
}

errno_t sysdb_get_direct_parents(TALLOC_CTX *mem_ctx,
                                 struct sss_domain_info *dom,
                                 struct sss_domain_info *parent_dom,
                                 enum sysdb_member_type mtype,
                                 const char *name,
                                 char ***_direct_parents)
{
    errno_t ret;
    const char *dn;
    char *sanitized_dn;
    struct ldb_dn *basedn;
    static const char *group_attrs[] = { SYSDB_NAME, NULL };
    const char *member_filter;
    size_t direct_sysdb_count = 0;
    struct ldb_message **direct_sysdb_groups = NULL;
    char **direct_parents = NULL;
    TALLOC_CTX *tmp_ctx = NULL;
    int i, pi;
    const char *tmp_str;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    if (mtype == SYSDB_MEMBER_USER) {
        dn = sysdb_user_strdn(tmp_ctx, dom->name, name);
    } else if (mtype == SYSDB_MEMBER_GROUP) {
        dn = sysdb_group_strdn(tmp_ctx, dom->name, name);
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unknown member type %d\n", mtype);
        ret = EINVAL;
        goto done;
    }

    if (!dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_filter_sanitize(tmp_ctx, dn, &sanitized_dn);
    if (ret != EOK) {
        goto done;
    }

    member_filter = talloc_asprintf(tmp_ctx, "(&(%s=%s)(%s=%s))",
                                    SYSDB_OBJECTCATEGORY, SYSDB_GROUP_CLASS,
                                    SYSDB_MEMBER, sanitized_dn);
    if (!member_filter) {
        ret = ENOMEM;
        goto done;
    }

    if (parent_dom == NULL) {
        basedn = sysdb_base_dn(dom->sysdb, tmp_ctx);
    } else {
        basedn = sysdb_group_base_dn(tmp_ctx, parent_dom);
    }
    if (!basedn) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "searching sysdb with filter [%s]\n", member_filter);

    ret = sysdb_search_entry(tmp_ctx, dom->sysdb, basedn,
                             LDB_SCOPE_SUBTREE, member_filter, group_attrs,
                             &direct_sysdb_count, &direct_sysdb_groups);
    if (ret == ENOENT) {
        direct_sysdb_count = 0;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_search_entry failed: [%d]: %s\n",
                  ret, strerror(ret));
        goto done;
    }

    /* EOK */
    /* Get the list of sysdb groups by name */
    direct_parents = talloc_array(tmp_ctx, char *, direct_sysdb_count+1);
    if (!direct_parents) {
        ret = ENOMEM;
        goto done;
    }

    pi = 0;
    for(i = 0; i < direct_sysdb_count; i++) {
        tmp_str = ldb_msg_find_attr_as_string(direct_sysdb_groups[i],
                                                SYSDB_NAME, NULL);
        if (!tmp_str) {
            DEBUG(SSSDBG_CRIT_FAILURE, "A group with no name?\n");
            /* This should never happen, but if it does, just continue */
            continue;
        }

        direct_parents[pi] = talloc_strdup(direct_parents, tmp_str);
        if (!direct_parents[pi]) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup() failed\n");
            ret = EIO;
            goto done;
        }
        pi++;
    }
    direct_parents[pi] = NULL;

    DEBUG(SSSDBG_TRACE_LIBS, "%s is a member of %zu sysdb groups\n",
              name, direct_sysdb_count);
    *_direct_parents = talloc_steal(mem_ctx, direct_parents);
    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_get_real_name(TALLOC_CTX *mem_ctx,
                            struct sss_domain_info *domain,
                            const char *name_or_upn_or_sid,
                            const char **_cname)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    const char *cname;
    struct ldb_message *msg;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = sysdb_getpwnam(tmp_ctx, domain, name_or_upn_or_sid, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot canonicalize username\n");
        goto done;
    }

    if (res->count == 0) {
        ret = sysdb_search_user_by_upn(tmp_ctx, domain, false, name_or_upn_or_sid,
                                       NULL, &msg);
        if (ret == ENOENT) {
            ret = sysdb_search_user_by_sid_str(tmp_ctx, domain,
                                               name_or_upn_or_sid, NULL, &msg);
            if (ret == ENOENT) {
                ret = sysdb_search_object_by_uuid(tmp_ctx, domain,
                                                  name_or_upn_or_sid, NULL,
                                                  &res);
                if (ret == EOK && res->count == 1) {
                    msg = res->msgs[0];
                } else if (ret != ENOENT) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "sysdb_search_object_by_uuid failed or returned "
                          "more than one result [%d][%s].\n",
                          ret, sss_strerror(ret));
                    ret = ENOENT;
                    goto done;
                }
            }
        }
        if (ret != EOK) {
            /* User cannot be found in cache */
            if (ret != ENOENT) {
                DEBUG(SSSDBG_OP_FAILURE, "Failed to find user [%s] in cache: %d\n",
                                         name_or_upn_or_sid, ret);
            } else {
                DEBUG(SSSDBG_TRACE_FUNC, "User [%s] is missing in cache\n",
                                         name_or_upn_or_sid);
            }
            goto done;
        }
    } else if (res->count == 1) {
        msg = res->msgs[0];
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sysdb_getpwnam returned count: [%d]\n", res->count);
        ret = EIO;
        goto done;
    }

    cname = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
    if (!cname) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "User '%s' without a name?\n", name_or_upn_or_sid);
        ret = ENOENT;
        goto done;
    }

    ret = EOK;
    *_cname = talloc_steal(mem_ctx, cname);
done:
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_search_user_by_cert_with_views(TALLOC_CTX *mem_ctx,
                                         struct sss_domain_info *domain,
                                         const char *cert,
                                         struct ldb_result **res)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_result *orig_obj = NULL;
    struct ldb_result *override_obj = NULL;
    const char *attrs[] = SYSDB_PW_ATTRS;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    /* If there are views we first have to search the overrides for matches */
    if (DOM_HAS_VIEWS(domain)) {
        ret = sysdb_search_override_by_cert(tmp_ctx, domain, cert, attrs,
                                            &override_obj, &orig_obj);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sysdb_search_override_by_cert failed.\n");
            goto done;
        }
    }

    /* If there are no views or nothing was found in the overrides the
     * original objects are searched. */
    if (orig_obj == NULL) {
        ret = sysdb_search_user_by_cert(tmp_ctx, domain, cert, &orig_obj);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_search_user_by_cert failed.\n");
            goto done;
        }
    }

    /* If there are views we have to check if override values must be added to
     * the original object. */
    if (DOM_HAS_VIEWS(domain) && orig_obj->count == 1) {
        ret = sysdb_add_overrides_to_object(domain, orig_obj->msgs[0],
                          override_obj == NULL ? NULL : override_obj->msgs[0],
                          NULL);
        if (ret == ENOENT) {
            *res = talloc_zero(mem_ctx, struct ldb_result);
            if (*res == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
                ret = ENOMEM;
            } else {
                ret = EOK;
            }
            goto done;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_add_overrides_to_object failed.\n");
            goto done;
        }
    }

    *res = talloc_steal(mem_ctx, orig_obj);
    ret = EOK;

done:

    talloc_free(tmp_ctx);
    return ret;
}

struct ldb_result *sss_merge_ldb_results(struct ldb_result *sysdb_res,
                                         struct ldb_result *ts_res)
{
    size_t i, ii, count, total;
    int ret;

    if (ts_res == NULL || ts_res->count == 0) {
        return sysdb_res;
    }

    total = sysdb_res->count + ts_res->count;
    sysdb_res->msgs = talloc_realloc(sysdb_res, sysdb_res->msgs,
                                     struct ldb_message *,
                                     total);
    if (sysdb_res->msgs == NULL) {
        return NULL;
    }

    /* FIXME - this is O(2), so inefficient for large sets! */
    count = sysdb_res->count;
    for (i = 0; i < ts_res->count; i++) {
        for (ii = 0; ii < sysdb_res->count; ii++) {
            ret = ldb_dn_compare(ts_res->msgs[i]->dn, sysdb_res->msgs[ii]->dn);
            if (ret == 0) {
                break;
            }
        }

        if (ii < sysdb_res->count) {
            /* We already have this DN but ts_res might be more up-to-date
             * wrt timestamps  */
            sysdb_res->msgs[ii] = talloc_steal(sysdb_res, ts_res->msgs[i]);
            continue;
        }
        /* new DN, merge */
        sysdb_res->msgs[count] = talloc_steal(sysdb_res, ts_res->msgs[i]);
        count++;
    }

    if (count < total) {
        sysdb_res->msgs = talloc_realloc(sysdb_res, sysdb_res->msgs,
                                         struct ldb_message *,
                                         count);
        if (sysdb_res->msgs == NULL) {
            return NULL;
        }
    }
    sysdb_res->count = count;
    return sysdb_res;
}

bool is_ts_cache_attr(const char *attrname)
{
    size_t i;

    for (i = 0; sysdb_ts_cache_attrs[i] != NULL; i++) {
        if (strcmp(attrname, sysdb_ts_cache_attrs[i]) == 0) {
            break;
        }
    }

    if (sysdb_ts_cache_attrs[i] == NULL) {
        return false;
    }

    return true;
}

struct sysdb_attrs *sysdb_filter_ts_attrs(TALLOC_CTX *mem_ctx,
                                          struct sysdb_attrs *attrs)
{
    struct sysdb_attrs *ts_attrs;
    int ti = 0;

    ts_attrs = sysdb_new_attrs(mem_ctx);
    if (ts_attrs == NULL) {
        return NULL;
    }

    ts_attrs->a = talloc_zero_array(ts_attrs,
                                    struct ldb_message_element,
                                    attrs->num);
    if (ts_attrs->a == NULL) {
        talloc_free(ts_attrs);
        return NULL;
    }

    for (int i = 0; i < attrs->num; i++) {
        if (is_ts_cache_attr(attrs->a[i].name)) {
            ts_attrs->a[ti] = attrs->a[i];
            ti++;
        }
    }
    ts_attrs->num = ti;

    return ts_attrs;
}
