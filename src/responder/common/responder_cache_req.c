/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

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

#include <dbus/dbus.h>
#include <ldb.h>
#include <talloc.h>
#include <tevent.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "responder/common/responder_cache_req.h"
#include "providers/data_provider.h"

#define CACHE_REQ_DEBUG(level, input, fmt, ...) \
    DEBUG(level, "Cache Request [%s #%u]: " fmt, \
          (input)->reqname, (input)->reqid, ##__VA_ARGS__)

static errno_t updated_users_by_filter(TALLOC_CTX *mem_ctx,
                                       struct sss_domain_info *domain,
                                       const char *name_filter,
                                       time_t since,
                                       struct ldb_result **_res)
{
    int ret;
    char *recent_filter;

    recent_filter = talloc_asprintf(mem_ctx, "(%s>=%lu)",
                                    SYSDB_LAST_UPDATE, since);
    ret = sysdb_enumpwent_filter_with_views(mem_ctx, domain,
                                            name_filter, recent_filter,
                                            _res);
    talloc_free(recent_filter);

    return ret;
}

static errno_t updated_groups_by_filter(TALLOC_CTX *mem_ctx,
                                        struct sss_domain_info *domain,
                                        const char *name_filter,
                                        time_t since,
                                        struct ldb_result **_res)
{
    int ret;
    char *recent_filter;

    recent_filter = talloc_asprintf(mem_ctx, "(%s>=%lu)",
                                    SYSDB_LAST_UPDATE, since);
    ret = sysdb_enumgrent_filter_with_views(mem_ctx, domain,
                                            name_filter, recent_filter,
                                            _res);
    talloc_free(recent_filter);

    return ret;
}

struct cache_req_input {
    enum cache_req_type type;

    /* Provided input. */
    struct {
        struct {
            const char *input;  /* Original input. */
            const char *name;   /* Parsed name or UPN. */
            const char *lookup; /* Converted per domain rules. */
        } name;
        uint32_t id;
        const char *cert;
        const char *sid;
        const char **attrs;
    } data;

    /* Data Provider request type resolved from @type.
     * FIXME: This is currently needed for data provider calls. We should
     * refactor responder_dp.c to get rid of this member. */
    enum sss_dp_acct_type dp_type;

    /* Domain related informations. */
    struct sss_domain_info *domain;

    /* Debug information */
    uint32_t reqid;
    const char *reqname;
    const char *debugobj;

    /* Time when the request started. Useful for by-filter lookups */
    time_t req_start;
};

static errno_t
cache_req_input_set_data(struct cache_req_input *input,
                         enum cache_req_type type,
                         uint32_t id,
                         const char *name,
                         const char *cert,
                         const char *sid,
                         const char **attrs)
{
    switch (input->type) {
    case CACHE_REQ_USER_BY_NAME:
    case CACHE_REQ_USER_BY_UPN:
    case CACHE_REQ_GROUP_BY_NAME:
    case CACHE_REQ_USER_BY_FILTER:
    case CACHE_REQ_GROUP_BY_FILTER:
    case CACHE_REQ_INITGROUPS:
    case CACHE_REQ_INITGROUPS_BY_UPN:
        if (name == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Bug: name cannot be NULL!\n");
            return ERR_INTERNAL;
        }

        input->data.name.input = talloc_strdup(input, name);
        if (input->data.name.input == NULL) {
            return ENOMEM;
        }
        break;
    case CACHE_REQ_USER_BY_CERT:
        if (cert == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Bug: certificate cannot be NULL!\n");
            return ERR_INTERNAL;
        }

        input->data.cert = talloc_strdup(input, cert);
        if (input->data.cert == NULL) {
            return ENOMEM;
        }
        break;
    case CACHE_REQ_USER_BY_ID:
    case CACHE_REQ_GROUP_BY_ID:
        if (id == 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Bug: id cannot be 0!\n");
            return ERR_INTERNAL;
        }

        input->data.id = id;
        break;
    case CACHE_REQ_OBJECT_BY_SID:
        if (sid == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Bug: SID cannot be NULL!\n");
            return ERR_INTERNAL;
        }

        input->data.sid = talloc_strdup(input, sid);
        if (input->data.sid == NULL) {
            return ENOMEM;
        }
        break;
    }

    if (attrs != NULL) {
        input->data.attrs = dup_string_list(input, attrs);
        if (input->data.attrs == NULL) {
            return ENOMEM;
        }
    }

    return EOK;
}

static void
cache_req_input_set_dp(struct cache_req_input *input, enum cache_req_type type)
{
    switch (type) {
    case CACHE_REQ_USER_BY_NAME:
    case CACHE_REQ_USER_BY_UPN:
    case CACHE_REQ_USER_BY_ID:
        input->dp_type = SSS_DP_USER;
        break;

    case CACHE_REQ_GROUP_BY_NAME:
    case CACHE_REQ_GROUP_BY_ID:
        input->dp_type = SSS_DP_GROUP;
        break;

    case CACHE_REQ_INITGROUPS:
    case CACHE_REQ_INITGROUPS_BY_UPN:
        input->dp_type = SSS_DP_INITGROUPS;
        break;

    case CACHE_REQ_USER_BY_CERT:
        input->dp_type = SSS_DP_CERT;
        break;

    case CACHE_REQ_USER_BY_FILTER:
        input->dp_type = SSS_DP_WILDCARD_USER;
        break;

    case CACHE_REQ_GROUP_BY_FILTER:
        input->dp_type = SSS_DP_WILDCARD_GROUP;
        break;

    case CACHE_REQ_OBJECT_BY_SID:
        input->dp_type = SSS_DP_SECID;
        break;
    }

    return;
}

static void
cache_req_input_set_reqname(struct cache_req_input *input,
                            enum cache_req_type type)
{
    switch (type) {
    case CACHE_REQ_USER_BY_NAME:
        input->reqname = "User by name";
        break;
    case CACHE_REQ_USER_BY_UPN:
        input->reqname = "User by UPN";
        break;
    case CACHE_REQ_USER_BY_ID:
        input->reqname = "User by ID";
        break;
    case CACHE_REQ_GROUP_BY_NAME:
        input->reqname = "Group by name";
        break;
    case CACHE_REQ_GROUP_BY_ID:
        input->reqname = "Group by ID";
        break;
    case CACHE_REQ_INITGROUPS:
        input->reqname = "Initgroups by name";
        break;
    case CACHE_REQ_INITGROUPS_BY_UPN:
        input->reqname = "Initgroups by UPN";
        break;
    case CACHE_REQ_USER_BY_CERT:
        input->reqname = "User by certificate";
        break;
    case CACHE_REQ_USER_BY_FILTER:
        input->reqname = "User by filter";
        break;
    case CACHE_REQ_GROUP_BY_FILTER:
        input->reqname = "Group by filter";
        break;
    case CACHE_REQ_OBJECT_BY_SID:
        input->reqname = "Object by SID";
        break;
    }

    return;
}

struct cache_req_input *
cache_req_input_create(TALLOC_CTX *mem_ctx,
                       struct resp_ctx *rctx,
                       enum cache_req_type type,
                       const char *name,
                       uint32_t id,
                       const char *cert,
                       const char *sid,
                       const char **attrs)
{
    struct cache_req_input *input;
    errno_t ret;

    input = talloc_zero(mem_ctx, struct cache_req_input);
    if (input == NULL) {
        return NULL;
    }

    input->type = type;
    input->req_start = time(NULL);

    /* It is perfectly fine to just overflow here. */
    input->reqid = rctx->cache_req_num++;

    ret = cache_req_input_set_data(input, type, id, name, cert, sid, attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set input data!\n");
        goto fail;
    }

    cache_req_input_set_reqname(input, type);
    cache_req_input_set_dp(input, type);

    return input;

fail:
    talloc_free(input);
    return NULL;
}

static errno_t
cache_req_input_set_name(struct cache_req_input *input,
                         const char *name)
{
    const char *dup_name;

    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, input, "Setting name [%s]\n", name);

    dup_name = talloc_strdup(input, name);
    if (dup_name == NULL) {
        return ENOMEM;
    }

    talloc_zfree(input->data.name.name);
    input->data.name.name = dup_name;

    return EOK;
}

static errno_t
cache_req_input_set_domain(struct cache_req_input *input,
                           struct sss_domain_info *domain,
                           struct resp_ctx *rctx)
{
    TALLOC_CTX *tmp_ctx = NULL;
    const char *name = NULL;
    const char *debugobj = NULL;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, input,
                    "Using domain [%s]\n", domain->name);

    talloc_zfree(input->data.name.lookup);
    talloc_zfree(input->debugobj);

    switch (input->type) {
    case CACHE_REQ_USER_BY_NAME:
    case CACHE_REQ_USER_BY_UPN:
    case CACHE_REQ_GROUP_BY_NAME:
    case CACHE_REQ_USER_BY_FILTER:
    case CACHE_REQ_GROUP_BY_FILTER:
    case CACHE_REQ_INITGROUPS:
    case CACHE_REQ_INITGROUPS_BY_UPN:
        if (input->data.name.name == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Bug: parsed name is NULL?\n");
            ret = ERR_INTERNAL;
            goto done;
        }

        name = sss_get_cased_name(tmp_ctx, input->data.name.name,
                                  domain->case_sensitive);
        if (name == NULL) {
            ret = ENOMEM;
            goto done;
        }

        name = sss_reverse_replace_space(tmp_ctx, name, rctx->override_space);
        if (name == NULL) {
            ret = ENOMEM;
            goto done;
        }

        debugobj = talloc_asprintf(tmp_ctx, "%s@%s", name, domain->name);
        if (debugobj == NULL) {
            ret = ENOMEM;
            goto done;
        }

        break;

    case CACHE_REQ_USER_BY_ID:
        debugobj = talloc_asprintf(tmp_ctx, "UID:%d@%s",
                                   input->data.id, domain->name);
        if (debugobj == NULL) {
            ret = ENOMEM;
            goto done;
        }
        break;

    case CACHE_REQ_GROUP_BY_ID:
        debugobj = talloc_asprintf(tmp_ctx, "GID:%d@%s",
                                   input->data.id, domain->name);
        if (debugobj == NULL) {
            ret = ENOMEM;
            goto done;
        }
        break;
    case CACHE_REQ_USER_BY_CERT:
        /* certificates might be quite long, only use the last 10 charcters
         * for logging */
        debugobj = talloc_asprintf(tmp_ctx, "CERT:%s@%s",
                                   get_last_x_chars(input->data.cert, 10),
                                   domain->name);
        if (debugobj == NULL) {
            ret = ENOMEM;
            goto done;
        }
        break;
    case CACHE_REQ_OBJECT_BY_SID:
        debugobj = talloc_asprintf(tmp_ctx, "SID:%s@%s",
                                   input->data.sid, domain->name);
        if (debugobj == NULL) {
            ret = ENOMEM;
            goto done;
        }
        break;
    }

    input->domain = domain;
    input->data.name.lookup = talloc_steal(input, name);
    input->debugobj = talloc_steal(input, debugobj);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static bool
cache_req_input_is_upn(struct cache_req_input *input)
{
    switch (input->type) {
    case CACHE_REQ_USER_BY_UPN:
    case CACHE_REQ_INITGROUPS_BY_UPN:
        return true;
    default:
        return false;
    }
}

static bool
cache_req_input_assume_upn(struct cache_req_input *input)
{
    errno_t ret;
    bool bret;

    if (input->data.name.input == NULL
            || strchr(input->data.name.input, '@') == NULL) {
        return false;
    }

    switch (input->type) {
    case CACHE_REQ_USER_BY_NAME:
        input->type = CACHE_REQ_USER_BY_UPN;
        bret = true;
        break;
    case CACHE_REQ_INITGROUPS:
        input->type = CACHE_REQ_INITGROUPS_BY_UPN;
        bret = true;
        break;
    default:
        bret = false;
        break;
    }

    if (bret == true) {
        ret = cache_req_input_set_name(input, input->data.name.input);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "cache_req_input_set_name() failed\n");
            return false;
        }

        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, input, "Assuming UPN [%s]\n",
                        input->data.name.input);
    }

    return bret;
}

static errno_t cache_req_check_ncache(struct cache_req_input *input,
                                      struct sss_nc_ctx *ncache,
                                      int neg_timeout)
{
    errno_t ret = ERR_INTERNAL;

    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, input, "Checking negative cache "
                    "for [%s]\n", input->debugobj);

    switch (input->type) {
    case CACHE_REQ_USER_BY_NAME:
    case CACHE_REQ_USER_BY_UPN:
    case CACHE_REQ_INITGROUPS:
    case CACHE_REQ_INITGROUPS_BY_UPN:
        ret = sss_ncache_check_user(ncache, neg_timeout,
                                    input->domain, input->data.name.lookup);
        break;
    case CACHE_REQ_GROUP_BY_NAME:
        ret = sss_ncache_check_group(ncache, neg_timeout,
                                     input->domain, input->data.name.lookup);
        break;
    case CACHE_REQ_USER_BY_ID:
        ret = sss_ncache_check_uid(ncache, neg_timeout, NULL, input->data.id);
        break;
    case CACHE_REQ_GROUP_BY_ID:
        ret = sss_ncache_check_gid(ncache, neg_timeout, NULL, input->data.id);
        break;
    case CACHE_REQ_USER_BY_CERT:
        ret = sss_ncache_check_cert(ncache, neg_timeout, input->data.cert);
        break;
    case CACHE_REQ_USER_BY_FILTER:
    case CACHE_REQ_GROUP_BY_FILTER:
        ret = EOK;
        break;
    case CACHE_REQ_OBJECT_BY_SID:
        ret = sss_ncache_check_sid(ncache, neg_timeout, input->data.sid);
        break;
    }

    if (ret == EEXIST) {
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, input, "[%s] does not exist "
                        "(negative cache)\n", input->debugobj);
    }

    return ret;
}

static void cache_req_add_to_ncache(struct cache_req_input *input,
                                    struct sss_nc_ctx *ncache)
{
    errno_t ret = ERR_INTERNAL;

    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, input, "Adding [%s] to "
                    "negative cache\n", input->debugobj);

    switch (input->type) {
    case CACHE_REQ_USER_BY_NAME:
    case CACHE_REQ_USER_BY_UPN:
    case CACHE_REQ_INITGROUPS:
    case CACHE_REQ_INITGROUPS_BY_UPN:
        ret = sss_ncache_set_user(ncache, false, input->domain,
                                  input->data.name.lookup);
        break;
    case CACHE_REQ_GROUP_BY_NAME:
        ret = sss_ncache_set_group(ncache, false, input->domain,
                                   input->data.name.lookup);
        break;
    case CACHE_REQ_USER_BY_FILTER:
    case CACHE_REQ_GROUP_BY_FILTER:
        /* Nothing to do, adding a wildcard request to ncache doesn't
         * make sense */
    case CACHE_REQ_USER_BY_ID:
    case CACHE_REQ_GROUP_BY_ID:
    case CACHE_REQ_USER_BY_CERT:
    case CACHE_REQ_OBJECT_BY_SID:
        /* Nothing to do. Those types must be unique among all domains so
         * the don't contain domain part. Therefore they must be set only
         * if all domains are search and the entry is not found. */
        ret = EOK;
        break;
    }

    if (ret != EOK) {
        CACHE_REQ_DEBUG(SSSDBG_MINOR_FAILURE, input,
                        "Cannot set negative cache for [%s] [%d]: %s\n",
                        input->debugobj, ret, sss_strerror(ret));

        /* not fatal */
    }

    return;
}

static void cache_req_add_to_ncache_global(struct cache_req_input *input,
                                           struct sss_nc_ctx *ncache)
{
    errno_t ret = ERR_INTERNAL;

    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, input, "Adding [%s] to global "
                    "negative cache\n", input->debugobj);

    switch (input->type) {
    case CACHE_REQ_USER_BY_FILTER:
    case CACHE_REQ_GROUP_BY_FILTER:
        /* Nothing to do, adding a wildcard request to ncache doesn't
         * make sense */
    case CACHE_REQ_USER_BY_NAME:
    case CACHE_REQ_USER_BY_UPN:
    case CACHE_REQ_GROUP_BY_NAME:
    case CACHE_REQ_INITGROUPS:
    case CACHE_REQ_INITGROUPS_BY_UPN:
        /* Nothing to do. Those types are already in ncache for selected
         * domains. */
        ret = EOK;
        break;
    case CACHE_REQ_USER_BY_ID:
        ret = sss_ncache_set_uid(ncache, false, NULL, input->data.id);
        break;
    case CACHE_REQ_GROUP_BY_ID:
        ret = sss_ncache_set_gid(ncache, false, NULL, input->data.id);
        break;
    case CACHE_REQ_USER_BY_CERT:
        ret = sss_ncache_set_cert(ncache, false, input->data.cert);
        break;
    case CACHE_REQ_OBJECT_BY_SID:
        ret = sss_ncache_set_sid(ncache, false, input->data.sid);
        break;
    }

    if (ret != EOK) {
        CACHE_REQ_DEBUG(SSSDBG_MINOR_FAILURE, input, "Cannot set negcache for "
                        "[%s] [%d]: %s\n", input->debugobj,
                        ret, sss_strerror(ret));

        /* not fatal */
    }

    return;
}

static errno_t cache_req_get_object(TALLOC_CTX *mem_ctx,
                                    struct cache_req_input *input,
                                    struct ldb_result **_result)
{
    struct ldb_result *result = NULL;
    bool one_item_only = false;
    errno_t ret = ERR_INTERNAL;

    CACHE_REQ_DEBUG(SSSDBG_FUNC_DATA, input, "Requesting info for [%s]\n",
                    input->debugobj);

    switch (input->type) {
    case CACHE_REQ_USER_BY_NAME:
        one_item_only = true;
        ret = sysdb_getpwnam_with_views(mem_ctx, input->domain,
                                        input->data.name.lookup, &result);
        break;
    case CACHE_REQ_USER_BY_UPN:
        one_item_only = true;
        ret = sysdb_getpwupn(mem_ctx, input->domain,
                             input->data.name.lookup, &result);
        break;
    case CACHE_REQ_USER_BY_ID:
        one_item_only = true;
        ret = sysdb_getpwuid_with_views(mem_ctx, input->domain,
                                        input->data.id, &result);
        break;
    case CACHE_REQ_GROUP_BY_NAME:
        one_item_only = true;
        ret = sysdb_getgrnam_with_views(mem_ctx, input->domain,
                                        input->data.name.lookup, &result);
        break;
    case CACHE_REQ_GROUP_BY_ID:
        one_item_only = true;
        ret = sysdb_getgrgid_with_views(mem_ctx, input->domain,
                                        input->data.id, &result);
        break;
    case CACHE_REQ_INITGROUPS:
        one_item_only = false;
        ret = sysdb_initgroups_with_views(mem_ctx, input->domain,
                                          input->data.name.lookup, &result);
        break;
    case CACHE_REQ_INITGROUPS_BY_UPN:
        one_item_only = false;
        ret = sysdb_initgroups_by_upn(mem_ctx, input->domain,
                                      input->data.name.lookup, &result);
        break;
    case CACHE_REQ_USER_BY_CERT:
        one_item_only = true;
        ret = sysdb_search_user_by_cert(mem_ctx, input->domain,
                                        input->data.cert, &result);
        break;
    case CACHE_REQ_USER_BY_FILTER:
        one_item_only = false;
        ret = updated_users_by_filter(mem_ctx, input->domain,
                                      input->data.name.lookup, input->req_start,
                                      &result);
        break;
    case CACHE_REQ_GROUP_BY_FILTER:
        one_item_only = false;
        ret = updated_groups_by_filter(mem_ctx, input->domain,
                                       input->data.name.lookup, input->req_start,
                                       &result);
        break;
    case CACHE_REQ_OBJECT_BY_SID:
        one_item_only = true;
        ret = sysdb_search_object_by_sid(mem_ctx, input->domain,
                                         input->data.sid, input->data.attrs,
                                         &result);
        break;
    }

    if (ret != EOK) {
        goto done;
    } else if (result->count == 0) {
        ret = ENOENT;
        goto done;
    } else if (one_item_only && result->count > 1) {
        ret = ERR_INTERNAL;
        CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, input,
                        "Multiple objects were found when "
                        "sysdb search expected only one!\n");
        goto done;
    }

    *_result = result;

done:
    return ret;
}

/* Return true if the request bypasses cache or false if the cache_req
 * code can leverage sysdb for this request.
 */
static bool cache_req_bypass_cache(struct cache_req_input *input)
{
    if (input->type == CACHE_REQ_USER_BY_FILTER ||
            input->type == CACHE_REQ_GROUP_BY_FILTER) {
        return true;
    }

    return false;
}

static errno_t cache_req_expiration_status(struct cache_req_input *input,
                                           struct ldb_result *result,
                                           time_t cache_refresh_percent)
{
    time_t expire;

    if (result == NULL || result->count == 0 || cache_req_bypass_cache(input)) {
        return ENOENT;
    }

    if (input->type == CACHE_REQ_INITGROUPS) {
        expire = ldb_msg_find_attr_as_uint64(result->msgs[0],
                                             SYSDB_INITGR_EXPIRE, 0);
    } else {
        expire = ldb_msg_find_attr_as_uint64(result->msgs[0],
                                             SYSDB_CACHE_EXPIRE, 0);
    }

    return sss_cmd_check_cache(result->msgs[0], cache_refresh_percent, expire);
}

static void cache_req_dpreq_params(TALLOC_CTX *mem_ctx,
                                   struct cache_req_input *input,
                                   struct ldb_result *result,
                                   const char **_string,
                                   uint32_t *_id,
                                   const char **_flag)
{
    struct ldb_result *user = NULL;
    const char *name = NULL;
    uint32_t id = 0;
    errno_t ret;

    *_id = input->data.id;
    *_string = input->data.name.lookup;
    *_flag = NULL;

    if (cache_req_input_is_upn(input)) {
        *_flag = EXTRA_NAME_IS_UPN;
        return;
    }

    if (input->type == CACHE_REQ_USER_BY_CERT) {
        *_string = input->data.cert;
        return;
    } else if (input->type == CACHE_REQ_OBJECT_BY_SID) {
        *_string = input->data.sid;
        return;
    }

    if (!DOM_HAS_VIEWS(input->domain)) {
        return;
    }

    /* We must search with views. */
    if (result == NULL || result->count == 0) {
        *_flag = EXTRA_INPUT_MAYBE_WITH_VIEW;
        return;
    }

    /* If domain has views we will try to user original values instead of the
     * overridden ones. This is a must for the LOCAL view since we can't look
     * it up otherwise. But it is also a shortcut for non-local views where
     * we will not fail over to the overridden value. */

    switch (input->type) {
    case CACHE_REQ_USER_BY_NAME:
    case CACHE_REQ_GROUP_BY_NAME:
       name = ldb_msg_find_attr_as_string(result->msgs[0], SYSDB_NAME, NULL);
       if (name == NULL) {
           DEBUG(SSSDBG_CRIT_FAILURE, "Bug: name cannot be NULL\n");
       }
       break;
    case CACHE_REQ_USER_BY_ID:
       id = ldb_msg_find_attr_as_uint64(result->msgs[0], SYSDB_UIDNUM, 0);
       if (id == 0) {
           DEBUG(SSSDBG_CRIT_FAILURE, "Bug: id cannot be 0\n");
       }
       break;
    case CACHE_REQ_GROUP_BY_ID:
       id = ldb_msg_find_attr_as_uint64(result->msgs[0], SYSDB_GIDNUM, 0);
       if (id == 0) {
           DEBUG(SSSDBG_CRIT_FAILURE, "Bug: id cannot be 0\n");
       }
       break;
    case CACHE_REQ_INITGROUPS:
        ret = sysdb_getpwnam_with_views(NULL, input->domain,
                                        input->data.name.lookup, &user);
        if (ret != EOK || user == NULL || user->count != 1) {
            /* Case where the user is not found has been already handled. If
             * this is not OK, it is an error. */
            CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, input,
                            "Unable to match initgroups user [%d]: %s\n",
                            ret, sss_strerror(ret));
            break;
        }

        name = ldb_msg_find_attr_as_string(user->msgs[0], SYSDB_NAME,
                                           NULL);
        if (name == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Bug: name cannot be NULL\n");
            break;
        }

        talloc_steal(mem_ctx, name);
        talloc_free(user);
        break;
    default:
        return;
    }

    /* Now we have the original name and id. We don't have to search with
     * views unless some error occurred. */
    if (name == NULL && id == 0) {
        *_flag = EXTRA_INPUT_MAYBE_WITH_VIEW;
        return;
    }

    *_string = talloc_steal(mem_ctx, name);
    *_id = id;
}

struct cache_req_cache_state {
    /* input data */
    struct tevent_context *ev;
    struct resp_ctx *rctx;
    struct sss_nc_ctx *ncache;
    int neg_timeout;
    int cache_refresh_percent;
    struct cache_req_input *input;

    /* output data */
    struct ldb_result *result;
};

static errno_t cache_req_cache_search(struct tevent_req *req);
static errno_t cache_req_cache_check(struct tevent_req *req);
static void cache_req_cache_done(struct tevent_req *subreq);

static struct tevent_req *cache_req_cache_send(TALLOC_CTX *mem_ctx,
                                               struct tevent_context *ev,
                                               struct resp_ctx *rctx,
                                               struct sss_nc_ctx *ncache,
                                               int neg_timeout,
                                               int cache_refresh_percent,
                                               struct cache_req_input *input)
{
    struct cache_req_cache_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct cache_req_cache_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("tevent_req_create() failed\n"));
        return NULL;
    }

    state->ev = ev;
    state->rctx = rctx;
    state->ncache = ncache;
    state->neg_timeout = neg_timeout;
    state->cache_refresh_percent = cache_refresh_percent;
    state->input = input;

    /* Check negative cache first. */
    ret = cache_req_check_ncache(state->input, state->ncache,
                                 state->neg_timeout);
    if (ret == EEXIST) {
        ret = ENOENT;
        goto immediately;
    }

    /* We will first search the cache. If we get cache miss or the entry
     * is expired we will contact data provider and then search again. */
    ret = cache_req_cache_search(req);
    if (ret != EAGAIN) {
        goto immediately;
    }

    return req;

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);

    return req;
}

static errno_t cache_req_cache_search(struct tevent_req *req)
{
    struct cache_req_cache_state *state = NULL;
    errno_t ret;

    state = tevent_req_data(req, struct cache_req_cache_state);

    ret = cache_req_get_object(state, state->input, &state->result);
    if (ret != EOK && ret != ENOENT) {
        CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, state->input, "Failed to make "
                        "request to our cache [%d]: %s\n",
                        ret, sss_strerror(ret));
        return ret;
    }

    /* Verify that the cache is up to date. */
    ret = cache_req_cache_check(req);
    if (req != EOK) {
        return ret;
    }

    /* One result found */
    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->input,
                    "Returning info for [%s]\n", state->input->debugobj);
    return EOK;
}

static errno_t cache_req_cache_check(struct tevent_req *req)
{
    struct cache_req_cache_state *state = NULL;
    struct tevent_req *subreq = NULL;
    const char *extra_flag = NULL;
    const char *search_str;
    uint32_t search_id;
    errno_t ret;

    state = tevent_req_data(req, struct cache_req_cache_state);

    cache_req_dpreq_params(state, state->input, state->result,
                           &search_str, &search_id, &extra_flag);

    ret = cache_req_expiration_status(state->input, state->result,
                                      state->cache_refresh_percent);

    switch (ret) {
    case EOK:
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->input,
                        "[%s] entry is valid\n", state->input->debugobj);
        return EOK;
    case EAGAIN:
        /* Out of band update. The calling function will return the cached
         * entry immediately. No callback is required. */

        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->input,
                        "Performing midpoint cache update of [%s]\n",
                        state->input->debugobj);

        subreq = sss_dp_get_account_send(state, state->rctx,
                                         state->input->domain, true,
                                         state->input->dp_type,
                                         search_str, search_id, extra_flag);
        if (subreq == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory sending out-of-band "
                                       "data provider request\n");
            /* This is non-fatal, so we'll continue here */
        }

        return EOK;
    case ENOENT:
        /* Cache miss or the cache is expired. We need to get the updated
         * information before returning it. */

        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->input,
                        "Looking up [%s] in data provider\n",
                        state->input->debugobj);

        subreq = sss_dp_get_account_send(state, state->rctx,
                                         state->input->domain, true,
                                         state->input->dp_type,
                                         search_str, search_id, extra_flag);
        if (subreq == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Out of memory sending data provider request\n");
            return ENOMEM;
        }

        tevent_req_set_callback(subreq, cache_req_cache_done, req);
        return EAGAIN;
    default:
        /* error */
        CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, state->input, "Error checking "
                        "cache [%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }
}

static void cache_req_cache_done(struct tevent_req *subreq)
{
    struct cache_req_cache_state *state = NULL;
    struct tevent_req *req = NULL;
    char *err_msg = NULL;
    dbus_uint16_t err_maj;
    dbus_uint32_t err_min;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct cache_req_cache_state);

    ret = sss_dp_get_account_recv(state, subreq, &err_maj, &err_min, &err_msg);
    talloc_zfree(subreq);
    if (ret != EOK) {
        CACHE_REQ_DEBUG(SSSDBG_OP_FAILURE, state->input,
                        "Could not get account info [%d]: %s\n",
                        ret, sss_strerror(ret));
    }

    if (err_maj) {
        CACHE_REQ_DEBUG(SSSDBG_MINOR_FAILURE, state->input,
              "Data Provider Error: %u, %u, %s (will return cached data)\n",
              (unsigned int)err_maj, (unsigned int)err_min, err_msg);
    }

    /* Get result from cache again. */
    ret = cache_req_get_object(state, state->input, &state->result);
    if (ret == ENOENT) {
        cache_req_add_to_ncache(state->input, state->ncache);
        ret = ENOENT;
    } else if (ret != EOK) {
        CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, state->input,
                        "Failed to make request to our cache [%d]: %s\n",
                        ret, sss_strerror(ret));
    }

    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    /* One result found */
    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->input,
                    "Returning %u results for [%s]\n", state->result->count,
                    state->input->debugobj);

    tevent_req_done(req);
}

static errno_t cache_req_cache_recv(TALLOC_CTX *mem_ctx,
                                    struct tevent_req *req,
                                    struct ldb_result **_result)
{
    struct cache_req_cache_state *state = NULL;
    state = tevent_req_data(req, struct cache_req_cache_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_result = talloc_steal(mem_ctx, state->result);

    return EOK;
}


struct cache_req_state {
    /* input data */
    struct tevent_context *ev;
    struct resp_ctx *rctx;
    struct sss_nc_ctx *ncache;
    int neg_timeout;
    int cache_refresh_percent;
    struct cache_req_input *input;

    /* work data */
    struct ldb_result *result;
    struct sss_domain_info *domain;
    struct sss_domain_info *selected_domain;
    bool check_next;
};

static void cache_req_input_parsed(struct tevent_req *subreq);

static errno_t cache_req_select_domains(struct tevent_req *req,
                                        const char *domain);

static errno_t cache_req_next_domain(struct tevent_req *req);

static void cache_req_done(struct tevent_req *subreq);

struct tevent_req *cache_req_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct resp_ctx *rctx,
                                  struct sss_nc_ctx *ncache,
                                  int neg_timeout,
                                  int cache_refresh_percent,
                                  const char *domain,
                                  struct cache_req_input *input)
{
    struct cache_req_state *state = NULL;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct cache_req_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("tevent_req_create() failed\n"));
        return NULL;
    }

    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, input, "New request\n");

    state->ev = ev;
    state->rctx = rctx;
    state->ncache = ncache;
    state->neg_timeout = neg_timeout;
    state->cache_refresh_percent = cache_refresh_percent;
    state->input = input;

    if (state->input->data.name.input != NULL && domain == NULL) {
        /* Parse input name first, since it may contain domain name. */
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, input, "Parsing input name [%s]\n",
                        input->data.name.input);

        subreq = sss_parse_inp_send(state, rctx, input->data.name.input);
        if (subreq == NULL) {
            ret = ENOMEM;
            goto immediately;
        }

        tevent_req_set_callback(subreq, cache_req_input_parsed, req);
    } else {
        if (input->data.name.input != NULL) {
            ret = cache_req_input_set_name(input, input->data.name.input);
            if (ret != EOK) {
                goto immediately;
            }
        }

        ret = cache_req_select_domains(req, domain);
        if (ret != EAGAIN) {
            goto immediately;
        }
    }

    return req;

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);

    return req;
}

static void cache_req_input_parsed(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct cache_req_state *state;
    char *name;
    char *domain;
    errno_t ret;
    bool maybe_upn;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct cache_req_state);

    ret = sss_parse_inp_recv(subreq, state, &name, &domain);
    switch (ret) {
    case EOK:
        ret = cache_req_input_set_name(state->input, name);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }
        break;
    case ERR_DOMAIN_NOT_FOUND:
        maybe_upn = cache_req_input_assume_upn(state->input);
        if (!maybe_upn) {
            tevent_req_error(req, ret);
            return;
        }

        domain = NULL;
        break;
    default:
        tevent_req_error(req, ret);
        return;
    }

    ret = cache_req_select_domains(req, domain);
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        return;
    }
}

static errno_t cache_req_select_domains(struct tevent_req *req,
                                        const char *domain)
{
    struct cache_req_state *state = NULL;

    state = tevent_req_data(req, struct cache_req_state);

    if (domain != NULL) {
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->input,
                        "Performing a single domain search\n");

        state->domain = responder_get_domain(state->rctx, domain);
        if (state->domain == NULL) {
            return ERR_DOMAIN_NOT_FOUND;
        }

        state->check_next = false;
    } else {
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->input,
                        "Performing a multi-domain search\n");

        state->domain = state->rctx->domains;
        state->check_next = true;
    }

    return cache_req_next_domain(req);
}

static errno_t cache_req_next_domain(struct tevent_req *req)
{
    struct cache_req_state *state = NULL;
    struct tevent_req *subreq = NULL;
    errno_t ret;

    state = tevent_req_data(req, struct cache_req_state);

    while (state->domain != NULL) {
       /* If it is a domainless search, skip domains that require fully
        * qualified names instead. */
        while (state->domain != NULL && state->check_next
                && state->domain->fqnames
                && state->input->type != CACHE_REQ_USER_BY_CERT
                && !cache_req_input_is_upn(state->input)) {
            state->domain = get_next_domain(state->domain, 0);
        }

        state->selected_domain = state->domain;

        if (state->domain == NULL) {
            break;
        }

        ret = cache_req_input_set_domain(state->input, state->domain,
                                         state->rctx);
        if (ret != EOK) {
            return ret;
        }

        subreq = cache_req_cache_send(state, state->ev, state->rctx,
                                      state->ncache, state->neg_timeout,
                                      state->cache_refresh_percent,
                                      state->input);
        if (subreq == NULL) {
            return ENOMEM;
        }

        tevent_req_set_callback(subreq, cache_req_done, req);

        /* we will continue with the following domain the next time */
        if (state->check_next) {
            if (cache_req_input_is_upn(state->input)
                    || state->input->type == CACHE_REQ_USER_BY_CERT ) {
                state->domain = get_next_domain(state->domain, SSS_GND_DESCEND);
            } else {
                state->domain = get_next_domain(state->domain, 0);
            }
        }

        return EAGAIN;
    }

    /* If the object searched has to be unique among all maintained domains,
     * we have to add it into negative cache here when all domains have
     * been searched. */

    cache_req_add_to_ncache_global(state->input, state->ncache);

    return ENOENT;
}

static void cache_req_done(struct tevent_req *subreq)
{
    struct cache_req_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct cache_req_state);

    ret = cache_req_cache_recv(state, subreq, &state->result);
    talloc_zfree(subreq);
    if (ret == EOK) {
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->input,
                        "Finished: Success\n");
        tevent_req_done(req);
        return;
    }

    if (state->check_next == false) {
        if (ret == ENOENT && cache_req_input_assume_upn(state->input)) {
            /* search by upn now */
            cache_req_select_domains(req, NULL);
            return;
        }

        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->input,
                        "Finished: Not found\n");
        tevent_req_error(req, ret);
        return;
    }

    ret = cache_req_next_domain(req);
    if (ret != EAGAIN) {
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->input,
                        "Finished: Error %d: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
    }

    return;
}

errno_t cache_req_recv(TALLOC_CTX *mem_ctx,
                       struct tevent_req *req,
                       struct ldb_result **_result,
                       struct sss_domain_info **_domain,
                       char **_name)
{
    struct cache_req_state *state = NULL;
    char *name;

    state = tevent_req_data(req, struct cache_req_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_name != NULL) {
        if (state->input->data.name.lookup == NULL) {
            *_name = NULL;
        } else {
            name = talloc_strdup(mem_ctx, state->input->data.name.name);
            if (name == NULL) {
                return ENOMEM;
            }

            *_name = name;
        }
    }

    if (_result != NULL) {
        *_result = talloc_steal(mem_ctx, state->result);
    }

    if (_domain != NULL) {
        *_domain = state->selected_domain;
    }

    return EOK;
}

static struct tevent_req *
cache_req_steal_input_and_send(TALLOC_CTX *mem_ctx,
                               struct tevent_context *ev,
                               struct resp_ctx *rctx,
                               struct sss_nc_ctx *ncache,
                               int neg_timeout,
                               int cache_refresh_percent,
                               const char *domain,
                               struct cache_req_input *input)
{
    struct tevent_req *req;

    req = cache_req_send(mem_ctx, ev, rctx, ncache, neg_timeout,
                         cache_refresh_percent, domain, input);
    if (req == NULL) {
        talloc_zfree(input);
    }

    talloc_steal(req, input);

    return req;
}

struct tevent_req *
cache_req_user_by_name_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct resp_ctx *rctx,
                            struct sss_nc_ctx *ncache,
                            int neg_timeout,
                            int cache_refresh_percent,
                            const char *domain,
                            const char *name)
{
    struct cache_req_input *input;

    input = cache_req_input_create(mem_ctx, rctx, CACHE_REQ_USER_BY_NAME,
                                   name, 0, NULL, NULL, NULL);
    if (input == NULL) {
        return NULL;
    }

    return cache_req_steal_input_and_send(mem_ctx, ev, rctx, ncache,
                                          neg_timeout, cache_refresh_percent,
                                          domain, input);
}

struct tevent_req *
cache_req_user_by_id_send(TALLOC_CTX *mem_ctx,
                          struct tevent_context *ev,
                          struct resp_ctx *rctx,
                          struct sss_nc_ctx *ncache,
                          int neg_timeout,
                          int cache_refresh_percent,
                          const char *domain,
                          uid_t uid)
{
    struct cache_req_input *input;

    input = cache_req_input_create(mem_ctx, rctx, CACHE_REQ_USER_BY_ID,
                                   NULL, uid, NULL, NULL, NULL);
    if (input == NULL) {
        return NULL;
    }

    return cache_req_steal_input_and_send(mem_ctx, ev, rctx, ncache,
                                          neg_timeout, cache_refresh_percent,
                                          domain, input);
}

struct tevent_req *
cache_req_user_by_cert_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct resp_ctx *rctx,
                            struct sss_nc_ctx *ncache,
                            int neg_timeout,
                            int cache_refresh_percent,
                            const char *domain,
                            const char *pem_cert)
{
    struct cache_req_input *input;

    input = cache_req_input_create(mem_ctx, rctx, CACHE_REQ_USER_BY_CERT,
                                   NULL, 0, pem_cert, NULL, NULL);
    if (input == NULL) {
        return NULL;
    }

    return cache_req_steal_input_and_send(mem_ctx, ev, rctx, ncache,
                                          neg_timeout, cache_refresh_percent,
                                          domain, input);
}

struct tevent_req *
cache_req_group_by_name_send(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev,
                             struct resp_ctx *rctx,
                             struct sss_nc_ctx *ncache,
                             int neg_timeout,
                             int cache_refresh_percent,
                             const char *domain,
                             const char *name)
{
    struct cache_req_input *input;

    input = cache_req_input_create(mem_ctx, rctx, CACHE_REQ_GROUP_BY_NAME,
                                   name, 0, NULL, NULL, NULL);
    if (input == NULL) {
        return NULL;
    }

    return cache_req_steal_input_and_send(mem_ctx, ev, rctx, ncache,
                                          neg_timeout, cache_refresh_percent,
                                          domain, input);
}

struct tevent_req *
cache_req_group_by_id_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct resp_ctx *rctx,
                           struct sss_nc_ctx *ncache,
                           int neg_timeout,
                           int cache_refresh_percent,
                           const char *domain,
                           gid_t gid)
{
    struct cache_req_input *input;

    input = cache_req_input_create(mem_ctx, rctx, CACHE_REQ_GROUP_BY_ID,
                                   NULL, gid, NULL, NULL, NULL);
    if (input == NULL) {
        return NULL;
    }

    return cache_req_steal_input_and_send(mem_ctx, ev, rctx, ncache,
                                          neg_timeout, cache_refresh_percent,
                                          domain, input);
}

struct tevent_req *
cache_req_initgr_by_name_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct resp_ctx *rctx,
                              struct sss_nc_ctx *ncache,
                              int neg_timeout,
                              int cache_refresh_percent,
                              const char *domain,
                              const char *name)
{
    struct cache_req_input *input;

    input = cache_req_input_create(mem_ctx, rctx, CACHE_REQ_INITGROUPS,
                                   name, 0, NULL, NULL, NULL);
    if (input == NULL) {
        return NULL;
    }

    return cache_req_steal_input_and_send(mem_ctx, ev, rctx, ncache,
                                          neg_timeout, cache_refresh_percent,
                                          domain, input);
}

struct tevent_req *
cache_req_user_by_filter_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct resp_ctx *rctx,
                              const char *domain,
                              const char *filter)
{
    struct cache_req_input *input;

    input = cache_req_input_create(mem_ctx, rctx, CACHE_REQ_USER_BY_FILTER,
                                   filter, 0, NULL, NULL, NULL);
    if (input == NULL) {
        return NULL;
    }

    return cache_req_steal_input_and_send(mem_ctx, ev, rctx, NULL,
                                          0, 0, domain, input);
}

struct tevent_req *
cache_req_group_by_filter_send(TALLOC_CTX *mem_ctx,
                               struct tevent_context *ev,
                               struct resp_ctx *rctx,
                               const char *domain,
                               const char *filter)
{
    struct cache_req_input *input;

    input = cache_req_input_create(mem_ctx, rctx, CACHE_REQ_GROUP_BY_FILTER,
                                   filter, 0, NULL, NULL, NULL);
    if (input == NULL) {
        return NULL;
    }

    return cache_req_steal_input_and_send(mem_ctx, ev, rctx, NULL,
                                          0, 0, domain, input);
}

struct tevent_req *
cache_req_object_by_sid_send(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev,
                             struct resp_ctx *rctx,
                             struct sss_nc_ctx *ncache,
                             int neg_timeout,
                             int cache_refresh_percent,
                             const char *domain,
                             const char *sid,
                             const char **attrs)
{
    struct cache_req_input *input;

    input = cache_req_input_create(mem_ctx, rctx, CACHE_REQ_OBJECT_BY_SID,
                                   NULL, 0, NULL, sid, attrs);
    if (input == NULL) {
        return NULL;
    }

    return cache_req_steal_input_and_send(mem_ctx, ev, rctx, ncache,
                                          neg_timeout, cache_refresh_percent,
                                          domain, input);
}
