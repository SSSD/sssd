/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2015 Red Hat

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

#include "db/sysdb.h"
#include "util/util.h"
#include "responder/common/responder.h"
#include "responder/ifp/ifp_cache.h"
#include "responder/ifp/ifp_users.h"
#include "responder/ifp/ifp_groups.h"

static struct ldb_dn *
ifp_cache_build_base_dn(TALLOC_CTX *mem_ctx,
                        enum ifp_cache_type type,
                        struct sss_domain_info *domain)
{
    struct ldb_dn *base_dn = NULL;

    switch (type) {
    case IFP_CACHE_USER:
        base_dn = sysdb_user_base_dn(mem_ctx, domain);
        break;
    case IFP_CACHE_GROUP:
        base_dn = sysdb_group_base_dn(mem_ctx, domain);
        break;
    }

    return base_dn;
}

static char *
ifp_cache_build_path(TALLOC_CTX *mem_ctx,
                     enum ifp_cache_type type,
                     struct sss_domain_info *domain,
                     struct ldb_message *msg)
{
    char *path = NULL;

    switch (type) {
    case IFP_CACHE_USER:
        path = ifp_users_build_path_from_msg(mem_ctx, domain, msg);
        break;
    case IFP_CACHE_GROUP:
        path = ifp_groups_build_path_from_msg(mem_ctx, domain, msg);
        break;
    }

    return path;
}

static const char *
ifp_cache_object_class(enum ifp_cache_type type)
{
    const char *class = NULL;

    switch (type) {
    case IFP_CACHE_USER:
        class = SYSDB_USER_CLASS;
        break;
    case IFP_CACHE_GROUP:
        class = SYSDB_GROUP_CLASS;
        break;
    }

    return class;
}

static errno_t
ifp_cache_get_cached_objects(TALLOC_CTX *mem_ctx,
                             enum ifp_cache_type type,
                             struct sss_domain_info *domain,
                             const char ***_paths)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *base_dn;
    struct ldb_result *result;
    const char *class = ifp_cache_object_class(type);
    const char **paths;
    errno_t ret;
    int ldb_ret;
    int i;
    const char *attrs[] = {SYSDB_OBJECTCATEGORY, SYSDB_UIDNUM,
                           SYSDB_GIDNUM, NULL};

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    base_dn = ifp_cache_build_base_dn(tmp_ctx, type, domain);
    if (base_dn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create base dn\n");
        ret = ENOMEM;
        goto done;
    }

    ldb_ret = ldb_search(sysdb_ctx_get_ldb(domain->sysdb), tmp_ctx, &result,
                         base_dn, LDB_SCOPE_SUBTREE, attrs,
                         "(&(%s=%s)(%s=TRUE))", SYSDB_OBJECTCATEGORY, class,
                         SYSDB_IFP_CACHED);
    if (ldb_ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to search the cache\n");
        ret = sss_ldb_error_to_errno(ldb_ret);
        goto done;
    }

    paths = talloc_zero_array(tmp_ctx, const char *, result->count + 1);
    if (paths == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < result->count; i++) {
        paths[i] = ifp_cache_build_path(paths, type, domain, result->msgs[i]);
        if (paths[i] == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    *_paths = talloc_steal(mem_ctx, paths);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
ifp_cache_list_domains(TALLOC_CTX *mem_ctx,
                       struct sss_domain_info *domains,
                       enum ifp_cache_type type,
                       const char ***_paths)
{
    TALLOC_CTX *tmp_ctx;
    struct sss_domain_info *domain;
    const char **tmp_paths = NULL;
    const char **paths;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    domain = domains;
    paths = NULL;
    while (domain != NULL) {
        ret = ifp_cache_get_cached_objects(tmp_ctx, type, domain, &tmp_paths);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to build object list "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            goto done;
        }

        ret = add_strings_lists(tmp_ctx, paths, tmp_paths, true,
                                discard_const(&paths));
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to build object list "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            goto done;
        }

        domain = get_next_domain(domain, SSS_GND_DESCEND);
    }

    if (_paths != NULL) {
        *_paths = talloc_steal(mem_ctx, paths);
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
ifp_cache_list(TALLOC_CTX *mem_ctx,
               struct ifp_ctx *ifp_ctx,
               enum ifp_cache_type type,
               const char ***_paths)
{
    return ifp_cache_list_domains(mem_ctx, ifp_ctx->rctx->domains,
                                  type, _paths);
}

errno_t
ifp_cache_list_by_domain(TALLOC_CTX *mem_ctx,
                         struct ifp_ctx *ifp_ctx,
                         const char *domainname,
                         enum ifp_cache_type type,
                         const char ***_paths)
{
    struct sss_domain_info *domain;

    domain = find_domain_by_name(ifp_ctx->rctx->domains, domainname, true);
    if (domain == NULL) {
        return ERR_DOMAIN_NOT_FOUND;
    }

    return ifp_cache_get_cached_objects(mem_ctx, type, domain, _paths);
}

static errno_t ifp_cache_object_set(struct sss_domain_info *domain,
                                    struct ldb_dn *dn,
                                    bool value)
{
    struct sysdb_attrs *attrs;
    errno_t ret;

    attrs = sysdb_new_attrs(NULL);
    if (attrs == NULL) {
        return ENOMEM;
    }

    ret = sysdb_attrs_add_bool(attrs, SYSDB_IFP_CACHED, value);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to add attribute [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = sysdb_set_entry_attr(domain->sysdb, dn, attrs, SYSDB_MOD_REP);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to modify entry [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;

done:
    talloc_free(attrs);

    return ret;
}

errno_t
ifp_cache_object_store(struct sss_domain_info *domain,
                       struct ldb_dn *dn)
{
    return ifp_cache_object_set(domain, dn, true);
}

errno_t
ifp_cache_object_remove(struct sss_domain_info *domain,
                        struct ldb_dn *dn)
{
    return ifp_cache_object_set(domain, dn, false);
}
