/*
   SSSD

   System Database - Sub-domain related calls

   Copyright (C) 2012 Jan Zeleny <jzeleny@redhat.com>
   Copyright (C) 2012 Sumit Bose <sbose@redhat.com>

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

errno_t sysdb_get_subdomains(TALLOC_CTX *mem_ctx, struct sysdb_ctx *sysdb,
                             size_t *subdomain_count,
                             struct sysdb_subdom ***subdomain_list)
{
    int i;
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    const char *attrs[] = {"cn",
                           SYSDB_SUBDOMAIN_REALM,
                           SYSDB_SUBDOMAIN_FLAT,
                           SYSDB_SUBDOMAIN_ID,
                           NULL};
    struct sysdb_subdom **list;
    struct ldb_dn *basedn;
    const char *tmp_str;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    basedn = ldb_dn_new(tmp_ctx, sysdb->ldb, SYSDB_BASE);
    if (basedn == NULL) {
        ret = EIO;
        goto done;
    }
    ret = ldb_search(sysdb->ldb, tmp_ctx, &res,
                     basedn, LDB_SCOPE_ONELEVEL,
                     attrs, "objectclass=%s", SYSDB_SUBDOMAIN_CLASS);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    list = talloc_zero_array(tmp_ctx, struct sysdb_subdom *, res->count);
    if (list == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < res->count; i++) {
        list[i] = talloc_zero(list, struct sysdb_subdom);
        if (list[i] == NULL) {
            ret = ENOMEM;
            goto done;
        }
        tmp_str = ldb_msg_find_attr_as_string(res->msgs[i], "cn", NULL);
        if (tmp_str == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("The object [%s] doesn't have a name\n",
                   ldb_dn_get_linearized(res->msgs[i]->dn)));
            ret = EINVAL;
            goto done;
        }

        list[i]->name = talloc_strdup(list, tmp_str);
        if (list[i]->name == NULL) {
            ret = ENOMEM;
            goto done;
        }

        tmp_str = ldb_msg_find_attr_as_string(res->msgs[i],
                                              SYSDB_SUBDOMAIN_REALM, NULL);
        if (tmp_str != NULL) {
            list[i]->realm = talloc_strdup(list, tmp_str);
            if (list[i]->realm == NULL) {
                ret = ENOMEM;
                goto done;
            }
        }

        tmp_str = ldb_msg_find_attr_as_string(res->msgs[i],
                                              SYSDB_SUBDOMAIN_FLAT, NULL);
        if (tmp_str != NULL) {
            list[i]->flat_name = talloc_strdup(list, tmp_str);
            if (list[i]->flat_name == NULL) {
                ret = ENOMEM;
                goto done;
            }
        }

        tmp_str = ldb_msg_find_attr_as_string(res->msgs[i],
                                              SYSDB_SUBDOMAIN_ID, NULL);
        if (tmp_str != NULL) {
            list[i]->id = talloc_strdup(list, tmp_str);
            if (list[i]->id == NULL) {
                ret = ENOMEM;
                goto done;
            }
        }
    }

    *subdomain_count = res->count;
    *subdomain_list = talloc_steal(mem_ctx, list);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_master_domain_get_info(TALLOC_CTX *mem_ctx,
                                     struct sysdb_ctx *sysdb,
                                     struct sysdb_subdom **_info)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    const char *tmp_str;
    struct ldb_dn *basedn;
    struct sysdb_subdom *info;
    struct ldb_result *res;
    const char *attrs[] = {"cn",
                           SYSDB_SUBDOMAIN_REALM,
                           SYSDB_SUBDOMAIN_FLAT,
                           SYSDB_SUBDOMAIN_ID,
                           NULL};

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    info = talloc_zero(tmp_ctx, struct sysdb_subdom);
    if (info == NULL) {
        ret = ENOMEM;
        goto done;
    }

    basedn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb, SYSDB_DOM_BASE,
                            sysdb->domain->name);
    if (basedn == NULL) {
        ret = EIO;
        goto done;
    }
    ret = ldb_search(sysdb->ldb, tmp_ctx, &res, basedn, LDB_SCOPE_BASE, attrs,
                     NULL);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    if (res->count == 0) {
        ret = ENOENT;
        goto done;
    }

    if (res->count > 1) {
        DEBUG(SSSDBG_OP_FAILURE, ("Base search returned [%d] results, "
                                 "expected 1.\n", res->count));
        ret = EINVAL;
        goto done;
    }

    tmp_str = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SUBDOMAIN_REALM,
                                          NULL);
    if (tmp_str != NULL) {
        info->realm = talloc_strdup(info, tmp_str);
        if (info->realm == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    tmp_str = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SUBDOMAIN_FLAT,
                                          NULL);
    if (tmp_str != NULL) {
        info->flat_name = talloc_strdup(info, tmp_str);
        if (info->flat_name == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    tmp_str = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SUBDOMAIN_ID,
                                          NULL);
    if (tmp_str != NULL) {
        info->flat_name = talloc_strdup(info, tmp_str);
        if (info->flat_name == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    *_info = talloc_steal(mem_ctx, info);
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_master_domain_add_info(struct sysdb_ctx *sysdb,
                                     struct sysdb_subdom *domain_info)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *msg;
    int ret;
    bool do_update = false;
    struct sysdb_subdom *current_info;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_master_domain_get_info(tmp_ctx, sysdb, &current_info);
    if (ret != EOK) {
        goto done;
    }

    msg = ldb_msg_new(tmp_ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb, SYSDB_DOM_BASE,
                             sysdb->domain->name);
    if (msg->dn == NULL) {
        ret = EIO;
        goto done;
    }

    if (domain_info->realm != NULL &&
        (current_info->realm == NULL ||
         strcmp(current_info->realm, domain_info->realm) != 0) ) {
        ret = ldb_msg_add_empty(msg, SYSDB_SUBDOMAIN_REALM,
                                LDB_FLAG_MOD_REPLACE, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_SUBDOMAIN_REALM,
                                 domain_info->realm);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        do_update = true;
    }

    if (domain_info->flat_name != NULL &&
        (current_info->flat_name == NULL ||
         strcmp(current_info->flat_name, domain_info->flat_name) != 0) ) {
        ret = ldb_msg_add_empty(msg, SYSDB_SUBDOMAIN_FLAT,
                                LDB_FLAG_MOD_REPLACE, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_SUBDOMAIN_FLAT,
                                 domain_info->flat_name);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        do_update = true;
    }

    if (domain_info->id != NULL &&
        (current_info->id == NULL ||
         strcmp(current_info->id, domain_info->id) != 0) ) {
        ret = ldb_msg_add_empty(msg, SYSDB_SUBDOMAIN_ID, LDB_FLAG_MOD_REPLACE,
                                NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_SUBDOMAIN_ID, domain_info->id);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        do_update = true;
    }

    if (do_update == false) {
        ret = EOK;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("Failed to add subdomain attributes to "
                                     "[%s]: [%d][%s]!\n",
                                     domain_info->name, ret,
                                     ldb_errstring(sysdb->ldb)));
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}
static errno_t sysdb_add_subdomain_attributes(struct sysdb_ctx *sysdb,
                                             struct sysdb_subdom *domain_info)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *msg;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    msg = ldb_msg_new(tmp_ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = ldb_dn_new_fmt(msg, sysdb->ldb, SYSDB_DOM_BASE,
                             domain_info->name);
    if (msg->dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, SYSDB_OBJECTCLASS, LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = ldb_msg_add_string(msg, SYSDB_OBJECTCLASS, SYSDB_SUBDOMAIN_CLASS);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    if (domain_info->realm != NULL) {
        ret = ldb_msg_add_empty(msg, SYSDB_SUBDOMAIN_REALM, LDB_FLAG_MOD_ADD,
                                NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_SUBDOMAIN_REALM,
                                 domain_info->realm);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    if (domain_info->flat_name != NULL) {
        ret = ldb_msg_add_empty(msg, SYSDB_SUBDOMAIN_FLAT, LDB_FLAG_MOD_ADD,
                                NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_SUBDOMAIN_FLAT,
                                 domain_info->flat_name);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    if (domain_info->id != NULL) {
        ret = ldb_msg_add_empty(msg, SYSDB_SUBDOMAIN_ID, LDB_FLAG_MOD_ADD,
                                NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_SUBDOMAIN_ID, domain_info->id);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("Failed to add subdomain attributes to "
                                     "[%s]: [%d][%s]!\n",
                                     domain_info->name, ret,
                                     ldb_errstring(sysdb->ldb)));
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t sysdb_update_subdomains(struct sysdb_ctx *sysdb,
                                int num_subdoms,
                                struct sysdb_subdom *subdoms)
{
    int ret;
    int sret;
    size_t c;
    size_t d;
    TALLOC_CTX *tmp_ctx = NULL;
    size_t cur_subdomains_count;
    struct sysdb_subdom **cur_subdomains;
    struct ldb_dn *dn;
    bool in_transaction = false;
    bool *keep_subdomain;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Retrieve all subdomains that are currently in sysdb */
    ret = sysdb_get_subdomains(tmp_ctx, sysdb, &cur_subdomains_count,
                               &cur_subdomains);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("sysdb_get_subdomains failed.\n"));
        goto done;
    }

    keep_subdomain = talloc_zero_array(tmp_ctx, bool, cur_subdomains_count);
    if (keep_subdomain == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_OP_FAILURE, ("talloc_zero_array failed.\n"));
        goto done;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("sysdb_transaction_start failed.\n"));
        goto done;
    }
    in_transaction = true;

    /* Go through a list of retrieved subdomains and:
     * - if a subdomain already exists in sysdb, mark it for preservation
     * - if the subdomain doesn't exist in sysdb, create its bare structure
     */
    for (c = 0; c < num_subdoms; c++) {
        for (d = 0; d < cur_subdomains_count; d++) {
            if (strcasecmp(subdoms[c].name,
                           cur_subdomains[d]->name) == 0) {
                keep_subdomain[d] = true;
                /* sub-domain already in cache, nothing to do */
                break;
            }
        }

        if (d == cur_subdomains_count) {
            DEBUG(SSSDBG_TRACE_FUNC, ("Adding sub-domain [%s].\n",
                                      subdoms[c].name));
            ret = sysdb_domain_create(sysdb, subdoms[c].name);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, ("sysdb_domain_create failed.\n"));
                goto done;
            }

            ret = sysdb_add_subdomain_attributes(sysdb, &subdoms[c]);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      ("sysdb_add_subdomain_attributes failed.\n"));
                goto done;
            }
        }
    }

    /* Now delete all subdomains that have been in sysdb prior to
     * refreshing the list and are not marked for preservation
     * (i.e. they are not in the new list of subdomains)
     */
    for (d = 0; d < cur_subdomains_count; d++) {
        if (!keep_subdomain[d]) {
            DEBUG(SSSDBG_TRACE_FUNC, ("Removing sub-domain [%s].\n",
                                      cur_subdomains[d]->name));
            dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb, SYSDB_DOM_BASE,
                                cur_subdomains[d]->name);
            if (dn == NULL) {
                ret = ENOMEM;
                goto done;
            }

            ret = sysdb_delete_recursive(sysdb, dn, true);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, ("sysdb_delete_recursive failed.\n"));
                goto done;
            }
        }
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret == EOK) {
        in_transaction = false;
    } else {
        DEBUG(SSSDBG_MINOR_FAILURE, ("Could not commit transaction\n"));
    }

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

errno_t sysdb_get_subdomain_context(TALLOC_CTX *mem_ctx,
                                    struct sysdb_ctx *sysdb,
                                    struct sss_domain_info *subdomain,
                                    struct sysdb_ctx **subdomain_ctx)
{
    struct sysdb_ctx *new_ctx;

    new_ctx = talloc_zero(mem_ctx, struct sysdb_ctx);
    if (new_ctx == NULL) {
        return ENOMEM;
    }

    new_ctx->domain = subdomain;
    new_ctx->mpg = true;

    new_ctx->ldb = sysdb->ldb;
    new_ctx->ldb_file = sysdb->ldb_file;

    *subdomain_ctx = new_ctx;

    return EOK;
}

#define CHECK_DOMAIN_INFO(dom_info) do { \
    if (dom_info == NULL || dom_info->sysdb == NULL) { \
        DEBUG(SSSDBG_OP_FAILURE, ("Invalid domain info.\n")); \
        return EINVAL; \
    } \
} while(0)

errno_t sysdb_search_domuser_by_name(TALLOC_CTX *mem_ctx,
                                     struct sss_domain_info *domain,
                                     const char *name,
                                     const char **attrs,
                                     struct ldb_message **msg)
{
    CHECK_DOMAIN_INFO(domain);

    return sysdb_search_user_by_name(mem_ctx, domain->sysdb, name, attrs, msg);
}

errno_t sysdb_search_domuser_by_uid(TALLOC_CTX *mem_ctx,
                                    struct sss_domain_info *domain,
                                    uid_t uid,
                                    const char **attrs,
                                    struct ldb_message **msg)
{
    CHECK_DOMAIN_INFO(domain);

    return sysdb_search_user_by_uid(mem_ctx, domain->sysdb, uid, attrs, msg);
}

errno_t sysdb_store_domuser(struct sss_domain_info *domain,
                            const char *name,
                            const char *pwd,
                            uid_t uid, gid_t gid,
                            const char *gecos,
                            const char *homedir,
                            const char *shell,
                            struct sysdb_attrs *attrs,
                            char **remove_attrs,
                            uint64_t cache_timeout,
                            time_t now)
{
    CHECK_DOMAIN_INFO(domain);

    return sysdb_store_user(domain->sysdb, name, pwd, uid, gid, gecos, homedir,
                            shell, attrs, remove_attrs, cache_timeout, now);
}

errno_t sysdb_delete_domuser(struct sss_domain_info *domain,
                             const char *name, uid_t uid)
{
    CHECK_DOMAIN_INFO(domain);

    return sysdb_delete_user(domain->sysdb, name, uid);
}

errno_t sysdb_search_domgroup_by_name(TALLOC_CTX *mem_ctx,
                                      struct sss_domain_info *domain,
                                      const char *name,
                                      const char **attrs,
                                      struct ldb_message **msg)
{
    CHECK_DOMAIN_INFO(domain);

    return sysdb_search_group_by_name(mem_ctx, domain->sysdb,
                                      name, attrs, msg);
}

errno_t sysdb_search_domgroup_by_gid(TALLOC_CTX *mem_ctx,
                                     struct sss_domain_info *domain,
                                     gid_t gid,
                                     const char **attrs,
                                     struct ldb_message **msg)
{
    CHECK_DOMAIN_INFO(domain);

    return sysdb_search_group_by_gid(mem_ctx, domain->sysdb, gid, attrs, msg);
}

errno_t sysdb_store_domgroup(struct sss_domain_info *domain,
                             const char *name,
                             gid_t gid,
                             struct sysdb_attrs *attrs,
                             uint64_t cache_timeout,
                             time_t now)
{
    CHECK_DOMAIN_INFO(domain);

    return sysdb_store_group(domain->sysdb, name, gid, attrs, cache_timeout,
                             now);
}

errno_t sysdb_delete_domgroup(struct sss_domain_info *domain,
                              const char *name, gid_t gid)
{
    CHECK_DOMAIN_INFO(domain);

    return sysdb_delete_group(domain->sysdb, name, gid);
}
