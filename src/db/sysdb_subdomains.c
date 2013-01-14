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

errno_t sysdb_get_subdomains(TALLOC_CTX *mem_ctx,
                             struct sss_domain_info *domain,
                             size_t *subdomain_count,
                             struct sss_domain_info ***subdomain_list)
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
    struct sss_domain_info **list;
    struct ldb_dn *basedn;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    basedn = ldb_dn_new(tmp_ctx, domain->sysdb->ldb, SYSDB_BASE);
    if (basedn == NULL) {
        ret = EIO;
        goto done;
    }
    ret = ldb_search(domain->sysdb->ldb, tmp_ctx, &res,
                     basedn, LDB_SCOPE_ONELEVEL,
                     attrs, "objectclass=%s", SYSDB_SUBDOMAIN_CLASS);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    list = talloc_zero_array(tmp_ctx, struct sss_domain_info *,
                             res->count + 1);
    if (list == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < res->count; i++) {
        const char *name;
        const char *realm;
        const char *flat;
        const char *id;

        name = ldb_msg_find_attr_as_string(res->msgs[i], "cn", NULL);
        if (name == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("The object [%s] doesn't have a name\n",
                   ldb_dn_get_linearized(res->msgs[i]->dn)));
            ret = EINVAL;
            goto done;
        }

        realm = ldb_msg_find_attr_as_string(res->msgs[i],
                                            SYSDB_SUBDOMAIN_REALM, NULL);

        flat = ldb_msg_find_attr_as_string(res->msgs[i],
                                           SYSDB_SUBDOMAIN_FLAT, NULL);

        id = ldb_msg_find_attr_as_string(res->msgs[i],
                                         SYSDB_SUBDOMAIN_ID, NULL);

        list[i] = new_subdomain(list, domain, name, realm, flat, id);
        if (list[i] == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    list[res->count] = NULL;

    *subdomain_count = res->count;
    *subdomain_list = talloc_steal(mem_ctx, list);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_master_domain_update(struct sss_domain_info *domain)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    const char *tmp_str;
    struct ldb_dn *basedn;
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

    basedn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                            SYSDB_DOM_BASE, domain->name);
    if (basedn == NULL) {
        ret = EIO;
        goto done;
    }
    ret = ldb_search(domain->sysdb->ldb, tmp_ctx, &res,
                     basedn, LDB_SCOPE_BASE, attrs, NULL);
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
    if (tmp_str != NULL &&
        (domain->realm == NULL || strcasecmp(tmp_str, domain->realm) != 0)) {
        talloc_free(domain->realm);
        domain->realm = talloc_strdup(domain, tmp_str);
        if (domain->realm == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    tmp_str = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SUBDOMAIN_FLAT,
                                          NULL);
    if (tmp_str != NULL &&
        (domain->flat_name == NULL ||
         strcasecmp(tmp_str, domain->flat_name) != 0)) {
        talloc_free(domain->flat_name);
        domain->flat_name = talloc_strdup(domain, tmp_str);
        if (domain->flat_name == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    tmp_str = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SUBDOMAIN_ID,
                                          NULL);
    if (tmp_str != NULL &&
        (domain->domain_id == NULL ||
         strcasecmp(tmp_str, domain->domain_id) != 0)) {
        talloc_free(domain->domain_id);
        domain->domain_id = talloc_strdup(domain, tmp_str);
        if (domain->domain_id == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_master_domain_add_info(struct sss_domain_info *domain,
                                     const char *realm, const char *flat,
                                     const char *id)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *msg;
    int ret;
    bool do_update = false;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_master_domain_update(domain);
    if (ret != EOK) {
        goto done;
    }

    msg = ldb_msg_new(tmp_ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                             SYSDB_DOM_BASE, domain->name);
    if (msg->dn == NULL) {
        ret = EIO;
        goto done;
    }

    if (realm != NULL && (domain->realm == NULL ||
                          strcmp(domain->realm, realm) != 0)) {
        ret = ldb_msg_add_empty(msg, SYSDB_SUBDOMAIN_REALM,
                                LDB_FLAG_MOD_REPLACE, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_SUBDOMAIN_REALM, realm);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        do_update = true;
    }

    if (flat != NULL && (domain->flat_name == NULL ||
                         strcmp(domain->flat_name, flat) != 0)) {
        ret = ldb_msg_add_empty(msg, SYSDB_SUBDOMAIN_FLAT,
                                LDB_FLAG_MOD_REPLACE, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_SUBDOMAIN_FLAT, flat);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        do_update = true;
    }

    if (id != NULL && (domain->domain_id == NULL ||
                       strcmp(domain->domain_id, id) != 0)) {
        ret = ldb_msg_add_empty(msg, SYSDB_SUBDOMAIN_ID,
                                LDB_FLAG_MOD_REPLACE, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_SUBDOMAIN_ID, id);
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

    ret = ldb_modify(domain->sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("Failed to add subdomain attributes to "
                                     "[%s]: [%d][%s]!\n", domain->name, ret,
                                     ldb_errstring(domain->sysdb->ldb)));
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t sysdb_subdomain_store(struct sysdb_ctx *sysdb,
                              const char *name, const char *realm,
                              const char *flat_name, const char *domain_id)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *msg;
    struct ldb_dn *dn;
    struct ldb_result *res;
    const char *attrs[] = {"cn",
                           SYSDB_SUBDOMAIN_REALM,
                           SYSDB_SUBDOMAIN_FLAT,
                           SYSDB_SUBDOMAIN_ID,
                           NULL};
    const char *tmp_str;
    bool store = false;
    int realm_flags = 0;
    int flat_flags = 0;
    int id_flags = 0;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb, SYSDB_DOM_BASE, name);
    if (dn == NULL) {
        ret = EIO;
        goto done;
    }
    ret = ldb_search(sysdb->ldb, tmp_ctx, &res,
                     dn, LDB_SCOPE_BASE, attrs, NULL);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    if (res->count == 0) {
        ret = sysdb_domain_create(sysdb, name);
        if (ret) {
            goto done;
        }
        store = true;
        if (realm) realm_flags = LDB_FLAG_MOD_ADD;
        if (flat_name) flat_flags = LDB_FLAG_MOD_ADD;
        if (domain_id) id_flags = LDB_FLAG_MOD_ADD;
    } else if (res->count != 1) {
        ret = EINVAL;
        goto done;
    } else { /* 1 found */
        if (realm) {
            tmp_str = ldb_msg_find_attr_as_string(res->msgs[0],
                                                  SYSDB_SUBDOMAIN_REALM, NULL);
            if (!tmp_str || strcasecmp(tmp_str, realm) != 0) {
                realm_flags = LDB_FLAG_MOD_REPLACE;
            }
        }
        if (flat_name) {
            tmp_str = ldb_msg_find_attr_as_string(res->msgs[0],
                                                  SYSDB_SUBDOMAIN_FLAT, NULL);
            if (!tmp_str || strcasecmp(tmp_str, flat_name) != 0) {
                flat_flags = LDB_FLAG_MOD_REPLACE;
            }
        }
        if (domain_id) {
            tmp_str = ldb_msg_find_attr_as_string(res->msgs[0],
                                                  SYSDB_SUBDOMAIN_ID, NULL);
            if (!tmp_str || strcasecmp(tmp_str, domain_id) != 0) {
                id_flags = LDB_FLAG_MOD_REPLACE;
            }
        }
    }

    if (!store && realm_flags == 0 && flat_flags == 0 && id_flags == 0) {
        ret = EOK;
        goto done;
    }

    msg = ldb_msg_new(tmp_ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = dn;

   if (store) {
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
    }

    if (realm_flags) {
        ret = ldb_msg_add_empty(msg, SYSDB_SUBDOMAIN_REALM, realm_flags, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_SUBDOMAIN_REALM, realm);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    if (flat_flags) {
        ret = ldb_msg_add_empty(msg, SYSDB_SUBDOMAIN_FLAT, flat_flags, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_SUBDOMAIN_FLAT, flat_name);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    if (id_flags) {
        ret = ldb_msg_add_empty(msg, SYSDB_SUBDOMAIN_ID, id_flags, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_SUBDOMAIN_ID, domain_id);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("Failed to add subdomain attributes to "
                                     "[%s]: [%d][%s]!\n", name, ret,
                                     ldb_errstring(sysdb->ldb)));
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t sysdb_update_subdomains(struct sss_domain_info *domain,
                                int num_subdoms,
                                struct sysdb_subdom *subdoms)
{
    int ret;
    int sret;
    size_t c;
    size_t d;
    TALLOC_CTX *tmp_ctx = NULL;
    size_t cur_subdomains_count;
    struct sss_domain_info **cur_subdomains;
    struct ldb_dn *dn;
    bool in_transaction = false;
    bool *keep_subdomain;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Retrieve all subdomains that are currently in sysdb */
    ret = sysdb_get_subdomains(tmp_ctx, domain, &cur_subdomains_count,
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

    ret = sysdb_transaction_start(domain->sysdb);
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
            struct sss_domain_info *ns;

            DEBUG(SSSDBG_TRACE_FUNC, ("Adding sub-domain [%s].\n",
                                      subdoms[c].name));

            ns = new_subdomain(tmp_ctx, domain,
                               subdoms[c].name, subdoms[c].realm,
                               subdoms[c].flat_name, subdoms[c].id);
            if (!ns) {
                DEBUG(SSSDBG_OP_FAILURE, ("new_subdomain failed.\n"));
                goto done;
            }

            ret = sysdb_subdomain_create(ns);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, ("sysdb_subdomain_create failed.\n"));
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
            dn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb, SYSDB_DOM_BASE,
                                cur_subdomains[d]->name);
            if (dn == NULL) {
                ret = ENOMEM;
                goto done;
            }

            ret = sysdb_delete_recursive(domain->sysdb, dn, true);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, ("sysdb_delete_recursive failed.\n"));
                goto done;
            }
        }
    }

    ret = sysdb_transaction_commit(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, ("Could not commit transaction\n"));
        goto done;
    }
    in_transaction = false;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(domain->sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Could not cancel transaction\n"));
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}
