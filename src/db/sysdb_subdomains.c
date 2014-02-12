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

errno_t sysdb_update_subdomains(struct sss_domain_info *domain)
{
    int i;
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    const char *attrs[] = {"cn",
                           SYSDB_SUBDOMAIN_REALM,
                           SYSDB_SUBDOMAIN_FLAT,
                           SYSDB_SUBDOMAIN_ID,
                           SYSDB_SUBDOMAIN_MPG,
                           SYSDB_SUBDOMAIN_ENUM,
                           SYSDB_SUBDOMAIN_FOREST,
                           NULL};
    struct sss_domain_info *dom;
    struct ldb_dn *basedn;
    const char *name;
    const char *realm;
    const char *flat;
    const char *id;
    const char *forest;
    bool mpg;
    bool enumerate;

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

    /* disable all domains,
     * let the search result refresh any that are still valid */
    for (dom = domain->subdomains; dom; dom = get_next_domain(dom, false)) {
        dom->disabled = true;
    }

    if (res->count == 0) {
        ret = EOK;
        goto done;
    }

    for (i = 0; i < res->count; i++) {

        name = ldb_msg_find_attr_as_string(res->msgs[i], "cn", NULL);
        if (name == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "The object [%s] doesn't have a name\n",
                   ldb_dn_get_linearized(res->msgs[i]->dn));
            ret = EINVAL;
            goto done;
        }

        realm = ldb_msg_find_attr_as_string(res->msgs[i],
                                            SYSDB_SUBDOMAIN_REALM, NULL);

        flat = ldb_msg_find_attr_as_string(res->msgs[i],
                                           SYSDB_SUBDOMAIN_FLAT, NULL);

        id = ldb_msg_find_attr_as_string(res->msgs[i],
                                         SYSDB_SUBDOMAIN_ID, NULL);

        mpg = ldb_msg_find_attr_as_bool(res->msgs[i],
                                        SYSDB_SUBDOMAIN_MPG, false);

        enumerate = ldb_msg_find_attr_as_bool(res->msgs[i],
                                              SYSDB_SUBDOMAIN_ENUM, false);

        forest = ldb_msg_find_attr_as_string(res->msgs[i],
                                             SYSDB_SUBDOMAIN_FOREST, NULL);

        /* explicitly use dom->next as we need to check 'disabled' domains */
        for (dom = domain->subdomains; dom; dom = dom->next) {
            if (strcasecmp(dom->name, name) == 0) {
                dom->disabled = false;
                /* in theory these may change, but it should never happen */
                if (strcasecmp(dom->realm, realm) != 0) {
                    DEBUG(SSSDBG_TRACE_INTERNAL,
                          "Realm name changed from [%s] to [%s]!\n",
                           dom->realm, realm);
                    talloc_zfree(dom->realm);
                    dom->realm = talloc_strdup(dom, realm);
                    if (dom->realm == NULL) {
                        ret = ENOMEM;
                        goto done;
                    }
                }
                if (strcasecmp(dom->flat_name, flat) != 0) {
                    DEBUG(SSSDBG_TRACE_INTERNAL,
                          "Flat name changed from [%s] to [%s]!\n",
                           dom->flat_name, flat);
                    talloc_zfree(dom->flat_name);
                    dom->flat_name = talloc_strdup(dom, flat);
                    if (dom->flat_name == NULL) {
                        ret = ENOMEM;
                        goto done;
                    }
                }
                if (strcasecmp(dom->domain_id, id) != 0) {
                    DEBUG(SSSDBG_TRACE_INTERNAL,
                          "Domain changed from [%s] to [%s]!\n",
                           dom->domain_id, id);
                    talloc_zfree(dom->domain_id);
                    dom->domain_id = talloc_strdup(dom, id);
                    if (dom->domain_id == NULL) {
                        ret = ENOMEM;
                        goto done;
                    }
                }

                if (dom->mpg != mpg) {
                    DEBUG(SSSDBG_TRACE_INTERNAL,
                          "MPG state change from [%s] to [%s]!\n",
                           dom->mpg ? "true" : "false",
                           mpg ? "true" : "false");
                    dom->mpg = mpg;
                }

                if (dom->enumerate != enumerate) {
                    DEBUG(SSSDBG_TRACE_INTERNAL,
                          "MPG state change from [%s] to [%s]!\n",
                           dom->enumerate ? "true" : "false",
                           enumerate ? "true" : "false");
                    dom->enumerate = enumerate;
                }

                if ((dom->forest == NULL && forest != NULL)
                        || (dom->forest != NULL && forest != NULL
                            && strcasecmp(dom->forest, forest) != 0)) {
                    DEBUG(SSSDBG_TRACE_INTERNAL,
                          "Forest changed from [%s] to [%s]!\n",
                           dom->forest, forest);
                    talloc_zfree(dom->forest);
                    dom->forest = talloc_strdup(dom, forest);
                    if (dom->forest == NULL) {
                        ret = ENOMEM;
                        goto done;
                    }
                }

                break;
            }
        }
        /* If not found in loop it is a new subdomain */
        if (dom == NULL) {
            dom = new_subdomain(domain, domain, name, realm,
                                flat, id, mpg, enumerate, forest);
            if (dom == NULL) {
                ret = ENOMEM;
                goto done;
            }
            DLIST_ADD_END(domain->subdomains, dom, struct sss_domain_info *);
        }
    }

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
                           SYSDB_SUBDOMAIN_FOREST,
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
        DEBUG(SSSDBG_OP_FAILURE, "Base search returned [%d] results, "
                                 "expected 1.\n", res->count);
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

    tmp_str = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SUBDOMAIN_FOREST,
                                          NULL);
    if (tmp_str != NULL &&
        (domain->forest == NULL ||
         strcasecmp(tmp_str, domain->forest) != 0)) {
        talloc_free(domain->forest);
        domain->forest = talloc_strdup(domain, tmp_str);
        if (domain->forest == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_master_domain_add_info(struct sss_domain_info *domain,
                                     const char *flat, const char *id,
                                     const char* forest)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *msg;
    int ret;
    bool do_update = false;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
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

   if (forest != NULL && (domain->forest == NULL ||
                       strcmp(domain->forest, forest) != 0)) {
        ret = ldb_msg_add_empty(msg, SYSDB_SUBDOMAIN_FOREST,
                                LDB_FLAG_MOD_REPLACE, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_SUBDOMAIN_FOREST, forest);
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
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to add subdomain attributes to "
                                     "[%s]: [%d][%s]!\n", domain->name, ret,
                                     ldb_errstring(domain->sysdb->ldb));
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = sysdb_master_domain_update(domain);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t sysdb_subdomain_store(struct sysdb_ctx *sysdb,
                              const char *name, const char *realm,
                              const char *flat_name, const char *domain_id,
                              bool mpg, bool enumerate, const char *forest)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *msg;
    struct ldb_dn *dn;
    struct ldb_result *res;
    const char *attrs[] = {"cn",
                           SYSDB_SUBDOMAIN_REALM,
                           SYSDB_SUBDOMAIN_FLAT,
                           SYSDB_SUBDOMAIN_ID,
                           SYSDB_SUBDOMAIN_MPG,
                           SYSDB_SUBDOMAIN_ENUM,
                           SYSDB_SUBDOMAIN_FOREST,
                           NULL};
    const char *tmp_str;
    bool tmp_bool;
    bool store = false;
    int realm_flags = 0;
    int flat_flags = 0;
    int id_flags = 0;
    int mpg_flags = 0;
    int enum_flags = 0;
    int forest_flags = 0;
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
        mpg_flags = LDB_FLAG_MOD_ADD;
        enum_flags = LDB_FLAG_MOD_ADD;
        if (forest) forest_flags = LDB_FLAG_MOD_ADD;
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

        tmp_bool = ldb_msg_find_attr_as_bool(res->msgs[0], SYSDB_SUBDOMAIN_MPG,
                                             !mpg);
        if (tmp_bool != mpg) {
            mpg_flags = LDB_FLAG_MOD_REPLACE;
        }
        tmp_bool = ldb_msg_find_attr_as_bool(res->msgs[0], SYSDB_SUBDOMAIN_ENUM,
                                             !enumerate);
        if (tmp_bool != enumerate) {
            enum_flags = LDB_FLAG_MOD_REPLACE;
        }

        if (forest) {
            tmp_str = ldb_msg_find_attr_as_string(res->msgs[0],
                                                  SYSDB_SUBDOMAIN_FOREST, NULL);
            if (!tmp_str || strcasecmp(tmp_str, forest) != 0) {
                forest_flags = LDB_FLAG_MOD_REPLACE;
            }
        }
    }

    if (!store && realm_flags == 0 && flat_flags == 0 && id_flags == 0
            && mpg_flags == 0 && enum_flags == 0 && forest_flags == 0) {
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

    if (mpg_flags) {
        ret = ldb_msg_add_empty(msg, SYSDB_SUBDOMAIN_MPG, mpg_flags, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_SUBDOMAIN_MPG,
                                 mpg ? "TRUE" : "FALSE");
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    if (enum_flags) {
        ret = ldb_msg_add_empty(msg, SYSDB_SUBDOMAIN_ENUM, enum_flags, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_SUBDOMAIN_ENUM,
                                 enumerate ? "TRUE" : "FALSE");
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    if (forest_flags) {
        ret = ldb_msg_add_empty(msg, SYSDB_SUBDOMAIN_FOREST, forest_flags,
                                NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_SUBDOMAIN_FOREST, forest);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to add subdomain attributes to "
                                     "[%s]: [%d][%s]!\n", name, ret,
                                     ldb_errstring(sysdb->ldb));
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t sysdb_subdomain_delete(struct sysdb_ctx *sysdb, const char *name)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct ldb_dn *dn;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Removing sub-domain [%s] from db.\n", name);
    dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb, SYSDB_DOM_BASE, name);
    if (dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_delete_recursive(sysdb, dn, true);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_delete_recursive failed.\n");
        goto done;
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}
