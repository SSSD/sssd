/*
    SSSD

    Authors:
        Yassir Elley <yelley@redhat.com>

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


#include "db/sysdb.h"
#include "db/sysdb_private.h"

static struct ldb_dn *
sysdb_gpo_dn(TALLOC_CTX *mem_ctx, struct sss_domain_info *domain,
             const char *gpo_guid)
{
    errno_t ret;
    char *clean_gpo_guid;
    struct ldb_dn *dn;

    ret = sysdb_dn_sanitize(NULL, gpo_guid, &clean_gpo_guid);
    if (ret != EOK) {
        return NULL;
    }

    DEBUG(SSSDBG_TRACE_ALL, SYSDB_TMPL_GPO"\n", clean_gpo_guid, domain->name);

    dn = ldb_dn_new_fmt(mem_ctx, domain->sysdb->ldb, SYSDB_TMPL_GPO,
                        clean_gpo_guid, domain->name);
    talloc_free(clean_gpo_guid);

    return dn;
}

errno_t
sysdb_gpo_store_gpo(struct sss_domain_info *domain,
                    const char *gpo_guid,
                    int gpo_version,
                    int cache_timeout,
                    time_t now)
{
    errno_t ret, sret;
    int lret;
    struct ldb_message *update_msg;
    struct ldb_message **msgs;
    static const char *attrs[] = SYSDB_GPO_ATTRS;
    size_t count;
    bool in_transaction = false;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    update_msg = ldb_msg_new(tmp_ctx);
    if (!update_msg) {
        ret = ENOMEM;
        goto done;
    }

    update_msg->dn = sysdb_gpo_dn(update_msg, domain, gpo_guid);
    if (!update_msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_transaction_start(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto done;
    }

    if (!now) {
        now = time(NULL);
    }

    in_transaction = true;

    /* Check for an existing gpo_guid entry */
    ret = sysdb_search_entry(tmp_ctx, domain->sysdb, update_msg->dn,
                             LDB_SCOPE_BASE, NULL, attrs, &count, &msgs);

    if (ret == ENOENT) {
        /* Create new GPO */
        DEBUG(SSSDBG_TRACE_FUNC,
              "Adding new GPO [gpo_guid:%s][gpo_version:%d]\n",
              gpo_guid, gpo_version);

        /* Add the objectClass */
        lret = ldb_msg_add_empty(update_msg, SYSDB_OBJECTCLASS,
                                 LDB_FLAG_MOD_ADD,
                                 NULL);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_msg_add_string(update_msg, SYSDB_OBJECTCLASS,
                                  SYSDB_GPO_OC);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        /* Add the GPO GUID */
        lret = ldb_msg_add_empty(update_msg, SYSDB_GPO_GUID_ATTR,
                                 LDB_FLAG_MOD_ADD,
                                 NULL);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_msg_add_string(update_msg, SYSDB_GPO_GUID_ATTR, gpo_guid);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        /* Add the Version */
        lret = ldb_msg_add_empty(update_msg, SYSDB_GPO_VERSION_ATTR,
                                 LDB_FLAG_MOD_ADD,
                                 NULL);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_msg_add_fmt(update_msg, SYSDB_GPO_VERSION_ATTR,
                               "%d", gpo_version);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        /* Add the Policy File Timeout */
        lret = ldb_msg_add_empty(update_msg, SYSDB_GPO_TIMEOUT_ATTR,
                                 LDB_FLAG_MOD_ADD, NULL);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_msg_add_fmt(update_msg, SYSDB_GPO_TIMEOUT_ATTR, "%"SPRItime,
                               ((cache_timeout) ? (now + cache_timeout) : 0));
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_add(domain->sysdb->ldb, update_msg);
        if (lret != LDB_SUCCESS) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to add GPO: [%s]\n",
                   ldb_strerror(lret));
            ret = sysdb_error_to_errno(lret);
            goto done;
        }
    } else if (ret == EOK && count == 1) {
        /* Update the existing GPO */

        DEBUG(SSSDBG_TRACE_ALL, "Updating new GPO [%s][%s]\n", domain->name, gpo_guid);

        /* Add the Version */
        lret = ldb_msg_add_empty(update_msg, SYSDB_GPO_VERSION_ATTR,
                                 LDB_FLAG_MOD_REPLACE,
                                 NULL);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_msg_add_fmt(update_msg, SYSDB_GPO_VERSION_ATTR,
                               "%d", gpo_version);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        /* Add the Policy File Timeout */
        lret = ldb_msg_add_empty(update_msg, SYSDB_GPO_TIMEOUT_ATTR,
                                 LDB_FLAG_MOD_REPLACE, NULL);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_msg_add_fmt(update_msg, SYSDB_GPO_TIMEOUT_ATTR, "%"SPRItime,
                               ((cache_timeout) ? (now + cache_timeout) : 0));
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_modify(domain->sysdb->ldb, update_msg);
        if (lret != LDB_SUCCESS) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to modify GPO: [%s](%d)[%s]\n",
                  ldb_strerror(lret), lret, ldb_errstring(domain->sysdb->ldb));
            ret = sysdb_error_to_errno(lret);
            goto done;
        }
    } else {
        ret = EIO;
        goto done;
    }

    ret = sysdb_transaction_commit(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not commit transaction: [%s]\n", strerror(ret));
        goto done;
    }
    in_transaction = false;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(domain->sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not cancel transaction\n");
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_gpo_get_gpo_by_guid(TALLOC_CTX *mem_ctx,
                          struct sss_domain_info *domain,
                          const char *gpo_guid,
                          struct ldb_result **_result)
{
    errno_t ret;
    int lret;
    struct ldb_dn *base_dn;
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;

    const char *attrs[] = SYSDB_GPO_ATTRS;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    DEBUG(SSSDBG_TRACE_ALL, SYSDB_TMPL_GPO_BASE"\n", domain->name);

    base_dn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                             SYSDB_TMPL_GPO_BASE,
                             domain->name);
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    lret = ldb_search(domain->sysdb->ldb, tmp_ctx, &res, base_dn,
                      LDB_SCOPE_SUBTREE, attrs, SYSDB_GPO_GUID_FILTER, gpo_guid);
    if (lret) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not locate GPO: [%s]\n",
              ldb_strerror(lret));
        ret = sysdb_error_to_errno(lret);
        goto done;
    }

    if (res->count > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Search for GUID [%s] returned more than " \
              "one object.\n", gpo_guid);
        ret = EINVAL;
        goto done;
    } else if (res->count == 0) {
        ret = ENOENT;
        goto done;
    }
    *_result = talloc_steal(mem_ctx, res);
    ret = EOK;
done:

    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_ALL, "No such entry.\n");
    } else if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
    }

    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_gpo_get_gpos(TALLOC_CTX *mem_ctx,
                   struct sss_domain_info *domain,
                   struct ldb_result **_result)
{
    errno_t ret;
    int lret;
    struct ldb_dn *base_dn;
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;

    const char *attrs[] = SYSDB_GPO_ATTRS;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    DEBUG(SSSDBG_TRACE_ALL, SYSDB_TMPL_GPO_BASE"\n", domain->name);

    base_dn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                             SYSDB_TMPL_GPO_BASE,
                             domain->name);
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    lret = ldb_search(domain->sysdb->ldb, tmp_ctx, &res, base_dn,
                      LDB_SCOPE_SUBTREE, attrs, SYSDB_GPO_FILTER);
    if (lret) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not locate GPOs: [%s]\n",
              ldb_strerror(lret));
        ret = sysdb_error_to_errno(lret);
        goto done;
    }

    if (res->count == 0) {
        ret = ENOENT;
        goto done;
    }

    *_result = talloc_steal(mem_ctx, res);
    ret = EOK;

done:

    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_ALL, "No GPO entries.\n");
    } else if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
    }

    talloc_free(tmp_ctx);
    return ret;
}

/* GPO Result */

static struct ldb_dn *
sysdb_gpo_result_dn(TALLOC_CTX *mem_ctx,
                    struct sss_domain_info *domain,
                    const char *result_name)
{
    errno_t ret;
    char *clean_result_name;
    struct ldb_dn *dn;

    ret = sysdb_dn_sanitize(NULL, result_name, &clean_result_name);
    if (ret != EOK) {
        return NULL;
    }

    DEBUG(SSSDBG_TRACE_ALL, SYSDB_TMPL_GPO_RESULT"\n",
          clean_result_name, domain->name);

    dn = ldb_dn_new_fmt(mem_ctx, domain->sysdb->ldb, SYSDB_TMPL_GPO_RESULT,
                        clean_result_name, domain->name);
    talloc_free(clean_result_name);

    return dn;
}

errno_t
sysdb_gpo_store_gpo_result_setting(struct sss_domain_info *domain,
                                   const char *ini_key,
                                   const char *ini_value)
{
    errno_t ret, sret;
    int lret;
    struct ldb_message *update_msg;
    struct ldb_message **msgs;
    size_t count;
    bool in_transaction = false;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    update_msg = ldb_msg_new(tmp_ctx);
    if (!update_msg) {
        ret = ENOMEM;
        goto done;
    }

    update_msg->dn = sysdb_gpo_result_dn(update_msg, domain, "gpo_result");
    if (!update_msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_transaction_start(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto done;
    }

    in_transaction = true;

    /* Check for an existing GPO Result object */
    ret = sysdb_search_entry(tmp_ctx, domain->sysdb, update_msg->dn,
                             LDB_SCOPE_BASE, NULL, NULL, &count, &msgs);

    if (ret == ENOENT) {
        /* Create new GPO Result object */
        DEBUG(SSSDBG_TRACE_FUNC, "Storing setting: key [%s] value [%s]\n",
              ini_key, ini_value);

        /* Add the objectClass */
        lret = ldb_msg_add_empty(update_msg, SYSDB_OBJECTCLASS,
                                 LDB_FLAG_MOD_ADD,
                                 NULL);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_msg_add_string(update_msg, SYSDB_OBJECTCLASS,
                                  SYSDB_GPO_RESULT_OC);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        /* Store the policy_setting if it is non-NULL */
        if (ini_value) {
            lret = ldb_msg_add_empty(update_msg, ini_key,
                                     LDB_FLAG_MOD_ADD,
                                     NULL);
            if (lret != LDB_SUCCESS) {
                ret = sysdb_error_to_errno(lret);
                goto done;
            }

            lret = ldb_msg_add_string(update_msg, ini_key, ini_value);
            if (lret != LDB_SUCCESS) {
                ret = sysdb_error_to_errno(lret);
                goto done;
            }
        }

        lret = ldb_add(domain->sysdb->ldb, update_msg);
        if (lret != LDB_SUCCESS) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to add GPO Result: [%s]\n",
                   ldb_strerror(lret));
            ret = sysdb_error_to_errno(lret);
            goto done;
        }
    } else if (ret == EOK && count == 1) {
        /* Update existing GPO Result object*/
        if (ini_value) {
            DEBUG(SSSDBG_TRACE_FUNC, "Updating setting: key [%s] value [%s]\n",
                  ini_key, ini_value);
            /* Update the policy setting */
            lret = ldb_msg_add_empty(update_msg, ini_key,
                                     LDB_FLAG_MOD_REPLACE,
                                     NULL);
            if (lret != LDB_SUCCESS) {
                ret = sysdb_error_to_errno(lret);
                goto done;
            }

            lret = ldb_msg_add_fmt(update_msg, ini_key, "%s", ini_value);
            if (lret != LDB_SUCCESS) {
                ret = sysdb_error_to_errno(lret);
                goto done;
            }
        } else {
            /* If the value is NULL, we need to remove it from the cache */
            DEBUG(SSSDBG_TRACE_FUNC, "Removing setting: key [%s]\n", ini_key);

            /* Update the policy setting */
            lret = ldb_msg_add_empty(update_msg, ini_key,
                                     LDB_FLAG_MOD_DELETE,
                                     NULL);
            if (lret != LDB_SUCCESS) {
                ret = sysdb_error_to_errno(lret);
                goto done;
            }
        }

        lret = ldb_modify(domain->sysdb->ldb, update_msg);
        if (lret != LDB_SUCCESS) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to modify GPO Result: [%s](%d)[%s]\n",
                  ldb_strerror(lret), lret, ldb_errstring(domain->sysdb->ldb));
            ret = sysdb_error_to_errno(lret);
            goto done;
        }
    } else {
        ret = EIO;
        goto done;
    }

    ret = sysdb_transaction_commit(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not commit transaction: [%s]\n", strerror(ret));
        goto done;
    }
    in_transaction = false;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(domain->sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not cancel transaction\n");
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
sysdb_gpo_get_gpo_result_object(TALLOC_CTX *mem_ctx,
                                struct sss_domain_info *domain,
                                const char **attrs,
                                struct ldb_result **_result)
{
    errno_t ret;
    int lret;
    struct ldb_dn *base_dn;
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    DEBUG(SSSDBG_TRACE_ALL, SYSDB_TMPL_GPO_RESULT_BASE"\n", domain->name);

    base_dn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                             SYSDB_TMPL_GPO_RESULT_BASE,
                             domain->name);
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    lret = ldb_search(domain->sysdb->ldb, tmp_ctx, &res, base_dn,
                      LDB_SCOPE_SUBTREE, attrs, SYSDB_GPO_RESULT_FILTER);
    if (lret) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not locate GPO Result object: [%s]\n",
              ldb_strerror(lret));
        ret = sysdb_error_to_errno(lret);
        goto done;
    }

    if (res->count == 0) {
        ret = ENOENT;
        goto done;
    }

    *_result = talloc_steal(mem_ctx, res);
    ret = EOK;

done:

    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_ALL, "No GPO Result object.\n");
    } else if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
    }

    talloc_free(tmp_ctx);
    return ret;
}


errno_t
sysdb_gpo_get_gpo_result_setting(TALLOC_CTX *mem_ctx,
                                 struct sss_domain_info *domain,
                                 const char *ini_key,
                                 const char **_ini_value)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    const char *ini_value;

    const char *attrs[] = {ini_key, NULL};

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    ret = sysdb_gpo_get_gpo_result_object(tmp_ctx, domain, attrs, &res);
    if (ret != EOK) {
        goto done;
    }

    ini_value = ldb_msg_find_attr_as_string(res->msgs[0],
                                            ini_key,
                                            NULL);
    DEBUG(SSSDBG_TRACE_FUNC, "key [%s] value [%s]\n", ini_key, ini_value);

    *_ini_value = talloc_strdup(mem_ctx, ini_value);
    if (!*_ini_value && ini_value) {
        /* If ini_value was NULL, this is expected to also be NULL */
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;

done:

    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_ALL, "No setting for key [%s].\n", ini_key);
    } else if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
    }

    talloc_free(tmp_ctx);
    return ret;
}


errno_t sysdb_gpo_delete_gpo_result_object(TALLOC_CTX *mem_ctx,
                                           struct sss_domain_info *domain)
{
    struct ldb_result *res;
    errno_t ret, sret;
    bool in_transaction = false;

    ret = sysdb_transaction_start(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto done;
    }

    in_transaction = true;

    ret = sysdb_gpo_get_gpo_result_object(mem_ctx, domain, NULL, &res);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not delete GPO result object: %d\n", ret);
        goto done;
    } else if (ret != ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, "Deleting GPO Result object\n");

        ret = sysdb_delete_entry(domain->sysdb, res->msgs[0]->dn, true);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Could not delete GPO Result cache entry\n");
            goto done;
        }
    }

    ret = sysdb_transaction_commit(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not commit transaction: [%s]\n", strerror(ret));
        goto done;
    }
    in_transaction = false;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(domain->sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not cancel transaction\n");
        }
    }
    return ret;

}
