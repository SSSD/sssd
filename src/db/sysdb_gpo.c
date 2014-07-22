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

    DEBUG(SSSDBG_TRACE_FUNC, SYSDB_TMPL_GPO"\n", clean_gpo_guid, domain->name);

    dn = ldb_dn_new_fmt(mem_ctx, domain->sysdb->ldb, SYSDB_TMPL_GPO,
                        clean_gpo_guid, domain->name);
    talloc_free(clean_gpo_guid);

    return dn;
}

errno_t
sysdb_gpo_store_gpo(struct sss_domain_info *domain,
                    const char *gpo_guid,
                    int gpo_version)
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

        DEBUG(SSSDBG_TRACE_FUNC,
              "Updating new GPO [%s][%s]\n", domain->name, gpo_guid);

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

        lret = ldb_modify(domain->sysdb->ldb, update_msg);
        if (lret != LDB_SUCCESS) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to modify GPO: [%s]\n", ldb_strerror(lret));
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
sysdb_gpo_get_gpo(TALLOC_CTX *mem_ctx,
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

    DEBUG(SSSDBG_TRACE_FUNC, SYSDB_TMPL_GPO_BASE"\n", domain->name);

    base_dn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                             SYSDB_TMPL_GPO_BASE,
                             domain->name);
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    lret = ldb_search(domain->sysdb->ldb, tmp_ctx, &res, base_dn,
                      LDB_SCOPE_SUBTREE, attrs, SYSDB_GPO_FILTER, gpo_guid);
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
