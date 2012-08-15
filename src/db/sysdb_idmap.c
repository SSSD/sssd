/*
    SSSD

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

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


#include "db/sysdb.h"
#include "db/sysdb_private.h"

struct ldb_dn *
sysdb_idmap_dn(TALLOC_CTX *mem_ctx, struct sysdb_ctx *sysdb,
               const char *object_sid)
{
    errno_t ret;
    char *clean_sid;
    struct ldb_dn *dn;

    ret = sysdb_dn_sanitize(NULL, object_sid, &clean_sid);
    if (ret != EOK) {
        return NULL;
    }

    DEBUG(SSSDBG_TRACE_ALL,
          (SYSDB_TMPL_IDMAP"\n", clean_sid, sysdb->domain->name));

    dn = ldb_dn_new_fmt(mem_ctx, sysdb->ldb, SYSDB_TMPL_IDMAP,
                        clean_sid, sysdb->domain->name);
    talloc_free(clean_sid);

    return dn;
}

errno_t
sysdb_idmap_store_mapping(struct sysdb_ctx *sysdb,
                          const char *dom_name,
                          const char *dom_sid,
                          id_t slice_num)
{
    errno_t ret, sret;
    int lret;
    bool in_transaction = false;
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *dn;
    static const char *attrs[] = SYSDB_IDMAP_ATTRS;
    size_t count;
    struct ldb_message *update_msg;
    struct ldb_message **msgs;
    const char *old_name;
    id_t old_slice;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    dn = sysdb_idmap_dn(tmp_ctx, sysdb, dom_sid);
    if (!dn) {
        ret = ENOMEM;
        goto done;
    }

    update_msg = ldb_msg_new(tmp_ctx);
    if (!update_msg) {
        ret = ENOMEM;
        goto done;
    }
    update_msg->dn = dn;

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to start transaction\n"));
        goto done;
    }

    in_transaction = true;


    /* Check for an existing mapping */
    ret = sysdb_search_entry(tmp_ctx, sysdb, dn, LDB_SCOPE_BASE,
                             NULL, attrs, &count, &msgs);
    if (ret != EOK && ret != ENOENT) goto done;

    if (ret == EOK && count != 1) {
        /* More than one reply for a base search? */
        ret = EIO;
        goto done;
    } else if (ret == ENOENT) {
        /* Create a new mapping */
        DEBUG(SSSDBG_CONF_SETTINGS,
              ("Adding new ID mapping [%s][%s][%lu]\n",
               dom_name, dom_sid, (unsigned long)slice_num));

        /* Add the objectClass */
        lret = ldb_msg_add_empty(update_msg, SYSDB_OBJECTCLASS,
                                 LDB_FLAG_MOD_ADD,
                                 NULL);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_msg_add_string(update_msg, SYSDB_OBJECTCLASS,
                                  SYSDB_IDMAP_MAPPING_OC);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        /* Add the domain objectSID */
        lret = ldb_msg_add_empty(update_msg, SYSDB_IDMAP_SID_ATTR,
                                 LDB_FLAG_MOD_ADD,
                                 NULL);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_msg_add_string(update_msg, SYSDB_IDMAP_SID_ATTR, dom_sid);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        /* Add the domain name */
        lret = ldb_msg_add_empty(update_msg, SYSDB_NAME,
                                 LDB_FLAG_MOD_ADD,
                                 NULL);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_msg_add_string(update_msg, SYSDB_NAME, dom_name);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        /* Add the slice number */
        lret = ldb_msg_add_empty(update_msg, SYSDB_IDMAP_SLICE_ATTR,
                                 LDB_FLAG_MOD_ADD,
                                 NULL);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_msg_add_fmt(update_msg, SYSDB_IDMAP_SLICE_ATTR,
                               "%lu", (unsigned long)slice_num);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_add(sysdb->ldb, update_msg);
        if (lret != LDB_SUCCESS) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Failed to add mapping: [%s]\n",
                   ldb_strerror(lret)));
            ret = sysdb_error_to_errno(lret);
            goto done;
        }
    } else {
        /* Update the existing mapping */

        /* Check whether the slice has changed
         * This should never happen, and it's a recipe for
         * disaster. We'll throw an error if it does.
         */
        old_slice = ldb_msg_find_attr_as_int(msgs[0],
                                             SYSDB_IDMAP_SLICE_ATTR,
                                             -1);
        if (old_slice == -1) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("Could not identify original slice for SID [%s]\n",
                   dom_sid));
            ret = ENOENT;
            goto done;
        }

        if (slice_num != old_slice) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  ("Detected attempt to change slice value for sid [%s] "
                   "This will break existing users. Refusing to perform.\n"));
            ret = EINVAL;
            goto done;
        }

        /* Check whether the name has changed. This may happen
         * if we're told the real name of a domain and want to
         * replace the SID as placeholder.
         */
        old_name = ldb_msg_find_attr_as_string(msgs[0], SYSDB_NAME, NULL);
        if (!old_name) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("Could not identify original domain name of SID [%s]\n",
                   dom_sid));
            ret = ENOENT;
            goto done;
        }

        if (strcmp(old_name, dom_name) == 0) {
            /* There's nothing to be done. We don't need to
             * make any changes here. Just return success.
             */
            DEBUG(SSSDBG_TRACE_LIBS,
                  ("No changes needed, canceling transaction\n"));
            ret = EOK;
            goto done;
        } else {
            /* The name has changed. Replace it */
            DEBUG(SSSDBG_CONF_SETTINGS,
                  ("Changing domain name of SID [%s] from [%s] to [%s]\n",
                   dom_sid, old_name, dom_name));

            /* Set the new name */
            lret = ldb_msg_add_empty(update_msg, SYSDB_NAME,
                                     LDB_FLAG_MOD_REPLACE,
                                     NULL);
            if (lret != LDB_SUCCESS) {
                ret = sysdb_error_to_errno(lret);
                goto done;
            }

            lret = ldb_msg_add_string(update_msg, SYSDB_NAME, dom_name);
            if (lret != LDB_SUCCESS) {
                ret = sysdb_error_to_errno(lret);
                goto done;
            }
        }

        lret = ldb_modify(sysdb->ldb, update_msg);
        if (lret != LDB_SUCCESS) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Failed to update mapping: [%s]\n",
                   ldb_strerror(lret)));
            ret = sysdb_error_to_errno(lret);
            goto done;
        }
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Could not commit transaction: [%s]\n", strerror(ret)));
        goto done;
    }
    in_transaction = false;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("Could not cancel transaction\n"));
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_idmap_get_mappings(TALLOC_CTX *mem_ctx,
                         struct sysdb_ctx *sysdb,
                         struct ldb_result **_result)
{
    errno_t ret;
    int lret;
    struct ldb_dn *base_dn;
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    static const char *attrs[] = SYSDB_IDMAP_ATTRS;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    DEBUG(SSSDBG_TRACE_ALL,
          (SYSDB_TMPL_IDMAP_BASE"\n", sysdb->domain->name));

    base_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                             SYSDB_TMPL_IDMAP_BASE,
                             sysdb->domain->name);
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    lret = ldb_search(sysdb->ldb, tmp_ctx, &res, base_dn,
                     LDB_SCOPE_SUBTREE, attrs, SYSDB_IDMAP_FILTER);
    if (lret) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Could not locate ID mappings: [%s]\n",
               ldb_strerror(lret)));
        ret = sysdb_error_to_errno(lret);
        goto done;
    }

    *_result = talloc_steal(mem_ctx, res);

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}
