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

#include <stdbool.h>

#include "util/util.h"
#include "db/sysdb_private.h"
#include "db/sysdb_services.h"
#include "db/sysdb_autofs.h"
#include "db/sysdb_iphosts.h"
#include "db/sysdb_ipnetworks.h"
#include "util/crypto/sss_crypto.h"
#include "util/cert.h"
#include <time.h>

#define SSS_SYSDB_NO_CACHE 0x0
#define SSS_SYSDB_CACHE 0x1
#define SSS_SYSDB_TS_CACHE 0x2
#define SSS_SYSDB_BOTH_CACHE (SSS_SYSDB_CACHE | SSS_SYSDB_TS_CACHE)

/*
 * The wrapper around ldb_modify that optionally uses
 * LDB_CONTROL_PERMISSIVE_MODIFY_OID so that on adds entries that already
 * exist are skipped and similarly entries that are missing are ignored
 * on deletes.
 *
 * Please note this function returns LDB error codes, not sysdb error
 * codes on purpose, see usage in callers!
 */
int sss_ldb_modify(struct ldb_context *ldb,
                   struct ldb_message *msg,
                   bool permissive)
{
    struct ldb_request *req;
    int ret;
    int cancel_ret;
    bool in_transaction = false;

    ret = ldb_build_mod_req(&req, ldb, ldb,
                            msg,
                            NULL,
                            NULL,
                            ldb_op_default_callback,
                            NULL);

    if (ret != LDB_SUCCESS) return ret;

    if (permissive) {
        ret = ldb_request_add_control(req, LDB_CONTROL_PERMISSIVE_MODIFY_OID,
                                      false, NULL);
        if (ret != LDB_SUCCESS) {
            talloc_free(req);
            return ret;
        }
    }

    ret = ldb_transaction_start(ldb);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to start ldb transaction [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    in_transaction = true;

    ret = ldb_request(ldb, req);
    if (ret == LDB_SUCCESS) {
        ret = ldb_wait(req->handle, LDB_WAIT_ALL);
        if (ret != LDB_SUCCESS) {
            goto done;
        }
    }

    ret = ldb_transaction_commit(ldb);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to commit ldb transaction [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    in_transaction = false;

    ret = LDB_SUCCESS;

done:
    if (in_transaction) {
        cancel_ret = ldb_transaction_cancel(ldb);
        if (cancel_ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to cancel ldb transaction [%d]: %s\n",
                  cancel_ret, sss_strerror(cancel_ret));
        }
    }

    talloc_free(req);

    /* Please note this function returns LDB error codes, not sysdb error
     * codes on purpose, see usage in callers!
     */
    return ret;
}

int sss_ldb_modify_permissive(struct ldb_context *ldb,
                              struct ldb_message *msg)
{
    return sss_ldb_modify(ldb, msg, true);
}

#define ERROR_OUT(v, r, l) do { v = r; goto l; } while(0)


/* =Remove-Entry-From-Sysdb=============================================== */
static int sysdb_delete_cache_entry(struct ldb_context *ldb,
                                    struct ldb_dn *dn,
                                    bool ignore_not_found)
{
    int ret;

    ret = ldb_delete(ldb, dn);
    switch (ret) {
    case LDB_SUCCESS:
        return EOK;
    case LDB_ERR_NO_SUCH_OBJECT:
        if (ignore_not_found) {
            return EOK;
        }
        /* fall through */
        SSS_ATTRIBUTE_FALLTHROUGH;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "LDB Error: %s (%d); error message: [%s]\n",
                  ldb_strerror(ret), ret, ldb_errstring(ldb));
        return sysdb_error_to_errno(ret);
    }
}

static int sysdb_delete_ts_entry(struct sysdb_ctx *sysdb,
                                 struct ldb_dn *dn)
{
    if (sysdb->ldb_ts == NULL) {
        return EOK;
    }

    return sysdb_delete_cache_entry(sysdb->ldb_ts, dn, true);
}

int sysdb_delete_entry(struct sysdb_ctx *sysdb,
                       struct ldb_dn *dn,
                       bool ignore_not_found)
{
    errno_t ret;
    errno_t tret;

    ret = sysdb_delete_cache_entry(sysdb->ldb, dn, ignore_not_found);
    if (ret == EOK) {
        tret = sysdb_delete_ts_entry(sysdb, dn);
        if (tret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "sysdb_delete_ts_entry failed: %d\n", tret);
            /* Not fatal */
        }
    } else {
        DEBUG(SSSDBG_OP_FAILURE,
              "sysdb_delete_cache_entry failed: %d\n", ret);
    }

    return ret;
}

/* =Remove-Subentries-From-Sysdb=========================================== */

int sysdb_delete_recursive_with_filter(struct sysdb_ctx *sysdb,
                                       struct ldb_dn *dn,
                                       bool ignore_not_found,
                                       const char *filter)
{
    const char *no_attrs[] = { NULL };
    struct ldb_message **msgs;
    size_t msgs_count;
    int ret;
    int i;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = ldb_transaction_start(sysdb->ldb);
    if (ret) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = sysdb_search_entry(tmp_ctx, sysdb, dn,
                             LDB_SCOPE_SUBTREE, filter,
                             no_attrs, &msgs_count, &msgs);
    if (ret) {
        if (ignore_not_found && ret == ENOENT) {
            ret = EOK;
        }
        if (ret) {
            DEBUG(SSSDBG_TRACE_FUNC, "Search error: %d (%s)\n",
                                     ret, strerror(ret));
        }
        goto done;
    }

    DEBUG(SSSDBG_TRACE_ALL, "Found [%zu] items to delete.\n", msgs_count);

    qsort(msgs, msgs_count,
          sizeof(struct ldb_message *), compare_ldb_dn_comp_num);

    for (i = 0; i < msgs_count; i++) {
        DEBUG(SSSDBG_TRACE_ALL, "Trying to delete [%s].\n",
                  ldb_dn_get_linearized(msgs[i]->dn));

        ret = sysdb_delete_entry(sysdb, msgs[i]->dn, false);
        if (ret) {
            goto done;
        }
    }

done:
    if (ret == EOK) {
        ret = ldb_transaction_commit(sysdb->ldb);
        ret = sysdb_error_to_errno(ret);
    } else {
        ldb_transaction_cancel(sysdb->ldb);
    }
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_delete_recursive(struct sysdb_ctx *sysdb,
                           struct ldb_dn *dn,
                           bool ignore_not_found)
{
    return sysdb_delete_recursive_with_filter(sysdb, dn, ignore_not_found,
                                              "(distinguishedName=*)");
}


/* =Search-Entry========================================================== */

int sysdb_cache_search_entry(TALLOC_CTX *mem_ctx,
                             struct ldb_context *ldb,
                             struct ldb_dn *base_dn,
                             enum ldb_scope scope,
                             const char *filter,
                             const char **attrs,
                             size_t *_msgs_count,
                             struct ldb_message ***_msgs)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_search(ldb, tmp_ctx, &res,
                     base_dn, scope, attrs,
                     filter?"%s":NULL, filter);
    if (ret != EOK) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    *_msgs_count = res->count;
    *_msgs = talloc_steal(mem_ctx, res->msgs);

    if (res->count == 0) {
        ret = ENOENT;
        goto done;
    }

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

int sysdb_search_entry(TALLOC_CTX *mem_ctx,
                       struct sysdb_ctx *sysdb,
                       struct ldb_dn *base_dn,
                       enum ldb_scope scope,
                       const char *filter,
                       const char **attrs,
                       size_t *_msgs_count,
                       struct ldb_message ***_msgs)
{
    errno_t ret;

    ret = sysdb_cache_search_entry(mem_ctx, sysdb->ldb, base_dn, scope,
                                   filter, attrs, _msgs_count, _msgs);
    if (ret != EOK) {
        return ret;
    }

    return sysdb_merge_msg_list_ts_attrs(sysdb, *_msgs_count, *_msgs,
                                         attrs);
}

int sysdb_search_ts_entry(TALLOC_CTX *mem_ctx,
                          struct sysdb_ctx *sysdb,
                          struct ldb_dn *base_dn,
                          enum ldb_scope scope,
                          const char *filter,
                          const char **attrs,
                          size_t *_msgs_count,
                          struct ldb_message ***_msgs)
{
    if (sysdb->ldb_ts == NULL) {
        if (_msgs_count != NULL) {
            *_msgs_count = 0;
        }
        if (_msgs != NULL) {
            *_msgs = NULL;
        }

        return EOK;
    }

    return sysdb_cache_search_entry(mem_ctx, sysdb->ldb_ts, base_dn, scope,
                                    filter, attrs, _msgs_count, _msgs);
}

/* =Search-Entry-by-SID-string============================================ */

int sysdb_search_entry_by_sid_str(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *domain,
                                  const char *search_base,
                                  const char *filter_str,
                                  const char *sid_str,
                                  const char **attrs,
                                  struct ldb_message **msg)
{
    TALLOC_CTX *tmp_ctx;
    const char *def_attrs[] = { SYSDB_NAME, SYSDB_SID_STR, NULL };
    struct ldb_message **msgs = NULL;
    struct ldb_dn *basedn;
    size_t msgs_count = 0;
    char *filter;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    basedn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                            search_base, domain->name);
    if (!basedn) {
        ret = ENOMEM;
        goto done;
    }

    filter = talloc_asprintf(tmp_ctx, filter_str, sid_str);
    if (!filter) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_entry(tmp_ctx, domain->sysdb, basedn, LDB_SCOPE_SUBTREE,
                             filter, attrs?attrs:def_attrs, &msgs_count,
                             &msgs);
    if (ret) {
        goto done;
    }

    *msg = talloc_steal(mem_ctx, msgs[0]);

done:
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, "No such entry\n");
    }
    else if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
    }

    talloc_zfree(tmp_ctx);
    return ret;
}

/* =Search-User-by-[UID/SID/NAME]============================================= */

static errno_t cleanup_dn_filter(TALLOC_CTX *mem_ctx,
                                struct ldb_result *ts_res,
                                const char *object_class,
                                const char *filter,
                                char **_dn_filter)
{
    TALLOC_CTX *tmp_ctx;
    char *dn_filter;
    char *sanitized_linearized_dn = NULL;
    errno_t ret;

    if (ts_res->count == 0) {
        *_dn_filter = NULL;
        return EOK;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    dn_filter = talloc_asprintf(tmp_ctx, "(&(%s)%s(|", object_class, filter);
    if (dn_filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (size_t i = 0; i < ts_res->count; i++) {
        ret = sss_filter_sanitize(tmp_ctx,
                                  ldb_dn_get_linearized(ts_res->msgs[i]->dn),
                                  &sanitized_linearized_dn);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "sss_filter_sanitize() failed: (%s) [%d]\n",
                  sss_strerror(ret), ret);
            goto done;
        }
        dn_filter = talloc_asprintf_append(
                                    dn_filter,
                                    "(%s=%s)",
                                    SYSDB_DN,
                                    sanitized_linearized_dn);
        if (dn_filter == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    dn_filter = talloc_asprintf_append(dn_filter, "))");
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

static int sysdb_search_by_name(TALLOC_CTX *mem_ctx,
                                struct sss_domain_info *domain,
                                const char *name,
                                enum sysdb_obj_type type,
                                const char **attrs,
                                struct ldb_message **msg)
{
    TALLOC_CTX *tmp_ctx;
    const char *def_attrs[] = { SYSDB_NAME, NULL, NULL };
    const char *filter_tmpl = NULL;
    struct ldb_message **msgs = NULL;
    struct ldb_dn *basedn;
    size_t msgs_count = 0;
    char *sanitized_name;
    char *lc_sanitized_name;
    char *filter;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    switch (type) {
    case SYSDB_USER:
        def_attrs[1] = SYSDB_UIDNUM;
        filter_tmpl = SYSDB_PWNAM_FILTER;
        basedn = sysdb_user_base_dn(tmp_ctx, domain);
        break;
    case SYSDB_GROUP:
        def_attrs[1] = SYSDB_GIDNUM;
        if (sss_domain_is_mpg(domain)) {
            /* When searching a group by name in a MPG domain, we also
             * need to search the user space in order to be able to match
             * a user private group/
             */
            filter_tmpl = SYSDB_GRNAM_MPG_FILTER;
            basedn = sysdb_domain_dn(tmp_ctx, domain);
        } else {
            filter_tmpl = SYSDB_GRNAM_FILTER;
            basedn = sysdb_group_base_dn(tmp_ctx, domain);
        }
        break;
    default:
        ret = EINVAL;
        goto done;
    }

    if (!basedn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_filter_sanitize_for_dom(tmp_ctx, name, domain, &sanitized_name,
                                      &lc_sanitized_name);
    if (ret != EOK) {
        goto done;
    }

    filter = talloc_asprintf(tmp_ctx, filter_tmpl, lc_sanitized_name,
                             sanitized_name, sanitized_name);
    if (!filter) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_entry(tmp_ctx, domain->sysdb, basedn, LDB_SCOPE_SUBTREE,
                             filter, attrs?attrs:def_attrs,
                             &msgs_count, &msgs);
    if (ret) {
        goto done;
    }

    ret = sysdb_merge_msg_list_ts_attrs(domain->sysdb, msgs_count, msgs, attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Cannot retrieve timestamp attributes\n");
    }

    *msg = talloc_steal(mem_ctx, msgs[0]);

done:
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, "No such entry\n");
    }
    else if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
    }
    talloc_zfree(tmp_ctx);
    return ret;
}

int sysdb_search_user_by_name(TALLOC_CTX *mem_ctx,
                              struct sss_domain_info *domain,
                              const char *name,
                              const char **attrs,
                              struct ldb_message **msg)
{
    return sysdb_search_by_name(mem_ctx, domain, name, SYSDB_USER, attrs, msg);
}

int sysdb_search_user_by_uid(TALLOC_CTX *mem_ctx,
                             struct sss_domain_info *domain,
                             uid_t uid,
                             const char **attrs,
                             struct ldb_message **msg)
{
    TALLOC_CTX *tmp_ctx;
    const char *def_attrs[] = { SYSDB_NAME, SYSDB_UIDNUM, NULL };
    struct ldb_message **msgs = NULL;
    struct ldb_dn *basedn;
    size_t msgs_count = 0;
    char *filter;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    basedn = sysdb_user_base_dn(tmp_ctx, domain);
    if (!basedn) {
        ret = ENOMEM;
        goto done;
    }

    filter = talloc_asprintf(tmp_ctx, SYSDB_PWUID_FILTER, (unsigned long)uid);
    if (!filter) {
        ret = ENOMEM;
        goto done;
    }

    /* Use SUBTREE scope here, not ONELEVEL
     * There is a bug in LDB that makes ONELEVEL searches extremely
     * slow (it ignores indexing)
     */
    ret = sysdb_search_entry(tmp_ctx, domain->sysdb, basedn,
                             LDB_SCOPE_SUBTREE, filter,
                             attrs?attrs:def_attrs, &msgs_count, &msgs);
    if (ret) {
        goto done;
    }

    *msg = talloc_steal(mem_ctx, msgs[0]);

done:
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, "No such entry\n");
    }
    else if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
    }

    talloc_zfree(tmp_ctx);
    return ret;
}

int sysdb_search_user_by_sid_str(TALLOC_CTX *mem_ctx,
                                 struct sss_domain_info *domain,
                                 const char *sid_str,
                                 const char **attrs,
                                 struct ldb_message **msg)
{

   return sysdb_search_entry_by_sid_str(mem_ctx, domain,
                                        SYSDB_TMPL_USER_BASE,
                                        SYSDB_PWSID_FILTER,
                                        sid_str, attrs, msg);
}

int sysdb_search_user_by_upn_res(TALLOC_CTX *mem_ctx,
                                 struct sss_domain_info *domain,
                                 bool domain_scope,
                                 const char *upn,
                                 const char **attrs,
                                 struct ldb_result **out_res)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    struct ldb_dn *base_dn;
    int ret;
    const char *def_attrs[] = { SYSDB_NAME, SYSDB_UPN, SYSDB_CANONICAL_UPN,
                                SYSDB_USER_EMAIL, NULL };
    char *sanitized;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_filter_sanitize(tmp_ctx, upn, &sanitized);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_filter_sanitize failed.\n");
        goto done;
    }

    if (domain_scope == true) {
        base_dn = sysdb_user_base_dn(tmp_ctx, domain);
    } else {
        base_dn = sysdb_base_dn(domain->sysdb, tmp_ctx);
    }
    if (base_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_search(domain->sysdb->ldb, tmp_ctx, &res,
                     base_dn, LDB_SCOPE_SUBTREE, attrs ? attrs : def_attrs,
                     SYSDB_PWUPN_FILTER, sanitized, sanitized, sanitized);
    if (ret != EOK) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    if (res->count == 0) {
        /* set result anyway */
        *out_res = talloc_steal(mem_ctx, res);
        ret = ENOENT;
        goto done;
    } else if (res->count > 1) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Search for upn [%s] returns more than one result. One of the "
              "possible reasons can be that several users share the same "
              "email address.\n", upn);
        ret = EINVAL;
        goto done;
    }

    /* Merge in the timestamps from the fast ts db */
    ret = sysdb_merge_res_ts_attrs(domain->sysdb, res,
                                   attrs ? attrs : def_attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Cannot merge timestamp cache values\n");
        /* non-fatal */
    }

    *out_res = talloc_steal(mem_ctx, res);
    ret = EOK;

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

int sysdb_search_user_by_upn(TALLOC_CTX *mem_ctx,
                             struct sss_domain_info *domain,
                             bool domain_scope,
                             const char *upn,
                             const char **attrs,
                             struct ldb_message **msg)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_user_by_upn_res(tmp_ctx, domain, domain_scope, upn, attrs, &res);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, "No entry with upn [%s] found.\n", upn);
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
        goto done;
    }

    *msg = talloc_steal(mem_ctx, res->msgs[0]);

    ret = EOK;

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

/* =Search-Group-by-[GID/SID/NAME]============================================ */

int sysdb_search_group_by_name(TALLOC_CTX *mem_ctx,
                               struct sss_domain_info *domain,
                               const char *name,
                               const char **attrs,
                               struct ldb_message **msg)
{
    return sysdb_search_by_name(mem_ctx, domain, name, SYSDB_GROUP, attrs, msg);
}

static int
sysdb_search_group_by_id(TALLOC_CTX *mem_ctx,
                         struct sss_domain_info *domain,
                         const char *filterfmt,
                         gid_t gid,
                         const char **attrs,
                         struct ldb_message **msg)
{
    TALLOC_CTX *tmp_ctx;
    const char *def_attrs[] = { SYSDB_NAME, SYSDB_GIDNUM, NULL };
    struct ldb_message **msgs = NULL;
    struct ldb_dn *basedn;
    size_t msgs_count = 0;
    char *filter;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    basedn = sysdb_group_base_dn(tmp_ctx, domain);
    if (!basedn) {
        ret = ENOMEM;
        goto done;
    }

    filter = talloc_asprintf(tmp_ctx, filterfmt, (unsigned long)gid);
    if (!filter) {
        ret = ENOMEM;
        goto done;
    }

    /* Use SUBTREE scope here, not ONELEVEL
     * There is a bug in LDB that makes ONELEVEL searches extremely
     * slow (it ignores indexing)
     */
    ret = sysdb_search_entry(tmp_ctx, domain->sysdb, basedn, LDB_SCOPE_SUBTREE,
                             filter, attrs?attrs:def_attrs,
                             &msgs_count, &msgs);
    if (ret) {
        goto done;
    }

    *msg = talloc_steal(mem_ctx, msgs[0]);

done:
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, "No such entry\n");
    }
    else if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
    }

    talloc_zfree(tmp_ctx);
    return ret;
}

/* Please note that sysdb_search_group_by_gid() is not aware of MPGs. If MPG
 * support is needed either the caller must handle it or sysdb_getgrgid() or
 * sysdb_getgrgid_attrs() should be used. */
int sysdb_search_group_by_gid(TALLOC_CTX *mem_ctx,
                              struct sss_domain_info *domain,
                              gid_t gid,
                              const char **attrs,
                              struct ldb_message **msg)
{
    return sysdb_search_group_by_id(mem_ctx, domain, SYSDB_GRGID_FILTER,
                                    gid, attrs, msg);
}

int sysdb_search_group_by_origgid(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *domain,
                                  gid_t gid,
                                  const char **attrs,
                                  struct ldb_message **msg)
{
    return sysdb_search_group_by_id(mem_ctx, domain, SYSDB_GRORIGGID_FILTER,
                                    gid, attrs, msg);
}

int sysdb_search_group_by_sid_str(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *domain,
                                  const char *sid_str,
                                  const char **attrs,
                                  struct ldb_message **msg)
{

   return sysdb_search_entry_by_sid_str(mem_ctx, domain,
                                        SYSDB_TMPL_GROUP_BASE,
                                        SYSDB_GRSID_FILTER,
                                        sid_str, attrs, msg);
}

/* =Search-Group-by-Name============================================ */

int sysdb_search_netgroup_by_name(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *domain,
                                  const char *name,
                                  const char **attrs,
                                  struct ldb_message **msg)
{
    TALLOC_CTX *tmp_ctx;
    static const char *def_attrs[] = { SYSDB_NAME, NULL };
    struct ldb_message **msgs = NULL;
    struct ldb_dn *basedn;
    size_t msgs_count = 0;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    basedn = sysdb_netgroup_dn(tmp_ctx, domain, name);
    if (!basedn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_entry(tmp_ctx, domain->sysdb, basedn, LDB_SCOPE_BASE,
                             NULL, attrs?attrs:def_attrs, &msgs_count,
                             &msgs);
    if (ret) {
        goto done;
    }

    *msg = talloc_steal(mem_ctx, msgs[0]);

done:
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, "No such entry\n");
    }
    else if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
    }
    talloc_zfree(tmp_ctx);
    return ret;
}

/* =Timestamp-cache-functions==============================================*/

/* If modifyTimestamp is the same in the TS cache, return EOK. Return ERR_NO_TS
 * if there is no timestamps cache for this domain and ERR_TS_CACHE_MISS if
 * the entry had changed and the caller needs to update the sysdb cache as well.
 */
static errno_t sysdb_check_ts_cache(struct sss_domain_info *domain,
                                    struct ldb_dn *entry_dn,
                                    struct sysdb_attrs *entry)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    size_t msgs_count;
    struct ldb_message **msgs;
    bool mod_ts_differs;

    if (domain->sysdb->ldb_ts == NULL) {
        return ERR_NO_TS;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    /* Check if the entry is in the timestamp cache */
    ret = sysdb_search_ts_entry(tmp_ctx,
                                domain->sysdb,
                                entry_dn,
                                LDB_SCOPE_BASE,
                                NULL,
                                sysdb_ts_cache_attrs,
                                &msgs_count,
                                &msgs);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Cannot find TS cache entry for [%s]: [%d]: %s\n",
              ldb_dn_get_linearized(entry_dn), ret, sss_strerror(ret));
        goto done;
    }

    if (msgs_count != 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Expected 1 result for base search, got %zu\n", msgs_count);
        return EIO;
    }

    mod_ts_differs = sysdb_msg_attrs_modts_differs(msgs[0], entry);
    if (mod_ts_differs == true) {
        ret = ERR_TS_CACHE_MISS;
        goto done;
    }

    ret = EOK;
done:
    talloc_zfree(tmp_ctx);
    return ret;
}

static int sysdb_set_ts_entry_attr(struct sysdb_ctx *sysdb,
                                   struct ldb_dn *entry_dn,
                                   struct sysdb_attrs *attrs,
                                   int mod_op);

static errno_t sysdb_create_ts_entry(struct sysdb_ctx *sysdb,
                                     struct ldb_dn *entry_dn,
                                     struct sysdb_attrs *attrs)
{
    struct ldb_message *msg;
    errno_t ret;
    int lret;
    TALLOC_CTX *tmp_ctx;

    if (sysdb->ldb_ts == NULL || attrs->num == 0) {
        return EOK;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    if (entry_dn == NULL) {
        ret = EINVAL;
        goto done;
    }

    msg = sysdb_attrs2msg(tmp_ctx, entry_dn, attrs, 0);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    lret = ldb_add(sysdb->ldb_ts, msg);
    if (lret != LDB_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ldb_add failed: [%s](%d)[%s]\n",
              ldb_strerror(lret), lret, ldb_errstring(sysdb->ldb_ts));
    }

    ret = sysdb_error_to_errno(lret);
done:
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, "No such entry\n");
    } else if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
    }
    talloc_zfree(tmp_ctx);
    return ret;
}

static struct sysdb_attrs *ts_obj_attrs(TALLOC_CTX *mem_ctx,
                                        enum sysdb_obj_type obj_type)
{
    struct sysdb_attrs *attrs;
    const char *oc;
    errno_t ret;

    switch (obj_type) {
    case SYSDB_USER:
        oc = SYSDB_USER_CLASS;
        break;
    case SYSDB_GROUP:
        oc = SYSDB_GROUP_CLASS;
        break;
    default:
        return NULL;
    }

    attrs = sysdb_new_attrs(mem_ctx);
    if (attrs == NULL) {
        return NULL;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_OBJECTCATEGORY, oc);
    if (ret != EOK) {
        talloc_free(attrs);
        return NULL;
    }

    return attrs;
}

static errno_t sysdb_update_ts_cache(struct sss_domain_info *domain,
                                     struct ldb_dn *entry_dn,
                                     struct sysdb_attrs *entry_attrs,
                                     struct sysdb_attrs *ts_attrs,
                                     int mod_op,
                                     uint64_t cache_timeout,
                                     time_t now)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    const char *modstamp;

    if (domain->sysdb->ldb_ts == NULL) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "No timestamp cache for this domain\n");
        return EOK;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    if (ts_attrs == NULL) {
        ts_attrs = sysdb_new_attrs(tmp_ctx);
        if (ts_attrs == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = sysdb_attrs_add_time_t(ts_attrs, SYSDB_LAST_UPDATE, now);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to add %s to tsdb\n", SYSDB_LAST_UPDATE);
        goto done;
    }

    ret = sysdb_attrs_add_time_t(ts_attrs, SYSDB_CACHE_EXPIRE,
                                 ((cache_timeout) ?
                                  (now + cache_timeout) : 0));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to add %s to tsdb\n", SYSDB_CACHE_EXPIRE);
        goto done;
    }

    if (entry_attrs != NULL) {
        ret = sysdb_attrs_get_string(entry_attrs, SYSDB_ORIG_MODSTAMP,
                                     &modstamp);
        if (ret == EOK) {
            ret = sysdb_attrs_add_string(ts_attrs,
                                         SYSDB_ORIG_MODSTAMP, modstamp);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                    "Failed to add %s to tsdb\n", SYSDB_ORIG_MODSTAMP);
                goto done;
            }
        }
    }

    ret = sysdb_set_ts_entry_attr(domain->sysdb, entry_dn,
                                  ts_attrs, mod_op);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Cannot set ts attrs for group %s\n",
              ldb_dn_get_linearized(entry_dn));
        /* Not fatal */
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t sysdb_check_and_update_ts_cache(struct sss_domain_info *domain,
                                               struct ldb_dn *entry_dn,
                                               struct sysdb_attrs *attrs,
                                               uint64_t cache_timeout,
                                               time_t now)
{
    errno_t ret;

    ret = sysdb_check_ts_cache(domain, entry_dn, attrs);
    switch (ret) {
    case ENOENT:
        DEBUG(SSSDBG_TRACE_INTERNAL, "No timestamps entry\n");
        break;
    case EOK:
        /* The entry's timestamp was the same. Just update the ts cache */
        ret = sysdb_update_ts_cache(domain, entry_dn, attrs, NULL,
                                    SYSDB_MOD_REP, cache_timeout, now);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Cannot update the timestamps cache [%d]: %s\n",
                  ret, sss_strerror(ret));
        }
        break;
    case ERR_TS_CACHE_MISS:
    case ERR_NO_TS:
        /* Either there is no cache or the cache is up-do-date. Just report
         * what's up
         */
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE,
              "Error checking the timestamps cache [%d]: %s\n",
              ret, sss_strerror(ret));
        break;
    }

    return ret;
}

static errno_t get_sysdb_obj_dn(TALLOC_CTX *mem_ctx,
                                struct sss_domain_info *domain,
                                enum sysdb_obj_type obj_type,
                                const char *obj_name,
                                struct ldb_dn **_obj_dn)
{
    struct ldb_dn *obj_dn;

    switch (obj_type) {
    case SYSDB_USER:
        obj_dn = sysdb_user_dn(mem_ctx, domain, obj_name);
        break;
    case SYSDB_GROUP:
        obj_dn = sysdb_group_dn(mem_ctx, domain, obj_name);
        break;
    default:
        return EINVAL;
    }

    if (obj_dn == NULL) {
        return ENOMEM;
    }

    *_obj_dn = obj_dn;
    return EOK;
}

static errno_t sysdb_check_and_update_ts_obj(struct sss_domain_info *domain,
                                             enum sysdb_obj_type obj_type,
                                             const char *obj_name,
                                             struct sysdb_attrs *attrs,
                                             uint64_t cache_timeout,
                                             time_t now)
{
    struct ldb_dn *entry_dn;
    TALLOC_CTX *tmp_ctx;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = get_sysdb_obj_dn(tmp_ctx, domain, obj_type, obj_name, &entry_dn);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_check_and_update_ts_cache(domain, entry_dn, attrs,
                                          cache_timeout, now);
done:
    talloc_zfree(tmp_ctx);
    return ret;
}

static errno_t sysdb_create_ts_obj(struct sss_domain_info *domain,
                                   enum sysdb_obj_type obj_type,
                                   const char *obj_name,
                                   uint64_t cache_timeout,
                                   time_t now)
{
    struct ldb_dn *entry_dn;
    struct sysdb_attrs *ts_attrs = NULL;
    TALLOC_CTX *tmp_ctx;
    errno_t ret;

    if (domain->sysdb->ldb_ts == NULL) {
        return EOK;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = get_sysdb_obj_dn(tmp_ctx, domain, obj_type, obj_name, &entry_dn);
    if (ret != EOK) {
        goto done;
    }

    ts_attrs = ts_obj_attrs(tmp_ctx, obj_type);
    if (ts_attrs == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_update_ts_cache(domain, entry_dn, NULL, ts_attrs,
                                SYSDB_MOD_ADD, cache_timeout, now);
    if (ret != EOK) {
        goto done;
    }

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

static errno_t sysdb_check_and_update_ts_grp(struct sss_domain_info *domain,
                                             const char *grp_name,
                                             struct sysdb_attrs *attrs,
                                             uint64_t cache_timeout,
                                             time_t now)
{
    return sysdb_check_and_update_ts_obj(domain, SYSDB_GROUP, grp_name,
                                         attrs, cache_timeout, now);
}

static errno_t sysdb_create_ts_grp(struct sss_domain_info *domain,
                                   const char *grp_name,
                                   uint64_t cache_timeout,
                                   time_t now)
{
    return sysdb_create_ts_obj(domain, SYSDB_GROUP, grp_name,
                               cache_timeout, now);
}

static errno_t sysdb_create_ts_usr(struct sss_domain_info *domain,
                                   const char *usr_name,
                                   uint64_t cache_timeout,
                                   time_t now)
{
    return sysdb_create_ts_obj(domain, SYSDB_USER, usr_name,
                               cache_timeout, now);
}

/* =Replace-Attributes-On-Entry=========================================== */
static int sysdb_set_cache_entry_attr(struct ldb_context *ldb,
                                      struct ldb_dn *entry_dn,
                                      struct sysdb_attrs *attrs,
                                      int mod_op)
{
    struct ldb_message *msg;
    int ret;
    int lret;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    if (entry_dn == NULL || attrs->num == 0) {
        ret = EINVAL;
        goto done;
    }

    msg = sysdb_attrs2msg(tmp_ctx, entry_dn, attrs, mod_op);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    lret = ldb_modify(ldb, msg);
    if (lret != LDB_SUCCESS) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "ldb_modify failed: [%s](%d)[%s]\n",
              ldb_strerror(lret), lret, ldb_errstring(ldb));
    }

    ret = sysdb_error_to_errno(lret);

done:
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, "No such entry\n");
    }
    else if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
    }
    talloc_zfree(tmp_ctx);
    return ret;
}

static const char *get_attr_storage(int state_mask)
{
    const char *storage = "";

    if (state_mask == SSS_SYSDB_BOTH_CACHE) {
        storage = "cache, ts_cache";
    } else if (state_mask == SSS_SYSDB_TS_CACHE) {
        storage = "ts_cache";
    } else if (state_mask == SSS_SYSDB_CACHE) {
        storage = "cache";
    }

    return storage;
}

int sysdb_set_entry_attr(struct sysdb_ctx *sysdb,
                         struct ldb_dn *entry_dn,
                         struct sysdb_attrs *attrs,
                         int mod_op)
{
    bool sysdb_write = true;
    errno_t ret = EOK;
    errno_t tret = EOK;
    int state_mask = SSS_SYSDB_NO_CACHE;

    sysdb_write = sysdb_entry_attrs_diff(sysdb, entry_dn, attrs, mod_op);
    if (sysdb_write == true) {
        ret = sysdb_set_cache_entry_attr(sysdb->ldb, entry_dn, attrs, mod_op);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Cannot set attrs for %s, %d [%s]\n",
                  ldb_dn_get_linearized(entry_dn), ret, sss_strerror(ret));
        } else {
            state_mask |= SSS_SYSDB_CACHE;
        }
    }

    if (ret == EOK && is_ts_ldb_dn(entry_dn)) {
        tret = sysdb_set_ts_entry_attr(sysdb, entry_dn, attrs, mod_op);
        if (tret == ENOENT && mod_op == SYSDB_MOD_REP) {
            /* Update failed because TS does non exist. Create missing TS */
            tret = sysdb_set_ts_entry_attr(sysdb, entry_dn, attrs,
                                           SYSDB_MOD_ADD);
            DEBUG(SSSDBG_TRACE_FUNC,
                  "The TS value for %s does not exist, trying to create it\n",
                  ldb_dn_get_linearized(entry_dn));
        }
        if (tret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                "Cannot set TS attrs for %s\n", ldb_dn_get_linearized(entry_dn));
            /* Not fatal */
        } else {
            state_mask |= SSS_SYSDB_TS_CACHE;
        }
    }

    if (state_mask != SSS_SYSDB_NO_CACHE) {
        DEBUG(SSSDBG_FUNC_DATA,
              "Entry [%s] has set [%s] attrs.\n",
              ldb_dn_get_linearized(entry_dn),
              get_attr_storage(state_mask));
    }

    return ret;
}

static int sysdb_rep_ts_entry_attr(struct sysdb_ctx *sysdb,
                                   struct ldb_dn *entry_dn,
                                   struct sysdb_attrs *attrs)
{
    if (sysdb->ldb_ts == NULL || attrs->num == 0) {
        return EOK;
    }

    return sysdb_set_cache_entry_attr(sysdb->ldb_ts, entry_dn,
                                      attrs, SYSDB_MOD_REP);
}

static int sysdb_set_ts_entry_attr(struct sysdb_ctx *sysdb,
                                   struct ldb_dn *entry_dn,
                                   struct sysdb_attrs *attrs,
                                   int mod_op)
{
    struct sysdb_attrs *ts_attrs;
    TALLOC_CTX *tmp_ctx;
    errno_t ret;

    if (sysdb->ldb_ts == NULL) {
        return EOK;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ts_attrs = sysdb_filter_ts_attrs(tmp_ctx, attrs);
    if (ts_attrs == NULL) {
        ret = ENOMEM;
        goto done;
    }

    switch (mod_op) {
    case SYSDB_MOD_REP:
        ret = sysdb_rep_ts_entry_attr(sysdb, entry_dn, ts_attrs);
        break;
    case SYSDB_MOD_ADD:
        ret = sysdb_create_ts_entry(sysdb, entry_dn, ts_attrs);
        break;
    default:
        ret = EINVAL;
        break;
    }

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

/* =Replace-Attributes-On-User============================================ */

int sysdb_set_user_attr(struct sss_domain_info *domain,
                        const char *name,
                        struct sysdb_attrs *attrs,
                        int mod_op)
{
    struct ldb_dn *dn;
    TALLOC_CTX *tmp_ctx;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    dn = sysdb_user_dn(tmp_ctx, domain, name);
    if (!dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_set_entry_attr(domain->sysdb, dn, attrs, mod_op);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;
done:
    talloc_zfree(tmp_ctx);
    return ret;
}

errno_t sysdb_update_user_shadow_last_change(struct sss_domain_info *domain,
                                             const char *name,
                                             const char *attrname)
{
    struct sysdb_attrs *attrs;
    char *value;
    errno_t ret;

    attrs = sysdb_new_attrs(NULL);
    if (attrs == NULL) {
        return ENOMEM;
    }

    /* The attribute contains number of days since the epoch */
    value = talloc_asprintf(attrs, "%ld", (long)time(NULL)/86400);
    if (value == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_add_string(attrs, attrname, value);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_set_user_attr(domain, name, attrs, SYSDB_MOD_REP);

done:
    talloc_free(attrs);
    return ret;
}

/* =Replace-Attributes-On-Group=========================================== */

int sysdb_set_group_attr(struct sss_domain_info *domain,
                         const char *name,
                         struct sysdb_attrs *attrs,
                         int mod_op)
{
    struct ldb_dn *dn;
    TALLOC_CTX *tmp_ctx;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        ret = ENOMEM;
        goto done;
    }

    dn = sysdb_group_dn(tmp_ctx, domain, name);
    if (!dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_set_entry_attr(domain->sysdb, dn, attrs, mod_op);
    if (ret) {
        goto done;
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

/* =Replace-Attributes-On-Netgroup=========================================== */

int sysdb_set_netgroup_attr(struct sss_domain_info *domain,
                            const char *name,
                            struct sysdb_attrs *attrs,
                            int mod_op)
{
    errno_t ret;
    struct ldb_dn *dn;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    dn = sysdb_netgroup_dn(tmp_ctx, domain, name);
    if (!dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_set_entry_attr(domain->sysdb, dn, attrs, mod_op);

done:
    talloc_free(tmp_ctx);
    return ret;
}

/* =Add-Basic-User-NO-CHECKS============================================== */

int sysdb_add_basic_user(struct sss_domain_info *domain,
                         const char *name,
                         uid_t uid, gid_t gid,
                         const char *gecos,
                         const char *homedir,
                         const char *shell)
{
    struct ldb_message *msg;
    int ret;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }

    /* user dn */
    msg->dn = sysdb_user_dn(msg, domain, name);
    if (!msg->dn) {
        ERROR_OUT(ret, ENOMEM, done);
    }

    ret = sysdb_add_string(msg, SYSDB_OBJECTCATEGORY, SYSDB_USER_CLASS);
    if (ret) goto done;

    ret = sysdb_add_string(msg, SYSDB_NAME, name);
    if (ret) goto done;

    ret = sysdb_add_ulong(msg, SYSDB_UIDNUM, (unsigned long)uid);
    if (ret) goto done;

    ret = sysdb_add_ulong(msg, SYSDB_GIDNUM, (unsigned long)gid);
    if (ret) goto done;

    /* We set gecos to be the same as fullname on user creation,
     * But we will not enforce coherency after that, it's up to
     * admins to decide if they want to keep it in sync if they change
     * one of the 2 */
    if (gecos && *gecos) {
        ret = sysdb_add_string(msg, SYSDB_FULLNAME, gecos);
        if (ret) goto done;
        ret = sysdb_add_string(msg, SYSDB_GECOS, gecos);
        if (ret) goto done;
    }

    if (homedir && *homedir) {
        ret = sysdb_add_string(msg, SYSDB_HOMEDIR, homedir);
        if (ret) goto done;
    }

    if (shell && *shell) {
        ret = sysdb_add_string(msg, SYSDB_SHELL, shell);
        if (ret) goto done;
    }

    /* creation time */
    ret = sysdb_add_ulong(msg, SYSDB_CREATE_TIME, (unsigned long)time(NULL));
    if (ret) goto done;

    ret = ldb_add(domain->sysdb->ldb, msg);
    ret = sysdb_error_to_errno(ret);

done:
    if (ret) {
        DEBUG(SSSDBG_TRACE_FUNC, "Error: %d (%s)\n", ret, strerror(ret));
    }
    talloc_zfree(tmp_ctx);
    return ret;
}

static errno_t
sysdb_remove_ghost_from_group(struct sss_domain_info *dom,
                              struct ldb_message *group,
                              struct ldb_message_element *alias_el,
                              const char *name,
                              const char *orig_dn,
                              const char *userdn)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *msg;
    struct ldb_message_element *orig_members;
    bool add_member = false;
    errno_t ret = EOK;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOENT;
    }

    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ERROR_OUT(ret, ENOMEM, done);
    }

    msg->dn = group->dn;

    if (orig_dn == NULL) {
        /* We have no way of telling which groups this user belongs to.
         * Add it to all that reference it in the ghost attribute */
        add_member = true;
    } else {
        add_member = false;
        orig_members = ldb_msg_find_element(group, SYSDB_ORIG_MEMBER);
        if (orig_members) {
            for (i = 0; i < orig_members->num_values; i++) {
                if (strcmp((const char *) orig_members->values[i].data,
                            orig_dn) == 0) {
                    /* This is a direct member. Add the member attribute */
                    add_member = true;
                }
            }
        } else {
            /* Nothing to compare the originalDN with. Let's rely on the
             * memberof plugin to do the right thing during initgroups..
             */
            add_member = true;
        }
    }

    if (add_member) {
        ret = sysdb_add_string(msg, SYSDB_MEMBER, userdn);
        if (ret) goto done;
    }

    ret = sysdb_delete_string(msg, SYSDB_GHOST, name);
    if (ret) goto done;

    /* Delete aliases from the ghost attribute as well */
    for (i = 0; i < alias_el->num_values; i++) {
        if (strcmp((const char *)alias_el->values[i].data, name) == 0) {
            continue;
        }
        ret = ldb_msg_add_string(msg, SYSDB_GHOST,
                (char *) alias_el->values[i].data);
        if (ret != LDB_SUCCESS) {
            ERROR_OUT(ret, EINVAL, done);
        }
    }


    ret = sss_ldb_modify_permissive(dom->sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "sss_ldb_modify_permissive failed: [%s](%d)[%s]\n",
              ldb_strerror(ret), ret, ldb_errstring(dom->sysdb->ldb));
    }

    ret = sysdb_error_to_errno(ret);
    if (ret != EOK) {
        goto done;
    }

    talloc_zfree(msg);


done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
sysdb_remove_ghostattr_from_groups(struct sss_domain_info *domain,
                                   const char *orig_dn,
                                   struct sysdb_attrs *attrs,
                                   const char *name)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message **groups;
    struct ldb_message_element *alias_el;
    struct ldb_dn *tmpdn;
    const char *group_attrs[] = {SYSDB_NAME, SYSDB_GHOST, SYSDB_ORIG_MEMBER, NULL};
    const char *userdn;
    char *sanitized_name;
    char *filter;
    errno_t ret = EOK;
    size_t group_count = 0;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOENT;
    }

    ret = sss_filter_sanitize(tmp_ctx, name, &sanitized_name);
    if (ret != EOK) {
        goto done;
    }

    filter = talloc_asprintf(tmp_ctx, "(|(%s=%s)",
                                      SYSDB_GHOST, sanitized_name);
    if (!filter) {
        ret = ENOMEM;
        goto done;
    }
    ret = sysdb_attrs_get_el(attrs, SYSDB_NAME_ALIAS, &alias_el);
    if (ret != EOK) {
        goto done;
    }

    for (i = 0; i < alias_el->num_values; i++) {
        if (strcmp((const char *)alias_el->values[i].data, name) == 0) {
            continue;
        }
        filter = talloc_asprintf_append(filter, "(%s=%s)",
                                        SYSDB_GHOST, alias_el->values[i].data);
        if (filter == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    filter = talloc_asprintf_append(filter, ")");
    if (filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tmpdn = sysdb_user_dn(tmp_ctx, domain, name);
    if (!tmpdn) {
        ERROR_OUT(ret, ENOMEM, done);
    }

    userdn = ldb_dn_get_linearized(tmpdn);
    if (!userdn) {
        ERROR_OUT(ret, EINVAL, done);
    }

    /* To cover cross-domain group-membership we must search in all
     * sub-domains. */
    tmpdn = ldb_dn_new(tmp_ctx, domain->sysdb->ldb, SYSDB_BASE);
    if (!tmpdn) {
        ret = ENOMEM;
        goto done;
    }

    /* We need to find all groups that contain this object as a ghost user
     * and replace the ghost user by actual member record in direct parents.
     * Note that this object can be referred to either by its name or any
     * of its aliases
     */
    ret = sysdb_search_entry(tmp_ctx, domain->sysdb, tmpdn, LDB_SCOPE_SUBTREE,
                             filter, group_attrs, &group_count, &groups);
    if (ret != EOK && ret != ENOENT) {
        goto done;
    }

    for (i = 0; i < group_count; i++) {
        sysdb_remove_ghost_from_group(domain, groups[i], alias_el, name,
                                      orig_dn, userdn);
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

/* =Add-User-Function===================================================== */

int sysdb_add_user(struct sss_domain_info *domain,
                   const char *name,
                   uid_t uid, gid_t gid,
                   const char *gecos,
                   const char *homedir,
                   const char *shell,
                   const char *orig_dn,
                   struct sysdb_attrs *attrs,
                   int cache_timeout,
                   time_t now)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *msg;
    struct ldb_message_element *el = NULL;
    int ret;
    bool posix;

    if (sss_domain_is_mpg(domain)) {
        if (gid != 0) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Cannot add user with arbitrary GID in MPG domain!\n");
            return EINVAL;
        }
        gid = uid;
    }

    if (domain->id_max != 0 && uid != 0 &&
        (uid < domain->id_min || uid > domain->id_max)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Supplied uid [%"SPRIuid"] is not in the allowed range "
               "[%d-%d].\n", uid, domain->id_min, domain->id_max);
        return ERANGE;
    }

    if (domain->id_max != 0 && gid != 0 &&
        (gid < domain->id_min || gid > domain->id_max)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Supplied gid [%"SPRIgid"] is not in the allowed range "
               "[%d-%d].\n", gid, domain->id_min, domain->id_max);
        return ERANGE;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = ldb_transaction_start(domain->sysdb->ldb);
    if (ret) {
        ret = sysdb_error_to_errno(ret);
        talloc_free(tmp_ctx);
        return ret;
    }

    if (sss_domain_is_mpg(domain)) {
        /* In MPG domains you can't have groups with the same name or GID
         * as users, search if a group with the same name exists.
         * Don't worry about users, if we try to add a user with the same
         * name the operation will fail */

        ret = sysdb_search_group_by_name(tmp_ctx, domain, name, NULL, &msg);
        if (ret != ENOENT) {
            if (ret == EOK) {
                DEBUG(SSSDBG_TRACE_FUNC,
                      "Group named %s already exists in an MPG domain\n",
                      name);
                ret = EEXIST;
            }
            goto done;
        }

        if (uid != 0) { /* uid == 0 means non-POSIX object */
            ret = sysdb_search_group_by_gid(tmp_ctx, domain, uid, NULL, &msg);
            if (ret != ENOENT) {
                if (ret == EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                        "Group with GID [%"SPRIgid"] already exists in an "
                        "MPG domain\n", uid);
                    ret = EEXIST;
                }
                goto done;
            }
        }
    }

    /* check no other user with the same uid exist */
    if (uid != 0) {
        ret = sysdb_search_user_by_uid(tmp_ctx, domain, uid, NULL, &msg);
        if (ret != ENOENT) {
            if (ret == EOK) ret = EEXIST;
            goto done;
        }
    }

    /* try to add the user */
    ret = sysdb_add_basic_user(domain, name, uid, gid, gecos, homedir, shell);
    if (ret) goto done;

    ret = sysdb_create_ts_usr(domain, name, cache_timeout, now);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Cannot create user timestamp entry\n");
        /* Not fatal */
    }

    if (!attrs) {
        attrs = sysdb_new_attrs(tmp_ctx);
        if (!attrs) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = sysdb_attrs_get_bool(attrs, SYSDB_POSIX, &posix);
    if (ret == ENOENT) {
        posix = true;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_LIBS, "Failed to get posix attribute.\n");
        goto done;
    }

    if (uid == 0 && posix == true) {
        DEBUG(SSSDBG_OP_FAILURE, "Can't store posix user with uid=0.\n");
        ret = EINVAL;
        goto done;
    }

    if (!now) {
        now = time(NULL);
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_LAST_UPDATE, now);
    if (ret) goto done;

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_CACHE_EXPIRE,
                                 ((cache_timeout) ?
                                  (now + cache_timeout) : 0));
    if (ret) goto done;

    ret = sysdb_attrs_get_el_ext(attrs, SYSDB_INITGR_EXPIRE, false, &el);
    if (ret == ENOENT) {
        ret = sysdb_attrs_add_time_t(attrs, SYSDB_INITGR_EXPIRE, 0);
        if (ret) goto done;
    }

    ret = sysdb_set_user_attr(domain, name, attrs, SYSDB_MOD_REP);
    if (ret) goto done;

    if (domain->enumerate == false) {
        /* If we're not enumerating, previous getgr{nam,gid} calls might
         * have stored ghost users into the cache, so we need to link them
         * with the newly-created user entry
         */
        ret = sysdb_remove_ghostattr_from_groups(domain, orig_dn, attrs,
                                                 name);
        if (ret) goto done;
    }

    ret = EOK;

done:
    if (ret == EOK) {
        ret = ldb_transaction_commit(domain->sysdb->ldb);
        ret = sysdb_error_to_errno(ret);
    } else {
        DEBUG(SSSDBG_TRACE_FUNC, "Error: %d (%s)\n", ret, strerror(ret));
        ldb_transaction_cancel(domain->sysdb->ldb);
    }
    talloc_zfree(tmp_ctx);
    return ret;
}

/* =Add-Basic-Group-NO-CHECKS============================================= */

int sysdb_add_basic_group(struct sss_domain_info *domain,
                          const char *name,
                          bool is_posix,
                          gid_t gid)
{
    struct ldb_message *msg;
    int ret;
    TALLOC_CTX *tmp_ctx;

    if (is_posix && gid == 0) {
        DEBUG(SSSDBG_OP_FAILURE, "Failure adding [%s], POSIX groups with gid==0 "
                                 "are not supported.\n", name);
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }

    /* group dn */
    msg->dn = sysdb_group_dn(msg, domain, name);
    if (!msg->dn) {
        ERROR_OUT(ret, ENOMEM, done);
    }

    ret = sysdb_add_bool(msg, SYSDB_POSIX, is_posix);
    if (ret) goto done;

    ret = sysdb_add_string(msg, SYSDB_OBJECTCATEGORY, SYSDB_GROUP_CLASS);
    if (ret) goto done;

    ret = sysdb_add_string(msg, SYSDB_NAME, name);
    if (ret) goto done;

    if (is_posix) {
        ret = sysdb_add_ulong(msg, SYSDB_GIDNUM, (unsigned long)gid);
        if (ret) goto done;
    }

    /* creation time */
    ret = sysdb_add_ulong(msg, SYSDB_CREATE_TIME, (unsigned long)time(NULL));
    if (ret) goto done;

    ret = ldb_add(domain->sysdb->ldb, msg);
    ret = sysdb_error_to_errno(ret);

done:
    if (ret) {
        DEBUG(SSSDBG_TRACE_FUNC, "Error: %d (%s)\n", ret, strerror(ret));
    }
    talloc_zfree(tmp_ctx);
    return ret;
}


/* =Add-Group-Function==================================================== */

int sysdb_add_group(struct sss_domain_info *domain,
                    const char *name, gid_t gid,
                    struct sysdb_attrs *attrs,
                    int cache_timeout,
                    time_t now)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *msg;
    int ret;
    bool posix;

    if (domain->id_max != 0 && gid != 0 &&
        (gid < domain->id_min || gid > domain->id_max)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Supplied gid [%"SPRIgid"] is not in the allowed range "
               "[%d-%d].\n", gid, domain->id_min, domain->id_max);
        return ERANGE;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = ldb_transaction_start(domain->sysdb->ldb);
    if (ret) {
        ret = sysdb_error_to_errno(ret);
        talloc_free(tmp_ctx);
        return ret;
    }

    if (sss_domain_is_mpg(domain)) {
        /* In MPG domains you can't have groups with the same name as users,
         * search if a group with the same name exists.
         * Don't worry about users, if we try to add a user with the same
         * name the operation will fail */

        ret = sysdb_search_user_by_name(tmp_ctx, domain, name, NULL, &msg);
        if (ret != ENOENT) {
            if (ret == EOK) {
                DEBUG(SSSDBG_TRACE_LIBS, "MPG domain contains a user "
                      "with the same name - %s.\n", name);
                ret = EEXIST;
            } else {
                DEBUG(SSSDBG_TRACE_LIBS,
                      "sysdb_search_user_by_name failed for user %s.\n", name);
            }
            goto done;
        }

        ret = sysdb_search_user_by_uid(tmp_ctx, domain, gid, NULL, &msg);
        if (ret != ENOENT) {
            if (ret == EOK) {
                DEBUG(SSSDBG_TRACE_LIBS,
                      "User with the same UID exists in MPG domain: "
                      "[%"SPRIgid"].\n", gid);
                ret = EEXIST;
            } else {
                DEBUG(SSSDBG_TRACE_LIBS,
                      "sysdb_search_user_by_uid failed for gid: "
                      "[%"SPRIgid"].\n", gid);
            }
            goto done;
        }
    }

    /* check no other groups with the same gid exist */
    if (gid != 0) {
        ret = sysdb_search_group_by_gid(tmp_ctx, domain, gid, NULL, &msg);
        if (ret != ENOENT) {
            if (ret == EOK) {
                DEBUG(SSSDBG_TRACE_LIBS,
                      "Group with the same gid exists: [%"SPRIgid"].\n", gid);
                ret = EEXIST;
            } else {
                DEBUG(SSSDBG_TRACE_LIBS,
                      "sysdb_search_group_by_gid failed for gid: "
                      "[%"SPRIgid"].\n", gid);
            }
            goto done;
        }
    }

    if (!attrs) {
        attrs = sysdb_new_attrs(tmp_ctx);
        if (!attrs) {
            DEBUG(SSSDBG_TRACE_LIBS, "sysdb_new_attrs failed.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    ret = sysdb_attrs_get_bool(attrs, SYSDB_POSIX, &posix);
    if (ret == ENOENT) {
        posix = true;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_LIBS, "Failed to get posix attribute.\n");
        goto done;
    }

    /* try to add the group */
    ret = sysdb_add_basic_group(domain, name, posix, gid);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sysdb_add_basic_group failed for: %s with gid: "
              "[%"SPRIgid"].\n", name, gid);
        goto done;
    }

    ret = sysdb_create_ts_grp(domain, name, cache_timeout, now);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Cannot set timestamp cache attributes for a group\n");
        /* Not fatal */
    }

    if (!now) {
        now = time(NULL);
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_LAST_UPDATE, now);
    if (ret) {
        DEBUG(SSSDBG_TRACE_LIBS, "Failed to add sysdb-last-update.\n");
        goto done;
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_CACHE_EXPIRE,
                                 ((cache_timeout) ?
                                  (now + cache_timeout) : 0));
    if (ret) {
        DEBUG(SSSDBG_TRACE_LIBS, "Failed to add sysdb-cache-expire.\n");
        goto done;
    }

    ret = sysdb_set_group_attr(domain, name, attrs, SYSDB_MOD_REP);
    if (ret) {
        DEBUG(SSSDBG_TRACE_LIBS, "sysdb_set_group_attr failed.\n");
        goto done;
    }

done:
    if (ret == EOK) {
        ret = ldb_transaction_commit(domain->sysdb->ldb);
        ret = sysdb_error_to_errno(ret);
    } else {
        DEBUG(SSSDBG_TRACE_FUNC, "Error: %d (%s)\n", ret, strerror(ret));
        ldb_transaction_cancel(domain->sysdb->ldb);
    }
    talloc_zfree(tmp_ctx);
    return ret;
}

int sysdb_add_incomplete_group(struct sss_domain_info *domain,
                               const char *name,
                               gid_t gid,
                               const char *original_dn,
                               const char *sid_str,
                               const char *uuid,
                               bool posix,
                               time_t now)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct sysdb_attrs *attrs;
    struct ldb_message *msg;
    const char *previous = NULL;
    const char *group_attrs[] = { SYSDB_SID_STR, SYSDB_UUID, SYSDB_ORIG_DN, NULL };
    const char *values[] = { sid_str, uuid, original_dn, NULL };
    bool same = false;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    if (posix) {
        ret = sysdb_search_group_by_gid(tmp_ctx, domain, gid, group_attrs, &msg);
        if (ret == EOK) {
            for (int i = 0; !same && group_attrs[i] != NULL; i++) {
                previous = ldb_msg_find_attr_as_string(msg,
                                                       group_attrs[i],
                                                       NULL);
                if (previous != NULL && values[i] != NULL) {
                    same = strcmp(previous, values[i]) == 0;
                }
            }

            if (same == true) {
                DEBUG(SSSDBG_TRACE_LIBS,
                      "The group with GID [%"SPRIgid"] was renamed\n", gid);
                ret = ERR_GID_DUPLICATED;
                goto done;
            }

            DEBUG(SSSDBG_OP_FAILURE,
                  "Another group with GID [%"SPRIgid"] already exists\n", gid);
            ret = ERR_GID_DUPLICATED;
            goto done;
        }
    }

    /* try to add the group */
    ret = sysdb_add_basic_group(domain, name, posix, gid);
    if (ret) goto done;

    if (!now) {
        now = time(NULL);
    }

    ret = sysdb_create_ts_grp(domain, name, now-1, now);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Cannot set timestamp cache attributes for a group\n");
        /* Not fatal */
    }

    attrs = sysdb_new_attrs(tmp_ctx);
    if (!attrs) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_LAST_UPDATE, now);
    if (ret) goto done;

    /* in case (ignore_group_members == true) group is actually complete */
    ret = sysdb_attrs_add_time_t(attrs, SYSDB_CACHE_EXPIRE,
                                 domain->ignore_group_members ?
                                     (now + domain->group_timeout) : (now-1));
    if (ret) goto done;

    if (original_dn) {
        ret = sysdb_attrs_add_string(attrs, SYSDB_ORIG_DN, original_dn);
        if (ret) goto done;
    }

    if (sid_str) {
        ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, sid_str);
        if (ret) goto done;
    }

    if (uuid) {
        ret = sysdb_attrs_add_string(attrs, SYSDB_UUID, uuid);
        if (ret) goto done;
    }

    ret = sysdb_set_group_attr(domain, name, attrs, SYSDB_MOD_REP);

done:
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_FUNC, "Error: %d (%s)\n", ret, sss_strerror(ret));
    }
    talloc_zfree(tmp_ctx);
    return ret;
}

/* =Add-Or-Remove-Group-Memeber=========================================== */

/* mod_op must be either SYSDB_MOD_ADD or SYSDB_MOD_DEL */
int sysdb_mod_group_member(struct sss_domain_info *domain,
                           struct ldb_dn *member_dn,
                           struct ldb_dn *group_dn,
                           int mod_op)
{
    struct ldb_message *msg;
    const char *dn;
    int ret;

    msg = ldb_msg_new(NULL);
    if (!msg) {
        ERROR_OUT(ret, ENOMEM, fail);
    }

    msg->dn = group_dn;
    ret = ldb_msg_add_empty(msg, SYSDB_MEMBER, mod_op, NULL);
    if (ret != LDB_SUCCESS) {
        ERROR_OUT(ret, ENOMEM, fail);
    }

    dn = ldb_dn_get_linearized(member_dn);
    if (!dn) {
        ERROR_OUT(ret, EINVAL, fail);
    }

    ret = ldb_msg_add_string(msg, SYSDB_MEMBER, dn);
    if (ret != LDB_SUCCESS) {
        ERROR_OUT(ret, EINVAL, fail);
    }

    ret = ldb_modify(domain->sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "ldb_modify failed: [%s](%d)[%s]\n",
              ldb_strerror(ret), ret, ldb_errstring(domain->sysdb->ldb));
    }
    ret = sysdb_error_to_errno(ret);

fail:
    if (ret) {
        DEBUG(SSSDBG_TRACE_FUNC, "Error: %d (%s)\n", ret, strerror(ret));
    }
    talloc_zfree(msg);
    return ret;
}

/* =Add-Basic-Netgroup-NO-CHECKS============================================= */

int sysdb_add_basic_netgroup(struct sss_domain_info *domain,
                             const char *name, const char *description)
{
    struct ldb_message *msg;
    int ret;

    msg = ldb_msg_new(NULL);
    if (!msg) {
        return ENOMEM;
    }

    /* netgroup dn */
    msg->dn = sysdb_netgroup_dn(msg, domain, name);
    if (!msg->dn) {
        ERROR_OUT(ret, ENOMEM, done);
    }

    ret = sysdb_add_string(msg, SYSDB_OBJECTCLASS, SYSDB_NETGROUP_CLASS);
    if (ret) goto done;

    ret = sysdb_add_string(msg, SYSDB_NAME, name);
    if (ret) goto done;

    if (description && *description) {
        ret = sysdb_add_string(msg, SYSDB_DESCRIPTION, description);
        if (ret) goto done;
    }

    /* creation time */
    ret = sysdb_add_ulong(msg, SYSDB_CREATE_TIME, (unsigned long) time(NULL));
    if (ret) goto done;

    ret = ldb_add(domain->sysdb->ldb, msg);
    ret = sysdb_error_to_errno(ret);

done:
    if (ret) {
        DEBUG(SSSDBG_TRACE_FUNC, "Error: %d (%s)\n", ret, strerror(ret));
    }
    talloc_zfree(msg);
    return ret;
}


/* =Add-Netgroup-Function==================================================== */

int sysdb_add_netgroup(struct sss_domain_info *domain,
                       const char *name,
                       const char *description,
                       struct sysdb_attrs *attrs,
                       char **missing,
                       int cache_timeout,
                       time_t now)
{
    TALLOC_CTX *tmp_ctx;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = ldb_transaction_start(domain->sysdb->ldb);
    if (ret) {
        ret = sysdb_error_to_errno(ret);
        talloc_free(tmp_ctx);
        return ret;
    }

    /* try to add the netgroup */
    ret = sysdb_add_basic_netgroup(domain, name, description);
    if (ret && ret != EEXIST) goto done;

    if (!attrs) {
        attrs = sysdb_new_attrs(tmp_ctx);
        if (!attrs) {
            ret = ENOMEM;
            goto done;
        }
    }

    if (!now) {
        now = time(NULL);
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_LAST_UPDATE, now);
    if (ret) goto done;

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_CACHE_EXPIRE,
                                 ((cache_timeout) ?
                                  (now + cache_timeout) : 0));
    if (ret) goto done;

    ret = sysdb_set_netgroup_attr(domain, name, attrs, SYSDB_MOD_REP);

    if (missing) {
        ret = sysdb_remove_attrs(domain, name,
                                 SYSDB_MEMBER_NETGROUP,
                                 missing);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Could not remove missing attributes\n");
        }
    }

done:
    if (ret == EOK) {
        ret = ldb_transaction_commit(domain->sysdb->ldb);
        ret = sysdb_error_to_errno(ret);
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_FUNC, "Error: %d (%s)\n", ret, strerror(ret));
        ldb_transaction_cancel(domain->sysdb->ldb);
    }
    talloc_zfree(tmp_ctx);
    return ret;
}

/* =Store-Users-(Native/Legacy)-(replaces-existing-data)================== */

static errno_t sysdb_store_new_user(struct sss_domain_info *domain,
                                    const char *name,
                                    uid_t uid,
                                    gid_t gid,
                                    const char *gecos,
                                    const char *homedir,
                                    const char *shell,
                                    const char *orig_dn,
                                    struct sysdb_attrs *attrs,
                                    uint64_t cache_timeout,
                                    time_t now);


static errno_t sysdb_store_user_attrs(struct sss_domain_info *domain,
                                      const char *name,
                                      uid_t uid,
                                      gid_t gid,
                                      const char *gecos,
                                      const char *homedir,
                                      const char *shell,
                                      const char *orig_dn,
                                      struct sysdb_attrs *attrs,
                                      char **remove_attrs,
                                      uint64_t cache_timeout,
                                      time_t now);

/* if one of the basic attributes is empty ("") as opposed to NULL,
 * this will just remove it */

int sysdb_store_user(struct sss_domain_info *domain,
                     const char *name,
                     const char *pwd,
                     uid_t uid, gid_t gid,
                     const char *gecos,
                     const char *homedir,
                     const char *shell,
                     const char *orig_dn,
                     struct sysdb_attrs *attrs,
                     char **remove_attrs,
                     uint64_t cache_timeout,
                     time_t now)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *msg;
    int ret;
    errno_t sret = EOK;
    bool in_transaction = false;

    /* get transaction timestamp */
    if (now == 0) {
        now = time(NULL);
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    if (!attrs) {
        attrs = sysdb_new_attrs(tmp_ctx);
        if (!attrs) {
            ret = ENOMEM;
            goto done;
        }
    }

    if (pwd && !*pwd) {
        ret = sysdb_attrs_add_string(attrs, SYSDB_PWD, pwd);
        if (ret) goto done;
    }

    ret = sysdb_transaction_start(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto done;
    }

    in_transaction = true;

    ret = sysdb_search_user_by_name(tmp_ctx, domain, name, NULL, &msg);
    if (ret && ret != ENOENT) {
        goto done;
    }
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_LIBS, "User %s does not exist.\n", name);
    }

    if (ret == ENOENT) {
        /* the user doesn't exist, turn into adding a user */
        ret = sysdb_store_new_user(domain, name, uid, gid, gecos, homedir,
                                   shell, orig_dn, attrs, cache_timeout, now);
        if (ret != EOK) {
            if ((ret == EEXIST) && sss_domain_is_mpg(domain)) {
                /* ipa_s2n_save_objects() will handle this later */
                DEBUG(SSSDBG_TRACE_FUNC, "sysdb_store_new_user() failed: conflict in MPG domain\n");
            } else {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_store_new_user() failed: %d\n", ret);
            }
        }
    } else {
        /* the user exists, let's just replace attributes when set */
        /*
         * The sysdb_search_user_by_name() function also matches lowercased
         * aliases, saved when the domain is case-insensitive. This means that
         * the stored entry name can differ in capitalization from the search
         * name. Use the cached entry name to perform the modification because
         * if name capitalization in entry's DN differs the modify operation
         * will fail.
         */
        const char *entry_name =
            ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
        if (entry_name != NULL) {
            name = entry_name;
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE, "User '%s' without a name?\n", name);
        }

        ret = sysdb_store_user_attrs(domain, name, uid, gid, gecos, homedir,
                                     shell, orig_dn, attrs, remove_attrs,
                                     cache_timeout, now);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_store_user_attrs() failed: %d\n", ret);
        }
    }
    if (ret != EOK) {
        goto done;
    }

    sret = sysdb_transaction_commit(domain->sysdb);
    if (sret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction\n");
        ret = EIO;
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

    if (ret) {
        DEBUG(SSSDBG_TRACE_FUNC, "Error: %d (%s)\n", ret, strerror(ret));
    } else {
        DEBUG(SSSDBG_TRACE_FUNC, "User \"%s\" has been stored\n", name);
    }
    talloc_zfree(tmp_ctx);
    return ret;
}

static errno_t sysdb_store_new_user(struct sss_domain_info *domain,
                                    const char *name,
                                    uid_t uid,
                                    gid_t gid,
                                    const char *gecos,
                                    const char *homedir,
                                    const char *shell,
                                    const char *orig_dn,
                                    struct sysdb_attrs *attrs,
                                    uint64_t cache_timeout,
                                    time_t now)
{
    errno_t ret;

    ret = sysdb_add_user(domain, name, uid, gid, gecos, homedir,
                         shell, orig_dn, attrs, cache_timeout, now);
    if (ret == EEXIST) {
        /* This may be a user rename. If there is a user with the
            * same UID, remove it and try to add the basic user again
            */
        ret = sysdb_delete_user(domain, NULL, uid);
        if (ret == ENOENT) {
            /* Not found by UID, return the original EEXIST,
                * this may be a conflict in MPG domain or something
                * else */
            return EEXIST;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_delete_user failed.\n");
            return ret;
        }
        DEBUG(SSSDBG_TRACE_FUNC,
                "A user with the same UID [%llu] was removed from the "
                "cache\n", (unsigned long long) uid);
        ret = sysdb_add_user(domain, name, uid, gid, gecos, homedir,
                             shell, orig_dn, attrs, cache_timeout, now);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE,
                    "sysdb_add_user failed (while renaming user) for: "
                    "%s [%"SPRIgid"].\n", name, gid);
            return ret;
        }
    }

    return EOK;
}

static errno_t sysdb_store_user_attrs(struct sss_domain_info *domain,
                                      const char *name,
                                      uid_t uid,
                                      gid_t gid,
                                      const char *gecos,
                                      const char *homedir,
                                      const char *shell,
                                      const char *orig_dn,
                                      struct sysdb_attrs *attrs,
                                      char **remove_attrs,
                                      uint64_t cache_timeout,
                                      time_t now)
{
    errno_t ret;

    if (uid) {
        ret = sysdb_attrs_add_uint32(attrs, SYSDB_UIDNUM, uid);
        if (ret) return ret;
    }

    if (gid) {
        ret = sysdb_attrs_add_uint32(attrs, SYSDB_GIDNUM, gid);
        if (ret) return ret;
    }

    if (uid && !gid && sss_domain_is_mpg(domain)) {
        ret = sysdb_attrs_add_uint32(attrs, SYSDB_GIDNUM, uid);
        if (ret) return ret;
    }

    if (gecos) {
        ret = sysdb_attrs_add_string(attrs, SYSDB_GECOS, gecos);
        if (ret) return ret;
    }

    if (homedir) {
        ret = sysdb_attrs_add_string(attrs, SYSDB_HOMEDIR, homedir);
        if (ret) return ret;
    }

    if (shell) {
        ret = sysdb_attrs_add_string(attrs, SYSDB_SHELL, shell);
        if (ret) return ret;
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_LAST_UPDATE, now);
    if (ret) return ret;

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_CACHE_EXPIRE,
                                 ((cache_timeout) ?
                                  (now + cache_timeout) : 0));
    if (ret) return ret;

    ret = sysdb_set_user_attr(domain, name, attrs, SYSDB_MOD_REP);
    if (ret) return ret;

    if (remove_attrs) {
        ret = sysdb_remove_attrs(domain, name,
                                 SYSDB_MEMBER_USER,
                                 remove_attrs);
        if (ret != EOK) {
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "Could not remove missing attributes\n");
        }
    }

    return EOK;
}

/* =Store-Group-(Native/Legacy)-(replaces-existing-data)================== */

/* this function does not check that all user members are actually present */

static errno_t sysdb_store_new_group(struct sss_domain_info *domain,
                                     const char *name,
                                     gid_t gid,
                                     struct sysdb_attrs *attrs,
                                     uint64_t cache_timeout,
                                     time_t now);

static errno_t sysdb_store_group_attrs(struct sss_domain_info *domain,
                                       const char *name,
                                       gid_t gid,
                                       struct sysdb_attrs *attrs,
                                       uint64_t cache_timeout,
                                       time_t now);

int sysdb_store_group(struct sss_domain_info *domain,
                      const char *name,
                      gid_t gid,
                      struct sysdb_attrs *attrs,
                      uint64_t cache_timeout,
                      time_t now)
{
    TALLOC_CTX *tmp_ctx;
    static const char *src_attrs[] = { "*", NULL };
    struct ldb_message *msg;
    bool new_group = false;
    int ret;
    errno_t sret = EOK;
    bool in_transaction = false;

    /* get transaction timestamp */
    if (!now) {
        now = time(NULL);
    }

    ret = sysdb_check_and_update_ts_grp(domain, name, attrs,
                                        cache_timeout, now);
    if (ret == EOK) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "The group record of %s did not change, only updated "
              "the timestamp cache\n", name);
        return EOK;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = sysdb_transaction_start(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto done;
    }
    in_transaction = true;

    ret = sysdb_search_group_by_name(tmp_ctx, domain, name, src_attrs, &msg);
    if (ret && ret != ENOENT) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "sysdb_search_group_by_name failed for %s with: [%d][%s].\n",
              name, ret, strerror(ret));
        goto done;
    }
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_LIBS, "Group %s does not exist.\n", name);
        new_group = true;
    }

    if (!attrs) {
        attrs = sysdb_new_attrs(tmp_ctx);
        if (!attrs) {
            ret = ENOMEM;
            goto done;
        }
    }

    if (new_group) {
        ret = sysdb_store_new_group(domain, name, gid, attrs,
                                    cache_timeout, now);
    } else {
        /*
         * The sysdb_search_group_by_name() function also matches lowercased
         * aliases, saved when the domain is case-insensitive. This means that
         * the stored entry name can differ in capitalization from the search
         * name. Use the cached entry name to perform the modification because
         * if name capitalization in entry's DN differs the modify operation
         * will fail.
         */
        const char *entry_name =
            ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
        if (entry_name != NULL) {
            name = entry_name;
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE, "Group '%s' without a name?\n", name);
        }

        ret = sysdb_store_group_attrs(domain, name, gid, attrs,
                                      cache_timeout, now);
    }
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cache update failed: %d\n", ret);
        goto done;
    }

    sret = sysdb_transaction_commit(domain->sysdb);
    if (sret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction\n");
        ret = EIO;
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

    if (ret) {
        DEBUG(SSSDBG_TRACE_FUNC, "Error: %d (%s)\n", ret, strerror(ret));
    } else {
        DEBUG(SSSDBG_TRACE_FUNC, "Group \"%s\" has been stored\n", name);
    }
    talloc_zfree(tmp_ctx);
    return ret;
}


static errno_t sysdb_store_new_group(struct sss_domain_info *domain,
                                     const char *name,
                                     gid_t gid,
                                     struct sysdb_attrs *attrs,
                                     uint64_t cache_timeout,
                                     time_t now)
{
    errno_t ret;

    /* group doesn't exist, turn into adding a group */
    ret = sysdb_add_group(domain, name, gid, attrs, cache_timeout, now);
    if (ret == EEXIST) {
        /* This may be a group rename. If there is a group with the
         * same GID, remove it and try to add the basic group again
         */
        DEBUG(SSSDBG_TRACE_LIBS, "sysdb_add_group failed: [EEXIST].\n");
        ret = sysdb_delete_group(domain, NULL, gid);
        if (ret == ENOENT) {
            /* Not found by GID, return the original EEXIST,
             * this may be a conflict in MPG domain or something
             * else */
            DEBUG(SSSDBG_OP_FAILURE,
                  "sysdb_delete_group failed (while renaming group). Not "
                  "found by gid: [%"SPRIgid"].\n", gid);
            return EEXIST;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_add_group failed.\n");
            return ret;
        }

        DEBUG(SSSDBG_TRACE_FUNC,
                "A group with the same GID [%"SPRIgid"] was removed from "
                "the cache\n", gid);
        ret = sysdb_add_group(domain, name, gid, attrs, cache_timeout, now);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE,
                    "sysdb_add_group failed (while renaming group) for: "
                    "%s [%"SPRIgid"].\n", name, gid);
            return ret;
        }
    }

    return EOK;
}

static errno_t sysdb_store_group_attrs(struct sss_domain_info *domain,
                                       const char *name,
                                       gid_t gid,
                                       struct sysdb_attrs *attrs,
                                       uint64_t cache_timeout,
                                       time_t now)
{
    errno_t ret;

    /* the group exists, let's just replace attributes when set */
    if (gid) {
        ret = sysdb_attrs_add_uint32(attrs, SYSDB_GIDNUM, gid);
        if (ret) {
            DEBUG(SSSDBG_TRACE_LIBS, "Failed to add GID.\n");
            return ret;
        }
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_LAST_UPDATE, now);
    if (ret) {
        DEBUG(SSSDBG_TRACE_LIBS, "Failed to add sysdb-last-update.\n");
        return ret;
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_CACHE_EXPIRE,
                                 ((cache_timeout) ?
                                  (now + cache_timeout) : 0));
    if (ret) {
        DEBUG(SSSDBG_TRACE_LIBS, "Failed to add sysdb-cache-expire.\n");
        return ret;
    }

    ret = sysdb_set_group_attr(domain, name, attrs, SYSDB_MOD_REP);
    if (ret) {
        DEBUG(SSSDBG_TRACE_LIBS, "sysdb_set_group_attr failed.\n");
        return ret;
    }

    return EOK;
}

/* =Add-User-to-Group(Native/Legacy)====================================== */
static int
sysdb_group_membership_mod(struct sss_domain_info *domain,
                           const char *group,
                           const char *member,
                           enum sysdb_member_type type,
                           int modify_op,
                           bool is_dn)
{
    struct ldb_dn *group_dn;
    struct ldb_dn *member_dn;
    char *member_domname;
    struct sss_domain_info *member_dom;
    struct sss_domain_info *group_dom;
    int ret;
    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = sss_parse_internal_fqname(tmp_ctx, member,
                                    NULL, &member_domname);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to parser internal fqname '%s' [%d]: %s\n",
              member, ret, sss_strerror(ret));
        goto done;
    }

    member_dom = find_domain_by_name(get_domains_head(domain),
                                     member_domname, false);
    if (member_dom == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Domain [%s] was not found\n", member_domname);
        ret = EINVAL;
        goto done;
    }

    if (type == SYSDB_MEMBER_USER) {
        member_dn = sysdb_user_dn(tmp_ctx, member_dom, member);
    } else if (type == SYSDB_MEMBER_GROUP) {
        member_dn = sysdb_group_dn(tmp_ctx, member_dom, member);
    } else {
        ret = EINVAL;
        goto done;
    }

    if (!member_dn) {
        ret = ENOMEM;
        goto done;
    }

    if (!is_dn) {
        /* To create a correct DN we have to check if the group belongs to */
        /* child domain */
        group_dom = find_domain_by_object_name(domain, group);
        if (group_dom == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "The right (sub)domain for the group [%s] was not found\n",
                  group);
            ret = EINVAL;
            goto done;
        }
        group_dn = sysdb_group_dn(tmp_ctx, group_dom, group);
    } else {
        group_dn = ldb_dn_new(tmp_ctx, domain->sysdb->ldb, group);
    }

    if (!group_dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_mod_group_member(domain, member_dn, group_dn, modify_op);

done:
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_add_group_member(struct sss_domain_info *domain,
                           const char *group,
                           const char *member,
                           enum sysdb_member_type type,
                           bool is_dn)
{
    return sysdb_group_membership_mod(domain, group, member, type,
                                      SYSDB_MOD_ADD, is_dn);
}

/* =Remove-member-from-Group(Native/Legacy)=============================== */


int sysdb_remove_group_member(struct sss_domain_info *domain,
                              const char *group,
                              const char *member,
                              enum sysdb_member_type type,
                              bool is_dn)
{
    return sysdb_group_membership_mod(domain, group, member, type,
                                      SYSDB_MOD_DEL, is_dn);
}


/* =Password-Caching====================================================== */

int sysdb_cache_password_ex(struct sss_domain_info *domain,
                            const char *username,
                            const char *password,
                            enum sss_authtok_type authtok_type,
                            size_t second_factor_len)
{
    TALLOC_CTX *tmp_ctx;
    struct sysdb_attrs *attrs;
    char *hash = NULL;
    char *salt;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = s3crypt_gen_salt(tmp_ctx, &salt);
    if (ret) {
        DEBUG(SSSDBG_CONF_SETTINGS, "Failed to generate random salt.\n");
        goto fail;
    }

    ret = s3crypt_sha512(tmp_ctx, password, salt, &hash);
    if (ret) {
        DEBUG(SSSDBG_CONF_SETTINGS, "Failed to create password hash.\n");
        goto fail;
    }

    attrs = sysdb_new_attrs(tmp_ctx);
    if (!attrs) {
        ERROR_OUT(ret, ENOMEM, fail);
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_CACHEDPWD, hash);
    if (ret) goto fail;

    ret = sysdb_attrs_add_long(attrs, SYSDB_CACHEDPWD_TYPE, authtok_type);
    if (ret) goto fail;

    if (authtok_type == SSS_AUTHTOK_TYPE_2FA && second_factor_len > 0) {
        ret = sysdb_attrs_add_long(attrs, SYSDB_CACHEDPWD_FA2_LEN,
                                   second_factor_len);
        if (ret) goto fail;
    }

    /* FIXME: should we use a different attribute for cache passwords?? */
    ret = sysdb_attrs_add_long(attrs, "lastCachedPasswordChange",
                               (long)time(NULL));
    if (ret) goto fail;

    ret = sysdb_attrs_add_uint32(attrs, SYSDB_FAILED_LOGIN_ATTEMPTS, 0U);
    if (ret) goto fail;


    ret = sysdb_set_user_attr(domain, username, attrs, SYSDB_MOD_REP);
    if (ret) {
        goto fail;
    }
    talloc_zfree(tmp_ctx);
    return EOK;

fail:
    if (ret) {
        DEBUG(SSSDBG_TRACE_FUNC, "Error: %d (%s)\n", ret, strerror(ret));
    }
    talloc_zfree(tmp_ctx);
    return ret;
}

int sysdb_cache_password(struct sss_domain_info *domain,
                         const char *username,
                         const char *password)
{
    return sysdb_cache_password_ex(domain, username, password,
                                   SSS_AUTHTOK_TYPE_PASSWORD, 0);
}

static errno_t set_initgroups_expire_attribute(struct sss_domain_info *domain,
                                               const char *name)
{
    errno_t ret;
    time_t cache_timeout;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(NULL);
    if (attrs == NULL) {
        return ENOMEM;
    }

    cache_timeout = domain->user_timeout
                        ? time(NULL) + domain->user_timeout
                        : 0;

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_INITGR_EXPIRE, cache_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not set up attrs\n");
        goto done;
    }

    ret = sysdb_set_user_attr(domain, name, attrs, SYSDB_MOD_REP);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to set initgroups expire attribute\n");
        goto done;
    }

done:
    talloc_zfree(attrs);
    return ret;
}

errno_t sysdb_set_initgr_expire_timestamp(struct sss_domain_info *domain,
                                          const char *name_or_upn_or_sid)
{
    const char *cname;
    errno_t ret;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = sysdb_get_real_name(tmp_ctx, domain, name_or_upn_or_sid, &cname);
    if (ret == ENOENT) {
        /* No point trying to bump timestamp of an entry that does not exist..*/
        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        cname = name_or_upn_or_sid;
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to canonicalize name, using [%s]\n", name_or_upn_or_sid);
    }

    ret = set_initgroups_expire_attribute(domain, cname);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Cannot set the initgroups expire attribute [%d]: %s\n",
              ret, sss_strerror(ret));
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

/* =Custom Search================== */

int sysdb_search_custom(TALLOC_CTX *mem_ctx,
                        struct sss_domain_info *domain,
                        const char *filter,
                        const char *subtree_name,
                        const char **attrs,
                        size_t *msgs_count,
                        struct ldb_message ***msgs)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *basedn = NULL;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (filter == NULL || subtree_name == NULL) {
        ret = EINVAL;
        goto done;
    }

    basedn = sysdb_custom_subtree_dn(tmp_ctx, domain, subtree_name);
    if (basedn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_custom_subtree_dn failed.\n");
        ret = ENOMEM;
        goto done;
    }
    if (!ldb_dn_validate(basedn)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Syntactically invalid subtree DN.\n");
        ret = EINVAL;
        goto done;
    }

    ret = sysdb_search_entry(mem_ctx, domain->sysdb, basedn,
                             LDB_SCOPE_SUBTREE, filter, attrs,
                             msgs_count, msgs);
done:
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_search_custom_by_name(TALLOC_CTX *mem_ctx,
                                struct sss_domain_info *domain,
                                const char *object_name,
                                const char *subtree_name,
                                const char **attrs,
                                size_t *_count,
                                struct ldb_message ***_msgs)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *basedn;
    struct ldb_message **msgs;
    size_t count;
    int ret;

    if (object_name == NULL || subtree_name == NULL) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    basedn = sysdb_custom_dn(tmp_ctx, domain, object_name, subtree_name);
    if (basedn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_custom_dn failed.\n");
        ret = ENOMEM;
        goto done;
    }
    if (!ldb_dn_validate(basedn)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Syntactically invalid DN.\n");
        ret = EINVAL;
        goto done;
    }

    ret = sysdb_search_entry(tmp_ctx, domain->sysdb, basedn,
                             LDB_SCOPE_BASE, NULL, attrs, &count, &msgs);
    if (ret) {
        goto done;
    }

    if (count > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "More than one result found.\n");
        ret = EFAULT;
        goto done;
    }

    *_count = count;
    *_msgs = talloc_move(mem_ctx, &msgs);

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

static int sysdb_cache_search_users(TALLOC_CTX *mem_ctx,
                                    struct sss_domain_info *domain,
                                    struct ldb_context *ldb,
                                    const char *sub_filter,
                                    const char **attrs,
                                    size_t *msgs_count,
                                    struct ldb_message ***msgs);

static int sysdb_cache_search_groups(TALLOC_CTX *mem_ctx,
                                     struct sss_domain_info *domain,
                                     struct ldb_context *ldb,
                                     const char *sub_filter,
                                     const char **attrs,
                                     size_t *msgs_count,
                                     struct ldb_message ***msgs);

errno_t sysdb_search_by_orig_dn(TALLOC_CTX *mem_ctx,
                                struct sss_domain_info *domain,
                                enum sysdb_member_type type,
                                const char *member_dn,
                                const char **attrs,
                                size_t *msgs_count,
                                struct ldb_message ***msgs)
{
    TALLOC_CTX *tmp_ctx;
    char *filter;
    char *sanitized_dn = NULL;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sss_filter_sanitize_dn(tmp_ctx, member_dn, &sanitized_dn);
    if (ret != EOK) {
        goto done;
    }

    filter = talloc_asprintf(tmp_ctx, "(%s=%s)", SYSDB_ORIG_DN, sanitized_dn);
    if (filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    switch (type) {
    case SYSDB_MEMBER_USER:
        ret = sysdb_cache_search_users(mem_ctx, domain, domain->sysdb->ldb,
                                       filter, attrs, msgs_count, msgs);
        break;
    case SYSDB_MEMBER_GROUP:
        ret = sysdb_cache_search_groups(mem_ctx, domain, domain->sysdb->ldb,
                                        filter, attrs, msgs_count, msgs);
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Trying to perform a search by orig_dn using a "
              "non-supported type %d\n", type);
        ret = EINVAL;
        goto done;
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

/* =Custom Store (replaces-existing-data)================== */

int sysdb_store_custom(struct sss_domain_info *domain,
                       const char *object_name,
                       const char *subtree_name,
                       struct sysdb_attrs *attrs)
{
    TALLOC_CTX *tmp_ctx;
    const char *search_attrs[] = { "*", NULL };
    size_t resp_count = 0;
    struct ldb_message **resp;
    struct ldb_message *msg;
    struct ldb_message_element *el;
    bool add_object = false;
    int ret;
    int i;

    if (object_name == NULL || subtree_name == NULL) {
        return EINVAL;
    }

    ret = ldb_transaction_start(domain->sysdb->ldb);
    if (ret) {
        return sysdb_error_to_errno(ret);
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_custom_by_name(tmp_ctx, domain,
                                      object_name, subtree_name,
                                      search_attrs, &resp_count, &resp);
    if (ret != EOK && ret != ENOENT) {
        goto done;
    }

    if (ret == ENOENT) {
       add_object = true;
    }

    msg = ldb_msg_new(tmp_ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = sysdb_custom_dn(tmp_ctx, domain, object_name, subtree_name);
    if (!msg->dn) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_custom_dn failed.\n");
        ret = ENOMEM;
        goto done;
    }

    msg->elements = talloc_array(msg, struct ldb_message_element, attrs->num);
    if (!msg->elements) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < attrs->num; i++) {
        msg->elements[i] = attrs->a[i];
        if (add_object) {
            msg->elements[i].flags = LDB_FLAG_MOD_ADD;
        } else {
            el = ldb_msg_find_element(resp[0], attrs->a[i].name);
            if (el == NULL) {
                msg->elements[i].flags = LDB_FLAG_MOD_ADD;
            } else {
                msg->elements[i].flags = LDB_FLAG_MOD_REPLACE;
            }
        }
    }
    msg->num_elements = attrs->num;

    if (add_object) {
        ret = ldb_add(domain->sysdb->ldb, msg);
    } else {
        ret = ldb_modify(domain->sysdb->ldb, msg);
    }
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to store custom entry: %s(%d)[%s]\n",
                  ldb_strerror(ret), ret, ldb_errstring(domain->sysdb->ldb));
        ret = sysdb_error_to_errno(ret);
    }

done:
    if (ret) {
        DEBUG(SSSDBG_TRACE_FUNC, "Error: %d (%s)\n", ret, strerror(ret));
        ldb_transaction_cancel(domain->sysdb->ldb);
    } else {
        ret = ldb_transaction_commit(domain->sysdb->ldb);
        ret = sysdb_error_to_errno(ret);
    }
    talloc_zfree(tmp_ctx);
    return ret;
}

/* = Custom Delete======================================= */

int sysdb_delete_custom(struct sss_domain_info *domain,
                        const char *object_name,
                        const char *subtree_name)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *dn;
    int ret;

    if (object_name == NULL || subtree_name == NULL) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    dn = sysdb_custom_dn(tmp_ctx, domain, object_name, subtree_name);
    if (dn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_custom_dn failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_delete(domain->sysdb->ldb, dn);

    switch (ret) {
    case LDB_SUCCESS:
    case LDB_ERR_NO_SUCH_OBJECT:
        ret = EOK;
        break;

    default:
        DEBUG(SSSDBG_CRIT_FAILURE,
              "ldb_delete failed: %s (%d); error Message: [%s]\n",
              ldb_strerror(ret), ret, ldb_errstring(domain->sysdb->ldb));
        ret = sysdb_error_to_errno(ret);
        break;
    }

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

/* = ASQ search request ======================================== */

int sysdb_asq_search(TALLOC_CTX *mem_ctx,
                     struct sss_domain_info *domain,
                     struct ldb_dn *base_dn,
                     const char *expression,
                     const char *asq_attribute,
                     const char **attrs,
                     size_t *msgs_count,
                     struct ldb_message ***msgs)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_request *ldb_req;
    struct ldb_control **ctrl;
    struct ldb_asq_control *asq_control;
    struct ldb_result *res;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ctrl = talloc_array(tmp_ctx, struct ldb_control *, 2);
    if (ctrl == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    ctrl[0] = talloc(ctrl, struct ldb_control);
    if (ctrl[0] == NULL) {
        ret = ENOMEM;
        goto fail;
    }
    ctrl[1] = NULL;

    ctrl[0]->oid = LDB_CONTROL_ASQ_OID;
    ctrl[0]->critical = 1;

    asq_control = talloc(ctrl[0], struct ldb_asq_control);
    if (asq_control == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    asq_control->request = 1;
    asq_control->source_attribute = talloc_strdup(asq_control, asq_attribute);
    if (asq_control->source_attribute == NULL) {
        ret = ENOMEM;
        goto fail;
    }
    asq_control->src_attr_len = strlen(asq_control->source_attribute);
    ctrl[0]->data = asq_control;

    res = talloc_zero(tmp_ctx, struct ldb_result);
    if (!res) {
        ret = ENOMEM;
        goto fail;
    }

    ret = ldb_build_search_req(&ldb_req, domain->sysdb->ldb, tmp_ctx,
                               base_dn, LDB_SCOPE_BASE,
                               expression, attrs, ctrl,
                               res, ldb_search_default_callback, NULL);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto fail;
    }

    ret = ldb_request(domain->sysdb->ldb, ldb_req);
    if (ret == LDB_SUCCESS) {
        ret = ldb_wait(ldb_req->handle, LDB_WAIT_ALL);
    }
    if (ret) {
        ret = sysdb_error_to_errno(ret);
        goto fail;
    }

    *msgs_count = res->count;
    *msgs = talloc_move(mem_ctx, &res->msgs);

    talloc_zfree(tmp_ctx);
    return EOK;

fail:
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, "No such entry\n");
    }
    else if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
    }
    talloc_zfree(tmp_ctx);
    return ret;
}

/* =Search-Users-with-Custom-Filter====================================== */

static int sysdb_cache_search_users(TALLOC_CTX *mem_ctx,
                                    struct sss_domain_info *domain,
                                    struct ldb_context *ldb,
                                    const char *sub_filter,
                                    const char **attrs,
                                    size_t *msgs_count,
                                    struct ldb_message ***msgs)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *basedn;
    char *filter;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    basedn = sysdb_user_base_dn(tmp_ctx, domain);
    if (!basedn) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to build base dn\n");
        ret = ENOMEM;
        goto fail;
    }

    filter = talloc_asprintf(tmp_ctx, "(&(%s)%s)", SYSDB_UC, sub_filter);
    if (!filter) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to build filter\n");
        ret = ENOMEM;
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Search users with filter: %s\n", filter);

    ret = sysdb_cache_search_entry(mem_ctx, ldb, basedn,
                                   LDB_SCOPE_SUBTREE, filter, attrs,
                                   msgs_count, msgs);
    if (ret) {
        goto fail;
    }

    talloc_zfree(tmp_ctx);
    return EOK;

fail:
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "No such entry\n");
    }
    else if (ret) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
    }
    talloc_zfree(tmp_ctx);
    return ret;
}

int sysdb_search_users(TALLOC_CTX *mem_ctx,
                       struct sss_domain_info *domain,
                       const char *sub_filter,
                       const char **attrs,
                       size_t *msgs_count,
                       struct ldb_message ***msgs)
{
    errno_t ret;

    ret = sysdb_cache_search_users(mem_ctx, domain, domain->sysdb->ldb,
                                   sub_filter, attrs, msgs_count, msgs);
    if (ret != EOK) {
        return ret;
    }

    return sysdb_merge_msg_list_ts_attrs(domain->sysdb, *msgs_count, *msgs,
                                         attrs);
}

int sysdb_search_users_by_timestamp(TALLOC_CTX *mem_ctx,
                                    struct sss_domain_info *domain,
                                    const char *sub_filter,
                                    const char *ts_sub_filter,
                                    const char **attrs,
                                    size_t *_msgs_count,
                                    struct ldb_message ***_msgs)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    struct ldb_result ts_res;
    struct ldb_message **msgs;
    size_t msgs_count;
    char *dn_filter = NULL;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_search_ts_users(tmp_ctx, domain, ts_sub_filter, NULL, &ts_res);
    if (ret == ERR_NO_TS) {
        ret = sysdb_cache_search_users(tmp_ctx, domain, domain->sysdb->ldb,
                                       ts_sub_filter, attrs, &msgs_count, &msgs);
        if (ret != EOK) {
            goto done;
        }

       ret = sysdb_merge_msg_list_ts_attrs(domain->sysdb, msgs_count, msgs, attrs);
       if (ret != EOK) {
           goto done;
       }

       goto immediately;
    } else if (ret != EOK) {
        goto done;
    }

    ret = cleanup_dn_filter(tmp_ctx, &ts_res, SYSDB_UC, sub_filter, &dn_filter);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_search_ts_matches(tmp_ctx, domain->sysdb, attrs,
                                  &ts_res, dn_filter, &res);
    if (ret != EOK) {
        goto done;
    }

    msgs_count = res->count;
    msgs = res->msgs;

immediately:
    *_msgs_count = msgs_count;
    *_msgs = talloc_steal(mem_ctx, msgs);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_search_ts_users(TALLOC_CTX *mem_ctx,
                          struct sss_domain_info *domain,
                          const char *sub_filter,
                          const char **attrs,
                          struct ldb_result *res)
{
    size_t msgs_count;
    struct ldb_message **msgs;
    int ret;

    if (res == NULL) {
        return EINVAL;
    }

    memset(res, 0, sizeof(*res));

    if (domain->sysdb->ldb_ts == NULL) {
        return ERR_NO_TS;
    }

    ret = sysdb_cache_search_users(mem_ctx, domain, domain->sysdb->ldb_ts,
                                    sub_filter, attrs, &msgs_count, &msgs);
    if (ret == EOK) {
        res->count = (unsigned)msgs_count;
        res->msgs = msgs;
    }

    return ret;
}

/* =Delete-User-by-Name-OR-uid============================================ */

static errno_t sysdb_user_local_override_dn(TALLOC_CTX *mem_ctx,
                                            struct sss_domain_info *domain,
                                            struct ldb_dn *obj_dn,
                                            struct ldb_dn **out_dn)
{
    struct ldb_context *ldb = sysdb_ctx_get_ldb(domain->sysdb);
    struct ldb_dn *override_dn;
    char *anchor;
    char *dn;
    errno_t ret;

    ret = sysdb_dn_sanitize(mem_ctx, ldb_dn_get_linearized(obj_dn), &dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_dn_sanitize() failed\n");
        return ret;
    }

    anchor = talloc_asprintf(mem_ctx, ":%s:%s", SYSDB_LOCAL_VIEW_NAME, dn);
    talloc_free(dn);
    if (anchor == NULL) {
        return ENOMEM;
    }

    override_dn = ldb_dn_new_fmt(mem_ctx, ldb, SYSDB_TMPL_OVERRIDE,
                                 anchor, SYSDB_LOCAL_VIEW_NAME);
    talloc_free(anchor);
    if (override_dn == NULL) {
        return ENOMEM;
    }

    *out_dn = override_dn;

    return EOK;
}

int sysdb_delete_user(struct sss_domain_info *domain,
                      const char *name, uid_t uid)
{
    TALLOC_CTX *tmp_ctx;
    const char *attrs[] = {SYSDB_GHOST, NULL};
    size_t msg_count;
    char *filter;
    struct ldb_message **msgs;
    struct ldb_message *msg;
    int ret;
    int i;
    char *sanitized_name;
    struct ldb_dn *override_dn = NULL;
    bool in_transaction = false;
    errno_t sret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    if (name) {
        ret = sysdb_search_user_by_name(tmp_ctx, domain, name, NULL, &msg);
    } else {
        ret = sysdb_search_user_by_uid(tmp_ctx, domain, uid, NULL, &msg);
    }
    if (ret == EOK) {
        if (name && uid) {
            /* verify name/gid match */
            const char *c_name;
            uint64_t c_uid;

            c_name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
            c_uid = ldb_msg_find_attr_as_uint64(msg, SYSDB_UIDNUM, 0);
            if (c_name == NULL || c_uid == 0) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Attribute is missing but this should never happen!\n");
                ret = EFAULT;
                goto fail;
            }
            if (strcmp(name, c_name) || uid != c_uid) {
                /* this is not the entry we are looking for */
                ret = EINVAL;
                goto fail;
            }
        }

        /* If user has a linked userOverride delete it */
        ret = sysdb_user_local_override_dn(tmp_ctx, domain, msg->dn,
                                           &override_dn);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to build local override DN: %s\n",
                  strerror(ret));
            goto fail;
        }

        ret = sysdb_transaction_start(domain->sysdb);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto fail;
        }
        in_transaction = true;

        ret = sysdb_delete_entry(domain->sysdb, override_dn, true);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Error deleting linked override DN: %s\n",
                  strerror(ret));
            goto fail;
        }

        ret = sysdb_delete_entry(domain->sysdb, msg->dn, false);
        if (ret) {
            goto fail;
        }

        ret = sysdb_transaction_commit(domain->sysdb);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to commit ldb transaction [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto fail;
        }
        in_transaction = false;

    } else if (ret == ENOENT && name != NULL) {
        /* Perhaps a ghost user? */
        ret = sss_filter_sanitize(tmp_ctx, name, &sanitized_name);
        if (ret != EOK) {
            goto fail;
        }

        filter = talloc_asprintf(tmp_ctx, "(%s=%s)",
                                          SYSDB_GHOST, sanitized_name);
        if (filter == NULL) {
            ret = ENOMEM;
            goto fail;
        }

        ret = sysdb_search_groups(tmp_ctx, domain, filter, attrs,
                                  &msg_count, &msgs);
        if (ret != EOK) {
            goto fail;
        }

        for (i = 0; i < msg_count; i++) {
            msg = ldb_msg_new(tmp_ctx);
            if (!msg) {
                ERROR_OUT(ret, ENOMEM, fail);
            }

            msg->dn = msgs[i]->dn;

            ret = sysdb_delete_string(msg, SYSDB_GHOST, name);
            if (ret) goto fail;

            ret = ldb_modify(domain->sysdb->ldb, msg);
            if (ret != LDB_SUCCESS) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "ldb_modify failed: [%s](%d)[%s]\n",
                      ldb_strerror(ret), ret,
                      ldb_errstring(domain->sysdb->ldb));
            }
            ret = sysdb_error_to_errno(ret);
            if (ret != EOK) {
                goto fail;
            }

            talloc_zfree(msg);
        }
    } else {
        goto fail;
    }


    talloc_zfree(tmp_ctx);
    return EOK;

fail:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(domain->sysdb);
        if (sret != LDB_SUCCESS) {
            sret = sysdb_error_to_errno(sret);
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to cancel ldb transaction [%d]: %s\n",
                  sret, sss_strerror(sret));
        }
    }
    DEBUG(SSSDBG_TRACE_FUNC, "Error: %d (%s)\n", ret, strerror(ret));
    talloc_zfree(tmp_ctx);
    return ret;
}


/* =Search-Groups-with-Custom-Filter===================================== */

static int sysdb_cache_search_groups(TALLOC_CTX *mem_ctx,
                                     struct sss_domain_info *domain,
                                     struct ldb_context *ldb,
                                     const char *sub_filter,
                                     const char **attrs,
                                     size_t *msgs_count,
                                     struct ldb_message ***msgs)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *basedn;
    char *filter;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    basedn = sysdb_group_base_dn(tmp_ctx, domain);
    if (!basedn) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to build base dn\n");
        ret = ENOMEM;
        goto fail;
    }

    filter = talloc_asprintf(tmp_ctx, "(&(%s)%s)", SYSDB_GC, sub_filter);
    if (!filter) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to build filter\n");
        ret = ENOMEM;
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Search groups with filter: %s\n", filter);

    ret = sysdb_cache_search_entry(mem_ctx, ldb, basedn,
                                   LDB_SCOPE_SUBTREE, filter, attrs,
                                   msgs_count, msgs);
    if (ret) {
        goto fail;
    }

    talloc_zfree(tmp_ctx);
    return EOK;

fail:
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "No such entry\n");
    }
    else if (ret) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
    }
    talloc_zfree(tmp_ctx);
    return ret;
}

int sysdb_search_groups(TALLOC_CTX *mem_ctx,
                        struct sss_domain_info *domain,
                        const char *sub_filter,
                        const char **attrs,
                        size_t *msgs_count,
                        struct ldb_message ***msgs)
{
    errno_t ret;

    ret = sysdb_cache_search_groups(mem_ctx, domain, domain->sysdb->ldb,
                                    sub_filter, attrs, msgs_count, msgs);
    if (ret != EOK) {
        return ret;
    }

    return sysdb_merge_msg_list_ts_attrs(domain->sysdb, *msgs_count, *msgs,
                                         attrs);
}

int sysdb_search_groups_by_timestamp(TALLOC_CTX *mem_ctx,
                                     struct sss_domain_info *domain,
                                     const char *sub_filter,
                                     const char *ts_sub_filter,
                                     const char **attrs,
                                     size_t *_msgs_count,
                                     struct ldb_message ***_msgs)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    struct ldb_result ts_res;
    struct ldb_message **msgs;
    size_t msgs_count;
    char *dn_filter = NULL;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_search_ts_groups(tmp_ctx, domain, ts_sub_filter, NULL, &ts_res);
    if (ret == ERR_NO_TS) {
        ret = sysdb_cache_search_groups(tmp_ctx, domain, domain->sysdb->ldb,
                                        ts_sub_filter, attrs, &msgs_count, &msgs);
        if (ret != EOK) {
            goto done;
        }

       ret = sysdb_merge_msg_list_ts_attrs(domain->sysdb, msgs_count, msgs, attrs);
       if (ret != EOK) {
           goto done;
       }

       goto immediately;
    } else if (ret != EOK) {
        goto done;
    }

    ret = cleanup_dn_filter(tmp_ctx, &ts_res, SYSDB_GC, sub_filter, &dn_filter);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_search_ts_matches(tmp_ctx, domain->sysdb, attrs,
                                  &ts_res, dn_filter, &res);
    if (ret != EOK) {
        goto done;
    }

    msgs_count = res->count;
    msgs = res->msgs;

immediately:
    *_msgs_count = msgs_count;
    *_msgs = talloc_steal(mem_ctx, msgs);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_search_ts_groups(TALLOC_CTX *mem_ctx,
                           struct sss_domain_info *domain,
                           const char *sub_filter,
                           const char **attrs,
                           struct ldb_result *res)
{
    size_t msgs_count;
    struct ldb_message **msgs;
    int ret;

    if (res == NULL) {
        return EINVAL;
    }

    memset(res, 0, sizeof(*res));

    if (domain->sysdb->ldb_ts == NULL) {
        return ERR_NO_TS;
    }

    ret = sysdb_cache_search_groups(mem_ctx, domain, domain->sysdb->ldb_ts,
                                    sub_filter, attrs, &msgs_count, &msgs);
    if (ret == EOK) {
        res->count = (unsigned)msgs_count;
        res->msgs = msgs;
    }

    return ret;
}

/* =Delete-Group-by-Name-OR-gid=========================================== */

int sysdb_delete_group(struct sss_domain_info *domain,
                       const char *name, gid_t gid)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *msg;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    if (name) {
        ret = sysdb_search_group_by_name(tmp_ctx, domain, name, NULL, &msg);
    } else {
        ret = sysdb_search_group_by_gid(tmp_ctx, domain, gid, NULL, &msg);
    }
    if (ret) {
        goto fail;
    }

    if (name && gid) {
        /* verify name/gid match */
        const char *c_name;
        uint64_t c_gid;

        c_name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
        c_gid = ldb_msg_find_attr_as_uint64(msg, SYSDB_GIDNUM, 0);
        if (c_name == NULL || c_gid == 0) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Attribute is missing but this should never happen!\n");
            ret = EFAULT;
            goto fail;
        }
        if (strcmp(name, c_name) || gid != c_gid) {
            /* this is not the entry we are looking for */
            ret = EINVAL;
            goto fail;
        }
    }

    ret = sysdb_delete_entry(domain->sysdb, msg->dn, false);
    if (ret) {
        goto fail;
    }

    talloc_zfree(tmp_ctx);
    return EOK;

fail:
    DEBUG(SSSDBG_TRACE_FUNC, "Error: %d (%s)\n", ret, strerror(ret));
    talloc_zfree(tmp_ctx);
    return ret;
}

/* =Search-Netgroups-with-Custom-Filter===================================== */

int sysdb_search_netgroups(TALLOC_CTX *mem_ctx,
                           struct sss_domain_info *domain,
                           const char *sub_filter,
                           const char **attrs,
                           size_t *msgs_count,
                           struct ldb_message ***msgs)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *basedn;
    char *filter;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    basedn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                            SYSDB_TMPL_NETGROUP_BASE, domain->name);
    if (!basedn) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to build base dn\n");
        ret = ENOMEM;
        goto fail;
    }

    filter = talloc_asprintf(tmp_ctx, "(&(%s)%s)", SYSDB_NC, sub_filter);
    if (!filter) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to build filter\n");
        ret = ENOMEM;
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Search netgroups with filter: %s\n", filter);

    ret = sysdb_search_entry(mem_ctx, domain->sysdb, basedn,
                             LDB_SCOPE_SUBTREE, filter, attrs,
                             msgs_count, msgs);
    if (ret) {
        goto fail;
    }

    talloc_zfree(tmp_ctx);
    return EOK;

fail:
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, "Entry not found\n");
    } else {
        DEBUG(SSSDBG_OP_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
    }
    talloc_zfree(tmp_ctx);
    return ret;
}

/* =Delete-Netgroup-by-Name============================================== */

int sysdb_delete_netgroup(struct sss_domain_info *domain,
                          const char *name)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *msg;
    int ret;

    if (!name) return EINVAL;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = sysdb_search_netgroup_by_name(tmp_ctx, domain, name, NULL, &msg);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "sysdb_search_netgroup_by_name failed: %d (%s)\n",
                   ret, strerror(ret));
        goto done;
    } else if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Netgroup does not exist, nothing to delete\n");
        ret = EOK;
        goto done;
    }

    ret = sysdb_delete_entry(domain->sysdb, msg->dn, false);
    if (ret != EOK) {
        goto done;
    }

done:
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_FUNC, "Error: %d (%s)\n", ret, strerror(ret));
    }
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_delete_by_sid(struct sysdb_ctx *sysdb,
                        struct sss_domain_info *domain,
                        const char *sid_str)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    int ret;

    if (!sid_str) return EINVAL;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = sysdb_search_object_by_sid(tmp_ctx, domain, sid_str, NULL, &res);

    if (ret == ENOENT) {
        /* No existing entry. Just quit. */
        DEBUG(SSSDBG_TRACE_FUNC,
              "search by sid did not return any results.\n");
        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "search by sid failed: %d (%s)\n",
              ret, strerror(ret));
        goto done;
    }

    if (res->count > 1) {
        DEBUG(SSSDBG_FATAL_FAILURE, "getbysid call returned more than one " \
                                     "result !?!\n");
        ret = EIO;
        goto done;
    }

    ret = sysdb_delete_entry(sysdb, res->msgs[0]->dn, false);
    if (ret != EOK) {
        goto done;
    }

done:
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
    }
    talloc_free(tmp_ctx);
    return ret;
}

/* ========= Authentication against cached password ============ */


errno_t check_failed_login_attempts(struct confdb_ctx *cdb,
                                    struct ldb_message *ldb_msg,
                                    uint32_t *failed_login_attempts,
                                    time_t *delayed_until)
{
    int ret;
    int allowed_failed_login_attempts;
    int failed_login_delay;
    time_t last_failed_login;
    time_t end;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    *delayed_until = -1;
    *failed_login_attempts = ldb_msg_find_attr_as_uint(ldb_msg,
                                                SYSDB_FAILED_LOGIN_ATTEMPTS, 0);
    last_failed_login = (time_t) ldb_msg_find_attr_as_int64(ldb_msg,
                                                    SYSDB_LAST_FAILED_LOGIN, 0);
    ret = confdb_get_int(cdb, CONFDB_PAM_CONF_ENTRY,
                         CONFDB_PAM_FAILED_LOGIN_ATTEMPTS,
                         CONFDB_DEFAULT_PAM_FAILED_LOGIN_ATTEMPTS,
                         &allowed_failed_login_attempts);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to read the number of allowed failed login "
                  "attempts.\n");
        ret = ERR_INTERNAL;
        goto done;
    }
    ret = confdb_get_int(cdb, CONFDB_PAM_CONF_ENTRY,
                         CONFDB_PAM_FAILED_LOGIN_DELAY,
                         CONFDB_DEFAULT_PAM_FAILED_LOGIN_DELAY,
                         &failed_login_delay);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to read the failed login delay.\n");
        ret = ERR_INTERNAL;
        goto done;
    }
    DEBUG(SSSDBG_TRACE_ALL,
          "Failed login attempts [%d], allowed failed login attempts [%d], "
              "failed login delay [%d].\n", *failed_login_attempts,
              allowed_failed_login_attempts, failed_login_delay);

    if (allowed_failed_login_attempts) {
        if (*failed_login_attempts >= allowed_failed_login_attempts) {
            if (failed_login_delay) {
                end = last_failed_login + (failed_login_delay * 60);
                if (end < time(NULL)) {
                    DEBUG(SSSDBG_TRACE_LIBS, "failed_login_delay has passed, "
                              "resetting failed_login_attempts.\n");
                    *failed_login_attempts = 0;
                } else {
                    DEBUG(SSSDBG_TRACE_LIBS,
                          "login delayed until %lld.\n", (long long) end);
                    *delayed_until = end;
                    ret = ERR_AUTH_DENIED;
                    goto done;
                }
            } else {
                DEBUG(SSSDBG_CONF_SETTINGS, "Too many failed logins.\n");
                ret = ERR_AUTH_DENIED;
                goto done;
            }
        }
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t check_for_combined_2fa_password(struct sss_domain_info *domain,
                                               struct ldb_message *ldb_msg,
                                               const char *password,
                                               const char *userhash)
{

    unsigned int cached_authtok_type;
    unsigned int cached_fa2_len;
    char *short_pw;
    char *comphash;
    size_t pw_len;
    TALLOC_CTX *tmp_ctx;
    int ret;

    cached_authtok_type = ldb_msg_find_attr_as_uint(ldb_msg,
                                                    SYSDB_CACHEDPWD_TYPE,
                                                    SSS_AUTHTOK_TYPE_EMPTY);
    if (cached_authtok_type != SSS_AUTHTOK_TYPE_2FA) {
        DEBUG(SSSDBG_TRACE_LIBS, "Wrong authtok type.\n");
        return EINVAL;
    }

    cached_fa2_len = ldb_msg_find_attr_as_uint(ldb_msg, SYSDB_CACHEDPWD_FA2_LEN,
                                               0);
    if (cached_fa2_len == 0) {
        DEBUG(SSSDBG_TRACE_LIBS, "Second factor size not available.\n");
        return EINVAL;
    }

    pw_len = strlen(password);
    if (pw_len < cached_fa2_len + domain->cache_credentials_min_ff_length) {
        DEBUG(SSSDBG_TRACE_LIBS, "Password too short.\n");
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    short_pw = talloc_strndup(tmp_ctx, password, (pw_len - cached_fa2_len));
    if (short_pw == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strndup failed.\n");
        ret = ENOMEM;
        goto done;
    }
    talloc_set_destructor((TALLOC_CTX *)short_pw,
                          sss_erase_talloc_mem_securely);

    ret = s3crypt_sha512(tmp_ctx, short_pw, userhash, &comphash);
    if (ret != EOK) {
        DEBUG(SSSDBG_CONF_SETTINGS, "Failed to create password hash.\n");
        ret = ERR_INTERNAL;
        goto done;
    }

    if (strcmp(userhash, comphash) != 0) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Hash of shorten password does not match.\n");
        ret = ERR_AUTH_FAILED;
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

int sysdb_cache_auth(struct sss_domain_info *domain,
                     const char *name,
                     const char *password,
                     struct confdb_ctx *cdb,
                     bool just_check,
                     time_t *_expire_date,
                     time_t *_delayed_until)
{
    TALLOC_CTX *tmp_ctx;
    const char *attrs[] = { SYSDB_NAME, SYSDB_CACHEDPWD, SYSDB_DISABLED,
                            SYSDB_LAST_LOGIN, SYSDB_LAST_ONLINE_AUTH,
                            "lastCachedPasswordChange",
                            "accountExpires", SYSDB_FAILED_LOGIN_ATTEMPTS,
                            SYSDB_LAST_FAILED_LOGIN, SYSDB_CACHEDPWD_TYPE,
                            SYSDB_CACHEDPWD_FA2_LEN, NULL };
    struct ldb_message *ldb_msg;
    const char *userhash;
    char *comphash;
    uint64_t lastLogin = 0;
    int cred_expiration;
    uint32_t failed_login_attempts = 0;
    struct sysdb_attrs *update_attrs;
    bool authentication_successful = false;
    time_t expire_date = -1;
    time_t delayed_until = -1;
    int ret;

    if (name == NULL || *name == '\0') {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing user name.\n");
        return EINVAL;
    }

    if (cdb == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing config db context.\n");
        return EINVAL;
    }

    if (domain->sysdb == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing sysdb db context.\n");
        return EINVAL;
    }

    if (!domain->cache_credentials) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Cached credentials not available.\n");
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = ldb_transaction_start(domain->sysdb->ldb);
    if (ret) {
        talloc_zfree(tmp_ctx);
        ret = sysdb_error_to_errno(ret);
        return ret;
    }

    ret = sysdb_search_user_by_name(tmp_ctx, domain, name, attrs, &ldb_msg);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sysdb_search_user_by_name failed [%d][%s].\n",
                  ret, strerror(ret));
        if (ret == ENOENT) ret = ERR_ACCOUNT_UNKNOWN;
        goto done;
    }

    /* Check offline_auth_cache_timeout */
    lastLogin = ldb_msg_find_attr_as_uint64(ldb_msg,
                                            SYSDB_LAST_ONLINE_AUTH,
                                            0);

    ret = confdb_get_int(cdb, CONFDB_PAM_CONF_ENTRY,
                         CONFDB_PAM_CRED_TIMEOUT, 0, &cred_expiration);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to read expiration time of offline credentials.\n");
        goto done;
    }
    DEBUG(SSSDBG_TRACE_ALL, "Offline credentials expiration is [%d] days.\n",
              cred_expiration);

    if (cred_expiration) {
        expire_date = lastLogin + (cred_expiration * 86400);
        if (expire_date < time(NULL)) {
            DEBUG(SSSDBG_CONF_SETTINGS, "Cached user entry is too old.\n");
            expire_date = 0;
            ret = ERR_CACHED_CREDS_EXPIRED;
            goto done;
        }
    } else {
        expire_date = 0;
    }

    ret = check_failed_login_attempts(cdb, ldb_msg, &failed_login_attempts,
                                      &delayed_until);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to check login attempts\n");
        goto done;
    }

    /* TODO: verify user account (disabled, expired ...) */

    userhash = ldb_msg_find_attr_as_string(ldb_msg, SYSDB_CACHEDPWD, NULL);
    if (userhash == NULL || *userhash == '\0') {
        DEBUG(SSSDBG_CONF_SETTINGS, "Cached credentials not available.\n");
        ret = ERR_NO_CACHED_CREDS;
        goto done;
    }

    ret = s3crypt_sha512(tmp_ctx, password, userhash, &comphash);
    if (ret) {
        DEBUG(SSSDBG_CONF_SETTINGS, "Failed to create password hash.\n");
        ret = ERR_INTERNAL;
        goto done;
    }

    update_attrs = sysdb_new_attrs(tmp_ctx);
    if (update_attrs == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_new_attrs failed.\n");
        ret = ENOMEM;
        goto done;
    }

    if (strcmp(userhash, comphash) == 0
            || check_for_combined_2fa_password(domain, ldb_msg,
                                               password, userhash) == EOK) {
        /* TODO: probable good point for audit logging */
        DEBUG(SSSDBG_CONF_SETTINGS, "Hashes do match!\n");
        authentication_successful = true;

        if (just_check) {
            ret = EOK;
            goto done;
        }

        ret = sysdb_attrs_add_time_t(update_attrs,
                                     SYSDB_LAST_LOGIN, time(NULL));
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "sysdb_attrs_add_time_t failed, "
                      "but authentication is successful.\n");
            ret = EOK;
            goto done;
        }

        ret = sysdb_attrs_add_uint32(update_attrs,
                                     SYSDB_FAILED_LOGIN_ATTEMPTS, 0U);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "sysdb_attrs_add_uint32 failed, "
                      "but authentication is successful.\n");
            ret = EOK;
            goto done;
        }

    } else {
        DEBUG(SSSDBG_CONF_SETTINGS, "Authentication failed.\n");
        authentication_successful = false;

        ret = sysdb_attrs_add_time_t(update_attrs,
                                     SYSDB_LAST_FAILED_LOGIN,
                                     time(NULL));
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "sysdb_attrs_add_time_t failed.\n");
            goto done;
        }

        ret = sysdb_attrs_add_uint32(update_attrs,
                                     SYSDB_FAILED_LOGIN_ATTEMPTS,
                                     ++failed_login_attempts);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "sysdb_attrs_add_uint32 failed.\n");
            goto done;
        }
    }

    ret = sysdb_set_user_attr(domain, name, update_attrs,
                              LDB_FLAG_MOD_REPLACE);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to update Login attempt information!\n");
    }

done:
    if (_expire_date != NULL) {
        *_expire_date = expire_date;
    }
    if (_delayed_until != NULL) {
        *_delayed_until = delayed_until;
    }
    if (ret) {
        ldb_transaction_cancel(domain->sysdb->ldb);
    } else {
        ret = ldb_transaction_commit(domain->sysdb->ldb);
        ret = sysdb_error_to_errno(ret);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to commit transaction!\n");
        }
    }
    if (authentication_successful) {
        ret = EOK;
    } else {
        if (ret == EOK) {
            ret = ERR_AUTH_FAILED;
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t sysdb_update_members_ex(struct sss_domain_info *domain,
                                       const char *member,
                                       enum sysdb_member_type type,
                                       const char *const *add_groups,
                                       const char *const *del_groups,
                                       bool is_dn)
{
    errno_t ret;
    errno_t sret;
    int i;
    bool in_transaction = false;

    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    if(!tmp_ctx) {
        return ENOMEM;
    }

    ret = sysdb_transaction_start(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to start update transaction\n");
        goto done;
    }

    in_transaction = true;

    if (add_groups) {
        /* Add the user to all add_groups */
        for (i = 0; add_groups[i]; i++) {
            ret = sysdb_add_group_member(domain, add_groups[i],
                                         member, type, is_dn);
            if (ret != EOK) {
                if (ret != EEXIST) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Could not add member [%s] to group [%s]. "
                              "Skipping.\n", member, add_groups[i]);
                } else {
                    DEBUG(SSSDBG_FUNC_DATA,
                          "Group [%s] already has member [%s]. Skipping.\n",
                          add_groups[i], member);
                }
                /* Continue on, we should try to finish the rest */
            }
        }
    }

    if (del_groups) {
        /* Remove the user from all del_groups */
        for (i = 0; del_groups[i]; i++) {
            ret = sysdb_remove_group_member(domain, del_groups[i],
                                            member, type, is_dn);
            if (ret != EOK) {
                if (ret != ENOENT) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Could not remove member [%s] from group [%s]. "
                              "Skipping\n", member, del_groups[i]);
                } else {
                    DEBUG(SSSDBG_FUNC_DATA,
                          "No member [%s] in group [%s]. "
                              "Skipping\n", member, del_groups[i]);
                }
                /* Continue on, we should try to finish the rest */
            }
        }
    }

    ret = sysdb_transaction_commit(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction\n");
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

errno_t sysdb_update_members(struct sss_domain_info *domain,
                             const char *member,
                             enum sysdb_member_type type,
                             const char *const *add_groups,
                             const char *const *del_groups)
{
    return sysdb_update_members_ex(domain, member, type,
                                   add_groups, del_groups, false);
}

errno_t sysdb_update_members_dn(struct sss_domain_info *member_domain,
                                const char *member,
                                enum sysdb_member_type type,
                                const char *const *add_groups,
                                const char *const *del_groups)
{
    return sysdb_update_members_ex(member_domain, member, type,
                                   add_groups, del_groups, true);
}

errno_t sysdb_remove_attrs(struct sss_domain_info *domain,
                           const char *name,
                           enum sysdb_member_type type,
                           char **remove_attrs)
{
    errno_t ret;
    errno_t sret = EOK;
    bool in_transaction = false;
    struct ldb_message *msg;
    int lret;
    size_t i;

    msg = ldb_msg_new(NULL);
    if (!msg) return ENOMEM;

    switch(type) {
    case SYSDB_MEMBER_USER:
        msg->dn = sysdb_user_dn(msg, domain, name);
        break;

    case SYSDB_MEMBER_GROUP:
        msg->dn = sysdb_group_dn(msg, domain, name);
        break;

    case SYSDB_MEMBER_NETGROUP:
        msg->dn = sysdb_netgroup_dn(msg, domain, name);
        break;

    case SYSDB_MEMBER_SERVICE:
        msg->dn = sysdb_svc_dn(domain->sysdb, msg, domain->name, name);
        break;
    case SYSDB_MEMBER_HOST:
        msg->dn = sysdb_host_dn(msg, domain, name);
        break;
    case SYSDB_MEMBER_IP_NETWORK:
        msg->dn = sysdb_ipnetwork_dn(msg, domain, name);
        break;
    }
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_transaction_start(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto done;
    }

    in_transaction = true;

    for (i = 0; remove_attrs[i]; i++) {
        /* SYSDB_MEMBEROF is exclusively handled by the memberof plugin */
        if (strcasecmp(remove_attrs[i], SYSDB_MEMBEROF) == 0) {
            continue;
        }
        DEBUG(SSSDBG_TRACE_INTERNAL, "Removing attribute [%s] from [%s]\n",
                  remove_attrs[i], name);
        lret = ldb_msg_add_empty(msg, remove_attrs[i],
                                 LDB_FLAG_MOD_DELETE, NULL);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        /* We need to do individual modifies so that we can
         * skip unknown attributes. Otherwise, any nonexistent
         * attribute in the sysdb will cause other removals to
         * fail.
         */
        lret = ldb_modify(domain->sysdb->ldb, msg);
        if (lret != LDB_SUCCESS && lret != LDB_ERR_NO_SUCH_ATTRIBUTE) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "ldb_modify failed: [%s](%d)[%s]\n",
                  ldb_strerror(lret), lret, ldb_errstring(domain->sysdb->ldb));
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        /* Remove this attribute and move on to the next one */
        ldb_msg_remove_attr(msg, remove_attrs[i]);
    }

    ret = sysdb_transaction_commit(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction\n");
        goto done;
    }

    in_transaction = false;

    ret = EOK;
done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(domain->sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not cancel transaction\n");
        }
    }
    talloc_free(msg);
    return ret;
}

static errno_t sysdb_search_object_attr(TALLOC_CTX *mem_ctx,
                                        struct sss_domain_info *domain,
                                        const char *filter,
                                        const char **attrs,
                                        bool expect_only_one_result,
                                        struct ldb_result **_res)
{
    TALLOC_CTX *tmp_ctx;
    const char *def_attrs[] = { SYSDB_NAME, SYSDB_UIDNUM, SYSDB_GIDNUM,
                                ORIGINALAD_PREFIX SYSDB_NAME,
                                SYSDB_DEFAULT_ATTRS,
                                NULL };
    struct ldb_dn *basedn;
    int ret;
    struct ldb_result *res = NULL;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    basedn = sysdb_domain_dn(tmp_ctx, domain);
    if (basedn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new_fmt failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_search(domain->sysdb->ldb, tmp_ctx, &res, basedn,
                     LDB_SCOPE_SUBTREE, attrs ? attrs : def_attrs,
                     "%s", filter);
    if (ret != EOK) {
        ret = sysdb_error_to_errno(ret);
        DEBUG(SSSDBG_OP_FAILURE, "ldb_search failed.\n");
        goto done;
    }

    if (res->count > 1 && expect_only_one_result) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Search with filter [%s] returned more than one object.\n",
              filter);
        ret = EINVAL;
        goto done;
    } else if (res->count == 0) {
        ret = ENOENT;
        goto done;
    }

    /* Merge in the timestamps from the fast ts db */
    ret = sysdb_merge_res_ts_attrs(domain->sysdb, res, attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Cannot merge timestamp cache values\n");
        /* non-fatal */
    }

    *_res = talloc_steal(mem_ctx, res);

done:
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, "No such entry.\n");
    } else if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
    }

    talloc_zfree(tmp_ctx);
    return ret;
}

static errno_t sysdb_search_object_by_str_attr(TALLOC_CTX *mem_ctx,
                                               struct sss_domain_info *domain,
                                               const char *filter_tmpl,
                                               const char *str,
                                               const char **attrs,
                                               bool expect_only_one_result,
                                               struct ldb_result **_res)
{
    char *filter = NULL;
    errno_t ret;
    char *sanitized = NULL;

    if (str == NULL) {
        return EINVAL;
    }

    ret = sss_filter_sanitize(NULL, str, &sanitized);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_filter_sanitize failed.\n");
        goto done;
    }

    filter = talloc_asprintf(NULL, filter_tmpl, sanitized);
    if (filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_object_attr(mem_ctx, domain, filter, attrs,
                                   expect_only_one_result, _res);

done:
    talloc_free(sanitized);
    talloc_free(filter);
    return ret;
}

errno_t sysdb_search_object_by_id(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *domain,
                                  uint32_t id,
                                  const char **attrs,
                                  struct ldb_result **res)
{
    char *filter;
    errno_t ret;

    filter = talloc_asprintf(NULL, SYSDB_ID_FILTER, id, id);
    if (filter == NULL) {
        return ENOMEM;
    }

    ret = sysdb_search_object_attr(mem_ctx, domain, filter, attrs, true, res);

    talloc_free(filter);
    return ret;
}

errno_t sysdb_search_object_by_name(TALLOC_CTX *mem_ctx,
                                    struct sss_domain_info *domain,
                                    const char *name,
                                    const char **attrs,
                                    struct ldb_result **res)
{
    TALLOC_CTX *tmp_ctx;
    char *filter;
    char *sanitized_name;
    char *sanitized_alias_name;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = sss_filter_sanitize_for_dom(tmp_ctx, name, domain, &sanitized_name,
                                      &sanitized_alias_name);
    if (ret != EOK) {
        goto done;
    }

    filter = talloc_asprintf(tmp_ctx, SYSDB_NAME_FILTER, sanitized_alias_name,
                             sanitized_name);
    if (filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_object_attr(mem_ctx, domain, filter, attrs, false, res);

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_search_object_by_sid(TALLOC_CTX *mem_ctx,
                                   struct sss_domain_info *domain,
                                   const char *sid_str,
                                   const char **attrs,
                                   struct ldb_result **res)
{
    return sysdb_search_object_by_str_attr(mem_ctx, domain, SYSDB_SID_FILTER,
                                           sid_str, attrs, true, res);
}

errno_t sysdb_search_object_by_uuid(TALLOC_CTX *mem_ctx,
                                    struct sss_domain_info *domain,
                                    const char *uuid_str,
                                    const char **attrs,
                                    struct ldb_result **res)
{
    return sysdb_search_object_by_str_attr(mem_ctx, domain, SYSDB_UUID_FILTER,
                                           uuid_str, attrs, true, res);
}

errno_t sysdb_cert_derb64_to_ldap_filter(TALLOC_CTX *mem_ctx,
                                         const char *derb64,
                                         const char *attr_name,
                                         char **ldap_filter)
{
    int ret;
    unsigned char *der;
    size_t der_size;
    char *val;

    if (derb64 == NULL || attr_name == NULL) {
        return EINVAL;
    }

    der = sss_base64_decode(mem_ctx, derb64, &der_size);
    if (der == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_base64_decode failed.\n");
        return EINVAL;
    }

    ret = bin_to_ldap_filter_value(mem_ctx, der, der_size, &val);
    talloc_free(der);
    if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "bin_to_ldap_filter_value failed.\n");
            return ret;
    }

    *ldap_filter = talloc_asprintf(mem_ctx, "(%s=%s)", attr_name, val);
    talloc_free(val);
    if (*ldap_filter == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
            return ENOMEM;
    }

    return EOK;
}

errno_t sysdb_search_object_by_cert(TALLOC_CTX *mem_ctx,
                                    struct sss_domain_info *domain,
                                    const char *cert,
                                    const char **attrs,
                                    struct ldb_result **res)
{
    int ret;
    char *user_filter = NULL;
    char *filter = NULL;

    ret = sysdb_cert_derb64_to_ldap_filter(mem_ctx, cert,
                                           SYSDB_USER_MAPPED_CERT,
                                           &user_filter);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_cert_derb64_to_ldap_filter failed.\n");
        return ret;
    }

    filter = talloc_asprintf(NULL, SYSDB_USER_CERT_FILTER, user_filter);
    talloc_free(user_filter);
    if (filter == NULL) {
        return ENOMEM;
    }

    ret = sysdb_search_object_attr(mem_ctx, domain, filter, attrs, false, res);

    talloc_free(filter);

    return ret;
}

errno_t sysdb_search_user_by_cert(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *domain,
                                  const char *cert,
                                  struct ldb_result **res)
{
    const char *user_attrs[] = SYSDB_PW_ATTRS;

    return sysdb_search_object_by_cert(mem_ctx, domain, cert, user_attrs, res);
}

errno_t sysdb_remove_mapped_data(struct sss_domain_info *domain,
                                 struct sysdb_attrs *mapped_attr)
{
    int ret;
    char *val;
    char *filter;
    const char *attrs[] = {SYSDB_NAME, NULL};
    struct ldb_result *res = NULL;
    size_t c;
    bool all_ok = true;

    if (mapped_attr->num != 1 || mapped_attr->a[0].num_values != 1) {
        DEBUG(SSSDBG_OP_FAILURE, "Unsupported number of attributes.\n");
        return EINVAL;
    }

    ret = bin_to_ldap_filter_value(NULL, mapped_attr->a[0].values[0].data,
                                   mapped_attr->a[0].values[0].length, &val);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "bin_to_ldap_filter_value failed.\n");
        return ret;
    }

    filter = talloc_asprintf(NULL, "(&("SYSDB_UC")(%s=%s))",
                             mapped_attr->a[0].name, val);
    talloc_free(val);
    if (filter == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        return ENOMEM;
    }

    ret = sysdb_search_object_attr(NULL, domain, filter, attrs, false, &res);
    talloc_free(filter);
    if (ret == ENOENT || res == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "Mapped data not found.\n");
        talloc_free(res);
        return EOK;
    } else if (ret != EOK) {
        talloc_free(res);
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_search_object_attr failed.\n");
        return ret;
    }

    for (c = 0; c < res->count; c++) {
        DEBUG(SSSDBG_TRACE_ALL, "Removing mapped data from [%s].\n",
                                ldb_dn_get_linearized(res->msgs[c]->dn));
        /* The timestamp cache is skipped on purpose here. */
        ret = sysdb_set_cache_entry_attr(domain->sysdb->ldb, res->msgs[c]->dn,
                                         mapped_attr, SYSDB_MOD_DEL);
        if (ret != EOK) {
            all_ok = false;
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to remove mapped data from [%s], skipping.\n",
                  ldb_dn_get_linearized(res->msgs[c]->dn));
        }
    }
    talloc_free(res);

    return (all_ok ? EOK : EIO);
}

errno_t sysdb_remove_cert(struct sss_domain_info *domain,
                          const char *cert)
{
    struct ldb_message_element el = { 0, SYSDB_USER_MAPPED_CERT, 0, NULL };
    struct sysdb_attrs del_attrs = { 1, &el };
    const char *attrs[] = {SYSDB_NAME, NULL};
    struct ldb_result *res = NULL;
    unsigned int i;
    errno_t ret;

    ret = sysdb_search_object_by_cert(NULL, domain, cert, attrs, &res);
    if (ret == ENOENT || res == NULL) {
        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to lookup object by cert "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    /* Certificate may be found on more objects, remove it from all.
     * If object contains more then one certificate, we still remove the
     * whole attribute since it will be downloaded again. */
    for (i = 0; i < res->count; i++) {
        ret = sysdb_set_entry_attr(domain->sysdb, res->msgs[0]->dn,
                                   &del_attrs, SYSDB_MOD_DEL);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to remove certificate "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            goto done;
        }

        ret = sysdb_mark_entry_as_expired_ldb_dn(domain, res->msgs[0]->dn);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Unable to expire object "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            continue;
        }
    }

done:
    talloc_free(res);
    return ret;
}

errno_t sysdb_get_sids_of_members(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *dom,
                                  const char *group_name,
                                  const char ***_sids,
                                  const char ***_dns,
                                  size_t *_n)
{
    errno_t ret;
    size_t i, m_count;
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *msg;
    struct ldb_message **members;
    const char *attrs[] = { SYSDB_SID_STR, NULL };
    const char **sids = NULL, **dns = NULL;
    size_t n = 0;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_search_group_by_name(tmp_ctx, dom, group_name, NULL, &msg);
    if (ret != EOK) {
        goto done;
    }

    /* Get sid_str attribute of all elements pointed to by group members */
    ret = sysdb_asq_search(tmp_ctx, dom, msg->dn, NULL, SYSDB_MEMBER, attrs,
                           &m_count, &members);
    if (ret != EOK) {
        goto done;
    }

    sids = talloc_array(tmp_ctx, const char*, m_count);
    if (sids == NULL) {
        ret = ENOMEM;
        goto done;
    }

    dns = talloc_array(tmp_ctx, const char*, m_count);
    if (dns == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i=0; i < m_count; i++) {
        const char *sidstr;

        sidstr = ldb_msg_find_attr_as_string(members[i], SYSDB_SID_STR, NULL);

        if (sidstr != NULL) {
            sids[n] = talloc_steal(sids, sidstr);

            dns[n] = talloc_steal(dns, ldb_dn_get_linearized(members[i]->dn));
            if (dns[n] == NULL) {
                ret = ENOMEM;
                goto done;
            }
            n++;
        }
    }

    if (n == 0) {
        ret = ENOENT;
        goto done;
    }

    *_n = n;
    *_sids = talloc_steal(mem_ctx, sids);
    *_dns = talloc_steal(mem_ctx, dns);

    ret = EOK;

done:
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, "No such entry\n");
    } else if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
    }
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_handle_original_uuid(const char *orig_name,
                                   struct sysdb_attrs *src_attrs,
                                   const char *src_name,
                                   struct sysdb_attrs *dest_attrs,
                                   const char *dest_name)
{
    int ret;
    struct ldb_message_element *el;
    char guid_str_buf[GUID_STR_BUF_SIZE];

    if (orig_name == NULL) {
        /* This provider doesn't handle UUIDs */
        return ENOENT;
    }

    if (src_attrs == NULL || src_name == NULL
            || dest_attrs == NULL || dest_name == NULL) {
        return EINVAL;
    }

    ret = sysdb_attrs_get_el_ext(src_attrs, src_name, false, &el);
    if (ret != EOK) {
        if (ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_el failed.\n");
        }
        return ret;
    }

    if (el->num_values != 1) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Found more than one UUID value, using the first.\n");
    }

    /* Check if we got a binary AD objectGUID */
    if (el->values[0].length == GUID_BIN_LENGTH
            && strcasecmp(orig_name, "objectGUID") == 0) {
        ret = guid_blob_to_string_buf(el->values[0].data, guid_str_buf,
                                      GUID_STR_BUF_SIZE);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "guid_blob_to_string_buf failed.\n");
            return ret;
        }

        ret = sysdb_attrs_add_string(dest_attrs, dest_name, guid_str_buf);
    } else {
        ret = sysdb_attrs_add_string(dest_attrs, dest_name,
                                     (const char *)el->values[0].data);
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_add_string failed.\n");
        return ret;
    }

    return EOK;
}

/* Mark entry as expired */
errno_t sysdb_mark_entry_as_expired_ldb_dn(struct sss_domain_info *dom,
                                           struct ldb_dn *ldbdn)
{
    struct ldb_message *msg;
    errno_t ret;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    msg = ldb_msg_new(tmp_ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = ldbdn;

    ret = ldb_msg_add_empty(msg, SYSDB_CACHE_EXPIRE,
                            LDB_FLAG_MOD_REPLACE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = ldb_msg_add_string(msg, SYSDB_CACHE_EXPIRE, "1");
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = ldb_msg_add_empty(msg, SYSDB_ORIG_MODSTAMP,
                            LDB_FLAG_MOD_REPLACE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = ldb_msg_add_string(msg, SYSDB_ORIG_MODSTAMP, "1");
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = ldb_modify(dom->sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    if (dom->sysdb->ldb_ts != NULL) {
        ret = ldb_modify(dom->sysdb->ldb_ts, msg);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Could not mark an entry as expired in the timestamp cache\n");
            /* non-fatal */
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_mark_entry_as_expired_ldb_val(struct sss_domain_info *dom,
                                            struct ldb_val *dn_val)
{
    struct ldb_dn *ldbdn;
    errno_t ret;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ldbdn = ldb_dn_from_ldb_val(tmp_ctx, dom->sysdb->ldb, dn_val);
    if (ldbdn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_mark_entry_as_expired_ldb_dn(dom, ldbdn);

done:
    talloc_free(tmp_ctx);
    return ret;
}

/* User/group invalidation of cache by direct writing to persistent cache
 * WARNING: This function can cause performance issue!!
 * is_user = true --> user invalidation
 * is_user = false --> group invalidation
 */
int sysdb_invalidate_cache_entry(struct sss_domain_info *domain,
                                 const char *name,
                                 bool is_user)
{
    TALLOC_CTX *tmp_ctx;
    struct sysdb_ctx *sysdb = domain->sysdb;
    struct ldb_dn *entry_dn = NULL;
    struct sysdb_attrs *attrs = NULL;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    if (is_user == true) {
        entry_dn = sysdb_user_dn(tmp_ctx, domain, name);
    } else {
        entry_dn = sysdb_group_dn(tmp_ctx, domain, name);
    }

    if (entry_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    attrs = sysdb_new_attrs(tmp_ctx);
    if (attrs == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Could not create sysdb attributes\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_CACHE_EXPIRE, 1);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not add expiration time to attributes\n");
        goto done;
    }

    ret = sysdb_set_cache_entry_attr(sysdb->ldb, entry_dn,
                                     attrs, SYSDB_MOD_REP);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Cannot set attrs for %s, %d [%s]\n",
              ldb_dn_get_linearized(entry_dn), ret, sss_strerror(ret));
        goto done;
    }

    if (sysdb->ldb_ts != NULL) {
        ret = sysdb_set_cache_entry_attr(sysdb->ldb_ts, entry_dn,
                                         attrs, SYSDB_MOD_REP);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Cannot set attrs in the timestamp cache for %s, %d [%s]\n",
                  ldb_dn_get_linearized(entry_dn), ret, sss_strerror(ret));
            /* non-fatal */
        }
    }

    DEBUG(SSSDBG_FUNC_DATA,
          "Cache entry [%s] has been invalidated.\n",
          ldb_dn_get_linearized(entry_dn));

    ret = EOK;

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

/* === Operation On Indexes ================================== */
errno_t sysdb_ldb_list_indexes(TALLOC_CTX *mem_ctx,
                               struct ldb_context *ldb,
                               const char *attribute,
                               const char ***_indexes)
{
    errno_t ret;
    int j;
    int i;
    int ldb_ret;
    unsigned int length;
    unsigned int attr_length = (attribute == NULL ? 0 : strlen(attribute));
    char *data;
    struct ldb_dn *dn;
    struct ldb_result *res;
    struct ldb_message_element *el;
    const char *attrs[] = { SYSDB_IDXATTR, NULL };
    const char **indexes = NULL;

    dn = ldb_dn_new(mem_ctx, ldb, SYSDB_INDEXES);
    if (dn == NULL) {
        ERROR_OUT(ret, EIO, done);
    }

    ldb_ret = ldb_search(ldb, mem_ctx, &res, dn, LDB_SCOPE_BASE, attrs, NULL);
    if (ldb_ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_search() failed: %i\n", ldb_ret);
        ERROR_OUT(ret, EIO, done);
    }
    if (res->count != 1) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ldb_search() returned %u messages. Expected 1.\n", res->count);
        ERROR_OUT(ret, EIO, done);
    }
    if (res->msgs[0]->num_elements != 1) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ldb_search() returned %u elements. Expected 1.\n",
              res->msgs[0]->num_elements);
        ERROR_OUT(ret, EIO, done);
    }

    el = res->msgs[0]->elements;
    j = 0;
    indexes = talloc_zero_array(mem_ctx, const char *, 1);
    if (indexes == NULL) ERROR_OUT(ret, ENOMEM, done);

    for (i = 0; i < el->num_values; i++) {
        data = (char *) el->values[i].data;
        length = (int) el->values[i].length;
        if (attr_length == 0 ||
            (attr_length == length && strncmp(attribute, data, length) == 0)) {
            indexes = talloc_realloc(mem_ctx, indexes, const char *, j + 2);
            if (indexes == NULL) ERROR_OUT(ret, ENOMEM, done);

            indexes[j] = talloc_asprintf(indexes, "%.*s", length, data);
            if (indexes[j] == NULL) ERROR_OUT(ret, ENOMEM, done);

            indexes[++j] = NULL;
        }
    }

    *_indexes = indexes;
    ret = EOK;

done:
    talloc_free(dn);
    if (ret != EOK) {
        talloc_free(indexes);
    }

    return ret;
}

errno_t sysdb_ldb_mod_index(TALLOC_CTX *mem_ctx,
                            enum sysdb_index_actions action,
                            struct ldb_context *ldb,
                            const char *attribute)
{
    errno_t ret;
    int ldb_ret;
    struct ldb_message *msg;

    msg = ldb_msg_new(mem_ctx);
    if (msg == NULL) {
        ERROR_OUT(ret, ENOMEM, done);
    }

    msg->dn = ldb_dn_new(msg, ldb, SYSDB_INDEXES);
    if (msg->dn == NULL) {
        ERROR_OUT(ret, EIO, done);
    }

    if (action == SYSDB_IDX_CREATE) {
        ldb_ret = sysdb_add_string(msg, SYSDB_IDXATTR, attribute);
    } else if (action == SYSDB_IDX_DELETE) {
        ldb_ret = sysdb_delete_string(msg, SYSDB_IDXATTR, attribute);
    } else {
        ERROR_OUT(ret, EINVAL, done);
    }
    if (ldb_ret != LDB_SUCCESS) {
        ERROR_OUT(ret, EIO, done);
    }

    ldb_ret = sss_ldb_modify(ldb, msg, false);
    if (ldb_ret != LDB_SUCCESS) {
        switch (ldb_ret) {
        case LDB_ERR_NO_SUCH_ATTRIBUTE:
            ret = ENOENT;
            break;
        case LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS:
            ret = EEXIST;
            break;
        default:
            ret = EIO;
        }
        goto done;
    }

    ret = EOK;

done:
    talloc_free(msg);

    return ret;
}

errno_t sysdb_manage_index(TALLOC_CTX *mem_ctx, enum sysdb_index_actions action,
                           const char *name, const char *attribute,
                           const char ***_indexes)
{
    errno_t ret;
    struct ldb_context *ldb = NULL;

    ret = sysdb_ldb_connect(mem_ctx, name, LDB_FLG_DONT_CREATE_DB, &ldb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_ldb_connect() failed.\n");
        goto done;
    }

    switch (action) {
    case SYSDB_IDX_CREATE:
    case SYSDB_IDX_DELETE:
        ret = sysdb_ldb_mod_index(ldb, action, ldb, attribute);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_ldb_mod_index() failed.\n");
            goto done;
        }
        break;
    case SYSDB_IDX_LIST:
        ret = sysdb_ldb_list_indexes(mem_ctx, ldb, attribute, _indexes);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_ldb_list_indexes() failed.\n");
            goto done;
        }
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unknown action: %i\n", action);
        goto done;
    }

done:
    talloc_free(ldb);

    return ret;
}
