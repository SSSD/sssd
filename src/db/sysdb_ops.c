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
#include "db/sysdb_services.h"
#include "db/sysdb_autofs.h"
#include "util/crypto/sss_crypto.h"
#include <time.h>

int add_string(struct ldb_message *msg, int flags,
               const char *attr, const char *value)
{
    int ret;

    ret = ldb_msg_add_empty(msg, attr, flags, NULL);
    if (ret == LDB_SUCCESS) {
        ret = ldb_msg_add_string(msg, attr, value);
        if (ret == LDB_SUCCESS) return EOK;
    }
    return ENOMEM;
}

int add_ulong(struct ldb_message *msg, int flags,
              const char *attr, unsigned long value)
{
    int ret;

    ret = ldb_msg_add_empty(msg, attr, flags, NULL);
    if (ret == LDB_SUCCESS) {
        ret = ldb_msg_add_fmt(msg, attr, "%lu", value);
        if (ret == LDB_SUCCESS) return EOK;
    }
    return ENOMEM;
}

static uint32_t get_attr_as_uint32(struct ldb_message *msg, const char *attr)
{
    const struct ldb_val *v = ldb_msg_find_ldb_val(msg, attr);
    long long int l;

    if (!v || !v->data) {
        return 0;
    }

    errno = 0;
    l = strtoll((const char *)v->data, NULL, 10);
    if (errno) {
        return (uint32_t)-1;
    }

    if (l < 0 || l > ((uint32_t)(-1))) {
        return (uint32_t)-1;
    }

    return l;
}


/* Wrapper around ldb_search to ensure that if zero results are found then
 * ENOENT is returned
 */
errno_t sss_ldb_search(struct ldb_context *ldb, TALLOC_CTX *mem_ctx,
                       struct ldb_result **_result, struct ldb_dn *base,
                       enum ldb_scope scope, const char * const *attrs,
                       const char *exp_fmt, ...)
{
    char *s;
    int lret;
    va_list ap;
    errno_t ret;
    TALLOC_CTX *tmp_ctx = NULL;

    if (exp_fmt != NULL) {
        tmp_ctx = talloc_new(NULL);
        if (tmp_ctx == NULL) {
            ret = ENOMEM;
            goto done;
        }

        va_start(ap, exp_fmt);
        s = talloc_vasprintf(tmp_ctx, exp_fmt, ap);
        va_end(ap);

        if (s == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Failed to process filter.\n");
            ret = ENOMEM;
            goto done;
        }
        lret = ldb_search(ldb, mem_ctx, _result, base, scope, attrs, "%s", s);
    } else {
        lret = ldb_search(ldb, mem_ctx, _result, base, scope, attrs, NULL);
    }

    ret = sysdb_error_to_errno(lret);
    if (ret != EOK) {
        goto done;
    }

    if ((*_result)->count == 0) {
        ret = ENOENT;
        goto done;
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

/*
 * The wrapper around ldb_modify that uses LDB_CONTROL_PERMISSIVE_MODIFY_OID
 * so that on adds entries that already exist are skipped and similarly
 * entries that are missing are ignored on deletes
 */
int sss_ldb_modify_permissive(struct ldb_context *ldb,
                              struct ldb_message *msg)
{
    struct ldb_request *req;
    int ret = EOK;

    ret = ldb_build_mod_req(&req, ldb, ldb,
                            msg,
                            NULL,
                            NULL,
                            ldb_op_default_callback,
                            NULL);

    if (ret != LDB_SUCCESS) return ret;

    ret = ldb_request_add_control(req, LDB_CONTROL_PERMISSIVE_MODIFY_OID,
                                  false, NULL);
    if (ret != LDB_SUCCESS) {
        talloc_free(req);
        return ret;
    }

    ret = ldb_request(ldb, req);
    if (ret == LDB_SUCCESS) {
        ret = ldb_wait(req->handle, LDB_WAIT_ALL);
    }

    talloc_free(req);

    return ret;
}

#define ERROR_OUT(v, r, l) do { v = r; goto l; } while(0)


/* =Remove-Entry-From-Sysdb=============================================== */

int sysdb_delete_entry(struct sysdb_ctx *sysdb,
                       struct ldb_dn *dn,
                       bool ignore_not_found)
{
    int ret;

    ret = ldb_delete(sysdb->ldb, dn);
    switch (ret) {
    case LDB_SUCCESS:
        return EOK;
    case LDB_ERR_NO_SUCH_OBJECT:
        if (ignore_not_found) {
            return EOK;
        }
        /* fall through */
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "LDB Error: %s(%d)\nError Message: [%s]\n",
                  ldb_strerror(ret), ret, ldb_errstring(sysdb->ldb));
        return sysdb_error_to_errno(ret);
    }
}

/* =Remove-Subentries-From-Sysdb=========================================== */

int sysdb_delete_recursive(struct sysdb_ctx *sysdb,
                           struct ldb_dn *dn,
                           bool ignore_not_found)
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
                             LDB_SCOPE_SUBTREE, "(distinguishedName=*)",
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


/* =Search-Entry========================================================== */

int sysdb_search_entry(TALLOC_CTX *mem_ctx,
                       struct sysdb_ctx *sysdb,
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

    ret = ldb_search(sysdb->ldb, tmp_ctx, &res,
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

int sysdb_search_user_by_name(TALLOC_CTX *mem_ctx,
                              struct sss_domain_info *domain,
                              const char *name,
                              const char **attrs,
                              struct ldb_message **msg)
{
    TALLOC_CTX *tmp_ctx;
    const char *def_attrs[] = { SYSDB_NAME, SYSDB_UIDNUM, NULL };
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

    basedn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                            SYSDB_TMPL_USER_BASE, domain->name);
    if (!basedn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_filter_sanitize_for_dom(tmp_ctx, name, domain, &sanitized_name,
                                      &lc_sanitized_name);
    if (ret != EOK) {
        goto done;
    }

    filter = talloc_asprintf(tmp_ctx, SYSDB_PWNAM_FILTER, lc_sanitized_name,
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

    basedn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                            SYSDB_TMPL_USER_BASE, domain->name);
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

int sysdb_search_user_by_upn(TALLOC_CTX *mem_ctx,
                             struct sss_domain_info *domain,
                             const char *upn,
                             const char **attrs,
                             struct ldb_message **msg)
{
    TALLOC_CTX *tmp_ctx;
    const char *def_attrs[] = { SYSDB_NAME, SYSDB_UPN, SYSDB_CANONICAL_UPN,
                                NULL };
    struct ldb_message **msgs = NULL;
    struct ldb_dn *basedn;
    size_t msgs_count = 0;
    char *filter;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    basedn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                            SYSDB_TMPL_USER_BASE, domain->name);
    if (basedn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    filter = talloc_asprintf(tmp_ctx, SYSDB_PWUPN_FILTER, upn, upn);
    if (filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_entry(tmp_ctx, domain->sysdb, basedn, LDB_SCOPE_SUBTREE,
                             filter, attrs?attrs:def_attrs, &msgs_count,
                             &msgs);
    if (ret != EOK) {
        goto done;
    }

    if (msgs_count > 1) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Search for upn [%s] returns more than one result.\n", upn);
        ret = EINVAL;
        goto done;
    }

    *msg = talloc_steal(mem_ctx, msgs[0]);

done:
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, "No entry with upn [%s] found.\n", upn);
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
    }

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
    TALLOC_CTX *tmp_ctx;
    static const char *def_attrs[] = { SYSDB_NAME, SYSDB_GIDNUM, NULL };
    struct ldb_message **msgs = NULL;
    struct ldb_dn *basedn;
    size_t msgs_count = 0;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    basedn = sysdb_group_dn(tmp_ctx, domain, name);
    if (!basedn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_entry(tmp_ctx, domain->sysdb, basedn, LDB_SCOPE_BASE,
                             NULL, attrs?attrs:def_attrs, &msgs_count, &msgs);
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

int sysdb_search_group_by_gid(TALLOC_CTX *mem_ctx,
                              struct sss_domain_info *domain,
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

    basedn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                            SYSDB_TMPL_GROUP_BASE, domain->name);
    if (!basedn) {
        ret = ENOMEM;
        goto done;
    }

    filter = talloc_asprintf(tmp_ctx, SYSDB_GRGID_FILTER, (unsigned long)gid);
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

/* =Replace-Attributes-On-Entry=========================================== */

int sysdb_set_entry_attr(struct sysdb_ctx *sysdb,
                         struct ldb_dn *entry_dn,
                         struct sysdb_attrs *attrs,
                         int mod_op)
{
    struct ldb_message *msg;
    int i, ret;
    int lret;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    if (!entry_dn || attrs->num == 0) {
        ret = EINVAL;
        goto done;
    }

    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = entry_dn;

    msg->elements = talloc_array(msg, struct ldb_message_element, attrs->num);
    if (!msg->elements) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < attrs->num; i++) {
        msg->elements[i] = attrs->a[i];
        msg->elements[i].flags = mod_op;
    }

    msg->num_elements = attrs->num;

    lret = ldb_modify(sysdb->ldb, msg);
    if (lret != LDB_SUCCESS) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "ldb_modify failed: [%s]\n", ldb_strerror(lret));
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

/* =Get-New-ID============================================================ */

int sysdb_get_new_id(struct sss_domain_info *domain,
                     uint32_t *_id)
{
    TALLOC_CTX *tmp_ctx;
    const char *attrs_1[] = { SYSDB_NEXTID, NULL };
    const char *attrs_2[] = { SYSDB_UIDNUM, SYSDB_GIDNUM, NULL };
    struct ldb_dn *base_dn;
    char *filter;
    uint32_t new_id = 0;
    struct ldb_message **msgs;
    size_t count;
    struct ldb_message *msg;
    uint32_t id;
    int ret;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    base_dn = sysdb_domain_dn(tmp_ctx, domain);
    if (!base_dn) {
        talloc_zfree(tmp_ctx);
        return ENOMEM;
    }

    ret = ldb_transaction_start(domain->sysdb->ldb);
    if (ret) {
        talloc_zfree(tmp_ctx);
        ret = sysdb_error_to_errno(ret);
        return ret;
    }

    ret = sysdb_search_entry(tmp_ctx, domain->sysdb, base_dn, LDB_SCOPE_BASE,
                             SYSDB_NEXTID_FILTER, attrs_1, &count, &msgs);
    switch (ret) {
    case EOK:
        new_id = get_attr_as_uint32(msgs[0], SYSDB_NEXTID);
        if (new_id == (uint32_t)(-1)) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Invalid Next ID in domain %s\n", domain->name);
            ret = ERANGE;
            goto done;
        }

        if (new_id < domain->id_min) {
            new_id = domain->id_min;
        }

        if ((domain->id_max != 0) && (new_id > domain->id_max)) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Failed to allocate new id, out of range (%u/%u)\n",
                      new_id, domain->id_max);
            ret = ERANGE;
            goto done;
        }
        break;

    case ENOENT:
        /* looks like the domain is not initialized yet, use min_id */
        new_id = domain->id_min;
        break;

    default:
        goto done;
    }
    talloc_zfree(msgs);
    count = 0;

    /* verify the id is actually really free.
     * search all entries with id >= new_id and < max_id */
    if (domain->id_max) {
        filter = talloc_asprintf(tmp_ctx,
                                 "(|(&(%s>=%u)(%s<=%u))(&(%s>=%u)(%s<=%u)))",
                                 SYSDB_UIDNUM, new_id,
                                 SYSDB_UIDNUM, domain->id_max,
                                 SYSDB_GIDNUM, new_id,
                                 SYSDB_GIDNUM, domain->id_max);
    }
    else {
        filter = talloc_asprintf(tmp_ctx,
                                 "(|(%s>=%u)(%s>=%u))",
                                 SYSDB_UIDNUM, new_id,
                                 SYSDB_GIDNUM, new_id);
    }
    if (!filter) {
        DEBUG(SSSDBG_TRACE_FUNC, "Error: Out of memory\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_entry(tmp_ctx, domain->sysdb, base_dn, LDB_SCOPE_SUBTREE,
                             filter, attrs_2, &count, &msgs);
    switch (ret) {
    /* if anything was found, find the maximum and increment past it */
    case EOK:
        for (i = 0; i < count; i++) {
            id = get_attr_as_uint32(msgs[i], SYSDB_UIDNUM);
            if (id != (uint32_t)(-1)) {
                if (id > new_id) new_id = id;
            }
            id = get_attr_as_uint32(msgs[i], SYSDB_GIDNUM);
            if (id != (uint32_t)(-1)) {
                if (id > new_id) new_id = id;
            }
        }

        new_id++;

        /* check again we are not falling out of range */
        if ((domain->id_max != 0) && (new_id > domain->id_max)) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Failed to allocate new id, out of range (%u/%u)\n",
                      new_id, domain->id_max);
            ret = ERANGE;
            goto done;
        }
        break;

    case ENOENT:
        break;

    default:
        goto done;
    }

    talloc_zfree(msgs);
    count = 0;

    /* finally store the new next id */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        DEBUG(SSSDBG_TRACE_FUNC, "Error: Out of memory\n");
        ret = ENOMEM;
        goto done;
    }
    msg->dn = base_dn;

    ret = add_ulong(msg, LDB_FLAG_MOD_REPLACE,
                    SYSDB_NEXTID, new_id + 1);
    if (ret) {
        goto done;
    }

    ret = ldb_modify(domain->sysdb->ldb, msg);
    ret = sysdb_error_to_errno(ret);

    *_id = new_id;

done:
    if (ret == EOK) {
        ret = ldb_transaction_commit(domain->sysdb->ldb);
        ret = sysdb_error_to_errno(ret);
    } else {
        ldb_transaction_cancel(domain->sysdb->ldb);
    }
    if (ret) {
        DEBUG(SSSDBG_TRACE_FUNC, "Error: %d (%s)\n", ret, strerror(ret));
    }
    talloc_zfree(tmp_ctx);
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

    ret = add_string(msg, LDB_FLAG_MOD_ADD, SYSDB_OBJECTCLASS, SYSDB_USER_CLASS);
    if (ret) goto done;

    ret = add_string(msg, LDB_FLAG_MOD_ADD, SYSDB_NAME, name);
    if (ret) goto done;

    ret = add_ulong(msg, LDB_FLAG_MOD_ADD, SYSDB_UIDNUM, (unsigned long)uid);
    if (ret) goto done;

    ret = add_ulong(msg, LDB_FLAG_MOD_ADD, SYSDB_GIDNUM, (unsigned long)gid);
    if (ret) goto done;

    /* We set gecos to be the same as fullname on user creation,
     * But we will not enforce coherency after that, it's up to
     * admins to decide if they want to keep it in sync if they change
     * one of the 2 */
    if (gecos && *gecos) {
        ret = add_string(msg, LDB_FLAG_MOD_ADD, SYSDB_FULLNAME, gecos);
        if (ret) goto done;
        ret = add_string(msg, LDB_FLAG_MOD_ADD, SYSDB_GECOS, gecos);
        if (ret) goto done;
    }

    if (homedir && *homedir) {
        ret = add_string(msg, LDB_FLAG_MOD_ADD, SYSDB_HOMEDIR, homedir);
        if (ret) goto done;
    }

    if (shell && *shell) {
        ret = add_string(msg, LDB_FLAG_MOD_ADD, SYSDB_SHELL, shell);
        if (ret) goto done;
    }

    /* creation time */
    ret = add_ulong(msg, LDB_FLAG_MOD_ADD, SYSDB_CREATE_TIME,
                    (unsigned long)time(NULL));
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
        ret = add_string(msg, LDB_FLAG_MOD_ADD, SYSDB_MEMBER, userdn);
        if (ret) goto done;
    }

    ret = add_string(msg, LDB_FLAG_MOD_DELETE, SYSDB_GHOST, name);
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

    tmpdn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                            SYSDB_TMPL_GROUP_BASE, domain->name);
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
    struct sysdb_attrs *id_attrs;
    uint32_t id;
    int ret;

    if (domain->mpg) {
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

    if (domain->mpg) {
        /* In MPG domains you can't have groups with the same name as users,
         * search if a group with the same name exists.
         * Don't worry about users, if we try to add a user with the same
         * name the operation will fail */

        ret = sysdb_search_group_by_name(tmp_ctx, domain, name, NULL, &msg);
        if (ret != ENOENT) {
            if (ret == EOK) ret = EEXIST;
            goto done;
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

    if (uid == 0) {
        ret = sysdb_get_new_id(domain, &id);
        if (ret) goto done;

        id_attrs = sysdb_new_attrs(tmp_ctx);
        if (!id_attrs) {
            ret = ENOMEM;
            goto done;
        }
        ret = sysdb_attrs_add_uint32(id_attrs, SYSDB_UIDNUM, id);
        if (ret) goto done;

        if (domain->mpg) {
            ret = sysdb_attrs_add_uint32(id_attrs, SYSDB_GIDNUM, id);
            if (ret) goto done;
        }

        ret = sysdb_set_user_attr(domain, name, id_attrs, SYSDB_MOD_REP);
        goto done;
    }

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
                          const char *name, gid_t gid)
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

    /* group dn */
    msg->dn = sysdb_group_dn(msg, domain, name);
    if (!msg->dn) {
        ERROR_OUT(ret, ENOMEM, done);
    }

    ret = add_string(msg, LDB_FLAG_MOD_ADD, SYSDB_OBJECTCLASS, SYSDB_GROUP_CLASS);
    if (ret) goto done;

    ret = add_string(msg, LDB_FLAG_MOD_ADD, SYSDB_NAME, name);
    if (ret) goto done;

    ret = add_ulong(msg, LDB_FLAG_MOD_ADD, SYSDB_GIDNUM, (unsigned long)gid);
    if (ret) goto done;

    /* creation time */
    ret = add_ulong(msg, LDB_FLAG_MOD_ADD, SYSDB_CREATE_TIME,
                    (unsigned long)time(NULL));
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
    uint32_t id;
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

    if (domain->mpg) {
        /* In MPG domains you can't have groups with the same name as users,
         * search if a group with the same name exists.
         * Don't worry about users, if we try to add a user with the same
         * name the operation will fail */

        ret = sysdb_search_user_by_name(tmp_ctx, domain, name, NULL, &msg);
        if (ret != ENOENT) {
            if (ret == EOK) ret = EEXIST;
            goto done;
        }
    }

    /* check no other groups with the same gid exist */
    if (gid != 0) {
        ret = sysdb_search_group_by_gid(tmp_ctx, domain, gid, NULL, &msg);
        if (ret != ENOENT) {
            if (ret == EOK) ret = EEXIST;
            goto done;
        }
    }

    /* try to add the group */
    ret = sysdb_add_basic_group(domain, name, gid);
    if (ret) goto done;

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
        ret = sysdb_attrs_add_bool(attrs, SYSDB_POSIX, true);
        if (ret) goto done;
    } else if (ret != EOK) {
        goto done;
    }

    if (posix && gid == 0) {
        ret = sysdb_get_new_id(domain, &id);
        if (ret) goto done;

        ret = sysdb_attrs_add_uint32(attrs, SYSDB_GIDNUM, id);
        if (ret) goto done;
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

    ret = sysdb_set_group_attr(domain, name, attrs, SYSDB_MOD_REP);

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
                               bool posix,
                               time_t now)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct sysdb_attrs *attrs;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    /* try to add the group */
    ret = sysdb_add_basic_group(domain, name, gid);
    if (ret) goto done;

    attrs = sysdb_new_attrs(tmp_ctx);
    if (!attrs) {
        ret = ENOMEM;
        goto done;
    }

    if (!now) {
        now = time(NULL);
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_LAST_UPDATE, now);
    if (ret) goto done;

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_CACHE_EXPIRE,
                                 now-1);
    if (ret) goto done;

    ret = sysdb_attrs_add_bool(attrs, SYSDB_POSIX, posix);
    if (ret) goto done;

    if (original_dn) {
        ret = sysdb_attrs_add_string(attrs, SYSDB_ORIG_DN, original_dn);
        if (ret) goto done;
    }

    if (sid_str) {
        ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, sid_str);
        if (ret) goto done;
    }

    ret = sysdb_set_group_attr(domain, name, attrs, SYSDB_MOD_REP);

done:
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_FUNC, "Error: %d (%s)\n", ret, strerror(ret));
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

    ret = add_string(msg, LDB_FLAG_MOD_ADD,
                     SYSDB_OBJECTCLASS, SYSDB_NETGROUP_CLASS);
    if (ret) goto done;

    ret = add_string(msg, LDB_FLAG_MOD_ADD, SYSDB_NAME, name);
    if (ret) goto done;

    if (description && *description) {
        ret = add_string(msg, LDB_FLAG_MOD_ADD,
                         SYSDB_DESCRIPTION, description);
        if (ret) goto done;
    }

    /* creation time */
    ret = add_ulong(msg, LDB_FLAG_MOD_ADD, SYSDB_CREATE_TIME,
                    (unsigned long) time(NULL));
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

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    if (!attrs) {
        attrs = sysdb_new_attrs(tmp_ctx);
        if (!attrs) {
            ret = ENOMEM;
            goto fail;
        }
    }

    if (pwd && (domain->legacy_passwords || !*pwd)) {
        ret = sysdb_attrs_add_string(attrs, SYSDB_PWD, pwd);
        if (ret) goto fail;
    }

    ret = sysdb_transaction_start(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto fail;
    }

    in_transaction = true;

    ret = sysdb_search_user_by_name(tmp_ctx, domain, name, NULL, &msg);
    if (ret && ret != ENOENT) {
        goto fail;
    }

    /* get transaction timestamp */
    if (!now) {
        now = time(NULL);
    }

    if (ret == ENOENT) {
        /* users doesn't exist, turn into adding a user */
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
                ret = EEXIST;
                goto fail;
            } else if (ret != EOK) {
                goto fail;
            }
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "A user with the same UID [%llu] was removed from the "
                   "cache\n", (unsigned long long) uid);
            ret = sysdb_add_user(domain, name, uid, gid, gecos, homedir,
                                 shell, orig_dn, attrs, cache_timeout, now);
        }

        /* Handle the result of sysdb_add_user */
        if (ret == EOK) {
            goto done;
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "Could not add user\n");
            goto fail;
        }
    }

    /* the user exists, let's just replace attributes when set */
    if (uid) {
        ret = sysdb_attrs_add_uint32(attrs, SYSDB_UIDNUM, uid);
        if (ret) goto fail;
    }

    if (gid) {
        ret = sysdb_attrs_add_uint32(attrs, SYSDB_GIDNUM, gid);
        if (ret) goto fail;
    }

    if (uid && !gid && domain->mpg) {
        ret = sysdb_attrs_add_uint32(attrs, SYSDB_GIDNUM, uid);
        if (ret) goto fail;
    }

    if (gecos) {
        ret = sysdb_attrs_add_string(attrs, SYSDB_GECOS, gecos);
        if (ret) goto fail;
    }

    if (homedir) {
        ret = sysdb_attrs_add_string(attrs, SYSDB_HOMEDIR, homedir);
        if (ret) goto fail;
    }

    if (shell) {
        ret = sysdb_attrs_add_string(attrs, SYSDB_SHELL, shell);
        if (ret) goto fail;
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_LAST_UPDATE, now);
    if (ret) goto fail;

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_CACHE_EXPIRE,
                                 ((cache_timeout) ?
                                  (now + cache_timeout) : 0));
    if (ret) goto fail;

    ret = sysdb_set_user_attr(domain, name, attrs, SYSDB_MOD_REP);
    if (ret != EOK) goto fail;

    if (remove_attrs) {
        ret = sysdb_remove_attrs(domain, name,
                                 SYSDB_MEMBER_USER,
                                 remove_attrs);
        if (ret != EOK) {
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "Could not remove missing attributes\n");
        }
    }

done:
    ret = sysdb_transaction_commit(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction\n");
        goto fail;
    }

    in_transaction = false;

fail:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(domain->sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not cancel transaction\n");
        }
    }

    if (ret) {
        DEBUG(SSSDBG_TRACE_FUNC, "Error: %d (%s)\n", ret, strerror(ret));
    }
    talloc_zfree(tmp_ctx);
    return ret;
}

/* =Store-Group-(Native/Legacy)-(replaces-existing-data)================== */

/* this function does not check that all user members are actually present */

int sysdb_store_group(struct sss_domain_info *domain,
                      const char *name,
                      gid_t gid,
                      struct sysdb_attrs *attrs,
                      uint64_t cache_timeout,
                      time_t now)
{
    TALLOC_CTX *tmp_ctx;
    static const char *src_attrs[] = { SYSDB_NAME, SYSDB_GIDNUM,
                                       SYSDB_ORIG_MODSTAMP, NULL };
    struct ldb_message *msg;
    bool new_group = false;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = sysdb_search_group_by_name(tmp_ctx, domain, name, src_attrs, &msg);
    if (ret && ret != ENOENT) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "sysdb_search_group_by_name failed for %s with: [%d][%s].\n",
              name, ret, strerror(ret));
        goto done;
    }
    if (ret == ENOENT) {
        new_group = true;
    }

    if (!attrs) {
        attrs = sysdb_new_attrs(tmp_ctx);
        if (!attrs) {
            ret = ENOMEM;
            goto done;
        }
    }

    /* get transaction timestamp */
    if (!now) {
        now = time(NULL);
    }

    /* FIXME: use the remote modification timestamp to know if the
     * group needs any update */

    if (new_group) {
        /* group doesn't exist, turn into adding a group */
        ret = sysdb_add_group(domain, name, gid, attrs, cache_timeout,
                              now);
        if (ret == EEXIST) {
            /* This may be a group rename. If there is a group with the
             * same GID, remove it and try to add the basic group again
             */
            ret = sysdb_delete_group(domain, NULL, gid);
            if (ret == ENOENT) {
                /* Not found by GID, return the original EEXIST,
                 * this may be a conflict in MPG domain or something
                 * else */
                return EEXIST;
            } else if (ret != EOK) {
                goto done;
            }
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "A group with the same GID [%llu] was removed from the "
                   "cache\n", (unsigned long long) gid);
            ret = sysdb_add_group(domain, name, gid, attrs, cache_timeout,
                                  now);
        }
        goto done;
    }

    /* the group exists, let's just replace attributes when set */
    if (gid) {
        ret = sysdb_attrs_add_uint32(attrs, SYSDB_GIDNUM, gid);
        if (ret) goto done;
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_LAST_UPDATE, now);
    if (ret) goto done;

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_CACHE_EXPIRE,
                                 ((cache_timeout) ?
                                  (now + cache_timeout) : 0));
    if (ret) goto done;

    ret = sysdb_set_group_attr(domain, name, attrs, SYSDB_MOD_REP);

done:
    if (ret) {
        DEBUG(SSSDBG_TRACE_FUNC, "Error: %d (%s)\n", ret, strerror(ret));
    }
    talloc_zfree(tmp_ctx);
    return ret;
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
    int ret;
    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    if (type == SYSDB_MEMBER_USER) {
        member_dn = sysdb_user_dn(tmp_ctx, domain, member);
    } else if (type == SYSDB_MEMBER_GROUP) {
        member_dn = sysdb_group_dn(tmp_ctx, domain, member);
    } else {
        ret = EINVAL;
        goto done;
    }

    if (!member_dn) {
        ret = ENOMEM;
        goto done;
    }

    if (!is_dn) {
        group_dn = sysdb_group_dn(tmp_ctx, domain, group);
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

int sysdb_cache_password(struct sss_domain_info *domain,
                         const char *username,
                         const char *password)
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

    /* FIXME: should we use a different attribute for chache passwords ?? */
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
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to create DN.\n");
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
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to create DN.\n");
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
        DEBUG(SSSDBG_CRIT_FAILURE, "LDB Error: %s(%d)\nError Message: [%s]\n",
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

int sysdb_search_users(TALLOC_CTX *mem_ctx,
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
                            SYSDB_TMPL_USER_BASE, domain->name);
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
        DEBUG(SSSDBG_TRACE_INTERNAL, "No such entry\n");
    }
    else if (ret) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
    }
    talloc_zfree(tmp_ctx);
    return ret;
}

/* =Delete-User-by-Name-OR-uid============================================ */

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

        ret = sysdb_delete_entry(domain->sysdb, msg->dn, false);
        if (ret) {
            goto fail;
        }
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

            ret = add_string(msg, LDB_FLAG_MOD_DELETE, SYSDB_GHOST, name);
            if (ret) goto fail;

            ret = ldb_modify(domain->sysdb->ldb, msg);
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
    DEBUG(SSSDBG_TRACE_FUNC, "Error: %d (%s)\n", ret, strerror(ret));
    talloc_zfree(tmp_ctx);
    return ret;
}


/* =Search-Groups-with-Custom-Filter===================================== */

int sysdb_search_groups(TALLOC_CTX *mem_ctx,
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
                            SYSDB_TMPL_GROUP_BASE, domain->name);
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
        DEBUG(SSSDBG_TRACE_INTERNAL, "No such entry\n");
    }
    else if (ret) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
    }
    talloc_zfree(tmp_ctx);
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
    if (ret != EOK) {
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

    if (res->count == 0) {
        /* No existing entry. Just quit. */
        ret = EOK;
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
                            SYSDB_LAST_FAILED_LOGIN, NULL };
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

    if (strcmp(userhash, comphash) == 0) {
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
            DEBUG(SSSDBG_MINOR_FAILURE, "sysdb_attrs_add_time_t failed\n.");
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
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Could not add member [%s] to group [%s]. "
                          "Skipping.\n", member, add_groups[i]);
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
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Could not remove member [%s] from group [%s]. "
                          "Skipping\n", member, del_groups[i]);
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

errno_t sysdb_search_object_by_sid(TALLOC_CTX *mem_ctx,
                                   struct sss_domain_info *domain,
                                   const char *sid_str,
                                   const char **attrs,
                                   struct ldb_result **msg)
{
    TALLOC_CTX *tmp_ctx;
    const char *def_attrs[] = { SYSDB_NAME, SYSDB_UIDNUM, SYSDB_GIDNUM,
                                SYSDB_OBJECTCLASS, NULL };
    struct ldb_dn *basedn;
    int ret;
    struct ldb_result *res = NULL;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    basedn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb, SYSDB_DOM_BASE, domain->name);
    if (basedn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new_fmt failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_search(domain->sysdb->ldb, tmp_ctx, &res,
                     basedn, LDB_SCOPE_SUBTREE, attrs?attrs:def_attrs,
                     SYSDB_SID_FILTER, sid_str);
    if (ret != EOK) {
        ret = sysdb_error_to_errno(ret);
        DEBUG(SSSDBG_OP_FAILURE, "ldb_search failed.\n");
        goto done;
    }

    if (res->count > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Search for SID [%s] returned more than " \
                                    "one object.\n", sid_str);
        ret = EINVAL;
        goto done;
    }

    *msg = talloc_steal(mem_ctx, res);

done:
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, "No such entry.\n");
    } else if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
    }

    talloc_zfree(tmp_ctx);
    return ret;
}
