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
#include "confdb/confdb.h"
#include <time.h>
#include <ctype.h>

/* users */

int sysdb_getpwnam(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *sysdb,
                   const char *name,
                   struct ldb_result **_res)
{
    TALLOC_CTX *tmp_ctx;
    static const char *attrs[] = SYSDB_PW_ATTRS;
    struct ldb_dn *base_dn;
    struct ldb_result *res;
    char *sanitized_name;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    base_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                             SYSDB_TMPL_USER_BASE, sysdb->domain->name);
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_filter_sanitize(tmp_ctx, name, &sanitized_name);
    if (ret != EOK) {
        goto done;
    }

    ret = ldb_search(sysdb->ldb, tmp_ctx, &res, base_dn,
                     LDB_SCOPE_SUBTREE, attrs, SYSDB_PWNAM_FILTER,
                     sanitized_name, sanitized_name);
    if (ret) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    *_res = talloc_steal(mem_ctx, res);

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

int sysdb_getpwuid(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *sysdb,
                   uid_t uid,
                   struct ldb_result **_res)
{
    TALLOC_CTX *tmp_ctx;
    unsigned long int ul_uid = uid;
    static const char *attrs[] = SYSDB_PW_ATTRS;
    struct ldb_dn *base_dn;
    struct ldb_result *res;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    base_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                             SYSDB_TMPL_USER_BASE, sysdb->domain->name);
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_search(sysdb->ldb, tmp_ctx, &res, base_dn,
                     LDB_SCOPE_SUBTREE, attrs, SYSDB_PWUID_FILTER, ul_uid);
    if (ret) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    *_res = talloc_steal(mem_ctx, res);

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

int sysdb_enumpwent(TALLOC_CTX *mem_ctx,
                    struct sysdb_ctx *sysdb,
                    struct ldb_result **_res)
{
    TALLOC_CTX *tmp_ctx;
    static const char *attrs[] = SYSDB_PW_ATTRS;
    struct ldb_dn *base_dn;
    struct ldb_result *res;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    base_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                             SYSDB_TMPL_USER_BASE, sysdb->domain->name);
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_search(sysdb->ldb, tmp_ctx, &res, base_dn,
                     LDB_SCOPE_SUBTREE, attrs, SYSDB_PWENT_FILTER);
    if (ret) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    *_res = talloc_steal(mem_ctx, res);

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

/* groups */

static int mpg_convert(struct ldb_message *msg)
{
    struct ldb_message_element *el;
    struct ldb_val *val;
    int i;

    el = ldb_msg_find_element(msg, "objectClass");
    if (!el) return EINVAL;

    /* see if this is a user to convert to a group */
    for (i = 0; i < el->num_values; i++) {
        val = &(el->values[i]);
        if (strncasecmp(SYSDB_USER_CLASS,
                        (char *)val->data, val->length) == 0) {
            break;
        }
    }
    /* no, leave as is */
    if (i == el->num_values) return EOK;

    /* yes, convert */
    val->data = (uint8_t *)talloc_strdup(msg, SYSDB_GROUP_CLASS);
    if (val->data == NULL) return ENOMEM;
    val->length = strlen(SYSDB_GROUP_CLASS);

    return EOK;
}

static int mpg_res_convert(struct ldb_result *res)
{
    int ret;
    int i;

    for (i = 0; i < res->count; i++) {
        ret = mpg_convert(res->msgs[i]);
        if (ret) {
            return ret;
        }
    }
    return EOK;
}

int sysdb_getgrnam(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *sysdb,
                   const char *name,
                   struct ldb_result **_res)
{
    TALLOC_CTX *tmp_ctx;
    static const char *attrs[] = SYSDB_GRSRC_ATTRS;
    const char *fmt_filter;
    char *sanitized_name;
    struct ldb_dn *base_dn;
    struct ldb_result *res;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    if (sysdb->mpg) {
        fmt_filter = SYSDB_GRNAM_MPG_FILTER;
        base_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                                 SYSDB_DOM_BASE, sysdb->domain->name);
    } else {
        fmt_filter = SYSDB_GRNAM_FILTER;
        base_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                                 SYSDB_TMPL_GROUP_BASE, sysdb->domain->name);
    }
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_filter_sanitize(tmp_ctx, name, &sanitized_name);
    if (ret != EOK) {
        goto done;
    }

    ret = ldb_search(sysdb->ldb, tmp_ctx, &res, base_dn,
                     LDB_SCOPE_SUBTREE, attrs, fmt_filter,
                     sanitized_name, sanitized_name);
    if (ret) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = mpg_res_convert(res);
    if (ret) {
        goto done;
    }

    *_res = talloc_steal(mem_ctx, res);

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

int sysdb_getgrgid(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *sysdb,
                   gid_t gid,
                   struct ldb_result **_res)
{
    TALLOC_CTX *tmp_ctx;
    unsigned long int ul_gid = gid;
    static const char *attrs[] = SYSDB_GRSRC_ATTRS;
    const char *fmt_filter;
    struct ldb_dn *base_dn;
    struct ldb_result *res;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    if (sysdb->mpg) {
        fmt_filter = SYSDB_GRGID_MPG_FILTER;
        base_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                                 SYSDB_DOM_BASE, sysdb->domain->name);
    } else {
        fmt_filter = SYSDB_GRGID_FILTER;
        base_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                                 SYSDB_TMPL_GROUP_BASE, sysdb->domain->name);
    }
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_search(sysdb->ldb, tmp_ctx, &res, base_dn,
                     LDB_SCOPE_SUBTREE, attrs, fmt_filter, ul_gid);
    if (ret) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = mpg_res_convert(res);
    if (ret) {
        goto done;
    }

    *_res = talloc_steal(mem_ctx, res);

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

int sysdb_enumgrent(TALLOC_CTX *mem_ctx,
                    struct sysdb_ctx *sysdb,
                    struct ldb_result **_res)
{
    TALLOC_CTX *tmp_ctx;
    static const char *attrs[] = SYSDB_GRSRC_ATTRS;
    const char *fmt_filter;
    struct ldb_dn *base_dn;
    struct ldb_result *res;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    if (sysdb->mpg) {
        fmt_filter = SYSDB_GRENT_MPG_FILTER;
        base_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                                 SYSDB_DOM_BASE, sysdb->domain->name);
    } else {
        fmt_filter = SYSDB_GRENT_FILTER;
        base_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                                 SYSDB_TMPL_GROUP_BASE, sysdb->domain->name);
    }
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_search(sysdb->ldb, tmp_ctx, &res, base_dn,
                     LDB_SCOPE_SUBTREE, attrs, "%s", fmt_filter);
    if (ret) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = mpg_res_convert(res);
    if (ret) {
        goto done;
    }

    *_res = talloc_steal(mem_ctx, res);

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

int sysdb_initgroups(TALLOC_CTX *mem_ctx,
                     struct sysdb_ctx *sysdb,
                     const char *name,
                     struct ldb_result **_res)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    struct ldb_dn *user_dn;
    struct ldb_request *req;
    struct ldb_control **ctrl;
    struct ldb_asq_control *control;
    static const char *attrs[] = SYSDB_INITGR_ATTRS;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = sysdb_getpwnam(tmp_ctx, sysdb, name, &res);
    if (ret != EOK) {
        DEBUG(1, ("sysdb_getpwnam failed: [%d][%s]\n",
                  ret, strerror(ret)));
        goto done;
    }

    if (res->count == 0) {
        /* User is not cached yet */
        *_res = talloc_steal(mem_ctx, res);
        ret = EOK;
        goto done;

    } else if (res->count != 1) {
        ret = EIO;
        DEBUG(1, ("sysdb_getpwnam returned count: [%d]\n", res->count));
        goto done;
    }

    /* no need to steal the dn, we are not freeing the result */
    user_dn = res->msgs[0]->dn;

    /* note we count on the fact that the default search callback
     * will just keep appending values. This is by design and can't
     * change so it is ok to already have a result (from the getpwnam)
     * even before we call the next search */

    ctrl = talloc_array(tmp_ctx, struct ldb_control *, 2);
    if (!ctrl) {
        ret = ENOMEM;
        goto done;
    }
    ctrl[1] = NULL;
    ctrl[0] = talloc(ctrl, struct ldb_control);
    if (!ctrl[0]) {
        ret = ENOMEM;
        goto done;
    }
    ctrl[0]->oid = LDB_CONTROL_ASQ_OID;
    ctrl[0]->critical = 1;
    control = talloc(ctrl[0], struct ldb_asq_control);
    if (!control) {
        ret = ENOMEM;
        goto done;
    }
    control->request = 1;
    control->source_attribute = talloc_strdup(control, SYSDB_INITGR_ATTR);
    if (!control->source_attribute) {
        ret = ENOMEM;
        goto done;
    }
    control->src_attr_len = strlen(control->source_attribute);
    ctrl[0]->data = control;

    ret = ldb_build_search_req(&req, sysdb->ldb, tmp_ctx,
                               user_dn, LDB_SCOPE_BASE,
                               SYSDB_INITGR_FILTER, attrs, ctrl,
                               res, ldb_search_default_callback,
                               NULL);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = ldb_request(sysdb->ldb, req);
    if (ret == LDB_SUCCESS) {
        ret = ldb_wait(req->handle, LDB_WAIT_ALL);
    }
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    *_res = talloc_steal(mem_ctx, res);

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

int sysdb_get_user_attr(TALLOC_CTX *mem_ctx,
                        struct sysdb_ctx *sysdb,
                        const char *name,
                        const char **attributes,
                        struct ldb_result **_res)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *base_dn;
    struct ldb_result *res;
    char *sanitized_name;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    base_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                             SYSDB_TMPL_USER_BASE, sysdb->domain->name);
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_filter_sanitize(tmp_ctx, name, &sanitized_name);
    if (ret != EOK) {
        goto done;
    }

    ret = ldb_search(sysdb->ldb, tmp_ctx, &res, base_dn,
                     LDB_SCOPE_SUBTREE, attributes,
                     SYSDB_PWNAM_FILTER, sanitized_name,
                     sanitized_name);
    if (ret) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    *_res = talloc_steal(mem_ctx, res);

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

/* This function splits a three-tuple into three strings
 * It assumes that any whitespace between the parentheses
 * and commas are intentional and does not attempt to
 * strip them out. Leading and trailing whitespace is
 * ignored.
 *
 * This behavior is compatible with nss_ldap's
 * implementation.
 */
static errno_t sysdb_netgr_split_triple(TALLOC_CTX *mem_ctx,
                                        const char *triple,
                                        char **hostname,
                                        char **username,
                                        char **domainname)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    const char *p = triple;
    const char *p_host;
    const char *p_user;
    const char *p_domain;
    size_t len;

    char *host = NULL;
    char *user = NULL;
    char *domain = NULL;

    /* Pre-set the values to NULL here so if they are not
     * copied, we don't return garbage below.
     */
    *hostname = NULL;
    *username = NULL;
    *domainname = NULL;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    /* Remove any leading whitespace */
    while (*p && isspace(*p)) p++;

    if (*p != '(') {
        /* Triple must start and end with parentheses */
        ret = EINVAL;
        goto done;
    }
    p++;
    p_host = p;

    /* Find the first comma */
    while (*p && *p != ',') p++;

    if (!*p) {
        /* No comma was found: parse error */
        ret = EINVAL;
        goto done;
    }

    len = p - p_host;

    if (len > 0) {
        /* Copy the host string */
        host = talloc_strndup(tmp_ctx, p_host, len);
        if (!host) {
            ret = ENOMEM;
            goto done;
        }
    }
    p++;
    p_user = p;

    /* Find the second comma */
    while (*p && *p != ',') p++;

    if (!*p) {
        /* No comma was found: parse error */
        ret = EINVAL;
        goto done;
    }

    len = p - p_user;

    if (len > 0) {
        /* Copy the user string */
        user = talloc_strndup(tmp_ctx, p_user, len);
        if (!user) {
            ret = ENOMEM;
            goto done;
        }
    }
    p++;
    p_domain = p;

    /* Find the closing parenthesis */
    while (*p && *p != ')') p++;
    if (*p != ')') {
        /* No trailing parenthesis: parse error */
        ret = EINVAL;
        goto done;
    }

    len = p - p_domain;

    if (len > 0) {
        /* Copy the domain string */
        domain = talloc_strndup(tmp_ctx, p_domain, len);
        if (!domain) {
            ret = ENOMEM;
            goto done;
        }
    }
    p++;

    /* skip trailing whitespace */
    while (*p && isspace(*p)) p++;

    if (*p) {
        /* Extra data after the closing parenthesis
         * is a parse error
         */
        ret = EINVAL;
        goto done;
    }

    /* Return any non-NULL values */
    if (host) {
        *hostname = talloc_steal(mem_ctx, host);
    }

    if (user) {
        *username = talloc_steal(mem_ctx, user);
    }

    if (domain) {
        *domainname = talloc_steal(mem_ctx, domain);
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_netgr_to_entries(TALLOC_CTX *mem_ctx,
                               struct ldb_result *res,
                               struct sysdb_netgroup_ctx ***entries)
{
    errno_t ret;
    size_t size = 0;
    size_t c = 0;
    char *triple_str;
    TALLOC_CTX *tmp_ctx;
    struct sysdb_netgroup_ctx **tmp_entry = NULL;
    struct ldb_message_element *el;
    int i, j;

    if(!res || res->count == 0) {
        return ENOENT;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    for (i=0; i < res->count; i++) {
        el = ldb_msg_find_element(res->msgs[i], SYSDB_NETGROUP_TRIPLE);
        if (el != NULL) {
            size += el->num_values;
        }
        el = ldb_msg_find_element(res->msgs[i], SYSDB_NETGROUP_MEMBER);
        if (el != NULL) {
            size += el->num_values;
        }
    }

    tmp_entry = talloc_array(tmp_ctx, struct sysdb_netgroup_ctx *, size + 1);
    if (tmp_entry == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (size != 0) {
        for (i=0; i < res->count; i++) {
            el = ldb_msg_find_element(res->msgs[i], SYSDB_NETGROUP_TRIPLE);
            if (el != NULL) {
                /* Copy in all of the entries */
                for(j = 0; j < el->num_values; j++) {
                    triple_str = talloc_strndup(tmp_ctx,
                                                (const char *)el->values[j].data,
                                                el->values[j].length);
                    if (!triple_str) {
                        ret = ENOMEM;
                        goto done;
                    }

                    tmp_entry[c] = talloc_zero(tmp_entry,
                                                  struct sysdb_netgroup_ctx);
                    if (!tmp_entry[c]) {
                        ret = ENOMEM;
                        goto done;
                    }

                    tmp_entry[c]->type = SYSDB_NETGROUP_TRIPLE_VAL;
                    ret = sysdb_netgr_split_triple(tmp_entry[c],
                                        triple_str,
                                        &tmp_entry[c]->value.triple.hostname,
                                        &tmp_entry[c]->value.triple.username,
                                        &tmp_entry[c]->value.triple.domainname);
                    if (ret != EOK) {
                        goto done;
                    }

                    c++;
                }
            }
            el = ldb_msg_find_element(res->msgs[i], SYSDB_NETGROUP_MEMBER);
            if (el != NULL) {
                for(j = 0; j < el->num_values; j++) {
                    tmp_entry[c] = talloc_zero(tmp_entry,
                                                  struct sysdb_netgroup_ctx);
                    if (!tmp_entry[c]) {
                        ret = ENOMEM;
                        goto done;
                    }

                    tmp_entry[c]->type = SYSDB_NETGROUP_GROUP_VAL;
                    tmp_entry[c]->value.groupname = talloc_strndup(tmp_entry[c],
                                               (const char *)el->values[j].data,
                                               el->values[j].length);
                    if (tmp_entry[c]->value.groupname == NULL) {
                        ret = ENOMEM;
                        goto done;
                    }

                    c++;
                }
            }
        }
    }

    /* Add NULL terminator */
    tmp_entry[c] = NULL;

    *entries = talloc_steal(mem_ctx, tmp_entry);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_getnetgr(TALLOC_CTX *mem_ctx,
                       struct sysdb_ctx *sysdb,
                       const char *netgroup,
                       struct ldb_result **res)
{
    TALLOC_CTX *tmp_ctx;
    static const char *attrs[] = SYSDB_NETGR_ATTRS;
    struct ldb_dn *base_dn;
    struct ldb_result *result;
    char *sanitized_netgroup;
    char *netgroup_dn;
    int lret;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    base_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                             SYSDB_TMPL_NETGROUP_BASE,
                             sysdb->domain->name);
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_filter_sanitize(tmp_ctx, netgroup, &sanitized_netgroup);
    if (ret != EOK) {
        goto done;
    }

    netgroup_dn = talloc_asprintf(tmp_ctx, SYSDB_TMPL_NETGROUP,
                                  sanitized_netgroup, sysdb->domain->name);
    if (!netgroup_dn) {
        ret = ENOMEM;
        goto done;
    }

    lret = ldb_search(sysdb->ldb, tmp_ctx, &result, base_dn,
                     LDB_SCOPE_SUBTREE, attrs,
                     SYSDB_NETGR_TRIPLES_FILTER,
                     sanitized_netgroup, sanitized_netgroup,
                     netgroup_dn);
    ret = sysdb_error_to_errno(lret);
    if (ret != EOK) {
        goto done;
    }

    *res = talloc_steal(mem_ctx, result);
    ret = EOK;

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

int sysdb_get_netgroup_attr(TALLOC_CTX *mem_ctx,
                            struct sysdb_ctx *sysdb,
                            const char *netgrname,
                            const char **attributes,
                            struct ldb_result **res)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *base_dn;
    struct ldb_result *result;
    char *sanitized_netgroup;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    base_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                             SYSDB_TMPL_NETGROUP_BASE, sysdb->domain->name);
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_filter_sanitize(tmp_ctx, netgrname, &sanitized_netgroup);
    if (ret != EOK) {
        goto done;
    }

    ret = ldb_search(sysdb->ldb, tmp_ctx, &result, base_dn,
                     LDB_SCOPE_SUBTREE, attributes,
                     SYSDB_NETGR_FILTER,
                     sanitized_netgroup,
                     sanitized_netgroup);
    if (ret) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    *res = talloc_steal(mem_ctx, result);
done:
    talloc_zfree(tmp_ctx);
    return ret;
}

errno_t sysdb_get_direct_parents(TALLOC_CTX *mem_ctx,
                                 struct sysdb_ctx *sysdb,
                                 struct sss_domain_info *dom,
                                 enum sysdb_member_type mtype,
                                 const char *name,
                                 char ***_direct_parents)
{
    errno_t ret;
    const char *dn;
    char *sanitized_dn;
    struct ldb_dn *basedn;
    static const char *group_attrs[] = { SYSDB_NAME, NULL };
    const char *member_filter;
    size_t direct_sysdb_count = 0;
    struct ldb_message **direct_sysdb_groups = NULL;
    char **direct_parents = NULL;
    TALLOC_CTX *tmp_ctx = NULL;
    int i, pi;
    const char *tmp_str;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    if (mtype == SYSDB_MEMBER_USER) {
        dn = sysdb_user_strdn(tmp_ctx, dom->name, name);
    } else if (mtype == SYSDB_MEMBER_GROUP) {
        dn = sysdb_group_strdn(tmp_ctx, dom->name, name);
    } else {
        DEBUG(1, ("Unknown member type\n"));
        ret = EINVAL;
        goto done;
    }

    if (!dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_filter_sanitize(tmp_ctx, dn, &sanitized_dn);
    if (ret != EOK) {
        goto done;
    }

    member_filter = talloc_asprintf(tmp_ctx, "(&(%s=%s)(%s=%s))",
                                    SYSDB_OBJECTCLASS, SYSDB_GROUP_CLASS,
                                    SYSDB_MEMBER, sanitized_dn);
    if (!member_filter) {
        ret = ENOMEM;
        goto done;
    }

    basedn = ldb_dn_new_fmt(tmp_ctx, sysdb_ctx_get_ldb(sysdb),
                            SYSDB_TMPL_GROUP_BASE, dom->name);
    if (!basedn) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(8, ("searching sysdb with filter [%s]\n", member_filter));

    ret = sysdb_search_entry(tmp_ctx, sysdb, basedn,
                             LDB_SCOPE_SUBTREE, member_filter, group_attrs,
                             &direct_sysdb_count, &direct_sysdb_groups);
    if (ret == ENOENT) {
        direct_sysdb_count = 0;
    } else if (ret != EOK && ret != ENOENT) {
        DEBUG(2, ("sysdb_search_entry failed: [%d]: %s\n",
                  ret, strerror(ret)));
        goto done;
    }

    /* EOK */
    /* Get the list of sysdb groups by name */
    direct_parents = talloc_array(tmp_ctx, char *, direct_sysdb_count+1);
    if (!direct_parents) {
        ret = ENOMEM;
        goto done;
    }

    pi = 0;
    for(i = 0; i < direct_sysdb_count; i++) {
        tmp_str = ldb_msg_find_attr_as_string(direct_sysdb_groups[i],
                                                SYSDB_NAME, NULL);
        if (!tmp_str) {
            /* This should never happen, but if it does, just continue */
            continue;
        }

        direct_parents[pi] = talloc_strdup(direct_parents, tmp_str);
        if (!direct_parents[pi]) {
            DEBUG(1, ("A group with no name?\n"));
            ret = EIO;
            goto done;
        }
        pi++;
    }
    direct_parents[pi] = NULL;

    DEBUG(7, ("%s is a member of %d sysdb groups\n",
              name, direct_sysdb_count));
    *_direct_parents = talloc_steal(mem_ctx, direct_parents);
    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}
