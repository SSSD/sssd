/*
   SSSD

   System Database

   Copyright (C) Simo Sorce <ssorce@redhat.com> 2008

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


struct ldb_dn *sysdb_custom_subtree_dn(struct sysdb_ctx *ctx, void *memctx,
                                       const char *domain,
                                       const char *subtree_name)
{
    return ldb_dn_new_fmt(memctx, ctx->ldb, SYSDB_TMPL_CUSTOM_SUBTREE,
                          subtree_name, domain);
}
struct ldb_dn *sysdb_custom_dn(struct sysdb_ctx *ctx, void *memctx,
                                const char *domain, const char *object_name,
                                const char *subtree_name)
{
    return ldb_dn_new_fmt(memctx, ctx->ldb, SYSDB_TMPL_CUSTOM, object_name,
                          subtree_name, domain);
}

struct ldb_dn *sysdb_user_dn(struct sysdb_ctx *ctx, void *memctx,
                             const char *domain, const char *name)
{
    return ldb_dn_new_fmt(memctx, ctx->ldb, SYSDB_TMPL_USER, name, domain);
}

struct ldb_dn *sysdb_group_dn(struct sysdb_ctx *ctx, void *memctx,
                              const char *domain, const char *name)
{
    return ldb_dn_new_fmt(memctx, ctx->ldb, SYSDB_TMPL_GROUP, name, domain);
}

errno_t sysdb_group_dn_name(struct sysdb_ctx *ctx, void *memctx,
                            const char *_dn, char **_name)
{
    struct ldb_dn *dn;
    *_name = NULL;

    dn = ldb_dn_new_fmt(memctx, ctx->ldb, "%s", _dn);
    if (dn == NULL) {
        return ENOMEM;
    }

    *_name = talloc_strdup(memctx, ldb_dn_get_rdn_name(dn));
    if (!*_name) {
        talloc_zfree(dn);
        return ENOMEM;
    }

    talloc_zfree(dn);

    return EOK;
}

struct ldb_dn *sysdb_domain_dn(struct sysdb_ctx *ctx, void *memctx,
                              const char *domain)
{
    return ldb_dn_new_fmt(memctx, ctx->ldb, SYSDB_DOM_BASE, domain);
}

struct ldb_context *sysdb_ctx_get_ldb(struct sysdb_ctx *ctx)
{
    return ctx->ldb;
}

struct sysdb_attrs *sysdb_new_attrs(TALLOC_CTX *memctx)
{
    return talloc_zero(memctx, struct sysdb_attrs);
}

static int sysdb_attrs_get_el_int(struct sysdb_attrs *attrs, const char *name,
                                  bool alloc, struct ldb_message_element **el)
{
    struct ldb_message_element *e = NULL;
    int i;

    for (i = 0; i < attrs->num; i++) {
        if (strcasecmp(name, attrs->a[i].name) == 0)
            e = &(attrs->a[i]);
    }

    if (!e && alloc) {
        e = talloc_realloc(attrs, attrs->a,
                           struct ldb_message_element, attrs->num+1);
        if (!e) return ENOMEM;
        attrs->a = e;

        e[attrs->num].name = talloc_strdup(e, name);
        if (!e[attrs->num].name) return ENOMEM;

        e[attrs->num].num_values = 0;
        e[attrs->num].values = NULL;
        e[attrs->num].flags = 0;

        e = &(attrs->a[attrs->num]);
        attrs->num++;
    }

    if (!e) {
        return ENOENT;
    }

    *el = e;

    return EOK;
}

int sysdb_attrs_get_el(struct sysdb_attrs *attrs, const char *name,
                       struct ldb_message_element **el)
{
    return sysdb_attrs_get_el_int(attrs, name, true, el);
}

int sysdb_attrs_get_string(struct sysdb_attrs *attrs, const char *name,
                           const char **string)
{
    struct ldb_message_element *el;
    int ret;

    ret = sysdb_attrs_get_el_int(attrs, name, false, &el);
    if (ret) {
        return ret;
    }

    if (el->num_values != 1) {
        return ERANGE;
    }

    *string = (const char *)el->values[0].data;
    return EOK;
}

int sysdb_attrs_get_string_array(struct sysdb_attrs *attrs, const char *name,
                                 TALLOC_CTX *mem_ctx, const char ***string)
{
    struct ldb_message_element *el;
    int ret;
    unsigned int u;
    const char **a;

    ret = sysdb_attrs_get_el_int(attrs, name, false, &el);
    if (ret) {
        return ret;
    }

    a = talloc_array(mem_ctx, const char *, el->num_values + 1);
    if (a == NULL) {
        return ENOMEM;
    }

    memset(a, 0, sizeof(const char *) * (el->num_values + 1));

    for(u = 0; u < el->num_values; u++) {
        a[u] = talloc_strndup(a, (const char *)el->values[u].data,
                              el->values[u].length);
        if (a[u] == NULL) {
            talloc_free(a);
            return ENOMEM;
        }
    }

    *string = a;
    return EOK;
}

int sysdb_attrs_add_val(struct sysdb_attrs *attrs,
                        const char *name, const struct ldb_val *val)
{
    struct ldb_message_element *el = NULL;
    struct ldb_val *vals;
    int ret;

    ret = sysdb_attrs_get_el(attrs, name, &el);

    vals = talloc_realloc(attrs->a, el->values,
                          struct ldb_val, el->num_values+1);
    if (!vals) return ENOMEM;

    vals[el->num_values] = ldb_val_dup(vals, val);
    if (vals[el->num_values].data == NULL &&
        vals[el->num_values].length != 0) {
        return ENOMEM;
    }

    el->values = vals;
    el->num_values++;

    return EOK;
}

int sysdb_attrs_add_string(struct sysdb_attrs *attrs,
                           const char *name, const char *str)
{
    struct ldb_val v;

    v.data = (uint8_t *)discard_const(str);
    v.length = strlen(str);

    return sysdb_attrs_add_val(attrs, name, &v);
}

int sysdb_attrs_add_bool(struct sysdb_attrs *attrs,
                         const char *name, bool value)
{
    if(value) {
        return sysdb_attrs_add_string(attrs, name, "TRUE");
    }

    return sysdb_attrs_add_string(attrs, name, "FALSE");
}

int sysdb_attrs_steal_string(struct sysdb_attrs *attrs,
                             const char *name, char *str)
{
    struct ldb_message_element *el = NULL;
    struct ldb_val *vals;
    int ret;

    ret = sysdb_attrs_get_el(attrs, name, &el);

    vals = talloc_realloc(attrs->a, el->values,
                          struct ldb_val, el->num_values+1);
    if (!vals) return ENOMEM;
    el->values = vals;

    /* now steal and assign the string */
    talloc_steal(el->values, str);

    el->values[el->num_values].data = (uint8_t *)str;
    el->values[el->num_values].length = strlen(str);
    el->num_values++;

    return EOK;
}

int sysdb_attrs_add_long(struct sysdb_attrs *attrs,
                         const char *name, long value)
{
    struct ldb_val v;
    char *str;
    int ret;

    str = talloc_asprintf(attrs, "%ld", value);
    if (!str) return ENOMEM;

    v.data = (uint8_t *)str;
    v.length = strlen(str);

    ret = sysdb_attrs_add_val(attrs, name, &v);
    talloc_free(str);

    return ret;
}

int sysdb_attrs_add_uint32(struct sysdb_attrs *attrs,
                           const char *name, uint32_t value)
{
    unsigned long val = value;
    struct ldb_val v;
    char *str;
    int ret;

    str = talloc_asprintf(attrs, "%lu", val);
    if (!str) return ENOMEM;

    v.data = (uint8_t *)str;
    v.length = strlen(str);

    ret = sysdb_attrs_add_val(attrs, name, &v);
    talloc_free(str);

    return ret;
}

int sysdb_attrs_add_time_t(struct sysdb_attrs *attrs,
                           const char *name, time_t value)
{
    long long val = value;
    struct ldb_val v;
    char *str;
    int ret;

    str = talloc_asprintf(attrs, "%lld", val);
    if (!str) return ENOMEM;

    v.data = (uint8_t *)str;
    v.length = strlen(str);

    ret = sysdb_attrs_add_val(attrs, name, &v);
    talloc_free(str);

    return ret;
}

int sysdb_attrs_users_from_str_list(struct sysdb_attrs *attrs,
                                    const char *attr_name,
                                    const char *domain,
                                    const char **list)
{
    struct ldb_message_element *el = NULL;
    struct ldb_val *vals;
    int i, j, num;
    char *member;
    int ret;

    ret = sysdb_attrs_get_el(attrs, attr_name, &el);
    if (ret) {
        return ret;
    }

    for (num = 0; list[num]; num++) /* count */ ;

    vals = talloc_realloc(attrs->a, el->values,
                          struct ldb_val, el->num_values + num);
    if (!vals) {
        return ENOMEM;
    }
    el->values = vals;

    DEBUG(9, ("Adding %d members to existing %d ones\n",
              num, el->num_values));

    for (i = 0, j = el->num_values; i < num; i++) {

        member = sysdb_user_strdn(el->values, domain, list[i]);
        if (!member) {
            DEBUG(4, ("Failed to get user dn for [%s]\n", list[i]));
            continue;
        }
        el->values[j].data = (uint8_t *)member;
        el->values[j].length = strlen(member);
        j++;

        DEBUG(7, ("    member #%d: [%s]\n", i, member));
    }
    el->num_values = j;

    return EOK;
}

int sysdb_attrs_users_from_ldb_vals(struct sysdb_attrs *attrs,
                                    const char *attr_name,
                                    const char *domain,
                                    struct ldb_val *values,
                                    int num_values)
{
    struct ldb_message_element *el = NULL;
    struct ldb_val *vals;
    int i, j;
    char *member;
    int ret;

    ret = sysdb_attrs_get_el(attrs, attr_name, &el);
    if (ret) {
        return ret;
    }

    vals = talloc_realloc(attrs->a, el->values, struct ldb_val,
                          el->num_values + num_values);
    if (!vals) {
        return ENOMEM;
    }
    el->values = vals;

    DEBUG(9, ("Adding %d members to existing %d ones\n",
              num_values, el->num_values));

    for (i = 0, j = el->num_values; i < num_values; i++) {
        member = sysdb_user_strdn(el->values, domain,
                                  (char *)values[i].data);
        if (!member) {
            DEBUG(4, ("Failed to get user dn for [%s]\n",
                      (char *)values[i].data));
            return ENOMEM;
        }
        el->values[j].data = (uint8_t *)member;
        el->values[j].length = strlen(member);
        j++;

        DEBUG(7, ("    member #%d: [%s]\n", i, member));
    }
    el->num_values = j;

    return EOK;
}

static char *build_dom_dn_str_escape(TALLOC_CTX *memctx, const char *template,
                                     const char *domain, const char *name)
{
    char *ret;
    int l;

    l = strcspn(name, ",=\n+<>#;\\\"");
    if (name[l] != '\0') {
        struct ldb_val v;
        char *tmp;

        v.data = discard_const_p(uint8_t, name);
        v.length = strlen(name);

        tmp = ldb_dn_escape_value(memctx, v);
        if (!tmp) {
            return NULL;
        }

        ret = talloc_asprintf(memctx, template, tmp, domain);
        talloc_zfree(tmp);
        if (!ret) {
            return NULL;
        }

        return ret;
    }

    ret = talloc_asprintf(memctx, template, name, domain);
    if (!ret) {
        return NULL;
    }

    return ret;
}

char *sysdb_user_strdn(TALLOC_CTX *memctx,
                       const char *domain, const char *name)
{
    return build_dom_dn_str_escape(memctx, SYSDB_TMPL_USER, domain, name);
}

char *sysdb_group_strdn(TALLOC_CTX *memctx,
                        const char *domain, const char *name)
{
    return build_dom_dn_str_escape(memctx, SYSDB_TMPL_GROUP, domain, name);
}

/* TODO: make a more complete and precise mapping */
int sysdb_error_to_errno(int ldberr)
{
    switch (ldberr) {
    case LDB_SUCCESS:
        return EOK;
    case LDB_ERR_OPERATIONS_ERROR:
        return EIO;
    case LDB_ERR_NO_SUCH_OBJECT:
        return ENOENT;
    case LDB_ERR_BUSY:
        return EBUSY;
    case LDB_ERR_ENTRY_ALREADY_EXISTS:
        return EEXIST;
    default:
        return EFAULT;
    }
}

/* =Transactions========================================================== */

int sysdb_transaction_start(struct sysdb_ctx *ctx)
{
    int ret;

    ret = ldb_transaction_start(ctx->ldb);
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to start ldb transaction! (%d)\n", ret));
    }
    return sysdb_error_to_errno(ret);
}

int sysdb_transaction_commit(struct sysdb_ctx *ctx)
{
    int ret;

    ret = ldb_transaction_commit(ctx->ldb);
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to commit ldb transaction! (%d)\n", ret));
    }
    return sysdb_error_to_errno(ret);
}

int sysdb_transaction_cancel(struct sysdb_ctx *ctx)
{
    int ret;

    ret = ldb_transaction_cancel(ctx->ldb);
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to cancel ldb transaction! (%d)\n", ret));
    }
    return sysdb_error_to_errno(ret);
}

/* =Initialization======================================================== */

static int sysdb_domain_init_internal(TALLOC_CTX *mem_ctx,
                                      struct sss_domain_info *domain,
                                      const char *db_path,
                                      bool allow_upgrade,
                                      struct sysdb_ctx **_ctx);

static int sysdb_get_db_file(TALLOC_CTX *mem_ctx,
                             const char *provider, const char *name,
                             const char *base_path, char **_ldb_file)
{
    char *ldb_file;

    /* special case for the local domain */
    if (strcasecmp(provider, "local") == 0) {
        ldb_file = talloc_asprintf(mem_ctx, "%s/"LOCAL_SYSDB_FILE,
                                   base_path);
    } else {
        ldb_file = talloc_asprintf(mem_ctx, "%s/"CACHE_SYSDB_FILE,
                                   base_path, name);
    }
    if (!ldb_file) {
        return ENOMEM;
    }

    *_ldb_file = ldb_file;
    return EOK;
}

/* serach all groups that have a memberUid attribute.
 * change it into a member attribute for a user of same domain.
 * remove the memberUid attribute
 * add the new member attribute
 * finally stop indexing memberUid
 * upgrade version to 0.2
 */
static int sysdb_upgrade_01(TALLOC_CTX *mem_ctx,
                            struct ldb_context *ldb,
                            const char **ver)
{
    struct ldb_message_element *el;
    struct ldb_result *res;
    struct ldb_dn *basedn;
    struct ldb_dn *mem_dn;
    struct ldb_message *msg;
    const struct ldb_val *val;
    const char *filter = "(&(memberUid=*)(objectclass=group))";
    const char *attrs[] = { "memberUid", NULL };
    const char *mdn;
    char *domain;
    int ret, i, j;

    basedn = ldb_dn_new(mem_ctx, ldb, "cn=sysdb");
    if (!basedn) {
        ret = EIO;
        goto done;
    }

    ret = ldb_search(ldb, mem_ctx, &res,
                     basedn, LDB_SCOPE_SUBTREE,
                     attrs, filter);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    ret = ldb_transaction_start(ldb);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    for (i = 0; i < res->count; i++) {
        el = ldb_msg_find_element(res->msgs[i], "memberUid");
        if (!el) {
            DEBUG(1, ("memberUid is missing from message [%s], skipping\n",
                      ldb_dn_get_linearized(res->msgs[i]->dn)));
            continue;
        }

        /* create modification message */
        msg = ldb_msg_new(mem_ctx);
        if (!msg) {
            ret = ENOMEM;
            goto done;
        }
        msg->dn = res->msgs[i]->dn;

        ret = ldb_msg_add_empty(msg, "memberUid", LDB_FLAG_MOD_DELETE, NULL);
        if (ret != LDB_SUCCESS) {
            ret = ENOMEM;
            goto done;
        }

        ret = ldb_msg_add_empty(msg, SYSDB_MEMBER, LDB_FLAG_MOD_ADD, NULL);
        if (ret != LDB_SUCCESS) {
            ret = ENOMEM;
            goto done;
        }

        /* get domain name component value */
        val = ldb_dn_get_component_val(res->msgs[i]->dn, 2);
        domain = talloc_strndup(mem_ctx, (const char *)val->data, val->length);
        if (!domain) {
            ret = ENOMEM;
            goto done;
        }

        for (j = 0; j < el->num_values; j++) {
            mem_dn = ldb_dn_new_fmt(mem_ctx, ldb, SYSDB_TMPL_USER,
                                    (const char *)el->values[j].data, domain);
            if (!mem_dn) {
                ret = ENOMEM;
                goto done;
            }

            mdn = talloc_strdup(msg, ldb_dn_get_linearized(mem_dn));
            if (!mdn) {
                ret = ENOMEM;
                goto done;
            }
            ret = ldb_msg_add_string(msg, SYSDB_MEMBER, mdn);
            if (ret != LDB_SUCCESS) {
                ret = ENOMEM;
                goto done;
            }

            talloc_zfree(mem_dn);
        }

        /* ok now we are ready to modify the entry */
        ret = ldb_modify(ldb, msg);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        talloc_zfree(msg);
    }

    /* conversion done, upgrade version number */
    msg = ldb_msg_new(mem_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(mem_ctx, ldb, "cn=sysdb");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "version", LDB_FLAG_MOD_REPLACE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "version", SYSDB_VERSION_0_2);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        ldb_transaction_cancel(ldb);
    } else {
        ret = ldb_transaction_commit(ldb);
        if (ret != LDB_SUCCESS) {
            return EIO;
        }

        *ver = SYSDB_VERSION_0_2;
    }

    return ret;
}

static int sysdb_check_upgrade_02(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *domains,
                                  const char *db_path)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct ldb_context *ldb;
    char *ldb_file;
    struct sysdb_ctx *ctx;
    struct sss_domain_info *dom;
    struct ldb_message_element *el;
    struct ldb_message *msg;
    struct ldb_result *res;
    struct ldb_dn *verdn;
    const char *version = NULL;
    bool do_02_upgrade = false;
    bool ctx_trans = false;
    int ret;

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = sysdb_get_db_file(mem_ctx,
                            "local", "UPGRADE",
                            db_path, &ldb_file);
    if (ret != EOK) {
        goto exit;
    }

    ldb = ldb_init(tmp_ctx, NULL);
    if (!ldb) {
        ret = EIO;
        goto exit;
    }

    ret = ldb_set_debug(ldb, ldb_debug_messages, NULL);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto exit;
    }

#ifdef SYSDB_TEST
    ldb_set_modules_dir(ctx->ldb, ABS_BUILD_DIR"/.libs");
#endif

    ret = ldb_connect(ldb, ldb_file, 0, NULL);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto exit;
    }

    verdn = ldb_dn_new(tmp_ctx, ldb, "cn=sysdb");
    if (!verdn) {
        ret = EIO;
        goto exit;
    }

    ret = ldb_search(ldb, tmp_ctx, &res,
                     verdn, LDB_SCOPE_BASE,
                     NULL, NULL);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto exit;
    }
    if (res->count > 1) {
        ret = EIO;
        goto exit;
    }

    if (res->count == 1) {
        el = ldb_msg_find_element(res->msgs[0], "version");
        if (el) {
            if (el->num_values != 1) {
                ret = EINVAL;
                goto exit;
            }
            version = talloc_strndup(tmp_ctx,
                                     (char *)(el->values[0].data),
                                     el->values[0].length);
            if (!version) {
                ret = ENOMEM;
                goto exit;
            }

            if (strcmp(version, SYSDB_VERSION) == 0) {
                /* all fine, return */
                ret = EOK;
                goto exit;
            }

            DEBUG(4, ("Upgrading DB from version: %s\n", version));

            if (strcmp(version, SYSDB_VERSION_0_1) == 0) {
                /* convert database */
                ret = sysdb_upgrade_01(tmp_ctx, ldb, &version);
                if (ret != EOK) goto exit;
            }

            if (strcmp(version, SYSDB_VERSION_0_2) == 0) {
                /* need to convert database to split files */
                do_02_upgrade = true;
            }

        }
    }

    if (!do_02_upgrade) {
        /* not a v2 upgrade, return and let the normal code take over any
        * further upgrade */
        ret = EOK;
        goto exit;
    }

    /* == V2->V3 UPGRADE == */

    DEBUG(0, ("UPGRADING DB TO VERSION %s\n", SYSDB_VERSION_0_3));

    /* ldb uses posix locks,
     * posix is stupid and kills all locks when you close *any* file
     * descriptor associated to the same file.
     * Therefore we must close and reopen the ldb file here */

    /* == Backup and reopen ldb == */

    /* close */
    talloc_zfree(ldb);

    /* backup*/
    ret = backup_file(ldb_file, 0);
    if (ret != EOK) {
        goto exit;
    }

    /* reopen */
    ldb = ldb_init(tmp_ctx, NULL);
    if (!ldb) {
        ret = EIO;
        goto exit;
    }

    ret = ldb_set_debug(ldb, ldb_debug_messages, NULL);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto exit;
    }

    ret = ldb_connect(ldb, ldb_file, 0, NULL);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto exit;
    }

    /* open a transaction */
    ret = ldb_transaction_start(ldb);
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to start ldb transaction! (%d)\n", ret));
        ret = EIO;
        goto exit;
    }

    /* == Upgrade contents == */

    for (dom = domains; dom; dom = dom->next) {
        struct ldb_dn *domain_dn;
        struct ldb_dn *users_dn;
        struct ldb_dn *groups_dn;
        int i;

        /* skip local */
        if (strcasecmp(dom->provider, "local") == 0) {
            continue;
        }

        /* create new dom db */
        ret = sysdb_domain_init_internal(tmp_ctx, dom,
                                         db_path, false, &ctx);
        if (ret != EOK) {
            goto done;
        }

        ret = ldb_transaction_start(ctx->ldb);
        if (ret != LDB_SUCCESS) {
            DEBUG(1, ("Failed to start ldb transaction! (%d)\n", ret));
            ret = EIO;
            goto done;
        }
        ctx_trans = true;

        /* search all entries for this domain in local,
         * copy them all in the new database,
         * then remove them from local */

        domain_dn = ldb_dn_new_fmt(tmp_ctx, ctx->ldb,
                                   SYSDB_DOM_BASE, ctx->domain->name);
        if (!domain_dn) {
            ret = ENOMEM;
            goto done;
        }

        ret = ldb_search(ldb, tmp_ctx, &res,
                         domain_dn, LDB_SCOPE_SUBTREE,
                         NULL, NULL);
        if (ret != LDB_SUCCESS) {
            ret = EIO;
            goto done;
        }

        users_dn = ldb_dn_new_fmt(tmp_ctx, ctx->ldb,
                                 SYSDB_TMPL_USER_BASE, ctx->domain->name);
        if (!users_dn) {
            ret = ENOMEM;
            goto done;
        }
        groups_dn = ldb_dn_new_fmt(tmp_ctx, ctx->ldb,
                                   SYSDB_TMPL_GROUP_BASE, ctx->domain->name);
        if (!groups_dn) {
            ret = ENOMEM;
            goto done;
        }

        for (i = 0; i < res->count; i++) {

            struct ldb_dn *orig_dn;

            msg = res->msgs[i];

            /* skip pre-created congtainers */
            if ((ldb_dn_compare(msg->dn, domain_dn) == 0) ||
                (ldb_dn_compare(msg->dn, users_dn) == 0) ||
                (ldb_dn_compare(msg->dn, groups_dn) == 0)) {
                continue;
            }

            /* regenerate the DN against the new ldb as it may have different
             * casefolding rules (example: name changing from case insensitive
             * to case sensitive) */
            orig_dn = msg->dn;
            msg->dn = ldb_dn_new(msg, ctx->ldb,
                                 ldb_dn_get_linearized(orig_dn));
            if (!msg->dn) {
                ret = ENOMEM;
                goto done;
            }

            ret = ldb_add(ctx->ldb, msg);
            if (ret != LDB_SUCCESS) {
                DEBUG(0, ("WARNING: Could not add entry %s,"
                          " to new ldb file! (%d [%s])\n",
                          ldb_dn_get_linearized(msg->dn),
                          ret, ldb_errstring(ctx->ldb)));
            }

            ret = ldb_delete(ldb, orig_dn);
            if (ret != LDB_SUCCESS) {
                DEBUG(0, ("WARNING: Could not remove entry %s,"
                          " from old ldb file! (%d [%s])\n",
                          ldb_dn_get_linearized(orig_dn),
                          ret, ldb_errstring(ldb)));
            }
        }

        /* now remove the basic containers from local */
        /* these were optional so debug at level 9 in case
         * of failure just for tracing */
        ret = ldb_delete(ldb, groups_dn);
        if (ret != LDB_SUCCESS) {
            DEBUG(9, ("WARNING: Could not remove entry %s,"
                      " from old ldb file! (%d [%s])\n",
                      ldb_dn_get_linearized(groups_dn),
                      ret, ldb_errstring(ldb)));
        }
        ret = ldb_delete(ldb, users_dn);
        if (ret != LDB_SUCCESS) {
            DEBUG(9, ("WARNING: Could not remove entry %s,"
                      " from old ldb file! (%d [%s])\n",
                      ldb_dn_get_linearized(users_dn),
                      ret, ldb_errstring(ldb)));
        }
        ret = ldb_delete(ldb, domain_dn);
        if (ret != LDB_SUCCESS) {
            DEBUG(9, ("WARNING: Could not remove entry %s,"
                      " from old ldb file! (%d [%s])\n",
                      ldb_dn_get_linearized(domain_dn),
                      ret, ldb_errstring(ldb)));
        }

        ret = ldb_transaction_commit(ctx->ldb);
        if (ret != LDB_SUCCESS) {
            DEBUG(1, ("Failed to commit ldb transaction! (%d)\n", ret));
            ret = EIO;
            goto done;
        }
        ctx_trans = false;

        talloc_zfree(domain_dn);
        talloc_zfree(groups_dn);
        talloc_zfree(users_dn);
        talloc_zfree(res);
    }

    /* conversion done, upgrade version number */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, ldb, "cn=sysdb");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "version", LDB_FLAG_MOD_REPLACE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "version", SYSDB_VERSION_0_3);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = ldb_transaction_commit(ldb);
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to commit ldb transaction! (%d)\n", ret));
        ret = EIO;
        goto exit;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        if (ctx_trans) {
            ret = ldb_transaction_cancel(ctx->ldb);
            if (ret != LDB_SUCCESS) {
                DEBUG(1, ("Failed to cancel ldb transaction! (%d)\n", ret));
            }
        }
        ret = ldb_transaction_cancel(ldb);
        if (ret != LDB_SUCCESS) {
            DEBUG(1, ("Failed to cancel ldb transaction! (%d)\n", ret));
        }
    }

exit:
    talloc_free(tmp_ctx);
    return ret;
}

static int sysdb_upgrade_03(struct sysdb_ctx *ctx, const char **ver)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_message *msg;

    tmp_ctx = talloc_new(ctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    DEBUG(0, ("UPGRADING DB TO VERSION %s\n", SYSDB_VERSION_0_4));

    ret = ldb_transaction_start(ctx->ldb);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    /* Make this database case-sensitive */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, ctx->ldb, "@ATTRIBUTES");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "name", LDB_FLAG_MOD_DELETE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(ctx->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* conversion done, upgrade version number */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, ctx->ldb, "cn=sysdb");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "version", LDB_FLAG_MOD_REPLACE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "version", SYSDB_VERSION_0_4);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(ctx->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = EOK;

done:
    talloc_zfree(tmp_ctx);

    if (ret != EOK) {
        ret = ldb_transaction_cancel(ctx->ldb);
    } else {
        ret = ldb_transaction_commit(ctx->ldb);
        *ver = SYSDB_VERSION_0_4;
    }
    if (ret != LDB_SUCCESS) {
        ret = EIO;
    }

    return ret;
}

static int sysdb_upgrade_04(struct sysdb_ctx *ctx, const char **ver)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_message *msg;

    tmp_ctx = talloc_new(ctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    DEBUG(0, ("UPGRADING DB TO VERSION %s\n", SYSDB_VERSION_0_5));

    ret = ldb_transaction_start(ctx->ldb);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    /* Add new index */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, ctx->ldb, "@INDEXLIST");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "@IDXATTR", LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "@IDXATTR", "originalDN");
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(ctx->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* Rebuild memberuid and memberoif attributes */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, ctx->ldb, "@MEMBEROF-REBUILD");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_add(ctx->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* conversion done, upgrade version number */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, ctx->ldb, "cn=sysdb");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "version", LDB_FLAG_MOD_REPLACE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "version", SYSDB_VERSION_0_5);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(ctx->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = EOK;

done:
    talloc_zfree(tmp_ctx);

    if (ret != EOK) {
        ret = ldb_transaction_cancel(ctx->ldb);
    } else {
        ret = ldb_transaction_commit(ctx->ldb);
        *ver = SYSDB_VERSION_0_5;
    }
    if (ret != LDB_SUCCESS) {
        ret = EIO;
    }

    return ret;
}

static int sysdb_domain_init_internal(TALLOC_CTX *mem_ctx,
                                      struct sss_domain_info *domain,
                                      const char *db_path,
                                      bool allow_upgrade,
                                      struct sysdb_ctx **_ctx)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct sysdb_ctx *ctx;
    const char *base_ldif;
    struct ldb_ldif *ldif;
    struct ldb_message *msg;
    struct ldb_message_element *el;
    struct ldb_result *res;
    struct ldb_dn *verdn;
    const char *version = NULL;
    int ret;

    ctx = talloc_zero(mem_ctx, struct sysdb_ctx);
    if (!ctx) {
        return ENOMEM;
    }
    ctx->domain = domain;

    /* The local provider s the only true MPG,
     * for the other domains, the provider actually unrolls MPGs */
    if (strcasecmp(domain->provider, "local") == 0) {
        ctx->mpg = true;
    }

    ret = sysdb_get_db_file(ctx, domain->provider,
                            domain->name, db_path,
                            &ctx->ldb_file);
    if (ret != EOK) {
        return ret;
    }
    DEBUG(5, ("DB File for %s: %s\n", domain->name, ctx->ldb_file));

    ctx->ldb = ldb_init(ctx, NULL);
    if (!ctx->ldb) {
        return EIO;
    }

    ret = ldb_set_debug(ctx->ldb, ldb_debug_messages, NULL);
    if (ret != LDB_SUCCESS) {
        return EIO;
    }

#ifdef SYSDB_TEST
    ldb_set_modules_dir(ctx->ldb, ABS_BUILD_DIR"/.libs");
#endif

    ret = ldb_connect(ctx->ldb, ctx->ldb_file, 0, NULL);
    if (ret != LDB_SUCCESS) {
        return EIO;
    }

    tmp_ctx = talloc_new(ctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    verdn = ldb_dn_new(tmp_ctx, ctx->ldb, "cn=sysdb");
    if (!verdn) {
        ret = EIO;
        goto done;
    }

    ret = ldb_search(ctx->ldb, tmp_ctx, &res,
                     verdn, LDB_SCOPE_BASE,
                     NULL, NULL);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }
    if (res->count > 1) {
        ret = EIO;
        goto done;
    }

    if (res->count == 1) {
        el = ldb_msg_find_element(res->msgs[0], "version");
        if (el) {
            if (el->num_values != 1) {
                ret = EINVAL;
                goto done;
            }
            version = talloc_strndup(tmp_ctx,
                                     (char *)(el->values[0].data),
                                     el->values[0].length);
            if (!version) {
                ret = ENOMEM;
                goto done;
            }

            if (strcmp(version, SYSDB_VERSION) == 0) {
                /* all fine, return */
                ret = EOK;
                goto done;
            }

            if (!allow_upgrade) {
                DEBUG(0, ("Wrong DB version (got %s expected %s)\n",
                          version, SYSDB_VERSION));
                ret = EINVAL;
                goto done;
            }

            DEBUG(4, ("Upgrading DB [%s] from version: %s\n",
                      domain->name, version));

            if (strcmp(version, SYSDB_VERSION_0_3) == 0) {
                ret = sysdb_upgrade_03(ctx, &version);
                if (ret != EOK) {
                    goto done;
                }
            }

            if (strcmp(version, SYSDB_VERSION_0_4) == 0) {
                ret = sysdb_upgrade_04(ctx, &version);
                goto done;
            }
        }

        DEBUG(0,("Unknown DB version [%s], expected [%s] for domain %s!\n",
                 version?version:"not found", SYSDB_VERSION, domain->name));
        ret = EINVAL;
        goto done;
    }

    /* cn=sysdb does not exists, means db is empty, populate */

    base_ldif = SYSDB_BASE_LDIF;
    while ((ldif = ldb_ldif_read_string(ctx->ldb, &base_ldif))) {
        ret = ldb_add(ctx->ldb, ldif->msg);
        if (ret != LDB_SUCCESS) {
            DEBUG(0, ("Failed to initialize DB (%d, [%s]) for domain %s!\n",
                      ret, ldb_errstring(ctx->ldb), domain->name));
            ret = EIO;
            goto done;
        }
        ldb_ldif_read_free(ctx->ldb, ldif);
    }

    /* == create base domain object == */

    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new_fmt(msg, ctx->ldb, SYSDB_DOM_BASE, domain->name);
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_fmt(msg, "cn", "%s", domain->name);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }
    /* do a synchronous add */
    ret = ldb_add(ctx->ldb, msg);
    if (ret != LDB_SUCCESS) {
        DEBUG(0, ("Failed to initialize DB (%d, [%s]) for domain %s!\n",
                  ret, ldb_errstring(ctx->ldb), domain->name));
        ret = EIO;
        goto done;
    }
    talloc_zfree(msg);

    /* == create Users tree == */

    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new_fmt(msg, ctx->ldb,
                             SYSDB_TMPL_USER_BASE, domain->name);
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_fmt(msg, "cn", "Users");
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }
    /* do a synchronous add */
    ret = ldb_add(ctx->ldb, msg);
    if (ret != LDB_SUCCESS) {
        DEBUG(0, ("Failed to initialize DB (%d, [%s]) for domain %s!\n",
                  ret, ldb_errstring(ctx->ldb), domain->name));
        ret = EIO;
        goto done;
    }
    talloc_zfree(msg);

    /* == create Groups tree == */

    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new_fmt(msg, ctx->ldb,
                             SYSDB_TMPL_GROUP_BASE, domain->name);
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_fmt(msg, "cn", "Groups");
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }
    /* do a synchronous add */
    ret = ldb_add(ctx->ldb, msg);
    if (ret != LDB_SUCCESS) {
        DEBUG(0, ("Failed to initialize DB (%d, [%s]) for domain %s!\n",
                  ret, ldb_errstring(ctx->ldb), domain->name));
        ret = EIO;
        goto done;
    }
    talloc_zfree(msg);

    ret = EOK;

done:
    if (ret == EOK) {
        *_ctx = ctx;
    }
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_init(TALLOC_CTX *mem_ctx,
               struct confdb_ctx *cdb,
               const char *alt_db_path,
               bool allow_upgrade,
               struct sysdb_ctx_list **_ctx_list)
{
    struct sysdb_ctx_list *ctx_list;
    struct sss_domain_info *domains, *dom;
    struct sysdb_ctx *ctx;
    int ret;

    ctx_list = talloc_zero(mem_ctx, struct sysdb_ctx_list);
    if (!ctx_list) {
        return ENOMEM;
    }

    if (alt_db_path) {
        ctx_list->db_path = talloc_strdup(ctx_list, alt_db_path);
    } else {
        ctx_list->db_path = talloc_strdup(ctx_list, DB_PATH);
    }
    if (!ctx_list->db_path) {
        talloc_zfree(ctx_list);
        return ENOMEM;
    }

    /* open a db for each backend */
    ret = confdb_get_domains(cdb, &domains);
    if (ret != EOK) {
        talloc_zfree(ctx_list);
        return ret;
    }

    if (allow_upgrade) {
        /* check if we have an old sssd.ldb to upgrade */
        ret = sysdb_check_upgrade_02(ctx_list, domains,
                                     ctx_list->db_path);
        if (ret != EOK) {
            talloc_zfree(ctx_list);
            return ret;
        }
    }

    for (dom = domains; dom; dom = dom->next) {

        ctx_list->dbs = talloc_realloc(ctx_list, ctx_list->dbs,
                                       struct sysdb_ctx *,
                                       ctx_list->num_dbs + 1);
        if (!ctx_list->dbs) {
            talloc_zfree(ctx_list);
            return ENOMEM;
        }

        ret = sysdb_domain_init_internal(ctx_list, dom,
                                         ctx_list->db_path,
                                         allow_upgrade, &ctx);
        if (ret != EOK) {
            talloc_zfree(ctx_list);
            return ret;
        }

        ctx_list->dbs[ctx_list->num_dbs] = ctx;
        ctx_list->num_dbs++;
    }
    if (ctx_list->num_dbs == 0) {
        /* what? .. */
        talloc_zfree(ctx_list);
        return ENOENT;
    }

    *_ctx_list = ctx_list;

    return EOK;
}

int sysdb_domain_init(TALLOC_CTX *mem_ctx,
                      struct sss_domain_info *domain,
                      const char *db_path,
                      struct sysdb_ctx **_ctx)
{
    return sysdb_domain_init_internal(mem_ctx, domain,
                                      db_path, false, _ctx);
}

int sysdb_get_ctx_from_list(struct sysdb_ctx_list *ctx_list,
                            struct sss_domain_info *domain,
                            struct sysdb_ctx **ctx)
{
    int i;

    for (i = 0; i < ctx_list->num_dbs; i++) {
        if (ctx_list->dbs[i]->domain == domain) {
            *ctx = ctx_list->dbs[i];
            return EOK;
        }
        if (strcasecmp(ctx_list->dbs[i]->domain->name, domain->name) == 0) {
            *ctx = ctx_list->dbs[i];
            return EOK;
        }
    }
    /* definitely not found */
    return ENOENT;
}


int compare_ldb_dn_comp_num(const void *m1, const void *m2)
{
    struct ldb_message *msg1 = talloc_get_type(*(void **) discard_const(m1),
                                               struct ldb_message);
    struct ldb_message *msg2 = talloc_get_type(*(void **) discard_const(m2),
                                               struct ldb_message);

    return ldb_dn_get_comp_num(msg2->dn) - ldb_dn_get_comp_num(msg1->dn);
}

int sysdb_attrs_replace_name(struct sysdb_attrs *attrs, const char *oldname,
                             const char *newname)
{
    struct ldb_message_element *e = NULL;
    int i;
    const char *dummy;

    if (attrs == NULL || oldname == NULL || newname == NULL) return EINVAL;

    for (i = 0; i < attrs->num; i++) {
        if (strcasecmp(oldname, attrs->a[i].name) == 0) {
            e = &(attrs->a[i]);
        }
        if (strcasecmp(newname, attrs->a[i].name) == 0) {
            DEBUG(3, ("New attribute name [%s] already exists.\n", newname));
            return EEXIST;
        }
    }

    if (e != NULL) {
        dummy = talloc_strdup(attrs, newname);
        if (dummy == NULL) {
            DEBUG(1, ("talloc_strdup failed.\n"));
            return ENOMEM;
        }

        talloc_free(discard_const(e->name));
        e->name = dummy;
    }

    return EOK;
}

/* Search for all incidences of attr_name in a list of
 * sysdb_attrs and add their value to a list
 *
 * TODO: Currently only works for single-valued
 * attributes. Multi-valued attributes will return
 * only the first entry
 */
errno_t sysdb_attrs_to_list(TALLOC_CTX *memctx,
                            struct sysdb_attrs **attrs,
                            int attr_count,
                            const char *attr_name,
                            char ***_list)
{
    int attr_idx;
    int i;
    char **list;
    char **tmp_list;
    int list_idx;

    *_list = NULL;

    /* Assume that every attrs entry contains the attr_name
     * This may waste a little memory if some entries don't
     * have the attribute, but it will save us the trouble
     * of continuously resizing the array.
     */
    list = talloc_array(memctx, char *, attr_count+1);
    if (!list) {
        return ENOMEM;
    }

    list_idx = 0;
    /* Loop through all entries in attrs */
    for (attr_idx = 0; attr_idx < attr_count; attr_idx++) {
        /* Examine each attribute within the entry */
        for (i = 0; i < attrs[attr_idx]->num; i++) {
            if (strcasecmp(attrs[attr_idx]->a->name, attr_name) == 0) {
                /* Attribute name matches the requested name
                 * Copy it to the output list
                 */
                list[list_idx] = talloc_strdup(
                        list,
                        (const char *)attrs[attr_idx]->a->values[0].data);
                if (!list[list_idx]) {
                    talloc_free(list);
                    return ENOMEM;
                }
                list_idx++;

                /* We only support single-valued attributes
                 * Break here and go on to the next entry
                 */
                break;
            }
        }
    }

    list[list_idx] = NULL;

    /* if list_idx < attr_count, do a realloc to
     * reclaim unused memory
     */
    if (list_idx < attr_count) {
        tmp_list = talloc_realloc(memctx, list, char *, list_idx+1);
        if (!tmp_list) {
            talloc_zfree(list);
            return ENOMEM;
        }
        list = tmp_list;
    }

    *_list = list;
    return EOK;
}
