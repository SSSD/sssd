/*
   SSSD

   System Database - SELinux support

   Copyright (C) Jan Zeleny <jzeleny@redhat.com>	2012

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

#include "db/sysdb_selinux.h"
#include "db/sysdb_private.h"

/* Some generic routines */
enum selinux_entity_type {
    SELINUX_CONFIG,
    SELINUX_USER_MAP
};

static errno_t
sysdb_add_selinux_entity(struct sysdb_ctx *sysdb,
                         struct ldb_dn *dn,
                         const char *objectclass,
                         struct sysdb_attrs *attrs,
                         time_t now)
{
    struct ldb_message *msg;
    TALLOC_CTX *tmp_ctx;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_OBJECTCLASS, objectclass);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not set map object class [%d]: %s\n",
              ret, strerror(ret));
        return ret;
    }

    if (!now) {
        now = time(NULL);
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_CREATE_TIME, now);
    if (ret) goto done;

    msg->dn = dn;
    msg->elements = attrs->a;
    msg->num_elements = attrs->num;

    ret = ldb_add(sysdb->ldb, msg);
    ret = sysdb_error_to_errno(ret);

done:
    if (ret) {
        DEBUG(SSSDBG_TRACE_LIBS, "Error: %d (%s)\n", ret, strerror(ret));
    }
    talloc_zfree(tmp_ctx);
    return ret;
}

static errno_t sysdb_store_selinux_entity(struct sss_domain_info *domain,
                                          struct sysdb_attrs *attrs,
                                          enum selinux_entity_type type)
{
    TALLOC_CTX *tmp_ctx;
    bool in_transaction = false;
    const char *objectclass = NULL;
    const char *name;
    char *clean_name;
    struct ldb_dn *dn = NULL;
    errno_t sret = EOK;
    errno_t ret;
    time_t now;
    struct sysdb_ctx *sysdb = domain->sysdb;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    switch (type) {
        case SELINUX_USER_MAP:
            objectclass = SYSDB_SELINUX_USERMAP_CLASS;
            ret = sysdb_attrs_get_string(attrs, SYSDB_NAME, &name);
            if (ret != EOK) {
                goto done;
            }

            ret = sysdb_dn_sanitize(tmp_ctx, name, &clean_name);
            if (ret != EOK) {
                goto done;
            }

            dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb, SYSDB_TMPL_SEUSERMAP,
                                clean_name, domain->name);
            break;
        case SELINUX_CONFIG:
            objectclass = SYSDB_SELINUX_CLASS;
            dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb, SYSDB_TMPL_SELINUX_BASE,
                                domain->name);
            break;
    }

    if (type != SELINUX_CONFIG && type != SELINUX_USER_MAP) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bad SELinux entity type: [%d]\n", type);
        ret = EINVAL;
        goto done;
    }

    if (!dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto done;
    }

    in_transaction = true;

    now = time(NULL);
    ret = sysdb_attrs_add_time_t(attrs, SYSDB_LAST_UPDATE, now);
    if (ret) goto done;

    ret = sysdb_add_selinux_entity(sysdb, dn, objectclass, attrs, now);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_set_entry_attr(sysdb, dn, attrs, SYSDB_MOD_REP);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction\n");
        goto done;
    }
    in_transaction = false;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not cancel transaction\n");
        }
    }

    if (ret) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
    }
    talloc_zfree(tmp_ctx);
    return ret;
}

errno_t sysdb_store_selinux_usermap(struct sss_domain_info *domain,
                                    struct sysdb_attrs *attrs)
{
    return sysdb_store_selinux_entity(domain, attrs, SELINUX_USER_MAP);
}

errno_t sysdb_store_selinux_config(struct sss_domain_info *domain,
                                   const char *default_user,
                                   const char *order)
{
    errno_t ret;
    struct sysdb_attrs *attrs;

    if (order == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "The SELinux order is missing\n");
        return EINVAL;
    }

    attrs = talloc_zero(NULL, struct sysdb_attrs);
    if (attrs == NULL) {
        return ENOMEM;
    }

    if (default_user) {
        ret = sysdb_attrs_add_string(attrs, SYSDB_SELINUX_DEFAULT_USER,
                                    default_user);
        if (ret != EOK) {
            goto done;
        }
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_SELINUX_DEFAULT_ORDER,
                                 order);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_store_selinux_entity(domain, attrs, SELINUX_CONFIG);
done:
    talloc_free(attrs);
    return ret;
}

errno_t sysdb_delete_usermaps(struct sss_domain_info *domain)
{
    struct ldb_dn *dn = NULL;
    errno_t ret;
    struct sysdb_ctx *sysdb = domain->sysdb;

    dn = ldb_dn_new_fmt(sysdb, sysdb->ldb,
                        SYSDB_TMPL_SELINUX_BASE, domain->name);
    if (!dn) return ENOMEM;

    ret = sysdb_delete_recursive(sysdb, dn, true);
    talloc_free(dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_delete_recursive failed.\n");
        return ret;
    }

    return EOK;
}

/* --- SYSDB SELinux search routines --- */
errno_t
sysdb_get_selinux_usermaps(TALLOC_CTX *mem_ctx,
                           struct sss_domain_info *domain,
                           const char **attrs,
                           size_t *count,
                           struct ldb_message ***messages)
{
    errno_t ret;
    char *filter;
    struct ldb_dn *basedn;
    struct sysdb_ctx *sysdb = domain->sysdb;

    basedn = ldb_dn_new_fmt(mem_ctx, sysdb_ctx_get_ldb(sysdb),
                            SYSDB_TMPL_SELINUX_BASE, domain->name);
    if (!basedn) {
        return ENOMEM;
    }

    filter = talloc_asprintf(mem_ctx, "(%s=%s)",
                             SYSDB_OBJECTCLASS, SYSDB_SELINUX_USERMAP_CLASS);
    if (filter == NULL) {
        talloc_free(basedn);
        return ENOMEM;
    }

    ret = sysdb_search_entry(mem_ctx, sysdb, basedn, LDB_SCOPE_SUBTREE, filter,
                             attrs, count, messages);
    talloc_free(basedn);
    talloc_free(filter);
    if (ret == ENOENT) {
        *count = 0;
        *messages = NULL;
    } else if (ret) {
        return ret;
    }

    return EOK;
}

errno_t sysdb_search_selinux_config(TALLOC_CTX *mem_ctx,
                                    struct sss_domain_info *domain,
                                    const char **attrs,
                                    struct ldb_message **_config)
{
    TALLOC_CTX *tmp_ctx;
    const char *def_attrs[] = { SYSDB_SELINUX_DEFAULT_USER,
                                SYSDB_SELINUX_DEFAULT_ORDER,
                                NULL };
    struct ldb_message **msgs;
    size_t msgs_count;
    struct ldb_dn *basedn;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    basedn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                            SYSDB_TMPL_SELINUX_BASE, domain->name);
    if (!basedn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_entry(tmp_ctx, domain->sysdb, basedn, LDB_SCOPE_BASE,
                             NULL, attrs?attrs:def_attrs, &msgs_count, &msgs);
    if (ret) {
        goto done;
    }

    *_config = talloc_steal(mem_ctx, msgs[0]);

done:
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, "No SELinux root entry found\n");
    } else if (ret) {
        DEBUG(SSSDBG_TRACE_FUNC, "Error: %d (%s)\n", ret, strerror(ret));
    }

    talloc_free(tmp_ctx);
    return ret;
}

