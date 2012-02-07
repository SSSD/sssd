/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2011 Red Hat

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

#define _XOPEN_SOURCE

#include <talloc.h>
#include <time.h>

#include "db/sysdb.h"
#include "db/sysdb_private.h"
#include "db/sysdb_sudo.h"

#define NULL_CHECK(val, rval, label) do { \
    if (!val) {                           \
        rval = ENOMEM;                    \
        goto label;                       \
    }                                     \
} while(0)

/* ====================  Utility functions ==================== */

static errno_t sysdb_sudo_check_time(struct sysdb_attrs *rule,
                                     time_t now,
                                     bool *result)
{
    TALLOC_CTX *tmp_ctx = NULL;
    const char **values = NULL;
    const char *name = NULL;
    char *tret = NULL;
    time_t notBefore = 0;
    time_t notAfter = 0;
    time_t converted;
    struct tm tm;
    errno_t ret;
    int i;

    if (!result) return EINVAL;
    *result = false;

    tmp_ctx = talloc_new(NULL);
    NULL_CHECK(tmp_ctx, ret, done);

    ret = sysdb_attrs_get_string(rule, SYSDB_SUDO_CACHE_AT_CN, &name);
    if (ret == ENOENT) {
        name = "<missing>";
    } else if(ret != EOK) {
        goto done;
    }

    /*
     * From man sudoers.ldap:
     *
     * A timestamp is in the form yyyymmddHHMMSSZ.
     * If multiple sudoNotBefore entries are present, the *earliest* is used.
     * If multiple sudoNotAfter entries are present, the *last one* is used.
     *
     * From sudo sources, ldap.c:
     * If either the sudoNotAfter or sudoNotBefore attributes are missing,
     * no time restriction shall be imposed.
     */

    /* check for sudoNotBefore */
    ret = sysdb_attrs_get_string_array(rule, SYSDB_SUDO_CACHE_AT_NOTBEFORE,
                                       tmp_ctx, &values);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_LIBS,
              ("notBefore attribute is missing, the rule [%s] is valid\n",
               name));
        *result = true;
        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        goto done;
    }

    for (i=0; values[i] ; i++) {
        tret = strptime(values[i], SYSDB_SUDO_TIME_FORMAT, &tm);
        if (tret == NULL || *tret != '\0') {
            DEBUG(SSSDBG_MINOR_FAILURE, ("Invalid time format in rule [%s]!\n",
                  name));
            ret = EINVAL;
            goto done;
        }
        converted = mktime(&tm);

        /* Grab the earliest */
        if (!notBefore) {
            notBefore = converted;
        } else if (notBefore > converted) {
            notBefore = converted;
        }
    }

    /* check for sudoNotAfter */
    ret = sysdb_attrs_get_string_array(rule, SYSDB_SUDO_CACHE_AT_NOTAFTER,
                                       tmp_ctx, &values);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_LIBS,
              ("notAfter attribute is missing, the rule [%s] is valid\n",
               name));
        *result = true;
        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        goto done;
    }

    for (i=0; values[i] ; i++) {
        tret = strptime(values[i], SYSDB_SUDO_TIME_FORMAT, &tm);
        if (tret == NULL || *tret != '\0') {
            DEBUG(SSSDBG_MINOR_FAILURE, ("Invalid time format in rule [%s]!\n",
                  name));
            ret = EINVAL;
            goto done;
        }
        converted = mktime(&tm);

        /* Grab the latest */
        if (!notAfter) {
            notAfter = converted;
        } else if (notAfter < converted) {
            notAfter = converted;
        }
    }

    if (now >= notBefore && now <= notAfter) {
        *result = true;
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_sudo_filter_rules_by_time(TALLOC_CTX *mem_ctx,
                                        size_t in_num_rules,
                                        struct sysdb_attrs **in_rules,
                                        time_t now,
                                        size_t *_num_rules,
                                        struct sysdb_attrs ***_rules)
{
    size_t num_rules = 0;
    struct sysdb_attrs **rules = NULL;
    TALLOC_CTX *tmp_ctx = NULL;
    bool allowed = false;
    errno_t ret;
    int i;

    tmp_ctx = talloc_new(NULL);
    NULL_CHECK(tmp_ctx, ret, done);

    if (now == 0) {
        now = time(NULL);
    }

    for (i = 0; i < in_num_rules; i++) {
        ret = sysdb_sudo_check_time(in_rules[i], now, &allowed);
        if (ret == EOK && allowed) {
            num_rules++;
            rules = talloc_realloc(tmp_ctx, rules, struct sysdb_attrs *,
                                   num_rules);
            NULL_CHECK(rules, ret, done);

            rules[num_rules - 1] = in_rules[i];
        }
    }

    *_num_rules = num_rules;
    *_rules = talloc_steal(mem_ctx, rules);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_get_sudo_filter(TALLOC_CTX *mem_ctx, const char *username,
                      uid_t uid, char **groupnames, unsigned int flags,
                      char **_filter)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *filter = NULL;
    char *specific_filter = NULL;
    errno_t ret;
    int i;

    tmp_ctx = talloc_new(NULL);
    NULL_CHECK(tmp_ctx, ret, done);

    /* build specific filter */

    specific_filter = talloc_zero(tmp_ctx, char); /* assign to tmp_ctx */
    NULL_CHECK(specific_filter, ret, done);

    if (flags & SYSDB_SUDO_FILTER_INCLUDE_ALL) {
        specific_filter = talloc_asprintf_append(specific_filter, "(%s=ALL)",
                                                 SYSDB_SUDO_CACHE_AT_USER);
        NULL_CHECK(specific_filter, ret, done);
    }

    if (flags & SYSDB_SUDO_FILTER_INCLUDE_DFL) {
        specific_filter = talloc_asprintf_append(specific_filter, "(%s=defaults)",
                                                 SYSDB_NAME);
        NULL_CHECK(specific_filter, ret, done);
    }

    if ((flags & SYSDB_SUDO_FILTER_USERNAME) && (username != NULL)) {
        specific_filter = talloc_asprintf_append(specific_filter, "(%s=%s)",
                                                 SYSDB_SUDO_CACHE_AT_USER,
                                                 username);
        NULL_CHECK(specific_filter, ret, done);
    }

    if ((flags & SYSDB_SUDO_FILTER_UID) && (uid != 0)) {
        specific_filter = talloc_asprintf_append(specific_filter, "(%s=#%llu)",
                                                 SYSDB_SUDO_CACHE_AT_USER,
                                                 (unsigned long long) uid);
        NULL_CHECK(specific_filter, ret, done);
    }

    if ((flags & SYSDB_SUDO_FILTER_GROUPS) && (groupnames != NULL)) {
        for (i=0; groupnames[i] != NULL; i++) {
            specific_filter = talloc_asprintf_append(specific_filter, "(%s=%%%s)",
                                                     SYSDB_SUDO_CACHE_AT_USER,
                                                     groupnames[i]);
            NULL_CHECK(specific_filter, ret, done);
        }
    }

    if (flags & SYSDB_SUDO_FILTER_NGRS) {
        specific_filter = talloc_asprintf_append(specific_filter, "(%s=+*)",
                                                 SYSDB_SUDO_CACHE_AT_USER);
        NULL_CHECK(specific_filter, ret, done);
    }

    /* build global filter */

    filter = talloc_asprintf(tmp_ctx, "(&(%s=%s)",
                             SYSDB_OBJECTCLASS, SYSDB_SUDO_CACHE_AT_OC);
    NULL_CHECK(filter, ret, done);

    if (specific_filter[0] != '\0') {
        filter = talloc_asprintf_append(filter, "(|%s)", specific_filter);
        NULL_CHECK(filter, ret, done);
    }

    filter = talloc_strdup_append(filter, ")");
    NULL_CHECK(filter, ret, done);

    ret = EOK;
    *_filter = talloc_steal(mem_ctx, filter);

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_get_sudo_user_info(TALLOC_CTX *mem_ctx, const char *username,
                         struct sysdb_ctx *sysdb, uid_t *_uid,
                         char ***groupnames)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    const char *attrs[3];
    struct ldb_message *msg;
    char **sysdb_groupnames = NULL;
    struct ldb_message_element *groups;
    uid_t uid;
    int i;

    tmp_ctx = talloc_new(NULL);
    NULL_CHECK(tmp_ctx, ret, done);

    attrs[0] = SYSDB_MEMBEROF;
    attrs[1] = SYSDB_UIDNUM;
    attrs[2] = NULL;
    ret = sysdb_search_user_by_name(tmp_ctx, sysdb, username,
                                    attrs, &msg);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Error looking up user %s\n", username));
        goto done;
    }

    uid = ldb_msg_find_attr_as_uint64(msg, SYSDB_UIDNUM, 0);
    if (!uid) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("A user with no UID?\n"));
        ret = EIO;
        goto done;
    }

    groups = ldb_msg_find_element(msg, SYSDB_MEMBEROF);
    if (!groups || groups->num_values == 0) {
        /* No groups for this user in sysdb currently */
        sysdb_groupnames = NULL;
    } else {
        sysdb_groupnames = talloc_array(tmp_ctx, char *, groups->num_values+1);
        NULL_CHECK(sysdb_groupnames, ret, done);

        /* Get a list of the groups by groupname only */
        for (i = 0; i < groups->num_values; i++) {
            ret = sysdb_group_dn_name(sysdb,
                                      sysdb_groupnames,
                                      (const char *)groups->values[i].data,
                                      &sysdb_groupnames[i]);
            if (ret != EOK) {
                ret = ENOMEM;
                goto done;
            }
        }
        sysdb_groupnames[groups->num_values] = NULL;
    }

    ret = EOK;
    *_uid = uid;
    *groupnames = talloc_steal(mem_ctx, sysdb_groupnames);
done:
    talloc_free(tmp_ctx);
    return EOK;
}

errno_t
sysdb_save_sudorule(struct sysdb_ctx *sysdb_ctx,
                   const char *rule_name,
                   struct sysdb_attrs *attrs)
{
    errno_t ret;

    DEBUG(SSSDBG_TRACE_FUNC, ("Adding sudo rule %s\n", rule_name));

    ret = sysdb_attrs_add_string(attrs, SYSDB_OBJECTCLASS,
                                 SYSDB_SUDO_CACHE_AT_OC);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not set rule object class [%d]: %s\n",
              ret, strerror(ret)));
        return ret;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_NAME, rule_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not set name attribute [%d]: %s\n",
              ret, strerror(ret)));
        return ret;
    }

    ret = sysdb_store_custom(sysdb_ctx, rule_name, SUDORULE_SUBDIR, attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("sysdb_store_custom failed [%d]: %s\n",
              ret, strerror(ret)));
        return ret;
    }

    return EOK;
}

errno_t sysdb_sudo_set_refreshed(struct sysdb_ctx *sysdb,
                                 bool refreshed)
{
    errno_t ret;
    struct ldb_dn *dn;
    TALLOC_CTX *tmp_ctx;


    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        ret = ENOMEM;
        goto done;
    }

    dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb, SYSDB_TMPL_CUSTOM_SUBTREE,
                        SUDORULE_SUBDIR, sysdb->domain->name);
    if (!dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_set_bool(sysdb, dn, SUDORULE_SUBDIR,
                         SYSDB_SUDO_AT_REFRESHED, refreshed);

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_sudo_get_refreshed(struct sysdb_ctx *sysdb,
                                 bool *refreshed)
{
    errno_t ret;
    struct ldb_dn *dn;
    TALLOC_CTX *tmp_ctx;


    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        ret = ENOMEM;
        goto done;
    }

    dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb, SYSDB_TMPL_CUSTOM_SUBTREE,
                        SUDORULE_SUBDIR, sysdb->domain->name);
    if (!dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_get_bool(sysdb, dn, SYSDB_SUDO_AT_REFRESHED, refreshed);

done:
    talloc_free(tmp_ctx);
    return ret;
}

char **sysdb_sudo_build_sudouser(TALLOC_CTX *mem_ctx, const char *username,
                                 uid_t uid, char **groupnames, bool include_all)
{
    char **sudouser = NULL;
    int count = 0;
    errno_t ret;
    int i;

    if (username == NULL || uid == 0) {
        return NULL;
    }

    count = include_all ? 3 : 2;
    sudouser = talloc_array(NULL, char*, count + 1);
    NULL_CHECK(sudouser, ret, done);

    sudouser[0] = talloc_strdup(sudouser, username);
    NULL_CHECK(sudouser[0], ret, done);

    sudouser[1] = talloc_asprintf(sudouser, "#%llu", (unsigned long long)uid);
    NULL_CHECK(sudouser[1], ret, done);

    if (include_all) {
        sudouser[2] = talloc_strdup(sudouser, "ALL");
        NULL_CHECK(sudouser[2], ret, done);
    }

    if (groupnames != NULL) {
        for (i = 0; groupnames[i] != NULL; i++) {
            count++;
            sudouser = talloc_realloc(NULL, sudouser, char*, count + 1);
            NULL_CHECK(sudouser, ret, done);

            sudouser[count - 1] = talloc_asprintf(sudouser, "%s", groupnames[i]);
            NULL_CHECK(sudouser[count - 1], ret, done);
        }
    }

    sudouser[count] = NULL;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(sudouser);
        return NULL;
    }

    return talloc_steal(mem_ctx, sudouser);
}

/* ====================  Purge functions ==================== */

errno_t sysdb_sudo_purge_all(struct sysdb_ctx *sysdb)
{
    struct ldb_dn *base_dn = NULL;
    TALLOC_CTX *tmp_ctx = NULL;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    NULL_CHECK(tmp_ctx, ret, done);

    base_dn = sysdb_custom_subtree_dn(sysdb, tmp_ctx, sysdb->domain->name,
                                      SUDORULE_SUBDIR);
    NULL_CHECK(base_dn, ret, done);

    ret = sysdb_delete_recursive(sysdb, base_dn, true);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("sysdb_delete_recursive failed.\n"));
        goto done;
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return EOK;
}

errno_t sysdb_sudo_purge_byname(struct sysdb_ctx *sysdb,
                                const char *name)
{
    DEBUG(SSSDBG_TRACE_INTERNAL, ("Deleting sudo rule %s\n", name));
    return sysdb_delete_custom(sysdb, name, SUDORULE_SUBDIR);
}

errno_t sysdb_sudo_purge_byfilter(struct sysdb_ctx *sysdb,
                                  const char *filter)
{
    TALLOC_CTX *tmp_ctx;
    size_t count;
    struct ldb_message **msgs;
    const char *name;
    int i;
    errno_t ret;
    errno_t sret;
    bool in_transaction = false;
    const char *attrs[] = { SYSDB_OBJECTCLASS,
                            SYSDB_NAME,
                            SYSDB_SUDO_CACHE_AT_OC,
                            SYSDB_SUDO_CACHE_AT_CN,
                            NULL };

    /* just purge all if there's no filter */
    if (!filter) {
        return sysdb_sudo_purge_all(sysdb);
    }

    tmp_ctx = talloc_new(NULL);
    NULL_CHECK(tmp_ctx, ret, done);

    /* match entries based on the filter and remove them one by one */
    ret = sysdb_search_custom(tmp_ctx, sysdb, filter,
                              SUDORULE_SUBDIR, attrs,
                              &count, &msgs);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, ("No rules matched\n"));
        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Error looking up SUDO rules"));
        goto done;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        goto done;
    }
    in_transaction = true;

    for (i = 0; i < count; i++) {
        name = ldb_msg_find_attr_as_string(msgs[i], SYSDB_NAME, NULL);
        if (name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, ("A rule without a name?\n"));
            /* skip this one but still delete other entries */
            continue;
        }

        ret = sysdb_sudo_purge_byname(sysdb, name);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("Could not delete rule %s\n", name));
            goto done;
        }
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret == EOK) {
        in_transaction = false;
    }

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("Could not cancel transaction\n"));
        }
    }

    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_sudo_purge_bysudouser(struct sysdb_ctx *sysdb,
                                    char **sudouser)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *filter = NULL;
    char *value = NULL;
    const char *rule_name = NULL;
    struct ldb_message_element *attr = NULL;
    struct ldb_message *msg = NULL;
    struct ldb_message **rules = NULL;
    size_t num_rules;
    errno_t ret;
    errno_t sret;
    int lret;
    int i, j, k;
    bool in_transaction = false;
    const char *attrs[] = { SYSDB_OBJECTCLASS,
                            SYSDB_NAME,
                            SYSDB_SUDO_CACHE_AT_USER,
                            NULL };

    if (sudouser == NULL || sudouser[0] == NULL) {
        return EOK;
    }

    tmp_ctx = talloc_new(NULL);
    NULL_CHECK(tmp_ctx, ret, done);

    /* create search filter */
    filter = talloc_strdup(tmp_ctx, "(|");
    NULL_CHECK(filter, ret, done);
    for (i = 0; sudouser[i] != NULL; i++) {
        filter = talloc_asprintf_append(filter, "(%s=%s)",
                                        SYSDB_SUDO_CACHE_AT_USER, sudouser[i]);
        NULL_CHECK(filter, ret, done);
    }
    filter = talloc_strdup_append(filter, ")");
    NULL_CHECK(filter, ret, done);

    /* search the rules */
    ret = sysdb_search_custom(tmp_ctx, sysdb, filter, SUDORULE_SUBDIR, attrs,
                              &num_rules, &rules);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Error looking up SUDO rules"));
        goto done;
    } if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, ("No rules matched\n"));
        ret = EOK;
        goto done;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        goto done;
    }
    in_transaction = true;

    /*
     * remove values from sudoUser and delete the rule
     * if the attribute is empty afterwards
     */

    for (i = 0; i < num_rules; i++) {
        /* find name */
        rule_name = ldb_msg_find_attr_as_string(rules[i], SYSDB_NAME, NULL);
        if (rule_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, ("A rule without a name?\n"));
            /* skip this one but still delete other entries */
            continue;
        }

        /* find sudoUser */
        attr = ldb_msg_find_element(rules[i], SYSDB_SUDO_CACHE_AT_USER);
        if (attr == NULL) {
            /* this should never happen because we search by this attribute */
            DEBUG(SSSDBG_CRIT_FAILURE, ("BUG: sudoUser attribute is missing\n"));
            continue;
        }

        /* create message */
        msg = ldb_msg_new(tmp_ctx);
        NULL_CHECK(msg, ret, done);

        msg->dn = ldb_dn_new_fmt(msg, sysdb->ldb, SYSDB_TMPL_CUSTOM, rule_name,
                                 SUDORULE_SUBDIR, sysdb->domain->name);
        NULL_CHECK(msg->dn, ret, done);

        /* create empty sudoUser */
        lret = ldb_msg_add_empty(msg, SYSDB_SUDO_CACHE_AT_USER,
                                 LDB_FLAG_MOD_DELETE, NULL);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        /* filter values */
        for (j = 0; j < attr->num_values; j++) {
            value = (char*)(attr->values[j].data);
            for (k = 0; sudouser[k] != NULL; k++) {
                if (strcmp(value, sudouser[k]) == 0) {
                    /* delete value from cache */
                    lret = ldb_msg_add_string(msg, SYSDB_SUDO_CACHE_AT_USER,
                                              sudouser[k]);
                    if (lret != LDB_SUCCESS) {
                        ret = sysdb_error_to_errno(lret);
                        goto done;
                    }
                    break;
                }
            }
        }

        /* update the cache */
        if (msg->elements[0].num_values == attr->num_values) {
            /* sudoUser would remain empty, delete the rule */
            ret = sysdb_sudo_purge_byname(sysdb, rule_name);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, ("Could not delete rule %s\n",
                      rule_name));
                goto done;
            }
        } else {
            /* sudoUser will not be empty, modify the rule */
            DEBUG(SSSDBG_TRACE_INTERNAL, ("Modifying sudoUser of rule %s\n",
                  rule_name));
            lret = ldb_modify(sysdb->ldb, msg);
            if (lret != LDB_SUCCESS) {
                DEBUG(SSSDBG_OP_FAILURE, ("Could not modify rule %s\n",
                      rule_name));
                ret = sysdb_error_to_errno(lret);
                goto done;
            }
        }

        talloc_free(msg);
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret == EOK) {
        in_transaction = false;
    }

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("Could not cancel transaction\n"));
        }
    }

    talloc_free(tmp_ctx);
    return ret;
}

