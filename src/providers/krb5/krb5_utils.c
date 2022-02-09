/*
    SSSD

    Kerberos 5 Backend Module -- Utilities

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2009 Red Hat

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
#include <string.h>
#include <stdlib.h>
#include <libgen.h>

#include "providers/krb5/krb5_utils.h"
#include "providers/krb5/krb5_ccache.h"
#include "providers/krb5/krb5_auth.h"
#include "src/util/find_uid.h"
#include "util/util.h"

errno_t find_or_guess_upn(TALLOC_CTX *mem_ctx, struct ldb_message *msg,
                          struct krb5_ctx *krb5_ctx,
                          struct sss_domain_info *dom, const char *user,
                          const char *user_dom, char **_upn)
{
    const char *upn = NULL;
    int ret;

    if (krb5_ctx == NULL || dom == NULL || user == NULL || _upn == NULL) {
        return EINVAL;
    }

    if (msg != NULL) {
        upn = ldb_msg_find_attr_as_string(msg, SYSDB_CANONICAL_UPN, NULL);
        if (upn != NULL) {
            ret = EOK;
            goto done;
        }

        upn = ldb_msg_find_attr_as_string(msg, SYSDB_UPN, NULL);
        if (upn != NULL) {
            ret = EOK;
            goto done;
        }
    }

    ret = krb5_get_simple_upn(mem_ctx, krb5_ctx, dom, user,
                              user_dom, _upn);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "krb5_get_simple_upn failed.\n");
        return ret;
    }

done:
    if (ret == EOK && upn != NULL) {
        *_upn = talloc_strdup(mem_ctx, upn);
        if (*_upn == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            return ENOMEM;
        }
    }

    return ret;
}

errno_t check_if_cached_upn_needs_update(struct sysdb_ctx *sysdb,
                                         struct sss_domain_info *domain,
                                         const char *user,
                                         const char *upn)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    int sret;
    const char *attrs[] = {SYSDB_UPN, SYSDB_CANONICAL_UPN, NULL};
    struct sysdb_attrs *new_attrs;
    struct ldb_result *res;
    bool in_transaction = false;
    const char *cached_upn;
    const char *cached_canonical_upn;

    if (sysdb == NULL || user == NULL || upn == NULL) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    ret = sysdb_get_user_attr(tmp_ctx, domain, user, attrs, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_get_user_attr failed.\n");
        goto done;
    }

    if (res->count != 1) {
        DEBUG(SSSDBG_OP_FAILURE, "[%d] user objects for name [%s] found, " \
                                  "expected 1.\n", res->count, user);
        ret = EINVAL;
        goto done;
    }

    cached_upn = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_UPN, NULL);

    if (cached_upn != NULL && strcmp(cached_upn, upn) == 0) {
        DEBUG(SSSDBG_TRACE_ALL, "Cached UPN and new one match, "
                                 "nothing to do.\n");
        ret = EOK;
        goto done;
    }

    cached_canonical_upn = ldb_msg_find_attr_as_string(res->msgs[0],
                                                       SYSDB_CANONICAL_UPN,
                                                       NULL);

    if (cached_canonical_upn != NULL
            && strcmp(cached_canonical_upn, upn) == 0) {
        DEBUG(SSSDBG_TRACE_ALL, "Cached canonical UPN and new one match, "
                                 "nothing to do.\n");
        ret = EOK;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "Replacing canonical UPN [%s] with [%s] " \
                              "for user [%s].\n",
                              cached_canonical_upn == NULL ?
                                                 "empty" : cached_canonical_upn,
                              upn, user);

    new_attrs = sysdb_new_attrs(tmp_ctx);
    if (new_attrs == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_new_attrs failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_add_string(new_attrs, SYSDB_CANONICAL_UPN, upn);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_add_string failed.\n");
        goto done;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Error %d starting transaction (%s)\n", ret, strerror(ret));
        goto done;
    }
    in_transaction = true;

    ret = sysdb_set_entry_attr(sysdb, res->msgs[0]->dn, new_attrs,
                               cached_canonical_upn == NULL ? SYSDB_MOD_ADD :
                                                              SYSDB_MOD_REP);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_set_entry_attr failed [%d][%s].\n",
                                  ret, strerror(ret));
        goto done;
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to commit transaction!\n");
        goto done;
    }
    in_transaction = false;

    ret = EOK;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to cancel transaction\n");
        }
    }

    talloc_free(tmp_ctx);

    return ret;
}

#define S_EXP_UID "{uid}"
#define L_EXP_UID (sizeof(S_EXP_UID) - 1)
#define S_EXP_USERID "{USERID}"
#define L_EXP_USERID (sizeof(S_EXP_USERID) - 1)
#define S_EXP_EUID "{euid}"
#define L_EXP_EUID (sizeof(S_EXP_EUID) - 1)
#define S_EXP_USERNAME "{username}"
#define L_EXP_USERNAME (sizeof(S_EXP_USERNAME) - 1)

static errno_t
check_ccache_re(const char *filename, sss_regexp_t *illegal_re)
{
    errno_t ret;

    ret = sss_regexp_match(illegal_re, filename, 0, 0);

    if (ret == 0) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Illegal pattern in ccache directory name [%s].\n", filename);
        return EINVAL;
    } else if (ret == SSS_REGEXP_ERROR_NOMATCH) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "Ccache directory name [%s] does not contain "
               "illegal patterns.\n", filename);
        return EOK;
    }

    DEBUG(SSSDBG_CRIT_FAILURE, "regexp match failed [%d].\n", ret);
    return EFAULT;
}

char *expand_ccname_template(TALLOC_CTX *mem_ctx, struct krb5child_req *kr,
                             const char *template, sss_regexp_t *illegal_re,
                             bool file_mode, bool case_sensitive)
{
    char *copy;
    char *p;
    char *n;
    char *result = NULL;
    char *dummy;
    char *name;
    char *res = NULL;
    const char *cache_dir_tmpl;
    TALLOC_CTX *tmp_ctx = NULL;
    char action;
    bool rerun;
    int ret;

    if (template == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing template.\n");
        return NULL;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return NULL;

    copy = talloc_strdup(tmp_ctx, template);
    if (copy == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup failed.\n");
        goto done;
    }

    result = talloc_strdup(tmp_ctx, "");
    if (result == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup failed.\n");
        goto done;
    }

    p = copy;
    while ( (n = strchr(p, '%')) != NULL) {
        *n = '\0';
        n++;
        if ( *n == '\0' ) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "format error, single %% at the end of the template.\n");
            goto done;
        }

        rerun = true;
        action = *n;
        while (rerun) {
            rerun = false;
            switch (action) {
            case 'u':
                if (kr->pd->user == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Cannot expand user name template "
                          "because user name is empty.\n");
                    goto done;
                }

                name = sss_output_name(tmp_ctx, kr->pd->user, case_sensitive, 0);
                if (name == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "sss_output_name failed\n");
                    goto done;
                }

                result = talloc_asprintf_append(result, "%s%s", p,
                                                name);
                break;
            case 'U':
                if (kr->uid <= 0) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "Cannot expand uid template "
                              "because uid is invalid.\n");
                    goto done;
                }
                result = talloc_asprintf_append(result, "%s%"SPRIuid, p,
                                                kr->uid);
                break;
            case 'p':
                if (kr->upn == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Cannot expand user principal name template "
                              "because upn is empty.\n");
                    goto done;
                }
                result = talloc_asprintf_append(result, "%s%s", p, kr->upn);
                break;
            case '%':
                result = talloc_asprintf_append(result, "%s%%", p);
                break;
            case 'r':
                dummy = dp_opt_get_string(kr->krb5_ctx->opts, KRB5_REALM);
                if (dummy == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "Missing kerberos realm.\n");
                    goto done;
                }
                result = talloc_asprintf_append(result, "%s%s", p, dummy);
                break;
            case 'h':
                if (kr->homedir == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Cannot expand home directory template "
                              "because the path is not available.\n");
                    goto done;
                }
                result = talloc_asprintf_append(result, "%s%s", p, kr->homedir);
                break;
            case 'd':
                if (file_mode) {
                    cache_dir_tmpl = dp_opt_get_string(kr->krb5_ctx->opts,
                                                       KRB5_CCACHEDIR);
                    if (cache_dir_tmpl == NULL) {
                        DEBUG(SSSDBG_CRIT_FAILURE,
                              "Missing credential cache directory.\n");
                        goto done;
                    }

                    dummy = expand_ccname_template(tmp_ctx, kr, cache_dir_tmpl,
                                                   illegal_re, false, case_sensitive);
                    if (dummy == NULL) {
                        DEBUG(SSSDBG_CRIT_FAILURE,
                              "Expanding credential cache directory "
                                  "template failed.\n");
                        goto done;
                    }
                    result = talloc_asprintf_append(result, "%s%s", p, dummy);
                    talloc_zfree(dummy);
                } else {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "'%%d' is not allowed in this template.\n");
                    goto done;
                }
                break;
            case 'P':
                if (!file_mode) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "'%%P' is not allowed in this template.\n");
                    goto done;
                }
                if (kr->pd->cli_pid == 0) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "Cannot expand PID template "
                              "because PID is not available.\n");
                    goto done;
                }
                result = talloc_asprintf_append(result, "%s%d", p,
                                                kr->pd->cli_pid);
                break;

            /* Additional syntax from krb5.conf default_ccache_name */
            case '{':
                if (strncmp(n , S_EXP_UID, L_EXP_UID) == 0) {
                    action = 'U';
                    n += L_EXP_UID - 1;
                    rerun = true;
                    continue;
                } else if (strncmp(n , S_EXP_USERID, L_EXP_USERID) == 0) {
                    action = 'U';
                    n += L_EXP_USERID - 1;
                    rerun = true;
                    continue;
                } else if (strncmp(n , S_EXP_EUID, L_EXP_EUID) == 0) {
                    /* SSSD does not distinguish between uid and euid,
                     * so we treat both the same way */
                    action = 'U';
                    n += L_EXP_EUID - 1;
                    rerun = true;
                    continue;
                } else if (strncmp(n , S_EXP_USERNAME, L_EXP_USERNAME) == 0) {
                    action = 'u';
                    n += L_EXP_USERNAME - 1;
                    rerun = true;
                    continue;
                } else {
                    /* ignore any expansion variable we do not understand and
                     * let libkrb5 hndle it or fail */
                    name = n;
                    n = strchr(name, '}');
                    if (!n) {
                        DEBUG(SSSDBG_CRIT_FAILURE,
                              "Invalid substitution sequence in cache "
                              "template. Missing closing '}' in [%s].\n",
                              template);
                        goto done;
                    }
                    result = talloc_asprintf_append(result, "%s%%%.*s", p,
                                                    (int)(n - name + 1), name);
                }
                break;
            default:
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "format error, unknown template [%%%c].\n", *n);
                goto done;
            }
        }

        if (result == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf_append failed.\n");
            goto done;
        }

        p = n + 1;
    }

    result = talloc_asprintf_append(result, "%s", p);
    if (result == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf_append failed.\n");
        goto done;
    }

    if (illegal_re != NULL) {
        ret = check_ccache_re(result, illegal_re);
        if (ret != EOK) {
            goto done;
        }
    }

    res = talloc_move(mem_ctx, &result);
done:
    talloc_zfree(tmp_ctx);
    return res;
}

errno_t get_domain_or_subdomain(struct be_ctx *be_ctx,
                                char *domain_name,
                                struct sss_domain_info **dom)
{

    if (domain_name != NULL &&
        strcasecmp(domain_name, be_ctx->domain->name) != 0) {
        *dom = find_domain_by_name(be_ctx->domain, domain_name, true);
        if (*dom == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "find_domain_by_name failed.\n");
            return ENOMEM;
        }
    } else {
        *dom = be_ctx->domain;
    }

    return EOK;
}

static errno_t split_tuple(TALLOC_CTX *mem_ctx, const char *tuple,
                           const char **_first, const char **_second)
{
    errno_t ret;
    char **list;
    int n;

    ret = split_on_separator(mem_ctx, tuple, ':', true, true, &list, &n);

    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "split_on_separator failed - %s:[%d]\n",
              sss_strerror(ret), ret);
        goto done;
    } else if (n != 2) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "split_on_separator failed - Expected format is: "
              "'username:primary' but got: '%s'.\n", tuple);
        ret = EINVAL;
        goto done;
    }

    *_first = list[0];
    *_second = list[1];

done:
    return ret;
}

static errno_t
fill_name_to_primary_map(TALLOC_CTX *mem_ctx, char **map,
                         struct map_id_name_to_krb_primary *name_to_primary,
                         size_t size)
{
    int i;
    errno_t ret;

    for (i = 0; i < size; i++) {
        ret = split_tuple(mem_ctx, map[i],
                          &name_to_primary[i].id_name,
                          &name_to_primary[i].krb_primary);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "split_tuple failed - %s:[%d]\n", sss_strerror(ret), ret);
            goto done;
        }
    }

    ret = EOK;

done:
    return ret;
}

errno_t
parse_krb5_map_user(TALLOC_CTX *mem_ctx,
                    const char *krb5_map_user,
                    const char *dom_name,
                    struct map_id_name_to_krb_primary **_name_to_primary)
{
    int size;
    char **map = NULL;
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    struct map_id_name_to_krb_primary *name_to_primary;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (krb5_map_user == NULL || strlen(krb5_map_user) == 0) {
        DEBUG(SSSDBG_CONF_SETTINGS, "krb5_map_user is empty!\n");
        size = 0;
    } else {
        ret = split_on_separator(tmp_ctx, krb5_map_user, ',', true, true,
                                 &map, &size);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to parse krb5_map_user!\n");
            goto done;
        }
    }

    name_to_primary = talloc_zero_array(tmp_ctx,
                                        struct map_id_name_to_krb_primary,
                                        size + 1);
    if (name_to_primary == NULL) {
        ret = ENOMEM;
        goto done;
    }
    /* sentinel */
    name_to_primary[size].id_name = NULL;
    name_to_primary[size].krb_primary = NULL;

    if (size > 0) {
        ret = fill_name_to_primary_map(name_to_primary, map, name_to_primary,
                                       size);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "fill_name_to_primary_map failed: %s:[%d]\n",
                  sss_strerror(ret), ret);
            goto done;
        }
    }

    /* conversion names to fully-qualified names */
    for (int i = 0; i < size; i++) {
        name_to_primary[i].id_name = sss_create_internal_fqname(
                                                     name_to_primary,
                                                     name_to_primary[i].id_name,
                                                     dom_name);
        if (name_to_primary[i].id_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "sss_create_internal_fqname failed\n");
            ret = ENOMEM;
            goto done;
        }

        name_to_primary[i].krb_primary = sss_create_internal_fqname(
                                                 name_to_primary,
                                                 name_to_primary[i].krb_primary,
                                                 dom_name);
        if (name_to_primary[i].krb_primary == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "sss_create_internal_fqname failed\n");
            ret = ENOMEM;
            goto done;
        }
    }
    ret = EOK;

done:
    if (ret == EOK) {
        *_name_to_primary = talloc_steal(mem_ctx, name_to_primary);
    }
    talloc_free(tmp_ctx);
    return ret;
}
