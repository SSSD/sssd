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

char *expand_ccname_template(TALLOC_CTX *mem_ctx, struct krb5child_req *kr,
                             const char *template, bool file_mode,
                             bool case_sensitive)
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
                name = sss_get_cased_name(tmp_ctx, kr->pd->user,
                                          case_sensitive);
                if (!name) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "sss_get_cased_name failed\n");
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
                                                   false, case_sensitive);
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
                    /* SSSD does not distinguish betwen uid and euid,
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

    res = talloc_move(mem_ctx, &result);
done:
    talloc_zfree(tmp_ctx);
    return res;
}

static errno_t check_parent_stat(struct stat *parent_stat, uid_t uid)
{
    if (parent_stat->st_uid != 0 && parent_stat->st_uid != uid) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Private directory can only be created below a directory "
              "belonging to root or to [%"SPRIuid"].\n", uid);
        return EINVAL;
    }

    if (parent_stat->st_uid == uid) {
        if (!(parent_stat->st_mode & S_IXUSR)) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Parent directory does not have the search bit set for "
                   "the owner.\n");
            return EINVAL;
        }
    } else {
        if (!(parent_stat->st_mode & S_IXOTH)) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Parent directory does not have the search bit set for "
                   "others.\n");
            return EINVAL;
        }
    }

    return EOK;
}

struct string_list {
    struct string_list *next;
    struct string_list *prev;
    char *s;
};

static errno_t find_ccdir_parent_data(TALLOC_CTX *mem_ctx,
                                      const char *ccdirname,
                                      struct stat *parent_stat,
                                      struct string_list **missing_parents)
{
    int ret = EFAULT;
    char *parent = NULL;
    char *end;
    struct string_list *li;

    ret = stat(ccdirname, parent_stat);
    if (ret == EOK) {
        if ( !S_ISDIR(parent_stat->st_mode) ) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "[%s] is not a directory.\n", ccdirname);
            return EINVAL;
        }
        return EOK;
    } else {
        if (errno != ENOENT) {
            ret = errno;
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "stat for [%s] failed: [%d][%s].\n", ccdirname, ret,
                   strerror(ret));
            return ret;
        }
    }

    li = talloc_zero(mem_ctx, struct string_list);
    if (li == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "talloc_zero failed.\n");
        return ENOMEM;
    }

    li->s = talloc_strdup(li, ccdirname);
    if (li->s == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "talloc_strdup failed.\n");
        return ENOMEM;
    }

    DLIST_ADD(*missing_parents, li);

    parent = talloc_strdup(mem_ctx, ccdirname);
    if (parent == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "talloc_strdup failed.\n");
        return ENOMEM;
    }

    /* We'll remove all trailing slashes from the back so that
     * we only pass /some/path to find_ccdir_parent_data, not
     * /some/path */
    do {
        end = strrchr(parent, '/');
        if (end == NULL || end == parent) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Cannot find parent directory of [%s], / is not allowed.\n",
                   ccdirname);
            ret = EINVAL;
            goto done;
        }
        *end = '\0';
    } while (*(end+1) == '\0');

    ret = find_ccdir_parent_data(mem_ctx, parent, parent_stat, missing_parents);

done:
    talloc_free(parent);
    return ret;
}

static errno_t
check_ccache_re(const char *filename, pcre *illegal_re)
{
    errno_t ret;

    ret = pcre_exec(illegal_re, NULL, filename, strlen(filename),
                    0, 0, NULL, 0);
    if (ret == 0) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Illegal pattern in ccache directory name [%s].\n", filename);
        return EINVAL;
    } else if (ret == PCRE_ERROR_NOMATCH) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "Ccache directory name [%s] does not contain "
               "illegal patterns.\n", filename);
        return EOK;
    }

    DEBUG(SSSDBG_CRIT_FAILURE, "pcre_exec failed [%d].\n", ret);
    return EFAULT;
}

errno_t
create_ccache_dir(const char *ccdirname, pcre *illegal_re,
                  uid_t uid, gid_t gid)
{
    int ret = EFAULT;
    struct stat parent_stat;
    struct string_list *missing_parents = NULL;
    struct string_list *li = NULL;
    mode_t old_umask;
    mode_t new_dir_mode;
    TALLOC_CTX *tmp_ctx = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "talloc_new failed.\n");
        return ENOMEM;
    }

    if (*ccdirname != '/') {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Only absolute paths are allowed, not [%s] .\n", ccdirname);
        ret = EINVAL;
        goto done;
    }

    if (illegal_re != NULL) {
        ret = check_ccache_re(ccdirname, illegal_re);
        if (ret != EOK) {
            goto done;
        }
    }

    ret = find_ccdir_parent_data(tmp_ctx, ccdirname, &parent_stat,
                                 &missing_parents);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "find_ccdir_parent_data failed.\n");
        goto done;
    }

    ret = check_parent_stat(&parent_stat, uid);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Check the ownership and permissions of krb5_ccachedir: [%s].\n",
              ccdirname);
        goto done;
    }

    DLIST_FOR_EACH(li, missing_parents) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Creating directory [%s].\n", li->s);
        new_dir_mode = 0700;

        old_umask = umask(0000);
        ret = mkdir(li->s, new_dir_mode);
        umask(old_umask);
        if (ret != EOK) {
            ret = errno;
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "mkdir [%s] failed: [%d][%s].\n", li->s, ret,
                   strerror(ret));
            goto done;
        }
        ret = chown(li->s, uid, gid);
        if (ret != EOK) {
            ret = errno;
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "chown failed [%d][%s].\n", ret, strerror(ret));
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t get_ccache_file_data(const char *ccache_file, const char *client_name,
                             struct tgt_times *tgtt)
{
    krb5_error_code kerr;
    krb5_context ctx = NULL;
    krb5_ccache cc = NULL;
    krb5_principal client_princ = NULL;
    krb5_principal server_princ = NULL;
    char *server_name;
    krb5_creds mcred;
    krb5_creds cred;
    const char *realm_name;
    int realm_length;

    kerr = krb5_init_context(&ctx);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_init_context failed.\n");
        goto done;
    }

    kerr = krb5_parse_name(ctx, client_name, &client_princ);
    if (kerr != 0) {
        KRB5_DEBUG(SSSDBG_OP_FAILURE, ctx, kerr);
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_parse_name failed.\n");
        goto done;
    }

    sss_krb5_princ_realm(ctx, client_princ, &realm_name, &realm_length);

    server_name = talloc_asprintf(NULL, "krbtgt/%.*s@%.*s",
                                  realm_length, realm_name,
                                  realm_length, realm_name);
    if (server_name == NULL) {
        kerr = KRB5_CC_NOMEM;
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
        goto done;
    }

    kerr = krb5_parse_name(ctx, server_name, &server_princ);
    talloc_free(server_name);
    if (kerr != 0) {
        KRB5_DEBUG(SSSDBG_OP_FAILURE, ctx, kerr);
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_parse_name failed.\n");
        goto done;
    }

    kerr = krb5_cc_resolve(ctx, ccache_file, &cc);
    if (kerr != 0) {
        KRB5_DEBUG(SSSDBG_OP_FAILURE, ctx, kerr);
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_cc_resolve failed.\n");
        goto done;
    }

    memset(&mcred, 0, sizeof(mcred));
    memset(&cred, 0, sizeof(mcred));

    mcred.server = server_princ;
    mcred.client = client_princ;

    kerr = krb5_cc_retrieve_cred(ctx, cc, 0, &mcred, &cred);
    if (kerr != 0) {
        KRB5_DEBUG(SSSDBG_OP_FAILURE, ctx, kerr);
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_cc_retrieve_cred failed.\n");
        goto done;
    }

    tgtt->authtime = cred.times.authtime;
    tgtt->starttime = cred.times.starttime;
    tgtt->endtime = cred.times.endtime;
    tgtt->renew_till = cred.times.renew_till;

    krb5_free_cred_contents(ctx, &cred);

    kerr = krb5_cc_close(ctx, cc);
    if (kerr != 0) {
        KRB5_DEBUG(SSSDBG_OP_FAILURE, ctx, kerr);
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_cc_close failed.\n");
        goto done;
    }
    cc = NULL;

    kerr = 0;

done:
    if (cc != NULL) {
        krb5_cc_close(ctx, cc);
    }

    if (client_princ != NULL) {
        krb5_free_principal(ctx, client_princ);
    }

    if (server_princ != NULL) {
        krb5_free_principal(ctx, server_princ);
    }

    if (ctx != NULL) {
        krb5_free_context(ctx);
    }

    if (kerr != 0) {
        return EIO;
    }

    return EOK;
}

errno_t sss_krb5_precreate_ccache(const char *ccname, pcre *illegal_re,
                                  uid_t uid, gid_t gid)
{
    TALLOC_CTX *tmp_ctx = NULL;
    const char *filename;
    char *ccdirname;
    char *end;
    errno_t ret;

    if (ccname[0] == '/') {
        filename = ccname;
    } else if (strncmp(ccname, "FILE:", 5) == 0) {
        filename = ccname + 5;
    } else if (strncmp(ccname, "DIR:", 4) == 0) {
        filename = ccname + 4;
    } else {
        /* only FILE and DIR types need precreation so far, we ignore any
         * other type */
        return EOK;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    ccdirname = talloc_strdup(tmp_ctx, filename);
    if (ccdirname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup failed.\n");
        ret = ENOMEM;
        goto done;
    }

    /* We'll remove all trailing slashes from the back so that
     * we only pass /some/path to find_ccdir_parent_data, not
     * /some/path/ */
    do {
        end = strrchr(ccdirname, '/');
        if (end == NULL || end == ccdirname) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Cannot find parent directory of [%s], "
                  "/ is not allowed.\n", ccdirname);
            ret = EINVAL;
            goto done;
        }
        *end = '\0';
    } while (*(end+1) == '\0');

    ret = create_ccache_dir(ccdirname, illegal_re, uid, gid);
done:
    talloc_free(tmp_ctx);
    return ret;
}


struct sss_krb5_ccache {
    struct sss_creds *creds;
    krb5_context context;
    krb5_ccache ccache;
};

static int sss_free_krb5_ccache(void *mem)
{
    struct sss_krb5_ccache *cc = talloc_get_type(mem, struct sss_krb5_ccache);

    if (cc->ccache) {
        krb5_cc_close(cc->context, cc->ccache);
    }
    krb5_free_context(cc->context);
    restore_creds(cc->creds);
    return 0;
}

static errno_t sss_open_ccache_as_user(TALLOC_CTX *mem_ctx,
                                       const char *ccname,
                                       uid_t uid, gid_t gid,
                                       struct sss_krb5_ccache **ccache)
{
    struct sss_krb5_ccache *cc;
    krb5_error_code kerr;
    errno_t ret;

    cc = talloc_zero(mem_ctx, struct sss_krb5_ccache);
    if (!cc) {
        return ENOMEM;
    }
    talloc_set_destructor((TALLOC_CTX *)cc, sss_free_krb5_ccache);

    ret = switch_creds(cc, uid, gid, 0, NULL, &cc->creds);
    if (ret) {
        goto done;
    }

    kerr = krb5_init_context(&cc->context);
    if (kerr) {
        ret = EIO;
        goto done;
    }

    kerr = krb5_cc_resolve(cc->context, ccname, &cc->ccache);
    if (kerr == KRB5_FCC_NOFILE || cc->ccache == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "ccache %s is missing or empty\n", ccname);
        ret = ERR_NOT_FOUND;
        goto done;
    } else if (kerr != 0) {
        KRB5_DEBUG(SSSDBG_OP_FAILURE, cc->context, kerr);
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_cc_resolve failed.\n");
        ret = ERR_INTERNAL;
        goto done;
    }

    ret = EOK;

done:
    if (ret) {
        talloc_free(cc);
    } else {
        *ccache = cc;
    }
    return ret;
}

static errno_t sss_destroy_ccache(struct sss_krb5_ccache *cc)
{
    krb5_error_code kerr;
    errno_t ret;

    kerr = krb5_cc_destroy(cc->context, cc->ccache);
    if (kerr) {
        KRB5_DEBUG(SSSDBG_OP_FAILURE, cc->context, kerr);
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_cc_destroy failed.\n");
        ret = EIO;
    } else {
        ret = EOK;
    }

    /* krb5_cc_destroy frees cc->ccache in all events */
    cc->ccache = NULL;

    return ret;
}

errno_t sss_krb5_cc_destroy(const char *ccname, uid_t uid, gid_t gid)
{
    struct sss_krb5_ccache *cc = NULL;
    TALLOC_CTX *tmp_ctx;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    ret = sss_open_ccache_as_user(tmp_ctx, ccname, uid, gid, &cc);
    if (ret) {
        goto done;
    }

    ret = sss_destroy_ccache(cc);

done:
    talloc_free(tmp_ctx);
    return ret;
}


/* This function is called only as a way to validate that we have the
 * right cache */
errno_t sss_krb5_check_ccache_princ(uid_t uid, gid_t gid,
                                    const char *ccname, const char *principal)
{
    struct sss_krb5_ccache *cc = NULL;
    krb5_principal ccprinc = NULL;
    krb5_principal kprinc = NULL;
    krb5_error_code kerr;
    const char *cc_type;
    TALLOC_CTX *tmp_ctx;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    ret = sss_open_ccache_as_user(tmp_ctx, ccname, uid, gid, &cc);
    if (ret) {
        goto done;
    }

    cc_type = krb5_cc_get_type(cc->context, cc->ccache);

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Searching for [%s] in cache of type [%s]\n", principal, cc_type);

    kerr = krb5_parse_name(cc->context, principal, &kprinc);
    if (kerr != 0) {
        KRB5_DEBUG(SSSDBG_OP_FAILURE, cc->context, kerr);
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_parse_name failed.\n");
        ret = ERR_INTERNAL;
        goto done;
    }

    kerr = krb5_cc_get_principal(cc->context, cc->ccache, &ccprinc);
    if (kerr != 0) {
        KRB5_DEBUG(SSSDBG_OP_FAILURE, cc->context, kerr);
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_cc_get_principal failed.\n");
    }

    if (ccprinc) {
        if (krb5_principal_compare(cc->context, kprinc, ccprinc) == TRUE) {
            /* found in the primary ccache */
            ret = EOK;
            goto done;
        }
    }

#ifdef HAVE_KRB5_CC_COLLECTION

    if (krb5_cc_support_switch(cc->context, cc_type)) {

        krb5_cc_close(cc->context, cc->ccache);
        cc->ccache = NULL;

        kerr = krb5_cc_set_default_name(cc->context, ccname);
        if (kerr != 0) {
            KRB5_DEBUG(SSSDBG_MINOR_FAILURE, cc->context, kerr);
            /* try to continue despite failure */
        }

        kerr = krb5_cc_cache_match(cc->context, kprinc, &cc->ccache);
        if (kerr == 0) {
            ret = EOK;
            goto done;
        }
        KRB5_DEBUG(SSSDBG_TRACE_INTERNAL, cc->context, kerr);
    }

#endif /* HAVE_KRB5_CC_COLLECTION */

    ret = ERR_NOT_FOUND;

done:
    if (cc) {
        krb5_free_principal(cc->context, ccprinc);
        krb5_free_principal(cc->context, kprinc);
    }
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t sss_low_level_path_check(const char *ccname)
{
    const char *filename;
    struct stat buf;
    int ret;

    if (ccname[0] == '/') {
        filename = ccname;
    } else if (strncmp(ccname, "FILE:", 5) == 0) {
        filename = ccname + 5;
    } else if (strncmp(ccname, "DIR:", 4) == 0) {
        filename = ccname + 4;
        if (filename[0] == ':') filename += 1;
    } else {
        /* only FILE and DIR types need file checks so far, we ignore any
         * other type */
        return EOK;
    }

    ret = stat(filename, &buf);
    if (ret == -1) return errno;
    return EOK;
}

errno_t sss_krb5_cc_verify_ccache(const char *ccname, uid_t uid, gid_t gid,
                                  const char *realm, const char *principal)
{
    struct sss_krb5_ccache *cc = NULL;
    TALLOC_CTX *tmp_ctx = NULL;
    krb5_principal tgt_princ = NULL;
    krb5_principal princ = NULL;
    char *tgt_name;
    krb5_creds mcred = { 0 };
    krb5_creds cred = { 0 };
    krb5_error_code kerr;
    errno_t ret;

    /* first of all verify if the old ccache file/dir exists as we may be
     * trying to verify if an old ccache exists at all. If no file/dir
     * exists bail out immediately otherwise a following krb5_cc_resolve()
     * call may actually create paths and files we do not want to have
     * around */
    ret = sss_low_level_path_check(ccname);
    if (ret) {
        return ret;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    ret = sss_open_ccache_as_user(tmp_ctx, ccname, uid, gid, &cc);
    if (ret) {
        goto done;
    }

    tgt_name = talloc_asprintf(tmp_ctx, "krbtgt/%s@%s", realm, realm);
    if (!tgt_name) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new failed.\n");
        ret = ENOMEM;
        goto done;
    }

    kerr = krb5_parse_name(cc->context, tgt_name, &tgt_princ);
    if (kerr) {
        KRB5_DEBUG(SSSDBG_CRIT_FAILURE, cc->context, kerr);
        if (kerr == KRB5_PARSE_MALFORMED) ret = EINVAL;
        else ret = ERR_INTERNAL;
        goto done;
    }

    kerr = krb5_parse_name(cc->context, principal, &princ);
    if (kerr) {
        KRB5_DEBUG(SSSDBG_CRIT_FAILURE, cc->context, kerr);
        if (kerr == KRB5_PARSE_MALFORMED) ret = EINVAL;
        else ret = ERR_INTERNAL;
        goto done;
    }

    mcred.client = princ;
    mcred.server = tgt_princ;
    mcred.times.endtime = time(NULL);

    kerr = krb5_cc_retrieve_cred(cc->context, cc->ccache,
                                 KRB5_TC_MATCH_TIMES, &mcred, &cred);
    if (kerr) {
        if (kerr == KRB5_CC_NOTFOUND || kerr == KRB5_FCC_NOFILE) {
            DEBUG(SSSDBG_TRACE_INTERNAL, "TGT not found or expired.\n");
            ret = EINVAL;
        } else {
            KRB5_DEBUG(SSSDBG_CRIT_FAILURE, cc->context, kerr);
            ret = ERR_INTERNAL;
        }
    }
    krb5_free_cred_contents(cc->context, &cred);

done:
    if (tgt_princ) krb5_free_principal(cc->context, tgt_princ);
    if (princ) krb5_free_principal(cc->context, princ);
    talloc_free(tmp_ctx);
    return ret;
}


errno_t get_domain_or_subdomain(struct be_ctx *be_ctx,
                                char *domain_name,
                                struct sss_domain_info **dom)
{

    if (domain_name != NULL &&
        strcasecmp(domain_name, be_ctx->domain->name) != 0) {
        *dom = find_subdomain_by_name(be_ctx->domain, domain_name, true);
        if (*dom == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "find_subdomain_by_name failed.\n");
            return ENOMEM;
        }
    } else {
        *dom = be_ctx->domain;
    }

    return EOK;
}
