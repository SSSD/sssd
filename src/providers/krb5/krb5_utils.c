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

#include "providers/krb5/krb5_utils.h"
#include "providers/krb5/krb5_auth.h"
#include "util/util.h"

char *expand_ccname_template(TALLOC_CTX *mem_ctx, struct krb5child_req *kr,
                             const char *template, bool file_mode,
                             bool *private_path)
{
    char *copy;
    char *p;
    char *n;
    char *result = NULL;
    const char *dummy;
    const char *cache_dir_tmpl;

    *private_path = false;

    if (template == NULL) {
        DEBUG(1, ("Missing template.\n"));
        return NULL;
    }

    copy = talloc_strdup(mem_ctx, template);
    if (copy == NULL) {
        DEBUG(1, ("talloc_strdup failed.\n"));
        return NULL;
    }

    result = talloc_strdup(mem_ctx, "");
    if (result == NULL) {
        DEBUG(1, ("talloc_strdup failed.\n"));
        return NULL;
    }

    p = copy;
    while ( (n = strchr(p, '%')) != NULL) {
        *n = '\0';
        n++;
        if ( *n == '\0' ) {
            DEBUG(1, ("format error, single %% at the end of the template.\n"));
            return NULL;
        }

        switch( *n ) {
            case 'u':
                if (kr->pd->user == NULL) {
                    DEBUG(1, ("Cannot expand user name template "
                              "because user name is empty.\n"));
                    return NULL;
                }
                result = talloc_asprintf_append(result, "%s%s", p,
                                                kr->pd->user);
                if (!file_mode) *private_path = true;
                break;
            case 'U':
                if (kr->uid <= 0) {
                    DEBUG(1, ("Cannot expand uid template "
                              "because uid is invalid.\n"));
                    return NULL;
                }
                result = talloc_asprintf_append(result, "%s%d", p,
                                                kr->uid);
                if (!file_mode) *private_path = true;
                break;
            case 'p':
                if (kr->upn == NULL) {
                    DEBUG(1, ("Cannot expand user principal name template "
                              "because upn is empty.\n"));
                    return NULL;
                }
                result = talloc_asprintf_append(result, "%s%s", p, kr->upn);
                if (!file_mode) *private_path = true;
                break;
            case '%':
                result = talloc_asprintf_append(result, "%s%%", p);
                break;
            case 'r':
                dummy = dp_opt_get_string(kr->krb5_ctx->opts, KRB5_REALM);
                if (dummy == NULL) {
                    DEBUG(1, ("Missing kerberos realm.\n"));
                    return NULL;
                }
                result = talloc_asprintf_append(result, "%s%s", p, dummy);
                break;
            case 'h':
                if (kr->homedir == NULL) {
                    DEBUG(1, ("Cannot expand home directory template "
                              "because the path is not available.\n"));
                    return NULL;
                }
                result = talloc_asprintf_append(result, "%s%s", p, kr->homedir);
                if (!file_mode) *private_path = true;
                break;
            case 'd':
                if (file_mode) {
                    cache_dir_tmpl = dp_opt_get_string(kr->krb5_ctx->opts,
                                                       KRB5_CCACHEDIR);
                    if (cache_dir_tmpl == NULL) {
                        DEBUG(1, ("Missing credential cache directory.\n"));
                        return NULL;
                    }

                    dummy = expand_ccname_template(mem_ctx, kr, cache_dir_tmpl,
                                                   false, private_path);
                    if (dummy == NULL) {
                        DEBUG(1, ("Expanding credential cache directory "
                                  "template failed.\n"));
                        return NULL;
                    }
                    result = talloc_asprintf_append(result, "%s%s", p, dummy);
                } else {
                    DEBUG(1, ("'%%d' is not allowed in this template.\n"));
                    return NULL;
                }
                break;
            case 'P':
                if (!file_mode) {
                    DEBUG(1, ("'%%P' is not allowed in this template.\n"));
                    return NULL;
                }
                if (kr->pd->cli_pid == 0) {
                    DEBUG(1, ("Cannot expand PID template "
                              "because PID is not available.\n"));
                    return NULL;
                }
                result = talloc_asprintf_append(result, "%s%d", p,
                                                kr->pd->cli_pid);
                break;
            default:
                DEBUG(1, ("format error, unknown template [%%%c].\n", *n));
                return NULL;
        }

        if (result == NULL) {
            DEBUG(1, ("talloc_asprintf_append failed.\n"));
            return NULL;
        }

        p = n + 1;
    }

    result = talloc_asprintf_append(result, "%s", p);

    return result;
}

static errno_t check_parent_stat(bool private_path, struct stat *parent_stat,
                                 uid_t uid, gid_t gid)
{
    if (private_path) {
        if (!((parent_stat->st_uid == 0 && parent_stat->st_gid == 0) ||
               parent_stat->st_uid == uid)) {
            DEBUG(1, ("Private directory can only be created below a "
                      "directory belonging to root or to [%d][%d].\n",
                      uid, gid));
            return EINVAL;
        }

        if (parent_stat->st_uid == uid) {
            if (!(parent_stat->st_mode & S_IXUSR)) {
                DEBUG(1, ("Parent directory does have the search bit set for "
                          "the owner.\n"));
                return EINVAL;
            }
        } else {
            if (!(parent_stat->st_mode & S_IXOTH)) {
                DEBUG(1, ("Parent directory does have the search bit set for "
                        "others.\n"));
                return EINVAL;
            }
        }
    } else {
        if (parent_stat->st_uid != 0 || parent_stat->st_gid != 0) {
            DEBUG(1, ("Public directory cannot be created below a user "
                      "directory.\n"));
            return EINVAL;
        }

        if (!(parent_stat->st_mode & S_IXOTH)) {
            DEBUG(1, ("Parent directory does have the search bit set for "
                      "others.\n"));
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

static errno_t find_ccdir_parent_data(TALLOC_CTX *mem_ctx, const char *dirname,
                                      struct stat *parent_stat,
                                      struct string_list **missing_parents)
{
    int ret = EFAULT;
    char *parent = NULL;
    char *end;
    struct string_list *li;

    ret = stat(dirname, parent_stat);
    if (ret == EOK) {
        if ( !S_ISDIR(parent_stat->st_mode) ) {
            DEBUG(1, ("[%s] is not a directory.\n", dirname));
            return EINVAL;
        }
        return EOK;
    } else {
        if (errno != ENOENT) {
            ret = errno;
            DEBUG(1, ("stat for [%s] failed: [%d][%s].\n", dirname, ret,
                      strerror(ret)));
            return ret;
        }
    }

    li = talloc_zero(mem_ctx, struct string_list);
    if (li == NULL) {
        DEBUG(1, ("talloc_zero failed.\n"));
        return ENOMEM;
    }

    li->s = talloc_strdup(li, dirname);
    if (li->s == NULL) {
        DEBUG(1, ("talloc_strdup failed.\n"));
        return ENOMEM;
    }

    DLIST_ADD(*missing_parents, li);

    parent = talloc_strdup(mem_ctx, dirname);
    if (parent == NULL) {
        DEBUG(1, ("talloc_strdup failed.\n"));
        return ENOMEM;
    }
    end = strrchr(parent, '/');
    if (end == NULL || end == parent) {
        DEBUG(1, ("Cannot find parent directory of [%s], / is not allowed.\n",
                   dirname));
        ret = EINVAL;
        goto done;
    }
    *end = '\0';

    ret = find_ccdir_parent_data(mem_ctx, parent, parent_stat, missing_parents);

done:
    talloc_free(parent);
    return ret;
}

errno_t create_ccache_dir(TALLOC_CTX *mem_ctx, const char *filename,
                          pcre *illegal_re, uid_t uid, gid_t gid,
                          bool private_path)
{
    int ret = EFAULT;
    char *dirname;
    char *end;
    struct stat parent_stat;
    struct string_list *missing_parents = NULL;
    struct string_list *li = NULL;
    mode_t old_umask;
    mode_t new_dir_mode;
    size_t offset = 0;
    TALLOC_CTX *tmp_ctx = NULL;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        DEBUG(1, ("talloc_new failed.\n"));
        return ENOMEM;
    }

    if (strncmp(filename, "FILE:", 5) == 0) {
        offset = 5;
    }

    dirname = talloc_strdup(tmp_ctx, filename + offset);
    if (dirname == NULL) {
        DEBUG(1, ("talloc_strndup failed.\n"));
        ret = ENOMEM;
        goto done;
    }

    if (*dirname != '/') {
        DEBUG(1, ("Only absolute paths are allowed, not [%s] .\n", dirname));
        ret = EINVAL;
        goto done;
    }

    if (illegal_re != NULL) {
        ret = pcre_exec(illegal_re, NULL, dirname, strlen(dirname),
                        0, 0, NULL, 0);
        if (ret == 0) {
            DEBUG(1, ("Illegal pattern in ccache directory name [%s].\n",
                      dirname));
            ret = EINVAL;
            goto done;
        } else if ( ret == PCRE_ERROR_NOMATCH) {
            DEBUG(9, ("Ccache directory name [%s] does not contain "
                      "illegal patterns.\n", dirname));
        } else {
            DEBUG(1, ("pcre_exec failed [%d].\n", ret));
            ret = EFAULT;
            goto done;
        }
    }

    end = strrchr(dirname, '/');
    if (end == NULL || end == dirname) {
        DEBUG(1, ("Missing filename in [%s].\n", dirname));
        ret = EINVAL;
        goto done;
    }
    *end = '\0';

    ret = find_ccdir_parent_data(tmp_ctx, dirname, &parent_stat,
                                 &missing_parents);
    if (ret != EOK) {
        DEBUG(1, ("find_ccdir_parent_data failed.\n"));
        goto done;
    }

    ret = check_parent_stat(private_path, &parent_stat, uid, gid);
    if (ret != EOK) {
        DEBUG(1, ("check_parent_stat failed for %s directory [%s].\n",
                  private_path ? "private" : "public", dirname));
        goto done;
    }

    DLIST_FOR_EACH(li, missing_parents) {
        DEBUG(9, ("Creating directory [%s].\n", li->s));
        if (li->next == NULL) {
            new_dir_mode = private_path ? 0700 : 01777;
        } else {
            if (private_path &&
                parent_stat.st_uid == uid && parent_stat.st_gid == gid) {
                new_dir_mode = 0700;
            } else {
                new_dir_mode = 0755;
            }
        }

        old_umask = umask(0000);
        ret = mkdir(li->s, new_dir_mode);
        umask(old_umask);
        if (ret != EOK) {
            ret = errno;
            DEBUG(1, ("mkdir [%s] failed: [%d][%s].\n", li->s, ret,
                      strerror(ret)));
            goto done;
        }
        if (private_path &&
            ((parent_stat.st_uid == uid && parent_stat.st_gid == gid) ||
             li->next == NULL)) {
            ret = chown(li->s, uid, gid);
            if (ret != EOK) {
                ret = errno;
                DEBUG(1, ("chown failed [%d][%s].\n", ret, strerror(ret)));
                goto done;
            }
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}
