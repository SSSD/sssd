/*
    SSSD

    Files provider operations

    Copyright (C) 2016 Red Hat

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
#include <dlfcn.h>

#include "config.h"

#include "providers/files/files_private.h"
#include "db/sysdb.h"
#include "util/inotify.h"
#include "util/util.h"
#include "providers/data_provider/dp_iface.h"

/* When changing this constant, make sure to also adjust the files integration
 * test for reallocation branch
 */
#define FILES_REALLOC_CHUNK 64

#define PWD_MAXSIZE         1024
#define GRP_MAXSIZE         2048

#define SF_UPDATE_PASSWD    1<<0
#define SF_UPDATE_GROUP     1<<1
#define SF_UPDATE_BOTH      (SF_UPDATE_PASSWD | SF_UPDATE_GROUP)
#define SF_UPDATE_IMMEDIATE 1<<2

struct files_ctx {
    struct files_ops_ctx *ops;
};

static errno_t enum_files_users(TALLOC_CTX *mem_ctx,
                                const char *passwd_file,
                                struct passwd ***_users)
{
    errno_t ret, close_ret;
    struct passwd *pwd_iter = NULL;
    struct passwd *pwd = NULL;
    struct passwd **users = NULL;
    FILE *pwd_handle = NULL;
    size_t n_users = 0;

    pwd_handle = fopen(passwd_file, "r");
    if (pwd_handle == NULL) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot open passwd file %s [%d]\n",
              passwd_file, ret);
        goto done;
    }

    users = talloc_zero_array(mem_ctx, struct passwd *,
                              FILES_REALLOC_CHUNK);
    if (users == NULL) {
        ret = ENOMEM;
        goto done;
    }

    while ((pwd_iter = fgetpwent(pwd_handle)) != NULL) {
        /* FIXME - we might want to support paging of sorts to avoid allocating
         * all users atop a memory context or only return users that differ from
         * the local storage as a diff to minimize memory spikes
         */
        DEBUG(SSSDBG_TRACE_LIBS,
              "User found (%s, %s, %"SPRIuid", %"SPRIgid", %s, %s, %s)\n",
              pwd_iter->pw_name, pwd_iter->pw_passwd,
              pwd_iter->pw_uid, pwd_iter->pw_gid,
              pwd_iter->pw_gecos, pwd_iter->pw_dir,
              pwd_iter->pw_shell);

        pwd = talloc_zero(users, struct passwd);
        if (pwd == NULL) {
            ret = ENOMEM;
            goto done;
        }

        pwd->pw_uid = pwd_iter->pw_uid;
        pwd->pw_gid = pwd_iter->pw_gid;

        pwd->pw_name = talloc_strdup(pwd, pwd_iter->pw_name);
        if (pwd->pw_name == NULL) {
            /* We only check pw_name here on purpose to allow broken
             * records to be optionally rejected when saving them
             * or fallback values to be used.
             */
            ret = ENOMEM;
            goto done;
        }

        pwd->pw_dir = talloc_strdup(pwd, pwd_iter->pw_dir);
        pwd->pw_gecos = talloc_strdup(pwd, pwd_iter->pw_gecos);
        pwd->pw_shell = talloc_strdup(pwd, pwd_iter->pw_shell);
        pwd->pw_passwd = talloc_strdup(pwd, pwd_iter->pw_passwd);

        users[n_users] = pwd;
        n_users++;
        if (n_users % FILES_REALLOC_CHUNK == 0) {
            users = talloc_realloc(mem_ctx,
                                   users,
                                   struct passwd *,
                                   talloc_array_length(users) + FILES_REALLOC_CHUNK);
            if (users == NULL) {
                ret = ENOMEM;
                goto done;
            }
        }
    }

    ret = EOK;
    users[n_users] = NULL;
    *_users = users;
done:
    if (ret != EOK) {
        talloc_free(users);
    }

    if (pwd_handle) {
        close_ret = fclose(pwd_handle);
        if (close_ret != 0) {
            close_ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot close passwd file %s [%d]\n",
                  passwd_file, close_ret);
        }
    }
    return ret;
}

static errno_t enum_files_groups(TALLOC_CTX *mem_ctx,
                                 const char *group_file,
                                 struct group ***_groups)
{
    errno_t ret, close_ret;
    struct group *grp_iter = NULL;
    struct group *grp = NULL;
    struct group **groups = NULL;
    size_t n_groups = 0;
    FILE *grp_handle = NULL;

    grp_handle = fopen(group_file, "r");
    if (grp_handle == NULL) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot open group file %s [%d]\n",
              group_file, ret);
        goto done;
    }

    groups = talloc_zero_array(mem_ctx, struct group *,
                               FILES_REALLOC_CHUNK);
    if (groups == NULL) {
        ret = ENOMEM;
        goto done;
    }

    while ((grp_iter = fgetgrent(grp_handle)) != NULL) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "Group found (%s, %"SPRIgid")\n",
              grp_iter->gr_name, grp_iter->gr_gid);

        grp = talloc_zero(groups, struct group);
        if (grp == NULL) {
            ret = ENOMEM;
            goto done;
        }

        grp->gr_gid = grp_iter->gr_gid;
        grp->gr_name = talloc_strdup(grp, grp_iter->gr_name);
        if (grp->gr_name == NULL) {
            /* We only check gr_name here on purpose to allow broken
             * records to be optionally rejected when saving them
             * or fallback values to be used.
             */
            ret = ENOMEM;
            goto done;
        }
        grp->gr_passwd = talloc_strdup(grp, grp_iter->gr_passwd);

        if (grp_iter->gr_mem != NULL) {
            size_t nmem;

            for (nmem = 0; grp_iter->gr_mem[nmem] != NULL; nmem++);

            grp->gr_mem = talloc_zero_array(grp, char *, nmem + 1);
            if (grp->gr_mem == NULL) {
                ret = ENOMEM;
                goto done;
            }

            for (nmem = 0; grp_iter->gr_mem[nmem] != NULL; nmem++) {
                grp->gr_mem[nmem] = talloc_strdup(grp, grp_iter->gr_mem[nmem]);
                if (grp->gr_mem[nmem] == NULL) {
                    ret = ENOMEM;
                    goto done;
                }
            }
        }

        groups[n_groups] = grp;
        n_groups++;
        if (n_groups % FILES_REALLOC_CHUNK == 0) {
            groups = talloc_realloc(mem_ctx,
                                    groups,
                                    struct group *,
                                    talloc_array_length(groups) + FILES_REALLOC_CHUNK);
            if (groups == NULL) {
                ret = ENOMEM;
                goto done;
            }
        }
    }

    ret = EOK;
    groups[n_groups] = NULL;
    *_groups = groups;
done:
    if (ret != EOK) {
        talloc_free(groups);
    }

    if (grp_handle) {
        close_ret = fclose(grp_handle);
        if (close_ret != 0) {
            close_ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot close group file %s [%d]\n",
                  group_file, close_ret);
        }
    }
    return ret;
}

static errno_t delete_all_users(struct sss_domain_info *dom)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *base_dn;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    base_dn = sysdb_user_base_dn(tmp_ctx, dom);
    if (base_dn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_delete_recursive(dom->sysdb, base_dn, true);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to delete users subtree [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t save_file_user(struct files_id_ctx *id_ctx,
                              struct passwd *pw)
{
    errno_t ret;
    char *fqname;
    TALLOC_CTX *tmp_ctx = NULL;
    const char *shell;
    const char *gecos;
    struct sysdb_attrs *attrs = NULL;

    if (strcmp(pw->pw_name, "root") == 0
            || pw->pw_uid == 0
            || pw->pw_gid == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "Skipping %s\n", pw->pw_name);
        return EOK;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    fqname = sss_create_internal_fqname(tmp_ctx, pw->pw_name,
                                        id_ctx->domain->name);
    if (fqname == NULL) {
        ret = ENOMEM;
        goto done;
    }

    attrs = sysdb_new_attrs(tmp_ctx);
    if (attrs == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (pw->pw_shell && pw->pw_shell[0] != '\0') {
        shell = pw->pw_shell;
    } else {
        shell = NULL;
    }

    if (pw->pw_gecos && pw->pw_gecos[0] != '\0') {
        gecos = pw->pw_gecos;
    } else {
        gecos = NULL;
    }

    /* FIXME - optimize later */
    ret = sysdb_store_user(id_ctx->domain,
                           fqname,
                           pw->pw_passwd,
                           pw->pw_uid,
                           pw->pw_gid,
                           gecos,
                           pw->pw_dir,
                           shell,
                           NULL, attrs,
                           NULL, 0, 0);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t refresh_override_attrs(struct files_id_ctx *id_ctx,
                                      enum sysdb_member_type type)
{
    const char *override_attrs[] = { SYSDB_OVERRIDE_OBJECT_DN,
                                     NULL};
    struct ldb_dn *base_dn;
    size_t count;
    struct ldb_message **msgs;
    struct ldb_message *msg = NULL;
    struct ldb_context *ldb_ctx;
    size_t c;
    TALLOC_CTX *tmp_ctx;
    int ret;
    const char *filter;

    ldb_ctx = sysdb_ctx_get_ldb(id_ctx->domain->sysdb);
    if (ldb_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing ldb_context.\n");
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    filter =  talloc_asprintf(tmp_ctx, "%s=%s", SYSDB_OBJECTCLASS,
                                                type == SYSDB_MEMBER_USER ?
                                                   SYSDB_OVERRIDE_USER_CLASS :
                                                   SYSDB_OVERRIDE_GROUP_CLASS );
    if (filter == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    base_dn = ldb_dn_new(tmp_ctx, ldb_ctx, SYSDB_TMPL_VIEW_BASE);
    if (base_dn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_entry(tmp_ctx, id_ctx->domain->sysdb, base_dn,
                             LDB_SCOPE_SUBTREE, filter,
                             override_attrs, &count, &msgs);
    if (ret != EOK) {
        if (ret == ENOENT) {
            DEBUG(SSSDBG_TRACE_FUNC, "No overrides, nothing to do.\n");
            ret = EOK;
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_search_entry failed.\n");
        }
        goto done;
    }

    for (c = 0; c < count; c++) {
        talloc_free(msg);
        msg = ldb_msg_new(tmp_ctx);
        if (msg == NULL) {
            ret = ENOMEM;
            goto done;
        }

        msg->dn = ldb_msg_find_attr_as_dn(ldb_ctx, tmp_ctx, msgs[c],
                                          SYSDB_OVERRIDE_OBJECT_DN);
        if (msg->dn == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to get object DN, skipping.\n");
            continue;
        }

        ret = ldb_msg_add_empty(msg, SYSDB_OVERRIDE_DN, LDB_FLAG_MOD_ADD, NULL);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_add_empty failed.\n");
            continue;
        }

        ret = ldb_msg_add_string(msg, SYSDB_OVERRIDE_DN,
                                 ldb_dn_get_linearized(msgs[c]->dn));
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_add_string failed.\n");
            continue;
        }

        ret = ldb_modify(ldb_ctx, msg);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to store override DN: %s(%d)[%s], skipping.\n",
                  ldb_strerror(ret), ret, ldb_errstring(ldb_ctx));
            continue;
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t sf_enum_groups(struct files_id_ctx *id_ctx,
                              struct group **groups, size_t start, size_t size);

static errno_t sf_enum_users(struct files_id_ctx *id_ctx, struct passwd **users,
                             size_t start, size_t size)
{
    errno_t ret;
    size_t i;

    for (i = start; i < (start + size) && users[i] != NULL; i++) {
        ret = save_file_user(id_ctx, users[i]);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Cannot save user %s: [%d]: %s\n",
                  users[i]->pw_name, ret, sss_strerror(ret));
            continue;
        }
    }

    if (users[i] == NULL) {
        ret = refresh_override_attrs(id_ctx, SYSDB_MEMBER_USER);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to refresh override attributes, "
                  "override values might not be available.\n");
        }

        ret = EOK;
    } else {
        ret = EAGAIN;
    }

    return ret;
}

static const char **get_cached_user_names(TALLOC_CTX *mem_ctx,
                                          struct sss_domain_info *dom)
{
    errno_t ret;
    struct ldb_result *res = NULL;
    const char **user_names = NULL;
    unsigned c = 0;

    ret = sysdb_enumpwent(mem_ctx, dom, &res);
    if (ret != EOK) {
        goto done;
    }

    user_names = talloc_zero_array(mem_ctx, const char *, res->count + 1);
    if (user_names == NULL) {
        goto done;
    }

    for (unsigned i = 0; i < res->count; i++) {
        user_names[c] = ldb_msg_find_attr_as_string(res->msgs[i],
                                                    SYSDB_NAME,
                                                    NULL);
        if (user_names[c] == NULL) {
            continue;
        }
        c++;
    }

done:
    /* Don't free res and keep it around to avoid duplicating the names */
    return user_names;
}

static errno_t delete_all_groups(struct sss_domain_info *dom)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *base_dn;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    base_dn = sysdb_group_base_dn(tmp_ctx, dom);
    if (base_dn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_delete_recursive(dom->sysdb, base_dn, true);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to delete groups subtree [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t save_file_group(struct files_id_ctx *id_ctx,
                               struct group *grp,
                               const char **cached_users)
{
    errno_t ret;
    char *fqname;
    struct sysdb_attrs *attrs = NULL;
    TALLOC_CTX *tmp_ctx = NULL;
    char **fq_gr_files_mem;
    const char **fq_gr_mem;
    unsigned mi = 0;

    if (strcmp(grp->gr_name, "root") == 0
            || grp->gr_gid == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "Skipping %s\n", grp->gr_name);
        return EOK;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    fqname = sss_create_internal_fqname(tmp_ctx, grp->gr_name,
                                        id_ctx->domain->name);
    if (fqname == NULL) {
        ret = ENOMEM;
        goto done;

    }

    attrs = sysdb_new_attrs(tmp_ctx);
    if (attrs == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (grp->gr_mem && grp->gr_mem[0]) {
        fq_gr_files_mem = sss_create_internal_fqname_list(
                                            tmp_ctx,
                                            (const char *const*) grp->gr_mem,
                                            id_ctx->domain->name);
        if (fq_gr_files_mem == NULL) {
            ret = ENOMEM;
            goto done;
        }

        fq_gr_mem = talloc_zero_array(tmp_ctx, const char *,
                                      talloc_array_length(fq_gr_files_mem));
        if (fq_gr_mem == NULL) {
            ret = ENOMEM;
            goto done;
        }

        for (unsigned i=0; fq_gr_files_mem[i] != NULL; i++) {
            if (string_in_list(fq_gr_files_mem[i],
                               discard_const(cached_users),
                               true)) {
                fq_gr_mem[mi] = fq_gr_files_mem[i];
                mi++;

                DEBUG(SSSDBG_TRACE_LIBS,
                      "User %s is cached, will become a member of %s\n",
                      fq_gr_files_mem[i], grp->gr_name);
            } else {
                ret = sysdb_attrs_add_string(attrs,
                                             SYSDB_GHOST,
                                             fq_gr_files_mem[i]);
                if (ret != EOK) {
                    DEBUG(SSSDBG_MINOR_FAILURE,
                          "Cannot add ghost %s for group %s\n",
                          fq_gr_files_mem[i], fqname);
                    continue;
                }

                DEBUG(SSSDBG_TRACE_LIBS,
                      "User %s is not cached, will become a ghost of %s\n",
                      fq_gr_files_mem[i], grp->gr_name);
            }
        }

        if (fq_gr_mem != NULL && fq_gr_mem[0] != NULL) {
            ret = sysdb_attrs_users_from_str_list(
                    attrs, SYSDB_MEMBER, id_ctx->domain->name,
                    (const char *const *) fq_gr_mem);
            if (ret) {
                DEBUG(SSSDBG_OP_FAILURE, "Could not add group members\n");
                goto done;
            }
        }

    }

    ret = sysdb_store_group(id_ctx->domain, fqname, grp->gr_gid,
                            attrs, 0, 0);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not add group to cache\n");
        goto done;
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t sf_enum_groups(struct files_id_ctx *id_ctx,
                              struct group **groups, size_t start, size_t size)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx = NULL;
    const char **cached_users = NULL;
    size_t i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    cached_users = get_cached_user_names(tmp_ctx, id_ctx->domain);
    if (cached_users == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = start; i < (start + size) && groups[i] != NULL; i++) {
        ret = save_file_group(id_ctx, groups[i], cached_users);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Cannot save group %s\n", groups[i]->gr_name);
            continue;
        }
    }

    if (groups[i] == NULL) {
        ret = refresh_override_attrs(id_ctx, SYSDB_MEMBER_GROUP);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to refresh override attributes, "
                  "override values might not be available.\n");
        }

        ret = EOK;
    } else {
        ret = EAGAIN;
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

enum update_steps {
    WAIT_TO_START_USERS,
    DELETE_USERS,
    READ_USERS,
    SAVE_USERS,
    WAIT_TO_START_GROUPS,
    DELETE_GROUPS,
    READ_GROUPS,
    SAVE_GROUPS,
    UPDATE_FINISH,
    UPDATE_DONE,
};

struct certmap_req_list {
    struct tevent_req *req;
    struct certmap_req_list *prev;
    struct certmap_req_list *next;
};

struct files_refresh_ctx {
    struct timeval start_passwd_refresh;
    enum refresh_task_status updating_passwd;
    bool passwd_start_again;
    struct timeval start_group_refresh;
    enum refresh_task_status updating_groups;
    bool group_start_again;

    struct certmap_req_list *certmap_req_list;
};

errno_t sf_add_certmap_req(struct files_refresh_ctx *refresh_ctx,
                           struct tevent_req *req)
{
    struct certmap_req_list *certmap_req_item;

    certmap_req_item = talloc_zero(refresh_ctx, struct certmap_req_list);
    if (certmap_req_item == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to allow memory for certmap request list.\n");
        return ENOMEM;
    }
    certmap_req_item->req = req;
    DLIST_ADD(refresh_ctx->certmap_req_list, certmap_req_item);

    return EOK;
}

static errno_t check_state(struct files_refresh_ctx *refresh_ctx, uint8_t flags)
{
    errno_t ret;
    struct timeval tv;
    struct timeval delay = { 1, 0 };
    const struct timeval tv_zero = {0 , 0};

    errno = 0;
    ret = gettimeofday(&tv, NULL);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE,
              "gettimeofday failed [%d][%s], keeping old value.\n",
              ret, sss_strerror(ret));
    }

    if ((flags & SF_UPDATE_PASSWD) && (flags & SF_UPDATE_GROUP)) {
        if (flags & SF_UPDATE_IMMEDIATE) {
            refresh_ctx->start_passwd_refresh = tv_zero;
        } else {
            if (ret == EOK) {
                timeradd(&tv, &delay,
                         &refresh_ctx->start_passwd_refresh);
            }
        }

        switch (refresh_ctx->updating_passwd) {
        case REFRESH_NOT_RUNNIG:
            break;
        case REFRESH_WAITING_TO_START:
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Refresh is already waiting to start, nothing to do.\n");
            return EAGAIN;
        case REFRESH_ACTIVE:
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Refresh currently active, queing another refresh.\n");
            refresh_ctx->passwd_start_again = true;
            return EAGAIN;
        default:
            DEBUG(SSSDBG_OP_FAILURE, "Unknown refresh state [%d].\n",
                                     refresh_ctx->updating_passwd);
            return EINVAL;
        }

        /* Groups are updated after passwd, in case a new passwd update
         * arrives we have to run the passwd steps again. */
        switch (refresh_ctx->updating_groups) {
        case REFRESH_NOT_RUNNIG:
            break;
        case REFRESH_WAITING_TO_START:
            refresh_ctx->passwd_start_again = true;
            return EAGAIN;
        case REFRESH_ACTIVE:
            refresh_ctx->passwd_start_again = true;
            refresh_ctx->group_start_again = true;
            return EAGAIN;
        default:
            DEBUG(SSSDBG_OP_FAILURE, "Unknown refresh state [%d].\n",
                                     refresh_ctx->updating_groups);
            return EINVAL;
        }

        refresh_ctx->passwd_start_again = false;
        refresh_ctx->updating_passwd = REFRESH_WAITING_TO_START;
        refresh_ctx->updating_groups = REFRESH_WAITING_TO_START;
        return EOK;
    } else if (flags & SF_UPDATE_GROUP) {
        if (flags & SF_UPDATE_IMMEDIATE) {
            refresh_ctx->start_group_refresh = tv_zero;
        } else {
            if (ret == EOK) {
                timeradd(&tv, &delay,
                         &refresh_ctx->start_group_refresh);
            }
        }

        switch (refresh_ctx->updating_groups) {
        case REFRESH_NOT_RUNNIG:
            break;
        case REFRESH_WAITING_TO_START:
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Refresh is already waiting to start, nothing to do.\n");
            return EAGAIN;
        case REFRESH_ACTIVE:
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Refresh currently active, queing another refresh.\n");
            refresh_ctx->group_start_again = true;
            return EAGAIN;
        default:
            DEBUG(SSSDBG_OP_FAILURE, "Unknown refresh state [%d].\n",
                                     refresh_ctx->updating_passwd);
            return EINVAL;
        }

        refresh_ctx->group_start_again = false;
        refresh_ctx->updating_groups = REFRESH_WAITING_TO_START;
        return EOK;
    }

    DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected refresh flags [%"PRIu8"].\n", flags);
    return EINVAL;
}

struct sf_enum_files_state {
    struct files_id_ctx *id_ctx;
    struct files_refresh_ctx *refresh_ctx;
    uint8_t flags;
    struct tevent_timer *te;
    enum update_steps current_step;
    size_t step;
    bool in_transaction;
    size_t batch_size;
    size_t obj_idx;
    size_t file_idx;
    struct passwd **users;
    struct group **groups;
    uint32_t delay;
    uint32_t initial_delay;
};

static int clear_refresh_ctx(void *ptr)
{
    struct sf_enum_files_state *state = (struct sf_enum_files_state *) ptr;

    state->id_ctx->refresh_ctx = NULL;

    return 0;
}

static void sf_enum_files_steps(struct tevent_context *ev,
                                struct tevent_timer *te,
                                struct timeval tv,
                                void *data);
static struct tevent_req *sf_enum_files_send(struct files_id_ctx *id_ctx,
                                             uint8_t flags)
{
    struct tevent_req *req;
    struct sf_enum_files_state *state;
    struct timeval tv;
    errno_t ret;
    struct files_refresh_ctx *refresh_ctx = NULL;

    if (id_ctx->refresh_ctx != NULL) {
        refresh_ctx = id_ctx->refresh_ctx;
    } else {
        refresh_ctx = talloc_zero(id_ctx, struct files_refresh_ctx);
        if (refresh_ctx == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to allocate refresh context.\n");
            return NULL;
        }
        refresh_ctx->updating_passwd = REFRESH_NOT_RUNNIG;
        refresh_ctx->updating_groups = REFRESH_NOT_RUNNIG;
        refresh_ctx->certmap_req_list = NULL;
    }

    ret = check_state(refresh_ctx, flags);
    if (ret != EOK) {
        return NULL;
    }

    req = tevent_req_create(id_ctx, &state, struct sf_enum_files_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    if (id_ctx->refresh_ctx == NULL) {
        id_ctx->refresh_ctx = talloc_steal(state, refresh_ctx);
        talloc_set_destructor((TALLOC_CTX *) state, clear_refresh_ctx);
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "The files refresh task should run only "
              "once, but a second was detected. Error in internal procession "
              "logic.\n");
        ret = EFAULT;
        goto done;
    }

    state->id_ctx = id_ctx;
    state->flags = flags;
    state->step = 0;
    state->batch_size = 1000;
    state->obj_idx = 0;
    state->file_idx = 0;
    state->initial_delay = 100;
    state->delay = 100;

    if (state->flags & SF_UPDATE_PASSWD) {
        state->current_step = WAIT_TO_START_USERS;
    } else if (state->flags & SF_UPDATE_GROUP) {
        state->current_step = WAIT_TO_START_GROUPS;
    } else {
        DEBUG(SSSDBG_OP_FAILURE, "None of the expected flags are set, "
                                 "cannot start the refresh.\n");
        ret = EINVAL;
        goto done;
    }

    tv = tevent_timeval_current_ofs(0, state->initial_delay);
    state->te = tevent_add_timer(id_ctx->be->ev, state, tv,
                                 sf_enum_files_steps, req);
    if (state->te == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to schedule files update.\n");
        ret = EFAULT;
        goto done;
    }

    return req;

done:
    tevent_req_error(req, ret);
    tevent_req_post(req, id_ctx->be->ev);
    return req;
}

static void sf_enum_files_steps(struct tevent_context *ev,
                                struct tevent_timer *te,
                                struct timeval tv,
                                void *data)
{
    errno_t ret;
    errno_t tret;
    struct sf_enum_files_state *state;
    struct tevent_req *req;
    struct files_id_ctx *id_ctx;
    const char *filename = NULL;
    struct timeval now;
    struct timeval diff;
    uint32_t delay;
    struct certmap_req_list *certmap_req_item;
    struct certmap_req_list *certmap_req_tmp;

    req = talloc_get_type(data, struct tevent_req);
    state = tevent_req_data(req, struct sf_enum_files_state);

    state->te = NULL;
    id_ctx = state->id_ctx;
    delay = state->delay;

    switch (state->current_step) {
    case WAIT_TO_START_USERS:
        DEBUG(SSSDBG_TRACE_ALL, "Step WAIT_TO_START_USERS.\n");
        errno = 0;
        ret = gettimeofday(&now, NULL);
        if (ret == -1) {
            ret = errno;
            DEBUG(SSSDBG_OP_FAILURE,
                  "gettimeofday failed [%d][%s], starting user refresh now.\n",
                  ret, sss_strerror(ret));
            state->current_step = DELETE_USERS;
            delay = 0;
        } else {
            timersub(&state->id_ctx->refresh_ctx->start_passwd_refresh, &now,
                     &diff);
            if (diff.tv_sec < 0) {
                state->current_step = DELETE_USERS;
                delay = 0;
            } else {
                delay = diff.tv_sec*1000000 + diff.tv_usec;
            }
        }
        break;
    case DELETE_USERS:
        if (!state->in_transaction) {
            ret = sysdb_transaction_start(id_ctx->domain->sysdb);
            if (ret != EOK) {
                goto done;
            }
            state->in_transaction = true;
        }

        id_ctx->refresh_ctx->updating_passwd = REFRESH_ACTIVE;
        DEBUG(SSSDBG_TRACE_ALL, "Step DELETE_USERS.\n");
        ret = delete_all_users(id_ctx->domain);
        if (ret != EOK) {
            goto done;
        }
        state->file_idx = 0;
        state->current_step = READ_USERS;
        break;
    case READ_USERS:
        DEBUG(SSSDBG_TRACE_ALL, "Step READ_USERS.\n");
        talloc_zfree(state->users);
        state->obj_idx = 0;
        /* All users were deleted, therefore we need to enumerate each file again */
        if (id_ctx->passwd_files[state->file_idx] != NULL) {
            filename = id_ctx->passwd_files[state->file_idx++];
            ret = enum_files_users(state, filename, &state->users);
            if (ret == EOK) {
                state->current_step = SAVE_USERS;
            } else if (ret == ENOENT) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "The file %s does not exist (yet), skipping\n",
                      filename);
            } else if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Cannot enumerate users from %s, aborting\n",
                      filename);
                goto done;
            }
        } else {
            id_ctx->refresh_ctx->updating_passwd = REFRESH_NOT_RUNNIG;
            if (state->flags & SF_UPDATE_GROUP) {
                state->current_step = WAIT_TO_START_GROUPS;
            } else {
                if (state->id_ctx->refresh_ctx->passwd_start_again) {
                    state->id_ctx->refresh_ctx->passwd_start_again = false;
                    id_ctx->refresh_ctx->updating_passwd = REFRESH_WAITING_TO_START;
                    state->current_step = WAIT_TO_START_USERS;
                } else if (state->id_ctx->refresh_ctx->group_start_again) {
                    state->id_ctx->refresh_ctx->group_start_again = false;
                    id_ctx->refresh_ctx->updating_groups = REFRESH_WAITING_TO_START;
                    state->current_step = WAIT_TO_START_GROUPS;
                } else {
                    state->current_step = UPDATE_FINISH;
                }
            }
        }
        break;
    case SAVE_USERS:
        DEBUG(SSSDBG_TRACE_ALL, "Step SAVE_USERS.\n");
        if (state->users != NULL) {
            ret = sf_enum_users(id_ctx, state->users,
                                state->obj_idx, state->batch_size);
            if (ret == EOK) {
                /* check next file */
                state->current_step = READ_USERS;
            } else if (ret == EAGAIN) {
                state->obj_idx += state->batch_size;
            } else {
                DEBUG(SSSDBG_OP_FAILURE, "Saving users failed.\n");
                goto done;
            }
        }
        break;
    case WAIT_TO_START_GROUPS:
        DEBUG(SSSDBG_TRACE_ALL, "Step WAIT_TO_START_GROUPS.\n");
        errno = 0;
        ret = gettimeofday(&now, NULL);
        if (ret == -1) {
            ret = errno;
            DEBUG(SSSDBG_OP_FAILURE,
                  "gettimeofday failed [%d][%s], starting user refresh now.\n",
                  ret, sss_strerror(ret));
            state->current_step = DELETE_GROUPS;
            delay = 0;
        } else {
            timersub(&state->id_ctx->refresh_ctx->start_passwd_refresh, &now,
                     &diff);
            if (diff.tv_sec < 0) {
                state->current_step = DELETE_GROUPS;
                delay = 0;
            } else {
                delay = diff.tv_sec*1000000 + diff.tv_usec;
            }
        }
        break;
    case DELETE_GROUPS:
        if (!state->in_transaction) {
            ret = sysdb_transaction_start(id_ctx->domain->sysdb);
            if (ret != EOK) {
                goto done;
            }
            state->in_transaction = true;
        }
        id_ctx->refresh_ctx->updating_groups = REFRESH_ACTIVE;
        DEBUG(SSSDBG_TRACE_ALL, "Step DELETE_GROUPS.\n");
        ret = delete_all_groups(id_ctx->domain);
        if (ret != EOK) {
            goto done;
        }
        state->file_idx = 0;
        state->current_step = READ_GROUPS;
        break;
    case READ_GROUPS:
        DEBUG(SSSDBG_TRACE_ALL, "Step READ_GROUPS.\n");
        talloc_zfree(state->groups);
        state->obj_idx = 0;
        /* All groups were deleted, therefore we need to enumerate each file again */
        if (id_ctx->group_files[state->file_idx] != NULL) {
            filename = id_ctx->group_files[state->file_idx++];
            ret = enum_files_groups(state, filename, &state->groups);
            if (ret == EOK) {
                state->current_step = SAVE_GROUPS;
            } else if (ret == ENOENT) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "The file %s does not exist (yet), skipping\n",
                      filename);
            } else if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Cannot enumerate groups from %s, aborting\n",
                      filename);
                goto done;
            }
        } else {
            id_ctx->refresh_ctx->updating_groups = REFRESH_NOT_RUNNIG;
            if (state->id_ctx->refresh_ctx->passwd_start_again) {
                state->id_ctx->refresh_ctx->passwd_start_again = false;
                id_ctx->refresh_ctx->updating_passwd = REFRESH_WAITING_TO_START;
                state->current_step = WAIT_TO_START_USERS;
            } else if (state->id_ctx->refresh_ctx->group_start_again) {
                state->id_ctx->refresh_ctx->group_start_again = false;
                id_ctx->refresh_ctx->updating_groups = REFRESH_WAITING_TO_START;
                state->current_step = WAIT_TO_START_GROUPS;
            } else {
                state->current_step = UPDATE_FINISH;
            }
        }
        break;
    case SAVE_GROUPS:
        DEBUG(SSSDBG_TRACE_ALL, "Step SAVE_GROUPS.\n");
        if (state->groups != NULL) {
            ret = sf_enum_groups(id_ctx, state->groups,
                                 state->obj_idx, state->batch_size);
            if (ret == EOK) {
                state->current_step = READ_GROUPS;
            } else if (ret == EAGAIN) {
                state->obj_idx += state->batch_size;
            } else {
                DEBUG(SSSDBG_OP_FAILURE, "Saving groups failed.\n");
                goto done;
            }
        }
        break;
    case UPDATE_FINISH:
        DEBUG(SSSDBG_TRACE_ALL, "Step UPDATE_FINISH.\n");
        ret = dp_add_sr_attribute(id_ctx->be);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to add session recording attribute, ignored.\n");
        }

        ret = sysdb_transaction_commit(id_ctx->domain->sysdb);
        if (ret != EOK) {
            goto done;
        }
        state->in_transaction = false;

        state->current_step = UPDATE_DONE;

        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Undefined update step [%u].\n",
                                   state->current_step);
        ret = EINVAL;
        goto done;
    }

    if (state->current_step != UPDATE_DONE) {
        tv = tevent_timeval_current_ofs(0, delay);
        state->te = tevent_add_timer(id_ctx->be->ev, state, tv,
                                     sf_enum_files_steps, req);
        if (state->te == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Unable to schedule files update.\n");
            ret = EFAULT;
            goto done;
        }

        return;
    }

    ret = EOK;
done:
    if (state->in_transaction) {
        tret = sysdb_transaction_cancel(id_ctx->domain->sysdb);
        if (tret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot cancel transaction: %d\n", ret);
        }
        state->in_transaction = false;
    }

    DLIST_FOR_EACH_SAFE(certmap_req_item, certmap_req_tmp,
                        id_ctx->refresh_ctx->certmap_req_list) {
        handle_certmap(certmap_req_item->req);
        DLIST_REMOVE(certmap_req_item,
                     id_ctx->refresh_ctx->certmap_req_list);
        talloc_free(certmap_req_item);
    }

    id_ctx->refresh_ctx->updating_passwd = REFRESH_NOT_RUNNIG;
    id_ctx->refresh_ctx->updating_groups = REFRESH_NOT_RUNNIG;
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }

    return;
}

static errno_t sf_enum_files_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static void sf_cb_done(struct files_id_ctx *id_ctx)
{
    /* Only activate a domain when both callbacks are done */
    if (id_ctx->refresh_ctx == NULL) {
        dp_sbus_domain_active(id_ctx->be->provider,
                              id_ctx->domain);
    }
}

static void sf_passwd_cb_done(struct tevent_req *req);
static int sf_passwd_cb(const char *filename, uint32_t flags, void *pvt)
{
    struct files_id_ctx *id_ctx;
    struct tevent_req *req;
    errno_t ret;

    id_ctx = talloc_get_type(pvt, struct files_id_ctx);
    if (id_ctx == NULL) {
        return EINVAL;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "passwd notification\n");
    dp_sbus_domain_inconsistent(id_ctx->be->provider, id_ctx->domain);

    dp_sbus_reset_users_ncache(id_ctx->be->provider, id_ctx->domain);
    dp_sbus_reset_users_memcache(id_ctx->be->provider);
    dp_sbus_reset_initgr_memcache(id_ctx->be->provider);

    /* Using SF_UDPATE_BOTH here the case when someone edits /etc/group, adds a group member and
     * only then edits passwd and adds the user. The reverse is not needed,
     * because member/memberof links are established when groups are saved.
     */
    req = sf_enum_files_send(id_ctx, SF_UPDATE_BOTH);
    if (req == NULL) {
        if (id_ctx->refresh_ctx != NULL) {
            /* Update is currently active, nothing to do */
            return EOK;
        }
        DEBUG(SSSDBG_OP_FAILURE, "Failed to start files update.\n");
        ret = ENOMEM;
        sf_cb_done(id_ctx);
        files_account_info_finished(id_ctx, BE_REQ_USER, ret);
        return ret;
    }

    tevent_req_set_callback(req, sf_passwd_cb_done, id_ctx);

    return EOK;
}

static void sf_passwd_cb_done(struct tevent_req *req)
{
    struct files_id_ctx *id_ctx;
    errno_t ret;

    id_ctx = tevent_req_callback_data(req, struct files_id_ctx);

    ret = sf_enum_files_recv(req);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not update files: [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;
done:
    sf_cb_done(id_ctx);
    files_account_info_finished(id_ctx, BE_REQ_USER, ret);
    files_account_info_finished(id_ctx, BE_REQ_GROUP, ret);
}

static void sf_group_cb_done(struct tevent_req *req);
static int sf_group_cb(const char *filename, uint32_t flags, void *pvt)
{
    struct files_id_ctx *id_ctx;
    errno_t ret;
    struct tevent_req *req;

    id_ctx = talloc_get_type(pvt, struct files_id_ctx);
    if (id_ctx == NULL) {
        return EINVAL;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "group notification\n");
    dp_sbus_domain_inconsistent(id_ctx->be->provider, id_ctx->domain);

    dp_sbus_reset_groups_ncache(id_ctx->be->provider, id_ctx->domain);
    dp_sbus_reset_groups_memcache(id_ctx->be->provider);
    dp_sbus_reset_initgr_memcache(id_ctx->be->provider);

    req = sf_enum_files_send(id_ctx, SF_UPDATE_GROUP);
    if (req == NULL) {
        if (id_ctx->refresh_ctx != NULL) {
            /* Update is currently active, nothing to do */
            return EOK;
        }
        DEBUG(SSSDBG_OP_FAILURE, "Failed to start files update.\n");
        ret = ENOMEM;
        sf_cb_done(id_ctx);
        files_account_info_finished(id_ctx, BE_REQ_GROUP, ret);
        return ret;
    }

    tevent_req_set_callback(req, sf_group_cb_done, id_ctx);

    return EOK;
}

static void sf_group_cb_done(struct tevent_req *req)
{
    struct files_id_ctx *id_ctx;
    errno_t ret;

    id_ctx = tevent_req_callback_data(req, struct files_id_ctx);

    ret = sf_enum_files_recv(req);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not update files: [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;
done:
    sf_cb_done(id_ctx);
    files_account_info_finished(id_ctx, BE_REQ_GROUP, ret);
}

static void startup_enum_files_done(struct tevent_req *req);
static void startup_enum_files(struct tevent_context *ev,
                               struct tevent_immediate *imm,
                               void *pvt)
{
    struct files_id_ctx *id_ctx = talloc_get_type(pvt, struct files_id_ctx);
    struct tevent_req *req;

    talloc_zfree(imm);

    req = sf_enum_files_send(id_ctx, SF_UPDATE_BOTH|SF_UPDATE_IMMEDIATE);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not update files after startup.\n");
        return;
    }

    tevent_req_set_callback(req, startup_enum_files_done, NULL);
}

static void startup_enum_files_done(struct tevent_req *req)
{
    errno_t ret;

    ret = sf_enum_files_recv(req);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not update files after startup: [%d]: %s\n",
              ret, sss_strerror(ret));
    }
}

static struct snotify_ctx *sf_setup_watch(TALLOC_CTX *mem_ctx,
                                          struct tevent_context *ev,
                                          const char *filename,
                                          snotify_cb_fn fn,
                                          struct files_id_ctx *id_ctx)
{
    return snotify_create(mem_ctx, ev, SNOTIFY_WATCH_DIR,
                          filename, NULL,
                          IN_DELETE_SELF | IN_CLOSE_WRITE | IN_MOVE_SELF | \
                          IN_CREATE | IN_MOVED_TO,
                          fn, id_ctx);
}

struct files_ctx *sf_init(TALLOC_CTX *mem_ctx,
                          struct tevent_context *ev,
                          const char **passwd_files,
                          const char **group_files,
                          struct files_id_ctx *id_ctx)
{
    struct files_ctx *fctx;
    struct tevent_immediate *imm;
    int i;
    struct snotify_ctx *snctx;

    fctx = talloc(mem_ctx, struct files_ctx);
    if (fctx == NULL) {
        return NULL;
    }

    for (i = 0; passwd_files[i]; i++) {
        snctx = sf_setup_watch(fctx, ev, passwd_files[i],
                               sf_passwd_cb, id_ctx);
        if (snctx == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Cannot set watch for passwd file %s\n", passwd_files[i]);
            /* Rather than reporting incomplete or inconsistent information
             * in case e.g. group memberships span multiple files, just abort
             */
            talloc_free(fctx);
            return NULL;
        }
    }

    for (i = 0; group_files[i]; i++) {
        snctx = sf_setup_watch(fctx, ev, group_files[i],
                                sf_group_cb, id_ctx);
        if (snctx == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Cannot set watch for group file %s\n", group_files[i]);
            /* Rather than reporting incomplete or inconsistent information
             * in case e.g. group memberships span multiple files, just abort
             */
            talloc_free(fctx);
            return NULL;
        }
    }

    /* Enumerate users and groups on startup to process any changes when
     * sssd was down. We schedule a request here to minimize the time
     * we spend in the init function
     */
    imm = tevent_create_immediate(id_ctx);
    if (imm == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "tevent_create_immediate failed.\n");
        talloc_free(fctx);
        return NULL;
    }
    tevent_schedule_immediate(imm, ev, startup_enum_files, id_ctx);

    return fctx;
}
