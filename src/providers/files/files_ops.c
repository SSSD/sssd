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

/* When changing this constant, make sure to also adjust the files integration
 * test for reallocation branch
 */
#define FILES_REALLOC_CHUNK 64

#define PWD_MAXSIZE         1024
#define GRP_MAXSIZE         2048

#define SF_UPDATE_PASSWD    1<<0
#define SF_UPDATE_GROUP     1<<1
#define SF_UPDATE_BOTH      (SF_UPDATE_PASSWD | SF_UPDATE_GROUP)

struct files_ctx {
    struct files_ops_ctx *ops;
};

static errno_t enum_files_users(TALLOC_CTX *mem_ctx,
                                struct files_id_ctx *id_ctx,
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
                                 struct files_id_ctx *id_ctx,
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
            DEBUG(SSSDBG_OP_FAILURE, "No overrides, nothing to do.\n");
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
                              const char *group_file);

errno_t sf_enum_users(struct files_id_ctx *id_ctx,
                      const char *passwd_file)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx = NULL;
    struct passwd **users = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = enum_files_users(tmp_ctx, id_ctx, passwd_file,
                           &users);
    if (ret != EOK) {
        goto done;
    }

    for (size_t i = 0; users[i]; i++) {
        ret = save_file_user(id_ctx, users[i]);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Cannot save user %s: [%d]: %s\n",
                  users[i]->pw_name, ret, sss_strerror(ret));
            continue;
        }
    }

    ret = refresh_override_attrs(id_ctx, SYSDB_MEMBER_USER);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to refresh override attributes, "
              "override values might not be available.\n");
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
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
                              const char *group_file)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx = NULL;
    struct group **groups = NULL;
    const char **cached_users = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = enum_files_groups(tmp_ctx, id_ctx, group_file,
                            &groups);
    if (ret != EOK) {
        goto done;
    }

    cached_users = get_cached_user_names(tmp_ctx, id_ctx->domain);
    if (cached_users == NULL) {
        goto done;
    }

    for (size_t i = 0; groups[i]; i++) {
        ret = save_file_group(id_ctx, groups[i], cached_users);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Cannot save group %s\n", groups[i]->gr_name);
            continue;
        }
    }

    ret = refresh_override_attrs(id_ctx, SYSDB_MEMBER_GROUP);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to refresh override attributes, "
              "override values might not be available.\n");
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t sf_enum_files(struct files_id_ctx *id_ctx,
                             uint8_t flags)
{
    errno_t ret;
    errno_t tret;
    bool in_transaction = false;

    ret = sysdb_transaction_start(id_ctx->domain->sysdb);
    if (ret != EOK) {
        goto done;
    }
    in_transaction = true;

    if (flags & SF_UPDATE_PASSWD) {
        ret = delete_all_users(id_ctx->domain);
        if (ret != EOK) {
            goto done;
        }

        /* All users were deleted, therefore we need to enumerate each file again */
        for (size_t i = 0; id_ctx->passwd_files[i] != NULL; i++) {
            ret = sf_enum_users(id_ctx, id_ctx->passwd_files[i]);
            if (ret == ENOENT) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "The file %s does not exist (yet), skipping\n",
                      id_ctx->passwd_files[i]);
                continue;
            } else if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Cannot enumerate users from %s, aborting\n",
                      id_ctx->passwd_files[i]);
                goto done;
            }
        }
    }

    if (flags & SF_UPDATE_GROUP) {
        ret = delete_all_groups(id_ctx->domain);
        if (ret != EOK) {
            goto done;
        }

        /* All groups were deleted, therefore we need to enumerate each file again */
        for (size_t i = 0; id_ctx->group_files[i] != NULL; i++) {
            ret = sf_enum_groups(id_ctx, id_ctx->group_files[i]);
            if (ret == ENOENT) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "The file %s does not exist (yet), skipping\n",
                      id_ctx->group_files[i]);
                continue;
            } else if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Cannot enumerate groups from %s, aborting\n",
                      id_ctx->group_files[i]);
                goto done;
            }
        }
    }

    ret = sysdb_transaction_commit(id_ctx->domain->sysdb);
    if (ret != EOK) {
        goto done;
    }
    in_transaction = false;

    ret = EOK;
done:
    if (in_transaction) {
        tret = sysdb_transaction_cancel(id_ctx->domain->sysdb);
        if (tret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot cancel transaction: %d\n", ret);
        }
    }

    return ret;
}

static void sf_cb_done(struct files_id_ctx *id_ctx)
{
    /* Only activate a domain when both callbacks are done */
    if (id_ctx->updating_passwd == false
            && id_ctx->updating_groups == false) {
        dp_sbus_domain_active(id_ctx->be->provider,
                              id_ctx->domain);
    }
}

static int sf_passwd_cb(const char *filename, uint32_t flags, void *pvt)
{
    struct files_id_ctx *id_ctx;
    errno_t ret;

    id_ctx = talloc_get_type(pvt, struct files_id_ctx);
    if (id_ctx == NULL) {
        return EINVAL;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "passwd notification\n");

    id_ctx->updating_passwd = true;
    dp_sbus_domain_inconsistent(id_ctx->be->provider, id_ctx->domain);

    dp_sbus_reset_users_ncache(id_ctx->be->provider, id_ctx->domain);
    dp_sbus_reset_users_memcache(id_ctx->be->provider);
    dp_sbus_reset_initgr_memcache(id_ctx->be->provider);

    /* Using SF_UDPATE_BOTH here the case when someone edits /etc/group, adds a group member and
     * only then edits passwd and adds the user. The reverse is not needed,
     * because member/memberof links are established when groups are saved.
     */
    ret = sf_enum_files(id_ctx, SF_UPDATE_BOTH);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not update files: [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;
done:
    id_ctx->updating_passwd = false;
    sf_cb_done(id_ctx);
    files_account_info_finished(id_ctx, BE_REQ_USER, ret);
    return ret;
}

static int sf_group_cb(const char *filename, uint32_t flags, void *pvt)
{
    struct files_id_ctx *id_ctx;
    errno_t ret;

    id_ctx = talloc_get_type(pvt, struct files_id_ctx);
    if (id_ctx == NULL) {
        return EINVAL;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "group notification\n");

    id_ctx->updating_groups = true;
    dp_sbus_domain_inconsistent(id_ctx->be->provider, id_ctx->domain);

    dp_sbus_reset_groups_ncache(id_ctx->be->provider, id_ctx->domain);
    dp_sbus_reset_groups_memcache(id_ctx->be->provider);
    dp_sbus_reset_initgr_memcache(id_ctx->be->provider);

    ret = sf_enum_files(id_ctx, SF_UPDATE_GROUP);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not update files: [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;
done:
    id_ctx->updating_groups = false;
    sf_cb_done(id_ctx);
    files_account_info_finished(id_ctx, BE_REQ_GROUP, ret);
    return ret;
}

static void startup_enum_files(struct tevent_context *ev,
                               struct tevent_immediate *imm,
                               void *pvt)
{
    struct files_id_ctx *id_ctx = talloc_get_type(pvt, struct files_id_ctx);
    errno_t ret;

    talloc_zfree(imm);

    ret = sf_enum_files(id_ctx, SF_UPDATE_BOTH);
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
