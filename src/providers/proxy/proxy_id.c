/*
    SSSD

    proxy_id.c

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2010 Red Hat

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

#include "util/strtonum.h"
#include "providers/proxy/proxy.h"

/* =Getpwnam-wrapper======================================================*/

static int save_user(struct sysdb_ctx *sysdb, bool lowercase,
                     struct passwd *pwd, const char *real_name,
                     const char *alias, uint64_t cache_timeout);

static int
handle_getpw_result(enum nss_status status, struct passwd *pwd,
                    struct sss_domain_info *dom, bool *del_user);

static int
delete_user(struct sysdb_ctx *sysdb, const char *name, uid_t uid);

static int get_pw_name(TALLOC_CTX *mem_ctx,
                       struct proxy_id_ctx *ctx,
                       struct sysdb_ctx *sysdb,
                       struct sss_domain_info *dom,
                       const char *name)
{
    TALLOC_CTX *tmpctx;
    struct passwd *pwd;
    enum nss_status status;
    char *buffer;
    size_t buflen;
    int ret;
    uid_t uid;
    bool del_user;
    struct ldb_result *cached_pwd = NULL;
    const char *real_name = NULL;

    DEBUG(SSSDBG_TRACE_FUNC, ("Searching user by name (%s)\n", name));

    tmpctx = talloc_new(NULL);
    if (!tmpctx) {
        return ENOMEM;
    }

    pwd = talloc_zero(tmpctx, struct passwd);
    if (!pwd) {
        ret = ENOMEM;
        goto done;
    }

    buflen = DEFAULT_BUFSIZE;
    buffer = talloc_size(tmpctx, buflen);
    if (!buffer) {
        ret = ENOMEM;
        goto done;
    }

    /* FIXME: should we move this call outside the transaction to keep the
     * transaction as short as possible ? */
    status = ctx->ops.getpwnam_r(name, pwd, buffer, buflen, &ret);
    ret = handle_getpw_result(status, pwd, dom, &del_user);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("getpwnam failed [%d]: %s\n", ret, strerror(ret)));
        goto done;
    }

    if (del_user) {
        ret = delete_user(sysdb, name, 0);
        goto done;
    }

    uid = pwd->pw_uid;

    /* Canonicalize the username in case it was actually an alias */

    if (ctx->fast_alias == true) {
        ret = sysdb_getpwuid(tmpctx, sysdb, uid, &cached_pwd);
        if (ret != EOK) {
            /* Non-fatal, attempt to canonicalize online */
            DEBUG(SSSDBG_TRACE_FUNC, ("Request to cache failed [%d]: %s\n",
                  ret, strerror(ret)));
        }

        if (ret == EOK && cached_pwd->count == 1) {
            real_name = ldb_msg_find_attr_as_string(cached_pwd->msgs[0],
                                                    SYSDB_NAME, NULL);
            if (!real_name) {
                DEBUG(SSSDBG_MINOR_FAILURE, ("Cached user has no name?\n"));
            }
        }
    }

    if (real_name == NULL) {
        memset(buffer, 0, buflen);

        status = ctx->ops.getpwuid_r(uid, pwd, buffer, buflen, &ret);
        ret = handle_getpw_result(status, pwd, dom, &del_user);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE,
                ("getpwuid failed [%d]: %s\n", ret, strerror(ret)));
            goto done;
        }

        real_name = pwd->pw_name;
    }

    if (del_user) {
        ret = delete_user(sysdb, name, uid);
        goto done;
    }

    /* Both lookups went fine, we can save the user now */
    ret = save_user(sysdb, !dom->case_sensitive, pwd,
                    real_name, name, dom->user_timeout);

done:
    talloc_zfree(tmpctx);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("proxy -> getpwnam_r failed for '%s' <%d>: %s\n",
               name, ret, strerror(ret)));
    }
    return ret;
}

static int
handle_getpw_result(enum nss_status status, struct passwd *pwd,
                    struct sss_domain_info *dom, bool *del_user)
{
    int ret = EOK;

    if (!del_user) {
        return EINVAL;
    }
    *del_user = false;

    switch (status) {
    case NSS_STATUS_NOTFOUND:

        DEBUG(SSSDBG_MINOR_FAILURE, ("User not found.\n"));
        *del_user = true;
        break;

    case NSS_STATUS_SUCCESS:

        DEBUG(SSSDBG_TRACE_FUNC, ("User found: (%s, %d, %d)\n",
              pwd->pw_name, pwd->pw_uid, pwd->pw_gid));

        /* uid=0 or gid=0 are invalid values */
        /* also check that the id is in the valid range for this domain */
        if (OUT_OF_ID_RANGE(pwd->pw_uid, dom->id_min, dom->id_max) ||
            OUT_OF_ID_RANGE(pwd->pw_gid, dom->id_min, dom->id_max)) {

            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("User filtered out! (id out of range)\n"));
            *del_user = true;
            break;
        }
        break;

    case NSS_STATUS_UNAVAIL:
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Remote back end is not available. Entering offline mode\n"));
        ret = ENXIO;
        break;

    default:
        DEBUG(SSSDBG_OP_FAILURE, ("Unknown return code %d\n", status));
        ret = EIO;
        break;
    }

    return ret;
}

static int
delete_user(struct sysdb_ctx *sysdb, const char *name, uid_t uid)
{
    int ret = EOK;

    DEBUG(SSSDBG_TRACE_FUNC,
          ("User %s does not exist (or is invalid) on remote server,"
           " deleting!\n", name));
    ret = sysdb_delete_user(sysdb, name, uid);
    if (ret == ENOENT) {
        ret = EOK;
    }

    return ret;
}

static int save_user(struct sysdb_ctx *sysdb, bool lowercase,
                     struct passwd *pwd, const char *real_name,
                     const char *alias, uint64_t cache_timeout)
{
    const char *shell;
    char *lower;
    struct sysdb_attrs *attrs = NULL;
    errno_t ret;
    const char *cased_alias;

    if (pwd->pw_shell && pwd->pw_shell[0] != '\0') {
        shell = pwd->pw_shell;
    } else {
        shell = NULL;
    }

    if (lowercase || alias) {
        attrs = sysdb_new_attrs(NULL);
        if (!attrs) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Allocation error ?!\n"));
            return ENOMEM;
        }
    }

    if (lowercase) {
        lower = sss_tc_utf8_str_tolower(attrs, pwd->pw_name);
        if (!lower) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Cannot convert name to lowercase\n"));
            talloc_zfree(attrs);
            return ENOMEM;
        }

        ret = sysdb_attrs_add_string(attrs, SYSDB_NAME_ALIAS, lower);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE, ("Could not add name alias\n"));
            talloc_zfree(attrs);
            return ret;
        }
    }

    if (alias) {
        cased_alias = sss_get_cased_name(attrs, alias, !lowercase);
        if (!cased_alias) {
            talloc_zfree(attrs);
            return ENOMEM;
        }

        ret = sysdb_attrs_add_string(attrs, SYSDB_NAME_ALIAS, cased_alias);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE, ("Could not add name alias\n"));
            talloc_zfree(attrs);
            return ret;
        }
    }

    ret = sysdb_store_user(sysdb,
                           real_name,
                           pwd->pw_passwd,
                           pwd->pw_uid,
                           pwd->pw_gid,
                           pwd->pw_gecos,
                           pwd->pw_dir,
                           shell,
                           NULL,
                           attrs,
                           NULL,
                           cache_timeout,
                           0);
    talloc_zfree(attrs);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not add user to cache\n"));
        return ret;
    }

    return EOK;
}

/* =Getpwuid-wrapper======================================================*/

static int get_pw_uid(TALLOC_CTX *mem_ctx,
                      struct proxy_id_ctx *ctx,
                      struct sysdb_ctx *sysdb,
                      struct sss_domain_info *dom,
                      uid_t uid)
{
    TALLOC_CTX *tmpctx;
    struct passwd *pwd;
    enum nss_status status;
    char *buffer;
    size_t buflen;
    bool del_user = false;
    int ret;

    DEBUG(SSSDBG_TRACE_FUNC, ("Searching user by uid (%d)\n", uid));

    tmpctx = talloc_new(NULL);
    if (!tmpctx) {
        return ENOMEM;
    }

    pwd = talloc_zero(tmpctx, struct passwd);
    if (!pwd) {
        ret = ENOMEM;
        goto done;
    }

    buflen = DEFAULT_BUFSIZE;
    buffer = talloc_size(tmpctx, buflen);
    if (!buffer) {
        ret = ENOMEM;
        goto done;
    }

    status = ctx->ops.getpwuid_r(uid, pwd, buffer, buflen, &ret);
    ret = handle_getpw_result(status, pwd, dom, &del_user);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("getpwuid failed [%d]: %s\n", ret, strerror(ret)));
        goto done;
    }

    if (del_user) {
        ret = delete_user(sysdb, NULL, uid);
        goto done;
    }

    ret = save_user(sysdb, !dom->case_sensitive, pwd,
                    pwd->pw_name, NULL, dom->user_timeout);

done:
    talloc_zfree(tmpctx);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("proxy -> getpwuid_r failed for '%d' <%d>: %s\n",
               uid, ret, strerror(ret)));
    }
    return ret;
}

/* =Getpwent-wrapper======================================================*/

static int enum_users(TALLOC_CTX *mem_ctx,
                      struct proxy_id_ctx *ctx,
                      struct sysdb_ctx *sysdb,
                      struct sss_domain_info *dom)
{
    TALLOC_CTX *tmpctx;
    bool in_transaction = false;
    struct passwd *pwd;
    enum nss_status status;
    size_t buflen;
    char *buffer;
    char *newbuf;
    int ret;
    errno_t sret;
    bool again;

    DEBUG(SSSDBG_TRACE_LIBS, ("Enumerating users\n"));

    tmpctx = talloc_new(mem_ctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    pwd = talloc_zero(tmpctx, struct passwd);
    if (!pwd) {
        ret = ENOMEM;
        goto done;
    }

    buflen = DEFAULT_BUFSIZE;
    buffer = talloc_size(tmpctx, buflen);
    if (!buffer) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to start transaction\n"));
        goto done;
    }
    in_transaction = true;

    status = ctx->ops.setpwent();
    if (status != NSS_STATUS_SUCCESS) {
        ret = EIO;
        goto done;
    }

    do {
        again = false;

        /* always zero out the pwd structure */
        memset(pwd, 0, sizeof(struct passwd));

        /* get entry */
        status = ctx->ops.getpwent_r(pwd, buffer, buflen, &ret);

        switch (status) {
            case NSS_STATUS_TRYAGAIN:
                /* buffer too small ? */
                if (buflen < MAX_BUF_SIZE) {
                    buflen *= 2;
                }
                if (buflen > MAX_BUF_SIZE) {
                    buflen = MAX_BUF_SIZE;
                }
                newbuf = talloc_realloc_size(tmpctx, buffer, buflen);
                if (!newbuf) {
                    ret = ENOMEM;
                    goto done;
                }
                buffer = newbuf;
                again = true;
                break;

            case NSS_STATUS_NOTFOUND:

                /* we are done here */
                DEBUG(SSSDBG_TRACE_LIBS, ("Enumeration completed.\n"));

                ret = sysdb_transaction_commit(sysdb);
                if (ret != EOK) {
                    DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to commit transaction\n"));
                    goto done;
                }
                in_transaction = false;
                break;

            case NSS_STATUS_SUCCESS:

                DEBUG(SSSDBG_TRACE_LIBS, ("User found (%s, %d, %d)\n",
                            pwd->pw_name, pwd->pw_uid, pwd->pw_gid));

                /* uid=0 or gid=0 are invalid values */
                /* also check that the id is in the valid range for this domain
                 */
                if (OUT_OF_ID_RANGE(pwd->pw_uid, dom->id_min, dom->id_max) ||
                    OUT_OF_ID_RANGE(pwd->pw_gid, dom->id_min, dom->id_max)) {

                    DEBUG(SSSDBG_OP_FAILURE, ("User [%s] filtered out! (id out"
                        " of range)\n", pwd->pw_name));

                    again = true;
                    break;
                }

                ret = save_user(sysdb, !dom->case_sensitive, pwd,
                        pwd->pw_name, NULL, dom->user_timeout);
                if (ret) {
                    /* Do not fail completely on errors.
                     * Just report the failure to save and go on */
                    DEBUG(SSSDBG_OP_FAILURE, ("Failed to store user %s."
                                " Ignoring.\n", pwd->pw_name));
                }
                again = true;
                break;

            case NSS_STATUS_UNAVAIL:
                /* "remote" backend unavailable. Enter offline mode */
                ret = ENXIO;
                break;

            default:
                ret = EIO;
                DEBUG(SSSDBG_OP_FAILURE, ("proxy -> getpwent_r failed (%d)[%s]"
                            "\n", ret, strerror(ret)));
                break;
        }
    } while (again);

done:
    talloc_zfree(tmpctx);
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to cancel transaction\n"));
        }
    }
    ctx->ops.endpwent();
    return ret;
}

/* =Save-group-utilities=================================================*/
#define DEBUG_GR_MEM(level, grp) \
    do { \
        if (DEBUG_IS_SET(debug_get_level(level))) { \
            if (!grp->gr_mem || !grp->gr_mem[0]) { \
                DEBUG(level, ("Group %s has no members!\n", \
                              grp->gr_name)); \
            } else { \
                int i = 0; \
                while (grp->gr_mem[i]) { \
                    /* count */ \
                    i++; \
                } \
                DEBUG(level, ("Group %s has %d members!\n", \
                              grp->gr_name, i)); \
            } \
        } \
    } while(0)


static errno_t proxy_process_missing_users(struct sysdb_ctx *sysdb,
                                           struct sysdb_attrs *group_attrs,
                                           struct group *grp,
                                           time_t now);
static int save_group(struct sysdb_ctx *sysdb, struct sss_domain_info *dom,
                      struct group *grp, const char *real_name,
                      const char *alias, uint64_t cache_timeout)
{
    errno_t ret, sret;
    struct sysdb_attrs *attrs = NULL;
    char *lower;
    const char *cased_alias;
    TALLOC_CTX *tmp_ctx;
    time_t now = time(NULL);
    bool in_transaction = false;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    DEBUG_GR_MEM(7, grp);

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to start transaction\n"));
        goto done;
    }
    in_transaction = true;

    if (grp->gr_mem && grp->gr_mem[0]) {
        attrs = sysdb_new_attrs(tmp_ctx);
        if (!attrs) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Allocation error ?!\n"));
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_attrs_users_from_str_list(
                attrs, SYSDB_MEMBER, dom->name,
                (const char *const *)grp->gr_mem);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE, ("Could not add group members\n"));
            goto done;
        }

        /* Create ghost users */
        ret = proxy_process_missing_users(sysdb, attrs, grp, now);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("Could not add missing members\n"));
            goto done;
        }
    }

    if (dom->case_sensitive == false || alias) {
        if (!attrs) {
            attrs = sysdb_new_attrs(tmp_ctx);
            if (!attrs) {
                DEBUG(SSSDBG_CRIT_FAILURE, ("Allocation error ?!\n"));
                ret = ENOMEM;
                goto done;
            }
        }

        if (dom->case_sensitive == false) {
            lower = sss_tc_utf8_str_tolower(attrs, grp->gr_name);
            if (!lower) {
                DEBUG(SSSDBG_CRIT_FAILURE, ("Cannot convert name to lowercase\n"));
                ret = ENOMEM;
                goto done;
            }

            ret = sysdb_attrs_add_string(attrs, SYSDB_NAME_ALIAS, lower);
            if (ret) {
                DEBUG(SSSDBG_OP_FAILURE, ("Could not add name alias\n"));
                ret = ENOMEM;
                goto done;
            }
        }

        if (alias) {
            cased_alias = sss_get_cased_name(attrs, alias, dom->case_sensitive);
            if (!cased_alias) {
                talloc_zfree(attrs);
                return ENOMEM;
            }

            ret = sysdb_attrs_add_string(attrs, SYSDB_NAME_ALIAS, cased_alias);
            if (ret) {
                DEBUG(SSSDBG_OP_FAILURE, ("Could not add name alias\n"));
                ret = ENOMEM;
                goto done;
            }
        }
    }

    ret = sysdb_store_group(sysdb,
                            real_name,
                            grp->gr_gid,
                            attrs,
                            cache_timeout,
                            now);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not add group to cache\n"));
        goto done;
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Could not commit transaction: [%s]\n",
               strerror(ret)));
        goto done;
    }
    in_transaction = false;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Could not cancel transaction\n"));
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t proxy_process_missing_users(struct sysdb_ctx *sysdb,
                                           struct sysdb_attrs *group_attrs,
                                           struct group *grp,
                                           time_t now)
{
    errno_t ret;
    size_t i;
    TALLOC_CTX *tmp_ctx = NULL;
    struct ldb_message *msg;

    if (!sysdb || !grp) return EINVAL;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    for (i = 0; grp->gr_mem[i]; i++) {
        ret = sysdb_search_user_by_name(tmp_ctx, sysdb, grp->gr_mem[i],
                                        NULL, &msg);
        if (ret == EOK) {
            /* Member already exists in the cache */
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  ("Member [%s] already cached\n", grp->gr_mem[i]));
            /* clean up */
            talloc_zfree(msg);
            continue;
        } else if (ret == ENOENT) {
            /* No entry for this user. Create a ghost user */
            DEBUG(SSSDBG_TRACE_LIBS,
                  ("Member [%s] not cached, creating ghost user entry\n",
                   grp->gr_mem[i]));

            ret = sysdb_attrs_add_string(group_attrs, SYSDB_GHOST, grp->gr_mem[i]);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      ("Cannot store ghost user entry: [%d]: %s\n",
                       ret, strerror(ret)));
                goto done;
            }
        } else {
            /* Unexpected error */
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Error searching cache for user [%s]: [%s]\n",
                   grp->gr_mem[i], strerror(ret)));
            goto done;
        }
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

/* =Getgrnam-wrapper======================================================*/
static char *
grow_group_buffer(TALLOC_CTX *mem_ctx,
                  char **buffer, size_t *buflen)
{
    char *newbuf;

    if (*buflen == 0) {
        *buflen = DEFAULT_BUFSIZE;
    }
    if (*buflen < MAX_BUF_SIZE) {
        *buflen *= 2;
    }
    if (*buflen > MAX_BUF_SIZE) {
        *buflen = MAX_BUF_SIZE;
    }

    newbuf = talloc_realloc_size(mem_ctx, *buffer, *buflen);
    if (!newbuf) {
        return NULL;
    }
    *buffer = newbuf;

    return *buffer;
}

static errno_t
handle_getgr_result(enum nss_status status, struct group *grp,
                    struct sss_domain_info *dom,
                    bool *delete_group)
{
    switch (status) {
    case NSS_STATUS_TRYAGAIN:
        DEBUG(SSSDBG_MINOR_FAILURE, ("Buffer too small\n"));
        return EAGAIN;

    case NSS_STATUS_NOTFOUND:
        DEBUG(SSSDBG_MINOR_FAILURE, ("Group not found.\n"));
        *delete_group = true;
        break;

    case NSS_STATUS_SUCCESS:
        DEBUG(SSSDBG_FUNC_DATA, ("Group found: (%s, %d)\n",
              grp->gr_name, grp->gr_gid));

        /* gid=0 is an invalid value */
        /* also check that the id is in the valid range for this domain */
        if (OUT_OF_ID_RANGE(grp->gr_gid, dom->id_min, dom->id_max)) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Group filtered out! (id out of range)\n"));
            *delete_group = true;
            break;
        }
        break;

    case NSS_STATUS_UNAVAIL:
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Remote back end is not available. Entering offline mode\n"));
        return ENXIO;

    default:
        DEBUG(SSSDBG_OP_FAILURE, ("Unknown return code %d\n", status));
        return EIO;
    }

    return EOK;
}

static int get_gr_name(TALLOC_CTX *mem_ctx,
                       struct proxy_id_ctx *ctx,
                       struct sysdb_ctx *sysdb,
                       struct sss_domain_info *dom,
                       const char *name)
{
    TALLOC_CTX *tmpctx;
    struct group *grp;
    enum nss_status status;
    char *buffer = 0;
    size_t buflen = 0;
    bool delete_group = false;
    int ret;
    gid_t gid;
    struct ldb_result *cached_grp = NULL;
    const char *real_name = NULL;

    DEBUG(SSSDBG_FUNC_DATA, ("Searching group by name (%s)\n", name));

    tmpctx = talloc_new(NULL);
    if (!tmpctx) {
        return ENOMEM;
    }

    grp = talloc(tmpctx, struct group);
    if (!grp) {
        ret = ENOMEM;
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("proxy -> getgrnam_r failed for '%s': [%d] %s\n",
              name, ret, strerror(ret)));
        goto done;
    }

    do {
        /* always zero out the grp structure */
        memset(grp, 0, sizeof(struct group));
        buffer = grow_group_buffer(tmpctx, &buffer, &buflen);
        if (!buffer) {
            ret = ENOMEM;
            goto done;
        }

        status = ctx->ops.getgrnam_r(name, grp, buffer, buflen, &ret);

        ret = handle_getgr_result(status, grp, dom, &delete_group);
    } while (ret == EAGAIN);

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("getgrnam failed [%d]: %s\n", ret, strerror(ret)));
        goto done;
    }

    gid = grp->gr_gid;

    /* Canonicalize the group name in case it was actually an alias */
    if (ctx->fast_alias == true) {
        ret = sysdb_getgrgid(tmpctx, sysdb, gid, &cached_grp);
        if (ret != EOK) {
            /* Non-fatal, attempt to canonicalize online */
            DEBUG(SSSDBG_TRACE_FUNC, ("Request to cache failed [%d]: %s\n",
                  ret, strerror(ret)));
        }

        if (ret == EOK && cached_grp->count == 1) {
            real_name = ldb_msg_find_attr_as_string(cached_grp->msgs[0],
                                                    SYSDB_NAME, NULL);
            if (!real_name) {
                DEBUG(SSSDBG_MINOR_FAILURE, ("Cached group has no name?\n"));
            }
        }
    }

    if (real_name == NULL) {
        talloc_zfree(buffer);
        buflen = 0;

        do {
            memset(grp, 0, sizeof(struct group));
            buffer = grow_group_buffer(tmpctx, &buffer, &buflen);
            if (!buffer) {
                ret = ENOMEM;
                goto done;
            }

            status = ctx->ops.getgrgid_r(gid, grp, buffer, buflen, &ret);

            ret = handle_getgr_result(status, grp, dom, &delete_group);
        } while (ret == EAGAIN);

        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                ("getgrgid failed [%d]: %s\n", ret, strerror(ret)));
            goto done;
        }

        real_name = grp->gr_name;
    }

    if (delete_group) {
        DEBUG(SSSDBG_TRACE_FUNC,
              ("Group %s does not exist (or is invalid) on remote server,"
               " deleting!\n", name));

        ret = sysdb_delete_group(sysdb, NULL, gid);
        if (ret == ENOENT) {
            ret = EOK;
        }
        goto done;
    }

    ret = save_group(sysdb, dom, grp, real_name, name, dom->group_timeout);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Cannot save group [%d]: %s\n", ret, strerror(ret)));
        goto done;
    }

done:
    talloc_zfree(tmpctx);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("proxy -> getgrnam_r failed for '%s' <%d>: %s\n",
              name, ret, strerror(ret)));
    }
    return ret;
}

/* =Getgrgid-wrapper======================================================*/
static int get_gr_gid(TALLOC_CTX *mem_ctx,
                      struct proxy_id_ctx *ctx,
                      struct sysdb_ctx *sysdb,
                      struct sss_domain_info *dom,
                      gid_t gid,
                      time_t now)
{
    TALLOC_CTX *tmpctx;
    struct group *grp;
    enum nss_status status;
    char *buffer = NULL;
    size_t buflen = 0;
    bool delete_group = false;
    int ret;

    DEBUG(SSSDBG_TRACE_FUNC, ("Searching group by gid (%d)\n", gid));

    tmpctx = talloc_new(mem_ctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    grp = talloc(tmpctx, struct group);
    if (!grp) {
        ret = ENOMEM;
        goto done;
    }

    do {
        /* always zero out the grp structure */
        memset(grp, 0, sizeof(struct group));
        buffer = grow_group_buffer(tmpctx, &buffer, &buflen);
        if (!buffer) {
            ret = ENOMEM;
            goto done;
        }

        status = ctx->ops.getgrgid_r(gid, grp, buffer, buflen, &ret);

        ret = handle_getgr_result(status, grp, dom, &delete_group);
    } while (ret == EAGAIN);

    if (delete_group) {
        DEBUG(SSSDBG_TRACE_FUNC,
              ("Group %d does not exist (or is invalid) on remote server,"
               " deleting!\n", gid));

        ret = sysdb_delete_group(sysdb, NULL, gid);
        if (ret == ENOENT) {
            ret = EOK;
        }
        goto done;
    }

    ret = save_group(sysdb, dom, grp, grp->gr_name, NULL, dom->group_timeout);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Cannot save user [%d]: %s\n", ret, strerror(ret)));
        goto done;
    }

done:
    talloc_zfree(tmpctx);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("proxy -> getgrgid_r failed for '%d' <%d>: %s\n",
               gid, ret, strerror(ret)));
    }
    return ret;
}

/* =Getgrent-wrapper======================================================*/

static int enum_groups(TALLOC_CTX *mem_ctx,
                       struct proxy_id_ctx *ctx,
                       struct sysdb_ctx *sysdb,
                       struct sss_domain_info *dom)
{
    TALLOC_CTX *tmpctx;
    bool in_transaction = false;
    struct group *grp;
    enum nss_status status;
    size_t buflen;
    char *buffer;
    char *newbuf;
    int ret;
    errno_t sret;
    bool again;

    DEBUG(SSSDBG_TRACE_LIBS, ("Enumerating groups\n"));

    tmpctx = talloc_new(mem_ctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    grp = talloc(tmpctx, struct group);
    if (!grp) {
        ret = ENOMEM;
        goto done;
    }

    buflen = DEFAULT_BUFSIZE;
    buffer = talloc_size(tmpctx, buflen);
    if (!buffer) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to start transaction\n"));
        goto done;
    }
    in_transaction = true;

    status = ctx->ops.setgrent();
    if (status != NSS_STATUS_SUCCESS) {
        ret = EIO;
        goto done;
    }

    do {
        again = false;

        /* always zero out the grp structure */
        memset(grp, 0, sizeof(struct group));

        /* get entry */
        status = ctx->ops.getgrent_r(grp, buffer, buflen, &ret);

        switch (status) {
            case NSS_STATUS_TRYAGAIN:
                /* buffer too small ? */
                if (buflen < MAX_BUF_SIZE) {
                    buflen *= 2;
                }
                if (buflen > MAX_BUF_SIZE) {
                    buflen = MAX_BUF_SIZE;
                }
                newbuf = talloc_realloc_size(tmpctx, buffer, buflen);
                if (!newbuf) {
                    ret = ENOMEM;
                    goto done;
                }
                buffer = newbuf;
                again = true;
                break;

            case NSS_STATUS_NOTFOUND:

                /* we are done here */
                DEBUG(SSSDBG_TRACE_LIBS, ("Enumeration completed.\n"));

                ret = sysdb_transaction_commit(sysdb);
                if (ret != EOK) {
                    DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to commit transaction\n"));
                    goto done;
                }
                in_transaction = false;
                break;

            case NSS_STATUS_SUCCESS:

                DEBUG(SSSDBG_OP_FAILURE, ("Group found (%s, %d)\n",
                            grp->gr_name, grp->gr_gid));

                /* gid=0 is an invalid value */
                /* also check that the id is in the valid range for this domain
                 */
                if (OUT_OF_ID_RANGE(grp->gr_gid, dom->id_min, dom->id_max)) {

                    DEBUG(SSSDBG_OP_FAILURE, ("Group [%s] filtered out! (id"
                        "out of range)\n", grp->gr_name));

                    again = true;
                    break;
                }

                ret = save_group(sysdb, dom, grp, grp->gr_name,
                        NULL, dom->group_timeout);
                if (ret) {
                    /* Do not fail completely on errors.
                     * Just report the failure to save and go on */
                    DEBUG(SSSDBG_OP_FAILURE, ("Failed to store group."
                                "Ignoring\n"));
                }
                again = true;
                break;

            case NSS_STATUS_UNAVAIL:
                /* "remote" backend unavailable. Enter offline mode */
                ret = ENXIO;
                break;

            default:
                ret = EIO;
                DEBUG(SSSDBG_OP_FAILURE, ("proxy -> getgrent_r failed (%d)[%s]"
                            "\n", ret, strerror(ret)));
                break;
        }
    } while (again);

done:
    talloc_zfree(tmpctx);
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to cancel transaction\n"));
        }
    }
    ctx->ops.endgrent();
    return ret;
}


/* =Initgroups-wrapper====================================================*/

static int get_initgr_groups_process(TALLOC_CTX *memctx,
                                     struct proxy_id_ctx *ctx,
                                     struct sysdb_ctx *sysdb,
                                     struct sss_domain_info *dom,
                                     struct passwd *pwd);

static int get_initgr(TALLOC_CTX *mem_ctx,
                      struct proxy_id_ctx *ctx,
                      struct sysdb_ctx *sysdb,
                      struct sss_domain_info *dom,
                      const char *name)
{
    TALLOC_CTX *tmpctx;
    bool in_transaction = false;
    struct passwd *pwd;
    enum nss_status status;
    char *buffer;
    size_t buflen;
    int ret;
    errno_t sret;
    bool del_user;
    uid_t uid;
    struct ldb_result *cached_pwd = NULL;
    const char *real_name = NULL;

    tmpctx = talloc_new(mem_ctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    pwd = talloc_zero(tmpctx, struct passwd);
    if (!pwd) {
        ret = ENOMEM;
        goto fail;
    }

    buflen = DEFAULT_BUFSIZE;
    buffer = talloc_size(tmpctx, buflen);
    if (!buffer) {
        ret = ENOMEM;
        goto fail;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to start transaction\n"));
        goto fail;
    }
    in_transaction = true;

    /* FIXME: should we move this call outside the transaction to keep the
     * transaction as short as possible ? */
    status = ctx->ops.getpwnam_r(name, pwd, buffer, buflen, &ret);
    ret = handle_getpw_result(status, pwd, dom, &del_user);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("getpwnam failed [%d]: %s\n", ret, strerror(ret)));
        goto fail;
    }

    if (del_user) {
        ret = delete_user(sysdb, name, 0);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE, ("Could not delete user\n"));
            goto fail;
        }
        goto done;
    }

    uid = pwd->pw_uid;
    memset(buffer, 0, buflen);

    /* Canonicalize the username in case it was actually an alias */
    if (ctx->fast_alias == true) {
        ret = sysdb_getpwuid(tmpctx, sysdb, uid, &cached_pwd);
        if (ret != EOK) {
            /* Non-fatal, attempt to canonicalize online */
            DEBUG(SSSDBG_TRACE_FUNC, ("Request to cache failed [%d]: %s\n",
                  ret, strerror(ret)));
        }

        if (ret == EOK && cached_pwd->count == 1) {
            real_name = ldb_msg_find_attr_as_string(cached_pwd->msgs[0],
                                                    SYSDB_NAME, NULL);
            if (!real_name) {
                DEBUG(SSSDBG_MINOR_FAILURE, ("Cached user has no name?\n"));
            }
        }
    }

    if (real_name == NULL) {
        memset(buffer, 0, buflen);

        status = ctx->ops.getpwuid_r(uid, pwd, buffer, buflen, &ret);
        ret = handle_getpw_result(status, pwd, dom, &del_user);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE,
                ("getpwuid failed [%d]: %s\n", ret, strerror(ret)));
            goto done;
        }

        real_name = pwd->pw_name;
    }

    if (del_user) {
        ret = delete_user(sysdb, name, uid);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE, ("Could not delete user\n"));
            goto fail;
        }
        goto done;
    }

    ret = save_user(sysdb, !dom->case_sensitive, pwd,
                    real_name, name, dom->user_timeout);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not save user\n"));
        goto fail;
    }

    ret = get_initgr_groups_process(tmpctx, ctx, sysdb, dom, pwd);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not process initgroups\n"));
        goto fail;
    }

done:
    ret = sysdb_transaction_commit(sysdb);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, ("Failed to commit transaction\n"));
        goto fail;
    }
    in_transaction = false;

fail:
    talloc_zfree(tmpctx);
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to cancel transaction\n"));
        }
    }
    return ret;
}

static int get_initgr_groups_process(TALLOC_CTX *memctx,
                                     struct proxy_id_ctx *ctx,
                                     struct sysdb_ctx *sysdb,
                                     struct sss_domain_info *dom,
                                     struct passwd *pwd)
{
    enum nss_status status;
    long int limit;
    long int size;
    long int num;
    long int num_gids;
    gid_t *gids;
    int ret;
    int i;
    time_t now;

    num_gids = 0;
    limit = 4096;
    num = 4096;
    size = num*sizeof(gid_t);
    gids = talloc_size(memctx, size);
    if (!gids) {
        return ENOMEM;
    }

    /* FIXME: should we move this call outside the transaction to keep the
     * transaction as short as possible ? */
    do {
        status = ctx->ops.initgroups_dyn(pwd->pw_name, pwd->pw_gid, &num_gids,
                &num, &gids, limit, &ret);

        if (status == NSS_STATUS_TRYAGAIN) {
            /* buffer too small ? */
            if (size < MAX_BUF_SIZE) {
                num *= 2;
                size = num*sizeof(gid_t);
            }
            if (size > MAX_BUF_SIZE) {
                size = MAX_BUF_SIZE;
                num = size/sizeof(gid_t);
            }
            limit = num;
            gids = talloc_realloc_size(memctx, gids, size);
            if (!gids) {
                return ENOMEM;
            }
        }
    } while(status == NSS_STATUS_TRYAGAIN);

    switch (status) {
    case NSS_STATUS_SUCCESS:
        DEBUG(SSSDBG_CONF_SETTINGS, ("User [%s] appears to be member of %lu"
                    "groups\n", pwd->pw_name, num_gids));

        now = time(NULL);
        for (i = 0; i < num_gids; i++) {
            ret = get_gr_gid(memctx, ctx, sysdb, dom, gids[i], now);
            if (ret) {
                return ret;
            }
        }
        ret = EOK;

        break;

    default:
        DEBUG(2, ("proxy -> initgroups_dyn failed (%d)[%s]\n",
                  ret, strerror(ret)));
        ret = EIO;
        break;
    }

    return ret;
}

/* =Proxy_Id-Functions====================================================*/

void proxy_get_account_info(struct be_req *breq)
{
    struct be_acct_req *ar;
    struct proxy_id_ctx *ctx;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;
    uid_t uid;
    gid_t gid;
    int ret;
    char *endptr;

    ar = talloc_get_type(breq->req_data, struct be_acct_req);
    ctx = talloc_get_type(breq->be_ctx->bet_info[BET_ID].pvt_bet_data,
                          struct proxy_id_ctx);
    sysdb = breq->be_ctx->sysdb;
    domain = breq->be_ctx->domain;

    if (be_is_offline(breq->be_ctx)) {
        return proxy_reply(breq, DP_ERR_OFFLINE, EAGAIN, "Offline");
    }

    /* for now we support only core attrs */
    if (ar->attr_type != BE_ATTR_CORE) {
        return proxy_reply(breq, DP_ERR_FATAL, EINVAL, "Invalid attr type");
    }

    switch (ar->entry_type & 0xFFF) {
    case BE_REQ_USER: /* user */
        switch (ar->filter_type) {
        case BE_FILTER_ENUM:
            ret = enum_users(breq, ctx, sysdb, domain);
            break;

        case BE_FILTER_NAME:
            ret = get_pw_name(breq, ctx, sysdb, domain, ar->filter_value);
            break;

        case BE_FILTER_IDNUM:
            uid = (uid_t) strtouint32(ar->filter_value, &endptr, 10);
            if (errno || *endptr || (ar->filter_value == endptr)) {
                return proxy_reply(breq, DP_ERR_FATAL,
                                   EINVAL, "Invalid attr type");
            }
            ret = get_pw_uid(breq, ctx, sysdb, domain, uid);
            break;
        default:
            return proxy_reply(breq, DP_ERR_FATAL,
                               EINVAL, "Invalid filter type");
        }
        break;

    case BE_REQ_GROUP: /* group */
        switch (ar->filter_type) {
        case BE_FILTER_ENUM:
            ret = enum_groups(breq, ctx, sysdb, domain);
            break;
        case BE_FILTER_NAME:
            ret = get_gr_name(breq, ctx, sysdb, domain, ar->filter_value);
            break;
        case BE_FILTER_IDNUM:
            gid = (gid_t) strtouint32(ar->filter_value, &endptr, 10);
            if (errno || *endptr || (ar->filter_value == endptr)) {
                return proxy_reply(breq, DP_ERR_FATAL,
                                   EINVAL, "Invalid attr type");
            }
            ret = get_gr_gid(breq, ctx, sysdb, domain, gid, 0);
            break;
        default:
            return proxy_reply(breq, DP_ERR_FATAL,
                               EINVAL, "Invalid filter type");
        }
        break;

    case BE_REQ_INITGROUPS: /* init groups for user */
        if (ar->filter_type != BE_FILTER_NAME) {
            return proxy_reply(breq, DP_ERR_FATAL,
                               EINVAL, "Invalid filter type");
        }
        if (ctx->ops.initgroups_dyn == NULL) {
            return proxy_reply(breq, DP_ERR_FATAL,
                               ENODEV, "Initgroups call not supported");
        }
        ret = get_initgr(breq, ctx, sysdb, domain, ar->filter_value);
        break;

    case BE_REQ_NETGROUP:
        if (ar->filter_type != BE_FILTER_NAME) {
            return proxy_reply(breq, DP_ERR_FATAL,
                               EINVAL, "Invalid filter type");
        }
        if (ctx->ops.setnetgrent == NULL || ctx->ops.getnetgrent_r == NULL ||
            ctx->ops.endnetgrent == NULL) {
            return proxy_reply(breq, DP_ERR_FATAL,
                               ENODEV, "Netgroups are not supported");
        }

        ret = get_netgroup(ctx, sysdb, domain, ar->filter_value);
        break;

    case BE_REQ_SERVICES:
        switch (ar->filter_type) {
        case BE_FILTER_NAME:
            if (ctx->ops.getservbyname_r == NULL) {
                return proxy_reply(breq, DP_ERR_FATAL,
                                   ENODEV, "Services are not supported");
            }
            ret = get_serv_byname(ctx, sysdb, domain,
                                  ar->filter_value,
                                  ar->extra_value);
            break;
        case BE_FILTER_IDNUM:
            if (ctx->ops.getservbyport_r == NULL) {
                return proxy_reply(breq, DP_ERR_FATAL,
                                   ENODEV, "Services are not supported");
            }
            ret = get_serv_byport(ctx, sysdb, domain,
                                  ar->filter_value,
                                  ar->extra_value);
            break;
        case BE_FILTER_ENUM:
            if (!ctx->ops.setservent
                    || !ctx->ops.getservent_r
                    || !ctx->ops.endservent) {
                return proxy_reply(breq, DP_ERR_FATAL,
                                   ENODEV, "Services are not supported");
            }
            ret = enum_services(ctx, sysdb, domain);
            break;
        default:
            return proxy_reply(breq, DP_ERR_FATAL,
                               EINVAL, "Invalid filter type");
        }
        break;

    default: /*fail*/
        return proxy_reply(breq, DP_ERR_FATAL,
                           EINVAL, "Invalid request type");
    }

    if (ret) {
        if (ret == ENXIO) {
            DEBUG(2, ("proxy returned UNAVAIL error, going offline!\n"));
            be_mark_offline(breq->be_ctx);
        }
        proxy_reply(breq, DP_ERR_FATAL, ret, NULL);
        return;
    }
    proxy_reply(breq, DP_ERR_OK, EOK, NULL);
}
