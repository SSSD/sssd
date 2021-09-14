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

#include <dhash.h>
#include "config.h"

#include "util/sss_format.h"
#include "util/strtonum.h"
#include "providers/proxy/proxy.h"

/* =Getpwnam-wrapper======================================================*/

static int save_user(struct sss_domain_info *domain,
                     struct passwd *pwd, const char *real_name,
                     const char *alias);

static int
handle_getpw_result(enum nss_status status, struct passwd *pwd,
                    struct sss_domain_info *dom, bool *del_user);

static int
delete_user(struct sss_domain_info *domain,
            const char *name, uid_t uid);

static int get_pw_name(struct proxy_id_ctx *ctx,
                       struct sss_domain_info *dom,
                       const char *i_name)
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
    char *shortname_or_alias;

    DEBUG(SSSDBG_TRACE_FUNC, "Searching user by name (%s)\n", i_name);

    tmpctx = talloc_new(NULL);
    if (!tmpctx) {
        return ENOMEM;
    }

    ret = sss_parse_internal_fqname(tmpctx, i_name, &shortname_or_alias, NULL);
    if (ret != EOK) {
        goto done;
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
     * transaction as short as possible? */
    status = ctx->ops.getpwnam_r(shortname_or_alias, pwd, buffer, buflen, &ret);
    ret = handle_getpw_result(status, pwd, dom, &del_user);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE,
              "getpwnam failed [%d]: %s\n", ret, strerror(ret));
        goto done;
    }

    if (del_user) {
        ret = delete_user(dom, i_name, 0);
        goto done;
    }

    uid = pwd->pw_uid;

    /* Canonicalize the username in case it was actually an alias */

    if (ctx->fast_alias == true) {
        ret = sysdb_getpwuid(tmpctx, dom, uid, &cached_pwd);
        if (ret != EOK) {
            /* Non-fatal, attempt to canonicalize online */
            DEBUG(SSSDBG_TRACE_FUNC, "Request to cache failed [%d]: %s\n",
                  ret, strerror(ret));
        }

        if (ret == EOK && cached_pwd->count == 1) {
            real_name = ldb_msg_find_attr_as_string(cached_pwd->msgs[0],
                                                    SYSDB_NAME, NULL);
            if (!real_name) {
                DEBUG(SSSDBG_MINOR_FAILURE, "Cached user has no name?\n");
            }
        }
    }

    if (real_name == NULL) {
        memset(buffer, 0, buflen);

        status = ctx->ops.getpwuid_r(uid, pwd, buffer, buflen, &ret);
        ret = handle_getpw_result(status, pwd, dom, &del_user);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE,
                "getpwuid failed [%d]: %s\n", ret, strerror(ret));
            goto done;
        }

        real_name = sss_create_internal_fqname(tmpctx, pwd->pw_name, dom->name);
        if (real_name == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    if (del_user) {
        ret = delete_user(dom, i_name, uid);
        goto done;
    }

    /* Both lookups went fine, we can save the user now */
    ret = save_user(dom, pwd, real_name, i_name);

done:
    talloc_zfree(tmpctx);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE,
              "proxy -> getpwnam_r failed for '%s' <%d>: %s\n",
               i_name, ret, strerror(ret));
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

        DEBUG(SSSDBG_TRACE_FUNC, "User not found.\n");
        *del_user = true;
        break;

    case NSS_STATUS_SUCCESS:

        DEBUG(SSSDBG_TRACE_FUNC, "User found: (%s, %"SPRIuid", %"SPRIgid")\n",
              pwd->pw_name, pwd->pw_uid, pwd->pw_gid);

        /* uid=0 or gid=0 are invalid values */
        /* also check that the id is in the valid range for this domain */
        if (OUT_OF_ID_RANGE(pwd->pw_uid, dom->id_min, dom->id_max) ||
            OUT_OF_ID_RANGE(pwd->pw_gid, dom->id_min, dom->id_max)) {

            DEBUG(SSSDBG_MINOR_FAILURE,
                  "User filtered out! (id out of range)\n");
            *del_user = true;
            break;
        }
        break;

    case NSS_STATUS_UNAVAIL:
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Remote back end is not available. Entering offline mode\n");
        ret = ENXIO;
        break;

    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unknown return code %d\n", status);
        ret = EIO;
        break;
    }

    return ret;
}

static int
delete_user(struct sss_domain_info *domain,
            const char *name, uid_t uid)
{
    int ret = EOK;

    if (name != NULL) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "User %s does not exist (or is invalid) on remote server,"
              " deleting!\n", name);
    } else {
        DEBUG(SSSDBG_TRACE_FUNC,
              "User with UID %"SPRIuid" does not exist (or is invalid) "
              "on remote server, deleting!\n", uid);
    }

    ret = sysdb_delete_user(domain, name, uid);
    if (ret == ENOENT) {
        ret = EOK;
    }

    return ret;
}

static int
prepare_attrs_for_saving_ops(TALLOC_CTX *mem_ctx,
                             bool case_sensitive,
                             const char *real_name, /* already_qualified */
                             const char *alias, /* already qualified */
                             struct sysdb_attrs **attrs)
{
    const char *lc_name = NULL;
    const char *cased_alias = NULL;
    errno_t ret;

    if (!case_sensitive || alias != NULL) {
        if (*attrs == NULL) {
            *attrs = sysdb_new_attrs(mem_ctx);
            if (*attrs == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Allocation error?!\n");
                ret = ENOMEM;
                goto done;
            }
        }
    }

    if (!case_sensitive) {
        lc_name = sss_tc_utf8_str_tolower(*attrs, real_name);
        if (lc_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Cannot convert name to lowercase.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_attrs_add_string(*attrs, SYSDB_NAME_ALIAS, lc_name);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not add name alias\n");
            ret = ENOMEM;
            goto done;
        }

    }

    if (alias != NULL) {
        cased_alias = sss_get_cased_name(*attrs, alias, case_sensitive);
        if (cased_alias == NULL) {
            ret = ENOMEM;
            goto done;
        }

        /* Add the alias only if it differs from lowercased pw_name */
        if (lc_name == NULL || strcmp(cased_alias, lc_name) != 0) {
            ret = sysdb_attrs_add_string(*attrs, SYSDB_NAME_ALIAS,
                                         cased_alias);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "Could not add name alias\n");
                goto done;
            }
        }
    }

    ret = EOK;
done:
    return ret;
}

static int save_user(struct sss_domain_info *domain,
                     struct passwd *pwd,
                     const char *real_name, /* already qualified */
                     const char *alias) /* already qualified */
{
    const char *shell;
    const char *gecos;
    struct sysdb_attrs *attrs = NULL;
    errno_t ret;

    if (pwd->pw_shell && pwd->pw_shell[0] != '\0') {
        shell = pwd->pw_shell;
    } else {
        shell = NULL;
    }

    if (pwd->pw_gecos && pwd->pw_gecos[0] != '\0') {
        gecos = pwd->pw_gecos;
    } else {
        gecos = NULL;
    }

    ret = prepare_attrs_for_saving_ops(NULL, domain->case_sensitive,
                                       real_name, alias, &attrs);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_store_user(domain,
                           real_name,
                           pwd->pw_passwd,
                           pwd->pw_uid,
                           pwd->pw_gid,
                           gecos,
                           pwd->pw_dir,
                           shell,
                           NULL,
                           attrs,
                           NULL,
                           domain->user_timeout,
                           0);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not add user to cache\n");
        goto done;
    }

done:
    talloc_zfree(attrs);
    return ret;
}

/* =Getpwuid-wrapper======================================================*/

static int get_pw_uid(struct proxy_id_ctx *ctx,
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
    char *name;

    DEBUG(SSSDBG_TRACE_FUNC, "Searching user by uid (%"SPRIuid")\n", uid);

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
              "getpwuid failed [%d]: %s\n", ret, strerror(ret));
        goto done;
    }

    if (del_user) {
        ret = delete_user(dom, NULL, uid);
        goto done;
    }

    name = sss_create_internal_fqname(tmpctx, pwd->pw_name, dom->name);
    if (name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "failed to qualify name '%s'\n",
              pwd->pw_name);
        goto done;
    }
    ret = save_user(dom, pwd, name, NULL);

done:
    talloc_zfree(tmpctx);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "proxy -> getpwuid_r failed for '%"SPRIuid"' <%d>: %s\n",
               uid, ret, strerror(ret));
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
    char *name;

    DEBUG(SSSDBG_TRACE_LIBS, "Enumerating users\n");

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
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
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
                /* buffer too small? */
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
                DEBUG(SSSDBG_TRACE_LIBS, "Enumeration completed.\n");

                ret = sysdb_transaction_commit(sysdb);
                if (ret != EOK) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction\n");
                    goto done;
                }
                in_transaction = false;
                break;

            case NSS_STATUS_SUCCESS:

                DEBUG(SSSDBG_TRACE_LIBS,
                      "User found (%s, %"SPRIuid", %"SPRIgid")\n",
                       pwd->pw_name, pwd->pw_uid, pwd->pw_gid);

                /* uid=0 or gid=0 are invalid values */
                /* also check that the id is in the valid range for this domain
                 */
                if (OUT_OF_ID_RANGE(pwd->pw_uid, dom->id_min, dom->id_max) ||
                    OUT_OF_ID_RANGE(pwd->pw_gid, dom->id_min, dom->id_max)) {

                    DEBUG(SSSDBG_OP_FAILURE, "User [%s] filtered out! (id out"
                        " of range)\n", pwd->pw_name);

                    again = true;
                    break;
                }

                name = sss_create_internal_fqname(tmpctx, pwd->pw_name, dom->name);
                if (name == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "failed to create internal name '%s'\n",
                          pwd->pw_name);
                    goto done;
                }
                ret = save_user(dom, pwd, name, NULL);
                if (ret) {
                    /* Do not fail completely on errors.
                     * Just report the failure to save and go on */
                    DEBUG(SSSDBG_OP_FAILURE, "Failed to store user %s."
                                " Ignoring.\n", pwd->pw_name);
                }
                again = true;
                break;

            case NSS_STATUS_UNAVAIL:
                /* "remote" backend unavailable. Enter offline mode */
                ret = ENXIO;
                break;

            default:
                ret = EIO;
                DEBUG(SSSDBG_OP_FAILURE, "proxy -> getpwent_r failed (%d)[%s]"
                            "\n", ret, strerror(ret));
                break;
        }
    } while (again);

done:
    talloc_zfree(tmpctx);
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to cancel transaction\n");
        }
    }
    ctx->ops.endpwent();
    return ret;
}

/* =Save-group-utilities=================================================*/
#define DEBUG_GR_MEM(level, grp) \
    do { \
        if (!grp->gr_mem || !grp->gr_mem[0]) { \
            DEBUG(level, "Group %s has no members!\n", \
                          grp->gr_name); \
        } else { \
            int i = 0; \
            while (grp->gr_mem[i]) { \
                /* count */ \
                i++; \
            } \
            DEBUG(level, "Group %s has %d members!\n", \
                          grp->gr_name, i); \
        } \
    } while(0)


static errno_t remove_duplicate_group_members(TALLOC_CTX *mem_ctx,
                                             const struct group *orig_grp,
                                             struct group **_grp)
{
    TALLOC_CTX *tmp_ctx;
    hash_table_t *member_tbl = NULL;
    struct hash_iter_context_t *iter;
    hash_entry_t *entry;
    hash_key_t key;
    hash_value_t value;
    struct group *grp;
    size_t orig_member_count= 0;
    size_t member_count= 0;
    size_t i;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc failed.\n");
        return ENOMEM;
    }

    grp = talloc(tmp_ctx, struct group);
    if (grp == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc failed.\n");
        ret = ENOMEM;
        goto done;
    }

    grp->gr_gid = orig_grp->gr_gid;

    grp->gr_name = talloc_strdup(grp, orig_grp->gr_name);
    if (grp->gr_name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
        ret = ENOMEM;
        goto done;
    }

    grp->gr_passwd = talloc_strdup(grp, orig_grp->gr_passwd);
    if (grp->gr_passwd == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
        ret = ENOMEM;
        goto done;
    }

    if (orig_grp->gr_mem == NULL) {
        grp->gr_mem = NULL;
        ret = EOK;
        goto done;
    }

    for (i=0; orig_grp->gr_mem[i] != NULL; ++i) /* no-op: just counting */;

    orig_member_count = i;

    if (orig_member_count == 0) {
        grp->gr_mem = talloc_zero_array(grp, char *, 1);
        if (grp->gr_mem == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_zero_array failed.\n");
            ret = ENOMEM;
            goto done;
        }
        grp->gr_mem[0] = NULL;
        ret = EOK;
        goto done;
    }

    ret = sss_hash_create(tmp_ctx, orig_member_count, &member_tbl);
    if (ret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to create hash table.\n");
        ret = ENOMEM;
        goto done;
    }

    for (i=0; i < orig_member_count; ++i) {
        key.type = HASH_KEY_STRING;
        key.str = orig_grp->gr_mem[i]; /* hash_enter() makes copy itself */

        value.type = HASH_VALUE_PTR;
        /* no need to put copy in hash_table since
           copy will be created during construction of new grp */
        value.ptr = orig_grp->gr_mem[i];

        ret = hash_enter(member_tbl, &key, &value);
        if (ret != HASH_SUCCESS) {
            ret = ENOMEM;
            goto done;
        }
    }

    member_count = hash_count(member_tbl);
    if (member_count == 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Empty resulting hash table - must be internal bug.\n");
        ret = EINVAL;
        goto done;
    }

    grp->gr_mem = talloc_zero_array(grp, char *, member_count + 1);
    if (grp->gr_mem == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero_array failed.\n");
        ret = ENOMEM;
        goto done;
    }

    iter = new_hash_iter_context(member_tbl);
    if (iter == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "new_hash_iter_context failed.\n");
        ret = EINVAL;
        goto done;
    }

    i = 0;
    while ((entry = iter->next(iter)) != NULL) {
        grp->gr_mem[i] = talloc_strdup(grp, entry->key.str);
        if (grp->gr_mem[i] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }
        i++;
    }
    grp->gr_mem[i] = NULL;

    ret = EOK;

done:
    if (ret == EOK) {
        *_grp = talloc_steal(mem_ctx, grp);
    }
    talloc_zfree(tmp_ctx);

    return ret;
}

static errno_t proxy_process_missing_users(struct sysdb_ctx *sysdb,
                                           struct sss_domain_info *domain,
                                           struct sysdb_attrs *group_attrs,
                                           const char *const*fq_gr_mem,
                                           time_t now);
static int save_group(struct sysdb_ctx *sysdb, struct sss_domain_info *dom,
                      const struct group *grp,
                      const char *real_name, /* already qualified */
                      const char *alias) /* already qualified */
{
    errno_t ret, sret;
    struct group *ngroup = NULL;
    struct sysdb_attrs *attrs = NULL;
    TALLOC_CTX *tmp_ctx;
    time_t now = time(NULL);
    bool in_transaction = false;
    char **fq_gr_mem;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = remove_duplicate_group_members(tmp_ctx, grp, &ngroup);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to remove duplicate group members\n");
        goto done;
    }

    DEBUG_GR_MEM(SSSDBG_TRACE_LIBS, ngroup);

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto done;
    }
    in_transaction = true;

    if (ngroup->gr_mem && ngroup->gr_mem[0]) {
        attrs = sysdb_new_attrs(tmp_ctx);
        if (!attrs) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Allocation error?!\n");
            ret = ENOMEM;
            goto done;
        }

        fq_gr_mem = sss_create_internal_fqname_list(
                                            tmp_ctx,
                                            (const char *const*) ngroup->gr_mem,
                                            dom->name);
        if (fq_gr_mem == NULL) {
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_attrs_users_from_str_list(
                attrs, SYSDB_MEMBER, dom->name,
                (const char *const *) fq_gr_mem);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not add group members\n");
            goto done;
        }

        /* Create ghost users */
        ret = proxy_process_missing_users(sysdb, dom, attrs,
                                          (const char *const*) fq_gr_mem, now);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not add missing members\n");
            goto done;
        }
    }

    ret = prepare_attrs_for_saving_ops(tmp_ctx, dom->case_sensitive,
                                       real_name, alias, &attrs);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_store_group(dom,
                            real_name,
                            ngroup->gr_gid,
                            attrs,
                            dom->group_timeout,
                            now);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not add group to cache\n");
        goto done;
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not commit transaction: [%s]\n",
               strerror(ret));
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
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t proxy_process_missing_users(struct sysdb_ctx *sysdb,
                                           struct sss_domain_info *domain,
                                           struct sysdb_attrs *group_attrs,
                                           const char *const*fq_gr_mem,
                                           time_t now)
{
    errno_t ret;
    size_t i;
    TALLOC_CTX *tmp_ctx = NULL;
    struct ldb_message *msg;

    if (!sysdb || !fq_gr_mem) return EINVAL;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    for (i = 0; fq_gr_mem[i]; i++) {
        ret = sysdb_search_user_by_name(tmp_ctx, domain, fq_gr_mem[i],
                                        NULL, &msg);
        if (ret == EOK) {
            /* Member already exists in the cache */
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "Member [%s] already cached\n", fq_gr_mem[i]);
            /* clean up */
            talloc_zfree(msg);
            continue;
        } else if (ret == ENOENT) {
            /* No entry for this user. Create a ghost user */
            DEBUG(SSSDBG_TRACE_LIBS,
                  "Member [%s] not cached, creating ghost user entry\n",
                   fq_gr_mem[i]);

            ret = sysdb_attrs_add_string(group_attrs, SYSDB_GHOST, fq_gr_mem[i]);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Cannot store ghost user entry: [%d]: %s\n",
                       ret, strerror(ret));
                goto done;
            }
        } else {
            /* Unexpected error */
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Error searching cache for user [%s]: [%s]\n",
                   fq_gr_mem[i], strerror(ret));
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
    if (delete_group) {
        *delete_group = false;
    }

    switch (status) {
    case NSS_STATUS_TRYAGAIN:
        DEBUG(SSSDBG_MINOR_FAILURE, "Buffer too small\n");
        return EAGAIN;

    case NSS_STATUS_NOTFOUND:
        DEBUG(SSSDBG_MINOR_FAILURE, "Group not found.\n");
        if (delete_group) {
            *delete_group = true;
        }
        break;

    case NSS_STATUS_SUCCESS:
        DEBUG(SSSDBG_FUNC_DATA, "Group found: (%s, %"SPRIgid")\n",
              grp->gr_name, grp->gr_gid);

        /* gid=0 is an invalid value */
        /* also check that the id is in the valid range for this domain */
        if (OUT_OF_ID_RANGE(grp->gr_gid, dom->id_min, dom->id_max)) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Group filtered out! (id out of range)\n");
            if (delete_group) {
                *delete_group = true;
            }
            break;
        }
        break;

    case NSS_STATUS_UNAVAIL:
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Remote back end is not available. Entering offline mode\n");
        return ENXIO;

    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unknown return code %d\n", status);
        return EIO;
    }

    return EOK;
}

static int get_gr_name(struct proxy_id_ctx *ctx,
                       struct sysdb_ctx *sysdb,
                       struct sss_domain_info *dom,
                       const char *i_name)
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
    char *shortname_or_alias;

    DEBUG(SSSDBG_FUNC_DATA, "Searching group by name (%s)\n", i_name);

    tmpctx = talloc_new(NULL);
    if (!tmpctx) {
        return ENOMEM;
    }

    ret = sss_parse_internal_fqname(tmpctx, i_name, &shortname_or_alias, NULL);
    if (ret != EOK) {
        goto done;
    }

    grp = talloc(tmpctx, struct group);
    if (!grp) {
        ret = ENOMEM;
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc() failed\n");
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

        status = ctx->ops.getgrnam_r(shortname_or_alias, grp, buffer,
                                     buflen, &ret);
        ret = handle_getgr_result(status, grp, dom, &delete_group);
    } while (ret == EAGAIN);

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "getgrnam failed [%d]: %s\n", ret, strerror(ret));
        goto done;
    }

    if (delete_group) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Group %s does not exist (or is invalid) on remote server,"
               " deleting!\n", i_name);

        ret = sysdb_delete_group(dom, i_name, 0);
        if (ret == ENOENT) {
            ret = EOK;
        }
        goto done;
    }

    gid = grp->gr_gid;

    /* Canonicalize the group name in case it was actually an alias */
    if (ctx->fast_alias == true) {
        ret = sysdb_getgrgid(tmpctx, dom, gid, &cached_grp);
        if (ret != EOK) {
            /* Non-fatal, attempt to canonicalize online */
            DEBUG(SSSDBG_TRACE_FUNC, "Request to cache failed [%d]: %s\n",
                  ret, strerror(ret));
        }

        if (ret == EOK && cached_grp->count == 1) {
            real_name = ldb_msg_find_attr_as_string(cached_grp->msgs[0],
                                                    SYSDB_NAME, NULL);
            if (!real_name) {
                DEBUG(SSSDBG_MINOR_FAILURE, "Cached group has no name?\n");
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
                "getgrgid failed [%d]: %s\n", ret, strerror(ret));
            goto done;
        }

        real_name = sss_create_internal_fqname(tmpctx, grp->gr_name, dom->name);
        if (real_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to create fqdn '%s'\n",
                  grp->gr_name);
            ret = ENOMEM;
            goto done;
        }
    }

    if (delete_group) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Group %s does not exist (or is invalid) on remote server,"
               " deleting!\n", i_name);

        ret = sysdb_delete_group(dom, i_name, gid);
        if (ret == ENOENT) {
            ret = EOK;
        }
        goto done;
    }

    ret = save_group(sysdb, dom, grp, real_name, i_name);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot save group [%d]: %s\n", ret, strerror(ret));
        goto done;
    }

done:
    talloc_zfree(tmpctx);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE,
              "proxy -> getgrnam_r failed for '%s' <%d>: %s\n",
              i_name, ret, strerror(ret));
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
    char *name;

    DEBUG(SSSDBG_TRACE_FUNC, "Searching group by gid (%"SPRIgid")\n", gid);

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

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "getgrgid failed [%d]: %s\n", ret, strerror(ret));
        goto done;
    }

    if (delete_group) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Group %"SPRIgid" does not exist (or is invalid) on remote "
               "server, deleting!\n", gid);

        ret = sysdb_delete_group(dom, NULL, gid);
        if (ret == ENOENT) {
            ret = EOK;
        }
        goto done;
    }

    name = sss_create_internal_fqname(tmpctx, grp->gr_name, dom->name);
    if (name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = save_group(sysdb, dom, grp, name, NULL);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot save user [%d]: %s\n", ret, strerror(ret));
        goto done;
    }

done:
    talloc_zfree(tmpctx);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE,
              "proxy -> getgrgid_r failed for '%"SPRIgid"' <%d>: %s\n",
               gid, ret, strerror(ret));
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
    char *name;

    DEBUG(SSSDBG_TRACE_LIBS, "Enumerating groups\n");

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
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
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
                /* buffer too small? */
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
                DEBUG(SSSDBG_TRACE_LIBS, "Enumeration completed.\n");

                ret = sysdb_transaction_commit(sysdb);
                if (ret != EOK) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction\n");
                    goto done;
                }
                in_transaction = false;
                break;

            case NSS_STATUS_SUCCESS:

                DEBUG(SSSDBG_OP_FAILURE, "Group found (%s, %"SPRIgid")\n",
                            grp->gr_name, grp->gr_gid);

                /* gid=0 is an invalid value */
                /* also check that the id is in the valid range for this domain
                 */
                if (OUT_OF_ID_RANGE(grp->gr_gid, dom->id_min, dom->id_max)) {

                    DEBUG(SSSDBG_OP_FAILURE, "Group [%s] filtered out! (id"
                        "out of range)\n", grp->gr_name);

                    again = true;
                    break;
                }

                name = sss_create_internal_fqname(tmpctx, grp->gr_name,
                                                  dom->name);
                if (name == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE, "Failed to create internal fqname "
                          "Ignoring\n");
                    ret = ENOMEM;
                }
                ret = save_group(sysdb, dom, grp, name, NULL);
                if (ret) {
                    /* Do not fail completely on errors.
                     * Just report the failure to save and go on */
                    DEBUG(SSSDBG_OP_FAILURE, "Failed to store group."
                                "Ignoring\n");
                }
                again = true;
                break;

            case NSS_STATUS_UNAVAIL:
                /* "remote" backend unavailable. Enter offline mode */
                ret = ENXIO;
                break;

            default:
                ret = EIO;
                DEBUG(SSSDBG_OP_FAILURE, "proxy -> getgrent_r failed (%d)[%s]"
                            "\n", ret, strerror(ret));
                break;
        }
    } while (again);

done:
    talloc_zfree(tmpctx);
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to cancel transaction\n");
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
                      const char *i_name)
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
    char *shortname_or_alias;

    tmpctx = talloc_new(mem_ctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    ret = sss_parse_internal_fqname(tmpctx, i_name, &shortname_or_alias, NULL);
    if (ret != EOK) {
        goto done;
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
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto fail;
    }
    in_transaction = true;

    /* FIXME: should we move this call outside the transaction to keep the
     * transaction as short as possible? */
    status = ctx->ops.getpwnam_r(shortname_or_alias, pwd,
                                 buffer, buflen, &ret);
    ret = handle_getpw_result(status, pwd, dom, &del_user);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE,
              "getpwnam failed [%d]: %s\n", ret, strerror(ret));
        goto fail;
    }

    if (del_user) {
        ret = delete_user(dom, i_name, 0);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not delete user\n");
            goto fail;
        }
        goto done;
    }

    uid = pwd->pw_uid;
    memset(buffer, 0, buflen);

    /* Canonicalize the username in case it was actually an alias */
    if (ctx->fast_alias == true) {
        ret = sysdb_getpwuid(tmpctx, dom, uid, &cached_pwd);
        if (ret != EOK) {
            /* Non-fatal, attempt to canonicalize online */
            DEBUG(SSSDBG_TRACE_FUNC, "Request to cache failed [%d]: %s\n",
                  ret, strerror(ret));
        }

        if (ret == EOK && cached_pwd->count == 1) {
            real_name = ldb_msg_find_attr_as_string(cached_pwd->msgs[0],
                                                    SYSDB_NAME, NULL);
            if (!real_name) {
                DEBUG(SSSDBG_MINOR_FAILURE, "Cached user has no name?\n");
            }
        }
    }

    if (real_name == NULL) {
        memset(buffer, 0, buflen);

        status = ctx->ops.getpwuid_r(uid, pwd, buffer, buflen, &ret);
        ret = handle_getpw_result(status, pwd, dom, &del_user);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE,
                "getpwuid failed [%d]: %s\n", ret, strerror(ret));
            goto done;
        }

        real_name = sss_create_internal_fqname(tmpctx, pwd->pw_name, dom->name);
        if (real_name == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    if (del_user) {
        ret = delete_user(dom, i_name, uid);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not delete user\n");
            goto fail;
        }
        goto done;
    }

    ret = save_user(dom, pwd, real_name, i_name);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not save user\n");
        goto fail;
    }

    ret = get_initgr_groups_process(tmpctx, ctx, sysdb, dom, pwd);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not process initgroups\n");
        goto fail;
    }

done:
    ret = sysdb_transaction_commit(sysdb);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to commit transaction\n");
        goto fail;
    }
    in_transaction = false;

fail:
    talloc_zfree(tmpctx);
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to cancel transaction\n");
        }
    }
    return ret;
}

static int remove_group_members(struct proxy_id_ctx *ctx,
                                struct sss_domain_info *dom,
                                const struct passwd *pwd,
                                long int num_gids,
                                const gid_t *gids,
                                long int num_cached_gids,
                                const gid_t *cached_gids)
{
    TALLOC_CTX *tmp_ctx = NULL;
    int i = 0, j = 0;
    int ret = EOK;
    const char *groupname = NULL;
    const char *username = NULL;
    bool group_found = false;
    struct ldb_result *res = NULL;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    username = sss_create_internal_fqname(tmp_ctx, pwd->pw_name, dom->name);
    if (username == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to create fqdn '%s'\n", pwd->pw_name);
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < num_cached_gids; i++) {
        group_found = false;
        /* group 0 is the primary group so it can be skipped */
        for (j = 1; j < num_gids; j++) {
            if (cached_gids[i] == gids[j]) {
                group_found = true;
                break;
            }
        }

        if (!group_found) {
            ret = sysdb_getgrgid(tmp_ctx, dom, cached_gids[i], &res);
            if (ret != EOK || res->count != 1) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "sysdb_getgrgid failed for GID [%d].\n", cached_gids[i]);
                continue;
            }

            groupname = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, NULL);
            if (groupname == NULL) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Attribute is missing but this should never happen!\n");
                continue;
            }

            ret = sysdb_remove_group_member(dom, groupname,
                                            username,
                                            SYSDB_MEMBER_USER, false);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Could not remove member [%s] from group [%s]\n",
                      username, groupname);
                continue;
            }
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static int get_cached_user_groups(struct sysdb_ctx *sysdb,
                                  struct sss_domain_info *dom,
                                  const struct passwd *pwd,
                                  unsigned int *_num_cached_gids,
                                  gid_t **_cached_gids)
{
    TALLOC_CTX *tmp_ctx = NULL;
    int ret = EOK;
    int i = 0, j = 0;
    gid_t gid = 0;
    gid_t *cached_gids = NULL;
    const char *username = NULL;
    struct ldb_result *res = NULL;

    if (_num_cached_gids == NULL || _cached_gids == NULL) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        ret = ENOMEM;
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        goto done;
    }

    username = sss_create_internal_fqname(tmp_ctx, pwd->pw_name, dom->name);
    if (username == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to create fqdn '%s'\n", pwd->pw_name);
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_initgroups(tmp_ctx, dom, username, &res);
    /* the first element is the user itself so it can be skipped */
    if (ret == EOK && res->count > 1) {
        cached_gids = talloc_array(tmp_ctx, gid_t, res->count - 1);

        for (i = 1; i < res->count; i++) {
            gid = ldb_msg_find_attr_as_uint(res->msgs[i], SYSDB_GIDNUM, 0);
            if (gid != 0) {
                cached_gids[j] = gid;
                j++;
            }
        }

        *_num_cached_gids = j;
        *_cached_gids = talloc_steal(sysdb, cached_gids);
    } else if (ret == EOK) {
        *_num_cached_gids = 0;
        *_cached_gids = NULL;
    } else {
        goto done;
    }

    ret = EOK;

done:
    talloc_zfree(tmp_ctx);

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
    gid_t *cached_gids = NULL;
    unsigned int num_cached_gids = 0;

    num_gids = 0;
    limit = 4096;
    num = 4096;
    size = num*sizeof(gid_t);
    gids = talloc_size(memctx, size);
    if (!gids) {
        return ENOMEM;
    }

    /* nss modules may skip the primary group when we pass it in so always add
     * it in advance */
    gids[0] = pwd->pw_gid;
    num_gids++;

    /* FIXME: should we move this call outside the transaction to keep the
     * transaction as short as possible? */
    do {
        status = ctx->ops.initgroups_dyn(pwd->pw_name, pwd->pw_gid, &num_gids,
                &num, &gids, limit, &ret);

        if (status == NSS_STATUS_TRYAGAIN) {
            /* buffer too small? */
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
    case NSS_STATUS_NOTFOUND:
        DEBUG(SSSDBG_FUNC_DATA, "The initgroups call returned 'NOTFOUND'. "
                                 "Assume the user is only member of its "
                                 "primary group (%"SPRIgid")\n", pwd->pw_gid);
        /* fall through */
        SSS_ATTRIBUTE_FALLTHROUGH;
    case NSS_STATUS_SUCCESS:
        DEBUG(SSSDBG_CONF_SETTINGS, "User [%s] appears to be member of %lu "
              "groups\n", pwd->pw_name, num_gids);

        ret = get_cached_user_groups(sysdb, dom, pwd, &num_cached_gids, &cached_gids);
        if (ret) {
            return ret;
        }
        ret = remove_group_members(ctx, dom, pwd, num_gids, gids, num_cached_gids, cached_gids);
        talloc_free(cached_gids);
        if (ret) {
            return ret;
        }

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
        DEBUG(SSSDBG_OP_FAILURE, "proxy -> initgroups_dyn failed (%d)[%s]\n",
                  ret, strerror(ret));
        ret = EIO;
        break;
    }

    return ret;
}

/* =Proxy_Id-Functions====================================================*/

static struct dp_reply_std
proxy_account_info(TALLOC_CTX *mem_ctx,
                   struct proxy_id_ctx *ctx,
                   struct dp_id_data *data,
                   struct be_ctx *be_ctx,
                   struct sss_domain_info *domain)
{
    struct dp_reply_std reply;
    struct sysdb_ctx *sysdb;
    uid_t uid;
    gid_t gid;
    errno_t ret;
    char *endptr;

    sysdb = domain->sysdb;

    /* Proxy provider does not support security ID lookups. */
    if (data->filter_type == BE_FILTER_SECID) {
        dp_reply_std_set(&reply, DP_ERR_FATAL, ENOSYS,
                         "Security lookups are not supported");
        return reply;
    }

    switch (data->entry_type & BE_REQ_TYPE_MASK) {
    case BE_REQ_USER: /* user */
        switch (data->filter_type) {
        case BE_FILTER_ENUM:
            ret = enum_users(mem_ctx, ctx, sysdb, domain);
            break;

        case BE_FILTER_NAME:
            ret = get_pw_name(ctx, domain, data->filter_value);
            break;

        case BE_FILTER_IDNUM:
            uid = (uid_t) strtouint32(data->filter_value, &endptr, 10);
            if (errno || *endptr || (data->filter_value == endptr)) {
                dp_reply_std_set(&reply, DP_ERR_FATAL, EINVAL,
                                 "Invalid attr type");
                return reply;
            }
            ret = get_pw_uid(ctx, domain, uid);
            break;
        default:
            dp_reply_std_set(&reply, DP_ERR_FATAL, EINVAL,
                             "Invalid filter type");
            return reply;
        }
        break;

    case BE_REQ_GROUP: /* group */
        switch (data->filter_type) {
        case BE_FILTER_ENUM:
            ret = enum_groups(mem_ctx, ctx, sysdb, domain);
            break;
        case BE_FILTER_NAME:
            ret = get_gr_name(ctx, sysdb, domain, data->filter_value);
            break;
        case BE_FILTER_IDNUM:
            gid = (gid_t) strtouint32(data->filter_value, &endptr, 10);
            if (errno || *endptr || (data->filter_value == endptr)) {
                dp_reply_std_set(&reply, DP_ERR_FATAL, EINVAL,
                                 "Invalid attr type");
                return reply;
            }
            ret = get_gr_gid(mem_ctx, ctx, sysdb, domain, gid, 0);
            break;
        default:
            dp_reply_std_set(&reply, DP_ERR_FATAL, EINVAL,
                             "Invalid filter type");
            return reply;
        }
        break;

    case BE_REQ_INITGROUPS: /* init groups for user */
        if (data->filter_type != BE_FILTER_NAME) {
            dp_reply_std_set(&reply, DP_ERR_FATAL, EINVAL,
                             "Invalid filter type");
            return reply;
        }
        if (ctx->ops.initgroups_dyn == NULL) {
            dp_reply_std_set(&reply, DP_ERR_FATAL, ENODEV,
                             "Initgroups call not supported");
            return reply;
        }
        ret = get_initgr(mem_ctx, ctx, sysdb, domain, data->filter_value);
        break;

    case BE_REQ_NETGROUP:
        if (data->filter_type != BE_FILTER_NAME) {
            dp_reply_std_set(&reply, DP_ERR_FATAL, EINVAL,
                             "Invalid filter type");
            return reply;
        }
        if (ctx->ops.setnetgrent == NULL || ctx->ops.getnetgrent_r == NULL ||
            ctx->ops.endnetgrent == NULL) {
            dp_reply_std_set(&reply, DP_ERR_FATAL, ENODEV,
                             "Netgroups are not supported");
            return reply;
        }

        ret = get_netgroup(ctx, domain, data->filter_value);
        break;

    case BE_REQ_SERVICES:
        switch (data->filter_type) {
        case BE_FILTER_NAME:
            if (ctx->ops.getservbyname_r == NULL) {
                dp_reply_std_set(&reply, DP_ERR_FATAL, ENODEV,
                                 "Services are not supported");
                return reply;
            }
            ret = get_serv_byname(ctx, domain,
                                  data->filter_value,
                                  data->extra_value);
            break;
        case BE_FILTER_IDNUM:
            if (ctx->ops.getservbyport_r == NULL) {
                dp_reply_std_set(&reply, DP_ERR_FATAL, ENODEV,
                                 "Services are not supported");
                return reply;
            }
            ret = get_serv_byport(ctx, domain,
                                  data->filter_value,
                                  data->extra_value);
            break;
        case BE_FILTER_ENUM:
            if (!ctx->ops.setservent
                    || !ctx->ops.getservent_r
                    || !ctx->ops.endservent) {
                dp_reply_std_set(&reply, DP_ERR_FATAL, ENODEV,
                                 "Services are not supported");
                return reply;
            }
            ret = enum_services(ctx, sysdb, domain);
            break;
        default:
            dp_reply_std_set(&reply, DP_ERR_FATAL, EINVAL,
                             "Invalid filter type");
            return reply;
        }
        break;

    default: /*fail*/
        dp_reply_std_set(&reply, DP_ERR_FATAL, EINVAL,
                         "Invalid filter type");
        return reply;
    }

    if (ret) {
        if (ret == ENXIO) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "proxy returned UNAVAIL error, going offline!\n");
            be_mark_offline(be_ctx);
        }

        dp_reply_std_set(&reply, DP_ERR_FATAL, ret, NULL);
        return reply;
    }

    dp_reply_std_set(&reply, DP_ERR_OK, EOK, NULL);
    return reply;
}

struct proxy_account_info_handler_state {
    struct dp_reply_std reply;
};

struct tevent_req *
proxy_account_info_handler_send(TALLOC_CTX *mem_ctx,
                               struct proxy_id_ctx *id_ctx,
                               struct dp_id_data *data,
                               struct dp_req_params *params)
{
    struct proxy_account_info_handler_state *state;
    struct tevent_req *req;

    req = tevent_req_create(mem_ctx, &state,
                            struct proxy_account_info_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->reply = proxy_account_info(state, id_ctx, data, params->be_ctx,
                                      params->be_ctx->domain);

    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
    tevent_req_post(req, params->ev);

    return req;
}

errno_t proxy_account_info_handler_recv(TALLOC_CTX *mem_ctx,
                                       struct tevent_req *req,
                                       struct dp_reply_std *data)
{
    struct proxy_account_info_handler_state *state = NULL;

    state = tevent_req_data(req, struct proxy_account_info_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *data = state->reply;

    return EOK;
}
