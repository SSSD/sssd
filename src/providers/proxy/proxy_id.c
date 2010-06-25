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

#include "providers/proxy/proxy.h"

/* =Getpwnam-wrapper======================================================*/

static int delete_user(TALLOC_CTX *mem_ctx, struct sysdb_ctx *sysdb,
                       struct sss_domain_info *domain, const char *name);

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

    DEBUG(7, ("Searching user by name (%s)\n", name));

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

    /* FIXME: should we move this call outside the transaction to keep the
     * transaction as short as possible ? */
    status = ctx->ops.getpwnam_r(name, pwd, buffer, buflen, &ret);

    switch (status) {
    case NSS_STATUS_NOTFOUND:

        DEBUG(7, ("User %s not found.\n", name));
        ret = delete_user(tmpctx, sysdb, dom, name);
        if (ret) {
            goto done;
        }
        break;

    case NSS_STATUS_SUCCESS:

        DEBUG(7, ("User %s found: (%s, %d, %d)\n",
                  name, pwd->pw_name, pwd->pw_uid, pwd->pw_gid));

        /* uid=0 or gid=0 are invalid values */
        /* also check that the id is in the valid range for this domain */
        if (OUT_OF_ID_RANGE(pwd->pw_uid, dom->id_min, dom->id_max) ||
            OUT_OF_ID_RANGE(pwd->pw_gid, dom->id_min, dom->id_max)) {

            DEBUG(2, ("User [%s] filtered out! (id out of range)\n", name));
            ret = delete_user(tmpctx, sysdb, dom, name);
            if (ret) {
                goto done;
            }
            break;
        }

        ret = sysdb_store_user(tmpctx, sysdb, dom,
                               pwd->pw_name,
                               pwd->pw_passwd,
                               pwd->pw_uid,
                               pwd->pw_gid,
                               pwd->pw_gecos,
                               pwd->pw_dir,
                               pwd->pw_shell,
                               NULL, ctx->entry_cache_timeout);
        if (ret) {
            goto done;
        }
        break;

    case NSS_STATUS_UNAVAIL:
        /* "remote" backend unavailable. Enter offline mode */
        ret = ENXIO;
        goto done;

    default:
        ret = EIO;
        goto done;
    }

done:
    talloc_zfree(tmpctx);
    if (ret) {
        DEBUG(2, ("proxy -> getpwnam_r failed for '%s' <%d>\n",
                  name, status));
    }
    return ret;
}

static int delete_user(TALLOC_CTX *mem_ctx, struct sysdb_ctx *sysdb,
                       struct sss_domain_info *domain, const char *name)
{
    struct ldb_dn *dn;

    DEBUG(7, ("User %s does not exist (or is invalid) on remote server,"
              " deleting!\n", name));

    dn = sysdb_user_dn(sysdb, mem_ctx, domain->name, name);
    if (!dn) {
        return ENOMEM;
    }

    return sysdb_delete_entry(sysdb, dn, true);
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

    DEBUG(7, ("Searching user by uid (%d)\n", uid));

    tmpctx = talloc_new(mem_ctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    pwd = talloc_zero(tmpctx, struct passwd);
    if (!pwd) {
        ret = ENOMEM;
        DEBUG(1, ("proxy -> getpwuid_r failed for '%d': [%d] %s\n",
                  uid, ret, strerror(ret)));
        return ret;
    }

    buflen = DEFAULT_BUFSIZE;
    buffer = talloc_size(tmpctx, buflen);
    if (!buffer) {
        ret = ENOMEM;
        DEBUG(1, ("proxy -> getpwuid_r failed for '%d': [%d] %s\n",
                  uid, ret, strerror(ret)));
        return ret;
    }

    status = ctx->ops.getpwuid_r(uid, pwd, buffer, buflen, &ret);

    switch (status) {
    case NSS_STATUS_NOTFOUND:

        DEBUG(7, ("User %d not found.\n", uid));
        del_user = true;
        break;

    case NSS_STATUS_SUCCESS:

        DEBUG(7, ("User %d found (%s, %d, %d)\n",
                  uid, pwd->pw_name, pwd->pw_uid, pwd->pw_gid));

        /* uid=0 or gid=0 are invalid values */
        /* also check that the id is in the valid range for this domain */
        if (OUT_OF_ID_RANGE(pwd->pw_uid, dom->id_min, dom->id_max) ||
            OUT_OF_ID_RANGE(pwd->pw_gid, dom->id_min, dom->id_max)) {

            DEBUG(2, ("User [%s] filtered out! (id out of range)\n",
                      pwd->pw_name));
            del_user = true;
            break;
        }

        ret = sysdb_store_user(tmpctx, sysdb, dom,
                               pwd->pw_name,
                               pwd->pw_passwd,
                               pwd->pw_uid,
                               pwd->pw_gid,
                               pwd->pw_gecos,
                               pwd->pw_dir,
                               pwd->pw_shell,
                               NULL, ctx->entry_cache_timeout);
        if (ret) {
            goto done;
        }
        break;

    case NSS_STATUS_UNAVAIL:
        /* "remote" backend unavailable. Enter offline mode */
        ret = ENXIO;
        goto done;

    default:
        ret = EIO;
        goto done;
    }

    if (del_user) {
        DEBUG(7, ("User %d does not exist (or is invalid) on remote server,"
                  " deleting!\n", uid));

        ret = sysdb_delete_user(tmpctx, sysdb, dom, NULL, uid);
        if (ret) {
            goto done;
        }
    }

done:
    talloc_zfree(tmpctx);
    if (ret) {
        DEBUG(2, ("proxy -> getpwuid_r failed for '%d' <%d>\n", uid, status));
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

    DEBUG(7, ("Enumerating users\n"));

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
        goto done;
    }
    in_transaction = true;

    status = ctx->ops.setpwent();
    if (status != NSS_STATUS_SUCCESS) {
        ret = EIO;
        goto done;
    }

again:
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
        goto again;

    case NSS_STATUS_NOTFOUND:

        /* we are done here */
        DEBUG(7, ("Enumeration completed.\n"));

        ret = sysdb_transaction_commit(sysdb);
        in_transaction = false;
        break;

    case NSS_STATUS_SUCCESS:

        DEBUG(7, ("User found (%s, %d, %d)\n",
                  pwd->pw_name, pwd->pw_uid, pwd->pw_gid));

        /* uid=0 or gid=0 are invalid values */
        /* also check that the id is in the valid range for this domain */
        if (OUT_OF_ID_RANGE(pwd->pw_uid, dom->id_min, dom->id_max) ||
            OUT_OF_ID_RANGE(pwd->pw_gid, dom->id_min, dom->id_max)) {

            DEBUG(2, ("User [%s] filtered out! (id out of range)\n",
                      pwd->pw_name));

            goto again; /* skip */
        }

        ret = sysdb_store_user(tmpctx, sysdb, dom,
                               pwd->pw_name,
                               pwd->pw_passwd,
                               pwd->pw_uid,
                               pwd->pw_gid,
                               pwd->pw_gecos,
                               pwd->pw_dir,
                               pwd->pw_shell,
                               NULL, ctx->entry_cache_timeout);
        if (ret) {
            /* Do not fail completely on errors.
             * Just report the failure to save and go on */
            DEBUG(2, ("Failed to store user %s. Ignoring.\n",
                      pwd->pw_name));
        }
        goto again; /* next */

    case NSS_STATUS_UNAVAIL:
        /* "remote" backend unavailable. Enter offline mode */
        ret = ENXIO;
        break;

    default:
        ret = EIO;
        DEBUG(2, ("proxy -> getpwent_r failed (%d)[%s]\n",
                  ret, strerror(ret)));
        break;
    }

done:
    talloc_zfree(tmpctx);
    if (in_transaction) {
        sysdb_transaction_cancel(sysdb);
    }
    ctx->ops.endpwent();
    return ret;
}

/* =Getgrnam-wrapper======================================================*/

#define DEBUG_GR_MEM(level, grp) \
    do { \
        if (debug_level >= level) { \
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

static int get_gr_name(TALLOC_CTX *mem_ctx,
                       struct proxy_id_ctx *ctx,
                       struct sysdb_ctx *sysdb,
                       struct sss_domain_info *dom,
                       const char *name)
{
    TALLOC_CTX *tmpctx;
    struct group *grp;
    enum nss_status status;
    char *buffer;
    char *newbuf;
    size_t buflen;
    bool delete_group = false;
    struct sysdb_attrs *members;
    int ret;

    DEBUG(7, ("Searching group by name (%s)\n", name));

    tmpctx = talloc_new(mem_ctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    grp = talloc(tmpctx, struct group);
    if (!grp) {
        ret = ENOMEM;
        DEBUG(1, ("proxy -> getgrnam_r failed for '%s': [%d] %s\n",
                  name, ret, strerror(ret)));
        return ret;
    }

    buflen = DEFAULT_BUFSIZE;
    buffer = talloc_size(tmpctx, buflen);
    if (!buffer) {
        ret = ENOMEM;
        DEBUG(1, ("proxy -> getgrnam_r failed for '%s': [%d] %s\n",
                  name, ret, strerror(ret)));
        return ret;
    }

    /* FIXME: should we move this call outside the transaction to keep the
     * transaction as short as possible ? */
again:
    /* always zero out the grp structure */
    memset(grp, 0, sizeof(struct group));

    status = ctx->ops.getgrnam_r(name, grp, buffer, buflen, &ret);

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
        goto again;

    case NSS_STATUS_NOTFOUND:

        DEBUG(7, ("Group %s not found.\n", name));
        delete_group = true;
        break;

    case NSS_STATUS_SUCCESS:

        DEBUG(7, ("Group %s found: (%s, %d)\n",
                  name, grp->gr_name, grp->gr_gid));

        /* gid=0 is an invalid value */
        /* also check that the id is in the valid range for this domain */
        if (OUT_OF_ID_RANGE(grp->gr_gid, dom->id_min, dom->id_max)) {

                DEBUG(2, ("Group [%s] filtered out! (id out of range)\n",
                          name));
            delete_group = true;
            break;
        }

        DEBUG_GR_MEM(7, grp);

        if (grp->gr_mem && grp->gr_mem[0]) {
            members = sysdb_new_attrs(tmpctx);
            if (!members) {
                ret = ENOMEM;
                goto done;
            }
            ret = sysdb_attrs_users_from_str_list(members, SYSDB_MEMBER,
                                                  dom->name,
                                                  (const char **)grp->gr_mem);
            if (ret) {
                goto done;
            }
        } else {
            members = NULL;
        }

        ret = sysdb_store_group(tmpctx, sysdb, dom,
                                grp->gr_name,
                                grp->gr_gid,
                                members,
                                ctx->entry_cache_timeout);
        if (ret) {
            goto done;
        }
        break;

    case NSS_STATUS_UNAVAIL:
        /* "remote" backend unavailable. Enter offline mode */
        ret = ENXIO;
        goto done;

    default:
        ret = EIO;
        goto done;
    }

    if (delete_group) {
        struct ldb_dn *dn;

        DEBUG(7, ("Group %s does not exist (or is invalid) on remote server,"
                  " deleting!\n", name));

        dn = sysdb_group_dn(sysdb, tmpctx, dom->name, name);
        if (!dn) {
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_delete_entry(sysdb, dn, true);
        if (ret) {
            goto done;
        }
    }

done:
    talloc_zfree(tmpctx);
    if (ret) {
        DEBUG(2, ("proxy -> getgrnam_r failed for '%s' <%d>\n",
                  name, status));
    }
    return ret;
}

/* =Getgrgid-wrapper======================================================*/

static int get_gr_gid(TALLOC_CTX *mem_ctx,
                      struct proxy_id_ctx *ctx,
                      struct sysdb_ctx *sysdb,
                      struct sss_domain_info *dom,
                      gid_t gid)
{
    TALLOC_CTX *tmpctx;
    struct group *grp;
    enum nss_status status;
    char *buffer;
    char *newbuf;
    size_t buflen;
    bool delete_group = false;
    struct sysdb_attrs *members;
    int ret;

    DEBUG(7, ("Searching group by gid (%d)\n", gid));

    tmpctx = talloc_new(mem_ctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    grp = talloc(tmpctx, struct group);
    if (!grp) {
        ret = ENOMEM;
        DEBUG(1, ("proxy -> getgrgid_r failed for '%d': [%d] %s\n",
                  gid, ret, strerror(ret)));
        return ret;
    }

    buflen = DEFAULT_BUFSIZE;
    buffer = talloc_size(tmpctx, buflen);
    if (!buffer) {
        ret = ENOMEM;
        DEBUG(1, ("proxy -> getgrgid_r failed for '%d': [%d] %s\n",
                  gid, ret, strerror(ret)));
        return ret;
    }

again:
    /* always zero out the group structure */
    memset(grp, 0, sizeof(struct group));

    status = ctx->ops.getgrgid_r(gid, grp, buffer, buflen, &ret);

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
        goto again;

    case NSS_STATUS_NOTFOUND:

        DEBUG(7, ("Group %d not found.\n", gid));
        delete_group = true;
        break;

    case NSS_STATUS_SUCCESS:

        DEBUG(7, ("Group %d found (%s, %d)\n",
                  gid, grp->gr_name, grp->gr_gid));

        /* gid=0 is an invalid value */
        /* also check that the id is in the valid range for this domain */
        if (OUT_OF_ID_RANGE(grp->gr_gid, dom->id_min, dom->id_max)) {

                DEBUG(2, ("Group [%s] filtered out! (id out of range)\n",
                          grp->gr_name));
            delete_group = true;
            break;
        }

        DEBUG_GR_MEM(7, grp);

        if (grp->gr_mem && grp->gr_mem[0]) {
            members = sysdb_new_attrs(tmpctx);
            if (!members) {
                ret = ENOMEM;
                goto done;
            }
            ret = sysdb_attrs_users_from_str_list(members, SYSDB_MEMBER,
                                                  dom->name,
                                                  (const char **)grp->gr_mem);
            if (ret) {
                goto done;
            }
        } else {
            members = NULL;
        }

        ret = sysdb_store_group(tmpctx, sysdb, dom,
                                grp->gr_name,
                                grp->gr_gid,
                                members,
                                ctx->entry_cache_timeout);
        if (ret) {
            goto done;
        }
        break;

    case NSS_STATUS_UNAVAIL:
        /* "remote" backend unavailable. Enter offline mode */
        ret = ENXIO;
        goto done;

    default:
        ret = EIO;
        goto done;
    }

    if (delete_group) {

        DEBUG(7, ("Group %d does not exist (or is invalid) on remote server,"
                  " deleting!\n", gid));

        ret = sysdb_delete_group(tmpctx, sysdb, dom, NULL, gid);
        if (ret) {
            goto done;
        }
    }

done:
    talloc_zfree(tmpctx);
    if (ret) {
        DEBUG(2, ("proxy -> getgrgid_r failed for '%d' <%d>\n",
                  gid, status));
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
    struct sysdb_attrs *members;
    char *newbuf;
    int ret;

    DEBUG(7, ("Enumerating groups\n"));

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
        goto done;
    }
    in_transaction = true;

    status = ctx->ops.setgrent();
    if (status != NSS_STATUS_SUCCESS) {
        ret = EIO;
        goto done;
    }

again:
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
        goto again;

    case NSS_STATUS_NOTFOUND:

        /* we are done here */
        DEBUG(7, ("Enumeration completed.\n"));

        ret = sysdb_transaction_commit(sysdb);
        in_transaction = false;
        break;

    case NSS_STATUS_SUCCESS:

        DEBUG(7, ("Group found (%s, %d)\n",
                  grp->gr_name, grp->gr_gid));

        /* gid=0 is an invalid value */
        /* also check that the id is in the valid range for this domain */
        if (OUT_OF_ID_RANGE(grp->gr_gid, dom->id_min, dom->id_max)) {

                DEBUG(2, ("Group [%s] filtered out! (id out of range)\n",
                          grp->gr_name));

            goto again; /* skip */
        }

        DEBUG_GR_MEM(7, grp);

        if (grp->gr_mem && grp->gr_mem[0]) {
            members = sysdb_new_attrs(tmpctx);
            if (!members) {
                ret = ENOMEM;
                goto done;
            }
            ret = sysdb_attrs_users_from_str_list(members, SYSDB_MEMBER,
                                                  dom->name,
                                                  (const char **)grp->gr_mem);
            if (ret) {
                goto done;
            }
        } else {
            members = NULL;
        }

        ret = sysdb_store_group(tmpctx, sysdb, dom,
                                grp->gr_name,
                                grp->gr_gid,
                                members,
                                ctx->entry_cache_timeout);
        if (ret) {
            /* Do not fail completely on errors.
             * Just report the failure to save and go on */
            DEBUG(2, ("Failed to store group. Ignoring.\n"));
        }
        goto again; /* next */

    case NSS_STATUS_UNAVAIL:
        /* "remote" backend unavailable. Enter offline mode */
        ret = ENXIO;
        break;

    default:
        ret = EIO;
        DEBUG(2, ("proxy -> getgrent_r failed (%d)[%s]\n",
                  ret, strerror(ret)));
        break;
    }

done:
    talloc_zfree(tmpctx);
    if (in_transaction) {
        sysdb_transaction_cancel(sysdb);
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
        goto done;
    }
    in_transaction = true;

    /* FIXME: should we move this call outside the transaction to keep the
     * transaction as short as possible ? */
    status = ctx->ops.getpwnam_r(name, pwd, buffer, buflen, &ret);

    switch (status) {
    case NSS_STATUS_NOTFOUND:

        DEBUG(7, ("User %s not found.\n", name));
        ret = delete_user(tmpctx, sysdb, dom, name);
        if (ret) {
            goto done;
        }
        break;

    case NSS_STATUS_SUCCESS:

        /* uid=0 or gid=0 are invalid values */
        /* also check that the id is in the valid range for this domain */
        if (OUT_OF_ID_RANGE(pwd->pw_uid, dom->id_min, dom->id_max) ||
            OUT_OF_ID_RANGE(pwd->pw_gid, dom->id_min, dom->id_max)) {

            DEBUG(2, ("User [%s] filtered out! (id out of range)\n",
                      name));
            ret = delete_user(tmpctx, sysdb, dom, name);
            break;
        }

        ret = sysdb_store_user(tmpctx, sysdb, dom,
                               pwd->pw_name,
                               pwd->pw_passwd,
                               pwd->pw_uid,
                               pwd->pw_gid,
                               pwd->pw_gecos,
                               pwd->pw_dir,
                               pwd->pw_shell,
                               NULL, ctx->entry_cache_timeout);
        if (ret) {
            goto done;
        }

        ret = get_initgr_groups_process(tmpctx, ctx, sysdb, dom, pwd);
        if (ret == EOK) {
            ret = sysdb_transaction_commit(sysdb);
            in_transaction = true;
        }
        break;

    case NSS_STATUS_UNAVAIL:
        /* "remote" backend unavailable. Enter offline mode */
        ret = ENXIO;
        break;

    default:
        DEBUG(2, ("proxy -> getpwnam_r failed for '%s' <%d>\n",
                  name, status));
        ret = EIO;
        break;
    }

done:
    talloc_zfree(tmpctx);
    if (in_transaction) {
        sysdb_transaction_cancel(sysdb);
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

    num_gids = 0;
    limit = 4096;
    num = 4096;
    size = num*sizeof(gid_t);
    gids = talloc_size(memctx, size);
    if (!gids) {
        return ENOMEM;
    }

again:
    /* FIXME: should we move this call outside the transaction to keep the
     * transaction as short as possible ? */
    status = ctx->ops.initgroups_dyn(pwd->pw_name, pwd->pw_gid, &num_gids,
                                     &num, &gids, limit, &ret);
    switch (status) {
    case NSS_STATUS_TRYAGAIN:
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
        goto again; /* retry with more memory */

    case NSS_STATUS_SUCCESS:
        DEBUG(4, ("User [%s] appears to be member of %lu groups\n",
                  pwd->pw_name, num_gids));

        for (i = 0; i < num_gids; i++) {
            ret = get_gr_gid(memctx, ctx, sysdb, dom, gids[i]);
            if (ret) {
                return ret;
            }
        }
        break;

    default:
        ret = EIO;
        DEBUG(2, ("proxy -> initgroups_dyn failed (%d)[%s]\n",
                  ret, strerror(ret)));
        break;
    }

    return ret;
}

/* =Proxy_Id-Functions====================================================*/

void proxy_get_account_info(struct be_req *breq)
{
    struct be_acct_req *ar;
    struct proxy_id_ctx *ctx;
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;
    uid_t uid;
    gid_t gid;
    int ret;

    ar = talloc_get_type(breq->req_data, struct be_acct_req);
    ctx = talloc_get_type(breq->be_ctx->bet_info[BET_ID].pvt_bet_data,
                          struct proxy_id_ctx);
    ev = breq->be_ctx->ev;
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
        case BE_FILTER_NAME:
            if (strchr(ar->filter_value, '*')) {
                ret = enum_users(breq, ctx, sysdb, domain);
            } else {
                ret = get_pw_name(breq, ctx, sysdb, domain, ar->filter_value);
            }
            break;

        case BE_FILTER_IDNUM:
            if (strchr(ar->filter_value, '*')) {
                return proxy_reply(breq, DP_ERR_FATAL,
                                   EINVAL, "Invalid attr type");
            } else {
                char *endptr;
                errno = 0;
                uid = (uid_t)strtol(ar->filter_value, &endptr, 0);
                if (errno || *endptr || (ar->filter_value == endptr)) {
                    return proxy_reply(breq, DP_ERR_FATAL,
                                       EINVAL, "Invalid attr type");
                }
                ret = get_pw_uid(breq, ctx, sysdb, domain, uid);
            }
            break;
        default:
            return proxy_reply(breq, DP_ERR_FATAL,
                               EINVAL, "Invalid filter type");
        }
        break;

    case BE_REQ_GROUP: /* group */
        switch (ar->filter_type) {
        case BE_FILTER_NAME:
            if (strchr(ar->filter_value, '*')) {
                ret = enum_groups(breq, ctx, sysdb, domain);
            } else {
                ret = get_gr_name(breq, ctx, sysdb, domain, ar->filter_value);
            }
            break;
        case BE_FILTER_IDNUM:
            if (strchr(ar->filter_value, '*')) {
                return proxy_reply(breq, DP_ERR_FATAL,
                                   EINVAL, "Invalid attr type");
            } else {
                char *endptr;
                errno = 0;
                gid = (gid_t)strtol(ar->filter_value, &endptr, 0);
                if (errno || *endptr || (ar->filter_value == endptr)) {
                    return proxy_reply(breq, DP_ERR_FATAL,
                                       EINVAL, "Invalid attr type");
                }
                ret = get_gr_gid(breq, ctx, sysdb, domain, gid);
            }
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
        if (strchr(ar->filter_value, '*')) {
            return proxy_reply(breq, DP_ERR_FATAL,
                               EINVAL, "Invalid filter value");
        }
        if (ctx->ops.initgroups_dyn == NULL) {
            return proxy_reply(breq, DP_ERR_FATAL,
                               ENODEV, "Initgroups call not supported");
        }
        ret = get_initgr(breq, ctx, sysdb, domain, ar->filter_value);
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
