/*
    SSSD

    Kerberos 5 Backend Module -- ccache related utilities

    Authors:
        Sumit Bose <sbose@redhat.com>
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2014 Red Hat

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

#ifdef HAVE_KRB5_KRB5_H
#include <krb5/krb5.h>
#else
#include <krb5.h>
#endif

#include "providers/krb5/krb5_ccache.h"
#include "util/sss_krb5.h"
#include "util/util.h"

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

static errno_t create_ccache_dir(const char *ccdirname, uid_t uid, gid_t gid)
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

errno_t sss_krb5_precreate_ccache(const char *ccname, uid_t uid, gid_t gid)
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

    ret = create_ccache_dir(ccdirname, uid, gid);
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

    kerr = sss_krb5_init_context(&cc->context);
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

    if (ccname == NULL) {
        /* nothing to remove */
        return EOK;
    }

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
errno_t sss_krb5_check_ccache_princ(krb5_context kctx,
                                    const char *ccname,
                                    krb5_principal user_princ)
{
    krb5_ccache kcc = NULL;
    krb5_principal ccprinc = NULL;
    krb5_error_code kerr;
    const char *cc_type;
    errno_t ret;

    kerr = krb5_cc_resolve(kctx, ccname, &kcc);
    if (kerr) {
        ret = ERR_INTERNAL;
        goto done;
    }

    cc_type = krb5_cc_get_type(kctx, kcc);

    kerr = krb5_cc_get_principal(kctx, kcc, &ccprinc);
    if (kerr != 0) {
        KRB5_DEBUG(SSSDBG_OP_FAILURE, kctx, kerr);
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_cc_get_principal failed.\n");
    }

    if (ccprinc) {
        if (krb5_principal_compare(kctx, user_princ, ccprinc) == TRUE) {
            /* found in the primary ccache */
            ret = EOK;
            goto done;
        }
    }

#ifdef HAVE_KRB5_CC_COLLECTION

    if (krb5_cc_support_switch(kctx, cc_type)) {

        krb5_cc_close(kctx, kcc);
        kcc = NULL;

        kerr = krb5_cc_set_default_name(kctx, ccname);
        if (kerr != 0) {
            KRB5_DEBUG(SSSDBG_MINOR_FAILURE, kctx, kerr);
            /* try to continue despite failure */
        }

        kerr = krb5_cc_cache_match(kctx, user_princ, &kcc);
        if (kerr == 0) {
            ret = EOK;
            goto done;
        }
        KRB5_DEBUG(SSSDBG_TRACE_INTERNAL, kctx, kerr);
    }

#endif /* HAVE_KRB5_CC_COLLECTION */

    ret = ERR_NOT_FOUND;

done:
    if (ccprinc) {
        krb5_free_principal(kctx, ccprinc);
    }
    if (kcc) {
        krb5_cc_close(kctx, kcc);
    }
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
    /* Type krb5_timestamp is a signed 32-bit integer, so we need to convert the
     * 64-bit time_t value returned by time(). Just keeping the lower 32 bits
     * should be enough as Kerberos seems to be planing on making this time
     * unsigned to avoid the Y2K38 problem.
     * Please check:
     * https://web.mit.edu/kerberos/krb5-latest/doc/appdev/y2038.html
     */
    mcred.times.endtime = time(NULL) & 0xFFFFFFFF;

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

    kerr = sss_krb5_init_context(&ctx);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_krb5_init_context failed.\n");
        goto done;
    }

    kerr = krb5_parse_name(ctx, client_name, &client_princ);
    if (kerr != 0) {
        KRB5_DEBUG(SSSDBG_OP_FAILURE, ctx, kerr);
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_parse_name failed.\n");
        goto done;
    }

    sss_krb5_princ_realm(ctx, client_princ, &realm_name, &realm_length);
    if (realm_length == 0) {
        kerr = KRB5KRB_ERR_GENERIC;
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_krb5_princ_realm failed.\n");
        goto done;
    }

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

errno_t safe_remove_old_ccache_file(const char *old_ccache,
                                    const char *new_ccache,
                                    uid_t uid, gid_t gid)
{
    if ((old_ccache == new_ccache)
        || (old_ccache && new_ccache
            && (strcmp(old_ccache, new_ccache) == 0))) {
        DEBUG(SSSDBG_TRACE_FUNC, "New and old ccache file are the same, "
                                  "none will be deleted.\n");
        return EOK;
    }

    return sss_krb5_cc_destroy(old_ccache, uid, gid);
}

krb5_error_code copy_ccache_into_memory(TALLOC_CTX *mem_ctx, krb5_context kctx,
                                        const char *ccache_file,
                                        char **_mem_name)
{
    krb5_error_code kerr;
    krb5_ccache ccache;
    krb5_ccache mem_ccache = NULL;
    char *ccache_name = NULL;
    krb5_principal princ = NULL;
    char *mem_name = NULL;
    char *sep;

    kerr = krb5_cc_resolve(kctx, ccache_file, &ccache);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "error resolving ccache [%s].\n",
                                    ccache_file);
        return kerr;
    }

    kerr = krb5_cc_get_full_name(kctx, ccache, &ccache_name);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to read name for ccache [%s].\n",
                                    ccache_file);
        goto done;
    }

    sep = strchr(ccache_name, ':');
    if (sep == NULL || sep[1] == '\0') {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Ccache name [%s] does not have delimiter[:] .\n", ccache_name);
        kerr = KRB5KRB_ERR_GENERIC;
        goto done;
    }

    if (strncmp(ccache_name, "MEMORY:", sizeof("MEMORY:") -1) == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "Ccache [%s] is already memory ccache.\n",
                                 ccache_name);
        *_mem_name = talloc_strdup(mem_ctx, ccache_name);
        if(*_mem_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            kerr = KRB5KRB_ERR_GENERIC;
            goto done;
        }
        kerr = 0;
        goto done;
    }
    if (strncmp(ccache_name, "FILE:", sizeof("FILE:") -1) == 0) {
        mem_name = talloc_asprintf(mem_ctx, "MEMORY:%s", sep + 1);
        if (mem_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
            kerr = KRB5KRB_ERR_GENERIC;
            goto done;
        }
    } else {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unexpected ccache type for ccache [%s], " \
                                    "currently only FILE is supported.\n",
                                    ccache_name);
        kerr = KRB5KRB_ERR_GENERIC;
        goto done;
    }

    kerr = krb5_cc_resolve(kctx, mem_name, &mem_ccache);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "error resolving ccache [%s].\n", mem_name);
        goto done;
    }

    kerr = krb5_cc_get_principal(kctx, ccache, &princ);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "error reading principal from ccache [%s].\n", ccache_name);
        goto done;
    }

    kerr = krb5_cc_initialize(kctx, mem_ccache, princ);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to initialize ccache [%s].\n", mem_name);
        goto done;
    }

    kerr = krb5_cc_copy_creds(kctx, ccache, mem_ccache);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to copy ccache [%s] to [%s].\n", ccache_name, mem_name);
        goto done;
    }

    *_mem_name = mem_name;
    kerr = 0;

done:
    if (kerr != 0) {
        talloc_free(mem_name);
    }

    free(ccache_name);
    krb5_free_principal(kctx, princ);

    if (krb5_cc_close(kctx, ccache) != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "krb5_cc_close failed.\n");
    }

    if (krb5_cc_close(kctx, mem_ccache) != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "krb5_cc_close failed.\n");
    }

    return  kerr;
}
