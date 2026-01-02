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

#include "config.h"
#include <unistd.h>

#ifdef HAVE_KRB5_KRB5_H
#include <krb5/krb5.h>
#else
#include <krb5.h>
#endif

#include "providers/krb5/krb5_ccache.h"
#include "util/sss_krb5.h"
#include "util/util.h"


/* `switch_to_()` functions expect that
 * real id == user id; set id == service id.
 * This is prepared (set) in `privileged_krb5_setup()`
 * if process has corresponding capabilities.
 */
errno_t switch_to_user(void)
{
    int ret;
    uid_t ruid, euid, suid;
    gid_t rgid, egid, sgid;

    ret = getresuid(&ruid, &euid, &suid);
    if (ret != 0) {
        return errno;
    }

    ret = getresgid(&rgid, &egid, &sgid);
    if (ret != 0) {
        return errno;
    }

    ret = setresuid(-1, ruid, -1);
    if (ret != 0) {
        return errno;
    }

    ret = setresgid(-1, rgid, -1);
    if (ret != 0) {
        setresuid(-1, suid, -1);
        return errno;
    }

    return EOK;
}

static errno_t switch_to_service(void)
{
    int ret;
    uid_t ruid, euid, suid;
    gid_t rgid, egid, sgid;

    ret = getresuid(&ruid, &euid, &suid);
    if (ret != 0) {
        return errno;
    }

    ret = getresgid(&rgid, &egid, &sgid);
    if (ret != 0) {
        return errno;
    }

    ret = setresuid(-1, suid, -1);
    if (ret != 0) {
        return errno;
    }

    ret = setresgid(-1, sgid, -1);
    if (ret != 0) {
        setresuid(-1, ruid, -1);
        return errno;
    }

    return EOK;
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
        if ( (parent_stat->st_mode & (S_IXUSR|S_IRUSR|S_IWUSR)) !=
            (S_IXUSR|S_IRUSR|S_IWUSR) ) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Parent directory is owned but not accessible by user?!\n");
            return EINVAL;
        }
    } else {
        if ( (parent_stat->st_mode & (S_IXOTH|S_IROTH|S_IWOTH)) !=
            (S_IXOTH|S_IROTH|S_IWOTH) ) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Parent directory is owned by root and not accessible to "
                  "user\n");
            return EINVAL;
        }
    }

    return EOK;
}

errno_t sss_krb5_precheck_ccache(const char *ccname, uid_t uid, gid_t gid)
{
    TALLOC_CTX *tmp_ctx = NULL;
    const char *filename;
    char *ccdirname;
    char *end;
    struct stat parent_stat;
    errno_t ret;

    if (ccname[0] == '/') {
        filename = ccname;
    } else if (strncmp(ccname, "FILE:", 5) == 0) {
        filename = ccname + 5;
    } else if (strncmp(ccname, "DIR:", 4) == 0) {
        filename = ccname + 4;
    } else {
        /* only FILE and DIR types need pre-checks, we ignore any
         * other type */
        DEBUG(SSSDBG_TRACE_ALL, "No checks needed for [%s]\n", ccname);
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

    /* Get parent directory of wanted ccache directory/file,
     * removing trailing slashes from the back
     */
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

    sss_set_cap_effective(CAP_DAC_READ_SEARCH, true);
    ret = stat(ccdirname, &parent_stat);
    sss_set_cap_effective(CAP_DAC_READ_SEARCH, false);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot stat() [%s]\n", ccdirname);
        ret = EINVAL;
        goto done;
    }

    ret = check_parent_stat(&parent_stat, uid);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Check the ownership and permissions of krb5_ccachedir: [%s].\n",
              ccdirname);
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

struct sss_krb5_ccache {
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
    return 0;
}

static errno_t sss_open_ccache(TALLOC_CTX *mem_ctx,
                               const char *ccname,
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

static errno_t sss_krb5_cc_destroy(const char *ccname)
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

    ret = sss_open_ccache(tmp_ctx, ccname, &cc);
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

errno_t sss_krb5_cc_verify_ccache(const char *ccname, const char *realm,
                                  const char *principal)
{
    struct sss_krb5_ccache *cc = NULL;
    TALLOC_CTX *tmp_ctx = NULL;
    krb5_principal tgt_princ = NULL;
    krb5_principal princ = NULL;
    char *tgt_name;
    krb5_creds mcred = { 0 };
    krb5_creds cred = { 0 };
    krb5_error_code kerr;
    errno_t ret, switch_ret;

    ret = switch_to_user();
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to switch to user IDs: %d\n", ret);
        return ret;
    }

    /* First of all verify if the old ccache file/dir exists as we may be
     * trying to verify if an old ccache exists at all. If no file/dir
     * exists bail out immediately otherwise a following krb5_cc_resolve()
     * call may actually create paths and files we do not want to have
     * around.
     */
    ret = sss_low_level_path_check(ccname);
    if (ret) {
        goto done;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sss_open_ccache(tmp_ctx, ccname, &cc);
    if (ret) {
        goto done;
    }

    tgt_name = talloc_asprintf(tmp_ctx, "krbtgt/%s@%s", realm, realm);
    if (!tgt_name) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf() failed.\n");
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
    switch_ret = switch_to_service();
    if (switch_ret != EOK) {
        if (ret == EOK) ret = switch_ret;
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to switch to service IDs: %d\n", ret);
    }
    if (tgt_princ) krb5_free_principal(cc->context, tgt_princ);
    if (princ) krb5_free_principal(cc->context, princ);
    talloc_free(tmp_ctx);
    return ret;
}

errno_t safe_remove_old_ccache_file(const char *old_ccache,
                                    const char *new_ccache)
{
    if ((old_ccache == new_ccache)
        || (old_ccache && new_ccache
            && (strcmp(old_ccache, new_ccache) == 0))) {
        DEBUG(SSSDBG_TRACE_FUNC, "New and old ccache file are the same, "
                                  "none will be deleted.\n");
        return EOK;
    }

    /* safe_remove_old_ccache_file() is always run with user effective IDs */
    return sss_krb5_cc_destroy(old_ccache);
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

    krb5_free_string(kctx, ccache_name);
    krb5_free_principal(kctx, princ);

    if (krb5_cc_close(kctx, ccache) != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "krb5_cc_close failed.\n");
    }

    if ((mem_ccache != NULL) && (krb5_cc_close(kctx, mem_ccache) != 0)) {
        DEBUG(SSSDBG_OP_FAILURE, "krb5_cc_close failed.\n");
    }

    return  kerr;
}
