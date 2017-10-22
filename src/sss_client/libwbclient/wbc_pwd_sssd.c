/*
   Unix SMB/CIFS implementation.

   Winbind client API - SSSD version

   Copyright (C) Sumit Bose <sbose@redhat.com> 2014

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
/* Required Headers */

#include <nss.h>
#include <dlfcn.h>
#include <errno.h>

#include "libwbclient.h"
#include "wbc_sssd_internal.h"

#define DEFAULT_BUFSIZE_HALF 2048
#define DEFAULT_BUFSIZE (2 * DEFAULT_BUFSIZE_HALF)
#define MAX_BUFSIZE (1024*1204)

struct nss_ops_ctx {
    void *dl_handle;

    enum nss_status (*getpwnam_r)(const char *name, struct passwd *result,
                      char *buffer, size_t buflen, int *errnop);
    enum nss_status (*getpwuid_r)(uid_t uid, struct passwd *result,
                      char *buffer, size_t buflen, int *errnop);
    enum nss_status (*setpwent)(void);
    enum nss_status (*getpwent_r)(struct passwd *result,
                      char *buffer, size_t buflen, int *errnop);
    enum nss_status (*endpwent)(void);

    enum nss_status (*getgrnam_r)(const char *name, struct group *result,
                      char *buffer, size_t buflen, int *errnop);
    enum nss_status (*getgrgid_r)(gid_t gid, struct group *result,
                      char *buffer, size_t buflen, int *errnop);
    enum nss_status (*setgrent)(void);
    enum nss_status (*getgrent_r)(struct group *result,
                      char *buffer, size_t buflen, int *errnop);
    enum nss_status (*endgrent)(void);

    enum nss_status (*initgroups_dyn)(const char *user, gid_t group,
                          long int *start, long int *size,
                          gid_t **groups, long int limit,
                          int *errnop);
};

struct nss_ops_ctx *ctx = NULL;

static bool open_libnss_sss(void)
{
    ctx = calloc(1, sizeof(struct nss_ops_ctx));
    if (ctx == NULL) {
        return false;
    }

    ctx->dl_handle = dlopen("libnss_sss.so.2", RTLD_NOW);
    if (ctx->dl_handle == NULL) {
        goto fail;
    }

    ctx->getpwnam_r = dlsym(ctx->dl_handle, "_nss_sss_getpwnam_r");
    if (ctx->getpwnam_r == NULL) {
        goto fail;
    }

    ctx->getpwuid_r = dlsym(ctx->dl_handle, "_nss_sss_getpwuid_r");
    if (ctx->getpwuid_r == NULL) {
        goto fail;
    }

    ctx->setpwent = dlsym(ctx->dl_handle, "_nss_sss_setpwent");
    if (ctx->setpwent == NULL) {
        goto fail;
    }

    ctx->getpwent_r = dlsym(ctx->dl_handle, "_nss_sss_getpwent_r");
    if (ctx->getpwent_r == NULL) {
        goto fail;
    }

    ctx->endpwent = dlsym(ctx->dl_handle, "_nss_sss_endpwent");
    if (ctx->endpwent == NULL) {
        goto fail;
    }

    ctx->getgrnam_r = dlsym(ctx->dl_handle, "_nss_sss_getgrnam_r");
    if (ctx->getgrnam_r == NULL) {
        goto fail;
    }

    ctx->getgrgid_r = dlsym(ctx->dl_handle, "_nss_sss_getgrgid_r");
    if (ctx->getgrgid_r == NULL) {
        goto fail;
    }

    ctx->setgrent = dlsym(ctx->dl_handle, "_nss_sss_setgrent");
    if (ctx->setgrent == NULL) {
        goto fail;
    }

    ctx->getgrent_r = dlsym(ctx->dl_handle, "_nss_sss_getgrent_r");
    if (ctx->getgrent_r == NULL) {
        goto fail;
    }

    ctx->endgrent = dlsym(ctx->dl_handle, "_nss_sss_endgrent");
    if (ctx->endgrent == NULL) {
        goto fail;
    }

    ctx->initgroups_dyn = dlsym(ctx->dl_handle, "_nss_sss_initgroups_dyn");
    if (ctx->initgroups_dyn == NULL) {
        goto fail;
    }

    return true;

fail:
    if (ctx->dl_handle != NULL) {
        dlclose(ctx->dl_handle);
    }

    free(ctx);
    ctx = NULL;

    return false;
}

static void wbcPasswdDestructor(void *ptr)
{
    struct passwd *pw = (struct passwd *)ptr;
    free(pw->pw_name);
    free(pw->pw_passwd);
    free(pw->pw_gecos);
    free(pw->pw_shell);
    free(pw->pw_dir);
}

static wbcErr copy_pwd(struct passwd *in, struct passwd **out)
{
    struct passwd *pw;

    pw = (struct passwd *)wbcAllocateMemory(1, sizeof(struct passwd),
                          wbcPasswdDestructor);
    if (pw == NULL) {
        return WBC_ERR_NO_MEMORY;
    }

    pw->pw_name = strdup(in->pw_name);
    if (pw->pw_name == NULL) {
        goto fail;
    }

    pw->pw_passwd = strdup(in->pw_passwd);
    if (pw->pw_passwd == NULL) {
        goto fail;
    }

    pw->pw_uid = in->pw_uid;
    pw->pw_gid = in->pw_gid;

    pw->pw_gecos = strdup(in->pw_gecos);
    if (pw->pw_gecos == NULL) {
        goto fail;
    }

    pw->pw_shell = strdup(in->pw_shell);
    if (pw->pw_shell == NULL) {
        goto fail;
    }

    pw->pw_dir = strdup(in->pw_dir);
    if (pw->pw_dir == NULL) {
        goto fail;
    }

    *out = pw;
    return WBC_ERR_SUCCESS;
fail:
    wbcFreeMemory(pw);

    return WBC_ERR_NO_MEMORY;
}

static wbcErr nss_to_wbc(enum nss_status status)
{
    wbcErr wbc_status;

    switch (status) {
    case NSS_STATUS_SUCCESS:
        wbc_status = WBC_ERR_SUCCESS;
        break;
    case NSS_STATUS_NOTFOUND:
        wbc_status = WBC_ERR_UNKNOWN_USER;
        break;
    case NSS_STATUS_UNAVAIL:
        wbc_status = WBC_ERR_WINBIND_NOT_AVAILABLE;
        break;
    default:
        wbc_status = WBC_ERR_UNKNOWN_FAILURE;
    }

    return wbc_status;
}

/* Fill in a struct passwd* for a domain user based on username */
wbcErr wbcGetpwnam(const char *name, struct passwd **pwd)
{
    struct passwd lpwd = {0};
    enum nss_status status;
    char *buffer = NULL;
    size_t buflen;
    wbcErr wbc_status;
    int nss_errno;

    if (ctx == NULL && !open_libnss_sss()) {
        return WBC_ERR_NSS_ERROR;
    }

    if (name == NULL || pwd == NULL) {
        return WBC_ERR_INVALID_PARAM;
    }

    buflen = DEFAULT_BUFSIZE;
    buffer = malloc(buflen);
    if (buffer == NULL) {
        return WBC_ERR_NO_MEMORY;
    }

    status = ctx->getpwnam_r(name, &lpwd, buffer, buflen, &nss_errno);
    wbc_status = nss_to_wbc(status);
    if (WBC_ERROR_IS_OK(wbc_status) == true) {
        wbc_status = copy_pwd(&lpwd, pwd);
    }

    free(buffer);

    return wbc_status;
}

/* Fill in a struct passwd* for a domain user based on uid */
wbcErr wbcGetpwuid(uid_t uid, struct passwd **pwd)
{
    struct passwd lpwd = {0};
    enum nss_status status;
    char *buffer = NULL;
    size_t buflen;
    wbcErr wbc_status;
    int nss_errno;

    if (ctx == NULL && !open_libnss_sss()) {
        return WBC_ERR_NSS_ERROR;
    }

    if (pwd == NULL) {
        return WBC_ERR_INVALID_PARAM;
    }

    buflen = DEFAULT_BUFSIZE;
    buffer = malloc(buflen);
    if (buffer == NULL) {
        return WBC_ERR_NO_MEMORY;
    }

    status = ctx->getpwuid_r(uid, &lpwd, buffer, buflen, &nss_errno);
    wbc_status = nss_to_wbc(status);
    if (WBC_ERROR_IS_OK(wbc_status) == true) {
        wbc_status = copy_pwd(&lpwd, pwd);
    }

    free(buffer);

    return wbc_status;
}

/* Fill in a struct passwd* for a domain user based on sid */
wbcErr wbcGetpwsid(struct wbcDomainSid *sid, struct passwd **pwd)
{
    wbcErr wbc_status;
    uid_t uid;

    wbc_status = wbcSidToUid(sid, &uid);
    if (!WBC_ERROR_IS_OK(wbc_status)) {
        return wbc_status;
    }

    wbc_status = wbcGetpwuid(uid, pwd);

    return wbc_status;

}

static void wbcGroupDestructor(void *ptr)
{
    struct group *gr = (struct group *)ptr;
    size_t c;

    free(gr->gr_name);
    free(gr->gr_passwd);

    /* if the array was partly created this can be NULL */
    if (gr->gr_mem == NULL) {
        return;
    }

    for (c=0; gr->gr_mem[c] != NULL; c++) {
        free(gr->gr_mem[c]);
    }
    free(gr->gr_mem);
}

static wbcErr copy_grp(struct group *in, struct group **out)
{
    struct group *gr;
    size_t members;
    size_t c;

    gr = (struct group *)wbcAllocateMemory(1, sizeof(struct group),
                          wbcGroupDestructor);
    if (gr == NULL) {
        return WBC_ERR_NO_MEMORY;
    }

    gr->gr_name = strdup(in->gr_name);
    if (gr->gr_name == NULL) {
        goto fail;
    }

    gr->gr_passwd = strdup(in->gr_passwd);
    if (gr->gr_passwd == NULL) {
        goto fail;
    }

    gr->gr_gid = in->gr_gid;

    for (members = 0; in->gr_mem[members] != NULL; members++);

    gr->gr_mem = (char **)calloc(members+1, sizeof(char *));
    if (gr->gr_mem == NULL) {
        goto fail;
    }

    for (c = 0; c < members; c++) {
        gr->gr_mem[c] = strdup(in->gr_mem[c]);
        if (gr->gr_mem[c] == NULL) {
            goto fail;
        }
    }

    *out = gr;
    return WBC_ERR_SUCCESS;
fail:
    wbcFreeMemory(gr);

    return WBC_ERR_NO_MEMORY;
}
/* Fill in a struct passwd* for a domain user based on username */
wbcErr wbcGetgrnam(const char *name, struct group **grp)
{
    struct group lgrp;
    enum nss_status status;
    char *newbuffer = NULL;
    char *buffer = NULL;
    size_t buflen = 0;
    wbcErr wbc_status;
    int nss_errno;

    if (ctx == NULL && !open_libnss_sss()) {
        return WBC_ERR_NSS_ERROR;
    }

    if (name == NULL || grp == NULL) {
        return WBC_ERR_INVALID_PARAM;
    }

    buflen = DEFAULT_BUFSIZE_HALF;
    do {
        buflen *= 2;

        newbuffer = realloc(buffer, buflen);
        if (newbuffer == NULL) {
            free(buffer);
            return WBC_ERR_NO_MEMORY;
        }
        buffer = newbuffer;

        memset(grp, 0, sizeof(struct group));
        status = ctx->getgrnam_r(name, &lgrp, buffer, buflen, &nss_errno);
        wbc_status = nss_to_wbc(status);
        if (WBC_ERROR_IS_OK(wbc_status) == true) {
            wbc_status = copy_grp(&lgrp, grp);
        }
    } while (status == NSS_STATUS_TRYAGAIN && nss_errno == ERANGE \
         && buflen < MAX_BUFSIZE);

    free(buffer);

    return wbc_status;
}

/* Fill in a struct passwd* for a domain user based on uid */
wbcErr wbcGetgrgid(gid_t gid, struct group **grp)
{
    struct group lgrp;
    enum nss_status status;
    char *newbuffer = NULL;
    char *buffer = NULL;
    size_t buflen = 0;
    wbcErr wbc_status;
    int nss_errno;

    if (ctx == NULL && !open_libnss_sss()) {
        return WBC_ERR_NSS_ERROR;
    }

    if (grp == NULL) {
        return WBC_ERR_INVALID_PARAM;
    }

    buflen = DEFAULT_BUFSIZE_HALF;
    do {
        buflen *= 2;

        newbuffer = realloc(buffer, buflen);
        if (newbuffer == NULL) {
            free(buffer);
            return WBC_ERR_NO_MEMORY;
        }
        buffer = newbuffer;

        memset(grp, 0, sizeof(struct group));
        status = ctx->getgrgid_r(gid, &lgrp, buffer, buflen, &nss_errno);
        wbc_status = nss_to_wbc(status);
        if (WBC_ERROR_IS_OK(wbc_status) == true) {
            wbc_status = copy_grp(&lgrp, grp);
        }
    } while (status == NSS_STATUS_TRYAGAIN && nss_errno == ERANGE \
         && buflen < MAX_BUFSIZE);

    free(buffer);

    return wbc_status;
}

/* Reset the passwd iterator */
wbcErr wbcSetpwent(void)
{
    enum nss_status status;
    wbcErr wbc_status;

    if (ctx == NULL && !open_libnss_sss()) {
        return WBC_ERR_NSS_ERROR;
    }

    status = ctx->setpwent();
    wbc_status = nss_to_wbc(status);

    return wbc_status;
}

/* Close the passwd iterator */
wbcErr wbcEndpwent(void)
{
    enum nss_status status;
    wbcErr wbc_status;

    if (ctx == NULL && !open_libnss_sss()) {
        return WBC_ERR_NSS_ERROR;
    }

    status = ctx->endpwent();
    wbc_status = nss_to_wbc(status);

    return wbc_status;
}

/* Return the next struct passwd* entry from the pwent iterator */
wbcErr wbcGetpwent(struct passwd **pwd)
{
    struct passwd lpwd = {0};
    enum nss_status status;
    char *buffer = NULL;
    size_t buflen;
    wbcErr wbc_status;
    int nss_errno;

    if (ctx == NULL && !open_libnss_sss()) {
        return WBC_ERR_NSS_ERROR;
    }

    if (pwd == NULL) {
        return WBC_ERR_INVALID_PARAM;
    }

    buflen = DEFAULT_BUFSIZE;
    buffer = malloc(buflen);
    if (buffer == NULL) {
        return WBC_ERR_NO_MEMORY;
    }

    status = ctx->getpwent_r(&lpwd, buffer, buflen, &nss_errno);
    wbc_status = nss_to_wbc(status);
    if (WBC_ERROR_IS_OK(wbc_status) == true) {
        wbc_status = copy_pwd(&lpwd, pwd);
    }

    free(buffer);

    return wbc_status;
}

/* Reset the group iterator */
wbcErr wbcSetgrent(void)
{
    enum nss_status status;
    wbcErr wbc_status;

    if (ctx == NULL && !open_libnss_sss()) {
        return WBC_ERR_NSS_ERROR;
    }

    status = ctx->setgrent();
    wbc_status = nss_to_wbc(status);

    return wbc_status;
}

/* Close the group iterator */
wbcErr wbcEndgrent(void)
{
    enum nss_status status;
    wbcErr wbc_status;

    if (ctx == NULL && !open_libnss_sss()) {
        return WBC_ERR_NSS_ERROR;
    }

    status = ctx->endgrent();
    wbc_status = nss_to_wbc(status);

    return wbc_status;
}

/* Return the next struct group* entry from the pwent iterator */
wbcErr wbcGetgrent(struct group **grp)
{
    struct group lgrp;
    enum nss_status status;
    char *newbuffer = NULL;
    char *buffer = NULL;
    size_t buflen = 0;
    wbcErr wbc_status;
    int nss_errno;

    if (ctx == NULL && !open_libnss_sss()) {
        return WBC_ERR_NSS_ERROR;
    }

    if (grp == NULL) {
        return WBC_ERR_INVALID_PARAM;
    }

    buflen = DEFAULT_BUFSIZE_HALF;
    do {
        buflen *= 2;

        newbuffer = realloc(buffer, buflen);
        if (newbuffer == NULL) {
            free(buffer);
            return WBC_ERR_NO_MEMORY;
        }
        buffer = newbuffer;

        memset(grp, 0, sizeof(struct group));
        status = ctx->getgrent_r(&lgrp, buffer, buflen, &nss_errno);
        wbc_status = nss_to_wbc(status);
        if (WBC_ERROR_IS_OK(wbc_status) == true) {
            wbc_status = copy_grp(&lgrp, grp);
        }
    } while (status == NSS_STATUS_TRYAGAIN && nss_errno == ERANGE \
         && buflen < MAX_BUFSIZE);

    free(buffer);

    return wbc_status;
}

/* Return the next struct group* entry from the pwent iterator */
wbcErr wbcGetgrlist(struct group **grp)
{
    /* Not used anywhere */
    WBC_SSSD_NOT_IMPLEMENTED;
}

/* Return the Unix group array belonging to the given user */
wbcErr wbcGetGroups(const char *account,
            uint32_t *num_groups,
            gid_t **_groups)
{
    wbcErr wbc_status;
    enum nss_status status;
    struct passwd *pwd;
    long int gr_size = 0;
    long int start = 0;
    gid_t *gids = NULL;
    int nss_errno;

    wbc_status = wbcGetpwnam(account, &pwd);
    if (!WBC_ERROR_IS_OK(wbc_status)) {
        return wbc_status;
    }

    gr_size = DEFAULT_BUFSIZE;
    gids = calloc(gr_size, sizeof(gid_t));
    if (gids == NULL) {
        wbc_status = WBC_ERR_NO_MEMORY;
        goto done;
    }

    /* nss modules may skip the primary group when we pass it in so always
     * add it in advance */
    gids[0] = pwd->pw_gid;
    start++;

    status = ctx->initgroups_dyn(pwd->pw_name, pwd->pw_gid, &start,
                     &gr_size, &gids, -1, &nss_errno);
    wbc_status = nss_to_wbc(status);
    if (!WBC_ERROR_IS_OK(wbc_status)) {
        goto done;
    }

    *_groups = gids;
    *num_groups = start;

    wbc_status = WBC_ERR_SUCCESS;

done:
    wbcFreeMemory(pwd);

    if (!WBC_ERROR_IS_OK(wbc_status)) {
        free(gids);
    }

    return wbc_status;
}
