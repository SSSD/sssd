/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2012 Red Hat

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

#include <errno.h>
#include <stdlib.h>

#include "sss_client/autofs/sss_autofs_private.h"
#include "sss_client/sss_cli.h"

/* Historically, autofs map and key names were just file names */
#define MAX_AUTOMNTMAPNAME_LEN  NAME_MAX
#define MAX_AUTOMNTKEYNAME_LEN  NAME_MAX

struct automtent {
    char *mapname;
    size_t cursor;
};

errno_t
_sss_setautomntent(const char *mapname, void **context)
{
    errno_t ret;
    int errnop;
    struct automtent *ctx;
    char *name;
    size_t name_len;
    struct sss_cli_req_data rd;
    uint8_t *repbuf = NULL;
    size_t replen;

    if (!mapname) return EINVAL;

    sss_nss_lock();

    ret = sss_strnlen(mapname, MAX_AUTOMNTMAPNAME_LEN, &name_len);
    if (ret != 0) {
        ret = EINVAL;
        goto out;
    }

    name = malloc(sizeof(char)*name_len + 1);
    if (name == NULL) {
        ret = ENOMEM;
        goto out;
    }
    strncpy(name, mapname, name_len + 1);

    rd.data = name;
    rd.len = name_len + 1;

    sss_autofs_make_request(SSS_AUTOFS_SETAUTOMNTENT, &rd,
                            &repbuf, &replen, &errnop);
    if (errnop != 0) {
        free(name);
        ret = errnop;
        goto out;
    }

    /* no results if not found */
    if (((uint32_t *)repbuf)[0] == 0) {
        free(name);
        free(repbuf);
        ret = ENOENT;
        goto out;
    }
    free(repbuf);

    ctx = malloc(sizeof(struct automtent));
    if (!ctx) {
        free(name);
        ret = ENOMEM;
        goto out;
    }

    ctx->mapname = strdup(name);
    if (!ctx->mapname) {
        free(name);
        free(ctx);
        ret = ENOMEM;
        goto out;
    }
    ctx->cursor = 0;
    free(name);

    *context = ctx;
    ret = 0;
out:
    sss_nss_unlock();
    return ret;
}

errno_t
_sss_getautomntent_r(char **key, char **value, void *context)
{
    int errnop;
    errno_t ret;
    size_t name_len;
    struct sss_cli_req_data rd;
    uint8_t *repbuf = NULL;
    size_t replen;
    struct automtent *ctx;
    size_t ctr = 0;
    size_t data_len = 0;
    uint8_t *data;
    uint32_t v;

    char *buf;
    uint32_t len;
    uint32_t keylen;
    uint32_t vallen;
    size_t rp;

    sss_nss_lock();

    ctx = (struct automtent *) context;
    if (!ctx) {
        ret = EINVAL;
        goto out;
    }

    /* Be paranoid in case someone tries to smuggle in a huge map name */
    ret = sss_strnlen(ctx->mapname, MAX_AUTOMNTMAPNAME_LEN, &name_len);
    if (ret != 0) {
        ret = EINVAL;
        goto out;
    }

    data_len = sizeof(uint32_t) +            /* mapname len */
               name_len + 1 +                /* mapname\0   */
               sizeof(uint32_t);             /* index into the map */

    data = malloc(data_len);
    if (!data) {
        ret = ENOMEM;
        goto out;
    }

    v = name_len;
    SAFEALIGN_COPY_UINT32(data, &v, &ctr);

    safealign_memcpy(data+ctr, ctx->mapname, name_len + 1, &ctr);

    v = ctx->cursor;
    SAFEALIGN_COPY_UINT32(data+ctr, &v, &ctr);

    rd.data = data;
    rd.len = data_len;

    sss_autofs_make_request(SSS_AUTOFS_GETAUTOMNTENT, &rd,
                            &repbuf, &replen, &errnop);
    free(data);
    if (errnop != 0) {
        ret = errnop;
        goto out;
    }

    /* Got reply, let's parse it */
    rp = 0;
    SAFEALIGN_COPY_UINT32(&len, repbuf+rp, &rp);
    if (len == 0) {
        /* End of iteration */
        *key = NULL;
        *value = NULL;
        ret = ENOENT;
        goto out;
    }

    SAFEALIGN_COPY_UINT32(&keylen, repbuf+rp, &rp);
    if (keylen > len-rp) {
        ret = EIO;
        goto out;
    }

    buf = malloc(keylen);
    if (!buf) {
        ret = ENOMEM;
        goto out;
    }

    safealign_memcpy(buf, repbuf+rp, keylen, &rp);
    *key = buf;

    SAFEALIGN_COPY_UINT32(&vallen, repbuf+rp, &rp);
    if (vallen > len-rp) {
        ret = EIO;
        goto out;
    }

    buf = malloc(vallen);
    if (!buf) {
        free(*key);
        ret = ENOMEM;
        goto out;
    }

    safealign_memcpy(buf, repbuf+rp, vallen, &rp);
    *value = buf;

    /* Advance the cursor so that we'll fetch the next map
     * next time getautomntent is called */
    ctx->cursor++;
    ret = 0;
out:
    free(repbuf);
    sss_nss_unlock();
    return ret;
}

errno_t
_sss_getautomntbyname_r(const char *key, char **value, void *context)
{
    int errnop;
    errno_t ret;
    struct automtent *ctx;
    size_t key_len;
    size_t name_len;
    size_t data_len = 0;
    uint8_t *data;
    uint32_t v;
    size_t ctr = 0;
    struct sss_cli_req_data rd;
    uint8_t *repbuf = NULL;
    size_t replen;

    char *buf;
    uint32_t len;
    uint32_t vallen;
    size_t rp;

    sss_nss_lock();

    ctx = (struct automtent *) context;
    if (!ctx || !key) {
        ret = EINVAL;
        goto out;
    }

    /* Be paranoid in case someone tries to smuggle in a huge map name */
    ret = sss_strnlen(ctx->mapname, MAX_AUTOMNTMAPNAME_LEN, &name_len);
    if (ret != 0) {
        ret = EINVAL;
        goto out;
    }

    ret = sss_strnlen(ctx->mapname, MAX_AUTOMNTKEYNAME_LEN, &key_len);
    if (ret != 0) {
        ret = EINVAL;
        goto out;
    }


    data_len = sizeof(uint32_t) +            /* mapname len */
               name_len + 1 +                /* mapname\0   */
               sizeof(uint32_t) +            /* keyname len */
               key_len + 1;                  /* keyname\0   */

    data = malloc(data_len);
    if (!data) {
        ret = ENOMEM;
        goto out;
    }

    v = name_len;
    SAFEALIGN_COPY_UINT32(data, &v, &ctr);

    safealign_memcpy(data+ctr, ctx->mapname, name_len + 1, &ctr);

    v = key_len;
    SAFEALIGN_COPY_UINT32(data+ctr, &v, &ctr);

    safealign_memcpy(data+ctr, key, key_len + 1, &ctr);

    rd.data = data;
    rd.len = data_len;

    sss_autofs_make_request(SSS_AUTOFS_GETAUTOMNTBYNAME, &rd,
                            &repbuf, &replen, &errnop);
    free(data);
    if (errnop != 0) {
        ret = errnop;
        goto out;
    }

    /* Got reply, let's parse it */
    rp = 0;
    SAFEALIGN_COPY_UINT32(&len, repbuf+rp, &rp);
    if (len == 0) {
        /* No data */
        *value = NULL;
        ret = ENOENT;
        goto out;
    }

    SAFEALIGN_COPY_UINT32(&vallen, repbuf+rp, &rp);
    if (vallen > len-rp) {
        ret = EIO;
        goto out;
    }

    buf = malloc(vallen);
    if (!buf) {
        ret = ENOMEM;
        goto out;
    }

    safealign_memcpy(buf, repbuf+rp, vallen, &rp);
    *value = buf;

    ret = 0;
out:
    free(repbuf);
    sss_nss_unlock();
    return ret;
}

errno_t
_sss_endautomntent(void **context)
{
    struct automtent *fctx;
    errno_t ret;
    int errnop;

    if (!context) return 0;

    sss_nss_lock();

    fctx = (struct automtent *) *context;

    free(fctx->mapname);
    free(fctx);

    sss_autofs_make_request(SSS_AUTOFS_ENDAUTOMNTENT,
                            NULL, NULL, NULL, &errnop);
    if (errnop != 0) {
        ret = errnop;
        goto out;
    }

    ret = 0;
out:
    sss_nss_unlock();
    return ret;
}
