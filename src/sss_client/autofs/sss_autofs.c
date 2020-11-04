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
#include <stdatomic.h>

#include "sss_client/autofs/sss_autofs_private.h"
#include "sss_client/sss_cli.h"

/* Historically, autofs map names were just file names. Direct key names
 * may be full directory paths
 */
#define MAX_AUTOMNTMAPNAME_LEN  NAME_MAX
#define MAX_AUTOMNTKEYNAME_LEN  PATH_MAX

/* How many entries shall _sss_getautomntent_r retrieve at once */
#define GETAUTOMNTENT_MAX_ENTRIES   512

static atomic_uint _protocol = 0;

unsigned int _sss_auto_protocol_version(unsigned int requested)
{
    switch (requested) {
    case 0:
        /* EHOSTDOWN will be translated to ENOENT */
        _protocol = 0;
        return 0;
    default:
        /* There is no other protocol version at this point. */
        _protocol = 1;
        return 1;
    }
}

/* Returns correct errno based on autofs version expectations. */
static errno_t errnop_to_errno(int errnop)
{
    if (errnop == EHOSTDOWN && _protocol == 0) {
        return ENOENT;
    }

    return errnop;
}

struct automtent {
    char *mapname;
    size_t cursor;
};

static struct sss_getautomntent_data {
    char *mapname;
    size_t len;
    size_t ptr;
    uint8_t *data;
} sss_getautomntent_data;

static void
sss_getautomntent_data_clean(void)
{
    free(sss_getautomntent_data.data);
    free(sss_getautomntent_data.mapname);
    memset(&sss_getautomntent_data, 0, sizeof(struct sss_getautomntent_data));
}

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
    uint32_t num_results = 0;

    if (!mapname) return EINVAL;

    sss_nss_lock();

    /* Make sure there are no leftovers from previous runs */
    sss_getautomntent_data_clean();

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

    ret = sss_autofs_make_request(SSS_AUTOFS_SETAUTOMNTENT, &rd,
                                  &repbuf, &replen, &errnop);
    if (ret != SSS_STATUS_SUCCESS) {
        free(name);
        ret = errnop_to_errno(errnop);
        goto out;
    }

    /* Get number of results from repbuf. */
    SAFEALIGN_COPY_UINT32(&num_results, repbuf, NULL);

    /* no results if not found */
    if (num_results == 0) {
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

static errno_t
sss_getautomntent_data_return(const char *mapname, char **_key, char **_value)
{
    size_t dp;
    uint32_t len = 0;
    char *key = NULL;
    uint32_t keylen;
    char *value = NULL;
    uint32_t vallen;
    errno_t ret;

    if (sss_getautomntent_data.mapname == NULL ||
        sss_getautomntent_data.data == NULL ||
        sss_getautomntent_data.ptr >= sss_getautomntent_data.len) {
        /* We're done with this buffer */
        ret = ENOENT;
        goto done;
    }

    ret = strcmp(mapname, sss_getautomntent_data.mapname);
    if (ret != EOK) {
        /* The map we're looking for is not cached. Let responder
         * do an implicit setautomntent */
        ret = ENOENT;
        goto done;
    }

    dp = sss_getautomntent_data.ptr;

    SAFEALIGN_COPY_UINT32(&len, sss_getautomntent_data.data+dp, &dp);
    if (len + sss_getautomntent_data.ptr > sss_getautomntent_data.len) {
        /* len is bigger than the buffer */
        ret = EIO;
        goto done;
    }

    if (len == 0) {
        /* There are no more records. */
        *_key = NULL;
        *_value = NULL;
        ret = ENOENT;
        goto done;
    }

    SAFEALIGN_COPY_UINT32(&keylen, sss_getautomntent_data.data+dp, &dp);
    if (keylen + dp > sss_getautomntent_data.len) {
        ret = EIO;
        goto done;
    }

    key = malloc(keylen);
    if (!key) {
        ret = ENOMEM;
        goto done;
    }

    safealign_memcpy(key, sss_getautomntent_data.data+dp, keylen, &dp);

    SAFEALIGN_COPY_UINT32(&vallen, sss_getautomntent_data.data+dp, &dp);
    if (vallen + dp > sss_getautomntent_data.len) {
        ret = EIO;
        goto done;
    }

    value = malloc(vallen);
    if (!value) {
        ret = ENOMEM;
        goto done;
    }

    safealign_memcpy(value, sss_getautomntent_data.data+dp, vallen, &dp);

    sss_getautomntent_data.ptr = dp;
    *_key = key;
    *_value = value;
    return EOK;

done:
    free(key);
    free(value);
    sss_getautomntent_data_clean();
    return ret;
}

/* The repbuf is owned by the sss_getautomntent_data once this
 * function is called */
static errno_t
sss_getautomntent_data_save(const char *mapname, uint8_t **repbuf, size_t replen)
{
    size_t rp;
    uint32_t num;

    rp = 0;
    SAFEALIGN_COPY_UINT32(&num, *repbuf+rp, &rp);
    if (num == 0) {
        free(*repbuf);
        return ENOENT;
    }

    sss_getautomntent_data.mapname = strdup(mapname);
    if (sss_getautomntent_data.mapname == NULL) {
        free(*repbuf);
        return ENOENT;
    }

    sss_getautomntent_data.data = *repbuf;
    sss_getautomntent_data.len = replen;
    sss_getautomntent_data.ptr = rp;
    *repbuf = NULL;
    return EOK;
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

    ret = sss_getautomntent_data_return(ctx->mapname, key, value);
    if (ret == EOK) {
        /* The results are available from cache. Just advance the
         * cursor and return. */
        ctx->cursor++;
        ret = 0;
        goto out;
    }
    /* Don't try to handle any error codes, just go to the responder again */

    data_len = sizeof(uint32_t) +            /* mapname len */
               name_len + 1 +                /* mapname\0   */
               sizeof(uint32_t) +            /* index into the map */
               sizeof(uint32_t);             /* num entries to retrieve */

    data = malloc(data_len);
    if (!data) {
        ret = ENOMEM;
        goto out;
    }

    SAFEALIGN_SET_UINT32(data, name_len, &ctr);

    safealign_memcpy(data+ctr, ctx->mapname, name_len + 1, &ctr);

    SAFEALIGN_SET_UINT32(data+ctr, ctx->cursor, &ctr);

    SAFEALIGN_SET_UINT32(data+ctr, GETAUTOMNTENT_MAX_ENTRIES, &ctr);

    rd.data = data;
    rd.len = data_len;

    ret = sss_autofs_make_request(SSS_AUTOFS_GETAUTOMNTENT, &rd,
                                  &repbuf, &replen, &errnop);
    free(data);
    if (ret != SSS_STATUS_SUCCESS) {
        ret = errnop_to_errno(errnop);
        goto out;
    }

    /* Got reply, let's save it and return from "cache" */
    ret = sss_getautomntent_data_save(ctx->mapname, &repbuf, replen);
    if (ret == ENOENT) {
        /* No results */
        *key = NULL;
        *value = NULL;
        goto out;
    } else if (ret != EOK) {
        /* Unexpected error */
        goto out;
    }

    ret = sss_getautomntent_data_return(ctx->mapname, key, value);
    if (ret != EOK) {
        goto out;
    }

    /* Advance the cursor so that we'll fetch the next map
     * next time getautomntent is called */
    ctx->cursor++;
    ret = 0;
out:
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

    ret = sss_strnlen(key, MAX_AUTOMNTKEYNAME_LEN, &key_len);
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

    SAFEALIGN_SET_UINT32(data, name_len, &ctr);

    safealign_memcpy(data+ctr, ctx->mapname, name_len + 1, &ctr);

    SAFEALIGN_SET_UINT32(data+ctr, key_len, &ctr);

    safealign_memcpy(data+ctr, key, key_len + 1, &ctr);

    rd.data = data;
    rd.len = data_len;

    ret = sss_autofs_make_request(SSS_AUTOFS_GETAUTOMNTBYNAME, &rd,
                                  &repbuf, &replen, &errnop);
    free(data);
    if (ret != SSS_STATUS_SUCCESS) {
        ret = errnop_to_errno(errnop);
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

    sss_getautomntent_data_clean();

    fctx = (struct automtent *) *context;

    if (fctx != NULL) {
        free(fctx->mapname);
        free(fctx);
    }

    ret = sss_autofs_make_request(SSS_AUTOFS_ENDAUTOMNTENT,
                                  NULL, NULL, NULL, &errnop);
    if (ret != SSS_STATUS_SUCCESS) {
        ret = errnop_to_errno(errnop);
        goto out;
    }

    ret = 0;
out:
    sss_nss_unlock();
    return ret;
}
