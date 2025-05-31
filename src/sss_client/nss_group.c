/*
 * System Security Services Daemon. NSS client interface
 *
 * Copyright (C) Simo Sorce 2007
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* GROUP database NSS interface */

#include "config.h"

#include <nss.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "sss_cli.h"
#include "nss_mc.h"
#include "nss_common.h"

static
#ifdef HAVE_PTHREAD_EXT
__thread
#endif
struct sss_nss_getgrent_data {
    size_t len;
    size_t ptr;
    uint8_t *data;
} sss_nss_getgrent_data;

static void sss_nss_getgrent_data_clean(void)
{
    if (sss_nss_getgrent_data.data != NULL) {
        free(sss_nss_getgrent_data.data);
        sss_nss_getgrent_data.data = NULL;
    }
    sss_nss_getgrent_data.len = 0;
    sss_nss_getgrent_data.ptr = 0;
}

enum sss_nss_gr_type {
    GETGR_NONE,
    GETGR_NAME,
    GETGR_GID
};

static
#ifdef HAVE_PTHREAD_EXT
__thread
#endif
struct sss_nss_getgr_data {
    enum sss_nss_gr_type type;
    union {
        char *grname;
        gid_t gid;
    } id;

    uint8_t *repbuf;
    size_t replen;
} sss_nss_getgr_data;

static void sss_nss_getgr_data_clean(bool freebuf)
{
    if (sss_nss_getgr_data.type == GETGR_NAME) {
        free(sss_nss_getgr_data.id.grname);
    }
    if (freebuf) {
        free(sss_nss_getgr_data.repbuf);
    }
    memset(&sss_nss_getgr_data, 0, sizeof(struct sss_nss_getgr_data));
}

static enum nss_status sss_nss_get_getgr_cache(const char *name, gid_t gid,
                                               enum sss_nss_gr_type type,
                                               uint8_t **repbuf,
                                               size_t *replen,
                                               int *errnop)
{
    bool freebuf = true;
    enum nss_status status;
    int ret = 0;

    if (sss_nss_getgr_data.type != type) {
        status = NSS_STATUS_NOTFOUND;
        goto done;
    }

    switch (type) {
    case GETGR_NAME:
        if (name != NULL) {
            ret = strcmp(name, sss_nss_getgr_data.id.grname);
        } else {
            ret = -1;
        }
        if (ret != 0) {
            status = NSS_STATUS_NOTFOUND;
            goto done;
        }
        break;
    case GETGR_GID:
        if (sss_nss_getgr_data.id.gid != gid) {
            status = NSS_STATUS_NOTFOUND;
            goto done;
        }
        break;
    default:
        status = NSS_STATUS_TRYAGAIN;
        ret = EINVAL;
        goto done;
    }

    /* ok we have it, remove from cache and pass back to the caller */
    *repbuf = sss_nss_getgr_data.repbuf;
    *replen = sss_nss_getgr_data.replen;

    /* prevent _clean() from freeing the buffer */
    freebuf = false;
    status = NSS_STATUS_SUCCESS;

done:
    sss_nss_getgr_data_clean(freebuf);
    *errnop = ret;
    return status;
}

/* this function always takes ownership of repbuf and NULLs it before
 * returning */
static void sss_nss_save_getgr_cache(const char *name, gid_t gid,
                                     enum sss_nss_gr_type type,
                                     uint8_t **repbuf, size_t replen)
{
    int ret = 0;

    sss_nss_getgr_data.type = type;
    sss_nss_getgr_data.repbuf = *repbuf;
    sss_nss_getgr_data.replen = replen;

    switch (type) {
    case GETGR_NAME:
        if (name == NULL) {
            ret = EINVAL;
            goto done;
        }
        sss_nss_getgr_data.id.grname = strdup(name);
        if (!sss_nss_getgr_data.id.grname) {
            ret = ENOMEM;
            goto done;
        }
        break;
    case GETGR_GID:
        if (gid == 0) {
            ret = EINVAL;
            goto done;
        }
        sss_nss_getgr_data.id.gid = gid;
        break;
    default:
        ret = EINVAL;
        goto done;
    }

done:
    if (ret) {
        sss_nss_getgr_data_clean(true);
    }
    *repbuf = NULL;
}

/* GETGRNAM Request:
 *
 * 0-X: string with name
 *
 * GERTGRGID Request:
 *
 * 0-7: 32bit number with gid
 *
 * INITGROUPS Request:
 *
 * 0-3: 32bit number with gid
 * 4-7: 32bit unsigned with max num of entries
 *
 * Replies:
 *
 * 0-3: 32bit unsigned number of results
 * 4-7: 32bit unsigned (reserved/padding)
 *  For each result (64bit padded?):
 *  0-3: 32bit number gid
 *  4-7: 32bit unsigned number of members
 *  8-X: sequence of 0 terminated strings (name, passwd, mem..)
 *
 *  FIXME: do we need to pad so that each result is 32 bit aligned?
 */

int sss_nss_getgr_readrep(struct sss_nss_gr_rep *pr,
                          uint8_t *buf, size_t *len)
{
    errno_t ret;
    size_t i, l, slen, ptmem, pad, dlen, glen;
    char *sbuf;
    uint32_t mem_num;
    uint32_t c;

    if (*len < 11) { /* not enough space for data, bad packet */
        return EBADMSG;
    }

    SAFEALIGN_COPY_UINT32(&c, buf, NULL);
    pr->result->gr_gid = c;
    SAFEALIGN_COPY_UINT32(&mem_num, buf+sizeof(uint32_t), NULL);

    sbuf = (char *)&buf[8];
    slen = *len - 8;
    dlen = pr->buflen;

    pr->result->gr_name = &(pr->buffer[0]);
    i = 0;

    ret = sss_readrep_copy_string(sbuf, &i,
                                  &slen, &dlen,
                                  &pr->result->gr_name,
                                  NULL);
    if (ret != EOK) return ret;

    pr->result->gr_passwd = &(pr->buffer[i]);
    ret = sss_readrep_copy_string(sbuf, &i,
                                  &slen, &dlen,
                                  &pr->result->gr_passwd,
                                  NULL);
    if (ret != EOK) return ret;

    /* Make sure pr->buffer[i+pad] is aligned to sizeof(char *) */
    pad = PADDING_SIZE(i, char *);

    /* now members */
    pr->result->gr_mem = DISCARD_ALIGN(&(pr->buffer[i+pad]), char **);

    ptmem = (sizeof(char *) * (mem_num + 1)) + pad;
    if (ptmem > dlen) {
        return ERANGE; /* not ENOMEM, ERANGE is what glibc looks for */
    }
    dlen -= ptmem;
    ptmem += i;
    pr->result->gr_mem[mem_num] = NULL; /* terminate array */

    for (l = 0; l < mem_num; l++) {
        pr->result->gr_mem[l] = &(pr->buffer[ptmem]);
        ret = sss_readrep_copy_string(sbuf, &i,
                                      &slen, &dlen,
                                      &pr->result->gr_mem[l],
                                      &glen);
        if (ret != EOK) return ret;

        ptmem += glen + 1;
    }

    *len = slen -i;
    return 0;
}

/* INITGROUP Reply:
 *
 * 0-3: 32bit unsigned number of results
 * 4-7: 32bit unsigned (reserved/padding)
 * For each result:
 *  0-4: 32bit number with gid
 */


enum nss_status _nss_sss_initgroups_dyn(const char *user, gid_t group,
                                        long int *start, long int *size,
                                        gid_t **groups, long int limit,
                                        int *errnop)
{
    struct sss_cli_req_data rd;
    uint8_t *repbuf;
    size_t replen;
    enum nss_status nret;
    size_t buf_index = 0;
    size_t user_len;
    uint32_t num_ret;
    long int l, max_ret;
    int ret;

    ret = sss_strnlen(user, SSS_NAME_MAX, &user_len);
    if (ret != 0) {
        *errnop = EINVAL;
        return NSS_STATUS_NOTFOUND;
    }

#ifdef SSSD_NON_ROOT_USER
    /* Never resolve SSSD_USER */
    if (strcmp(user, SSSD_USER) == 0) {
        *errnop = 0;
        return NSS_STATUS_NOTFOUND;
    }
#endif /* SSSD_NON_ROOT_USER */

    ret = sss_nss_mc_initgroups_dyn(user, user_len, group, start, size,
                                    groups, limit);
    switch (ret) {
    case 0:
        *errnop = 0;
        return NSS_STATUS_SUCCESS;
    case ERANGE:
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    case ENOENT:
        /* fall through, we need to actively ask the parent
         * if no entry is found */
        break;
    default:
        /* if using the mmapped cache failed,
         * fall back to socket based comms */
        break;
    }

    rd.len = user_len + 1;
    rd.data = user;

    sss_nss_lock();

    /* previous thread might already initialize entry in mmap cache */
    ret = sss_nss_mc_initgroups_dyn(user, user_len, group, start, size,
                                    groups, limit);
    switch (ret) {
    case 0:
        *errnop = 0;
        nret = NSS_STATUS_SUCCESS;
        goto out;
    case ERANGE:
        *errnop = ERANGE;
        nret = NSS_STATUS_TRYAGAIN;
        goto out;
    case ENOENT:
        /* fall through, we need to actively ask the parent
         * if no entry is found */
        break;
    default:
        /* if using the mmapped cache failed,
         * fall back to socket based comms */
        break;
    }

    nret = sss_nss_make_request(SSS_NSS_INITGR, &rd,
                                &repbuf, &replen, errnop);
    if (nret != NSS_STATUS_SUCCESS) {
        goto out;
    }

    /* no results if not found */
    SAFEALIGN_COPY_UINT32(&num_ret, repbuf, NULL);
    if (num_ret == 0) {
        free(repbuf);
        nret = NSS_STATUS_NOTFOUND;
        goto out;
    }
    max_ret = num_ret;

    /* check we have enough space in the buffer */
    if ((*size - *start) < num_ret) {
        long int newsize;
        gid_t *newgroups;

        newsize = *size + num_ret;
        if ((limit > 0) && (newsize > limit)) {
            newsize = limit;
            max_ret = newsize - *start;
        }

        newgroups = (gid_t *)realloc((*groups), newsize * sizeof(**groups));
        if (!newgroups) {
            *errnop = ENOMEM;
            free(repbuf);
            nret = NSS_STATUS_TRYAGAIN;
            goto out;
        }
        *groups = newgroups;
        *size = newsize;
    }

    /* Skip first two 32 bit values (number of results and
     * reserved padding) */
    buf_index = 2 * sizeof(uint32_t);

    for (l = 0; l < max_ret; l++) {
        SAFEALIGN_COPY_UINT32(&(*groups)[*start], repbuf + buf_index,
                                 &buf_index);
        *start += 1;
    }

    free(repbuf);
    nret = NSS_STATUS_SUCCESS;

out:
    sss_nss_unlock();
    return nret;
}


enum nss_status _nss_sss_getgrnam_r(const char *name, struct group *result,
                                    char *buffer, size_t buflen, int *errnop)
{
    struct sss_cli_req_data rd;
    struct sss_nss_gr_rep grrep;
    uint8_t *repbuf;
    size_t replen, len, name_len;
    uint32_t num_results;
    enum nss_status nret;
    int ret;

    /* Caught once glibc passing in buffer == 0x0 */
    if (!buffer || !buflen) {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    ret = sss_strnlen(name, SSS_NAME_MAX, &name_len);
    if (ret != 0) {
        *errnop = EINVAL;
        return NSS_STATUS_NOTFOUND;
    }

    if (name_len == 0) {
        *errnop = EINVAL;
        return NSS_STATUS_NOTFOUND;
    }

#ifdef SSSD_NON_ROOT_USER
    /* Never resolve SSSD_USER */
    if (strcmp(name, SSSD_USER) == 0) {
        *errnop = 0;
        return NSS_STATUS_NOTFOUND;
    }
#endif /* SSSD_NON_ROOT_USER */

    ret = sss_nss_mc_getgrnam(name, name_len, result, buffer, buflen);
    switch (ret) {
    case 0:
        *errnop = 0;
        return NSS_STATUS_SUCCESS;
    case ERANGE:
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    case ENOENT:
        /* fall through, we need to actively ask the parent
         * if no entry is found */
        break;
    default:
        /* if using the mmapped cache failed,
         * fall back to socket based comms */
        break;
    }

    rd.len = name_len + 1;
    rd.data = name;

    sss_nss_lock();

    /* previous thread might already initialize entry in mmap cache */
    ret = sss_nss_mc_getgrnam(name, name_len, result, buffer, buflen);
    switch (ret) {
    case 0:
        *errnop = 0;
        nret = NSS_STATUS_SUCCESS;
        goto out;
    case ERANGE:
        *errnop = ERANGE;
        nret = NSS_STATUS_TRYAGAIN;
        goto out;
    case ENOENT:
        /* fall through, we need to actively ask the parent
         * if no entry is found */
        break;
    default:
        /* if using the mmapped cache failed,
         * fall back to socket based comms */
        break;
    }

    nret = sss_nss_get_getgr_cache(name, 0, GETGR_NAME,
                                   &repbuf, &replen, errnop);
    if (nret == NSS_STATUS_NOTFOUND) {
        nret = sss_nss_make_request(SSS_NSS_GETGRNAM, &rd,
                                    &repbuf, &replen, errnop);
    }
    if (nret != NSS_STATUS_SUCCESS) {
        goto out;
    }

    grrep.result = result;
    grrep.buffer = buffer;
    grrep.buflen = buflen;

    /* Get number of results from repbuf. */
    SAFEALIGN_COPY_UINT32(&num_results, repbuf, NULL);

    /* no results if not found */
    if (num_results == 0) {
        free(repbuf);
        nret = NSS_STATUS_NOTFOUND;
        goto out;
    }

    /* only 1 result is accepted for this function */
    if (num_results != 1) {
        *errnop = EBADMSG;
        free(repbuf);
        nret = NSS_STATUS_TRYAGAIN;
        goto out;
    }

    len = replen - 8;
    ret = sss_nss_getgr_readrep(&grrep, repbuf+8, &len);
    if (ret == ERANGE) {
        sss_nss_save_getgr_cache(name, 0, GETGR_NAME, &repbuf, replen);
    } else {
        free(repbuf);
    }
    if (ret) {
        *errnop = ret;
        nret = NSS_STATUS_TRYAGAIN;
        goto out;
    }

    nret = NSS_STATUS_SUCCESS;

out:
    sss_nss_unlock();
    return nret;
}

enum nss_status _nss_sss_getgrgid_r(gid_t gid, struct group *result,
                                    char *buffer, size_t buflen, int *errnop)
{
    struct sss_cli_req_data rd;
    struct sss_nss_gr_rep grrep;
    uint8_t *repbuf;
    size_t replen, len;
    uint32_t num_results;
    enum nss_status nret;
    uint32_t group_gid;
    int ret;

    /* Caught once glibc passing in buffer == 0x0 */
    if (!buffer || !buflen) {
	*errnop = ERANGE;
	return NSS_STATUS_TRYAGAIN;
    }

    ret = sss_nss_mc_getgrgid(gid, result, buffer, buflen);
    switch (ret) {
    case 0:
        *errnop = 0;
        return NSS_STATUS_SUCCESS;
    case ERANGE:
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    case ENOENT:
        /* fall through, we need to actively ask the parent
         * if no entry is found */
        break;
    default:
        /* if using the mmapped cache failed,
         * fall back to socket based comms */
        break;
    }

    group_gid = gid;
    rd.len = sizeof(uint32_t);
    rd.data = &group_gid;

    sss_nss_lock();

    /* previous thread might already initialize entry in mmap cache */
    ret = sss_nss_mc_getgrgid(gid, result, buffer, buflen);
    switch (ret) {
    case 0:
        *errnop = 0;
        nret = NSS_STATUS_SUCCESS;
        goto out;
    case ERANGE:
        *errnop = ERANGE;
        nret = NSS_STATUS_TRYAGAIN;
        goto out;
    case ENOENT:
        /* fall through, we need to actively ask the parent
         * if no entry is found */
        break;
    default:
        /* if using the mmapped cache failed,
         * fall back to socket based comms */
        break;
    }

    nret = sss_nss_get_getgr_cache(NULL, gid, GETGR_GID,
                                   &repbuf, &replen, errnop);
    if (nret == NSS_STATUS_NOTFOUND) {
        nret = sss_nss_make_request(SSS_NSS_GETGRGID, &rd,
                                    &repbuf, &replen, errnop);
    }
    if (nret != NSS_STATUS_SUCCESS) {
        goto out;
    }

    grrep.result = result;
    grrep.buffer = buffer;
    grrep.buflen = buflen;

    /* Get number of results from repbuf. */
    SAFEALIGN_COPY_UINT32(&num_results, repbuf, NULL);

    /* no results if not found */
    if (num_results == 0) {
        free(repbuf);
        nret = NSS_STATUS_NOTFOUND;
        goto out;
    }

    /* only 1 result is accepted for this function */
    if (num_results != 1) {
        *errnop = EBADMSG;
        free(repbuf);
        nret = NSS_STATUS_TRYAGAIN;
        goto out;
    }

    len = replen - 8;
    ret = sss_nss_getgr_readrep(&grrep, repbuf+8, &len);
    if (ret == ERANGE) {
        sss_nss_save_getgr_cache(NULL, gid, GETGR_GID, &repbuf, replen);
    } else {
        free(repbuf);
    }
    if (ret) {
        *errnop = ret;
        nret = NSS_STATUS_TRYAGAIN;
        goto out;
    }

    nret = NSS_STATUS_SUCCESS;

out:
    sss_nss_unlock();
    return nret;
}

enum nss_status _nss_sss_setgrent(void)
{
    enum nss_status nret;
    int errnop;

    sss_nss_lock();

    /* make sure we do not have leftovers, and release memory */
    sss_nss_getgrent_data_clean();

    nret = sss_nss_make_request(SSS_NSS_SETGRENT,
                                NULL, NULL, NULL, &errnop);
    if (nret != NSS_STATUS_SUCCESS) {
        errno = errnop;
    }

    sss_nss_unlock();
    return nret;
}

static enum nss_status internal_getgrent_r(struct group *result,
                                           char *buffer, size_t buflen,
                                           int *errnop)
{
    struct sss_cli_req_data rd;
    struct sss_nss_gr_rep grrep;
    uint8_t *repbuf;
    size_t replen;
    uint32_t num_results;
    enum nss_status nret;
    uint32_t num_entries;
    int ret;

    /* Caught once glibc passing in buffer == 0x0 */
    if (!buffer || !buflen) {
	*errnop = ERANGE;
	return NSS_STATUS_TRYAGAIN;
    }

    /* if there are leftovers return the next one */
    if (sss_nss_getgrent_data.data != NULL &&
        sss_nss_getgrent_data.ptr < sss_nss_getgrent_data.len) {

        repbuf = (uint8_t *)sss_nss_getgrent_data.data +
                    sss_nss_getgrent_data.ptr;
        replen = sss_nss_getgrent_data.len -
                    sss_nss_getgrent_data.ptr;

        grrep.result = result;
        grrep.buffer = buffer;
        grrep.buflen = buflen;

        ret = sss_nss_getgr_readrep(&grrep, repbuf, &replen);
        if (ret) {
            *errnop = ret;
            return NSS_STATUS_TRYAGAIN;
        }

        /* advance buffer pointer */
        sss_nss_getgrent_data.ptr = sss_nss_getgrent_data.len - replen;

        return NSS_STATUS_SUCCESS;
    }

    /* release memory if any */
    sss_nss_getgrent_data_clean();

    /* retrieve no more than SSS_NSS_MAX_ENTRIES at a time */
    num_entries = SSS_NSS_MAX_ENTRIES;
    rd.len = sizeof(uint32_t);
    rd.data = &num_entries;

    nret = sss_nss_make_request(SSS_NSS_GETGRENT, &rd,
                                &repbuf, &replen, errnop);
    if (nret != NSS_STATUS_SUCCESS) {
        return nret;
    }

    /* Get number of results from repbuf. */
    SAFEALIGN_COPY_UINT32(&num_results, repbuf, NULL);

    /* no results if not found */
    if ((num_results == 0) || (replen - 8 == 0)) {
        free(repbuf);
        return NSS_STATUS_NOTFOUND;
    }

    sss_nss_getgrent_data.data = repbuf;
    sss_nss_getgrent_data.len = replen;
    sss_nss_getgrent_data.ptr = 8; /* skip metadata fields */

    /* call again ourselves, this will return the first result */
    return internal_getgrent_r(result, buffer, buflen, errnop);
}

enum nss_status _nss_sss_getgrent_r(struct group *result,
                                    char *buffer, size_t buflen, int *errnop)
{
    enum nss_status nret;

    sss_nss_lock();
    nret = internal_getgrent_r(result, buffer, buflen, errnop);
    sss_nss_unlock();

    return nret;
}

enum nss_status _nss_sss_endgrent(void)
{
    enum nss_status nret;
    int errnop;
    int saved_errno = errno;

    sss_nss_lock();

    /* make sure we do not have leftovers, and release memory */
    sss_nss_getgrent_data_clean();

    nret = sss_nss_make_request(SSS_NSS_ENDGRENT,
                                NULL, NULL, NULL, &errnop);
    if (nret != NSS_STATUS_SUCCESS) {
        errno = errnop;
    } else {
        errno = saved_errno;
    }

    sss_nss_unlock();
    return nret;
}
