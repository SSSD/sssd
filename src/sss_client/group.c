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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* GROUP database NSS interface */

#include <nss.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "sss_cli.h"

static struct sss_nss_getgrent_data {
    size_t len;
    size_t ptr;
    uint8_t *data;
} sss_nss_getgrent_data;

static void sss_nss_getgrent_data_clean(void) {

    if (sss_nss_getgrent_data.data != NULL) {
        free(sss_nss_getgrent_data.data);
        sss_nss_getgrent_data.data = NULL;
    }
    sss_nss_getgrent_data.len = 0;
    sss_nss_getgrent_data.ptr = 0;
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
 *  For each result (64bit padded ?):
 *  0-3: 32bit number gid
 *  4-7: 32bit unsigned number of members
 *  8-X: sequence of 0 terminated strings (name, passwd, mem..)
 *
 *  FIXME: do we need to pad so that each result is 32 bit aligned ?
 */
struct sss_nss_gr_rep {
    struct group *result;
    char *buffer;
    size_t buflen;
};

static int sss_nss_getgr_readrep(struct sss_nss_gr_rep *pr,
                                 uint8_t *buf, size_t *len)
{
    size_t i, l, slen, ptmem, pad;
    ssize_t dlen;
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
    while (slen > i && dlen > 0) {
        pr->buffer[i] = sbuf[i];
        if (pr->buffer[i] == '\0') break;
        i++;
        dlen--;
    }
    if (slen <= i) { /* premature end of buf */
        return EBADMSG;
    }
    if (dlen <= 0) { /* not enough memory */
        return ERANGE; /* not ENOMEM, ERANGE is what glibc looks for */
    }
    i++;
    dlen--;

    pr->result->gr_passwd = &(pr->buffer[i]);
    while (slen > i && dlen > 0) {
        pr->buffer[i] = sbuf[i];
        if (pr->buffer[i] == '\0') break;
        i++;
        dlen--;
    }
    if (slen <= i) { /* premature end of buf */
        return EBADMSG;
    }
    if (dlen <= 0) { /* not enough memory */
        return ERANGE; /* not ENOMEM, ERANGE is what glibc looks for */
    }
    i++;
    dlen--;

    /* Make sure pr->buffer[i+pad] is 32 bit aligned */
    pad = 0;
    while((i + pad) % 4) {
        pad++;
    }

    /* now members */
    pr->result->gr_mem = (char **)&(pr->buffer[i+pad]);
    ptmem = (sizeof(char *) * (mem_num + 1)) + pad;
    if (ptmem > dlen) {
        return ERANGE; /* not ENOMEM, ERANGE is what glibc looks for */
    }
    dlen -= ptmem;
    ptmem += i;
    pr->result->gr_mem[mem_num] = NULL; /* terminate array */

    for (l = 0; l < mem_num; l++) {
        pr->result->gr_mem[l] = &(pr->buffer[ptmem]);
        while ((slen > i) && (dlen > 0)) {
            pr->buffer[ptmem] = sbuf[i];
            if (pr->buffer[ptmem] == '\0') break;
            i++;
            dlen--;
            ptmem++;
        }
        if (slen <= i) { /* premature end of buf */
            return EBADMSG;
        }
        if (dlen <= 0) { /* not enough memory */
            return ERANGE; /* not ENOMEM, ERANGE is what glibc looks for */
        }
        i++;
        dlen--;
        ptmem++;
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
    uint32_t *rbuf;
    uint32_t num_ret;
    long int l, max_ret;

    rd.len = strlen(user) +1;
    rd.data = user;

    nret = sss_nss_make_request(SSS_NSS_INITGR, &rd,
                                &repbuf, &replen, errnop);
    if (nret != NSS_STATUS_SUCCESS) {
        return nret;
    }

    /* no results if not found */
    num_ret = ((uint32_t *)repbuf)[0];
    if (num_ret == 0) {
        free(repbuf);
        return NSS_STATUS_NOTFOUND;
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
            return NSS_STATUS_TRYAGAIN;
        }
        *groups = newgroups;
        *size = newsize;
    }

    rbuf = &((uint32_t *)repbuf)[2];
    for (l = 0; l < max_ret; l++) {
        (*groups)[*start] = rbuf[l];
        *start += 1;
    }

    return NSS_STATUS_SUCCESS;
}


enum nss_status _nss_sss_getgrnam_r(const char *name, struct group *result,
                                    char *buffer, size_t buflen, int *errnop)
{
    struct sss_cli_req_data rd;
    struct sss_nss_gr_rep grrep;
    uint8_t *repbuf;
    size_t replen, len;
    enum nss_status nret;
    int ret;

    /* Caught once glibc passing in buffer == 0x0 */
    if (!buffer || !buflen) return ERANGE;

    rd.len = strlen(name) + 1;
    rd.data = name;

    nret = sss_nss_make_request(SSS_NSS_GETGRNAM, &rd,
                                &repbuf, &replen, errnop);
    if (nret != NSS_STATUS_SUCCESS) {
        return nret;
    }

    grrep.result = result;
    grrep.buffer = buffer;
    grrep.buflen = buflen;

    /* no results if not found */
    if (((uint32_t *)repbuf)[0] == 0) {
        free(repbuf);
        return NSS_STATUS_NOTFOUND;
    }

    /* only 1 result is accepted for this function */
    if (((uint32_t *)repbuf)[0] != 1) {
        *errnop = EBADMSG;
        return NSS_STATUS_TRYAGAIN;
    }

    len = replen - 8;
    ret = sss_nss_getgr_readrep(&grrep, repbuf+8, &len);
    free(repbuf);
    if (ret) {
        *errnop = ret;
        return NSS_STATUS_TRYAGAIN;
    }

    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_sss_getgrgid_r(gid_t gid, struct group *result,
                                    char *buffer, size_t buflen, int *errnop)
{
    struct sss_cli_req_data rd;
    struct sss_nss_gr_rep grrep;
    uint8_t *repbuf;
    size_t replen, len;
    enum nss_status nret;
    uint32_t group_gid;
    int ret;

    /* Caught once glibc passing in buffer == 0x0 */
    if (!buffer || !buflen) return ERANGE;

    group_gid = gid;
    rd.len = sizeof(uint32_t);
    rd.data = &group_gid;

    nret = sss_nss_make_request(SSS_NSS_GETGRGID, &rd,
                                &repbuf, &replen, errnop);
    if (nret != NSS_STATUS_SUCCESS) {
        return nret;
    }

    grrep.result = result;
    grrep.buffer = buffer;
    grrep.buflen = buflen;

    /* no results if not found */
    if (((uint32_t *)repbuf)[0] == 0) {
        free(repbuf);
        return NSS_STATUS_NOTFOUND;
    }

    /* only 1 result is accepted for this function */
    if (((uint32_t *)repbuf)[0] != 1) {
        *errnop = EBADMSG;
        return NSS_STATUS_TRYAGAIN;
    }

    len = replen - 8;
    ret = sss_nss_getgr_readrep(&grrep, repbuf+8, &len);
    free(repbuf);
    if (ret) {
        *errnop = ret;
        return NSS_STATUS_TRYAGAIN;
    }

    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_sss_setgrent(void)
{
    enum nss_status nret;
    int errnop;

    /* make sure we do not have leftovers, and release memory */
    sss_nss_getgrent_data_clean();

    nret = sss_nss_make_request(SSS_NSS_SETGRENT,
                                NULL, NULL, NULL, &errnop);
    if (nret != NSS_STATUS_SUCCESS) {
        errno = errnop;
        return nret;
    }

    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_sss_getgrent_r(struct group *result,
                                    char *buffer, size_t buflen, int *errnop)
{
    struct sss_cli_req_data rd;
    struct sss_nss_gr_rep grrep;
    uint8_t *repbuf;
    size_t replen;
    enum nss_status nret;
    uint32_t num_entries;
    int ret;

    /* Caught once glibc passing in buffer == 0x0 */
    if (!buffer || !buflen) return ERANGE;

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

    /* no results if not found */
    if ((((uint32_t *)repbuf)[0] == 0) || (replen - 8 == 0)) {
        free(repbuf);
        return NSS_STATUS_NOTFOUND;
    }

    sss_nss_getgrent_data.data = repbuf;
    sss_nss_getgrent_data.len = replen;
    sss_nss_getgrent_data.ptr = 8; /* skip metadata fields */

    /* call again ourselves, this will return the first result */
    return _nss_sss_getgrent_r(result, buffer, buflen, errnop);
}

enum nss_status _nss_sss_endgrent(void)
{
    enum nss_status nret;
    int errnop;

    /* make sure we do not have leftovers, and release memory */
    sss_nss_getgrent_data_clean();

    nret = sss_nss_make_request(SSS_NSS_ENDGRENT,
                                NULL, NULL, NULL, &errnop);
    if (nret != NSS_STATUS_SUCCESS) {
        errno = errnop;
        return nret;
    }

    return NSS_STATUS_SUCCESS;
}
