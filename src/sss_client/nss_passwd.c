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

/* PASSWD database NSS interface */

#include "config.h"

#include <nss.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "sss_cli.h"
#include "nss_mc.h"
#include "nss_common.h"

static
#ifdef HAVE_PTHREAD_EXT
__thread
#endif
struct sss_nss_getpwent_data {
    size_t len;
    size_t ptr;
    uint8_t *data;
} sss_nss_getpwent_data;

static void sss_nss_getpwent_data_clean(void) {

    if (sss_nss_getpwent_data.data != NULL) {
        free(sss_nss_getpwent_data.data);
        sss_nss_getpwent_data.data = NULL;
    }
    sss_nss_getpwent_data.len = 0;
    sss_nss_getpwent_data.ptr = 0;
}

/* GETPWNAM Request:
 *
 * 0-X: string with name
 *
 * GERTPWUID Request:
 *
 * 0-3: 32bit number with uid
 *
 * Replies:
 *
 * 0-3: 32bit unsigned number of results
 * 4-7: 32bit unsigned (reserved/padding)
 * For each result:
 *  0-3: 32bit number uid
 *  4-7: 32bit number gid
 *  8-X: sequence of 5, 0 terminated, strings (name, passwd, gecos, dir, shell)
 */

int sss_nss_getpw_readrep(struct sss_nss_pw_rep *pr,
                          uint8_t *buf, size_t *len)
{
    errno_t ret;
    size_t i, slen, dlen;
    char *sbuf;
    uint32_t c;

    if (*len < 13) { /* not enough space for data, bad packet */
        return EBADMSG;
    }

    SAFEALIGN_COPY_UINT32(&c, buf, NULL);
    pr->result->pw_uid = c;
    SAFEALIGN_COPY_UINT32(&c, buf+sizeof(uint32_t), NULL);
    pr->result->pw_gid = c;

    sbuf = (char *)&buf[8];
    slen = *len - 8;
    dlen = pr->buflen;

    i = 0;
    pr->result->pw_name = &(pr->buffer[i]);

    ret = sss_readrep_copy_string(sbuf, &i,
                                  &slen, &dlen,
                                  &pr->result->pw_name,
                                  NULL);
    if (ret != EOK) return ret;

    pr->result->pw_passwd = &(pr->buffer[i]);
    ret = sss_readrep_copy_string(sbuf, &i,
                                  &slen, &dlen,
                                  &pr->result->pw_passwd,
                                  NULL);
    if (ret != EOK) return ret;

    pr->result->pw_gecos = &(pr->buffer[i]);
    ret = sss_readrep_copy_string(sbuf, &i,
                                  &slen, &dlen,
                                  &pr->result->pw_gecos,
                                  NULL);
    if (ret != EOK) return ret;


    pr->result->pw_dir = &(pr->buffer[i]);
    ret = sss_readrep_copy_string(sbuf, &i,
                                  &slen, &dlen,
                                  &pr->result->pw_dir,
                                  NULL);
    if (ret != EOK) return ret;

    pr->result->pw_shell = &(pr->buffer[i]);
    ret = sss_readrep_copy_string(sbuf, &i,
                                  &slen, &dlen,
                                  &pr->result->pw_shell,
                                  NULL);
    if (ret != EOK) return ret;
    *len = slen - i;

    return 0;
}

enum nss_status _nss_sss_getpwnam_r(const char *name, struct passwd *result,
                                    char *buffer, size_t buflen, int *errnop)
{
    struct sss_cli_req_data rd;
    struct sss_nss_pw_rep pwrep;
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

#ifdef SSSD_NON_ROOT_USER
    /* Never resolve SSSD_USER */
    if (strcmp(name, SSSD_USER) == 0) {
        *errnop = 0;
        return NSS_STATUS_NOTFOUND;
    }
#endif /* SSSD_NON_ROOT_USER */

    ret = sss_nss_mc_getpwnam(name, name_len, result, buffer, buflen);
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
    ret = sss_nss_mc_getpwnam(name, name_len, result, buffer, buflen);
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

    nret = sss_nss_make_request(SSS_NSS_GETPWNAM, &rd,
                                &repbuf, &replen, errnop);
    if (nret != NSS_STATUS_SUCCESS) {
        goto out;
    }

    pwrep.result = result;
    pwrep.buffer = buffer;
    pwrep.buflen = buflen;

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
    ret = sss_nss_getpw_readrep(&pwrep, repbuf+8, &len);
    free(repbuf);
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

enum nss_status _nss_sss_getpwuid_r(uid_t uid, struct passwd *result,
                                    char *buffer, size_t buflen, int *errnop)
{
    struct sss_cli_req_data rd;
    struct sss_nss_pw_rep pwrep;
    uint8_t *repbuf;
    size_t replen, len;
    uint32_t num_results;
    enum nss_status nret;
    uint32_t user_uid;
    int ret;

    /* Caught once glibc passing in buffer == 0x0 */
    if (!buffer || !buflen) {
	*errnop = ERANGE;
	return NSS_STATUS_TRYAGAIN;
    }

    ret = sss_nss_mc_getpwuid(uid, result, buffer, buflen);
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

    user_uid = uid;
    rd.len = sizeof(uint32_t);
    rd.data = &user_uid;

    sss_nss_lock();

    /* previous thread might already initialize entry in mmap cache */
    ret = sss_nss_mc_getpwuid(uid, result, buffer, buflen);
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

    nret = sss_nss_make_request(SSS_NSS_GETPWUID, &rd,
                                &repbuf, &replen, errnop);
    if (nret != NSS_STATUS_SUCCESS) {
        goto out;
    }

    pwrep.result = result;
    pwrep.buffer = buffer;
    pwrep.buflen = buflen;

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
    ret = sss_nss_getpw_readrep(&pwrep, repbuf+8, &len);
    free(repbuf);
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

enum nss_status _nss_sss_setpwent(void)
{
    enum nss_status nret;
    int errnop;

    sss_nss_lock();

    /* make sure we do not have leftovers, and release memory */
    sss_nss_getpwent_data_clean();

    nret = sss_nss_make_request(SSS_NSS_SETPWENT,
                                NULL, NULL, NULL, &errnop);
    if (nret != NSS_STATUS_SUCCESS) {
        errno = errnop;
    }

    sss_nss_unlock();
    return nret;
}

static enum nss_status internal_getpwent_r(struct passwd *result,
                                           char *buffer, size_t buflen,
                                           int *errnop)
{
    struct sss_cli_req_data rd;
    struct sss_nss_pw_rep pwrep;
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
    if (sss_nss_getpwent_data.data != NULL &&
        sss_nss_getpwent_data.ptr < sss_nss_getpwent_data.len) {

        repbuf = sss_nss_getpwent_data.data + sss_nss_getpwent_data.ptr;
        replen = sss_nss_getpwent_data.len - sss_nss_getpwent_data.ptr;

        pwrep.result = result;
        pwrep.buffer = buffer;
        pwrep.buflen = buflen;

        ret = sss_nss_getpw_readrep(&pwrep, repbuf, &replen);
        if (ret) {
            *errnop = ret;
            return NSS_STATUS_TRYAGAIN;
        }

        /* advance buffer pointer */
        sss_nss_getpwent_data.ptr = sss_nss_getpwent_data.len - replen;

        return NSS_STATUS_SUCCESS;
    }

    /* release memory if any */
    sss_nss_getpwent_data_clean();

    /* retrieve no more than SSS_NSS_MAX_ENTRIES at a time */
    num_entries = SSS_NSS_MAX_ENTRIES;
    rd.len = sizeof(uint32_t);
    rd.data = &num_entries;

    nret = sss_nss_make_request(SSS_NSS_GETPWENT, &rd,
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

    sss_nss_getpwent_data.data = repbuf;
    sss_nss_getpwent_data.len = replen;
    sss_nss_getpwent_data.ptr = 8; /* skip metadata fields */

    /* call again ourselves, this will return the first result */
    return internal_getpwent_r(result, buffer, buflen, errnop);
}

enum nss_status _nss_sss_getpwent_r(struct passwd *result,
                                    char *buffer, size_t buflen,
                                    int *errnop)
{
    enum nss_status nret;

    sss_nss_lock();
    nret = internal_getpwent_r(result, buffer, buflen, errnop);
    sss_nss_unlock();

    return nret;
}

enum nss_status _nss_sss_endpwent(void)
{
    enum nss_status nret;
    int errnop;
    int saved_errno = errno;

    sss_nss_lock();

    /* make sure we do not have leftovers, and release memory */
    sss_nss_getpwent_data_clean();

    nret = sss_nss_make_request(SSS_NSS_ENDPWENT,
                                NULL, NULL, NULL, &errnop);
    if (nret != NSS_STATUS_SUCCESS) {
        errno = errnop;
    } else {
        errno = saved_errno;
    }

    sss_nss_unlock();
    return nret;
}
