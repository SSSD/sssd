/*
    SSSD

    Authors:
        Samuel Cabrero <scabrero@suse.com>

    Copyright (C) 2019 SUSE LINUX GmbH, Nuernberg, Germany.

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

#include <nss.h>
#include <netdb.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "sss_cli.h"

static
#ifdef HAVE_PTHREAD_EXT
__thread
#endif
struct sss_nss_gethostent_data {
    size_t len;
    size_t ptr;
    uint8_t *data;
} sss_nss_gethostent_data;

static void
sss_nss_gethostent_data_clean(void)
{
    if (sss_nss_gethostent_data.data != NULL) {
        free(sss_nss_gethostent_data.data);
        sss_nss_gethostent_data.data = NULL;
    }
    sss_nss_gethostent_data.len = 0;
    sss_nss_gethostent_data.ptr = 0;
}

/* GETHOSTBYNAME2 Request
 *
 * 0-X: One zero-terminated string (name)
 *
 * GETHOSTBYADDR Request:
 * 0-3: 32-bit unsigned address family
 * 4-7: 32-bit unsigned address length
 * 8-X: binary address
 *
 * Replies:
 * 0-3: 32-bit unsigned number of results
 * 4-7: 32-bit unsigned (reserved/padding)
 * 7-X: Result data (blocks equal to number of results)
 *
 * Result data:
 * 0-3: 32-bit unsigned number of aliases
 * 4-7: 32-bit unsigned number of addresses
 * 8-X: sequence of zero-terminated strings
 *      (name, zero or more aliases, zero or more addresses)
 */

struct sss_nss_host_rep {
    struct hostent *result;
    char *buffer;
    size_t buflen;
};

#define HOST_METADATA_COUNT 8

static errno_t
sss_nss_gethost_readrep(struct sss_nss_host_rep *sr,
                        uint8_t *buf, size_t *len, int af)
{
    errno_t ret;
    uint32_t num_aliases;
    uint32_t num_addresses;
    const char *sbuf;
    size_t i, a, l, slen, dlen, pad, ptmem, alen;

    if (af != AF_INET && af != AF_INET6) {
        return EBADMSG;
    }

    /* Buffer must contain two 32-bit integers,
     * at least one character and null-terminator
     * for the name, at least a null-terminator for
     * the aliases and a null-terminator for the
     * addresses.
     */
    if (*len < 12) {
        /* not enough data, bad packet */
        return EBADMSG;
    }

    /* Get the number of aliases */
    SAFEALIGN_COPY_UINT32(&num_aliases, buf, NULL);

    /* Get the number of addresses */
    SAFEALIGN_COPY_UINT32(&num_addresses, buf + sizeof(uint32_t), NULL);

    sbuf = (char *)&buf[2 * sizeof(uint32_t)];
    slen = *len - (2 * sizeof(uint32_t));
    dlen = sr->buflen;

    i = 0;
    sr->result->h_name = &(sr->buffer[i]);
    ret = sss_readrep_copy_string(sbuf, &i,
                                  &slen, &dlen,
                                  &sr->result->h_name,
                                  NULL);
    if (ret != EOK) {
        return ret;
    }

    /* Copy the aliases */
    pad = PADDING_SIZE(i, char *);
    sr->result->h_aliases = DISCARD_ALIGN(&(sr->buffer[i+pad]), char **);

    ptmem = (sizeof(char *) * (num_aliases + 1)) + pad;
    if (ptmem > dlen) {
        /* Not ENOMEM, ERANGE is what glibc looks for */
        return ERANGE;
    }

    dlen -= ptmem;
    ptmem += i;

    /* Terminate array */
    sr->result->h_aliases[num_aliases] = NULL;

    for (l = 0; l < num_aliases; l++) {
        sr->result->h_aliases[l] = &(sr->buffer[ptmem]);
        ret = sss_readrep_copy_string(sbuf, &i,
                                      &slen, &dlen,
                                      &sr->result->h_aliases[l],
                                      &alen);
        if (ret != EOK) {
            return ret;
        }

        ptmem += alen + 1;
    }

    /* Copy the addresses */
    pad = PADDING_SIZE(ptmem, char *);
    sr->result->h_addr_list =
        DISCARD_ALIGN(&(sr->buffer[ptmem + pad]), char **);

    ptmem += (sizeof(char *) * (num_addresses + 1)) + pad;
    if (ptmem > dlen) {
        /* Not ENOMEM, ERANGE is what glibc looks for */
        return ERANGE;
    }

    dlen -= (sizeof(char *) * (num_addresses + 1)) + pad;

    /* Initialize array, can return less address than num_addresses depending
     * on requested address family */
    for (a = 0; a < num_addresses + 1; a++) {
        sr->result->h_addr_list[a] = NULL;
    }

    for (a = 0, l = 0; l < num_addresses; l++) {
        /* Can be optimized, but ensure we can fit an IPv6 for now */
        if (dlen < IN6ADDRSZ) {
            return ERANGE;
        }

        sr->result->h_addr_list[a] = &(sr->buffer[ptmem]);

        if (af == AF_INET &&
            inet_pton(AF_INET, &sbuf[i], &(sr->buffer[ptmem]))) {
            sr->result->h_addrtype = AF_INET;
            sr->result->h_length = INADDRSZ;
            dlen -= INADDRSZ;
            ptmem += INADDRSZ;
            a++;
        } else if (af == AF_INET6 &&
                   inet_pton(AF_INET6, &sbuf[i], &(sr->buffer[ptmem]))) {
            sr->result->h_addrtype = AF_INET6;
            sr->result->h_length = IN6ADDRSZ;
            dlen -= IN6ADDRSZ;
            ptmem += IN6ADDRSZ;
            a++;
        } else {
            /* Skip illegal address */
            sr->result->h_addr_list[a] = NULL;
        }

        i += strlen(&sbuf[i]) + 1;
    }

    *len = slen - i;

    return EOK;
}

static enum nss_status
internal_gethostbyname2_r(const char *name, int af,
                          struct hostent *result,
                          char *buffer, size_t buflen,
                          int *errnop, int *h_errnop)
{
    struct sss_cli_req_data rd;
    struct sss_nss_host_rep hostrep;
    size_t name_len;
    uint8_t *repbuf;
    size_t replen, len;
    uint32_t num_results;
    enum nss_status nret;
    int ret;

    if (af != AF_INET && af != AF_INET6) {
        *errnop = EAFNOSUPPORT;
        *h_errnop = NETDB_INTERNAL;
        return NSS_STATUS_UNAVAIL;
    }

    /* Caught once glibc passing in buffer == 0x0 */
    if (buffer == NULL || buflen == 0) {
        *errnop = ERANGE;
        *h_errnop = NETDB_INTERNAL;
        return NSS_STATUS_TRYAGAIN;
    }

    ret = sss_strnlen(name, SSS_NAME_MAX, &name_len);
    if (ret != 0) {
        *errnop = EINVAL;
        *h_errnop = NETDB_INTERNAL;
        return NSS_STATUS_UNAVAIL;
    }

    rd.len = name_len + 1;
    rd.data = name;

    sss_nss_lock();

    nret = sss_nss_make_request(SSS_NSS_GETHOSTBYNAME2, &rd,
                                &repbuf, &replen, errnop);
    if (nret != NSS_STATUS_SUCCESS) {
        *h_errnop = NO_RECOVERY;
        goto out;
    }

    hostrep.result = result;
    hostrep.buffer = buffer;
    hostrep.buflen = buflen;

    /* Get number of results from repbuf. */
    SAFEALIGN_COPY_UINT32(&num_results, repbuf, NULL);

    /* No results if not found */
    if (num_results == 0) {
        free(repbuf);
        nret = NSS_STATUS_NOTFOUND;
        *h_errnop = HOST_NOT_FOUND;
        goto out;
    }

    /* Only 1 result is accepted for this function */
    if (num_results != 1) {
        free(repbuf);
        *errnop = EBADMSG;
        *h_errnop = NETDB_INTERNAL;
        nret = NSS_STATUS_TRYAGAIN;
        goto out;
    }

    len = replen - HOST_METADATA_COUNT;
    ret = sss_nss_gethost_readrep(&hostrep, repbuf + HOST_METADATA_COUNT,
                                  &len, af);
    free(repbuf);
    if (ret) {
        *errnop = ret;
        nret = NSS_STATUS_TRYAGAIN;
        *h_errnop = NETDB_INTERNAL;
        goto out;
    }

    /* If host name is valid but does not have an IP address of the requested
     * address family return the correct error.  */
    if (result->h_addr_list[0] == NULL) {
        *h_errnop = NO_DATA;
        nret = NSS_STATUS_TRYAGAIN;
        goto out;
    }

    nret = NSS_STATUS_SUCCESS;

out:
    sss_nss_unlock();

    return nret;
}

enum nss_status
_nss_sss_gethostbyname2_r(const char *name, int af,
                          struct hostent *result,
                          char *buffer, size_t buflen,
                          int *errnop, int *h_errnop)
{
    return internal_gethostbyname2_r(name, af, result, buffer, buflen,
                                     errnop, h_errnop);
}

enum nss_status
_nss_sss_gethostbyname_r(const char *name,
                         struct hostent *result,
                         char *buffer, size_t buflen,
                         int *errnop, int *h_errnop)
{
    return internal_gethostbyname2_r(name, AF_INET, result, buffer, buflen,
                                     errnop, h_errnop);
}

enum nss_status
_nss_sss_gethostbyaddr_r(const void *addr, socklen_t addrlen,
                         int af, struct hostent *result,
                         char *buffer, size_t buflen,
                         int *errnop, int *h_errnop)
{
    struct sss_cli_req_data rd;
    struct sss_nss_host_rep hostrep;
    uint8_t *repbuf;
    uint8_t *data;
    size_t replen, len;
    uint32_t num_results;
    enum nss_status nret;
    int ret;
    size_t data_len = 0;
    size_t ctr = 0;

    if (af != AF_INET && af != AF_INET6) {
        *errnop = EAFNOSUPPORT;
        *h_errnop = NETDB_INTERNAL;
        return NSS_STATUS_UNAVAIL;
    }

    /* Caught once glibc passing in buffer == 0x0 */
    if (buffer == NULL || buflen == 0) {
        *errnop = ERANGE;
        *h_errnop = NETDB_INTERNAL;
        return NSS_STATUS_TRYAGAIN;
    }

    data_len = sizeof(uint32_t) + sizeof(socklen_t) + addrlen;
    data = malloc(data_len);
    if (data == NULL) {
        *h_errnop = NETDB_INTERNAL;
        return NSS_STATUS_TRYAGAIN;
    }

    /* Push AF */
    SAFEALIGN_SETMEM_VALUE(data, af, uint32_t, &ctr);

    /* Push LEN */
    SAFEALIGN_SETMEM_VALUE(data + ctr, addrlen, socklen_t, &ctr);

    /* Push ADDR */
    SAFEALIGN_SETMEM_STRING(data + ctr, addr, addrlen, &ctr);

    rd.data = data;
    rd.len = data_len;

    sss_nss_lock();

    nret = sss_nss_make_request(SSS_NSS_GETHOSTBYADDR, &rd,
                                &repbuf, &replen, errnop);
    free(data);
    if (nret != NSS_STATUS_SUCCESS) {
        *h_errnop = NO_RECOVERY;
        goto out;
    }

    hostrep.result = result;
    hostrep.buffer = buffer;
    hostrep.buflen = buflen;

    /* Get number of results from repbuf. */
    SAFEALIGN_COPY_UINT32(&num_results, repbuf, NULL);

    /* No results if not found */
    if (num_results == 0) {
        free(repbuf);
        nret = NSS_STATUS_NOTFOUND;
        *h_errnop = HOST_NOT_FOUND;
        goto out;
    }

    /* Only 1 result is accepted for this function */
    if (num_results != 1) {
        free(repbuf);
        *errnop = EBADMSG;
        *h_errnop = NETDB_INTERNAL;
        nret = NSS_STATUS_TRYAGAIN;
        goto out;
    }

    len = replen - HOST_METADATA_COUNT;
    ret = sss_nss_gethost_readrep(&hostrep, repbuf + HOST_METADATA_COUNT,
                                  &len, af);
    free(repbuf);
    if (ret) {
        *errnop = ret;
        nret = NSS_STATUS_TRYAGAIN;
        *h_errnop = NETDB_INTERNAL;
        goto out;
    }

    /* If host name is valid but does not have an IP address of the requested
     * address family return the correct error.  */
    if (result->h_addr_list[0] == NULL) {
        *h_errnop = NO_DATA;
        nret = NSS_STATUS_TRYAGAIN;
        goto out;
    }

    nret = NSS_STATUS_SUCCESS;

out:
    sss_nss_unlock();

    return nret;
}

static enum nss_status
internal_gethostent_r(struct hostent *result,
                      char *buffer, size_t buflen,
                      int *errnop, int *h_errnop)
{
    struct sss_cli_req_data rd;
    struct sss_nss_host_rep pwrep;
    uint8_t *repbuf;
    size_t replen;
    uint32_t num_results;
    enum nss_status nret;
    uint32_t num_entries;
    int retval;

    /* Caught once glibc passing in buffer == 0x0 */
    if (buffer == NULL || buflen == 0) {
        *errnop = ERANGE;
        *h_errnop = NETDB_INTERNAL;
        return NSS_STATUS_TRYAGAIN;
    }

    /* if there are leftovers return the next one */
    if (sss_nss_gethostent_data.data != NULL &&
        sss_nss_gethostent_data.ptr < sss_nss_gethostent_data.len) {

        repbuf = sss_nss_gethostent_data.data + sss_nss_gethostent_data.ptr;
        replen = sss_nss_gethostent_data.len - sss_nss_gethostent_data.ptr;

        pwrep.result = result;
        pwrep.buffer = buffer;
        pwrep.buflen = buflen;

        retval = sss_nss_gethost_readrep(&pwrep, repbuf, &replen, AF_INET);
        if (retval) {
            *errnop = retval;
            *h_errnop = NETDB_INTERNAL;
            return NSS_STATUS_TRYAGAIN;
        }

        /* advance buffer pointer */
        sss_nss_gethostent_data.ptr = sss_nss_gethostent_data.len - replen;

        /* If host name is valid but does not have an IP address of the
         * requested address family return the correct error.  */
        if (result->h_addr_list[0] == NULL) {
            *h_errnop = NO_DATA;
            return NSS_STATUS_TRYAGAIN;
        }

        *h_errnop = 0;

        return NSS_STATUS_SUCCESS;
    }

    /* release memory if any */
    sss_nss_gethostent_data_clean();

    /* retrieve no more than SSS_NSS_MAX_ENTRIES at a time */
    num_entries = SSS_NSS_MAX_ENTRIES;
    rd.len = sizeof(uint32_t);
    rd.data = &num_entries;

    nret = sss_nss_make_request(SSS_NSS_GETHOSTENT, &rd,
                                &repbuf, &replen, errnop);
    if (nret != NSS_STATUS_SUCCESS) {
        *h_errnop = NO_RECOVERY;
        return nret;
    }

    /* Get number of results from repbuf */
    SAFEALIGN_COPY_UINT32(&num_results, repbuf, NULL);

    /* no results if not found */
    if ((num_results == 0) || (replen - HOST_METADATA_COUNT == 0)) {
        free(repbuf);
        *h_errnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
    }

    sss_nss_gethostent_data.data = repbuf;
    sss_nss_gethostent_data.len = replen;

    /* skip metadata fields */
    sss_nss_gethostent_data.ptr = HOST_METADATA_COUNT;

    /* call again ourselves, this will return the first result */
    return internal_gethostent_r(result, buffer, buflen, errnop, h_errnop);
}

enum nss_status
_nss_sss_sethostent(void)
{
    enum nss_status nret;
    int errnop;

    sss_nss_lock();

    /* make sure we do not have leftovers, and release memory */
    sss_nss_gethostent_data_clean();

    nret = sss_nss_make_request(SSS_NSS_SETHOSTENT,
                                NULL, NULL, NULL, &errnop);
    if (nret != NSS_STATUS_SUCCESS) {
        errno = errnop;
    }

    sss_nss_unlock();

    return nret;
}

enum nss_status
_nss_sss_gethostent_r(struct hostent *result,
                      char *buffer, size_t buflen,
                      int *errnop, int *h_errnop)
{
    enum nss_status nret;

    sss_nss_lock();
    nret = internal_gethostent_r(result, buffer, buflen, errnop, h_errnop);
    sss_nss_unlock();

    return nret;
}

enum nss_status
_nss_sss_endhostent(void)
{
    enum nss_status nret;
    int errnop;
    int saved_errno = errno;

    sss_nss_lock();

    /* make sure we do not have leftovers, and release memory */
    sss_nss_gethostent_data_clean();

    nret = sss_nss_make_request(SSS_NSS_ENDHOSTENT,
                                NULL, NULL, NULL, &errnop);
    if (nret != NSS_STATUS_SUCCESS) {
        errno = errnop;
    } else {
        errno = saved_errno;
    }

    sss_nss_unlock();
    return nret;
}
