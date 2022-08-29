/*
    SSSD

    Authors:
        Samuel Cabrero <scabrero@suse.com>

    Copyright (C) 2020 SUSE LINUX GmbH, Nuernberg, Germany.

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
struct sss_nss_getnetent_data {
    size_t len;
    size_t ptr;
    uint8_t *data;
} sss_nss_getnetent_data;

static void
sss_nss_getnetent_data_clean(void)
{
    if (sss_nss_getnetent_data.data != NULL) {
        free(sss_nss_getnetent_data.data);
        sss_nss_getnetent_data.data = NULL;
    }
    sss_nss_getnetent_data.len = 0;
    sss_nss_getnetent_data.ptr = 0;
}

/* GETNETBYNAME Request
 *
 * 0-X: One zero-terminated string (name)
 *
 * GETNETBYADDR Request:
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
 * 4-X: sequence of zero-terminated strings
 *      (name, address, zero or more aliases)
 */

struct sss_nss_net_rep {
    struct netent *result;
    char *buffer;
    size_t buflen;
};

#define IP_NETWORK_METADATA_COUNT 8

static errno_t
sss_nss_net_readrep(struct sss_nss_net_rep *sr,
                    uint8_t *buf, size_t *len, int type)
{
    errno_t ret;
    char *net_addrstr;
    uint32_t net_addr;
    uint32_t num_aliases;
    const char *sbuf;
    size_t i, l, slen, dlen, pad, ptmem, alen;

    /* Only AF_INET is supported */
    if (type != AF_INET) {
        return EBADMSG;
    }

    /* Buffer must contain one 32-bit integer,
     * at least one character and null terminator
     * for the name, at least one character and a
     * null terminator for the address and a null
     * terminator for the aliases.
     */
    if (*len < 9) {
        /* not enough data, bad packet */
        return EBADMSG;
    }

    /* Get the number of aliases */
    SAFEALIGN_COPY_UINT32(&num_aliases, buf, NULL);

    sbuf = (char *)&buf[sizeof(uint32_t)];
    slen = *len - (sizeof(uint32_t));
    dlen = sr->buflen;
    i = 0;

    /* Copy the name */
    sr->result->n_name = &(sr->buffer[i]);
    ret = sss_readrep_copy_string(sbuf, &i,
                                  &slen, &dlen,
                                  &sr->result->n_name,
                                  NULL);
    if (ret != EOK) {
        return ret;
    }

    /* Copy the address */
    net_addrstr = &(sr->buffer[i]);
    ret = sss_readrep_copy_string(sbuf, &i,
                                  &slen, &dlen,
                                  &net_addrstr,
                                  NULL);
    if (ret != EOK) {
        return ret;
    }

    if (inet_pton(AF_INET, net_addrstr, &net_addr)) {
        sr->result->n_addrtype = AF_INET;
    } else {
        /* Skip illegal address */
        return EAFNOSUPPORT;
    }

    /* result->n_net must be represented in host byte order */
    sr->result->n_net = ntohl(net_addr);

    /* Copy the aliases */
    pad = PADDING_SIZE(i, char *);
    sr->result->n_aliases = DISCARD_ALIGN(&(sr->buffer[i+pad]), char **);

    ptmem = (sizeof(char *) * (num_aliases + 1)) + pad;
    if (ptmem > dlen) {
        /* Not ENOMEM, ERANGE is what glibc looks for */
        return ERANGE;
    }

    dlen -= ptmem;
    ptmem += i;

    /* Terminate array */
    sr->result->n_aliases[num_aliases] = NULL;

    for (l = 0; l < num_aliases; l++) {
        sr->result->n_aliases[l] = &(sr->buffer[ptmem]);
        ret = sss_readrep_copy_string(sbuf, &i,
                                      &slen, &dlen,
                                      &sr->result->n_aliases[l],
                                      &alen);
        if (ret != EOK) {
            return ret;
        }

        ptmem += alen + 1;
    }

    *len = slen - i;

    return EOK;
}

enum nss_status
_nss_sss_getnetbyname_r(const char *name,
                        struct netent *result,
                        char *buffer, size_t buflen,
                        int *errnop, int *h_errnop)
{
    struct sss_cli_req_data rd;
    struct sss_nss_net_rep netrep;
    size_t name_len;
    uint8_t *repbuf;
    size_t replen, len;
    uint32_t num_results;
    enum nss_status nret;
    int ret;

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

    nret = sss_nss_make_request(SSS_NSS_GETNETBYNAME, &rd,
                                &repbuf, &replen, errnop);
    if (nret != NSS_STATUS_SUCCESS) {
        *h_errnop = NETDB_INTERNAL;
        goto out;
    }

    netrep.result = result;
    netrep.buffer = buffer;
    netrep.buflen = buflen;

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

    len = replen - IP_NETWORK_METADATA_COUNT;
    ret = sss_nss_net_readrep(&netrep, repbuf + IP_NETWORK_METADATA_COUNT,
                              &len, AF_INET);
    free(repbuf);

    /* If network name is valid but does not have an IP address of the
     * requested address family return the correct error
     */
    if (ret == EAFNOSUPPORT) {
        *h_errnop = NO_DATA;
        nret = NSS_STATUS_TRYAGAIN;
        goto out;
    } else if (ret) {
        *errnop = ret;
        nret = NSS_STATUS_TRYAGAIN;
        *h_errnop = NETDB_INTERNAL;
        goto out;
    }

    nret = NSS_STATUS_SUCCESS;

out:
    sss_nss_unlock();

    return nret;
}

enum nss_status
_nss_sss_getnetbyaddr_r(uint32_t addr, int type,
                        struct netent *result,
                        char *buffer, size_t buflen,
                        int *errnop, int *h_errnop)
{
    struct sss_cli_req_data rd;
    struct sss_nss_net_rep netrep;
    uint8_t *repbuf;
    uint8_t *data;
    size_t replen, len;
    uint32_t num_results;
    enum nss_status nret;
    int ret;
    size_t data_len = 0;
    size_t ctr = 0;
    socklen_t addrlen;

    /* addr is in host byte order, but nss_protocol_parse_addr and inet_ntop
     * expects the buffer in network byte order */
    addr = htonl(addr);

    if (type == AF_UNSPEC) {
        char addrbuf[INET_ADDRSTRLEN];

        /* Try to parse to IPv4 */
        if (inet_ntop(AF_INET, &addr, addrbuf, INET_ADDRSTRLEN)) {
            type = AF_INET;
        }
    }

    if (type != AF_INET) {
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

    addrlen = INADDRSZ;

    data_len = sizeof(uint32_t) + sizeof(socklen_t) + addrlen;
    data = malloc(data_len);
    if (data == NULL) {
        *h_errnop = NETDB_INTERNAL;
        return NSS_STATUS_TRYAGAIN;
    }

    /* Push type */
    SAFEALIGN_SETMEM_VALUE(data, type, int, &ctr);

    /* Push LEN */
    SAFEALIGN_SETMEM_VALUE(data + ctr, addrlen, socklen_t, &ctr);

    /* Push ADDR */
    SAFEALIGN_SETMEM_STRING(data + ctr, &addr, addrlen, &ctr);

    rd.data = data;
    rd.len = data_len;

    sss_nss_lock();

    nret = sss_nss_make_request(SSS_NSS_GETNETBYADDR, &rd,
                                &repbuf, &replen, errnop);
    free(data);
    if (nret != NSS_STATUS_SUCCESS) {
        *h_errnop = NETDB_INTERNAL;
        goto out;
    }

    netrep.result = result;
    netrep.buffer = buffer;
    netrep.buflen = buflen;

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

    len = replen - IP_NETWORK_METADATA_COUNT;
    ret = sss_nss_net_readrep(&netrep, repbuf + IP_NETWORK_METADATA_COUNT,
                              &len, type);
    free(repbuf);

    /* If network name is valid but does not have an IP address of the
     * requested address family return the correct error
     */
    if (ret == EAFNOSUPPORT) {
        *h_errnop = NO_DATA;
        nret = NSS_STATUS_TRYAGAIN;
        goto out;
    } else if (ret) {
        *errnop = ret;
        nret = NSS_STATUS_TRYAGAIN;
        *h_errnop = NETDB_INTERNAL;
        goto out;
    }

    nret = NSS_STATUS_SUCCESS;

out:
    sss_nss_unlock();

    return nret;
}

static enum nss_status
internal_getnetent_r(struct netent *result,
                     char *buffer, size_t buflen,
                     int *errnop, int *h_errnop)
{
    struct sss_cli_req_data rd;
    struct sss_nss_net_rep netrep;
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
    if (sss_nss_getnetent_data.data != NULL &&
        sss_nss_getnetent_data.ptr < sss_nss_getnetent_data.len) {

        repbuf = sss_nss_getnetent_data.data + sss_nss_getnetent_data.ptr;
        replen = sss_nss_getnetent_data.len - sss_nss_getnetent_data.ptr;

        netrep.result = result;
        netrep.buffer = buffer;
        netrep.buflen = buflen;

        retval = sss_nss_net_readrep(&netrep, repbuf, &replen, AF_INET);
        /* If net name is valid but does not have an IP address of the
         * requested address family return the correct error.  */
        if (retval == EAFNOSUPPORT) {
            *h_errnop = NO_DATA;
            return NSS_STATUS_TRYAGAIN;
        } else if (retval) {
            *errnop = retval;
            *h_errnop = NETDB_INTERNAL;
            return NSS_STATUS_TRYAGAIN;
        }

        /* advance buffer pointer */
        sss_nss_getnetent_data.ptr = sss_nss_getnetent_data.len - replen;

        *h_errnop = 0;

        return NSS_STATUS_SUCCESS;
    }

    /* release memory if any */
    sss_nss_getnetent_data_clean();

    /* retrieve no more than SSS_NSS_MAX_ENTRIES at a time */
    num_entries = SSS_NSS_MAX_ENTRIES;
    rd.len = sizeof(uint32_t);
    rd.data = &num_entries;

    nret = sss_nss_make_request(SSS_NSS_GETNETENT, &rd,
                                &repbuf, &replen, errnop);
    if (nret != NSS_STATUS_SUCCESS) {
        *h_errnop = NETDB_INTERNAL;
        return nret;
    }

    /* Get number of results from repbuf */
    SAFEALIGN_COPY_UINT32(&num_results, repbuf, NULL);

    /* no results if not found */
    if ((num_results == 0) || (replen - IP_NETWORK_METADATA_COUNT == 0)) {
        free(repbuf);
        *h_errnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
    }

    sss_nss_getnetent_data.data = repbuf;
    sss_nss_getnetent_data.len = replen;

    /* skip metadata fields */
    sss_nss_getnetent_data.ptr = IP_NETWORK_METADATA_COUNT;

    /* call again ourselves, this will return the first result */
    return internal_getnetent_r(result, buffer, buflen, errnop, h_errnop);
}

enum nss_status
_nss_sss_setnetent(void)
{
    enum nss_status nret;
    int errnop;

    sss_nss_lock();

    /* make sure we do not have leftovers, and release memory */
    sss_nss_getnetent_data_clean();

    nret = sss_nss_make_request(SSS_NSS_SETNETENT,
                                NULL, NULL, NULL, &errnop);
    if (nret != NSS_STATUS_SUCCESS) {
        errno = errnop;
    }

    sss_nss_unlock();

    return nret;
}

enum nss_status
_nss_sss_getnetent_r(struct netent *result,
                     char *buffer, size_t buflen,
                     int *errnop, int *h_errnop)
{
    enum nss_status nret;

    sss_nss_lock();
    nret = internal_getnetent_r(result, buffer, buflen, errnop, h_errnop);
    sss_nss_unlock();

    return nret;
}

enum nss_status
_nss_sss_endnetent(void)
{
    enum nss_status nret;
    int errnop;
    int saved_errno = errno;

    sss_nss_lock();

    /* make sure we do not have leftovers, and release memory */
    sss_nss_getnetent_data_clean();

    nret = sss_nss_make_request(SSS_NSS_ENDNETENT,
                                NULL, NULL, NULL, &errnop);
    if (nret != NSS_STATUS_SUCCESS) {
        errno = errnop;
    } else {
        errno = saved_errno;
    }

    sss_nss_unlock();
    return nret;
}

