/*
    SSSD

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

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

#include "config.h"

#include <nss.h>
#include <netdb.h>
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
struct sss_nss_getservent_data {
    size_t len;
    size_t ptr;
    uint8_t *data;
} sss_nss_getservent_data;

static void sss_nss_getservent_data_clean(void) {

    if (sss_nss_getservent_data.data != NULL) {
        free(sss_nss_getservent_data.data);
        sss_nss_getservent_data.data = NULL;
    }
    sss_nss_getservent_data.len = 0;
    sss_nss_getservent_data.ptr = 0;
}

/* GETSERVBYNAME Request
 *
 * 0-X: Sequence of two, zero-terminated strings (name, protocol).
 * Protocol may be zero-length to imply "any"
 *
 * GETSERVBYPORT Request:
 * 0-3: 16-bit port number in network byte order
 * 4-15: Reserved/padding
 * 16-X: Zero-terminated string (protocol)
 * Protocol may be zero-length to imply "any"
 *
 * Replies:
 * 0-3: 32-bit unsigned number of results
 * 4-7: 32-bit unsigned (reserved/padding)
 * 7-X: Result data (blocks equal to number of results)
 *
 * Result data:
 * 0-3: 32-bit unsigned port number in network byte order
 * 4-7: 32-bit unsigned number of aliases
 * 8-X: sequence of zero-terminated strings
 *      (name, protocol, zero or more aliases)
 */
struct sss_nss_svc_rep {
    struct servent *result;
    char *buffer;
    size_t buflen;
};

#define SVC_METADATA_COUNT 8

static errno_t
sss_nss_getsvc_readrep(struct sss_nss_svc_rep *sr,
                       uint8_t *buf, size_t *len)
{
    errno_t ret;
    uint32_t c;
    uint32_t num_aliases;
    size_t i, l, slen, dlen, pad, ptaliases, alen;
    char *sbuf;

    /* Buffer must contain two 32-bit integers,
     * at least one character and null-terminator
     * for the name, and at least a null-
     * terminator for the protocol.
     */
    if (*len < 11) {
        /* not enough space for data, bad packet */
        return EBADMSG;
    }

    /* Get the port */
    SAFEALIGN_COPY_UINT32(&c, buf, NULL);
    sr->result->s_port = (uint16_t)c;

    /* Get the number of aliases */
    SAFEALIGN_COPY_UINT32(&num_aliases, buf + sizeof(uint32_t), NULL);

    sbuf = (char *)&buf[2 * sizeof(uint32_t)];
    slen = *len - (2 * sizeof(uint32_t));
    dlen = sr->buflen;

    /* Copy in the name */
    i = 0;
    sr->result->s_name = &(sr->buffer[i]);

    ret = sss_readrep_copy_string(sbuf, &i,
                                  &slen, &dlen,
                                  &sr->result->s_name,
                                  NULL);
    if (ret != EOK) return ret;

    /* Copy in the protocol */
    sr->result->s_proto = &(sr->buffer[i]);

    ret = sss_readrep_copy_string(sbuf, &i,
                                  &slen, &dlen,
                                  &sr->result->s_proto,
                                  NULL);
    if (ret != EOK) return ret;

    /* Make sure sr->buffer[i+pad] is aligned to sizeof(char *) */
    pad = PADDING_SIZE(i, char *);

    /* Copy in the aliases */
    sr->result->s_aliases = DISCARD_ALIGN(&(sr->buffer[i+pad]), char **);

    ptaliases = (sizeof(char *) * (num_aliases + 1)) + pad;
    if (ptaliases > dlen) {
        return ERANGE; /* not ENOMEM, ERANGE is what glibc looks for */
    }

    dlen -= ptaliases;
    ptaliases += i;
    sr->result->s_aliases[num_aliases] = NULL; /* terminate array */

    for (l = 0; l < num_aliases; l++) {
        sr->result->s_aliases[l] = &(sr->buffer[ptaliases]);
        ret = sss_readrep_copy_string(sbuf, &i,
                                      &slen, &dlen,
                                      &sr->result->s_aliases[l],
                                      &alen);
        if (ret != EOK) return ret;

        ptaliases += alen + 1;
    }

    *len = slen - i;

    return EOK;
}

enum nss_status
_nss_sss_getservbyname_r(const char *name,
                         const char *protocol,
                         struct servent *result,
                         char *buffer, size_t buflen,
                         int *errnop)
{
    struct sss_cli_req_data rd;
    struct sss_nss_svc_rep svcrep;
    size_t name_len;
    size_t proto_len = 0;
    uint8_t *repbuf;
    uint8_t *data;
    size_t replen, len;
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

    if (protocol) {
        ret = sss_strnlen(protocol, SSS_NAME_MAX, &proto_len);
        if (ret != 0) {
            *errnop = EINVAL;
            return NSS_STATUS_NOTFOUND;
        }
    }

    rd.len = name_len + proto_len + 2;
    data = malloc(sizeof(uint8_t)*rd.len);
    if (data == NULL) {
        *errnop = ENOMEM;
        return NSS_STATUS_TRYAGAIN;
    }

    memcpy(data, name, name_len + 1);

    if (protocol) {
        memcpy(data + name_len + 1, protocol, proto_len + 1);
    } else {
        /* No protocol specified, pass empty string */
        data[name_len + 1] = '\0';
    }
    rd.data = data;

    sss_nss_lock();

    nret = sss_nss_make_request(SSS_NSS_GETSERVBYNAME, &rd,
                                &repbuf, &replen, errnop);
    free(data);
    if (nret != NSS_STATUS_SUCCESS) {
        goto out;
    }

    svcrep.result = result;
    svcrep.buffer = buffer;
    svcrep.buflen = buflen;

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

    len = replen - SVC_METADATA_COUNT;
    ret = sss_nss_getsvc_readrep(&svcrep,
                                 repbuf + SVC_METADATA_COUNT,
                                 &len);
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


enum nss_status
_nss_sss_getservbyport_r(int port, const char *protocol,
                         struct servent *result,
                         char *buffer, size_t buflen,
                         int *errnop)
{
    struct sss_cli_req_data rd;
    struct sss_nss_svc_rep svcrep;
    size_t proto_len = 0;
    uint8_t *repbuf;
    uint8_t *data;
    size_t p = 0;
    size_t replen, len;
    uint32_t num_results;
    enum nss_status nret;
    int ret;

    /* Caught once glibc passing in buffer == 0x0 */
    if (!buffer || !buflen) {
	*errnop = ERANGE;
	return NSS_STATUS_TRYAGAIN;
    }

    if (port == 0) {
        *errnop = EINVAL;
        return NSS_STATUS_NOTFOUND;
    }

    if (protocol) {
        ret = sss_strnlen(protocol, SSS_NAME_MAX, &proto_len);
        if (ret != 0) {
            *errnop = EINVAL;
            return NSS_STATUS_NOTFOUND;
        }
    }

    rd.len = sizeof(uint32_t)*2 + proto_len + 1;
    data = malloc(sizeof(uint8_t)*rd.len);
    if (data == NULL) {
        *errnop = ENOMEM;
        return NSS_STATUS_TRYAGAIN;
    }

    SAFEALIGN_SET_UINT16(data, port, &p);

    /* Padding */
    SAFEALIGN_SET_UINT16(data + p, 0, &p);
    SAFEALIGN_SET_UINT32(data + p, 0, &p);

    if (protocol) {
        memcpy(data + p, protocol, proto_len + 1);
    } else {
        /* No protocol specified, pass empty string */
        data[p] = '\0';
    }
    rd.data = data;

    sss_nss_lock();

    nret = sss_nss_make_request(SSS_NSS_GETSERVBYPORT, &rd,
                                &repbuf, &replen, errnop);
    free(data);
    if (nret != NSS_STATUS_SUCCESS) {
        goto out;
    }

    svcrep.result = result;
    svcrep.buffer = buffer;
    svcrep.buflen = buflen;

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

    len = replen - SVC_METADATA_COUNT;
    ret = sss_nss_getsvc_readrep(&svcrep,
                                 repbuf + SVC_METADATA_COUNT,
                                 &len);
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


enum nss_status
_nss_sss_setservent(void)
{
    enum nss_status nret;
    int errnop;
    sss_nss_lock();

    /* make sure we do not have leftovers, and release memory */
    sss_nss_getservent_data_clean();

    nret = sss_nss_make_request(SSS_NSS_SETSERVENT,
                                NULL, NULL, NULL, &errnop);
    if (nret != NSS_STATUS_SUCCESS) {
        errno = errnop;
    }

    sss_nss_unlock();
    return nret;
}

static enum nss_status internal_getservent_r(struct servent *result,
                                             char *buffer, size_t buflen,
                                             int *errnop);

enum nss_status
_nss_sss_getservent_r(struct servent *result,
                      char *buffer, size_t buflen,
                      int *errnop)
{
    enum nss_status nret;

    sss_nss_lock();
    nret = internal_getservent_r(result, buffer, buflen, errnop);
    sss_nss_unlock();

    return nret;
}

static enum nss_status internal_getservent_r(struct servent *result,
                                             char *buffer, size_t buflen,
                                             int *errnop)
{
    struct sss_cli_req_data rd;
    struct sss_nss_svc_rep pwrep;
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
    if (sss_nss_getservent_data.data != NULL &&
        sss_nss_getservent_data.ptr < sss_nss_getservent_data.len) {

        repbuf = sss_nss_getservent_data.data + sss_nss_getservent_data.ptr;
        replen = sss_nss_getservent_data.len - sss_nss_getservent_data.ptr;

        pwrep.result = result;
        pwrep.buffer = buffer;
        pwrep.buflen = buflen;

        ret = sss_nss_getsvc_readrep(&pwrep, repbuf, &replen);
        if (ret) {
            *errnop = ret;
            return NSS_STATUS_TRYAGAIN;
        }

        /* advance buffer pointer */
        sss_nss_getservent_data.ptr = sss_nss_getservent_data.len - replen;

        return NSS_STATUS_SUCCESS;
    }

    /* release memory if any */
    sss_nss_getservent_data_clean();

    /* retrieve no more than SSS_NSS_MAX_ENTRIES at a time */
    num_entries = SSS_NSS_MAX_ENTRIES;
    rd.len = sizeof(uint32_t);
    rd.data = &num_entries;

    nret = sss_nss_make_request(SSS_NSS_GETSERVENT, &rd,
                                &repbuf, &replen, errnop);
    if (nret != NSS_STATUS_SUCCESS) {
        return nret;
    }

    /* Get number of results from repbuf */
    SAFEALIGN_COPY_UINT32(&num_results, repbuf, NULL);

    /* no results if not found */
    if ((num_results == 0) || (replen - SVC_METADATA_COUNT == 0)) {
        free(repbuf);
        return NSS_STATUS_NOTFOUND;
    }

    sss_nss_getservent_data.data = repbuf;
    sss_nss_getservent_data.len = replen;

    /* skip metadata fields */
    sss_nss_getservent_data.ptr = SVC_METADATA_COUNT;

    /* call again ourselves, this will return the first result */
    return internal_getservent_r(result, buffer, buflen, errnop);
}


enum nss_status
_nss_sss_endservent(void)
{
    enum nss_status nret;
    int errnop;
    int saved_errno = errno;

    sss_nss_lock();

    /* make sure we do not have leftovers, and release memory */
    sss_nss_getservent_data_clean();

    nret = sss_nss_make_request(SSS_NSS_ENDSERVENT,
                                NULL, NULL, NULL, &errnop);
    if (nret != NSS_STATUS_SUCCESS) {
        errno = errnop;
    } else {
        errno = saved_errno;
    }

    sss_nss_unlock();
    return nret;
}
