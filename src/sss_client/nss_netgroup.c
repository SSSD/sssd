/*
    SSSD

    nss_netgroup.c

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2010 Red Hat

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

#include <nss.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "sss_cli.h"
#include "nss_compat.h"

#define CLEAR_NETGRENT_DATA(netgrent) do { \
        free(netgrent->data); \
        netgrent->data = NULL; \
        netgrent->idx.position = 0; \
        netgrent->data_size = 0; \
} while (0);

/*
 * Replies:
 *
 * 0-3: 32bit unsigned number of results N
 * 4-7: 32bit unsigned (reserved/padding)
 *  For each result:
 *  8-11: 32bit unsigned type of result
 *  12-X: \0 terminated string representing a tuple
 *        (host, user, domain)
 *        or a netgroup, depending on the type indicator
 *  ... repeated N times
 */
#define NETGR_METADATA_COUNT 2 * sizeof(uint32_t)
struct sss_nss_netgr_rep {
    struct __netgrent *result;
    char *buffer;
    size_t buflen;
};

static int sss_nss_getnetgr_readrep(struct sss_nss_netgr_rep *pr,
                                    uint8_t *buf, size_t *len)
{
    errno_t ret;
    char *sbuf;
    char *temp;
    size_t i, slen, dlen, size;
    uint32_t type;

    if (*len < 6) {
        /* Not enough space for data, bad packet */
        return EBADMSG;
    }

    sbuf = (char *)(buf + sizeof(uint32_t));
    slen = *len - sizeof(uint32_t);
    dlen = pr->buflen;

    i = 0;

    SAFEALIGN_COPY_UINT32(&type, buf, NULL);
    switch (type) {
        case SSS_NETGR_REP_TRIPLE:
            pr->result->type = triple_val;

            /* Host value */
            temp = &(pr->buffer[i]);
            ret = sss_readrep_copy_string(sbuf, &i,
                                          &slen, &dlen,
                                          &temp,
                                          &size);
            if (ret != EOK) return ret;

            /* libc expects NULL instead of empty string */
            if (size == 0) {
                pr->result->val.triple.host = NULL;
            } else {
                pr->result->val.triple.host = temp;
            }

            /* User value */
            temp = &(pr->buffer[i]);
            ret = sss_readrep_copy_string(sbuf, &i,
                                          &slen, &dlen,
                                          &temp,
                                          &size);
            if (ret != EOK) return ret;

            /* libc expects NULL instead of empty string */
            if (size == 0) {
                pr->result->val.triple.user = NULL;
            } else {
                pr->result->val.triple.user = temp;
            }

            /* Domain value */
            temp = &(pr->buffer[i]);
            ret = sss_readrep_copy_string(sbuf, &i,
                                          &slen, &dlen,
                                          &temp,
                                          &size);
            if (ret != EOK) return ret;

            /* libc expects NULL instead of empty string */
            if (size == 0) {
                pr->result->val.triple.domain = NULL;
            } else {
                pr->result->val.triple.domain = temp;
            }

            break;

        case SSS_NETGR_REP_GROUP:
            pr->result->type = group_val;

            temp = &(pr->buffer[i]);
            ret = sss_readrep_copy_string(sbuf, &i,
                                          &slen, &dlen,
                                          &temp,
                                          NULL);
            if (ret != EOK) return ret;

            pr->result->val.group = temp;

            break;

        default:
            return EBADMSG;
    }


    *len = slen -i;

    return 0;
}

enum nss_status _nss_sss_setnetgrent(const char *netgroup,
                     struct __netgrent *result)
{
    uint8_t *repbuf = NULL;
    size_t replen;
    uint32_t num_results;
    enum nss_status nret;
    struct sss_cli_req_data rd;
    int errnop;
    char *name;
    size_t name_len;
    errno_t ret;

    if (!netgroup) return NSS_STATUS_NOTFOUND;

    sss_nss_lock();

    /* make sure we do not have leftovers, and release memory */
    CLEAR_NETGRENT_DATA(result);

    ret = sss_strnlen(netgroup, SSS_NAME_MAX, &name_len);
    if (ret != 0) {
        nret = NSS_STATUS_NOTFOUND;
        goto out;
    }

    name = malloc(sizeof(char)*name_len + 1);
    if (name == NULL) {
        nret = NSS_STATUS_TRYAGAIN;
        goto out;
    }
    strncpy(name, netgroup, name_len + 1);

    rd.data = name;
    rd.len = name_len + 1;

    nret = sss_nss_make_request(SSS_NSS_SETNETGRENT, &rd,
                                &repbuf, &replen, &errnop);
    free(name);
    if (nret != NSS_STATUS_SUCCESS) {
        errno = errnop;
        goto out;
    }

    /* Get number of results from repbuf */
    SAFEALIGN_COPY_UINT32(&num_results, repbuf, NULL);

    /* no results if not found */
    if ((num_results == 0) || (replen < NETGR_METADATA_COUNT)) {
        free(repbuf);
        nret = NSS_STATUS_NOTFOUND;
        goto out;
    }

    result->data = (char *) repbuf;
    result->data_size = replen;
    /* skip metadata fields */
    result->idx.position = NETGR_METADATA_COUNT;

    nret = NSS_STATUS_SUCCESS;

out:
    sss_nss_unlock();
    return nret;
}

static enum nss_status internal_getnetgrent_r(struct __netgrent *result,
                                              char *buffer, size_t buflen,
                                              int *errnop)
{
    struct sss_nss_netgr_rep netgrrep;
    uint8_t *repbuf;
    size_t replen;
    int ret;

    /* Caught once glibc passing in buffer == 0x0 */
    if (!buffer || !buflen) {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    /* If we're already processing result data, continue to
     * return it.
     */
    if (result->data != NULL &&
        result->idx.position < result->data_size) {

        repbuf = (uint8_t *) result->data + result->idx.position;
        replen = result->data_size - result->idx.position;

        netgrrep.result = result;
        netgrrep.buffer = buffer;
        netgrrep.buflen = buflen;

        ret = sss_nss_getnetgr_readrep(&netgrrep, repbuf, &replen);
        if (ret != 0) {
            *errnop = ret;
            return NSS_STATUS_TRYAGAIN;
        }

        result->idx.position = result->data_size - replen;

        return NSS_STATUS_SUCCESS;
    }

    return NSS_STATUS_RETURN;
}

enum nss_status _nss_sss_getnetgrent_r(struct __netgrent *result,
                       char *buffer, size_t buflen,
                       int *errnop)
{
    enum nss_status nret;

    /* no lock needed because results are already stored in result */
    nret = internal_getnetgrent_r(result, buffer, buflen, errnop);

    return nret;
}

enum nss_status _nss_sss_endnetgrent(struct __netgrent *result)
{
    /* no lock needed because resources in the responder are already
     * released */
    /* make sure we do not have leftovers, and release memory */
    CLEAR_NETGRENT_DATA(result);

    return NSS_STATUS_SUCCESS;
}
