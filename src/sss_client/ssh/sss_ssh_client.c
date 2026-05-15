/*
    Authors:
        Jan Cholasta <jcholast@redhat.com>

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

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <talloc.h>

#include <popt.h>
#include <locale.h>
#include <libintl.h>
#include <string.h>

#include "util/util.h"
#include "util/crypto/sss_crypto.h"
#include "util/sss_ssh.h"
#include "sss_client/sss_cli.h"
#include "sss_client/ssh/sss_ssh_client.h"

/* FIXME - split from tools_util to create a common function */
void usage(poptContext pc, const char *error)
{
    poptPrintUsage(pc, stderr, 0);
    if (error) fprintf(stderr, "%s", error);
}

/* FIXME - split from tools_util to create a common function */
int set_locale(void)
{
    char *c;

    c = setlocale(LC_ALL, "");
    if (c == NULL) {
        /* If setlocale fails, continue with the default
         * locale. */
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to set locale\n");
    }

    errno = 0;
    c = bindtextdomain(PACKAGE, LOCALEDIR);
    if (c == NULL) {
        return errno;
    }

    errno = 0;
    c = textdomain(PACKAGE);
    if (c == NULL) {
        return errno;
    }

    return EOK;
}

/* SSH public key request:
 *
 * header:
 *   0..3: flags (unsigned int, must be combination of SSS_SSH_REQ_* flags)
 *   4..7: name length (unsigned int)
 *   8..X: name (null-terminated UTF-8 string)
 * alias (only included if flags & SSS_SSH_REQ_ALIAS):
 *   0..3: alias length (unsigned int)
 *   4..X: alias (null-terminated UTF-8 string)
 * domain (ony included if flags & SSS_SSH_REQ_DOMAIN):
 *   0..3: domain length (unsigned int, 0 means default domain)
 *   4..X: domain (null-terminated UTF-8 string)
 *
 * SSH public key reply:
 *
 * header:
 *   0..3: number of results (unsigned int)
 *   4..7: reserved (unsigned int, must be 0)
 * results (repeated for each result):
 *   0..3:     flags (unsigned int, must be 0)
 *   4..7:     name length (unsigned int)
 *   8..(X-1): name (null-terminated UTF-8 string)
 *   X..(X+3): key length (unsigned int)
 *   (X+4)..Y: key (public key data)
 */
errno_t
sss_ssh_get_ent(TALLOC_CTX *mem_ctx,
                enum sss_cli_command command,
                const char *name,
                const char *domain,
                const char *alias,
                struct sss_ssh_ent **result)
{
    TALLOC_CTX *tmp_ctx;
    struct sss_ssh_ent *res = NULL;
    errno_t ret;
    uint32_t flags;
    uint32_t name_len;
    uint32_t alias_len = 0;
    uint32_t domain_len;
    size_t req_len;
    uint8_t *req = NULL;
    size_t c = 0;
    struct sss_cli_req_data rd;
    int req_ret, req_errno;
    uint8_t *rep = NULL;
    size_t rep_len;
    uint32_t count, reserved, len, i;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    /* build request */
    flags = 0;
    name_len = strlen(name)+1;
    req_len = 2*sizeof(uint32_t) + name_len;

    if (alias) {
        flags |= SSS_SSH_REQ_ALIAS;
        alias_len = strlen(alias)+1;
        req_len += sizeof(uint32_t) + alias_len;
    }

    flags |= SSS_SSH_REQ_DOMAIN;
    domain_len = domain ? (strlen(domain)+1) : 0;
    req_len += sizeof(uint32_t) + domain_len;

    req = talloc_array(tmp_ctx, uint8_t, req_len);
    if (!req) {
        ret = ENOMEM;
        goto done;
    }

    SAFEALIGN_SET_UINT32(req+c, flags, &c);
    SAFEALIGN_SET_UINT32(req+c, name_len, &c);
    safealign_memcpy(req+c, name, name_len, &c);
    if (alias) {
        SAFEALIGN_SET_UINT32(req+c, alias_len, &c);
        safealign_memcpy(req+c, alias, alias_len, &c);
    }
    SAFEALIGN_SET_UINT32(req+c, domain_len, &c);
    if (domain_len > 0) {
        safealign_memcpy(req+c, domain, domain_len, &c);
    }

    /* send request */
    rd.data = req;
    rd.len = req_len;

    req_ret = sss_ssh_make_request(command, &rd, &rep, &rep_len, &req_errno);
    if (req_errno != EOK) {
        ret = req_errno;
        goto done;
    }
    if (req_ret != SSS_STATUS_SUCCESS) {
        ret = EFAULT;
        goto done;
    }

    /* parse reply */
    c = 0;
    if (rep_len < c + 2*sizeof(uint32_t)) {
        ret = EINVAL;
        goto done;
    }

    SAFEALIGN_COPY_UINT32(&count, rep+c, &c);

    SAFEALIGN_COPY_UINT32(&reserved, rep+c, &c);
    if (reserved != 0) {
        ret = EINVAL;
        goto done;
    }

    res = talloc_zero(tmp_ctx, struct sss_ssh_ent);
    if (!res) {
        ret = ENOMEM;
        goto done;
    }

    if (count > 0) {
        res->pubkeys = talloc_zero_array(res, struct sss_ssh_pubkey, count);
        if (!res->pubkeys) {
            ret = ENOMEM;
            goto done;
        }

        res->num_pubkeys = count;
    }

    for (i = 0; i < count; i++) {
        if (rep_len-c < 2*sizeof(uint32_t)) {
            ret = EINVAL;
            goto done;
        }

        SAFEALIGN_COPY_UINT32(&flags, rep+c, &c);
        if (flags != 0) {
            ret = EINVAL;
            goto done;
        }

        SAFEALIGN_COPY_UINT32(&len, rep+c, &c);

        if (len > rep_len - c - sizeof(uint32_t)) {
            ret = EINVAL;
            goto done;
        }

        if (!res->name) {
            res->name = talloc_array(res, char, len);
            if (!res->name) {
                ret = ENOMEM;
                goto done;
            }

            safealign_memcpy(res->name, rep+c, len, &c);
            if (strnlen(res->name, len) != len-1) {
                ret = EINVAL;
                goto done;
            }
        } else {
            c += len;
        }

        SAFEALIGN_COPY_UINT32(&len, rep+c, &c);

        if (len > rep_len - c) {
            ret = EINVAL;
            goto done;
        }

        res->pubkeys[i].data = talloc_array(res, uint8_t, len);
        if (!res->pubkeys[i].data) {
            ret = ENOMEM;
            goto done;
        }

        safealign_memcpy(res->pubkeys[i].data, rep+c, len, &c);
        res->pubkeys[i].data_len = len;
    }

    *result = talloc_steal(mem_ctx, res);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    free(rep);

    return ret;
}
