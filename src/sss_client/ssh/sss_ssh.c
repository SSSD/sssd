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
#include <arpa/inet.h>
#include <talloc.h>

#include <popt.h>
#include <locale.h>
#include <libintl.h>
#include <string.h>

#include "util/crypto/sss_crypto.h"
#include "sss_client/sss_cli.h"
#include "sss_client/ssh/sss_ssh.h"

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
        return EIO;
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
 * 0..3: flags (unsigned int, must be 0)
 * 4..7: name length (unsigned int)
 * 8..$: name (null-terminated UTF-8 string)
 * 
 * SSH public key reply:
 * 
 * 0..3: number of results (unsigned int)
 * 4..7: reserved (unsigned int, must be 0)
 * 8..$: array of results:
 *   0..3:     flags (unsigned int, must be 0)
 *   4..7:     name length (unsigned int)
 *   8..(X-1): name (null-terminated UTF-8 string)
 *   X..(X+3): key length (unsigned int)
 *   (X+4)..Y: key (public key blob as defined in RFC4253, section 6.6)
 */
errno_t
sss_ssh_get_pubkeys(TALLOC_CTX *mem_ctx,
                    enum sss_cli_command command,
                    const char *name,
                    struct sss_ssh_pubkey **pubkeys,
                    size_t *pubkeys_len)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret = EOK;
    uint32_t name_len;
    size_t req_len;
    uint8_t *req = NULL;
    size_t c = 0;
    struct sss_cli_req_data rd;
    int req_ret, req_errno;
    uint8_t *rep = NULL;
    size_t rep_len;
    uint32_t count, reserved, len, i;
    struct sss_ssh_pubkey *result = NULL;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    /* build request */
    name_len = strlen(name)+1;
    req_len = 2*sizeof(uint32_t) + name_len;

    req = talloc_array(tmp_ctx, uint8_t, req_len);
    if (!req) {
        ret = ENOMEM;
        goto done;
    }

    SAFEALIGN_SET_UINT32(req+c, 0, &c);
    SAFEALIGN_SET_UINT32(req+c, name_len, &c);
    safealign_memcpy(req+c, name, name_len, &c);

    /* send request */
    rd.data = req;
    rd.len = req_len;

    req_ret = sss_ssh_make_request(command, &rd, &rep, &rep_len, &req_errno);
    if (req_ret != SSS_STATUS_SUCCESS) {
        ret = EFAULT;
        goto done;
    }
    if (req_errno != EOK) {
        ret = req_errno;
        goto done;
    }

    /* parse reply */
    c = 0;
    if (rep_len-c < 2*sizeof(uint32_t)) {
        ret = EINVAL;
        goto done;
    }

    SAFEALIGN_COPY_UINT32(&count, rep+c, &c);

    SAFEALIGN_COPY_UINT32(&reserved, rep+c, &c);
    if (reserved != 0) {
        ret = EINVAL;
        goto done;
    }

    if (count > 0) {
        result = talloc_zero_array(tmp_ctx, struct sss_ssh_pubkey, count);
        if (!result) {
            ret = ENOMEM;
            goto done;
        }
    }

    for (i = 0; i < count; i++) {
        if (rep_len-c < 2*sizeof(uint32_t)) {
            ret = EINVAL;
            goto done;
        }

        SAFEALIGN_COPY_UINT32(&result[i].flags, rep+c, &c);
        if (result[i].flags != 0) {
            ret = EINVAL;
            goto done;
        }

        SAFEALIGN_COPY_UINT32(&len, rep+c, &c);

        if (rep_len-c < len + sizeof(uint32_t)) {
            ret = EINVAL;
            goto done;
        }

        result[i].name = talloc_array(result, char, len);
        if (!result[i].name) {
            ret = ENOMEM;
            goto done;
        }

        safealign_memcpy(result[i].name, rep+c, len, &c);
        if (strnlen(result[i].name, len) != len-1) {
            ret = EINVAL;
            goto done;
        }

        SAFEALIGN_COPY_UINT32(&len, rep+c, &c);

        if (rep_len-c < len) {
            ret = EINVAL;
            goto done;
        }

        result[i].key = talloc_array(result, uint8_t, len);
        if (!result[i].key) {
            ret = ENOMEM;
            goto done;
        }

        safealign_memcpy(result[i].key, rep+c, len, &c);
        result[i].key_len = len;
    }

    *pubkeys = result ? talloc_steal(mem_ctx, result) : NULL;
    *pubkeys_len = count;

done:
    talloc_free(tmp_ctx);

    return ret;
}

char *
sss_ssh_get_pubkey_algorithm(TALLOC_CTX *mem_ctx,
                             struct sss_ssh_pubkey *pubkey)
{
    size_t c = 0;
    uint32_t algo_len;
    char *algo;

    SAFEALIGN_COPY_UINT32(&algo_len, pubkey->key, &c);
    algo_len = ntohl(algo_len);

    algo = talloc_zero_array(mem_ctx, char, algo_len+1);
    if (!algo) {
        return NULL;
    }

    memcpy(algo, pubkey->key+c, algo_len);

    return algo;
}

errno_t
sss_ssh_format_pubkey(TALLOC_CTX *mem_ctx,
                      struct sss_ssh_pubkey *pubkey,
                      enum sss_ssh_pubkey_format format,
                      char **result)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret = EOK;
    char *pk;
    char *algo;
    char *out;

    if (!pubkey) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    pk = sss_base64_encode(tmp_ctx, pubkey->key, pubkey->key_len);
    if (!pk) {
        ret = ENOMEM;
        goto done;
    }

    switch (format) {
    case SSS_SSH_FORMAT_RAW:
        /* base64-encoded key blob */

        out = talloc_steal(mem_ctx, pk);

        break;

    case SSS_SSH_FORMAT_OPENSSH:
        /* OpenSSH authorized_keys/known_hosts format */

        algo = sss_ssh_get_pubkey_algorithm(tmp_ctx, pubkey);
        if (!algo) {
            ret = ENOMEM;
            goto done;
        }

        out = talloc_asprintf(tmp_ctx, "%s %s %s",
                              algo, pk, pubkey->name);
        if (!out) {
            ret = ENOMEM;
            goto done;
        }

        talloc_steal(mem_ctx, out);

        break;
    }

    *result = out;

done:
    talloc_free(tmp_ctx);

    return ret;
}
