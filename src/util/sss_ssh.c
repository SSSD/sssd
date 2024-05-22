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

#include <arpa/inet.h>

#include "db/sysdb.h"
#include "util/util.h"
#include "util/crypto/sss_crypto.h"
#include "util/sss_ssh.h"

errno_t
sss_ssh_make_ent(TALLOC_CTX *mem_ctx,
                 struct ldb_message *msg,
                 struct sss_ssh_ent **result)
{
    TALLOC_CTX *tmp_ctx;
    struct sss_ssh_ent *res = NULL;
    errno_t ret;
    const char *name;
    struct ldb_message_element *el;
    unsigned int i;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
    if (!name) {
        ret = EINVAL;
        DEBUG(SSSDBG_CRIT_FAILURE, "Host is missing name attribute\n");
        goto done;
    }

    res = talloc_zero(tmp_ctx, struct sss_ssh_ent);
    if (!res) {
        ret = ENOMEM;
        goto done;
    }

    res->name = talloc_strdup(res, name);
    if (!res->name) {
        ret = ENOMEM;
        goto done;
    }

    el = ldb_msg_find_element(msg, SYSDB_SSH_PUBKEY);
    if (el) {
        res->num_pubkeys = el->num_values;

        res->pubkeys = talloc_array(res, struct sss_ssh_pubkey,
                                    res->num_pubkeys);
        if (!res->pubkeys) {
            ret = ENOMEM;
            goto done;
        }

        for (i = 0; i < el->num_values; i++) {
            res->pubkeys[i].data = sss_base64_decode(res->pubkeys,
                    (char *)el->values[i].data, &res->pubkeys[i].data_len);
            if (!res->pubkeys[i].data) {
                ret = ENOMEM;
                goto done;
            }
        }
    }

    el = ldb_msg_find_element(msg, SYSDB_NAME_ALIAS);
    if (el) {
        res->num_aliases = el->num_values;

        res->aliases = talloc_array(res, char *, res->num_aliases);
        if (!res->aliases) {
            ret = ENOMEM;
            goto done;
        }

        for (i = 0; i < el->num_values; i++) {
            res->aliases[i] = talloc_strdup(res->aliases,
                                            (char *)el->values[i].data);
            if (!res->aliases[i]) {
                ret = ENOMEM;
                goto done;
            }
        }
    }

    *result = talloc_steal(mem_ctx, res);
    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t
sss_ssh_get_pubkey_algorithm(TALLOC_CTX *mem_ctx,
                             struct sss_ssh_pubkey *pubkey,
                             char **result)
{
    size_t c = 0;
    uint32_t algo_len;
    char *algo;

    if (pubkey->data_len < 5) {
        return EINVAL;
    }

    SAFEALIGN_COPY_UINT32(&algo_len, pubkey->data, &c);
    algo_len = ntohl(algo_len);
    if (algo_len < 1 || algo_len > 64 || algo_len > pubkey->data_len - 4) {
        /* the maximum length of 64 is defined in RFC 4250 */
        return EINVAL;
    }

    algo = talloc_zero_array(mem_ctx, char, algo_len+1);
    if (!algo) {
        return ENOMEM;
    }

    memcpy(algo, pubkey->data+c, algo_len);

    *result = algo;
    return EOK;
}

errno_t
sss_ssh_format_pubkey(TALLOC_CTX *mem_ctx,
                      struct sss_ssh_pubkey *pubkey,
                      char **result)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    char *blob;
    char *algo;
    char *out = NULL;
    size_t i, len;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    if (pubkey->data_len > 4 && memcmp(pubkey->data, "\0\0\0", 3) == 0) {
        /* All valid public key blobs start with 3 null bytes (see RFC 4253
         * section 6.6, RFC 4251 section 5 and RFC 4250 section 4.6)
         */
        blob = sss_base64_encode(tmp_ctx, pubkey->data, pubkey->data_len);
        if (!blob) {
            ret = ENOMEM;
            goto done;
        }

        ret = sss_ssh_get_pubkey_algorithm(tmp_ctx, pubkey, &algo);
        if (ret != EOK) {
            goto done;
        }

        out = talloc_asprintf(mem_ctx, "%s %s", algo, blob);
        if (!out) {
            ret = ENOMEM;
            goto done;
        }
    } else {
        /* Not a valid public key blob, so this must be a textual public key */
        for (i = 0; i < pubkey->data_len; i++) {
            if (pubkey->data[i] == '\0' ||
                (pubkey->data[i] == '\n' && i != pubkey->data_len - 1) ||
                pubkey->data[i] == '\r') {
                ret = EINVAL;
                goto done;
            }
        }

        len = pubkey->data_len;
        if (len == 0) {
            ret = EINVAL;
            goto done;
        }
        if (pubkey->data[len - 1] == '\n') {
            len--;
        }

        out = talloc_array(mem_ctx, char, len + 1);
        if (out == NULL) {
            ret = ENOMEM;
            goto done;
        }

        memcpy(out, pubkey->data, len);
        out[len] = '\0';
    }

    *result = out;
    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
sss_ssh_print_pubkey(struct sss_ssh_pubkey *pubkey, const char *keyhost)
{
    TALLOC_CTX *tmp_ctx;
    char *repr = NULL;
    char *repr_break = NULL;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sss_ssh_format_pubkey(tmp_ctx, pubkey, &repr);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sss_ssh_format_pubkey() failed (%d): %s\n",
              ret, strerror(ret));
        sss_log(SSS_LOG_ERR, "SSH key is malformed: %s\n", strerror(ret));
        goto end;
    }

    /* OpenSSH expects a linebreak after each key */
    if (keyhost == NULL) {
        repr_break = talloc_asprintf(tmp_ctx, "%s\n", repr);
    } else {
        repr_break = talloc_asprintf(tmp_ctx, "%s %s\n", keyhost, repr);
    }
    talloc_zfree(repr);
    if (repr_break == NULL) {
        ret = ENOMEM;
        goto end;
    }

    ret = sss_atomic_write_s(STDOUT_FILENO, repr_break, strlen(repr_break));
    /* Avoid spiking memory with too many large keys */
    talloc_zfree(repr_break);
    if (ret < 0) {
        ret = errno;
        if (ret == EPIPE) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "SSHD closed the pipe before all keys could be written\n");
            /* Return 0 so that openssh doesn't abort pubkey auth */
            ret = 0;
            goto end;
        }
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sss_atomic_write_s() failed (%d): %s\n",
              ret, strerror(ret));
        goto end;
    }

    ret = EOK;

 end:
    talloc_zfree(tmp_ctx);

    return ret;
}
