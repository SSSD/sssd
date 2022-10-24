/*
   SSSD - digest functions - OpenSSL version
   The calls defined here should be usable outside of SSSD as well, e.g. in
   libsss_certmap.

   Copyright (C) Sumit Bose <sbose@redhat.com> 2022

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

#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <talloc.h>
#include <openssl/opensslv.h>
#include <openssl/objects.h>
#include <openssl/evp.h>

#include "lib/certmap/sss_certmap_int.h"

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))
#define EVP_MD_free(ctx)
#define EVP_MD_fetch(ctx, algorithm, properties) discard_const(EVP_get_digestbyname(algorithm))
#endif

#define DATA_STEP_SIZE 30

struct get_digest_data {
    const char **list;
    size_t size;
    size_t idx;
    int error;
};

static void get_digest_helper(const OBJ_NAME *name, void *arg)
{
    struct get_digest_data *data = (struct get_digest_data *) arg;
    EVP_MD *md = NULL;

    if (data->error != 0) {
        return;
    }

    /* All digest names are expected to start with a lower case letter. For
     * compatibility(?) with older version the digest list might contain some
     * RSA based signature algorithms, e.g. RSA-SHA1, which should be ignored
     * here. */
    if (name == NULL || name->name == NULL || islower(*name->name) == 0
        || strstr(name->name, "RSA") != NULL
        || strstr(name->name, "rsa") != NULL) {
        return;
    }

    /* check if digest can be fetched. */
    md = EVP_MD_fetch(NULL, name->name, NULL);
    if (md == NULL) {
        return;
    }
    EVP_MD_free(md);

    data->list[data->idx] = talloc_strdup(data->list, name->name);
    if (data->list[data->idx] == NULL) {
        data->error = ENOMEM;
        return;
    }

    data->idx++;
    if (data->idx == data->size - 1) {
        data->size += DATA_STEP_SIZE;
        data->list = talloc_realloc(data->list, data->list,
                                    const char *, data->size);
        if (data->list == NULL) {
            data->error = ENOMEM;
            return;
        }
    }
    data->list[data->idx] = NULL;
}


int get_digest_list(TALLOC_CTX *mem_ctx, const char ***digest_list)
{
    struct get_digest_data data = { 0 };

    data.size = DATA_STEP_SIZE;
    data.list = talloc_array(mem_ctx, const char *, data.size);
    if (data.list == NULL) {
        return ENOMEM;
    }

    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS \
                        | OPENSSL_INIT_ADD_ALL_DIGESTS \
                        | OPENSSL_INIT_LOAD_CONFIG, NULL);

    OBJ_NAME_do_all(OBJ_NAME_TYPE_MD_METH, get_digest_helper, &data);
    if (data.error != 0) {
        talloc_free(data.list);
        return data.error;
    }

    *digest_list = data.list;

    return 0;
}

int get_hash(TALLOC_CTX *mem_ctx, const uint8_t *blob, size_t blob_size,
             const char *digest, bool upper, bool colon, bool reverse,
             char **out)
{
    int ret;
    EVP_MD *md = NULL;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    char *tmp_str = NULL;

    md = EVP_MD_fetch(NULL, digest, NULL);
    if (md == NULL) {
        return EINVAL;
    }

    ret = EVP_Digest(blob, blob_size, md_value, &md_len, md, NULL);
    if (ret != 1) {
        ret = EIO;
        goto done;
    }

    ret = bin_to_hex(mem_ctx, upper, colon, reverse, md_value, md_len,
                     &tmp_str);
    if (ret != 0) {
        goto done;
    }

    *out = tmp_str;
    ret = 0;

done:
    if (ret != 0) {
        talloc_free(tmp_str);
    }
    EVP_MD_free(md);

    return ret;
}
