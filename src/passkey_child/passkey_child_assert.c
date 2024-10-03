/*
    SSSD

    Helper child to commmunicate with passkey devices

    Authors:
        Iker Pedrosa <ipedrosa@redhat.com>

    Copyright (C) 2022 Red Hat

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

#include <jansson.h>
#include <termios.h>
#include <stdio.h>
#include <fido/es256.h>
#include <fido/rs256.h>
#include <fido/eddsa.h>

#include "util/crypto/sss_crypto.h"
#include "util/debug.h"
#include "util/util.h"

#include "passkey_child.h"

errno_t
set_assert_client_data_hash(const struct passkey_data *data,
                            fido_assert_t *_assert)
{
    TALLOC_CTX *tmp_ctx = NULL;
    unsigned char cdh[32];
    unsigned char *crypto_challenge = NULL;
    size_t crypto_challenge_len;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new() failed.\n");
        return ENOMEM;
    }

    if (data->action == ACTION_AUTHENTICATE
        || data->action == ACTION_PREFLIGHT) {
        ret = sss_generate_csprng_buffer(cdh, sizeof(cdh));
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sss_generate_csprng_buffer failed [%d]: %s.\n",
                  ret, fido_strerr(ret));
            goto done;
        }

        ret = fido_assert_set_clientdata_hash(_assert, cdh, sizeof(cdh));
        if (ret != FIDO_OK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "fido_assert_set_clientdata_hash failed [%d]: %s.\n",
                  ret, fido_strerr(ret));
            goto done;
        }
    } else {
        crypto_challenge = sss_base64_decode(tmp_ctx, data->crypto_challenge,
                                             &crypto_challenge_len);
        if (crypto_challenge == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "failed to decode client data hash.\n");
            ret = ENOMEM;
            goto done;
        }

        if (crypto_challenge_len != 32) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "cryptographic-challenge length [%ld] must be 32.\n",
                  crypto_challenge_len);
            ret = EINVAL;
            goto done;
        }

        ret = fido_assert_set_clientdata_hash(_assert, crypto_challenge,
                                              crypto_challenge_len);
        if (ret != FIDO_OK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "fido_assert_set_clientdata_hash failed [%d]: %s.\n",
                  ret, fido_strerr(ret));
            goto done;
        }
    }

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
set_assert_options(fido_opt_t up, fido_opt_t uv, fido_assert_t *_assert)
{
    errno_t ret;

    ret = fido_assert_set_up(_assert, up);
    if (ret != FIDO_OK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "fido_assert_set_up failed [%d]: %s.\n",
              ret, fido_strerr(ret));
        goto done;
    }

    ret = fido_assert_set_uv(_assert, uv);
    if (ret != FIDO_OK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "fido_assert_set_uv failed [%d]: %s.\n",
              ret, fido_strerr(ret));
        goto done;
    }

done:
    return ret;
}

errno_t
get_assert_auth_data_signature(TALLOC_CTX *mem_ctx, fido_assert_t *assert,
                               const char **_auth_data,
                               const char **_signature)
{
    TALLOC_CTX *tmp_ctx = NULL;
    const unsigned char *auth_data;
    const unsigned char *signature;
    const char *b64_auth_data;
    const char *b64_signature;
    size_t auth_data_len;
    size_t signature_len;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new() failed.\n");
        return ENOMEM;
    }

    auth_data = fido_assert_authdata_ptr(assert, 0);
    if (auth_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "fido_assert_authdata_ptr failed.\n");
        ret = ENOMEM;
        goto done;
    }

    auth_data_len = fido_assert_authdata_len(assert, 0);
    if (auth_data_len == 0) {
        DEBUG(SSSDBG_OP_FAILURE,
              "fido_assert_authdata_len failed.\n");
        ret = ENOMEM;
        goto done;
    }

    b64_auth_data = sss_base64_encode(tmp_ctx, auth_data, auth_data_len);
    if (b64_auth_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "failed to encode authenticator data.\n");
        ret = ENOMEM;
        goto done;
    }

    signature = fido_assert_sig_ptr(assert, 0);
    if (signature == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "fido_assert_sig_ptr failed.\n");
        ret = ENOMEM;
        goto done;
    }

    signature_len = fido_assert_sig_len(assert, 0);
    if (signature_len == 0) {
        DEBUG(SSSDBG_OP_FAILURE,
              "fido_assert_sig_len failed.\n");
        ret = ENOMEM;
        goto done;
    }

    b64_signature = sss_base64_encode(tmp_ctx, signature, signature_len);
    if (b64_signature == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "failed to encode signature.\n");
        ret = ENOMEM;
        goto done;
    }

    *_auth_data = talloc_steal(mem_ctx, b64_auth_data);
    *_signature = talloc_steal(mem_ctx, b64_signature);
    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
set_assert_auth_data_signature(const struct passkey_data *data,
                               fido_assert_t *_assert)
{
    TALLOC_CTX *tmp_ctx = NULL;
    const unsigned char *auth_data = NULL;
    const unsigned char *signature = NULL;
    size_t auth_data_len;
    size_t signature_len;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = fido_assert_set_count(_assert, 1);
    if (ret != FIDO_OK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "fido_assert_set_count failed [%d]: %s.\n",
              ret, fido_strerr(ret));
        goto done;
    }

    auth_data = sss_base64_decode(tmp_ctx, data->auth_data, &auth_data_len);
    if (auth_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "failed to decode authenticator data.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = fido_assert_set_authdata(_assert, 0, auth_data, auth_data_len);
    if (ret != FIDO_OK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "fido_assert_set_authdata failed [%d]: %s.\n",
              ret, fido_strerr(ret));
        goto done;
    }

    signature = sss_base64_decode(tmp_ctx, data->signature, &signature_len);
    if (signature == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "failed to decode signature.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = fido_assert_set_sig(_assert, 0, signature, signature_len);
    if (ret != FIDO_OK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "fido_assert_set_sig failed [%d]: %s.\n",
              ret, fido_strerr(ret));
        goto done;
    }

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
prepare_assert(const struct passkey_data *data, int index,
               fido_assert_t *_assert)
{
    TALLOC_CTX *tmp_ctx = NULL;
    unsigned char *key_handle;
    size_t key_handle_len;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = fido_assert_set_rp(_assert, data->domain);
    if (ret != FIDO_OK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "fido_assert_set_rp failed [%d]: %s.\n", ret, fido_strerr(ret));
        goto done;
    }

    key_handle = sss_base64_decode(tmp_ctx, data->key_handle_list[index],
                                   &key_handle_len);
    if (key_handle == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to decode key handle.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = fido_assert_allow_cred(_assert, key_handle, key_handle_len);
    if (ret != FIDO_OK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "fido_assert_allow_cred failed [%d]: %s.\n", ret, fido_strerr(ret));
        goto done;
    }

    ret = set_assert_options(FIDO_OPT_FALSE, FIDO_OPT_OMIT, _assert);
    if (ret != FIDO_OK) {
        goto done;
    }

    ret = set_assert_client_data_hash(data, _assert);
    if (ret != EOK) {
        goto done;
    }

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
reset_public_key(struct pk_data_t *_pk_data)
{
    if (_pk_data->type == COSE_ES256) {
        es256_pk_free((es256_pk_t **) &_pk_data->public_key);
    } else if (_pk_data->type == COSE_RS256) {
        rs256_pk_free((rs256_pk_t **) &_pk_data->public_key);
    } else if (_pk_data->type == COSE_EDDSA) {
        eddsa_pk_free((eddsa_pk_t **) &_pk_data->public_key);
    }

    return EOK;
}

errno_t
request_assert(struct passkey_data *data, fido_dev_t *dev,
               fido_assert_t *_assert)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *pin = NULL;
    bool has_pin;
    bool has_uv;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new() failed.\n");
        return ENOMEM;
    }

    has_pin = fido_dev_has_pin(dev);
    has_uv = fido_dev_has_uv(dev);
    if (has_uv == true && data->user_verification != FIDO_OPT_FALSE) {
        ret = fido_dev_get_assert(dev, _assert, NULL);
        if (ret != FIDO_OK && has_pin == true) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "fido_dev_get_assert failed [%d]: %s. "
                  "Falling back to PIN authentication.\n",
                  ret, fido_strerr(ret));
        } else if (ret != FIDO_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "fido_dev_get_assert failed [%d]: %s.\n",
                  ret, fido_strerr(ret));
            goto done;
        } else {
            DEBUG(SSSDBG_TRACE_FUNC, "fido_dev_get_assert succeeded.\n");
            goto done;
        }
    }

    if (has_pin == true && data->user_verification != FIDO_OPT_FALSE) {
        ret = passkey_recv_pin(tmp_ctx, STDIN_FILENO, &pin);
        if (ret != EOK) {
            goto done;
        }
    }

    ret = fido_dev_get_assert(dev, _assert, pin);
    if (ret != FIDO_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "fido_dev_get_assert failed [%d]: %s.\n",
              ret, fido_strerr(ret));
        goto done;
    }

    ret = fido_assert_set_uv(_assert, data->user_verification);
    if (ret != FIDO_OK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "fido_assert_set_uv failed [%d]: %s.\n",
              ret, fido_strerr(ret));
        goto done;
    }

done:
    if (pin != NULL) {
        sss_erase_mem_securely(pin, strlen(pin));
    }
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
verify_assert(struct pk_data_t *pk_data, fido_assert_t *assert)
{
    errno_t ret;

    ret = fido_assert_verify(assert, 0, pk_data->type, pk_data->public_key);
    if (ret != FIDO_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "fido_assert_verify failed [%d]: %s.\n",
              ret, fido_strerr(ret));
        goto done;
    }

done:
    return ret;
}

void
print_assert_data(const char *key_handle, const char *crypto_challenge,
                  const char *auth_data, const char *signature)
{
    json_t *passkey = NULL;
    char* string = NULL;

    /* Kerberos expects the user_id field, thus it cannot be removed and there
     * is nothing to set so it's an empty string.
     */
    passkey = json_pack("{s:s*, s:s*, s:s*, s:s*, s:s*}",
                        "credential_id", key_handle,
                        "cryptographic_challenge", crypto_challenge,
                        "authenticator_data", auth_data,
                        "assertion_signature", signature,
                        "user_id", "");
    if (passkey == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to create passkey object.\n");
        goto done;
    }

    string = json_dumps(passkey, 0);
    if (string == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "json_dumps() failed.\n");
        goto done;
    }

    puts(string);
    free(string);

done:
    json_decref(passkey);

    return;
}
