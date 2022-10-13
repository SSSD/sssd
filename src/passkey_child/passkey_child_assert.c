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
set_assert_client_data_hash(fido_assert_t *_assert)
{
    unsigned char cdh[32];
    errno_t ret;

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

done:
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

    ret = set_assert_client_data_hash(_assert);
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
