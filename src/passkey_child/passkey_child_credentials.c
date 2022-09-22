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

#include "util/crypto/sss_crypto.h"
#include "util/debug.h"
#include "util/util.h"

#include "passkey_child.h"

errno_t
prepare_credentials(struct passkey_data *data, fido_dev_t *dev,
                    fido_cred_t *cred)
{
    unsigned char userid[32];
    unsigned char cdh[32];
    bool has_pin;
    bool has_uv;
    errno_t ret = EOK;

    ret = fido_cred_set_type(cred, data->type);
    if (ret != FIDO_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "fido_cred_set_type failed [%d]: %s.\n",
              ret, fido_strerr(ret));
        goto done;
    }

    ret = sss_generate_csprng_buffer(cdh, sizeof(cdh));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sss_generate_csprng_buffer failed [%d]: %s.\n",
              ret, fido_strerr(ret));
        goto done;
    }

    ret = fido_cred_set_clientdata_hash(cred, cdh, sizeof(cdh));
    if (ret != FIDO_OK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "fido_cred_set_clientdata_hash failed [%d]: %s.\n",
              ret, fido_strerr(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Setting Relying Party ID and name to %s.\n",
          data->domain);

    ret = fido_cred_set_rp(cred, data->domain, data->domain);
    if (ret != FIDO_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "fido_cred_set_rp failed [%d]: %s.\n",
              ret, fido_strerr(ret));
        goto done;
    }

    ret = sss_generate_csprng_buffer(userid, sizeof(userid));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sss_generate_csprng_buffer failed [%d]: %s.\n",
              ret, fido_strerr(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Setting user: %s.\n", data->shortname);

    ret = fido_cred_set_user(cred, userid, sizeof(userid), data->shortname,
                             NULL, NULL);
    if (ret != FIDO_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "fido_cred_set_user failed [%d]: %s.\n",
              ret, fido_strerr(ret));
        goto done;
    }

    /* Set to FIDO_OPT_OMIT instead of FIDO_OPT_FALSE for compatibility reasons
     */
    ret = fido_cred_set_rk(cred, FIDO_OPT_OMIT);
    if (ret != FIDO_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "fido_cred_set_rk failed [%d]: %s.\n",
              ret, fido_strerr(ret));
        goto done;
    }

    has_uv = fido_dev_has_uv(dev);
    has_pin = fido_dev_has_pin(dev);
    if (data->user_verification == FIDO_OPT_TRUE && has_uv == false
        && has_pin == false) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Policy enabled user-verification but there isn't any "
              "verification method set.\n");
        ret = EINVAL;
        goto done;
    }

    if (data->user_verification == FIDO_OPT_FALSE
        && (has_uv == true || has_pin == true)) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Policy disabled user-verification but the key settings are "
              "enforcing it. Thus, enabling user-verification.\n");
        data->user_verification = FIDO_OPT_TRUE;
    }

    if (has_uv == true) {
        ret = fido_cred_set_uv(cred, FIDO_OPT_TRUE);
        if (ret != FIDO_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "fido_cred_set_uv failed [%d]: %s.\n",
                  ret, fido_strerr(ret));
            goto done;
        }
    }

done:
    return ret;
}

ssize_t
read_pin(char **pin)
{
    char *line_ptr = NULL;
    struct termios old, new;
    size_t line_len = 0;
    ssize_t bytes_read;
    ssize_t ret;

    ret = tcgetattr(STDIN_FILENO, &old);
    if (ret != 0) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable get the parameters associated with stdin.\n");
        goto done;
    }
    new = old;
    new.c_lflag &= ~ECHO;
    ret = tcsetattr(STDIN_FILENO, TCSAFLUSH, &new);
    if (ret != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to turn echoing off.\n");
        goto done;
    }

    ERROR("Enter PIN: ");
    bytes_read = getline(&line_ptr, &line_len, stdin);
    if (bytes_read == -1) {
        DEBUG(SSSDBG_OP_FAILURE, "getline failed [%d]: %s.\n",
              errno, sss_strerror(errno));
    } else {
        /* Remove the end of line '\n' character */
        line_ptr[--bytes_read] = '\0';
    }
    ERROR("\n");

    ret = tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
    if (ret != 0) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to restore parameters associated with stdin.\n");
        goto done;
    }

    ret = bytes_read;
    *pin = line_ptr;

done:
    return ret;
}

errno_t
generate_credentials(struct passkey_data *data, fido_dev_t *dev,
                     fido_cred_t *cred)
{
    char *pin = NULL;
    bool has_pin;
    ssize_t pin_len = 0;
    errno_t ret;

    has_pin = fido_dev_has_pin(dev);
    if (has_pin == true) {
        pin_len = read_pin(&pin);
        if (pin_len == -1) {
            ret = ERR_INPUT_PARSE;
            goto done;
        }
    }

    ERROR("Please touch the device.\n");
    ret = fido_dev_make_cred(dev, cred, pin);
    sss_erase_mem_securely(pin, pin_len);
    if (pin != NULL) {
        free(pin);
    }

    if (ret != FIDO_OK) {
        if (ret == FIDO_ERR_PIN_INVALID) {
            ERROR("Invalid PIN.\n");
        }
        DEBUG(SSSDBG_OP_FAILURE, "fido_dev_make_cred failed [%d]: %s.\n",
              ret, fido_strerr(ret));
        goto done;
    }

    if (has_pin == true) {
        ret = fido_cred_set_uv(cred, FIDO_OPT_TRUE);
        if (ret != FIDO_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "fido_cred_set_uv failed [%d]: %s.\n",
                  ret, fido_strerr(ret));
            goto done;
        }
    }

done:
    return ret;
}

errno_t
verify_credentials(const fido_cred_t *const cred)
{
    errno_t ret;

    if (fido_cred_x5c_ptr(cred) != NULL) {
        ret = fido_cred_verify(cred);
        if (ret != FIDO_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "fido_cred_verify failed [%d]: %s.\n",
                  ret, fido_strerr(ret));
            goto done;
        }
    } else {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Attestation certificate missing. "
              "Falling back to self attestation.\n");
        ret = fido_cred_verify_self(cred);
        if (ret != FIDO_OK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "fido_cred_verify_self failed [%d]: %s.\n",
                  ret, fido_strerr(ret));
            goto done;
        }
    }

done:
    return ret;
}

errno_t
print_credentials(const struct passkey_data *data, const fido_cred_t *const cred)
{
    TALLOC_CTX *tmp_ctx = NULL;
    const unsigned char *cred_id = NULL;
    const unsigned char *public_key = NULL;
    const char *b64_cred_id = NULL;
    const char *b64_public_key = NULL;
    size_t cred_id_len;
    size_t user_key_len;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    cred_id = fido_cred_id_ptr(cred);
    if (cred_id == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "fido_cred_id_ptr failed.\n");
        ret = ERR_CREDS_INVALID;
        goto done;
    }

    cred_id_len = fido_cred_id_len(cred);
    if (cred_id_len == 0) {
        DEBUG(SSSDBG_OP_FAILURE, "fido_cred_id_len returned 0.\n");
        ret = ERR_CREDS_INVALID;
        goto done;
    }

    b64_cred_id = sss_base64_encode(tmp_ctx, cred_id, cred_id_len);
    if (b64_cred_id == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "failed to encode key handle.\n");
        ret = ENOMEM;
        goto done;
    }

    public_key = fido_cred_pubkey_ptr(cred);
    if (public_key == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "fido_cred_pubkey_ptr failed.\n");
        ret = ERR_CREDS_INVALID;
        goto done;
    }

    user_key_len = fido_cred_pubkey_len(cred);
    if (user_key_len == 0) {
        DEBUG(SSSDBG_OP_FAILURE, "fido_cred_pubkey_len returned 0.\n");
        ret = ERR_CREDS_INVALID;
        goto done;
    }

    b64_public_key = sss_base64_encode(tmp_ctx, public_key, user_key_len);
    if (b64_public_key == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "failed to encode public key.\n");
        ret = ENOMEM;
        goto done;
    }

    printf("passkey:%s,%s\n", b64_cred_id, b64_public_key);
    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}
