/*
   SSSD - auth utils

   Copyright (C) Simo Sorce <simo@redhat.com> 2012

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

#include "authtok.h"

struct sss_auth_token {
    enum sss_authtok_type type;
    uint8_t *data;
    size_t length;
};

const char *sss_authtok_type_to_str(enum sss_authtok_type type)
{
    switch (type) {
    case SSS_AUTHTOK_TYPE_EMPTY:
        return "No authentication token available";
    case SSS_AUTHTOK_TYPE_PASSWORD:
        return "Password";
    case SSS_AUTHTOK_TYPE_CCFILE:
        return "Path to a Kerberos credential cache file";
    case SSS_AUTHTOK_TYPE_2FA:
        return "Two factors";
    case SSS_AUTHTOK_TYPE_SC_PIN:
        return "Smart Card PIN";
    case SSS_AUTHTOK_TYPE_SC_KEYPAD:
        return "Smart Card PIN will be entered at the card reader";
    case SSS_AUTHTOK_TYPE_2FA_SINGLE:
        return "Two factors in a single string";
    case SSS_AUTHTOK_TYPE_OAUTH2:
        return "OAuth2";
    case SSS_AUTHTOK_TYPE_PASSKEY:
        return "Passkey";
    case SSS_AUTHTOK_TYPE_PASSKEY_KRB:
        return "Passkey kerberos";
    case SSS_AUTHTOK_TYPE_PASSKEY_REPLY:
        return "Passkey kerberos reply";
    case SSS_AUTHTOK_TYPE_PAM_STACKED:
        return "PAM stacked password";
    }

    DEBUG(SSSDBG_MINOR_FAILURE, "Unknown authtok type %d\n", type);
    return "-unknown-";
}

enum sss_authtok_type sss_authtok_get_type(struct sss_auth_token *tok)
{
    return tok->type;
}

size_t sss_authtok_get_size(struct sss_auth_token *tok)
{
    if (!tok) {
        return 0;
    }
    switch (tok->type) {
    case SSS_AUTHTOK_TYPE_PASSWORD:
    case SSS_AUTHTOK_TYPE_CCFILE:
    case SSS_AUTHTOK_TYPE_2FA:
    case SSS_AUTHTOK_TYPE_SC_PIN:
    case SSS_AUTHTOK_TYPE_SC_KEYPAD:
    case SSS_AUTHTOK_TYPE_2FA_SINGLE:
    case SSS_AUTHTOK_TYPE_OAUTH2:
    case SSS_AUTHTOK_TYPE_PASSKEY:
    case SSS_AUTHTOK_TYPE_PASSKEY_KRB:
    case SSS_AUTHTOK_TYPE_PASSKEY_REPLY:
    case SSS_AUTHTOK_TYPE_PAM_STACKED:
        return tok->length;
    case SSS_AUTHTOK_TYPE_EMPTY:
        return 0;
    }

    return EINVAL;
}

uint8_t *sss_authtok_get_data(struct sss_auth_token *tok)
{
    if (!tok) {
        return NULL;
    }
    return tok->data;
}

errno_t sss_authtok_get_password(struct sss_auth_token *tok,
                                 const char **pwd, size_t *len)
{
    if (!tok) {
        return EFAULT;
    }
    switch (tok->type) {
    case SSS_AUTHTOK_TYPE_EMPTY:
        return ENOENT;
    case SSS_AUTHTOK_TYPE_PAM_STACKED:
    case SSS_AUTHTOK_TYPE_PASSWORD:
        *pwd = (const char *)tok->data;
        if (len) {
            *len = tok->length - 1;
        }
        return EOK;
    case SSS_AUTHTOK_TYPE_CCFILE:
    case SSS_AUTHTOK_TYPE_2FA:
    case SSS_AUTHTOK_TYPE_SC_PIN:
    case SSS_AUTHTOK_TYPE_SC_KEYPAD:
    case SSS_AUTHTOK_TYPE_2FA_SINGLE:
    case SSS_AUTHTOK_TYPE_OAUTH2:
    case SSS_AUTHTOK_TYPE_PASSKEY:
    case SSS_AUTHTOK_TYPE_PASSKEY_KRB:
    case SSS_AUTHTOK_TYPE_PASSKEY_REPLY:
        return EACCES;
    }

    return EINVAL;
}

errno_t sss_authtok_get_ccfile(struct sss_auth_token *tok,
                               const char **ccfile, size_t *len)
{
    if (!tok) {
        return EINVAL;
    }
    switch (tok->type) {
    case SSS_AUTHTOK_TYPE_EMPTY:
        return ENOENT;
    case SSS_AUTHTOK_TYPE_CCFILE:
        *ccfile = (const char *)tok->data;
        if (len) {
            *len = tok->length - 1;
        }
        return EOK;
    case SSS_AUTHTOK_TYPE_PASSWORD:
    case SSS_AUTHTOK_TYPE_2FA:
    case SSS_AUTHTOK_TYPE_SC_PIN:
    case SSS_AUTHTOK_TYPE_SC_KEYPAD:
    case SSS_AUTHTOK_TYPE_2FA_SINGLE:
    case SSS_AUTHTOK_TYPE_OAUTH2:
    case SSS_AUTHTOK_TYPE_PASSKEY:
    case SSS_AUTHTOK_TYPE_PASSKEY_KRB:
    case SSS_AUTHTOK_TYPE_PASSKEY_REPLY:
    case SSS_AUTHTOK_TYPE_PAM_STACKED:
        return EACCES;
    }

    return EINVAL;
}

errno_t sss_authtok_get_2fa_single(struct sss_auth_token *tok,
                                   const char **str, size_t *len)
{
    if (!tok) {
        return EINVAL;
    }
    switch (tok->type) {
    case SSS_AUTHTOK_TYPE_EMPTY:
        return ENOENT;
    case SSS_AUTHTOK_TYPE_PAM_STACKED:
    case SSS_AUTHTOK_TYPE_2FA_SINGLE:
        *str = (const char *)tok->data;
        if (len) {
            *len = tok->length - 1;
        }
        return EOK;
    case SSS_AUTHTOK_TYPE_PASSWORD:
    case SSS_AUTHTOK_TYPE_2FA:
    case SSS_AUTHTOK_TYPE_SC_PIN:
    case SSS_AUTHTOK_TYPE_SC_KEYPAD:
    case SSS_AUTHTOK_TYPE_CCFILE:
    case SSS_AUTHTOK_TYPE_OAUTH2:
    case SSS_AUTHTOK_TYPE_PASSKEY:
    case SSS_AUTHTOK_TYPE_PASSKEY_KRB:
    case SSS_AUTHTOK_TYPE_PASSKEY_REPLY:
        return EACCES;
    }

    return EINVAL;
}

errno_t sss_authtok_get_oauth2(struct sss_auth_token *tok,
                               const char **str, size_t *len)
{
    if (!tok) {
        return EINVAL;
    }
    switch (tok->type) {
    case SSS_AUTHTOK_TYPE_EMPTY:
        return ENOENT;
    case SSS_AUTHTOK_TYPE_OAUTH2:
        *str = (const char *)tok->data;
        if (len) {
            *len = tok->length - 1;
        }
        return EOK;
    case SSS_AUTHTOK_TYPE_PASSWORD:
    case SSS_AUTHTOK_TYPE_2FA:
    case SSS_AUTHTOK_TYPE_SC_PIN:
    case SSS_AUTHTOK_TYPE_SC_KEYPAD:
    case SSS_AUTHTOK_TYPE_CCFILE:
    case SSS_AUTHTOK_TYPE_2FA_SINGLE:
    case SSS_AUTHTOK_TYPE_PASSKEY:
    case SSS_AUTHTOK_TYPE_PASSKEY_KRB:
    case SSS_AUTHTOK_TYPE_PASSKEY_REPLY:
    case SSS_AUTHTOK_TYPE_PAM_STACKED:
        return EACCES;
    }

    return EINVAL;
}

errno_t sss_authtok_get_passkey_reply(struct sss_auth_token *tok,
                                      const char **str, size_t *len)
{
    if (!tok) {
        return EINVAL;
    }
    switch (tok->type) {
    case SSS_AUTHTOK_TYPE_EMPTY:
        return ENOENT;
    case SSS_AUTHTOK_TYPE_PASSKEY_REPLY:
        *str = (const char *)tok->data;
        if (len) {
            *len = tok->length - 1;
        }
        return EOK;
    case SSS_AUTHTOK_TYPE_PASSWORD:
    case SSS_AUTHTOK_TYPE_2FA:
    case SSS_AUTHTOK_TYPE_SC_PIN:
    case SSS_AUTHTOK_TYPE_SC_KEYPAD:
    case SSS_AUTHTOK_TYPE_CCFILE:
    case SSS_AUTHTOK_TYPE_2FA_SINGLE:
    case SSS_AUTHTOK_TYPE_OAUTH2:
    case SSS_AUTHTOK_TYPE_PASSKEY:
    case SSS_AUTHTOK_TYPE_PASSKEY_KRB:
    case SSS_AUTHTOK_TYPE_PAM_STACKED:
        return EACCES;
    }

    return EINVAL;
}

errno_t sss_authtok_get_passkey_pin(struct sss_auth_token *tok,
                                    const char **_pin, size_t *_len)
{
    int ret;
    const char *pin = NULL;
    const char *key = NULL;
    const char *prompt = NULL;
    size_t pin_len = 0;

    if (!tok) {
        return EINVAL;
    }
    switch (tok->type) {
    case SSS_AUTHTOK_TYPE_EMPTY:
        return ENOENT;
    case SSS_AUTHTOK_TYPE_PASSKEY:
        *_pin = (const char *)tok->data;
        if (_len) {
            *_len = tok->length - 1;
        }
        return EOK;
    case SSS_AUTHTOK_TYPE_PASSKEY_KRB:
        ret = sss_authtok_get_passkey(NULL, tok, &prompt, &key, &pin, &pin_len);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sss_authtok_get_passkey failed.\n");
            return ret;
        }

        *_pin = pin;
        *_len = pin_len;

        return EOK;
    case SSS_AUTHTOK_TYPE_PASSWORD:
    case SSS_AUTHTOK_TYPE_2FA:
    case SSS_AUTHTOK_TYPE_SC_PIN:
    case SSS_AUTHTOK_TYPE_SC_KEYPAD:
    case SSS_AUTHTOK_TYPE_CCFILE:
    case SSS_AUTHTOK_TYPE_2FA_SINGLE:
    case SSS_AUTHTOK_TYPE_OAUTH2:
    case SSS_AUTHTOK_TYPE_PASSKEY_REPLY:
    case SSS_AUTHTOK_TYPE_PAM_STACKED:
        return EACCES;
    }

    return EINVAL;
}
static errno_t sss_authtok_set_string(struct sss_auth_token *tok,
                                      enum sss_authtok_type type,
                                      const char *context_name,
                                      const char *str, size_t len)
{
    size_t size;

    if (len == 0) {
        len = strlen(str);
    } else {
        while (len > 0 && str[len - 1] == '\0') len--;
    }

    if (len == 0) {
        /* we do not allow zero length typed tokens */
        return EINVAL;
    }

    size = len + 1;

    tok->data = talloc_named(tok, size, "%s", context_name);
    if (!tok->data) {
        return ENOMEM;
    }
    memcpy(tok->data, str, len);
    tok->data[len] = '\0';
    tok->type = type;
    tok->length = size;

    return EOK;

}

void sss_authtok_set_empty(struct sss_auth_token *tok)
{
    if (!tok) {
        return;
    }
    switch (tok->type) {
    case SSS_AUTHTOK_TYPE_EMPTY:
        return;
    case SSS_AUTHTOK_TYPE_PASSWORD:
    case SSS_AUTHTOK_TYPE_2FA:
    case SSS_AUTHTOK_TYPE_SC_PIN:
    case SSS_AUTHTOK_TYPE_2FA_SINGLE:
    case SSS_AUTHTOK_TYPE_PASSKEY:
    case SSS_AUTHTOK_TYPE_PASSKEY_KRB:
    case SSS_AUTHTOK_TYPE_PASSKEY_REPLY:
    case SSS_AUTHTOK_TYPE_OAUTH2:
    case SSS_AUTHTOK_TYPE_PAM_STACKED:
        sss_erase_mem_securely(tok->data, tok->length);
        break;
    case SSS_AUTHTOK_TYPE_CCFILE:
    case SSS_AUTHTOK_TYPE_SC_KEYPAD:
        break;
    }

    tok->type = SSS_AUTHTOK_TYPE_EMPTY;
    talloc_zfree(tok->data);
    tok->length = 0;
}

errno_t sss_authtok_set_password(struct sss_auth_token *tok,
                                 const char *password, size_t len)
{
    sss_authtok_set_empty(tok);

    return sss_authtok_set_string(tok, SSS_AUTHTOK_TYPE_PASSWORD,
                                  "password", password, len);
}

errno_t sss_authtok_set_ccfile(struct sss_auth_token *tok,
                               const char *ccfile, size_t len)
{
    sss_authtok_set_empty(tok);

    return sss_authtok_set_string(tok, SSS_AUTHTOK_TYPE_CCFILE,
                                  "ccfile", ccfile, len);
}

errno_t sss_authtok_set_2fa_single(struct sss_auth_token *tok,
                                   const char *str, size_t len)
{
    sss_authtok_set_empty(tok);

    return sss_authtok_set_string(tok, SSS_AUTHTOK_TYPE_2FA_SINGLE,
                                  "2fa_single", str, len);
}

errno_t sss_authtok_set_oauth2(struct sss_auth_token *tok,
                               const char *str, size_t len)
{
    sss_authtok_set_empty(tok);

    return sss_authtok_set_string(tok, SSS_AUTHTOK_TYPE_OAUTH2,
                                  "oauth2", str, len);
}

errno_t sss_authtok_set_passkey_reply(struct sss_auth_token *tok,
                                      const char *str, size_t len)
{
    sss_authtok_set_empty(tok);

    return sss_authtok_set_string(tok, SSS_AUTHTOK_TYPE_PASSKEY_REPLY,
                                  "passkey kerberos reply", str, len);
}

errno_t sss_authtok_set_passkey(struct sss_auth_token *tok,
                                const char *str, size_t len)
{
    sss_authtok_set_empty(tok);

    return sss_authtok_set_string(tok, SSS_AUTHTOK_TYPE_PASSKEY,
                                  "passkey", str, len);
}

errno_t sss_authtok_set_pam_stacked(struct sss_auth_token *tok,
                                    const char *str, size_t len)
{
    sss_authtok_set_empty(tok);

    return sss_authtok_set_string(tok, SSS_AUTHTOK_TYPE_PAM_STACKED,
                                  "pam stacked", str, len);
}

static errno_t sss_authtok_set_2fa_from_blob(struct sss_auth_token *tok,
                                             const uint8_t *data, size_t len);
static errno_t sss_authtok_set_passkey_from_blob(struct sss_auth_token *tok,
                                                 const uint8_t *data, size_t len);

errno_t sss_authtok_set(struct sss_auth_token *tok,
                        enum sss_authtok_type type,
                        const uint8_t *data, size_t len)
{
    switch (type) {
    case SSS_AUTHTOK_TYPE_PASSWORD:
        return sss_authtok_set_password(tok, (const char *)data, len);
    case SSS_AUTHTOK_TYPE_CCFILE:
        return sss_authtok_set_ccfile(tok, (const char *)data, len);
    case SSS_AUTHTOK_TYPE_2FA:
        return sss_authtok_set_2fa_from_blob(tok, data, len);
    case SSS_AUTHTOK_TYPE_SC_PIN:
        return sss_authtok_set_sc_from_blob(tok, data, len);
    case SSS_AUTHTOK_TYPE_SC_KEYPAD:
        return sss_authtok_set_sc_from_blob(tok, data, len);
    case SSS_AUTHTOK_TYPE_2FA_SINGLE:
        return sss_authtok_set_2fa_single(tok, (const char *) data, len);
    case SSS_AUTHTOK_TYPE_OAUTH2:
        return sss_authtok_set_oauth2(tok, (const char *) data, len);
    case SSS_AUTHTOK_TYPE_PASSKEY_KRB:
        return sss_authtok_set_passkey_from_blob(tok, data, len);
    case SSS_AUTHTOK_TYPE_PASSKEY:
        return sss_authtok_set_passkey(tok, (const char *) data, len);
    case SSS_AUTHTOK_TYPE_PASSKEY_REPLY:
        return sss_authtok_set_passkey_reply(tok, (const char *)data, len);
    case SSS_AUTHTOK_TYPE_PAM_STACKED:
        return sss_authtok_set_pam_stacked(tok, (const char *)data, len);
    case SSS_AUTHTOK_TYPE_EMPTY:
        sss_authtok_set_empty(tok);
        return EOK;
    }

    return EINVAL;
}

errno_t sss_authtok_copy(struct sss_auth_token *src,
                         struct sss_auth_token *dst)
{
    if (!src || !dst) {
        return EINVAL;
    }
    sss_authtok_set_empty(dst);

    if (src->type == SSS_AUTHTOK_TYPE_EMPTY) {
        return EOK;
    }

    dst->data = talloc_memdup(dst, src->data, src->length);
    if (!dst->data) {
        return ENOMEM;
    }
    dst->length = src->length;
    dst->type = src->type;

    return EOK;
}

static int sss_auth_token_destructor(struct sss_auth_token *tok)
{
    if (tok != NULL) {
        sss_erase_talloc_mem_securely(tok->data);
    }
    return 0;
}

struct sss_auth_token *sss_authtok_new(TALLOC_CTX *mem_ctx)
{
    struct sss_auth_token *token;

    token = talloc_zero(mem_ctx, struct sss_auth_token);
    if (token == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
    }

    talloc_set_destructor(token, sss_auth_token_destructor);

    return token;
}


void sss_authtok_wipe_password(struct sss_auth_token *tok)
{
    if (!tok || (tok->type != SSS_AUTHTOK_TYPE_PASSWORD &&
                 tok->type != SSS_AUTHTOK_TYPE_PAM_STACKED)) {
        return;
    }

    sss_erase_mem_securely(tok->data, tok->length);
}

errno_t sss_auth_unpack_2fa_blob(TALLOC_CTX *mem_ctx,
                                 const uint8_t *blob, size_t blob_len,
                                 char **fa1, size_t *_fa1_len,
                                 char **fa2, size_t *_fa2_len)
{
    size_t c;
    uint32_t fa1_len;
    uint32_t fa2_len;

    if (blob_len < 2 * sizeof(uint32_t)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Blob too small.\n");
        return EINVAL;
    }

    c = 0;
    SAFEALIGN_COPY_UINT32(&fa1_len, blob, &c);
    SAFEALIGN_COPY_UINT32(&fa2_len, blob + c, &c);

    if (blob_len != 2 * sizeof(uint32_t) + fa1_len + fa2_len) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Blob size mismatch.\n");
        return EINVAL;
    }

    if (fa1_len != 0) {
        *fa1 = talloc_strndup(mem_ctx, (const char *) blob + c, fa1_len);
        if (*fa1 == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strndup failed.\n");
            return ENOMEM;
        }
    } else {
        *fa1 = NULL;
    }

    if (fa2_len != 0) {
        *fa2 = talloc_strndup(mem_ctx, (const char *) blob + c + fa1_len,
                              fa2_len);
        if (*fa2 == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strndup failed.\n");
            talloc_free(*fa1);
            return ENOMEM;
        }
    } else {
        *fa2 = NULL;
    }

    /* Re-calculate length for the case where \0 was missing in the blob */
    *_fa1_len = (*fa1 == NULL) ? 0 : strlen(*fa1);
    *_fa2_len = (*fa2 == NULL) ? 0 : strlen(*fa2);

    return EOK;
}

static errno_t sss_authtok_set_2fa_from_blob(struct sss_auth_token *tok,
                                             const uint8_t *data, size_t len)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    char *fa1;
    size_t fa1_len;
    char *fa2;
    size_t fa2_len;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sss_auth_unpack_2fa_blob(tmp_ctx, data, len, &fa1, &fa1_len,
                                   &fa2, &fa2_len);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_auth_unpack_2fa_blob failed.\n");
        goto done;
    }

    ret = sss_authtok_set_2fa(tok, fa1, fa1_len, fa2, fa2_len);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_authtok_set_2fa failed.\n");
        goto done;
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);

    if (ret != EOK) {
        sss_authtok_set_empty(tok);
    }

    return ret;
}

errno_t sss_authtok_get_2fa(struct sss_auth_token *tok,
                            const char **fa1, size_t *fa1_len,
                            const char **fa2, size_t *fa2_len)
{
    size_t c;
    uint32_t tmp_uint32_t;

    if (tok->type != SSS_AUTHTOK_TYPE_2FA) {
        return (tok->type == SSS_AUTHTOK_TYPE_EMPTY) ? ENOENT : EACCES;
    }

    if (tok->length < 2 * sizeof(uint32_t)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Blob too small.\n");
        return EINVAL;
    }

    c = 0;
    SAFEALIGN_COPY_UINT32(&tmp_uint32_t, tok->data, &c);
    *fa1_len = tmp_uint32_t - 1;
    SAFEALIGN_COPY_UINT32(&tmp_uint32_t, tok->data + c, &c);
    *fa2_len = tmp_uint32_t - 1;

    if (*fa1_len == 0 || *fa2_len == 0
            || tok->length != 2 * sizeof(uint32_t) + *fa1_len + *fa2_len + 2) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Blob size mismatch.\n");
        return EINVAL;
    }

    if (tok->data[c + *fa1_len] != '\0'
            || tok->data[c + *fa1_len + 1 + *fa2_len] != '\0') {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing terminating null character.\n");
        return EINVAL;
    }

    *fa1 = (const char *) tok->data + c;
    *fa2 = (const char *) tok->data + c + *fa1_len + 1;

    return EOK;
}

errno_t sss_authtok_set_2fa(struct sss_auth_token *tok,
                            const char *fa1, size_t fa1_len,
                            const char *fa2, size_t fa2_len)
{
    int ret;
    size_t needed_size;

    if (tok == NULL) {
        return EINVAL;
    }

    sss_authtok_set_empty(tok);

    ret = sss_auth_pack_2fa_blob(fa1, fa1_len, fa2, fa2_len, NULL, 0,
                                 &needed_size);
    if (ret != EAGAIN) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sss_auth_pack_2fa_blob unexpectedly returned [%d].\n", ret);
        return EINVAL;
    }

    tok->data = talloc_size(tok, needed_size);
    if (tok->data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_size failed.\n");
        return ENOMEM;
    }

    ret = sss_auth_pack_2fa_blob(fa1, fa1_len, fa2, fa2_len, tok->data,
                                 needed_size, &needed_size);
    if (ret != EOK) {
        talloc_free(tok->data);
        DEBUG(SSSDBG_OP_FAILURE, "sss_auth_pack_2fa_blob failed.\n");
        return ret;
    }
    tok->length = needed_size;
    tok->type = SSS_AUTHTOK_TYPE_2FA;

    return EOK;
}

errno_t sss_auth_unpack_passkey_blob(TALLOC_CTX *mem_ctx,
                                     const uint8_t *blob,
                                     char **_prompt,
                                     char **_key,
                                     char **_pin)
{
    size_t len = 0;
    char *prompt;
    char *key;
    char *pin;

    prompt = talloc_strdup(mem_ctx, (const char *) blob + len);
    if (prompt == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup prompt failed.\n");
        return ENOMEM;
    }
    len += strlen(prompt) + 1;

    key = talloc_strdup(mem_ctx, (const char *) blob + len);
    if (key == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup key failed.\n");
        talloc_free(prompt);
        return ENOMEM;
    }
    len += strlen(key) + 1;

    pin = talloc_strdup(mem_ctx, (const char *) blob + len);
    if (pin == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup pin failed.\n");
        talloc_free(prompt);
        talloc_free(key);
        return ENOMEM;
    }

    *_prompt = prompt;
    *_key = key;
    *_pin = pin;

    return EOK;
}

errno_t sss_authtok_set_passkey_krb(struct sss_auth_token *tok,
                                    const char *prompt,
                                    const char *key,
                                    const char *pin)
{
    int ret;
    size_t needed_size;

    if (tok == NULL) {
        return EINVAL;
    }

    sss_authtok_set_empty(tok);

    ret = sss_auth_passkey_calc_size(prompt, key, pin, &needed_size);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_auth_calc_size failed [%d]: [%s].\n",
              ret, sss_strerror(ret));
        return ret;
    }

    tok->data = talloc_size(tok, needed_size);
    if (tok->data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_size failed.\n");
        return ENOMEM;
    }

    ret = sss_auth_pack_passkey_blob(tok->data, prompt, key, pin);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sss_auth_pack_passkey_blob unexpectedly returned [%d]: [%s].\n",
              ret, sss_strerror(ret));
        return EINVAL;
    }

    tok->length = needed_size;
    tok->type = SSS_AUTHTOK_TYPE_PASSKEY_KRB;

    return EOK;
}

static errno_t sss_authtok_set_passkey_from_blob(struct sss_auth_token *tok,
                                                 const uint8_t *data, size_t len)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    char *prompt;
    char *key;
    char *pin;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sss_auth_unpack_passkey_blob(tmp_ctx, data, &prompt, &key,
                                       &pin);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_auth_unpack_passkey_blob returned [%d]: [%s].\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = sss_authtok_set_passkey_krb(tok, prompt, key, pin);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_authtok_set_passkey_krb returned [%d]: [%s].\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);

    if (ret != EOK) {
        sss_authtok_set_empty(tok);
    }

    return ret;
}

errno_t sss_authtok_get_passkey(TALLOC_CTX *mem_ctx,
                                struct sss_auth_token *tok,
                                const char **_prompt,
                                const char **_key,
                                const char **_pin,
                                size_t *_pin_len)
{
    char *prompt;
    char *key;
    char *pin;
    size_t pin_len = 0;
    errno_t ret;

    if (!tok) {
        return EFAULT;
    }
    if (tok->type != SSS_AUTHTOK_TYPE_PASSKEY_KRB) {
        return (tok->type == SSS_AUTHTOK_TYPE_EMPTY) ? ENOENT : EACCES;
    }

    ret = sss_auth_unpack_passkey_blob(mem_ctx, tok->data, &prompt, &key,
                                       &pin);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_auth_unpack_passkey_blob returned [%d]: [%s].\n",
              ret, sss_strerror(ret));
        goto done;
    }

    pin_len = strlen(pin);

    *_prompt = prompt;
    *_key = key;
    *_pin = pin;
    *_pin_len = pin_len;
done:
    return ret;

}

errno_t sss_authtok_set_sc(struct sss_auth_token *tok,
                           enum sss_authtok_type type,
                           const char *pin, size_t pin_len,
                           const char *token_name, size_t token_name_len,
                           const char *module_name, size_t module_name_len,
                           const char *key_id, size_t key_id_len,
                           const char *label, size_t label_len)
{
    int ret;
    size_t needed_size;

    if (type != SSS_AUTHTOK_TYPE_SC_PIN
            && type != SSS_AUTHTOK_TYPE_SC_KEYPAD) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid type [%d].\n", type);
        return EINVAL;
    }

    sss_authtok_set_empty(tok);

    ret = sss_auth_pack_sc_blob(pin, pin_len, token_name, token_name_len,
                                module_name, module_name_len,
                                key_id, key_id_len, label, label_len, NULL, 0,
                                &needed_size);
    if (ret != EAGAIN) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_auth_pack_sc_blob failed.\n");
        return ret;
    }

    tok->data = talloc_size(tok, needed_size);
    if (tok->data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_size failed.\n");
        return ENOMEM;
    }

    ret = sss_auth_pack_sc_blob(pin, pin_len, token_name, token_name_len,
                                module_name, module_name_len,
                                key_id, key_id_len, label, label_len, tok->data,
                                needed_size, &needed_size);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_auth_pack_sc_blob failed.\n");
        talloc_free(tok->data);
        return ret;
    }

    tok->length = needed_size;
    tok->type = type;

    return EOK;
}

errno_t sss_authtok_set_sc_from_blob(struct sss_auth_token *tok,
                                     const uint8_t *data,
                                     size_t len)
{
    int ret;
    char *pin = NULL;
    size_t pin_len;
    char *token_name = NULL;
    size_t token_name_len;
    char *module_name = NULL;
    size_t module_name_len;
    char *key_id = NULL;
    size_t key_id_len;
    char *label = NULL;
    size_t label_len;
    TALLOC_CTX *tmp_ctx;

    if (tok == NULL) {
        return EFAULT;
    }
    if (data == NULL || len == 0) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sss_auth_unpack_sc_blob(tmp_ctx, data, len, &pin, &pin_len,
                                  &token_name, &token_name_len,
                                  &module_name, &module_name_len,
                                  &key_id, &key_id_len, &label, &label_len);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_auth_unpack_sc_blob failed.\n");
        goto done;
    }

    ret = sss_authtok_set_sc(tok, SSS_AUTHTOK_TYPE_SC_PIN, pin, pin_len,
                             token_name, token_name_len,
                             module_name, module_name_len,
                             key_id, key_id_len, label, label_len);

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t sss_authtok_set_sc_pin(struct sss_auth_token *tok, const char *pin,
                               size_t len)
{
    if (tok == NULL) {
        return EFAULT;
    }
    if (pin == NULL) {
        return EINVAL;
    }

    return sss_authtok_set_sc(tok, SSS_AUTHTOK_TYPE_SC_PIN, pin, len,
                              NULL, 0, NULL, 0, NULL, 0, NULL, 0);
}

errno_t sss_authtok_get_sc_pin(struct sss_auth_token *tok, const char **_pin,
                               size_t *len)
{
    int ret;
    const char *pin = NULL;
    size_t pin_len;

    if (!tok) {
        return EFAULT;
    }
    switch (tok->type) {
    case SSS_AUTHTOK_TYPE_EMPTY:
        return ENOENT;
    case SSS_AUTHTOK_TYPE_SC_PIN:
        ret = sss_authtok_get_sc(tok, &pin, &pin_len,
                                 NULL, NULL, NULL, NULL, NULL, NULL,
                                 NULL, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sss_authtok_get_sc failed.\n");
            return ret;
        }

        *_pin = pin;
        if (len) {
            *len = pin_len;
        }
        return EOK;
    case SSS_AUTHTOK_TYPE_PASSWORD:
    case SSS_AUTHTOK_TYPE_CCFILE:
    case SSS_AUTHTOK_TYPE_2FA:
    case SSS_AUTHTOK_TYPE_SC_KEYPAD:
    case SSS_AUTHTOK_TYPE_2FA_SINGLE:
    case SSS_AUTHTOK_TYPE_OAUTH2:
    case SSS_AUTHTOK_TYPE_PASSKEY:
    case SSS_AUTHTOK_TYPE_PASSKEY_KRB:
    case SSS_AUTHTOK_TYPE_PASSKEY_REPLY:
    case SSS_AUTHTOK_TYPE_PAM_STACKED:
        return EACCES;
    }

    return EINVAL;
}

void sss_authtok_set_sc_keypad(struct sss_auth_token *tok)
{
    if (tok == NULL) {
        return;
    }

    sss_authtok_set_empty(tok);

    tok->type = SSS_AUTHTOK_TYPE_SC_KEYPAD;
}

errno_t sss_auth_unpack_sc_blob(TALLOC_CTX *mem_ctx,
                                 const uint8_t *blob, size_t blob_len,
                                 char **pin, size_t *_pin_len,
                                 char **token_name, size_t *_token_name_len,
                                 char **module_name, size_t *_module_name_len,
                                 char **key_id, size_t *_key_id_len,
                                 char **label, size_t *_label_len)
{
    size_t c;
    uint32_t pin_len;
    uint32_t token_name_len;
    uint32_t module_name_len;
    uint32_t key_id_len;
    uint32_t label_len;

    c = 0;

    if (blob == NULL || blob_len == 0) {
        pin_len = 0;
        token_name_len = 0;
        module_name_len = 0;
        key_id_len = 0;
        label_len = 0;
    } else if (blob_len > 0
                && strnlen((const char *) blob, blob_len) == blob_len - 1) {
        pin_len = blob_len;
        token_name_len = 0;
        module_name_len = 0;
        key_id_len = 0;
        label_len = 0;
    } else {
        if (blob_len < 5 * sizeof(uint32_t)) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Blob too small.\n");
            return EINVAL;
        }

        SAFEALIGN_COPY_UINT32(&pin_len, blob, &c);
        SAFEALIGN_COPY_UINT32(&token_name_len, blob + c, &c);
        SAFEALIGN_COPY_UINT32(&module_name_len, blob + c, &c);
        SAFEALIGN_COPY_UINT32(&key_id_len, blob + c, &c);
        SAFEALIGN_COPY_UINT32(&label_len, blob + c, &c);

        if (blob_len != 5 * sizeof(uint32_t) + pin_len + token_name_len
                                             + module_name_len + key_id_len
                                             + label_len) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Blob size mismatch.\n");
            return EINVAL;
        }
    }

    if (pin_len != 0) {
        *pin = talloc_strndup(mem_ctx, (const char *) blob + c, pin_len);
        if (*pin == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strndup failed.\n");
            return ENOMEM;
        }
    } else {
        *pin = NULL;
    }

    if (token_name_len != 0) {
        *token_name = talloc_strndup(mem_ctx, (const char *) blob + c + pin_len,
                                     token_name_len);
        if (*token_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strndup failed.\n");
            talloc_free(*pin);
            return ENOMEM;
        }
    } else {
        *token_name = NULL;
    }

    if (module_name_len != 0) {
        *module_name = talloc_strndup(mem_ctx,
                                      (const char *) blob + c + pin_len
                                                              + token_name_len,
                                      module_name_len);
        if (*module_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strndup failed.\n");
            talloc_free(*pin);
            talloc_free(*token_name);
            return ENOMEM;
        }
    } else {
        *module_name = NULL;
    }

    if (key_id_len != 0) {
        *key_id = talloc_strndup(mem_ctx,
                                      (const char *) blob + c + pin_len
                                                              + token_name_len
                                                              + module_name_len,
                                      key_id_len);
        if (*key_id == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strndup failed.\n");
            talloc_free(*pin);
            talloc_free(*token_name);
            talloc_free(*module_name);
            return ENOMEM;
        }
    } else {
        *key_id = NULL;
    }

    if (label_len != 0) {
        *label = talloc_strndup(mem_ctx,
                                      (const char *) blob + c + pin_len
                                                              + token_name_len
                                                              + module_name_len
                                                              + key_id_len,
                                      label_len);
        if (*label == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strndup failed.\n");
            talloc_free(*pin);
            talloc_free(*token_name);
            talloc_free(*module_name);
            talloc_free(*key_id);
            return ENOMEM;
        }
    } else {
        *label = NULL;
    }

    /* Re-calculate length for the case where \0 was missing in the blob */
    if (_pin_len != NULL) {
        *_pin_len = (*pin == NULL) ? 0 : strlen(*pin);
    }
    if (_token_name_len != NULL) {
        *_token_name_len = (*token_name == NULL) ? 0 : strlen(*token_name);
    }
    if (_module_name_len != NULL) {
        *_module_name_len = (*module_name == NULL) ? 0 : strlen(*module_name);
    }

    if (_key_id_len != NULL) {
        *_key_id_len = (*key_id == NULL) ? 0 : strlen(*key_id);
    }

    if (_label_len != NULL) {
        *_label_len = (*label == NULL) ? 0 : strlen(*label);
    }

    return EOK;
}

errno_t sss_authtok_get_sc(struct sss_auth_token *tok,
                           const char **_pin, size_t *_pin_len,
                           const char **_token_name, size_t *_token_name_len,
                           const char **_module_name, size_t *_module_name_len,
                           const char **_key_id, size_t *_key_id_len,
                           const char **_label, size_t *_label_len)
{
    size_t c = 0;
    size_t pin_len;
    size_t token_name_len;
    size_t module_name_len;
    size_t key_id_len;
    size_t label_len;
    uint32_t tmp_uint32_t;

    if (!tok) {
        return EFAULT;
    }

    if (tok->type != SSS_AUTHTOK_TYPE_SC_PIN
            && tok->type != SSS_AUTHTOK_TYPE_SC_KEYPAD) {
        return (tok->type == SSS_AUTHTOK_TYPE_EMPTY) ? ENOENT : EACCES;
    }

    if (tok->length < 5 * sizeof(uint32_t)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Blob too small.\n");
        return EINVAL;
    }

    SAFEALIGN_COPY_UINT32(&tmp_uint32_t, tok->data, &c);
    pin_len = tmp_uint32_t - 1;
    SAFEALIGN_COPY_UINT32(&tmp_uint32_t, tok->data + c, &c);
    token_name_len = tmp_uint32_t - 1;
    SAFEALIGN_COPY_UINT32(&tmp_uint32_t, tok->data + c, &c);
    module_name_len = tmp_uint32_t -1;
    SAFEALIGN_COPY_UINT32(&tmp_uint32_t, tok->data + c, &c);
    key_id_len = tmp_uint32_t -1;
    SAFEALIGN_COPY_UINT32(&tmp_uint32_t, tok->data + c, &c);
    label_len = tmp_uint32_t -1;

    if (tok->length != 5 * sizeof(uint32_t) +  5 + pin_len + token_name_len
                                         + module_name_len + key_id_len
                                         + label_len) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Blob size mismatch.\n");
        return EINVAL;
    }

    if (_pin != NULL) {
        *_pin = (const char *) tok->data + c;
    }
    if (_pin_len != NULL) {
        *_pin_len = pin_len;
    }

    if (_token_name != NULL) {
        *_token_name = (const char *) tok->data + c + pin_len + 1;
    }
    if (_token_name_len != NULL) {
        *_token_name_len = token_name_len;
    }

    if (_module_name != NULL) {
        *_module_name = (const char *) tok->data + c + pin_len + 1
                                                     + token_name_len + 1;
    }
    if (_module_name_len != NULL) {
        *_module_name_len = module_name_len;
    }

    if (_key_id != NULL) {
        *_key_id = (const char *) tok->data + c + pin_len + 1
                               + token_name_len + 1 + module_name_len + 1;
    }
    if (_key_id_len != NULL) {
        *_key_id_len = key_id_len;
    }

    if (_label != NULL) {
        *_label = (const char *) tok->data + c + pin_len + 1
                               + token_name_len + 1 + module_name_len + 1
                               + key_id_len + 1;
    }
    if (_label_len != NULL) {
        *_label_len = label_len;
    }

    return EOK;
}
