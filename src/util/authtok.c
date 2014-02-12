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
    case SSS_AUTHTOK_TYPE_PASSWORD:
        *pwd = (const char *)tok->data;
        if (len) {
            *len = tok->length - 1;
        }
        return EOK;
    case SSS_AUTHTOK_TYPE_CCFILE:
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
        safezero(tok->data, tok->length);
        break;
    case SSS_AUTHTOK_TYPE_CCFILE:
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

errno_t sss_authtok_set(struct sss_auth_token *tok,
                        enum sss_authtok_type type,
                        const uint8_t *data, size_t len)
{
    switch (type) {
    case SSS_AUTHTOK_TYPE_PASSWORD:
        return sss_authtok_set_password(tok, (const char *)data, len);
    case SSS_AUTHTOK_TYPE_CCFILE:
        return sss_authtok_set_ccfile(tok, (const char *)data, len);
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

struct sss_auth_token *sss_authtok_new(TALLOC_CTX *mem_ctx)
{
    struct sss_auth_token *token;

    token = talloc_zero(mem_ctx, struct sss_auth_token);
    if (token == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
    }

    return token;
}


void sss_authtok_wipe_password(struct sss_auth_token *tok)
{
    if (!tok || tok->type != SSS_AUTHTOK_TYPE_PASSWORD) {
        return;
    }

    safezero(tok->data, tok->length);
}

