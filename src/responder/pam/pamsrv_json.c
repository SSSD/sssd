/*
    SSSD

    pamsrv_json authentication selection helper for GDM

    Authors:
        Iker Pedrosa <ipedrosa@redhat.com>

    Copyright (C) 2024 Red Hat

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

#define _GNU_SOURCE

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "responder/pam/pamsrv.h"
#ifdef BUILD_PASSKEY
#include "responder/pam/pamsrv_passkey.h"
#endif /* BUILD_PASSKEY */
#include "util/debug.h"

#include "pamsrv_json.h"

struct cert_auth_info {
    char *cert_user;
    char *cert;
    char *token_name;
    char *module_name;
    char *key_id;
    char *label;
    char *prompt_str;
    char *pam_cert_user;
    char *choice_list_id;
    struct cert_auth_info *prev;
    struct cert_auth_info *next;
};


static errno_t
obtain_oauth2_data(TALLOC_CTX *mem_ctx, struct pam_data *pd,
                   struct auth_data *_auth_data)
{
    TALLOC_CTX *tmp_ctx = NULL;
    uint8_t *oauth2 = NULL;
    char *uri = NULL;
    char *uri_complete = NULL;
    char *code = NULL;
    int32_t len;
    int32_t offset;
    int32_t str_len;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = pam_get_response_data(tmp_ctx, pd, SSS_PAM_OAUTH2_INFO, &oauth2, &len);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to get SSS_PAM_OAUTH2_INFO, ret %d.\n",
              ret);
        goto done;
    }

    str_len = strnlen((const char *)oauth2, len);
    if (str_len >= len) {
        DEBUG(SSSDBG_OP_FAILURE,
              "uri string is not null-terminated within buffer bounds.\n");
        ret = EINVAL;
        goto done;
    }

    uri = talloc_strndup(tmp_ctx, (const char *)oauth2, str_len);
    if (uri == NULL) {
        ret = ENOMEM;
        goto done;
    }
    offset = str_len + 1;

    if (offset >= len) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Trying to access data outside of the boundaries.\n");
        ret = EPERM;
        goto done;
    }

    str_len = strnlen((const char *)oauth2 + offset, len - offset);
    if (str_len >= (len - offset)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "uri_complete string is not null-terminated within buffer bounds.\n");
        ret = EINVAL;
        goto done;
    }

    uri_complete = talloc_strndup(tmp_ctx, (const char *)oauth2 + offset, str_len);
    if (uri_complete == NULL) {
        ret = ENOMEM;
        goto done;
    }
    offset += str_len + 1;

    if (offset >= len) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Trying to access data outside of the boundaries.\n");
        ret = EPERM;
        goto done;
    }

    str_len = strnlen((const char *)oauth2 + offset, len - offset);
    if (str_len >= (len - offset)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "code string is not null-terminated within buffer bounds.\n");
        ret = EINVAL;
        goto done;
    }

    code = talloc_strndup(tmp_ctx, (const char *)oauth2 + offset, str_len);
    if (code == NULL) {
        ret = ENOMEM;
        goto done;
    }

    _auth_data->oauth2->uri = talloc_steal(mem_ctx, uri);
    _auth_data->oauth2->code = talloc_steal(mem_ctx, code);
    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

#ifdef BUILD_PASSKEY
static errno_t
obtain_passkey_data(TALLOC_CTX *mem_ctx, struct pam_data *pd,
                    struct auth_data *_auth_data)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct pk_child_user_data *pk_data = NULL;
    const char *crypto_challenge = NULL;
    bool passkey_enabled = false;
    bool passkey_kerberos = false;
    bool user_verification = true;
    uint8_t *buf = NULL;
    int32_t len;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = pam_get_response_data(tmp_ctx, pd, SSS_PAM_PASSKEY_KRB_INFO, &buf, &len);
    if (ret == EOK) {
        passkey_enabled = true;
        passkey_kerberos = true;
        ret = decode_pam_passkey_msg(tmp_ctx, buf, len, &pk_data);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failure decoding PAM passkey msg, ret %d.\n",
                  ret);
            goto done;
        }

        if (strcmp(pk_data->user_verification, "false") == 0) {
            user_verification = false;
        }
        crypto_challenge = pk_data->crypto_challenge;
    } else if (ret == ENOENT) {
        DEBUG(SSSDBG_FUNC_DATA, "SSS_PAM_PASSKEY_KRB_INFO not found.\n");
        ret = pam_get_response_data(tmp_ctx, pd, SSS_PAM_PASSKEY_INFO, &buf, &len);
        if (ret == EOK) {
            passkey_enabled = true;
            crypto_challenge = talloc_strdup(tmp_ctx, "");
        } else if (ret == ENOENT) {
            DEBUG(SSSDBG_FUNC_DATA, "SSS_PAM_PASSKEY_INFO not found.\n");
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Unable to get SSS_PAM_PASSKEY_INFO, ret %d.\n",
                  ret);
            goto done;
        }
    } else {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to get SSS_PAM_PASSKEY_KRB_INFO, ret %d.\n",
              ret);
        goto done;
    }

    _auth_data->passkey->enabled = passkey_enabled;
    _auth_data->passkey->kerberos = passkey_kerberos;
    _auth_data->passkey->key_connected = true;
    _auth_data->passkey->pin_request = user_verification;
    _auth_data->passkey->crypto_challenge = talloc_steal(mem_ctx, crypto_challenge);
    /* Hardcoding of the following values for the moment */
    _auth_data->passkey->pin_attempts = 8;
    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}
#endif /* BUILD_PASSKEY */

static errno_t
obtain_prompts(struct confdb_ctx *cdb, TALLOC_CTX *mem_ctx,
               struct prompt_config **pc_list, struct auth_data *_auth_data)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *password_prompt = NULL;
    char *oauth2_init_prompt = NULL;
    char *oauth2_link_prompt = NULL;
    char *sc_init_prompt = NULL;
    char *sc_pin_prompt = NULL;
    char *passkey_init_prompt = NULL;
    char *passkey_pin_prompt = NULL;
    char *passkey_touch_prompt = NULL;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    password_prompt = talloc_strdup(tmp_ctx, PASSWORD_PROMPT);
    if (password_prompt == NULL) {
        ret = ENOMEM;
        goto done;
    }

    oauth2_init_prompt = talloc_strdup(tmp_ctx, OAUTH2_INIT_PROMPT);
    if (oauth2_init_prompt == NULL) {
        ret = ENOMEM;
        goto done;
    }

    oauth2_link_prompt = talloc_strdup(tmp_ctx, OAUTH2_LINK_PROMPT);
    if (oauth2_link_prompt == NULL) {
        ret = ENOMEM;
        goto done;
    }

    sc_init_prompt = talloc_strdup(tmp_ctx, SC_INIT_PROMPT);
    if (sc_init_prompt == NULL) {
        ret = ENOMEM;
        goto done;
    }

    sc_pin_prompt = talloc_strdup(tmp_ctx, SC_PIN_PROMPT);
    if (sc_pin_prompt == NULL) {
        ret = ENOMEM;
        goto done;
    }

    passkey_init_prompt = talloc_strdup(tmp_ctx, PASSKEY_INIT_PROMPT);
    if (passkey_init_prompt == NULL) {
        ret = ENOMEM;
        goto done;
    }

    passkey_pin_prompt = talloc_strdup(tmp_ctx, PASSKEY_PIN_PROMPT);
    if (passkey_pin_prompt == NULL) {
        ret = ENOMEM;
        goto done;
    }

    passkey_touch_prompt = talloc_strdup(tmp_ctx, PASSKEY_TOUCH_PROMPT);
    if (passkey_touch_prompt == NULL) {
        ret = ENOMEM;
        goto done;
    }

    _auth_data->pswd->prompt = talloc_steal(mem_ctx, password_prompt);
    _auth_data->oauth2->init_prompt = talloc_steal(mem_ctx, oauth2_init_prompt);
    _auth_data->oauth2->link_prompt = talloc_steal(mem_ctx, oauth2_link_prompt);
    _auth_data->sc->init_prompt = talloc_steal(mem_ctx, sc_init_prompt);
    _auth_data->sc->pin_prompt = talloc_steal(mem_ctx, sc_pin_prompt);
    _auth_data->passkey->init_prompt = talloc_steal(mem_ctx, passkey_init_prompt);
    _auth_data->passkey->pin_prompt = talloc_steal(mem_ctx, passkey_pin_prompt);
    _auth_data->passkey->touch_prompt = talloc_steal(mem_ctx, passkey_touch_prompt);
    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
get_cert_list(TALLOC_CTX *mem_ctx, struct pam_data *pd,
              struct cert_auth_info **_cert_list)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct cert_auth_info *cert_list = NULL;
    struct cert_auth_info *cai = NULL;
    uint8_t **sc = NULL;
    int32_t *len = NULL;
    int32_t offset;
    int32_t str_len;
    int num;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = pam_get_response_data_all_same_type(tmp_ctx, pd, SSS_PAM_CERT_INFO,
                                              &sc, &len, &num);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to get SSS_PAM_CERT_INFO, ret %d.\n",
              ret);
        goto done;
    }

    for (int i = 0; i < num; i++) {
        cai = talloc_zero(tmp_ctx, struct cert_auth_info);
        if (cai == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
            ret = ENOMEM;
            goto done;
        }

        str_len = strnlen((const char *)sc[i], len[i]);
        if (str_len >= len[i]) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "cert_user string is not null-terminated within buffer bounds.\n");
            ret = EINVAL;
            goto done;
        }
        cai->cert_user = talloc_strndup(cai, (const char *)sc[i], str_len);
        if (cai->cert_user == NULL) {
            ret = ENOMEM;
            goto done;
        }
        offset = str_len + 1;

        if (offset >= len[i]) {
            DEBUG(SSSDBG_OP_FAILURE,
                "Trying to access data outside of the boundaries.\n");
            ret = EPERM;
            goto done;
        }

        str_len = strnlen((const char *)sc[i] + offset, len[i] - offset);
        if (str_len >= (len[i] - offset)) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "token_name string is not null-terminated within buffer bounds.\n");
            ret = EINVAL;
            goto done;
        }
        cai->token_name = talloc_strndup(cai, (const char *)sc[i] + offset, str_len);
        if (cai->token_name == NULL) {
            ret = ENOMEM;
            goto done;
        }
        offset += str_len + 1;

        if (offset >= len[i]) {
            DEBUG(SSSDBG_OP_FAILURE,
                "Trying to access data outside of the boundaries.\n");
            ret = EPERM;
            goto done;
        }

        str_len = strnlen((const char *)sc[i] + offset, len[i] - offset);
        if (str_len >= (len[i] - offset)) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "module_name string is not null-terminated within buffer bounds.\n");
            ret = EINVAL;
            goto done;
        }
        cai->module_name = talloc_strndup(cai, (const char *)sc[i] + offset, str_len);
        if (cai->module_name == NULL) {
            ret = ENOMEM;
            goto done;
        }
        offset += str_len + 1;

        if (offset >= len[i]) {
            DEBUG(SSSDBG_OP_FAILURE,
                "Trying to access data outside of the boundaries.\n");
            ret = EPERM;
            goto done;
        }

        str_len = strnlen((const char *)sc[i] + offset, len[i] - offset);
        if (str_len >= (len[i] - offset)) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "key_id string is not null-terminated within buffer bounds.\n");
            ret = EINVAL;
            goto done;
        }
        cai->key_id = talloc_strndup(cai, (const char *)sc[i] + offset, str_len);
        if (cai->key_id == NULL) {
            ret = ENOMEM;
            goto done;
        }
        offset += str_len + 1;

        if (offset >= len[i]) {
            DEBUG(SSSDBG_OP_FAILURE,
                "Trying to access data outside of the boundaries.\n");
            ret = EPERM;
            goto done;
        }

        str_len = strnlen((const char *)sc[i] + offset, len[i] - offset);
        if (str_len >= (len[i] - offset)) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "label string is not null-terminated within buffer bounds.\n");
            ret = EINVAL;
            goto done;
        }
        cai->label = talloc_strndup(cai, (const char *)sc[i] + offset, str_len);
        if (cai->label == NULL) {
            ret = ENOMEM;
            goto done;
        }
        offset += str_len + 1;

        if (offset >= len[i]) {
            DEBUG(SSSDBG_OP_FAILURE,
                "Trying to access data outside of the boundaries.\n");
            ret = EPERM;
            goto done;
        }

        str_len = strnlen((const char *)sc[i] + offset, len[i] - offset);
        if (str_len >= (len[i] - offset)) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "prompt_str string is not null-terminated within buffer bounds.\n");
            ret = EINVAL;
            goto done;
        }
        cai->prompt_str = talloc_strndup(cai, (const char *)sc[i] + offset, str_len);
        if (cai->prompt_str == NULL) {
            ret = ENOMEM;
            goto done;
        }
        offset += str_len + 1;

        if (offset >= len[i]) {
            DEBUG(SSSDBG_OP_FAILURE,
                "Trying to access data outside of the boundaries.\n");
            ret = EPERM;
            goto done;
        }

        str_len = strnlen((const char *)sc[i] + offset, len[i] - offset);
        if (str_len >= (len[i] - offset)) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "pam_cert_user string is not null-terminated within buffer bounds.\n");
            ret = EINVAL;
            goto done;
        }
        cai->pam_cert_user = talloc_strndup(cai, (const char *)sc[i] + offset, str_len);
        if (cai->pam_cert_user == NULL) {
            ret = ENOMEM;
            goto done;
        }
        offset += str_len + 1;

        DEBUG(SSSDBG_FUNC_DATA,
              "cert_user %s, token_name %s, module_name %s, key_id %s,"
              "label %s, prompt_str %s, pam_cert_user %s.\n",
              cai->cert_user, cai->token_name, cai->module_name, cai->key_id,
              cai->label, cai->prompt_str, cai->pam_cert_user);

        DLIST_ADD(cert_list, cai);
    }

    DLIST_FOR_EACH(cai, cert_list) {
        talloc_steal(mem_ctx, cai);
    }
    *_cert_list = cert_list;
    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t
init_auth_data(TALLOC_CTX *mem_ctx, struct confdb_ctx *cdb,
               struct prompt_config **pc_list, struct pam_data *pd,
               struct auth_data **_auth_data)
{
    struct cert_auth_info *cert_list = NULL;
    struct pam_resp_auth_type types;
    errno_t ret = EOK;

    *_auth_data = talloc_zero(mem_ctx, struct auth_data);
    if (*_auth_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
        ret = ENOMEM;
        goto done;
    }

    (*_auth_data)->pswd = talloc_zero(mem_ctx, struct password_data);
    if ((*_auth_data)->pswd == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
        ret = ENOMEM;
        goto done;
    }

    (*_auth_data)->oauth2 = talloc_zero(mem_ctx, struct oauth2_data);
    if ((*_auth_data)->oauth2 == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
        ret = ENOMEM;
        goto done;
    }

    (*_auth_data)->sc = talloc_zero(mem_ctx, struct sc_data);
    if ((*_auth_data)->sc == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
        ret = ENOMEM;
        goto done;
    }

    (*_auth_data)->passkey = talloc_zero(mem_ctx, struct passkey_data);
    if ((*_auth_data)->passkey == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = pam_get_auth_types(pd, &types);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get authentication types\n");
        goto done;
    }
    (*_auth_data)->pswd->enabled = types.password_auth;
    (*_auth_data)->oauth2->enabled = true;
    (*_auth_data)->sc->enabled = types.cert_auth;
    (*_auth_data)->passkey->enabled = types.passkey_auth;

    ret = obtain_prompts(cdb, mem_ctx, pc_list, *_auth_data);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failure to obtain the prompts.\n");
        goto done;
    }

    ret = obtain_oauth2_data(mem_ctx, pd, *_auth_data);
    if (ret == ENOENT) {
        (*_auth_data)->oauth2->enabled = false;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failure to obtain OAUTH2 data.\n");
        goto done;
    }

    if ((*_auth_data)->sc->enabled) {
        ret = get_cert_list(mem_ctx, pd, &cert_list);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                "Failure to obtain smartcard certificate list.\n");
            goto done;
        }

        ret = get_cert_data(mem_ctx, cert_list, *_auth_data);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failure to obtain smartcard labels.\n");
            goto done;
        }
    }

#ifdef BUILD_PASSKEY
    if ((*_auth_data)->passkey->enabled) {
        ret = obtain_passkey_data(mem_ctx, pd, *_auth_data);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failure to obtain passkey data.\n");
            goto done;
        }
    }
#else
    (*_auth_data)->passkey->enabled = false;
#endif /* BUILD_PASSKEY */

done:
    return ret;
}

errno_t
get_cert_data(TALLOC_CTX *mem_ctx, struct cert_auth_info *cert_list,
               struct auth_data *_auth_data)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct cert_auth_info *item = NULL;
    char **names = NULL;
    char **cert_instructions = NULL;
    char **module_names = NULL;
    char **key_ids = NULL;
    char **labels = NULL;
    int i = 0;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        ret = ENOMEM;
        goto done;
    }

    DLIST_FOR_EACH(item, cert_list) {
        i++;
    }

    names = talloc_array(tmp_ctx, char *, i+1);
    if (names == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
        ret = ENOMEM;
        goto done;
    }

    cert_instructions = talloc_array(tmp_ctx, char *, i+1);
    if (cert_instructions == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
        ret = ENOMEM;
        goto done;
    }

    module_names = talloc_array(tmp_ctx, char *, i+1);
    if (module_names == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
        ret = ENOMEM;
        goto done;
    }

    key_ids = talloc_array(tmp_ctx, char *, i+1);
    if (key_ids == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
        ret = ENOMEM;
        goto done;
    }

    labels = talloc_array(tmp_ctx, char *, i+1);
    if (labels == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
        ret = ENOMEM;
        goto done;
    }

    i = 0;
    DLIST_FOR_EACH(item, cert_list) {
        names[i] = talloc_strdup(names, item->token_name);
        if (names[i] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }

        cert_instructions[i] = talloc_strdup(names, item->prompt_str);
        if (cert_instructions[i] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }

        module_names[i] = talloc_strdup(names, item->module_name);
        if (module_names[i] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }

        key_ids[i] = talloc_strdup(names, item->key_id);
        if (key_ids[i] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }

        labels[i] = talloc_strdup(names, item->label);
        if (labels[i] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }
        i++;
    }
    names[i] = NULL;
    cert_instructions[i] = NULL;
    module_names[i] = NULL;
    key_ids[i] = NULL;
    labels[i] = NULL;

    _auth_data->sc->names = talloc_steal(mem_ctx, names);
    _auth_data->sc->cert_instructions = talloc_steal(mem_ctx, cert_instructions);
    _auth_data->sc->module_names = talloc_steal(mem_ctx, module_names);
    _auth_data->sc->key_ids = talloc_steal(mem_ctx, key_ids);
    _auth_data->sc->labels = talloc_steal(mem_ctx, labels);
    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
json_format_mechanisms(struct auth_data *auth_data, json_t **_list_mech)
{
    json_t *root = NULL;
    json_t *json_pass = NULL;
    json_t *json_oauth2 = NULL;
    json_t *json_cert = NULL;
    json_t *json_cert_array = NULL;
    json_t *json_sc = NULL;
    json_t *json_passkey = NULL;
    int ret;

    root = json_object();
    if (root == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "json_array failed.\n");
        ret = ENOMEM;
        goto done;
    }

    if (auth_data->pswd->enabled) {
        json_pass = json_pack("{s:s,s:s,s:s}",
                              "name", "Password",
                              "role", "password",
                              "prompt", auth_data->pswd->prompt);
        if (json_pass == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "json_pack failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = json_object_set_new(root, "password", json_pass);
        if (ret == -1) {
            DEBUG(SSSDBG_OP_FAILURE, "json_array_append failed.\n");
            json_decref(json_pass);
            ret = ENOMEM;
            goto done;
        }
    }

    if (auth_data->oauth2->enabled) {
        json_oauth2 = json_pack("{s:s,s:s,s:s,s:s,s:s,s:s,s:i}",
                                "name", "Web Login",
                                "role", "eidp",
                                "initPrompt", auth_data->oauth2->init_prompt,
                                "linkPrompt", auth_data->oauth2->link_prompt,
                                "uri", auth_data->oauth2->uri,
                                "code", auth_data->oauth2->code,
                                "timeout", 300);
        if (json_oauth2 == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "json_pack failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = json_object_set_new(root, "eidp", json_oauth2);
        if (ret == -1) {
            DEBUG(SSSDBG_OP_FAILURE, "json_array_append failed.\n");
            json_decref(json_oauth2);
            ret = ENOMEM;
            goto done;
        }
    }

    if (auth_data->sc->enabled) {
        json_cert_array = json_array();
        if (json_cert_array == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "json_array failed.\n");
            ret = ENOMEM;
            goto done;
        }

        for (int i = 0; auth_data->sc->names[i] != NULL; i++) {
            json_cert = json_pack("{s:s,s:s,s:s,s:s,s:s,s:s}",
                                  "tokenName", auth_data->sc->names[i],
                                  "certInstruction", auth_data->sc->cert_instructions[i],
                                  "pinPrompt", auth_data->sc->pin_prompt,
                                  "moduleName", auth_data->sc->module_names[i],
                                  "keyId", auth_data->sc->key_ids[i],
                                  "label", auth_data->sc->labels[i]);
            if (json_cert == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "json_pack failed.\n");
                ret = ENOMEM;
                goto done;
            }

            ret = json_array_append_new(json_cert_array, json_cert);
            if (ret == -1) {
                DEBUG(SSSDBG_OP_FAILURE, "json_array_append_new failed.\n");
                json_decref(json_cert);
                ret = ENOMEM;
                goto done;
            }
        }

        json_sc = json_pack("{s:s,s:s,s:o}",
                            "name", "Smartcard",
                            "role", "smartcard",
                            "certificates", json_cert_array);
        if (json_sc == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "json_pack failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = json_object_set_new(root, "smartcard", json_sc);
        if (ret == -1) {
            DEBUG(SSSDBG_OP_FAILURE, "json_object_set_new failed.\n");
            json_decref(json_sc);
            ret = ENOMEM;
            goto done;
        }
    }

    if (auth_data->passkey->enabled) {
        json_passkey = json_pack("{s:s,s:s,s:s,s:b,s:b,s:i,s:s,s:s,s:b,s:s}",
                                 "name", "Passkey",
                                 "role", "passkey",
                                 "initInstruction", auth_data->passkey->init_prompt,
                                 "keyConnected", auth_data->passkey->key_connected,
                                 "pinRequest", auth_data->passkey->pin_request,
                                 "pinAttempts", auth_data->passkey->pin_attempts,
                                 "pinPrompt", auth_data->passkey->pin_prompt,
                                 "touchInstruction", auth_data->passkey->touch_prompt,
                                 "kerberos", auth_data->passkey->kerberos,
                                 "cryptoChallenge", auth_data->passkey->crypto_challenge);
        if (json_passkey == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "json_pack failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = json_object_set_new(root, "passkey", json_passkey);
        if (ret == -1) {
            DEBUG(SSSDBG_OP_FAILURE, "json_array_append failed.\n");
            json_decref(json_passkey);
            ret = ENOMEM;
            goto done;
        }
    }

    *_list_mech = root;
    ret = EOK;

done:
    if (ret != EOK) {
        json_decref(root);
        if (json_cert_array != NULL) {
            json_decref(json_cert_array);
        }
    }

    return ret;
}

errno_t
json_format_priority(struct auth_data *auth_data, json_t **_priority)
{
    json_t *root = NULL;
    json_t *json_priority = NULL;
    int ret;

    root = json_array();
    if (root == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "json_array failed.\n");
        ret = ENOMEM;
        goto done;
    }

    if (auth_data->sc->enabled) {
        json_priority = json_string("smartcard");
        if (json_priority == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "json_string failed.\n");
            ret = ENOMEM;
            goto done;
        }
        ret = json_array_append_new(root, json_priority);
        if (ret == -1) {
            DEBUG(SSSDBG_OP_FAILURE, "json_array_append failed.\n");
            json_decref(json_priority);
            ret = ENOMEM;
            goto done;
        }
    }

    if (auth_data->passkey->enabled) {
        json_priority = json_string("passkey");
        if (json_priority == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "json_string failed.\n");
            ret = ENOMEM;
            goto done;
        }
        ret = json_array_append_new(root, json_priority);
        if (ret == -1) {
            DEBUG(SSSDBG_OP_FAILURE, "json_array_append failed.\n");
            json_decref(json_priority);
            ret = ENOMEM;
            goto done;
        }
    }

    if (auth_data->oauth2->enabled) {
        json_priority = json_string("eidp");
        if (json_priority == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "json_string failed.\n");
            ret = ENOMEM;
            goto done;
        }
        ret = json_array_append_new(root, json_priority);
        if (ret == -1) {
            DEBUG(SSSDBG_OP_FAILURE, "json_array_append failed.\n");
            json_decref(json_priority);
            ret = ENOMEM;
            goto done;
        }
    }

    if (auth_data->pswd->enabled) {
        json_priority = json_string("password");
        if (json_priority == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "json_string failed.\n");
            ret = ENOMEM;
            goto done;
        }
        ret = json_array_append_new(root, json_priority);
        if (ret == -1) {
            DEBUG(SSSDBG_OP_FAILURE, "json_array_append failed.\n");
            json_decref(json_priority);
            ret = ENOMEM;
            goto done;
        }
    }

    ret = EOK;
    *_priority = root;

done:
    if (ret != EOK) {
        json_decref(root);
    }

    return ret;
}

errno_t
json_format_auth_selection(TALLOC_CTX *mem_ctx, struct auth_data *auth_data,
                           char **_result)
{
    json_t *root = NULL;
    json_t *json_mech = NULL;
    json_t *json_priority = NULL;
    char *string = NULL;
    int ret;

    ret = json_format_mechanisms(auth_data, &json_mech);
    if (ret != EOK) {
        goto done;
    }

    ret = json_format_priority(auth_data, &json_priority);
    if (ret != EOK) {
        json_decref(json_mech);
        goto done;
    }

    root = json_pack("{s:{s:o,s:o}}",
                     "authSelection",
                     "mechanisms", json_mech,
                     "priority", json_priority);
    if (root == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "json_pack failed.\n");
        ret = ENOMEM;
        json_decref(json_mech);
        json_decref(json_priority);
        goto done;
    }

    string = json_dumps(root, 0);
    if (string == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "json_dumps failed.\n");
        ret = ENOMEM;
        goto done;
    }

    *_result = talloc_strdup(mem_ctx, string);
    ret = EOK;

done:
    free(string);
    json_decref(root);

    return ret;
}

errno_t
generate_json_auth_message(struct confdb_ctx *cdb,
                           struct prompt_config **pc_list,
                           struct pam_data *_pd)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct auth_data *auth_data = NULL;
    char *result = NULL;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = init_auth_data(tmp_ctx, cdb, pc_list, _pd, &auth_data);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to initialize authentication data.\n");
        goto done;
    }

    ret = json_format_auth_selection(tmp_ctx, auth_data, &result);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to format JSON message.\n");
        goto done;
    }

    ret = pam_add_response(_pd, SSS_PAM_JSON_AUTH_INFO, strlen(result)+1,
                           (const uint8_t *)result);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
        goto done;
    }
    DEBUG(SSSDBG_TRACE_FUNC, "Generated JSON message: %s.\n", result);
    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
json_unpack_password(json_t *jroot, char **_password)
{
    char *password = NULL;
    int ret = EOK;

    ret = json_unpack(jroot, "{s:s}",
                      "password", &password);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "json_unpack for password failed.\n");
        ret = EINVAL;
        goto done;
    }

    *_password = password;
    ret = EOK;

done:
    return ret;
}

errno_t
json_unpack_oauth2_code(TALLOC_CTX *mem_ctx, char *json_auth_msg,
                        char **_oauth2_code)
{
    json_t *jroot = NULL;
    json_t *json_mechs = NULL;
    json_t *json_priority = NULL;
    json_t *json_mech = NULL;
    json_t *jobj = NULL;
    const char *key = NULL;
    const char *oauth2_code = NULL;
    json_error_t jret;
    int ret = EOK;

    jroot = json_loads(json_auth_msg, 0, &jret);
    if (jroot == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "json_loads failed.\n");
        ret = EINVAL;
        goto done;
    }

    ret = json_unpack(jroot, "{s:{s:o,s:o}}",
                      "authSelection",
                      "mechanisms", &json_mechs,
                      "priority", &json_priority);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "json_unpack failed.\n");
        ret = EINVAL;
        goto done;
    }

    json_object_foreach(json_mechs, key, json_mech){
        if (strcmp(key, "eidp") == 0) {
            json_object_foreach(json_mech, key, jobj){
                if (strcmp(key, "code") == 0) {
                    oauth2_code = json_string_value(jobj);
                    ret = EOK;
                    goto done;
                }
            }
        }
    }

    DEBUG(SSSDBG_CRIT_FAILURE, "OAUTH2 code not found in JSON message.\n");
    ret = ENOENT;

done:
    if (ret == EOK) {
        *_oauth2_code = talloc_strdup(mem_ctx, oauth2_code);
    }
    if (jroot != NULL) {
        json_decref(jroot);
    }

    return ret;
}

errno_t
json_unpack_smartcard(TALLOC_CTX *mem_ctx, json_t *jroot,
                      const char **_pin, struct cert_auth_info **_cai)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct cert_auth_info *cai = NULL;
    char *pin = NULL;
    int ret = EOK;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    cai = talloc_zero(tmp_ctx, struct cert_auth_info);
    if (cai == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = json_unpack(jroot, "{s:s,s:s,s:s,s:s,s:s}",
                      "pin", &pin,
                      "tokenName", &cai->token_name,
                      "moduleName", &cai->module_name,
                      "keyId", &cai->key_id,
                      "label", &cai->label);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "json_unpack for smartcard failed.\n");
        ret = EINVAL;
        goto done;
    }

    *_pin = pin;
    *_cai = talloc_steal(mem_ctx, cai);

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
json_unpack_passkey(json_t *jroot, const char **_pin, bool *_kerberos,
                    char **_crypto_challenge)
{
    json_t *pin = NULL;
    json_t *kerberos = NULL;
    json_t *crypto = NULL;
    int ret = EOK;

    pin = json_object_get(jroot, "pin");
    if (pin == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "json_object_get for pin failed.\n");
        ret = EINVAL;
        goto done;
    }

    kerberos = json_object_get(jroot, "kerberos");
    if (kerberos == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "json_object_get for kerberos failed.\n");
        ret = EINVAL;
        goto done;
    }

    crypto = json_object_get(jroot, "cryptoChallenge");
    if (crypto == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "json_object_get for crypto-challenge failed.\n");
        ret = EINVAL;
        goto done;
    }

    *_pin = discard_const(json_string_value(pin));
    *_kerberos = json_boolean_value(kerberos);
    *_crypto_challenge = discard_const(json_string_value(crypto));
    ret = EOK;

done:
    return ret;
}

errno_t
json_unpack_auth_reply(struct pam_data *pd)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct cert_auth_info *cai = NULL;
    json_t *jroot = NULL;
    json_t *jauth_selection = NULL;
    json_t *jobj = NULL;
    json_error_t jret;
    const char *key = NULL;
    const char *status = NULL;
    const char *user_verification = NULL;
    char *password = NULL;
    char *oauth2_code = NULL;
    const char *pin = NULL;
    char *crypto_challenge = NULL;
    bool passkey_kerberos = false;
    int ret = EOK;

    DEBUG(SSSDBG_TRACE_FUNC, "Received JSON message: %s.\n",
          pd->json_auth_selected);

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    jroot = json_loads(pd->json_auth_selected, 0, &jret);
    if (jroot == NULL) {
        ret = EINVAL;
        goto done;
    }

    ret = json_unpack(jroot, "{s:o}", "authSelection", &jauth_selection);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "json_unpack for authSelection failed.\n");
        ret = EINVAL;
        goto done;
    }

    json_object_foreach(jauth_selection, key, jobj){
        if (strcmp(key, "status") == 0) {
            status = json_string_value(jobj);
            if (status == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "NULL status returned.\n");
                ret = EINVAL;
                goto done;
            } else if (strcmp(status, "Ok") != 0) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Incorrect status returned: %s.\n", status);
                ret = EINVAL;
                goto done;
            }
        }

        if (strcmp(key, "password") == 0) {
            ret = json_unpack_password(jobj, &password);
            if (ret != EOK) {
                goto done;
            }

            ret = sss_authtok_set_password(pd->authtok, password, strlen(password));
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                    "sss_authtok_set_password failed: %d.\n", ret);
            }
            goto done;
        }

        if (strcmp(key, "eidp") == 0) {
            ret = json_unpack_oauth2_code(tmp_ctx, pd->json_auth_msg, &oauth2_code);
            if (ret != EOK) {
                goto done;
            }

            ret = sss_authtok_set_oauth2(pd->authtok, oauth2_code,
                                         strlen(oauth2_code));
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "sss_authtok_set_oauth2 failed: %d.\n", ret);
            }
            goto done;
        }

        if (strncmp(key, "smartcard", strlen("smartcard")) == 0) {
            ret = json_unpack_smartcard(tmp_ctx, jobj, &pin, &cai);
            if (ret != EOK) {
                goto done;
            }

            ret = sss_authtok_set_sc(pd->authtok, SSS_AUTHTOK_TYPE_SC_PIN,
                                     pin, strlen(pin),
                                     cai->token_name, strlen(cai->token_name),
                                     cai->module_name, strlen(cai->module_name),
                                     cai->key_id, strlen(cai->key_id),
                                     cai->label, strlen(cai->label));
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "sss_authtok_set_sc failed: %d.\n", ret);
            }
            goto done;
        }

        if (strcmp(key, "passkey") == 0) {
            ret = json_unpack_passkey(jobj, &pin, &passkey_kerberos, &crypto_challenge);
            if (ret != EOK) {
                goto done;
            }

            if (passkey_kerberos) {
                if (pin != NULL && pin[0] != '\0') {
                    user_verification = talloc_strdup(tmp_ctx, "true");
                } else {
                    user_verification = talloc_strdup(tmp_ctx, "false");
                }
                ret = sss_authtok_set_passkey_krb(pd->authtok, user_verification, crypto_challenge, pin);
                if (ret != EOK) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "sss_authtok_set_passkey_krb failed: %d.\n", ret);
                    goto done;
                }
            } else {
                ret = sss_authtok_set_local_passkey_pin(pd->authtok, pin);
                if (ret != EOK) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "sss_authtok_set_local_passkey_pin failed: %d.\n",
                          ret);
                    goto done;
                }
            }
            goto done;
        }
    }

    DEBUG(SSSDBG_CRIT_FAILURE, "Unknown authentication mechanism\n");
    ret = EINVAL;

done:
    if (jroot != NULL) {
        json_decref(jroot);
    }
    talloc_free(tmp_ctx);

    return ret;
}

bool is_pam_json_enabled(char **json_services,
                         char *service)
{
    if (json_services == NULL) {
        return false;
    }

    if (strcmp(json_services[0], "-") == 0) {
        /* Dash is used to disable the JSON protocol */
        DEBUG(SSSDBG_TRACE_FUNC, "Dash - was used as a PAM service name. "
              "JSON protocol is disabled.\n");
        return false;
    }

    return string_in_list(service, json_services, true);
}
