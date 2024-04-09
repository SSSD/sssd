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
obtain_oauth2_data(TALLOC_CTX *mem_ctx, struct pam_data *pd, char **_uri,
                   char **_code)
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

    *_uri = talloc_steal(mem_ctx, uri);
    *_code = talloc_steal(mem_ctx, code);
    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t
obtain_prompts(struct confdb_ctx *cdb, TALLOC_CTX *mem_ctx,
               struct prompt_config **pc_list, const char **_password_prompt,
               const char **_oauth2_init_prompt, const char **_oauth2_link_prompt,
               const char **_sc_init_prompt, const char **_sc_pin_prompt)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *password_prompt = NULL;
    char *oauth2_init_prompt = NULL;
    char *oauth2_link_prompt = NULL;
    char *sc_init_prompt = NULL;
    char *sc_pin_prompt = NULL;
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

    *_password_prompt = talloc_steal(mem_ctx, password_prompt);
    *_oauth2_init_prompt = talloc_steal(mem_ctx, oauth2_init_prompt);
    *_oauth2_link_prompt = talloc_steal(mem_ctx, oauth2_link_prompt);
    *_sc_init_prompt = talloc_steal(mem_ctx, sc_init_prompt);
    *_sc_pin_prompt = talloc_steal(mem_ctx, sc_pin_prompt);
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

errno_t
get_cert_names(TALLOC_CTX *mem_ctx, struct cert_auth_info *cert_list,
               char ***_names)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct cert_auth_info *item = NULL;
    char **names = NULL;
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

    i = 0;
    DLIST_FOR_EACH(item, cert_list) {
        names[i] = talloc_strdup(names, item->prompt_str);
        if (names[i] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }
        i++;
    }
    names[i] = NULL;

    *_names = talloc_steal(mem_ctx, names);
    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
json_format_mechanisms(bool password_auth, const char *password_prompt,
                       bool oauth2_auth, const char *uri, const char *code,
                       const char *oauth2_init_prompt,
                       const char *oauth2_link_prompt,
                       bool sc_auth, char **sc_names,
                       const char *sc_init_prompt,
                       const char *sc_pin_prompt,
                       json_t **_list_mech)
{
    json_t *root = NULL;
    json_t *json_pass = NULL;
    json_t *json_oauth2 = NULL;
    json_t *json_sc = NULL;
    char *key = NULL;
    int ret;

    root = json_object();
    if (root == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "json_array failed.\n");
        ret = ENOMEM;
        goto done;
    }

    if (password_auth) {
        json_pass = json_pack("{s:s,s:s,s:s}",
                              "name", "Password",
                              "role", "password",
                              "prompt", password_prompt);
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

    if (oauth2_auth) {
        json_oauth2 = json_pack("{s:s,s:s,s:s,s:s,s:s,s:s,s:i}",
                                "name", "Web Login",
                                "role", "eidp",
                                "initPrompt", oauth2_init_prompt,
                                "linkPrompt", oauth2_link_prompt,
                                "uri", uri,
                                "code", code,
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

    if (sc_auth) {
        for (int i = 0; sc_names[i] != NULL; i++) {
            json_sc = json_pack("{s:s,s:s,s:b,s:s,s:s}",
                                "name", sc_names[i],
                                "role", "smartcard",
                                "selectable", true,
                                "init_instruction", sc_init_prompt,
                                "pin_prompt", sc_pin_prompt);
            if (json_sc == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "json_pack failed.\n");
                ret = ENOMEM;
                goto done;
            }

            ret = asprintf(&key, "smartcard:%d", i+1);
            if (ret == -1) {
                DEBUG(SSSDBG_OP_FAILURE, "asprintf failed.\n");
                ret = ENOMEM;
                goto done;
            }

            ret = json_object_set_new(root, key, json_sc);
            if (ret == -1) {
                DEBUG(SSSDBG_OP_FAILURE, "json_array_append failed.\n");
                json_decref(json_pass);
                ret = ENOMEM;
                goto done;
            }
            free(key);
        }
    }

    *_list_mech = root;
    ret = EOK;

done:
    if (ret != EOK) {
        json_decref(root);
    }

    return ret;
}

errno_t
json_format_priority(bool password_auth, bool oauth2_auth, bool sc_auth,
                     char **sc_names, json_t **_priority)
{
    json_t *root = NULL;
    json_t *json_priority = NULL;
    char *key = NULL;
    int ret;

    root = json_array();
    if (root == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "json_array failed.\n");
        ret = ENOMEM;
        goto done;
    }

    if (oauth2_auth) {
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

    if (sc_auth) {
        for (int i = 0; sc_names[i] != NULL; i++) {
            ret = asprintf(&key, "smartcard:%d", i+1);
            if (ret == -1) {
                DEBUG(SSSDBG_OP_FAILURE, "asprintf failed.\n");
                ret = ENOMEM;
                goto done;
            }
            json_priority = json_string(key);
            free(key);
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
    }

    if (password_auth) {
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
json_format_auth_selection(TALLOC_CTX *mem_ctx,
                           bool password_auth, const char *password_prompt,
                           bool oauth2_auth, const char *uri, const char *code,
                           const char *oauth2_init_prompt,
                           const char *oauth2_link_prompt,
                           bool sc_auth, char **sc_names,
                           const char *sc_init_prompt,
                           const char *sc_pin_prompt,
                           char **_result)
{
    json_t *root = NULL;
    json_t *json_mech = NULL;
    json_t *json_priority = NULL;
    char *string = NULL;
    int ret;

    ret = json_format_mechanisms(password_auth, password_prompt,
                                 oauth2_auth, uri, code,
                                 oauth2_init_prompt, oauth2_link_prompt,
                                 sc_auth, sc_names,
                                 sc_init_prompt, sc_pin_prompt,
                                 &json_mech);
    if (ret != EOK) {
        goto done;
    }

    ret = json_format_priority(password_auth, oauth2_auth, sc_auth, sc_names,
                               &json_priority);
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
    struct cert_auth_info *cert_list = NULL;
    const char *password_prompt = NULL;
    const char *oauth2_init_prompt = NULL;
    const char *oauth2_link_prompt = NULL;
    const char *sc_init_prompt = NULL;
    const char *sc_pin_prompt = NULL;
    char *oauth2_uri = NULL;
    char *oauth2_code = NULL;
    char **sc_names = NULL;
    char *result = NULL;
    bool oauth2_auth = true;
    bool sc_auth = true;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = obtain_prompts(cdb, tmp_ctx, pc_list, &password_prompt,
                         &oauth2_init_prompt, &oauth2_link_prompt,
                         &sc_init_prompt, &sc_pin_prompt);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failure to obtain the prompts.\n");
        goto done;
    }

    ret = obtain_oauth2_data(tmp_ctx, _pd, &oauth2_uri, &oauth2_code);
    if (ret == ENOENT) {
        oauth2_auth = false;
    } else if (ret != EOK) {
        goto done;
    }

    ret = get_cert_list(tmp_ctx, _pd, &cert_list);
    if (ret == ENOENT) {
        sc_auth = false;
    } else if (ret != EOK) {
        goto done;
    }

    ret = get_cert_names(tmp_ctx, cert_list, &sc_names);
    if (ret != EOK) {
        goto done;
    }

    ret = json_format_auth_selection(tmp_ctx, true, password_prompt,
                                     oauth2_auth, oauth2_uri, oauth2_code,
                                     oauth2_init_prompt, oauth2_link_prompt,
                                     sc_auth, sc_names,
                                     sc_init_prompt, sc_pin_prompt,
                                     &result);
    if (ret != EOK) {
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
json_unpack_auth_reply(struct pam_data *pd)
{
    TALLOC_CTX *tmp_ctx = NULL;
    json_t *jroot = NULL;
    json_t *jauth_selection = NULL;
    json_t *jobj = NULL;
    json_error_t jret;
    const char *key = NULL;
    const char *status = NULL;
    char *password = NULL;
    char *oauth2_code = NULL;
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
