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

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include "responder/pam/pamsrv.h"
#include "util/debug.h"

#include "pamsrv_json.h"


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
               const char **_oauth2_init_prompt, const char **_oauth2_link_prompt)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *password_prompt = NULL;
    char *oauth2_init_prompt = NULL;
    char *oauth2_link_prompt = NULL;
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

    *_password_prompt = talloc_steal(mem_ctx, password_prompt);
    *_oauth2_init_prompt = talloc_steal(mem_ctx, oauth2_init_prompt);
    *_oauth2_link_prompt = talloc_steal(mem_ctx, oauth2_link_prompt);
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
                       json_t **_list_mech)
{
    json_t *root = NULL;
    json_t *json_pass = NULL;
    json_t *json_oauth2 = NULL;
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
                                "init_prompt", oauth2_init_prompt,
                                "link_prompt", oauth2_link_prompt,
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

    *_list_mech = root;
    ret = EOK;

done:
    if (ret != EOK) {
        json_decref(root);
    }

    return ret;
}

errno_t
json_format_priority(bool password_auth, bool oauth2_auth, json_t **_priority)
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

    if (oauth2_auth) {
        json_priority = json_string("eidp");
        ret = json_array_append_new(root, json_priority);
        if (ret == -1) {
            DEBUG(SSSDBG_OP_FAILURE, "json_array_append failed.\n");
            json_decref(json_priority);
            ret = ENOMEM;
            goto done;
        }
    }

    if (password_auth) {
        json_priority = json_string("password");
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
                           char **_result)
{
    json_t *root = NULL;
    json_t *json_mech = NULL;
    json_t *json_priority = NULL;
    char *string = NULL;
    int ret;

    ret = json_format_mechanisms(password_auth, password_prompt,
                                 oauth2_auth, uri, code, oauth2_init_prompt,
                                 oauth2_link_prompt, &json_mech);
    if (ret != EOK) {
        goto done;
    }

    ret = json_format_priority(password_auth, oauth2_auth, &json_priority);
    if (ret != EOK) {
        json_decref(json_mech);
        goto done;
    }

    root = json_pack("{s:{s:o,s:o}}",
                     "auth-selection",
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
    const char *password_prompt = NULL;
    const char *oauth2_init_prompt = NULL;
    const char *oauth2_link_prompt = NULL;
    char *oauth2_uri = NULL;
    char *oauth2_code = NULL;
    char *result = NULL;
    bool oauth2_auth = true;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = obtain_prompts(cdb, tmp_ctx, pc_list, &password_prompt,
                         &oauth2_init_prompt, &oauth2_link_prompt);
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

    ret = json_format_auth_selection(tmp_ctx, true, password_prompt,
                                     oauth2_auth, oauth2_uri, oauth2_code,
                                     oauth2_init_prompt, oauth2_link_prompt,
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
