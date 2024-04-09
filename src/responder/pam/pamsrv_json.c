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
}; //TODO: fix with proper definition


//TODO: use add_pam_cert_response() to set data for responder?

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

    uri = talloc_strdup(tmp_ctx, (const char *)oauth2);
    if (uri == NULL) {
        ret = ENOMEM;
        goto done;
    }
    offset = strlen((const char *)uri);
    offset++;

    if (offset > len) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Trying to access data outside of the boundaries.\n");
        ret = EPERM;
        goto done;
    }
    uri_complete = talloc_strdup(tmp_ctx, (const char *)oauth2+offset);
    if (uri_complete == NULL) {
        ret = ENOMEM;
        goto done;
    }
    offset += strlen((const char *)uri_complete);
    offset++;

    if (offset > len) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Trying to access data outside of the boundaries.\n");
        ret = EPERM;
        goto done;
    }
    code = talloc_strdup(tmp_ctx, (const char *)oauth2+offset);
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

//TODO: check output data
static errno_t
obtain_sc_data(TALLOC_CTX *mem_ctx, struct pam_data *pd, char **_name,
               char **_prompt)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct cert_auth_info *cai = NULL;
    uint8_t *sc = NULL;
    int32_t len;
    int32_t offset;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    //TODO: check also SSS_PAM_CERT_INFO_WITH_HINT
    ret = pam_get_response_data(tmp_ctx, pd, SSS_PAM_CERT_INFO, &sc, &len);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to get SSS_PAM_CERT_INFO, ret %d.\n",
              ret);
        goto done;
    }

    cai = talloc_zero(tmp_ctx, struct cert_auth_info);
    if (cai == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
        ret = ENOMEM;
        goto done;
    }

    cai->cert_user = talloc_strdup(tmp_ctx, (const char *)sc);
    if (cai->cert_user == NULL) {
        ret = ENOMEM;
        goto done;
    }
    offset = strlen((const char *)cai->cert_user);
    offset++;

    if (offset > len) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Trying to access data outside of the boundaries.\n");
        ret = EPERM;
        goto done;
    }
    cai->token_name = talloc_strdup(tmp_ctx, (const char *)sc+offset);
    if (cai->token_name == NULL) {
        ret = ENOMEM;
        goto done;
    }
    offset += strlen((const char *)cai->token_name);
    offset++;

    if (offset > len) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Trying to access data outside of the boundaries.\n");
        ret = EPERM;
        goto done;
    }
    cai->module_name = talloc_strdup(tmp_ctx, (const char *)sc+offset);
    if (cai->module_name == NULL) {
        ret = ENOMEM;
        goto done;
    }
    offset += strlen((const char *)cai->token_name);
    offset++;

    if (offset > len) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Trying to access data outside of the boundaries.\n");
        ret = EPERM;
        goto done;
    }
    cai->key_id = talloc_strdup(tmp_ctx, (const char *)sc+offset);
    if (cai->key_id == NULL) {
        ret = ENOMEM;
        goto done;
    }
    offset += strlen((const char *)cai->key_id);
    offset++;

    if (offset > len) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Trying to access data outside of the boundaries.\n");
        ret = EPERM;
        goto done;
    }
    cai->label = talloc_strdup(tmp_ctx, (const char *)sc+offset);
    if (cai->label == NULL) {
        ret = ENOMEM;
        goto done;
    }
    offset += strlen((const char *)cai->label);
    offset++;

    if (offset > len) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Trying to access data outside of the boundaries.\n");
        ret = EPERM;
        goto done;
    }
    cai->prompt_str = talloc_strdup(tmp_ctx, (const char *)sc+offset);
    if (cai->prompt_str == NULL) {
        ret = ENOMEM;
        goto done;
    }
    offset += strlen((const char *)cai->prompt_str);
    offset++;

    if (offset > len) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Trying to access data outside of the boundaries.\n");
        ret = EPERM;
        goto done;
    }
    cai->pam_cert_user = talloc_strdup(tmp_ctx, (const char *)sc+offset);
    if (cai->pam_cert_user == NULL) {
        ret = ENOMEM;
        goto done;
    }
    offset += strlen((const char *)cai->pam_cert_user);
    offset++;

    DEBUG(SSSDBG_OP_FAILURE,
          "ikertxo: cert_user %s, token_name %s, module_name %s, key_id %s,"
          "label %s, prompt_str %s, pam_cert_user %s.\n",
          cai->cert_user, cai->token_name, cai->module_name, cai->key_id,
          cai->label, cai->prompt_str, cai->pam_cert_user); //TODO: delete or change debug level

    *_name = talloc_strdup(mem_ctx, "smartcard ID1"); //TODO: replace by talloc_steal
    *_prompt = talloc_strdup(mem_ctx, "Enter PIN:"); //TODO: replace by talloc_steal
    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
json_format_mechanisms(bool password_auth, const char *password_prompt,
                       bool oauth2_auth, const char *uri, const char *code,
                       bool sc_auth, const char *sc_name, const char *sc_prompt,
                       json_t **_list_mech)
{
    json_t *root = NULL;
    json_t *json_pass = NULL;
    json_t *json_oauth2 = NULL;
    json_t *json_sc = NULL;
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
                                "init_prompt", "Log In",
                                "link_prompt", "Log in online with another device",
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
        json_sc = json_pack("{s:s,s:s,s:s}",
                              "name", sc_name,
                              "role", "smartcard",
                              "prompt", sc_prompt);
        if (json_sc == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "json_pack failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = json_object_set_new(root, sc_name, json_sc); //TODO: review `name`
        if (ret == -1) {
            DEBUG(SSSDBG_OP_FAILURE, "json_array_append failed.\n");
            json_decref(json_pass);
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
json_format_priority(bool password_auth, bool oauth2_auth, bool sc_auth,
                     const char *sc_name, json_t **_priority)
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

    if (sc_auth) {
        json_priority = json_string(sc_name); //TODO: change
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
                           bool sc_auth, const char *sc_name,
                           const char *sc_prompt,
                           char **_result)
{
    json_t *root = NULL;
    json_t *json_mech = NULL;
    json_t *json_priority = NULL;
    char *string = NULL;
    int ret;

    ret = json_format_mechanisms(password_auth, password_prompt,
                                 oauth2_auth, uri, code,
                                 sc_auth, sc_name, sc_prompt,
                                 &json_mech);
    if (ret != EOK) {
        goto done;
    }

    ret = json_format_priority(password_auth, oauth2_auth, sc_auth, sc_name,
                               &json_priority);
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
generate_json_auth_message(struct confdb_ctx *cdb, struct pam_data *_pd)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *password_prompt = NULL;
    char *oauth2_uri = NULL;
    char *oauth2_code = NULL;
    char *sc_name = NULL;
    char *sc_prompt = NULL;
    char *result = NULL;
    bool oauth2_auth = true;
    bool sc_auth = true;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = confdb_get_string(cdb, tmp_ctx, CONFDB_PC_CONF_ENTRY, CONFDB_PC_PASSWORD_PROMPT,
                            "", &password_prompt);
    if (ret != EOK) {
        goto done;
    }

    ret = obtain_oauth2_data(tmp_ctx, _pd, &oauth2_uri, &oauth2_code);
    if (ret == ENOENT) {
        oauth2_auth = false;
    } else if (ret != EOK) {
        goto done;
    }

    ret = obtain_sc_data(tmp_ctx, _pd, &sc_name, &sc_prompt);
    //TODO: review the following if/elseif block
    if (ret == ENOENT) {
        sc_auth = false;
    } else if (ret != EOK) {
        goto done;
    }

    ret = json_format_auth_selection(tmp_ctx, true, password_prompt,
                                     oauth2_auth, oauth2_uri, oauth2_code,
                                     sc_auth, sc_name, sc_prompt,
                                     &result);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_OP_FAILURE, "ikertxo: result %s.\n", result); //TODO: delete

    ret = pam_add_response(_pd, SSS_PAM_JSON_AUTH_INFO, strlen(result)+1,
                           (const uint8_t *)result);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
        goto done;
    }
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
json_unpack_auth_reply(struct pam_data *pd)
{
    json_t *jroot = NULL;
    json_t *json_data = NULL;
    json_error_t jret;
    char *status = NULL;
    char *password = NULL;
    int ret = EOK;

    jroot = json_loads(pd->json_auth_selected, 0, &jret);
    if (jroot == NULL) {
        ret = EINVAL;
        goto done;
    }

    ret = json_unpack(jroot, "{s:{s:s,s:o}}", "auth-selection",
                      "status", &status, "password", &json_data);
    if (ret == 0) {
        if (strcmp(status, "Ok") != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "json_unpack for password failed: %s.\n", status);
            ret = EINVAL;
            goto done;
        }

        ret = json_unpack_password(json_data, &password);
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

    ret = json_unpack(jroot, "{s:{s:s,s:o}}", "auth-selection",
                      "status", &status, "eidp", &json_data);
    if (ret == 0) {
        if (strcmp(status, "Ok") != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "json_unpack for eidp failed: %s.\n", status);
            ret = EINVAL;
        }
        goto done;
    }

    DEBUG(SSSDBG_CRIT_FAILURE, "Unknown authentication mechanism\n");
    ret = EINVAL;

done:
    if (jroot != NULL) {
        json_decref(jroot);
    }

    return ret;
}

bool is_pam_json_enabled(const char **json_services,
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

    return string_in_list(service, discard_const(json_services), true);
}
