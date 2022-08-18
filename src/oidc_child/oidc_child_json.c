
/*
    SSSD

    Helper child for OIDC and OAuth 2.0 Device Authorization Grant
    JSON utilities

    Authors:
        Sumit Bose <sbose@redhat.com>

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

#include <jose/jws.h>
#include <jose/b64.h>
#include <jansson.h>

#include "util/strtonum.h"
#include "oidc_child/oidc_child_util.h"

static char *get_json_string(TALLOC_CTX *mem_ctx, const json_t *root,
                             const char *attr)
{
    json_t *tmp;
    char *str;

    tmp = json_object_get(root, attr);
    if (!json_is_string(tmp)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Result does not contain the '%s' string.\n", attr);
        return NULL;
    }

    str = talloc_strdup(mem_ctx, json_string_value(tmp));
    if (str == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to copy '%s' string.\n", attr);
        return NULL;
    }

    return str;
}

static int get_json_integer(const json_t *root, const char *attr,
                            bool fallback_to_string)
{
    json_t *tmp;
    int val;
    char *endptr;

    tmp = json_object_get(root, attr);
    if (!json_is_integer(tmp)) {
        if (fallback_to_string) {
            if (!json_is_string(tmp) || json_string_value(tmp)== NULL) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Result does not contain the '%s' integer or string.\n",
                      attr);
                return -1;
            }

            val = (int) strtoint32(json_string_value(tmp), &endptr, 10);
            if (errno != 0 || *endptr != '\0') {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Value [%s] of attribute [%s] is not a valid integer.\n",
                      json_string_value(tmp), attr);
                return -1;
            }
            return val;
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Result does not contain the '%s' integer.\n", attr);
            return -1;
        }
    }

    return json_integer_value(tmp);
}

static char *get_json_scope(TALLOC_CTX *mem_ctx, const json_t *root,
                            const char *attr)
{
    json_t *tmp;
    json_t *s;
    size_t index;
    char *str = NULL;

    tmp = json_object_get(root, attr);
    if (!json_is_array(tmp)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Result does not contain the '%s' array.\n", attr);
        return NULL;
    }

    json_array_foreach(tmp, index, s) {
        if (!json_is_string(s)) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to read supported scopes.\n");
            talloc_free(str);
            return NULL;
        }

        if (str == NULL) {
            str = talloc_strdup(mem_ctx, json_string_value(s));
        } else {
            str = talloc_asprintf_append(str, "%%20%s", json_string_value(s));
        }
        if (str == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to copy '%s' string.\n", attr);
            return NULL;
        }

    }

    return str;
}

static errno_t get_endpoints(json_t *inp, struct devicecode_ctx *dc_ctx)
{
    int ret;

    dc_ctx->device_authorization_endpoint = get_json_string(dc_ctx, inp,
                                               "device_authorization_endpoint");
    if (dc_ctx->device_authorization_endpoint == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing device_authorization_endpoint in "
                                   "openid configuration.\n");
        ret = EINVAL;
        goto done;
    }
    dc_ctx->token_endpoint = get_json_string(dc_ctx, inp, "token_endpoint");
    if (dc_ctx->token_endpoint == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing token_endpoint in openid "
                                   "configuration.\n");
        ret = EINVAL;
        goto done;
    }
    dc_ctx->userinfo_endpoint = get_json_string(dc_ctx, inp,
                                                "userinfo_endpoint");
    if (dc_ctx->userinfo_endpoint == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing userinfo_endpoint in openid "
                                   "configuration.\n");
        ret = EINVAL;
        goto done;
    }

    dc_ctx->jwks_uri = get_json_string(dc_ctx, inp, "jwks_uri");
    if (dc_ctx->jwks_uri == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing jwks_uri in openid "
                                   "configuration.\n");
    }

    dc_ctx->scope = get_json_scope(dc_ctx, inp, "scopes_supported");
    if (dc_ctx->scope == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing scopes in openid "
                                   "configuration.\n");
    }

    ret = EOK;
done:
    return ret;
}

static errno_t str_to_jws(TALLOC_CTX *mem_ctx, const char *inp, json_t **jws)
{
    char *pl;
    char *sig;
    json_t *o = NULL;
    int ret;
    char *str = NULL;

    str = talloc_strdup(mem_ctx, inp);
    if (str == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to copy token string.\n");
        ret = ENOMEM;
        goto done;
    }

    pl = strchr(str, '.');
    if (pl == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "String does not look like serialized JWS, missing first '.'\n");
        ret = EINVAL;
        goto done;
    }
    *pl = '\0';
    pl++;

    sig = strchr(pl, '.');
    if (sig == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "String does not look like serialized JWS, missing second '.'\n");
        ret = EINVAL;
        goto done;
    }
    *sig = '\0';
    sig++;

    o = json_object();
    if (o == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to create JSON object.\n");
        ret = EIO;
        goto done;
    }

    ret = json_object_set_new(o, "protected", json_string(str));
    if (ret == 0) {
        ret = json_object_set_new(o, "payload", json_string(pl));
    }
    if (ret == 0) {
        ret = json_object_set_new(o, "signature", json_string(sig));
    }
    if (ret == -1) {
        json_decref(o);
        DEBUG(SSSDBG_OP_FAILURE, "json_object_set_new() failed.\n");
        ret = EINVAL;
        goto done;
    }

    *jws = o;
    ret = EOK;

done:
    talloc_free(str);
    return ret;
}

/* It looks like not all tokens can be verified even if the keys are read from
 * the URL given in the OIDC configuration URL and that it differs between
 * different IdPs. For the time being the verification code is called but
 * errors in the verification are ignored. But the debug output should help to
 * understand if and how the keys based verification can be used so that we
 * might add new options to tune the verification for different IdPs.
 */
errno_t verify_token(struct devicecode_ctx *dc_ctx)
{
    int ret;
    json_t *keys = NULL;
    json_error_t json_error;
    json_t *jws = NULL;

    ret = get_jwks(dc_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to read jwks file.\n");
        goto done;
    }

    keys = json_loads(dc_ctx->http_data, 0, &json_error);
    if (keys == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to parse jwk data from [%s] on line [%d]: [%s].\n",
              dc_ctx->jwks_uri, json_error.line, json_error.text);
        ret = EINVAL;
        goto done;
    }

    if (dc_ctx->td->id_token_str != NULL) {
        ret = str_to_jws(dc_ctx, dc_ctx->td->id_token_str, &jws);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to convert id token into jws.\n");
            dc_ctx->td->id_token_payload = NULL;
            ret = EOK;
            goto done;
        }
        if (!jose_jws_ver(NULL, jws, NULL, keys, false)) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to verify id_token.\n");
        }

        dc_ctx->td->id_token_payload = jose_b64_dec_load(json_object_get(jws,
                                                                    "payload"));

        json_decref(jws);
    }
    if (dc_ctx->td->access_token_str != NULL) {
        ret = str_to_jws(dc_ctx, dc_ctx->td->access_token_str, &jws);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to convert access_token into jws.\n");
            dc_ctx->td->access_token_payload = NULL;
            ret = EOK;
            goto done;
        }
        if (!jose_jws_ver(NULL, jws, NULL, keys, false)) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to verify access_token.\n");
        }

        dc_ctx->td->access_token_payload = jose_b64_dec_load(json_object_get(jws,
                                                                     "payload"));
        json_decref(jws);
    }

    ret = EOK;

done:
    json_decref(keys);
    clean_http_data(dc_ctx);

    return ret;
}

errno_t parse_openid_configuration(struct devicecode_ctx *dc_ctx)
{
    int ret;
    json_t *root = NULL;
    json_error_t json_error;

    root = json_loads(dc_ctx->http_data, 0, &json_error);
    if (root == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to parse json data on line [%d]: [%s].\n",
              json_error.line, json_error.text);
        ret = EINVAL;
        goto done;
    }

    ret = get_endpoints(root, dc_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get endpoints.\n");
        goto done;
    }

    clean_http_data(dc_ctx);

    ret = EOK;

done:
    json_decref(root);
    return ret;
}

errno_t parse_result(struct devicecode_ctx *dc_ctx)
{
    int ret;
    json_t *root = NULL;
    json_error_t json_error;

    root = json_loads(dc_ctx->http_data, 0, &json_error);
    if (root == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to parse json data on line [%d]: [%s].\n",
              json_error.line, json_error.text);
        ret = EINVAL;
        goto done;
    }

    dc_ctx->user_code = get_json_string(dc_ctx, root, "user_code");
    if (dc_ctx->user_code != NULL) {
        talloc_set_destructor((void *) dc_ctx->user_code, sss_erase_talloc_mem_securely);
    }
    dc_ctx->device_code = get_json_string(dc_ctx, root, "device_code");
    if (dc_ctx->device_code != NULL) {
        talloc_set_destructor((void *) dc_ctx->device_code, sss_erase_talloc_mem_securely);
    }
    dc_ctx->verification_uri = get_json_string(dc_ctx, root,
                                               "verification_uri");
    if (dc_ctx->verification_uri == NULL) {
        /* Google uses _urL rather than _urI, see e.g.
         * https://developers.google.com/identity/protocols/oauth2/limited-input-device
         * Old Azure AD v1 endpoints do the same. */
        dc_ctx->verification_uri = get_json_string(dc_ctx, root,
                                                   "verification_url");
    }
    dc_ctx->verification_uri_complete = get_json_string(dc_ctx, root,
                                                   "verification_uri_complete");
    dc_ctx->message = get_json_string(dc_ctx, root, "message");
    dc_ctx->interval = get_json_integer(root, "interval", true);
    dc_ctx->expires_in = get_json_integer(root, "expires_in", true);

    ret = EOK;

done:
    json_decref(root);
    return ret;
}

static int token_destructor(void *p)
{
    struct token_data *td = talloc_get_type(p, struct token_data);

    json_decref(td->result);

    return 0;
}

errno_t parse_token_result(struct devicecode_ctx *dc_ctx,
                           char **error_description)
{
    json_t *tmp = NULL;
    json_error_t json_error;
    json_t *result = NULL;

    *error_description = NULL;
    result = json_loads(dc_ctx->http_data, 0, &json_error);
    if (result == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to parse json data on line [%d]: [%s].\n",
              json_error.line, json_error.text);
        return EINVAL;
    }

    tmp = json_object_get(result, "error");
    if (json_is_string(tmp)) {
        if (strcmp(json_string_value(tmp), "authorization_pending") == 0) {
            json_decref(result);
            return EAGAIN;
        } else if (strcmp(json_string_value(tmp), "slow_down") == 0) {
            /* RFC 8628: "... the interval MUST be increased by 5 seconds for"
             *           "this and all subsequent requests." */
            dc_ctx->interval += 5;
            json_decref(result);
            return EAGAIN;
        } else {
            *error_description = get_json_string(dc_ctx, result,
                                                 "error_description");
            DEBUG(SSSDBG_OP_FAILURE, "Token request failed with [%s][%s].\n",
                                     json_string_value(tmp),
                                     *error_description);
            json_decref(result);
            return EIO;
        }
    }

    /* Looks like we got the tokens */
    dc_ctx->td = talloc_zero(dc_ctx, struct token_data);
    if (dc_ctx->td == NULL) {
        json_decref(result);
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to allocate memory for token data.\n");
        return ENOMEM;
    }
    talloc_set_destructor((void *) dc_ctx->td, token_destructor);
    dc_ctx->td->result = result;
    dc_ctx->td->access_token = json_object_get(dc_ctx->td->result,
                                               "access_token");
    dc_ctx->td->access_token_str = get_json_string(dc_ctx->td,
                                                   dc_ctx->td->result,
                                                   "access_token");
    dc_ctx->td->id_token = json_object_get(dc_ctx->td->result, "id_token");
    dc_ctx->td->id_token_str = get_json_string(dc_ctx->td, dc_ctx->td->result,
                                               "id_token");

    return EOK;
}

static const char *get_id_string(TALLOC_CTX *mem_ctx, json_t *id_object)
{
    switch (json_typeof(id_object)) {
    case JSON_STRING:
        return talloc_strdup(mem_ctx, json_string_value(id_object));
        break;
    case JSON_INTEGER:
        return talloc_asprintf(mem_ctx, "%" JSON_INTEGER_FORMAT,
                                        json_integer_value(id_object));
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unexpected user identifier type.\n");
    }

    return NULL;
}

const char *get_user_identifier(TALLOC_CTX *mem_ctx, json_t *userinfo,
                                const char *user_identifier_attr)
{
    json_t *id_object = NULL;
    const char *user_identifier = NULL;
    const char *id_attr_list[] = { "sub", "id", NULL };
    size_t c;

    if (user_identifier_attr != NULL) {
        id_attr_list[0] = user_identifier_attr;
        id_attr_list[1] = NULL;
    }

    for (c = 0; id_attr_list[c] != NULL; c++) {
        id_object = json_object_get(userinfo, id_attr_list[c]);
        if (id_object != NULL) {
            user_identifier = get_id_string(mem_ctx, id_object);
            if (user_identifier == NULL) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to get user identifier string.\n");
            }
            break;
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to read attribute [%s] from userinfo data.\n",
                  id_attr_list[c]);
        }
    }

    if (user_identifier == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "No attribute to identify the user found.\n");
    } else {
        DEBUG(SSSDBG_CONF_SETTINGS, "User identifier: [%s].\n",
                                    user_identifier);
    }

    return user_identifier;
}
