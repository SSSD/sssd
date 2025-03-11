/*
    SSSD

    Helper child for reading user and group information form IdPs

    Authors:
        Sumit Bose <sbose@redhat.com>

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

#include "oidc_child/oidc_child_util.h"

#include "util/util.h"

#define IS_ID_CMD(cmd) ( \
    cmd == GET_USER || cmd == GET_USER_GROUPS \
                              || cmd == GET_GROUP \
                              || cmd == GET_GROUP_MEMBERS )

/* The following function will lookup users and groups based on Mircosoft's
 * Graph API as described in
 * https://learn.microsoft.com/de-de/graph/api/overview */
errno_t entra_id_lookup(TALLOC_CTX *mem_ctx, enum oidc_cmd oidc_cmd,
                        char *idp_type,
                        char *input, enum search_str_type input_type,
                        bool libcurl_debug, const char *ca_db,
                        const char *client_id, const char *client_secret,
                        const char *token_endpoint, const char *scope,
                        const char *bearer_token, struct rest_ctx *rest_ctx,
                        char **out)
{
    errno_t ret;
    char *uri;
    char *filter;
    char *filter_enc;
    const char *obj_id;
    const char **id_list;
    char *short_name;
    char *sep;
    char *tmp;
    struct name_and_type_identifier entra_name_and_type_identifier = {
                            .user_identifier_attr = "userPrincipalName",
                            .group_identifier_attr = "groupTypes",
                            .user_name_attr = "userPrincipalName",
                            .group_name_attr = "displayName" };

    switch (oidc_cmd) {
    case GET_USER:
    case GET_USER_GROUPS:
        sep = strrchr(input, '@');
        if (sep == NULL || sep == input) {
            filter = talloc_asprintf(rest_ctx, "startsWith(userPrincipalName,'%s@')", input);
        } else {
            filter = talloc_asprintf(rest_ctx,
                                     "mail eq '%s' or userPrincipalName eq '%s'",
                                     input, input);
        }
        break;
    case GET_GROUP:
    case GET_GROUP_MEMBERS:
        sep = strrchr(input, '@');
        if (sep == NULL || sep == input) {
            filter = talloc_asprintf(rest_ctx, "displayName eq '%s'", input);
        } else {
            short_name = talloc_strndup(rest_ctx, input, sep - input);
            if (short_name == NULL) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to generate short name, using plain input [%s].\n",
                      input);
                filter = talloc_asprintf(rest_ctx, "displayName eq '%s'", input);
            } else {
                filter = talloc_asprintf(rest_ctx,
                                         "displayName eq '%s' or displayName eq '%s'",
                                         input, short_name);
            }
        }
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unknown command [%d].\n", oidc_cmd);
        ret = EINVAL;
        goto done;
    }

    if (filter == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to create user search filter.\n");
        ret = ENOMEM;
        goto done;
    }

    filter_enc = url_encode_string(rest_ctx, filter);
    if (filter_enc == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to encode user search filter.\n");
        ret = ENOMEM;
        goto done;
    }

    switch (oidc_cmd) {
    case GET_USER:
    case GET_USER_GROUPS:
        uri = talloc_asprintf(rest_ctx, "https://graph.microsoft.com/v1.0/users?$filter=%s", filter_enc);
        break;
    case GET_GROUP:
    case GET_GROUP_MEMBERS:
        uri = talloc_asprintf(rest_ctx, "https://graph.microsoft.com/v1.0/groups?$filter=%s", filter_enc);
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unknown command [%d].\n", oidc_cmd);
        ret = EINVAL;
        goto done;
    }

    if (uri == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate lookup URI.\n");
        ret = ENOMEM;
        goto done;
    }

    clean_http_data(rest_ctx);
    ret = do_http_request(rest_ctx, uri, NULL, bearer_token);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "User search request failed.\n");
        goto done;
    }

    if (oidc_cmd == GET_USER || oidc_cmd == GET_GROUP) {
        ret = EOK;
        goto done;
    }

    obj_id = get_str_attr_from_embed_json_string(rest_ctx,
                                                 get_http_data(rest_ctx),
                                                 "value", "id");
    if (obj_id == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to read mandatory object id.\n");
        ret = EINVAL;
        goto done;
    }

    switch (oidc_cmd) {
    case GET_USER_GROUPS:
        uri = talloc_asprintf(rest_ctx,
                              "https://graph.microsoft.com/v1.0/users/%s/getMemberGroups",
                              obj_id);
        break;
    case GET_GROUP_MEMBERS:
        uri = talloc_asprintf(rest_ctx,
                              "https://graph.microsoft.com/v1.0/groups/%s/members",
                              obj_id);
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unknown command [%d].\n", oidc_cmd);
        ret = EINVAL;
        goto done;
    }

    if (uri == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate lookup URI.\n");
        ret = ENOMEM;
        goto done;
    }

    clean_http_data(rest_ctx);
    switch (oidc_cmd) {
    case GET_USER_GROUPS:
        ret = do_http_request_json_data(rest_ctx, uri, "{\"securityEnabledOnly\": true}", bearer_token);
        break;
    case GET_GROUP_MEMBERS:
        ret = do_http_request_json_data(rest_ctx, uri, NULL, bearer_token);
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unknown command [%d].\n", oidc_cmd);
        ret = EINVAL;
        goto done;
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Member(of) search request failed.\n");
        goto done;
    }

    if (oidc_cmd == GET_GROUP_MEMBERS) {
        goto done;
    }

    id_list = get_str_list_from_json_string(rest_ctx, get_http_data(rest_ctx),
                                            "value");
    if (id_list == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get id list.\n");
        ret = EINVAL;
        goto done;
    }

    if (out != NULL) {
        *out = get_json_string_array_by_id_list(mem_ctx, rest_ctx, bearer_token,
                                                id_list);
        if (*out == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to get objects by ID.\n");
            ret = EIO;
            goto done;
        }
    }

done:
    if (ret == EOK && out != NULL && oidc_cmd != GET_USER_GROUPS) {
        *out = get_json_string_array_from_json_string(mem_ctx, get_http_data(rest_ctx), "value");
        if (*out == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to copy output data.\n");
            ret = ENOMEM;
        }
    }

    if (ret == EOK && out != NULL) {
        ret = add_posix_to_json_string_array(mem_ctx,
                                             &entra_name_and_type_identifier,
                                             '@', *out, &tmp);
        talloc_free(*out);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to add POSIX data.\n");
            *out = NULL;
        } else {
            *out = tmp;
        }
    }

    return ret;
}

/* The following function will lookup users and groups based on Keycloak's
 * REST API as described in
 * https://www.keycloak.org/docs-api/latest/rest-api/index.html */
errno_t keycloak_lookup(TALLOC_CTX *mem_ctx, enum oidc_cmd oidc_cmd,
                        char *idp_type,
                        char *input, enum search_str_type input_type,
                        bool libcurl_debug, const char *ca_db,
                        const char *client_id, const char *client_secret,
                        const char *token_endpoint, const char *scope,
                        const char *bearer_token, struct rest_ctx *rest_ctx,
                        char **out)
{
    errno_t ret;
    char *uri;
    char *filter;
    char *filter_enc;
    char *input_enc;
    const char *obj_id;
    char *short_name;
    char *sep;
    char *base_url;
    char *last;
    struct name_and_type_identifier keycloak_name_and_type_identifier = {
                            .user_identifier_attr = "username",
                            .group_identifier_attr = "name",
                            .user_name_attr = "username",
                            .group_name_attr = "name" };

    base_url = strchr(idp_type, ':');
    if (base_url == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Unexpected IdP type [%s].\n", idp_type);
        return EINVAL;
    }

    base_url++;
    if (*base_url == '\0' || strncasecmp(base_url, "http", 4) != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing base URL in IdP type [%s].\n",
                                 idp_type);
        return EINVAL;
    }

    /* remove trailing '/' from the base URL, we will add it later for the
     * individual requests and it looks like older Keycloak versions have an
     * issue with multiple '/'s in a row. */
    last = base_url + strlen(base_url) - 1;
    while (last > base_url && *last == '/') last--;
    last[1] = '\0';

    input_enc = url_encode_string(rest_ctx, input);
    if (input_enc == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to encode input [%s].\n", input);
        return EINVAL;
    }

    switch (oidc_cmd) {
    case GET_USER:
    case GET_USER_GROUPS:
        filter = talloc_asprintf(rest_ctx, "username=%s&exact=true", input_enc);
        break;
    case GET_GROUP:
    case GET_GROUP_MEMBERS:
        sep = strrchr(input, '@');
        if (sep == NULL && sep != input) {
            filter = talloc_asprintf(rest_ctx, "search=%s&exact=true&populateHierarchy=false&briefRepresentation=false", input_enc);
        } else {
            short_name = talloc_strndup(rest_ctx, input, sep - input);
            if (short_name == NULL) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to generate short name, using plain input [%s].\n",
                      input);
                filter = talloc_asprintf(rest_ctx, "search=%s&exact=true",
                                                   input_enc);
            } else {
                filter = talloc_asprintf(rest_ctx, "search=%s&exact=true",
                                                   short_name);
            }
        }
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unknown command [%d].\n", oidc_cmd);
        ret = EINVAL;
        goto done;
    }

    if (filter == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to create user search filter.\n");
        ret = ENOMEM;
        goto done;
    }

    filter_enc = filter;

    switch (oidc_cmd) {
    case GET_USER:
    case GET_USER_GROUPS:
        uri = talloc_asprintf(rest_ctx, "%s/users?%s", base_url, filter_enc);
        break;
    case GET_GROUP:
    case GET_GROUP_MEMBERS:
        uri = talloc_asprintf(rest_ctx, "%s/groups?%s", base_url, filter_enc);
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unknown command [%d].\n", oidc_cmd);
        ret = EINVAL;
        goto done;
    }

    if (uri == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate lookup URI.\n");
        ret = ENOMEM;
        goto done;
    }

    clean_http_data(rest_ctx);
    ret = do_http_request(rest_ctx, uri, NULL, bearer_token);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "User search request failed.\n");
        goto done;
    }

    if (oidc_cmd == GET_USER || oidc_cmd == GET_GROUP) {
        ret = EOK;
        goto done;
    }

    obj_id = get_str_attr_from_json_array_string(rest_ctx, get_http_data(rest_ctx),
                                                 "id");
    if (obj_id == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to read mandatory object id.\n");
        ret = EINVAL;
        goto done;
    }

    switch (oidc_cmd) {
    case GET_USER_GROUPS:
        uri = talloc_asprintf(rest_ctx,
                              "%s/users/%s/groups?briefRepresentation=false", base_url, obj_id);
        break;
    case GET_GROUP_MEMBERS:
        uri = talloc_asprintf(rest_ctx,
                              "%s/groups/%s/members", base_url, obj_id);
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unknown command [%d].\n", oidc_cmd);
        ret = EINVAL;
        goto done;
    }

    if (uri == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate lookup URI.\n");
        ret = ENOMEM;
        goto done;
    }

    clean_http_data(rest_ctx);
    switch (oidc_cmd) {
    case GET_USER_GROUPS:
        ret = do_http_request_json_data(rest_ctx, uri, NULL, bearer_token);
        break;
    case GET_GROUP_MEMBERS:
        ret = do_http_request_json_data(rest_ctx, uri, NULL, bearer_token);
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unknown command [%d].\n", oidc_cmd);
        ret = EINVAL;
        goto done;
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Member(of) search request failed.\n");
        goto done;
    }

    ret = EOK;

done:
    if (ret == EOK && out != NULL) {
        ret = add_posix_to_json_string_array(mem_ctx,
                                             &keycloak_name_and_type_identifier,
                                             0, get_http_data(rest_ctx), out);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to add POSIX data.\n");
        }
    }

    return ret;
}

errno_t oidc_get_id(TALLOC_CTX *mem_ctx, enum oidc_cmd oidc_cmd,
                    char *idp_type,
                    char *input, enum search_str_type input_type,
                    bool libcurl_debug, const char *ca_db,
                    const char *client_id, const char *client_secret,
                    const char *token_endpoint, const char *scope, char **out)
{
    errno_t ret;
    struct rest_ctx *rest_ctx;
    char *cli_cred_reply;
    const char *bearer_token;

    if (!IS_ID_CMD(oidc_cmd)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported command [%d].\n", oidc_cmd);
        return EINVAL;
    }

    if (client_id == NULL || client_secret == NULL || token_endpoint == NULL
            || input == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing required argument.\n");
        return EINVAL;
    }

    rest_ctx = get_rest_ctx(mem_ctx, libcurl_debug, ca_db);
    if (rest_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get REST context.\n");
        return ENOMEM;
    }

    ret = client_credentials_grant(rest_ctx, token_endpoint,
                                   client_id, client_secret, scope);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to get access token with client credentials grant.\n");
        goto done;
    }

    cli_cred_reply = talloc_strdup(rest_ctx, get_http_data(rest_ctx));
    bearer_token = get_bearer_token(rest_ctx, cli_cred_reply);

    if (input_type ==TYPE_OBJECT_ID) {
        ret = ENOTSUP;
        goto done;
    }

    if (idp_type != NULL && strncasecmp(idp_type, "keycloak:",9) == 0) {
        ret = keycloak_lookup(mem_ctx, oidc_cmd, idp_type, input, input_type,
                              libcurl_debug, ca_db, client_id, client_secret,
                              token_endpoint, scope, bearer_token, rest_ctx,
                              out);
    } else if (idp_type == NULL || strcasecmp(idp_type, "entra_id") == 0) {
        ret = entra_id_lookup(mem_ctx, oidc_cmd, idp_type, input, input_type,
                              libcurl_debug, ca_db, client_id, client_secret,
                              token_endpoint, scope, bearer_token, rest_ctx,
                              out);
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported IdP type [%s].\n", idp_type);
        ret = EINVAL;
        goto done;
    }

done:

    talloc_free(rest_ctx);
    return ret;
}
