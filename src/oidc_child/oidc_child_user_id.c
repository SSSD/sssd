/*
    SSSD

    Helper child for OIDC - user identifier extraction

    Copyright (C) 2026 the authors of SSSD

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

#include <jansson.h>
#include <string.h>

#include "util/util.h"
#include "util/crypto/sss_crypto.h"
#include "oidc_child/oidc_child_util.h"

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

/* Entra ID onPremisesImmutableId is typically the base64-encoded AD
 * objectGUID (sourceAnchor). Convert it to the same UUID string form SSSD
 * uses when storing objectGUID via guid_blob_to_string_buf(). */
#define ONPREM_IMMUTABLE_ID "onPremisesImmutableId"

static const char *get_onprem_immutable_id(TALLOC_CTX *mem_ctx,
                                           json_t *id_object)
{
    const char *immutable_id;
    unsigned char *guid_bytes = NULL;
    size_t decoded_len = 0;
    char uuid_str[GUID_STR_BUF_SIZE];
    errno_t ret;

    if (!json_is_string(id_object)) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unexpected onPremisesImmutableId type.\n");
        return NULL;
    }

    immutable_id = json_string_value(id_object);
    if (immutable_id == NULL || *immutable_id == '\0') {
        DEBUG(SSSDBG_TRACE_FUNC, "Empty onPremisesImmutableId value.\n");
        return NULL;
    }

    guid_bytes = sss_base64_decode(mem_ctx, immutable_id, &decoded_len);
    if (guid_bytes == NULL || decoded_len != GUID_BIN_LENGTH) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to decode onPremisesImmutableId as objectGUID "
              "(decoded length [%zu], expected [%d]).\n",
              decoded_len, GUID_BIN_LENGTH);
        talloc_free(guid_bytes);
        return NULL;
    }

    ret = guid_blob_to_string_buf(guid_bytes, uuid_str, sizeof(uuid_str));
    talloc_free(guid_bytes);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to convert objectGUID blob to string.\n");
        return NULL;
    }

    return talloc_strdup(mem_ctx, uuid_str);
}

static const char *identifier_from_attr(TALLOC_CTX *mem_ctx,
                                        json_t *userinfo,
                                        const char *attr_name,
                                        const char *user_info_type)
{
    json_t *id_object;
    const char *user_identifier = NULL;

    id_object = json_object_get(userinfo, attr_name);
    if (id_object == NULL || json_is_null(id_object)) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Attribute [%s] not present in %s data.\n",
              attr_name,
              user_info_type != NULL ? user_info_type : "userinfo");
        return NULL;
    }

    if (strcmp(attr_name, ONPREM_IMMUTABLE_ID) == 0) {
        user_identifier = get_onprem_immutable_id(mem_ctx, id_object);
    } else {
        user_identifier = get_id_string(mem_ctx, id_object);
    }

    if (user_identifier == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to get user identifier from attribute [%s].\n",
              attr_name);
    }

    return user_identifier;
}

const char *get_user_identifier(TALLOC_CTX *mem_ctx, json_t *userinfo,
                                const char *user_identifier_attr,
                                const char *user_info_type)
{
    const char *user_identifier = NULL;
    static const char *default_attrs[] = { "sub", "id", NULL };
    const char *configured_attrs[2] = { NULL, NULL };
    const char **attr_lists[2];
    size_t n_lists = 0;
    size_t list_i;
    size_t c;

    if (userinfo == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing userinfo data.\n");
        return NULL;
    }

    /* Prefer the configured attribute when set, then fall back to the
     * provider defaults. Fallback matters for hybrid Entra deployments that
     * also contain cloud-only users without onPremisesImmutableId. */
    if (user_identifier_attr != NULL && *user_identifier_attr != '\0') {
        configured_attrs[0] = user_identifier_attr;
        attr_lists[n_lists++] = configured_attrs;
    }
    attr_lists[n_lists++] = default_attrs;

    for (list_i = 0; list_i < n_lists && user_identifier == NULL; list_i++) {
        for (c = 0; attr_lists[list_i][c] != NULL; c++) {
            /* Skip default attrs already tried as the configured attr. */
            if (list_i > 0 && user_identifier_attr != NULL
                    && strcmp(attr_lists[list_i][c],
                              user_identifier_attr) == 0) {
                continue;
            }

            user_identifier = identifier_from_attr(mem_ctx, userinfo,
                                                   attr_lists[list_i][c],
                                                   user_info_type);
            if (user_identifier != NULL) {
                break;
            }
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

