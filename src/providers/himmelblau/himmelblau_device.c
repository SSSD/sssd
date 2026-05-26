/*
    SSSD

    Himmelblau Provider - Device state management (sysdb storage)

    Authors:
        David Mulder <dmulder@suse.com>

    Copyright (C) 2026 SUSE

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

#include "config.h"

#include <string.h>
#include <time.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "providers/himmelblau/himmelblau_common.h"

errno_t
himmelblau_sysdb_save_device_enrollment(
    struct sss_domain_info *domain,
    const char *device_id,
    const char *auth_value,
    LoadableMsOapxbcRsaKey *transport_key,
    LoadableMsDeviceEnrolmentKey *cert_key)
{
    TALLOC_CTX *tmp_ctx;
    struct sysdb_attrs *attrs = NULL;
    char *transport_key_bytes = NULL;
    char *cert_key_bytes = NULL;
    uintptr_t transport_len = 0;
    uintptr_t cert_len = 0;
    MSAL_ERROR *error = NULL;
    errno_t ret;

    if (domain == NULL || device_id == NULL || auth_value == NULL ||
        transport_key == NULL || cert_key == NULL) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Saving device enrollment to sysdb\n");

    /* Serialize binary keys using libhimmelblau */
    error = serialize_loadable_ms_oapxbc_rsa_key(transport_key,
                                                  &transport_key_bytes,
                                                  &transport_len);
    if (error) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to serialize transport key: %s\n", error->msg);
        error_free(error);
        ret = EIO;
        goto done;
    }

    error = serialize_loadable_ms_device_enrolment_key(cert_key,
                                                        &cert_key_bytes,
                                                        &cert_len);
    if (error) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to serialize cert key: %s\n", error->msg);
        error_free(error);
        free(transport_key_bytes);
        ret = EIO;
        goto done;
    }

    /* Build sysdb attributes */
    attrs = sysdb_new_attrs(tmp_ctx);
    if (attrs == NULL) {
        free(transport_key_bytes);
        free(cert_key_bytes);
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_HIMMELBLAU_DEVICE_ID, device_id);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add device_id attribute: %d\n", ret);
        goto cleanup_keys;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_HIMMELBLAU_AUTH_VALUE, auth_value);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add auth_value attribute: %d\n", ret);
        goto cleanup_keys;
    }

    ret = sysdb_attrs_add_mem(attrs, SYSDB_HIMMELBLAU_TRANSPORT_KEY,
                             transport_key_bytes, transport_len);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add transport_key attribute: %d\n", ret);
        goto cleanup_keys;
    }

    ret = sysdb_attrs_add_mem(attrs, SYSDB_HIMMELBLAU_CERT_KEY,
                             cert_key_bytes, cert_len);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add cert_key attribute: %d\n", ret);
        goto cleanup_keys;
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_HIMMELBLAU_ENROLLED_AT, time(NULL));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add enrolled_at attribute: %d\n", ret);
        goto cleanup_keys;
    }

    /* Store in sysdb with transaction */
    ret = sysdb_transaction_start(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to start transaction: %d\n", ret);
        goto cleanup_keys;
    }

    ret = sysdb_store_custom(domain, HIMMELBLAU_DEVICE_OBJ,
                            HIMMELBLAU_DEVICE_SUBDIR, attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to store device enrollment: %d\n", ret);
        sysdb_transaction_cancel(domain->sysdb);
        goto cleanup_keys;
    }

    ret = sysdb_transaction_commit(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to commit transaction: %d\n", ret);
    } else {
        DEBUG(SSSDBG_TRACE_FUNC, "Device enrollment saved to sysdb successfully\n");
    }

cleanup_keys:
    free(transport_key_bytes);
    free(cert_key_bytes);

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
himmelblau_sysdb_load_device_enrollment(
    TALLOC_CTX *mem_ctx,
    struct sss_domain_info *domain,
    char **_device_id,
    char **_auth_value,
    LoadableMsOapxbcRsaKey **_transport_key,
    LoadableMsDeviceEnrolmentKey **_cert_key)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message **msgs;
    struct ldb_message_element *el;
    const char *attrs_list[] = {
        SYSDB_HIMMELBLAU_DEVICE_ID,
        SYSDB_HIMMELBLAU_AUTH_VALUE,
        SYSDB_HIMMELBLAU_TRANSPORT_KEY,
        SYSDB_HIMMELBLAU_CERT_KEY,
        NULL
    };
    size_t count;
    const char *device_id;
    const char *auth_value;
    MSAL_ERROR *error = NULL;
    errno_t ret;

    if (domain == NULL) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Loading device enrollment from sysdb\n");

    /* Search for device object */
    ret = sysdb_search_custom_by_name(tmp_ctx, domain,
                                      HIMMELBLAU_DEVICE_OBJ,
                                      HIMMELBLAU_DEVICE_SUBDIR,
                                      attrs_list, &count, &msgs);
    if (ret != EOK || count == 0) {
        if (ret == ENOENT || count == 0) {
            DEBUG(SSSDBG_TRACE_FUNC, "Device not enrolled (object not found)\n");
            ret = ENOENT;
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to search for device object: %d\n", ret);
        }
        goto done;
    }

    /* Extract string attributes */
    if (_device_id != NULL) {
        device_id = ldb_msg_find_attr_as_string(msgs[0], SYSDB_HIMMELBLAU_DEVICE_ID, NULL);
        if (device_id == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Device object missing device_id attribute\n");
            ret = EINVAL;
            goto done;
        }
        *_device_id = talloc_strdup(mem_ctx, device_id);
        if (*_device_id == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    if (_auth_value != NULL) {
        auth_value = ldb_msg_find_attr_as_string(msgs[0], SYSDB_HIMMELBLAU_AUTH_VALUE, NULL);
        if (auth_value == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Device object missing auth_value attribute\n");
            ret = EINVAL;
            goto done;
        }
        *_auth_value = talloc_strdup(mem_ctx, auth_value);
        if (*_auth_value == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    /* Extract binary attributes */
    if (_transport_key != NULL) {
        el = ldb_msg_find_element(msgs[0], SYSDB_HIMMELBLAU_TRANSPORT_KEY);
        if (el == NULL || el->num_values == 0) {
            DEBUG(SSSDBG_OP_FAILURE, "Device object missing transport_key attribute\n");
            ret = EINVAL;
            goto done;
        }

        error = deserialize_loadable_ms_oapxbc_rsa_key(el->values[0].data,
                                                        el->values[0].length,
                                                        _transport_key);
        if (error) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to deserialize transport key: %s\n", error->msg);
            error_free(error);
            ret = EIO;
            goto done;
        }
    }

    if (_cert_key != NULL) {
        el = ldb_msg_find_element(msgs[0], SYSDB_HIMMELBLAU_CERT_KEY);
        if (el == NULL || el->num_values == 0) {
            DEBUG(SSSDBG_OP_FAILURE, "Device object missing cert_key attribute\n");
            ret = EINVAL;
            goto done;
        }

        error = deserialize_loadable_ms_device_enrolment_key(el->values[0].data,
                                                               el->values[0].length,
                                                               _cert_key);
        if (error) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to deserialize cert key: %s\n", error->msg);
            error_free(error);
            if (_transport_key != NULL && *_transport_key != NULL) {
                loadable_ms_oapxbc_rsa_key_free(*_transport_key);
                *_transport_key = NULL;
            }
            ret = EIO;
            goto done;
        }
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Device enrollment loaded successfully from sysdb\n");
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
himmelblau_sysdb_check_device_enrolled(
    struct sss_domain_info *domain,
    bool *_enrolled)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message **msgs;
    const char *attrs_list[] = {SYSDB_HIMMELBLAU_DEVICE_ID, NULL};
    size_t count;
    errno_t ret;

    if (domain == NULL || _enrolled == NULL) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_search_custom_by_name(tmp_ctx, domain,
                                      HIMMELBLAU_DEVICE_OBJ,
                                      HIMMELBLAU_DEVICE_SUBDIR,
                                      attrs_list, &count, &msgs);
    if (ret == EOK && count > 0) {
        *_enrolled = true;
        DEBUG(SSSDBG_TRACE_FUNC, "Device is enrolled\n");
    } else if (ret == ENOENT || (ret == EOK && count == 0)) {
        *_enrolled = false;
        DEBUG(SSSDBG_TRACE_FUNC, "Device is not enrolled\n");
        ret = EOK;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to check device enrollment: %d\n", ret);
        *_enrolled = false;
        /* Propagate the error - do not mask it */
    }

    talloc_free(tmp_ctx);
    return ret;
}

errno_t
himmelblau_sysdb_delete_device_enrollment(
    struct sss_domain_info *domain)
{
    errno_t ret;

    if (domain == NULL) {
        return EINVAL;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Deleting device enrollment from sysdb\n");

    ret = sysdb_transaction_start(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to start transaction: %d\n", ret);
        return ret;
    }

    ret = sysdb_delete_custom(domain, HIMMELBLAU_DEVICE_OBJ,
                             HIMMELBLAU_DEVICE_SUBDIR);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to delete device enrollment: %d\n", ret);
        sysdb_transaction_cancel(domain->sysdb);
        return ret;
    }

    ret = sysdb_transaction_commit(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to commit transaction: %d\n", ret);
        return ret;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Device enrollment deleted successfully\n");
    return EOK;
}

errno_t
himmelblau_sysdb_save_refresh_token(
    struct sss_domain_info *domain,
    const char *username,
    const char *refresh_token)
{
    struct sysdb_attrs *attrs;
    errno_t ret;

    if (domain == NULL || username == NULL || refresh_token == NULL) {
        return EINVAL;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Saving refresh token for user %s to sysdb\n", username);

    attrs = sysdb_new_attrs(NULL);
    if (attrs == NULL) {
        return ENOMEM;
    }

    /* Use predefined SYSDB_REFRESH_TOKEN attribute (from sysdb.h) */
    ret = sysdb_attrs_add_string(attrs, SYSDB_REFRESH_TOKEN, refresh_token);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add refresh_token attribute: %d\n", ret);
        talloc_free(attrs);
        return ret;
    }

    /* Store on user object with transaction */
    ret = sysdb_transaction_start(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to start transaction: %d\n", ret);
        talloc_free(attrs);
        return ret;
    }

    ret = sysdb_set_user_attr(domain, username, attrs, SYSDB_MOD_REP);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to set user attribute: %d\n", ret);
        sysdb_transaction_cancel(domain->sysdb);
        talloc_free(attrs);
        return ret;
    }

    ret = sysdb_transaction_commit(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to commit transaction: %d\n", ret);
        talloc_free(attrs);
        return ret;
    }

    talloc_free(attrs);
    DEBUG(SSSDBG_TRACE_FUNC, "Refresh token saved successfully for user %s\n", username);
    return EOK;
}

errno_t
himmelblau_sysdb_load_refresh_token(
    TALLOC_CTX *mem_ctx,
    struct sss_domain_info *domain,
    const char *username,
    char **_refresh_token)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    const char *token;
    errno_t ret;

    if (domain == NULL || username == NULL || _refresh_token == NULL) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Loading refresh token for user %s from sysdb\n", username);

    /* Get user with refresh token attribute */
    ret = sysdb_getpwnam(tmp_ctx, domain, username, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get user %s: %d\n", username, ret);
        goto done;
    }

    if (res->count == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "User %s not found in sysdb\n", username);
        ret = ENOENT;
        goto done;
    }

    token = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_REFRESH_TOKEN, NULL);
    if (token == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "User %s exists but no refresh token cached\n", username);
        ret = ENOENT;
        goto done;
    }

    *_refresh_token = talloc_strdup(mem_ctx, token);
    if (*_refresh_token == NULL) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Refresh token loaded successfully for user %s\n", username);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
himmelblau_sysdb_delete_refresh_token(
    struct sss_domain_info *domain,
    const char *username)
{
    struct sysdb_attrs *attrs;
    errno_t ret;

    if (domain == NULL || username == NULL) {
        return EINVAL;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Deleting refresh token for user %s from sysdb\n", username);

    attrs = sysdb_new_attrs(NULL);
    if (attrs == NULL) {
        return ENOMEM;
    }

    /* Remove SYSDB_REFRESH_TOKEN attribute */
    ret = sysdb_attrs_add_empty(attrs, SYSDB_REFRESH_TOKEN);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to prepare attribute for deletion: %d\n", ret);
        talloc_free(attrs);
        return ret;
    }

    ret = sysdb_transaction_start(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to start transaction: %d\n", ret);
        talloc_free(attrs);
        return ret;
    }

    ret = sysdb_set_user_attr(domain, username, attrs, SYSDB_MOD_DEL);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to delete user attribute: %d\n", ret);
        sysdb_transaction_cancel(domain->sysdb);
        talloc_free(attrs);
        return ret;
    }

    ret = sysdb_transaction_commit(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to commit transaction: %d\n", ret);
        talloc_free(attrs);
        return ret;
    }

    talloc_free(attrs);
    DEBUG(SSSDBG_TRACE_FUNC, "Refresh token deleted successfully for user %s\n", username);
    return EOK;
}
