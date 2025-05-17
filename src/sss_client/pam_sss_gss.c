/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2020 Red Hat

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

#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_generic.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/syslog.h>
#include <unistd.h>
#include <string.h>

#include "util/sss_format.h"
#include "sss_client/sss_cli.h"
#include "sss_client/sss_pam_compat.h"

bool debug_enabled;

#define TRACE(pamh, fmt, ...) do { \
    if (debug_enabled) { \
        pam_info(pamh, "pam_sss_gss: " fmt, ## __VA_ARGS__); \
    } \
} while (0)

#define ERROR(pamh, fmt, ...) do { \
    if (debug_enabled) { \
        pam_error(pamh, "pam_sss_gss: " fmt, ## __VA_ARGS__); \
        pam_syslog(pamh, LOG_ERR, fmt, ## __VA_ARGS__); \
    } \
} while (0)

static bool switch_euid(pam_handle_t *pamh, uid_t current, uid_t desired)
{
    int ret;

    TRACE(pamh, "Switching euid from %" SPRIuid " to %" SPRIuid, current,
          desired);

    if (current == desired) {
        return true;
    }

    ret = seteuid(desired);
    if (ret != 0) {
        ERROR(pamh, "Unable to set euid to %" SPRIuid, desired);
        return false;
    }

    return true;
}

static const char *get_item_as_string(pam_handle_t *pamh, int item)
{
    const char *str;
    int ret;

    ret = pam_get_item(pamh, item, (void *)&str);
    if (ret != PAM_SUCCESS || str == NULL || str[0] == '\0') {
        return NULL;
    }

    return str;
}

static errno_t string_to_gss_name(pam_handle_t *pamh,
                                  const char *target,
                                  gss_OID type,
                                  gss_name_t *_name)
{
    gss_buffer_desc name_buf;
    OM_uint32 major;
    OM_uint32 minor;

    name_buf.value = (void *)(uintptr_t)target;
    name_buf.length = strlen(target);
    major = gss_import_name(&minor, &name_buf, type, _name);
    if (GSS_ERROR(major)) {
        ERROR(pamh, "Could not convert target to GSS name");
        return EIO;
    }

    return EOK;
}

static void gssapi_log_status(pam_handle_t *pamh,
                              int type,
                              OM_uint32 status_code)
{
    gss_buffer_desc buf;
    OM_uint32 message_context;
    OM_uint32 minor;

    message_context = 0;
    do {
        gss_display_status(&minor, status_code, type, GSS_C_NO_OID,
                           &message_context, &buf);
        ERROR(pamh, "GSSAPI: %.*s", (int)buf.length, (char *)buf.value);
        gss_release_buffer(&minor, &buf);
    } while (message_context != 0);
}

static void gssapi_log_error(pam_handle_t *pamh,
                             OM_uint32 major,
                             OM_uint32 minor)
{
    gssapi_log_status(pamh, GSS_C_GSS_CODE, major);
    gssapi_log_status(pamh, GSS_C_MECH_CODE, minor);
}

static errno_t gssapi_get_creds(pam_handle_t *pamh,
                                const char *ccache,
                                const char *target,
                                const char *upn,
                                gss_cred_id_t *_creds)
{
    gss_key_value_set_desc cstore = {0, NULL};
    gss_key_value_element_desc el;
    gss_name_t name = GSS_C_NO_NAME;
    OM_uint32 major;
    OM_uint32 minor;
    errno_t ret;

    if (upn != NULL && upn[0] != '\0') {
        TRACE(pamh, "Acquiring credentials for principal [%s]", upn);
        ret = string_to_gss_name(pamh, upn, GSS_C_NT_USER_NAME, &name);
        if (ret != EOK) {
            goto done;
        }
    } else {
        TRACE(pamh, "Acquiring credentials, principal name will be derived");
    }

    if (ccache != NULL) {
        el.key = "ccache";
        el.value = ccache;
        cstore.count = 1;
        cstore.elements = &el;
    }

    major = gss_acquire_cred_from(&minor, name, GSS_C_INDEFINITE,
                                  GSS_C_NO_OID_SET, GSS_C_INITIATE,
                                  &cstore, _creds, NULL, NULL);
    if (GSS_ERROR(major)) {
        /* TODO: Do not hardcode the error code. */
        if (minor == 2529639053 && name != GSS_C_NO_NAME) {
            /* Hint principal was not found. Try again and let GSSAPI choose. */
            TRACE(pamh, "Principal [%s] was not found in ccache", upn);
            ret = gssapi_get_creds(pamh, ccache, target, NULL, _creds);
            goto done;
        } else {
            ERROR(pamh, "Unable to read credentials from [%s] "
                  "[maj:0x%x, min:0x%x]", ccache == NULL ? "default" : ccache,
                  major, minor);

            gssapi_log_error(pamh, major, minor);
            ret = EIO;
            goto done;
        }
    }

    ret = EOK;

done:
    gss_release_name(&minor, &name);

    return ret;
}

static errno_t sssd_gssapi_init_send(pam_handle_t *pamh,
                                     const char *pam_service,
                                     const char *pam_user,
                                     uint8_t **_reply,
                                     size_t *_reply_len)
{
    struct sss_cli_req_data req_data;
    size_t service_len;
    size_t user_len;
    size_t reply_len;
    uint8_t *reply = NULL;
    uint8_t *data;
    errno_t ret;
    int ret_errno;

    if (pam_service == NULL || pam_user == NULL) {
        return EINVAL;
    }

    service_len = strlen(pam_service) + 1;
    user_len = strlen(pam_user) + 1;

    req_data.len = (service_len + user_len) * sizeof(char);
    data = (uint8_t*)malloc(req_data.len);
    if (data == NULL) {
        return ENOMEM;
    }

    memcpy(data, pam_service, service_len);
    memcpy(data + service_len, pam_user, user_len);

    req_data.data = data;

    ret = sss_pam_make_request(SSS_GSSAPI_INIT, &req_data, &reply, &reply_len,
                               &ret_errno);
    free(data);
    if (ret != PAM_SUCCESS) {
        if (ret_errno == ENOTSUP) {
            TRACE(pamh, "GSSAPI authentication is not supported for user %s "
                  "and service %s", pam_user, pam_service);
            return ret_errno;
        }

        ERROR(pamh, "Communication error [%d, %d]: %s; %s", ret, ret_errno,
              pam_strerror(pamh, ret), strerror(ret_errno));

        return (ret_errno != EOK) ? ret_errno : EIO;
    }

    if (ret_errno == EOK) {
        *_reply = reply;
        *_reply_len = reply_len;
    } else {
        /* We got PAM_SUCCESS therefore the communication with SSSD was
         * successful and we have received a reply buffer. We just don't care
         * about it, we are only interested in the error code. */
        free(reply);
    }

    return ret_errno;
}

static errno_t sssd_gssapi_init_recv(uint8_t *reply,
                                     size_t reply_len,
                                     char **_username,
                                     char **_domain,
                                     char **_target,
                                     char **_upn)
{
    char *username = NULL;
    char *domain = NULL;
    char *target = NULL;
    char *upn = NULL;
    const char *buf;
    size_t pctr = 0;
    size_t dlen;
    errno_t ret;

    username = malloc(reply_len * sizeof(char));
    domain = malloc(reply_len * sizeof(char));
    target = malloc(reply_len * sizeof(char));
    upn = malloc(reply_len * sizeof(char));
    if (username == NULL || domain == NULL || target == NULL || upn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    buf = (const char*)reply;

    dlen = reply_len;
    ret = sss_readrep_copy_string(buf, &pctr, &reply_len, &dlen, &username,
                                  NULL);
    if (ret != EOK) {
        goto done;
    }

    dlen = reply_len;
    ret = sss_readrep_copy_string(buf, &pctr, &reply_len, &dlen, &domain, NULL);
    if (ret != EOK) {
        goto done;
    }

    dlen = reply_len;
    ret = sss_readrep_copy_string(buf, &pctr, &reply_len, &dlen, &target, NULL);
    if (ret != EOK) {
        goto done;
    }

    dlen = reply_len;
    ret = sss_readrep_copy_string(buf, &pctr, &reply_len, &dlen, &upn, NULL);
    if (ret != EOK) {
        goto done;
    }

    *_username = username;
    *_domain = domain;
    *_target = target;
    *_upn = upn;

done:
    if (ret != EOK) {
        free(username);
        free(domain);
        free(target);
        free(upn);
    }

    return ret;
}

static errno_t sssd_gssapi_init(pam_handle_t *pamh,
                                const char *pam_service,
                                const char *pam_user,
                                char **_username,
                                char **_domain,
                                char **_target,
                                char **_upn)
{
    size_t reply_len = 0;
    uint8_t *reply = NULL;
    errno_t ret;

    ret = sssd_gssapi_init_send(pamh, pam_service, pam_user, &reply,
                                &reply_len);
    if (ret != EOK) {
        return ret;
    }

    ret = sssd_gssapi_init_recv(reply, reply_len, _username, _domain, _target,
                                _upn);
    free(reply);

    return ret;
}

static errno_t sssd_establish_sec_ctx_send(pam_handle_t *pamh,
                                           const char *pam_service,
                                           const char *username,
                                           const char *domain,
                                           const void *gss_data,
                                           size_t gss_data_len,
                                           void **_reply,
                                           size_t *_reply_len)
{
    struct sss_cli_req_data req_data;
    size_t username_len;
    size_t service_len;
    size_t domain_len;
    uint8_t *data;
    int ret_errno;
    int ret;

    service_len = strlen(pam_service) + 1;
    username_len = strlen(username) + 1;
    domain_len = strlen(domain) + 1;

    req_data.len = (service_len + username_len + domain_len) * sizeof(char)
                   + gss_data_len;
    data = malloc(req_data.len);
    if (data == NULL) {
        return ENOMEM;
    }

    memcpy(data, pam_service, service_len);
    memcpy(data + service_len, username, username_len);
    memcpy(data + service_len + username_len, domain, domain_len);
    memcpy(data + service_len + username_len + domain_len, gss_data,
           gss_data_len);

    req_data.data = data;
    ret = sss_pam_make_request(SSS_GSSAPI_SEC_CTX, &req_data, (uint8_t**)_reply,
                               _reply_len, &ret_errno);
    free(data);
    if (ret != PAM_SUCCESS) {
        /* ENOTSUP should not happend here so let's keep it as generic error. */
        ERROR(pamh, "Communication error [%d, %d]: %s; %s", ret, ret_errno,
              pam_strerror(pamh, ret), strerror(ret_errno));

        return (ret_errno != EOK) ? ret_errno : EIO;
    }

    return ret_errno;
}

static int sssd_establish_sec_ctx(pam_handle_t *pamh,
                                  const char *ccache,
                                  const char *pam_service,
                                  const char *username,
                                  const char *domain,
                                  const char *target,
                                  const char *upn)
{
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_buffer_desc input = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output = GSS_C_EMPTY_BUFFER;
    OM_uint32 flags = GSS_C_MUTUAL_FLAG;
    gss_name_t gss_name;
    gss_cred_id_t creds;
    OM_uint32 ret_flags;
    OM_uint32 major;
    OM_uint32 minor;
    int ret;

    ret = gssapi_get_creds(pamh, ccache, target, upn, &creds);
    if (ret != EOK) {
        return ret;
    }

    ret = string_to_gss_name(pamh, target, GSS_C_NT_HOSTBASED_SERVICE, &gss_name);
    if (ret != 0) {
        return ret;
    }

    do {
        major = gss_init_sec_context(&minor, creds, &ctx,
                                     gss_name, GSS_C_NO_OID, flags, 0, NULL,
                                     &input, NULL, &output,
                                     &ret_flags, NULL);

        free(input.value);
        memset(&input, 0, sizeof(gss_buffer_desc));

        if (GSS_ERROR(major)) {
            ERROR(pamh, "Unable to establish GSS context [maj:0x%x, min:0x%x]",
                  major, minor);
            gssapi_log_error(pamh, major, minor);
            ret = EIO;
            goto done;
        } else if (major == GSS_S_CONTINUE_NEEDED || output.length > 0) {
            ret = sssd_establish_sec_ctx_send(pamh, pam_service,
                                              username, domain,
                                              output.value, output.length,
                                              &input.value, &input.length);
            gss_release_buffer(NULL, &output);
            if (ret != EOK) {
                goto done;
            }
        }
    } while (major != GSS_S_COMPLETE);

    if ((ret_flags & flags) != flags) {
        ERROR(pamh, "Negotiated context does not support requested flags\n");
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    gss_delete_sec_context(&minor, &ctx, NULL);
    gss_release_name(&minor, &gss_name);

    return ret;
}

static int errno_to_pam(pam_handle_t *pamh, errno_t ret)
{
    switch (ret) {
        case EOK:
            TRACE(pamh, "Authentication successful");
            return PAM_SUCCESS;
        case ENOENT:
            TRACE(pamh, "User not found");
            return PAM_USER_UNKNOWN;
        case ENOTSUP:
            TRACE(pamh, "GSSAPI authentication is not enabled "
                  "for given user and service");
            return PAM_USER_UNKNOWN;
        case ESSS_NO_SOCKET:
            TRACE(pamh, "SSSD socket does not exist");
            return PAM_AUTHINFO_UNAVAIL;
        case EPERM:
            TRACE(pamh, "Authentication failed");
            return PAM_AUTH_ERR;
        default:
            TRACE(pamh, "System error [%d]: %s",
                     ret, strerror(ret));
            return PAM_SYSTEM_ERR;
    }
}

static errno_t sss_cli_getenv(const char *variable_name, char **_value)
{
    char *value = getenv(variable_name);
    if (value == NULL) {
        *_value = NULL;
        return EOK;
    }

    *_value = strdup(value);
    if (*_value == NULL) {
        return ENOMEM;
    }

    return EOK;
}

int pam_sm_authenticate(pam_handle_t *pamh,
                        int flags,
                        int argc,
                        const char **argv)
{
    const char *pam_service = NULL;
    const char *pam_user = NULL;
    char *ccache = NULL;
    char *username = NULL;
    char *domain = NULL;
    char *target = NULL;
    char *upn = NULL;
    uid_t uid;
    uid_t euid;
    errno_t ret;

    debug_enabled = false;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "debug") == 0) {
            debug_enabled = true;
            break;
        }
    }

    /* Get non-default ccache if specified, may be NULL. */
    ret = sss_cli_getenv("KRB5CCNAME", &ccache);
    if (ret != EOK) {
        ERROR(pamh, "sss_cli_getenv() call failed [%d]: %s", ret, strerror(ret));
        goto done;
    }

    uid = getuid();
    euid = geteuid();

    /* Read PAM data. */
    pam_service = get_item_as_string(pamh, PAM_SERVICE);
    pam_user = get_item_as_string(pamh, PAM_USER);
    if (pam_service == NULL || pam_user == NULL) {
        ERROR(pamh, "Unable to get PAM data!");
        ret = EINVAL;
        goto done;
    }

    /* Initialize GSSAPI authentication with SSSD. Get user domain
     * and target GSS service name. */
    TRACE(pamh, "Initializing GSSAPI authentication with SSSD");
    ret = sssd_gssapi_init(pamh, pam_service, pam_user, &username, &domain,
                           &target, &upn);
    if (ret != EOK) {
        goto done;
    }

    /* PAM is often called from set-user-id applications (sudo, su). we want to
     * make sure that we access credentials of the caller (real uid). */
    if (!switch_euid(pamh, euid, uid)) {
        ret = EFAULT;
        goto done;
    }

    /* Authenticate the user by estabilishing security context. Authorization is
     * expected to be done by other modules through pam_access. */
    TRACE(pamh, "Trying to establish security context");
    TRACE(pamh, "SSSD User name: %s", username);
    TRACE(pamh, "User domain: %s", domain);
    TRACE(pamh, "User principal: %s", upn);
    TRACE(pamh, "Target name: %s", target);
    TRACE(pamh, "Using ccache: %s", ccache == NULL ? "default" : ccache);
    ret = sssd_establish_sec_ctx(pamh, ccache, pam_service,
                                 username, domain, target, upn);

    /* Restore original euid. */
    if (!switch_euid(pamh, uid, euid)) {
        ret = EFAULT;
        goto done;
    }

done:
    sss_pam_lock();
    sss_cli_close_socket();
    sss_pam_unlock();
    free(username);
    free(domain);
    free(target);
    free(upn);
    free(ccache);

    return errno_to_pam(pamh, ret);
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_IGNORE;
}

int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_IGNORE;
}

int pam_sm_open_session(pam_handle_t *pamh,
                        int flags,
                        int argc,
                        const char **argv)
{
    return PAM_IGNORE;
}

int pam_sm_close_session(pam_handle_t *pamh,
                         int flags,
                         int argc,
                         const char **argv)
{
    return PAM_IGNORE;
}

int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_IGNORE;
}
