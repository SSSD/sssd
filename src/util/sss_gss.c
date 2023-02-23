/*
    Authors:
        Tomas Halman <thalman@redhat.com>

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

#include "sss_gss.h"

#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_krb5.h>

#include "util/sss_krb5.h"

/* obtain error message from gss api */
char *sss_gss_error_message(TALLOC_CTX *ctx, OM_uint32 status_code)
{
    OM_uint32 message_context;
    OM_uint32 maj_status;
    OM_uint32 min_status;
    gss_buffer_desc status_string;
    char *message = NULL;

    message_context = 0;

    do {

        maj_status = gss_display_status(
            &min_status,
            status_code,
            GSS_C_GSS_CODE,
            GSS_C_NO_OID,
            &message_context,
            &status_string);
        if (GSS_ERROR(maj_status)) {
            DEBUG(SSSDBG_OP_FAILURE, "Error while reading GSS message (maj: %u, min: %u)\n", maj_status, min_status);
            return message;
        }
        if (message) {
            message = talloc_asprintf_append(message, "%.*s",
                                             (int)status_string.length,
                                             (char *)status_string.value);
        } else {
            message = talloc_asprintf(ctx, "%.*s",
                                      (int)status_string.length,
                                      (char *)status_string.value);
        }
        if (message == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Error while reading GSS message - out of memory\n");
            return NULL;
        }

        gss_release_buffer(&min_status, &status_string);
    } while (message_context != 0);

    return message;
}


/* get principal from gss gredentials */
char *sss_gss_get_principal_from_creds(TALLOC_CTX *ctx, gss_cred_id_t creds)
{
    OM_uint32 major;
    OM_uint32 minor;
    gss_buffer_desc gss_name_buf;
    gss_name_t gss_name = GSS_C_NO_NAME;
    char *result = NULL;

    major = gss_inquire_cred(&minor, creds, &gss_name, NULL, NULL, NULL);
    if (GSS_ERROR(major)) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Could not get principal from credentials - "
                                    "gss_inquire_cred failed\n");
        goto done;
    }

    major = gss_display_name(&minor, gss_name, &gss_name_buf, NULL);
    if (GSS_ERROR(major)) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Could not get principal from credentials - "
                                    "gss_display_name failed\n");
        goto done;
    }

    result = talloc_asprintf(ctx,
                             "%.*s",
                             (int)gss_name_buf.length,
                             (char *)gss_name_buf.value);

done:
    major = gss_release_buffer(&minor, &gss_name_buf);
    if (GSS_ERROR(major)) {
        DEBUG(SSSDBG_MINOR_FAILURE, "The gss_release_buffer failed\n");
    }

    return result;
}

/* acquire credentials from keytab */
errno_t sss_gss_get_creds(TALLOC_CTX *ctx,
                          const char *principal,
                          const char *realm,
                          OM_uint32 lifetime,
                          const char *keytab_name,
                          gss_cred_id_t *_creds,
                          char **_principal,
                          OM_uint32 *_lifetime_out)
{
    gss_buffer_desc name_buf;
    gss_name_t gss_name = GSS_C_NO_NAME;
    gss_key_value_set_desc cstore;
    OM_uint32 major;
    OM_uint32 minor;
    gss_OID_set_desc krb5_set = {1, gss_mech_krb5};
    char *full_principal = NULL;
    errno_t ret = EOK;

    if (principal == NULL || _principal == NULL ||
        _creds == NULL || _lifetime_out == NULL) {
        return EINVAL;
    }

    *_principal = NULL;

    if (strchr(principal, '@') || realm == NULL) {
        full_principal = talloc_strdup(ctx, principal);
    } else {
        full_principal = talloc_asprintf(ctx, "%s@%s",
                                         principal, realm);
    }
    if (!full_principal) {
        ret = ENOMEM;
        goto done;
    }

    name_buf.value = (void *)(uintptr_t)full_principal;
    name_buf.length = strlen(full_principal);
    major = gss_import_name(&minor, &name_buf, GSS_C_NT_USER_NAME, &gss_name);
    if (GSS_ERROR(major)) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not convert %s to GSS name\n", full_principal);
        ret = EIO;
        goto done;
    }

    cstore.elements = talloc_array(ctx, struct gss_key_value_element_struct, 1);
    cstore.elements[0].key = "client_keytab";
    cstore.elements[0].value = keytab_name ? keytab_name : "/etc/krb5.keytab";
    cstore.count = 1;
    major = gss_acquire_cred_from(&minor, gss_name, lifetime,
                                  &krb5_set, GSS_C_INITIATE,
                                  &cstore, _creds, NULL, _lifetime_out);
    talloc_free(cstore.elements);

    if (GSS_ERROR(major)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not acquire credentials for %s from %s: GSS message: %s\n",
              full_principal,
              keytab_name ? keytab_name : "default keytab",
              sss_gss_error_message(ctx, major));
        ret = EIO;
        goto done;
    }

    *_principal = sss_gss_get_principal_from_creds(ctx, *_creds);
    if (*_principal == NULL) {
        /* getting principal from credentials failed lets use the input */
        /* value to have at least something */
        *_principal = full_principal;
        full_principal = NULL;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "GSS acquire credentials for %s OK\n", full_principal);

 done:
    gss_release_name(&minor, &gss_name);
    talloc_free(full_principal);
    return ret;
}


static errno_t sss_compose_principal(TALLOC_CTX *ctx,
                                     const char *primary_pattern,
                                     const char *realm_pattern,
                                     const char *hostname,
                                     const char *realm,
                                     char **_full_principal)
{
    char *primary_part = NULL;
    char *realm_part = NULL;
    errno_t ret = EOK;

    *_full_principal = NULL;

    if (primary_pattern == NULL || hostname == NULL || realm == NULL) {
        ret = EINVAL;
        goto done;
    }

    primary_part = sss_krb5_get_primary(ctx,
                                        primary_pattern,
                                        hostname);
    if (primary_part == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (realm_pattern) {
        realm_part = talloc_asprintf(ctx, realm_pattern, realm);
        if (realm_part == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    if (realm_part == NULL) {
        *_full_principal = primary_part;
        primary_part = NULL;
    } else {
        *_full_principal = talloc_asprintf(ctx, "%s@%s", primary_part, realm_part);
        if (*_full_principal == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }
 done:
    talloc_free(primary_part);
    talloc_free(realm_part);
    return ret;
}


/* find suitable credentials from keytab */
errno_t sss_gss_find_host_creds(TALLOC_CTX *ctx,
                                const char *hostname,
                                const char *realm,
                                int lifetime,
                                const char *keytab_name,
                                gss_cred_id_t *_creds,
                                char **_principal,
                                OM_uint32 *_lifetime)
{
    char *full_principal;
    errno_t ret;
    int idx = 0;

    /**
     * The %s conversion is passed as-is, the %S conversion is translated to
     * "short host name"
     *
     * Priority of lookup:
     * - our.hostname@REALM or host/our.hostname@REALM depending on the input
     * - SHORT.HOSTNAME$@REALM (AD domain)
     * - host/our.hostname@REALM
     * - pick the default principal in the keytab
     * GSS does not allow us to iterate keytab so in unlike in the direct keytab access
     * we skip lookups for
     * - foobar$@REALM (AD domain)
     * - host/foobar@REALM
     * - host/foo@BAR
     */
    const char *primary_patterns[] = {"%s", "%S$", "host/%s", NULL};
    const char *realm_patterns[] =   {"%s", "%s",  "%s",      NULL};

    do {
        ret = sss_compose_principal(ctx,
                                    primary_patterns[idx],
                                    realm_patterns[idx],
                                    hostname,
                                    realm,
                                    &full_principal);
        if (ret != EOK) {
            talloc_zfree(full_principal);
            return ret;
        }

        ret = sss_gss_get_creds(ctx,
                                full_principal,
                                NULL,
                                lifetime,
                                keytab_name,
                                _creds,
                                _principal,
                                _lifetime);
        talloc_zfree(full_principal);
        if (ret == EOK) {
            break;
        }

        ++idx;
    } while(primary_patterns[idx-1] != NULL || realm_patterns[idx-1] != NULL);

    return ret;
}
