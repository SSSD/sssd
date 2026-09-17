/*
    SSSD

    Helper child for OIDC and OAuth 2.0 Device Authorization Grant
    GSSAPI credential setup for Kerberos/SPNEGO client authentication

    Copyright (C) 2025 Red Hat

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

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <stdlib.h>

#include "util/util.h"
#include "oidc_child/oidc_child_util.h"

#define OIDC_GSSAPI_CCACHE "MEMORY:oidc_child"

/*
 * Acquire an initiator credential from the host keytab and store it in a
 * MEMORY: ccache.  Setting KRB5CCNAME to that ccache makes libcurl's
 * CURLAUTH_GSSNEGOTIATE pick it up when forming the Authorization: Negotiate
 * header for the token / device-auth endpoints.
 *
 * keytab_name may be NULL to use the system default keytab.
 */
errno_t oidc_setup_gssapi(const char *keytab_name)
{
    OM_uint32 major;
    OM_uint32 minor;
    gss_cred_id_t cred_handle = GSS_C_NO_CREDENTIAL;
    errno_t ret;

    /* Use the system default keytab if none was specified. */
    const char *kt = (keytab_name != NULL) ? keytab_name : "/etc/krb5.keytab";

    gss_key_value_element_desc acquire_elems[] = {
        { "client_keytab", kt }
    };
    gss_key_value_set_desc acquire_store = {
        .count = 1,
        .elements = acquire_elems
    };

    gss_key_value_element_desc store_elems[] = {
        { "ccache", OIDC_GSSAPI_CCACHE }
    };
    gss_key_value_set_desc store_store = {
        .count = 1,
        .elements = store_elems
    };

    DEBUG(SSSDBG_TRACE_FUNC,
          "Acquiring GSSAPI credentials from keytab [%s].\n", kt);

    major = gss_acquire_cred_from(&minor,
                                  GSS_C_NO_NAME,
                                  GSS_C_INDEFINITE,
                                  GSS_C_NO_OID_SET,
                                  GSS_C_INITIATE,
                                  &acquire_store,
                                  &cred_handle,
                                  NULL,
                                  NULL);
    if (GSS_ERROR(major)) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "gss_acquire_cred_from failed: major=0x%08x minor=0x%08x\n",
              major, minor);
        ret = EIO;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Storing GSSAPI credentials into ccache [%s].\n", OIDC_GSSAPI_CCACHE);

    major = gss_store_cred_into(&minor,
                                cred_handle,
                                GSS_C_INITIATE,
                                GSS_C_NO_OID,
                                1,   /* overwrite */
                                1,   /* default_cred */
                                &store_store,
                                NULL,
                                NULL);
    if (GSS_ERROR(major)) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "gss_store_cred_into failed: major=0x%08x minor=0x%08x\n",
              major, minor);
        ret = EIO;
        goto done;
    }

    if (setenv("KRB5CCNAME", OIDC_GSSAPI_CCACHE, 1) != 0) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "setenv(KRB5CCNAME) failed [%d]: %s\n", ret, strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_CONF_SETTINGS,
          "GSSAPI credentials ready; KRB5CCNAME=%s\n", OIDC_GSSAPI_CCACHE);
    ret = EOK;

done:
    if (cred_handle != GSS_C_NO_CREDENTIAL) {
        gss_release_cred(&minor, &cred_handle);
    }
    return ret;
}
