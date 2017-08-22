/*
   Unix SMB/CIFS implementation.

   Winbind client API - SSSD version

   Copyright (C) Sumit Bose <sbose@redhat.com> 2014

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/* Required Headers */
#include "libwbclient.h"
#include "wbc_sssd_internal.h"

/* Authenticate a username/password pair */
wbcErr wbcAuthenticateUser(const char *username,
               const char *password)
{
    wbcErr wbc_status = WBC_ERR_SUCCESS;
    struct wbcAuthUserParams params = {0};

    params.account_name       = username;
    params.level              = WBC_AUTH_USER_LEVEL_PLAIN;
    params.password.plaintext = password;

    wbc_status = wbcAuthenticateUserEx(&params, NULL, NULL);

    return wbc_status;
}


/* Authenticate with more detailed information */
wbcErr wbcAuthenticateUserEx(const struct wbcAuthUserParams *params,
                 struct wbcAuthUserInfo **info,
                 struct wbcAuthErrorInfo **error)
{
    if (error != NULL) {
        *error = NULL;
    }

    return WBC_ERR_WINBIND_NOT_AVAILABLE;
}

/* Trigger a verification of the trust credentials of a specific domain */
wbcErr wbcCheckTrustCredentials(const char *domain,
                struct wbcAuthErrorInfo **error)
{
    if (error != NULL) {
        *error = NULL;
    }

    WBC_SSSD_NOT_IMPLEMENTED;
}

/* Trigger a change of the trust credentials for a specific domain */
wbcErr wbcChangeTrustCredentials(const char *domain,
                 struct wbcAuthErrorInfo **error)
{
    if (error != NULL) {
        *error = NULL;
    }

    WBC_SSSD_NOT_IMPLEMENTED;
}

/*
 * Trigger a no-op NETLOGON call. Lightweight version of
 * wbcCheckTrustCredentials
 */
wbcErr wbcPingDc(const char *domain, struct wbcAuthErrorInfo **error)
{
    return wbcPingDc2(domain, error, NULL);
}

/*
 * Trigger a no-op NETLOGON call. Lightweight version of
 * wbcCheckTrustCredentials, optionally return attempted DC
 */
wbcErr wbcPingDc2(const char *domain, struct wbcAuthErrorInfo **error,
          char **dcname)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

/* Trigger an extended logoff notification to Winbind for a specific user */
wbcErr wbcLogoffUserEx(const struct wbcLogoffUserParams *params,
               struct wbcAuthErrorInfo **error)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

/* Trigger a logoff notification to Winbind for a specific user */
wbcErr wbcLogoffUser(const char *username,
             uid_t uid,
             const char *ccfilename)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

/* Change a password for a user with more detailed information upon failure */
wbcErr wbcChangeUserPasswordEx(const struct wbcChangePasswordParams *params,
                   struct wbcAuthErrorInfo **error,
                   enum wbcPasswordChangeRejectReason *reject_reason,
                   struct wbcUserPasswordPolicyInfo **policy)
{
    if (error != NULL) {
        *error = NULL;
    }

    if (policy != NULL) {
        *policy = NULL;
    }

    WBC_SSSD_NOT_IMPLEMENTED;
}

/* Change a password for a user */
wbcErr wbcChangeUserPassword(const char *username,
                 const char *old_password,
                 const char *new_password)
{
    wbcErr wbc_status = WBC_ERR_SUCCESS;
    struct wbcChangePasswordParams params = {0};

    params.account_name        = username;
    params.level            = WBC_CHANGE_PASSWORD_LEVEL_PLAIN;
    params.old_password.plaintext    = old_password;
    params.new_password.plaintext    = new_password;

    wbc_status = wbcChangeUserPasswordEx(&params, NULL, NULL, NULL);

    return wbc_status;
}

/* Logon a User */
wbcErr wbcLogonUser(const struct wbcLogonUserParams *params,
            struct wbcLogonUserInfo **info,
            struct wbcAuthErrorInfo **error,
            struct wbcUserPasswordPolicyInfo **policy)
{
    if (info != NULL) {
        *info = NULL;
    }

    if (error != NULL) {
        *error = NULL;
    }

    if (policy != NULL) {
        *policy = NULL;
    }

    WBC_SSSD_NOT_IMPLEMENTED;
}

/* Authenticate a user with cached credentials */
wbcErr wbcCredentialCache(struct wbcCredentialCacheParams *params,
                          struct wbcCredentialCacheInfo **info,
                          struct wbcAuthErrorInfo **error)
{
    if (error != NULL) {
        *error = NULL;
    }

    WBC_SSSD_NOT_IMPLEMENTED;
}

/* Authenticate a user with cached credentials */
wbcErr wbcCredentialSave(const char *user, const char *password)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}
