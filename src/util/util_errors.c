/*
    Copyright (C) 2012 Red Hat

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

    Authors:
        Simo Sorce <ssorce@redhat.com>
*/

#include "util/util.h"

struct err_string {
    const char *msg;
};

struct err_string error_to_str[] = {
    { "Invalid Error" },        /* ERR_INVALID */
    { "Internal Error" },       /* ERR_INTERNAL */
    { "Account Unknown" },      /* ERR_ACCOUNT_UNKNOWN */
    { "Invalid credential type" },  /* ERR_INVALID_CRED_TYPE */
    { "No credentials available" }, /* ERR_NO_CREDS */
    { "Credentials are expired" }, /* ERR_CREDS_EXPIRED */
    { "Credentials are expired, old ccache was removed" }, /* ERR_CREDS_EXPIRED_CCACHE */
    { "Failure setting user credentials"}, /* ERR_CREDS_INVALID */
    { "No cached credentials available" }, /* ERR_NO_CACHED_CREDS */
    { "Cached credentials are expired" }, /* ERR_CACHED_CREDS_EXPIRED */
    { "Authentication Denied" }, /* ERR_AUTH_DENIED */
    { "Authentication Failed" }, /* ERR_AUTH_FAILED */
    { "Password Change Denied" }, /* ERR_CHPASS_DENIED */
    { "Password Change Failed" }, /* ERR_CHPASS_FAILED */
    { "Network I/O Error" }, /* ERR_NETWORK_IO */
    { "Account Expired" }, /* ERR_ACCOUNT_EXPIRED */
    { "Password Expired" }, /* ERR_PASSWORD_EXPIRED */
    { "Password Expired (reject access)" }, /* ERR_PASSWORD_EXPIRED_REJECT */
    { "Password Expired (warn user)" }, /* ERR_PASSWORD_EXPIRED_WARN */
    { "Password Expired (ask for new password)" }, /* ERR_PASSWORD_EXPIRED_RENEW */
    { "Host Access Denied" }, /* ERR_ACCESS_DENIED */
    { "SRV record not found" }, /* ERR_SRV_NOT_FOUND */
    { "SRV lookup error" }, /* ERR_SRV_LOOKUP_ERROR */
    { "SRV lookup did not return any new server" }, /* ERR_SRV_DUPLICATES */
    { "Dynamic DNS update failed" }, /* ERR_DYNDNS_FAILED */
    { "Dynamic DNS update timed out" }, /* ERR_DYNDNS_TIMEOUT */
    { "Dynamic DNS update not possible while offline" }, /* ERR_DYNDNS_OFFLINE */
    { "Cannot parse input" }, /* ERR_INPUT_PARSE */
    { "Entry not found" }, /* ERR_NOT_FOUND */
    { "Domain not found" }, /* ERR_DOMAIN_NOT_FOUND */
    { "Missing configuration file" }, /* ERR_MISSING_CONF */
    { "Malformed search filter" }, /* ERR_INVALID_FILTER, */
    { "No POSIX attributes detected" }, /* ERR_NO_POSIX */
    { "Extra attribute is a duplicate" }, /* ERR_DUP_EXTRA_ATTR */
    { "Malformed extra attribute" }, /* ERR_INVALID_EXTRA_ATTR */
    { "Cannot get bus message sender" }, /* ERR_SBUS_GET_SENDER_ERROR */
    { "Bus message has no sender" }, /* ERR_SBUS_NO_SENDER */
    { "Invalid SBUS path provided" }, /* ERR_SBUS_INVALID_PATH */
    { "User/Group SIDs not found" }, /* ERR_NO_SIDS */
    { "Bus method not supported" }, /* ERR_SBUS_NOSUP */
    { "Cannot connect to system bus" }, /* ERR_NO_SYSBUS */
    { "LDAP search returned a referral" }, /* ERR_REFERRAL */
    { "Error setting SELinux user context" }, /* ERR_SELINUX_CONTEXT */
    { "Username format not allowed by re_expression" }, /* ERR_REGEX_NOMATCH */
    { "Time specification not supported" }, /* ERR_TIMESPEC_NOT_SUPPORTED */
    { "Invalid SSSD configuration detected" }, /* ERR_INVALID_CONFIG */
    { "Malformed cache entry" }, /* ERR_MALFORMED_ENTRY */
    { "Unexpected cache entry type" }, /* ERR_UNEXPECTED_ENTRY_TYPE */
    { "Failed to resolve one of user groups" }, /* ERR_SIMPLE_GROUPS_MISSING */
    { "Home directory is NULL" }, /* ERR_HOMEDIR_IS_NULL */
    { "Unsupported trust direction" }, /* ERR_TRUST_NOT_SUPPORTED */
    { "Retrieving keytab failed" }, /* ERR_IPA_GETKEYTAB_FAILED */
    { "Trusted forest root unknown" }, /* ERR_TRUST_FOREST_UNKNOWN */
    { "p11_child failed" }, /* ERR_P11_CHILD */
    { "Address family not supported" }, /* ERR_ADDR_FAMILY_NOT_SUPPORTED */
    { "Message sender is the bus" }, /* ERR_SBUS_SENDER_BUS */
    { "Subdomain is inactive" }, /* ERR_SUBDOM_INACTIVE */
    { "Account is locked" }, /* ERR_ACCOUNT_LOCKED */
    { "AD renewal child failed" }, /* ERR_RENEWAL_CHILD */
    { "ERR_LAST" } /* ERR_LAST */
};


const char *sss_strerror(errno_t error)
{
    if (IS_SSSD_ERROR(error)) {
        return error_to_str[SSSD_ERR_IDX(error)].msg;
    }

    return strerror(error);
}

