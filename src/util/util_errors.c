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
#include <ldb.h>

struct err_string {
    const char *msg;
};

struct err_string error_to_str[] = {
    { "Invalid Error" },        /* ERR_INVALID */
    { "Internal Error" },       /* ERR_INTERNAL */
    { "SSSD is running" },  /* ERR_SSSD_RUNNING */
    { "SSSD is not running" },  /* ERR_SSSD_NOT_RUNNING */
    { "SSSD is offline" },       /* ERR_OFFLINE */
    { "Terminated" },       /* ERR_TERMINATED */
    { "Invalid data type" },       /* ERR_INVALID_DATA_TYPE */
    { "DP target is not configured" }, /* ERR_MISSING_DP_TARGET */
    { "Account Unknown" },      /* ERR_ACCOUNT_UNKNOWN */
    { "No suitable principal found in keytab" }, /* ERR_KRB5_PRINCIPAL_NOT_FOUND */
    { "Invalid credential type" },  /* ERR_INVALID_CRED_TYPE */
    { "No credentials available" }, /* ERR_NO_CREDS */
    { "Credentials are expired" }, /* ERR_CREDS_EXPIRED */
    { "Credentials are expired, old ccache was removed" }, /* ERR_CREDS_EXPIRED_CCACHE */
    { "Failure setting user credentials"}, /* ERR_CREDS_INVALID */
    { "No cached credentials available" }, /* ERR_NO_CACHED_CREDS */
    { "No matching credentials found" }, /* ERR_NO_MATCHING_CREDS */
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
    { "No domain is enabled" }, /* ERR_NO_DOMAIN_ENABLED */
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
    { "SELinux is not managed by libsemanage" }, /* ERR_SELINUX_NOT_MANAGED */
    { "SELinux user does not exist" }, /* ERR_SELINUX_USER_NOT_FOUND */
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
    { "p11_child timeout" }, /* ERR_P11_CHILD_TIMEOUT */
    { "PIN locked" }, /* ERR_P11_PIN_LOCKED */
    { "passkey_child failed" }, /* ERR_PASSKEY_CHILD */
    { "passkey_child timeout" }, /* ERR_PASSKEY_CHILD_TIMEOUT */
    { "Address family not supported" }, /* ERR_ADDR_FAMILY_NOT_SUPPORTED */
    { "Message sender is the bus" }, /* ERR_SBUS_SENDER_BUS */
    { "Subdomain is inactive" }, /* ERR_SUBDOM_INACTIVE */
    { "Account is locked" }, /* ERR_ACCOUNT_LOCKED */
    { "AD renewal child failed" }, /* ERR_RENEWAL_CHILD */
    { "SBUS request already handled" }, /* ERR_SBUS_REQUEST_HANDLED */
    { "Sysdb version is too old" },  /* ERR_SYSDB_VERSION_TOO_OLD */
    { "Sysdb version is too new" },  /* ERR_SYSDB_VERSION_TOO_NEW */
    { "Domain has to timestamp cache" }, /* ERR_NO_TS */
    { "No timestamp cache record" }, /* ERR_TS_CACHE_MISS */
    { "Dereference threshold reached" }, /* ERR_DEREF_THRESHOLD */
    { "The user is not handled by SSSD" }, /* ERR_NON_SSSD_USER */
    { "The internal name format cannot be parsed" }, /* ERR_WRONG_NAME_FORMAT */
    { "The maximum level of nested containers has been reached" }, /* ERR_SEC_INVALID_CONTAINERS_NEST_LEVEL */
    { "The maximum number of stored secrets has been reached" }, /* ERR_SEC_INVALID_TOO_MANY_SECRETS */
    { "The secret payload size is too large" }, /* ERR_SEC_PAYLOAD_SIZE_IS_TOO_LARGE */
    { "No authentication method available" }, /* ERR_NO_AUTH_METHOD_AVAILABLE */
    { "Smartcard authentication not supported" }, /* ERR_SC_AUTH_NOT_SUPPORTED */
    { "Malformed input KCM packet" }, /* ERR_KCM_MALFORMED_IN_PKT */
    { "KCM operation not implemented" }, /* ERR_KCM_OP_NOT_IMPLEMENTED */
    { "End of credential cache reached" }, /* ERR_KCM_CC_END */
    { "Credential cache name not allowed" }, /* ERR_KCM_WRONG_CCNAME_FORMAT */
    { "Cannot encode a JSON object to string" }, /* ERR_JSON_ENCODING */
    { "Cannot decode a JSON object from string" }, /* ERR_JSON_DECODING */
    { "Invalid certificate provided" }, /* ERR_INVALID_CERT */
    { "Unable to initialize SSL" }, /* ERR_SSL_FAILURE */
    { "Unable to verify peer" }, /* ERR_UNABLE_TO_VERIFY_PEER */
    { "Unable to resolve host" }, /* ERR_UNABLE_TO_RESOLVE_HOST */
    { "GetAccountDomain() not supported" }, /* ERR_GET_ACCT_DOM_NOT_SUPPORTED */
    { "Subid ranges are not supported by this provider" }, /* ERR_GET_ACCT_SUBID_RANGES_NOT_SUPPORTED */
    { "The last GetAccountDomain() result is still valid" }, /* ERR_GET_ACCT_DOM_CACHED */
    { "ID is outside the allowed range" }, /* ERR_ID_OUTSIDE_RANGE */
    { "Group ID is duplicated" }, /* ERR_GID_DUPLICATED */
    { "Multiple objects were found when only one was expected" }, /* ERR_MULTIPLE_ENTRIES */
    { "Unsupported range type" }, /* ERR_UNSUPPORTED_RANGE_TYPE */
    { "proxy_child terminated by a signal" }, /* ERR_PROXY_CHILD_SIGNAL */
    { "PAC check failed" }, /* ERR_CHECK_PAC_FAILED */
    { "Check next authentication type" }, /* ERR_CHECK_NEXT_AUTH_TYPE */

    /* DBUS Errors */
    { "Connection was killed on demand" }, /* ERR_SBUS_KILL_CONNECTION */
    { "NULL string cannot be sent over D-Bus" }, /* ERR_SBUS_EMPTY_STRING */
    { "Maximum number of connections was reached" }, /* ERR_SBUS_CONNECTION_LIMIT */
    { "String contains invalid characters" }, /* ERR_SBUS_INVALID_STRING */
    { "Unexpected argument type provided" }, /* ERR_SBUS_INVALID_TYPE */
    { "Unknown service" }, /* ERR_SBUS_UNKNOWN_SERVICE */
    { "Unknown interface" }, /* ERR_SBUS_UNKNOWN_INTERFACE */
    { "Unknown property" }, /* ERR_SBUS_UNKNOWN_PROPERTY */
    { "Unknown bus owner" }, /* ERR_SBUS_UNKNOWN_OWNER */
    { "No reply was received" }, /* ERR_SBUS_NO_REPLY */

    /* ini parsing errors */
    { "Failed to open main config file" }, /* ERR_INI_OPEN_FAILED */
    { "File ownership and permissions check failed" }, /* ERR_INI_INVALID_PERMISSION */
    { "Error while parsing configuration file" }, /* ERR_INI_PARSE_FAILED */
    { "Failed to add configuration snippets" }, /* ERR_INI_ADD_SNIPPETS_FAILED */
    { "Neither main config nor config snippets exist" }, /* ERR_INI_EMPTY_CONFIG */

    { "TLS handshake was interrupted"}, /* ERR_TLS_HANDSHAKE_INTERRUPTED */

    { "Certificate authority file not found"}, /* ERR_CA_DB_NOT_FOUND */

    { "Server failure"}, /* ERR_SERVER_FAILURE */

    { "ERR_LAST" } /* ERR_LAST */
};


const char *sss_strerror(errno_t error)
{
    if (IS_SSSD_ERROR(error)) {
        return error_to_str[SSSD_ERR_IDX(error)].msg;
    }

    return strerror(error);
}

/* TODO: make a more complete and precise mapping */
errno_t sss_ldb_error_to_errno(int ldberr)
{
    switch (ldberr) {
    case LDB_SUCCESS:
        return EOK;
    case LDB_ERR_OPERATIONS_ERROR:
        return EIO;
    case LDB_ERR_NO_SUCH_OBJECT:
    case LDB_ERR_NO_SUCH_ATTRIBUTE:
        return ENOENT;
    case LDB_ERR_BUSY:
        return EBUSY;
    case LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS:
    case LDB_ERR_ENTRY_ALREADY_EXISTS:
        return EEXIST;
    case LDB_ERR_INVALID_ATTRIBUTE_SYNTAX:
        return EINVAL;
    default:
        DEBUG(SSSDBG_MINOR_FAILURE,
              "LDB returned unexpected error: [%i]\n",
              ldberr);
        return EFAULT;
    }
}
