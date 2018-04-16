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

#ifndef __SSSD_UTIL_ERRORS_H__
#define __SSSD_UTIL_ERRORS_H__

#ifndef HAVE_ERRNO_T
#define HAVE_ERRNO_T
typedef int errno_t;
#endif

/*
 * We define a specific number space so that we do not overlap with other
 * generic errors returned by various libraries. This will make it easy
 * to have functions that double check that what was returned was an SSSD
 * specific error where it matters. For example we may want to ensure some
 * particularly sensitive paths only return SSSD-specific errors as that
 * will ensure all error conditions have been explicitly dealt with,
 * and are not the result of assigning the wrong return result.
 *
 * Basic system errno errors can still be used, but when an error condition
 * does not properly map to a system error we should use an SSSD specific one
 */

#define ERR_BASE    0x555D0000
#define ERR_MASK    0x0000FFFF

/* never use ERR_INVALID, it is used for catching and returning
 * information on invalid error numbers */
/* never use ERR_LAST, this represents the maximum error value available
 * and is used to validate error codes */
enum sssd_errors {
    ERR_INVALID = ERR_BASE + 0,
    ERR_INTERNAL,
    ERR_SSSD_RUNNING,
    ERR_SSSD_NOT_RUNNING,
    ERR_OFFLINE,
    ERR_TERMINATED,
    ERR_INVALID_DATA_TYPE,
    ERR_MISSING_DP_TARGET,
    ERR_ACCOUNT_UNKNOWN,
    ERR_INVALID_CRED_TYPE,
    ERR_NO_CREDS,
    ERR_CREDS_EXPIRED,
    ERR_CREDS_EXPIRED_CCACHE,
    ERR_CREDS_INVALID,
    ERR_NO_CACHED_CREDS,
    ERR_NO_MATCHING_CREDS,
    ERR_CACHED_CREDS_EXPIRED,
    ERR_AUTH_DENIED,
    ERR_AUTH_FAILED,
    ERR_CHPASS_DENIED,
    ERR_CHPASS_FAILED,
    ERR_NETWORK_IO,
    ERR_ACCOUNT_EXPIRED,
    ERR_PASSWORD_EXPIRED,
    ERR_PASSWORD_EXPIRED_REJECT,
    ERR_PASSWORD_EXPIRED_WARN,
    ERR_PASSWORD_EXPIRED_RENEW,
    ERR_ACCESS_DENIED,
    ERR_SRV_NOT_FOUND,
    ERR_SRV_LOOKUP_ERROR,
    ERR_SRV_DUPLICATES,
    ERR_DYNDNS_FAILED,
    ERR_DYNDNS_TIMEOUT,
    ERR_DYNDNS_OFFLINE,
    ERR_INPUT_PARSE,
    ERR_NOT_FOUND,
    ERR_DOMAIN_NOT_FOUND,
    ERR_INVALID_FILTER,
    ERR_NO_POSIX,
    ERR_DUP_EXTRA_ATTR,
    ERR_INVALID_EXTRA_ATTR,
    ERR_SBUS_GET_SENDER_ERROR,
    ERR_SBUS_NO_SENDER,
    ERR_SBUS_INVALID_PATH,
    ERR_NO_SIDS,
    ERR_SBUS_NOSUP,
    ERR_NO_SYSBUS,
    ERR_REFERRAL,
    ERR_SELINUX_CONTEXT,
    ERR_SELINUX_NOT_MANAGED,
    ERR_REGEX_NOMATCH,
    ERR_TIMESPEC_NOT_SUPPORTED,
    ERR_INVALID_CONFIG,
    ERR_MALFORMED_ENTRY,
    ERR_UNEXPECTED_ENTRY_TYPE,
    ERR_SIMPLE_GROUPS_MISSING,
    ERR_HOMEDIR_IS_NULL,
    ERR_TRUST_NOT_SUPPORTED,
    ERR_IPA_GETKEYTAB_FAILED,
    ERR_TRUST_FOREST_UNKNOWN,
    ERR_P11_CHILD,
    ERR_ADDR_FAMILY_NOT_SUPPORTED,
    ERR_SBUS_SENDER_BUS,
    ERR_SUBDOM_INACTIVE,
    ERR_ACCOUNT_LOCKED,
    ERR_RENEWAL_CHILD,
    ERR_SBUS_REQUEST_HANDLED,
    ERR_SYSDB_VERSION_TOO_OLD,
    ERR_SYSDB_VERSION_TOO_NEW,
    ERR_NO_TS,
    ERR_TS_CACHE_MISS,
    ERR_DEREF_THRESHOLD,
    ERR_NON_SSSD_USER,
    ERR_WRONG_NAME_FORMAT,
    ERR_SEC_INVALID_CONTAINERS_NEST_LEVEL,
    ERR_SEC_NO_PROXY,
    ERR_SEC_INVALID_TOO_MANY_SECRETS,
    ERR_SEC_PAYLOAD_SIZE_IS_TOO_LARGE,
    ERR_NO_AUTH_METHOD_AVAILABLE,
    ERR_SC_AUTH_NOT_SUPPORTED,
    ERR_KCM_MALFORMED_IN_PKT,
    ERR_KCM_OP_NOT_IMPLEMENTED,
    ERR_KCM_CC_END,
    ERR_KCM_WRONG_CCNAME_FORMAT,
    ERR_JSON_ENCODING,
    ERR_JSON_DECODING,
    ERR_INVALID_CERT,
    ERR_SSL_FAILURE,
    ERR_UNABLE_TO_VERIFY_PEER,
    ERR_UNABLE_TO_RESOLVE_HOST,
    ERR_GET_ACCT_DOM_NOT_SUPPORTED,
    ERR_GET_ACCT_DOM_CACHED,
    ERR_ID_OUTSIDE_RANGE,
    ERR_GID_DUPLICATED,
    ERR_LAST            /* ALWAYS LAST */
};

#define SSSD_ERR_BASE(err) ((err) & ~ERR_MASK)
#define SSSD_ERR_IDX(err) ((err) & ERR_MASK)
#define IS_SSSD_ERROR(err) \
    ((SSSD_ERR_BASE(err) == ERR_BASE) && ((err) <= ERR_LAST))

#define ERR_OK      0
/* Backwards compat */
#ifndef EOK
#define EOK ERR_OK
#endif

/**
 * @brief return a string describing the error number like strerror()
 *
 * @param error     An errno_t number, can be an SSSD error or a system error
 *
 * @return A statically allocated string.
 */
const char *sss_strerror(errno_t error);

#endif /* __SSSD_UTIL_ERRORS_H__ */
