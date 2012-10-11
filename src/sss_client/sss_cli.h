/*
   SSSD

   Client Interface for NSS and PAM.

   Authors:
        Simo Sorce <ssorce@redhat.com>

   Copyright (C) Red Hat, Inc 2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _SSSCLI_H
#define _SSSCLI_H

#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

#ifndef HAVE_ERRNO_T
#define HAVE_ERRNO_T
typedef int errno_t;
#endif


#ifndef EOK
#define EOK 0
#endif

#define SSS_NSS_PROTOCOL_VERSION 1
#define SSS_PAM_PROTOCOL_VERSION 3
#define SSS_SUDO_PROTOCOL_VERSION 1
#define SSS_AUTOFS_PROTOCOL_VERSION 1
#define SSS_SSH_PROTOCOL_VERSION 0
#define SSS_PAC_PROTOCOL_VERSION 1

#ifdef LOGIN_NAME_MAX
#define SSS_NAME_MAX LOGIN_NAME_MAX
#else
#define SSS_NAME_MAX 256
#endif

/**
 * @defgroup sss_cli_command SSS client commands
 * @{
 */

/** The allowed commands a SSS client can send to the SSSD */

enum sss_cli_command {
/* null */
    SSS_CLI_NULL           = 0x0000,

/* version */
    SSS_GET_VERSION    = 0x0001,

/* passwd */

    SSS_NSS_GETPWNAM       = 0x0011,
    SSS_NSS_GETPWUID       = 0x0012,
    SSS_NSS_SETPWENT       = 0x0013,
    SSS_NSS_GETPWENT       = 0x0014,
    SSS_NSS_ENDPWENT       = 0x0015,

/* group */

    SSS_NSS_GETGRNAM       = 0x0021,
    SSS_NSS_GETGRGID       = 0x0022,
    SSS_NSS_SETGRENT       = 0x0023,
    SSS_NSS_GETGRENT       = 0x0024,
    SSS_NSS_ENDGRENT       = 0x0025,
    SSS_NSS_INITGR         = 0x0026,

#if 0
/* aliases */

    SSS_NSS_GETALIASBYNAME = 0x0031,
    SSS_NSS_GETALIASBYPORT = 0x0032,
    SSS_NSS_SETALIASENT    = 0x0033,
    SSS_NSS_GETALIASENT    = 0x0034,
    SSS_NSS_ENDALIASENT    = 0x0035,

/* ethers */

    SSS_NSS_GETHOSTTON     = 0x0041,
    SSS_NSS_GETNTOHOST     = 0x0042,
    SSS_NSS_SETETHERENT    = 0x0043,
    SSS_NSS_GETETHERENT    = 0x0044,
    SSS_NSS_ENDETHERENT    = 0x0045,

/* hosts */

    SSS_NSS_GETHOSTBYNAME  = 0x0051,
    SSS_NSS_GETHOSTBYNAME2 = 0x0052,
    SSS_NSS_GETHOSTBYADDR  = 0x0053,
    SSS_NSS_SETHOSTENT     = 0x0054,
    SSS_NSS_GETHOSTENT     = 0x0055,
    SSS_NSS_ENDHOSTENT     = 0x0056,
#endif
/* netgroup */

    SSS_NSS_SETNETGRENT    = 0x0061,
    SSS_NSS_GETNETGRENT    = 0x0062,
    SSS_NSS_ENDNETGRENT    = 0x0063,
    /* SSS_NSS_INNETGR     = 0x0064, */
#if 0
/* networks */

    SSS_NSS_GETNETBYNAME   = 0x0071,
    SSS_NSS_GETNETBYADDR   = 0x0072,
    SSS_NSS_SETNETENT      = 0x0073,
    SSS_NSS_GETNETENT      = 0x0074,
    SSS_NSS_ENDNETENT      = 0x0075,

/* protocols */

    SSS_NSS_GETPROTOBYNAME = 0x0081,
    SSS_NSS_GETPROTOBYNUM  = 0x0082,
    SSS_NSS_SETPROTOENT    = 0x0083,
    SSS_NSS_GETPROTOENT    = 0x0084,
    SSS_NSS_ENDPROTOENT    = 0x0085,

/* rpc */

    SSS_NSS_GETRPCBYNAME   = 0x0091,
    SSS_NSS_GETRPCBYNUM    = 0x0092,
    SSS_NSS_SETRPCENT      = 0x0093,
    SSS_NSS_GETRPCENT      = 0x0094,
    SSS_NSS_ENDRPCENT      = 0x0095,
#endif

/* services */

    SSS_NSS_GETSERVBYNAME  = 0x00A1,
    SSS_NSS_GETSERVBYPORT  = 0x00A2,
    SSS_NSS_SETSERVENT     = 0x00A3,
    SSS_NSS_GETSERVENT     = 0x00A4,
    SSS_NSS_ENDSERVENT     = 0x00A5,

#if 0
/* shadow */

    SSS_NSS_GETSPNAM       = 0x00B1,
    SSS_NSS_GETSPUID       = 0x00B2,
    SSS_NSS_SETSPENT       = 0x00B3,
    SSS_NSS_GETSPENT       = 0x00B4,
    SSS_NSS_ENDSPENT       = 0x00B5,
#endif

/* SUDO */
    SSS_SUDO_GET_SUDORULES = 0x00C1,
    SSS_SUDO_GET_DEFAULTS  = 0x00C2,

/* autofs */
    SSS_AUTOFS_SETAUTOMNTENT    = 0x00D1,
    SSS_AUTOFS_GETAUTOMNTENT    = 0x00D2,
    SSS_AUTOFS_GETAUTOMNTBYNAME  = 0x00D3,
    SSS_AUTOFS_ENDAUTOMNTENT    = 0x00D4,

/* SSH */
    SSS_SSH_GET_USER_PUBKEYS = 0x00E1,
    SSS_SSH_GET_HOST_PUBKEYS = 0x00E2,

/* PAM related calls */
    SSS_PAM_AUTHENTICATE     = 0x00F1, /**< see pam_sm_authenticate(3) for
                                        * details.
                                        *
                                        * Additionally we allow sssd to send
                                        * the return code PAM_NEW_AUTHTOK_REQD
                                        * during authentication if the
                                        * authentication was successful but
                                        * the authentication token is expired.
                                        * To meet the standards of libpam we
                                        * return PAM_SUCCESS for
                                        * authentication and set a flag so
                                        * that the account management module
                                        * can return PAM_NEW_AUTHTOK_REQD if
                                        * sssd return success for account
                                        * management. We do this to reduce the
                                        * communication with external servers,
                                        * because there are cases, e.g.
                                        * Kerberos authentication, where the
                                        * information that the password is
                                        * expired is already available during
                                        * authentication. */
    SSS_PAM_SETCRED          = 0x00F2, /**< see pam_sm_setcred(3) for
                                        * details */
    SSS_PAM_ACCT_MGMT        = 0x00F3, /**< see pam_sm_acct_mgmt(3) for
                                        * details */
    SSS_PAM_OPEN_SESSION     = 0x00F4, /**< see pam_sm_open_session(3) for
                                        * details */
    SSS_PAM_CLOSE_SESSION    = 0x00F5, /**< see pam_sm_close_session(3) for
                                        *details */
    SSS_PAM_CHAUTHTOK        = 0x00F6, /**< second run of the password change
                                        * operation where the PAM_UPDATE_AUTHTOK
                                        * flag is set and the real change may
                                        * happen, see pam_sm_chauthtok(3) for
                                        * details */
    SSS_PAM_CHAUTHTOK_PRELIM = 0x00F7, /**< first run of the password change
                                        * operation where the PAM_PRELIM_CHECK
                                        * flag is set, see pam_sm_chauthtok(3)
                                        * for details */
    SSS_CMD_RENEW            = 0x00F8, /**< Renew a credential with a limited
                                        * lifetime, e.g. a Kerberos Ticket
                                        * Granting Ticket (TGT) */

/* PAC responder calls */
    SSS_PAC_ADD_PAC_USER     = 0x0101,

};

/**
 * @}
 */ /* end of group sss_cli_command */


/**
 * @defgroup sss_pam SSSD and PAM
 *
 * SSSD offers authentication and authorization via PAM
 *
 * The SSSD provides a PAM client modules pam_sss which can be called from the
 * PAM stack of the operation system. pam_sss will collect all the data about
 * the user from the PAM stack and sends them via a socket to the PAM
 * responder of the SSSD. The PAM responder selects the appropriate backend
 * and forwards the data via DBUS to the backend. The backend preforms the
 * requested operation and sends the result expressed by a PAM return value
 * and optional additional information back to the PAM responder. Finally the
 * PAM responder forwards the response back to the client.
 *
 * @{
 */

/**
 * @}
 */ /* end of group sss_pam */

/**
 * @defgroup sss_authtok_type Authentication Tokens
 * @ingroup sss_pam
 *
 * To indicate to the components of the SSSD how to handle the authentication
 * token the client sends the type of the authentication token to the SSSD.
 *
 * @{
 */

/** The different types of authentication tokens */

enum sss_authtok_type {
    SSS_AUTHTOK_TYPE_EMPTY    =  0x0000, /**< No authentication token
                                          * available */
    SSS_AUTHTOK_TYPE_PASSWORD =  0x0001, /**< Authentication token is a
                                          * password, it may or may no contain
                                          * a trailing \\0 */
    SSS_AUTHTOK_TYPE_CCFILE =    0x0002, /**< Authentication token is a path to
                                          * a Kerberos credential cache file,
                                          * it may or may no contain
                                          * a trailing \\0 */
};

/**
 * @}
 */ /* end of group sss_authtok_type */

#define SSS_START_OF_PAM_REQUEST 0x4d415049
#define SSS_END_OF_PAM_REQUEST 0x4950414d

enum pam_item_type {
    SSS_PAM_ITEM_EMPTY = 0x0000,
    SSS_PAM_ITEM_USER,
    SSS_PAM_ITEM_SERVICE,
    SSS_PAM_ITEM_TTY,
    SSS_PAM_ITEM_RUSER,
    SSS_PAM_ITEM_RHOST,
    SSS_PAM_ITEM_AUTHTOK,
    SSS_PAM_ITEM_NEWAUTHTOK,
    SSS_PAM_ITEM_CLI_LOCALE,
    SSS_PAM_ITEM_CLI_PID,
};

#define SSS_NSS_MAX_ENTRIES 256
#define SSS_NSS_HEADER_SIZE (sizeof(uint32_t) * 4)
struct sss_cli_req_data {
    size_t len;
    const void *data;
};

/* this is in milliseconds, wait up to 300 seconds */
#define SSS_CLI_SOCKET_TIMEOUT 300000

enum sss_status {
    SSS_STATUS_TRYAGAIN,
    SSS_STATUS_UNAVAIL,
    SSS_STATUS_SUCCESS
};

/**
 * @defgroup sss_pam_cli Responses to the PAM client
 * @ingroup sss_pam
 * @{
 */

/**
 * @defgroup response_type Messages from the server
 * @ingroup sss_pam_cli
 *
 * SSSD can send different kind of information back to the client.
 * A response from the SSSD can contain 0 or more messages. Each message
 * contains a type tag and the size of the message data, both are unsigned
 * 32-bit integer values, followed be the message specific data.
 *
 * If the message is generated by a backend it is send back to the PAM
 * responder via a D-BUS message in an array of D-BUS structs. The struct
 * consists of a DBUS_TYPE_UINT32 for the tag and a DBUS_TYPE_ARRAY to hold
 * the message.
 *
 * Examples:
 *  - #SSS_PAM_ENV_ITEM,
 *    <pre>
 *    ------------------------------------
 *    | uint32_t | uint32_t | uint8_t[4] |
 *    | 0x03     | 0x04     | a=b\\0      |
 *    ------------------------------------
 *    </pre>
 * @{
 */

/** Types of different messages */

enum response_type {
    SSS_PAM_SYSTEM_INFO = 0x01, /**< Message for the system log.
                                 * @param String, zero terminated. */
    SSS_PAM_DOMAIN_NAME, /**< Name of the domain the user belongs too.
                          * This messages is generated by the PAM responder.
                          * @param String, zero terminated, with the domain
                          * name. */
    SSS_PAM_ENV_ITEM,    /**< Set and environment variable with pam_putenv(3).
                          * @param String, zero terminated, of the form
                          * name=value. See pam_putenv(3) for details. */
    SSS_ENV_ITEM,        /**< Set and environment variable with putenv(3).
                          * @param String, zero terminated, of the form
                          * name=value. See putenv(3) for details. */
    SSS_ALL_ENV_ITEM,    /**< Set and environment variable with putenv(3) and
                          * pam_putenv(3).
                          * @param String, zero terminated, of the form
                          * name=value. See putenv(3) and pam_putenv(3) for
                          * details. */
    SSS_PAM_USER_INFO,   /**< A message which should be displayed to the user.
                          * @param User info message, see #user_info_type
                          * for details. */
    SSS_PAM_TEXT_MSG,    /**< A plain text message which should be displayed to
                          * the user.This should only be used in the case where
                          * it is not possile to use SSS_PAM_USER_INFO.
                          * @param A zero terminated string. */
};

/**
 * @defgroup user_info_type User info messages
 * @ingroup response_type
 *
 * To achieve a consistent user experience and to facilitate
 * internationalization all messages show to the user are generate by the PAM
 * client and not by the SSSD server components. To indicate what message the
 * client should display to the user SSSD can send a #SSS_PAM_USER_INFO message
 * where the data part contains one of the following tags as an unsigned
 * 32-bit integer value and optional data.
 *
 * Examples:
 *  - #SSS_PAM_USER_INFO_OFFLINE_CHPASS
 *    <pre>
 *    ----------------------------------
 *    | uint32_t | uint32_t | uint32_t |
 *    | 0x06     | 0x01     | 0x03     |
 *    ----------------------------------
 *    </pre>
 *  - #SSS_PAM_USER_INFO_CHPASS_ERROR
 *    <pre>
 *    ----------------------------------------------------------
 *    | uint32_t | uint32_t | uint32_t | uint32_t | uint8_t[3] |
 *    | 0x06     | 0x05     | 0x04     | 0x03     | abc        |
 *    ----------------------------------------------------------
 *    </pre>
 * @{
 */

/** Different types of user messages */

enum user_info_type {
    SSS_PAM_USER_INFO_OFFLINE_AUTH = 0x01, /**< Inform the user that the
                                            * authentication happened offline.
                                            * This message is generated by the
                                            * PAM responder.
                                            * @param Time when the cached
                                            * password will expire in seconds
                                            * since the UNIX Epoch as returned
                                            * by time(2) as int64_t. A value
                                            * of zero indicates that the
                                            * cached password will never
                                            * expire. */
    SSS_PAM_USER_INFO_OFFLINE_AUTH_DELAYED, /**< Tell the user how low a new
                                             * authentication is delayed. This
                                             * message is generated by the PAM
                                             * responder.
                                             * @param Time when an
                                             * authentication is allowed again
                                             * in seconds since the UNIX Epoch
                                             * as returned by time(2) as
                                             * int64_t. */
    SSS_PAM_USER_INFO_OFFLINE_CHPASS, /**< * Tell the user that it is not
                                       * possible to change the password while
                                       * the system is offline. This message
                                       * is generated by the PAM responder. */
    SSS_PAM_USER_INFO_CHPASS_ERROR, /**< Tell the user that a password change
                                     * failed and optionally give a reason.
                                     * @param Size of the message as unsigned
                                     * 32-bit integer value. A value of 0
                                     * indicates that no message is following.
                                     * @param String with the specified
                                     * length. */
    SSS_PAM_USER_INFO_GRACE_LOGIN, /**< Warn the user that the password is
                                    * expired and inform about the remaining
                                    * number of grace logins.
                                    * @param The number of remaining grace
                                    * logins as uint32_t */
    SSS_PAM_USER_INFO_EXPIRE_WARN /**< Warn the user that the password will
                                   * expire soon.
                                   * @param Number of seconds before the user's
                                   * password will expire. */
};
/**
 * @}
 */ /* end of group user_info_type */

/**
 * @}
 */ /* end of group response_type */

/**
 * @}
 */ /* end of group sss_pam_cli */

enum sss_netgr_rep_type {
    SSS_NETGR_REP_TRIPLE = 1,
    SSS_NETGR_REP_GROUP
};

enum sss_cli_error_codes {
    ESSS_SSS_CLI_ERROR_START = 0x1000,
    ESSS_BAD_PRIV_SOCKET,
    ESSS_BAD_PUB_SOCKET,
    ESSS_BAD_CRED_MSG,
    ESSS_SERVER_NOT_TRUSTED,

    ESS_SSS_CLI_ERROR_MAX
};

const char *ssscli_err2string(int err);

enum nss_status sss_nss_make_request(enum sss_cli_command cmd,
                                     struct sss_cli_req_data *rd,
                                     uint8_t **repbuf, size_t *replen,
                                     int *errnop);

int sss_pam_make_request(enum sss_cli_command cmd,
                         struct sss_cli_req_data *rd,
                         uint8_t **repbuf, size_t *replen,
                         int *errnop);
void sss_pam_close_fd(void);

int sss_pac_make_request(enum sss_cli_command cmd,
                         struct sss_cli_req_data *rd,
                         uint8_t **repbuf, size_t *replen,
                         int *errnop);

int sss_sudo_make_request(enum sss_cli_command cmd,
                          struct sss_cli_req_data *rd,
                          uint8_t **repbuf, size_t *replen,
                          int *errnop);

int sss_autofs_make_request(enum sss_cli_command cmd,
                            struct sss_cli_req_data *rd,
                            uint8_t **repbuf, size_t *replen,
                            int *errnop);

int sss_ssh_make_request(enum sss_cli_command cmd,
                         struct sss_cli_req_data *rd,
                         uint8_t **repbuf, size_t *replen,
                         int *errnop);

#ifndef SAFEALIGN_COPY_UINT32
static inline void
safealign_memcpy(void *dest, const void *src, size_t n, size_t *counter)
{
    memcpy(dest, src, n);
    if (counter) {
        *counter += n;
    }
}

#define SAFEALIGN_SET_VALUE(dest, value, type, pctr) do { \
    type CV_MACRO_val = (type)(value); \
    safealign_memcpy(dest, &CV_MACRO_val, sizeof(type), pctr); \
} while(0)

#ifndef SAFEALIGN_SET_UINT32
#define SAFEALIGN_SET_UINT32(dest, value, pctr) \
    SAFEALIGN_SET_VALUE(dest, value, uint32_t, pctr)
#endif

#define SAFEALIGN_COPY_UINT32(dest, src, pctr) \
    safealign_memcpy(dest, src, sizeof(uint32_t), pctr)
#endif

#ifndef SAFEALIGN_SET_UINT16
#define SAFEALIGN_SET_UINT16(dest, value, pctr) \
    SAFEALIGN_SET_VALUE(dest, value, uint16_t, pctr)
#endif

#ifndef SAFEALIGN_COPY_UINT16
#define SAFEALIGN_COPY_UINT16(dest, src, pctr) \
    safealign_memcpy(dest, src, sizeof(uint16_t), pctr)
#endif

#if 0

/* GETSPNAM Request:
 *
 * 0-X: string with name
 *
 * Replies:
 *
 * 0-3: 32bit unsigned number of results
 * 4-7: 32bit unsigned (reserved/padding)
 * For each result:
 *  0-7: 64bit unsigned with Date of last change
 *  8-15: 64bit unsigned with Min #days between changes
 *  16-23: 64bit unsigned with Max #days between changes
 *  24-31: 64bit unsigned with #days before pwd expires
 *  32-39: 64bit unsigned with #days after pwd expires until account is disabled
 *  40-47: 64bit unsigned with expiration date in days since 1970-01-01
 *  48-55: 64bit unsigned (flags/reserved)
 *  56-X: sequence of 2, 0 terminated, strings (name, pwd) 64bit padded
 */
#endif

/* Return strlen(str) or maxlen, whichever is shorter
 * Returns EINVAL if str is NULL, EFBIG if str is longer than maxlen
 * _len will return the result
 */
errno_t sss_strnlen(const char *str, size_t maxlen, size_t *len);

void sss_nss_lock(void);
void sss_nss_unlock(void);
void sss_pam_lock(void);
void sss_pam_unlock(void);

errno_t sss_readrep_copy_string(const char *in,
                                size_t *offset,
                                size_t *slen,
                                size_t *dlen,
                                char **out,
                                size_t *size);

#endif /* _SSSCLI_H */
