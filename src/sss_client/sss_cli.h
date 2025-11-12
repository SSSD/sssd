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

#include "config.h"

#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>

#include "shared/safealign.h"

#ifndef HAVE_ERRNO_T
#define HAVE_ERRNO_T
typedef int errno_t;
#else
#include <errno.h>
#endif

#ifndef EOK
#define EOK 0
#endif

#ifndef NETDB_INTERNAL
#define NETDB_INTERNAL (-1)
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

/** The allowed commands an SSS client can send to the SSSD */

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

    SSS_NSS_GETPWNAM_EX    = 0x0019,
    SSS_NSS_GETPWUID_EX    = 0x001A,

/* group */

    SSS_NSS_GETGRNAM       = 0x0021,
    SSS_NSS_GETGRGID       = 0x0022,
    SSS_NSS_SETGRENT       = 0x0023,
    SSS_NSS_GETGRENT       = 0x0024,
    SSS_NSS_ENDGRENT       = 0x0025,
    SSS_NSS_INITGR         = 0x0026,

    SSS_NSS_GETGRNAM_EX    = 0x0029,
    SSS_NSS_GETGRGID_EX    = 0x002A,
    SSS_NSS_INITGR_EX      = 0x002E,

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
#endif

/* hosts */

    SSS_NSS_GETHOSTBYNAME  = 0x0051,
    SSS_NSS_GETHOSTBYNAME2 = 0x0052,
    SSS_NSS_GETHOSTBYADDR  = 0x0053,
    SSS_NSS_SETHOSTENT     = 0x0054,
    SSS_NSS_GETHOSTENT     = 0x0055,
    SSS_NSS_ENDHOSTENT     = 0x0056,

/* netgroup */

    SSS_NSS_SETNETGRENT    = 0x0061,
    SSS_NSS_GETNETGRENT    = 0x0062,
    SSS_NSS_ENDNETGRENT    = 0x0063,

/* networks */

    SSS_NSS_GETNETBYNAME   = 0x0071,
    SSS_NSS_GETNETBYADDR   = 0x0072,
    SSS_NSS_SETNETENT      = 0x0073,
    SSS_NSS_GETNETENT      = 0x0074,
    SSS_NSS_ENDNETENT      = 0x0075,

#if 0
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
    SSS_PAM_PREAUTH          = 0x00F9, /**< Request which can be run before
                                        * an authentication request to find
                                        * out which authentication methods
                                        * are available for the given user. */
    SSS_GSSAPI_INIT          = 0x00FA, /**< Initialize GSSAPI authentication. */
    SSS_GSSAPI_SEC_CTX       = 0x00FB, /**< Establish GSSAPI security ctx. */

/* PAC responder calls */
    SSS_PAC_ADD_PAC_USER     = 0x0101,

/* ID-SID mapping calls */
SSS_NSS_GETSIDBYNAME = 0x0111, /**< Takes a zero terminated fully qualified
                                    name and returns the zero terminated
                                    string representation of the SID of the
                                    object with the given name. */
SSS_NSS_GETSIDBYID   = 0x0112, /**< Takes an unsigned 32bit integer (POSIX ID)
                                    and returns the zero terminated string
                                    representation of the SID of the object
                                    with the given ID. */
SSS_NSS_GETNAMEBYSID = 0x0113, /**< Takes the zero terminated string
                                    representation of a SID and returns the
                                    zero terminated fully qualified name of
                                    the related object. */
SSS_NSS_GETIDBYSID   = 0x0114, /**< Takes the zero terminated string
                                    representation of a SID and returns and
                                    returns the POSIX ID of the related object
                                    as unsigned 32bit integer value and
                                    another unsigned 32bit integer value
                                    indicating the type (unknown, user, group,
                                    both) of the object. */
SSS_NSS_GETORIGBYNAME = 0x0115, /**< Takes a zero terminated fully qualified
                                     name and returns a list of zero
                                     terminated strings with key-value pairs
                                     where the first string is the key and
                                     second the value. Hence the list should
                                     have an even number of strings, if not
                                     the whole list is invalid. */
SSS_NSS_GETNAMEBYCERT = 0x0116, /**< Takes the zero terminated string
                                     of the base64 encoded DER representation
                                     of a X509 certificate and returns the zero
                                     terminated fully qualified name of the
                                     related object. */
SSS_NSS_GETLISTBYCERT = 0x0117, /**< Takes the zero terminated string
                                     of the base64 encoded DER representation
                                     of a X509 certificate and returns a list
                                     of zero terminated fully qualified names
                                     of the related objects. */
SSS_NSS_GETSIDBYUID   = 0x0118, /**< Takes an unsigned 32bit integer (POSIX UID)
                                     and return the zero terminated string
                                     representation of the SID of the object
                                     with the given UID. */
SSS_NSS_GETSIDBYGID   = 0x0119, /**< Takes an unsigned 32bit integer (POSIX GID)
                                     and return the zero terminated string
                                     representation of the SID of the object
                                     with the given UID. */
SSS_NSS_GETORIGBYUSERNAME = 0x011A, /**< Takes a zero terminated fully qualified
                                     user name and returns a list of zero
                                     terminated strings with key-value pairs
                                     where the first string is the key and
                                     second the value. Hence the list should
                                     have an even number of strings, if not
                                     the whole list is invalid. */
SSS_NSS_GETORIGBYGROUPNAME = 0x011B, /**< Takes a zero terminated fully qualified
                                     group name and returns a list of zero
                                     terminated strings with key-value pairs
                                     where the first string is the key and
                                     second the value. Hence the list should
                                     have an even number of strings, if not
                                     the whole list is invalid. */
SSS_NSS_GETSIDBYUSERNAME = 0x011C, /**< Takes a zero terminated fully qualified
                                    name and returns the zero terminated
                                    string representation of the SID of the
                                    user with the given name. */
SSS_NSS_GETSIDBYGROUPNAME = 0x011D, /**< Takes a zero terminated fully qualified
                                     name and returns the zero terminated
                                     string representation of the SID of the
                                     group with the given name. */


/* subid */
    SSS_NSS_GET_SUBID_RANGES = 0x0130, /**< Requests both subuid and subgid ranges
                                            defined for a user. */
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
 * and forwards the data via D-BUS to the backend. The backend preforms the
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
    SSS_AUTHTOK_TYPE_2FA =       0x0003, /**< Authentication token has two
                                          * factors, they may or may no contain
                                          * a trailing \\0 */
    SSS_AUTHTOK_TYPE_SC_PIN =    0x0004, /**< Authentication token is a Smart
                                          * Card PIN, it may or may no contain
                                          * a trailing \\0 */
    SSS_AUTHTOK_TYPE_SC_KEYPAD = 0x0005, /**< Authentication token indicates
                                          * Smart Card authentication is used
                                          * and that the PIN will be entered
                                          * at the card reader. */
    SSS_AUTHTOK_TYPE_2FA_SINGLE = 0x0006, /**< Authentication token has two
                                           * factors in a single string, it may
                                           * or may no contain a trailing \\0 */
    SSS_AUTHTOK_TYPE_OAUTH2 =     0x0007, /**< Authentication token is a
                                           * oauth2 token for presented
                                           * challenge that is acquired from
                                           * Kerberos. It may or may no
                                           * contain a trailing \\0 */
    SSS_AUTHTOK_TYPE_PASSKEY =    0x0008, /**< Authentication token is a Passkey
                                           * PIN, it may or may not contain
                                           * a trailing \\0 */
    SSS_AUTHTOK_TYPE_PASSKEY_KRB = 0x0009,  /**< Authentication token contains
                                             * Passkey data used for Kerberos
                                             * pre-authentication */
    SSS_AUTHTOK_TYPE_PASSKEY_REPLY = 0x0010, /**< Authentication token contains
                                              * Passkey reply data presented as
                                              * a kerberos challenge answer */
    SSS_AUTHTOK_TYPE_PAM_STACKED = 0x0011, /**< Authentication token contains
                                            * either 2FA_SINGLE or PASSWORD
                                            * via PAM use_first_pass */
};

/**
 * @}
 */ /* end of group sss_authtok_type */

#define SSS_START_OF_PAM_REQUEST 0x4d415049
#define SSS_END_OF_PAM_REQUEST 0x4950414d

#define PAM_PREAUTH_INDICATOR PUBCONF_PATH"/pam_preauth_available"

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
    SSS_PAM_ITEM_CHILD_PID,
    SSS_PAM_ITEM_REQUESTED_DOMAINS,
    SSS_PAM_ITEM_FLAGS,
    SSS_PAM_ITEM_JSON_AUTH_INFO,
    SSS_PAM_ITEM_JSON_AUTH_SELECTED,
};

#define PAM_CLI_FLAGS_USE_FIRST_PASS (1 << 0)
#define PAM_CLI_FLAGS_FORWARD_PASS   (1 << 1)
#define PAM_CLI_FLAGS_USE_AUTHTOK    (1 << 2)
#define PAM_CLI_FLAGS_IGNORE_UNKNOWN_USER (1 << 3)
#define PAM_CLI_FLAGS_IGNORE_AUTHINFO_UNAVAIL (1 << 4)
#define PAM_CLI_FLAGS_USE_2FA (1 << 5)
#define PAM_CLI_FLAGS_ALLOW_MISSING_NAME (1 << 6)
#define PAM_CLI_FLAGS_PROMPT_ALWAYS (1 << 7)
#define PAM_CLI_FLAGS_TRY_CERT_AUTH (1 << 8)
#define PAM_CLI_FLAGS_REQUIRE_CERT_AUTH (1 << 9)
#define PAM_CLI_FLAGS_ALLOW_CHAUTHTOK_BY_ROOT (1 << 10)
#define PAM_CLI_FLAGS_CHAUTHTOK_PREAUTH (1 << 11)

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
       uint32_t | uint32_t | uint8_t[4]
      ----------|----------|------------
       0x03     | 0x04     | a=b\\0
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
                          * the user. This should only be used in the case where
                          * it is not possible to use SSS_PAM_USER_INFO.
                          * @param A zero terminated string. */
    SSS_PAM_OTP_INFO,    /**< A message which optionally may contain the name
                          * of the vendor, the ID of an OTP token and a
                          * challenge.
                          * @param Three zero terminated strings, if one of the
                          * strings is missing the message will contain only
                          * an empty string (\0) for that component. */
    SSS_PAM_CERT_INFO,   /**< A message indicating that Smartcard/certificate
                          * based authentication is available and contains
                          * details about the found Smartcard.
                          * @param user name, zero terminated
                          * @param token name, zero terminated
                          * @param PKCS#11 module name, zero terminated
                          * @param key id, zero terminated */
    SSS_OTP,             /**< Indicates that the authtok was a OTP, so don't
                          * cache it. There is no message.
                          * @param None. */
    SSS_PASSWORD_PROMPTING, /**< Indicates that password prompting is possible.
                             * This might be used together with
                             * SSS_PAM_OTP_INFO to determine the type of
                             * prompting. There is no message.
                             * @param None. */
    SSS_CERT_AUTH_PROMPTING, /**< Indicates that on the server side
                              * Smartcard/certificate based authentication is
                              * available for the selected account. This might
                              * be used together with other prompting options
                              * to determine the type of prompting.
                              * @param None. */
    SSS_PAM_CERT_INFO_WITH_HINT, /**< Same as SSS_PAM_CERT_INFO but user name
                                  * might be missing and should be prompted
                                  * for. */
    SSS_PAM_PROMPT_CONFIG, /**< Contains data which controls which credentials
                            * are expected and how the user is prompted for
                            * them. */
    SSS_CHILD_KEEP_ALIVE, /**< Indicates that the child process is kept alived
                            * and further communication must be done with the
                            * same child. The message is the pid of the child
                            * process. */
    SSS_PAM_OAUTH2_INFO,  /**< A message which contains the oauth2
                            *  parameters for the user.
                            * @param Three zero terminated strings:
                            *   - verification_uri
                            *   - verification_uri_complete
                            *   - user_code
                            */
    SSS_PAM_PASSKEY_INFO, /**< Indicates that passkey authentication is available.
                            * including a parameter string which dictates whether
                            * prompting for PIN is needed.
                            * @param
                            *   - prompt_pin
                            */
    SSS_PAM_PASSKEY_KRB_INFO, /**< A message containing the passkey parameters
                               * for the user. The key is the cryptographic challenge
                               * used as the key to the passkey hash table entry.
                               * @param
                               *   - user verification (string)
                               *   - key (string)
                               */
    SSS_PAM_JSON_AUTH_INFO, /**< A JSON formatted message containing the available
                             * authentication mechanisms and their associated data.
                             * @param
                             *   - json_auth_msg
                             */
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
 *     uint32_t | uint32_t | uint32_t
 *    ----------|----------|----------
 *     0x06     | 0x04     | 0x03
 *
 *  - #SSS_PAM_USER_INFO_CHPASS_ERROR
 *     uint32_t | uint32_t | uint32_t | uint32_t | uint8_t[3]
 *    ----------|----------|----------|----------|------------
 *     0x06     | 0x0B     | 0x04     | 0x03     | abc
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
    SSS_PAM_USER_INFO_OTP_CHPASS,   /**< Tell the user that he needs to kinit
                                      * or login and logout to get a TGT after
                                      * an OTP password change */
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
    SSS_PAM_USER_INFO_EXPIRE_WARN, /**< Warn the user that the password will
                                    * expire soon.
                                    * @param Number of seconds before the
                                    * user's password will expire. */

    SSS_PAM_USER_INFO_ACCOUNT_EXPIRED, /**< Tell the user that the account
                                        * has expired and optionally give
                                        * a reason.
                                        * @param Size of the message as
                                        * unsigned 32-bit integer value. A
                                        * value of 0 indicates that no message
                                        * is following. @param String with the
                                        * specified length. */

    SSS_PAM_USER_INFO_PIN_LOCKED, /**< Tell the user that the PIN is locked */
    SSS_PAM_USER_INFO_NO_KRB_TGT, /**< Tell the user that Kerberos local/offline
                                       auth was performed, therefore no TGT
                                       is granted */
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


enum prompt_config_type {
    PC_TYPE_INVALID = 0,
    PC_TYPE_PASSWORD,
    PC_TYPE_2FA,
    PC_TYPE_2FA_SINGLE,
    PC_TYPE_PASSKEY,
    PC_TYPE_SMARTCARD,
    PC_TYPE_EIDP,
    PC_TYPE_LAST
};

struct prompt_config;

enum prompt_config_type pc_get_type(struct prompt_config *pc);
const char *pc_get_password_prompt(struct prompt_config *pc);
const char *pc_get_2fa_1st_prompt(struct prompt_config *pc);
const char *pc_get_2fa_2nd_prompt(struct prompt_config *pc);
const char *pc_get_2fa_single_prompt(struct prompt_config *pc);
const char *pc_get_passkey_inter_prompt(struct prompt_config *pc);
const char *pc_get_passkey_touch_prompt(struct prompt_config *pc);
const char *pc_get_eidp_init_prompt(struct prompt_config *pc);
const char *pc_get_eidp_link_prompt(struct prompt_config *pc);
const char *pc_get_smartcard_init_prompt(struct prompt_config *pc);
const char *pc_get_smartcard_pin_prompt(struct prompt_config *pc);
errno_t pc_list_add_passkey(struct prompt_config ***pc_list,
                            const char *inter_prompt,
                            const char *touch_prompt);
void pc_list_free(struct prompt_config **pc_list);
errno_t pc_list_add_password(struct prompt_config ***pc_list,
                             const char *prompt);
errno_t pc_list_add_2fa(struct prompt_config ***pc_list,
                        const char *prompt_1st, const char *prompt_2nd);
errno_t pc_list_add_2fa_single(struct prompt_config ***pc_list,
                               const char *prompt);
errno_t pc_list_add_eidp(struct prompt_config ***pc_list,
                         const char *prompt_init, const char *prompt_link);
errno_t pc_list_add_smartcard(struct prompt_config ***pc_list,
                              const char *prompt_init, const char *prompt_pin);
errno_t pam_get_response_prompt_config(struct prompt_config **pc_list, int *len,
                                       uint8_t **data);
errno_t pc_list_from_response(int size, uint8_t *buf,
                              struct prompt_config ***pc_list);

enum sss_netgr_rep_type {
    SSS_NETGR_REP_TRIPLE = 1,
    SSS_NETGR_REP_GROUP
};

enum sss_cli_error_codes {
    ESSS_SSS_CLI_ERROR_START = 0x1000,
    ESSS_BAD_SOCKET,
    ESSS_BAD_CRED_MSG,
    ESSS_SERVER_NOT_TRUSTED,
    ESSS_NO_SOCKET,
    ESSS_SOCKET_STAT_ERROR,

    ESS_SSS_CLI_ERROR_MAX
};

const char *ssscli_err2string(int err);

enum sss_status sss_cli_make_request_with_checks(enum sss_cli_command cmd,
                                                 struct sss_cli_req_data *rd,
                                                 int timeout,
                                                 uint8_t **repbuf, size_t *replen,
                                                 int *errnop,
                                                 const char *socket_name,
                                                 bool check_server_creds,
                                                 bool allow_custom_errors);

enum nss_status sss_nss_make_request(enum sss_cli_command cmd,
                                     struct sss_cli_req_data *rd,
                                     uint8_t **repbuf, size_t *replen,
                                     int *errnop);

enum nss_status sss_nss_make_request_timeout(enum sss_cli_command cmd,
                                             struct sss_cli_req_data *rd,
                                             int timeout,
                                             uint8_t **repbuf, size_t *replen,
                                             int *errnop);

int sss_pam_make_request(enum sss_cli_command cmd,
                         struct sss_cli_req_data *rd,
                         uint8_t **repbuf, size_t *replen,
                         int *errnop);

void sss_cli_close_socket(void);

/* Checks access to the PAC responder and opens the socket, if available.
 * Required for processes like krb5_child that need to open the socket
 * before dropping privs.
 */
int sss_pac_check_and_open(void);

int sss_pac_make_request(enum sss_cli_command cmd,
                         struct sss_cli_req_data *rd,
                         uint8_t **repbuf, size_t *replen,
                         int *errnop);

int sss_pac_make_request_with_lock(enum sss_cli_command cmd,
                                   struct sss_cli_req_data *rd,
                                   uint8_t **repbuf, size_t *replen,
                                   int *errnop);

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
void sss_nss_mc_lock(void);
void sss_nss_mc_unlock(void);
void sss_pac_lock(void);
void sss_pac_unlock(void);

errno_t sss_readrep_copy_string(const char *in,
                                size_t *offset,
                                size_t *slen,
                                size_t *dlen,
                                char **out,
                                size_t *size);

enum pam_gssapi_cmd {
    PAM_GSSAPI_GET_NAME,
    PAM_GSSAPI_INIT,
    PAM_GSSAPI_SENTINEL
};

#endif /* _SSSCLI_H */
