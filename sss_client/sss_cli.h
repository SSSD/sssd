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

#ifndef HAVE_ERRNO_T
#define HAVE_ERRNO_T
typedef int errno_t;
#endif

#define SSS_NSS_PROTOCOL_VERSION 1
#define SSS_PAM_PROTOCOL_VERSION 3

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

/* netgroup */

    SSS_NSS_SETNETGRENT    = 0x0061,
    SSS_NSS_GETNETGRENT    = 0x0062,
    SSS_NSS_ENDNETGRENT    = 0x0063,
    /* SSS_NSS_INNETGR     = 0x0064, */

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

/* services */

    SSS_NSS_GETSERVBYNAME  = 0x00A1,
    SSS_NSS_GETSERVBYPORT  = 0x00A2,
    SSS_NSS_SETSERVENT     = 0x00A3,
    SSS_NSS_GETSERVENT     = 0x00A4,
    SSS_NSS_ENDSERVENT     = 0x00A5,

/* shadow */

    SSS_NSS_GETSPNAM       = 0x00B1,
    SSS_NSS_GETSPUID       = 0x00B2,
    SSS_NSS_SETSPENT       = 0x00B3,
    SSS_NSS_GETSPENT       = 0x00B4,
    SSS_NSS_ENDSPENT       = 0x00B5,
#endif

/* PAM related calls */
    SSS_PAM_AUTHENTICATE     = 0x00F1,
    SSS_PAM_SETCRED          = 0x00F2,
    SSS_PAM_ACCT_MGMT        = 0x00F3,
    SSS_PAM_OPEN_SESSION     = 0x00F4,
    SSS_PAM_CLOSE_SESSION    = 0x00F5,
    SSS_PAM_CHAUTHTOK        = 0x00F6,
    SSS_PAM_CHAUTHTOK_PRELIM = 0x00F7,

};

enum sss_authtok_type {
    SSS_AUTHTOK_TYPE_EMPTY    =  0x0000,
    SSS_AUTHTOK_TYPE_PASSWORD =  0x0001,
};

#define START_OF_PAM_REQUEST 0x4d415049
#define END_OF_PAM_REQUEST 0x4950414d

enum pam_item_type {
    PAM_ITEM_EMPTY = 0x0000,
    PAM_ITEM_USER,
    PAM_ITEM_SERVICE,
    PAM_ITEM_TTY,
    PAM_ITEM_RUSER,
    PAM_ITEM_RHOST,
    PAM_ITEM_AUTHTOK,
    PAM_ITEM_NEWAUTHTOK,
    PAM_ITEM_CLI_LOCALE,
    PAM_ITEM_CLI_PID,
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
    SSS_STATUS_UNAVAIL,
    SSS_STATUS_SUCCESS
};

enum response_type {
    PAM_USER_INFO = 0x01,
    PAM_DOMAIN_NAME,
    PAM_ENV_ITEM,    /* only pam environment */
    ENV_ITEM,        /* only user environment */
    ALL_ENV_ITEM,    /* pam and user environment */
};

enum nss_status sss_nss_make_request(enum sss_cli_command cmd,
                                     struct sss_cli_req_data *rd,
                                     uint8_t **repbuf, size_t *replen,
                                     int *errnop);

int sss_pam_make_request(enum sss_cli_command cmd,
                                     struct sss_cli_req_data *rd,
                                     uint8_t **repbuf, size_t *replen,
                                     int *errnop);

#endif /* _SSSCLI_H */

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

